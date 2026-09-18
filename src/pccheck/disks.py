"""Storage tests: SMART health, drive self-tests, full surface read scans, optional write/verify."""

import json
import glob
import logging
import mmap
import os
import signal
import threading
import time

from .findings import FAIL, INFO, WARN
from .kmsg import REC_DISK
from .util import ManagedProcess, fmt_bytes, out, run, boot_id

log = logging.getLogger("pccheck")

CHUNK = 4 * 1024 * 1024
MAX_READ_ERRORS = 64


# --------------------------------------------------------------------------- discovery

def block_disks(exclude=()):
    """Physical block devices to test: [{name, path, size, model, serial, rotational, transport}]."""
    res = run(["lsblk", "-J", "-b", "-d", "-o", "NAME,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,TRAN,RO,RM"])
    if res.returncode != 0:
        raise RuntimeError(f"Block device discovery failed: {res.stderr.strip()}")
    try:
        devices = json.loads(res.stdout).get("blockdevices", [])
    except ValueError as exc:
        raise RuntimeError("Block device discovery returned invalid JSON") from exc
    disks = []
    for d in devices:
        name = d.get("name", "")
        if d.get("type") != "disk" or name in exclude:
            continue
        if name.startswith(("loop", "ram", "zram", "sr", "fd", "nbd", "md", "dm-")):
            continue
        if int(d.get("size") or 0) == 0 or str(d.get("ro")) in ("1", "True", "true"):
            continue
        disks.append({
            "name": name, "path": f"/dev/{name}", "size": int(d.get("size") or 0),
            "model": (d.get("model") or "").strip(), "serial": (d.get("serial") or "").strip(),
            "wwn": d.get("wwn") or "", "rotational": str(d.get("rota")) in ("1", "True", "true"),
            "transport": d.get("tran") or "",
        })
    return disks


def disk_id(disk):
    return disk.get("serial") or disk.get("wwn") or disk["name"]


def smart_devices(exclude=()):
    """smartctl --scan-open also finds disks behind RAID controllers (megaraid,N / cciss,N ...)."""
    res = run(["smartctl", "--scan-open", "-j"], timeout=120)
    if res.returncode != 0:
        raise RuntimeError(f"SMART device discovery failed: {res.stderr.strip()}")
    try:
        devices = json.loads(res.stdout).get("devices", [])
    except ValueError as exc:
        raise RuntimeError("SMART device discovery returned invalid JSON") from exc
    result = []
    for d in devices:
        name = d.get("name", "")
        # Disks behind a RAID controller share the controller's device node; only skip direct devices.
        if os.path.basename(name) in exclude and "," not in d.get("type", ""):
            continue
        result.append({"name": name, "type": d.get("type", "auto")})
    return result


def smart_read(dev):
    res = run(["smartctl", "-j", "-x", "-d", dev["type"], dev["name"]], timeout=180)
    try:
        return json.loads(res.stdout)
    except ValueError:
        return {}


def smart_label(data, dev):
    model = data.get("model_name") or data.get("scsi_model_name") or data.get("model_family") or ""
    serial = data.get("serial_number", "")
    return f"{dev['name']}{'/' + dev['type'] if ',' in dev['type'] else ''} {model} SN:{serial}".strip()


def _ata_attrs(data):
    return {a.get("id"): a for a in data.get("ata_smart_attributes", {}).get("table", [])}


def smart_metrics(data):
    """The counters we compare before/after the burn-in."""
    m = {}
    attrs = _ata_attrs(data)
    for aid, name in ((5, "reallocated"), (187, "reported_uncorrect"), (197, "pending"), (198, "offline_uncorrectable"),
                      (199, "udma_crc"), (10, "spin_retry"), (184, "end_to_end"), (196, "realloc_events")):
        if aid in attrs:
            m[name] = int(attrs[aid].get("raw", {}).get("value", 0)) & 0xFFFFFFFF
    nvme = data.get("nvme_smart_health_information_log")
    if nvme:
        for key in ("critical_warning", "media_errors", "num_err_log_entries", "percentage_used",
                    "available_spare", "available_spare_threshold"):
            if key in nvme:
                m[key] = int(nvme[key])
    if "scsi_grown_defect_list" in data:
        m["grown_defects"] = int(data["scsi_grown_defect_list"])
    for op in ("read", "write", "verify"):
        errs = data.get("scsi_error_counter_log", {}).get(op, {})
        if "total_uncorrected_errors" in errs:
            m[f"scsi_{op}_uncorrected"] = int(errs["total_uncorrected_errors"])
    return m


def evaluate_smart(data, label, before=None, phase_note=""):
    """Return a list of finding kwargs for a SMART report. before = metrics at test start."""
    findings = []

    def add(key, sev, title, detail="", evidence=None):
        findings.append({"key": f"smart:{label.split()[0]}:{key}", "severity": sev, "component": "Storage",
                         "title": f"{title} - {label}", "detail": detail, "recommendation": REC_DISK,
                         "evidence": evidence or []})

    if not data:
        return findings
    status = data.get("smart_status", {})
    if status.get("passed") is False:
        add("health", FAIL, "SMART overall health check FAILED")
    m = smart_metrics(data)
    for a in _ata_attrs(data).values():
        wf = a.get("when_failed", "")
        if wf == "now":
            add(f"attr{a.get('id')}", FAIL, f"SMART attribute {a.get('name')} is failing now")
        elif wf == "past":
            add(f"attr{a.get('id')}", WARN, f"SMART attribute {a.get('name')} failed in the past")
    for name, sev in (("pending", FAIL), ("offline_uncorrectable", FAIL), ("reallocated", WARN),
                      ("reported_uncorrect", WARN), ("spin_retry", WARN), ("end_to_end", FAIL),
                      ("media_errors", FAIL), ("grown_defects", WARN), ("scsi_read_uncorrected", FAIL),
                      ("scsi_write_uncorrected", FAIL), ("scsi_verify_uncorrected", FAIL)):
        if m.get(name, 0) > 0:
            add(name, sev, f"SMART {name.replace('_', ' ')} = {m[name]}")
    if m.get("critical_warning", 0):
        add("critical_warning", FAIL, f"NVMe critical warning flags 0x{m['critical_warning']:02x}")
    if m.get("percentage_used", 0) >= 90:
        add("wear", WARN, f"SSD endurance used {m['percentage_used']}%")
    if "available_spare" in m and m["available_spare"] < m.get("available_spare_threshold", 0):
        add("spare", FAIL, f"NVMe available spare {m['available_spare']}% below threshold")
    if before:
        for name, value in m.items():
            if name in ("percentage_used", "available_spare", "available_spare_threshold", "num_err_log_entries"):
                continue
            prev = before.get(name)
            if prev is not None and value > prev:
                sev = WARN if name == "udma_crc" else FAIL
                add(f"grew:{name}", sev, f"SMART {name.replace('_', ' ')} increased during the test ({prev} -> {value})",
                    detail="udma_crc errors point to the SATA cable/backplane" if name == "udma_crc" else "")
    # Self-test results (most recent entry)
    ata = data.get("ata_smart_self_test_log", {})
    ata_log = ata.get("extended", {}).get("table") or ata.get("standard", {}).get("table", [])
    if ata_log:
        st = ata_log[0].get("status", {})
        if st.get("passed") is False:
            add("selftest", FAIL, f"SMART self-test failed: {st.get('string', '')}")
    nvme_log = data.get("nvme_self_test_log", {}).get("table", [])
    if nvme_log:
        result = nvme_log[0].get("self_test_result", {}).get("value", 0)
        if result in (5, 6, 7):
            add("selftest", FAIL, f"NVMe self-test failed: {nvme_log[0].get('self_test_result', {}).get('string', result)}")
    scsi_result = data.get("scsi_self_test_0", {}).get("result", {})
    if scsi_result.get("value") in (3, 4, 5, 6, 7):
        add("selftest", FAIL, f"SCSI self-test failed: {scsi_result.get('string', '')}")
    return findings


def selftest_in_progress(data):
    if data.get("ata_smart_data", {}).get("self_test", {}).get("status", {}).get("remaining_percent") is not None:
        return True
    return (data.get("nvme_self_test_log", {}).get("current_self_test_operation", {}).get("value", 0) != 0
            or data.get("scsi_self_test_0", {}).get("self_test_in_progress", False))


def selftest_result(data):
    """Latest result and a log fingerprint. A historical successful test is not this run's success."""
    ata = data.get("ata_smart_self_test_log", {})
    table = (ata.get("extended", {}).get("table") or ata.get("standard", {}).get("table") or [])
    if table:
        return table[0].get("status", {}).get("passed"), table
    table = data.get("nvme_self_test_log", {}).get("table", [])
    if table:
        return table[0].get("self_test_result", {}).get("value") == 0, table
    scsi = data.get("scsi_self_test_0")
    if scsi:
        return scsi.get("result", {}).get("value") == 0, scsi
    return None, None


def is_solid_state(data):
    return "nvme_smart_health_information_log" in data or data.get("rotation_rate") == 0


# --------------------------------------------------------------------------- surface scan

class SurfaceScan(threading.Thread):
    """Reads every sector of a disk with O_DIRECT. Pausable, resumable after reboot."""

    def __init__(self, manager, disk, offset=0):
        super().__init__(name=f"scan-{disk['name']}", daemon=True)
        self.manager = manager
        self.disk = disk
        self.offset = offset
        self.errors = []
        self.slow_reads = 0
        self.bytes_read = 0
        self.seconds = 0.0
        self.done = False
        self.aborted = False

    @property
    def progress(self):
        return min(1.0, self.offset / self.disk["size"]) if self.disk["size"] else 1.0

    @property
    def rate(self):
        return self.bytes_read / self.seconds if self.seconds > 0 else 0.0

    def run(self):
        ctx = self.manager.ctx
        path = self.disk["path"]
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
        except OSError:
            try:
                fd = os.open(path, os.O_RDONLY)
            except OSError as exc:
                ctx.findings.add(f"scan-open:{self.disk['name']}", FAIL, "Storage",
                                 f"Cannot open {self.disk['name']} for reading", evidence=[str(exc)])
                self.done = True
                return
        buf = mmap.mmap(-1, CHUNK)
        size = self.disk["size"]
        log.info("surface scan %s from %s", path, fmt_bytes(self.offset))
        try:
            while self.offset < size and not self.manager.stop_event.is_set():
                self.manager.running_event.wait()
                length = min(CHUNK, size - self.offset)
                view = memoryview(buf)[:length]
                t0 = time.monotonic()
                try:
                    n = os.preadv(fd, [view], self.offset)
                except OSError as exc:
                    n = 0
                    self.errors.append((self.offset, str(exc)))
                    log.error("read error on %s at %d: %s", path, self.offset, exc)
                    if len(self.errors) >= MAX_READ_ERRORS:
                        self.aborted = True
                        break
                    self.offset += length
                    continue
                finally:
                    view.release()
                dt = time.monotonic() - t0
                self.seconds += dt
                if dt > ctx.opts.slow_read_seconds:
                    self.slow_reads += 1
                if n <= 0:
                    self.errors.append((self.offset, "Unexpected end of device before its advertised size"))
                    break
                self.bytes_read += n
                self.offset += n
        finally:
            buf.close()
            os.close(fd)
        if self.offset >= size or self.aborted:
            self.done = True
        self.manager.report_scan(self)


class WriteVerify:
    """fio sequential write + verify over the whole disk (destroys data)."""

    def __init__(self, manager, disk):
        self.manager = manager
        self.disk = disk
        self.proc = None
        self.done = False
        self.logfile = manager.ctx.session.path("logs", f"fio-{disk['name']}.log")

    def start(self):
        cmd = ["fio", "--name=writeverify", f"--filename={self.disk['path']}", "--direct=1", "--ioengine=libaio",
               "--rw=write", "--bs=1M", "--iodepth=16", "--verify=crc32c", "--do_verify=1", "--verify_fatal=1",
               "--verify_backlog=1024", "--size=100%", "--output-format=json", f"--output={self.logfile}.json"]
        self.proc = ManagedProcess(cmd, self.logfile, low_priority=False)

    def finished(self):
        if self.proc is None or self.done:
            return self.done
        rc = self.proc.poll()
        if rc is None:
            return False
        self.done = True
        self.proc.close()
        ctx = self.manager.ctx
        if rc != 0:
            ctx.findings.add(f"writeverify:{self.disk['name']}", FAIL, "Storage",
                             f"Write/verify test failed on {self.disk['name']} {self.disk['model']} SN:{self.disk['serial']}",
                             recommendation=REC_DISK, evidence=self.proc.output_tail(4000).splitlines()[-20:])
        else:
            ctx.findings.add(f"writeverify-ok:{self.disk['name']}", INFO, "Storage",
                             f"Write/verify pass completed on {self.disk['name']} {self.disk['model']}")
        return True


class DiskManager:
    """Owns SMART baselines/self-tests and background surface scans for all non-boot disks."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.stop_event = threading.Event()
        self.running_event = threading.Event()
        self.running_event.set()
        self.scans = []
        self.writers = []
        self.state = ctx.session.state.setdefault("disk_scans", {})
        self.selftests = ctx.session.state.setdefault("selftests", {})
        from .storage import parent_disk
        log_device = getattr(getattr(ctx, "storage", None), "device", "")
        self.exclude = tuple(x for x in (ctx.boot_disk, parent_disk(log_device)) if x)

    # ----- SMART
    def smart_baseline(self):
        base = self.ctx.session.state.setdefault("baselines", {}).setdefault("smart", {})
        devices = smart_devices(self.exclude)
        for disk in block_disks(self.exclude):
            # NVMe SMART discovery commonly returns /dev/nvme0, not /dev/nvme0n1.
            if not any(disk["path"] == dev["name"] or
                       (disk["name"].startswith("nvme") and disk["path"].startswith(dev["name"] + "n"))
                       for dev in devices):
                self.ctx.findings.add(f"smart-undiscovered:{disk_id(disk)}", WARN, "Storage",
                                      f"No SMART target discovered for {disk['name']} {disk['model']}", incomplete=True)
        for dev in devices:
            data = smart_read(dev)
            if not data or not any(k in data for k in ("smart_status", "ata_smart_attributes",
                                                       "nvme_smart_health_information_log", "scsi_error_counter_log")):
                self.ctx.findings.add(f"smart-unreadable:{dev['name']}:{dev['type']}", WARN, "Storage",
                                      f"SMART health data unavailable for {dev['name']} ({dev['type']})",
                                      incomplete=True)
                continue
            label = smart_label(data, dev)
            key = f"{dev['name']}|{dev['type']}"
            if key not in base:
                base[key] = {"label": label, "metrics": smart_metrics(data), "solid_state": is_solid_state(data),
                             "selftest_log": selftest_result(data)[1], "serial": data.get("serial_number")}
                for f in evaluate_smart(data, label):
                    f["title"] = f["title"] + " (before test)"
                    self.ctx.findings.add(**f)
        self.ctx.session.save()

    def start_selftests(self, long_test):
        base = self.ctx.session.state["baselines"].get("smart", {})
        for key, info in base.items():
            name, dtype = key.split("|", 1)
            kind = "long" if long_test else "short"
            res = run(["smartctl", "-d", dtype, "-t", kind, name], timeout=60)
            # smartctl is a bitmask: bits 0..2 are command/access failures; health bits
            # can be set even though the self-test command was accepted.
            started = res.returncode >= 0 and not res.returncode & 7
            self.selftests[key] = {"kind": kind, "started": started, "boot_id": boot_id(),
                                   "status": "running" if started else "unavailable"}
            if not started:
                self.ctx.findings.add(f"selftest-start:{key}", WARN, "Storage",
                                      f"SMART {kind} self-test could not start - {info['label']}", incomplete=True,
                                      evidence=[res.stdout[-2000:], res.stderr[-1000:]])
            log.info("smart self-test %s on %s: rc=%s", kind, name, res.returncode)
        self.ctx.session.save()

    def smart_final(self, wait_seconds):
        base = self.ctx.session.state.get("baselines", {}).get("smart", {})
        deadline = time.monotonic() + wait_seconds
        pending = dict(base)
        while pending and time.monotonic() < deadline and not self.ctx.abort_event.is_set():
            for key in list(pending):
                name, dtype = key.split("|", 1)
                data = smart_read({"name": name, "type": dtype})
                if selftest_in_progress(data):
                    self.selftests.setdefault(key, {})["observed_running"] = True
                else:
                    pending.pop(key)
            if pending:
                self.ctx.status_note = f"waiting for SMART self-tests: {', '.join(k.split('|')[0] for k in pending)}"
                time.sleep(30)
        for key, info in base.items():
            name, dtype = key.split("|", 1)
            data = smart_read({"name": name, "type": dtype})
            if not data or (info.get("serial") and data.get("serial_number") != info["serial"]):
                self.ctx.findings.add(f"smart-final-missing:{key}", WARN, "Storage",
                                      f"Final SMART data missing or device identity changed - {info['label']}",
                                      incomplete=True)
            with open(self.ctx.session.path("logs", f"smart-{os.path.basename(name)}-{dtype.replace(',', '_')}.json"), "w") as fh:
                json.dump(data, fh, indent=1)
            for f in evaluate_smart(data, info["label"], before=info.get("metrics")):
                self.ctx.findings.add(**f)
            record = self.selftests.setdefault(key, {})
            passed, fingerprint = selftest_result(data)
            completed = (record.get("started") and passed is True and not selftest_in_progress(data)
                         and (fingerprint != info.get("selftest_log") or
                              (record.get("observed_running") and record.get("boot_id") == boot_id())))
            record["status"] = "complete" if completed else "incomplete"
            if not completed:
                self.ctx.findings.add(f"smart-selftest-unfinished:{key}", WARN, "Storage",
                                      f"No completed successful self-test from this run - {info['label']}", incomplete=True)
        self.ctx.session.save()

    # ----- surface scans / write verify
    def destructive_candidates(self, disks):
        eligible, skipped = [], []
        for d in disks:
            signatures = run(["wipefs", "--no-act", "--noheadings", d["path"]])
            topology = run(["lsblk", "-J", "-o", "NAME,MOUNTPOINTS", d["path"]])
            try:
                nodes = json.loads(topology.stdout)["blockdevices"]
                def busy(node):
                    return (any(node.get("mountpoints") or []) or
                            bool(glob.glob(f"/sys/class/block/{node['name']}/holders/*")) or
                            any(busy(c) for c in node.get("children", [])))
                in_use = not nodes or any(busy(node) for node in nodes)
                children = any(node.get("children") for node in nodes)
            except (ValueError, KeyError, TypeError):
                in_use, children = True, True
            # force overrides existing data, never active mounts, device holders,
            # unreadable discovery, or uncertainty about which disk booted the OS.
            if (not self.ctx.boot_disk or d["name"] in self.exclude or in_use or
                    signatures.returncode != 0 or topology.returncode != 0 or
                    ((signatures.stdout.strip() or children) and self.ctx.opts.destructive != "force")):
                skipped.append(d)
            else:
                eligible.append(d)
        return eligible, skipped

    def start_scans(self, destructive_disks=()):
        disks = block_disks(self.exclude)
        destructive_names = {d["name"] for d in destructive_disks}
        for disk in disks:
            ident = disk_id(disk)
            entry = self.state.setdefault(ident, {"name": disk["name"], "model": disk["model"], "size": disk["size"],
                                                  "offset": 0, "done": False,
                                                  "mode": "write-verify" if disk["name"] in destructive_names else "read"})
            if entry.get("done"):
                continue
            if entry["mode"] == "write-verify":
                eligible, _ = self.destructive_candidates([disk])
                if (not eligible or disk["name"] not in destructive_names or
                        (getattr(self.ctx.session, "resumed", False) and not (disk.get("wwn") or disk.get("serial")))):
                    self.ctx.findings.add(f"writeverify-unsafe:{ident}", WARN, "Storage",
                                          f"Write/verify safety checks refused {disk['name']}", incomplete=True)
                    continue
                w = WriteVerify(self, disk)
                w.start()
                self.writers.append(w)
            else:
                scan = SurfaceScan(self, disk, offset=entry.get("offset", 0))
                self.scans.append(scan)
                scan.start()
        self.ctx.session.save()

    def pause(self):
        self.running_event.clear()
        for w in self.writers:
            if w.proc and w.proc.poll() is None:
                w.proc.send_signal(signal.SIGSTOP)

    def resume(self):
        self.running_event.set()
        for w in self.writers:
            if w.proc and w.proc.poll() is None:
                w.proc.send_signal(signal.SIGCONT)

    def all_done(self):
        return all(s.done or not s.is_alive() for s in self.scans) and all(w.finished() for w in self.writers)

    def save_progress(self):
        with self.ctx.session.lock:
            for s in self.scans:
                entry = self.state.get(disk_id(s.disk))
                if entry is not None:
                    entry["offset"] = s.offset
                    entry["done"] = s.done
            for w in self.writers:
                entry = self.state.get(disk_id(w.disk))
                if entry is not None:
                    entry["done"] = w.finished() and not entry.get("incomplete")

    def summary(self):
        rows = []
        for s in self.scans:
            rows.append({"name": s.disk["name"], "mode": "read", "progress": s.progress, "rate": s.rate,
                         "done": s.done, "errors": len(s.errors)})
        for w in self.writers:
            rows.append({"name": w.disk["name"], "mode": "write-verify", "progress": 1.0 if w.done else None,
                         "rate": 0, "done": w.done, "errors": 0})
        return rows

    def report_scan(self, scan):
        ctx = self.ctx
        d = scan.disk
        label = f"{d['name']} {d['model']} SN:{d['serial']}"
        if scan.errors:
            ctx.findings.add(f"scan-errors:{disk_id(d)}", FAIL, "Storage",
                             f"Unreadable sectors found on {label} ({len(scan.errors)} regions)",
                             recommendation=REC_DISK,
                             evidence=[f"offset {off} ({fmt_bytes(off)}): {err}" for off, err in scan.errors[:25]])
        if scan.slow_reads >= 10:
            ctx.findings.add(f"scan-slow:{disk_id(d)}", WARN, "Storage",
                             f"{scan.slow_reads} very slow reads on {label} (weak sectors / retries)",
                             recommendation=REC_DISK)
        if scan.done and not scan.aborted:
            ctx.findings.add(f"scan-ok:{disk_id(d)}", INFO, "Storage",
                             f"Full surface read completed on {label} (avg {scan.rate / 2**20:.0f} MiB/s this boot)")
        self.save_progress()

    def stop(self, wait=True):
        self.stop_event.set()
        self.running_event.set()
        if wait:
            for s in self.scans:
                s.join(timeout=120)
        for w in self.writers:
            if not w.finished() and w.proc:
                w.proc.stop()
                w.done = True  # a deliberate stop must not become a hardware failure in finished()
                self.state[disk_id(w.disk)]["incomplete"] = True
                self.ctx.findings.add(f"writeverify-unfinished:{w.disk['name']}", WARN, "Storage",
                                      f"Write/verify on {w.disk['name']} did not finish within the test time",
                                      incomplete=True)
        for s in self.scans:
            if not s.done:
                self.ctx.findings.add(f"scan-partial:{disk_id(s.disk)}", WARN, "Storage",
                                      f"Surface read of {s.disk['name']} covered {s.progress * 100:.0f}% "
                                      f"within the test time", incomplete=True)
        self.save_progress()
