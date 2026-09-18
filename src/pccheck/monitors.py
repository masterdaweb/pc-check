"""Background hardware monitors that run for the whole test."""

import glob
import hashlib
import json
import logging
import os
import re
import threading

from .findings import FAIL, INFO, WARN
from .kmsg import REC_MEMORY, REC_PCIE, REC_THERMAL
from .util import append_line, have, meminfo, now_iso, out, read_file, read_int, run, uptime

log = logging.getLogger("pccheck")


class Monitor(threading.Thread):
    interval = 30.0

    def __init__(self, ctx):
        super().__init__(name=self.__class__.__name__, daemon=True)
        self.ctx = ctx
        self.stop_event = threading.Event()
        self.last_error = None
        self.poll_lock = threading.Lock()

    def available(self):
        return True

    def poll(self):
        raise NotImplementedError

    def run(self):
        while not self.stop_event.is_set():
            self.sample()
            self.stop_event.wait(self.interval)

    def sample(self):
        with self.poll_lock:
            try:
                self.poll()
            except Exception as exc:  # a monitor must never take down the test
                if str(exc) != self.last_error:
                    log.exception("%s poll failed", self.name)
                    self.last_error = str(exc)
                    self.ctx.findings.add(f"monitor-error:{self.name}", WARN, "Test",
                                          f"Hardware monitor {self.name} lost coverage", incomplete=True,
                                          evidence=[str(exc)])

    def stop(self):
        self.stop_event.set()


# --------------------------------------------------------------------------- EDAC

def edac_counts(root="/sys/devices/system/edac/mc"):
    """{key: (label, ce, ue)} per DIMM, plus 'noinfo' counters per controller."""
    result = {}
    for mc in sorted(glob.glob(os.path.join(root, "mc[0-9]*"))):
        mcname = os.path.basename(mc)
        dimms = sorted(glob.glob(os.path.join(mc, "dimm[0-9]*"))) or sorted(glob.glob(os.path.join(mc, "rank[0-9]*")))
        for dimm in dimms:
            label = read_file(os.path.join(dimm, "dimm_label")).strip() or f"{mcname}/{os.path.basename(dimm)}"
            loc = read_file(os.path.join(dimm, "dimm_location")).strip()
            if loc:
                label = f"{label} ({loc})"
            ce = read_int(os.path.join(dimm, "dimm_ce_count"), 0)
            ue = read_int(os.path.join(dimm, "dimm_ue_count"), 0)
            result[f"{mcname}/{os.path.basename(dimm)}"] = (label, ce, ue)
        # Some EDAC drivers expose only controller/csrow totals. Account for
        # errors missing from DIMM counters before relying on this monitor.
        dimm_ce = sum(v[1] for k, v in result.items() if k.startswith(mcname + "/"))
        dimm_ue = sum(v[2] for k, v in result.items() if k.startswith(mcname + "/"))
        ce = max(read_int(os.path.join(mc, "ce_noinfo_count"), 0),
                 read_int(os.path.join(mc, "ce_count"), 0) - dimm_ce)
        ue = max(read_int(os.path.join(mc, "ue_noinfo_count"), 0),
                 read_int(os.path.join(mc, "ue_count"), 0) - dimm_ue)
        result[f"{mcname}/noinfo"] = (f"{mcname} (DIMM unknown)", ce, ue)
    return result


class EdacMonitor(Monitor):
    interval = 20.0

    def available(self):
        return bool(glob.glob("/sys/devices/system/edac/mc/mc[0-9]*"))

    def poll(self):
        seen = self.ctx.session.per_boot_counters("edac")
        for key, (label, ce, ue) in edac_counts().items():
            prev_ce, prev_ue = seen.get(key, (0, 0))
            if ce > prev_ce:
                f = self.ctx.findings.add(
                    f"memory-ce:{label}", WARN, "Memory", f"Corrected memory errors (ECC) on {label}",
                    detail="The memory controller corrected bit errors. New DIMMs should not produce any "
                           "corrected errors under stress; this DIMM is likely to fail in production.",
                    recommendation=REC_MEMORY, count=ce - prev_ce,
                    evidence=[f"{now_iso()} {label}: ce_count {prev_ce} -> {ce}"])
                if f.count >= self.ctx.opts.ce_fail:
                    self.ctx.findings.escalate(f.key, FAIL)
            if ue > prev_ue:
                self.ctx.findings.add(
                    f"memory-ue:{label}", FAIL, "Memory", f"Uncorrectable memory errors on {label}",
                    recommendation=REC_MEMORY, count=ue - prev_ue,
                    evidence=[f"{now_iso()} {label}: ue_count {prev_ue} -> {ue}"])
            with self.ctx.session.lock:
                seen[key] = (ce, ue)


# --------------------------------------------------------------------------- PCIe AER

def parse_aer_file(text):
    counts = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            counts[parts[0]] = int(parts[1])
    return counts


def pci_name(bdf):
    text = out(["lspci", "-s", bdf], timeout=10).strip()
    return text.split(" ", 1)[1] if " " in text else bdf


class AerMonitor(Monitor):
    interval = 30.0

    def available(self):
        return bool(glob.glob("/sys/bus/pci/devices/*/aer_dev_correctable"))

    def poll(self):
        seen = self.ctx.session.per_boot_counters("aer")
        for path in glob.glob("/sys/bus/pci/devices/*"):
            bdf = os.path.basename(path)
            for kind, total_key, severity in (("correctable", "TOTAL_ERR_COR", WARN),
                                              ("nonfatal", "TOTAL_ERR_NONFATAL", FAIL),
                                              ("fatal", "TOTAL_ERR_FATAL", FAIL)):
                counts = parse_aer_file(read_file(os.path.join(path, f"aer_dev_{kind}")))
                if not counts:
                    continue
                total = counts.get(total_key, 0)
                prev = seen.get(f"{bdf}:{kind}", 0)
                if total > prev:
                    details = ", ".join(f"{k}={v}" for k, v in counts.items() if v and not k.startswith("TOTAL"))
                    if kind == "correctable":
                        key, title = f"aer-corrected:{bdf}", f"Corrected PCIe errors on {bdf} {pci_name(bdf)}"
                    else:
                        key, title = f"aer-uncorrected:{bdf}", f"Uncorrected PCIe errors on {bdf} {pci_name(bdf)}"
                    f = self.ctx.findings.add(key, severity, "PCIe", title, recommendation=REC_PCIE,
                                              count=total - prev, evidence=[f"{now_iso()} {kind}: {details}"])
                    if kind == "correctable" and f.count >= self.ctx.opts.aer_fail:
                        self.ctx.findings.escalate(key, FAIL)
                with self.ctx.session.lock:
                    seen[f"{bdf}:{kind}"] = total


# --------------------------------------------------------------------------- thermal throttling

def throttle_counts():
    total = {"core": 0, "package": 0}
    for cpu in glob.glob("/sys/devices/system/cpu/cpu[0-9]*/thermal_throttle"):
        total["core"] += read_int(os.path.join(cpu, "core_throttle_count"), 0)
        # package counters are replicated on every CPU of the package; take the max per package
    packages = {}
    for cpu in glob.glob("/sys/devices/system/cpu/cpu[0-9]*"):
        pkg = read_file(os.path.join(cpu, "topology/physical_package_id")).strip()
        cnt = read_int(os.path.join(cpu, "thermal_throttle/package_throttle_count"), 0)
        packages[pkg] = max(packages.get(pkg, 0), cnt)
    total["package"] = sum(packages.values())
    return total


class ThrottleMonitor(Monitor):
    interval = 30.0

    def available(self):
        return bool(glob.glob("/sys/devices/system/cpu/cpu0/thermal_throttle"))

    def poll(self):
        seen = self.ctx.session.per_boot_counters("throttle")
        counts = throttle_counts()
        delta = sum(max(0, counts[k] - seen.get(k, 0)) for k in counts)
        if delta > 0:
            self.ctx.findings.add(
                "thermal-throttle", WARN, "Thermal", "CPU thermal throttling occurred",
                detail="The CPU reduced its speed because it reached its temperature limit. Under production "
                       "load this costs performance and indicates marginal cooling.",
                recommendation=REC_THERMAL, count=delta,
                evidence=[f"{now_iso()} core_throttle_count={counts['core']} package_throttle_count={counts['package']} "
                          f"(phase {self.ctx.findings.current_phase})"])
        with self.ctx.session.lock:
            seen.update(counts)


# --------------------------------------------------------------------------- lm-sensors

def parse_sensors_json(data):
    """Flatten `sensors -j` into a list of dicts: chip, label, kind, value, max, crit, alarm."""
    readings = []
    for chip, features in (data or {}).items():
        if not isinstance(features, dict):
            continue
        for label, values in features.items():
            if not isinstance(values, dict):
                continue
            for name, value in values.items():
                m = re.match(r"(temp|fan|in|power|curr)(\d+)_input$", name)
                if not m or not isinstance(value, (int, float)):
                    continue
                prefix = f"{m.group(1)}{m.group(2)}"
                readings.append({
                    "chip": chip, "label": label, "kind": m.group(1), "value": float(value),
                    "max": values.get(f"{prefix}_max"), "crit": values.get(f"{prefix}_crit"),
                    "alarm": bool(values.get(f"{prefix}_alarm") or values.get(f"{prefix}_crit_alarm")),
                })
    return readings


CPU_CHIPS = ("coretemp", "k10temp", "zenpower", "cpu_thermal")
DRIVE_CHIPS = ("nvme", "drivetemp")


def classify_chip(chip):
    if chip.startswith(CPU_CHIPS):
        return "cpu"
    if chip.startswith(DRIVE_CHIPS):
        return "drive"
    return "board"


class SensorMonitor(Monitor):
    """Temperatures from lm-sensors; keeps maxima for the report and the live dashboard."""

    interval = 15.0

    def __init__(self, ctx):
        super().__init__(ctx)
        self.current = {}   # group -> current max
        self.peaks = ctx.session.state.setdefault("telemetry_peaks", {})

    def available(self):
        return have("sensors")

    def poll(self):
        res = run(["sensors", "-j"], timeout=30)
        if res.returncode != 0 or not res.stdout.strip():
            raise RuntimeError("sensors did not return telemetry")
        try:
            data = json.loads(res.stdout)
        except ValueError as exc:
            raise RuntimeError("Invalid sensors JSON") from exc
        current = {}
        opts = self.ctx.opts
        for r in parse_sensors_json(data):
            if r["kind"] != "temp" or r["value"] <= -40 or r["value"] >= 200:
                continue
            group = classify_chip(r["chip"])
            name = f"{r['chip']}/{r['label']}"
            current[group] = max(current.get(group, -999), r["value"])
            with self.ctx.session.lock:
                self.peaks[name] = max(self.peaks.get(name, -999), r["value"])
            crit = r["crit"] if isinstance(r["crit"], (int, float)) and 20 < r["crit"] < 150 else None
            high = r["max"] if isinstance(r["max"], (int, float)) and 20 < r["max"] < 150 else None
            if crit and r["value"] >= crit:
                self.ctx.findings.add(f"temp-crit:{name}", FAIL, "Thermal", f"Critical temperature on {name}",
                                      recommendation=REC_THERMAL,
                                      evidence=[f"{now_iso()} {r['value']:.0f}C (crit {crit:.0f}C) phase {self.ctx.findings.current_phase}"])
                self.ctx.request_abort(f"Critical temperature on {name}")
            elif (high and r["value"] >= high) or (
                    not high and not crit and group == "cpu" and r["value"] >= opts.cpu_temp_warn) or (
                    not high and not crit and group == "drive" and r["value"] >= opts.drive_temp_warn):
                limit = high or (opts.cpu_temp_warn if group == "cpu" else opts.drive_temp_warn)
                self.ctx.findings.add(f"temp-high:{name}", WARN, "Thermal", f"High temperature on {name}",
                                      recommendation=REC_THERMAL,
                                      evidence=[f"{now_iso()} {r['value']:.0f}C (limit {limit:.0f}C) phase {self.ctx.findings.current_phase}"])
        self.current = current
        if not current:
            self.ctx.findings.add("sensors-empty", WARN, "Thermal", "No usable temperature sensors reported")


# --------------------------------------------------------------------------- IPMI (BMC)

SEL_FAIL = re.compile(r"Uncorrectable|Machine Check|IERR|Thermal Trip|Critical Interrupt|Bus Fatal|Bus Uncorrectable|"
                      r"PCI SERR|PCI PERR|Fatal|Failure detected|Power Supply AC lost|AC lost|Predictive failure|"
                      r"Watchdog.*(?:Hard reset|Power down|Power cycle)|CATERR|Processor.*Error|Drive Fault|"
                      r"Configuration Error|Non-recoverable|Lower Non-recoverable|Upper Non-recoverable|"
                      r"Upper Critical going high|Lower Critical going low", re.I)
SEL_WARN = re.compile(r"Correctable|Redundancy Lost|Redundancy Degraded|Non-critical going|Upper Non-critical|"
                      r"Lower Non-critical|Throttl|Presence detected.*Deasserted|Power off|Power down|"
                      r"System Restart|OS Stop|Timestamp Clock Sync", re.I)
SEL_IGNORE = re.compile(r"Log area reset|Log area cleared|Event Logging Disabled.*Log area|Initiated by power up|"
                        r"Initiated by hard reset|Initiated by warm reset|System Boot|OEM record", re.I)


def classify_sel(line):
    if "Deasserted" in line and not SEL_FAIL.search(line):
        return None
    if SEL_IGNORE.search(line):
        return INFO
    if SEL_FAIL.search(line):
        return FAIL
    if SEL_WARN.search(line):
        return WARN
    return INFO


def parse_sdr(text):
    """ipmitool sdr elist -> list of (name, status, reading)."""
    rows = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 5:
            rows.append((parts[0], parts[2].lower(), parts[4]))
    return rows


SDR_FAIL = {"cr", "nr", "lcr", "ucr", "lnr", "unr"}
SDR_WARN = {"nc", "lnc", "unc"}


class IpmiMonitor(Monitor):
    interval = 60.0

    def __init__(self, ctx):
        super().__init__(ctx)
        self.polls = 0

    def available(self):
        return have("ipmitool") and bool(glob.glob("/dev/ipmi*"))

    def sel_lines(self):
        res = run(["ipmitool", "sel", "elist"], timeout=180)
        if res.returncode != 0:
            raise RuntimeError(f"Cannot read BMC SEL: {res.stderr.strip()}")
        return [l.strip() for l in res.stdout.splitlines() if "|" in l]

    def baseline(self):
        """Classify SEL entries that existed before the test (historic, severity lowered one step)."""
        base = self.ctx.session.state.setdefault("baselines", {})
        if "sel_hashes" in base:
            return
        lines = self.sel_lines()
        base["sel_hashes"] = [hashlib.sha1(l.split("|", 1)[-1].encode()).hexdigest()[:16] for l in lines]
        historic = [l for l in lines if classify_sel(l) in (FAIL, WARN)]
        if historic:
            worst = FAIL if any(classify_sel(l) == FAIL for l in historic) else WARN
            self.ctx.findings.add(
                "sel-historic", WARN if worst == FAIL else INFO, "BMC",
                f"{len(historic)} hardware events already in the BMC event log before the test",
                detail="These happened before PC-Check started (e.g. in the factory, in transit or a previous "
                       "deployment). Review them: memory/CPU/PSU events often point at the component that will fail.",
                recommendation="Review the events; clear the SEL after resolving them so future runs start clean.",
                evidence=historic[-25:])
        self.ctx.session.save()

    def poll(self):
        self.polls += 1
        self.baseline()
        base = self.ctx.session.state["baselines"]
        known = set(base.get("sel_hashes", []))
        new_hashes = []
        for line in self.sel_lines():
            h = hashlib.sha1(line.split("|", 1)[-1].encode()).hexdigest()[:16]
            if h in known:
                continue
            new_hashes.append(h)
            known.add(h)
            sev = classify_sel(line)
            if sev is None or sev == INFO:
                self.ctx.findings.add("sel-info", INFO, "BMC", "Informational BMC events during the test",
                                      evidence=[line], count=1)
                continue
            fields = [p.strip() for p in line.split("|")]
            sensor = fields[3] if len(fields) > 3 else "event"
            event = fields[4] if len(fields) > 4 else line
            finding = self.ctx.findings.add(f"sel:{sensor}:{event}", sev, "BMC",
                                  f"BMC event during test: {sensor} - {event}",
                                  recommendation="Check the component named by the sensor (DIMM/CPU/PSU/fan).",
                                  evidence=[line])
            if sev == WARN and re.search(r"Correctable.*ECC|Correctable.*memory", line, re.I):
                if finding.count >= self.ctx.opts.ce_fail:
                    self.ctx.findings.escalate(finding.key, FAIL)
        if new_hashes:
            with self.ctx.session.lock:
                base.setdefault("sel_hashes", []).extend(new_hashes)
            self.ctx.session.save()

        res = run(["ipmitool", "sdr", "elist"], timeout=180)
        if res.returncode != 0:
            raise RuntimeError(f"Cannot read BMC sensors: {res.stderr.strip()}")
        for name, status, reading in parse_sdr(res.stdout):
            if status in SDR_FAIL:
                self.ctx.findings.add(f"sdr:{name}", FAIL, "BMC", f"BMC sensor critical: {name}",
                                      evidence=[f"{now_iso()} {name}: {status} {reading}"])
            elif status in SDR_WARN:
                self.ctx.findings.add(f"sdr:{name}", WARN, "BMC", f"BMC sensor non-critical: {name}",
                                      evidence=[f"{now_iso()} {name}: {status} {reading}"])


# --------------------------------------------------------------------------- NIC error counters

NIC_COUNTERS = ("rx_crc_errors", "rx_frame_errors", "rx_length_errors", "rx_fifo_errors",
                "tx_carrier_errors", "tx_aborted_errors", "tx_fifo_errors", "tx_heartbeat_errors")


def physical_nics():
    return sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob("/sys/class/net/*/device"))


class NicMonitor(Monitor):
    interval = 120.0

    def available(self):
        return bool(physical_nics())

    def poll(self):
        seen = self.ctx.session.per_boot_counters("nic")
        if uptime() < 90:  # links are still negotiating
            return
        for nic in physical_nics():
            base = f"/sys/class/net/{nic}"
            if read_file(f"{base}/operstate").strip() != "up":
                continue
            values = {c: read_int(f"{base}/statistics/{c}", 0) for c in NIC_COUNTERS}
            values["carrier_changes"] = read_int(f"{base}/carrier_changes", 0)
            if nic not in seen:
                with self.ctx.session.lock:
                    seen[nic] = values
                continue
            prev = seen[nic]
            errors = {k: values[k] - prev.get(k, 0) for k in NIC_COUNTERS if values[k] > prev.get(k, 0)}
            flaps = values["carrier_changes"] - prev.get("carrier_changes", 0)
            if errors:
                self.ctx.findings.add(f"nic-errors:{nic}", WARN, "Network", f"Network errors on {nic}",
                                      recommendation="Check/replace cable, transceiver or switch port; then the NIC.",
                                      count=sum(errors.values()),
                                      evidence=[f"{now_iso()} " + ", ".join(f"{k}+{v}" for k, v in errors.items())])
            if flaps > 0:
                self.ctx.findings.add(f"nic-flap:{nic}", WARN, "Network", f"Link flapped on {nic}",
                                      recommendation="Check cable/transceiver/switch port; then the NIC.",
                                      count=flaps, evidence=[f"{now_iso()} carrier_changes +{flaps}"])
            with self.ctx.session.lock:
                seen[nic] = values


# --------------------------------------------------------------------------- heartbeat & telemetry

class Heartbeat(Monitor):
    """Persists liveness, telemetry and progress so a reset can be diagnosed afterwards."""

    interval = 30.0

    def __init__(self, ctx, sensors):
        super().__init__(ctx)
        self.sensors = sensors
        self.csv = ctx.session.path("logs", "telemetry.csv")
        if not os.path.exists(self.csv):
            append_line(self.csv, "time,uptime_s,phase,cpu_temp_c,drive_temp_c,board_temp_c,load1,mem_available_mib")

    def poll(self):
        ctx = self.ctx
        mi = meminfo()
        load1 = os.getloadavg()[0]
        temps = self.sensors.current if self.sensors else {}
        telemetry = {
            "time": now_iso(), "uptime": round(uptime()), "phase": ctx.findings.current_phase,
            "cpu_temp": temps.get("cpu"), "drive_temp": temps.get("drive"), "board_temp": temps.get("board"),
            "load1": round(load1, 1), "mem_available_mib": mi.get("MemAvailable", 0) // 2**20,
        }
        ctx.telemetry = telemetry

        def fmt(v):
            return "" if v is None else f"{v:.0f}" if isinstance(v, float) else str(v)

        append_line(self.csv, ",".join(fmt(telemetry[k]) for k in
                                       ("time", "uptime", "phase", "cpu_temp", "drive_temp", "board_temp",
                                        "load1", "mem_available_mib")), sync=True)
        if ctx.disk_manager:
            ctx.disk_manager.save_progress()
        ctx.findings.flush()
        ctx.session.update(last_heartbeat=telemetry["time"], telemetry=telemetry)
        ctx.write_status()
