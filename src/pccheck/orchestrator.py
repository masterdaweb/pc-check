"""Test orchestration: session resume, phase sequencing, final analysis."""

import functools
import http.server
import logging
import os
import socketserver
import sys
import threading
import time

from . import PRODUCT, __version__, inventory, report
from .config import build_plan, load_options
from .disks import DiskManager, block_disks, disk_id
from .findings import FAIL, INFO, WARN, Findings
from .inventory import check_pcie_links, check_taint, collect_pstore, parse_pcie_links
from .kmsg import KmsgMonitor
from .monitors import (AerMonitor, EdacMonitor, Heartbeat, IpmiMonitor, Monitor, NicMonitor, SensorMonitor,
                       ThrottleMonitor)
from .phases import PHASES, TITLES
from .ras import RasMonitor
from .session import Session, machine_identity
from .storage import setup_storage
from .util import ManagedProcess, append_line, atomic_write_json, have, now_iso, out, run, fmt_duration

log = logging.getLogger("pccheck")

RUN_DIR = "/run/pccheck"
STATUS_FILE = os.path.join(RUN_DIR, "status.json")
ABORT_FILE = os.path.join(RUN_DIR, "abort")


class Context:
    def __init__(self):
        self.opts = None
        self.storage = None
        self.session = None
        self.findings = Findings()
        self.boot_disk = ""
        self.sysfs_counters = set()
        self.abort_event = threading.Event()
        self.disk_manager = None
        self.current_phase = None
        self.status_note = ""
        self.telemetry = {}
        self.started_wall = time.time()
        self.final_verdict = None
        self.scroll = 0
        self.dashboard = None
        self.pending_confirmation = None
        self.monitors = []
        self.reboot_request = None

    def request_abort(self, reason):
        if not self.abort_event.is_set():
            log.warning("abort requested: %s", reason)
            self.status_note = f"ABORTING: {reason}"
            if self.session:
                self.session.update(abort_reason=reason)
            self.abort_event.set()

    def request_reboot(self, cycle):
        """Ask the orchestrator to reboot on purpose; the next boot must not count it as a crash."""
        self.reboot_request = cycle
        with self.session.lock:
            self.session.state["planned_reboot"] = {"cycle": cycle, "requested_epoch": time.time(),
                                                    "requested_at": now_iso()}
        self.session.save()

    def remaining_estimate(self):
        if not self.session:
            return 0
        total = 0.0
        st = self.session.state
        for p in st.get("plan", []):
            status = st["phases"].get(p["name"], {}).get("status")
            if status == "pending":
                total += p["duration"]
            elif status == "running" and self.current_phase is not None:
                total += self.current_phase.remaining
        return total

    def write_status(self):
        if not self.session:
            return
        st = self.session.state
        status = {
            "time": now_iso(), "session_dir": self.session.dir, "status": st.get("status"),
            "profile": st.get("profile"), "phase": self.findings.current_phase, "note": self.status_note,
            "remaining_seconds": int(self.remaining_estimate()), "unexpected_reboots": st.get("unexpected_reboots", 0),
            "findings": self.findings.counts(), "verdict": self.final_verdict, "telemetry": self.telemetry,
            "phases": {k: v.get("status") for k, v in st.get("phases", {}).items()},
            "plan": [p["name"] for p in st.get("plan", [])],
            "step_progress": round(self.current_phase.progress() or 0, 3) if self.current_phase else None,
            "top_findings": [f"{f.severity} {f.component}: {f.title}" + (f" (x{f.count})" if f.count > 1 else "")
                             for f in self.findings.all() if f.severity != INFO][:10],
            "identity": {k: st.get("identity", {}).get(k) for k in ("system_manufacturer", "system_product", "display_serial")},
        }
        try:
            atomic_write_json(STATUS_FILE, status)
        except OSError:
            pass


# --------------------------------------------------------------------------- web server

class _Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path in ("/status.json", "/status"):
            data = open(STATUS_FILE, "rb").read() if os.path.exists(STATUS_FILE) else b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/":
            session = self.server.ctx.session
            if session:
                rel = os.path.relpath(session.dir, self.directory)
                target = f"/{rel}/report.html" if os.path.exists(os.path.join(session.dir, "report.html")) else f"/{rel}/"
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
                return
        super().do_GET()


def start_http(ctx):
    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    try:
        handler = functools.partial(_Handler, directory=ctx.session.base)
        server = Server(("", 80), handler)
        server.ctx = ctx
    except OSError as exc:
        log.warning("web server not started: %s", exc)
        return
    threading.Thread(target=server.serve_forever, name="http", daemon=True).start()


# --------------------------------------------------------------------------- orchestration

def setup_logging():
    os.makedirs(RUN_DIR, exist_ok=True)
    logger = logging.getLogger("pccheck")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(threadName)s: %(message)s")
    handler = logging.FileHandler(os.path.join(RUN_DIR, "pccheck.log"))
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    # journal (stderr of the service) for errors
    err = logging.StreamHandler(sys.stderr)
    err.setLevel(logging.WARNING)
    err.setFormatter(fmt)
    logger.addHandler(err)
    return fmt


def maintenance_screen():
    sys.stdout.write("\033[H\033[2J")
    sys.stdout.write(f"{PRODUCT} {__version__} - maintenance mode (pccheck.auto=0)\n\n"
                     "No tests will run. Press Alt+F2 for a root shell.\n"
                     "Start a test manually from the shell with:  systemctl restart pccheck  "
                     "after removing pccheck.auto=0, or run:  pccheck run --force\n")
    sys.stdout.flush()
    while True:
        time.sleep(3600)


def start_monitors(ctx):
    sensors = SensorMonitor(ctx)
    candidates = [
        (EdacMonitor(ctx), "edac"), (AerMonitor(ctx), "aer"), (ThrottleMonitor(ctx), "throttle"),
        (sensors, None), (IpmiMonitor(ctx), None), (NicMonitor(ctx), None), (RasMonitor(ctx), None),
    ]
    for mon, counter in candidates:
        if mon.available():
            if counter:
                ctx.sysfs_counters.add(counter)
            mon.start()
            ctx.monitors.append(mon)
        else:
            log.info("monitor %s not available on this hardware", mon.name)
    if not sensors.available():
        sensors = None
    hb = Heartbeat(ctx, sensors)
    hb.start()
    ctx.monitors.append(hb)


def start_turbostat(ctx):
    if not have("turbostat"):
        return None
    try:
        return ManagedProcess(["turbostat", "--quiet", "--Summary", "--interval", "60",
                               "--show", "Time_Of_Day_Seconds,Busy%,Bzy_MHz,PkgTmp,PkgWatt,RAMWatt,CPU%c1,CPU%c6,Pkg%pc2,Pkg%pc6"],
                              ctx.session.path("logs", "turbostat.log"), low_priority=False)
    except OSError:
        return None


def record_incident(ctx):
    s = ctx.session
    prev = s.previous_state or {}
    if s.unexpected_reboot:
        phase = prev.get("running_phase")
        incident = {"type": "unexpected reboot", "detected_at": now_iso(), "running_phase": phase,
                    "last_heartbeat": prev.get("last_heartbeat"), "last_telemetry": prev.get("telemetry")}
        with s.lock:
            s.state.setdefault("incidents", []).append(incident)
        tel = prev.get("telemetry") or {}
        ctx.findings.add(
            f"unexpected-reboot-{s.state['unexpected_reboots']}", FAIL, "System",
            f"Machine reset unexpectedly during '{TITLES.get(phase, phase or 'unknown')}'",
            detail="The system rebooted or lost power while the test was running. This is exactly the failure seen in "
                   "production. Correlate with the crash log (pstore), BMC events and the last telemetry below: high "
                   "temperatures suggest cooling; heavy-load phases suggest PSU/VRM or CPU; idle/transient phases "
                   "suggest power delivery or C-state problems; memory phases suggest DIMMs.",
            recommendation="Check the PSU and power cabling, CPU/VRM cooling, reseat DIMMs/CPU, update BIOS; "
                           "swap components one at a time and re-run the test.",
            evidence=[f"last heartbeat {prev.get('last_heartbeat')} (up to 30 s before the reset)",
                      f"last telemetry: CPU {tel.get('cpu_temp')}C, drives {tel.get('drive_temp')}C, "
                      f"load {tel.get('load1')}, phase {tel.get('phase')}"],
            phase=phase or "")
        if phase == "inventory":
            s.set_phase(phase, status="pending")  # nothing was stressed yet; collect inventory again
        elif phase:
            s.set_phase(phase, status="interrupted", result="machine reset")
    elif s.planned_reboot:
        ctx.findings.add("powercycle-progress", INFO, "System",
                         f"Resumed after planned reboot #{s.state.get('reboot_cycles_done')}")
    elif s.orchestrator_restart:
        phase = prev.get("running_phase")
        ctx.findings.add("orchestrator-restart", WARN, "Test", "Test software restarted (not a hardware reboot)",
                         evidence=[f"during phase {phase}"])
        if phase == "inventory":
            s.set_phase(phase, status="pending")
        elif phase:
            s.set_phase(phase, status="error", result="orchestrator restarted")
    s.save()


def confirm_destructive(ctx, disks):
    """Countdown on screen; the operator can cancel with 'n'."""
    ctx.pending_confirmation = threading.Event()
    names = ", ".join(f"{d['name']} ({d['model']} {d['size'] // 10**9} GB)" for d in disks)
    end = time.monotonic() + ctx.opts.destructive_countdown
    while time.monotonic() < end:
        if ctx.abort_event.is_set():
            ctx.pending_confirmation = None
            return False
        ctx.status_note = (f"DESTRUCTIVE write test will ERASE: {names} - starts in "
                           f"{int(end - time.monotonic())}s, press 'n' to cancel")
        if ctx.pending_confirmation.wait(1):
            ctx.pending_confirmation = None
            ctx.status_note = "destructive test cancelled by operator; read-only scan instead"
            ctx.findings.add("destructive-cancelled", INFO, "Storage", "Destructive disk test cancelled by operator")
            return False
    ctx.pending_confirmation = None
    return not ctx.abort_event.is_set()


def run_inventory_phase(ctx):
    ctx.status_note = "collecting inventory"
    inventory.run_inventory(ctx)
    if ctx.opts.reboot_cycles and not ctx.session.state.get("powercycle_baseline"):
        ctx.session.update(powercycle_baseline=PHASES["powercycle"](ctx, 0).snapshot())
    dm = ctx.disk_manager
    ctx.status_note = "reading SMART data"
    dm.smart_baseline()
    dm.start_selftests(ctx.opts.profile_info["long_selftest"])


def start_disk_tests(ctx):
    dm = ctx.disk_manager
    st = ctx.session.state
    if st.get("disk_tests_finished"):
        return
    destructive = []
    if "destructive_disks" not in st:
        chosen = []
        identities = {}
        if ctx.opts.is_destructive:
            eligible, skipped = dm.destructive_candidates(block_disks(dm.exclude))
            for d in skipped:
                ctx.findings.add(f"destructive-skip:{d['name']}", WARN, "Storage",
                                 f"Destructive test skipped on {d['name']} {d['model']}: existing data, "
                                 "active use, or incomplete safety discovery", incomplete=True)
            if eligible and confirm_destructive(ctx, eligible):
                chosen = [d["name"] for d in eligible]
                identities = {disk_id(d): d["size"] for d in eligible}
        ctx.session.update(destructive_disks=chosen, destructive_identities=identities)
    identities = st.get("destructive_identities", {})
    destructive = [d for d in block_disks(dm.exclude) if identities.get(disk_id(d)) == d["size"]]
    dm.start_scans(destructive)


def perform_reboot(ctx):
    """Flush everything to the USB stick, then reboot (warm) or power cycle through the BMC."""
    cycle = ctx.reboot_request
    log.warning("planned reboot #%s", cycle)
    ctx.findings.flush(force=True)
    if ctx.disk_manager:
        ctx.disk_manager.pause()
        ctx.disk_manager.save_progress()
    ctx.session.save()
    for mon in ctx.monitors:
        mon.stop()
    os.sync()
    time.sleep(2)
    method = ctx.opts.reboot_method
    use_ipmi = method == "ipmi" or (method == "auto" and os.path.exists("/dev/ipmi0"))
    if use_ipmi:
        res = run(["ipmitool", "chassis", "power", "cycle"], timeout=60)
        if res.returncode == 0:
            time.sleep(120)  # the BMC cuts power; if it does not, fall through to a warm reboot
        else:
            log.error("ipmitool power cycle failed: %s", res.stderr.strip())
    run(["systemctl", "reboot"], timeout=60)
    time.sleep(300)
    run(["reboot", "-f"], timeout=60)


def run_phases(ctx):
    s = ctx.session
    for p in s.state["plan"]:
        name = p["name"]
        ps = s.phase_state(name)
        if ps.get("status") not in ("pending",):
            continue
        if ctx.abort_event.is_set():
            break
        if s.state.get("unexpected_reboots", 0) >= ctx.opts.max_unexpected_reboots:
            s.set_phase(name, status="skipped", result="too many unexpected reboots")
            continue
        ctx.findings.current_phase = name
        if name == "powercycle" and not s.state.get("disk_tests_finished"):
            # Planned power cycles must not abort the drive self-tests we intend to validate.
            finish_disk_tests(ctx)
            if ctx.abort_event.is_set():
                break
        start_wall = time.time()
        s.set_phase(name, status="running", started=now_iso())
        log.info("phase %s started (%s)", name, fmt_duration(p["duration"]))
        try:
            if name == "inventory":
                run_inventory_phase(ctx)
                start_disk_tests(ctx)
            else:
                phase = PHASES[name](ctx, p["duration"])
                ctx.current_phase = phase
                phase.run()
        except Exception as exc:
            log.exception("phase %s crashed", name)
            ctx.findings.add(f"phase-error:{name}", WARN, "Test", f"Internal error in phase {name}: {exc}",
                             incomplete=True)
            s.set_phase(name, status="error", elapsed=int(time.time() - start_wall), result=str(exc)[:200])
            continue
        finally:
            ctx.current_phase = None
            ctx.status_note = ""
        if ctx.reboot_request:
            s.set_phase(name, status="pending", elapsed=int(time.time() - start_wall))
            perform_reboot(ctx)
            return
        phase_findings = ctx.findings.by_phase(name)
        if ctx.abort_event.is_set():
            status = "aborted"
        elif any(f.incomplete for f in phase_findings):
            status = "error"
        elif any(f.severity == FAIL for f in phase_findings):
            status = "failed"
        elif any(f.severity == WARN for f in phase_findings):
            status = "warn"
        else:
            status = "done"
        s.set_phase(name, status=status, elapsed=int(time.time() - start_wall), finished=now_iso(),
                    result=f"{sum(f.severity == FAIL for f in phase_findings)} fail, "
                           f"{sum(f.severity == WARN for f in phase_findings)} warn")
        log.info("phase %s finished: %s", name, status)


def finish_disk_tests(ctx):
    aborted = ctx.abort_event.is_set()
    dm = ctx.disk_manager
    if dm and not aborted:
        wait = ctx.opts.profile_info["disk_wait_hours"] * 3600
        end = time.monotonic() + wait
        while not dm.all_done() and time.monotonic() < end and not ctx.abort_event.is_set():
            ctx.status_note = f"waiting for disk scans to finish (max {fmt_duration(end - time.monotonic())})"
            time.sleep(10)
    aborted = ctx.abort_event.is_set()
    if dm:
        ctx.status_note = "stopping disk tests"
        dm.stop()
        ctx.status_note = "collecting final SMART data"
        dm.smart_final(0 if aborted else (600 if ctx.opts.profile == "quick" else 1800))
    ctx.session.update(disk_tests_finished=True)


def finalize(ctx):
    s = ctx.session
    ctx.findings.current_phase = "final"
    if not s.state.get("disk_tests_finished"):
        finish_disk_tests(ctx)
    elif ctx.disk_manager:
        ctx.disk_manager.smart_final(0)  # also check health changes introduced by planned reboot cycles
    ctx.status_note = "final hardware checks"
    for mon in ctx.monitors:
        if not isinstance(mon, Monitor):
            continue
        try:
            mon.sample()  # serialized with the background poll: no double counting
            if isinstance(mon, RasMonitor):
                mon.export()
        except Exception:
            log.exception("final poll of %s failed", mon.name)
            ctx.findings.add(f"monitor-final:{mon.name}", WARN, "Test",
                             f"Final monitoring evidence unavailable: {mon.name}", incomplete=True)
    pci_result = run(["lspci", "-vvv", "-nn"], timeout=120)
    links_now = parse_pcie_links(pci_result.stdout)
    baseline_links = s.state.get("baselines", {}).get("pcie_links")
    if pci_result.returncode != 0:
        ctx.findings.add("pcie-final-unavailable", WARN, "Test",
                         "Final PCIe inventory could not be read", incomplete=True)
    elif baseline_links:
        check_pcie_links(links_now, ctx.findings, baseline=baseline_links)
    check_taint(ctx.findings, start_taint=s.state.get("baselines", {}).get("taint", 0))
    logs = s.path("logs")
    for name, cmd in (("ras-mc-ctl-summary.txt", ["ras-mc-ctl", "--summary"]),
                      ("ras-mc-ctl-errors.txt", ["ras-mc-ctl", "--errors"]),
                      ("dmesg-final.txt", ["dmesg", "-T"]),
                      ("ipmi-sel-final.txt", ["ipmitool", "sel", "elist"]),
                      ("journal.txt", ["journalctl", "-b", "--no-pager"])):
        if cmd[0] == "ipmitool" and not os.path.exists("/dev/ipmi0"):
            continue
        with open(os.path.join(logs, name), "w") as fh:
            fh.write(run(cmd, timeout=300).stdout)
    for mon in ctx.monitors:
        mon.stop()
    for mon in ctx.monitors:
        mon.join(timeout=5)
    aborted = ctx.abort_event.is_set()
    ctx.findings.flush(force=True)
    s.finish("aborted" if aborted else "complete")
    result, text = report.write_reports(s.dir, incomplete=aborted)
    append_line(os.path.join(s.base, "index.csv"),
                f"{now_iso()},{s.state['identity'].get('display_serial')},{s.state['identity'].get('system_product')},"
                f"{s.state.get('profile')},{result},{s.state['session']}", sync=True)
    if result == FAIL and ctx.opts.identify and os.path.exists("/dev/ipmi0"):
        run(["ipmitool", "chassis", "identify", "force"], timeout=30)
    os.sync()
    if ctx.dashboard:
        ctx.dashboard.final_text = text
    ctx.final_verdict = result
    ctx.status_note = ""
    ctx.write_status()
    return result, text


def main(force=False):
    fmt = setup_logging()
    ctx = Context()
    ctx.opts = load_options()
    if not ctx.opts.auto and not force:
        maintenance_screen()
        return 0

    sys.stdout.write(f"\033[H\033[2J{PRODUCT} {__version__}\n\nPreparing log storage and identifying hardware...\n")
    sys.stdout.flush()
    ctx.storage = setup_storage()
    ctx.boot_disk = ctx.storage.boot_disk
    ctx.opts = load_options(ctx.storage.root if ctx.storage.persistent else None)
    if not ctx.opts.auto and not force:
        maintenance_screen()
        return 0
    identity = machine_identity()
    plan = build_plan(ctx.opts)
    ctx.session = Session.open(ctx.storage.root, identity, ctx.opts, plan)
    s = ctx.session
    # A resumed session keeps its original profile and thresholds.
    for key, value in s.state.get("options", {}).items():
        if hasattr(ctx.opts, key):
            setattr(ctx.opts, key, tuple(value) if isinstance(value, list) else value)

    handler = logging.FileHandler(s.path("logs", "pccheck.log"))
    handler.setFormatter(fmt)
    logging.getLogger("pccheck").addHandler(handler)
    log.info("%s %s session %s (resumed=%s)", PRODUCT, __version__, s.state["session"], s.resumed)

    ctx.findings = Findings(s.path("findings.json"))
    for problem in ctx.opts.validation_errors:
        ctx.findings.add(f"config:{problem}", WARN, "Test", f"Invalid test configuration: {problem}",
                         incomplete=True)
    ctx.started_wall = time.time()
    if not ctx.storage.persistent:
        ctx.findings.add("storage-ram", WARN, "Test", "Logs are kept in RAM only",
                         detail=ctx.storage.note,
                         recommendation="Prepare the USB stick with write-usb.sh so it has a PCCHECKDATA partition.",
                         incomplete=True)
    record_incident(ctx)

    from .dashboard import Dashboard, KeyReader
    ctx.dashboard = Dashboard(ctx)
    ctx.dashboard.start()
    KeyReader(ctx).start()
    if ctx.opts.http:
        start_http(ctx)

    kmsg = KmsgMonitor(ctx)
    ctx.disk_manager = DiskManager(ctx)
    start_monitors(ctx)   # decides which sysfs counters own counts before kmsg rules run
    kmsg.start()
    ctx.monitors.append(kmsg)
    collect_pstore(s.path("logs", "pstore"), ctx.findings, s, persistent=ctx.storage.persistent)
    turbostat = start_turbostat(ctx)

    def status_loop():
        """Live status for `pccheck status` / http, and the `pccheck abort` request file."""
        while ctx.final_verdict is None:
            if os.path.exists(ABORT_FILE):
                os.unlink(ABORT_FILE)
                ctx.request_abort("pccheck abort command")
            ctx.write_status()
            time.sleep(2)

    threading.Thread(target=status_loop, name="status", daemon=True).start()

    if s.state.get("phases", {}).get("inventory", {}).get("status") not in ("pending", None):
        start_disk_tests(ctx)  # resumed session: continue disk scans where they stopped
    run_phases(ctx)
    if ctx.reboot_request:  # the machine is on its way down for a planned reboot
        time.sleep(900)
        return 0
    result, text = finalize(ctx)
    if turbostat:
        turbostat.stop()
    ctx.dashboard.draw()
    log.info("final verdict: %s", result)
    # Keep serving the result on screen and over HTTP until the operator powers off.
    while True:
        time.sleep(3600)
