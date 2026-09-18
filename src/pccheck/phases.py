"""Stress phases. Each phase gets a time budget and reports problems through ctx.findings.

Design notes (why this catches what simple burn-in tools miss):
 * Workloads request result verification where supported (stress-ng --verify, stressapptest data checks,
   Prime95 FFT round-off checks). Silent miscalculation is the classic sign of a marginal CPU/RAM.
 * Hardware error reporting (MCE, EDAC, AER, BMC SEL) is monitored the whole time, so corrected
   errors - the early warning that precedes crashes - fail the machine even when no test fails.
 * Load changes are part of the test: rapid on/off load steps stress PSU/VRM transient response,
   and an idle soak exercises deep C-states, where many "random reboot" platforms actually die.
 * Resets are detected on the next boot and reported with the last telemetry.
"""

import glob
import logging
import os
import random
import re
import signal
import time

from .findings import FAIL, INFO, WARN
from .kmsg import REC_CPU_MEM, REC_MEMORY
from .util import ManagedProcess, cpu_count, have, meminfo, read_file, load_json

log = logging.getLogger("pccheck")

MPRIME = "/opt/mprime/mprime"

# stress-ng stressors that exercise distinct CPU blocks and verify their results.
CPU_STRESSORS = [
    ("cpu", ["--cpu", "0", "--cpu-method", "all"]),
    ("matrix", ["--matrix", "0", "--matrix-method", "all"]),
    ("vecmath", ["--vecmath", "0"]),
    ("vecwide", ["--vecwide", "0"]),
    ("vecfp", ["--vecfp", "0"]),
    ("fma", ["--fma", "0"]),
    ("fp", ["--fp", "0"]),
    ("intmath", ["--intmath", "0"]),
    ("hash", ["--hash", "0"]),
    ("crypt", ["--crypt", "0"]),
    ("ipsec-mb", ["--ipsec-mb", "0"]),
    ("zlib", ["--zlib", "0"]),
    ("cache", ["--cache", "0"]),
    ("l1cache", ["--l1cache", "0"]),
    ("branch", ["--branch", "0"]),
    ("bitops", ["--bitops", "0"]),
    ("memcpy", ["--memcpy", "0"]),
    ("trig", ["--trig", "0"]),
    ("prime", ["--prime", "0"]),
    ("tsc", ["--tsc", "0"]),
    ("vnni", ["--vnni", "0"]),
    ("matrix-3d", ["--matrix-3d", "0"]),
]

STRESSNG_FAIL_RE = re.compile(r"verif|checksum|mismatch|miscompar|killed by signal|SIGSEGV|SIGILL|SIGBUS", re.I)


def mem_budget_mib(fraction):
    """Memory for a stress tool: a fraction of available memory, keeping a reserve for the live system."""
    mi = meminfo()
    avail = mi.get("MemAvailable", 0)
    total = mi.get("MemTotal", 0)
    reserve = max(768 * 2**20, int(total * 0.04))
    budget = int(max(0, avail - reserve) * fraction) // 2**20
    if budget < 64:
        raise RuntimeError("Insufficient available RAM for a verified workload plus the OS reserve")
    return budget


class Phase:
    name = ""
    title = ""

    def __init__(self, ctx, duration):
        self.ctx = ctx
        self.duration = duration
        self.start = time.monotonic()
        self.deadline = self.start + duration

    @property
    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def progress(self):
        if self.duration <= 0:
            return None
        return min(1.0, (time.monotonic() - self.start) / self.duration)

    def logfile(self, suffix):
        return self.ctx.session.path("logs", f"{self.name}-{suffix}.log")

    def stopped(self):
        return self.ctx.abort_event.is_set()

    def run(self):
        raise NotImplementedError

    # ----- stress-ng helper
    def run_stressng(self, label, args, seconds):
        seconds = max(10, int(seconds))
        cmd = ["stress-ng", *args, "--verify", "--metrics-brief", "--timeout", f"{seconds}s",
               "--temp-path", "/tmp", "--oom-avoid"]
        proc = ManagedProcess(cmd, self.logfile(label))
        rc = proc.wait(time.monotonic() + seconds + 300, self.ctx.abort_event)
        if rc is None:
            hung = not self.ctx.abort_event.is_set()
            proc.stop()
            if hung:
                self.ctx.findings.add(f"stressng-hang:{label}", FAIL, "CPU/Memory",
                                      f"stress-ng '{label}' did not finish (hung workload)",
                                      recommendation=REC_CPU_MEM)
            return None
        proc.close()
        self.check_stressng(label, rc, proc.output_tail())
        if rc == 0 and time.monotonic() - proc.started < seconds * 0.9 and not self.stopped():
            self.ctx.findings.add(f"stressng-short:{self.name}:{label}", WARN, "Test",
                                  f"stress-ng '{label}' ended before its allotted test time", incomplete=True)
        return rc

    def check_stressng(self, label, rc, output):
        fail_lines = [l.strip() for l in output.splitlines()
                      if "stress-ng: fail:" in l or ("stress-ng: error:" in l and STRESSNG_FAIL_RE.search(l))]
        if rc in (2, 5) or fail_lines:
            self.ctx.findings.add(f"stressng-fail:{self.name}:{label}", FAIL, "CPU/Memory",
                                  f"stress-ng '{label}' detected a computation/verification failure",
                                  detail="A stress workload produced wrong results or crashed. This is the typical "
                                         "symptom of an unstable CPU, memory, VRM or overclock/XMP settings.",
                                  recommendation=REC_CPU_MEM, evidence=fail_lines[-15:] or [f"exit code {rc}"])
        elif rc == 4:
            self.ctx.findings.add(f"stressng-unsupported:{label}", WARN, "Test",
                                  f"stress-ng '{label}' is unsupported on this platform")
        elif rc != 0 or "successful run completed" not in output:
            self.ctx.findings.add(f"stressng-rc:{label}", WARN, "Test",
                                  f"stress-ng '{label}' did not complete successfully (code {rc})", incomplete=True,
                                  evidence=[l for l in output.splitlines() if "error" in l.lower()][-10:])


class CpuPhase(Phase):
    name, title = "cpu", "CPU stress (stress-ng, verified)"

    def run(self):
        slice_s = min(600, max(45, self.duration / len(CPU_STRESSORS)))
        i = 0
        stressors = list(CPU_STRESSORS)
        while self.remaining > 20 and not self.stopped():
            if not stressors:
                self.ctx.findings.add("cpu-no-workloads", WARN, "Test",
                                      "No CPU stress workloads could run", incomplete=True)
                break
            label, args = stressors[i % len(stressors)]
            self.ctx.status_note = f"stress-ng {label}"
            rc = self.run_stressng(label, args, min(slice_s, self.remaining))
            if rc in (1, 3, 4, 6, 7):
                stressors.remove((label, args))
            i += 1


class MemoryPhase(Phase):
    name, title = "memory", "Memory stress (stressapptest + stress-ng)"

    def run(self):
        sat_seconds = int(self.duration * 0.7)
        if have("stressapptest"):
            run_stressapptest(self, "stressapptest", sat_seconds, mem_budget_mib(0.92),
                              extra=["-W", "-i", "2", "--pause_delay", "900", "--pause_duration", "15"])
        else:
            self.ctx.findings.add("sat-missing", WARN, "Test", "stressapptest is unavailable", incomplete=True)
        if self.stopped():
            return
        budget = mem_budget_mib(0.85)
        workers = max(1, min(cpu_count(), 16, budget // 64))
        self.ctx.status_note = "stress-ng vm (all patterns)"
        # stress-ng divides vm-bytes among workers internally.
        self.run_stressng("vm", ["--vm", str(workers), "--vm-bytes", f"{budget}M", "--vm-method", "all",
                                 "--vm-keep"], self.remaining)


def run_stressapptest(phase, label, seconds, mem_mib, extra=()):
    ctx = phase.ctx
    seconds = max(30, int(seconds))
    ctx.status_note = f"stressapptest {mem_mib} MiB"
    cmd = ["stressapptest", "-s", str(seconds), "-M", str(mem_mib), "-v", "8", *extra]
    proc = ManagedProcess(cmd, phase.logfile(label))
    rc = proc.wait(time.monotonic() + seconds + 600, ctx.abort_event)
    if rc is None:
        hung = not ctx.abort_event.is_set()
        proc.stop()
        if hung:
            ctx.findings.add(f"sat-hang:{phase.name}", FAIL, "CPU/Memory", "stressapptest hung",
                             recommendation=REC_CPU_MEM)
        return
    proc.close()
    check_stressapptest(ctx, phase.name, rc, proc.output_tail(400_000))
    if rc == 0 and time.monotonic() - proc.started < seconds * 0.9 and not phase.stopped():
        ctx.findings.add(f"sat-short:{phase.name}", WARN, "Test",
                         "stressapptest ended before its allotted test time", incomplete=True)


def check_stressapptest(ctx, phase_name, rc, output):
    incidents = 0
    m = re.search(r"Found (\d+) hardware incidents", output)
    if m:
        incidents = int(m.group(1))
    errors = [l.strip() for l in output.splitlines()
              if re.search(r"Hardware Error|Report Error|miscompare|Error: .*(?:DIMM|CPU)|Status: FAIL", l)]
    if incidents or errors or "Status: FAIL" in output:
        ctx.findings.add(f"sat-fail:{phase_name}", FAIL, "Memory",
                         f"stressapptest found {incidents or 'some'} memory/CPU data errors",
                         detail="stressapptest (Google's server burn-in tool) detected corrupted data. "
                                "The DIMM or CPU memory controller is unstable.",
                         recommendation=REC_MEMORY, evidence=errors[:25])
    elif rc != 0 or "Status: PASS" not in output:
        ctx.findings.add(f"sat-rc:{phase_name}", WARN, "Test",
                         f"stressapptest did not complete successfully (exit code {rc})", incomplete=True,
                         evidence=output.strip().splitlines()[-10:])


class MprimePhase(Phase):
    name, title = "mprime", "Prime95 torture test (FFT verification)"

    ERROR_RE = re.compile(r"FATAL ERROR|Hardware failure detected|Possible hardware failure|ROUND ?OFF|"
                          r"SUM\(INPUTS\) != SUM\(OUTPUTS\)|TORTURE TEST FAILED|Rounding was .* expected less than|"
                          r"illegal (?:sumout|instruction)|\b[1-9]\d* errors?, \d+ warnings?|"
                          r"Torture test.*[1-9]\d* errors", re.I)

    def run(self):
        if not os.access(MPRIME, os.X_OK):
            self.ctx.findings.add("mprime-missing", WARN, "Test",
                                  "Prime95 (mprime) not included in this image; ran extra stress-ng load instead")
            self.run_stressng("matrix-fallback", ["--matrix", "0", "--matrix-method", "all",
                                                  "--vecwide", "0"], self.remaining)
            return
        workdir = "/tmp/mprime"
        os.makedirs(workdir, exist_ok=True)
        for leftover in glob.glob(os.path.join(workdir, "*")):
            try:
                os.unlink(leftover)
            except OSError:
                pass
        mem = mem_budget_mib(0.75)
        with open(os.path.join(workdir, "prime.txt"), "w") as fh:
            fh.write("V24OptionsConverted=1\nV30OptionsConverted=1\nWGUID_version=2\nStressTester=1\n"
                     "UsePrimenet=0\nOutputIterations=10000\nResultsFile=results.txt\n"
                     f"TortureThreads={cpu_count()}\nTortureHyperthreading=1\nTortureTime=6\n"
                     f"MinTortureFFT=4\nMaxTortureFFT=8192\nTortureMem={mem}\nTortureWeak=0\n")
        self.ctx.status_note = f"mprime blend, {cpu_count()} threads, {mem} MiB"
        proc = ManagedProcess([MPRIME, "-t", f"-W{workdir}"], self.logfile("mprime"), cwd=workdir)
        rc = proc.wait(self.deadline, self.ctx.abort_event)
        exited_early = rc is not None
        proc.stop(sig=signal.SIGINT, grace=60)
        output = proc.output_tail(500_000) + "\n" + read_file(os.path.join(workdir, "results.txt"))
        try:
            with open(self.logfile("results"), "w") as fh:
                fh.write(read_file(os.path.join(workdir, "results.txt")))
        except OSError:
            pass
        errors = [l.strip() for l in output.splitlines() if self.ERROR_RE.search(l)]
        passed = len(re.findall(r"Self-test \S+ passed", output))
        if errors:
            self.ctx.findings.add("mprime-fail", FAIL, "CPU/Memory",
                                  "Prime95 torture test detected calculation errors",
                                  detail="Prime95 verifies FFT results; errors mean the CPU, memory or VRM produced "
                                         "wrong results under sustained AVX load.",
                                  recommendation=REC_CPU_MEM, evidence=errors[:20])
        elif exited_early and time.monotonic() < self.deadline - 60 and not self.stopped():
            self.ctx.findings.add("mprime-exit", WARN, "Test", f"mprime exited early (code {rc})",
                                  evidence=output.strip().splitlines()[-10:], incomplete=True)
        if not errors and not passed and not self.stopped():
            self.ctx.findings.add("mprime-unverified", WARN, "Test",
                                  "Prime95 produced no completed FFT self-tests", incomplete=True)
        log.info("mprime: %d self-tests passed", passed)


class TransientPhase(Phase):
    """Full load switched on and off with random timing, from milliseconds to minutes.

    Rapid current steps expose weak PSUs, VRMs and power delivery; long idle gaps let the
    CPU drop into deep C-states and wake again under instant full load.
    """

    name, title = "transient", "Load transients (PSU/VRM stress)"

    PATTERNS = [
        ("fast", (0.05, 0.5), (0.05, 0.5), 60),
        ("medium", (2, 20), (1, 15), 300),
        ("slow", (30, 180), (20, 120), 900),
    ]

    def _sleep(self, seconds, proc):
        """Sleep, but never past the phase deadline or after the workload/test stopped."""
        end = min(time.monotonic() + seconds, self.deadline)
        while time.monotonic() < end and proc.poll() is None and not self.stopped():
            time.sleep(min(0.5, max(0.0, end - time.monotonic())))

    def run(self):
        budget = mem_budget_mib(0.4)
        workers = max(1, min(cpu_count(), 8, budget // 64))
        # The timeout is only a safety net: SIGSTOP'ed time counts against it, so the phase ends the run itself.
        args = ["stress-ng", "--cpu", "0", "--cpu-method", "matrixprod",
                "--vm", str(workers), "--vm-bytes", f"{budget}M",
                "--vm-method", "all", "--verify", "--metrics-brief", "--timeout", f"{int(self.duration) + 900}s",
                "--temp-path", "/tmp", "--oom-avoid"]
        proc = ManagedProcess(args, self.logfile("stress-ng"))
        rng = random.Random()
        steps = 0
        try:
            while proc.poll() is None and not self.stopped() and self.remaining > 0:
                name, on_range, off_range, block = rng.choice(self.PATTERNS)
                block_end = min(self.deadline, time.monotonic() + block)
                while time.monotonic() < block_end and proc.poll() is None and not self.stopped():
                    self.ctx.status_note = f"{name} load steps: full load ({steps} steps so far)"
                    proc.send_signal(signal.SIGCONT)
                    self._sleep(rng.uniform(*on_range), proc)
                    if time.monotonic() >= self.deadline:
                        break
                    self.ctx.status_note = f"{name} load steps: idle ({steps} steps so far)"
                    proc.send_signal(signal.SIGSTOP)
                    self._sleep(rng.uniform(*off_range), proc)
                    steps += 2
        finally:
            proc.send_signal(signal.SIGCONT)
        rc = proc.poll()
        if rc is not None and self.remaining > 5 and not self.stopped():
            self.ctx.findings.add("transient-short", WARN, "Test",
                                  "Load transient workload exited early", incomplete=True)
        if rc is None:
            # Normal end of phase: ask stress-ng to stop and print its verification summary.
            proc.send_signal(signal.SIGINT)
            rc = proc.wait(time.monotonic() + 120)
            if rc is None:
                proc.stop()
                self.ctx.findings.add("transient-hang", WARN, "Test", "stress-ng did not stop after the transient phase")
        proc.close()
        self.check_stressng("transient", rc, proc.output_tail())
        self.ctx.findings.add("transient-steps", INFO, "Power", f"Load transient phase: {steps} load steps applied")
        log.info("transient phase: %d load steps", steps)


class IdlePhase(Phase):
    name, title = "idle", "Idle soak (deep C-states)"

    def run(self):
        before = cstate_usage()
        dm = self.ctx.disk_manager
        if dm:
            dm.pause()
        try:
            self.ctx.status_note = "system idle, monitoring"
            while self.remaining > 0 and not self.stopped():
                time.sleep(min(5, self.remaining))
        finally:
            if dm:
                dm.resume()
        after = cstate_usage()
        used = {k: after[k] - before.get(k, 0) for k in after if after[k] > before.get(k, 0)}
        if used:
            self.ctx.findings.add("idle-cstates", INFO, "CPU", "Idle states used during idle soak",
                                  evidence=[f"{k}: {v / 1e6:.0f} s total residency" for k, v in sorted(used.items())])
        else:
            self.ctx.findings.add("idle-unverified", WARN, "CPU",
                                  "No CPU idle-state residency could be verified",
                                  recommendation="Check firmware C-state settings and turbostat residency logs.")


def cstate_usage():
    usage = {}
    for state in glob.glob("/sys/devices/system/cpu/cpu[0-9]*/cpuidle/state[0-9]*"):
        name = read_file(os.path.join(state, "name")).strip()
        try:
            usage[name] = usage.get(name, 0) + int(read_file(os.path.join(state, "time")).strip() or 0)
        except ValueError:
            pass
    return usage


class CombinedPhase(Phase):
    """Everything at once: memory + CPU + disk reads + optional network. Maximum power and heat."""

    name, title = "combined", "Combined max load (CPU+RAM+disks)"

    def run(self):
        from .disks import block_disks
        processes = []
        dm = self.ctx.disk_manager
        if dm:
            dm.pause()
        try:
            # Keep exercising storage after the one-time surface scans have finished.
            for disk in block_disks(dm.exclude if dm else (self.ctx.boot_disk,)):
                label = f"disk-{disk['name']}"
                result_path = self.logfile(label) + ".json"
                try:
                    os.unlink(result_path)
                except FileNotFoundError:
                    pass
                cmd = ["fio", "--readonly", "--name=combined-read", f"--filename={disk['path']}",
                       "--allow_file_create=0", "--rw=randread", "--bs=128k", "--direct=1",
                       "--ioengine=libaio", "--iodepth=32", "--time_based=1", "--size=100%",
                       f"--runtime={max(1, int(self.remaining))}", "--output-format=json",
                       f"--output={result_path}"]
                processes.append((label, ManagedProcess(cmd, self.logfile(label)), result_path))
            if self.ctx.opts.iperf3:
                label = "iperf3"
                proc = ManagedProcess(["iperf3", "-c", self.ctx.opts.iperf3, "--bidir",
                                       "-t", str(max(1, int(self.remaining))), "-P", "4", "--json"],
                                      self.logfile(label))
                processes.append((label, proc, None))
            else:
                self.ctx.findings.add("network-not-loaded", WARN, "Network",
                                      "No iperf3 peer configured; network ports were not load-tested",
                                      recommendation="Set iperf3 to a test peer; qualify every production port separately.")
            run_stressapptest(self, "stressapptest", self.remaining, mem_budget_mib(0.85),
                              extra=["-W", "-C", str(max(1, cpu_count() // 2)),
                                     "--pause_delay", "600", "--pause_duration", "10"])
            for label, proc, result_path in processes:
                rc = proc.wait(self.deadline + 120, self.ctx.abort_event)
                if self.stopped():
                    break
                if result_path:
                    data = load_json(result_path, {})
                    jobs = data.get("jobs", [])
                    verified = bool(jobs) and all(j.get("error") == 0 and
                               j.get("read", {}).get("io_bytes", 0) > 0 and
                               j.get("read", {}).get("runtime", 0) >= self.duration * 900 for j in jobs)
                else:
                    import json
                    output = proc.output_tail(500_000)
                    try:
                        data = json.loads(output[output.index("{"):])
                        end = data.get("end", {})
                        verified = not data.get("error") and bool(end) and any(
                            isinstance(v, dict) and v.get("bytes", 0) > 0 and
                            v.get("seconds", 0) >= self.duration * 0.9 for v in end.values())
                    except (ValueError, TypeError):
                        verified = False
                if rc != 0 or not verified:
                    self.ctx.findings.add(f"combined-load:{label}", WARN, "Test",
                                          f"Combined {label} load did not complete (exit {rc})",
                                          evidence=proc.output_tail(4000).splitlines()[-10:], incomplete=True)
        finally:
            for _, proc, _ in processes:
                if proc.poll() is None:
                    proc.stop()
                else:
                    proc.close()
            if dm:
                dm.resume()


class PowerCyclePhase(Phase):
    """Reboots (or cold power cycles) the machine a number of times and checks it comes back whole.

    Machines that "randomly reboot" often fail on the way up instead: a DIMM that is not trained,
    a CPU core left disabled, a disk or NIC that disappears, or a POST that hangs. Each cycle
    compares the hardware inventory with the one taken at the start of the test.
    """

    name, title = "powercycle", "Reboot / power-cycle stability"

    def snapshot(self):
        from .disks import block_disks, disk_id
        from .inventory import parse_dmidecode, dimms_from_dmi
        from .util import meminfo, out
        return {
            "cpus": cpu_count(),
            "memory_mib": meminfo().get("MemTotal", 0) // 2**20,
            "dimms": sorted(f"{d['locator']}:{d['serial']}:{d['size']}" for d in
                            dimms_from_dmi(parse_dmidecode(out(["dmidecode"], timeout=120)))),
            "disks": sorted(f"{disk_id(d)}:{d['size']}" for d in block_disks()),
            "nics": sorted(read_file(os.path.join(os.path.dirname(p), "address")).strip()
                           for p in glob.glob("/sys/class/net/*/device")),
        }

    def compare(self, baseline, now, cycle):
        if not baseline:
            return
        for key, label in (("cpus", "logical CPUs"), ("dimms", "memory modules"),
                           ("disks", "disks"), ("nics", "network interfaces")):
            if key in baseline and baseline[key] != now.get(key):
                self.ctx.findings.add(
                    f"powercycle-missing:{key}", FAIL, "System",
                    f"Hardware changed after reboot #{cycle}: {label} {baseline[key]} -> {now.get(key)}",
                    detail="A component was not detected after a reboot. Intermittently missing hardware "
                           "after POST is a classic sign of a failing DIMM/slot, riser, cable or PSU.",
                    recommendation="Reseat the missing component; check the BMC/POST log of that boot.")
        base_mem, now_mem = baseline.get("memory_mib", 0), now.get("memory_mib", 0)
        if base_mem and abs(base_mem - now_mem) > max(64, base_mem * 0.02):
            self.ctx.findings.add(
                "powercycle-memory", FAIL, "Memory",
                f"Usable memory changed after reboot #{cycle}: {base_mem} MiB -> {now_mem} MiB",
                recommendation="Reseat/replace DIMMs; check BIOS memory training and POST messages.")

    def run(self):
        ctx = self.ctx
        state = ctx.session.state
        target = max(0, min(50, ctx.opts.reboot_cycles))
        done = state.get("reboot_cycles_done", 0)
        baseline = state.get("powercycle_baseline") or self.snapshot()
        with ctx.session.lock:
            state["powercycle_baseline"] = baseline
        if done:
            self.compare(baseline, self.snapshot(), done)
            boot_seconds = state.get("last_reboot_seconds")
            if boot_seconds:
                ctx.findings.add("powercycle-time", INFO, "System",
                                 f"Boot after reboot #{done} took about {boot_seconds} s")
        if not getattr(ctx.storage, "persistent", False):
            ctx.findings.add("powercycle-skipped", WARN, "Test",
                             "Reboot cycles skipped: without persistent storage the machine would "
                             "restart the test forever",
                             recommendation="Prepare the USB stick with write-usb.sh so it has a "
                                            "PCCHECKDATA partition, then run the test again.")
            return
        if done >= target:
            ctx.findings.add("powercycle-ok", INFO, "System",
                             f"Completed {done} reboot/power cycles with the hardware intact")
            return
        ctx.status_note = f"reboot cycle {done + 1} of {target}: rebooting now"
        ctx.request_reboot(done + 1)


PHASES = {cls.name: cls for cls in (CpuPhase, MemoryPhase, MprimePhase, TransientPhase, IdlePhase,
                                    CombinedPhase, PowerCyclePhase)}
TITLES = {"inventory": "Inventory & pre-checks", **{n: c.title for n, c in PHASES.items()},
          "final": "Final analysis & report"}
DESCRIPTIONS = {
    "inventory": "Lists hardware; checks DIMMs, CPUs, PCIe links, SMART, BMC log; starts disk scans",
    "cpu": "All cores run math/vector/crypto/cache workloads with verification where supported",
    "memory": "Fills RAM with verified data patterns: finds bad DIMMs / memory controller",
    "mprime": "Prime95 AVX torture test: detects miscalculation by unstable CPU/RAM/VRM",
    "transient": "Switches full load on/off rapidly: stresses power supply and VRMs",
    "idle": "Machine idle: deep sleep states are a common cause of random reboots",
    "combined": "CPU + RAM + disks at full load together: maximum power draw and heat",
    "powercycle": "Reboots the machine repeatedly and checks all hardware comes back",
    "final": "Waits for disk scans/self-tests, compares before/after, writes the report",
}
