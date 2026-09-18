"""Kernel log (/dev/kmsg) watcher and hardware error classification rules."""

import errno
import logging
import os
import re
import threading
import time

from .findings import FAIL, INFO, WARN
from .util import append_line, boot_id, sync_storage

log = logging.getLogger("pccheck")

BDF_RE = re.compile(r"\b([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\b")

# Messages within this many seconds of boot are attributed to the boot itself
# (firmware-logged errors, errors carried over from the previous boot).
BOOT_WINDOW = 120.0


class Rule:
    def __init__(self, rid, pattern, severity, component, title, recommendation="", key_group=None,
                 counter=None, boot_title=None, ignore_at_boot=False):
        self.id = rid
        self.re = re.compile(pattern)
        self.severity = severity
        self.component = component
        self.title = title
        self.recommendation = recommendation
        self.key_group = key_group      # regex group used to split findings per device
        self.counter = counter          # name of a sysfs counter that owns the count (evidence only)
        self.boot_title = boot_title
        self.ignore_at_boot = ignore_at_boot  # driver probe messages that look alarming but are normal


REC_CPU_MEM = ("Unstable CPU or memory. Check rasdaemon/MCE decode in the logs to locate the "
               "socket/DIMM; reseat or replace it, verify BIOS memory settings (no XMP/EXPO overclock) "
               "and update BIOS/microcode.")
REC_MEMORY = "Replace or reseat the reported DIMM; re-run the test after swapping it to another slot to confirm."
REC_PCIE = ("PCIe signal integrity problem: reseat the device/riser/cable, try another slot, "
            "update device firmware; replace the riser or the card if errors continue.")
REC_DISK = "Replace the drive (or the cable/backplane slot if only link errors are reported)."
REC_THERMAL = "Improve cooling: check heatsink mounting and thermal paste, fans, airflow and blanking panels."

RULES = [
    Rule("kernel-panic", r"Kernel panic - not syncing", FAIL, "System",
         "Kernel panic", REC_CPU_MEM),
    Rule("mce-fatal", r"Fatal machine check|Machine check: .*(?:corrupt|PANIC)|\[Hardware Error\]: .*(?:Uncorrected|uncorrected|Fatal)",
         FAIL, "CPU/Memory", "Uncorrected machine check exception (MCE)", REC_CPU_MEM),
    Rule("bert", r"BERT: Error records from previous boot", WARN, "System",
         "Firmware recorded a fatal hardware error from a previous boot (BERT)", REC_CPU_MEM),
    Rule("ghes-fatal", r"\[Hardware Error\]: event severity: (?:fatal|recoverable)", FAIL, "Platform",
         "Uncorrected hardware error reported by firmware (APEI/GHES)", REC_CPU_MEM),
    Rule("ghes-corrected", r"\[Hardware Error\]: event severity: corrected", WARN, "Platform",
         "Corrected hardware error reported by firmware (APEI/GHES)", REC_CPU_MEM),
    Rule("mce-corrected", r"\[Hardware Error\]: (?:Corrected error|Machine check events logged)", WARN,
         "CPU/Memory", "Corrected machine check (MCE) during test", REC_CPU_MEM,
         boot_title="Machine check logged at boot (error happened before/while booting)"),
    Rule("edac-ue", r"EDAC .*(?:\bUE\b|[Uu]ncorrect)", FAIL, "Memory",
         "Uncorrectable memory error (EDAC)", REC_MEMORY, counter="edac"),
    Rule("edac-ce", r"EDAC .*\bCE\b", WARN, "Memory",
         "Corrected memory error (EDAC)", REC_MEMORY, counter="edac"),
    Rule("memory-failure", r"Memory failure: |\bBad page (?:state|map)\b|HardwareCorrupted|soft offline:", FAIL,
         "Memory", "Kernel memory failure handling (poisoned/bad page)", REC_MEMORY),
    Rule("nmi", r"NMI received for unknown reason|NMI: PCI system error|NMI: IOCK error|Dazed and confused",
         FAIL, "Platform", "Unexpected hardware NMI", REC_CPU_MEM),
    Rule("lockup", r"soft lockup - CPU#|hard LOCKUP|rcu_(?:sched|preempt) (?:self-)?detected stall|rcu: INFO: \S+ (?:self-)?detected stall",
         FAIL, "CPU", "CPU lockup / RCU stall (a CPU stopped responding)", REC_CPU_MEM),
    Rule("stress-crash", r"(?:stress-ng|stressapptest|mprime)\S*\[\d+\]:? (?:segfault|general protection|trap)",
         FAIL, "CPU/Memory", "Stress test process crashed (segfault / illegal instruction)", REC_CPU_MEM),
    Rule("segfault", r"\bsegfault at [0-9a-f]+ ip |traps: \S+\[\d+\] (?:general protection|trap)", WARN, "CPU/Memory",
         "Unexpected process crash (segfault)", REC_CPU_MEM),
    Rule("oops", r"general protection fault(?:,|: [0-9a-f]{4})|invalid opcode: [0-9a-f]{4}|BUG: unable to handle|\bOops: |kernel BUG at|BUG: Bad rss-counter",
         FAIL, "CPU/Memory", "Kernel crash (oops) - typical of unstable CPU or memory", REC_CPU_MEM),
    Rule("aer-uncorrected", r"PCIe Bus Error: severity=(?:Uncorrect|Fatal)|AER: (?:Multiple )?Uncorrect",
         FAIL, "PCIe", "Uncorrected PCIe error", REC_PCIE, key_group="bdf", counter="aer"),
    Rule("aer-corrected", r"PCIe Bus Error: severity=Corrected", WARN, "PCIe",
         "Corrected PCIe errors (link signal integrity)", REC_PCIE, key_group="bdf", counter="aer"),
    Rule("pcie-link-down", r"pciehp .*Link Down|PCIe link lost|Surprise Removal", FAIL, "PCIe",
         "PCIe device dropped off the bus", REC_PCIE, ignore_at_boot=True),
    Rule("gpu-lost", r"fallen off the bus|GPU has fallen", FAIL, "GPU", "GPU dropped off the bus", REC_PCIE),
    Rule("disk-io-error", r"I/O error, dev (\w+)|blk_update_request: (?:critical )?(?:medium|I/O) error, dev (\w+)",
         FAIL, "Storage", "Disk I/O error", REC_DISK, key_group="dev"),
    Rule("disk-medium", r"Unrecovered read error|Medium Error|critical medium error|\bUNC\b", FAIL, "Storage",
         "Disk medium error (unreadable sector)", REC_DISK),
    Rule("nvme-timeout", r"(nvme\d+)\S*: (?:I/O(?: tag)? \d+ .*timeout|controller is down|Device not ready|"
                         r"Removing after probe failure|resetting controller|Abort status)",
         FAIL, "Storage", "NVMe controller timeout/reset", REC_DISK, key_group="dev"),
    Rule("sata-link", r"(ata\d+)(?:\.\d+)?: (?:hard resetting link|SError: |failed command|exception Emask|COMRESET failed|limiting SATA link speed)",
         WARN, "Storage", "SATA link errors (cable, backplane or drive)", REC_DISK, key_group="dev"),
    Rule("sas-reset", r"(?:mpt3sas|megaraid_sas|smartpqi|aacraid|hpsa)\S*: .*(?:FW fault|fault state|reset|timeout|Timeout)",
         WARN, "Storage", "Storage controller reset/timeout", REC_DISK, ignore_at_boot=True),
    Rule("thermal-throttle", r"(?:Core|Package) temperature above threshold, cpu clock throttled", WARN, "Thermal",
         "CPU thermal throttling", REC_THERMAL, counter="throttle"),
    Rule("thermal-critical", r"[Cc]ritical temperature reached|thermal_zone\d+: critical|temperature above critical",
         FAIL, "Thermal", "Critical temperature reached", REC_THERMAL),
    Rule("clocksource", r"clocksource: .*unstable|TSC found unstable|Marking TSC unstable|timekeeping watchdog.*skew",
         WARN, "CPU/Platform", "Unstable clock source (TSC)",
         "Often a firmware or CPU/board problem; update BIOS and re-test."),
    Rule("hung-task", r"blocked for more than \d+ seconds", WARN, "System",
         "Task hung for a long time (storage stall or lockup)", REC_DISK),
    Rule("oom", r"Out of memory: Killed process|invoked oom-killer", WARN, "Test",
         "Out of memory during stress test (test configuration issue, not a hardware failure)"),
    Rule("nic-hang", r"Detected Hardware Unit Hang|NETDEV WATCHDOG: .*transmit queue \d+ timed out|"
                     r"(?:tx|TX) timeout|firmware (?:error|crashed)|Reset adapter|PCIe link lost",
         WARN, "Network", "Network adapter hang/reset",
         "Reseat the NIC/optics, update NIC firmware; replace if it repeats.", ignore_at_boot=True),
    Rule("iommu-fault", r"DMAR: \[DMA (?:Read|Write)\]|DMAR: DRHD: handling fault|AMD-Vi: Event logged \[IO_PAGE_FAULT",
         WARN, "Platform", "IOMMU fault (device accessed invalid memory)",
         "Usually a device firmware/driver issue; update firmware. Hardware if repeated under load."),
    Rule("irq-nobody", r"irq \d+: nobody cared", WARN, "Platform", "Spurious interrupt storm (irq nobody cared)",
         "Update BIOS; can be a failing device asserting interrupts."),
    Rule("usb-overcurrent", r"over-current condition", WARN, "Platform", "USB over-current condition",
         "Check USB devices/ports and board power."),
    Rule("firmware-bug", r"\[Firmware Bug\]", INFO, "Firmware", "Firmware bug reported by the kernel",
         "Consider a BIOS/BMC firmware update."),
]


def classify(message):
    for rule in RULES:
        m = rule.re.search(message)
        if m:
            return rule, m
    return None, None


def parse_record(raw):
    """Parse a /dev/kmsg record: 'prio,seq,usec,flags;message'. Returns (level, seq, seconds, message)."""
    head, _, rest = raw.partition(";")
    fields = head.split(",")
    try:
        prio = int(fields[0])
        seq = int(fields[1])
        usec = int(fields[2])
    except (IndexError, ValueError):
        return None
    message = rest.split("\n", 1)[0]
    return prio & 7, seq, usec / 1e6, message


def device_key(rule, match, message):
    if rule.key_group == "bdf":
        m = BDF_RE.search(message)
        return m.group(1) if m else "unknown"
    if rule.key_group == "dev":
        groups = [g for g in match.groups() if g]
        return groups[0] if groups else "unknown"
    return ""


class KmsgMonitor(threading.Thread):
    """Streams /dev/kmsg into <session>/logs/kernel.log and raises findings.

    Lines are fsync'ed in small batches so the last messages before a reset
    (the most valuable ones) make it onto the USB stick.
    """

    def __init__(self, ctx):
        super().__init__(name="kmsg", daemon=True)
        self.ctx = ctx
        self.logfile = ctx.session.path("logs", "kernel.log")
        self.stop_event = threading.Event()
        self.lines_total = 0
        self.error_lines = []

    def _process(self, level, seconds, message):
        ctx = self.ctx
        rule, match = classify(message)
        if rule is None:
            if level <= 2:
                norm = re.sub(r"\d+", "#", message)[:80]
                ctx.findings.add(f"kmsg-crit:{norm}", WARN, "System", "Critical kernel message",
                                 evidence=[message])
            return
        at_boot = seconds < BOOT_WINDOW
        if at_boot and rule.ignore_at_boot:
            return
        key = rule.id
        dev = device_key(rule, match, message)
        if dev:
            key = f"{rule.id}:{dev}"
        title = rule.title + (f" ({dev})" if dev else "")
        severity = rule.severity
        if at_boot and rule.boot_title:
            key = f"{rule.id}-boot"
            title = rule.boot_title
            severity = WARN
        if rule.id == "bert" and ctx.session.unexpected_reboot:
            severity = FAIL
            title = "Firmware recorded the fatal hardware error that reset the machine (BERT)"
        if rule.id in ("disk-io-error", "disk-medium", "nvme-timeout", "sata-link") and ctx.boot_disk and ctx.boot_disk in message:
            key, severity = f"bootdisk:{rule.id}", WARN
            title = "I/O errors on the PC-Check USB boot device (USB stick/port, not the tested hardware)"
        count = 1
        if rule.counter and rule.counter in ctx.sysfs_counters:
            count = 0  # the sysfs monitor owns the count; keep the text as evidence
            if rule.counter == "edac" and rule.severity != FAIL:
                return  # EDAC monitor reports per DIMM with labels; avoid a duplicate finding
            if rule.counter == "throttle":
                key = "thermal-throttle"
        finding = ctx.findings.add(key, severity, rule.component, title, recommendation=rule.recommendation,
                                   evidence=[f"[{seconds:10.3f}] {message}"], count=count)
        threshold = {"mce-corrected": ctx.opts.mce_fail, "ghes-corrected": ctx.opts.mce_fail,
                     "edac-ce": ctx.opts.ce_fail,
                     "aer-corrected": ctx.opts.aer_fail if "aer" not in ctx.sysfs_counters else None,
                     "sata-link": ctx.opts.sata_link_fail}.get(rule.id)
        if threshold and severity == WARN and not key.endswith("-boot") and finding.count >= threshold:
            ctx.findings.escalate(key, FAIL)

    def run(self):
        state = self.ctx.session.per_boot_counters("kmsg")
        last_seq = state.get("last_seq", -1)
        try:
            fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
        except OSError as exc:
            log.error("cannot open /dev/kmsg: %s", exc)
            self.ctx.findings.add("kmsg-unavailable", WARN, "Test",
                                  "Kernel hardware-error monitoring is unavailable", evidence=[str(exc)],
                                  incomplete=True)
            return
        append_line(self.logfile, f"===== boot {boot_id()} (monitor start {time.strftime('%F %T')}) =====")
        pending = []
        last_sync = time.monotonic()
        with open(self.logfile, "a") as out_fh:
            while not self.stop_event.is_set():
                try:
                    raw = os.read(fd, 8192).decode("utf-8", "replace")
                except BlockingIOError:
                    raw = None
                except OSError as exc:
                    if exc.errno == errno.EPIPE:  # ring buffer overwritten; continue with next record
                        self.ctx.findings.add("kmsg-overrun", WARN, "Test",
                                              "Kernel log overflowed; hardware error messages may be missing",
                                              incomplete=True)
                        continue
                    log.error("kmsg read error: %s", exc)
                    time.sleep(1)
                    continue
                if raw:
                    rec = parse_record(raw)
                    if rec is None:
                        continue
                    level, seq, seconds, message = rec
                    if seq <= last_seq:
                        continue
                    last_seq = seq
                    self.lines_total += 1
                    pending.append(f"[{seconds:12.6f}] <{level}> {message}")
                    if level <= 3:
                        self.error_lines.append(f"[{seconds:10.3f}] {message}")
                        del self.error_lines[:-500]
                    try:
                        self._process(level, seconds, message)
                    except Exception:
                        log.exception("kmsg rule handling failed for %r", message)
                    if len(pending) < 200:
                        continue
                if pending and (raw is None or len(pending) >= 200 or time.monotonic() - last_sync > 1):
                    out_fh.write("\n".join(pending) + "\n")
                    out_fh.flush()
                    try:
                        os.fsync(out_fh.fileno())
                    except OSError:
                        pass
                    sync_storage(self.logfile, force=False, min_interval=2.0)
                    pending.clear()
                    last_sync = time.monotonic()
                    with self.ctx.session.lock:
                        state["last_seq"] = last_seq
                if raw is None:
                    time.sleep(0.25)
            if pending:
                out_fh.write("\n".join(pending) + "\n")
                out_fh.flush()
                os.fsync(out_fh.fileno())
        os.close(fd)

    def stop(self):
        self.stop_event.set()
