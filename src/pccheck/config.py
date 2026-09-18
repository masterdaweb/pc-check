"""Test profiles, thresholds and option parsing (kernel command line + pccheck.conf)."""

import dataclasses
import logging
import math
import os
import shlex

from .util import read_file

log = logging.getLogger("pccheck")

# Relative share of the profile's time budget per stress phase. Inventory and the
# final analysis are not part of the budget; disk surface scans run in the background.
PHASE_WEIGHTS = [
    ("cpu", 0.14),        # stress-ng CPU stressors with result verification
    ("memory", 0.24),     # stressapptest + stress-ng VM patterns
    ("mprime", 0.16),     # Prime95 torture test (FFT verification)
    ("transient", 0.12),  # rapid load on/off switching (PSU/VRM/C-state transitions)
    ("idle", 0.08),       # deep idle soak (C-state related freezes/reboots)
    ("combined", 0.26),   # everything at once: max power draw and heat
]

PROFILES = {
    "quick": {"hours": 1.0, "disk_wait_hours": 0.0, "long_selftest": False,
              "label": "Quick smoke test"},
    "standard": {"hours": 12.0, "disk_wait_hours": 2.0, "long_selftest": True,
                 "label": "Standard burn-in"},
    "extended": {"hours": 24.0, "disk_wait_hours": 8.0, "long_selftest": True,
                 "label": "Extended burn-in"},
    "burnin": {"hours": 72.0, "disk_wait_hours": 24.0, "long_selftest": True,
               "label": "Full burn-in"},
}

CONF_FILENAME = "pccheck.conf"


@dataclasses.dataclass
class Options:
    profile: str = "standard"
    hours: float = 0.0              # 0 = profile default
    auto: bool = True               # start testing automatically
    destructive: str = "0"          # "0", "1" (blank disks only) or "force"
    destructive_countdown: int = 120
    http: bool = True               # serve reports on port 80
    identify: bool = True           # turn on the chassis ID LED via IPMI when the verdict is FAIL
    max_unexpected_reboots: int = 3
    skip: tuple = ()                # phase names to skip
    iperf3: str = ""                # optional iperf3 server to load the network against
    reboot_cycles: int = 0          # planned reboots at the end of the run (cold boot / POST stability)
    reboot_method: str = "auto"     # auto | reboot (warm) | ipmi (cold power cycle through the BMC)
    # Thresholds (counts during the test that turn a warning into a failure)
    ce_fail: int = 1                # corrected memory errors (EDAC) per DIMM
    mce_fail: int = 1               # corrected machine checks
    aer_fail: int = 20              # PCIe corrected errors per device
    sata_link_fail: int = 10        # SATA link resets per port
    cpu_temp_warn: float = 90.0     # used only when the sensor reports no limits
    drive_temp_warn: float = 70.0
    slow_read_seconds: float = 5.0  # a single 4 MiB read slower than this counts as a slow read
    validation_errors: tuple = dataclasses.field(default=(), init=False)

    @property
    def profile_info(self):
        return PROFILES.get(self.profile, PROFILES["standard"])

    @property
    def total_hours(self):
        return self.hours if self.hours > 0 else self.profile_info["hours"]

    @property
    def is_destructive(self):
        return self.destructive in ("1", "yes", "true", "force")


def _bool(value):
    return str(value).strip().lower() in ("1", "yes", "true", "on", "y")


def _apply(opts, key, value, source):
    key = key.strip().lower().replace("-", "_")
    field_types = {f.name: f.type for f in dataclasses.fields(Options) if f.init}
    if key not in field_types:
        log.warning("%s: unknown option %r ignored", source, key)
        return
    current = getattr(opts, key)
    try:
        if isinstance(current, bool):
            setattr(opts, key, _bool(value))
        elif isinstance(current, int):
            setattr(opts, key, int(value))
        elif isinstance(current, float):
            setattr(opts, key, float(value))
        elif isinstance(current, tuple):
            setattr(opts, key, tuple(v.strip() for v in value.split(",") if v.strip()))
        else:
            setattr(opts, key, str(value).strip())
    except ValueError:
        log.warning("%s: bad value for %s: %r", source, key, value)
        opts.validation_errors += (f"Invalid {key}: {value}",)
        return
    if key == "profile" and opts.profile not in PROFILES:
        log.warning("%s: unknown profile %r, using standard", source, value)
        opts.profile = "standard"


def parse_cmdline(text):
    """Extract pccheck.* options from a kernel command line."""
    result = {}
    try:
        tokens = shlex.split(text)
    except ValueError:
        tokens = text.split()
    for tok in tokens:
        if tok.startswith("pccheck.") and "=" in tok:
            key, value = tok[len("pccheck."):].split("=", 1)
            result[key] = value
    return result


def parse_conf(text):
    result = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def load_options(storage_root=None, cmdline=None):
    """pccheck.conf on the data partition first, then kernel command line overrides."""
    opts = Options()
    if storage_root:
        path = os.path.join(storage_root, CONF_FILENAME)
        for key, value in parse_conf(read_file(path)).items():
            _apply(opts, key, value, path)
    if cmdline is None:
        cmdline = read_file("/proc/cmdline")
    for key, value in parse_cmdline(cmdline).items():
        _apply(opts, key, value, "kernel cmdline")
    defaults = Options()
    ranges = {"hours": (0, 8760), "destructive_countdown": (0, 3600), "reboot_cycles": (0, 50),
              "max_unexpected_reboots": (1, 50), "cpu_temp_warn": (20, 150), "drive_temp_warn": (20, 150),
              "slow_read_seconds": (0.001, 3600)}
    ranges.update({key: (1, 1_000_000) for key in ("ce_fail", "mce_fail", "aer_fail", "sata_link_fail")})
    for key, (minimum, maximum) in ranges.items():
        value = getattr(opts, key)
        if not math.isfinite(value) or not minimum <= value <= maximum:
            opts.validation_errors += (f"{key} must be between {minimum} and {maximum}; got {value}",)
            setattr(opts, key, getattr(defaults, key))
    for key, allowed in (("destructive", ("0", "1", "yes", "true", "force")),
                         ("reboot_method", ("auto", "ipmi", "reboot"))):
        if getattr(opts, key) not in allowed:
            opts.validation_errors += (f"Invalid {key}: {getattr(opts, key)}",)
            setattr(opts, key, getattr(defaults, key))
    return opts


def build_plan(opts):
    """Ordered phase list with durations in seconds."""
    total = opts.total_hours * 3600
    plan = [{"name": "inventory", "duration": 0}]
    for name, weight in PHASE_WEIGHTS:
        if name in opts.skip:
            continue
        plan.append({"name": name, "duration": max(60, int(total * weight))})
    if opts.reboot_cycles > 0 and "powercycle" not in opts.skip:
        plan.append({"name": "powercycle", "duration": 0})
    return plan
