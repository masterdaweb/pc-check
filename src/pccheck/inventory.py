"""Hardware inventory and static pre-checks (configuration problems visible without stress)."""

import glob
import json
import logging
import os
import re
import shutil

from .findings import FAIL, INFO, WARN
from .kmsg import REC_PCIE
from .util import have, meminfo, out, read_file, read_int, run, fmt_bytes

log = logging.getLogger("pccheck")

RAW_COMMANDS = {
    "dmidecode.txt": ["dmidecode"],
    "lscpu.txt": ["lscpu"],
    "lscpu-extended.txt": ["lscpu", "-e"],
    "cpuinfo.txt": ["cat", "/proc/cpuinfo"],
    "lspci-vvv.txt": ["lspci", "-vvv", "-nn"],
    "lspci-tree.txt": ["lspci", "-tv"],
    "lsblk.json": ["lsblk", "-O", "-J"],
    "lsusb.txt": ["lsusb", "-t"],
    "lshw.json": ["lshw", "-json", "-quiet"],
    "numa.txt": ["numactl", "-H"],
    "sensors.txt": ["sensors"],
    "ip-link.txt": ["ip", "-d", "-s", "link"],
    "ip-addr.txt": ["ip", "addr"],
    "nvme-list.txt": ["nvme", "list"],
    "smart-scan.txt": ["smartctl", "--scan-open"],
    "edac.txt": ["edac-util", "-v", "--report=full"],
    "ras-layout.txt": ["ras-mc-ctl", "--layout"],
    "cpuidle.txt": ["cpupower", "idle-info"],
    "cpufreq.txt": ["cpupower", "frequency-info"],
    "efibootmgr.txt": ["efibootmgr", "-v"],
    "cmdline.txt": ["cat", "/proc/cmdline"],
    "uname.txt": ["uname", "-a"],
    "modules.txt": ["lsmod"],
    "ipmi-mc-info.txt": ["ipmitool", "mc", "info"],
    "ipmi-fru.txt": ["ipmitool", "fru", "print"],
    "ipmi-sdr.txt": ["ipmitool", "sdr", "elist"],
    "ipmi-sel.txt": ["ipmitool", "sel", "elist"],
    "ipmi-lan.txt": ["ipmitool", "lan", "print"],
    "dmesg-boot.txt": ["dmesg", "-T"],
}


def collect_raw(directory, note=lambda text: None):
    os.makedirs(directory, exist_ok=True)
    have_ipmi = bool(glob.glob("/dev/ipmi*"))
    for filename, cmd in RAW_COMMANDS.items():
        if cmd[0] == "ipmitool" and not have_ipmi:
            continue
        if not have(cmd[0]):
            continue
        note(f"collecting inventory: {' '.join(cmd)}")
        res = run(cmd, timeout=300)
        with open(os.path.join(directory, filename), "w") as fh:
            fh.write(res.stdout)
            if res.returncode != 0 and res.stderr:
                fh.write(f"\n# exit {res.returncode}: {res.stderr}")
    for nic in sorted(os.path.basename(os.path.dirname(p)) for p in glob.glob("/sys/class/net/*/device")):
        with open(os.path.join(directory, f"ethtool-{nic}.txt"), "w") as fh:
            for args in (["ethtool", nic], ["ethtool", "-i", nic], ["ethtool", "-m", nic], ["ethtool", "-S", nic]):
                fh.write(f"$ {' '.join(args)}\n{run(args, timeout=30).stdout}\n")


# --------------------------------------------------------------------------- dmidecode parsing

def parse_dmidecode(text):
    """Split dmidecode output into a list of (type_name, {key: value})."""
    records = []
    for block in re.split(r"\n\s*\n", text):
        lines = block.strip("\n").splitlines()
        if len(lines) < 2 or not lines[0].startswith("Handle"):
            continue
        name = lines[1].strip()
        fields = {}
        for line in lines[2:]:
            if ":" in line and line.startswith("\t") and not line.startswith("\t\t"):
                k, v = line.strip().split(":", 1)
                fields[k.strip()] = v.strip()
        records.append((name, fields))
    return records


def parse_size(text):
    m = re.match(r"(\d+)\s*(KB|MB|GB|TB|kB)", text or "")
    if not m:
        return 0
    return int(m.group(1)) * {"KB": 2**10, "kB": 2**10, "MB": 2**20, "GB": 2**30, "TB": 2**40}[m.group(2)]


def parse_speed(text):
    m = re.match(r"(\d+)", text or "")
    return int(m.group(1)) if m else 0


def dimms_from_dmi(records):
    dimms = []
    for name, f in records:
        if name != "Memory Device":
            continue
        size = parse_size(f.get("Size", ""))
        if not size:
            continue
        dimms.append({
            "locator": f.get("Locator", ""), "bank": f.get("Bank Locator", ""), "size": size,
            "type": f.get("Type", ""), "speed": parse_speed(f.get("Speed", "")),
            "configured_speed": parse_speed(f.get("Configured Memory Speed", f.get("Configured Clock Speed", ""))),
            "manufacturer": f.get("Manufacturer", ""), "part": f.get("Part Number", "").strip(),
            "serial": f.get("Serial Number", ""), "rank": f.get("Rank", ""),
        })
    return dimms


def check_memory(records, findings):
    dimms = dimms_from_dmi(records)
    if not dimms:
        findings.add("dmi-no-dimms", INFO, "Memory", "Firmware (SMBIOS) does not list memory modules")
        return dimms
    installed = sum(d["size"] for d in dimms)
    total = meminfo().get("MemTotal", 0)
    if total and installed and total < installed * 0.85:
        findings.add("memory-missing", FAIL, "Memory",
                     f"Only {fmt_bytes(total)} usable of {fmt_bytes(installed)} installed memory",
                     detail="The OS sees much less memory than the modules listed by firmware. A DIMM or a memory "
                            "channel was probably disabled during POST (training failure), or memory is mapped out.",
                     recommendation="Check BIOS/BMC POST messages, reseat or swap DIMMs to find the failing module/slot.")
    parts = {d["part"] for d in dimms if d["part"] and d["part"].lower() not in ("unknown", "not specified")}
    if len(parts) > 1:
        findings.add("memory-mixed", WARN, "Memory", f"Mixed memory module part numbers ({len(parts)} different)",
                     detail="Mixed DIMMs are a common source of marginal memory stability.",
                     recommendation="Use identical, vendor-qualified DIMMs (same part number) in a system.",
                     evidence=sorted(parts))
    sizes = {d["size"] for d in dimms}
    if len(sizes) > 1:
        findings.add("memory-mixed-size", WARN, "Memory", "Memory modules of different sizes installed",
                     evidence=[f"{d['locator']}: {fmt_bytes(d['size'])}" for d in dimms])
    slow = [d for d in dimms if d["speed"] and d["configured_speed"] and d["configured_speed"] < d["speed"]]
    if slow:
        findings.add("memory-speed", INFO, "Memory", "Memory runs below its rated speed",
                     detail="Normal for some population rules/CPUs; confirm it matches the platform's expected speed.",
                     evidence=[f"{d['locator']}: rated {d['speed']} MT/s, configured {d['configured_speed']} MT/s" for d in slow[:16]])
    ecc = [f.get("Error Correction Type", "") for n, f in records if n == "Physical Memory Array"]
    if ecc and all(e in ("None", "") for e in ecc):
        findings.add("memory-non-ecc", INFO, "Memory", "Memory is not ECC",
                     detail="Without ECC, memory errors cannot be observed directly; detection relies on the stress "
                            "tests' data verification. ECC memory is strongly recommended for production servers.")
    elif ecc and not glob.glob("/sys/devices/system/edac/mc/mc[0-9]*"):
        findings.add("edac-missing", WARN, "Memory", "ECC memory present but no EDAC driver is active",
                     detail="Corrected memory errors will only be visible through machine checks or the BMC event "
                            "log (firmware-first platforms). Per-DIMM error counts are unavailable.",
                     recommendation="Check the BMC SEL after the test; enable OS error reporting in BIOS if available.")
    return dimms


def check_cpus(records, findings):
    sockets = [f for n, f in records if n == "Processor Information"]
    expected_threads = 0
    for f in sockets:
        status = f.get("Status", "")
        designation = f.get("Socket Designation", "?")
        if "Populated" in status and "Enabled" not in status:
            sev = FAIL if "POST Error" in status else WARN
            findings.add(f"cpu-socket:{designation}", sev, "CPU", f"CPU in {designation} is not enabled ({status})",
                         recommendation="Check BIOS settings and POST log; reseat or replace the CPU.")
        if "Enabled" in status:
            expected_threads += int(f.get("Thread Count", "0") or 0)
    online = len(glob.glob("/sys/devices/system/cpu/cpu[0-9]*"))
    offline = read_file("/sys/devices/system/cpu/offline").strip()
    if offline:
        findings.add("cpu-offline", WARN, "CPU", f"Some logical CPUs are offline: {offline}")
    if expected_threads and online < expected_threads:
        findings.add("cpu-count", WARN, "CPU",
                     f"OS sees {online} logical CPUs but firmware reports {expected_threads} threads",
                     detail="Cores or SMT may be disabled in BIOS, or a CPU/core failed to initialize.",
                     recommendation="Verify BIOS core/SMT settings match the production configuration.")
    return sockets


# --------------------------------------------------------------------------- PCIe links

LNK_RE = re.compile(r"Speed ([\d.]+)GT/s[^,]*, Width x(\d+)")


def parse_pcie_links(text):
    """lspci -vvv -> {bdf: {name, cap_speed, cap_width, sta_speed, sta_width, bridge}}."""
    links = {}
    for block in re.split(r"\n(?=[0-9a-f]{2,4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7] |[0-9a-f]{2}:[0-9a-f]{2}\.[0-7] )", text):
        header = block.split("\n", 1)[0]
        m = re.match(r"((?:[0-9a-f]{4}:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]) (.*)", header)
        if not m:
            continue
        cap = re.search(r"LnkCap:\s+Port #\d+, " + LNK_RE.pattern, block) or re.search(r"LnkCap:.*?" + LNK_RE.pattern, block)
        sta = re.search(r"LnkSta:\s+" + LNK_RE.pattern, block)
        if not cap or not sta:
            continue
        links[m.group(1)] = {
            "name": m.group(2), "cap_speed": float(cap.group(1)), "cap_width": int(cap.group(2)),
            "sta_speed": float(sta.group(1)), "sta_width": int(sta.group(2)),
            "bridge": bool(re.search(r"PCI bridge|Root Port|Upstream|Downstream|Switch", header)),
        }
    return links


def check_pcie_links(links, findings, baseline=None):
    for bdf, link in (baseline or {}).items():
        if bdf not in links and not link["bridge"]:
            findings.add(f"pcie-missing:{bdf}", FAIL, "PCIe",
                         f"PCIe device disappeared during the test: {bdf} {link['name']}",
                         recommendation=REC_PCIE)
    for bdf, l in links.items():
        if l["bridge"]:
            continue
        if l["sta_width"] == 0:
            continue
        if baseline and bdf in baseline:
            b = baseline[bdf]
            if l["sta_width"] < b["sta_width"]:
                findings.add(f"pcie-width-drop:{bdf}", FAIL, "PCIe",
                             f"PCIe link width dropped during the test on {bdf} {l['name']}",
                             recommendation=REC_PCIE,
                             evidence=[f"x{b['sta_width']} -> x{l['sta_width']}"])
            elif l["sta_speed"] < b["sta_speed"]:
                findings.add(f"pcie-speed-drop:{bdf}", WARN, "PCIe",
                             f"PCIe link speed dropped during the test on {bdf} {l['name']}",
                             detail="Some devices (GPUs) lower link speed when idle; storage/network devices should not.",
                             recommendation=REC_PCIE,
                             evidence=[f"{b['sta_speed']}GT/s -> {l['sta_speed']}GT/s"])
            continue
        if l["sta_width"] < l["cap_width"]:
            findings.add(f"pcie-width:{bdf}", WARN, "PCIe",
                         f"PCIe link degraded: {bdf} {l['name']} runs x{l['sta_width']} (capable x{l['cap_width']})",
                         detail="Expected if the slot is electrically narrower than the card; otherwise a bad seat, "
                                "riser or slot.",
                         recommendation=REC_PCIE)
        elif l["sta_speed"] < l["cap_speed"]:
            findings.add(f"pcie-speed:{bdf}", INFO, "PCIe",
                         f"PCIe link below max speed: {bdf} {l['name']} at {l['sta_speed']}GT/s "
                         f"(capable {l['cap_speed']}GT/s)",
                         detail="Can be power management or platform limits; a consistent downgrade under load "
                                "indicates signal integrity problems.")


# --------------------------------------------------------------------------- misc checks

def check_rtc(findings):
    epoch = read_int("/sys/class/rtc/rtc0/since_epoch")
    build = 0
    for line in read_file("/etc/pccheck-release").splitlines():
        if line.startswith("PCCHECK_BUILD_EPOCH="):
            build = int(line.split("=", 1)[1] or 0)
    if epoch and build and epoch < build - 86400:
        findings.add("rtc-clock", WARN, "Board", "Hardware clock (RTC) is earlier than the PC-Check build date",
                     detail="The CMOS battery may be depleted or the clock was never set.",
                     recommendation="Replace the CMOS battery if the time is lost after power removal; set the clock.")


def check_taint(findings, start_taint=None):
    """Kernel taint flags: M = machine check, B = bad page. At start they are warnings (pre-existing)."""
    taint = read_int("/proc/sys/kernel/tainted", 0) or 0
    for bit, key, component, text in ((4, "mce", "CPU/Memory", "a machine check exception"),
                                      (5, "badpage", "Memory", "a bad memory page")):
        if not taint & (1 << bit):
            continue
        if start_taint is None:
            findings.add(f"taint-{key}-boot", WARN, component, f"Kernel flagged {text} before the test started")
        elif not start_taint & (1 << bit):
            findings.add(f"taint-{key}", FAIL, component, f"Kernel flagged {text} during the test")
    return taint


def collect_pstore(dest, findings, session, persistent=True):
    """Crash logs saved by the kernel in UEFI variables / ERST before a reset."""
    entries = sorted(glob.glob("/sys/fs/pstore/*"))
    if not entries:
        return []
    os.makedirs(dest, exist_ok=True)
    saved = []
    for path in entries:
        target = os.path.join(dest, os.path.basename(path))
        try:
            shutil.copyfile(path, target)
            saved.append(target)
            if persistent:
                os.unlink(path)  # frees NVRAM space for the next crash record
        except OSError as exc:
            log.warning("pstore copy %s failed: %s", path, exc)
    text = "\n".join(read_file(p)[-4000:] for p in saved if "dmesg" in p)
    reasons = sorted(set(re.findall(r"(Kernel panic - not syncing: [^\n]*|Machine check[^\n]*|BUG: [^\n]*|"
                                    r"watchdog: [^\n]*|general protection fault[^\n]*)", text)))
    if session.unexpected_reboot:
        findings.add("pstore-crash", FAIL, "System", "Kernel crash log recovered from the reset (pstore)",
                     detail="The kernel saved its last messages before the machine reset.",
                     evidence=reasons[:10] + [f"saved: {os.path.basename(p)}" for p in saved[:10]])
    else:
        findings.add("pstore-historic", WARN, "System",
                     "Kernel crash logs from before this test were found in firmware storage (pstore)",
                     detail="This machine crashed at some point before PC-Check started.",
                     evidence=reasons[:10] + [f"saved: {os.path.basename(p)}" for p in saved[:10]])
    return saved


# --------------------------------------------------------------------------- summary for the report

def summarize(records, dimms, links):
    def first(type_name):
        return next((f for n, f in records if n == type_name), {})

    system, board, bios = first("System Information"), first("Base Board Information"), first("BIOS Information")
    cpus = []
    for n, f in records:
        if n == "Processor Information" and "Populated" in f.get("Status", ""):
            cpus.append({"socket": f.get("Socket Designation", ""), "model": f.get("Version", ""),
                         "cores": f.get("Core Count", ""), "threads": f.get("Thread Count", "")})
    microcode = ""
    m = re.search(r"^microcode\s*:\s*(\S+)", read_file("/proc/cpuinfo"), re.M)
    if m:
        microcode = m.group(1)
    disks = []
    try:
        for d in json.loads(out(["lsblk", "-J", "-b", "-d", "-o", "NAME,TYPE,SIZE,MODEL,SERIAL,TRAN,ROTA"]))["blockdevices"]:
            if d.get("type") == "disk" and not d["name"].startswith(("loop", "zram", "ram", "sr")):
                disks.append({"name": d["name"], "model": (d.get("model") or "").strip(),
                              "serial": d.get("serial") or "", "size": fmt_bytes(int(d.get("size") or 0)),
                              "transport": d.get("tran") or "", "rotational": d.get("rota")})
    except (ValueError, KeyError, TypeError):
        pass
    nics = []
    for p in sorted(glob.glob("/sys/class/net/*/device")):
        nic = p.split("/")[-2]
        drv = os.path.basename(os.path.realpath(f"/sys/class/net/{nic}/device/driver"))
        info = out(["ethtool", "-i", nic], timeout=10)
        fw = re.search(r"firmware-version: (.*)", info)
        speed = read_file(f"/sys/class/net/{nic}/speed").strip()
        nics.append({"name": nic, "driver": drv, "firmware": fw.group(1).strip() if fw else "",
                     "mac": read_file(f"/sys/class/net/{nic}/address").strip(),
                     "link": read_file(f"/sys/class/net/{nic}/operstate").strip(),
                     "speed": f"{speed} Mb/s" if speed and not speed.startswith("-") else ""})
    bmc = out(["ipmitool", "mc", "info"], timeout=30) if glob.glob("/dev/ipmi*") else ""
    bmc_fw = re.search(r"Firmware Revision\s*:\s*(.*)", bmc)
    gpus = [f"{bdf} {l['name']}" for bdf, l in links.items() if re.search(r"VGA|3D controller|Display", l["name"])]
    return {
        "system": {"manufacturer": system.get("Manufacturer", ""), "product": system.get("Product Name", ""),
                   "serial": system.get("Serial Number", ""), "uuid": system.get("UUID", "")},
        "board": {"manufacturer": board.get("Manufacturer", ""), "product": board.get("Product Name", ""),
                  "serial": board.get("Serial Number", "")},
        "bios": {"vendor": bios.get("Vendor", ""), "version": bios.get("Version", ""),
                 "date": bios.get("Release Date", "")},
        "bmc_firmware": bmc_fw.group(1).strip() if bmc_fw else "",
        "cpus": cpus, "logical_cpus": os.cpu_count(), "microcode": microcode,
        "memory_total": fmt_bytes(meminfo().get("MemTotal", 0)),
        "dimms": dimms, "disks": disks, "nics": nics, "gpus": gpus,
        "boot_mode": "UEFI" if os.path.isdir("/sys/firmware/efi") else "Legacy BIOS",
        "kernel": os.uname().release,
    }


def run_inventory(ctx):
    inv_dir = ctx.session.path("inventory")

    def note(text):
        ctx.status_note = text

    collect_raw(inv_dir, note)
    note("checking memory, CPUs and PCIe links")
    records = parse_dmidecode(read_file(os.path.join(inv_dir, "dmidecode.txt")))
    if not records:
        ctx.findings.add("inventory-missing", WARN, "Test",
                         "SMBIOS inventory could not be read; installed components cannot be verified",
                         incomplete=True)
    dimms = check_memory(records, ctx.findings)
    check_cpus(records, ctx.findings)
    links = parse_pcie_links(read_file(os.path.join(inv_dir, "lspci-vvv.txt")))
    check_pcie_links(links, ctx.findings)
    check_rtc(ctx.findings)
    ctx.session.state.setdefault("baselines", {})["taint"] = check_taint(ctx.findings)
    summary = summarize(records, dimms, links)
    if summary.get("gpus"):
        ctx.findings.add("gpu-not-tested", WARN, "GPU",
                         "No dedicated GPU compute or VRAM verification was performed",
                         recommendation="Run the GPU vendor's diagnostics for any production accelerators.")
    if not glob.glob("/sys/class/watchdog/watchdog*"):
        ctx.findings.add("watchdog-missing", WARN, "System",
                         "No hardware watchdog exposed; a hard hang may require an external reset",
                         recommendation="Enable the platform watchdog or supervise through the BMC during qualification.")
    ctx.findings.add("pre-os-memory", INFO, "Memory",
                     "Linux workloads cannot test RAM reserved by the kernel or firmware",
                     recommendation="Supplement with standalone Memtest86+ and vendor diagnostics.")
    if summary.get("disks") and not ctx.opts.is_destructive:
        ctx.findings.add("storage-read-only", INFO, "Storage",
                         "Storage write integrity was not tested; disk tests are read-only",
                         recommendation="On disposable disks, explicitly enable destructive write/verify before acceptance.")
    with ctx.session.lock:
        ctx.session.state["inventory"] = summary
        ctx.session.state.setdefault("baselines", {})["pcie_links"] = links
    ctx.session.save()
    return summary
