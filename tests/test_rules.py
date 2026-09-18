import os
import sys
import tempfile
import logging
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
logging.disable(logging.CRITICAL)

from pccheck import config, disks, inventory, kmsg, monitors, phases, storage  # noqa: E402
from pccheck.findings import FAIL, INFO, WARN, Findings, verdict  # noqa: E402


class KmsgRulesTest(unittest.TestCase):
    def rid(self, message):
        rule, _ = kmsg.classify(message)
        return rule.id if rule else None

    def test_machine_checks(self):
        self.assertEqual(self.rid("mce: [Hardware Error]: Machine check events logged"), "mce-corrected")
        self.assertEqual(self.rid("[Hardware Error]: Corrected error, no action required."), "mce-corrected")
        self.assertEqual(self.rid("Kernel panic - not syncing: Fatal machine check"), "kernel-panic")
        self.assertEqual(self.rid("mce: [Hardware Error]: Machine check: Processor context corrupt"), "mce-fatal")
        self.assertEqual(self.rid("{1}[Hardware Error]: event severity: corrected"), "ghes-corrected")
        self.assertEqual(self.rid("{1}[Hardware Error]: event severity: fatal"), "ghes-fatal")

    def test_memory(self):
        self.assertEqual(self.rid("EDAC MC0: 1 CE memory read error on CPU_SrcID#0_MC#0_Chan#1_DIMM#0"), "edac-ce")
        self.assertEqual(self.rid("EDAC MC1: 1 UE memory read error on DIMM_B2"), "edac-ue")
        self.assertEqual(self.rid("Memory failure: 0x1234: recovery action for dirty LRU page: Recovered"),
                         "memory-failure")

    def test_crashes(self):
        self.assertEqual(self.rid("stress-ng-cpu[4242]: segfault at 0 ip 000055d0 sp 00007ffc error 4"), "stress-crash")
        self.assertEqual(self.rid("traps: stress-ng-matrix[99] general protection fault ip:55 sp:7f error:0"),
                         "stress-crash")
        self.assertEqual(self.rid("traps: bash[99] general protection fault ip:55 sp:7f error:0 in libc"), "segfault")
        self.assertEqual(self.rid("general protection fault, probably for non-canonical address 0xdead: 0000 [#1] SMP"),
                         "oops")
        self.assertEqual(self.rid("watchdog: BUG: soft lockup - CPU#3 stuck for 22s! [stress-ng:123]"), "lockup")
        self.assertEqual(self.rid("rcu: INFO: rcu_preempt self-detected stall on CPU"), "lockup")

    def test_pcie_and_disks(self):
        rule, m = kmsg.classify("pcieport 0000:00:01.1: PCIe Bus Error: severity=Corrected, type=Physical Layer, (Receiver ID)")
        self.assertEqual(rule.id, "aer-corrected")
        self.assertEqual(kmsg.device_key(rule, m, "pcieport 0000:00:01.1: PCIe Bus Error"), "0000:00:01.1")
        rule, m = kmsg.classify("I/O error, dev sda, sector 2048 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 2")
        self.assertEqual(rule.id, "disk-io-error")
        self.assertEqual(kmsg.device_key(rule, m, ""), "sda")
        self.assertEqual(self.rid("nvme nvme0: I/O 123 QID 4 timeout, aborting"), "nvme-timeout")
        self.assertEqual(self.rid("ata3.00: exception Emask 0x10 SAct 0x0 SErr 0x4050000 action 0xe frozen"), "sata-link")

    def test_benign(self):
        for msg in ("Linux version 6.12.0-amd64", "e1000e 0000:00:1f.6 eno1: NIC Link is Up 1000 Mbps Full Duplex",
                    "nvme nvme0: 16/0/0 default/read/poll queues", "EDAC MC: Ver: 3.0.0",
                    "microcode: Current revision: 0x000000f8"):
            self.assertIsNone(self.rid(msg), msg)

    def test_parse_record(self):
        self.assertEqual(kmsg.parse_record("3,1234,5678901,-;EDAC MC0: 1 CE\n SUBSYSTEM=edac"),
                         (3, 1234, 5.678901, "EDAC MC0: 1 CE"))


class FindingsTest(unittest.TestCase):
    def test_dedupe_escalate_persist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "findings.json")
            f = Findings(path)
            f.add("k", WARN, "Memory", "CE", evidence=["a"])
            f.add("k", WARN, "Memory", "CE", evidence=["a", "b"], count=3)
            self.assertEqual(f.get("k").count, 4)
            self.assertEqual(f.get("k").evidence, ["a", "b"])
            self.assertEqual(verdict(f), "PASS WITH WARNINGS")
            f.escalate("k", FAIL)
            f.add("i", INFO, "x", "info")
            self.assertEqual(verdict(Findings(path)), FAIL)
            f.add("evidence-only", WARN, "PCIe", "t", count=0)
            self.assertEqual(f.get("evidence-only").count, 1)

    def test_verdicts(self):
        f = Findings()
        self.assertEqual(verdict(f), "PASS")
        self.assertEqual(verdict(f, incomplete=True), "INCOMPLETE")


class ConfigTest(unittest.TestCase):
    def test_cmdline_and_conf(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, config.CONF_FILENAME), "w") as fh:
                fh.write("# fleet defaults\nprofile = extended\nce_fail=3\nhttp=no\n")
            opts = config.load_options(tmp, cmdline="BOOT_IMAGE=/live/vmlinuz boot=live pccheck.hours=0.5 "
                                                    "pccheck.skip=idle,mprime pccheck.destructive=force")
        self.assertEqual(opts.profile, "extended")
        self.assertEqual(opts.ce_fail, 3)
        self.assertFalse(opts.http)
        self.assertEqual(opts.total_hours, 0.5)
        self.assertEqual(opts.skip, ("idle", "mprime"))
        self.assertTrue(opts.is_destructive)
        names = [p["name"] for p in config.build_plan(opts)]
        self.assertEqual(names, ["inventory", "cpu", "memory", "ycruncher", "transient", "combined"])

    def test_plan_budget(self):
        opts = config.load_options(cmdline="pccheck.profile=standard")
        total = sum(p["duration"] for p in config.build_plan(opts))
        self.assertAlmostEqual(total, 12 * 3600, delta=10)

    def test_bad_values(self):
        opts = config.load_options(cmdline="pccheck.profile=turbo pccheck.ce_fail=abc pccheck.nonsense=1")
        self.assertEqual(opts.profile, "standard")
        self.assertEqual(opts.ce_fail, 1)


class ParserTest(unittest.TestCase):
    LSPCI = """00:01.1 PCI bridge [0604]: Advanced Micro Devices, Inc. [AMD] GPP Bridge [1022:1453]
\t\tLnkCap:\tPort #0, Speed 8GT/s, Width x16, ASPM L1, Exit Latency L1 <1s
\t\tLnkSta:\tSpeed 8GT/s, Width x8 (downgraded)

01:00.0 Non-Volatile memory controller [0108]: Samsung Electronics Co Ltd NVMe SSD Controller [144d:a80a]
\t\tLnkCap:\tPort #0, Speed 16GT/s, Width x4, ASPM L1, Exit Latency L1 <64us
\t\tLnkSta:\tSpeed 16GT/s (ok), Width x2 (downgraded)
\t\tLnkCap2: Supported Link Speeds: 2.5-16GT/s, Crosslink- Retimer+ 2Retimers+ DRS-
\t\tLnkSta2: Current De-emphasis Level: -3.5dB

02:00.0 Ethernet controller [0200]: Intel Corporation I350 Gigabit Network Connection [8086:1521]
\t\tLnkCap:\tPort #2, Speed 5GT/s, Width x4, ASPM L0s L1, Exit Latency L0s <4s, L1 <32s
\t\tLnkSta:\tSpeed 2.5GT/s (downgraded), Width x4 (ok)
"""

    def test_pcie(self):
        links = inventory.parse_pcie_links(self.LSPCI)
        self.assertTrue(links["00:01.1"]["bridge"])
        self.assertEqual((links["01:00.0"]["cap_width"], links["01:00.0"]["sta_width"]), (4, 2))
        f = Findings()
        inventory.check_pcie_links(links, f)
        self.assertEqual(f.get("pcie-width:01:00.0").severity, WARN)
        self.assertEqual(f.get("pcie-speed:02:00.0").severity, INFO)
        self.assertIsNone(f.get("pcie-width:00:01.1"))
        after = {k: dict(v) for k, v in links.items()}
        after["02:00.0"]["sta_width"] = 1
        f2 = Findings()
        inventory.check_pcie_links(after, f2, baseline=links)
        self.assertEqual(f2.get("pcie-width-drop:02:00.0").severity, FAIL)

    DMI = """# dmidecode 3.6
Handle 0x0010, DMI type 16, 23 bytes
Physical Memory Array
\tLocation: System Board Or Motherboard
\tError Correction Type: Multi-bit ECC

Handle 0x0011, DMI type 17, 92 bytes
Memory Device
\tSize: 32 GB
\tLocator: DIMM_A1
\tType: DDR5
\tSpeed: 4800 MT/s
\tManufacturer: Samsung
\tPart Number: M321R4GA3BB6-CQK
\tConfigured Memory Speed: 4400 MT/s

Handle 0x0012, DMI type 17, 92 bytes
Memory Device
\tSize: No Module Installed
\tLocator: DIMM_A2

Handle 0x0013, DMI type 17, 92 bytes
Memory Device
\tSize: 16 GB
\tLocator: DIMM_B1
\tType: DDR5
\tSpeed: 4800 MT/s
\tManufacturer: Micron
\tPart Number: MTC20F2085S1RC48BA1
\tConfigured Memory Speed: 4800 MT/s

Handle 0x0020, DMI type 4, 48 bytes
Processor Information
\tSocket Designation: CPU1
\tStatus: Populated, Enabled
\tThread Count: 1
"""

    def test_dmidecode(self):
        records = inventory.parse_dmidecode(self.DMI)
        dimms = inventory.dimms_from_dmi(records)
        self.assertEqual([d["locator"] for d in dimms], ["DIMM_A1", "DIMM_B1"])
        f = Findings()
        inventory.check_memory(records, f)
        self.assertEqual(f.get("memory-mixed").severity, WARN)
        self.assertEqual(f.get("memory-speed").severity, INFO)

    def test_sensors(self):
        data = {"coretemp-isa-0000": {"Adapter": "ISA adapter",
                                      "Package id 0": {"temp1_input": 71.0, "temp1_max": 80.0, "temp1_crit": 100.0,
                                                       "temp1_crit_alarm": 0.0}},
                "nvme-pci-0100": {"Composite": {"temp1_input": 44.85, "temp1_max": 81.85}}}
        readings = monitors.parse_sensors_json(data)
        self.assertEqual(len(readings), 2)
        self.assertEqual(monitors.classify_chip("coretemp-isa-0000"), "cpu")
        self.assertEqual(monitors.classify_chip("nvme-pci-0100"), "drive")

    def test_sel_and_sdr(self):
        self.assertEqual(monitors.classify_sel(
            "   1 | 03/04/2026 | 10:00:00 | Memory #0x01 | Correctable ECC | Asserted"), WARN)
        self.assertEqual(monitors.classify_sel(
            "   2 | 03/04/2026 | 10:00:00 | Memory #0x01 | Uncorrectable ECC | Asserted"), FAIL)
        self.assertEqual(monitors.classify_sel(
            "   3 | 03/04/2026 | 10:00:00 | Power Supply #0x51 | Power Supply AC lost | Asserted"), FAIL)
        self.assertIsNone(monitors.classify_sel(
            "   4 | 03/04/2026 | 10:00:00 | Temperature #0x30 | Upper Non-critical going high | Deasserted"))
        self.assertEqual(monitors.classify_sel(
            "   5 | 03/04/2026 | 10:00:00 | Event Logging Disabled #0x07 | Log area reset/cleared | Asserted"), INFO)
        rows = monitors.parse_sdr("CPU1 Temp        | 01h | ok  |  3.1 | 45 degrees C\nFAN3  | 43h | cr  | 29.3 | 0 RPM")
        self.assertEqual(rows[1], ("FAN3", "cr", "0 RPM"))

    def test_aer_file(self):
        text = "RxErr 3\nBadTLP 1\nBadDLLP 0\nRollover 0\nTimeout 0\nNonFatalErr 0\nCorrIntErr 0\nHeaderOF 0\nTOTAL_ERR_COR 4\n"
        self.assertEqual(monitors.parse_aer_file(text)["TOTAL_ERR_COR"], 4)


class SmartTest(unittest.TestCase):
    def test_ata(self):
        data = {"model_name": "HDD", "serial_number": "S1", "smart_status": {"passed": True},
                "ata_smart_attributes": {"table": [
                    {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 8}, "when_failed": ""},
                    {"id": 197, "name": "Current_Pending_Sector", "raw": {"value": 2}, "when_failed": ""},
                    {"id": 199, "name": "UDMA_CRC_Error_Count", "raw": {"value": 7}, "when_failed": ""}]},
                "ata_smart_self_test_log": {"standard": {"table": [{"status": {"passed": False, "string": "read failure"}}]}}}
        before = {"reallocated": 8, "pending": 0, "udma_crc": 1}
        found = {f["key"].split(":", 2)[2]: f["severity"] for f in disks.evaluate_smart(data, "/dev/sda HDD SN:S1", before)}
        self.assertEqual(found["reallocated"], WARN)
        self.assertEqual(found["pending"], FAIL)
        self.assertEqual(found["grew:pending"], FAIL)
        self.assertEqual(found["grew:udma_crc"], WARN)
        self.assertEqual(found["selftest"], FAIL)
        self.assertNotIn("grew:reallocated", found)

    def test_nvme_healthy(self):
        data = {"smart_status": {"passed": True},
                "nvme_smart_health_information_log": {"critical_warning": 0, "media_errors": 0, "percentage_used": 3,
                                                      "available_spare": 100, "available_spare_threshold": 10,
                                                      "num_err_log_entries": 12},
                "nvme_self_test_log": {"table": [{"self_test_result": {"value": 0}}]}}
        self.assertEqual(disks.evaluate_smart(data, "/dev/nvme0 X SN:1", {"num_err_log_entries": 0}), [])
        self.assertTrue(disks.is_solid_state(data))


class StressOutputTest(unittest.TestCase):
    class Ctx:
        def __init__(self):
            self.findings = Findings()

    def test_stressapptest(self):
        ctx = self.Ctx()
        phases.check_stressapptest(ctx, "memory", 0, "Stats: Found 0 hardware incidents\nStatus: PASS - please verify no corrected errors")
        self.assertEqual(verdict(ctx.findings), "PASS")
        phases.check_stressapptest(ctx, "memory", 1, "Log: Hardware Error: miscompare on CPU 3 at 0x7f00\n"
                                                    "Stats: Found 2 hardware incidents\nStatus: FAIL - test discovered HW problems")
        self.assertEqual(ctx.findings.get("sat-fail:memory").severity, FAIL)

    def test_stressng(self):
        ctx = self.Ctx()
        phase = phases.CpuPhase.__new__(phases.CpuPhase)
        phase.ctx = ctx
        phase.check_stressng("matrix", 0, "stress-ng: info:  [1] successful run completed in 60.00 secs")
        self.assertEqual(verdict(ctx.findings), "PASS")
        phase.check_stressng("matrix", 2, "stress-ng: fail:  [12] matrix: matrix-prod: result verification failed")
        self.assertEqual(verdict(ctx.findings), FAIL)


class StorageTest(unittest.TestCase):
    def test_plan_partition_iso(self):
        table = {"partitiontable": {"label": "dos", "sectorsize": 512, "partitions": [
            {"node": "/dev/sdb1", "start": 0, "size": 1_800_000, "type": "0"},
            {"node": "/dev/sdb2", "start": 1_000, "size": 8_000, "type": "ef"}]}}
        start, label = storage.plan_partition(table, 16 * 10**9, 1_800_000 * 512 + 3000)
        self.assertEqual(label, "dos")
        self.assertEqual(start % 2048, 0)
        self.assertGreaterEqual(start, 1_800_006)
        self.assertIsNone(storage.plan_partition(table, 1_800_000 * 512 + 10 * 2**20, 0))


if __name__ == "__main__":
    unittest.main()


class PersistenceTest(unittest.TestCase):
    """A power cut must never destroy both copies of the state (reboot detection depends on it)."""

    def test_rotating_slots_survive_interrupted_write(self):
        from pccheck.util import read_rotating, rotating_paths, write_rotating
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "state.json")
            for seq in range(1, 6):
                write_rotating(base, {"status": "running", "phase": f"p{seq}"}, seq)
            data, seq = read_rotating(base)
            self.assertEqual((data["phase"], seq), ("p5", 5))
            # simulate fsck truncating the slot that was being written during the reset
            newest = rotating_paths(base)[5 % 2]
            open(newest, "w").close()
            data, seq = read_rotating(base)
            self.assertEqual(data["phase"], "p4")
            # garbage in a slot is ignored as well
            with open(newest, "w") as fh:
                fh.write("{broken")
            self.assertEqual(read_rotating(base)[0]["phase"], "p4")

    def test_findings_reload_after_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "findings.json")
            f = Findings(path)
            f.add("k", FAIL, "Memory", "bad DIMM")
            reloaded = Findings(path)
            self.assertEqual(reloaded.get("k").severity, FAIL)
            reloaded.add("k2", WARN, "PCIe", "link")
            self.assertEqual(Findings(path).counts()[WARN], 1)


class SessionTest(unittest.TestCase):
    def test_resume_detects_reboot_without_pointer(self):
        from pccheck.session import Session
        from pccheck.util import write_rotating
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.join(tmp, "pccheck")
            sdir = os.path.join(base, "sessions", "20260101-000000_SN1")
            os.makedirs(sdir)
            write_rotating(os.path.join(sdir, "state.json"),
                           {"status": "running", "identity": {"machine_id": "abc123"},
                            "phases": {"cpu": {"status": "running"}}, "boots": [{"boot_id": "old-boot"}],
                            "last_heartbeat": "2026-01-01T00:05:00"}, 7)
            found, state, seq = Session._find_running(base, "abc123")
            self.assertEqual((found, seq), (sdir, 7))
            self.assertIsNone(Session._find_running(base, "other")[1])
            session = Session(base, sdir, state, seq)
            session._resume()
            self.assertTrue(session.unexpected_reboot)
            self.assertEqual(session.state["unexpected_reboots"], 1)
            self.assertEqual(session.previous_state["running_phase"], "cpu")
