"""Regression tests for false passes and hardware error coverage; no hardware stress on the host."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch, Mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pccheck import config, disks, inventory, kmsg, monitors, phases, report, orchestrator, session
from pccheck.findings import Findings, FAIL, WARN, verdict
from pccheck.ras import RasMonitor
from pccheck.util import ManagedProcess, write_rotating


def context(directory="/tmp"):
    state = {"baselines": {}, "disk_scans": {}, "plan": [], "phases": {}}
    counters = {}
    session = SimpleNamespace(state=state, lock=threading.RLock(), save=Mock(),
                              path=lambda *p: os.path.join(directory, *p),
                              per_boot_counters=lambda g: counters.setdefault(g, {}))
    ctx = SimpleNamespace(session=session, findings=Findings(), opts=config.Options(),
                          abort_event=threading.Event(), boot_disk="sdb", sysfs_counters=set(),
                          status_note="", disk_manager=None)
    ctx.request_abort = lambda reason: ctx.abort_event.set()
    return ctx


class AcceptanceTest(unittest.TestCase):
    def test_invalid_duration_and_thresholds_cannot_silently_weaken_tests(self):
        opts = config.load_options(cmdline="pccheck.hours=inf pccheck.ce_fail=0 pccheck.reboot_cycles=-1")
        self.assertEqual(len(opts.validation_errors), 3)
        self.assertEqual(opts.ce_fail, 1)
        self.assertTrue(config.build_plan(opts))

    def test_machine_identity_survives_missing_nic(self):
        with patch.object(session, "_dmi", side_effect=lambda key: "stable-uuid" if key == "system-uuid" else ""), \
             patch.object(session, "first_mac", side_effect=["aa:bb:cc:dd:ee:ff", ""]):
            self.assertEqual(session.machine_identity()["machine_id"], session.machine_identity()["machine_id"])

    def test_abort_cancels_destructive_countdown(self):
        ctx = context()
        ctx.abort_event.set()
        self.assertFalse(orchestrator.confirm_destructive(ctx, [{"name": "fake", "model": "test", "size": 1024}]))

    def test_missing_evidence_blocks_pass_but_failure_takes_precedence(self):
        f = Findings()
        f.add("gap", WARN, "Test", "workload missing", incomplete=True)
        self.assertEqual(verdict(f), "INCOMPLETE")
        f.add("ue", FAIL, "Memory", "uncorrected error")
        self.assertEqual(verdict(f), FAIL)

    def test_running_error_skipped_and_missing_sessions_do_not_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(report.build(tmp)[2], "INCOMPLETE")
            for seq, status in enumerate(("pending", "running", "error", "skipped", "interrupted", "aborted"), 1):
                state = {"status": "complete", "plan": [{"name": "cpu"}], "phases": {"cpu": {"status": status}}}
                write_rotating(os.path.join(tmp, "state.json"), state, seq)
                self.assertEqual(report.build(tmp, incomplete=False)[2], "INCOMPLETE", status)

    def test_report_machine_readable_coverage_and_failure_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = {"status": "complete", "plan": [{"name": "cpu"}],
                     "phases": {"cpu": {"status": "done"}}, "options": {"skip": ["memory"]},
                     "disk_scans": {"SN1": {"done": False}}}
            write_rotating(os.path.join(tmp, "state.json"), state, 1)
            f = Findings(os.path.join(tmp, "findings.json"))
            f.add("ue", FAIL, "Memory", "UE")
            self.assertEqual(report.write_reports(tmp)[0], FAIL)
            with open(os.path.join(tmp, "report.json")) as fh:
                data = json.load(fh)
            self.assertFalse(data["coverage_complete"])
            self.assertEqual(len(data["coverage_gaps"]), 2)

    def test_completed_clean_run_can_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_rotating(os.path.join(tmp, "state.json"),
                           {"status": "complete", "plan": [{"name": "cpu"}],
                            "phases": {"cpu": {"status": "done"}}}, 1)
            self.assertEqual(report.build(tmp)[2], "PASS")

    def test_incomplete_persists_and_cannot_be_downgraded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "findings.json")
            f = Findings(path)
            f.add("gap", WARN, "Test", "gap", incomplete=True)
            f.add("gap", WARN, "Test", "gap", incomplete=False)
            f.flush()
            self.assertEqual(verdict(Findings(path)), "INCOMPLETE")


class WorkloadTest(unittest.TestCase):
    def test_old_pass_does_not_validate_new_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            logfile = os.path.join(tmp, "workload.log")
            with open(logfile, "w") as fh:
                fh.write("Status: PASS\n")
            proc = ManagedProcess([sys.executable, "-c", "print('initialization failed')"], logfile,
                                  low_priority=False)
            proc.proc.wait(timeout=5)
            proc.close()
            self.assertNotIn("Status: PASS", proc.output_tail())
            self.assertIn("initialization failed", proc.output_tail())

    def test_stressng_resource_errors_not_success(self):
        for rc in (1, 3, 6, 7, 127):
            ctx = context()
            phases.CpuPhase(ctx, 60).check_stressng("cpu", rc, "")
            self.assertEqual(verdict(ctx.findings), "INCOMPLETE", rc)

    def test_unsupported_stressor_is_explicit_warning(self):
        ctx = context()
        phases.CpuPhase(ctx, 60).check_stressng("vnni", 4, "unsupported")
        self.assertEqual(verdict(ctx.findings), "PASS WITH WARNINGS")

    def test_sat_bad_exit_overrides_pass_text(self):
        ctx = context()
        phases.check_stressapptest(ctx, "memory", 1, "Status: PASS")
        self.assertEqual(verdict(ctx.findings), "INCOMPLETE")

    def test_sat_miscompare_without_summary_is_failure(self):
        ctx = context()
        phases.check_stressapptest(ctx, "memory", 1, "Hardware Error: miscompare at 0x1234")
        self.assertEqual(verdict(ctx.findings), FAIL)

    def test_memory_budget_reserves_os_ram(self):
        with patch.object(phases, "meminfo", return_value={"MemAvailable": 500 * 2**20, "MemTotal": 1024 * 2**20}):
            with self.assertRaises(RuntimeError):
                phases.mem_budget_mib(.92)

    def test_vm_bytes_is_total_not_divided_twice(self):
        ctx = context()
        with patch.object(phases, "have", return_value=False), \
             patch.object(phases, "mem_budget_mib", return_value=4096), \
             patch.object(phases, "cpu_count", return_value=16), \
             patch.object(phases.MemoryPhase, "run_stressng") as run:
            phases.MemoryPhase(ctx, 60).run()
        args = run.call_args.args[1]
        self.assertEqual(args[args.index("--vm-bytes") + 1], "4096M")

    def test_combined_disk_reads_even_when_surface_scan_finished_and_cleanup_on_error(self):
        ctx = context()
        ctx.disk_manager = Mock(exclude=("sdb",))
        proc = Mock()
        proc.poll.return_value = None
        with patch.object(disks, "block_disks", return_value=[{"name": "sda", "path": "/dev/sda"}]), \
             patch.object(phases, "ManagedProcess", return_value=proc) as start, \
             patch.object(phases, "mem_budget_mib", return_value=1024), \
             patch.object(phases, "run_stressapptest", side_effect=RuntimeError("SAT unavailable")):
            with self.assertRaises(RuntimeError):
                phases.CombinedPhase(ctx, 60).run()
        cmd = start.call_args.args[0]
        self.assertIn("--readonly", cmd)
        self.assertIn("--time_based=1", cmd)
        self.assertIn("--allow_file_create=0", cmd)
        proc.stop.assert_called_once()
        ctx.disk_manager.resume.assert_called_once()


class MonitoringTest(unittest.TestCase):
    def test_legacy_edac_controller_only_counts_are_not_lost(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "mc0"))
            for name, value in (("ce_count", "5"), ("ue_count", "1")):
                with open(os.path.join(tmp, "mc0", name), "w") as fh:
                    fh.write(value)
            self.assertEqual(monitors.edac_counts(tmp)["mc0/noinfo"][1:], (5, 1))

    def test_edac_dimm_plus_controller_does_not_double_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "mc0", "dimm0"))
            for name, value in (("ce_count", "5"), ("dimm0/dimm_ce_count", "4")):
                with open(os.path.join(tmp, "mc0", name), "w") as fh:
                    fh.write(value)
            self.assertEqual(sum(v[1] for v in monitors.edac_counts(tmp).values()), 5)

    def test_kernel_fallback_corrected_errors_obey_threshold(self):
        for msg in ("EDAC MC0: 1 CE on DIMM_A1", "pcieport 0000:00:01.0: PCIe Bus Error: severity=Corrected"):
            ctx = context()
            ctx.opts.aer_fail = 1
            kmsg.KmsgMonitor(ctx)._process(3, 200, msg)
            self.assertEqual(verdict(ctx.findings), FAIL)

    def test_uncorrected_kernel_edac_cannot_be_hidden_by_sysfs(self):
        ctx = context()
        ctx.sysfs_counters.add("edac")
        kmsg.KmsgMonitor(ctx)._process(3, 200, "EDAC MC0: 1 UE on DIMM_A1")
        self.assertEqual(verdict(ctx.findings), FAIL)

    def test_monitor_exception_blocks_pass(self):
        ctx = context()
        mon = monitors.Monitor(ctx)
        mon.poll = Mock(side_effect=OSError("lost sensor"))
        mon.sample()
        self.assertEqual(verdict(ctx.findings), "INCOMPLETE")

    def test_critical_temperature_stops_stress(self):
        ctx = context()
        data = {"coretemp-isa-0000": {"Package": {"temp1_input": 101, "temp1_crit": 100}}}
        with patch.object(monitors, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(data), "")):
            monitors.SensorMonitor(ctx).poll()
        self.assertTrue(ctx.abort_event.is_set())
        self.assertEqual(verdict(ctx.findings), FAIL)

    def test_pcie_disappearance_is_failure(self):
        ctx = context()
        inventory.check_pcie_links({}, ctx.findings,
                                   baseline={"01:00.0": {"name": "NIC", "bridge": False}})
        self.assertEqual(verdict(ctx.findings), FAIL)

    def test_ras_trace_only_events_and_cursor_resume(self):
        ctx = context()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ras.db")
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE mc_event (id INTEGER PRIMARY KEY, err_type TEXT, err_count INT, label TEXT)")
                db.execute("INSERT INTO mc_event VALUES (1, 'Corrected', 2, 'DIMM_A1')")
            mon = RasMonitor(ctx)
            mon.database = path
            with patch("pccheck.ras.run", return_value=subprocess.CompletedProcess([], 0, "", "")):
                mon.poll()
                mon.poll()
            self.assertEqual(verdict(ctx.findings), FAIL)
            self.assertEqual(ctx.findings.all()[0].count, 2)

    def test_ras_uncorrected_mce_ignores_high_corrected_threshold(self):
        ctx = context()
        ctx.opts.mce_fail = 100
        RasMonitor(ctx).record("mce_record", {"status": (1 << 61), "socketid": 0, "bank": 2})
        self.assertEqual(verdict(ctx.findings), FAIL)

    def test_ras_informational_memory_event_is_not_a_fault(self):
        ctx = context()
        RasMonitor(ctx).record("mc_event", {"err_type": "Info"})
        self.assertEqual(verdict(ctx.findings), "PASS")

    def test_bmc_only_corrected_ecc_fails_strict_acceptance(self):
        ctx = context()
        ctx.session.state["baselines"]["sel_hashes"] = []
        mon = monitors.IpmiMonitor(ctx)
        mon.sel_lines = lambda: ["1 | 01/01/2026 | 12:00:00 | Memory #0x01 | Correctable ECC | Asserted"]
        with patch.object(monitors, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            mon.poll()
        self.assertEqual(verdict(ctx.findings), FAIL)


class DiskCompletionTest(unittest.TestCase):
    def test_failed_discovery_is_not_an_empty_healthy_disk_inventory(self):
        with patch.object(disks, "run", return_value=subprocess.CompletedProcess([], 1, "", "failed")):
            with self.assertRaises(RuntimeError):
                disks.block_disks()
            with self.assertRaises(RuntimeError):
                disks.smart_devices()

    def test_powercycle_uses_stable_disk_identities(self):
        ctx = context()
        before = {"name": "sda", "serial": "S1", "size": 100}
        after = {"name": "sdc", "serial": "S1", "size": 100}
        with patch.object(disks, "block_disks", side_effect=[[before], [after]]), \
             patch("pccheck.util.out", return_value=""):
            phase = phases.PowerCyclePhase(ctx, 0)
            self.assertEqual(phase.snapshot()["disks"], phase.snapshot()["disks"])

    def test_destructive_resume_cannot_target_replacement_at_same_device_name(self):
        ctx = context()
        disk = {"name": "sda", "path": "/dev/sda", "size": 8192, "serial": "replacement", "model": "disk"}
        dm = disks.DiskManager(ctx)
        ctx.disk_manager = dm
        ctx.session.state.update(destructive_disks=["sda"], destructive_identities={"original": 8192})
        dm.start_scans = Mock()
        with patch.object(orchestrator, "block_disks", return_value=[disk]):
            orchestrator.start_disk_tests(ctx)
        dm.start_scans.assert_called_once_with([])

    def test_completed_disk_validation_is_not_restarted_after_planned_reboot(self):
        ctx = context()
        ctx.session.state["disk_tests_finished"] = True
        ctx.disk_manager = Mock()
        orchestrator.start_disk_tests(ctx)
        ctx.disk_manager.start_scans.assert_not_called()

    def test_hdds_get_long_selftests_and_health_bits_do_not_hide_start(self):
        ctx = context()
        ctx.session.state["baselines"]["smart"] = {"/dev/sda|sat": {"label": "HDD", "solid_state": False}}
        dm = disks.DiskManager(ctx)
        with patch.object(disks, "run", return_value=subprocess.CompletedProcess([], 8, "started", "")) as run:
            dm.start_selftests(True)
        self.assertIn("long", run.call_args.args[0])
        self.assertTrue(dm.selftests["/dev/sda|sat"]["started"])

    def test_selftest_start_failure_is_incomplete(self):
        ctx = context()
        ctx.session.state["baselines"]["smart"] = {"/dev/sda|sat": {"label": "HDD"}}
        with patch.object(disks, "run", return_value=subprocess.CompletedProcess([], 4, "unsupported", "")):
            disks.DiskManager(ctx).start_selftests(True)
        self.assertEqual(verdict(ctx.findings), "INCOMPLETE")

    def test_stale_selftest_result_not_accepted_but_new_completion_is(self):
        for fresh in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                os.mkdir(os.path.join(tmp, "logs"))
                ctx = context(tmp)
                old = [{"status": {"passed": True}, "lifetime_hours": 5}]
                new = [{"status": {"passed": True}, "lifetime_hours": 6}] if fresh else old
                ctx.session.state["baselines"]["smart"] = {
                    "/dev/sda|sat": {"label": "HDD", "selftest_log": old}}
                dm = disks.DiskManager(ctx)
                dm.selftests["/dev/sda|sat"] = {"started": True}
                with patch.object(disks, "smart_read", return_value={
                        "ata_smart_self_test_log": {"standard": {"table": new}}}):
                    dm.smart_final(0)
                self.assertEqual(verdict(ctx.findings), "PASS" if fresh else "INCOMPLETE")

    def test_scsi_and_extended_ata_failures(self):
        samples = [
            {"scsi_self_test_0": {"result": {"value": 7, "string": "segment failure"}}},
            {"ata_smart_self_test_log": {"extended": {"table": [{"status": {"passed": False}}]}}},
        ]
        for data in samples:
            self.assertTrue(any(f["severity"] == FAIL for f in disks.evaluate_smart(data, "disk")))

    def test_truncated_disk_read_is_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "disk")
            with open(path, "wb") as fh:
                fh.write(b"\0" * 4096)
            ctx = context(tmp)
            dm = disks.DiskManager(ctx)
            disk = {"name": "fake", "path": path, "size": 8192, "model": "fake", "serial": "S1"}
            scan = disks.SurfaceScan(dm, disk)
            scan.run()
            self.assertFalse(scan.done)
            self.assertEqual(verdict(ctx.findings), FAIL)

    def test_partial_scan_is_incomplete(self):
        ctx = context()
        dm = disks.DiskManager(ctx)
        scan = Mock(done=False, disk={"name": "fake", "serial": "S1"}, progress=.5)
        dm.scans = [scan]
        dm.stop()
        self.assertEqual(verdict(ctx.findings), "INCOMPLETE")

    def test_force_never_writes_mounted_or_unidentified_boot_disks(self):
        for boot, mounted, rc in (("sdb", "/mnt/data", 0), ("", None, 0), ("sdb", None, 1)):
            ctx = context()
            ctx.boot_disk = boot
            ctx.opts.destructive = "force"
            data = json.dumps({"blockdevices": [{"name": "sda", "mountpoints": [mounted]}]})
            with patch.object(disks, "run", side_effect=[subprocess.CompletedProcess([], rc, "", ""),
                                                        subprocess.CompletedProcess([], 0, data, "")]):
                eligible, skipped = disks.DiskManager(ctx).destructive_candidates([{"name": "sda", "path": "/dev/sda"}])
            self.assertFalse(eligible)
            self.assertEqual(len(skipped), 1)
