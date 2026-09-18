"""y-cruncher acceptance regressions; no stress workloads run in unit tests."""

import json
import os
import signal
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pccheck import config, kmsg, phases, ycruncher
from pccheck.findings import FAIL, verdict
from tests.test_acceptance import context


def success_output():
    # Representative lines from the pinned Linux 0.8.7.9547 release.
    return ("y-cruncher v0.8.7 Build 9547-gcc\nStop on Error: Enabled\n"
            "  Core 0: 126 MiB  node 0 (100%)\n  Core 2: 126 MiB  node 1 (100%)\n"
            + "".join(f"Running {tag}: Passed  Test Speed: 1.00 * 10^09 bits / sec\n"
                      for tag in ycruncher.TESTS)
            + "Test Finished. Waiting for threads to terminate...\n")


class YCruncherTest(unittest.TestCase):
    def parse(self, text, offset=0):
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(text.encode()); fh.flush()
            return ycruncher.read_evidence(fh.name, offset)

    def check(self, evidence, rc=0, elapsed=60, aborted=False):
        ctx = context()
        if aborted:
            ctx.abort_event.set()
        phases.YCruncherPhase(ctx, 60).check_result(evidence, [0, 2], 60, elapsed, rc)
        return ctx.findings

    def test_complete_verified_coverage(self):
        evidence = self.parse(success_output())
        self.assertEqual(evidence["allocation_nodes"], [0, 1])
        self.assertEqual(set(evidence["passed"]), set(ycruncher.TESTS))
        findings = self.check(evidence)
        self.assertEqual(verdict(findings), "PASS")
        self.assertIsNotNone(findings.get("ycruncher-ok"))

    def test_missing_algorithm_prevents_pass(self):
        text = success_output().replace("Running VT3: Passed", "Running VT3: Skipped")
        self.assertEqual(verdict(self.check(self.parse(text))), "INCOMPLETE")

    def test_core_without_allocation_prevents_pass(self):
        text = success_output().replace("Core 2:", "Core 3:")
        self.assertEqual(verdict(self.check(self.parse(text))), "INCOMPLETE")

    def test_missing_completion_marker_prevents_pass(self):
        text = success_output().replace("Test Finished. Waiting for threads to terminate...", "")
        self.assertEqual(verdict(self.check(self.parse(text))), "INCOMPLETE")

    def test_early_exit_nonzero_and_abort_prevent_pass(self):
        evidence = self.parse(success_output())
        for options in ({"elapsed": 2}, {"rc": 1}, {"rc": None}, {"aborted": True}):
            with self.subTest(options=options):
                self.assertEqual(verdict(self.check(evidence, **options)), "INCOMPLETE")

    def test_crashes_fail_without_claiming_specific_component(self):
        for rc in (-signal.SIGSEGV, 128 + signal.SIGSEGV, -signal.SIGILL, 128 + signal.SIGFPE):
            self.assertEqual(verdict(self.check(self.parse(""), rc=rc)), FAIL)

    def test_explicit_hardware_errors_fail_even_with_zero_exit_and_later_pass(self):
        for error in ("Running VT3: Failed", "Test Failed", "Stress test failed with 1 errors",
                      "Error(s) encountered on logical core 2", "Checksum Mismatch. Multiplication Failed."):
            with self.subTest(error=error):
                findings = self.check(self.parse(error + "\n" + success_output()))
                self.assertEqual(verdict(findings), FAIL)
                self.assertIsNone(findings.get("ycruncher-ok"))

    def test_initial_error_is_not_lost_after_large_output(self):
        text = "Test Failed\n" + "progress\n" * 40000 + success_output()
        self.assertEqual(verdict(self.check(self.parse(text))), FAIL)

    def test_resource_and_affinity_errors_are_incomplete(self):
        for error in ("Large heap allocation failed.", "Failed to set core affinity to core: 2"):
            self.assertEqual(verdict(self.check(self.parse(error + "\n" + success_output()))), "INCOMPLETE")

    def test_old_output_cannot_validate_new_run(self):
        old = success_output()
        evidence = self.parse(old + "Invalid configuration\n", len(old.encode()))
        self.assertEqual(evidence["passed"], {})
        self.assertEqual(verdict(self.check(evidence)), "INCOMPLETE")

    def test_aliases_and_console_colors(self):
        text = success_output().replace("Running N63:", "Running NTT63:").replace("Running VT3:", "Running VSTv3:")
        text = text.replace("Passed", "\x1b[32mPassed\x1b[0m")
        self.assertEqual(verdict(self.check(self.parse(text))), "PASS")

    def test_plan_includes_phase_and_preserves_profile_budget(self):
        for profile in config.PROFILES:
            opts = config.Options(profile=profile)
            plan = config.build_plan(opts)
            self.assertIn("ycruncher", [p["name"] for p in plan])
            self.assertAlmostEqual(sum(p["duration"] for p in plan), opts.total_hours * 3600, delta=10)

    def test_config_uses_actual_cpu_ids_and_explicit_limits(self):
        cfg = ycruncher.configuration([0, 2], 256, 60)["StressTest"]
        self.assertEqual(cfg["LogicalCores"], ["0", "2"])
        self.assertEqual(cfg["TotalMemory"], 256 * 2**20)
        self.assertTrue(cfg["AllocateLocally"])
        self.assertTrue(cfg["StopOnError"])
        self.assertLess(cfg["SecondsPerTest"] * len(ycruncher.TESTS), 60)

    def test_missing_binary_is_incomplete(self):
        ctx = context()
        with patch.object(phases.os, "access", return_value=False):
            phases.YCruncherPhase(ctx, 60).run()
        self.assertEqual(verdict(ctx.findings), "INCOMPLETE")

    def test_run_saves_config_result_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "logs"))
            ctx = context(tmp)
            proc = Mock(logfile=os.path.join(tmp, "logs", "ycruncher-stress.log"), output_start=0, started=0)
            proc.wait.return_value = 0
            with open(proc.logfile, "w") as fh:
                fh.write(success_output())
            with patch.object(phases.os, "access", return_value=True), \
                 patch.object(phases.os, "sched_getaffinity", return_value={0, 2}), \
                 patch.object(phases, "mem_budget_mib", return_value=256), \
                 patch.object(phases, "ManagedProcess", return_value=proc) as launch:
                phases.YCruncherPhase(ctx, 60).run()
            proc.stop.assert_called_once()
            self.assertIn("pause:-2", launch.call_args.args[0])
            self.assertEqual(launch.call_args.kwargs["env"]["LD_LIBRARY_PATH"], "/opt/y-cruncher/Binaries")
            with open(os.path.join(tmp, "logs", "ycruncher-result.json")) as fh:
                result = json.load(fh)
            self.assertEqual(result["requested_cores"], [0, 2])
            self.assertEqual(result["requested_memory_mib"], 256)
            self.assertEqual(verdict(ctx.findings), "PASS")

    def test_abort_or_wait_exception_always_reaps_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkdir(os.path.join(tmp, "logs"))
            ctx = context(tmp)
            proc = Mock()
            proc.wait.side_effect = RuntimeError("monitor failed")
            with patch.object(phases.os, "access", return_value=True), \
                 patch.object(phases, "mem_budget_mib", return_value=256), \
                 patch.object(phases, "ManagedProcess", return_value=proc):
                with self.assertRaises(RuntimeError):
                    phases.YCruncherPhase(ctx, 60).run()
            proc.stop.assert_called_once()

    def test_kernel_crash_identifies_launcher_and_architecture_binary(self):
        for name in ("y-cruncher", "19-ZN2 ~ Kagari", "24-ZN5 ~ Komari"):
            rule, _ = kmsg.classify(f"{name}[123]: segfault at 0 ip 000055d0 sp 00007ffc error 4")
            self.assertEqual(rule.id, "stress-crash")
