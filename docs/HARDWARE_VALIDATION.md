# Hardware validation review

Reviewed 2026-09-18. PC-Check has a useful Linux burn-in architecture, but the earlier verdict
was too optimistic to serve as an unattended production acceptance gate. More runtime alone
does not fix missing tests or unobserved error channels. There is no universal burn-in duration
that proves every CPU, DIMM, board, PSU and peripheral is sound.

## Corrections made

| Gap found in the implementation | Resulting behavior |
| --- | --- |
| Skipped/crashed phases, missing workload summaries and partial disk scans could pass. | Required evidence gaps yield INCOMPLETE. FAIL retains precedence. Text, HTML and JSON expose coverage gaps. |
| Appended workload logs allowed an earlier PASS to validate a later invocation. | Each process parses output from its own invocation only; exit status and completion summaries are checked. |
| VM memory allocation was divided twice. | Pass the total budget to stress-ng, which divides it internally. Preserve an OS reserve and refuse inadequate memory budgets. |
| stress-ng resource/unsupported exits were silently accepted. | Resource/setup errors are incomplete; unsupported CPU stressors are explicit warnings and removed from subsequent cycles. |
| rasdaemon evidence was collected as raw files without affecting the verdict. | Poll recorded memory, machine-check, PCIe and firmware events; retain decoded evidence and export a consistent SQLite backup. |
| Legacy EDAC drivers exposing controller totals could lose errors. | Include controller errors not attributed to DIMMs. Kernel-only corrected errors also honor thresholds. |
| BMC-only corrected ECC events did not honor the corrected-error policy. | Apply the CE threshold to newly asserted BMC correctable ECC events. |
| Long profiles still requested short tests on rotational disks. | Request long tests on HDDs and SSDs, check command acceptance, and require a fresh successful result. Parse SCSI and extended ATA self-test failures. |
| Combined load relied on surface scans still running. | Run sustained read-only direct random I/O throughout combined load, alongside RAM/CPU load and optional bidirectional network traffic. |
| Missing PCIe devices were absent from final comparison. | Detect disappearance; failure to obtain an inventory is a coverage gap. |
| Critical temperature findings did not stop further stress. | Abort the run on a sensor's critical temperature while retaining FAIL and producing reports. |
| Background monitors silently lost coverage; concurrent final polls could duplicate counters. | Record monitoring failures and serialize each monitor's sampling. |
| Python child setup used preexec_fn in a multithreaded process. | Set child priorities from the parent, avoiding this documented deadlock hazard. |
| Force-mode disk safety and reboot identity depended on volatile device names. | Protect active/mounted/held devices, exclude log storage, fail closed on discovery errors, and retain selected destructive disk identities. |
| Planned reboot cycles could interrupt disk self-tests. | Finish disk validation before planned reboots. |
| A missing/reordered NIC could change machine identity and conceal a previous crash. | Prefer firmware UUID/serial identity; use MAC only when those identifiers are unavailable. |

Start a fresh qualification session when moving from an older image: the stable machine identity
format changed. Keep previous reports for comparison; an old run and a new run are not one test.

## Practical acceptance procedure

1. Record expected CPU sockets/cores, DIMMs, capacities and slots, disk serials, PCIe cards, NIC
   ports, firmware versions, production power settings and memory population rules. Inventory
   describes what the OS sees; without an expected bill of materials it cannot identify a part
   that never enumerated at all.
2. Test at the intended supported firmware, microcode and BIOS settings. Preserve the firmware
   defaults/production settings in the asset record. Do not tune away a failure and then deploy
   with different settings. Unsupported overclocks are not an appropriate qualification baseline.
3. Prepare durable log storage, confirm the USB boots again after a reset, and verify that RAS,
   thermal and BMC reporting work on the actual server family. A VM is suitable for software
   integration checks, not electrical, thermal, DIMM or watchdog qualification.
4. Supplement Linux testing with standalone Memtest86+ and the server vendor's diagnostics.
   Linux tests cannot cover the physical pages occupied by the running kernel/firmware. Include
   memory address/pattern testing and the vendor's supported memory-controller checks.
5. Choose a budget appropriate to the platform and failure history. A practical initial policy is
   24 hours for routine systems, 72 hours for a new configuration or intermittent instability,
   and five planned boots. These are project recommendations, not standardized certification
   thresholds. Large drives may require longer to finish their surface scans and self-tests.
6. Configure an iperf3 peer on the intended network. Exercise each production NIC port/path
   separately and review negotiated speed, throughput, errors and link events. Enable destructive
   disk verification only on disposable storage. Hardware RAID requires controller/physical-drive,
   cache protection and rebuild tests in addition to OS-visible volume reads.
7. Perform externally supervised AC removal/cold startup and redundant PSU/feed failover tests
   where relevant. A BMC chassis power cycle leaves standby power available; software load steps
   do not measure PSU ripple, rail regulation or VRM electrical margins. A system that cannot POST
   or never returns from a hang needs external observation.
8. Hold deployment on FAIL or INCOMPLETE. Review every WARN and every deliberately untested
   subsystem against the asset's role. The strict default of failing on one corrected memory/MCE
   event is a conservative fleet acceptance policy, not a universal vendor replacement threshold.
9. After repairs or firmware changes, run the complete acceptance suite again. Finish with a soak
   on the intended production OS/kernel, drivers, storage layout and representative workload.
   Keep reports, firmware versions and the image checksum with the asset record.

## Boundaries of automated diagnosis

- A RAM miscompare implicates the memory path; it does not by itself prove that the DIMM is the
  defective part. CPU memory controllers, board traces, sockets, settings and power can cause
  similar symptoms. Slot swapping and controlled component substitution remain necessary.
- Kernel crashes may be caused by software/firmware as well as hardware. A FAIL is a deployment
  hold backed by evidence, not automatic authorization to replace the named component.
- GPU compute/VRAM, RDMA, vendor RAID/cache, PSU redundancy, true AC cycles and peripheral port
  qualification are not automatically covered. GPU presence and absent network load are reported.
- RAS support depends on the platform and firmware. Vendor-specific rasdaemon tables outside the
  standard memory/MCE/AER/extlog handlers remain available as raw evidence, not decoded verdict rules.
- Polling and durable USB writes reduce the evidence lost in a reset but cannot guarantee capture
  of the final instant. Use BMC/external supervision for hangs, failure to POST and lab power events.
- Surface reads establish readability, not original data integrity. Only known-pattern write/read
  verification can check the full write path; it necessarily destroys existing disk contents here.
- A missing SMART/self-test capability is an evidence gap, not proof of a bad disk. Resolve it with
  controller/vendor tooling and an explicit external acceptance record.

## Primary references

- [Linux RAS administration](https://cdn.kernel.org/doc/html/latest/admin-guide/RAS/main.html):
  corrected/uncorrected error reporting and the need to observe RAS evidence.
- [stress-ng manual packaged for Debian 13](https://manpages.debian.org/trixie/stress-ng/stress-ng.1.en.html)
  and [VM implementation](https://github.com/ColinIanKing/stress-ng/blob/V0.19.03/stress-vm.c):
  verification, exit status and division of the memory budget among workers.
- [Google stressapptest](https://github.com/stressapptest/stressapptest): userspace memory/I/O stress
  and data verification.
- [y-cruncher release and documentation](https://github.com/Mysticial/y-cruncher/releases/tag/v0.8.7.9547):
  pinned Linux component stress tester; its bundled `Command Lines.txt` describes automation.
  The configuration schema was obtained using the tester's Save Configuration command.
  See also the [commercial-use terms](https://www.numberworld.org/y-cruncher/license.html).
- [rasdaemon database implementation](https://github.com/mchehab/rasdaemon/blob/v0.8.3/ras-record.c):
  recorded hardware event schemas used by the monitor.
- [smartctl manual](https://manpages.debian.org/trixie/smartmontools/smartctl.8.en.html):
  self-tests and the exit-status bitmask.
- [fio documentation](https://fio.readthedocs.io/en/latest/fio_doc.html): direct I/O, time-based loads,
  read-only operation and write verification.
- [Memtest86+ documentation](https://memtest.org/readme): standalone memory coverage beyond what
  an OS-hosted test can access.
- [Python subprocess documentation](https://docs.python.org/3/library/subprocess.html):
  preexec_fn is unsafe with threads.

## Validation performed before adding y-cruncher

- 62 unit/regression tests pass, including missing evidence, stale PASS output, memory budgeting,
  corrected/uncorrected error handling, self-test freshness, destructive-target protection and
  stable hardware identity. Tests do not stress or write to host hardware.
- The Debian live ISO builds successfully. Its SHA-256 manifest verifies and every packaged
  Python module matches the current source.
- A shortened QEMU/KVM run exercises CPU, memory, Prime95, transients, idle and combined load,
  surface reads and report generation. Actual stress-ng output confirms that four VM workers
  share the full requested memory budget. Combined fio reads run after surface scans finish.
- The short run correctly reports INCOMPLETE: Prime95 has insufficient time to complete FFT
  self-tests and the virtual NVMe controller does not support drive self-tests. Its smartctl
  command nevertheless returns zero, demonstrating why completion evidence is required.
- On the final image, an abrupt VM power loss during CPU stress is recovered as exactly one
  unexpected reboot and a persistent FAIL. The interrupted phase remains interrupted. The
  remaining phases run and one planned warm reboot completes with hardware intact, without
  increasing the unexpected-reboot count. Unsupported virtual drive self-tests still mark
  coverage incomplete, including the checks performed before the planned reboot.

Local artifacts: `out/pccheck-2026.09.18-amd64.iso`, its `.sha256` manifest,
`out/qemu-review/report.json`, and `out/qemu-final/{report.json,validation.json}`.
The final VM hardware report intentionally says FAIL because a reset was injected; the validation
record confirms the expected behavior. No 24–72 hour physical-server qualification was performed
in this development session.

## y-cruncher coverage

The new `ycruncher` phase runs automatically for 12% of each profile's stress budget. It uses
SFTv4, SNT, SVT, FFTv4, N63 and VT3, with verified results, local memory allocation for each
assigned logical core, stop-on-error, and explicit duration/memory limits. The other phases
remain in the plan. These time allocations are fleet screening policy, not a certification.

The report requires per-algorithm success, allocation evidence for every assigned core, normal
completion and sufficient elapsed time. Calculation failures and crashes produce FAIL; absent
binaries, unsupported algorithms, setup errors, timeout, abort and early exit produce INCOMPLETE.
The parser reads the whole current invocation so an earlier error or an old PASS cannot be lost
or reused. Raw output, configuration and structured results remain in the session's `logs/`.
Memory/CPU failures still need correlation with ECC/MCE/BMC evidence to isolate a component.

The default archive is 0.8.7.9547 dynamic Linux, obtained from the author's GitHub release with
SHA-256 `bee23ee59464d71635a054bb4f6f09c06b8ef0bdc441fb70d4cd81a9bd42a7a7`, matching the release
asset's published digest. The full distribution and its notices are retained. Downloads must
pass checksum validation; custom URLs require an explicit SHA-256. Build with `--no-ycruncher`
to omit it. Its commercial-use terms must be resolved with the author before commercial use.

Validation for this addition:

- 79 unit/regression tests pass, including 17 y-cruncher tests for missing algorithms/cores,
  stale success output, errors early in long logs, setup failures, signals, timeout/abort,
  process cleanup and time-budget preservation. These tests do not run stress workloads.
- A separate real-binary wrapper smoke test completed all six algorithms using only two cores
  and 256 MiB for about 32 seconds. It caught and verified the fix for the bundled TBB library
  search path when running from an isolated working directory.
- Build-script syntax and ShellCheck checks pass. A custom download without a SHA-256 is rejected
  before network/build work begins.
- The updated ISO builds and its SHA-256 verifies. Every Python module extracted from its
  squashfs matches the final source; the pinned upstream archive provenance and license are present.
- A targeted QEMU/KVM boot starts y-cruncher automatically on four vCPUs with 2333 MiB allocated.
  The phase finishes in 94 seconds, records all six algorithms successfully (11 successful tests
  total), and appears as `done` with zero phase warnings/failures in the saved report. The overall
  verdict correctly remains INCOMPLETE because other stress phases were deliberately skipped.

Addition artifacts: `out/pccheck-2026.09.18-ycruncher-amd64.iso`, its `.sha256` manifest,
and `out/qemu-ycruncher/{report.json,validation.json,ycruncher-result.json,ycruncher-stress.log}`.
These are integration checks; long physical-server, multi-socket/NUMA and fault-injection
qualification remains necessary before fleet rollout.
