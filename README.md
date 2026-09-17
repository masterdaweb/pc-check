# Master da Web PC-Check: automated bare-metal burn-in

PC-Check is a bootable USB Linux (Debian 13 live) that tests a machine's hardware on its own, for
hours or days, and ends with a clear **PASS / PASS WITH WARNINGS / FAIL** diagnosis. It aims to
catch the hardware that passes quick checks but later reboots or freezes in production: marginal
CPUs, DIMMs, VRMs/PSUs, PCIe links, disks and cooling.

## Why it catches what BurnInTest-style tools miss

Most burn-in tools run a steady load and check whether their own workload failed. Many unstable
machines survive that, then crash in production. PC-Check checks several more things:

| Weak spot of typical burn-in tools | What PC-Check does |
| --- | --- |
| Corrected errors are invisible: ECC fixes the bit flip, the test "passes". | Watches EDAC per-DIMM counters, machine checks (MCE/CMCI), APEI/GHES, PCIe AER and the BMC event log for the whole run. By default a single corrected memory error or machine check during burn-in is a **FAIL**. |
| Only steady full load. | Adds a **load-transient** phase (full load switched on and off from 50 ms to minutes) to stress PSU/VRM transient response, and an **idle soak** where deep C-state bugs cause "random" reboots. |
| A reset kills the test, and nothing records it. | The session state and kernel log are synced to the USB stick continuously. When the machine resets, the next boot detects it, recovers the kernel crash log (pstore/ERST), records the last phase and temperatures, reports a **FAIL** and continues with the remaining phases. Hangs become resets through panic-on-lockup and the hardware watchdog. |
| Workloads that don't verify results. | stress-ng with `--verify`, Google's **stressapptest** (the tool Google uses for server burn-in), and **Prime95** torture tests (FFT round-off checks). Any miscalculation is a FAIL. |
| Configuration faults go unnoticed. | Pre-checks for DIMMs not detected, mixed DIMMs, CPUs or cores disabled, PCIe links at reduced width (and links that degrade during the test), ECC present without error reporting, existing BMC hardware events, earlier crash logs, SMART problems and a dead CMOS battery. |

## Test sequence

| # | Phase | Share of time | What it tests |
| --- | --- | --- | --- |
| 0 | Inventory & pre-checks | a few minutes | Full hardware inventory, static checks, SMART baseline, starts drive self-tests and background disk surface scans |
| 1 | CPU stress | 14% | 22 stress-ng stressors with result verification (FPU, AVX/vector, matrix, crypto, cache, branch, TSC…) |
| 2 | Memory stress | 24% | stressapptest (~92% RAM, with power-spike pauses), then stress-ng VM with every access pattern |
| 3 | Prime95 torture | 16% | mprime blend torture test over all threads |
| 4 | Load transients | 12% | CPU+memory load toggled with random timing (fast/medium/slow step patterns) |
| 5 | Idle soak | 8% | Machine idle (disk scans paused) to exercise deep C-states |
| 6 | Combined max load | 26% | stressapptest memory + CPU threads + disk reads (+ optional iperf3): peak power and heat |
| 7 | Reboot / power-cycle stability | optional | `reboot_cycles=N`: reboots (cold power cycle via BMC when available) N times and checks that every CPU, DIMM, disk and NIC comes back |
| – | Final analysis | – | Waits for disk scans and self-tests, compares SMART and PCIe links before/after, checks kernel taint, writes reports |

These monitors run the whole time: kernel log (MCE, EDAC, AER, lockups, oopses, I/O errors, NVMe and SATA
resets, throttling, NMIs…), EDAC and AER counters, thermal throttle counters, lm-sensors
temperatures, the IPMI SEL and sensor states, NIC error counters and link flaps, turbostat (power and
C-states), plus a heartbeat with telemetry every 30 s.

Profiles (selected from the boot menu):

| Profile | Stress time | Extra wait for disk scans |
| --- | --- | --- |
| `quick` | 1 h | 0 |
| `standard` (default) | 12 h | up to 2 h |
| `extended` | 24 h | up to 8 h |
| `burnin` | 72 h | up to 24 h |

For a machine that must be completely stable in production, use `extended` as a minimum and
`burnin` (72 h) for new servers; the phases scale with the budget, so a longer run means more
cycles of every workload, not just one longer pass. Add `pccheck.reboot_cycles=5` to also prove
the machine survives repeated (cold) boots. Any duration works, e.g. `pccheck.hours=168`.

## Build

Requirements: Docker (on Linux or WSL2), about 10 GB of disk, and internet access.

```bash
./build.sh              # runs unit tests, then builds out/pccheck-<date>-amd64.iso
./build.sh --no-mprime  # without Prime95
```

The build uses Debian `live-build` inside a privileged container, with a package cache kept in the
`pccheck-build-cache` volume. Prime95 (`mprime`) is freeware, not in Debian, and gets downloaded at
build time. Set `MPRIME_URL`/`MPRIME_SHA256` to pin a version. Check that its license fits your use.

Unit tests only: `python3 -m unittest discover -s tests -t .`

## Create the USB stick

Use `write-usb.sh` (recommended). It writes the ISO and adds a FAT32 `PCCHECKDATA` partition for
logs and reports:

```bash
sudo ./write-usb.sh out/pccheck-*.iso /dev/sdX
sudo ./write-usb.sh out/pccheck-*.iso /dev/sdX --conf my-pccheck.conf   # with fleet defaults
```

If you write the ISO with another tool (dd, Etcher, Rufus in DD mode), PC-Check creates the
`PCCHECKDATA` partition itself on first boot, in the free space after the image. If the stick is a
FAT32 copy of the ISO (Rufus ISO mode), logs go to the stick itself. With no writable storage the
test still runs, but it warns that it cannot detect reboots.

Use a USB stick of **8 GB or more**. Plug it into a rear/motherboard port rather than a front-panel
header.

## Run

1. In the BIOS, make the USB stick the **first boot device**. The machine must boot back into
   PC-Check after an unexpected reset so the reset gets detected and the test continues.
2. Boot. The menu auto-selects the default entry after 10 s:
   - *automatic burn-in* uses `pccheck.conf` or the standard profile
   - *quick / extended / full burn-in*
   - *Advanced*: destructive disk write/verify, safe graphics (nomodeset), maintenance mode
     (no tests), load into RAM
   - *Utilities*: Memtest86+ (standalone, not part of the automatic report), UEFI firmware settings
3. Leave it alone. tty1 shows live progress, temperatures, disk scan progress and findings.
   - `q` twice: abort (the report is marked INCOMPLETE)
   - `Alt+F2`: root shell (`pccheck status`, `pccheck abort`); the serial console (IPMI SOL, 115200) also has a root shell
   - `http://<machine-ip>/` shows the report and `/status.json` shows live status (DHCP on all NICs)
4. At the end, the screen shows the verdict and the findings with recommended actions. On a FAIL
   with a BMC present, the chassis **identify LED** is turned on so the machine is easy to find in the rack.

**Note:** a manual reboot or power cut during the test counts as an unexpected reboot (FAIL).
Press `q` twice to abort first.

## Results

Everything goes on the `PCCHECKDATA` partition, which is readable on any OS:

```
pccheck/
  index.csv                         one line per finished run: time, serial, model, profile, verdict
  sessions/<date>_<serial>/
    report.txt | report.html | report.json
    state.json  findings.json
    inventory/   dmidecode, lspci -vvv, lshw, SMART scan, IPMI FRU/SDR/SEL, ethtool, ...
    logs/        kernel.log (all boots), telemetry.csv, turbostat.log, stress tool outputs,
                 smart-*.json, pstore/ (crash logs), ras-mc-ctl, journal, final dmesg
```

`report.json` is meant for automation, such as importing results into an asset or inventory
system. `pccheck report <session-dir>` regenerates a report.

## Configuration

Copy [pccheck.conf.example](pccheck.conf.example) to the root of `PCCHECKDATA` as `pccheck.conf`, or
press `e` in the GRUB menu and add `pccheck.<option>=<value>` to the `linux` line. Useful options:

| Option | Default | Meaning |
| --- | --- | --- |
| `profile` | standard | quick, standard, extended, burnin |
| `hours` | profile | custom stress duration |
| `skip` | – | phases to skip, e.g. `mprime,idle` |
| `destructive` | 0 | `1`: fio write+verify on non-boot disks **without partitions or filesystems**; `force`: all non-boot disks. A cancellable 120 s countdown runs first. |
| `ce_fail` / `mce_fail` / `aer_fail` | 1 / 1 / 20 | event counts that turn a warning into a FAIL |
| `max_unexpected_reboots` | 3 | after this many resets the remaining phases are skipped |
| `http`, `identify` | 1 | web report, chassis identify LED on FAIL |
| `reboot_cycles` | 0 | planned reboots at the end; each one verifies the hardware comes back complete (recommended: 5 for new servers) |
| `reboot_method` | auto | `auto`/`ipmi` (cold power cycle via BMC) or `reboot` (warm) |
| `iperf3` | – | iperf3 server to load the network during the combined phase |
| `auto` | 1 | `0` = maintenance mode |

## Reading the verdict

- **FAIL**: do not ship. Each finding names the component (DIMM label, PCIe address, disk serial,
  sensor) and an action. Typical fixes: replace or reseat the named DIMM, reseat the riser/card,
  replace the disk or cable, fix cooling, check the PSU. Then run the test again.
- **PASS WITH WARNINGS**: review each warning. Some are configuration notes (for example, a card in
  an electrically narrower slot).
- **Unexpected reboot**: the report includes the phase, the last temperatures and load, and any
  crash log. Resets under heavy load point to the PSU/VRM/CPU/cooling. Resets in the idle or
  transient phases point to power delivery or C-states (try a BIOS update or the PSU). Resets in the
  memory phases point to the DIMMs.

## Project layout

```
build.sh, write-usb.sh          host tools
docker/                         builder image + in-container build script
live/                           live-build configuration (packages, GRUB menu, systemd units, sysctl)
src/pccheck/                    the test orchestrator (Python, stdlib only)
  orchestrator.py               session flow, reboot detection, finalize, web server
  phases.py                     stress phases
  kmsg.py                       kernel log rules
  monitors.py                   EDAC, AER, throttling, sensors, IPMI, NIC, heartbeat
  disks.py                      SMART, self-tests, surface scan, write/verify
  inventory.py                  inventory and static checks
  report.py, dashboard.py       output
tests/                          unit tests for parsers and classification rules
tools/qemu-test.sh              boot the ISO in QEMU/KVM for a smoke test
```

## Verified behaviour

The image and the orchestrator were tested in QEMU/KVM with UEFI and legacy BIOS firmware,
a USB stick prepared by `write-usb.sh`, and NVMe + SATA test disks:

- full run through every phase, including real Prime95, stressapptest and stress-ng workloads,
  disk surface scans and SMART self-tests, ending in a report on screen, on the stick and over HTTP
- `pccheck.conf` on the stick is honoured, the boot menu overrides it
- **simulated power loss** (VM killed mid-test): the next boot detects the reset, recovers the
  evidence, reports `FAIL` naming the exact phase (`Machine reset unexpectedly during 'Memory
  stress'`), marks that phase `interrupted` and continues with the remaining phases
- planned reboot cycles resume without being counted as crashes, and measure the boot time
- the log partition is created automatically when the ISO is written with `dd`

State is written to two alternating files and every durable write is followed by `syncfs()` plus a
block-device flush, because on vfat a file `fsync()` alone does not flush the directory entry - a
power cut would otherwise destroy exactly the state needed to detect that power cut.

## Limitations

- Memtest86+ runs outside Linux, so its results aren't in the report. Use it separately if you want a
  pre-OS memory test. The in-OS memory stress plus ECC monitoring is usually more sensitive to
  marginal DIMMs.
- GPUs get no dedicated stress (a GPU dropping off the bus is still detected).
- Disks behind hardware RAID controllers get SMART checks through `smartctl --scan-open` where
  supported, but surface scans only cover block devices the OS can see.
- If the machine does not boot back into PC-Check after a reset (wrong boot order, or it does not
  POST at all), the reset is only recorded the next time the stick boots.
- The verdict is only as good as what the platform reports: on machines without ECC, or where the
  BIOS hides errors from the OS (no EDAC driver and no BMC), silent memory errors can only be
  caught through the stress tools' own data verification.
