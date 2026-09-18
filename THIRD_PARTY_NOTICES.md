# Third-party software

PC-Check's own code (the `src/pccheck` orchestrator, build scripts, live-build configuration
and tools in this repository) is licensed under the GNU General Public License v3.0 or later.
See [LICENSE](LICENSE).

The bootable ISO is an aggregate that also contains software by other authors, each under its
own license. Their licenses are not changed by PC-Check's license.

## Debian GNU/Linux packages

The live system is built from Debian 13 "trixie" packages (`main`, `contrib`, `non-free` and
`non-free-firmware`), including the Linux kernel, stress-ng, stressapptest, fio, smartmontools,
ipmitool, rasdaemon, lm-sensors and memtest86+. Each package's copyright and license are in the
image under `/usr/share/doc/<package>/copyright`.

Every release ships a `pccheck-<version>-amd64.packages` manifest listing the exact package names
and versions in the image. Source code for those versions is available from the Debian archive
(`apt-get source <package>=<version>`) and permanently from https://snapshot.debian.org/.
Firmware packages from `non-free-firmware` are distributed in binary form under their vendors'
redistribution terms.

## Prime95 / mprime

The ISO includes `mprime` (Prime95 for Linux) by Mersenne Research, Inc. / the Great Internet
Mersenne Prime Search (GIMPS), installed under `/opt/mprime`. It is freeware, **not open source**,
and is subject to the GIMPS end-user license shipped with it (`/opt/mprime/license.txt`) and the
rules at https://www.mersenne.org/legal/. It bundles GNU MP (LGPL-3.0-or-later / GPL-2.0-or-later)
and cJSON (MIT); see `/opt/mprime/readme.txt`.

PC-Check uses mprime only in torture-test mode and never connects to PrimeNet. To build an image
without it, run `./build.sh --no-mprime`.
