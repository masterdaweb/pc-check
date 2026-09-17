"""Persistent log storage on the boot USB stick.

Lookup order:
 1. a filesystem labelled PCCHECKDATA (created by write-usb.sh), preferring the boot disk
 2. the boot medium itself if it is writable (e.g. ISO extracted to a FAT32 stick by Rufus)
 3. free space after the ISO image on the boot disk: a PCCHECKDATA partition is created
 4. RAM only (reboots cannot be detected; reported as a warning)
"""

import dataclasses
import errno
import json
import logging
import os
import stat
import struct
import time

from .util import out, read_file, run, set_flush_device

log = logging.getLogger("pccheck")

DATA_LABEL = "PCCHECKDATA"
MOUNT_POINT = "/mnt/pccheck"
LIVE_MEDIUM = "/run/live/medium"
RAM_FALLBACK = "/run/pccheck/storage"
MIN_FREE_BYTES = 256 * 1024 * 1024


@dataclasses.dataclass
class StorageInfo:
    root: str               # directory where pccheck/ lives
    device: str = ""
    persistent: bool = False
    note: str = ""
    boot_disk: str = ""     # e.g. "sdb"; excluded from disk tests


def _findmnt_source(path):
    return out(["findmnt", "-no", "SOURCE", path]).strip()


def _fstype(dev):
    return out(["blkid", "-o", "value", "-s", "TYPE", dev]).strip()


def parent_disk(dev):
    """/dev/sdb1 -> sdb, /dev/sdb -> sdb, /dev/nvme0n1p2 -> nvme0n1."""
    if not dev.startswith("/dev/"):
        return ""
    pk = out(["lsblk", "-ndo", "PKNAME", dev]).strip()
    return pk or os.path.basename(dev)


def find_boot_disk():
    src = _findmnt_source(LIVE_MEDIUM)
    if not src:
        # toram: medium unmounted; live-boot records the device it copied from
        for line in read_file("/run/live/medium-device").splitlines():
            src = line.strip()
    return (parent_disk(src) if src else ""), src


def _labelled_devices():
    res = run(["blkid", "-t", f"LABEL={DATA_LABEL}", "-o", "device"])
    return [d.strip() for d in res.stdout.splitlines() if d.strip()]


def _is_mounted_at(mount_point):
    return os.path.ismount(mount_point)


def usable_device(dev):
    """A device node that can be opened exclusively (for mkfs, fsck and mount).

    When the live system booted from a dd'ed ISO, the whole USB disk is mounted as the live
    medium and the kernel refuses exclusive opens of its partitions (EBUSY). In that case a
    loop device mapped over the partition's byte range gives the same data without the claim.
    """
    try:
        fd = os.open(dev, os.O_RDWR | os.O_EXCL)
        os.close(fd)
        return dev
    except OSError as exc:
        if exc.errno != errno.EBUSY:
            log.warning("cannot open %s: %s", dev, exc)
            return dev
    name = os.path.basename(dev)
    start = read_file(f"/sys/class/block/{name}/start").strip()
    size = read_file(f"/sys/class/block/{name}/size").strip()
    disk = parent_disk(dev)
    if not (start and size and disk and disk != name):
        return dev
    res = run(["losetup", "--find", "--show", "--offset", str(int(start) * 512),
               "--sizelimit", str(int(size) * 512), f"/dev/{disk}"])
    loop = res.stdout.strip()
    if res.returncode != 0 or not loop:
        log.error("losetup for %s failed: %s", dev, res.stderr.strip())
        return dev
    # Without direct I/O the loop device writes into the page cache of the backing disk and
    # flushes are not propagated: everything written in the last ~30 s is lost on a power cut,
    # which would defeat reboot detection. Direct I/O sends each write straight to the disk.
    if run(["losetup", "--direct-io=on", loop]).returncode != 0:
        log.warning("could not enable direct I/O on %s; writes may be lost on a sudden reset", loop)
    set_flush_device(f"/dev/{disk}")
    log.info("%s is busy (boot disk in use); using %s over the same sectors", dev, loop)
    return loop


def _mount(dev, mount_point):
    os.makedirs(mount_point, exist_ok=True)
    fstype = _fstype(dev)
    target = usable_device(dev)
    if fstype == "vfat":
        # Repair a dirty FAT left behind by a crash before mounting read-write.
        run(["fsck.vfat", "-a", "-w", target], timeout=600)
        # sync: the log partition must survive an unannounced reset at any moment
        opts = "rw,noatime,sync,flush,utf8,dmask=0022,fmask=0133"
    elif fstype.startswith("ext"):
        run(["fsck", "-p", target], timeout=1800)
        opts = "rw,noatime,sync,data=journal" if fstype in ("ext3", "ext4") else "rw,noatime,sync"
    else:
        opts = "rw,noatime,sync"
    res = run(["mount", "-t", fstype or "auto", "-o", opts, target, mount_point])
    if res.returncode != 0:
        log.error("mount %s failed: %s", target, res.stderr.strip())
        return False
    return True


def _writable(path):
    probe = os.path.join(path, ".pccheck-write-test")
    try:
        with open(probe, "w") as fh:
            fh.write("ok")
            fh.flush()
            os.fsync(fh.fileno())
        os.unlink(probe)
        return True
    except OSError:
        return False


def iso_size_bytes(dev):
    """Size of an ISO9660 filesystem (from the primary volume descriptor), 0 if not ISO9660."""
    try:
        with open(dev, "rb") as fh:
            fh.seek(32768)
            pvd = fh.read(2048)
    except OSError:
        return 0
    if len(pvd) < 136 or pvd[1:6] != b"CD001":
        return 0
    blocks = struct.unpack_from("<I", pvd, 80)[0]
    block_size = struct.unpack_from("<H", pvd, 128)[0] or 2048
    return blocks * block_size


def plan_partition(sfdisk_json, disk_bytes, iso_bytes, sector=512):
    """Decide where a new data partition fits. Returns (start_sector, label_type) or None."""
    table = (sfdisk_json or {}).get("partitiontable", {})
    label = table.get("label", "dos")
    sector = table.get("sectorsize", sector)
    parts = table.get("partitions", [])
    if label == "dos" and len(parts) >= 4:
        return None
    end = max([p["start"] + p["size"] for p in parts] + [0])
    end = max(end, (iso_bytes + sector - 1) // sector)
    align = (1024 * 1024) // sector
    start = ((end + align - 1) // align) * align
    last_usable = disk_bytes // sector - (34 if label == "gpt" else 1)
    if (last_usable - start) * sector < MIN_FREE_BYTES:
        return None
    return start, label


def create_data_partition(disk):
    """Append a FAT32 PCCHECKDATA partition in the free space after the ISO on the boot disk."""
    dev = f"/dev/{disk}"
    dump = run(["sfdisk", "--json", dev])
    if dump.returncode != 0:
        log.info("no partition table on %s: %s", dev, dump.stderr.strip())
        return ""
    try:
        table = json.loads(dump.stdout)
    except ValueError:
        return ""
    disk_bytes = int(out(["blockdev", "--getsize64", dev]).strip() or 0)
    plan = plan_partition(table, disk_bytes, iso_size_bytes(dev))
    if not plan:
        log.info("no room for a data partition on %s", dev)
        return ""
    start, label = plan
    if label == "gpt":
        # xorriso places the backup GPT at the end of the image; move it to the end of the disk.
        run(["sfdisk", "--force", "--relocate", "gpt-bak-std", dev])
        ptype = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
    else:
        ptype = "c"
    before = set(out(["lsblk", "-lnpo", "NAME", dev]).split())
    res = run(["sfdisk", "--force", "--append", "--no-reread", "--no-tell-kernel", dev],
              input=f"start={start}, type={ptype}\n")
    if res.returncode != 0:
        log.error("sfdisk append failed on %s: %s", dev, res.stderr.strip())
        return ""
    # The disk is in use (live medium), so add only the new partition to the kernel.
    run(["partx", "-a", dev])
    run(["udevadm", "settle"], timeout=60)
    time.sleep(1)
    new = [p for p in out(["lsblk", "-lnpo", "NAME", dev]).split() if p not in before and p != dev]
    if not new:
        log.error("new partition on %s did not appear", dev)
        return ""
    part = new[-1]
    for _ in range(20):  # wait for udev to create the device node
        if os.path.exists(part):
            break
        time.sleep(0.5)
    else:
        devnum = read_file(f"/sys/class/block/{os.path.basename(part)}/dev").strip()
        if devnum:
            major, minor = (int(x) for x in devnum.split(":"))
            os.mknod(part, 0o600 | stat.S_IFBLK, os.makedev(major, minor))
    target = usable_device(part)
    res = run(["mkfs.vfat", "-F", "32", "-n", DATA_LABEL, target], timeout=600)
    if target != part:
        run(["losetup", "-d", target])
    if res.returncode != 0:
        log.error("mkfs.vfat failed on %s: %s", part, res.stderr.strip())
        return ""
    log.info("created data partition %s on boot disk", part)
    return part


def setup_storage():
    boot_disk, medium_dev = find_boot_disk()
    info = StorageInfo(root=RAM_FALLBACK, boot_disk=boot_disk)

    if _is_mounted_at(MOUNT_POINT) and _writable(MOUNT_POINT):
        info.root, info.persistent = MOUNT_POINT, True
        info.device = _findmnt_source(MOUNT_POINT)
        return info

    # 1. Labelled data partition, boot disk first
    devices = _labelled_devices()
    devices.sort(key=lambda d: 0 if boot_disk and parent_disk(d) == boot_disk else 1)
    for dev in devices:
        if _mount(dev, MOUNT_POINT) and _writable(MOUNT_POINT):
            info.root, info.device, info.persistent = MOUNT_POINT, dev, True
            info.note = "data partition"
            return info

    # 2. Writable boot medium
    if medium_dev and _fstype(medium_dev) in ("vfat", "exfat", "ext4", "ext3", "ext2", "ntfs", "ntfs3"):
        run(["mount", "-o", "remount,rw", LIVE_MEDIUM])
        if _writable(LIVE_MEDIUM):
            info.root, info.device, info.persistent = LIVE_MEDIUM, medium_dev, True
            info.note = "boot medium"
            return info

    # 3. Create a partition after the ISO image
    if boot_disk:
        part = create_data_partition(boot_disk)
        if part and _mount(part, MOUNT_POINT) and _writable(MOUNT_POINT):
            info.root, info.device, info.persistent = MOUNT_POINT, part, True
            info.note = "data partition (created automatically)"
            return info

    # 4. RAM
    os.makedirs(RAM_FALLBACK, exist_ok=True)
    info.note = "RAM only - logs are lost on reboot and unexpected reboots cannot be detected"
    log.error("no persistent storage found; %s", info.note)
    return info
