#!/usr/bin/env bash
# Write the PC-Check ISO to a USB stick and add a FAT32 "PCCHECKDATA" partition
# for logs, reports and the optional pccheck.conf.
#
#   sudo ./write-usb.sh out/pccheck-<version>-amd64.iso /dev/sdX [--conf my-pccheck.conf]
#
# ALL DATA ON THE TARGET DEVICE IS DESTROYED.
set -euo pipefail

usage() { sed -n '2,8p' "$0"; exit 2; }
[ $# -ge 2 ] || usage
ISO="$1"; DEV="$2"; shift 2
CONF=""
while [ $# -gt 0 ]; do
    case "$1" in
        --conf) CONF="$2"; shift 2 ;;
        *) usage ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (sudo)" >&2; exit 1; }
[ -f "$ISO" ] || { echo "ISO not found: $ISO" >&2; exit 1; }
[ -b "$DEV" ] || { echo "not a block device: $DEV" >&2; exit 1; }
case "$(lsblk -dno TYPE "$DEV")" in
    disk|loop) ;;   # loop allows preparing an image file for testing
    *) echo "$DEV is not a whole disk (use /dev/sdX, not a partition)" >&2; exit 1 ;;
esac
for tool in sfdisk mkfs.vfat partprobe wipefs; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool (install fdisk, dosfstools, parted, util-linux)" >&2; exit 1; }
done

# Refuse the disk that holds the running system.
ROOT_DISK="$(lsblk -no PKNAME "$(findmnt -no SOURCE /)" 2>/dev/null | head -n1 || true)"
if [ -n "$ROOT_DISK" ] && [ "/dev/$ROOT_DISK" = "$DEV" ]; then
    echo "$DEV holds the running system; refusing." >&2; exit 1
fi
if lsblk -no MOUNTPOINT "$DEV" | grep -q .; then
    echo "$DEV has mounted partitions; unmount them first:" >&2
    lsblk -o NAME,SIZE,MOUNTPOINT "$DEV" >&2
    exit 1
fi

SIZE=$(lsblk -dnbo SIZE "$DEV")
ISO_SIZE=$(stat -c %s "$ISO")
if [ "$SIZE" -lt $((ISO_SIZE + 512 * 1024 * 1024)) ]; then
    echo "device too small: need at least ISO size + 512 MiB" >&2; exit 1
fi

echo "Target: $DEV  $(lsblk -dno MODEL,SIZE,TRAN "$DEV")"
lsblk -o NAME,SIZE,FSTYPE,LABEL "$DEV"
read -r -p "ALL DATA ON $DEV WILL BE DESTROYED. Type YES to continue: " answer
[ "$answer" = "YES" ] || { echo "aborted"; exit 1; }

echo "==> Wiping signatures"
wipefs -a "$DEV" >/dev/null

echo "==> Writing ISO ($((ISO_SIZE / 1024 / 1024)) MiB)"
dd if="$ISO" of="$DEV" bs=4M conv=fsync oflag=direct status=progress
sync

echo "==> Adding PCCHECKDATA partition"
LABEL_TYPE=$(sfdisk --dump "$DEV" 2>/dev/null | awk -F': ' '/^label:/{print $2}')
ISO_SECTORS=$(( (ISO_SIZE + 511) / 512 ))
LAST_END=$(sfdisk --dump "$DEV" | awk -F'[=,]' '/start=/{s=$2+0; z=$4+0; if (s+z>m) m=s+z} END{print m+0}')
START=$(( ISO_SECTORS > LAST_END ? ISO_SECTORS : LAST_END ))
START=$(( (START + 2047) / 2048 * 2048 ))
if [ "$LABEL_TYPE" = "gpt" ]; then
    sfdisk --force --relocate gpt-bak-std "$DEV" >/dev/null 2>&1 || true
    PTYPE="EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
else
    PTYPE="c"
fi
echo "start=${START}, type=${PTYPE}" | sfdisk --force --append --no-reread "$DEV"
partprobe "$DEV" 2>/dev/null || blockdev --rereadpt "$DEV" 2>/dev/null || true
udevadm settle 2>/dev/null || sleep 3

PART=""
for _ in $(seq 1 20); do                      # wait for udev to create the device node
    PART=$(lsblk -lnpo NAME "$DEV" | tail -n1)
    [ "$PART" != "$DEV" ] && [ -b "$PART" ] && break
    sleep 0.5
done
if [ -z "$PART" ] || [ "$PART" = "$DEV" ] || [ ! -b "$PART" ]; then
    echo "the new partition did not appear; re-plug the stick and run:" >&2
    echo "    mkfs.vfat -F 32 -n PCCHECKDATA <last partition of $DEV>" >&2
    exit 1
fi
mkfs.vfat -F 32 -n PCCHECKDATA "$PART" >/dev/null

if [ -n "$CONF" ]; then
    MNT=$(mktemp -d)
    mount "$PART" "$MNT"
    cp "$CONF" "$MNT/pccheck.conf"
    umount "$MNT"
    rmdir "$MNT"
    echo "==> Installed $CONF as pccheck.conf"
fi
sync

echo
lsblk -o NAME,SIZE,FSTYPE,LABEL "$DEV"
echo
echo "Done. Boot the target machine from this stick (set it first in the boot order so the test"
echo "resumes after an unexpected reboot). Reports: PCCHECKDATA:/pccheck/sessions/"
