#!/usr/bin/env bash
# Boot a PC-Check ISO in QEMU (inside Docker) for a smoke test.
#
#   tools/qemu-test.sh out/pccheck-*.iso                  # GRUB boot, UEFI (default entry)
#   tools/qemu-test.sh out/pccheck-*.iso --bios           # GRUB boot, legacy BIOS
#   tools/qemu-test.sh out/pccheck-*.iso --direct "pccheck.hours=0.1"
#                                                         # kernel boot with extra cmdline options
# Options: --keep (reuse the USB image from the previous run, e.g. to test resume after a reset)
#          Simulate a power loss: docker kill pccheck-vm ; screenshot of tty1: tools/qemu-screenshot.sh
#          --timeout SECONDS (default 1800), --allow-reboot (let the guest reboot itself,
#          needed to test pccheck.reboot_cycles; otherwise a guest reboot ends the VM)
#
# The ISO is copied into a larger "USB stick" image so the data partition can be created.
# Two blank test disks (NVMe + SATA) are attached. Serial console -> out/qemu/serial.log,
# web UI -> http://localhost:${WEB_PORT:-8089}/
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

ISO="${1:?usage: tools/qemu-test.sh <iso> [--bios] [--direct \"cmdline\"] [--keep] [--timeout s]}"; shift
MODE=uefi; EXTRA=""; KEEP=0; TIMEOUT=1800; ALLOW_REBOOT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --bios) MODE=bios; shift ;;
        --direct) MODE=direct; EXTRA="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --allow-reboot) ALLOW_REBOOT=1; shift ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

if [ -z "${DOCKER_CONFIG:-}" ] && grep -q '"credsStore"' "${HOME}/.docker/config.json" 2>/dev/null; then
    export DOCKER_CONFIG="$(mktemp -d)"; echo '{}' > "${DOCKER_CONFIG}/config.json"
fi

WORK=out/qemu
mkdir -p "$WORK"
chmod 0777 "$WORK" 2>/dev/null || true
ISO_ABS="$(readlink -f "$ISO")"

docker build -q -t pccheck-qemu - >/dev/null <<'EOF'
FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils ovmf xorriso socat python3 mtools \
    && rm -rf /var/lib/apt/lists/*
EOF

docker rm -f pccheck-vm >/dev/null 2>&1 || true
docker run --rm -i --name pccheck-vm --device /dev/kvm -p "${WEB_PORT:-8089}":8080 \
    -v "$ISO_ABS":/iso/image.iso:ro -v "$PWD/$WORK":/work \
    -e MODE="$MODE" -e EXTRA="$EXTRA" -e KEEP="$KEEP" -e TIMEOUT="$TIMEOUT" -e ALLOW_REBOOT="$ALLOW_REBOOT" \
    pccheck-qemu bash -s <<'EOS'
set -euo pipefail
cd /work
if [ "$KEEP" != 1 ] || [ ! -f usb.img ]; then
    rm -f usb.img nvme.img sata.img serial.log
    cp /iso/image.iso usb.img
    truncate -s 4G usb.img
    truncate -s 2G nvme.img
    truncate -s 1G sata.img
fi
BOOT=()
case "$MODE" in
    uefi)
        cp -n /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd 2>/dev/null || true
        BOOT=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
              -drive if=pflash,format=raw,file=vars.fd) ;;
    bios) ;;
    direct)
        rm -rf boot && mkdir boot
        xorriso -osirrox on -indev /iso/image.iso -extract /live boot/live >/dev/null 2>&1
        KERNEL=$(ls boot/live/vmlinuz-* | head -n1); INITRD=$(ls boot/live/initrd.img-* | head -n1)
        APPEND="boot=live components hostname=pccheck live-config.noautologin loglevel=3 panic=10 \
nmi_watchdog=1 softlockup_panic=1 hardlockup_panic=1 printk.devkmsg=on console=tty0 console=ttyS0,115200n8 $EXTRA"
        BOOT=(-kernel "$KERNEL" -initrd "$INITRD" -append "$APPEND") ;;
esac
USB_BOOTINDEX=",bootindex=0"           # boot the stick first; -kernel already owns index 0
[ "$MODE" = direct ] && USB_BOOTINDEX=""
REBOOT_OPTS="-no-reboot -action panic=exit-failure"
[ "$ALLOW_REBOOT" = 1 ] && REBOOT_OPTS=""
echo "booting ($MODE), serial log: out/qemu/serial.log, timeout ${TIMEOUT}s"
timeout "$TIMEOUT" qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 4096 -machine q35 \
    "${BOOT[@]}" \
    -drive if=none,id=usbstick,format=raw,file=usb.img -device qemu-xhci -device usb-storage,drive=usbstick$USB_BOOTINDEX \
    -drive if=none,id=nvme0,format=raw,file=nvme.img -device nvme,drive=nvme0,serial=PCCHECKNVME01 \
    -drive if=none,id=sata0,format=raw,file=sata.img -device ahci,id=ahci -device ide-hd,drive=sata0,bus=ahci.0,serial=PCCHECKSATA01 \
    -device i6300esb -nic user,model=e1000e,hostfwd=tcp::8080-:80 \
    -display none -serial file:serial.log -monitor unix:/work/monitor.sock,server,nowait $REBOOT_OPTS \
    || echo "qemu exited with $?"
EOS
