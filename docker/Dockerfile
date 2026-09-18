# Build environment for the PC-Check live image.
# The image itself is built with Debian live-build inside this container
# (requires --privileged because live-build mounts /proc, /sys, etc. in a chroot).
FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's/Components: main/Components: main contrib non-free non-free-firmware/' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      live-build debootstrap xorriso squashfs-tools mtools dosfstools \
      grub-pc-bin grub-efi-amd64-bin grub-efi-amd64-signed shim-signed \
      memtest86+ cpio zstd xz-utils curl ca-certificates python3 rsync fdisk \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
