#!/usr/bin/env bash
# Save a PNG screenshot of the running PC-Check VM console (started by tools/qemu-test.sh).
#   tools/qemu-screenshot.sh [out/qemu/screen.png]
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
OUT="${1:-out/qemu/screen.png}"
docker exec pccheck-vm bash -c '
echo "screendump /work/screen.ppm" | socat - UNIX-CONNECT:/work/monitor.sock >/dev/null
sleep 1
python3 - <<PY
import struct, zlib
data = open("/work/screen.ppm", "rb").read()
# Parse the PPM header token by token: pixel data may start with whitespace bytes,
# so the offset has to be tracked exactly instead of using split().
pos, tokens = 0, []
while len(tokens) < 4:
    while pos < len(data) and data[pos:pos + 1].isspace():
        pos += 1
    if data[pos:pos + 1] == b"#":
        while data[pos:pos + 1] not in (b"\n", b""):
            pos += 1
        continue
    start = pos
    while pos < len(data) and not data[pos:pos + 1].isspace():
        pos += 1
    tokens.append(data[start:pos])
pos += 1  # exactly one whitespace byte separates the header from the data
w, h = int(tokens[1]), int(tokens[2])
pixels = data[pos:pos + w * h * 3]
raw = b"".join(b"\x00" + pixels[y * w * 3:(y + 1) * w * 3] for y in range(h))
def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b"")
open("/work/screen.png", "wb").write(png)
PY'
cp out/qemu/screen.png "$OUT" 2>/dev/null || true
echo "$OUT"
