#!/bin/bash
# Runs inside the builder container. /src is the project checkout, /out receives the ISO.
set -euo pipefail

SRC=/src
WORK=/build/work
OUT=/out
VERSION="${PCCHECK_VERSION:-$(date -u +%Y.%m.%d)}"
MPRIME_URL="${MPRIME_URL:-https://download.mersenne.ca/gimps/v30/30.19/p95v3019b20.linux64.tar.gz}"
MPRIME_SHA256="${MPRIME_SHA256:-}"

log() { echo -e "\033[1;34m[build]\033[0m $*"; }

log "Preparing live-build tree (version ${VERSION})"
# Keep the package cache (named volume at /build/cache) but always start from a clean config.
if [ -d "${WORK}" ]; then
    (cd "${WORK}" && lb clean --purge >/dev/null 2>&1 || true)
    rm -rf "${WORK}"
fi
mkdir -p "${WORK}" /build/cache
rsync -a "${SRC}/live/" "${WORK}/"
ln -sfn /build/cache "${WORK}/cache"

# Test orchestrator
INC="${WORK}/config/includes.chroot"
mkdir -p "${INC}/opt/pccheck"
rsync -a --delete --exclude '__pycache__' "${SRC}/src/pccheck" "${INC}/opt/pccheck/"
cat > "${INC}/etc/pccheck-release" <<EOF
PCCHECK_VERSION=${VERSION}
PCCHECK_BUILD_EPOCH=$(date -u +%s)
PCCHECK_BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

# Prime95 (mprime) is freeware but not in Debian; fetch it at build time.
# The build continues without it if the download fails (the test falls back to stress-ng).
if [ "${MPRIME_URL}" != "none" ]; then
    log "Fetching mprime from ${MPRIME_URL}"
    mkdir -p /build/cache/downloads
    TARBALL="/build/cache/downloads/$(basename "${MPRIME_URL}")"
    if [ -s "${TARBALL}" ] || curl -fL --retry 3 -o "${TARBALL}.part" "${MPRIME_URL}"; then
        [ -s "${TARBALL}" ] || mv "${TARBALL}.part" "${TARBALL}"
        if [ -n "${MPRIME_SHA256}" ]; then
            echo "${MPRIME_SHA256}  ${TARBALL}" | sha256sum -c -
        fi
        mkdir -p "${INC}/opt/mprime"
        tar -xzf "${TARBALL}" -C "${INC}/opt/mprime"
        chmod 0755 "${INC}/opt/mprime/mprime"
    else
        log "WARNING: mprime download failed; image will not include Prime95"
    fi
fi

cd "${WORK}"
log "lb config"
lb config
log "lb build (this takes a while)"
lb build 2>&1 | tee /build/lb-build.log

ISO=$(ls -1 "${WORK}"/*.iso 2>/dev/null | head -n1 || true)
if [ -z "${ISO}" ]; then
    echo "Build failed: no ISO produced. See lb-build.log" >&2
    cp /build/lb-build.log "${OUT}/lb-build.log" || true
    exit 1
fi

NAME="pccheck-${VERSION}-amd64.iso"
mkdir -p "${OUT}"
cp "${ISO}" "${OUT}/${NAME}"
cp /build/lb-build.log "${OUT}/lb-build.log"
(cd "${OUT}" && sha256sum "${NAME}" > "${NAME}.sha256")
log "Done: out/${NAME} ($(du -h "${OUT}/${NAME}" | cut -f1))"
