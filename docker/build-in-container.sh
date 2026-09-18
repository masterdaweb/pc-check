#!/bin/bash
# Runs inside the builder container. /src is the project checkout, /out receives the ISO.
set -euo pipefail

SRC=/src
WORK=/build/work
OUT=/out
VERSION="${PCCHECK_VERSION:-$(date -u +%Y.%m.%d)}"
MPRIME_DEFAULT_URL=https://download.mersenne.ca/gimps/v30/30.19/p95v3019b20.linux64.tar.gz
MPRIME_DEFAULT_SHA256=4ce2377e03deb4cf189523136e26401ba08f67857a128e420dd030d00cdca601
MPRIME_URL="${MPRIME_URL:-${MPRIME_DEFAULT_URL}}"
MPRIME_SHA256="${MPRIME_SHA256:-}"
# The default download is pinned; a custom MPRIME_URL is checked only if MPRIME_SHA256 is given.
if [ -z "${MPRIME_SHA256}" ] && [ "${MPRIME_URL}" = "${MPRIME_DEFAULT_URL}" ]; then
    MPRIME_SHA256="${MPRIME_DEFAULT_SHA256}"
fi

# y-cruncher: retain the entire upstream distribution, including license and library notices.
# Free redistribution is allowed; commercial use requires contacting its author.
# A failed download/checksum is a build error, never an implicitly reduced test suite.
YCRUNCHER_DEFAULT_URL=https://github.com/Mysticial/y-cruncher/releases/download/v0.8.7.9547/y-cruncher.v0.8.7.9547-dynamic.tar.xz
YCRUNCHER_DEFAULT_SHA256=bee23ee59464d71635a054bb4f6f09c06b8ef0bdc441fb70d4cd81a9bd42a7a7
YCRUNCHER_URL="${YCRUNCHER_URL:-${YCRUNCHER_DEFAULT_URL}}"
YCRUNCHER_SHA256="${YCRUNCHER_SHA256:-}"
if [ -z "${YCRUNCHER_SHA256}" ] && [ "${YCRUNCHER_URL}" = "${YCRUNCHER_DEFAULT_URL}" ]; then
    YCRUNCHER_SHA256="${YCRUNCHER_DEFAULT_SHA256}"
fi
if [ "${YCRUNCHER_URL}" != "none" ] && ! [[ "${YCRUNCHER_SHA256}" =~ ^[a-fA-F0-9]{64}$ ]]; then
    echo "YCRUNCHER_SHA256 is required for a custom y-cruncher download" >&2
    exit 1
fi

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

if [ "${YCRUNCHER_URL}" != "none" ]; then
    log "Fetching y-cruncher from ${YCRUNCHER_URL}"
    mkdir -p /build/cache/downloads
    YC_ARCHIVE="/build/cache/downloads/ycruncher-${YCRUNCHER_SHA256}.tar.xz"
    if [ ! -s "${YC_ARCHIVE}" ]; then
        curl -fL --retry 3 -o "${YC_ARCHIVE}.part" "${YCRUNCHER_URL}"
        mv "${YC_ARCHIVE}.part" "${YC_ARCHIVE}"
    fi
    echo "${YCRUNCHER_SHA256}  ${YC_ARCHIVE}" | sha256sum -c -
    mkdir -p "${INC}/opt/y-cruncher"
    tar -xJf "${YC_ARCHIVE}" --strip-components=1 --no-same-owner -C "${INC}/opt/y-cruncher"
    test -x "${INC}/opt/y-cruncher/y-cruncher"
    test -f "${INC}/opt/y-cruncher/Read Me.txt"
    printf 'URL=%s\nSHA256=%s\n' "${YCRUNCHER_URL}" "${YCRUNCHER_SHA256}" \
        > "${INC}/opt/y-cruncher/pccheck-source.txt"
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
# Package manifest: which Debian packages (and versions) the image contains, for source lookup.
PKGS=$(ls -1 "${WORK}"/*.packages "${WORK}"/chroot.packages.live 2>/dev/null | head -n1 || true)
[ -n "${PKGS}" ] && cp "${PKGS}" "${OUT}/pccheck-${VERSION}-amd64.packages"
(cd "${OUT}" && sha256sum "${NAME}" > "${NAME}.sha256")
log "Done: out/${NAME} ($(du -h "${OUT}/${NAME}" | cut -f1))"
