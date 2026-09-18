#!/usr/bin/env bash
# Build the PC-Check bootable ISO using Docker.
#
#   ./build.sh                 build out/pccheck-<date>-amd64.iso
#   ./build.sh --no-mprime     build without downloading Prime95
#   ./build.sh --no-ycruncher  build without y-cruncher (scheduled test becomes INCOMPLETE)
#   ./build.sh --clean-cache   drop the apt package cache volume first
#
# Environment overrides: PCCHECK_VERSION, MPRIME_URL, MPRIME_SHA256, YCRUNCHER_URL, YCRUNCHER_SHA256
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

IMAGE=pccheck-builder
CACHE_VOLUME=pccheck-build-cache
MPRIME_URL="${MPRIME_URL:-}"
YCRUNCHER_URL="${YCRUNCHER_URL:-}"

for arg in "$@"; do
    case "$arg" in
        --no-mprime) MPRIME_URL=none ;;
        --no-ycruncher) YCRUNCHER_URL=none ;;
        --clean-cache) docker volume rm -f "${CACHE_VOLUME}" >/dev/null ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

# Docker Desktop credential helpers are often broken under WSL; public images need no auth.
if [ -z "${DOCKER_CONFIG:-}" ] && grep -q '"credsStore"' "${HOME}/.docker/config.json" 2>/dev/null; then
    DOCKER_CONFIG="$(mktemp -d)"
    export DOCKER_CONFIG
    echo '{}' > "${DOCKER_CONFIG}/config.json"
    trap 'rm -rf "${DOCKER_CONFIG}"' EXIT
fi

echo "==> Running unit tests"
python3 -m unittest discover -s tests -t . -q

echo "==> Building builder image"
docker build -t "${IMAGE}" docker/

mkdir -p out
echo "==> Building live ISO"
docker run --rm --privileged \
    -v "$PWD":/src:ro \
    -v "$PWD/out":/out \
    -v "${CACHE_VOLUME}":/build/cache \
    -e PCCHECK_VERSION="${PCCHECK_VERSION:-}" \
    ${MPRIME_URL:+-e MPRIME_URL="${MPRIME_URL}"} \
    -e MPRIME_SHA256="${MPRIME_SHA256:-}" \
    -e YCRUNCHER_URL="${YCRUNCHER_URL}" \
    -e YCRUNCHER_SHA256="${YCRUNCHER_SHA256:-}" \
    "${IMAGE}" bash /src/docker/build-in-container.sh

echo "==> ISO images in ./out:"
ls -lh out/*.iso
