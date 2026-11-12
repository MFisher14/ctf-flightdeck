#!/bin/sh
# Build the .deb in a throwaway debian:12 container (build-deb.sh says what is in it).
#
#   packaging/deb/build-in-docker.sh WHEEL OUT_DIR
#
# Needs docker and uv here. The locked dependencies come from this checkout's uv.lock
# (`uv export`, with hashes); the container gets the same uv version as this machine, from
# astral.sh, and the standalone Python from uv's downloads. The .deb is for the architecture
# docker runs here.
set -eu

fail() { echo "build-in-docker: $*" >&2; exit 1; }

[ $# -eq 2 ] || fail "usage: build-in-docker.sh WHEEL OUT_DIR"
[ -f "$1" ] || fail "no wheel at $1"
command -v docker >/dev/null || fail "docker is not on PATH"
command -v uv >/dev/null || fail "uv is not on PATH"
repo=$(cd "$(dirname "$0")/../.." && pwd)
wheel_dir=$(cd "$(dirname "$1")" && pwd)
wheel=$(basename "$1")
mkdir -p "$2"
out=$(cd "$2" && pwd)
uv_version=$(uv --version | awk '{ print $2 }')
[ -n "$uv_version" ] || fail "cannot read uv's version"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$repo" && uv export --locked --no-dev --no-emit-project --format requirements-txt --output-file "$work/requirements.txt" >/dev/null)

docker run --rm \
  -v "$repo:/src:ro" -v "$wheel_dir:/wheel:ro" -v "$work:/locked:ro" -v "$out:/out" \
  -e UV_VERSION="$uv_version" -e WHEEL="$wheel" \
  debian:12 sh -euc '
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends ca-certificates curl >/dev/null
    curl -LsSf "https://astral.sh/uv/$UV_VERSION/install.sh" | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
    sh /src/packaging/deb/build-deb.sh "/wheel/$WHEEL" /locked/requirements.txt /out
  '
