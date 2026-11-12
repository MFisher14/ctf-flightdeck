#!/bin/sh
# Build the .deb of a release: flightdeck with a Python of its own.
#
#   build-deb.sh WHEEL REQUIREMENTS OUT_DIR
#
# Debian 12 has Python 3.11 and flightdeck needs 3.12, so the package brings one: uv's
# standalone Python under /opt/ctf-flightdeck/python, a venv under /opt/ctf-flightdeck/venv
# with the wheel and its locked dependencies (REQUIREMENTS: `uv export` with hashes, each
# checked), and flightdeck, ctfdeck and ctf-flightdeck in /usr/bin as links into the venv.
#
# A venv holds absolute paths, so it is built where it will live: this script writes
# /opt/ctf-flightdeck on the machine it runs on, refuses to start when that exists, and
# removes it when it is done. Run it as root in a throwaway Debian container
# (build-in-docker.sh does), with uv and dpkg-deb on PATH. The package's architecture is
# this machine's.
set -eu

fail() { echo "build-deb: $*" >&2; exit 1; }

[ $# -eq 3 ] || fail "usage: build-deb.sh WHEEL REQUIREMENTS OUT_DIR"
wheel=$1 requirements=$2 out=$3
prefix=/opt/ctf-flightdeck
here=$(cd "$(dirname "$0")" && pwd)
license=$here/../../LICENSE

[ "$(id -u)" -eq 0 ] || fail "must run as root (it writes $prefix): use build-in-docker.sh"
command -v uv >/dev/null || fail "uv is not on PATH"
command -v dpkg-deb >/dev/null || fail "dpkg-deb is not on PATH: this needs a Debian system"
[ -f "$wheel" ] || fail "no wheel at $wheel"
[ -f "$requirements" ] || fail "no requirements file at $requirements"
[ -f "$license" ] || fail "no LICENSE at $license"
[ -d "$out" ] || fail "no output folder at $out"
[ ! -e "$prefix" ] || fail "$prefix exists already: this script builds there and will not overwrite it"

case $(basename "$wheel") in
  ctf_flightdeck-*-py3-none-any.whl) ;;
  *) fail "$(basename "$wheel") is not a ctf_flightdeck wheel" ;;
esac
version=$(basename "$wheel" | sed 's/^ctf_flightdeck-\(.*\)-py3-none-any\.whl$/\1/')
# Debian sorts 1.0~rc1 before 1.0, as PEP 440 sorts 1.0rc1; a final release is unchanged.
deb_version=$(printf '%s' "$version" | sed -E 's/\.?(a|b|rc|dev)([0-9]+)/~\1\2/g; s/\.post/+post/')
arch=$(dpkg --print-architecture)

stage=$(mktemp -d)
trap 'rm -rf "$prefix" "$stage"' EXIT

export UV_PYTHON_INSTALL_DIR=$prefix/python UV_PYTHON_PREFERENCE=only-managed UV_NO_CACHE=1 UV_LINK_MODE=copy
uv python install --no-bin 3.12  # no python3.12 link outside the prefix
python=$(uv python find 3.12)
case $python in
  "$prefix"/python/*) ;;
  *) fail "uv found Python at $python, not under $prefix/python" ;;
esac
uv venv --python "$python" "$prefix/venv"
uv pip install --python "$prefix/venv/bin/python" --require-hashes --no-deps --compile-bytecode -r "$requirements"
uv pip install --python "$prefix/venv/bin/python" --no-deps --compile-bytecode "$wheel"

said=$("$prefix/venv/bin/flightdeck" --version)
[ "$said" = "flightdeck $version" ] || fail "the venv's flightdeck says '$said', not 'flightdeck $version'"

mkdir -p "$stage/opt" "$stage/usr/bin" "$stage/usr/share/doc/ctf-flightdeck" "$stage/DEBIAN"
cp -a "$prefix" "$stage/opt/"
for name in flightdeck ctfdeck ctf-flightdeck; do
  [ -x "$prefix/venv/bin/$name" ] || fail "the venv has no $name command"
  ln -s "$prefix/venv/bin/$name" "$stage/usr/bin/$name"
done
cp "$license" "$stage/usr/share/doc/ctf-flightdeck/copyright"

cat > "$stage/DEBIAN/control" <<EOF
Package: ctf-flightdeck
Version: $deb_version
Architecture: $arch
Maintainer: Maximus Fisher <MFisher14@users.noreply.github.com>
Installed-Size: $(du -sk "$stage/opt" "$stage/usr" | awk '{ total += $1 } END { print total }')
Depends: libc6, ca-certificates
Suggests: docker.io | docker-ce
Section: utils
Priority: optional
Homepage: https://github.com/MFisher14/ctf-flightdeck
Description: terminal harness for playing CTFs with AI agents
 The player runs the loop: flightdeck pulls and triages challenges, runs
 no-model solvers, starts agent lanes and submits, and the player watches every
 lane and steps in. This package brings its own Python 3.12 under
 /opt/ctf-flightdeck. Docker lanes need Docker, which it does not install.
EOF

deb=$out/ctf-flightdeck_${deb_version}_${arch}.deb
dpkg-deb --root-owner-group --build "$stage" "$deb"
echo "built $deb"
