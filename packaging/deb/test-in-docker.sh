#!/bin/sh
# Install the .deb in a clean debian:12 container and run flightdeck from it.
#
#   packaging/deb/test-in-docker.sh DEB VERSION
#
# The container has no Python of its own, no flightdeck config and no Docker. What must hold:
#   - apt installs the package and its dependencies;
#   - there is still no python3 on PATH, so the Python that runs is the package's;
#   - flightdeck, ctfdeck and ctf-flightdeck each print their name and VERSION;
#   - `flightdeck doctor` runs every check and exits 1 with exactly two failures, the config
#     (there is none) and Docker (there is none), and says its Python is 3.12. Status 1 is
#     what doctor owes a machine that is not set up: 0 here would mean doctor missed that,
#     and any other status, or a traceback, that it broke.
set -eu

fail() { echo "test-in-docker: $*" >&2; exit 1; }

[ $# -eq 2 ] || fail "usage: test-in-docker.sh DEB VERSION"
[ -f "$1" ] || fail "no package at $1"
command -v docker >/dev/null || fail "docker is not on PATH"
deb_dir=$(cd "$(dirname "$1")" && pwd)

docker run --rm -v "$deb_dir:/debs:ro" -e DEB="$(basename "$1")" -e VERSION="$2" debian:12 sh -euc '
  fail() { echo "test-in-docker: $*" >&2; exit 1; }
  ! command -v python3 >/dev/null || fail "this image has a python3 already, so it cannot show the package brings its own"
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "/debs/$DEB" >/dev/null
  ! command -v python3 >/dev/null || fail "installing the package put a python3 on PATH"

  for name in flightdeck ctfdeck ctf-flightdeck; do
    said=$("$name" --version)
    echo "$name --version: $said"
    [ "$said" = "$name $VERSION" ] || fail "$name --version said \"$said\", not \"$name $VERSION\""
  done

  status=0
  flightdeck doctor > /tmp/doctor.txt 2>&1 || status=$?
  cat /tmp/doctor.txt
  echo "flightdeck doctor: exit $status"
  [ "$status" -eq 1 ] || fail "doctor exited $status on a machine with no config and no Docker, not 1"
  ! grep -q Traceback /tmp/doctor.txt || fail "doctor printed a traceback"
  grep -q "^ok   python: Python 3\.12\.[0-9]*, flightdeck $VERSION\$" /tmp/doctor.txt || fail "doctor did not say Python 3.12 and flightdeck $VERSION"
  failures=$(grep "^FAIL " /tmp/doctor.txt | sed "s/^FAIL \([a-z ]*\):.*/\1/" | sort | tr "\n" ",")
  [ "$failures" = "config,docker," ] || fail "doctor failed \"$failures\", not the config and docker alone"
  echo "ok: the package installs, runs on its own Python, and doctor names the two things a new machine lacks"
'
