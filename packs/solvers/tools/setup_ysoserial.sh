#!/bin/bash
# Set up Java deserialization payload generation for solvers/toolkits/java_deser.py, once per Mac.
#
#   tools/setup_ysoserial.sh            fetch and check the jar, pull the JRE image, compile the two helpers
#   tools/setup_ysoserial.sh --check    change nothing; say what is there (exit 0 when every route is ready)
#
# What it puts where (all outside git; $CTF_TOOLS_DIR, default ~/.csctf-tools):
#   ysoserial/ysoserial-all.jar   ysoserial v0.0.6 from its official GitHub release, kept only when its SHA-256 is
#                                 the one pinned in java_deser.py (YSOSERIAL_SHA256); read-only (0444)
#   ysoserial/classes/            CsctfSleep.class and CsctfDeserCheck.class, compiled from tools/ysoserial/
#                                 with javac --release 8 (only when a javac is on PATH; the payload routes do not
#                                 need them: they serve `java_deser.py regen` and the deserialization test)
#   docker image JRE_IMAGE        eclipse-temurin:8-jre pinned by digest (java_deser.JRE_IMAGE)
#
# The fetch, by hand, is:
#   curl -fL -o ~/.csctf-tools/ysoserial/ysoserial-all.jar \
#        https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar
#   shasum -a 256 ~/.csctf-tools/ysoserial/ysoserial-all.jar   # must print YSOSERIAL_SHA256
#   docker pull eclipse-temurin@sha256:<JRE_IMAGE's digest>
#
# Needs the network (GitHub, Docker Hub) for the fetch and the pull; nothing it installs ever touches the
# network again: every payload is built with --network none. No token is read.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/.venv/bin/python"
[ -x "$PY" ] || PY=python3
pin() { "$PY" -I -c "import sys; sys.path.insert(0, '$REPO/solvers/toolkits'); import java_deser as J; print(J.$1)"; }
URL="$(pin YSOSERIAL_URL)"
SHA="$(pin YSOSERIAL_SHA256)"
IMAGE="$(pin JRE_IMAGE)"
DIR="${CTF_TOOLS_DIR:-$HOME/.csctf-tools}/ysoserial"
JAR="$DIR/ysoserial-all.jar"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

sha_of() { shasum -a 256 "$1" | awk '{print $1}'; }

if [ "$CHECK" = 1 ]; then
  "$PY" -I "$REPO/solvers/toolkits/java_deser.py" status
  "$PY" -I -c "import sys; sys.path.insert(0, '$REPO/solvers/toolkits'); import java_deser as J; s = J.java_status(); sys.exit(0 if s['jar'] and s['docker'] else 1)"
  exit $?
fi

mkdir -p "$DIR"
if [ -f "$JAR" ] && [ "$(sha_of "$JAR")" = "$SHA" ]; then
  echo "jar: $JAR already there, SHA-256 matches"
else
  echo "jar: fetching $URL"
  curl -fL --retry 2 -o "$JAR.part" "$URL"
  GOT="$(sha_of "$JAR.part")"
  if [ "$GOT" != "$SHA" ]; then
    rm -f "$JAR.part"
    echo "jar: SHA-256 $GOT is not the pinned $SHA: NOT installed" >&2
    exit 1
  fi
  rm -f "$JAR"
  mv "$JAR.part" "$JAR"
  chmod 444 "$JAR"
  echo "jar: installed, SHA-256 $SHA"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "image: $IMAGE already there"
  else
    echo "image: pulling $IMAGE"
    docker pull -q "$IMAGE"
  fi
else
  echo "image: docker is not running; the docker route stays off (the local java and the templates still work)" >&2
fi

if command -v javac >/dev/null 2>&1; then
  mkdir -p "$DIR/classes"
  javac --release 8 -nowarn -Xlint:-options -cp "$JAR" -d "$DIR/classes" \
    "$REPO/tools/ysoserial/CsctfSleep.java" "$REPO/tools/ysoserial/CsctfDeserCheck.java"
  echo "classes: compiled into $DIR/classes"
else
  echo "classes: no javac on PATH; regen and the deserialization test are skipped (payloads unaffected)" >&2
fi

"$PY" -I "$REPO/solvers/toolkits/java_deser.py" status
