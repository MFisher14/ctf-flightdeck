#!/bin/bash
# ctf-runtime-entry SECONDS RUNNER [ARGS...]      (B-242; installed in every ctf-runtime-* image)
#
# tools/sandbox.py runtime_run starts it as the container's command. Nothing is mounted from the host:
#   stdin   an uncompressed tar holding artifact.bin and the folder dep/ (dep/NNN.bin), built by
#           runtime_run from bytes its caller holds. The member names are fixed by runtime_run and
#           never come from a delivered file; only those two paths are unpacked.
#   stdout  what the runner prints (its one trace line), cut at 8 MiB
#   stderr  the runner's diagnostics, cut at 256 KiB
# The runner is stopped after SECONDS (TERM, then KILL two seconds later); the exit status is the
# runner's, or 124 when the time limit stopped it, as timeout(1) gives it.
set -euo pipefail
work="${CTF_RUNTIME_WORK:-/work}"
out_max=$((8 * 1024 * 1024))
err_max=$((256 * 1024))
if [ "$#" -lt 2 ]; then
  echo "usage: ctf-runtime-entry SECONDS RUNNER [ARGS...]" >&2
  exit 2
fi
seconds="$1"
shift
case "$seconds" in
  '' | *[!0-9.]*)
    echo "ctf-runtime-entry: SECONDS must be a number, got '$seconds'" >&2
    exit 2
    ;;
esac
cd "$work"
tar -xf - --no-same-owner --no-same-permissions artifact.bin dep
timeout -k 2 "$seconds" "$@" </dev/null 2> >(head -c "$err_max" >&2) | head -c "$out_max"
