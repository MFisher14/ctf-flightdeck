#!/usr/bin/env bash
# Makes the pack ready on this machine: a Python environment of its own (.venv) with its pinned
# libraries. `flightdeck pack install` runs this. Safe to run again.
#
# It installs Python packages from PyPI into the pack's own folder and nothing else. The native
# tools some engines call (ghidra, jadx, tshark, exiftool, binwalk and others: see Brewfile and
# docs/CAPABILITIES.md) are yours to install; an engine whose tool is missing is skipped and named.
# With lanes in Docker the engines run in the pack's image instead (`flightdeck pack image`).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v uv >/dev/null 2>&1; then
  echo "setup: uv is not on PATH; install it from https://docs.astral.sh/uv/ and run this again" >&2
  exit 1
fi
uv venv --quiet --allow-existing -p 3.12 .venv
# both files: requirements.txt is what the pack asks for, requirements.lock.txt every version its suite ran on
uv pip install --quiet -p .venv/bin/python -r requirements.lock.txt -r requirements.txt --override maint/overrides.txt
.venv/bin/python -c "import ctf; print('setup: the pack environment is ready:', __import__('sys').version.split()[0])"
