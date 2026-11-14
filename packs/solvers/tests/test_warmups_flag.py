#!/usr/bin/env python3
"""CSCTF warmups: the auto-decoder must surface a flag hidden under encoding layers.

Standalone: `.venv/bin/python tests/test_warmups_flag.py` -> prints ok / exits 0, or prints the
failure and exits 1. Replaces the Huntress "slug sentence" warmups tests (which were day-specific).
"""
import base64
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import paths

REPO = Path(__file__).resolve().parent.parent
CRIB = REPO / "solvers" / "warmups" / "crib_decode.py"
PY = REPO / ".venv" / "bin" / "python"
if not PY.exists():
    PY = Path(sys.executable)


def _run(data: bytes) -> str:
    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as fh:
        fh.write(data)
        path = fh.name
    env = dict(os.environ, CTF_WORKDIR=str(paths.ensure_workdir()))
    try:
        out = subprocess.run([str(PY), str(CRIB), path], capture_output=True, text=True,
                             timeout=120, env=env)
        return out.stdout + out.stderr
    finally:
        os.unlink(path)


def check() -> None:
    # 1) base64 of a message containing a flag -> the flag must appear in the decode output.
    out = _run(base64.b64encode(b"Hello flag{test}"))
    assert "flag{test}" in out, f"base64 layer: flag not surfaced:\n{out}"

    # 2) double layer (base64 of hex of a flag) -> still found.
    inner = b"csctf{layered_ok}".hex().encode()
    out = _run(base64.b64encode(inner))
    assert "csctf{layered_ok}" in out, f"b64+hex layer: flag not surfaced:\n{out}"

    # 3) a plain, unencoded flag in the open is surfaced too.
    out = _run(b"the answer is chronos{in_the_open}\n")
    assert "chronos{in_the_open}" in out, f"plaintext: flag not surfaced:\n{out}"

    print("ok")


if __name__ == "__main__":
    try:
        check()
    except AssertionError as e:
        print("FAIL:", e)
        sys.exit(1)
