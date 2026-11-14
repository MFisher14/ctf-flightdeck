#!/usr/bin/env python3
"""Offline shellcode-plan template; this file deliberately has no transport code."""
from pathlib import Path
import sys


REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
from pwn_shellcode import ShellcodeError, build_shellcode  # noqa: E402


def main() -> int:
    # Paste the `allowed` list from pwn_seccomp.py here.  When execve is absent and ORW is
    # complete, the builder labels and emits ORW automatically.
    allowed = ["openat", "read", "write"]
    try:
        result = build_shellcode("execve", "amd64", avoid={0x00, 0x0A},
                                 allowed_syscalls=allowed, path="/flag")
    except ShellcodeError as exc:
        print(f"shellcode_payload: {exc}", file=sys.stderr)
        return 2
    print(result.raw.hex())
    print(result.pwntools, end="")
    # Feed result.raw to the existing scope-locked exploit client only after human review.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
