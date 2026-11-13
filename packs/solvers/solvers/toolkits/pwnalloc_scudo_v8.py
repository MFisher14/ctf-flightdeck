#!/usr/bin/env python3
"""Offline, fact-driven analysis for current Scudo and V8 sandbox metadata.

The module deliberately supports two source-pinned structural profiles instead of trying to
guess allocator or V8 versions from bytes:

* LLVM Scudo standalone's 64-bit little-endian compact chunk header at ``fae51e8f227c``;
* V8's sandbox model at ``2e8a80edf4ac``.

It never reads another process, dereferences a supplied address, executes a target, or performs
network I/O.  Addresses, table words, object fields, and allocator configuration are facts from
the caller.  Results are arithmetic interpretations and reviewable plans only.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from functools import wraps
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence


MAX_JSON = 1 << 20
MAX_FIELDS = 256
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
SCUDO_MAX_ALIGNMENT = 1 << 24
SCUDO_MAX_ALLOWED_MALLOC_SIZE = 1 << 40

SCUDO_PROFILE = "llvm-fae51e8f227c-scudo-standalone-le64"
V8_PROFILE = "v8-2e8a80edf4ac"


class PwnAllocError(ValueError):
    """The supplied facts are malformed, inconsistent, or use an unknown profile."""


def _fail_closed(function):
    """Translate every ordinary malformed-input failure to the public error contract."""

    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except PwnAllocError:
            raise
        except Exception as exc:
            raise PwnAllocError(f"malformed {function.__name__} input: {exc}") from exc

    return guarded


def _uint(value: object, name: str, bits: int = 64) -> int:
    if isinstance(value, str):
        if len(value) > 80:
            raise PwnAllocError(f"{name} integer text is too long")
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise PwnAllocError(f"{name} is not an integer") from exc
    maximum = (1 << bits) - 1
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise PwnAllocError(f"{name} must be an unsigned {bits}-bit integer")
    return value


def _bounded_int(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PwnAllocError(f"{name} must be in {minimum}..{maximum}")
    return value


def _bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise PwnAllocError(f"{name} must be boolean")
    return value


def _checked_add(left: int, right: int, name: str) -> int:
    if right < 0 or left > UINT64_MAX - right:
        raise PwnAllocError(f"{name} crosses the 64-bit address space")
    return left + right


def _power_of_two(value: int, name: str) -> int:
    if value <= 0 or value & (value - 1):
        raise PwnAllocError(f"{name} must be a power of two")
    return value


def _require_profile(profile: object, supported: str, family: str) -> str:
    if not isinstance(profile, str) or profile != supported:
        raise PwnAllocError(f"unknown {family} profile; supported profile is {supported!r}")
    return profile


def _exact_bytes(value: object, length: int, name: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise PwnAllocError(f"{name} must be bytes-like")
    raw = bytes(value)
    if len(raw) != length:
        raise PwnAllocError(f"{name} must be exactly {length} bytes")
    return raw


def _round_up(value: int, alignment: int, name: str) -> int:
    _power_of_two(alignment, f"{name} alignment")
    if value > UINT64_MAX - (alignment - 1):
        raise PwnAllocError(f"{name} overflows while rounding")
    return (value + alignment - 1) & -alignment


def _scudo_minimum_alignment(value: object) -> tuple[int, int]:
    """Return the only minimum-alignment profile reviewed for this LE64 layout."""

    log = _bounded_int(value, "min_alignment_log", 4, 4)
    return log, 1 << log


def _bsd_word(checksum: int, word: int) -> int:
    for _ in range(8):
        checksum = ((checksum >> 1) | ((checksum & 1) << 15)) & 0xFFFF
        checksum = (checksum + (word & 0xFF)) & 0xFFFF
        word >>= 8
    return checksum


def _crc32c_word(crc: int, word: int) -> int:
    """SSE4.2/ARM CRC32C word update: direct seed, no initial/final xor."""

    for _ in range(8):
        crc ^= word & 0xFF
        word >>= 8
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc & UINT32_MAX


def _scudo_checksum(cookie: int, user_pointer: int, header_without_checksum: int,
                    algorithm: str) -> int:
    if algorithm == "bsd":
        checksum = cookie & 0xFFFF
        checksum = _bsd_word(checksum, user_pointer)
        return _bsd_word(checksum, header_without_checksum)
    if algorithm == "crc32c":
        crc = _crc32c_word(cookie, user_pointer)
        crc = _crc32c_word(crc, header_without_checksum)
        return (crc ^ (crc >> 16)) & 0xFFFF
    raise PwnAllocError("checksum_algorithm must be 'bsd' or 'crc32c'")


@dataclass(frozen=True)
class ScudoHeaderReport:
    """Decoded compact header and optional independently recomputed integrity evidence."""

    profile: str
    raw: int
    class_id: int
    backend: str
    state: str
    origin_or_was_zeroed: int
    origin: str | None
    was_zeroed: bool | None
    size_or_unused_bytes: int
    requested_size: int | None
    unused_bytes: int | None
    offset_units: int
    checksum: int
    checksum_status: str
    expected_checksum: int | None
    checksum_algorithm: str | None
    anomalies: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "raw": self.raw,
            "raw_hex": f"{self.raw:016x}",
            "class_id": self.class_id,
            "backend": self.backend,
            "state": self.state,
            "origin_or_was_zeroed": self.origin_or_was_zeroed,
            "origin": self.origin,
            "was_zeroed": self.was_zeroed,
            "size_or_unused_bytes": self.size_or_unused_bytes,
            "requested_size": self.requested_size,
            "unused_bytes": self.unused_bytes,
            "offset_units": self.offset_units,
            "checksum": self.checksum,
            "checksum_status": self.checksum_status,
            "expected_checksum": self.expected_checksum,
            "checksum_algorithm": self.checksum_algorithm,
            "anomalies": list(self.anomalies),
            "offline_only": True,
        }


@dataclass(frozen=True)
class ScudoSizePlan:
    """Caller-selected Scudo class-map reasoning, including larger-class retries."""

    profile: str
    class_map: str
    request_size: int
    alignment: int
    minimum_alignment: int
    header_size: int
    needed_size: int
    route: str
    primary_class_id: int | None
    primary_block_size: int | None
    retry_class_ids: tuple[int, ...]
    secondary_fallback: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "class_map": self.class_map,
            "request_size": self.request_size,
            "alignment": self.alignment,
            "minimum_alignment": self.minimum_alignment,
            "header_size": self.header_size,
            "needed_size": self.needed_size,
            "route": self.route,
            "primary_class_id": self.primary_class_id,
            "primary_block_size": self.primary_block_size,
            "retry_class_ids": list(self.retry_class_ids),
            "secondary_fallback": self.secondary_fallback,
            "offline_only": True,
        }


@dataclass(frozen=True)
class ScudoChunkAnalysis:
    """Geometry derived from a compact header and explicit address/class facts."""

    header: ScudoHeaderReport
    user_pointer: int
    packed_header_address: int
    block_begin: int
    block_end: int
    header_size: int
    offset_bytes: int
    usable_size: int
    requested_size: int
    slack: int

    def as_dict(self) -> dict[str, object]:
        return {
            "header": self.header.as_dict(),
            "user_pointer": self.user_pointer,
            "packed_header_address": self.packed_header_address,
            "block_begin": self.block_begin,
            "block_end": self.block_end,
            "header_size": self.header_size,
            "offset_bytes": self.offset_bytes,
            "usable_size": self.usable_size,
            "requested_size": self.requested_size,
            "slack": self.slack,
            "offline_only": True,
        }


@_fail_closed
def decode_scudo_header(
    data: bytes,
    *,
    profile: str,
    cookie: int | None = None,
    user_pointer: int | None = None,
    checksum_algorithm: str | None = None,
) -> ScudoHeaderReport:
    """Decode one source-pinned Scudo compact header without version guessing.

    Integrity remains ``unverified`` unless cookie, user pointer, and runtime-selected checksum
    algorithm are all supplied.  A mismatch is reported as evidence rather than hidden.
    """

    profile = _require_profile(profile, SCUDO_PROFILE, "Scudo")
    raw_bytes = _exact_bytes(data, 8, "Scudo compact header")
    raw = int.from_bytes(raw_bytes, "little")
    class_id = raw & 0xFF
    state_value = (raw >> 8) & 0x3
    origin_value = (raw >> 10) & 0x3
    size_value = (raw >> 12) & 0xFFFFF
    offset = (raw >> 32) & 0xFFFF
    checksum = (raw >> 48) & 0xFFFF
    states = {0: "available", 1: "allocated", 2: "quarantined"}
    if state_value not in states:
        raise PwnAllocError("Scudo header uses reserved state value 3")

    anomalies: list[str] = []
    origins = {0: "malloc", 1: "new", 2: "new-array", 3: "memalign"}
    if state_value == 1:
        origin = origins[origin_value]
        was_zeroed = None
    else:
        origin = None
        was_zeroed = bool(origin_value) if origin_value in (0, 1) else None
        if origin_value not in (0, 1):
            anomalies.append("non-boolean was-zeroed field")

    supplied = (cookie is not None, user_pointer is not None, checksum_algorithm is not None)
    if any(supplied) and not all(supplied):
        raise PwnAllocError(
            "checksum verification requires cookie, user_pointer, and checksum_algorithm together"
        )
    expected: int | None = None
    algorithm: str | None = None
    status = "unverified"
    if all(supplied):
        checked_cookie = _uint(cookie, "cookie", 32)
        checked_pointer = _uint(user_pointer, "user_pointer", 64)
        if not isinstance(checksum_algorithm, str):
            raise PwnAllocError("checksum_algorithm must be text")
        algorithm = checksum_algorithm
        header_without_checksum = raw & ((1 << 48) - 1)
        expected = _scudo_checksum(
            checked_cookie, checked_pointer, header_without_checksum, algorithm
        )
        status = "valid" if expected == checksum else "invalid"
        if status == "invalid":
            anomalies.append("checksum mismatch")

    primary = class_id != 0
    return ScudoHeaderReport(
        profile=profile,
        raw=raw,
        class_id=class_id,
        backend="primary" if primary else "secondary",
        state=states[state_value],
        origin_or_was_zeroed=origin_value,
        origin=origin,
        was_zeroed=was_zeroed,
        size_or_unused_bytes=size_value,
        requested_size=size_value if primary else None,
        unused_bytes=None if primary else size_value,
        offset_units=offset,
        checksum=checksum,
        checksum_status=status,
        expected_checksum=expected,
        checksum_algorithm=algorithm,
        anomalies=tuple(anomalies),
    )


def _default_scudo_class_sizes() -> tuple[int, ...]:
    # FixedSizeClassMap parameters at the pinned source: 3 bits, logs 5/8/17, delta 0.
    values: list[int] = []
    for class_id in range(1, 45):
        if class_id <= 8:
            values.append(class_id << 5)
        else:
            index = class_id - 8
            base = 256 << (index >> 2)
            values.append(base + (base >> 2) * (index & 3))
    return tuple(values)


def _class_sizes(class_map: object, supplied: object, minimum_alignment: int) -> tuple[str, tuple[int, ...]]:
    if class_map == "llvm-default-fixed":
        if supplied is not None:
            raise PwnAllocError("class_sizes must be omitted for llvm-default-fixed")
        return "llvm-default-fixed", _default_scudo_class_sizes()
    if class_map != "caller":
        raise PwnAllocError("class_map must be 'llvm-default-fixed' or 'caller'")
    if isinstance(supplied, (str, bytes, bytearray)) or not isinstance(supplied, Sequence):
        raise PwnAllocError("caller class_sizes must be a sequence")
    if not 1 <= len(supplied) <= 255:
        raise PwnAllocError("caller class_sizes must contain 1..255 primary classes")
    result: list[int] = []
    previous = 0
    for index, value in enumerate(supplied, 1):
        size = _uint(value, f"class_sizes[{index}]", 64)
        if size <= previous:
            raise PwnAllocError("caller class_sizes must be strictly increasing")
        if size % minimum_alignment:
            raise PwnAllocError("caller class_sizes must be minimum-alignment multiples")
        result.append(size)
        previous = size
    return "caller", tuple(result)


@_fail_closed
def plan_scudo_allocation(
    request_size: int,
    *,
    profile: str,
    alignment: int | None = None,
    min_alignment_log: int = 4,
    class_map: str = "llvm-default-fixed",
    class_sizes: Sequence[int] | None = None,
) -> ScudoSizePlan:
    """Reason about Scudo's needed size, first primary class, retries, and fallback."""

    profile = _require_profile(profile, SCUDO_PROFILE, "Scudo")
    request = _uint(request_size, "request_size", 64)
    _, minimum = _scudo_minimum_alignment(min_alignment_log)
    chosen_alignment = minimum if alignment is None else _uint(alignment, "alignment", 64)
    chosen_alignment = max(chosen_alignment, minimum)
    _power_of_two(chosen_alignment, "alignment")
    if chosen_alignment > SCUDO_MAX_ALIGNMENT:
        raise PwnAllocError("alignment exceeds the pinned Scudo MaxAlignment (1 << 24)")
    if request >= SCUDO_MAX_ALLOWED_MALLOC_SIZE:
        raise PwnAllocError("request_size reaches the pinned Scudo MaxAllowedMallocSize (1 << 40)")
    header_size = _round_up(8, minimum, "Scudo header size")
    rounded_request = _round_up(request, minimum, "request_size")
    overhead = chosen_alignment if chosen_alignment > minimum else header_size
    needed = _checked_add(rounded_request, overhead, "Scudo needed size")
    map_name, sizes = _class_sizes(class_map, class_sizes, minimum)

    selected = next((index for index, size in enumerate(sizes, 1) if size >= needed), None)
    if selected is None:
        return ScudoSizePlan(
            profile, map_name, request, chosen_alignment, minimum, header_size, needed,
            "secondary", None, None, (), False,
        )
    return ScudoSizePlan(
        profile=profile,
        class_map=map_name,
        request_size=request,
        alignment=chosen_alignment,
        minimum_alignment=minimum,
        header_size=header_size,
        needed_size=needed,
        route="primary",
        primary_class_id=selected,
        primary_block_size=sizes[selected - 1],
        retry_class_ids=tuple(range(selected + 1, len(sizes) + 1)),
        secondary_fallback=True,
    )


@_fail_closed
def analyze_scudo_chunk(
    data: bytes,
    *,
    profile: str,
    user_pointer: int,
    min_alignment_log: int = 4,
    class_sizes: Sequence[int] | None = None,
    secondary_block_end: int | None = None,
    cookie: int | None = None,
    checksum_algorithm: str | None = None,
) -> ScudoChunkAnalysis:
    """Derive primary/secondary block geometry only from sufficient supplied facts."""

    pointer = _uint(user_pointer, "user_pointer", 64)
    report = decode_scudo_header(
        data,
        profile=profile,
        cookie=cookie,
        user_pointer=pointer if cookie is not None or checksum_algorithm is not None else None,
        checksum_algorithm=checksum_algorithm,
    )
    if report.checksum_status == "invalid":
        raise PwnAllocError("refusing geometry from a Scudo header with an invalid checksum")
    log, minimum = _scudo_minimum_alignment(min_alignment_log)
    if pointer % minimum:
        raise PwnAllocError("Scudo user_pointer is not minimum-alignment aligned")
    header_size = _round_up(8, minimum, "Scudo header size")
    offset_bytes = report.offset_units << log
    distance = header_size + offset_bytes
    if pointer < distance:
        raise PwnAllocError("Scudo block begin underflows the address space")
    block_begin = pointer - distance
    packed_header_address = pointer - header_size

    if report.backend == "primary":
        _, sizes = _class_sizes("caller", class_sizes, minimum)
        if report.class_id > len(sizes):
            raise PwnAllocError("Scudo class_id is outside caller class_sizes")
        block_size = sizes[report.class_id - 1]
        block_end = _checked_add(block_begin, block_size, "Scudo primary block")
        if block_end < pointer:
            raise PwnAllocError("Scudo primary user pointer lies beyond its class block")
        usable = block_end - pointer
        requested = report.size_or_unused_bytes
    else:
        if class_sizes is not None:
            raise PwnAllocError("class_sizes must be omitted for a Secondary chunk")
        if secondary_block_end is None:
            raise PwnAllocError("Secondary chunk analysis requires secondary_block_end")
        block_end = _uint(secondary_block_end, "secondary_block_end", 64)
        if block_end < pointer:
            raise PwnAllocError("secondary_block_end precedes the user pointer")
        usable = block_end - pointer
        if report.size_or_unused_bytes > usable:
            raise PwnAllocError("Secondary unused-byte count exceeds usable bytes")
        requested = usable - report.size_or_unused_bytes
    if requested > usable:
        raise PwnAllocError("Scudo requested size exceeds derived usable size")
    return ScudoChunkAnalysis(
        report, pointer, packed_header_address, block_begin, block_end, header_size,
        offset_bytes, usable, requested, usable - requested,
    )


@dataclass(frozen=True)
class V8LayoutReport:
    """A supplied V8 object layout interpreted without reading target memory."""

    profile: str
    platform: str
    la57: bool
    sandbox_base: int
    sandbox_size: int
    object_address: int
    object_size: int
    object_space: str
    fields: tuple[Mapping[str, object], ...]
    overlaps: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "platform": self.platform,
            "la57": self.la57,
            "sandbox_base": self.sandbox_base,
            "sandbox_size": self.sandbox_size,
            "sandbox_end": self.sandbox_base + self.sandbox_size,
            "object_address": self.object_address,
            "object_size": self.object_size,
            "object_space": self.object_space,
            "fields": [dict(item) for item in self.fields],
            "overlaps": [list(item) for item in self.overlaps],
            "offline_only": True,
        }


_V8_PLATFORMS = {
    "x64": (40, 6, 512 << 20),
    "android64": (37, 7, 256 << 20),
    "ios64": (34, 8, 128 << 20),
    "chromeos-arm64": (37, 6, 512 << 20),
    "riscv64": (37, 6, 512 << 20),
    "loong64": (37, 6, 512 << 20),
}


def _v8_platform(value: object) -> tuple[str, int, int, int]:
    if not isinstance(value, str) or value not in _V8_PLATFORMS:
        raise PwnAllocError(f"unknown V8 platform; choose one of {', '.join(_V8_PLATFORMS)}")
    sandbox_log, external_shift, external_reservation = _V8_PLATFORMS[value]
    return value, sandbox_log, external_shift, external_reservation


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PwnAllocError(f"{name} must be an object")
    return value


def _optional_base(facts: Mapping[str, Any], key: str, alignment: int) -> int | None:
    if key not in facts:
        return None
    base = _uint(facts[key], key, 64)
    if base % alignment:
        raise PwnAllocError(f"{key} must be {alignment:#x}-aligned")
    return base


def _inside(address: int, start: int, size: int) -> bool:
    return start <= address < start + size


def _signed32(value: int) -> int:
    return value - (1 << 32) if value & (1 << 31) else value


def _tag_range(field: Mapping[str, Any], maximum: int) -> tuple[int, int] | None:
    one = field.get("expected_tag")
    low = field.get("expected_tag_min")
    high = field.get("expected_tag_max")
    if one is not None:
        if low is not None or high is not None:
            raise PwnAllocError("use expected_tag or an expected tag range, not both")
        checked = _bounded_int(one, "expected_tag", 0, maximum)
        return checked, checked
    if low is None and high is None:
        return None
    if low is None or high is None:
        raise PwnAllocError("expected_tag_min and expected_tag_max must appear together")
    checked_low = _bounded_int(low, "expected_tag_min", 0, maximum)
    checked_high = _bounded_int(high, "expected_tag_max", checked_low, maximum)
    return checked_low, checked_high


def _compressed_details(value: int, cage_base: int, sandbox_base: int,
                        sandbox_size: int) -> dict[str, object]:
    if value & 1 == 0:
        return {
            "classification": "smi",
            "smi_value": _signed32(value) >> 1,
        }
    tagged = _checked_add(cage_base, value, "V8 compressed pointer")
    tag = value & 0x3
    return {
        "classification": "heap-object",
        "tagged_address": tagged,
        "tag_bits": tag,
        "weak": tag == 3,
        "untagged_address": tagged - tag,
        "inside_sandbox": _inside(tagged, sandbox_base, sandbox_size),
    }


def _decode_external_entry(entry: int, tag_range: tuple[int, int] | None,
                           la57: bool) -> dict[str, object]:
    if la57:
        mark_bit = 1 << 56
        tag_shift = 57
        tag_mask = 0xFE00000000000000
        payload_mask = 0x00FFFFFFFFFFFFFF
    else:
        mark_bit = 1 << 48
        tag_shift = 49
        tag_mask = 0x00FE000000000000
        payload_mask = 0xFF00FFFFFFFFFFFF
    tag = (entry & tag_mask) >> tag_shift
    special = {0x7D: "zapped", 0x7E: "evacuation", 0x7F: "freelist"}.get(tag)
    matches = tag_range is not None and tag_range[0] <= tag <= tag_range[1]
    safe = matches and special is None
    return {
        "entry_word": entry,
        "entry_tag": tag,
        "entry_marked": bool(entry & mark_bit),
        "entry_kind": special or "pointer",
        "tag_match": matches if tag_range is not None else None,
        "payload_candidate": entry & payload_mask,
        "resolved_pointer": (entry & payload_mask) if safe else None,
    }


def _decode_trusted_entry(entry: int, tag_range: tuple[int, int] | None, la57: bool,
                          sandbox_base: int, sandbox_size: int) -> dict[str, object]:
    if la57:
        mark_bit = 1 << 56
        tag_shift = 57
        tag_mask = 0xFE00000000000000
        payload_mask = 0x00FFFFFFFFFFFFFF
    else:
        mark_bit = 1 << 48
        tag_shift = 49
        tag_mask = 0xFFFE000000000000
        payload_mask = 0x0000FFFFFFFFFFFF
    tag = (entry & tag_mask) >> tag_shift
    payload = entry & payload_mask
    matches = tag_range is not None and tag_range[0] <= tag <= tag_range[1]
    outside = not _inside(payload, sandbox_base, sandbox_size)
    special = {
        0: "null",
        0x7C: "unpublished",
        0x7D: "zapped",
        0x7E: "evacuation",
        0x7F: "freelist",
    }.get(tag)
    regular = 1 <= tag <= 0x0F
    tagged_heap_object = bool(payload & 1)
    return {
        "entry_word": entry,
        "entry_tag": tag,
        "entry_marked": bool(entry & mark_bit),
        "entry_kind": special or ("trusted-pointer" if regular else "reserved"),
        "tag_match": matches if tag_range is not None else None,
        "payload_candidate": payload,
        "outside_sandbox": outside,
        "tagged_heap_object": tagged_heap_object,
        "resolved_pointer": (
            payload if matches and regular and outside and tagged_heap_object else None
        ),
    }


@_fail_closed
def analyze_v8_layout(facts: Mapping[str, Any], *, profile: str) -> V8LayoutReport:
    """Interpret supplied V8 object/pointer facts for one immutable sandbox profile."""

    profile = _require_profile(profile, V8_PROFILE, "V8")
    facts = _mapping(facts, "facts")
    platform, sandbox_log, external_shift, external_reservation = _v8_platform(
        facts.get("platform")
    )
    la57 = _bool(facts.get("la57", False), "la57")
    if la57 and platform != "x64":
        raise PwnAllocError("LA57 entry layout is supported only for the x64 platform profile")
    if _bool(facts.get("lsan", False), "lsan"):
        raise PwnAllocError("LSan fat pointer-table entries are outside this V8 profile")

    sandbox_base = _uint(facts.get("sandbox_base"), "sandbox_base", 64)
    if sandbox_base % (1 << 32):
        raise PwnAllocError("sandbox_base must be 4-GiB aligned")
    sandbox_size = 1 << sandbox_log
    _checked_add(sandbox_base, sandbox_size, "V8 sandbox")
    object_address = _uint(facts.get("object_address"), "object_address", 64)
    object_size = _bounded_int(facts.get("object_size"), "object_size", 1, MAX_JSON)
    object_end = _checked_add(object_address, object_size, "V8 object")
    object_space = facts.get("object_space", "sandbox")
    if object_space not in ("sandbox", "trusted"):
        raise PwnAllocError("object_space must be 'sandbox' or 'trusted'")
    sandbox_end = sandbox_base + sandbox_size
    object_inside = sandbox_base <= object_address and object_end <= sandbox_end
    object_disjoint = object_end <= sandbox_base or object_address >= sandbox_end
    if object_space == "sandbox" and not object_inside:
        raise PwnAllocError("sandbox object is not wholly inside the sandbox")
    if object_space == "trusted" and not object_disjoint:
        raise PwnAllocError("trusted object overlaps the sandbox")

    pointer_cage = _optional_base(facts, "pointer_cage_base", 1 << 32)
    trusted_cage = _optional_base(facts, "trusted_cage_base", 1 << 32)
    ept_base = _optional_base(facts, "external_pointer_table_base", 8)
    tpt_base = _optional_base(facts, "trusted_pointer_table_base", 8)
    if pointer_cage is not None:
        pointer_cage_end = _checked_add(pointer_cage, 1 << 32, "pointer compression cage")
        if pointer_cage != sandbox_base or pointer_cage_end > sandbox_end:
            raise PwnAllocError(
                "pointer_cage_base must be the 4-GiB cage at the start of the sandbox"
            )
    if trusted_cage is not None:
        trusted_cage_end = _checked_add(trusted_cage, 1 << 32, "trusted compression cage")
        if not (trusted_cage_end <= sandbox_base or trusted_cage >= sandbox_end):
            raise PwnAllocError("trusted_cage_base overlaps the sandbox")
    if ept_base is not None:
        ept_end = _checked_add(ept_base, external_reservation, "external pointer table")
        if not (ept_end <= sandbox_base or ept_base >= sandbox_end):
            raise PwnAllocError("external pointer table overlaps the sandbox")
    if tpt_base is not None:
        tpt_end = _checked_add(tpt_base, 64 << 20, "trusted pointer table")
        if not (tpt_end <= sandbox_base or tpt_base >= sandbox_end):
            raise PwnAllocError("trusted pointer table overlaps the sandbox")

    raw_fields = facts.get("fields")
    if isinstance(raw_fields, (str, bytes, bytearray)) or not isinstance(raw_fields, Sequence):
        raise PwnAllocError("fields must be a sequence")
    if not 1 <= len(raw_fields) <= MAX_FIELDS:
        raise PwnAllocError(f"fields must contain 1..{MAX_FIELDS} entries")

    fields: list[dict[str, object]] = []
    spans: list[tuple[str, int, int]] = []
    names: set[str] = set()
    widths = {
        "sandboxed_pointer": 8,
        "compressed_tagged": 4,
        "external_handle": 4,
        "trusted_handle": 4,
        "protected_pointer": 4,
    }
    for index, raw_field in enumerate(raw_fields):
        field = _mapping(raw_field, f"fields[{index}]")
        name = field.get("name")
        if not isinstance(name, str) or not name or len(name) > 128:
            raise PwnAllocError("field names must be non-empty text of at most 128 characters")
        if name in names:
            raise PwnAllocError(f"duplicate field name {name!r}")
        names.add(name)
        kind = field.get("kind")
        if not isinstance(kind, str) or kind not in (*widths, "raw_pointer"):
            raise PwnAllocError(f"unknown V8 field kind {kind!r}")
        offset = _bounded_int(field.get("offset"), f"{name}.offset", 0, object_size - 1)
        width = field.get("width", widths.get(kind, 8))
        if kind == "raw_pointer":
            width = _bounded_int(width, f"{name}.width", 1, 8)
            if width not in (1, 2, 4, 8):
                raise PwnAllocError("raw_pointer width must be 1, 2, 4, or 8")
        elif width != widths[kind]:
            raise PwnAllocError(f"{kind} fields must be {widths[kind]} bytes wide")
        if offset + width > object_size:
            raise PwnAllocError(f"field {name!r} extends beyond object_size")
        value = _uint(field.get("value"), f"{name}.value", width * 8)
        field_address = _checked_add(object_address, offset, f"field {name}")
        result: dict[str, object] = {
            "name": name,
            "kind": kind,
            "offset": offset,
            "width": width,
            "field_address": field_address,
            "value": value,
        }

        if kind == "sandboxed_pointer":
            shift = 64 - sandbox_log
            offset_value = value >> shift
            decoded = _checked_add(sandbox_base, offset_value, f"{name} sandboxed pointer")
            result.update({
                "encoding_shift": shift,
                "decoded_offset": offset_value,
                "decoded_pointer": decoded,
                "canonical_encoding": value & ((1 << shift) - 1) == 0,
                "inside_sandbox": _inside(decoded, sandbox_base, sandbox_size),
            })
        elif kind == "compressed_tagged":
            if pointer_cage is None:
                raise PwnAllocError(f"{name} requires pointer_cage_base")
            result.update(_compressed_details(
                value, pointer_cage, sandbox_base, sandbox_size
            ))
        elif kind == "external_handle":
            if object_space != "sandbox":
                raise PwnAllocError("external handles are expected in sandbox objects")
            if ept_base is None:
                raise PwnAllocError(f"{name} requires external_pointer_table_base")
            index_value = value >> external_shift
            entry_address = _checked_add(ept_base, index_value * 8, f"{name} EPT entry")
            capacity = external_reservation // 8
            result.update({
                "handle_shift": external_shift,
                "handle_index": index_value,
                "canonical_handle": value & ((1 << external_shift) - 1) == 0,
                "null_handle": value == 0,
                "table_capacity": capacity,
                "entry_address": entry_address,
            })
            if index_value >= capacity:
                raise PwnAllocError(f"{name} external handle index exceeds table capacity")
            if "entry_word" in field:
                entry = _uint(field["entry_word"], f"{name}.entry_word", 64)
                result.update(_decode_external_entry(entry, _tag_range(field, 0x7F), la57))
            elif _tag_range(field, 0x7F) is not None:
                raise PwnAllocError(f"{name} expected tag requires entry_word evidence")
        elif kind == "trusted_handle":
            if object_space != "sandbox":
                raise PwnAllocError("trusted handles are expected in sandbox objects")
            if tpt_base is None:
                raise PwnAllocError(f"{name} requires trusted_pointer_table_base")
            shift = 9
            index_value = value >> shift
            capacity = (64 << 20) // 8
            if index_value >= capacity:
                raise PwnAllocError(f"{name} trusted handle index exceeds table capacity")
            result.update({
                "handle_shift": shift,
                "handle_index": index_value,
                "canonical_handle": value & ((1 << shift) - 1) == 0,
                "null_handle": value == 0,
                "table_capacity": capacity,
                "entry_address": _checked_add(tpt_base, index_value * 8, f"{name} TPT entry"),
            })
            if "entry_word" in field:
                entry = _uint(field["entry_word"], f"{name}.entry_word", 64)
                result.update(_decode_trusted_entry(
                    entry, _tag_range(field, 0x7F), la57, sandbox_base, sandbox_size
                ))
            elif _tag_range(field, 0x7F) is not None:
                raise PwnAllocError(f"{name} expected tag requires entry_word evidence")
        elif kind == "protected_pointer":
            if object_space != "trusted":
                raise PwnAllocError("protected pointers are permitted only in trusted objects")
            if trusted_cage is None:
                raise PwnAllocError(f"{name} requires trusted_cage_base")
            if value == 0:
                result.update({"classification": "empty-smi", "smi_value": 0})
            elif value & 1 == 0:
                raise PwnAllocError("a non-empty protected pointer must be a tagged heap pointer")
            else:
                details = _compressed_details(
                    value, trusted_cage, sandbox_base, sandbox_size
                )
                if details.get("inside_sandbox"):
                    raise PwnAllocError("protected pointer target must remain outside the sandbox")
                result.update(details)
        else:  # raw_pointer
            result.update({
                "classification": "inside-sandbox" if _inside(
                    value, sandbox_base, sandbox_size
                ) else "outside-sandbox",
            })

        fields.append(result)
        spans.append((name, offset, offset + width))

    overlaps: list[tuple[str, str]] = []
    for index, (left_name, left_start, left_end) in enumerate(spans):
        for right_name, right_start, right_end in spans[index + 1:]:
            if max(left_start, right_start) < min(left_end, right_end):
                overlaps.append((left_name, right_name))
    return V8LayoutReport(
        profile, platform, la57, sandbox_base, sandbox_size, object_address, object_size,
        object_space, tuple(MappingProxyType(dict(field)) for field in fields), tuple(overlaps),
    )


def _load_json(path: str) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_JSON + 1)
    except OSError as exc:
        raise PwnAllocError(f"cannot read config: {exc}") from exc
    if len(raw) > MAX_JSON:
        raise PwnAllocError("JSON config exceeds 1 MiB")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PwnAllocError(f"invalid JSON config: {exc}") from exc
    if not isinstance(value, dict):
        raise PwnAllocError("JSON root must be an object")
    return value


def _header_bytes(config: dict[str, Any]) -> bytes:
    value = config.pop("header_hex", None)
    if not isinstance(value, str) or len(value) != 16:
        raise PwnAllocError("header_hex must contain exactly 16 hexadecimal characters")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise PwnAllocError("header_hex is not hexadecimal") from exc


def _from_config(action: str, config: dict[str, Any]) -> object:
    try:
        if action == "scudo-header":
            data = _header_bytes(config)
            return decode_scudo_header(data, **config)
        if action == "scudo-plan":
            return plan_scudo_allocation(**config)
        if action == "scudo-chunk":
            data = _header_bytes(config)
            return analyze_scudo_chunk(data, **config)
        if action == "v8-layout":
            profile = config.pop("profile", None)
            return analyze_v8_layout(config, profile=profile)
        raise PwnAllocError("unknown action")
    except PwnAllocError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise PwnAllocError(f"malformed {action} config: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pwnalloc_scudo_v8.py")
    parser.add_argument(
        "action", choices=("scudo-header", "scudo-plan", "scudo-chunk", "v8-layout")
    )
    parser.add_argument("config", help="bounded JSON facts; no target is opened or executed")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        report = _from_config(args.action, _load_json(args.config))
        if not hasattr(report, "as_dict"):
            raise PwnAllocError("internal report lacks serialization contract")
        print(json.dumps(report.as_dict(), sort_keys=True))
        return 0
    except PwnAllocError as exc:
        print(f"pwnalloc_scudo_v8: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # guarded CLI boundary
        print(f"pwnalloc_scudo_v8: malformed input: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "PwnAllocError",
    "SCUDO_PROFILE",
    "V8_PROFILE",
    "ScudoChunkAnalysis",
    "ScudoHeaderReport",
    "ScudoSizePlan",
    "V8LayoutReport",
    "analyze_scudo_chunk",
    "analyze_v8_layout",
    "decode_scudo_header",
    "plan_scudo_allocation",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
