#!/usr/bin/env python3
"""Offline, configuration-declared Linux page exploitation geometry.

The helpers in this module perform arithmetic only. They never inspect a
running kernel, execute input, open a target, or access a network. Every
kernel-dependent quantity is supplied by the caller; an unknown memory model,
page-table shape, address range, or slab layout is rejected rather than
replaced with a common x86 default.

This complements ``kernel_pwn`` and ``research_wp_kernel_pages`` with generic
page-table composition, explicit Linux memory models, bounded direct-map
translation, exact partial descriptor-pointer patches, and physical page-UAF
overlap/field landings.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from functools import wraps
from itertools import islice
import json
import sys
from typing import Any, TypeVar, cast


U64_MAX = (1 << 64) - 1
MAX_LEVELS = 8
MAX_LEVEL_BITS = 16
MAX_VALID_RANGES = 4096
MAX_STRUCT_PAGE_SIZE = 1 << 20
MAX_SLAB_OBJECTS = 1 << 16
MAX_ORDER = 30


class PageGeometryError(ValueError):
    """The requested calculation is malformed or lacks exact configuration."""


_F = TypeVar("_F", bound=Callable[..., Any])


def _fail_closed(function: _F) -> _F:
    """Normalize every public arithmetic failure to ``PageGeometryError``."""

    @wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except PageGeometryError:
            raise
        except Exception as exc:
            raise PageGeometryError(
                f"{function.__name__} received malformed input"
            ) from exc

    return cast(_F, guarded)


def _uint(value: object, name: str, *, maximum: int = U64_MAX) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PageGeometryError(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise PageGeometryError(f"{name} must be in 0..{maximum}")
    return value


def _positive(value: object, name: str, *, maximum: int = U64_MAX) -> int:
    result = _uint(value, name, maximum=maximum)
    if result == 0:
        raise PageGeometryError(f"{name} must be positive")
    return result


def _bits(value: object, name: str, *, minimum: int, maximum: int) -> int:
    result = _uint(value, name, maximum=maximum)
    if result < minimum:
        raise PageGeometryError(f"{name} must be in {minimum}..{maximum}")
    return result


def _power_of_two(value: object, name: str, *, maximum: int) -> int:
    result = _positive(value, name, maximum=maximum)
    if result & (result - 1):
        raise PageGeometryError(f"{name} must be a power of two")
    return result


def _checked_end(start: int, length: int, maximum: int, name: str) -> int:
    """Return a half-open end after proving the inclusive last byte fits."""

    if length <= 0:
        raise PageGeometryError(f"{name} length must be positive")
    if start > maximum - (length - 1):
        raise PageGeometryError(f"{name} range overflows its address width")
    return start + length


@dataclass(frozen=True)
class PageTableLevel:
    """One caller-declared page-table level for a decomposed address."""

    name: str
    index_bits: int
    shift: int
    index: int
    entry_offset: int
    coverage_bytes: int | None
    leaf_alignment_pfns: int | None
    folded: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "coverage_bytes": self.coverage_bytes,
            "entry_offset": self.entry_offset,
            "folded": self.folded,
            "index": self.index,
            "index_bits": self.index_bits,
            "leaf_alignment_pfns": self.leaf_alignment_pfns,
            "name": self.name,
            "shift": self.shift,
        }


@dataclass(frozen=True)
class PageTableAddress:
    """A canonical address and its exact caller-declared walk geometry."""

    address: int
    page_shift: int
    page_size: int
    va_bits: int
    word_bits: int
    entry_size: int
    canonical_policy: str
    offset: int
    levels: tuple[PageTableLevel, ...]
    round_trip_address: int

    @property
    def indices(self) -> dict[str, int]:
        return {level.name: level.index for level in self.levels}

    def as_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "address_hex": f"0x{self.address:x}",
            "canonical_policy": self.canonical_policy,
            "entry_size": self.entry_size,
            "indices": self.indices,
            "levels": [level.as_dict() for level in self.levels],
            "offset": self.offset,
            "page_shift": self.page_shift,
            "page_size": self.page_size,
            "round_trip_address": self.round_trip_address,
            "va_bits": self.va_bits,
            "word_bits": self.word_bits,
        }


@dataclass(frozen=True)
class MemoryModelMapping:
    """One PFN's physical base and descriptor under an explicit Linux model."""

    memory_model: str
    pfn: int
    descriptor_address: int
    descriptor_base: int
    descriptor_index: int
    struct_page_size: int
    physical_page_base: int
    page_shift: int
    page_size: int
    physical_address_bits: int
    virtual_address_bits: int
    word_bits: int
    canonical_policy: str
    valid_pfn_range: tuple[int, int]
    arch_pfn_offset: int | None

    def as_dict(self) -> dict[str, object]:
        return {
            "arch_pfn_offset": self.arch_pfn_offset,
            "canonical_policy": self.canonical_policy,
            "descriptor_address": self.descriptor_address,
            "descriptor_address_hex": f"0x{self.descriptor_address:x}",
            "descriptor_base": self.descriptor_base,
            "descriptor_index": self.descriptor_index,
            "memory_model": self.memory_model,
            "page_shift": self.page_shift,
            "page_size": self.page_size,
            "pfn": self.pfn,
            "physical_address_bits": self.physical_address_bits,
            "physical_page_base": self.physical_page_base,
            "struct_page_size": self.struct_page_size,
            "valid_pfn_range": list(self.valid_pfn_range),
            "virtual_address_bits": self.virtual_address_bits,
            "word_bits": self.word_bits,
        }


@dataclass(frozen=True)
class DirectMapMapping:
    """A value translated inside one caller-bounded affine direct map."""

    physical_address: int
    virtual_address: int
    physical_base: int
    virtual_base: int
    length: int
    offset: int
    physical_address_bits: int
    virtual_address_bits: int
    word_bits: int
    canonical_policy: str

    def as_dict(self) -> dict[str, object]:
        return {
            "canonical_policy": self.canonical_policy,
            "length": self.length,
            "offset": self.offset,
            "physical_address": self.physical_address,
            "physical_address_hex": f"0x{self.physical_address:x}",
            "physical_address_bits": self.physical_address_bits,
            "physical_base": self.physical_base,
            "virtual_address": self.virtual_address,
            "virtual_address_hex": f"0x{self.virtual_address:x}",
            "virtual_base": self.virtual_base,
            "virtual_address_bits": self.virtual_address_bits,
            "word_bits": self.word_bits,
        }


@dataclass(frozen=True)
class PfnDirectMapMapping:
    """A PFN plus byte offset translated through a bounded direct map."""

    pfn: int
    page_offset: int
    page_shift: int
    page_size: int
    physical_address: int
    virtual_address: int
    physical_base: int
    virtual_base: int
    length: int
    physical_address_bits: int
    virtual_address_bits: int
    word_bits: int
    canonical_policy: str

    def as_dict(self) -> dict[str, object]:
        return {
            "canonical_policy": self.canonical_policy,
            "length": self.length,
            "page_offset": self.page_offset,
            "page_shift": self.page_shift,
            "page_size": self.page_size,
            "pfn": self.pfn,
            "physical_address": self.physical_address,
            "physical_address_hex": f"0x{self.physical_address:x}",
            "physical_address_bits": self.physical_address_bits,
            "physical_base": self.physical_base,
            "virtual_address": self.virtual_address,
            "virtual_address_hex": f"0x{self.virtual_address:x}",
            "virtual_base": self.virtual_base,
            "virtual_address_bits": self.virtual_address_bits,
            "word_bits": self.word_bits,
        }


@dataclass(frozen=True)
class DescriptorPointerPatch:
    """An exact partial-byte patch between two valid page descriptors."""

    source_pfn: int
    target_pfn: int
    source_pointer: int
    target_pointer: int
    descriptor_delta: int
    pointer_width: int
    overwrite_offset: int
    overwrite_width: int
    byteorder: str
    source_bytes_hex: str
    target_bytes_hex: str
    patch_hex: str

    @property
    def patch(self) -> bytes:
        return bytes.fromhex(self.patch_hex)

    def as_dict(self) -> dict[str, object]:
        return {
            "byteorder": self.byteorder,
            "descriptor_delta": self.descriptor_delta,
            "overwrite_offset": self.overwrite_offset,
            "overwrite_width": self.overwrite_width,
            "patch_hex": self.patch_hex,
            "pointer_width": self.pointer_width,
            "preserved_bytes_match": True,
            "source_bytes_hex": self.source_bytes_hex,
            "source_pfn": self.source_pfn,
            "source_pointer": self.source_pointer,
            "target_bytes_hex": self.target_bytes_hex,
            "target_pfn": self.target_pfn,
            "target_pointer": self.target_pointer,
        }


@dataclass(frozen=True)
class ReclaimedFieldLanding:
    """One target-slab field touched through the stale physical window."""

    object_index: int
    object_ordinal: int
    replacement_byte_offset: int
    physical_address: int
    width: int
    first_pfn: int
    last_pfn: int
    replacement_first_page_index: int
    replacement_last_page_index: int
    in_page_offset: int
    fully_reachable: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "field_start": self.physical_address,
            "first_pfn": self.first_pfn,
            "fully_reachable": self.fully_reachable,
            "in_page_offset": self.in_page_offset,
            "last_pfn": self.last_pfn,
            "object_index": self.object_index,
            "object_ordinal": self.object_ordinal,
            "physical_address": self.physical_address,
            "replacement_byte_offset": self.replacement_byte_offset,
            "replacement_first_page_index": self.replacement_first_page_index,
            "replacement_last_page_index": self.replacement_last_page_index,
            "width": self.width,
        }


@dataclass(frozen=True)
class PageUafLanding:
    """Exact released/replacement overlap and reachable target fields."""

    page_shift: int
    page_size: int
    physical_address_bits: int
    released_head_pfn: int
    released_order: int
    released_pfn_range: tuple[int, int]
    replacement_head_pfn: int
    replacement_order: int
    replacement_pfn_range: tuple[int, int]
    extent_overlap_pfn_range: tuple[int, int] | None
    extent_relation: str
    stale_page_index: int
    stale_offset: int
    stale_length: int
    stale_physical_range: tuple[int, int]
    stale_overlap_physical_range: tuple[int, int] | None
    access_relation: str
    released_overlap_page_range: tuple[int, int] | None
    replacement_overlap_page_range: tuple[int, int] | None
    first_object_offset: int
    object_stride: int
    object_size: int
    objects_per_slab: int
    field_offset: int
    field_width: int
    reachable_fields: tuple[ReclaimedFieldLanding, ...]
    partial_fields: tuple[ReclaimedFieldLanding, ...]
    prerequisites: tuple[str, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        def interval(value: tuple[int, int] | None) -> list[int] | None:
            return None if value is None else list(value)

        source_indices = None
        replacement_indices = None
        if self.released_overlap_page_range is not None:
            source_indices = [
                self.released_overlap_page_range[0],
                self.released_overlap_page_range[1] - 1,
            ]
        if self.replacement_overlap_page_range is not None:
            replacement_indices = [
                self.replacement_overlap_page_range[0],
                self.replacement_overlap_page_range[1] - 1,
            ]
        all_fields = sorted(
            (*self.reachable_fields, *self.partial_fields),
            key=lambda item: item.object_index,
        )
        return {
            "access_relation": self.access_relation,
            "extent_overlap_pfn_range": interval(self.extent_overlap_pfn_range),
            "extent_relation": self.extent_relation,
            "field_landings": [item.as_dict() for item in all_fields],
            "field_offset": self.field_offset,
            "field_width": self.field_width,
            "first_object_offset": self.first_object_offset,
            "object_size": self.object_size,
            "object_stride": self.object_stride,
            "objects_per_slab": self.objects_per_slab,
            "page_shift": self.page_shift,
            "page_size": self.page_size,
            "partial_fields": [item.as_dict() for item in self.partial_fields],
            "physical_address_bits": self.physical_address_bits,
            "prerequisites": list(self.prerequisites),
            "reachable_fields": [item.as_dict() for item in self.reachable_fields],
            "released_head_pfn": self.released_head_pfn,
            "released_order": self.released_order,
            "released_overlap_page_range": interval(self.released_overlap_page_range),
            "released_pfn_range": list(self.released_pfn_range),
            "replacement_head_pfn": self.replacement_head_pfn,
            "replacement_order": self.replacement_order,
            "replacement_overlap_page_range": interval(self.replacement_overlap_page_range),
            "replacement_page_indices": replacement_indices,
            "replacement_pfn_range": list(self.replacement_pfn_range),
            "reuse_guaranteed": False,
            "stale_length": self.stale_length,
            "stale_offset": self.stale_offset,
            "stale_overlap_physical_range": interval(self.stale_overlap_physical_range),
            "stale_page_index": self.stale_page_index,
            "stale_physical_range": list(self.stale_physical_range),
            "stale_source_page_indices": source_indices,
            "warnings": list(self.warnings),
        }


def _bounded_tuple(value: object, name: str, maximum: int) -> tuple[object, ...]:
    if isinstance(value, (str, bytes, bytearray)):
        raise PageGeometryError(f"{name} must be a finite sequence")
    try:
        iterator = iter(cast(Sequence[object], value))
        rows = tuple(islice(iterator, maximum + 1))
    except (TypeError, ValueError, OverflowError) as exc:
        raise PageGeometryError(f"{name} must be a finite sequence") from exc
    if len(rows) > maximum:
        raise PageGeometryError(f"{name} exceeds its {maximum}-entry bound")
    return rows


def _normalize_levels(levels: object) -> tuple[tuple[str, int], ...]:
    rows = _bounded_tuple(levels, "levels", MAX_LEVELS)
    if not rows:
        raise PageGeometryError("levels must contain at least one entry")
    normalized: list[tuple[str, int]] = []
    seen: set[str] = set()
    for position, row in enumerate(rows):
        parts = _bounded_tuple(row, f"levels[{position}]", 2)
        if len(parts) != 2:
            raise PageGeometryError(f"levels[{position}] must be (name, index_bits)")
        name, raw_bits = parts
        if not isinstance(name, str) or not name or len(name) > 32:
            raise PageGeometryError(
                "level names must be unique non-empty strings up to 32 characters"
            )
        if name in seen:
            raise PageGeometryError(f"duplicate page-table level name: {name}")
        seen.add(name)
        width = _uint(
            raw_bits, f"levels[{position}].index_bits", maximum=MAX_LEVEL_BITS
        )
        normalized.append((name, width))
    if not any(width for _, width in normalized):
        raise PageGeometryError("at least one page-table level must have index bits")
    return tuple(normalized)


def _table_geometry(
    *,
    levels: object,
    page_shift: object,
    va_bits: object,
    word_bits: object,
    entry_size: object,
    canonical_policy: object,
) -> tuple[tuple[tuple[str, int], ...], int, int, int, int, str]:
    normalized = _normalize_levels(levels)
    shift = _bits(page_shift, "page_shift", minimum=9, maximum=30)
    va_width = _bits(va_bits, "va_bits", minimum=shift + 1, maximum=64)
    word_width = _bits(word_bits, "word_bits", minimum=va_width, maximum=64)
    entry = _power_of_two(entry_size, "entry_size", maximum=1 << shift)
    policy = _canonical_policy_value(canonical_policy)
    if shift + sum(width for _, width in normalized) != va_width:
        raise PageGeometryError(
            "page_shift plus all level widths must equal va_bits exactly"
        )
    page_size = 1 << shift
    for name, width in normalized:
        if (1 << width) * entry > page_size:
            raise PageGeometryError(
                f"level {name} has more entries than fit in one declared table page"
            )
    return normalized, shift, va_width, word_width, entry, policy


def _canonicalize_low(low: int, va_bits: int, word_bits: int, policy: str) -> int:
    low_mask = (1 << va_bits) - 1
    value = low & low_mask
    if policy == "zero-extended" or not (value & (1 << (va_bits - 1))):
        return value
    return value | (((1 << word_bits) - 1) ^ low_mask)


def _canonical_policy_value(value: object) -> str:
    if not isinstance(value, str) or value not in (
        "sign-extended",
        "zero-extended",
    ):
        raise PageGeometryError(
            "canonical_policy must be 'sign-extended' or 'zero-extended'"
        )
    return value


def _require_canonical(address: object, va_bits: int, word_bits: int, policy: str) -> int:
    value = _uint(address, "address", maximum=(1 << word_bits) - 1)
    low = value & ((1 << va_bits) - 1)
    if value != _canonicalize_low(low, va_bits, word_bits, policy):
        raise PageGeometryError(
            f"address is not canonical under the declared {policy} VA policy"
        )
    return value


def _require_canonical_range(
    start: int,
    length: int,
    *,
    va_bits: int,
    word_bits: int,
    policy: str,
    name: str,
) -> int:
    """Validate that every address in one half-open virtual range is canonical."""

    maximum = (1 << word_bits) - 1
    end = _checked_end(start, length, maximum, name)
    last = end - 1
    _require_canonical(start, va_bits, word_bits, policy)
    _require_canonical(last, va_bits, word_bits, policy)
    if policy == "zero-extended":
        if last >= 1 << va_bits:
            raise PageGeometryError(f"{name} crosses the zero-extended VA range")
    elif va_bits == word_bits:
        pass
    else:
        low_end = 1 << (va_bits - 1)
        high_start = _canonicalize_low(low_end, va_bits, word_bits, policy)
        if start < low_end:
            if last >= low_end:
                raise PageGeometryError(f"{name} crosses the noncanonical VA gap")
        elif start < high_start:
            raise PageGeometryError(f"{name} starts in the noncanonical VA gap")
    return end


def _decompose_validated(
    address: int,
    normalized: tuple[tuple[str, int], ...],
    page_shift: int,
    va_bits: int,
    word_bits: int,
    entry_size: int,
    policy: str,
) -> PageTableAddress:
    value = _require_canonical(address, va_bits, word_bits, policy)
    low = value & ((1 << va_bits) - 1)
    page_size = 1 << page_shift
    offset = low & (page_size - 1)
    shift = page_shift
    level_rows: list[PageTableLevel] = []
    raw = offset
    for name, width in normalized:
        mask = (1 << width) - 1 if width else 0
        index = (low >> shift) & mask if width else 0
        level_rows.append(
            PageTableLevel(
                name=name,
                index_bits=width,
                shift=shift,
                index=index,
                entry_offset=index * entry_size,
                coverage_bytes=None if width == 0 else 1 << shift,
                leaf_alignment_pfns=(
                    None if width == 0 else 1 << (shift - page_shift)
                ),
                folded=width == 0,
            )
        )
        raw |= index << shift
        shift += width
    round_trip = _canonicalize_low(raw, va_bits, word_bits, policy)
    if round_trip != value:
        raise PageGeometryError("page-table decomposition did not round-trip")
    return PageTableAddress(
        address=value,
        page_shift=page_shift,
        page_size=page_size,
        va_bits=va_bits,
        word_bits=word_bits,
        entry_size=entry_size,
        canonical_policy=policy,
        offset=offset,
        levels=tuple(level_rows),
        round_trip_address=round_trip,
    )


@_fail_closed
def decompose_page_table(
    address: int,
    *,
    levels: Sequence[tuple[str, int]],
    page_shift: int,
    va_bits: int,
    word_bits: int,
    entry_size: int,
    canonical_policy: str,
) -> PageTableAddress:
    """Decompose a canonical VA using only caller-declared geometry.

    ``levels`` is ordered from the leaf upward (for example PTE, PMD, PUD,
    PGD). A folded level may be represented explicitly with zero index bits.
    """

    geometry = _table_geometry(
        levels=levels,
        page_shift=page_shift,
        va_bits=va_bits,
        word_bits=word_bits,
        entry_size=entry_size,
        canonical_policy=canonical_policy,
    )
    return _decompose_validated(address, *geometry)


@_fail_closed
def compose_page_table(
    indices: Mapping[str, int],
    *,
    offset: int,
    levels: Sequence[tuple[str, int]],
    page_shift: int,
    va_bits: int,
    word_bits: int,
    entry_size: int,
    canonical_policy: str,
) -> PageTableAddress:
    """Compose and verify a VA from one exact index per declared level."""

    normalized, shift, va_width, word_width, entry, policy = _table_geometry(
        levels=levels,
        page_shift=page_shift,
        va_bits=va_bits,
        word_bits=word_bits,
        entry_size=entry_size,
        canonical_policy=canonical_policy,
    )
    if not isinstance(indices, Mapping):
        raise PageGeometryError("indices must be a mapping keyed by level name")
    expected = {name for name, _ in normalized}
    try:
        supplied_keys = tuple(islice(iter(indices), MAX_LEVELS + 1))
    except (TypeError, ValueError, OverflowError) as exc:
        raise PageGeometryError("indices must have a finite bounded key set") from exc
    if len(supplied_keys) > MAX_LEVELS:
        raise PageGeometryError(f"indices exceeds its {MAX_LEVELS}-key bound")
    supplied = set(supplied_keys)
    if supplied != expected:
        missing = sorted(expected - supplied)
        extra = sorted(supplied - expected, key=str)
        raise PageGeometryError(
            f"indices must match levels exactly (missing={missing!r}, extra={extra!r})"
        )
    page_size = 1 << shift
    raw = _uint(offset, "offset", maximum=page_size - 1)
    current_shift = shift
    for name, width in normalized:
        index = _uint(
            indices[name], f"indices[{name!r}]", maximum=(1 << width) - 1
        )
        raw |= index << current_shift
        current_shift += width
    address = _canonicalize_low(raw, va_width, word_width, policy)
    return _decompose_validated(
        address, normalized, shift, va_width, word_width, entry, policy
    )


def _memory_geometry(
    *,
    memory_model: object,
    descriptor_base: object,
    struct_page_size: object,
    page_shift: object,
    physical_address_bits: object,
    virtual_address_bits: object,
    word_bits: object,
    canonical_policy: object,
    valid_pfn_ranges: object,
    arch_pfn_offset: object,
) -> tuple[
    str,
    int,
    int,
    int,
    int,
    int,
    int,
    str,
    tuple[tuple[int, int], ...],
    int | None,
]:
    if not isinstance(memory_model, str):
        raise PageGeometryError("memory_model must be declared")
    if memory_model in ("sparsemem", "classic-sparsemem", "sparsemem-classic"):
        raise PageGeometryError(
            "classic SPARSEMEM needs section metadata and is not an affine model"
        )
    if memory_model not in ("sparsemem-vmemmap", "flatmem"):
        raise PageGeometryError(
            "memory_model must be 'sparsemem-vmemmap' or 'flatmem'"
        )
    pointer_bits = _bits(word_bits, "word_bits", minimum=16, maximum=64)
    virtual_bits = _bits(
        virtual_address_bits,
        "virtual_address_bits",
        minimum=2,
        maximum=pointer_bits,
    )
    policy = _canonical_policy_value(canonical_policy)
    base = _require_canonical(
        descriptor_base, virtual_bits, pointer_bits, policy
    )
    descriptor_size = _positive(
        struct_page_size, "struct_page_size", maximum=MAX_STRUCT_PAGE_SIZE
    )
    shift = _bits(page_shift, "page_shift", minimum=9, maximum=30)
    physical_bits = _bits(
        physical_address_bits,
        "physical_address_bits",
        minimum=shift + 1,
        maximum=64,
    )
    maximum_pfn_exclusive = 1 << (physical_bits - shift)
    rows = _bounded_tuple(valid_pfn_ranges, "valid_pfn_ranges", MAX_VALID_RANGES)
    if not rows:
        raise PageGeometryError("valid_pfn_ranges must contain at least one range")
    normalized_ranges: list[tuple[int, int]] = []
    for position, row in enumerate(rows):
        parts = _bounded_tuple(row, f"valid_pfn_ranges[{position}]", 2)
        if len(parts) != 2:
            raise PageGeometryError(
                f"valid_pfn_ranges[{position}] must be (start, end)"
            )
        start = _uint(
            parts[0],
            f"valid_pfn_ranges[{position}].start",
            maximum=maximum_pfn_exclusive,
        )
        end = _uint(
            parts[1],
            f"valid_pfn_ranges[{position}].end",
            maximum=maximum_pfn_exclusive,
        )
        if start >= end:
            raise PageGeometryError("valid PFN ranges must be non-empty and half-open")
        normalized_ranges.append((start, end))
    normalized_ranges.sort()
    for previous, current in zip(normalized_ranges, normalized_ranges[1:]):
        if current[0] < previous[1]:
            raise PageGeometryError("valid PFN ranges must not overlap")
    if memory_model == "flatmem":
        if arch_pfn_offset is None:
            raise PageGeometryError("flatmem requires arch_pfn_offset")
        arch_offset: int | None = _uint(
            arch_pfn_offset,
            "arch_pfn_offset",
            maximum=maximum_pfn_exclusive - 1,
        )
    else:
        if arch_pfn_offset is not None:
            raise PageGeometryError(
                "arch_pfn_offset is only valid for the flatmem model"
            )
        arch_offset = None
    return (
        memory_model,
        base,
        descriptor_size,
        shift,
        physical_bits,
        pointer_bits,
        virtual_bits,
        policy,
        tuple(normalized_ranges),
        arch_offset,
    )


def _containing_pfn_range(
    pfn: int, ranges: tuple[tuple[int, int], ...]
) -> tuple[int, int]:
    for start, end in ranges:
        if start <= pfn < end:
            return start, end
    raise PageGeometryError("PFN is outside every caller-declared valid range")


def _map_pfn_validated(
    pfn: object,
    geometry: tuple[
        str,
        int,
        int,
        int,
        int,
        int,
        int,
        str,
        tuple[tuple[int, int], ...],
        int | None,
    ],
) -> MemoryModelMapping:
    (
        model,
        base,
        descriptor_size,
        shift,
        physical_bits,
        pointer_bits,
        virtual_bits,
        policy,
        ranges,
        arch_offset,
    ) = geometry
    max_pfn = (1 << (physical_bits - shift)) - 1
    number = _uint(pfn, "pfn", maximum=max_pfn)
    valid_range = _containing_pfn_range(number, ranges)
    if model == "flatmem":
        assert arch_offset is not None
        if number < arch_offset:
            raise PageGeometryError("flatmem PFN is below arch_pfn_offset")
        descriptor_index = number - arch_offset
    else:
        descriptor_index = number
    pointer_max = (1 << pointer_bits) - 1
    delta = descriptor_index * descriptor_size
    if delta > pointer_max - base:
        raise PageGeometryError("page descriptor address overflows word_bits")
    descriptor_address = base + delta
    _require_canonical_range(
        descriptor_address,
        descriptor_size,
        va_bits=virtual_bits,
        word_bits=pointer_bits,
        policy=policy,
        name="page descriptor",
    )
    physical_base = number << shift
    physical_max = (1 << physical_bits) - 1
    if physical_base > physical_max - ((1 << shift) - 1):
        raise PageGeometryError("physical page exceeds the declared address width")
    return MemoryModelMapping(
        memory_model=model,
        pfn=number,
        descriptor_address=descriptor_address,
        descriptor_base=base,
        descriptor_index=descriptor_index,
        struct_page_size=descriptor_size,
        physical_page_base=physical_base,
        page_shift=shift,
        page_size=1 << shift,
        physical_address_bits=physical_bits,
        virtual_address_bits=virtual_bits,
        word_bits=pointer_bits,
        canonical_policy=policy,
        valid_pfn_range=valid_range,
        arch_pfn_offset=arch_offset,
    )


@_fail_closed
def map_pfn(
    pfn: int,
    *,
    memory_model: str,
    descriptor_base: int,
    struct_page_size: int,
    page_shift: int,
    physical_address_bits: int,
    virtual_address_bits: int,
    word_bits: int,
    canonical_policy: str,
    valid_pfn_ranges: Sequence[tuple[int, int]],
    arch_pfn_offset: int | None = None,
) -> MemoryModelMapping:
    """Map a valid PFN through explicit VMEMMAP or FLATMEM arithmetic."""

    geometry = _memory_geometry(
        memory_model=memory_model,
        descriptor_base=descriptor_base,
        struct_page_size=struct_page_size,
        page_shift=page_shift,
        physical_address_bits=physical_address_bits,
        virtual_address_bits=virtual_address_bits,
        word_bits=word_bits,
        canonical_policy=canonical_policy,
        valid_pfn_ranges=valid_pfn_ranges,
        arch_pfn_offset=arch_pfn_offset,
    )
    return _map_pfn_validated(pfn, geometry)


@_fail_closed
def map_descriptor(
    descriptor_address: int,
    *,
    memory_model: str,
    descriptor_base: int,
    struct_page_size: int,
    page_shift: int,
    physical_address_bits: int,
    virtual_address_bits: int,
    word_bits: int,
    canonical_policy: str,
    valid_pfn_ranges: Sequence[tuple[int, int]],
    arch_pfn_offset: int | None = None,
) -> MemoryModelMapping:
    """Invert an exactly aligned descriptor under the declared memory model."""

    geometry = _memory_geometry(
        memory_model=memory_model,
        descriptor_base=descriptor_base,
        struct_page_size=struct_page_size,
        page_shift=page_shift,
        physical_address_bits=physical_address_bits,
        virtual_address_bits=virtual_address_bits,
        word_bits=word_bits,
        canonical_policy=canonical_policy,
        valid_pfn_ranges=valid_pfn_ranges,
        arch_pfn_offset=arch_pfn_offset,
    )
    (
        model,
        base,
        descriptor_size,
        shift,
        physical_bits,
        pointer_bits,
        virtual_bits,
        policy,
        _,
        arch_offset,
    ) = geometry
    address = _require_canonical(
        descriptor_address, virtual_bits, pointer_bits, policy
    )
    _require_canonical_range(
        address,
        descriptor_size,
        va_bits=virtual_bits,
        word_bits=pointer_bits,
        policy=policy,
        name="page descriptor",
    )
    if address < base:
        raise PageGeometryError("descriptor_address is below descriptor_base")
    delta = address - base
    if delta % descriptor_size:
        raise PageGeometryError("descriptor_address is not on a descriptor boundary")
    descriptor_index = delta // descriptor_size
    pfn = (
        descriptor_index
        if model == "sparsemem-vmemmap"
        else descriptor_index + cast(int, arch_offset)
    )
    max_pfn = (1 << (physical_bits - shift)) - 1
    if pfn > max_pfn:
        raise PageGeometryError("descriptor resolves beyond the physical address width")
    result = _map_pfn_validated(pfn, geometry)
    if result.descriptor_address != address:
        raise PageGeometryError("descriptor mapping did not round-trip")
    return result


def _direct_geometry(
    *,
    physical_base: object,
    virtual_base: object,
    length: object,
    physical_address_bits: object,
    virtual_address_bits: object,
    word_bits: object,
    canonical_policy: object,
) -> tuple[int, int, int, int, int, int, str]:
    physical_bits = _bits(
        physical_address_bits, "physical_address_bits", minimum=1, maximum=64
    )
    pointer_bits = _bits(word_bits, "word_bits", minimum=2, maximum=64)
    virtual_bits = _bits(
        virtual_address_bits,
        "virtual_address_bits",
        minimum=2,
        maximum=pointer_bits,
    )
    policy = _canonical_policy_value(canonical_policy)
    physical_max = (1 << physical_bits) - 1
    virtual_max = (1 << pointer_bits) - 1
    phys = _uint(physical_base, "physical_base", maximum=physical_max)
    virt = _uint(virtual_base, "virtual_base", maximum=virtual_max)
    span = _positive(length, "length", maximum=U64_MAX)
    _checked_end(phys, span, physical_max, "physical direct-map")
    _require_canonical_range(
        virt,
        span,
        va_bits=virtual_bits,
        word_bits=pointer_bits,
        policy=policy,
        name="virtual direct-map",
    )
    return phys, virt, span, physical_bits, virtual_bits, pointer_bits, policy


@_fail_closed
def physical_to_direct_map(
    physical_address: int,
    *,
    physical_base: int,
    virtual_base: int,
    length: int,
    physical_address_bits: int,
    virtual_address_bits: int,
    word_bits: int,
    canonical_policy: str,
) -> DirectMapMapping:
    """Translate a physical byte only inside a declared direct-map interval."""

    (
        phys,
        virt,
        span,
        physical_bits,
        virtual_bits,
        pointer_bits,
        policy,
    ) = _direct_geometry(
        physical_base=physical_base,
        virtual_base=virtual_base,
        length=length,
        physical_address_bits=physical_address_bits,
        virtual_address_bits=virtual_address_bits,
        word_bits=word_bits,
        canonical_policy=canonical_policy,
    )
    value = _uint(
        physical_address,
        "physical_address",
        maximum=(1 << physical_bits) - 1,
    )
    if not phys <= value < phys + span:
        raise PageGeometryError("physical_address is outside the declared direct map")
    offset = value - phys
    return DirectMapMapping(
        physical_address=value,
        virtual_address=virt + offset,
        physical_base=phys,
        virtual_base=virt,
        length=span,
        offset=offset,
        physical_address_bits=physical_bits,
        virtual_address_bits=virtual_bits,
        word_bits=pointer_bits,
        canonical_policy=policy,
    )


@_fail_closed
def direct_map_to_physical(
    virtual_address: int,
    *,
    physical_base: int,
    virtual_base: int,
    length: int,
    physical_address_bits: int,
    virtual_address_bits: int,
    word_bits: int,
    canonical_policy: str,
) -> DirectMapMapping:
    """Invert a virtual byte only inside a declared direct-map interval."""

    (
        phys,
        virt,
        span,
        physical_bits,
        virtual_bits,
        pointer_bits,
        policy,
    ) = _direct_geometry(
        physical_base=physical_base,
        virtual_base=virtual_base,
        length=length,
        physical_address_bits=physical_address_bits,
        virtual_address_bits=virtual_address_bits,
        word_bits=word_bits,
        canonical_policy=canonical_policy,
    )
    value = _uint(
        virtual_address,
        "virtual_address",
        maximum=(1 << pointer_bits) - 1,
    )
    if not virt <= value < virt + span:
        raise PageGeometryError("virtual_address is outside the declared direct map")
    offset = value - virt
    return DirectMapMapping(
        physical_address=phys + offset,
        virtual_address=value,
        physical_base=phys,
        virtual_base=virt,
        length=span,
        offset=offset,
        physical_address_bits=physical_bits,
        virtual_address_bits=virtual_bits,
        word_bits=pointer_bits,
        canonical_policy=policy,
    )


@_fail_closed
def pfn_to_direct_map(
    pfn: int,
    *,
    page_offset: int,
    page_shift: int,
    physical_base: int,
    virtual_base: int,
    length: int,
    physical_address_bits: int,
    virtual_address_bits: int,
    word_bits: int,
    canonical_policy: str,
) -> PfnDirectMapMapping:
    """Translate an exact PFN and in-page byte through a declared direct map."""

    shift = _bits(page_shift, "page_shift", minimum=9, maximum=30)
    physical_bits = _bits(
        physical_address_bits,
        "physical_address_bits",
        minimum=shift + 1,
        maximum=64,
    )
    page_size = 1 << shift
    maximum_pfn = (1 << (physical_bits - shift)) - 1
    number = _uint(pfn, "pfn", maximum=maximum_pfn)
    offset = _uint(page_offset, "page_offset", maximum=page_size - 1)
    physical = (number << shift) + offset
    translated = physical_to_direct_map(
        physical,
        physical_base=physical_base,
        virtual_base=virtual_base,
        length=length,
        physical_address_bits=physical_bits,
        virtual_address_bits=virtual_address_bits,
        word_bits=word_bits,
        canonical_policy=canonical_policy,
    )
    return PfnDirectMapMapping(
        pfn=number,
        page_offset=offset,
        page_shift=shift,
        page_size=page_size,
        physical_address=translated.physical_address,
        virtual_address=translated.virtual_address,
        physical_base=translated.physical_base,
        virtual_base=translated.virtual_base,
        length=translated.length,
        physical_address_bits=translated.physical_address_bits,
        virtual_address_bits=translated.virtual_address_bits,
        word_bits=translated.word_bits,
        canonical_policy=translated.canonical_policy,
    )


@_fail_closed
def direct_map_to_pfn(
    virtual_address: int,
    *,
    page_shift: int,
    physical_base: int,
    virtual_base: int,
    length: int,
    physical_address_bits: int,
    virtual_address_bits: int,
    word_bits: int,
    canonical_policy: str,
) -> PfnDirectMapMapping:
    """Invert a direct-map byte into its exact PFN and in-page offset."""

    shift = _bits(page_shift, "page_shift", minimum=9, maximum=30)
    physical_bits = _bits(
        physical_address_bits,
        "physical_address_bits",
        minimum=shift + 1,
        maximum=64,
    )
    translated = direct_map_to_physical(
        virtual_address,
        physical_base=physical_base,
        virtual_base=virtual_base,
        length=length,
        physical_address_bits=physical_bits,
        virtual_address_bits=virtual_address_bits,
        word_bits=word_bits,
        canonical_policy=canonical_policy,
    )
    page_size = 1 << shift
    number, offset = divmod(translated.physical_address, page_size)
    maximum_pfn = (1 << (physical_bits - shift)) - 1
    if number > maximum_pfn:
        raise PageGeometryError("direct-map address resolves beyond PFN width")
    return PfnDirectMapMapping(
        pfn=number,
        page_offset=offset,
        page_shift=shift,
        page_size=page_size,
        physical_address=translated.physical_address,
        virtual_address=translated.virtual_address,
        physical_base=translated.physical_base,
        virtual_base=translated.virtual_base,
        length=translated.length,
        physical_address_bits=translated.physical_address_bits,
        virtual_address_bits=translated.virtual_address_bits,
        word_bits=translated.word_bits,
        canonical_policy=translated.canonical_policy,
    )


@_fail_closed
def plan_descriptor_pointer_patch(
    source_pfn: int,
    target_pfn: int,
    *,
    memory_model: str,
    descriptor_base: int,
    struct_page_size: int,
    page_shift: int,
    physical_address_bits: int,
    virtual_address_bits: int,
    word_bits: int,
    canonical_policy: str,
    valid_pfn_ranges: Sequence[tuple[int, int]],
    arch_pfn_offset: int | None = None,
    pointer_width: int,
    overwrite_offset: int,
    overwrite_width: int,
    byteorder: str,
) -> DescriptorPointerPatch:
    """Prove that one partial pointer write changes source descriptor to target.

    ``overwrite_offset`` is a byte offset in the pointer's in-memory
    representation. Every byte outside the controlled window must already be
    identical; otherwise the proposal is rejected.
    """

    geometry = _memory_geometry(
        memory_model=memory_model,
        descriptor_base=descriptor_base,
        struct_page_size=struct_page_size,
        page_shift=page_shift,
        physical_address_bits=physical_address_bits,
        virtual_address_bits=virtual_address_bits,
        word_bits=word_bits,
        canonical_policy=canonical_policy,
        valid_pfn_ranges=valid_pfn_ranges,
        arch_pfn_offset=arch_pfn_offset,
    )
    source = _map_pfn_validated(source_pfn, geometry)
    target = _map_pfn_validated(target_pfn, geometry)
    width = _positive(pointer_width, "pointer_width", maximum=8)
    if word_bits % 8 or width != word_bits // 8:
        raise PageGeometryError("pointer_width must exactly match word_bits")
    offset = _uint(overwrite_offset, "overwrite_offset", maximum=width - 1)
    controlled = _positive(overwrite_width, "overwrite_width", maximum=width)
    if offset + controlled > width:
        raise PageGeometryError("partial pointer overwrite exceeds pointer_width")
    if byteorder not in ("little", "big"):
        raise PageGeometryError("byteorder must be 'little' or 'big'")
    if source.pfn == target.pfn:
        raise PageGeometryError("source and target descriptors are identical")
    source_bytes = source.descriptor_address.to_bytes(width, byteorder)
    target_bytes = target.descriptor_address.to_bytes(width, byteorder)
    end = offset + controlled
    if (
        source_bytes[:offset] != target_bytes[:offset]
        or source_bytes[end:] != target_bytes[end:]
    ):
        raise PageGeometryError(
            "uncontrolled pointer bytes differ between source and target"
        )
    patch = target_bytes[offset:end]
    reconstructed = source_bytes[:offset] + patch + source_bytes[end:]
    if reconstructed != target_bytes:
        raise PageGeometryError("partial pointer patch does not reconstruct the target")
    return DescriptorPointerPatch(
        source_pfn=source.pfn,
        target_pfn=target.pfn,
        source_pointer=source.descriptor_address,
        target_pointer=target.descriptor_address,
        descriptor_delta=target.pfn - source.pfn,
        pointer_width=width,
        overwrite_offset=offset,
        overwrite_width=controlled,
        byteorder=byteorder,
        source_bytes_hex=source_bytes.hex(),
        target_bytes_hex=target_bytes.hex(),
        patch_hex=patch.hex(),
    )


def _allocation_extent(
    head_pfn: object,
    order: object,
    *,
    name: str,
    maximum_pfn_exclusive: int,
) -> tuple[int, int, int]:
    selected_order = _uint(order, f"{name}_order", maximum=MAX_ORDER)
    pages = 1 << selected_order
    head = _uint(
        head_pfn, f"{name}_head_pfn", maximum=maximum_pfn_exclusive - 1
    )
    if head % pages:
        raise PageGeometryError(
            f"{name}_head_pfn must be aligned to its order-{selected_order} extent"
        )
    if pages > maximum_pfn_exclusive - head:
        raise PageGeometryError(f"{name} extent exceeds physical address width")
    return head, selected_order, pages


def _field_landing(
    *,
    object_index: int,
    replacement_start: int,
    replacement_head_pfn: int,
    replacement_byte_offset: int,
    field_width: int,
    page_shift: int,
    fully_reachable: bool,
) -> ReclaimedFieldLanding:
    page_size = 1 << page_shift
    physical = replacement_start + replacement_byte_offset
    final = physical + field_width - 1
    first_pfn = physical >> page_shift
    last_pfn = final >> page_shift
    return ReclaimedFieldLanding(
        object_index=object_index,
        object_ordinal=object_index + 1,
        replacement_byte_offset=replacement_byte_offset,
        physical_address=physical,
        width=field_width,
        first_pfn=first_pfn,
        last_pfn=last_pfn,
        replacement_first_page_index=first_pfn - replacement_head_pfn,
        replacement_last_page_index=last_pfn - replacement_head_pfn,
        in_page_offset=physical & (page_size - 1),
        fully_reachable=fully_reachable,
    )


@_fail_closed
def plan_page_uaf_landing(
    *,
    page_shift: int,
    physical_address_bits: int,
    released_head_pfn: int,
    released_order: int,
    stale_page_index: int,
    stale_offset: int,
    stale_length: int,
    replacement_head_pfn: int,
    replacement_order: int,
    first_object_offset: int,
    object_stride: int,
    object_size: int,
    objects_per_slab: int,
    field_offset: int,
    field_width: int,
) -> PageUafLanding:
    """Plan exact stale-page overlap with fields in a proposed replacement slab.

    The result proves only address geometry. It never predicts that the buddy
    or slab allocator will actually reuse the released extent.
    """

    shift = _bits(page_shift, "page_shift", minimum=9, maximum=30)
    physical_bits = _bits(
        physical_address_bits,
        "physical_address_bits",
        minimum=shift + 1,
        maximum=64,
    )
    page_size = 1 << shift
    maximum_pfn_exclusive = 1 << (physical_bits - shift)
    released_head, release_order, release_pages = _allocation_extent(
        released_head_pfn,
        released_order,
        name="released",
        maximum_pfn_exclusive=maximum_pfn_exclusive,
    )
    replacement_head, replace_order, replacement_pages = _allocation_extent(
        replacement_head_pfn,
        replacement_order,
        name="replacement",
        maximum_pfn_exclusive=maximum_pfn_exclusive,
    )
    stale_index = _uint(
        stale_page_index, "stale_page_index", maximum=release_pages - 1
    )
    in_page = _uint(stale_offset, "stale_offset", maximum=page_size - 1)
    access_length = _positive(stale_length, "stale_length")
    released_start = released_head << shift
    released_end = (released_head + release_pages) << shift
    replacement_start = replacement_head << shift
    replacement_end = (replacement_head + replacement_pages) << shift
    stale_start = ((released_head + stale_index) << shift) + in_page
    stale_end = _checked_end(
        stale_start, access_length, (1 << physical_bits) - 1, "stale access"
    )
    if stale_end > released_end:
        raise PageGeometryError("stale access extends beyond the released extent")

    extent_start = max(released_start, replacement_start)
    extent_end = min(released_end, replacement_end)
    if extent_start >= extent_end:
        extent_pfn_range: tuple[int, int] | None = None
        extent_relation = "disjoint"
    else:
        extent_pfn_range = (extent_start >> shift, extent_end >> shift)
        if released_start == replacement_start and released_end == replacement_end:
            extent_relation = "exact"
        elif released_start <= replacement_start and replacement_end <= released_end:
            extent_relation = "replacement-within-released"
        elif replacement_start <= released_start and released_end <= replacement_end:
            extent_relation = "released-within-replacement"
        else:
            extent_relation = "partial"

    access_overlap_start = max(stale_start, replacement_start)
    access_overlap_end = min(stale_end, replacement_end)
    if access_overlap_start >= access_overlap_end:
        access_overlap: tuple[int, int] | None = None
        access_relation = "disjoint"
        released_pages_touched: tuple[int, int] | None = None
        replacement_pages_touched: tuple[int, int] | None = None
    else:
        access_overlap = (access_overlap_start, access_overlap_end)
        if access_overlap_start == stale_start and access_overlap_end == stale_end:
            access_relation = "fully-contained-in-replacement"
        else:
            access_relation = "partially-overlaps-replacement"
        first_pfn = access_overlap_start >> shift
        last_pfn = (access_overlap_end - 1) >> shift
        released_pages_touched = (
            first_pfn - released_head,
            last_pfn - released_head + 1,
        )
        replacement_pages_touched = (
            first_pfn - replacement_head,
            last_pfn - replacement_head + 1,
        )

    replacement_bytes = replacement_pages * page_size
    first = _uint(
        first_object_offset, "first_object_offset", maximum=replacement_bytes - 1
    )
    stride = _positive(object_stride, "object_stride", maximum=replacement_bytes)
    size = _positive(object_size, "object_size", maximum=replacement_bytes)
    if size > stride:
        raise PageGeometryError("object_size cannot exceed object_stride")
    count = _positive(
        objects_per_slab, "objects_per_slab", maximum=MAX_SLAB_OBJECTS
    )
    if count > 1 + (replacement_bytes - 1 - first) // stride:
        raise PageGeometryError(
            "objects_per_slab places a slot outside replacement extent"
        )
    last_object_end = first + (count - 1) * stride + size
    if last_object_end > replacement_bytes:
        raise PageGeometryError("last target object does not fit replacement extent")
    target_field = _uint(field_offset, "field_offset", maximum=size - 1)
    target_width = _positive(field_width, "field_width", maximum=size)
    if target_field + target_width > size:
        raise PageGeometryError("target field exceeds object_size")

    reachable: list[ReclaimedFieldLanding] = []
    partial: list[ReclaimedFieldLanding] = []
    for object_index in range(count):
        relative = first + object_index * stride + target_field
        field_start = replacement_start + relative
        field_end = field_start + target_width
        fully = stale_start <= field_start and field_end <= stale_end
        overlaps = max(stale_start, field_start) < min(stale_end, field_end)
        if fully:
            reachable.append(
                _field_landing(
                    object_index=object_index,
                    replacement_start=replacement_start,
                    replacement_head_pfn=replacement_head,
                    replacement_byte_offset=relative,
                    field_width=target_width,
                    page_shift=shift,
                    fully_reachable=True,
                )
            )
        elif overlaps:
            partial.append(
                _field_landing(
                    object_index=object_index,
                    replacement_start=replacement_start,
                    replacement_head_pfn=replacement_head,
                    replacement_byte_offset=relative,
                    field_width=target_width,
                    page_shift=shift,
                    fully_reachable=False,
                )
            )

    return PageUafLanding(
        page_shift=shift,
        page_size=page_size,
        physical_address_bits=physical_bits,
        released_head_pfn=released_head,
        released_order=release_order,
        released_pfn_range=(released_head, released_head + release_pages),
        replacement_head_pfn=replacement_head,
        replacement_order=replace_order,
        replacement_pfn_range=(
            replacement_head,
            replacement_head + replacement_pages,
        ),
        extent_overlap_pfn_range=extent_pfn_range,
        extent_relation=extent_relation,
        stale_page_index=stale_index,
        stale_offset=in_page,
        stale_length=access_length,
        stale_physical_range=(stale_start, stale_end),
        stale_overlap_physical_range=access_overlap,
        access_relation=access_relation,
        released_overlap_page_range=released_pages_touched,
        replacement_overlap_page_range=replacement_pages_touched,
        first_object_offset=first,
        object_stride=stride,
        object_size=size,
        objects_per_slab=count,
        field_offset=target_field,
        field_width=target_width,
        reachable_fields=tuple(reachable),
        partial_fields=tuple(partial),
        prerequisites=(
            "The released and replacement allocations use compatible zone, NUMA node, migratetype, GFP/accounting class, and allocator path.",
            "The released extent actually reaches the page allocator and no intervening allocation consumes it.",
            "The supplied replacement cache order, stride, object count, padding, and field layout match the exact target build.",
        ),
        warnings=(
            "Static interval arithmetic only; this result does not prove allocator reuse, refcount behavior, or exploitability.",
        ),
    )


def _cli_int(text: str) -> int:
    try:
        return int(text, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from exc


def _cli_pair(text: str, label: str) -> tuple[str, int]:
    try:
        name, raw = text.split(":", 1)
        if not name:
            raise ValueError
        return name, int(raw, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(
            f"invalid {label} {text!r}; expected NAME:INTEGER"
        ) from exc


def _cli_level(text: str) -> tuple[str, int]:
    return _cli_pair(text, "level")


def _cli_index(text: str) -> tuple[str, int]:
    return _cli_pair(text, "index")


def _cli_range(text: str) -> tuple[int, int]:
    try:
        start, end = text.split(":", 1)
        return int(start, 0), int(end, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(
            f"invalid PFN range {text!r}; expected START:END"
        ) from exc


def _add_table_geometry(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--level", action="append", required=True, type=_cli_level)
    parser.add_argument("--page-shift", required=True, type=_cli_int)
    parser.add_argument("--va-bits", required=True, type=_cli_int)
    parser.add_argument("--word-bits", required=True, type=_cli_int)
    parser.add_argument("--entry-size", required=True, type=_cli_int)
    parser.add_argument(
        "--canonical-policy",
        required=True,
        choices=("sign-extended", "zero-extended"),
    )


def _add_memory_geometry(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--memory-model", required=True)
    parser.add_argument("--descriptor-base", required=True, type=_cli_int)
    parser.add_argument("--struct-page-size", required=True, type=_cli_int)
    parser.add_argument("--page-shift", required=True, type=_cli_int)
    parser.add_argument("--physical-address-bits", required=True, type=_cli_int)
    parser.add_argument("--virtual-address-bits", required=True, type=_cli_int)
    parser.add_argument("--word-bits", required=True, type=_cli_int)
    parser.add_argument(
        "--canonical-policy",
        required=True,
        choices=("sign-extended", "zero-extended"),
    )
    parser.add_argument(
        "--valid-pfn-range", action="append", required=True, type=_cli_range
    )
    parser.add_argument("--arch-pfn-offset", type=_cli_int)


def _add_direct_geometry(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--physical-base", required=True, type=_cli_int)
    parser.add_argument("--virtual-base", required=True, type=_cli_int)
    parser.add_argument("--length", required=True, type=_cli_int)
    parser.add_argument("--physical-address-bits", required=True, type=_cli_int)
    parser.add_argument("--virtual-address-bits", required=True, type=_cli_int)
    parser.add_argument("--word-bits", required=True, type=_cli_int)
    parser.add_argument(
        "--canonical-policy",
        required=True,
        choices=("sign-extended", "zero-extended"),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline caller-declared Linux page geometry planner"
    )
    commands = parser.add_subparsers(dest="operation", required=True)

    decompose = commands.add_parser("pt-decompose", help="decompose a virtual address")
    decompose.add_argument("address", type=_cli_int)
    _add_table_geometry(decompose)

    compose = commands.add_parser("pt-compose", help="compose a virtual address")
    compose.add_argument("--index", action="append", required=True, type=_cli_index)
    compose.add_argument("--offset", required=True, type=_cli_int)
    _add_table_geometry(compose)

    pfn = commands.add_parser("pfn", help="map PFN to physical/descriptor address")
    pfn.add_argument("value", type=_cli_int)
    _add_memory_geometry(pfn)

    descriptor = commands.add_parser("descriptor", help="map descriptor address to PFN")
    descriptor.add_argument("value", type=_cli_int)
    _add_memory_geometry(descriptor)

    direct_phys = commands.add_parser("direct-phys", help="physical to direct-map VA")
    direct_phys.add_argument("value", type=_cli_int)
    _add_direct_geometry(direct_phys)

    direct_virt = commands.add_parser("direct-virt", help="direct-map VA to physical")
    direct_virt.add_argument("value", type=_cli_int)
    _add_direct_geometry(direct_virt)

    direct_pfn = commands.add_parser("direct-pfn", help="PFN to direct-map VA")
    direct_pfn.add_argument("value", type=_cli_int)
    direct_pfn.add_argument("--page-offset", required=True, type=_cli_int)
    direct_pfn.add_argument("--page-shift", required=True, type=_cli_int)
    _add_direct_geometry(direct_pfn)

    direct_to_pfn = commands.add_parser("direct-to-pfn", help="direct-map VA to PFN")
    direct_to_pfn.add_argument("value", type=_cli_int)
    direct_to_pfn.add_argument("--page-shift", required=True, type=_cli_int)
    _add_direct_geometry(direct_to_pfn)

    patch = commands.add_parser(
        "pointer-patch", help="plan a partial descriptor-pointer write"
    )
    patch.add_argument("source_pfn", type=_cli_int)
    patch.add_argument("target_pfn", type=_cli_int)
    _add_memory_geometry(patch)
    patch.add_argument("--pointer-width", required=True, type=_cli_int)
    patch.add_argument("--overwrite-offset", required=True, type=_cli_int)
    patch.add_argument("--overwrite-width", required=True, type=_cli_int)
    patch.add_argument("--byteorder", required=True, choices=("little", "big"))

    uaf = commands.add_parser(
        "uaf", help="plan stale-page to replacement-slab fields"
    )
    for name in (
        "page-shift",
        "physical-address-bits",
        "released-head-pfn",
        "released-order",
        "stale-page-index",
        "stale-offset",
        "stale-length",
        "replacement-head-pfn",
        "replacement-order",
        "first-object-offset",
        "object-stride",
        "object-size",
        "objects-per-slab",
        "field-offset",
        "field-width",
    ):
        uaf.add_argument(f"--{name}", required=True, type=_cli_int)
    return parser


def _memory_kwargs(args: argparse.Namespace) -> dict[str, object]:
    return {
        "memory_model": args.memory_model,
        "descriptor_base": args.descriptor_base,
        "struct_page_size": args.struct_page_size,
        "page_shift": args.page_shift,
        "physical_address_bits": args.physical_address_bits,
        "virtual_address_bits": args.virtual_address_bits,
        "word_bits": args.word_bits,
        "canonical_policy": args.canonical_policy,
        "valid_pfn_ranges": args.valid_pfn_range,
        "arch_pfn_offset": args.arch_pfn_offset,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guarded, deterministic JSON CLI."""

    try:
        args = _parser().parse_args(argv)
        if args.operation == "pt-decompose":
            result = decompose_page_table(
                args.address,
                levels=args.level,
                page_shift=args.page_shift,
                va_bits=args.va_bits,
                word_bits=args.word_bits,
                entry_size=args.entry_size,
                canonical_policy=args.canonical_policy,
            )
        elif args.operation == "pt-compose":
            indices = dict(args.index)
            if len(indices) != len(args.index):
                raise PageGeometryError("duplicate --index level")
            result = compose_page_table(
                indices,
                offset=args.offset,
                levels=args.level,
                page_shift=args.page_shift,
                va_bits=args.va_bits,
                word_bits=args.word_bits,
                entry_size=args.entry_size,
                canonical_policy=args.canonical_policy,
            )
        elif args.operation == "pfn":
            result = map_pfn(args.value, **_memory_kwargs(args))
        elif args.operation == "descriptor":
            result = map_descriptor(args.value, **_memory_kwargs(args))
        elif args.operation == "direct-phys":
            result = physical_to_direct_map(
                args.value,
                physical_base=args.physical_base,
                virtual_base=args.virtual_base,
                length=args.length,
                physical_address_bits=args.physical_address_bits,
                virtual_address_bits=args.virtual_address_bits,
                word_bits=args.word_bits,
                canonical_policy=args.canonical_policy,
            )
        elif args.operation == "direct-virt":
            result = direct_map_to_physical(
                args.value,
                physical_base=args.physical_base,
                virtual_base=args.virtual_base,
                length=args.length,
                physical_address_bits=args.physical_address_bits,
                virtual_address_bits=args.virtual_address_bits,
                word_bits=args.word_bits,
                canonical_policy=args.canonical_policy,
            )
        elif args.operation == "direct-pfn":
            result = pfn_to_direct_map(
                args.value,
                page_offset=args.page_offset,
                page_shift=args.page_shift,
                physical_base=args.physical_base,
                virtual_base=args.virtual_base,
                length=args.length,
                physical_address_bits=args.physical_address_bits,
                virtual_address_bits=args.virtual_address_bits,
                word_bits=args.word_bits,
                canonical_policy=args.canonical_policy,
            )
        elif args.operation == "direct-to-pfn":
            result = direct_map_to_pfn(
                args.value,
                page_shift=args.page_shift,
                physical_base=args.physical_base,
                virtual_base=args.virtual_base,
                length=args.length,
                physical_address_bits=args.physical_address_bits,
                virtual_address_bits=args.virtual_address_bits,
                word_bits=args.word_bits,
                canonical_policy=args.canonical_policy,
            )
        elif args.operation == "pointer-patch":
            result = plan_descriptor_pointer_patch(
                args.source_pfn,
                args.target_pfn,
                **_memory_kwargs(args),
                pointer_width=args.pointer_width,
                overwrite_offset=args.overwrite_offset,
                overwrite_width=args.overwrite_width,
                byteorder=args.byteorder,
            )
        elif args.operation == "uaf":
            result = plan_page_uaf_landing(
                page_shift=args.page_shift,
                physical_address_bits=args.physical_address_bits,
                released_head_pfn=args.released_head_pfn,
                released_order=args.released_order,
                stale_page_index=args.stale_page_index,
                stale_offset=args.stale_offset,
                stale_length=args.stale_length,
                replacement_head_pfn=args.replacement_head_pfn,
                replacement_order=args.replacement_order,
                first_object_offset=args.first_object_offset,
                object_stride=args.object_stride,
                object_size=args.object_size,
                objects_per_slab=args.objects_per_slab,
                field_offset=args.field_offset,
                field_width=args.field_width,
            )
        else:  # argparse requires a known subcommand.
            raise PageGeometryError("unsupported operation")
        print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except PageGeometryError as exc:
        print(f"wpgap_pagegeo_planner: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("wpgap_pagegeo_planner: malformed input", file=sys.stderr)
        return 2


__all__ = [
    "PageGeometryError",
    "PageTableLevel",
    "PageTableAddress",
    "MemoryModelMapping",
    "DirectMapMapping",
    "PfnDirectMapMapping",
    "DescriptorPointerPatch",
    "ReclaimedFieldLanding",
    "PageUafLanding",
    "decompose_page_table",
    "compose_page_table",
    "map_pfn",
    "map_descriptor",
    "physical_to_direct_map",
    "direct_map_to_physical",
    "pfn_to_direct_map",
    "direct_map_to_pfn",
    "plan_descriptor_pointer_patch",
    "plan_page_uaf_landing",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
