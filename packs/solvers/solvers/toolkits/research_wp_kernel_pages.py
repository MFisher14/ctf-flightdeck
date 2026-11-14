#!/usr/bin/env python3
"""Offline arithmetic for recent Linux page-level kernel exploitation research.

This module performs only caller-parameterized calculations.  It does not read
kernel memory, open devices, execute generated material, or contact a target.
The PageJack and slab results deliberately describe arithmetic feasibility,
never exploitability.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Sequence


U64_MAX = (1 << 64) - 1
X86_PAGE_SHIFT = 12
INDEX_MASK = 0x1FF
MAX_STRUCT_PAGE_SIZE = 1 << 20
MAX_SLAB_BYTES = 1 << 30
MAX_SLAB_OBJECTS = 1 << 20


class ResearchWPKernelError(ValueError):
    """Input cannot be represented by the declared kernel geometry."""


def _uint(value: object, name: str, *, maximum: int = U64_MAX) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResearchWPKernelError(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise ResearchWPKernelError(f"{name} must be in 0..{maximum}")
    return value


def _positive(value: object, name: str, *, maximum: int) -> int:
    result = _uint(value, name, maximum=maximum)
    if result == 0:
        raise ResearchWPKernelError(f"{name} must be positive")
    return result


def _page_size(page_shift: object) -> tuple[int, int]:
    shift = _uint(page_shift, "page_shift", maximum=30)
    if shift < 9:
        raise ResearchWPKernelError("page_shift must be in 9..30")
    return shift, 1 << shift


def _struct_geometry(vmemmap_base: object, struct_page_size: object) -> tuple[int, int]:
    base = _uint(vmemmap_base, "vmemmap_base")
    size = _positive(
        struct_page_size, "struct_page_size", maximum=MAX_STRUCT_PAGE_SIZE
    )
    if base % size:
        raise ResearchWPKernelError(
            "vmemmap_base must be aligned to struct_page_size"
        )
    return base, size


@dataclass(frozen=True)
class X86VADecomposition:
    """One canonical x86-64 virtual address split into page-table indices."""

    address: int
    levels: int
    canonical_bits: int
    pgd: int
    p4d: int
    pud: int
    pmd: int
    pte: int
    offset: int
    p4d_folded: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "address_hex": f"0x{self.address:016x}",
            "canonical": True,
            "canonical_bits": self.canonical_bits,
            "levels": self.levels,
            "offset": self.offset,
            "p4d": self.p4d,
            "p4d_folded": self.p4d_folded,
            "pgd": self.pgd,
            "pmd": self.pmd,
            "pte": self.pte,
            "pud": self.pud,
        }


@dataclass(frozen=True)
class PageDescriptorMapping:
    """Exact mapping among a PFN, its descriptor, and a physical address."""

    pfn: int
    struct_page_address: int
    physical_address: int
    physical_page_base: int
    page_offset: int
    page_shift: int
    page_size: int
    vmemmap_base: int
    struct_page_size: int

    def as_dict(self) -> dict[str, object]:
        return {
            "page_offset": self.page_offset,
            "page_shift": self.page_shift,
            "page_size": self.page_size,
            "pfn": self.pfn,
            "physical_address": self.physical_address,
            "physical_address_hex": f"0x{self.physical_address:x}",
            "physical_page_base": self.physical_page_base,
            "struct_page_address": self.struct_page_address,
            "struct_page_address_hex": f"0x{self.struct_page_address:016x}",
            "struct_page_size": self.struct_page_size,
            "vmemmap_base": self.vmemmap_base,
        }


@dataclass(frozen=True)
class PageJackAssessment:
    """Arithmetic effect of zeroing one low byte of a ``struct page *``."""

    source_struct_page: int
    zeroed_struct_page: int
    low_byte_before: int
    byte_delta: int
    descriptor_delta: int
    source_pfn: int
    target_pfn: int | None
    classification: str
    arithmetically_feasible: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "arithmetically_feasible": self.arithmetically_feasible,
            "byte_delta": self.byte_delta,
            "classification": self.classification,
            "descriptor_delta": self.descriptor_delta,
            "exploitability_verified": False,
            "low_byte_before": self.low_byte_before,
            "note": (
                "descriptor arithmetic only; allocation state, lifetime, and "
                "exploitability are not inferred"
            ),
            "source_pfn": self.source_pfn,
            "source_struct_page": self.source_struct_page,
            "target_pfn": self.target_pfn,
            "zeroed_struct_page": self.zeroed_struct_page,
        }


@dataclass(frozen=True)
class SlabLanding:
    """A bounded modular landing calculation for one OOB write."""

    oob_delta: int
    source_offset: int
    slab_size: int
    slab_pages: int
    first_object_offset: int
    object_size: int
    object_stride: int
    objects_per_slab: int
    write_width: int
    landing_offset: int
    slot_index: int | None
    object_index: int | None
    object_ordinal: int | None
    offset_in_object: int | None
    hits_object: bool
    write_fits_object: bool
    arithmetically_feasible: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "arithmetically_feasible": self.arithmetically_feasible,
            "exploitability_verified": False,
            "first_object_offset": self.first_object_offset,
            "hits_object": self.hits_object,
            "landing_offset": self.landing_offset,
            "object_index": self.object_index,
            "object_ordinal": self.object_ordinal,
            "object_size": self.object_size,
            "object_stride": self.object_stride,
            "objects_per_slab": self.objects_per_slab,
            "offset_in_object": self.offset_in_object,
            "oob_delta": self.oob_delta,
            "slab_pages": self.slab_pages,
            "slab_size": self.slab_size,
            "slot_index": self.slot_index,
            "source_offset": self.source_offset,
            "write_fits_object": self.write_fits_object,
            "write_width": self.write_width,
            "note": (
                "modular slab arithmetic only; adjacency, allocator state, and "
                "exploitability are not inferred"
            ),
        }


def decompose_x86_64_va(address: int, *, levels: int = 4) -> X86VADecomposition:
    """Split a canonical x86-64 address for a 4- or 5-level 4 KiB walk.

    With four levels Linux folds P4D, so ``p4d`` is reported as zero and
    ``p4d_folded`` is true.  Five-level paging uses a real P4D index.
    """

    value = _uint(address, "address")
    depth = _uint(levels, "levels", maximum=5)
    if depth not in (4, 5):
        raise ResearchWPKernelError("levels must be 4 or 5")

    canonical_bits = 48 if depth == 4 else 57
    sign = (value >> (canonical_bits - 1)) & 1
    upper_width = 64 - canonical_bits
    upper = value >> canonical_bits
    expected = (1 << upper_width) - 1 if sign else 0
    if upper != expected:
        raise ResearchWPKernelError(
            f"address is not canonical for {depth}-level x86-64 paging"
        )

    if depth == 4:
        pgd = (value >> 39) & INDEX_MASK
        p4d = 0
    else:
        pgd = (value >> 48) & INDEX_MASK
        p4d = (value >> 39) & INDEX_MASK
    return X86VADecomposition(
        address=value,
        levels=depth,
        canonical_bits=canonical_bits,
        pgd=pgd,
        p4d=p4d,
        pud=(value >> 30) & INDEX_MASK,
        pmd=(value >> 21) & INDEX_MASK,
        pte=(value >> X86_PAGE_SHIFT) & INDEX_MASK,
        offset=value & ((1 << X86_PAGE_SHIFT) - 1),
        p4d_folded=depth == 4,
    )


def page_from_pfn(
    pfn: int,
    *,
    vmemmap_base: int,
    struct_page_size: int,
    page_shift: int = X86_PAGE_SHIFT,
) -> PageDescriptorMapping:
    """Map a PFN to its ``struct page`` and physical page base."""

    number = _uint(pfn, "pfn")
    base, descriptor_size = _struct_geometry(vmemmap_base, struct_page_size)
    shift, page_size = _page_size(page_shift)
    descriptor_delta = number * descriptor_size
    physical_base = number * page_size
    if descriptor_delta > U64_MAX - base:
        raise ResearchWPKernelError("struct page address overflows 64 bits")
    if physical_base > U64_MAX:
        raise ResearchWPKernelError("physical page base overflows 64 bits")
    return PageDescriptorMapping(
        pfn=number,
        struct_page_address=base + descriptor_delta,
        physical_address=physical_base,
        physical_page_base=physical_base,
        page_offset=0,
        page_shift=shift,
        page_size=page_size,
        vmemmap_base=base,
        struct_page_size=descriptor_size,
    )


def page_from_struct_page(
    struct_page_address: int,
    *,
    vmemmap_base: int,
    struct_page_size: int,
    page_shift: int = X86_PAGE_SHIFT,
) -> PageDescriptorMapping:
    """Map an exactly aligned ``struct page *`` back to its PFN."""

    address = _uint(struct_page_address, "struct_page_address")
    base, descriptor_size = _struct_geometry(vmemmap_base, struct_page_size)
    if address < base:
        raise ResearchWPKernelError("struct_page_address is below vmemmap_base")
    delta = address - base
    if delta % descriptor_size:
        raise ResearchWPKernelError(
            "struct_page_address is not aligned to the descriptor array"
        )
    result = page_from_pfn(
        delta // descriptor_size,
        vmemmap_base=base,
        struct_page_size=descriptor_size,
        page_shift=page_shift,
    )
    if result.struct_page_address != address:
        raise ResearchWPKernelError("struct page round-trip is inconsistent")
    return result


def page_from_physical_address(
    physical_address: int,
    *,
    vmemmap_base: int,
    struct_page_size: int,
    page_shift: int = X86_PAGE_SHIFT,
) -> PageDescriptorMapping:
    """Map a physical byte address to its PFN and page descriptor."""

    physical = _uint(physical_address, "physical_address")
    shift, page_size = _page_size(page_shift)
    page_offset = physical & (page_size - 1)
    result = page_from_pfn(
        physical >> shift,
        vmemmap_base=vmemmap_base,
        struct_page_size=struct_page_size,
        page_shift=shift,
    )
    return PageDescriptorMapping(
        pfn=result.pfn,
        struct_page_address=result.struct_page_address,
        physical_address=physical,
        physical_page_base=result.physical_page_base,
        page_offset=page_offset,
        page_shift=result.page_shift,
        page_size=result.page_size,
        vmemmap_base=result.vmemmap_base,
        struct_page_size=result.struct_page_size,
    )


def classify_pagejack_low_byte(
    struct_page_address: int,
    *,
    vmemmap_base: int,
    struct_page_size: int,
) -> PageJackAssessment:
    """Classify zeroing the least-significant byte of a page descriptor pointer.

    Both the source and resulting pointer must land exactly on descriptor
    boundaries.  A redirect is called arithmetically feasible only when it
    moves to a different descriptor at or above the supplied vmemmap base.
    """

    address = _uint(struct_page_address, "struct_page_address")
    base, descriptor_size = _struct_geometry(vmemmap_base, struct_page_size)
    source = page_from_struct_page(
        address,
        vmemmap_base=base,
        struct_page_size=descriptor_size,
    )
    zeroed = address & ~0xFF
    byte_delta = zeroed - address
    if byte_delta % descriptor_size:
        raise ResearchWPKernelError(
            "low-byte zeroing does not land on a struct page boundary"
        )
    descriptor_delta = byte_delta // descriptor_size

    if zeroed == address:
        classification = "unchanged-low-byte-zero"
        target_pfn: int | None = source.pfn
        feasible = False
    elif zeroed < base:
        classification = "below-vmemmap-base"
        target_pfn = None
        feasible = False
    else:
        target = page_from_struct_page(
            zeroed,
            vmemmap_base=base,
            struct_page_size=descriptor_size,
        )
        target_pfn = target.pfn
        classification = "redirects-to-earlier-descriptor"
        feasible = descriptor_delta < 0
    return PageJackAssessment(
        source_struct_page=address,
        zeroed_struct_page=zeroed,
        low_byte_before=address & 0xFF,
        byte_delta=byte_delta,
        descriptor_delta=descriptor_delta,
        source_pfn=source.pfn,
        target_pfn=target_pfn,
        classification=classification,
        arithmetically_feasible=feasible,
    )


def plan_slab_oob_landing(
    *,
    oob_delta: int,
    source_offset: int,
    object_size: int,
    slab_pages: int = 1,
    page_shift: int = X86_PAGE_SHIFT,
    write_width: int = 1,
    first_object_offset: int = 0,
    object_stride: int | None = None,
    objects_per_slab: int | None = None,
) -> SlabLanding:
    """Calculate where a fixed-distance OOB write lands in a periodic slab.

    ``source_offset`` is the attacking object's offset in the target slab's
    alignment period.  Optional stride/count inputs allow caller-confirmed
    redzones or unused slab tails; no allocator layout is guessed.
    """

    delta = _positive(oob_delta, "oob_delta", maximum=U64_MAX)
    shift, page_size = _page_size(page_shift)
    pages = _positive(slab_pages, "slab_pages", maximum=MAX_SLAB_BYTES)
    if pages > MAX_SLAB_BYTES // page_size:
        raise ResearchWPKernelError("slab size exceeds the bounded 1 GiB limit")
    slab_size = pages * page_size
    source = _uint(source_offset, "source_offset", maximum=slab_size - 1)
    first = _uint(first_object_offset, "first_object_offset", maximum=slab_size - 1)
    size = _positive(object_size, "object_size", maximum=slab_size)
    stride = size if object_stride is None else _positive(
        object_stride, "object_stride", maximum=slab_size
    )
    if stride < size:
        raise ResearchWPKernelError("object_stride cannot be smaller than object_size")
    available = slab_size - first
    if available < size:
        raise ResearchWPKernelError("no complete object slot fits in the slab")
    capacity = 1 + (available - size) // stride
    if capacity > MAX_SLAB_OBJECTS:
        raise ResearchWPKernelError("slab object capacity exceeds the bounded limit")
    if objects_per_slab is None:
        count = capacity
    else:
        count = _positive(
            objects_per_slab, "objects_per_slab", maximum=MAX_SLAB_OBJECTS
        )
        if count > capacity:
            raise ResearchWPKernelError("objects_per_slab exceeds geometric capacity")
    width = _positive(write_width, "write_width", maximum=slab_size)
    if delta > U64_MAX - source:
        raise ResearchWPKernelError("source_offset plus oob_delta overflows 64 bits")

    landing = (source + delta) % slab_size
    relative = landing - first
    slot_index: int | None = None
    object_index: int | None = None
    ordinal: int | None = None
    offset_in_object: int | None = None
    hits = False
    fits = False
    if relative >= 0:
        candidate_index, slot_offset = divmod(relative, stride)
        if candidate_index < count:
            slot_index = candidate_index
            if slot_offset < size:
                hits = True
                object_index = candidate_index
                ordinal = candidate_index + 1
                offset_in_object = slot_offset
                fits = slot_offset + width <= size
    return SlabLanding(
        oob_delta=delta,
        source_offset=source,
        slab_size=slab_size,
        slab_pages=pages,
        first_object_offset=first,
        object_size=size,
        object_stride=stride,
        objects_per_slab=count,
        write_width=width,
        landing_offset=landing,
        slot_index=slot_index,
        object_index=object_index,
        object_ordinal=ordinal,
        offset_in_object=offset_in_object,
        hits_object=hits,
        write_fits_object=fits,
        arithmetically_feasible=hits and fits,
    )


def _cli_int(text: str) -> int:
    try:
        return int(text, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {text!r}") from exc


def _add_page_geometry(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--vmemmap-base", required=True, type=_cli_int)
    parser.add_argument("--struct-page-size", required=True, type=_cli_int)
    parser.add_argument("--page-shift", type=_cli_int, default=X86_PAGE_SHIFT)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline Linux page/slab arithmetic research helper"
    )
    commands = parser.add_subparsers(dest="operation", required=True)

    va = commands.add_parser("va", help="decompose a canonical x86-64 VA")
    va.add_argument("address", type=_cli_int)
    va.add_argument("--levels", type=_cli_int, choices=(4, 5), default=4)

    pfn = commands.add_parser("pfn", help="map PFN to struct page")
    pfn.add_argument("value", type=_cli_int)
    _add_page_geometry(pfn)

    descriptor = commands.add_parser("struct-page", help="map struct page to PFN")
    descriptor.add_argument("value", type=_cli_int)
    _add_page_geometry(descriptor)

    physical = commands.add_parser("physical", help="map physical address to struct page")
    physical.add_argument("value", type=_cli_int)
    _add_page_geometry(physical)

    pagejack = commands.add_parser("pagejack", help="classify low-byte pointer zeroing")
    pagejack.add_argument("value", type=_cli_int)
    pagejack.add_argument("--vmemmap-base", required=True, type=_cli_int)
    pagejack.add_argument("--struct-page-size", required=True, type=_cli_int)

    slab = commands.add_parser("slab", help="calculate an OOB slab landing")
    slab.add_argument("--oob-delta", required=True, type=_cli_int)
    slab.add_argument("--source-offset", required=True, type=_cli_int)
    slab.add_argument("--object-size", required=True, type=_cli_int)
    slab.add_argument("--slab-pages", type=_cli_int, default=1)
    slab.add_argument("--page-shift", type=_cli_int, default=X86_PAGE_SHIFT)
    slab.add_argument("--write-width", type=_cli_int, default=1)
    slab.add_argument("--first-object-offset", type=_cli_int, default=0)
    slab.add_argument("--object-stride", type=_cli_int)
    slab.add_argument("--objects-per-slab", type=_cli_int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guarded, offline JSON CLI."""

    try:
        args = _parser().parse_args(argv)
        if args.operation == "va":
            result = decompose_x86_64_va(args.address, levels=args.levels)
        elif args.operation == "pfn":
            result = page_from_pfn(
                args.value,
                vmemmap_base=args.vmemmap_base,
                struct_page_size=args.struct_page_size,
                page_shift=args.page_shift,
            )
        elif args.operation == "struct-page":
            result = page_from_struct_page(
                args.value,
                vmemmap_base=args.vmemmap_base,
                struct_page_size=args.struct_page_size,
                page_shift=args.page_shift,
            )
        elif args.operation == "physical":
            result = page_from_physical_address(
                args.value,
                vmemmap_base=args.vmemmap_base,
                struct_page_size=args.struct_page_size,
                page_shift=args.page_shift,
            )
        elif args.operation == "pagejack":
            result = classify_pagejack_low_byte(
                args.value,
                vmemmap_base=args.vmemmap_base,
                struct_page_size=args.struct_page_size,
            )
        elif args.operation == "slab":
            result = plan_slab_oob_landing(
                oob_delta=args.oob_delta,
                source_offset=args.source_offset,
                object_size=args.object_size,
                slab_pages=args.slab_pages,
                page_shift=args.page_shift,
                write_width=args.write_width,
                first_object_offset=args.first_object_offset,
                object_stride=args.object_stride,
                objects_per_slab=args.objects_per_slab,
            )
        else:  # argparse's required subparser makes this unreachable.
            raise ResearchWPKernelError("unsupported operation")
        print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (
        ResearchWPKernelError,
        OSError,
        UnicodeError,
        TypeError,
        OverflowError,
        MemoryError,
    ) as exc:
        print(f"research_wp_kernel_pages: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "ResearchWPKernelError",
    "X86VADecomposition",
    "PageDescriptorMapping",
    "PageJackAssessment",
    "SlabLanding",
    "decompose_x86_64_va",
    "page_from_pfn",
    "page_from_struct_page",
    "page_from_physical_address",
    "classify_pagejack_low_byte",
    "plan_slab_oob_landing",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
