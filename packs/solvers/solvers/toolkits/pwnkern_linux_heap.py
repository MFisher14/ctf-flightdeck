"""Offline planners for modern Linux kernel heap exploitation primitives.

This module serializes caller-supplied structure values and produces bounded,
deterministic plans.  It never opens a device, invokes a syscall against a
target, executes generated data, or accesses a network.  Kernel allocator
state is inherently runtime- and build-dependent, so planning results carry
explicit uncertainty warnings and never claim that page reuse will occur.

The structure profiles are deliberately named.  Their offsets describe the
common 64-bit little-endian Linux layouts documented by the upstream kernel;
callers must confirm them against the challenge's exact ``vmlinux``/BTF.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from functools import wraps
import json
import struct
import sys
from typing import Any, Callable, Sequence, TypeVar, cast


U64_MAX = (1 << 64) - 1
MAX_MESSAGE_LENGTH = 64 << 20
MAX_SEGMENTS = 1 << 15
MAX_SLAB_BYTES = 1 << 30
MAX_PLAN_OBJECTS = 1 << 31
MAX_USMA_BLOCKS = 1 << 16
MAX_USMA_MAPPING = 1 << 30

MSG_MSG_PROFILE = "linux-x86_64-msg_msg-common-v1"
MSG_MSGSEG_PROFILE = "linux-x86_64-msg_msgseg-common-v1"
SLUB_PROFILE = "linux-slub-arithmetic-plan-v1"
DIRTYCRED_PROFILE = "dirtycred-object-swap-plan-v1"
USMA_PROFILE = "linux-x86_64-af_packet-pg_vec-common-v1"

MSG_MSG_HEADER_SIZE = 48
MSG_MSGSEG_HEADER_SIZE = 8


class PwnkernLinuxError(ValueError):
    """A Linux kernel primitive request is malformed or not representable."""


_F = TypeVar("_F", bound=Callable[..., Any])


def _fail_closed(function: _F) -> _F:
    """Normalize every public builder failure to :class:`PwnkernLinuxError`."""

    @wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except PwnkernLinuxError:
            raise
        except Exception as exc:
            raise PwnkernLinuxError(
                f"{function.__name__} received malformed input"
            ) from exc

    return cast(_F, guarded)


@dataclass(frozen=True)
class FieldPlacement:
    """One serialized field in an inert structure image."""

    name: str
    offset: int
    width: int

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "offset": self.offset, "width": self.width}


@dataclass(frozen=True)
class SerializedObject:
    """A JSON-safe representation of inert bytes and their field offsets."""

    profile: str
    payload_hex: str
    placements: tuple[FieldPlacement, ...]
    warnings: tuple[str, ...] = ()

    @property
    def payload(self) -> bytes:
        return bytes.fromhex(self.payload_hex)

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "payload_hex": self.payload_hex,
            "length": len(self.payload_hex) // 2,
            "placements": [item.as_dict() for item in self.placements],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class AllocationSpan:
    """One separately allocated ``msg_msg`` or ``msg_msgseg`` object."""

    kind: str
    index: int
    payload_offset: int
    payload_length: int
    header_size: int
    allocation_size: int

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "index": self.index,
            "payload_offset": self.payload_offset,
            "payload_length": self.payload_length,
            "header_size": self.header_size,
            "allocation_size": self.allocation_size,
        }


@dataclass(frozen=True)
class MessageAllocationPlan:
    """Page-split allocation arithmetic for a SysV message payload."""

    profile: str
    message_length: int
    page_size: int
    first_capacity: int
    segment_capacity: int
    spans: tuple[AllocationSpan, ...]
    total_allocation_bytes: int
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "message_length": self.message_length,
            "page_size": self.page_size,
            "first_capacity": self.first_capacity,
            "segment_capacity": self.segment_capacity,
            "spans": [span.as_dict() for span in self.spans],
            "total_allocation_bytes": self.total_allocation_bytes,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class PlanPhase:
    """A descriptive phase with a bounded arithmetic object count."""

    index: int
    name: str
    operation: str
    object_count: int
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "name": self.name,
            "operation": self.operation,
            "object_count": self.object_count,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CrossCachePlan:
    """Arithmetic-only SLUB-to-buddy-to-SLUB page-reuse plan."""

    profile: str
    allocator_profile: str
    slab_bytes: int
    source_object_size: int
    target_object_size: int
    source_objects_per_slab: int
    target_objects_per_slab: int
    source_count_is_estimate: bool
    target_count_is_estimate: bool
    phases: tuple[PlanPhase, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "allocator_profile": self.allocator_profile,
            "slab_bytes": self.slab_bytes,
            "source_object_size": self.source_object_size,
            "target_object_size": self.target_object_size,
            "source_objects_per_slab": self.source_objects_per_slab,
            "target_objects_per_slab": self.target_objects_per_slab,
            "source_count_is_estimate": self.source_count_is_estimate,
            "target_count_is_estimate": self.target_count_is_estimate,
            "phases": [phase.as_dict() for phase in self.phases],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class TimelinePhase:
    """One data-only DirtyCred planning step."""

    index: int
    name: str
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"index": self.index, "name": self.name, "detail": self.detail}


@dataclass(frozen=True)
class DirtyCredPlan:
    """A non-executing credential/file-object swap timeline."""

    profile: str
    variant: str
    blocking_mechanism: str
    free_primitive: str
    phases: tuple[TimelinePhase, ...]
    prerequisites: tuple[str, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "variant": self.variant,
            "blocking_mechanism": self.blocking_mechanism,
            "free_primitive": self.free_primitive,
            "phases": [phase.as_dict() for phase in self.phases],
            "prerequisites": list(self.prerequisites),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class UsmaPgVecPlan:
    """Inert AF_PACKET ``pg_vec`` pointer vector and coverage calculation."""

    profile: str
    payload_hex: str
    pointers: tuple[int, ...]
    block_count: int
    block_size: int
    page_size: int
    pages_per_block: int
    mapping_pages: int
    mapping_length: int
    access_path: str
    prerequisites: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def payload(self) -> bytes:
        return bytes.fromhex(self.payload_hex)

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile,
            "payload_hex": self.payload_hex,
            "length": len(self.payload_hex) // 2,
            "pointers": list(self.pointers),
            "block_count": self.block_count,
            "block_size": self.block_size,
            "page_size": self.page_size,
            "pages_per_block": self.pages_per_block,
            "mapping_pages": self.mapping_pages,
            "mapping_length": self.mapping_length,
            "access_path": self.access_path,
            "prerequisites": list(self.prerequisites),
            "warnings": list(self.warnings),
        }


def _uint(value: object, name: str, *, maximum: int = U64_MAX) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PwnkernLinuxError(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise PwnkernLinuxError(f"{name} must be in 0..{maximum}")
    return value


def _positive(value: object, name: str, *, maximum: int) -> int:
    result = _uint(value, name, maximum=maximum)
    if result == 0:
        raise PwnkernLinuxError(f"{name} must be positive")
    return result


def _power_of_two(value: object, name: str, *, minimum: int, maximum: int) -> int:
    result = _positive(value, name, maximum=maximum)
    if result < minimum or result & (result - 1):
        raise PwnkernLinuxError(
            f"{name} must be a power of two in {minimum}..{maximum}"
        )
    return result


def _canonical_x86_64(value: object, name: str, *, allow_zero: bool = False) -> int:
    result = _uint(value, name)
    if result == 0 and allow_zero:
        return result
    high = result >> 48
    if result == 0 or high not in (0, 0xFFFF):
        raise PwnkernLinuxError(f"{name} must be a non-zero canonical x86-64 address")
    return result


def _bounded_bytes(value: object, name: str, *, maximum: int) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise PwnkernLinuxError(f"{name} must be bytes-like")
    result = bytes(value)
    if len(result) > maximum:
        raise PwnkernLinuxError(f"{name} exceeds {maximum} bytes")
    return result


def _choice(value: object, name: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise PwnkernLinuxError(f"{name} must be one of: {', '.join(choices)}")
    return value


@_fail_closed
def serialize_msg_msg(
    *,
    m_list_next: int,
    m_list_prev: int,
    m_type: int,
    m_ts: int,
    next_segment: int,
    security: int,
    text: bytes = b"",
) -> SerializedObject:
    """Serialize the common x86-64 48-byte ``struct msg_msg`` header.

    ``text`` is the controlled data immediately following the header in the
    first allocation.  ``m_ts`` is intentionally independent from its length
    so fake-object plans can model corrupted sizes.
    """

    values = (
        _canonical_x86_64(m_list_next, "m_list_next", allow_zero=True),
        _canonical_x86_64(m_list_prev, "m_list_prev", allow_zero=True),
        _uint(m_type, "m_type"),
        _uint(m_ts, "m_ts"),
        _canonical_x86_64(next_segment, "next_segment", allow_zero=True),
        _canonical_x86_64(security, "security", allow_zero=True),
    )
    controlled = _bounded_bytes(text, "text", maximum=MAX_MESSAGE_LENGTH)
    header = struct.pack("<6Q", *values)
    placements = (
        FieldPlacement("m_list.next", 0x00, 8),
        FieldPlacement("m_list.prev", 0x08, 8),
        FieldPlacement("m_type", 0x10, 8),
        FieldPlacement("m_ts", 0x18, 8),
        FieldPlacement("next", 0x20, 8),
        FieldPlacement("security", 0x28, 8),
        FieldPlacement("text", MSG_MSG_HEADER_SIZE, len(controlled)),
    )
    return SerializedObject(
        profile=MSG_MSG_PROFILE,
        payload_hex=(header + controlled).hex(),
        placements=placements,
        warnings=(
            "Common x86-64 profile only; confirm offsets and allocator family against target BTF/vmlinux.",
        ),
    )


@_fail_closed
def serialize_msg_msgseg(*, next_segment: int, text: bytes = b"") -> SerializedObject:
    """Serialize the common x86-64 8-byte ``struct msg_msgseg`` header."""

    pointer = _canonical_x86_64(next_segment, "next_segment", allow_zero=True)
    controlled = _bounded_bytes(text, "text", maximum=MAX_MESSAGE_LENGTH)
    payload = struct.pack("<Q", pointer) + controlled
    return SerializedObject(
        profile=MSG_MSGSEG_PROFILE,
        payload_hex=payload.hex(),
        placements=(
            FieldPlacement("next", 0, 8),
            FieldPlacement("text", MSG_MSGSEG_HEADER_SIZE, len(controlled)),
        ),
        warnings=(
            "Common x86-64 profile only; confirm the segment header against the target kernel.",
        ),
    )


@_fail_closed
def plan_msg_allocations(
    message_length: int,
    *,
    page_size: int = 4096,
) -> MessageAllocationPlan:
    """Calculate upstream ``msg_msg`` first-object and segment spans.

    The model follows ``DATALEN_MSG = PAGE_SIZE - sizeof(msg_msg)`` and
    ``DATALEN_SEG = PAGE_SIZE - sizeof(msg_msgseg)``.  It describes requested
    allocation sizes, not the final SLUB bucket chosen by a particular build.
    """

    length = _uint(message_length, "message_length", maximum=MAX_MESSAGE_LENGTH)
    page = _power_of_two(page_size, "page_size", minimum=512, maximum=1 << 20)
    if page <= MSG_MSG_HEADER_SIZE:
        raise PwnkernLinuxError("page_size is too small for the msg_msg header")
    first_capacity = page - MSG_MSG_HEADER_SIZE
    segment_capacity = page - MSG_MSGSEG_HEADER_SIZE
    first_length = min(length, first_capacity)
    spans = [
        AllocationSpan(
            kind="msg_msg",
            index=0,
            payload_offset=0,
            payload_length=first_length,
            header_size=MSG_MSG_HEADER_SIZE,
            allocation_size=MSG_MSG_HEADER_SIZE + first_length,
        )
    ]
    consumed = first_length
    index = 0
    while consumed < length:
        index += 1
        if index > MAX_SEGMENTS:
            raise PwnkernLinuxError("message requires too many msg_msgseg allocations")
        chunk = min(length - consumed, segment_capacity)
        spans.append(
            AllocationSpan(
                kind="msg_msgseg",
                index=index,
                payload_offset=consumed,
                payload_length=chunk,
                header_size=MSG_MSGSEG_HEADER_SIZE,
                allocation_size=MSG_MSGSEG_HEADER_SIZE + chunk,
            )
        )
        consumed += chunk
    total = sum(span.allocation_size for span in spans)
    return MessageAllocationPlan(
        profile=MSG_MSG_PROFILE,
        message_length=length,
        page_size=page,
        first_capacity=first_capacity,
        segment_capacity=segment_capacity,
        spans=tuple(spans),
        total_allocation_bytes=total,
        warnings=(
            "Allocation sizes do not prove a kmalloc bucket or physical placement.",
            "Recent kernels may use dedicated/typed msg_msg buckets rather than historical generic kmalloc-cg caches.",
        ),
    )


def _objects_per_slab(
    *,
    object_size: int,
    slab_bytes: int,
    alignment: int,
    exact: int | None,
    name: str,
) -> tuple[int, bool]:
    aligned = (object_size + alignment - 1) & -alignment
    capacity = slab_bytes // aligned
    if capacity < 1:
        raise PwnkernLinuxError(f"{name} cannot be derived: object exceeds slab")
    if exact is not None:
        count = _positive(exact, name, maximum=MAX_PLAN_OBJECTS)
        if count > capacity:
            raise PwnkernLinuxError(
                f"{name} exceeds the size/alignment capacity of this slab"
            )
        return count, False
    return capacity, True


@_fail_closed
def plan_cross_cache(
    *,
    source_object_size: int,
    target_object_size: int,
    page_size: int = 4096,
    slab_order: int = 0,
    object_alignment: int = 8,
    source_objects_per_slab: int | None = None,
    target_objects_per_slab: int | None = None,
    per_cpu_partial_slabs: int = 0,
    release_slabs: int = 1,
    reclaim_slabs: int = 1,
    safety_slabs: int = 2,
    allocator_profile: str = "slub-generic",
) -> CrossCachePlan:
    """Produce bounded phase/count arithmetic for a cross-cache attempt.

    Derived objects-per-slab counts are only size/alignment upper estimates.
    Supply exact values observed for the target cache whenever possible.
    """

    source_size = _positive(
        source_object_size, "source_object_size", maximum=MAX_SLAB_BYTES
    )
    target_size = _positive(
        target_object_size, "target_object_size", maximum=MAX_SLAB_BYTES
    )
    page = _power_of_two(page_size, "page_size", minimum=512, maximum=1 << 20)
    order = _uint(slab_order, "slab_order", maximum=18)
    alignment = _power_of_two(
        object_alignment, "object_alignment", minimum=1, maximum=page
    )
    partial = _uint(
        per_cpu_partial_slabs, "per_cpu_partial_slabs", maximum=1 << 16
    )
    release = _positive(release_slabs, "release_slabs", maximum=1 << 16)
    reclaim = _positive(reclaim_slabs, "reclaim_slabs", maximum=1 << 16)
    safety = _uint(safety_slabs, "safety_slabs", maximum=1 << 16)
    profile = _choice(
        allocator_profile,
        "allocator_profile",
        ("slub-generic", "slub-dedicated", "slub-typed"),
    )
    slab_bytes = page << order
    if slab_bytes > MAX_SLAB_BYTES:
        raise PwnkernLinuxError("page_size << slab_order exceeds the plan bound")
    source_per, source_estimate = _objects_per_slab(
        object_size=source_size,
        slab_bytes=slab_bytes,
        alignment=alignment,
        exact=source_objects_per_slab,
        name="source_objects_per_slab",
    )
    target_per, target_estimate = _objects_per_slab(
        object_size=target_size,
        slab_bytes=slab_bytes,
        alignment=alignment,
        exact=target_objects_per_slab,
        name="target_objects_per_slab",
    )
    counts = {
        "drain": source_per * (partial + safety),
        "populate": source_per * (release + safety),
        "release": source_per * release,
        "reclaim": target_per * reclaim,
    }
    if any(value > MAX_PLAN_OBJECTS for value in counts.values()):
        raise PwnkernLinuxError("derived phase count exceeds the bounded plan limit")
    phases = (
        PlanPhase(
            1,
            "drain-source-freelists",
            "allocate-source",
            counts["drain"],
            "Arithmetic budget for per-CPU partial slabs plus caller safety slabs.",
        ),
        PlanPhase(
            2,
            "populate-source-slabs",
            "allocate-source",
            counts["populate"],
            "Track every handle so chosen complete slabs can later be freed as units.",
        ),
        PlanPhase(
            3,
            "place-and-trigger-victim",
            "retain-source-victim",
            1,
            "Keep the vulnerable object in a selected source slab; trigger details are challenge-specific.",
        ),
        PlanPhase(
            4,
            "return-source-pages-to-buddy",
            "free-selected-source",
            counts["release"],
            "Free all tracked objects in selected complete slabs; partial objects prevent page release.",
        ),
        PlanPhase(
            5,
            "reclaim-with-target-cache",
            "allocate-target",
            counts["reclaim"],
            "Target allocations request pages from the buddy allocator; reuse is not guaranteed.",
        ),
    )
    warnings = [
        "This is arithmetic, not an allocator simulation; it cannot guarantee page reuse or exploit reliability.",
        "CPU partial lists, NUMA node, slab order, debug options, fragmentation, RCU, and concurrent activity can change every count.",
        "Confirm cache order and objects-per-slab from the exact kernel (for example, slabinfo/BTF/debugger evidence).",
    ]
    if source_estimate or target_estimate:
        warnings.append(
            "At least one objects-per-slab value is an alignment-only estimate that ignores SLUB metadata and redzones."
        )
    if profile != "slub-generic":
        warnings.append(
            "Dedicated/typed cache isolation prevents same-cache replacement; this plan relies on a complete page returning through the buddy allocator."
        )
    if reclaim < release:
        warnings.append(
            "reclaim_slabs is smaller than release_slabs, so the target spray does not cover every planned released page."
        )
    return CrossCachePlan(
        profile=SLUB_PROFILE,
        allocator_profile=profile,
        slab_bytes=slab_bytes,
        source_object_size=source_size,
        target_object_size=target_size,
        source_objects_per_slab=source_per,
        target_objects_per_slab=target_per,
        source_count_is_estimate=source_estimate,
        target_count_is_estimate=target_estimate,
        phases=phases,
        warnings=tuple(warnings),
    )


@_fail_closed
def plan_dirtycred(
    *,
    variant: str,
    blocking_mechanism: str,
    free_primitive: str,
) -> DirtyCredPlan:
    """Describe a DirtyCred file- or cred-object swap without performing it."""

    selected_variant = _choice(variant, "variant", ("file", "cred"))
    blocker = _choice(
        blocking_mechanism,
        "blocking_mechanism",
        ("userfaultfd", "fuse", "filesystem-lock"),
    )
    primitive = _choice(
        free_primitive,
        "free_primitive",
        ("arbitrary-free", "double-free", "uaf-free"),
    )
    blocker_requirements = {
        "userfaultfd": (
            "Kernel-fault interception is permitted via CAP_SYS_PTRACE, vm.unprivileged_userfaultfd=1, or an accessible /dev/userfaultfd.",
            "A copy_to/from_user fault occurs after the relevant check and before the sensitive use.",
        ),
        "fuse": (
            "FUSE mounting and a controllable faulting mapping are available in the challenge namespace.",
            "The FUSE request blocks after the relevant check and can be released deterministically.",
        ),
        "filesystem-lock": (
            "A reachable filesystem lock or slow path exists strictly between the permission check and object use.",
        ),
    }[blocker]
    if selected_variant == "file":
        phases = (
            TimelinePhase(1, "allocate-low-privilege-file", "Open and retain the file object whose access mode passes the intended write path."),
            TimelinePhase(2, "pass-check-and-block", "Enter the operation, pass permission/f_mode checks, then block before the content write uses the file object."),
            TimelinePhase(3, "invalidate-checked-object", f"Use the caller-confirmed {primitive} capability to free the checked struct file while the operation is blocked."),
            TimelinePhase(4, "reclaim-with-target-file", "Actively allocate the privileged/read-only target file object in the same slot and confirm all required fields remain valid."),
            TimelinePhase(5, "resume-stale-operation", "Release the blocker so the already-authorized operation consumes the reclaimed file object."),
            TimelinePhase(6, "stabilize", "Close surviving references and restore collateral metadata required for a clean challenge solve."),
        )
        variant_requirements = (
            "The vulnerable object and struct file can reach the same cache slot, directly or through cross-cache page reuse.",
            "A privileged/read-only target file object can be allocated actively during the blocked window.",
        )
    else:
        phases = (
            TimelinePhase(1, "allocate-low-privilege-cred", "Create and retain the unprivileged credential object and a stale reference path that will later consume it."),
            TimelinePhase(2, "block-before-credential-use", "Pause a credential-consuming path after its relevant setup but before the stale object is used."),
            TimelinePhase(3, "invalidate-low-privilege-cred", f"Use the caller-confirmed {primitive} capability to free the low-privilege struct cred."),
            TimelinePhase(4, "reclaim-with-privileged-cred", "Trigger an active privileged credential allocation in the same cache slot without corrupting reference metadata."),
            TimelinePhase(5, "resume-stale-reference", "Release the blocker so the retained reference resolves to the privileged replacement."),
            TimelinePhase(6, "stabilize", "Repair reference-count/lifetime side effects required by the exact target."),
        )
        variant_requirements = (
            "Low- and high-privilege cred objects share a reclaimable allocation domain on the target kernel.",
            "A privileged cred allocation can be induced during the controlled window.",
        )
    prerequisites = (
        *blocker_requirements,
        *variant_requirements,
        "The exact free site, reference lifetime, cache profile, and LSM/security fields are confirmed from the target build.",
    )
    return DirtyCredPlan(
        profile=DIRTYCRED_PROFILE,
        variant=selected_variant,
        blocking_mechanism=blocker,
        free_primitive=primitive,
        phases=phases,
        prerequisites=prerequisites,
        warnings=(
            "Timeline only: it does not trigger a vulnerability, race a kernel, or prove that an object swap is possible.",
            "Modern typed/dedicated caches, reference hardening, LSM state, and disabled userfaultfd/FUSE can invalidate this route.",
        ),
    )


@_fail_closed
def build_usma_pg_vec(
    pointers: Sequence[int],
    *,
    block_count: int,
    block_size: int,
    mapping_length: int,
    page_size: int = 4096,
    access_path: str = "user-and-network-namespaces",
) -> UsmaPgVecPlan:
    """Build an inert x86-64 AF_PACKET ``struct pgv`` pointer array.

    ``packet_mmap`` maps ``block_count * block_size`` bytes by walking each
    vector pointer a page at a time.  The requested VMA length must match that
    coverage exactly.  Pointers may repeat (a common way to keep every entry
    valid), but each must be canonical and page-aligned.
    """

    if isinstance(pointers, (str, bytes, bytearray, memoryview)) or not isinstance(
        pointers, Sequence
    ):
        raise PwnkernLinuxError("pointers must be a finite sequence of integers")
    count = _positive(block_count, "block_count", maximum=MAX_USMA_BLOCKS)
    if len(pointers) != count:
        raise PwnkernLinuxError("pointer count must equal block_count exactly")
    page = _power_of_two(page_size, "page_size", minimum=512, maximum=1 << 20)
    block = _positive(block_size, "block_size", maximum=MAX_USMA_MAPPING)
    if block % page:
        raise PwnkernLinuxError("block_size must be an exact multiple of page_size")
    requested_mapping = _positive(
        mapping_length, "mapping_length", maximum=MAX_USMA_MAPPING
    )
    expected_mapping = count * block
    if expected_mapping > MAX_USMA_MAPPING:
        raise PwnkernLinuxError("block_count * block_size exceeds the mapping bound")
    if requested_mapping != expected_mapping:
        raise PwnkernLinuxError(
            "mapping_length must equal block_count * block_size for exact coverage"
        )
    selected_access = _choice(
        access_path,
        "access_path",
        ("user-and-network-namespaces", "existing-cap-net-raw", "unknown"),
    )
    normalized: list[int] = []
    for index, raw in enumerate(pointers):
        pointer = _canonical_x86_64(raw, f"pointers[{index}]")
        if pointer % page:
            raise PwnkernLinuxError(f"pointers[{index}] must be page-aligned")
        final_page = pointer + block - page
        if final_page > U64_MAX:
            raise PwnkernLinuxError(f"pointers[{index}] block coverage overflows u64")
        _canonical_x86_64(final_page, f"pointers[{index}] final page")
        normalized.append(pointer)
    payload = b"".join(struct.pack("<Q", pointer) for pointer in normalized)
    access_requirements = {
        "user-and-network-namespaces": (
            "CONFIG_USER_NS and network namespaces are enabled and unprivileged creation is allowed.",
            "The new user/network namespace grants the process CAP_NET_RAW for its AF_PACKET socket.",
        ),
        "existing-cap-net-raw": (
            "The process already has CAP_NET_RAW in the user namespace governing the target network namespace.",
        ),
        "unknown": (
            "Determine whether AF_PACKET socket creation is reachable through namespaces or an existing CAP_NET_RAW grant.",
        ),
    }[selected_access]
    warnings = [
        "The vector is inert and does not prove that packet_mmap will accept or map any selected physical page.",
        "Confirm struct pgv, packet ring fields, page validation, cache placement, and vm_insert_page behavior in the exact kernel.",
        "Every page covered by every block must remain valid; one insertion error aborts the mapping path.",
    ]
    if selected_access == "unknown":
        warnings.append(
            "Namespace/capability access is unresolved; hardened kernelCTF-style targets commonly disable CONFIG_USER_NS."
        )
    return UsmaPgVecPlan(
        profile=USMA_PROFILE,
        payload_hex=payload.hex(),
        pointers=tuple(normalized),
        block_count=count,
        block_size=block,
        page_size=page,
        pages_per_block=block // page,
        mapping_pages=expected_mapping // page,
        mapping_length=expected_mapping,
        access_path=selected_access,
        prerequisites=(
            *access_requirements,
            "A memory-corruption primitive can replace every traversed pg_vec entry with the serialized vector.",
            "All selected addresses resolve through pgv_to_page and are permitted by the target's vm_insert_page checks.",
        ),
        warnings=tuple(warnings),
    )


def _cli_int(value: str) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc


def _cli_hex(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("value must be even-length hexadecimal") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwnkern_linux_heap",
        description="Offline Linux kernel heap primitive layout and plan generator",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    msg = commands.add_parser("msg-layout", help="serialize a common x86-64 msg_msg")
    msg.add_argument("--m-list-next", type=_cli_int, default=0)
    msg.add_argument("--m-list-prev", type=_cli_int, default=0)
    msg.add_argument("--m-type", type=_cli_int, default=1)
    msg.add_argument("--m-ts", type=_cli_int, required=True)
    msg.add_argument("--next-segment", type=_cli_int, default=0)
    msg.add_argument("--security", type=_cli_int, default=0)
    msg.add_argument("--text-hex", type=_cli_hex, default=b"")

    spans = commands.add_parser("msg-spans", help="calculate msg_msg allocation spans")
    spans.add_argument("message_length", type=_cli_int)
    spans.add_argument("--page-size", type=_cli_int, default=4096)

    cross = commands.add_parser("cross-cache", help="generate cross-cache phase counts")
    cross.add_argument("source_object_size", type=_cli_int)
    cross.add_argument("target_object_size", type=_cli_int)
    cross.add_argument("--page-size", type=_cli_int, default=4096)
    cross.add_argument("--slab-order", type=_cli_int, default=0)
    cross.add_argument("--object-alignment", type=_cli_int, default=8)
    cross.add_argument("--source-objects-per-slab", type=_cli_int)
    cross.add_argument("--target-objects-per-slab", type=_cli_int)
    cross.add_argument("--per-cpu-partial-slabs", type=_cli_int, default=0)
    cross.add_argument("--release-slabs", type=_cli_int, default=1)
    cross.add_argument("--reclaim-slabs", type=_cli_int, default=1)
    cross.add_argument("--safety-slabs", type=_cli_int, default=2)
    cross.add_argument(
        "--allocator-profile",
        choices=("slub-generic", "slub-dedicated", "slub-typed"),
        default="slub-generic",
    )

    dirty = commands.add_parser("dirtycred", help="generate a DirtyCred timeline")
    dirty.add_argument("variant", choices=("file", "cred"))
    dirty.add_argument(
        "--blocking-mechanism",
        choices=("userfaultfd", "fuse", "filesystem-lock"),
        required=True,
    )
    dirty.add_argument(
        "--free-primitive",
        choices=("arbitrary-free", "double-free", "uaf-free"),
        required=True,
    )

    usma = commands.add_parser("usma", help="serialize an AF_PACKET pg_vec")
    usma.add_argument("pointers", nargs="+", type=_cli_int)
    usma.add_argument("--block-count", type=_cli_int, required=True)
    usma.add_argument("--block-size", type=_cli_int, required=True)
    usma.add_argument("--mapping-length", type=_cli_int, required=True)
    usma.add_argument("--page-size", type=_cli_int, default=4096)
    usma.add_argument(
        "--access-path",
        choices=("user-and-network-namespaces", "existing-cap-net-raw", "unknown"),
        default="user-and-network-namespaces",
    )
    return parser


def _dispatch(arguments: argparse.Namespace) -> object:
    if arguments.command == "msg-layout":
        return serialize_msg_msg(
            m_list_next=arguments.m_list_next,
            m_list_prev=arguments.m_list_prev,
            m_type=arguments.m_type,
            m_ts=arguments.m_ts,
            next_segment=arguments.next_segment,
            security=arguments.security,
            text=arguments.text_hex,
        ).as_dict()
    if arguments.command == "msg-spans":
        return plan_msg_allocations(
            arguments.message_length, page_size=arguments.page_size
        ).as_dict()
    if arguments.command == "cross-cache":
        return plan_cross_cache(
            source_object_size=arguments.source_object_size,
            target_object_size=arguments.target_object_size,
            page_size=arguments.page_size,
            slab_order=arguments.slab_order,
            object_alignment=arguments.object_alignment,
            source_objects_per_slab=arguments.source_objects_per_slab,
            target_objects_per_slab=arguments.target_objects_per_slab,
            per_cpu_partial_slabs=arguments.per_cpu_partial_slabs,
            release_slabs=arguments.release_slabs,
            reclaim_slabs=arguments.reclaim_slabs,
            safety_slabs=arguments.safety_slabs,
            allocator_profile=arguments.allocator_profile,
        ).as_dict()
    if arguments.command == "dirtycred":
        return plan_dirtycred(
            variant=arguments.variant,
            blocking_mechanism=arguments.blocking_mechanism,
            free_primitive=arguments.free_primitive,
        ).as_dict()
    if arguments.command == "usma":
        return build_usma_pg_vec(
            arguments.pointers,
            block_count=arguments.block_count,
            block_size=arguments.block_size,
            mapping_length=arguments.mapping_length,
            page_size=arguments.page_size,
            access_path=arguments.access_path,
        ).as_dict()
    raise PwnkernLinuxError("unknown command")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guarded JSON CLI and return an integer status code."""

    parser = _parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception:
        parser._print_message(
            "pwnkern_linux_heap: error: malformed argv\n", sys.stderr
        )
        return 2
    try:
        document = _dispatch(arguments)
        print(json.dumps(document, sort_keys=True, separators=(",", ":")))
        return 0
    except PwnkernLinuxError as exc:
        parser._print_message(f"pwnkern_linux_heap: error: {exc}\n", sys.stderr)
        return 2
    except Exception:
        parser._print_message(
            "pwnkern_linux_heap: error: malformed CLI input\n", sys.stderr
        )
        return 2


__all__ = [
    "PwnkernLinuxError",
    "FieldPlacement",
    "SerializedObject",
    "AllocationSpan",
    "MessageAllocationPlan",
    "PlanPhase",
    "CrossCachePlan",
    "TimelinePhase",
    "DirtyCredPlan",
    "UsmaPgVecPlan",
    "MSG_MSG_PROFILE",
    "MSG_MSGSEG_PROFILE",
    "MSG_MSG_HEADER_SIZE",
    "MSG_MSGSEG_HEADER_SIZE",
    "serialize_msg_msg",
    "serialize_msg_msgseg",
    "plan_msg_allocations",
    "plan_cross_cache",
    "plan_dirtycred",
    "build_usma_pg_vec",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
