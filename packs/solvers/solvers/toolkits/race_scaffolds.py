"""Inert, deterministic race-window scaffolds for offline CTF review.

The builders serialize event timelines, controlled buffers, prerequisites, and
compile-blocked C review skeletons for userfaultfd, FUSE, and generic TOCTOU
patterns.  They never compile, run, mount, open a device, retry a race, or
contact a target.  Every generated source section starts with ``#error`` so an
operator must deliberately review and remove the guard before any later use.

Each public ``build_*`` returns the shared immutable ``PayloadBuild`` contract.
"""
from __future__ import annotations

import json
import re
import struct
from collections.abc import Mapping, Sequence

try:  # package and direct toolkit imports
    from .contract import BuildError, PayloadBuild, ensure_uint
except ImportError:  # pragma: no cover - repository tests use direct imports
    from contract import BuildError, PayloadBuild, ensure_uint


class RaceBuildError(BuildError):
    """A requested inert race plan is inconsistent or unsafe to serialize."""


MAGIC = b"R5BRACE1"
FORMAT_VERSION = 1
MAX_BUFFER = 1 << 20
MAX_PAYLOAD = 4 << 20
MAX_RETRIES = 100_000
MAX_TIMEOUT_MS = 60_000
MAX_TOTAL_RETRY_BUDGET_MS = 600_000
MAX_SECTIONS = 16
_LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def _kernel_version(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?", value):
        raise RaceBuildError("kernel_version must be MAJOR.MINOR or MAJOR.MINOR.PATCH")
    parts = [int(item) for item in value.split(".")]
    parts += [0] * (3 - len(parts))
    return tuple(parts)  # type: ignore[return-value]


def _bounded_bytes(value: bytes | bytearray, name: str, *, maximum: int = MAX_BUFFER) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise RaceBuildError(f"{name} must be bytes")
    raw = bytes(value)
    if not raw or len(raw) > maximum:
        raise RaceBuildError(f"{name} must contain 1..{maximum} bytes")
    return raw


def _retries(value: int) -> int:
    value = ensure_uint(value, 32, name="max_retries")
    if not 1 <= value <= MAX_RETRIES:
        raise RaceBuildError(f"max_retries must be in 1..{MAX_RETRIES}")
    return value


def _timeout(value: int) -> int:
    value = ensure_uint(value, 32, name="timeout_ms")
    if not 1 <= value <= MAX_TIMEOUT_MS:
        raise RaceBuildError(f"timeout_ms must be in 1..{MAX_TIMEOUT_MS}")
    return value


def _timeline(rows: Sequence[Mapping[str, object]]) -> bytes:
    if not 2 <= len(rows) <= 64:
        raise RaceBuildError("timeline must contain 2..64 events")
    normalized = []
    seen: set[str] = set()
    for index, source in enumerate(rows):
        row = dict(source)
        event = row.get("event")
        actor = row.get("actor")
        if not isinstance(event, str) or not _LABEL_RE.fullmatch(event) or event in seen:
            raise RaceBuildError("timeline event names must be unique safe labels")
        if not isinstance(actor, str) or not _LABEL_RE.fullmatch(actor):
            raise RaceBuildError("timeline actors must be safe labels")
        seen.add(event)
        row["sequence"] = index
        normalized.append(row)
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _source_guard(strategy: str, body: str) -> bytes:
    if not _LABEL_RE.fullmatch(strategy):
        raise RaceBuildError("strategy must be a safe label")
    text = (
        f'#error "R5B INERT REVIEW SCAFFOLD: {strategy}; deliberate human enablement required"\n'
        "/* This generated source is never compiled or run by the builder/tests. */\n"
        + body.strip() + "\n"
    )
    return text.encode("utf-8")


def _compose(
    *, strategy: str, architecture: str, sections: Sequence[tuple[str, bytes]],
    prerequisites: Sequence[str], constraints: Sequence[str], max_retries: int,
    timeout_ms: int, metadata: Mapping[str, str],
) -> PayloadBuild:
    if not 1 <= len(sections) <= MAX_SECTIONS:
        raise RaceBuildError(f"section count must be in 1..{MAX_SECTIONS}")
    if not all(isinstance(item, str) and item for item in prerequisites):
        raise RaceBuildError("prerequisites must be non-empty strings")
    if not all(isinstance(item, str) and item for item in constraints):
        raise RaceBuildError("constraints must be non-empty strings")
    total_retry_budget_ms = max_retries * timeout_ms
    if total_retry_budget_ms > MAX_TOTAL_RETRY_BUDGET_MS:
        raise RaceBuildError(
            f"max_retries * timeout_ms exceeds {MAX_TOTAL_RETRY_BUDGET_MS} ms total budget"
        )
    payload = bytearray(MAGIC + struct.pack("<HH", FORMAT_VERSION, len(sections)))
    placements: dict[str, int] = {"header": 0}
    widths: dict[str, int] = {"header": len(payload)}
    seen: set[str] = set()
    for name, data in sections:
        if not isinstance(name, str) or not _LABEL_RE.fullmatch(name) or name in seen:
            raise RaceBuildError("section names must be unique safe labels")
        seen.add(name)
        if not isinstance(data, bytes) or not data or len(data) > MAX_BUFFER:
            raise RaceBuildError(f"section {name} must contain 1..{MAX_BUFFER} bytes")
        padding = (-len(payload)) % 8
        payload.extend(b"\x00" * padding)
        record_start = len(payload)
        encoded_name = name.encode("ascii")
        payload.extend(struct.pack("<HI", len(encoded_name), len(data)))
        payload.extend(encoded_name)
        data_start = len(payload)
        payload.extend(data)
        if len(payload) > MAX_PAYLOAD:
            raise RaceBuildError(f"combined race plan exceeds {MAX_PAYLOAD} bytes")
        placements[f"record.{name}"] = record_start
        widths[f"record.{name}"] = len(payload) - record_start
        placements[f"section.{name}"] = data_start
        widths[f"section.{name}"] = len(data)
    meta = {
        "constraints_json": json.dumps(list(constraints), sort_keys=True),
        "inert_source": "true",
        "max_retries": str(max_retries),
        "prerequisites_json": json.dumps(list(prerequisites), sort_keys=True),
        "timeout_ms": str(timeout_ms),
        "total_retry_budget_ms": str(total_retry_budget_ms),
        **dict(metadata),
    }
    return PayloadBuild(
        payload=bytes(payload), placements=placements, widths=widths,
        architecture=architecture, strategy=strategy, metadata=meta,
    )


def parse_sections(payload: bytes) -> dict[str, bytes]:
    """Decode a generated envelope for independent structural verification."""

    if not isinstance(payload, bytes) or len(payload) < 12 or payload[:8] != MAGIC:
        raise RaceBuildError("not an r5b race envelope")
    if len(payload) > MAX_PAYLOAD:
        raise RaceBuildError(f"race envelope exceeds {MAX_PAYLOAD} bytes")
    version, count = struct.unpack_from("<HH", payload, 8)
    if version != FORMAT_VERSION or not 1 <= count <= MAX_SECTIONS:
        raise RaceBuildError("unsupported race envelope version or section count")
    cursor = 12
    answer: dict[str, bytes] = {}
    for _index in range(count):
        cursor += (-cursor) % 8
        if cursor + 6 > len(payload):
            raise RaceBuildError("truncated race section header")
        name_length, data_length = struct.unpack_from("<HI", payload, cursor)
        cursor += 6
        if data_length == 0 or data_length > MAX_BUFFER:
            raise RaceBuildError("race section length is outside the bounded range")
        end_name = cursor + name_length
        end_data = end_name + data_length
        if name_length == 0 or end_data > len(payload):
            raise RaceBuildError("truncated race section")
        try:
            name = payload[cursor:end_name].decode("ascii")
        except UnicodeDecodeError as exc:
            raise RaceBuildError("non-ASCII race section name") from exc
        if not _LABEL_RE.fullmatch(name) or name in answer:
            raise RaceBuildError("invalid or duplicate race section name")
        answer[name] = payload[end_name:end_data]
        cursor = end_data
    if cursor != len(payload):
        raise RaceBuildError("unexpected trailing bytes")
    return answer


def build_userfaultfd_race_plan(
    *, kernel_version: str, fault_page_address: int,
    initial_buffer: bytes, replacement_buffer: bytes,
    mode: str = "missing", page_size: int = 4096,
    max_retries: int = 64, timeout_ms: int = 5000,
    unprivileged: bool = True, kernel_faults: bool = True,
) -> PayloadBuild:
    """Build an inert userfaultfd synchronization and buffer-placement plan."""

    version = _kernel_version(kernel_version)
    if version < (4, 3, 0):
        raise RaceBuildError("userfaultfd requires Linux 4.3 or newer")
    if mode not in {"missing", "writeprotect"}:
        raise RaceBuildError("mode must be missing or writeprotect")
    if mode == "writeprotect" and version < (5, 7, 0):
        raise RaceBuildError("writeprotect planning requires Linux 5.7+ and feature probing")
    if page_size < 4096 or page_size > MAX_BUFFER or page_size & (page_size - 1):
        raise RaceBuildError(f"page_size must be a power of two in 4096..{MAX_BUFFER}")
    address = ensure_uint(fault_page_address, 64, name="fault_page_address")
    if address == 0 or address % page_size:
        raise RaceBuildError("fault_page_address must be nonzero and page-aligned")
    if address + page_size > 1 << 64:
        raise RaceBuildError("fault page backing range wraps the 64-bit address space")
    initial = _bounded_bytes(initial_buffer, "initial_buffer", maximum=min(page_size, MAX_BUFFER))
    replacement = _bounded_bytes(
        replacement_buffer, "replacement_buffer", maximum=min(page_size, MAX_BUFFER)
    )
    if len(initial) != len(replacement):
        raise RaceBuildError("initial and replacement buffers must have identical lengths")
    if initial == replacement:
        raise RaceBuildError("initial and replacement buffers must differ")
    logical_length = len(initial)
    initial_backing = initial.ljust(page_size, b"\x00")
    replacement_backing = replacement.ljust(page_size, b"\x00")
    retries = _retries(max_retries)
    timeout = _timeout(timeout_ms)
    fault_event = "pagefault_missing" if mode == "missing" else "pagefault_writeprotect"
    resolution = "UFFDIO_COPY" if mode == "missing" else "UFFDIO_WRITEPROTECT_remove"
    timeline_rows = [
        {"actor": "controller", "event": "probe_features", "signals": "features_known"},
        {"actor": "controller", "event": "register_range", "waits_for": "features_known", "signals": "range_ready"},
        {"actor": "fault_handler", "event": "wait_for_fault", "waits_for": "range_ready", "signals": fault_event},
        {"actor": "trigger_thread", "event": "enter_checked_operation", "waits_for": "range_ready", "signals": "fault_triggered"},
        {"actor": "controller", "event": "mutate_controlled_state", "waits_for": fault_event, "signals": "replacement_ready"},
        {"actor": "fault_handler", "event": "resolve_fault", "waits_for": "replacement_ready", "method": resolution, "signals": "fault_resolved"},
        {"actor": "controller", "event": "join_and_verify", "waits_for": "fault_resolved", "signals": "attempt_complete"},
    ]
    prerequisites = [
        f"Linux kernel {kernel_version} with CONFIG_USERFAULTFD and userfaultfd syscall/device support",
        f"runtime UFFDIO_API feature probe confirms {mode} registration/ioctls",
        "target mapping is private/writable and compatible with requested userfaultfd mode",
        f"both supplied backing images are explicitly zero-padded to one {page_size}-byte page",
        "official reference: https://docs.kernel.org/admin-guide/mm/userfaultfd.html",
    ]
    if unprivileged and kernel_faults:
        prerequisites.append("CAP_SYS_PTRACE or vm.unprivileged_userfaultfd=1 for kernel-fault handling")
    elif unprivileged and version >= (5, 11, 0):
        prerequisites.append("use UFFD_USER_MODE_ONLY for userspace faults; probe flag availability")
    elif unprivileged:
        prerequisites.append(
            "kernel predates UFFD_USER_MODE_ONLY; confirm vm.unprivileged_userfaultfd or required capability"
        )
    manifest = {
        "format": "r5b-userfaultfd-race-plan-v1", "inert": True,
        "kernel_version": kernel_version, "mode": mode,
        "fault_page_address": f"0x{address:x}", "page_size": page_size,
        "buffer_length": logical_length, "backing_length": page_size,
        "padding_byte": 0, "max_retries": retries, "timeout_ms": timeout,
        "total_retry_budget_ms": retries * timeout,
        "unprivileged": bool(unprivileged), "kernel_faults": bool(kernel_faults),
    }
    source = _source_guard("userfaultfd", f"""
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
/* Review skeleton only: no entry point, system call, ioctl, or worker is emitted. */
struct r5b_uffd_plan {{
    uintptr_t fault_page; size_t page_size; unsigned max_retries; unsigned timeout_ms;
    atomic_uint event_index;
}};
/* Event order: probe -> register -> fault -> mutate -> {resolution} -> verify. */
/* Required page address: 0x{address:x}; controlled bytes: {logical_length}; backing: {page_size}. */
""")
    return _compose(
        strategy="userfaultfd-race-review", architecture="linux",
        sections=(
            ("manifest", json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()),
            ("timeline", _timeline(timeline_rows)),
            ("buffer.initial", initial_backing),
            ("buffer.replacement", replacement_backing),
            ("source.c", source),
        ),
        prerequisites=prerequisites,
        constraints=(
            "never run generated source; it is compile-blocked review material",
            "abort each attempt on timeout and join all actors before retry",
            "re-probe features on the exact challenge kernel rather than assuming host support",
            "fault resolution must occur exactly once per observed event identifier",
            "UFFDIO_COPY source and destination backing cover exactly one complete page",
        ),
        max_retries=retries, timeout_ms=timeout,
        metadata={
            "buffer_address": f"0x{address:x}", "kernel_version": kernel_version,
            "mode": mode, "source_guard": "#error",
            "logical_buffer_length": str(logical_length),
            "page_backing_length": str(page_size),
        },
    )


def build_fuse_race_plan(
    *, kernel_version: str, mapped_buffer_address: int,
    initial_buffer: bytes, replacement_buffer: bytes,
    mountpoint: str = "/tmp/r5b-fuse-review", page_size: int = 4096,
    max_retries: int = 64, timeout_ms: int = 5000,
    direct_io: bool = False,
) -> PayloadBuild:
    """Build an inert FUSE request-stall timeline and placement plan."""

    version = _kernel_version(kernel_version)
    if version < (2, 6, 14):
        raise RaceBuildError("FUSE planning requires Linux 2.6.14 or newer")
    if (not isinstance(mountpoint, str) or not mountpoint.startswith("/")
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in mountpoint)
            or "*/" in mountpoint):
        raise RaceBuildError("mountpoint must be an absolute printable path safe for review text")
    if len(mountpoint.encode("utf-8")) > 256:
        raise RaceBuildError("mountpoint exceeds 256 UTF-8 bytes")
    if page_size < 4096 or page_size > 1 << 21 or page_size & (page_size - 1):
        raise RaceBuildError("page_size must be a power of two in 4096..2097152")
    address = ensure_uint(mapped_buffer_address, 64, name="mapped_buffer_address")
    if address == 0 or address % page_size:
        raise RaceBuildError("mapped_buffer_address must be nonzero and page-aligned")
    if address + page_size > 1 << 64:
        raise RaceBuildError("mapped FUSE page range wraps the 64-bit address space")
    initial = _bounded_bytes(initial_buffer, "initial_buffer", maximum=min(page_size, MAX_BUFFER))
    replacement = _bounded_bytes(
        replacement_buffer, "replacement_buffer", maximum=min(page_size, MAX_BUFFER)
    )
    if len(initial) != len(replacement) or initial == replacement:
        raise RaceBuildError("controlled FUSE buffers must be equal-length and different")
    retries, timeout = _retries(max_retries), _timeout(timeout_ms)
    timeline_rows = [
        {"actor": "controller", "event": "mount_review_filesystem", "signals": "mount_ready"},
        {"actor": "fuse_daemon", "event": "publish_controlled_file", "waits_for": "mount_ready", "signals": "file_ready"},
        {"actor": "trigger_thread", "event": "enter_checked_operation", "waits_for": "file_ready", "signals": "fuse_read_requested"},
        {"actor": "fuse_daemon", "event": "hold_read_response", "waits_for": "fuse_read_requested", "signals": "window_open"},
        {"actor": "controller", "event": "swap_controlled_state", "waits_for": "window_open", "signals": "replacement_ready"},
        {"actor": "fuse_daemon", "event": "release_read_response", "waits_for": "replacement_ready", "signals": "request_released"},
        {"actor": "controller", "event": "join_verify_unmount", "waits_for": "request_released", "signals": "attempt_complete"},
    ]
    prerequisites = [
        f"Linux kernel {kernel_version} with CONFIG_FUSE_FS and accessible /dev/fuse",
        "matching libfuse/fusermount support and permission to create a private user mount",
        "mount namespace and cleanup path are controlled; no unrelated filesystem is touched",
        "official reference: https://docs.kernel.org/filesystems/fuse/",
    ]
    manifest = {
        "format": "r5b-fuse-race-plan-v1", "inert": True,
        "kernel_version": kernel_version, "mountpoint": mountpoint,
        "mapped_buffer_address": f"0x{address:x}", "page_size": page_size,
        "buffer_length": len(initial), "max_retries": retries,
        "timeout_ms": timeout, "total_retry_budget_ms": retries * timeout,
        "direct_io": bool(direct_io),
    }
    source = _source_guard("fuse", f"""
#include <fuse3/fuse.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
/* Review skeleton only: no entry point, mount, callback, or worker is emitted. */
struct r5b_fuse_plan {{
    uintptr_t mapped_page; size_t page_size; unsigned max_retries; unsigned timeout_ms;
    atomic_uint event_index;
}};
/* Mountpoint placeholder: {mountpoint}; direct_io={int(bool(direct_io))}. */
/* Event order: mount -> request -> hold -> swap -> release -> unmount. */
""")
    return _compose(
        strategy="fuse-race-review", architecture="linux",
        sections=(
            ("manifest", json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()),
            ("timeline", _timeline(timeline_rows)),
            ("buffer.initial", initial), ("buffer.replacement", replacement),
            ("source.c", source),
        ),
        prerequisites=prerequisites,
        constraints=(
            "never run generated source; it is compile-blocked review material",
            "use a private mount namespace and deterministic unmount/daemon shutdown on every attempt",
            "bound queued FUSE requests and abort the connection on timeout",
            "cache/direct_io semantics must be confirmed on the exact kernel and libfuse build",
        ),
        max_retries=retries, timeout_ms=timeout,
        metadata={
            "buffer_address": f"0x{address:x}", "kernel_version": kernel_version,
            "mountpoint": mountpoint, "source_guard": "#error",
        },
    )


def build_toctou_race_plan(
    *, kernel_version: str, controlled_buffer_address: int,
    checked_buffer: bytes, used_buffer: bytes,
    resource_label: str = "reviewed_object",
    max_retries: int = 100, timeout_ms: int = 2000,
    worker_count: int = 2,
) -> PayloadBuild:
    """Build a generic barrier-coordinated check/use race review scaffold."""

    _kernel_version(kernel_version)
    address = ensure_uint(controlled_buffer_address, 64, name="controlled_buffer_address")
    if address == 0:
        raise RaceBuildError("controlled_buffer_address must be nonzero")
    checked = _bounded_bytes(checked_buffer, "checked_buffer")
    used = _bounded_bytes(used_buffer, "used_buffer")
    if len(checked) != len(used) or checked == used:
        raise RaceBuildError("checked/used buffers must be equal-length and different")
    if address + len(checked) > 1 << 64:
        raise RaceBuildError("controlled buffer range wraps the 64-bit address space")
    if not isinstance(resource_label, str) or not _LABEL_RE.fullmatch(resource_label):
        raise RaceBuildError("resource_label must be a safe 1..64 byte label")
    retries, timeout = _retries(max_retries), _timeout(timeout_ms)
    workers = ensure_uint(worker_count, 16, name="worker_count")
    if not 2 <= workers <= 64:
        raise RaceBuildError("worker_count must be in 2..64")
    timeline_rows = [
        {"actor": "controller", "event": "reset_attempt", "signals": "state_checked"},
        {"actor": "checker", "event": "present_checked_buffer", "waits_for": "state_checked", "signals": "check_entered"},
        {"actor": "mutator", "event": "wait_for_check_boundary", "waits_for": "check_entered", "signals": "swap_authorized"},
        {"actor": "mutator", "event": "publish_used_buffer", "waits_for": "swap_authorized", "signals": "use_state_ready"},
        {"actor": "user", "event": "enter_use_boundary", "waits_for": "use_state_ready", "signals": "use_complete"},
        {"actor": "controller", "event": "join_and_classify", "waits_for": "use_complete", "signals": "attempt_complete"},
    ]
    prerequisites = [
        f"Linux kernel {kernel_version}; exact vulnerable check/use path confirmed from challenge evidence",
        "caller controls both serialized states and can observe a deterministic synchronization boundary",
        "all worker lifetimes, barriers, and resource ownership are local to the assigned challenge",
    ]
    manifest = {
        "format": "r5b-generic-toctou-plan-v1", "inert": True,
        "kernel_version": kernel_version, "resource_label": resource_label,
        "controlled_buffer_address": f"0x{address:x}",
        "buffer_length": len(checked), "max_retries": retries,
        "timeout_ms": timeout, "total_retry_budget_ms": retries * timeout,
        "worker_count": workers,
    }
    source = _source_guard("generic-toctou", f"""
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
/* Review skeleton only: no target call, thread body, or retry loop is emitted. */
struct r5b_toctou_plan {{
    uintptr_t controlled_buffer; size_t buffer_length;
    unsigned max_retries; unsigned timeout_ms; unsigned worker_count;
    pthread_barrier_t before_check, before_use; atomic_uint event_index;
}};
/* Resource label: {resource_label}; buffer address: 0x{address:x}. */
/* Event order: reset -> checked state -> boundary -> swap -> use -> classify. */
""")
    return _compose(
        strategy="generic-toctou-review", architecture="linux",
        sections=(
            ("manifest", json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()),
            ("timeline", _timeline(timeline_rows)),
            ("buffer.checked", checked), ("buffer.used", used),
            ("source.c", source),
        ),
        prerequisites=prerequisites,
        constraints=(
            "never run generated source; it is compile-blocked review material",
            "retry count and per-attempt timeout are hard caps, not adaptive unbounded loops",
            "reset all shared state and join every worker before the next attempt",
            "a schedule observation is evidence only; do not claim success without target-state verification",
        ),
        max_retries=retries, timeout_ms=timeout,
        metadata={
            "buffer_address": f"0x{address:x}", "kernel_version": kernel_version,
            "resource_label": resource_label, "source_guard": "#error",
            "worker_count": str(workers),
        },
    )


__all__ = [
    "RaceBuildError", "MAGIC", "parse_sections", "build_userfaultfd_race_plan",
    "build_fuse_race_plan", "build_toctou_race_plan",
]
