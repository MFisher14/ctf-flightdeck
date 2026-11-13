#!/usr/bin/env python3
"""Offline glibc 2.40--2.43 allocator-transition planner.

This module models upstream allocator *metadata and routing facts*.  It never
loads a libc, opens a process, executes an artifact, or emits an exploit.  In
particular, a tcache-eligible result is not an exploitability claim: the
caller still has to establish the exact target build, tunables, arena state,
and a memory-corruption primitive.

The 2.42 release tag and maintained ``release/2.42`` branch differ at the
small-tcache ceiling.  That distinction is explicit through ``source_profile``
instead of being hidden behind one version number:

* ``release-tag`` follows the glibc-2.42 tag: ``tidx2usize(63)`` and an
  exclusive ``nb < tcache_max_bytes`` comparison.
* ``maintained-release-branch`` follows the backported/corrected form:
  ``tidx2csize(63)`` and ``nb + 1``, which includes the normalized ceiling.

Primary sources:

* https://sourceware.org/pipermail/libc-announce/2025/000048.html
* https://sourceware.org/pipermail/glibc-cvs/2025q2/088647.html
* https://sourceware.org/pipermail/glibc-cvs/2025q2/088613.html
* https://sourceware.org/pipermail/glibc-cvs/2025q2/088463.html
* https://sourceware.org/pipermail/glibc-cvs/2025q4/090189.html
* https://sourceware.org/pipermail/libc-alpha/2025-October/171175.html
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import sys
from typing import Sequence


SUPPORTED_VERSIONS = ("2.40", "2.41", "2.42", "2.43")
SOURCE_RELEASE_TAG = "release-tag"
SOURCE_MAINTAINED_242 = "maintained-release-branch"
MAX_TCACHE_TUNABLE = 4 * 1024 * 1024
MAX_PLANNED_REQUEST = MAX_TCACHE_TUNABLE


class ResearchWPGlibcError(ValueError):
    """A version, ABI, size, or source profile is unsupported or ambiguous."""


def _integer(value: object, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResearchWPGlibcError(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise ResearchWPGlibcError(f"{name} must be in 0..{maximum}")
    return value


def _abi(bits: object) -> tuple[int, int, int]:
    width = _integer(bits, "bits", maximum=64)
    if width not in (32, 64):
        raise ResearchWPGlibcError("bits must be 32 or 64")
    word = width // 8
    alignment = 16 if width == 64 else 8
    minimum = 0x20 if width == 64 else 0x10
    return word, alignment, minimum


def _version(value: object) -> tuple[str, int]:
    if not isinstance(value, str) or len(value) > 32:
        raise ResearchWPGlibcError("glibc_version must be a short 2.MINOR string")
    parts = value.split(".")
    if len(parts) < 2 or parts[0] != "2" or not parts[1].isdigit():
        raise ResearchWPGlibcError("glibc_version must be 2.MINOR")
    normalized = f"2.{int(parts[1])}"
    if normalized not in SUPPORTED_VERSIONS:
        raise ResearchWPGlibcError("supported modern allocator range is glibc 2.40 through 2.43")
    return normalized, int(parts[1])


def _source_profile(version: str, value: object) -> str:
    if not isinstance(value, str):
        raise ResearchWPGlibcError("source_profile must be text")
    if value == SOURCE_RELEASE_TAG:
        return value
    if value == SOURCE_MAINTAINED_242 and version == "2.42":
        return value
    if value == SOURCE_MAINTAINED_242:
        raise ResearchWPGlibcError(
            "maintained-release-branch is only a distinct modeled profile for glibc 2.42"
        )
    raise ResearchWPGlibcError(
        "source_profile must be release-tag or maintained-release-branch"
    )


def request2size(request_size: int, *, bits: int = 64) -> int:
    """Apply the bounded ptmalloc ``request2size`` macro arithmetic."""

    request = _integer(request_size, "request_size", maximum=MAX_PLANNED_REQUEST)
    word, alignment, minimum = _abi(bits)
    mask = alignment - 1
    total = request + word + mask
    if total > (1 << bits) - 1:
        raise ResearchWPGlibcError("request2size arithmetic overflows the selected ABI")
    return minimum if total < minimum else total & ~mask


def _small_index(chunk_size: int, bits: int) -> int:
    _word, alignment, minimum = _abi(bits)
    chunk = _integer(chunk_size, "chunk_size", maximum=MAX_TCACHE_TUNABLE + alignment)
    if chunk < minimum or chunk % alignment:
        raise ResearchWPGlibcError("chunk_size must be an aligned ptmalloc chunk size")
    return (chunk - minimum) // alignment


def _max_small_chunk(bits: int) -> int:
    _word, alignment, minimum = _abi(bits)
    return minimum + 63 * alignment


def _max_small_usable(bits: int) -> int:
    word, _alignment, _minimum = _abi(bits)
    return _max_small_chunk(bits) - word


def tcache_index(
    chunk_size: int,
    *,
    glibc_version: str,
    bits: int = 64,
) -> tuple[int, str]:
    """Return the source-level tcache index and ``small``/``large`` class.

    Eligibility under a configured ceiling is deliberately handled by
    :func:`plan_tcache`; this function only performs bin geometry.
    """

    version, minor = _version(glibc_version)
    chunk = _integer(
        chunk_size, "chunk_size", maximum=MAX_TCACHE_TUNABLE + 0x100
    )
    small = _small_index(chunk, bits)
    if small < 64:
        return small, "small"
    if minor < 42:
        raise ResearchWPGlibcError(f"glibc {version} has no large tcache bins")
    # Equivalent to 64 + clz(MAX_TCACHE_SMALL_SIZE) - clz(nb) for positive
    # values of the same C integer width.  Corrected and tag constants have
    # the same bit length, so the logarithmic boundaries are identical.
    index = 64 + chunk.bit_length() - _max_small_chunk(bits).bit_length()
    if not 64 <= index < 76:
        raise ResearchWPGlibcError("chunk_size is outside the 12 large tcache bins")
    return index, "large"


@dataclass(frozen=True, slots=True)
class GlibcModernProfile:
    version: str
    source_profile: str
    bits: int
    tcache_small_bins: int
    tcache_large_bins: int
    tcache_total_bins: int
    default_tcache_count: int
    counter_field: str
    counter_semantics: str
    calloc_uses_tcache: bool
    all_bin_double_free_scan: bool
    fastbins_present: bool
    safe_linking: bool
    default_ceiling_kind: str
    default_ceiling_value: int
    maximum_tunable_value: int
    counter_offset: int
    counter_bytes: int
    entries_offset: int
    entries_bytes: int
    perthread_struct_size: int
    perthread_malloc_chunk_size: int
    entry_next_offset: int
    entry_key_offset: int
    entry_size: int
    constraints: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["constraints"] = list(self.constraints)
        return row


def profile_for(
    glibc_version: str,
    *,
    bits: int = 64,
    source_profile: str = SOURCE_RELEASE_TAG,
) -> GlibcModernProfile:
    """Return an explicit upstream release/source-layout profile."""

    version, minor = _version(glibc_version)
    source = _source_profile(version, source_profile)
    word, alignment, _minimum = _abi(bits)
    large_bins = 12 if minor >= 42 else 0
    bins = 64 + large_bins
    counter_bytes = bins * 2
    entries_offset = (counter_bytes + alignment - 1) & ~(alignment - 1)
    entries_bytes = bins * word
    struct_size = entries_offset + entries_bytes
    chunk_size = request2size(struct_size, bits=bits)

    if minor < 42:
        ceiling_kind = "inclusive-user-request-via-bin-count"
        ceiling = _max_small_usable(bits)
        counter_field = "counts"
        counter_semantics = "occupied-entries-up-counter"
    elif version == "2.42" and source == SOURCE_RELEASE_TAG:
        ceiling_kind = "exclusive-normalized-chunk"
        ceiling = _max_small_usable(bits)
        counter_field = "num_slots"
        counter_semantics = "remaining-slots-down-counter"
    else:
        ceiling_kind = "exclusive-normalized-chunk-plus-one"
        ceiling = _max_small_chunk(bits) + 1
        counter_field = "num_slots"
        counter_semantics = "remaining-slots-down-counter"

    constraints = [
        "upstream source profile only; validate distro backports and GLIBC_TUNABLES",
        "tcache eligibility is allocator routing evidence, not an exploitation primitive",
        "singly linked tcache pointers remain protected by Safe-Linking",
    ]
    if minor >= 42:
        constraints.extend((
            "large tcache bins require glibc.malloc.tcache_max above the small default",
            "large bins are logarithmic ranges and allocation searches for a fitting chunk",
            "a suspicious tcache key triggers duplicate verification across all tcache bins",
        ))
    if minor >= 43:
        constraints.append("fastbin infrastructure is absent; do not plan a fastbin route")
    return GlibcModernProfile(
        version=version,
        source_profile=source,
        bits=bits,
        tcache_small_bins=64,
        tcache_large_bins=large_bins,
        tcache_total_bins=bins,
        # Fastbin removal in 2.43 was paired with a default fill-count
        # increase from seven to sixteen (glibc patch series 9/9).
        default_tcache_count=16 if minor >= 43 else 7,
        counter_field=counter_field,
        counter_semantics=counter_semantics,
        calloc_uses_tcache=minor >= 41,
        all_bin_double_free_scan=minor >= 42,
        fastbins_present=minor <= 42,
        safe_linking=True,
        default_ceiling_kind=ceiling_kind,
        default_ceiling_value=ceiling,
        maximum_tunable_value=MAX_TCACHE_TUNABLE if minor >= 42 else _max_small_usable(bits),
        counter_offset=0,
        counter_bytes=counter_bytes,
        entries_offset=entries_offset,
        entries_bytes=entries_bytes,
        perthread_struct_size=struct_size,
        perthread_malloc_chunk_size=chunk_size,
        entry_next_offset=0,
        entry_key_offset=word,
        entry_size=2 * word,
        constraints=tuple(constraints),
    )


@dataclass(frozen=True, slots=True)
class TcachePlan:
    version: str
    source_profile: str
    bits: int
    request_size: int
    chunk_size: int
    bin_index: int | None
    bin_kind: str | None
    tcache_max_input: int | None
    effective_exclusive_chunk_ceiling: int | None
    active_small_bins: int
    tcache_eligible: bool
    fastbin_route_exists: bool
    calloc_uses_same_tcache_route: bool
    all_bin_double_free_scan: bool
    reasons: tuple[str, ...]
    exploitability_verified: bool = False
    offline: bool = True
    network_requests: int = 0

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["reasons"] = list(self.reasons)
        return row


def plan_tcache(
    glibc_version: str,
    request_size: int,
    *,
    bits: int = 64,
    tcache_max: int | None = None,
    source_profile: str = SOURCE_RELEASE_TAG,
) -> TcachePlan:
    """Plan version-correct tcache routing for one bounded allocation size."""

    profile = profile_for(
        glibc_version, bits=bits, source_profile=source_profile
    )
    request = _integer(request_size, "request_size", maximum=MAX_PLANNED_REQUEST)
    chunk = request2size(request, bits=bits)
    reasons: list[str] = []
    bin_index: int | None
    bin_kind: str | None
    try:
        bin_index, bin_kind = tcache_index(
            chunk, glibc_version=profile.version, bits=bits
        )
    except ResearchWPGlibcError:
        bin_index, bin_kind = None, None

    active_small_bins = 64
    exclusive: int | None = None
    eligible = False
    normalized_input: int | None = None

    if tcache_max is not None:
        supplied = _integer(
            tcache_max, "tcache_max", maximum=profile.maximum_tunable_value
        )
        normalized_input = supplied
    else:
        supplied = None

    minor = int(profile.version.split(".")[1])
    if minor < 42:
        max_user = _max_small_usable(bits)
        chosen = max_user if supplied is None else supplied
        # Pre-2.42 stores a number of active small bins derived from the
        # normalized configured request, rather than comparing every nb to a
        # byte threshold.
        configured_chunk = request2size(chosen, bits=bits)
        configured_index = _small_index(configured_chunk, bits)
        active_small_bins = min(64, configured_index + 1)
        eligible = bin_index is not None and bin_kind == "small" and bin_index < active_small_bins
        exclusive = _max_small_chunk(bits) + 1 if supplied is None else configured_chunk + 1
        reasons.append(
            f"pre-2.42 active small-bin count is {active_small_bins} from the configured request"
        )
    else:
        if supplied is None:
            exclusive = profile.default_ceiling_value
            reasons.append("release default leaves logarithmic large tcache bins inactive")
        else:
            configured_chunk = request2size(supplied, bits=bits)
            # Reject tunables that normalize beyond the 12-bin geometry even
            # when the documentation describes the ceiling approximately as 4 MiB.
            tcache_index(
                configured_chunk,
                glibc_version=profile.version,
                bits=bits,
            )
            if profile.version == "2.42" and profile.source_profile == SOURCE_RELEASE_TAG:
                exclusive = configured_chunk
                reasons.append("2.42 release tag stores normalized nb and compares chunk_size < nb")
            else:
                exclusive = configured_chunk + 1
                reasons.append("corrected source stores normalized nb + 1 for the exclusive comparison")
            if configured_chunk <= _max_small_chunk(bits):
                active_small_bins = min(64, _small_index(configured_chunk, bits) + 1)
        eligible = bin_index is not None and exclusive is not None and chunk < exclusive
        if bin_kind == "large" and supplied is None:
            eligible = False
    if bin_index is None:
        reasons.append("chunk size has no modeled tcache bin")
    elif eligible:
        reasons.append(f"chunk maps to active {bin_kind} tcache bin {bin_index}")
    else:
        reasons.append(f"chunk maps to bin {bin_index} but is outside the active ceiling")

    return TcachePlan(
        version=profile.version,
        source_profile=profile.source_profile,
        bits=bits,
        request_size=request,
        chunk_size=chunk,
        bin_index=bin_index,
        bin_kind=bin_kind,
        tcache_max_input=normalized_input,
        effective_exclusive_chunk_ceiling=exclusive,
        active_small_bins=active_small_bins,
        tcache_eligible=eligible,
        fastbin_route_exists=profile.fastbins_present,
        calloc_uses_same_tcache_route=profile.calloc_uses_tcache,
        all_bin_double_free_scan=profile.all_bin_double_free_scan,
        reasons=tuple(reasons),
    )


def _cli_int(value: str) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline glibc 2.40--2.43 allocator transition planner"
    )
    commands = parser.add_subparsers(dest="operation", required=True)
    for name in ("profile", "plan"):
        command = commands.add_parser(name)
        command.add_argument("version")
        if name == "plan":
            command.add_argument("request_size", type=_cli_int)
            command.add_argument("--tcache-max", type=_cli_int)
        command.add_argument("--bits", type=_cli_int, choices=(32, 64), default=64)
        command.add_argument(
            "--source-profile",
            choices=(SOURCE_RELEASE_TAG, SOURCE_MAINTAINED_242),
            default=SOURCE_RELEASE_TAG,
        )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guarded offline JSON CLI."""

    try:
        args = _parser().parse_args(argv)
        if args.operation == "profile":
            result = profile_for(
                args.version, bits=args.bits, source_profile=args.source_profile
            )
        elif args.operation == "plan":
            result = plan_tcache(
                args.version,
                args.request_size,
                bits=args.bits,
                tcache_max=args.tcache_max,
                source_profile=args.source_profile,
            )
        else:  # required argparse subparser
            raise ResearchWPGlibcError("unsupported operation")
        print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except ResearchWPGlibcError as exc:
        print(f"research_wp_glibc_modern: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, TypeError, ValueError, OverflowError) as exc:
        print(
            f"research_wp_glibc_modern: malformed input ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


__all__ = [
    "ResearchWPGlibcError",
    "GlibcModernProfile",
    "TcachePlan",
    "SUPPORTED_VERSIONS",
    "SOURCE_RELEASE_TAG",
    "SOURCE_MAINTAINED_242",
    "request2size",
    "tcache_index",
    "profile_for",
    "plan_tcache",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
