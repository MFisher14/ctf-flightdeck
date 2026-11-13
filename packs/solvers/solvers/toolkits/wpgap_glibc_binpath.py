#!/usr/bin/env python3
"""Offline x86-64 glibc 2.40--2.43 size-to-bin path planner.

This complements :mod:`research_wp_glibc_modern`: that engine owns the
source-derived tcache geometry and tunable semantics, while this module adds
the ordered arena fallback and free-staging paths.  It never opens a process,
loads a libc, executes supplied data, or sends a request.

Only pristine upstream release tags on the ordinary x86-64 LP64 ABI are
accepted.  Patch suffixes and vendor/backport labels are deliberately refused;
their allocator behavior cannot be inferred from a version string.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from functools import wraps
import json
import sys
from typing import Callable, Sequence, TypeVar

try:  # Package import and repository basename import are both supported.
    from . import research_wp_glibc_modern as modern
except ImportError:  # pragma: no cover - exercised by the repository test layout
    import research_wp_glibc_modern as modern


SUPPORTED_VERSIONS = ("2.40", "2.41", "2.42", "2.43")
SUPPORTED_APIS = ("malloc", "calloc")
TCACHE_STATES = ("unknown", "hit", "miss")
MAX_REQUEST = modern.MAX_PLANNED_REQUEST
MAX_TCACHE_COUNT = (1 << 16) - 1
MIN_LARGE_SIZE = 0x400
DEFAULT_MAX_FAST_CHUNK = 0x80


class WPGAPGlibcError(ValueError):
    """Malformed, ambiguous, or unsupported allocator-plan input."""


_Result = TypeVar("_Result")


def _fail_closed(function: Callable[..., _Result]) -> Callable[..., _Result]:
    """Ensure public helpers expose only the lane's declared exception."""

    @wraps(function)
    def guarded(*args: object, **kwargs: object) -> _Result:
        try:
            return function(*args, **kwargs)
        except WPGAPGlibcError:
            raise
        except Exception as exc:
            raise WPGAPGlibcError(f"malformed {function.__name__} input") from exc

    return guarded


def _exact_version(value: object) -> str:
    if not isinstance(value, str) or value not in SUPPORTED_VERSIONS:
        raise WPGAPGlibcError(
            "glibc_version must be an exact upstream release tag: "
            "2.40, 2.41, 2.42, or 2.43"
        )
    return value


def _integer(value: object, name: str, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WPGAPGlibcError(f"{name} must be an integer")
    if value < 0 or value > maximum:
        raise WPGAPGlibcError(f"{name} must be in 0..{maximum}")
    return value


def _choice(value: object, name: str, choices: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise WPGAPGlibcError(f"{name} must be one of {', '.join(choices)}")
    return value


@dataclass(frozen=True, slots=True)
class ReleasePathProfile:
    """Routing facts added on top of the existing modern tcache profile."""

    version: str
    abi: str
    source_profile: str
    tcache_counter_field: str
    tcache_counter_semantics: str
    tcache_total_bins: int
    default_tcache_count: int
    all_bin_double_free_scan: bool
    calloc_tcache_first: bool
    fastbins_present: bool
    default_max_fast_chunk: int | None
    ordinary_small_free_staging: str
    large_tcache_selection: str
    constraints: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["constraints"] = list(self.constraints)
        return row


@dataclass(frozen=True, slots=True)
class PathStep:
    """One ordered conditional allocator step; no operation is performed."""

    order: int
    component: str
    bin_kind: str | None
    bin_index: int | None
    condition: str
    outcome: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AllocatorPathPlan:
    """Deterministic size facts plus state-conditional allocation routes."""

    version: str
    abi: str
    api: str
    request_size: int
    chunk_size: int
    tcache_configuration: str
    tcache_max_input: int | None
    tcache_count: int
    tcache_state_fact: str
    tcache_bin_kind: str | None
    tcache_bin_index: int | None
    tcache_size_eligible: bool
    tcache_checked: bool
    tcache_selection_rule: str | None
    large_tcache_for_request: bool
    fastbin_index: int | None
    arena_bin_kind: str
    arena_bin_index: int
    confirmed_allocation_source: str | None
    allocation_path: tuple[PathStep, ...]
    free_path: tuple[PathStep, ...]
    profile: ReleasePathProfile
    constraints: tuple[str, ...]
    address_assumptions: tuple[int, ...] = ()
    offline: bool = True
    network_requests: int = 0
    executed: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "abi": self.abi,
            "api": self.api,
            "request_size": self.request_size,
            "chunk_size": self.chunk_size,
            "tcache_configuration": self.tcache_configuration,
            "tcache_max_input": self.tcache_max_input,
            "tcache_count": self.tcache_count,
            "tcache_state_fact": self.tcache_state_fact,
            "tcache_bin_kind": self.tcache_bin_kind,
            "tcache_bin_index": self.tcache_bin_index,
            "tcache_size_eligible": self.tcache_size_eligible,
            "tcache_checked": self.tcache_checked,
            "tcache_selection_rule": self.tcache_selection_rule,
            "large_tcache_for_request": self.large_tcache_for_request,
            "fastbin_index": self.fastbin_index,
            "arena_bin_kind": self.arena_bin_kind,
            "arena_bin_index": self.arena_bin_index,
            "confirmed_allocation_source": self.confirmed_allocation_source,
            "allocation_path": [step.as_dict() for step in self.allocation_path],
            "free_path": [step.as_dict() for step in self.free_path],
            "profile": self.profile.as_dict(),
            "constraints": list(self.constraints),
            "address_assumptions": list(self.address_assumptions),
            "offline": self.offline,
            "network_requests": self.network_requests,
            "executed": self.executed,
        }


@_fail_closed
def release_profile(glibc_version: str) -> ReleasePathProfile:
    """Return one exact upstream x86-64 release-routing profile."""

    version = _exact_version(glibc_version)
    base = modern.profile_for(
        version, bits=64, source_profile=modern.SOURCE_RELEASE_TAG
    )
    minor = int(version.split(".")[1])
    if minor < 42:
        large_selection = "absent"
    elif minor == 42:
        large_selection = "first-chunk-greater-than-or-equal-within-sorted-bin"
    else:
        large_selection = "exact-chunk-size-within-sorted-bin"

    constraints = (
        "pristine upstream release tag and ordinary x86-64 LP64 ABI only",
        "non-default mxfast is not modeled; 2.40-2.42 use the release default",
        "bin occupancy, neighbors, arena ownership, top size, and mmap state are caller facts",
        "a tcache key match scans all bins only in 2.42 and 2.43",
        "unknown vendor patches and backports must be declined, not inferred",
    )
    return ReleasePathProfile(
        version=version,
        abi="x86_64-lp64",
        source_profile="upstream-release-tag",
        tcache_counter_field=base.counter_field,
        tcache_counter_semantics=base.counter_semantics,
        tcache_total_bins=base.tcache_total_bins,
        default_tcache_count=base.default_tcache_count,
        all_bin_double_free_scan=base.all_bin_double_free_scan,
        calloc_tcache_first=base.calloc_uses_tcache,
        fastbins_present=base.fastbins_present,
        default_max_fast_chunk=DEFAULT_MAX_FAST_CHUNK if base.fastbins_present else None,
        ordinary_small_free_staging=(
            "unsorted-after-coalescing"
            if version == "2.40"
            else "smallbin-after-coalescing"
        ),
        large_tcache_selection=large_selection,
        constraints=constraints,
    )


@_fail_closed
def largebin_index_64(chunk_size: int) -> int:
    """Evaluate glibc's published x86-64 arena ``largebin_index`` macro."""

    size = _integer(chunk_size, "chunk_size", maximum=MAX_REQUEST + 0x20)
    if size < MIN_LARGE_SIZE or size & 0xF:
        raise WPGAPGlibcError(
            "chunk_size must be a 0x10-aligned arena-large chunk"
        )
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


def _tcache_rule(profile: ReleasePathProfile, bin_kind: str | None) -> str | None:
    if bin_kind == "small":
        return "exact-size LIFO entry"
    if bin_kind == "large":
        return profile.large_tcache_selection
    return None


@_fail_closed
def plan_allocation(
    glibc_version: str,
    request_size: int,
    *,
    api: str = "malloc",
    tcache_max: int | None = None,
    tcache_count: int | None = None,
    tcache_state: str = "unknown",
) -> AllocatorPathPlan:
    """Plan an allocation's size classes and ordered conditional paths.

    ``tcache_state`` is a caller fact: ``hit`` means a usable entry satisfying
    the version's selection rule is present, while ``miss`` means no such entry
    is present.  ``unknown`` keeps both branches.  Arena occupancy is never
    invented, so only a confirmed tcache hit yields a confirmed source.
    """

    version = _exact_version(glibc_version)
    request = _integer(request_size, "request_size", maximum=MAX_REQUEST)
    selected_api = _choice(api, "api", SUPPORTED_APIS)
    state = _choice(tcache_state, "tcache_state", TCACHE_STATES)
    profile = release_profile(version)

    count = (
        profile.default_tcache_count
        if tcache_count is None
        else _integer(tcache_count, "tcache_count", maximum=MAX_TCACHE_COUNT)
    )
    if tcache_max is not None:
        _integer(tcache_max, "tcache_max", maximum=modern.MAX_TCACHE_TUNABLE)

    tcache = modern.plan_tcache(
        version,
        request,
        bits=64,
        tcache_max=tcache_max,
        source_profile=modern.SOURCE_RELEASE_TAG,
    )
    chunk = tcache.chunk_size
    size_eligible = tcache.tcache_eligible
    api_checks_tcache = selected_api == "malloc" or profile.calloc_tcache_first
    tcache_checked = size_eligible and count > 0 and api_checks_tcache
    if state == "hit" and not tcache_checked:
        raise WPGAPGlibcError(
            "tcache_state=hit contradicts this version/API/tunable profile"
        )

    selection_rule = _tcache_rule(profile, tcache.bin_kind)
    fast_index = None
    if profile.fastbins_present and chunk <= DEFAULT_MAX_FAST_CHUNK:
        fast_index = (chunk >> 4) - 2

    if chunk < MIN_LARGE_SIZE:
        arena_kind = "smallbin"
        arena_index = chunk >> 4
    else:
        arena_kind = "largebin"
        arena_index = largebin_index_64(chunk)

    allocation_steps: list[PathStep] = []

    def add_alloc(
        component: str,
        bin_kind: str | None,
        bin_index: int | None,
        condition: str,
        outcome: str,
    ) -> None:
        allocation_steps.append(
            PathStep(
                len(allocation_steps), component, bin_kind, bin_index,
                condition, outcome,
            )
        )

    if tcache_checked:
        if state == "hit":
            condition = "caller confirms an entry satisfying the selection rule"
            outcome = "return the cached chunk"
        elif state == "miss":
            condition = "caller confirms no entry satisfies the selection rule"
            outcome = "fall through to the arena path"
        else:
            condition = "if an entry satisfying the selection rule exists"
            outcome = "return it; otherwise fall through"
        add_alloc("tcache", tcache.bin_kind, tcache.bin_index, condition, outcome)
    else:
        if count == 0:
            reason = "tcache_count=0 disables the cache"
        elif not api_checks_tcache:
            reason = "glibc 2.40 calloc does not use the direct tcache path"
        else:
            reason = "normalized size is outside the active tcache ceiling"
        add_alloc("tcache-bypass", tcache.bin_kind, tcache.bin_index, reason, "continue")

    if fast_index is not None:
        add_alloc(
            "fastbin", "fastbin", fast_index,
            "if the exact default fastbin is nonempty",
            "pop its LIFO head; otherwise continue",
        )

    if arena_kind == "smallbin":
        add_alloc(
            "smallbin", "smallbin", arena_index,
            "if the exact smallbin is nonempty",
            "unlink a same-size chunk; otherwise continue",
        )
        add_alloc(
            "unsorted-scan", "unsorted", 1,
            "scan last remainder and unsorted survivors",
            "use a valid fit or sort survivors into regular bins",
        )
    else:
        if profile.fastbins_present:
            add_alloc(
                "malloc-consolidate", "fastbin", None,
                "if the arena reports pending fastchunks",
                "coalesce fastbins into normal free chunks before the large search",
            )
        add_alloc(
            "unsorted-scan", "unsorted", 1,
            "scan unsorted chunks before the regular largebin",
            "use a valid fit or sort survivors into regular bins",
        )
        add_alloc(
            "largebin", "largebin", arena_index,
            "if this largebin contains a best fit",
            "unlink the smallest adequate chunk; otherwise continue",
        )

    add_alloc(
        "binmap-search", "regular-bin", None,
        "if a later nonempty bin contains a splittable fit",
        "unlink and split; otherwise continue",
    )
    add_alloc(
        "top", "top", None,
        "if the arena top chunk is large enough",
        "split top and return; otherwise continue",
    )
    add_alloc(
        "sysmalloc", None, None,
        "arena bins and top cannot satisfy the request",
        "extend an arena or mmap according to dynamic runtime state",
    )

    free_steps: list[PathStep] = []

    def add_free(
        component: str,
        bin_kind: str | None,
        bin_index: int | None,
        condition: str,
        outcome: str,
    ) -> None:
        free_steps.append(
            PathStep(
                len(free_steps), component, bin_kind, bin_index,
                condition, outcome,
            )
        )

    minor = int(version.split(".")[1])
    free_tcache_enabled = size_eligible and count > 0
    if minor <= 42:
        add_free(
            "mmap-release", None, None,
            "if this is a directly mmapped chunk",
            "bypass arena/tcache lists and unmap it",
        )
    if free_tcache_enabled:
        mmap_note = (
            " and the chunk is arena-backed"
            if minor <= 42
            else " (the 2.43 mmap layout may also be cached)"
        )
        add_free(
            "tcache", tcache.bin_kind, tcache.bin_index,
            "if the selected bin has a remaining slot" + mmap_note,
            "insert in tcache; otherwise continue",
        )
    else:
        add_free(
            "tcache-bypass", tcache.bin_kind, tcache.bin_index,
            "size/configuration is not tcache-free eligible",
            "continue",
        )
    if minor >= 43:
        add_free(
            "mmap-release", None, None,
            "if the chunk is mmapped and was not cached",
            "unmap it",
        )
    if fast_index is not None:
        add_free(
            "fastbin", "fastbin", fast_index,
            "if tcache did not accept this arena-backed chunk",
            "push without coalescing",
        )
    add_free(
        "coalesce", None, None,
        "for an arena-backed chunk not accepted above",
        "merge free neighbors; the resulting size may change class",
    )
    if version == "2.40":
        add_free(
            "ordinary-free-staging", "unsorted", 1,
            "if the coalesced chunk does not merge into top",
            "place it in unsorted, including a small result",
        )
    else:
        add_free(
            "ordinary-free-staging", "smallbin-or-unsorted", None,
            "if the coalesced chunk does not merge into top",
            "small result -> smallbin[(size>>4)]; large result -> unsorted",
        )
    add_free(
        "top-merge", "top", None,
        "if the coalesced chunk borders top",
        "make it the new top chunk",
    )

    confirmed = None
    if state == "hit":
        confirmed = f"tcache[{tcache.bin_index}]"

    constraints = tuple(profile.constraints) + (
        "allocation source after a tcache miss requires exact live heap-state facts",
        "tcache_state=hit means a fitting entry, not merely a nonempty coarse large bin",
        "free destination depends on remaining tcache capacity and post-coalescing size",
        "mmap_threshold is dynamic; size alone cannot prove mmap versus arena service",
        "no runtime address is assumed or emitted by this size-only planner",
    )
    return AllocatorPathPlan(
        version=version,
        abi="x86_64-lp64",
        api=selected_api,
        request_size=request,
        chunk_size=chunk,
        tcache_configuration=(
            "release-default" if tcache_max is None else "explicit-tunable"
        ),
        tcache_max_input=tcache_max,
        tcache_count=count,
        tcache_state_fact=state,
        tcache_bin_kind=tcache.bin_kind,
        tcache_bin_index=tcache.bin_index,
        tcache_size_eligible=size_eligible,
        tcache_checked=tcache_checked,
        tcache_selection_rule=selection_rule,
        large_tcache_for_request=(tcache.bin_kind == "large" and tcache_checked),
        fastbin_index=fast_index,
        arena_bin_kind=arena_kind,
        arena_bin_index=arena_index,
        confirmed_allocation_source=confirmed,
        allocation_path=tuple(allocation_steps),
        free_path=tuple(free_steps),
        profile=profile,
        constraints=constraints,
    )


def _cli_int(value: str) -> int:
    try:
        return int(value, 0)
    except (TypeError, ValueError, OverflowError) as exc:
        raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline upstream glibc 2.40-2.43 size-to-bin path planner"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    profile = commands.add_parser("profile")
    profile.add_argument("version")
    plan = commands.add_parser("plan")
    plan.add_argument("version")
    plan.add_argument("request_size", type=_cli_int)
    plan.add_argument("--api", choices=SUPPORTED_APIS, default="malloc")
    plan.add_argument("--tcache-max", type=_cli_int)
    plan.add_argument("--tcache-count", type=_cli_int)
    plan.add_argument("--tcache-state", choices=TCACHE_STATES, default="unknown")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the guarded, deterministic JSON CLI."""

    try:
        try:
            args = _parser().parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        if args.command == "profile":
            result: ReleasePathProfile | AllocatorPathPlan = release_profile(args.version)
        elif args.command == "plan":
            result = plan_allocation(
                args.version,
                args.request_size,
                api=args.api,
                tcache_max=args.tcache_max,
                tcache_count=args.tcache_count,
                tcache_state=args.tcache_state,
            )
        else:  # pragma: no cover - required subparser makes this unreachable
            raise WPGAPGlibcError("unsupported command")
        print(json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")))
        return 0
    except WPGAPGlibcError as exc:
        print(f"wpgap_glibc_binpath: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # fail-closed CLI boundary
        print(
            f"wpgap_glibc_binpath: malformed input ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


__all__ = [
    "AllocatorPathPlan",
    "PathStep",
    "ReleasePathProfile",
    "SUPPORTED_VERSIONS",
    "WPGAPGlibcError",
    "largebin_index_64",
    "plan_allocation",
    "release_profile",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
