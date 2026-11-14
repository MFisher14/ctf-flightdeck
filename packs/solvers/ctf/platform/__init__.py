"""Platform adapters, selected by the event profile's platform.kind.

    from ctf.platform import get_adapter
    plat = get_adapter(profile)       # a SubmitGate around the kind's adapter, event rules and the
                                      # cross-process submit queue installed

Each kind is one module, ctf/platform/<kind>.py, with make_adapter(profile). Adding a kind means
adding a file; there is no registry to edit. A kind with no module fails loudly.

An event whose rules say ai_on_platform = "forbidden" gets the manual adapter whatever its platform
kind: no automation touches that platform, reads included (code-enforced manual mode).
"""
from __future__ import annotations

import importlib

from ..event import PLATFORM_KINDS, EventProfile
from .base import (Challenge, ChallengeSolve, FileRef, InstanceCapability, InstanceInfo,  # noqa: F401
                   NotAllowed, NotSupported, PlatformAdapter, PlatformError, ScoreRow, SolvesCapability,
                   SubmitResult, SubmitStatus, TeamSolve, challenge_solves, supports_instances)
from .policy import AttemptRef, RecordError, SubmitGate  # noqa: F401


def adapter_kind(profile: EventProfile) -> str:
    """The adapter module the profile selects: its platform kind, or manual when automation may not
    touch the platform at all."""
    if profile.rules.ai_on_platform == "forbidden":
        return "manual"
    return profile.platform.kind


def get_adapter(profile: EventProfile) -> SubmitGate:
    kind = adapter_kind(profile)
    if kind not in PLATFORM_KINDS:
        raise PlatformError(f"unknown platform kind {kind!r}")
    modname = f"{__name__}.{kind}"
    try:
        mod = importlib.import_module(modname)
    except ModuleNotFoundError as e:
        if e.name != modname:
            raise
        raise PlatformError(f"no adapter for platform kind {kind!r}: {modname} does not exist yet "
                            "(B-005 builds it)") from None
    make = getattr(mod, "make_adapter", None)
    if make is None:
        raise PlatformError(f"{modname} has no make_adapter(profile)")
    adapter = make(profile)
    if not isinstance(adapter, PlatformAdapter):
        raise PlatformError(f"{modname}.make_adapter returned {type(adapter).__name__}, "
                            "which does not implement PlatformAdapter")
    from . import halloffame, queue, rules, wire  # local: they import policy/event, which this module re-exports
    gate = SubmitGate(adapter, profile)
    rules.install(gate)
    halloffame.install(gate)   # B-044: Hall of Fame check on every timed result, teammate-attempt guard
    from .. import residual
    residual.install(gate)     # B-254: no plain value on an id marked residual without the player's go
    queue.install(gate)     # B-006: the cross-process submit queue (dedupe, pacing, retry, spool)
    wire.install(gate, adapter)   # B-140: every HTTP request journaled and budgeted (wire.of(gate))
    return gate
