"""Code-enforced manual mode for the carried CTFd path (R-02).

ctf.platform.get_adapter(profile) already gives a manual event the manual adapter, which has no
network code. The carried CTFd path does not go through it: ctf.client.CTFd, ctf.submit.guarded_submit,
the built-in `ctf` read commands (me, list, pull, triage, status, check, wait, doctor's auth line) and
ctf.fastlane's rules-page GET. Each of them asks this module first. (B-006 moved `ctf submit`,
`python -m ctf.submit` and ctf.dynamic behind get_adapter and the SubmitGate; they still ask
refusal()/resolve() first, so a manual event is refused before any adapter, lock or file exists.)

    from ctf.platform import legacy
    profile = legacy.require("CTFd client")                       # a read: refuses manual events
    legacy.check(profile, "submit", submit=True)                  # a send: also submit_mode manual

Both raise before any session, socket or name lookup exists. The refusals, in order:

  NoProfile(NotAllowed)   no loadable event profile (CTF_EVENT unset with several profiles, a bad
                          profile): fail closed, naming the EventError.
  NotAllowed              the event's adapter kind is manual (platform.kind = "manual", or
                          rules.ai_on_platform = "forbidden": no automation touches that platform,
                          reads included), the same selection ctf.platform.adapter_kind() makes.
  NotAllowed              a submission (submit=True) on an event whose rules.submit_mode is "manual".
  NotSupported            the event's platform is not CTFd (e.g. gamemaster): the carried client
                          speaks only the CTFd API; use ctf.platform.get_adapter(profile).
"""
from __future__ import annotations

from .. import event as _event
from ..event import EventError, EventProfile
from .base import NotAllowed, NotSupported

LEGACY_KIND = "ctfd"


class NoProfile(NotAllowed):
    """The carried client refuses to run without an event profile to read the rules from."""


def refusal(profile: EventProfile, call: str, *, submit: bool = False) -> NotSupported | None:
    """The error `call` must raise under `profile`, or None when the carried CTFd path may make it."""
    rules = profile.rules
    if profile.platform.kind == "manual":
        return NotAllowed(f"{call}: event {profile.slug!r} is manual (platform kind manual): the player "
                          "works the platform by hand; no automated platform call, reads included")
    if rules.ai_on_platform == "forbidden":
        return NotAllowed(f"{call}: event {profile.slug!r} forbids automation on its platform "
                          "(rules.ai_on_platform = forbidden): manual mode, reads included")
    if submit and rules.submit_mode == "manual":
        return NotAllowed(f"{call}: event {profile.slug!r} has submit_mode manual: the player submits "
                          "by hand")
    if profile.platform.kind != LEGACY_KIND:
        return NotSupported(f"{call}: event {profile.slug!r} runs on a {profile.platform.kind} platform; "
                            "the carried client speaks only CTFd: use ctf.platform.get_adapter(profile)")
    return None


def check(profile: EventProfile, call: str, *, submit: bool = False) -> None:
    err = refusal(profile, call, submit=submit)
    if err is not None:
        raise err


def resolve(call: str, profile: EventProfile | None = None) -> EventProfile:
    """`profile`, else the current event (ctf.event.current()); none loadable is NoProfile."""
    if profile is not None:
        if not isinstance(profile, EventProfile):
            raise TypeError(f"{call}: profile must be an EventProfile, got {type(profile).__name__}")
        return profile
    try:
        return _event.current()
    except EventError as e:
        raise NoProfile(f"{call}: refused: no event profile to check the platform rules against ({e})") \
            from None


def require(call: str, *, submit: bool = False, profile: EventProfile | None = None) -> EventProfile:
    """Resolve the event profile and refuse `call` if its rules forbid it. Returns the profile."""
    prof = resolve(call, profile)
    check(prof, call, submit=submit)
    return prof
