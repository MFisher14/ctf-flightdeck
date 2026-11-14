"""Pre-event work, by default: the doctor and a rehearsal, then only the builds the ranking approved
(B-008, "pay for the build once").

    from ctf import preevent
    steps = preevent.plan(profile, ranking)     # doctor, rehearsal, approved builds in rank order
    results = preevent.run_hooks(profile)       # runs the doctor and rehearsal hooks

The two hooks are B-039's (`fn(profile: EventProfile) -> HookResult`):

  doctor_hook     ctf.doctor.run_checks(profile): profile, announced-vs-routed categories, router,
                  the Codex model and ONE real Codex smoke call, the submit dry run, instances. Any
                  failed check fails the hook; warnings and skipped checks are listed in the detail.
  rehearsal_hook  ctf.rehearsal.rehearse(profile) in a temp folder: one wave replayed end to end
                  against a fake CTFd on 127.0.0.1 (or the manual drop folder). Any failed step fails it.

A hook that crashes or returns something else is a "fail" with the reason. "stub" stays a status so a
hook that is not built yet can say so, and it never counts as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .buildplan import Ranking
from .event import EventProfile

HOOK_STATUSES = ("ok", "fail", "stub")


@dataclass(frozen=True)
class HookResult:
    name: str
    status: str             # ok | fail | stub
    detail: str

    @property
    def passed(self) -> bool:
        return self.status == "ok"


@dataclass(frozen=True)
class Step:
    kind: str               # hook | build
    name: str
    detail: str


def doctor_hook(profile: EventProfile) -> HookResult:
    """Preflight doctor (B-039): profile, category routes, router, Codex smoke call, submit dry run."""
    from . import doctor
    checks = doctor.run_checks(profile)
    bad = doctor.failed(checks)
    if bad:
        return HookResult("doctor", "fail", f"{len(bad)} check(s) failed: "
                          + "; ".join(f"{c.name}: {c.detail}" for c in bad))
    soft = [c for c in checks if c.status in ("warn", "skip")]
    detail = f"{len(checks) - len(soft)} ok"
    if soft:
        detail += "; " + "; ".join(f"{c.status} {c.name}: {c.detail}" for c in soft)
    return HookResult("doctor", "ok", detail)


def rehearsal_hook(profile: EventProfile) -> HookResult:
    """Wave rehearsal (B-039): one wave replayed end to end against a fake CTFd on 127.0.0.1."""
    import tempfile
    from pathlib import Path

    from . import rehearsal
    with tempfile.TemporaryDirectory(prefix="ctf-rehearsal-") as td:
        try:
            rep = rehearsal.rehearse(profile, workdir=Path(td) / "run")
        except rehearsal.RehearsalError as e:
            return HookResult("rehearsal", "fail", f"cannot rehearse: {e}")
    if not rep.passed:
        return HookResult("rehearsal", "fail", "; ".join(f"{s.name}: {s.detail}" for s in rep.failures()))
    warns = [s for s in rep.steps if s.status == "warn"]
    detail = f"{len(rep.steps)} steps passed in {rep.timings.get('total', 0.0):.1f}s"
    if warns:
        detail += "; " + "; ".join(f"warn {s.name}: {s.detail}" for s in warns)
    return HookResult("rehearsal", "ok", detail)


HOOKS: tuple[tuple[str, Callable[[EventProfile], HookResult]], ...] = (
    ("doctor", doctor_hook),
    ("rehearsal", rehearsal_hook),
)


def run_hooks(profile: EventProfile) -> list[HookResult]:
    out = []
    for name, fn in HOOKS:
        try:
            r = fn(profile)
        except Exception as e:  # a crashing hook is a failure with its reason, never a pass
            r = HookResult(name, "fail", f"hook raised {type(e).__name__}: {e}")
        if not isinstance(r, HookResult) or r.status not in HOOK_STATUSES:
            r = HookResult(name, "fail", f"hook returned {r!r}, not a HookResult")
        out.append(r)
    return out


def plan(profile: EventProfile, ranking: Ranking | None) -> list[Step]:
    """The default pre-event plan: doctor, rehearsal, then the approved builds (none without a
    ranking, and none with the default effort budget of 0)."""
    steps = [Step("hook", name, (fn.__doc__ or "").strip().splitlines()[0]) for name, fn in HOOKS]
    if ranking is not None:
        if ranking.event != profile.slug:
            raise ValueError(f"ranking is for event '{ranking.event}', not '{profile.slug}'")
        for e in ranking.approved():
            steps.append(Step("build", e.id, f"#{e.rank} {e.title} (score {e.score:g}, {e.effort})"))
    return steps
