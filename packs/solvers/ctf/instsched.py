"""Value-ordered slot scheduler for per-team container instances (B-003).

The problem (dev/SPEED-STUDY.md item 4, sessions/csctf-claude-event.md): a CTFd Docker plugin caps how
many instances a team may run at once (3 at CSCTF 2026). With more container challenges than slots, idle
slots and late starts cost real points — ~891 s of idle slots across 19 challenges, and the web/pwn
instance lanes dispatched at +321/+618/+1269 s through a human breakglass. This module decides, with no
model, which instances to run: start the highest-value open challenges up to the cap, and free a slot the
moment a challenge is solved (spawn-only-while-working, tear-down-on-solve).

Two layers, so the policy is pure and testable and the I/O is thin:

  * `plan(needs, cap=...)` -> `SlotPlan`: pure. Given every challenge that needs an instance (its point
    value, whether it is solved, whether we already run it) and the local cap, it returns which to stop
    (every running+solved one — the slot is released on solve), which unsolved challenges to start
    (highest value first, breaking ties by id, up to the free slots), which to keep running, and which
    are blocked for want of a slot. It never evicts a running unsolved challenge to make room: a started
    instance is being worked on.
  * `apply_plan(controller, plan, ...)` -> `[Action]`: calls `controller.stop_instance(id)` for the
    releases first (freeing slots), then `controller.start_instance(id)` for the starts, carrying the
    `InstanceInfo` (host:port for the handout) back. A `controller` is any object with the
    InstanceCapability methods — the SubmitGate from `ctf.platform.get_adapter`, or a fake in tests.

`SlotLedger` / `start_capped` / `stop_tracked` make the local cap bind across processes: the engine
(`ctf.instances.Instances`) counts in memory, so each CLI process used to start with an empty count.
`due_for_renewal` / `apply_renewals` renew running unsolved instances near expiry.

`permission_allowlist()` gives the harness allow-entries that let a solver subagent run the vetted
per-challenge `ctf instance` verbs without a safety-classifier breakglass (no whole-CLI catch-all;
`--profile`/`--event` and the team-wide `stop-all`/`schedule` are denied); raw container endpoints
are not allowed. B-003's finding was that classifier-blocked
`containers/api/request` calls forced a hand-run plugin call that drew cheating accusations
(sessions/csctf-claude-event.md:46-50); routing every instance op through the CLI and allow-listing only
that CLI closes it.

Nothing here contacts a platform directly, runs a model, or submits a flag.
"""
from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable


class ScheduleError(RuntimeError):
    """The scheduler cannot act: a bad cap, or a need record missing its id."""


# ------------------------------------------------------------------------------------- the inputs

@dataclass(frozen=True)
class InstanceNeed:
    """One challenge that uses a container instance, as the scheduler weighs it.

    `value` is the challenge's point worth (higher = scheduled first). `solved` frees its slot.
    `running` is whether we already hold a slot for it (from a live `instance_status` sweep or the
    tracked set). `expires_at`/`remaining_s` are optional and only used by renewal callers."""
    challenge_id: str
    value: int = 0
    solved: bool = False
    running: bool = False
    remaining_s: float | None = None

    def __post_init__(self):
        if self.challenge_id is None or str(self.challenge_id).strip() == "":
            raise ScheduleError("an InstanceNeed has no challenge_id")


# Tags that mark a CTFd challenge as using a per-team container instance. The platform has no single
# standard field for this, so the scheduler reads the challenge's tags; an operator can always name the
# container ids explicitly instead (`select_needs(only=...)`, `ctf instance schedule --challenge`).
DEFAULT_CONTAINER_TAGS = ("container", "docker", "remote", "instance", "on-demand", "web-instance")


def is_container(ch: Any, *, container_tags: Iterable[str] = DEFAULT_CONTAINER_TAGS) -> bool:
    """Whether a challenge object (platform.base.Challenge-shaped: `.tags`) looks like a container."""
    tags = {str(t).strip().lower() for t in (getattr(ch, "tags", ()) or ())}
    return bool(tags & {t.strip().lower() for t in container_tags})


def select_needs(challenges: Iterable[Any], *, solved_ids: Iterable[str] = (),
                 running_ids: Iterable[str] = (), only: Iterable[str] | None = None,
                 container_tags: Iterable[str] = DEFAULT_CONTAINER_TAGS) -> list[InstanceNeed]:
    """Build the scheduler's `InstanceNeed`s from a board (platform.base.Challenge objects: `.id`,
    `.points`, `.tags`, `.solved_by_team`). With `only`, exactly those ids are considered (the operator
    named the container challenges); otherwise a challenge is included when its tags mark it a container.
    `solved_ids`/`running_ids` layer live solve and running state over the board."""
    solved = {str(x) for x in solved_ids}
    running = {str(x) for x in running_ids}
    only_set = None if only is None else {str(x) for x in only}
    out: list[InstanceNeed] = []
    for ch in challenges:
        cid = str(getattr(ch, "id"))
        if only_set is not None:
            if cid not in only_set:
                continue
        elif not is_container(ch, container_tags=container_tags):
            continue
        out.append(InstanceNeed(
            cid, value=int(getattr(ch, "points", 0) or 0),
            solved=(cid in solved) or bool(getattr(ch, "solved_by_team", False)),
            running=cid in running))
    return out


# ------------------------------------------------------------------------------------- the plan

@dataclass(frozen=True)
class SlotPlan:
    to_stop: tuple[str, ...]      # running AND solved: release the slot now
    to_start: tuple[str, ...]     # unsolved, not running, highest value first, within the free slots
    keep: tuple[str, ...]         # running and not solved: left alone
    blocked: tuple[str, ...]      # want to start but no slot free (the cap is the ceiling)
    cap: int | None

    @property
    def free_after(self) -> int | None:
        """Slots still free once this plan is applied (None when there is no local cap)."""
        if self.cap is None:
            return None
        return max(self.cap - len(self.keep) - len(self.to_start), 0)


def plan(needs: Iterable[InstanceNeed], *, cap: int | None) -> SlotPlan:
    """Decide the slot assignment. Pure: no I/O. See the module docstring for the policy."""
    if cap is not None and (not isinstance(cap, int) or isinstance(cap, bool) or cap < 1):
        raise ScheduleError(f"cap must be a positive int or None, got {cap!r}")
    needs = list(needs)
    seen: set[str] = set()
    for n in needs:
        cid = str(n.challenge_id)
        if cid in seen:
            raise ScheduleError(f"challenge {cid} appears twice in the instance needs")
        seen.add(cid)

    running = [n for n in needs if n.running]
    to_stop = [str(n.challenge_id) for n in running if n.solved]        # release on solve
    keep = [str(n.challenge_id) for n in running if not n.solved]
    free = None if cap is None else max(cap - len(keep), 0)

    # Candidates to start: open (unsolved) and not already running, best value first, id as tiebreak.
    cands = sorted((n for n in needs if not n.solved and not n.running),
                   key=lambda n: (-int(n.value), str(n.challenge_id)))
    to_start, blocked = [], []
    for n in cands:
        if free is None or len(to_start) < free:
            to_start.append(str(n.challenge_id))
        else:
            blocked.append(str(n.challenge_id))
    return SlotPlan(tuple(to_stop), tuple(to_start), tuple(keep), tuple(blocked), cap)


def due_for_renewal(needs: Iterable[InstanceNeed], *, within_s: float) -> list[str]:
    """Running, unsolved challenges whose instance expires within `within_s` seconds (renew to hold the
    slot before the plugin reaps it). A need with no `remaining_s` is not renewed (nothing is known)."""
    if within_s < 0:
        raise ScheduleError(f"within_s must be >= 0, got {within_s}")
    out = []
    for n in needs:
        if n.running and not n.solved and n.remaining_s is not None and n.remaining_s <= within_s:
            out.append(str(n.challenge_id))
    return out


# ------------------------------------------------------------------------------------- applying it

@dataclass(frozen=True)
class Action:
    """One instance op the scheduler drove: op in start|stop|renew, ok, and either the InstanceInfo it
    returned or the error that was raised (named, never swallowed)."""
    op: str
    challenge_id: str
    ok: bool
    info: Any = None
    error: str | None = None

    @property
    def connect(self) -> str:
        return getattr(self.info, "connection_info", "") or ""


def apply_plan(controller: Any, p: SlotPlan, *,
               on_action: Callable[["Action"], None] | None = None,
               errors: type | tuple = Exception) -> list[Action]:
    """Carry out `p`: stop the released instances first (free the slots), then start the chosen ones.

    `controller` is any InstanceCapability (the SubmitGate from get_adapter, or a fake). An op that
    raises one of `errors` is recorded as a failed Action and does not stop the rest; anything else
    propagates. `on_action` is called after each op. Returns an Action per op, stops before starts."""
    out: list[Action] = []

    def do(op: str, fn: Callable[[str], Any], cid: str) -> None:
        try:
            info = fn(cid)
            act = Action(op, cid, True, info)
        except errors as e:  # noqa: BLE001 - each failure is reported by id, never dropped
            act = Action(op, cid, False, None, f"{type(e).__name__}: {e}")
        out.append(act)
        if on_action is not None:
            on_action(act)

    for cid in p.to_stop:
        do("stop", controller.stop_instance, cid)
    for cid in p.to_start:
        do("start", controller.start_instance, cid)
    return out


def remaining_from(info: Any, now: float) -> float | None:
    """Seconds until an InstanceInfo's absolute `expires_at`, or None when the plugin gave no expiry.
    (`InstanceNeed.remaining_s` is relative; the adapter reports `expires_at` as an epoch.)"""
    exp = getattr(info, "expires_at", None)
    if not isinstance(exp, (int, float)) or isinstance(exp, bool):
        return None
    return float(exp) - float(now)


def apply_renewals(controller: Any, ids: Iterable[str], *,
                   on_action: Callable[["Action"], None] | None = None,
                   errors: type | tuple = Exception) -> list[Action]:
    """Renew each id (`controller.renew_instance`), one `renew` Action per id; a failure is recorded by
    id and does not stop the rest. A controller with no `renew_instance` is a ScheduleError (named),
    never a silent skip."""
    ids = [str(x) for x in ids]
    if not ids:
        return []
    renew = getattr(controller, "renew_instance", None)
    if renew is None:
        raise ScheduleError("renewal asked for, but this event's instance plugin has no renew route "
                            "(renew_instance is unavailable)")
    out: list[Action] = []
    for cid in ids:
        try:
            act = Action("renew", cid, True, renew(cid))
        except errors as e:  # noqa: BLE001 - reported by id
            act = Action("renew", cid, False, None, f"{type(e).__name__}: {e}")
        out.append(act)
        if on_action is not None:
            on_action(act)
    return out


# ------------------------------------------------------------------------------------- cross-process slots

class CapReached(ScheduleError):
    """A start would exceed the event's local slot cap (counted across every process, via SlotLedger)."""


# States that hold a plugin slot. Anything else (stopped, unknown: the plugin no longer reports a
# connection) is dropped from the ledger when it is re-read.
LIVE_STATES = frozenset({"running", "starting"})
SLOT_LEDGER_NAME = "slots.json"


class SlotLedger:
    """The instances this team started through `ctf instance`, shared by every process on the machine.

    `ctf.instances.Instances` counts its cap in memory, so each CLI process (each solver subagent) used
    to start with an empty count and the local cap never bound across processes. This is a small JSON
    file (`{"running": [ids]}`) under an exclusive flock: `with SlotLedger(path) as led:` holds the lock
    for the whole check-and-start, so two concurrent `start`s cannot both take the last slot. The file is
    written back on exit (also after an error, so a start that did happen is never forgotten). A corrupt
    file is a ScheduleError naming it, never read as empty."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._fd: int | None = None
        self._ids: set[str] | None = None

    def __enter__(self) -> "SlotLedger":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._ids = self._read()
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def __exit__(self, *exc) -> None:
        try:
            self._write()
        finally:
            fd, self._fd = self._fd, None
            if fd is not None:
                os.close(fd)          # closing the descriptor releases the flock

    def _read(self) -> set[str]:
        if not self.path.exists():
            return set()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ScheduleError(f"instance slot ledger {self.path} is unreadable ({e}); fix or remove "
                                "it after checking `ctf instance list`") from None
        ids = data.get("running") if isinstance(data, dict) else None
        if not isinstance(ids, list) or not all(isinstance(x, str) and x for x in ids):
            raise ScheduleError(f"instance slot ledger {self.path} is malformed (want {{\"running\": "
                                "[ids]}); fix or remove it after checking `ctf instance list`")
        return set(ids)

    def _write(self) -> None:
        if self._ids is None:
            return
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps({"running": sorted(self._ids)}) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)

    def _need(self) -> set[str]:
        if self._ids is None or self._fd is None:
            raise ScheduleError("SlotLedger used outside its `with` block (the lock is not held)")
        return self._ids

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(self._need())

    def add(self, cid: str) -> None:
        self._need().add(str(cid))

    def discard(self, cid: str) -> None:
        self._need().discard(str(cid))


def slot_ledger_path(workdir: Path | str) -> Path:
    """The ledger file for an event, under its workdir (`ctf.paths.workdir(slug)`)."""
    return Path(workdir) / "instances" / SLOT_LEDGER_NAME


def reconcile(controller: Any, ledger: SlotLedger, *, errors: type | tuple = Exception,
              on_error: Callable[[str, BaseException], None] | None = None) -> dict[str, Any]:
    """Re-read every tracked id with `controller.instance_status` and drop from the ledger the ones no
    longer live. Returns {id: InstanceInfo | None} for the ids still counted. A status call that raises
    one of `errors` keeps the id counted with None (the cap is a ceiling: an unreadable slot is assumed
    held) and is reported through `on_error`; anything else propagates."""
    live: dict[str, Any] = {}
    for cid in sorted(ledger.ids):
        try:
            info = controller.instance_status(cid)
        except errors as e:  # noqa: BLE001 - kept counted, reported by id
            live[cid] = None
            if on_error is not None:
                on_error(cid, e)
            continue
        if getattr(info, "state", None) in LIVE_STATES:
            live[cid] = info
        else:
            ledger.discard(cid)
    return live


def start_capped(controller: Any, ledger: SlotLedger, cid: str, *, cap: int | None,
                 errors: type | tuple = Exception,
                 on_error: Callable[[str, BaseException], None] | None = None) -> Any:
    """Start our instance for `cid` unless that would exceed `cap` across every process.

    Call inside `with ledger:`. The ledger is reconciled against live status first; if `cid` is already
    live its current InstanceInfo is returned (no second slot). Otherwise, with `cap` set and the other
    live slots already at the cap, CapReached names them. A successful start is recorded."""
    if cap is not None and (not isinstance(cap, int) or isinstance(cap, bool) or cap < 1):
        raise ScheduleError(f"cap must be a positive int or None, got {cap!r}")
    cid = str(cid)
    live = reconcile(controller, ledger, errors=errors, on_error=on_error)
    if live.get(cid) is not None:
        return live[cid]
    others = sorted(set(live) - {cid})
    if cap is not None and len(others) >= cap:
        raise CapReached(f"at the local instance cap ({cap} held: {', '.join(others)}); stop one "
                         f"(`ctf instance stop ID`) before starting {cid}")
    info = controller.start_instance(cid)
    ledger.add(cid)
    return info


def stop_tracked(controller: Any, ledger: SlotLedger, cid: str) -> Any:
    """Stop our instance for `cid` and free its ledger slot. A stop that raises leaves the slot counted
    (it may still be running); the next reconcile drops it once the plugin reports it gone."""
    cid = str(cid)
    info = controller.stop_instance(cid)
    ledger.discard(cid)
    return info


# ------------------------------------------------------------------------------------- permissions

# The per-challenge, scope-locked, point-safe CLI verbs a solver subagent may run unattended. `stop-all`
# and `schedule` act on every slot the team holds, so they stay with the operator / dispatcher.
SOLVER_VERBS = ("start", "status", "renew", "stop", "list")
OPERATOR_VERBS = ("stop-all", "schedule")
# Parent options that pick the event: never allowed to a solver (a self-written profile could point the
# platform client, and its credentials, at another host). The CLI also refuses a --profile outside
# events/ (ctf.cli.instance), and argparse rejects these options after the verb.
_EVENT_OPTIONS = ("--profile", "--event")


def permission_allowlist(*, python: str = "python") -> list[str]:
    """Harness allow-entries (Claude Code `permissions.allow` shape) that let a solver subagent drive
    its own instances through the vetted `ctf instance` CLI without a safety-classifier breakglass.

    Each entry is one verb prefix (`<python> -m ctf instance <verb>`, optionally with `--json` before
    the verb); there is no catch-all for the whole CLI, so `--profile`/`--event` (which must precede the
    verb) and the team-wide `stop-all`/`schedule` are not allowed. Not raw container endpoints, curl, or
    arbitrary Bash: the allowance can never spend points, touch another team's instance, or reach an
    unreleased challenge (the CLI's scope lock and cross-process cap enforce that). `python` names the
    interpreter the harness invokes."""
    base = f"{python} -m ctf instance"
    allow = [f"Bash({base} {verb}:*)" for verb in SOLVER_VERBS]
    allow += [f"Bash({base} --json {verb}:*)" for verb in SOLVER_VERBS]
    return allow


def permission_denylist(*, python: str = "python") -> list[str]:
    """Explicit denies for the solver profile: the event-selecting options and the team-wide verbs."""
    base = f"{python} -m ctf instance"
    deny = [f"Bash({base} {opt}:*)" for opt in _EVENT_OPTIONS]
    deny += [f"Bash({base} {verb}:*)" for verb in OPERATOR_VERBS]
    deny += [f"Bash({base} --json {verb}:*)" for verb in OPERATOR_VERBS]
    return deny


def permission_profile(*, python: str = "python") -> dict:
    """The solver allow/deny lists wrapped as a settings.json fragment an operator pastes into the
    solver subagents' harness config."""
    return {"permissions": {"allow": permission_allowlist(python=python),
                            "deny": permission_denylist(python=python)}}
