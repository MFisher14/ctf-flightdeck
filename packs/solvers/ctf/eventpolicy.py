"""One per-event solve policy that every harness reads (B-173).

    from ctf import eventpolicy
    pol = eventpolicy.summary(profile)            # Policy: every policy value of the event, resolved
    eventpolicy.lines(pol)                         # what `python -m ctf policy show` prints
    pol.to_dict()                                  # what `python -m ctf policy show --json` prints
    eventpolicy.run_sweep(gate, cid, candidates, auth_id=..., note=...)   # one authorized, paced sweep run
    eventpolicy.point(profile, cid, "host:port", reason)                    # a player-pointed service
    eventpolicy.unpoint(profile, "host:port", reason)
    eventpolicy.guess_log(profile, cid)            # the logged guesses and sweep sends, with provenance

Why. Submit and solve policy differed between the Claude rules, the Codex rules and the player: at
CSCTF who submits and whether sweeps were allowed were re-argued, and the local guard made the player
re-authorize a sweep on every run; at PINK+ the guess and hint policy swung and agents kept
suggesting hints; at Spooky Claude treated a live challenge server the player pointed at as
forbidden infrastructure while Codex solved against it. Here the answer to each question is a field
of events/<slug>/event.toml (docs/CONTRACTS.md section 1); the one agent-rules template renders it
into CLAUDE.md and AGENTS.md (ctf/eventrules.py), `ctf policy show` prints it, and the code enforces
it: the submit gate (ctf/platform/rules.py: wrong_answer_stop, approved_extras, guess_budget,
authorized sweeps) and the scope guard (ctf/scope.py: live_service_scope, pointed_services).

The questions and where each answer lives:

  penalty            rules.wrong_penalty (points per wrong answer; absent = not known)
  throttle           [submit] per_minute / interval_s / per_challenge_interval_s (the B-006 queue)
  who submits        rules.submit_mode: auto = each solver on sight, confirm = the solver after the
                     player's yes, manual = the player by hand
  wrong quota        rules.wrong_answer_stop, and rules.approved_extras (may the player reopen it?)
  guesses            rules.guess_budget; every guess=True send is logged with its provenance note
  sweeps             [sweep] mode / max_count / interval_s / ttl_s
  hints              rules.hints_allowed, rules.hint_suggestions
  live services      rules.live_service_scope, rules.pointed_services
  platform           rules.ai_on_platform
  execution          rules.sandboxed_execution (B-242): may the runtime adapters run a delivered
                     managed or bytecode artifact in a pinned, networkless container? Default
                     forbidden; execution_refusal() is the gate binary.runtime_trace calls

Sweeps: the guard stays on by default. With [sweep] mode = "player-authorized" the player runs
`python -m ctf policy authorize-sweep <id> --count N --reason ...` once; the printed id authorizes
ONE run of `python -m ctf policy sweep <id> --auth <auth id> --candidates FILE` (or run_sweep() from
a script): up to N sends on that challenge, paced sweep.interval_s apart on top of the team queue,
with no per-attempt re-authorization. A second run with the same id is refused (a claim file under
<workdir>/sweeps/), and so is every send once the count is used or the authorization expired. The
run lists each value (its SHA-256) in that claim file before offering it, and the gate sends a sweep
value only when its run listed it, so `submit-queue drain` resends the run's own spooled sends and
never a hand-written spool record.

Pointed services: with rules.pointed_services = "allowed", a challenge service the player points
at (they give its address) is recorded with point(); the scope guard then admits that exact host
(and port). The platform is never admitted. "forbidden" (the default) refuses point().
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from . import event as _event
from . import ledger, paths, scope
from .platform.base import SubmitResult, SubmitStatus
from .platform.rules import EVENT as SUBMIT_EVENT
from .platform.rules import EventRules, challenge_key, sweep_claim_path
WHO_SUBMITS = {
    "auto": "each solver submits its own flag on sight through the gate (no orchestrator step)",
    "confirm": "the solver submits through the gate after the player's yes on each flag",
    "manual": "the player submits by hand; no agent submits anything",
}


class PolicyError(ValueError):
    """The event's policy forbids the request, or a value is unusable; the message names the key."""


# ------------------------------------------------------------------------------------------ summary

@dataclass(frozen=True)
class Policy:
    event: str
    submit_mode: str
    who_submits: str
    wrong_penalty: int | None
    per_minute: int
    interval_s: float
    per_challenge_interval_s: float
    wrong_answer_stop: int
    approved_extras: bool
    guess_budget: int
    sweep_mode: str
    sweep_max_count: int
    sweep_interval_s: float
    sweep_ttl_s: float
    hints_allowed: bool
    hint_suggestions: bool
    live_service_scope: tuple[str, ...]
    pointed_services: str
    pointed: tuple[str, ...] = field(default=())
    ai_on_platform: str = "allowed"
    web_state_changing: bool = False
    flag_sharing: str = "forbidden"
    sandboxed_execution: str = "forbidden"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["live_service_scope"] = list(self.live_service_scope)
        d["pointed"] = list(self.pointed)
        return d


def _addr(host: str, port: int | None) -> str:
    h = f"[{host}]" if ":" in host else host
    return h if port is None else f"{h}:{port}"


def summary(profile: _event.EventProfile) -> Policy:
    """Every policy value of the event, resolved (the player-pointed services read from the ledger)."""
    r, q, sw = profile.rules, profile.submit, profile.sweep
    pts = scope.pointed(profile, error=PolicyError) if r.pointed_services == "allowed" else ()
    return Policy(
        event=profile.slug, submit_mode=r.submit_mode, who_submits=WHO_SUBMITS[r.submit_mode],
        wrong_penalty=r.wrong_penalty, per_minute=q.per_minute, interval_s=q.interval_s,
        per_challenge_interval_s=q.per_challenge_interval_s, wrong_answer_stop=r.wrong_answer_stop,
        approved_extras=r.approved_extras, guess_budget=r.guess_budget, sweep_mode=sw.mode,
        sweep_max_count=sw.max_count, sweep_interval_s=sw.interval_s, sweep_ttl_s=sw.ttl_s,
        hints_allowed=r.hints_allowed, hint_suggestions=r.hint_suggestions,
        live_service_scope=tuple(r.live_service_scope), pointed_services=r.pointed_services,
        pointed=tuple(_addr(h, p) for h, p in pts), ai_on_platform=r.ai_on_platform,
        web_state_changing=r.web_state_changing, flag_sharing=r.flag_sharing,
        sandboxed_execution=r.sandboxed_execution)


def execution_refusal(profile: _event.EventProfile) -> str | None:
    """None when the event lets the runtime adapters run a delivered artifact in the pinned sandbox
    (rules.sandboxed_execution = "allowed"); otherwise the reason, naming the profile key. The one
    gate of B-242: nothing delivered is run for a trace unless this returns None."""
    value = profile.rules.sandboxed_execution
    if value == "allowed":
        return None
    return (f"event {profile.slug!r} has rules.sandboxed_execution = {value!r}: no delivered artifact "
            "is run, not even in the sandbox (the player sets it to \"allowed\" in event.toml when the "
            "event's rules permit running delivered files in an isolated container)")


def penalty_text(wrong_penalty: int | None) -> str:
    if wrong_penalty is None:
        return "not recorded in the profile: treat every wrong answer as costly"
    if wrong_penalty == 0:
        return "none (0 points), but every wrong answer still counts toward the stop"
    return f"{wrong_penalty} point(s) lost per wrong answer"


def lines(pol: Policy) -> list[str]:
    """The policy as `name  value` lines, in the order of the module docstring."""
    manual = pol.submit_mode == "manual"
    out = [f"event          {pol.event}",
           f"who submits    {pol.submit_mode}: {pol.who_submits}",
           f"penalty        {penalty_text(pol.wrong_penalty)}"]
    if manual:
        out.append("throttle       none (nothing is sent by the master)")
    else:
        out.append(f"throttle       {pol.per_minute}/min team-wide, {pol.interval_s:g}s between sends, "
                   f"{pol.per_challenge_interval_s:g}s per challenge (the submit queue)")
    extras = ("the player may approve more (`ctf submit-queue approve`)" if pol.approved_extras
              else "final: no approval reopens a challenge")
    out.append(f"wrong quota    stop after {pol.wrong_answer_stop} wrong on one challenge; {extras}")
    out.append(f"guesses        budget {pol.guess_budget} per challenge; each guess is logged with its "
               "note (`ctf policy guesses`)")
    if pol.sweep_mode == "player-authorized":
        out.append(f"sweeps         player-authorized, once per run: at most {pol.sweep_max_count} sends, "
                   f"{pol.sweep_interval_s:g}s apart, expiring after {pol.sweep_ttl_s:g}s")
    else:
        out.append("sweeps         forbidden")
    hints = "allowed, the player decides" if pol.hints_allowed else "never buy or request one"
    sugg = "agents may suggest one" if pol.hint_suggestions else "agents do not suggest them"
    out.append(f"hints          {hints}; {sugg}")
    out.append(f"live scope     {', '.join(pol.live_service_scope) or 'none'}")
    if pol.pointed_services == "allowed":
        out.append("pointed        allowed: a challenge service the player points at may be solved "
                   f"against (now: {', '.join(pol.pointed) or 'none'})")
    else:
        out.append("pointed        forbidden: only the live scope above")
    out.append(f"platform       automation {pol.ai_on_platform}; state-changing web requests "
               f"{'allowed' if pol.web_state_changing else 'need the player'}; flag sharing "
               f"{pol.flag_sharing}")
    if pol.sandboxed_execution == "allowed":
        out.append("execution      allowed: the runtime adapters may run a delivered managed or bytecode "
                   "artifact in a pinned container (no network, no host mount)")
    else:
        out.append("execution      forbidden: no delivered artifact is run by the master, not even in "
                   "the sandbox")
    return out


# ------------------------------------------------------------------------------------------ guesses

def guess_log(profile: _event.EventProfile, challenge_id: str | None = None,
              workdir: Path | None = None) -> list[dict]:
    """Every logged guess (guess=True) and sweep send for the event, oldest first, optionally for one
    challenge: the platform.submit records, with their provenance notes."""
    wd = paths.workdir(profile.slug) if workdir is None else Path(workdir)
    key = challenge_key(challenge_id) if challenge_id is not None else None
    return [r for r in ledger.read(wd)
            if r.get("event") == SUBMIT_EVENT and r.get("event_slug") == profile.slug
            and (r.get("guess") or r.get("sweep"))
            and (key is None or challenge_key(str(r.get("challenge_id", ""))) == key)]


# ------------------------------------------------------------------------------------------ pointed

def parse_address(text: str) -> tuple[str, int | None]:
    """"host", "host:port", "[v6]:port" or a bare IP -> (normalised host, port or None)."""
    t = str(text or "").strip()
    if "://" in t or "/" in t:
        raise PolicyError(f"{text!r}: give a host or host:port, not a URL or a network")
    port: int | None = None
    if t.startswith("["):
        host, sep, rest = t[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            raise PolicyError(f"{text!r} is not [ipv6] or [ipv6]:port")
        port_s = rest[1:] if rest else None
    elif t.count(":") == 1:
        host, port_s = t.split(":")
    else:
        host, port_s = t, None
    if port_s is not None:
        if not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
            raise PolicyError(f"{text!r}: the port must be 1-65535")
        port = int(port_s)
    host = host.strip().lower().rstrip(".")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        if not _event._HOST_RE.fullmatch(host):
            raise PolicyError(f"{text!r}: {host!r} is not a bare host name or IP address "
                              "(no wildcards: a point names one service)") from None
    return host, port


def point(profile: _event.EventProfile, challenge_id: str, address: str, reason: str,
          workdir: Path | None = None) -> dict:
    """Record a challenge service the player pointed at, so the scope guard admits it. Refused when
    the profile has rules.pointed_services = "forbidden" or the address is the platform."""
    if profile.rules.pointed_services != "allowed":
        raise PolicyError(f"event {profile.slug!r} has rules.pointed_services = "
                          f"{profile.rules.pointed_services!r}: only rules.live_service_scope may be "
                          "contacted (the player edits event.toml to change that)")
    if not reason or not reason.strip():
        raise PolicyError("a point needs a reason: the player's words naming the service")
    if not str(challenge_id).strip():
        raise PolicyError("a point names the challenge it is for")
    host, port = parse_address(address)
    for p_host, p_port in scope.policy(profile, error=PolicyError).platform:
        if host == p_host and (port is None or port == p_port):
            raise PolicyError(f"{_addr(host, port)} is the event platform ({p_host}:{p_port}), never a "
                              "challenge service")
    fields: dict[str, Any] = {"event_slug": profile.slug, "challenge_id": challenge_key(str(challenge_id)),
                              "host": host, "reason": reason.strip()}
    if port is not None:
        fields["port"] = port
    return ledger.append(scope.POINTED, workdir=_wd(profile, workdir), **fields)


def unpoint(profile: _event.EventProfile, address: str, reason: str, workdir: Path | None = None) -> dict:
    """Withdraw a point (the same host and port as it was recorded)."""
    if not reason or not reason.strip():
        raise PolicyError("an unpoint needs a reason")
    host, port = parse_address(address)
    fields: dict[str, Any] = {"event_slug": profile.slug, "host": host, "reason": reason.strip()}
    if port is not None:
        fields["port"] = port
    return ledger.append(scope.UNPOINTED, workdir=_wd(profile, workdir), **fields)


def _wd(profile: _event.EventProfile, workdir: Path | None) -> Path:
    return paths.workdir(profile.slug) if workdir is None else Path(workdir)


# ------------------------------------------------------------------------------------------ sweeps

class SweepError(PolicyError):
    """A sweep run cannot start: the authorization is missing, expired, used up or already run."""


@dataclass
class SweepReport:
    challenge_id: str
    auth_id: str
    outcome: str = "exhausted"          # accepted | exhausted | stopped
    reason: str = ""
    sent: int = 0
    skipped: list[str] = field(default_factory=list)      # duplicates the queue refused, never sent
    results: list[tuple[str, str]] = field(default_factory=list)   # (candidate, status)
    accepted: str | None = None


def _claim(wd: Path, auth_id: str, challenge_id: str, now: float) -> Path:
    if not auth_id.isalnum():
        raise SweepError(f"sweep authorization id {auth_id!r} is not an id `ctf policy authorize-sweep` prints")
    path = sweep_claim_path(wd, auth_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        try:
            prior = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prior = {}
        raise SweepError(f"sweep authorization {auth_id} was already used by a run (pid "
                         f"{prior.get('pid', '?')}); an authorization covers one run: ask the player "
                         "for a new one") from None
    try:
        os.write(fd, json.dumps({"pid": os.getpid(), "started": now, "challenge_id": challenge_id,
                                 "offered": []}).encode("utf-8"))
    finally:
        os.close(fd)
    return path


def _offer(path: Path, flag: str) -> None:
    """List `flag` (its SHA-256 only) in the run's claim file before the run offers it to the gate:
    the gate's check sends a sweep value only when the run listed it (EventRules.sweep_unclaimed),
    so a drained spool record of this run still goes and a hand-written one never does."""
    claim = json.loads(path.read_text(encoding="utf-8"))
    claim["offered"].append(hashlib.sha256(flag.encode("utf-8")).hexdigest())  # run_sweep dedupes
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, json.dumps(claim).encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def run_sweep(gate: Any, challenge_id: str, candidates: Iterable[str], *, auth_id: str, note: str,
              workdir: Path | None = None, clock: Callable[[], float] = time.time,
              sleep: Callable[[float], None] = time.sleep) -> SweepReport:
    """One player-authorized sweep run: send each candidate through the gate (and its queue) under
    `auth_id`, paced sweep.interval_s apart, until one is accepted, the candidates run out or the
    gate refuses (authorization used up or expired, challenge solved). Each send is a logged guess
    whose provenance is `note` plus its place in the run. Raises SweepError before any send when the
    authorization does not cover this challenge now or was already used by a run."""
    profile = gate.profile
    if not note or not note.strip():
        raise SweepError("a sweep needs a note: how the candidate list was built (it goes into the write-up)")
    cid = str(challenge_id)
    wd = _wd(profile, workdir)
    why = EventRules(profile, wd, clock=clock).sweep_refusal(cid, auth_id)
    if why:
        raise SweepError(why)
    claim = _claim(wd, auth_id, cid, clock())
    rep = SweepReport(challenge_id=cid, auth_id=auth_id)
    interval = profile.sweep.interval_s
    last_send: float | None = None
    seen: set[str] = set()
    for n, raw in enumerate(candidates, 1):
        flag = str(raw).strip()
        if not flag or flag in seen:
            continue
        seen.add(flag)
        if last_send is not None:
            wait = last_send + interval - clock()
            if wait > 0:
                sleep(wait)
        _offer(claim, flag)
        res: SubmitResult = gate.submit(cid, flag, provenance=f"{note.strip()} [sweep {auth_id} #{n}]",
                                        confirmed=True, guess=True, sweep=auth_id)
        if res.sent:
            last_send = clock()
            rep.sent += 1
        rep.results.append((flag, res.status.value))
        if res.accepted:
            rep.outcome, rep.accepted, rep.reason = "accepted", flag, res.message
            return rep
        if res.status is SubmitStatus.NOT_ALLOWED and not res.sent:
            if res.message.startswith("duplicate"):
                rep.skipped.append(flag)
                continue
            rep.outcome, rep.reason = "stopped", res.message
            return rep
        if not res.status.judged:
            rep.outcome, rep.reason = "stopped", f"unjudged ({res.status.value}): {res.message}"
            return rep
    rep.reason = "every candidate was tried"
    return rep
