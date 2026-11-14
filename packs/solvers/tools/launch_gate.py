"""Budget gate for the agent launchers (R-09): tools/codex_launch and tools/claude_launch.

With `--challenge ID` (or $CTF_CHALLENGE) a launcher opens a Gate on the event ledger
(ctf.budget.LedgerMeter) and:

  * refuses to launch when the challenge is at its cap, stopped by a team solve, stopped by hand, or
    past the no-progress timer -- naming the reason and the command that lifts it
    (`python -m ctf budget extend ID ...` for a cap, `python -m ctf budget resume ID` for a manual or
    no-progress stop; a team-solve stop is final);
  * runs the agent as a supervised child instead of exec'ing it, re-checks the gate every
    `poll_seconds`, and stops the agent when the challenge becomes capped or stopped mid-run;
  * charges spend read from the agent's own usage output, where the harness prints one:
      claude -p  -> `--output-format stream-json` (assistant lines priced with tools/ledger/pricing.json,
                    de-duplicated by message id; the final `result` line's total_cost_usd tops it up
                    when it is higher, so the harness's own figure is never undercut);
      codex exec -> `--json` (`turn.completed` usage, priced for the launcher's --model).
    An interactive TUI prints no usage; its spend is not metered by the launcher and the launcher
    says so (feed it with `python -m tools.ledger feed`). The stop signals still apply to it.

Exit codes: the agent's own code when it ends by itself; EXIT_REFUSED (3, as `tools.ledger feed` at the
cap) when the gate refuses a launch or stops a running agent; 2 for a launcher error.

Ledger events written here: agent_launch {challenge_id, harness, mode, metered, pid, model?, role?,
and, for a routed launch (B-201, tools/route_launch.py), difficulty?, effort? (the effort the agent
was launched at: an explicit --effort, else the route's), tier?, route?, category?, tier_budget_usd?}, agent_refused {challenge_id, harness, reason}, agent_exit {challenge_id, harness,
rc, reason?}. A speed-tier route sets Gate.agent_cap_usd: once this run has been charged that much the
agent is stopped like a capped one, with reason "route_budget".
Spend goes in as ordinary `spend` events with source "launcher:<harness>". From a metered run's output
the B-101 stages are recorded too (ctf/stages.py AgentStreamTap): first_tool {by, tool} once, and a
candidate {by, flag_sha256} per distinct flag-format value the agent sees (never the value), and at most
one agent_stop {reason, detail, model?} on a terminal refusal / provider error (B-016 reroutes on it).

B-143 (ctf/spawn.py): after the budget check, admit() runs the per-challenge agent gate (admit_spawn).
$CTF_SPAWN_ID names a spawn admitted by `ctf spawn request` (checked and marked `spawn_bound`); without
it the run is its own `spawn` request (mode "launch"). The 6th agent on a challenge is held for the
player (`ctf spawn allow`) and refused here with exit 3. Every record the gate writes for an admitted
run carries `spawn_id`. A run that may not spawn (a helper, a forked child) is started with the
harness's spawn tool off (no_spawn_args). An admitted run whose agent never starts (the launcher fails
between admission and the exec) gives its seat back (release_unstarted: `spawn_void` for the run's own
spawn, `spawn_unbound` for a bound $CTF_SPAWN_ID); the launchers call it on every return path.

B-175 (ctf/jobs.py, ctf/sessions.py): every supervised agent gets a fresh job owner. Its environment
carries CTF_JOB_OWNER (the owner label), CTF_JOB_OWNER_PID (this launcher's pid, whose start time
pins the identity) and CTF_JOBS_DIR, so each `ctf job start` the agent makes is recorded against it;
when the agent exits (agent_exit recorded) the launcher stops every live job of that owner and
records `jobs_reaped {owner, stopped, failed}`. With --session NAME (or $CTF_SESSION) the launcher
first claims the session name (claim_session) and refuses with exit 3 while a previous holder is
alive by pid AND start time; the claim is released when the launcher returns. An exec'd (ungated)
agent gets the same owner variables (exec_owner_env; the pid is the agent itself after exec).

Agent output is data: only the usage fields are read from it.
"""
from __future__ import annotations

import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from ctf import budget as _budget
from ctf import env as _env
from ctf import event as _event
from ctf import jobs as _jobs
from ctf import ledger as _ledger
from ctf import sessions as _sessions
from tools import process_group as _pg
from tools.ledger import pricing as _pricing
from tools.ledger import scan as _scan

EXIT_REFUSED = 3
ROUTE_BUDGET = "route_budget"    # B-201: a speed-tier run spent its route's budget_usd
DEFAULT_POLL_SECONDS = 15.0
INTERACTIVE_TERM_GRACE = 5.0


class GateRefused(RuntimeError):
    """The challenge may not be worked on now. `reason`: at_cap | team_solve | no_progress | manual."""

    def __init__(self, challenge_id: str, reason: str, message: str):
        super().__init__(message)
        self.challenge_id, self.reason = challenge_id, reason


class GateError(ValueError):
    """The gate cannot be applied as asked (e.g. spend that cannot be priced)."""


def challenge_from(arg: str | None) -> str | None:
    """--challenge, else $CTF_CHALLENGE, else None (gate off)."""
    cid = arg if arg is not None else _env.get("CTF_CHALLENGE")
    if cid is not None and not cid.strip():
        raise GateError("--challenge / CTF_CHALLENGE is empty")
    return cid


def role_from(arg: str | None) -> str | None:
    """B-096: the agent's work role for cost accounting -- --role, else $CTF_ROLE, else None. A given
    role must be one of ctf.stages.SPEND_CATEGORIES (solve, build, verify, doc, orchestrate, guardian,
    other), so verify-role spend can be told apart from solve-role spend when deciding the Opus/Sonnet
    split (EFFICIENCY-PLAN 3.8). Recorded on the agent_launch event; never routes a model on its own."""
    role = arg if arg is not None else _env.get("CTF_ROLE")
    if role is None:
        return None
    role = role.strip()
    if not role:
        raise GateError("--role / CTF_ROLE is empty")
    from ctf import stages as _stages
    if role not in _stages.SPEND_CATEGORIES:
        raise GateError(f"unknown role {role!r}; one of: {', '.join(_stages.SPEND_CATEGORIES)}")
    return role


def refusal_text(st: _budget.ChallengeStatus, reason: str) -> str:
    cid = st.challenge_id
    if reason == "at_cap":
        return (f"challenge {cid} is at its budget cap: spent ${st.spent_usd:.2f} of ${st.cap_usd:.2f}. "
                f"To continue, a person at a terminal runs: "
                f"python -m ctf budget extend {cid} --usd <amount> --reason <why>")
    if reason == "team_solve":
        by = f" by {st.stop_by}" if st.stop_by else ""
        return (f"challenge {cid} was solved{by} (team_solve stop). That stop is final: there is "
                f"nothing to extend or resume (python -m ctf budget status {cid})")
    what = {"no_progress": "stopped for no progress (20-minute timer on a high-value tail)",
            "manual": "stopped by hand"}.get(reason, f"stopped ({reason})")
    return (f"challenge {cid} is {what}. To continue, a person at a terminal runs: "
            f"python -m ctf budget resume {cid}")


class Gate:
    """One challenge's budget gate over a Meter with LedgerMeter's check/status API."""

    def __init__(self, meter: _budget.LedgerMeter, challenge_id: str, *, harness: str, flags=None,
                 role: str | None = None):
        self.meter, self.challenge_id, self.harness = meter, challenge_id, harness
        self.source = f"launcher:{harness}"
        self.flags = flags              # the event's FlagFormat: candidate stages (B-101)
        self.role = role                # B-096: the agent's work role, recorded on agent_launch
        self.spawn = None               # B-143: the admitted ctf.spawn.Decision this run is
        self.spawn_bound = False        # B-143: the spawn came from $CTF_SPAWN_ID (bound, not requested)
        self.spawn_recorded = False     # B-143: admission wrote a ledger record (not a dry run)
        self.started = False            # an agent_launch was recorded: the agent is running
        self.launch_fields: dict = {}   # B-201: the route's fields, added to agent_launch
        self.agent_cap_usd: float | None = None   # B-201: a speed-tier route's own budget_usd
        self.agent_spent_usd = 0.0      # what this run has been charged

    def _refused(self, reason: str) -> GateRefused:
        st = self.meter.status(self.challenge_id)
        if reason == ROUTE_BUDGET:
            msg = (f"challenge {self.challenge_id}: this agent spent ${self.agent_spent_usd:.2f} of the "
                   f"${self.agent_cap_usd:.2f} its speed-tier route allows (B-201 [routing] budget_usd). "
                   "Relaunch on the standard tier, or raise the route's budget_usd in event.toml")
        else:
            msg = refusal_text(st, reason)
        _ledger.append("agent_refused", workdir=self.meter.workdir, challenge_id=self.challenge_id,
                       harness=self.harness, reason=reason)
        return GateRefused(self.challenge_id, reason, msg)

    def check(self) -> _budget.ChallengeStatus:
        """meter.check(): records a no-progress stop or a cap checkpoint as B-033 does."""
        try:
            return self.meter.check(self.challenge_id)
        except _budget.ChallengeStopped as e:
            raise self._refused(e.reason) from None
        except _budget.BudgetExceeded:
            raise self._refused("at_cap") from None

    def peek(self) -> tuple[_budget.ChallengeStatus, str | None]:
        """What check() would decide, without writing anything (for --dry-run)."""
        st = self.meter.status(self.challenge_id)
        if st.stop_reason:
            return st, st.stop_reason
        if st.timer_applies and st.idle_seconds is not None \
                and st.idle_seconds >= self.meter.no_progress_seconds:
            return st, "no_progress"
        if st.spent_usd >= st.cap_usd:
            return st, "at_cap"
        return st, None

    def charge(self, usd: float, tokens: int) -> None:
        if usd <= 0 and tokens <= 0:
            return
        try:
            self.meter.add_spend(self.challenge_id, round(max(0.0, usd), 10), max(0, int(tokens)),
                                 source=self.source)
        except _budget.BudgetExceeded:
            raise self._refused("at_cap") from None
        finally:
            self.agent_spent_usd += max(0.0, usd)
        if self.agent_cap_usd is not None and self.agent_spent_usd >= self.agent_cap_usd:
            raise self._refused(ROUTE_BUDGET)

    def record(self, event_type: str, **fields) -> None:
        if event_type == "agent_launch":
            self.started = True
        if self.spawn is not None and "spawn_id" not in fields:
            fields["spawn_id"] = self.spawn.spawn_id        # B-143: ties launch/exit/stop to the spawn
        _ledger.append(event_type, workdir=self.meter.workdir, challenge_id=self.challenge_id,
                       harness=self.harness, **fields)


def open_gate(challenge_id: str, *, harness: str, event_slug: str | None = None,
              role: str | None = None) -> Gate:
    """The gate for one challenge of the event (--event, else $CTF_EVENT / the only profile).
    The ledger is the event workdir's ($CTF_WORKDIR wins). Raises EventError when no event resolves."""
    prof = _event.load(event_slug) if event_slug else _event.current()
    meter = _budget.LedgerMeter(prof, on_cap=lambda st, path: None)   # the refusal names the command
    from ctf import flagfmt as _flagfmt
    return Gate(meter, challenge_id, harness=harness, flags=_flagfmt.for_profile(prof), role=role)


def status_line(st: _budget.ChallengeStatus) -> str:
    return (f"budget gate: challenge {st.challenge_id}: spent ${st.spent_usd:.2f} of ${st.cap_usd:.2f} cap"
            f" ({st.state})")


# ------------------------------------------------------------------ usage readers (agent stdout)

@dataclass
class Increment:
    usd: float
    tokens: int


class ClaudeStreamUsage:
    """Usage from `claude -p --output-format stream-json`. Assistant lines are priced per message id
    (a later line for the same id with more output tokens is charged the difference); the `result`
    line's total_cost_usd is the harness's own total and tops the charge up when it is higher."""

    harness = "claude"

    def __init__(self, prices: dict | None = None):
        self.prices = prices if prices is not None else _pricing.load_prices()
        self._parser = _scan.ClaudeParser()
        self._seen: dict[str, dict] = {}
        self.usd = 0.0
        self.tokens = 0

    def feed(self, line: str) -> list[Increment]:
        out: list[Increment] = []
        got = self._parser.feed(line)
        if got:
            mid, row = got
            old = self._seen.get(mid)
            if old is None or row.get("output", 0) > old["output"]:
                usd = _pricing.cost(row, self.prices)
                tok = _pricing.tokens(row)
                d_usd = usd - (old["usd"] if old else 0.0)
                d_tok = tok - (old["tok"] if old else 0)
                self._seen[mid] = {"usd": usd, "tok": tok, "output": row.get("output", 0)}
                out.append(self._add(max(0.0, d_usd), max(0, d_tok)))
            return out
        if '"result"' not in line:
            return out
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return out
        if not isinstance(d, dict) or d.get("type") != "result":
            return out
        total = d.get("total_cost_usd")
        if isinstance(total, (int, float)) and not isinstance(total, bool) and total > self.usd:
            out.append(self._add(float(total) - self.usd, 0))
        return out

    def _add(self, usd: float, tokens: int) -> Increment:
        self.usd += usd
        self.tokens += tokens
        return Increment(usd, tokens)


class CodexJsonUsage:
    """Usage from `codex exec --json`: each `turn.completed` line's usage {input_tokens,
    cached_input_tokens, output_tokens}, priced for `model` at the default tier (the launcher switches
    the fast tiers off). The lines carry no model name, so the model must be given and priced."""

    harness = "codex"

    def __init__(self, model: str | None, prices: dict | None = None, *, speed: str = "default"):
        self.prices = prices if prices is not None else _pricing.load_prices()
        if not model:
            raise GateError("metering codex spend needs --model: `codex exec --json` usage lines carry "
                            "no model name, so the launcher cannot price them")
        if model not in self.prices["codex"]:
            raise GateError(f"no price for codex model {model!r} (add it to tools/ledger/pricing.json)")
        tiers = self.prices["codex"][model].get("tier_multiplier", {"default": 1})
        if speed not in tiers:
            raise GateError(f"no tier multiplier for codex model {model!r} tier {speed!r} "
                            "(tools/ledger/pricing.json)")
        self.model = model
        self.speed = speed              # B-201: a routed speed tier is priced at its multiplier
        self.usd = 0.0
        self.tokens = 0

    def feed(self, line: str) -> list[Increment]:
        if '"turn.completed"' not in line:
            return []
        try:
            d = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(d, dict) or d.get("type") != "turn.completed":
            return []
        u = d.get("usage") or {}
        if not isinstance(u, dict):
            return []
        row = {"harness": "codex", "model": self.model, "speed": self.speed,
               "input": int(u.get("input_tokens") or 0), "cached": int(u.get("cached_input_tokens") or 0),
               "output": int(u.get("output_tokens") or 0)}
        usd, tok = _pricing.cost(row, self.prices), _pricing.tokens(row)
        self.usd += usd
        self.tokens += tok
        return [Increment(usd, tok)]


# ------------------------------------------------------------------ the supervisor

def _write_out(stream, raw: bytes) -> None:
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        buf.write(raw)
        buf.flush()
    else:
        stream.write(raw.decode("utf-8", errors="replace"))
        stream.flush()


def _reader(pipe, usage, q: "queue.Queue", out) -> None:
    try:
        for raw in iter(pipe.readline, b""):
            _write_out(out, raw)
            try:
                for inc in usage.feed(raw.decode("utf-8", errors="replace")):
                    q.put(inc)
            except _pricing.PricingError as e:
                q.put(e)
    finally:
        q.put(None)


# ------------------------------------------------------------------ B-175: job owner and sessions

_OWNER_BAD = re.compile(r"[^A-Za-z0-9_.-]+")


def new_owner(harness: str, challenge_id: str | None) -> str:
    """A fresh job-owner label for one launched agent: <harness>-<challenge>-<launcher pid>-<random>."""
    parts = [harness, challenge_id or "nochallenge", str(os.getpid()), secrets.token_hex(3)]
    return "-".join(_OWNER_BAD.sub("_", p).strip("_") or "x" for p in parts)[:128]


def job_owner_env(owner: str, *, jobs_dir: Path | None) -> dict:
    """The variables that make the agent's `ctf job start` record `owner` and this launcher's pid."""
    out = {_jobs.OWNER_ENV: owner, _jobs.OWNER_PID_ENV: str(os.getpid())}
    if jobs_dir is not None:
        out["CTF_JOBS_DIR"] = str(jobs_dir)
    return out


def exec_owner_env(harness: str, challenge_id: str | None) -> dict:
    """For a launcher that execs the agent (no supervisor): the pid survives exec, so the owner's
    identity is the agent itself. Its jobs root is whatever `ctf job` resolves in the agent."""
    return job_owner_env(new_owner(harness, challenge_id), jobs_dir=None)


def launch_jobs_dir(gate: Gate) -> Path:
    """Where the supervised agent's jobs are recorded and reaped: $CTF_JOBS_DIR, else <ledger workdir>/jobs."""
    v = _env.get("CTF_JOBS_DIR")
    return Path(v).expanduser().resolve() if v else Path(gate.meter.workdir) / "jobs"


def reap_owned_jobs(gate: Gate, owner: str, jobs_dir: Path, *, err=None) -> list:
    """Stop every live job `owner` started (the agent has exited). Recorded as `jobs_reaped`; a job
    that could not be stopped is named on stderr and in the record, never silently left running."""
    err = err if err is not None else sys.stderr
    if not Path(jobs_dir).is_dir():
        return []
    try:
        res = _jobs.reap(jobs_dir, owner=owner)
    except _jobs.JobError as e:
        print(f"{gate.harness}_launch: could not reap the agent's jobs: {e}", file=err)
        gate.record("jobs_reaped", owner=owner, stopped=[], failed=["*"], error=str(e))
        return []
    if res:
        failed = [r for r in res if r.outcome == "failed"]
        gate.record("jobs_reaped", owner=owner, stopped=[r.id for r in res if r.outcome != "failed"],
                    failed=[r.id for r in failed])
        for r in res:
            print(f"{gate.harness}_launch: agent exited; job {r.id}: {r.outcome} ({r.detail})", file=err)
    return res


def session_from(arg: str | None) -> str | None:
    """--session, else $CTF_SESSION, else None (no session claim)."""
    name = arg if arg is not None else _env.get(_sessions.SESSION_ENV)
    return name.strip() if isinstance(name, str) and name.strip() else None


def claim_session(args, harness: str, *, dry_run: bool, err=None):
    """Claim --session NAME before anything else starts. Returns (claim | None, refused_rc | None).

    A live holder (launcher or agent alive by pid AND start time) refuses the launch with EXIT_REFUSED
    and says how the player ends it; a stale record is replaced and said so. A dry run only checks.
    A name or sessions folder that cannot be used is a GateError (exit 2)."""
    err = err if err is not None else sys.stderr
    name = session_from(getattr(args, "session", None))
    if name is None:
        return None, None
    try:
        root = _sessions.sessions_root()
        if dry_run:
            st = _sessions.peek(root, name)
            if st is not None and st.status == "live":
                holder = "agent" if st.agent == "alive" else "launcher"
                print(f"{harness}_launch: refused: {_sessions.SessionLive(name, st.record, holder)}", file=err)
                return None, EXIT_REFUSED
            print(f"{harness}_launch: session {name!r} is free (dry run: not claimed)", file=err)
            return None, None
        c = _sessions.claim(root, name, harness=harness, challenge=challenge_from(getattr(args, "challenge", None)))
    except _sessions.SessionLive as e:
        print(f"{harness}_launch: refused: {e}", file=err)
        return None, EXIT_REFUSED
    except _sessions.SessionError as e:
        raise GateError(str(e)) from None
    if c.replaced is not None:
        print(f"{harness}_launch: session {name!r}: replaced a stale record (launcher pid "
              f"{c.replaced.get('launcher_pid')} is gone or was reused)", file=err)
    return c, None


def release_session(claim) -> bool:
    try:
        return _sessions.release(claim)
    except _sessions.SessionError as e:
        print(f"launcher: could not release session {getattr(claim, 'name', '?')!r}: {e}", file=sys.stderr)
        return False


def supervise(argv: Sequence[str], gate: Gate, *, cwd: str | Path, usage=None, interactive: bool = False,
              poll_seconds: float = DEFAULT_POLL_SECONDS, stdout=None, stderr=None,
              popen_kwargs: dict | None = None, clock: Callable[[], float] = time.monotonic,
              session=None, owner: str | None = None) -> int:
    """Run the agent under the gate. Returns the agent's exit code, or EXIT_REFUSED when the gate
    stopped it, or 2 when its spend could not be priced (the agent is stopped: unmetered spend under
    a cap is what the gate exists to prevent).

    B-175: the agent's jobs are recorded against `owner` (a fresh one by default) and every live one
    is stopped once the agent has exited; `session` (a ctf.sessions.Claim) gets the agent's identity."""
    err = stderr if stderr is not None else sys.stderr
    owner = owner or new_owner(gate.harness, gate.challenge_id)
    jobs_dir = launch_jobs_dir(gate)
    kw = dict(popen_kwargs or {})
    kw["env"] = {**(kw.get("env") or os.environ), **job_owner_env(owner, jobs_dir=jobs_dir)}
    try:
        return _supervise(argv, gate, cwd=cwd, usage=usage, interactive=interactive,
                          poll_seconds=poll_seconds, stdout=stdout, stderr=stderr, popen_kwargs=kw,
                          clock=clock, session=session, owner=owner)
    finally:
        if gate.started:
            reap_owned_jobs(gate, owner, jobs_dir, err=err)


def _supervise(argv: Sequence[str], gate: Gate, *, cwd, usage, interactive, poll_seconds, stdout, stderr,
               popen_kwargs, clock, session, owner) -> int:
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    kw = dict(popen_kwargs or {})
    kw["cwd"] = str(cwd)
    if usage is not None:
        kw["stdout"] = subprocess.PIPE
    if interactive:
        proc = subprocess.Popen(list(argv), **kw)       # keeps the terminal: no new session
        owned = None
    else:
        owned = _pg.spawn(list(argv), **kw)            # own process group: stop takes descendants
        proc = owned.popen
    model = getattr(usage, "model", None) or _flag_value(argv, "--model") or _flag_value(argv, "-m")
    role = getattr(gate, "role", None)
    gate.record("agent_launch", mode="interactive" if interactive else "headless", metered=usage is not None,
                pid=proc.pid, **({"model": model} if isinstance(model, str) and model else {}),  # B-016
                **({"role": role} if role else {}), job_owner=owner,                             # B-175
                **dict(getattr(gate, "launch_fields", None) or {}))                               # B-201
    if session is not None:
        try:
            _sessions.set_agent(session, proc.pid, own_group=owned is not None, owner=owner)
        except _sessions.SessionError as e:
            print(f"{gate.harness}_launch: session {session.name!r}: could not record the agent: {e}",
                  file=err)

    q: queue.Queue = queue.Queue()
    reader = None
    if usage is not None:
        # B-101: the same output lines give the first tool call and candidate flags (ctf/stages.py)
        from ctf import stages as _stages
        flags = getattr(gate, "flags", None)
        if flags is None or not flags.known:
            print(f"{gate.harness}_launch: candidate flags are not recorded: the event's flag format is "
                  "not known", file=err)
        usage = _stages.AgentStreamTap(usage, gate.record, harness=gate.harness, flags=flags, err=err)
        reader = threading.Thread(target=_reader, args=(proc.stdout, usage, q, out), daemon=True)
        reader.start()

    def stop_agent() -> None:
        if owned is not None:
            owned.stop(grace=1.0)
            owned.wait_after_stop(timeout=5.0)
        else:
            proc.terminate()
            try:
                proc.wait(timeout=INTERACTIVE_TERM_GRACE)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def drain(block_s: float) -> None:
        """Charge queued increments; raises GateRefused / GateError."""
        deadline = clock() + block_s
        while True:
            try:
                item = q.get(timeout=max(0.0, deadline - clock())) if block_s > 0 else q.get_nowait()
            except queue.Empty:
                return
            if item is None:
                continue
            if isinstance(item, Exception):
                raise GateError(f"agent spend could not be priced: {item}")
            gate.charge(item.usd, item.tokens)
            block_s = 0                                 # after one item, take only what is queued

    next_check = clock() + poll_seconds
    try:
        while proc.poll() is None:
            if usage is not None:
                drain(min(0.1, poll_seconds))
            else:
                try:
                    proc.wait(timeout=min(0.1, poll_seconds))
                except subprocess.TimeoutExpired:
                    pass
            if clock() >= next_check and proc.poll() is None:
                gate.check()
                next_check = clock() + poll_seconds
    except GateRefused as e:
        stop_agent()
        if reader is not None:
            reader.join(timeout=2.0)
        _drain_quietly(q, gate, err)
        gate.record("agent_exit", rc=EXIT_REFUSED, reason=e.reason)
        print(f"{gate.harness}_launch: stopped the agent: {e}", file=err)
        return EXIT_REFUSED
    except GateError as e:
        stop_agent()
        if reader is not None:
            reader.join(timeout=2.0)
        _drain_quietly(q, gate, err)                    # spend already reported is still charged
        gate.record("agent_exit", rc=2, reason="unpriced")
        print(f"{gate.harness}_launch: stopped the agent: {e}", file=err)
        return 2
    except KeyboardInterrupt:
        stop_agent()
        if reader is not None:
            reader.join(timeout=2.0)
        _drain_quietly(q, gate, err)
        gate.record("agent_exit", rc=130, reason="interrupted")
        return 130

    rc = proc.returncode
    if reader is not None:
        reader.join(timeout=2.0)
    capped = _drain_quietly(q, gate, err)
    gate.record("agent_exit", rc=rc, **({"reason": capped} if capped else {}))
    return rc


def _drain_quietly(q: "queue.Queue", gate: Gate, err) -> str | None:
    """Charge what is left after the agent ended; report (not raise) a cap or a pricing failure."""
    reason = None
    while True:
        try:
            item = q.get_nowait()
        except queue.Empty:
            return reason
        if item is None:
            continue
        if isinstance(item, Exception):
            print(f"{gate.harness}_launch: UNPRICED agent spend: {item}", file=err)
            reason = reason or "unpriced"
            continue
        try:
            gate.charge(item.usd, item.tokens)
        except GateRefused as e:
            if reason != e.reason:
                print(f"{gate.harness}_launch: {e}", file=err)
            reason = e.reason       # at_cap, or B-201's route_budget



# ------------------------------------------------------------------ launcher wiring

def add_gate_options(p) -> None:
    p.add_argument("--challenge", help="challenge id: refuse to launch or continue when it is capped or "
                   "stopped, and charge the agent's spend to it (default $CTF_CHALLENGE)")
    p.add_argument("--gate-poll", type=float, default=DEFAULT_POLL_SECONDS, metavar="SECONDS",
                   help=f"how often a running agent's challenge is re-checked (default {DEFAULT_POLL_SECONDS:g})")
    p.add_argument("--role", help="the agent's work role for cost accounting (one of ctf.stages "
                   "SPEND_CATEGORIES: solve, build, verify, doc, orchestrate, guardian, other); recorded "
                   "on agent_launch so verify-role spend can be told apart by model (default $CTF_ROLE)")
    p.add_argument("--session", help="claim this session name (B-175): refuse to start while a previous "
                   "launch of it is still alive by pid and start time (default $CTF_SESSION)")


def gate_for(args, harness: str, *, err=None) -> Gate | None:
    """The Gate named by the launcher's options, or None (said on stderr) when no challenge is named.
    An invalid --role / $CTF_ROLE is refused loudly even when the gate is off."""
    err = err if err is not None else sys.stderr
    if args.gate_poll is None or not args.gate_poll > 0:
        raise GateError(f"--gate-poll must be > 0 seconds (got {args.gate_poll!r})")
    role = role_from(getattr(args, "role", None))
    cid = challenge_from(args.challenge)
    if cid is None:
        print("budget gate: off: no --challenge (or CTF_CHALLENGE) named; this session's spend is not "
              "metered or capped", file=err)
        return None
    return open_gate(cid, harness=harness, event_slug=args.event, role=role)


def admit(gate: Gate, *, dry_run: bool, err=None) -> int | None:
    """The launch-time check: the budget gate, then the B-143 agent gate (admit_spawn). Returns None to
    go ahead, or the exit code after printing why not. A dry run decides the same way but writes nothing
    to the ledger."""
    err = err if err is not None else sys.stderr
    prog = f"{gate.harness}_launch"
    if dry_run:
        st, reason = gate.peek()
        print(status_line(st), file=err)
        if reason:
            print(f"{prog}: refused: {refusal_text(st, reason)}", file=err)
            return EXIT_REFUSED
        return admit_spawn(gate, dry_run=True, err=err)
    try:
        st = gate.check()
    except GateRefused as e:
        print(f"{prog}: refused: {e}", file=err)
        return EXIT_REFUSED
    print(status_line(st), file=err)
    return admit_spawn(gate, dry_run=False, err=err)


def admit_spawn(gate: Gate, *, dry_run: bool, err=None) -> int | None:
    """B-143's agent gate, after the budget check: $CTF_SPAWN_ID names an admitted spawn this run
    starts (checked, and marked launched so one id starts one agent); without it the run is its own
    spawn request (`mode = "launch"`, the owner seat when free, else a helper). Held at the agent limit
    or refused: exit EXIT_REFUSED naming why and the command that lifts it. A dry run writes nothing."""
    from ctf import spawn as _spawn
    err = err if err is not None else sys.stderr
    prog = f"{gate.harness}_launch"
    sp = _spawn.Spawner(gate.meter.workdir)
    sid = _spawn.spawn_id_from_env()
    try:
        if sid:
            d = sp.lookup(sid, gate.challenge_id) if dry_run else sp.bind(sid, gate.challenge_id,
                                                                          harness=gate.harness)
        elif dry_run:
            d = sp.peek(gate.challenge_id, mode="launch")
        else:
            d = sp.request(gate.challenge_id, mode="launch", harness=gate.harness, check_budget=False)
    except _spawn.SpawnError as e:
        if not dry_run:
            _ledger.append("agent_refused", workdir=gate.meter.workdir, challenge_id=gate.challenge_id,
                           harness=gate.harness, reason="spawn")
        print(f"{prog}: refused: CTF_SPAWN_ID: {e}", file=err)
        return EXIT_REFUSED
    if not d.admitted:
        if not dry_run:
            _ledger.append("agent_refused", workdir=gate.meter.workdir, challenge_id=gate.challenge_id,
                           harness=gate.harness, reason=f"spawn_{d.reason}")
        print(f"{prog}: refused: {d.detail}", file=err)
        return EXIT_REFUSED
    gate.spawn = d
    gate.spawn_bound = bool(sid)
    gate.spawn_recorded = not dry_run
    size = "fresh launch" if d.first_input_tok is None else f"first input ~{d.first_input_tok:,} tok"
    print(f"spawn gate: challenge {gate.challenge_id}: agent {d.agents + 1} of {d.cap} ({d.role}, {d.mode}, "
          f"{size}; spawn tool {'kept' if d.spawn_tool else 'off'})"
          + ("" if dry_run else f" as {d.spawn_id}"), file=err)
    return None


def release_unstarted(gate: Gate | None, reason: str, *, err=None) -> bool:
    """Give back the seat of an admitted run whose agent never started (B-143): `spawn_void` for the
    run's own spawn, `spawn_unbound` for a bound $CTF_SPAWN_ID. No-op (False) when the gate is off,
    nothing was admitted or recorded, or the agent started. A failure to write is said on stderr (the
    launcher is already exiting with its own error), never raised. Idempotent."""
    if gate is None or gate.spawn is None or not gate.spawn_recorded or gate.started:
        return False
    err = err if err is not None else sys.stderr
    from ctf import spawn as _spawn
    sid, bound = gate.spawn.spawn_id, gate.spawn_bound
    gate.spawn_recorded = False
    try:
        _spawn.Spawner(gate.meter.workdir).release(sid, gate.challenge_id, bound=bound, reason=reason)
    except Exception as e:  # noqa: BLE001 -- said by name; the caller's own error is the exit reason
        print(f"{gate.harness}_launch: could not release spawn {sid} (the agent never started): "
              f"{type(e).__name__}: {e}; end it by hand: python -m ctf spawn end {sid}", file=err)
        return False
    print(f"spawn gate: released {sid} ({'unbound, may be launched again' if bound else 'not counted'}): "
          f"the agent never started", file=err)
    return True


def no_spawn_args(gate: Gate | None) -> list[str]:
    """The harness arguments that take the spawn tool away from an admitted run that may not spawn
    (a helper or a forked child, B-143); [] when the gate is off or the run is the owner."""
    if gate is None or gate.spawn is None or gate.spawn.spawn_tool:
        return []
    from ctf import spawn as _spawn
    return _spawn.no_spawn_args(gate.harness)


def _flag_value(extra: Sequence[str], flag: str) -> str | None:
    for i, a in enumerate(extra):
        if a == flag:
            return extra[i + 1] if i + 1 < len(extra) else ""
        if a.startswith(flag + "="):
            return a.split("=", 1)[1]
    return None


def claude_metering(extra: Sequence[str]) -> tuple[list[str], ClaudeStreamUsage | None]:
    """Gated Claude: a print-mode run (-p/--print) streams JSON so its usage can be charged; an
    interactive run is not metered (returns None). Refuses an output format that carries no usage."""
    extra = list(extra)
    if "-p" not in extra and "--print" not in extra:
        return extra, None
    fmt = _flag_value(extra, "--output-format")
    if fmt is not None and fmt != "stream-json":
        raise GateError(f"refused --output-format {fmt or '<missing>'} on a gated run: the launcher "
                        "charges spend from stream-json output (drop the flag or use stream-json)")
    pre = [] if fmt is not None else ["--output-format", "stream-json"]
    if "--verbose" not in extra:
        pre.append("--verbose")                 # claude requires it for stream-json in print mode
    return pre + extra, ClaudeStreamUsage()


def codex_metering(extra: Sequence[str], model: str | None, *, headless: bool, speed: str = "default"
                   ) -> tuple[list[str], CodexJsonUsage | None]:
    """Gated Codex: `codex exec` prints JSON events so its usage can be charged; the TUI is not
    metered (returns None). The model must come from --model so the usage can be priced."""
    extra = list(extra)
    if not headless:
        return extra, None
    for a in extra:
        # -m X, -mX, -m=X (clap's short forms) and --model X, --model=X
        flag = "--model" if a == "--model" or a.startswith("--model=") else (
            "-m" if a.startswith("-m") else None)
        if flag:
            raise GateError(f"refused codex argument {flag} on a gated run: pass the model with the "
                            "launcher's --model so its spend can be priced")
    for i, a in enumerate(extra):
        if a.startswith("--config="):
            val = a.split("=", 1)[1]
        elif a in ("-c", "--config"):
            val = extra[i + 1] if i + 1 < len(extra) else None
        elif a.startswith("-c"):                        # -cKEY=V and -c=KEY=V
            val = a[2:][1:] if a.startswith("-c=") else a[2:]
        else:
            val = None
        if val is not None and val.strip().split("=", 1)[0].strip() in ("model", "model_provider"):
            raise GateError("refused codex override 'model' on a gated run: pass the model with the "
                            "launcher's --model so its spend can be priced")
    usage = CodexJsonUsage(model, speed=speed)
    if "--json" not in extra:
        extra.insert(0, "--json")
    return extra, usage


def unmetered_notice(gate: Gate, err=None) -> None:
    print(f"budget gate: the interactive session's spend is not metered by the launcher; charge it with "
          f"python -m tools.ledger feed --challenge {gate.challenge_id} --harness {gate.harness} <session log>. "
          f"Stops and the cap are still re-checked every poll.", file=err if err is not None else sys.stderr)
