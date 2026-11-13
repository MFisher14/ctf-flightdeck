"""Wave rehearsal (B-039): replay one wave end to end against a fake platform, offline.

    from ctf import rehearsal
    r = rehearsal.rehearse(profile, workdir=Path(tmp))     # Rehearsal; r.passed, r.steps, r.timings
    print(r.render())

A CTFd event is replayed against ctf.fakectfd (127.0.0.1 only) through the code the wave really runs:
the carried CTFd client (ctf.client), `ctf wait`'s open detection, the workspace, triage and the
manifest router, a no-model Layer-1 flag scan, the Codex handoff brief (tools/codex_handoff.sh
--brief: no model call) and the guarded submit path (ctf.submit.guarded_submit) with the
machine-wide pacer. A manual event is replayed through its drop folder and the submit gate, which
must refuse every send. A Game Master event has no rehearsal here (the Huntress fake and its
scenarios were not carried): rehearse() raises RehearsalError saying so.

The synthetic board is built from the profile: one challenge per announced category (three stand-in
categories when none are announced, said in the report), each with a file holding a flag in the
event format, plus three control challenges: one whose planted flag the fake judges wrong (then the
same value is re-sent and must be deduped), one the team already solved (must not be sent), and a
decoy with no flag in the event format (must get a handoff brief, not a submission). The first
category challenge also has an instance, probed through the docker_per_team status route.

Steps (each ok / warn / fail, with seconds):
  auth       the client is authenticated before the open (`ctf me`; CTFd answers it while closed)
  open       `ctf wait` sees 403 until the fake opens the board, then 200
  pull       every visible challenge is pulled; files arrive byte for byte
  route      triage.suggest + the manifest router name engines for each challenge (an unrouted
             category is a warn, the same finding as the doctor's categories check)
  solve      the Layer-1 scan finds exactly the planted flag in each flagged challenge, none in the decoy
  handoff    a Codex handoff brief is written for the unsolved decoy, naming the event and workspace
  submit     correct / incorrect / skipped-solved as planned, the re-send deduped, no rate limit hit
             with the pacer on, flag.txt written for the solved ones
  instances  the instance status route answers through ctf.instances (a read; nothing starts)
  hygiene    every request authenticated, no hint endpoint touched, no route the fake does not know,
             nothing but the open polls and `ctf me` asked of the board before it opened

The rehearsal never reads .ctf/, never uses the real token (a fresh random one is given to the fake
and the client), and its client ignores proxy settings so nothing leaves loopback.
"""
from __future__ import annotations

import dataclasses
import json
import os
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import doctor, flagfmt, paths
from .event import EventProfile
from .fakectfd import FakeChallenge, FakeCTFd

STEP_STATUSES = ("ok", "warn", "fail")
DEFAULT_CATEGORIES = ("Web", "Crypto", "Forensics")
DEFAULT_SUBMIT_INTERVAL = 0.5      # seconds; the live pacer uses Config.submit_interval_min_s (3 s)
HANDOFF_LABEL = "rehearsal"
PROVENANCE = "rehearsal: layer-1 flag scan of the pulled file"


class RehearsalError(RuntimeError):
    """The rehearsal cannot run for this event; the message says why."""


@dataclass(frozen=True)
class Step:
    name: str
    status: str
    detail: str
    seconds: float | None = None

    def __post_init__(self):
        if self.status not in STEP_STATUSES:
            raise ValueError(f"step {self.name!r}: status {self.status!r} not in {STEP_STATUSES}")


@dataclass
class Planned:
    """What the rehearsal expects for one board challenge."""
    challenge: FakeChallenge
    planted: str | None            # the flag-format value written into its file (None: decoy)
    expect: str                    # correct | incorrect | skipped-solved | no-candidate


@dataclass
class Rehearsal:
    slug: str
    mode: str                      # ctfd | manual
    workdir: Path
    steps: list[Step] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.steps) and not any(s.status == "fail" for s in self.steps)

    def failures(self) -> list[Step]:
        return [s for s in self.steps if s.status == "fail"]

    def step(self, name: str) -> Step:
        for s in self.steps:
            if s.name == name:
                return s
        raise KeyError(name)

    def render(self) -> str:
        out = [f"wave rehearsal for {self.slug} ({self.mode}), scratch {self.workdir}"]
        out += [f"  note: {n}" for n in self.notes]
        for s in self.steps:
            secs = f" [{s.seconds:.2f}s]" if s.seconds is not None else ""
            out.append(f"  {s.status.upper():<4} {s.name}{secs}: {s.detail}")
        if self.timings:
            out.append("  timings: " + ", ".join(f"{k} {v:.2f}s" for k, v in self.timings.items()))
        out.append("REHEARSAL PASSED" if self.passed else
                   f"REHEARSAL FAILED: {', '.join(s.name for s in self.failures())}")
        return "\n".join(out)

    def to_dict(self) -> dict:
        return {"slug": self.slug, "mode": self.mode, "workdir": str(self.workdir), "passed": self.passed,
                "notes": self.notes, "timings": self.timings,
                "steps": [dataclasses.asdict(s) for s in self.steps]}


# ---------------------------------------------------------------------------------------- board

def build_board(profile: EventProfile, rng=secrets) -> tuple[list[Planned], list[str]]:
    """The synthetic board for `profile` and notes about it. Raises RehearsalError when no value in
    the event's flag format can be built."""
    ff = flagfmt.for_profile(profile)
    notes = []
    cats = list(profile.categories)
    if not cats:
        cats = list(DEFAULT_CATEGORIES)
        notes.append(f"no categories announced: stand-in categories {', '.join(cats)}")

    def flag() -> str:
        try:
            return doctor.synth_flag(profile, rng.token_hex(4))
        except ValueError as e:
            raise RehearsalError(str(e)) from None

    def artifact(value: str, label: str) -> bytes:
        return (f"rehearsal artifact ({label})\nnoise line 1\nrecovered: {value}\nnoise line 2\n").encode()

    plan: list[Planned] = []
    for i, cat in enumerate(cats):
        f = flag()
        ch = FakeChallenge(100 + i, f"rehearsal {cat}", cat, files={f"artifact_{i}.txt": artifact(f, cat)},
                           flag=f, description=f"Rehearsal challenge for {cat}.", instance=(i == 0))
        plan.append(Planned(ch, f, "correct"))
    wrong_planted, wrong_real = flag(), flag()
    plan.append(Planned(FakeChallenge(200, "rehearsal wrong flag", cats[0],
                                      files={"wrong.txt": artifact(wrong_planted, "a wrong flag")},
                                      flag=wrong_real, description="The planted value is wrong."),
                        wrong_planted, "incorrect"))
    solved = flag()
    plan.append(Planned(FakeChallenge(201, "rehearsal already solved", cats[0],
                                      files={"solved.txt": artifact(solved, "already solved")},
                                      flag=solved, solved=True, description="A teammate solved it."),
                        solved, "skipped-solved"))
    decoy = "ZZNOTTHEEVENT{" + rng.token_hex(4) + "}"
    if ff.find_flags(decoy):
        decoy = "no flag in this file, only a hint at one"
    plan.append(Planned(FakeChallenge(202, "rehearsal decoy", cats[-1],
                                      files={"decoy.txt": artifact(decoy, "decoy")},
                                      flag=None, description="Nothing in the event format here."),
                        None, "no-candidate"))
    return plan, notes


# ---------------------------------------------------------------------------------------- shared steps

def _route_step(pulled: dict[int, tuple[str, str, Path]], root: Path | None) -> Step:
    from . import triage
    from .engines import router
    t = time.monotonic()
    unrouted, counts = [], []
    for cid, (category, description, files_dir) in sorted(pulled.items()):
        hits = router.route(category, description, files_dir, root=root)
        sug = triage.suggest(category, description, files_dir)
        if not hits and not sug["engines"]:
            unrouted.append(f"{cid} [{category}]")
        counts.append(len(hits))
    secs = time.monotonic() - t
    if not pulled:
        return Step("route", "fail", "nothing pulled to route", secs)
    if unrouted:
        return Step("route", "warn", f"no engine for {len(unrouted)} challenge(s): {', '.join(unrouted)}", secs)
    return Step("route", "ok", f"{len(pulled)} challenges routed (manifest hits per challenge "
                f"{min(counts)}-{max(counts)})", secs)


def _scan(files_dir: Path, ff) -> list[str]:
    seen: list[str] = []
    for f in sorted(Path(files_dir).rglob("*")):
        if f.is_file():
            for v in ff.find_flags(f.read_bytes()):
                if v not in seen:
                    seen.append(v)
    return seen


def _solve_step(plan: dict[int, Planned], pulled: dict[int, tuple[str, str, Path]], ff) -> tuple[Step, dict]:
    t = time.monotonic()
    found, wrong = {}, []
    for cid, (_, _, files_dir) in sorted(pulled.items()):
        cands = _scan(files_dir, ff)
        found[cid] = cands
        want = [plan[cid].planted] if plan[cid].planted else []
        if cands != want:
            wrong.append(f"{cid}: found {cands}, planted {want}")
    secs = time.monotonic() - t
    if wrong:
        return Step("solve", "fail", "Layer-1 scan disagrees with the board: " + "; ".join(wrong), secs), found
    n = sum(1 for v in found.values() if v)
    return Step("solve", "ok", f"Layer-1 scan found the planted flag in {n} challenge(s) and none in the "
                "decoy", secs), found


def _handoff_step(profile: EventProfile, ws_dirs: list[Path], workdir: Path, root: Path) -> Step:
    """A Codex handoff brief for each unsolved challenge: tools/codex_handoff.sh --brief (no model call)."""
    t = time.monotonic()
    if not ws_dirs:
        return Step("handoff", "fail", "no unsolved challenge to hand off (the decoy should be one)")
    script = root / doctor.HANDOFF_SCRIPT
    e = {k: v for k, v in os.environ.items() if not k.startswith("CODEX_")}
    e.update(CTF_WORKDIR=str(workdir), CTF_EVENT=profile.slug,
             CODEX_BIN=str(workdir / "no-codex-in-a-rehearsal"))   # a launch by mistake fails, never runs
    problems = []
    for d in ws_dirs:
        try:
            p = subprocess.run(["bash", str(script), "--event", profile.name, "--challenge", str(d), "--brief",
                                "--label", HANDOFF_LABEL], input="Rehearsal guidance: try the files first.\n",
                               cwd=str(root), env=e, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as err:
            problems.append(f"{d.name}: {err}")
            continue
        brief = d / f"codex_brief-{HANDOFF_LABEL}.md"
        if p.returncode != 0:
            problems.append(f"{d.name}: exit {p.returncode}: {(p.stderr or p.stdout).strip()[-200:]}")
        elif not brief.is_file():
            problems.append(f"{d.name}: no brief at {brief}")
        else:
            text = brief.read_text(encoding="utf-8")
            if profile.name not in text or str(d) not in text:
                problems.append(f"{d.name}: the brief does not name the event and the workspace")
    secs = time.monotonic() - t
    if problems:
        return Step("handoff", "fail", "; ".join(problems), secs)
    return Step("handoff", "ok", f"{len(ws_dirs)} handoff brief(s) written (no model call)", secs)


# ---------------------------------------------------------------------------------------- CTFd

def _rehearse_ctfd(profile: EventProfile, rep: Rehearsal, plan: list[Planned], *, submit_interval: float,
                   open_after: int, poll_interval: float, open_timeout: float, root: Path) -> None:
    from . import client as _client
    from . import config as _config
    from . import submit as _submit
    from . import workspace as _ws
    from .cli import wait_for_open
    from .platform import legacy as _legacy
    from .platform.base import NotSupported

    ff = flagfmt.for_profile(profile)
    by_id = {p.challenge.id: p for p in plan}
    token = "rehearsal-" + secrets.token_hex(12)
    work = rep.workdir / "work"
    with FakeCTFd([p.challenge for p in plan], token=token, open_after=open_after,
                  min_attempt_gap=submit_interval * 0.9) as fake:
        rprof = dataclasses.replace(profile, platform=dataclasses.replace(profile.platform,
                                                                          base_url=fake.base_url))
        cfg = _config.Config(base_url=fake.base_url, token=token, team_id=None, workdir=work, flags=ff,
                             submit_interval_min_s=submit_interval, request_timeout_s=10.0,
                             user_agent="ctf-rehearsal")
        c = _client.CTFd(cfg, profile=rprof)
        c.s.trust_env = False                     # loopback only: no proxy from the environment
        c._pacer = _client.SubmitPacer(fake.base_url, submit_interval, state_dir=rep.workdir / "pace")

        # auth (what `ctf me` checks before the wave: CTFd answers /users/me while the board is closed)
        t0 = time.monotonic()
        try:
            me = c.me()
        except _client.CTFdError as e:
            rep.steps.append(Step("auth", "fail", f"the client is not authenticated: {e}",
                                  time.monotonic() - t0))
            return
        rep.steps.append(Step("auth", "ok", f"authenticated as {me.get('name')!r} before the open",
                              time.monotonic() - t0))

        # open
        code, msg = wait_for_open(c.challenges, interval=poll_interval, timeout=open_timeout,
                                  log=lambda m: None)
        t_open = time.monotonic()
        lists = fake.requests("list")
        refused = sum(1 for r in lists if r.status == 403)
        if code != 0:
            unauth = sum(1 for r in list(fake.log) if not r.authed and r.path == "/api/v1/challenges")
            rep.steps.append(Step("open", "fail", f"`ctf wait` did not see the wave open: {msg}"
                                  + (f" ({unauth} poll(s) carried no valid token: a 403 for bad auth "
                                     "looks like a closed board)" if unauth else ""), t_open - t0))
            return
        if refused != open_after:
            rep.steps.append(Step("open", "fail", f"saw {refused} closed polls, the fake answered "
                                  f"{open_after}", t_open - t0))
            return
        rep.steps.append(Step("open", "ok", f"{msg} after {refused} closed poll(s)", t_open - t0))

        # pull
        pulled: dict[int, tuple[str, str, Path]] = {}
        chs: dict[int, _ws.Challenge] = {}
        problems = []
        team_solved = c.team_solved_ids()
        visible = c.challenges()
        for row in visible:
            detail = c.challenge(int(row["id"]))
            ch = _ws.for_challenge(detail, cfg)
            got = c.download_files(ch.cid, ch.files_dir)
            want = by_id[ch.cid].challenge.files
            have = {p.name: p.read_bytes() for p in got}
            if have != want:
                problems.append(f"{ch.cid}: files {sorted(have)} differ from the board's {sorted(want)}")
            pulled[ch.cid] = (ch.category, detail.get("description") or "", ch.files_dir)
            chs[ch.cid] = ch
        t_pulled = time.monotonic()
        rep.timings["open_to_pulled"] = t_pulled - t_open
        if len(pulled) != len(plan):
            problems.append(f"pulled {len(pulled)} of {len(plan)} challenges")
        rep.steps.append(Step("pull", "fail" if problems else "ok",
                              "; ".join(problems) or f"{len(pulled)} challenges pulled into {work}",
                              t_pulled - t_open))

        rep.steps.append(_route_step(pulled, root))
        solve, found = _solve_step(by_id, pulled, ff)
        rep.steps.append(solve)
        rep.steps.append(_handoff_step(profile, [chs[cid].dir for cid, v in sorted(found.items()) if not v],
                                       work, root))

        # submit
        refuse = _legacy.refusal(rprof, "guarded_submit", submit=True)
        t_s = time.monotonic()
        problems, sent_expected, outcomes = [], 0, []
        first_sub = None
        for cid, cands in sorted(found.items()):
            for value in cands:
                try:
                    res = _submit.guarded_submit(c, chs[cid], value, provenance=PROVENANCE,
                                                 team_solved=team_solved)
                except NotSupported as e:
                    if refuse is None:
                        problems.append(f"{cid}: refused unexpectedly: {e}")
                    outcomes.append((cid, "refused"))
                    continue
                if first_sub is None and res.submitted:
                    first_sub = time.monotonic()
                outcomes.append((cid, res.status))
                want = by_id[cid].expect
                if refuse is not None:
                    problems.append(f"{cid}: sent although the event's rules refuse it")
                elif res.status != want:
                    problems.append(f"{cid}: {res.status} ({res.message}), planned {want}")
                if want in ("correct", "incorrect"):
                    sent_expected += 1
                if want == "incorrect":
                    again = _submit.guarded_submit(c, chs[cid], value, provenance=PROVENANCE,
                                                   team_solved=team_solved)
                    if again.status != "duplicate" or again.submitted:
                        problems.append(f"{cid}: re-sending a judged-wrong value was {again.status}, "
                                        "not deduped")
                if want in ("correct", "skipped-solved") and not chs[cid].solved():
                    problems.append(f"{cid}: no flag.txt after {res.status}")
        t_e = time.monotonic()
        attempts = fake.requests("attempt")
        if refuse is not None:
            sent_expected = 0
        if len(attempts) != sent_expected:
            problems.append(f"the fake saw {len(attempts)} attempt(s), planned {sent_expected}")
        limited = [a for a in attempts if a.verdict == "ratelimited"]
        if limited:
            problems.append(f"{len(limited)} attempt(s) rate-limited: the pacer let sends through faster "
                            f"than {submit_interval:g}s apart")
        if first_sub is not None:
            rep.timings["open_to_first_submit"] = first_sub - t_open
        rep.timings["open_to_last_submit"] = t_e - t_open
        detail = ("; ".join(problems) if problems else
                  (f"every send refused as the rules say ({refuse})" if refuse is not None else
                   f"{len(attempts)} paced attempt(s): " + ", ".join(f"{cid} {s}" for cid, s in outcomes)))
        rep.steps.append(Step("submit", "fail" if problems else "ok", detail, t_e - t_s))

        # instances (read-only status probe through the doctor's probe)
        inst_ids = [p.challenge.id for p in plan if p.challenge.instance]
        t_i = time.monotonic()
        chk = doctor.check_instances(rprof, {"endpoints": {"plugin": "docker_per_team"}, "cap": None},
                                     inst_ids[0], client=c)
        want = f"127.0.0.1:{40000 + inst_ids[0]}"
        ok = chk.status == "ok" and repr(want) in chk.detail
        rep.steps.append(Step("instances", "ok" if ok else "fail",
                              chk.detail if ok else f"{chk.detail} (wanted connect {want})",
                              time.monotonic() - t_i))

        # hygiene
        log = list(fake.log)
        bad = []
        if any(r.kind == "hint" for r in log):
            bad.append("a hint endpoint was requested")
        unauth = sorted({f"{r.method} {r.path}" for r in log if not r.authed})
        if unauth:
            bad.append(f"{sum(not r.authed for r in log)} unauthenticated request(s): " + ", ".join(unauth))
        early = sorted({f"{r.method} {r.path}" for r in log if r.kind == "closed"})
        if early:
            bad.append("requested before the board opened: " + ", ".join(early))
        unknown = sorted({f"{r.method} {r.path}" for r in log if r.kind == "unknown"})
        if unknown:
            bad.append("routes the fake does not serve: " + ", ".join(unknown))
        rep.steps.append(Step("hygiene", "fail" if bad else "ok",
                              "; ".join(bad) or f"{len(log)} requests, all authenticated, no hint touched"))
        rep.timings["total"] = time.monotonic() - t0


# ---------------------------------------------------------------------------------------- manual

def _toml_str(s: str) -> str:
    return json.dumps(s)          # a JSON string literal is a valid TOML basic string for this text


def _rehearse_manual(profile: EventProfile, rep: Rehearsal, plan: list[Planned], *, root: Path) -> None:
    from .platform.manual import ManualAdapter
    from .platform.policy import SubmitGate

    ff = flagfmt.for_profile(profile)
    by_id = {p.challenge.id: p for p in plan}
    drop = rep.workdir / "drop"
    for p in plan:
        d = drop / str(p.challenge.id)
        d.mkdir(parents=True)
        c = p.challenge
        (d / "challenge.toml").write_text(
            f"name = {_toml_str(c.name)}\ncategory = {_toml_str(c.category)}\npoints = {c.value}\n"
            f"description = {_toml_str(c.description)}\n", encoding="utf-8")
        for name, data in c.files.items():
            (d / name).write_bytes(data)
        if c.solved:
            (d / "SOLVED").write_text("a teammate\n", encoding="utf-8")
    gate = SubmitGate(ManualAdapter(profile, drop_dir=drop), profile)

    t0 = time.monotonic()
    pulled, dirs, problems = {}, {}, []
    for ch in gate.list_challenges():
        cid = int(ch.id)
        dest = rep.workdir / "work" / f"{cid}" / "files"
        got = gate.download_files(ch.id, dest)
        have = {p.name: p.read_bytes() for p in got}
        if have != by_id[cid].challenge.files:
            problems.append(f"{cid}: files differ from the drop folder")
        pulled[cid] = (ch.category, ch.description, dest)
        dirs[cid] = dest.parent
    if len(pulled) != len(plan):
        problems.append(f"read {len(pulled)} of {len(plan)} drop-folder challenges")
    t1 = time.monotonic()
    rep.timings["pulled"] = t1 - t0
    rep.steps.append(Step("pull", "fail" if problems else "ok",
                          "; ".join(problems) or f"{len(pulled)} challenges read from the drop folder", t1 - t0))
    rep.steps.append(_route_step(pulled, root))
    solve, found = _solve_step(by_id, pulled, ff)
    rep.steps.append(solve)
    rep.steps.append(_handoff_step(profile, [dirs[cid] for cid, v in sorted(found.items()) if not v],
                                   rep.workdir / "work", root))
    t_s = time.monotonic()
    problems, n = [], 0
    for cid, cands in sorted(found.items()):
        for value in cands:
            n += 1
            r = gate.submit(str(cid), value, provenance=PROVENANCE, confirmed=True)
            if r.sent or r.status.value != "not_allowed":
                problems.append(f"{cid}: the gate let a send through on a manual event ({r.status.value})")
    rep.steps.append(Step("submit", "fail" if problems else "ok",
                          "; ".join(problems) or f"all {n} candidate(s) refused by the gate (manual: the "
                          "player submits)", time.monotonic() - t_s))
    rep.timings["total"] = time.monotonic() - t0


# ---------------------------------------------------------------------------------------- entry

def rehearse(profile: EventProfile, *, workdir: Path, submit_interval: float = DEFAULT_SUBMIT_INTERVAL,
             open_after: int = 2, poll_interval: float = 0.05, open_timeout: float = 30.0,
             root: Path | None = None) -> Rehearsal:
    """Replay one wave for `profile` in the scratch folder `workdir` (created; must be empty)."""
    from .platform import adapter_kind
    if submit_interval <= 0:
        raise RehearsalError("submit_interval must be > 0: the rehearsal checks the pacer")
    if open_after < 1:
        raise RehearsalError("open_after must be >= 1: the rehearsal checks the closed-board wait")
    workdir = Path(workdir)
    if workdir.exists() and any(workdir.iterdir()):
        raise RehearsalError(f"rehearsal scratch folder {workdir} is not empty")
    workdir.mkdir(parents=True, exist_ok=True)
    root = paths.repo_root() if root is None else Path(root)
    kind = adapter_kind(profile)
    if kind not in ("ctfd", "manual"):
        raise RehearsalError(f"no rehearsal for a {kind} platform: the Game Master fake and its scenarios "
                             "(Huntress tools/rehearse.py) are not carried into the master")
    plan, notes = build_board(profile)
    rep = Rehearsal(profile.slug, kind, workdir, notes=notes)
    if kind == "manual":
        _rehearse_manual(profile, rep, plan, root=root)
    else:
        _rehearse_ctfd(profile, rep, plan, submit_interval=submit_interval, open_after=open_after,
                       poll_interval=poll_interval, open_timeout=open_timeout, root=root)
    return rep
