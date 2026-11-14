"""Parallel no-model intake per challenge (B-002).

    rep = intake.intake_one("9076", profile)            # one challenge, in this process
    outs = intake.intake_many(["9076", "9080"], profile)   # one worker process per challenge, in parallel
    ids, skipped = intake.board(profile)                # the board's challenges intake should take

One intake = download, sweep, engines, report, all without a model:

1. Download through the platform adapter (`ctf.platform.get_adapter(profile)`: CTFd, Game Master, or
   the manual drop folder) into `<workdir>/<id>-<slug>/files/`, with `challenge.json` and `notes.md`
   beside it (the layout `ctf pull` uses).
2. The B-013 sweep (`ctf.sweep.sweep`): recursive unpack into `unpacked/`, sha256 manifest, per-file
   identify, and the flag-format search (plain, UTF-16, embedded tokens, URL layer, metadata joins).
3. Engines with an `[intake]` input adapter (ctf/intake/engines.py), on the unpacked files, inside the
   network guard (ctf/intake/guard.py), under a per-challenge time budget.
4. `recon/index.md` (what is there and what was found), `triage.md` (per file: kind and the engines
   that claim it; the routed engines and how to run the ones intake did not), `recon/flags.txt`,
   `recon/intake.json` (machine-readable, with stage timings), a `## intake` block in notes.md, and an
   `intake` ledger record.

Between the engines and the report, the fastlane stage (B-012, ctf/intake/decode.py) runs the
encoding-chain decoder over every handout file and every encoded blob in the brief; decoder noise is
excluded and a weakly supported decode only makes a `candidate`.

intake_one itself never submits: a found flag is `solved` (flag found, not accepted) or `candidate`.
A flag only an engine that returned `candidate` found stays a `candidate` (B-090).
The capped auto-submit (B-012, ctf/intake/autosubmit.py, `ctf intake --submit [--submit-cap N]`) and
the dispatcher (B-004) consume the result, through the SubmitGate. The result's engine is "intake".
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from .. import flagfmt as _flagfmt
from .. import ledger as _ledger
from .. import paths as _paths
from .. import sweep as _sweep
from ..result import Cost, Evidence, SolverResult
from . import engines as _engines
from . import guard as _guard

SCHEMA = 1
ENGINE = "intake"
LEDGER_EVENT = "intake"
RECON = "recon"
INDEX = "recon/index.md"
TRIAGE = "triage.md"
REPORT = "recon/intake.json"
FLAGS = "recon/flags.txt"
DEFAULT_ENGINE_BUDGET = 60.0          # seconds of engine time per challenge
MIN_ENGINE_SLICE = 0.5                # an engine is not started with less of the budget left than this
MAX_JOBS = 64
_SAFE_ID = re.compile(r"[^A-Za-z0-9._-]+")


class IntakeError(RuntimeError):
    """Intake cannot start: a bad option, an id that cannot name a folder, no workdir."""


@dataclass
class Options:
    engines: bool = True              # run the engines that have an [intake] adapter
    max_cost: str = "cheap"           # the highest engine cost_class intake runs
    engine_budget: float = DEFAULT_ENGINE_BUDGET
    net_guard: str = "auto"           # auto | os | hook (ctf/intake/guard.py)
    record: bool = True               # ledger records (intake, engine.run)
    root: Path | None = None          # the checkout whose engines run (default: this one)
    python: str | None = None         # the engine interpreter (default: this one)
    brief_fetch: bool = True          # B-088: one scope-checked GET of a URL the brief names (off: instruction only)

    def __post_init__(self):
        if self.max_cost not in _engines.COST_ORDER:
            raise IntakeError(f"max_cost {self.max_cost!r}: use one of {', '.join(_engines.COST_ORDER)}")
        if not self.engine_budget > 0:
            raise IntakeError(f"engine_budget must be > 0 seconds, got {self.engine_budget}")
        if self.net_guard not in _guard.MODES:
            raise IntakeError(f"net_guard {self.net_guard!r}: use one of {', '.join(_guard.MODES)}")

    def argv(self) -> list[str]:
        """The worker's command-line form of these options."""
        out = ["--max-cost", self.max_cost, "--engine-budget", repr(float(self.engine_budget)),
               "--net-guard", self.net_guard]
        if not self.engines:
            out.append("--no-engines")
        if not self.record:
            out.append("--no-ledger")
        if not self.brief_fetch:
            out.append("--no-brief-fetch")
        if self.root is not None:
            out += ["--root", str(self.root)]
        return out


# ---------------------------------------------------------------- folders

def challenge_dir(workdir: Path, challenge) -> Path:
    """<workdir>/<id>-<slug of the name> (ctf.workspace.dir_name): the folder `ctf pull` uses for the
    same challenge. A numeric id is read as a number, as pull reads a CTFd id (`0042` -> `42`); any
    other id (Game Master, manual drop folders, which pull does not take) has every run of characters
    outside [A-Za-z0-9._-] made one `-`, so it cannot climb out of the workdir."""
    from ..workspace import dir_name
    raw = str(challenge.id)
    cid = str(int(raw)) if raw.isascii() and raw.isdigit() else _SAFE_ID.sub("-", raw).strip("-.")
    if not cid:
        raise IntakeError(f"challenge id {challenge.id!r} cannot name a folder")
    return Path(workdir) / dir_name(cid, challenge.name)


def _challenge_json(ch) -> dict:
    return {"id": ch.id, "name": ch.name, "category": ch.category, "value": ch.points,
            "description": ch.description, "connection_info": ch.connection_info, "tags": list(ch.tags),
            "files": [f.name for f in ch.files], "solved_by_team": ch.solved_by_team, "source": "intake"}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------- the report

@dataclass
class Report:
    challenge_id: str
    dir: Path | None
    result: SolverResult
    seconds: float = 0.0
    stages: dict = field(default_factory=dict)          # download / sweep / engines -> seconds
    challenge: object = None                            # ctf.platform.base.Challenge
    sweep: object = None                                # ctf.sweep.Report, when the sweep ran
    plan: object = None                                 # engines.Plan, when engines were planned
    runs: list = field(default_factory=list)            # [engines.EngineRun]
    flags: dict = field(default_factory=dict)           # normalized flag -> [where]
    excluded: dict = field(default_factory=dict)        # normalized flag -> why
    fastlane: list = field(default_factory=list)        # [decode.Hit] from the fastlane decoders (B-012)
    welcome: dict | None = None                         # ctf.fastlane.try_welcome result on a welcome/profile challenge (B-041)
    brief_url: dict | None = None                       # ctf.brieffield.try_brief_url result: a named field read off a brief URL (B-088)
    unconfirmed: dict = field(default_factory=dict)     # normalized flag -> why (only a weak decode or a candidate-status engine found it)
    disputed: dict = field(default_factory=dict)        # normalized flag -> why (an engine calls it a possible decoy)
    notes: list = field(default_factory=list)
    guard: object = None                                # guard.Guard
    error: str | None = None
    started: float = 0.0                                # epoch

    @property
    def status(self) -> str:
        return self.result.status

    def counts(self) -> dict:
        man = self.sweep.manifest if self.sweep is not None else []
        return {"files": sum(1 for e in man if e.original), "members": sum(1 for e in man if not e.original),
                "engines": len(self.runs), "flags": len(self.flags)}

    def to_dict(self) -> dict:
        ch = self.challenge
        p = self.plan
        return {
            "schema": SCHEMA, "engine": ENGINE, "challenge_id": self.challenge_id,
            "name": getattr(ch, "name", None), "category": getattr(ch, "category", None),
            "points": getattr(ch, "points", None), "dir": str(self.dir) if self.dir else None,
            "status": self.status, "started": round(self.started, 3), "seconds": round(self.seconds, 3),
            "stages": {k: round(v, 3) for k, v in self.stages.items()}, **self.counts(),
            "flags_found": self.flags, "excluded": self.excluded, "unconfirmed": self.unconfirmed,
            "disputed": self.disputed,
            "fastlane": [{"flag": h.flag, "how": h.how, "verdict": h.verdict, "why": h.why} for h in self.fastlane],
            "welcome": self.welcome,
            "brief_url": self.brief_url,
            "net_guard": {"mode": self.guard.mode, "reason": self.guard.reason} if self.guard else None,
            "engines_run": [r.to_dict() for r in self.runs],
            "engines_skipped": [{"engine": s.engine, "reason": s.reason} for s in (p.skipped if p else [])],
            "engines_without_adapter": [{"engine": e, "priority": pr, "why": w} for e, pr, w in (p.unadapted if p else [])],
            "notes": self.notes, "error": self.error,
            "result": json.loads(self.result.to_json()),
        }

    def summary(self) -> str:
        flags = " ".join(self.result.flags[:3]) + (" ..." if len(self.result.flags) > 3 else "")
        where = f" -> {self.dir / INDEX}" if self.dir else ""
        c = self.counts()
        return (f"intake {self.challenge_id}: {self.status} in {self.seconds:.1f}s  files={c['files']} "
                f"members={c['members']} engines={c['engines']}" + (f"  {flags}" if flags else "")
                + (f"  ({self.error})" if self.error else "") + where)


def _merge(rep: Report, profile, brief: str) -> None:
    """Flags from the sweep and from engine output, deduplicated, brief and placeholder text excluded."""
    ff = _flagfmt.for_profile(profile)
    in_brief = {_sweep._norm(ff, f) for f in ff.find_flags(brief)} if brief else set()
    if rep.sweep is not None:
        locs = rep.sweep._locations()
        for f, hits in rep.sweep.flags.items():
            rep.flags.setdefault(f, []).extend(
                f"sweep {h.method} in {(locs.get(h.sha256) or ['?'])[0]}"
                + (f" @0x{h.offset:x}" if h.offset is not None else "") for h in hits[:3])
        rep.excluded.update(rep.sweep.excluded)
    # B-090: an engine that itself returned `candidate` (for example toolkits.series_chain, whose
    # answer is a computed field of a sibling's file) offers its flags as candidates. Such a flag is
    # kept, but stays `unconfirmed` unless a confirmed source (the sweep, an engine that did not say
    # candidate, a confirmed decode) also found it, so intake's roll-up never calls it `solved` and
    # the capped auto-submit (autosubmit.eligible: `solved` only) never sends it.
    engine_candidates: dict = {}
    engine_confirmed: set = set()
    # The flags already merged before the engines' are the sweep's (a confirmed source): read from
    # rep.flags, not rep.sweep, so a report built without a sweep object confirms the same way.
    sweep_keys = set(rep.flags)
    for run in rep.runs:
        for raw in run.flags:
            key = _sweep._norm(ff, raw)
            if key is None:
                continue
            why = _sweep._excluded(key, in_brief)
            if why:
                rep.excluded.setdefault(key, why)
                continue
            rep.flags.setdefault(key, []).append(
                f"engine {run.engine}" + (f" on {', '.join(run.inputs)}" if run.inputs else "") + f" ({run.output})")
            if run.result_status == "candidate":
                engine_candidates.setdefault(key, f"engine {run.engine} returned it as a candidate only")
            else:
                engine_confirmed.add(key)
        # B-132: a flag an engine's own result calls a possible decoy (evidence kind `decoy`) stays a
        # found flag, but whoever else found it (the sweep reads the same bytes), it is never `solved`
        # on its own: the engine knows where in the artifact the value sits.
        for raw in getattr(run, "disputed", ()):
            key = _sweep._norm(ff, raw)
            if key is not None:
                rep.disputed.setdefault(key, f"engine {run.engine} reports it as a possible decoy ({run.output})")
    # B-132: the sweep disputes a flag it found only where decoys sit (Walk.doubt), so intake stands down
    # even when no engine ran (--no-engines, a timeout, a crash, a missing module). Only the engine the
    # sweep names, reporting the flag `solved` without disputing it, settles that (it proved the value
    # elsewhere in the document, from a script or an index list). If that engine disputes it itself, its
    # own dispute above stands whatever this says.
    if rep.sweep is not None:
        for key, d in (getattr(rep.sweep, "disputed", None) or {}).items():
            settled = any(run.engine == d.get("engine") and run.result_status == "solved"
                          and key in {_sweep._norm(ff, f) for f in run.flags}
                          for run in rep.runs)
            if key in rep.flags and not settled:
                rep.disputed.setdefault(key, f"the sweep found it {d.get('why')}")
    for key, why in engine_candidates.items():
        if key not in engine_confirmed and key not in sweep_keys:
            rep.unconfirmed.setdefault(key, why)
    # B-012: deterministic decoders run inside intake. Noise (a control character in the body) is
    # excluded; an unconfirmed decode (loose steps only, no crib support) is kept as a flag but marks
    # it `unconfirmed` unless a confirmed source (sweep, engine, a confirmed decode) also found it, and
    # an unconfirmed flag makes the intake a `candidate` (ctf/intake/decode.py).
    from . import decode as _decode
    confirmed = set(rep.flags)
    for h in sorted(rep.fastlane, key=lambda h: h.verdict != _decode.FLAG):
        key = _sweep._norm(ff, h.flag)
        if key is None:
            continue
        if h.verdict == _decode.NOISE:
            if key not in rep.flags:
                rep.excluded.setdefault(key.encode("unicode_escape").decode("ascii"), h.why)
            continue
        why = _sweep._excluded(key, in_brief)
        if why:
            rep.excluded.setdefault(key, why)
            continue
        if h.verdict == _decode.FLAG:
            confirmed.add(key)
            rep.unconfirmed.pop(key, None)      # a confirmed decode settles an engine's candidate
            rep.flags.setdefault(key, []).append(f"fastlane decode ({h.how})")
        else:
            rep.flags.setdefault(key, []).append(f"fastlane decode ({h.how}) [{h.why}]")
            if key not in confirmed:
                rep.unconfirmed.setdefault(key, h.why)
    # B-041: on a welcome / zero-file / platform-profile challenge the flag is often the brief itself,
    # which the in-brief filter above drops as template text. The auto-trigger recovered one unambiguous
    # inline flag offline (ctf.fastlane.try_welcome); force it in as a confirmed flag so the welcome
    # freebie is `solved`, not excluded. A flagless welcome result (a platform human step) adds nothing.
    w = rep.welcome
    if w and w.get("flag"):
        key = _sweep._norm(ff, w["flag"])
        if key is not None:
            rep.excluded.pop(key, None)
            rep.unconfirmed.pop(key, None)
            rep.flags.setdefault(key, []).append(f"fastlane welcome ({w.get('how') or 'inline brief flag'})")


def _result(rep: Report, cid: str) -> SolverResult:
    cost = Cost(seconds=round(rep.seconds, 3))
    found = list(rep.flags)
    joins = []
    if rep.sweep is not None:
        joins = [j.flag for j, _ in rep.sweep.joins if j.flag not in rep.flags]
    evidence = [Evidence("intake", f"{f} via {w[0]}", path=INDEX) for f, w in rep.flags.items()]
    evidence += [Evidence("join", f"{j} joined from metadata fragments (sweep)", path=INDEX) for j in joins]
    common = dict(engine=ENGINE, challenge_id=cid, cost=cost)
    if len(found) == 1 and found[0] in rep.unconfirmed:
        return SolverResult("candidate", flags=found + joins, evidence=evidence,
                            notes=f"one flag, unconfirmed (no confirmed source found it): {rep.unconfirmed[found[0]]}",
                            **common)
    if len(found) == 1 and found[0] in rep.disputed:
        return SolverResult("candidate", flags=found + joins, evidence=evidence,
                            notes=f"one flag, and {rep.disputed[found[0]]}: not proven, the player picks", **common)
    if len(found) == 1:
        return SolverResult("solved", flags=found, evidence=evidence,
                            notes="one distinct flag in the handout (found, not submitted)", **common)
    if found or joins:
        return SolverResult("candidate", flags=found + joins, evidence=evidence,
                            notes=f"{len(found)} distinct flag(s) and {len(joins)} metadata join(s): "
                                  "decoys are possible", **common)
    return SolverResult("none", notes="no flag in the event format in the handout or in engine output", **common)


def write_outputs(rep: Report) -> None:
    from . import report as _report
    d = rep.dir
    _write(d / REPORT, json.dumps(rep.to_dict(), indent=1) + "\n")
    _write(d / FLAGS, "".join(f"{f}\t{w[0]}\n" for f, w in rep.flags.items()))
    _write(d / INDEX, _report.index_md(rep))
    _write(d / TRIAGE, _report.triage_md(rep))
    with open(d / "notes.md", "a", encoding="utf-8") as fh:
        fh.write("\n## intake\n\n" + rep.summary() + "\n")


# ---------------------------------------------------------------- one challenge

def intake_one(challenge_id: str, profile, *, adapter=None, workdir: Path | None = None,
               options: Options | None = None, manifests=None) -> Report:
    """Intake one challenge in this process. Platform failures give a `blocked` report (written when
    the folder exists); a bad option raises IntakeError."""
    opts = options or Options()
    t0, started = time.monotonic(), time.time()
    cid = str(challenge_id)
    workdir = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
    rep = Report(cid, None, SolverResult("none", engine=ENGINE, challenge_id=cid), started=started)
    from ..platform import PlatformError, get_adapter
    try:
        plat = adapter if adapter is not None else get_adapter(profile)
        ch = plat.get_challenge(cid)
        rep.challenge = ch
        d = challenge_dir(workdir, ch)
        (d / "files").mkdir(parents=True, exist_ok=True)
        rep.dir = d.resolve()          # the sweep reports resolved paths; keep one spelling
        files_dir = rep.dir / "files"
        _write(rep.dir / "challenge.json", json.dumps(_challenge_json(ch), indent=1) + "\n")
        if not (rep.dir / "notes.md").exists():
            head = f"# {ch.name}  [{ch.category}]  ({ch.points if ch.points is not None else '?'} pts)\n"
            if ch.connection_info:
                head += f"\ntarget: {ch.connection_info}\n"
            if ch.description.strip():
                head += "\n## description\n\n" + ch.description.strip() + "\n"
            _write(rep.dir / "notes.md", head)
        t = time.monotonic()
        plat.download_files(cid, files_dir)
        rep.stages["download"] = time.monotonic() - t
    except (PlatformError, OSError) as e:
        rep.error = f"{type(e).__name__}: {e}"
        rep.seconds = time.monotonic() - t0
        rep.result = SolverResult("blocked", engine=ENGINE, challenge_id=cid, cost=Cost(seconds=round(rep.seconds, 3)),
                                  notes=f"intake could not fetch the challenge: {rep.error}")
        if rep.dir is not None:
            write_outputs(rep)
        record(rep, workdir, opts)
        return rep

    # 2. sweep: unpack + manifest + identify + flag search
    t = time.monotonic()
    folder = files_dir
    try:
        rep.sweep = _sweep.sweep(rep.dir, profile)
        folder = rep.sweep.target.out
        rep.notes += [f"sweep: {n}" for n in rep.sweep.notes]
    except _sweep.NothingToSweep:
        rep.notes.append("sweep: no handout files")
    except Exception as e:          # the download stands; the failure is named in every report
        rep.notes.append(f"sweep FAILED ({type(e).__name__}: {e}); engines get the downloaded files as they are")
    rep.stages["sweep"] = time.monotonic() - t

    # 3. engines with an input adapter (planned always, for triage.md; run unless --no-engines)
    t = time.monotonic()
    _engines_step(rep, profile, folder, opts, manifests, workdir)
    rep.stages["engines"] = time.monotonic() - t

    # 4. fastlane deterministic decoders (B-012): layered reversible decode of the handout blobs, on
    #    top of the sweep's embedded-token pass, surfacing flags deeper encode chains hide.
    t = time.monotonic()
    _fastlane_step(rep, ch, files_dir)
    _welcome_step(rep, ch, files_dir, profile)
    _brief_url_step(rep, ch, profile, opts)
    rep.stages["fastlane"] = time.monotonic() - t

    _merge(rep, profile, ch.description)
    rep.seconds = time.monotonic() - t0
    rep.result = _result(rep, cid)
    write_outputs(rep)
    record(rep, workdir, opts)
    return rep


def _engines_step(rep: Report, profile, folder: Path, opts: Options, manifests, workdir: Path) -> None:
    from ..engines import manifest as _manifest
    root = Path(opts.root) if opts.root is not None else _paths.repo_root()
    try:
        ms = _manifest.discover(root) if manifests is None else manifests
    except _manifest.ManifestError as e:
        rep.notes.append(f"engines NOT planned or run: {e}")
        return
    blocked = None
    if not opts.engines:
        rep.guard = _guard.Guard("hook", (), "engines not run (--no-engines)")
        blocked = "engines not run (--no-engines)"
    else:
        try:
            rep.guard = _guard.resolve(opts.net_guard)
        except _guard.GuardError as e:
            rep.guard = _guard.Guard("hook", (), f"not applied: {e}")
            blocked = f"engines NOT RUN: {e}"
    ch = rep.challenge
    # Routing reads the tags too (B-112): a challenge tagged `discord` often says nothing else about it.
    brief = "\n".join([ch.description, *(str(t) for t in ch.tags)])
    left = []                       # the handout's files the sweep left out of `folder` for size (section 6, `originals`)
    if rep.sweep is not None:
        left = _engines.left_out(rep.sweep.target.sources, {e.chain[0] for e in rep.sweep.manifest if e.original})
    rep.plan = _engines.plan(ms, ch.category, brief, folder, guard=rep.guard, max_cost=opts.max_cost,
                             originals=left)
    if blocked:
        rep.notes.append(blocked)
        rep.plan.skipped += [_engines.Skip(j.engine, blocked) for j in rep.plan.jobs]
        rep.plan.jobs = []
        return
    ctx = _engines.Context(challenge_dir=rep.dir, folder=folder, out_root=rep.dir / RECON / "engines",
                           profile=profile, guard=rep.guard, root=root, python=opts.python or sys.executable,
                           challenge_id=rep.challenge_id, record=opts.record, workdir=workdir)
    deadline = time.monotonic() + opts.engine_budget
    for i, job in enumerate(rep.plan.jobs):
        left = deadline - time.monotonic()
        if left <= MIN_ENGINE_SLICE:
            rest = rep.plan.jobs[i:]
            rep.plan.skipped += [_engines.Skip(j.engine, f"the intake engine budget of {opts.engine_budget:g}s "
                                                         "was spent") for j in rest]
            rep.plan.jobs = rep.plan.jobs[:i]
            break
        rep.runs.append(_engines.run_job(job, ctx, timeout=left))


def _fastlane_step(rep: Report, ch, files_dir: Path) -> None:
    """Run the carried fastlane encoding-chain decoder over the handout and record any flag it surfaces.

    This is the offline, deterministic part of ctf.fastlane only (no network, no sanity/OSINT branch):
    the challenge brief and files are untrusted DATA, read and decoded, never executed. A missing
    decoder is named loudly in the notes (rule 6), never a silent skip; a decoder crash is caught so a
    bad handout can never take intake down -- the download, sweep and engine results still stand."""
    from .. import fastlane as _fastlane
    from . import decode as _decode
    if _fastlane._crib is None:
        rep.notes.append("fastlane decode skipped: the crib_decode decoder is unavailable "
                         "(solvers/warmups/crib_decode.py)")
        return
    detail = {"name": ch.name, "category": ch.category, "description": ch.description}
    try:
        hits = _decode.decode_hits(detail, files_dir, fastlane=_fastlane)
    except Exception as e:                   # the handout is untrusted; a decoder fault is a note, not a crash
        rep.notes.append(f"fastlane decode FAILED ({type(e).__name__}: {e})")
        return
    rep.fastlane.extend(hits)
    for h in hits:
        if h.verdict != _decode.FLAG:
            rep.notes.append(f"fastlane: {h.flag.encode('unicode_escape').decode('ascii')} from {h.source}: {h.why}")


def _welcome_step(rep: Report, ch, files_dir: Path, profile) -> None:
    """B-041: auto-run the offline fast lane on a welcome / zero-file / platform-profile challenge.

    A welcome/intro challenge often prints its flag in the brief itself, and a rules/profile challenge's
    answer is a step the player takes on the event platform. ``_merge`` drops a brief-quoted flag as
    template text, so without this the welcome freebie would be lost. This recovers the one unambiguous
    inline flag deterministically (``ctf.fastlane.try_welcome``, no network) and records the fast-lane
    class and, when there is no inline flag, the human step (reading the rules page, filling a CTFd
    profile, a learning-platform lesson), which is never scripted. The brief is untrusted DATA; a fault
    is a note, never an intake crash."""
    from .. import fastlane as _fastlane
    detail = {"name": ch.name, "category": ch.category, "description": ch.description}
    base_url = getattr(getattr(profile, "platform", None), "base_url", None)
    try:
        res = _fastlane.try_welcome(detail, files_dir, base_url=base_url)
    except Exception as e:            # the brief is untrusted; a fault is a note, not a crash
        rep.notes.append(f"fastlane welcome-trigger FAILED ({type(e).__name__}: {e})")
        return
    if res is None:
        return
    rep.welcome = res
    if res.get("flag"):
        rep.notes.append(f"fastlane welcome [{res['klass']}]: {res['how']}")
    elif res.get("instruction"):
        rep.notes.append(f"fastlane welcome [{res['klass']}] human step: {res['instruction']}")


def _brief_url_step(rep: Report, ch, profile, opts: Options) -> None:
    """B-088: a brief that names a site and asks for one field on it ("Find the company registration
    number shown on the site") gets one bounded GET of that site -- after ctf.scope.check_url
    against this event's profile (rules.live_service_scope, or a `ctf policy point` record) -- and the
    page's label/value pair matched to the noun (ctf.brieffield.try_brief_url). It runs here in the
    intake worker, not as an [intake] engine, because engines are network-denied. The value is a
    `candidate` with an instruction, never a flag: it does not change the intake status and is never
    submitted. An out-of-scope URL is not fetched and is named; --no-brief-fetch gives the instruction
    without the GET. The page is untrusted data; a fault is a note, never an intake crash."""
    from .. import brieffield as _bf
    detail = {"name": ch.name, "category": ch.category, "description": ch.description}
    try:
        res = _bf.try_brief_url(detail, profile=profile, online=opts.brief_fetch)
    except Exception as e:            # the brief and page are untrusted; a fault is a note, not a crash
        rep.notes.append(f"fastlane brief-url FAILED ({type(e).__name__}: {e})")
        return
    if res is None:
        return
    rep.brief_url = res
    if res.get("candidate"):
        rep.notes.append(f"fastlane brief-url CANDIDATE (not a flag, verify): {res['field']} = "
                         f"{res['candidate']} -- {res['instruction']}")
    else:
        rep.notes.append(f"fastlane brief-url [{res['field']}]: {res['how']}; next: {res['instruction']}")


def record(rep: Report, workdir: Path | None = None, options: Options | None = None) -> dict | None:
    """Append the `intake` ledger record (docs/CONTRACTS.md section 10) unless options.record is off."""
    if options is not None and not options.record:
        return None
    c = rep.counts()
    return _ledger.append(LEDGER_EVENT, workdir=workdir, challenge_id=rep.challenge_id, status=rep.status,
                   seconds=round(rep.seconds, 3), stages={k: round(v, 3) for k, v in rep.stages.items()},
                   files=c["files"], members=c["members"], engines=c["engines"], flags=c["flags"])


# ---------------------------------------------------------------- the board, and many at once

def board(profile, *, adapter=None, workdir: Path | None = None, include_solved: bool = False,
          force: bool = False) -> tuple[list[str], list[tuple[str, str]]]:
    """(ids to intake, [(id, why skipped)]) from the platform's challenge list: team-solved challenges
    and ones with a finished intake are skipped unless asked for. Finished = recon/intake.json holds a
    status other than `blocked`; a blocked intake (the download failed, say an HTTP 5xx at wave open)
    is taken again by the next board, and so is a report that cannot be read."""
    from ..platform import get_adapter
    plat = adapter if adapter is not None else get_adapter(profile)
    workdir = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
    take, skipped = [], []
    for ch in plat.list_challenges():
        if ch.solved_by_team and not include_solved:
            skipped.append((ch.id, "solved by the team"))
            continue
        done = None if force else finished(challenge_dir(workdir, ch))
        if done:
            skipped.append((ch.id, f"already taken in ({challenge_dir(workdir, ch) / REPORT}: {done}); "
                                   "--force redoes it"))
        else:
            take.append(ch.id)
    return take, skipped


def finished(d: Path) -> str | None:
    """The status of the intake in folder d when it finished (any status but `blocked`), else None:
    no report, a blocked one, or one that is not a readable intake report."""
    try:
        status = json.loads((Path(d) / REPORT).read_text(encoding="utf-8")).get("status")
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(status, str) or status == "blocked":
        return None
    return status


@dataclass
class Outcome:
    challenge_id: str
    exit_code: int | None
    started: float                    # seconds after the first worker started
    seconds: float                    # the worker's wall time
    summary: dict | None = None       # the worker's last line (JSON), when it printed one
    log: Path | None = None
    report: Report | None = None      # in-process runs only

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


_WORKER = ("import sys; sys.path.insert(0, sys.argv[1]); from ctf.intake import worker_main; "
           "raise SystemExit(worker_main(sys.argv[2:]))")


def default_jobs(n: int) -> int:
    return max(1, min(n, MAX_JOBS, 2 * (os.cpu_count() or 2)))


def worker_command(challenge_id: str, slug: str, options: Options, *, python: str | None = None,
                   root: Path | None = None) -> list[str]:
    root = Path(options.root) if options.root is not None else (root or _paths.repo_root())
    return [python or options.python or sys.executable, "-I", "-c", _WORKER, str(root),
            "--event", slug, "--id", str(challenge_id), *options.argv()]


def intake_many(ids, profile, *, jobs: int | None = None, options: Options | None = None,
                workdir: Path | None = None, spawn: bool = True, adapter=None, on_done=None,
                poll: float = 0.02) -> list[Outcome]:
    """Intake every id, one worker per challenge, at most `jobs` at once (default: all of them up to
    2 x CPUs, capped at MAX_JOBS). spawn=True starts a worker process per challenge (`worker_main`),
    which builds its own platform adapter; spawn=False runs intake_one on threads (an injected
    adapter, tests). on_done(outcome) is called as each finishes. Outcomes come back in `ids` order."""
    ids = [str(i) for i in ids]
    if len(set(ids)) != len(ids):
        raise IntakeError("a challenge id is listed twice")
    opts = options or Options()
    workdir = Path(workdir) if workdir is not None else _paths.workdir(profile.slug)
    jobs = default_jobs(len(ids)) if jobs is None else int(jobs)
    if jobs < 1:
        raise IntakeError(f"jobs must be >= 1, got {jobs}")
    if not ids:
        return []
    if not spawn:
        return _many_threads(ids, profile, jobs, opts, workdir, adapter, on_done)
    if adapter is not None:
        raise IntakeError("an adapter object cannot cross into worker processes: use spawn=False")
    logs = workdir / "intake" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CTF_WORKDIR=str(workdir), CTF_EVENT=profile.slug)
    pending = list(ids)
    running: dict[str, tuple] = {}
    done: dict[str, Outcome] = {}
    first = None
    while pending or running:
        while pending and len(running) < jobs:
            cid = pending.pop(0)
            log = logs / f"{_SAFE_ID.sub('-', cid)}.log"
            fh = open(log, "wb")
            now = time.monotonic()
            first = now if first is None else first
            proc = subprocess.Popen(worker_command(cid, profile.slug, opts), stdin=subprocess.DEVNULL,
                                    stdout=fh, stderr=subprocess.STDOUT, env=env, cwd=str(workdir))
            running[cid] = (proc, fh, now, log)
        for cid in list(running):
            proc, fh, t, log = running[cid]
            code = proc.poll()
            if code is None:
                continue
            fh.close()
            del running[cid]
            out = Outcome(cid, code, t - first, time.monotonic() - t, _last_json(log), log)
            done[cid] = out
            if on_done:
                on_done(out)
        if running:
            time.sleep(poll)
    return [done[c] for c in ids]


def _last_json(log: Path) -> dict | None:
    try:
        lines = [ln for ln in log.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
        return json.loads(lines[-1]) if lines else None
    except (OSError, ValueError):
        return None


def _many_threads(ids, profile, jobs, opts, workdir, adapter, on_done) -> list[Outcome]:
    from concurrent.futures import ThreadPoolExecutor
    first = time.monotonic()

    def one(cid):
        t = time.monotonic()
        try:
            rep = intake_one(cid, profile, adapter=adapter, workdir=workdir, options=opts)
            code = 1 if rep.status == "blocked" else 0
        except Exception as e:
            rep, code = None, 1
            traceback.print_exc()
            print(f"intake {cid}: FAILED ({type(e).__name__}: {e})", file=sys.stderr)
        out = Outcome(cid, code, t - first, time.monotonic() - t,
                      _summary(rep) if rep else None, None, rep)
        if on_done:
            on_done(out)
        return out

    with ThreadPoolExecutor(max_workers=jobs) as ex:
        return list(ex.map(one, ids))


def _summary(rep: Report) -> dict:
    return {"challenge_id": rep.challenge_id, "status": rep.status, "seconds": round(rep.seconds, 3),
            "flags": list(rep.result.flags), "dir": str(rep.dir) if rep.dir else None,
            "line": rep.summary()}


# ---------------------------------------------------------------- the worker process

def worker_main(argv: list[str]) -> int:
    """One worker: `python -I -c <_WORKER> <root> --event SLUG --id ID [options]`. Prints the summary
    and, last, one JSON line for the parent. 0 = intake ran (whatever it found), 1 = blocked or crashed."""
    import argparse
    from .. import event as _event
    p = argparse.ArgumentParser(prog="ctf intake worker")
    p.add_argument("--event", required=True)
    p.add_argument("--id", required=True)
    p.add_argument("--max-cost", default="cheap")
    p.add_argument("--engine-budget", type=float, default=DEFAULT_ENGINE_BUDGET)
    p.add_argument("--net-guard", default="auto")
    p.add_argument("--no-engines", action="store_true")
    p.add_argument("--no-ledger", action="store_true")
    p.add_argument("--no-brief-fetch", action="store_true")
    p.add_argument("--root", help="the checkout whose engines run (default: this one)")
    a = p.parse_args(argv)
    try:
        profile = _event.load(a.event)
        opts = Options(engines=not a.no_engines, max_cost=a.max_cost, engine_budget=a.engine_budget,
                       net_guard=a.net_guard, record=not a.no_ledger, root=Path(a.root) if a.root else None,
                       brief_fetch=not a.no_brief_fetch)
        rep = intake_one(a.id, profile, options=opts)
    except Exception as e:
        traceback.print_exc()
        print(json.dumps({"challenge_id": a.id, "status": "error", "error": f"{type(e).__name__}: {e}"}))
        return 1
    print(rep.summary())
    print(json.dumps(_summary(rep)))
    return 1 if rep.status == "blocked" else 0
