#!/usr/bin/env python3
"""Toolkit `evidence_core`: the shared evidence layer (rows, queries, times, the cross-artifact
indicator index, the question router with its exactly-one rule). The code is
solvers/common/evidence_core.py; this file is its toolkit face, so tools/run.py, tools/verify.py
and tools/lane_match.py can load it like any other toolkit:

  .venv/bin/python solvers/toolkits/evidence_core.py <file | folder | saved attempt folder>...

  signals(questions, files) -> float      0..1, cheap
  solve_set(questions, files, ctx) -> {qid: plain | labels.pick(...) | None}
  table(path), q(table, op, ...), ioc(files), tables(name, bytes), parse_time, time_options, ...

The bundle router (2026-10-08, the real-data round). An incident bundle mixes categories: an auth
log, a pickled model, an agent transcript, a package. The evidence layer answers what is a row, a
count or the only indicator; a question it leaves None is handed to the specific toolkits, and the
answer of the ONE toolkit that gives one is taken, as that toolkit gave it (plain, or an unsure
pick under its own key). Two toolkits with different answers are two candidates: None. Nothing is
handed over on a known lane's question, when the evidence layer answered, or after ROUTE_SECONDS.
`CTF_BUNDLE_ROUTER=off` turns the router off; `ctx["evidence_core"]["routed"]` and one stderr
line per question say who answered. The router is on by default and its registry is
solvers/toolkits/registry.py: a missing or broken registry or toolkit raises a named error
(ctf/packs.py), never "registry not loaded" in a note (B-001b; the forks ran with the router off).

Quick reference: docs/toolkits/evidence_core.md.
"""
import importlib.util
import os
import sys
import time
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env

_IMPL = Path(__file__).resolve().parent.parent / "common" / "evidence_core.py"
_NAME = "evidence_core_impl"
if _NAME in sys.modules:
    _mod = sys.modules[_NAME]
else:
    _spec = importlib.util.spec_from_file_location(_NAME, _IMPL)
    _mod = importlib.util.module_from_spec(_spec)
    sys.modules[_NAME] = _mod
    _spec.loader.exec_module(_mod)

globals().update({k: v for k, v in vars(_mod).items() if not k.startswith("__")})
KEY = _mod.KEY
signals = _mod.signals

ROUTE_SECONDS = 10.0            # no further toolkit is asked after this long (never on a clock: no lane policy plays a toolkit;
                                # measured: 0.3 s on a five-file bundle, 13 s for twelve questions over 193 real files, 60 MB)
ROUTE_SIGNAL = 0.25             # a toolkit is asked from this signal on (registry.SHOWN: what the triage map names)
NOT_ROUTED = ("evidence_core", "web")       # itself, and the live-target toolkit


_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))         # appended, never first: the repo root must not shadow a lane module


def _registry():
    """solvers/toolkits/registry.py of this tree. RegistryLoadError (ctf/packs.py) when it is missing or
    broken: the router never runs without it and never says so only in a note (B-001b)."""
    from ctf import packs
    return packs.toolkit_registry(_ROOT)


def route(questions, files, ctx=None, budget: float = ROUTE_SECONDS) -> tuple:
    """({qid: answer}, {qid: [toolkit keys that answered]}, [notes]) for the questions given: each
    one's answer from the specific toolkits. A question gets an answer only when every toolkit that
    answers it gives the same value; different values are left None and listed. A registry or toolkit
    that cannot be loaded raises (RegistryLoadError, PackMissing, PackLoadError); a toolkit whose
    solve_set raises answers nothing and is named in the notes."""
    out, who, notes = {}, {}, []
    if not questions:
        return out, who, notes
    reg = _registry()
    t0 = time.monotonic()
    answers = {}                # qid -> [(key, value)]
    for t in reg.entries(match_only=False):
        key = t["key"]
        if key in NOT_ROUTED:
            continue
        if time.monotonic() - t0 > budget:
            notes.append(f"not asked (time): {key}")
            continue
        if reg.signal(key, questions, files) < ROUTE_SIGNAL:
            continue
        mod = reg.load(key)             # loaded by signal() above; a load miss has already raised there
        try:
            got = mod.solve_set(questions, files, {"routed_by": KEY})
        except Exception as e:          # noqa: BLE001 - a toolkit that fails answers nothing
            # Exception, not BaseException: the runner's own stop (tools/run.py SolverTimeout, raised from
            # its timer) must pass through here, or the hand-over would outlive the solver's budget.
            notes.append(f"{key}: {type(e).__name__}")
            continue
        for q in questions:
            qid = q.get("qid") or q.get("id")
            v = (got or {}).get(qid)
            if v is not None:
                answers.setdefault(qid, []).append((key, v))
    for qid, rows in answers.items():
        who[qid] = [k for k, _ in rows]
        values = {v if isinstance(v, str) else repr(v) for _, v in rows}
        if len(values) == 1:
            out[qid] = rows[0][1]
        else:
            notes.append(f"{qid}: {', '.join(who[qid])} answer differently: two candidates, no answer")
    return out, who, notes


def _same_from(key: str, q: dict, qid, value, files: dict, member: str) -> bool:
    """True when toolkit `key`, handed only the file the question names (and what was unpacked from
    it), answers `value` again."""
    own = {k: v for k, v in (files or {}).items() if member in {Path(part.strip()).name for part in str(k).split(_mod.ARROW)}}
    if not own:
        return False
    if len(own) == len(files):
        return True
    mod = _registry().load(key)
    try:
        again = mod.solve_set([q], own, {"routed_by": KEY})
    except Exception as e:      # noqa: BLE001 - the re-check failed: not proven from the named file, said so
        print(f"[evidence_core] NOTE {qid}: toolkit:{key} raised {type(e).__name__} re-reading {member} alone; "
              f"the answer is offered as unsure", file=sys.stderr)
        return False
    return isinstance(again, dict) and again.get(qid) == value


def _in_lane_match() -> bool:
    """True inside `tools/lane_match.py --one`: the match already runs every toolkit as a candidate of
    its own, each under a two-second cap, so this one answers for itself there and hands nothing on
    (a hand-over that ran into the cap would cost the layer its own answers)."""
    argv = [str(a) for a in sys.argv[:3]]
    return bool(argv) and Path(argv[0]).name == "lane_match.py" and "--one" in argv


def solve_set(questions, files, ctx) -> dict:
    ctx = ctx if isinstance(ctx, dict) else {}
    out = _mod.solve_set(questions, files, ctx)
    if ctf_env.get("CTF_BUNDLE_ROUTER", "").lower() == "off" or ctx.get("routed_by") or _in_lane_match():
        return out
    components = _mod.lane_components(questions)     # a failure here is a bug in the layer: it raises (B-001b)
    left = [q for q in questions if out.get(q.get("qid") or q.get("id")) is None and not _mod.known_lane(q, components)]
    if not left:
        return out
    routed, who, notes = route(left, files, ctx)
    partial = ctx.get("partial") if isinstance(ctx.get("partial"), dict) else None
    delivered = {Path(str(k).split(_mod.ARROW)[-1]).name for k in files or {}}
    by_qid = {(q.get("qid") or q.get("id")): q for q in left}
    for qid, v in list(routed.items()):
        # A toolkit proves its answer inside its own slice of the delivery. In a bundle that is the
        # whole proof only when the question names the file: a plain answer to a question that names
        # none ("the attacker's IP", with an auth log, a proxy log and an alert in the delivery) is
        # offered under this toolkit's key, named after the toolkit that gave it, and probed.
        q = by_qid.get(qid) or {}
        member = Path(str(q.get("member") or "")).name
        named = bool(member) and member in delivered
        if named and not (isinstance(v, str) and v.startswith("??")):
            # ... and only when the toolkit gives the same answer from the named file alone: one that
            # read it out of another file of the bundle has proven nothing about the file asked about
            # (review, 2026-10-08; this group's toolkits leave such a question alone, not every one does).
            named = _same_from(who[qid][0], q, qid, v, files, member)
        if not named and not (isinstance(v, str) and v.startswith("??")):
            v = _mod.pick("routed", _mod._aid(q), [(f"by_{who[qid][0]}", v)]) if isinstance(v, str) else None
            if v is None:
                routed.pop(qid)
                continue
        out[qid] = v
        if partial is not None:
            partial[qid] = v
        print(f"[evidence_core] NOTE {qid}: answered by toolkit:{who[qid][0]}", file=sys.stderr)
    for n in notes:
        print(f"[evidence_core] NOTE router: {n}", file=sys.stderr)
    rep = ctx.setdefault("evidence_core", {})
    if isinstance(rep, dict):
        rep["routed"] = {qid: who[qid] for qid in who}
        rep.setdefault("notes", [])
        rep["notes"] += notes
    return out


if __name__ == "__main__":
    sys.exit(_mod.main(sys.argv[1:]))
