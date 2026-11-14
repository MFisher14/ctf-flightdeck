"""ctf gate plan | run | inventory -- the impact-selected regression gate (B-195, ctf/gate).

    python -m ctf gate plan [SELECT] [--json]          what a run would do: mode, why, each file RUN or WARM
    python -m ctf gate run  [SELECT] [--jobs N] [--no-warm] [--out DIR] [--pytest-arg ARG ...]
                            [--mark-green SLUG]   full run only; on green + clean tree: tag HEAD green (B-197)
                            [--idle-lock | --no-idle-lock] [--idle-timeout S]   hold the idle-machine lock
                            exclusive while files run (B-213, ctf.workreg; default $CTF_IDLE_LOCK, else off)
    python -m ctf gate inventory                       refresh the content-hash dependency inventory
    python -m ctf gate budget [--lane L] [--jobs N] [--import-junit XML] [--json]
                                                       each lane's cost estimate against its budget (B-153)
    python -m ctf gate baseline check|list|keys|add ID --kind K --reason R [--owner O]
                                                       the tracked baseline ledger of known reds (B-153)
    python -m ctf gate prearm [--jobs N] [--out DIR] [--mark-green SLUG]
                                                       the pre-arm full gate: preflight, then a full run
    common: --root DIR --config FILE --state DIR --python PATH (the children's interpreter; default
            $CTF_PYTHON, the checkout's .venv, the main checkout's .venv, then this one -- ctf.pyinterp)

SELECT (at least one; --base and --changed combine):
    --base REF          files changed between REF and the working tree (committed, staged, unstaged,
                        deleted, untracked) select the test files whose closure holds them
    --changed FILE ...  the same, for a list you give
    --lane L            only test files in lane L (tests/gate.toml [lanes]); alone: every file of the lane
    --batch ID          the first run of a batch is a full run and is recorded; later runs of the batch
                        are impact runs (give --base or --changed) and also rerun every file that is red
                        in the batch (from the full run or a later run) until it runs green
    --full              every test file (lists the tree without reading the git index, B-137)

Mode rules: a full run (from --full, a batch's first run, a changed global input, or a changed file no
test maps to) runs every file and reuses nothing; impact and lane runs reuse a stored green result whose
exact-hash key matches (--no-warm turns that off), except a file carried as red in the batch, which
always runs. Green complete results are stored by every run; a red run deletes the one under its key.
Strict not-run (B-196): a file whose tests all passed but where a test (or a recorded part of one) did
not run is NOTRUN, which is red, unless its kind is in tests/gate.toml not_run_ok or given with
--allow-not-run KIND ('any': not strict for this run).
Exit: 0 green, 1 any FAIL/ERROR/TIMEOUT/NOTRUN, 2 usage or config problem (or a refused --mark-green), 130
interrupted. An ENV file (an environment problem, not a code defect; B-137) is reported apart and does
not turn the gate red. Every run writes a stable record to <state>/last-fail.log naming what failed, so
a red survives a pipe to tail; the GATE summary stays the final stdout line.
B-153: a run with --lane (not full) has a time budget, [budget] in tests/gate.toml, 300 s by default and
never more (ctf/gate/budget.py): refused before it starts when the recorded cost is already over, and
exit 3 after a run whose measured cost was over (`budget=over:...` on the GATE line); --budget S
overrides. When tests/gate.toml names a `baseline` ledger, every red file's failing tests are split
into new and baseline reds (`red_new=` / `red_baseline=`, ctf/gate/baseline.py); a red stays red.
`prearm` exits 0 green, 1 red or any ENV file, 2 usage, 4 preflight refused (ctf/gate/prearm.py).
State: $CTF_GATE_STATE, else <git common dir>/ctf-gate (ctf.paths.gate_state).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from ._idle import add_idle_lock_args, idle_lock_factory

HELP = "impact-selected regression gate: plan, run (warm reuse, load-scaled walls, --lane, --jobs), inventory"


def _selectors(p: argparse.ArgumentParser) -> None:
    p.add_argument("--base", help="git ref: gate the files changed since it")
    p.add_argument("--changed", nargs="+", default=[], metavar="FILE", help="changed files (repo-relative)")
    p.add_argument("--lane", help="only test files of this lane")
    p.add_argument("--batch", help="batch id: its first run is the full run")
    p.add_argument("--full", action="store_true", help="every test file, no warm reuse")


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", type=Path, help="checkout to gate (default: this one)")
    p.add_argument("--config", type=Path, help="gate config (default: <root>/tests/gate.toml)")
    p.add_argument("--state", type=Path, help="state folder (default: ctf.paths.gate_state())")
    p.add_argument("--python", help="interpreter for the pytest children (default: $CTF_PYTHON, the "
                                    "checkout's .venv, the main checkout's .venv, then this one; B-153)")
    sp = p.add_subparsers(dest="action", required=True)
    pl = sp.add_parser("plan", help="show the selection and which files a run would reuse warm")
    _selectors(pl)
    pl.add_argument("--json", action="store_true")
    pl.add_argument("--jobs", type=int, default=2, help="jobs the lane budget estimate assumes (default 2)")
    pl.add_argument("--budget", type=float, help="override the lane budget, in seconds (B-153)")
    ru = sp.add_parser("run", help="run the selection, one line per file, one GATE line")
    _selectors(ru)
    ru.add_argument("--budget", type=float, help="override the lane budget, in seconds (B-153)")
    ru.add_argument("--jobs", type=int, default=2, help="test files at a time (default 2)")
    ru.add_argument("--no-warm", action="store_true", help="run every selected file even when a warm result matches")
    ru.add_argument("--out", type=Path, help="folder for per-file output (default: under the state folder)")
    ru.add_argument("--pytest-arg", action="append", default=[], help="extra pytest argument (repeatable)")
    ru.add_argument("--allow-not-run", action="append", default=[], metavar="KIND",
                    help="accept tests that did not run of this kind (needs_tool, needs_realdata, live, "
                         "known-fail, xfail, skip; 'any' turns strict not-run off for this run). The gate is "
                         "strict by default: a file with a not-run test of another kind is NOTRUN, which is red "
                         "(B-196); tests/gate.toml not_run_ok lists the kinds always accepted")
    ru.add_argument("--mark-green", metavar="SLUG",
                    help="after a green FULL run (every test file, no lane filter, no warm reuse, no "
                         "pytest selection args) on a clean tree, tag HEAD green for event SLUG (the "
                         "B-197 rollback target, ctf.arm.mark_green); a refusal exits 2 before running")
    add_idle_lock_args(ru)
    sp.add_parser("inventory", help="refresh the content-hash dependency inventory and print its counts")
    bu = sp.add_parser("budget", help="each lane's cost estimate against its budget (exit 3 when one is over)")
    bu.add_argument("--lane", help="only this lane")
    bu.add_argument("--jobs", type=int, default=2, help="jobs the estimate assumes (default 2)")
    bu.add_argument("--import-junit", type=Path, metavar="XML",
                    help="first seed the timings store from a full-suite junit (files with no gate record)")
    bu.add_argument("--json", action="store_true")
    bl = sp.add_parser("baseline", help="the tracked baseline ledger of known reds (check, list, keys, add)")
    bl.add_argument("what", choices=("check", "list", "keys", "add"))
    bl.add_argument("id", nargs="?", help="add: the pytest node id")
    bl.add_argument("--kind", help="add: " + " | ".join(("flaky", "env", "stale", "broken")))
    bl.add_argument("--reason", help="add: what fails and why")
    bl.add_argument("--owner", default="", help="add: the item that will fix it")
    pa = sp.add_parser("prearm", help="the pre-arm full gate: preflight checks, then a full index-free run")
    pa.add_argument("--jobs", type=int, default=2, help="test files at a time (default 2)")
    pa.add_argument("--out", type=Path, help="folder for per-file output (default: under the state folder)")
    pa.add_argument("--mark-green", metavar="SLUG", help="on a green pre-arm run, tag HEAD green (as run --full)")
    add_idle_lock_args(pa)   # prearm runs files through _execute, which takes the idle lock as run does (B-213)


def _setup(args):
    from .. import paths
    from ..gate import config as gconfig
    from ..gate.impact import Graph
    from ..gate.warm import checkout_state
    root = (args.root or paths.repo_root()).resolve()
    cfg = gconfig.load(root, args.config)
    try:
        state = args.state.resolve() if args.state else paths.gate_state(root)
    except FileNotFoundError as e:
        from ..gate import GateError
        raise GateError(str(e)) from e
    t0 = time.monotonic()
    # A full run lists the tree without reading the git index (B-137): what is staged -- a deletion, an
    # add, a `git rm --cached` -- must not change which files a full run sees. An impact run is about
    # the working tree's changes, so it keeps the fast index-based listing.
    index_free = bool(getattr(args, "full", False))
    graph = Graph(root, cfg, checkout_state(state, root), use_index=not index_free)
    return root, cfg, state, graph, time.monotonic() - t0


def _rel(root: Path, f: str) -> str:
    p = Path(f)
    if p.is_absolute():
        try:
            return p.resolve().relative_to(root).as_posix()
        except ValueError:
            from ..gate import GateError
            raise GateError(f"--changed {f} is outside the checkout {root}")
    s = p.as_posix()
    while s.startswith("./"):
        s = s[2:]
    return s


def choose(graph, args, state: Path):
    """The Selection for these arguments (see the module docstring for the rules)."""
    from ..gate import GateError
    from ..gate.impact import Selection, changed_files
    from ..gate.warm import Batches, check_batch_id
    root = graph.root
    changed = [_rel(root, f) for f in args.changed]
    if args.base:
        changed += changed_files(root, args.base)
    has_changes = bool(args.base or args.changed)
    if args.batch:
        check_batch_id(args.batch)
    batch_rec = Batches(state).full_run(args.batch) if args.batch else None
    if args.full:
        sel = graph.full_selection(["full: --full"])
    elif args.batch and batch_rec is None:
        sel = graph.full_selection([f"full: first run of batch {args.batch} (one full run per batch)"])
    elif has_changes:
        sel = graph.select(changed)
    elif args.lane:
        tests = graph.lane_tests(args.lane)
        if not tests:
            raise GateError(f"lane {args.lane!r} selects no test file")
        sel = Selection("lane", tests, [f"lane {args.lane}: {len(tests)} of {len(graph.tests)} test files"],
                        {t: ["<lane>"] for t in tests})
    elif args.batch:
        raise GateError(f"batch {args.batch} already had its full run "
                        f"({time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(batch_rec['ts']))}, "
                        f"result={batch_rec.get('result')}); give --base or --changed for an impact run, or --full")
    else:
        raise GateError("say what to gate: --base REF, --changed FILE ..., --lane L, --batch ID or --full")
    if args.lane and sel.mode != "lane":
        lane = set(graph.lane_tests(args.lane))
        kept = [t for t in sel.tests if t in lane]
        sel.reasons.append(f"lane {args.lane}: {len(kept)} of {len(sel.tests)} selected files")
        sel.tests = kept
        sel.why = {t: sel.why[t] for t in kept}
    if args.lane and sel.mode != "full":
        _leave_full_only(graph, sel, args.lane)
    if batch_rec is not None and sel.mode != "full":
        _carry_batch_red(graph, sel, args.batch, batch_rec)
    return sel


def _leave_full_only(graph, sel, lane: str) -> None:
    """Drop the `[budget] full_only` files from a lane selection (B-153): they cannot fit a five-minute
    lane gate, so the full and pre-arm gates run them. Never silent: the reason line names every one."""
    from ..gate import GateError
    left = [t for t in sel.tests if graph.cfg.is_full_only(t)]
    if not left:
        return
    sel.tests = [t for t in sel.tests if t not in left]
    sel.why = {t: w for t, w in sel.why.items() if t not in left}
    sel.reasons.append(f"lane {lane}: {len(left)} full-only file(s) NOT run here, left to the full and pre-arm "
                       f"gates ([budget] full_only): {', '.join(left)}")
    if not sel.tests and sel.mode == "lane":
        raise GateError(f"lane {lane!r}: every file it selects is full-only ({', '.join(left)}); run --full "
                        f"or `ctf gate prearm`")


def _carry_batch_red(graph, sel, batch: str, rec: dict) -> None:
    """Add the batch's red files to a later run of the batch, after any lane filter: a failure found by the
    full run (or a later run) is rerun until it is green, whatever the new change touches."""
    red = rec["red"]
    if not red:
        return
    tests = set(graph.tests)
    live = [t for t in red if t in tests]
    gone = [t for t in red if t not in tests]
    added = [t for t in live if t not in sel.why]
    for t in live:
        sel.why.setdefault(t, []).append(f"red in batch {batch}")
    sel.tests = sorted(set(sel.tests) | set(live))
    if live:
        sel.reasons.append(f"batch {batch}: {len(live)} red file(s) rerun until green"
                           + (f" ({len(added)} not otherwise selected)" if added else ""))
    if gone:
        sel.reasons.append(f"batch {batch}: red file(s) no longer in the tree, dropped: {', '.join(gone)}")


def batch_red(args, state: Path) -> set:
    """The batch's red files: a run of the batch never reuses them warm."""
    from ..gate.warm import Batches
    rec = Batches(state).full_run(args.batch) if args.batch else None
    return set(rec["red"]) if rec else set()


def _warm_flags(graph, sel, state, warm_on: bool, pytest_args=(), no_reuse=(), python: str | None = None):
    from ..gate.config import matches
    from ..gate.warm import WarmStore, file_key
    store = WarmStore(state)
    out = {}
    for t in sel.tests:
        key = file_key(graph, t, pytest_args, python)
        out[t] = bool(warm_on and t not in no_reuse and not matches(t, graph.cfg.no_warm) and store.get(key, t))
    graph.hashes.save()
    return out


def _python(args, root: Path):
    """The pytest children's interpreter (ctf.pyinterp, B-153): --python, else the resolved one."""
    from ..gate import GateError
    from .. import pyinterp
    if getattr(args, "python", None):
        p = Path(args.python)
        if not (p.is_file() and os.access(p, os.X_OK)):
            raise GateError(f"--python {args.python} is not an executable interpreter")
        return pyinterp.Interpreter(str(args.python), "--python")
    try:
        return pyinterp.resolve(root)
    except pyinterp.PythonError as e:
        raise GateError(str(e)) from e


def _lane_budget(args, cfg, sel):
    """(limit seconds, the lane) when a lane budget applies to this run, else (None, None): a run with
    --lane whose selection is not a full run (B-153). The selection's mode is the one test: --full, a
    batch's first run and a changed global input all make a full selection, which has no lane budget."""
    from ..gate import budget
    lane = getattr(args, "lane", None)
    if not lane or sel.mode == "full":
        return None, None
    return budget.lane_budget(cfg, lane, getattr(args, "budget", None)), lane


def _plan(args) -> int:
    from ..gate import budget
    root, cfg, state, graph, _ = _setup(args)
    sel = choose(graph, args, state)
    py = _python(args, root)
    warm = _warm_flags(graph, sel, state, sel.mode != "full", no_reuse=batch_red(args, state), python=py.path)
    limit, lane = _lane_budget(args, cfg, sel)
    est = None
    if limit is not None:
        est = budget.estimate(lane, [t for t in sel.tests if not warm[t]], budget.Timings(state).load(),
                              budget=limit, jobs=args.jobs)
    rc = budget.EXIT_OVER_BUDGET if est is not None and est.over else 0
    if args.json:
        d = sel.to_json()
        d["warm"] = sorted(t for t, w in warm.items() if w)
        d["python"] = py.path
        if args.lane and sel.mode != "full":
            d["no_lane"] = no_lane_tests(graph)
        if est is not None:
            d["budget"] = {"lane": lane, "limit": est.budget, "estimate": round(est.cost, 1), "jobs": est.jobs,
                           "known": est.known, "unknown": est.unknown, "over": est.over, "fits_at_jobs": est.fit_jobs}
        print(json.dumps(d, indent=1, sort_keys=True))
        return rc
    print(f"gate: repo={root}")
    print(f"gate: python={py.describe()}")
    for r in sel.reasons:
        print(f"gate: {r}")
    for t in sel.tests:
        why = sel.why.get(t, [])
        print(f"{'WARM' if warm[t] else 'RUN '}  {t}" + (f"  <- {', '.join(why[:3])}" + (" ..." if len(why) > 3 else "")
                                                        if why and not why[0].startswith("<") else ""))
    if est is not None:
        print(est.line())
        if est.over:
            print(f"gate: {est.explain()}", file=sys.stderr)
    if args.lane and sel.mode != "full":
        n = len(no_lane_tests(graph))
        print(f"gate: {n} test file(s) are in no lane and never run by a lane gate (`ctf gate budget` names them)")
    nw = sum(warm.values())
    print(f"PLAN mode={sel.mode} files={len(sel.tests)} warm={nw} run={len(sel.tests) - nw}")
    return rc


def _progress(root: Path, state: Path, sel, args):
    """The run's progress file under <state>/progress, read by `ctf live` (B-198)."""
    from .. import progress
    return progress.Progress(state / progress.PROGRESS_DIR, "gate", total=len(sel.tests), jobs=args.jobs,
                             label=sel.mode, head=progress.head_of(root))


def _run(args) -> int:
    from ..gate import GateError, baseline, budget
    if args.jobs < 1:
        raise GateError("--jobs must be at least 1")
    root, cfg, state, graph, _ = _setup(args)
    allow = allowed_not_run(cfg, args.allow_not_run)
    sel = choose(graph, args, state)
    py = _python(args, root)
    ledger = baseline.for_config(root, cfg)
    if getattr(args, "mark_green", None):
        why_not = green_refusal(graph, sel, tuple(args.pytest_arg))
        from ..gate.notrun import ANY
        if not why_not and ANY in allow:
            why_not = "--allow-not-run any: a rollback target needs strict not-run (name the kinds you accept)"
        if why_not:
            print(f"gate: --mark-green {args.mark_green} refused: {why_not}", file=sys.stderr)
            return 2
    limit, lane = _lane_budget(args, cfg, sel)
    if limit is not None:
        # B-153: a lane gate whose recorded cost already exceeds its budget is refused before it starts.
        warm = _warm_flags(graph, sel, state, not args.no_warm, tuple(args.pytest_arg),
                           no_reuse=batch_red(args, state), python=py.path)
        est = budget.estimate(lane, [t for t in sel.tests if not warm[t]], budget.Timings(state).load(),
                              budget=limit, jobs=args.jobs)
        if est.over:
            print(est.line())
            print(f"gate: refused before running: {est.explain()}", file=sys.stderr)
            return budget.EXIT_OVER_BUDGET
    rc, _rep = _execute(args, root, state, graph, sel, python=py, ledger=ledger, lane=lane, limit=limit,
                       allow=allow)
    return rc


def _execute(args, root: Path, state: Path, graph, sel, *, python, ledger, lane=None, limit=None, allow=()):
    """Run a chosen selection and report it: rows, the stable fail log, the GATE line, the batch record,
    the lane budget verdict and --mark-green. `allow` is the not-run kinds the run accepts (B-196,
    allowed_not_run). Returns (exit code, Report)."""
    from ..gate import budget
    from ..gate.runner import BAD, format_summary, run_gate
    from ..gate.warm import Batches
    out = args.out or state / "runs" / f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}"
    print(f"gate: repo={root}")
    print(f"gate: python={python.describe()}")
    print(f"gate: output={out}")
    if ledger is not None:
        print(f"gate: baseline ledger {ledger.path} ({len(ledger)} known red test(s)) attributes every red")
    for r in sel.reasons:
        print(f"gate: {r}")
    from ..gate.notrun import ANY
    print("gate: not-run: " + ("not strict (--allow-not-run any)" if ANY in allow else
                               "strict, accepted kinds: " + (", ".join(allow) or "none")))
    sys.stdout.flush()
    idle = idle_lock_factory(args, root, "gate run")
    prog = _progress(root, state, sel, args)
    pytest_args = tuple(getattr(args, "pytest_arg", ()) or ())
    try:
        rep = run_gate(graph, sel, state=state, out_dir=out, jobs=args.jobs,
                       warm=(sel.mode != "full" and not getattr(args, "no_warm", False)), pytest_args=pytest_args,
                       emit=lambda s: (print(s), sys.stdout.flush()), no_reuse=batch_red(args, state),
                       on_row=lambda r: prog.step(seconds=r.seconds, warm=bool(r.warm),
                                                  bad=r.test if r.status in BAD else None),
                       python=python.path, baseline=ledger, allow_not_run=allow, idle=idle)
    except KeyboardInterrupt:
        prog.finish("interrupted")
        raise
    except BaseException:
        prog.finish("error")              # a crashed gate is not an interrupted one
        raise
    prog.finish("pass" if rep.ok else "fail")
    # A stable record of this run at a fixed path, so a red is never lost to a pipe (B-137): the per-run
    # output dir has a fresh name each time, but <state>/last-fail.log always names what failed. Written
    # before the GATE summary, which stays the final line tools parse.
    from .. import progress
    from ..gate import faillog
    try:
        log_path = faillog.record(state, root, rep, run_dir=out, head=progress.head_of(root))
        env_n = rep.count("ENV")
        if not rep.ok or env_n:
            print(f"gate: see {log_path}"
                  + (f" ({env_n} file(s) blocked by the environment, not counted as failures)" if env_n else ""))
    except OSError as e:
        print(f"gate: could not write the stable fail log: {e}", file=sys.stderr)
    over = None
    if limit is not None:
        m = budget.measured(lane, rep.rows, budget=limit, jobs=args.jobs, cpus=rep.cpus)
        rep.budget = f"{'over' if m.over else 'ok'}:{m.cost:.0f}/{limit:.0f}s"
        if m.over:
            over = m
            print(f"gate: OVER BUDGET: {m.explain()}", file=sys.stderr)
    print(format_summary(rep))
    red = [r.test for r in rep.rows if r.status in BAD]
    batch = getattr(args, "batch", None)
    if batch and sel.mode == "full":
        Batches(state).record_full(batch, result="pass" if rep.ok else "fail", files=len(rep.rows),
                                   seconds=rep.seconds, red=red)
        print(f"gate: batch {batch} full run recorded; later runs of the batch are impact runs"
              + (f" and rerun its {len(red)} red file(s) until green" if red else ""))
    elif batch:
        gone = set(Batches(state).full_run(batch)["red"]) - set(graph.tests)
        # only a file that really ran can leave the red list: a warm row is a stored result, not a rerun
        ran = [r.test for r in rep.rows if not r.warm]
        now = Batches(state).update_red(batch, ran=ran + sorted(gone), red=red)
        print(f"gate: batch {batch} red files: " + (", ".join(now) if now else "none"))
    if not rep.ok:
        return 1, rep
    if over is not None:
        return budget.EXIT_OVER_BUDGET, rep
    if getattr(args, "mark_green", None):
        return _mark_green(root, args.mark_green, sel.mode, len(rep.rows), env=rep.count("ENV")), rep
    return 0, rep


def allowed_not_run(cfg, extra) -> tuple:
    """The not-run kinds a CLI run accepts: tests/gate.toml not_run_ok plus --allow-not-run (B-196)."""
    from ..gate import GateError
    from ..gate.notrun import check_allow
    try:
        extra = check_allow(extra or ())
    except ValueError as e:
        raise GateError(f"--allow-not-run: {e}") from e
    return tuple(dict.fromkeys((*cfg.not_run_ok, *extra)))


# pytest options that narrow which tests in a file run: a run with one of them is not a full green.
_NARROWING = ("-k", "-m", "--deselect", "--lf", "--last-failed", "--sw", "--stepwise", "--ignore",
              "--ignore-glob", "--co", "--collect-only")


def green_refusal(graph, sel, pytest_args: tuple = ()) -> str:
    """Why this selection cannot mark a rollback target, or "" when it can. Only a full run counts:
    every test file in the tree, none reused warm, none filtered out by a lane or a pytest selection
    option. A green impact or lane run proves only the files it ran, so it would make a commit the
    'last green' that most of the suite never ran on."""
    if sel.mode != "full":
        return (f"this {sel.mode} run is not a full green (it gates {len(sel.tests)} of "
                f"{len(graph.tests)} test files); run with --full")
    if set(sel.tests) != set(graph.tests):
        return (f"the run gates {len(sel.tests)} of {len(graph.tests)} test files (a --lane filter); "
                f"a rollback target needs every file")
    for a in pytest_args:
        flag = a.split("=", 1)[0]
        if flag in _NARROWING or (flag[:2] in ("-k", "-m") and not flag.startswith("--")):
            return f"--pytest-arg {a} narrows the tests that run; a rollback target needs all of them"
    return ""


def _mark_green(root: Path, slug: str, mode: str, files: int, *, env: int = 0) -> int:
    """Tag HEAD green for `slug` after a green run (B-197). Refused, exit 2, when nothing was gated,
    the tree is dirty (the run then does not describe HEAD), or any file was ENV. An ENV file was
    blocked by the environment and never actually exercised its code (envfail.py), so it does not turn
    the gate red -- but a rollback target that counted it green would be exactly the lie B-137 exists to
    stop: the arm step must not mark HEAD on code a part of the suite never verified."""
    from .. import arm
    from ..promote import PromoteError
    if files == 0:
        print(f"gate: --mark-green {slug} refused: the run gated no test file", file=sys.stderr)
        return 2
    if env:
        print(f"gate: --mark-green {slug} refused: {env} file(s) were blocked by the environment (ENV) "
              f"and not proven green; a rollback target needs every file actually verified", file=sys.stderr)
        return 2
    try:
        t = arm.mark_green(slug, master=root, require_clean=True, note=f"gate {mode} run, {files} file(s)")
    except PromoteError as e:
        print(f"gate: --mark-green {slug} refused: {e}", file=sys.stderr)
        return 2
    print(f"gate: marked green {slug} at {t.commit[:12]}: {t.name}")
    return 0


def _inventory(args) -> int:
    root, cfg, state, graph, secs = _setup(args)
    s = graph.stats
    print(f"INVENTORY files={len(graph.files)} python={s.total} parsed={s.computed} reused={s.reused} "
          f"removed={s.removed} hashed={graph.hashes.hashed} tests={len(graph.tests)} seconds={secs:.2f}"
          + (f"  ({s.rebuilt})" if s.rebuilt else "") + (f"  ({graph.hashes.rebuilt})" if graph.hashes.rebuilt else ""))
    return 0


def no_lane_tests(graph) -> list[str]:
    """The test files no lane selects (B-153): a lane gate never runs them, so `ctf gate budget` and
    `plan --lane` name them instead of leaving the gap silent."""
    return [t for t in graph.tests if not graph.lanes_of(t)]


def _budget_cmd(args) -> int:
    """Every lane's (or one lane's) cost estimate from the timings store, against its budget (B-153)."""
    from ..gate import GateError, budget
    if args.jobs < 1:
        raise GateError("--jobs must be at least 1")
    root, cfg, state, graph, _ = _setup(args)
    if args.import_junit:
        n, unknown = budget.import_junit(state, args.import_junit, graph.tests)
        print(f"gate: imported {n} file timing(s) from {args.import_junit}"
              + (f"; {len(unknown)} junit file(s) are not test files here (ignored)" if unknown else ""))
    lanes = [args.lane] if args.lane else sorted(cfg.lanes)
    if not lanes:
        raise GateError(f"{cfg.path} defines no [lanes]")
    timings = budget.Timings(state).load()
    ests = []
    left = {}
    for lane in lanes:
        tests = graph.lane_tests(lane)
        left[lane] = [t for t in tests if cfg.is_full_only(t)]
        tests = [t for t in tests if not cfg.is_full_only(t)]
        ests.append(budget.estimate(lane, tests, timings, budget=budget.lane_budget(cfg, lane), jobs=args.jobs))
    if args.json:
        print(json.dumps([{"lane": e.lane, "limit": e.budget, "estimate": round(e.cost, 1), "jobs": e.jobs,
                           "known": e.known, "unknown": len(e.unknown), "over": e.over,
                           "fits_at_jobs": e.fit_jobs, "top": [[t, round(c, 1)] for t, c in e.top],
                           "full_only": left[e.lane]}
                          for e in ests], indent=1))
    else:
        for e in ests:
            print(e.line())
            if left[e.lane]:
                print(f"gate: lane {e.lane} leaves {len(left[e.lane])} full-only file(s) to the full gate: "
                      f"{', '.join(left[e.lane])}")
            if e.over:
                print(f"gate: {e.explain()}", file=sys.stderr)
    over = [e.lane for e in ests if e.over]
    if not args.json:
        nolane = no_lane_tests(graph)
        print(f"gate: {len(nolane)} test file(s) are in no lane: a lane gate never runs them, only an impact "
              f"run (--base/--changed) and the full gate do" + (f": {', '.join(nolane)}" if nolane else ""))
        print(f"BUDGETS lanes={len(ests)} over={len(over)}" + (f" ({', '.join(over)})" if over else ""))
    return budget.EXIT_OVER_BUDGET if over else 0


def _baseline_cmd(args) -> int:
    """check | list | keys | add for the tracked baseline ledger (B-153)."""
    from .. import paths
    from ..gate import GateError, baseline, config as gconfig
    root = (args.root or paths.repo_root()).resolve()
    cfg = gconfig.load(root, args.config)
    if not cfg.baseline:
        raise GateError(f"{cfg.path} names no baseline ledger (baseline = \"tests/gate_baseline.toml\")")
    path = root / cfg.baseline
    if args.what == "add":
        if not (args.id and args.kind and args.reason):
            raise GateError("baseline add needs the node id, --kind and --reason")
        if args.kind not in baseline.KINDS:
            raise GateError(f"--kind must be one of {', '.join(baseline.KINDS)}")
        if not (root / args.id.split("::", 1)[0]).is_file():
            raise GateError(f"{args.id}: no such test file in {root}")
        e = baseline.append_entry(path, args.id, args.kind, args.reason, owner=args.owner)
        print(f"gate: added {e.id} ({e.describe()}) to {cfg.baseline}")
        return 0
    led = baseline.load(path)
    if args.what == "keys":
        for k in led.keys():
            print(k)
        return 0
    if args.what == "list":
        for e in sorted(led.entries.values(), key=lambda e: (e.since, e.id)):
            print(f"{e.since.isoformat()}  {e.kind:<6} {e.id}  {e.reason}" + (f"  [{e.owner}]" if e.owner else ""))
        print(f"BASELINE entries={len(led)}")
        return 0
    stale = led.stale(root)
    for e in stale:
        print(f"gate: stale baseline entry (its test file is gone): {e.id}", file=sys.stderr)
    print(f"BASELINE entries={len(led)} stale={len(stale)} result={'fail' if stale else 'ok'}")
    return 1 if stale else 0


def _prearm_cmd(args) -> int:
    """The pre-arm full gate (B-153): preflight checks, then a full index-free run with nothing reused.
    Exit 0 green, 1 red (an ENV file counts: the pre-arm gate needs every file verified), 2 usage or a
    refused --mark-green, 4 preflight refused (nothing ran)."""
    from ..gate import GateError, baseline, prearm
    if args.jobs < 1:
        raise GateError("--jobs must be at least 1")
    args.full, args.batch, args.lane, args.base, args.changed = True, None, None, None, []
    args.no_warm, args.pytest_arg = True, []
    root, cfg, state, graph, _ = _setup(args)
    py = _python(args, root)
    checks = prearm.preflight(root, cfg, python=py.path, source=py.source)
    for c in checks:
        print(c.line())
    sys.stdout.flush()
    if any(not c.ok for c in checks):
        prearm.record(state, {"result": "refused", "preflight": prearm.checks_json(checks), "gate": None})
        print(f"gate: pre-arm refused: fix the failing preflight check(s) above; the full gate did not run",
              file=sys.stderr)
        print(prearm.summary("refused", checks))
        return prearm.EXIT_REFUSED
    sel = choose(graph, args, state)
    ledger = baseline.for_config(root, cfg)
    if args.mark_green:
        why_not = green_refusal(graph, sel, ())
        if why_not:
            print(f"gate: --mark-green {args.mark_green} refused: {why_not}", file=sys.stderr)
            return 2
    # strict not-run (B-196): the pre-arm full gate accepts only tests/gate.toml not_run_ok
    rc, rep = _execute(args, root, state, graph, sel, python=py, ledger=ledger, allow=allowed_not_run(cfg, ()))
    env_n = rep.count("ENV")
    if rc == 0 and env_n:
        rc = 1          # a plain run lets ENV through; the pre-arm gate needs every file verified
        print(f"gate: pre-arm fails: {env_n} file(s) were blocked by the environment (ENV) and verified nothing",
              file=sys.stderr)
    result = "pass" if rc == 0 else "fail"
    prearm.record(state, {"result": result, "preflight": prearm.checks_json(checks),
                          "gate": {"ok": rep.ok, "files": len(rep.rows), "env": env_n,
                                   "red": [r.test for r in rep.rows if r.status in ("FAIL", "ERROR", "TIMEOUT")]}})
    print(prearm.summary(result, checks, rep))
    return rc


def run(args: argparse.Namespace) -> int:
    from ..gate import GateError
    from ..workreg import WorkRegError
    try:
        return {"plan": _plan, "run": _run, "inventory": _inventory, "budget": _budget_cmd,
                "baseline": _baseline_cmd, "prearm": _prearm_cmd}[args.action](args)
    except (GateError, WorkRegError) as e:
        print(f"gate: error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("gate: interrupted", file=sys.stderr)
        return 130
