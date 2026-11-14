"""ctf integrity -- test and docs integrity checks (B-196, ctf/integrity).

    python -m ctf integrity mutate FILE [--function NAME ...] [--lines A-B] [--op OP ...] [--max N]
                                        [--tests T ...] [--min-score S] [--json]
        mutate FILE in a temporary copy of the checkout and run the tests the gate selects for it;
        exit 0 when the kill score reaches --min-score (default 1.0), 1 below it
    python -m ctf integrity fakes [--source DIR ...] [--json]
        every CTF_TESTING / stub branch has a test that takes it with the flag off (or a waiver in
        tests/fake_branches.toml); exit 1 when one is missing or a waiver is stale
    python -m ctf integrity collected [--json]
        every tests/ file that defines tests is collected by pytest and selected by the gate; exit 1 on a
        finding not in tests/collection_known.toml, or a stale entry there
    python -m ctf integrity doclint [DOC ...] [--json]
        the maintained docs name only existing paths, links and ctf commands; exit 1 on a finding not in
        tests/doclint_known.toml, or a stale entry there
    python -m ctf integrity preserve [--run] [--lane L ...] [--recorded] [--allow-not-run KIND ...] [--json]
        the known solve paths (tests/known_solves.toml) keep live, non-hollow tests; --run runs them (strict
        not-run), --lane / --recorded replay lane regression sets (event cases from `ctf adapt record`)
    python -m ctf integrity engines --base REF [--json]
        audit every engine manifest added since REF: loads, reached by a test, no hollow test, no
        unaudited fake branch; prints the mutation command for each
    python -m ctf integrity all [--base REF] [--source DIR ...]
        fakes, collected, doclint and preserve (static), plus engines when --base is given

Exit codes: 0 clean, 1 findings (or a run that failed), 2 a usage or configuration error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "test and docs integrity: mutate, fakes, collected, doclint, preserve, engines, all"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", type=Path, help="checkout to check (default: this one)")
    sp = p.add_subparsers(dest="action", required=True)
    m = sp.add_parser("mutate", help="mutation check of one source file against its gate-selected tests")
    m.add_argument("file", help="repo-relative source file")
    m.add_argument("--function", action="append", default=[], help="only mutants in this function (repeatable)")
    m.add_argument("--lines", help="only mutants on lines A-B")
    m.add_argument("--op", action="append", default=[], help="only this operator (repeatable)")
    m.add_argument("--max", type=int, help="at most N mutants, spread evenly over the file")
    m.add_argument("--tests", nargs="+", default=[], help="test files to run instead of the gate's selection")
    m.add_argument("--min-score", type=float, default=1.0, help="kill fraction needed to exit 0 (default 1.0)")
    m.add_argument("--state", type=Path, help="gate state folder (default: ctf.paths.gate_state())")
    m.add_argument("--config", type=Path, help="gate config (default: <root>/tests/gate.toml)")
    m.add_argument("--json", action="store_true")
    m.add_argument("--list", action="store_true", help="list the mutants and run nothing")
    f = sp.add_parser("fakes", help="fake-branch audit")
    f.add_argument("--source", action="append", default=[], metavar="DIR",
                   help="source folder to audit (repeatable; default: ctf, solvers, tools)")
    f.add_argument("--json", action="store_true")
    c = sp.add_parser("collected", help="every test file is collected and gated")
    c.add_argument("--json", action="store_true")
    d = sp.add_parser("doclint", help="stale paths, links and commands in the maintained docs")
    d.add_argument("docs", nargs="*", help="repo-relative docs (default: every maintained doc)")
    d.add_argument("--json", action="store_true")
    pr = sp.add_parser("preserve", help="known solve paths keep their tests; --run runs them")
    pr.add_argument("--run", action="store_true", help="run every registry test (strict not-run)")
    pr.add_argument("--lane", action="append", default=[], help="replay this lane's regression set (repeatable)")
    pr.add_argument("--recorded", action="store_true", help="replay every lane with event cases in the workdir")
    pr.add_argument("--workdir", type=Path, help="event workdir for --lane/--recorded (default: ctf.paths)")
    pr.add_argument("--allow-not-run", action="append", default=[], metavar="KIND",
                    help="accept a skipped registry test of this kind (default: none)")
    pr.add_argument("--out", type=Path, help="folder for the run's per-file output (default: a temp folder)")
    pr.add_argument("--json", action="store_true")
    e = sp.add_parser("engines", help="audit engine manifests added since a ref")
    e.add_argument("--base", required=True, help="git ref to diff against")
    e.add_argument("--state", type=Path, help="gate state folder")
    e.add_argument("--json", action="store_true")
    a = sp.add_parser("all", help="every static check (engines too with --base)")
    a.add_argument("--base", help="git ref: also audit engines added since it")
    a.add_argument("--state", type=Path, help="gate state folder")
    a.add_argument("--source", action="append", default=[], metavar="DIR", help="fakes: source folder (repeatable)")


def _root(args) -> Path:
    from .. import paths
    return (args.root or paths.repo_root()).resolve()


def _parse_lines(spec: str | None):
    from ..integrity import IntegrityError
    if not spec:
        return None
    try:
        a, b = (int(x) for x in spec.split("-", 1)) if "-" in spec else (int(spec), int(spec))
    except ValueError:
        raise IntegrityError(f"--lines {spec!r}: give A-B (line numbers)") from None
    if a < 1 or b < a:
        raise IntegrityError(f"--lines {spec!r}: need 1 <= A <= B")
    return a, b


def _mutate(args) -> int:
    from ..integrity import IntegrityError, mutate
    root = _root(args)
    if not (0.0 <= args.min_score <= 1.0):
        raise IntegrityError("--min-score must be between 0 and 1")
    if args.max is not None and args.max < 1:
        raise IntegrityError("--max must be at least 1")
    ops = tuple(args.op) or mutate.OPS
    lines = _parse_lines(args.lines)
    if args.list:
        ms, counts = mutate.generate(root, args.file, ops=ops, functions=tuple(args.function), lines=lines)
        total = len(ms)
        ms = mutate.spread(ms, args.max)
        for m in ms:
            print(m.describe())
        print(f"MUTANTS {len(ms)} of {total} invalid={counts['invalid']} duplicate={counts['duplicate']} "
              f"pragma={counts['pragma']}")
        return 0
    emit = (lambda s: None) if args.json else (lambda s: (print(s), sys.stdout.flush()))
    rep = mutate.run(root, args.file, tests=args.tests or None, ops=ops, functions=tuple(args.function),
                     lines=lines, max_mutants=args.max, state=args.state, config=args.config, emit=emit)
    if args.json:
        print(json.dumps(rep.to_json(), indent=1))
    else:
        print(rep.summary())
    return 0 if rep.score >= args.min_score else 1


def _fakes(args) -> int:
    from ..integrity import fakes
    res = fakes.audit(_root(args), source_dirs=tuple(getattr(args, "source", None) or fakes.SOURCE_DIRS))
    if args.json:
        print(json.dumps({"ok": res.ok, "findings": res.findings,
                          "branches": [{"path": b.path, "line": b.line, "function": b.function, "flags": list(b.flags),
                                        "process": b.process, "status": b.status, "evidence": b.evidence,
                                        "waived": b.waived} for b in res.branches]}, indent=1))
    else:
        for b in res.branches:
            print(b.text())
        for f in res.findings:
            print(f)
        print(f"FAKES branches={len(res.branches)} covered={sum(b.status == 'COVERED' for b in res.branches)} "
              f"waived={sum(b.status == 'WAIVED' for b in res.branches)} findings={len(res.findings)}")
    return 0 if res.ok else 1


def _known_report(name: str, res, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"ok": res.ok, "new": [vars(f) for f in res.new], "known": [vars(f) for f in res.known],
                          "stale": res.stale}, indent=1))
    else:
        for f in res.new:
            print(f.text())
        for s in res.stale:
            print(f"STALE known entry (no finding matches it any more; delete it): {s}")
        print(f"{name} new={len(res.new)} known={len(res.known)} stale={len(res.stale)}")
    return 0 if res.ok else 1


def _collected(args) -> int:
    from ..integrity import collected
    return _known_report("COLLECTED", collected.audit(_root(args)), args.json)


def _doclint(args) -> int:
    from ..integrity import doclint
    return _known_report("DOCLINT", doclint.audit(_root(args), args.docs or None), args.json)


def _preserve(args) -> int:
    import tempfile
    from ..gate.notrun import check_allow
    from ..integrity import IntegrityError, preserve
    root = _root(args)
    try:
        allow = check_allow(args.allow_not_run)
    except ValueError as e:
        raise IntegrityError(f"--allow-not-run: {e}") from e
    res = preserve.check(root)
    for f in res.findings:
        print(f"FINDING {f}")
    emit = (lambda s: None) if args.json else (lambda s: (print(s), sys.stdout.flush()))
    if args.run:
        out = args.out or Path(tempfile.mkdtemp(prefix="ctf-preserve-"))
        preserve.run(root, res, out_dir=out, allow_not_run=allow, emit=emit)
    lanes = list(args.lane)
    if args.recorded:
        from .. import paths
        from ..adapt import regress
        wd = args.workdir or paths.workdir()
        lanes += [x for x in regress.recorded_lanes(wd) if x not in lanes]
        if not lanes:
            raise IntegrityError(f"--recorded: no lane has event cases under {wd} (record them with ctf adapt record)")
    if lanes:
        kw = {"root": root}
        if args.workdir:
            kw["workdir"] = args.workdir
        preserve.run_lanes(lanes, res, emit=emit, **kw)
    if args.json:
        print(json.dumps({"ok": res.ok, "findings": res.findings, "solves": [s.id for s in res.solves],
                          "runs": [{"tests": n, "status": r.status, "detail": r.detail} for n, r in res.runs],
                          "lanes": [{"lane": g.lane, "verdict": g.verdict, "reason": g.reason} for g in res.lanes]},
                         indent=1))
    else:
        print(f"PRESERVE solves={len(res.solves)} tests={sum(len(s.tests) for s in res.solves)} "
              f"findings={len(res.findings)} runs={len(res.runs)} "
              f"red={sum(1 for _, r in res.runs if r.status != 'PASS')} lanes={len(res.lanes)} "
              f"result={'pass' if res.ok else 'fail'}")
    return 0 if res.ok else 1


def _engines(args) -> int:
    from ..integrity import newengines
    res = newengines.audit(_root(args), args.base, state=args.state)
    if args.json:
        print(json.dumps([{"manifest": a.manifest, "engine": a.engine, "entry": a.entry, "tests": a.tests,
                           "findings": a.findings, "mutate": a.mutate_command()} for a in res], indent=1))
    else:
        for a in res:
            print(f"{'OK' if a.ok else 'FINDINGS'}  {a.engine or a.manifest}  entry={a.entry or '-'}  "
                  f"tests={len(a.tests)}")
            for f in a.findings:
                print(f"    {f}")
            if a.entry:
                print(f"    next: {a.mutate_command()}")
        print(f"ENGINES new={len(res)} with_findings={sum(1 for a in res if not a.ok)}")
    return 0 if all(a.ok for a in res) else 1


def _all(args) -> int:
    rc = 0
    for name, fn, extra in (("fakes", _fakes, {"source": args.source}), ("collected", _collected, {}), ("doclint", _doclint, {"docs": []}),
                            ("preserve", _preserve, {"run": False, "lane": [], "recorded": False, "workdir": None,
                                                     "allow_not_run": [], "out": None})):
        print(f"== integrity {name}")
        ns = argparse.Namespace(root=args.root, json=False, **extra)
        rc = max(rc, fn(ns))
    if args.base:
        print("== integrity engines")
        rc = max(rc, _engines(argparse.Namespace(root=args.root, json=False, base=args.base, state=args.state)))
    print(f"INTEGRITY result={'pass' if rc == 0 else 'fail'}")
    return rc


def run(args: argparse.Namespace) -> int:
    from ..integrity import IntegrityError
    try:
        return {"mutate": _mutate, "fakes": _fakes, "collected": _collected, "doclint": _doclint,
                "preserve": _preserve, "engines": _engines, "all": _all}[args.action](args)
    except IntegrityError as e:
        print(f"integrity: error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("integrity: interrupted", file=sys.stderr)
        return 130
