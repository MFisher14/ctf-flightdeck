"""`python -m ctf lookahead` — the look-ahead completeness gate (B-174, docs/CONTRACTS.md section 35).

    python -m ctf lookahead gate MATRIX [--lane L]... [--timeout S] [--guard auto|os|hook]
                                        [--json] [--report-out FILE] [--no-record]
    python -m ctf lookahead thresholds PATH... [--matrix MATRIX] [--json]
    python -m ctf lookahead scale SPECIMEN OUT --bytes N
    python -m ctf lookahead score FORECAST --lane L --previous P.json --actual A.json [--report R.json]
                                  [--no-record] [--json]
    python -m ctf lookahead plan MATRIX --report R.json [--json]

Common: --workdir DIR (default: ctf.paths.workdir(); the ledger and run folders), --root DIR (the
checkout readers are resolved against).

Exit codes. gate: 0 every lane green, 1 a lane has a gap, 2 an error. thresholds: 0 every found
threshold is declared or waived (or no --matrix), 1 some are not, 2 an error. scale: 0 written, 2 an
error. score: 0 scored (the numbers are the result), 2 an error. plan: 0 no lane needs an agent, 1 some
lane does, 2 an error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import paths as _paths
from ..event import EventError
from ..adapt import qdiff as _qdiff
from ..intake import guard as _guard
from ..lookahead import LookaheadError
from ..lookahead import forecast as _forecast
from ..lookahead import gate as _lgate
from ..lookahead import matrix as _matrix
from ..lookahead import scale as _scale

HELP = "the look-ahead completeness gate: fail on unanswered deterministic facts, skips, thresholds"


def _workdir(args) -> Path:
    return Path(args.workdir) if args.workdir else _paths.workdir()


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="action", required=True)
    g = sub.add_parser("gate", help="run every lane's reader over the matrix; fail on any coverage gap")
    g.add_argument("matrix", type=Path)
    g.add_argument("--lane", action="append", default=[], metavar="L")
    g.add_argument("--timeout", type=float, metavar="S", help="per-specimen cap (default: the lane's)")
    g.add_argument("--guard", choices=_guard.MODES, default="auto")
    g.add_argument("--json", action="store_true")
    g.add_argument("--report-out", type=Path, metavar="FILE", help="write the reports as JSON (for score/plan)")
    g.add_argument("--no-record", action="store_true", help="write no ledger record")
    t = sub.add_parser("thresholds", help="find size thresholds in code; with --matrix, fail on undeclared ones")
    t.add_argument("paths", nargs="+", type=Path)
    t.add_argument("--matrix", type=Path)
    t.add_argument("--json", action="store_true")
    s = sub.add_parser("scale", help="replicate a specimen as sets until it is past a size")
    s.add_argument("specimen", type=Path)
    s.add_argument("out", type=Path)
    s.add_argument("--bytes", type=int, required=True, metavar="N")
    sc = sub.add_parser("score", help="score a forecast against the day")
    sc.add_argument("forecast", type=Path)
    sc.add_argument("--lane", required=True)
    sc.add_argument("--previous", type=Path, required=True, help="the previous base's questions (JSON)")
    sc.add_argument("--actual", type=Path, required=True, help="the day's questions (JSON)")
    sc.add_argument("--report", type=Path, help="the day's gate report (gate --report-out)")
    sc.add_argument("--no-record", action="store_true")
    sc.add_argument("--json", action="store_true")
    p = sub.add_parser("plan", help="which lanes the next look-ahead runs an agent for")
    p.add_argument("matrix", type=Path)
    p.add_argument("--report", type=Path, required=True, help="the gate report (gate --report-out)")
    p.add_argument("--json", action="store_true")
    for sp in (g, t, s, sc, p):
        sp.add_argument("--workdir", type=Path, metavar="DIR")
        sp.add_argument("--root", type=Path, metavar="DIR")


def _read_json(path: Path, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LookaheadError(f"{what} {path}: not there") from None
    except (OSError, ValueError) as e:
        raise LookaheadError(f"{what} {path}: not readable JSON ({e})") from None


def _gate_cmd(args) -> int:
    reports = _lgate.gate(args.matrix, args.lane or None, root=args.root, workdir=_workdir(args),
                         guard=args.guard, timeout=args.timeout, record_to_ledger=not args.no_record)
    body = [r.to_json() for r in reports]
    if args.report_out:
        args.report_out.write_text(json.dumps(body, indent=1, default=str), encoding="utf-8")
    if args.json:
        print(json.dumps(body, indent=1, default=str))
    else:
        for r in reports:
            print("\n".join(r.lines()))
    return 0 if all(r.ok for r in reports) else 1


def _thresholds(args) -> int:
    root = args.root or _paths.repo_root()
    found = _scale.scan(args.paths, root=root)
    left = _scale.undeclared(found, _matrix.load(args.matrix)) if args.matrix else None
    if args.json:
        print(json.dumps({"found": [f.__dict__ for f in found],
                          "undeclared": None if left is None else [f.__dict__ for f in left]}, indent=1))
    else:
        for f in found:
            tag = "" if left is None else ("UNDECLARED " if f in left else "declared   ")
            print(tag + f.line_text())
        if left is not None:
            print(f"{len(found)} threshold(s) found, {len(left)} neither declared nor waived in {args.matrix}")
    return 1 if left else 0


def _scale_cmd(args) -> int:
    out = _scale.replicate(args.specimen, args.out, args.bytes)
    spec = _matrix.load_specimen(out.parent.name, out)
    print(f"wrote {out}: {spec.total_bytes} bytes in {len(spec.sizes)} member(s), {len(spec.questions)} id(s)")
    return 0


def _score(args) -> int:
    fc = _forecast.load(args.forecast)
    report = None
    if args.report:
        body = _read_json(args.report, "report")
        rows = body if isinstance(body, list) else [body]
        mine = [r for r in rows if isinstance(r, dict) and r.get("lane") == args.lane]
        if not mine:
            raise LookaheadError(f"report {args.report}: no lane {args.lane!r}")
        report = mine[0]
    s = _forecast.score(fc, args.lane, _read_json(args.previous, "previous"), _read_json(args.actual, "actual"),
                        report, workdir=None if args.no_record else _workdir(args), record=not args.no_record)
    if args.json:
        print(json.dumps({**s.__dict__, "recall": s.recall}, indent=1))
    else:
        print("\n".join(s.lines()))
    return 0


def plans_from_matrix(matrix: Path, report: Path) -> list:
    """The look-ahead lane plans (`forecast.plan`) for a matrix and its gate report: each matrix lane's
    previous and base questions give its shape. Shared by `lookahead plan` and `helpers arm --matrix`
    (B-212). A missing or unreadable file is a LookaheadError naming it."""
    m = _matrix.load(matrix)
    body = _read_json(report, "report")
    reports = body if isinstance(body, list) else [body]
    shapes = {}
    for lane, cfg in m.lanes.items():
        if cfg.previous is not None and cfg.base is not None:
            shapes[lane] = (_read_json(cfg.previous, "previous"), _read_json(cfg.base, "base"))
        else:
            shapes[lane] = None
    return _forecast.plan(reports, shapes)


def _plan(args) -> int:
    plans = plans_from_matrix(args.matrix, args.report)
    if args.json:
        print(json.dumps([p.__dict__ for p in plans], indent=1))
    else:
        for p in plans:
            print(p.line())
    return 1 if any(p.agent for p in plans) else 0


def run(args: argparse.Namespace) -> int:
    fn = {"gate": _gate_cmd, "thresholds": _thresholds, "scale": _scale_cmd, "score": _score, "plan": _plan}[args.action]
    try:
        return fn(args)
    except (LookaheadError, _qdiff.QDiffError, _guard.GuardError, EventError) as e:
        print(f"lookahead {args.action}: {e}", file=sys.stderr)
        return 2
