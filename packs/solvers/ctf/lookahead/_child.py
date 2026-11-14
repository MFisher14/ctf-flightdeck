"""The look-ahead reader child (B-174). Not a command for people; ctf.lookahead.gate starts it as

    <python> -I ctf/intake/_guardboot.py --mode M -- ctf/engines/_boot.py --repo R --no-ledger
             -m ctf.lookahead._child JOB.json OUT.jsonl

under the intake network guard. JOB.json: {"reader": <path>, "timeout": <s>, "specimens":
[{"name", "dir", "ctx"}]}. It loads the reader module once (ctf.packs.load_module) and calls its
solve_set(questions, files, ctx) on each specimen in turn, each under a SIGALRM cap. One JSON line per
specimen is appended to OUT.jsonl as soon as it is done, so a child that dies mid-matrix still leaves
every finished result:

    {"name", "status": "ran" | "crashed" | "cut", "reason", "answers", "seconds"}

A reader that does not load writes one {"status": "load_error", "reason"} line and exits 3.
"""
from __future__ import annotations

import json
import signal
import sys
import time
import traceback
from pathlib import Path


class _Cut(BaseException):
    """The per-specimen cap fired (a BaseException so a reader's `except Exception` cannot eat it)."""


def _alarm(signum, frame):
    raise _Cut()


def _files(sdir: Path) -> dict:
    fdir = sdir / "files"
    return {p.relative_to(fdir).as_posix(): p.read_bytes()
            for p in sorted(fdir.rglob("*")) if p.is_file() and not p.is_symlink()}


def _questions(sdir: Path) -> list:
    body = json.loads((sdir / "questions.json").read_text(encoding="utf-8"))
    return body.get("questions") if isinstance(body, dict) else body


def _jsonable(answers) -> dict:
    return json.loads(json.dumps(answers, default=str))


def _emit(out, rec: dict) -> None:
    out.write(json.dumps(rec, sort_keys=True) + "\n")
    out.flush()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("_child: usage: JOB.json OUT.jsonl", file=sys.stderr)
        return 2
    job = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    from ctf import packs
    with open(argv[1], "a", encoding="utf-8") as out:
        try:
            mod = packs.load_module("_lookahead_reader", job["reader"], pack="lookahead-reader")
            solve_set = getattr(mod, "solve_set")
        except (packs.PackError, AttributeError) as e:
            _emit(out, {"status": "load_error", "reason": f"{type(e).__name__}: {str(e)[:300]}"})
            return 3
        signal.signal(signal.SIGALRM, _alarm)
        cap = float(job["timeout"])
        for s in job["specimens"]:
            sdir = Path(s["dir"])
            ctx = {"lookahead": True, "specimen": s["name"], "partial": {}}
            ctx.update(s.get("ctx") or {})
            t0 = time.perf_counter()
            status, reason, answers = "ran", "", {}
            try:
                questions, files = _questions(sdir), _files(sdir)
                signal.setitimer(signal.ITIMER_REAL, cap)
                try:
                    got = solve_set(questions, files, ctx)
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                if not isinstance(got, dict):
                    status, reason = "crashed", f"solve_set returned {type(got).__name__}, not a dict"
                else:
                    answers = _jsonable(got)
            except _Cut:
                status, reason = "cut", f"cut at the {cap:g}s cap"
                answers = _jsonable(ctx.get("partial") or {})
            except Exception as e:  # the reader's own failure is the specimen's result, named
                tb = traceback.extract_tb(e.__traceback__)
                at = f" at {Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else ""
                status, reason = "crashed", f"{type(e).__name__}: {str(e)[:200]}{at}"
            _emit(out, {"name": s["name"], "status": status, "reason": reason, "answers": answers,
                        "seconds": round(time.perf_counter() - t0, 4)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
