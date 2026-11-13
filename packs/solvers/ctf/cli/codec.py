"""ctf codec FILE... — the shared recursive codec graph (B-163, ctf/codec/) on a blob, no model.

    python -m ctf codec blob.txt --event csctf                    # oracle: the event flag format
    python -m ctf codec blob.txt --crib "Nice work" --slug        # a slug answer right after the crib
    python -m ctf codec mastery.txt --records --crib "..." --slug # numbered records, joined at the true cut
    python -m ctf codec day*.txt --consensus --crib "..." --slug  # N sibling record sets, consensus chains
    python -m ctf codec blob.txt --pack warmups --depth 10 --json

Exit 0 when exactly one answer was reached for every file, 1 when a file reached none or several
(the candidates are printed), 2 when it could not run (unreadable or oversized file, no flag format
for the event, an unknown or missing codec pack, a file that is not numbered records under
--records/--consensus). Files are untrusted data: read and decoded, never executed. Nothing is
submitted.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .. import event as _event
from ..packs import PackError

HELP = "decode a blob through the shared recursive codec graph toward a flag, crib or slug (no model)"
MAX_FILE = 1 << 20


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("files", nargs="+", help="blob file(s); with --consensus, the sibling record sets")
    p.add_argument("--event", help="event slug for the flag format (default: $CTF_EVENT / the only profile)")
    p.add_argument("--crib", help="known plaintext: the oracle (or, with --slug, what the slug follows)")
    p.add_argument("--slug", action="store_true", help="the answer is a slug word-word-word-NN")
    p.add_argument("--slug-pattern", help="a challenge-stated answer shape instead of the default slug")
    p.add_argument("--records", action="store_true", help="the file is numbered records NN<TAB>payload")
    p.add_argument("--consensus", action="store_true", help="the files are sibling record sets: N-record consensus")
    p.add_argument("--group", choices=("index", "all"), default="index",
                   help="consensus key: record number across sets (index) or every record (all)")
    p.add_argument("--min-n", type=int, default=3, help="records that must agree on a chain (default 3)")
    p.add_argument("--pack", action="append", default=[], help="add a codec breadth pack (e.g. warmups)")
    p.add_argument("--depth", type=int, default=None, help="max codec steps in a chain (default 8)")
    p.add_argument("--nodes", type=int, default=None, help="max decode attempts (default 40000)")
    p.add_argument("--budget", type=float, default=None, help="seconds for the whole run")
    p.add_argument("--json", action="store_true", help="print JSON")


class _Usage(Exception):
    pass


def _oracle(args):
    from ..codec import CribOracle, FlagOracle, SlugOracle
    from .. import flagfmt
    if args.slug or args.slug_pattern:
        kw = {"pattern": args.slug_pattern} if args.slug_pattern else {}
        return SlugOracle(crib=args.crib, **kw)
    if args.crib:
        return CribOracle(args.crib)
    profile = _event.load(args.event) if args.event else _event.current()
    if not flagfmt.for_profile(profile).known:
        raise _Usage(f"event {profile.slug!r} has no flag format: pass --crib or --slug")
    return FlagOracle(profile)


def _read(path: str) -> bytes:
    p = Path(path)
    if not p.is_file():
        raise _Usage(f"{path}: not a file")
    if p.stat().st_size > MAX_FILE:
        raise _Usage(f"{path}: over {MAX_FILE} bytes; the codec graph reads blobs, not corpora")
    return p.read_bytes()


def run(args: argparse.Namespace) -> int:
    from ..codec import Graph, core
    from ..codec import pack as _pack
    from ..codec import records as R
    try:
        if args.min_n < 1:
            raise _Usage("--min-n must be at least 1")
        oracle = _oracle(args)
        codecs = core()
        for name in args.pack:
            codecs = codecs + _pack.load(name)
        bounds = {k: v for k, v in (("max_depth", args.depth), ("max_nodes", args.nodes)) if v is not None}
        graph = Graph(codecs, **bounds)
        blobs = [(f, _read(f)) for f in args.files]
        deadline = time.monotonic() + args.budget if args.budget else None
        crib = (args.crib or "").encode()
        out = []
        if args.consensus:
            sets = [R.parse(b) for _, b in blobs]
            for (f, _), res in zip(blobs, R.consensus(sets, oracle, crib=crib, min_n=args.min_n, group=args.group,
                                                     graph=graph, deadline=deadline)):
                out.append((f, [res.answer] if res.answer else [], res.reason, res.to_json()))
        else:
            for f, b in blobs:
                if args.records:
                    res = R.assemble(R.parse(b), oracle, crib=crib, graph=graph, deadline=deadline)
                    out.append((f, [res.answer] if res.answer else
                                sorted({a for x in res.assemblies for a in x.answers}), res.reason, res.to_json()))
                else:
                    res = graph.search(b, oracle, deadline=deadline)
                    why = f"cut by its {res.truncated} bound" if res.truncated else "bound searched"
                    out.append((f, res.answers, why, res.to_json()))
    except (_Usage, R.RecordsError, _event.EventError, PackError, ValueError, OSError) as e:
        print(f"ctf codec: {type(e).__name__ if not isinstance(e, _Usage) else 'error'}: {e}", file=sys.stderr)
        return 2
    ok = all(len(answers) == 1 for _, answers, _, _ in out)
    if args.json:
        print(json.dumps([{"file": f, "answers": a, "reason": why, "detail": d} for f, a, why, d in out], indent=1))
    else:
        for f, answers, why, d in out:
            if len(answers) == 1:
                hits = d.get("hits") or []
                how = "+".join(hits[0]["chain"]) if hits else ""
                print(f"{f}: {answers[0]}" + (f"  (via {how or 'plain'})" if hits else "") + f"  [{why}]")
            elif answers:
                print(f"{f}: AMBIGUOUS, {len(answers)} answers: {', '.join(answers[:8])}  [{why}]")
            else:
                print(f"{f}: nothing reached the oracle  [{why}]")
    return 0 if ok else 1
