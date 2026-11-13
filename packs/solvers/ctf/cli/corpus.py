"""ctf corpus — the blind rehearsal corpus of past challenges (B-155).

    python -m ctf corpus index [--json]
    python -m ctf corpus stage <id> --dest DIR [--event SLUG]
    python -m ctf corpus score <id> --flag FLAG [--event SLUG]
    python -m ctf corpus serve <id> [--probe]
    python -m ctf corpus rehearse [--id ID ...] [--event SLUG] [--keep DIR] [--no-engines]
                                  [--engine-budget S] [--json]
    python -m ctf corpus import SRC --id ID --category CAT [--name N] [--description D]
                                [--key-file F] [--service F] [--strip GLOB ...] [--engine E ...]
                                [--corpus DIR] [--index FILE]

`index` lists the committed index (metadata only) and marks which entries are present in the external
corpus. `stage` copies one challenge blind (key and strip globs removed). `score` scores a flag
against a challenge's key. `serve` starts a challenge's replay service on 127.0.0.1 (with `--probe`
it drives the service's probe once and exits). `rehearse` stages every present challenge blind,
routes it, starts any live service's replay (its probe is a reachability check), serves the
challenges on the B-039 fake CTFd with the replay endpoint as connection_info, runs the no-model
intake (sweep + engines) through the CTFd adapter, and scores what the tooling found, per engine.
`import` copies a cloned public challenge folder into the corpus with its answer files stripped and
prints (or, with --index, appends) its index stanza; the stanza holds no flag.

The corpus is external ($CTF_REHEARSAL_CORPUS); nothing here reaches off-loopback, runs a challenge
binary, or submits. Exit 0 ok / passed, 1 a step failed or the rehearsal failed, 2 a named error
(no corpus, unknown id, bad profile).
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
import tomllib
from pathlib import Path

from .. import corpus as _corpus
from .. import event as _event
from .. import flagfmt as _flagfmt
from .. import paths as _paths
from .. import livereplay as _replay

HELP = "blind rehearsal corpus: stage past challenges blind, score, replay live services"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="corpus_cmd", required=True)

    pi = sub.add_parser("index", help="list the index and which entries are present in the corpus")
    pi.add_argument("--json", action="store_true")

    ps = sub.add_parser("stage", help="stage one challenge blind into DIR")
    ps.add_argument("id")
    ps.add_argument("--dest", type=Path, required=True)
    ps.add_argument("--event")

    psc = sub.add_parser("score", help="score a flag against a challenge's key")
    psc.add_argument("id")
    psc.add_argument("--flag", required=True)
    psc.add_argument("--event")

    psv = sub.add_parser("serve", help="start a challenge's replay service on 127.0.0.1")
    psv.add_argument("id")
    psv.add_argument("--probe", action="store_true", help="drive the service's probe once, then exit")

    pr = sub.add_parser("rehearse", help="stage, route, replay and score the whole corpus")
    pr.add_argument("--id", action="append", dest="ids", metavar="ID", help="only this id (repeatable)")
    pr.add_argument("--event")
    pr.add_argument("--keep", type=Path, metavar="DIR", help="work in DIR (absent or empty) and keep it")
    pr.add_argument("--no-engines", action="store_true", help="plan the intake engines but do not run them")
    pr.add_argument("--engine-budget", type=float, default=_corpus.DEFAULT_ENGINE_BUDGET, metavar="S",
                    help="seconds of intake engine time per challenge")

    pim = sub.add_parser("import", help="copy a public challenge folder into the corpus, answers stripped")
    pim.add_argument("src", type=Path)
    pim.add_argument("--id", required=True, dest="cid")
    pim.add_argument("--category", required=True)
    pim.add_argument("--name")
    pim.add_argument("--description", default="")
    pim.add_argument("--key-file", help="the flag file, relative to SRC (default flag.txt)")
    pim.add_argument("--service", help="a ctf.livereplay spec, relative to SRC")
    pim.add_argument("--strip", action="append", default=[], metavar="GLOB", help="more answer globs")
    pim.add_argument("--engine", action="append", default=[], dest="engines", metavar="ID",
                     help="an engine the router should name (expect_engines)")
    pim.add_argument("--corpus", type=Path, help="the corpus root (default $CTF_REHEARSAL_CORPUS)")
    pim.add_argument("--index", type=Path, help="append the stanza to this index file")
    pr.add_argument("--json", action="store_true")


def _profile(args):
    return _event.load(args.event) if getattr(args, "event", None) else _event.current()


def _find(index, cid):
    for c in index:
        if c.id == cid:
            return c
    raise _corpus.CorpusError(f"unknown challenge id {cid!r} in the index")


def _cmd_index(args) -> int:
    index = _corpus.load_index()
    root = _paths.rehearsal_corpus_root()
    rows = []
    for c in index:
        present = bool(root) and c.challenge_dir(root).is_dir() if root else False
        rows.append({"id": c.id, "category": c.category, "name": c.name, "live": c.service is not None,
                     "expect_engines": list(c.expect_engines), "present": present})
    if args.json:
        print(json.dumps({"corpus_root": str(root) if root else None, "challenges": rows}, indent=1))
        return 0
    where = str(root) if root else "NOT SET (CTF_REHEARSAL_CORPUS)"
    print(f"corpus index ({len(rows)} entries); corpus root: {where}")
    for r in rows:
        mark = "present" if r["present"] else ("absent" if root else "?")
        live = f" live={'yes' if r['live'] else 'no'}"
        print(f"  [{mark:7}] {r['id']} <{r['category']}>{live}  engines={','.join(r['expect_engines']) or '-'}")
    return 0


def _cmd_stage(args) -> int:
    index = _corpus.load_index()
    ch = _find(index, args.id)
    root = _paths.require_rehearsal_corpus()
    members = _corpus.stage(ch, root, args.dest)
    print(f"staged {ch.id} blind into {args.dest} ({len(members)} file(s)); key and strip globs excluded")
    return 0


def _cmd_score(args) -> int:
    index = _corpus.load_index()
    ch = _find(index, args.id)
    root = _paths.require_rehearsal_corpus()
    prof = _profile(args)
    ff = _flagfmt.for_profile(prof)
    key = _corpus.read_key(ch, root)
    verdict = _corpus.score([args.flag], key, ff)
    print(f"{ch.id}: {verdict}")
    return 0 if verdict == "correct" else 1


def _cmd_serve(args) -> int:
    index = _corpus.load_index()
    ch = _find(index, args.id)
    root = _paths.require_rehearsal_corpus()
    if not ch.service:
        print(f"ctf corpus serve: {ch.id} declares no live service", file=sys.stderr)
        return 2
    spec = _corpus.load_service_spec(ch, root)
    with _replay.start(spec) as svc:
        print(f"{ch.id}: {svc.kind} replay at {svc.endpoint}")
        if args.probe:
            data = _replay.run_probe(svc, spec)
            sys.stdout.write(data.decode("utf-8", "replace"))
            if not data.endswith(b"\n"):
                sys.stdout.write("\n")
            return 0
        print("serving on loopback; Ctrl-C to stop")
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            return 0
    return 0


def _cmd_rehearse(args) -> int:
    prof = _profile(args)
    index = _corpus.load_index()
    root = _paths.require_rehearsal_corpus()
    if not args.engine_budget > 0:
        raise _corpus.CorpusError(f"--engine-budget must be > 0 seconds, got {args.engine_budget}")
    kw = dict(ids=args.ids, engines=not args.no_engines, engine_budget=args.engine_budget)
    if args.keep is not None:
        rep = _corpus.rehearse(prof, index, root, args.keep, **kw)
    else:
        with tempfile.TemporaryDirectory(prefix="ctf-corpus-") as td:
            rep = _corpus.rehearse(prof, index, root, Path(td) / "run", **kw)
    print(json.dumps(rep.to_dict(), indent=1) if args.json else rep.render())
    return 0 if rep.passed else 1


def _index_text(path: Path) -> str:
    """The current index text ('' if the file is absent). A non-empty index must already load."""
    p = Path(path)
    text = p.read_text(encoding="utf-8") if p.exists() else ""
    if text.strip():
        try:
            _corpus.parse_index(tomllib.loads(text), src=str(p))
        except tomllib.TOMLDecodeError as e:
            raise _corpus.CorpusError(f"{p}: {e}") from None
    return text


def _cmd_import(args) -> int:
    root = args.corpus if args.corpus is not None else _paths.require_rehearsal_corpus()
    old_text = None
    if args.index is not None:
        # check the index before anything is written: a duplicate id or a broken index must leave
        # both the corpus folder and the index file untouched
        old_text = _index_text(args.index)
        if old_text.strip():
            ids = {c.id for c in _corpus.parse_index(tomllib.loads(old_text), src=str(args.index))}
            if args.cid in ids:
                raise _corpus.CorpusError(f"{args.index}: challenge id {args.cid!r} is already indexed; "
                                          "nothing was imported")
    res = _corpus.import_challenge(args.src, root, args.cid, args.category, name=args.name,
                                   description=args.description, key_file=args.key_file,
                                   service=args.service, strip=tuple(args.strip),
                                   expect_engines=tuple(args.engines))
    print(f"imported {args.cid} into {res.dest}: {len(res.copied)} file(s) copied, "
          f"{len(res.stripped)} answer path(s) stripped, {len(res.links_skipped)} symlink(s) not followed")
    for s in res.stripped:
        print(f"  stripped {s}")
    for s in res.links_skipped:
        print(f"  symlink not followed {s}")
    if args.index is not None:
        new_text = old_text + "\n" + res.stanza
        # the index must still load with the stanza in it; checked before the file is written
        _corpus.parse_index(tomllib.loads(new_text), src=str(args.index))
        Path(args.index).write_text(new_text, encoding="utf-8")
        print(f"appended the stanza to {args.index}")
    else:
        print("\nindex stanza (no flag):\n" + res.stanza, end="")
    return 0


_DISPATCH = {"index": _cmd_index, "stage": _cmd_stage, "score": _cmd_score,
             "serve": _cmd_serve, "rehearse": _cmd_rehearse, "import": _cmd_import}


def run(args: argparse.Namespace) -> int:
    try:
        return _DISPATCH[args.corpus_cmd](args)
    except _event.EventError as e:
        print(f"ctf corpus: {e}", file=sys.stderr)
        return 2
    except (_corpus.CorpusError, _replay.ReplayError, OSError) as e:
        print(f"ctf corpus: {e}", file=sys.stderr)
        return 2
