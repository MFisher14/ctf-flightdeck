"""ctf formats list | identify | build | matrix — the ranked format catalog, its synthetic corpus and the
property coverage matrix of the metadata lane's readers (B-162).

    python -m ctf formats list                       the catalog, by rank
    python -m ctf formats identify FILE...           the formats each file could be, best first
                                                     (`sure` = the bytes have the structure; an extension
                                                     alone is never sure)
    python -m ctf formats fingerprint FILE...        measure a file identify cannot name and look it up
                                                     offline: the magic table, then the known-format DB
    python -m ctf formats known [--json]             the known-format DB (B-087): what each entry matches
                                                     on and the public reference it names
    python -m ctf formats build --out DIR [SAMPLE...] write corpus samples (all without names) into DIR
    python -m ctf formats matrix [--json]            compute the matrix; print it (markdown or JSON)
    python -m ctf formats matrix --write             write docs/coverage/FORMATS.md
    python -m ctf formats matrix --check             exit 1 when docs/coverage/FORMATS.md is stale

Exit codes: 0 ok; 1 matrix problems (a check the readers miss, a nearest-reader answer that is not unsure,
a misidentified sample, a reader that raises, a namespace with no reader) or a stale file under --check,
or an identify with no sure match; 2 unusable input (a bad catalog, an unknown sample, an existing file
under build, a missing lane pack, a file over identify's limit, a detector that failed).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HELP = "ranked format catalog, synthetic corpus and the metadata readers' property coverage matrix"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    sp.add_parser("list", help="the catalog by rank")
    idf = sp.add_parser("identify", help="the formats each file could be, best first")
    idf.add_argument("files", nargs="+", type=Path)
    fp = sp.add_parser("fingerprint", help="fingerprint a member identify cannot name, then look it up")
    fp.add_argument("files", nargs="+", type=Path)
    fp.add_argument("--online", action="store_true",
                    help="allow public code search on the short magic strings (event policy gated)")
    fp.add_argument("--event", help="event slug whose rules.public_fetch_allow gates --online")
    fp.add_argument("--json", action="store_true")
    kn = sp.add_parser("known", help="the known-format DB: signals and the public reference of each entry")
    kn.add_argument("--json", action="store_true")
    bd = sp.add_parser("build", help="write corpus samples into a folder")
    bd.add_argument("samples", nargs="*", help="sample ids (default: every sample)")
    bd.add_argument("--out", type=Path, required=True)
    mx = sp.add_parser("matrix", help="the property coverage matrix")
    g = mx.add_mutually_exclusive_group()
    g.add_argument("--json", action="store_true")
    g.add_argument("--write", action="store_true", help="write docs/coverage/FORMATS.md")
    g.add_argument("--check", action="store_true", help="exit 1 when docs/coverage/FORMATS.md is stale")
    p.add_argument("--catalog", type=Path, help="another catalog file (default ctf/formats/catalog.toml)")


def _list(cat) -> int:
    for f in cat:
        print(f"{f.rank:>2}. {f.id:6} {f.label}")
        print(f"      basis: {f.basis}")
        print(f"      extensions {' '.join(f.extensions)}; namespaces {', '.join(f.namespaces)}; samples {', '.join(f.samples)}")
    return 0


def _identify(cat, files) -> int:
    from .. import formats
    rc = 0
    for path in files:
        if not path.is_file():
            print(f"ctf formats identify: {path}: not a file", file=sys.stderr)
            return 2
        try:
            matches = formats.identify_path(path, cat)      # mapped, never read whole
        except (formats.FormatLimit, formats.DetectorError) as e:
            print(f"ctf formats identify: {path}: {e}", file=sys.stderr)
            return 2
        sure = [m for m in matches if m.sure]
        if not sure:
            rc = 1
        shown = "; ".join(f"{m.format} ({'sure' if m.sure else 'unsure'}: {m.why})" for m in matches) or "no catalog format"
        print(f"{path}: {shown}")
    return rc


def _fingerprint(cat, args) -> int:
    import json as _json
    import mmap
    import os
    from .. import event as _event
    from ..formats import fingerprint as fpmod

    client = None
    profile = None
    if args.online:
        from ..formats import codesearch
        client = codesearch.PublicCodeSearchClient(enabled=True)
        if args.event:
            try:
                profile = _event.load(args.event)
            except _event.EventError as e:
                print(f"ctf formats fingerprint: --event {args.event}: {e}", file=sys.stderr)
                return 2
        elif os.environ.get("CTF_EVENT"):
            # Opt-in is explicit: say which event policy will gate the search, not silently fall back.
            print(f"ctf formats fingerprint: --online without --event uses CTF_EVENT="
                  f"{os.environ['CTF_EVENT']!r} for rules.public_fetch_allow", file=sys.stderr)
        else:
            print("ctf formats fingerprint: --online needs an event policy to gate the public code "
                  "search: pass --event SLUG (or set CTF_EVENT) whose rules.public_fetch_allow lists "
                  "the host", file=sys.stderr)
            return 2
    from ..formats import known as knownmod
    try:
        magic_table = fpmod.load_magic()
        known_table = knownmod.load()
    except (fpmod.MagicError, knownmod.KnownError) as e:
        print(f"ctf formats fingerprint: {e}", file=sys.stderr)
        return 2
    results = []
    for path in args.files:
        if not path.is_file():
            print(f"ctf formats fingerprint: {path}: not a file", file=sys.stderr)
            return 2
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            if size == 0:
                res = fpmod.analyze(path.name, b"", catalog=cat, magic_table=magic_table,
                                    client=client, profile=profile, known=known_table)
            else:
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    res = fpmod.analyze(path.name, mapped, catalog=cat, magic_table=magic_table,
                                        client=client, profile=profile, known=known_table)
        results.append((path, res))

    if args.json:
        out = []
        for path, res in results:
            out.append({
                "path": str(path),
                "named": [{"format": m.format, "why": m.why} for m in res.named],
                "fingerprint": None if res.fp is None else {
                    "size": res.fp.size, "head_hex": res.fp.head_hex,
                    "magic_ascii": list(res.fp.magic_ascii), "entropy": res.fp.entropy,
                    "entropy_profile": list(res.fp.entropy_profile), "stride": res.fp.stride,
                    "stride_score": res.fp.stride_score, "header_fields": list(res.fp.header_fields),
                    "strings": list(res.fp.strings)},
                "candidates": [{"source": c.source, "label": c.label, "tool": c.tool, "why": c.why,
                                "score": c.score, "ref": c.ref} for c in res.candidates],
                "online_used": res.online_used, "online_error": res.online_error,
                "sent_magics": list(res.sent_magics),
            })
        print(_json.dumps(out, indent=2))
        return 0

    for path, res in results:
        if res.named:
            shown = "; ".join(f"{m.format} ({m.why})" for m in res.named)
            print(f"{path}: named by identify: {shown}")
            continue
        fp = res.fp
        print(f"{path}: fingerprint  magic {fp.head_hex[:16]}.. size {fp.size} "
              f"entropy {fp.entropy:.2f}b/byte"
              + (f" stride {fp.stride} ({fp.stride_score:.0%})" if fp.stride else " no stride"))
        if fp.magic_ascii:
            print(f"      magic strings: {', '.join(fp.magic_ascii[:6])}")
        if res.candidates:
            for c in res.candidates:
                tool = f" (tool: {c.tool})" if c.tool else ""
                ref = f" [{c.ref}]" if c.ref else ""
                print(f"      likely {c.label}{tool} -- {c.why}{ref}  <{c.source}, score {c.score}>")
        else:
            print("      no offline or online lead (unsure; for a human read)")
        if res.online_error:
            print(f"      code search: {res.online_error}", file=sys.stderr)
    return 0


def _known(args) -> int:
    import json as _json
    from ..formats import known as knownmod
    try:
        table = knownmod.load()
    except knownmod.KnownError as e:
        print(f"ctf formats known: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(_json.dumps([{
            "id": k.id, "label": k.label, "family": k.family, "reference": k.reference, "basis": k.basis,
            "note": k.note, "require": list(k.require), "support": list(k.support),
            "min_support": k.min_support, "names": list(k.names), "ascii": list(k.ascii),
            "magic": [{"at": m.at, "hex": m.sig.hex()} for m in k.magic],
            "geometry": None if k.geometry is None else {
                "header": k.geometry.header, "record": k.geometry.record, "trailer": k.geometry.trailer,
                "min_records": k.geometry.min_records},
            "entropy_min": k.entropy_min} for k in table], indent=2))
        return 0
    for k in table:
        print(f"{k.id}: {k.label}")
        print(f"      reference: {k.reference}")
        need = ", ".join(k.require)
        extra = (f"; plus {k.min_support} of {', '.join(k.support)}" if k.min_support
                 else f"; supported by {', '.join(k.support)}" if k.support else "")
        print(f"      matches on: {need}{extra}")
        print(f"      basis: {k.basis}")
        if k.note:
            print(f"      next: {k.note}")
    return 0


def _build(args) -> int:
    from ..formats import corpus
    ids = args.samples or sorted(corpus.BUILDERS)
    samples = [corpus.build(i) for i in ids]
    args.out.mkdir(parents=True, exist_ok=True)
    for s in samples:
        dest = args.out / s.id / s.name
        if dest.exists():
            print(f"ctf formats build: {dest} exists; not overwritten", file=sys.stderr)
            return 2
    for s in samples:
        dest = args.out / s.id / s.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(s.data)
        print(f"{dest}  {len(s.data)} bytes, {len(s.checks)} checks")
    return 0


def _matrix(args, cat) -> int:
    from ..formats import matrix
    m = matrix.compute(cat)
    text = matrix.render_markdown(m)
    problems = m.problems()
    if args.check:
        path = matrix.doc_path()
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current != text:
            print(f"ctf formats matrix: {path} is stale: run python -m ctf formats matrix --write", file=sys.stderr)
            return 1
        print(f"{path}: current")
    elif args.write:
        path = matrix.doc_path()
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path}")
    elif args.json:
        print(m.to_json())
    else:
        sys.stdout.write(text)
    for p in problems:
        print(f"PROBLEM {p}", file=sys.stderr)
    for n in m.not_run():
        print(f"NOT RUN {n}", file=sys.stderr)
    return 1 if problems else 0


def run(args: argparse.Namespace) -> int:
    from .. import formats
    from ..packs import PackError
    try:
        cat = formats.load(args.catalog)
        if args.action == "list":
            return _list(cat)
        if args.action == "identify":
            return _identify(cat, args.files)
        if args.action == "fingerprint":
            return _fingerprint(cat, args)
        if args.action == "known":
            return _known(args)
        if args.action == "build":
            return _build(args)
        return _matrix(args, cat)
    except (formats.CatalogError, formats.corpus.CorpusError, PackError) as e:
        print(f"ctf formats {args.action}: {e}", file=sys.stderr)
        return 2
