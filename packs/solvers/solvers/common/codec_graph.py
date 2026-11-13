"""Engine: the shared recursive codec graph over a challenge's files (B-163).

    python -m ctf run common.codec_graph <challenge_dir> [--opt crib=TEXT] [--opt slug=1] [--opt pack=warmups]
        [--opt budget=SECONDS] [--event SLUG]

Every small handout file (and every numbered-record file, `NN<TAB>payload` lines) goes through
`ctf.codec`: the bounded recursive search over strict, symbol, loose and keyed codecs with an oracle
that validates the final object. The oracle is the event flag format, or, with `crib=`, the crib
itself, or with `slug=1` a slug answer (after the crib when one is given). Numbered records are
assembled at the true cut (`ctf.codec.records`), and an ambiguous file is settled by the chain its own
vouched records agree on.

Result: `solved` for one distinct flag in the event format reached by a confirmed chain (a
representation step, or a strong oracle); `candidate` for several, for loose-only chains, and for
non-flag answers (a slug or crib is an answer, not a flag); `none` when nothing was reached;
`blocked` when the event has no flag format and no other oracle was asked for, or a requested codec
pack is missing. Files are untrusted data: read and decoded, never executed. It never submits.
"""
from __future__ import annotations

import time
from pathlib import Path

ENGINE = "common.codec_graph"
MAX_FILE = 256 * 1024
MAX_FILES = 32
SKIP_DIRS = {"recon", ".sweep", "unpacked"}
DEFAULT_BUDGET = 20.0


def _files(challenge_dir: Path) -> list[Path]:
    base = challenge_dir / "files" if (challenge_dir / "files").is_dir() else challenge_dir
    out = []
    for p in sorted(base.rglob("*")):
        rel = p.relative_to(base).parts
        if any(part in SKIP_DIRS or part.startswith(".") for part in rel):
            continue
        if p.is_file() and not p.is_symlink() and 0 < p.stat().st_size <= MAX_FILE:
            out.append(p)
    return out[:MAX_FILES]


def _truthy(v) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def solve(challenge_dir, profile, **opts):
    from ctf import flagfmt
    from ctf import packs as _packs
    from ctf.codec import CribOracle, FlagOracle, Graph, SlugOracle, core
    from ctf.codec import pack as _pack
    from ctf.codec import records as R
    from ctf.result import Cost, Evidence, SolverResult

    t0 = time.monotonic()
    challenge_dir = Path(challenge_dir)
    crib = opts.get("crib") or None
    slug = _truthy(opts.get("slug", ""))
    budget = float(opts.get("budget", DEFAULT_BUDGET))
    deadline = t0 + budget

    if slug:
        oracle = SlugOracle(crib=crib)
    elif crib:
        oracle = CribOracle(crib)
    else:
        if not flagfmt.for_profile(profile).known:
            return SolverResult("blocked", engine=ENGINE,
                                notes="the event profile has no flag format; pass --opt crib=TEXT or --opt slug=1")
        oracle = FlagOracle(profile)
    codecs = core()
    for name in [n for n in str(opts.get("pack", "")).split(",") if n.strip()]:
        try:
            codecs = codecs + _pack.load(name.strip())
        except _packs.PackError as e:
            return SolverResult("blocked", engine=ENGINE, notes=f"codec pack not loaded: {e}")
    graph = Graph(codecs)

    found: dict = {}            # answer -> [(file, chain, confirmed)]
    notes = []
    files = _files(challenge_dir)
    for f in files:
        if time.monotonic() >= deadline:
            notes.append(f"budget of {budget:g}s spent before {f.name}")
            break
        data = f.read_bytes()
        try:
            recs = R.parse(data)
        except R.RecordsError:
            recs = None
        if recs is not None:
            res = R.consensus([recs], oracle, crib=(crib or "").encode(), group="all", graph=graph,
                              deadline=deadline)[0]
            if res.answer is not None:
                chains = "; ".join("+".join(c) or "plain" for _, c in res.assemblies[0].picks)
                found.setdefault(res.answer, []).append((f.name, f"records: {chains}", True))
            else:
                notes.append(f"{f.name}: {len(recs)} records, {res.reason}")
                for a in res.assemblies:
                    for ans in a.answers:
                        found.setdefault(ans, []).append((f.name, "records (ambiguous)", False))
            continue
        res = graph.search(data, oracle, deadline=deadline)
        if res.truncated:
            notes.append(f"{f.name}: search cut by its {res.truncated} bound")
        for h in res.hits:
            found.setdefault(h.answer, []).append((f.name, h.how, h.confirmed))

    evidence = [Evidence("decode", f"{src} via {how}" + ("" if ok else " (unconfirmed)"), path=src)
                for ans, rows in found.items() for src, how, ok in rows]
    cost = Cost(seconds=round(time.monotonic() - t0, 3))
    if not found:
        return SolverResult("none", engine=ENGINE, cost=cost,
                            notes="; ".join([f"{len(files)} file(s), nothing reached the oracle"] + notes))
    answers = list(found)
    is_flag = isinstance(oracle, FlagOracle)
    confirmed = [a for a in answers if any(ok for _, _, ok in found[a])]
    if is_flag and len(answers) == 1 and confirmed:
        return SolverResult("solved", flags=answers, evidence=evidence, engine=ENGINE, cost=cost,
                            notes="; ".join(notes))
    why = ("several distinct answers" if len(answers) > 1 else
           "an unconfirmed (loose-only) chain" if not confirmed else
           f"a {oracle.name} answer, not an event flag")
    return SolverResult("candidate", flags=answers, evidence=evidence, engine=ENGINE, cost=cost,
                        notes="; ".join([why] + notes))
