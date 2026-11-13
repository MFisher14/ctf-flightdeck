"""`ctf marker`: the constructed-marker fallback (B-119, solvers/common/marker_convention.py).

    python -m ctf marker fields <challenge_dir> [--json]
                                    named values the handout states, with the evidence that holds each
    python -m ctf marker candidates <challenge_dir> [--field NAME[:KIND]=VALUE]... [--family F]
                                    [--witness HEX[@WHERE]]... [--digest FORM]... [--budget N] [--top N]
                                    [--max-fields N] [--min-fields N] [--max-deviations N] [--keep-order]
                                    [--all-fields] [--nonstandard] [--id ID] [--out FILE] [--save FILE]
                                    [--json] [--event SLUG]
                                    the ranked candidate list and what the guess budget lets out
    python -m ctf marker learn --verdict accepted|rejected (--from REPORT --flag VALUE |
                                    --family F --convention NAME [--kind ROLE=KIND]...) [--id ID]
                                    record the judge's verdict on a convention in the knowledge base
    python -m ctf marker kb [--family F] [--json]
                                    what the knowledge base holds

A constructed marker is a digest of several evidence values joined in an order and in spellings the
author chose; the files do not say which. `candidates` enumerates field subset x order x rendering
x join, hashes each text, checks it against a witness (a hex tag the files carry for the same
digest, found or given with --witness) and ranks: witness hits, then conventions the judge accepted
for the family, then the least unusual compositions. A hit is strong only while few chance matches
are expected over the texts hashed and the tags compared (at most 32 are taken from the files; the
rest are named, not compared). When the brief or --digest states a cut other than the one a family's
convention was accepted with, its fields, order and renderings are listed under the stated cut as
`kb-recut`: a guess, not a backed value. It prints candidates and a plan; it sends nothing. The plan is the event's guess budget applied to the ranked list: what may go out now through
`ctf submit` (the first value as reasoned only when a strong witness or an accepted convention backs
it, everything else with --guess), and what is held for the player's sweep authorization
(`ctf policy authorize-sweep`, then `ctf policy sweep --candidates FILE`; --out writes that file).

Kinds: text, tag (a short ASCII tag, also spelled as its hex bytes), hexid, integer, timestamp,
decimal. WHERE: prefix, suffix, edge (either end, the default), any. FORM: sha256[:8], sha256[-8:],
sha256, md5[:8]..., with .upper for upper-case hex. `learn` writes the runtime label ledger; `ctf
seed-fold marker` folds it into the tracked seed, so the next event starts from it.

Exit codes. fields: 0. candidates: 0 a list was printed, 1 nothing to offer (no field, or every
candidate left out), 2 error. learn: 0 recorded, 2 error (no judge ledger, an unknown flag or
convention). kb: 0, 2 when the knowledge base cannot be read.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import packs as _packs
from .. import paths as _paths

HELP = "constructed-marker fallback: fields, candidates within the guess budget, learn, kb (B-119)"


def engine():
    """solvers/common/marker_convention.py of this checkout, loaded once under its flat name (the name
    the lanes and the suite import it by)."""
    return _packs.load_module("marker_convention",
                              _paths.repo_root() / "solvers" / "common" / "marker_convention.py",
                              pack="marker_convention")


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    f = sub.add_parser("fields", help="named values the handout states, with their evidence")
    f.add_argument("challenge_dir", type=Path)
    f.add_argument("--json", action="store_true")
    c = sub.add_parser("candidates", help="the ranked candidate list and the guess-budget plan")
    c.add_argument("challenge_dir", type=Path)
    c.add_argument("--field", action="append", default=[], metavar="NAME[:KIND]=VALUE",
                   help="a value the marker is built from, in your best order (repeatable); with none, "
                        "the corroborated values of the handout are used")
    c.add_argument("--family", help="the convention family (default: the challenge's category)")
    c.add_argument("--witness", action="append", default=[], metavar="HEX[@WHERE]",
                   help="a hex tag the evidence carries for the digest (repeatable)")
    c.add_argument("--digest", action="append", default=[], metavar="FORM",
                   help="how the marker is cut from the digest (default: what the brief states, else "
                        "sha256[:8] then sha256)")
    c.add_argument("--budget", type=int, help="texts hashed at most")
    c.add_argument("--top", type=int, help="candidates listed at most")
    c.add_argument("--max-fields", type=int, help="extracted fields used at most")
    c.add_argument("--min-fields", type=int, help="smallest subset of the fields tried (default 2)")
    c.add_argument("--max-deviations", type=int, help="fields not in their default spelling, at most")
    c.add_argument("--keep-order", action="store_true", help="the field order is known: try no other")
    c.add_argument("--all-fields", action="store_true",
                   help="use extracted values held by one source too")
    c.add_argument("--nonstandard", action="store_true",
                   help="the brief asks for the bare marker: no flag wrapper")
    c.add_argument("--id", metavar="ID", help="the challenge id: the plan counts its used guesses")
    c.add_argument("--out", type=Path, metavar="FILE",
                   help="write the held candidates, one per line (for `ctf policy sweep --candidates`)")
    c.add_argument("--save", type=Path, metavar="FILE", help="write the report as JSON (for `learn --from`)")
    c.add_argument("--json", action="store_true")
    c.add_argument("--event", metavar="SLUG", help="default: the current event (CTF_EVENT)")
    le = sub.add_parser("learn", help="record the judge's verdict on a convention")
    le.add_argument("--verdict", required=True, choices=("accepted", "rejected"))
    le.add_argument("--from", dest="report", type=Path, metavar="REPORT",
                    help="a report written by `candidates --save`")
    le.add_argument("--flag", help="with --from: the judged value")
    le.add_argument("--family")
    le.add_argument("--convention", metavar="NAME", help="<digest>;<join>;<role>=<rendering>,...")
    le.add_argument("--kind", action="append", default=[], metavar="ROLE=KIND",
                    help="the kind of a role's value (repeatable): teaches its rendering to every family")
    le.add_argument("--id", metavar="ID", help="the challenge id, kept with the verdict")
    k = sub.add_parser("kb", help="what the convention knowledge base holds")
    k.add_argument("--family")
    k.add_argument("--json", action="store_true")


def _err(action: str, msg: str, code: int = 2) -> int:
    print(f"ctf marker {action}: error: {msg}", file=sys.stderr)
    return code


def _fields(args, mc) -> int:
    if not args.challenge_dir.is_dir():
        return _err("fields", f"challenge folder not found: {args.challenge_dir}")
    docs, notes = mc.load_handout(args.challenge_dir)
    brief, _category, more = mc.read_brief(args.challenge_dir)
    fields, more2 = mc.extract_fields(docs, brief)
    witnesses, more3 = mc.find_witnesses(docs)
    notes = notes + more + more2 + more3
    if args.json:
        print(json.dumps({"fields": [f.to_dict() for f in fields],
                          "witnesses": [w.to_dict() for w in witnesses], "notes": notes},
                         sort_keys=True, ensure_ascii=False))
        return 0
    held = [f for f in fields if len(f.sources) >= 2]
    print(f"{len(fields)} named value(s), {len(held)} held by two or more sources:")
    for f in fields:
        mark = "*" if len(f.sources) >= 2 else " "
        print(f" {mark} {f.name}:{f.kind}={f.stored}   ({', '.join(f.sources)})")
    for w in witnesses:
        print(f"witness {w.token} ({w.source}): checked against either end of each digest")
    for n in notes:
        print(f"note: {n}")
    print("* is used by `ctf marker candidates` when no --field is given. A capture or a binary is not "
          "decoded here: pass what its engine read as --field NAME[:KIND]=VALUE.")
    return 0


def _candidates(args, mc, profile) -> int:
    from .. import flagcheck as fc
    opts = {"fields": args.field, "family": args.family, "witness": args.witness, "digest": args.digest,
            "budget": args.budget, "top": args.top, "max_fields": args.max_fields,
            "min_fields": args.min_fields, "max_deviations": args.max_deviations,
            "permute": not args.keep_order, "all_fields": args.all_fields, "nonstandard": args.nonstandard}
    report, unused, notes = mc.run(args.challenge_dir, profile, **opts)
    if report is None:
        for n in notes:
            print(f"note: {n}", file=sys.stderr)
        seen = ", ".join(f"{f.name}={f.stored}" for f in unused[:8])
        print("ctf marker candidates: no named value is held by two evidence sources"
              + (f" (seen once: {seen})" if seen else "")
              + "; name the values with --field NAME[:KIND]=VALUE, or pass --all-fields", file=sys.stderr)
        return 1
    left = (fc.guesses_left(profile, args.id) if args.id is not None else profile.rules.guess_budget)
    plan = mc.send_plan(report, profile, left, allow_nonstandard=args.nonstandard)
    doc = report.to_dict()
    doc["plan"] = plan.to_dict()
    doc["kinds"] = report.kinds()
    for path, text in ((args.save, json.dumps(doc, sort_keys=True, ensure_ascii=False, indent=1) + "\n"),
                       (args.out, "".join(f"{v}\n" for v in plan.held))):
        if path is not None:
            try:
                path.write_text(text, encoding="utf-8")
            except OSError as e:
                return _err("candidates", f"cannot write {path}: {e}")
    if args.json:
        print(json.dumps(doc, sort_keys=True, ensure_ascii=False))
        return 0 if report.candidates else 1
    print(f"family {report.family}; digest {', '.join(report.digests)}; fields: "
          + ", ".join(f"{f.name}:{f.kind}" for f in report.fields))
    print(f"hashed {report.enumerated} of {report.space} compositions; {len(report.witnesses)} "
          f"witness(es), {report.witness_hits} hit(s)")
    for n in report.notes:
        print(f"note: {n}")
    if not report.candidates:
        print("no candidate is left")
        return 1
    print(f"{len(report.candidates)} candidate(s), best first (candidates only: nothing here is proven):")
    for c in report.candidates:
        print(f"  {c.rank:>2}. {c.flag}   [{c.basis}] {c.convention}")
        if c.detail:
            print(f"      {c.detail}")
    who = f"challenge {args.id}" if args.id is not None else "a challenge"
    cid = args.id if args.id is not None else "<id>"
    print(f"plan: guess budget {profile.rules.guess_budget} per challenge, {left} left on {who}")
    if not report.supported:
        print("  the first candidate is a guess: no strong witness and no accepted convention backs it")
    bare = " --nonstandard" if args.nonstandard else ""      # a bare marker is out of the flag format:
    for i, value in enumerate(plan.send):                    # the gate refuses it without the switch
        how = "--source derived" if plan.reasoned and i == 0 else "--guess"
        print(f"  send: ctf submit {cid} '{value}' {how}{bare} --note 'ctf marker candidates, rank {i + 1}'")
    if plan.held:
        tail = f" (written to {args.out})" if args.out is not None else " (--out FILE writes them)"
        print(f"  held for the player: {len(plan.held)} candidate(s){tail}: `ctf policy authorize-sweep "
              f"{cid} --count N --reason ...`, then `ctf policy sweep {cid} --auth A --candidates FILE "
              "--note ...`")
    print("  send nothing else by hand; record each verdict: ctf marker learn --from REPORT --flag "
          "VALUE --verdict accepted|rejected (--save REPORT writes the report)")
    return 0


def _learn(args, mc) -> int:
    kinds: dict[str, str] = {}
    if args.report is not None:
        if not args.flag or args.convention or args.family:
            return _err("learn", "--from takes --flag VALUE (and no --family or --convention)")
        try:
            doc = json.loads(args.report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            return _err("learn", f"cannot read the report {args.report}: {e}")
        hit = next((c for c in doc.get("candidates", []) if args.flag in (c.get("flag"), c.get("marker"))),
                   None)
        if hit is None:
            return _err("learn", f"{args.flag!r} is not a candidate of {args.report}: only a value this "
                        "tool built names a convention")
        family, convention = doc.get("family"), hit["convention"]
        kinds = dict(doc.get("kinds") or {})
    else:
        if not args.family or not args.convention or args.flag:
            return _err("learn", "give --from REPORT --flag VALUE, or --family F --convention NAME")
        family, convention = args.family, args.convention
    for item in args.kind:
        r, sep, kind = item.partition("=")
        if not sep:
            return _err("learn", f"--kind {item!r}: write ROLE=KIND")
        kinds[mc.role(r)] = kind.strip().lower()
    rows = mc.learn(family, convention, args.verdict, kinds=kinds, challenge_id=args.id)
    for key, name in rows:
        print(f"{args.verdict}: {key} -> {name}")
    print(f"recorded {len(rows)} row(s) in the event's label ledger; fold them into the tracked seed with "
          "`python -m ctf seed-fold marker` and commit the seed")
    return 0


def _kb(args, mc) -> int:
    kb = mc.KB()
    if not kb.available:
        return _err("kb", kb.reason)
    families = [mc.family_name(args.family)] if args.family else kb.families()
    doc = {"families": {fam: {"accepted": kb.accepted(fam), "rejected": sorted(kb.rejected(fam))}
                        for fam in families},
           "joins": kb.joins(), "digests": kb.digests(),
           "renderings": {kind: kb.renders(kind) for kind in mc.KINDS if kb.renders(kind)}}
    if args.json:
        print(json.dumps(doc, sort_keys=True, ensure_ascii=False))
        return 0
    if not families:
        print("the knowledge base holds no convention yet")
    for fam in families:
        got = doc["families"][fam]
        print(f"family {fam}: {len(got['accepted'])} accepted, {len(got['rejected'])} rejected")
        for name in got["accepted"]:
            print(f"  accepted  {name}")
            print(f"            fields to name: {', '.join(mc.Convention.parse(name).roles)}")
        for name in got["rejected"]:
            print(f"  rejected  {name}")
    print(f"tried first in every family: joins {', '.join(doc['joins']) or '-'}; digests "
          f"{', '.join(doc['digests']) or '-'}")
    for kind, names in doc["renderings"].items():
        print(f"  {kind} values: {', '.join(names)} before the stored spelling")
    return 0


def run(args: argparse.Namespace) -> int:
    act = args.action
    try:
        mc = engine()
    except (_packs.PackMissing, _packs.PackLoadError) as e:
        return _err(act, str(e))
    try:
        if act == "fields":
            return _fields(args, mc)
        if act == "learn":
            return _learn(args, mc)
        if act == "kb":
            return _kb(args, mc)
        slug = getattr(args, "event", None)
        profile = _event.load(slug) if slug else _event.current()
        return _candidates(args, mc, profile)
    except _event.EventError as e:
        return _err(act, str(e))
    except ValueError as e:           # MarkerError, FlagCheckError, a corrupt ledger line
        return _err(act, str(e))
