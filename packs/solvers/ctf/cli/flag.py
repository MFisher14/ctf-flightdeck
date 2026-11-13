"""`ctf flag`: the flag plausibility check and the one ranked variant set (B-154, ctf/flagcheck.py).

    python -m ctf flag check <value> [--source S] [--other V]... [--passed CHECK]...
                                     [--case-lossy] [--case-ref FILE] [--nonstandard] [--json]
                                                    findings before a send: decoy, lost case, format
    python -m ctf flag variants <value> [same options] [--max N] [--id ID] [--out FILE] [--json]
                                                    the ranked variant set; --out writes the variants
                                                    past the guess budget for `ctf policy sweep`
    python -m ctf flag try <id> <value> --note N [same options] [--max N] [--confirm]
                                                    send the set in rank order through the submit gate:
                                                    the value, then variants within the guess budget

--source names how the value was found (`ctf flag check --help` lists the names): a static shortcut
(strings, grep, metadata, intake...) draws a decoy warning, a case-losing cipher (enigma, morse...)
draws case guidance. --case-ref is a case-keeping text (the challenge text, a source file) whose
spelling of the value's words restores their case. The event is CTF_EVENT (else the only profile);
check and variants take --event SLUG. Nothing here reads challenge files except --case-ref, which
is only searched for the value's words.

Exit codes. check: 0 ok, 1 warnings, 4 blocked (never a flag, or outside the format). variants: 0,
4 blocked. try: 0 accepted, 1 nothing accepted (exhausted, capped by the guess budget, stopped), 2
error, 4 refused before any send (manual event, a blocked value).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import flagcheck as fc
from ..platform import NotAllowed, NotSupported, PlatformError, get_adapter
from ..platform import legacy as _legacy
from ..platform.queue import QueueError

HELP = "flag plausibility check and the ranked flag-variant set: check, variants, try (B-154)"
REFUSED_EXIT = 4
WARN_EXIT = 1


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("value", help="the candidate flag (quote it)")
    p.add_argument("--source", choices=sorted(fc.SOURCES), help="how the value was found")
    p.add_argument("--other", action="append", default=[], metavar="V",
                   help="another value found in the same material (repeatable)")
    p.add_argument("--passed", action="append", default=[], metavar="CHECK",
                   help="a local check the value passed, e.g. pkcs7, hmac, json (repeatable)")
    p.add_argument("--case-lossy", action="store_true", help="the value went through a case-losing step")
    p.add_argument("--case-ref", type=Path, metavar="FILE", help="a case-keeping text to restore case from")
    p.add_argument("--nonstandard", action="store_true",
                   help="a brief-defined answer: the event flag format does not apply")


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    c = sub.add_parser("check", help="plausibility findings for one value")
    _common(c)
    c.add_argument("--event", metavar="SLUG", help="default: the current event (CTF_EVENT)")
    c.add_argument("--json", action="store_true")
    v = sub.add_parser("variants", help="the one ranked variant set of a value")
    _common(v)
    v.add_argument("--event", metavar="SLUG", help="default: the current event (CTF_EVENT)")
    v.add_argument("--max", type=int, default=fc.DEFAULT_MAX_VARIANTS, help="variants after the value")
    v.add_argument("--id", metavar="ID", help="a challenge id: the budget line counts its used guesses")
    v.add_argument("--out", type=Path, metavar="FILE",
                   help="write the variants past the guess budget, one per line (for `ctf policy sweep`)")
    v.add_argument("--json", action="store_true")
    t = sub.add_parser("try", help="send the ranked set in order within the guess budget")
    t.add_argument("challenge_id")
    _common(t)
    t.add_argument("--note", required=True, help="how the value was derived (each send's provenance)")
    t.add_argument("--max", type=int, default=fc.DEFAULT_MAX_VARIANTS, help="variants after the value")
    t.add_argument("--confirm", action="store_true",
                   help="the player confirmed (confirm-mode events; never past the stop on your own)")


def _err(action: str, msg: str, code: int = 2) -> int:
    word = "refused" if code == REFUSED_EXIT else "error"
    print(f"ctf flag {action}: {word}: {msg}", file=sys.stderr)
    return code


def _kw(args) -> dict:
    ref = None
    if args.case_ref is not None:
        try:
            with open(args.case_ref, "rb") as fh:
                ref = fh.read(fc.REF_LIMIT).decode("utf-8", errors="replace")
        except OSError as e:
            raise fc.FlagCheckError(f"cannot read the case reference {args.case_ref}: {e}") from None
    return dict(source=args.source, others=args.other, local_checks=args.passed,
                case_lossy=args.case_lossy, case_ref=ref, allow_nonstandard=args.nonstandard)


def _print_check(chk: fc.Check) -> None:
    print(f"verdict: {chk.verdict}")
    if chk.primary != chk.value:
        print(f"primary: {chk.primary}")
    for f in chk.findings:
        print(f"  {f.level:<5} {f.code}: {f.message}")
    print("only the platform's accepted answer marks a challenge solved")


def _check(args, profile) -> int:
    chk = fc.check(args.value, profile, **_kw(args))
    if args.json:
        print(json.dumps(chk.to_dict(), sort_keys=True, ensure_ascii=False))
    else:
        _print_check(chk)
    return {"ok": 0, "warn": WARN_EXIT, "block": REFUSED_EXIT}[chk.verdict]


def _variants(args, profile) -> int:
    vs = fc.variants(args.value, profile, max_variants=args.max, **_kw(args))
    left = (fc.guesses_left(profile, args.id) if args.id is not None else profile.rules.guess_budget)
    _send, held = vs.plan(left, allow_nonstandard=args.nonstandard)
    if args.out is not None:
        try:
            args.out.write_text("".join(f"{v.value}\n" for v in held), encoding="utf-8")
        except OSError as e:
            return _err("variants", f"cannot write {args.out}: {e}")
    if args.json:
        doc = vs.to_dict()
        doc["guesses_left"] = left
        doc["held"] = [v.value for v in held]
        print(json.dumps(doc, sort_keys=True, ensure_ascii=False))
        return REFUSED_EXIT if vs.check.verdict == "block" else 0
    _print_check(vs.check)
    print(f"ranked set ({len(vs.ranked) - 1} variant(s) after the value; submit in this order, stop at "
          "the first accepted):")
    for v in vs.ranked:
        mark = "" if v.in_format or args.nonstandard else "  [not in the flag format]"
        what = ", ".join(v.changes) if v.changes else "the value as checked"
        print(f"  {v.rank:>2}. {v.value}   ({what}; score {v.score:.3f}){mark}")
    who = f"challenge {args.id}" if args.id is not None else "a challenge"
    print(f"guess budget: {profile.rules.guess_budget} per challenge, {left} left on {who}: the value "
          f"and the first {min(left, len(vs.sendable(args.nonstandard)))} variant(s) may be sent; "
          f"{len(held)} held for the player")
    if held:
        tail = f" (written to {args.out})" if args.out is not None else " (--out FILE writes them)"
        print(f"held variants need the player: a sweep authorization (`ctf policy authorize-sweep`) "
              f"runs them with `ctf policy sweep --candidates FILE`{tail}")
    return REFUSED_EXIT if vs.check.verdict == "block" else 0


def _try(args, profile) -> int:
    call = "ctf flag try"
    err = _legacy.refusal(profile, call, submit=True)       # R-02: a manual event refuses first
    if isinstance(err, NotAllowed):
        return _err("try", f"{err}; print the ranked set with `ctf flag variants` and hand it to the "
                    "player instead", REFUSED_EXIT)
    try:
        gate = get_adapter(profile)
        rep = fc.try_variants(gate, args.challenge_id, args.value, note=args.note,
                              confirmed=args.confirm, max_variants=args.max, **_kw(args))
    except NotSupported:
        raise
    except (PlatformError, QueueError) as e:
        notes = "".join(f"; {n}" for n in getattr(e, "__notes__", ()))
        return _err("try", f"{e}{notes}")
    for f in rep.check.findings if rep.check else ():
        if f.level != "info":
            print(f"{call}: plausibility {f.level} ({f.code}): {f.message}", file=sys.stderr)
    if rep.outcome == "refused":
        return _err("try", rep.reason, REFUSED_EXIT)
    shown = (lambda s: s) if profile.rules.flag_sharing == "allowed" else (lambda s: "<flag>")
    for rank, value, status in rep.results:
        print(f"  {rank:>2}. {shown(value)} -> {status}")
    for rank, value, why in rep.skipped:
        print(f"  {rank:>2}. {shown(value)} skipped: {why}")
    print(f"{rep.outcome}: {rep.sent} sent, {rep.guesses} guess(es) used; {rep.reason}")
    if rep.held:
        print(f"held for the player: {len(rep.held)} variant(s) (`ctf flag variants ... --id "
              f"{args.challenge_id} --out FILE` writes them)")
    if rep.outcome == "stopped" and not rep.sent:
        return REFUSED_EXIT
    return 0 if rep.accepted is not None else 1


def run(args: argparse.Namespace) -> int:
    act = args.action
    try:
        slug = getattr(args, "event", None)
        profile = _event.load(slug) if slug else _event.current()
    except _event.EventError as e:
        return _err(act, str(e))
    try:
        if act == "check":
            return _check(args, profile)
        if act == "variants":
            return _variants(args, profile)
        return _try(args, profile)
    except fc.FlagCheckError as e:
        return _err(act, str(e), REFUSED_EXIT if "no variants" in str(e) else 2)
    except ValueError as e:       # a corrupt ledger line
        return _err(act, str(e))
