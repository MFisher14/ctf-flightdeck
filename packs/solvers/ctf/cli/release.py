"""ctf release: arm and release-morning safety (B-197). (`ctf arm` is B-014's Layer-1 opener gate.)

    python -m ctf release SLUG                 write a dated armed tag on HEAD (no git tag -f)
    python -m ctf release SLUG --ref REF       ... on another commit
    python -m ctf release arm SLUG             the same as `ctf release SLUG`
    python -m ctf release status SLUG          latest armed tag, lag vs HEAD, freeze state
    python -m ctf release check SLUG           diff armed vs the release ref; exit 1 while it lags
    python -m ctf release green SLUG           mark HEAD a green commit (a rollback target)
    python -m ctf release freeze SLUG          start a hard code freeze (arming past it is refused)
    python -m ctf release thaw SLUG            lift the freeze
    python -m ctf release rollback SLUG        print the last green commit to roll back to
    python -m ctf release unwired              list modules nothing but tests imports (built-but-unwired)
    python -m ctf release unwired --include-tests   ... counting test files as callers too

Exit 0 ok; 1 the release ref lags the armed tag (check) or the action was refused (frozen, nothing to
thaw or roll back, the fence regression failed); 2 an error (a ref that is not a commit, an unknown
action, no slug, a missing tool).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import arm as _arm
from ..promote import PromoteError

HELP = "release-morning safety: dated armed tags, lag check, code freeze, rollback, unwired report"

ACTIONS = ("arm", "status", "check", "green", "freeze", "thaw", "rollback", "unwired")


def add_arguments(p: argparse.ArgumentParser) -> None:
    # No argparse `choices` on the action: `ctf release SLUG` puts the slug here, and run() reads a
    # first word that is not an action as the slug of an `arm`.
    p.add_argument("action", nargs="?", default="arm", metavar="ACTION|SLUG",
                   help=f"one of {', '.join(ACTIONS)} (default arm); a slug alone means arm")
    p.add_argument("slug", nargs="?", help="event slug (not needed for 'unwired')")
    p.add_argument("--ref", default="HEAD", help="commit to act on (default HEAD)")
    p.add_argument("--head", default="HEAD", help="release ref for status/check (default HEAD)")
    p.add_argument("--master", type=Path, help="the master checkout (default: this checkout)")
    p.add_argument("--allow-past-freeze", action="store_true",
                   help="arm even while frozen (ships code past the freeze)")
    p.add_argument("--package", default="ctf", help="package to scan for 'unwired' (default ctf)")
    p.add_argument("--include-tests", action="store_true",
                   help="'unwired': count test files (tests/, conftest.py, test_*.py) as callers; by "
                        "default a module only a test imports is reported")
    p.add_argument("--json", action="store_true")


def _need_slug(args) -> str:
    if not args.slug:
        raise PromoteError(f"ctf release {args.action}: an event slug is required")
    return args.slug


def _normalise(args: argparse.Namespace) -> None:
    """`ctf release SLUG` -> action arm, slug SLUG. An unknown word followed by a slug is an error."""
    if args.action in ACTIONS:
        return
    if args.slug is not None:
        raise PromoteError(f"unknown action {args.action!r} (one of {', '.join(ACTIONS)})")
    args.action, args.slug = "arm", args.action


def run(args: argparse.Namespace) -> int:
    try:
        _normalise(args)
        return _dispatch(args)
    except PromoteError as e:
        print(f"ctf release: {e}", file=sys.stderr)
        return 1 if isinstance(e, _arm.ArmError) else 2


def _dispatch(args: argparse.Namespace) -> int:
    m = args.master

    if args.action == "unwired":
        rows = _arm.unwired(root=m, package=args.package, include_tests=args.include_tests)
        if args.json:
            print(json.dumps([r.__dict__ for r in rows], indent=2))
        else:
            for r in rows:
                print(f"UNWIRED  {r.module}  ({r.path})  {r.reason}")
            print(f"release unwired: {len(rows)} module(s) nothing imports", file=sys.stderr)
        return 0

    slug = _need_slug(args)

    if args.action == "arm":
        t = _arm.arm(slug, master=m, ref=args.ref, allow_past_freeze=args.allow_past_freeze)
        _emit(args, {"action": "armed", "tag": t.name, "commit": t.commit},
              f"armed {slug} at {t.commit[:12]}: {t.name}")
        return 0

    if args.action == "green":
        t = _arm.mark_green(slug, master=m, ref=args.ref, note="marked by hand (ctf release green)")
        _emit(args, {"action": "green", "tag": t.name, "commit": t.commit},
              f"marked green {slug} at {t.commit[:12]}: {t.name}")
        return 0

    if args.action == "freeze":
        t = _arm.freeze(slug, master=m, ref=args.ref)
        _emit(args, {"action": "freeze", "tag": t.name, "commit": t.commit},
              f"froze {slug} at {t.commit[:12]}: {t.name}")
        return 0

    if args.action == "thaw":
        t = _arm.thaw(slug, master=m)
        _emit(args, {"action": "thaw", "tag": t.name, "commit": t.commit},
              f"thawed {slug}: {t.name}")
        return 0

    if args.action == "rollback":
        t = _arm.rollback_target(slug, master=m)
        _emit(args, {"action": "rollback", "tag": t.name, "commit": t.commit},
              f"roll back {slug} to {t.commit} ({t.name})")
        return 0

    # status / check share the lag view.
    lg = _arm.lag(slug, master=m, head=args.head)
    fz = _arm.active_freeze(slug, master=m)
    green = _arm.last_green(slug, master=m)
    if args.json:
        print(json.dumps({
            "slug": slug,
            "state": lg.state,
            "is_lagging": lg.is_lagging,
            "behind": lg.behind,
            "armed": lg.armed.name if lg.armed else None,
            "armed_commit": lg.armed.commit if lg.armed else None,
            "head_commit": lg.head_commit,
            "files": list(lg.files),
            "detail": lg.detail,
            "freeze": fz.name if fz else None,
            "last_green": green.name if green else None,
        }, indent=2))
    else:
        print(f"release status {slug}: {lg.state.upper()} — {lg.detail}")
        if fz is not None:
            print(f"  FROZEN at {fz.commit[:12]} ({fz.name})")
        if green is not None:
            print(f"  last green {green.commit[:12]} ({green.name})")
        for f in lg.files:
            print(f"  changed-since-armed  {f}")
    if args.action == "check":
        return 1 if lg.is_lagging else 0
    return 0


def _emit(args, payload: dict, line: str) -> None:
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(line)
