"""ctf event list | show [SLUG] | check [SLUG ...] — inspect and validate event profiles."""
from __future__ import annotations

import argparse
import sys

from .. import event as _event
from .. import flagfmt as _flagfmt

HELP = "list, show or validate event profiles (events/<slug>/event.toml)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    sp.add_parser("list", help="slugs with an event.toml")
    sh = sp.add_parser("show", help="print one profile (default: the current event)")
    sh.add_argument("slug", nargs="?")
    ck = sp.add_parser("check", help="validate profiles (default: all); exit 1 on any error")
    ck.add_argument("slugs", nargs="*")


def _show(prof: _event.EventProfile) -> None:
    ff = _flagfmt.for_profile(prof)
    r = prof.rules
    print(f"{prof.slug}: {prof.name}  ({prof.start} .. {prof.end})")
    print(f"  platform   {prof.platform.kind}  {prof.platform.base_url or '-'}  team={prof.platform.team or '-'}")
    print(f"  flag       {ff.pattern}  case={prof.flag.case}{'' if ff.known else '  (format not known yet)'}")
    if prof.proof:
        print(f"  proof      {ff.proof_pattern}")
    print(f"  submit     {r.submit_mode}  stop after {r.wrong_answer_stop} wrong  guess_budget={r.guess_budget}  "
          f"hints={'yes' if r.hints_allowed else 'no'}")
    print(f"  sharing    flags {r.flag_sharing}  ai_on_platform {r.ai_on_platform}  "
          f"web_state_changing={'yes' if r.web_state_changing else 'no'}")
    print(f"  scope      {', '.join(r.live_service_scope) or '-'}")
    print(f"  pub fetch  {', '.join(r.public_fetch_allow) or '-'}")
    b = prof.budget
    per = f"${b.per_challenge_day}/challenge-day" if b.per_challenge_day is not None else f"${b.per_point}/pt"
    print(f"  budget     {per}  floor ${b.floor}  ceiling ${b.ceiling}")
    print(f"  categories {', '.join(prof.categories) or '-'}")


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "list":
            for slug in _event.available():
                print(slug)
            return 0
        if args.action == "show":
            _show(_event.load(args.slug) if args.slug else _event.current())
            return 0
        slugs = args.slugs or _event.available()
        if not slugs:
            print("no event profiles found", file=sys.stderr)
            return 1
        bad = 0
        for slug in slugs:
            try:
                _event.load(slug)
                print(f"ok    {slug}")
            except _event.EventError as e:
                bad += 1
                print(f"FAIL  {slug}: {e}")
        return 1 if bad else 0
    except _event.EventError as e:
        print(f"ctf event: {e}", file=sys.stderr)
        return 2
