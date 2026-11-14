"""ctf new-event SLUG [--manual] [...] — scaffold events/<slug>/: event.toml plus CLAUDE.md and AGENTS.md.

    python -m ctf new-event acme --name "ACME CTF 2027" --start 2027-03-01T09:00:00Z \\
        --end 2027-03-03T09:00:00Z --base-url https://ctf.acme.example --flag-prefix ACME
    python -m ctf new-event spookier --manual --start 2027-10-30 --end 2027-10-31 --flag-prefix spooky
    python -m ctf new-event acme --regen [--workdir DIR]      # after hand-editing event.toml

Writes events/<slug>/event.toml (rules, sectors and dates from the options; edit the file by hand for
anything else), then renders events/<slug>/CLAUDE.md and events/<slug>/AGENTS.md from the ONE
template, templates/event/agent-rules.md.tmpl, so both harnesses load the same rules.

Categories: when the platform is not manual, automation on it is allowed, a base URL is set
(--base-url or CTF_PLATFORM_URL) and a token is configured (CTF_TOKEN), they come from the platform
adapter's list_challenges(); --category adds hand-entered ones. A failed fetch stops the scaffold
(use --no-fetch to skip it on purpose). The token is never printed.

Defaults are the cautious ones: flag sharing forbidden, submit_mode "confirm" (or "manual"), flag
format unknown until --flag-prefix. --manual means a Spooky-type event: platform kind manual, no
submit, and ai_on_platform forbidden unless --ai-on-platform allowed is given.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import shutil
import sys
from pathlib import Path

from .. import env
from .. import event as _event
from .. import eventrules
from .. import eventscaffold as sc
from .. import paths

HELP = "scaffold a new event: events/<slug>/event.toml plus CLAUDE.md and AGENTS.md from one template"

_PROFILE_OPTS = ("manual", "name", "start", "end", "platform", "base_url", "team", "flag_prefix",
                 "flag_body", "flag_case", "proof_pattern", "submit_mode", "wrong_answer_stop",
                 "guess_budget", "hints_allowed", "flag_sharing", "ai_on_platform", "scope",
                 "public_fetch", "web_state_changing", "category", "sector", "public_repo", "no_fetch", "force",
                 "wrong_penalty", "no_approved_extras", "hint_suggestions", "pointed_services", "sweep",
                 "chain_rpc",
                 "sandboxed_execution")


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("slug", help="event folder name: lower-case letters, digits and dashes")
    p.add_argument("--manual", action="store_true",
                   help="manual event: no platform automation, the player pulls and submits by hand")
    p.add_argument("--regen", action="store_true",
                   help="only re-render CLAUDE.md and AGENTS.md from the existing event.toml")
    p.add_argument("--force", action="store_true", help="overwrite an existing event.toml")
    p.add_argument("--workdir", type=Path, metavar="DIR",
                   help="also install copies of CLAUDE.md and AGENTS.md into DIR (where sessions run)")
    p.add_argument("--events-root", type=Path, metavar="DIR", help="default: <repo>/events")
    g = p.add_argument_group("event")
    g.add_argument("--name", help="display name (default: the slug)")
    g.add_argument("--start", help="ISO date or datetime (required for a new event)")
    g.add_argument("--end", help="ISO date or datetime (required for a new event)")
    g.add_argument("--category", action="append", default=[], help="hand-entered category (repeatable)")
    g.add_argument("--sector", action="append", default=[], help="target sector (repeatable)")
    g = p.add_argument_group("platform")
    g.add_argument("--platform", choices=_event.PLATFORM_KINDS,
                   help="default: manual with --manual, else ctfd")
    g.add_argument("--base-url", help="platform URL (default: $CTF_PLATFORM_URL)")
    g.add_argument("--team", help="our team name or id on the platform")
    g.add_argument("--no-fetch", action="store_true",
                   help="do not read categories from the platform even when a token is configured")
    g = p.add_argument_group("flag")
    g.add_argument("--flag-prefix", action="append", default=[],
                   help="flag prefix, e.g. ACME for ACME{...} (repeatable; none = format not known yet)")
    g.add_argument("--flag-body", help=f"body regex (default {_event.DEFAULT_BODY})")
    g.add_argument("--flag-case", choices=_event.CASE_RULES, default=None, help="default exact")
    g.add_argument("--proof-pattern", help="regex of a non-flag proof token, if the event has one")
    g = p.add_argument_group("rules (hand-entered from the organizer's rules page)")
    g.add_argument("--submit-mode", choices=_event.SUBMIT_MODES,
                   help="default: manual for a manual or ai-forbidden event, else confirm")
    g.add_argument("--wrong-answer-stop", type=int, default=None, help="default 3")
    g.add_argument("--guess-budget", type=int, default=None, help="default 0")
    g.add_argument("--hints-allowed", action="store_true")
    g.add_argument("--flag-sharing", choices=_event.ALLOWED_FORBIDDEN, help="default forbidden")
    g.add_argument("--ai-on-platform", choices=_event.ALLOWED_FORBIDDEN,
                   help="default: forbidden with --manual, else allowed")
    g.add_argument("--scope", action="append", default=[], metavar="GLOB",
                   help="live host glob agents may contact (repeatable; none = no live host)")
    g.add_argument("--public-fetch", action="append", default=[], metavar="GLOB",
                   help="public third-party host (symbol server, mirror) tools may fetch from "
                        "(repeatable; none = no public fetch)")
    g.add_argument("--web-state-changing", action="store_true",
                   help="allow state-changing web requests against live targets")
    g.add_argument("--public-repo", help="where public write-ups go")
    g = p.add_argument_group("solve policy (B-173; `python -m ctf policy show` prints it)")
    g.add_argument("--wrong-penalty", type=int, default=None, metavar="POINTS",
                   help="points lost per wrong answer (default: not known)")
    g.add_argument("--no-approved-extras", action="store_true",
                   help="make the wrong-answer stop final: the player cannot approve more sends")
    g.add_argument("--hint-suggestions", action="store_true",
                   help="let agents suggest taking a hint to the player (default: they do not)")
    g.add_argument("--pointed-services", choices=_event.ALLOWED_FORBIDDEN,
                   help="may agents solve against a challenge service the player points at (default forbidden)")
    g.add_argument("--chain-rpc", choices=_event.ALLOWED_FORBIDDEN,
                   help="may the read-only EVM JSON-RPC reader query an in-scope chain node (default forbidden)")
    g.add_argument("--sweep", choices=_event.SWEEP_MODES,
                   help="forbidden (default) or player-authorized: one-run sweeps the player authorizes")
    g.add_argument("--sandboxed-execution", choices=_event.ALLOWED_FORBIDDEN,
                   help="may the runtime adapters run a delivered managed or bytecode artifact in a pinned, "
                        "networkless container (default forbidden)")


def _err(msg: str) -> int:
    print(f"ctf new-event: {msg}", file=sys.stderr)
    return 1


def _install(files: list[Path], workdir: Path) -> None:
    workdir.mkdir(parents=True, exist_ok=True)
    for f in files:
        shutil.copyfile(f, workdir / f.name)
        print(f"installed {workdir / f.name}")


def _regen(args: argparse.Namespace, root: Path) -> int:
    # `is` for None/False: an explicit 0 (--wrong-penalty 0) equals False and must still count as given
    given = [o for o in _PROFILE_OPTS
             if getattr(args, o) is not None and getattr(args, o) is not False and getattr(args, o) != []]
    if given:
        return _err("--regen re-renders from the existing event.toml and takes no profile options "
                    f"(got: {', '.join('--' + o.replace('_', '-') for o in given)}); edit the file instead")
    prof = _event.load(args.slug, root)
    files = eventrules.write(prof, root / args.slug)
    for f in files:
        print(f"wrote {f}")
    if args.workdir:
        _install(files, args.workdir)
    return 0


def _build(args: argparse.Namespace, root: Path) -> int:
    slug = args.slug
    dest = root / slug
    toml_path = dest / _event.PROFILE_NAME
    if toml_path.exists() and not args.force:
        return _err(f"{toml_path} already exists; edit it and run `new-event {slug} --regen`, "
                    "or pass --force to overwrite it")
    if args.start is None or args.end is None:
        return _err("--start and --end are required for a new event (ISO date or datetime)")
    if args.manual and args.platform not in (None, "manual"):
        return _err(f"--manual conflicts with --platform {args.platform}")
    kind = "manual" if args.manual else (args.platform or "ctfd")
    base_url = args.base_url
    url_note = ""
    if base_url is None and kind != "manual":
        base_url = env.get("CTF_PLATFORM_URL")
        url_note = " (from CTF_PLATFORM_URL)" if base_url else ""
    if kind != "manual" and not base_url:
        return _err(f"platform kind {kind!r} needs --base-url (or CTF_PLATFORM_URL); "
                    "use --manual for an event with no platform automation")
    ai = args.ai_on_platform or ("forbidden" if kind == "manual" else "allowed")
    submit_mode = args.submit_mode or ("manual" if kind == "manual" or ai == "forbidden" else "confirm")
    start = sc.parse_when(args.start, "--start")
    end = sc.parse_when(args.end, "--end")

    def make(categories: list[str]) -> dict:
        return sc.profile_data(
            slug, name=args.name or slug, start=start, end=end, kind=kind, base_url=base_url,
            team=args.team, categories=categories, sectors=sc.merge_categories(args.sector),
            prefixes=args.flag_prefix, body=args.flag_body, case=args.flag_case or "exact",
            proof_pattern=args.proof_pattern, submit_mode=submit_mode,
            wrong_answer_stop=3 if args.wrong_answer_stop is None else args.wrong_answer_stop,
            guess_budget=0 if args.guess_budget is None else args.guess_budget,
            hints_allowed=args.hints_allowed, flag_sharing=args.flag_sharing or "forbidden",
            ai_on_platform=ai, live_service_scope=args.scope, web_state_changing=args.web_state_changing,
            public_fetch_allow=args.public_fetch, public_repo=args.public_repo,
            wrong_penalty=args.wrong_penalty, approved_extras=not args.no_approved_extras,
            hint_suggestions=args.hint_suggestions,
            pointed_services=args.pointed_services or "forbidden", sweep_mode=args.sweep or "forbidden",
            chain_rpc=args.chain_rpc or "forbidden",
            sandboxed_execution=args.sandboxed_execution or "forbidden")

    hand = sc.merge_categories(args.category)
    data = make(hand)
    prof = sc.validate(data, slug)  # fail on bad options before any platform call

    why = sc.fetch_refusal(prof)
    if args.no_fetch:
        cat_note = "categories: not fetched (--no-fetch)"
    elif why:
        cat_note = f"categories: not fetched ({why})"
    elif not sc.token_configured():
        cat_note = "categories: not fetched (CTF_TOKEN is not set)"
    else:
        fetched, n = sc.fetch_categories(prof)
        data = make(sc.merge_categories(fetched, hand))
        prof = sc.validate(data, slug)
        cat_note = f"categories: {len(fetched)} from the platform's list_challenges ({n} challenges)"
    if hand:
        cat_note += f"; {len(hand)} hand-entered"
    print(cat_note)

    header = [
        f"{prof.name}: event profile, scaffolded by `python -m ctf new-event` on "
        f"{_dt.date.today().isoformat()}.",
        "Rules, sectors and dates are hand-entered from the organizer's pages; edit any value here, then run",
        f"`python -m ctf new-event {slug} --regen` so CLAUDE.md and AGENTS.md carry the change.",
        f"{cat_note}.",
        "Schema: docs/CONTRACTS.md section 1.",
    ]
    prof = sc.write_profile(data, toml_path, header)
    print(f"wrote {toml_path}{url_note}")
    files = eventrules.write(prof, dest)
    for f in files:
        print(f"wrote {f}")
    if args.workdir:
        _install(files, args.workdir)
    if not prof.flag.known:
        print("note: flag format not known yet; set flag.prefixes in event.toml once it is, then --regen")
    print(f"next: export CTF_EVENT={slug}; python -m ctf check-event {slug}")
    return 0


def run(args: argparse.Namespace) -> int:
    root = args.events_root or paths.events_root()
    try:
        paths.event_dir(args.slug)  # rejects path-like slugs
        if args.regen:
            return _regen(args, root)
        return _build(args, root)
    except (ValueError, sc.ScaffoldError, _event.EventError, eventrules.TemplateError) as e:
        return _err(str(e))
