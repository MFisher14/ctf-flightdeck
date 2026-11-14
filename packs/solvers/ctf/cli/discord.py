"""ctf discord -- Discord recon for announcement and recognition flags (B-112).

    python -m ctf discord checklist [--challenge ID] [--card] [--json]
        the places a person reads in the event's Discord server, with what the snapshot already
        covers; --card puts the request on the player's task cards (`ctf human cards`), once.
    python -m ctf discord ingest FILE... [--as auto|snapshot|export|text] [--where PLACE] [--kind KIND]
        add what the player saved to the event's snapshot: a text paste (needs --where; `-` reads
        stdin), a chat exporter's channel JSON, or another snapshot.
    python -m ctf discord capture [--guild ID] [--first N] [--recent N] [--bots N] [--max-requests N]
                                  [--timeout S] [--min-interval S]
        read the server through the bot API, GET only. Refused (exit 4) unless the event profile says
        `[discord] capture = "bot"`, lists the API host in rules.public_fetch_allow, and the variable
        named by `[discord] token_env` holds the bot token.
    python -m ctf discord analyze [--challenge ID] [--cue TEXT]... [--top N] [--json] [--no-decode]
        flag and recognition-word candidates in the snapshot, best first, with no model. With
        --challenge the challenge's own words rank the items and the report is written to
        <challenge>/recon/discord.md; otherwise to <workdir>/discord/candidates.md.
    python -m ctf discord status [--json]
        what the snapshot holds and the notes of each capture.

Common: --event SLUG, --workdir DIR (before the sub-command). The snapshot is
<workdir>/discord/snapshot.json. Nothing here submits, joins a server or reads the Discord app's own
data; the token is never printed. Exit codes: 0 ok (analyze: at least one candidate), 1 analyze found
nothing, 2 a named error, 4 capture refused before any request.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import discordapi as _api
from .. import discordrecon as _dr
from .. import event as _event
from .. import ledger as _ledger
from .. import paths as _paths

HELP = "Discord recon: checklist, ingest a paste or export, bot capture, flag and recognition-word candidates"

REFUSED_EXIT = 4
ERROR_EXIT = 2
NOTHING_EXIT = 1


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event working folder (default: the event's own)")
    sp = p.add_subparsers(dest="action", required=True)

    ck = sp.add_parser("checklist", help="the places to read in the server, and what is already captured")
    ck.add_argument("--challenge", metavar="ID", help="the challenge the read is for")
    ck.add_argument("--card", action="store_true",
                    help="also put the request on the player's task cards (needs --challenge)")
    ck.add_argument("--json", action="store_true")

    ig = sp.add_parser("ingest", help="add a text paste, a chat export or a snapshot to the event snapshot")
    ig.add_argument("files", nargs="+", metavar="FILE", help="a saved file; '-' reads a text paste from stdin")
    ig.add_argument("--as", dest="as_", choices=("auto", "snapshot", "export", "text"), default="auto")
    ig.add_argument("--where", help="for text: the place it was read, e.g. '#rules' or 'bot Watchtower'")
    ig.add_argument("--kind", choices=_dr.KINDS, help="for text: what it is (default: message)")

    cp = sp.add_parser("capture", help="read the server through the bot API (profile clearance required)")
    cp.add_argument("--guild", metavar="ID", help="the server's numeric id (default: the profile's guild_id)")
    cp.add_argument("--first", type=int, default=50, metavar="N",
                    help="oldest messages read per channel, the channel start (default 50, at most 100)")
    cp.add_argument("--recent", type=int, default=0, metavar="N",
                    help="newest messages read per channel (default 0, at most 100)")
    cp.add_argument("--bots", type=int, default=25, metavar="N", help="bots whose description is read (default 25)")
    cp.add_argument("--max-requests", type=int, default=400, metavar="N", help="request budget (default 400)")
    cp.add_argument("--timeout", type=float, default=20.0, metavar="S", help="per-request timeout (default 20)")
    cp.add_argument("--min-interval", type=float, default=0.25, metavar="S",
                    help="least time between two requests (default 0.25)")

    an = sp.add_parser("analyze", help="flag and recognition-word candidates in the snapshot")
    an.add_argument("--challenge", metavar="ID", help="rank for this challenge and write its recon/discord.md")
    an.add_argument("--cue", action="append", default=[], metavar="TEXT",
                    help="words that tie an item to what you look for (repeatable)")
    an.add_argument("--top", type=int, default=25, metavar="N", help="candidates shown (default 25)")
    an.add_argument("--json", action="store_true")
    an.add_argument("--no-decode", action="store_true", help="skip the codec graph (base64, hex, rot13 ...)")

    st = sp.add_parser("status", help="what the snapshot holds")
    st.add_argument("--json", action="store_true")


def _record(workdir: Path, event_type: str, **fields) -> None:
    try:
        _ledger.append(event_type, workdir=workdir, **fields)
    except OSError as e:
        print(f"ctf discord: not recorded in the ledger ({e})", file=sys.stderr)


def _challenge_dir(ref: str, workdir: Path) -> Path:
    from .. import scratch as _scratch
    try:
        return _scratch.challenge_dir(ref, workdir)
    except _scratch.ScratchError as e:
        raise _dr.DiscordReconError(str(e)) from None


def run(args: argparse.Namespace) -> int:
    try:
        prof = _event.load(args.event) if args.event else _event.current()
        workdir = Path(args.workdir) if args.workdir else _paths.workdir(prof.slug)
        snap_path = _dr.snapshot_path(workdir)
        return {"checklist": _checklist, "ingest": _ingest, "capture": _capture, "analyze": _analyze,
                "status": _status}[args.action](args, prof, workdir, snap_path)
    except _api.DiscordRefused as e:
        print(f"ctf discord: refused: {e}", file=sys.stderr)
        return REFUSED_EXIT
    except (_event.EventError, _dr.DiscordReconError, _api.DiscordError, ValueError, OSError) as e:
        print(f"ctf discord: {e}", file=sys.stderr)
        return ERROR_EXIT


def _checklist(args, prof, workdir: Path, snap_path: Path) -> int:
    snap = _dr.load(snap_path) if snap_path.exists() else None
    places = _dr.checklist(snap)
    card = created = None
    if args.card:
        if not args.challenge:
            raise _dr.DiscordReconError("--card needs --challenge ID (a card is for one challenge)")
        from .. import humanops as _h
        try:
            card, created = _dr.request_card(prof, args.challenge, workdir=workdir)
        except _h.HumanOpsError as e:
            raise _dr.DiscordReconError(str(e)) from None
    if args.json:
        print(json.dumps({"event": prof.slug, "capture": prof.discord.capture, "challenge": args.challenge,
                          "snapshot": str(snap_path) if snap is not None else None,
                          "card": card.id if card is not None else None, "card_created": created,
                          "places": [{"key": p.key, "ask": p.ask, "kinds": list(p.kinds), "by_bot": p.by_bot,
                                      "have": p.have, "done": p.done} for p in places]}, indent=1))
        return 0
    sys.stdout.write(_dr.render_checklist(places, capture=prof.discord.capture, challenge=args.challenge))
    if card is not None:
        print(f"task card {card.id}: {'opened' if created else 'already open'} (python -m ctf human cards)")
    return 0


def _ingest(args, prof, workdir: Path, snap_path: Path) -> int:
    snap = _dr.load_or_new(snap_path)
    total = added = 0
    for f in args.files:
        if f == "-":
            if args.as_ not in ("auto", "text"):
                raise _dr.DiscordReconError("stdin is read as a text paste (--as text)")
            guild, items, fmt = {}, _dr.ingest_text(sys.stdin.read(), where=args.where or "",
                                                    kind=args.kind or "message"), "text"
        else:
            guild, items, fmt = _dr.ingest_file(f, as_=args.as_, where=args.where, kind=args.kind)
        for k, v in guild.items():
            snap.guild.setdefault(k, v)
        src = {"text": "paste", "export": "export", "snapshot": "snapshot"}[fmt]
        new = snap.add(items, source=src)
        total += len(items)
        added += new
        print(f"{f}: {fmt}, {len(items)} item(s), {new} new")
        _record(workdir, "discord.ingest", event_slug=prof.slug, source=src, items=len(items), added=new)
    _dr.save(snap, snap_path)
    print(f"snapshot: {snap_path} ({len(snap.items)} item(s)); next: python -m ctf discord analyze")
    return 0


def _capture(args, prof, workdir: Path, snap_path: Path) -> int:
    guild_id = args.guild or prof.discord.guild_id
    client = _api.from_profile(prof, timeout=args.timeout, max_requests=args.max_requests,
                               min_interval=args.min_interval)
    if not guild_id:
        raise _dr.DiscordReconError(f"no server id: pass --guild ID or set [discord] guild_id in "
                                    f"events/{prof.slug}/event.toml")
    snap = _dr.load_or_new(snap_path)       # an unreadable snapshot fails here, before any request
    res = _api.capture(client, guild_id, first=args.first, recent=args.recent, bots=args.bots)
    for k, v in res.guild.items():
        snap.guild[k] = v
    new = snap.add(res.items, source="api", notes=res.notes)
    _dr.save(snap, snap_path)
    _record(workdir, "discord.capture", event_slug=prof.slug, guild_id=str(guild_id), items=len(res.items),
            added=new, requests=res.requests, partial=res.partial, notes=len(res.notes))
    print(f"captured {len(res.items)} item(s) ({new} new) in {res.requests} request(s)"
          + (" -- PARTIAL, see the notes" if res.partial else ""))
    for n in res.notes:
        print(f"  note: {n}")
    print(f"snapshot: {snap_path} ({len(snap.items)} item(s)); next: python -m ctf discord analyze")
    return 0


def _analyze(args, prof, workdir: Path, snap_path: Path) -> int:
    snap = _dr.load(snap_path)
    decode = not args.no_decode
    if args.challenge:
        chal = _challenge_dir(args.challenge, workdir)
        rep, out = _dr.analyze_challenge(snap, prof, chal, extra_cues=args.cue, decode=decode)
        title = _dr.report_title(_dr.read_challenge(chal))
    else:
        rep = _dr.analyze(snap, prof, cues=_dr.cue_words(*args.cue), decode=decode)
        out = snap_path.with_name(_dr.REPORT_NAME)
        title = "Discord recon candidates"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(_dr.render_report(rep, title=title, top=50), encoding="utf-8")
    _record(workdir, "discord.analyze", event_slug=prof.slug, items=rep.items, candidates=len(rep.candidates),
            flags=len(rep.flags()), **({"challenge_id": str(args.challenge)} if args.challenge else {}))
    if args.json:
        print(json.dumps({**rep.to_dict(), "report": str(out)}, indent=1, ensure_ascii=False))
    else:
        sys.stdout.write(_dr.render_report(rep, title=title, top=args.top))
        print(f"\nreport: {out}")
    return 0 if rep.candidates else NOTHING_EXIT


def _status(args, prof, workdir: Path, snap_path: Path) -> int:
    snap = _dr.load(snap_path)
    if args.json:
        print(json.dumps({"event": prof.slug, "snapshot": str(snap_path), "guild": snap.guild,
                          "items": len(snap.items), "counts": snap.counts(), "captures": snap.captures,
                          "capture": prof.discord.capture}, indent=1))
        return 0
    name = snap.guild.get("name") or snap.guild.get("id") or "(server not named)"
    print(f"{snap_path}: {len(snap.items)} item(s) from {name}; profile capture = {prof.discord.capture}")
    for k, n in snap.counts().items():
        print(f"  {k:18} {n}")
    for c in snap.captures:
        print(f"  capture via {c.get('source')}: {c.get('items')} item(s), {c.get('added')} new")
        for n in c.get("notes", []):
            print(f"    note: {n}")
    return 0
