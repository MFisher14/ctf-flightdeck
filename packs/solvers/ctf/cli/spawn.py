"""ctf spawn request | brief | result | results | end | allow | board | escalations -- brief-not-fork
spawning and the per-challenge agent gate (B-143, ctf/spawn.py).

    python -m ctf spawn request ID [--role owner|helper|auto] [--lane L] [--task T] [--evidence PATH ...]
                                  [--fork --reason R [--parent-tok N] [--fork-turns all|N]]
                                  [--harness H] [--model M] [--replaces SPAWN] [--minutes N] [--json]
    python -m ctf spawn brief ID [--lane L] [--task T] [--evidence PATH ...]   print a brief, record nothing
    python -m ctf spawn result ID --lane L --status found|ruled_out|partial|blocked --summary T
                              [--spawn SPAWN] [--path P ...]
    python -m ctf spawn results ID [--json]
    python -m ctf spawn end SPAWN [--reason R]
    python -m ctf spawn allow ID --agents N --reason R     the player's, at a terminal only
    python -m ctf spawn board [ID ...] [--json]
    python -m ctf spawn escalations [--harness H] [--json]

Run `request` before starting any helper agent. Admitted (exit 0): it prints the spawn id, the brief
file to start the helper from with `fork_turns: "none"`, and the helper's first-input size; launch it
with CTF_SPAWN_ID=<spawn id> through tools/codex_launch or tools/claude_launch (or hand the brief to the
harness's own spawn tool). Held (exit 3): the challenge already has its limit of agents; do not start
one: the player decides with `ctf spawn allow`. Refused (exit 4): the reason is named (a stopped or
capped challenge, a second owner, a full fork with no stated reason). 2 is a named error.

`escalations` answers each dispatched B-016 escalation record with a spawn request on its model
(exit 3 when any is held, 4 when any is refused). Nothing here launches an agent or calls a model.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from .. import event as _event
from .. import paths as _paths
from .. import spawn as _spawn

HELP = "brief-not-fork spawning and the 5-agent gate per challenge: request, result, end, allow, board"

EXIT_HELD = 3
EXIT_REFUSED = 4


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)

    def brief_opts(s):
        s.add_argument("id", help="challenge id")
        s.add_argument("--lane", help="the lane this agent works (web, crypto, osint-geo, ...)")
        s.add_argument("--task", help="one line: what this agent is to do")
        s.add_argument("--evidence", action="append", default=[], metavar="PATH",
                       help="a file the agent must read first (repeatable; must exist)")
        s.add_argument("--minutes", type=int, default=_spawn.STOP_MINUTES,
                       help=f"stop after this many minutes without new evidence (default {_spawn.STOP_MINUTES})")

    rq = sp.add_parser("request", help="ask to start one agent on a challenge (brief by default)")
    brief_opts(rq)
    rq.add_argument("--role", default=_spawn.ROLE_AUTO, choices=(*_spawn.ROLES, _spawn.ROLE_AUTO))
    rq.add_argument("--fork", action="store_true", help="a full fork of the parent's context (needs --reason "
                    f"unless --parent-tok is at most {_spawn.FORK_MAX_TOK:,})")
    rq.add_argument("--reason", help="why a full fork is needed")
    rq.add_argument("--parent-tok", type=int, help="the parent's current context size in tokens")
    rq.add_argument("--fork-turns", help="fork only: 'all' (default) or a turn count")
    rq.add_argument("--harness", help="claude or codex")
    rq.add_argument("--model")
    rq.add_argument("--replaces", metavar="SPAWN", help="hand the owner seat over from this live owner")
    rq.add_argument("--json", action="store_true")

    br = sp.add_parser("brief", help="print the brief a request would write, recording nothing")
    brief_opts(br)

    rs = sp.add_parser("result", help="record one lane result as it is found")
    rs.add_argument("id")
    rs.add_argument("--lane", required=True)
    rs.add_argument("--status", required=True, choices=_spawn.RESULT_STATUSES)
    rs.add_argument("--summary", required=True)
    rs.add_argument("--spawn", help="the spawn id of the agent recording it")
    rs.add_argument("--path", action="append", default=[], help="a file holding the evidence (repeatable)")

    rl = sp.add_parser("results", help="list a challenge's lane results")
    rl.add_argument("id")
    rl.add_argument("--json", action="store_true")

    en = sp.add_parser("end", help="mark a spawned agent finished (frees the owner seat)")
    en.add_argument("spawn")
    en.add_argument("--reason")

    al = sp.add_parser("allow", help="let more agents onto a challenge (interactive; the player's decision)")
    al.add_argument("id")
    al.add_argument("--agents", type=int, required=True, help="how many more agents")
    al.add_argument("--reason", required=True)

    bo = sp.add_parser("board", help="agents per challenge: role, mode, first-input size, live or ended")
    bo.add_argument("ids", nargs="*")
    bo.add_argument("--json", action="store_true")

    es = sp.add_parser("escalations", help="answer dispatched B-016 escalation records with spawn requests")
    es.add_argument("--harness", help="the harness the escalated agents will run on")
    es.add_argument("--json", action="store_true")


def _profile(args) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _held_msg(d: _spawn.Decision) -> None:
    print(f"SPAWN GATE: {d.detail} (checkpoint: {d.checkpoint})", file=sys.stderr, flush=True)


def _say(d: _spawn.Decision, as_json: bool) -> int:
    if as_json:
        print(json.dumps(d.to_fields(), ensure_ascii=False), flush=True)
    if d.status == "admitted":
        if not as_json:
            size = "unknown (fork of a parent of unknown size)" if d.first_input_tok is None \
                else f"~{d.first_input_tok:,} tok"
            print(f"admitted: {d.spawn_id} ({d.role}, {d.mode}) on {d.challenge_id}: agent {d.agents + 1} of "
                  f"{d.cap}; first input {size}; fork_turns {d.fork_turns}; "
                  f"spawn tool {'kept' if d.spawn_tool else 'OFF'}")
            if d.brief_path:
                print(f"brief: {d.brief_path}")
            print(f"launch with CTF_SPAWN_ID={d.spawn_id}")
        return 0
    if d.status == "held":
        if not as_json:
            print(f"held: {d.detail}", file=sys.stderr)
        return EXIT_HELD
    if not as_json:
        print(f"refused ({d.reason}): {d.detail}", file=sys.stderr)
    return EXIT_REFUSED


def _require_human(cid: str) -> str:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise PermissionError("`ctf spawn allow` is the player's decision: run it yourself in an interactive "
                              "terminal (no flag bypasses this)")
    typed = input(f"Type the challenge id ({cid}) to let more agents onto it: ").strip()
    if typed != cid:
        raise PermissionError(f"confirmation did not match {cid!r}; nothing changed")
    return getpass.getuser() or "human"


def _board_lines(v: _spawn.ChallengeView) -> list[str]:
    owner = v.owner
    out = [f"{v.challenge_id:<12} agents {v.agents}/{v.cap}  owner "
           f"{owner.get('spawn_id') if owner else '-'}"
           + ("  HELD: waiting for `ctf spawn allow`" if v.waiting else "")
           + (f"  (+{v.legacy_launches} launch(es) from before the gate)" if v.legacy_launches else "")]
    for s in v.spawns:
        fit = s.get("first_input_tok")
        if fit is None:
            size = "fresh launch" if s.get("mode") == "launch" else "size unknown"
        else:
            size = f"{int(fit):,} tok" + (" LARGE" if int(fit) > _spawn.FORK_MAX_TOK else "")
        out.append(f"  {s.get('spawn_id'):<16} {s.get('role', '?'):<6} {s.get('mode', '?'):<6} first input "
                   f"{size:<18} lane {s.get('lane') or '-':<12} {s.get('model') or '-':<16} "
                   f"{'live' if s.get('live') else 'ended'}")
    return out


def run(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
        wd = _paths.workdir(profile.slug)
        sp = _spawn.Spawner(wd, profile=profile, on_hold=_held_msg)
        if args.action == "brief":
            text = sp.preview(args.id, lane=args.lane, task=args.task, evidence=args.evidence,
                              stop_minutes=args.minutes)
            print(text)
            print(f"(~{_spawn.estimate_tok(text):,} tok)", file=sys.stderr)
            return 0
        if args.action == "request":
            if (args.reason or args.parent_tok is not None or args.fork_turns) and not args.fork:
                raise _spawn.SpawnError("--reason, --parent-tok and --fork-turns are for a full fork (--fork)")
            if args.harness:
                _spawn.no_spawn_args(args.harness)          # an unknown harness is named here
            d = sp.request(args.id, role=args.role, mode="fork" if args.fork else "brief", reason=args.reason,
                           parent_tok=args.parent_tok, fork_turns=args.fork_turns, lane=args.lane,
                           task=args.task, evidence=args.evidence, harness=args.harness, model=args.model,
                           stop_minutes=args.minutes, replaces=args.replaces)
            return _say(d, args.json)
        if args.action == "result":
            rec = _spawn.record_result(args.id, args.lane, args.status, args.summary, spawn_id=args.spawn,
                                       paths=args.path, workdir=wd)
            print(f"recorded lane_result: {rec['challenge_id']} lane {rec['lane']} {rec['status']}")
            return 0
        if args.action == "results":
            for r in _spawn.results(args.id, workdir=wd):
                if args.json:
                    print(json.dumps(r, ensure_ascii=False))
                else:
                    print(f"[{r.get('status')}] lane {r.get('lane')}: {_spawn.one_line(r.get('summary'), 400)}"
                          + (f" ({r.get('spawn_id')})" if r.get("spawn_id") else ""))
            return 0
        if args.action == "end":
            sp.end(args.spawn, reason=args.reason)
            print(f"ended {args.spawn}")
            return 0
        if args.action == "allow":
            v = sp.view(args.id)
            print(f"{args.id}: {v.agents} agent(s), limit {v.cap}")
            if args.agents < 1:
                raise _spawn.SpawnError("--agents must be at least 1")
            who = _require_human(args.id)
            new = sp.allow(args.id, args.agents, by=who, reason=args.reason)
            print(f"{args.id}: agent limit now {new}")
            return 0
        if args.action == "board":
            views = sp.board(args.ids or None)
            if not views and not args.json:
                print("no spawned agents in the ledger yet")
            for v in views:
                if args.json:
                    print(json.dumps(v.to_dict(), ensure_ascii=False, default=str))
                else:
                    print("\n".join(_board_lines(v)))
            return 0
        if args.action == "escalations":
            if args.harness:
                _spawn.no_spawn_args(args.harness)
            rc = 0
            for d in sp.from_escalations(harness=args.harness):
                r = _say(d, args.json)
                rc = max(rc, r)
            return rc
        raise _spawn.SpawnError(f"unknown action {args.action!r}")
    except PermissionError as e:
        print(f"ctf spawn: {e}", file=sys.stderr)
        return 1
    except (_event.EventError, _spawn.SpawnError, ValueError, EOFError) as e:
        print(f"ctf spawn: {e}", file=sys.stderr)
        return 2
