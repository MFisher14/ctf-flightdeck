"""ctf campaign -- checkpointed goals, crash-safe campaign state and auto-resume (B-178).

    python -m ctf campaign status [--json]                  reconcile agents, show goals and agents
    python -m ctf campaign goal add ID --title T [--challenge C] [--lane L] [--next N]
    python -m ctf campaign goal checkpoint ID --note N [--next N] [--by WHO]
    python -m ctf campaign goal set ID --status open|active|blocked|done|dropped [--blocker B] [--note N] [--next N]
    python -m ctf campaign goal list [--json]
    python -m ctf campaign launch AGENT --harness claude|codex|other [--challenge C] [--goal G]
                                  [--cwd DIR] [--prompt-file F] [--no-scratch] -- LAUNCHER [ARGS ...]
    python -m ctf campaign register AGENT --harness H [--challenge C] [--goal G] [--note N]
    python -m ctf campaign heartbeat AGENT [--note N]
    python -m ctf campaign agent-done AGENT --status done|failed [--note N]
    python -m ctf campaign resume [--relaunch] [--include-failed] [--max-launches N] [--quiet]
    python -m ctf campaign relaunch AGENT [--include-failed]
    python -m ctf campaign end --summary S [--by WHO]       the mandatory end of every build/session
    python -m ctf campaign check [--hook]                   exit 1 (2 with --hook) when the resume is unfit
    python -m ctf campaign brief next-session | gap [--lane web] [--stdout]
    python -m ctf campaign recover                          restore state.json from state.json.prev

State lives in <workdir>/campaign/; RESUME.md and briefs/ are generated in the workdir. See
docs/campaign.md for the hooks that run `resume` at session start and `check --hook` at stop.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from .. import campaign as _campaign
from .. import event as _event
from .. import paths as _paths
from .. import scratch as _scratch

HELP = "checkpointed goals, crash-safe campaign state, relaunch list, resume file and briefs"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    sp = p.add_subparsers(dest="action", required=True)
    st = sp.add_parser("status", help="reconcile agents and show the campaign")
    st.add_argument("--json", action="store_true")

    g = sp.add_parser("goal", help="add, checkpoint, set or list goals")
    gs = g.add_subparsers(dest="goal_action", required=True)
    ga = gs.add_parser("add")
    ga.add_argument("id")
    ga.add_argument("--title", required=True)
    ga.add_argument("--challenge")
    ga.add_argument("--lane", help="e.g. web, rev, crypto (gap briefs are per lane)")
    ga.add_argument("--next", dest="next_step")
    ga.add_argument("--by")
    gc = gs.add_parser("checkpoint")
    gc.add_argument("id")
    gc.add_argument("--note", required=True, help="what was done or ruled out")
    gc.add_argument("--next", dest="next_step", help="where to pick up")
    gc.add_argument("--by")
    gc.add_argument("--agent")
    gt = gs.add_parser("set")
    gt.add_argument("id")
    gt.add_argument("--status", required=True, choices=_campaign.GOAL_STATUSES)
    gt.add_argument("--blocker")
    gt.add_argument("--note")
    gt.add_argument("--next", dest="next_step")
    gt.add_argument("--by")
    gl = gs.add_parser("list")
    gl.add_argument("--json", action="store_true")

    la = sp.add_parser("launch", help="start an agent under a detached supervisor")
    la.add_argument("agent")
    la.add_argument("--harness", required=True, choices=_campaign.HARNESSES)
    la.add_argument("--challenge")
    la.add_argument("--goal")
    la.add_argument("--cwd")
    la.add_argument("--prompt-file", help="fed to the agent's stdin (with a resume preamble on relaunch)")
    la.add_argument("--no-scratch", action="store_true", help="do not open a scratch pass for the challenge")
    la.add_argument("command", nargs="*", help="-- LAUNCHER [ARGS ...] (everything after -- is the command)")

    rg = sp.add_parser("register", help="record an agent started elsewhere (alive while it heartbeats)")
    rg.add_argument("agent")
    rg.add_argument("--harness", required=True, choices=_campaign.HARNESSES)
    rg.add_argument("--challenge")
    rg.add_argument("--goal")
    rg.add_argument("--note")
    hb = sp.add_parser("heartbeat", help="a registered agent is still alive")
    hb.add_argument("agent")
    hb.add_argument("--note")
    ad = sp.add_parser("agent-done", help="an agent finished")
    ad.add_argument("agent")
    ad.add_argument("--status", required=True, choices=("done", "failed"))
    ad.add_argument("--note")

    rs = sp.add_parser("resume", help="reconcile, rebuild RESUME.md, print it; --relaunch restarts lost agents")
    rs.add_argument("--relaunch", action="store_true")
    rs.add_argument("--include-failed", action="store_true", help="also relaunch agents that exited non-zero")
    rs.add_argument("--max-launches", type=int, default=_campaign.MAX_LAUNCHES)
    rs.add_argument("--quiet", action="store_true", help="do not print RESUME.md")
    rl = sp.add_parser("relaunch", help="relaunch one lost agent")
    rl.add_argument("agent")
    rl.add_argument("--include-failed", action="store_true")
    rl.add_argument("--max-launches", type=int, default=_campaign.MAX_LAUNCHES)

    en = sp.add_parser("end", help="end the build/session: resume file + next-session and gap briefs")
    en.add_argument("--summary", required=True)
    en.add_argument("--by")
    ck = sp.add_parser("check", help="is the resume file current and complete?")
    ck.add_argument("--hook", action="store_true",
                    help="Claude Code Stop hook mode: exit 2 to block the stop (once), reasons on stderr")
    br = sp.add_parser("brief", help="write a brief: next-session, or gap for a lane")
    br.add_argument("kind", choices=("next-session", "gap"))
    br.add_argument("--lane", default="web")
    br.add_argument("--stdout", action="store_true", help="also print it")
    sp.add_parser("recover", help="restore state.json from state.json.prev")


def _profile(args):
    return _event.load(args.event) if args.event else _event.current()


def _campaign_for(args) -> _campaign.Campaign:
    slug = args.event
    if slug is None:
        try:
            slug = _event.current().slug
        except _event.EventError:
            slug = None       # CTF_WORKDIR alone is enough to locate the campaign; briefs say "-"
    return _campaign.Campaign(_paths.workdir(slug) if args.event else _paths.workdir(), event=slug)


def _status(camp: _campaign.Campaign, as_json: bool) -> int:
    lost = camp.reconcile()
    st = camp.load()
    if as_json:
        print(json.dumps({"rev": st["rev"], "event": st.get("event"), "newly_lost": lost,
                          "goals": st["goals"], "agents": st["agents"],
                          "relaunch": [{k: v for k, v in x.items() if k != "record"} for x in camp.relaunch_list(st)]},
                         sort_keys=True))
        return 0
    print(f"campaign rev {st['rev']}  ({camp.state_path})")
    for g in _campaign._live_goals(st):
        print(f"  goal {g['id']:<20} {g['status']:<8} next: {g.get('next') or 'NOT SET'}")
    for aid, a in sorted(st["agents"].items()):
        print(f"  agent {aid:<19} {a['status']:<8} {a['harness']} launch {a.get('launches', 1)}"
              + (f" ({a['lost_reason']})" if a["status"] == "lost" and a.get("lost_reason") else ""))
    for aid in lost:
        print(f"LOST: agent {aid} (see `python -m ctf campaign resume`)")
    return 0


def _hook_stop_active() -> bool:
    """Claude Code passes {"stop_hook_active": true} when a Stop hook already blocked once."""
    if sys.stdin is None or sys.stdin.isatty():
        return False
    try:
        data = json.loads(sys.stdin.read() or "{}")
    except (ValueError, OSError):
        return False
    return bool(isinstance(data, dict) and data.get("stop_hook_active"))


def run(args: argparse.Namespace) -> int:
    try:
        camp = _campaign_for(args)
        a = args.action
        if a == "status":
            return _status(camp, args.json)
        if a == "goal":
            ga = args.goal_action
            if ga == "add":
                camp.add_goal(args.id, args.title, challenge=args.challenge, lane=args.lane,
                              next_step=args.next_step, by=args.by)
                print(f"goal {args.id} added")
            elif ga == "checkpoint":
                camp.checkpoint(args.id, args.note, next_step=args.next_step, by=args.by, agent=args.agent)
                print(f"goal {args.id} checkpointed")
            elif ga == "set":
                g = camp.set_goal_status(args.id, args.status, blocker=args.blocker, note=args.note,
                                         next_step=args.next_step, by=args.by)
                print(f"goal {args.id} is {g['status']}")
            else:
                st = camp.load()
                if args.json:
                    print(json.dumps(st["goals"], sort_keys=True))
                else:
                    for g in sorted(st["goals"].values(), key=lambda g: g["id"]):
                        print(f"{g['id']:<20} {g['status']:<8} {g.get('challenge') or '-':<10} {g['title']}")
            return 0
        if a == "launch":
            cmd = list(args.command)
            if cmd and cmd[0] == "--":
                cmd = cmd[1:]
            rec = camp.launch(args.agent, cmd, harness=args.harness, cwd=args.cwd, challenge=args.challenge,
                              goal=args.goal, prompt_file=args.prompt_file, scratch=not args.no_scratch)
            print(f"agent {args.agent} launch {rec['launches']} started (supervisor pid {rec['supervisor_pid']}, "
                  f"log {rec['log']})" + (f", scratch {rec['scratch']}" if rec.get("scratch") else ""))
            return 0
        if a == "register":
            camp.register(args.agent, args.harness, challenge=args.challenge, goal=args.goal, note=args.note)
            print(f"agent {args.agent} registered; heartbeat at least every "
                  f"{_campaign.STALE_HEARTBEAT_SECONDS // 60} min or it is marked lost")
            return 0
        if a == "heartbeat":
            camp.heartbeat(args.agent, args.note)
            return 0
        if a == "agent-done":
            changed = camp.finish(args.agent, args.status, note=args.note)
            print(f"agent {args.agent}: {args.status}" if changed else f"agent {args.agent}: already finished")
            return 0
        if a == "resume":
            lost = camp.reconcile()
            for aid in lost:
                print(f"LOST: agent {aid}", file=sys.stderr)
            rc = 0
            if args.relaunch:
                for x in camp.relaunch_list(include_failed=args.include_failed, max_launches=args.max_launches):
                    if not x["eligible"]:
                        print(f"not relaunched: {x['agent']}: {x['reason']}", file=sys.stderr)
                        rc = 1
                        continue
                    try:
                        rec = camp.relaunch(x["agent"], include_failed=args.include_failed,
                                            max_launches=args.max_launches)
                        print(f"relaunched {x['agent']} (launch {rec['launches']})", file=sys.stderr)
                    except _campaign.CampaignError as e:
                        print(f"not relaunched: {x['agent']}: {e}", file=sys.stderr)
                        rc = 1
            camp.refresh_resume()
            if not args.quiet:
                sys.stdout.write(camp.resume_path.read_text(encoding="utf-8"))
            return rc
        if a == "relaunch":
            rec = camp.relaunch(args.agent, include_failed=args.include_failed, max_launches=args.max_launches)
            print(f"relaunched {args.agent} (launch {rec['launches']}, log {rec['log']})")
            return 0
        if a == "end":
            try:
                prof = _profile(args)
            except _event.EventError:
                prof = None   # gap briefs then point at the event's AGENTS.md instead of quoting rules
            for path in camp.end_session(args.summary, by=args.by or getpass.getuser(), profile=prof):
                print(path)
            return 0
        if a == "check":
            problems = camp.check()
            if not problems:
                if not camp.state_path.exists():
                    print(f"campaign: no campaign in {camp.workdir} yet; nothing to resume", file=sys.stderr)
                return 0
            for p in problems:
                print(f"campaign: {p}", file=sys.stderr)
            if args.hook:
                if _hook_stop_active():
                    return 0          # blocked once already; never trap the session in a loop
                print("campaign: before stopping, run `python -m ctf campaign end --summary ...`",
                      file=sys.stderr)
                return 2
            return 1
        if a == "brief":
            prof = _profile(args) if args.kind == "gap" else None
            path = camp.write_brief(args.kind, lane=args.lane, profile=prof)
            if args.stdout:
                sys.stdout.write(path.read_text(encoding="utf-8"))
            else:
                print(path)
            return 0
        if a == "recover":
            print(camp.recover())
            return 0
        raise _campaign.CampaignError(f"unknown action {a!r}")
    except (_campaign.CampaignError, _scratch.ScratchError, _event.EventError) as e:
        print(f"ctf campaign: {e}", file=sys.stderr)
        return 2
