"""ctf research — the shared research cache: look a question up once per event (B-199, ctf.research).

    python -m ctf research get "<query or URL>" [--claim]     print a stored answer
    python -m ctf research put "<query or URL>" --answer TEXT | --answer-file F [--source URL]... [--replace]
    python -m ctf research claim "<query or URL>"             say you are looking it up now
    python -m ctf research release "<query or URL>"           drop your claim (you gave up)
    python -m ctf research list                               every stored answer, newest first
    python -m ctf research key "<query or URL>"               the normalized key (what matches what)

Nothing here fetches anything: it stores what an agent found with its own tools, so the next agent
asking the same thing reads it instead of fetching again. The store is `<workdir>/research/` of the
current event ($CTF_WORKDIR, else ~/ctf-work/<CTF_EVENT>); `--dir DIR` overrides. The agent name is
`--agent`, else $CTF_AGENT, else "agent".

Exit codes: 0 hit / stored / claimed / released; 1 miss (with --claim: you now hold the claim, look it
up and `put` it), or `release` of a key you hold no claim on; 2 error (an empty or refused key, a refused or oversized answer, an existing answer
without --replace, an unreadable store, no event selected); 3 another agent holds a fresh claim (it
is looking this up now: do other work and ask again, do not fetch in parallel).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import hygiene, readmap, research
from ..event import EventError

HELP = "shared research cache: get/put/claim answers by normalized query or URL, one look-up per event (B-199)"

HELD_EXIT = 3


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dir", type=Path, default=None, help="the research store (default: <workdir>/research)")
    p.add_argument("--agent", default=None, help="who is asking (default: $CTF_AGENT, else 'agent')")
    sp = p.add_subparsers(dest="action", required=True)
    g = sp.add_parser("get", help="print the stored answer (exit 1 on a miss, 3 when another agent holds it)")
    g.add_argument("text", help="the query or document URL")
    g.add_argument("--claim", action="store_true", help="on a miss, claim it (you then look it up and put it)")
    g.add_argument("--max-tokens", type=int, default=hygiene.CAP_TOKENS, help="cap the printed answer")
    pu = sp.add_parser("put", help="store an answer (releases your claim)")
    pu.add_argument("text", help="the query or document URL")
    src = pu.add_mutually_exclusive_group(required=True)
    src.add_argument("--answer", help="the answer: a summary with what matters, not a whole page")
    src.add_argument("--answer-file", type=Path, help="read the answer from this file")
    pu.add_argument("--source", action="append", default=[], help="a source URL (repeatable)")
    pu.add_argument("--replace", action="store_true", help="overwrite an answer already stored")
    c = sp.add_parser("claim", help="claim a key you are about to look up (exit 3 when another agent holds it)")
    c.add_argument("text")
    r = sp.add_parser("release", help="drop your claim on a key")
    r.add_argument("text")
    sp.add_parser("list", help="every stored answer, newest first")
    k = sp.add_parser("key", help="print the normalized key")
    k.add_argument("text")


def _err(msg: str, code: int = 2) -> int:
    print(f"ctf research: {msg}", file=sys.stderr)
    return code


def _held(claim: research.Claim) -> int:
    print(f"ctf research: {claim.agent} is looking this up now (claimed {claim.age():.0f} s ago); do other "
          f"work and ask again, do not fetch it in parallel", file=sys.stderr)
    return HELD_EXIT


def run(args: argparse.Namespace) -> int:
    agent = args.agent or readmap.agent_id()
    try:
        if args.action == "key":
            print(research.normalize(args.text))
            return 0
        cache = research.Cache(args.dir if args.dir is not None else research.default_root())
        if args.action == "get":
            if args.max_tokens <= 0:
                return _err(f"--max-tokens must be positive, got {args.max_tokens}")
            got = cache.lookup(args.text, agent=agent, claim=args.claim)
            if got.status == "hit":
                e = got.entry
                print(f"[ctf research: answered by {e.agent} at {research._iso(e.at)}; key {e.key}]")
                print(f"asked: {e.asked}")       # the stored question, so a near-miss key is visible
                print(hygiene.cap_text(e.answer, max_tokens=args.max_tokens).render())
                for s in e.sources:
                    print(f"source: {s}")
                return 0
            if got.status == "held":
                return _held(got.claim)
            if got.status == "claimed":
                print(f"ctf research: miss; you ({agent}) now hold the claim on {got.key}. Look it up, then "
                      f"`ctf research put` it (or `ctf research release` it).", file=sys.stderr)
                return 1
            print(f"ctf research: miss ({got.key}); pass --claim before you look it up", file=sys.stderr)
            return 1
        if args.action == "put":
            if args.answer_file is not None:
                try:
                    answer = args.answer_file.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError) as e:
                    return _err(f"cannot read --answer-file {args.answer_file}: {e}")
            else:
                answer = args.answer
            e = cache.put(args.text, answer, sources=args.source, agent=agent, replace=args.replace)
            print(f"stored {e.key} ({len(answer.encode('utf-8'))} bytes) in {cache.root}")
            return 0
        if args.action == "claim":
            try:
                cl = cache.claim(args.text, agent=agent)
            except research.ClaimHeld as e:
                return _held(e.claim)
            print(f"claimed {cl.key} for {agent}")
            return 0
        if args.action == "release":
            if cache.release(args.text, agent=agent):
                print(f"released {research.normalize(args.text)}")
                return 0
            return _err(f"{agent} holds no claim on {research.normalize(args.text)}", 1)
        if args.action == "list":
            rows = [f"{research._iso(e.at)}  {e.agent:<12}  {e.key}" for e in cache.entries()]
            print(hygiene.cap_text("\n".join(rows) or "(no answers stored)").render())
            return 0
    except research.ResearchError as e:
        return _err(str(e))
    except (EventError, ValueError) as e:       # no event selected / bad slug (ctf.paths.workdir)
        return _err(f"no research store: {e} (set CTF_EVENT or CTF_WORKDIR, or pass --dir)")
    return _err(f"unknown action {args.action!r}")
