#!/usr/bin/env python3
"""Discord recon for a challenge whose flag is in the event's Discord server: ranks the flag and recognition-word candidates of the captured server snapshot for this challenge, offline (B-112).

A "flag is somewhere on the Discord" challenge has no file and no target, so intake had nothing to
run and an agent could only ask the player for screenshots. This engine reads the event's Discord
snapshot (`<workdir>/discord/snapshot.json`: what the player pasted or exported, or what the cleared
bot captured; see `python -m ctf discord`) and ranks its candidates for the challenge it is given: the
challenge's own words pick the items that talk about it, and a value quoted in the brief or shown as
a format example is marked a decoy.

    python -m ctf run toolkits.osint_discord <challenge_dir> [--opt flags=true] [--opt card=false]

Results (`solve(challenge_dir, profile, **opts) -> SolverResult`):

  blocked  no snapshot yet. Reading the server is a human step, so the engine puts one `discord` task
           card for the challenge on the player's list (`python -m ctf human cards`; opt card=false
           turns that off) and names the commands in its notes. The card is opened only for a
           challenge that lives in the server: tagged discord, or with no handout and no target. A
           brief that merely says "ask on Discord" gets the note, not a card.
  none     the snapshot holds no candidate.
  unsure   candidates exist and are written to `<challenge>/recon/discord.md`. The result carries NO
           flag: one server holds the flags of several challenges and a rules page shows format
           examples, so a Discord flag is never attributed to a challenge by a machine. (Intake merges
           an engine's flags and would submit a lone one under `--submit`.)
  candidate  only with opt flags=true, for a caller that asks for the values: the event-format flags,
           best first, decoys last.

Opts: snapshot=PATH (another snapshot file), flags=true, card=false, decode=false (skip the codec
graph). It opens no connection and reads only the snapshot and the challenge's challenge.json.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

ENGINE = "toolkits.osint_discord"
MAX_FLAGS = 12


def _truthy(v, default: bool) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def solve(challenge_dir: Path, profile, **opts):
    from ctf import discordrecon as dr
    from ctf import paths
    from ctf.result import Cost, Evidence, SolverResult

    t0 = time.process_time()
    challenge_dir = Path(challenge_dir)
    unknown = set(opts) - {"snapshot", "flags", "card", "decode"}
    if unknown:
        return SolverResult("blocked", engine=ENGINE,
                            notes=f"unknown option(s): {', '.join(sorted(unknown))} (snapshot, flags, card, decode)")
    try:
        ch = dr.read_challenge(challenge_dir)
    except dr.DiscordReconError as e:
        return SolverResult("blocked", engine=ENGINE, notes=str(e))
    cid = ch["id"]
    workdir = paths.workdir(profile.slug)
    if opts.get("snapshot"):
        try:            # checked before the path is even looked at: the app's folder is never an input
            snap_path = dr.refuse_app_data(opts["snapshot"])
        except dr.DiscordReconError as e:
            return SolverResult("blocked", engine=ENGINE, challenge_id=cid, notes=str(e))
    else:
        snap_path = dr.snapshot_path(workdir)
    if not snap_path.exists():
        note = (f"no Discord snapshot for event {profile.slug} at {snap_path}: reading the server is a human "
                f"step. Run `python -m ctf discord checklist --challenge {cid}`, hand the text over with "
                "`python -m ctf discord ingest`, then run this engine again")
        if not ch["discord_only"]:
            # "ask on Discord if stuck" in a challenge with a handout or a target is not a request to
            # read the server: no card, so the player's list holds only real asks.
            if ch["bare"] is None:
                why = "the challenge has no challenge.json"
            elif ch["bare"]:
                why = ("the challenge is not tagged discord and its brief does not point into the server (no "
                       "sentence names Discord beside a recon cue without a help word)")
            else:
                why = "the challenge has files or a target and is not tagged discord"
            note += (f". No task card was opened: {why}. If its flag is in the server: "
                     f"`python -m ctf discord checklist --challenge {cid} --card`")
        elif _truthy(opts.get("card"), True):
            try:
                card, created = dr.request_card(profile, cid, name=ch["name"], workdir=workdir)
                note += f". Task card {card.id} {'opened' if created else 'is already open'} for the player"
            except (ValueError, OSError) as e:      # HumanOpsError is a ValueError
                note += f". The task card could not be opened ({e}): run `python -m ctf human add-card discord`"
        return SolverResult("blocked", engine=ENGINE, challenge_id=cid, notes=note)
    try:
        snap = dr.load(snap_path)
        rep, out = dr.analyze_challenge(snap, profile, challenge_dir, decode=_truthy(opts.get("decode"), True))
    except dr.DiscordReconError as e:
        return SolverResult("blocked", engine=ENGINE, challenge_id=cid, notes=str(e))
    cost = Cost(seconds=round(time.process_time() - t0, 3))
    rel = out.relative_to(challenge_dir).as_posix()
    if not rep.candidates:
        return SolverResult("none", engine=ENGINE, challenge_id=cid, cost=cost,
                            notes=f"no candidate among {rep.items} snapshot item(s); the report ({rel}) lists "
                                  "the acrostic readings and what the capture could not read")
    kinds: dict[str, int] = {}
    for c in rep.candidates:
        kinds[c.kind] = kinds.get(c.kind, 0) + 1
    summary = ", ".join(f"{n} {k}" for k, n in kinds.items())
    # The evidence and notes name places and kinds, never a value: intake scans this output for flags.
    evidence = [Evidence("match", f"{c.kind} in {c.where}: {c.how.split(';')[0]}"[:200], path=rel)
                for c in rep.candidates[:8] if not profile_flags(profile, f"{c.where} {c.how}")]
    if _truthy(opts.get("flags"), False):
        flags = rep.flags(decoys=True)[:MAX_FLAGS]
        if flags:
            return SolverResult("candidate", flags=flags, evidence=evidence, engine=ENGINE, challenge_id=cid,
                                cost=cost, notes=f"{summary}; ranked in {rel}. Not attributed to this challenge "
                                                 "by the engine: read where each came from before submitting")
    return SolverResult("unsure", evidence=evidence, engine=ENGINE, challenge_id=cid, cost=cost,
                        notes=f"{len(rep.candidates)} Discord candidate(s) ({summary}) ranked in {rel}. No value "
                              "is returned: a Discord flag is not attributed to a challenge automatically. Read "
                              "the report, then submit the one that answers this challenge through the gate")


def profile_flags(profile, text: str) -> list[str]:
    """The event-format flags in `text` (used to keep values out of the result's evidence lines)."""
    from ctf import flagfmt
    return flagfmt.for_profile(profile).find_flags(text)


def main(argv=None) -> int:
    from ctf import event
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1 or argv[0] in ("-h", "--help"):
        print(__doc__, file=sys.stderr)
        return 2
    print(solve(Path(argv[0]), event.current()).to_json(indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
