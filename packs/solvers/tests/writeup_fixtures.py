"""Synthetic event profiles and workdirs for the B-098 writeup pipeline tests (no real event data)."""
from __future__ import annotations

import json
from pathlib import Path

from ctf import event

FLAG = "ZZ{" + "s3cr3t_v4lue_42" + "}"         # the confirmed flag of challenge 7
WRONG = "zz{" + "wr0ng_guess_77" + "}"           # a rejected candidate (lower-case prefix)
BARE = "h4sh3d_p4ssw0rd"                         # a rejected bare (unwrapped) candidate
FLAG9 = "ZZ{" + "second_flag_99" + "}"           # challenge 9's flag


def profile(root: Path, *, slug="zz", prefixes=("ZZ",), sharing="forbidden", redact=True, hold=True,
            repo=None, end="2026-01-02", scope=("*.inst.zz.example",), base="https://ctf.zz.example"):
    text = (f'slug = "{slug}"\nname = "ZZ CTF"\ndates = {{ start = 2026-01-01, end = {end} }}\n'
            f'[platform]\nkind = "ctfd"\nbase_url = "{base}"\n'
            f'[flag]\nprefixes = {json.dumps(list(prefixes))}\n'
            f'[rules]\nsubmit_mode = "confirm"\nflag_sharing = "{sharing}"\nai_on_platform = "allowed"\n'
            f'live_service_scope = {json.dumps(list(scope))}\n'
            f'[writeups]\nredact_flags = {str(redact).lower()}\npublish_hold = {str(hold).lower()}\n')
    if repo:
        text += f'public_repo = "{repo}"\n'
    d = Path(root) / "events" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "event.toml").write_text(text)
    return event.load(slug, root=Path(root) / "events")


def ledger(wd: Path, records: list[dict]) -> None:
    with open(wd / "ledger.jsonl", "a") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")


def workdir(root: Path, *, notes_extra: str = "") -> Path:
    """Two challenges: 7 solved (flag, a rejected candidate, a solver script, ledger records), 9
    attempted and unsolved; plus a folder without challenge.json that must be ignored."""
    wd = Path(root) / "wd"
    c7 = wd / "7-glitch"
    (c7 / "files").mkdir(parents=True)
    (c7 / "challenge.json").write_text(json.dumps({
        "id": 7, "name": "Glitch", "category": "Stego", "value": 100,
        "description": "Find the hidden thing.", "connection_info": "nc chal.inst.zz.example 31337"}))
    (c7 / "files" / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 10)
    (c7 / "notes.md").write_text(f"lsb plane 0 gave {FLAG}\nfirst tried {WRONG} and {BARE}\n"
                                 f"inner part {FLAG[3:-1].upper()} seen again\n{notes_extra}")
    (c7 / "flag.txt").write_text(FLAG + "\n")
    (c7 / "tried.json").write_text(json.dumps({"attempts": [
        {"flag": WRONG, "status": "incorrect", "t": 1.0},
        {"flag": BARE, "status": "incorrect", "t": 2.0},
        {"flag": FLAG, "status": "correct", "t": 3.0}]}))
    (c7 / "solve.py").write_text(f"print('{FLAG}')\n")
    (c7 / "README.md").write_text("workspace readme: not a script\n")
    c9 = wd / "9-other"
    c9.mkdir()
    (c9 / "challenge.json").write_text(json.dumps({"id": 9, "name": "Other | pipe", "category": "Crypto",
                                                   "value": 300, "description": ""}))
    (c9 / "tried.json").write_text(json.dumps({"attempts": [{"flag": "ZZ{nope_one}", "status": "incorrect"}]}))
    (wd / "junk").mkdir()
    ledger(wd, [
        {"ts": 1767225600.0, "event": "engine.run", "engine": "stego.lsb", "via": "ctf-run", "exit_code": 0,
         "seconds": 2.5, "status": "solved", "challenge_id": "7"},
        {"ts": 1767225660.0, "event": "spend", "challenge_id": "7", "usd": 1.5, "tok": 1200},
        {"ts": 1767225720.0, "event": "platform.submit", "challenge_id": "7", "status": "incorrect",
         "judged": True, "flag_sha256": "0" * 64, "provenance": f"guess {WRONG}"},
        {"ts": 1767226200.0, "event": "platform.submit", "challenge_id": "7", "status": "correct",
         "judged": True, "flag_sha256": "1" * 64},
        {"ts": 1767225700.0, "event": "engine.run", "engine": "crypto.rsa", "via": "ctfpy", "exit_code": 0,
         "seconds": 9.0, "status": "none", "challenge_id": "9"},
        {"ts": 1767229000.0, "event": "spend", "challenge_id": "9", "usd": 4.0, "tok": 5000},
        {"ts": 1767229300.0, "event": "stop", "challenge_id": "9", "reason": "manual", "by": "player"},
        # outside a 2026-01-01 day window
        {"ts": 1767312000.0 + 3600, "event": "spend", "challenge_id": "9", "usd": 100.0, "tok": 1},
    ])
    return wd
