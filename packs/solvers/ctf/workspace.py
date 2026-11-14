"""Per-challenge working folders under $CTF_WORKDIR (default ./workspace, git-ignored).

    workspace/<id>-<slug>/
        challenge.json    the CTFd detail as pulled (description, category, value, connection_info)
        files/            downloaded attachments (treat as UNTRUSTED input: analyse, never execute on the host)
        notes.md          running notes for the write-up (the podium write-up is due 24 h after close)
        tried.json        flags already submitted for this challenge, and their verdicts (dedupe + the 3-wrong guard)
        flag.txt          the confirmed flag, once solved

Downloaded files are untrusted: the solver analyses them and only ever detonates/executes them inside
the Docker sandbox (tools/sandbox.py), never on the Mac.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from . import config as _config

# Verdicts CTFd returns without judging the flag. Such an attempt neither blocks a re-send nor counts as
# a wrong answer, nor spends a post-guard approval.
UNJUDGED_STATUSES = frozenset({"ratelimited", "paused", "authentication_required"})


def slug(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s[:48] or "challenge"


def dir_name(cid, name: str) -> str:
    """`<id>-<slug of name>`: the challenge folder's name, for `ctf pull` and `ctf intake` alike."""
    return f"{cid}-{slug(name)}"


@dataclass
class Challenge:
    cid: int
    name: str
    category: str
    dir: Path

    @property
    def files_dir(self) -> Path:
        return self.dir / "files"

    @property
    def tried_path(self) -> Path:
        return self.dir / "tried.json"

    @property
    def flag_path(self) -> Path:
        return self.dir / "flag.txt"

    @property
    def notes_path(self) -> Path:
        return self.dir / "notes.md"

    def load_tried(self) -> dict:
        try:
            return json.loads(self.tried_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"attempts": []}

    def record_attempt(self, flag: str, status: str) -> None:
        data = self.load_tried()
        data["attempts"].append({"flag": flag, "status": status, "t": time.time()})
        self.tried_path.write_text(json.dumps(data, indent=1), encoding="utf-8")

    def already_tried(self, flag: str) -> bool:
        # A ratelimited/paused/auth-failed attempt was never judged by CTFd, so it must not block a re-send.
        return any(a["flag"] == flag and a.get("status") not in UNJUDGED_STATUSES
                   for a in self.load_tried().get("attempts", []))

    def wrong_count(self) -> int:
        return sum(1 for a in self.load_tried().get("attempts", []) if a["status"] == "incorrect")

    # Player approvals past the wrong-answer guard. Kept in tried.json next to the attempts they unlock,
    # so the record is per challenge, counted (each grant allows `count` sends), and auditable.
    def grant_post_guard_approval(self, reason: str, count: int = 1) -> None:
        """Record that the player approved `count` more reasoned submissions on THIS challenge after the
        wrong-answer guard stopped it. `reason` must say who approved and why (it goes into the write-up)."""
        reason = (reason or "").strip()
        if not reason:
            raise ValueError("a post-guard approval needs a reason naming the player's decision")
        if int(count) < 1:
            raise ValueError("a post-guard approval must allow at least one submission")
        data = self.load_tried()
        data.setdefault("approvals", []).append(
            {"kind": "grant", "count": int(count), "reason": reason, "t": time.time()})
        self.tried_path.write_text(json.dumps(data, indent=1), encoding="utf-8")
        self.note(f"- PLAYER APPROVAL recorded: {int(count)} post-guard submission(s) ({reason})")

    def post_guard_approvals_left(self) -> int:
        recs = self.load_tried().get("approvals", [])
        granted = sum(int(r.get("count", 0)) for r in recs if r.get("kind") == "grant")
        used = sum(1 for r in recs if r.get("kind") == "use")
        return max(0, granted - used)

    def consume_post_guard_approval(self, flag: str, provenance: str = "") -> None:
        if self.post_guard_approvals_left() < 1:
            raise ValueError("no unused post-guard approval on this challenge")
        data = self.load_tried()
        data.setdefault("approvals", []).append(
            {"kind": "use", "flag": flag, "provenance": provenance, "t": time.time()})
        self.tried_path.write_text(json.dumps(data, indent=1), encoding="utf-8")

    def mark_solved(self, flag: str) -> None:
        self.flag_path.write_text(flag + "\n", encoding="utf-8")

    def solved(self) -> bool:
        return self.flag_path.exists()

    def note(self, line: str) -> None:
        with open(self.notes_path, "a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")


def root(cfg: _config.Config | None = None) -> Path:
    cfg = cfg or _config.load()
    cfg.workdir.mkdir(parents=True, exist_ok=True)
    return cfg.workdir


def for_challenge(detail: dict, cfg: _config.Config | None = None) -> Challenge:
    cfg = cfg or _config.load()
    cid = int(detail["id"])
    name = detail.get("name", str(cid))
    d = root(cfg) / dir_name(cid, name)
    (d / "files").mkdir(parents=True, exist_ok=True)
    ch = Challenge(cid=cid, name=name, category=detail.get("category", "?"), dir=d)
    (d / "challenge.json").write_text(json.dumps(detail, indent=1), encoding="utf-8")
    if not ch.notes_path.exists():
        conn = detail.get("connection_info") or ""
        ch.note(f"# {name}  [{ch.category}]  ({detail.get('value','?')} pts)\n")
        if conn:
            ch.note(f"target: {conn}\n")
        desc = (detail.get("description") or "").strip()
        if desc:
            ch.note("## description\n\n" + desc + "\n")
    return ch
