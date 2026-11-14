"""Saved per-challenge evidence, read from the workdir (ctf.workspace layout + the event ledger).

    evs = evidence.collect(workdir)           # [ChallengeEvidence], sorted by challenge id
    evidence.known_values(evs, records)       # every flag value seen: confirmed, tried, ledger

Workdir layout (ctf/workspace.py): <workdir>/<id>-<slug>/ with challenge.json (the platform detail),
files/ (handouts: listed, never read or copied), notes.md (the solve log), tried.json (attempts and
verdicts), flag.txt (the confirmed flag), plus any solver scripts the player or an agent saved at the
top of the folder. The ledger is <workdir>/ledger.jsonl (ctf/ledger.py): engine.run, platform.submit,
spend, stop, budget_extend, ... records carrying challenge_id.

Everything here is data from challenge folders: it is read, never executed, and never followed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .. import ledger as _ledger

SCRIPT_SUFFIXES = (".py", ".sage", ".sh", ".c", ".cpp", ".rs", ".go", ".js", ".ts", ".rb", ".pl",
                   ".php", ".java", ".ps1", ".lua", ".gdb", ".r2", ".txt", ".md")
SCRIPT_MAX_BYTES = 256 * 1024
# Workspace bookkeeping: never a solver script, never copied out.
RESERVED = frozenset({"challenge.json", "notes.md", "tried.json", "flag.txt", "writeup.md",
                      "ledger.jsonl", "README.md"})
ACCEPTED = frozenset({"correct", "already_solved"})


class EvidenceError(ValueError):
    """The workdir or one of its records cannot be read (named in the message)."""


@dataclass(frozen=True)
class Attempt:
    value: str
    status: str


@dataclass
class ChallengeEvidence:
    cid: str
    name: str
    category: str
    points: int | float | None
    description: str
    dir: Path
    files: list[tuple[str, int]] = field(default_factory=list)
    notes: str = ""
    writeup_md: str = ""          # a workspace writeup.md an agent kept while solving
    flag: str | None = None
    attempts: list[Attempt] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)
    scripts: list[Path] = field(default_factory=list)

    @property
    def folder(self) -> str:
        return self.dir.name

    @property
    def accepted(self) -> bool:
        """The platform accepted a flag (a platform.submit record), or the attempt log says so."""
        if any(r.get("event") == "platform.submit" and r.get("status") in ACCEPTED for r in self.records):
            return True
        return any(a.status in ACCEPTED for a in self.attempts)

    @property
    def solved(self) -> bool:
        return self.flag is not None or self.accepted

    @property
    def wrong(self) -> int:
        from_ledger = sum(1 for r in self.records
                          if r.get("event") == "platform.submit" and r.get("status") == "incorrect")
        from_tried = sum(1 for a in self.attempts if a.status == "incorrect")
        return max(from_ledger, from_tried)

    @property
    def rejected_values(self) -> list[str]:
        return [a.value for a in self.attempts if a.status == "incorrect"]

    def engine_runs(self) -> list[dict]:
        return [r for r in self.records if r.get("event") == "engine.run"]

    @property
    def spend_usd(self) -> float:
        return sum(float(r.get("usd") or 0.0) for r in self.records if r.get("event") == "spend")

    @property
    def status_line(self) -> str:
        if self.accepted:
            return "Solved: the platform accepted the flag."
        if self.flag is not None:
            return "Solved: flag recorded (no platform acceptance on record)."
        if self.attempts or self.records or self.notes.strip():
            return f"Unsolved: attempted, {self.wrong} wrong submission(s)."
        return "Not attempted."


def _read_json(p: Path, default):
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        raise EvidenceError(f"{p}: not valid JSON: {e}") from None


def _text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def _cid_of(detail: dict, folder: str) -> str:
    if isinstance(detail, dict) and detail.get("id") not in (None, ""):
        return str(detail["id"])
    return folder.split("-", 1)[0]


def read_records(workdir: Path) -> list[dict]:
    try:
        return list(_ledger.read(workdir))
    except ValueError as e:
        raise EvidenceError(str(e)) from None


def load_challenge(d: Path, records: list[dict] | None = None) -> ChallengeEvidence:
    detail = _read_json(d / "challenge.json", None)
    if not isinstance(detail, dict):
        raise EvidenceError(f"{d}: challenge.json is missing or not an object")
    cid = _cid_of(detail, d.name)
    files = []
    fd = d / "files"
    if fd.is_dir():
        for f in sorted(fd.rglob("*")):
            if f.is_file() and not f.is_symlink():
                files.append((f.relative_to(fd).as_posix(), f.stat().st_size))
    tried = _read_json(d / "tried.json", {"attempts": []})
    attempts = []
    for a in (tried.get("attempts", []) if isinstance(tried, dict) else []):
        if isinstance(a, dict) and isinstance(a.get("flag"), str):
            attempts.append(Attempt(a["flag"], str(a.get("status", ""))))
    flag_txt = _text(d / "flag.txt").strip()
    scripts = sorted(p for p in d.iterdir()
                     if p.is_file() and not p.is_symlink() and p.name not in RESERVED
                     and not p.name.startswith(".") and p.suffix.lower() in SCRIPT_SUFFIXES
                     and p.stat().st_size <= SCRIPT_MAX_BYTES)
    mine = [r for r in (records or []) if str(r.get("challenge_id", "")) == cid]
    points = detail.get("value")
    return ChallengeEvidence(
        cid=cid, name=str(detail.get("name") or cid), category=str(detail.get("category") or "uncategorized"),
        points=points if isinstance(points, (int, float)) and not isinstance(points, bool) else None,
        description=str(detail.get("description") or ""), dir=d, files=files, notes=_text(d / "notes.md"),
        writeup_md=_text(d / "writeup.md"),
        flag=flag_txt or None, attempts=attempts, records=mine, scripts=scripts)


def _sort_key(e: ChallengeEvidence):
    return (0, int(e.cid), e.cid) if e.cid.isdigit() else (1, 0, e.cid)


def collect(workdir: Path, records: list[dict] | None = None) -> list[ChallengeEvidence]:
    """Every challenge folder (a subfolder holding challenge.json) under `workdir`."""
    workdir = Path(workdir)
    if not workdir.is_dir():
        raise EvidenceError(f"workdir {workdir} does not exist (set CTF_WORKDIR or pass --workdir)")
    if records is None:
        records = read_records(workdir)
    out = [load_challenge(d, records) for d in sorted(workdir.iterdir())
           if d.is_dir() and not d.name.startswith((".", "_")) and (d / "challenge.json").is_file()]
    return sorted(out, key=_sort_key)


def known_values(evs: list[ChallengeEvidence], records: list[dict] = ()) -> set[str]:
    """Every flag value on record: confirmed flags, every attempt (accepted or rejected), and the
    flag fields of ledger records (written only when the event allows sharing)."""
    vals: set[str] = set()
    for e in evs:
        if e.flag:
            vals.add(e.flag)
        vals.update(a.value for a in e.attempts)
    for r in records:
        for k in ("flag", "candidate"):
            v = r.get(k)
            if isinstance(v, str) and v.strip():
                vals.add(v.strip())
    return {v for v in vals if v}


def known_hashes(records: list[dict] = ()) -> set[str]:
    """The `flag_sha256` of every ledger record that has one: an event that forbids sharing records the
    submitted value only as its hash (ctf/platform/rules.py), so the scanner matches tokens against
    these. A malformed hash is a damaged ledger and fails by name."""
    out: set[str] = set()
    for r in records:
        h = r.get("flag_sha256")
        if h is None:
            continue
        if not isinstance(h, str) or len(h.strip()) != 64 or any(c not in "0123456789abcdef"
                                                                  for c in h.strip().lower()):
            raise EvidenceError(f"ledger record {r.get('event', '?')} for challenge {r.get('challenge_id', '?')}: "
                                "flag_sha256 is not a sha256 hex digest")
        out.add(h.strip().lower())
    return out
