"""The manual-mode cockpit (B-209): the player's side of a manual event, kept on local disk.

On a manual event (platform.kind = "manual" or ai_on_platform = "forbidden") the player is the
only one who touches the platform: they download every file and submit every flag. At Spooky that
relay loop was the main cost, files landed in the wrong place, and the "what do you still need"
list got buried. The cockpit makes the loop mechanical and never touches the platform:

    drop-zone watcher   anything the player drops in <workdir>/inbox/ (or loose at the drop root,
                        or loose in a challenge folder) is filed into the manual adapter's drop
                        folder, <workdir>/drop/<id>/files/<file>, and checked: an empty file, a web
                        page saved under a binary name, a name that disagrees with the content, a
                        helper (Volatility symbols, TLS key log) whose capture is absent, a capture
                        the description promises that no file is.
    needs checklist     every open need, ordered, shown N at a time with the total always printed:
                        computed ones (no files yet, no description, each problem above) and ones
                        agents add (`need`), which resolve themselves when an --expect file lands.
    submission queue    agents queue a flag with its provenance (format, dedupe, wrong-answer stop
                        and guess budget checked first, queued guesses counting against the
                        budget); the player works through it and records accepted / rejected. The
                        rules are checked again before `next` serves an item and before a verdict:
                        an item they now refuse (a rejection since hit the stop) is "held" until the
                        player confirms it (`confirm`) or withdraws it; past the wrong-answer stop the
                        gate also needs the player's counted approval (B-006: `ctf submit-queue approve
                        <id> --reason ...`), so a confirmed item stays held until one is unused. Verdicts go to the ledger as platform.submit records,
                        so ctf/platform/rules.py counts them like any other submission. Accepted
                        writes the drop folder's SOLVED marker (the adapter's team_solves reads it):
                        only a recorded verdict ever writes it.

Layout under paths.workdir(<event>):

    inbox/                 the drop zone (or --inbox DIR)
    drop/<id>/             the manual adapter's challenge folder (ctf/platform/manual.py)
        challenge.toml     name, category, points, description, ... (the adapter's keys only)
        SOLVED             written on an accepted verdict; first line names the solver
        files/             the challenge's files
    cockpit/state.json     needs, the queue, the focus, dismissed checks (mode 0600; holds flags)
    cockpit/lock           flock for every read-modify-write (agents and the watcher share it)
    ledger.jsonl           cockpit.* records and platform.submit verdicts

Files are moved, not copied (Spooky's captures ran to 1 GB). Symlinks are never followed or moved.
Partial downloads (.crdownload, .part, ...) and files modified in the last `settle` seconds wait.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import time
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterator

from .. import flagfmt, ledger, paths
from ..event import EventProfile
from ..platform import PlatformError, SubmitResult, SubmitStatus, adapter_kind, get_adapter
from ..platform.manual import META, SOLVED
from ..platform.policy import SubmitRequest
from ..platform.rules import EventRules
from . import kinds as _kinds

SCHEMA = 1
FILES = "files"
DESCRIPTION_NAMES = ("description.txt", "description.md", "desc.txt", "desc.md", "description")
_ID_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PREFIXED = re.compile(r"^(?P<cid>[^_].*?)__(?P<rest>.+)$")
_META_STR = ("name", "category", "description", "connection_info")
NEED_KINDS = ("files", "redownload", "capture", "instance", "description", "other")
_PRIORITY = {k: i for i, k in enumerate(NEED_KINDS)}
_REDOWNLOAD = {"empty_file", "disguised_html", "extension_mismatch"}


class CockpitError(Exception):
    """A usage or configuration problem (exit 2)."""


class Refused(CockpitError):
    """A policy refusal: the queue or a verdict said no (exit 4)."""


@dataclass(frozen=True)
class Need:
    id: str            # "n<k>" for an added need; "<challenge>:<check>" for a computed one
    challenge: str
    kind: str          # one of NEED_KINDS
    text: str
    source: str        # "auto" (computed from the drop) | "added" (an agent or the player)
    created: float
    expect: str | None = None


@dataclass
class SweepReport:
    filed: list[dict] = field(default_factory=list)       # {src, challenge, rel, kind, detail, problems, how}
    duplicates: list[dict] = field(default_factory=list)  # {src, challenge, rel}: identical bytes, source removed
    waiting: list[dict] = field(default_factory=list)     # {src, reason}: partial or still being written
    unfiled: list[dict] = field(default_factory=list)     # {src, reason}: no challenge to file it under
    conflicts: list[dict] = field(default_factory=list)   # {src, challenge, rel}: a different file has the name
    refused: list[dict] = field(default_factory=list)     # {src, reason}: symlinks and other things never moved
    described: list[str] = field(default_factory=list)    # challenges whose description a dropped file set
    created: list[str] = field(default_factory=list)      # challenges a drop created

    def to_json(self) -> dict:
        return asdict(self)


def make_id(name: str) -> str:
    """A drop-folder id from a challenge name: runs of anything outside [A-Za-z0-9._-] become '-'."""
    cid = re.sub(r"[^A-Za-z0-9._-]+", "-", (name or "").strip()).strip("-._")[:128].rstrip("-._")
    if not _ID_OK.match(cid):
        raise CockpitError(f"cannot make a challenge id from {name!r}: give a name with letters or digits")
    return cid


def _key(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _toml_str(s: str) -> str:
    out = json.dumps(s, ensure_ascii=False)
    return out.replace("\x7f", "\\u007f")


def _toml_dump(data: dict) -> str:
    lines = []
    for k, v in data.items():
        if isinstance(v, bool):
            raise CockpitError(f"challenge.toml {k}: a boolean is not allowed")
        if isinstance(v, int):
            lines.append(f"{k} = {v}")
        elif isinstance(v, str):
            lines.append(f"{k} = {_toml_str(v)}")
        elif isinstance(v, list):
            lines.append(f"{k} = [{', '.join(_toml_str(str(x)) for x in v)}]")
        else:
            raise CockpitError(f"challenge.toml {k}: unsupported value {type(v).__name__}")
    text = "\n".join(lines) + "\n"
    if tomllib.loads(text) != data:
        raise CockpitError("challenge.toml did not round-trip; nothing written")
    return text


def _safe_rel(rel: str) -> str:
    """A name under files/: relative, no '..', no hidden part (files() would never show it)."""
    p = PurePosixPath(str(rel).replace("\\", "/"))
    if not str(rel).strip() or p.is_absolute() or any(part == ".." or part.startswith(".")
                                                       for part in p.parts):
        raise CockpitError(f"{rel!r} is not a plain name under files/ (no absolute path, no '..', "
                           "no hidden part)")
    return p.as_posix()


def _atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, text.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


class Cockpit:
    def __init__(self, profile: EventProfile, *, inbox: Path | None = None, settle: float = 2.0,
                 clock=time.time):
        if adapter_kind(profile) != "manual":
            raise CockpitError(f"event {profile.slug!r} is not manual (platform kind "
                               f"{profile.platform.kind!r}, ai_on_platform "
                               f"{profile.rules.ai_on_platform!r}): the cockpit is for events where the "
                               "player downloads and submits by hand; use `ctf pull` / `ctf submit`")
        self.profile = profile
        self.plat = get_adapter(profile)          # the manual adapter behind the gate: reads only
        self.workdir = paths.workdir(profile.slug)
        self.drop_dir = Path(self.plat.drop_dir)
        self.inbox = Path(inbox) if inbox is not None else self.workdir / "inbox"
        self.state_dir = self.workdir / "cockpit"
        self.settle = float(settle)
        self.clock = clock
        self.track_growth = False                  # watch mode: a file must look the same twice
        self._seen: dict[str, tuple[int, int]] = {}
        self._kind_cache: dict[tuple[str, int, int], _kinds.Kind] = {}
        self._depth = 0
        self._state: dict | None = None
        self._lockfd: int | None = None
        for d in (self.drop_dir, self.inbox, self.state_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ============================================================================ state + lock
    @property
    def state_path(self) -> Path:
        return self.state_dir / "state.json"

    def _blank(self) -> dict:
        return {"schema": SCHEMA, "event": self.profile.slug, "next": 1, "focus": None,
                "challenges": {}, "needs": [], "dismissed": [], "queue": []}

    def _read_state(self) -> dict:
        p = self.state_path
        if not p.exists():
            return self._blank()
        try:
            st = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise CockpitError(f"{p}: unreadable cockpit state ({e}); fix or move it aside") from None
        if st.get("schema") != SCHEMA:
            raise CockpitError(f"{p}: schema {st.get('schema')!r}, expected {SCHEMA}")
        if st.get("event") != self.profile.slug:
            raise CockpitError(f"{p}: belongs to event {st.get('event')!r}, not {self.profile.slug!r}; "
                               "each event needs its own workdir")
        return st

    @contextlib.contextmanager
    def _txn(self) -> Iterator[dict]:
        """Exclusive read-modify-write of the state (re-entrant in this object)."""
        if self._depth:
            self._depth += 1
            try:
                yield self._state
            finally:
                self._depth -= 1
            return
        fd = os.open(self.state_dir / "lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._state = self._read_state()
            before = json.dumps(self._state, sort_keys=True)
            self._depth = 1
            try:
                yield self._state
            finally:
                self._depth = 0
            after = json.dumps(self._state, sort_keys=True)
            if after != before:
                _atomic_write(self.state_path, json.dumps(self._state, indent=1, sort_keys=True), 0o600)
        finally:
            self._state = None
            os.close(fd)

    def _next_id(self, st: dict) -> int:
        n = int(st["next"])
        st["next"] = n + 1
        return n

    def _log(self, event: str, **fields) -> None:
        ledger.append(event, workdir=self.workdir, event_slug=self.profile.slug, **fields)

    def _flag_fields(self, flag: str) -> dict:
        if self.profile.rules.flag_sharing == "allowed":
            return {"flag": flag}
        return {"flag_sha256": hashlib.sha256(flag.encode("utf-8")).hexdigest()}

    # ============================================================================ challenges
    def challenge_ids(self) -> list[str]:
        return sorted(d.name for d in self.drop_dir.iterdir()
                      if d.is_dir() and not d.is_symlink() and _ID_OK.match(d.name))

    def folder(self, cid: str) -> Path:
        return self.drop_dir / cid

    def files_dir(self, cid: str) -> Path:
        return self.folder(cid) / FILES

    def meta(self, cid: str) -> dict:
        """challenge.toml, validated by the manual adapter (unknown keys and bad types raise)."""
        return dict(self.plat.get_challenge(cid).raw)

    def solved(self, cid: str) -> bool:
        m = self.folder(cid) / SOLVED
        return m.is_file() and not m.is_symlink()

    def resolve(self, name: str) -> str | None:
        """The challenge a name refers to: an exact id, else an id or challenge.toml name that is
        equal ignoring case and punctuation. Ambiguous is an error, never a guess."""
        ids = self.challenge_ids()
        if name in ids:
            return name
        k = _key(name)
        if not k:
            return None
        hits = set()
        for cid in ids:
            if _key(cid) == k:
                hits.add(cid)
                continue
            meta_path = self.folder(cid) / META
            if meta_path.is_file() and _key(self.meta(cid).get("name", "")) == k:
                hits.add(cid)
        if len(hits) > 1:
            raise CockpitError(f"{name!r} matches several challenges: {', '.join(sorted(hits))}; "
                               "use the exact id")
        return hits.pop() if hits else None

    def require(self, name: str) -> str:
        cid = self.resolve(name)
        if cid is None:
            raise CockpitError(f"no challenge {name!r} in {self.drop_dir}; add it with "
                               f"`ctf cockpit add {name!r}`")
        return cid

    def _create(self, name: str, how: str) -> str:
        cid = make_id(name)
        folder = self.folder(cid)
        if folder.is_symlink():
            raise CockpitError(f"{folder} is a symlink; drop folders hold plain folders only")
        (folder / FILES).mkdir(parents=True, exist_ok=True)
        with self._txn() as st:
            st["challenges"].setdefault(cid, {"added": self.clock(), "no_files": False})
        if name != cid and not (folder / META).exists():
            self.set_meta(cid, name=name)
        self._log("cockpit.add", challenge_id=cid, name=name, how=how)
        return cid

    def add(self, name: str, *, category: str | None = None, points: int | None = None,
            description: str | None = None, connection_info: str | None = None,
            no_files: bool = False) -> str:
        """Register a challenge the player sees on the platform (idempotent). Returns its id."""
        cid = self.resolve(name) or self._create(name, "add")
        self.files_dir(cid).mkdir(parents=True, exist_ok=True)
        fields = {k: v for k, v in (("category", category), ("points", points),
                                    ("description", description),
                                    ("connection_info", connection_info)) if v is not None}
        if fields:
            self.set_meta(cid, **fields)
        with self._txn() as st:
            rec = st["challenges"].setdefault(cid, {"added": self.clock(), "no_files": False})
            if no_files:
                rec["no_files"] = True
        return cid

    def set_meta(self, cid: str, **fields) -> None:
        folder = self.folder(cid)
        meta = self.meta(cid) if (folder / META).exists() else {}
        for k, v in fields.items():
            if k not in _META_STR + ("points", "tags"):
                raise CockpitError(f"challenge.toml has no key {k!r}")
            if k == "points" and (isinstance(v, bool) or not isinstance(v, int)):
                raise CockpitError("points must be a whole number")
            meta[k] = v
        _atomic_write(folder / META, _toml_dump(meta))
        self.plat.get_challenge(cid)               # the adapter must still read it

    def describe(self, name: str, text: str) -> str:
        cid = self.require(name)
        text = (text or "").strip()
        if not text:
            raise CockpitError("an empty description; nothing written")
        self.set_meta(cid, description=text)
        self._log("cockpit.describe", challenge_id=cid, chars=len(text))
        return cid

    def focus(self, name: str | None) -> str | None:
        cid = self.require(name) if name else None
        with self._txn() as st:
            st["focus"] = cid
        return cid

    def current_focus(self) -> str | None:
        with self._txn() as st:
            f = st.get("focus")
        return f if f and f in self.challenge_ids() else None

    # ============================================================================ files
    def files(self, cid: str) -> dict[str, _kinds.Kind]:
        """rel name -> Kind for each file in the challenge's files/ (hidden names skipped)."""
        root = self.files_dir(cid)
        out: dict[str, _kinds.Kind] = {}
        if not root.is_dir():
            return out
        for p in sorted(root.rglob("*")):
            rel = p.relative_to(root)
            if any(part.startswith(".") for part in rel.parts) or p.is_symlink() or not p.is_file():
                continue
            s = p.stat()
            ck = (str(p), s.st_size, s.st_mtime_ns)
            k = self._kind_cache.get(ck)
            if k is None:
                k = self._kind_cache[ck] = _kinds.classify(p)
            out[rel.as_posix()] = k
        return out

    def problems(self, cid: str) -> list[_kinds.Problem]:
        fs = self.files(cid)
        out = [p for rel, k in fs.items() for p in _kinds.file_problems(rel, k)]
        desc = self.meta(cid).get("description", "") if (self.folder(cid) / META).exists() else ""
        return out + _kinds.challenge_problems(fs, desc)

    # ============================================================================ sweep
    def _settled(self, p: Path, rep: SweepReport) -> bool:
        if _kinds.is_partial(p.name):
            rep.waiting.append({"src": str(p), "reason": "partial download"})
            return False
        s = p.stat()
        sig = (s.st_size, s.st_mtime_ns)
        if self.clock() - s.st_mtime < self.settle:
            self._seen[str(p)] = sig
            rep.waiting.append({"src": str(p), "reason": "still being written"})
            return False
        if self.track_growth and self._seen.get(str(p)) != sig:
            self._seen[str(p)] = sig
            rep.waiting.append({"src": str(p), "reason": "first seen this pass"})
            return False
        return True

    def _walk(self, src: Path, rep: SweepReport) -> list[tuple[Path, str]] | None:
        """(file, rel) for every file under src; None when anything inside must wait. Symlinks are
        reported and left alone."""
        out: list[tuple[Path, str]] = []
        if src.is_file():
            return [(src, src.name)] if self._settled(src, rep) else None
        ready = True
        for p in sorted(src.rglob("*")):
            rel = p.relative_to(src)
            if any(part.startswith(".") for part in rel.parts):
                continue
            if p.is_symlink():
                rep.refused.append({"src": str(p), "reason": "a symlink: copy the real file in"})
                continue
            if p.is_file():
                if not self._settled(p, rep):
                    ready = False
                out.append((p, rel.as_posix()))
        return out if ready else None

    def _move(self, src: Path, cid: str, rel: str, how: str, rep: SweepReport, *,
              replace: bool = False) -> bool:
        if rel.split("/", 1)[0] == FILES and "/" in rel:
            rel = rel.split("/", 1)[1]           # a drop that mirrored the layout: <id>/files/x
        rel = _safe_rel(rel)
        root = self.files_dir(cid)
        dest = root / rel
        if not dest.parent.resolve().is_relative_to(root.resolve()):
            raise CockpitError(f"{dest} would land outside {root} (a symlinked folder on the way)")
        if dest.exists() or dest.is_symlink():
            if not dest.is_symlink() and dest.is_file() and _sha256(dest) == _sha256(src):
                src.unlink()
                rep.duplicates.append({"src": str(src), "challenge": cid, "rel": rel})
                return True
            if dest.is_dir() and not dest.is_symlink():
                rep.conflicts.append({"src": str(src), "challenge": cid, "rel": rel})
                return False
            bad = (dest.is_file() and not dest.is_symlink()
                   and any(p.code in _REDOWNLOAD
                           for p in _kinds.file_problems(rel, _kinds.classify(dest))))
            if not (replace or bad):
                rep.conflicts.append({"src": str(src), "challenge": cid, "rel": rel})
                return False
            dest.unlink()                          # --replace, or the re-download of a bad file
            how = f"{how} (replaced {'a bad download' if bad else 'the old file'})"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dest))
        kind = _kinds.classify(dest)
        probs = _kinds.file_problems(rel, kind)
        rep.filed.append({"src": str(src), "challenge": cid, "rel": rel, "kind": kind.kind,
                          "role": kind.role, "detail": kind.detail, "how": how,
                          "problems": [p.message for p in probs]})
        self._log("cockpit.filed", challenge_id=cid, file=rel, how=how, kind=kind.kind,
                  role=kind.role, size=dest.stat().st_size, sha256=_sha256(dest),
                  problems=[p.code for p in probs])
        return True

    def _prune(self, top: Path, keep_top: bool) -> None:
        dirs = sorted((d for d in top.rglob("*") if d.is_dir() and not d.is_symlink()),
                      key=lambda d: len(d.parts), reverse=True)
        for d in dirs + ([] if keep_top else [top]):
            with contextlib.suppress(OSError):
                d.rmdir()                          # only empty folders go

    def _absorb_description(self, cid: str, p: Path, rep: SweepReport) -> bool:
        """A dropped description file sets an empty description. True when it was consumed."""
        try:
            text = p.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeDecodeError):
            return False
        have = self.meta(cid).get("description", "") if (self.folder(cid) / META).exists() else ""
        if not text or (have and have.strip() != text):
            return False
        if not have:
            self.set_meta(cid, description=text)
            rep.described.append(cid)
            self._log("cockpit.describe", challenge_id=cid, chars=len(text), how="dropped file")
        p.unlink()
        return True

    def _target_for_loose(self, name: str, st: dict) -> tuple[str | None, str, str]:
        """(challenge, file name, how) for a loose file; challenge None when nothing says where."""
        m = _PREFIXED.match(name)
        if m:
            cid = self.resolve(m["cid"])
            if cid is not None:                    # only an existing challenge: "a__b.zip" is a name too
                return cid, m["rest"], f"named {m['cid']}__"
        hits = {n["challenge"] for n in st["needs"]
                if n["status"] == "open" and n.get("expect") and _kinds.matches(n["expect"], name)
                and n["challenge"] in self.challenge_ids()}
        if len(hits) == 1:
            return hits.pop(), name, "matched a need's expected file"
        if len(hits) > 1:
            return None, name, f"matches the expected file of several challenges: {', '.join(sorted(hits))}"
        focus = st.get("focus")
        if focus and focus in self.challenge_ids():
            return focus, name, "focus"
        return None, name, "no challenge: name it <id>__<file>, drop it in a folder named after the " \
                           "challenge, set `ctf cockpit focus <id>`, or `ctf cockpit file`"

    def _place_loose(self, src: Path, where: str, st: dict, rep: SweepReport) -> None:
        if src.is_symlink():
            rep.refused.append({"src": str(src), "reason": "a symlink: copy the real file in"})
            return
        if not self._settled(src, rep):
            return
        cid, name, how = self._target_for_loose(src.name, st)
        if cid is None:
            rep.unfiled.append({"src": str(src), "reason": how})
            return
        if name.lower() in DESCRIPTION_NAMES and self._absorb_description(cid, src, rep):
            return
        self._move(src, cid, name, f"{where}: {how}", rep)

    def _place_dir(self, src: Path, st: dict, rep: SweepReport) -> None:
        if src.name.lower() == FILES:              # a bare files/ folder: each child is loose
            for child in sorted(src.iterdir()):
                if not child.name.startswith("."):
                    if child.is_dir() and not child.is_symlink():
                        rep.unfiled.append({"src": str(child), "reason": "a folder inside a bare files/ "
                                            "folder: drop it in a folder named after the challenge"})
                    else:
                        self._place_loose(child, "inbox files/", st, rep)
            self._prune(src, keep_top=False)
            return
        items = self._walk(src, rep)
        if items is None:
            return                                 # something inside is still downloading
        cid = self.resolve(src.name)
        if cid is None:
            if not items:
                rep.unfiled.append({"src": str(src), "reason": "an empty folder that names no known "
                                    "challenge (register it with `ctf cockpit add`)"})
                return
            cid = self._create(src.name, "inbox folder")
            rep.created.append(cid)
        for p, rel in items:
            if rel.lower() in DESCRIPTION_NAMES and self._absorb_description(cid, p, rep):
                continue
            self._move(p, cid, rel, "inbox folder", rep)
        self._prune(src, keep_top=False)

    def _place_in_folder(self, cid: str, entry: Path, rep: SweepReport) -> None:
        if entry.is_file() and entry.name.lower() in DESCRIPTION_NAMES:
            if not self._settled(entry, rep):
                return
            if self._absorb_description(cid, entry, rep):
                return
        items = self._walk(entry, rep)
        if items is None:
            return
        for p, rel in items:
            sub = rel if entry.is_file() else f"{entry.name}/{rel}"
            self._move(p, cid, sub, "loose in the challenge folder", rep)
        if entry.is_dir():
            self._prune(entry, keep_top=False)

    @staticmethod
    def _isolate(rep: SweepReport, entry: Path, fn, *args) -> None:
        """One bad drop (an ambiguous name, a broken challenge.toml) is reported, not fatal: the
        watcher keeps filing everything else."""
        try:
            fn(*args)
        except (CockpitError, PlatformError, OSError) as e:
            rep.refused.append({"src": str(entry), "reason": str(e)})

    def sweep(self) -> SweepReport:
        """One pass of the drop-zone watcher. Files everything that is ready; reports the rest."""
        rep = SweepReport()
        with self._txn() as st:
            # 1. loose in a challenge folder (next to challenge.toml instead of under files/)
            for cid in self.challenge_ids():
                folder = self.folder(cid)
                for entry in sorted(folder.iterdir()):
                    if entry.name in (META, SOLVED, FILES) or entry.name.startswith("."):
                        continue
                    if entry.is_symlink():
                        rep.refused.append({"src": str(entry), "reason": "a symlink: copy the real file in"})
                        continue
                    self._isolate(rep, entry, self._place_in_folder, cid, entry, rep)
                (folder / FILES).mkdir(exist_ok=True)
                st["challenges"].setdefault(cid, {"added": self.clock(), "no_files": False})
            # 2. loose at the drop root (a file there is no challenge at all to the adapter)
            for entry in sorted(self.drop_dir.iterdir()):
                if entry.name.startswith(".") or (entry.is_dir() and not entry.is_symlink()):
                    continue
                self._isolate(rep, entry, self._place_loose, entry, "drop root", st, rep)
            # 3. the inbox
            for entry in sorted(self.inbox.iterdir()):
                if entry.name.startswith("."):
                    continue
                if entry.is_symlink():
                    rep.refused.append({"src": str(entry), "reason": "a symlink: copy the real file in"})
                elif entry.is_dir():
                    self._isolate(rep, entry, self._place_dir, entry, st, rep)
                else:
                    self._isolate(rep, entry, self._place_loose, entry, "inbox", st, rep)
            # 4. added needs whose expected file has now landed
            self._resolve_expected(st)
        return rep

    def file(self, src: str | Path, name: str, *, as_name: str | None = None,
             replace: bool = False) -> SweepReport:
        """File one drop by hand: a path, or a name in the inbox / at the drop root."""
        p = Path(src)
        if not p.is_absolute() and not p.exists():
            for base in (self.inbox, self.drop_dir):
                if (base / p).exists() or (base / p).is_symlink():
                    p = base / p
                    break
        if p.is_symlink():
            raise CockpitError(f"{p} is a symlink; copy the real file in")
        if not p.exists():
            raise CockpitError(f"no file {src!s} (looked as given, in {self.inbox} and {self.drop_dir})")
        cid = self.require(name)
        rep = SweepReport()
        base = p.name if as_name is None else as_name  # an empty --as is refused, not ignored (_move)
        with self._txn() as st:
            if p.is_dir():
                items = self._walk(p, rep) or []
                for f, rel in items:
                    self._move(f, cid, f"{base}/{rel}", "filed by hand", rep, replace=replace)
                self._prune(p, keep_top=False)
            else:
                self._move(p, cid, base, "filed by hand", rep, replace=replace)
            self._resolve_expected(st)
        return rep

    # ============================================================================ needs
    def _resolve_expected(self, st: dict) -> None:
        for n in st["needs"]:
            if n["status"] != "open" or not n.get("expect"):
                continue
            hit = next((rel for rel in self.files(n["challenge"]) if _kinds.matches(n["expect"], rel)),
                       None) if n["challenge"] in self.challenge_ids() else None
            if hit:
                n.update(status="done", done_at=self.clock(), note=f"filed {hit}")
                self._log("cockpit.need_done", need=n["id"], challenge_id=n["challenge"],
                          note=f"filed {hit}")

    def add_need(self, name: str, text: str, *, kind: str = "other", expect: str | None = None) -> dict:
        """Add a need (an agent asking the player for something). Returns the record; its status is
        already "done" when the --expect file is already filed."""
        cid = self.require(name)
        text = (text or "").strip()
        if not text:
            raise CockpitError("a need needs a text: what should the player get?")
        if kind not in NEED_KINDS:
            raise CockpitError(f"need kind {kind!r}: one of {', '.join(NEED_KINDS)}")
        with self._txn() as st:
            for n in st["needs"]:
                if n["status"] == "open" and n["challenge"] == cid and n["text"] == text:
                    return dict(n)
            n = {"id": f"n{self._next_id(st)}", "challenge": cid, "kind": kind, "text": text,
                 "expect": expect or None, "status": "open", "created": self.clock()}
            st["needs"].append(n)
            self._resolve_expected(st)
        self._log("cockpit.need", need=n["id"], challenge_id=cid, kind=kind, text=text,
                  expect=expect or None)
        return dict(n)

    @staticmethod
    def _need(n: dict) -> Need:
        return Need(n["id"], n["challenge"], n["kind"], n["text"], "added", n["created"], n.get("expect"))

    def done(self, need_id: str, note: str = "") -> str:
        """Close an added need, or dismiss a computed one (the player says it is fine: a challenge
        with no files, a mismatch that is not one). Returns what happened."""
        with self._txn() as st:
            for n in st["needs"]:
                if n["id"] == need_id:
                    if n["status"] != "open":
                        raise CockpitError(f"need {need_id} is already {n['status']}")
                    n.update(status="done", done_at=self.clock(), note=note)
                    self._log("cockpit.need_done", need=need_id, challenge_id=n["challenge"], note=note)
                    return f"{need_id} done"
            open_auto = {n.id: n for n in self._auto_needs(st)}
            if need_id not in open_auto:
                raise CockpitError(f"no open need {need_id!r} (see `ctf cockpit needs --all`)")
            cid = open_auto[need_id].challenge
            st["dismissed"].append(need_id)
            self._log("cockpit.need_dismissed", need=need_id, challenge_id=cid, note=note)
            return f"{need_id} dismissed"

    def _added(self, st: dict, cid: str) -> float:
        rec = st["challenges"].get(cid)
        if rec and "added" in rec:
            return float(rec["added"])
        return self.folder(cid).stat().st_mtime

    def _auto_needs(self, st: dict) -> list[Need]:
        out = []
        dismissed = set(st["dismissed"])
        for cid in self.challenge_ids():
            if self.solved(cid):
                continue
            t = self._added(st, cid)
            meta = self.meta(cid) if (self.folder(cid) / META).exists() else {}
            label = meta.get("name") or cid
            fs = self.files(cid)
            no_files = st["challenges"].get(cid, {}).get("no_files", False)
            cand = []
            if not fs and not no_files:
                cand.append(Need(f"{cid}:files", cid, "files",
                                 f"download {label}'s files: drop them in the inbox in a folder named "
                                 f"{cid} (or name each {cid}__<file>); `ctf cockpit done {cid}:files` if "
                                 "it has none", "auto", t))
            for p in self.problems(cid):
                cand.append(Need(f"{cid}:{p.key}", cid,
                                 "redownload" if p.code in _REDOWNLOAD else "capture", p.message,
                                 "auto", t))
            if not (meta.get("description") or "").strip():
                cand.append(Need(f"{cid}:description", cid, "description",
                                 f"paste {label}'s description: `ctf cockpit describe {cid} -` (or drop "
                                 "description.txt in its folder)", "auto", t))
            out += [n for n in cand if n.id not in dismissed]
        return out

    def needs(self) -> list[Need]:
        """Every open need, most blocking first (files, re-downloads, captures, instances,
        descriptions, other), then by when the challenge was added."""
        with self._txn() as st:
            solved = {cid for cid in self.challenge_ids() if self.solved(cid)}
            added = [self._need(n) for n in st["needs"]
                     if n["status"] == "open" and n["challenge"] not in solved]
            items = self._auto_needs(st) + added
            order = {cid: self._added(st, cid) for cid in self.challenge_ids()}
        return sorted(items, key=lambda n: (_PRIORITY[n.kind], order.get(n.challenge, n.created),
                                            n.challenge, n.created, n.id))

    # ============================================================================ queue
    def _value_key(self, flag: str, nonstandard: bool) -> str:
        if nonstandard:
            return flag.strip()
        return flagfmt.for_profile(self.profile).normalize(flag)

    def enqueue(self, name: str, flag: str, *, provenance: str, nonstandard: bool = False,
                guess: bool = False, confirmed: bool = False) -> dict:
        """Queue a value for the player to submit. Refuses (Refused) exactly where the submit gate
        would: no provenance, not the event format (unless nonstandard), the event rules
        (wrong_answer_stop unless confirmed, guess_budget); and also a solved challenge or a value
        already queued, accepted or rejected for it."""
        cid = self.require(name)
        flag = (flag or "").strip()
        if not flag:
            raise Refused("an empty value")
        if not (provenance or "").strip():
            raise Refused("a queued flag needs a provenance note (where it came from; it goes into "
                          "the write-up)")
        if not nonstandard and not flagfmt.for_profile(self.profile).is_flag(flag):
            raise Refused("value is not in the event flag format (pass --nonstandard only for an "
                          "answer the brief defines)")
        if self.solved(cid):
            raise Refused(f"challenge {cid} is already solved (its SOLVED marker is written)")
        key = self._value_key(flag, nonstandard)
        req = SubmitRequest(cid, flag, provenance, confirmed, nonstandard, guess)
        with self._txn() as st:                    # the rule check and the append under one lock
            rules = EventRules(self.profile)
            reason = rules.check(self.profile, req)
            if reason:
                raise Refused(reason)
            if guess:                              # a queued guess spends the budget when it is sent
                used = rules.guesses_used(cid)
                queued = sum(1 for q in st["queue"]
                             if q["challenge"] == cid and q["status"] == "pending" and q["guess"])
                if used + queued >= self.profile.rules.guess_budget:
                    raise Refused(f"guess_budget: {used} guess(es) used and {queued} queued on challenge "
                                  f"{cid} (budget {self.profile.rules.guess_budget}); re-derive the "
                                  "value from the artifact instead of varying it")
            for q in st["queue"]:
                # (an accepted value never gets here: its challenge is solved, refused above)
                if q["challenge"] == cid and q["key"] == key and q["status"] in ("pending", "rejected"):
                    raise Refused(f"#{q['id']} already holds this value for {cid} ({q['status']})")
            item = {"id": self._next_id(st), "challenge": cid, "flag": flag, "key": key,
                    "provenance": provenance.strip(), "nonstandard": nonstandard, "guess": guess,
                    "confirmed": confirmed, "status": "pending", "created": self.clock()}
            st["queue"].append(item)
        self._log("cockpit.enqueue", challenge_id=cid, item=item["id"], provenance=item["provenance"],
                  nonstandard=nonstandard, guess=guess, confirmed=confirmed, **self._flag_fields(flag))
        return dict(item)

    def _hold(self, q: dict) -> str | None:
        """Why a pending item may not be sent now, or None. The gate checks the event rules right
        before each send; here the player's send is `next`, so the rules are checked again against
        the ledger as it is now (a rejection since the item was queued can have hit the stop)."""
        req = SubmitRequest(q["challenge"], q["flag"], q["provenance"], q["confirmed"],
                            q["nonstandard"], q["guess"])
        return EventRules(self.profile).check(self.profile, req)

    def queue(self, *, all_items: bool = False) -> list[dict]:
        """Queue items, oldest first. Each pending one carries "held": the reason the event rules
        refuse it now (None when it may be sent)."""
        with self._txn() as st:
            items = [dict(q) for q in st["queue"] if all_items or q["status"] == "pending"]
        for q in items:
            if q["status"] == "pending":
                q["held"] = self._hold(q)
        return sorted(items, key=lambda q: (q["created"], q["id"]))

    def next_item(self) -> dict | None:
        """The oldest pending item the event rules allow now; a held item is never served."""
        return next((q for q in self.queue() if q["held"] is None), None)

    def confirm(self, qid: int, *, by: str, interactive: bool, relayed: str | None = None) -> dict:
        """The player's yes past the wrong-answer stop for one queued item (the gate's
        confirmed=True). Like a verdict it is the player's: with no terminal it needs `relayed`."""
        if not interactive and not (relayed or "").strip():
            raise Refused("going past the wrong-answer stop is the player's decision: run it in a "
                          "terminal, or pass --relayed with the player's own words (they are recorded)")
        with self._txn() as st:
            q = self._item(st, qid)
            if q["status"] != "pending":
                raise Refused(f"#{qid} is {q['status']}, not pending")
            q.update(confirmed=True, confirmed_by=by, confirmed_at=self.clock(),
                     confirm_relayed=relayed or None)
            self._log("cockpit.confirm", challenge_id=q["challenge"], item=qid, by=by,
                      relayed=relayed or None)
            out = dict(q)
        out["held"] = self._hold(out)
        return out

    def _item(self, st: dict, qid: int) -> dict:
        for q in st["queue"]:
            if q["id"] == qid:
                return q
        raise CockpitError(f"no queue item #{qid}")

    def verdict(self, qid: int, accepted: bool, *, by: str, interactive: bool,
                relayed: str | None = None) -> dict:
        """Record the platform's answer to a value the player submitted by hand. Only the player
        knows it: from a script with no terminal, `relayed` must carry the player's own words."""
        if not interactive and not (relayed or "").strip():
            raise Refused("a verdict is the player's: run it in a terminal, or pass --relayed with "
                          "the player's own words (they are recorded)")
        with self._txn() as st:
            q = self._item(st, qid)
            if q["status"] != "pending":
                raise Refused(f"#{qid} is {q['status']}, not pending")
            held = self._hold(q)
            if held:
                raise Refused(f"#{qid} is held and should not have been sent: {held}. If the player "
                              f"decided to send it past the wrong-answer stop: `ctf submit-queue approve "
                              f"{q['challenge']} --reason ...` and `ctf cockpit confirm {qid}` first; a "
                              f"guess past the budget: `ctf cockpit withdraw {qid}`")
            cid = q["challenge"]
            status = SubmitStatus.CORRECT if accepted else SubmitStatus.INCORRECT
            marker = self.folder(cid) / SOLVED
            wrote_marker = False
            if accepted:                           # the marker first: if it fails, nothing is recorded
                if marker.is_symlink():
                    raise CockpitError(f"{marker} is a symlink; not writing through it")
                wrote_marker = not marker.exists()
                marker.write_text(f"{by}\naccepted: cockpit queue #{qid} at "
                                  f"{time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(self.clock()))}\n",
                                  encoding="utf-8")
            req = SubmitRequest(cid, q["flag"], q["provenance"], q["confirmed"], q["nonstandard"],
                                q["guess"])
            try:
                EventRules(self.profile).record(self.profile, req, SubmitResult(
                    status, "player verdict (manual submission, recorded in the cockpit)", sent=True))
            except BaseException:
                if wrote_marker:                   # no record, so no marker: the item stays pending
                    marker.unlink(missing_ok=True)
                raise
            q.update(status="accepted" if accepted else "rejected", decided=self.clock(), by=by,
                     relayed=(relayed or None))
            self._log("cockpit.verdict", challenge_id=cid, item=qid, status=status.value, by=by,
                      relayed=relayed or None)
            if accepted:
                for other in st["queue"]:
                    if other["challenge"] == cid and other["status"] == "pending":
                        other.update(status="superseded", decided=self.clock())
                for n in st["needs"]:
                    if n["challenge"] == cid and n["status"] == "open":
                        n.update(status="done", done_at=self.clock(), note="challenge accepted")
            out = dict(q)
        out["wrong"] = EventRules(self.profile).wrong_count(cid)
        out["stop"] = (not accepted) and out["wrong"] >= self.profile.rules.wrong_answer_stop
        out["held"] = [q["id"] for q in self.queue() if q["challenge"] == cid and q["held"]]
        return out

    def withdraw(self, qid: int, note: str = "") -> dict:
        with self._txn() as st:
            q = self._item(st, qid)
            if q["status"] != "pending":
                raise Refused(f"#{qid} is {q['status']}, not pending")
            q.update(status="withdrawn", decided=self.clock(), note=note)
            self._log("cockpit.withdraw", challenge_id=q["challenge"], item=qid, note=note)
            return dict(q)

    # ============================================================================ board data
    def board(self) -> dict:
        """Everything the live view shows, as data (also `status --json`)."""
        needs = self.needs()
        pending = self.queue()
        rows = []
        for cid in self.challenge_ids():
            meta = self.meta(cid) if (self.folder(cid) / META).exists() else {}
            fs = self.files(cid)
            mine = [n for n in needs if n.challenge == cid]
            queued = [q for q in pending if q["challenge"] == cid]
            if self.solved(cid):
                state = "solved"
            elif queued:
                state = "flag queued"
            elif any(n.kind == "files" for n in mine):
                state = "waiting for files"
            elif mine:
                state = "needs"
            else:
                state = "ready"
            rows.append({"id": cid, "name": meta.get("name", cid), "category": meta.get("category", ""),
                         "points": meta.get("points"), "state": state, "files": len(fs),
                         "bytes": sum((self.files_dir(cid) / r).stat().st_size for r in fs),
                         "needs": len(mine), "queued": len(queued),
                         "folder": str(self.folder(cid))})
        unfiled = sorted(str(p) for p in self.inbox.iterdir() if not p.name.startswith("."))
        return {"event": self.profile.slug, "drop": str(self.drop_dir), "inbox": str(self.inbox),
                "focus": self.current_focus(), "challenges": rows,
                "needs": [asdict(n) for n in needs], "queue": pending, "inbox_left": unfiled}
