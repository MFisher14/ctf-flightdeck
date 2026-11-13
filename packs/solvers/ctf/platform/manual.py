"""Manual mode: the player is the only one who touches the platform (Spooky-type events).

Code-enforced, not prose: this adapter has no network code at all. submit() raises NotAllowed, as do
scoreboard(), challenge_solves() (B-099) and every instance call (start_instance, stop_instance, instance_status), so nothing
linked into a solver can reach the platform. get_adapter() also routes any event whose rules say
ai_on_platform = "forbidden" here, whatever its platform kind.

Challenges come from a drop folder the player fills by hand, <workdir>/drop/ by default:

    drop/<challenge id>/                 one folder per challenge; the folder name is the id
        challenge.toml                   optional: name, category, points, description,
                                         connection_info, tags (other keys are an error)
        SOLVED                           optional marker the player writes; its first line, if any,
                                         names the solver
        <anything else>                  the files the player downloaded

list_challenges() reads the folders, download_files() copies a folder's files (not the two control
files) into dest, team_solves() reads the SOLVED markers. A missing drop folder or challenge folder
is a PlatformError naming the path. Symlinks in a drop folder are refused, never followed.
"""
from __future__ import annotations

import re
import shutil
import tomllib
from pathlib import Path

from .. import paths
from ..event import EventProfile
from .base import (INSTANCE_METHODS, Challenge, ChallengeSolve, FileRef, InstancesNotAllowed,
                   NotAllowed, PlatformError, ScoreRow, SubmitResult, TeamSolve)

META = "challenge.toml"
SOLVED = "SOLVED"
_CONTROL = {META, SOLVED}
_META_KEYS = {"name": str, "category": str, "points": int, "description": str,
              "connection_info": str, "tags": list}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$")


class ManualAdapter:
    kind = "manual"

    def __init__(self, profile: EventProfile, drop_dir: Path | None = None):
        self.profile = profile
        self._drop = Path(drop_dir) if drop_dir is not None else None

    @property
    def drop_dir(self) -> Path:
        return self._drop if self._drop is not None else paths.workdir(self.profile.slug) / "drop"

    def _why(self) -> str:
        return (f"event {self.profile.slug!r} is manual: the player works the platform by hand "
                "(no automated submit, instance, or scoreboard call)")

    # ------------------------------------------------------------------------------- drop folder
    def _root(self, call: str) -> Path:
        d = self.drop_dir
        if not d.is_dir():
            raise PlatformError(f"{call}: manual mode reads challenges from the drop folder {d}, which "
                                "does not exist; create it and put each challenge's files in "
                                f"{d}/<challenge id>/")
        return d

    def _folder(self, challenge_id: str, call: str) -> Path:
        cid = str(challenge_id)
        if not _ID.match(cid) or cid in (".", ".."):
            raise PlatformError(f"{call}: {cid!r} is not a usable drop-folder challenge id")
        d = self._root(call) / cid
        if d.is_symlink() or not d.is_dir():
            raise PlatformError(f"{call}: no drop folder for challenge {cid!r} at {d}")
        return d

    def _meta(self, folder: Path) -> dict:
        p = folder / META
        if not p.exists():
            return {}
        if p.is_symlink():
            raise PlatformError(f"{p}: a symlink; drop folders hold plain files only")
        try:
            data = tomllib.loads(p.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
            raise PlatformError(f"{p}: unreadable ({e})") from None
        for k, v in data.items():
            want = _META_KEYS.get(k)
            if want is None:
                raise PlatformError(f"{p}: unknown key {k!r} (allowed: {', '.join(sorted(_META_KEYS))})")
            if not isinstance(v, want) or isinstance(v, bool):
                raise PlatformError(f"{p}: {k} must be a {want.__name__}")
        return data

    def _files(self, folder: Path) -> list[Path]:
        out = []
        for p in sorted(folder.rglob("*")):
            rel = p.relative_to(folder)
            if p.is_symlink():
                raise PlatformError(f"{p}: a symlink in a drop folder; copy the real file in instead")
            if p.is_file() and not (len(rel.parts) == 1 and rel.name in _CONTROL):
                out.append(p)
        return out

    def _challenge(self, folder: Path) -> Challenge:
        meta = self._meta(folder)
        files = tuple(FileRef(name=str(p.relative_to(folder))) for p in self._files(folder))
        return Challenge(id=folder.name, name=meta.get("name", folder.name),
                         category=meta.get("category", ""), points=meta.get("points"),
                         description=meta.get("description", ""), files=files,
                         connection_info=meta.get("connection_info", ""),
                         solved_by_team=(folder / SOLVED).is_file(),
                         tags=tuple(str(t) for t in meta.get("tags", ())), raw=meta)

    # ------------------------------------------------------------------------------- reads
    def list_challenges(self) -> list[Challenge]:
        root = self._root("list_challenges")
        return [self._challenge(d) for d in sorted(root.iterdir())
                if d.is_dir() and not d.is_symlink() and _ID.match(d.name)]

    def get_challenge(self, challenge_id: str) -> Challenge:
        return self._challenge(self._folder(challenge_id, "get_challenge"))

    def download_files(self, challenge_id: str, dest: Path) -> list[Path]:
        folder = self._folder(challenge_id, "download_files")
        dest = Path(dest)
        if dest.resolve() == folder.resolve() or folder.resolve() in dest.resolve().parents:
            raise PlatformError(f"download_files: dest {dest} is inside the drop folder {folder}")
        written = []
        for src in self._files(folder):
            out = dest / src.relative_to(folder)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, out)
            written.append(out)
        return written

    def team_solves(self) -> list[TeamSolve]:
        out = []
        for ch in self.list_challenges():
            marker = self.drop_dir / ch.id / SOLVED
            if marker.is_file() and not marker.is_symlink():
                first = marker.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                out.append(TeamSolve(challenge_id=ch.id, solver=(first[0].strip() or None) if first else None,
                                     at=marker.stat().st_mtime))
        return out

    # ------------------------------------------------------------------------------- refused
    def scoreboard(self) -> list[ScoreRow]:
        raise NotAllowed(f"scoreboard: {self._why()}")

    def challenge_solves(self, challenge_id: str) -> list[ChallengeSolve]:
        raise NotAllowed(f"challenge_solves({challenge_id}): {self._why()}")

    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        raise NotAllowed(f"submit: {self._why()}")

    def __getattr__(self, name: str):
        if name in INSTANCE_METHODS:
            raise InstancesNotAllowed(f"{name}: {self._why()}")
        raise AttributeError(name)


def make_adapter(profile: EventProfile, *, drop_dir: Path | None = None) -> ManualAdapter:
    return ManualAdapter(profile, drop_dir)
