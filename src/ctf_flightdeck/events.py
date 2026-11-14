"""The events this player has set up: what `flightdeck` alone offers to resume.

An event is a folder with an event.toml (start.py). flightdeck notes each one it sets up or
plays in its state folder (events.json: the folder and when it was last played) and also
looks in ~/ctf, where `flightdeck start` puts events by default, so a folder made before this
note existed, or copied from another machine, is found too. The note holds paths and times
only. A folder that is gone, or no longer an event, is left out and dropped from the note.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from . import start
from .leftovers import state_folder

NOTE = "events.json"
MAX_EVENTS = 50


@dataclass(frozen=True)
class Known:
    folder: Path
    name: str  # from its event.toml ("" when that cannot be read: the folder's name is shown)
    platform: str
    challenges: int  # challenge folders on its board
    played: float  # when it was last played or set up (seconds since the epoch; 0.0: not known)

    @property
    def title(self) -> str:
        return self.name or self.folder.name


def _note() -> Path:
    return state_folder() / NOTE


def _read() -> dict[str, float]:
    try:
        data = json.loads(_note().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {path: float(when) for path, when in data.items() if isinstance(path, str) and isinstance(when, (int, float))}


def remember(folder: Path, *, now: float | None = None) -> None:
    """Note that this event folder was set up or played now. A note that cannot be written is
    not an error: the event is still found in ~/ctf, or by its path."""
    try:
        noted = _read()
        noted[str(folder.resolve())] = time.time() if now is None else now
        kept = dict(sorted(noted.items(), key=lambda item: -item[1])[:MAX_EVENTS])
        path = _note()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(kept, indent=1) + "\n", encoding="utf-8")
    except OSError:
        pass


def known(home: Path | None = None) -> list[Known]:
    """Every event folder flightdeck knows of that is still there, most recently played first."""
    from .platform.manual import challenge_folders

    noted = _read()
    folders: dict[Path, float] = {Path(path): when for path, when in noted.items()}
    try:
        root = (home or Path.home()) / "ctf"
        for entry in sorted(root.iterdir()):
            if entry.is_dir() and not entry.is_symlink():
                folders.setdefault(entry.resolve(), 0.0)
    except (OSError, RuntimeError):
        pass
    found = []
    for folder, when in folders.items():
        try:
            if not start.is_event_folder(folder):
                continue
            if not when:
                when = start.event_file(folder).stat().st_mtime
        except OSError:
            continue
        name = platform = ""
        try:
            import tomllib

            table = tomllib.loads(start.event_file(folder).read_text(encoding="utf-8")).get("event", {})
            name = table.get("name", "") if isinstance(table.get("name", ""), str) else ""
            platform = table.get("platform", "") if isinstance(table.get("platform", ""), str) else ""
        except (OSError, ValueError, AttributeError):
            pass
        found.append(Known(folder, " ".join(name.split())[:80], platform, len(challenge_folders(folder / start.BOARD_DIR)), when))
    return sorted(found, key=lambda event: -event.played)


def ago(when: float, now: float | None = None) -> str:
    """How long ago, in a few words."""
    seconds = max(0.0, (time.time() if now is None else now) - when)
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute")):
        if seconds >= size:
            n = int(seconds // size)
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    return "just now"
