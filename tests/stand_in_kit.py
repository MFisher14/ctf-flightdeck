"""Stand-in flags where the search of the handout at a lane's start does not look, for the
tests of the claim search (agent/owntext.py) in both kinds of lane and for L1 results."""

from __future__ import annotations

from pathlib import Path

STAND_IN = "t{stand_in}"
OWN_TEXT = "is written in the challenge's own text (its description or a handout file)"

PAST = {
    # where the start's search (planted) does not look: (the handout's files, its limits as set
    # for the test by name, the description, or "" for the usual one)
    "past-the-first-1-MB-of-a-file": ({"firmware.bin": b"\x7fELF" + b"\x00" * (1536 * 1024) + STAND_IN.encode()}, {}, ""),
    "past-the-bytes-in-all": ({"a.bin": b"\x00" * 8192, "b.bin": b"\x00" + STAND_IN.encode() + b"\x00"},
                              {"bytes": 4096}, ""),
    "past-the-seconds": ({"flag.txt": STAND_IN + "\n"}, {"seconds": -1.0}, ""),
    "past-the-files": ({"a1.txt": "x\n", "a2.txt": "x\n", "a3.txt": "x\n", "z.txt": STAND_IN + "\n"}, {"files": 3}, ""),
    "past-the-folder-depth": ({"d1/d2/flag.txt": STAND_IN + "\n"}, {"depth": 2}, ""),
    "as-utf-16-in-a-binary": ({"app.exe": b"MZ\x00\x00" + STAND_IN.encode("utf-16-le") + b"\x00\x00"}, {}, ""),
}


def handout_of(tmp_path: Path, files: dict[str, bytes | str], name: str = "note") -> Path:
    """tmp_path/board/<name>/ holding `files` (paths may have folders; text or bytes)."""
    folder = tmp_path / "board" / name
    folder.mkdir(parents=True)
    for file, data in files.items():
        (folder / file).parent.mkdir(parents=True, exist_ok=True)
        (folder / file).write_bytes(data.encode() if isinstance(data, str) else data)
    return folder


def cut_short(monkeypatch, limits: dict[str, float], targets: dict[str, tuple[object, str]]) -> None:
    """Set the start's search limits named in `limits`, each on the module attribute `targets` names."""
    for name, value in limits.items():
        monkeypatch.setattr(*targets[name], value)
