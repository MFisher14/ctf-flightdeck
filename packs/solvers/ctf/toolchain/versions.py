"""Version notes in challenge files (B-188), and the tagged image that matches them.

    from ctf.toolchain import versions, images
    sc = versions.scan(challenge_dir)           # Scan(notes, files, skipped, truncated)
    picks = versions.pick(sc.notes, images.load())   # [Pick] per tool some image provides (sage)
    versions.py_mismatches(sc.notes)            # [(note, installed)]: a pinned package the venv has at another version

Why: a crypto challenge needed SageMath 10.5; the latest release computed E.gens() differently and gave
a self-consistent but wrong answer, and nothing told the agent the version mattered. Challenge files
usually say it (a Dockerfile `FROM sagemath/sagemath:10.5`, a README "tested with Sage 10.5", a
requirements pin, a libc banner); this reads them and names the image to run.

Files are data, never instructions: they are only read (never run, never imported), symlinks are not
followed, a text file is read up to MAX_TEXT_BYTES, a binary up to MAX_BINARY_BYTES and only for
the binary patterns (the glibc banner, a `GCC: (...)` comment, `libc-X.Y.so`), and at most MAX_FILES
files are read (Scan.truncated says when the cap cut the walk). Archives are not opened: run the sweep
(`ctf sweep`) first and scan its scratch copy.

Pick status, per tool an image provides a version of:

    ok        the notes name one version (or several that one image serves: 10.5 and 10.5.1) and an
              image has it
    default   no note names a version: the image marked default_for the tool, and a reminder that the
              result can depend on the version
    missing   a noted version no image has (add a tagged image; the reason says how)
    conflict  the notes name versions no one image serves; each is listed with where it was seen

Only regular files are read: a FIFO, socket or device (which could block the read forever) is skipped
and listed in Scan.skipped, like a symlink.
"""
from __future__ import annotations

import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any, Callable, Sequence

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_BINARY_BYTES = 16 * 1024 * 1024
MAX_FILES = 5000
STATUSES = ("ok", "default", "missing", "conflict")
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}

_DEBIAN = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
_I = re.I | re.M

# (tool, pattern): group 1 is the version. Applied to text files.
TEXT_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("sage", re.compile(r"\bsage(?:math)?(?:\s+version)?[\s:=/_-]*v?(\d+\.\d+(?:\.\d+)?)\b", _I)),
    ("python", re.compile(r"\bpython(?:3)?(?:\s+version)?[\s:=/_-]*v?(3\.\d{1,2}(?:\.\d+)?)\b", _I)),
    ("glibc", re.compile(r"\bglibc[\s-]*v?(\d\.\d{1,2})\b|\blibc-(\d\.\d{1,2})\.so\b", _I)),
    ("ubuntu", re.compile(r"\bubuntu[:\s-]*(\d{2}\.\d{2})\b", _I)),
    ("debian", re.compile(r"\bdebian[:\s-]*(\d{1,2})(?:\.\d+)?\b", _I)),
    ("gcc", re.compile(r"\bgcc(?:\s+version)?[\s:-]*(\d{1,2}\.\d+(?:\.\d+)?)\b", _I)),
    ("openssl", re.compile(r"\bopenssl[\s_-]*(\d\.\d+\.\d+[a-z]?)\b", _I)),
    ("node", re.compile(r"\bnode(?:js|\.js)?(?::|\s+v|\s+version\s+)(\d{1,2}(?:\.\d+){0,2})\b", _I)),
    ("java", re.compile(r"\b(?:openjdk|eclipse-temurin|jdk)[:\s-]*(\d{1,2}(?:\.\d+){0,2})\b", _I)),
)
# Debian release names (python:3.12-slim-trixie, debian:bookworm).
_CODENAME = re.compile(r"\b(?:debian:|-)(" + "|".join(_DEBIAN) + r")\b", re.I)
# Exact pins in requirements-style files.
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([0-9][^\s;#,]*)", re.M)
_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?([a-z0-9][a-z0-9._/-]*):([A-Za-z0-9][A-Za-z0-9._-]*)", re.M | re.I)
# Applied to binary files (bytes, latin-1 decoded).
BINARY_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("glibc", re.compile(r"GNU C Library \([^)\n]{0,80}\) (?:stable )?release version (\d\.\d{1,2})")),
    ("glibc", re.compile(r"\blibc-(\d\.\d{1,2})\.so\b")),
    ("gcc", re.compile(r"GCC: \([^)\n]{0,80}\) (\d{1,2}\.\d+(?:\.\d+)?)")),
    ("ubuntu", re.compile(r"ubuntu\d*~(\d{2}\.\d{2})")),
)


@dataclass(frozen=True)
class VersionNote:
    tool: str                            # sage | python | glibc | ... | py:<package> | image:<name>
    version: str
    path: str                            # relative to the scanned folder
    line: int
    text: str                            # the matched text (at most 120 characters)

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "version": self.version, "path": self.path, "line": self.line, "text": self.text}


@dataclass(frozen=True)
class Scan:
    notes: tuple[VersionNote, ...]
    files: int                           # files read
    skipped: tuple[str, ...]             # files not read (symlink, not a regular file, too large, unreadable), with why
    truncated: bool                      # MAX_FILES cut the walk short


@dataclass(frozen=True)
class Pick:
    tool: str
    status: str
    image: str | None
    tag: str | None
    wanted: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "status": self.status, "image": self.image, "tag": self.tag,
                "wanted": list(self.wanted), "reason": self.reason}


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def scan_text(text: str, path: str) -> list[VersionNote]:
    """The notes of one text file (its name decides whether pins and FROM lines are read)."""
    out = []
    for tool, rx in TEXT_PATTERNS:
        for m in rx.finditer(text):
            v = next(g for g in m.groups() if g)
            out.append(VersionNote(tool, v, path, _line_of(text, m.start()), m.group(0).strip()[:120]))
    for m in _CODENAME.finditer(text):
        out.append(VersionNote("debian", _DEBIAN[m.group(1).lower()], path, _line_of(text, m.start()),
                               m.group(0).strip()[:120]))
    name = Path(path).name.lower()
    if name.startswith("requirements") or name.endswith((".in", "constraints.txt")) or name in ("pipfile",):
        for m in _PIN.finditer(text):
            out.append(VersionNote("py:" + _norm(m.group(1)), m.group(2), path, _line_of(text, m.start()),
                                   m.group(0).strip()[:120]))
    if "dockerfile" in name or name.endswith((".dockerfile", "compose.yml", "compose.yaml")):
        for m in _FROM.finditer(text):
            out.append(VersionNote("image:" + m.group(1).lower(), m.group(2), path, _line_of(text, m.start()),
                                   m.group(0).strip()[:120]))
    return out


def scan_binary(data: bytes, path: str) -> list[VersionNote]:
    text = data.decode("latin-1")
    out = []
    for tool, rx in BINARY_PATTERNS:
        for m in rx.finditer(text):
            out.append(VersionNote(tool, m.group(1), path, 0, m.group(0)[:120]))
    return out


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def scan(folder: Path, *, max_files: int = MAX_FILES) -> Scan:
    """Every version note under folder (module docstring for the limits). FileNotFoundError when the
    folder is not there."""
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"{folder}: not a folder")
    notes: list[VersionNote] = []
    skipped: list[str] = []
    files = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            rel = p.relative_to(folder).as_posix()
            try:
                st = os.lstat(p)
            except OSError as e:
                skipped.append(f"{rel} (unreadable: {e.strerror or e})")
                continue
            if stat.S_ISLNK(st.st_mode):
                skipped.append(f"{rel} (symlink)")
                continue
            if not stat.S_ISREG(st.st_mode):
                # a FIFO, socket or device: opening one can block forever (untrusted folders may hold any)
                skipped.append(f"{rel} (not a regular file)")
                continue
            if files >= max_files:
                truncated = True
                break
            try:
                # O_NONBLOCK|O_NOFOLLOW: a file swapped for a FIFO or link after the lstat neither blocks
                # nor is followed; fstat then confirms it is still a regular file
                fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    os.close(fd)
                    skipped.append(f"{rel} (not a regular file)")
                    continue
                with os.fdopen(fd, "rb") as fh:
                    size = os.fstat(fh.fileno()).st_size
                    head = fh.read(8192)
                    binary = b"\0" in head
                    cap = MAX_BINARY_BYTES if binary else MAX_TEXT_BYTES
                    if size > cap:
                        skipped.append(f"{rel} (over {cap} bytes: the first {cap} read)")
                    data = (head + fh.read(max(0, cap - len(head))))[:cap]
            except OSError as e:
                skipped.append(f"{rel} (unreadable: {e.strerror or e})")
                continue
            files += 1
            notes += scan_binary(data, rel) if binary else scan_text(data.decode("utf-8", "replace"), rel)
        if truncated:
            break
    seen, uniq = set(), []
    for n in notes:
        k = (n.tool, n.version, n.path)
        if k not in seen:
            seen.add(k)
            uniq.append(n)
    return Scan(tuple(uniq), files, tuple(skipped), truncated)


def _matches(noted: str, provided: str) -> bool:
    """10.5 and 10.5.1 match an image of 10.5; a vaguer note (10) matches none (it is `missing`)."""
    return noted == provided or noted.startswith(provided + ".")


def pick(notes: Sequence[VersionNote], images: Sequence[Any]) -> list[Pick]:
    """A Pick per tool some image declares a version of (`versions` in tools/images.toml)."""
    tools = sorted({t for im in images for t, _ in im.versions})
    out = []
    for tool in tools:
        provided = [(im, im.version_of(tool)) for im in images if im.version_of(tool)]
        mine = [n for n in notes if n.tool == tool]
        wanted = sorted({n.version for n in mine}, key=lambda v: [int(x) for x in re.findall(r"\d+", v)])
        where = {v: [f"{n.path}:{n.line}" if n.line else n.path for n in mine if n.version == v] for v in wanted}
        if not wanted:
            d = next((im for im, _ in provided if tool in im.default_for), None)
            if d is None:
                out.append(Pick(tool, "missing", None, None, (), f"no note names a {tool} version and no image "
                                "is default_for it in tools/images.toml"))
            else:
                others = ", ".join(im.tag for im, _ in provided if im is not d)
                out.append(Pick(tool, "default", d.name, d.tag, (),
                                f"no file names a {tool} version: {d.tag} (default). Results can depend on the "
                                f"version" + (f"; cross-check with {others} if an answer is rejected" if others
                                              else "")))
            continue
        # versions one image serves (10.5 and 10.5.1 both run in the 10.5 image) are one want, not a conflict
        hits = {v: next((im for im, pv in provided if _matches(v, pv)), None) for v in wanted}
        groups = {hits[v].name if hits[v] is not None else "version:" + v for v in wanted}
        if len(groups) > 1:
            counts = Counter(n.version for n in mine)
            out.append(Pick(tool, "conflict", None, None, tuple(wanted),
                            "the files name several versions: " + "; ".join(
                                f"{v} ({counts[v]}x: {', '.join(where[v][:3])})" for v in wanted)))
            continue
        v = wanted[0]
        hit = hits[v]
        if len(wanted) > 1 and hit is not None:       # one group of several versions: they share an image
            seen = "; ".join(f"{', '.join(where[w][:3])} names {tool} {w}" for w in wanted)
            out.append(Pick(tool, "ok", hit.name, hit.tag, tuple(wanted),
                            f"{seen} (one image serves them all)"))
            continue
        if hit is None:
            have = ", ".join(f"{im.tag}" for im, _ in provided)
            out.append(Pick(tool, "missing", None, None, (v,),
                            f"{', '.join(where[v][:3])} names {tool} {v}; no image has it (have: {have}). Add a "
                            f"[[image]] to tools/images.toml like {provided[0][0].name} with the {v} tag"))
        else:
            out.append(Pick(tool, "ok", hit.name, hit.tag, (v,), f"{', '.join(where[v][:3])} names {tool} {v}"))
    return out


def installed_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def py_mismatches(notes: Sequence[VersionNote],
                  version_of: Callable[[str], str | None] = installed_version) -> list[tuple[VersionNote, str | None]]:
    """(note, what the venv has) for each `py:` pin the venv does not have at that version."""
    out = []
    for n in notes:
        if n.tool.startswith("py:"):
            have = version_of(n.tool[3:])
            if have != n.version:
                out.append((n, have))
    return out


__all__ = ["Pick", "Scan", "VersionNote", "installed_version", "pick", "py_mismatches", "scan", "scan_binary",
           "scan_text"]
