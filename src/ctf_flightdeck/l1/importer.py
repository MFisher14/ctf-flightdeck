"""The script importer: a folder of plain scripts becomes L1 engines, with no script touched.

import_scripts(folder) writes a generated manifest for every script there that has no
manifest of its own, into folder/.flightdeck/generated/<relative path>.manifest.toml:

- a *.py file with an `if __name__ == "__main__":` block (at the top level; also written
  `if (__name__ == "__main__"):`, or with more conditions after it) runs as
  `python3 <relative path>`;
- any other file with an executable bit and a #! line runs as itself;

both with output "text" (every flag-format match in what they print is a candidate), tag
"imported", priority 20, and one route: the category code its folder's name maps to
(crypto/ -> cry, forensics/ -> for, the board's own mapping) and keywords from its file
name's words (the name without its extension, split on _ - . and spaces; words of 3+
letters, minus solve, solver, script, exploit and main). The script gets the challenge
directory as its last argument.

Nothing that looks like a script is left out without a word: each is listed as skipped,
with the reason. A script with neither a category nor a keyword gets no manifest, since a
route with no condition would never match; nor does a script some manifest already runs,
a .py file with no main block (a module, or a script whose code runs when it is imported:
write a manifest for it), or a #! script without an executable bit.

Hidden files and directories and .flightdeck/ are not searched, and symlinks are not
followed. Nor is a folder that holds a challenge's files (a challenge folder, a board
folder, a flightdeck workspace: manifest.challenge_files): its scripts are the challenge's,
never the player's, and it is listed as skipped. A folder that is itself one of those is
not imported at all. Re-running the import rewrites only files under
.flightdeck/generated/: manifests for scripts that are gone, or that now have a manifest of
their own, are removed.
"""

from __future__ import annotations

import hashlib
import os
import re
import shlex
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..agent.workspace import PRIVATE
from ..platform.manual import CATEGORY_CODES
from ..text import untrusted
from .manifest import GENERATED, MAX_ID, SUFFIX, Manifest, ManifestError, challenge_files, load, manifest_files

PRIORITY = 20
TAG = "imported"
STOPWORDS = frozenset({"solve", "solver", "script", "exploit", "main"})
MIN_LETTERS = 3
MAX_SCRIPT_BYTES = 5 * 1024 * 1024  # a .py bigger than this is not read for a main block
FOLDER_CATEGORIES = {**CATEGORY_CODES, **{code: code for code in CATEGORY_CODES.values()}}
"""Folder names (lower-cased) that name a category: the board's names and its short codes."""

# A main block at the top level: `if __name__ == "__main__":`, also parenthesised, the other
# way round, or with more conditions after it (`... and len(sys.argv) > 1:`).
_MAIN = re.compile(r"""^if\s*\(?\s*(?:__name__\s*==\s*(['"])__main__\1|(['"])__main__\2\s*==\s*__name__)""", re.M)
NO_MAIN = 'no `if __name__ == "__main__":` block, and not an executable with a #! line; write a manifest for it'
NOT_EXECUTABLE = "a #! script without an executable bit: chmod +x it, or write a manifest for it"
_SPLIT = re.compile(r"[_.\-\s]+")  # the contract's _ - . and whitespace: "rsa attack.py" is two words
_TEMP_PREFIX, _TEMP_SUFFIX = ".import-", ".tmp"


class ImporterError(Exception):
    """The folder cannot be imported; the message says why."""


@dataclass(frozen=True)
class ImportReport:
    written: list[Path]  # every generated manifest now in place, sorted
    skipped: list[tuple[Path, str]]  # (script, why it has no generated manifest), sorted


@dataclass(frozen=True)
class _Script:
    path: Path  # absolute
    rel: str  # posix, relative to the folder
    kind: str  # "python" | "exec"


def import_scripts(folder: Path) -> ImportReport:
    root = Path(folder).expanduser().absolute()
    if not root.is_dir():
        raise ImporterError(f"{_show(root)}: {'is not a folder' if root.exists() else 'no such folder'}")
    held = challenge_files(root)
    if held:
        raise ImporterError(f"{_show(root)} is {held}: its scripts are the challenge's, never engines of yours")
    out = root / PRIVATE / GENERATED
    for directory in (root / PRIVATE, out):
        if directory.is_symlink():
            raise ImporterError(f"{_show(directory)} is a symlink; flightdeck writes its generated manifests only into a real folder")

    own = [load(path) for path in manifest_files(root) if not path.is_relative_to(out)]
    runs = _run_files(own)
    taken = {manifest.id for manifest in own}
    planned: dict[Path, tuple[_Script, str]] = {}
    skipped: list[tuple[Path, str]] = []
    scripts, odd = _scripts(root)
    skipped += odd
    for script in scripts:
        by = runs.get(script.path.resolve())
        if by is not None:
            skipped.append((script.path, f"already run by the manifest {_show(_relative(by, root))}"))
            continue
        category = FOLDER_CATEGORIES.get(_folder_name(script, root).lower())
        keywords = keywords_of(PurePosixPath(script.rel).name)
        if category is None and not keywords:
            skipped.append((
                script.path,
                "no category from its folder name and no keyword from its file name, so a route "
                "would never match; write a manifest for it",
            ))
            continue
        engine_id = _unique_id(script.rel, taken)
        taken.add(engine_id)
        planned[out / (script.rel + SUFFIX)] = (script, _manifest_text(script, engine_id, category, keywords))

    written: list[Path] = []
    for target, (script, text) in sorted(planned.items()):
        problem = _write(target, text, out)
        if problem:
            skipped.append((script.path, problem))
        else:
            written.append(target)
    _remove_stale(out, set(written))
    return ImportReport(sorted(written), sorted(skipped))


def keywords_of(name: str) -> tuple[str, ...]:
    """Keywords from a file name: its stem's words (split on _ - .), lower-cased, with 3+
    letters, minus the words every script name has."""
    stem = name.rsplit(".", 1)[0] if "." in name.lstrip(".") else name
    words = (word.lower() for word in _SPLIT.split(stem))
    keep = (w for w in words if sum(c.isalpha() for c in w) >= MIN_LETTERS and w not in STOPWORDS)
    return tuple(dict.fromkeys(keep))


# ---------------------------------------------------------------- finding scripts


def _scripts(root: Path) -> tuple[list[_Script], list[tuple[Path, str]]]:
    """(scripts, skipped) under root, in path order."""
    scripts: list[_Script] = []
    skipped: list[tuple[Path, str]] = []
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda e: e.name)
        except OSError as exc:
            raise ImporterError(f"{_show(directory)}: cannot list it ({exc.strerror})") from None
        for entry in entries:
            if entry.name.startswith("."):
                continue  # hidden, and .flightdeck
            path = Path(entry.path)
            rel = prefix + entry.name
            if entry.is_symlink():
                if _looks_like_script(path):
                    skipped.append((path, "a symlink; only regular files are imported"))
                continue
            if entry.is_dir(follow_symlinks=False):
                held = challenge_files(path)
                if held:
                    skipped.append((path, f"{held}: its scripts are the challenge's, never engines; not searched"))
                else:
                    pending.append((path, rel + "/"))
                continue
            if not entry.is_file(follow_symlinks=False) or entry.name.endswith(SUFFIX):
                continue
            try:
                kind, why = _kind(path)
            except OSError as exc:
                skipped.append((path, f"cannot read it ({exc.strerror})"))
                continue
            except _TooBig:
                skipped.append((path, f"over {MAX_SCRIPT_BYTES // (1024 * 1024)} MB, not read"))
                continue
            if kind is None:
                if why:  # it looks like a script: say why it is not one, never drop it quietly
                    skipped.append((path, why))
                continue
            try:
                rel.encode("utf-8")
            except UnicodeEncodeError:
                skipped.append((path, "its name is not UTF-8, which a manifest cannot hold"))
                continue
            scripts.append(_Script(path, rel, kind))
    scripts.sort(key=lambda s: s.rel)
    return scripts, skipped


class _TooBig(Exception):
    pass


def _kind(path: Path) -> tuple[str | None, str | None]:
    """("python" | "exec", None) for a script; (None, why not) for a file that looks like one
    (a .py file, a file with a #! line); (None, None) for anything else."""
    info = path.stat()
    if path.name.endswith(".py"):
        if info.st_size > MAX_SCRIPT_BYTES:
            raise _TooBig
        if _MAIN.search(path.read_bytes().decode("utf-8", "replace")):
            return "python", None
    with open(path, "rb") as handle:
        shebang = handle.read(2) == b"#!"
    if shebang and info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        return "exec", None
    if path.name.endswith(".py"):
        return None, NO_MAIN
    return None, NOT_EXECUTABLE if shebang else None


def _looks_like_script(path: Path) -> bool:
    try:
        return path.name.endswith(".py") or (path.is_file() and os.access(path, os.X_OK))
    except OSError:
        return False


def _run_files(manifests: list[Manifest]) -> dict[Path, Path]:
    """Every file a manifest runs (resolved) -> that manifest's path."""
    runs: dict[Path, Path] = {}
    for manifest in manifests:
        for target in manifest.files:
            runs.setdefault(target.resolve(), manifest.path)
    return runs


def _folder_name(script: _Script, root: Path) -> str:
    parent = PurePosixPath(script.rel).parent
    return parent.name if parent.parts else root.resolve().name


# ---------------------------------------------------------------- writing manifests


def _unique_id(rel: str, taken: set[str]) -> str:
    slug = re.sub(r"[^a-z0-9_.-]", "_", rel.lower().replace("/", "."))
    base = f"{TAG}.{slug}"
    if len(base) > MAX_ID - 4:  # room for a -n suffix
        digest = hashlib.sha1(rel.encode("utf-8"), usedforsecurity=False).hexdigest()[:8]
        base = f"{base[:MAX_ID - 14]}-{digest}"
    engine_id, n = base, 1
    while engine_id in taken:
        n += 1
        engine_id = f"{base}-{n}"
    return engine_id


def _manifest_text(script: _Script, engine_id: str, category: str | None, keywords: tuple[str, ...]) -> str:
    # "./" first: a word that starts with "-" would read as an option, and a bare name as a
    # command on PATH; the runner passes the file's absolute path either way
    path = shlex.quote("./" + script.rel)
    entry = f"cli:python3 {path}" if script.kind == "python" else f"cli:{path}"
    lines = [
        f"# Generated by `flightdeck l1 import` for {_toml(script.rel)}. Re-running the import",
        "# rewrites this file: to change it, write a manifest of your own for the script.",
        f"id = {_toml(engine_id)}",
        f"entry = {_toml(entry)}",
        f"tags = [{_toml(TAG)}]",
        'output = "text"',
        "",
        "[[routes]]",
    ]
    if category:
        lines.append(f"category = [{_toml(category)}]")
    if keywords:
        lines.append(f"keywords = [{', '.join(_toml(k) for k in keywords)}]")
    lines.append(f"priority = {PRIORITY}")
    return "\n".join(lines) + "\n"


def _toml(text: str) -> str:
    """A TOML basic string: quotes, backslashes and control characters escaped."""
    out = ['"']
    for ch in text:
        if ch in '"\\':
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _write(target: Path, text: str, out: Path) -> str:
    """Write a generated manifest atomically, after checking it loads. "" when written,
    else why not."""
    _real_dirs(target.parent, out)
    fd, temp = tempfile.mkstemp(dir=target.parent, prefix=_TEMP_PREFIX, suffix=_TEMP_SUFFIX)
    try:
        with open(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        try:
            load(Path(temp))
        except ManifestError as exc:
            return f"its generated manifest would not load ({exc.problem})"
        os.replace(temp, target)
        temp = ""
    finally:
        if temp:
            os.unlink(temp)
    return ""


def _real_dirs(directory: Path, out: Path) -> None:
    """Make `directory` (inside `out`, folder/.flightdeck/generated) and the folders above
    it up to the imported folder, refusing a symlink on the way."""
    root = out.parent.parent
    current = root
    for part in directory.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            raise ImporterError(f"{_show(current)} is a symlink; flightdeck writes its generated manifests only into real folders")
        current.mkdir(exist_ok=True)


def _remove_stale(out: Path, keep: set[Path]) -> None:
    """Remove generated manifests not in `keep`, then empty folders, under `out` only."""
    if not out.is_dir():
        return
    for directory, dirs, files in os.walk(out, topdown=False):  # never follows symlinks
        here = Path(directory)
        for name in files:
            path = here / name
            stale = name.endswith(SUFFIX) and path not in keep
            if stale or (name.startswith(_TEMP_PREFIX) and name.endswith(_TEMP_SUFFIX)):  # or left by a crash
                path.unlink()
        if here != out:
            try:
                here.rmdir()
            except OSError:
                pass  # not empty: something is still in it


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
