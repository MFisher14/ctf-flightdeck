"""A plugin's board: flightdeck writes what a pull lists into a folder board, never the plugin.

The plugin downloads a pull's files into a staging folder and lists the challenges; this
module builds each new challenge's folder (a challenge.json of the folder board's own keys,
and the files moved in), reads it back with the folder board's own loader, and only then
moves it into the board. A challenge that does not pass is left out and named; the others
land. What a plugin lists is thus checked as any untrusted board is: no path may leave the
staging folder, no link is followed, and nothing is run.

The board folder holds plugin.json (STATE_FILE): which plugin pulled it, from which address,
and each board id's ref, the platform's own id for the challenge that a submit is sent with:

    {"format": 1, "plugin": "myctf", "url": "https://ctf.example.org", "refs": {"warm-up": "17"}}

A folder that holds another plugin's board, a board from another address, or challenges
flightdeck did not pull through the plugin is refused: flags would go to the wrong place.
A second pull adds only the refs the board does not have yet.

The same writer serves the built-in http platform (platform/http.py), whose caller makes the
three calls itself: its board's record says "plugin": "http", a name no plugin can take, and
the messages here name it by the caller's own label.

What one pull may do is bounded: an answer lists at most plugins.call.MAX_CHALLENGES
challenges, MAX_PROBLEMS of those left out are named and the rest counted, and the folders are
made in a thread, so a run's console and lanes go on while a large board lands.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ..addchallenge import AddError, slug
from ..platform.ctfd import MAX_FILE_BYTES
from ..platform.manual import CHALLENGE_FILE, CHALLENGE_KEYS, MAX_ID, BoardError, load_challenge
from ..text import untrusted
from .call import MAX_SHOWN, PLUGIN_PULL, REF_RULE, PlatformCaller, plugin_label, scrub, valid_ref
from .manifest import PluginError

STATE_FILE = "plugin.json"
"""In the board folder: the plugin that pulled it, the address, and each board id's ref."""
FORMAT = 1
MAX_STATE_BYTES = 1_000_000  # a plugin.json bigger than this is refused
REPLY_KEYS = ("ref", "name", "category", "points", "description", "files", "urls", "solves", "max_attempts")
"""What a plugin may say of a challenge. All but `ref` are the folder board's own keys
(manual.CHALLENGE_KEYS), and are checked by its loader."""
_COPIED = tuple(key for key in REPLY_KEYS if key not in ("ref", "files"))
_STAGING = ".plugin-pull-"
MAX_PROBLEMS = 20  # challenges a pull names as left out: each is a warning in a run, so the rest are counted
_IGNORED = (".DS_Store",)
assert all(key in CHALLENGE_KEYS for key in REPLY_KEYS if key != "ref")


@dataclass
class Written:
    """What a pull did to the board."""

    added: list[str] = field(default_factory=list)  # the board ids of the new challenge folders
    problems: list[str] = field(default_factory=list)  # "<name or ref>: <why it was left out>", made safe: MAX_PROBLEMS, then how many more
    notes: list[str] = field(default_factory=list)  # what the plugin wants the player to know, made safe


def load_refs(board: Path, *, plugin: str, url: str, label: str | None = None, command: str = PLUGIN_PULL) -> dict[str, str]:
    """Board id -> ref, from the plugin.json a pull through `plugin` from `url` wrote into the
    board folder. PluginError when the folder holds no such file (nothing says where its
    flags go), or one of another plugin or another address. `label` and `command`: how the
    messages name what pulls the board and the command that does (a plugin's by default)."""
    root = Path(board).expanduser()
    path = root / STATE_FILE
    label = label or plugin_label(plugin)
    if not (path.is_symlink() or path.exists()):
        raise PluginError(
            f"{_show(root)} was not pulled by {label}, so flightdeck has nowhere to send its flags: "
            f"`{command} EVENT.toml` first, or set policies.pull to auto or confirm"
        )
    return _state(root, path, plugin, url, label)


async def pull_into(caller: PlatformCaller, board: Path, *, plugin: str, url: str) -> Written:
    """Pull the platform's challenges through `caller` and add the new ones to the board
    folder `board` (made if it is not there). PluginError when the folder is another board's;
    plugins.call.CallFailed when the plugin's pull fails. What a pull adds stays when a later
    challenge of it does not pass: each of those is named in `problems`."""
    try:
        root = Path(board).expanduser()
        root.mkdir(parents=True, exist_ok=True)
        root = root.resolve()
    except (OSError, RuntimeError) as exc:
        raise PluginError(f"{_show(board)}: cannot make the board folder ({getattr(exc, 'strerror', None) or exc})") from None
    refs = _known(root, plugin, url, caller.label)
    token = caller.token
    written = Written()
    try:
        staging = Path(tempfile.mkdtemp(prefix=_STAGING, dir=root.parent))  # beside the board: a move into it is a rename
    except OSError as exc:
        raise PluginError(f"{_show(root.parent)}: cannot make a staging folder there ({exc.strerror or exc})") from None
    try:
        files = staging / "files"
        built = staging / "built"
        files.mkdir()
        built.mkdir()
        reply = await caller.pull(files, sorted(set(refs.values())))
        written.notes = list(reply.notes)
        written.problems = list(reply.problems)  # what the caller itself left out (a file it could not fetch), before the checks here
        # The folders are made in a thread: in a run this is awaited on the console's loop, which every lane shares
        await asyncio.to_thread(_land, written, reply.challenges, root, files, built, refs, plugin, url, token)
    finally:
        await asyncio.to_thread(shutil.rmtree, staging, ignore_errors=True)
    return written


def _land(written: Written, challenges, root: Path, files: Path, built: Path, refs: dict[str, str], plugin: str, url: str,
          token: str | None) -> None:
    """Add a pull's new challenges to the board `root`, each built and read back in the staging
    area first (`files`: where the plugin put its downloads; `built`: where a folder is made).
    `written` takes what was added and what was left out; `refs` the new refs, and plugin.json
    is written as each folder lands, so a pull that is cut short leaves a board that knows
    what it has. Blocking work on files: run in a thread (pull_into)."""
    _write_state(root, plugin, url, refs)  # the folder is this plugin's board from here on, with nothing in it too
    known = frozenset(refs.values())  # on the board before this pull
    seen = set(known)
    left = 0
    for item in challenges:
        folder = None
        try:
            ref = _checked(item)
            if ref in seen:
                if ref in known:
                    continue  # on the board already
                raise _Left("its ref is another challenge's in the same pull")
            seen.add(ref)
            cid = _free_id(root, built, item["name"], ref)
            folder = built / cid
            _build(folder, item, files)
            try:
                load_challenge(folder)  # read back as any untrusted board is
            except BoardError as exc:
                raise _Left(_board_error(exc, folder, root / cid)) from None
            os.rename(folder, root / cid)
        except (_Left, OSError) as exc:
            left += 1
            if left <= MAX_PROBLEMS:
                why = str(exc) if isinstance(exc, _Left) else f"could not be written ({exc.strerror or exc})"
                written.problems.append(f"{_label(item, token)}: {scrub(why, token, limit=2 * MAX_SHOWN)}")
            if folder is not None:
                shutil.rmtree(folder, ignore_errors=True)
            continue
        refs[cid] = ref
        _write_state(root, plugin, url, refs)
        written.added.append(cid)
    if left > MAX_PROBLEMS:
        more = left - MAX_PROBLEMS
        written.problems.append(f"{more:,} more challenge{' was' if more == 1 else 's were'} left out too: the first {MAX_PROBLEMS} "
                                "are named, and they may share a cause")


class _Left(Exception):
    """Why one challenge of a pull is left out."""


def _board_error(exc: BoardError, built: Path, final: Path) -> str:
    """The folder board's own reason without the staging folder's path in it."""
    text = str(exc)
    prefix = f"{_show(built / CHALLENGE_FILE)}: "
    return text.removeprefix(prefix) if text.startswith(prefix) else text.replace(str(built), str(final))


def _label(item: Mapping, token: str) -> str:
    """What a challenge of a pull is called in a problem: its name, else its ref, made safe."""
    for key in ("name", "ref"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return scrub(value.strip(), token, limit=80)
    return "a challenge with no name and no ref"


def _checked(item: Mapping) -> str:
    """The challenge's ref, once what the plugin said of it has the keys this API knows, a ref
    and a name. The other fields are checked when the folder is read back."""
    unknown = [key for key in item if key not in REPLY_KEYS]
    if unknown:
        raise _Left(f"unknown key {', '.join(str(key)[:64] for key in unknown[:5])} (known: {', '.join(REPLY_KEYS)})")
    ref = item.get("ref")
    if not valid_ref(ref):
        raise _Left(f'"ref" must be {REF_RULE}')
    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        raise _Left('"name" must be a non-empty string')
    return ref


def _free_id(root: Path, built: Path, name: str, ref: str) -> str:
    """A board id for a new challenge: from its name, else from its ref (a name with no ASCII
    letter or digit gives none), numbered when the board has that folder already."""
    try:
        base = slug(name)
    except AddError:
        base = slug("c-" + ref)  # never empty: the c is there
    cid, n = base, 1
    while os.path.lexists(root / cid) or os.path.lexists(built / cid):
        n += 1
        tail = f"-{n}"
        cid = base[:MAX_ID - len(tail)].rstrip("-._") + tail
    return cid


def _build(folder: Path, item: Mapping, files: Path) -> None:
    """The challenge's folder, built in the staging area: its files moved in from where the
    plugin put them, and a challenge.json of the folder board's keys."""
    listed = item.get("files", [])
    if not isinstance(listed, list):
        raise _Left('"files" must be a list of paths inside the files folder the pull was given')
    folder.mkdir()
    names: list[str] = []
    for i, rel in enumerate(listed):
        source = _staged_file(files, f'"files"[{i}]', rel)
        name = source.name
        if name == CHALLENGE_FILE or name in names:
            raise _Left(f'"files"[{i}] has the name of another file of the challenge')
        os.chmod(source, 0o644)
        shutil.move(source, folder / name)
        names.append(name)
    data = {key: item[key] for key in _COPIED if key in item}
    data.setdefault("category", "misc")
    data.setdefault("points", 0)
    data["files"] = names
    (folder / CHALLENGE_FILE).write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="ascii")


def _staged_file(files: Path, where: str, rel: object) -> Path:
    """`rel` as a regular file inside the staging folder `files`, through no link, and no
    bigger than flightdeck takes by itself."""
    if not isinstance(rel, str) or not rel.strip() or "\x00" in rel:
        raise _Left(f"{where} must be a path inside the files folder the pull was given")
    path = PurePosixPath(rel)
    if path.is_absolute() or ".." in path.parts or not path.parts or os.path.isabs(rel):
        raise _Left(f"{where} must be a relative path inside the files folder the pull was given, with no ..")
    current = files
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise _Left(f"{where} is a link or inside one; flightdeck does not follow links")
    try:
        status = current.lstat()
    except OSError:
        raise _Left(f"{where} names a file the plugin did not put in the files folder") from None
    if not stat.S_ISREG(status.st_mode):
        raise _Left(f"{where} is not a regular file")
    if status.st_size > MAX_FILE_BYTES:
        raise _Left(f"{where} is over {MAX_FILE_BYTES:,} bytes, more than flightdeck takes by itself; fetch it by hand")
    return current


# ---------------------------------------------------------------------- plugin.json


def _known(root: Path, plugin: str, url: str, label: str) -> dict[str, str]:
    """The refs the board folder has, for a pull: none for a new or empty folder."""
    path = root / STATE_FILE
    if path.is_symlink() or path.exists():
        return _state(root, path, plugin, url, label)
    try:
        others = [entry.name for entry in root.iterdir() if entry.name not in _IGNORED]
    except OSError as exc:
        raise PluginError(f"{_show(root)}: cannot list it ({exc.strerror or exc})") from None
    if others:
        raise PluginError(
            f"{_show(root)} is not empty and holds no {STATE_FILE}, so it is not a board {label} pulled: "
            "use a new folder"
        )
    return {}


def _state(root: Path, path: Path, plugin: str, url: str, label: str) -> dict[str, str]:
    broken = PluginError(f"{_show(path)} is not a {STATE_FILE} flightdeck wrote: use a new folder for the board")
    if path.is_symlink() or not path.is_file():
        raise broken
    try:
        if path.stat().st_size > MAX_STATE_BYTES:
            raise broken
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PluginError(f"{_show(path)}: cannot read it ({exc.strerror or exc})") from None
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise broken from None
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise broken
    refs = data.get("refs")
    if not isinstance(refs, dict) or not all(isinstance(cid, str) and valid_ref(ref) for cid, ref in refs.items()):
        raise broken
    if data.get("plugin") != plugin or _address(data.get("url")) != _address(url):
        other = "by another plugin" if label == plugin_label(plugin) else f"by something else than {label}"
        raise PluginError(f"{_show(root)} holds a board pulled {other} or from another address: use a new folder")
    return dict(refs)


def _write_state(root: Path, plugin: str, url: str, refs: Mapping[str, str]) -> None:
    """Write plugin.json atomically (a temporary file in the same folder, then os.replace)."""
    path = root / STATE_FILE
    text = json.dumps({"format": FORMAT, "plugin": plugin, "url": _address(url), "refs": dict(sorted(refs.items()))},
                      indent=2, ensure_ascii=True) + "\n"
    try:
        fd, temp = tempfile.mkstemp(dir=root, prefix=f".{STATE_FILE}.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as out:
                out.write(text)
            os.chmod(temp, 0o644)
            os.replace(temp, path)
        except BaseException:
            Path(temp).unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise PluginError(f"{_show(path)}: cannot write it ({exc.strerror or exc})") from None


def _address(url: object) -> str | None:
    return url.rstrip("/") if isinstance(url, str) else None


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
