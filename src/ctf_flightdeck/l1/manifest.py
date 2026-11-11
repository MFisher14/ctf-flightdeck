"""Manifests: one sidecar file per L1 engine, `<anything>.manifest.toml`, anywhere in a pack.

    id = "decode.base64_layers"          # required; unique in the pack; [a-z0-9][a-z0-9_.-]*
    entry = "decode_layers.py:solve"     # required: "<file>.py:<function>" or "cli:<command ...>"
    tags = ["crypto", "decode"]          # optional, lower-case
    needs_tools = ["zsteg"]              # optional: executables that must be on PATH
    timeout_seconds = 60                 # optional, 1..600
    output = "result"                    # optional: "result" (the default) or "text"

    [[routes]]                           # one or more; a route matches when all it states holds
    category = ["cry"]                   # the board's short codes: web cry rev pwn for misc osint ...
    keywords = ["base64"]                # lower-case substrings of the challenge name + description
    files = ["ext:.txt", "magic:PK", "magic:0x1f8b", "name:*.pcap"]
    priority = 60                        # 0..100, default 50

Entries. A python entry names a .py file and a function `fn(challenge_dir: Path)` that
returns a SolverResult; the file must lie inside the manifest's folder (a relative path,
no `..`, not leaving it through a symlink). A cli entry is a command, split like a shell
line; the challenge directory is appended to it when it runs. The command runs in a copy
of the challenge, so a word of it that names a file in the manifest's folder (`solve.sh`,
`tools/x.py`) is run as that file: the runner passes its absolute path.

Outputs. "result": the last non-empty line the engine prints is a SolverResult as JSON (a
python entry gets this for free from the boot script). "text": free text; every match of
the event's flag format in it becomes a candidate flag.

Generated manifests. The importer writes manifests for plain scripts into
`<folder>/.flightdeck/generated/`. Paths in those start from `<folder>`, the folder they
describe, not from the generated directory.

discover() walks a pack for manifests, skipping hidden files and directories and
`.flightdeck/`, except `.flightdeck/generated/`. It never follows a symlinked directory.
Every problem is a ManifestError naming the file and the key: an unknown key is an error,
so a typo fails loudly instead of quietly never matching.
"""

from __future__ import annotations

import os
import re
import shlex
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..agent.workspace import PRIVATE
from ..platform.manual import category_code
from ..text import untrusted

SUFFIX = ".manifest.toml"
GENERATED = "generated"  # <folder>/.flightdeck/generated/: the importer's manifests
MAX_BYTES = 256 * 1024
MAX_ID = 100
ID = re.compile(r"[a-z0-9][a-z0-9_.-]*")
TOP_KEYS = ("id", "entry", "tags", "needs_tools", "timeout_seconds", "output", "routes")
ROUTE_KEYS = ("category", "keywords", "files", "priority")
OUTPUTS = ("result", "text")
FILE_KINDS = ("ext", "magic", "name")
MAGIC_BYTES = 4096  # how much of a file a magic: pattern can see
DEFAULT_TIMEOUT = 60
MAX_TIMEOUT = 600
DEFAULT_PRIORITY = 50


class ManifestError(Exception):
    """A manifest (or a pack) cannot be used. The message names the file and the dotted key."""

    def __init__(self, path: Path | None, key: str | None, problem: str) -> None:
        self.path = path
        self.key = key
        self.problem = problem
        where = _show(path) if path is not None else "manifest"
        super().__init__(f"{where}: {key}: {problem}" if key else f"{where}: {problem}")


@dataclass(frozen=True)
class Route:
    category: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    files: tuple[str, ...] = ()  # "ext:.x" | "magic:<text>" | "magic:0x<hex>" | "name:<glob>"
    priority: int = DEFAULT_PRIORITY


@dataclass(frozen=True)
class Entry:
    kind: str  # "python" | "cli"
    path: str | None  # python: the .py path relative to the manifest's folder (see Manifest.base)
    function: str | None  # python: the function name
    argv: tuple[str, ...] = ()  # cli: the command (shell-split)


@dataclass(frozen=True)
class Manifest:
    id: str
    entry: Entry
    tags: tuple[str, ...]
    needs_tools: tuple[str, ...]
    timeout_seconds: int
    output: str
    routes: tuple[Route, ...]
    path: Path  # the sidecar file (absolute)

    @property
    def base(self) -> Path:
        """Where the entry's relative paths start: the manifest's folder, or for a generated
        manifest the folder the importer was run on."""
        return generated_root(self.path) or self.path.parent

    @property
    def entry_file(self) -> Path | None:
        """A python entry's file, absolute; None for a cli entry."""
        return self.base / self.entry.path if self.entry.kind == "python" and self.entry.path else None


def generated_root(path: Path) -> Path | None:
    """The folder whose `.flightdeck/generated/` holds `path`, or None if it is not in one."""
    for parent in Path(path).parents:
        if parent.name == GENERATED and parent.parent.name == PRIVATE:
            return parent.parent.parent
    return None


def pack_file(word: str, base: Path) -> Path | None:
    """The file in `base` that a word of a cli entry names (absolute), or None when the word
    is not a relative path to an existing file there (an option, a command on PATH, an
    absolute path, anything with ..)."""
    if not word or word.startswith(("-", "/")) or "\x00" in word:
        return None
    rel = PurePosixPath(word)
    if not rel.parts or ".." in rel.parts:
        return None
    candidate = Path(base) / rel
    return candidate if candidate.is_file() else None


def load(path: Path) -> Manifest:
    """Read and check one manifest."""
    path = Path(path).expanduser().absolute()
    data = _read(path)
    unknown = [key for key in data if key not in TOP_KEYS]
    if unknown:
        raise ManifestError(path, unknown[0], f"unknown key (known: {', '.join(TOP_KEYS)})")
    base = generated_root(path) or path.parent

    engine_id = _required(path, data, "id")
    if not isinstance(engine_id, str) or not ID.fullmatch(engine_id) or len(engine_id) > MAX_ID:
        raise ManifestError(
            path, "id",
            f"must be lower-case letters, digits and _ . - (not first), at most {MAX_ID} characters, "
            f"got {_value(engine_id)}",
        )
    entry = _entry(path, _required(path, data, "entry"), base)
    tags = _words(path, "tags", data.get("tags", []), lower=True)
    needs = _words(path, "needs_tools", data.get("needs_tools", []))
    for i, tool in enumerate(needs):
        if "/" in tool:
            raise ManifestError(path, f"needs_tools[{i}]", f"{_value(tool)} must be a command name on PATH, not a path")
    timeout = data.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not (_is_int(timeout) and 1 <= timeout <= MAX_TIMEOUT):
        raise ManifestError(path, "timeout_seconds", f"must be a whole number of seconds, 1..{MAX_TIMEOUT}, got {_value(timeout)}")
    output = data.get("output", "result")
    if output not in OUTPUTS:
        raise ManifestError(path, "output", f'must be "result" or "text", got {_value(output)}')
    routes = _routes(path, data.get("routes"))
    return Manifest(engine_id, entry, tags, needs, timeout, output, routes, path)


def discover(pack: Path) -> list[Manifest]:
    """Every engine in the pack, sorted by id. Two manifests with one id is an error."""
    root = Path(pack).expanduser().absolute()
    if not root.is_dir():
        raise ManifestError(root, None, "is not a folder" if root.exists() else "no such pack folder")
    manifests = [load(path) for path in manifest_files(root)]
    seen: dict[str, Path] = {}
    for manifest in manifests:
        if manifest.id in seen:
            raise ManifestError(manifest.path, "id", f"{manifest.id} is also the id in {_show(seen[manifest.id])}")
        seen[manifest.id] = manifest.path
    return sorted(manifests, key=lambda m: m.id)


def manifest_files(pack: Path, *, generated: bool = True) -> list[Path]:
    """Every *.manifest.toml under pack, sorted by path. Skips hidden files and directories
    and `.flightdeck/`, except `.flightdeck/generated/` when generated=True; never follows a
    symlinked directory."""
    return sorted(_walk(Path(pack).absolute(), generated))


def _walk(root: Path, generated: bool) -> Iterator[Path]:
    pending: list[tuple[Path, bool]] = [(root, False)]  # (directory, inside .flightdeck)
    while pending:
        directory, private = pending.pop()
        try:
            with os.scandir(directory) as listing:
                entries = sorted(listing, key=lambda e: e.name)
        except OSError as exc:
            raise ManifestError(directory, None, f"cannot list it ({exc.strerror})") from None
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                if private:
                    if entry.name == GENERATED and generated:
                        pending.append((Path(entry.path), False))
                elif entry.name == PRIVATE:
                    pending.append((Path(entry.path), True))
                elif not entry.name.startswith("."):
                    pending.append((Path(entry.path), False))
            elif not private and entry.name.endswith(SUFFIX) and not entry.name.startswith("."):
                if entry.is_file():  # a symlinked manifest is the player's to follow
                    yield Path(entry.path)


# ---------------------------------------------------------------- parts of a manifest


def _read(path: Path) -> dict:
    try:
        size = path.stat().st_size
        if size > MAX_BYTES:
            raise ManifestError(path, None, f"is over {MAX_BYTES // 1024} KB, too big for a manifest")
        raw = path.read_bytes()
    except FileNotFoundError:
        raise ManifestError(path, None, "no such file") from None
    except OSError as exc:
        raise ManifestError(path, None, f"cannot read it ({exc.strerror})") from None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ManifestError(path, None, "is not UTF-8 text") from None
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(path, None, f"is not valid TOML ({_show(exc)})") from None


def _required(path: Path, data: dict, key: str) -> object:
    if key not in data:
        raise ManifestError(path, key, "is missing")
    return data[key]


def _entry(path: Path, value: object, base: Path) -> Entry:
    shapes = 'must be "<file>.py:<function>" or "cli:<command>"'
    if not isinstance(value, str) or not value.strip():
        raise ManifestError(path, "entry", f"{shapes}, got {_value(value)}")
    if "\x00" in value:
        raise ManifestError(path, "entry", "contains a NUL character")
    if value.startswith("cli:"):
        return _cli_entry(path, value[len("cli:"):], base)
    file, sep, function = value.rpartition(":")
    if not sep or not file:
        raise ManifestError(path, "entry", f"{shapes}, got {_value(value)}")
    if not function.isidentifier():
        raise ManifestError(path, "entry", f"{_value(function)} is not a python function name")
    if not file.endswith(".py"):
        raise ManifestError(path, "entry", f"a python entry names a .py file, got {_value(file)}")
    rel = PurePosixPath(file)
    if rel.is_absolute() or ".." in rel.parts:
        raise ManifestError(path, "entry", f"{_value(file)} must be a relative path inside the pack, with no ..")
    full = base / rel
    if not full.is_file():
        raise ManifestError(path, "entry", f"{_value(file)} {'is not a file' if full.exists() else 'does not exist'} in {_show(base)}")
    if not full.resolve().is_relative_to(base.resolve()):
        raise ManifestError(path, "entry", f"{_value(file)} leaves {_show(base)} through a symlink")
    return Entry("python", rel.as_posix(), function)


def _cli_entry(path: Path, command: str, base: Path) -> Entry:
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise ManifestError(path, "entry", f"the command does not split like a shell line ({exc})") from None
    if not argv:
        raise ManifestError(path, "entry", 'the command after "cli:" is empty')
    program = argv[0]
    if "/" in program and not program.startswith("/"):
        rel = PurePosixPath(program)
        if ".." in rel.parts:
            raise ManifestError(path, "entry", f"{_value(program)} must be inside the pack, with no ..")
        full = base / rel
        if not full.is_file():
            raise ManifestError(path, "entry", f"{_value(program)} does not exist in {_show(base)}")
        if not os.access(full, os.X_OK):
            raise ManifestError(path, "entry", f"{_value(program)} is not executable (chmod +x it, or run it with its interpreter)")
    return Entry("cli", None, None, tuple(argv))


def _words(path: Path, key: str, value: object, *, lower: bool = False) -> tuple[str, ...]:
    """A list of non-empty strings without whitespace (lower-case when lower=True)."""
    if not isinstance(value, list):
        raise ManifestError(path, key, f"must be a list of strings, got {_value(value)}")
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item or any(c.isspace() for c in item):
            raise ManifestError(path, f"{key}[{i}]", f"must be a non-empty string with no spaces, got {_value(item)}")
        if lower and item != item.lower():
            raise ManifestError(path, f"{key}[{i}]", f"must be lower-case, got {_value(item)}")
        out.append(item)
    return tuple(out)


def _routes(path: Path, value: object) -> tuple[Route, ...]:
    if value is None:
        raise ManifestError(path, "routes", "is missing: an engine needs at least one [[routes]] table")
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ManifestError(path, "routes", "must be one or more [[routes]] tables")
    if not value:
        raise ManifestError(path, "routes", "is empty: an engine needs at least one [[routes]] table")
    return tuple(_route(path, f"routes[{i}]", item) for i, item in enumerate(value))


def _route(path: Path, where: str, table: dict) -> Route:
    unknown = [key for key in table if key not in ROUTE_KEYS]
    if unknown:
        raise ManifestError(path, f"{where}.{unknown[0]}", f"unknown key (known: {', '.join(ROUTE_KEYS)})")
    conditions = {}
    for key in ("category", "keywords", "files"):
        if key not in table:
            conditions[key] = ()
            continue
        raw = table[key]
        if not isinstance(raw, list) or not raw:
            raise ManifestError(path, f"{where}.{key}", f"must be a non-empty list of strings (leave the key out to not use it), got {_value(raw)}")
        items: list[str] = []
        for i, item in enumerate(raw):
            if not isinstance(item, str) or not item.strip():
                raise ManifestError(path, f"{where}.{key}[{i}]", f"must be a non-empty string, got {_value(item)}")
            items.append(_condition(path, f"{where}.{key}[{i}]", key, item))
        conditions[key] = tuple(items)
    if not any(conditions.values()):
        raise ManifestError(path, where, "has no condition (category, keywords or files), so it would never match")
    priority = table.get("priority", DEFAULT_PRIORITY)
    if not (_is_int(priority) and 0 <= priority <= 100):
        raise ManifestError(path, f"{where}.priority", f"must be a whole number 0..100, got {_value(priority)}")
    return Route(conditions["category"], conditions["keywords"], conditions["files"], priority)


def _condition(path: Path, where: str, key: str, item: str) -> str:
    if key == "category":
        if item != item.lower() or any(c.isspace() for c in item):
            raise ManifestError(path, where, f"must be a lower-case category code with no spaces, got {_value(item)}")
        code = category_code(item)
        if code != item:
            raise ManifestError(path, where, f"write the board's short code {code!r}, not {item!r}")
        return item
    if key == "keywords":
        if item != item.lower():
            raise ManifestError(path, where, f"must be lower-case (matching ignores case), got {_value(item)}")
        return item
    try:
        file_pattern(item)
    except ValueError as exc:
        raise ManifestError(path, where, str(exc)) from None
    return item


def file_pattern(pattern: str) -> tuple[str, str | bytes]:
    """("ext", ".tar.gz") | ("magic", b"...") | ("name", "*.pcap"), or ValueError saying what
    is wrong. ext is lower-cased (it matches ignoring case); magic is bytes: latin-1 text,
    or hex after 0x."""
    kind, sep, arg = pattern.partition(":")
    if not sep or kind not in FILE_KINDS:
        raise ValueError(f"{_value(pattern)} must start with ext:, magic: or name:")
    if kind == "ext":
        if len(arg) < 2 or not arg.startswith(".") or "/" in arg:
            raise ValueError(f"{_value(pattern)}: write an extension with its dot, like ext:.txt or ext:.tar.gz")
        return kind, arg.lower()
    if kind == "name":
        if not arg or "/" in arg:
            raise ValueError(f"{_value(pattern)}: write a file-name glob with no /, like name:*.pcap")
        return kind, arg
    if arg.startswith("0x"):
        digits = arg[2:]
        if len(digits) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", digits):
            raise ValueError(f"{_value(pattern)}: after magic:0x write whole bytes in hex, like magic:0x1f8b")
        magic = bytes.fromhex(digits)
    else:
        try:
            magic = arg.encode("latin-1")
        except UnicodeEncodeError:
            raise ValueError(f"{_value(pattern)}: magic text must be latin-1 (write other bytes as magic:0x<hex>)") from None
        if not magic:
            raise ValueError(f"{_value(pattern)}: write the bytes a file starts with, like magic:PK")
    if len(magic) > MAGIC_BYTES:
        raise ValueError(f"magic is {len(magic)} bytes; a file's first {MAGIC_BYTES} bytes are compared")
    return kind, magic


# ---------------------------------------------------------------- helpers


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _value(value: object) -> str:
    """A value from a manifest for an error message: on one line, cut short."""
    text = untrusted(repr(value), one_line=True)
    return text if len(text) <= 60 else text[:57] + "..."


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)
