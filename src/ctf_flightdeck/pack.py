"""Installing a solver pack: fetch it, set it up, and point the config at it.

A pack is a folder of L1 engines (docs/SOLVERS.md). One that needs more than its files (a
Python environment, tools, a Docker image for its engines) says so in a `pack.toml` at its
top:

    name = "flightdeck-solvers"          # required: lower-case letters, digits, _ . -
    version = "1.0.0"                    # optional
    description = "..."                  # optional, one line
    engines = "flightdeck"               # optional: the folder searched for *.manifest.toml (default: the whole pack)
    tools = ["tshark", "binwalk"]        # optional: the programs its engines call, by name: doctor says which are missing

    [setup]                              # optional: what makes the pack ready on this machine
    command = "./setup.sh"               # a file of the pack and its arguments, run in the pack's folder

    [image]                              # optional: the image its engines run in when lanes run in Docker
    tag = "ctf-flightdeck-pack:1"
    dockerfile = "flightdeck/Dockerfile" # inside the pack
    context = "."                        # inside the pack; default: the Dockerfile's folder

    [lanes]                              # optional: the pack as a toolkit for the lanes' models
    note = "flightdeck/LANE.md"          # what a lane's brief says about it; {pack} is the pack's folder

An unknown key is an error. A pack with no pack.toml needs no setup and runs in the lane image.

`tools` is for the player, not for the run: `flightdeck doctor` and `flightdeck pack info` name
the listed programs that are missing where the engines run (missing_on_host: this machine's
PATH, its absolute folders only, as an engine's programs are found; missing_in_image: the
image's PATH, asked of one throwaway container with no network, never pulled). A run looks
nothing up from this list and never stops for it: an engine whose own program is missing says
so when it runs (l1/runner.py), and a pack with one engine for everything (P31) finds its tools
itself. Nothing is installed.

install() does, in order: fetch (a git clone into flightdeck's packs folder, or an update of
the clone that is there; a local folder is used where it is), read pack.toml, run the setup
command, build the image, and write `[l1] pack` (and `image`) into the config. Each step is a
function of its own here; the CLI (pack_cli.py) asks the player before the steps that run the
pack's code.

A pack is code the player chooses to run: its setup command runs on this machine as the
player, and its engines read challenge files. flightdeck says what it will run before it
runs it, never fetches a pack by itself, and never runs a setup command it was not asked to.
What a pack.toml says is shown through untrusted(): it comes from the network.

The config is edited as text, so its comments stay: only the `pack` and `image` lines of the
[l1] table change (the table is added when it is missing). The edited file must load; when it
does not, the file is put back as it was and the error says so.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .text import untrusted

PACK_FILE = "pack.toml"
DEFAULT_SOURCE = "https://github.com/MFisher14/ctf-flightdeck"  # flightdeck's own repository holds its solver pack
DEFAULT_SUBDIR = "packs/solvers"  # in that folder of it, which the PyPI package leaves out
DEFAULT_NAME = "flightdeck-solvers"
DATA_ENV = "XDG_DATA_HOME"
MAX_BYTES = 64 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_TOP = ("name", "version", "description", "engines", "tools", "setup", "image", "lanes")
TOOL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,63}")  # a program's name: no path, and nothing an option could be
MAX_TOOLS = 200
LOOKUP_TIMEOUT = 120.0  # seconds docker has to start a container of the image and answer
_LANES = ("note",)
MAX_NOTE = 3000  # characters of a pack's note in a lane's brief: it is in every turn's context
_SETUP = ("command",)
_IMAGE = ("tag", "dockerfile", "context")
_URL = re.compile(r"(https://|ssh://|file://|git@)[^\s]+")


class PackError(Exception):
    """A pack cannot be fetched, read, set up or written into the config. One line, for the player."""


@dataclass(frozen=True)
class Image:
    tag: str
    dockerfile: Path  # absolute, inside the pack
    context: Path  # absolute, inside the pack


@dataclass(frozen=True)
class PackInfo:
    root: Path
    name: str
    version: str = ""
    description: str = ""
    setup: tuple[str, ...] = ()  # the setup command's argv; its first word is a file of the pack, absolute
    image: Image | None = None
    lane_note: Path | None = None  # the file whose text a lane's brief gets under [l1] lane_tools
    tools: tuple[str, ...] = ()  # the programs its engines call, as pack.toml lists them


def packs_folder() -> Path:
    """Where fetched packs live: $XDG_DATA_HOME/ctf-flightdeck/packs when that is an absolute
    path, else ~/.local/share/ctf-flightdeck/packs."""
    base = os.environ.get(DATA_ENV, "")
    if os.path.isabs(base):
        return Path(base) / "ctf-flightdeck" / "packs"
    try:
        return Path.home() / ".local" / "share" / "ctf-flightdeck" / "packs"
    except RuntimeError:
        raise PackError(f"there is no home folder to keep packs in; set {DATA_ENV} to a folder") from None


def is_url(source: str) -> bool:
    return bool(_URL.fullmatch(source))


def folder_name(source: str) -> str:
    """The folder a fetched pack gets: the last part of its address, without .git."""
    last = source.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    name = re.sub(r"\.git$", "", last).lower()
    name = re.sub(r"[^a-z0-9_.-]", "-", name).strip(".-")
    if not NAME.fullmatch(name or ""):
        raise PackError(f"cannot name a folder after {_show(source)}; pass --name")
    return name


def own_pack() -> Path | None:
    """flightdeck's own solver pack beside this source tree (a git checkout of flightdeck, or
    an editable install), or None: the PyPI package does not hold it."""
    here = Path(__file__).resolve().parents[2] / DEFAULT_SUBDIR
    return here if (here / PACK_FILE).is_file() else None


def default_ref() -> str:
    """The tag of this flightdeck's release: its own pack is fetched as it was released with it."""
    from . import __version__

    return f"v{__version__}"


def fetch(source: str, *, ref: str | None = None, name: str | None = None, into: Path | None = None,
          subdir: str | None = None) -> tuple[Path, str]:
    """(the pack's folder, what was done). `source` is a git address (https://, ssh://,
    git@host:path, file://): cloned into the packs folder, or, when its clone is there
    already, updated (fast-forward only: a clone the player changed is left alone, with the
    reason). `ref` is a branch or tag. `subdir`: the pack is that folder of the repository,
    and only that folder is checked out (a sparse clone)."""
    if subdir is not None:
        parts = Path(subdir).parts
        if not subdir or os.path.isabs(subdir) or ".." in parts or subdir.startswith("-") or any(c.isspace() for c in subdir):
            raise PackError(f"--subdir {_show(subdir)} must be a folder's path inside the repository")
    if not is_url(source):
        raise PackError(f"{_show(source)} is not a git address (https://, ssh://, git@host:path or file://) or an existing folder")
    if ref is not None and (not ref or ref.startswith("-") or any(c.isspace() for c in ref)):
        raise PackError(f"--ref {_show(ref)} is not a branch or tag name")
    if name is not None and not NAME.fullmatch(name):
        raise PackError(f"--name {_show(name)} must be lower-case letters, digits, _ . or -")
    git = shutil.which("git")
    if git is None:
        raise PackError("fetching a pack needs git, which is not on PATH")
    target = (into if into is not None else packs_folder()) / (name or folder_name(source))
    if target.exists():
        if not (target / ".git").exists():
            raise PackError(f"{target} is there already and is not a git clone; remove it, or pass --name")
        origin = _git(git, ["-C", str(target), "remote", "get-url", "origin"], "read the clone's origin").strip()
        if origin != source:
            raise PackError(f"{target} is a clone of {_show(origin)}, not of {_show(source)}; remove it, or pass --name")
        if ref is not None:
            _git(git, ["-C", str(target), "fetch", "--depth", "1", "origin", ref], f"fetch {ref}")
            _git(git, ["-C", str(target), "checkout", "--quiet", "FETCH_HEAD"], f"check out {ref}")
            return _pack_in(target, subdir), f"updated to {ref}"
        _git(git, ["-C", str(target), "pull", "--ff-only", "--quiet"], "update the clone")
        return _pack_in(target, subdir), "updated"
    target.parent.mkdir(parents=True, exist_ok=True)
    argv = ["clone", "--quiet", "--depth", "1"]
    if ref is not None:
        argv += ["--branch", ref]
    if subdir is not None:
        argv += ["--filter=blob:none", "--sparse"]
    try:
        _git(git, [*argv, "--", source, str(target)], "clone the pack")
        if subdir is not None:
            _git(git, ["-C", str(target), "sparse-checkout", "set", "--", subdir], f"check out {subdir}")
        return _pack_in(target, subdir), "fetched"
    except PackError:
        shutil.rmtree(target, ignore_errors=True)  # a half-made clone would stop the next try
        raise


def _pack_in(clone: Path, subdir: str | None) -> Path:
    if subdir is None:
        return clone
    folder = clone / subdir
    if folder.is_symlink() or not folder.is_dir():
        raise PackError(f"the repository has no folder {_show(subdir)}")
    return folder


def _git(git: str, argv: list[str], what: str) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # a private address fails; it never waits for a password
    done = subprocess.run([git, *argv], capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL)
    if done.returncode != 0:
        lines = (done.stderr or done.stdout).strip().splitlines()
        raise PackError(f"git could not {what}: {_show(lines[-1]) if lines else f'exit {done.returncode}'}")
    return done.stdout


def read(root: Path) -> PackInfo:
    """The pack at `root`, from its pack.toml; a pack without one is named after its folder."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise PackError(f"{root} is not a folder")
    path = root / PACK_FILE
    if not path.exists():
        return PackInfo(root, root.name)
    if path.is_symlink() or not path.is_file():
        raise PackError(f"{path} is not a regular file")
    if path.stat().st_size > MAX_BYTES:
        raise PackError(f"{path} is larger than {MAX_BYTES} bytes")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise PackError(f"{path} is not valid TOML: {_show(str(exc))}") from None
    _known(path, "", data, _TOP)
    name = data.get("name")
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise PackError(f"{path}: name is required: lower-case letters, digits, _ . or -, at most 64")
    version, description = data.get("version", ""), data.get("description", "")
    for key, value in (("version", version), ("description", description)):
        if not isinstance(value, str) or "\n" in value or len(value) > 300:
            raise PackError(f"{path}: {key} must be one line of at most 300 characters")
    if "engines" in data:
        from .l1.manifest import ManifestError, engines_folder

        try:
            engines_folder(root)
        except ManifestError as exc:
            raise PackError(str(exc)) from None
    tools = _tools(path, data.get("tools", []))
    setup: tuple[str, ...] = ()
    if "setup" in data:
        table = _table(path, "setup", data["setup"], _SETUP)
        command = table.get("command")
        if not isinstance(command, str) or not command.strip():
            raise PackError(f"{path}: setup.command must be a command line")
        try:
            words = shlex.split(command)
        except ValueError as exc:
            raise PackError(f"{path}: setup.command cannot be split into words: {exc}") from None
        setup = (str(_inside(path, "setup.command", root, words[0], file=True)), *words[1:])
    image = None
    if "image" in data:
        table = _table(path, "image", data["image"], _IMAGE)
        tag = table.get("tag")
        if not isinstance(tag, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_./-]*:[A-Za-z0-9_][A-Za-z0-9_.-]*", tag):
            raise PackError(f"{path}: image.tag must be a docker image name with a tag, such as my-pack:1")
        dockerfile = table.get("dockerfile")
        if not isinstance(dockerfile, str) or not dockerfile:
            raise PackError(f"{path}: image.dockerfile is required: the Dockerfile's path inside the pack")
        docker_path = _inside(path, "image.dockerfile", root, dockerfile, file=True)
        context = table.get("context")
        if context is not None and not isinstance(context, str):
            raise PackError(f"{path}: image.context must be a folder's path inside the pack")
        context_path = _inside(path, "image.context", root, context, file=False) if context is not None else docker_path.parent
        image = Image(tag, docker_path, context_path)
    note = None
    if "lanes" in data:
        table = _table(path, "lanes", data["lanes"], _LANES)
        rel = table.get("note")
        if not isinstance(rel, str) or not rel:
            raise PackError(f"{path}: lanes.note is required: a text file's path inside the pack")
        note = _inside(path, "lanes.note", root, rel, file=True)
    return PackInfo(root, name, version, description, setup, image, note, tools)


def _tools(path: Path, value: object) -> tuple[str, ...]:
    """pack.toml's `tools`: a list of distinct program names."""
    if not isinstance(value, list) or len(value) > MAX_TOOLS:
        raise PackError(f"{path}: tools must be a list of at most {MAX_TOOLS} program names, such as [\"tshark\", \"binwalk\"]")
    for i, tool in enumerate(value):
        if not isinstance(tool, str) or not TOOL.fullmatch(tool):
            shown = _show(tool) if isinstance(tool, str) else type(tool).__name__
            raise PackError(f"{path}: tools[{i}] ({shown}) must be a program's name as it is typed (letters, digits, "
                            "_ . + -, at most 64, not starting with . + or -), not a path")
        if tool in value[:i]:
            raise PackError(f"{path}: tools lists {tool} twice")
    return tuple(value)


def missing_on_host(tools: Sequence[str], path: str | None = None) -> list[str]:
    """The `tools` that are not programs on this machine's PATH (`path`, by default this
    process's), in their order: looked up in its absolute folders only, as an engine's
    programs are (l1/runner.py safe_path, find_program)."""
    from .l1.runner import find_program, safe_path

    folders = safe_path(path)
    return [tool for tool in tools if find_program(tool, folders) is None]


def missing_in_image(image: str, tools: Sequence[str], *, docker: str | None = None) -> list[str]:
    """The `tools` that are not programs on the PATH of the docker image `image`, in their
    order: one throwaway container (`docker run --rm`, never pulled, no network) runs the
    lookup an engine's container runs (l1/container.py), on the image's PATH with only its
    absolute folders. PackError when docker or the image does not answer it (no docker, the
    image is not on this machine or has no bash, no answer in LOOKUP_TIMEOUT seconds): what is
    missing is then not known, and nothing is guessed."""
    from .l1.container import _LOOKUP
    from .l1.runner import safe_path

    tools = list(dict.fromkeys(tools))
    for tool in tools:
        if not TOOL.fullmatch(tool):
            raise PackError(f"{_show(tool)} is not a program's name")
    if not tools:
        return []
    docker = docker or shutil.which("docker", path=safe_path())
    if docker is None:
        raise PackError(f"docker is not on PATH, so the image {_show(image)} cannot be asked for its programs")
    argv = [docker, "run", "--rm", "--pull", "never", "--network", "none", "--entrypoint", "bash", image,
            "-c", _LOOKUP, "flightdeck-pack", *tools]
    try:
        done = subprocess.run(argv, capture_output=True, timeout=LOOKUP_TIMEOUT, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        raise PackError(f"docker did not say within {LOOKUP_TIMEOUT:g} s which programs the image {_show(image)} has") from None
    except OSError as exc:
        raise PackError(f"docker cannot be run ({exc.strerror or type(exc).__name__})") from None
    parts = done.stdout.decode("utf-8", "replace").split("\0")
    if done.returncode != 0 or len(parts) != len(tools) + 2 or parts[-1]:
        lines = done.stderr.decode("utf-8", "replace").strip().splitlines()
        said = _show(lines[-1]) if lines else f"docker run exited {done.returncode}"
        raise PackError(f"the image {_show(image)} did not say which programs it has (it needs bash): {said}")
    return [tool for tool, at in zip(tools, parts[1:-1]) if not at.startswith("/")]


def lane_note(info: PackInfo, seen_at: str | None = None) -> str:
    """What a lane's brief says about the pack as a toolkit: the text of its [lanes] note, with
    {pack} replaced by the folder a lane sees the pack at. The pack's author wrote it, and the
    player chose the pack: it goes in the brief as flightdeck's own words do, outside the
    challenge's fence. Control characters are taken out and it is cut at MAX_NOTE."""
    if info.lane_note is None:
        raise PackError(f"the pack {info.name} is no toolkit for lanes (no [lanes] note in its {PACK_FILE})")
    try:
        text = info.lane_note.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PackError(f"cannot read the pack's lane note {info.lane_note}: {exc}") from None
    text = untrusted(text.strip()).replace("{pack}", seen_at if seen_at is not None else str(info.root))
    if not text:
        raise PackError(f"the pack's lane note {info.lane_note} is empty")
    return text if len(text) <= MAX_NOTE else text[:MAX_NOTE - 3] + "..."


def _known(path: Path, where: str, table: dict, keys: tuple[str, ...]) -> None:
    unknown = [key for key in table if key not in keys]
    if unknown:
        raise PackError(f"{path}: {where + '.' if where else ''}{_show(unknown[0])} is not a key flightdeck knows (known: {', '.join(keys)})")


def _table(path: Path, name: str, value: object, keys: tuple[str, ...]) -> dict:
    if not isinstance(value, dict):
        raise PackError(f"{path}: [{name}] must be a table")
    _known(path, name, value, keys)
    return value


def _inside(path: Path, key: str, root: Path, rel: str, *, file: bool) -> Path:
    """`rel` as an absolute path that is inside the pack, exists, and is no symlink out of it."""
    if os.path.isabs(rel) or rel.startswith("-"):
        raise PackError(f"{path}: {key} must be a path inside the pack, got {_show(rel)}")
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise PackError(f"{path}: {key} {_show(rel)} leaves the pack")
    if not (target.is_file() if file else target.is_dir()):
        raise PackError(f"{path}: {key} {_show(rel)} is not a {'file' if file else 'folder'} of the pack")
    return target


def setup_command(info: PackInfo) -> list[str]:
    return list(info.setup)


def image_command(info: PackInfo, lane_image: str, *, docker: str | None = None) -> list[str]:
    """The `docker build` argv for the pack's image. The Dockerfile gets the lane image as the
    build argument LANE_IMAGE, so a pack can build on it (`ARG LANE_IMAGE` / `FROM $LANE_IMAGE`)."""
    if info.image is None:
        raise PackError(f"the pack {info.name} has no image (no [image] table in its {PACK_FILE})")
    return [docker or shutil.which("docker") or "docker", "build", "--tag", info.image.tag, "--file", str(info.image.dockerfile),
            "--build-arg", f"LANE_IMAGE={lane_image}", str(info.image.context)]


# ---------------------------------------------------------------- the config's [l1] table

_HEADER = re.compile(r"^\s*\[([^\]]+)\]\s*(#.*)?$")


def set_l1(text: str, pack: Path, image: str | None, lane_tools: bool | None = None) -> str:
    """`text` (a config file) with `[l1] pack` set to `pack`, and `image` set to `image` (None:
    an image line that is there is commented out). `lane_tools`: True sets it, False comments
    a line that is there out, None leaves it. Everything else stays as it is, comments
    included; a commented `# pack = ...` line is where the value goes."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if (m := _HEADER.match(line)) and m.group(1).strip() == "l1"), None)
    if start is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines += ["[l1]"]
        start = len(lines) - 1
    end = next((i for i in range(start + 1, len(lines)) if _HEADER.match(lines[i])), len(lines))
    body = lines[start + 1:end]
    body = _set_key(body, "pack", f'pack = {_toml(str(pack))}')
    body = _set_key(body, "image", f"image = {_toml(image)}" if image is not None else None)
    if lane_tools is not None:
        body = _set_key(body, "lane_tools", "lane_tools = true" if lane_tools else None)
    out = "\n".join(lines[:start + 1] + body + lines[end:])
    return out + "\n"


def _set_key(body: list[str], key: str, line: str | None) -> list[str]:
    live = re.compile(rf"^\s*{key}\s*=")
    dead = re.compile(rf"^\s*#\s*{key}\s*=")
    at = next((i for i, text in enumerate(body) if live.match(text)), None)
    if at is not None:
        if line is None:
            return body[:at] + ["# " + body[at].lstrip()] + body[at + 1:]
        return body[:at] + [line] + body[at + 1:]
    if line is None:
        return body
    at = next((i for i, text in enumerate(body) if dead.match(text)), None)
    if at is not None:
        return body[:at + 1] + [line] + body[at + 1:]  # under the example line, which stays
    last = next((i for i in range(len(body) - 1, -1, -1) if body[i].strip()), -1)
    return body[:last + 1] + [line] + body[last + 1:]


def _toml(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_config(path: Path, pack: Path, image: str | None, lane_tools: bool | None = None) -> None:
    """Point the config at `path` to the pack. The edited file must load, or it is put back."""
    from .config import ConfigError, load_config

    try:
        before = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise PackError(f"there is no config at {path}: run `flightdeck init` first, then this again") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise PackError(f"cannot read the config {path}: {exc}") from None
    after = set_l1(before, pack, image, lane_tools)
    if after == before:
        return
    path.write_text(after, encoding="utf-8")
    try:
        loaded = load_config(path)
        if loaded.l1.pack != pack or loaded.l1.image != image or (lane_tools is not None and loaded.l1.lane_tools != lane_tools):
            raise ConfigError(f"{path}: [l1] did not take the pack")
    except ConfigError as exc:
        path.write_text(before, encoding="utf-8")
        raise PackError(f"the config did not load with the pack in it, so it was put back as it was: {exc}") from None


def _show(text: str) -> str:
    return untrusted(str(text), one_line=True)
