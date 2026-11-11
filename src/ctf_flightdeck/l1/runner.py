"""Running L1 engines: each in a fresh copy of the challenge, never in the handout itself.

run_engine() gives an engine its own workspace, by default agent.workspace.HostWorkspace at
workdir/<engine id>: prepare() copies the handout there, and the engine's command runs in
that copy with M1's sandboxing: an environment built from an allowlist (no API keys, no
tokens), its own process group, killed with its children on timeout, output captured. The
command is the entry with "." (the copy) appended:

- python entry: python3 -I <flightdeck's _boot.py> <absolute engine file> <function> .
- cli entry: its argv, where each word the manifest named as a file of the pack (settled
  when it was loaded: Entry.pack_files) becomes that file's absolute path (the command runs
  in the copy, not in the pack). A pack file that has gone since blocks the engine: the bare
  word would name the challenge's file of that name in the copy.

Programs (python3, a cli entry's program, needs_tools) are looked up on the absolute
directories of PATH only (safe_path), and the command names the program it found by its
absolute path. The engine runs with PATH cut to those directories too, so neither it nor
anything it starts finds a program through "." or an empty entry, both of which mean the
working directory: the copy of the challenge, where a handout file named python3 waits.

Then what it printed becomes a SolverResult:
- output "result": the last non-empty stdout line, read as a SolverResult (not one: unsure);
- output "text": every flag-format match in stdout, in order and deduplicated: candidate;
  no match: none;
- a timeout: unsure, "timed out after Ns"; a non-zero exit with no result: unsure, "exited
  N: <the end of its stderr>";
- tools missing from PATH (needs_tools, python3 for a python entry, the program of a cli
  entry), files of the pack that have gone, or a PATH with no absolute directory at all:
  blocked, naming them, and nothing runs;
- a workspace that cannot be prepared: blocked, with the reason.
engine and challenge_id are filled in, and cost.seconds is the measured run time.

Engines are the player's code, but they read untrusted challenge data, so what they print
is untrusted: it is parsed strictly, and stderr reaches notes only through untrusted().
On the host runtime an engine runs as the player and can read the player's files (P6); the
allowlist only keeps flightdeck's environment from it. A docker workspace can be passed as
workspace_factory: the boot script, the engine files and the tool check are host-side, so
such a factory must mount the pack and this folder at the same paths, read-only.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import math
import os
import re
import shlex
import shutil
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..agent.workspace import PRIVATE, HostWorkspace, RunResult, Workspace, WorkspaceError, open_inside
from ..platform.manual import CHALLENGE_FILE
from ..text import untrusted
from .manifest import Manifest
from .result import Cost, Evidence, ResultError, SolverResult
from .router import Hit

BOOT = Path(__file__).resolve().with_name("_boot.py")
PYTHON = "python3"
STDERR_FILE = f"{PRIVATE}/l1-stderr.log"  # in the workspace: the engine's stderr, apart from stdout
STDERR_TAIL = 300  # characters of stderr kept in the notes of a failed run
NO_SAFE_PATH = (
    "PATH has no absolute directory (only relative entries such as \".\", which would find programs in the copy "
    "of the challenge), so no program can be looked up safely; nothing ran"
)
LINE_TAIL = 120  # characters of a last line that was not a result, kept in the notes

WorkspaceFactory = Callable[[str, Path, Path], Workspace]
"""(engine id, workspace root, handout) -> a workspace that is not prepared yet."""


def host_workspace(engine_id: str, root: Path, handout: Path) -> Workspace:
    return HostWorkspace(root, handout)


@dataclass(frozen=True)
class EngineRun:
    manifest: Manifest
    result: SolverResult
    seconds: float  # the whole run: workspace copy, command and reading its output


async def run_engine(
    manifest: Manifest,
    handout: Path,
    *,
    workdir: Path,
    flag_format: str,
    timeout: float | None = None,
    workspace_factory: WorkspaceFactory | None = None,
    challenge_id: str | None = None,
) -> SolverResult:
    """Run one engine on one challenge. `timeout` overrides the manifest's timeout_seconds;
    `challenge_id` defaults to the handout's challenge.json id, else its folder name."""
    pattern = _flag_pattern(flag_format)
    limit = manifest.timeout_seconds if timeout is None else timeout
    if not (isinstance(limit, (int, float)) and not isinstance(limit, bool) and math.isfinite(limit) and limit > 0):
        raise ValueError(f"timeout must be a positive number of seconds, got {limit!r}")
    handout = Path(handout)
    label = challenge_id if challenge_id is not None else challenge_id_of(handout)

    def done(result: SolverResult, seconds: float) -> SolverResult:
        cost = Cost(seconds=seconds, usd=result.cost.usd, tokens=result.cost.tokens)
        return dataclasses.replace(result, engine=manifest.id, challenge_id=label, cost=cost)

    gone = missing_files(manifest)
    if gone:
        return done(SolverResult("blocked", notes=f"pack file {', '.join(gone)} is missing (it was there when the pack was read); nothing ran"), 0.0)
    path = safe_path()
    if not path:
        return done(SolverResult("blocked", notes=NO_SAFE_PATH), 0.0)
    missing = missing_tools(manifest)
    if missing:
        return done(SolverResult("blocked", notes=f"missing tools: {', '.join(missing)} (not on PATH); nothing ran"), 0.0)
    try:
        argv = command(manifest)
    except LookupError as exc:  # a program went between the check and now
        return done(SolverResult("blocked", notes=f"{_safe(str(exc))}; nothing ran"), 0.0)
    workspace = (workspace_factory or host_workspace)(manifest.id, Path(workdir) / manifest.id, handout)
    try:
        result, seconds = await _run_in(workspace, manifest, argv, path, limit, pattern)
    finally:
        try:
            await workspace.close()
            unclosed = ""
        except WorkspaceError as exc:  # e.g. docker rm failed: say so, keep the result
            unclosed = f"its workspace did not close cleanly: {_safe(str(exc))}"
    if unclosed:
        result = dataclasses.replace(result, notes=f"{result.notes}; {unclosed}" if result.notes else unclosed)
    return done(result, seconds)


async def run_routed(
    hits: Sequence[Hit],
    handout: Path,
    *,
    workdir: Path,
    flag_format: str,
    concurrency: int = 4,
    workspace_factory: WorkspaceFactory | None = None,
    challenge_id: str | None = None,
) -> list[EngineRun]:
    """Run every routed engine, at most `concurrency` at once, best first. The runs come
    back in priority order (high first, then id), whenever each one finished."""
    if not (isinstance(concurrency, int) and not isinstance(concurrency, bool) and concurrency >= 1):
        raise ValueError(f"concurrency must be a whole number, 1 or more, got {concurrency!r}")
    ordered = sorted(hits, key=lambda hit: (-hit.priority, hit.manifest.id))
    ids = [hit.manifest.id for hit in ordered]
    if len(set(ids)) != len(ids):
        raise ValueError("an engine is listed twice; each engine runs once per challenge")
    _flag_pattern(flag_format)  # a bad format fails before anything starts
    label = challenge_id if challenge_id is not None else challenge_id_of(Path(handout))
    gate = asyncio.Semaphore(concurrency)

    async def one(hit: Hit) -> EngineRun:
        async with gate:
            begun = time.monotonic()
            try:
                result = await run_engine(
                    hit.manifest, handout, workdir=workdir, flag_format=flag_format,
                    workspace_factory=workspace_factory, challenge_id=label,
                )
            except Exception as exc:  # a flightdeck bug or a failing factory: this engine's run only, never the others'
                result = SolverResult(
                    "unsure", engine=hit.manifest.id, challenge_id=label, cost=Cost(seconds=time.monotonic() - begun),
                    notes=f"flightdeck could not run it: {type(exc).__name__}: {_safe(str(exc))}",
                )
            return EngineRun(hit.manifest, result, time.monotonic() - begun)

    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(one(hit)) for hit in ordered]
    return [task.result() for task in tasks]


def command(manifest: Manifest) -> list[str]:
    """The argv an engine runs with, in its workspace: its program by absolute path (found on
    safe_path(), or a pack file) and pack files by absolute path. LookupError when the
    program is not there (run_engine checks missing_tools first)."""
    path = safe_path()
    entry = manifest.entry
    if entry.kind == "python":
        return [_program(PYTHON, path), "-I", str(BOOT), str(manifest.entry_file), str(entry.function), "."]
    words = list(entry.argv)
    for i in entry.pack_files:  # settled when the manifest was loaded, never looked up again here
        words[i] = str(manifest.base / entry.argv[i])
    if 0 not in entry.pack_files:
        words[0] = _program(words[0], path)
    return [*words, "."]


def safe_path(path: str | None = None) -> str:
    """PATH (default: this process's) with only its absolute directories, in order. A
    relative entry, "." or an empty one, is the working directory of whatever looks a
    program up: for an engine, the copy of the challenge."""
    raw = os.environ.get("PATH", "") if path is None else path
    return os.pathsep.join(entry for entry in raw.split(os.pathsep) if os.path.isabs(entry))


def find_program(name: str, path: str) -> str | None:
    """The absolute path `name` runs as: itself if it is an absolute path to an executable,
    else the first executable of that name in path's directories; None if there is none."""
    if os.path.isabs(name):
        return name if shutil.which(name) is not None else None
    if not path or "/" in name:
        return None
    found = shutil.which(name, path=path)
    return os.path.abspath(found) if found is not None else None


def _program(name: str, path: str) -> str:
    found = find_program(name, path)
    if found is None:
        raise LookupError(f"{name} is not on PATH")
    return found


def missing_files(manifest: Manifest) -> list[str]:
    """The files of the pack the entry names (Manifest.files) that are no longer there, as
    the manifest wrote them."""
    entry = manifest.entry
    words = [entry.path] if entry.kind == "python" else [entry.argv[i] for i in entry.pack_files]
    return [str(word) for word, path in zip(words, manifest.files) if not path.is_file()]


def missing_tools(manifest: Manifest) -> list[str]:
    """The tools the engine needs that are not on PATH, in the order it names them."""
    needed: list[str] = []
    if manifest.entry.kind == "python":
        needed.append(PYTHON)
    elif 0 not in manifest.entry.pack_files:
        needed.append(manifest.entry.argv[0])  # a command on PATH, or an absolute path
    needed += manifest.needs_tools
    path = safe_path()
    return [tool for tool in dict.fromkeys(needed) if find_program(tool, path) is None]


def challenge_id_of(handout: Path) -> str:
    """The board's id for a challenge folder: its challenge.json "id", else the folder name
    (the folder board's rule). Only labels results; the board loader checks the rest."""
    spec = Path(handout) / CHALLENGE_FILE
    try:
        if spec.is_file() and not spec.is_symlink() and spec.stat().st_size <= 1_000_000:
            data = json.loads(spec.read_bytes().decode("utf-8-sig"))
            if isinstance(data, dict) and isinstance(data.get("id"), str) and data["id"]:
                return data["id"]
    except (OSError, ValueError, RecursionError):
        pass  # a broken challenge.json is the board loader's to report; the label is the folder name
    return Path(handout).resolve().name


# ---------------------------------------------------------------- running and reading what an engine printed


async def _run_in(
    workspace: Workspace, manifest: Manifest, argv: list[str], path: str, limit: float, pattern: re.Pattern[str]
) -> tuple[SolverResult, float]:
    """(result, seconds the command ran) for one engine in a workspace that is not prepared yet."""
    try:
        await workspace.prepare()
    except WorkspaceError as exc:
        return SolverResult("blocked", notes=f"its workspace could not be prepared: {_safe(str(exc))}"), 0.0
    line = f"PATH={shlex.quote(path)} exec {shlex.join(argv)} 2>{shlex.quote(STDERR_FILE)}"
    begun = time.monotonic()
    try:
        run = await workspace.run(line, timeout=limit)
    except WorkspaceError as exc:
        return SolverResult("blocked", notes=f"its workspace could not run it: {_safe(str(exc))}"), time.monotonic() - begun
    seconds = time.monotonic() - begun
    stderr = _stderr_tail(workspace.root) if run.exit_code else ""
    return _interpret(manifest, run, stderr, pattern, limit), seconds


def _interpret(manifest: Manifest, run: RunResult, stderr: str, pattern: re.Pattern[str], limit: float) -> SolverResult:
    if run.timed_out:
        return SolverResult("unsure", notes=f"timed out after {limit:g}s")
    if run.exit_code is None:
        return SolverResult("unsure", notes="stopped before it finished (its workspace was closed)")
    code = run.exit_code
    stdout = run.output.decode("utf-8", "replace")
    if manifest.output == "result":
        last = _last_line(stdout)
        try:
            if last is None:
                raise ResultError("it printed nothing")
            return SolverResult.from_json(last)
        except ResultError as exc:
            if code != 0:
                return SolverResult("unsure", notes=_exited(code, stderr))
            shown = "" if last is None else f"; its last line: {_safe(last[:LINE_TAIL])}"
            return SolverResult(
                "unsure",
                notes=f"its output was not a result ({_safe(str(exc))}){shown}. A result engine prints a SolverResult as JSON on its last line",
            )
    flags = _flags(stdout, pattern)
    if flags:
        evidence = Evidence("match", f"{len(flags)} distinct flag-format match{'es' if len(flags) > 1 else ''} in its output")
        return SolverResult("candidate", flags=flags, evidence=(evidence,), notes="" if code == 0 else f"exited {code}")
    if code != 0:
        return SolverResult("unsure", notes=_exited(code, stderr))
    return SolverResult("none")


def _last_line(text: str) -> str | None:
    """The last non-empty line, split on newlines only: a result's JSON may hold a raw line
    separator inside a string (an engine not written in Python), and that is not a line end."""
    for line in reversed(text.split("\n")):
        if line.strip():
            return line.strip()
    return None


def _flags(text: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    found = (m.group(0) for m in pattern.finditer(text))
    return tuple(dict.fromkeys(flag for flag in found if flag.strip()))


def _exited(code: int, stderr: str) -> str:
    return f"exited {code}: {stderr}" if stderr else f"exited {code} with nothing on stderr"


def _stderr_tail(root: Path) -> str:
    """The last STDERR_TAIL characters of the engine's stderr, made safe and on one line."""
    try:
        fd = open_inside(root, STDERR_FILE.split("/"))
    except OSError:
        return ""
    try:
        size = os.fstat(fd).st_size
        os.lseek(fd, max(0, size - STDERR_TAIL * 4), os.SEEK_SET)  # a character is at most 4 bytes
        data = os.read(fd, STDERR_TAIL * 4)
    except OSError:
        return ""
    finally:
        os.close(fd)
    text = data.decode("utf-8", "replace").strip()
    return untrusted(text[-STDERR_TAIL:], one_line=True)


def _flag_pattern(flag_format: str) -> re.Pattern[str]:
    if not isinstance(flag_format, str) or not flag_format:
        raise ValueError("a flag format (a regular expression) is needed to find flags")
    try:
        return re.compile(flag_format)
    except re.error as exc:
        raise ValueError(f"the flag format does not compile as a regular expression ({exc})") from None


def _safe(text: str) -> str:
    return untrusted(text, one_line=True)
