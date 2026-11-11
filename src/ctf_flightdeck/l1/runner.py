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

The engine runs under l1/_capture.py, flightdeck's own python, which keeps the first 6 MB
and the last 2 MB of its stdout and the last 4 KB of its stderr, counts every byte, and
writes nothing to disk; so an engine that prints without end fills neither memory nor disk.

The result channel. The engine's environment has FLIGHTDECK_L1_RESULT, the path of a file
in the workspace's .flightdeck/ whose name has a random part. A python engine's returned
result reaches it through the boot script; a cli engine may write its SolverResult JSON
there itself. Stdout is never read as a python engine's result: an engine prints what it
read from the challenge, and a line the challenge's author wrote could pose as a result.

Then the run becomes a SolverResult:
- a result in the result file is the result, whatever the output mode (not a valid one:
  unsure, never another reading);
- a python engine with output "result" that returned nothing: unsure;
- a cli engine with output "result": the last non-empty stdout line, read as a
  SolverResult (not one: unsure);
- output "text": every flag-format match in stdout, in order and deduplicated: candidate;
  no match: none. Output past what was kept is reported, never taken for nothing: the
  notes say how many bytes went unsearched, and with no flag found the run is unsure;
- a timeout: unsure, "timed out after Ns"; a non-zero exit with no result: unsure, "exited
  N: <the end of its stderr>";
- tools missing from PATH (needs_tools, python3 for a python entry, the program of a cli
  entry, bash), files of the pack that have gone, or a PATH with no absolute directory at
  all: blocked, naming them, and nothing runs;
- a workspace that cannot be prepared: blocked, with the reason.
engine and challenge_id are filled in, and cost.seconds is the measured run time.

Engines are the player's code, but they read untrusted challenge data, so what they print
is untrusted: it is parsed strictly, and stderr reaches notes only through untrusted().
On the host runtime an engine runs as the player and can read the player's files (P6); the
allowlist only keeps flightdeck's environment from it.

When lanes run in Docker, so do engines (D17): a workspace_factory that makes an
l1.container.EngineContainer runs each engine in a container of its own. Then its programs
(python3, a cli entry's program, needs_tools, bash) are looked up in the container's image,
not on this machine; the pack and the boot script are mounted there at the paths they have
here, so the command names the same files; and the capture still runs here, with
flightdeck's own python, starting `docker exec`. A program the image lacks blocks the engine,
naming it, after the container was started (its image is what is checked), and nothing ran.
The engine gets PATH (the image's, absolute directories only), TERM=dumb and
FLIGHTDECK_L1_RESULT (in /work), and nothing else of this machine's environment.

A run marks the flags it found in an engine's output (output "text") as scraped
(EngineRun.scraped): the engine printed them, it never claimed them, and what it printed may
be the challenge's own decoy.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import math
import os
import re
import secrets
import shlex
import shutil
import stat
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from ..agent.workspace import OUTPUT_CAP, PRIVATE, HostWorkspace, RunResult, Workspace, WorkspaceError, open_inside
from ..platform.manual import CHALLENGE_FILE
from ..text import untrusted
from .container import EngineContainer
from .manifest import Manifest
from .result import Cost, Evidence, ResultError, SolverResult
from .router import Hit

BOOT = Path(__file__).resolve().with_name("_boot.py")
CAPTURE = Path(__file__).resolve().with_name("_capture.py")
PYTHON = "python3"
SHELL = "bash"  # starts the engine (as the workspace's own commands do): a #!-less script runs as a shell script
RESULT_ENV = "FLIGHTDECK_L1_RESULT"  # the engine's result file, as the engine sees it
RESULT_MAX = 1024 * 1024  # a result file bigger than this is not read
MB = 1024 * 1024
HEAD_BYTES = 6 * MB  # stdout kept from its start
TAIL_BYTES = 2 * MB  # and from its end
STDERR_BYTES = 4096  # stderr kept from its end
STDERR_TAIL = 300  # characters of stderr kept in the notes of a failed run
NO_SAFE_PATH = (
    "PATH has no absolute directory (only relative entries such as \".\", which would find programs in the copy "
    "of the challenge), so no program can be looked up safely; nothing ran"
)
LINE_TAIL = 120  # characters of a last line that was not a result, kept in the notes
WINDOW = 2048  # characters of a line the flag search looks at in one search
OVERLAP = 512  # windows overlap by this much: a flag up to this long is never cut
_CAPTURE_KEYS = ("capture", "status", "stdout", "head", "tail", "stderr", "stderr_kept")
if HEAD_BYTES + TAIL_BYTES + STDERR_BYTES + 4096 > OUTPUT_CAP:  # the record must reach the runner whole
    raise RuntimeError("the capture's record would not fit in a workspace's output cap")

WorkspaceFactory = Callable[[str, Path, Path], Workspace]
"""(engine id, workspace root, handout) -> a workspace that is not prepared yet."""


def host_workspace(engine_id: str, root: Path, handout: Path) -> Workspace:
    return HostWorkspace(root, handout)


@dataclass(frozen=True)
class EngineRun:
    manifest: Manifest
    result: SolverResult
    seconds: float  # the whole run: workspace copy, command and reading its output
    scraped: bool = False  # its flags are flag-format matches in what it printed (output "text"), never claimed by it


class _Outcome(NamedTuple):
    result: SolverResult
    scraped: bool  # the result's flags are matches the runner found in the engine's output


async def run_engine(
    manifest: Manifest,
    handout: Path,
    *,
    workdir: Path,
    flag_format: str,
    timeout: float | None = None,
    workspace_factory: WorkspaceFactory | None = None,
    challenge_id: str | None = None,
    keep: bool = False,
) -> SolverResult:
    """Run one engine on one challenge. `timeout` overrides the manifest's timeout_seconds;
    `challenge_id` defaults to the handout's challenge.json id, else its folder name. The
    engine's copy of the challenge is removed once its result is read (a forensics image
    times every engine routed to it adds up), unless `keep`; a folder that was there before
    the run is never removed. A run that is cancelled (a lane killed, flightdeck quitting)
    still closes its workspace and removes its copy before the cancel goes on: the clean-up
    is shielded, and waits for a copy still being made (its thread cannot be stopped)."""
    outcome = await _run_engine(manifest, handout, workdir=workdir, flag_format=flag_format, timeout=timeout,
                                workspace_factory=workspace_factory, challenge_id=challenge_id, keep=keep)
    return outcome.result


async def _run_engine(
    manifest: Manifest,
    handout: Path,
    *,
    workdir: Path,
    flag_format: str,
    timeout: float | None,
    workspace_factory: WorkspaceFactory | None,
    challenge_id: str | None,
    keep: bool,
) -> _Outcome:
    pattern = _flag_pattern(flag_format)
    limit = manifest.timeout_seconds if timeout is None else timeout
    if not (isinstance(limit, (int, float)) and not isinstance(limit, bool) and math.isfinite(limit) and limit > 0):
        raise ValueError(f"timeout must be a positive number of seconds, got {limit!r}")
    handout = Path(handout)
    label = challenge_id if challenge_id is not None else challenge_id_of(handout)

    def done(result: SolverResult, seconds: float, scraped: bool = False) -> _Outcome:
        cost = Cost(seconds=seconds, usd=result.cost.usd, tokens=result.cost.tokens)
        return _Outcome(dataclasses.replace(result, engine=manifest.id, challenge_id=label, cost=cost), scraped)

    gone = missing_files(manifest)
    if gone:
        return done(SolverResult("blocked", notes=f"pack file {', '.join(gone)} is missing (it was there when the pack was read); nothing ran"), 0.0)
    workspace = (workspace_factory or host_workspace)(manifest.id, Path(workdir) / manifest.id, handout)
    boxed = isinstance(workspace, EngineContainer)  # its programs are looked up in the container, once it runs
    path = "" if boxed else safe_path()
    if not boxed and not path:
        return done(SolverResult("blocked", notes=NO_SAFE_PATH), 0.0)
    if not (sys.executable and os.path.isabs(sys.executable)):
        return done(SolverResult("blocked", notes="flightdeck cannot name its own python, which captures what an engine prints; nothing ran"), 0.0)
    argv: list[str] = []
    if not boxed:
        missing = missing_tools(manifest)
        if missing:
            return done(SolverResult("blocked", notes=f"missing tools: {', '.join(missing)} (not on PATH); nothing ran"), 0.0)
        try:
            argv = command(manifest)
        except LookupError as exc:  # a program went between the check and now
            return done(SolverResult("blocked", notes=f"{_safe(str(exc))}; nothing ran"), 0.0)
    root = Path(workspace.root)
    ours = not os.path.lexists(root)  # made by prepare(): this run's to remove
    # prepare() runs as a task of its own: a cancel must not leave the handout's copy thread
    # running unseen, so the clean-up below can wait for it
    preparing = asyncio.ensure_future(workspace.prepare())
    try:
        result, seconds, scraped = await _run_in(workspace, preparing, manifest, argv, path, limit, pattern)
    finally:
        tidy = asyncio.ensure_future(_tidy(workspace, preparing, root, remove=ours and not keep))
        trouble = await asyncio.shield(tidy)  # cancelled meanwhile: the clean-up still runs to its end
    if trouble:  # said in the notes, after the engine's own
        result = dataclasses.replace(result, notes="; ".join(filter(None, [result.notes, *trouble])))
    return done(result, seconds, scraped)


async def _tidy(workspace: Workspace, preparing: asyncio.Future[None], root: Path, *, remove: bool) -> list[str]:
    """After an engine's run, however it ended: wait until its workspace is prepared or has
    failed to be (the copy may still be going on after a cancel), close the workspace, and
    remove the copy when `remove` (an engine's container empties it first, from inside: what
    the engine made there may not be this machine's user's to remove). What went wrong, for
    the notes; it never raises."""
    trouble: list[str] = []
    await asyncio.wait([preparing])
    if not preparing.cancelled():
        preparing.exception()  # its failure is the run's result already (or the run never got to it)
    if remove and isinstance(workspace, EngineContainer):
        await workspace.wipe()  # what it could not remove is tried again from here, which says if it fails
    try:
        await workspace.close()
    except WorkspaceError as exc:  # e.g. docker rm failed: say so, keep the result
        trouble.append(f"its workspace did not close cleanly: {_safe(str(exc))}")
    except Exception as exc:  # a flightdeck bug: the copy is still removed, and the notes say so
        trouble.append(f"its workspace did not close cleanly: {type(exc).__name__}: {_safe(str(exc))}")
    if remove and os.path.lexists(root):
        left = await asyncio.to_thread(remove_tree, root)
        if left:
            trouble.append(f"its copy of the challenge {_safe(str(root))} could not be removed: {left}")
    return trouble


def remove_tree(root: Path) -> str:
    """Remove an engine's copy of the challenge: "" when it is gone, else why not. The tree is
    the engine's doing, so this never follows a symlink (shutil.rmtree walks by descriptor) and
    first gives the owner back every folder an engine or an archive made read-only or shut."""
    try:
        _open_up(Path(root))
        shutil.rmtree(root)
    except OSError as exc:
        where = f" ({_safe(str(exc.filename))})" if exc.filename else ""
        return f"{_safe(exc.strerror or str(exc))}{where}"
    return ""


def _open_up(root: Path) -> None:
    """Owner read, write and search on every real folder under root, symlinks never followed."""
    pending = [root]
    while pending:
        directory = pending.pop()
        mode = os.lstat(directory).st_mode
        if not stat.S_ISDIR(mode):
            continue
        if (mode & 0o700) != 0o700:
            try:
                os.chmod(directory, stat.S_IMODE(mode) | 0o700, follow_symlinks=False)
            except (NotImplementedError, OSError):  # no lchmod here (Linux): lstat said it is a real folder
                os.chmod(directory, stat.S_IMODE(mode) | 0o700)
        with os.scandir(directory) as listing:
            pending.extend(entry.path for entry in listing if entry.is_dir(follow_symlinks=False))


async def run_routed(
    hits: Sequence[Hit],
    handout: Path,
    *,
    workdir: Path,
    flag_format: str,
    concurrency: int = 4,
    workspace_factory: WorkspaceFactory | None = None,
    challenge_id: str | None = None,
    keep: bool = False,
) -> list[EngineRun]:
    """Run every routed engine, at most `concurrency` at once, best first. The runs come
    back in priority order (high first, then id), whenever each one finished. `keep` keeps
    each engine's copy of the challenge (run_engine)."""
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
                outcome = await _run_engine(
                    hit.manifest, handout, workdir=workdir, flag_format=flag_format, timeout=None,
                    workspace_factory=workspace_factory, challenge_id=label, keep=keep,
                )
            except Exception as exc:  # a flightdeck bug or a failing factory: this engine's run only, never the others'
                outcome = _Outcome(SolverResult(
                    "unsure", engine=hit.manifest.id, challenge_id=label, cost=Cost(seconds=time.monotonic() - begun),
                    notes=f"flightdeck could not run it: {type(exc).__name__}: {_safe(str(exc))}",
                ), False)
            return EngineRun(hit.manifest, outcome.result, time.monotonic() - begun, scraped=outcome.scraped)

    async with asyncio.TaskGroup() as group:
        tasks = [group.create_task(one(hit)) for hit in ordered]
    return [task.result() for task in tasks]


def command(manifest: Manifest, find: Callable[[str], str] | None = None) -> list[str]:
    """The argv an engine runs with, in its workspace: its program by absolute path, or a
    pack file, and pack files by absolute path. `find` gives a program's absolute path where
    the engine runs (default: on safe_path() here; an engine's container passes what it
    found in its image). LookupError when the program is not there (run_engine checks
    missing_tools first)."""
    if find is None:
        path = safe_path()

        def find(name: str) -> str:
            return _program(name, path)

    entry = manifest.entry
    if entry.kind == "python":
        return [find(PYTHON), "-I", str(BOOT), str(manifest.entry_file), str(entry.function), "."]
    words = list(entry.argv)
    for i in entry.pack_files:  # settled when the manifest was loaded, never looked up again here
        words[i] = str(manifest.base / entry.argv[i])
    if 0 not in entry.pack_files:
        words[0] = find(words[0])
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


def needed_tools(manifest: Manifest) -> list[str]:
    """The programs an engine needs where it runs, in the order it names them, each once:
    python3 for a python entry or a cli entry's program (unless it is a pack file),
    needs_tools, then bash, which starts it."""
    needed: list[str] = []
    if manifest.entry.kind == "python":
        needed.append(PYTHON)
    elif 0 not in manifest.entry.pack_files:
        needed.append(manifest.entry.argv[0])  # a command on PATH, or an absolute path
    needed += manifest.needs_tools
    needed.append(SHELL)  # flightdeck's own: it starts the engine
    return list(dict.fromkeys(needed))


def missing_tools(manifest: Manifest) -> list[str]:
    """The tools the engine needs that are not on PATH, in the order it names them."""
    path = safe_path()
    return [tool for tool in needed_tools(manifest) if find_program(tool, path) is None]


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
    workspace: Workspace, preparing: asyncio.Future[None], manifest: Manifest, argv: list[str], path: str, limit: float,
    pattern: re.Pattern[str],
) -> tuple[SolverResult, float, bool]:
    """(result, seconds the command ran, whether its flags were scraped from its output) for
    one engine in a workspace that `preparing` (its prepare(), as a task) gets ready."""
    try:
        await asyncio.shield(preparing)  # a cancel leaves it running: run_engine's clean-up waits for it
    except WorkspaceError as exc:
        return SolverResult("blocked", notes=f"its workspace could not be prepared: {_safe(str(exc))}"), 0.0, False
    name = f"l1-result-{secrets.token_hex(16)}.json"  # a challenge cannot know it, so cannot plant it
    capture = [sys.executable, "-I", str(CAPTURE), str(HEAD_BYTES), str(TAIL_BYTES), str(STDERR_BYTES)]
    begun = time.monotonic()
    try:
        if isinstance(workspace, EngineContainer):
            host_argv = await _in_container(workspace, manifest, name, capture)
            if isinstance(host_argv, SolverResult):  # the image lacks a program: nothing ran
                return host_argv, 0.0, False
            begun = time.monotonic()
            run = await workspace.run_argv(host_argv, timeout=limit)
        else:
            seen_as = getattr(workspace, "workdir", None) or str(workspace.root)  # the root as the command sees it
            shell = _program(SHELL, path)
            line = " ".join([
                f"PATH={shlex.quote(path)}",
                f"{RESULT_ENV}={shlex.quote(f'{seen_as}/{PRIVATE}/{name}')}",
                "exec",
                shlex.join(capture),
                '${LC_CTYPE+"--lc-ctype=$LC_CTYPE"}',  # the engine gets the LC_CTYPE this shell has, or none (_capture.py)
                "--",
                shlex.join([shell, "-c", 'exec "$@"', "flightdeck-l1", *argv]),
            ])
            run = await workspace.run(line, timeout=limit)
    except WorkspaceError as exc:
        return SolverResult("blocked", notes=f"its workspace could not run it: {_safe(str(exc))}"), time.monotonic() - begun, False
    seconds = time.monotonic() - begun
    # reading the record and searching megabytes of output: never on the event loop, where it
    # would hold up every other engine's timeout (and, in a lane, the console)
    result, scraped = await asyncio.to_thread(_interpret, manifest, run, workspace.root, name, pattern, limit)
    return result, seconds, scraped


async def _in_container(box: EngineContainer, manifest: Manifest, name: str, capture: list[str]) -> list[str] | SolverResult:
    """The argv, run on this machine, that runs the engine in its container: flightdeck's
    capture starting `docker exec` with the programs the image has. The blocked result,
    naming them, when the image lacks some."""
    needed = needed_tools(manifest)
    found, path = await box.programs(needed)
    missing = [tool for tool in needed if found.get(tool) is None]
    if missing:
        hint = " (`flightdeck image build` builds the lane image, which has python3)" if PYTHON in missing else ""
        return SolverResult("blocked", notes=(
            f"missing tools: {', '.join(missing)} (not in the lane image {box.image}, where engines run when lanes "
            f"run in Docker){hint}; nothing ran"
        ))
    argv = command(manifest, find=lambda program: str(found[program]))
    env = {"PATH": path, "TERM": "dumb", RESULT_ENV: f"{box.workdir}/{PRIVATE}/{name}"}
    return [*capture, "--", *box.exec_argv([str(found[SHELL]), "-c", 'exec "$@"', "flightdeck-l1", *argv], env)]


@dataclass(frozen=True)
class Captured:
    """What _capture.py kept of an engine's output, and how much there was."""

    status: int
    stdout: int  # bytes the engine printed on stdout
    head: bytes  # the first of them
    tail: bytes  # the last of those after the head
    stderr: bytes  # the end of stderr
    stderr_total: int

    @property
    def dropped(self) -> int:
        """Bytes of stdout between head and tail that were not kept."""
        return self.stdout - len(self.head) - len(self.tail)


def parse_captured(output: bytes) -> Captured:
    """The record _capture.py writes (its docstring has the format). ValueError, saying what
    is wrong, for anything else: the capture failed, or something else wrote there."""
    line, newline, rest = output.partition(b"\n")
    if not newline:
        raise ValueError("no record")
    try:
        record = json.loads(line)
    except ValueError:
        raise ValueError("the record is not JSON") from None
    if not (isinstance(record, dict) and sorted(record) == sorted(_CAPTURE_KEYS) and record["capture"] == 1
            and all(type(record[key]) is int and record[key] >= 0 for key in _CAPTURE_KEYS)):
        raise ValueError("not a capture record")
    head, tail, err = record["head"], record["tail"], record["stderr_kept"]
    if len(rest) != head + tail + err or record["stdout"] < head + tail or record["stderr"] < err:
        raise ValueError("its sizes do not match what follows it")
    return Captured(record["status"], record["stdout"], rest[:head], rest[head:head + tail], rest[head + tail:], record["stderr"])


def _interpret(manifest: Manifest, run: RunResult, root: Path, name: str, pattern: re.Pattern[str],
               limit: float) -> tuple[SolverResult, bool]:
    """(the run's result, True when its flags are flag-format matches found in what the
    engine printed: output "text" with no result of its own)."""
    result = _result_of(manifest, run, root, name, pattern, limit)
    if isinstance(result, _Scraped):
        return result.result, True
    return result, False


class _Scraped(NamedTuple):
    result: SolverResult  # a candidate whose flags the runner found in the engine's output


def _result_of(manifest: Manifest, run: RunResult, root: Path, name: str, pattern: re.Pattern[str],
               limit: float) -> SolverResult | _Scraped:
    if run.timed_out:
        return SolverResult("unsure", notes=f"timed out after {limit:g}s")
    if run.exit_code is None:
        return SolverResult("unsure", notes="stopped before it finished (its workspace was closed)")
    try:
        out = parse_captured(run.output)
    except ValueError as exc:
        shown = _safe(run.output[-STDERR_TAIL:].decode("utf-8", "replace").strip())
        return SolverResult("unsure", notes=f"flightdeck could not read what it printed ({exc}): {shown or 'nothing more'}")
    code = out.status
    stderr = _stderr_text(out.stderr) if code else ""
    own, problem = _result_file(root, name, "the result it returned" if manifest.entry.kind == "python" else f"the result it wrote to ${RESULT_ENV}")
    if own is not None:
        return own
    if problem:
        return SolverResult("unsure", notes=problem if code == 0 else f"{problem}; {_exited(code, stderr)}")
    if manifest.output == "result":
        if manifest.entry.kind == "cli":
            return _last_line_result(out, code, stderr)
        if code != 0:  # what a python engine prints is never its result
            return SolverResult("unsure", notes=_exited(code, stderr))
        return SolverResult("unsure", notes=(
            f"{manifest.entry.function}() returned nothing; a result engine returns a SolverResult "
            '(output = "text" is for an engine that prints its findings)'
        ))
    flags, unsearched = _search(out, pattern, limit)
    if flags:
        evidence = Evidence("match", f"{len(flags)} distinct flag-format match{'es' if len(flags) > 1 else ''} in its output")
        notes = [f"exited {code}"] if code else []
        return _Scraped(SolverResult("candidate", flags=flags, evidence=(evidence,), notes="; ".join(notes + unsearched)))
    if code != 0:
        return SolverResult("unsure", notes="; ".join([_exited(code, stderr), *unsearched]))
    if unsearched:  # not all of it was searched: that is not "nothing found"
        return SolverResult("unsure", notes="; ".join(unsearched))
    return SolverResult("none")


def _last_line_result(out: Captured, code: int, stderr: str) -> SolverResult:
    """A cli result engine's last non-empty stdout line, read as its SolverResult; kept even
    after a non-zero exit (the engine said what it could)."""
    end = out.head + out.tail if out.dropped == 0 else out.tail
    last = _last_line(end.decode("utf-8", "replace"))
    try:
        if last is None:
            raise ResultError("it printed nothing")
        return SolverResult.from_json(last)
    except ResultError as exc:
        if code != 0:
            return SolverResult("unsure", notes=_exited(code, stderr))
        shown = "" if last is None else f"; its last line: {_safe(last[:LINE_TAIL])}"
        return SolverResult("unsure", notes=(
            f"its output was not a result ({_safe(str(exc))}){shown}. A result engine prints a SolverResult as "
            f"JSON on its last line, or writes it to the file ${RESULT_ENV} names"
        ))


def _result_file(root: Path, name: str, label: str) -> tuple[SolverResult | None, str]:
    """(the result in the engine's result file, "") or (None, why there is none to read: ""
    when the engine wrote none). `label` names the result in what goes wrong."""
    try:
        fd = open_inside(root, [PRIVATE, name])
    except FileNotFoundError:
        if not os.path.lexists(root / PRIVATE):
            return None, f"its workspace's {PRIVATE} folder is gone (did it remove it?), and any result with it"
        return None, ""
    except OSError as exc:  # a symlink, a directory, a FIFO where the file should be
        return None, f"{label} cannot be read ({_safe(exc.strerror or str(exc))})"
    try:
        data = _read_upto(fd, RESULT_MAX + 1)
    except OSError as exc:
        return None, f"{label} cannot be read ({_safe(exc.strerror or str(exc))})"
    finally:
        os.close(fd)
    if len(data) > RESULT_MAX:
        return None, f"{label} is over {RESULT_MAX // MB} MB, too big for a result"
    try:
        return SolverResult.from_json(data), ""
    except ResultError as exc:
        return None, f"{label} is not a SolverResult ({_safe(str(exc))})"


def _search(out: Captured, pattern: re.Pattern[str], limit: float) -> tuple[tuple[str, ...], list[str]]:
    """(the flags in what was kept of stdout, in order, deduplicated; notes on what was not
    searched). The search stops after `limit` seconds, the engine's own time limit."""
    deadline = time.monotonic() + limit
    found: dict[str, None] = {}
    notes: list[str] = []
    parts = [out.head + out.tail] if out.dropped == 0 else [out.head, out.tail]  # head and tail meet only when nothing was dropped
    for part in parts:
        if not scan(part.decode("utf-8", "replace"), pattern, deadline, found):
            notes.append(f"flag search stopped after {limit:g}s, before the end of its output")
            break
    if out.dropped:
        notes.append(f"output over {(HEAD_BYTES + TAIL_BYTES) // MB} MB: {out.dropped} bytes in the middle not searched")
    return tuple(found), notes


def scan(text: str, pattern: re.Pattern[str], deadline: float, found: dict[str, None]) -> bool:
    """Add every flag-format match in `text` to `found`, in order; False if time.monotonic()
    passed `deadline` before the end (what was found so far stays in `found`).

    The cost of one search is bounded whatever the text or the format: each line is searched
    on its own (a flag never spans a line break), and a line longer than WINDOW characters in
    windows of WINDOW that overlap by OVERLAP, so a flag up to OVERLAP characters long is never
    cut. A match counts for the window it starts in (before the overlap), searching resumes
    where the last match ended, as one search over the line would, and the deadline is
    checked between searches. A format with an unbounded repeat, such as \\w+\\{[^{}\\s]+\\} (a
    board may set one), is quadratic on a run of word characters (a line of hex): a window
    keeps that to WINDOW squared steps, where one search over a megabyte line would take
    hours. flightdeck's own default (core.model.DeckConfig) is bounded, \\w{1,64}\\{...\\}: at
    most 64 steps from each place a search starts, so it is linear even without windows. A
    search itself cannot be stopped, so a format that backtracks exponentially can still take
    long on one window."""
    end = len(text)
    start = 0
    while start <= end:
        if time.monotonic() > deadline:
            return False
        stop = text.find("\n", start)
        if stop < 0:
            stop = end
        window = start
        resume = start
        while True:
            last = min(window + WINDOW, stop)
            own = last if last == stop else window + WINDOW - OVERLAP  # matches from here on belong to the next window
            for match in pattern.finditer(text, max(window, resume), last):
                if match.start() >= own:
                    break
                if match.end() > match.start():
                    if match.group(0).strip():
                        found.setdefault(match.group(0))
                    resume = match.end()
            if last == stop:
                break
            window += WINDOW - OVERLAP
            if time.monotonic() > deadline:
                return False
        start = stop + 1
    return True


def _read_upto(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while size < limit:
        chunk = os.read(fd, min(65536, limit - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def _last_line(text: str) -> str | None:
    """The last non-empty line, split on newlines only: a result's JSON may hold a raw line
    separator inside a string (an engine not written in Python), and that is not a line end."""
    for line in reversed(text.split("\n")):
        if line.strip():
            return line.strip()
    return None


def _exited(code: int, stderr: str) -> str:
    return f"exited {code}: {stderr}" if stderr else f"exited {code} with nothing on stderr"


def _stderr_text(data: bytes) -> str:
    """The last STDERR_TAIL characters of what was kept of stderr, made safe and on one line."""
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
