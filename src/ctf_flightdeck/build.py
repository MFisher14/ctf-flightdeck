"""Build mode: turn a gap (a challenge no L1 engine solved) into a new L1 engine, with a test
that proves the raw handout reaches it.

scaffold(pack, challenge_dir) writes, and never over a file or folder that is there:

- <pack>/<category>/<name>.py: the engine, a solve(challenge_dir) stub that returns
  SolverResult("none", notes="not written yet") until the player writes it;
- <pack>/<category>/<name>.manifest.toml: its manifest (output "result"), with one route
  that describes the challenge: its category code, up to 3 distinctive words of its
  description (see keywords()) and its handout's file extensions (see extensions()), at
  priority 60. A route matches when all of its conditions hold, so it fits this challenge
  and ones like it; the player widens it;
- <pack>/tests/cases/<name>/: the case. .board/<challenge id>/ is a copy of the challenge as
  it was handed out (its challenge.json and files), in a folder board of its own whose
  board.json keeps the event's flag format; answers.sha256.json holds the sha256 of the
  flag, never the flag; case.json names the engine and the challenge; copy.log says what
  the copy left out;
- <pack>/tests/test_<name>.py: the case test. test_routed loads the archived challenge,
  routes it with l1.router and fails unless the engine is among the hits; test_solved runs
  the engine with l1.runner on that copy and fails unless it reports "solved" with a flag
  whose sha256 is the archived one. It fails until the player writes the solver: a solver
  is done only when its test passes.

The copy sits in a hidden folder (.board) on purpose. Manifest discovery, the script
importer (`flightdeck l1 import`) and pytest all skip hidden folders, so nothing in a
handout (a *.manifest.toml, a conftest.py, a test_*.py, an executable script) is ever read
as part of the pack, imported or run. The handout is copied as data the way an engine's
workspace gets it (agent.workspace.copy_handout: regular files and folders only, never a
symlink), and nothing in it runs while scaffolding.

check(pack) runs each case test with pytest, one subprocess per case, so a test that hangs
or does not import costs only its own case. The subprocess is the python flightdeck runs
with (-I, so no PYTHON* variable or user site applies and its working folder is not on
sys.path; -B, so no bytecode lands in the pack), in an empty folder of its own, with an
environment built from an allowlist (PATH, LANG and LC_ALL; HOME and TMPDIR its own), so
the player's API keys and tokens never reach it, and with a timeout after which its whole
process group is stopped. No pytest configuration file applies (the case tests need none,
and one above the pack could change what runs), and no conftest.py above the pack is
loaded; the pack's own conftest.py files are the player's and are. A case passes only when
both of its tests ran and passed: a skipped test is not a pass.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from string import Template

from .agent.workspace import PRIVATE, WorkspaceError, copy_handout
from .l1.manifest import ID as ENGINE_ID
from .l1.manifest import MAX_ID, MAX_TIMEOUT, SUFFIX, ManifestError, discover, load
from .l1.router import HandoutFiles, route
from .platform.manual import ANSWERS_FILE, BOARD_FILE, CHALLENGE_FILE, SHA256, BoardError, category_code, load_board
from .platform.manual import ID as CHALLENGE_ID
from .platform.manual import MAX_ID as MAX_CHALLENGE_ID
from .text import untrusted

TESTS = "tests"
CASES = "cases"
BOARD = ".board"  # in a case folder: the archived folder board (hidden, see above)
CASE_FILE = "case.json"
COPY_LOG = "copy.log"
PRIORITY = 60
MAX_KEYWORDS = 3
MIN_LETTERS = 4
MAX_WORD = 30  # longer "words" are blobs (base64, hex, hashes) that never come back
MAX_EXTENSIONS = 10
REQUIRED_TESTS = ("test_routed", "test_solved")
ALLOWED_ENV = ("PATH", "LANG", "LC_ALL")  # the host workspace's allowlist (agent/workspace.py)
CHECK_SLACK = 120.0  # seconds a case test gets on top of its engine's own timeout
STOP_GRACE = 5.0  # seconds between asking a timed-out pytest to stop (SIGINT) and killing it
PROBE_TIMEOUT = 60.0
OUTPUT_TAIL = 4000  # characters of pytest's output kept to explain a run that left no report
MAX_REPORT_BYTES = 10 * 1024 * 1024
DETAIL = 240  # characters of a failure message shown

STOP_WORDS = frozenset(
    """
    about above after again against almost alone along already also although always among
    another anybody anyhow anyone anything anyway anywhere around because become becomes been
    before behind being below beside besides between beyond both cannot could does doing done
    down during each eight either else elsewhere enough even ever every everybody everyone
    everything everywhere except fifteen fifty first five forty four from further gave give
    given gives going gone have having hello hence here hers herself himself however hundred
    indeed inside into itself just keep know knows last latter like made make makes many maybe
    might mine more moreover most mostly much must myself need needs neither never next nine
    nobody none nothing nowhere often once ones only onto other others otherwise ours ourselves
    over perhaps please quite rather really said same seem seemed seems several should since
    sixty some somebody somehow someone something sometime sometimes somewhere still such sure
    take tell than that their theirs them themselves then there thereby therefore these they
    thing things think third this those though three through throughout thus time times
    together took toward towards twelve twenty under unless until upon used using very want
    wants welcome well were what whatever when whenever where whereas wherever whether which
    while whoever whole whom whose will with within without would year years your yours
    yourself yourselves
    attached attachment attachments author authors challenge challenges code connect data
    description download downloads easy enjoy file files find flag flags format good hard
    help hidden hint hints link luck medium message messages note notes point points secret
    secrets server simple solve solved solver submit text wrap wrapped
    """.split()
)
"""Words left out of a route's keywords: common English words and what every CTF
description says (flag, challenge, file...)."""

_WORD = re.compile(r"[a-z0-9]+")
_EXTENSION = re.compile(r"\.[a-z0-9_+-]{1,16}")
_ROUTE_CATEGORY = re.compile(r"[a-z0-9][a-z0-9_.+-]{0,39}")
_FOLDER_JUNK = re.compile(r"[^a-z0-9_-]+")
_CASE_NAME = re.compile(r"[a-z0-9_]+")
RESERVED_FOLDERS = frozenset({TESTS})
NO_CATEGORY = "uncategorized"


class BuildError(Exception):
    """Build mode cannot do what was asked. The message says why, safe to print."""


@dataclass(frozen=True)
class CheckResult:
    """One case test, run by check()."""

    name: str  # the case: tests/cases/<name>/ and tests/test_<name>.py
    engine: str  # the engine it tests (from case.json; the case name if that cannot be read)
    test: Path  # the test file
    passed: bool
    detail: str = ""  # why it did not pass, on one line and safe to print; "" when it passed
    outcomes: tuple[tuple[str, str], ...] = field(default=())  # (test, passed | failed | error | skipped)
    seconds: float = 0.0


@dataclass(frozen=True)
class Layout:
    """Where scaffold() puts an engine called `name` in `pack`."""

    pack: Path
    folder: str  # the category folder
    name: str  # the file names' stem: the engine id with . and - as _

    @property
    def solver(self) -> Path:
        return self.pack / self.folder / f"{self.name}.py"

    @property
    def manifest(self) -> Path:
        return self.pack / self.folder / f"{self.name}{SUFFIX}"

    @property
    def test(self) -> Path:
        return self.pack / TESTS / f"test_{self.name}.py"

    @property
    def case(self) -> Path:
        return self.pack / TESTS / CASES / self.name

    @property
    def board(self) -> Path:
        return self.case / BOARD

    @property
    def answers(self) -> Path:
        return self.case / ANSWERS_FILE


# ---------------------------------------------------------------- scaffold


def scaffold(pack: Path, challenge_dir: Path, *, engine_id: str | None = None, answers: Path | None = None) -> list[Path]:
    """Write a new engine for the challenge in `challenge_dir` (a folder-board challenge; its
    parent is read as the board) into `pack`, with its case and its test. `engine_id`
    defaults to <category>.<challenge id>. `answers` is an answers file (challenge id to the
    sha256 of its flag); without it, the board's own answers.sha256.json is used if it has
    one. With no answer for the challenge, the case holds none and test_solved says how to
    add it. Returns [the engine, its manifest, its test, the case folder]."""
    pack = Path(pack).expanduser().absolute()
    item, board = _source(Path(challenge_dir), answers)
    challenge = item.challenge
    route_category, folder = category_parts(challenge.category)
    engine = engine_id if engine_id is not None else f"{folder}.{challenge.id}"
    name = engine_name(engine)
    layout = Layout(pack, folder, name)
    handout = item.handout.resolve()
    if pack.resolve().is_relative_to(handout):
        raise BuildError(f"the pack {_show(pack)} is inside the challenge {_show(handout)}; nothing is ever written to a handout")
    if handout.is_relative_to(pack.resolve()):
        raise BuildError(
            f"the challenge {_show(handout)} is inside the pack {_show(pack)}, where discovery would read its files "
            "as part of the pack; keep boards outside the pack"
        )
    if pack.exists() and not pack.is_dir():
        raise BuildError(f"{_show(pack)} is not a folder")
    taken = _engine_ids(pack)
    if engine in taken:
        raise BuildError(f"the pack already has an engine with the id {engine} (in {_show(taken[engine])}); pass another --name")
    there = [path for path in (layout.solver, layout.manifest, layout.test, layout.case) if os.path.lexists(path)]
    if there:
        listed = ", ".join(_show(path) for path in there)
        raise BuildError(f"{listed} {'is' if len(there) == 1 else 'are'} there already; build mode never overwrites: pass another --name")
    digest = _answer(board, challenge.id)

    created: list[Path] = []
    try:
        if not pack.exists():
            pack.mkdir(parents=True)
            created.append(pack)
        for parts in ((folder,), (TESTS, CASES)):
            _real_dirs(pack, parts, created)
        _write_case(layout, item.handout, board, engine, challenge.id, digest, created)
        archived, archived_item = _archived(layout, challenge.id)
        words, from_name = keywords(challenge.description), False
        files = extensions(archived_item.handout)
        if not (route_category or words or files):
            words, from_name = keywords(challenge.name), True
        if not (route_category or words or files):
            raise BuildError(
                f"nothing about {challenge.id} can make a route: its category is not a short code, and neither its "
                "description nor its name has a distinctive word, nor its handout a file with an extension"
            )
        _write_new(layout.solver, _solver_text(engine, challenge.id, name), created)
        _write_new(layout.manifest, manifest_text(engine, challenge.id, name, route_category, words, files, from_name=from_name), created)
        _write_new(layout.test, _test_text(engine, challenge.id, name), created)
        _verify(layout, engine, archived_item)
    except BaseException as exc:
        _undo(created)
        if isinstance(exc, (OSError, WorkspaceError)):
            raise BuildError(f"could not write the new engine into {_show(pack)}: {_show(exc)}; nothing was kept") from None
        raise
    return [layout.solver, layout.manifest, layout.test, layout.case]


def category_parts(category: str) -> tuple[str | None, str]:
    """(the category code a route can name, or None; the folder the engine goes in) for a
    board category, which is untrusted text. A route names a short code like cry or for;
    a category with spaces or other characters gets no category condition, and a folder
    named after it with those characters as _ ("uncategorized" when nothing is left)."""
    code = category_code(category)
    usable = code if _ROUTE_CATEGORY.fullmatch(code) and category_code(code) == code else None
    folder = _FOLDER_JUNK.sub("_", code).strip("_-")[:32].strip("_-") or NO_CATEGORY
    if folder in RESERVED_FOLDERS:
        folder += "_"
    return usable, folder


def engine_name(engine_id: str) -> str:
    """The file names' stem for an engine id, which it checks: the id with . and - as _."""
    if not isinstance(engine_id, str) or not ENGINE_ID.fullmatch(engine_id) or len(engine_id) > MAX_ID:
        raise BuildError(
            f"{_quote(engine_id)} is not an engine id: lower-case letters, digits and _ . - (not first), "
            f"at most {MAX_ID} characters"
        )
    name = re.sub(r"[.-]", "_", engine_id)
    if name in sys.stdlib_module_names:
        raise BuildError(
            f"the engine file {name}.py would hide python's own {name} module from the engine; pass another --name"
        )
    return name


def keywords(text: str) -> tuple[str, ...]:
    """Up to 3 distinctive words of a challenge's text, for a route's keywords: lower-case
    runs of a-z and 0-9 with at least 4 letters and at most 30 characters, without the stop
    words, the longest first (longer words are rarer), then in the order they appear."""
    found: list[str] = []
    for word in _WORD.findall(text.lower()):
        if len(word) > MAX_WORD or sum(c.isalpha() for c in word) < MIN_LETTERS:
            continue
        if word not in STOP_WORDS and word not in found:
            found.append(word)
    return tuple(sorted(found, key=len, reverse=True)[:MAX_KEYWORDS])  # sorted() is stable


def extensions(handout: Path) -> tuple[str, ...]:
    """The handout's file extensions as ext: patterns, sorted: each file's last suffix,
    lower-cased, over the files the router sees. A suffix with other characters than a-z,
    0-9 and _ + - is left out, and so are all but the 10 most common."""
    counts: dict[str, int] = {}
    for _, name in HandoutFiles(handout).files():
        suffix = PurePosixPath(name).suffix.lower()
        if _EXTENSION.fullmatch(suffix):
            counts[suffix] = counts.get(suffix, 0) + 1
    common = sorted(counts, key=lambda suffix: (-counts[suffix], suffix))[:MAX_EXTENSIONS]
    return tuple(f"ext:{suffix}" for suffix in sorted(common))


def manifest_text(engine: str, challenge_id: str, name: str, category: str | None, words: tuple[str, ...],
                  files: tuple[str, ...], *, from_name: bool = False) -> str:
    """The manifest of a scaffolded engine. Every value is one a manifest accepts (checked
    by the caller), written as a TOML string."""
    lines = [
        f"# The L1 engine {engine}, written by `flightdeck build gap` for the challenge {challenge_id}.",
        "# Its route describes that one challenge: a route matches when every condition in it",
        "# holds, and a condition holds when any one of its items does. Widen it so challenges",
        f"# like this one reach the engine too: tests/test_{name}.py checks that the archived",
        "# handout still does.",
        f"id = {_toml(engine)}",
        f"entry = {_toml(name + '.py:solve')}",
        'output = "result"',
        "",
        "[[routes]]",
    ]
    if category:
        lines.append(f"category = [{_toml(category)}]  # its category")
    if words:
        where = "its name (its description has none)" if from_name else "its description"
        lines.append(f"keywords = [{', '.join(_toml(word) for word in words)}]  # distinctive words of {where}")
    if files:
        lines.append(f"files = [{', '.join(_toml(pattern) for pattern in files)}]  # its handout's file extensions")
    lines.append(f"priority = {PRIORITY}")
    return "\n".join(lines) + "\n"


def case_size(case: Path) -> tuple[int, int]:
    """(files, bytes) of the challenge copy in a case folder (its challenge.json included,
    the case's own board.json not)."""
    files = size = 0
    for directory, _, names in os.walk(case / BOARD):  # never follows a symlink
        for file_name in names:
            if Path(directory) == case / BOARD and file_name == BOARD_FILE:
                continue
            files += 1
            size += os.lstat(os.path.join(directory, file_name)).st_size
    return files, size


# ---------------------------------------------------------------- the parts of a scaffold


def _source(challenge_dir: Path, answers: Path | None):
    """(BoardChallenge, Board) for a challenge folder, read through its parent's board."""
    directory = challenge_dir.expanduser()
    if not (directory / CHALLENGE_FILE).is_file():
        raise BuildError(f"{_show(directory)} is not a challenge folder (it has no {CHALLENGE_FILE})")
    target = directory.resolve()
    try:
        board = load_board(target.parent, answers=answers)
    except BoardError as exc:
        raise BuildError(str(exc)) from None
    for item in board.challenges:
        if item.handout.resolve() == target:
            return item, board
    raise BuildError(f"{_show(directory)} is not one of the challenges of the board in {_show(target.parent)}")


def _answer(board, challenge_id: str) -> str | None:
    """The sha256 the board's answers file holds for the challenge, or None. load_board
    has checked the file; the hash is checked again as it is read."""
    if board.answers is None:
        return None
    try:
        data = json.loads(Path(board.answers).read_bytes().decode("utf-8-sig"))
    except (OSError, ValueError) as exc:
        raise BuildError(f"cannot read the answers file {_show(board.answers)}: {_show(exc)}") from None
    digest = data.get(challenge_id) if isinstance(data, dict) else None
    return digest if isinstance(digest, str) and SHA256.fullmatch(digest) else None


def _engine_ids(pack: Path) -> dict[str, Path]:
    """The ids of the engines already in the pack. A pack that does not load is refused:
    the case test would fail on it."""
    if not pack.is_dir():
        return {}
    try:
        return {manifest.id: manifest.path for manifest in discover(pack)}
    except ManifestError as exc:
        raise BuildError(f"the pack does not load, so a new engine could not be tested in it: {exc}") from None


def _real_dirs(pack: Path, parts: tuple[str, ...], created: list[Path]) -> None:
    """pack/parts as real folders: made when missing, refused when a symlink (discovery never
    follows a symlinked folder, so an engine in one would never be found)."""
    current = pack
    for part in parts:
        current = current / part
        if current.is_symlink() or (current.exists() and not current.is_dir()):
            raise BuildError(f"{_show(current)} is {'a symlink' if current.is_symlink() else 'not a folder'}; build mode writes only into real folders")
        if not current.exists():
            current.mkdir()
            created.append(current)


def _write_case(layout: Layout, handout: Path, board, engine: str, challenge_id: str, digest: str | None,
                created: list[Path]) -> None:
    """The case folder: the challenge copied as data, its board's flag format, the answer's
    sha256 (when known) and case.json."""
    layout.case.mkdir()  # never one that is there: scaffold checked, and mkdir refuses
    created.append(layout.case)
    layout.board.mkdir()
    archive = layout.board / challenge_id
    copy_handout(handout, archive)
    os.replace(archive / PRIVATE / "prepare.log", layout.case / COPY_LOG)
    shutil.rmtree(archive / PRIVATE)  # copy_handout's own folder, made for a workspace: not handout content
    settings: dict[str, str] = {"event": board.event}
    if board.flag_format:
        settings["flag_format"] = board.flag_format
    _write_new(layout.board / BOARD_FILE, json.dumps(settings, indent=2) + "\n", created)
    if digest is not None:
        _write_new(layout.answers, json.dumps({challenge_id: digest}, indent=2) + "\n", created)
    _write_new(layout.case / CASE_FILE, json.dumps({"engine": engine, "challenge": challenge_id}, indent=2) + "\n", created)


def _archived(layout: Layout, challenge_id: str):
    """(Board, BoardChallenge) read back from the case, the way the case test reads it."""
    try:
        board = load_board(layout.board, answers=layout.answers if layout.answers.exists() else None)
    except BoardError as exc:
        raise BuildError(f"the copy of the challenge does not load as a board: {exc}") from None
    for item in board.challenges:
        if item.challenge.id == challenge_id:
            return board, item
    raise BuildError(f"the copy in {_show(layout.board)} does not hold the challenge {challenge_id}")


def _verify(layout: Layout, engine: str, archived_item) -> None:
    """What the case test's routing step checks, checked once now: the manifest loads, the
    pack finds the engine, and the archived challenge routes to it."""
    try:
        load(layout.manifest)
        manifests = discover(layout.pack)
    except ManifestError as exc:
        raise BuildError(f"the new manifest does not load: {exc}") from None
    if engine not in {manifest.id for manifest in manifests}:
        raise BuildError(f"the pack's discovery does not find {_show(layout.manifest)}")
    hits = route(manifests, archived_item.challenge, archived_item.handout)
    if engine not in {hit.manifest.id for hit in hits}:
        raise BuildError(f"the new route does not reach the challenge it was made from (in {_show(layout.manifest)})")


def _write_new(path: Path, text: str, created: list[Path]) -> None:
    """A new file, never one that is there (a symlink included): O_EXCL and O_NOFOLLOW."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
    except FileExistsError:
        raise BuildError(f"{_show(path)} is there already; build mode never overwrites") from None
    created.append(path)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as out:
        out.write(text)


def _undo(created: list[Path]) -> None:
    """Remove what a failed scaffold made, newest first; nothing that was there before."""
    for path in reversed(created):
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)  # a folder scaffold made: everything in it is scaffold's too
            else:
                path.unlink(missing_ok=True)
        except OSError:
            pass  # best effort: the error being raised says what went wrong


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


_SOLVER = Template('''\
"""The L1 engine $engine, written by `flightdeck build gap` for the challenge $challenge.

flightdeck calls solve(challenge_dir) in a copy of a challenge's handout: challenge_dir
holds its files and its challenge.json, and scratch files may go there too. solve()
returns a SolverResult:
- "solved": the flag, with evidence a human can check;
- "candidate": flags that may be right;
- "none": nothing found;
- "blocked": something it needs is missing (its notes say what).

The engine is done when its test passes: `flightdeck build check <pack>` runs
tests/test_$name.py. The challenge it was written for is in
tests/cases/$name/.board/$challenge/, as it was handed out.
"""

from pathlib import Path

from ctf_flightdeck.l1.result import Evidence, SolverResult


def solve(challenge_dir: Path) -> SolverResult:
    # Find the flag in challenge_dir, then say how you found it, for example:
    #     return SolverResult("solved", flags=[flag], evidence=[Evidence("decode", "base64, three times", "message.txt")])
    return SolverResult("none", notes="not written yet")
''')

_TEST = Template('''\
"""The case test of the L1 engine $engine, written by `flightdeck build gap`.

cases/$name/ is the challenge $challenge as it was handed out: a copy of its challenge.json
and files in cases/$name/.board/ (a hidden folder, so that neither flightdeck nor pytest
ever reads a handout file as code), and the sha256 of its flag in answers.sha256.json, never
the flag itself.

The engine is done when both tests pass:
- test_routed: flightdeck's router sends the archived handout to $engine;
- test_solved: run the way flightdeck runs it, in a copy of the handout, $engine reports
  "solved" with the archived flag.
`flightdeck build check <pack>` runs them; so does pytest.
"""

import asyncio
from pathlib import Path

import pytest

from ctf_flightdeck.core.model import DeckConfig
from ctf_flightdeck.l1.manifest import discover
from ctf_flightdeck.l1.router import route
from ctf_flightdeck.l1.runner import run_engine
from ctf_flightdeck.platform.manual import AnswerVerifier, load_board
from ctf_flightdeck.text import untrusted

ENGINE = $engine_literal
CHALLENGE = $challenge_literal
HERE = Path(__file__).resolve().parent
PACK = HERE.parent
CASE = HERE / "cases" / $name_literal
ANSWERS = CASE / "answers.sha256.json"


def archived():
    """(board, challenge) from the case, read the way flightdeck reads a folder board."""
    board = load_board(CASE / ".board", answers=ANSWERS if ANSWERS.exists() else None)
    for item in board.challenges:
        if item.challenge.id == CHALLENGE:
            return board, item
    pytest.fail(f"the case in {CASE} does not hold the challenge {CHALLENGE}")


def test_routed():
    board, item = archived()
    routed = [hit.manifest.id for hit in route(discover(PACK), item.challenge, item.handout)]
    if ENGINE not in routed:
        pytest.fail(
            f"the router does not send {CHALLENGE} to {ENGINE} (it sends it to {', '.join(routed) or 'no engine'}); "
            f"change the routes in the manifest of {ENGINE} until it does"
        )


def test_solved(tmp_path):
    board, item = archived()
    if board.answers is None:
        pytest.fail(f'no answer is archived: write {{"{CHALLENGE}": "<the sha256 of the flag>"}} to {ANSWERS}')
    engine = next((manifest for manifest in discover(PACK) if manifest.id == ENGINE), None)
    if engine is None:
        pytest.fail(f"no engine in {PACK} has the id {ENGINE}")
    flag_format = board.flag_format or DeckConfig(event=board.event).flag_format
    result = asyncio.run(run_engine(engine, item.handout, workdir=tmp_path, flag_format=flag_format, challenge_id=CHALLENGE))
    if result.status != "solved":
        notes = untrusted(result.notes, one_line=True)[:300]
        pytest.fail(f"{ENGINE} reported {result.status}, not solved" + (f": {notes}" if notes else ""))
    right = AnswerVerifier(board.answers)
    if not any(right(CHALLENGE, flag) for flag in result.flags):
        pytest.fail(f"{ENGINE} reported solved, but none of its {len(result.flags)} flags is the archived one")
''')


def _solver_text(engine: str, challenge_id: str, name: str) -> str:
    return _SOLVER.substitute(engine=engine, challenge=challenge_id, name=name)


def _test_text(engine: str, challenge_id: str, name: str) -> str:
    return _TEST.substitute(
        engine=engine, challenge=challenge_id, name=name,
        engine_literal=json.dumps(engine), challenge_literal=json.dumps(challenge_id), name_literal=json.dumps(name),
    )


# ---------------------------------------------------------------- check


@dataclass(frozen=True)
class _Case:
    name: str
    engine: str
    test: Path


def check(pack: Path, *, timeout: float | None = None, python: str | None = None) -> list[CheckResult]:
    """Run every case test in the pack (tests/test_<name>.py for each tests/cases/<name>/
    with a case.json), each in a pytest subprocess of its own (see the module docstring),
    in case-name order. `timeout` is seconds per case (default: its engine's timeout plus
    two minutes); `python` the interpreter (default: the one flightdeck runs with), which
    must be able to import pytest and flightdeck: BuildError names what is missing."""
    root = Path(pack).expanduser().absolute()
    if not root.is_dir():
        raise BuildError(f"{_show(root)}: {'is not a folder' if root.exists() else 'no such pack folder'}")
    if timeout is not None and not (isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
                                    and math.isfinite(timeout) and timeout > 0):
        raise BuildError(f"the timeout must be a positive number of seconds, got {timeout!r}")
    cases = _cases(root)
    if not cases:
        return []
    interpreter = python or sys.executable
    if not interpreter:
        raise BuildError("flightdeck cannot tell which python it runs with (sys.executable is empty), so it cannot run pytest")
    limits = _engine_timeouts(root)
    scratch = Path(tempfile.mkdtemp(prefix="flightdeck-build-check-"))
    try:
        _probe(interpreter, scratch / "probe")
        results = []
        for case in cases:
            limit = timeout if timeout is not None else limits.get(case.engine, MAX_TIMEOUT) + CHECK_SLACK
            results.append(_check_case(interpreter, root, case, float(limit), scratch / case.name))
        return results
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def _cases(root: Path) -> list[_Case]:
    folder = root / TESTS / CASES
    if folder.is_symlink() or not folder.is_dir():
        return []
    cases: list[_Case] = []
    with os.scandir(folder) as listing:
        entries = sorted(listing, key=lambda entry: entry.name)
    for entry in entries:
        if not _CASE_NAME.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
            continue
        if not (Path(entry.path) / CASE_FILE).is_file():
            continue
        engine, _ = case_ids(Path(entry.path))
        cases.append(_Case(entry.name, engine or entry.name, root / TESTS / f"test_{entry.name}.py"))
    return cases


def case_ids(case: Path) -> tuple[str | None, str | None]:
    """(engine id, challenge id) from a case folder's case.json; None for one it does not
    name, or names in a form that is not an id."""
    try:
        path = Path(case) / CASE_FILE
        if path.stat().st_size > 64 * 1024:
            return None, None
        data = json.loads(path.read_bytes().decode("utf-8-sig"))
    except (OSError, ValueError, RecursionError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    engine, challenge = data.get("engine"), data.get("challenge")
    engine_ok = isinstance(engine, str) and ENGINE_ID.fullmatch(engine) and len(engine) <= MAX_ID
    challenge_ok = isinstance(challenge, str) and CHALLENGE_ID.fullmatch(challenge) and len(challenge) <= MAX_CHALLENGE_ID
    return (engine if engine_ok else None), (challenge if challenge_ok else None)


def _engine_timeouts(root: Path) -> dict[str, int]:
    """Each engine's own timeout. A pack that does not load gives none: every case test then
    fails on it, saying why."""
    try:
        return {manifest.id: manifest.timeout_seconds for manifest in discover(root)}
    except ManifestError:
        return {}


_PROBE = (
    "import importlib.util\n"
    "print(' '.join(m for m in ('pytest', 'ctf_flightdeck') if importlib.util.find_spec(m) is None))\n"
)


def _probe(python: str, work: Path) -> None:
    """Check that `python`, run the way a case test is, can import pytest and flightdeck."""
    env = _env(work)
    try:
        done = subprocess.run(
            [python, "-I", "-B", "-c", _PROBE], cwd=work / "cwd", env=env, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=PROBE_TIMEOUT,
        )
    except OSError as exc:
        raise BuildError(f"cannot run {_show(python)} to run the case tests: {_show(exc.strerror or exc)}") from None
    except subprocess.TimeoutExpired:
        raise BuildError(f"{_show(python)} did not answer within {PROBE_TIMEOUT:g}s") from None
    missing = done.stdout.decode("utf-8", "replace").split()
    if done.returncode != 0 or any(name not in ("pytest", "ctf_flightdeck") for name in missing):
        raise BuildError(f"{_show(python)} could not be asked what it can import (it exited {done.returncode})")
    if "pytest" in missing:
        raise BuildError(
            f"pytest is not installed for {_show(python)}, so the case tests cannot run: install pytest "
            "into the environment flightdeck runs in"
        )
    if missing:
        raise BuildError(f"{_show(python)} cannot import ctf_flightdeck, which the case tests use")


def _env(work: Path) -> dict[str, str]:
    """The allowlist, and a HOME and TMPDIR of the run's own (made here)."""
    for sub in ("home", "tmp", "cwd"):
        (work / sub).mkdir(parents=True, exist_ok=True)
    env = {name: os.environ[name] for name in ALLOWED_ENV if name in os.environ}
    env["HOME"] = str(work / "home")
    env["TMPDIR"] = str(work / "tmp")
    env["TERM"] = "dumb"
    return env


def _check_case(python: str, root: Path, case: _Case, limit: float, work: Path) -> CheckResult:
    shown = case.test.relative_to(root).as_posix()
    if not case.test.is_file():
        return CheckResult(case.name, case.engine, case.test, False, f"{shown} is missing")
    env = _env(work)
    ini = work / "pytest.ini"
    ini.write_text("[pytest]\n", encoding="utf-8")  # so no configuration above the pack applies
    report = work / "report.xml"
    argv = [
        python, "-I", "-B", "-m", "pytest", "-q", "--color=no", "-p", "no:cacheprovider",
        "-c", str(ini), "--rootdir", str(root), "--confcutdir", str(root),
        "--basetemp", str(work / "basetemp"), "--junitxml", str(report), str(case.test),
    ]
    begun = time.monotonic()
    code, output, timed_out = _run(argv, cwd=work / "cwd", env=env, limit=limit, log=work / "output.log")
    seconds = time.monotonic() - begun
    if timed_out:
        return CheckResult(case.name, case.engine, case.test, False, f"timed out after {limit:g}s; pytest was stopped",
                           seconds=seconds)
    outcomes = _outcomes(report)
    passed, detail = _verdict(code, outcomes, output)
    pairs = tuple((test, outcome) for test, outcome, _ in outcomes or ())
    return CheckResult(case.name, case.engine, case.test, passed, detail, pairs, seconds)


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], limit: float, log: Path) -> tuple[int | None, str, bool]:
    """(exit code, the end of the output, timed out) of a command in a session of its own.
    On timeout, or when flightdeck itself is interrupted, it is stopped (see _stop).
    Whatever its process group left running is killed either way."""
    with open(log, "wb") as out:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as exc:
            raise BuildError(f"cannot run {_show(argv[0])}: {_show(exc.strerror or exc)}") from None
        timed_out = False
        try:
            proc.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if proc.returncode is None:  # timed out, or flightdeck was interrupted: never leave it running
                _stop(proc)
            _signal_group(proc.pid, signal.SIGKILL)
    with open(log, "rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        handle.seek(max(0, size - OUTPUT_TAIL * 4))
        tail = handle.read().decode("utf-8", "replace")[-OUTPUT_TAIL:]
    return (None if timed_out else proc.returncode), tail, timed_out


def _stop(proc: subprocess.Popen) -> None:
    """Ask the process group to stop (SIGINT: pytest stops, and an engine run in progress
    kills the engine's own process group as it unwinds), then kill it after STOP_GRACE."""
    _signal_group(proc.pid, signal.SIGINT)
    try:
        proc.wait(timeout=STOP_GRACE)
    except subprocess.TimeoutExpired:
        _signal_group(proc.pid, signal.SIGKILL)
        proc.wait()


def _signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass  # the group is gone


def _outcomes(report: Path) -> list[tuple[str, str, str]] | None:
    """(test, outcome, message) for each test pytest's report lists, or None when there is
    no report it could read."""
    try:
        if not report.is_file() or report.stat().st_size > MAX_REPORT_BYTES:
            return None
        tree = ElementTree.parse(report)
    except (OSError, ElementTree.ParseError):
        return None
    found: list[tuple[str, str, str]] = []
    for case in tree.iter("testcase"):
        test = case.get("name", "")
        outcome, message = "passed", ""
        for kind in ("failure", "error", "skipped"):
            element = case.find(kind)
            if element is not None:
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[kind]
                message = _message(element)
                break
        found.append((test, outcome, message))
    return found


def _message(element: ElementTree.Element) -> str:
    """A failure's message, without pytest's "Failed: " for a pytest.fail(), and for a test
    module that did not import, the error it raised."""
    message = element.get("message", "")
    if message == "collection failure":
        errors = [line for line in (element.text or "").splitlines() if line.startswith("E ")]
        message = errors[-1][1:].strip() if errors else "it did not import"
    return message.removeprefix("Failed: ")


def _verdict(code: int | None, outcomes: list[tuple[str, str, str]] | None, output: str) -> tuple[bool, str]:
    """(passed, why not) from pytest's exit code and the tests its report lists."""
    if outcomes is None:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        last = f": {_detail(lines[-1])}" if lines else ""
        return False, f"pytest exited {code} and wrote no report{last}"
    problems: list[tuple[int, str]] = []  # (the test's place: test_routed first, then test_solved, then others; why)
    for test, outcome, message in outcomes:
        base = test.split("[", 1)[0]  # a parametrized test_solved[x] is test_solved
        rank = REQUIRED_TESTS.index(base) if base in REQUIRED_TESTS else len(REQUIRED_TESTS)
        if outcome == "skipped":
            problems.append((rank, f"{test} was skipped ({_detail(message)}); a skipped test is not a pass"))
        elif outcome != "passed":
            problems.append((rank, f"{test}: {_detail(message)}" if message else f"{test}: {outcome}"))
    if problems:
        return False, min(problems)[1]
    names = {test.split("[", 1)[0] for test, _, _ in outcomes}
    missing = [test for test in REQUIRED_TESTS if test not in names]
    if missing:
        return False, f"{' and '.join(missing)} did not run"
    if code != 0:
        return False, f"pytest exited {code}"
    return True, ""


def _detail(text: str) -> str:
    safe = untrusted(text, one_line=True).strip()
    return safe if len(safe) <= DETAIL else safe[: DETAIL - 3] + "..."


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _quote(value: object) -> str:
    safe = untrusted(str(value), one_line=True)
    return json.dumps(safe if len(safe) <= 60 else safe[:57] + "...", ensure_ascii=False)
