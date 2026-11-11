"""Build mode: scaffold() on synthetic folder boards in tmp_path (the files it writes, the
manifest through l1.manifest.load, the case test's routing and solved steps run in process,
never overwriting, handout files kept as data), check() running real pytest subprocesses
on those packs (passing and failing engines, the environment allowlist, timeouts, skips),
and the `flightdeck build` commands. Every engine is written here; none is a real solver,
and no challenge file is ever run."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import itertools
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck.build import (
    BuildError,
    case_ids,
    category_parts,
    check,
    extensions,
    keywords,
    scaffold,
)
from ctf_flightdeck.build_cli import app
from ctf_flightdeck.l1.importer import import_scripts
from ctf_flightdeck.l1.manifest import Route, discover, load
from ctf_flightdeck.l1.router import route
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.text import MARK, NEWLINE, untrusted

from l1_kit import challenge_dir, tree, write_manifest

FORMAT = r"t\{[a-z0-9_]+\}"
FLAG = "t{base64_three_times}"
DIGEST = hashlib.sha256(FLAG.encode()).hexdigest()
NOTE_FLAG = "t{on_the_note}"
FAKE_TOKEN = "fake-token-value-for-the-build-env-test"
ALLOWED = {"PATH", "LANG", "LC_ALL", "TERM", "HOME", "TMPDIR"}
PROCESS_OWN = {"PWD", "SHLVL", "_", "OLDPWD", "__CF_USER_TEXT_ENCODING", "LC_CTYPE", "PYTEST_VERSION", "PYTEST_CURRENT_TEST"}

# An engine that peels the base64 layers off message.txt; RESULT is what it returns.
_LAYERS = r'''
import base64
from ctf_flightdeck.l1.result import Evidence, SolverResult

def solve(challenge_dir):
    data = (challenge_dir / "message.txt").read_bytes()
    for _ in range(10):
        if data.startswith(b"t{"):
            break
        data = base64.b64decode(data)
    flag = data.decode()
    return RESULT
'''
REAL = _LAYERS.replace("RESULT", 'SolverResult("solved", flags=[flag], evidence=[Evidence("decode", "base64 until it reads t{", "message.txt")])')
CANDIDATE = _LAYERS.replace("RESULT", 'SolverResult("candidate", flags=[flag])')
WRONG = _LAYERS.replace("RESULT", 'SolverResult("solved", flags=[flag + "x"], evidence=[Evidence("decode", "one too many")])')
NOTE = r'''
import re
from ctf_flightdeck.l1.result import Evidence, SolverResult

def solve(challenge_dir):
    flag = re.search(r"t\{[a-z_]+\}", (challenge_dir / "note.txt").read_text()).group(0)
    return SolverResult("solved", flags=[flag], evidence=[Evidence("read", "the note says it", "note.txt")])
'''

runner = CliRunner()
_modules = itertools.count()


def invoke(*args):
    return runner.invoke(app, [str(a) for a in args], prog_name="flightdeck build")


def layered(text: str, times: int = 3) -> bytes:
    data = text.encode()
    for _ in range(times):
        data = base64.b64encode(data)
    return data


@pytest.fixture
def board(tmp_path: Path) -> Path:
    b = tmp_path / "board"
    b.mkdir()
    (b / "board.json").write_text(json.dumps({"event": "Test CTF", "flag_format": FORMAT}))
    challenge_dir(b, "layers", {"message.txt": layered(FLAG), "notes/readme.md": "nothing to see\n"}, category="Crypto",
                  title="Layers", description="Somebody encoded the flag with Base64, over and over. Peel every layer!")
    challenge_dir(b, "sticky-note", {"note.txt": f"the answer: {NOTE_FLAG}\n"}, title="Sticky Note",
                  description="Read the sticky note on the fridge.")
    (b / "answers.sha256.json").write_text(json.dumps({
        "layers": DIGEST, "sticky-note": hashlib.sha256(NOTE_FLAG.encode()).hexdigest(),
    }))
    return b


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    return tmp_path / "pack"  # scaffold makes it


def case_test(pack: Path, name: str):
    """The generated test module of a case, imported in this process (no bytecode written)."""
    path = pack / "tests" / f"test_{name}.py"
    spec = importlib.util.spec_from_file_location(f"case_test_{name}_{next(_modules)}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    before, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = before
    return module


def listing(root: Path) -> dict[str, str]:
    """relative path -> kind and content hash, for every entry under root (no times)."""
    return {rel: kind for rel, (kind, _, _) in tree(root).items()}


# ---------------------------------------------------------------- what scaffold writes


def test_scaffold_writes_the_engine_its_manifest_its_test_and_a_case_holding_a_copy_of_the_challenge(board, pack):
    before = tree(board)
    paths = scaffold(pack, board / "layers")
    assert paths == [
        pack / "cry" / "cry_layers.py",
        pack / "cry" / "cry_layers.manifest.toml",
        pack / "tests" / "test_cry_layers.py",
        pack / "tests" / "cases" / "cry_layers",
    ]
    case = paths[3]
    # the copy is the challenge as it was handed out, challenge.json included, byte for byte,
    # with nothing of flightdeck's own left in it
    assert listing(case / ".board" / "layers") == listing(board / "layers")
    assert json.loads((case / ".board" / "board.json").read_text()) == {"event": "Test CTF", "flag_format": FORMAT}
    assert json.loads((case / "answers.sha256.json").read_text()) == {"layers": DIGEST}
    assert json.loads((case / "case.json").read_text()) == {"engine": "cry.layers", "challenge": "layers"}
    assert case_ids(case) == ("cry.layers", "layers")
    assert (case / "copy.log").read_text().startswith("copied 3 files")
    assert sorted(path.relative_to(pack).as_posix() for path in pack.rglob("*") if path.is_file()) == [
        "cry/cry_layers.manifest.toml",
        "cry/cry_layers.py",
        "tests/cases/cry_layers/.board/board.json",
        "tests/cases/cry_layers/.board/layers/challenge.json",
        "tests/cases/cry_layers/.board/layers/message.txt",
        "tests/cases/cry_layers/.board/layers/notes/readme.md",
        "tests/cases/cry_layers/answers.sha256.json",
        "tests/cases/cry_layers/case.json",
        "tests/cases/cry_layers/copy.log",
        "tests/test_cry_layers.py",
    ]
    assert 'return SolverResult("none", notes="not written yet")' in paths[0].read_text()
    assert tree(board) == before  # nothing was written to the board


def test_the_manifest_loads_and_routes_by_category_description_words_and_extensions_at_priority_60(board, pack):
    scaffold(pack, board / "layers")
    manifest = load(pack / "cry" / "cry_layers.manifest.toml")
    entry = manifest.entry
    assert (manifest.id, entry.kind, entry.path, entry.function, manifest.output) == ("cry.layers", "python", "cry_layers.py", "solve", "result")
    assert manifest.routes == (
        Route(category=("cry",), keywords=("encoded", "base64", "layer"), files=("ext:.md", "ext:.txt"), priority=60),
    )
    assert [m.id for m in discover(pack)] == ["cry.layers"]


def test_the_archived_challenge_routes_to_the_new_engine_through_the_router(board, pack):
    scaffold(pack, board / "layers")
    [item] = load_board(pack / "tests" / "cases" / "cry_layers" / ".board").challenges
    assert [hit.manifest.id for hit in route(discover(pack), item.challenge, item.handout)] == ["cry.layers"]
    case_test(pack, "cry_layers").test_routed()  # the generated routing step passes as written


def test_the_routing_step_fails_when_the_route_no_longer_reaches_the_handout(board, pack):
    _, manifest, _, _ = scaffold(pack, board / "layers")
    manifest.write_text(manifest.read_text().replace('"encoded", "base64", "layer"', '"nothing_like_it"'))
    with pytest.raises(pytest.fail.Exception, match=r"the router does not send layers to cry\.layers \(it sends it to no engine\)"):
        case_test(pack, "cry_layers").test_routed()


def test_the_solved_step_fails_until_a_real_solver_is_written_then_passes(board, pack, tmp_path):
    solver, *_ = scaffold(pack, board / "layers")
    module = case_test(pack, "cry_layers")
    with pytest.raises(pytest.fail.Exception, match=r"^cry\.layers reported none, not solved: not written yet$"):
        module.test_solved(tmp_path / "w1")
    solver.write_text(REAL)
    module.test_solved(tmp_path / "w2")  # the engine finds the flag in a copy of the raw handout


@pytest.mark.parametrize(("body", "error"), [
    (WRONG, r"cry\.layers reported solved, but none of its 1 flags is the archived one"),
    (CANDIDATE, r"cry\.layers reported candidate, not solved"),
])
def test_only_solved_with_the_archived_flag_passes(board, pack, tmp_path, body, error):
    solver, *_ = scaffold(pack, board / "layers")
    solver.write_text(body)
    with pytest.raises(pytest.fail.Exception, match=error):
        case_test(pack, "cry_layers").test_solved(tmp_path / "w")


def test_without_an_answer_the_solved_step_says_how_to_add_one(board, pack, tmp_path):
    (board / "answers.sha256.json").unlink()
    solver, _, _, case = scaffold(pack, board / "layers")
    assert not (case / "answers.sha256.json").exists()
    solver.write_text(REAL)
    module = case_test(pack, "cry_layers")
    module.test_routed()
    with pytest.raises(pytest.fail.Exception, match=r'no answer is archived: write \{"layers": "<the sha256 of the flag>"\} to '):
        module.test_solved(tmp_path / "w1")
    (case / "answers.sha256.json").write_text(json.dumps({"layers": DIGEST}))
    module.test_solved(tmp_path / "w2")


def test_an_answers_file_given_is_used_and_only_the_sha256_of_the_flag_is_kept(board, pack, tmp_path):
    (board / "answers.sha256.json").unlink()
    given = tmp_path / "mine.sha256.json"
    given.write_text(json.dumps({"layers": DIGEST}))
    scaffold(pack, board / "layers", answers=given)
    assert json.loads((pack / "tests" / "cases" / "cry_layers" / "answers.sha256.json").read_text()) == {"layers": DIGEST}
    for path in pack.rglob("*"):
        if path.is_file():
            assert FLAG.encode() not in path.read_bytes(), path


# ---------------------------------------------------------------- never overwriting, refusing


def test_scaffold_never_overwrites_and_writes_nothing_when_one_of_its_files_is_there(board, pack):
    (pack / "tests").mkdir(parents=True)
    (pack / "tests" / "test_cry_layers.py").write_text("# the player's own\n")
    before = tree(pack)
    with pytest.raises(BuildError, match=r"test_cry_layers\.py is there already; build mode never overwrites: pass another --name"):
        scaffold(pack, board / "layers")
    assert tree(pack) == before
    (pack / "tests" / "test_cry_layers.py").unlink()
    os.symlink(pack / "nowhere", pack / "tests" / "test_cry_layers.py")  # a dangling symlink is there too
    with pytest.raises(BuildError, match="there already"):
        scaffold(pack, board / "layers")
    (pack / "tests" / "test_cry_layers.py").unlink()

    scaffold(pack, board / "layers")
    after = tree(pack)
    with pytest.raises(BuildError, match=r"the pack already has an engine with the id cry\.layers"):
        scaffold(pack, board / "layers")
    with pytest.raises(BuildError, match=r"cry_layers\.py, .*cry_layers\.manifest\.toml, .*test_cry_layers\.py, .*cases/cry_layers are there already"):
        scaffold(pack, board / "layers", engine_id="cry-layers")  # another id, the same file names
    assert tree(pack) == after
    other = scaffold(pack, board / "layers", engine_id="decode.base64_layers")
    assert other[0] == pack / "cry" / "decode_base64_layers.py"
    assert [m.id for m in discover(pack)] == ["cry.layers", "decode.base64_layers"]


@pytest.mark.parametrize(("engine_id", "error"), [
    ("Bad Name", "is not an engine id"),
    ("-layers", "is not an engine id"),
    ("x" * 101, "is not an engine id"),
    ("json", "would hide python's own json module"),
])
def test_an_engine_id_is_checked_before_anything_is_written(board, pack, engine_id, error):
    with pytest.raises(BuildError, match=error):
        scaffold(pack, board / "layers", engine_id=engine_id)
    assert not pack.exists()


def test_a_pack_that_does_not_load_is_refused(board, pack):
    write_manifest(pack, "broken", 'id = "broken"\nentry = "cli:true"\n[[routes]]\npriority = 5\n')
    with pytest.raises(BuildError, match="the pack does not load"):
        scaffold(pack, board / "layers")
    assert sorted(p.name for p in pack.iterdir()) == ["broken.manifest.toml"]


def test_a_pack_and_a_board_inside_each_other_are_refused(board, tmp_path):
    before = tree(board)
    with pytest.raises(BuildError, match="is inside the challenge"):
        scaffold(board / "layers" / "pack", board / "layers")
    assert tree(board) == before  # no pack folder was made in the handout
    with pytest.raises(BuildError, match="keep boards outside the pack"):
        scaffold(tmp_path, board / "layers")


def test_a_symlinked_folder_in_the_pack_is_refused(board, pack, tmp_path):
    pack.mkdir()
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", pack / "cry")
    with pytest.raises(BuildError, match="is a symlink; build mode writes only into real folders"):
        scaffold(pack, board / "layers")
    assert list((tmp_path / "elsewhere").iterdir()) == [] and sorted(p.name for p in pack.iterdir()) == ["cry"]


def test_a_folder_that_is_not_a_challenge_is_refused(board, pack):
    (board / "empty").mkdir()
    with pytest.raises(BuildError, match="is not a challenge folder"):
        scaffold(pack, board / "empty")


def test_with_nothing_else_to_route_by_the_keywords_come_from_the_name(tmp_path, pack):
    folder = challenge_dir(tmp_path / "b", "crackme", {"chall": b"\x00\x01"}, category="Reverse Engineering",
                           title="Baby Crackme", description="")
    _, manifest, _, _ = scaffold(pack, folder)
    assert load(manifest).routes == (Route(keywords=("crackme", "baby"), priority=60),)
    assert "# distinctive words of its name (its description has none)" in manifest.read_text()
    case_test(pack, "reverse_engineering_crackme").test_routed()


def test_a_challenge_nothing_can_route_is_refused_and_nothing_is_kept(tmp_path, pack):
    folder = challenge_dir(tmp_path / "b", "x", {"chall": b"\x00"}, category="Reverse Engineering", title="X", description="")
    with pytest.raises(BuildError, match="nothing about x can make a route"):
        scaffold(pack, folder)
    assert not pack.exists()  # it made the pack, then the case, and took both back


def test_a_scaffold_that_fails_its_own_check_leaves_nothing_behind(board, pack, monkeypatch):
    pack.mkdir()
    (pack / "mine.txt").write_text("the player's\n")
    before = listing(pack)
    monkeypatch.setattr("ctf_flightdeck.build.route", lambda *args: [])  # the router finds no hit for the new route
    with pytest.raises(BuildError, match="the new route does not reach the challenge it was made from"):
        scaffold(pack, board / "layers")
    assert listing(pack) == before


# ---------------------------------------------------------------- the handout is data


def test_handout_files_are_copied_as_data_and_never_run_imported_or_read_as_engines(tmp_path, pack):
    marks = tmp_path / "marks"
    marks.mkdir()
    b = tmp_path / "board"
    folder = challenge_dir(b, "layers", {
        "message.txt": layered(FLAG),
        "evil.manifest.toml": 'id = "evil"\nentry = "cli:./evil.sh"\n[[routes]]\nkeywords = ["layer"]\npriority = 100\n',
        "evil.sh": f"#!/bin/sh\ntouch {marks / 'evil'}\n",
        "run.sh": f"#!/bin/sh\ntouch {marks / 'run'}\n",
        "conftest.py": f"open({str(marks / 'conftest')!r}, 'w').close()\n",
        "test_planted.py": f"open({str(marks / 'planted')!r}, 'w').close()\n\ndef test_planted():\n    pass\n",
        "solve.py": f"if __name__ == '__main__':\n    open({str(marks / 'solve')!r}, 'w').close()\n",
    }, category="crypto", description="Peel every layer.")
    for name in ("evil.sh", "run.sh"):
        (folder / name).chmod(0o755)
    (b / "answers.sha256.json").write_text(json.dumps({"layers": DIGEST}))
    solver, *_ = scaffold(pack, folder)
    solver.write_text(REAL)
    assert [m.id for m in discover(pack)] == ["cry.layers"]  # the handout's manifest is not an engine of the pack
    assert import_scripts(pack).written == []  # nor are its scripts, for the importer
    [result] = check(pack)
    assert (result.engine, result.passed, result.outcomes) == ("cry.layers", True, (("test_routed", "passed"), ("test_solved", "passed")))
    # a player who runs plain pytest on the whole pack collects the case test, and nothing of the handout
    plain = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "pytest", "-q", "-p", "no:cacheprovider", str(pack)],
        cwd=pack, env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)}, capture_output=True, text=True, timeout=300,
    )
    assert plain.returncode == 0, plain.stdout
    assert plain.stdout.splitlines()[-1].startswith("2 passed")
    assert list(marks.iterdir()) == []  # nothing from the handout ran, while scaffolding or checking


@pytest.mark.parametrize(("category", "parts"), [
    ("Crypto", ("cry", "cry")),
    ("forensics", ("for", "for")),
    ("hardware", ("hardware", "hardware")),
    ("Reverse Engineering", (None, "reverse_engineering")),
    ("Web / ‮Rev", (None, "web_rev")),
    ("", (None, "uncategorized")),
    ("网络", (None, "uncategorized")),
    ("tests", ("tests", "tests_")),  # the pack's tests folder is not a category folder
])
def test_a_category_gives_a_route_code_only_when_a_manifest_can_name_it_and_always_a_plain_folder(category, parts):
    assert category_parts(category) == parts


@pytest.mark.parametrize(("text", "words"), [
    ("Somebody encoded the flag with Base64, over and over. Peel every layer!", ("encoded", "base64", "layer")),
    ("alpha bravo charlie delta", ("charlie", "alpha", "bravo")),  # the longest first, then in order
    ("zebra lemur koala", ("zebra", "lemur", "koala")),
    ("RSA with e = 3, xor xor XOR", ()),  # under 4 letters, or a stop word
    ("an md5sum of the dump", ("md5sum", "dump")),  # letters are counted, digits ride along
    ("key: " + "a" * 31 + " then pangolin", ("pangolin",)),  # a blob is not a word
    ("Find the flag in this file, it is hidden somewhere here.", ()),
])
def test_keywords_are_up_to_3_distinctive_words(text, words):
    assert keywords(text) == words


def test_extensions_are_each_files_last_suffix_lower_cased_sorted_and_capped_at_10(tmp_path):
    handout = challenge_dir(tmp_path / "b", "c", {
        "a.TXT": "", "sub/b.txt": "", "c.tar.gz": "", "noext": "", ".bashrc": "", "e.we!rd": "",
    })
    assert extensions(handout) == ("ext:.gz", "ext:.txt")  # challenge.json is the board's, not the handout's
    many = challenge_dir(tmp_path / "b", "many", {f"f{i}.e{i:02d}": "" for i in range(12)} | {"g.e10": "", "g.e11": ""})
    assert extensions(many) == tuple(f"ext:.e{i:02d}" for i in (0, 1, 2, 3, 4, 5, 6, 7, 10, 11))


def test_hostile_challenge_text_stays_data_in_every_file_written(tmp_path, pack):
    b = tmp_path / "hostile"
    folder = challenge_dir(
        b, "evil", {"x.bin": b"\x00", "y.\x1bz": b"", "notes.TXT": "hi"},
        category="Web / ‮Rev", title='Evil """\n\x1b[2J',
        description='"""; import os; os.system("x") \x1b]0;pwn\x07 ‮desserts‬ ' + "A" * 50 + " zebrafish",
    )
    paths = scaffold(pack, folder)
    solver, manifest, test, case = paths
    assert paths[0] == pack / "web_rev" / "web_rev_evil.py"
    assert load(manifest).routes == (Route(keywords=("zebrafish", "desserts", "import"), files=("ext:.bin", "ext:.txt"), priority=60),)
    for path in (solver, manifest, test, case / "case.json", case / ".board" / "board.json", case / "answers.sha256.json"):
        if not path.exists():
            continue
        text = path.read_text()
        assert text == untrusted(text), path  # no control, bidi or invisible character in anything written
        assert "os.system" not in text and "Evil" not in text, path
    for path in (solver, test):
        compile(path.read_text(), str(path), "exec")
    case_test(pack, "web_rev_evil").test_routed()


# ---------------------------------------------------------------- check


def test_check_lists_engines_passing_and_failing_and_why(board, pack):
    layers, layers_manifest, _, _ = scaffold(pack, board / "layers")
    scaffold(pack, board / "sticky-note")
    layers.write_text(REAL)
    results = check(pack)
    assert [(r.name, r.engine, r.passed) for r in results] == [("cry_layers", "cry.layers", True), ("misc_sticky_note", "misc.sticky-note", False)]
    assert results[0].detail == "" and results[0].outcomes == (("test_routed", "passed"), ("test_solved", "passed"))
    assert results[1].detail == "test_solved: misc.sticky-note reported none, not solved: not written yet"
    assert results[1].outcomes == (("test_routed", "passed"), ("test_solved", "failed"))
    assert results[1].test == pack / "tests" / "test_misc_sticky_note.py"

    layers_manifest.write_text(layers_manifest.read_text().replace('"encoded", "base64", "layer"', '"nothing_like_it"'))
    first = check(pack)[0]
    assert not first.passed and first.outcomes == (("test_routed", "failed"), ("test_solved", "passed"))
    assert first.detail.startswith("test_routed: the router does not send layers to cry.layers (it sends it to no engine)")
    for leftover in ("__pycache__", ".pytest_cache"):
        assert not list(pack.rglob(leftover))  # pytest left nothing in the pack


def test_check_needs_both_tests_to_run_and_pass(board, pack):
    solver, _, test, _ = scaffold(pack, board / "layers")
    solver.write_text(REAL)
    test.write_text(test.read_text().split("def test_solved")[0])  # test_solved deleted
    [result] = check(pack)
    assert (result.passed, result.detail) == (False, "test_solved did not run")
    test.unlink()
    [result] = check(pack)
    assert (result.passed, result.detail) == (False, "tests/test_cry_layers.py is missing")


def test_a_skipped_case_test_is_not_a_pass(board, pack):
    solver, *_ = scaffold(pack, board / "layers")
    solver.write_text(REAL)
    (pack / "tests" / "conftest.py").write_text(
        "import pytest\n\n@pytest.fixture(autouse=True)\ndef no_tool():\n    pytest.skip('no zsteg here')\n"
    )
    [result] = check(pack)
    assert not result.passed
    assert result.detail == "test_routed was skipped (no zsteg here); a skipped test is not a pass"


def test_a_case_test_that_does_not_import_fails_with_its_error(board, pack):
    _, _, test, _ = scaffold(pack, board / "layers")
    test.write_text("import not_a_module_anywhere\n" + test.read_text())
    [result] = check(pack)
    assert not result.passed
    assert result.detail == "tests.test_cry_layers: ModuleNotFoundError: No module named 'not_a_module_anywhere'"


def test_failure_messages_are_made_safe_to_print(board, pack, tmp_path):
    solver, _, test, _ = scaffold(pack, board / "layers")
    solver.write_text(  # an engine whose notes carry what a challenge file might
        "from ctf_flightdeck.l1.result import SolverResult\n\n"
        "def solve(challenge_dir):\n    return SolverResult('none', notes='line one\\nline \\u202etwo\\x1b[2J')\n"
    )
    with pytest.raises(pytest.fail.Exception) as failed:
        case_test(pack, "cry_layers").test_solved(tmp_path / "w")
    assert str(failed.value) == f"cry.layers reported none, not solved: line one{NEWLINE}line {MARK}two^[[2J"
    test.write_text("raise RuntimeError('bad \\u202eidea')\n" + test.read_text())
    [result] = check(pack)
    assert result.detail == f"tests.test_cry_layers: RuntimeError: bad {MARK}idea"


def test_check_runs_the_case_tests_without_the_players_secrets(board, pack, tmp_path, monkeypatch):
    for name in ("CTFD_TOKEN", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN"):
        monkeypatch.setenv(name, FAKE_TOKEN)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("PYTEST_ADDOPTS", "--not-an-option-of-pytest")
    scaffold(pack, board / "layers")
    seen = tmp_path / "seen.json"
    (pack / "tests" / "conftest.py").write_text(  # the player's own test code, which check runs
        f"import json, os, sys\nwith open({str(seen)!r}, 'w') as out:\n"
        "    json.dump({'env': dict(os.environ), 'isolated': sys.flags.isolated, 'no_bytecode': sys.dont_write_bytecode}, out)\n"
    )
    [result] = check(pack)
    assert result.outcomes == (("test_routed", "passed"), ("test_solved", "failed"))  # pytest ran, without the bad option
    raw = seen.read_text()
    seen_by_tests = json.loads(raw)
    env = seen_by_tests["env"]
    assert FAKE_TOKEN not in raw and "PYTHONPATH" not in env and "PYTEST_ADDOPTS" not in env
    assert set(env) - PROCESS_OWN <= ALLOWED and "PATH" in env
    assert "flightdeck-build-check-" in env["HOME"] and env["HOME"] != os.environ.get("HOME")
    assert (seen_by_tests["isolated"], seen_by_tests["no_bytecode"]) == (1, True)  # python -I -B


def test_a_run_pytest_calls_failed_is_not_a_pass_even_when_each_test_passed(board, pack):
    solver, *_ = scaffold(pack, board / "layers")
    solver.write_text(REAL)
    (pack / "tests" / "conftest.py").write_text("def pytest_sessionfinish(session):\n    session.exitstatus = 3\n")
    [result] = check(pack)
    assert result.outcomes == (("test_routed", "passed"), ("test_solved", "passed"))
    assert (result.passed, result.detail) == (False, "pytest exited 3")


def test_no_configuration_or_conftest_above_the_pack_applies(board, tmp_path):
    above = tmp_path / "workspace"
    pack = above / "pack"
    above.mkdir()
    (above / "pytest.ini").write_text("[pytest]\naddopts = --not-an-option-of-pytest\n")
    (above / "conftest.py").write_text(f"open({str(tmp_path / 'above-ran')!r}, 'w').close()\n")
    solver, *_ = scaffold(pack, board / "layers")
    solver.write_text(REAL)
    [result] = check(pack)
    assert (result.passed, result.detail) == (True, "")
    assert not (tmp_path / "above-ran").exists()


def test_a_case_test_past_its_timeout_is_stopped_with_its_engine_and_whatever_it_left_running(board, pack, tmp_path):
    marks = tmp_path / "marks"
    marks.mkdir()
    solver, *_ = scaffold(pack, board / "layers")
    solver.write_text(  # an engine that hangs (its own timeout is 60 s)
        "import time\nfrom ctf_flightdeck.l1.result import SolverResult\n\n"
        f"def solve(challenge_dir):\n    open({str(marks / 'engine-started')!r}, 'w').close()\n"
        f"    time.sleep(4)\n    open({str(marks / 'engine-finished')!r}, 'w').close()\n"
        "    return SolverResult('none')\n"
    )
    (pack / "tests" / "conftest.py").write_text(  # and test code that leaves a process behind, deaf to SIGINT
        "import subprocess\n"
        f"subprocess.Popen(['sh', '-c', \"trap '' INT; sleep 4; touch {marks / 'leftover'}\"])\n"
    )
    begun = time.monotonic()
    [result] = check(pack, timeout=3)
    assert time.monotonic() - begun < 3 + 5 + 2  # the timeout, the grace before a kill, and slack
    assert (result.passed, result.detail) == (False, "timed out after 3s; pytest was stopped")
    time.sleep(3)  # past the moment the engine and the leftover process would have written their marks
    assert sorted(p.name for p in marks.iterdir()) == ["engine-started"]


def test_check_without_pytest_or_a_python_fails_loudly(board, pack, tmp_path):
    scaffold(pack, board / "layers")
    fake = tmp_path / "python-without-pytest"
    fake.write_text("#!/bin/sh\necho pytest\n")  # stands in for an interpreter that cannot import pytest
    fake.chmod(0o755)
    with pytest.raises(BuildError, match="pytest is not installed for .*python-without-pytest, so the case tests cannot run"):
        check(pack, python=str(fake))
    with pytest.raises(BuildError, match="cannot run .*no-such-python"):
        check(pack, python=str(tmp_path / "no-such-python"))


def test_check_of_a_pack_with_no_cases_runs_nothing(tmp_path):
    (tmp_path / "pack").mkdir()
    assert check(tmp_path / "pack") == []
    with pytest.raises(BuildError, match="no such pack folder"):
        check(tmp_path / "missing")
    with pytest.raises(BuildError, match="the timeout must be a positive number"):
        check(tmp_path / "pack", timeout=0)


# ---------------------------------------------------------------- the commands


def test_build_gap_writes_the_engine_and_says_what_to_do_next(board, pack):
    result = invoke("gap", board / "layers", "--pack", pack)
    assert result.exit_code == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[:3] == [
        "wrote cry/cry_layers.py: the engine, a stub until you write solve()",
        "wrote cry/cry_layers.manifest.toml: routes category cry, and keywords encoded | base64 | layer, "
        "and files ext:.md | ext:.txt (priority 60)",
        "wrote tests/test_cry_layers.py: its test, test_routed and test_solved",
    ]
    assert lines[3].startswith("wrote tests/cases/cry_layers/: a copy of the challenge as it was handed out (3 files, ")
    assert lines[3].endswith(") and the sha256 of its flag")
    assert lines[4] == f"next: write solve() in cry/cry_layers.py, then run `flightdeck build check {pack}`; the engine is done when its test passes"
    assert result.stderr == ""


def test_build_gap_takes_a_name_and_an_answers_file_and_warns_when_there_is_no_answer(board, pack, tmp_path):
    (board / "answers.sha256.json").unlink()
    result = invoke("gap", board / "sticky-note", "--pack", pack, "--name", "read.notes")
    assert result.exit_code == 0, result.stderr
    assert result.stdout.startswith("wrote misc/read_notes.py: ")
    assert "and the sha256 of its flag" not in result.stdout
    assert 'the board has no answer for sticky-note, so test_solved fails until you write {"sticky-note": "<the sha256 of the flag>"}' in result.stderr
    given = tmp_path / "answers.json"
    given.write_text(json.dumps({"layers": DIGEST}))
    result = invoke("gap", board / "layers", "--pack", pack, "--answers", given)
    assert result.exit_code == 0 and "and the sha256 of its flag" in result.stdout and result.stderr == ""


def test_build_gap_fails_with_the_reason(board, pack):
    (board / "empty").mkdir()
    result = invoke("gap", board / "empty", "--pack", pack)
    assert result.exit_code == 2 and result.stdout == ""
    assert "is not a challenge folder" in result.stderr
    result = invoke("gap", board / "layers", "--pack", pack, "--name", "Bad Name")
    assert result.exit_code == 2 and "is not an engine id" in result.stderr
    assert not pack.exists()


def test_build_check_lists_passing_and_failing_engines_and_exits_1_while_one_fails(board, pack):
    layers, *_ = scaffold(pack, board / "layers")
    note, *_ = scaffold(pack, board / "sticky-note")
    layers.write_text(REAL)
    result = invoke("check", pack)
    assert result.exit_code == 1, result.stderr
    assert result.stdout.splitlines() == [
        "pass  cry.layers",
        "FAIL  misc.sticky-note: test_solved: misc.sticky-note reported none, not solved: not written yet",
        "1 engine passing, 1 failing",
    ]
    note.write_text(NOTE)
    result = invoke("check", pack)
    assert result.exit_code == 0, result.stdout
    assert result.stdout.splitlines() == ["pass  cry.layers", "pass  misc.sticky-note", "2 engines passing, 0 failing"]


def test_build_check_of_a_pack_without_cases_says_so(tmp_path):
    (tmp_path / "pack").mkdir()
    result = invoke("check", tmp_path / "pack")
    assert result.exit_code == 0 and result.stdout == ""
    assert "no case tests in" in result.stderr and "flightdeck build gap" in result.stderr
