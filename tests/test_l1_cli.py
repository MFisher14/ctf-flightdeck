"""`flightdeck l1 ...`: the Typer sub-app the integrator mounts as `flightdeck l1`, driven on
its own here with synthetic packs and folder-board challenges."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck.l1.cli import app
from ctf_flightdeck.l1.result import SolverResult

from l1_kit import challenge_dir, cli_engine, python_engine, write_manifest

runner = CliRunner()


def invoke(*args):
    return runner.invoke(app, [str(a) for a in args], prog_name="flightdeck l1")


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    p = tmp_path / "pack"
    python_engine(p, "note_reader", """
        from ctf_flightdeck.l1.result import Evidence, SolverResult

        def solve(d):
            flag = (d / "note.txt").read_text().split()[-1]
            return SolverResult("solved", flags=[flag], evidence=[Evidence("read", "the note", "note.txt")])
        """, engine_id="read.note", route='files = ["name:note.txt"]\npriority = 80', extra='tags = ["misc"]')
    cli_engine(p, "grep", 'cat "$1"/*.txt\n', engine_id="text.grep", route='keywords = ["note"]\npriority = 30')
    cli_engine(p, "never", "echo t{never}\n", engine_id="never", route='category = ["pwn"]')
    return p


@pytest.fixture
def board(tmp_path: Path) -> Path:
    b = tmp_path / "board"
    b.mkdir()
    (b / "board.json").write_text(json.dumps({"event": "Test CTF", "flag_format": r"t\{[a-z_]+\}"}))
    challenge_dir(b, "sticky-note", {"note.txt": "the answer: t{on_the_note}\n"}, title="Sticky Note", description="read the note")
    challenge_dir(b, "other", {"x.bin": b"\x00"})
    return b


def test_list_shows_each_engine_with_its_routes(pack):
    result = invoke("list", pack)
    assert result.exit_code == 0, result.stderr
    lines = result.stdout.splitlines()
    assert lines[0] == "never: cli: ./never.sh (output text, timeout 60s)"
    assert "read.note [misc]: note_reader.py:solve (output result, timeout 60s)" in lines
    assert "    priority 80: files name:note.txt" in lines


def test_list_of_an_empty_pack_says_how_to_get_engines(tmp_path):
    (tmp_path / "empty").mkdir()
    result = invoke("list", tmp_path / "empty")
    assert result.exit_code == 0 and result.stdout == ""
    assert "no engines" in result.stderr and "flightdeck l1 import" in result.stderr


def test_a_broken_pack_fails_with_the_file_and_key(pack):
    write_manifest(pack, "bad", 'id = "bad"\nentry = "cli:true"\n[[routes]]\npriority = 5\n')
    for command in (["list", pack], ["route", pack, pack]):
        result = invoke(*command)
        assert result.exit_code == 2
        assert "bad.manifest.toml: routes[0]: has no condition" in result.stderr


def test_route_lists_the_hits_best_first_with_reasons(pack, board):
    result = invoke("route", pack, board / "sticky-note")
    assert result.exit_code == 0, result.stderr
    assert result.stdout.splitlines() == [
        " 80  read.note  file 'note.txt' (name:note.txt)",
        " 30  text.grep  keyword 'note'",
    ]
    quiet = invoke("route", pack, board / "other")
    assert quiet.exit_code == 0 and quiet.stdout == "" and "no engine" in quiet.stderr


def test_run_prints_one_json_result_per_engine_using_the_boards_flag_format(pack, board, tmp_path):
    result = invoke("run", pack, board / "sticky-note", "--workdir", tmp_path / "runs")
    assert result.exit_code == 0, result.stderr
    results = [SolverResult.from_json(line) for line in result.stdout.splitlines()]
    assert [(r.engine, r.status, r.flags) for r in results] == [
        ("read.note", "solved", ("t{on_the_note}",)),
        ("text.grep", "candidate", ("t{on_the_note}",)),  # found with the board's format
    ]
    assert all(r.challenge_id == "sticky-note" for r in results)
    [run_dir] = (tmp_path / "runs").iterdir()  # a new folder per run inside --workdir
    assert sorted(p.name for p in run_dir.iterdir()) == ["read.note", "text.grep"]
    assert "no API keys or tokens" in result.stderr and str(run_dir) in result.stderr
    again = invoke("run", pack, board / "sticky-note", "--workdir", tmp_path / "runs")
    assert again.exit_code == 0 and len(list((tmp_path / "runs").iterdir())) == 2


def test_run_takes_a_flag_format_and_refuses_a_bad_one(pack, board, tmp_path):
    result = invoke("run", pack, board / "sticky-note", "--flag-format", r"answer:", "--workdir", tmp_path / "w")
    grep = SolverResult.from_json(result.stdout.splitlines()[1])
    assert grep.flags == ("answer:",)
    bad = invoke("run", pack, board / "sticky-note", "--flag-format", "t{(")
    assert bad.exit_code == 2 and "does not compile" in bad.stderr and bad.stdout == ""


def test_run_says_which_flag_format_it_uses_when_the_board_has_none(pack, tmp_path):
    b = tmp_path / "plain-board"
    challenge_dir(b, "sticky", {"note.txt": "flag{generic_one}\n"}, description="a note")
    result = invoke("run", pack, b / "sticky", "--workdir", tmp_path / "w")
    assert result.exit_code == 0, result.stderr
    assert "the board sets no flag format; using" in result.stderr
    assert SolverResult.from_json(result.stdout.splitlines()[1]).flags == ("flag{generic_one}",)


def test_run_with_no_hits_runs_nothing(pack, board, tmp_path):
    result = invoke("run", pack, board / "other", "--workdir", tmp_path / "w")
    assert result.exit_code == 0 and result.stdout == "" and "nothing ran" in result.stderr
    assert not (tmp_path / "w").exists()


def test_a_folder_that_is_not_a_challenge_is_refused(pack, board, tmp_path):
    result = invoke("run", pack, board)
    assert result.exit_code == 2 and "is not a challenge folder" in result.stderr
    (board / "broken").mkdir()
    (board / "broken" / "challenge.json").write_text('{"name": "x"}')
    broken = invoke("route", pack, board / "sticky-note")
    assert broken.exit_code == 2 and '"category" is missing' in broken.stderr


def test_import_writes_manifests_and_lists_what_it_skipped(tmp_path):
    folder = tmp_path / "scripts"
    (folder / "crypto").mkdir(parents=True)
    (folder / "crypto" / "rsa_wiener.py").write_text('if __name__ == "__main__":\n    print("x")\n')
    (folder / "tools").mkdir()
    (folder / "tools" / "solve.py").write_text('if __name__ == "__main__":\n    print("x")\n')
    result = invoke("import", folder)
    assert result.exit_code == 0, result.stderr
    assert result.stdout.splitlines() == [
        "wrote .flightdeck/generated/crypto/rsa_wiener.py.manifest.toml",
        "skipped tools/solve.py: no category from its folder name and no keyword from its file name, "
        "so a route would never match; write a manifest for it",
    ]
    assert "1 generated manifest, 1 skipped" in result.stderr
    listed = invoke("list", folder)
    assert listed.stdout.startswith("imported.crypto.rsa_wiener.py [imported]: cli: python3 ./crypto/rsa_wiener.py")


def test_import_of_a_folder_with_a_broken_manifest_fails_loudly(tmp_path):
    folder = tmp_path / "scripts"
    write_manifest(folder, "mine", 'id = "mine"\n')
    result = invoke("import", folder)
    assert result.exit_code == 2 and "mine.manifest.toml: entry: is missing" in result.stderr
