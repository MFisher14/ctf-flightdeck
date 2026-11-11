"""The runner end to end: synthetic engines (python and cli, result and text output) run as
real processes in host workspaces under tmp_path. No engine is a real solver and nothing
runs a challenge file: the handouts hold invented text and bytes."""

from __future__ import annotations

import json
import re
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ctf_flightdeck.agent.workspace import HostWorkspace
from ctf_flightdeck.l1.manifest import load
from ctf_flightdeck.l1.router import Hit
from ctf_flightdeck.l1.runner import (
    BOOT,
    HEAD_BYTES,
    NO_SAFE_PATH,
    STDERR_TAIL,
    TAIL_BYTES,
    challenge_id_of,
    command,
    missing_tools,
    run_engine,
    run_routed,
    safe_path,
)

from l1_kit import FLAG, challenge_dir, cli_engine, python_engine, run, tree, write_manifest

FAKE_TOKEN = "fake-token-value-for-the-l1-env-test"
ALLOWED = {"PATH", "LANG", "LC_ALL", "TERM", "HOME", "TMPDIR"}
PROCESS_OWN = {"PWD", "SHLVL", "_", "OLDPWD", "__CF_USER_TEXT_ENCODING", "LC_CTYPE"}  # set by bash, macOS or Python itself


@pytest.fixture
def board(tmp_path: Path) -> Path:
    return tmp_path / "board"


@pytest.fixture
def handout(board: Path) -> Path:
    return challenge_dir(board, "demo", {"note.txt": "the flag is t{in_the_note}\n", "sub/data.bin": b"\x00\x01\x02"}, id="demo-id")


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    p = tmp_path / "pack"
    p.mkdir()
    return p


def go(manifest: Path, handout: Path, workdir: Path, **kw):
    return run(run_engine(load(manifest), handout, workdir=workdir, flag_format=FLAG, **kw))


def hit(manifest: Path, priority: int = 50) -> Hit:
    return Hit(load(manifest), priority, "test")


# ---------------------------------------------------------------- python engines


def test_a_python_engine_is_solved_with_its_engine_challenge_and_measured_time(pack, handout, tmp_path):
    m = python_engine(pack, "reader", """
        import time
        from ctf_flightdeck.l1.result import Cost, Evidence, SolverResult

        def solve(challenge_dir):
            flag = (challenge_dir / "note.txt").read_text().split()[-1]
            time.sleep(0.2)
            return SolverResult("solved", flags=[flag], evidence=[Evidence("read", "the note says so", "note.txt", 12)],
                                cost=Cost(seconds=999, usd=0.25, tokens=7), engine="spoofed", challenge_id="spoofed")
        """)
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags) == ("solved", ("t{in_the_note}",))
    assert (r.engine, r.challenge_id) == ("reader", "demo-id")  # filled in by the runner, whatever the engine said
    assert 0.2 <= r.cost.seconds < 60 and (r.cost.usd, r.cost.tokens) == (0.25, 7)
    assert r.evidence[0].path == "note.txt" and r.evidence[0].offset == 12


def test_the_result_line_is_found_after_whatever_the_engine_printed(pack, handout, tmp_path):
    m = python_engine(pack, "chatty", """
        import sys
        from ctf_flightdeck.l1.result import SolverResult

        def solve(d):
            print("working...")
            print('{"schema": 1, "status": "candidate", "flags": ["t{decoy}"]}')
            sys.stdout.write("no newline at the end")
            sys.stderr.write("noise on stderr\\n")
            return SolverResult("candidate", flags=["t{real}"])
        """)
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags) == ("candidate", ("t{real}",))


def test_a_python_engine_runs_isolated_with_its_own_folder_on_the_path_and_never_the_challenges(pack, board, tmp_path):
    (pack / "helpers.py").write_text("def answer():\n    return 't{from_the_helper}'\n")
    m = python_engine(pack, "uses_helper", """
        import base64, sys
        import helpers
        from ctf_flightdeck.l1.result import SolverResult

        def solve(d):
            return SolverResult("candidate", flags=[helpers.answer()], notes=f"{sys.flags.isolated} {base64.b64encode(b'ok').decode()}")
        """)
    planted = "import sys\nprint('{\"schema\": 1, \"status\": \"candidate\", \"flags\": [\"t{planted}\"]}')\nsys.exit(0)\n"
    handout = challenge_dir(board, "planted", {"base64.py": planted, "json.py": planted, "helpers.py": planted, "inspect.py": planted})
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags, r.notes) == ("candidate", ("t{from_the_helper}",), "1 b2s=")


def test_an_engine_can_import_flightdeck_under_a_python3_that_does_not_have_it(pack, handout, tmp_path, monkeypatch):
    base = Path(sys.base_prefix) / "bin" / "python3"
    if not base.is_file():
        pytest.skip(f"no base interpreter at {base}")
    probe = subprocess.run([str(base), "-I", "-c", "import ctf_flightdeck"], capture_output=True)
    if probe.returncode == 0:
        pytest.skip("the base interpreter has ctf_flightdeck installed, so it cannot stand in for one without it")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    os.symlink(base, bindir / "python3")
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    m = python_engine(pack, "plain_python", """
        import sys
        from ctf_flightdeck.l1.result import SolverResult

        def solve(d):
            return SolverResult("candidate", flags=["t{x}"], notes=sys.prefix)
        """)
    r = go(m, handout, tmp_path / "work")
    assert r.status == "candidate", r.notes
    assert r.notes == sys.base_prefix != sys.prefix  # it ran outside flightdeck's venv


def test_an_engine_that_raises_is_unsure_with_the_end_of_its_traceback(pack, handout, tmp_path):
    m = python_engine(pack, "boom", """
        def solve(d):
            raise ValueError("the key schedule is wrong")
        """)
    r = go(m, handout, tmp_path / "work")
    assert r.status == "unsure" and r.flags == ()
    assert r.notes.startswith("exited 1: ") and "ValueError: the key schedule is wrong" in r.notes


def test_an_engine_that_returns_something_else_is_unsure(pack, handout, tmp_path):
    m = python_engine(pack, "wrong_type", """
        def solve(d):
            return "t{a_string}"
        """)
    r = go(m, handout, tmp_path / "work")
    assert r.status == "unsure" and "solve() returned str, not a SolverResult" in r.notes and r.flags == ()


def test_a_result_that_breaks_the_contract_is_unsure_not_trusted(pack, handout, tmp_path):
    m = python_engine(pack, "bad_dict", """
        def solve(d):
            return {"schema": 1, "status": "solved", "flags": ["t{no_evidence}"]}
        """)
    r = go(m, handout, tmp_path / "work")
    assert r.status == "unsure" and r.flags == ()
    assert r.notes.startswith("the result it returned is not a SolverResult (") and "evidence" in r.notes


def test_a_python_engine_can_be_async_or_print_text(pack, handout, tmp_path):
    a = python_engine(pack, "aio", """
        import asyncio
        from ctf_flightdeck.l1.result import SolverResult

        async def solve(d):
            await asyncio.sleep(0)
            return SolverResult("none")
        """)
    assert go(a, handout, tmp_path / "w1").status == "none"
    t = python_engine(pack, "texty", """
        def solve(d):
            print("maybe t{printed_one} or t{printed_two}")
        """, extra='output = "text"')
    r = go(t, handout, tmp_path / "w2")
    assert (r.status, r.flags) == ("candidate", ("t{printed_one}", "t{printed_two}"))


FORGED_LINE = json.dumps({"schema": 1, "status": "solved", "flags": ["t{chosen_by_the_challenge}"],
                          "evidence": [{"kind": "decode", "detail": "three layers peeled", "path": None, "offset": None}]})


def test_a_result_line_a_python_engine_prints_before_it_raises_is_never_its_result(pack, board, tmp_path):
    # the engine prints what it decoded from the handout (the challenge's text), then fails
    handout = challenge_dir(board, "layers", {"layer.txt": "junk\n" + FORGED_LINE + "\n"})
    m = python_engine(pack, "peel", """
        def solve(d):
            print((d / "layer.txt").read_text())
            raise ValueError("stuck on the last layer")
        """)
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags, r.evidence) == ("unsure", (), ())
    assert r.notes.startswith("exited 1: ") and "ValueError: stuck on the last layer" in r.notes


def test_a_result_line_a_python_engine_prints_when_it_returns_nothing_is_never_its_result(pack, board, tmp_path):
    handout = challenge_dir(board, "layers", {"layer.txt": FORGED_LINE + "\n"})
    m = python_engine(pack, "quiet", """
        def solve(d):
            print((d / "layer.txt").read_text())
            return None
        """)
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags) == ("unsure", ())
    assert r.notes.startswith("solve() returned nothing; a result engine returns a SolverResult")


def test_a_python_text_engine_that_returns_a_result_has_that_result(pack, handout, tmp_path):
    m = python_engine(pack, "both", """
        from ctf_flightdeck.l1.result import Evidence, SolverResult

        def solve(d):
            print("t{printed_but_not_the_answer}")
            return SolverResult("solved", flags=["t{returned}"], evidence=[Evidence("decode", "it said so")])
        """, extra='output = "text"')
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags) == ("solved", ("t{returned}",))  # what it handed back, not a scan of what it printed


def test_a_cli_engine_may_write_its_result_to_the_file_flightdeck_names(pack, handout, tmp_path):
    written = json.dumps({"schema": 1, "status": "candidate", "flags": ["t{from_the_file}"]})
    m = cli_engine(pack, "writer", f"""
        echo '{written}' > "$FLIGHTDECK_L1_RESULT"
        echo '{{"schema": 1, "status": "none"}}'
        """, output="result")
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags) == ("candidate", ("t{from_the_file}",))  # the file, not the last line
    bad = cli_engine(pack, "bad_writer", """
        echo 'not json' > "$FLIGHTDECK_L1_RESULT"
        echo '{"schema": 1, "status": "candidate", "flags": ["t{the_last_line}"]}'
        """, output="result")
    r = go(bad, handout, tmp_path / "w2")
    assert (r.status, r.flags) == ("unsure", ())  # never read another way
    assert r.notes.startswith("the result it wrote to $FLIGHTDECK_L1_RESULT is not a SolverResult (not JSON")


def test_the_result_file_is_new_for_every_run_and_never_one_a_challenge_could_name(pack, handout, tmp_path):
    m = cli_engine(pack, "where", 'echo "$FLIGHTDECK_L1_RESULT"\n')
    names = set()
    for i in range(2):
        work = tmp_path / f"w{i}"
        r = run(run_engine(load(m), handout, workdir=work, flag_format=r"\S*l1-result-\S*"))
        [path] = r.flags
        assert Path(path).parent == work / "where" / ".flightdeck"
        names.add(Path(path).name)
    assert len(names) == 2


# ---------------------------------------------------------------- output past what is kept


BULK = "yes 'trying key 0x41414141 ... no' | head -c 10000000\necho\n"  # 10 MB of progress lines, then a line end


def test_a_flag_printed_after_megabytes_of_output_is_still_found_and_the_gap_is_said(pack, handout, tmp_path):
    m = cli_engine(pack, "brute", BULK + "echo 'key found: t{late_flag}'\n")
    r = go(m, handout, tmp_path / "work")
    total = 10_000_001 + len("key found: t{late_flag}\n")
    assert (r.status, r.flags) == ("candidate", ("t{late_flag}",))
    assert r.notes == f"output over 8 MB: {total - HEAD_BYTES - TAIL_BYTES} bytes in the middle not searched"


def test_output_not_all_searched_is_never_none(pack, handout, tmp_path):
    m = cli_engine(pack, "brute", "yes 'nothing yet' | head -c 7000000\necho t{in_the_middle}\n" + BULK)
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags) == ("unsure", ())
    assert r.notes.startswith("output over 8 MB: ") and r.notes.endswith(" bytes in the middle not searched")


def test_a_result_after_megabytes_of_output_is_still_read(pack, handout, tmp_path):
    line = '{"schema": 1, "status": "candidate", "flags": ["t{cli_result}"]}'
    cli = cli_engine(pack, "cli_brute", BULK + f"echo '{line}'\n", output="result")
    assert go(cli, handout, tmp_path / "w1").flags == ("t{cli_result}",)  # its last line, from the end that was kept
    py = python_engine(pack, "py_brute", """
        from ctf_flightdeck.l1.result import Evidence, SolverResult

        def solve(d):
            for key in range(400_000):
                print(f"trying key {key:08d} ... no")
            return SolverResult("solved", flags=["t{key_found}"], evidence=[Evidence("oracle", "key 0x42 decrypts the header")])
        """)
    r = go(py, handout, tmp_path / "w2")
    assert (r.status, r.flags) == ("solved", ("t{key_found}",))


def test_stderr_is_kept_only_at_its_end_and_never_written_to_disk(pack, handout, tmp_path):
    m = cli_engine(pack, "noisy", "head -c 30000000 /dev/zero | tr '\\0' w >&2\necho 'last words' >&2\nexit 1\n")
    r = go(m, handout, tmp_path / "work")
    assert r.status == "unsure" and r.notes.startswith("exited 1: ") and r.notes.endswith("wwwlast words")
    sizes = [p.stat().st_size for p in (tmp_path / "work").rglob("*") if p.is_file()]
    assert max(sizes) < 1_000_000  # 30 MB of stderr went nowhere


# ---------------------------------------------------------------- cli engines


def test_a_cli_engine_runs_in_the_copy_with_dot_appended_and_its_result_line_is_read(pack, handout, tmp_path):
    m = cli_engine(pack, "where", """
        echo "some log line"
        printf '{"schema": 1, "status": "none", "notes": "%s|%s|%s"}\\n' "$#" "$1" "$(pwd -P)"
        echo
        echo "   "
        """, output="result")
    r = go(m, handout, tmp_path / "work")
    assert r.status == "none"
    assert r.notes == f"1|.|{os.path.realpath(tmp_path / 'work' / 'where')}"


def test_words_of_a_cli_entry_that_name_pack_files_become_absolute_paths(pack, handout, tmp_path):
    (pack / "tools").mkdir()
    (pack / "tools" / "args.sh").write_text('for a in "$@"; do echo "arg: $a"; done\necho "t{ran}"\n')
    (pack / "tools" / "words.txt").write_text("x\n")
    m = write_manifest(pack, "args", """
        id = "args"
        entry = "cli:bash tools/args.sh --mode 'two words' tools/words.txt missing.txt"
        output = "text"
        [[routes]]
        keywords = ["demo"]
        """)
    manifest = load(m)
    assert command(manifest) == [shutil.which("bash", path=safe_path()), str(pack / "tools" / "args.sh"), "--mode", "two words", str(pack / "tools" / "words.txt"), "missing.txt", "."]
    assert go(m, handout, tmp_path / "work").flags == ("t{ran}",)


PLANTED = "#!/bin/sh\ntouch HANDOUT_CODE_RAN\necho 't{planted_by_the_handout}'\n"


def test_a_pack_file_gone_since_the_pack_was_read_blocks_the_engine_and_never_runs_the_challenges(pack, board, tmp_path):
    handout = challenge_dir(board, "plants", {"x.sh": PLANTED, "helper.py": "open('HANDOUT_CODE_RAN', 'w')\nprint('t{planted}')\n"})
    (handout / "x.sh").chmod(0o755)
    (pack / "helper.py").write_text("print('t{mine}')\n")
    by_name = load(cli_engine(pack, "x", "echo t{mine}\n"))  # entry cli:./x.sh
    by_word = load(write_manifest(pack, "h", 'id = "h"\nentry = "cli:python3 helper.py"\noutput = "text"\n[[routes]]\nkeywords = ["demo"]\n'))
    by_python = load(python_engine(pack, "py", "def solve(d):\n    return None\n"))
    for name in ("x.sh", "helper.py", "py.py"):
        (pack / name).unlink()  # the player renames or deletes it mid-event
    for manifest, word in ((by_name, "./x.sh"), (by_word, "helper.py"), (by_python, "py.py")):
        r = run(run_engine(manifest, handout, workdir=tmp_path / "work", flag_format=FLAG))
        assert (r.status, r.flags) == ("blocked", ())
        assert r.notes == f"pack file {word} is missing (it was there when the pack was read); nothing ran"
    assert not (tmp_path / "work").exists() and not list(tmp_path.rglob("HANDOUT_CODE_RAN"))


def test_the_python_command_is_the_boot_script_in_isolated_mode(pack):
    manifest = load(python_engine(pack, "x", "def solve(d):\n    return None\n"))
    assert command(manifest) == [shutil.which("python3", path=safe_path()), "-I", str(BOOT), str(pack / "x.py"), "solve", "."]
    assert BOOT.is_file() and BOOT.is_absolute()


def test_text_output_gives_candidates_in_order_without_repeats(pack, handout, tmp_path):
    m = cli_engine(pack, "grep", """
        echo "t{second} came after t{first}? no: t{second}, then t{first}, then T{upper} and t{}"
        echo "and t{third}" >&2
        """)
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.flags) == ("candidate", ("t{second}", "t{first}"))  # stdout only, as found
    assert r.evidence[0].kind == "match" and r.notes == ""


def test_a_flag_format_with_a_group_still_gives_whole_flags(pack, handout, tmp_path):
    m = cli_engine(pack, "grep", 'echo "flag(abc) and flag(def)"\n')
    r = run(run_engine(load(m), handout, workdir=tmp_path / "work", flag_format=r"flag\((\w+)\)"))
    assert r.flags == ("flag(abc)", "flag(def)")


def test_text_output_with_nothing_found_is_none(pack, handout, tmp_path):
    r = go(cli_engine(pack, "quiet", 'echo "nothing here"\n'), handout, tmp_path / "work")
    assert (r.status, r.flags, r.notes) == ("none", (), "")


def test_a_failing_engine_is_unsure_with_the_end_of_its_stderr_made_safe(pack, handout, tmp_path):
    m = cli_engine(pack, "fails", """
        printf 'x%.0s' $(seq 1 1000) >&2
        printf '\\033[31mred\\nlast line\\n' >&2
        exit 3
        """)
    r = go(m, handout, tmp_path / "work")
    assert r.status == "unsure" and r.notes.startswith("exited 3: ")
    tail = r.notes[len("exited 3: "):]
    assert "\x1b" not in r.notes and "^[[31mred" in tail and tail.endswith("last line")
    assert "\n" not in r.notes  # folded onto one line
    assert 280 <= tail.count("x") <= STDERR_TAIL  # only the end of 1000 characters
    quiet = go(cli_engine(pack, "silent_fail", "exit 4\n"), handout, tmp_path / "w2")
    assert (quiet.status, quiet.notes) == ("unsure", "exited 4 with nothing on stderr")


def test_a_failing_text_engine_that_found_flags_still_reports_them(pack, handout, tmp_path):
    r = go(cli_engine(pack, "half", 'echo "t{partial}"\nexit 5\n'), handout, tmp_path / "work")
    assert (r.status, r.flags, r.notes) == ("candidate", ("t{partial}",), "exited 5")


def test_result_engines_that_print_nothing_or_fail(pack, handout, tmp_path):
    r = go(cli_engine(pack, "mute", "true\n", output="result"), handout, tmp_path / "w1")
    assert r.status == "unsure" and "it printed nothing" in r.notes
    r = go(cli_engine(pack, "junk", 'echo "solved it: t{x}"\n', output="result"), handout, tmp_path / "w2")
    assert r.status == "unsure" and r.flags == () and "not JSON" in r.notes and "solved it" in r.notes
    r = go(cli_engine(pack, "crash", 'echo "half a line"\necho "segfault-ish" >&2\nexit 139\n', output="result"), handout, tmp_path / "w3")
    assert (r.status, r.notes) == ("unsure", "exited 139: segfault-ish")
    # a non-zero exit WITH a result keeps the result: the engine said what it could
    blocked = '{"schema": 1, "status": "blocked", "notes": "needs a wordlist"}'
    r = go(cli_engine(pack, "own_block", f"echo '{blocked}'\nexit 2\n", output="result"), handout, tmp_path / "w4")
    assert (r.status, r.notes) == ("blocked", "needs a wordlist")


# ---------------------------------------------------------------- limits and what is missing


def test_an_engine_that_runs_too_long_is_killed_with_its_children_and_is_unsure(pack, handout, tmp_path):
    m = cli_engine(pack, "sleeper", """
        echo $$ > engine.pid
        sleep 60 &
        echo $! > child.pid
        wait
        """)
    began = time.monotonic()
    r = go(m, handout, tmp_path / "work", timeout=0.5)
    assert time.monotonic() - began < 15
    assert (r.status, r.notes) == ("unsure", "timed out after 0.5s")
    root = tmp_path / "work" / "sleeper"
    for name in ("engine.pid", "child.pid"):
        pid = int((root / name).read_text())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            pytest.fail(f"{name} {pid} still alive after the timeout")


def test_the_manifests_timeout_applies_when_none_is_given(pack, handout, tmp_path):
    m = cli_engine(pack, "slow", "sleep 30\n", extra="timeout_seconds = 1")
    r = go(m, handout, tmp_path / "work")
    assert (r.status, r.notes) == ("unsure", "timed out after 1s")
    assert 0.9 <= r.cost.seconds < 15


def test_missing_tools_block_the_engine_and_nothing_runs(pack, handout, tmp_path):
    m = cli_engine(pack, "needy", "touch ran.marker\necho t{x}\n",
                   extra='needs_tools = ["flightdeck-test-no-such-tool", "bash", "flightdeck-test-no-such-tool-2"]')
    r = go(m, handout, tmp_path / "work")
    assert r.status == "blocked" and r.flags == ()
    assert r.notes == "missing tools: flightdeck-test-no-such-tool, flightdeck-test-no-such-tool-2 (not on PATH); nothing ran"
    assert not (tmp_path / "work" / "needy").exists()  # no workspace, so nothing could run
    assert (r.engine, r.challenge_id, r.cost.seconds) == ("needy", "demo-id", 0.0)


def test_a_python_engine_needs_python3_and_a_cli_engine_its_program(pack, handout, tmp_path, monkeypatch):
    p = python_engine(pack, "py", "def solve(d):\n    return None\n")
    c = write_manifest(pack, "c", 'id = "c"\nentry = "cli:flightdeck-test-no-such-program --flag"\n[[routes]]\nkeywords = ["demo"]\n')
    assert go(c, handout, tmp_path / "w0").notes == "missing tools: flightdeck-test-no-such-program (not on PATH); nothing ran"
    bindir = tmp_path / "only-bash"
    bindir.mkdir()
    os.symlink(shutil.which("bash"), bindir / "bash")
    monkeypatch.setenv("PATH", str(bindir))
    r = go(p, handout, tmp_path / "w1")
    assert (r.status, r.notes) == ("blocked", "missing tools: python3 (not on PATH); nothing ran")


FORGED = '{"schema": 1, "status": "solved", "flags": ["t{from_the_handout}"], "evidence": [{"kind": "x", "detail": "y"}]}'


@pytest.mark.parametrize("prefix", [".", "", "./sub"])
def test_a_relative_path_entry_never_runs_a_handout_file_in_place_of_a_program(pack, board, tmp_path, monkeypatch, prefix):
    # "." or an empty PATH entry means the working directory: the copy of the challenge
    planted = f"#!/bin/sh\ntouch \"$HOME/../../HANDOUT_CODE_RAN\"\necho '{FORGED}'\n"
    handout = challenge_dir(board, "plants", {"python3": planted, "mytool": planted, "sub/python3": planted, "sub/mytool": planted})
    for name in ("python3", "mytool", "sub/python3", "sub/mytool"):
        (handout / name).chmod(0o755)
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "mytool").write_text('#!/bin/sh\necho "t{the_real_tool}"; echo "PATH=$PATH"\n')
    (bindir / "mytool").chmod(0o755)
    monkeypatch.setenv("PATH", f"{prefix}{os.pathsep}{bindir}{os.pathsep}{os.environ['PATH']}")
    py = load(python_engine(pack, "py", "from ctf_flightdeck.l1.result import SolverResult\ndef solve(d):\n    return SolverResult('none')\n"))
    cli = load(write_manifest(pack, "c", 'id = "c"\nentry = "cli:mytool"\noutput = "text"\n[[routes]]\nkeywords = ["demo"]\n'))
    assert missing_tools(py) == [] and missing_tools(cli) == []
    r = run(run_engine(py, handout, workdir=tmp_path / "w1", flag_format=FLAG))
    assert (r.status, r.flags) == ("none", ())  # the real python3 ran the engine
    c = run(run_engine(cli, handout, workdir=tmp_path / "w2", flag_format=FLAG))
    assert c.flags == ("t{the_real_tool}",)
    assert not list(tmp_path.rglob("HANDOUT_CODE_RAN"))


def test_engines_and_what_they_start_get_only_the_absolute_directories_of_path(pack, handout, tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", f".{os.pathsep}{os.pathsep}rel/bin{os.pathsep}{os.environ['PATH']}{os.pathsep}")
    assert safe_path() == os.pathsep.join(p for p in os.environ["PATH"].split(os.pathsep) if p.startswith("/"))
    c = cli_engine(pack, "env_path", 'echo "$PATH" > seen.path\n')
    assert go(c, handout, tmp_path / "w").status == "none"
    seen = (tmp_path / "w" / "env_path" / "seen.path").read_text().strip().split(os.pathsep)
    assert seen == safe_path().split(os.pathsep) and all(p.startswith("/") for p in seen)


def test_a_tool_found_only_through_a_relative_path_entry_is_missing(pack, handout, tmp_path, monkeypatch):
    (tmp_path / "relbin").mkdir()
    (tmp_path / "relbin" / "flightdeck-test-relative-tool").write_text("#!/bin/sh\necho hi\n")
    (tmp_path / "relbin" / "flightdeck-test-relative-tool").chmod(0o755)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", f"relbin{os.pathsep}{os.environ['PATH']}")
    assert shutil.which("flightdeck-test-relative-tool") is not None  # the plain lookup would find it
    m = cli_engine(pack, "needs_rel", "true\n", extra='needs_tools = ["flightdeck-test-relative-tool"]')
    r = go(m, handout, tmp_path / "w")
    assert (r.status, r.notes) == ("blocked", "missing tools: flightdeck-test-relative-tool (not on PATH); nothing ran")


def test_a_path_with_no_absolute_directory_blocks_every_engine(pack, handout, tmp_path, monkeypatch):
    m = cli_engine(pack, "e", "touch ran.marker\n")
    monkeypatch.setenv("PATH", f".{os.pathsep}bin")
    r = go(m, handout, tmp_path / "w")
    assert (r.status, r.notes) == ("blocked", NO_SAFE_PATH) and not (tmp_path / "w").exists()


# ---------------------------------------------------------------- the sandbox


def test_engines_see_only_the_allowlisted_environment(pack, handout, tmp_path, monkeypatch):
    for name in ("CTFD_TOKEN", "OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN"):
        monkeypatch.setenv(name, FAKE_TOKEN)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    m = python_engine(pack, "env_py", """
        import json, os
        from ctf_flightdeck.l1.result import SolverResult

        def solve(d):
            return SolverResult("none", notes=json.dumps(dict(os.environ)))
        """)
    r = go(m, handout, tmp_path / "w1")
    assert r.status == "none" and FAKE_TOKEN not in r.notes
    env = json.loads(r.notes)
    assert set(env) - PROCESS_OWN <= ALLOWED | {"FLIGHTDECK_L1_RESULT"} and "PATH" in env
    assert env["HOME"] == str(tmp_path / "w1" / "env_py" / ".flightdeck" / "home")
    result_file = Path(env["FLIGHTDECK_L1_RESULT"])  # flightdeck's own: where the result goes, a name nobody can guess
    assert result_file.parent == tmp_path / "w1" / "env_py" / ".flightdeck" and re.fullmatch(r"l1-result-[0-9a-f]{32}\.json", result_file.name)
    c = cli_engine(pack, "env_cli", "env > seen.env\n")
    assert go(c, handout, tmp_path / "w2").status == "none"
    seen = (tmp_path / "w2" / "env_cli" / "seen.env").read_text()
    assert FAKE_TOKEN not in seen and "CTFD_TOKEN" not in seen and "PYTHONPATH" not in seen


def test_a_cli_engine_gets_the_locale_it_was_given_not_the_one_python_sets_for_itself(pack, handout, tmp_path, monkeypatch):
    # with no locale set, Python sets LC_CTYPE=C.UTF-8 for itself and what it starts (PEP 538);
    # the capture runs under Python, but the engine must see the plain C locale it was given
    for name in ("LANG", "LC_ALL", "LC_CTYPE"):
        monkeypatch.delenv(name, raising=False)
    c = cli_engine(pack, "env_cli", "env > seen.env\n")
    assert go(c, handout, tmp_path / "w").status == "none"
    names = {line.split("=", 1)[0] for line in (tmp_path / "w" / "env_cli" / "seen.env").read_text().splitlines()}
    assert "LC_CTYPE" not in names and "LANG" not in names


def test_the_handout_is_never_written_whatever_the_engine_does(pack, handout, tmp_path):
    before = tree(handout)
    m = cli_engine(pack, "vandal", """
        echo "changed" >> note.txt
        rm -rf sub
        echo "t{new_file}" > made.txt
        chmod 000 challenge.json
        touch -t 200001010000 note.txt
        cat made.txt
        """)
    r = go(m, handout, tmp_path / "work")
    assert r.flags == ("t{new_file}",)
    assert tree(handout) == before
    copy = tmp_path / "work" / "vandal"
    assert (copy / "note.txt").read_text().endswith("changed\n") and not (copy / "sub").exists()


def test_a_workspace_that_cannot_be_prepared_blocks_the_engine_with_the_reason(pack, handout, tmp_path):
    m = cli_engine(pack, "e", "echo t{x}\n")
    (tmp_path / "work" / "e").mkdir(parents=True)
    (tmp_path / "work" / "e" / "leftover").write_text("from an earlier run")
    r = go(m, handout, tmp_path / "work")
    assert r.status == "blocked" and r.notes.startswith("its workspace could not be prepared: ")
    assert "already exists and is not an empty directory" in r.notes


def test_a_workspace_factory_chooses_the_workspace(pack, handout, tmp_path):
    calls = []

    def factory(engine_id, root, given):
        calls.append((engine_id, root, given))
        return HostWorkspace(root, given)

    m = cli_engine(pack, "e", "echo t{via_factory}\n")
    r = go(m, handout, tmp_path / "work", workspace_factory=factory)
    assert calls == [("e", tmp_path / "work" / "e", handout)] and r.flags == ("t{via_factory}",)


def test_challenge_ids_come_from_the_caller_the_challenge_json_or_the_folder(board, tmp_path, pack):
    with_id = challenge_dir(board, "folder-a", id="given-id")
    without = challenge_dir(board, "folder-b")
    assert (challenge_id_of(with_id), challenge_id_of(without)) == ("given-id", "folder-b")
    m = cli_engine(pack, "e", "true\n")
    assert go(m, with_id, tmp_path / "w1", challenge_id="from-caller").challenge_id == "from-caller"


# ---------------------------------------------------------------- run_routed


def test_runs_come_back_in_priority_order_whenever_each_finished(pack, handout, tmp_path):
    slow = cli_engine(pack, "slow_high", "sleep 0.6\necho t{slow}\n")
    fast = cli_engine(pack, "fast_low", "echo t{fast}\n")
    mid = cli_engine(pack, "mid", "echo t{mid}\n")
    runs = run(run_routed([hit(fast, 10), hit(slow, 90), hit(mid, 50)], handout, workdir=tmp_path / "work", flag_format=FLAG))
    assert [run_.manifest.id for run_ in runs] == ["slow_high", "mid", "fast_low"]
    assert [run_.result.flags for run_ in runs] == [("t{slow}",), ("t{mid}",), ("t{fast}",)]
    assert runs[0].seconds >= 0.6 and all(r.result.challenge_id == "demo-id" for r in runs)


def test_concurrency_one_runs_engines_one_after_another(pack, handout, tmp_path):
    body = """
        import time
        from ctf_flightdeck.l1.result import SolverResult

        def solve(d):
            start = time.time()
            time.sleep(0.15)
            return SolverResult("none", notes=f"{start} {time.time()}")
        """
    hits = [hit(python_engine(pack, f"s{i}", body)) for i in range(3)]
    runs = run(run_routed(hits, handout, workdir=tmp_path / "work", flag_format=FLAG, concurrency=1))
    spans = sorted(tuple(map(float, r.result.notes.split())) for r in runs)
    assert len(spans) == 3
    for (_, end), (start, _) in zip(spans, spans[1:]):
        assert start >= end  # never two at once


def test_engines_within_the_concurrency_limit_run_at_the_same_time(pack, handout, tmp_path):
    shared = tmp_path / "rendezvous"
    shared.mkdir()
    script = """
        touch "{shared}/{me}"
        for i in $(seq 1 200); do
            if [ -e "{shared}/{other}" ]; then echo "t{{met_{me}}}"; exit 0; fi
            sleep 0.05
        done
        exit 1
        """
    a = cli_engine(pack, "a", script.format(shared=shared, me="a", other="b"))
    b = cli_engine(pack, "b", script.format(shared=shared, me="b", other="a"))
    runs = run(run_routed([hit(a), hit(b)], handout, workdir=tmp_path / "work", flag_format=FLAG, concurrency=2))
    assert [r.result.flags for r in runs] == [("t{met_a}",), ("t{met_b}",)]  # each saw the other running


def test_one_engine_that_cannot_run_never_stops_the_others(pack, handout, tmp_path):
    def factory(engine_id, root, given):
        if engine_id == "broken":
            raise RuntimeError("no room for its copy")
        return HostWorkspace(root, given)

    broken = cli_engine(pack, "broken", "echo t{never}\n")
    slow = cli_engine(pack, "slow", "sleep 0.5\necho t{the_real_one}\n")
    runs = run(run_routed([hit(broken, 90), hit(slow, 10)], handout, workdir=tmp_path / "work", flag_format=FLAG,
                          workspace_factory=factory))
    assert [(r.manifest.id, r.result.status, r.result.flags) for r in runs] == [
        ("broken", "unsure", ()),
        ("slow", "candidate", ("t{the_real_one}",)),  # still ran to the end
    ]
    assert runs[0].result.notes == "flightdeck could not run it: RuntimeError: no room for its copy"
    assert (runs[0].result.engine, runs[0].result.challenge_id) == ("broken", "demo-id")


def test_a_result_with_a_number_too_big_for_a_float_is_unsure_and_the_others_still_run(pack, handout, tmp_path):
    line = '{"schema": 1, "status": "none", "cost": {"seconds": 1' + "0" * 400 + "}}"
    big = cli_engine(pack, "big", f"echo '{line}'\n", output="result")
    good = cli_engine(pack, "good", "sleep 0.3\necho t{the_real_one}\n")
    runs = run(run_routed([hit(big, 90), hit(good, 10)], handout, workdir=tmp_path / "work", flag_format=FLAG))
    assert [(r.result.status, r.result.flags) for r in runs] == [("unsure", ()), ("candidate", ("t{the_real_one}",))]
    assert "cost.seconds is too large" in runs[0].result.notes


def test_run_routed_refuses_bad_arguments_before_anything_runs(pack, handout, tmp_path):
    h = hit(cli_engine(pack, "e", "touch ran.marker\n"))
    for kwargs, words in (
        ({"flag_format": "t{("}, "does not compile"),
        ({"flag_format": ""}, "flag format"),
        ({"flag_format": FLAG, "concurrency": 0}, "concurrency"),
        ({"flag_format": FLAG, "concurrency": True}, "concurrency"),
    ):
        with pytest.raises(ValueError, match=words):
            run(run_routed([h], handout, workdir=tmp_path / "work", **kwargs))
    with pytest.raises(ValueError, match="listed twice"):
        run(run_routed([h, h], handout, workdir=tmp_path / "work", flag_format=FLAG))
    assert not (tmp_path / "work").exists()
    with pytest.raises(ValueError, match="timeout"):
        run(run_engine(h.manifest, handout, workdir=tmp_path / "work", flag_format=FLAG, timeout=0))


def test_no_hits_is_no_runs(handout, tmp_path):
    assert run(run_routed([], handout, workdir=tmp_path / "work", flag_format=FLAG)) == []
