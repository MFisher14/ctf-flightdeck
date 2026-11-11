"""l1/_capture.py, the process an engine runs under: what it keeps of stdout and stderr, the
counts, the status, and the record the runner reads (parse_captured). Every command here is
a synthetic shell line; nothing runs a challenge file."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf_flightdeck.l1.runner import CAPTURE, Captured, parse_captured


def capture(head: int, tail: int, err: int, script: str, *options: str, env: dict | None = None) -> tuple[Captured, int]:
    """Run `sh -c script` under the capture; (the record it wrote, its exit status)."""
    proc = subprocess.run(
        [sys.executable, "-I", str(CAPTURE), str(head), str(tail), str(err), *options, "--", "/bin/sh", "-c", script],
        capture_output=True, env=env, timeout=60,
    )
    assert proc.stderr == b"", proc.stderr
    return parse_captured(proc.stdout), proc.returncode


def test_it_keeps_the_head_and_the_tail_of_stdout_and_the_end_of_stderr_counting_every_byte():
    out, status = capture(10, 5, 8, "printf 0123456789ABCDEFGHIJKLMNOPQRST; printf 'warning one\\nlast words' >&2; exit 3")
    assert (status, out.status) == (3, 3)
    assert (out.stdout, out.head, out.tail, out.dropped) == (30, b"0123456789", b"PQRST", 15)
    assert (out.stderr, out.stderr_total) == (b"st words", 22)


def test_nothing_is_dropped_when_it_all_fits():
    out, _ = capture(10, 5, 8, "printf 0123456789ABC; printf e >&2")
    assert (out.head, out.tail, out.dropped, out.stderr) == (b"0123456789", b"ABC", 0, b"e")
    empty, status = capture(10, 5, 8, "true")
    assert (status, empty.stdout, empty.head, empty.tail, empty.stderr, empty.stderr_total) == (0, 0, b"", b"", b"", 0)


def test_megabytes_of_output_are_read_to_the_end_and_counted_exactly():
    out, status = capture(1000, 1000, 100, "head -c 3000000 /dev/zero; printf END; head -c 2000000 /dev/zero >&2; printf FIN >&2")
    assert status == 0 and out.stdout == 3000003 and out.dropped == 3000003 - 2000
    assert out.head == b"\x00" * 1000 and out.tail.endswith(b"END") and len(out.tail) == 1000
    assert out.stderr_total == 2000003 and out.stderr.endswith(b"FIN") and len(out.stderr) == 100


def test_a_signal_is_a_shell_style_status_and_a_command_it_cannot_start_is_127(tmp_path):
    out, status = capture(10, 10, 100, "kill -TERM $$")
    assert (status, out.status) == (143, 143)
    proc = subprocess.run([sys.executable, "-I", str(CAPTURE), "10", "10", "4096", "--", str(tmp_path / "no-such-program")],
                          capture_output=True, timeout=60)
    missing = parse_captured(proc.stdout)
    assert (proc.returncode, missing.status) == (127, 127)
    assert missing.stderr.startswith(b"flightdeck: cannot start ") and b"no-such-program" in missing.stderr


def test_the_engine_gets_the_lc_ctype_it_was_given_and_never_pythons_own():
    plain = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}  # no locale: Python sets LC_CTYPE for itself (PEP 538)
    out, _ = capture(4096, 0, 100, "env", env=plain)
    assert b"LC_CTYPE" not in out.head
    given, _ = capture(4096, 0, 100, "printf '%s' \"$LC_CTYPE\"", "--lc-ctype=en_US.ISO8859-1", env=plain)
    assert given.head == b"en_US.ISO8859-1"


def test_what_the_engine_and_its_children_print_is_only_ever_data_inside_the_record():
    # the engine prints a record of its own, and a child of it prints after the engine exited:
    # both are stdout data, kept whole, and the record is still the capture's
    record_line = json.dumps({"capture": 1, "status": 0, "stdout": 0, "head": 0, "tail": 0, "stderr": 0, "stderr_kept": 0})
    out, status = capture(4096, 0, 100, f"printf '%s\\n' '{record_line}'; (sleep 0.3; echo late) & exit 5")
    assert (status, out.status) == (5, 5)
    assert out.head == record_line.encode() + b"\nlate\n" and out.stdout == len(out.head)


def test_bad_arguments_are_refused_with_usage():
    proc = subprocess.run([sys.executable, "-I", str(CAPTURE), "10", "x", "10", "--", "true"], capture_output=True, timeout=60)
    assert proc.returncode == 2 and b"usage" in proc.stderr and proc.stdout == b""


@pytest.mark.parametrize(
    "output",
    [
        b"",
        b"no record here",
        b'{"capture": 1}\n',
        b'{"capture": 2, "status": 0, "stdout": 0, "head": 0, "tail": 0, "stderr": 0, "stderr_kept": 0}\n',
        b'{"capture": 1, "status": 0, "stdout": 3, "head": 3, "tail": 0, "stderr": 0, "stderr_kept": 0}\nab',  # short
        b'{"capture": 1, "status": 0, "stdout": 3, "head": 2, "tail": 0, "stderr": 0, "stderr_kept": 0}\nabc',  # long
        b'{"capture": 1, "status": 0, "stdout": 1, "head": 2, "tail": 0, "stderr": 0, "stderr_kept": 0}\nab',  # counts
        b'{"capture": 1, "status": -1, "stdout": 0, "head": 0, "tail": 0, "stderr": 0, "stderr_kept": 0}\n',
        b'{"capture": 1, "status": true, "stdout": 0, "head": 0, "tail": 0, "stderr": 0, "stderr_kept": 0}\n',
        b'{"capture": 1, "status": 0, "stdout": 0, "head": 0, "tail": 0, "stderr": 0, "stderr_kept": 0, "x": 1}\n',
        b"Traceback (most recent call last):\n  ...\n",
    ],
)
def test_anything_but_a_whole_record_is_refused(output):
    with pytest.raises(ValueError):
        parse_captured(output)


def test_the_capture_is_standard_library_python_3_8():
    tree = ast.parse(Path(CAPTURE).read_text(), feature_version=(3, 8))
    imports = {node.names[0].name for node in ast.walk(tree) if isinstance(node, ast.Import)}
    imports |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imports <= {"json", "os", "subprocess", "sys", "threading"}
    assert os.access(CAPTURE, os.R_OK)
