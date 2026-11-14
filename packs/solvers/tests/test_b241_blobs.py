#!/usr/bin/env python3
"""B-241: the generated machine-code fixtures (tests/b241_blobs.py) match their assembly listings.

``tests/b241_fixture_asm.py`` assembles ``tests/fixtures/native_image/B241_*.s`` with clang into
``tests/b241_blobs.py``.  A hand-edited blob, or a listing changed without a rebuild, would leave the tests
running code nobody can read: this test re-assembles the listings and compares.  It needs clang (it reports
NOT RUN where clang is absent) and writes only into pytest's temporary folder.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

import b241_fixture_asm as builder  # noqa: E402

pytestmark = pytest.mark.needs_tool("clang")


def test_the_committed_blobs_are_what_the_listings_assemble_to(capsys):
    assert builder.main(["--check"]) == 0, capsys.readouterr().err
    assert "is current" in capsys.readouterr().out


def test_a_stale_or_hand_edited_blob_file_is_reported(tmp_path, monkeypatch, capsys):
    current = builder.OUT.read_text(encoding="utf-8")
    edited = tmp_path / "b241_blobs.py"
    # one byte of the JNI listing's code changed by hand: the check must notice
    first = current.index('JNI64_HEX = (\n    "') + len('JNI64_HEX = (\n    "')
    flipped = "0" if current[first] != "0" else "1"
    edited.write_text(current[:first] + flipped + current[first + 1:], encoding="utf-8")
    monkeypatch.setattr(builder, "OUT", edited)
    assert builder.main(["--check"]) == 1
    assert "stale" in capsys.readouterr().err
    edited.unlink()
    assert builder.main(["--check"]) == 1                      # a missing file is stale too
    assert not edited.exists()                                  # --check never writes
