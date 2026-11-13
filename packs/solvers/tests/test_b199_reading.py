"""B-199: the binary-first read (ctf.binsummary) and `ctf read --symbol` / `--strings`.

Every fixture is synthetic, built here. Each test fails when the behaviour is wrong: a binary that is
dumped or refused instead of summarized, a wrong type, offset or entropy band, a symbol read that shows
the wrong lines or is refused as a large window, an ambiguous name silently picking one.
"""
from __future__ import annotations

import argparse
import os
import textwrap

import pytest

from ctf import binsummary, hygiene, readmap
from ctf.cli import read as cli_read
from ctf.formats import fingerprint as _fp


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    monkeypatch.delenv("CTF_EVENT", raising=False)


def _args(**over):
    p = argparse.ArgumentParser()
    cli_read.add_arguments(p)
    ns = p.parse_args([over.pop("path")])
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


ELF = (b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"hello world string\x00\x00/lib64/ld-linux-x86-64.so.2\x00"
       + "WIDE_TEXT".encode("utf-16-le") + b"\x00\x00" + b"ab\x00")


# --------------------------------------------------------------------------- binsummary

def test_summary_identifies_elf_by_magic_and_lists_strings_with_offsets():
    s = binsummary.summarize("x.bin", ELF)
    assert s.size == len(ELF)
    assert any(lbl.startswith("ELF object / executable (magic 7f454c46 at 0") for lbl in s.labels)
    by_text = {t: (off, enc) for off, enc, t in s.strings}
    assert by_text["hello world string"] == (16, "ascii")
    assert by_text["/lib64/ld-linux-x86-64.so.2"] == (ELF.index(b"/lib64"), "ascii")
    assert by_text["WIDE_TEXT"] == (ELF.index("WIDE_TEXT".encode("utf-16-le")), "utf16le")
    assert "ab" not in by_text                         # shorter than MIN_STRING
    text = s.render()
    assert text.splitlines()[0].startswith(f"[binary] x.bin: {len(ELF)} bytes, sha256 ")
    assert "00000000  7f 45 4c 46" in text             # the hex head
    assert "  0x00000010  hello world string" in text
    assert "  0x" in text and "[utf16le]  WIDE_TEXT" in text


def test_summary_names_a_catalog_structure_match():
    riff = b"RIFF" + (100).to_bytes(4, "little") + b"WAVE" + bytes(range(256)) * 2
    labels, problems = binsummary.identify("a.wav", riff)
    assert problems == []
    assert labels and labels[0].startswith("riff (catalog: structure)")


def test_summary_of_unknown_bytes_says_so_and_entropy_bands():
    rnd = os.urandom(1 << 16)
    s = binsummary.summarize("r.bin", b"\x01\x02\x03\x04" + rnd)
    assert s.labels == []
    assert "type: not identified by the format catalog or the magic table" in s.render()
    assert s.entropy > 7.5 and "high: compressed, encrypted or packed" in s.render()
    z = binsummary.summarize("z.bin", b"\x00" * 4096)
    assert z.entropy == 0.0 and "low: text-like" in z.render()
    assert binsummary.entropy(bytes([0, 1]) * 100) == pytest.approx(1.0)


def test_summary_names_a_failing_identifier_instead_of_saying_unknown(monkeypatch):
    def broken(path=None):
        raise _fp.MagicError("magic.toml: broken for the test")
    monkeypatch.setattr(_fp, "load_magic", broken)
    s = binsummary.summarize("x.bin", ELF)
    assert s.problems == ["magic table: magic.toml: broken for the test"]
    assert "identify problem: magic table: magic.toml: broken for the test" in s.render()


def test_summary_caps_its_string_list_and_names_the_scan_cut(monkeypatch):
    blob = b"".join(b"string_number_%04d\x00" % i for i in range(100))
    s = binsummary.summarize("many.bin", blob)
    assert len(s.strings) == binsummary.SUMMARY_STRINGS and s.strings_total == 100
    assert f"{binsummary.SUMMARY_STRINGS} shown of 100" in s.render()
    monkeypatch.setattr(binsummary, "SCAN_BYTES", 200)
    s2 = binsummary.summarize("many.bin", blob)
    assert s2.strings_total == 11                 # 10 whole 19-byte records, then "string_num" cut at 200
    assert f"in the first 200 of {len(blob)} bytes" in s2.render()


def test_a_file_that_is_exactly_a_magic_signature_is_identified():
    labels, _ = binsummary.identify("x.bin", b"\x7fELF")          # 4 bytes: the signature and nothing else
    assert any(lbl.startswith("ELF object / executable (magic 7f454c46 at 0") for lbl in labels)
    labels, _ = binsummary.identify("x.bin", b"\x7fEL")           # one byte short: no match
    assert not any("magic 7f454c46" in lbl for lbl in labels)


def test_a_wide_run_that_falls_under_the_minimum_after_trimming_is_dropped():
    # ascii "abcd" ends at 'd'; the wide match starts on that 'd' and its NUL ("d\0X\0Y\0Z\0", 4 pairs),
    # so trimming the borrowed pair leaves "XYZ": 3 characters, under min_len 4
    short = binsummary.strings(b"abcd\x00X\x00Y\x00Z\x00", min_len=4)
    assert short == [(0, "ascii", "abcd")]
    longer = binsummary.strings(b"abcd\x00W\x00X\x00Y\x00Z\x00", min_len=4)
    assert longer == [(0, "ascii", "abcd"), (5, "utf16le", "WXYZ")]


def test_strings_rejects_a_zero_minimum():
    with pytest.raises(ValueError):
        binsummary.strings(b"abc", min_len=0)


# --------------------------------------------------------------------------- ctf read on a binary

def test_read_binary_prints_the_summary_and_records_selector_summary(tmp_path, capsys):
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "challenge.json").write_text("{}")
    f = d / "files" / "a.out"
    f.write_bytes(ELF)
    assert cli_read.run(_args(path=str(f))) == 0
    out = capsys.readouterr().out
    assert "type: ELF object / executable" in out and "hello world string" in out
    entry = readmap.ReadMap.load(d).lookup("files/a.out")
    assert [r.selector for r in entry.reads] == ["summary"] and entry.kind == "binary"


def test_read_binary_refuses_line_and_symbol_windows(tmp_path, capsys):
    f = tmp_path / "a.out"
    f.write_bytes(ELF)
    assert cli_read.run(_args(path=str(f), lines="1-5", no_map=True)) == 1
    assert "is binary" in capsys.readouterr().err
    assert cli_read.run(_args(path=str(f), symbol="main", no_map=True)) == 1
    assert capsys.readouterr().out == ""


def test_read_strings_lists_every_string_with_offsets(tmp_path, capsys):
    f = tmp_path / "a.out"
    f.write_bytes(ELF)
    assert cli_read.run(_args(path=str(f), strings=4, no_map=True)) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "3 string(s) of >= 4 chars (ascii, then utf-16le):"
    assert "0x00000010  hello world string" in out
    assert f"0x{ELF.index(b'/lib64'):08x}  /lib64/ld-linux-x86-64.so.2" in out
    assert any(line.endswith("[utf16le]  WIDE_TEXT") for line in out)
    assert cli_read.run(_args(path=str(f), strings=0, no_map=True)) == 2


def test_read_strings_of_two_chars_finds_the_short_run(tmp_path, capsys):
    f = tmp_path / "a.out"
    f.write_bytes(ELF)
    assert cli_read.run(_args(path=str(f), strings=2, no_map=True)) == 0
    assert f"0x{len(ELF) - 3:08x}  ab" in capsys.readouterr().out


def test_two_selections_in_a_hand_built_namespace_are_refused(tmp_path, capsys):
    f = tmp_path / "m.py"
    f.write_text("def a():\n    return 1\n")
    assert cli_read.run(_args(path=str(f), symbol="a", lines="1-2", no_map=True)) == 2
    assert "--lines and --symbol cannot be combined" in capsys.readouterr().err


# --------------------------------------------------------------------------- ctf read --symbol

SRC = textwrap.dedent('''\
    """Module."""
    import os

    LIMIT = 3


    @staticmethod
    @property
    def top(a, b=1):
        """Top doc."""
        return a + b


    class Box:
        def get(self):
            return 1

        def put(self, x):
            return x


    class Bag:
        def get(self):
            return 2
''')


def _src(tmp_path, text=SRC):
    f = tmp_path / "mod.py"
    f.write_text(text)
    return f


def test_symbol_read_shows_exactly_the_definition_with_its_decorators(tmp_path, capsys):
    f = _src(tmp_path)
    assert cli_read.run(_args(path=str(f), symbol="top", no_map=True)) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == ["7:@staticmethod", "8:@property", "9:def top(a, b=1):", '10:    """Top doc."""',
                   "11:    return a + b"]


def test_symbol_read_of_a_lone_cr_file_stays_inside_the_file(tmp_path, capsys):
    # ast counts a lone CR as a line break, `ctf read` splits on LF only: the definition ends on ast
    # line 2 of a file that is one LF-line long, so the window is clamped to the file instead of
    # indexing past its end
    f = tmp_path / "cr.py"
    f.write_bytes(b"def f():\r    return 1\r")
    assert cli_read.run(_args(path=str(f), symbol="f", no_map=True)) == 0
    assert "return 1" in capsys.readouterr().out


def test_symbol_read_by_qualified_name_and_ambiguity_is_named(tmp_path, capsys):
    f = _src(tmp_path)
    assert cli_read.run(_args(path=str(f), symbol="Bag.get", no_map=True)) == 0
    assert capsys.readouterr().out.splitlines() == ["23:    def get(self):", "24:        return 2"]
    assert cli_read.run(_args(path=str(f), symbol="get", no_map=True)) == 2
    err = capsys.readouterr().err
    assert "ambiguous" in err and "Box.get (L15-16)" in err and "Bag.get (L23-24)" in err
    assert cli_read.run(_args(path=str(f), symbol="put", no_map=True)) == 0
    assert capsys.readouterr().out.splitlines()[0] == "18:    def put(self, x):"


def test_symbol_not_found_lists_the_top_level_names(tmp_path, capsys):
    f = _src(tmp_path)
    assert cli_read.run(_args(path=str(f), symbol="nope", no_map=True)) == 2
    err = capsys.readouterr().err
    assert "no symbol 'nope'" in err and "top, Box, Bag" in err and "LIMIT" not in err


def test_symbol_read_of_non_python_is_an_error(tmp_path, capsys):
    f = tmp_path / "notes.txt"
    f.write_text("this is ( not python\n")
    assert cli_read.run(_args(path=str(f), symbol="x", no_map=True)) == 2
    assert "--symbol needs Python source" in capsys.readouterr().err


def test_a_long_symbol_is_not_refused_as_a_window_but_is_capped_and_recorded_as_lines(tmp_path, capsys):
    body = "\n".join(f"    x{i} = {i}  # " + "pad " * 10 for i in range(400))
    d = tmp_path / "chal"
    (d / "files").mkdir(parents=True)
    (d / "challenge.json").write_text("{}")
    f = d / "files" / "big.py"
    f.write_text(f"def big():\n{body}\n    return 0\n\n\ndef small():\n    return 1\n")
    assert cli_read.run(_args(path=str(f), lines="1-402")) == 1           # the same window by lines: refused
    capsys.readouterr()
    assert cli_read.run(_args(path=str(f), symbol="big")) == 0
    out = capsys.readouterr().out
    assert out.startswith("1:def big():")
    assert "[ctf: output capped" in out                                    # still under the cap
    assert hygiene.estimate_tokens(out) < hygiene.CAP_TOKENS + 200
    entry = readmap.ReadMap.load(d).lookup("files/big.py")
    assert [r.selector for r in entry.reads] == ["lines:1-402"]
