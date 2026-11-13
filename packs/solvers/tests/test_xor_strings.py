"""xor_strings: find single-byte-XOR-encoded ASCII strings in a binary."""
from __future__ import annotations

import pytest

import xor_strings as xs


def _embed(flag: bytes, key: int) -> bytes:
    enc = bytes(c ^ key for c in flag)
    # surround with bytes that decode to \x00 (a clean run separator) under this key — i.e. what a real
    # binary's random surroundings look like under the flag's key: non-printable, isolating the flag.
    sep = bytes([key]) * 8
    return sep + enc + sep


def test_finds_xor_encoded_flag():
    flag = b"CSCTF{xor_strings_find_me}"
    blob = _embed(flag, 0x5a)
    hits = xs.xor_strings(blob)
    texts = [(h["key"], h["text"]) for h in hits]
    assert (0x5a, flag.decode()) in texts
    # flag-shaped hit ranks at the top
    assert "{" in hits[0]["text"]


def test_flag_candidates_filters_to_flag_shape():
    flag = b"FLAG{deadbeef}"
    blob = _embed(flag, 0x11)
    cands = xs.flag_candidates(blob)
    assert any(c["text"] == flag.decode() and c["key"] == 0x11 for c in cands)


def test_specific_key_only():
    flag = b"CSCTF{only_this_key}"
    blob = _embed(flag, 0x7f)
    hits = xs.xor_strings(blob, keys=[0x7f])
    assert any(h["text"] == flag.decode() for h in hits)
    assert all(h["key"] == 0x7f for h in hits)


def test_min_len_filters_short_runs():
    # a 3-char encoded run should be dropped at min_len=5
    blob = _embed(b"abc", 0x40)
    assert not any(h["text"] == "abc" for h in xs.xor_strings(blob, min_len=5))


def test_fail_closed():
    assert xs.xor_strings(b"") == []
    assert xs.xor_strings("not bytes") == []
    assert xs.xor_strings(b"x" * 10, min_len=2) == []  # min_len < 3 rejected


def test_cli(tmp_path, capsys):
    flag = b"CSCTF{cli_xor_strings}"
    f = tmp_path / "bin"
    f.write_bytes(_embed(flag, 0x33))
    rc = xs.main([str(f), "--flags-only", "--json"])
    assert rc == 0
    import json
    out = json.loads(capsys.readouterr().out)
    assert any(o["text"] == flag.decode() for o in out)
    assert xs.main([str(tmp_path / "nope")]) == 1
    assert xs.main(["--help"]) == 0
