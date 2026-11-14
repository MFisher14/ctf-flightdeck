"""crib_drag: keystream-reuse (two-time / many-time pad) recovery."""
from __future__ import annotations

import os

import pytest

import crib_drag as cd


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def test_xor_helper():
    assert cd.xor(b"\x01\x02\x03", b"\x01\x01\x01") == b"\x00\x03\x02"


def test_crib_drag_reveals_the_other_message_at_the_crib_offset():
    key = os.urandom(80)
    p1 = b"the flag is CSCTF{keystream_reuse_is_fatal} keep it secret please okay"
    p2 = b"meanwhile the second message says hello world and some more english text"
    c1, c2 = _xor(p1, key), _xor(p2, key)
    crib = b"the flag is "
    off = p1.index(crib)
    results = cd.crib_drag(c1, c2, crib)
    # at the true offset, the revealed bytes must equal p2 at that offset (the key cancels)
    match = next((r for r in results if r["offset"] == off), None)
    assert match is not None
    assert match["revealed"] == p2[off:off + len(crib)]


def test_many_time_pad_recovers_plaintexts():
    key = os.urandom(90)
    messages = [
        b"the quick brown fox jumps over the lazy dog every single day now",
        b"we attack at dawn so please be ready with the plans and the maps ok",
        b"cryptography is fun until someone reuses a one time pad like this",
        b"never roll your own crypto say the wise people of the internet here",
        b"the flag will be hidden inside one of these parallel plaintext lines",
        b"a space is special because xored with a letter it stays a letter yes",
        b"many time pad attacks rely on english letter frequency and spaces now",
        b"this is the eighth line of text to give the solver enough statistics",
    ]
    cts = [_xor(m, key) for m in messages]
    res = cd.many_time_pad(cts)
    assert res["keystream"]
    # the recovered plaintexts should match the originals well where columns have coverage
    def sim(a, b):
        n = min(len(a), len(b))
        return sum(1 for i in range(n) if a[i] == b[i]) / n if n else 0
    best = max(sim(pt, m) for pt, m in zip(res["plaintexts"], messages))
    assert best >= 0.75


def test_fail_closed():
    assert cd.crib_drag(b"abc", b"abc", b"") == []
    assert cd.crib_drag(12, 34, b"x") == []
    assert cd.many_time_pad([b"only one"])["plaintexts"] == []
    assert cd.many_time_pad([123, 456])["plaintexts"] == []


def test_cli_drag_and_mtp(tmp_path, capsys):
    key = os.urandom(40)
    p1 = b"the password is hunter2 and nothing else matters to anyone here ok"
    p2 = b"a totally different english sentence goes right over here instead yo"
    c1, c2 = _xor(p1, key), _xor(p2, key)
    rc = cd.main(["drag", c1.decode("latin-1"), c2.decode("latin-1"), "the password is"])
    assert rc == 0
    assert "other-reads" in capsys.readouterr().out
    # mtp CLI over files
    f1 = tmp_path / "a.bin"; f2 = tmp_path / "b.bin"
    f1.write_bytes(c1); f2.write_bytes(c2)
    rc2 = cd.main(["mtp", str(f1), str(f2)])
    assert rc2 == 0
    assert cd.main(["--help"]) == 0
