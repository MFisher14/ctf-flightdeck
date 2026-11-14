"""xor_repeat: crib-less repeating-key XOR cryptanalysis — recovers key+plaintext with no crib."""
from __future__ import annotations

import pytest

import xor_repeat as xr


# A long-ish English plaintext so column statistics and Hamming key-length detection are reliable.
PLAIN = (
    b"The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. "
    b"How razorback jumping frogs can level six piqued gymnasts. The five boxing wizards jump "
    b"quickly, and the jovial public amazed the quacking sphinx of black quartz judge my vow."
)


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(data))


def test_hamming_matches_cryptopals_reference():
    assert xr.hamming(b"this is a test", b"wokka wokka!!!") == 37


def test_recover_exact_key_and_plaintext_for_known_keylen():
    key = b"SECRET"
    ct = _xor(PLAIN, key)
    rkey, rplain, _score = xr.recover_with_keylen(ct, len(key))
    assert rkey == key
    assert rplain == PLAIN


LONG = PLAIN * 4  # more bytes per column -> reliable crib-less recovery


def _similarity(a: bytes, b: bytes) -> float:
    n = min(len(a), len(b))
    return sum(1 for i in range(n) if a[i] == b[i]) / n if n else 0.0


def test_solve_recovers_plaintext_without_a_crib():
    key = b"K3y!"
    ct = _xor(LONG, key)
    cands = xr.solve(ct)
    assert cands, "expected ranked candidates"
    # crib-less frequency recovery of an arbitrary-byte key is not guaranteed byte-exact, but the best
    # candidate must reconstruct the plaintext well enough to read (>= 95% of bytes correct).
    best = max((_similarity(c["plaintext"], LONG) for c in cands), default=0.0)
    assert best >= 0.95


def test_key_length_candidates_includes_true_length():
    key = b"longerkey7"
    ct = _xor(LONG, key)
    cands = xr.key_length_candidates(ct)
    # the true length (or a small multiple) should be surfaced
    assert len(key) in cands or 2 * len(key) in cands


def test_single_byte_xor_recovers_the_key():
    key = 0x42
    ct = bytes(c ^ key for c in PLAIN)
    cands = xr.single_byte(ct)
    assert cands[0]["key"] == key
    assert cands[0]["plaintext"] == PLAIN


def test_fail_closed_on_unusable_input():
    assert xr.solve(b"") == []
    assert xr.solve(b"ab") == []        # too short
    assert xr.solve(12345) == []        # wrong type
    assert xr.single_byte(b"") == []


def test_cli_json_and_error(tmp_path, capsys):
    key = b"xy"
    f = tmp_path / "ct.bin"
    f.write_bytes(_xor(PLAIN, key))
    rc = xr.main([str(f), "--json"])
    assert rc == 0
    import json
    out = json.loads(capsys.readouterr().out)
    assert isinstance(out, list) and out and "key_hex" in out[0]
    # missing file -> guarded error, no traceback
    assert xr.main([str(tmp_path / "nope.bin")]) == 1
    assert xr.main(["--help"]) == 0
