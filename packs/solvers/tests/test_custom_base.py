"""custom_base: decode base-N with a scrambled alphabet + recover the alphabet from a crib."""
from __future__ import annotations

import random

import pytest

import custom_base as cb


def _scramble(alphabet, seed=7):
    lst = list(alphabet)
    random.Random(seed).shuffle(lst)
    return "".join(lst)


def test_decode_scrambled_base64_roundtrip():
    alpha = _scramble(cb.STD_B64)
    flag = b"CSCTF{scrambled_base64_alphabet}"
    ct = cb.encode(flag, alpha)
    assert cb.decode(ct, alpha) == flag


def test_decode_scrambled_base32():
    alpha = _scramble(cb.STD_B32, seed=3)
    data = b"hello base32 custom"
    ct = cb.encode(data, alpha)
    assert cb.decode(ct, alpha) == data


def test_standard_alphabet_matches_stdlib():
    import base64
    data = b"ordinary base64 check"
    assert cb.encode(data, cb.STD_B64).rstrip("=") == base64.b64encode(data).decode().rstrip("=")
    assert cb.decode(base64.b64encode(data).decode(), cb.STD_B64) == data


def test_recover_alphabet_from_crib():
    alpha = _scramble(cb.STD_B64, seed=11)
    # a long known plaintext so most of the 64 symbols appear in its encoding
    plain = bytes(range(256)) * 2
    ct = cb.encode(plain, alpha)
    res = cb.recover_alphabet(plain, ct, base=64)
    assert res["complete"] and res["alphabet"] == alpha
    # and the recovered alphabet decodes a fresh message correctly
    flag = b"CSCTF{crib}"
    assert cb.decode(cb.encode(flag, alpha), res["alphabet"]) == flag


def test_fail_closed():
    with pytest.raises(cb.BaseError):
        cb.decode("abc", "A")                       # alphabet too short
    with pytest.raises(cb.BaseError):
        cb.decode("abc", "AABB")                    # duplicate symbols
    assert cb.decode("!!!not in alphabet", cb.STD_B64) is None
    assert cb.decode(12345, cb.STD_B64) is None
    with pytest.raises(cb.BaseError):
        cb.recover_alphabet(b"longplaintexthere", "sh", base=64)  # ciphertext too short


def test_non_power_of_two_numeric_decode():
    # a 58-symbol alphabet decodes via big-int; round-trip a known value
    alpha58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    # encode manually (big-int) then decode
    data = b"\x01\x02\x03abc"
    num = int.from_bytes(data, "big")
    s = ""
    while num:
        num, r = divmod(num, 58)
        s = alpha58[r] + s
    assert cb.decode(s, alpha58) == data


def test_cli(capsysbinary):
    alpha = _scramble(cb.STD_B64, seed=5)
    ct = cb.encode(b"CSCTF{cli}", alpha)
    assert cb.main(["decode", ct, alpha]) == 0
    assert b"CSCTF{cli}" in capsysbinary.readouterr().out   # decode writes bytes to stdout.buffer
    assert cb.main(["decode", "!!!", cb.STD_B64]) == 1       # symbol outside alphabet
    assert cb.main(["recover", "hello world this is plenty", cb.encode(b"hello world this is plenty", alpha)]) == 0
    assert cb.main(["--help"]) == 0
