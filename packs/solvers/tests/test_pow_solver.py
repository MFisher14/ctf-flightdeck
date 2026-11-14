from __future__ import annotations

import sys
from pathlib import Path


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers/toolkits"
sys.path.insert(0, str(TOOLKITS))
import pow_solver as P  # noqa: E402


def test_leading_zero_bits_and_decimal_round_trip():
    assert P.leading_zero_bits(b"\x00\x10") == 11
    ch = P.PowChallenge(b"fixture:", 12, "sha256", "decimal")
    hit = P.solve_pow(ch, max_attempts=100_000)
    assert hit is not None
    assert P.verify_pow(ch, hit.suffix)
    assert hit.counter == int(hit.suffix)


def test_hex_and_binary_encodings_are_verified():
    for encoding, width in (("hex", 4), ("binary", 2)):
        ch = P.PowChallenge(b"enc:", 8, "sha1", encoding, width=width)
        hit = P.solve_pow(ch, max_attempts=10_000)
        assert hit is not None
        assert P.verify_pow(ch, hit.suffix)
        assert len(hit.suffix) == (width if encoding == "hex" else width)


def test_prompt_parser_and_solver_are_fail_closed():
    prompt = 'Find a decimal suffix so sha256(prefix + suffix) starts with 000. prefix="redpwn-fixture:"'
    parsed = P.parse_prompt(prompt)
    assert parsed is not None
    challenge, cap = parsed
    assert challenge.difficulty_bits == 12
    answer = P.solve_prompt(prompt, max_attempts=200_000)
    assert answer is not None
    assert P.verify_pow(challenge, answer)
    assert P.parse_prompt("please do some work") is None
    assert P.parse_prompt('sha256 prefix="x" starts with 00000000') is None  # over cap


def test_hashcash_v1_round_trip_and_tamper():
    stamp = P.mint_hashcash("ctf@example.invalid", 10, date="261104120000",
                            salt="fixture", max_attempts=50_000)
    assert stamp is not None
    assert P.verify_hashcash(stamp, min_bits=10)
    assert not P.verify_hashcash(stamp + "x", min_bits=10)


def test_limits_reject_unbounded_work():
    bad = P.PowChallenge(b"x", P.MAX_DIFFICULTY_BITS + 1)
    try:
        P.solve_pow(bad, max_attempts=1)
    except ValueError as exc:
        assert "difficulty" in str(exc)
    else:
        raise AssertionError("difficulty cap was not enforced")

