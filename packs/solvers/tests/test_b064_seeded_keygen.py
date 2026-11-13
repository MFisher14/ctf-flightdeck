#!/usr/bin/env python3
"""B-064: seeded-keygen (PRNG prime) RSA recovery engine.

The never-wrong boundary proved here:
  * ``generate_primes`` replays CPython ``random.Random(seed)`` prime generation EXACTLY, for every
    scheme option (top bit, low bit, ``next_prime_ge`` / ``strict_next_prime``) over several seeds --
    checked against an independent reconstruction built in the test, not the module's own helper.
  * ``recover`` returns a key ONLY when the seed's primes (plus at most one prime cofactor) multiply
    back to ``n`` and the key gate passes; it finds a seed whose SECOND prime is the divisor, handles
    one-seeded-prime and multi-prime moduli, and keeps searching past a dividing seed that fails the
    gate.  A wrong window is ``None``; a dividing seed that never passes the gate raises a named
    ``SeededKeygenGateError`` -- never a wrong key, never a silent ``None``.
  * The seed range is bounded at exactly the cap (CAP accepted, CAP+1 refused) on every path.
  * The epoch window is derived from a capture's packet timestamps or a file's mtime.
  * The bounded CLI (``solvers/toolkits/prng_recovery.py seeded-keygen``) runs the same recovery and
    reports ``verified`` only on a gated key; bad requests fail with a named reason.

All synthetic: primes are generated from a seed with small ``nbits`` so the search is fast, and work
is bounded by tiny seed windows, never by a wall-clock assertion.  No network, no token, no
challenge file.
"""
from __future__ import annotations

import itertools
import json
import os
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
COMMON = REPO / "solvers" / "common"
CLI = REPO / "solvers" / "toolkits" / "prng_recovery.py"
sys.path.insert(0, str(COMMON))

import seeded_keygen as sk  # noqa: E402
import rsa_attacks as rsa  # noqa: E402


# A fixed power-up epoch / serial, mirroring the (epoch << 16) | serial field-provisioning scheme.
EPOCH = 1_699_994_067
SERIAL = 6631
SHIFT = 16
SEED = (EPOCH << SHIFT) | SERIAL
CAP = sk.DEFAULT_SEED_CAP


def _trial_prime(v):
    return v > 1 and all(v % d for d in range(2, int(v ** 0.5) + 1))


def _draws(seed, nbits, count):
    rng = random.Random(seed)
    return [rng.getrandbits(nbits) for _ in range(count)]


def _independent_primes(seed, nbits, num_primes, *, set_top=True, set_odd=True, strict=False):
    """Rebuild the keygen's primes WITHOUT calling seeded_keygen, to catch a wrong replay.

    Deliberately the naive form: adjust the draw, then step by ONE until trial division says prime
    (strictly above the draw for ``strict``)."""
    primes = []
    for v in _draws(seed, nbits, num_primes):
        if set_top:
            v |= 1 << (nbits - 1)
        if set_odd:
            v |= 1
        if strict:
            v += 1
        while not _trial_prime(v):
            v += 1
        primes.append(v)
    return primes


def _other_prime(start, avoid):
    v = start
    while not _trial_prime(v) or v in avoid:
        v += 1
    return v


# --------------------------------------------------------------------------- exact replay

REPLAY_SEEDS = [SEED + k for k in range(12)] + [0, 1, 7, 12345]


# Hang guard only: a broken prime stepper can loop forever on an even draw.  Not a speed assertion.
@pytest.mark.timeout(600)
@pytest.mark.parametrize("set_top,set_odd,strict", list(itertools.product((True, False), repeat=3)))
def test_generate_primes_matches_independent_replay_every_option(set_top, set_odd, strict):
    nbits = 16
    scheme = sk.KeygenScheme(nbits=nbits, num_primes=3, set_top_bit=set_top, set_odd=set_odd,
                             prime_method="strict_next_prime" if strict else "next_prime_ge")
    for seed in REPLAY_SEEDS:
        assert sk.generate_primes(seed, scheme) == _independent_primes(
            seed, nbits, 3, set_top=set_top, set_odd=set_odd, strict=strict), seed
    raw = [d for seed in REPLAY_SEEDS for d in _draws(seed, nbits, 3)]
    # Preconditions that make the comparison discriminating (computed independently of the module):
    assert any(not d & (1 << (nbits - 1)) for d in raw)  # some draw has its top bit clear
    assert any(not d & 1 for d in raw)                    # some draw is even


def test_strict_next_prime_skips_a_draw_that_is_already_prime():
    nbits = 16
    # Find a seed whose first adjusted draw is itself prime (computed independently).
    seed = next(s for s in range(5000)
                if _trial_prime(_draws(s, nbits, 1)[0] | (1 << (nbits - 1)) | 1))
    draw = _draws(seed, nbits, 1)[0] | (1 << (nbits - 1)) | 1
    ge = sk.generate_primes(seed, sk.KeygenScheme(nbits=nbits, num_primes=1))
    strict = sk.generate_primes(seed, sk.KeygenScheme(nbits=nbits, num_primes=1,
                                                      prime_method="strict_next_prime"))
    assert ge == [draw]
    assert strict[0] > draw and strict == _independent_primes(seed, nbits, 1, strict=True)


def test_set_odd_changes_the_prime_under_strict_method():
    # Without set_odd an even draw v keeps its low bit clear, so strict_next_prime picks the first
    # prime > v; with set_odd it is the first prime > v|1.  These differ whenever v+1 is prime.
    nbits = 16
    seed = next(s for s in range(20000)
                if not _draws(s, nbits, 1)[0] & 1
                and _trial_prime((_draws(s, nbits, 1)[0] | (1 << (nbits - 1))) + 1))
    v = _draws(seed, nbits, 1)[0] | (1 << (nbits - 1))
    plain = sk.generate_primes(seed, sk.KeygenScheme(nbits=nbits, num_primes=1, set_odd=False,
                                                     prime_method="strict_next_prime"))
    forced = sk.generate_primes(seed, sk.KeygenScheme(nbits=nbits, num_primes=1, set_odd=True,
                                                      prime_method="strict_next_prime"))
    assert plain == [v + 1]
    assert forced[0] > v + 1


# --------------------------------------------------------------------------- recovery

def test_recover_finds_seed_factors_and_decrypts():
    scheme = sk.KeygenScheme(nbits=64, num_primes=2, e=65537)
    p, q = sk.generate_primes(SEED, scheme)
    n = p * q
    message = int.from_bytes(b"CSCTF{dawn}", "big")
    c = pow(message, scheme.e, n)
    res = sk.recover(n, scheme=scheme, epoch_start=EPOCH - 40, epoch_stop=EPOCH + 40,
                     serial=SERIAL, shift=SHIFT, ciphertext=c, workers=2)
    assert res is not None
    assert res["seed"] == SEED
    assert {res["p"], res["q"]} == {p, q} and res["primes"] == sorted((p, q))
    assert res["verified"] is True and res["gate_failures"] == []
    assert bytes.fromhex(res["plaintext_hex"]) == b"CSCTF{dawn}"
    assert res["plaintext_int"] == message


def test_recover_serial_and_parallel_agree():
    scheme = sk.KeygenScheme(nbits=64, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    n = p * q
    serial_res = sk.recover(n, scheme=scheme, seed_start=SEED - 20, seed_stop=SEED + 20, workers=1)
    parallel_res = sk.recover(n, scheme=scheme, seed_start=SEED - 20, seed_stop=SEED + 20, workers=3)
    assert serial_res["seed"] == parallel_res["seed"] == SEED


def test_recover_when_only_the_second_drawn_prime_divides_n():
    scheme = sk.KeygenScheme(nbits=32, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    r = _other_prime((1 << 31) + 99991, {p, q})
    n = q * r  # the first drawn prime p does NOT divide n
    assert n % p
    res = sk.recover(n, scheme=scheme, seeds=[SEED - 1, SEED, SEED + 1], workers=1)
    assert res is not None and res["seed"] == SEED
    assert res["primes"] == sorted((q, r))


def test_recover_one_seeded_prime_with_prime_cofactor():
    scheme = sk.KeygenScheme(nbits=32, num_primes=1)
    (p,) = sk.generate_primes(SEED, scheme)
    r = _other_prime((1 << 31) + 4242, {p})
    res = sk.recover(p * r, scheme=scheme, seeds=[SEED], ciphertext=pow(7, 65537, p * r))
    assert res["primes"] == sorted((p, r)) and res["plaintext_int"] == 7


def test_recover_multiprime_modulus_factors_and_decrypts():
    scheme = sk.KeygenScheme(nbits=32, num_primes=3)
    primes = sk.generate_primes(SEED, scheme)
    assert len(set(primes)) == 3
    n = primes[0] * primes[1] * primes[2]
    message = 0xC0FFEE
    res = sk.recover(n, scheme=scheme, seeds=[SEED - 1, SEED, SEED + 1],
                     ciphertext=pow(message, 65537, n), workers=1)
    assert res is not None and res["seed"] == SEED
    assert res["primes"] == sorted(primes)
    assert "p" not in res and "q" not in res
    assert res["plaintext_int"] == message
    assert pow(pow(12345, 65537, n), res["d"], n) == 12345


def test_recover_wrong_window_is_none():
    scheme = sk.KeygenScheme(nbits=64, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    # A window that does not contain the true seed must not fabricate a key.
    assert sk.recover(p * q, scheme=scheme, seed_start=SEED + 100, seed_stop=SEED + 200,
                      workers=1) is None


def test_prime_n_equal_to_a_seeded_prime_is_refused():
    # n is the seed's one prime: it "divides" n and the cofactor is 1, but a one-prime modulus is
    # not an RSA key.  Refused with its own reason, never returned as a verified key.
    scheme = sk.KeygenScheme(nbits=32, num_primes=1)
    (p,) = sk.generate_primes(SEED, scheme)
    with pytest.raises(sk.SeededKeygenGateError) as info:
        sk.recover(p, scheme=scheme, seeds=[SEED], workers=1)
    (failure,) = info.value.failures
    assert failure["seed"] == SEED and failure["reason"] == "n is itself prime"
    assert failure["primes"] == [p]


def test_more_than_one_seed_source_is_refused():
    scheme = sk.KeygenScheme(nbits=32, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    clashes = [
        dict(seeds=[SEED], seed_start=SEED, seed_stop=SEED + 1),
        dict(seeds=[SEED], serial=SERIAL),
        dict(seed_start=SEED, seed_stop=SEED + 1, epoch_start=EPOCH, epoch_stop=EPOCH + 1,
             serial=SERIAL),
        dict(seed_stop=SEED + 1, epoch_start=EPOCH),
    ]
    for kwargs in clashes:
        with pytest.raises(sk.SeededKeygenError, match="give exactly one seed source"):
            sk.recover(p * q, scheme=scheme, workers=1, **kwargs)
    # Each source on its own still works (the refusal is about the combination, not the source).
    assert sk.recover(p * q, scheme=scheme, seeds=[SEED], workers=1)["seed"] == SEED
    assert sk.recover(p * q, scheme=scheme, seed_start=SEED, seed_stop=SEED + 1,
                      workers=1)["seed"] == SEED


def test_gate_failure_is_raised_with_seed_and_reason():
    scheme = sk.KeygenScheme(nbits=64, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    # p and q divide this modulus but the cofactor 15 is composite: refused, loudly.  (A cofactor
    # of 2 would be prime and give a valid three-prime key, so it is not a refusal case.)
    with pytest.raises(sk.SeededKeygenGateError) as info:
        sk.recover(q * p * 15, scheme=scheme, seeds=[SEED])
    (failure,) = info.value.failures
    assert failure["seed"] == SEED and "not prime" in failure["reason"]
    # A repeated prime is refused with its own reason.
    with pytest.raises(sk.SeededKeygenGateError) as info:
        sk.recover(p * p * q, scheme=scheme, seeds=[SEED])
    assert "more than once" in info.value.failures[0]["reason"]
    # e not invertible (e=2 always divides p-1): two-prime and multi-prime gates refuse.
    with pytest.raises(sk.SeededKeygenGateError) as info:
        sk.recover(p * q, scheme=sk.KeygenScheme(nbits=64, num_primes=2, e=2), seeds=[SEED])
    assert "two-prime key gate refused" in info.value.failures[0]["reason"]
    tri = sk.generate_primes(SEED, sk.KeygenScheme(nbits=32, num_primes=3))
    with pytest.raises(sk.SeededKeygenGateError) as info:
        sk.recover(tri[0] * tri[1] * tri[2], scheme=sk.KeygenScheme(nbits=32, num_primes=3, e=2),
                   seeds=[SEED])
    assert "multi-prime key gate refused" in info.value.failures[0]["reason"]
    # The gate error is a SeededKeygenError (ValueError), so the CLI reports it as a failure.
    assert issubclass(sk.SeededKeygenGateError, sk.SeededKeygenError)


def test_search_continues_past_a_dividing_seed_that_fails_the_gate():
    scheme = sk.KeygenScheme(nbits=32, num_primes=2)
    a1, a2 = sk.generate_primes(SEED, scheme)
    b1, b2 = sk.generate_primes(SEED + 1, scheme)
    assert len({a1, a2, b1, b2}) == 4
    n = a1 * b1 * b2
    assert all(n % prime for prime in sk.generate_primes(SEED - 1, scheme))  # SEED-1 never divides
    # Seed SEED divides n (a1) but its cofactor b1*b2 is composite; seed SEED+1 factors n fully.  A
    # non-dividing seed comes FIRST, so dropping by position instead of the failing seed is caught:
    # it would gate SEED twice.
    seeds = [SEED - 1, SEED, SEED + 1]
    res = sk.recover(n, scheme=scheme, seeds=seeds, workers=1)
    assert res is not None and res["seed"] == SEED + 1
    assert res["primes"] == sorted((a1, b1, b2))
    assert [f["seed"] for f in res["gate_failures"]] == [SEED]
    assert sk.recover(n, scheme=scheme, seeds=seeds, workers=2)["seed"] == SEED + 1
    # A seed listed twice is searched (and gated) once.
    res = sk.recover(n, scheme=scheme, seeds=[SEED - 1, SEED, SEED, SEED + 1], workers=1)
    assert [f["seed"] for f in res["gate_failures"]] == [SEED]


def test_gate_failure_rescans_only_its_own_block(monkeypatch):
    # The window is searched in SEARCH_BLOCK-sized blocks, in order.  After a gate failure only the
    # rest of that block is searched again, never the window from the start, so k failures in a
    # 1e6-seed window cost at most k extra blocks.  Counted in score calls (serial, in-process).
    scheme = sk.KeygenScheme(nbits=32, num_primes=2)
    a1, _a2 = sk.generate_primes(SEED, scheme)
    b1, b2 = sk.generate_primes(SEED + 1, scheme)
    n = a1 * b1 * b2
    fail, good = SEED, SEED + 1
    fillers = [SEED + 10 + k for k in range(14)]
    for f in fillers:
        assert all(n % prime for prime in sk.generate_primes(f, scheme))
    # Blocks of 4: [f0 f1 f2 f3] [f4 f5 f6 f7] [f8 FAIL f9 GOOD] [f10 f11 f12 f13]
    seeds = fillers[:9] + [fail] + [fillers[9], good] + fillers[10:]
    assert seeds.index(fail) == 9 and seeds.index(good) == 11
    monkeypatch.setattr(sk, "SEARCH_BLOCK", 4)
    calls = []
    real = sk._seed_divisor
    monkeypatch.setattr(sk, "_seed_divisor",
                        lambda n_, scheme_, seed: calls.append(seed) or real(n_, scheme_, seed))
    res = sk.recover(n, scheme=scheme, seeds=seeds, workers=1)
    assert res["seed"] == good and [f["seed"] for f in res["gate_failures"]] == [fail]
    # 8 (blocks 1-2) + 2 (f8, FAIL) + 3 (block 3 again without FAIL: f8, f9, GOOD) = 13.  The last
    # block is never scored.  A restart from the window start would score 10 + 11 = 21.
    assert len(calls) == 13
    assert calls[:10] == seeds[:10] and calls[10:] == [fillers[8], fillers[9], good]


def test_seed_divisor_generates_lazily_and_scheme_is_validated_once(monkeypatch):
    scheme = sk.KeygenScheme(nbits=32, num_primes=4)
    primes = sk.generate_primes(SEED, scheme)
    calls = []
    real_next = sk._next_prime
    monkeypatch.setattr(sk, "_next_prime", lambda v, s: calls.append(v) or real_next(v, s))
    assert sk._seed_divisor(primes[0] * 3, scheme, SEED) == primes[0]
    assert len(calls) == 1  # stopped at the first dividing prime, did not draw the other three
    monkeypatch.setattr(sk, "_next_prime", real_next)

    validations = []
    real_validate = sk.KeygenScheme.validate
    monkeypatch.setattr(sk.KeygenScheme, "validate",
                        lambda self: validations.append(1) or real_validate(self))
    sk.recover(primes[0] * primes[1], scheme=sk.KeygenScheme(nbits=32, num_primes=2),
               seeds=range(SEED - 30, SEED + 30), workers=1)
    assert len(validations) == 1


# --------------------------------------------------------------------------- bounds

def test_seeds_from_epochs_formula_and_exact_cap():
    assert sk.seeds_from_epochs(100, 103, 5, shift=8) == [(100 << 8) | 5, (101 << 8) | 5,
                                                          (102 << 8) | 5]
    assert len(sk.seeds_from_epochs(0, CAP, 0)) == CAP          # exactly the cap is allowed
    with pytest.raises(sk.SeededKeygenError, match="exceeds seed cap"):
        sk.seeds_from_epochs(0, CAP + 1, 0)                      # one over is refused
    with pytest.raises(sk.SeededKeygenError):
        sk.seeds_from_epochs(0, 10, 1 << 8, shift=8)             # serial overflows shift
    with pytest.raises(sk.SeededKeygenError):
        sk.seeds_from_epochs(10, 10, 0)                          # empty / inverted span


def test_seed_range_and_list_exact_cap():
    coerce = sk._coerce_seed_list
    assert len(coerce(None, 0, CAP, None, None, None, 16)) == CAP
    with pytest.raises(sk.SeededKeygenError, match="exceeds cap"):
        coerce(None, 0, CAP + 1, None, None, None, 16)
    assert len(coerce(range(CAP), None, None, None, None, None, 16)) == CAP
    with pytest.raises(sk.SeededKeygenError, match="exceeds cap"):
        coerce(range(CAP + 1), None, None, None, None, None, 16)
    with pytest.raises(sk.SeededKeygenError, match="exceeds cap"):
        sk.recover(10 ** 20, scheme=sk.KeygenScheme(nbits=64), seed_start=0, seed_stop=CAP + 1)


def test_scheme_and_range_validation():
    with pytest.raises(sk.SeededKeygenError):
        sk.KeygenScheme(prng="java").validate()
    with pytest.raises(sk.SeededKeygenError):
        sk.generate_primes(-1, sk.KeygenScheme(nbits=32))
    with pytest.raises(sk.SeededKeygenError, match="no seed source"):
        sk.recover(10 ** 20, scheme=sk.KeygenScheme(nbits=64))


# --------------------------------------------------------------------------- timestamp windows

def _udp_frame(payload: bytes) -> bytes:
    udp = struct.pack(">HHHH", 40000, 9151, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + udp


def _pcap(records) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for seconds, payload in records:
        frame = _udp_frame(payload)
        out += struct.pack("<IIII", seconds, 500_000, len(frame), len(frame)) + frame
    return out


CAPTURE = _pcap([(EPOCH - 30, b"HELLO courier"), (EPOCH + 4, b"REG n=..."), (EPOCH + 90, b"BYE")])


def test_epoch_window_from_pcap_marker_and_all_packets():
    win = sk.epoch_window_from_pcap(CAPTURE, marker=b"REG", before=10, after=0)
    assert (win["epoch_start"], win["epoch_stop"]) == (EPOCH + 4 - 10, EPOCH + 5)
    assert win["anchor_count"] == 1 and win["damaged"] is None
    every = sk.epoch_window_from_pcap(CAPTURE, before=5, after=3)
    assert (every["epoch_start"], every["epoch_stop"]) == (EPOCH - 35, EPOCH + 94)
    assert every["anchor_count"] == 3
    # The derived window feeds recover and contains the true seed epoch.
    scheme = sk.KeygenScheme(nbits=64, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    res = sk.recover(p * q, scheme=scheme, epoch_start=win["epoch_start"],
                     epoch_stop=win["epoch_stop"], serial=SERIAL, workers=1)
    assert res["seed"] == SEED


def test_epoch_window_from_pcap_refuses_loudly():
    with pytest.raises(sk.SeededKeygenError, match="no packet containing marker"):
        sk.epoch_window_from_pcap(CAPTURE, marker=b"NOPE")
    with pytest.raises(sk.SeededKeygenError, match="not a readable capture"):
        sk.epoch_window_from_pcap(b"this is not a capture at all")
    with pytest.raises(sk.SeededKeygenError, match="no timestamped packet"):
        sk.epoch_window_from_pcap(_pcap([]))
    with pytest.raises(sk.SeededKeygenError, match="over seed cap"):
        sk.epoch_window_from_pcap(CAPTURE, before=CAP, after=0)


def test_epoch_window_from_mtime_and_exact_cap(tmp_path):
    f = tmp_path / "keyfile.bin"
    f.write_bytes(b"x")
    os.utime(f, (EPOCH + 7, EPOCH + 7))
    win = sk.epoch_window_from_mtime(f, before=20, after=2)
    assert (win["epoch_start"], win["epoch_stop"]) == (EPOCH - 13, EPOCH + 10)
    assert win["source"] == "mtime"
    # span = before + after + 1: CAP allowed, CAP + 1 refused.
    ok = sk.epoch_window_from_mtime(f, before=CAP - 1, after=0)
    assert ok["epoch_stop"] - ok["epoch_start"] == CAP
    with pytest.raises(sk.SeededKeygenError, match="over seed cap"):
        sk.epoch_window_from_mtime(f, before=CAP, after=0)
    with pytest.raises(OSError):
        sk.epoch_window_from_mtime(tmp_path / "missing")


# --------------------------------------------------------------------------- rsa_attacks gate

def test_rsa_attacks_seeded_private_key_gate():
    scheme = sk.KeygenScheme(nbits=64, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    n = p * q
    key = rsa.recover_seeded_private_key(n, 65537, p)
    assert key is not None
    d, kp, kq = key
    assert {kp, kq} == {p, q}
    assert pow(pow(12345, 65537, n), d, n) == 12345 % n
    # Not a divisor of n -> None; a bool masquerading as 1 -> None; composite cofactor -> None.
    assert rsa.recover_seeded_private_key(n, 65537, p + 2) is None
    assert rsa.recover_seeded_private_key(n, 65537, True) is None
    assert rsa.recover_seeded_private_key(p * (q * 2), 65537, p) is None


# --------------------------------------------------------------------------- CLI

def _cli(request: dict, d: Path):
    req = d / "req.json"
    req.write_text(json.dumps(request))
    return subprocess.run([sys.executable, "-I", str(CLI), "seeded-keygen", str(req)],
                          capture_output=True, text=True, timeout=600)


def test_cli_seeded_keygen_roundtrip_and_bad_requests():
    scheme = sk.KeygenScheme(nbits=64, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    n = p * q
    c = pow(42, 65537, n)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        proc = _cli({"n": n, "ciphertext": c, "scheme": {"nbits": 64, "num_primes": 2},
                     "epoch_start": EPOCH - 20, "epoch_stop": EPOCH + 20, "serial": SERIAL,
                     "workers": 2}, d)
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["verified"] is True
        assert payload["candidate"]["seed"] == SEED
        assert payload["candidate"]["plaintext_int"] == 42

        proc = _cli({"n": n, "scheme": {"nope": 1}, "seeds": [SEED]}, d)
        assert proc.returncode == 2 and "nope" in proc.stderr

        proc = _cli({"scheme": {"nbits": 64}, "seeds": [SEED]}, d)
        assert proc.returncode == 2 and "seeded-keygen request needs n" in proc.stderr

        proc = _cli({"n": q * p * 15, "scheme": {"nbits": 64}, "seeds": [SEED]}, d)
        assert proc.returncode == 2 and "gate refused" in proc.stderr


def test_cli_seeded_keygen_epoch_window_from_pcap():
    scheme = sk.KeygenScheme(nbits=64, num_primes=2)
    p, q = sk.generate_primes(SEED, scheme)
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        cap = d / "courier.pcap"
        cap.write_bytes(CAPTURE)
        proc = _cli({"n": p * q, "scheme": {"nbits": 64}, "pcap": str(cap), "pcap_marker": "REG",
                     "before": 10, "after": 0, "serial": SERIAL, "workers": 1}, d)
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["verified"] is True and payload["candidate"]["seed"] == SEED
        assert payload["candidate"]["epoch_window"]["epoch_start"] == EPOCH - 6

        proc = _cli({"n": p * q, "scheme": {"nbits": 64}, "pcap": str(cap), "serial": SERIAL,
                     "epoch_start": EPOCH, "epoch_stop": EPOCH + 1}, d)
        assert proc.returncode == 2 and "do not also pass epoch_start" in proc.stderr


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-q"]))
