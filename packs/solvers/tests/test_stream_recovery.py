"""Deterministic success, replay, ambiguity, and cap tests for r5c streams."""

from __future__ import annotations

import itertools
import importlib
import random
import sys
from collections import Counter
from pathlib import Path

from Crypto.Cipher import ARC4


COMMON = Path(__file__).resolve().parents[1] / "solvers" / "common"
sys.path.insert(0, str(COMMON))

import stream_recovery as stream  # noqa: E402


def test_berlekamp_massey_and_unique_lfsr_recovery_replay_every_bit():
    coefficients = (0, 0, 1, 1)
    state = (1, 0, 0, 1)
    observed = stream.lfsr_generate(state, coefficients, 128)
    assert observed is not None
    assert stream.berlekamp_massey(observed) == coefficients
    recovered = stream.recover_lfsr(observed)
    assert recovered == stream.LFSRRecovery(4, state, coefficients)
    assert stream.lfsr_generate(recovered.state, recovered.coefficients, len(observed)) == observed
    # Fewer than 2L bits cannot uniquely establish the recurrence.
    assert stream.recover_lfsr(observed[:7]) is None


def test_berlekamp_zero_and_malformed_sequences_decline_safely():
    assert stream.berlekamp_massey([0] * 32) == ()
    assert stream.recover_lfsr([0] * 32) is None
    assert stream.berlekamp_massey([0, 1, 2]) is None
    assert stream.berlekamp_massey(itertools.repeat(0, stream.MAX_BITS + 1)) is None
    assert stream.lfsr_generate((1, 0), (1, 0), 8) is None  # non-minimal degree marker


def test_geffe_correlation_ordering_ends_in_unique_full_replay():
    coefficients = ((0, 1, 1), (0, 0, 1, 1), (0, 0, 1, 0, 1))
    states = ((1, 0, 1), (1, 0, 0, 1), (1, 0, 1, 1, 0))
    components = [stream.lfsr_generate(state, taps, 96)
                  for state, taps in zip(states, coefficients)]
    observed = stream.geffe_combine(*components)
    assert observed is not None
    assert stream.recover_geffe_states(observed, *coefficients) == states
    assert stream.recover_geffe_states(
        observed, *coefficients, verify=lambda candidate: candidate == states
    ) == states
    assert stream.recover_geffe_states(
        observed, *coefficients, verify=lambda _candidate: False
    ) is None
    # A short output admits multiple exact state triples and must not be chosen.
    assert stream.recover_geffe_states(observed[:3], *coefficients) is None


def test_nonlinear_filter_truth_table_state_recovery_and_ambiguity():
    coefficients, state = (0, 0, 1, 1), (1, 0, 0, 1)
    offsets = (0, 1, 3)
    # f(x,y,z) = x XOR (y AND z), table in xyz order.
    table = tuple(((index >> 2) & 1) ^ (((index >> 1) & 1) & (index & 1))
                  for index in range(8))
    raw = stream.lfsr_generate(state, coefficients, 52)
    observed = []
    for time in range(48):
        index = 0
        for offset in offsets:
            index = (index << 1) | raw[time + offset]
        observed.append(table[index])
    candidates = range(1, 1 << len(coefficients))
    assert stream.recover_filtered_lfsr_state(
        observed, coefficients, offsets, table, candidates
    ) == state
    assert stream.recover_filtered_lfsr_state(
        observed, coefficients, offsets, table, candidates,
        verify=lambda _state: "truthy but not bool",
    ) is None
    # Constant filters erase all state evidence.
    assert stream.recover_filtered_lfsr_state(
        [0] * 16, coefficients, offsets, [0] * 8, candidates
    ) is None


def test_shrinking_generator_toy_recovery_and_short_ambiguity():
    control_coefficients, data_coefficients = (1, 1), (0, 1)
    control_state, data_state = (1, 0), (0, 1)
    observed = stream.shrinking_generate(
        control_state, control_coefficients, data_state, data_coefficients, 64
    )
    assert observed is not None
    assert stream.recover_shrinking_generator(
        observed, control_coefficients, data_coefficients
    ) == (control_state, data_state)
    assert stream.recover_shrinking_generator(
        observed[:1], control_coefficients, data_coefficients
    ) is None


def test_alternating_generator_toy_recovery_and_short_ambiguity():
    coefficients = ((0, 1, 1), (0, 0, 1, 1), (0, 0, 1, 0, 1))
    states = ((1, 0, 1), (1, 0, 0, 1), (1, 0, 1, 1, 0))
    observed = stream.alternating_generate(
        states[0], coefficients[0], states[1], coefficients[1],
        states[2], coefficients[2], 48,
    )
    assert observed is not None
    assert stream.recover_alternating_generator(observed, *coefficients) == states
    assert stream.recover_alternating_generator(observed[:2], *coefficients) is None


def test_rc4_primitives_match_rfc_vector_and_pycryptodome():
    key = b"Key"
    expected = bytes.fromhex("eb9f7781b734ca72a7194a2867b64295")
    assert stream.rc4_keystream(key, len(expected)) == expected
    assert stream.rc4_keystream(key, len(expected)) == ARC4.new(key).encrypt(bytes(len(expected)))
    plaintext = b"Plaintext"
    ciphertext = stream.rc4_crypt(key, plaintext)
    assert ciphertext == ARC4.new(key).encrypt(plaintext)
    assert stream.rc4_crypt(key, ciphertext) == plaintext
    state = stream.rc4_ksa(key)
    assert state is not None and stream.rc4_prga(state, 16) == expected


def _fms_packets(secret: bytes):
    packets = []
    for key_index in range(len(secret)):
        for nonce in range(256):
            iv = bytes((key_index + 3, 0xFF, nonce))
            plaintext = bytes((0x41 + key_index,))
            ciphertext = stream.rc4_crypt(iv + secret, plaintext)
            packets.append((iv, ciphertext, plaintext))
    return packets


def test_fms_key_bytes_are_emitted_only_after_every_packet_replays():
    secret = b"KEY"
    packets = _fms_packets(secret)
    assert stream.recover_rc4_fms_key(packets, len(secret)) == secret
    corrupted = list(packets)
    iv, ciphertext, plaintext = corrupted[-1]
    corrupted[-1] = (iv, bytes([ciphertext[0] ^ 1]), plaintext)
    assert stream.recover_rc4_fms_key(corrupted, len(secret)) is None
    assert stream.recover_rc4_fms_key(
        packets + [packets[0]], len(secret)
    ) is None  # duplicate IVs may not manufacture statistical confidence
    # Two different one-vote hypotheses tie and are explicitly ambiguous.
    assert stream.recover_rc4_fms_key(
        packets[:2], 1, min_packets_per_byte=2, min_votes=1, min_margin=1
    ) is None


def test_rc4_bias_report_matches_independent_counts_and_declines_ties_only_as_report():
    samples = [bytes((index & 0xFF, 0)) for index in range(64)]
    samples += [bytes((index & 0xFF, 1)) for index in range(8)]
    report = stream.analyze_rc4_bias(samples, position=1)
    assert report is not None
    independent = Counter(sample[1] for sample in samples)
    assert report.counts[0] == independent[0] == 64
    assert report.most_common == (0,)
    assert report.zero_frequency == 64 / 72
    assert report.chi_square > 0
    # A uniform two-value fixture is a report, not a guessed secret.
    tied = stream.analyze_rc4_bias([b"\x00", b"\x01"], position=0)
    assert tied is not None and tied.most_common == (0, 1)


def test_known_plaintext_keystream_requires_xor_consistency_and_verifier():
    keystream = bytes.fromhex("00112233445566778899aabbccddeeff")
    plaintext_a = b"known plaintext!"
    plaintext_b = b"short crib"
    ciphertext_a = bytes(a ^ b for a, b in zip(plaintext_a, keystream))
    ciphertext_b = bytes(a ^ b for a, b in zip(plaintext_b, keystream))
    observations = [(plaintext_a, ciphertext_a), (plaintext_b, ciphertext_b)]
    assert stream.recover_known_plaintext_keystream(
        observations, lambda candidate: candidate == keystream[:len(plaintext_a)]
    ) == keystream[:len(plaintext_a)]
    assert stream.recover_known_plaintext_keystream(
        observations, lambda _candidate: False
    ) is None
    assert stream.recover_known_plaintext_keystream(
        observations, lambda _candidate: True
    ) is None  # overaccepting verifier fails the one-bit negative control
    contradictory = list(observations)
    contradictory[1] = (plaintext_b, bytes([ciphertext_b[0] ^ 1]) + ciphertext_b[1:])
    assert stream.recover_known_plaintext_keystream(
        contradictory, lambda _candidate: True
    ) is None


def _raises(*_args):
    raise RuntimeError("synthetic callback failure")


def test_callbacks_malformed_inputs_and_work_caps_decline():
    coefficients = ((0, 1, 1), (0, 0, 1, 1), (0, 0, 1, 0, 1))
    states = ((1, 0, 1), (1, 0, 0, 1), (1, 0, 1, 1, 0))
    components = [stream.lfsr_generate(state, taps, 32)
                  for state, taps in zip(states, coefficients)]
    observed = stream.geffe_combine(*components)
    assert stream.recover_geffe_states(
        observed, *coefficients, verify=_raises
    ) is None
    assert stream.recover_geffe_states(
        observed, *coefficients, max_combinations=1
    ) is None
    assert stream.recover_geffe_states(
        observed, *coefficients,
        max_combinations=stream.MAX_GENERATOR_COMBINATIONS + 1,
    ) is None
    assert stream.recover_filtered_lfsr_state(
        [0, 1], (1, 1), [0, -1], [0, 1, 1, 0], [1, 2, 3]
    ) is None
    assert stream.recover_shrinking_generator(
        [0, 1], (0,) * 12 + (1,), (1, 1)
    ) is None
    assert stream.recover_shrinking_generator(
        [0, 1], (1, 1), (0, 1),
        max_combinations=stream.MAX_GENERATOR_COMBINATIONS + 1,
    ) is None
    assert stream.recover_alternating_generator(
        [0, 1], (1, 1), (0, 1), (1, 1),
        max_combinations=stream.MAX_GENERATOR_COMBINATIONS + 1,
    ) is None
    assert stream.rc4_ksa(b"") is None
    assert stream.rc4_prga(tuple([True] + list(range(1, 256))), 1) is None
    assert stream.rc4_prga(tuple(float(value) for value in range(256)), 1) is None
    assert stream.rc4_keystream(b"k", stream.MAX_RC4_BYTES + 1) is None
    assert stream.recover_rc4_fms_key([(b"bad", b"x", b"yy")], 1) is None
    assert stream.analyze_rc4_bias(
        itertools.repeat(b"xx", stream.MAX_BIAS_SAMPLES + 1)
    ) is None
    assert stream.recover_known_plaintext_keystream([(b"a", b"b")], _raises) is None
    assert stream.recover_known_plaintext_keystream(
        itertools.repeat((b"a", b"b"), stream.MAX_STATE_CANDIDATES + 1),
        lambda _candidate: True,
    ) is None


def test_failing_iterators_and_aggregate_work_caps_decline_before_expansion():
    def failing_bits():
        yield 0
        yield 1
        raise RuntimeError("iterator failed")

    assert stream.berlekamp_massey(failing_bits()) is None
    assert stream.analyze_rc4_bias(failing_bits(), position=0) is None

    long_coefficients = (0,) * 11 + (1,)
    # Cardinality alone is modest (4095 states), but state-bits work is not.
    assert stream.recover_geffe_states(
        [0] * 3000, long_coefficients, (1,), (1,)
    ) is None
    balanced = (0, 0, 1, 0, 1)
    # Precomputed streams are cheap here, but 31^3 full 300-bit replays exceed
    # the aggregate exact-combination work budget.
    assert stream.recover_geffe_states(
        [0] * 300, balanced, balanced, balanced
    ) is None
    assert stream.recover_filtered_lfsr_state(
        [0] * 3000, long_coefficients, [0], [0, 1], range(1, 1 << 12)
    ) is None


def test_bm_complexity_cap_stops_random_long_input_but_keeps_order_64():
    rng = random.Random(0xC5C7F2026)
    noisy = [rng.getrandbits(1) for _ in range(stream.MAX_BITS)]
    assert stream.berlekamp_massey(noisy) is None

    coefficients = (0,) * 63 + (1,)
    # A single impulse repeated every 64 clocks has exact linear complexity 64.
    state = (1,) + (0,) * 63
    observed = stream.lfsr_generate(state, coefficients, stream.MAX_BITS)
    assert stream.berlekamp_massey(observed) == coefficients
    assert stream.recover_lfsr(observed) == stream.LFSRRecovery(64, state, coefficients)


def test_package_import_smoke_uses_same_public_implementation():
    packaged = importlib.import_module("solvers.common.stream_recovery")
    assert packaged.rc4_keystream(b"Key", 8) == stream.rc4_keystream(b"Key", 8)
    assert packaged.berlekamp_massey([1, 0, 1, 1, 0, 1]) is not None
