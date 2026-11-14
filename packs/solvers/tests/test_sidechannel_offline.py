"""Deterministic offline tests for the r5c side-channel/fault evidence lane."""

from __future__ import annotations

import importlib
import math
import random
import sys
from dataclasses import FrozenInstanceError
from itertools import repeat
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))

import sidechannel_offline as sc  # noqa: E402


def _byte_fixture(key=0x2B, count=128):
    rng = random.Random(0x51DEC0DE + key)
    inputs = [rng.randrange(256) for _ in range(count)]
    traces = []
    for index, value in enumerate(inputs):
        leakage = sc._AES_SBOX[value ^ key].bit_count()
        traces.append(
            [
                ((value * 3 + index * 5) % 31) / 10.0,
                ((value + index) % 17) / 7.0,
                leakage + ((index % 7) - 3) * 0.02,
                ((value * 11 + index) % 23) / 9.0,
            ]
        )
    return inputs, traces


def test_package_and_direct_imports_match():
    sys.path.insert(0, str(REPO))
    packaged = importlib.import_module("solvers.common.sidechannel_offline")
    assert packaged.__all__ == sc.__all__
    assert packaged.hamming_distance(0xAA, 0x0F, 8) == sc.hamming_distance(0xAA, 0x0F, 8)


def test_pearson_and_spearman_cross_checked_statistics_and_declines():
    x = [1, 2, 3, 4, 5, 6]
    y = [2, 4, 6, 8, 10, 12]
    assert sc.pearson_correlation(x, y) == pytest.approx(1.0)
    assert sc.spearman_correlation(x, list(reversed(y))) == pytest.approx(-1.0)
    tied_x = [1, 1, 2, 3, 3]
    tied_y = [5, 5, 7, 9, 9]
    assert sc.spearman_correlation(tied_x, tied_y) == pytest.approx(1.0)
    assert sc.pearson_correlation([1, 1, 1], [2, 3, 4]) is None
    assert sc.pearson_correlation([1, math.nan], [2, 3]) is None


def test_difference_of_means_and_hamming_models():
    traces = [[1.0, 10.0], [2.0, 12.0], [5.0, 20.0], [7.0, 24.0]]
    assert sc.difference_of_means(traces, [0, 0, 1, 1]) == pytest.approx((4.5, 11.0))
    assert sc.difference_of_means(traces, [1, 1, 1, 1]) is None
    assert sc.hamming_weight(0b101101, 6) == 4
    assert sc.hamming_distance(0b1010, 0b0011, 4) == 2
    assert sc.hamming_weight(-1) is None
    assert sc.hamming_weight(1, 10**6) is None
    assert sc.hamming_distance(1, 2, 10**6) is None


def test_aes_sbox_cpa_hw_and_hd_recover_only_unique_byte():
    key = 0x2B
    inputs, traces = _byte_fixture(key)
    assert (
        sc.recover_aes_sbox_byte_cpa(
            inputs, traces, min_correlation=0.5, margin=0.1
        )
        == key
    )
    hd_traces = []
    for index, value in enumerate(inputs):
        leakage = (sc._AES_SBOX[value ^ key] ^ value).bit_count()
        hd_traces.append([leakage + ((index % 5) - 2) * 0.015, traces[index][0]])
    assert (
        sc.recover_aes_sbox_byte_cpa(
            inputs,
            hd_traces,
            leakage_model="sbox_hd_input",
            min_correlation=0.5,
            margin=0.1,
        )
        == key
    )
    assert sc.recover_aes_sbox_byte_cpa(inputs, [[1.0, 1.0]] * len(inputs)) is None


def test_aes_sbox_dpa_partition_recovery_and_ambiguity_decline():
    key, bit = 0x2B, 2
    inputs, base = _byte_fixture(key)
    traces = []
    for index, value in enumerate(inputs):
        group = (sc._AES_SBOX[value ^ key] >> bit) & 1
        traces.append([base[index][0], 4.0 * group + ((index % 5) - 2) * 0.03])
    assert (
        sc.recover_aes_sbox_byte_dpa(
            inputs, traces, bit_index=bit, min_effect=2.0, margin=0.5
        )
        == key
    )
    assert sc.recover_aes_sbox_byte_dpa(inputs, [[0.0]] * len(inputs), bit_index=bit) is None


def test_dpa_normalizes_trace_matrix_only_for_input_and_final_replay(monkeypatch):
    key, bit = 0x2B, 2
    inputs, base = _byte_fixture(key, count=64)
    traces = [
        [3.0 * ((sc._AES_SBOX[value ^ key] >> bit) & 1) + (index % 3) * 0.01]
        for index, value in enumerate(inputs)
    ]
    original = sc._trace_matrix
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(sc, "_trace_matrix", counted)
    assert (
        sc.recover_aes_sbox_byte_dpa(
            inputs, traces, bit_index=bit, min_effect=1.0, margin=0.2
        )
        == key
    )
    assert len(calls) == 2


def _full_key_fixture():
    rng = random.Random(0xA35128)
    key = bytes(range(16))
    plaintexts = [bytes(rng.randrange(256) for _ in range(16)) for _ in range(72)]
    traces = []
    for row_index, plaintext in enumerate(plaintexts):
        traces.append(
            [
                sc._AES_SBOX[plaintext[index] ^ key[index]].bit_count()
                + (((row_index * 3 + index * 5) % 11) - 5) * 0.015
                for index in range(16)
            ]
        )
    return key, plaintexts, traces


def test_multibyte_cpa_requires_each_byte_and_full_cipher_negative_control():
    from Crypto.Cipher import AES

    key, plaintexts, traces = _full_key_fixture()
    block = bytes(range(16))
    ciphertext = AES.new(key, AES.MODE_ECB).encrypt(block)
    recovered = sc.recover_aes_key_cpa(
        plaintexts,
        traces,
        min_correlation=0.6,
        margin=0.08,
        verification_pairs=((item for item in [(block, ciphertext)])),
    )
    assert recovered == key
    corrupted = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    assert (
        sc.recover_aes_key_cpa(
            plaintexts,
            traces,
            min_correlation=0.6,
            margin=0.08,
            verification_pairs=[(block, corrupted)],
        )
        is None
    )


def test_partial_key_verifier_called_once_per_control_and_exact_bool_required():
    key, plaintexts, traces = _full_key_fixture()
    expected = key[:2]
    calls = []

    def verifier(candidate):
        if candidate in calls:
            raise AssertionError("verifier called twice for one candidate")
        calls.append(candidate)
        return candidate == expected

    recovered = sc.recover_aes_key_cpa(
        plaintexts,
        traces,
        byte_indices=[0, 1],
        min_correlation=0.6,
        margin=0.08,
        verifier=verifier,
    )
    assert recovered == expected
    assert calls == [expected, bytes([expected[0] ^ 1, expected[1]])]
    assert (
        sc.recover_aes_key_cpa(
            plaintexts,
            traces,
            byte_indices=[0, 1],
            min_correlation=0.6,
            margin=0.08,
            verifier=lambda _candidate: 1,
        )
        is None
    )


def test_generic_timing_recovery_correlation_rank_likelihood_and_tie_decline():
    inputs = list(range(1, 41))
    secret = 7

    def model(candidate, value):
        return float((candidate * value + value * value) % 97)

    timings = [model(secret, value) + ((value % 5) - 2) * 0.02 for value in inputs]
    for method in ("correlation", "rank", "likelihood"):
        assert (
            sc.recover_timing_candidate(
                inputs,
                timings,
                range(1, 13),
                model,
                method=method,
                min_score=0.5,
                margin=0.1,
                max_rmse=0.2,
            )
            == secret
        )
    assert (
        sc.recover_timing_candidate(
            inputs,
            timings,
            [1, 2],
            lambda _candidate, value: float(value),
            method="correlation",
            margin=0.0,
        )
        is None
    )
    assert (
        sc.recover_timing_candidate(
            inputs,
            timings,
            [1, 2],
            lambda _candidate, value: float(value),
            method="likelihood",
            margin=0.0,
            max_rmse=100.0,
        )
        is None
    )


def test_square_multiply_model_and_toy_rsa_timing_recovery():
    modulus, exponent = 3233, 173
    bases = list(range(2, 80))
    timings = [
        sc.square_multiply_timing_model(base, exponent, modulus) + ((base % 5) - 2) * 0.01
        for base in bases
    ]
    assert sc.square_multiply_timing_model(2, exponent, modulus) is not None
    assert sc.square_multiply_timing_model(modulus, exponent, modulus) is None
    assert (
        sc.recover_modexp_timing_exponent(
            bases,
            timings,
            modulus,
            range(160, 190),
            method="likelihood",
            margin=0.05,
            max_rmse=0.1,
        )
        == exponent
    )
    assert (
        sc.recover_modexp_timing_exponent(
            bases, [1.0] * len(bases), modulus, [171, 172], method="correlation"
        )
        is None
    )


def _cache_fixture():
    pattern = (2, 0, 1, 2, 1, 0)
    traces = []
    for index, cache_set in enumerate(pattern):
        row = [0.1, 0.2, 0.3]
        row[cache_set] = 5.0 + index * 0.01
        traces.append(row)
    return pattern, traces


def test_cache_access_pattern_and_mapping_unique_replay():
    pattern, traces = _cache_fixture()
    candidates = [pattern, (1, 0, 1, 2, 1, 0), (2, 0, 0, 2, 1, 0)]
    assert sc.infer_cache_access_pattern(traces, candidates, margin=0.1) == pattern
    labels = ("A", "B", "C", "A", "C", "B")
    mappings = [
        {"A": 2, "B": 0, "C": 1},
        {"A": 1, "B": 0, "C": 2},
        {"A": 2, "B": 1, "C": 0},
    ]
    assert sc.infer_cache_set_mapping(labels, traces, mappings, margin=0.1) == (
        ("A", 2),
        ("B", 0),
        ("C", 1),
    )
    assert sc.infer_cache_set_mapping(iter(labels), iter(traces), iter(mappings), margin=0.1) == (
        ("A", 2),
        ("B", 0),
        ("C", 1),
    )
    tied = [[1.0, 1.0] for _ in range(4)]
    assert sc.infer_cache_access_pattern(tied, [(0, 0, 0, 0), (1, 1, 1, 1)]) is None
    split = [[3.0, 0.0], [0.0, 3.0]]
    assert (
        sc.infer_cache_access_pattern(
            split, [(0, 0), (1, 1)], min_accuracy=0.5, margin=0.0
        )
        is None
    )


def test_aes_dfa_differential_recovery_and_duplicate_observation_ambiguity():
    key, output_mask = 0x4D, 0x93
    inputs = [3, 4, 5, 6]
    masks = [1, 2, 4, 8]
    good = [sc._AES_SBOX[value ^ key] ^ output_mask for value in inputs]
    faulty = [
        sc._AES_SBOX[(value ^ mask) ^ key] ^ output_mask
        for value, mask in zip(inputs, masks)
    ]
    assert sc.recover_aes_dfa_byte(inputs, good, faulty, masks) == key
    assert (
        sc.recover_aes_dfa_byte(
            [inputs[0], inputs[0]],
            [good[0], good[0]],
            [faulty[0], faulty[0]],
            [masks[0], masks[0]],
        )
        is None
    )
    assert sc.recover_aes_dfa_byte(inputs, good, good, [0] * len(inputs)) is None


def test_instruction_skip_recovery_and_indistinguishable_skip_decline():
    operations = (lambda value: value + 3, lambda value: value * 2, lambda value: value ^ 5)
    inputs = (1, 4, 10)

    def replay(value, skip=None):
        for index, operation in enumerate(operations):
            if index != skip:
                value = operation(value)
        return value

    good = [replay(value) for value in inputs]
    faulty = [replay(value, 1) for value in inputs]
    assert sc.recover_instruction_skip(inputs, good, faulty, operations) == 1
    ambiguous_ops = (lambda value: value, lambda value: value)
    assert sc.recover_instruction_skip(inputs, inputs, inputs, ambiguous_ops) is None


def test_redundancy_candidate_full_good_faulty_replay_and_ambiguity_decline():
    secret = 7
    inputs = [2, 5, 9, 12]
    labels = [1, 2, 4, 8]
    primary_model = lambda candidate, value: (candidate + value) % 257
    redundant_model = lambda candidate, value: candidate ^ value
    fault_model = lambda redundant, label: redundant ^ label
    primary = [primary_model(secret, value) for value in inputs]
    redundant = [redundant_model(secret, value) for value in inputs]
    faulty = [fault_model(value, label) for value, label in zip(redundant, labels)]
    assert (
        sc.recover_redundant_candidate(
            inputs,
            primary,
            redundant,
            faulty,
            labels,
            range(1, 15),
            primary_model,
            redundant_model,
            fault_model,
        )
        == secret
    )
    assert (
        sc.recover_redundant_candidate(
            inputs,
            [0] * len(inputs),
            [0] * len(inputs),
            labels,
            labels,
            [1, 2],
            lambda _candidate, _value: 0,
            lambda _candidate, _value: 0,
            lambda value, label: value ^ label,
        )
        is None
    )


def test_fault_clustering_exact_replay_and_expected_cluster_decline():
    good = [(1, 2), (3, 4), (5, 6), (7, 8)]
    faulty = [(1 ^ 4, 2), (3 ^ 4, 4), (5, 6 ^ 8), (7, 8 ^ 8)]
    clusters = sc.cluster_fault_differences(good, faulty, expected_clusters=2)
    assert clusters is not None
    assert all(isinstance(cluster, sc.FaultCluster) for cluster in clusters)
    assert {(cluster.signature, cluster.count) for cluster in clusters} == {
        ((4, 0), 2),
        ((0, 8), 2),
    }
    with pytest.raises(FrozenInstanceError):
        clusters[0].count = 99
    assert sc.cluster_fault_differences(good, faulty, expected_clusters=1) is None
    differences = sc.cluster_fault_differences(good, [(2, 4), (4, 6), (6, 8), (8, 10)], mode="difference")
    assert differences is not None


def test_failing_infinite_malformed_and_nonfinite_inputs_decline():
    def broken():
        yield [1.0]
        raise RuntimeError("truncated trace")

    assert sc.recover_aes_sbox_byte_cpa(repeat(0), [[0.0]]) is None
    assert sc.recover_aes_sbox_byte_cpa([0, 1], broken()) is None
    assert sc.difference_of_means([[1.0], [math.inf]], [0, 1]) is None
    assert sc.infer_cache_access_pattern([[1.0], [2.0]], repeat((0, 0))) is None
    assert sc.recover_instruction_skip([1], [1], [1], [lambda _value: (_ for _ in ()).throw(RuntimeError())]) is None
    assert sc.cluster_fault_differences([[1, 2], [3]], [[1, 2], [3, 4]]) is None


def test_aggregate_trace_cell_cap_is_enforced_during_parse(monkeypatch):
    monkeypatch.setattr(sc, "MAX_TRACE_CELLS", 10)
    traces = [[float(row + column) for column in range(4)] for row in range(3)]
    assert sc.difference_of_means(traces, [0, 1, 1]) is None
