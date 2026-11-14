"""Independent NumPy/SciPy oracles for saved-model evidence statistics."""
import json
import math
import random

import numpy as np
import pytest
from scipy.stats import binom

import model_integrity_forensics as model


def test_paired_predictions_and_confidence_arithmetic():
    records = [{'clean_prediction': 'a' if i % 2 else 'b', 'triggered_prediction': 'target',
                'true_label': 'a' if i % 2 else 'b', 'clean_confidence': 0.7,
                'triggered_confidence': 0.9} for i in range(8)]
    result = model.backdoor_behavior_report(records)
    assert result['target_candidate'] == 'target'
    assert result['target_fraction'] == result['label_flip_fraction'] == 1
    assert result['clean_target_fraction'] == 0
    assert result['clean_accuracy'] == 1 and result['triggered_accuracy'] == 0
    assert result['mean_confidence_shift'] == pytest.approx(0.2)
    assert result['findings'][0]['kind'] == 'target-concentration-candidate'
    assert result['backdoor_verified'] is False


def test_spectral_top_direction_matches_numpy_eigh():
    matrix = np.array([[1, 0], [-1, 0], [0, 2], [0, -2]], dtype=float)
    centered = matrix - matrix.mean(axis=0)
    values, vectors = np.linalg.eigh(centered.T @ centered / len(matrix))
    result = model.activation_spectral_report(matrix.tolist(), labels=['a', 'b', 'a', 'b'])
    assert result['top_eigenvalue'] == pytest.approx(values[-1])
    assert abs(np.dot(result['direction'], vectors[:, -1])) == pytest.approx(1)
    assert result['label_count'] == 2


def test_spectral_orthogonal_initial_direction():
    matrix = np.array([[1, -1], [-1, 1]], dtype=float)
    expected = np.linalg.eigvalsh(matrix.T @ matrix / 2)[-1]
    assert model.activation_spectral_report(matrix.tolist())['top_eigenvalue'] == pytest.approx(expected)


def test_neural_cleanse_median_mad_and_weight_energy():
    norms = {'a': 1, 'b': 9, 'c': 10, 'd': 11, 'e': 12}
    values = np.array(list(norms.values()))
    median = np.median(values)
    mad = np.median(np.abs(values-median))
    out = model.neural_cleanse_summary(norms)
    assert out['median_norm'] == median and out['mad_norm'] == mad
    assert out['minimum_class'] == 'a'
    assert out['anomaly_index'] == pytest.approx((median-1)/(1.4826*mad))
    weights = np.array([1.0]*99 + [100.0])
    out = model.weight_outlier_report([{'name': 'layer', 'values': weights.tolist()}])
    assert out['tensors'][0]['top_one_percent_energy_fraction'] == pytest.approx(10000 / np.dot(weights, weights))
    assert out['findings'][0]['kind'] == 'weight-concentration-candidate'


@pytest.mark.parametrize(('n', 'k', 'rate'), [(20, 18, 0.5), (10, 3, 0.2), (100, 75, 0.5), (8, 8, 0), (8, 0, 1)])
def test_watermark_exact_binomial_scipy(n, k, rate):
    out = model.watermark_response_report([True]*k + [False]*(n-k), expected_rate=rate)
    assert out['one_sided_p_value'] == pytest.approx(binom.sf(k-1, n, rate), rel=1e-12, abs=1e-15)
    assert out['matches'] == k and out['trials'] == n
    assert out['model_loaded'] is False and out['network_used'] is False


def test_signature_margin_hamming_and_probability():
    out = model.weight_signature_report([2, -3, 0, 0.1, 5], [1, 1, 0, 1, 1], margin=0.2)
    assert out['observed_bits'] == [1, 0, None, None, 1]
    assert out['decided_bits'] == 3 and out['hamming_distance'] == 1
    assert out['one_sided_p_value'] == pytest.approx(binom.sf(1, 3, 0.5))
    assert json.loads(model.json_report({'b': 2, 'a': 1})) == {'a': 1, 'b': 2}
    assert model.json_report({'b': 2, 'a': 1}) == '{"a": 1, "b": 2}'


@pytest.mark.parametrize('entry', [model.backdoor_behavior_report, model.activation_spectral_report,
                                 model.neural_cleanse_summary, model.weight_outlier_report,
                                 model.watermark_response_report,
                                 lambda value: model.weight_signature_report(value, [1])])
def test_malformed_evidence_only_declared_valueerror(entry):
    rng = random.Random(0x4d4f444c)
    samples = [None, [], {}, b'', b'\xff'*32, 'text', 5, [None], [math.nan], [math.inf],
               [[1], [1, 2]], [{'values': [math.inf]}], [{'norm': math.nan}],
               [rng.random() for _ in range(64)]]
    for sample in samples:
        try:
            entry(sample)
        except ValueError as error:
            assert type(error) is ValueError


@pytest.mark.parametrize('kwargs', [{'iterations': 1.5}, {'iterations': None}, {'trigger_flags': 3}])
def test_bad_spectral_options_only_declared_valueerror(kwargs):
    try:
        model.activation_spectral_report([[1], [2]], **kwargs)
    except ValueError as error:
        assert type(error) is ValueError


def test_small_limits_and_nonfinite_evidence(monkeypatch):
    monkeypatch.setattr(model, 'MAX_ROWS', 2)
    with pytest.raises(ValueError):
        model.watermark_response_report([True]*3)
    monkeypatch.setattr(model, 'MAX_VALUES', 2)
    with pytest.raises(ValueError):
        model.weight_outlier_report([{'values': [1, 2, 3]}])
    for value in (math.nan, math.inf, -math.inf, 10**500):
        with pytest.raises(ValueError):
            model.activation_spectral_report([[value], [1]])


def test_saved_numeric_analysis_never_unpickles_or_connects(monkeypatch):
    import pickle
    import socket
    def forbidden(*args, **kwargs):
        pytest.fail('Saved evidence analysis attempted model loading or network')
    monkeypatch.setattr(pickle, 'load', forbidden)
    monkeypatch.setattr(pickle, 'loads', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    assert model.watermark_response_report([True, False])['model_loaded'] is False
