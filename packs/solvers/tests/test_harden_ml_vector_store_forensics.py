"""Saved-vector geometry verified against SciPy/NumPy, without retrieval calls."""
import hashlib
import json
import math
import random
import struct

import numpy as np
import pytest
from scipy.spatial.distance import cosine

import vector_store_forensics as store


DOCS = [{'id': 'east', 'text': 'red apple', 'vector': [1, 0]},
        {'id': 'north', 'text': 'blue ocean', 'vector': [0, 1]},
        {'id': 'west', 'text': 'green tree', 'vector': [-1, 0]}]


def test_vector_validation_norm_hash_and_problem_kinds():
    out = store.validate_vector_store([{'id': 'a', 'text': 'Hello  WORLD', 'vector': [3, 4]}])
    assert out['valid'] and out['dimension_counts'] == {2: 1}
    assert out['records'][0]['norm'] == np.linalg.norm([3, 4])
    assert out['records'][0]['vector_sha256'] == hashlib.sha256(struct.pack('>dd', 3, 4)).hexdigest()
    assert out['records'][0]['text_sha256'] == hashlib.sha256(b'hello world').hexdigest()
    invalid = [{'id': 'same', 'vector': [0, 0]}, {'id': 'same', 'vector': [1]},
               {'id': 'bad', 'vector': [math.nan]}]
    out = store.validate_vector_store(invalid)
    assert {row['kind'] for row in out['findings']} == {
        'zero-norm-vector', 'duplicate-document-id', 'mixed-vector-dimensions', 'vector-has-nonfinite-value'}
    assert out['valid'] is False


def test_saved_ranking_against_scipy_cosine():
    query = np.array([3., 4.])
    expected = sorted(((1-cosine(query, row['vector']), row['id']) for row in DOCS),
                      key=lambda item: (-item[0], item[1]))
    returned = [{'id': ident, 'score': float(score)} for score, ident in expected]
    out = store.audit_saved_ranking(query.tolist(), returned, DOCS)
    assert out['recomputed_order'] == [ident for _, ident in expected]
    assert out['findings'] == [] and out['retrieval_contacted'] is False
    bad = store.audit_saved_ranking(query.tolist(), [{'id': 'west', 'score': 0.9}], DOCS)
    findings = {row['kind']: row for row in bad['findings']}
    assert findings['reported-score-mismatch']['recomputed'] == pytest.approx(-0.6)
    assert findings['nearer-corpus-items-omitted']['documents'] == ['north', 'east']


def test_poison_geometry_known_cosine_and_lexical_disagreement():
    docs = DOCS + [{'id': 'copy', 'text': 'unrelated zebra', 'vector': [1, 0]}]
    out = store.vector_poison_report(docs, trusted_ids=['east'], k=1)
    assert out['pair_comparisons'] == math.comb(4, 2)
    assert out['trusted_centroid_computed'] is True
    collisions = [row for row in out['findings'] if row['kind'] == 'vector-text-collision-candidate']
    assert len(collisions) == 1
    assert collisions[0]['cosine'] == 1 and collisions[0]['token_jaccard'] == 0
    outliers = [row for row in out['findings'] if row['kind'] == 'trusted-centroid-outlier-candidate']
    assert outliers[0]['document'] == 'west' and outliers[0]['centroid_cosine'] == -1
    assert out['poisoning_verified'] is False


def test_embedding_exact_nearest_and_additive_residual():
    codebook = {'east': [1, 0], 'north': [0, 1], 'west': [-1, 0]}
    out = store.embedding_exposure_report({'exact': [1, 0], 'diagonal': [1, 1]}, codebook, additive=True, max_terms=2)
    exact, diagonal = out['results']
    assert exact['nearest_label'] == 'east' and exact['exact_match'] is True
    assert exact['plaintext_recovered'] is True and exact['residual_l2'] == 0
    assert diagonal['cosine'] == pytest.approx(1/math.sqrt(2))
    assert diagonal['residual_l2'] == np.linalg.norm(np.array([1, 1])-np.array([1, 0]))
    assert diagonal['plaintext_recovered'] is False
    assert diagonal['additive_candidate'] == ['east', 'north']
    assert diagonal['additive_residual_l2'] == 0
    assert out['embedding_service_contacted'] is False
    assert store.stable_json({'b': 2, 'a': 1}) == '{"a": 1, "b": 2}'


@pytest.mark.parametrize('entry', [store.validate_vector_store, store.vector_poison_report,
                                 lambda raw: store.audit_saved_ranking([1, 0], [], raw),
                                 lambda raw: store.embedding_exposure_report(raw, {'unit': [1, 0]})])
def test_malformed_structures_and_byte_mutations(entry):
    rng = random.Random(0x56454354)
    samples = [None, [], {}, b'', b'\xff'*32, b'\0'*32, 'bad', 5, [None],
               [{'vector': [math.nan]}], [{'vector': [math.inf]}], [{'vector': [10**500]}]]
    encoded = json.dumps(DOCS).encode()
    samples.extend(encoded[:n] for n in range(0, len(encoded), 7))
    for _ in range(16):
        changed = bytearray(encoded)
        changed[rng.randrange(len(encoded))] ^= 1 << rng.randrange(8)
        samples.append(bytes(changed))
    for sample in samples:
        try:
            entry(sample)
        except ValueError as error:
            assert type(error) is ValueError


@pytest.mark.parametrize('kwargs', [{'near_similarity': None}, {'lexical_ceiling': 'bad'}])
def test_poison_invalid_thresholds_only_declared_error(kwargs):
    try:
        store.vector_poison_report(DOCS, **kwargs)
    except ValueError as error:
        assert type(error) is ValueError


def test_ranking_tolerance_overflow_only_declared_error():
    try:
        store.audit_saved_ranking([1, 0], [], DOCS, score_tolerance=10**500)
    except ValueError as error:
        assert type(error) is ValueError


def test_small_caps_and_deep_container(monkeypatch):
    monkeypatch.setattr(store, 'MAX_COMPARISONS', 1)
    out = store.vector_poison_report(DOCS)
    assert out['pair_comparisons_capped'] is True
    assert out['pair_comparisons'] == 1
    assert out['hub_occurrences'] == {}
    with pytest.raises(ValueError):
        store.embedding_exposure_report({'x': [1, 0]}, {'a': [1, 0], 'b': [0, 1]})
    monkeypatch.setattr(store, 'MAX_DOCUMENTS', 2)
    with pytest.raises(ValueError):
        store.validate_vector_store(DOCS)
    nested = {'documents': []}
    for _ in range(100):
        nested = {'nested': nested}
    assert store.validate_vector_store(nested)['document_count'] == 0


def test_no_network_or_unpickling(monkeypatch):
    import pickle
    import socket
    def forbidden(*args, **kwargs):
        pytest.fail('Vector evidence analysis attempted execution or retrieval')
    monkeypatch.setattr(pickle, 'loads', forbidden)
    monkeypatch.setattr(pickle, 'load', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    assert store.validate_vector_store(DOCS)['network_used'] is False
    assert store.audit_saved_ranking([1, 0], [], DOCS)['retrieval_contacted'] is False
