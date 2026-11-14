"""B-027: schema/DER-tolerant ECDSA (r,s,z) readers + related-nonce recovery.

Every fixture is built synthetically inside the test (real signatures over a chosen private scalar);
no real challenge file is committed. Recovery is self-verified (d*G == Q), so each test asserts the
recovered scalar equals the one the fixture signed with, and the negative tests assert None.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "solvers" / "common"))

import ecc_faults as ef                       # noqa: E402
import ecdsa_recovery as er                   # noqa: E402

K1 = ef.SECP256K1
R1 = ef.SECP256R1


def _pub(d, curve):
    return ef.ec_mul(d, None, curve)


def _sign(d, message, *, curve, k, low_s=False):
    return er.ecdsa_sign(d, message, curve=curve, k=k, low_s=low_s)


# --------------------------------------------------------------------------- JSON reader


def _json_export(d, curve, messages, nonces):
    pub = _pub(d, curve)
    records = []
    for i, (msg, k) in enumerate(zip(messages, nonces)):
        r, s = _sign(d, msg, curve=curve, k=k)
        rs = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        records.append({"record_id": f"R-{i}", "message_b64": base64.b64encode(msg).decode(),
                        "signature_rs_hex": rs.hex()})
    return {"public_key": {"x": f"{pub[0]:064x}", "y": f"{pub[1]:064x}"},
            "signature_format": {"curve": curve.name, "hash": "SHA-256",
                                 "signature": "r||s"}, "records": records}


def test_json_reader_splits_rs_and_decodes_message():
    d = 0x1234567890ABCDEF1234567890ABCDEF
    obj = _json_export(d, K1, [b"alpha order", b"bravo order"], [111111, 222222])
    records, point = er.read_json_records(obj)
    assert point == _pub(d, K1)
    assert len(records) == 2
    # z must be H(message) mod n, verifiable against the public key.
    for rec in records:
        assert ef.ecdsa_verify(rec.rsz, point, K1)
        assert rec.z == er.hash_z(rec.message, K1)


def test_repeated_nonce_recovery_from_json_export():
    d = 0x0FEEDFACECAFEBEEF00DDEADBEEF1234
    # Two records share the nonce (the rollback/repeated-r fault).
    obj = _json_export(d, K1, [b"dispatch 0", b"dispatch 1"], [999999, 999999])
    records, point = er.read_json_records(obj)
    rec = er.recover(records, point, curve="secp256k1")
    assert rec is not None and rec.method == "reused-nonce"
    assert rec.private == d


def test_repeated_nonce_needs_two_distinct_messages_same_r():
    d = 0x55
    # Distinct nonces -> distinct r -> no reuse; nothing recovered by the reused path alone.
    obj = _json_export(d, K1, [b"a", b"b"], [12345, 67890])
    records, point = er.read_json_records(obj)
    assert er.recover_reused_nonce(records, point, "secp256k1") is None


# --------------------------------------------------------------------------- DER reader


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, body):
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(value):
    body = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


_OID_SECP256K1 = bytes.fromhex("2b8104000a")       # 1.3.132.0.10
_OID_P256 = bytes.fromhex("2a8648ce3d030107")      # 1.2.840.10045.3.1.7


def _spki(point, curve_oid=_OID_SECP256K1):
    bit = b"\x00" + b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    alg = _tlv(0x30, _tlv(0x06, bytes.fromhex("2a8648ce3d0201")) + _tlv(0x06, curve_oid))
    return _tlv(0x30, alg + _tlv(0x03, bit))


def _signed_order_bundle(d, curve, messages, nonces, curve_oid=_OID_SECP256K1):
    pub = _pub(d, curve)
    orders = b""
    for i, (msg, k) in enumerate(zip(messages, nonces)):
        r, s = _sign(d, msg, curve=curve, k=k)
        sig = _tlv(0x30, _der_int(r) + _der_int(s))
        orders += _tlv(0x30, _der_int(i) + _tlv(0x04, msg) + sig)
    bundle = _der_int(1) + _spki(pub, curve_oid) + _tlv(0x30, orders)
    return _tlv(0x30, bundle), pub


def test_der_reader_extracts_point_and_records():
    d = 0x2A2A2A2A
    der, pub = _signed_order_bundle(d, K1, [b"ord0", b"ord1"], [7, 9])
    records, point = er.read_der_records(der)
    assert point == pub
    assert len(records) == 2
    assert [rec.index for rec in records] == [0, 1]
    for rec in records:
        assert ef.ecdsa_verify(rec.rsz, point, K1)


def test_parse_der_rejects_truncated_length():
    with pytest.raises(er.EcdsaReadError):
        er.parse_der(bytes([0x30, 0x82, 0x01]))     # length claims 2 bytes but buffer ends


# --------------------------------------------------------------------------- linear-nonce recovery


def _linear_records(d, curve, count, k0, stride, degree_build=1):
    """Sign `count` messages with k_i = k0 + stride*i (+ i^2 term when degree_build==2)."""
    recs = []
    for i in range(count):
        if degree_build == 1:
            k = (k0 + stride * i) % curve.n
        else:
            k = (k0 + stride * i + 3 * i * i) % curve.n
        msg = f"order {i}".encode()
        r, s = _sign(d, msg, curve=curve, k=k)
        recs.append(er.SigRecord(r=r, s=s, z=er.hash_z(msg, curve), index=i))
    return recs


def test_linear_nonce_recovery_arithmetic_progression():
    d = 0x79C7842BF8177446
    pub = _pub(d, K1)
    recs = _linear_records(d, K1, 6, k0=0xBEEF, stride=0x1234, degree_build=1)
    out = er.recover_ecdsa_linear_nonce(recs, pub, degree=1, curve="secp256k1")
    assert out == d


def test_linear_nonce_recovery_via_dispatch_on_der():
    d = 0x5151515151
    pub = _pub(d, K1)
    orders, nonces = [], []
    k0, stride = 0xAAAA, 0x55
    for i in range(6):
        nonces.append((k0 + stride * i) % K1.n)
        orders.append(f"dispatch {i}".encode())
    der, _ = _signed_order_bundle(d, K1, orders, nonces)
    records, point = er.read_der_records(der)
    rec = er.recover(records, point, curve="secp256k1")
    assert rec is not None and rec.method.startswith("linear-nonce")
    assert rec.private == d


def test_linear_degree1_declines_quadratic_nonce():
    # A degree-2 nonce relation is not recoverable as degree 1: must decline, never return a wrong d.
    d = 0x33
    pub = _pub(d, K1)
    recs = _linear_records(d, K1, 4, k0=0x10, stride=0x7, degree_build=2)
    assert er.recover_ecdsa_linear_nonce(recs, pub, degree=1, curve="secp256k1") is None
    # ...but degree 2 recovers it.
    recs2 = _linear_records(d, K1, 5, k0=0x10, stride=0x7, degree_build=2)
    assert er.recover_ecdsa_linear_nonce(recs2, pub, degree=2, curve="secp256k1") == d


def test_linear_needs_enough_records():
    d = 0x44
    pub = _pub(d, K1)
    recs = _linear_records(d, K1, 2, k0=0x1, stride=0x1)      # degree1 needs 3
    assert er.recover_ecdsa_linear_nonce(recs, pub, degree=1, curve="secp256k1") is None


@pytest.mark.parametrize("degree", [1, 2])
def test_linear_recovers_from_exactly_the_minimum_record_count(degree):
    # degree+2 unknowns (c0..c_degree, d): exactly degree+2 signatures must suffice (3 for an AP nonce,
    # 4 for a quadratic one); one fewer must decline. Kills an off-by-one in the minimum-records check.
    d = 0x5EED + degree
    pub = _pub(d, K1)
    exact = _linear_records(d, K1, degree + 2, k0=0x4321, stride=0x11, degree_build=degree)
    assert er.recover_ecdsa_linear_nonce(exact, pub, degree=degree, curve="secp256k1") == d
    short = exact[:-1]
    assert er.recover_ecdsa_linear_nonce(short, pub, degree=degree, curve="secp256k1") is None


def test_recover_dispatch_uses_exactly_three_ap_records():
    d = 0xA11CE
    pub = _pub(d, K1)
    recs = _linear_records(d, K1, 3, k0=0x777, stride=0x5)
    rec = er.recover(recs, pub, curve="secp256k1")
    assert rec is not None and rec.method == "linear-nonce-degree-1" and rec.private == d


def test_linear_rejects_wrong_public_key():
    d = 0x61
    recs = _linear_records(d, K1, 6, k0=0x9, stride=0x3)
    wrong = _pub(d + 1, K1)
    assert er.recover_ecdsa_linear_nonce(recs, wrong, degree=1, curve="secp256k1") is None


def test_linear_rejects_tampered_z():
    d = 0x62
    pub = _pub(d, K1)
    recs = _linear_records(d, K1, 6, k0=0x9, stride=0x3)
    bad = [recs[0]] + [er.SigRecord(r=r.r, s=r.s, z=(r.z ^ 1), index=r.index) for r in recs[1:]]
    assert er.recover_ecdsa_linear_nonce(bad, pub, degree=1, curve="secp256k1") is None


def test_linear_nonce_uniform_high_s_needs_the_flip():
    # Every signature stored as the high-S alternative (s' = n - s_raw). Recovery must try the uniform
    # sign flip; the raw-s solve alone does not verify, so this fails if the flip branch is dropped.
    d = 0x71
    pub = _pub(d, K1)
    raw = _linear_records(d, K1, 6, k0=0x1234, stride=0x9)
    flipped = [er.SigRecord(r=rec.r, s=(K1.n - rec.s) % K1.n, z=rec.z, index=rec.index) for rec in raw]
    assert all(ef.ecdsa_verify(rec.rsz, pub, K1) for rec in flipped)
    assert er.recover_ecdsa_linear_nonce(flipped, pub, degree=1, curve="secp256k1") == d


def test_linear_nonce_on_p256():
    d = 0x1ABC
    pub = _pub(d, R1)
    recs = _linear_records(d, R1, 5, k0=0x1000, stride=0x77)
    assert er.recover_ecdsa_linear_nonce(recs, pub, degree=1, curve="secp256r1") == d


# --------------------------------------------------------------------------- known nonce / nonce delta


def _records(d, curve, nonces, indices=None):
    out = []
    for pos, k in enumerate(nonces):
        msg = f"leak {pos}".encode()
        r, s = _sign(d, msg, curve=curve, k=k)
        idx = indices[pos] if indices is not None else pos
        out.append(er.SigRecord(r=r, s=s, z=er.hash_z(msg, curve), index=idx))
    return out


def test_known_nonce_recovers_from_a_single_signature():
    # One signature: neither reused nor linear can work; only the supplied leaked nonce does.
    d = 0xC0FFEE
    pub = _pub(d, R1)
    recs = _records(d, R1, [0x13371337])
    assert er.recover(recs, pub, curve="secp256r1") is None
    rec = er.recover(recs, pub, curve="secp256r1", known_nonce=0x13371337)
    assert rec is not None and rec.method == "known-nonce" and rec.private == d


def test_known_nonce_wrong_value_declines():
    d = 0xC0FFEE
    pub = _pub(d, R1)
    recs = _records(d, R1, [0x13371337])
    assert er.recover_known_nonce(recs, 0x13371338, pub, "secp256r1") is None


def test_known_nonce_requires_every_record_to_verify():
    d = 0xBADC0DE
    pub = _pub(d, K1)
    good = _records(d, K1, [0x2468, 0x9999])
    tampered = [good[0], er.SigRecord(r=good[1].r, s=good[1].s, z=good[1].z ^ 1, index=1)]
    assert er.recover_known_nonce(good, 0x2468, pub, "secp256k1") == d
    assert er.recover_known_nonce(tampered, 0x2468, pub, "secp256k1") is None


def test_nonce_delta_recovers_from_two_signatures():
    # Two signatures with k2 = k1 + delta: the linear solve needs three, so only the delta path works.
    d = 0xD1E7A
    pub = _pub(d, K1)
    recs = _records(d, K1, [0x1000, 0x1000 + 0x42])
    assert er.recover(recs, pub, curve="secp256k1") is None
    rec = er.recover(recs, pub, curve="secp256k1", nonce_delta=0x42)
    assert rec is not None and rec.method == "nonce-delta" and rec.private == d
    assert er.recover_nonce_delta(recs, 0x43, pub, "secp256k1") is None


def test_nonce_delta_scales_with_index_gap():
    # Records at index 0 and 3 of a k_i = k0 + i*delta stream: the pair's nonce gap is 3*delta.
    d = 0xD1E7B
    pub = _pub(d, K1)
    delta = 0x99
    recs = _records(d, K1, [0x5000, 0x5000 + 3 * delta], indices=[0, 3])
    assert er.recover_nonce_delta(recs, delta, pub, "secp256k1") == d


def test_nonce_delta_sorts_records_by_index_before_pairing():
    # Records stored out of index order (seq 1 before seq 0): unsorted pairing would see a negative
    # step, skip the only pair and return None. Sorting by index must recover d.
    d = 0xD1E7D
    pub = _pub(d, K1)
    delta = 0x31
    recs = _records(d, K1, [0x6000, 0x6000 + delta])
    assert er.recover_nonce_delta(list(reversed(recs)), delta, pub, "secp256k1") == d
    shuffled = _records(d, K1, [0x6000 + 2 * delta, 0x6000, 0x6000 + delta], indices=[2, 0, 1])
    assert er.recover_nonce_delta(shuffled, delta, pub, "secp256k1") == d


def test_nonce_delta_requires_every_record_to_verify():
    d = 0xD1E7C
    pub = _pub(d, K1)
    recs = _records(d, K1, [0x7000, 0x7000 + 5, 0x123456])
    bad = recs[:2] + [er.SigRecord(r=recs[2].r, s=recs[2].s, z=recs[2].z ^ 1, index=2)]
    assert er.recover_nonce_delta(recs, 5, pub, "secp256k1") == d
    assert er.recover_nonce_delta(bad, 5, pub, "secp256k1") is None


# --------------------------------------------------------------------------- curve declarations


def test_json_declared_curve_names():
    assert er.json_declared_curve({"signature_format": {"curve": "P-256"}}) == "secp256r1"
    assert er.json_declared_curve({"signature_format": {"curve": "secp256k1"}}) == "secp256k1"
    assert er.json_declared_curve({"signature_format": {"curve": "ed25519"}}) is None
    assert er.json_declared_curve({"records": []}) is None


def test_der_declared_curve_from_spki_oid():
    k1_der, _ = _signed_order_bundle(0x21, K1, [b"a"], [5])
    r1_der, _ = _signed_order_bundle(0x21, R1, [b"a"], [5], curve_oid=_OID_P256)
    assert er.der_declared_curve(er.parse_der(k1_der)) == "secp256k1"
    assert er.der_declared_curve(er.parse_der(r1_der)) == "secp256r1"
    no_oid = _tlv(0x30, _tlv(0x30, _der_int(1) + _tlv(0x04, b"m") + _tlv(0x30, _der_int(3) + _der_int(4))))
    assert er.der_declared_curve(er.parse_der(no_oid)) is None


# --------------------------------------------------------------------------- canonical log messages


SP00KY_LOG_LAYOUT = (
    ("const", b"SP00KY-LOG-v1"),
    ("uint", "ts", 8),
    ("lenpstr", "user", 1),
    ("lenpstr", "event", 2),
)


def test_build_canonical_message_exact_bytes():
    rec = {"ts": 0x0102030405060708, "user": "admin", "event": "LOGIN"}
    msg = er.build_canonical_message(rec, SP00KY_LOG_LAYOUT)
    expected = (b"SP00KY-LOG-v1" + (0x0102030405060708).to_bytes(8, "big")
                + bytes([5]) + b"admin" + (5).to_bytes(2, "big") + b"LOGIN")
    assert msg == expected


def test_read_log_records_then_repeated_nonce_recovery():
    d = 0x4242424242
    pub = _pub(d, R1)
    base = []
    for i, (ts, user, ev) in enumerate([(1000, "admin", "A"), (2000, "general", "B"),
                                        (3000, "admin", "C")]):
        rec = {"ts": ts, "user": user, "event": ev}
        msg = er.build_canonical_message(rec, SP00KY_LOG_LAYOUT)
        # Two admin records reuse the nonce; the general record uses a different one.
        k = 0xDEAD if user == "admin" else 0xBEEF
        r, s = _sign(d, msg, curve=R1, k=k)
        rec.update(r=r, s=s)
        base.append(rec)
    records = er.read_log_records(base, SP00KY_LOG_LAYOUT, curve="secp256r1")
    assert len(records) == 3
    rec = er.recover(records, pub, curve="secp256r1")
    assert rec is not None and rec.method == "reused-nonce" and rec.private == d


# --------------------------------------------------------------------------- signing


def test_ecdsa_sign_verifies_and_is_deterministic():
    d = 0x9988
    msg = b"authorize me"
    sig1 = er.ecdsa_sign(d, msg, curve="secp256r1")
    sig2 = er.ecdsa_sign(d, msg, curve="secp256r1")
    assert sig1 == sig2                                  # RFC 6979 deterministic
    assert ef.ecdsa_verify((sig1[0], sig1[1], er.hash_z(msg, R1)), _pub(d, R1), R1)


def test_ecdsa_sign_low_s_is_canonical():
    d = 0x7
    r, s = er.ecdsa_sign(d, b"x", curve="secp256k1", low_s=True)
    assert s <= K1.n // 2


# --------------------------------------------------------------------------- solve() entry


def _write_challenge(tmp_path, obj):
    files = tmp_path / "files"
    files.mkdir()
    (files / "signing-export.json").write_text(json.dumps(obj))
    return tmp_path


def _profile():
    from ctf import event
    return event.load("csctf")


def test_solve_recovers_scalar_and_offers_candidate_flag(tmp_path):
    d = 0x3B5789E468DADF358D375BB08DCD19B977C5715364A709326B43A35B0D5EAAB1
    obj = _json_export(d, K1, [b"dispatch zero", b"dispatch one"], [0x5151, 0x5151])
    cdir = _write_challenge(tmp_path, obj)
    res = er.solve(cdir, _profile())
    assert res.status == "candidate"
    assert f"{d:064x}" in res.notes
    assert any(f"{d:064x}" in flag for flag in res.flags)


def test_solve_none_without_artifacts(tmp_path):
    (tmp_path / "files").mkdir()
    res = er.solve(tmp_path, _profile())
    assert res.status == "none" and not res.flags


def test_solve_none_when_no_recovery_verifies(tmp_path):
    # Distinct nonces, no linear relation that holds: read records but recover nothing.
    d = 0x12
    obj = _json_export(d, K1, [b"m0", b"m1"], [3, 50000])
    cdir = _write_challenge(tmp_path, obj)
    res = er.solve(cdir, _profile())
    assert res.status == "none" and not res.flags


def test_solve_honors_declared_p256_curve_on_first_attempt(tmp_path):
    # A secp256r1-declared export must be recovered on the declared curve directly, not via the
    # wrong-curve fallback re-read.
    d = 0x2F00D
    obj = _json_export(d, R1, [b"p256 a", b"p256 b"], [0x6161, 0x6161])
    cdir = _write_challenge(tmp_path, obj)
    loaded = er._load_artifacts(cdir)
    assert [art[3] for art in loaded] == ["secp256r1"]
    res = er.solve(cdir, _profile())
    assert res.status == "candidate" and f"{d:064x}" in res.notes
    assert "secp256r1" in res.notes
    assert "curve source: declared by the artifact" in res.notes


def test_solve_honors_der_oid_p256(tmp_path):
    d = 0x2F00E
    der, _ = _signed_order_bundle(d, R1, [b"o0", b"o1"], [0x7171, 0x7171], curve_oid=_OID_P256)
    files = tmp_path / "files"
    files.mkdir()
    (files / "orders.der").write_bytes(der)
    res = er.solve(tmp_path, _profile())
    assert res.status == "candidate" and f"{d:064x}" in res.notes
    assert "curve source: declared by the artifact" in res.notes


def test_solve_falls_back_when_declared_curve_is_wrong(tmp_path):
    # Declares secp256k1 but the signatures are P-256: the declared attempt fails d*G, the other curve
    # recovers, and the notes say it was a fallback.
    d = 0x2F00F
    obj = _json_export(d, R1, [b"x0", b"x1"], [0x8181, 0x8181])
    obj["signature_format"]["curve"] = "secp256k1"
    cdir = _write_challenge(tmp_path, obj)
    res = er.solve(cdir, _profile())
    assert res.status == "candidate" and f"{d:064x}" in res.notes
    assert "curve source: fallback after secp256k1 failed" in res.notes


def test_solve_curve_option_overrides_and_does_not_fall_back(tmp_path):
    d = 0x2F010
    obj = _json_export(d, R1, [b"y0", b"y1"], [0x9191, 0x9191])
    cdir = _write_challenge(tmp_path, obj)
    ok = er.solve(cdir, _profile(), curve="p-256")
    assert ok.status == "candidate" and "curve source: option" in ok.notes
    wrong = er.solve(cdir, _profile(), curve="secp256k1")
    assert wrong.status == "none" and not wrong.flags


def _raw_z_sig(d, z, k, curve):
    r = ef.ec_mul(k, None, curve)[0] % curve.n
    s = (pow(k, -1, curve.n) * (z + r * d)) % curve.n
    return r, s


def test_solve_rereads_raw_z_under_the_option_curve(tmp_path):
    # Declared P-256, but the signatures are secp256k1 over raw z values in [n_P256, n_secp256k1).
    # The first read reduces z mod n_P256 (wrong); solve must re-read under the option curve so z is
    # kept modulo n_secp256k1, else the reused-nonce solve yields a d that fails d*G.
    assert R1.n < K1.n
    d = 0x5EED0F
    k = 0xABCDEF0123
    zs = [R1.n + 0x1111, R1.n + 0x2222]
    assert all(R1.n <= z < K1.n for z in zs)
    pub = _pub(d, K1)
    records = []
    for i, z in enumerate(zs):
        r, s = _raw_z_sig(d, z, k, K1)
        assert r < R1.n and s < R1.n  # readable under the declared curve too
        records.append({"record_id": f"Z-{i}", "r": r, "s": s, "z": z})
    obj = {"public_key": {"x": f"{pub[0]:064x}", "y": f"{pub[1]:064x}"},
           "signature_format": {"curve": "secp256r1", "hash": "SHA-256"}, "records": records}
    cdir = _write_challenge(tmp_path, obj)
    loaded = er._load_artifacts(cdir)
    assert [art[3] for art in loaded] == ["secp256r1"]
    assert [rec.z for rec in loaded[0][1]] == [z % R1.n for z in zs]
    res = er.solve(cdir, _profile(), curve="secp256k1")
    assert res.status == "candidate" and f"{d:064x}" in res.notes
    assert "curve source: option" in res.notes


def test_solve_blocks_on_unknown_curve_or_bad_nonce_option(tmp_path):
    obj = _json_export(0x5, K1, [b"z"], [0x77])
    cdir = _write_challenge(tmp_path, obj)
    bad_curve = er.solve(cdir, _profile(), curve="curve25519")
    assert bad_curve.status == "blocked" and "curve25519" in bad_curve.notes
    bad_nonce = er.solve(cdir, _profile(), known_nonce="not-a-number")
    assert bad_nonce.status == "blocked" and "known_nonce" in bad_nonce.notes


def test_solve_known_nonce_option_on_single_signature(tmp_path):
    d = 0x3141592653589793
    k = 0x2718281828
    obj = _json_export(d, K1, [b"only one"], [k])
    cdir = _write_challenge(tmp_path, obj)
    assert er.solve(cdir, _profile()).status == "none"
    res = er.solve(cdir, _profile(), known_nonce=f"0x{k:x}")
    assert res.status == "candidate" and "known-nonce" in res.notes and f"{d:064x}" in res.notes


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
