"""Tests for the weak-EC-key PKI toolkit (B-128): small-scalar search, PKI anomaly triage, proof sig.

All fixtures are built synthetically inside the test: self-signed certs / CSRs with a chosen private
scalar, and invented ceremony logs / inventories (made-up timestamps, object ids, certificate names
and handler names, in two different vocabularies). No challenge file is read. The proof client is
driven through an in-process fake transport and through a fake HTTP server the test starts on
127.0.0.1; nothing else is contacted. Each test fails when the behaviour under test is wrong.
"""
from __future__ import annotations

import base64
import datetime
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography import x509                    # pinned in requirements.in
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# conftest puts solvers/common and solvers/toolkits on sys.path.
import pki_weakkey as pk                         # noqa: E402
from ecc_faults import SECP256R1, ecdsa_verify   # noqa: E402
from ecdsa_recovery import hash_z                # noqa: E402
from ctf import scope                            # noqa: E402

# A healthy intermediate's scalar: a full-width P-384 private key (not findable by a small search).
HEALTHY = 0x4F2C9A1B8D3E6705C1A2B3C4D5E6F708192A3B4C5D6E7F8091A2B3C4D5E6F7081
WEAK = 2741  # an invented tiny scalar


def _point(scalar: int, curve=None) -> tuple[int, int]:
    nums = ec.derive_private_key(scalar, curve or ec.SECP384R1()).public_key().public_numbers()
    return nums.x, nums.y


def _self_signed(scalar: int, cn: str, curve=None) -> bytes:
    curve = curve or ec.SECP384R1()
    key = ec.derive_private_key(scalar, curve)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(scalar % (1 << 159) or 1)
            .not_valid_before(datetime.datetime(2030, 1, 1))
            .not_valid_after(datetime.datetime(2031, 1, 1))
            .sign(key, hashes.SHA384()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _csr(scalar: int, cn: str) -> bytes:
    key = ec.derive_private_key(scalar, ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    req = (x509.CertificateSigningRequestBuilder()
           .subject_name(name)
           .sign(key, hashes.SHA384()))
    return req.public_bytes(serialization.Encoding.PEM)


# Invented ceremony: K-11 is generated and used directly; K-17 is generated, wrapped, then brought
# back as K-17b through a legacy-import handler, and K-17b backs certificate relay-ca-2.
CEREMONY = (
    "2031-02-09T11:05:01Z KEY   GENERATE object=K-11 curve=P-384 status=OK\n"
    "2031-02-09T11:05:09Z CSR   CREATE   object=K-11 certificate=relay-ca-1 status=OK\n"
    "2031-02-09T11:06:12Z KEY   GENERATE object=K-17 curve=P-384 status=OK\n"
    "2031-02-09T11:06:20Z HSM   WRAP     object=K-17 mechanism=CHACHA-KW status=OK\n"
    "2031-02-09T11:06:31Z HSM   UNWRAP   source=K-17 object=K-17b handler=legacy-import status=OK\n"
    "2031-02-09T11:06:40Z CSR   CREATE   object=K-17b certificate=relay-ca-2 status=OK\n"
)
INVENTORY = (
    "certificate,csr_object,csr_status,algorithm,validation\n"
    "relay-ca-1.pem,K-11,SIGNED,ECDSA-P384,PASS\n"
    "relay-ca-2.pem,K-17b,SIGNED,ECDSA-P384,PASS\n"
)


def _challenge_dir(tmp_path: Path, weak_scalar: int = WEAK) -> Path:
    files = tmp_path / "files"
    files.mkdir()
    (files / "relay-ca-1.pem").write_bytes(_self_signed(HEALTHY, "relay-healthy"))
    (files / "relay-ca-2.pem").write_bytes(_self_signed(weak_scalar, "relay-weak"))
    (files / "ceremony.log").write_text(CEREMONY)
    (files / "key-inventory.csv").write_text(INVENTORY)
    return tmp_path


def _sig_verifies(sig_b64: str, message: bytes, scalar: int, curve=pk.P384, ec_curve=None,
                  hash_name: str = "sha384") -> bool:
    r, s = decode_dss_signature(base64.b64decode(sig_b64))
    return ecdsa_verify((r, s, hash_z(message, curve, hash_name)), _point(scalar, ec_curve), curve=curve)


# --------------------------------------------------------------------------- small-scalar search


def test_small_scalar_recovers_tiny_p384_key():
    for scalar in (1, 7, 2741, 40961):
        got = pk.small_scalar(_point(scalar), bound=1 << 17, deadline=time.monotonic() + 60)
        assert got == scalar


def test_small_scalar_returns_none_above_bound_never_wrong():
    # A scalar beyond the search window must yield None, not a bogus value (never-wrong contract).
    assert pk.small_scalar(_point(500_000), bound=1 << 12, deadline=time.monotonic() + 60) is None


def test_small_scalar_rejects_point_not_on_curve():
    x, y = _point(5)
    assert pk.small_scalar((x, (y + 1) % pk.P384.p), bound=1 << 10) is None


def test_small_scalar_never_wrong_gate_drops_a_bad_dlog(monkeypatch):
    point = _point(WEAK)
    # The patch reaches small_scalar: a dlog that returns the true scalar is passed through ...
    monkeypatch.setattr(pk, "_bsgs", lambda *a, **k: WEAK)
    assert pk.small_scalar(point, bound=1 << 14) == WEAK
    # ... and one that returns a wrong scalar is dropped by the [d]G == Q gate.
    monkeypatch.setattr(pk, "_bsgs", lambda *a, **k: WEAK + 1)
    assert pk.small_scalar(point, bound=1 << 14) is None


def test_small_scalar_search_dedups_repeated_points_and_lists_every_path():
    point = _point(WEAK)
    a = pk.CertInfo("a.pem", "certificate", "CN=a", "secp384r1", point)
    b = pk.CertInfo("b.pem", "certificate", "CN=b", "secp384r1", point)
    recs = pk.small_scalar_search([a, b], bound=1 << 14, deadline=time.monotonic() + 60)
    assert len(recs) == 1
    assert recs[0].scalar == WEAK
    assert recs[0].paths == ("a.pem", "b.pem")


def test_search_uses_each_certificates_own_curve():
    p256 = pk.CertInfo("p256.pem", "certificate", "CN=p", "secp256r1", _point(7, ec.SECP256R1()))
    k1 = pk.CertInfo("k1.pem", "certificate", "CN=k", "secp256k1", _point(11, ec.SECP256K1()))
    p384 = pk.CertInfo("p384.pem", "certificate", "CN=q", "secp384r1", _point(13))
    rep = pk.search_certs([p256, k1, p384], bound=1 << 10, deadline=time.monotonic() + 60)
    assert {(r.cert.path, r.scalar) for r in rep.recoveries} == {
        ("p256.pem", 7), ("k1.pem", 11), ("p384.pem", 13)}
    assert rep.searched == 3 and rep.skipped == {} and rep.unfinished == 0


def test_search_names_points_on_a_curve_without_params():
    p521 = pk.CertInfo("p521.pem", "certificate", "CN=x", "secp521r1", _point(3, ec.SECP521R1()))
    rep = pk.search_certs([p521], bound=1 << 10, deadline=time.monotonic() + 60)
    assert rep.recoveries == () and rep.searched == 0
    assert rep.skipped == {"secp521r1": 1}


def test_search_explicit_curve_skips_points_on_other_curves():
    p256 = pk.CertInfo("p256.pem", "certificate", "CN=p", "secp256r1", _point(7, ec.SECP256R1()))
    p384 = pk.CertInfo("p384.pem", "certificate", "CN=q", "secp384r1", _point(13))
    rep = pk.search_certs([p256, p384], curve=pk.P384, bound=1 << 10, deadline=time.monotonic() + 60)
    assert [r.scalar for r in rep.recoveries] == [13]
    assert rep.skipped == {"secp256r1": 1}


def test_search_counts_points_cut_off_by_the_budget():
    # A deadline already in the past: nothing is searched, and that is reported, not "found none".
    info = pk.CertInfo("a.pem", "certificate", "CN=a", "secp384r1", _point(WEAK))
    rep = pk.search_certs([info], bound=1 << 14, deadline=time.monotonic() - 1)
    assert rep.recoveries == () and rep.searched == 0 and rep.unfinished == 1


def test_search_counts_a_point_the_deadline_cut_mid_search_as_unfinished(monkeypatch):
    # The deadline is still ahead when the point's search starts and passes during it (an injected
    # step clock, no wall time): _bsgs then gives up with None, and that point is unfinished, not
    # "searched and found none".
    now = [0.0]
    calls = []

    def bsgs_that_runs_out(*args, **kwargs):
        calls.append(args)
        now[0] = 100.0
        return None

    monkeypatch.setattr(pk, "_bsgs", bsgs_that_runs_out)
    info = pk.CertInfo("a.pem", "certificate", "CN=a", "secp384r1", _point(WEAK))
    rep = pk.search_certs([info], bound=1 << 14, deadline=50.0, clock=lambda: now[0])
    assert len(calls) == 1                    # the search really started (not the pre-check)
    assert rep.recoveries == () and rep.unfinished == 1 and rep.searched == 0


def test_search_counts_a_point_whose_window_was_covered_as_searched(monkeypatch):
    # The same None from _bsgs with the deadline still ahead means the window held no scalar.
    monkeypatch.setattr(pk, "_bsgs", lambda *a, **k: None)
    info = pk.CertInfo("a.pem", "certificate", "CN=a", "secp384r1", _point(WEAK))
    rep = pk.search_certs([info], bound=1 << 14, deadline=50.0, clock=lambda: 0.0)
    assert rep.recoveries == () and rep.searched == 1 and rep.unfinished == 0


def test_bound_beyond_the_bsgs_window_is_refused_not_reported_as_searched(tmp_path):
    # ecc_weak._bsgs declines a window wider than BSGS_LIMIT_EC**2 (2**38); that decline must not be
    # counted as "searched, found none". d=5 is tiny, so a silent decline would be a false negative.
    assert pk.max_scalar_bound() == pk.BSGS_LIMIT_EC ** 2 == 1 << 38
    info = pk.CertInfo("a.pem", "certificate", "CN=a", "secp384r1", _point(5))
    with pytest.raises(pk.WeakKeyError, match="exceeds the baby-step/giant-step window"):
        pk.search_certs([info], bound=1 << 40, deadline=time.monotonic() + 60)
    with pytest.raises(pk.WeakKeyError, match="exceeds the baby-step/giant-step window"):
        pk.small_scalar(_point(5), bound=1 << 40, deadline=time.monotonic() + 60)
    files = tmp_path / "files"
    files.mkdir()
    (files / "weak.pem").write_bytes(_self_signed(5, "weak"))
    res = pk.solve(tmp_path, _profile(), bound=1 << 40, budget=60)
    assert res.status == "blocked"
    assert res.notes.startswith("option bound refused:") and str(1 << 38) in res.notes
    assert "searched 1" not in res.notes and "found none" not in res.notes


def test_bound_window_edge_follows_the_bsgs_limit(monkeypatch):
    # Shrink the BSGS limit to 64 baby steps so the edge is cheap to hit for real: 64**2 is the
    # widest window _bsgs still covers (d=4000 is found), one more is refused before searching.
    monkeypatch.setattr(pk, "BSGS_LIMIT_EC", 64)
    assert pk.max_scalar_bound() == 4096
    assert pk.small_scalar(_point(4000), bound=4096, deadline=time.monotonic() + 600) == 4000
    with pytest.raises(pk.WeakKeyError):
        pk.small_scalar(_point(4000), bound=4097, deadline=time.monotonic() + 600)
    info = pk.CertInfo("a.pem", "certificate", "CN=a", "secp384r1", _point(4000))
    with pytest.raises(pk.WeakKeyError):
        pk.search_certs([info], bound=4097, deadline=time.monotonic() + 600)


def test_bound_below_two_is_refused():
    for bad in (1, 0, -5):
        with pytest.raises(pk.WeakKeyError, match="below 2"):
            pk.small_scalar(_point(WEAK), bound=bad)
    with pytest.raises(pk.WeakKeyError, match="integer"):
        pk.search_certs([], bound=True)
    assert pk.check_bound(2) == 2


def test_cli_triage_refuses_a_bound_beyond_the_window(tmp_path, capsys):
    (tmp_path / "weak.pem").write_bytes(_self_signed(5, "weak"))
    assert pk.main(["triage", str(tmp_path), "--bound", str(1 << 40)]) == 2
    assert "exceeds the baby-step/giant-step window" in capsys.readouterr().err


def test_curve_params_resolves_local_and_shared_curves():
    assert pk.curve_params("secp384r1") is pk.P384
    assert pk.curve_params("P-384") is pk.P384
    assert pk.curve_params("prime256v1") == SECP256R1
    assert pk.curve_params("secp521r1") is None


# --------------------------------------------------------------------------- PKI anomaly triage


def test_triage_ranks_restored_legacy_object_first():
    anomalies = pk.triage(pk.parse_ceremony_log(CEREMONY), pk.parse_inventory(INVENTORY))
    assert [a.object_id for a in anomalies] == ["K-17b"]
    top = anomalies[0]
    assert top.severity == pk.SEVERITY_RESTORED + pk.SEVERITY_SUSPECT_HANDLER == 80
    assert top.certificate == "relay-ca-2.pem"
    assert "via handler 'legacy-import' (legacy/compat/restore path)" in top.reasons[0]
    assert "from K-17" in top.reasons[0]


def test_triage_severity_order_over_several_anomalies():
    log = (
        "2031-05-01T09:00:00Z KEY GENERATE object=V-1 status=OK\n"
        "2031-05-01T09:00:01Z CSR CREATE   object=V-1 certificate=leaf-1 status=OK\n"
        # a plain unwrap through a non-suspect handler
        "2031-05-01T09:00:02Z KEY GENERATE object=V-3 status=OK\n"
        "2031-05-01T09:00:03Z HSM UNWRAP   source=V-3 object=V-3w handler=hsm-native status=OK\n"
        "2031-05-01T09:00:04Z CSR CREATE   object=V-3w certificate=leaf-3 status=OK\n"
        # an unwrap through a compat handler
        "2031-05-01T09:00:05Z KEY GENERATE object=V-2 status=OK\n"
        "2031-05-01T09:00:06Z HSM UNWRAP   source=V-2 object=V-2r handler=compat-shim status=OK\n"
        "2031-05-01T09:00:07Z CSR CREATE   object=V-2r certificate=leaf-2 status=OK\n"
        # a rename between generation and CSR, no restore
        "2031-05-01T09:00:08Z KEY GENERATE object=V-4 status=OK\n"
        "2031-05-01T09:00:09Z CSR CREATE   object=V-4-alt certificate=leaf-4 status=OK\n"
        # a CSR object that never appears in GENERATE at all
        "2031-05-01T09:00:10Z CSR CREATE   object=Q-9 certificate=leaf-9 status=OK\n"
    )
    got = [(a.object_id, a.severity) for a in pk.triage(pk.parse_ceremony_log(log), [])]
    assert got == [("V-2r", 80), ("V-3w", 50), ("V-4-alt", 35), ("Q-9", 20)]


def test_triage_flags_rename_without_restore():
    for csr_obj in ("K-41-B", "K-41b", "K-41_alt"):
        log = (
            "2031-03-14T07:00:00Z KEY GENERATE object=K-41 curve=P-384 status=OK\n"
            f"2031-03-14T07:00:01Z CSR CREATE   object={csr_obj} certificate=gw-ca-4 status=OK\n"
        )
        anomalies = pk.triage(pk.parse_ceremony_log(log), [])
        assert [a.object_id for a in anomalies] == [csr_obj]
        assert f"CSR object {csr_obj} is a rename of generated K-41" in anomalies[0].reasons
        assert anomalies[0].severity == pk.SEVERITY_NEVER_GENERATED + pk.SEVERITY_RENAMED


def test_triage_digit_continuation_is_not_a_rename():
    log = (
        "2031-03-14T07:00:00Z KEY GENERATE object=ST-1 status=OK\n"
        "2031-03-14T07:00:01Z CSR CREATE   object=ST-10 certificate=gw-ca-10 status=OK\n"
    )
    anomalies = pk.triage(pk.parse_ceremony_log(log), [])
    assert [(a.object_id, a.severity) for a in anomalies] == [("ST-10", pk.SEVERITY_NEVER_GENERATED)]
    assert not any("rename" in r for r in anomalies[0].reasons)


def test_triage_letter_continuing_a_letter_id_is_not_a_rename():
    # A suffix letter counts as a rename only after a trailing digit (K-17 -> K-17b); hk-a -> hk-ab
    # is a different id that merely shares a prefix.
    log = (
        "1940000000 VAULT  KEYGEN  object=hk-a alg=ec384\n"
        "1940000005 PKCS10 REQUEST object=hk-ab cert=edge-ca-9\n"
    )
    anomalies = pk.triage(pk.parse_ceremony_log(log), [])
    assert [(a.object_id, a.severity) for a in anomalies] == [("hk-ab", pk.SEVERITY_NEVER_GENERATED)]
    assert not any("rename" in r for r in anomalies[0].reasons)


def test_triage_rename_names_the_longest_generated_prefix():
    # Nested generated ids: K-1-A-r is a rename of K-1-A, not of the shorter K-1.
    log = (
        "2031-03-14T07:00:00Z KEY GENERATE object=K-1 status=OK\n"
        "2031-03-14T07:00:01Z KEY GENERATE object=K-1-A status=OK\n"
        "2031-03-14T07:00:02Z CSR CREATE   object=K-1-A-r certificate=gw-ca-1 status=OK\n"
    )
    anomalies = pk.triage(pk.parse_ceremony_log(log), [])
    assert [a.object_id for a in anomalies] == ["K-1-A-r"]
    assert "CSR object K-1-A-r is a rename of generated K-1-A" in anomalies[0].reasons


def test_triage_other_vocabulary_restore_import_rename():
    # A differently spelled HSM log: epoch timestamps, VAULT/PKCS10 facilities, KEYGEN, REQUEST
    # with cert=, IMPORT and RESTORE actions, and an explicit RENAME event.
    log = (
        "1940000000 VAULT  KEYGEN  object=hk-a alg=ec384\n"
        "1940000005 PKCS10 REQUEST object=hk-a cert=edge-ca-1\n"
        "1940000010 VAULT  IMPORT  object=hk-b source=offline-tape handler=legacy-bridge\n"
        "1940000015 PKCS10 REQUEST object=hk-b cert=edge-ca-2\n"
        "1940000020 VAULT  RESTORE object=hk-c source=hk-a\n"
        "1940000025 PKCS10 REQUEST object=hk-c cert=edge-ca-3\n"
        "1940000030 VAULT  RENAME  source=hk-a object=signer-two\n"
        "1940000035 PKCS10 REQUEST object=signer-two cert=edge-ca-4\n"
    )
    anomalies = pk.triage(pk.parse_ceremony_log(log), [])
    assert [(a.object_id, a.certificate, a.severity) for a in anomalies] == [
        ("hk-b", "edge-ca-2", 80), ("hk-c", "edge-ca-3", 50), ("signer-two", "edge-ca-4", 35)]
    assert "CSR object signer-two is a rename of generated hk-a" in anomalies[2].reasons


def test_triage_clean_ceremony_has_no_anomalies():
    log = (
        "2031-03-14T07:00:00Z KEY GENERATE object=K-11 curve=P-384 status=OK\n"
        "2031-03-14T07:00:01Z CSR CREATE   object=K-11 certificate=relay-ca-1 status=OK\n"
    )
    assert pk.triage(pk.parse_ceremony_log(log), []) == []


def test_order_by_triage_puts_flagged_certificates_first():
    certs = [pk.CertInfo(n, "certificate", "CN=" + n, "secp384r1", _point(i + 2))
             for i, n in enumerate(("a.pem", "m.pem", "z.csr.pem"))]
    anomalies = [pk.Anomaly("O-2", "z", ("x",), 80), pk.Anomaly("O-1", "m.pem", ("y",), 20)]
    assert [c.path for c in pk.order_by_triage(certs, anomalies)] == ["z.csr.pem", "m.pem", "a.pem"]


def test_order_by_triage_first_anomaly_of_a_certificate_sets_its_rank():
    # Two anomalies name the same certificate (m.pem and m): its highest-ranked (first) anomaly
    # places it; a later, lower one does not push it behind z.
    certs = [pk.CertInfo(n, "certificate", "CN=" + n, "secp384r1", _point(i + 2))
             for i, n in enumerate(("a.pem", "m.pem", "z.pem"))]
    anomalies = [pk.Anomaly("O-1", "m.pem", ("x",), 80), pk.Anomaly("O-2", "z", ("y",), 50),
                 pk.Anomaly("O-3", "m", ("w",), 20)]
    assert [c.path for c in pk.order_by_triage(certs, anomalies)] == ["m.pem", "z.pem", "a.pem"]


# --------------------------------------------------------------------------- artifact loading


def test_load_public_points_reads_cert_and_csr_skips_non_ec(tmp_path):
    (tmp_path / "cert.pem").write_bytes(_self_signed(WEAK, "relay-weak"))
    (tmp_path / "req.pem").write_bytes(_csr(7, "relay-req"))
    (tmp_path / "noise.txt").write_text("not a certificate")
    infos = pk.load_public_points(tmp_path)
    assert sorted(i.kind for i in infos) == ["certificate", "csr"]
    assert {i.point for i in infos} == {_point(WEAK), _point(7)}


def test_load_public_points_does_not_follow_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "elsewhere.pem").write_bytes(_self_signed(3, "outside-file"))
    handout = tmp_path / "handout"
    handout.mkdir()
    (handout / "inside.pem").write_bytes(_self_signed(5, "inside"))
    (handout / "link.pem").symlink_to(outside / "elsewhere.pem")
    (handout / "linkdir").symlink_to(outside, target_is_directory=True)
    infos = pk.load_public_points(handout)
    assert [i.path for i in infos] == ["inside.pem"]
    files, links = pk._handout_files(handout)
    assert links == 2 and [p.name for p in files] == ["inside.pem"]


# --------------------------------------------------------------------------- proof signer / client


def test_sign_proof_verifies_and_wrong_key_rejected():
    msg = b"audit: please prove possession 2031"
    proof = pk.sign_proof(WEAK, msg)
    assert _sig_verifies(proof["signature"], msg, WEAK)
    assert not _sig_verifies(proof["signature"], msg, HEALTHY)


def test_sign_proof_rejects_out_of_range_scalar():
    with pytest.raises(pk.WeakKeyError):
        pk.sign_proof(0, b"x")
    with pytest.raises(pk.WeakKeyError):
        pk.sign_proof(pk.P384.n, b"x")


def test_build_proof_echoes_session_and_signs_exact_message():
    challenge = {"session_id": "sess-xyz", "message": "prove you still hold K-17b"}
    payload = pk.build_proof(challenge, WEAK)
    assert payload["session_id"] == "sess-xyz"
    assert _sig_verifies(payload["signature"], challenge["message"].encode("utf-8"), WEAK)


def test_build_proof_base64_message_decoded_before_signing():
    raw = b"\x00\x01binary audit blob\xff"
    challenge = {"session_id": "s", "message": base64.b64encode(raw).decode("ascii")}
    payload = pk.build_proof(challenge, WEAK, message_b64=True)
    assert _sig_verifies(payload["signature"], raw, WEAK)


def _verify_body(state, body, public_point):
    if not isinstance(body, dict) or body.get("session_id") != state["session_id"]:
        return {"ok": False, "error": "unknown session"}
    r, s = decode_dss_signature(base64.b64decode(body["signature"]))
    z = hash_z(state["message"].encode("utf-8"), pk.P384, "sha384")
    if ecdsa_verify((r, s, z), public_point, curve=pk.P384):
        return {"ok": True, "flag": "flag{loopback-proof}"}
    return {"ok": False}


def _fake_transport(public_point, message="audit-nonce-7f3a"):
    """An in-process fake proof server: issues a challenge, verifies the signature, returns a flag."""
    state = {"session_id": "fake-session-01", "message": message}

    def transport(method, url, body):
        if method == "GET":
            return dict(state)
        assert method == "POST"
        return _verify_body(state, body, public_point)

    return transport


def test_run_proof_against_fake_returns_flag():
    result = pk.run_proof(_fake_transport(_point(WEAK)), "http://127.0.0.1:0", WEAK)
    assert result == {"ok": True, "flag": "flag{loopback-proof}"}


def test_run_proof_wrong_scalar_fails_verification():
    result = pk.run_proof(_fake_transport(_point(WEAK)), "http://127.0.0.1:0", HEALTHY)
    assert result.get("ok") is False
    assert "flag" not in result


def test_run_proof_requires_transport():
    with pytest.raises(pk.WeakKeyError):
        pk.run_proof(None, "http://127.0.0.1:0", WEAK)


@pytest.fixture
def proof_server():
    """A fake proof server on 127.0.0.1: GET /challenge, POST /verify, GET /bounce redirects."""
    state = {"session_id": "http-session-9", "message": "audit-http-c0ffee"}
    public = _point(WEAK)
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, obj, extra=None):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            seen.append(("GET", self.path))
            if self.path == "/challenge":
                self._send(200, state)
            elif self.path.startswith("/bounce"):
                # same loopback server, so a followed redirect shows up in `seen` and contacts nothing else
                self._send(302, {}, {"Location": "/challenge"})
            else:
                self._send(404, {"error": "no"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append(("POST", self.path))
            res = _verify_body(state, body, public)
            self._send(200 if res.get("ok") else 403, res)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    finally:
        srv.shutdown()
        srv.server_close()
        th.join()


def test_http_transport_drives_proof_server_on_loopback(proof_server):
    base, seen = proof_server
    result = pk.run_proof(pk.http_transport(timeout=60), base, WEAK)
    assert result == {"ok": True, "flag": "flag{loopback-proof}"}
    assert seen == [("GET", "/challenge"), ("POST", "/verify")]


def test_http_transport_returns_json_error_body_for_wrong_key(proof_server):
    base, _ = proof_server
    result = pk.run_proof(pk.http_transport(timeout=60), base, HEALTHY)
    assert result == {"ok": False}


def test_http_transport_refuses_redirects(proof_server):
    base, seen = proof_server
    with pytest.raises(pk.WeakKeyError, match="redirect"):
        pk.http_transport(timeout=60)("GET", base + "/bounce", None)
    assert seen == [("GET", "/bounce")]


def test_http_transport_scope_checks_before_connecting(proof_server):
    _, seen = proof_server
    with pytest.raises(scope.OutOfScope):
        pk.http_transport(timeout=60)("GET", "http://proof.example.com/challenge", None)
    with pytest.raises(pk.WeakKeyError, match="not http"):
        pk.http_transport(timeout=60)("GET", "file:///etc/hosts", None)
    assert seen == []


# --------------------------------------------------------------------------- CLI


def test_cli_sign_challenge_file_prints_payload(tmp_path, capsys):
    challenge = {"session_id": "cli-sess", "message": "sign me exactly"}
    path = tmp_path / "challenge.json"
    path.write_text(json.dumps(challenge))
    assert pk.main(["sign", str(path), "--scalar", hex(WEAK)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["session_id"] == "cli-sess"
    assert _sig_verifies(payload["signature"], b"sign me exactly", WEAK)


def test_cli_sign_message_on_another_curve_hash_follows_curve(capsys):
    # No --hash: a 256-bit curve signs with sha256.
    assert pk.main(["sign", "--message", "hello", "--scalar", "7", "--curve", "secp256r1"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert _sig_verifies(out["signature"], b"hello", 7, curve=SECP256R1, ec_curve=ec.SECP256R1(),
                         hash_name="sha256")
    # An explicit --hash wins over the curve default.
    assert pk.main(["sign", "--message", "hello", "--scalar", "7", "--curve", "secp256r1",
                    "--hash", "sha384"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert _sig_verifies(out["signature"], b"hello", 7, curve=SECP256R1, ec_curve=ec.SECP256R1(),
                         hash_name="sha384")


def test_cli_sign_unknown_curve_is_refused():
    assert pk.main(["sign", "--message", "x", "--scalar", "5", "--curve", "secp521r1"]) == 2


def test_cli_sign_message_b64(capsys):
    raw = b"\x10\x20raw"
    assert pk.main(["sign", "--message-b64", base64.b64encode(raw).decode(), "--scalar", str(WEAK)]) == 0
    assert _sig_verifies(json.loads(capsys.readouterr().out)["signature"], raw, WEAK)


def test_cli_sign_needs_a_message(capsys):
    assert pk.main(["sign", "--scalar", "5"]) == 2
    assert "challenge JSON file or --message" in capsys.readouterr().err


def test_cli_prove_against_loopback_server(proof_server, capsys):
    base, _ = proof_server
    assert pk.main(["prove", base, "--scalar", str(WEAK), "--timeout", "60"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ok": True, "flag": "flag{loopback-proof}"}


def test_cli_prove_out_of_scope_is_refused(capsys):
    assert pk.main(["prove", "http://proof.example.com", "--scalar", "5"]) == 3
    assert "refused" in capsys.readouterr().err


# --------------------------------------------------------------------------- solve() contract entry


def _profile():
    from ctf import event
    return event.load("spooky")


def test_solve_recovers_weak_key_and_reports_triage(tmp_path):
    cdir = _challenge_dir(tmp_path)
    res = pk.solve(cdir, _profile(), bound=1 << 14, budget=60)
    assert res.status == "unsure"
    assert f"d = {WEAK} " in res.notes
    match = [e for e in res.evidence if e.kind == "match"]
    triage_ev = [e for e in res.evidence if e.kind == "triage"]
    assert [e.path for e in match] == ["relay-ca-2.pem"]
    assert len(triage_ev) == 1 and "legacy-import" in triage_ev[0].detail
    assert "sign challenge.json" in res.notes


def test_solve_lists_every_weak_key_suspect_first(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "aa-plain.pem").write_bytes(_self_signed(5, "plain-weak"))
    (files / "zz-suspect.pem").write_bytes(_self_signed(9, "suspect-weak"))
    (files / "ceremony.log").write_text(
        "2031-07-01T00:00:00Z HSM UNWRAP source=M-1 object=M-1r handler=compat-x status=OK\n"
        "2031-07-01T00:00:01Z CSR CREATE object=M-1r certificate=zz-suspect status=OK\n")
    res = pk.solve(tmp_path, _profile(), bound=1 << 10, budget=60)
    assert res.status == "unsure"
    match = [e.path for e in res.evidence if e.kind == "match"]
    assert match == ["zz-suspect.pem", "aa-plain.pem"]
    assert "2 weak key(s)" in res.notes and "d = 5 " in res.notes and "d = 9 " in res.notes


def test_solve_triage_reason_matches_exact_certificate_name(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "X-1.pem").write_bytes(_self_signed(HEALTHY, "healthy"))
    (files / "X-10.pem").write_bytes(_self_signed(WEAK, "weak"))
    (files / "ceremony.log").write_text(
        "2031-07-01T00:00:00Z HSM UNWRAP source=N-1 object=N-1r handler=compat-x status=OK\n"
        "2031-07-01T00:00:01Z CSR CREATE object=N-1r certificate=X-1 status=OK\n")
    res = pk.solve(tmp_path, _profile(), bound=1 << 14, budget=60)
    assert [e.path for e in res.evidence if e.kind == "match"] == ["X-10.pem"]
    assert not [e for e in res.evidence if e.kind == "triage"]


def test_solve_p256_tiny_scalar_is_recovered(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "p256.pem").write_bytes(_self_signed(7, "p256-weak", ec.SECP256R1()))
    res = pk.solve(tmp_path, _profile(), bound=1 << 10, budget=60)
    assert res.status == "unsure"
    assert "d = 7 (0x7) on secp256r1" in res.notes


def test_solve_unsupported_curve_only_is_blocked_and_named(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "p521.pem").write_bytes(_self_signed(3, "p521", ec.SECP521R1()))
    res = pk.solve(tmp_path, _profile(), bound=1 << 10, budget=60)
    assert res.status == "blocked"
    assert "skipped 1 point(s) on secp521r1: no curve params" in res.notes


def test_solve_found_none_counts_only_searched_points(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "relay-ca-2.pem").write_bytes(_self_signed(HEALTHY, "relay-healthy"))
    (files / "p521.pem").write_bytes(_self_signed(3, "p521", ec.SECP521R1()))
    (files / "ceremony.log").write_text(CEREMONY)
    (files / "key-inventory.csv").write_text(INVENTORY)
    res = pk.solve(tmp_path, _profile(), bound=1 << 12, budget=60)
    assert res.status == "unsure"
    assert not res.flags
    assert "searched 1 EC public point(s)" in res.notes and "found none" in res.notes
    assert "skipped 1 point(s) on secp521r1" in res.notes
    assert "K-17b" in res.notes


def test_solve_reports_budget_exhaustion(tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    (files / "relay-ca-2.pem").write_bytes(_self_signed(WEAK, "relay-weak"))
    res = pk.solve(tmp_path, _profile(), bound=1 << 14, budget=-1)
    assert res.status == "unsure"
    assert "1 point(s) not fully searched" in res.notes and "searched 0 EC" in res.notes


def test_solve_reports_ignored_symlinks(tmp_path):
    outside = tmp_path / "outside.pem"
    outside.write_bytes(_self_signed(3, "outside"))
    files = tmp_path / "chal" / "files"
    files.mkdir(parents=True)
    (files / "inside.pem").write_bytes(_self_signed(HEALTHY, "inside"))
    (files / "link.pem").symlink_to(outside)
    res = pk.solve(tmp_path / "chal", _profile(), bound=1 << 10, budget=60)
    assert res.status == "unsure"
    assert "d = 3 " not in res.notes
    assert "ignored 1 symlink(s)" in res.notes


def test_solve_none_without_certificates(tmp_path):
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "readme.txt").write_text("nothing here")
    res = pk.solve(tmp_path, _profile())
    assert res.status == "none"


def test_solve_blocked_when_cryptography_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(pk, "_HAVE_CRYPTO", False)
    monkeypatch.setattr(pk, "_CRYPTO_IMPORT_ERROR", "simulated absence")
    res = pk.solve(tmp_path, _profile())
    assert res.status == "blocked"
    assert "cryptography" in res.notes
