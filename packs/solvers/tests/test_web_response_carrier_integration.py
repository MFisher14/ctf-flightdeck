#!/usr/bin/env python3
"""Proof-policy integration tests for bounded response carriers (no network)."""

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web tests: proof_<32 hex> payoffs (events/huntress [proof])

import gzip
import io
import json
import sys
import time
import zipfile
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "web"))
import forge_event as F  # noqa: E402
import xxe_read as X  # noqa: E402


PROOF = "proof_0123456789abcdef0123456789abcdef"
PROOF_TWO = "proof_fedcba9876543210fedcba9876543210"


def response(body, *, status=200, headers=None, pairs=None):
    out = {"status": status, "body": body,
           "response_headers": dict(headers or {})}
    if pairs is not None:
        out["response_header_pairs"] = list(pairs)
    return out


def success_doc(proof=PROOF):
    return json.dumps({"ok": True, "effect": "internal_read", "proof": proof},
                      separators=(",", ":")).encode()


def multipart(parts, boundary="huntress-boundary"):
    chunks = []
    for content_type, body in parts:
        chunks.append((f"--{boundary}\r\nContent-Type: {content_type}\r\n\r\n").encode()
                      + body + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/mixed; boundary={boundary}"


def test_http_encoding_charset_and_archive_views_auto_only_from_coherent_success():
    raw = success_doc()
    cases = [
        response(gzip.compress(raw), headers={"Content-Type": "application/json",
                                              "Content-Encoding": "gzip"}),
        response(zlib.compress(gzip.compress(raw)), headers={"Content-Type": "application/json",
                                                        "Content-Encoding": "gzip, deflate"}),
        response(raw.decode().encode("utf-16"), headers={"Content-Type":
                                                         "application/json; charset=utf-16"}),
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payoff.json", raw)
    cases.append(response(buf.getvalue(), headers={"Content-Type": "application/zip"}))
    body, content_type = multipart([("application/json", raw)])
    cases.append(response(body, headers={"Content-Type": content_type}))
    for item in cases:
        info = F.extract_success(item, [])
        assert info["auto"] == PROOF and info["success"] is True, (item["response_headers"], info)


def test_controls_receive_identical_decoding_and_suppress_repeated_value():
    control = response(gzip.compress(success_doc()), headers={
        "Content-Type": "application/json", "Content-Encoding": "gzip"})
    baseline = F.response_baseline_text(control)
    assert PROOF in baseline
    info = F.extract_success(response(success_doc()), [baseline])
    assert info["auto"] is None and info["wire"] == [], info


def test_unsupported_baseline_charset_poison_prevents_false_novelty():
    # cp037 is deliberately outside the carrier decoder's allow-list.  Raw
    # UTF-8 replacement cannot establish what semantic proof the baseline
    # contained, so a later UTF-8 spelling must not be considered novel.
    control = response(PROOF.encode("cp037"), headers={
        "Content-Type": "text/plain; charset=cp037"})
    baseline = F.response_baseline_text(control)
    assert F.baseline_set_incomplete([baseline]) is True, baseline[:500]
    info = F.extract_success(response(success_doc(PROOF)), [baseline])
    assert info["auto"] is None and info["wire"] == [PROOF], info


def test_baseline_marks_survive_late_multipart_member_without_joining_siblings():
    # The final member begins after roughly 450 KiB. Each preceding member is
    # independently within the carrier leaf cap, but their display text exceeds
    # forge_event.MAX_TEXT before the decoy is reached.
    filler = b"A-" * (115 << 10)
    body, content_type = multipart([
        ("text/plain", filler),
        ("text/plain", filler),
        ("text/plain", b"late baseline decoy " + PROOF.encode()),
    ])
    baseline = F.response_baseline_text(response(body, headers={"Content-Type": content_type}))
    assert len(baseline) <= F.MAX_TEXT
    assert F.baseline_proofs([baseline]) == [PROOF]
    info = F.extract_success(response(success_doc(PROOF)), [baseline])
    assert info["auto"] is None and info["wire"] == [], info

    split, split_type = multipart([
        ("text/plain", b"proof:"),
        ("text/plain", b"must_not_become_a_cross_sibling_candidate"),
    ])
    split_baseline = F.response_baseline_text(
        response(split, headers={"Content-Type": split_type}))
    assert "must_not_become_a_cross_sibling_candidate" not in F._candidate_values(
        split_baseline, max_values=F.MAX_BASELINE_MARKS)


def test_baseline_marks_survive_full_body_and_late_ordered_header():
    candidate = "future_evidence_shape_123456"
    control = response(b"B" * F.MAX_TEXT, pairs=[
        ("Content-Type", "text/plain"),
        ("X-Filler", "ordinary"),
        ("X-Decoy", f"evidence: {candidate}; proof: {PROOF}"),
    ])
    baseline = F.response_baseline_text(control)
    assert len(baseline) <= F.MAX_TEXT
    assert F.baseline_proofs([baseline]) == [PROOF]

    payoff = json.dumps({"ok": True, "effect": "internal_read",
                         "proof": PROOF, "evidence": candidate}).encode()
    info = F.extract_success(response(payoff), [baseline])
    assert info["auto"] is None and info["wire"] == [] and info["candidates"] == [], info


def test_strict_baseline_set_survives_more_than_256_decoys_and_overflow_fails_closed():
    def late_control(count):
        early = "\n".join(f"proof_{index:032x}" for index in range(count)).encode()
        padding = b"Z" * max(0, 450_000 - len(early))
        return response(early + b"\n" + padding + b"\n" + PROOF.encode(),
                        headers={"Content-Type": "text/plain"})

    # This set fits the bounded representation and must be retained exactly;
    # the former 256-item marker quota dropped the final matching decoy.
    baseline = F.response_baseline_text(late_control(300))
    assert F.BASELINE_STRICT_INCOMPLETE not in baseline
    assert PROOF in baseline
    info = F.extract_success(response(success_doc(PROOF)), [baseline])
    assert info["success"] is True and info["auto"] is None and info["wire"] == [], info

    truncated = baseline[:100]
    assert F.BASELINE_STRICT_START in truncated and F.BASELINE_STRICT_END not in truncated
    info = F.extract_success(response(success_doc(PROOF)), [truncated])
    assert info["success"] is True and info["auto"] is None and info["wire"] == [PROOF], info

    # A set too large for MAX_TEXT is explicitly incomplete. Even though the
    # late matching value cannot be serialized, novelty therefore fails closed.
    overflow = F.response_baseline_text(late_control(10_000))
    assert F.BASELINE_STRICT_INCOMPLETE in overflow
    info = F.extract_success(response(success_doc(PROOF)), [overflow])
    assert info["success"] is True and info["auto"] is None and info["wire"] == [PROOF], info


def test_incomplete_transport_metadata_poison_baselines_and_cannot_supply_payoffs():
    exact_cap = response(b"C" * F.MAX_BASELINE_SCAN, headers={"Content-Type": "text/plain"})
    exact_cap["truncated"] = True
    baseline = F.response_baseline_text(exact_cap)
    assert F.BASELINE_STRICT_INCOMPLETE in baseline
    info = F.extract_success(response(success_doc(PROOF)), [baseline])
    assert info["success"] is True and info["auto"] is None and info["wire"] == [PROOF], info

    for key, value in (
            ("incomplete", True), ("limit_error", "byte limit"),
            ("protocol_error", "partial frame"), ("framing_error", "TE plus CL")):
        control = response(b"ordinary complete-looking bytes")
        control[key] = value
        assert F.BASELINE_STRICT_INCOMPLETE in F.response_baseline_text(control), key

    framed_payoff = response(success_doc(PROOF), headers={"Content-Type": "application/json"})
    framed_payoff["framing_error"] = "conflicting Content-Length"
    info = F.extract_success(framed_payoff, [])
    assert info["success"] is False and info["auto"] is None and info["wire"] == [], info
    assert F.success_signal(framed_payoff) is False


def test_declared_broken_carriers_poison_baseline_but_valid_empty_carrier_does_not():
    broken = [
        response(b"opaque", headers={"Content-Type": "text/plain",
                                      "Content-Encoding": "x-unknown"}),
        response(b"not gzip", headers={"Content-Type": "text/plain",
                                        "Content-Encoding": "gzip"}),
        response(b"not a zip", headers={"Content-Type": "application/zip"}),
        response(b"--broken", headers={"Content-Type":
                                        "multipart/mixed; boundary=missing"}),
    ]
    for control in broken:
        baseline = F.response_baseline_text(control)
        assert F.BASELINE_STRICT_INCOMPLETE in baseline, control["response_headers"]
        info = F.extract_success(response(success_doc(PROOF)), [baseline])
        assert info["auto"] is None, (control["response_headers"], info)

    empty = response(gzip.compress(b""), headers={"Content-Type": "text/plain",
                                                   "Content-Encoding": "gzip"})
    baseline = F.response_baseline_text(empty)
    assert F.BASELINE_STRICT_INCOMPLETE not in baseline


def test_late_escaped_json_proof_scalar_bypasses_no_candidate_or_display_cap():
    early = ",".join(f'"evidence_{index}":"decoy_{index:03d}"' for index in range(90))
    escaped = PROOF.replace("o", "\\u006f", 1)
    body = ("{" + early + ',"padding":"' + ("Q" * 410_000)
            + f'","proof":"{escaped}"' + "}").encode()
    assert PROOF.encode() not in body
    baseline = F.response_baseline_text(
        response(body, headers={"Content-Type": "application/json"}))
    assert PROOF in baseline
    info = F.extract_success(response(success_doc(PROOF)), [baseline])
    assert info["success"] is True and info["auto"] is None and info["wire"] == [], info


def test_structurally_decoded_json_proof_can_be_the_exact_payoff():
    escaped = PROOF.replace("o", "\\u006f", 1)
    body = ('{"ok":true,"effect":"read","proof":"' + escaped + '"}').encode()
    assert PROOF.encode() not in body
    info = F.extract_success(response(body, headers={"Content-Type": "application/json"}), [])
    assert info["success"] is True and info["auto"] == PROOF and info["wire"] == [PROOF], info


def test_invalid_utf8_json_cannot_auto_bank_or_authorize_a_mutation():
    body = (b'{"ok":true,"effect":"forged_event_consumed","note":"\x80",'
            b'"xml_method":"POST","xml_content_type":"application/xml",'
            b'"xml_route":"/read","xml_root":"parcel","xml_field":"payload",'
            b'"proof":"' + PROOF.encode() + b'"}')
    item = response(body, headers={"Content-Type": "application/json"})
    info = F.extract_success(item, [])
    assert info["success"] is False and info["auto"] is None and info["wire"] == [], info
    assert F.response_text_views(item, strict=True) == []
    assert X._json(item, strict=True) is None


def test_sibling_fragments_never_join_and_distinct_parts_remain_ambiguous():
    first = json.dumps({"ok": True, "proof": "proof_0123456789abcdef"}).encode()
    second = json.dumps({"ok": True, "proof": "0123456789abcdef"}).encode()
    body, content_type = multipart([("application/json", first), ("application/json", second)])
    info = F.extract_success(response(body, headers={"Content-Type": content_type}))
    assert info["auto"] is None and PROOF not in info["wire"], info

    body, content_type = multipart([
        ("application/json", success_doc(PROOF)),
        ("application/json", success_doc(PROOF_TWO)),
    ])
    info = F.extract_success(response(body, headers={"Content-Type": content_type}))
    assert info["auto"] is None and set(info["wire"]) == {PROOF, PROOF_TWO}, info

    body, content_type = multipart([
        ("application/json", json.dumps({"ok": False, "error": "denied"}).encode()),
        ("application/json", success_doc(PROOF)),
    ])
    info = F.extract_success(response(body, headers={"Content-Type": content_type}))
    assert info["success"] is False and info["auto"] is None and info["wire"] == [], info

    body, content_type = multipart([
        ("application/json", success_doc(PROOF)),
        ("text/plain", ("diagnostic evidence: " + PROOF_TWO).encode()),
    ])
    info = F.extract_success(response(body, headers={"Content-Type": content_type}))
    assert info["success"] is True and info["auto"] is None, info
    assert {PROOF, PROOF_TWO} <= set(info["candidates"]), info

    header_only = response(
        json.dumps({"ok": True, "effect": "forged_event_consumed"}).encode(),
        headers={"Content-Type": "application/json", "X-Proof": PROOF},
    )
    info = F.extract_success(header_only, [])
    assert info["success"] is True and info["auto"] is None and info["wire"] == [], info


def test_huge_json_numbers_are_rejected_before_integer_conversion():
    bomb = '{"n":' + ('9' * 100_000) + '}'
    started = time.monotonic()
    assert F._json_whole(bomb) is None
    assert F._json_objects(bomb) == []
    baseline = F.response_baseline_text(
        response(bomb.encode(), headers={"Content-Type": "application/json"}))
    assert time.monotonic() - started < 0.5
    assert F.BASELINE_STRICT_INCOMPLETE in baseline


def test_embedded_json_scanner_is_linear_and_malformed_policy_is_incomplete():
    bomb = '{"a":' * 10_000
    started = time.monotonic()
    assert F._json_objects(bomb) == []
    assert time.monotonic() - started < 0.5

    malformed = 'prefix {"evid\\u0065nce":"ODD-EVIDENCE-BETA",'
    integrity = {}
    assert F._security_json_objects(malformed, _integrity=integrity) == []
    assert integrity.get("incomplete") is True, integrity

    poisoned = response(success_doc(), headers={"Content-Type": "application/json"}, pairs=[
        ("Content-Type", "application/json"), ("X-Meta", malformed),
    ])
    info = F.extract_success(poisoned, [])
    assert info["success"] is True and info["auto"] is None, info

    # A malformed leading candidate may not be skipped in favor of a later
    # valid-looking document that would authorize a live mutation.
    mixed = (malformed + '\n' + json.dumps({
        "feature_route": "/webhook", "event_type": "case.promoted",
        "owner_scope": "executive",
    }, separators=(",", ":"))).encode()
    runner = object.__new__(F._Forge)
    assert runner._docs(response(mixed, headers={"Content-Type": "text/plain"})) == []


def test_javascript_source_survives_optional_json_and_jwt_interpretations():
    for source in (
        "const x = window.location.hash;",
        "[foo].forEach(render);",
        '["use strict"]; location.hash;',
    ):
        views = F.response_text_views(response(
            source.encode(), headers={"Content-Type": "application/javascript"}))
        assert source in views, (source, views)


def test_ambiguous_mime_sibling_invalidates_every_other_payoff_and_baseline():
    boundary = "ambiguous-inner-header"
    body = (
        f"--{boundary}\r\nContent-Type: application/json\r\n\r\n".encode()
        + success_doc(PROOF) + b"\r\n"
        + f"--{boundary}\r\nContent-Type: application/json\r\n".encode()
        + b"Content-Type: text/plain\r\n\r\n"
        + success_doc(PROOF_TWO) + b"\r\n"
        + f"--{boundary}--\r\n".encode()
    )
    item = response(body, headers={
        "Content-Type": f"multipart/mixed; boundary={boundary}"})
    assert F.response_text_views(item, strict=True) == []
    baseline = F.response_baseline_text(item)
    assert F.BASELINE_STRICT_INCOMPLETE in baseline
    info = F.extract_success(item, [])
    assert info["success"] is False and info["auto"] is None and info["wire"] == [], info


def test_malformed_or_oversized_encoded_entities_fail_closed():
    malformed = b"not-a-gzip " + PROOF.encode()
    info = F.extract_success(response(malformed, headers={"Content-Type": "application/json",
                                                          "Content-Encoding": "gzip"}))
    assert info["success"] is False and info["auto"] is None and info["wire"] == [], info

    # A highly compressible body exceeds the decoder's ratio ceiling. The
    # strict token in its compressed source cannot become response evidence.
    bomb = gzip.compress((b"A" * (400 << 10)) + PROOF.encode())
    info = F.extract_success(response(bomb, headers={"Content-Type": "text/plain",
                                                     "Content-Encoding": "gzip"}))
    assert info["success"] is False and info["auto"] is None, info


def test_new_carrier_budget_issue_codes_are_fatal_for_payoffs():
    from types import SimpleNamespace

    leaf = SimpleNamespace(kind="json-document", data=success_doc(),
                           metadata_dict=lambda: {})
    original = F._carriers.decode_response
    try:
        for code in ("node_count_limit", "issue_count_limit"):
            F._carriers.decode_response = lambda *_args, _code=code, **_kwargs: SimpleNamespace(
                leaves=[leaf], issues=[SimpleNamespace(code=_code, provenance=("response",))])
            item = response(success_doc(), headers={"Content-Type": "application/json"})
            assert F.response_text_views(item, strict=True) == []
            assert F.response_text_views(item, strict=False) == [success_doc().decode()]
    finally:
        F._carriers.decode_response = original


def test_unverified_jwt_claims_never_auto_answer():
    import base64

    enc = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    token = ".".join((enc(b'{"alg":"none"}'),
                      enc(json.dumps({"proof": PROOF}).encode()), ""))
    body = json.dumps({"ok": True, "token": token}).encode()
    info = F.extract_success(response(body, headers={"Content-Type": "application/json"}))
    assert info["auto"] is None and PROOF not in info["wire"], info


def test_ordered_duplicate_headers_participate_in_ambiguity():
    item = response(success_doc(), headers={"Content-Type": "application/json"}, pairs=[
        ("Content-Type", "application/json"),
        ("X-Evidence", PROOF_TWO),
        ("X-Evidence", PROOF_TWO),
    ])
    info = F.extract_success(item, [])
    assert info["auto"] is None and info["wire"] == [PROOF], info
    assert {PROOF, PROOF_TWO} <= set(info["candidates"]), info

    late = response(success_doc(), headers={"Content-Type": "application/json"}, pairs=[
        ("Content-Type", "application/json"),
        ("X-Evidence", ("x" * 4097) + " evidence: " + PROOF_TWO),
    ])
    info = F.extract_success(late, [])
    assert info["auto"] is None and {PROOF, PROOF_TWO} <= set(info["candidates"]), info

    repeated = [f"evidence: benign-{index}" for index in range(24)]
    baseline = " ".join(repeated)
    saturated = response(success_doc(), headers={"Content-Type": "application/json"}, pairs=[
        ("Content-Type", "application/json"),
        ("X-Evidence", baseline + " evidence: " + PROOF_TWO),
    ])
    info = F.extract_success(saturated, [baseline])
    assert info["auto"] is None and PROOF_TWO in info["candidates"], info

    baseline_doc = {f"evidence_{index:02d}": f"baseline_{index:02d}"
                    for index in range(24)}
    header_doc = dict(baseline_doc)
    header_doc["evidence_tail"] = "ODD-EVIDENCE-BETA"
    generic_saturated = response(
        success_doc(), headers={"Content-Type": "application/json"}, pairs=[
            ("Content-Type", "application/json"),
            ("X-Debug", json.dumps(header_doc, separators=(",", ":"))),
        ])
    info = F.extract_success(
        generic_saturated, [json.dumps(baseline_doc, separators=(",", ":"))])
    assert info["auto"] is None and "ODD-EVIDENCE-BETA" in info["candidates"], info

    ambiguous_embedded = response(
        success_doc(), headers={"Content-Type": "application/json"}, pairs=[
            ("Content-Type", "application/json"),
            ("X-Debug", 'prefix {"evid\\u0065nce":"ODD-EVIDENCE-BETA",'
                        '"evidence":"baseline_00"}'),
        ])
    info = F.extract_success(
        ambiguous_embedded, ['{"evidence":"baseline_00"}'])
    assert info["auto"] is None, info

    oversized = response(success_doc(), headers={"Content-Type": "application/json"}, pairs=[
        ("Content-Type", "application/json"),
        ("X-Evidence", ("x" * (F.MAX_RESPONSE_HEADER_VALUE + 1)) + PROOF_TWO),
    ])
    info = F.extract_success(oversized, [])
    assert info["success"] is False and info["auto"] is None, info


def test_no_carrier_fallback_rejects_duplicate_critical_headers():
    old = F._carriers
    F._carriers = None
    try:
        for pairs in (
            [("Content-Type", "multipart/mixed; boundary=x"),
             ("Content-Type", "application/json")],
            [("Content-Encoding", "gzip"), ("Content-Encoding", "identity")],
        ):
            item = response(success_doc(), pairs=pairs)
            info = F.extract_success(item, [])
            assert info["success"] is False and info["auto"] is None, info
    finally:
        F._carriers = old


def test_malformed_json_and_conflicting_content_types_do_not_fall_back_to_raw_payoff():
    malformed = response(b'{"ok":true,"proof":"' + PROOF.encode(),
                         headers={"Content-Type": "application/json"})
    info = F.extract_success(malformed, [])
    assert info["success"] is False and info["auto"] is None and info["wire"] == [], info

    conflict = response(success_doc(), pairs=[
        ("Content-Type", "application/json"), ("Content-Type", "text/plain")])
    info = F.extract_success(conflict, [])
    assert info["success"] is False and info["auto"] is None and info["wire"] == [], info

    # Controls use the opposite trust direction: raw and every safe decoded
    # view remain subtraction material even when a carrier is malformed.
    assert PROOF in F.response_baseline_text(malformed)


def test_duplicate_security_json_members_never_signal_success():
    cases = [
        b'{"ok":false,"ok":true,"proof":"' + PROOF.encode() + b'"}',
        b'{"ok":true,"nested":{"proof":"' + PROOF.encode()
        + b'","proof":"' + PROOF_TWO.encode() + b'"}}',
        b'{"ok":false,"OK":true,"proof":"' + PROOF.encode() + b'"}',
    ]
    for body in cases:
        info = F.extract_success(response(body, headers={"Content-Type": "application/json"}), [])
        assert info["success"] is False and info["auto"] is None and info["wire"] == [], info


def main():
    tests = [value for name, value in sorted(globals().items())
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
        print("PASS", test.__name__)
    print(f"PASS all {len(tests)} response-carrier integration tests")


if __name__ == "__main__":
    main()
