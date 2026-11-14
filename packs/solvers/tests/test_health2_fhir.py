"""FHIR R4 independent tests: RFC 4648 vectors, HL7 examples, manual fixtures.

Reference rules: https://hl7.org/fhir/R4/bundle.html#references
Waveform example: https://hl7.org/fhir/R4/observation-example-sample-data.json.html
No fixture is created from this engine's output. No network access is required.
"""
import argparse
import base64
import copy
import hashlib
import json
from decimal import Decimal

import pytest

import health2_fhir as H


def entry(kind, identifier, base="https://a.example/fhir/", **fields):
    return {"fullUrl": base + kind + "/" + identifier,
            "resource": {"resourceType": kind, "id": identifier, **fields}}


def bundle(*entries):
    return {"resourceType": "Bundle", "type": "collection", "entry": list(entries)}


def ref(reference):
    return {"reference": reference}


@pytest.mark.parametrize("encoded,plain", [("", b""), ("Zg==", b"f"), ("Zm8=", b"fo"),
    ("Zm9v", b"foo"), ("Zm9vYg==", b"foob"), ("Zm9vYmE=", b"fooba"), ("Zm9vYmFy", b"foobar")])
def test_rfc4648_base64_vectors(encoded, plain):
    assert H.decode_base64(encoded) == plain


@pytest.mark.parametrize("encoded", ["Zh==", "Zg", "Zg=", "Zg===", "Zg==garbage", "-w==", "_w==", "Zg!!", "\u00a0Zg==", None, b"Zg=="])
def test_invalid_base64(encoded):
    with pytest.raises(H.FHIRFormatError):
        H.decode_base64(encoded)


def test_transport_whitespace():
    assert H.decode_base64(" Zm9v\r\nYmFy\t") == b"foobar"


def test_source_base_disambiguates_ids():
    data = bundle(entry("Patient", "same"), entry("Patient", "same", "https://b.example/fhir/"),
                  entry("Observation", "o", subject=ref("Patient/same")))
    out = H.parse_fhir(data)
    assert out["references"] == [{"path": "/entry/2/resource/subject/reference", "reference": "Patient/same",
                                  "status": "resolved", "targets": ["/entry/0/resource"]}]


def test_no_fallback_to_wrong_server():
    data = bundle(entry("Patient", "p", "https://b.example/fhir/"),
                  entry("Observation", "o", subject=ref("Patient/p")))
    assert H.parse_fhir(data)["references"][0]["status"] == "unresolved"


def test_no_relative_resolution_without_rest_base():
    source = entry("Observation", "o", subject=ref("Patient/p"))
    source["fullUrl"] = "urn:uuid:example-observation"
    data = bundle(entry("Patient", "p"), source)
    assert H.parse_fhir(data)["references"][0]["status"] == "unresolved"


def test_urn_and_external_references():
    patient = {"fullUrl": "urn:uuid:example-patient", "resource": {"resourceType": "Patient", "id": "p"}}
    source = entry("Observation", "o", subject=ref("urn:uuid:example-patient"),
                   performer=[ref("https://outside.example/fhir/Practitioner/p")])
    out = H.parse_fhir(bundle(patient, source))["references"]
    assert [item["status"] for item in out] == ["resolved", "unresolved"]
    assert out[0]["targets"] == ["/entry/0/resource"]


def test_history_version_and_ambiguity():
    data = bundle(entry("Patient", "p", meta={"versionId": "1"}),
                  entry("Patient", "p", meta={"versionId": "2"}),
                  entry("Observation", "o", subject=ref("Patient/p/_history/2"),
                        focus=[ref("Patient/p"), ref("Patient/p/_history/3"),
                               ref("https://a.example/fhir/Patient/p/_history/1")]))
    data["type"] = "history"
    out = H.parse_fhir(data)["references"]
    assert [item["status"] for item in out] == ["resolved", "ambiguous", "unresolved", "resolved"]
    assert out[0]["targets"] == ["/entry/1/resource"]
    assert out[3]["targets"] == ["/entry/0/resource"]


def test_contained_sibling_container_and_external_refs():
    source = entry("Observation", "o", subject=ref("#p"), contained=[
        {"resourceType": "Patient", "id": "p", "generalPractitioner": [ref("#pr")],
         "managingOrganization": ref("Organization/org")},
        {"resourceType": "Practitioner", "id": "pr", "extension": [{"valueReference": ref("#")}]}])
    other = entry("Observation", "other", subject=ref("#p"))
    out = H.parse_fhir(bundle(source, other, entry("Organization", "org")))["references"]
    assert [item["status"] for item in out] == ["resolved", "resolved", "resolved", "resolved", "unresolved"]
    assert out[0]["targets"] == ["/entry/0/resource/contained/0"]
    assert out[1]["targets"] == ["/entry/0/resource/contained/1"]
    assert out[2]["targets"] == ["/entry/2/resource"]
    assert out[3]["targets"] == ["/entry/0/resource"]


def test_nested_bundle_scope_and_list_entries():
    inside = bundle(entry("Patient", "p"), entry("Observation", "o", subject=ref("Patient/p")))
    data = bundle(entry("Patient", "p"), {"resource": inside, "fullUrl": "urn:uuid:inner"},
                  entry("List", "list", entry=[{"item": ref("Patient/p")}]))
    refs = H.parse_fhir(data)["references"]
    assert refs[0]["targets"] == ["/entry/1/resource/entry/0/resource"]
    assert refs[1]["targets"] == ["/entry/0/resource"]


def test_binary_and_attachment_with_integrity_and_url():
    # Plain literal encodings, not produced by engine. 'foobar' is an RFC vector.
    data = bundle({"fullUrl": "urn:uuid:binary", "resource": {"resourceType": "Binary", "id": "b",
                  "contentType": "text/plain", "data": "Zm9vYmFy"}},
                  entry("DocumentReference", "d", content=[{"attachment": {
                      "contentType": "text/plain", "data": "Zm9v", "size": 3,
                      "hash": base64.b64encode(hashlib.sha1(b"foo").digest()).decode(),
                      "url": "urn:uuid:binary", "title": "../../not-a-filename"}}]))
    out = H.parse_fhir(data)
    assert [item["data"] for item in out["blobs"]] == [b"foobar", b"foo"]
    assert out["references"][0]["targets"] == ["/entry/0/resource"]
    assert out["blobs"][0]["sha256"] == hashlib.sha256(b"foobar").hexdigest()


def test_embedded_flag_and_json_input():
    # Independent RFC-compliant standard-library encoder is the test oracle.
    payload = b"%PDF-1.7\nCSCTF{embedded_fhir_document}\n%%EOF"
    data = {"resourceType": "DiagnosticReport", "presentedForm": [{
        "contentType": "application/pdf", "data": base64.b64encode(payload).decode()}]}
    out = H.parse_fhir(json.dumps(data).encode())
    assert out["flags"] == ["CSCTF{embedded_fhir_document}"]
    assert out["blobs"][0]["data"] == payload


@pytest.mark.parametrize("field,value", [("size", 4), ("size", True), ("hash", "Zm9v"),
                                        ("contentType", None), ("data", "bad")])
def test_bad_attachment_metadata(field, value):
    attachment = {"contentType": "text/plain", "data": "Zm9v", field: value}
    with pytest.raises(H.FHIRFormatError):
        H.parse_fhir({"resourceType": "DocumentReference", "content": [{"attachment": attachment}]})


def test_remote_attachment_is_not_opened():
    out = H.parse_fhir({"resourceType": "DocumentReference", "content": [{"attachment": {
        "contentType": "text/plain", "url": "file:///etc/passwd"}}]})
    assert out["blobs"] == []
    assert out["references"][0]["status"] == "unresolved"


def test_published_hl7_ekg_example_prefix():
    # First six samples and metadata from the HL7 R4 sample-data example above.
    sampled = {"origin": {"value": 2048}, "period": 10, "factor": 1.612,
               "lowerLimit": -3300, "upperLimit": 3300, "dimensions": 1,
               "data": "2041 2043 2037 2047 2060 2062"}
    out = H.decode_sampled_data(sampled)
    expected = [float(Decimal(n) * Decimal("1.612") + Decimal("2048"))
                for n in (2041, 2043, 2037, 2047, 2060, 2062)]
    assert [row[0] for row in out["rows"]] == pytest.approx(expected)
    assert out["period_ms"] == 10


def test_sampled_multidimensional_markers_and_default_factor():
    sampled = {"origin": {"value": -3, "unit": "mV"}, "period": 2,
               "dimensions": 3, "data": "1 E 3 L 5 U"}
    out = H.parse_fhir({"resourceType": "Observation", "component": [{"valueSampledData": sampled}]})
    assert out["sampled_data"][0]["rows"] == [[-2.0, "E", 0.0], ["L", 2.0, "U"]]
    assert out["sampled_data"][0]["sample_count"] == 2


@pytest.mark.parametrize("field,value", [("dimensions", 0), ("dimensions", True), ("dimensions", "2"),
    ("period", 0), ("period", float("inf")), ("factor", "1.0"), ("factor", float("nan")),
    ("origin", {}), ("origin", {"value": 0, "unit": 3}), ("data", "1  2"), ("data", "1\n2"), ("data", "nan"),
    ("data", "1e999"), ("data", "1"), ("data", "1 +2"), ("data", "01 2")])
def test_malformed_sampled_data(field, value):
    data = {"origin": {"value": 0}, "period": 1, "dimensions": 2, "data": "1 2", field: value}
    with pytest.raises(H.FHIRFormatError):
        H.decode_sampled_data(data)


@pytest.mark.parametrize("value", [None, [], b"", b"\xff", "{}", '{"resourceType":"Patient","resourceType":"Binary"}',
    '{"resourceType":"Observation","x":NaN}', {"resourceType": 2},
    {"resourceType": "Patient", "id": "bad/id"}, {"resourceType": "Patient", "contained": {}},
    {"resourceType": "Bundle", "entry": [None]}, {"resourceType": "Bundle", "entry": {}},
    {"resourceType": "Patient", "meta": []}, {"resourceType": "Patient", "x": ref(None)}])
def test_bad_fhir_contract(value):
    with pytest.raises(H.FHIRFormatError):
        H.parse_fhir(value)


def test_duplicate_contained_and_unsupported_nesting():
    data = {"resourceType": "Patient", "contained": [{"resourceType": "Organization", "id": "o"}] * 2}
    with pytest.raises(H.FHIRFormatError):
        H.parse_fhir(data)
    data["contained"] = [{"resourceType": "Organization", "id": "o", "contained": [
        {"resourceType": "Practitioner", "id": "p"}]}]
    with pytest.raises(H.FHIRFormatError):
        H.parse_fhir(data)


def test_cycles_and_depth_are_bounded():
    data = {"resourceType": "Patient"}
    data["x"] = data
    with pytest.raises(H.FHIRFormatError):
        H.parse_fhir(data)


def test_input_not_mutated():
    data = bundle(entry("Patient", "p"), entry("Observation", "o", subject=ref("Patient/p")))
    before = copy.deepcopy(data)
    H.parse_fhir(data)
    assert data == before


def test_json_pointer_escaping():
    data = {"resourceType": "Patient", "a/b~c": ref("urn:uuid:absent")}
    assert H.parse_fhir(data)["references"][0]["path"] == "/a~1b~0c/reference"


def test_csv_blobs_safe_names_and_refuse_overwrite(tmp_path):
    data = bundle(entry("Binary", "b", contentType="text/plain", data="Zm9v"),
        entry("Observation", "o", valueSampledData={"origin": {"value": 0}, "period": 10,
             "dimensions": 2, "data": "1 E 2 3"}))
    out = H.parse_fhir(data)
    files = H.extract_report(out, tmp_path)
    assert len(files) == 2
    assert (tmp_path / "blob-0000.bin").read_bytes() == b"foo"
    assert (tmp_path / "samples-0000.csv").read_text().splitlines() == [
        "time_ms,dimension_0,dimension_1", "0.0,1.0,E", "10.0,2.0,3.0"]
    with pytest.raises(H.FHIRFormatError):
        H.extract_report(out, tmp_path)


def test_cli(tmp_path, capsys):
    file = tmp_path / "input.json"
    file.write_text('{"resourceType":"Binary","contentType":"text/plain","data":"Zm9v"}')
    assert H.main([str(file), "--extract-dir", str(tmp_path / "out")]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["blobs"][0]["size"] == 3 and "data" not in report["blobs"][0]
    assert H.main([]) == 2
    assert H.main(["--help"]) == 0
    assert H.main([str(tmp_path / "missing")]) == 2


def test_cli_noninteger_systemexit(monkeypatch):
    def fail(*args, **kwargs):
        raise SystemExit("bad")
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", fail)
    assert H.main([]) == 2
