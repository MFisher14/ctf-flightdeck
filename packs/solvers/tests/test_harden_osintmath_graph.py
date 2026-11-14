"""Independent graph/lead vectors and deterministic fail-closed regressions.

No lookup is performed.  ORCID uses its ISO 7064 check algorithm, LEI/IBAN use
ISO mod-97, VIN uses the published ISO 3779 transliteration/weights, and graph
totals/edges are calculated directly from the synthetic saved records below.
"""
from __future__ import annotations

import base64
import hashlib
import json
import random

import pytest

import osint_entity_graph as graph
import osint_leads as leads


ORCID = "0000-0002-1825-0097"  # checksum-valid public ISO 7064 example
LEI = "HWUPKR0MPOU8FGXBT394"   # checksum-valid ISO 17442 identifier
TARGET = "0x1111111111111111111111111111111111111111"
SENDER = "0x2222222222222222222222222222222222222222"
RECEIVER = "0x3333333333333333333333333333333333333333"


def _mod97(value: str) -> int:
    """Independent alphanumeric ISO mod-97 renderer."""
    digits = "".join(str(ord(char) - 55) if "A" <= char <= "Z" else char
                     for char in value.upper())
    remainder = 0
    for char in digits:
        remainder = (remainder * 10 + int(char)) % 97
    return remainder


def _orcid_check(value: str) -> bool:
    compact = value.replace("-", "").upper()
    total = 0
    for char in compact[:-1]:
        total = (total + int(char)) * 2
    check = (12 - total % 11) % 11
    return compact[-1] == ("X" if check == 10 else str(check))


def test_published_identifier_checks_against_independent_arithmetic():
    assert _orcid_check(ORCID)
    assert _mod97(LEI) == 1
    assert graph.valid_orcid(ORCID) is True
    assert graph.valid_orcid(ORCID[:-1] + "8") is False
    assert graph.valid_lei(LEI) is True
    assert graph.valid_lei(LEI[:-1] + "5") is False


def test_public_entity_graph_vector_from_saved_record_semantics():
    records = [
        {
            "record_kind": "orcid", "source": "ORCID", "orcid-identifier": {"path": ORCID},
            "person": {"name": {"given-names": {"value": "Josiah"},
                                  "family-name": {"value": "Carberry"}}},
        },
        {
            "record_kind": "wikidata", "source": "Wikidata", "id": "Q42",
            "labels": {"en": {"value": "Josiah Carberry"}},
        },
        {
            "record_kind": "gleif", "source": "GLEIF",
            "data": {"id": LEI, "attributes": {"lei": LEI,
                     "entity": {"legalName": {"name": "Apple Inc."}},
                     "registration": {"status": "ISSUED"}}},
        },
    ]
    result = graph.normalize_public_entities(records)
    nodes = {(node["type"], node["value"]): node for node in result["nodes"]}
    assert result["records"] == 3 and result["declined"] == []
    assert ("orcid", ORCID) in nodes and ("lei", LEI) in nodes
    assert ("wikidata_qid", "Q42") in nodes
    assert nodes[("organization_record", "Apple Inc.")]["registration_status"] == "ISSUED"
    assert [edge["relation"] for edge in result["edges"]] == ["claims_public_identifier"] * 3
    assert result["label_correlations"] == [{
        "normalized_label": "josiah carberry",
        "nodes": sorted(node["id"] for node in result["nodes"]
                        if node["value"] == "Josiah Carberry"),
        "candidate_only": True,
    }]
    assert result["identity_verdict"] is None and result["requires_human_pin"] is True


def test_social_graph_shared_attributes_and_email_privacy_vector():
    profiles = [
        {"provider": "github", "handle": "Alice", "display_name": "Alice Smith",
         "location": "Paris", "email": "Alice@example.com",
         "links": ["https://example.com/a"]},
        {"provider": "gitlab", "username": "alice", "name": "ALICE SMITH",
         "location": "Paris", "email": "alice@example.com",
         "links": ["https://example.com/b"]},
        {"provider": "reddit", "username": "bob", "name": "Alice Smith"},
    ]
    result = graph.build_social_evidence_graph("@Alice", profiles)
    digest = hashlib.sha256(b"alice@example.com").hexdigest()
    nodes = {(node["type"], node["value"]): node for node in result["nodes"]}
    assert result["exact_handle"] == "alice" and len(result["accounts"]) == 2
    assert ("email_sha256", digest) in nodes and nodes[("email_sha256", digest)]["redacted"] is True
    assert not any("@" in str(node["value"]) for node in result["nodes"])
    shared = {(row["field"], row["normalized_value"]): row["providers"]
              for row in result["shared_attributes"]}
    assert shared == {
        ("display_name", "alice smith"): ["github", "gitlab"],
        ("email_sha256", digest): ["github", "gitlab"],
        ("linked_domain", "example.com"): ["github", "gitlab"],
        ("location", "paris"): ["github", "gitlab"],
    }
    assert result["conflicts"] == [{"provider": "reddit", "field": "handle", "observed": "bob"}]


def test_social_graph_repository_relation_uses_correct_noun():
    result = graph.build_social_evidence_graph("alice", [
        {"provider": "github", "handle": "alice", "repositories": ["project"]},
        {"provider": "gitlab", "handle": "alice", "repositories": ["project"]},
    ])
    assert {node["type"] for node in result["nodes"] if node["value"] == "project"} == {"repository"}


def test_saved_eth_flow_graph_totals_chronology_and_edges():
    transactions = [
        {"hash": "0x" + "a" * 64, "from": SENDER, "to": TARGET, "value": "25",
         "timeStamp": "2020-01-01T00:00:00Z"},
        {"hash": "0x" + "b" * 64, "from": TARGET, "to": RECEIVER, "value": 7,
         "timeStamp": 1_577_836_801},
        {"hash": "0x" + "c" * 64, "from": TARGET, "to": TARGET, "value": "3",
         "timeStamp": 1_577_836_802},
        {"hash": "0x" + "d" * 64, "from": SENDER, "to": RECEIVER, "value": 99,
         "timeStamp": 1_577_836_803},
        {"hash": "0x" + "a" * 64, "from": SENDER, "to": TARGET, "value": "25"},
    ]
    result = graph.analyze_saved_wallet_flows("eth", TARGET, transactions)
    assert result["transactions_seen"] == 5
    assert result["transactions_used"] == 3 and result["declined_transactions"] == 2
    assert result["total_in_base_units"] == 25 + 3
    assert result["total_out_base_units"] == 7 + 3
    assert result["counterparties"] == [SENDER, RECEIVER]
    assert [row["timestamp"] for row in result["chronology"]] == [
        1_577_836_800, 1_577_836_801, 1_577_836_802]
    assert {edge["relation"] for edge in result["edges"]} == {
        "funds_transaction", "pays", "outgoing_transaction", "self_transfer_in", "self_transfer_out"}
    assert all(edge["verified_from_record"] is True for edge in result["edges"])


def _json_segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def test_lead_vectors_vin_iban_cve_jwt_and_ranking():
    vin = "1M8GDM9AXKP042788"  # ISO 3779 worked example
    iban = "GB82WEST12345698765432"
    token = _json_segment({"alg": "none", "typ": "JWT"}) + "." + \
        _json_segment({"sub": "CSCTF{offline}", "exp": 1_800_000_000}) + ".synthetic"
    text = f"CVE_2021_44228 VIN {vin} IBAN {iban} token {token}"
    extracted = leads.extract_extra(text)
    assert _mod97(iban[4:] + iban[:4]) == 1
    assert extracted["cve"] == ["CVE-2021-44228"]
    assert extracted["vin"] == [vin] and extracted.get("vin_candidate", []) == []
    assert extracted["iban"] == [iban] and extracted.get("iban_candidate", []) == []
    assert extracted["jwt"] == [token]
    assert leads.jwt_claims(token) == {
        "header": {"alg": "none", "typ": "JWT"},
        "payload": {"sub": "CSCTF{offline}", "exp": 1_800_000_000},
    }
    ranked = leads.rank({"cve": {"CVE-2021-44228": ["a.txt", "b.txt"]},
                         "vin": {vin: ["a.txt"]}})
    assert [(row["kind"], row["score"]) for row in ranked] == [("cve", 90), ("vin", 74)]


@pytest.mark.parametrize("text", [
    "40.748400, -73.985700",
    "40.7484 N, 73.9857 W",
    "40\N{DEGREE SIGN}44'54.24\"N, 73\N{DEGREE SIGN}59'08.52\"W",
])
def test_coordinate_formats_normalize_to_known_empire_state_pair(text):
    expected = "40.748400, -73.985700"
    assert leads.extract_gps(text) == [expected]
    assert leads.maps_link(text) == "https://www.google.com/maps?q=40.748400,-73.985700"


@pytest.mark.parametrize("reader", [leads.extract_gps, leads.maps_link], ids=["extract_gps", "maps_link"])
def test_malformed_dms_components_are_rejected(reader):
    value = "10\N{DEGREE SIGN} 99' 00\" N 20\N{DEGREE SIGN} 00' 00\" E"
    assert reader(value) in ([], None)


@pytest.mark.parametrize("reader", [leads.extract_gps, leads.maps_link], ids=["extract_gps", "maps_link"])
def test_malformed_dms_axis_order_is_rejected(reader):
    value = "10\N{DEGREE SIGN} 00' 00\" E 20\N{DEGREE SIGN} 00' 00\" N"
    assert reader(value) in ([], None)


def test_malformed_coordinate_string_fuzz_returns_cleanly():
    rng = random.Random(0x051A7)
    corpus = ["", "garbage", "nan, inf", "91.000, 181.000", "0.000, 0.000",
              "40.0N", "40\N{DEGREE SIGN}", "40;", "--1.000, +2.000", "\ud800"]
    corpus.extend(rng.randbytes(length).decode("latin-1") for length in range(1, 128, 7))
    for value in corpus:
        assert isinstance(leads.extract_gps(value), list)
        assert leads.maps_link(value) is None or isinstance(leads.maps_link(value), str)
        assert isinstance(leads.extract_extra(value), dict)
        assert isinstance(leads.jwt_claims(value), dict)


_WRONG_TYPE_CASES = [
    pytest.param(leads.extract_gps, None, [], id="gps-none"),
    pytest.param(leads.extract_gps, b"coord", [], id="gps-bytes"),
    pytest.param(leads.extract_gps, {"lat": 1}, [], id="gps-dict"),
    pytest.param(leads.extract_extra, 7, {}, id="extra-int"),
    pytest.param(leads.extract_extra, b"lead", {}, id="extra-bytes"),
    pytest.param(leads.jwt_claims, None, {}, id="jwt-none"),
    pytest.param(leads.jwt_claims, b"token", {}, id="jwt-bytes"),
]


@pytest.mark.parametrize("reader,value,expected", _WRONG_TYPE_CASES)
def test_lead_parsers_wrong_types_fail_closed(reader, value, expected):
    assert reader(value) == expected


@pytest.mark.parametrize("value", [None, b"coord", {"lat": 1}, 7, []])
def test_maps_link_non_text_fuzz_fails_closed(value):
    assert leads.maps_link(value) is None


def test_entity_graph_malformed_fuzz_uses_only_declared_error():
    rng = random.Random(0xE1717)
    malformed = [None, 0, True, "", b"", {}, [], [None],
                 [{"record_kind": "orcid", "orcid": "bad"}],
                 [{"provider": "x", "handle": "\ud800"}],
                 [rng.randbytes(length) for length in (0, 1, 7, 31, 127)]]
    readers = [
        lambda value: graph.normalize_public_entities(value),
        lambda value: graph.build_social_evidence_graph("alice", value),
        lambda value: graph.analyze_saved_wallet_flows("eth", TARGET, value),
    ]
    for reader in readers:
        for value in malformed:
            try:
                result = reader(value)
            except graph.EntityGraphError:
                continue
            assert isinstance(result, dict)


def test_graph_resource_bounds_raise_declared_error(monkeypatch):
    monkeypatch.setattr(graph, "MAX_RECORDS", 2)
    with pytest.raises(graph.EntityGraphError):
        graph.normalize_public_entities([{}, {}, {}])
    deeply_nested = value = {}
    for _ in range(graph.MAX_DEPTH + 2):
        value["child"] = {}
        value = value["child"]
    with pytest.raises(graph.EntityGraphError):
        graph.normalize_public_entities([deeply_nested])
