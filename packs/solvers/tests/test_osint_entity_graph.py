from __future__ import annotations

import hashlib
import itertools
import json
import sys
from pathlib import Path

import pytest


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))
import osint_entity_graph as E  # noqa: E402


ORCID = "0000-0002-1825-0097"
LEI = "5493001KJTIIGC8Y1R12"
BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
BTC_OTHER = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
BTC_THIRD = "1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp"
ETH = "0x" + "1" * 40
ETH_OTHER = "0x" + "2" * 40
ETH_THIRD = "0x" + "3" * 40


def assert_human(report):
    assert report["requires_human_pin"] is True
    assert report["automatic_answer"] is None
    assert report["identity_verdict"] is None
    assert report["attribution_verdict"] is None
    json.dumps(report, allow_nan=False)


def test_public_identifier_checksums_and_saved_record_normalization():
    assert E.valid_orcid(ORCID)
    assert not E.valid_orcid(ORCID[:-1] + "8")
    assert E.valid_lei(LEI)
    assert not E.valid_lei(LEI[:-1] + "3")
    records = [
        {
            "provider": "ORCID saved record",
            "orcid-identifier": {"path": ORCID},
            "person": {"name": {"given-names": {"value": "Alice"},
                                  "family-name": {"value": "Example"}}},
        },
        {
            "provider": "GLEIF saved record",
            "data": {"id": LEI, "attributes": {"lei": LEI,
                     "entity": {"legalName": {"name": "Alice Example"}},
                     "registration": {"status": "ISSUED"}}},
        },
        {
            "provider": "Wikidata saved record",
            "entities": {"Q42": {"labels": {"en": {"value": "Alice Example"}}}},
        },
    ]
    report = E.normalize_public_entities(records)
    assert len(report["roots"]) == 3
    assert report["declined"] == []
    assert report["label_correlations"] == [{
        "normalized_label": "alice example",
        "nodes": sorted(report["roots"]),
        "candidate_only": True,
    }]
    assert {node["type"] for node in report["nodes"]} >= {"orcid", "lei", "wikidata_qid"}
    assert_human(report)


def test_bad_saved_records_are_declined_without_identity_verdicts():
    report = E.normalize_public_entities([
        {"provider": "orcid", "orcid": "0000-0002-1825-0098"},
        {"provider": "unknown", "id": "not-a-public-id"},
    ])
    assert len(report["declined"]) == 2
    assert report["roots"] == []
    assert_human(report)


def test_exact_handle_social_graph_hashes_email_and_reports_conflicts():
    email = "challenge-clue@example.net"
    report = E.build_social_evidence_graph("@Alice_7", [
        {"provider": "GitHub", "login": "Alice_7", "name": "Alice Example",
         "avatar_hash": "abc123", "location": "Bucharest",
         "email": email, "links": ["https://portfolio.example/about"],
         "repositories": ["solver"], "packages": ["ctf-kit"]},
        {"provider": "GitLab", "username": "alice_7", "display_name": "Alice Example",
         "avatar_hash": "abc123", "email": email,
         "links": ["https://portfolio.example/projects",
                   "https://portfolio.example:bad/malformed",
                   "https://2026.ctf-platform.example/forbidden"]},
        {"provider": "Reddit", "username": "different", "name": "Alice Example"},
    ])
    assert len(report["accounts"]) == 2
    assert report["conflicts"] == [{"provider": "reddit", "field": "handle",
                                     "observed": "different"}]
    shared = {(row["field"], row["normalized_value"]): row for row in report["shared_attributes"]}
    assert ("display_name", "alice example") in shared
    assert ("avatar_hash", "abc123") in shared
    assert ("linked_domain", "portfolio.example") in shared
    digest = hashlib.sha256(email.casefold().encode()).hexdigest()
    assert ("email_sha256", digest) in shared
    serialized = json.dumps(report)
    assert email not in serialized
    assert "ctf-platform.example" not in serialized
    assert ":bad" not in serialized
    assert "common ownership" in report["warning"]
    assert_human(report)


def test_eth_saved_flows_preserve_chronology_and_decline_unrelated_transactions():
    report = E.analyze_saved_wallet_flows("eth", ETH, [
        {"hash": "0x" + "a" * 64, "from": ETH_OTHER, "to": ETH,
         "value": "25", "timeStamp": "1700000000"},
        {"hash": "0x" + "b" * 64, "from": ETH, "to": ETH_THIRD,
         "value": 7, "timestamp": "2023-11-15T00:00:00Z"},
        {"hash": "0x" + "c" * 64, "from": ETH_OTHER, "to": ETH_THIRD,
         "value": 999, "timeStamp": "1700000001"},
        {"hash": "0x" + "d" * 64, "from": ETH, "to": ETH_THIRD,
         "value": 1.25, "timeStamp": "1700000002"},
    ])
    assert report["network"] == "evm"
    assert report["transactions_used"] == 2
    assert report["declined_transactions"] == 2
    assert report["total_in_base_units"] == 25
    assert report["total_out_base_units"] == 7
    tx_values = {node["value"] for node in report["nodes"] if node["type"] == "transaction"}
    assert tx_values == {"0x" + "a" * 64, "0x" + "b" * 64}
    assert report["chronology"][0]["transaction"] == "0x" + "a" * 64
    assert_human(report)


def test_btc_saved_flows_use_checksum_network_and_label_heuristics_only():
    report = E.analyze_saved_wallet_flows("btc", BTC, [{
        "txid": "e" * 64,
        "status": {"block_time": 1_700_000_000},
        "vin": [
            {"prevout": {"scriptpubkey_address": BTC, "value": 1_000}},
            {"prevout": {"scriptpubkey_address": BTC_OTHER, "value": 500}},
        ],
        "vout": [
            {"scriptpubkey_address": BTC, "value": 200},
            {"scriptpubkey_address": BTC_THIRD, "value": 1_200},
        ],
    }])
    assert report["network"] == "mainnet"
    assert report["total_in_base_units"] == 200
    assert report["total_out_base_units"] == 1_000
    assert report["heuristics"] == [{
        "kind": "common_input_candidate", "transaction": "e" * 64,
        "addresses": [BTC_OTHER], "verified": False,
        "reason": "common-input ownership may fail for CoinJoin or shared custody",
    }]
    assert all(node.get("network") == "mainnet" for node in report["nodes"]
               if node["type"] == "wallet")
    assert_human(report)


def test_eth_self_transfer_counts_both_sides_without_self_counterparty():
    report = E.analyze_saved_wallet_flows("eth", ETH, [{
        "hash": "0x" + "9" * 64, "from": ETH, "to": ETH,
        "value": "12", "timeStamp": "1700000000",
    }])
    assert report["total_in_base_units"] == 12
    assert report["total_out_base_units"] == 12
    assert report["counterparties"] == []
    assert {edge["relation"] for edge in report["edges"]} == {
        "self_transfer_in", "self_transfer_out"}
    assert_human(report)


def test_wallet_checksum_and_cross_network_fail_closed():
    with pytest.raises(E.EntityGraphError, match="does not match"):
        E.analyze_saved_wallet_flows("btc", BTC[:-1] + "b", [{"txid": "f" * 64}])
    testnet = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
    report = E.analyze_saved_wallet_flows("btc", BTC, [{
        "txid": "f" * 64,
        "vin": [{"prevout": {"scriptpubkey_address": testnet, "value": 1}}],
        "vout": [{"scriptpubkey_address": BTC, "value": 1}],
    }])
    assert report["transactions_used"] == 1
    assert testnet not in json.dumps(report)


def test_zero_value_and_duplicate_transaction_ids_are_handled_deterministically():
    unrelated = {
        "txid": "7" * 64,
        "vin": [{"prevout": {"scriptpubkey_address": BTC_OTHER, "value": 1}}],
        "vout": [{"scriptpubkey_address": BTC_THIRD, "value": 1}],
    }
    relevant = {
        "txid": "7" * 64,
        "vin": [{"prevout": {"scriptpubkey_address": BTC, "value": 0}}],
        "vout": [{"scriptpubkey_address": BTC, "value": 0}],
    }
    report = E.analyze_saved_wallet_flows("btc", BTC, [unrelated, relevant, relevant])
    assert report["transactions_used"] == 1
    assert report["declined_transactions"] == 2
    assert report["total_in_base_units"] == report["total_out_base_units"] == 0
    assert len([node for node in report["nodes"] if node["type"] == "transaction"]) == 1
    assert_human(report)


def test_top_level_generators_are_consumed_only_to_cap_plus_one(monkeypatch):
    monkeypatch.setattr(E, "MAX_RECORDS", 2)
    produced = []

    def forever():
        for index in itertools.count():
            produced.append(index)
            yield {"provider": "unknown", "id": str(index)}

    with pytest.raises(E.EntityGraphError, match="exceeds the 2 item cap"):
        E.normalize_public_entities(forever())
    assert produced == [0, 1, 2]
    with pytest.raises(E.EntityGraphError, match="iterable"):
        E.normalize_public_entities(42)


def test_controls_and_surrogates_are_declined_before_becoming_graph_values():
    with pytest.raises(E.EntityGraphError, match="controls"):
        E.build_social_evidence_graph("alice\n", [{"provider": "x", "username": "alice"}])
    with pytest.raises(E.EntityGraphError, match="surrogate"):
        E.normalize_public_entities([{"provider": "unknown", "value": "bad\ud800"}])


def test_transaction_endpoint_caps_and_strict_json_finiteness(monkeypatch):
    monkeypatch.setattr(E, "MAX_TX_ENDPOINTS", 2)
    report = E.analyze_saved_wallet_flows("btc", BTC, [{
        "txid": "1" * 64,
        "vin": [{"prevout": {"scriptpubkey_address": BTC, "value": 1}}] * 3,
        "vout": [{"scriptpubkey_address": BTC, "value": 1}],
        "noise": float("nan"),
    }])
    assert report["transactions_used"] == 0
    assert report["declined_transactions"] == 1
    json.dumps(report, allow_nan=False)
