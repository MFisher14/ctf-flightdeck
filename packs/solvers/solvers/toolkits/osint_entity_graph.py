#!/usr/bin/env python3
"""Offline entity, social-account, and public-chain evidence graphs.

Consumes saved public records and explorer responses only. It exposes relationships,
chronology, and conflicts without fetching or making identity/attribution verdicts.
E-mail values are retained only as SHA-256 digests.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import re
import urllib.parse
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # package import in tests; direct import when used as a script
    from . import blockchain
except ImportError:  # pragma: no cover - script execution path
    import blockchain  # type: ignore

MAX_RECORDS = 2_000
MAX_NODES = 8_000
MAX_EDGES = 16_000
MAX_TEXT = 4_096
MAX_DEPTH = 12
MAX_JSON_NODES = 80_000
MAX_TRANSACTIONS = 4_000
MAX_TX_ENDPOINTS = 256

ORCID_RE = re.compile(r"\d{4}-\d{4}-\d{4}-\d{3}[\dX]\Z", re.I)
LEI_RE = re.compile(r"[A-Z0-9]{20}\Z")
QID_RE = re.compile(r"Q[1-9]\d{0,11}\Z", re.I)
HANDLE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}\Z")
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]{1,255}\Z")


class EntityGraphError(ValueError):
    pass


def _take(values: Iterable[Any], cap: int, field: str, *, minimum: int = 0) -> list[Any]:
    if isinstance(values, (str, bytes, bytearray, Mapping)):
        raise EntityGraphError(f"{field} must be an iterable of records")
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise EntityGraphError(f"{field} must be an iterable of records") from exc
    rows = []
    for _ in range(cap + 1):
        try:
            rows.append(next(iterator))
        except StopIteration:
            break
    if len(rows) > cap:
        raise EntityGraphError(f"{field} exceeds the {cap} item cap")
    if len(rows) < minimum:
        raise EntityGraphError(f"{field} needs at least {minimum} item(s)")
    return rows


def _text(value: Any, field: str, limit: int = MAX_TEXT, *, empty: bool = False) -> str:
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise EntityGraphError(f"{field} must be text")
    raw = str(value)
    result = raw.strip()
    if ((not result and not empty) or len(result) > limit
            or any(ord(char) < 0x20 for char in raw)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in raw)):
        raise EntityGraphError(f"{field} is empty, overlong, or contains controls")
    return result


def _bounded_json(value: Any, *, budget: list[int] | None = None, depth: int = 0) -> Any:
    if budget is None:
        budget = [MAX_JSON_NODES]
    if budget[0] <= 0 or depth > MAX_DEPTH:
        raise EntityGraphError("saved JSON exceeds structural bounds")
    budget[0] -= 1
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                raise EntityGraphError("saved JSON contains a surrogate code point")
            return value[:MAX_TEXT]
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {str(key)[:128]: _bounded_json(item, budget=budget, depth=depth + 1)
                for key, item in list(value.items())[:512]}
    if isinstance(value, (list, tuple)):
        return [_bounded_json(item, budget=budget, depth=depth + 1) for item in value[:1_024]]
    return str(value)[:MAX_TEXT]


def _report(kind: str, **values: Any) -> dict[str, Any]:
    return {"kind": kind, **values, "identity_verdict": None, "attribution_verdict": None,
            "automatic_answer": None, "requires_human_pin": True,
            "note": "relationship evidence only; the player must corroborate and make the final pin"}


def valid_orcid(value: str) -> bool:
    raw = str(value).strip().upper()
    if not ORCID_RE.fullmatch(raw):
        return False
    digits, total = raw.replace("-", ""), 0
    for char in digits[:-1]:
        total = (total + int(char)) * 2
    remainder = (12 - total % 11) % 11
    return digits[-1] == ("X" if remainder == 10 else str(remainder))


def valid_lei(value: str) -> bool:
    raw = str(value).strip().upper()
    if not LEI_RE.fullmatch(raw):
        return False
    expanded = "".join(str(ord(char) - 55) if char.isalpha() else char for char in raw)
    return int(expanded) % 97 == 1


def _first_string(value: Any, *paths: Sequence[str]) -> str | None:
    for path in paths:
        current = value
        for key in path:
            if not isinstance(current, Mapping):
                current = None
                break
            current = current.get(key)
        if isinstance(current, Mapping) and isinstance(current.get("value"), str):
            current = current["value"]
        if isinstance(current, str) and current.strip():
            return current.strip()[:MAX_TEXT]
    return None


def _add_node(nodes: dict[str, dict[str, Any]], kind: str, value: str,
              source: str, **fields: Any) -> str:
    digest = hashlib.sha256(f"{kind}\0{value.casefold()}".encode()).hexdigest()[:20]
    node_id = f"{kind}:{digest}"
    if node_id not in nodes and len(nodes) >= MAX_NODES:
        raise EntityGraphError("entity node cap reached")
    node = nodes.setdefault(node_id, {"id": node_id, "type": kind, "value": value, "sources": []})
    if source not in node["sources"]:
        node["sources"].append(source)
        node["sources"].sort()
    for key, item in fields.items():
        if item not in (None, "", [], {}):
            node[key] = item
    return node_id


def _add_edge(edges: list[dict[str, Any]], left: str, right: str, relation: str,
              source: str, *, verified: bool = False, **fields: Any) -> None:
    if len(edges) >= MAX_EDGES:
        raise EntityGraphError("entity edge cap reached")
    row = {"from": left, "to": right, "relation": relation, "source": source,
           "verified_from_record": bool(verified), **fields}
    if row not in edges:
        edges.append(row)


def _orcid_record(record: Mapping[str, Any], source: str, nodes: dict[str, dict[str, Any]],
                  edges: list[dict[str, Any]]) -> str:
    identifier = _first_string(record, ("orcid-identifier", "path"), ("orcid",), ("id",))
    if not identifier or not valid_orcid(identifier):
        raise EntityGraphError("ORCID record lacks a checksum-valid ORCID")
    person = record.get("person") if isinstance(record.get("person"), Mapping) else record
    given = _first_string(person, ("name", "given-names"), ("given_name",)) or ""
    family = _first_string(person, ("name", "family-name"), ("family_name",)) or ""
    label = " ".join(part for part in (given, family) if part).strip() or identifier.upper()
    root = _add_node(nodes, "person_record", label, source, record_kind="orcid")
    identifier_node = _add_node(nodes, "orcid", identifier.upper(), source)
    _add_edge(edges, root, identifier_node, "claims_public_identifier", source, verified=True)
    return root


def _gleif_record(record: Mapping[str, Any], source: str, nodes: dict[str, dict[str, Any]],
                  edges: list[dict[str, Any]]) -> str:
    data = record.get("data") if isinstance(record.get("data"), Mapping) else record
    attrs = data.get("attributes") if isinstance(data.get("attributes"), Mapping) else data
    lei = str(attrs.get("lei", data.get("id", record.get("lei", "")))).strip().upper()
    if not valid_lei(lei):
        raise EntityGraphError("GLEIF record lacks a checksum-valid LEI")
    entity = attrs.get("entity") if isinstance(attrs.get("entity"), Mapping) else attrs
    legal = entity.get("legalName")
    if isinstance(legal, Mapping):
        legal = legal.get("name")
    name = _text(legal or lei, "GLEIF legal name")
    root = _add_node(nodes, "organization_record", name, source, record_kind="gleif")
    identifier_node = _add_node(nodes, "lei", lei, source)
    _add_edge(edges, root, identifier_node, "claims_public_identifier", source, verified=True)
    registration = attrs.get("registration", {})
    if isinstance(registration, Mapping) and isinstance(registration.get("status"), str):
        nodes[root]["registration_status"] = registration["status"][:128]
    return root


def _wikidata_record(record: Mapping[str, Any], source: str, nodes: dict[str, dict[str, Any]],
                     edges: list[dict[str, Any]]) -> str:
    entities = record.get("entities")
    if isinstance(entities, Mapping) and entities:
        candidates = [(str(key), value) for key, value in list(entities.items())[:32]
                      if isinstance(value, Mapping)]
        if len(candidates) != 1:
            raise EntityGraphError("Wikidata input must contain exactly one entity")
        qid, data = candidates[0]
    else:
        qid, data = str(record.get("id", "")), record
    qid = qid.upper()
    if not QID_RE.fullmatch(qid):
        raise EntityGraphError("Wikidata record lacks an exact QID")
    labels = data.get("labels") if isinstance(data.get("labels"), Mapping) else {}
    english = labels.get("en") if isinstance(labels.get("en"), Mapping) else None
    label = english.get("value") if isinstance(english, Mapping) else None
    root = _add_node(nodes, "public_entity_record", _text(label or qid, "Wikidata label"),
                     source, record_kind="wikidata")
    identifier_node = _add_node(nodes, "wikidata_qid", qid, source)
    _add_edge(edges, root, identifier_node, "claims_public_identifier", source, verified=True)
    return root


def normalize_public_entities(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Normalize saved ORCID/GLEIF/single-QID records into a typed graph."""
    rows = _take(records, MAX_RECORDS, "entity records", minimum=1)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    declined, roots = [], []
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise EntityGraphError("entity records must be mappings")
        row = _bounded_json(raw)
        source = _text(row.get("source", row.get("provider", f"record-{index}")), "record source", 128)
        kind = str(row.get("record_kind", row.get("provider", ""))).casefold()
        try:
            if "orcid" in kind or "orcid-identifier" in row:
                roots.append(_orcid_record(row, source, nodes, edges))
            elif "gleif" in kind or "lei" in row or (isinstance(row.get("data"), Mapping)
                                                        and "attributes" in row["data"]):
                roots.append(_gleif_record(row, source, nodes, edges))
            elif "wikidata" in kind or "entities" in row or QID_RE.fullmatch(str(row.get("id", ""))):
                roots.append(_wikidata_record(row, source, nodes, edges))
            else:
                declined.append({"source": source, "reason": "unsupported saved public-record shape"})
        except EntityGraphError as exc:
            declined.append({"source": source, "reason": str(exc)[:300]})
    labels: dict[str, list[str]] = defaultdict(list)
    for node in nodes.values():
        if node["type"].endswith("record"):
            labels[" ".join(str(node["value"]).casefold().split())].append(node["id"])
    correlations = [{"normalized_label": label, "nodes": sorted(ids), "candidate_only": True}
                    for label, ids in labels.items() if label and len(ids) > 1]
    return _report("public_entity_graph", records=len(rows), roots=roots,
                   nodes=sorted(nodes.values(), key=lambda item: item["id"]),
                   edges=sorted(edges, key=lambda item: (item["from"], item["to"], item["relation"])),
                   label_correlations=sorted(correlations, key=lambda item: item["normalized_label"]),
                   declined=declined)


def _canonical_handle(value: Any) -> str:
    raw = _text(value, "exact handle", 128).lstrip("@")
    if not HANDLE_RE.fullmatch(raw) or "@" in raw:
        raise EntityGraphError("invalid exact handle")
    return raw.casefold()


def _public_url(value: Any) -> tuple[str, str] | None:
    if (not isinstance(value, str) or not value.strip()
            or any(ord(char) < 0x20 for char in value)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
        return None
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password or port not in (None, 80, 443)):
        return None
    try:
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").casefold()
    except UnicodeError:
        return None
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        address = None
    if ((address is not None and not address.is_global) or host == "localhost"
            or host.endswith(".localhost") or host == "ctf-platform.example"
            or host.endswith(".ctf-platform.example")):
        return None
    return value.strip()[:2_048], host


def build_social_evidence_graph(exact_handle: str, profiles: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    handle = _canonical_handle(exact_handle)
    rows = _take(profiles, MAX_RECORDS, "profile records", minimum=1)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    accounts, conflicts = [], []
    values_by_field: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise EntityGraphError("profile records must be mappings")
        row = _bounded_json(raw)
        provider = _text(row.get("provider", f"provider-{index}"), "profile provider", 128).casefold()
        observed = row.get("handle", row.get("username", row.get("login")))
        try:
            observed_handle = _canonical_handle(observed)
        except EntityGraphError:
            observed_handle = ""
        if observed_handle != handle:
            conflicts.append({"provider": provider, "field": "handle", "observed": str(observed)[:128]})
            continue
        account = _add_node(nodes, "public_account", f"{provider}:{handle}", provider,
                            provider=provider, exact_handle=handle)
        accounts.append(account)
        for field, value in (("display_name", row.get("display_name", row.get("name"))),
                             ("avatar_hash", row.get("avatar_hash")),
                             ("location", row.get("location"))):
            if isinstance(value, str) and value.strip():
                try:
                    clean = _text(value, field, 512)
                except EntityGraphError:
                    continue
                attribute = _add_node(nodes, field, clean, provider)
                _add_edge(edges, account, attribute, f"observed_{field}", provider, verified=True)
                values_by_field[field][clean.casefold()].add(provider)
        raw_links = row.get("links", [])
        if isinstance(raw_links, list):
            for url in raw_links[:64]:
                parsed = _public_url(url)
                if not parsed:
                    continue
                clean_url, host = parsed
                host_node = _add_node(nodes, "linked_domain", host, provider)
                _add_edge(edges, account, host_node, "links_domain", provider, verified=True,
                          source_url=clean_url)
                values_by_field["linked_domain"][host].add(provider)
        email = row.get("email")
        if isinstance(email, str) and EMAIL_RE.fullmatch(email.strip()):
            digest = hashlib.sha256(email.strip().casefold().encode()).hexdigest()
            email_node = _add_node(nodes, "email_sha256", digest, provider, redacted=True)
            _add_edge(edges, account, email_node, "claims_email_digest", provider, verified=True)
            values_by_field["email_sha256"][digest].add(provider)
        for key in ("repositories", "packages"):
            singular = key[:-3] + "y" if key.endswith("ies") else key[:-1]
            items = row.get(key, [])
            if isinstance(items, list):
                for item in items[:128]:
                    if isinstance(item, str) and item.strip():
                        try:
                            clean = _text(item, singular, 256)
                        except EntityGraphError:
                            continue
                        artifact = _add_node(nodes, singular, clean, provider)
                        _add_edge(edges, account, artifact, f"publishes_{singular}", provider, verified=True)
                        values_by_field[singular][clean.casefold()].add(provider)
    shared = [{"field": field, "normalized_value": value, "providers": sorted(providers),
               "candidate_only": True}
              for field, values in values_by_field.items() for value, providers in values.items()
              if len(providers) >= 2]
    return _report("social_evidence_graph", exact_handle=handle, accounts=sorted(set(accounts)),
                   nodes=sorted(nodes.values(), key=lambda item: item["id"]),
                   edges=sorted(edges, key=lambda item: (item["from"], item["to"], item["relation"])),
                   shared_attributes=sorted(shared, key=lambda item: (item["field"], item["normalized_value"])),
                   conflicts=conflicts,
                   warning="same handle or shared public attribute is not proof of common ownership")


def _timestamp(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        result = int(value)
        return result if 0 <= result <= 4_102_444_800 else None
    if isinstance(value, str):
        raw = value.strip().replace("Z", "+00:00")
        if raw.isdigit():
            return _timestamp(int(raw))
        try:
            stamp = datetime.fromisoformat(raw)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            return _timestamp(stamp.timestamp())
        except (ValueError, OverflowError):
            return None
    return None


def _amount(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        number = int(value.strip())
    else:
        return None
    return number if 0 <= number < (1 << 256) else None


def _wallet_shape(chain: str, value: Any) -> tuple[str, str]:
    address = _text(value, "wallet address", 128)
    if chain == "btc":
        classified = blockchain.classify_btc_address(address)
        if isinstance(classified, Mapping) and classified.get("kind") != "wif":
            canonical = address.casefold() if address.lower().startswith(("bc1", "tb1", "bcrt1")) else address
            return canonical, str(classified.get("network", "unknown"))
    if chain == "eth":
        classified = blockchain.classify_eth_address(address)
        if isinstance(classified, Mapping) and classified.get("checksum") != "invalid":
            return address.casefold(), "evm"
    raise EntityGraphError("wallet address does not match the selected chain")


def analyze_saved_wallet_flows(chain: str, address: str,
                               transactions: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    normalized_chain = str(chain).strip().casefold()
    if normalized_chain not in {"btc", "eth"}:
        raise EntityGraphError("chain must be btc or eth")
    target, target_network = _wallet_shape(normalized_chain, address)
    rows = _take(transactions, MAX_TRANSACTIONS, "saved transactions", minimum=1)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    wallet_node = _add_node(nodes, "wallet", target, "saved-explorer", chain=normalized_chain,
                            network=target_network)
    chronology, heuristics, counterparties = [], [], set()
    total_in = total_out = declined = 0
    seen_transactions: set[str] = set()

    def endpoint(value: Any) -> str | None:
        try:
            candidate, network = _wallet_shape(normalized_chain, value)
            return candidate if network == target_network else None
        except EntityGraphError:
            return None

    for raw in rows:
        if not isinstance(raw, Mapping):
            raise EntityGraphError("saved transactions must be mappings")
        row = _bounded_json(raw)
        txid = str(row.get("txid", row.get("hash", ""))).strip()
        if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{64}", txid):
            declined += 1
            continue
        txid = txid.casefold().removeprefix("0x")
        txid = ("0x" if normalized_chain == "eth" else "") + txid
        if txid in seen_transactions:
            declined += 1
            continue
        stamp = _timestamp(row.get("timestamp", row.get("timeStamp")))
        if stamp is None and isinstance(row.get("status"), Mapping):
            stamp = _timestamp(row["status"].get("block_time"))
        if normalized_chain == "eth":
            sender, receiver = endpoint(row.get("from")), endpoint(row.get("to"))
            amount = _amount(row.get("value", 0))
            if not sender or not receiver or amount is None:
                declined += 1
                continue
            if sender != target and receiver != target:
                declined += 1
                continue
            seen_transactions.add(txid)
            tx_node = _add_node(nodes, "transaction", txid, "saved-explorer")
            if sender == target and receiver == target:
                total_out += amount
                total_in += amount
                _add_edge(edges, wallet_node, tx_node, "self_transfer_out", "saved-explorer",
                          verified=True, amount=amount)
                _add_edge(edges, tx_node, wallet_node, "self_transfer_in", "saved-explorer",
                          verified=True, amount=amount)
                other = None
            elif sender == target:
                total_out += amount
                other = receiver
                _add_edge(edges, wallet_node, tx_node, "outgoing_transaction", "saved-explorer", verified=True, amount=amount)
                _add_edge(edges, tx_node, _add_node(nodes, "wallet", other, "saved-explorer", chain="eth",
                                                    network=target_network),
                          "pays", "saved-explorer", verified=True, amount=amount)
            elif receiver == target:
                total_in += amount
                other = sender
                _add_edge(edges, _add_node(nodes, "wallet", other, "saved-explorer", chain="eth",
                                          network=target_network),
                          tx_node, "funds_transaction", "saved-explorer", verified=True, amount=amount)
                _add_edge(edges, tx_node, wallet_node, "pays", "saved-explorer", verified=True, amount=amount)
            else:
                declined += 1
                continue
            if other is not None:
                counterparties.add(other)
        else:
            vins, vouts = row.get("vin", []), row.get("vout", [])
            if (not isinstance(vins, list) or not isinstance(vouts, list)
                    or len(vins) > MAX_TX_ENDPOINTS or len(vouts) > MAX_TX_ENDPOINTS):
                declined += 1
                continue
            inputs, outputs = [], []
            for item in vins[:MAX_TX_ENDPOINTS]:
                prev = item.get("prevout", {}) if isinstance(item, Mapping) else {}
                if isinstance(prev, Mapping):
                    wallet, amount = endpoint(prev.get("scriptpubkey_address")), _amount(prev.get("value"))
                    if wallet and amount is not None:
                        inputs.append((wallet, amount))
            for item in vouts[:MAX_TX_ENDPOINTS]:
                if isinstance(item, Mapping):
                    wallet, amount = endpoint(item.get("scriptpubkey_address")), _amount(item.get("value"))
                    if wallet and amount is not None:
                        outputs.append((wallet, amount))
            if not inputs and not outputs:
                declined += 1
                continue
            target_spent = sum(amount for wallet, amount in inputs if wallet == target)
            target_received = sum(amount for wallet, amount in outputs if wallet == target)
            target_in_inputs = any(wallet == target for wallet, _amount_value in inputs)
            target_in_outputs = any(wallet == target for wallet, _amount_value in outputs)
            if not target_in_inputs and not target_in_outputs:
                declined += 1
                continue
            seen_transactions.add(txid)
            tx_node = _add_node(nodes, "transaction", txid, "saved-explorer")
            total_out += target_spent
            total_in += target_received
            for wallet, amount in inputs:
                node = wallet_node if wallet == target else _add_node(
                    nodes, "wallet", wallet, "saved-explorer", chain="btc", network=target_network)
                _add_edge(edges, node, tx_node, "funds_transaction", "saved-explorer", verified=True, amount=amount)
                if wallet != target:
                    counterparties.add(wallet)
            for wallet, amount in outputs:
                node = wallet_node if wallet == target else _add_node(
                    nodes, "wallet", wallet, "saved-explorer", chain="btc", network=target_network)
                _add_edge(edges, tx_node, node, "pays", "saved-explorer", verified=True, amount=amount)
                if wallet != target:
                    counterparties.add(wallet)
            co_inputs = sorted({wallet for wallet, _ in inputs if wallet != target})
            if target_in_inputs and co_inputs:
                heuristics.append({"kind": "common_input_candidate", "transaction": txid,
                                   "addresses": co_inputs, "verified": False,
                                   "reason": "common-input ownership may fail for CoinJoin or shared custody"})
        chronology.append({"transaction": txid, "timestamp": stamp})
    chronology.sort(key=lambda item: (item["timestamp"] is None, item["timestamp"] or 0, item["transaction"]))
    return _report("saved_wallet_flow_graph", chain=normalized_chain, network=target_network, address=target,
                   transactions_seen=len(rows), transactions_used=len(chronology),
                   declined_transactions=declined, total_in_base_units=total_in,
                   total_out_base_units=total_out, counterparties=sorted(counterparties),
                   nodes=sorted(nodes.values(), key=lambda item: item["id"]),
                   edges=sorted(edges, key=lambda item: (item["from"], item["to"], item["relation"])),
                   chronology=chronology, heuristics=heuristics,
                   warning="wallet flows and clustering heuristics do not prove real-world ownership")


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise EntityGraphError(message)


def _json_file(path: str) -> Any:
    raw = Path(path).read_bytes()
    if len(raw) > 16 << 20:
        raise EntityGraphError("input exceeds 16 MiB")
    return json.loads(raw)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="offline saved public-record/social/wallet evidence graphs")
    parser.add_argument("operation", choices=("entities", "social", "wallet"))
    parser.add_argument("input")
    parser.add_argument("--handle")
    parser.add_argument("--chain", choices=("btc", "eth"))
    parser.add_argument("--address")
    try:
        args = parser.parse_args(argv)
        value = _json_file(args.input)
        if args.operation == "entities":
            result = normalize_public_entities(value)
        elif args.operation == "social":
            if not args.handle:
                raise EntityGraphError("social needs --handle")
            result = build_social_evidence_graph(args.handle, value)
        else:
            if not args.chain or not args.address:
                raise EntityGraphError("wallet needs --chain and --address")
            result = analyze_saved_wallet_flows(args.chain, args.address, value)
        print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
        return 0
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError,
            RecursionError, MemoryError, OverflowError) as exc:
        print(f"osint_entity_graph: {exc}", file=__import__("sys").stderr)
        return 2


__all__ = ["EntityGraphError", "analyze_saved_wallet_flows", "build_social_evidence_graph",
           "normalize_public_entities", "valid_lei", "valid_orcid"]

if __name__ == "__main__":
    raise SystemExit(main())
