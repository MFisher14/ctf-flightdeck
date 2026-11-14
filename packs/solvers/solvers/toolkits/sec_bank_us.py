#!/usr/bin/env python3
"""Passive US interbank-payment artifact profiler.

The engine reads supplied bytes only.  It recognizes FedNow and Fedwire ISO
20022 envelopes, delegates NACHA controls to :mod:`fin2_ach`, and exposes a
strict adapter around the repository's mature ISO 8583 decoder.  It never
creates, signs, transmits, or submits a payment.

CLI::

    ./.venv/bin/python solvers/toolkits/sec_bank_us.py iso20022 FILE [--rail auto|fednow|fedwire]
    ./.venv/bin/python solvers/toolkits/sec_bank_us.py nacha FILE [--allow-unpadded]
    ./.venv/bin/python solvers/toolkits/sec_bank_us.py iso8583 FILE --encoding ascii|bin-bitmap|packed|ascii-mti-packed
"""

from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation
from functools import wraps
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable, Sequence, TypeVar


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_XML_BYTES = 8 * 1024 * 1024
MAX_BINARY_BYTES = 16 * 1024 * 1024
MAX_XML_NODES = 100_000
MAX_XML_DEPTH = 64
MAX_XML_ATTRIBUTES = 64
MAX_TEXT_BYTES = 8 * 1024 * 1024
MAX_LIST_ITEMS = 20_000
ISO_PREFIX = "urn:iso:std:iso:20022:tech:xsd:"
FLAG_RE = flagfmt.TEXT
MESSAGE_RE = re.compile(r"(?:pacs|camt)\.\d{3}\.\d{3}\.\d{2}\Z")
SUPPORTED_MESSAGES = {
    "pacs.002.001.10",
    "pacs.004.001.09",
    "pacs.004.001.10",
    "pacs.008.001.08",
    "pacs.009.001.08",
    "pacs.028.001.03",
    "camt.029.001.09",
    "camt.054.001.08",
    "camt.056.001.08",
    "camt.110.001.01",
    "camt.111.001.01",
}


class SecBankUSError(ValueError):
    """Malformed, unsupported, ambiguous, or resource-limited supplied input."""


_T = TypeVar("_T")


def _fail_closed(function: Callable[..., _T]) -> Callable[..., _T]:
    """Normalize every ordinary implementation failure to the declared error."""

    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> _T:
        try:
            return function(*args, **kwargs)
        except SecBankUSError:
            raise
        except Exception as exc:
            raise SecBankUSError(
                f"{function.__name__} failed: {type(exc).__name__}: {str(exc)[:240]}"
            ) from None

    return wrapped


def _bytes(value: Any, *, limit: int, label: str, text: bool = False) -> bytes:
    try:
        if len(value) > limit:
            raise SecBankUSError(f"{label} must be nonempty bytes up to {limit} bytes")
    except TypeError:
        pass
    if isinstance(value, str) and text:
        value = value.encode("utf-8")
    elif isinstance(value, memoryview):
        value = value.tobytes()
    elif isinstance(value, bytearray):
        value = bytes(value)
    if not isinstance(value, bytes) or not value or len(value) > limit:
        raise SecBankUSError(f"{label} must be nonempty bytes up to {limit} bytes")
    return value


def _local(node: Any) -> str:
    tag = getattr(node, "tag", None)
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _namespace(node: Any) -> str | None:
    tag = getattr(node, "tag", None)
    if isinstance(tag, str) and tag.startswith("{") and "}" in tag:
        return tag[1:].split("}", 1)[0]
    return None


def _safe_xml(value: Any) -> Any:
    try:
        from lxml import etree
    except ImportError as exc:
        raise SecBankUSError("lxml is required for XML analysis") from exc

    class DenyResolver(etree.Resolver):
        def resolve(self, url: str, public_id: str, context: Any) -> Any:
            raise SecBankUSError("external XML resources are forbidden")

    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
        recover=False,
    )
    parser.resolvers.add(DenyResolver())
    root = etree.fromstring(
        _bytes(value, limit=MAX_XML_BYTES, label="XML input", text=True), parser
    )
    if root.getroottree().docinfo.doctype:
        raise SecBankUSError("DOCTYPE is forbidden")
    text_bytes = 0
    for count, node in enumerate(root.iter(), 1):
        if count > MAX_XML_NODES:
            raise SecBankUSError("XML node limit exceeded")
        if isinstance(node, etree._Entity):
            raise SecBankUSError("XML entities are forbidden")
        if len(getattr(node, "attrib", {})) > MAX_XML_ATTRIBUTES:
            raise SecBankUSError("XML attribute limit exceeded")
        depth = 0
        parent = node
        while parent is not None:
            depth += 1
            if depth > MAX_XML_DEPTH:
                raise SecBankUSError("XML depth limit exceeded")
            parent = parent.getparent()
        if _namespace(node) == "http://www.w3.org/2001/XInclude":
            raise SecBankUSError("XInclude is forbidden")
        for part in (getattr(node, "text", None), getattr(node, "tail", None)):
            if part:
                text_bytes += len(part.encode("utf-8", "surrogatepass"))
                if text_bytes > MAX_TEXT_BYTES:
                    raise SecBankUSError("XML text limit exceeded")
    return root


def _children(node: Any, name: str, namespace: str | None = None) -> list[Any]:
    result = [child for child in node if _local(child) == name]
    if namespace is not None:
        result = [child for child in result if _namespace(child) == namespace]
    return result


def _one(node: Any, name: str, namespace: str | None = None) -> Any | None:
    result = _children(node, name, namespace)
    if len(result) > 1:
        raise SecBankUSError(f"duplicate singleton element {name}")
    return result[0] if result else None


def _path(node: Any, path: str, namespace: str) -> Any | None:
    current = node
    for name in path.split("/"):
        if current is None:
            return None
        current = _one(current, name, namespace)
    return current


def _text(node: Any, path: str, namespace: str) -> str | None:
    found = _path(node, path, namespace)
    if found is None or found.text is None:
        return None
    value = found.text.strip()
    return value or None


def _descendants(node: Any, name: str, namespace: str | None = None) -> list[Any]:
    result = [item for item in node.iter() if _local(item) == name]
    if namespace is not None:
        result = [item for item in result if _namespace(item) == namespace]
    if len(result) > MAX_LIST_ITEMS:
        raise SecBankUSError(f"too many {name} elements")
    return result


def _amount(node: Any | None) -> dict[str, str | None] | None:
    if node is None or node.text is None:
        return None
    value = node.text.strip()
    if len(value) > 80 or not re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", value):
        raise SecBankUSError("invalid ISO 20022 decimal amount")
    try:
        Decimal(value)
    except InvalidOperation as exc:
        raise SecBankUSError("invalid ISO 20022 decimal amount") from exc
    return {"value": value, "currency": node.get("Ccy")}


def _account(node: Any, prefix: str, namespace: str) -> str | None:
    return (
        _text(node, prefix + "/Id/IBAN", namespace)
        or _text(node, prefix + "/Id/Othr/Id", namespace)
    )


def _agent(node: Any, prefix: str, namespace: str) -> str | None:
    return (
        _text(node, prefix + "/FinInstnId/BICFI", namespace)
        or _text(node, prefix + "/FinInstnId/ClrSysMmbId/MmbId", namespace)
        or _text(node, prefix + "/FinInstnId/LEI", namespace)
    )


def _party(node: Any, prefix: str, namespace: str) -> dict[str, Any]:
    party = _path(node, prefix, namespace)
    address: list[str] = []
    if party is not None:
        address = [
            (item.text or "").strip()
            for item in _descendants(party, "AdrLine", namespace)
            if (item.text or "").strip()
        ]
    return {
        "name": _text(node, prefix + "/Nm", namespace),
        "address_lines": address,
    }


def _reasons(node: Any, container: str, namespace: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for reason in _children(node, container, namespace):
        result.append(
            {
                "originator": _text(reason, "Orgtr/Nm", namespace),
                "code": _text(reason, "Rsn/Cd", namespace),
                "proprietary": _text(reason, "Rsn/Prtry", namespace),
                "additional_information": [
                    (item.text or "").strip()
                    for item in _children(reason, "AddtlInf", namespace)
                    if (item.text or "").strip()
                ],
            }
        )
    return result


def _payment_transaction(node: Any, namespace: str) -> dict[str, Any]:
    remittance_root = _path(node, "RmtInf", namespace)
    remittance = (
        [
            (item.text or "").strip()
            for item in _descendants(remittance_root, "Ustrd", namespace)
            if (item.text or "").strip()
        ]
        if remittance_root is not None
        else []
    )
    amount_node = _path(node, "IntrBkSttlmAmt", namespace)
    if amount_node is None:
        amount_node = _path(node, "IntrBkSttlmAmt/Amt", namespace)
    return {
        "instruction_id": _text(node, "PmtId/InstrId", namespace),
        "end_to_end_id": _text(node, "PmtId/EndToEndId", namespace),
        "transaction_id": _text(node, "PmtId/TxId", namespace),
        "uetr": _text(node, "PmtId/UETR", namespace),
        "service_level": _text(node, "PmtTpInf/SvcLvl/Cd", namespace)
        or _text(node, "PmtTpInf/SvcLvl/Prtry", namespace),
        "local_instrument": _text(node, "PmtTpInf/LclInstrm/Cd", namespace)
        or _text(node, "PmtTpInf/LclInstrm/Prtry", namespace),
        "category_purpose": _text(node, "PmtTpInf/CtgyPurp/Cd", namespace)
        or _text(node, "PmtTpInf/CtgyPurp/Prtry", namespace),
        "amount": _amount(amount_node),
        "settlement_date": _text(node, "IntrBkSttlmDt", namespace),
        "acceptance_datetime": _text(node, "AccptncDtTm", namespace),
        "debtor": _party(node, "Dbtr", namespace),
        "debtor_account": _account(node, "DbtrAcct", namespace),
        "debtor_agent": _agent(node, "DbtrAgt", namespace),
        "creditor": _party(node, "Cdtr", namespace),
        "creditor_account": _account(node, "CdtrAcct", namespace),
        "creditor_agent": _agent(node, "CdtrAgt", namespace),
        "charge_bearer": _text(node, "ChrgBr", namespace),
        "remittance": remittance,
    }


def _group_header(body: Any, namespace: str) -> dict[str, Any]:
    header = _path(body, "GrpHdr", namespace)
    if header is None:
        return {}
    return {
        "message_id": _text(header, "MsgId", namespace),
        "created": _text(header, "CreDtTm", namespace),
        "number_of_transactions": _text(header, "NbOfTxs", namespace),
        "total_interbank_settlement_amount": _amount(
            _path(header, "TtlIntrBkSttlmAmt", namespace)
        ),
        "interbank_settlement_date": _text(header, "IntrBkSttlmDt", namespace),
        "settlement_method": _text(header, "SttlmInf/SttlmMtd", namespace),
        "instructing_agent": _agent(header, "InstgAgt", namespace),
        "instructed_agent": _agent(header, "InstdAgt", namespace),
    }


def _bah_identifier(node: Any | None, side: str) -> str | None:
    if node is None:
        return None
    candidates = [item for item in node.iter() if _local(item) == side]
    if len(candidates) > 1:
        raise SecBankUSError(f"duplicate AppHdr {side}")
    if not candidates:
        return None
    for name in ("BICFI", "MmbId", "LEI", "Id"):
        values = [
            (item.text or "").strip()
            for item in candidates[0].iter()
            if _local(item) == name and (item.text or "").strip()
        ]
        if values:
            return values[0]
    return None


def _bah_text(node: Any | None, name: str) -> str | None:
    if node is None:
        return None
    values = [
        (item.text or "").strip()
        for item in node.iter()
        if _local(item) == name and (item.text or "").strip()
    ]
    if len(values) > 1:
        raise SecBankUSError(f"duplicate AppHdr {name}")
    return values[0] if values else None


_ROOTS = {
    "pacs.008": "FIToFICstmrCdtTrf",
    "pacs.002": "FIToFIPmtStsRpt",
    "pacs.004": "PmtRtr",
    "pacs.009": "FICdtTrf",
    "pacs.028": "FIToFIPmtStsReq",
    "camt.054": "BkToCstmrDbtCdtNtfctn",
    "camt.029": "RsltnOfInvstgtn",
    "camt.056": "FIToFIPmtCxlReq",
    "camt.110": "InvstgtnReq",
    "camt.111": "InvstgtnRspn",
}
_FEDNOW = {
    "pacs.008",
    "pacs.002",
    "pacs.004",
    "pacs.009",
    "pacs.028",
    "camt.029",
    "camt.054",
    "camt.056",
}
_FEDWIRE = {
    "pacs.008",
    "pacs.002",
    "pacs.004",
    "pacs.009",
    "pacs.028",
    "camt.029",
    "camt.056",
    "camt.110",
    "camt.111",
}


def _rail_assessment(
    requested: str, family: str, wrapper: str, business_service: str | None
) -> dict[str, Any]:
    candidates = []
    if family in _FEDNOW:
        candidates.append("fednow")
    if family in _FEDWIRE:
        candidates.append("fedwire")
    evidence: list[str] = []
    detected: str | None = None
    service = (business_service or "").lower()
    if wrapper == "MessageEnvelope" or "fedwire" in wrapper.lower():
        detected = "fedwire"
        evidence.append("wrapper name is Fedwire-specific evidence")
    elif "fedwire" in service:
        detected = "fedwire"
        evidence.append("BizSvc names Fedwire")
    elif "fednow" in service:
        detected = "fednow"
        evidence.append("BizSvc names FedNow")
    elif len(candidates) == 1:
        detected = candidates[0]
        evidence.append("message family is unique to this supported rail set")
    if requested != "auto":
        selected = requested
        confidence = "caller-supplied"
    elif detected is not None:
        selected = detected
        confidence = "inferred"
    else:
        selected = None
        confidence = "undetermined"
        evidence.append("shared message family needs rail context")
    return {
        "requested": requested,
        "selected": selected,
        "detected": detected,
        "candidates": candidates,
        "confidence": confidence,
        "evidence": evidence,
    }


def _status_payload(body: Any, namespace: str) -> dict[str, Any]:
    original = _path(body, "OrgnlGrpInfAndSts", namespace)
    statuses = []
    for item in _children(body, "TxInfAndSts", namespace):
        statuses.append(
            {
                "status_id": _text(item, "StsId", namespace),
                "original_instruction_id": _text(item, "OrgnlInstrId", namespace),
                "original_end_to_end_id": _text(item, "OrgnlEndToEndId", namespace),
                "original_transaction_id": _text(item, "OrgnlTxId", namespace),
                "original_uetr": _text(item, "OrgnlUETR", namespace),
                "transaction_status": _text(item, "TxSts", namespace),
                "reasons": _reasons(item, "StsRsnInf", namespace),
            }
        )
    if original is None:
        raise SecBankUSError("pacs.002 lacks original-message information")
    original_message_id = _text(original, "OrgnlMsgId", namespace)
    original_message_name = _text(original, "OrgnlMsgNmId", namespace)
    group_status = _text(original, "GrpSts", namespace)
    if not original_message_id or not original_message_name:
        raise SecBankUSError("pacs.002 lacks original-message identifiers")
    if not group_status and not statuses:
        raise SecBankUSError("pacs.002 contains no group or transaction status")
    if any(not item["transaction_status"] for item in statuses):
        raise SecBankUSError("pacs.002 transaction status lacks TxSts")
    return {
        "original_group": {
            "message_id": original_message_id,
            "message_name": original_message_name,
            "group_status": group_status,
            "reasons": _reasons(original, "StsRsnInf", namespace),
        },
        "transaction_statuses": statuses,
    }


def _notification_payload(body: Any, namespace: str) -> dict[str, Any]:
    notifications = []
    for notice in _children(body, "Ntfctn", namespace):
        entries = []
        for entry in _children(notice, "Ntry", namespace):
            refs: dict[str, list[str]] = {}
            for name in ("InstrId", "EndToEndId", "TxId", "UETR", "AcctSvcrRef"):
                values = [
                    (item.text or "").strip()
                    for item in _descendants(entry, name, namespace)
                    if (item.text or "").strip()
                ]
                if values:
                    refs[name] = list(dict.fromkeys(values))
            entries.append(
                {
                    "amount": _amount(_path(entry, "Amt", namespace)),
                    "credit_debit": _text(entry, "CdtDbtInd", namespace),
                    "status": _text(entry, "Sts/Cd", namespace) or _text(entry, "Sts", namespace),
                    "booking_date": _text(entry, "BookgDt/Dt", namespace)
                    or _text(entry, "BookgDt/DtTm", namespace),
                    "value_date": _text(entry, "ValDt/Dt", namespace)
                    or _text(entry, "ValDt/DtTm", namespace),
                    "account_servicer_reference": _text(entry, "AcctSvcrRef", namespace),
                    "references": refs,
                    "remittance": [
                        (item.text or "").strip()
                        for item in _descendants(entry, "Ustrd", namespace)
                        if (item.text or "").strip()
                    ],
                }
            )
        notifications.append(
            {
                "id": _text(notice, "Id", namespace),
                "created": _text(notice, "CreDtTm", namespace),
                "account": _account(notice, "Acct", namespace),
                "account_currency": _text(notice, "Acct/Ccy", namespace),
                "entries": entries,
            }
        )
    if not notifications or any(
        not item["id"] or not item["account"] or not item["entries"]
        for item in notifications
    ):
        raise SecBankUSError("camt.054 lacks a complete notification")
    return {"report_kind": "debit-credit-notification", "notifications": notifications}


def _return_payload(body: Any, namespace: str) -> dict[str, Any]:
    original = _path(body, "OrgnlGrpInf", namespace)
    returns = []
    for item in _children(body, "TxInf", namespace):
        returns.append(
            {
                "return_id": _text(item, "RtrId", namespace),
                "original_instruction_id": _text(item, "OrgnlInstrId", namespace),
                "original_end_to_end_id": _text(item, "OrgnlEndToEndId", namespace),
                "original_transaction_id": _text(item, "OrgnlTxId", namespace),
                "original_uetr": _text(item, "OrgnlUETR", namespace),
                "returned_amount": _amount(_path(item, "RtrdIntrBkSttlmAmt", namespace)),
                "reasons": _reasons(item, "RtrRsnInf", namespace),
            }
        )
    if original is None or not returns:
        raise SecBankUSError("pacs.004 lacks original-group or return data")
    return {
        "original_group": {
            "message_id": _text(original, "OrgnlMsgId", namespace) if original is not None else None,
            "message_name": _text(original, "OrgnlMsgNmId", namespace) if original is not None else None,
        },
        "returns": returns,
    }


def _investigation_payload(body: Any, namespace: str) -> dict[str, Any]:
    """Bounded high-value references for cancellation/investigation families."""
    values: dict[str, list[str]] = {}
    for name in (
        "Id",
        "CaseId",
        "Assgnr",
        "Assgne",
        "OrgnlMsgId",
        "OrgnlMsgNmId",
        "OrgnlInstrId",
        "OrgnlEndToEndId",
        "OrgnlTxId",
        "OrgnlUETR",
        "CxlStsId",
        "TxCxlSts",
        "Conf",
        "Rsn",
        "AddtlInf",
    ):
        found = [
            (item.text or "").strip()
            for item in _descendants(body, name, namespace)
            if (item.text or "").strip()
        ]
        if found:
            values[name] = list(dict.fromkeys(found))[:1000]
    if not values:
        raise SecBankUSError("message contains no recognized investigation references")
    return {"investigation_fields": values}


@_fail_closed
def parse_iso20022(data: Any, *, rail: str = "auto") -> dict[str, Any]:
    """Analyze one supplied US-rail ISO 20022 XML artifact.

    ``rail`` is a caller hint, not proof.  Shared message families remain
    undetermined in auto mode unless the envelope or BAH supplies rail evidence.
    """
    if rail not in {"auto", "fednow", "fedwire"}:
        raise SecBankUSError("rail must be auto, fednow, or fedwire")
    root = _safe_xml(data)
    documents = [node for node in root.iter() if _local(node) == "Document"]
    if len(documents) != 1:
        raise SecBankUSError("expected exactly one ISO 20022 Document")
    document = documents[0]
    namespace = _namespace(document)
    if not namespace or not namespace.startswith(ISO_PREFIX):
        raise SecBankUSError("Document has no supported ISO 20022 namespace")
    message = namespace[len(ISO_PREFIX) :]
    if not MESSAGE_RE.fullmatch(message):
        raise SecBankUSError("unsupported ISO 20022 message identifier")
    family = ".".join(message.split(".")[:2])
    expected_root = _ROOTS.get(family)
    if expected_root is None:
        raise SecBankUSError(f"unsupported FedNow/Fedwire message family {family}")
    bodies = _children(document, expected_root, namespace)
    if len(bodies) != 1 or len(document) != 1:
        raise SecBankUSError(f"Document must contain exactly one {expected_root}")
    body = bodies[0]

    app_headers = [node for node in root.iter() if _local(node) == "AppHdr"]
    if len(app_headers) > 1:
        raise SecBankUSError("multiple AppHdr elements are ambiguous")
    app_header = app_headers[0] if app_headers else None
    if app_header is not None and app_header in document.iter():
        raise SecBankUSError("AppHdr must not be nested in Document")
    wrapper = "bare-Document" if root is document else _local(root)
    app_header_namespace = _namespace(app_header) if app_header is not None else None
    bah = {
        "namespace": app_header_namespace,
        "from": _bah_identifier(app_header, "Fr"),
        "to": _bah_identifier(app_header, "To"),
        "business_message_id": _bah_text(app_header, "BizMsgIdr"),
        "message_definition_id": _bah_text(app_header, "MsgDefIdr"),
        "business_service": _bah_text(app_header, "BizSvc"),
        "created": _bah_text(app_header, "CreDt"),
        "possible_duplicate": _bah_text(app_header, "PssblDplct"),
        "market_practice": _text(app_header, "MktPrctc/Id", app_header_namespace)
        if app_header is not None and app_header_namespace is not None
        else None,
    }
    assessment = _rail_assessment(rail, family, wrapper, bah["business_service"])
    issues: list[dict[str, Any]] = []

    def issue(code: str, path: str, expected: Any, actual: Any) -> None:
        issues.append({"code": code, "path": path, "expected": expected, "actual": actual})

    if bah["message_definition_id"] and bah["message_definition_id"] != message:
        issue("bah_message_mismatch", "AppHdr/MsgDefIdr", message, bah["message_definition_id"])
    if message not in SUPPORTED_MESSAGES:
        issue(
            "unsupported_rail_message_version",
            "Document",
            sorted(SUPPORTED_MESSAGES),
            message,
        )
    if app_header is not None and not (app_header_namespace or "").startswith(
        ISO_PREFIX + "head.001."
    ):
        issue(
            "bah_namespace",
            "AppHdr",
            ISO_PREFIX + "head.001.*",
            app_header_namespace,
        )
    selected = assessment["selected"]
    allowed = _FEDNOW if selected == "fednow" else _FEDWIRE if selected == "fedwire" else set()
    if selected and family not in allowed:
        issue("rail_message_family", "Document", sorted(allowed), family)
    if selected and assessment["detected"] and assessment["detected"] != selected:
        issue(
            "rail_evidence_conflict",
            "rail",
            assessment["detected"],
            selected,
        )

    result: dict[str, Any] = {
        "type": "us-iso20022",
        "message": message,
        "family": family,
        "document_root": expected_root,
        "wrapper": wrapper,
        "business_application_header": bah,
        "rail_assessment": assessment,
        "group_header": _group_header(body, namespace),
        "issues": issues,
        "authentication": "not established by syntax",
        "settlement": "not established by a request message alone",
        "limitations": [
            "Generic ISO syntax does not establish FedNow/Fedwire profile conformance.",
            "BAH and message identifiers are evidence, not participant authentication.",
            "No signature, account ownership, acceptance, or settlement is verified.",
        ],
    }
    if family in {"pacs.008", "pacs.009"}:
        tx_name = "CdtTrfTxInf"
        result["transactions"] = [
            _payment_transaction(item, namespace) for item in _children(body, tx_name, namespace)
        ]
        if not result["group_header"].get("message_id") or not result["transactions"]:
            raise SecBankUSError(f"{family} lacks group-header or transaction data")
    elif family == "pacs.002":
        result.update(_status_payload(body, namespace))
    elif family == "pacs.004":
        result.update(_return_payload(body, namespace))
    elif family == "pacs.028":
        result.update(_investigation_payload(body, namespace))
    elif family == "camt.054":
        result.update(_notification_payload(body, namespace))
    else:
        result.update(_investigation_payload(body, namespace))

    if message == "pacs.008.001.08":
        try:
            from lxml import etree
            import fin2_iso20022

            delegated = fin2_iso20022.analyze(etree.tostring(document), sepa=False)
        except Exception as exc:
            raise SecBankUSError(
                f"delegated pacs.008 validation failed: {type(exc).__name__}: {str(exc)[:240]}"
            ) from None
        result["generic_iso20022_analysis"] = delegated
        if not delegated.get("schema_valid", False):
            issue("schema_invalid", "Document", True, False)
        elif not delegated.get("valid", False):
            issue(
                "generic_consistency_invalid",
                "Document",
                True,
                delegated.get("issues", []),
            )

    all_text = "\n".join(part for part in root.itertext() if isinstance(part, str))
    result["flags"] = list(dict.fromkeys(FLAG_RE.findall(all_text)))
    result["valid"] = not issues
    return result


@_fail_closed
def parse_nacha(data: Any, *, require_padding: bool = True) -> dict[str, Any]:
    """Strict sector adapter around the existing NACHA control checker."""
    if type(require_padding) is not bool:
        raise SecBankUSError("require_padding must be boolean")
    try:
        import fin2_ach

        report = fin2_ach.parse_ach(data, require_padding=require_padding)
    except Exception as exc:
        raise SecBankUSError(f"NACHA analysis failed: {type(exc).__name__}: {str(exc)[:240]}") from None
    result = dict(report)
    result["source_engine"] = "fin2_ach"
    result["sector_profile"] = "US NACHA ACH common origination"
    result.setdefault("limitations", []).extend(
        [
            "Controls detect corruption, not payment authorization or account ownership.",
            "IAT, CTX, returns, and notices of change require their specific layouts.",
        ]
    )
    return result


@_fail_closed
def parse_iso8583(
    data: Any,
    *,
    encoding: str = "ascii",
    spec: str = "1987",
    strip_mli: bool = False,
) -> dict[str, Any]:
    """Strict full-consumption adapter around ``financial.parse_iso8583``.

    Encodings and field maps are explicit because ISO 8583 does not define a
    universal transport framing or network profile.
    """
    if encoding not in {"ascii", "bin-bitmap", "packed", "ascii-mti-packed"}:
        raise SecBankUSError("unsupported ISO 8583 encoding")
    if spec not in {"1987", "1993"}:
        raise SecBankUSError("spec must be 1987 or 1993")
    if type(strip_mli) is not bool:
        raise SecBankUSError("strip_mli must be boolean")
    payload = _bytes(data, limit=MAX_BINARY_BYTES, label="ISO 8583 input")
    has_exact_mli = len(payload) >= 2 and int.from_bytes(payload[:2], "big") == len(payload) - 2
    if has_exact_mli and not strip_mli:
        raise SecBankUSError("two-byte MLI present; set strip_mli=True explicitly")
    try:
        import financial

        report = financial.parse_iso8583(
            payload, encoding=encoding, spec=spec, strip_mli=strip_mli
        )
    except Exception as exc:
        raise SecBankUSError(
            f"ISO 8583 analysis failed: {type(exc).__name__}: {str(exc)[:240]}"
        ) from None
    if report is None:
        raise SecBankUSError("input does not match the declared ISO 8583 profile")
    if report.get("has_tertiary_bitmap"):
        raise SecBankUSError("tertiary ISO 8583 bitmap indication is unsupported")
    if report.get("trailing_hex"):
        raise SecBankUSError("trailing bytes after ISO 8583 data elements")
    result = dict(report)
    result["valid"] = True
    result["source_engine"] = "financial"
    result["profile"] = f"ISO 8583:{spec} field map; {encoding} encoding"
    result["authentication"] = "MAC/PIN/signature not verified"
    result["limitations"] = [
        "ISO 8583 transport framing and field encodings are network-profile specific.",
        "This adapter does not claim ISO 8583:2023 or card-network profile conformance.",
    ]
    return result


def _read(path: Any, limit: int) -> bytes:
    with Path(path).open("rb") as stream:
        return stream.read(limit + 1)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    xml_parser = subparsers.add_parser("iso20022", help="analyze FedNow/Fedwire XML")
    xml_parser.add_argument("file")
    xml_parser.add_argument("--rail", choices=("auto", "fednow", "fedwire"), default="auto")

    ach_parser = subparsers.add_parser("nacha", help="analyze a NACHA ACH file")
    ach_parser.add_argument("file")
    ach_parser.add_argument("--allow-unpadded", action="store_true")

    iso_parser = subparsers.add_parser("iso8583", help="analyze an ISO 8583 authorization")
    iso_parser.add_argument("file")
    iso_parser.add_argument(
        "--encoding",
        choices=("ascii", "bin-bitmap", "packed", "ascii-mti-packed"),
        required=True,
    )
    iso_parser.add_argument("--spec", choices=("1987", "1993"), default="1987")
    iso_parser.add_argument("--strip-mli", action="store_true")

    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError):
        return 2

    try:
        if arguments.command == "iso20022":
            report = parse_iso20022(
                _read(arguments.file, MAX_XML_BYTES), rail=arguments.rail
            )
        elif arguments.command == "nacha":
            report = parse_nacha(
                _read(arguments.file, MAX_BINARY_BYTES),
                require_padding=not arguments.allow_unpadded,
            )
        else:
            report = parse_iso8583(
                _read(arguments.file, MAX_BINARY_BYTES),
                encoding=arguments.encoding,
                spec=arguments.spec,
                strip_mli=arguments.strip_mli,
            )
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
        return 0 if report.get("valid", True) else 1
    except SecBankUSError as exc:
        print(f"sec_bank_us: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"sec_bank_us: analysis failed ({type(exc).__name__})", file=sys.stderr)
        return 2


__all__ = [
    "SecBankUSError",
    "parse_iso20022",
    "parse_nacha",
    "parse_iso8583",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
