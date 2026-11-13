#!/usr/bin/env python3
"""Offline EBICS H004/H005 and EPC ISO 20022 evidence reader.

The engine consumes supplied XML only.  It never opens a network connection,
decrypts order data, inflates payloads, verifies a signature without trust
material, or creates/submits a payment.  Generic pacs.008 and camt.053 XSD and
consistency checks are delegated to the existing ``fin2_iso20022`` engine; this
module adds EBICS, pacs.002/camt.054, and SCT Inst profile evidence.

CLI::

    ./.venv/bin/python solvers/toolkits/sec_bank_ebics.py ebics FILE
    ./.venv/bin/python solvers/toolkits/sec_bank_ebics.py iso20022 FILE \
        [--profile auto|sct-inst-2025]
"""

from __future__ import annotations

import argparse
import base64
import binascii
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable, TypeVar


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_BYTES = 8 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 64
MAX_ATTRIBUTES = 64
MAX_TEXT_CHARS = 4 * 1024 * 1024
MAX_B64_BYTES = 4 * 1024 * 1024
EBICS_NAMESPACES = {
    "H004": "urn:org:ebics:H004",
    "H005": "urn:org:ebics:H005",
}
ISO_PREFIX = "urn:iso:std:iso:20022:tech:xsd:"
ISO_ROOTS = {
    "pacs.008.001.08": "FIToFICstmrCdtTrf",
    "pacs.002.001.10": "FIToFIPmtStsRpt",
    "camt.053.001.08": "BkToCstmrStmt",
    "camt.054.001.08": "BkToCstmrDbtCdtNtfctn",
}
EBICS_ROOTS = {
    "ebicsRequest",
    "ebicsResponse",
    "ebicsUnsecuredRequest",
    "ebicsNoPubKeyDigestsRequest",
    "ebicsKeyManagementResponse",
}
FLAG_RE = flagfmt.TEXT
_DECIMAL_RE = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)")
_T = TypeVar("_T")


class SecBankEbicsError(ValueError):
    """Malformed, unsafe, unsupported, or resource-limited bank XML."""


def _public(function: Callable[..., _T]) -> Callable[..., _T]:
    """Normalize every ordinary failure at a public API boundary."""

    def wrapped(*args: Any, **kwargs: Any) -> _T:
        try:
            return function(*args, **kwargs)
        except SecBankEbicsError:
            raise
        except Exception as exc:
            raise SecBankEbicsError(
                f"analysis failed: {type(exc).__name__}: {str(exc)[:240]}"
            ) from None

    wrapped.__name__ = function.__name__
    wrapped.__doc__ = function.__doc__
    return wrapped


def _bytes(value: Any) -> bytes:
    try:
        if len(value) > MAX_BYTES:
            raise SecBankEbicsError("expected nonempty XML at most 8 MiB")
    except TypeError:
        pass
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    elif isinstance(value, bytearray):
        raw = bytes(value)
    elif isinstance(value, memoryview):
        try:
            raw = value.tobytes()
        except (TypeError, ValueError, BufferError) as exc:
            raise SecBankEbicsError("invalid or released input buffer") from exc
    else:
        raise SecBankEbicsError("expected XML bytes or text")
    if not raw or len(raw) > MAX_BYTES:
        raise SecBankEbicsError("expected nonempty XML at most 8 MiB")
    return raw


def _xml(value: Any):
    try:
        from lxml import etree
    except ImportError as exc:  # pragma: no cover - locked runtime dependency
        raise SecBankEbicsError("lxml is required") from exc

    class _DenyResolver(etree.Resolver):
        def resolve(self, url, public_id, context):  # noqa: ANN001
            raise SecBankEbicsError("external XML resource blocked")

    parser = etree.XMLParser(
        resolve_entities=False,
        load_dtd=False,
        no_network=True,
        huge_tree=False,
        recover=False,
        remove_comments=False,
    )
    parser.resolvers.add(_DenyResolver())
    root = etree.fromstring(_bytes(value), parser)
    if root.getroottree().docinfo.doctype:
        raise SecBankEbicsError("DOCTYPE is forbidden")
    depth: dict[Any, int] = {root: 1}
    text_chars = 0
    for count, node in enumerate(root.iter(), 1):
        if count > MAX_NODES:
            raise SecBankEbicsError("XML node limit exceeded")
        if isinstance(node, etree._Entity):
            raise SecBankEbicsError("XML entities are forbidden")
        if not isinstance(node.tag, str):
            continue
        if node.tag.startswith("{http://www.w3.org/2001/XInclude}"):
            raise SecBankEbicsError("XInclude is forbidden")
        parent = node.getparent()
        current_depth = 1 if parent is None else depth.get(parent, MAX_DEPTH) + 1
        depth[node] = current_depth
        if current_depth > MAX_DEPTH:
            raise SecBankEbicsError("XML depth limit exceeded")
        if len(node.attrib) > MAX_ATTRIBUTES:
            raise SecBankEbicsError("XML attribute limit exceeded")
        text_chars += len(node.text or "") + len(node.tail or "")
        if text_chars > MAX_TEXT_CHARS:
            raise SecBankEbicsError("XML text limit exceeded")
    return root


def _name(node: Any) -> tuple[str | None, str]:
    from lxml import etree

    qname = etree.QName(node)
    return qname.namespace, qname.localname


def _element_children(node: Any) -> list[Any]:
    return [child for child in node if isinstance(child.tag, str)]


def _children(node: Any | None, local: str, namespace: str | None = None) -> list[Any]:
    if node is None:
        return []
    return [
        child
        for child in _element_children(node)
        if _name(child)[1] == local and (namespace is None or _name(child)[0] == namespace)
    ]


def _one(
    node: Any | None,
    local: str,
    *,
    namespace: str | None = None,
    required: bool = False,
) -> Any | None:
    found = _children(node, local, namespace)
    if len(found) > 1:
        raise SecBankEbicsError(f"duplicate singleton element {local}")
    if required and not found:
        raise SecBankEbicsError(f"missing required element {local}")
    return found[0] if found else None


def _path(node: Any | None, path: str, namespace: str) -> Any | None:
    current = node
    for part in path.split("/"):
        current = _one(current, part, namespace=namespace)
        if current is None:
            return None
    return current


def _text(node: Any | None, path: str, namespace: str) -> str | None:
    result = _path(node, path, namespace)
    if result is None or result.text is None:
        return None
    return result.text.strip()


def _all_path(node: Any | None, path: str, namespace: str) -> list[Any]:
    parts = path.split("/")
    current = [node] if node is not None else []
    for part in parts:
        current = [child for parent in current for child in _children(parent, part, namespace)]
    return current


def _descendants(
    node: Any | None, local: str, namespace: str | None = None
) -> list[Any]:
    if node is None:
        return []
    return [
        item
        for item in node.iter()
        if isinstance(item.tag, str)
        and _name(item)[1] == local
        and (namespace is None or _name(item)[0] == namespace)
    ]


def _unique_descendant(
    node: Any | None, local: str, namespace: str | None = None
) -> Any | None:
    found = _descendants(node, local, namespace)
    if len(found) > 1:
        raise SecBankEbicsError(f"duplicate singleton descendant {local}")
    return found[0] if found else None


def _attrs(node: Any | None) -> dict[str, str]:
    if node is None:
        return {}
    return {str(key): value for key, value in sorted(node.attrib.items())}


def _decimal(text: str | None, label: str) -> str | None:
    if text is None:
        return None
    value = text.strip()
    if len(value) > 80 or _DECIMAL_RE.fullmatch(value) is None:
        raise SecBankEbicsError(f"invalid decimal in {label}")
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise SecBankEbicsError(f"invalid decimal in {label}") from exc
    if not number.is_finite():
        raise SecBankEbicsError(f"non-finite decimal in {label}")
    return value


def _opaque_b64(node: Any | None, label: str) -> dict[str, Any] | None:
    if node is None:
        return None
    compact = "".join((node.text or "").split())
    if not compact:
        raise SecBankEbicsError(f"empty {label}")
    if len(compact) > (MAX_B64_BYTES * 4 // 3) + 8:
        raise SecBankEbicsError(f"{label} exceeds decoded-size limit")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SecBankEbicsError(f"invalid base64 in {label}") from exc
    if len(decoded) > MAX_B64_BYTES:
        raise SecBankEbicsError(f"{label} exceeds decoded-size limit")
    return {
        "encoded_chars": len(compact),
        "decoded_bytes": len(decoded),
        "sha256": hashlib.sha256(decoded).hexdigest(),
    }


def _algorithm(node: Any | None) -> str | None:
    return None if node is None else node.get("Algorithm")


def _signature(root: Any) -> dict[str, Any]:
    ebics_namespace = _name(root)[0]
    ds_namespace = "http://www.w3.org/2000/09/xmldsig#"
    auth = _one(root, "AuthSignature", namespace=ebics_namespace)
    if auth is None:
        return {
            "present": False,
            "verified": False,
            "verification": "not performed; no AuthSignature present",
        }
    signed_info = _unique_descendant(auth, "SignedInfo", ds_namespace)
    signature_value = _unique_descendant(auth, "SignatureValue", ds_namespace)
    if signed_info is None or signature_value is None:
        raise SecBankEbicsError("incomplete AuthSignature")
    references = _descendants(signed_info, "Reference", ds_namespace)
    if not references:
        raise SecBankEbicsError("AuthSignature has no Reference")
    if len(references) > 8:
        raise SecBankEbicsError("too many signature references")
    reference_rows = []
    for reference in references:
        uri = reference.get("URI", "")
        if uri and not uri.startswith("#"):
            raise SecBankEbicsError("external AuthSignature reference forbidden")
        transforms = _descendants(reference, "Transform", ds_namespace)
        if len(transforms) > 16:
            raise SecBankEbicsError("too many signature transforms")
        digest_method = _unique_descendant(reference, "DigestMethod", ds_namespace)
        digest_value = _unique_descendant(reference, "DigestValue", ds_namespace)
        reference_rows.append(
            {
                "uri": uri,
                "same_document": not uri or uri.startswith("#"),
                "transforms": [_algorithm(item) for item in transforms],
                "digest_method": _algorithm(digest_method),
                "digest": _opaque_b64(digest_value, "DigestValue") if digest_value is not None else None,
            }
        )
    canonicalization = _unique_descendant(
        signed_info, "CanonicalizationMethod", ds_namespace
    )
    signature_method = _unique_descendant(signed_info, "SignatureMethod", ds_namespace)
    return {
        "present": True,
        "canonicalization_method": _algorithm(canonicalization),
        "signature_method": _algorithm(signature_method),
        "references": reference_rows,
        "signature_value": _opaque_b64(signature_value, "SignatureValue"),
        "verified": False,
        "verification": "not performed; trusted keys and EBICS canonicalization are required",
    }


def _payloads(body: Any | None, namespace: str) -> dict[str, Any]:
    transfer = _one(body, "DataTransfer", namespace=namespace)
    if transfer is None:
        receipt = _one(body, "TransferReceipt", namespace=namespace)
        return {
            "kind": "transfer-receipt" if receipt is not None else None,
            "receipt_code": _text(receipt, "ReceiptCode", namespace),
        }
    encryption = _one(transfer, "DataEncryptionInfo", namespace=namespace)
    key_digest = _one(encryption, "EncryptionPubKeyDigest", namespace=namespace)
    transaction_key = _one(encryption, "TransactionKey", namespace=namespace)
    signature_data = _one(transfer, "SignatureData", namespace=namespace)
    order_data = _one(transfer, "OrderData", namespace=namespace)
    data_digests = []
    for digest in _descendants(body, "DataDigest", namespace):
        data_digests.append(
            {
                "attributes": _attrs(digest),
                "value": _opaque_b64(digest, "DataDigest"),
            }
        )
    return {
        "kind": "data-transfer",
        "data_encryption": None
        if encryption is None
        else {
            "authenticate": encryption.get("authenticate"),
            "public_key_digest_attributes": _attrs(key_digest),
            "public_key_digest": _opaque_b64(key_digest, "EncryptionPubKeyDigest")
            if key_digest is not None
            else None,
            "transaction_key": _opaque_b64(transaction_key, "TransactionKey")
            if transaction_key is not None
            else None,
        },
        "signature_data": _opaque_b64(signature_data, "SignatureData")
        if signature_data is not None
        else None,
        "signature_data_attributes": _attrs(signature_data),
        "data_digests": data_digests,
        "order_data": _opaque_b64(order_data, "OrderData") if order_data is not None else None,
        "decoded": False,
        "decrypted": False,
    }


def _order(order: Any | None, namespace: str, version: str) -> dict[str, Any] | None:
    if order is None:
        return None
    result: dict[str, Any] = {
        "admin_order_type": _text(order, "AdminOrderType", namespace),
    }
    if version == "H004":
        parameters: dict[str, list[str]] = {}
        for child in _element_children(order):
            local = _name(child)[1]
            if local in {"OrderType", "OrderAttribute", "AdminOrderType"}:
                continue
            for item in child.iter():
                if item is child or not isinstance(item.tag, str):
                    continue
                item_namespace, item_local = _name(item)
                value = (item.text or "").strip()
                if item_namespace == namespace and value and not _element_children(item):
                    parameters.setdefault(item_local, []).append(value)
        result.update(
            {
                "order_type": _text(order, "OrderType", namespace),
                "order_attribute": _text(order, "OrderAttribute", namespace),
                "order_parameters": parameters,
            }
        )
        return result
    params = _one(order, "BTUOrderParams", namespace=namespace)
    direction = "upload"
    if params is None:
        params = _one(order, "BTDOrderParams", namespace=namespace)
        direction = "download"
    if params is None:
        result["btf"] = None
        return result
    service = _one(params, "Service", namespace=namespace, required=True)
    components: dict[str, Any] = {}
    for local in ("ServiceName", "Scope", "ServiceOption", "Container", "MsgName"):
        item = _one(service, local, namespace=namespace)
        if item is not None:
            components[local] = {"value": (item.text or "").strip(), "attributes": _attrs(item)}
    date_range = _one(params, "DateRange", namespace=namespace)
    result["btf"] = {
        "direction": direction,
        "service": components,
        "service_attributes": _attrs(service),
        "date_range": None
        if date_range is None
        else {
            "start": _text(date_range, "Start", namespace),
            "end": _text(date_range, "End", namespace),
        },
    }
    return result


def _return_info(root: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for code in _descendants(root, "ReturnCode"):
        parent = code.getparent()
        reports = [item for item in _children(parent, "ReportText")]
        if len(reports) > 1:
            raise SecBankEbicsError("duplicate ReportText beside ReturnCode")
        rows.append(
            {
                "code": (code.text or "").strip(),
                "report_text": (reports[0].text or "").strip() if reports else None,
            }
        )
    return rows


def _parse_ebics(data: Any) -> dict[str, Any]:
    root = _xml(data)
    namespace, root_name = _name(root)
    if root_name not in EBICS_ROOTS:
        raise SecBankEbicsError("unsupported EBICS root")
    version = root.get("Version")
    expected_namespace = EBICS_NAMESPACES.get(version or "")
    if expected_namespace is None or namespace != expected_namespace:
        raise SecBankEbicsError("EBICS namespace and Version disagree or are unsupported")
    for item in root.iter():
        if not isinstance(item.tag, str):
            continue
        item_namespace, _ = _name(item)
        if item_namespace in set(EBICS_NAMESPACES.values()) - {namespace}:
            raise SecBankEbicsError("mixed EBICS protocol namespaces")

    header = _one(root, "header", namespace=namespace, required=True)
    body = _one(root, "body", namespace=namespace, required=True)
    static = _one(header, "static", namespace=namespace)
    mutable = _one(header, "mutable", namespace=namespace)
    if static is None and mutable is None:
        raise SecBankEbicsError("EBICS header has no static or mutable content")
    if not _element_children(body):
        raise SecBankEbicsError("EBICS body has no recognized content")
    order_details = _one(static, "OrderDetails", namespace=namespace)
    segment = _one(mutable, "SegmentNumber", namespace=namespace)
    product = _one(static, "Product", namespace=namespace)
    bank_digests = _one(static, "BankPubKeyDigests", namespace=namespace)
    digest_rows: dict[str, Any] = {}
    for label in ("Authentication", "Encryption"):
        item = _one(bank_digests, label, namespace=namespace)
        if item is not None:
            digest_rows[label.lower()] = {
                "attributes": _attrs(item),
                "value": _opaque_b64(item, f"BankPubKeyDigests/{label}"),
            }

    if root_name == "ebicsUnsecuredRequest":
        security_state = "unsecured-request"
    elif root_name == "ebicsNoPubKeyDigestsRequest":
        security_state = "no-public-key-digests-request"
    elif _one(root, "AuthSignature", namespace=namespace) is not None:
        security_state = "signature-present-not-verified"
    else:
        security_state = "signature-absent"

    result = {
        "type": "ebics",
        "protocol_version": version,
        "revision": root.get("Revision"),
        "namespace": namespace,
        "root": root_name,
        "variant": "instant-request-candidate"
        if root.get("Variant", "").lower() == "instant"
        else "standard-or-undetermined",
        "security_state": security_state,
        "header": {
            "authenticate": None if header is None else header.get("authenticate"),
            "host_id": _text(static, "HostID", namespace),
            "nonce": _text(static, "Nonce", namespace),
            "timestamp": _text(static, "Timestamp", namespace),
            "transaction_id": _text(static, "TransactionID", namespace),
            "partner_id": _text(static, "PartnerID", namespace),
            "user_id": _text(static, "UserID", namespace),
            "system_id": _text(static, "SystemID", namespace),
            "product": None if product is None else (product.text or "").strip(),
            "product_language": None if product is None else product.get("Language"),
            "security_medium": _text(static, "SecurityMedium", namespace),
            "bank_public_key_digests": digest_rows,
            "transaction_phase": _text(mutable, "TransactionPhase", namespace),
            "order_id": _text(mutable, "OrderID", namespace),
            "segment_number": None if segment is None else (segment.text or "").strip(),
            "last_segment": None if segment is None else segment.get("lastSegment"),
            "number_of_segments": _text(static, "NumSegments", namespace)
            or _text(mutable, "NumSegments", namespace),
        },
        "order": _order(order_details, namespace, version),
        "auth_signature": _signature(root),
        "body": _payloads(body, namespace),
        "returns": _return_info(root),
        "flags": list(dict.fromkeys(FLAG_RE.findall("\n".join(root.itertext())))),
        "limitations": [
            "XML structure and declared algorithms are evidence, not signature verification.",
            "Opaque EBICS payloads are hashed only; they are not decrypted, inflated, or executed.",
            "Schema validity and bank/customer authorization are not established by this parser.",
        ],
    }
    return result


@_public
def parse_ebics(data: Any) -> dict[str, Any]:
    """Parse one supplied EBICS H004/H005 XML envelope."""

    return _parse_ebics(data)


def _iso_body(root: Any, namespace: str, message: str) -> Any:
    children = _element_children(root)
    if len(children) != 1 or _name(children[0]) != (namespace, ISO_ROOTS[message]):
        raise SecBankEbicsError("ISO 20022 Document has the wrong or ambiguous body root")
    return children[0]


def _iso_amount(node: Any | None, label: str) -> dict[str, Any] | None:
    if node is None:
        return None
    return {"value": _decimal(node.text, label), "currency": node.get("Ccy")}


def _iso_account(node: Any | None, namespace: str) -> str | None:
    return _text(node, "Id/IBAN", namespace) or _text(node, "Id/Othr/Id", namespace)


def _iso_agent(node: Any | None, namespace: str) -> str | None:
    return _text(node, "FinInstnId/BICFI", namespace) or _text(
        node, "FinInstnId/Othr/Id", namespace
    )


def _reasons(node: Any | None, namespace: str) -> list[dict[str, Any]]:
    rows = []
    for info in _children(node, "StsRsnInf", namespace):
        rows.append(
            {
                "originator": _text(info, "Orgtr/Nm", namespace),
                "code": _text(info, "Rsn/Cd", namespace),
                "proprietary": _text(info, "Rsn/Prtry", namespace),
                "additional": [
                    (item.text or "").strip()
                    for item in _children(info, "AddtlInf", namespace)
                ],
            }
        )
    return rows


def _extended_pacs008(body: Any, namespace: str) -> dict[str, Any]:
    group = _one(body, "GrpHdr", namespace=namespace, required=True)
    rows = []
    for tx in _children(body, "CdtTrfTxInf", namespace):
        amount = _one(tx, "IntrBkSttlmAmt", namespace=namespace)
        rows.append(
            {
                "instruction_id": _text(tx, "PmtId/InstrId", namespace),
                "end_to_end_id": _text(tx, "PmtId/EndToEndId", namespace),
                "transaction_id": _text(tx, "PmtId/TxId", namespace),
                "uetr": _text(tx, "PmtId/UETR", namespace),
                "service_levels": [
                    (item.text or "").strip()
                    for item in _all_path(tx, "PmtTpInf/SvcLvl/Cd", namespace)
                ],
                "local_instruments": [
                    (item.text or "").strip()
                    for item in _all_path(tx, "PmtTpInf/LclInstrm/Cd", namespace)
                ],
                "settlement_amount": _iso_amount(amount, "IntrBkSttlmAmt"),
                "settlement_date": _text(tx, "IntrBkSttlmDt", namespace),
                "acceptance_datetime": _text(tx, "AccptncDtTm", namespace),
                "charge_bearer": _text(tx, "ChrgBr", namespace),
                "debtor_agent": _iso_agent(_path(tx, "DbtrAgt", namespace), namespace),
                "creditor_agent": _iso_agent(_path(tx, "CdtrAgt", namespace), namespace),
            }
        )
    return {
        "group_header": {
            "message_id": _text(group, "MsgId", namespace),
            "created": _text(group, "CreDtTm", namespace),
            "number_of_transactions": _text(group, "NbOfTxs", namespace),
        },
        "transactions": rows,
    }


def _sct_inst_assessment(extension: dict[str, Any], requested: bool) -> dict[str, Any]:
    transactions = extension["transactions"]
    candidate = any("INST" in tx["local_instruments"] for tx in transactions)
    issues: list[dict[str, Any]] = []
    if requested or candidate:
        if len(transactions) != 1:
            issues.append({"code": "transaction_count", "expected": 1, "actual": len(transactions)})
        for index, tx in enumerate(transactions):
            amount = tx["settlement_amount"] or {}
            if amount.get("currency") != "EUR":
                issues.append(
                    {"code": "currency", "transaction": index, "expected": "EUR", "actual": amount.get("currency")}
                )
            if "INST" not in tx["local_instruments"]:
                issues.append(
                    {"code": "local_instrument", "transaction": index, "expected": "INST", "actual": tx["local_instruments"]}
                )
            if "SEPA" not in tx["service_levels"]:
                issues.append(
                    {"code": "service_level", "transaction": index, "expected": "SEPA", "actual": tx["service_levels"]}
                )
            timestamp = tx["acceptance_datetime"] or extension["group_header"]["created"]
            if timestamp is None or re.search(r"\.\d{3}(?:\d*)?(?:Z|[+-]\d\d:\d\d)?$", timestamp) is None:
                issues.append(
                    {"code": "millisecond_timestamp", "transaction": index, "actual": timestamp}
                )
    return {
        "profile": "EPC SCT Inst 2025" if requested or candidate else None,
        "candidate": candidate,
        "assessed": requested or candidate,
        "conforms_to_checked_subset": (not issues) if requested or candidate else None,
        "issues": issues,
        "note": "This is a bounded subset of EPC business rules, not full scheme conformance.",
    }


def _pacs002(body: Any, namespace: str) -> dict[str, Any]:
    group = _one(body, "GrpHdr", namespace=namespace, required=True)
    original = _one(body, "OrgnlGrpInfAndSts", namespace=namespace)
    statuses = []
    for tx in _children(body, "TxInfAndSts", namespace):
        statuses.append(
            {
                "status_id": _text(tx, "StsId", namespace),
                "original_instruction_id": _text(tx, "OrgnlInstrId", namespace),
                "original_end_to_end_id": _text(tx, "OrgnlEndToEndId", namespace),
                "original_transaction_id": _text(tx, "OrgnlTxId", namespace),
                "original_uetr": _text(tx, "OrgnlUETR", namespace),
                "transaction_status": _text(tx, "TxSts", namespace),
                "reasons": _reasons(tx, namespace),
                "original_local_instrument": _text(
                    tx, "OrgnlTxRef/PmtTpInf/LclInstrm/Cd", namespace
                ),
            }
        )
    group_message_id = _text(group, "MsgId", namespace)
    group_created = _text(group, "CreDtTm", namespace)
    if not group_message_id or not group_created or original is None:
        raise SecBankEbicsError("pacs.002 lacks required group/original-message data")
    original_message_id = _text(original, "OrgnlMsgId", namespace)
    original_message_name = _text(original, "OrgnlMsgNmId", namespace)
    group_status = _text(original, "GrpSts", namespace)
    if not original_message_id or not original_message_name:
        raise SecBankEbicsError("pacs.002 lacks required original-message identifiers")
    if not group_status and not statuses:
        raise SecBankEbicsError("pacs.002 contains no group or transaction status")
    if any(not item["transaction_status"] for item in statuses):
        raise SecBankEbicsError("pacs.002 transaction status lacks TxSts")
    return {
        "group_header": {
            "message_id": group_message_id,
            "created": group_created,
        },
        "original_group": {
            "message_id": original_message_id,
            "message_name": original_message_name,
            "group_status": group_status,
            "reasons": _reasons(original, namespace),
        },
        "statuses": statuses,
    }


def _sct_inst_status_assessment(
    payload: dict[str, Any], requested: bool
) -> dict[str, Any]:
    statuses = payload["statuses"]
    candidate = any(
        item.get("original_local_instrument") == "INST" for item in statuses
    )
    assessed = requested or candidate
    issues: list[dict[str, Any]] = []
    original = payload.get("original_group") or {}
    if assessed:
        if original.get("message_name") != "pacs.008.001.08":
            issues.append(
                {
                    "code": "original_message",
                    "expected": "pacs.008.001.08",
                    "actual": original.get("message_name"),
                }
            )
        for index, item in enumerate(statuses):
            if item.get("original_local_instrument") != "INST":
                issues.append(
                    {
                        "code": "original_local_instrument",
                        "transaction": index,
                        "expected": "INST",
                        "actual": item.get("original_local_instrument"),
                    }
                )
    observed = [
        code
        for code in [original.get("group_status")]
        + [item.get("transaction_status") for item in statuses]
        if code
    ]
    return {
        "profile": "EPC SCT Inst 2025" if assessed else None,
        "candidate": candidate,
        "assessed": assessed,
        "conforms_to_checked_subset": (not issues) if assessed else None,
        "issues": issues,
        "observed_statuses": observed,
        "status_semantics": {
            "ACCP": "accepted customer profile confirmation",
            "RJCT": "rejected",
        },
        "note": "Status syntax is evidence; it does not independently prove settlement.",
    }


def _entry(entry: Any, namespace: str) -> dict[str, Any]:
    amount_node = _one(entry, "Amt", namespace=namespace)
    details = []
    for tx in _all_path(entry, "NtryDtls/TxDtls", namespace):
        details.append(
            {
                "end_to_end_id": _text(tx, "Refs/EndToEndId", namespace),
                "transaction_id": _text(tx, "Refs/TxId", namespace),
                "uetr": _text(tx, "Refs/UETR", namespace),
                "remittance": [
                    (item.text or "").strip()
                    for item in _all_path(tx, "RmtInf/Ustrd", namespace)
                ],
            }
        )
    return {
        "reference": _text(entry, "NtryRef", namespace),
        "amount": _iso_amount(amount_node, "Ntry/Amt"),
        "credit_debit": _text(entry, "CdtDbtInd", namespace),
        "status": _text(entry, "Sts/Cd", namespace) or _text(entry, "Sts", namespace),
        "booking_date": _text(entry, "BookgDt/Dt", namespace)
        or _text(entry, "BookgDt/DtTm", namespace),
        "value_date": _text(entry, "ValDt/Dt", namespace)
        or _text(entry, "ValDt/DtTm", namespace),
        "account_servicer_reference": _text(entry, "AcctSvcrRef", namespace),
        "transactions": details,
    }


def _camt054(body: Any, namespace: str) -> dict[str, Any]:
    group = _one(body, "GrpHdr", namespace=namespace, required=True)
    notifications = []
    for notification in _children(body, "Ntfctn", namespace):
        account_node = _one(notification, "Acct", namespace=namespace)
        notifications.append(
            {
                "id": _text(notification, "Id", namespace),
                "created": _text(notification, "CreDtTm", namespace),
                "account": _iso_account(account_node, namespace),
                "currency": _text(account_node, "Ccy", namespace),
                "entries": [
                    _entry(item, namespace)
                    for item in _children(notification, "Ntry", namespace)
                ],
            }
        )
    group_message_id = _text(group, "MsgId", namespace)
    group_created = _text(group, "CreDtTm", namespace)
    if not group_message_id or not group_created or not notifications:
        raise SecBankEbicsError("camt.054 lacks required group/notification data")
    if any(
        not item["id"] or not item["account"] or not item["entries"]
        for item in notifications
    ):
        raise SecBankEbicsError("camt.054 has an incomplete notification")
    return {
        "report_kind": "debit-credit-notification",
        "group_header": {
            "message_id": group_message_id,
            "created": group_created,
        },
        "notifications": notifications,
    }


def _parse_iso20022(data: Any, profile: str) -> dict[str, Any]:
    if profile not in {"auto", "sct-inst-2025"}:
        raise SecBankEbicsError("profile must be auto or sct-inst-2025")
    raw = _bytes(data)
    root = _xml(raw)
    namespace, root_name = _name(root)
    if root_name != "Document" or namespace is None or not namespace.startswith(ISO_PREFIX):
        raise SecBankEbicsError("expected a namespace-qualified ISO 20022 Document")
    message = namespace[len(ISO_PREFIX) :]
    if message not in ISO_ROOTS:
        raise SecBankEbicsError("unsupported ISO 20022 message/version")
    body = _iso_body(root, namespace, message)
    result: dict[str, Any] = {
        "type": "iso20022-epc",
        "message": message,
        "namespace": namespace,
        "scheme_profile_requested": profile,
        "schema_valid": None,
        "flags": list(dict.fromkeys(FLAG_RE.findall("\n".join(root.itertext())))),
        "limitations": [
            "A syntactically valid message does not prove signature authenticity, acceptance, or settlement.",
            "EPC checks are a documented subset and do not replace the complete rulebook.",
        ],
    }
    if message in {"pacs.008.001.08", "camt.053.001.08"}:
        try:
            import fin2_iso20022

            base = fin2_iso20022.analyze(raw, sepa=False)
        except Exception as exc:
            raise SecBankEbicsError(f"base ISO 20022 validation failed: {str(exc)[:240]}") from None
        result["base_analysis"] = base
        result["schema_valid"] = base.get("schema_valid")
        result["valid"] = base.get("valid")
        if message == "pacs.008.001.08":
            extension = _extended_pacs008(body, namespace)
            result.update(extension)
            result["sct_inst"] = _sct_inst_assessment(
                extension, profile == "sct-inst-2025"
            )
            if result["sct_inst"]["assessed"]:
                result["valid"] = bool(result["valid"]) and bool(
                    result["sct_inst"]["conforms_to_checked_subset"]
                )
        else:
            result["statements"] = base.get("statements", [])
            result["valid"] = base.get("valid")
    elif message == "pacs.002.001.10":
        payload = _pacs002(body, namespace)
        result.update(payload)
        result["sct_inst"] = _sct_inst_status_assessment(
            payload, profile == "sct-inst-2025"
        )
        result["valid"] = not result["sct_inst"]["issues"]
        result["limitations"].append(
            "No pacs.002 XSD is bundled; namespace, cardinality, and extracted semantics were checked."
        )
    else:
        result.update(_camt054(body, namespace))
        result["valid"] = True
        result["limitations"].append(
            "No camt.054 XSD is bundled; namespace, cardinality, and extracted semantics were checked."
        )
    return result


@_public
def parse_iso20022(data: Any, *, profile: str = "auto") -> dict[str, Any]:
    """Analyze a pinned 2025 EPC pacs.008/.002 or camt.053/.054 document."""

    return _parse_iso20022(data, profile)


def _read(path: Any) -> bytes:
    with Path(path).open("rb") as stream:
        return stream.read(MAX_BYTES + 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    ebics_parser = subparsers.add_parser("ebics", help="parse EBICS H004/H005 XML")
    ebics_parser.add_argument("file")
    iso_parser = subparsers.add_parser("iso20022", help="parse EPC ISO 20022 XML")
    iso_parser.add_argument("file")
    iso_parser.add_argument(
        "--profile", choices=("auto", "sct-inst-2025"), default="auto"
    )
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError):
        return 2
    try:
        raw = _read(arguments.file)
        if arguments.command == "ebics":
            result = parse_ebics(raw)
        else:
            result = parse_iso20022(raw, profile=arguments.profile)
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        return 0 if result.get("valid", True) else 1
    except (SecBankEbicsError, OSError, TypeError, ValueError) as exc:
        print(f"sec_bank_ebics: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "SecBankEbicsError",
    "parse_ebics",
    "parse_iso20022",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
