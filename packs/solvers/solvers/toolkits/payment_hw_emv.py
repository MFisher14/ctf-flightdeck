#!/usr/bin/env python3
"""Offline EMV response semantics and exact DOL field mapping.

Reuses financial's BER reader; input is response DATA, without SW1/SW2.
The inherited EMV reader accepts 00/FF padding between TLV objects.
No cryptogram verification or issuer-specific IAD interpretation is attempted.
Public parsers accept bytes/bytearray or whitespace-separated hex strings and
raise PaymentEMVError for malformed/unsupported input. CLI emits JSON.
"""
import argparse
import json
import sys
from pathlib import Path

import financial


class PaymentEMVError(ValueError):
    """Invalid or unsupported EMV data."""


MAX_INPUT = 1024 * 1024


def _bytes(value):
    if isinstance(value, str):
        if len(value) > MAX_INPUT * 3:
            raise PaymentEMVError("hex input too large")
        try:
            value = bytes.fromhex(value)
        except ValueError as exc:
            raise PaymentEMVError("invalid hex input") from exc
    if not isinstance(value, (bytes, bytearray)):
        raise PaymentEMVError("expected bytes or hex string")
    if len(value) > MAX_INPUT:
        raise PaymentEMVError("input too large")
    return bytes(value)


def _nodes(data):
    try:
        nodes, consumed = financial._tlv_walk(data, 0, len(data), 0, [4096])
    except (financial.TLVError, ValueError, IndexError, OverflowError, RecursionError) as exc:
        raise PaymentEMVError("malformed BER-TLV") from exc
    if consumed != len(data) or not nodes:
        raise PaymentEMVError("empty or incomplete TLV data")
    return nodes


def _template(data):
    nodes = _nodes(_bytes(data))
    if len(nodes) != 1 or nodes[0]["tag"] not in ("80", "77"):
        raise PaymentEMVError("expected exactly one response template 80 or 77")
    return nodes[0]


def _children(node):
    result = {}
    for child in node["children"]:
        tag = child["tag"]
        if tag in result or child["constructed"]:
            raise PaymentEMVError("duplicate or constructed response field")
        result[tag] = child["value"]
    return result


def _field(fields, tag, length=None, required=True):
    value = fields.get(tag)
    if value is None:
        if required:
            raise PaymentEMVError(f"missing field {tag}")
        return None
    if length is not None and len(value) != length:
        raise PaymentEMVError(f"field {tag} must be {length} bytes")
    return value


def parse_cryptogram(data):
    """Extract one GENERATE AC response (format 1/2, including CDA SDAD).

    The CID's top two bits identify AAC/TC/ARQC; reserved 11 is rejected.
    For CDA with SDAD but no plain AC, application_cryptogram is None.
    """
    node = _template(data)
    if node["tag"] == "80":
        value = node["value"]
        if not 11 <= len(value) <= 43:
            raise PaymentEMVError("format-1 cryptogram needs 11..43 bytes")
        fields = {"9F27": value[:1], "9F36": value[1:3], "9F26": value[3:11]}
        if len(value) > 11:
            fields["9F10"] = value[11:]
    else:
        fields = _children(node)
    cid = _field(fields, "9F27", 1)[0]
    if cid >> 6 == 3:
        raise PaymentEMVError("reserved cryptogram type")
    atc = _field(fields, "9F36", 2)
    ac = _field(fields, "9F26", 8, required=False)
    sdad = _field(fields, "9F4B", required=False)
    if ac is None and not sdad:
        raise PaymentEMVError("missing application cryptogram or signed dynamic data")
    if sdad is not None and not sdad:
        raise PaymentEMVError("empty signed dynamic data")
    iad = _field(fields, "9F10", required=False)
    if iad is not None and len(iad) > 32:
        raise PaymentEMVError("IAD must contain at most 32 bytes")
    return {
        "template": node["tag"], "cryptogram_type": ("AAC", "TC", "ARQC")[cid >> 6],
        "cid": f"{cid:02X}", "atc": int.from_bytes(atc, "big"),
        "application_cryptogram": ac.hex().upper() if ac is not None else None,
        "issuer_application_data": iad.hex().upper() if iad is not None else None,
        "signed_dynamic_application_data": sdad.hex().upper() if sdad is not None else None,
        "fields": {k: v.hex().upper() for k, v in fields.items()},
        "cryptogram_verified": False, "iad_interpretation": "opaque; requires issuer profile",
    }


def parse_afl(data):
    """Read four-byte AFL entries; validate SFI, record bounds and ODA count."""
    data = _bytes(data)
    if len(data) % 4:
        raise PaymentEMVError("AFL length must be a multiple of four")
    entries = []
    for offset in range(0, len(data), 4):
        sfi_byte, first, last, count = data[offset:offset + 4]
        sfi = sfi_byte >> 3
        if sfi_byte & 7 or not 1 <= sfi <= 30 or not 1 <= first <= last or count > last - first + 1:
            raise PaymentEMVError("invalid AFL record range/SFI/ODA count")
        entries.append({"sfi": sfi, "first_record": first, "last_record": last,
                        "offline_authentication_records": count})
    return entries


def parse_gpo(data):
    """Extract AIP and AFL from GPO template 80 or 77.

    Format 77 without AFL is retained for contactless profiles that omit it.
    No kernel-specific interpretation of AIP bits is guessed.
    """
    node = _template(data)
    if node["tag"] == "80":
        value = node["value"]
        if len(value) < 2:
            raise PaymentEMVError("format-1 GPO missing AIP")
        fields = {"82": value[:2], "94": value[2:]}
    else:
        fields = _children(node)
    aip = _field(fields, "82", 2)
    afl = _field(fields, "94", required=False)
    return {"template": node["tag"], "aip": aip.hex().upper(),
            "afl": parse_afl(afl) if afl is not None else None,
            "fields": {k: v.hex().upper() for k, v in fields.items()}}


def parse_dol(data):
    """Read tag + ONE length byte entries, not BER-TLV. Preserve duplicates."""
    data = _bytes(data)
    if len(data) > 4096:
        raise PaymentEMVError("DOL too large")
    entries, cursor, offset = [], 0, 0
    while cursor < len(data):
        if data[cursor] in (0, 255):
            raise PaymentEMVError("padding is not a DOL entry")
        try:
            tag, constructed, _, end = financial._parse_tag(data, cursor)
        except (financial.TLVError, ValueError, IndexError) as exc:
            raise PaymentEMVError("invalid DOL tag") from exc
        if constructed or end >= len(data):
            raise PaymentEMVError("constructed DOL tag or missing length")
        if end - cursor > 1 and data[cursor + 1] & 0x7F == 0:
            raise PaymentEMVError("invalid high-tag encoding")
        length = data[end]
        entries.append({"tag": tag, "name": financial.EMV_TAGS.get(tag, "unknown tag"),
                        "length": length, "offset": offset})
        offset += length
        cursor = end + 1
    return entries


def map_dol(dol, data):
    """Split captured PDOL/CDOL/DDOL data using an explicit corresponding DOL."""
    entries, data = parse_dol(dol), _bytes(data)
    if sum(entry["length"] for entry in entries) != len(data):
        raise PaymentEMVError("DOL total does not match transaction data length")
    for entry in entries:
        start = entry["offset"]
        value = data[start:start + entry["length"]]
        entry["value"] = value.hex().upper()
        entry["decoded"] = financial._emv_decode_value(entry["tag"], value)
    return entries


def parse_issuer_authentication(data, method):
    """Split tag-91 VALUE given an explicit ARPC method (1 or 2).

    Method 1: eight-byte ARPC + optional issuer bytes. Method 2: four-byte
    ARPC + four-byte CSU + optional proprietary authentication data. No MAC
    verification, ARC recovery, or issuer-profile inference is performed.
    """
    data = _bytes(data)
    if type(method) is not int or method not in (1, 2):
        raise PaymentEMVError("ARPC method must be 1 or 2")
    if not 8 <= len(data) <= 16:
        raise PaymentEMVError("issuer authentication data must be 8..16 bytes")
    return {"method": method, "arpc": data[:8 if method == 1 else 4].hex().upper(),
            "card_status_update": data[4:8].hex().upper() if method == 2 else None,
            "issuer_additional_data": data[8:].hex().upper(), "cryptogram_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("cryptogram", "gpo", "dol", "issuer"))
    parser.add_argument("file", help="raw binary input (response data, no SW1/SW2)")
    parser.add_argument("--hex", action="store_true", help="file contains hex text")
    parser.add_argument("--dol", help="hex DOL defining data in file (dol mode)")
    parser.add_argument("--method", type=int, choices=(1, 2), help="ARPC method for issuer mode")
    try:
        args = parser.parse_args(argv)
        with Path(args.file).open("rb") as stream:
            data = stream.read(MAX_INPUT * 3 + 1 if args.hex else MAX_INPUT + 1)
        if args.hex:
            data = data.decode("ascii")
        if args.mode == "cryptogram":
            result = parse_cryptogram(data)
        elif args.mode == "gpo":
            result = parse_gpo(data)
        elif args.mode == "dol":
            result = map_dol(args.dol, data) if args.dol is not None else parse_dol(data)
        else:
            result = parse_issuer_authentication(data, args.method)
        print(json.dumps(result, indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (PaymentEMVError, OSError, ValueError) as exc:
        print(f"payment_hw_emv: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
