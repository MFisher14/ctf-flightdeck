#!/usr/bin/env python3
"""Offline selected MAP argument/result decoder, 3GPP TS 29.002.

Input is the BER parameter SEQUENCE extracted from TCAP, not a TCAP envelope.
An explicit MAP local operation number and argument/result direction prevent
confusing MAP with CAP, whose operation namespace is separate. Definite-length
BER only; unknown extension values remain raw and are structurally checked.
No network, target interaction, ASN.1 compiler, or artifact execution.

API: parse_map(data, operation, result=False), decode_tbcd(data),
decode_isdn(data). Malformed/unsupported inputs raise MAPError exclusively.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


class MAPError(ValueError):
    """Invalid, unsupported, ambiguous, or over-budget MAP input."""


MAX_INPUT = 1024 * 1024
MAX_NODES = 2048
MAX_DEPTH = 16
OPERATIONS = {44: "mt-ForwardSM", 45: "sendRoutingInfoForSM", 46: "mo-ForwardSM",
              59: "processUnstructuredSS-Request", 60: "unstructuredSS-Request",
              61: "unstructuredSS-Notify", 70: "provideSubscriberInfo",
              71: "anyTimeInterrogation"}


def _bytes(data, maximum=MAX_INPUT):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise MAPError("input must be bytes")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > maximum:
            raise MAPError("input exceeds size budget")
        return bytes(data)
    except (ValueError, TypeError) as exc:
        raise MAPError("invalid or oversized byte buffer") from exc


def decode_tbcd(data, decimal_only=False):
    """Strict low-nibble-first TBCD; F is permitted only as final high filler."""
    data = _bytes(data, 32)
    if not data:
        raise MAPError("empty TBCD")
    alphabet = "0123456789*#abc"
    digits = []
    for i, octet in enumerate(data):
        for high, nibble in ((False, octet & 15), (True, octet >> 4)):
            if nibble == 15:
                if high and i == len(data) - 1:
                    continue
                raise MAPError("TBCD filler is not final high nibble")
            if decimal_only and nibble > 9:
                raise MAPError("nondecimal IMSI digit")
            digits.append(alphabet[nibble])
    return "".join(digits)


def decode_isdn(data):
    """Decode ISDN-AddressString TON/NPI plus TBCD digits (TS 29.002)."""
    return _address(data, 9)


def _address(data, maximum):
    data = _bytes(data, maximum)
    if not data or not data[0] & 0x80:
        raise MAPError("invalid ISDN address header/length")
    return {"ton": (data[0] >> 4) & 7, "npi": data[0] & 15,
            "digits": decode_tbcd(data[1:]) if len(data) > 1 else "", "raw_hex": data.hex()}


def _imsi(data):
    if not 3 <= len(data) <= 8:
        raise MAPError("IMSI length outside 3..8 octets")
    digits = decode_tbcd(data, decimal_only=True)
    if len(digits) > 15:
        raise MAPError("IMSI exceeds 15 digits")
    return digits


def _ber(data, start, end, depth, budget):
    if depth > MAX_DEPTH:
        raise MAPError("BER depth limit")
    nodes = []
    while start < end:
        budget[0] += 1
        if budget[0] > MAX_NODES or end - start < 2:
            raise MAPError("BER node limit or truncated header")
        offset, tag = start, data[start]
        start += 1
        if tag & 31 == 31:
            # Preserve unfamiliar high-tag identifiers without guessing schema.
            count, number = 0, 0
            while True:
                if start >= end or count >= 4:
                    raise MAPError("invalid high-tag BER identifier")
                octet = data[start]
                start += 1
                if count == 0 and octet & 127 == 0:
                    raise MAPError("nonminimal high-tag BER identifier")
                number = (number << 7) | (octet & 127)
                count += 1
                if not octet & 128:
                    break
            if number < 31:
                raise MAPError("nonminimal high-tag BER identifier")
        tag_hex = data[offset:start].hex()
        if start >= end:
            raise MAPError("missing BER length")
        length = data[start]
        start += 1
        if length & 128:
            count = length & 127
            if not count or count > 4 or start + count > end:
                raise MAPError("unsupported indefinite or invalid BER length")
            length = int.from_bytes(data[start:start + count], "big")
            start += count
        value_end = start + length
        if value_end > end:
            raise MAPError("BER value exceeds containing element")
        if tag == 0:
            raise MAPError("unexpected BER end-of-contents")
        node = {"tag": tag if len(tag_hex) == 2 else None, "tag_hex": tag_hex,
                "value": data[start:value_end]}
        if tag & 32:
            node["children"] = _ber(data, start, value_end, depth + 1, budget)
        nodes.append(node)
        start = value_end
    return nodes


def _expect(nodes, index, tag):
    if index >= len(nodes) or nodes[index]["tag"] != tag:
        raise MAPError(f"expected MAP field tag {tag:02x} at index {index}")
    return nodes[index]


def _raw(nodes):
    return [{"tag_hex": n["tag_hex"], "raw_hex": n["value"].hex()} for n in nodes]


def _unique_tail(nodes, forbidden=()):
    seen = set(forbidden)
    for node in nodes:
        if node["tag_hex"] in seen:
            raise MAPError("duplicate or out-of-order MAP field")
        seen.add(node["tag_hex"])
    return _raw(nodes)


def _requested(node):
    fields = {}
    nulls = {0x80: "locationInformation", 0x81: "subscriberState", 0x83: "currentLocation",
             0x86: "imei", 0x85: "ms-classmark", 0x87: "mnpRequestedInfo",
             0x8B: "locationInformationEPS-Supported", 0x88: "t-adsData",
             0x8A: "servingNodeIndication", 0x8C: "localTimeZoneRequest"}
    children = node.get("children", [])
    _unique_tail(children)
    unknown = []
    for child in children:
        tag, value = child["tag"], child["value"]
        if tag in nulls:
            if value:
                raise MAPError("NULL requested-info flag contains data")
            fields[nulls[tag]] = True
        elif tag == 0x84:
            if len(value) != 1 or value[0] > 1:
                raise MAPError("unsupported requestedDomain")
            fields["requestedDomain"] = "cs-Domain" if value[0] == 0 else "ps-Domain"
        else:
            unknown.append(child)
    if unknown:
        fields["raw_fields"] = _raw(unknown)
    return fields


def _rp_address(node, destination):
    tag, value = node["tag"], node["value"]
    if tag == 0x85:
        if value:
            raise MAPError("NULL SM-RP address contains data")
        return {"kind": "noSM-RP-DA" if destination else "noSM-RP-OA"}
    if tag == 0x84:
        return {"kind": "serviceCentreAddress", "address": _address(value, 20)}
    if tag == 0x80 and destination:
        return {"kind": "imsi", "imsi": _imsi(value)}
    if tag == 0x81 and destination:
        if len(value) != 4:
            raise MAPError("LMSI must have four octets")
        return {"kind": "lmsi", "raw_hex": value.hex()}
    if tag == 0x82 and not destination:
        return {"kind": "msisdn", "address": decode_isdn(value)}
    raise MAPError("invalid SM-RP address choice")


def parse_map(data, operation, result=False):
    """Decode selected MAP parameters; raw extension BER is preserved."""
    data = _bytes(data)
    if type(operation) is not int or operation not in OPERATIONS or type(result) is not bool:
        raise MAPError("unsupported MAP operation or direction")
    if result and operation not in (45, 59, 60):
        raise MAPError("result schema not implemented for this operation")
    top = _ber(data, 0, len(data), 0, [0])
    if len(top) != 1 or top[0]["tag"] != 0x30:
        raise MAPError("expected exactly one parameter SEQUENCE")
    nodes = top[0]["children"]
    fields = {}
    if operation == 45 and not result:
        fields["msisdn"] = decode_isdn(_expect(nodes, 0, 0x80)["value"])
        value = _expect(nodes, 1, 0x81)["value"]
        if len(value) != 1:
            raise MAPError("invalid sm-RP-PRI boolean")
        fields["sm-RP-PRI"] = value != b"\0"
        fields["serviceCentreAddress"] = _address(_expect(nodes, 2, 0x82)["value"], 20)
        tail = _unique_tail(nodes[3:], ("80", "81", "82"))
    elif operation == 45:
        fields["imsi"] = _imsi(_expect(nodes, 0, 4)["value"])
        location = _expect(nodes, 1, 0xA0)["children"]
        info = {"networkNode-Number": decode_isdn(_expect(location, 0, 0x81)["value"])}
        index = 1
        if len(location) > 1 and location[1]["tag"] == 4:
            if len(location[1]["value"]) != 4:
                raise MAPError("LMSI must have four octets")
            info["lmsi_hex"] = location[1]["value"].hex()
            index += 1
        info["raw_fields"] = _unique_tail(location[index:], ("81", "04"))
        fields["locationInfoWithLMSI"] = info
        tail = _unique_tail(nodes[2:], ("04", "a0"))
    elif operation == 70:
        fields["imsi"] = _imsi(_expect(nodes, 0, 0x80)["value"])
        index = 1
        if len(nodes) > 1 and nodes[1]["tag"] == 0x81:
            if len(nodes[1]["value"]) != 4:
                raise MAPError("LMSI must have four octets")
            fields["lmsi_hex"] = nodes[1]["value"].hex()
            index += 1
        fields["requestedInfo"] = _requested(_expect(nodes, index, 0xA2))
        tail = _unique_tail(nodes[index + 1:], ("80", "81", "a2"))
    elif operation == 71:
        identity = _expect(nodes, 0, 0xA0)["children"]
        if len(identity) != 1 or identity[0]["tag"] not in (0x80, 0x81):
            raise MAPError("invalid explicit subscriberIdentity choice")
        ident = identity[0]
        fields["subscriberIdentity"] = ({"imsi": _imsi(ident["value"])} if ident["tag"] == 0x80
                                        else {"msisdn": decode_isdn(ident["value"])})
        fields["requestedInfo"] = _requested(_expect(nodes, 1, 0xA1))
        fields["gsmSCF-Address"] = decode_isdn(_expect(nodes, 2, 0x83)["value"])
        tail = _unique_tail(nodes[3:], ("a0", "a1", "83"))
    elif operation in (44, 46):
        if len(nodes) < 3:
            raise MAPError("missing SM-RP fields")
        fields["sm-RP-DA"] = _rp_address(nodes[0], True)
        fields["sm-RP-OA"] = _rp_address(nodes[1], False)
        tpdu = _expect(nodes, 2, 4)["value"]
        if not 1 <= len(tpdu) <= 200:
            raise MAPError("SM-RP-UI outside 1..200 octets")
        fields["sm-RP-UI_hex"] = tpdu.hex()
        tail = _unique_tail(nodes[3:])
    else:
        dcs = _expect(nodes, 0, 4)["value"]
        value = _expect(nodes, 1, 4)["value"]
        if len(dcs) != 1 or not 1 <= len(value) <= 160:
            raise MAPError("invalid USSD DCS/string length")
        fields["ussd-DataCodingScheme"] = dcs[0]
        fields["ussd-String_hex"] = value.hex()
        fields["text"] = None
        if dcs[0] == 0x48:  # Uncompressed UCS2, no message class (TS 23.038).
            if len(value) % 2 or any(0xD800 <= int.from_bytes(value[i:i+2], "big") <= 0xDFFF
                                      for i in range(0, len(value), 2)):
                raise MAPError("invalid USSD UCS2")
            try:
                fields["text"] = value.decode("utf-16-be")
            except UnicodeError as exc:
                raise MAPError("invalid USSD UCS2") from exc
        index = 2
        if not result and len(nodes) > index and nodes[index]["tag"] == 4:
            if len(nodes[index]["value"]) != 1:
                raise MAPError("invalid alertingPattern length")
            fields["alertingPattern"] = nodes[index]["value"][0]
            index += 1
        if not result and len(nodes) > index and nodes[index]["tag"] == 0x80:
            fields["msisdn"] = decode_isdn(nodes[index]["value"])
            index += 1
        if len(nodes) != index:
            raise MAPError("unexpected USSD fields")
        tail = []
    return {"namespace": "MAP", "operation": operation, "name": OPERATIONS[operation],
            "direction": "result" if result else "argument", "fields": fields,
            "raw_extensions": tail}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--operation", type=int, required=True, choices=tuple(OPERATIONS))
    parser.add_argument("--result", action="store_true")
    parser.add_argument("--hex", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open("rb") as handle:
            data = handle.read(MAX_INPUT * (3 if args.hex else 1) + 1)
        if args.hex:
            if len(data) > MAX_INPUT * 3:
                raise MAPError("hex input exceeds size budget")
            data = bytes.fromhex(data.decode("ascii"))
        print(json.dumps(parse_map(data, args.operation, args.result), indent=2, ensure_ascii=False))
        return 0
    except (MAPError, OSError, ValueError, UnicodeError) as exc:
        print(f"MAP error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
