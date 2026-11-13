#!/usr/bin/env python3
"""Strict offline RADIUS and Diameter wire readers.

Complements telecom.py's broad Scapy decoder: exact framing, offsets, bounded
nested AVPs, explicit vendor namespaces, and a small audited dictionary. No
network access, password guessing, or execution. Inputs are raw PDUs/AVP blocks,
not pcap; use the existing capture engines to extract/reassemble transport data.

References: RFC 2865 (RADIUS and PAP), RFC 2869 (Message-Authenticator/EAP),
RFC 6733 (Diameter), RFC 4006 (credit control), 3GPP TS 29.272 (S6a subset).
Unknown values remain hex; unknown VSAs are opaque because not all vendors use
one-byte type/length fields. Dictionary coverage is intentionally incomplete.

CLI: telecom2_aaa.py radius|diameter|avps FILE [--hex] [--secret-file FILE]
All public parse/decrypt functions raise AAAError for invalid input. PAP recovery
with a supplied secret does not authenticate an Access-Request: check the
reported Message-Authenticator where present. No Message-Authenticator is not
proof of vulnerability. Diameter padding is retained, not interpreted as data.
"""
from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import sys

MAX_INPUT = 4 * 1024 * 1024
MAX_ITEMS = 10000
MAX_DEPTH = 16


class AAAError(ValueError):
    """Malformed, unsupported, or resource-limited AAA input."""


def _guard(fn):
    @wraps(fn)
    def guarded(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except AAAError:
            raise
        except Exception as exc:
            raise AAAError(f"invalid input to {fn.__name__}: {type(exc).__name__}") from None
    return guarded


def _bytes(data, limit=MAX_INPUT):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise AAAError("expected bytes")
    if (data.nbytes if isinstance(data, memoryview) else len(data)) > limit:
        raise AAAError("input exceeds size limit")
    result = bytes(data)
    if len(result) > limit:
        raise AAAError("input exceeds size limit")
    return result


def _secret(data):
    result = _bytes(data, 4096)
    if not result:
        raise AAAError("shared secret must not be empty")
    return result


RADIUS_CODES = {1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
                4: "Accounting-Request", 5: "Accounting-Response", 11: "Access-Challenge",
                12: "Status-Server", 13: "Status-Client", 40: "Disconnect-Request",
                41: "Disconnect-ACK", 42: "Disconnect-NAK", 43: "CoA-Request",
                44: "CoA-ACK", 45: "CoA-NAK"}
# RFC 2865/2866/2869; unknown attributes are not assigned speculative types.
RADIUS_DICT = {
    1: ("User-Name", "text"), 2: ("User-Password", "pap"),
    3: ("CHAP-Password", "chap"), 4: ("NAS-IP-Address", "ipv4"),
    5: ("NAS-Port", "u32"), 6: ("Service-Type", "u32"),
    7: ("Framed-Protocol", "u32"), 8: ("Framed-IP-Address", "ipv4"),
    9: ("Framed-IP-Netmask", "ipv4"), 10: ("Framed-Routing", "u32"),
    11: ("Filter-Id", "text"), 12: ("Framed-MTU", "u32"),
    13: ("Framed-Compression", "u32"), 14: ("Login-IP-Host", "ipv4"),
    15: ("Login-Service", "u32"), 16: ("Login-TCP-Port", "u32"),
    18: ("Reply-Message", "text"), 19: ("Callback-Number", "text"),
    20: ("Callback-Id", "text"), 22: ("Framed-Route", "text"),
    24: ("State", "octets"), 25: ("Class", "octets"),
    26: ("Vendor-Specific", "vsa"), 27: ("Session-Timeout", "u32"),
    28: ("Idle-Timeout", "u32"), 29: ("Termination-Action", "u32"),
    30: ("Called-Station-Id", "text"), 31: ("Calling-Station-Id", "text"),
    32: ("NAS-Identifier", "text"), 33: ("Proxy-State", "octets"),
    40: ("Acct-Status-Type", "u32"), 41: ("Acct-Delay-Time", "u32"),
    42: ("Acct-Input-Octets", "u32"), 43: ("Acct-Output-Octets", "u32"),
    44: ("Acct-Session-Id", "text"), 45: ("Acct-Authentic", "u32"),
    46: ("Acct-Session-Time", "u32"), 47: ("Acct-Input-Packets", "u32"),
    48: ("Acct-Output-Packets", "u32"), 49: ("Acct-Terminate-Cause", "u32"),
    50: ("Acct-Multi-Session-Id", "text"), 51: ("Acct-Link-Count", "u32"),
    60: ("CHAP-Challenge", "octets"), 61: ("NAS-Port-Type", "u32"),
    62: ("Port-Limit", "u32"), 63: ("Login-LAT-Port", "text"),
    79: ("EAP-Message", "octets"), 80: ("Message-Authenticator", "auth16"),
    85: ("Acct-Interim-Interval", "u32"), 87: ("NAS-Port-Id", "text"),
    95: ("NAS-IPv6-Address", "ipv6"),
}
# Only vendors whose format is known to use 1-byte type + 1-byte length.
VENDOR_TLV_IDS = frozenset((9, 311, 10415))
VENDOR_DICT = {
    (9, 1): ("Cisco-AVPair", "text"),
    (311, 1): ("MS-CHAP-Response", "octets"),
    (311, 2): ("MS-CHAP-Error", "octets"),
    (311, 16): ("MS-MPPE-Send-Key", "octets"),
    (311, 17): ("MS-MPPE-Recv-Key", "octets"),
    (311, 25): ("MS-CHAP2-Response", "octets"),
    (311, 26): ("MS-CHAP2-Success", "octets"),
    (10415, 1): ("3GPP-IMSI", "text"),
}

# RFC 6733, RFC 4006/8506, and RFC 5778 Service-Selection.
DIAMETER_DICT = {
    (0, 1): ("User-Name", "text"),
    (0, 27): ("Session-Timeout", "u32"),
    (0, 55): ("Event-Timestamp", "time"),
    (0, 257): ("Host-IP-Address", "address"),
    (0, 258): ("Auth-Application-Id", "u32"),
    (0, 259): ("Acct-Application-Id", "u32"),
    (0, 260): ("Vendor-Specific-Application-Id", "grouped"),
    (0, 263): ("Session-Id", "text"),
    (0, 264): ("Origin-Host", "text"),
    (0, 266): ("Vendor-Id", "u32"),
    (0, 268): ("Result-Code", "u32"),
    (0, 269): ("Product-Name", "text"),
    (0, 279): ("Failed-AVP", "grouped"),
    (0, 280): ("Proxy-Host", "text"),
    (0, 281): ("Error-Message", "text"),
    (0, 282): ("Route-Record", "text"),
    (0, 283): ("Destination-Realm", "text"),
    (0, 284): ("Proxy-Info", "grouped"),
    (0, 293): ("Destination-Host", "text"),
    (0, 296): ("Origin-Realm", "text"),
    (0, 297): ("Experimental-Result", "grouped"),
    (0, 298): ("Experimental-Result-Code", "u32"),
    (0, 416): ("CC-Request-Type", "i32"),
    (0, 415): ("CC-Request-Number", "u32"),
    (0, 417): ("CC-Service-Specific-Units", "u64"),
    (0, 420): ("CC-Time", "u32"),
    (0, 421): ("CC-Total-Octets", "u64"),
    (0, 430): ("Final-Unit-Indication", "grouped"),
    (0, 431): ("Granted-Service-Unit", "grouped"),
    (0, 432): ("Rating-Group", "u32"),
    (0, 437): ("Requested-Service-Unit", "grouped"),
    (0, 439): ("Service-Identifier", "u32"),
    (0, 443): ("Subscription-Id", "grouped"),
    (0, 444): ("Subscription-Id-Data", "text"),
    (0, 450): ("Subscription-Id-Type", "i32"),
    (0, 456): ("Multiple-Services-Credit-Control", "grouped"),
    (0, 461): ("Service-Context-Id", "text"),
    (0, 493): ("Service-Selection", "text"),
    (10415, 628): ("Supported-Features", "grouped"),
    (10415, 629): ("Feature-List-ID", "u32"),
    (10415, 630): ("Feature-List", "u32"),
    (10415, 701): ("MSISDN", "tbcd"),
    (10415, 1032): ("RAT-Type", "i32"),
    (10415, 1400): ("Subscription-Data", "grouped"),
    (10415, 1401): ("Terminal-Information", "grouped"),
    (10415, 1402): ("IMEI", "text"),
    (10415, 1403): ("Software-Version", "text"),
    (10415, 1407): ("Visited-PLMN-Id", "plmn"),
    (10415, 1408): ("Requested-EUTRAN-Authentication-Info", "grouped"),
    (10415, 1410): ("Number-Of-Requested-Vectors", "u32"),
    (10415, 1411): ("Re-Synchronization-Info", "octets"),
    (10415, 1413): ("Authentication-Info", "grouped"),
    (10415, 1414): ("E-UTRAN-Vector", "grouped"),
    (10415, 1415): ("UTRAN-Vector", "grouped"),
    (10415, 1416): ("GERAN-Vector", "grouped"),
    (10415, 1419): ("Item-Number", "u32"),
    (10415, 1423): ("Context-Identifier", "u32"),
    (10415, 1424): ("Subscriber-Status", "i32"),
    (10415, 1427): ("APN-OI-Replacement", "text"),
    (10415, 1428): ("All-APN-Configurations-Included-Indicator", "i32"),
    (10415, 1429): ("APN-Configuration-Profile", "grouped"),
    (10415, 1430): ("APN-Configuration", "grouped"),
    (10415, 1431): ("EPS-Subscribed-QoS-Profile", "grouped"),
}


def _value(raw, kind):
    if kind == "text":
        return raw.decode("utf-8")
    if kind in ("u32", "i32", "time", "u64"):
        if len(raw) != (8 if kind == "u64" else 4):
            raise AAAError(f"invalid {kind} length")
        value = int.from_bytes(raw, "big", signed=kind == "i32")
        # Keep NTP seconds intact; era cannot be inferred from four octets.
        return {"ntp_seconds": value} if kind == "time" else value
    if kind in ("ipv4", "ipv6"):
        if len(raw) != (4 if kind == "ipv4" else 16):
            raise AAAError("invalid IP address length")
        return str(ipaddress.ip_address(raw))
    if kind == "address":
        family = int.from_bytes(raw[:2], "big")
        if family not in (1, 2):
            raise AAAError("unsupported Diameter Address family")
        return _value(raw[2:], "ipv4" if family == 1 else "ipv6")
    if kind == "tbcd":
        if not raw:
            raise AAAError("empty TBCD")
        digits = []
        for index, byte in enumerate(raw):
            low, high = byte & 15, byte >> 4
            if low > 9 or (high > 9 and not (high == 15 and index == len(raw) - 1)):
                raise AAAError("invalid decimal TBCD/filler")
            digits.append(str(low))
            if high != 15:
                digits.append(str(high))
        return "".join(digits)
    if kind == "plmn":
        if len(raw) != 3:
            raise AAAError("invalid PLMN length")
        mcc = (raw[0] & 15, raw[0] >> 4, raw[1] & 15)
        mnc = (raw[2] & 15, raw[2] >> 4)
        if raw[1] >> 4 != 15:
            mnc += (raw[1] >> 4,)
        if any(x > 9 for x in mcc + mnc):
            raise AAAError("invalid PLMN BCD")
        return {"mcc": "".join(map(str, mcc)), "mnc": "".join(map(str, mnc))}
    if kind == "pap" and (not 16 <= len(raw) <= 128 or len(raw) % 16):
        raise AAAError("User-Password must contain 16..128 octets in 16-octet blocks")
    if kind == "chap" and len(raw) != 17:
        raise AAAError("CHAP-Password must contain 17 octets")
    if kind == "auth16" and len(raw) != 16:
        raise AAAError("Message-Authenticator must contain 16 octets")
    return raw.hex()


@_guard
def decrypt_user_password(ciphertext, secret, request_authenticator):
    """Recover RFC 2865 PAP bytes with one supplied secret; no authenticity claim."""
    ciphertext = _bytes(ciphertext, 128)
    secret = _secret(secret)
    request_authenticator = _bytes(request_authenticator, 16)
    if len(request_authenticator) != 16:
        raise AAAError("Request Authenticator must contain 16 octets")
    _value(ciphertext, "pap")
    previous, plaintext = request_authenticator, bytearray()
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        mask = hashlib.md5(secret + previous).digest()
        plaintext.extend(x ^ y for x, y in zip(block, mask))
        previous = block
    return bytes(plaintext).rstrip(b"\0")


def _radius_attrs(data, base, vendor=None):
    records, offset = [], 0
    while offset < len(data):
        if len(records) >= MAX_ITEMS or offset + 2 > len(data):
            raise AAAError("truncated or excessive RADIUS attributes")
        code, length = data[offset:offset + 2]
        if not code or length < 2 or offset + length > len(data):
            raise AAAError("invalid RADIUS attribute length/type")
        raw = data[offset + 2:offset + length]
        if vendor is None and code == 79 and not raw:
            raise AAAError("empty EAP-Message fragment")
        name, kind = (RADIUS_DICT.get(code, (f"Attribute-{code}", "octets")) if vendor is None
                      else VENDOR_DICT.get((vendor, code), (f"Vendor-{vendor}-Attribute-{code}", "octets")))
        record = {"type": code, "name": name, "offset": base + offset, "length": length,
                  "data_type": kind, "raw_hex": raw.hex()}
        if kind == "vsa":
            if len(raw) < 5:
                raise AAAError("Vendor-Specific requires vendor ID and vendor data")
            vendor_id = int.from_bytes(raw[:4], "big")
            if not vendor_id or vendor_id >> 24:
                raise AAAError("invalid RFC 2865 Vendor-Id")
            record["vendor_id"] = vendor_id
            record["value"] = raw[4:].hex()
            if vendor_id in VENDOR_TLV_IDS:
                record["attributes"] = _radius_attrs(raw[4:], base + offset + 6, vendor_id)
        else:
            record["value"] = _value(raw, kind)
        records.append(record)
        offset += length
    return records


@_guard
def parse_radius(data, *, secret=None):
    """One exact classic RADIUS PDU (20..4096 bytes), ordered/repeated attributes.

    With secret, decrypt Access-Request PAP and validate Access-Request
    Message-Authenticator. Other code-specific authenticators are not inferred.
    """
    data = _bytes(data, 4096)
    if len(data) < 20 or int.from_bytes(data[2:4], "big") != len(data) or not data[0]:
        raise AAAError("invalid RADIUS PDU header/length")
    attrs = _radius_attrs(data[20:], 20)
    authenticators = [r for r in attrs if r["type"] == 80]
    if len(authenticators) > 1:
        raise AAAError("duplicate Message-Authenticator")
    passwords = [r for r in attrs if r["type"] == 2]
    if len(passwords) > 1:
        raise AAAError("duplicate User-Password")
    result = {"protocol": "RADIUS", "code": data[0],
              "code_name": RADIUS_CODES.get(data[0], f"Code-{data[0]}"),
              "identifier": data[1], "length": len(data), "authenticator_hex": data[4:20].hex(),
              "attributes": attrs, "message_authenticator_present": bool(authenticators),
              "message_authenticator_valid": None}
    fragments = [bytes.fromhex(r["raw_hex"]) for r in attrs if r["type"] == 79]
    if fragments:
        eap = b"".join(fragments)
        if len(eap) < 4 or int.from_bytes(eap[2:4], "big") != len(eap):
            raise AAAError("invalid reassembled EAP length")
        if eap[0] in (1, 2) and len(eap) < 5:
            raise AAAError("EAP Request/Response requires a Type octet")
        if eap[0] in (3, 4) and len(eap) != 4:
            raise AAAError("EAP Success/Failure has no body")
        result["eap"] = {"code": eap[0], "identifier": eap[1], "length": len(eap), "raw_hex": eap.hex()}
    if secret is not None:
        secret = _secret(secret)
        if data[0] != 1:
            raise AAAError("secret processing requires an Access-Request; use verify_radius_response for responses")
        for password in passwords:
            clear = decrypt_user_password(bytes.fromhex(password["raw_hex"]), secret, data[4:20])
            password["plaintext_hex"] = clear.hex()
            try:
                password["plaintext_text"] = clear.decode("utf-8")
            except UnicodeDecodeError:
                password["plaintext_text"] = None
        if authenticators:
            attr = authenticators[0]
            offset = attr["offset"] + 2
            message = data[:offset] + bytes(16) + data[offset + 16:]
            actual = hmac.new(secret, message, hashlib.md5).digest()
            result["message_authenticator_valid"] = hmac.compare_digest(actual, bytes.fromhex(attr["raw_hex"]))
    return result


@_guard
def verify_radius_response(response, request, secret):
    """Check RFC 2865 response authenticator against its Access-Request and secret."""
    response, request, secret = _bytes(response, 4096), _bytes(request, 4096), _secret(secret)
    r, q = parse_radius(response), parse_radius(request)
    if q["code"] != 1 or r["code"] not in (2, 3, 11):
        raise AAAError("expected Access-Request and Access-Accept/Reject/Challenge")
    if r["identifier"] != q["identifier"]:
        return False
    expected = hashlib.md5(response[:4] + request[4:20] + response[20:] + secret).digest()
    return hmac.compare_digest(expected, response[4:20])


def _avps(data, base, depth, budget):
    if depth > MAX_DEPTH:
        raise AAAError("Diameter group depth limit")
    records, offset = [], 0
    while offset < len(data):
        budget[0] += 1
        if budget[0] > MAX_ITEMS or offset + 8 > len(data):
            raise AAAError("truncated or excessive Diameter AVPs")
        code = int.from_bytes(data[offset:offset + 4], "big")
        flags = data[offset + 4]
        length = int.from_bytes(data[offset + 5:offset + 8], "big")
        header = 12 if flags & 128 else 8
        padded = (length + 3) & ~3
        if length < header or offset + padded > len(data):
            raise AAAError("invalid Diameter AVP length/padding")
        vendor = int.from_bytes(data[offset + 8:offset + 12], "big") if flags & 128 else 0
        if flags & 128 and not vendor:
            raise AAAError("Diameter V bit cannot carry vendor ID zero")
        raw = data[offset + header:offset + length]
        name, kind = DIAMETER_DICT.get((vendor, code), (f"AVP-{vendor}-{code}", "octets"))
        record = {"code": code, "vendor_id": vendor, "name": name, "flags": flags,
                  "offset": base + offset, "length": length, "data_type": kind,
                  "raw_hex": raw.hex(), "padding_hex": data[offset + length:offset + padded].hex()}
        if kind == "grouped":
            record["children"] = _avps(raw, base + offset + header, depth + 1, budget)
        else:
            record["value"] = _value(raw, kind)
        records.append(record)
        offset += padded
    return records


@_guard
def walk_diameter_avps(data):
    """Walk an exact AVP block. Unknown vendor/code pairs are opaque, never guessed."""
    return _avps(_bytes(data), 0, 0, [0])


@_guard
def parse_diameter(data):
    """Validate and decode one exact Diameter message, including all nested lengths."""
    data = _bytes(data)
    if len(data) < 20 or data[0] != 1 or int.from_bytes(data[1:4], "big") != len(data) or len(data) % 4:
        raise AAAError("invalid Diameter header/length")
    return {"protocol": "Diameter", "version": 1, "length": len(data), "flags": data[4],
            "command_code": int.from_bytes(data[5:8], "big"),
            "application_id": int.from_bytes(data[8:12], "big"),
            "hop_by_hop": int.from_bytes(data[12:16], "big"),
            "end_to_end": int.from_bytes(data[16:20], "big"),
            "avps": _avps(data[20:], 20, 0, [0])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("radius", "diameter", "avps"))
    parser.add_argument("file")
    parser.add_argument("--hex", action="store_true", help="input file contains whitespace-separated hex")
    parser.add_argument("--secret-file", help="exact shared-secret bytes; RADIUS Access-Request only")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open("rb") as handle:
            data = handle.read(MAX_INPUT * (3 if args.hex else 1) + 1)
        if len(data) > MAX_INPUT * (3 if args.hex else 1):
            raise AAAError("input file exceeds size limit")
        if args.hex:
            data = bytes.fromhex(data.decode("ascii"))
        secret = None
        if args.secret_file:
            if args.kind != "radius":
                raise AAAError("--secret-file requires radius")
            with Path(args.secret_file).open("rb") as handle:
                secret = _secret(handle.read(4097))
        result = (parse_radius(data, secret=secret) if args.kind == "radius" else
                  parse_diameter(data) if args.kind == "diameter" else walk_diameter_avps(data))
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (AAAError, OSError, ValueError, UnicodeError) as exc:
        print(f"telecom2_aaa: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
