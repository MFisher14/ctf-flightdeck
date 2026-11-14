#!/usr/bin/env python3
"""Offline PIV CHUID and certificate-object reader (NIST SP 800-73 pt1).

Input is a GET DATA response's data field (53 wrapper), or an exported object's
bare TLVs. Pass apdu=True only when the input includes the SW1/SW2 status word.
This is not a generic CAC reader, card driver, authenticator or signature checker.
FASC-N and CMS signatures remain opaque. Certificates are syntax-checked using
the existing cryptography dependency; no chain, revocation or signature checks.
All malformed/unsupported public input raises PIVError.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zlib
from datetime import date
from pathlib import Path
from uuid import UUID

MAX_BYTES = 65536
MAX_ITEMS = 128


class PIVError(ValueError):
    """Invalid, unsupported or oversized PIV artifact."""


def _tlvs(data):
    # SCEPACS tags 30/3E are opaque, irrespective of ASN.1 constructed bits.
    out = []
    p = 0
    while p < len(data):
        start = p
        tag = data[p]
        p += 1
        if tag in (0, 255):
            raise PIVError("invalid PIV tag")
        if tag & 31 == 31:
            count = 0
            while True:
                if p >= len(data) or count == 3:
                    raise PIVError("truncated or oversized tag")
                b = data[p]
                if count == 0 and b & 127 == 0:
                    raise PIVError("invalid high-tag encoding")
                tag = (tag << 8) | b
                p += 1
                count += 1
                if not b & 128:
                    break
        if p >= len(data):
            raise PIVError("missing length")
        length = data[p]
        p += 1
        if length & 128:
            count = length & 127
            if not 1 <= count <= 3 or p + count > len(data):
                raise PIVError("indefinite, oversized or truncated length")
            length = int.from_bytes(data[p:p + count], "big")
            p += count
        if length > len(data) - p:
            raise PIVError("value exceeds object boundary")
        out.append((tag, data[p:p + length], start))
        p += length
        if len(out) > MAX_ITEMS:
            raise PIVError("too many data elements")
    return out


def _certificate(data, info):
    if info not in (b"\x00", b"\x01"):
        raise PIVError("unsupported CertInfo; expected 00 or 01")
    if info == b"\x01":
        dec = zlib.decompressobj(31)
        try:
            data = dec.decompress(data, MAX_BYTES + 1)
        except zlib.error as exc:
            raise PIVError("invalid gzip certificate") from exc
        if len(data) > MAX_BYTES or not dec.eof or dec.unused_data or dec.unconsumed_tail:
            raise PIVError("oversized, truncated or concatenated gzip certificate")
    if not data:
        raise PIVError("empty certificate")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        cert = x509.load_der_x509_certificate(data)
        if cert.public_bytes(Encoding.DER) != data:
            raise PIVError("certificate has trailing or non-DER data")
    except PIVError:
        raise
    except Exception as exc:
        raise PIVError("invalid DER certificate or cryptography unavailable") from exc
    return data


def parse_piv(data: bytes, *, kind: str = "auto", apdu: bool = False) -> dict:
    """Parse one CHUID/certificate object; return JSON-safe facts and exact hex.

    Empty issuer signatures are reported as unsigned, never authenticated.
    Unknown optional data elements are retained. Duplicate tags are rejected.
    """
    if type(data) not in (bytes, bytearray) or not 0 < len(data) <= MAX_BYTES:
        raise PIVError("expected 1..65536 bytes")
    if type(kind) is not str or kind not in ("auto", "chuid", "certificate"):
        raise PIVError("unsupported object kind")
    if type(apdu) is not bool:
        raise PIVError("apdu must be bool")
    data = bytes(data)
    if apdu:
        if not data.endswith(b"\x90\x00"):
            raise PIVError("missing successful APDU status 9000")
        data = data[:-2]
    items = _tlvs(data)
    wrapped = len(items) == 1 and items[0][0] == 0x53
    if wrapped:
        items = _tlvs(items[0][1])
    fields = {}
    for tag, value, _ in items:
        if tag in fields:
            raise PIVError("duplicate data-element tag")
        fields[tag] = value
    if kind == "auto":
        is_chuid = 0x30 in fields and 0x34 in fields
        is_cert = 0x70 in fields
        if is_chuid == is_cert:
            raise PIVError("ambiguous or unrecognized PIV object")
        kind = "chuid" if is_chuid else "certificate"
    required = {0x30, 0x34, 0x35, 0x3E, 0xFE} if kind == "chuid" else {0x70, 0x71, 0xFE}
    if not required <= fields.keys():
        raise PIVError("missing mandatory PIV data element")
    if fields[0xFE]:
        raise PIVError("PIV Error Detection Code must be zero length")
    result = {"kind": kind, "wrapped": wrapped, "authenticated": False,
              "fields": [{"tag": f"{tag:02X}", "length": len(value), "hex": value.hex()}
                         for tag, value, _ in items]}
    if kind == "certificate":
        if {0x30, 0x34, 0x35} & fields.keys():
            raise PIVError("mixed CHUID and certificate elements")
        cert = _certificate(fields[0x70], fields[0x71])
        result.update(compressed=fields[0x71] == b"\x01", certificate_der_hex=cert.hex(),
                      certificate_bytes=len(cert))
    else:
        if {0x70, 0x71} & fields.keys():
            raise PIVError("mixed CHUID and certificate elements")
        if len(fields[0x3E]) > 2816:
            raise PIVError("CHUID issuer signature exceeds specification limit")
        for tag, length in ((0x30, 25), (0x34, 16), (0x35, 8), (0x36, 16),
                            (0xEE, 2), (0x32, 4), (0x33, 9)):
            if tag in fields and len(fields[tag]) != length:
                raise PIVError(f"incorrect size for CHUID tag {tag:02X}")
        try:
            expiry = fields[0x35].decode("ascii")
            if not re.fullmatch(r"[0-9]{8}", expiry):
                raise ValueError("not YYYYMMDD")
            iso_expiry = date(int(expiry[:4]), int(expiry[4:6]), int(expiry[6:])).isoformat()
        except (UnicodeError, ValueError) as exc:
            raise PIVError("invalid CHUID expiration date") from exc
        result.update(fasc_n_hex=fields[0x30].hex(), guid=str(UUID(bytes=fields[0x34])),
                      expiration=iso_expiry, signature_present=bool(fields[0x3E]),
                      signature_verified=False)
        if 0x36 in fields:
            result["cardholder_uuid"] = str(UUID(bytes=fields[0x36]))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--kind", choices=("auto", "chuid", "certificate"), default="auto")
    parser.add_argument("--apdu", action="store_true", help="input includes terminal 9000 status")
    parser.add_argument("--certificate-out", type=Path, help="write extracted DER to a new file")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open("rb") as source:
            result = parse_piv(source.read(MAX_BYTES + 1), kind=args.kind, apdu=args.apdu)
        if args.certificate_out:
            if result["kind"] != "certificate":
                raise PIVError("--certificate-out requires a certificate object")
            with args.certificate_out.open("xb") as target:
                target.write(bytes.fromhex(result["certificate_der_hex"]))
        print(json.dumps(result, indent=2))
        return 0
    except (PIVError, OSError, ValueError) as exc:
        print(f"defense_piv: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
