#!/usr/bin/env python3
"""Offline evidence matcher for the published Industroyer SIPROTEC DoS IOC.

ESET, WIN32/INDUSTROYER (2017-06-12), printed page 13, Figure 20, documents
an 18-byte UDP payload to destination port 50000: bytes 0..1 are 11 49,
bytes 2..15 are zero, and bytes 16..17 are 28 9e. These are observed bytes,
not a specification of the proprietary protocol's field meanings.

Public detectors return a JSON-compatible evidence record on exact match,
None on a well-formed nonmatch, and raise SiprotecError on malformed inputs.
The CLI reads one supplied payload or UDP datagram; it has no network or
packet-generation functionality. PCAP extraction belongs to ics_capture.py.
An IOC match does not establish device vulnerability, successful exploitation,
or malware attribution. Partial or variant payloads deliberately do not match.
"""
from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path


MAX_DATAGRAM = 65535
MAX_PAYLOAD = MAX_DATAGRAM - 8
REPORT_URL = "https://cdn1.esetstatic.com/ESET/INT/Landing/2017/black-hat/WIN32_Industroyer-USLetter-WEB.pdf"


class SiprotecError(ValueError):
    """Malformed or out-of-bounds supplied forensic evidence."""


def _blob(data, maximum):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SiprotecError("evidence must be bytes")
    try:
        length = data.nbytes if isinstance(data, memoryview) else len(data)
        if length > maximum:
            raise SiprotecError("evidence exceeds size limit")
        return bytes(data)
    except (TypeError, ValueError) as exc:
        if isinstance(exc, SiprotecError):
            raise
        raise SiprotecError("invalid byte buffer") from exc


def detect_payload(data: bytes, *, destination_port: int | None = None,
                   transport: str | None = None) -> dict | None:
    """Match a complete supplied payload, optionally constrained by flow metadata.

    Omitting metadata yields only ``documented_payload`` evidence; supplying
    UDP and destination 50000 yields ``documented_udp_flow`` evidence. A known
    wrong transport/port cannot match. No direction is inferred from source port.
    """
    data = _blob(data, MAX_PAYLOAD)
    if destination_port is not None and (type(destination_port) is not int
                                        or not 0 <= destination_port <= 65535):
        raise SiprotecError("destination_port must be a 16-bit integer or None")
    if transport is not None:
        if not isinstance(transport, str) or transport.lower() not in ("udp", "tcp"):
            raise SiprotecError("transport must be udp, tcp, or None")
        transport = transport.lower()
    if transport == "tcp" or destination_port not in (None, 50000):
        return None
    if (len(data) != 18 or data[:2] != b"\x11\x49"
            or any(data[2:16]) or data[16:] != b"\x28\x9e"):
        return None
    complete_context = transport == "udp" and destination_port == 50000
    return {
        "matched": True,
        "rule_id": "industroyer_siprotec_cve_2015_5374",
        "cve": "CVE-2015-5374",
        "evidence": "documented_udp_flow" if complete_context else "documented_payload",
        "payload_length": 18,
        "destination_port": destination_port,
        "transport": transport,
        "reference": {"url": REPORT_URL, "page": 13, "figure": 20},
        "assessment": "Published IOC match; exploitation success, device vulnerability and attribution are not established.",
    }


def detect_udp_datagram(data: bytes) -> dict | None:
    """Match one exact UDP header plus payload, with no IP or Ethernet header.

    RFC 768's 8-byte header is parsed in network order; the length must consume
    the complete buffer. UDP checksum validity cannot be established without
    the IP pseudo-header and is explicitly left unverified. Fragment reassembly
    and capture extraction must happen before this function is called.
    """
    data = _blob(data, MAX_DATAGRAM)
    if len(data) < 8:
        raise SiprotecError("truncated UDP header")
    source_port = int.from_bytes(data[0:2], "big")
    destination_port = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:6], "big")
    if length < 8 or length != len(data):
        raise SiprotecError("UDP length does not match the complete datagram")
    result = detect_payload(data[8:], destination_port=destination_port, transport="udp")
    if result is not None:
        result.update(source_port=source_port, udp_length=length, checksum_verified=False)
    return result


def main(argv=None) -> int:
    """Analyze a supplied regular file; 0 for a completed check, 2 for invalid input."""
    if argv is not None and (not isinstance(argv, (list, tuple))
                             or any(not isinstance(arg, str) for arg in argv)):
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--format", choices=("payload", "udp"), default="payload")
    parser.add_argument("--destination-port", type=int)
    parser.add_argument("--transport", choices=("udp", "tcp"))
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.format == "udp" and (args.destination_port is not None or args.transport is not None):
            raise SiprotecError("UDP format reads flow metadata from the supplied header")
        if not stat.S_ISREG(args.artifact.stat().st_mode):
            raise SiprotecError("artifact must be a regular file")
        with args.artifact.open("rb") as stream:
            data = stream.read(MAX_DATAGRAM + 1)
        result = (detect_udp_datagram(data) if args.format == "udp" else
                  detect_payload(data, destination_port=args.destination_port, transport=args.transport))
        print(json.dumps(result if result is not None else {"matched": False}, sort_keys=True))
        return 0
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"ot_siprotec_signature: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
