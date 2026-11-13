#!/usr/bin/env python3
"""Offline air-waybill checksum and ULD identifier analysis.

AWB: three-digit airline accounting prefix + seven-digit serial + mod-7 digit.
ULD: type (alpha/alphanumeric/alphanumeric), four/five-character serial, owner.
ULD syntax checks do not certify a registered type, owner or physical airworthiness.
No lookup, registry request, correction or candidate enumeration is performed.
References: Australian Border Force Air Waybill Number Validation; IATA ULD ID
Code overview; dnata Aircraft Handling SOP ULD ID composition table.
"""
from __future__ import annotations

import argparse
import json
import re
import sys


class TransportCargoError(ValueError):
    """Malformed or unsupported air-cargo identifier."""


def _bounded(value: str) -> str:
    if not isinstance(value, str) or len(value) > 64 or not value.isascii():
        raise TransportCargoError("identifier must be at most 64 ASCII characters")
    return value.strip()


def parse_awb(value: str) -> dict:
    """Parse an AWB and report its checksum status; preserve all leading zeroes."""
    value = _bounded(value)
    match = re.fullmatch(r"([0-9]{3})[- ]?([0-9]{7})([0-9])", value)
    if match is None:
        raise TransportCargoError("expected airline prefix and eight-digit AWB number")
    prefix, serial, digit = match.groups()
    return {"kind": "air_waybill", "airline_prefix": prefix, "serial": serial,
            "check_digit": int(digit), "checksum_valid": int(serial) % 7 == int(digit),
            "canonical": f"{prefix}-{serial}{digit}"}


def parse_uld(value: str) -> dict:
    """Split the IATA ULD identifier syntax; no type/owner registry assertions."""
    value = _bounded(value)
    # IATA composition a,m,m / m,n,n,n,(n) / m,m; m = alphanumeric.
    match = re.fullmatch(r"([A-Z][A-Z0-9]{2})([A-Z0-9][0-9]{3,4})([A-Z0-9]{2})", value)
    if match is None:
        raise TransportCargoError("expected ULD type, four/five-character serial and owner")
    type_code, serial, owner = match.groups()
    return {"kind": "uld", "type_code": type_code, "category_code": type_code[0],
            "base_code": type_code[1], "contour_code": type_code[2],
            "serial": serial, "owner_code": owner, "canonical": value,
            "registry_verified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("awb", "uld"))
    parser.add_argument("value", help="saved identifier to analyze")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = (parse_awb if args.kind == "awb" else parse_uld)(args.value)
        print(json.dumps(result, sort_keys=True))
        return 0
    except TransportCargoError as exc:
        print(f"transport_cargo: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
