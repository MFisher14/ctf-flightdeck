#!/usr/bin/env python3
"""CLI for offline CBC/CTR chosen-plaintext malleability payload generation.

The reusable implementation lives in :mod:`modern_crypto`.  This wrapper accepts only local hex
bytes and prints a candidate for human review; it never opens a connection, calls an oracle, or
submits a value.

Examples::

    python solvers/common/crypto_malleability.py cbc \
      --iv 000102... --ciphertext deadbeef... --edit 5:75736572:726f6f74 --json
    python solvers/common/crypto_malleability.py ctr \
      --ciphertext deadbeef... --edit 5:75736572:726f6f74
"""
from __future__ import annotations

import argparse
import json
import sys

from _shadowed import common_module

modern_crypto = common_module("modern_crypto")  # solvers/toolkits/modern_crypto.py wins a flat import


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def _hex(value: str, label: str) -> bytes:
    if len(value) > modern_crypto.MAX_MALLEABILITY_BYTES * 2:
        raise ValueError(f"{label} exceeds the byte cap")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be even-length hexadecimal") from exc


def _edit(value: str):
    try:
        offset_text, known_text, desired_text = value.split(":", 2)
        offset = int(offset_text, 0)
    except (ValueError, TypeError) as exc:
        raise ValueError("--edit must be OFFSET:KNOWN_HEX:DESIRED_HEX") from exc
    return offset, _hex(known_text, "known plaintext"), _hex(desired_text, "desired plaintext")


def _serialise(result: dict) -> dict:
    return {key: value.hex() if isinstance(value, bytes) else value for key, value in result.items()}


def main(argv=None) -> int:
    parser = _Parser(description="offline CBC/CTR malleability payload generator")
    sub = parser.add_subparsers(dest="mode", required=True)
    cbc = sub.add_parser("cbc", help="edit CBC plaintext via the IV/previous ciphertext block")
    cbc.add_argument("--iv", required=True, help="IV as hex")
    cbc.add_argument("--ciphertext", required=True, help="ciphertext as hex")
    cbc.add_argument("--block-size", type=int, default=16)
    cbc.add_argument("--edit", action="append", required=True,
                     metavar="OFFSET:KNOWN_HEX:DESIRED_HEX")
    cbc.add_argument("--json", action="store_true")
    ctr = sub.add_parser("ctr", help="edit CTR plaintext at known offsets")
    ctr.add_argument("--ciphertext", required=True, help="ciphertext as hex")
    ctr.add_argument("--edit", action="append", required=True,
                     metavar="OFFSET:KNOWN_HEX:DESIRED_HEX")
    ctr.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        edits = [_edit(value) for value in args.edit]
        ciphertext = _hex(args.ciphertext, "ciphertext")
        if args.mode == "cbc":
            result = modern_crypto.cbc_bitflip_forge(
                _hex(args.iv, "IV"), ciphertext, edits, block_size=args.block_size
            )
        else:
            result = modern_crypto.ctr_edit_forge(ciphertext, edits)
        document = _serialise(result)
        if args.json:
            print(json.dumps(document, indent=2, sort_keys=True))
        else:
            if "iv" in document:
                print(f"iv={document['iv']}")
            print(f"ciphertext={document['ciphertext']}")
            if document["collateral_plaintext_blocks"]:
                blocks = ",".join(map(str, document["collateral_plaintext_blocks"]))
                print(f"collateral_plaintext_blocks={blocks}")
        return 0
    except (ValueError, OSError, modern_crypto.MalleabilityError) as exc:
        print(f"crypto_malleability: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
