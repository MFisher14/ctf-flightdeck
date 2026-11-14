#!/usr/bin/env python3
"""Inspect an ASCII TR-31 (X9.143) A/B/C/D key-block envelope offline.

This is a structural parser, not a MAC verifier or a key unwrap operation. It
preserves unrecognized alphanumeric usage/algorithm codes without interpreting
them. Input is exactly one block, at most 9999 characters, with 2018-style
reserved header bytes '00'. All invalid API inputs raise PaymentHWTR31Error.

CLI: ./.venv/bin/python solvers/toolkits/payment_hw_tr31.py block.txt
     ./.venv/bin/python solvers/toolkits/payment_hw_tr31.py --block D0144...
"""

import argparse
import json
import re
import sys


class PaymentHWTR31Error(ValueError):
    """Malformed or unsupported TR-31 envelope."""


MAX_BLOCK = 9999
_VERSIONS = {
    "A": (8, 4, "TDES variant binding"),
    "B": (8, 8, "TDES derivation binding"),
    "C": (8, 4, "TDES variant binding"),
    "D": (16, 16, "AES derivation binding"),
}


def _hex_number(value, field):
    if not value or re.fullmatch(r"[0-9A-Fa-f]+", value) is None:
        raise PaymentHWTR31Error(f"{field} must contain hexadecimal digits")
    return int(value, 16)


def parse_key_block(data):
    """Return JSON-compatible header, optional blocks, ciphertext and MAC.

    ``data`` must be an ASCII str or bytes with no surrounding whitespace.
    Offsets and lengths refer to ASCII characters, not decoded ciphertext bytes.
    Optional-block length fields include the ID and all length fields. Unknown
    optional blocks are preserved. Duplicate IDs and nonterminal PB are rejected.
    A structurally valid result always has ``authenticated=False``.
    """
    if not isinstance(data, (str, bytes)):
        raise PaymentHWTR31Error("key block must be ASCII str or bytes")
    if not 16 <= len(data) <= MAX_BLOCK:
        raise PaymentHWTR31Error("key block must contain 16..9999 characters")
    if isinstance(data, bytes):
        try:
            data = data.decode("ascii")
        except UnicodeDecodeError:
            raise PaymentHWTR31Error("key block must be ASCII") from None
    if any(not 32 <= ord(char) <= 126 for char in data):
        raise PaymentHWTR31Error("key block must be printable ASCII")
    if re.fullmatch(r"[A-Za-z0-9]{16}", data[:16]) is None:
        raise PaymentHWTR31Error("fixed header must be ASCII alphanumeric")
    version = data[0]
    if version not in _VERSIONS:
        raise PaymentHWTR31Error("only key-block versions A, B, C and D are supported")
    block_size, mac_size, binding = _VERSIONS[version]
    if re.fullmatch(r"[0-9]{4}", data[1:5]) is None:
        raise PaymentHWTR31Error("total length must be four decimal digits")
    if int(data[1:5]) != len(data):
        raise PaymentHWTR31Error("declared total length does not match input")
    if re.fullmatch(r"[0-9]{2}", data[12:14]) is None:
        raise PaymentHWTR31Error("optional-block count must be two decimal digits")
    if data[14:16] != "00":
        raise PaymentHWTR31Error("unsupported nonzero reserved header bytes")

    count = int(data[12:14])
    offset = 16
    optional = []
    seen = set()
    # Leave enough room for at least one ciphertext block and the complete MAC.
    header_limit = len(data) - 2 * (block_size + mac_size)
    for index in range(count):
        start = offset
        if offset + 4 > header_limit:
            raise PaymentHWTR31Error("truncated optional block")
        block_id = data[offset:offset + 2]
        if re.fullmatch(r"[A-Za-z0-9]{2}", block_id) is None:
            raise PaymentHWTR31Error("optional-block ID must be ASCII alphanumeric")
        if block_id in seen:
            raise PaymentHWTR31Error("duplicate optional-block ID")
        seen.add(block_id)
        size = _hex_number(data[offset + 2:offset + 4], "optional-block length")
        offset += 4
        extended = size == 0
        if extended:
            if offset + 2 > header_limit:
                raise PaymentHWTR31Error("truncated extended length")
            length_bytes = _hex_number(data[offset:offset + 2], "length of length")
            offset += 2
            if length_bytes == 0 or offset + length_bytes * 2 > header_limit:
                raise PaymentHWTR31Error("invalid extended length width")
            size = _hex_number(data[offset:offset + length_bytes * 2], "extended length")
            offset += length_bytes * 2
        if size < offset - start or start + size > header_limit:
            raise PaymentHWTR31Error("optional-block length is out of bounds")
        value = data[offset:start + size]
        if block_id.upper() == "PB" and index != count - 1:
            raise PaymentHWTR31Error("padding block must be last")
        optional.append({"id": block_id, "data": value, "offset": start,
                         "length": size, "extended_length": extended})
        offset = start + size

    if offset % block_size:
        raise PaymentHWTR31Error("header is not aligned to the protection block size")
    body = data[offset:]
    if re.fullmatch(r"[0-9A-Fa-f]+", body) is None:
        raise PaymentHWTR31Error("ciphertext and MAC must be hexadecimal")
    cipher_chars = len(body) - mac_size * 2
    if cipher_chars < block_size * 2 or cipher_chars % (block_size * 2):
        raise PaymentHWTR31Error("ciphertext must contain complete nonempty cipher blocks")
    return {
        "version": version, "length": len(data), "key_usage": data[5:7],
        "algorithm": data[7], "mode_of_use": data[8], "key_version": data[9:11],
        "exportability": data[11], "optional_count": count, "reserved": data[14:16],
        "binding": binding, "header_length": offset, "header": data[:offset],
        "optional_blocks": optional, "ciphertext": body[:cipher_chars].upper(),
        "ciphertext_bytes": cipher_chars // 2, "mac": body[cipher_chars:].upper(),
        "mac_bytes": mac_size, "authenticated": False,
        "authentication_note": "Structure only; MAC not verified and key not decrypted.",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="ASCII block file (one trailing newline allowed)")
    parser.add_argument("--block", help="literal ASCII key block")
    try:
        args = parser.parse_args(argv)
        if (args.file is None) == (args.block is None):
            parser.error("provide exactly one file or --block")
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.file is not None:
            with open(args.file, "rb") as source:
                data = source.read(MAX_BLOCK + 3)
            if data.endswith(b"\r\n"):
                data = data[:-2]
            elif data.endswith(b"\n"):
                data = data[:-1]
        else:
            data = args.block
        print(json.dumps(parse_key_block(data), indent=2))
        return 0
    except (PaymentHWTR31Error, OSError, ValueError) as exc:
        print(f"payment_hw_tr31: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
