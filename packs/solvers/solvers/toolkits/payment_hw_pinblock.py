#!/usr/bin/env python3
"""Offline ISO 9564 PIN-block inspection with an explicitly supplied format.

decode_pin_block accepts clear blocks for formats 0--3 and the *clear PIN field*
for format 4. Formats 0/3 require the full PAN (13--19 digits, including check
digit). decrypt_pin_block accepts a supplied key: TDES-ECB for 0--3, or the
two-stage AES construction for 4. Nothing here guesses PINs, keys or formats.

Format validity is not cryptographic authentication or proof of the correct PIN.
Runtime: stdlib for clear data; PyCryptodome only for known-key decryption.
Reference/oracle: https://github.com/knovichikhin/psec/blob/master/psec/pinblock.py

CLI: ./.venv/bin/python solvers/toolkits/payment_hw_pinblock.py block.hex \
         --hex --format 0 --pan 5544332211009966
"""

import argparse
import json
import re
import sys
from pathlib import Path


class PinBlockError(ValueError):
    """Invalid/unsupported PIN block, parameters, or unavailable crypto backend."""


def _binary(value, length, label):
    if not isinstance(value, (bytes, bytearray)) or len(value) != length:
        raise PinBlockError(f"{label} must contain exactly {length} bytes")
    return bytes(value)


def _format(value):
    if type(value) is not int or value not in (0, 1, 2, 3, 4):
        raise PinBlockError("format must be an integer from 0 through 4")
    return value


def _pan(value, minimum):
    if not isinstance(value, str) or not minimum <= len(value) <= 19:
        raise PinBlockError(f"PAN must contain {minimum}--19 ASCII digits")
    if not re.fullmatch(r"[0-9]+", value):
        raise PinBlockError("PAN must contain ASCII digits only")
    return value


def _xor(left, right):
    return bytes(a ^ b for a, b in zip(left, right))


def _pan_field(pan, format):
    if format in (0, 3):
        pan = _pan(pan, 13)
        return bytes.fromhex("0000" + pan[-13:-1])
    pan = _pan(pan, 1)
    # Format 4 includes the check digit and encodes max(length-12, 0).
    nibbles = str(max(len(pan) - 12, 0)) + pan.rjust(12, "0")
    return bytes.fromhex(nibbles.ljust(32, "0"))


def decode_pin_block(block, format, pan=None):
    """Return decoded clear PIN fields, or raise PinBlockError.

    A format-4 input is the 16-byte PIN field before AES/PAN binding, *not* an
    AES-decrypted intermediate block. PAN is only accepted here for 0 and 3.
    Luhn is deliberately not enforced: it is not part of PIN-block construction.
    """
    format = _format(format)
    block = _binary(block, 16 if format == 4 else 8, "block")
    if format in (0, 3):
        block = _xor(block, _pan_field(pan, format))
    elif pan is not None:
        raise PinBlockError("clear formats 1, 2 and 4 do not accept a PAN")

    field = block.hex().upper()
    if int(field[0], 16) != format:
        raise PinBlockError("control nibble does not match the supplied format")
    size = int(field[1], 16)
    if not 4 <= size <= 12:
        raise PinBlockError("PIN length must be 4--12 digits")
    pin = field[2:2 + size]
    if not re.fullmatch(r"[0-9]+", pin):
        raise PinBlockError("PIN contains a non-decimal nibble")
    filler = field[2 + size:16]
    if format in (0, 2) and any(c != "F" for c in filler):
        raise PinBlockError("formats 0 and 2 require F filler")
    if format == 3 and any(c not in "ABCDEF" for c in filler):
        raise PinBlockError("format 3 requires filler nibbles A--F")
    if format == 4 and any(c != "A" for c in filler):
        raise PinBlockError("format 4 requires A filler before its random field")
    result = {
        "format": format,
        "pin": pin,
        "pin_length": size,
        "pin_field_hex": field,
        "filler_hex": filler,
        "pan_binding": format in (0, 3),
        "authenticated": False,
        "input_kind": "clear_pin_field" if format == 4 else "clear_pin_block",
    }
    if format == 1:
        result["filler_kind"] = "transaction_or_random_data"
    if format == 4:
        result["random_field_hex"] = field[16:]
    return result


def decrypt_pin_block(block, format, key, pan=None):
    """Decode one block using a supplied TDES/AES key; no key search or I/O.

    Key lengths: 16/24 bytes (TDES) for 0--3, 16/24/32 (AES) for 4.
    PAN is required for 0, 3 and 4; formats 1/2 reject an extraneous PAN.
    PyCryptodome rejects TDES keys that degenerate to single DES.
    """
    format = _format(format)
    block = _binary(block, 16 if format == 4 else 8, "encrypted block")
    key_sizes = (16, 24, 32) if format == 4 else (16, 24)
    if not isinstance(key, (bytes, bytearray)) or len(key) not in key_sizes:
        raise PinBlockError(f"key length must be one of {key_sizes} bytes")
    key = bytes(key)
    if format in (0, 3, 4):
        pan_field = _pan_field(pan, format)
    elif pan is not None:
        raise PinBlockError("formats 1 and 2 do not accept a PAN")
    try:
        if format == 4:
            from Crypto.Cipher import AES

            cipher = AES.new(key, AES.MODE_ECB)
            # Reverse C=E_K(E_K(PIN_field) XOR PAN_field), not just AES(C).
            plain = cipher.decrypt(_xor(cipher.decrypt(block), pan_field))
        else:
            from Crypto.Cipher import DES3

            plain = DES3.new(key, DES3.MODE_ECB).decrypt(block)
    except (ImportError, ValueError, TypeError) as exc:
        raise PinBlockError("key rejected or PyCryptodome unavailable") from exc
    result = decode_pin_block(plain, format, pan if format in (0, 3) else None)
    result["input_kind"] = "encrypted_pin_block"
    result["pan_binding"] = format in (0, 3, 4)
    result["cipher"] = "AES-ISO4" if format == 4 else "TDES-ECB"
    return result


def _unhex(value, label):
    if not isinstance(value, str) or len(value) > 4096:
        raise PinBlockError(f"{label} must be bounded hexadecimal text")
    if not re.fullmatch(r"[0-9A-Fa-f \t\r\n]+", value):
        raise PinBlockError(f"{label} is not hexadecimal text")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise PinBlockError(f"{label} has incomplete hexadecimal bytes") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="one raw block or an ASCII hex file")
    parser.add_argument("--hex", action="store_true", help="input file contains ASCII hex")
    parser.add_argument("--format", type=int, required=True, choices=range(5))
    parser.add_argument("--pan", help="full PAN, including check digit")
    parser.add_argument("--key", help="supplied key as hex; input is encrypted when present")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open("rb") as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            raise PinBlockError("input exceeds 4096 bytes")
        if args.hex:
            try:
                data = _unhex(data.decode("ascii"), "block")
            except UnicodeDecodeError as exc:
                raise PinBlockError("hex file must be ASCII") from exc
        if args.key is None:
            result = decode_pin_block(data, args.format, args.pan)
        else:
            result = decrypt_pin_block(data, args.format, _unhex(args.key, "key"), args.pan)
        print(json.dumps(result, indent=2))
        return 0
    except (PinBlockError, OSError, ValueError) as exc:
        print(f"payment_hw_pinblock: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
