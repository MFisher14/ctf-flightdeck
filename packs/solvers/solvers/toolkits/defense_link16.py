"""Offline public Link-16 J-series word-header classification.

Parses already-decoded 70-bit information words, not encrypted JTIDS radio
frames. Input can be numeric hex words or nine-byte little-endian containers
whose top two padding bits are zero. RF sync, 5 parity bits, DIS packing and
message-specific tactical fields must be handled upstream with their schemas.

Reference: DSTO-TN-1257 and the Wireshark Link16 public dissector:
https://willrobertson.id.au/resources/wireshark/DSTO-TN-1257.pdf
https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-link16.c
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


class DefenseLink16Error(ValueError):
    """Malformed, unsupported or ambiguously framed J-series input."""


MAX_WORDS = 4096
MAX_FILE = MAX_WORDS * 24
_NAMES = {0: "initial", 1: "continuation", 2: "extension"}


def decode_word(value: object) -> dict:
    """Decode the common header; expose remaining bits without inventing fields."""
    if type(value) is not int or not 0 <= value < (1 << 70):
        raise DefenseLink16Error("expected an unsigned 70-bit information word")
    form = value & 3
    if form == 3:
        raise DefenseLink16Error("reserved word format 3")
    result = {"word_hex": f"{value:018x}", "word_format": form, "kind": _NAMES[form]}
    if form == 0:
        label, sublabel = (value >> 2) & 31, (value >> 7) & 7
        result.update(label=label, sublabel=sublabel, message=f"J{label}.{sublabel}",
                      message_length_indicator=(value >> 10) & 7)
        offset = 13
    elif form == 1:
        result["continuation_label"] = (value >> 2) & 31
        offset = 7
    else:
        offset = 2
    result.update(information_bit_offset=offset, information_bit_count=70-offset,
                  information_hex=f"{value >> offset:x}")
    return result


def decode_words(values: object) -> list[dict]:
    """Associate extension/continuation words with the latest initial word.

    This does not validate message-specific word ordering or interpret MLI as a
    byte count. A capture beginning midway through a message is rejected.
    """
    if type(values) not in (tuple, list) or not 1 <= len(values) <= MAX_WORDS:
        raise DefenseLink16Error(f"expected 1..{MAX_WORDS} words in a list or tuple")
    result = []
    message = None
    extension = 0
    for value in values:
        word = decode_word(value)
        if word["kind"] == "initial":
            message = word["message"]
            extension = 0
        elif message is None:
            raise DefenseLink16Error("extension/continuation without an initial word")
        else:
            word["message"] = message
            if word["kind"] == "extension":
                word["extension_index"] = extension
                extension += 1
        result.append(word)
    return result


def parse_words(data: object, packing: object = "hex") -> list[dict]:
    """Parse hex text bytes or explicit le9 normalized containers, then decode."""
    if type(data) not in (bytes, bytearray) or len(data) > MAX_FILE:
        raise DefenseLink16Error("expected bounded bytes")
    if type(packing) is not str or packing not in ("hex", "le9"):
        raise DefenseLink16Error("packing must be hex or le9")
    if packing == "le9":
        if len(data) % 9:
            raise DefenseLink16Error("truncated nine-byte container")
        if not 1 <= len(data) // 9 <= MAX_WORDS:
            raise DefenseLink16Error("invalid word count")
        values = [int.from_bytes(data[i:i+9], "little") for i in range(0, len(data), 9)]
    else:
        try:
            text = data.decode("ascii")
        except UnicodeError as exc:
            raise DefenseLink16Error("hex word file is not ASCII") from exc
        tokens = text.split()
        if not 1 <= len(tokens) <= MAX_WORDS:
            raise DefenseLink16Error("invalid word count")
        if any(re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,18}", t) is None for t in tokens):
            raise DefenseLink16Error("invalid hexadecimal word")
        values = [int(t, 16) for t in tokens]
    return decode_words(values)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="normalized 70-bit word capture")
    parser.add_argument("--packing", choices=("hex", "le9"), default="hex")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open("rb") as stream:
            data = stream.read(MAX_FILE + 1)
        print(json.dumps(parse_words(data, args.packing), indent=2))
        return 0
    except (DefenseLink16Error, OSError, ValueError) as exc:
        print(f"defense_link16: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
