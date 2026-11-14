"""Offline MIL-STD-1553B decoded-word reader (no waveform or bus access).

Input words contain the 16 information bits, without sync or parity.  An optional
separate odd-parity bit can be checked by decode_command/decode_status.  Transfer
decoding requires one complete BC-to-RT or RT-to-BC transaction in wire order;
RT-to-RT, partial captures and vendor capture envelopes are outside this grammar.

Reference: MIL-STD-1553B 4.3.3.5 and 4.3.3.6, reproduced in the designer guide:
https://www.milstd1553.com/resources-2/desginers-guide/review-and-rationale-of-mil-std-1553-a-and-b/4-0-general-requirements/
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

class Defense1553Error(ValueError):
    """Malformed or unsupported decoded 1553 input."""


MAX_FILE = 4096
_MODES = {
    0: "dynamic_bus_control", 1: "synchronize", 2: "transmit_status_word",
    3: "initiate_self_test", 4: "transmitter_shutdown",
    5: "override_transmitter_shutdown", 6: "inhibit_terminal_flag",
    7: "override_inhibit_terminal_flag", 8: "reset_remote_terminal",
    16: "transmit_vector_word", 17: "synchronize_with_data",
    18: "transmit_last_command_word", 19: "transmit_bit_word",
    20: "selected_transmitter_shutdown", 21: "override_selected_transmitter_shutdown",
}
_STATUS_BITS = {
    "message_error": 10, "instrumentation": 9, "service_request": 8,
    "broadcast_received": 4, "busy": 3, "subsystem_flag": 2,
    "dynamic_bus_control_acceptance": 1, "terminal_flag": 0,
}


def _word(value: object, parity: object = None) -> int:
    if type(value) is not int or not 0 <= value <= 65535:
        raise Defense1553Error("word must be an unsigned 16-bit integer")
    if parity is not None:
        if type(parity) is not int or parity not in (0, 1):
            raise Defense1553Error("parity must be 0, 1 or None")
        if (value.bit_count() + parity) % 2 != 1:
            raise Defense1553Error("odd parity check failed")
    return value


def decode_command(word: object, parity: object = None) -> dict:
    """Decode 16 information bits; preserve reserved mode codes as metadata."""
    value = _word(word, parity)
    rt = value >> 11
    transmit = bool(value & 1024)
    subaddress = (value >> 5) & 31
    low = value & 31
    mode = subaddress in (0, 31)
    return {
        "word_hex": f"{value:04x}", "rt_address": rt,
        "broadcast": rt == 31, "transmit": transmit,
        "subaddress": subaddress, "is_mode_command": mode,
        "word_count": None if mode else (low or 32),
        "mode_code": low if mode else None,
        "mode_name": _MODES.get(low, "reserved") if mode else None,
        "mode_data_words": (1 if low >= 16 else 0) if mode else None,
        "parity_checked": parity is not None,
    }


def decode_status(word: object, parity: object = None) -> dict:
    """Decode status flags, including nonzero reserved bits for forensic review."""
    value = _word(word, parity)
    return {
        "word_hex": f"{value:04x}", "rt_address": value >> 11,
        **{name: bool(value & (1 << bit)) for name, bit in _STATUS_BITS.items()},
        "reserved_bits": (value >> 5) & 7,
        "parity_checked": parity is not None,
    }


def decode_transfer(words: object, byteorder: object = "big") -> dict:
    """Parse one complete non-RT-to-RT transaction of 16-bit words in wire order.

    Receive: command, data, status. Transmit: command, status, data.
    Broadcasts omit status. Status-only busy/error replies to transmit commands
    are reported with an empty payload. Payload byte order is an explicit choice
    for application data, not a property imposed by the bus standard.
    """
    if type(words) not in (list, tuple) or not 1 <= len(words) <= 34:
        raise Defense1553Error("expected 1..34 decoded words in a list or tuple")
    if type(byteorder) is not str or byteorder not in ("big", "little"):
        raise Defense1553Error("byteorder must be big or little")
    values = [_word(word) for word in words]
    command = decode_command(values[0])
    is_mode, transmit, broadcast = (command[k] for k in
                                   ("is_mode_command", "transmit", "broadcast"))
    count = command["mode_data_words"] if is_mode else command["word_count"]
    if is_mode:
        code = command["mode_code"]
        if code not in _MODES:
            raise Defense1553Error("reserved mode code is not a supported transfer")
        expected_transmit = code <= 8 or code in (16, 18, 19)
        if transmit != expected_transmit:
            raise Defense1553Error("mode-code T/R bit contradicts MIL-STD-1553B")
        if broadcast and code in (0, 2, 16, 18, 19):
            raise Defense1553Error("mode code does not permit broadcast")
    elif broadcast and transmit:
        raise Defense1553Error("ordinary broadcast must be a receive command")
    status = None
    if broadcast:
        payload = values[1:]
    else:
        if len(values) < 2:
            raise Defense1553Error("missing status word")
        status = decode_status(values[1] if transmit else values[-1])
        if status["rt_address"] != command["rt_address"]:
            raise Defense1553Error("status RT address does not match command")
        if status["instrumentation"] or status["reserved_bits"]:
            raise Defense1553Error("status has nonzero instrumentation/reserved bits")
        payload = values[2:] if transmit else values[1:-1]
        if transmit and (status["busy"] or status["message_error"]):
            count = 0
    if len(payload) != count:
        raise Defense1553Error("data word count disagrees with command/status")
    raw = b"".join(word.to_bytes(2, byteorder) for word in payload)
    text = raw.decode("ascii", "replace")
    return {
        "command": command, "status": status,
        "data_words": payload, "payload_hex": raw.hex(), "payload_ascii": text,
        "payload_byteorder": byteorder,
        "flags": flagfmt.PACKED_TEXT.findall(text),       # packed data words: no word boundary (R-16)
    }


def parse_word_text(text: object) -> list[int]:
    """Parse whitespace-separated hexadecimal words, optionally prefixed 0x."""
    if type(text) is not str or len(text) > MAX_FILE:
        raise Defense1553Error("expected bounded text")
    tokens = text.split()
    if not 1 <= len(tokens) <= 34:
        raise Defense1553Error("expected 1..34 hexadecimal words")
    if any(re.fullmatch(r"(?:0[xX])?[0-9A-Fa-f]{1,4}", t) is None for t in tokens):
        raise Defense1553Error("invalid hexadecimal word")
    return [int(token, 16) for token in tokens]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="kind", required=True)
    for name in ("command", "status"):
        p = sub.add_parser(name)
        p.add_argument("word", help="hexadecimal 16-bit information word")
        p.add_argument("--parity", type=int, choices=(0, 1))
    p = sub.add_parser("transfer")
    p.add_argument("file", help="whitespace-separated hex words in wire order")
    p.add_argument("--byteorder", choices=("big", "little"), default="big")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.kind == "transfer":
            with Path(args.file).open("rb") as stream:
                raw = stream.read(MAX_FILE + 1)
            result = decode_transfer(parse_word_text(raw.decode("ascii")), args.byteorder)
        else:
            words = parse_word_text(args.word)
            if len(words) != 1:
                raise Defense1553Error("expected a single word")
            decoder = decode_command if args.kind == "command" else decode_status
            result = decoder(words[0], args.parity)
        print(json.dumps(result, indent=2))
        return 0
    except (Defense1553Error, OSError, ValueError) as exc:
        print(f"defense_mil1553: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
