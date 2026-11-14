#!/usr/bin/env python3
"""Offline ISO 7816 APDU framing and paired payment-card trace reader.

Public parsers accept bytes/bytearray or hexadecimal text, except parse_trace,
which accepts text only. Malformed or oversized inputs raise APDUError. Returned
objects contain JSON-safe values. No card access, execution, or cryptographic
verification is performed. Transport framing (T=0, T=1, CCID, ISO-DEP) must already
be removed; input is complete APDUs, not transport packets.

Trace grammar: one complete hexadecimal APDU per line, commands prefixed with
``>`` or ``C:`` and responses with ``<`` or ``R:``. Blank lines and whole-line
``#`` comments are allowed. Pairing is strict; no inferred direction or partial
exchange recovery. Individual commands/responses can instead be read separately.

References: EMV Book 3 section 6; Oracle Java Card Extended APDU Format:
https://docs.oracle.com/en/java/javacard/3.1/guide/extended-apdu-format.html

CLI: ./.venv/bin/python solvers/toolkits/payment_hw_apdu.py trace capture.txt
     ./.venv/bin/python solvers/toolkits/payment_hw_apdu.py command --hex '80A8000002830000'
"""

import argparse
import json
import re
import sys


MAX_COMMAND = 65544
MAX_RESPONSE = 65538
MAX_TRACE = 4 * 1024 * 1024
MAX_TRACE_LINES = 20000
_HEX = re.compile(r"[0-9a-fA-F\t\r\n ]*")


class APDUError(ValueError):
    """Invalid, incomplete, ambiguous-direction, or oversized APDU input."""


def _bytes(data, maximum):
    if isinstance(data, str):
        if len(data) > maximum * 4 or not _HEX.fullmatch(data):
            raise APDUError("invalid or oversized hexadecimal APDU")
        try:
            data = bytes.fromhex(data)
        except ValueError as exc:
            raise APDUError("APDU hex must contain complete bytes") from exc
    elif isinstance(data, (bytes, bytearray)):
        if len(data) > maximum:
            raise APDUError("APDU exceeds length limit")
        data = bytes(data)
    else:
        raise APDUError("APDU must be bytes, bytearray, or hexadecimal text")
    if len(data) > maximum:
        raise APDUError("APDU exceeds length limit")
    return data


_ISO_COMMANDS = {
    0xA4: "SELECT", 0xB2: "READ RECORD", 0x20: "VERIFY",
    0xC0: "GET RESPONSE", 0xCA: "GET DATA", 0x84: "GET CHALLENGE",
    0x82: "EXTERNAL AUTHENTICATE", 0x88: "INTERNAL AUTHENTICATE",
}
_EMV_COMMANDS = {0xA8: "GET PROCESSING OPTIONS", 0xAE: "GENERATE AC", 0xCA: "GET DATA"}


def _semantics(cla, ins, p1, p2, body):
    info = {"command": "UNKNOWN", "class_coding": "proprietary_or_reserved"}
    secure = False
    if cla < 0x20 or 0x40 <= cla <= 0x7F:
        info["class_coding"] = "interindustry"
        info["command"] = _ISO_COMMANDS.get(ins, "UNKNOWN")
        if cla < 0x20:
            info["logical_channel"] = cla & 3
            secure = bool(cla & 0x0C)
        else:
            info["logical_channel"] = 4 + (cla & 0x0F)
            secure = bool(cla & 0x20)
        info["secure_messaging"] = secure
        info["command_chaining"] = bool(cla & 0x10)
    elif cla == 0x80:
        info["class_coding"] = "EMV"
        info["command"] = _EMV_COMMANDS.get(ins, "UNKNOWN")
    if info["command"] == "SELECT" and p1 == 4 and not secure:
        info["selection"] = "DF name"
        info["df_name_hex"] = body.hex().upper()
        if body and all(32 <= byte <= 126 for byte in body):
            info["df_name_ascii"] = body.decode("ascii")
    elif info["command"] == "READ RECORD":
        info["record_reference"] = p1
        info["record_mode"] = p2 & 7
        info["sfi"] = p2 >> 3
        info["sfi_meaning"] = "current EF" if p2 >> 3 == 0 else (
            "reserved" if p2 >> 3 == 31 else "short file identifier")
    elif info["command"] == "GENERATE AC":
        info["requested_cryptogram"] = {0: "AAC", 1: "TC", 2: "ARQC", 3: "RFU"}[p1 >> 6]
        info["cda_requested"] = bool(p1 & 0x10)
    elif info["command"] == "VERIFY" and p1 == 0:
        info["verification_reference"] = {
            0x80: "plaintext offline PIN", 0x88: "enciphered offline PIN",
        }.get(p2, "other reference")
    return info


def parse_command(data):
    """Decode one complete C-APDU, including all seven short/extended cases."""
    raw = _bytes(data, MAX_COMMAND)
    size = len(raw)
    if size < 4:
        raise APDUError("command requires the four-byte header")
    cla, ins, p1, p2 = raw[:4]
    body, lc, le, extended = b"", 0, None, False
    if size == 4:
        case = "1"
    elif size == 5:
        case, le = "2S", raw[4] or 256
    elif raw[4]:
        lc = raw[4]
        end = 5 + lc
        if size not in (end, end + 1):
            raise APDUError("short command length does not match Lc plus optional Le")
        body = raw[5:end]
        case = "3S" if size == end else "4S"
        if size == end + 1:
            le = raw[-1] or 256
    else:
        if size < 7:
            raise APDUError("truncated extended length")
        extended = True
        length = int.from_bytes(raw[5:7], "big")
        if size == 7:
            case, le = "2E", length or 65536
        else:
            if not length:
                raise APDUError("extended Lc cannot be zero")
            lc = length
            end = 7 + lc
            if size not in (end, end + 2):
                raise APDUError("extended command length does not match Lc plus optional two-byte Le")
            body = raw[7:end]
            case = "3E" if size == end else "4E"
            if size == end + 2:
                le = int.from_bytes(raw[-2:], "big") or 65536
    result = {"raw_hex": raw.hex().upper(), "cla": cla, "ins": ins, "p1": p1, "p2": p2,
              "case": case, "extended": extended, "lc": lc, "le": le,
              "data_hex": body.hex().upper()}
    result.update(_semantics(cla, ins, p1, p2, body))
    return result


_STATUS = {
    0x9000: "normal processing",
    0x6281: "returned data may be corrupted", 0x6282: "end of file or record reached",
    0x6283: "selected file invalidated", 0x6284: "FCI format not supported",
    0x6300: "authentication failed or state changed warning",
    0x6700: "wrong length", 0x6982: "security status not satisfied",
    0x6983: "authentication method blocked", 0x6984: "reference data invalidated",
    0x6985: "conditions of use not satisfied", 0x6986: "command not allowed",
    0x6A80: "incorrect command data", 0x6A81: "function not supported",
    0x6A82: "file or application not found", 0x6A83: "record not found",
    0x6A86: "incorrect P1/P2", 0x6A88: "referenced data not found",
    0x6B00: "wrong parameters", 0x6D00: "instruction not supported",
    0x6E00: "class not supported", 0x6F00: "unspecified error",
}


def parse_response(data):
    """Decode one complete R-APDU; status words are labels, not authentication."""
    raw = _bytes(data, MAX_RESPONSE)
    if len(raw) < 2:
        raise APDUError("response requires SW1 and SW2")
    sw1, sw2 = raw[-2:]
    status = (sw1 << 8) | sw2
    result = {"raw_hex": raw.hex().upper(), "data_hex": raw[:-2].hex().upper(),
              "data_length": len(raw) - 2, "sw": f"{status:04X}", "sw1": sw1, "sw2": sw2,
              "success": status == 0x9000, "status": _STATUS.get(status, "unknown status")}
    if sw1 == 0x61:
        result.update(status="response bytes available", available_bytes=sw2 or 256)
    elif sw1 == 0x6C:
        result.update(status="wrong Le; correct short Le indicated", correct_le=sw2 or 256)
    elif sw1 == 0x63 and sw2 & 0xF0 == 0xC0:
        result.update(status="verification failed; retry counter indicated", retries_remaining=sw2 & 0x0F)
    return result


def parse_trace(text):
    """Decode strict alternating command/response lines into ordered exchanges."""
    if not isinstance(text, str) or len(text) > MAX_TRACE:
        raise APDUError("trace must be bounded text")
    lines = text.splitlines()
    if len(lines) > MAX_TRACE_LINES:
        raise APDUError("trace exceeds line limit")
    exchanges, pending = [], None
    for line_number, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line[0] in "><":
            direction, payload = line[0], line[1:].strip()
        elif line[:2].upper() in ("C:", "R:"):
            direction, payload = (">" if line[0].upper() == "C" else "<"), line[2:].strip()
        else:
            raise APDUError(f"line {line_number}: expected >, <, C: or R: direction")
        try:
            if direction == ">":
                if pending is not None:
                    raise APDUError("new command before previous response")
                pending = {"command_line": line_number, "command": parse_command(payload)}
            else:
                if pending is None:
                    raise APDUError("response without command")
                pending.update(response_line=line_number, response=parse_response(payload))
                exchanges.append(pending)
                pending = None
        except APDUError as exc:
            raise APDUError(f"line {line_number}: {exc}") from exc
    if pending is not None:
        raise APDUError(f"line {pending['command_line']}: command has no response")
    if not exchanges:
        raise APDUError("trace contains no exchanges")
    return exchanges


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("command", "response", "trace"))
    parser.add_argument("file", nargs="?", help="raw APDU file, or UTF-8 directed trace text")
    parser.add_argument("--hex", dest="hex_data", help="one APDU as hexadecimal text (not a file)")
    try:
        args = parser.parse_args(argv)
        if (args.file is None) == (args.hex_data is None):
            parser.error("provide exactly one file or --hex value")
        if args.kind == "trace" and args.hex_data is not None:
            parser.error("trace requires a text file")
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.hex_data is not None:
            data = args.hex_data
        else:
            limit = MAX_TRACE if args.kind == "trace" else MAX_COMMAND if args.kind == "command" else MAX_RESPONSE
            with open(args.file, "rb") as stream:
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise APDUError("input file exceeds length limit")
            if args.kind == "trace":
                data = data.decode("utf-8")
        decode = {"command": parse_command, "response": parse_response, "trace": parse_trace}[args.kind]
        print(json.dumps(decode(data), indent=2))
        return 0
    except (APDUError, OSError, UnicodeError, ValueError) as exc:
        print(f"payment_hw_apdu: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
