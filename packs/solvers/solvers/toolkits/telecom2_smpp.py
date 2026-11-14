#!/usr/bin/env python3
"""Offline SMPP 3.4 PDU-stream reader (SMPP v3.4 Issue 1.2, sections 3--5).

Reads complete, ordered, one-direction TCP payloads, not pcap or TCP segments.
No sockets, execution, submissions, or guessed SMSC alphabet. DCS=0 remains raw
unless the caller chooses a default alphabet. GSM decoding is *unpacked*
septets, as used by many SMPP providers, never GSM TPDU septet packing.

API: parse_pdu(data, default_alphabet="raw"), parse_stream(data, ...),
decode_message(data, data_coding, default_alphabet="raw"). All malformed
inputs raise SMPPError; unsupported commands/alphabets remain explicit raw data.
CLI: python telecom2_smpp.py payload.bin [--hex] [--default-alphabet gsm]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


class SMPPError(ValueError):
    """Invalid, truncated, ambiguous, or over-budget SMPP input."""


MAX_PDU = 1024 * 1024
MAX_STREAM = 16 * 1024 * 1024
MAX_PDUS = 4096
MAX_TLVS = 1024
COMMANDS = {
    1: "bind_receiver", 2: "bind_transmitter", 3: "query_sm", 4: "submit_sm",
    5: "deliver_sm", 6: "unbind", 7: "replace_sm", 8: "cancel_sm",
    9: "bind_transceiver", 0x0B: "outbind", 0x15: "enquire_link",
    0x21: "submit_multi", 0x102: "alert_notification", 0x103: "data_sm",
}
TLVS = {
    0x001E: ("receipted_message_id", "cstring", 65),
    0x020A: ("source_port", "integer", 2),
    0x020B: ("destination_port", "integer", 2),
    0x020C: ("sar_msg_ref_num", "integer", 2),
    0x020E: ("sar_total_segments", "integer", 1),
    0x020F: ("sar_segment_seqnum", "integer", 1),
    0x0210: ("sc_interface_version", "integer", 1),
    0x0423: ("network_error_code", "octets", 3),
    0x0424: ("message_payload", "payload", None),
    0x0427: ("message_state", "integer", 1),
    0x0501: ("ussd_service_op", "integer", 1),
}
GSM = (
    "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ"
    " !\"#¤%&'()*+,-./0123456789:;<=>?¡"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿"
    "abcdefghijklmnopqrstuvwxyzäöñüà"
)
GSM_EXT = {10: "\f", 20: "^", 40: "{", 41: "}", 47: "\\",
           60: "[", 61: "~", 62: "]", 64: "|", 101: "€"}


def _bytes(data, limit):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SMPPError("input must be bytes")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > limit:
            raise SMPPError("input exceeds size budget")
        value = bytes(data)
    except (ValueError, TypeError) as exc:
        raise SMPPError("invalid byte buffer") from exc
    if len(value) > limit:
        raise SMPPError("input exceeds size budget")
    return value


class _Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        end = self.pos + count
        if end > len(self.data):
            raise SMPPError("truncated PDU field")
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def integer(self, size=1):
        return int.from_bytes(self.take(size), "big")

    def cstring(self, maximum):
        end = self.data.find(b"\0", self.pos, self.pos + maximum)
        if end == -1:
            raise SMPPError("unterminated or oversized C-octet string")
        value = self.take(end - self.pos + 1)[:-1]
        try:
            return value.decode("ascii")
        except UnicodeError as exc:
            raise SMPPError("non-ASCII C-octet string") from exc

    def done(self):
        if self.pos != len(self.data):
            raise SMPPError("unexpected trailing PDU fields")


def decode_message(data, data_coding, default_alphabet="raw"):
    """Return text or None for unselected/unsupported encoding; strict decoding."""
    data = _bytes(data, MAX_PDU)
    if type(data_coding) is not int or not 0 <= data_coding <= 255:
        raise SMPPError("data_coding must be an octet")
    if not isinstance(default_alphabet, str) or default_alphabet not in (
            "raw", "gsm", "ascii", "latin1"):
        raise SMPPError("unknown default alphabet")
    alphabet = {0: default_alphabet, 1: "ascii", 3: "latin1", 8: "ucs2"}.get(data_coding)
    try:
        if alphabet == "gsm":
            text, escaped = [], False
            for octet in data:
                if escaped:
                    if octet not in GSM_EXT:
                        raise SMPPError("undefined GSM extension")
                    text.append(GSM_EXT[octet])
                    escaped = False
                elif octet == 27:
                    escaped = True
                elif octet > 127:
                    raise SMPPError("GSM unpacked septet exceeds 127")
                else:
                    text.append(GSM[octet])
            if escaped:
                raise SMPPError("trailing GSM escape")
            return "".join(text)
        if alphabet == "ucs2":
            if len(data) % 2 or any(0xD800 <= int.from_bytes(data[i:i+2], "big") <= 0xDFFF
                                    for i in range(0, len(data), 2)):
                raise SMPPError("invalid UCS-2 code units")
            return data.decode("utf-16-be")
        if alphabet in ("ascii", "latin1"):
            return data.decode(alphabet)
        return None
    except UnicodeError as exc:
        raise SMPPError("invalid message encoding") from exc


def _tlvs(reader):
    values = []
    while reader.pos < len(reader.data):
        if len(values) >= MAX_TLVS:
            raise SMPPError("too many TLVs")
        tag, length = reader.integer(2), reader.integer(2)
        data = reader.take(length)
        name, kind, size = TLVS.get(tag, (f"unknown_0x{tag:04x}", "raw", None))
        if size is not None and kind != "cstring" and length != size:
            raise SMPPError(f"wrong length for {name}")
        value = {"tag": tag, "name": name, "length": length, "raw_hex": data.hex()}
        if kind == "integer":
            value["value"] = int.from_bytes(data, "big")
        elif kind == "cstring":
            if not data or len(data) > size:
                raise SMPPError(f"wrong length for {name}")
            sub = _Reader(data)
            value["value"] = sub.cstring(size)
            sub.done()
        values.append(value)
    return values


def _address(reader, fields, prefix, maximum=21):
    fields[prefix + "_addr_ton"] = reader.integer()
    fields[prefix + "_addr_npi"] = reader.integer()
    fields[prefix + "_addr"] = reader.cstring(maximum)


def _udh(payload):
    reader = _Reader(payload)
    length = reader.integer()
    ies = _Reader(reader.take(length))
    values, concatenation = [], None
    while ies.pos < len(ies.data):
        tag, size = ies.integer(), ies.integer()
        data = ies.take(size)
        values.append({"tag": tag, "raw_hex": data.hex()})
        if tag in (0, 8):
            if size != (3 if tag == 0 else 4) or concatenation is not None:
                raise SMPPError("invalid or duplicate UDH concatenation element")
            refsize = 1 if tag == 0 else 2
            total, seq = data[refsize:]
            if total == 0 or not 1 <= seq <= total:
                raise SMPPError("invalid UDH segment numbering")
            concatenation = {"method": "udh8" if tag == 0 else "udh16",
                             "reference": int.from_bytes(data[:refsize], "big"),
                             "total": total, "sequence": seq}
    return payload[reader.pos:], values, concatenation


def _message(fields, tlvs, short, default_alphabet):
    singleton = {}
    for tlv in tlvs:
        if tlv["tag"] in (0x0424, 0x020C, 0x020E, 0x020F):
            if tlv["tag"] in singleton:
                raise SMPPError("duplicate payload or SAR TLV")
            singleton[tlv["tag"]] = tlv
    payload = short
    if 0x0424 in singleton:
        if short:
            raise SMPPError("both short_message and message_payload present")
        payload = bytes.fromhex(singleton[0x0424]["raw_hex"])
    concatenation = None
    sar = [tag in singleton for tag in (0x020C, 0x020E, 0x020F)]
    if any(sar):
        if not all(sar):
            raise SMPPError("incomplete SAR parameters")
        total, seq = (singleton[t]["value"] for t in (0x020E, 0x020F))
        if total == 0 or not 1 <= seq <= total:
            raise SMPPError("invalid SAR segment numbering")
        concatenation = {"method": "sar", "reference": singleton[0x020C]["value"],
                         "total": total, "sequence": seq}
    result = {"payload_hex": payload.hex(), "concatenation": concatenation,
              "delivery_receipt": (fields["esm_class"] & 0x3C) == 0x04}
    if fields["esm_class"] & 0x40:
        payload, result["udh"], udh_concat = _udh(payload)
        if concatenation is not None:
            raise SMPPError("SAR parameters cannot be combined with UDHI")
        result["concatenation"] = udh_concat
    result["text"] = decode_message(payload, fields["data_coding"], default_alphabet)
    result["content_hex"] = payload.hex()
    return result


def parse_pdu(data, default_alphabet="raw"):
    """Decode exactly one PDU. Unknown command bodies remain opaque."""
    data = _bytes(data, MAX_PDU)
    decode_message(b"", 0, default_alphabet)  # Validate option even for non-message PDUs.
    reader = _Reader(data)
    length, command, status, seq = (reader.integer(4) for _ in range(4))
    if length != len(data) or length < 16:
        raise SMPPError("command_length does not match PDU")
    response, base = bool(command & 0x80000000), command & 0x7FFFFFFF
    name = COMMANDS.get(base, f"unknown_0x{command:08x}")
    if command == 0x80000000:
        name = "generic_nack"
    elif response and base in COMMANDS:
        name += "_resp"
    result = {"command_length": length, "command_id": command, "command": name,
              "command_status": status, "sequence_number": seq,
              "fields": {}, "tlvs": []}
    fields = result["fields"]
    if response and status and length == 16:
        return result
    if base in (6, 0x15) or command == 0x80000000:
        reader.done()
    elif response and base in (1, 2, 9):
        fields["system_id"] = reader.cstring(16)
        result["tlvs"] = _tlvs(reader)
    elif response and base in (4, 5, 0x103):
        fields["message_id"] = reader.cstring(65)
        result["tlvs"] = _tlvs(reader)
    elif response and base in (7, 8):
        reader.done()
    elif not response and base in (1, 2, 9, 0x0B):
        fields["system_id"] = reader.cstring(16)
        fields["password"] = reader.cstring(9)
        if base != 0x0B:
            fields["system_type"] = reader.cstring(13)
            fields["interface_version"] = reader.integer()
            fields["addr_ton"] = reader.integer()
            fields["addr_npi"] = reader.integer()
            fields["address_range"] = reader.cstring(41)
        reader.done()
    elif not response and base in (4, 5, 0x103):
        fields["service_type"] = reader.cstring(6)
        maximum = 65 if base == 0x103 else 21  # SMPP 3.4 table 4-20.
        _address(reader, fields, "source", maximum)
        _address(reader, fields, "destination", maximum)
        fields["esm_class"] = reader.integer()
        if base != 0x103:
            fields["protocol_id"] = reader.integer()
            fields["priority_flag"] = reader.integer()
            fields["schedule_delivery_time"] = reader.cstring(17)
            fields["validity_period"] = reader.cstring(17)
        fields["registered_delivery"] = reader.integer()
        if base != 0x103:
            fields["replace_if_present_flag"] = reader.integer()
        fields["data_coding"] = reader.integer()
        short = b""
        if base != 0x103:
            fields["sm_default_msg_id"] = reader.integer()
            fields["sm_length"] = reader.integer()
            if fields["sm_length"] > 254:
                raise SMPPError("sm_length exceeds SMPP maximum 254")
            short = reader.take(fields["sm_length"])
            fields["short_message_hex"] = short.hex()
        result["tlvs"] = _tlvs(reader)
        result["message"] = _message(fields, result["tlvs"], short, default_alphabet)
    else:
        result["unsupported_body_hex"] = reader.take(len(data) - reader.pos).hex()
    return result


def parse_stream(data, default_alphabet="raw"):
    """Decode complete, concatenated PDUs; never resynchronize after bad framing."""
    data = _bytes(data, MAX_STREAM)
    decode_message(b"", 0, default_alphabet)
    if not data:
        raise SMPPError("empty PDU stream")
    pdus, offset = [], 0
    while offset < len(data):
        if len(pdus) >= MAX_PDUS or len(data) - offset < 16:
            raise SMPPError("PDU count limit or truncated stream header")
        length = int.from_bytes(data[offset:offset + 4], "big")
        if length < 16 or length > MAX_PDU or offset + length > len(data):
            raise SMPPError("invalid or truncated stream PDU")
        pdu = parse_pdu(data[offset:offset + length], default_alphabet)
        pdu["offset"] = offset
        pdus.append(pdu)
        offset += length
    return pdus


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--hex", action="store_true", help="input is ASCII hexadecimal")
    parser.add_argument("--default-alphabet", choices=("raw", "gsm", "ascii", "latin1"), default="raw")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open("rb") as handle:
            data = handle.read(MAX_STREAM * (3 if args.hex else 1) + 1)
        if args.hex:
            if len(data) > MAX_STREAM * 3:
                raise SMPPError("hex file exceeds input budget")
            data = bytes.fromhex(data.decode("ascii"))
        print(json.dumps(parse_stream(data, args.default_alphabet), indent=2, ensure_ascii=False))
        return 0
    except (SMPPError, OSError, UnicodeError, ValueError) as exc:
        print(f"SMPP error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
