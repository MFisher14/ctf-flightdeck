#!/usr/bin/env python3
"""Bounded offline decoders for saved RFID/NFC dumps and bit captures.

Nothing in this module opens a reader, radio, interface, socket, or subprocess.  Inputs are bytes
or bit strings already supplied as challenge artifacts.  The parsers intentionally preserve raw
values alongside interpretation so an analyst can distinguish corruption from access policy.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any, Iterable, Sequence


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 32 << 20
MAX_RECORDS = 65_536
MAX_NDEF_DEPTH = 8
FLAG_RE = flagfmt.BYTES


class RFIDParseError(ValueError):
    """A saved RFID/NFC artifact is malformed or exceeds a deterministic bound."""


def _bytes(data: bytes | bytearray | memoryview, what: str = "input") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"{what} must be bytes-like")
    value = bytes(data)
    if len(value) > MAX_INPUT:
        raise RFIDParseError(f"{what} exceeds 32 MiB cap")
    return value


def _need(data: bytes, offset: int, length: int, what: str) -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise RFIDParseError(f"truncated {what} at offset {offset}")


def _flags(data: bytes) -> list[str]:
    return [match.group().decode("latin-1") for match in FLAG_RE.finditer(data)][:256]


# ------------------------------------------------------------------ MIFARE Classic

MIFARE_DATA_RIGHTS = {
    0b000: {"read": "A|B", "write": "A|B", "increment": "A|B", "decrement_transfer_restore": "A|B"},
    0b010: {"read": "A|B", "write": "never", "increment": "never", "decrement_transfer_restore": "A|B"},
    0b100: {"read": "A|B", "write": "B", "increment": "never", "decrement_transfer_restore": "never"},
    0b110: {"read": "A|B", "write": "B", "increment": "B", "decrement_transfer_restore": "A|B"},
    0b001: {"read": "A|B", "write": "never", "increment": "never", "decrement_transfer_restore": "A|B"},
    0b011: {"read": "B", "write": "B", "increment": "never", "decrement_transfer_restore": "never"},
    0b101: {"read": "B", "write": "never", "increment": "never", "decrement_transfer_restore": "never"},
    0b111: {"read": "never", "write": "never", "increment": "never", "decrement_transfer_restore": "never"},
}

# Key A is never readable; this table describes writes plus access-bit/Key-B visibility.
MIFARE_TRAILER_RIGHTS = {
    0b000: {"key_a_write": "A", "access_read": "A", "access_write": "A", "key_b_read": "A", "key_b_write": "A"},
    0b010: {"key_a_write": "never", "access_read": "A", "access_write": "never", "key_b_read": "A", "key_b_write": "never"},
    0b100: {"key_a_write": "B", "access_read": "A|B", "access_write": "never", "key_b_read": "never", "key_b_write": "B"},
    0b110: {"key_a_write": "never", "access_read": "A|B", "access_write": "B", "key_b_read": "never", "key_b_write": "B"},
    0b001: {"key_a_write": "A", "access_read": "A", "access_write": "A", "key_b_read": "A", "key_b_write": "A"},
    0b011: {"key_a_write": "B", "access_read": "A|B", "access_write": "B", "key_b_read": "never", "key_b_write": "B"},
    0b101: {"key_a_write": "never", "access_read": "A|B", "access_write": "B", "key_b_read": "never", "key_b_write": "never"},
    0b111: {"key_a_write": "never", "access_read": "A|B", "access_write": "never", "key_b_read": "never", "key_b_write": "never"},
}


def decode_mifare_access_bits(value: bytes) -> dict[str, Any]:
    """Decode the redundant three-byte Classic sector access field.

    ``value`` may be exactly bytes 6..8 or a complete 16-byte trailer.
    """
    raw = _bytes(value, "MIFARE access bits")
    if len(raw) == 16:
        raw = raw[6:9]
    if len(raw) != 3:
        raise RFIDParseError("MIFARE access field must be 3 bytes or one 16-byte trailer")
    b6, b7, b8 = raw
    blocks, valid = [], True
    for block in range(4):
        # NXP's redundant layout is: byte6 = ~C2|~C1, byte7 = C1|~C3,
        # byte8 = C3|C2 (high nibble first in each expression).
        c1 = (b7 >> (4 + block)) & 1
        c2 = (b8 >> block) & 1
        c3 = (b8 >> (4 + block)) & 1
        complement_ok = (
            ((b6 >> block) & 1) == (c1 ^ 1)
            and ((b6 >> (4 + block)) & 1) == (c2 ^ 1)
            and ((b7 >> block) & 1) == (c3 ^ 1)
        )
        valid &= complement_ok
        condition = (c1 << 2) | (c2 << 1) | c3
        rights = MIFARE_TRAILER_RIGHTS if block == 3 else MIFARE_DATA_RIGHTS
        blocks.append({
            "block": block,
            "c1": c1,
            "c2": c2,
            "c3": c3,
            "condition": f"{c1}{c2}{c3}",
            "condition_value": condition,
            "complements_valid": complement_ok,
            "rights": dict(rights[condition]),
        })
    return {"raw": raw.hex(), "valid": valid, "blocks": blocks}


def parse_mifare_value_block(block: bytes) -> dict[str, Any]:
    """Validate and decode the redundant 16-byte Classic value-block format."""
    raw = _bytes(block, "MIFARE value block")
    if len(raw) != 16:
        raise RFIDParseError("MIFARE value block must be 16 bytes")
    value_raw, inverse, repeated = raw[:4], raw[4:8], raw[8:12]
    address = raw[12]
    value_ok = repeated == value_raw and inverse == bytes(byte ^ 0xFF for byte in value_raw)
    address_ok = raw[13] == (address ^ 0xFF) and raw[14] == address and raw[15] == (address ^ 0xFF)
    return {
        "value": int.from_bytes(value_raw, "little", signed=True),
        "value_unsigned": int.from_bytes(value_raw, "little"),
        "address": address,
        "value_redundancy_valid": value_ok,
        "address_redundancy_valid": address_ok,
        "valid": value_ok and address_ok,
        "raw": raw.hex(),
    }


def _mifare_sector_layout(block_count: int) -> list[tuple[int, int]]:
    if block_count <= 0:
        raise RFIDParseError("empty MIFARE dump")
    if block_count <= 128:
        if block_count % 4:
            raise RFIDParseError("small-sector MIFARE dump must contain a multiple of four blocks")
        return [(sector, sector * 4) for sector in range(block_count // 4)]
    if block_count == 256:  # Classic 4K: 32*4 then 8*16 blocks.
        layout = [(sector, sector * 4) for sector in range(32)]
        layout.extend((sector, 128 + (sector - 32) * 16) for sector in range(32, 40))
        return layout
    raise RFIDParseError("unsupported MIFARE Classic dump geometry")


def parse_mifare_classic_dump(data: bytes) -> dict[str, Any]:
    """Parse Mini/1K/2K/4K raw block dumps and all sector trailers."""
    raw = _bytes(data, "MIFARE dump")
    if len(raw) % 16:
        raise RFIDParseError("MIFARE dump is not block aligned")
    block_count = len(raw) // 16
    layout = _mifare_sector_layout(block_count)
    sectors = []
    for position, (sector, first_block) in enumerate(layout):
        next_first = layout[position + 1][1] if position + 1 < len(layout) else block_count
        count = next_first - first_block
        trailer_index = first_block + count - 1
        trailer = raw[trailer_index * 16:(trailer_index + 1) * 16]
        access = decode_mifare_access_bits(trailer)
        data_blocks = []
        for index in range(first_block, trailer_index):
            block = raw[index * 16:(index + 1) * 16]
            value = parse_mifare_value_block(block)
            data_blocks.append({
                "absolute_block": index,
                "sector_block": index - first_block,
                "raw": block.hex(),
                "value_block": value if value["valid"] else None,
                "flags": _flags(block),
            })
        sectors.append({
            "sector": sector,
            "first_block": first_block,
            "block_count": count,
            "trailer_block": trailer_index,
            "key_a": trailer[:6].hex(),
            "access": access,
            "gpb": trailer[9],
            "key_b": trailer[10:].hex(),
            "data_blocks": data_blocks,
        })
    manufacturer = raw[:16]
    uid = manufacturer[:4]
    return {
        "format": "mifare-classic",
        "size_bytes": len(raw),
        "block_count": block_count,
        "sector_count": len(sectors),
        "uid": uid.hex().upper(),
        "bcc": manufacturer[4],
        "bcc_valid": manufacturer[4] == (uid[0] ^ uid[1] ^ uid[2] ^ uid[3]),
        "sectors": sectors,
        "flags": _flags(raw),
    }


# ------------------------------------------------------------------ DESFire

DESFIRE_COMMANDS = {
    0x0A: "AUTHENTICATE_LEGACY", 0xAA: "AUTHENTICATE_AES", 0x1A: "AUTHENTICATE_ISO",
    0x5A: "SELECT_APPLICATION", 0x6A: "GET_APPLICATION_IDS", 0xCA: "CREATE_APPLICATION",
    0xDA: "DELETE_APPLICATION", 0x6F: "GET_FILE_IDS", 0xF5: "GET_FILE_SETTINGS",
    0xCD: "CREATE_STD_DATA_FILE", 0xCB: "CREATE_BACKUP_DATA_FILE", 0xC1: "CREATE_LINEAR_RECORD_FILE",
    0xC0: "CREATE_CYCLIC_RECORD_FILE", 0xCC: "CREATE_VALUE_FILE", 0xDF: "DELETE_FILE",
    0xBD: "READ_DATA", 0xAD: "READ_DATA_ISO", 0x3D: "WRITE_DATA", 0xBB: "READ_RECORDS",
    0x3B: "WRITE_RECORD", 0x6C: "GET_VALUE", 0x0C: "CREDIT", 0xDC: "DEBIT",
    0x1C: "LIMITED_CREDIT", 0xC7: "COMMIT_TRANSACTION", 0xA7: "ABORT_TRANSACTION",
    0xAF: "ADDITIONAL_FRAME",
}
DESFIRE_FILE_TYPES = {0: "standard-data", 1: "backup-data", 2: "value", 3: "linear-record", 4: "cyclic-record"}
DESFIRE_COMMUNICATION = {0: "plain", 1: "plain-maced", 3: "enciphered"}


def _le24(data: bytes, offset: int) -> int:
    _need(data, offset, 3, "little-endian uint24")
    return int.from_bytes(data[offset:offset + 3], "little")


def parse_desfire_file_settings(data: bytes) -> dict[str, Any]:
    raw = _bytes(data, "DESFire file settings")
    _need(raw, 0, 4, "DESFire file settings")
    file_type, communication = raw[0], raw[1]
    if file_type not in DESFIRE_FILE_TYPES:
        raise RFIDParseError(f"unknown DESFire file type {file_type}")
    out: dict[str, Any] = {
        "file_type": file_type,
        "file_type_name": DESFIRE_FILE_TYPES[file_type],
        "communication": communication,
        "communication_name": DESFIRE_COMMUNICATION.get(communication, "reserved"),
        "access_rights": {
            "read_write": raw[2] >> 4,
            "change": raw[2] & 0xF,
            "read": raw[3] >> 4,
            "write": raw[3] & 0xF,
        },
        "raw": raw.hex(),
    }
    if file_type in (0, 1):
        if len(raw) != 7:
            raise RFIDParseError("DESFire data-file settings must be exactly 7 bytes")
        out["file_size"] = _le24(raw, 4)
    elif file_type == 2:
        if len(raw) != 17:
            raise RFIDParseError("DESFire value-file settings must be exactly 17 bytes")
        out.update(
            lower_limit=int.from_bytes(raw[4:8], "little", signed=True),
            upper_limit=int.from_bytes(raw[8:12], "little", signed=True),
            limited_credit_value=int.from_bytes(raw[12:16], "little", signed=True),
            limited_credit_enabled=bool(raw[16]),
        )
    else:
        if len(raw) != 13:
            raise RFIDParseError("DESFire record-file settings must be exactly 13 bytes")
        out.update(record_size=_le24(raw, 4), max_records=_le24(raw, 7), current_records=_le24(raw, 10))
    return out


def parse_desfire_apdu(data: bytes, *, direction: str = "auto") -> dict[str, Any]:
    """Parse one saved native-wrapped DESFire command or response APDU."""
    raw = _bytes(data, "DESFire APDU")
    if direction not in {"auto", "command", "response"}:
        raise ValueError("direction must be auto, command or response")
    command_shape = (len(raw) >= 5 and raw[0] == 0x90
                     and 5 + raw[4] in (len(raw), len(raw) - 1))
    # Prefer a structurally complete command in auto mode.  Its final data byte may legitimately
    # be 0x91, so status-suffix detection alone would misclassify it as a response.
    response = direction == "response" or (direction == "auto" and not command_shape
                                             and len(raw) >= 2 and raw[-2] == 0x91)
    if response:
        _need(raw, 0, 2, "DESFire response status")
        if raw[-2] != 0x91:
            raise RFIDParseError("DESFire response lacks 0x91 status class")
        status = raw[-1]
        return {
            "direction": "response",
            "status": status,
            "status_name": {0x00: "success", 0xAF: "additional-frame", 0xAE: "authentication-error",
                            0x9D: "permission-denied", 0xF0: "file-not-found"}.get(status, "error-or-vendor"),
            "data": raw[:-2].hex(),
            "flags": _flags(raw[:-2]),
        }
    _need(raw, 0, 5, "DESFire command APDU")
    if raw[0] != 0x90:
        raise RFIDParseError("DESFire native-wrapped command must use CLA 0x90")
    instruction, p1, p2 = raw[1], raw[2], raw[3]
    lc, cursor = raw[4], 5
    _need(raw, cursor, lc, "DESFire APDU data")
    body = raw[cursor:cursor + lc]
    cursor += lc
    if cursor < len(raw):
        if cursor + 1 != len(raw):
            raise RFIDParseError("DESFire command has trailing bytes beyond Le")
        le = raw[cursor]
    else:
        le = None
    out: dict[str, Any] = {
        "direction": "command", "instruction": instruction,
        "command": DESFIRE_COMMANDS.get(instruction, f"UNKNOWN_{instruction:02X}"),
        "p1": p1, "p2": p2, "le": le, "data": body.hex(), "flags": _flags(body),
    }
    if instruction in (0x5A, 0xCA, 0xDA):
        _need(body, 0, 3, "DESFire application identifier")
        out["application_id"] = f"{_le24(body, 0):06X}"
        if instruction in (0x5A, 0xDA) and len(body) != 3:
            raise RFIDParseError("DESFire select/delete application must contain exactly one AID")
    if instruction in (0xBD, 0xAD, 0x3D, 0xBB, 0x3B):
        _need(body, 0, 7, "DESFire file range")
        out.update(file_id=body[0], offset=_le24(body, 1), length=_le24(body, 4), payload=body[7:].hex())
        if instruction in (0x3D, 0x3B) and len(body[7:]) != out["length"]:
            raise RFIDParseError("DESFire write payload length mismatch")
        if instruction in (0xBD, 0xAD, 0xBB) and len(body) != 7:
            raise RFIDParseError("DESFire read command has undeclared trailing bytes")
    elif instruction in (0xF5, 0x6C, 0xDF):
        _need(body, 0, 1, "DESFire file identifier")
        if len(body) != 1:
            raise RFIDParseError("DESFire file command must contain exactly one file identifier")
        out["file_id"] = body[0]
    return out


def analyze_desfire_trace(apdus: Iterable[bytes]) -> dict[str, Any]:
    """Track selected applications and file operations across saved APDU records."""
    records, selected, operations = [], None, []
    for index, apdu in enumerate(apdus):
        if index >= MAX_RECORDS:
            raise RFIDParseError("DESFire trace exceeds record cap")
        row = parse_desfire_apdu(apdu)
        row["index"] = index
        row["selected_application"] = selected
        if row["direction"] == "command":
            if row["instruction"] == 0x5A and "application_id" in row:
                selected = row["application_id"]
                row["selected_application"] = selected
            if row["instruction"] in (0x3D, 0x3B, 0x0C, 0xDC, 0x1C, 0xC7, 0xA7):
                operations.append({"index": index, "application": selected, "operation": row["command"],
                                   "file_id": row.get("file_id"), "payload": row.get("payload")})
        records.append(row)
    return {"records": records, "selected_application": selected, "operations": operations}


def parse_desfire_dump_records(data: bytes) -> dict[str, Any]:
    """Parse a neutral TLV export: A0=AID, F0=file settings, F1=data, F2=record."""
    raw = _bytes(data, "DESFire dump records")
    cursor, application, records = 0, None, []
    while cursor < len(raw):
        if len(records) >= MAX_RECORDS:
            raise RFIDParseError("too many DESFire dump records")
        _need(raw, cursor, 3, "DESFire dump TLV")
        tag, length = raw[cursor], int.from_bytes(raw[cursor + 1:cursor + 3], "little")
        cursor += 3
        _need(raw, cursor, length, "DESFire dump value")
        value = raw[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"tag": tag, "length": length, "raw": value.hex(), "application": application}
        if tag == 0xA0:
            if length != 3:
                raise RFIDParseError("DESFire AID record must be three bytes")
            application = f"{int.from_bytes(value, 'little'):06X}"
            row.update(kind="application", application=application)
        elif tag == 0xF0:
            _need(value, 0, 2, "DESFire file settings record")
            row.update(kind="file-settings", file_id=value[0], settings=parse_desfire_file_settings(value[1:]))
        elif tag in (0xF1, 0xF2):
            _need(value, 0, 4, "DESFire file data record")
            row.update(kind="file-data" if tag == 0xF1 else "record-data", file_id=value[0],
                       offset=_le24(value, 1), data=value[4:].hex(), flags=_flags(value[4:]))
        else:
            row["kind"] = "unknown"
        records.append(row)
    return {"records": records, "applications": sorted({r["application"] for r in records if r.get("application")})}


# ------------------------------------------------------------------ NTAG / NDEF

URI_PREFIXES = {
    0x00: "", 0x01: "http://www.", 0x02: "https://www.", 0x03: "http://", 0x04: "https://",
    0x05: "tel:", 0x06: "mailto:", 0x0F: "ftp://ftp.", 0x13: "urn:uuid:",
}


def parse_ndef_message(data: bytes, *, _depth: int = 0) -> list[dict[str, Any]]:
    raw = _bytes(data, "NDEF message")
    if _depth > MAX_NDEF_DEPTH:
        raise RFIDParseError("NDEF nesting depth exceeded")
    cursor, records, saw_me = 0, [], False
    while cursor < len(raw):
        if len(records) >= MAX_RECORDS:
            raise RFIDParseError("too many NDEF records")
        _need(raw, cursor, 2, "NDEF record header")
        header, type_length = raw[cursor], raw[cursor + 1]
        cursor += 2
        mb, me, cf, sr, il, tnf = bool(header & 0x80), bool(header & 0x40), bool(header & 0x20), bool(header & 0x10), bool(header & 0x08), header & 7
        if not records and not mb:
            raise RFIDParseError("first NDEF record lacks MB flag")
        if records and mb:
            raise RFIDParseError("non-first NDEF record sets MB")
        if saw_me:
            raise RFIDParseError("data follows NDEF ME record")
        if sr:
            _need(raw, cursor, 1, "NDEF short payload length")
            payload_length, cursor = raw[cursor], cursor + 1
        else:
            _need(raw, cursor, 4, "NDEF payload length")
            payload_length, cursor = int.from_bytes(raw[cursor:cursor + 4], "big"), cursor + 4
        id_length = 0
        if il:
            _need(raw, cursor, 1, "NDEF ID length")
            id_length, cursor = raw[cursor], cursor + 1
        _need(raw, cursor, type_length + id_length + payload_length, "NDEF record body")
        record_type = raw[cursor:cursor + type_length]
        cursor += type_length
        identifier = raw[cursor:cursor + id_length]
        cursor += id_length
        payload = raw[cursor:cursor + payload_length]
        cursor += payload_length
        row: dict[str, Any] = {
            "mb": mb, "me": me, "chunked": cf, "short": sr, "tnf": tnf,
            "type": record_type.decode("ascii", "replace"), "id": identifier.hex(),
            "payload": payload.hex(), "flags": _flags(payload),
        }
        if not cf and tnf == 1 and record_type == b"U" and payload:
            row["uri"] = URI_PREFIXES.get(payload[0], f"urn:nfc:wkt:uri-prefix-{payload[0]:02x}:") + payload[1:].decode("utf-8", "replace")
        elif not cf and tnf == 1 and record_type == b"T" and payload:
            status = payload[0]
            language_length = status & 0x3F
            _need(payload, 1, language_length, "NDEF language")
            row.update(encoding="utf-16" if status & 0x80 else "utf-8",
                       language=payload[1:1 + language_length].decode("ascii", "replace"),
                       text=payload[1 + language_length:].decode("utf-16" if status & 0x80 else "utf-8", "replace"))
        elif not cf and tnf == 1 and record_type == b"Sp":
            row["nested_records"] = parse_ndef_message(payload, _depth=_depth + 1)
        elif not cf and tnf in (2, 4):
            row["media_or_external_type"] = record_type.decode("ascii", "replace")
        records.append(row)
        saw_me = me
        if me and cursor != len(raw):
            raise RFIDParseError("trailing data follows NDEF message end")
    if records and not saw_me:
        raise RFIDParseError("NDEF message lacks ME record")
    active: dict[str, Any] | None = None
    for index, row in enumerate(records):
        if active is not None:
            if row["tnf"] != 6 or row["type"] or row["id"]:
                raise RFIDParseError("invalid NDEF continuation chunk")
            active["payloads"].append(bytes.fromhex(row["payload"]))
            row["chunk_continuation"] = True
            if not row["chunked"]:
                combined = b"".join(active["payloads"])
                logical = {key: value for key, value in records[active["index"]].items()
                           if key not in {"payload", "flags", "chunked"}}
                logical.update(payload=combined.hex(), flags=_flags(combined), chunked=False)
                record_type = logical["type"].encode("ascii", "replace")
                if logical["tnf"] == 1 and record_type == b"U" and combined:
                    logical["uri"] = URI_PREFIXES.get(combined[0], f"urn:nfc:wkt:uri-prefix-{combined[0]:02x}:") + combined[1:].decode("utf-8", "replace")
                elif logical["tnf"] == 1 and record_type == b"T" and combined:
                    language_length = combined[0] & 0x3F
                    _need(combined, 1, language_length, "chunked NDEF language")
                    encoding = "utf-16" if combined[0] & 0x80 else "utf-8"
                    logical.update(encoding=encoding,
                                   language=combined[1:1 + language_length].decode("ascii", "replace"),
                                   text=combined[1 + language_length:].decode(encoding, "replace"))
                records[active["index"]]["reassembled_record"] = logical
                row["completes_chunk_of"] = active["index"]
                active = None
        elif row["chunked"]:
            if row["tnf"] in (0, 5, 6, 7):
                raise RFIDParseError("invalid TNF on first NDEF chunk")
            active = {"index": index, "payloads": [bytes.fromhex(row["payload"])]}
        elif row["tnf"] == 6:
            raise RFIDParseError("orphan NDEF continuation chunk")
    if active is not None:
        raise RFIDParseError("unterminated NDEF chunk sequence")
    return records


def parse_ntag_tlvs(data: bytes, *, offset: int = 0) -> list[dict[str, Any]]:
    raw = _bytes(data, "NTAG TLV area")
    if not 0 <= offset <= len(raw):
        raise RFIDParseError("invalid NTAG TLV offset")
    cursor, rows = offset, []
    names = {0x00: "null", 0x01: "lock-control", 0x02: "memory-control", 0x03: "ndef", 0xFD: "proprietary", 0xFE: "terminator"}
    while cursor < len(raw):
        if len(rows) >= MAX_RECORDS:
            raise RFIDParseError("too many NTAG TLVs")
        start, tag = cursor, raw[cursor]
        cursor += 1
        if tag == 0x00:
            rows.append({"offset": start, "tag": tag, "kind": "null", "length": 0})
            continue
        if tag == 0xFE:
            rows.append({"offset": start, "tag": tag, "kind": "terminator", "length": 0})
            if any(byte not in (0x00, 0xFF) for byte in raw[cursor:]):
                rows[-1]["non_padding_after_terminator"] = True
            break
        _need(raw, cursor, 1, "NTAG TLV length")
        length = raw[cursor]
        cursor += 1
        if length == 0xFF:
            _need(raw, cursor, 2, "NTAG extended TLV length")
            length, cursor = int.from_bytes(raw[cursor:cursor + 2], "big"), cursor + 2
            if length < 0xFF:
                raise RFIDParseError("non-canonical NTAG extended TLV length")
        _need(raw, cursor, length, "NTAG TLV value")
        value = raw[cursor:cursor + length]
        cursor += length
        row: dict[str, Any] = {"offset": start, "tag": tag, "kind": names.get(tag, "unknown"), "length": length,
                               "value": value.hex(), "flags": _flags(value)}
        if tag == 0x03:
            row["ndef"] = parse_ndef_message(value)
        elif tag in (0x01, 0x02) and length == 3:
            row["page_address"] = value[0] >> 4
            row["byte_offset"] = value[0] & 0x0F
            row["size_bits"] = value[1] if value[1] else 256
            row["bytes_per_page"] = 1 << (value[2] & 0x0F)
            row["bytes_locked_per_bit"] = 1 << ((value[2] >> 4) & 0x0F)
        rows.append(row)
    return rows


NTAG_MODELS = {
    45: ("NTAG213", 40, 41),
    135: ("NTAG215", 130, 131),
    231: ("NTAG216", 226, 227),
}


def parse_ntag_dump(data: bytes, *, model: str | None = None) -> dict[str, Any]:
    """Parse a page-aligned NTAG213/215/216 dump, NDEF TLVs, locks, and config."""
    raw = _bytes(data, "NTAG dump")
    if len(raw) % 4:
        raise RFIDParseError("NTAG dump must be aligned to four-byte pages")
    pages = len(raw) // 4
    # MIFARE Ultralight C is a 48-page tag whose layout (AUTH0/AUTH1, 3DES key pages) differs from
    # the NTAG family; route a complete UL-C geometry to its own parser (B-084).
    if pages == ULTRALIGHT_C_PAGES and model is None:
        return parse_ultralight_c_dump(raw)
    if pages not in NTAG_MODELS:
        if model is None:
            raise RFIDParseError("unknown NTAG page geometry; provide a supported complete dump")
        candidates = [entry for count, entry in NTAG_MODELS.items() if entry[0].lower() == model.lower()]
        if not candidates:
            raise RFIDParseError("unsupported NTAG model")
        name, dynamic_lock_page, config_page = candidates[0]
        if pages <= config_page + 3:
            raise RFIDParseError("NTAG dump is truncated before configuration pages")
    else:
        name, dynamic_lock_page, config_page = NTAG_MODELS[pages]
        if model is not None and name.lower() != model.lower():
            raise RFIDParseError("NTAG model conflicts with dump geometry")
    page = lambda index: raw[index * 4:(index + 1) * 4]
    cc = page(3)
    if cc[0] != 0xE1:
        raise RFIDParseError("NTAG capability container lacks NDEF magic")
    static_locks = int.from_bytes(page(2)[2:4], "little")
    dynamic = page(dynamic_lock_page)
    cfg0, cfg1 = page(config_page), page(config_page + 1)
    pwd, pack = page(config_page + 2), page(config_page + 3)[:2]
    user_end = min(dynamic_lock_page, 4 + cc[2] * 2)
    user = raw[4 * 4:user_end * 4]
    uid = page(0)[0:3] + page(1)[0:4]
    dynamic_locks = int.from_bytes(dynamic[:3], "little")
    return {
        "format": "ntag", "model": name, "page_count": pages,
        "uid": uid.hex().upper(),
        "bcc0": page(0)[3], "bcc1": page(2)[0],
        "bcc0_valid": page(0)[3] == (0x88 ^ uid[0] ^ uid[1] ^ uid[2]),
        "bcc1_valid": page(2)[0] == (uid[3] ^ uid[4] ^ uid[5] ^ uid[6]),
        "capability_container": {"version": cc[1], "capacity_bytes": cc[2] * 8,
                                 "read_access": cc[3] >> 4, "write_access": cc[3] & 0xF},
        "static_lock_bits": static_locks,
        "static_lock_set_bits": [bit for bit in range(16) if static_locks & (1 << bit)],
        "dynamic_lock_bits": dynamic_locks,
        "dynamic_lock_set_bits": [bit for bit in range(24) if dynamic_locks & (1 << bit)],
        "dynamic_lock_page": dynamic_lock_page,
        "configuration": {
            "mirror": cfg0[0] >> 6, "mirror_byte_offset": (cfg0[0] >> 4) & 3,
            "mirror_page": cfg0[2], "auth0": cfg0[3],
            "access": cfg1[0], "protect_reads": bool(cfg1[0] & 0x80),
            "auth_limit": cfg1[0] & 7, "password": pwd.hex(), "pack": pack.hex(),
        },
        "tlvs": parse_ntag_tlvs(user), "flags": _flags(raw),
    }


# ------------------------------------------------------------------ MIFARE Ultralight C
#
# MF0ICU2 (Ultralight C) is a 48-page / 192-byte tag.  Unlike plain Ultralight / NTAG it carries a
# 2-key 3DES mutual-authentication key and an AUTH0/AUTH1 protection window.  This section adds the
# layout, a factory-key library, 3DES/AES-CBC decrypt + re-encrypt of a page range (so an operator
# can read and rewrite an application record that a card stores enciphered), an offline CRC
# identifier, and a field editor that forges a card end to end.  Every function here is offline: it
# takes bytes already saved as a challenge artifact.  The only networked step (uploading a forged
# card to a live validator) lives in rfid_validator_probe and is player-gated.

ULTRALIGHT_C_PAGES = 48
ULTRALIGHT_C_BYTES = ULTRALIGHT_C_PAGES * 4  # 192

# Page addresses in the MF0ICU2 memory map.
ULC_OTP_PAGE = 0x03
ULC_USER_FIRST_PAGE = 0x04
ULC_USER_LAST_PAGE = 0x27           # inclusive; pages 0x04..0x27 = 144 bytes of user memory
ULC_DYNAMIC_LOCK_PAGE = 0x28        # lock bytes 2..3 in bytes 0..1
ULC_COUNTER_PAGE = 0x29             # 16-bit one-way counter in bytes 0..1
ULC_AUTH0_PAGE = 0x2A               # byte 0: first page that needs authentication (>=0x30 disables)
ULC_AUTH1_PAGE = 0x2B               # byte 0 bit0: 0 => read+write protected, 1 => write protected only
ULC_KEY_FIRST_PAGE = 0x2C           # pages 0x2C..0x2F hold the 16-byte 2-key 3DES key (write-only)
ULC_KEY_LAST_PAGE = 0x2F

# Factory-default authentication keys shipped on blank cards.  The NXP Ultralight C default is the
# ASCII string "BREAKMEIFYOUCAN!" (16 bytes), used directly as the 2-key 3DES key.
UL_C_FACTORY_KEYS = {
    "nxp-default": b"BREAKMEIFYOUCAN!",
    "all-zero": bytes(16),
}

_CBC_ALGOS = {"3des": "3des", "des3": "3des", "tdea": "3des",
              "aes": "aes", "aes-cbc": "aes", "aes128": "aes", "aes256": "aes"}


class RFIDCryptoUnavailable(RFIDParseError):
    """pycryptodome is required for an Ultralight C crypto operation but could not be imported."""


def _cbc_cipher(algo: str, key: bytes, iv: bytes | None):
    """Return ``(cipher, block_size)`` for a CBC decrypt/encrypt, failing loudly (never silently) on
    a missing dependency, an unknown algorithm, or a wrong key/IV length."""
    name = _CBC_ALGOS.get(str(algo).lower())
    if name is None:
        raise RFIDParseError(f"unsupported CBC algorithm {algo!r}; use '3des' or 'aes'")
    try:
        if name == "3des":
            from Crypto.Cipher import DES3 as _cipher
        else:
            from Crypto.Cipher import AES as _cipher
    except ImportError as exc:
        raise RFIDCryptoUnavailable(
            "Ultralight C 3DES/AES operations need pycryptodome (import Crypto failed): "
            f"{exc!r}; install pycryptodome==3.24.0 into the venv") from exc
    if name == "3des":
        if len(key) not in (16, 24):
            raise RFIDParseError(f"3DES key must be 16 or 24 bytes, got {len(key)}")
        iv = bytes(8) if iv is None else bytes(iv)
        if len(iv) != 8:
            raise RFIDParseError("3DES CBC IV must be 8 bytes")
        try:
            return _cipher.new(key, _cipher.MODE_CBC, iv=iv), 8
        except ValueError as exc:
            raise RFIDParseError(f"invalid 3DES key: {exc}") from exc
    if len(key) not in (16, 24, 32):
        raise RFIDParseError(f"AES key must be 16, 24 or 32 bytes, got {len(key)}")
    iv = bytes(16) if iv is None else bytes(iv)
    if len(iv) != 16:
        raise RFIDParseError("AES CBC IV must be 16 bytes")
    return _cipher.new(key, _cipher.MODE_CBC, iv=iv), 16


def decrypt_cbc(ciphertext: bytes, key: bytes, *, algo: str = "3des", iv: bytes | None = None) -> bytes:
    """CBC-decrypt a block-aligned region with 3DES (default) or AES via pycryptodome."""
    data = _bytes(ciphertext, "ciphertext")
    cipher, block = _cbc_cipher(algo, _bytes(key, "key"), iv)
    if len(data) % block:
        raise RFIDParseError(f"ciphertext length {len(data)} is not a multiple of {block}")
    return cipher.decrypt(data)


def encrypt_cbc(plaintext: bytes, key: bytes, *, algo: str = "3des", iv: bytes | None = None) -> bytes:
    """CBC-encrypt a block-aligned region (the inverse of :func:`decrypt_cbc`)."""
    data = _bytes(plaintext, "plaintext")
    cipher, block = _cbc_cipher(algo, _bytes(key, "key"), iv)
    if len(data) % block:
        raise RFIDParseError(f"plaintext length {len(data)} is not a multiple of {block}")
    return cipher.encrypt(data)


def _ulc_pages(data: bytes) -> bytes:
    raw = _bytes(data, "Ultralight C dump")
    if len(raw) % 4:
        raise RFIDParseError("Ultralight C dump must be aligned to four-byte pages")
    if len(raw) // 4 != ULTRALIGHT_C_PAGES:
        raise RFIDParseError(
            f"Ultralight C dump must be {ULTRALIGHT_C_PAGES} pages ({ULTRALIGHT_C_BYTES} bytes); "
            f"got {len(raw) // 4} pages")
    return raw


def ultralight_bcc(uid7: bytes) -> tuple[int, int]:
    """The two block-check bytes NXP derives from a 7-byte UID (BCC0 = 0x88^uid0^uid1^uid2)."""
    uid = _bytes(uid7, "UID")
    if len(uid) != 7:
        raise RFIDParseError("Ultralight UID must be 7 bytes")
    return (0x88 ^ uid[0] ^ uid[1] ^ uid[2], uid[3] ^ uid[4] ^ uid[5] ^ uid[6])


def parse_ultralight_c_dump(data: bytes) -> dict[str, Any]:
    """Parse a 192-byte Ultralight C dump: UID/BCC, lock bytes, OTP, user memory, AUTH0/AUTH1, and
    the (write-only, read-back-zero) 3DES key pages."""
    raw = _ulc_pages(data)
    page = lambda index: raw[index * 4:(index + 1) * 4]
    uid = page(0)[0:3] + page(1)[0:4]
    bcc0, bcc1 = page(0)[3], page(2)[0]
    expect0, expect1 = ultralight_bcc(uid)
    key_pages = raw[ULC_KEY_FIRST_PAGE * 4:(ULC_KEY_LAST_PAGE + 1) * 4]
    user = raw[ULC_USER_FIRST_PAGE * 4:(ULC_USER_LAST_PAGE + 1) * 4]
    auth0 = page(ULC_AUTH0_PAGE)[0]
    auth1 = page(ULC_AUTH1_PAGE)[0]
    try:
        tlvs = parse_ntag_tlvs(user)
    except RFIDParseError:
        tlvs = []  # user memory is enciphered or not a Type-2 TLV area; read it raw instead
    return {
        "format": "ultralight-c", "page_count": ULTRALIGHT_C_PAGES, "size_bytes": len(raw),
        "uid": uid.hex().upper(),
        "bcc0": bcc0, "bcc1": bcc1,
        "bcc0_valid": bcc0 == expect0, "bcc1_valid": bcc1 == expect1,
        "static_lock_bits": int.from_bytes(page(2)[2:4], "little"),
        "dynamic_lock_bits": int.from_bytes(page(ULC_DYNAMIC_LOCK_PAGE)[0:2], "little"),
        "otp": page(ULC_OTP_PAGE).hex(),
        "counter": int.from_bytes(page(ULC_COUNTER_PAGE)[0:2], "little"),
        "auth0": auth0, "auth_from_page": auth0, "auth_enabled": auth0 <= ULC_KEY_LAST_PAGE,
        "auth1": auth1, "auth1_write_only": bool(auth1 & 1),
        "key_first_page": ULC_KEY_FIRST_PAGE, "key_pages": key_pages.hex(),
        "key_pages_zeroed": set(key_pages) <= {0},
        "user_first_page": ULC_USER_FIRST_PAGE, "user_last_page": ULC_USER_LAST_PAGE,
        "user_bytes": user.hex(),
        "tlvs": tlvs, "flags": _flags(raw),
    }


def set_ultralight_uid(data: bytes, uid7: bytes) -> bytes:
    """Return a copy of the dump with a new 7-byte UID and its two recomputed BCC bytes."""
    raw = bytearray(_ulc_pages(data))
    uid = _bytes(uid7, "UID")
    if len(uid) != 7:
        raise RFIDParseError("Ultralight UID must be 7 bytes")
    bcc0, bcc1 = ultralight_bcc(uid)
    raw[0:3], raw[3] = uid[0:3], bcc0
    raw[4:8], raw[8] = uid[3:7], bcc1
    return bytes(raw)


def ul_c_data_region(data: bytes, *, start_page: int = ULC_USER_FIRST_PAGE,
                     end_page: int = ULC_USER_LAST_PAGE + 1) -> tuple[bytes, int, int]:
    """The ciphertext region ``[start_page, end_page)`` of a UL-C dump, with its page bounds."""
    raw = _ulc_pages(data)
    if not 0 <= start_page < end_page <= ULTRALIGHT_C_PAGES:
        raise RFIDParseError("invalid Ultralight C page range")
    return raw[start_page * 4:end_page * 4], start_page, end_page


def decrypt_ul_c_data(data: bytes, key: bytes, *, algo: str = "3des", iv: bytes | None = None,
                      start_page: int = ULC_USER_FIRST_PAGE,
                      end_page: int = ULC_USER_LAST_PAGE + 1) -> bytes:
    """Decrypt a UL-C dump's data region (default: the 144-byte user memory, pages 0x04..0x27)."""
    region, _, _ = ul_c_data_region(data, start_page=start_page, end_page=end_page)
    return decrypt_cbc(region, key, algo=algo, iv=iv)


def reencrypt_ul_c_data(data: bytes, plaintext: bytes, key: bytes, *, algo: str = "3des",
                        iv: bytes | None = None, start_page: int = ULC_USER_FIRST_PAGE,
                        end_page: int = ULC_USER_LAST_PAGE + 1) -> bytes:
    """Return a copy of the dump whose data region holds ``plaintext`` re-enciphered in place."""
    raw = bytearray(_ulc_pages(data))
    region, start, end = ul_c_data_region(data, start_page=start_page, end_page=end_page)
    pt = _bytes(plaintext, "plaintext")
    if len(pt) != len(region):
        raise RFIDParseError(f"plaintext length {len(pt)} != data region length {len(region)}")
    raw[start * 4:end * 4] = encrypt_cbc(pt, key, algo=algo, iv=iv)
    return bytes(raw)


# --- offline CRC identification (run before any live validator probe) ---------------------------

_ECC_MODULE: Any = None
_ECC_FILE_MODULE_NAME = "rfid_nfc_depth_ecc"


def _load_ecc_by_file() -> Any:
    """Load the sibling ``ecc.py`` by path. The module is registered in ``sys.modules`` before it is
    executed: its ``@dataclass`` under ``from __future__ import annotations`` looks its own module up
    there, and crashes ('NoneType' object has no attribute '__dict__') when it is missing."""
    import importlib.util
    import sys
    if _ECC_FILE_MODULE_NAME in sys.modules:
        return sys.modules[_ECC_FILE_MODULE_NAME]
    source = Path(__file__).resolve().parent / "ecc.py"
    if not source.is_file():
        raise RFIDParseError(f"the ecc toolkit is missing: {source} not found (needed for CRC work)")
    spec = importlib.util.spec_from_file_location(_ECC_FILE_MODULE_NAME, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[_ECC_FILE_MODULE_NAME] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(_ECC_FILE_MODULE_NAME, None)
        raise
    return module


def _ecc():
    """The sibling ecc toolkit: ``<package>.ecc`` when this module is imported as part of a package
    (``solvers.toolkits.rfid_nfc_depth``), flat ``ecc`` on the engine path, or by file as a last
    resort. Cached after the first load."""
    global _ECC_MODULE
    if _ECC_MODULE is not None:
        return _ECC_MODULE
    import importlib
    name = f"{__package__}.ecc" if __package__ else "ecc"
    try:
        module = importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:   # ecc itself failed to import one of its own dependencies
            raise
        module = _load_ecc_by_file()
    _ECC_MODULE = module
    return module


def _crc_catalog():
    """Named CRC parameter sets to try when identifying an unknown tag (widths 8/16/32). Candidates
    are handed to ``ecc.recover_crc_parameters``; names are only labels for the report."""
    params = _ecc().CRCParameters
    return [
        ("CRC-32", params(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True)),   # == zlib.crc32
        ("CRC-32/BZIP2", params(32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, False, False)),
        ("CRC-32C", params(32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, True, True)),
        ("CRC-32/MPEG-2", params(32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, False, False)),
        ("CRC-32/POSIX", params(32, 0x04C11DB7, 0x00000000, 0xFFFFFFFF, False, False)),
        ("CRC-32/JAMCRC", params(32, 0x04C11DB7, 0xFFFFFFFF, 0x00000000, True, True)),
        ("CRC-32/XFER", params(32, 0x000000AF, 0x00000000, 0x00000000, False, False)),
        # ISO/IEC 14443-3 Type A frame CRC (CRC_A), the CRC an NFC-A card itself sends (LSB first).
        # Catalogue init is 0xC6C6; ecc.crc_value loads ``init`` into the shift register as given for
        # a reflected CRC (it does not reflect it), so the register form 0x6363 is passed here.
        # Check value over b"123456789" is 0xBF05 (pinned by a test).
        ("CRC-16/ISO-IEC-14443-3-A", params(16, 0x1021, 0x6363, 0x0000, True, True)),
        # ISO/IEC 14443-3 Type B (CRC_B), == CRC-16/X-25.
        ("CRC-16/ISO-IEC-14443-3-B", params(16, 0x1021, 0xFFFF, 0xFFFF, True, True)),
        ("CRC-16/CCITT-FALSE", params(16, 0x1021, 0xFFFF, 0x0000, False, False)),
        ("CRC-16/XMODEM", params(16, 0x1021, 0x0000, 0x0000, False, False)),
        ("CRC-16/KERMIT", params(16, 0x1021, 0x0000, 0x0000, True, True)),
        ("CRC-16/ARC", params(16, 0x8005, 0x0000, 0x0000, True, True)),
        ("CRC-16/MODBUS", params(16, 0x8005, 0xFFFF, 0x0000, True, True)),
        ("CRC-8/SMBUS", params(8, 0x07, 0x00, 0x00, False, False)),
        ("CRC-8/MAXIM", params(8, 0x31, 0x00, 0x00, True, True)),
    ]


def identify_crc_samples(samples: Sequence[tuple[bytes, bytes]], *,
                         extra: Sequence[Any] = ()) -> list[dict[str, Any]]:
    """Every catalogued (or ``extra``) CRC that maps EVERY ``(message, tag)`` sample to its tag, trying
    the tags as big- and little-endian integers.  Several samples (e.g. each decrypted handout record)
    rule out chance matches.  All tags must be the same 1..4 bytes; that length fixes the CRC width.
    Built on ``ecc.recover_crc_parameters``."""
    ecc = _ecc()
    pairs = [(_bytes(message, "CRC message"), _bytes(tag, "CRC tag")) for message, tag in samples]
    if not pairs:
        raise RFIDParseError("identify_crc needs at least one (message, tag) sample")
    size = len(pairs[0][1])
    if not 1 <= size <= 4:
        raise RFIDParseError("CRC tag must be 1..4 bytes")
    if any(len(tag) != size for _, tag in pairs):
        raise RFIDParseError("every CRC tag sample must have the same length")
    width = size * 8
    catalog = [(name, params) for name, params in _crc_catalog() if params.width == width]
    catalog += [("custom", params) for params in extra if params.width == width]
    names: dict[Any, str] = {}
    for name, params in catalog:
        names.setdefault(params, name)
    matches = []
    for endian in ("big", "little"):
        observed = [(message, int.from_bytes(tag, endian)) for message, tag in pairs]
        for params in ecc.recover_crc_parameters(observed, candidates=list(names)):
            matches.append({"name": names[params], "width": params.width, "endian": endian,
                            "params": params, "value": observed[0][1]})
    return matches


def identify_crc(message: bytes, tag: bytes, *, extra: Sequence[Any] = (),
                 samples: Sequence[tuple[bytes, bytes]] = ()) -> list[dict[str, Any]]:
    """:func:`identify_crc_samples` for one ``(message, tag)`` plus any further ``samples``."""
    return identify_crc_samples([(message, tag), *samples], extra=extra)


def find_crc_records(records: Sequence[tuple[Sequence[tuple[str, bytes]], bytes]], *,
                     extra: Sequence[Any] = ()) -> list[dict[str, Any]]:
    """Search for which contiguous run of named fields produces each record's CRC tag.

    ``records`` is ``[(components, tag), ...]``: one per decrypted handout record, each with the same
    ordered ``(name, bytes)`` fields.  A run is reported only when one catalogued CRC reproduces the
    tag of every record, so several records rule out chance matches.  Use it to recover a card's
    checksum definition offline before any live upload."""
    recs = []
    for components, tag in records:
        comps = [(str(name), _bytes(value, f"component {name}")) for name, value in components]
        recs.append((comps, _bytes(tag, "CRC tag")))
    if not recs:
        raise RFIDParseError("find_crc_records needs at least one record")
    names = [name for name, _ in recs[0][0]]
    if any([name for name, _ in comps] != names for comps, _ in recs):
        raise RFIDParseError("every record must list the same component names in the same order")
    out = []
    for start in range(len(names)):
        for stop in range(start + 1, len(names) + 1):
            samples = [(b"".join(value for _, value in comps[start:stop]), tag) for comps, tag in recs]
            for match in identify_crc_samples(samples, extra=extra):
                out.append({**match, "components": names[start:stop], "message": samples[0][0].hex()})
    return out


def find_crc_message(components: Sequence[tuple[str, bytes]], tag: bytes, *,
                     extra: Sequence[Any] = ()) -> list[dict[str, Any]]:
    """:func:`find_crc_records` for a single record: e.g. the UID, timestamp and user-type fields of
    one decrypted record and its stored tag."""
    return find_crc_records([(components, tag)], extra=extra)


# --- field editor / forge -----------------------------------------------------------------------

def _resolve_crc_component(ref: Sequence[Any], *, plaintext: bytes, dump: bytes, uid: bytes) -> bytes:
    kind = ref[0]
    if kind == "uid":
        return uid
    if kind == "plain":
        return bytes(plaintext[ref[1]:ref[2]])
    if kind == "page":
        page, lo, hi = ref[1], ref[2], ref[3]
        return bytes(dump[page * 4 + lo:page * 4 + hi])
    if kind == "bytes":
        return bytes.fromhex(ref[1]) if isinstance(ref[1], str) else bytes(ref[1])
    raise RFIDParseError(f"unknown CRC component ref {ref!r}")


def forge_ul_c_card(data: bytes, key: bytes, *, data_edits: Iterable[tuple[int, bytes]] = (),
                    uid: bytes | None = None, algo: str = "3des", iv: bytes | None = None,
                    start_page: int = ULC_USER_FIRST_PAGE, end_page: int = ULC_USER_LAST_PAGE + 1,
                    crc: dict[str, Any] | None = None) -> dict[str, Any]:
    """Forge a UL-C card end to end: optionally set a new UID (BCC recomputed), decrypt the data
    region, apply byte edits, optionally recompute a CRC over named fields and write it back, then
    re-encrypt.

    ``crc`` (optional) is ``{"message": [ref, ...], "at": offset, "params": CRCParameters,
    "endian": "big"|"little"}`` where each ``ref`` is ``("uid",)``, ``("plain", lo, hi)``,
    ``("page", page, lo, hi)`` or ``("bytes", hex)``; ``at`` is the offset in the decrypted region
    where the packed CRC is written.  Returns ``{"dump", "plaintext", "uid", "crc"}``."""
    raw = set_ultralight_uid(data, uid) if uid is not None else bytes(_ulc_pages(data))
    uid7 = bytes(raw[0:3] + raw[4:8])
    plaintext = bytearray(decrypt_ul_c_data(raw, key, algo=algo, iv=iv,
                                            start_page=start_page, end_page=end_page))
    for offset, value in data_edits:
        chunk = _bytes(value, "edit value")
        if offset < 0 or offset + len(chunk) > len(plaintext):
            raise RFIDParseError(f"edit at {offset} exceeds the {len(plaintext)}-byte data region")
        plaintext[offset:offset + len(chunk)] = chunk
    crc_out = None
    if crc is not None:
        ecc = _ecc()
        params = crc["params"]
        message = b"".join(
            _resolve_crc_component(ref, plaintext=bytes(plaintext), dump=raw, uid=uid7)
            for ref in crc["message"])
        crc_out = ecc.crc_value(message, params)
        width_bytes = params.width // 8
        at = crc["at"]
        if at < 0 or at + width_bytes > len(plaintext):
            raise RFIDParseError("CRC write offset exceeds the data region")
        plaintext[at:at + width_bytes] = crc_out.to_bytes(width_bytes, crc.get("endian", "big"))
    new_dump = reencrypt_ul_c_data(raw, bytes(plaintext), key, algo=algo, iv=iv,
                                   start_page=start_page, end_page=end_page)
    return {"dump": new_dump, "plaintext": bytes(plaintext), "uid": uid7.hex().upper(), "crc": crc_out}


# ------------------------------------------------------------------ LF RFID bit frames

def _bit_string(bits: str | Sequence[int], what: str) -> str:
    if isinstance(bits, str):
        out = "".join(bits.split())
    else:
        if len(bits) > MAX_INPUT * 8:
            raise RFIDParseError(f"{what} exceeds bit cap")
        out = "".join(str(int(bit)) for bit in bits)
    if len(out) > MAX_INPUT * 8 or set(out) - {"0", "1"}:
        raise RFIDParseError(f"{what} must be a bounded binary string")
    return out


def parse_em4100_frame(bits: str | Sequence[int]) -> dict[str, Any]:
    frame = _bit_string(bits, "EM4100 frame")
    if len(frame) != 64:
        raise RFIDParseError("EM4100 frame must contain 64 bits")
    header_ok, stop_ok = frame[:9] == "1" * 9, frame[-1] == "0"
    rows, nibbles, row_parity = [], [], []
    cursor = 9
    for row in range(10):
        data = frame[cursor:cursor + 4]
        parity = int(frame[cursor + 4])
        valid = (data.count("1") + parity) % 2 == 0
        rows.append({"row": row, "nibble": int(data, 2), "parity": parity, "valid": valid})
        nibbles.append(data)
        row_parity.append(valid)
        cursor += 5
    columns = frame[cursor:cursor + 4]
    column_valid = []
    for column in range(4):
        column_valid.append((sum(int(nibble[column]) for nibble in nibbles) + int(columns[column])) % 2 == 0)
    identifier = int("".join(nibbles), 2)
    return {
        "protocol": "EM4100", "raw": frame, "header_valid": header_ok, "stop_valid": stop_ok,
        "row_parity_valid": row_parity, "column_parity_valid": column_valid,
        "parity_valid": all(row_parity) and all(column_valid), "valid": header_ok and stop_ok and all(row_parity) and all(column_valid),
        "identifier": identifier, "identifier_hex": f"{identifier:010X}",
        "customer": identifier >> 32, "card_number": identifier & 0xFFFFFFFF, "rows": rows,
    }


def find_em4100_frames(bits: str | Sequence[int], *, include_invalid: bool = False) -> list[dict[str, Any]]:
    stream = _bit_string(bits, "EM4100 capture")
    rows = []
    for inverted in (False, True):
        candidate = "".join("1" if bit == "0" else "0" for bit in stream) if inverted else stream
        for offset in range(0, len(candidate) - 63):
            if candidate[offset:offset + 9] != "1" * 9:
                continue
            parsed = parse_em4100_frame(candidate[offset:offset + 64])
            if include_invalid or parsed["valid"]:
                parsed.update(offset=offset, inverted=inverted)
                rows.append(parsed)
            if len(rows) >= MAX_RECORDS:
                raise RFIDParseError("too many EM4100 frames")
    return rows


def parse_hid_wiegand(bits: str | Sequence[int], *, format_bits: int | None = None) -> dict[str, Any]:
    frame = _bit_string(bits, "HID/Wiegand frame")
    width = len(frame) if format_bits is None else format_bits
    if len(frame) != width or width not in (26, 34):
        raise RFIDParseError("supported HID/Wiegand frames are exactly 26 or 34 bits")
    half = (width - 2) // 2
    first_valid = frame[0] == str(frame[1:1 + half].count("1") & 1)  # makes first half even
    second_valid = frame[-1] == str(1 ^ (frame[1 + half:-1].count("1") & 1))  # makes second half odd
    if width == 26:
        facility, card = int(frame[1:9], 2), int(frame[9:25], 2)
        format_name = "H10301-26"
    else:
        facility, card = int(frame[1:17], 2), int(frame[17:33], 2)
        format_name = "H10306-34"
    return {"protocol": "HID-Prox/Wiegand", "format": format_name, "bits": frame,
            "facility_code": facility, "card_number": card,
            "even_parity_valid": first_valid, "odd_parity_valid": second_valid,
            "valid": first_valid and second_valid}


def find_hid_wiegand_frames(bits: str | Sequence[int], *, widths: Sequence[int] = (26, 34)) -> list[dict[str, Any]]:
    """Scan a decoded HID/Wiegand bit capture for parity-valid 26/34-bit payloads."""
    stream = _bit_string(bits, "HID/Wiegand capture")
    selected = tuple(dict.fromkeys(int(width) for width in widths))
    if not selected or any(width not in (26, 34) for width in selected):
        raise RFIDParseError("HID/Wiegand scan widths must be 26 and/or 34")
    found = []
    for width in selected:
        for offset in range(len(stream) - width + 1):
            parsed = parse_hid_wiegand(stream[offset:offset + width], format_bits=width)
            if parsed["valid"]:
                parsed["offset"] = offset
                found.append(parsed)
                if len(found) >= MAX_RECORDS:
                    raise RFIDParseError("too many HID/Wiegand frames")
    return sorted(found, key=lambda row: (row["offset"], len(row["bits"])))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline RFID/NFC artifact decoder")
    parser.add_argument("format", choices=("mifare", "ntag", "ulc", "desfire-apdu", "desfire-tlv", "ndef", "em4100", "hid"))
    parser.add_argument("artifact")
    parser.add_argument("--direction", choices=("auto", "command", "response"), default="auto")
    args = parser.parse_args(argv)
    try:
        raw = Path(args.artifact).read_bytes()
        if len(raw) > MAX_INPUT:
            raise RFIDParseError("artifact exceeds cap")
        if args.format == "mifare":
            result: Any = parse_mifare_classic_dump(raw)
        elif args.format == "ntag":
            result = parse_ntag_dump(raw)
        elif args.format == "ulc":
            result = parse_ultralight_c_dump(raw)
        elif args.format == "desfire-apdu":
            result = parse_desfire_apdu(raw, direction=args.direction)
        elif args.format == "desfire-tlv":
            result = parse_desfire_dump_records(raw)
        elif args.format == "ndef":
            result = parse_ndef_message(raw)
        elif args.format == "em4100":
            result = find_em4100_frames(raw.decode("ascii"))
        else:
            result = parse_hid_wiegand(raw.decode("ascii"))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, UnicodeError, RFIDParseError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
