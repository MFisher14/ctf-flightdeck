"""Offline Schneider STA/ZEF/APX inventory and captured UMAS (0x5a) decoding.

No network, PLC operations, archive extraction to disk, or executable loading.
UMAS direction is mandatory: responses contain a status, not a function echo.
Known layouts follow the original UMAS research and Black Hat EU 2024 paper;
unrecognized firmware extensions stay opaque. APX parsing follows apxutil's
observed section types 0/1/2, not an assumed universal Schneider specification.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import zipfile
from functools import wraps
from pathlib import Path

import ics_vendor_exports


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

class SchneiderError(ValueError):
    """Malformed, oversized, unsafe, or unsupported input to this reader."""


MAX_INPUT = 32 * 1024 * 1024
MAX_MEMBER = 8 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_ENTRIES = 512
MAX_SECTIONS = 512
MAX_STRINGS = 128
MAX_PDU = 65534  # MBAP length includes its unit byte.

_OPERATIONS = {
    0x01: "initialize", 0x02: "read_plc_info", 0x04: "read_status",
    0x06: "read_memory_card_info", 0x10: "reserve", 0x11: "release",
    0x12: "keep_reservation", 0x20: "read_memory", 0x21: "write_memory",
    0x30: "begin_download", 0x31: "download_packet", 0x32: "end_download",
    0x33: "begin_upload", 0x34: "upload_packet", 0x35: "end_upload",
    0x38: "signed_request", 0x40: "start_plc", 0x41: "stop_plc",
}


def _closed(function):
    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SchneiderError:
            raise
        except Exception as exc:
            raise SchneiderError(f"{function.__name__}: {type(exc).__name__}: {exc}") from None
    return call


def _bytes(data, limit=MAX_INPUT):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SchneiderError("input must be bytes-like")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if not 0 < size <= limit:
        raise SchneiderError(f"input length must be 1..{limit}")
    data = bytes(data)
    return data


def _evidence(data):
    strings = []
    truncated = False
    for pattern, encoding in ((rb"[\x20-\x7e]{4,512}", "ascii"),
                              (rb"(?:[\x20-\x7e]\x00){4,512}", "utf-16le")):
        for match in re.finditer(pattern, data):
            if len(strings) == MAX_STRINGS:
                truncated = True
                break
            strings.append({"offset": match.start(), "encoding": encoding,
                            "text": match.group().decode(encoding)})
    flags = []
    for match in flagfmt.BYTES.finditer(data):
        value = match.group().decode("ascii", errors="backslashreplace")
        if value not in flags:
            flags.append(value)
        if len(flags) == MAX_STRINGS:
            break
    return {"strings": strings, "strings_truncated": truncated, "flag_candidates": flags}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


@_closed
def parse_apx(data):
    """Inventory observed APX header/section layouts; leave compressed data opaque."""
    data = _bytes(data)
    if len(data) < 32 or data[:4] != b"APX\0":
        raise SchneiderError("expected a complete 32-byte APX header")
    result = {
        "format": "schneider-apx", "size": len(data), "sha256": _sha(data),
        "header": {"raw_hex": data[:32].hex(),
                   "version_raw": int.from_bytes(data[4:6], "little"),
                   "rte_type": data[6], "rte_size": data[10]},
        "sections": [], "complete": True,
        "limitations": ["Observed APX layouts only; no code execution, decompression, or checksum authentication."],
    }
    if data[6] != 2 or data[10] != 16:
        result.update(complete=False, opaque_offset=32,
                      unsupported="APX RTE profile is not type 2 / size 16")
        result["evidence"] = _evidence(data[32:])
        return result
    offset = 32
    while offset < len(data):
        if len(result["sections"]) >= MAX_SECTIONS:
            raise SchneiderError("APX section count exceeds limit")
        if len(data) - offset < 2:
            raise SchneiderError("truncated APX section type")
        section_type = int.from_bytes(data[offset:offset + 2], "little")
        if section_type not in (0, 1, 2):
            result.update(complete=False, opaque_offset=offset,
                          unsupported=f"unrecognized APX section type {section_type}")
            result["opaque_evidence"] = _evidence(data[offset:])
            break
        header_size = 8 if section_type == 0 else 16
        if len(data) - offset < header_size + 16:
            raise SchneiderError("truncated APX section header or RTE")
        header = data[offset:offset + header_size]
        rte = data[offset + header_size:offset + header_size + 16]
        attributes = int.from_bytes(rte[8:12], "little")
        declared_size = int.from_bytes(header[10:14], "little") if section_type == 2 else 0
        stored_size = 0 if attributes & (1 << 28) else declared_size
        start = offset + header_size + 16
        end = start + stored_size
        if end > len(data):
            raise SchneiderError("APX section extends beyond input")
        payload = data[start:end]
        compressed = bool(attributes & (1 << 13))
        section = {
            "offset": offset, "type": section_type,
            "number": int.from_bytes(header[4:6], "little"),
            "header_hex": header.hex(), "rte_hex": rte.hex(),
            "declared_data_size": declared_size, "stored_data_size": stored_size,
            "data_offset": start, "attributes": attributes,
            "rte_size_minus_one_raw": int.from_bytes(rte[4:8], "little"),
            "crc_raw": int.from_bytes(rte[12:14], "little"),
            "memory_byte_raw": rte[14], "compressed": compressed,
            "sha256": _sha(payload), "evidence": _evidence(payload),
        }
        if section_type == 2:
            section["memory_offset_raw"] = int.from_bytes(header[6:10], "little")
        result["sections"].append(section)
        offset = end
    return result


def _zip_preflight(data):
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        raise SchneiderError("expected a ZIP-based STA/ZEF archive (protected variants unsupported)")
    # Reject prefixed, ZIP64 and multidisk archives, and bound central-directory
    # work before ZipFile allocates its list of member objects.
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise SchneiderError("ZIP end record missing/truncated")
    _, disk, cd_disk, on_disk, count, cd_size, cd_offset, comment = struct.unpack_from("<4s4H2IH", data, end)
    if disk or cd_disk or count != on_disk or count == 65535:
        raise SchneiderError("multidisk/ZIP64 archive unsupported")
    if end + 22 + comment != len(data) or cd_offset + cd_size != end:
        raise SchneiderError("invalid ZIP directory extent")
    if count > MAX_ENTRIES or cd_size > 1024 * 1024:
        raise SchneiderError("ZIP directory exceeds limits")
    cursor = cd_offset
    actual = 0
    while cursor < end:
        if cursor + 46 > end or data[cursor:cursor + 4] != b"PK\x01\x02":
            raise SchneiderError("invalid ZIP central directory")
        compressed, expanded = struct.unpack_from("<II", data, cursor + 20)
        name_len, extra_len, comment_len, start_disk = struct.unpack_from("<4H", data, cursor + 28)
        local_offset = struct.unpack_from("<I", data, cursor + 42)[0]
        if start_disk or 0xFFFFFFFF in (compressed, expanded, local_offset):
            raise SchneiderError("multidisk/ZIP64 member unsupported")
        cursor += 46 + name_len + extra_len + comment_len
        actual += 1
        if actual > MAX_ENTRIES or cursor > end:
            raise SchneiderError("ZIP directory count/extent exceeds limits")
    if actual != count:
        raise SchneiderError("ZIP directory entry count mismatch")


def _safe_name(info):
    name = info.orig_filename
    normalized = name.replace("\\", "/")
    parts = normalized.rstrip("/").split("/")
    if (not name or len(name) > 1024 or "\x00" in name or normalized.startswith("/")
            or any(p in ("", ".", "..") for p in parts) or ":" in parts[0]):
        raise SchneiderError("unsafe archive member path")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise SchneiderError("archive symlinks unsupported")
    return normalized


@_closed
def parse_archive(data, *, name="<bytes>"):
    """Inventory a ZIP-based STA/ZEF; decode contained APX/XEF in memory only."""
    data = _bytes(data)
    if not isinstance(name, str) or len(name) > 4096:
        raise SchneiderError("name must be a bounded string")
    _zip_preflight(data)
    result = {"format": "schneider-zip", "source": name,
              "size": len(data), "sha256": _sha(data), "entries": [],
              "limitations": ["No archive recursion, disk extraction, decryption, or DTM execution.",
                              "ZIP/content hints do not authenticate Schneider origin."]}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        total = 0
        seen = set()
        for info in members:
            normalized = _safe_name(info)
            if normalized.casefold() in seen:
                raise SchneiderError("duplicate archive member path")
            seen.add(normalized.casefold())
            if info.file_size > MAX_MEMBER or info.compress_size > MAX_INPUT:
                raise SchneiderError("archive member exceeds size limit")
            total += info.file_size
            if total > MAX_EXPANDED:
                raise SchneiderError("archive expanded size exceeds limit")
        for info in members:
            item = {"name": info.filename, "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "compression": info.compress_type, "crc32": f"{info.CRC:08x}"}
            result["entries"].append(item)
            if info.is_dir():
                item["kind"] = "directory"
                continue
            if info.flag_bits & 1:
                item.update(kind="opaque", reason="encrypted member")
                continue
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                item.update(kind="opaque", reason="unsupported compression method")
                continue
            with archive.open(info) as stream:
                content = stream.read(MAX_MEMBER + 1)
            if len(content) != info.file_size or len(content) > MAX_MEMBER:
                raise SchneiderError("archive member actual size mismatch/limit exceeded")
            item["sha256"] = _sha(content)
            item["evidence"] = _evidence(content)
            if content.startswith(b"APX\0"):
                item.update(kind="apx", decoded=parse_apx(content))
            elif info.filename.lower().endswith(".xef"):
                item.update(kind="readable-export",
                            decoded=ics_vendor_exports.parse_export(content, name=info.filename))
            else:
                item["kind"] = "opaque"
    names = {item["name"].replace("\\", "/").casefold() for item in result["entries"]}
    result["container_hint"] = ("sta" if "binappli/station.apx" in names else
                                "zef" if "unitpro.xef" in names else "unknown")
    return result


def _need(payload, size, *, exact=False):
    if len(payload) < size or (exact and len(payload) != size):
        raise SchneiderError(f"UMAS payload must be {'exactly' if exact else 'at least'} {size} bytes")


def _transfer_marker(payload):
    _need(payload, 2)
    if payload[:2] != b"\x00\x01":
        raise SchneiderError("unsupported UMAS transfer marker (expected bytes 00 01)")


def _request_fields(function, payload):
    fields = {}
    if function == 0x01:
        if payload not in (b"", b"\0"):
            fields["profile"] = "opaque initialization extension"
    elif function == 0x10:
        _need(payload, 5)
        size = payload[4]
        _need(payload, 5 + size)
        fields = {"reserver_id_hex": payload[:4].hex(), "name_field_length": size,
                  "name_field_hex": payload[5:5 + size].hex(),
                  "extension_hex": payload[5 + size:].hex()}
        name = payload[5:5 + size].split(b"\0", 1)[0]
        fields["client_name"] = name.decode("utf-8", errors="backslashreplace")
        fields["profile"] = "reservation name field; authentication extension not interpreted"
    elif function in (0x11, 0x12):
        fields["extension_hex"] = payload.hex()
    elif function in (0x30, 0x31, 0x32, 0x33, 0x34, 0x35):
        _transfer_marker(payload)
        fields["marker_hex"] = payload[:2].hex()
        if function == 0x30:
            _need(payload, 2, exact=True)
        elif function == 0x31:
            _need(payload, 6)
            size = int.from_bytes(payload[4:6], "little")
            _need(payload, 6 + size, exact=True)
            fields.update(block_number=int.from_bytes(payload[2:4], "little"),
                          block_size=size, data_hex=payload[6:].hex())
        elif function == 0x34:
            _need(payload, 4, exact=True)
            fields["block_number"] = int.from_bytes(payload[2:4], "little")
        else:
            _need(payload, 4, exact=True)
            value = int.from_bytes(payload[2:4], "little")
            fields["max_block_size" if function == 0x33 else "block_count"] = value
    return fields


def _response_fields(function, payload):
    if function == 0x01:
        _need(payload, 13)
        size = payload[12]
        _need(payload, 13 + size)
        return {"max_frame_size": int.from_bytes(payload[:2], "little"),
                "firmware_raw": int.from_bytes(payload[2:4], "little"),
                "unknown1_hex": payload[4:8].hex(), "unknown2_hex": payload[8:12].hex(),
                "client_name": payload[13:13 + size].decode("utf-8", errors="backslashreplace"),
                "extension_hex": payload[13 + size:].hex()}
    if function == 0x10:
        _need(payload, 1)
        return {"assigned_session": payload[0], "extension_hex": payload[1:].hex()}
    if function == 0x34:
        _need(payload, 2)
        size = int.from_bytes(payload[:2], "little")
        _need(payload, 2 + size, exact=True)
        return {"block_size": size, "data_hex": payload[2:].hex()}
    if function == 0x31:
        _need(payload, 1, exact=True)
        if payload != b"\0":
            raise SchneiderError("unsupported UMAS download acknowledgement marker")
        return {"acknowledgement_hex": payload.hex()}
    return {"extension_hex": payload.hex()} if payload else {}


@_closed
def decode_umas(data, *, direction, framing="pdu", request_function=None):
    """Decode one captured PDU or complete Modbus/TCP ADU; never transmit.

    Supply request_function for operation-specific response decoding. Signed
    envelope bytes remain opaque and are never authenticated by this reader.
    """
    data = _bytes(data, MAX_PDU + 7)
    if direction not in ("request", "response") or framing not in ("pdu", "tcp"):
        raise SchneiderError("explicit request/response direction and pdu/tcp framing required")
    if request_function is not None and (type(request_function) is not int or not 0 <= request_function <= 255):
        raise SchneiderError("request_function must be a byte integer")
    if direction == "request" and request_function is not None:
        raise SchneiderError("request_function context is only for responses")
    result = {"format": "umas", "direction": direction, "framing": framing}
    if framing == "tcp":
        _need(data, 10)
        transaction, protocol, size, unit = struct.unpack_from(">HHHB", data)
        if protocol != 0 or size != len(data) - 6:
            raise SchneiderError("invalid Modbus/TCP protocol or length (one full ADU required)")
        result["mbap"] = {"transaction_id": transaction, "protocol_id": protocol,
                          "length": size, "unit_id": unit}
        data = data[7:]
    if len(data) > MAX_PDU:
        raise SchneiderError("UMAS PDU exceeds size limit")
    _need(data, 3)
    if data[0] != 0x5A:
        raise SchneiderError("expected Modbus function 0x5a")
    result.update(session=data[1], payload_hex=data[3:].hex())
    payload = data[3:]
    function = data[2] if direction == "request" else request_function
    result["function"] = function
    result["operation"] = _OPERATIONS.get(function, "unknown")
    if function in (0x30, 0x31, 0x32):
        result["transfer_direction"] = "workstation-to-plc"
    elif function in (0x33, 0x34, 0x35):
        result["transfer_direction"] = "plc-to-workstation"
    if direction == "response":
        if data[2] not in (0xFE, 0xFD):
            raise SchneiderError("unsupported UMAS response status (expected fe/fd)")
        result.update(status=data[2], success=data[2] == 0xFE)
        if data[2] == 0xFD:
            result["fields"] = {"error_payload_hex": payload.hex()}
        elif function is None:
            result["fields"] = {}
            result["limitation"] = "Response has no function echo; supply matching request_function to decode its fields."
        elif function == 0x38:
            result["fields"] = {"signed_envelope_hex": payload.hex()}
            result["limitation"] = ("Signed envelope retained opaque; signature is not verified. "
                                    "Success reflects the outer status only; inner operation status is not decoded.")
        else:
            result["fields"] = _response_fields(function, payload)
    else:
        result["fields"] = _request_fields(function, payload)
        if function == 0x38:
            result["limitation"] = "Signed envelope retained opaque; signature is not verified."
    return result


@_closed
def analyze_file(path):
    """Read at most MAX_INPUT bytes from an ordinary local artifact file."""
    path = Path(path)
    if not path.is_file():
        raise SchneiderError("artifact path must be a regular file")
    # Do not block on a FIFO if the path changes between checking and opening.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SchneiderError("artifact path must be a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_INPUT + 1)
    finally:
        os.close(descriptor)
    data = _bytes(data)
    if data.startswith(b"APX\0"):
        return parse_apx(data)
    return parse_archive(data, name=str(path))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    archive = sub.add_parser("archive", help="inventory local STA/ZEF/APX")
    archive.add_argument("path")
    umas = sub.add_parser("umas", help="decode one captured hexadecimal UMAS PDU/ADU")
    umas.add_argument("hex")
    umas.add_argument("--direction", choices=("request", "response"), required=True)
    umas.add_argument("--framing", choices=("pdu", "tcp"), default="pdu")
    umas.add_argument("--request-function", type=lambda value: int(value, 0))
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        if args.command == "archive":
            result = analyze_file(args.path)
        else:
            if len(args.hex) > 3 * (MAX_PDU + 7):
                raise SchneiderError("hex input exceeds limit")
            result = decode_umas(bytes.fromhex(args.hex), direction=args.direction,
                                 framing=args.framing, request_function=args.request_function)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
