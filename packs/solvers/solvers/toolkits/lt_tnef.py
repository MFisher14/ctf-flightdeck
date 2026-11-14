#!/usr/bin/env python3
"""TNEF (winmail.dat, application/ms-tnef) reader (B-251 long tail): message, properties, attachments.

A TNEF stream ([MS-OXTNEF]) is the signature 0x223E9F78, a key, then attributes: a level (1 message,
2 attachment), an id whose high word is its type, a length, the data and a 16-bit sum of the data
bytes. The message's MAPI properties (attMsgProps) and each attachment's (attAttachment) are a typed
property list, read here with named properties, multi-values and embedded objects.

    read_tnef(data) -> dict    the message fields, its properties by name, every attachment (names,
                               dates, size, sha256, MIME tag), an embedded message read in turn
    detect / inspect / solve   the engine entry points (_lt_common)

The body is taken from attBody, PR_BODY, PR_BODY_HTML and PR_RTF_COMPRESSED (decompressed with the
pinned compressed_rtf; without it the RTF is listed as `undecoded` with the needs_tool name). An
attribute whose checksum does not match is still read and is listed in `checksum_mismatches`: a
changed byte is evidence, not a reason to hide the rest. Attachment bytes go to the flag scan and,
on the CLI with --out, to files.

Bounds: MAX_ATTRIBUTES attributes, MAX_PROPS properties per list and values per property, MAX_DEPTH
embedded messages, and no length is trusted past the end of the data: every value of a property takes
bytes, so the bytes bound the values (a multi-valued property of a type with no size, PT_UNSPECIFIED or
PT_NULL, which MAPI does not define, is a FormatError: its count would be all that bounds it).

A compressed RTF body met without the compressed_rtf package is listed as undecoded and named under
`needs_tool`, which solve() carries into its notes (the rest of the stream is still read; the
compressed bytes are not scanned: they show the text in pieces, and a match across the pieces is not a
flag).
"""
from __future__ import annotations

import codecs
import datetime as _dt
import hashlib
import struct
import sys
import uuid

from _lt_common import FormatError, cli, need, solve_files, text_or_hex

ENGINE = "toolkits.lt_tnef"
SIGNATURE = b"\x78\x9f\x3e\x22"
MAX_ATTRIBUTES = 100_000
MAX_PROPS = 20_000
MAX_DEPTH = 8
IID_IMESSAGE = uuid.UUID("00020307-0000-0000-c000-000000000046").bytes_le

ATTRIBUTES = {0x8000: "from", 0x8004: "subject", 0x8005: "date_sent", 0x8006: "date_received", 0x8007: "message_status",
              0x8008: "message_class", 0x8009: "message_id", 0x800A: "parent_id", 0x800B: "conversation_id",
              0x800C: "body", 0x800D: "priority", 0x800F: "attach_data", 0x8010: "attach_title",
              0x8011: "attach_metafile", 0x8012: "attach_create_date", 0x8013: "attach_modify_date",
              0x8020: "date_modified", 0x9001: "attach_transport_filename", 0x9002: "attach_rend_data",
              0x9003: "message_props", 0x9004: "recipient_table", 0x9005: "attachment_props", 0x9006: "tnef_version",
              0x9007: "oem_codepage", 0x0600: "original_message_class", 0x0000: "owner", 0x0001: "sent_for",
              0x0002: "delegate", 0x0006: "date_start", 0x0007: "date_end", 0x0008: "aid_owner", 0x0009: "request_response"}
PROPS = {0x001A: "message_class", 0x0037: "subject", 0x0039: "client_submit_time", 0x003D: "subject_prefix",
         0x0042: "sent_representing_name", 0x0070: "conversation_topic", 0x007D: "transport_message_headers",
         0x0C1A: "sender_name", 0x0C1E: "sender_address_type", 0x0C1F: "sender_email_address", 0x0E02: "display_bcc",
         0x0E03: "display_cc", 0x0E04: "display_to", 0x0E06: "message_delivery_time", 0x0E1D: "normalized_subject",
         0x1000: "body", 0x1009: "rtf_compressed", 0x1013: "body_html", 0x1035: "internet_message_id",
         0x3001: "display_name", 0x3007: "creation_time", 0x3008: "last_modification_time", 0x3701: "attach_data",
         0x3703: "attach_extension", 0x3704: "attach_filename", 0x3705: "attach_method", 0x3707: "attach_long_filename",
         0x370E: "attach_mime_tag", 0x3712: "attach_content_id", 0x3716: "attach_content_disposition"}
FIXED = {0x0002: ("<h", 4), 0x0003: ("<i", 4), 0x0004: ("<f", 4), 0x0005: ("<d", 8), 0x0006: ("<q", 8),
         0x0007: ("<d", 8), 0x000A: ("<I", 4), 0x000B: ("<H", 4), 0x0014: ("<q", 8), 0x0040: ("<Q", 8)}
VARIABLE = (0x001E, 0x001F, 0x0102, 0x000D)


def _take(d, o, n):
    need(0 <= n <= len(d) - o, f"a {n}-byte value at offset {o} runs past the end of the data")
    return bytes(d[o:o + n]), o + n


def _filetime(v: int):
    try:
        return (_dt.datetime(1601, 1, 1) + _dt.timedelta(microseconds=v // 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OverflowError:
        return f"filetime {v}"


def _date(raw: bytes):
    if len(raw) < 12:
        return None
    y, mo, d, h, mi, s = struct.unpack_from("<6H", raw)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}"


def _text(raw: bytes, codec: str):
    raw = raw.split(b"\x00", 1)[0] if codec != "utf-16-le" else raw
    s = raw.decode(codec, "replace")
    return s.split("\x00", 1)[0] if codec == "utf-16-le" else s


def read_props(d: bytes, codec: str):
    """[(property id, type, name or None, value)] of a MAPI property list. A named property's name is
    its string, or `<guid>:0x<id>`; a value is a str, int, float, bool, bytes, or a list of those."""
    need(len(d) >= 4, "a property list is shorter than its count")
    count, o, out = struct.unpack_from("<I", d)[0], 4, []
    need(count <= MAX_PROPS, f"a property list states {count} properties")
    for _ in range(count):
        raw, o = _take(d, o, 4)
        ptype, pid = struct.unpack("<HH", raw)
        name = None
        if pid >= 0x8000:
            guid, o = _take(d, o, 16)
            kind, o = _take(d, o, 4)
            if struct.unpack("<I", kind)[0] == 0:
                lid, o = _take(d, o, 4)
                name = f"{uuid.UUID(bytes_le=guid)}:0x{struct.unpack('<I', lid)[0]:04x}"
            else:
                ln, o = _take(d, o, 4)
                n = struct.unpack("<I", ln)[0]
                raw, o = _take(d, o, n)
                o += -n % 4
                name = raw.decode("utf-16-le", "replace").rstrip("\x00")
        base, multi = ptype & 0x0FFF, bool(ptype & 0x1000)
        need(not (multi and base in (0x0000, 0x0001)),
             f"the property 0x{pid:04x} is a multi-valued list of a type with no size (0x{ptype:04x})")
        values = []
        if base in VARIABLE or multi:
            raw, o = _take(d, o, 4)
            n = struct.unpack("<I", raw)[0]
            need(n <= MAX_PROPS, f"a property states {n} values")
        else:
            n = 1
        for _ in range(n):
            if base in VARIABLE:
                raw, o = _take(d, o, 4)
                ln = struct.unpack("<I", raw)[0]
                v, o = _take(d, o, ln)
                o += -ln % 4
                if base == 0x001E:
                    v = _text(v, codec)
                elif base == 0x001F:
                    v = _text(v, "utf-16-le")
            elif base in FIXED:
                fmt, width = FIXED[base]
                raw, o = _take(d, o, width)
                v = struct.unpack_from(fmt, raw)[0]
                if base == 0x000B:
                    v = bool(v)
                elif base == 0x0040:
                    v = _filetime(v)
            elif base == 0x0048:
                raw, o = _take(d, o, 16)
                v = str(uuid.UUID(bytes_le=raw))
            elif base in (0x0000, 0x0001):
                v = None
            else:
                raise FormatError(f"the property 0x{pid:04x} has the type 0x{ptype:04x}, which this reader cannot size")
            values.append(v)
        out.append((pid, ptype, name, values if multi else values[0] if values else None))
    return out


def _attributes(data: bytes):
    """[(level, attribute id, data, checksum ok, offset)] after the signature and key."""
    o, out = 6, []
    while o < len(data):
        need(len(out) < MAX_ATTRIBUTES, f"more than {MAX_ATTRIBUTES} attributes")
        head, at = _take(data, o, 9)
        level, ident, length = struct.unpack("<BII", head)
        need(level in (1, 2), f"the attribute at offset {o} has the level {level}")
        body, at = _take(data, at, length)
        check, at = _take(data, at, 2)
        out.append((level, ident & 0xFFFF, body, sum(body) & 0xFFFF == struct.unpack("<H", check)[0], o))
        o = at
    return out


def read_tnef(data: bytes, blobs=None, depth: int = 0, missing=None) -> dict:
    """`missing` collects, across embedded messages, what a decoder that is not installed left
    undecoded; the outermost message states it under `needs_tool`."""
    blobs = [] if blobs is None else blobs
    missing = [] if missing is None else missing
    need(data[:4] == SIGNATURE, "no TNEF signature (78 9F 3E 22)")
    need(len(data) >= 6, "the stream ends before its key")
    need(depth <= MAX_DEPTH, "embedded messages nest deeper than this reader follows")
    attrs = _attributes(data)
    codepage = next((struct.unpack_from("<I", b)[0] for lv, i, b, _, _ in attrs if i == 0x9007 and len(b) >= 4), 1252)
    codec = f"cp{codepage}"
    out = {"format": "tnef", "key": struct.unpack_from("<H", data, 4)[0], "oem_codepage": codepage,
           "attribute_count": len(attrs), "checksum_mismatches": []}
    try:
        codecs.lookup(codec)
    except LookupError:
        out["codepage_note"] = f"no codec for code page {codepage}: 8-bit text is read as cp1252"
        codec = "cp1252"
    attachments, current = [], None

    def props_into(target, raw, where):
        named = {}
        for pid, ptype, name, v in read_props(raw, codec):
            key = name or PROPS.get(pid, f"0x{pid:04x}")
            if isinstance(v, bytes):
                if pid == 0x3701 and ptype & 0x0FFF == 0x000D and v[:16] == IID_IMESSAGE and v[16:20] == SIGNATURE:
                    target["embedded_message"] = read_tnef(v[16:], blobs, depth + 1, missing)
                    continue
                if pid == 0x3701:
                    target["_data"] = v
                    continue
                if pid == 0x1009:
                    named[key] = _rtf(v, blobs, where, missing)
                    continue
                blobs.append((f"{where} {key}", v))
                v = text_or_hex(v, 2048)
            elif isinstance(v, list):
                v = [text_or_hex(x, 512) if isinstance(x, bytes) else x for x in v]
            named[key] = v
        target.setdefault("properties", {}).update(named)

    for level, ident, body, ok, offset in attrs:
        name = ATTRIBUTES.get(ident, f"0x{ident:04x}")
        if not ok:
            out["checksum_mismatches"].append(f"{name} at offset {offset}")
        if level == 1:
            if ident == 0x9003:
                props_into(out, body, "message")
            elif ident == 0x9006 and len(body) >= 4:
                out["tnef_version"] = f"0x{struct.unpack_from('<I', body)[0]:08x}"
            elif ident in (0x8005, 0x8006, 0x8020, 0x0006, 0x0007):
                out[name] = _date(body)
            elif ident in (0x8004, 0x8008, 0x8009, 0x800C, 0x0600, 0x800A, 0x800B):
                out[name] = _text(body, codec)
                blobs.append((f"message {name}", body))
            elif ident == 0x800D and len(body) >= 2:
                out[name] = struct.unpack_from("<H", body)[0]
            elif ident not in (0x9007,):
                out.setdefault("other_attributes", {})[name] = text_or_hex(body, 256)
                blobs.append((f"message {name}", body))
            continue
        if ident == 0x9002 or current is None:                 # attAttachRendData opens each attachment
            current = {}
            attachments.append(current)
        if ident == 0x800F:
            current["_data"] = body
        elif ident == 0x8010:
            current["title"] = _text(body, codec)
        elif ident == 0x9001:
            current["transport_filename"] = _text(body, codec)
        elif ident in (0x8012, 0x8013):
            current["created" if ident == 0x8012 else "modified"] = _date(body)
        elif ident == 0x9005:
            props_into(current, body, f"attachment {len(attachments)}")
        elif ident == 0x8011:
            current["metafile_bytes"] = len(body)
            blobs.append((f"attachment {len(attachments)} metafile", body))
    out["attachments"] = []
    for i, a in enumerate(attachments):
        p = a.get("properties", {})
        raw = a.pop("_data", None)
        row = {"name": p.get("attach_long_filename") or a.get("title") or p.get("attach_filename")
               or a.get("transport_filename") or f"attachment-{i + 1}"}
        row.update({k: v for k, v in a.items() if not k.startswith("_")})
        if raw is not None:
            row.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            blobs.append((row["name"], raw))
        out["attachments"].append(row)
    out.pop("_data", None)
    if missing and depth == 0:
        out["needs_tool"] = list(missing)
    return out


def _rtf(raw: bytes, blobs, where, missing):
    try:
        import compressed_rtf
    except ImportError:              # named, and its compressed bytes kept out of the flag scan: compressed RTF
        missing.append(f"py:compressed_rtf: the {where} body is compressed RTF")   # shows its text in pieces
        return {"undecoded": "needs_tool py:compressed_rtf: the body is compressed RTF", "compressed_bytes": len(raw)}
    try:
        rtf = compressed_rtf.decompress(raw)
    except Exception as e:      # the library raises its own and plain errors on a corrupt stream
        blobs.append((f"{where} rtf_compressed", raw))
        return {"undecoded": f"the compressed RTF does not decompress ({type(e).__name__}: {e})", "compressed_bytes": len(raw)}
    blobs.append((f"{where} rtf", rtf))
    return text_or_hex(rtf, 4096)


def detect(head: bytes, name: str = "") -> bool:
    return head[:4] == SIGNATURE


def inspect(data: bytes, name: str = "", opts=None):
    blobs = []
    return read_tnef(data, blobs), blobs


def solve(challenge_dir, profile=None, **opts):
    """Read every TNEF stream in the handout: scan the message, its properties and attachments for a flag."""
    return solve_files(ENGINE, "TNEF stream", challenge_dir, profile, detect, inspect, opts)


if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:], __doc__, detect, inspect))
