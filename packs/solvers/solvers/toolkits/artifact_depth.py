#!/usr/bin/env python3
"""Offline host/mail/malware artifact depth: journal, PST/OST, and safe YARA subset.

The established ``windows.py``, ``nix_host.py``, ``email.py``, ``jumplist.py``, and
``ese_reader.py`` already cover registry/EVTX/Prefetch/AmCache/LNK/SRUM, plist/text-log/history,
and EML/MSG/MBOX.  This module fills three actual seams without executing artifacts:

* binary systemd-journal DATA/ENTRY objects (including bounded XZ DATA fields),
* PST/OST header validation and conservative string/embedded-object carving, and
* a non-``eval`` YARA-style literal/hex matcher with bounded boolean conditions.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _datetime
import hashlib
import json
import lzma
import re
import struct
import sys
import zlib
from pathlib import Path


MAX_INPUT = 256 << 20
MAX_OBJECTS = 1_000_000
MAX_ENTRIES = 100_000
MAX_FIELD = 4 << 20
MAX_MATCHES = 10_000
JOURNAL_MAGIC = b"LPKSHHRH"
PST_MAGIC = b"!BDN"


class ArtifactError(ValueError):
    pass


def _uuidish(raw: bytes) -> str:
    return raw.hex() if len(raw) == 16 else ""


def _journal_field_payload(obj: bytes, flags: int) -> bytes:
    if len(obj) < 64:
        raise ArtifactError("truncated systemd journal DATA object")
    payload = obj[64:]
    compression = flags & 0x07
    if not compression:
        return payload
    if len(payload) < 8:
        raise ArtifactError("compressed journal DATA object lacks its original size")
    expected = struct.unpack_from("<Q", payload, 0)[0]
    if expected > MAX_FIELD:
        raise ArtifactError("journal DATA decompression exceeds cap")
    if compression not in (1, 2, 4):
        raise ArtifactError("journal DATA object has conflicting compression flags")
    if compression == 1:
        try:
            decoded = lzma.decompress(payload[8:])
        except lzma.LZMAError as exc:
            raise ArtifactError("journal XZ DATA object did not decompress") from exc
        if len(decoded) != expected:
            raise ArtifactError("journal XZ DATA size mismatch")
        return decoded
    if compression == 2:
        try:
            import lz4.block
            decoded = lz4.block.decompress(payload[8:], uncompressed_size=expected)
        except (ImportError, ValueError, RuntimeError) as exc:
            raise ArtifactError("journal LZ4 DATA object did not decompress") from exc
    else:
        try:
            import zstandard
            decoder = zstandard.ZstdDecompressor().decompressobj()
            decoded = decoder.decompress(payload[8:])
            if not decoder.eof or decoder.unused_data:
                raise ArtifactError("journal Zstd DATA has a truncated or trailing frame")
        except ImportError as exc:
            raise ArtifactError("journal Zstd DATA needs the offline zstandard codec") from exc
        except zstandard.ZstdError as exc:
            raise ArtifactError("journal Zstd DATA object did not decompress") from exc
    if len(decoded) != expected:
        raise ArtifactError("journal compressed DATA size mismatch")
    return decoded


def parse_systemd_journal(data: bytes) -> dict:
    """Parse bounded DATA and ENTRY objects from one binary journal file."""
    if not isinstance(data, bytes) or len(data) < 104 or len(data) > MAX_INPUT or data[:8] != JOURNAL_MAGIC:
        raise ArtifactError("invalid or oversized systemd journal")
    incompatible = struct.unpack_from("<I", data, 12)[0]
    if incompatible & ~0x1F:
        raise ArtifactError("journal uses unknown incompatible flags")
    header_size, arena_size = struct.unpack_from("<QQ", data, 88)
    if header_size < 104 or header_size > len(data) or arena_size > len(data) - header_size:
        raise ArtifactError("systemd journal header/arena bounds are invalid")
    end = header_size + arena_size
    objects: dict[int, tuple[int, int, bytes]] = {}
    offset = (header_size + 7) & ~7
    while offset + 16 <= end:
        obj_type, flags = struct.unpack_from("BB", data, offset)
        size = struct.unpack_from("<Q", data, offset + 8)[0]
        if size < 16 or offset + size > end:
            # Zero-filled tail is legal arena slack; nonzero bytes are corruption.
            if not any(data[offset:end]):
                break
            raise ArtifactError("journal object has invalid bounds")
        if obj_type not in range(1, 8):
            raise ArtifactError("journal object has an unknown type")
        objects[offset] = (obj_type, flags, data[offset:offset + size])
        if len(objects) > MAX_OBJECTS:
            raise ArtifactError("journal object count exceeds cap")
        offset = (offset + size + 7) & ~7

    fields: dict[int, tuple[str, str]] = {}
    diagnostics = []
    for at, (obj_type, flags, obj) in objects.items():
        if obj_type != 1:
            continue
        try:
            payload = _journal_field_payload(obj, flags)
        except ArtifactError as exc:
            diagnostics.append(f"DATA@0x{at:x}: {exc}")
            continue
        if len(payload) > MAX_FIELD or b"=" not in payload:
            continue
        name, value = payload.split(b"=", 1)
        if not re.fullmatch(rb"[A-Z0-9_]{1,64}", name):
            continue
        fields[at] = (name.decode("ascii"), value.decode("utf-8", "backslashreplace"))

    entries = []
    for at, (obj_type, _flags, obj) in objects.items():
        if obj_type != 3 or len(entries) >= MAX_ENTRIES:
            continue
        if len(obj) < 64 or (len(obj) - 64) % 16:
            diagnostics.append(f"ENTRY@0x{at:x}: invalid item table")
            continue
        seqnum, realtime, monotonic = struct.unpack_from("<QQQ", obj, 16)
        row = {"offset": at, "seqnum": seqnum, "realtime_us": realtime,
               "monotonic_us": monotonic, "boot_id": _uuidish(obj[40:56]), "fields": {}}
        if realtime:
            try:
                row["realtime"] = _datetime.datetime.fromtimestamp(
                    realtime / 1_000_000, tz=_datetime.timezone.utc).isoformat().replace("+00:00", "Z")
            except (OverflowError, OSError, ValueError):
                pass
        for item_at in range(64, len(obj), 16):
            data_offset = struct.unpack_from("<Q", obj, item_at)[0]
            field = fields.get(data_offset)
            if field is not None:
                name, value = field
                if name in row["fields"]:
                    old = row["fields"][name]
                    row["fields"][name] = old + [value] if isinstance(old, list) else [old, value]
                else:
                    row["fields"][name] = value
        entries.append(row)
    entries.sort(key=lambda row: (row["realtime_us"], row["seqnum"], row["offset"]))
    return {"file_id": _uuidish(data[24:40]), "machine_id": _uuidish(data[40:56]),
            "boot_id": _uuidish(data[56:72]), "state": data[16], "header_size": header_size,
            "arena_size": arena_size, "objects": len(objects), "data_fields": len(fields),
            "entries": entries, "diagnostics": diagnostics}


_EMBEDDED_MAGICS = (
    (b"MZ", "pe"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"),
    (b"%PDF-", "pdf"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"\x89PNG\r\n\x1a\n", "png"), (b"GIF87a", "gif"), (b"GIF89a", "gif"),
)


def _pst_btree_page(data: bytes, offset: int, *, unicode_store: bool,
                    expected_type: int, expected_bid: int | None = None) -> dict:
    """Decode and checksum one PST/OST NDB B-tree page.

    This deliberately stops at the NDB layer: it returns BBT/NBT metadata and child references,
    never guesses at Messaging-layer property contexts.  Both ANSI (512-byte/32-bit BREF) and
    Unicode (512-byte/64-bit BREF) page layouts are accepted.
    """
    if offset <= 0 or offset % 512 or offset + 512 > len(data):
        raise ArtifactError("PST B-tree page reference is outside the file or unaligned")
    page = data[offset:offset + 512]
    trailer_size = 16 if unicode_store else 12
    trailer_at = 512 - trailer_size
    header_at = trailer_at - (8 if unicode_store else 4)
    ptype, repeated = page[trailer_at], page[trailer_at + 1]
    if ptype != expected_type or repeated != ptype:
        raise ArtifactError("PST B-tree page type/repeat byte mismatch")
    stored_crc = struct.unpack_from("<I", page, trailer_at + 4)[0]
    if stored_crc != (zlib.crc32(page[:trailer_at]) & 0xFFFFFFFF):
        raise ArtifactError("PST B-tree page CRC mismatch")
    bid_width = 8 if unicode_store else 4
    trailer_bid = int.from_bytes(page[trailer_at + 8:trailer_at + 8 + bid_width], "little")
    if expected_bid is not None and (trailer_bid & ~1) != (expected_bid & ~1):
        raise ArtifactError("PST B-tree page BID does not match its parent reference")
    count, maximum, entry_size, level = struct.unpack_from("BBBB", page, header_at)
    if not entry_size or count > maximum or count * entry_size > header_at:
        raise ArtifactError("PST B-tree page entry table is invalid")
    entries = [page[index * entry_size:(index + 1) * entry_size] for index in range(count)]
    return {"offset": offset, "bid": trailer_bid, "level": level,
            "entry_size": entry_size, "entries": entries}


def _pst_walk_tree(data: bytes, root_bid: int, root_offset: int, *, unicode_store: bool,
                   tree: str) -> dict:
    """Walk a bounded NDB BBT or NBT from a header BREF and return verified leaf rows."""
    if tree not in ("bbt", "nbt"):
        raise ArtifactError("unknown PST B-tree kind")
    if not root_bid and not root_offset:
        return {"root_bid": 0, "root_offset": 0, "pages": 0, "entries": []}
    if not root_bid or not root_offset:
        raise ArtifactError("PST B-tree root BREF is incomplete")
    ptype = 0x80 if tree == "bbt" else 0x81
    width = 8 if unicode_store else 4
    pending = [(root_bid, root_offset, None)]
    seen: set[int] = set()
    leaves: list[dict] = []
    while pending:
        bid, offset, parent_level = pending.pop()
        if offset in seen:
            raise ArtifactError("PST B-tree contains a page cycle or duplicate reference")
        if len(seen) >= 4096:
            raise ArtifactError("PST B-tree page count exceeds cap")
        page = _pst_btree_page(data, offset, unicode_store=unicode_store,
                               expected_type=ptype, expected_bid=bid)
        seen.add(offset)
        level = page["level"]
        if parent_level is not None and level + 1 != parent_level:
            raise ArtifactError("PST B-tree levels are inconsistent")
        if level:
            minimum = width * 3  # key + child BID + child file offset
            if page["entry_size"] < minimum:
                raise ArtifactError("PST internal B-tree entry is truncated")
            last_key = -1
            children = []
            for raw in page["entries"]:
                key = int.from_bytes(raw[:width], "little")
                child_bid = int.from_bytes(raw[width:2 * width], "little")
                child_offset = int.from_bytes(raw[2 * width:3 * width], "little")
                if key < last_key or not child_bid or not child_offset:
                    raise ArtifactError("PST internal B-tree keys/references are invalid")
                last_key = key
                children.append((child_bid, child_offset, level))
            pending.extend(reversed(children))
            continue
        for raw in page["entries"]:
            if tree == "bbt":
                if len(raw) < 2 * width + 4:
                    raise ArtifactError("PST BBT leaf entry is truncated")
                row = {
                    "bid": int.from_bytes(raw[:width], "little"),
                    "file_offset": int.from_bytes(raw[width:2 * width], "little"),
                    "size": int.from_bytes(raw[2 * width:2 * width + 2], "little"),
                    "references": int.from_bytes(raw[2 * width + 2:2 * width + 4], "little"),
                    "page": offset,
                }
                if not row["bid"] or row["file_offset"] + row["size"] > len(data):
                    raise ArtifactError("PST BBT leaf points outside the file")
            else:
                if unicode_store:
                    # Unicode writers use the naturally aligned 32-byte form.  A few early
                    # implementations used the packed 24-byte form; cbEnt distinguishes them.
                    if len(raw) >= 32:
                        bid_data_at, bid_sub_at, parent_at = 8, 16, 24
                    elif len(raw) >= 24:
                        bid_data_at, bid_sub_at, parent_at = 4, 12, 20
                    else:
                        raise ArtifactError("PST Unicode NBT leaf entry is truncated")
                else:
                    if len(raw) < 16:
                        raise ArtifactError("PST ANSI NBT leaf entry is truncated")
                    bid_data_at, bid_sub_at, parent_at = 4, 8, 12
                row = {
                    "nid": int.from_bytes(raw[:4], "little"),
                    "bid_data": int.from_bytes(raw[bid_data_at:bid_data_at + width], "little"),
                    "bid_sub": int.from_bytes(raw[bid_sub_at:bid_sub_at + width], "little"),
                    "parent_nid": int.from_bytes(raw[parent_at:parent_at + 4], "little"),
                    "page": offset,
                }
                if not row["nid"]:
                    raise ArtifactError("PST NBT leaf contains a zero NID")
            leaves.append(row)
            if len(leaves) > MAX_OBJECTS:
                raise ArtifactError("PST B-tree leaf-entry count exceeds cap")
    return {"root_bid": root_bid, "root_offset": root_offset,
            "pages": len(seen), "entries": leaves}


def pst_ndb_trees(data: bytes, *, unicode_store: bool) -> dict:
    """Read header root BREFs and traverse the NDB node/block B-trees."""
    root_at = 0xB4 if unicode_store else 0xA8
    width = 8 if unicode_store else 4
    nbt_at = root_at + (36 if unicode_store else 20)
    bbt_at = root_at + (52 if unicode_store else 28)
    if bbt_at + width * 2 > len(data):
        raise ArtifactError("PST header is truncated before its B-tree roots")

    def bref(at: int) -> tuple[int, int]:
        return (int.from_bytes(data[at:at + width], "little"),
                int.from_bytes(data[at + width:at + 2 * width], "little"))

    nbt_bid, nbt_offset = bref(nbt_at)
    bbt_bid, bbt_offset = bref(bbt_at)
    return {"nbt": _pst_walk_tree(data, nbt_bid, nbt_offset, unicode_store=unicode_store, tree="nbt"),
            "bbt": _pst_walk_tree(data, bbt_bid, bbt_offset, unicode_store=unicode_store, tree="bbt")}


def inspect_pst_ost(data: bytes, name: str = "") -> dict:
    """Validate an NDB header, traverse BBT/NBT pages, and return bounded recovery leads."""
    if not isinstance(data, bytes) or len(data) < 512 or len(data) > MAX_INPUT or data[:4] != PST_MAGIC:
        raise ArtifactError("invalid or oversized PST/OST NDB file")
    if data[8:10] != b"SM":
        raise ArtifactError("PST/OST client magic is invalid")
    version, client_version = struct.unpack_from("<HH", data, 10)
    if version not in (14, 15, 23, 36, 37):
        raise ArtifactError(f"unsupported PST/OST NDB version {version}")
    kind = "ost" if name.lower().endswith(".ost") else "pst" if name.lower().endswith(".pst") else "pst-or-ost"
    unicode_store = version >= 23
    crypt_offset = 0x201 if unicode_store else 0x1CE
    crypt_method = data[crypt_offset] if crypt_offset < len(data) else 0
    crypt_names = {0: "none", 1: "permute", 2: "cyclic"}
    if crypt_method not in crypt_names:
        raise ArtifactError(f"unsupported PST high-encoding method {crypt_method}")
    strings = []
    seen = set()
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,512}", data):
        text = match.group().decode("utf-16le", "strict")
        if text not in seen:
            strings.append({"offset": match.start(), "encoding": "utf-16le", "value": text})
            seen.add(text)
        if len(strings) >= 512:
            break
    if len(strings) < 512:
        for match in re.finditer(rb"[ -~]{8,512}", data):
            text = match.group().decode("ascii")
            if text not in seen:
                strings.append({"offset": match.start(), "encoding": "ascii", "value": text})
                seen.add(text)
            if len(strings) >= 512:
                break
    embedded = []
    for magic, label in _EMBEDDED_MAGICS:
        start = 0
        while len(embedded) < 512:
            at = data.find(magic, start)
            if at < 0:
                break
            embedded.append({"offset": at, "type": label, "magic": magic.hex()})
            start = at + len(magic)
    embedded.sort(key=lambda row: row["offset"])
    trees = pst_ndb_trees(data, unicode_store=unicode_store)
    return {"format": kind, "ndb_version": version, "client_version": client_version,
            "unicode": unicode_store, "file_size": len(data),
            "crypt_method": crypt_method, "high_encoding": crypt_names[crypt_method],
            "header_sha256": hashlib.sha256(data[:512]).hexdigest(),
            "ndb_trees": trees,
            "strings": strings, "embedded": embedded[:512],
            "limitations": ["NDB BBT/NBT traversal stops before Messaging-layer PC/TC decoding",
                            ("data blocks use PST high encoding and are not decoded" if crypt_method
                             else "PST data blocks are not decoded at the Messaging layer")]}


@dataclasses.dataclass(frozen=True)
class YaraPattern:
    identifier: str
    regex: re.Pattern[bytes]


@dataclasses.dataclass(frozen=True)
class YaraRule:
    name: str
    patterns: tuple[YaraPattern, ...]
    condition: str


def _unescape_yara_string(value: str) -> bytes:
    if len(value) > 65536:
        raise ArtifactError("safe-YARA string literal exceeds cap")
    out = bytearray()
    index = 0
    while index < len(value):
        if value[index] != "\\":
            code = ord(value[index])
            if code > 0x7F:
                raise ArtifactError("YARA string literals must be ASCII in the safe subset")
            out.append(code)
            index += 1
            continue
        index += 1
        if index >= len(value):
            raise ArtifactError("trailing escape in YARA string")
        escaped = value[index]
        if escaped == "x" and index + 2 < len(value) and re.fullmatch(r"[0-9A-Fa-f]{2}", value[index + 1:index + 3]):
            out.append(int(value[index + 1:index + 3], 16))
            index += 3
        elif escaped in {'\\', '"'}:
            out.append(ord(escaped)); index += 1
        elif escaped in {"n", "r", "t"}:
            out.append({"n": 10, "r": 13, "t": 9}[escaped]); index += 1
        else:
            raise ArtifactError(f"unsupported YARA escape \\{escaped}")
    return bytes(out)


def _hex_regex(body: str) -> bytes:
    pieces = []
    tokens = body.split()
    if len(tokens) > 4096:
        raise ArtifactError("safe-YARA hex token count exceeds cap")
    for token in tokens:
        if re.fullmatch(r"[0-9A-Fa-f]{2}", token):
            pieces.append(re.escape(bytes([int(token, 16)])))
        elif token == "??":
            pieces.append(b"[\\x00-\\xff]")
        elif re.fullmatch(r"[0-9A-Fa-f]\?", token):
            high = int(token[0], 16) << 4
            pieces.append(b"[" + bytes(f"\\x{high:02x}-\\x{high + 15:02x}", "ascii") + b"]")
        elif re.fullmatch(r"\?[0-9A-Fa-f]", token):
            low = int(token[1], 16)
            pieces.append(b"(?:" + b"|".join(re.escape(bytes([value])) for value in range(low, 256, 16)) + b")")
        else:
            gap = re.fullmatch(r"\[(\d{1,5})(?:-(\d{1,5}))?\]", token)
            if gap is None:
                raise ArtifactError(f"unsupported safe-YARA hex token {token!r}")
            low, high = int(gap.group(1)), int(gap.group(2) or gap.group(1))
            if low > high or high > 65536:
                raise ArtifactError("safe-YARA hex gap exceeds cap")
            pieces.append(bytes(f"[\\x00-\\xff]{{{low},{high}}}", "ascii"))
    if not pieces:
        raise ArtifactError("empty YARA hex pattern")
    expression = b"".join(pieces)
    if len(expression) > 1 << 20:
        raise ArtifactError("expanded safe-YARA hex expression exceeds cap")
    return expression


def parse_yara_rules(text: str) -> list[YaraRule]:
    if not isinstance(text, str) or len(text) > 1 << 20:
        raise ArtifactError("YARA rules text exceeds cap")
    rules = []
    starts = list(re.finditer(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", text))
    for start_match in starts:
        depth, quote, escape = 1, False, False
        cursor = start_match.end()
        while cursor < len(text) and depth:
            char = text[cursor]
            if quote:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    quote = False
            elif char == '"':
                quote = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            cursor += 1
        if depth:
            raise ArtifactError(f"unterminated YARA rule {start_match.group(1)}")
        body = text[start_match.end():cursor - 1]
        sections = re.search(r"(?is)\bstrings\s*:(.*)\bcondition\s*:(.*)$", body)
        if sections is None:
            raise ArtifactError(f"YARA rule {start_match.group(1)} lacks strings/condition")
        patterns = []
        for line in sections.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            literal = re.fullmatch(r'\$([A-Za-z0-9_]+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(.*)', line)
            hexa = re.fullmatch(r"\$([A-Za-z0-9_]+)\s*=\s*\{(.*)\}\s*", line)
            if literal:
                ident, encoded, modifier_text = literal.groups()
                modifiers = set(modifier_text.lower().split())
                if not modifiers <= {"ascii", "wide", "nocase", "fullword"}:
                    raise ArtifactError(f"unsupported safe-YARA modifiers: {modifier_text}")
                value = _unescape_yara_string(encoded)
                alternatives = []
                if not modifiers or "ascii" in modifiers or "wide" not in modifiers:
                    alternatives.append(re.escape(value))
                if "wide" in modifiers:
                    alternatives.append(re.escape(b"".join(bytes((byte, 0)) for byte in value)))
                expression = b"(?:" + b"|".join(alternatives) + b")"
                if "fullword" in modifiers:
                    expression = b"(?<![A-Za-z0-9_])" + expression + b"(?![A-Za-z0-9_])"
                flags = re.I if "nocase" in modifiers else 0
            elif hexa:
                ident, encoded = hexa.groups()
                expression, flags = _hex_regex(encoded), 0
            else:
                raise ArtifactError(f"unsupported safe-YARA string line: {line[:120]}")
            try:
                compiled = re.compile(expression, flags)
            except re.error as exc:
                raise ArtifactError(f"invalid safe-YARA pattern ${ident}") from exc
            patterns.append(YaraPattern(ident, compiled))
        if not patterns or len(patterns) > 4096:
            raise ArtifactError("safe-YARA rule has no patterns or exceeds cap")
        condition = re.sub(r"//.*", "", sections.group(2)).strip()
        rules.append(YaraRule(start_match.group(1), tuple(patterns), condition))
    if not rules or len(rules) > 4096:
        raise ArtifactError("no bounded YARA rules found")
    return rules


def _condition(rule: YaraRule, present: dict[str, bool]) -> bool:
    condition = " ".join(rule.condition.split())
    count = sum(present.values())
    total = len(present)
    match = re.fullmatch(r"(?i)(all|any|\d+)\s+of\s+them", condition)
    if match:
        word = match.group(1).lower()
        needed = total if word == "all" else 1 if word == "any" else int(word)
        return count >= needed
    # Bounded boolean subset over identifiers; a recursive-descent evaluator avoids eval().
    tokens = re.findall(r"\$[A-Za-z0-9_]+|\(|\)|\b(?:and|or|not|true|false)\b", condition, re.I)
    if len(tokens) > 512:
        raise ArtifactError("safe-YARA condition token count exceeds cap")
    if " ".join(tokens).replace("$ ", "$") == "" or re.sub(r"\s+", "", "".join(tokens)).lower() != re.sub(r"\s+", "", condition).lower():
        raise ArtifactError(f"unsupported safe-YARA condition: {condition[:120]}")
    position = 0
    def primary():
        nonlocal position
        if position >= len(tokens):
            raise ArtifactError("truncated safe-YARA condition")
        token = tokens[position]; position += 1
        if token == "(":
            value = disjunction()
            if position >= len(tokens) or tokens[position] != ")":
                raise ArtifactError("unbalanced safe-YARA condition")
            position += 1
            return value
        if token.lower() in ("true", "false"):
            return token.lower() == "true"
        if token.startswith("$") and token[1:] in present:
            return present[token[1:]]
        raise ArtifactError(f"unknown safe-YARA identifier {token}")
    def negation():
        nonlocal position
        if position < len(tokens) and tokens[position].lower() == "not":
            position += 1
            return not negation()
        return primary()
    def conjunction():
        nonlocal position
        value = negation()
        while position < len(tokens) and tokens[position].lower() == "and":
            position += 1
            right = negation()
            value = value and right
        return value
    def disjunction():
        nonlocal position
        value = conjunction()
        while position < len(tokens) and tokens[position].lower() == "or":
            position += 1
            right = conjunction()
            value = value or right
        return value
    answer = disjunction()
    if position != len(tokens):
        raise ArtifactError("unsupported tail in safe-YARA condition")
    return answer


def scan_yara(data: bytes, rules: list[YaraRule]) -> list[dict]:
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ArtifactError("YARA scan input exceeds cap")
    output = []
    for rule in rules:
        hits, present = {}, {}
        for pattern in rule.patterns:
            offsets = []
            for match in pattern.regex.finditer(data):
                offsets.append(match.start())
                if sum(len(row) for row in hits.values()) + len(offsets) >= MAX_MATCHES:
                    break
            hits[pattern.identifier] = offsets
            present[pattern.identifier] = bool(offsets)
        if _condition(rule, present):
            output.append({"rule": rule.name, "matches": hits})
    return output


BUILTIN_RULES = r'''
rule encoded_powershell {
 strings:
  $a = "powershell" nocase fullword
  $b = "-EncodedCommand" nocase
  $c = "FromBase64String" nocase
 condition:
  $a and ($b or $c)
}
rule packed_pe_leads {
 strings:
  $mz = { 4D 5A }
  $upx = "UPX!"
  $upx0 = "UPX0"
 condition:
  $mz and ($upx or $upx0)
}
rule suspicious_loader_apis {
 strings:
  $a = "VirtualAlloc" ascii wide
  $b = "WriteProcessMemory" ascii wide
  $c = "CreateRemoteThread" ascii wide
 condition:
  2 of them
}
'''


def builtin_malware_triage(data: bytes) -> list[dict]:
    return scan_yara(data, parse_yara_rules(BUILTIN_RULES))


def _read(path: str) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ArtifactError("input exceeds size cap")
    return data


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # pragma: no cover
        raise ValueError(message)


def main(argv=None) -> int:
    parser = _Parser(prog="artifact_depth.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    journal = sub.add_parser("journal"); journal.add_argument("input")
    pst = sub.add_parser("pst"); pst.add_argument("input")
    yara = sub.add_parser("yara"); yara.add_argument("input"); yara.add_argument("--rules")
    parser.add_argument("--json", action="store_true")
    for command in (journal, pst, yara):
        command.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    try:
        args = parser.parse_args(argv)
        data = _read(args.input)
        if args.operation == "journal":
            result = parse_systemd_journal(data)
        elif args.operation == "pst":
            result = inspect_pst_ost(data, args.input)
        else:
            rules = parse_yara_rules(Path(args.rules).read_text("utf-8")) if args.rules else parse_yara_rules(BUILTIN_RULES)
            result = {"matches": scan_yara(data, rules)}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, OverflowError, UnicodeError, struct.error,
            lzma.LZMAError, re.error, MemoryError, RecursionError) as exc:
        print(f"artifact_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
