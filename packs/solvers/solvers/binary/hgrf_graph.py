#!/usr/bin/env python3
"""Strict, question-stated HGRF property-graph reader.

HGRF uses the HCFG record layout with another magic::

    HGRF | version:u8 | xor-key:u8 | payload-length:u16le |
    crc32(plain):u32le | payload XOR xor-key

This reader is intentionally not tied to a day prefix.  It fills only unanswered
questions whose text states that layout, an exact ``graph.config.<property>`` JSON
path, and either a unique member selector or a cross-member graph-equality rule.
The record, member, path, count and omitted graph key all come from the question;
no artifact value or day-specific answer is carried here.

Nothing is executed.  A fact is offered only after bounded byte parsing, strict
UTF-8/JSON (including duplicate-key rejection), CRC-32 verification and unique
selection.  Duplicate member names, malformed Neko members, multiple valid HGRF
records, oversized inputs and divergent canonical graphs fail closed.
"""
from __future__ import annotations

import json
import re
import struct
import sys
import zlib

import binfmt
import binlib
import members as binary_members


MAGIC = b"HGRF"
HEADER = 12
PLAIN_PREFIX_MEMBERS = 16
MAX_PREFIX_MEMBERS = 32
MAX_MEMBER_BYTES = 16 << 20
MAX_PREFIX_BYTES = 32 << 20
MAX_MAGIC_MARKS = 64
MAX_ANSWER_BYTES = 4096
MAX_DELIVERY_BYTES = 256 << 20
MAX_ZIP_ENTRIES = 4096
MAX_CENTRAL_BYTES = 4 << 20

SET_PREFIX = re.compile(r"^set\d+\.", re.I)
PREFIX = re.compile(r"[a-z][a-z0-9]*", re.I)
PROPERTY = re.compile(r"[a-z][a-z0-9_]*", re.I)
SAFE_SUFFIX = re.compile(r"[a-z0-9_.-]{1,96}", re.I)

CAPSULE_FIELD = re.compile(r"analysis_config_capsule_graph_config_([a-z][a-z0-9_]*)", re.I)
COMMON_FIELD = re.compile(r"analysis_config_([a-z][a-z0-9_]*)", re.I)
PATH = re.compile(
    r"\bat\s+([a-z0-9_.-]{1,96})\s+decoded\s+HGRF\s+JSON\s+property\s+"
    r"graph\.config\.([a-z][a-z0-9_]*)\b",
    re.I,
)
ANY_PATH = re.compile(r"\bgraph\.config\.([a-z][a-z0-9_]*)\b", re.I)
UNIQUE_MEMBER = re.compile(
    r"\buse\s+the\s+unique\s+([a-z][a-z0-9]*)--\s+member\s+whose\s+basename\s+ends\s+"
    r"([a-z0-9_.-]{1,96})\b",
    re.I,
)
ANY_BASENAME = re.compile(r"\bbasename\s+ends\s+([a-z0-9_.-]{1,96})\b", re.I)
COMMON_GRAPH = re.compile(
    r"\buse\s+([a-z0-9_.-]{1,96})['’]s\s+decoded\s+HGRF\s+graph\.config\s+object\s+"
    r"after\s+confirming\s+all\s+([a-z0-9-]+)\s+canonical\s+campaign\s+graphs\s+match\s+"
    r"when\s+([a-z][a-z0-9_]*)\s+is\s+omitted\b",
    re.I,
)
ANY_COMMON_MEMBER = re.compile(
    r"\buse\s+([a-z0-9_.-]{1,96})['’]s\s+decoded\s+HGRF\s+graph\.config\s+object\b",
    re.I,
)
ANY_COMMON_RULE = re.compile(
    r"\ball\s+([a-z0-9-]+)\s+canonical\s+campaign\s+graphs\s+match\s+when\s+"
    r"([a-z][a-z0-9_]*)\s+is\s+omitted\b",
    re.I,
)

COUNT_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
    "twenty-one": 21,
    "twenty-two": 22,
    "twenty-three": 23,
    "twenty-four": 24,
    "twenty-five": 25,
    "twenty-six": 26,
    "twenty-seven": 27,
    "twenty-eight": 28,
    "twenty-nine": 29,
    "thirty": 30,
    "thirty-one": 31,
    "thirty-two": 32,
}

LAYOUT_PHRASES = (
    "unique crc32-valid hgrf record",
    "byte-4 version",
    "byte-5 xor key",
    "little-endian length and crc32 fields",
    "xor decoding",
    "utf-8 json payload",
    "same 12-byte layout as hcfg",
    "submit the exact json string",
    "without json quotes",
)


def _note(text: str) -> None:
    print(f"[hgrf_graph] {str(text)[:400]}", file=sys.stderr)


def _qid(q) -> str:
    if not isinstance(q, dict):
        return ""
    value = q.get("qid") or q.get("id") or ""
    return value if isinstance(value, str) else ""


def _parts(qid: str):
    bare = SET_PREFIX.sub("", qid)
    prefix, sep, field = bare.partition("_")
    if not sep or not PREFIX.fullmatch(prefix):
        return None
    return prefix.lower(), field.lower()


def _text(q) -> str:
    value = q.get("question") if isinstance(q, dict) else ""
    return value if isinstance(value, str) else ""


def _fold_text(value: str) -> str:
    return " ".join(value.lower().split())


def _exact_text(q) -> bool:
    fmt = q.get("answer_format") if isinstance(q, dict) else None
    if not isinstance(fmt, dict) or str(fmt.get("kind") or "").lower() != "exact_text":
        return False
    syntax = _fold_text(str(fmt.get("syntax") or ""))
    return "exact" in syntax and "no quotes" in syntax


def _layout_stated(q) -> bool:
    text = _fold_text(_text(q))
    return _exact_text(q) and all(phrase in text for phrase in LAYOUT_PHRASES)


def _count(word: str):
    word = word.lower()
    if word.isdigit():
        value = int(word)
    else:
        value = COUNT_WORDS.get(word)
    return value if isinstance(value, int) and 1 <= value <= MAX_PREFIX_MEMBERS else None


def _basename(name: str) -> str:
    return str(name).replace("\\", "/").rsplit("/", 1)[-1]


def _archive_has_duplicate(prefix: str, ctx) -> bool:
    """Reject a duplicate prefix basename visible in the delivery central directory.

    A files dict cannot represent two entries with the exact same archive name. ZIP
    central-directory names remain visible even when entry data is encrypted, so use
    them as an additional ambiguity guard when the runner supplied the delivery bytes.
    This is a bounded parser, not ``ZipFile.infolist()``: the artifact, entry count and
    central-directory span are capped before any names are decoded or collected.

    ``True`` also means an attempted ZIP directory is malformed or outside the caps;
    uncertainty about duplicate selection must fail closed. A non-ZIP or absent
    delivery is not evidence of a duplicate and is left alone.
    """
    delivery = (ctx or {}).get("delivery") if isinstance(ctx, dict) else None
    if not isinstance(delivery, (bytes, bytearray)) or bytes(delivery[:2]) != b"PK":
        return False
    data = bytes(delivery)
    if len(data) > MAX_DELIVERY_BYTES:
        return True
    mine = re.compile(rf"{re.escape(prefix)}(?![0-9a-z])", re.I)
    try:
        # EOCD plus its maximum 65535-byte comment. ZIP64 sentinels are refused: this
        # small property reader does not need a second, wider directory grammar.
        eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
        if eocd < 0 or eocd + 22 > len(data):
            return True
        disk, cd_disk, disk_entries, total_entries, cd_size, cd_at, comment = struct.unpack_from(
            "<HHHHIIH", data, eocd + 4
        )
        if (disk != 0 or cd_disk != 0 or disk_entries != total_entries
                or total_entries == 0xFFFF or cd_size == 0xFFFFFFFF or cd_at == 0xFFFFFFFF
                or total_entries > MAX_ZIP_ENTRIES or cd_size > MAX_CENTRAL_BYTES
                or cd_at + cd_size != eocd or eocd + 22 + comment != len(data)):
            return True
    except (IndexError, struct.error, ValueError):
        return True
    seen = set()
    count = 0
    at = cd_at
    end = cd_at + cd_size
    for _ in range(total_entries):
        if at + 46 > end or data[at:at + 4] != b"PK\x01\x02":
            return True
        flags = struct.unpack_from("<H", data, at + 8)[0]
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", data, at + 28)
        after = at + 46 + name_size + extra_size + comment_size
        if after > end:
            return True
        raw = data[at + 46:at + 46 + name_size]
        try:
            name = raw.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeDecodeError:
            return True
        at = after
        if name.endswith(("/", "\\")):
            continue
        base = _basename(name)
        if not mine.match(base):
            continue
        count += 1
        folded = base.casefold()
        if count > MAX_PREFIX_MEMBERS or folded in seen:
            return True
        seen.add(folded)
    return at != end


def _members(prefix: str, files, ctx):
    if not isinstance(files, dict) or _archive_has_duplicate(prefix, ctx):
        return None
    try:
        found = binary_members.day_members(files, ctx or {}, prefix)
        day = re.fullmatch(r"d0*(\d+)", prefix, re.I)
        if not found and day:
            found = binlib.day_files(files, int(day.group(1)))
    except Exception:
        return None
    if not found or len(found) > MAX_PREFIX_MEMBERS:
        return None
    out = []
    seen = set()
    total = 0
    for name, body in found:
        if not isinstance(name, str) or not isinstance(body, (bytes, bytearray)):
            return None
        base = _basename(name)
        folded = base.casefold()
        if not base or folded in seen:
            return None
        seen.add(folded)
        blob = bytes(body)
        total += len(blob)
        if len(blob) > MAX_MEMBER_BYTES or total > MAX_PREFIX_BYTES:
            return None
        out.append((name, base, blob))
    return out


def _strict_object(pairs):
    out = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in out:
            raise ValueError("duplicate or non-text JSON object key")
        out[key] = value
    return out


def _constant(value):
    raise ValueError(f"non-finite JSON constant {value}")


def _record(data: bytes):
    """The member's one CRC-valid strict-JSON HGRF object record, else None.

    Every strict-JSON payload counts toward record uniqueness.  A CRC-valid scalar or
    list beside an object therefore makes the stated "unique ... HGRF record" false;
    it is not ignored merely because it cannot supply ``graph.config``.
    """
    if len(data) > MAX_MEMBER_BYTES or data.count(MAGIC) > MAX_MAGIC_MARKS:
        return None
    valid = []
    before = len(data)
    while True:
        at = data.rfind(MAGIC, 0, before)
        if at < 0:
            break
        before = at
        if at + HEADER > len(data):
            continue
        key = data[at + 5]
        length = struct.unpack_from("<H", data, at + 6)[0]
        crc = struct.unpack_from("<I", data, at + 8)[0]
        end = at + HEADER + length
        if end > len(data):
            continue
        plain = bytes(value ^ key for value in data[at + HEADER:end])
        if zlib.crc32(plain) & 0xFFFFFFFF != crc:
            continue
        try:
            obj = json.loads(
                plain.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=_constant,
            )
        except (UnicodeDecodeError, ValueError, RecursionError):
            continue
        valid.append((obj, plain))
        if len(valid) > 1:
            return None
    return valid[0] if len(valid) == 1 and isinstance(valid[0][0], dict) else None


def _select(pool, suffix: str):
    if not SAFE_SUFFIX.fullmatch(str(suffix or "")):
        return None
    suffix = suffix.casefold()
    hits = [item for item in pool if item[1].casefold().endswith(suffix)]
    return hits[0] if len(hits) == 1 else None


def _neko_pool(pool):
    out = []
    for item in pool:
        _name, base, data = item
        looks_neko = data[:4] == b"NEKO" or base.casefold().endswith(".n")
        head = binfmt.neko_header(data)
        if looks_neko and head is None:
            return None
        if head is not None:
            out.append(item)
    return out


def _config_value(record, name: str):
    if record is None or not PROPERTY.fullmatch(name):
        return None
    config = record[0].get("config")
    value = config.get(name) if isinstance(config, dict) else None
    if not isinstance(value, str) or not value:
        return None
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return None
    return value if size <= MAX_ANSWER_BYTES else None


def _canonical_without(obj, omitted: str):
    if not isinstance(obj, dict) or omitted not in obj:
        return None
    stripped = {key: value for key, value in obj.items() if key != omitted}
    try:
        return json.dumps(stripped, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return None


def _property_spec(prefix: str, field: str, q):
    if not _layout_stated(q):
        return None
    text = _text(q)
    paths = PATH.findall(text)
    all_paths = ANY_PATH.findall(text)
    if len(paths) != 1 or len(all_paths) != 1:
        return None
    path_member, path_property = paths[0][0], paths[0][1].lower()
    if all_paths[0].lower() != path_property:
        return None

    match = CAPSULE_FIELD.fullmatch(field)
    if match:
        prop = match.group(1).lower()
        selected = UNIQUE_MEMBER.findall(text)
        basenames = ANY_BASENAME.findall(text)
        if (len(selected) != 1 or len(basenames) != 1
                or ANY_COMMON_MEMBER.search(text) or ANY_COMMON_RULE.search(text)):
            return None
        selected_prefix, suffix = selected[0]
        if (selected_prefix.lower() != prefix or prop != path_property
                or suffix.casefold() != path_member.casefold()
                or basenames[0].casefold() != suffix.casefold()):
            return None
        return ("member", suffix, prop, None, None)

    match = COMMON_FIELD.fullmatch(field)
    if match and not field.startswith("analysis_config_capsule_"):
        prop = match.group(1).lower()
        common = COMMON_GRAPH.findall(text)
        common_members = ANY_COMMON_MEMBER.findall(text)
        common_rules = ANY_COMMON_RULE.findall(text)
        if (len(common) != 1 or len(common_members) != 1 or len(common_rules) != 1
                or UNIQUE_MEMBER.search(text) or ANY_BASENAME.search(text)
                or prop != path_property):
            return None
        suffix, count_word, omitted = common[0]
        count = _count(count_word)
        if (count is None or suffix.casefold() != path_member.casefold()
                or common_members[0].casefold() != suffix.casefold()
                or common_rules[0][0].lower() != count_word.lower()
                or common_rules[0][1].lower() != omitted.lower()
                or not PROPERTY.fullmatch(omitted)):
            return None
        return ("common", suffix, prop, count, omitted)
    return None


def _format_spec(prefix: str, field: str, q):
    if field != "analysis_config_capsule_format":
        return None
    fmt = q.get("answer_format") if isinstance(q, dict) else None
    text = _fold_text(_text(q))
    selected = UNIQUE_MEMBER.findall(_text(q))
    basenames = ANY_BASENAME.findall(_text(q))
    if (not isinstance(fmt, dict) or str(fmt.get("kind") or "").lower() != "enum"
            or len(selected) != 1 or len(basenames) != 1
            or selected[0][0].lower() != prefix
            or basenames[0].casefold() != selected[0][1].casefold()
            or "classify final bytes by magic and parsed container" not in text
            or "neko_bytecode for neko bytecode" not in text
            or "submit exactly one listed lowercase token" not in text):
        return None
    return selected[0][1]


def _large_pool_candidate(qid: str, value: str, count: int):
    """Keep newly supported 17--32-member facts candidate-only.

    The first sixteen-member bound was part of the shipped reader's plain-answer
    proof.  Day 31 can plausibly carry one cumulative member per prior day, but
    widening that bound must not silently widen plain output.  Exact strict bytes
    are therefore exposed under a fresh shape key until that shape/name is judged.
    An already-unsure enum remains as-is rather than nesting one unsure value in
    another.
    """
    if count <= PLAIN_PREFIX_MEMBERS:
        return value
    try:
        import labels
        if labels.parse(value) is not None:
            return value
        parts = _parts(qid)
        if parts is None:
            return None
        key = f"binary.{parts[1]}/hgrf+members{count}"
        return labels.candidates(key, [("strict_hgrf_bytes", value)])
    except (Exception, SystemExit):
        return None


def relevant(q) -> bool:
    """Cheap evidence.py prefilter: whether this question could use the reader."""
    qid = _qid(q)
    parts = _parts(qid)
    if parts is None:
        return False
    _prefix, field = parts
    return ("hgrf" in _text(q).lower()
            or (field == "analysis_config_capsule_format" and "basename ends" in _text(q).lower()))


def fill(prefix: str, questions, got, files, ctx):
    """Fill only ``None`` answers established by the strict contracts above."""
    todo = []
    for q in questions or []:
        qid = _qid(q)
        parts = _parts(qid)
        if not qid or parts is None or parts[0] != prefix or got.get(qid) is not None:
            continue
        prop = _property_spec(prefix, parts[1], q)
        fmt = _format_spec(prefix, parts[1], q)
        if prop is not None or fmt is not None:
            todo.append((q, prop, fmt))
    if not todo:
        return got

    pool = _members(prefix, files, ctx)
    if pool is None:
        _note(f"{prefix}: member set is missing, duplicate, oversized or ambiguous; no HGRF answer")
        return got
    neko = _neko_pool(pool)
    if neko is None:
        _note(f"{prefix}: a .n/NEKO member has an invalid bounded header; no HGRF answer")
        return got
    records = {}

    def record(item):
        key = item[0]
        if key not in records:
            records[key] = _record(item[2])
        return records[key]

    common_cache = {}
    for q, prop, format_suffix in todo:
        qid = _qid(q)
        value = None
        if format_suffix is not None:
            selected = _select(neko, format_suffix)
            if selected is not None:
                try:
                    import structural_enums
                    value = structural_enums.format_answer(
                        selected[2], q.get("answer_format"), enum_only=True,
                        field="analysis_config_capsule_format",
                    )
                except (Exception, SystemExit):
                    value = None
        elif prop is not None:
            mode, suffix, name, expected, omitted = prop
            selected = _select(neko, suffix)
            if selected is not None and mode == "member":
                value = _config_value(record(selected), name)
            elif selected is not None and mode == "common":
                cache_key = (expected, omitted)
                established = common_cache.get(cache_key)
                if cache_key not in common_cache:
                    established = False
                    if len(neko) == expected:
                        recs = [record(item) for item in neko]
                        canonical = [
                            _canonical_without(rec[0], omitted) if rec is not None else None
                            for rec in recs
                        ]
                        established = all(item is not None for item in canonical) and len(set(canonical)) == 1
                    common_cache[cache_key] = established
                if established:
                    value = _config_value(record(selected), name)
        if isinstance(value, str) and value.strip():
            value = _large_pool_candidate(qid, value, len(pool))
        if isinstance(value, str) and value.strip():
            got[qid] = value
            _note(f"{qid}: filled from strict bounded member/HGRF bytes")
    return got
