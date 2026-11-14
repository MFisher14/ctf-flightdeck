#!/usr/bin/env python3
"""Puzzle documents that are not JSON: one member's bytes read as a document, for codec_search.py.

  parse(name, body) -> [(object, format)]

A Huntress mobile fixture has carried its puzzle as a JSON document since Day 1. If a later
fixture keeps the same fields in another container, these readers turn it into the same kind
of object (a dict of fields, or a list of them), and codec_search.py solves it as it solves a
JSON document, marked `doc-<format>` in the route, so the answer is unsure until the judge
accepts that route. Formats, each recognised by its bytes and never by the member's name:

  plist        Apple property list, binary (bplist00) or XML (an IPA's Info.plist or a puzzle plist)
  axml         Android compiled XML (res/xml/*.xml): every element's attributes, by `name` when it has one
  arsc         resources.arsc: the string, integer and array resources by name (strings.xml compiled)
  xml          text XML: SharedPreferences (<map><string name=..>), strings.xml (<resources>), or
               any element tree with attributes and text
  sqlite       an SQLite database: a two-column key/value table as one object, any other table row by row
  properties   Java .properties, .env or INI lines (key=value, key: value)
  yaml         a flat YAML mapping (through PyYAML when it is installed, else `key: value` lines)
  toml         through tomllib
  msgpack      a MessagePack map
  cbor         a CBOR map
  protobuf     a protobuf message read by wire type alone: fields named f<number>

Field names are normalised afterwards (normalise): a name whose last word is one the puzzle
schema uses (`huntress_codec`, `puzzle.data`, `PUZZLE_KEY`) is also given under that word, unless
the document already has it. Nothing here decides an answer; the readers only say what the
member holds. Everything is bounded and fails closed: a reader that does not recognise the bytes,
or raises, gives nothing.
"""
import base64
import io
import json
import plistlib
import re
import struct

import apk_resources as R

MAX_DOC = 1 << 16          # bytes of a member that is tried as a document (resources.arsc: MAX_TABLE)
MAX_TABLE = 1 << 20
MAX_ROWS = 200
MAX_FIELDS = 400
SCHEMA_WORDS = ("schema", "day", "codec", "data", "key", "iv", "nonce", "order", "parts", "steps", "shift",
                "encoding", "alg", "algorithm", "payload", "alphabet", "pipeline", "chain", "rails", "offsets")


MAX_NODES = 20000          # values of one parsed document: a binary plist can list one object many times over


class TooLarge(ValueError):
    pass


def _jsonable(v, depth=0, budget=None):
    """A parsed value as JSON would hold it: bytes as text (printable ASCII) or base64, dates as text.

    Raises TooLarge past MAX_NODES values: a container that refers to the same child again and
    again is small on disk and enormous once copied."""
    budget = [MAX_NODES] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0:
        raise TooLarge()
    if depth > 12:
        return None
    if isinstance(v, (bytes, bytearray, memoryview)):
        b = bytes(v)
        if b and all(32 <= c < 127 for c in b):
            return b.decode("ascii")
        return base64.b64encode(b).decode("ascii")
    if isinstance(v, dict):
        return {str(k): _jsonable(x, depth + 1, budget) for k, x in list(v.items())[:MAX_FIELDS]}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x, depth + 1, budget) for x in list(v)[:MAX_FIELDS]]
    if isinstance(v, (str, int, float, bool)) or v is None:
        return v
    return str(v)


def normalise(obj):
    """obj with every field also under the schema word its name ends in, when that word is free.

    `huntress_codec: xor` gains `codec: xor`. Two fields that end in the same word leave the word
    unset: nothing says which of them is meant."""
    if isinstance(obj, list):
        return [normalise(x) for x in obj]
    if not isinstance(obj, dict):
        return obj
    out = {k: normalise(v) for k, v in obj.items()}
    claims = {}
    for k in obj:
        words = [w for w in re.split(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])", str(k)) if w]
        if len(words) > 1 and words[-1].lower() in SCHEMA_WORDS:
            claims.setdefault(words[-1].lower(), []).append(k)
        elif len(words) == 1 and words[0].lower() in SCHEMA_WORDS and words[0] != words[0].lower():
            claims.setdefault(words[0].lower(), []).append(k)
    for word, names in claims.items():
        if len(names) == 1 and word not in out:
            out[word] = out[names[0]]
    return out


def _scalar(text):
    """One value written as text: an integer, a JSON list or object, a quoted string, else the text."""
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'":
        return t[1:-1]
    if re.fullmatch(r"-?\d{1,18}", t) and (t == "0" or not t.lstrip("-").startswith("0")):
        return int(t)
    if t[:1] in "[{":
        try:
            v = json.loads(t)
            if isinstance(v, (list, dict)):
                return v
        except ValueError:
            pass
    return t


# ---------------------------------------------------------------------------- readers

def _plist(body):
    if not (body.startswith(b"bplist00") or (b"<plist" in body[:512] and b"<!ENTITY" not in body)):
        return None
    return plistlib.loads(body)


def _elements(els):
    """Compiled or text XML elements as one object: an element with a `name` attribute is a field."""
    doc, arrays = {}, {}
    current = None
    for el in els:
        attrs, tag = el["attrs"], el["tag"]
        name = attrs.get("name")
        text = (el.get("text") or "").strip()
        if tag == "item" and current is not None and el["depth"] > current[1]:
            arrays[current[0]].append(_scalar(text) if text else attrs.get("value"))
            continue
        current = None
        if isinstance(name, str) and name:
            if tag.endswith("-array") or tag in ("array", "set", "string-set"):
                arrays[name] = []
                current = (name, el["depth"])
                continue
            value = attrs.get("value") if "value" in attrs else (_scalar(text) if text else None)
            if tag in ("string",) and text:
                value = text
            if isinstance(value, str) and tag in ("int", "integer", "long") and re.fullmatch(r"-?\d{1,18}", value):
                value = int(value)
            if value is not None and name not in doc:
                doc[name] = value
        else:
            for k, v in attrs.items():
                if k != "name" and k not in doc and v is not None:
                    doc[k] = _scalar(v) if isinstance(v, str) else v
            if text and tag not in doc:
                doc[tag] = _scalar(text)
    for k, v in arrays.items():
        doc.setdefault(k, v)
    return doc or None


def _axml(body):
    if not R.is_axml(body):
        return None
    return _elements(R.axml_tree(body))


def _arsc(body):
    if not R.is_arsc(body):
        return None
    doc = {}
    for (kind, name), value in R.arsc_values(body).items():
        if kind in ("string", "integer", "array", "bool", "raw", "xml") and value is not None and name not in doc:
            doc[name] = value
        if len(doc) >= MAX_FIELDS:
            break
    return doc or None


def _xml(body):
    head = body.lstrip()[:256]
    if not head.startswith(b"<") or b"<!ENTITY" in body or b"<plist" in head:
        return None
    if b"\0" in head:
        return None     # UTF-16 or UTF-32: the entity check above reads bytes and would not see one
    import xml.etree.ElementTree as ET
    root = ET.fromstring(body)
    els = []

    def walk(node, depth):
        if len(els) >= R.MAX_ELEMENTS or depth > 32:
            return
        tag = node.tag.split("}")[-1] if isinstance(node.tag, str) else ""
        els.append({"tag": tag, "depth": depth, "text": node.text or "",
                    "attrs": {k.split("}")[-1]: v for k, v in node.attrib.items()}})
        for child in node:
            walk(child, depth + 1)

    walk(root, 0)
    return _elements(els)


def _sqlite(body):
    if not body.startswith(b"SQLite format 3\x00"):
        return None
    import sqlite3
    con = sqlite3.connect(":memory:")
    try:
        ticks = [0]

        def tick():     # a database is read for a few rows: anything that runs long is stopped
            ticks[0] += 1
            return 1 if ticks[0] > 200 else 0

        con.set_progress_handler(tick, 1000)
        con.deserialize(body)
        con.execute("PRAGMA trusted_schema=OFF")
        out = []
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 32")]
        for t in tables:
            if not re.fullmatch(r"\w{1,64}", t) or t.startswith("sqlite_") or t == "android_metadata":
                continue
            cur = con.execute('SELECT * FROM "%s" LIMIT %d' % (t, MAX_ROWS))
            cols = [c[0] for c in cur.description]
            rows = [[_jsonable(v) for v in row] for row in cur.fetchall()]
            if len(cols) == 2 and rows and all(isinstance(r[0], str) for r in rows) \
                    and len({r[0] for r in rows}) == len(rows):
                out.append({r[0]: (_scalar(r[1]) if isinstance(r[1], str) else r[1]) for r in rows})
            elif len(cols) == 3 and rows and all(isinstance(r[1], str) for r in rows) \
                    and len({r[1] for r in rows}) == len(rows) and all(isinstance(r[0], int) for r in rows):
                out.append({r[1]: (_scalar(r[2]) if isinstance(r[2], str) else r[2]) for r in rows})   # id, key, value
            else:
                out += [dict(zip(cols, r)) for r in rows]
        return out or None
    finally:
        con.close()


MAX_CELL_ROWS = 4000     # rows of one table whose cells are read
MAX_CELLS = 40000        # cells of one database


def sqlite_cells(body):
    """([(table, column, bytes)], complete) for every TEXT and BLOB cell of every table of a SQLite file.

    Each cell is a string of its own: in the file's bytes a record's values follow one another
    with no separator, and the byte before a 20-character TEXT is its serial type, the digit `5`
    (row 270). TEXT comes back as UTF-8 whatever the database's encoding; a BLOB as it is.
    `complete` is False when a table or a row was not read (a limit, an error, a table whose
    name is not a plain word); a long cell is read whole and is no such case: the caller must then not say the database holds one value
    only. None when the body is no SQLite file or cannot be opened at all."""
    if not body.startswith(b"SQLite format 3\x00"):
        return None
    import sqlite3
    cells, complete = [], True
    try:
        con = sqlite3.connect(":memory:")
    except Exception:
        return None
    try:
        ticks = [0]

        def tick():
            ticks[0] += 1
            return 1 if ticks[0] > 2000 else 0

        con.set_progress_handler(tick, 1000)
        con.text_factory = bytes
        con.deserialize(bytes(body))
        con.execute("PRAGMA trusted_schema=OFF")
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 65")]
        if len(tables) > 64:
            complete = False
        for t in tables[:64]:
            t = t.decode("utf-8", "replace") if isinstance(t, bytes) else str(t)
            if t.startswith("sqlite_"):
                continue
            if not re.fullmatch(r"\w{1,64}", t):
                complete = False
                continue
            cur = con.execute('SELECT * FROM "%s" LIMIT %d' % (t, MAX_CELL_ROWS + 1))
            cols = [c[0] for c in cur.description]
            for i, row in enumerate(cur):
                if i >= MAX_CELL_ROWS or len(cells) >= MAX_CELLS:
                    complete = False
                    break
                for c, v in zip(cols, row):
                    if isinstance(v, (bytes, bytearray)) and v:
                        cells.append((t, c, bytes(v)))   # whole, however long: a member is at most 1 MiB
    except Exception:
        complete = False
    finally:
        con.close()
    return cells, complete


_LINE = re.compile(r"\s*(?:export\s+|set\s+)?([A-Za-z_][\w.\-]{0,63})\s*(=|:)\s*(.*?)\s*$")


def _text(body):
    """The member as text, or None when it is not (control bytes, not UTF-8, too long a line)."""
    if b"\0" in body:
        return None
    try:
        t = body.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    return t if all(len(line) <= 4096 for line in t.splitlines()) else None


def _properties(body):
    t = _text(body)
    if t is None:
        return None
    doc, seps = {}, set()
    lines = [x for x in t.splitlines() if x.strip() and not x.lstrip().startswith(("#", "!", ";", "//"))
             and not re.fullmatch(r"\s*\[[^\]]*\]\s*", x)]
    if not 2 <= len(lines) <= MAX_FIELDS:
        return None
    for line in lines:
        m = _LINE.fullmatch(line)
        if not m:
            return None
        seps.add(m.group(2))
        doc.setdefault(m.group(1), _scalar(m.group(3)))
    return doc if len(seps) == 1 else None


def _yaml(body):
    t = _text(body)
    if t is None or not re.search(r"(?m)^[A-Za-z_][\w.\-]*\s*:(\s|$)", t):
        return None
    if re.search(r"(?m)(^|[\s\[{,:-])[&*][A-Za-z0-9_]", t) or "<<" in t or "!!" in t:
        return None     # anchors, aliases, merges and tags: a small text can stand for a very large object
    try:
        import yaml
    except ImportError:
        return None
    obj = yaml.safe_load(t)
    return obj if isinstance(obj, (dict, list)) else None


def _toml(body):
    t = _text(body)
    if t is None or "=" not in t:
        return None
    import tomllib
    return tomllib.loads(t)


class _Short(Exception):
    pass


def _msgpack(body):
    if not body or not (0x80 <= body[0] <= 0x8f or body[0] in (0xde, 0xdf)):
        return None
    pos, budget = 0, [MAX_FIELDS * 8]

    def take(n):
        nonlocal pos
        if pos + n > len(body):
            raise _Short()
        pos += n
        return body[pos - n:pos]

    def num(fmt):
        return struct.unpack(fmt, take(struct.calcsize(fmt)))[0]

    def val(depth=0):
        budget[0] -= 1
        if budget[0] < 0 or depth > 16:
            raise _Short()
        b = take(1)[0]
        if b <= 0x7f:
            return b
        if b >= 0xe0:
            return b - 256
        if 0x80 <= b <= 0x8f or b in (0xde, 0xdf):
            n = b & 15 if b <= 0x8f else num(">H") if b == 0xde else num(">I")
            return {str(val(depth + 1)): val(depth + 1) for _ in range(min(n, MAX_FIELDS + 1))}
        if 0x90 <= b <= 0x9f or b in (0xdc, 0xdd):
            n = b & 15 if b <= 0x9f else num(">H") if b == 0xdc else num(">I")
            return [val(depth + 1) for _ in range(min(n, MAX_FIELDS + 1))]
        if 0xa0 <= b <= 0xbf or b in (0xd9, 0xda, 0xdb):
            n = b & 31 if b <= 0xbf else num(">B") if b == 0xd9 else num(">H") if b == 0xda else num(">I")
            return take(n).decode("utf-8", "replace")
        if b in (0xc4, 0xc5, 0xc6):
            return take(num({0xc4: ">B", 0xc5: ">H", 0xc6: ">I"}[b]))
        simple = {0xc0: None, 0xc2: False, 0xc3: True}
        if b in simple:
            return simple[b]
        fmts = {0xcc: ">B", 0xcd: ">H", 0xce: ">I", 0xcf: ">Q", 0xd0: ">b", 0xd1: ">h", 0xd2: ">i", 0xd3: ">q",
                0xca: ">f", 0xcb: ">d"}
        if b in fmts:
            return num(fmts[b])
        raise _Short()

    obj = val()
    return obj if pos == len(body) and isinstance(obj, dict) and len(obj) >= 2 else None


def _cbor(body):
    if not body or body[0] >> 5 != 5:
        return None
    pos, budget = 0, [MAX_FIELDS * 8]

    def take(n):
        nonlocal pos
        if pos + n > len(body):
            raise _Short()
        pos += n
        return body[pos - n:pos]

    def val(depth=0):
        budget[0] -= 1
        if budget[0] < 0 or depth > 16:
            raise _Short()
        b = take(1)[0]
        major, info = b >> 5, b & 31
        if major == 7:
            if info in (20, 21, 22):
                return {20: False, 21: True, 22: None}[info]
            raise _Short()
        if info < 24:
            n = info
        elif info in (24, 25, 26, 27):
            n = int.from_bytes(take(1 << (info - 24)), "big")
        else:
            raise _Short()      # indefinite lengths are not read
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return take(n)
        if major == 3:
            return take(n).decode("utf-8", "replace")
        if major == 4:
            return [val(depth + 1) for _ in range(min(n, MAX_FIELDS + 1))]
        if major == 5:
            return {str(val(depth + 1)): val(depth + 1) for _ in range(min(n, MAX_FIELDS + 1))}
        return val(depth + 1)   # a tag: its content

    obj = val()
    return obj if pos == len(body) and isinstance(obj, dict) and len(obj) >= 2 else None


def _protobuf(body, depth=0):
    """A protobuf message read by wire type alone: {"f<number>": value}. None unless the whole
    body is a run of well-formed fields with small field numbers, at least two of them."""
    if not 4 <= len(body) <= MAX_DOC:
        return None
    if depth == 0 and not any(c < 9 or 13 < c < 32 or c >= 128 for c in body):
        return None     # plain text: a message's tags and lengths are almost never all printable
    pos, doc = 0, {}

    def varint():
        nonlocal pos
        n, shift = 0, 0
        while True:
            if pos >= len(body) or shift > 63:
                raise _Short()
            c = body[pos]
            pos += 1
            n |= (c & 0x7F) << shift
            if not c & 0x80:
                return n
            shift += 7

    try:
        while pos < len(body):
            tag = varint()
            number, wire = tag >> 3, tag & 7
            if not 1 <= number <= 64 or len(doc) > 64:
                return None
            if wire == 0:
                value = varint()
            elif wire == 2:
                n = varint()
                if pos + n > len(body):
                    return None
                raw = body[pos:pos + n]
                pos += n
                try:
                    value = raw.decode("utf-8")
                    if any(ord(c) < 32 and c not in "\t\n\r" for c in value):
                        raise ValueError
                except ValueError:
                    inner = _protobuf(raw, depth + 1) if depth < 2 else None
                    value = inner if inner is not None else raw
            elif wire == 5:
                value = struct.unpack_from("<I", body, pos)[0]
                pos += 4
            elif wire == 1:
                value = struct.unpack_from("<Q", body, pos)[0]
                pos += 8
            else:
                return None
            name = "f%d" % number
            if name in doc:     # a repeated field is a list
                doc[name] = (doc[name] if isinstance(doc[name], list) else [doc[name]]) + [value]
            else:
                doc[name] = value
    except (_Short, struct.error):
        return None
    if len(doc) < 2 or not any(isinstance(v, (str, dict)) for v in doc.values()):
        return None
    return doc


def name_fields(doc, known):
    """A document whose fields have no names (protobuf): the one text field that is a codec name
    `known` recognises is also given as `codec`. Nothing else is named: the other text fields are
    read as data and the numbers as keys by codec_search, each marked in the route."""
    if not isinstance(doc, dict) or "codec" in doc:
        return doc
    names = [k for k, v in doc.items() if isinstance(v, str) and 2 <= len(v) <= 40 and known(v.strip().lower())]
    if len(names) == 1:
        doc = {**doc, "codec": doc[names[0]].strip().lower()}
    return doc


READERS = (("plist", _plist), ("axml", _axml), ("arsc", _arsc), ("sqlite", _sqlite), ("xml", _xml),
           ("toml", _toml), ("properties", _properties), ("yaml", _yaml), ("msgpack", _msgpack), ("cbor", _cbor),
           ("protobuf", _protobuf))


def parse(name, body, known=None) -> list:
    """[(object, format)] for one member: the first reader that makes an object of it, normalised.

    `known` says whether a text is a codec name (for a document with unnamed fields). A member
    over 64 KiB is not tried, except a resource table or a database (1 MiB)."""
    limit = MAX_TABLE if (R.is_arsc(body) or body.startswith(b"SQLite format 3\x00")) else MAX_DOC
    if not body or len(body) > limit:
        return []
    for fmt, reader in READERS:
        try:
            obj = reader(body)
        except Exception:
            obj = None
        if obj is None or not isinstance(obj, (dict, list)) or not obj:
            continue
        try:
            obj = _jsonable(obj)
        except (TooLarge, RecursionError):
            return []
        if fmt == "protobuf" and known is not None:
            obj = name_fields(obj, known)
        return [(normalise(obj), fmt)]
    return []
