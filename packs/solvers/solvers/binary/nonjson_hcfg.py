#!/usr/bin/env python3
"""Non-JSON HCFG payload reader (backlog binary/re row 1, "Non-JSON HCFG payload").

The lane's samples carry their config in an HCFG container (magic, version, XOR key, length,
CRC-32, XOR-ed payload; `hcfg.py`). Every day so far has written that payload as UTF-8 JSON, so
`hcfg._parse` runs `json.loads` only and a payload serialised any other way is dropped. An author
may keep the exact same header and CRC-32 but serialise the config as CBOR, MessagePack, BSON,
`key=value` lines or a flat XML document instead.

`decode(plain)` takes the already-de-XOR'd payload bytes (the bytes whose CRC-32 the header stores,
so the CRC is the proof they are exactly the author's) and returns `(format, {name: value})` for a
self-describing, UNAMBIGUOUS mapping, or None. Self-describing means the names are IN the bytes:

  cbor / msgpack / bson   a map whose keys are all non-empty strings (schema-less decoders in
                          toolkits/wire_decode.py; a buffer that does not consume exactly, that is
                          not a string-keyed map, or that several wire formats could claim is None)
  keyvalue                every non-blank ASCII line is `key = value` / `key: value`, keys unique
  xml                     one flat element whose children each hold text only, child tags unique

Protobuf is NOT read: its field NUMBERS are not names, so `analysis_config_<name>` cannot be mapped
to a field without the author's schema (`wire_decode` can still read a protobuf's structure, but a
field number is the author's private mapping, never a byte-proven member name). Anything the gate
leaves ambiguous is None.

This reader never decides a plain answer. `hcfg._headers` attaches the decoded map to the
container hit under `json` with a marker `nonjson=<format>`; `generic.config_answer` then offers
every member as an UNSURE `labels.pick` under a format-scoped key (the serialisation has never been
judged), and only the header-proven facts (XOR key, CRC-32, version) stay plain, exactly as for a
JSON payload. The CRC-32 over the exact payload bytes is the proof the bytes decoded here are the
author's; it is NOT a proof that the judge spells a member the way this reader read it.

Bounds: `MAX_PAYLOAD` bytes, and the wire decoders carry their own depth/item caps.
"""
import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLKITS = HERE.parent / "toolkits"
COMMON = HERE.parent / "common"

MAX_PAYLOAD = 1 << 20            # a config payload is well under a megabyte (the lane's are < 1 KB)
MAX_KV_LINES = 4096             # a key=value config of more lines than this is not read
MAX_XML_CHILDREN = 4096
WIRE_FORMATS = ("bson", "cbor", "msgpack")     # self-describing, string-keyed maps; NOT protobuf

_KV_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.\-]*)\s*[=:]\s*(.*?)\s*$")

_WIRE = []      # [module] or [None]: wire_decode, loaded once, defensively


def _wire_decode():
    """toolkits/wire_decode.py, loaded by path so a binary solver need not sit on the toolkits
    path, or None after one stderr line (then only the text and XML readers run)."""
    if not _WIRE:
        try:
            for p in (str(COMMON), str(TOOLKITS)):
                if p not in sys.path:
                    sys.path.insert(0, p)       # wire_decode imports `labels` and `triage` from common
            spec = importlib.util.spec_from_file_location("binary_wire_decode", TOOLKITS / "wire_decode.py")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _WIRE.append(mod)
        except Exception as e:                  # pragma: no cover - environment-dependent
            print(f"[nonjson_hcfg] wire_decode.py did not load ({type(e).__name__}: {e}); "
                  "a CBOR/MessagePack/BSON payload is not read", file=sys.stderr)
            _WIRE.append(None)
    return _WIRE[0]


def _string_keyed_map(value):
    """`value` when it is a non-empty mapping whose every key is a non-empty string, else None.
    A non-string key (a CBOR/MessagePack integer key) cannot map to analysis_config_<name>."""
    if not isinstance(value, dict) or not value:
        return None
    if all(isinstance(k, str) and k for k in value):
        return value
    return None


def _wire_reading(plain: bytes):
    """(format, map) for a CBOR/MessagePack/BSON payload that decodes to one unambiguous
    string-keyed map, or None. Protobuf and any ambiguous or non-map decode are None."""
    mod = _wire_decode()
    if mod is None:
        return None
    try:
        c = mod.classify(plain)
    except Exception:
        return None
    if not c or c.get("ambiguous"):             # several formats decode it: nothing is claimed
        return None
    fmt = c.get("format")
    if fmt not in WIRE_FORMATS:                 # protobuf (field numbers, not names) and the rest
        return None
    mapping = _string_keyed_map(c.get("value"))
    return (fmt, mapping) if mapping is not None else None


def _keyvalue_reading(plain: bytes):
    """(\"keyvalue\", map) when `plain` is ASCII text whose every non-blank line is `key=value`
    or `key: value` with unique keys, else None. Every line must match: a single stray line
    makes the structure ambiguous, so nothing is read."""
    try:
        text = plain.decode("ascii")
    except UnicodeDecodeError:
        return None
    out = {}
    lines = text.splitlines()
    if len(lines) > MAX_KV_LINES:
        return None
    for line in lines:
        if not line.strip():
            continue
        m = _KV_LINE.match(line)
        if not m:
            return None                         # a line that is not key=value: not a kv config
        key = m.group(1)
        if key in out:
            return None                         # a duplicate key is ambiguous
        out[key] = m.group(2)
    return ("keyvalue", out) if out else None


def _xml_reading(plain: bytes):
    """(\"xml\", map) when `plain` is one flat XML element whose children each hold only text and
    whose child tags are unique, else None. Bounded, no DTD and no external entities."""
    import xml.etree.ElementTree as ET

    if b"<" not in plain:
        return None
    try:
        # A DOCTYPE/entity declaration is refused outright (never resolve an entity).
        if re.search(rb"<!DOCTYPE|<!ENTITY", plain):
            return None
        parser = ET.XMLParser()
        try:
            parser.parser.DefaultHandlerExpand = lambda *a: None   # neutralise anything expat would expand
        except Exception:
            pass
        root = ET.fromstring(plain, parser=parser)
    except ET.ParseError:
        return None
    except Exception:
        return None
    children = list(root)
    if not children or len(children) > MAX_XML_CHILDREN:
        return None
    out = {}
    for child in children:
        if len(list(child)) or child.attrib:    # a nested element or attributes: not a flat map
            return None
        tag = child.tag
        if not isinstance(tag, str) or tag in out:
            return None                          # a comment/PI (non-str tag) or a duplicate tag
        out[tag] = child.text if child.text is not None else ""
    return ("xml", out) if out else None


def decode(plain: bytes):
    """(format, {name: value}) for a non-JSON HCFG payload whose structure is unambiguous, or None.
    `plain` is the de-XOR'd payload whose CRC-32 the header has already verified. The caller must
    have confirmed the payload is NOT JSON (hcfg._parse returned None) first."""
    if not isinstance(plain, (bytes, bytearray)) or not plain or len(plain) > MAX_PAYLOAD:
        return None
    plain = bytes(plain)
    wire = _wire_reading(plain)
    if wire is not None:
        return wire
    # Only when no wire decoder consumed the bytes: a clean wire decode is the reading, and a
    # second interpretation would be ambiguous.
    kv = _keyvalue_reading(plain)
    if kv is not None:
        return kv
    return _xml_reading(plain)


def main(argv) -> int:
    import zlib
    try:
        import hcfg
    except Exception:
        hcfg = None
    for path in argv[1:]:
        data = Path(path).read_bytes()
        shown = False
        if hcfg is not None and hcfg.MAGIC in data:
            # Walk the file's headers, de-XOR each payload, and report any CRC-valid non-JSON map.
            o = data.find(hcfg.MAGIC)
            while o >= 0:
                if o + 12 < len(data):
                    import struct
                    key = data[o + 5]
                    length, crc = struct.unpack_from("<HI", data, o + 6)
                    enc = bytes(data[o + 12:o + 12 + length])
                    if length and len(enc) == length:
                        plain = hcfg._xor(enc, key)
                        if zlib.crc32(plain) & 0xFFFFFFFF == crc and hcfg._parse(plain) is None:
                            got = decode(plain)
                            if got:
                                print(f"{path}: offset=0x{o:x} format={got[0]} crc_ok")
                                for k, v in got[1].items():
                                    print(f"  {k} = {v!r}")
                                shown = True
                o = data.find(hcfg.MAGIC, o + 1)
        if not shown:
            got = decode(data)
            if got:
                print(f"{path}: whole file format={got[0]}")
                for k, v in got[1].items():
                    print(f"  {k} = {v!r}")
            else:
                print(f"{path}: no unambiguous non-JSON mapping")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
