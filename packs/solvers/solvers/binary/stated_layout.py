#!/usr/bin/env python3
"""The Day 21 look-ahead (Binary, item L1): read a day's wrapper the way its own question text states it.

Days 19 and 20 put the d-sample's HCFG record inside a wrapper with a new magic (PK19, RS20) and asked one or two
new fields about it (`overlay_offset`, `overlay_size`, `hcfg_resource_size`). No shipped reader knew the new
fields, Layer 1 left them None and the lane waited for an agent's `fields_dNN.py` (Day 20: +97 s on the base, the
clocks behind it). Yet the config questions of the same prefix stated the wrapper word for word:

    Find the final RS20 overlay. Read HCFG resource length u32le at +8 and scratch length u16le at +12; bytes
    +16..+47 are the scratch SHA-256, the HCFG resource starts at +48, and scratch follows it. Verify exact end
    bounds and scratch SHA-256, then use the HCFG resource at offset 0.

    Find the final PK19 overlay. Read k1 at +5, k2 at +6, packed length u32le at +8, the 32-byte unpacked
    SHA-256 at +12, and packed bytes at +44. For each packed byte compute ror8(byte XOR k2,3) XOR k1; verify the
    unpacked SHA-256 and use the HCFG record at unpacked offset 0.

This module parses that sentence (`spec_of`), reads the final overlay of that magic in the prefix's members
(`read`), and checks everything the text says to check: every digest it names (SHA-256, CRC-32 or MD5 of a named
region), the end bound when it says "exact end bounds", every region inside the member; and when it names an HCFG
record, that record's own CRC-32. A text it cannot parse, an overlay that does not verify, or a stated
check it cannot carry out gives nothing (`read` is None), so nothing here is ever a guess.

What it answers, through `answers` (called last by evidence.solve_prefix, before the kind check):

  - ids still None of the new structural fields, ALWAYS as unsure picks (labels.pick) under
    `binary.stated_layout/<field>`: the magic's offset (`*_offset` asked of the overlay or its magic), the member
    length minus it (`overlay_size` / a text that says "minus the ... offset"), a header field the text names
    (`hcfg_resource_size` <- "HCFG resource length u32le at +8": the name's words with size/length/len/count as
    one word), a region's start, length or digest. The judge's first acceptance of a key makes it plain on the
    next variant (the gate replays it), so the base pays one probe per new field instead of a STOP. Each option is
    named by its READING (`magic_offset`, `length_from_magic`, `field:<the stated name>`, `region_start:<region>`,
    `region_length:<region>`, `<algo>_of:<region>`, `stated_magic`, `overlay_end`; a hex form after a colon), so a
    name the judge accepts for a key never answers another reading of that key plain on a later day.
  - the config ids (`config_*`, `xor_key_hex`, `hcfg_version`) from the HCFG record the text points at:
      * still None (no reader found the record: a stated transform no reader inverts): plain when every stated
        check verified, the record is CRC-valid and its campaign names the day (`BR<day>-`), else a pick;
      * answered plain by the walk from ANOTHER record (a CRC-valid decoy in the sample, in the scratch, or an
        earlier overlay): a pick of the stated record's value first and the walk's second, under
        `binary.stated_layout/config` (one NOTE line). The walk alone would send the decoy plain.

The transform grammar (`For each <region> byte compute <expr>`): byte, the index i, every one-byte or u16/u32 field
the text names, a multi-byte key field indexed `key[i % n]`, XOR / AND / OR / + / - / * / % / << / >> / NOT,
ror8(x, n) and rol8(x, n); evaluated vectorised over the region, every value taken mod 256. Anything else in the
expression makes the spec unusable. Bounds: a region over 16 MiB is not read, at most 64 occurrences of the magic
are tried, and an earlier occurrence is used only when every later one lies inside its own verified span (the
magic's bytes inside the payload are data, not a later overlay).

Nothing here is asked when no question of the prefix says "final <MAGIC> <noun>", so a day without a stated
wrapper pays one regular-expression pass over its question texts.

A stated multi-stage pipeline (backlog row 423, the Day 21 build, round 4; `_stages`, `unstage`, `_pipeline`): a
procedure that names its stages in order ("For each packed byte compute <expr>, then zlib-decompress the result",
"Base64-decode the packed bytes, then for each decoded byte compute ...", "Decompress the packed bytes with bzip2,
then base64-decode the result", "... through these stages in order: byte XOR k1 -> zlib -> base64", "Gunzip ...,
then XOR each byte with k2") is carried out stage by stage: a byte map (the grammar above, "XOR each byte with <k>",
"rotate each byte left|right by N"), zlib, raw deflate ("inflate" alone: raw deflate, else a zlib header's), gzip,
xz, LZMA (alone or xz), bzip2, base64, hex, reverse, and a bare "decompress" by its stream's own header. The first
stage reads the region its object names (or the one region there is); every later stage reads the stage before.
Each stage must end its stream (a truncated or unterminated stream reads nothing) and put out at most STAGE_MAX
bytes; the whole pipeline stops after PIPE_TIME. The record is taken ONLY from the last output, at the stated offset
(0 when none is stated), CRC-32-valid, every stated digest equal to the region it names or to one stage's output,
and with no second CRC-valid record of other JSON in that output. A verb that states a stage no pattern places
(`decrypt`, a bare `decode`, ...), an ordering word beside a stage verb ("after", "before"), an unknown item of a
stage list or more than MAX_STAGES stages make the spec unusable: nothing is read. A procedure with no stage word
(Days 19 and 20) is parsed exactly as before, the one-map transform included. The answers are the same as above.

Since the Day 21 final prep (group binary-stated): stated cipher stages, `RC4-decrypt <obj> with <key>` and
`AES-128|192|256-CBC|ECB-decrypt <obj> with <key> [and IV]` (`decrypt`), whose key is ONLY a stated byte field of the
header (`the 16-byte RC4 key is at +16`, `the AES-128 key is at +16`, `the IV at +32`: CIPHER_FIELD; `with the key`
names the one field whose name ends in key) or a quoted literal of the text (`with the ASCII key "..."`), never a
search; a key whose size the text does not state, a stage that names no key, CBC with no IV named, or a padding word
other than PKCS#7/#5 make the spec unusable; a stated PKCS#7 padding is checked and removed. And the text encodings
base32 (RFC 4648, padding optional), base32hex, base85, Ascii85 (Adobe or not) and Z85 as `<algo>-decode <obj>`
stages. Every proof rule above stands: the record CRC-32-valid with a JSON object, every stated digest verified, and
the config plain only when its campaign names the day.

Since the wave121 coverage build (the next stated ciphers, backlog row mobile+binary; `tests/test_wave121_binary_stated_ciphers.py`):
more stated cipher stages, so a config packed behind the stream/block cipher that follows RC4 and AES in the
Day 19-to-24 cipher/packaging arc is read exactly as its question states it. `ChaCha20|XChaCha20|Salsa20-decrypt
<obj> with <key> and the nonce` (a stream cipher; the nonce is a stated byte field named `nonce`/`IV`, the key size
is the stated field's, decrypted with the venv's Cryptodome, and cryptography for a 16-byte ChaCha20 nonce) and
`[big-endian|little-endian] XTEA[-CBC|-ECB]-decrypt|-decipher <obj> with <key> [and IV]` and `XXTEA-decrypt <obj>
with <key>` (the block ciphers, 128-bit key, delta 0x9E3779B9, 64 XTEA rounds / 6+52/n XXTEA rounds, words
big-endian unless the text states little-endian; a stated PKCS#7/#5 padding checked and removed, block 8). The key
and nonce/IV come ONLY from a stated byte field (or the text's quoted literal for the key), never a search; a key or
nonce whose size the text does not state, a stream stage that names no nonce, XTEA-CBC with no IV, XXTEA with a
stated mode/IV, and a padding word other than PKCS make the spec unusable (nothing read). Every proof rule above
stands, so this is never-wrong by construction: a wrong key/nonce/endianness/variant decrypts to bytes whose HCFG
record fails its CRC-32, and the whole overlay reads as None. Not built: a key given as hex in the text, a key
derived from a field (a hash of it), AEAD tags (ChaCha20-Poly1305), XTEA with a non-standard round count, and an
unstated little-endian XTEA/XXTEA (big-endian is the one default; the other is a stated word).
"""
import ast
import base64
import binascii
import bz2
import hashlib
import lzma
import re
import struct
import sys
import time
import zlib

try:
    import numpy as np
except Exception:          # pragma: no cover - the lane imports numpy with the solver
    np = None

REGION_MAX = 1 << 24
MAX_HITS = 64
NOUNS = (r"resource overlay|overlay|resource|trailer|footer|appendix|stage|blob|section|container|wrapper|package|"
         r"bundle|payload|archive|chunk|record|segment|tail|block|envelope|capsule")
WRAP = re.compile(r"\b(?:find|locate|use|read|take)\s+the\s+(?:final|last)\s+(?P<magic>[A-Z0-9][A-Za-z0-9_]{2,7})\s+"
                  r"(?P<noun>" + NOUNS + r")\b", re.I)
TYPES = {"u8": ("<B", 1), "uint8": ("<B", 1), "byte": ("<B", 1),
         "u16le": ("<H", 2), "u16be": (">H", 2), "u16": ("<H", 2), "uint16": ("<H", 2),
         "u32le": ("<I", 4), "u32be": (">I", 4), "u32": ("<I", 4), "uint32": ("<I", 4),
         "u64le": ("<Q", 8), "u64be": (">Q", 8), "u64": ("<Q", 8), "uint64": ("<Q", 8),
         "i32le": ("<i", 4), "i16le": ("<h", 2)}
DIGESTS = {"sha-256": ("sha256", 32), "sha256": ("sha256", 32), "sha-1": ("sha1", 20), "sha1": ("sha1", 20),
           "md5": ("md5", 16), "crc32": ("crc32", 4), "crc-32": ("crc32", 4),
           # wave70: the wider SHA-2 family, each the stdlib hash; a stated "N-byte <name> SHA-512 at +M" that no
           # reader read used to give no spec. Longest alternatives first so "SHA-512" is not read as "SHA-5".
           "sha-512": ("sha512", 64), "sha512": ("sha512", 64), "sha-384": ("sha384", 48), "sha384": ("sha384", 48),
           "sha-224": ("sha224", 28), "sha224": ("sha224", 28)}
# the digest-name alternation used by every digest clause (longest first)
_DIG = r"SHA-?512|SHA-?384|SHA-?256|SHA-?224|SHA-?1|MD5|CRC-?32"
SIZE_WORDS = {"size", "length", "len", "count", "bytes", "byte", "nbytes"}
STOP_WORDS = {"the", "a", "an", "its", "of", "field", "value", "little", "endian", "big", "le", "be", "data",
              "stored", "u8", "u16le", "u32le", "u64le", "u16be", "u32be", "u64be"}
NAME = r"(?P<name>[A-Za-z][A-Za-z0-9 _-]{0,40}?)"
# the Day 21 final prep, widened by wave121: a cipher key, nonce or IV field, `the 16-byte RC4 key is at +16`, `the
# AES-128 key is at +16`, `the 32-byte ChaCha20 key is at +16`, `the 12-byte nonce at +48`, `the IV at +32` (a bare
# `key at +N` keeps the u8 reading of before unless a size is stated)
CIPHER_FIELD = re.compile(r"(?i)(?:the )?(?:(?P<n>\d+)-byte )?(?P<name>(?:(?:RC4|ARC4|AES(?:-(?:128|192|256))?|"
                          r"X?ChaCha20|Salsa20|XX?TEA)\s+)?"
                          r"(?:key|IV|nonce|initiali[sz]ation vector))\s+(?:is |are )?(?:stored )?at \+(?P<at>\d+)$")


# ---------------------------------------------------------------------------- the words

def _words(text) -> tuple:
    """The name's words, lower case, the stop words dropped, every size word as `length`."""
    out = []
    for w in re.findall(r"[a-z0-9]+", str(text).lower()):
        if w in STOP_WORDS:
            continue
        out.append("length" if w in SIZE_WORDS else w)
    return tuple(out)


def _snake(text) -> str:
    return "_".join(re.findall(r"[a-z0-9]+", str(text).lower()))


def _clean_name(name: str) -> str:
    name = re.sub(r"^(?:and|then|read|the|with|also|plus)\s+", "", name.strip(), flags=re.I)
    name = re.sub(r"^(?:and|then|read|the)\s+", "", name.strip(), flags=re.I)
    return name.strip(" ,;:")


# ---------------------------------------------------------------------------- the spec

def _procedure(text: str):
    """(magic, noun, the sentences after `final <MAGIC> <noun>` up to the HCFG boilerplate) or None."""
    m = WRAP.search(text or "")
    if not m or m.group("magic").upper() == "HCFG" or not re.search(r"[A-Z]", m.group("magic")):
        return None
    rest = text[m.end():]
    cut = re.search(r"Locate the unique CRC32|Submit |Report |Return |Give ", rest)
    return m.group("magic"), m.group("noun").lower(), rest[:cut.start()] if cut else rest


def _parse(magic: str, noun: str, body: str):
    """The layout a procedure sentence states: {'magic', 'noun', 'ints', 'bytes', 'digests', 'regions',
    'transform', 'use', 'end_exact', 'checks', 'unparsed'}; None when it states nothing to read."""
    spec = {"magic": magic, "noun": noun, "ints": {}, "bytes": {}, "digests": [], "regions": {}, "order": [],
            "transform": None, "use": None, "end_exact": False, "checks": set(), "text": body}
    clauses = [c.strip() for c in re.split(r";|\.(?=\s|$)|, (?=and |then |the |bytes |verify |use |for each )|"
                                            r"(?<=\d), ", body, flags=re.I) if c.strip()]
    for clause in clauses:
        if re.match(r"(?i)(?:read |then |and )?for each ", clause):
            _clause(spec, clause)          # an expression keeps its commas: rol8(byte, 3)
            continue
        for part in re.split(r",\s+|\s+and\s+(?=[A-Za-z0-9 _-]{1,40}?\s(?:at|starts|begins|follows))", clause):
            _clause(spec, part.strip())
    if re.search(r"exact end bound|ends? exactly at the (?:member'?s? )?end|end of the member", body, re.I):
        spec["end_exact"] = True
    for m in re.finditer(r"verify (?:the )?(?P<what>[^,;.]+)", body, re.I):
        spec["checks"].add(m.group("what").strip().lower())
    if not (spec["ints"] or spec["regions"] or spec["digests"]):
        return None
    stages = _stages(body, spec)
    if stages is False:
        return None                  # a stated stage this parser cannot carry out: nothing is read
    if stages and not (len(stages) == 1 and stages[0].get("from") == "for_each"):
        spec["pipeline"] = stages    # row 423: a multi-stage (or a non-map) pipeline replaces the one-map transform
        spec["transform"] = None
    # every digest the text says to verify must be one this parser read with its place: a check it cannot carry
    # out makes the whole spec unusable (never a read that skipped a stated check)
    asked = sum(len(re.findall(r"(?:" + _DIG + r")|digest|checksum|hash", what, re.I))
                for what in spec["checks"])
    if asked > len(spec["digests"]):
        return None
    return spec


def _clause(spec: dict, part: str):
    part = re.sub(r"(?i)^(?:(?:read|then|and|also)\s+)+", "", part or "").strip()
    if not part:
        return
    m = re.match(r"(?i)(?:read |then )?for each (?P<src>[A-Za-z0-9 _-]+?) byte,? compute (?P<expr>.+)$", part)
    if m:
        spec["transform"] = {"src": _clean_name(m.group("src")), "expr": m.group("expr").strip()}
        return
    m = re.match(r"(?i)(?:then |and )?use the (?P<what>[A-Za-z0-9 _-]+?) at (?:(?P<region>[A-Za-z0-9_-]+) )?"
                 r"(?:byte )?offset (?P<off>\d+)", part)
    if m:
        spec["use"] = {"what": _clean_name(m.group("what")), "region": m.group("region"), "off": int(m.group("off"))}
        return
    m = re.match(r"(?i)(?:the )?bytes \+(?P<a>\d+)\s*\.\.\s*\+(?P<b>\d+) are the " + NAME +
                 r"\s+(?P<algo>" + _DIG + r")\b", part)
    if m:
        algo, n = DIGESTS[m.group("algo").lower()]
        a, b = int(m.group("a")), int(m.group("b"))
        if b - a + 1 == n:
            spec["digests"].append({"of": _clean_name(m.group("name")), "algo": algo, "at": a, "n": n})
        return
    m = re.match(r"(?i)(?:the )?(?:(?P<n>\d+)-byte )?(?P<algo>" + _DIG + r")(?:\s+(?P<type>u32le|u32be))?"
                 r" of the " + NAME + r" at \+(?P<at>\d+)$", part) or \
        re.match(r"(?i)(?:the )?(?:(?P<n>\d+)-byte )?" + NAME + r"\s+(?P<algo>" + _DIG + r")"
                 r"(?:\s+(?P<type>u32le|u32be))? at \+(?P<at>\d+)", part)
    if m:
        algo, n = DIGESTS[m.group("algo").lower()]
        if m.group("n") and int(m.group("n")) != n:
            return
        spec["digests"].append({"of": _clean_name(m.group("name")), "algo": algo, "at": int(m.group("at")), "n": n,
                                "type": (m.group("type") or "").lower()})
        return
    m = re.match(r"(?i)(?:the )?" + NAME + r" (?:starts|begins) at \+(?P<at>\d+)$", part)
    if not m:
        m = re.match(r"(?i)(?:the )?" + NAME + r" bytes (?:start )?at \+(?P<at>\d+)$", part)
    if m:
        _region(spec, _clean_name(m.group("name")), at=int(m.group("at")))
        return
    m = re.match(r"(?i)(?:and )?(?:the )?" + NAME + r" (?:follows|comes after|is after) (?:it|that|them|the (?P<prev>"
                 r"[A-Za-z0-9 _-]+?))$", part)
    if m:
        prev = _clean_name(m.group("prev")) if m.group("prev") else (spec["order"][-1] if spec["order"] else None)
        if prev:
            _region(spec, _clean_name(m.group("name")), after=prev)
        return
    m = CIPHER_FIELD.match(part)
    if m:
        # the Day 21 final prep: a cipher's key or IV field ('the 16-byte RC4 key is at +16', 'the AES-128 key is at
        # +16', 'the IV at +32'); its length is the stated N, else the AES size, else 16 for an IV. A bare 'key at
        # +N' (no size, no cipher word) is the u8 of before.
        name, n = _clean_name(m.group("name")), m.group("n")
        bits = re.search(r"(?i)AES-(128|192|256)", name)
        size = int(n) if n else (int(bits.group(1)) // 8 if bits else
                                 16 if re.search(r"(?i)\b(?:IV|nonce|vector)\b", name) else None)
        if bits and size != int(bits.group(1)) // 8:
            size = None
        if size is not None:
            spec["bytes"][name] = (int(m.group("at")), size)
            return
        if n or re.search(r"(?i)RC4|ARC4|AES|X?ChaCha20|Salsa20|XX?TEA|\bIV\b|nonce|vector", name):
            return                   # a key whose size the text does not state: no field (a stage naming it fails)
    m = re.match(r"(?i)(?:the )?(?P<n>\d+)-byte " + NAME + r" at \+(?P<at>\d+)$", part)
    if m:
        spec["bytes"][_clean_name(m.group("name"))] = (int(m.group("at")), int(m.group("n")))
        return
    m = re.match(r"(?i)(?:the )?" + NAME + r" (?P<type>u8|uint8|u16le|u16be|u16|uint16|u32le|u32be|u32|uint32|u64le|"
                 r"u64be|u64|uint64|i32le|i16le) at \+(?P<at>\d+)$", part)
    if not m:
        m = re.match(r"(?i)(?:the )?" + NAME + r" \((?P<type>u8|u16le|u16be|u32le|u32be|u64le|u64be)\) at \+(?P<at>\d+)$",
                     part)
    if m:
        spec["ints"][_clean_name(m.group("name"))] = (int(m.group("at")), m.group("type").lower())
        return
    m = re.match(r"(?i)(?:the )?(?:byte |key byte )?" + NAME + r" at \+(?P<at>\d+)$", part)
    if m and len(_words(m.group("name"))) <= 3:
        spec["ints"][_clean_name(m.group("name"))] = (int(m.group("at")), "u8")


def _region(spec, name, at=None, after=None):
    spec["regions"][name] = {"at": at, "after": after}
    spec["order"].append(name)


# ---------------------------------------------------------------------------- the stated pipeline (row 423)

STAGE_MAX = 1 << 23          # the most bytes any one stage may put out (8 MiB); more reads nothing
PIPE_TIME = 1.0              # seconds for one occurrence's whole pipeline, checked between stages
MAX_STAGES = 8
ALGO = (r"(?P<algo>raw[- ]deflate|raw[- ]inflate|zlib|deflate|lzma|xz|bzip2|bz2|gzip|base-?64|base-?32-?hex|base-?32|"
        r"base-?85|ascii-?85|z85|hex)")
# keyed by the algorithm's name with blanks and hyphens dropped, lower case
KINDS = {"rawdeflate": "deflate", "rawinflate": "deflate", "deflate": "deflate", "zlib": "zlib", "lzma": "lzma",
         "xz": "xz", "bzip2": "bz2", "bz2": "bz2", "gzip": "gzip", "base64": "base64", "hex": "hex",
         "base32": "base32", "base32hex": "base32hex", "base85": "base85", "ascii85": "ascii85", "z85": "z85"}
# the Day 21 final prep: a stated cipher stage. The key is a stated field ('with the key', 'with the RC4 key') or a
# quoted literal of the text ('with the ASCII key "..."'), never a search.
KEYREF = (r"(?:the\s+)?(?:(?:ascii|utf-?8|string|text|literal|printable|secret)\s+)*(?:key\s+)?"
          r"(?:[\"\u201c](?P<lit>[\x20-\x7e]{1,256}?)[\"\u201d]|'(?P<lit2>[\x20-\x7e]{1,256}?)'|"
          r"(?P<ref>(?!(?:then|and|verify|to|before|after|with)\b)[A-Za-z][A-Za-z0-9_-]*"
          r"(?:\s+(?!(?:then|and|verify|to|before|after|with)\b)[A-Za-z][A-Za-z0-9_-]*){0,2}))")
# a verb that states a stage: one this parser did not place makes a stated pipeline unusable
STAGE_VERBS = re.compile(r"(?i)\b(?:decompress|uncompress|inflate|decode|gunzip|bunzip2?|unxz|unlzma|unzip|decrypt|"
                         r"decipher|deobfuscate|descramble)\b")
# every word a stage pattern below needs (lower case, as substrings): a body with none of them states no pipeline,
# and costs a few substring tests (a case-insensitive alternation cost 20 us a text)
STAGE_HINTS = ("compress", "inflate", "decode", "gunzip", "bunzip", "unxz", "unlzma", "unzip", "decrypt", "decipher",
               "deobfusc", "descrambl", "xor each", "xor every", "rotate", "reverse", "stage", "pipeline", "step",
               "order")
_OBJ = r"(?P<obj>(?:\s+(?!(?:and|then|with|as|using|from|via|to|before|after)\b)[A-Za-z0-9_-]+){0,6})"
_DECOMP = r"(?:decompress|uncompress|decode|inflate)"
STAGE_RES = (
    ("list", re.compile(r"(?i)\b(?:stages?|pipeline|steps?|in (?:this|that|the following) order|in order)\s*"
                        r"(?:\([^)]*\))?\s*:\s*(?P<list>[^.;]+)")),
    ("for_each", re.compile(r"(?i)\bfor each (?P<src>[A-Za-z0-9 _-]+?) byte,? compute (?P<expr>.+?)"
                            r"(?=,\s*(?:and\s+)?then\b|;|\.(?:\s|$)|\s+(?:and\s+)?then\s|,\s*(?:and\s+)?(?:verify|use)\b|$)")),
    ("rc4", re.compile(r"(?i)\b(?:RC4|ARC4)[- ]decrypt\b" + _OBJ + r"\s+(?:with|using|under)\s+" + KEYREF)),
    ("aes", re.compile(r"(?i)\bAES-(?P<bits>128|192|256)-(?P<mode>CBC|ECB)[- ]decrypt\b" + _OBJ +
                       r"\s+(?:with|using|under)\s+" + KEYREF +
                       r"(?:\s+and\s+(?:the\s+)?(?P<iv>IV|nonce|initiali[sz]ation vector)\b)?")),
    # wave121: the next stated ciphers. Stream (ChaCha20/XChaCha20/Salsa20) needs a stated nonce field; the block
    # ciphers XTEA/XXTEA take a 128-bit key, words big-endian unless the text states little-endian.
    ("stream", re.compile(r"(?i)\b(?P<cipher>XChaCha20|ChaCha20|Salsa20)[- ](?:decrypt|decipher)\b" + _OBJ +
                          r"\s+(?:with|using|under)\s+" + KEYREF +
                          r"(?:\s+and\s+(?:the\s+)?(?P<nonce>nonce|IV|initiali[sz]ation vector)\b)?")),
    ("tea", re.compile(r"(?i)\b(?:(?P<endian>big|little)-endian\s+)?(?P<cipher>XXTEA|XTEA)(?:-(?P<mode>CBC|ECB))?[- ]"
                       r"(?:decrypt|decipher)\b" + _OBJ + r"\s+(?:with|using|under)\s+" + KEYREF +
                       r"(?:\s+and\s+(?:the\s+)?(?P<iv>IV|nonce|initiali[sz]ation vector)\b)?")),
    ("algo_verb", re.compile(r"(?i)\b" + ALGO + r"[- ]" + _DECOMP + r"\b" + _OBJ)),
    ("verb_algo", re.compile(r"(?i)\b" + _DECOMP + r"\b" + _OBJ + r"\s*(?:\(\s*|\b(?:with|as|using|from|via)\s+"
                             r"(?:an?\s+|the\s+)?)" + ALGO + r"\b(?:\s+(?:stream|data|format|encoding|text|bytes))?"
                             r"\s*\)?")),
    ("unverb", re.compile(r"(?i)\b(?P<verb>gunzip|bunzip2?|unxz|unlzma)\b" + _OBJ)),
    ("xor_with", re.compile(r"(?i)\bXOR (?:each|every) (?:(?P<src>[A-Za-z0-9_-]+(?: [A-Za-z0-9_-]+)?) )?byte with "
                            r"(?:the )?(?P<key>[A-Za-z][A-Za-z0-9_]*(?: (?!then\b|and\b)[A-Za-z0-9_]+)?)")),
    ("rotate", re.compile(r"(?i)\brotate (?:each|every) (?:(?P<src>[A-Za-z0-9_-]+(?: [A-Za-z0-9_-]+)?) )?byte "
                          r"(?P<dir>left|right) by (?P<n>\d+)")),
    ("reverse", re.compile(r"(?i)\breverse\b(?: the (?:byte )?order of)?" + _OBJ)),
    ("inflate", re.compile(r"(?i)\binflate\b" + _OBJ)),
    ("decompress", re.compile(r"(?i)\b(?:decompress|uncompress)\b" + _OBJ)),
)
PRONOUNS = {"", "it", "them", "that", "this", "result", "output", "the result", "the output", "these", "those"}


def _obj_src(obj):
    """The region a stage's object names ('the packed bytes' -> 'packed'), or None for a pronoun or nothing."""
    words = re.findall(r"[A-Za-z0-9_-]+", obj or "")
    while words and words[0].lower() in ("the", "a", "an", "its"):
        words = words[1:]
    while words and words[-1].lower() in ("bytes", "byte", "region", "data", "stream", "text", "blob", "string"):
        words = words[:-1]
    name = " ".join(words)
    return None if name.lower() in PRONOUNS else name


def _cipher_key(g, bnames):
    """('lit', bytes) of a quoted literal, ('field', name) of the ONE stated byte field the reference names, or None."""
    lit = g.get("lit") if g.get("lit") is not None else g.get("lit2")
    if lit is not None:
        return ("lit", lit.encode("ascii")) if lit else None
    words = [w for w in _words(g.get("ref") or "") if w not in ("field", "bytes")]
    if not words:
        return None
    hits = [b for b in bnames if _same(b.replace("_", " "), " ".join(words))]
    if not hits and words[-1] == "key":
        # 'the key': the one stated byte field whose name ends in key ('RC4 key', 'AES-128 key')
        hits = [b for b in bnames if _words(b.replace("_", " "))[-1:] == ("key",)]
    return ("field", hits[0]) if len(hits) == 1 else None


def _stage_of(kind, m, names, bnames=()):
    """One stage {'op', 'src', 'expr'?, 'from'} from a match of STAGE_RES[kind], or None."""
    g = m.groupdict()
    if kind == "for_each":
        return {"op": "map", "expr": g["expr"].strip(), "src": _clean_name(g["src"]), "from": kind}
    if kind in ("algo_verb", "verb_algo"):
        op = KINDS.get(re.sub(r"[\s-]+", "", g["algo"].lower()))
        return op and {"op": op, "src": _obj_src(g.get("obj")), "from": kind}
    if kind in ("rc4", "aes"):
        key = _cipher_key(g, bnames)
        if key is None:
            return None
        st = {"op": kind, "src": _obj_src(g.get("obj")), "from": kind, "key": key}
        if kind == "aes":
            st.update(bits=int(g["bits"]), mode=g["mode"].upper())
            if st["mode"] == "CBC":
                ivs = [b for b in bnames if set(_words(b.replace("_", " "))) & {"iv", "nonce", "vector"}]
                if not g.get("iv") or len(ivs) != 1:
                    return None      # CBC with no stated IV field, or two
                st["iv"] = ivs[0]
            elif g.get("iv"):
                return None
        return st
    if kind == "stream":
        # wave121: a stream cipher (ChaCha20/XChaCha20/Salsa20) always needs a stated nonce field
        key = _cipher_key(g, bnames)
        if key is None:
            return None
        nonces = [b for b in bnames if set(_words(b.replace("_", " "))) & {"iv", "nonce", "vector"}]
        if not g.get("nonce") or len(nonces) != 1:
            return None              # no nonce named, or more than one nonce/IV field
        return {"op": "stream", "src": _obj_src(g.get("obj")), "from": kind, "key": key,
                "cipher": re.sub(r"\s+", "", g["cipher"].lower()), "nonce": nonces[0]}
    if kind == "tea":
        # wave121: XTEA (64-bit block, ECB/CBC) or XXTEA (whole message); 128-bit key, big-endian unless stated
        key = _cipher_key(g, bnames)
        if key is None:
            return None
        cipher = g["cipher"].lower()
        st = {"op": "tea", "src": _obj_src(g.get("obj")), "from": kind, "key": key, "cipher": cipher,
              "endian": "le" if (g.get("endian") or "").lower() == "little" else "be"}
        if cipher == "xxtea":
            if g.get("mode") or g.get("iv"):
                return None          # XXTEA is a whole-message cipher: no ECB/CBC, no IV
            st["mode"] = None
            return st
        st["mode"] = (g.get("mode") or "ECB").upper()
        if st["mode"] == "CBC":
            ivs = [b for b in bnames if set(_words(b.replace("_", " "))) & {"iv", "nonce", "vector"}]
            if not g.get("iv") or len(ivs) != 1:
                return None          # CBC with no stated IV field, or two
            st["iv"] = ivs[0]
        elif g.get("iv"):
            return None
        return st
    if kind == "unverb":
        op = {"gunzip": "gzip", "bunzip": "bz2", "bunzip2": "bz2", "unxz": "xz", "unlzma": "lzma"}[g["verb"].lower()]
        return {"op": op, "src": _obj_src(g.get("obj")), "from": kind}
    if kind == "xor_with":
        key = g["key"]
        parts = key.split()
        key = next((k for k in ("_".join(parts), parts[0]) if k in names), parts[0])
        return {"op": "map", "expr": f"byte XOR {key}", "src": _clean_name(g["src"] or ""), "from": kind}
    if kind == "rotate":
        fn = "rol8" if g["dir"].lower() == "left" else "ror8"
        return {"op": "map", "expr": f"{fn}(byte, {int(g['n']) % 8})", "src": _clean_name(g["src"] or ""),
                "from": kind}
    if kind == "reverse":
        return {"op": "reverse", "src": _obj_src(g.get("obj")), "from": kind}
    if kind == "inflate":
        return {"op": "deflate", "src": _obj_src(g.get("obj")), "from": kind}
    if kind == "decompress":
        return {"op": "auto", "src": _obj_src(g.get("obj")), "from": kind}
    return None


def _split_list(text):
    """The items of a stated stage list, split at -> , => , ' > ', commas and 'then'/'and' outside parentheses."""
    items, depth, cur, i = [], 0, "", 0
    seps = re.compile(r"\s*(?:->|→|=>|\s>\s|,\s*(?:and\s+)?then\s+|,\s*and\s+|,|\s+then\s+|\s+and\s+)\s*")
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if depth == 0:
            m = seps.match(text, i)
            if m and m.end() > i:
                items.append(cur)
                cur, i = "", m.end()
                continue
        cur += ch
        i += 1
    items.append(cur)
    return [t.strip() for t in items if t.strip()]


def _list_stages(text, names, bnames=()):
    out = []
    for item in _split_list(text):
        item = re.sub(r"(?i)^(?:\(?\d+[).:]\s*|(?:first|second|third|next|finally|last)[,:]?\s+)", "", item).strip()
        m = re.fullmatch(r"(?i)" + ALGO + r"(?:[- ](?:decompress(?:ion)?|decode|decoding|inflate|stream|decompressed))?",
                         item)
        if m:
            out.append(_stage_of("algo_verb", m, names))
            continue
        hit = None
        for kind, rx in STAGE_RES[1:]:
            m = rx.search(item)
            if m:
                hit = _stage_of(kind, m, names, bnames)
                break
        if hit is None and re.search(r"(?i)\b(?:byte|b)\b", item) and _expr_tree(item, names) is not None:
            hit = {"op": "map", "expr": item, "src": None, "from": "list"}
        if hit is None:
            return None
        out.append(hit)
    return out


def _stages(body: str, spec: dict):
    """The ordered stages the procedure states ([] when none), or False when it states a stage pipeline this
    parser cannot place whole (a verb it did not read, an item of a stage list it does not know, too many)."""
    low = body.lower()
    if not any(w in low for w in STAGE_HINTS):
        return []                   # Days 19 and 20: one search, and the one-map transform of before
    names = {k.replace(" ", "_") for k in list(spec["ints"]) + list(spec["bytes"])}
    bnames = {k.replace(" ", "_") for k in spec["bytes"]}
    taken, found = [], []
    for kind, rx in STAGE_RES:
        for m in rx.finditer(body):
            if any(m.start() < b and a < m.end() for a, b in taken):
                continue
            if kind == "list":
                got = _list_stages(m.group("list"), names, bnames)
                if got is None:
                    return False
                found.extend((m.start() + k / 100.0, st) for k, st in enumerate(got))
            else:
                st = _stage_of(kind, m, names, bnames)
                if st is None:
                    return False
                found.append((m.start(), st))
            taken.append((m.start(), m.end()))
    found.sort(key=lambda p: p[0])
    stages = [st for _, st in found]
    for v in STAGE_VERBS.finditer(body):
        if not any(a <= v.start() < b for a, b in taken):
            return False            # a stated stage no pattern placed: never a read that skipped it
    if not stages or (len(stages) == 1 and stages[0]["from"] == "for_each"):
        return stages               # no pipeline: the one-map transform of before, exactly as it was read
    if len(stages) > MAX_STAGES:
        return False
    # an ordering word beside a stage verb ("before", "after", "prior to") could reverse the textual order
    for clause in re.split(r"[;.]", body):
        if STAGE_VERBS.search(clause) and re.search(r"(?i)\b(?:before|after|prior to|preceding)\b", clause):
            return False
    # the block ciphers (AES, and wave121's XTEA; XXTEA is a whole-message cipher with no PKCS framing)
    block = [st for st in stages if st["op"] == "aes" or (st["op"] == "tea" and st.get("cipher") == "xtea")]
    if block:
        # the padding as the text states it: PKCS#7 (or #5) is checked and removed; any other padding word is a step
        # this parser does not carry out; no padding word leaves the plaintext whole (the record bounds itself)
        pkcs = bool(re.search(r"(?i)\bPKCS\s*#?\s*[57]\b", body))
        if not pkcs and re.search(r"(?i)\bpad(?:s|ding|ded)?\b", body):
            return False
        for st in block:
            st["pad"] = pkcs
            st["block"] = 8 if st["op"] == "tea" else 16
    return stages


_SPECS = {}


def spec_of(questions) -> dict:
    """The one wrapper the prefix's questions state, or None (none stated, or two that differ). Memoised on the
    texts: a Mastery asks the same prefix's texts once a set."""
    texts = tuple(sorted({q.get("question") or "" for q in questions or []}))
    if texts not in _SPECS:
        if len(_SPECS) > 256:
            _SPECS.clear()
        _SPECS[texts] = _spec_of(texts)
    return _SPECS[texts]


def _spec_of(texts) -> dict:
    found, seen = {}, set()
    for text in texts:
        got = _procedure(text)
        if not got or got in seen:
            continue                 # (the config ids of a prefix repeat one procedure: it is parsed once)
        seen.add(got)
        magic, noun, body = got
        if not body.strip():
            continue
        spec = _parse(magic, noun, body)
        if spec is not None:
            found.setdefault((magic, _canon(spec)), spec)
    if len({k[0] for k in found}) != 1 or len(found) != 1:
        return None
    return next(iter(found.values()))


def _canon(spec) -> str:
    return repr((sorted(spec["ints"].items()), sorted(spec["bytes"].items()), sorted(map(repr, spec["digests"])),
                 sorted(map(repr, spec["regions"].items())), spec["transform"], spec["use"], spec["end_exact"])) + \
        (repr(spec["pipeline"]) if spec.get("pipeline") else "")


def magic_of(questions, day):
    """The magic a prefix's questions name: the stated wrapper's, else `<MAGIC> for Day <day>` of a question."""
    spec = spec_of(questions)
    if spec:
        return spec["magic"]
    for q in questions or []:
        for m in re.finditer(r"\b([A-Z0-9]{3,8}) for Day (\d+)\b", q.get("question") or ""):
            if day is not None and int(m.group(2)) == int(day) and re.search(r"[A-Z]", m.group(1)):
                return m.group(1)
    return None


# ---------------------------------------------------------------------------- the transform

FUNCS = {"ror8", "rol8", "ror", "rol"}


def _expr_tree(expr: str, names):
    """A checked ast of the stated byte expression, or None. `names` are the fields it may name."""
    text = expr.strip().rstrip(".;")
    text = re.sub(r"\bXOR\b", "^", text, flags=re.I)
    text = re.sub(r"\bAND\b", "&", text, flags=re.I)
    text = re.sub(r"\bOR\b", "|", text, flags=re.I)
    text = re.sub(r"\bNOT\b", "~", text, flags=re.I)
    text = re.sub(r"\bplus\b", "+", text, flags=re.I)
    text = re.sub(r"\bminus\b", "-", text, flags=re.I)
    text = re.sub(r"\bmod(?:ulo)?\b", "%", text, flags=re.I)
    text = re.sub(r"\b(?:index|position)\b", "i", text, flags=re.I)
    text = text.replace("⊕", "^")
    cut = re.split(r"\s+(?:to|and then|then|giving|which)\b", text, maxsplit=1)[0]
    try:
        tree = ast.parse(cut.strip(), mode="eval")
    except SyntaxError:
        return None
    ok_bin = (ast.BitXor, ast.BitAnd, ast.BitOr, ast.Add, ast.Sub, ast.Mult, ast.Mod, ast.LShift, ast.RShift)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Expression, ast.Load)):
            continue
        if isinstance(node, ast.BinOp) and isinstance(node.op, ok_bin):
            continue
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.Invert, ast.USub)):
            continue
        if isinstance(node, (ast.BitXor, ast.BitAnd, ast.BitOr, ast.Add, ast.Sub, ast.Mult, ast.Mod, ast.LShift,
                             ast.RShift, ast.Invert, ast.USub)):
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            continue
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id.lower() in FUNCS \
                and len(node.args) == 2 and not node.keywords:
            continue
        if isinstance(node, ast.Subscript):
            continue
        if isinstance(node, ast.Name) and (node.id in ("byte", "b", "i") or node.id.lower() in FUNCS
                                           or node.id in names):
            continue
        return None
    return tree


def _eval(node, env):
    if isinstance(node, ast.Expression):
        return _eval(node.body, env)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env[node.id]
    if isinstance(node, ast.UnaryOp):
        v = _eval(node.operand, env)
        return (~v) & 0xFF if isinstance(node.op, ast.Invert) else (-v) & 0xFF
    if isinstance(node, ast.BinOp):
        a, b = _eval(node.left, env), _eval(node.right, env)
        op = node.op
        if isinstance(op, ast.BitXor):
            r = a ^ b
        elif isinstance(op, ast.BitAnd):
            r = a & b
        elif isinstance(op, ast.BitOr):
            r = a | b
        elif isinstance(op, ast.Add):
            r = a + b
        elif isinstance(op, ast.Sub):
            r = a - b
        elif isinstance(op, ast.Mult):
            r = a * b
        elif isinstance(op, ast.Mod):
            r = a % b
        elif isinstance(op, ast.LShift):
            r = a << b
        else:
            r = a >> b
        return r & 0xFF if not isinstance(op, ast.Mod) else r
    if isinstance(node, ast.Call):
        x, n = _eval(node.args[0], env), _eval(node.args[1], env)
        if not isinstance(n, int):
            raise ValueError("a rotation count that is not a constant")
        n %= 8
        x = x & 0xFF
        if node.func.id.lower().startswith("ror"):
            return ((x >> n) | (x << (8 - n))) & 0xFF
        return ((x << n) | (x >> (8 - n))) & 0xFF
    if isinstance(node, ast.Subscript):
        base = env[node.value.id] if isinstance(node.value, ast.Name) else None
        idx = _eval(node.slice, env)
        if not isinstance(base, (bytes, bytearray)) or not base:
            raise ValueError("an index into something that is not a key of bytes")
        arr = np.frombuffer(bytes(base), dtype=np.uint8).astype(np.int64)
        return arr[idx % len(base)] if not isinstance(idx, int) else int(base[idx % len(base)])
    raise ValueError(f"an expression node {type(node).__name__}")


def transform(expr: str, region: bytes, fields: dict):
    """The region under the stated byte expression, or None (unparsed, a field it names is missing)."""
    if np is None or len(region) > REGION_MAX:
        return None
    names = set(fields)
    tree = _expr_tree(expr, names)
    if tree is None:
        return None
    env = dict(fields)
    arr = np.frombuffer(region, dtype=np.uint8).astype(np.int64)
    env["byte"] = env["b"] = arr
    env["i"] = np.arange(len(region), dtype=np.int64)
    try:
        out = _eval(tree, env)
    except (KeyError, ValueError, TypeError, ZeroDivisionError, IndexError):
        return None
    if isinstance(out, int):
        return None
    return (np.asarray(out) & 0xFF).astype(np.uint8).tobytes()


def _sniff(data: bytes):
    """The stream a bare 'decompress' meets, by its own header only, or None."""
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:3] == b"BZh" and data[3:4].isdigit():
        return "bz2"
    if data[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(data) >= 2 and (data[0] & 0x0F) == 8 and (data[0] >> 4) <= 7 and ((data[0] << 8) | data[1]) % 31 == 0:
        return "zlib"
    if data[:1] == b"\x5d" and len(data) >= 13 and data[1:5] != b"\x00\x00\x00\x00":
        return "lzma"
    return None


def unstage(op: str, data: bytes):
    """One decoding stage of a stated pipeline: its whole output, at most STAGE_MAX bytes, or None (not that
    stream, a stream that does not end, an output over the bound, an empty output)."""
    if op == "auto":
        op = _sniff(data)
        if op is None:
            return None
    if op == "deflate":                  # 'inflate' / 'deflate' without more: raw deflate, else a zlib header's
        out = unstage("rawdeflate", data)
        if out is None and _sniff(data) == "zlib":
            out = unstage("zlib", data)
        return out
    try:
        if op in ("zlib", "rawdeflate", "gzip"):
            d = zlib.decompressobj({"zlib": 15, "rawdeflate": -15, "gzip": 31}[op])
            out = d.decompress(data, STAGE_MAX + 1)
            if not d.eof or len(out) > STAGE_MAX:
                return None
        elif op in ("lzma", "xz", "bz2"):
            d = bz2.BZ2Decompressor() if op == "bz2" else \
                lzma.LZMADecompressor(lzma.FORMAT_XZ if op == "xz" else lzma.FORMAT_AUTO)
            out = d.decompress(data, max_length=STAGE_MAX + 1)
            if not d.eof or len(out) > STAGE_MAX:
                return None
        elif op == "base64":
            out = base64.b64decode(re.sub(rb"\s+", b"", bytes(data)), validate=True)
        elif op == "hex":
            out = binascii.unhexlify(re.sub(rb"\s+", b"", bytes(data)))
        elif op in ("base32", "base32hex"):
            # RFC 4648, the padding optional: whatever padding stands is dropped and the length's own is put back
            text = re.sub(rb"\s+", b"", bytes(data)).rstrip(b"=")
            text += b"=" * (-len(text) % 8)
            out = (base64.b32decode if op == "base32" else base64.b32hexdecode)(text, casefold=True)
        elif op == "base85":
            out = base64.b85decode(re.sub(rb"\s+", b"", bytes(data)))
        elif op == "ascii85":
            text = re.sub(rb"\s+", b"", bytes(data))
            adobe = text.startswith(b"<~") and text.endswith(b"~>")
            out = base64.a85decode(text, adobe=adobe)
        elif op == "z85":
            out = _z85(re.sub(rb"\s+", b"", bytes(data)))
        elif op == "reverse":
            out = bytes(data[::-1])
        else:
            return None
    except (zlib.error, lzma.LZMAError, OSError, EOFError, ValueError, TypeError, binascii.Error, MemoryError,
            KeyError):
        return None
    return bytes(out) or None


Z85 = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_Z85_INV = {c: i for i, c in enumerate(Z85)}


def _z85(text: bytes) -> bytes:
    """ZeroMQ's Z85 (RFC 32): five characters a four-byte group, big-endian; another length or character raises."""
    if len(text) % 5:
        raise ValueError("a Z85 text is a multiple of 5 characters")
    out = bytearray()
    for k in range(0, len(text), 5):
        v = 0
        for c in text[k:k + 5]:
            v = v * 85 + _Z85_INV[c]
        if v > 0xFFFFFFFF:
            raise ValueError("a Z85 group over 32 bits")
        out += struct.pack(">I", v)
    return bytes(out)


def _rc4(key: bytes, data: bytes) -> bytes:
    try:
        from Cryptodome.Cipher import ARC4
        return ARC4.new(key).encrypt(data)
    except (ImportError, ValueError):
        pass
    S, j = list(range(256)), 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for c in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def _aes(key: bytes, iv, data: bytes, mode: str) -> bytes:
    try:
        from Cryptodome.Cipher import AES
        return (AES.new(key, AES.MODE_CBC, iv) if mode == "CBC" else AES.new(key, AES.MODE_ECB)).decrypt(data)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        d = Cipher(algorithms.AES(key), modes.CBC(iv) if mode == "CBC" else modes.ECB()).decryptor()
        return d.update(data) + d.finalize()


# ---------------------------------------------------------------------------- wave121: the next stated ciphers

def _stream(cipher: str, key: bytes, nonce: bytes, data: bytes):
    """ChaCha20/XChaCha20/Salsa20 keystream decrypt, or None. The library enforces the key and nonce sizes
    (ChaCha20 key 32; Salsa20 key 16/32; nonce 8/12 for ChaCha20, 24 for XChaCha20, 8 for Salsa20, 16 for a
    cryptography-style ChaCha20 counter+nonce), so a wrong size is None, and a wrong value decrypts to bytes whose
    record fails its CRC-32."""
    try:
        if cipher == "salsa20":
            from Cryptodome.Cipher import Salsa20
            return Salsa20.new(key=key, nonce=nonce).decrypt(data)
        if cipher == "xchacha20":
            if len(nonce) != 24:
                return None
            from Cryptodome.Cipher import ChaCha20
            return ChaCha20.new(key=key, nonce=nonce).decrypt(data)
        # chacha20
        if len(nonce) == 16:
            # the full 128-bit counter+nonce form of pyca/cryptography (Cryptodome takes only 8/12/24)
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
            d = Cipher(algorithms.ChaCha20(key, nonce), mode=None).decryptor()
            return d.update(data) + d.finalize()
        from Cryptodome.Cipher import ChaCha20
        return ChaCha20.new(key=key, nonce=nonce).decrypt(data)
    except (ValueError, TypeError):
        return None


_TEA_DELTA = 0x9E3779B9
_U32 = 0xFFFFFFFF


def _xtea_block(v0: int, v1: int, kw, rounds: int = 32):
    """One 64-bit XTEA block deciphered (the Needham-Wheeler reference, `rounds` cycles)."""
    s = (_TEA_DELTA * rounds) & _U32
    for _ in range(rounds):
        v1 = (v1 - (((((v0 << 4) & _U32) ^ (v0 >> 5)) + v0) ^ (s + kw[(s >> 11) & 3]))) & _U32
        s = (s - _TEA_DELTA) & _U32
        v0 = (v0 - (((((v1 << 4) & _U32) ^ (v1 >> 5)) + v1) ^ (s + kw[s & 3]))) & _U32
    return v0, v1


def _xxtea_decrypt(v, kw):
    """The whole-message Corrected Block TEA (btea decode, n>=2 words) in place over `v`."""
    n = len(v)
    rounds = 6 + 52 // n
    s = (rounds * _TEA_DELTA) & _U32
    y = v[0]
    while rounds > 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            mx = ((((z >> 5) ^ ((y << 2) & _U32)) + ((y >> 3) ^ ((z << 4) & _U32)))
                  ^ (((s ^ y) & _U32) + ((kw[(p & 3) ^ e] ^ z) & _U32))) & _U32
            v[p] = (v[p] - mx) & _U32
            y = v[p]
        z = v[n - 1]
        mx = ((((z >> 5) ^ ((y << 2) & _U32)) + ((y >> 3) ^ ((z << 4) & _U32)))
              ^ (((s ^ y) & _U32) + ((kw[e] ^ z) & _U32))) & _U32
        v[0] = (v[0] - mx) & _U32
        y = v[0]
        s = (s - _TEA_DELTA) & _U32
        rounds -= 1
    return v


def _tea(cipher: str, mode, endian: str, key: bytes, iv, data: bytes):
    """XTEA (64-bit ECB/CBC) or XXTEA (whole message), 128-bit key, words in `endian` ('be'/'le'), or None when the
    key is not 16 bytes, the data is not whole 32-bit words (and for XTEA whole 64-bit blocks), or there are too
    few words for XXTEA. A wrong key/endianness/variant decrypts to bytes whose record fails its CRC-32."""
    try:
        if len(key) != 16 or not data or len(data) % 4:
            return None
        bo = ">" if endian == "be" else "<"
        kw = list(struct.unpack(bo + "4I", key))
        words = list(struct.unpack(bo + f"{len(data) // 4}I", data))
        if cipher == "xxtea":
            if len(words) < 2:
                return None
            out = _xxtea_decrypt(words, kw)
            return struct.pack(bo + f"{len(out)}I", *out)
        if len(data) % 8:
            return None              # XTEA blocks are 64 bits
        prev = struct.unpack(bo + "2I", iv) if (mode == "CBC" and iv) else None
        out = []
        for i in range(0, len(words), 2):
            c0, c1 = words[i], words[i + 1]
            d0, d1 = _xtea_block(c0, c1, kw)
            if mode == "CBC":
                if prev is None:
                    return None
                d0 ^= prev[0]
                d1 ^= prev[1]
                prev = (c0, c1)
            out.extend((d0 & _U32, d1 & _U32))
        return struct.pack(bo + f"{len(out)}I", *out)
    except (ValueError, TypeError, struct.error):
        return None


def decrypt(st: dict, data: bytes, env: dict):
    """One stated cipher stage: RC4, AES-128/192/256 in CBC or ECB (the Day 21 final prep), or wave121's stream
    (ChaCha20/XChaCha20/Salsa20, with a stated nonce field) and block (XTEA/XXTEA) ciphers, under the key the stage
    names (a stated byte field of the header, or the text's quoted literal) and, for CBC, the stated IV field. None
    when a key, nonce or IV is not bytes of the right size, the data is not whole blocks, or a stated PKCS#7 padding
    does not check."""
    how, key = st["key"]
    if how == "field":
        key = env.get(key)
    if not isinstance(key, (bytes, bytearray)) or not 1 <= len(key) <= 256:
        return None
    key = bytes(key)
    op = st["op"]
    try:
        if op == "rc4":
            return _rc4(key, bytes(data)) or None
        if op == "stream":
            nonce = env.get(st["nonce"])
            if not isinstance(nonce, (bytes, bytearray)):
                return None
            return _stream(st["cipher"], key, bytes(nonce), bytes(data)) or None
        if op == "tea":
            iv = None
            if st.get("mode") == "CBC":
                iv = env.get(st["iv"])
                if not isinstance(iv, (bytes, bytearray)) or len(iv) != 8:
                    return None
                iv = bytes(iv)
            out = _tea(st["cipher"], st.get("mode"), st["endian"], key, iv, bytes(data))
            if out is None:
                return None
        else:                            # aes
            if len(key) != st["bits"] // 8 or not data or len(data) % 16:
                return None
            iv = None
            if st["mode"] == "CBC":
                iv = env.get(st["iv"])
                if not isinstance(iv, (bytes, bytearray)) or len(iv) != 16:
                    return None
                iv = bytes(iv)
            out = _aes(key, iv, bytes(data), st["mode"])
    except (ValueError, TypeError, KeyError):
        return None
    if st.get("pad"):
        bs = st.get("block", 16)
        n = out[-1] if out else 0
        if not 1 <= n <= bs or len(out) < n or out[-n:] != bytes([n]) * n:
            return None
        out = out[:-n]
    return out or None


def _pipeline(spec: dict, regions: dict, env: dict):
    """(every stage's output in order, the region the first stage read) or (None, ...): any stage that fails,
    an output over STAGE_MAX, the whole over PIPE_TIME, a first source that names no region (with more than one)."""
    pipe = spec["pipeline"]
    src = pipe[0].get("src")
    name = next((k for k in regions if _same(k, src)), None) if src else None
    if name is None:
        if len(regions) != 1:
            return None, None
        name = next(iter(regions))
    data, outs, t0 = regions[name][1], [], time.perf_counter()
    for st in pipe:
        if time.perf_counter() - t0 > PIPE_TIME:
            return None, name
        data = transform(st["expr"], data, env) if st["op"] == "map" else \
            decrypt(st, data, env) if st["op"] in ("rc4", "aes", "stream", "tea") else unstage(st["op"], data)
        if not data or len(data) > STAGE_MAX:
            return None, name
        outs.append(data)
    return outs, name


def _other_record(body: bytes, cfg: dict, off: int) -> bool:
    """True when the pipeline's output holds a second CRC-valid HCFG record with other JSON than the stated one."""
    at, seen = -1, 0
    while seen < MAX_HITS:
        at = body.find(b"HCFG", at + 1)
        if at < 0:
            return False
        seen += 1
        if at == off:
            continue
        rec = _record(body[at:])
        if rec is not None and rec["json"] != cfg["json"]:
            return True
    return False


# ---------------------------------------------------------------------------- reading a member

def _same(a: str, b: str) -> bool:
    wa, wb = _words(a), _words(b)
    return bool(wa) and (wa == wb or (len(wa) == 1 and wa[0] in wb and len(wb) <= 2)
                         or (len(wb) == 1 and wb[0] in wa and len(wa) <= 2))


def _length_of(spec, region: str, ints: dict):
    """The value of the stated length field of `region` ('scratch length' for 'scratch'), or None."""
    target = _words(region)
    for name, value in ints.items():
        w = _words(name)
        if w and w[-1] == "length" and (w[:-1] == target or (target and w[:-1] and
                                                              (set(w[:-1]) <= set(target) or set(target) <= set(w[:-1])))):
            return value
    return None


def _digest(algo: str, data: bytes) -> bytes:
    if algo == "crc32":
        return struct.pack("<I", zlib.crc32(data) & 0xFFFFFFFF)
    return hashlib.new(algo, data).digest()


def _at(data: bytes, at: int, spec: dict):
    """The overlay read at `at` under `spec`, every stated check carried out, or None."""
    ints, raw = {}, {}
    for name, (off, typ) in spec["ints"].items():
        fmt, n = TYPES.get(typ, (None, 0))
        if fmt is None or at + off + n > len(data):
            return None
        ints[name] = struct.unpack_from(fmt, data, at + off)[0]
    for name, (off, n) in spec["bytes"].items():
        if at + off + n > len(data):
            return None
        raw[name] = data[at + off:at + off + n]
    regions, header_end = {}, 0
    for name in spec["order"]:
        r = spec["regions"][name]
        if r["at"] is not None:
            start = r["at"]
        else:
            prev = next((k for k in regions if _same(k, r["after"])), None)
            if prev is None:
                return None
            start = regions[prev][0] + len(regions[prev][1])
        length = _length_of(spec, name, ints)
        if length is None:
            # a region whose length the text does not state runs to the next region or the member's end
            nxt = [spec["regions"][o]["at"] for o in spec["order"] if spec["regions"][o]["at"] is not None
                   and spec["regions"][o]["at"] > start]
            length = (min(nxt) - start) if nxt else len(data) - at - start
        if length < 0 or length > REGION_MAX or at + start + length > len(data):
            return None
        regions[name] = (start, data[at + start:at + start + length])
    end = max([s + len(b) for s, b in regions.values()] + [0])
    for d in spec["digests"]:
        header_end = max(header_end, d["at"] + d["n"])
    for _, (off, typ) in spec["ints"].items():
        header_end = max(header_end, off + TYPES[typ][1])
    if spec["end_exact"] and at + end != len(data):
        return None
    derived, outs, pipe_src = {}, [], None
    if spec.get("pipeline"):
        env = {k.replace(" ", "_"): v for k, v in ints.items()}
        env.update({k.replace(" ", "_"): v for k, v in raw.items()})
        outs, pipe_src = _pipeline(spec, regions, env)
        if not outs:
            return None
        derived["unpacked"] = outs[-1]
    elif spec["transform"]:
        src = next((k for k in regions if _same(k, spec["transform"]["src"])), None)
        if src is None:
            return None
        env = {k.replace(" ", "_"): v for k, v in ints.items()}
        env.update({k.replace(" ", "_"): v for k, v in raw.items()})
        out = transform(spec["transform"]["expr"], regions[src][1], env)
        if out is None:
            return None
        derived["unpacked"] = out
    verified = []
    for d in spec["digests"]:
        stored = data[at + d["at"]:at + d["at"] + d["n"]]
        if d["algo"] == "crc32" and d.get("type") == "u32be":
            stored = stored[::-1]
        body = None
        name = next((k for k in regions if _same(k, d["of"])), None)
        if name is None and outs:
            # a digest of no region names a stage's output ('the unpacked SHA-256'): it must equal one of them
            if not any(_digest(d["algo"], o) == stored for o in outs):
                return None
            verified.append(f"{d['algo']}({d['of']})")
            continue
        if name is not None:
            body = regions[name][1]
        elif derived and (_same("unpacked", d["of"]) or _same(spec["transform"]["src"], d["of"]) is False):
            body = derived.get("unpacked")
        if body is None or _digest(d["algo"], body) != stored:
            return None
        verified.append(f"{d['algo']}({d['of']})")
    cfg = None
    use = spec["use"]
    if outs:
        # row 423: the record is taken ONLY from the pipeline's output (or a region other than its source the text
        # names), at the stated offset (0 when none is stated), CRC-valid, and with no second CRC-valid record of
        # other JSON in that output
        where = (use["region"] or use["what"]) if use else None
        name = next((k for k in regions if _same(k, where)), None) if where else None
        body = regions[name][1] if name is not None and name != pipe_src else outs[-1]
        off = use["off"] if use else 0
        cfg = _record(body[off:])
        if cfg is None or _other_record(body, cfg, off):
            return None
        verified.append("pipeline(" + ">".join(st["op"] for st in spec["pipeline"]) + ")")
    elif use:
        body = None
        where = use["region"] or use["what"]
        name = next((k for k in regions if _same(k, where)), None)
        if name is not None:
            body = regions[name][1]
        elif derived:
            body = derived["unpacked"]
        if body is None:
            return None
        cfg = _record(body[use["off"]:])
        if cfg is None:
            return None
    return {"offset": at, "ints": ints, "bytes": raw, "regions": {k: (s, len(b), b) for k, (s, b) in regions.items()},
            "end": at + end, "member_length": len(data), "verified": verified, "config": cfg,
            "end_exact": spec["end_exact"], "header_end": header_end}


def _record(body: bytes):
    """The HCFG record at the start of `body` in the lane's layout, CRC-valid with a JSON object, or None."""
    if len(body) < 12 or body[:4] != b"HCFG":
        return None
    version, key = body[4], body[5]
    length, crc = struct.unpack_from("<HI", body, 6)
    if 12 + length > len(body):
        return None
    plain = bytes(b ^ key for b in body[12:12 + length])
    if zlib.crc32(plain) & 0xFFFFFFFF != crc:
        return None
    try:
        import json
        obj = json.loads(plain.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    return {"offset": 0, "version": version, "key": key, "crc32": crc, "crc_ok": True, "json": obj, "plain": plain,
            "how": "xor", "length": 12 + length}


_CACHE = {}


def read(members: list, spec: dict):
    """The verified final overlay of `spec`'s magic in the prefix's members [(name, bytes)], as
    {'member', ...the fields of _at...}, or None."""
    if not spec or not members:
        return None
    magic = spec["magic"].encode()
    # `read` searches the complete member for the final stated magic.  A tail-only digest let two
    # equal-length members with identical final 4096 bytes reuse a result even when an earlier overlay
    # existed in only one.  Keep the bounded cache, but scope it to every exact member byte.
    key = (spec["magic"], _canon(spec),
           tuple((n, len(b), hashlib.sha256(bytes(b)).digest()) for n, b in members))
    if key in _CACHE:
        return _CACHE[key]
    found = None
    for name, data in reversed(members):
        data = bytes(data)
        hits, at = [], len(data)
        while len(hits) < MAX_HITS:
            at = data.rfind(magic, 0, at)
            if at < 0:
                break
            hits.append(at)
        for k, at in enumerate(hits):
            got = _at(data, at, spec)
            if got is None:
                continue
            # an earlier occurrence stands only when every later one lies inside its own span (payload bytes)
            if all(at < later < got["end"] for later in hits[:k]):
                found = dict(got, member=name)
            break
        if hits:
            break                    # the final member that holds the magic decides
    if len(_CACHE) > 64:
        _CACHE.clear()
    _CACHE[key] = found
    return found


# ---------------------------------------------------------------------------- answers

def _field(qid: str) -> str:
    return re.sub(r"^set\d+\.", "", qid).split("_", 1)[-1]


def _values(n: int, fmt, method: str) -> list:
    """[(name, value)] of the number in the form its question asks: base 10, or hexadecimal as the syntax states it
    (answer_kinds reads the syntax: prefix, case), both widths. The NAME is the reading (`magic_offset`,
    `field:hcfg_resource_length`, ...) with the form after a colon: what the judge accepts for a key is that
    reading, so another reading of the same key on a later day is never answered plain under it."""
    import answer_kinds
    kind = answer_kinds.kind_of(fmt)
    if kind == "integer":
        return [(method, str(n))]
    form = answer_kinds.hex_form(fmt) if kind == "pattern" else None
    if answer_kinds.wants_hex(fmt) or form is not None:
        prefix, upper = form if form is not None else (True, False)
        digits = [f"{n:x}", f"{n:08x}"]
        if upper:
            digits = [d.upper() for d in digits]
        pre = "" if prefix is False else "0x"
        return [(f"{method}:hex", pre + digits[0]), (f"{method}:hex8", pre + digits[1])]
    return [(method, str(n))]


def _pick(field: str, options):
    import labels
    tail = re.sub(r"^analysis_", "", field)
    return labels.pick(f"binary.stated_layout/{tail}", options)


def structural(field: str, q: dict, got: dict, fmt):
    """An unsure answer for a structural field of the read overlay, or None."""
    text = (q.get("question") or "")
    tail = re.sub(r"^analysis_", "", field)
    words = _words(tail.replace("_", " "))
    nounw = set(_words(got.get("noun", "")))
    # the magic's offset: "<noun|overlay|magic>_offset", or a text asking the magic's zero-based offset
    if words and words[-1] == "offset" and (set(words[:-1]) & ({"overlay", "magic", "wrapper", "trailer"} | nounw)
                                            or re.search(r"magic\b.*\boffset", text, re.I)):
        if not any(_same(r, " ".join(words[:-1])) for r in got["regions"]):
            return _pick(field, _values(got["offset"], fmt, "magic_offset"))
    # the magic itself, and where the overlay ends
    if tail in ("overlay_magic", "magic", f"{_snake(got.get('noun', ''))}_magic"):
        return _pick(field, [("stated_magic", got["magic"])])
    if words in (("overlay", "end"), ("overlay", "end", "offset")) and got["end_exact"]:
        return _pick(field, _values(got["end"], fmt, "overlay_end"))
    # the member length minus the magic's offset
    if re.search(r"member (?:byte )?length minus the (?:located )?(?:overlay )?magic", text, re.I) or (
            words in (("overlay", "length"),) and got["end_exact"]):
        return _pick(field, _values(got["member_length"] - got["offset"], fmt, "length_from_magic"))
    # a header field the text names: by the question's own "<name> field", then by the id's words
    named = re.search(r"read the (?:little-endian |big-endian )?(?P<name>[A-Za-z0-9 _-]+?) field", text, re.I)
    for want in ([named.group("name")] if named else []) + [tail.replace("_", " ")]:
        hits = [n for n in got["ints"] if _words(n) == _words(want)]
        if not hits:
            # one name the other's words hold whole ("payload length" for "HCFG payload size"), only when one
            # field of the header fits so, and never a lone size word
            hits = [n for n in got["ints"] if len(_words(n)) > 1 and len(_words(want)) > 1 and
                    (set(_words(n)) < set(_words(want)) or set(_words(want)) < set(_words(n)))]
        if len(hits) == 1:
            return _pick(field, _values(got["ints"][hits[0]], fmt, f"field:{_snake(hits[0])}"))
    # a region's start, length or digest
    if words and words[-1] in ("offset", "length") and len(words) > 1:
        base = " ".join(words[:-1])
        hits = [r for r in got["regions"] if _same(r, base)]
        if len(hits) == 1:
            start, length, _ = got["regions"][hits[0]]
            slug = _snake(hits[0])
            if words[-1] == "length":
                return _pick(field, _values(length, fmt, f"region_length:{slug}"))
            return _pick(field, _values(got["offset"] + start, fmt, f"region_start:{slug}") +
                         _values(start, fmt, f"region_start_in_overlay:{slug}"))
    m = re.fullmatch(r"(.+?)_(sha512|sha384|sha256|sha224|sha1|md5|crc32)(?:_hex)?", tail)
    if m:
        hits = [r for r in got["regions"] if _same(r, m.group(1).replace("_", " "))]
        if len(hits) == 1:
            body = got["regions"][hits[0]][2]
            dg = _digest(m.group(2), body)
            value = (f"0x{struct.unpack('<I', dg)[0]:08x}" if m.group(2) == "crc32" else dg.hex())
            return _pick(field, [(f"{m.group(2)}_of:{_snake(hits[0])}", value)])
    return None


CONFIG = re.compile(r"analysis_(?:config_.+|xor_key_hex|hcfg_version)")


def _config_answer(gen, field, cfg, fmt):
    if field == "analysis_hcfg_version":
        return gen.hcfg_header_answer(field, cfg, fmt)[0]
    return gen.config_answer(field, cfg, lambda: set(cfg["json"]), "", fmt)[0]


def answers(prefix: str, qs: list, got: dict, members: list, gen, log=None) -> dict:
    """{qid: new answer} for the prefix's ids this reader settles (see the module docstring). {} when no
    question of the prefix states a wrapper, or the wrapper does not verify."""
    log = log or (lambda line: print(line, file=sys.stderr))
    spec = spec_of(qs)
    if spec is None:
        return {}
    ov = read(members, spec)
    if ov is None:
        pipe = (" through the stated pipeline " + ">".join(st["op"] for st in spec["pipeline"]) + " (row 423)") \
            if spec.get("pipeline") else ""
        log(f"[stated] {prefix}: the questions state a final {spec['magic']} {spec['noun']}, and no occurrence in "
            f"the prefix's members verifies as stated{pipe}; nothing is answered from it")
        return {}
    ov = dict(ov, noun=spec["noun"], magic=spec["magic"])
    out = {}
    day = re.fullmatch(r"d0*(\d+)", prefix)
    cfg = ov.get("config")
    for q in qs:
        qid = q.get("qid") or q.get("id")
        field = _field(qid)
        fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else None
        have = got.get(qid)
        try:
            if cfg is not None and CONFIG.fullmatch(field):
                mine = _config_answer(gen, field, cfg, fmt)
                if mine is None or have == mine:
                    continue
                if have is None:
                    camp = cfg["json"].get("campaign")
                    names_day = bool(day) and isinstance(camp, str) and camp.startswith(f"BR{int(day.group(1)):02d}-")
                    if names_day or gen.labels.is_unsure(mine):
                        out[qid] = mine
                    else:
                        out[qid] = _pick("config", [("stated", mine)])
                elif isinstance(have, str) and not gen.labels.is_unsure(have) and not gen.labels.is_unsure(mine):
                    out[qid] = _pick("config", [("stated", mine), ("walk", have)])
                    log(f"NOTE [stated] {qid}: the {spec['magic']} {spec['noun']} the text names holds {mine!r}, "
                        f"the record the walk read holds {have!r}: unsure, the stated record first")
                continue
            # a structural id still None, or answered only unsure by a reader that does not know the wrapper
            # (the catalog's `hcfg_payload_size` is the HCFG record's payload) when its own question names it
            names_it = re.search(rf"\b{re.escape(spec['magic'])}\b", q.get("question") or "")
            if have is None or (names_it and gen.labels.is_unsure(have)):
                value = structural(field, q, ov, fmt)
                if value is not None and value != have:
                    out[qid] = value
        except Exception as e:      # one field's failure costs that field
            log(f"[stated] {qid}: raised {type(e).__name__}: {e}")
    if out:
        log(f"[stated] {prefix}: final {spec['magic']} {spec['noun']} at {ov['offset']} in {ov['member']} "
            f"(checks {', '.join(ov['verified']) or 'none stated'}{', end bound' if ov['end_exact'] else ''}) "
            f"answers {len(out)} id(s): {', '.join(sorted(out))}")
    return out
