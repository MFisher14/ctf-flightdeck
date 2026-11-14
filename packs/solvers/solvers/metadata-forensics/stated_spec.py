#!/usr/bin/env python3
"""The Day 21 build, round 3 (item 3): a question's STATED spec, read the way Binary's stated_layout.py reads a wrapper.

A Metadata question names a property (`Determine pe.coff_machine_u16_hex for x.exe.`) and an answer format whose
`syntax` text often says more than the property's name: the form (`lowercase hexadecimal with a 0x prefix`, `exact 32
hexadecimal characters ... no 0x prefix`), and on a day that brings a new name it may say the whole of it (`a compact
JSON array of 0x-prefixed 8-digit lowercase hex values, each once, in ascending order`; `the little-endian u32 at
offset 0x3c`). Day 20's `macho.cpu_type_set` was such a name: the reader was there, the form was not judged, and it
cost a STOP and four candidates. This module turns those sentences into a spec (`spec_of`) and the solver's answer
into one that follows it (`revise`), never inventing a fact: the fact still comes from a reader or from the bytes at
the stated place.

What a spec holds (each only when the text states it, and only when it states one value of it):

  hex       the text speaks of hexadecimal
  prefix    True for `0x-prefixed`, `with a 0x prefix`, `prefixed with 0x`, `leading 0x`; False for `no/without (0x|prefix)`
  case      lower / upper (`lowercase`, `uppercase`); `any` for `letter case is ignored`, `case-insensitive`
  digits    the hex digits of a number: `8-digit`, `8 hex digits`, `zero-padded to 8 digits`, `padded to 32 bits`
  order     ascending / descending (of the values themselves: `ascending order`, `sorted ascending`, `smallest first`;
            never `ascending digest order`, which orders by something else), or file (`in file order`)
  unique    `unique`, `distinct`, `each once`, `deduplicated`, `without duplicates`
  endian    little / big
  place     a field at a stated offset: `<u8|u16le|u32be|i32le|...> at offset N`, `the little-endian 32-bit unsigned
            integer at offset N`, `at offset N as a u16le`, or bytes: `N bytes at offset M`, `bytes A..B` (inclusive)
  mask      a bit mask over an integer: `masked with 0xNN`, `& 0xNN`, `the low N bits`, `the high N bits of a 32-bit
            value`, `bits A..B` (inclusive). Narrows the value read at a stated place; never applied without a place.
  encoding  a text encoding of a byte range: `utf-8`, `utf-16le`/`utf-16be`/`utf-16`, `utf-32...`, `ascii`,
            `latin-1`/`iso-8859-1`, `windows-1252`. Decodes the bytes at a stated byte range to text.
  base      (B-248) the structure a place's offset counts from, tied to that offset in words: `offset N of/in/into/
            relative to the start of the PE header | COFF/file header | optional header | overlay | program header
            table | section header table | <.name> section | section `<name>``. Its start and length come from the
            file's own size fields (e_lfanew, SizeOfOptionalHeader, a section's PointerToRawData/SizeOfRawData, an
            ELF section's sh_offset/sh_size); a place past the structure's end reads nothing.
  member    (B-248) the archive member a place is read in: `member <name>`, `zip/tar/ar member <name>`, `archive
            entry <name>`, `<name> member` (quoted, or a filename with an extension; a path goes through members
            that are archives). Read out of a zip, tar or ar target; the target already being that member is used
            as it is. Two members, or two structures, stated: nothing is read.

The Day 21 build, round 3 (the mask and encoding gaps): both read only from the value at a STATED place, so the
fact always comes from the bytes and the mask or encoding only from the words. Every form stays UNSURE; nothing
is ever made plain from a word of the text.

What `revise(q, answer, target)` does with it (called by properties_strict.answer_question last, before the
row-280 form check, which keeps its own words: no 0x, uppercase, braces, no hyphens):

  plain     a PLAIN answer whose form the spec certainly contradicts (a 0x number with too few digits, uppercase
            letters under `lowercase`, a hex number with letters and no 0x under `0x-prefixed`, a JSON array whose
            hex elements are so, which repeats a value under `unique`, or whose numbers are out of the stated order)
            becomes `labels.pick('metadata.stated/<property>+<words>', [('as_stated', fit), ('as_judged', answer)])`:
            the stated form first, the judged one second. The judge's word wins only once it is given (the key's
            accepted name answers the next variant plain). Nothing is ever made plain from a word of the text.
  unsure    the options that already fit every stated check are moved first (their order kept); when none fits and
            the first option can be re-written to fit, that form is offered first as `<name>+stated`.
  None      a question that states a place: the field is read from the target file at that place, under the
            stated type and byte order, and offered as a pick under `metadata.stated/<property>+<type>` in the
            stated form (`stated_place:decimal`, `stated_place:hex_padded`, `stated_place:hex_min`, ...). A place
            past the file's end, a multi-byte type with no byte order stated, two places stated: nothing.
  place vs a plain reader: a PLAIN number that differs from the value at the stated place becomes a candidate pick
            (row 346; the stated place first, `reader` last): two readings, nothing proves which is asked.

Every line it prints starts `STATED <id>: ` (the day-review marker `metadata-stated-spec`). A spec costs one
memoised regular-expression pass per (question text, syntax text); a question whose text and syntax hold none of
its trigger words costs one search.
"""
import functools
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "common"))
import labels  # noqa: E402

KEY = "metadata.stated/"
TEXT_LIMIT = 2000          # characters of a question's text read for a spec (the syntax text: 600)
MAX_PLACE = 1 << 26        # the farthest offset a stated place may name
MAX_BYTES = 64             # the most bytes a stated byte range may name

TRIGGER = re.compile(r"hex|0x|case|digit|padded|order|ascending|descending|sorted|smallest|largest|unique|distinct|"
                     r"once|duplicat|endian|offset|\bu(?:int)?(?:8|16|32|64)|\bi(?:nt)?(?:8|16|32|64)|bytes\s+\+?\d|"
                     r"mask|bitmask|logical\s+and|&\s*0x|utf-?(?:8|16|32)|\bascii\b|latin-?1|iso-8859|"
                     r"windows-12\d\d|cp-?12\d\d|\b(?:low(?:est)?|bottom|least\s+significant|high(?:est)?|top|most\s+"
                     r"significant)\s+\d+\s+bits?\b|\bbits?\s+\d+\s*(?:\.\.|-|to|through)\s*\d+\b",
                     re.I)

_NO_0X = re.compile(r"\b(?:no|without)\s+(?:an?\s+|the\s+|any\s+)?(?:leading\s+)?(?:`?0x`?|prefix)\b|\bunprefixed\b")
_WITH_0X = re.compile(r"(?<![\w`])`?0x`?[- ]?prefix(?:ed)?\b|\bwith\s+(?:a|an|the)\s+(?:leading\s+)?`?0x`?(?:\s+prefix)?\b"
                      r"|\bprefixed\s+(?:with|by)\s+`?0x`?|\bleading\s+`?0x`?(?!\w)|\bstart(?:s|ing)?\s+with\s+`?0x`?(?!\w)")
_LOWER = re.compile(r"\blower[- ]?case\b")
_UPPER = re.compile(r"\bupper[- ]?case\b")
_ANYCASE = re.compile(r"\b(?:letter\s+)?case\s+(?:is\s+)?(?:ignored|insensitive|does\s+not\s+matter)\b|\bcase[- ]insensitive\b"
                      r"|\b(?:either|any)\s+(?:letter\s+)?case\b")
_HEX = re.compile(r"\bhex(?:adecimal)?\b|\b0x")
_DIGITS = (re.compile(r"\b(\d{1,2})[- ](?:hex(?:adecimal)?[- ])?digits?\b"),
           re.compile(r"\b(\d{1,2})\s+(?:lower[- ]?case\s+|upper[- ]?case\s+)?hex(?:adecimal)?\s+(?:digits?|characters?|chars?)\b"),
           re.compile(r"\b(?:zero[- ]?)?padded\s+to\s+(\d{1,2})\s+(?:hex(?:adecimal)?\s+)?(?:digits?|characters?|chars?)\b"))
_BITS = (re.compile(r"\b(?:zero[- ]?padded|padded|full[- ]width|fixed[- ]width)\b[^.;]{0,40}?\b(8|16|32|64)[- ]bits?\b"),
         re.compile(r"\b(8|16|32|64)[- ]bits?\b[^.;]{0,40}?\b(?:zero[- ]?padded|padded|full[- ]width|fixed[- ]width)\b"))
_ASC = re.compile(r"\bascending(?:\s+(?:numeric(?:al)?|lexicographic(?:al)?|alphabetical))?\s+order\b(?!\s+of\b)"
                  r"|\bsorted(?:\s+in)?\s+ascending(?:\s+order)?\b(?!\s+(?:by|of)\b)|\bsorted\s+(?:numerically|smallest\s+first)\b"
                  r"|\bsmallest\s+(?:value\s+)?first\b|\blowest\s+(?:value\s+)?first\b|\bin\s+increasing\s+order\b")
_DESC = re.compile(r"\bdescending(?:\s+(?:numeric(?:al)?|lexicographic(?:al)?|alphabetical))?\s+order\b(?!\s+of\b)"
                   r"|\bsorted(?:\s+in)?\s+descending(?:\s+order)?\b(?!\s+(?:by|of)\b)|\blargest\s+(?:value\s+)?first\b"
                   r"|\bhighest\s+(?:value\s+)?first\b|\bin\s+decreasing\s+order\b")
_FILE_ORDER = re.compile(r"\b(?:in\s+)?(?:file|stored|on-disk|header|table)\s+order\b|\bin\s+(?:the\s+)?order\s+(?:they\s+)?"
                         r"(?:appear|are\s+stored|are\s+listed)\b|\border\s+of\s+appearance\b")
_ALPHA = re.compile(r"\b(?:lexicographic(?:al)?|alphabetical)(?:ly)?\b")
_UNIQUE = re.compile(r"\b(?:unique|distinct|deduplicated|de-duplicated|without\s+duplicates|no\s+duplicates?)\b"
                     r"|\beach\s+(?:\w+\s+)?(?:only\s+)?once\b")
_LITTLE = re.compile(r"\blittle[- ]endian\b")
_BIG = re.compile(r"\bbig[- ]endian\b")
_ARRAY = re.compile(r"\bjson\s+(?:array|list)\b|\barray\b")

# The Day 21 build, round 3 gaps: a stated bit mask over an integer, and a stated text encoding of a byte
# range. Both are read only from the value at a STATED place (never a guess, never a plain answer): the value
# comes from the bytes, the mask or the encoding comes from the words, and every form is offered unsure.
_MASK_HEX = re.compile(r"(?:mask(?:ed)?(?:\s+(?:with|by|of|to))?|bit-?mask(?:\s+(?:with|by|of))?|"
                       r"logical\s+and(?:\s+with)?|&)\s*(0x[0-9a-f]+|\d+)", re.I)
_LOW_BITS = re.compile(r"\b(?:low(?:est)?|bottom|least\s+significant)\s+(\d{1,2})\s+bits?\b", re.I)
_HIGH_BITS = re.compile(r"\b(?:high(?:est)?|top|most\s+significant)\s+(\d{1,2})\s+bits?\s+of\s+(?:an?\s+)?"
                        r"(8|16|32|64)[- ]bit\b", re.I)
_BITS_RANGE = re.compile(r"\bbits?\s+(\d{1,2})\s*(?:\.\.|-|to|through)\s*(\d{1,2})\b", re.I)
# (regex, python codec name). Specific endianness before the bare family, so `utf-16le` resolves to -le.
_ENCODINGS = (
    (re.compile(r"\butf-?16-?le\b|\butf-?16\s+little[- ]endian\b", re.I), "utf-16-le"),
    (re.compile(r"\butf-?16-?be\b|\butf-?16\s+big[- ]endian\b", re.I), "utf-16-be"),
    (re.compile(r"\butf-?16\b", re.I), "utf-16"),
    (re.compile(r"\butf-?32-?le\b", re.I), "utf-32-le"),
    (re.compile(r"\butf-?32-?be\b", re.I), "utf-32-be"),
    (re.compile(r"\butf-?32\b", re.I), "utf-32"),
    (re.compile(r"\butf-?8\b", re.I), "utf-8"),
    (re.compile(r"\bascii\b", re.I), "ascii"),
    (re.compile(r"\b(?:latin-?1|iso-8859-1)\b", re.I), "latin-1"),
    (re.compile(r"\b(?:windows-12\d\d|cp-?12\d\d)\b", re.I), "windows-1252"),
)
_ENC_FAMILIES = (("utf-16", "utf-16-le", "utf-16-be"), ("utf-32", "utf-32-le", "utf-32-be"))

NUM = r"\+?(0x[0-9a-f]+|\d+)"
# wave70: the Windows type words dword/qword/word are unambiguous and little-endian by convention (a DWORD is a
# 32-bit little-endian value); a stated byte order still overrides. `byte` is deliberately left out (it collides
# with ordinary English). Every value read at a stated place is UNSURE, never plain, so these never guess a name.
TYPE = (r"(u8|u16|u32|u64|i8|i16|i32|i64|uint8|uint16|uint32|uint64|int8|int16|int32|int64|dword|qword|word)"
        r"(le|be|_le|_be)?")
_WINWORD = {"word": 2, "dword": 4, "qword": 8}
_PLACES = (
    # <type> at offset N
    re.compile(r"\b" + TYPE + r"\b(?:\s+(?:value|field|word|integer|number))?\s+(?:stored\s+)?(?:at|from)\s+"
               r"(?:file\s+|byte\s+)?(?:offset\s+|position\s+)?" + NUM + r"\b"),
    # the little-endian 32-bit unsigned integer at offset N
    re.compile(r"\b((?:(?:little|big)[- ]endian\s+|(?:unsigned|signed)\s+){0,2})(8|16|32|64)[- ]bit\s+"
               r"((?:(?:little|big)[- ]endian\s+|(?:unsigned|signed)\s+){0,2})(?:integer|value|field|word|number)\s+"
               r"(?:stored\s+)?(?:at|from)\s+(?:file\s+|byte\s+)?(?:offset\s+|position\s+)?" + NUM + r"\b"),
    # at offset N, (read) as a u16le / as a little-endian 32-bit integer
    re.compile(r"\bat\s+(?:file\s+|byte\s+)?offset\s+" + NUM + r"\b[^.;]{0,40}?\bas\s+(?:an?\s+)?(?:(little|big)[- ]endian\s+)?"
               r"(?:" + TYPE + r"\b|(?:(unsigned|signed)\s+)?(8|16|32|64)[- ]bit\b)"),
)
_BYTES_AT = re.compile(r"\b(\d{1,3})\s+bytes\s+(?:starting\s+)?(?:at|from)\s+(?:file\s+)?(?:offset\s+)?" + NUM + r"\b")
_BYTE_RANGE = re.compile(r"\bbytes\s+" + NUM + r"\s*(?:\.\.|to|through)\s*" + NUM + r"\b")

# B-248: a place inside a STRUCTURE named in words, and a place inside an ARCHIVE MEMBER. A structure is read only
# when its words are tied to the stated offset (`offset 0x10 of the optional header`, `offset 4 into the .text
# section`, `offset 8 relative to the start of the PE header`), and its own size fields say where it starts and how
# long it is: a place past its end reads nothing. A member is named with the word `member` (or `archive entry`),
# its name quoted or a filename with an extension, and is read out of a zip, tar or ar target (a path names a member
# of a member). Two structures or two members stated: nothing is read. The key carries the structure or `member`.
_REL = (r"\s+(?:bytes?\s+)?(?:of|in|within|inside|into|from|relative\s+to|past|after)\s+(?:the\s+)?"
        r"(?:(?:start|beginning)\s+of\s+(?:the\s+)?)?")
_SECNAME = r"(?:`([^`\s]{1,16})`|'([^'\s]{1,16})'|\"([^\"\s]{1,16})\"|(\.[a-z0-9_$.]{1,15}))"
# `PE file header` (and `NT file header`) is ambiguous: authors use it for the PE signature's header and for the COFF
# file header (IMAGE_FILE_HEADER) after the signature. It matches both bases, so the place is a base conflict and
# nothing is read rather than one reading picked.
_PE_FILE_HEADER = r"(?:pe|nt)\s+file\s+headers?\b"
_BASE_WORDS = (("pe_header", r"(?:pe|nt)\s+headers?\b|pe\s+signature\b|" + _PE_FILE_HEADER),
               ("coff_header", r"coff\s+(?:file\s+)?header\b|(?<!optional )file\s+header\b|" + _PE_FILE_HEADER),
               ("optional_header", r"optional\s+header\b"),
               ("elf_phdr", r"program\s+header\s+table\b"),
               ("elf_shdr", r"section\s+header\s+table\b"),
               ("overlay", r"overlay\b"))
_ANCHOR = r"\b(?:offset|position)\s+" + NUM + _REL
_INTO = r"\b" + NUM + r"\s+bytes\s+(?:into|past\s+the\s+start\s+of|after\s+the\s+start\s+of)\s+(?:the\s+)?"
_BASES = tuple((name, re.compile(lead + r"(?:" + words + ")")) for name, words in _BASE_WORDS for lead in (_ANCHOR, _INTO))
_SECTIONS = tuple(re.compile(lead + tail) for lead in (_ANCHOR, _INTO)
                  for tail in (r"section\s+(?:named\s+|called\s+)?" + _SECNAME, _SECNAME + r"\s+section\b(?!\s+header)"))
_MNAME = r"(?:`([^`\n]{1,200})`|'([^'\n]{1,200})'|\"([^\"\n]{1,200})\"|([A-Za-z0-9_][\w.\-/]*\.[A-Za-z0-9]{1,8})\b)"
_MEMBERS = (re.compile(r"\b(?:(?:archive|zip|tar|ar|7z)\s+)?member\s+(?:file\s+)?(?:named\s+|called\s+)?" + _MNAME, re.I),
            re.compile(r"\b(?:archive|zip|tar)\s+entry\s+(?:named\s+|called\s+)?" + _MNAME, re.I),
            re.compile(_MNAME + r"\s+(?:archive\s+|zip\s+|tar\s+)?member\b", re.I))
MAX_MEMBER = 64 << 20       # bytes of a member read out of an archive
MAX_ENTRIES = 4096          # entries of an archive listed
MAX_DEPTH = 3               # archives opened inside archives for one member path

_STRUCT = {1: "B", 2: "H", 4: "I", 8: "Q"}


def _num(text: str) -> int:
    return int(text, 16) if text.startswith("0x") else int(text)


def _one(values):
    """The one value a set of statements gives, else None (nothing stated, or two different values)."""
    vals = {v for v in values if v is not None}
    return vals.pop() if len(vals) == 1 else None


def _mask_of(text: str):
    """The one bit mask the text states (`masked with 0xNN`, `the low N bits`, `bits A..B`, `the high N bits of
    a 32-bit value`), else None. Lowercase input. Two different masks, or none, state nothing."""
    vals = [_num(m.group(1)) for m in _MASK_HEX.finditer(text)]
    for m in _LOW_BITS.finditer(text):
        n = int(m.group(1))
        if 1 <= n <= 64:
            vals.append((1 << n) - 1)
    for m in _HIGH_BITS.finditer(text):
        n, width = int(m.group(1)), int(m.group(2))
        if 1 <= n <= width <= 64:
            vals.append(((1 << width) - 1) ^ ((1 << (width - n)) - 1))
    for m in _BITS_RANGE.finditer(text):
        a, b = int(m.group(1)), int(m.group(2))
        if 0 <= a <= b <= 63:
            vals.append(((1 << (b + 1)) - 1) ^ ((1 << a) - 1))
    return _one([v for v in vals if v])


def _encoding_of(text: str):
    """The one text encoding the text states (a python codec name), else None. A bare `utf-16` is dropped when a
    specific endianness of it is also stated; two different encodings state nothing."""
    found = {name for rx, name in _ENCODINGS if rx.search(text)}
    for fam, le, be in _ENC_FAMILIES:
        if (le in found or be in found) and fam in found:
            found.discard(fam)
    return found.pop() if len(found) == 1 else None


def _base_of(text: str):
    """B-248: {(offset, base)} the text ties to a stated offset, base ('pe_header',) ... or ('section', name). Lowercase
    input."""
    found = set()
    for name, rx in _BASES:
        for m in rx.finditer(text):
            found.add((_num(m.group(1)), (name,)))
    for rx in _SECTIONS:
        for m in rx.finditer(text):
            sec = next(g for g in m.groups()[1:] if g)
            found.add((_num(m.group(1)), ("section", sec)))
    return found


def _member_of(raw: str):
    """B-248: the one archive member path the (case-kept) text names, 'conflict' for two, else None."""
    names = {next(g for g in m.groups() if g).strip().strip("/") for rx in _MEMBERS for m in rx.finditer(raw)}
    names.discard("")
    if not names:
        return None
    return names.pop() if len(names) == 1 else "conflict"


@functools.lru_cache(maxsize=1024)
def _spec(text: str, syntax: str, kind: str, member=None):
    """The spec of one (question text, syntax text, answer kind), or None when nothing is stated. Lowercase input;
    `member` is the archive member the case-kept text names (B-248), read only beside a stated place."""
    both = text + " \n " + syntax
    if not TRIGGER.search(both):
        return None
    spec = {}
    if _HEX.search(both):
        spec["hex"] = True
    no0x, with0x = bool(_NO_0X.search(both)), bool(_WITH_0X.search(_NO_0X.sub(" ", both)))
    if no0x != with0x:
        spec["prefix"] = with0x
    lower, upper, anycase = bool(_LOWER.search(both)), bool(_UPPER.search(both)), bool(_ANYCASE.search(both))
    if anycase:
        spec["case"] = "any"
    elif lower != upper:
        spec["case"] = "lower" if lower else "upper"
    digits = [int(m.group(1)) for rx in _DIGITS for m in rx.finditer(both)]
    digits += [int(m.group(1)) // 4 for rx in _BITS for m in rx.finditer(both)]
    d = _one(digits)
    if d and 1 <= d <= 64:
        spec["digits"] = d
    asc, desc, filed = bool(_ASC.search(both)), bool(_DESC.search(both)), bool(_FILE_ORDER.search(both))
    if asc + desc + filed == 1:
        spec["order"] = "ascending" if asc else "descending" if desc else "file"
        if _ALPHA.search(both):
            spec["alpha"] = True
    if _UNIQUE.search(both):
        spec["unique"] = True
    little, big = bool(_LITTLE.search(both)), bool(_BIG.search(both))
    if little != big:
        spec["endian"] = "little" if little else "big"
    if kind == "json" or _ARRAY.search(syntax):
        spec["array"] = True
    places = _places(both, spec.get("endian"))
    if places == "conflict":
        spec["place_conflict"] = True
    elif places:
        spec["place"] = places
        # B-248: the structure the place's offset is counted from, and the archive member it is read in
        at = places[2] if places[0] == "int" else places[1]
        bases = _base_of(both)
        if bases:
            if len(bases) == 1 and next(iter(bases))[0] == at:
                spec["base"] = next(iter(bases))[1]
            else:
                spec["base_conflict"] = True
        if member == "conflict":
            spec["member_conflict"] = True
        elif member:
            spec["member"] = member
    mask = _mask_of(both)
    if mask is not None:
        spec["mask"] = mask
    enc = _encoding_of(both)
    if enc:
        spec["encoding"] = enc
    return spec or None


def _type(name, endian_word, default_endian):
    """(struct format, width, signed, type name) of a stated type, or None (a multi-byte type with no byte order)."""
    if name in _WINWORD:
        width = _WINWORD[name]
        e = {"le": "little", "be": "big"}.get((endian_word or "").strip("_")) or default_endian or "little"
        fmt = ("<" if e != "big" else ">") + _STRUCT[width]
        return fmt, width, False, "u" + str(width * 8) + {"little": "le", "big": "be"}[e]
    name = name.replace("uint", "u").replace("int", "i")
    signed, bits = name[0] == "i", int(name[1:])
    width = bits // 8
    e = (endian_word or "").strip("_")
    e = {"le": "little", "be": "big"}.get(e, e) or default_endian
    if width > 1 and e not in ("little", "big"):
        return None
    fmt = ("<" if e != "big" else ">") + (_STRUCT[width].lower() if signed else _STRUCT[width])
    tname = ("i" if signed else "u") + str(bits) + ({"little": "le", "big": "be"}[e] if width > 1 else "")
    return fmt, width, signed, tname


def _places(text: str, default_endian):
    """The one place the text states: ('int', fmt, offset, width, type name) or ('bytes', offset, count); None when it
    states none, 'conflict' when it states two different ones or one it cannot read whole."""
    found = set()
    for m in _PLACES[0].finditer(text):
        t = _type(m.group(1), m.group(2), default_endian)
        found.add(("int",) + (t[0], _num(m.group(3)), t[1], t[3]) if t else "conflict")
    for m in _PLACES[1].finditer(text):
        words = (m.group(1) or "") + " " + (m.group(3) or "")
        ends = set(re.findall(r"(little|big)[- ]endian", words))
        if len(ends) > 1:
            found.add("conflict")
            continue
        endian = ends.pop() if ends else default_endian
        signed = bool(re.search(r"(?<!un)signed", words))
        t = _type(("i" if signed else "u") + m.group(2), endian, default_endian)
        found.add(("int",) + (t[0], _num(m.group(4)), t[1], t[3]) if t else "conflict")
    for m in _PLACES[2].finditer(text):
        offset, endian = _num(m.group(1)), m.group(2) or default_endian
        if m.group(3):
            t = _type(m.group(3), m.group(4) or endian, default_endian)
        else:
            t = _type(("i" if m.group(5) == "signed" else "u") + m.group(6), endian, default_endian)
        found.add(("int",) + (t[0], offset, t[1], t[3]) if t else "conflict")
    for m in _BYTES_AT.finditer(text):
        n = int(m.group(1))
        found.add(("bytes", _num(m.group(2)), n) if 1 <= n <= MAX_BYTES else "conflict")
    for m in _BYTE_RANGE.finditer(text):
        a, b = _num(m.group(1)), _num(m.group(2))
        found.add(("bytes", a, b - a + 1) if a <= b and b - a + 1 <= MAX_BYTES else "conflict")
    if not found:
        return None
    if "conflict" in found or len(found) > 1:
        return "conflict"
    place = found.pop()
    return place if place[2 if place[0] == "int" else 1] <= MAX_PLACE else "conflict"


def spec_of(q: dict):
    """The spec a question states (a dict, see the module text), or None."""
    text = q.get("question") if isinstance(q.get("question"), str) else ""
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    syntax = fmt.get("syntax") if isinstance(fmt.get("syntax"), str) else ""
    kind = fmt.get("kind") if isinstance(fmt.get("kind"), str) else ""
    raw = (text, syntax, kind)
    if raw in _MEMO:
        return _MEMO[raw]
    if len(_MEMO) > 4096:
        _MEMO.clear()
    _MEMO[raw] = got = _spec_of(text, syntax, kind)
    return got


_MEMO = {}


def _spec_of(text, syntax, kind):
    raw = re.sub(r"\s+", " ", text[:TEXT_LIMIT])
    raw_syntax = re.sub(r"\s+", " ", syntax[:600])
    text, syntax = raw.lower(), raw_syntax.lower()
    member = None
    if "member" in text or "entry" in text or "member" in syntax or "entry" in syntax:
        member = _member_of(raw + " \n " + raw_syntax)   # B-248: names keep their case, so the raw texts
    if not TRIGGER.search(text):
        text = ""          # the question's text states nothing: the spec of its syntax alone is shared by every file
    return _spec(text, syntax, kind.lower(), member)


# ------------------------------------------------------------------ fitting a value to a spec

_HEXNUM = re.compile(r"0x[0-9a-fA-F]+")
_BAREHEX = re.compile(r"[0-9a-fA-F]+")
_DECIMAL = re.compile(r"[0-9]+")


def _as_hex(n: int, spec: dict):
    """A non-negative integer written the way a STATED hex spec asks (case, zero-pad, 0x), with the form words so
    `revise` keys the pick. The rendered hex is the `as_stated` option offered first; `revise` keeps the decimal
    as `as_judged`, so nothing plain and wrong reaches the judge and the judged form wins once it is probed."""
    upper = spec.get("case") == "upper"
    body = format(n, "X" if upper else "x")
    words = ["hex"]
    digits = spec.get("digits")
    if digits and len(body) < digits:
        body = body.rjust(digits, "0")
        words.append(f"{digits}_digits")
    if upper:
        words.append("upper")
    if spec.get("prefix") is False:
        return body, words + ["no0x"]
    if spec.get("prefix") is True:
        return "0x" + body, words + ["0x"]
    return "0x" + body, words


def fit_scalar(v: str, spec: dict, kind: str = None):
    """(value in the stated form, words), or (None, words) when the value cannot be written so (a number with more
    significant digits than stated), or (v, []) when nothing stated applies. Only numbers written in hex are
    re-written: a digest or a byte string without 0x is never padded or cut. One exception, gated on the answer
    kind being `integer` (`kind`): a base-10 integer under a STATED hex spec is the judged-form hole the all-or-
    nothing batch cannot afford (the judge wants `0x1000`, the reader has `4096`), so it is rendered as the spec
    asks and returned with words, which makes `revise` demote it to an UNSURE hex-first pick, never a plain
    decimal under a hex format. A digest or exact_text value whose characters happen all to be decimal is left
    alone (it is not an `integer` kind), so no digest is ever re-read as a number."""
    words = []
    if _HEXNUM.fullmatch(v):
        body = v[2:]
    elif (spec.get("prefix") is True and _BAREHEX.fullmatch(v) and re.search(r"[a-fA-F]", v)):
        body = v
        words.append("0x")
    elif kind == "integer" and spec.get("hex") and _DECIMAL.fullmatch(v):
        return _as_hex(int(v), spec)
    else:
        return v, []
    if spec.get("case") == "lower" and re.search(r"[A-F]", body):
        body = body.lower()
        words.append("lower")
    n = spec.get("digits")
    if n and len(body) != n:
        if len(body) < n:
            body = body.rjust(n, "0")
        elif set(body[:len(body) - n]) == {"0"}:
            body = body[len(body) - n:]
        else:
            return None, words + [f"{n}_digits"]
        words.append(f"{n}_digits")
    return ("0x" + body if words or v.startswith("0x") else body), words


def _number(v):
    """The integer a JSON element or a text writes (decimal, or hex with 0x), else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        if _HEXNUM.fullmatch(v):
            return int(v, 16)
        if re.fullmatch(r"-?\d+", v):
            return int(v)
    return None


def fit(v: str, spec: dict, kind: str = None):
    """(the value in the stated form, words); words empty when the value already fits (or nothing applies), and the
    value None when it cannot be made to fit. `kind` is the answer-format kind, passed through to fit_scalar so a
    base-10 integer under a stated hex spec is demoted; array elements are fit without it (kind None)."""
    if not isinstance(v, str) or not v:
        return v, []
    if not (spec.get("array") and v[:1] == "["):
        return fit_scalar(v, spec, kind)
    try:
        items = json.loads(v)
    except ValueError:
        return v, []
    if not isinstance(items, list):
        return v, []
    words, out = [], []
    for x in items:
        if isinstance(x, str):
            y, w = fit_scalar(x, spec)
            if y is None:
                return None, w
            words += [t for t in w if t not in words]
            out.append(y)
        elif (isinstance(x, int) and not isinstance(x, bool) and spec.get("hex") and spec.get("prefix") is True
              and spec.get("digits")):
            # a JSON number under "an array of 0x-prefixed N-digit hex values": the same number, written as asked
            out.append("0x" + format(x, "0%d%s" % (spec["digits"], "X" if spec.get("case") == "upper" else "x")))
            if "hex_strings" not in words:
                words.append("hex_strings")
        else:
            out.append(x)
    if spec.get("unique"):
        seen, kept = [], []
        for x in out:
            mark = json.dumps(x, sort_keys=True)
            if mark not in seen:
                seen.append(mark)
                kept.append(x)
        if len(kept) != len(out):
            out = kept
            words.append("unique")
    if spec.get("order") in ("ascending", "descending") and len(out) > 1:
        nums = [_number(x) for x in out]
        if all(n is not None for n in nums):
            order = sorted(range(len(out)), key=lambda i: nums[i], reverse=spec["order"] == "descending")
        elif spec.get("alpha") and all(isinstance(x, str) for x in out) and \
                sorted(out) == sorted(out, key=str.casefold):
            order = sorted(range(len(out)), key=lambda i: out[i], reverse=spec["order"] == "descending")
        else:
            order = None
        if order is not None and order != sorted(order):
            out = [out[i] for i in order]
            words.append(spec["order"])
    if not words:
        return v, []
    sep = (", ", ": ") if ", " in v else (",", ":")
    return json.dumps(out, separators=sep, ensure_ascii="\\u" in v or not any(ord(c) > 127 for c in v)), words


# ------------------------------------------------------------------ a stated place

def read_place(place, data: bytes):
    """The value at a stated place: an int, or bytes for a byte range; None when the file is too short."""
    if place[0] == "int":
        _, fmt, offset, width, _ = place
        if offset + width > len(data):
            return None
        return struct.unpack_from(fmt, data, offset)[0]
    _, offset, count = place
    if offset + count > len(data):
        return None
    return bytes(data[offset:offset + count])


def encoded_forms(value, enc: str) -> list:
    """[(name, text)] of a byte range decoded under a STATED text encoding (the Day 21 r3 gap); [] when the bytes
    do not decode under it (fail closed). The decoded text first, a NUL-trimmed form second."""
    try:
        text = bytes(value).decode(enc)
    except (UnicodeDecodeError, LookupError, ValueError):
        return []
    tag = "stated_text:" + enc.replace("-", "_")
    out = [(tag, text)]
    trimmed = text.rstrip("\x00")
    if trimmed and trimmed != text:
        out.append((tag + "_trimmed", trimmed))
    return out


def place_forms(value, place, spec: dict, kind: str) -> list:
    """[(name, text)] of a value read at a stated place, in the form the spec and the answer kind ask, best first.
    A stated text encoding decodes a byte range to text; a stated bit mask is applied to an integer by the caller."""
    upper = spec.get("case") == "upper"
    if isinstance(value, (bytes, bytearray)):
        if spec.get("encoding"):
            return encoded_forms(value, spec["encoding"])
        body = value.hex().upper() if upper else value.hex()
        return [("stated_place:hex_0x", "0x" + body)] if spec.get("prefix") is True else [("stated_place:hex", body)]
    if kind == "integer":
        return [("stated_place:decimal", str(value))]
    if kind in ("enum", "json"):
        return []          # a meaning or an array of a number: nothing here says which
    if value < 0:
        return [] if spec.get("hex") else [("stated_place:decimal", str(value))]
    width = place[3]
    pad = spec.get("digits") or width * 2
    hexes = []
    for name, n in (("hex_padded", pad), ("hex_min", 0)):
        body = format(value, "0%d%s" % (n, "X" if upper else "x")) if n else format(value, "X" if upper else "x")
        if spec.get("digits") and len(body) > spec["digits"]:
            continue
        if spec.get("prefix") is not False:
            hexes.append(("stated_place:" + name, "0x" + body))
        if spec.get("prefix") is not True:
            hexes.append(("stated_place:" + name + "_noprefix", body))
    out, seen = [], set()
    if spec.get("hex"):
        cand = hexes
    else:
        cand = [("stated_place:decimal", str(value))] + hexes
    for name, text in cand:
        if text not in seen:
            seen.add(text)
            out.append((name, text))
    return out[:labels.MAX_OPTIONS]


# ------------------------------------------------------------------ B-248: a place inside a structure or a member

def _pe(data: bytes):
    """(e_lfanew, size of optional header, number of sections) of a PE image, or None."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if e + 24 > len(data) or data[e:e + 4] != b"PE\x00\x00":
        return None
    nsec, = struct.unpack_from("<H", data, e + 6)
    opt, = struct.unpack_from("<H", data, e + 20)
    return e, opt, nsec


def _pe_sections(data, pe):
    e, opt, nsec = pe
    table = e + 24 + opt
    if table + 40 * nsec > len(data):
        return None
    out = []
    for i in range(nsec):
        name, = struct.unpack_from("8s", data, table + 40 * i)
        size, ptr = struct.unpack_from("<II", data, table + 40 * i + 16)
        out.append((name.rstrip(b"\x00").decode("latin-1"), ptr, size))
    return out


def _elf(data: bytes):
    """(endian, is64, e_phoff, phsize, e_shoff, shentsize, shnum, shstrndx) of an ELF file, or None."""
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    e = "<" if data[5] == 1 else ">"
    if data[4] == 2:
        if len(data) < 64:
            return None
        phoff, shoff = struct.unpack_from(e + "QQ", data, 32)
        phent, phnum, shent, shnum, shstr = struct.unpack_from(e + "HHHHH", data, 54)
    else:
        phoff, shoff = struct.unpack_from(e + "II", data, 28)
        phent, phnum, shent, shnum, shstr = struct.unpack_from(e + "HHHHH", data, 42)
    return e, data[4] == 2, phoff, phent * phnum, shoff, shent, shnum, shstr


def _elf_sections(data, h):
    e, is64, _, _, shoff, shent, shnum, shstr = h
    if not shoff or shnum == 0 or shent < (64 if is64 else 40) or shoff + shent * shnum > len(data) or shstr >= shnum:
        return None
    fmt = e + ("IIQQQQ" if is64 else "IIIIII")
    heads = [struct.unpack_from(fmt, data, shoff + shent * i) for i in range(shnum)]
    _, _, _, _, str_off, str_size = heads[shstr]
    if str_off + str_size > len(data):
        return None
    out = []
    for name_at, typ, _, _, off, size in heads:
        end = data.find(b"\x00", str_off + name_at, str_off + str_size)
        if name_at >= str_size or end < 0:
            return None
        out.append((data[str_off + name_at:end].decode("latin-1"), off, 0 if typ == 8 else size))   # SHT_NOBITS: no bytes
    return out


def base_offset(base, data: bytes):
    """(start, length, None) of a stated structure in the file, by its own size fields; (None, None, why) when the
    file has no such structure, or has it twice."""
    kind = base[0]
    pe, elf = _pe(data), _elf(data)
    if kind in ("pe_header", "coff_header", "optional_header", "overlay") and pe is None:
        return None, None, f"the text names the {kind.replace('_', ' ')} of a PE image, and the file is none"
    if kind in ("elf_phdr", "elf_shdr") and elf is None:
        return None, None, f"the text names the ELF {kind[4:]} table, and the file is no ELF"
    if kind == "pe_header":
        return pe[0], 24 + pe[1], None
    if kind == "coff_header":
        return pe[0] + 4, 20, None
    if kind == "optional_header":
        return pe[0] + 24, pe[1], None
    if kind == "overlay":
        secs = _pe_sections(data, pe)
        if secs is None:
            return None, None, "the PE section table is cut"
        end = max([p + s for _, p, s in secs if s] + [pe[0] + 24 + pe[1] + 40 * pe[2]])
        return end, max(len(data) - end, 0), None
    if kind == "elf_phdr":
        return elf[2], elf[3], None
    if kind == "elf_shdr":
        return elf[4], elf[5] * elf[6], None
    secs = _pe_sections(data, pe) if pe else _elf_sections(data, elf) if elf else None
    if secs is None:
        return None, None, f"the text names the section {base[1]}, and the file has no section table that reads"
    hits = [(p, s) for n, p, s in secs if n.casefold() == base[1].casefold()]
    if len(hits) != 1:
        return None, None, f"the file has {len(hits)} sections named {base[1]}"
    return hits[0][0], hits[0][1], None


def _shift(place, start: int, length: int):
    """The place moved to the structure's start; None when it does not lie wholly inside the structure."""
    if place[0] == "int":
        _, fmt, offset, width, tname = place
        return ("int", fmt, start + offset, width, tname) if offset + width <= length else None
    _, offset, count = place
    return ("bytes", start + offset, count) if offset + count <= length else None


def _ar_entries(data: bytes):
    out, pos, longnames = [], 8, b""
    while pos + 60 <= len(data) and len(out) < MAX_ENTRIES:
        hdr = data[pos:pos + 60]
        if hdr[58:60] != b"`\n":
            raise ValueError("an ar member header with no terminator")
        raw, size = hdr[:16].rstrip(), int(hdr[48:58].strip())
        body_at, pos = pos + 60, pos + 60 + size + (size & 1)
        if body_at + size > len(data):
            raise ValueError("an ar member runs past the archive")
        body = data[body_at:body_at + size]
        if raw == b"//":
            longnames = body
            continue
        if raw in (b"/", b"/SYM64/", b"__.SYMDEF", b"__.SYMDEF SORTED"):
            continue
        name = raw.decode("latin-1")
        if name.startswith("/") and name[1:].isdigit():
            end = longnames.find(b"\n", int(name[1:]))
            name = longnames[int(name[1:]):end if end >= 0 else len(longnames)].decode("latin-1").rstrip("/")
        elif name.startswith("#1/") and name[3:].isdigit():
            n = int(name[3:])
            name, body = body[:n].rstrip(b"\x00").decode("latin-1"), body[n:]
        else:
            name = name.rstrip("/")
        out.append((name, lambda b=body: b))
    return out


def _entries(data: bytes):
    """[(name, read)] of a zip, tar or ar archive, files only; None when the data is none of them."""
    import io
    if data[:8] == b"!<arch>\n":
        return _ar_entries(data)
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        import zipfile
        z = zipfile.ZipFile(io.BytesIO(data))
        infos = [i for i in z.infolist()[:MAX_ENTRIES] if not i.is_dir()]

        def read(i):
            if i.flag_bits & 1:
                raise ValueError(f"the member {i.filename} is encrypted")
            if i.file_size > MAX_MEMBER:
                raise ValueError(f"the member {i.filename} is larger than is read")
            return z.read(i)
        return [(i.filename, lambda i=i: read(i)) for i in infos]
    import tarfile
    try:
        t = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        return None
    out = []
    for m in t:
        if len(out) >= MAX_ENTRIES:
            break
        if m.isfile():
            if m.size > MAX_MEMBER:
                raise ValueError(f"the member {m.name} is larger than is read")
            out.append((m.name, lambda m=m: t.extractfile(m).read()))
    return out


def member_bytes(data: bytes, path: str, depth: int = 0):
    """(bytes, None) of the archive member `path` (a path may go through members that are archives themselves),
    or (None, why). A name matches a member's full name, else exactly one member's base name."""
    try:
        entries = _entries(bytes(data))
    except Exception as e:     # a damaged archive reads nothing
        return None, f"the archive does not read ({type(e).__name__}: {str(e)[:80]})"
    if entries is None:
        return None, "the target is no zip, tar or ar archive"
    hits = [r for n, r in entries if n.strip("/") == path]
    if not hits and "/" not in path:
        hits = [r for n, r in entries if n.strip("/").rsplit("/", 1)[-1] == path]
    if len(hits) > 1:
        return None, f"{len(hits)} members are named {path}"
    if hits:
        try:
            return hits[0](), None
        except Exception as e:
            return None, f"the member {path} does not read ({type(e).__name__}: {str(e)[:80]})"
    parts = path.split("/")
    if depth < MAX_DEPTH:
        for i in range(len(parts) - 1, 0, -1):     # the longest leading path that is a member, read inside it
            outer, why = member_bytes(data, "/".join(parts[:i]), depth + 1) if "/".join(parts[:i]) else (None, "")
            if outer is not None:
                return member_bytes(outer, "/".join(parts[i:]), depth + 1)
    return None, f"no member is named {path}"


# ------------------------------------------------------------------ the answer

def _say(line: str):
    print(line, file=sys.stderr)


def _prop(q: dict, prop) -> str:
    if callable(prop):
        try:
            prop = prop()
        except Exception:
            prop = None
    aid = q.get("answer_id") or q.get("qid") or q.get("id") or "x"
    return re.sub(r"[^a-z0-9_.+-]+", "_", str(prop or re.sub(r"^set\d+\.", "", str(aid))).lower())[:80]


def revise(q: dict, answer, target, prop=None):
    """The answer as the question's stated spec has it (see the module text). `target` is a callable giving
    (name, bytes) of the file the question is about; it is called only for a stated place."""
    spec = spec_of(q)
    if not spec:
        return answer
    aid = q.get("answer_id") or q.get("qid")
    if "synthesis" in str(aid):
        return answer          # row 311's own handler states and answers its order itself
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    kind = str(fmt.get("kind") or "").lower()
    if spec.get("place_conflict"):
        _say(f"STATED {aid}: the text states two places or one this module cannot read whole; no place is read")
    place = spec.get("place")
    if place is not None and (answer is None or (isinstance(answer, str) and not labels.is_unsure(answer))):
        got = _place_answer(q, answer, place, spec, kind, _prop(q, prop), target)
        if got is not False:
            return got
    if isinstance(answer, str) and answer and not labels.is_unsure(answer):
        fitted, words = fit(answer, spec, kind)
        if fitted is None:
            _say(f"STATED {aid}: the plain answer {answer[:80]!r} cannot be written as the text states "
                 f"({', '.join(words)}); it stands")
            return answer
        if words and fitted != answer:
            key = KEY + f"{_prop(q, prop)}+{'+'.join(words)}"
            _say(f"STATED {aid}: the judged form {answer[:80]!r} is not what the text states ({', '.join(words)}); "
                 f"unsure under {key}, {fitted[:80]!r} first")
            return labels.pick(key, [("as_stated", fitted), ("as_judged", answer)])
        return answer
    if labels.is_unsure(answer):
        return _reorder(q, answer, spec, aid)
    return answer


def _reorder(q, answer, spec, aid):
    got = labels.parse(answer)
    if not got or not got.key or not got.options or not _states_form(spec):
        return answer
    opts = list(got.options)
    values = {v for _, v in opts}
    fits, made = [], []
    for n, v in opts:
        if not (isinstance(v, str) and applies(v, spec)):
            continue          # an option the stated form says nothing about (a constant's name, a decimal number)
        fitted, words = fit(v, spec)
        if not words:
            fits.append((n, v))
        elif fitted and fitted not in values and len(made) < 2:
            made.append((n + "+stated", fitted))
            values.add(fitted)
    if fits:
        new = fits + [o for o in opts if o not in fits]
        if new == opts:
            return answer
        _say(f"STATED {aid}: {len(fits)} option(s) of {got.key} fit the stated form; offered first")
        return labels.pick(got.key, new)
    if made:
        _say(f"STATED {aid}: no option of {got.key} fits the stated form; {made[0][1][:80]!r} offered first as "
             f"{made[0][0]}")
        return labels.pick(got.key, made + opts)
    return answer


def _states_form(spec: dict) -> bool:
    """Does the spec state a form that can tell options apart (a digit count, a case, an order, each once)? `hex` and
    `array` alone do not: `compact valid JSON array with exact values and order` says nothing of an element's form."""
    return bool(spec.get("digits") or spec.get("case") in ("lower", "upper") or spec.get("unique")
                or spec.get("order") in ("ascending", "descending") or spec.get("prefix") is True)


def applies(v: str, spec: dict) -> bool:
    """Does the stated form speak of this value at all: a number written in hex (0x, or letters under a stated 0x),
    or a JSON array the form re-writes or whose elements are such numbers."""
    if _HEXNUM.fullmatch(v) or (spec.get("prefix") is True and _BAREHEX.fullmatch(v) and re.search(r"[a-fA-F]", v)):
        return True
    if spec.get("array") and v[:1] == "[":
        if fit(v, spec)[1]:
            return True
        try:
            items = json.loads(v)
        except ValueError:
            return False
        return isinstance(items, list) and bool(items) and all(isinstance(x, str) and applies(x, spec) for x in items)
    return False


def _place_answer(q, answer, place, spec, kind, name, target):
    """The answer of a question that states a place (False: the place gives nothing, keep the answer as it is)."""
    aid = q.get("answer_id") or q.get("qid")
    try:
        fname, data = target()
    except Exception:
        fname, data = None, None
    if not isinstance(data, (bytes, bytearray)):
        return False
    where = (f"{place[4]} at {place[2]:#x}" if place[0] == "int" else f"{place[2]} bytes at {place[1]:#x}")
    more = ""
    if spec.get("member_conflict") or spec.get("base_conflict"):
        _say(f"STATED {aid}: the text names two archive members or two structures for {where}; nothing read")
        return False
    member = spec.get("member")
    if member and str(fname or "").replace("\\", "/").rsplit("/", 1)[-1].rsplit(" -> ", 1)[-1] != member.rsplit("/", 1)[-1]:
        got, why = member_bytes(data, member)
        if got is None:
            _say(f"STATED {aid}: the text reads {where} in the member {member[:60]} of {str(fname)[:60]}: {why}; nothing read")
            return False
        fname, data, more = f"{fname} -> {member}", got, "+member"
    base = spec.get("base")
    if base:
        start, length, why = base_offset(base, data)
        label = base[0] if base[0] != "section" else "section_" + re.sub(r"[^a-z0-9_.$]+", "_", base[1].lower())
        if start is None:
            _say(f"STATED {aid}: {why}; nothing read")
            return False
        moved = _shift(place, start, length)
        if moved is None:
            _say(f"STATED {aid}: {where} of the {label} lies past its end ({length} bytes from {start:#x}); nothing read")
            return False
        place, where, more = moved, f"{where} of the {label} (file offset {start:#x} + n)", more + "+in_" + label
    value = read_place(place, data)
    if value is None:
        _say(f"STATED {aid}: the text states {where}, past the end of {str(fname)[:60]} ({len(data)} bytes); nothing read")
        return False
    tag = (place[4] if place[0] == "int" else "bytes") + more
    # the Day 21 r3 gaps: a stated bit mask narrows an integer place; a stated encoding tags a byte range's key
    if place[0] == "int" and spec.get("mask") is not None:
        value &= spec["mask"]
        tag += "+mask_%x" % spec["mask"]
        where += f" & {spec['mask']:#x}"
    elif place[0] == "bytes" and spec.get("encoding"):
        tag += "+" + spec["encoding"].replace("-", "")
    forms = place_forms(value, place, spec, kind)
    if not forms:
        return False
    if answer is None:
        key = KEY + f"{name}+{tag}"
        _say(f"STATED {aid}: {where} in {str(fname)[:60]} reads {forms[0][1][:40]}; unsure under {key}")
        return labels.pick(key, forms)
    # a plain answer beside a stated place: the same number is no news; a different one is a second reading
    mine = _number(answer.strip()) if place[0] == "int" else None
    if place[0] == "int" and mine is not None and mine != value:
        key = KEY + f"{name}+{tag}+reader"
        _say(f"STATED {aid}: {where} in {str(fname)[:60]} reads {value}, the reader's plain answer {answer[:40]!r} "
             f"is another number; a candidate pick under {key}, the stated place first")
        return labels.candidates(key, forms[:labels.MAX_OPTIONS - 1] + [("reader", answer)])
    return False


# ------------------------------------------------------------------ coverage of the saved questions

def coverage(paths) -> dict:
    """{phrase: count} of what the saved questions state, read by spec_of: the build's report."""
    from collections import Counter
    seen, c = set(), Counter()
    for p in paths:
        try:
            att = json.loads(Path(p).read_text())
        except Exception:
            continue
        for q in att.get("questions") or []:
            fmt = q.get("answer_format") or {}
            mark = (q.get("question"), json.dumps(fmt, sort_keys=True))
            if mark in seen:
                continue
            seen.add(mark)
            c["questions"] += 1
            s = spec_of(q) or {}
            c["with_spec"] += bool(s)
            for k, v in s.items():
                c[f"{k}={v}" if k not in ("place", "mask", "encoding") else k] += 1
    return dict(c)


if __name__ == "__main__":
    import glob
    if len(sys.argv) > 1:
        root = sys.argv[1]
    else:
        sys.path.append(str(HERE.parent.parent))           # the checkout root, for the ctf package
        from ctf import paths as ctf_paths
        root = str(ctf_paths.workdir())
    paths = glob.glob(f"{root}/day-*/metadata-forensics-*/**/attempt.json", recursive=True)
    for k, v in sorted(coverage(paths).items()):
        print(f"{v:6d}  {k}")
