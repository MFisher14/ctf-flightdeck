#!/usr/bin/env python3
"""Backlog row 422 (the Day 21 build, round 4): a header id no rule defines, answered ONLY from the definition its
own question states.

A new day may ask a header id no reader of the lane knows (`import_count`, `tls_callback_count`, `api_hash`,
`string_count`, `section_entropy`, ...). Its name alone has several readings (DLLs or functions? with or without the
null symbol? which hash, which seed, which input?), and a pick from a guessed reading is a guess: this module never
answers from the name. It answers only when the question TEXT states how the value is computed, computes exactly
that from the bytes, and offers it as a ONE-option `labels.pick` under `binary.stated_define/<the definition>` (the
key is named by the stated definition, never by the field, and ends in a tag of the question text, `+t<crc32 of
judged_forms.norm_text>`, so a name the judge accepts for one text never answers another text plain, whatever
restriction of it the parser did not read: the review of row 422). With no stated definition, or a definition with
a word this module does not read, the id stays None, as before.

What it reads (each in a question of an id still None after every other reader; `evidence.defined()`):

  - entropy: "Shannon entropy ... of the <.sec> section('s raw bytes) | of the whole member | of member N ... in
    bits per byte ... rounded|truncated to N decimal places". Bits per byte and the decimals and the rounding word
    must all be stated; a PE section needs "raw" (or SizeOfRawData / file bytes); a value within 1e-6 of a
    rounding boundary is None.
  - a count: "number of | count of | how many <what> ...":
      * PE import descriptors ("imported DLLs", "import descriptors", "modules|libraries in the import table");
      * PE imported functions ("imported functions|symbols|APIs|thunks", "by name" counts the named ones only);
      * ELF DT_NEEDED entries (the text names DT_NEEDED);
      * ELF undefined .dynsym symbols, only when the text says how the null entry is counted ("named", "non-empty
        name", "excluding the null symbol|entry|index 0");
      * PE TLS callbacks (the AddressOfCallBacks array up to its null pointer; no TLS directory is 0 only when the
        text says so);
      * entries of a named section or table (`sh_size / sh_entsize`, ELF);
      * printable strings: a stated minimum length, printable ASCII (0x20..0x7e; a tab only when the text names
        it), NUL-terminated when stated, distinct when stated, in a named section or the whole member.
  - a hash: ROR13 (the order of rotate and add stated, by words or by a formula), FNV-1 / FNV-1a (32- or 64-bit
    stated), djb2 / djb2a and sdbm (a stated width), CRC-32 (zlib's), MD5, SHA-1, SHA-256; of a quoted literal or
    a named API / function name, of a named section's bytes or of the member; ASCII unless UTF-16LE is stated; a
    NUL terminator or an upper/lower-case fold only when the text states it; a stated seed.
  - a typed read: "the u32le | little-endian 32-bit (unsigned) integer at (file) offset N (of the <.sec>
    section)": the integer at that place.

Any other qualifier in the text (excluding, only, unless, ignore, distinct, first, last, minus, whose, not, starts
with, after, before, zero..., average..., block..., a named .dll or .so, ...) that the reading did not consume makes
it None, as does a text that states two kinds of definition at once. The member is
`member N` when the text names one, else the prefix's one ELF or PE member (two executables and no member named:
None). A config, HCFG, overlay or trailer id, and any field generic.py knows, is never asked here.

Lines (stderr): `[defined] <qid>: <definition> = <value> from <member> (a one-option pick)`, and
`[defined] <qid>: the question states <kind>; not answered: <why>` when a definition was seen and not computed.
"""
import hashlib
import math
import re
import struct
import sys
import zlib

try:
    import numpy as np
except Exception:          # pragma: no cover - the lane imports numpy with the solver
    np = None

import binfmt

KEY = "binary.stated_define/"
SEQ_MAX = 1 << 20          # a byte-by-byte hash (ror13, fnv, djb2, sdbm) reads at most 1 MiB
STRINGS_MAX = 1 << 16      # distinct strings kept for a "distinct" count
CALLBACKS_MAX = 4096
NUMBERS = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
           "nine": 9, "ten": 10}
NUM = r"(\d+|zero|one|two|three|four|five|six|seven|eight|nine|ten)"
TYPES = {"u8": ("<B", 1), "uint8": ("<B", 1), "u16le": ("<H", 2), "u16be": (">H", 2), "u32le": ("<I", 4),
         "u32be": (">I", 4), "u64le": ("<Q", 8), "u64be": (">Q", 8)}

# the lane's own boilerplate, removed before a text is read
BOILER = [r"In evidence\.zip,\s*", r"Use all d\d+--? ?members in ZIP central-directory order\.\s*",
          r",?\s*where members are the d\d+--? ?members in ZIP central-directory order \(1-based\)",
          r"For the requested delivered binary,\s*"]
QUALIFIERS = re.compile(r"\b(?:except|excluding|exclude[sd]?|only|unless|ignor\w*|skip\w*|without|other than|"
                        r"non-?zero|non-?empty|distinct|unique|dedup\w*|sorted|first|last|minus|plus|subtract\w*|"
                        r"divided|multipl\w*|percent\w*|normali[sz]\w*|averag\w*|mean|median|maximum|minimum|"
                        r"delay\w*|virtual|rva|in memory|loaded|mapped|"
                        # the review of row 422: a restriction of what is counted or hashed, or of the bytes, that no
                        # reading here consumes (a DLL named, a name filter, a block-wise computation, bytes changed
                        # first). The list is a backstop only: the key's text tag is what keeps one text's accepted
                        # reading from answering another.
                        r"whose|which|where|not|start\w* with|begin\w* with|end\w* with|prefix\w*|suffix\w*|"
                        r"contain\w*|match\w*|after|before|zero\w*|block\w*|chunk\w*|window\w*|sliding|"
                        r"patch\w*|replac\w*|mask\w*|clear\w*|overwrit\w*|modif\w*|"
                        r"[\w+-]+\.(?:dll|sys|drv|ocx|dylib)|[\w+-]+\.so(?:\.\d+)*)\b", re.I)
SKIP_FIELD = re.compile(r"(?:^|_)(?:config|hcfg|overlay|trailer|resource|scratch|xor_key|artifact)(?:_|$)")


def _num(word) -> int:
    word = str(word).lower()
    return int(word) if word.isdigit() else NUMBERS[word]


def _clean(text: str) -> str:
    for rx in BOILER:
        text = re.sub(rx, "", text, flags=re.I)
    return re.sub(r"\s+", " ", text).strip()


def _unread(text: str, consumed) -> list:
    """The qualifier words of `text` that no consumed phrase covers."""
    rest = text
    for rx in consumed:
        rest = re.sub(rx, " ", rest, flags=re.I)
    return sorted({m.group(0).lower() for m in QUALIFIERS.finditer(rest)})


class Unread(Exception):
    """A definition was seen and not computed: the reason."""


# ---------------------------------------------------------------------------- the member and the region

def _exe(data: bytes):
    if data[:4] == b"\x7fELF":
        info = binfmt.elf(data)
        return ("elf", info) if info else None
    if data[:2] == b"MZ":
        info = binfmt.pe(data)
        return ("pe", info) if info else None
    return None


def _member(text: str, members: list):
    """(name, bytes, (kind, info) or None) of the member the text asks about."""
    m = re.search(r"\b(?:of|in|over|from) member (\d+)\b", text, re.I)
    if m:
        n = int(m.group(1))
        if not 1 <= n <= len(members):
            raise Unread(f"member {n} is not among the prefix's {len(members)} member(s)")
        name, data = members[n - 1]
        return name, bytes(data), _exe(bytes(data))
    exes = []
    for name, data in members:
        got = _exe(bytes(data))
        if got:
            exes.append((name, bytes(data), got))
    if len(exes) == 1:
        return exes[0]
    if not exes and len(members) == 1:
        return members[0][0], bytes(members[0][1]), None
    raise Unread(f"{len(exes)} executable members and the text names none")


SECTION = r"(?:the )?[`'\"]?(?P<sec>\.[A-Za-z0-9_.$]{1,15}?)[`'\"]? section"


def _section(kind_info, sec: str, text: str, consumed: list):
    """The named section's bytes in the file, or Unread."""
    if not kind_info:
        raise Unread("the member is not an ELF or PE image")
    kind, info = kind_info
    secs = [s for s in (info.get("sections") or []) if s.get("name") == sec]
    if len(secs) != 1:
        raise Unread(f"{len(secs)} sections named {sec}")
    s = secs[0]
    if kind == "elf":
        if s["type"] == 8:
            raise Unread(f"{sec} is SHT_NOBITS: it has no bytes in the file")
        return s["offset"], s["size"]
    raw = re.compile(r"\braw(?: data| bytes)?\b|SizeOfRawData|PointerToRawData|on-disk|file bytes|bytes in the file|"
                     r"as stored in the file", re.I)
    if not raw.search(text):
        raise Unread(f"a PE section's bytes ({sec}) without 'raw': raw or virtual size is not stated")
    consumed.append(raw.pattern)
    return s["raw"], s["rsize"]


def _region(text: str, members: list, consumed: list, need_exe=False):
    """(slug, name, bytes, (kind, info)) of the region the text names: a section or the whole member."""
    name, data, ki = _member(text, members)
    m = re.search(SECTION, text)
    if m:
        off, size = _section(ki, m.group("sec"), text, consumed)
        if off + size > len(data) or size < 0:
            raise Unread(f"{m.group('sec')} runs past the member's end")
        return "section_" + re.sub(r"[^a-z0-9]", "", m.group("sec").lower()), name, data[off:off + size], ki
    whole = re.compile(r"\b(?:whole|entire|complete|full) (?:member|file|sample|binary)\b|\ball (?:the )?bytes of the "
                       r"(?:member|file)\b|\b(?:exact |raw )?bytes of member \d+\b|\bthe member'?s? (?:exact )?bytes\b|"
                       r"\bof member \d+\b", re.I)
    if whole.search(text):
        if need_exe and not ki:
            raise Unread("the member is not an ELF or PE image")
        return "member", name, data, ki
    raise Unread("no region is stated (a named section or the whole member)")


# ---------------------------------------------------------------------------- entropy

NORMALISED = r"\bnormali[sz]ed\b"
NORM_SCALE = (r"\b(?:divided by|over)\s+(?:8|eight)\b(?: bits?)?|/\s*8\b|\b(?:in|to|into|within|between) (?:the )?"
              r"(?:range |interval )?\[?0(?:\.0)?\s*(?:,|\.\.|to|and|-|–)\s*1(?:\.0)?\]?")


def _decimals(text: str, consumed: list):
    for rx in (NUM + r" decimal (?:places?|digits?)", NUM + r" digits? after the (?:decimal )?point",
               r"\b(?:to|with) " + NUM + r" decimals\b", NUM + r" fractional digits?"):
        m = re.search(rx, text, re.I)
        if m:
            consumed.append(rx)
            return _num(m.group(1))
    return None


def _entropy(text: str, members: list):
    consumed = [r"shannon", r"entropy"]
    # B-246: a NORMALISED entropy (bits per byte divided by 8, in [0, 1]), only when the text says to what
    norm = re.search(NORMALISED, text, re.I)
    if norm:
        scale = re.search(NORM_SCALE, text, re.I)
        if not scale:
            raise Unread("a normalised entropy, and what it is normalised by is not stated")
        consumed += [NORMALISED, NORM_SCALE]
    elif not re.search(r"bits? per byte|bits?/byte", text, re.I):
        raise Unread("bits per byte is not stated")
    n = _decimals(text, consumed)
    if n is None or n > 12:
        raise Unread("the number of decimals is not stated")
    rounding = ("trunc" if re.search(r"\btruncat", text, re.I)
                else "round" if re.search(r"\bround", text, re.I) else None)
    if rounding is None:
        raise Unread("neither rounded nor truncated is stated")
    slug, name, region, _ = _region(text, members, consumed)
    if not region:
        raise Unread("the region is empty")
    if np is not None:
        counts = np.bincount(np.frombuffer(region, dtype=np.uint8), minlength=256)
        p = counts[counts > 0] / len(region)
        h = float(-(p * np.log2(p)).sum())
    else:
        h = 0.0
        for c in range(256):
            k = region.count(bytes([c]))
            if k:
                h -= k / len(region) * math.log2(k / len(region))
    if norm:
        h /= 8
    scaled = h * 10 ** n
    frac = scaled - math.floor(scaled)
    if rounding == "round":
        if abs(frac - 0.5) < 1e-6:
            raise Unread(f"the entropy {h!r} lies on a rounding boundary")
        v = math.floor(scaled + 0.5)
    else:
        if frac < 1e-6 or frac > 1 - 1e-6:
            raise Unread(f"the entropy {h!r} lies on a truncation boundary")
        v = math.floor(scaled)
    if n == 0:
        value = str(v)
    else:
        digits = str(v).rjust(n + 1, "0")
        value = digits[:-n] + "." + digits[-n:]
    if norm:
        return (f"entropy_normalised+{slug}+{n}dp+{rounding}", [("shannon_bits_per_byte_over_8", value)], name,
                consumed)
    return (f"entropy+{slug}+{n}dp+{rounding}", [("shannon_bits_per_byte", value)], name, consumed)


# ---------------------------------------------------------------------------- counts

def _pe_imports(data: bytes, info: dict):
    """[(dll, [thunk values])] of the import directory, or Unread."""
    rva = info["dirs"].get("import", (0, 0))[0]
    if not rva:
        raise Unread("the PE has no import directory")
    at = binfmt.pe_offset(info["sections"], rva)
    if at is None:
        raise Unread("the import directory is outside every section")
    width = 8 if info["plus"] else 4
    out = []
    try:
        for k in range(binfmt.TABLE_MAX):
            ilt, _, _, name, iat = struct.unpack_from("<IIIII", data, at + 20 * k)
            if not (ilt or name or iat):
                break
            table = binfmt.pe_offset(info["sections"], ilt or iat)
            if table is None:
                raise Unread("an import thunk table is outside every section")
            thunks = []
            for j in range(binfmt.TABLE_MAX):
                v = struct.unpack_from("<Q" if width == 8 else "<I", data, table + width * j)[0]
                if v == 0:
                    break
                thunks.append(v)
            else:
                raise Unread("an import thunk table has no end")
            out.append((name, thunks))
        else:
            raise Unread("the import directory has no end")
    except struct.error:
        raise Unread("the import directory is cut")
    return out


DELAY = re.compile(r"\bdelay[- ]?(?:load(?:ed|ing)?|import(?:ed|s)?)(?:[- ]import(?:ed|s)?)?\b", re.I)
EXPORTS_BY_NAME = re.compile(r"\bby name\b|\bnamed exports?\b|\bexport(?:ed)? names?\b|\bNumberOfNames\b", re.I)
EXPORTS_BY_EAT = re.compile(r"\bNumberOfFunctions\b|\bexport address table(?: entries)?\b|\bEAT(?: entries)?\b", re.I)


def _pe_dir_at(data: bytes, info: dict, name: str):
    """The file offset of a PE data directory, None when the image has none, or Unread."""
    rva = info["dirs"].get(name, (0, 0))[0]
    if not rva:
        return None
    at = binfmt.pe_offset(info["sections"], rva)
    if at is None:
        raise Unread(f"the {name} directory is outside every section")
    return at


def _pe_delay_descriptors(data: bytes, info: dict) -> int:
    """B-246: the delay-load descriptors (ImgDelayDescr, 32 bytes each) up to the one with no DLL name."""
    at = _pe_dir_at(data, info, "delay_import")
    if at is None:
        raise Unread("the PE has no delay-import directory")
    try:
        for k in range(binfmt.TABLE_MAX):
            if struct.unpack_from("<8I", data, at + 32 * k)[1] == 0:
                return k
    except struct.error:
        raise Unread("the delay-import directory is cut")
    raise Unread("the delay-import directory has no end")


def _pe_exports(data: bytes, info: dict, text: str, consumed: list):
    """B-246: (slug, options) of a PE export count, only when the text says which count: by name
    (NumberOfNames) or the export address table (NumberOfFunctions, which counts gaps); else Unread."""
    by_name, by_eat = EXPORTS_BY_NAME.search(text), EXPORTS_BY_EAT.search(text)
    if bool(by_name) == bool(by_eat):
        raise Unread("whether exports are counted by name or by the export address table is not stated")
    at = _pe_dir_at(data, info, "export")
    if at is None:
        if re.search(r"\b(?:0|zero) (?:if|when) (?:there is |the image has |it has )?no export", text, re.I):
            consumed.append(r"\b(?:0|zero) (?:if|when) (?:there is |the image has |it has )?no export\w*(?: \w+)?")
            n_fn = n_names = 0
        else:
            raise Unread("the PE has no export directory and the text does not say what to answer then")
    else:
        try:
            n_fn, n_names = struct.unpack_from("<II", data, at + 20)
        except struct.error:
            raise Unread("the export directory is cut")
    if by_name:
        consumed.append(EXPORTS_BY_NAME.pattern)
        return "count+pe_exports+by_name", [("number_of_names", str(n_names))]
    consumed.append(EXPORTS_BY_EAT.pattern)
    return "count+pe_exports+eat", [("number_of_functions", str(n_fn))]


def _tls_callbacks(data: bytes, info: dict, text: str, consumed: list) -> int:
    rva = info["dirs"].get("tls", (0, 0))[0]
    absent = re.compile(r"\b(?:0|zero) (?:if|when) (?:there is |the image has |it has )?no TLS(?: directory)?", re.I)
    stated = bool(absent.search(text))
    if stated:
        consumed.append(absent.pattern)
    if not rva:
        if stated:
            return 0
        raise Unread("the PE has no TLS directory and the text does not say what to answer then")
    at = binfmt.pe_offset(info["sections"], rva)
    if at is None:
        raise Unread("the TLS directory is outside every section")
    width = 8 if info["plus"] else 4
    try:
        va = struct.unpack_from("<Q" if width == 8 else "<I", data, at + 3 * width)[0]
        if va == 0:
            return 0
        arr = binfmt.pe_offset(info["sections"], va - info["image_base"])
        if arr is None:
            raise Unread("AddressOfCallBacks is outside every section")
        for j in range(CALLBACKS_MAX):
            if struct.unpack_from("<Q" if width == 8 else "<I", data, arr + width * j)[0] == 0:
                return j
    except struct.error:
        raise Unread("the TLS callback array is cut")
    raise Unread("the TLS callback array has no end")


def _strings(text: str, members: list, consumed: list):
    m = re.search(r"\b(?:at least |of length (?:at least )?|minimum (?:length )?(?:of )?|min(?:imum)? length )" + NUM +
                  r"\b(?: (?:printable )?(?:characters?|chars?|bytes?))?|\b" + NUM +
                  r" or more (?:printable )?(?:ascii )?(?:characters?|chars?|bytes?)", text, re.I)
    if not m:
        raise Unread("the minimum string length is not stated")
    consumed.append(re.escape(m.group(0)))
    least = _num(m.group(1) or m.group(2))
    if least < 1:
        raise Unread("a minimum length under 1")
    if not re.search(r"printable ascii|0x20\s*(?:-|–|\.\.|to|through)\s*0x7e", text, re.I):
        raise Unread("printable ASCII (0x20..0x7e) is not stated")
    tab = bool(re.search(r"\btab\b|0x09\b|\\t", text, re.I))
    nul = re.compile(r"\b(?:NUL|null)[- ]terminated\b|followed by a (?:NUL|null|zero)(?: byte)?", re.I)
    terminated = bool(nul.search(text))
    if terminated:
        consumed.append(nul.pattern)
    distinct = bool(re.search(r"\b(?:distinct|unique)\b", text, re.I))
    if distinct:
        consumed.append(r"\b(?:distinct|unique)\b")
    slug, name, region, _ = _region(text, members, consumed)
    if np is None:
        raise Unread("numpy is not available")
    arr = np.frombuffer(region, dtype=np.uint8)
    ok = (arr >= 0x20) & (arr <= 0x7E)
    if tab:
        ok |= arr == 0x09
    edge = np.diff(np.concatenate(([0], ok.astype(np.int8), [0])))
    starts, ends = np.flatnonzero(edge == 1), np.flatnonzero(edge == -1)
    keep = (ends - starts) >= least
    if terminated:
        after = np.zeros(len(ends), dtype=bool)
        inside = ends < len(arr)
        after[inside] = arr[ends[inside]] == 0
        keep &= after
    if distinct:
        seen = set()
        for a, b in zip(starts[keep], ends[keep]):
            seen.add(region[a:b])
            if len(seen) > STRINGS_MAX:
                raise Unread("more distinct strings than this reader keeps")
        count = len(seen)
    else:
        count = int(keep.sum())
    slug = (f"strings+{slug}+min{least}" + ("+tab" if tab else "") + ("+nul" if terminated else "")
            + ("+distinct" if distinct else ""))
    return slug, count, name


def _count(text: str, members: list):
    consumed = [r"\bnumber of\b", r"\bcount(?: of)?\b", r"\bhow many\b"]
    m = re.search(r"\b(?:number of|count(?: of| the| all)*|how many) (?:the |all )?(?P<what>[A-Za-z0-9 _./$-]{2,60}?)"
                  r"(?= (?:in|of|from|listed|across|that|are|is|does|the)\b| \(|[.,;:?]|$)", text, re.I)
    if not m:
        raise Unread("what is counted is not stated")
    what = m.group("what").lower().strip()
    if re.search(r"\bstrings?\b", what):
        slug, n, name = _strings(text, members, consumed)
        return slug, [("printable_runs", str(n))], name, consumed
    name, data, ki = _member(text, members)
    kind, info = ki if ki else (None, None)
    if re.search(r"\btls callbacks?\b|\bcallbacks?\b", what) and re.search(r"\bTLS\b", text):
        if kind != "pe":
            raise Unread("TLS callbacks of an image that is not a PE")
        return "count+pe_tls_callbacks", [("tls_callback_array", str(_tls_callbacks(data, info, text, consumed)))], \
            name, consumed
    if re.search(r"\bdt_needed\b", text, re.I) and re.search(r"\b(?:entries|librar(?:y|ies)|dt_needed)\b", what):
        if kind != "elf" or info.get("dynamic") is None:
            raise Unread("DT_NEEDED of an image with no dynamic table")
        return "count+elf_dt_needed", [("dt_needed_entries", str(sum(1 for t, _ in info["dynamic"] if t == 1)))], \
            name, consumed
    # B-246: delay-load imports and PE exports (the backlog's "stated definitions" residual)
    if DELAY.search(text) and re.search(r"\b(?:dlls?|modules?|librar(?:y|ies)|descriptors?)\b", what) and \
            not re.search(r"\b(?:functions?|symbols?|apis?|thunks?)\b", what):
        if kind != "pe":
            raise Unread("delay-load imports of an image that is not a PE")
        consumed.append(DELAY.pattern)
        return "count+pe_delay_import_descriptors", \
            [("delay_import_descriptors", str(_pe_delay_descriptors(data, info)))], name, consumed
    if re.search(r"\bexport", text, re.I) and kind == "pe" and \
            re.search(r"\b(?:functions?|exports?|names?|symbols?|entries|apis?)\b", what):
        return _pe_exports(data, info, text, consumed) + (name, consumed)
    if re.search(r"\b(?:dlls?|modules?|librar(?:y|ies)|(?:import )?descriptors?)\b", what) and \
            re.search(r"\bimport", text, re.I) and not re.search(r"\b(?:functions?|symbols?|apis?|thunks?)\b", what):
        if kind != "pe":
            raise Unread("import descriptors of an image that is not a PE")
        return "count+pe_import_descriptors", [("import_descriptors", str(len(_pe_imports(data, info))))], \
            name, consumed
    if re.search(r"\b(?:functions?|apis?|thunks?|symbols?)\b", what) and re.search(r"\bimport", text, re.I) and \
            kind == "pe":
        both = re.compile(r"\bby name (?:and|or) (?:by )?ordinal|\bby ordinal (?:and|or) (?:by )?name", re.I)
        by_name = re.compile(r"\bby name\b", re.I)
        top = 1 << 63 if info["plus"] else 1 << 31
        rows = _pe_imports(data, info)
        if not both.search(text) and by_name.search(text):
            consumed.append(by_name.pattern)
            if re.search(r"\bordinal", text, re.I):
                raise Unread("an ordinal rule beside 'by name' this reader does not read")
            n = sum(1 for _, t in rows for v in t if not v & top)
            return "count+pe_imported_functions+by_name", [("import_thunks_by_name", str(n))], name, consumed
        if re.search(r"\bordinal", text, re.I) and not both.search(text):
            raise Unread("an ordinal rule this reader does not read")
        consumed.append(both.pattern)
        n = sum(len(t) for _, t in rows)
        return "count+pe_imported_functions", [("import_thunks", str(n))], name, consumed
    if re.search(r"\b(?:symbols?)\b", what) and re.search(r"\.dynsym\b", text) and re.search(r"\bundefined\b|SHN_UNDEF",
                                                                                               text):
        if kind != "elf":
            raise Unread(".dynsym of an image that is not an ELF")
        null = re.compile(r"\bnamed\b|non-?empty names?|excluding the (?:null|index 0|first|STN_UNDEF) (?:symbol|entry)"
                          r"(?: at index 0)?|\bwith a name\b", re.I)
        if not null.search(text):
            raise Unread("how the null symbol at index 0 is counted is not stated")
        consumed.append(null.pattern)
        return "count+elf_dynsym_undef_named", [("dynsym_undef_named", str(_dynsym_undef(data, info)))], name, \
            consumed
    m2 = None
    if re.search(r"\bentries\b", what):
        m2 = re.search(r"\bentries (?:in|of) (?:the )?[`'\"]?(?P<sec>\.[A-Za-z0-9_.$]{1,15}?)[`'\"]? "
                       r"(?:section|table|array)", text)
    if m2:
        if kind != "elf":
            raise Unread("section entries of an image that is not an ELF")
        sec = m2.group("sec")
        secs = [s for s in (info.get("sections") or []) if s.get("name") == sec]
        if len(secs) != 1:
            raise Unread(f"{len(secs)} sections named {sec}")
        s = secs[0]
        if not s["entsize"] or s["size"] % s["entsize"]:
            raise Unread(f"{sec} states no entry size that divides its size")
        slug = re.sub(r"[^a-z0-9]", "", sec.lower())
        return f"count+elf_entries+{slug}", [("sh_size_over_sh_entsize", str(s["size"] // s["entsize"]))], name, \
            consumed
    raise Unread(f"a count of '{what}' this reader does not read")


def _dynsym_undef(data: bytes, info: dict) -> int:
    secs = [s for s in (info.get("sections") or []) if s.get("name") == ".dynsym"]
    if len(secs) != 1:
        raise Unread(f"{len(secs)} .dynsym sections")
    s = secs[0]
    wide = info["bits"] == 64
    end = "<" if info["ei_data"] == 1 else ">"
    size = 24 if wide else 16
    if s["entsize"] not in (0, size) or s["offset"] + s["size"] > len(data):
        raise Unread(".dynsym is cut or has an odd entry size")
    n = 0
    for k in range(s["size"] // size):
        at = s["offset"] + k * size
        if wide:
            name, _, _, shndx = struct.unpack_from(end + "IBBH", data, at)
        else:
            name, _, _, _, _, shndx = struct.unpack_from(end + "IIIBBH", data, at)
        if shndx == 0 and name != 0:
            n += 1
    return n


# ---------------------------------------------------------------------------- hashes

LITERAL = r"\"([^\"\n]{1,256})\"|`([^`\n]{1,256})`|“([^”\n]{1,256})”|(?<![A-Za-z])'([^'\n]{1,256})'"

ALGOS = [("ror13", r"\bror-?13\b|\brotate[- ]right[- ]13\b"), ("fnv1a", r"\bfnv-?1a\b"), ("fnv1", r"\bfnv-?1(?!a)\b"),
         ("djb2a", r"\bdjb2a\b"), ("djb2", r"\bdjb2(?!a)\b"), ("sdbm", r"\bsdbm\b"), ("crc32", r"\bcrc-?32(?!c)\b"),
         ("md5", r"\bmd5\b"), ("sha1", r"\bsha-?1\b"), ("sha256", r"\bsha-?256\b")]


def _int_hash(algo: str, b: bytes, width: int, seed, text: str) -> int:
    mask = (1 << width) - 1
    if algo == "ror13":
        h = seed or 0
        add_first = bool(re.search(r"\badd\w*\b[^.;]{0,60}?\bthen\b[^.;]{0,20}?\brotat|h\s*=\s*ror(?:32)?\(\s*h\s*\+",
                                   text, re.I))
        rot_first = bool(re.search(r"\brotat\w*\b[^.;]{0,60}?\bthen\b[^.;]{0,20}?\badd|"
                                   r"h\s*=\s*ror(?:32)?\(\s*h\s*,\s*13"
                                   r"\s*\)\s*\+", text, re.I))
        if add_first == rot_first:
            raise Unread("the order of rotate and add is not stated")
        for c in b:
            if rot_first:
                h = ((((h >> 13) | (h << 19)) & 0xFFFFFFFF) + c) & 0xFFFFFFFF
            else:
                h = (h + c) & 0xFFFFFFFF
                h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        return h
    if algo in ("fnv1", "fnv1a"):
        basis, prime = ((0x811C9DC5, 0x01000193) if width == 32 else (0xCBF29CE484222325, 0x100000001B3))
        h = basis if seed is None else seed
        for c in b:
            if algo == "fnv1a":
                h = ((h ^ c) * prime) & mask
            else:
                h = ((h * prime) & mask) ^ c
        return h
    if algo in ("djb2", "djb2a"):
        h = 5381 if seed is None else seed
        for c in b:
            h = ((h * 33) + c) & mask if algo == "djb2" else ((h * 33) ^ c) & mask
        return h
    if algo == "sdbm":
        h = 0 if seed is None else seed
        for c in b:
            h = (c + (h << 6) + (h << 16) - h) & mask
        return h
    if algo == "crc32":
        return zlib.crc32(b) & 0xFFFFFFFF
    raise Unread(f"no integer hash {algo}")


WIDTH = r"\b(32|64)[- ]?bits?\b|\bfnv-?1a?[-_ ]?(32|64)\b|\buint(32|64)\b|\bmod(?:ulo)? 2\^?(32|64)\b"


def _width(text: str, algo: str, rx: str):
    """The hash's stated width: the one width the text states, or, when it states two (`in this 64-bit PE, the
    32-bit FNV-1a of ...`), the one written next to the algorithm's name; two and none next to it is Unread.
    CRC-32 and the digests have their own width, so a width elsewhere in the text is not theirs."""
    if algo in ("crc32", "md5", "sha1", "sha256"):
        return None
    widths = {int(next(g for g in m.groups() if g)) for m in re.finditer(WIDTH, text, re.I)}
    if len(widths) <= 1:
        return widths.pop() if widths else None
    near = {int(next(g for g in m.groups() if g)) for m in
            re.finditer(r"\b(32|64)[- ]?bits?[- ](?:" + rx + r")|(?:" + rx + r")[-_ ]?\(?(32|64)\b", text, re.I)}
    if len(near) == 1:
        return near.pop()
    raise Unread(f"two widths stated ({', '.join(map(str, sorted(widths)))}) and not one next to {algo}")


def _hash(text: str, members: list, fmt):
    found = [(a, rx) for a, rx in ALGOS if re.search(rx, text, re.I)]
    if len(found) != 1:
        raise Unread(f"{len(found)} hash algorithms named")
    algo, rx = found[0]
    consumed = [rx, r"\bhash\w*\b", r"\bdigest\b", r"\bchecksum\b"]
    if algo == "crc32" and re.search(r"castagnoli|crc-?32c|\bbzip2\b|\bmpeg\b", text, re.I):
        raise Unread("a CRC-32 variant this reader does not read")
    width = _width(text, algo, rx)
    if algo in ("fnv1", "fnv1a", "djb2", "djb2a", "sdbm") and width is None:
        raise Unread(f"{algo} with no stated width")
    if algo == "ror13":
        width = width or 32
        if width != 32:
            raise Unread("ror13 that is not 32-bit")
        consumed += [r"\brotat\w*\b", r"\badd\w*\b"]
    if algo == "crc32":
        width = 32
    if algo in ("md5", "sha1", "sha256"):
        width = None
    wpart = "" if width is None else f"+w{width}"
    seed = None
    m = re.search(r"\b(?:initial value|seed|start(?:ing)? (?:at|from|with)|initiali[sz]ed (?:to|with))\s*(?:of |=\s*)?"
                  r"(0x[0-9a-f]+|\d+)", text, re.I)
    if m:
        seed = int(m.group(1), 0)
        consumed.append(re.escape(m.group(0)))
    # the input
    lit = re.findall(LITERAL, text)
    lits = sorted({next(g for g in t if g) for t in lit})
    named = re.findall(r"\b(?:API|function|export|import|symbol|procedure) name ([A-Za-z_][A-Za-z0-9_@?$]{1,127})\b",
                       text)
    name = None
    if lits or named:
        values = set(lits) | set(named)
        if len(values) != 1:
            raise Unread(f"{len(values)} literal inputs")
        source, src = "literal", values.pop()
        wide = re.compile(r"utf-?16(?:-?le| little[- ]endian)?|\bwide\b|unicode", re.I)
        if wide.search(text):
            if re.search(r"utf-?16-?be|big[- ]endian", text, re.I):
                raise Unread("a big-endian UTF-16 input")
            consumed.append(wide.pattern)
            enc = "utf16le"
        else:
            if any(ord(c) > 0x7E or ord(c) < 0x20 for c in src):
                raise Unread("a literal that is not printable ASCII and no encoding stated")
            enc = "ascii"
        fold = None
        up = re.compile(r"\b(?:upper-?cased?|converted to upper ?case|in upper ?case|upper-?case (?:the |its |each )?"
                        r"(?:name|string|input|characters?|letters?))\b", re.I)
        low = re.compile(r"\b(?:lower-?cased?|converted to lower ?case|in lower ?case|lower-?case (?:the |its |each )?"
                         r"(?:name|string|input|characters?|letters?))\b", re.I)
        out_case = re.compile(r"\b(?:upper|lower)[- ]?case (?:hex\w*|digits?)\b", re.I)
        rest = out_case.sub(" ", text)
        if up.search(rest) and low.search(rest):
            raise Unread("both an upper- and a lower-case fold are stated")
        if up.search(rest):
            fold = "upper"
        elif low.search(rest):
            fold = "lower"
        elif re.search(r"\b(?:upper|lower)[- ]?case\b|\bcase[- ]insensitive\b", rest, re.I):
            raise Unread("a case rule this reader does not read")
        if fold:
            src = src.upper() if fold == "upper" else src.lower()
        consumed += [up.pattern, low.pattern, out_case.pattern]
        b = src.encode("utf-16-le" if enc == "utf16le" else "ascii")
        inc = re.compile(r"\b(?:including|with|plus|and|followed by) (?:the |its |a |one )?"
                         r"(?:terminating |trailing |final )?"
                         r"(?:NUL|null)(?: terminator| byte| character| char)?", re.I)
        exc = re.compile(r"\b(?:excluding|without|not including|no) (?:the |any |a |its )?"
                         r"(?:terminating |trailing |final )?"
                         r"(?:NUL|null)(?: terminator| byte| character| char)?", re.I)
        if inc.search(text) and exc.search(text):
            raise Unread("the NUL terminator is both included and excluded")
        nul = "nul" if inc.search(text) else "nonul"
        if nul == "nul":
            b += b"\0\0" if enc == "utf16le" else b"\0"
            consumed.append(inc.pattern)
        elif exc.search(text):
            consumed.append(exc.pattern)
        elif algo == "ror13" and not re.search(r"\bfor each (?:byte|character|char)\b", text, re.I):
            raise Unread("ror13 of a name with no word on the NUL terminator")
        slug = f"hash+{algo}{wpart}+literal+{enc}+{fold or 'asis'}+{nul}" + ("" if seed is None else "+seed")
        method = f"{algo}:{enc}"
    else:
        if re.search(r"\b(?:name|string)\b", text, re.I) and not re.search(SECTION, text) and \
                not re.search(r"\bmember\b", text, re.I):
            raise Unread("the hashed name is not quoted in the text")
        rslug, name, b, _ = _region(text, members, consumed)
        slug = f"hash+{algo}{wpart}+{rslug}" + ("" if seed is None else "+seed")
        method = f"{algo}:{rslug}"
        if algo not in ("crc32", "md5", "sha1", "sha256") and len(b) > SEQ_MAX:
            raise Unread(f"a byte-by-byte hash over {len(b)} bytes (more than {SEQ_MAX})")
    if algo in ("md5", "sha1", "sha256"):
        if seed is not None:
            raise Unread("a seed for a digest")
        value = hashlib.new(algo, b).hexdigest()
        syntax = (fmt or {}).get("syntax") or ""
        if re.search(r"\buppercase\b", syntax, re.I) and not re.search(r"\blowercase\b", syntax, re.I):
            value = value.upper()
        return slug, [(method, value)], name, consumed
    return slug, _int_options(_int_hash(algo, b, width, seed, text), fmt, method, width), name, consumed


def _int_options(n: int, fmt, method: str, width=None) -> list:
    """[(name, value)] of the number in the form its question asks: base 10, or hexadecimal as the syntax states it
    (answer_kinds reads prefix and case); bare and padded to the width when the syntax does not say which, one of
    them when it does."""
    import answer_kinds
    kind = answer_kinds.kind_of(fmt)
    if kind == "integer":
        return [(method, str(n))]
    form = answer_kinds.hex_form(fmt) if kind == "pattern" else None
    if not (answer_kinds.wants_hex(fmt) or form is not None):
        return [(method, str(n))]
    prefix, upper = form if form is not None else (True, False)
    digits = (width or 32) // 4
    bare, padded = f"{n:x}", f"{n:0{digits}x}"
    if upper:
        bare, padded = bare.upper(), padded.upper()
    pre = "" if prefix is False else "0x"
    opts = [(f"{method}:hex", pre + bare), (f"{method}:hex{digits}", pre + padded)]
    syntax = ((fmt or {}).get("syntax") or "").lower()
    if re.search(rf"\b(?:exactly )?{digits}\b|zero-?padded|\bpadded\b|fixed[- ]width", syntax):
        opts = opts[1:]
    elif re.search(r"no leading zeros?|without leading zeros?", syntax):
        opts = opts[:1]
    return opts[:1] if len({v for _, v in opts}) == 1 else opts


# ---------------------------------------------------------------------------- a typed read

TYPED = re.compile(r"\b(?:the )?(?:(?P<t>u8|uint8|u16le|u16be|u32le|u32be|u64le|u64be)|(?P<e>little|big)[- ]endian "
                   r"(?P<w>8|16|32|64)-bit (?:unsigned )?(?:integer|value|word|field|number))(?: value| field)? "
                   r"(?:stored )?at (?:(?P<file>file|byte) )?offset (?P<off>0x[0-9a-f]+|\d+)", re.I)


def _typed(text: str, members: list, fmt):
    m = TYPED.search(text)
    consumed = [TYPED.pattern]
    if m.group("t"):
        typ = m.group("t").lower().replace("uint8", "u8")
    else:
        w = int(m.group("w"))
        typ = "u8" if w == 8 else f"u{w}{'le' if m.group('e').lower() == 'little' else 'be'}"
    off = int(m.group("off"), 0)
    sec = re.search(r"\boffset (?:0x[0-9a-f]+|\d+) (?:of|in|from|into|relative to the start of) " + SECTION, text, re.I)
    name, data, ki = _member(text, members)
    base, where = 0, "file"
    if sec:
        start, size = _section(ki, sec.group("sec"), text, consumed)
        if off + TYPES[typ][1] > size:
            raise Unread("the offset lies past the section's end")
        base, where = start, "section_" + re.sub(r"[^a-z0-9]", "", sec.group("sec").lower())
    elif re.search(r"\bsection\b|\bsegment\b|\brelative\b|\boverlay\b|\btrailer\b|\bwrapper\b|\brecord\b|"
                   r"\bresource\b|\bpayload\b|\bheader\b|\bstructure\b|\btable\b|\bentry\b|\bafter\b|\bpast\b|"
                   r"\bfrom the (?:start|end|beginning)\b|\bunpacked\b|\bdecoded\b|\bdecrypted\b", text, re.I):
        raise Unread("an offset relative to something this reader does not read")
    else:
        tail = text[m.end():]
        if not re.match(r"\s*(?:(?:of|in) (?:the )?(?:whole |entire )?(?:member|file)\b|[.,;:)]|$|and\b|as\b|then\b)",
                        tail, re.I):
            raise Unread("the offset is followed by words this reader does not read")
    fmt_, n = TYPES[typ]
    if base + off + n > len(data):
        raise Unread("the offset lies past the member's end")
    value = struct.unpack_from(fmt_, data, base + off)[0]
    return f"read+{typ}+{where}", _int_options(value, fmt, f"{typ}@{where}", n * 8), name, consumed


# ---------------------------------------------------------------------------- the dispatch

KINDS = [("entropy", re.compile(r"\bentropy\b", re.I)),
         ("hash", re.compile("|".join(rx for _, rx in ALGOS), re.I)),
         ("count", re.compile(r"\bnumber of\b|\bcount\b|\bhow many\b", re.I)),
         ("read", TYPED)]
TRIGGER = re.compile("|".join(rx.pattern for _, rx in KINDS), re.I)


def definition(q: dict, members: list):
    """(key, options, member name, kind) for the definition the question states, None when it states none;
    raises Unread when it states one this module does not compute."""
    text = _clean(q.get("question") or "")
    kinds = [k for k, rx in KINDS if rx.search(text)]
    if not kinds:
        return None
    if len(kinds) != 1:
        raise Unread(f"the text states {' and '.join(kinds)} at once")
    kind = kinds[0]
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else None
    if kind == "entropy":
        slug, opts, name, consumed = _entropy(text, members)
    elif kind == "hash":
        slug, opts, name, consumed = _hash(text, members, fmt)
    elif kind == "count":
        slug, opts, name, consumed = _count(text, members)
    else:
        slug, opts, name, consumed = _typed(text, members, fmt)
    left = _unread(text, consumed + [SECTION, r"\bmember \d+\b", LITERAL])
    if left:
        raise Unread(f"a qualifier this reader does not read ({', '.join(left)})")
    return KEY + slug + "+t" + text_tag(q.get("question")), opts, name, kind


def text_tag(question) -> str:
    """Eight hex digits that name the question text (judged_forms.norm_text: lower case, blanks folded, the day
    masked), the last part of every key: the definition the parser read is only what it read, so a reading the
    judge accepts for one text never answers another text plain, whatever word of it the parser skipped (the
    review of row 422). The same text on the next variant or day keeps its key."""
    import judged_forms
    return f"{zlib.crc32(judged_forms.norm_text(question or '').encode()):08x}"


def _field(qid: str) -> str:
    return re.sub(r"^set\d+\.", "", qid).split("_", 1)[-1]


def asks(field: str, gen=None) -> bool:
    """Whether an id of this field may be answered here: never a config, HCFG, overlay or trailer id, and never a
    field generic.py knows."""
    if SKIP_FIELD.search(field):
        return False
    return not (gen is not None and callable(getattr(gen, "knows", None)) and gen.knows(field))


def answers(prefix: str, qs: list, got: dict, members: list, gen=None, log=None) -> dict:
    """{qid: one-option pick} for the prefix's ids still None whose question states a definition this module
    computes. {} when none does."""
    import labels
    log = log or (lambda line: print(line, file=sys.stderr))
    out = {}
    for q in qs:
        qid = q.get("qid") or q.get("id")
        if got.get(qid) is not None or not asks(_field(qid), gen):
            continue
        if not TRIGGER.search(q.get("question") or ""):
            continue
        try:
            found = definition(q, members)
        except Unread as e:
            log(f"[defined] {qid}: the question names a computation; not answered: {e}")
            continue
        except Exception as e:     # one field's failure costs that field
            log(f"[defined] {qid}: stated_define.py raised {type(e).__name__}: {e}")
            continue
        if found is None:
            continue
        key, opts, name, kind = found
        value = labels.pick(key, opts)
        if value is None:
            log(f"[defined] {qid}: {key[len(KEY):]}: every option is rejected for the key; not answered")
            continue
        out[qid] = value
        log(f"[defined] {qid}: {key[len(KEY):]} = {opts[0][1]} from {name or 'the literal the question states'} "
            f"({'plain: the judge accepted the reading' if not labels.is_unsure(value) else 'a one-option pick'})")
    return out
