#!/usr/bin/env python3
"""Lane-agnostic render-candidates helper (the Day-23 trick class, generalized to every lane).

The single most expensive adaptation class is NOT a missing reader: it is a value we READ
correctly whose RENDERING or ORDER the author chose and the judge has never accepted for this
key. Day 23: `sqlite.page_size_bytes` read 1024 but the one plain spelling we sent was wrong and
sank a 28-id batch; `macho.cpu_type_set` read `["0x0100000c"]` in file order, judge wanted it
SORTED; a decoy `.wav` was really Opus (a container trick, handled elsewhere). The metadata lane
has `solvers/metadata-forensics/format_candidates.py` for exactly this, but it lives inside the
metadata tree, is never auto-invoked, and no other lane can reach it.

This module is the same primitive, in `solvers/common/` so warmups, script-analysis, binary,
mobile, metadata and every toolkit can import it, with two generalizations:

  T2 (the re-speller): `render(value, kind)` turns a KNOWN value plus a kind hint into the ranked
     plausible spellings (case, zero-pad vs minimal, 0x prefix, base, separators, GUID forms,
     endianness as DIFFERENT candidates, ...).
  T3 (the order/collation axis): any collection answer whose order is unjudged is emitted as
     document-order, sorted, sorted+dedup and descending candidates -- the exact macho/zip/
     synthesis-order class.

Plus a generic kind CLASSIFIER so a reader that read a value but cannot name its spelling gets
candidates with no bespoke wiring: `classify(answer_format, value)` -> a kind, and
`pick_auto(key, value, answer_format)` = classify + pick.

NEVER-WRONG CONTRACT (the whole point):
  * Every public answer goes through `labels.candidates`, so it is a `??`-candidate string, NEVER a
    plain value, until the judge accepts a hypothesis NAME for the key. A wrong plain answer -- the
    thing that sinks an all-or-nothing batch -- is structurally impossible here.
  * The caller already READ `value` from the bytes (that is where never-guess lives). This module
    reads no bytes and makes no network call; it only decides how to SPELL / ORDER a value that is
    already established.
  * Unknown or ambiguous -> `None` (never a default, never the most common value).
  * Bounded: at most `labels.MAX_OPTIONS` (12) options, author-most-common first, de-duplicated,
    deterministic. A renderer never raises into a solver (a raise is [] / None).
  * A candidate key ends in `labels.CANDIDATE_MARK`, so `tools/verify.py` probes it on the untimed
    base and the runners probe it only on an attempt with NO deadline (row 346). With a deadline
    nothing of it is sent.

Adoption (next cycle; this module touches no per-lane reader):
    import render_candidates as RC           # solvers/common is on sys.path for every lane
    # a reader / day_patch that read V but cannot name its spelling for the asked key+shape:
    return RC.pick_auto("binary.page_size/sqlite", V, q.get("answer_format"))
    # or, when the kind is known:
    return RC.pick("metadata.sqlite/page_size_bytes", 1024, "integer")
    # a collection whose order is unjudged:
    return RC.pick("metadata.format/macho.cpu_type_set", ["0x0100000c"], "list_or_intlist")

`render(value, kind)` and `order_axis(seq)` are pure (no ledger, no key) and so are unit-testable;
`pick`/`pick_auto` consult `labels` for what the judge has accepted.

The composition axis (B-119): `compose_axis(fields)` enumerates field subset x order x rendering x join
for a string BUILT from several read values (a constructed marker), for offline comparison with a check
the caller holds; `compose_size` sizes that space. The `decimal` kind spells a real number at fixed
decimal places. Neither is reached by `classify`, so no existing candidate list changes.
"""
from __future__ import annotations

import html
import itertools
import math
import re
import sys
import unicodedata
import urllib.parse
from collections import namedtuple
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
import labels  # noqa: E402  (the unsure-answer contract; candidates()/pick()/MAX_OPTIONS)

MAX = labels.MAX_OPTIONS   # 12


# --------------------------------------------------------------------------- scalar helpers

def _as_int(value):
    """An int from an int, a hex/decimal str (0x or bare), or big-endian bytes. None otherwise."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(bytes(value), "big") if value else 0
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            return int(s, 16) if s[:2].lower() == "0x" else int(s)
        except ValueError:
            try:
                return int(s, 16)
            except ValueError:
                return None
    return None


def _hex_digits(value, width_bits=None):
    """Lowercase hex digits (no 0x), zero-padded to width_bits/4 if given. bytes keep their own
    length; an int with no width is minimal rounded up to a whole byte. None if not a number."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value).hex()
    else:
        n = _as_int(value)
        if n is None or n < 0:
            return None
        raw = format(n, "x")
        if len(raw) % 2:
            raw = "0" + raw
    if width_bits:
        raw = raw.rjust(width_bits // 4, "0")
    return raw


def _compact_json(obj):
    import json
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _dedup(options):
    """Keep the first (name, value) per distinct rendered string; cap at MAX. A value that cannot be
    rendered (None) is dropped. Names kept unique by suffixing a counter, so a candidate list never
    carries two options under one name (labels.candidates would otherwise drop the later one)."""
    out, seen_vals, seen_names = [], set(), set()
    for name, val in options:
        if val is None:
            continue
        if not isinstance(val, str):
            val = _compact_json(val)
        if val in seen_vals:
            continue
        nm = name
        i = 2
        while nm in seen_names:
            nm = f"{name}_{i}"
            i += 1
        out.append((nm, val))
        seen_vals.add(val)
        seen_names.add(nm)
        if len(out) >= MAX:
            break
    return out


# --------------------------------------------------------------------------- per-kind renderers
# Each returns [(hypothesis_name, rendered_value), ...], author-most-common FIRST, before _dedup/cap.
# A name names the HYPOTHESIS (the spelling), never the value, so an accepted name carries to the
# next variant where it answers that variant's own value.

def _r_integer(value, width_bits=None, with_base=False, **_):
    n = _as_int(value)
    if n is None:
        return []
    opts = [("integer", str(n))]
    if n >= 0:
        minimal = format(n, "x")           # 0x400
        byte_even = _hex_digits(n)         # 0x0400
        if width_bits:
            opts.append(("hex_0x_padded", "0x" + _hex_digits(n, width_bits)))
        opts.append(("hex_0x", "0x" + minimal))
        opts.append(("hex_0x_byte", "0x" + byte_even))
        opts.append(("hex_bare", minimal))
        opts.append(("hex_bare_upper", minimal.upper()))
        if with_base:
            opts.append(("octal_0o", "0o" + format(n, "o")))
            opts.append(("binary_0b", "0b" + format(n, "b")))
    return opts


def _r_hex(value, width_bits=None, **_):
    lo = _hex_digits(value, width_bits)
    lo_min = _hex_digits(value)
    if lo is None:
        return []
    opts = []
    if width_bits:
        opts.append(("hex_0x_padded_lower", "0x" + lo))
        opts.append(("hex_padded_lower", lo))
    opts += [
        ("hex_0x_lower", "0x" + lo_min),
        ("hex_lower", lo_min),
        ("hex_0x_upper", "0x" + lo_min.upper()),
        ("hex_upper", lo_min.upper()),
    ]
    return opts


def _r_base(value, width_bits=None, **_):
    """One number in several bases: decimal, 0x hex (padded first if width given), octal, binary."""
    n = _as_int(value)
    if n is None or n < 0:
        return []
    opts = [("base10", str(n))]
    if width_bits:
        opts.append(("base16_0x_padded", "0x" + _hex_digits(n, width_bits)))
    opts += [("base16_0x", "0x" + format(n, "x")), ("base16_bare", format(n, "x")),
             ("base8_0o", "0o" + format(n, "o")), ("base2_0b", "0b" + format(n, "b"))]
    return opts


def _int_from_bytes(value, **_):
    """Endianness as DIFFERENT candidates: the big- and little-endian integer of raw bytes, decimal
    and 0x each. Only for a bytes value of 1..8 bytes (a wider field is rarely an integer answer)."""
    if not isinstance(value, (bytes, bytearray)) or not (1 <= len(value) <= 8):
        return []
    be = int.from_bytes(bytes(value), "big")
    le = int.from_bytes(bytes(value), "little")
    opts = [("big_endian", str(be)), ("big_endian_0x", "0x" + format(be, "x"))]
    if le != be:
        opts += [("little_endian", str(le)), ("little_endian_0x", "0x" + format(le, "x"))]
    return opts


def _guid_hex32(value):
    if isinstance(value, (bytes, bytearray)) and len(value) == 16:
        return bytes(value).hex()
    if isinstance(value, str):
        digs = "".join(c for c in value if c in "0123456789abcdefABCDEF").lower()
        return digs if len(digs) == 32 else None
    return None


def _hyphenate(h32):
    return f"{h32[0:8]}-{h32[8:12]}-{h32[12:16]}-{h32[16:20]}-{h32[20:32]}"


def _r_guid(value, **_):
    h = _guid_hex32(value)
    if h is None:
        return []
    hy = _hyphenate(h)
    opts = [
        ("hyphen_lower", hy),
        ("hyphen_upper", hy.upper()),
        ("braces_upper", "{" + hy.upper() + "}"),
        ("braces_lower", "{" + hy + "}"),
        ("compact_lower", h),
        ("compact_upper", h.upper()),
    ]
    if isinstance(value, str) and value.strip():
        opts.insert(0, ("as_stored", value.strip()))
    return opts


def _r_message_id(value, **_):
    if not isinstance(value, str):
        return []
    s = value.strip()
    inner = s
    if s.startswith("<") and s.endswith(">") and s.count("<") == 1 and s.count(">") == 1:
        inner = s[1:-1]
    bracketed = inner if inner.startswith("<") else "<" + inner + ">"
    return [("with_angle", bracketed), ("without_angle", inner)]


# --------------------------------------------------------------------------- the order/collation axis (T3)

def _order_variants(seq, numeric):
    """Document order, then ascending sorted, then sorted+dedup, then descending -- the collations a
    judge picks between for a collection whose order is unjudged (Day 23 zip names / macho types /
    synthesis order). Each is a list of items; duplicates and no-op variants are not emitted."""
    doc = list(seq)
    try:
        srt = sorted(doc)
    except TypeError:
        srt = doc
    out = [("document_order", doc)]
    if srt != doc:
        out.append(("sorted", srt))
    # sorted + de-duplicated (keep first occurrence under sorted order)
    seen, dedup = set(), []
    for x in srt:
        if x not in seen:
            seen.add(x)
            dedup.append(x)
    if dedup != srt and all(dedup != v for _, v in out):
        out.append(("sorted_dedup", dedup))
    # document order de-duplicated
    seen, dd = set(), []
    for x in doc:
        if x not in seen:
            seen.add(x)
            dd.append(x)
    if dd != doc and all(dd != v for _, v in out):
        out.append(("document_order_dedup", dd))
    try:
        desc = sorted(doc, reverse=True)
    except TypeError:
        desc = None
    if desc is not None and desc != doc and all(desc != v for _, v in out):
        out.append(("descending", desc))
    return out


_SEPS = (("comma", ","), ("comma_space", ", "), ("space", " "), ("pipe", "|"))


def _render_list(seq, numeric, prefer_json=False):
    opts = []
    for oname, items in _order_variants(seq, numeric):
        if numeric:
            texts = [str(int(x)) for x in items]
            jsonable = [int(x) for x in items]
        else:
            texts = [str(x) for x in items]
            jsonable = list(items)
        json_opt = (f"{oname}+json", _compact_json(jsonable))
        sep_opts = [(f"{oname}+{sname}", sep.join(texts)) for sname, sep in _SEPS]
        if prefer_json:
            opts.append(json_opt)
            opts.extend(sep_opts)
        else:
            opts.extend(sep_opts)
            opts.append(json_opt)
    return opts


def _r_list(value, prefer_json=False, **_):
    if not isinstance(value, (list, tuple)):
        return []
    return _render_list(value, numeric=False, prefer_json=prefer_json)


def _r_intlist(value, prefer_json=False, **_):
    if not isinstance(value, (list, tuple)):
        return []
    try:
        ints = [int(x) for x in value]
    except (TypeError, ValueError):
        return []
    return _render_list(ints, numeric=True, prefer_json=prefer_json)


def _r_list_or_intlist(value, prefer_json=False, **_):
    """A JSON-array answer whose element type is not pinned: numeric collation if every element is an
    int-like non-string, else string collation. The macho/zip case (hex-string elements) lands here
    as strings (so `["0x0100000c"]` is spelled as a JSON array of strings, sorted lexically)."""
    if not isinstance(value, (list, tuple)):
        return []
    numeric = all(isinstance(x, int) and not isinstance(x, bool) for x in value) and len(value) > 0
    return _render_list(value, numeric=numeric, prefer_json=prefer_json)


def _r_bool(value, **_):
    if isinstance(value, str):
        s = value.strip().lower()
        if s not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
            return []
        b = s in ("1", "true", "yes", "on")
    else:
        b = bool(value)
    t = [("true_false", "true"), ("True_False", "True"), ("one_zero", "1"), ("yes_no", "yes"), ("on_off", "on")]
    f = [("true_false", "false"), ("True_False", "False"), ("one_zero", "0"), ("yes_no", "no"), ("on_off", "off")]
    return t if b else f


def _r_dims(value, **_):
    if not (isinstance(value, (list, tuple)) and len(value) == 2):
        return []
    try:
        w, h = int(value[0]), int(value[1])
    except (TypeError, ValueError):
        return []
    return [
        ("x_lower", f"{w}x{h}"),
        ("x_upper", f"{w}X{h}"),
        ("star", f"{w}*{h}"),
        ("spaced_x", f"{w} x {h}"),
        ("json", _compact_json([w, h])),
    ]


def _r_digest(value, **_):
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).hex()
    if not isinstance(value, str) or not value.strip():
        return []
    s = value.strip()
    return [("lower", s.lower()), ("upper", s.upper())]


def _r_path(value, **_):
    if not isinstance(value, str) or not value.strip():
        return []
    s = value.strip()
    fwd = s.replace("\\", "/")
    back = s.replace("/", "\\")
    base = fwd.rstrip("/").split("/")[-1]
    return [("forward_slash", fwd), ("back_slash", back), ("basename", base)]


def _r_version(value, **_):
    if isinstance(value, (list, tuple)):
        try:
            parts = [str(int(x)) for x in value]
        except (TypeError, ValueError):
            return []
        dotted = ".".join(parts)
    elif isinstance(value, str) and value.strip():
        dotted = value.strip().lstrip("vV")
        parts = dotted.split(".")
    else:
        return []
    trimmed = ".".join(parts).rstrip("0").rstrip(".") if len(parts) > 1 else dotted
    opts = [("dotted", dotted)]
    if trimmed and trimmed != dotted:
        opts.append(("dotted_trimmed", trimmed))
    if len(parts) >= 2 and parts[1].isdigit():
        opts.append(("minor_2_digits", parts[0] + "." + parts[1].zfill(2)))
    return opts


def _r_encoding(value, **_):
    if not isinstance(value, str) or not value.strip():
        return []
    s = value.strip().lower()
    compact = s.replace("-", "")
    return [
        ("hyphen_lower", s),
        ("compact_lower", compact),
        ("hyphen_upper", s.upper()),
        ("compact_upper", compact.upper()),
    ]


def _r_timestamp(value, **_):
    """A point in time as DIFFERENT renderings a judge may want: ISO 8601 (with Z, with offset, with
    a space), epoch seconds and millis. Input is epoch seconds (int/float) or an ISO string.
    Timezone-ambiguous inputs are rendered as given; this never invents an offset."""
    import datetime as _dt
    if isinstance(value, bool):
        return []
    dt = None
    epoch = None
    if isinstance(value, (int, float)):
        epoch = int(value)
        try:
            dt = _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return []
    elif isinstance(value, str) and value.strip():
        s = value.strip()
        try:
            dt = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is not None:
                epoch = int(dt.timestamp())
        except ValueError:
            return [("as_stored", s)]
    else:
        return []
    iso = dt.replace(microsecond=0).isoformat()
    iso_z = iso.replace("+00:00", "Z")
    iso_no_tz = iso.split("+")[0].split("Z")[0]
    opts = [("iso8601_z", iso_z), ("iso8601_offset", iso), ("iso8601_space", iso_no_tz.replace("T", " "))]
    if epoch is not None:
        opts.append(("epoch_seconds", str(epoch)))
        opts.append(("epoch_millis", str(epoch * 1000)))
    return opts


# --------------------------------------------------------------------------- the unicode / encoding axis (#8)
#
# The second deception axis (ticket #8): a value READ correctly from the bytes can still carry a Unicode or
# encoding layer the judge normalised away. The judge may store the NFKC form of a compatibility-ligature
# string, the ASCII form of a homoglyph/IDN host, the zero-width-stripped form of a padded token, or the
# percent-/HTML-entity-decoded plaintext. Each is the SAME established value spelled through a different
# normalisation or decode layer, so it is a candidate rendering of ONE fact -- never a plain answer and never
# a value found from scratch (the caller already read it; that is where never-guess lives). These renderers
# are pure, bounded, and never raise: an input they cannot touch yields []; a layer that does not change the
# value is dropped; every output is a str. The classifier deliberately never auto-selects these kinds (a
# clean scalar would otherwise sprout spurious encodings), so they are reached only explicitly, or through
# `deception_axis` (the re-speller's full axis, used by the proposer's re-speller tier in propose.py).

_AXIS_MAX_LEN = 4096   # a single answer field is never this long; a longer value is not an encoding puzzle

# Invisible / zero-width / bidi-control code points a deception commonly hides inside a token.
_ZERO_WIDTH = (
    "​‌‍⁠﻿­᠎"   # ZWSP ZWNJ ZWJ WJ BOM SHY MVS
    "‎‏‪‫‬‭‮"   # LRM RLM + bidi embeddings/overrides
    "⁡⁢⁣⁤⁦⁧⁨⁩"  # invisible operators + bidi isolates
)
_ZERO_WIDTH_TABLE = {ord(c): None for c in _ZERO_WIDTH}

# A curated confusable/homoglyph fold to ASCII. NFKC already folds compatibility forms (fullwidth, ligatures)
# but NOT cross-script lookalikes (Cyrillic/Greek), so this covers the classic look-alike-domain/name trick.
_CONFUSABLES = {
    # Cyrillic -> Latin
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j",
    # Greek -> Latin
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v",
    # punctuation lookalikes
    "–": "-", "—": "-", "−": "-", "‐": "-", "‑": "-",
    "“": '"', "”": '"', "‘": "'", "’": "'",
}


def _printable_text(text) -> bool:
    """A decoded string that reads as text: non-empty and every char printable or ordinary whitespace."""
    return bool(text) and all(ch.isprintable() or ch in "\t\n\r " for ch in text)


def _looks_hostname(text) -> bool:
    return bool(text) and " " not in text and "/" not in text and "@" not in text and len(text) <= 253


def _idna_forms(text):
    """(name, rendered) IDNA/punycode forms of a host-like string: the Unicode form of an `xn--` host, and
    the `xn--` form of a Unicode host. [] when neither applies. Never raises (idna/punycode validate)."""
    out = []
    low = text.strip()
    if not low:
        return out
    if "xn--" in low.lower():
        try:
            parts, decoded, changed = low.split("."), [], False
            for p in parts:
                if p.lower().startswith("xn--") and len(p) > 4:
                    decoded.append(p[4:].encode("ascii").decode("punycode"))
                    changed = True
                else:
                    decoded.append(p)
            if changed:
                out.append(("idna_unicode", ".".join(decoded)))
        except Exception:  # noqa: BLE001 - a punycode label that will not decode is simply not offered
            pass
    if any(ord(c) > 127 for c in low) and _looks_hostname(low):
        try:
            out.append(("idna_punycode", low.encode("idna").decode("ascii")))
        except Exception:  # noqa: BLE001 - not a valid IDNA host -> no punycode candidate
            pass
    return out


def _r_unicode(value, **_):
    """Text-layer deception renderings of a STRING, author-most-common first: as-stored, then the forms that
    DIFFER from it -- NFC/NFKC/NFD/NFKD, zero-width/invisible stripped (raw and NFKC'd), homoglyph->ASCII fold
    (raw and NFKC'd), percent-decode (one layer and to a fixpoint), HTML-entity decode, and IDNA/punycode.
    [] for a non-string, the empty string, an over-long value, or a value no layer changes (nothing to spell)."""
    if not isinstance(value, str) or not value or len(value) > _AXIS_MAX_LEN:
        return []
    s = value
    opts, seen = [], {s}

    def add(name, text):
        if isinstance(text, str) and text and text != s and text not in seen:
            seen.add(text)
            opts.append((name, text))

    for form in ("NFC", "NFKC", "NFD", "NFKD"):
        try:
            add(form.lower(), unicodedata.normalize(form, s))
        except Exception:  # noqa: BLE001
            pass
    stripped = s.translate(_ZERO_WIDTH_TABLE)
    add("strip_zero_width", stripped)
    try:
        add("strip_zero_width_nfkc", unicodedata.normalize("NFKC", stripped))
    except Exception:  # noqa: BLE001
        pass
    folded = "".join(_CONFUSABLES.get(c, c) for c in s)
    add("homoglyph_ascii", folded)
    try:
        add("homoglyph_ascii_nfkc", unicodedata.normalize("NFKC", folded))
    except Exception:  # noqa: BLE001
        pass
    if "%" in s:
        try:
            add("percent_decoded", urllib.parse.unquote(s, errors="strict"))
            fx = s
            for _ in range(3):
                nxt = urllib.parse.unquote(fx, errors="strict")
                if nxt == fx:
                    break
                fx = nxt
            add("percent_decoded_fixpoint", fx)
        except Exception:  # noqa: BLE001
            pass
    if "&" in s:
        try:
            add("html_unescaped", html.unescape(s))
        except Exception:  # noqa: BLE001
            pass
    for name, text in _idna_forms(s):
        add(name, text)
    if not opts:
        return []
    return [("as_stored", s)] + opts


_REDECODE = (("utf8", "utf-8"), ("utf16le", "utf-16-le"), ("utf16be", "utf-16-be"), ("utf16_bom", "utf-16"),
             ("utf32le", "utf-32-le"), ("utf32be", "utf-32-be"), ("latin1", "latin-1"), ("cp1252", "cp1252"),
             ("ascii", "ascii"), ("utf8_sig", "utf-8-sig"))


def _r_redecode(value, **_):
    """Byte re-decode renderings of raw BYTES: the same bytes read as utf-8 / utf-16 (LE, BE, BOM) / utf-32 /
    latin-1 / cp1252 / ascii / utf-8-sig, each with a leading BOM stripped, keeping only the decodes that read
    as text and are distinct. [] for a non-bytes value, empty bytes, an over-long blob, or no text decode."""
    if not isinstance(value, (bytes, bytearray)):
        return []
    raw = bytes(value)
    if not raw or len(raw) > _AXIS_MAX_LEN:
        return []
    opts, seen = [], set()
    for name, enc in _REDECODE:
        try:
            text = raw.decode(enc)
        except Exception:  # noqa: BLE001 - a codec that cannot read these bytes is skipped
            continue
        text = text.lstrip("﻿")
        if _printable_text(text) and text not in seen:
            seen.add(text)
            opts.append((name, text))
    return opts


_DECIMAL_RE = re.compile(r"\A[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\Z")
_DECIMAL_PLACES = (1, 2, 3, 4, 5, 6, 0, 7, 8)   # the places an author prints, most common first


def _r_decimal(value, max_places=8, **_):
    """A real number at fixed decimal places (B-119): `dp_4` is `31.4072`, `dp_6` is `0.000300`. An author
    who hashes or prints a coordinate, an offset or a distance picks the places, and the file rarely says
    which: each count is a different candidate. Then the shortest round-trip form (`repr`), and, for a
    string input, the spelling as stored when no other option equals it. Input: an int, a float or a plain
    decimal string. [] for a bool, a NaN or infinity, or text that is not one number."""
    if isinstance(value, bool):
        return []
    stored = None
    if isinstance(value, str):
        stored = value.strip()
        if not _DECIMAL_RE.match(stored):
            return []
        num = float(stored)
    elif isinstance(value, (int, float)):
        num = float(value)
    else:
        return []
    if num != num or num in (float("inf"), float("-inf")):
        return []
    try:
        top = max(0, min(8, int(max_places)))
    except (TypeError, ValueError):
        top = 8
    opts = [(f"dp_{n}", format(num, f".{n}f")) for n in _DECIMAL_PLACES if n <= top]
    opts.append(("shortest", repr(num)))
    if stored is not None:
        opts.append(("as_stored", stored))
    return opts


_KINDS = {
    "integer": _r_integer,
    "int": _r_integer,
    "hex": _r_hex,
    "base": _r_base,
    "int_from_bytes": _int_from_bytes,
    "endianness": _int_from_bytes,
    "guid": _r_guid,
    "uuid": _r_guid,
    "message_id": _r_message_id,
    "list": _r_list,
    "intlist": _r_intlist,
    "list_or_intlist": _r_list_or_intlist,
    "collection": _r_list_or_intlist,
    "bool": _r_bool,
    "boolean": _r_bool,
    "dims": _r_dims,
    "dimensions": _r_dims,
    "digest": _r_digest,
    "hash": _r_digest,
    "path": _r_path,
    "version": _r_version,
    "encoding": _r_encoding,
    "charset": _r_encoding,
    "timestamp": _r_timestamp,
    "datetime": _r_timestamp,
    # the decimal-places axis (B-119); reached explicitly, never by classify
    "decimal": _r_decimal,
    "float": _r_decimal,
    # the unicode / encoding deception axis (#8); reached explicitly or via deception_axis, never by classify
    "unicode": _r_unicode,
    "text": _r_unicode,
    "normalize": _r_unicode,
    "redecode": _r_redecode,
    "bytes_text": _r_redecode,
}

KINDS = tuple(dict.fromkeys(_KINDS))


# --------------------------------------------------------------------------- public API

def render(value, kind, **opts):
    """Ordered [(hypothesis_name, rendered_value), ...] for a KNOWN value, author-most-common first,
    at most MAX, each rendered value distinct. [] when the kind is unknown or the value cannot be
    rendered in it. No bytes read, nothing guessed: the caller established `value`, this only spells
    or orders it. Pure, so testable with no ledger. A renderer never raises into a solver."""
    fn = _KINDS.get(str(kind).strip().lower())
    if fn is None:
        return []
    try:
        raw = fn(value, **opts)
    except Exception:  # noqa: BLE001 - a renderer must never raise into a solver
        return []
    return _dedup(raw)


def render_named(value, kind, **opts):
    """Every (hypothesis_name, rendered_value) of the kind, in `render`'s order, with NO de-duplication
    and no cap: the lookup for spelling a value under a rendering known by NAME (a convention learned on
    another value, B-119). `render` keeps one name per distinct text, so for the tag `1234` it drops
    `hex_0x_upper` (the same text as `hex_0x_lower`); a caller told "this field is `hex_0x_upper`" still
    needs that name to resolve. Never a candidate list: `render` is. [] as `render` gives it."""
    fn = _KINDS.get(str(kind).strip().lower())
    if fn is None:
        return []
    try:
        raw = fn(value, **opts)
    except Exception:  # noqa: BLE001 - a renderer must never raise into a solver
        return []
    return [(name, val if isinstance(val, str) else _compact_json(val)) for name, val in raw if val is not None]


def order_axis(seq, numeric=None, prefer_json=False):
    """The T3 collation axis alone, as [(name, rendered)] candidate options: document order, sorted,
    sorted+dedup, descending, each in the natural separator/json renderings. [] for a non-sequence.
    `numeric` forces numeric sort (default: inferred, numeric only when no element is a str)."""
    if not isinstance(seq, (list, tuple)):
        return []
    if numeric is None:
        numeric = all(isinstance(x, int) and not isinstance(x, bool) for x in seq) and len(seq) > 0
    try:
        return _dedup(_render_list(seq, numeric=bool(numeric), prefer_json=prefer_json))
    except Exception:  # noqa: BLE001
        return []


# --------------------------------------------------------------------------- the composition axis (B-119)
#
# A constructed answer (a marker, a witness, a checksum) is ONE string built from several values that were
# each read correctly: which values, in which order, each in which spelling, joined by what. The files do
# not say, so every choice is an axis. `compose_axis` enumerates field subset x order x per-field rendering
# x join, best first, for OFFLINE use only: the caller hashes each text and compares it with a check it
# holds (an in-file tag, a known digest). The space is far larger than MAX, so nothing here is ever offered
# to a judge as it stands: a caller that wants to send takes its ranked survivors through
# `labels.candidates` like any candidate list. The spelling of each value still comes from `render`.

JOINS = (("colon", ":"), ("none", ""), ("pipe", "|"), ("comma", ","), ("semicolon", ";"),
         ("underscore", "_"), ("dash", "-"), ("space", " "), ("newline", "\n"))
COMPOSE_MAX_FIELDS = 10    # 10 fields already give 9.8 million orders of subsets: more is a caller's mistake

Composed = namedtuple("Composed", "fields renders join text")
Composed.__doc__ = """One composition: the field names in order, the rendering name used for each, the join's
name (None when one field is used: nothing is joined) and the composed text."""


def _compose_args(fields, joins, min_fields, max_fields, max_deviations):
    """The checked arguments of compose_axis / compose_size. ValueError names what is wrong with the CALL
    (never with a value: a value that cannot be rendered is the caller's to leave out)."""
    flds = []
    for item in fields or ():
        if not (isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str) and item[0]):
            raise ValueError("compose: each field is (name, [(render name, text), ...])")
        name, options = item
        if not isinstance(options, (list, tuple)) or not all(
                isinstance(o, (list, tuple)) and len(o) == 2 for o in options):
            raise ValueError(f"compose: field {name!r}: renderings are (render name, text) pairs")
        opts = [(str(n), t) for n, t in options if isinstance(t, str)]
        if not opts:
            raise ValueError(f"compose: field {name!r} has no rendering")
        if len({n for n, _ in opts}) != len(opts):
            raise ValueError(f"compose: field {name!r} names a rendering twice")
        flds.append((name, opts))
    if not flds:
        raise ValueError("compose: no fields")
    if len({name for name, _ in flds}) != len(flds):
        raise ValueError("compose: a field name is used twice")
    if len(flds) > COMPOSE_MAX_FIELDS:
        raise ValueError(f"compose: {len(flds)} fields; at most {COMPOSE_MAX_FIELDS} (choose a subset first)")
    jns = [(str(n), str(s)) for n, s in (JOINS if joins is None else joins)]
    if not jns:
        raise ValueError("compose: no join")
    n = len(flds)
    hi = n if max_fields is None else int(max_fields)
    lo = int(min_fields)
    if not 1 <= lo <= hi <= n:
        raise ValueError(f"compose: need 1 <= min_fields <= max_fields <= {n}, got {lo} and {hi}")
    dmax = n if max_deviations is None else int(max_deviations)
    if dmax < 0:
        raise ValueError(f"compose: max_deviations must be >= 0, got {dmax}")
    return flds, jns, lo, hi, min(dmax, n)


def compose_axis(fields, joins=None, min_fields=1, max_fields=None, max_deviations=None, permute=True,
                 limit=None):
    """Yield `Composed(fields, renders, join, text)` for every way of building one string from `fields`:
    a subset of at least `min_fields` and at most `max_fields` of them, in every order (`permute=False`
    keeps the given order), each field in one of its renderings, joined by one of `joins` (JOINS: colon
    first; one field alone is not joined).

    fields  [(name, [(render name, text), ...]), ...] in the caller's best order; each field's renderings
            best first, as `render` returns them. The first rendering is the field's default.

    Best first, so a `limit` cuts the least likely part: by the number of fields NOT in their default
    rendering (0, then 1, ... up to `max_deviations`), then larger subsets before smaller, then the given
    order before the other orders, then the joins in order. Deterministic. `limit` stops after that many
    compositions; `compose_size` gives the size of the whole space, so a caller can say what it left out.
    Two compositions may spell the same text (a rendering that coincides, an empty text): they are
    different hypotheses and both are yielded. ValueError for a malformed call."""
    flds, jns, lo, hi, dmax = _compose_args(fields, joins, min_fields, max_fields, max_deviations)
    if limit is not None and int(limit) <= 0:
        return
    n, done = len(flds), 0
    for dev in range(dmax + 1):
        for k in range(hi, lo - 1, -1):
            if dev > k:
                continue
            use_joins = jns if k > 1 else [(None, "")]
            for subset in itertools.combinations(range(n), k):
                for order in (itertools.permutations(subset) if permute else (subset,)):
                    names = tuple(flds[i][0] for i in order)
                    base_r = [flds[i][1][0][0] for i in order]
                    base_t = [flds[i][1][0][1] for i in order]
                    for where in itertools.combinations(range(k), dev):
                        alts = [flds[order[p]][1][1:] for p in where]
                        if not all(alts):
                            continue
                        for picks in itertools.product(*alts):
                            rnames, texts = list(base_r), list(base_t)
                            for p, (rname, text) in zip(where, picks):
                                rnames[p], texts[p] = rname, text
                            for jname, sep in use_joins:
                                yield Composed(names, tuple(rnames), jname, sep.join(texts))
                                done += 1
                                if limit is not None and done >= int(limit):
                                    return


def compose_size(fields, joins=None, min_fields=1, max_fields=None, max_deviations=None, permute=True):
    """How many compositions `compose_axis` yields for the same arguments with no `limit`, computed
    without enumerating them."""
    flds, jns, lo, hi, dmax = _compose_args(fields, joins, min_fields, max_fields, max_deviations)
    total = 0
    for k in range(lo, hi + 1):
        orders = math.factorial(k) if permute else 1
        njoins = len(jns) if k > 1 else 1
        for subset in itertools.combinations(range(len(flds)), k):
            ways = [1] + [0] * dmax      # ways[d]: choices of d deviating fields and their renderings
            for i in subset:
                extra = len(flds[i][1]) - 1
                for d in range(dmax, 0, -1):
                    ways[d] += ways[d - 1] * extra
            total += orders * njoins * sum(ways)
    return total


def pick(key, value, kind, **opts):
    """`labels.candidates(key, render(value, kind))`: an unsure candidate pick over the plausible
    renderings of a known value. NEVER plain before the judge accepts a hypothesis for `key`, so it
    can never sink a batch. None when there is nothing to offer. `key` is a labels key
    `<lane>.<field>/<shape>` (labels adds CANDIDATE_MARK); a bad lane prefix raises in labels, as for
    any key -- callers pass a real lane."""
    options = render(value, kind, **opts)
    if not options:
        return None
    return labels.candidates(key, options)


# --------------------------------------------------------------------------- the kind classifier (T2 glue)
#
# A reader has an answer_format (its `kind`/`syntax`) and a value it read. It often cannot name the
# spelling the author chose. classify() maps (answer_format, value) -> a render kind, so pick_auto()
# gives candidates with no bespoke wiring. It is CONSERVATIVE: None when the kind is genuinely
# unclear, because a mis-classified kind only wastes probe budget (every output is still a candidate,
# never plain -- never-wrong holds either way). It never inspects question PROSE (untrusted, and a
# field is chosen by format/value, never by words of the text); only an optional field WORD helps
# disambiguate value shapes that several kinds share.

_HEXRE = re.compile(r"\A[0-9a-fA-F]+\Z")
_GUIDRE = re.compile(r"\A\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?\Z")
_MIDRE = re.compile(r"\A<?[^<>@\s]+@[^<>@\s]+>?\Z")
_DIGEST_LENS = {32, 40, 56, 64, 96, 128}      # md5, sha1, sha224, sha256, sha384, sha512 hex lengths
_FMT_KIND = {"integer": "integer", "int": "integer", "number": "integer",
             "hex": "hex", "guid": "guid", "uuid": "guid", "bool": "bool", "boolean": "bool",
             "version": "version", "path": "path", "encoding": "encoding", "digest": "digest",
             "hash": "digest", "timestamp": "timestamp", "datetime": "timestamp"}


def classify(answer_format=None, value=None, field=None):
    """A render kind for (answer_format, value), or None when it is not clear enough to be useful.

    answer_format: the question's dict (its `kind`, `syntax`) or None.
    value:         what the reader read (any type).
    field:         optional field word; only used to disambiguate `dimensions`/`version`/`path`/
                   `message_id`/`digest`/`encoding` when the value shape alone is ambiguous.
    """
    fmt = answer_format if isinstance(answer_format, dict) else {}
    fkind = str(fmt.get("kind") or "").strip().lower()
    fw = str(field or "").strip().lower()

    # Collections first: a JSON array / list value is the order-sensitive class whatever the format says.
    if isinstance(value, (list, tuple)):
        if len(value) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in value) \
                and any(w in fw for w in ("dim", "resolution", "geometry")):
            return "dimensions"
        if fkind == "version" or ("version" in fw and all(isinstance(x, int) for x in value)):
            return "version"
        return "list_or_intlist"

    if isinstance(value, bool):
        return "bool"

    # An explicit format kind wins for scalars (the reader trusts the question's declared kind).
    if fkind in _FMT_KIND:
        k = _FMT_KIND[fkind]
        if k == "guid" and not (isinstance(value, str) and _GUIDRE.match(value.strip())) \
                and not (isinstance(value, (bytes, bytearray)) and len(value) == 16):
            return None
        if k == "timestamp" and not isinstance(value, (int, float, str)):
            return None
        return k

    # bytes: an integer field if narrow, else a GUID only when the field says so.
    if isinstance(value, (bytes, bytearray)):
        if len(value) == 16 and ("guid" in fw or "uuid" in fw):
            return "guid"
        if 1 <= len(value) <= 8:
            return "int_from_bytes"
        return None

    if isinstance(value, int):
        return "integer"

    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if _GUIDRE.match(s):
            return "guid"
        if _MIDRE.match(s) and "@" in s and ("message" in fw or "content_id" in fw or fw.endswith("id")):
            return "message_id"
        if _HEXRE.match(s) and len(s) in _DIGEST_LENS and any(w in fw for w in ("digest", "hash", "sha", "md5", "crc")):
            return "digest"
        if ("/" in s or "\\" in s) and any(w in fw for w in ("path", "file", "dir", "name")):
            return "path"
        if "encod" in fw or "charset" in fw:
            return "encoding"
        if re.fullmatch(r"v?\d+(\.\d+){1,3}", s) and "version" in fw:
            return "version"
        # A bare integer-looking string with no stronger signal -> integer (0x/base re-spell).
        if re.fullmatch(r"-?\d+", s) or re.fullmatch(r"0x[0-9a-fA-F]+", s):
            return "integer"
        return None

    return None


def pick_auto(key, value, answer_format=None, field=None, prefer_json=None, **opts):
    """classify(answer_format, value) then pick(key, value, kind). None when the kind is unclear or
    nothing renders. The one-line adoption primitive: a reader that read a value but cannot name its
    spelling returns `RC.pick_auto(key, value, q.get("answer_format"), field=...)`. `prefer_json`
    defaults to True when the question's format kind is json (the macho/zip/synthesis-array case)."""
    kind = classify(answer_format, value, field)
    if kind is None:
        return None
    if prefer_json is None:
        fkind = str((answer_format or {}).get("kind") or "").strip().lower() if isinstance(answer_format, dict) else ""
        prefer_json = fkind in ("json", "array", "list")
    if kind in ("list", "intlist", "list_or_intlist", "collection"):
        opts.setdefault("prefer_json", prefer_json)
    return pick(key, value, kind, **opts)


def deception_axis(value, answer_format=None, field=None, prefer_json=None):
    """The FULL re-speller axis for a value ALREADY read (the re-speller tier of propose.py builds on this):
    the classify+render scalar/collation renderings (T2/T3, the case/pad/base/endian/order forms) PLUS the
    unicode/encoding-layer renderings (#8) -- for a str the NFKC/NFC/homoglyph/zero-width/percent/HTML/IDNA
    forms, for raw bytes the utf-8/utf-16/latin-1/... re-decodes. Raw [(hypothesis_name, rendered_str), ...],
    author-most-common first, de-duplicated by value, at most MAX. [] for nothing to offer.

    Pure and never-raising, like `render`. It makes no plain answer on its own: it returns candidate options,
    which a caller wraps with `labels.candidates` (so every output is an unsure `??` string until the judge
    accepts a hypothesis for the key). The value was read from the bytes by the caller; this only re-spells it,
    so never-guess is upstream. The classifier never auto-selects the unicode kinds, so the axis is additive:
    a clean scalar gets only its scalar re-spellings, a text value with a hidden layer gets that layer too."""
    try:
        raw = []
        kind = classify(answer_format, value, field)
        if kind is not None and kind in _KINDS:
            if prefer_json is None:
                fkind = str((answer_format or {}).get("kind") or "").strip().lower() \
                    if isinstance(answer_format, dict) else ""
                prefer_json = fkind in ("json", "array", "list")
            try:
                raw = list(_KINDS[kind](value, prefer_json=bool(prefer_json)))
            except Exception:  # noqa: BLE001 - a renderer must never raise into a solver
                raw = []
        if isinstance(value, str):
            raw += _r_unicode(value)
        elif isinstance(value, (bytes, bytearray)):
            raw += _r_redecode(value)
        return _dedup(raw)
    except Exception:  # noqa: BLE001
        return []


# Convenience aliases for the briefs' vocabulary (T2 the re-speller, T3 the order axis).
respell = pick
collation = order_axis


if __name__ == "__main__":  # a quick manual look, no network
    demo = [
        ("integer", 1024), ("base", 0x8664), ("hex", b"\x86\x64"),
        ("int_from_bytes", b"\x04\x00"),
        ("guid", bytes(range(16))), ("list_or_intlist", ["0x0100000c", "0x01000007"]),
        ("intlist", [5, 2, 5]), ("dims", (320, 180)), ("timestamp", 1700000000),
    ]
    for k, v in demo:
        print(f"{k:16} {v!r:28} -> {render(v, k)[:4]}")
    print("classify json array ->", classify({"kind": "json"}, ["0x0100000c"], "macho.cpu_type_set"))
    print("pick_auto ->", pick_auto("metadata.format/macho.cpu_type_set", ["0x0100000c"], {"kind": "json"}))
