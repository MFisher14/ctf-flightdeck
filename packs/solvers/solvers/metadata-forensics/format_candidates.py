#!/usr/bin/env python3
"""Format-candidate helper (Day 23 root-cause fix: the all-or-nothing unjudged-format failure).

On Day 23 the Metadata Time Trial failed all morning on `sqlite.page_size_bytes`: we read the
VALUE (1024) correctly, but the author's exact rendering/label for that field had never been
judged, and the shipped path submitted ONE plain rendering, which was wrong and sank the whole
batch. That is the single most expensive metadata failure mode: the value is in hand, only the
spelling is unknown.

This module turns a KNOWN value plus a cheap kind hint into a ranked list of plausible renderings,
to be submitted as `labels.candidates` (row 346): unsure, ranked, at most 12, NEVER plain. The
judge then settles the rendering with one probe on the untimed base (or on a no-deadline attempt),
and the accepted hypothesis name answers the next variant's own value under the same key. A wrong
plain answer is impossible here: every output is a candidate option.

It is a pure, reusable primitive with NO byte-reading and NO network: the caller has already read
the value from the bytes (that is where never-guess lives). This module only decides how to SPELL a
value that is already established, so it can be called from any lane's `day_patch.py` or a reader.

Usage from a metadata day_patch.py (M is properties_strict):

    import format_candidates as FC        # loaded beside properties_strict

    def override(q, answer, files, ctx):
        key, named = _key(q)
        if key != M.canon("sqlite.page_size_bytes"):
            return None
        name, data = M.target_file(q, files, ctx, named, key)
        if data is None:
            return WITHDRAW
        value = int.from_bytes(data[16:18], "big")        # read from the bytes (never guessed)
        return FC.pick("metadata.sqlite/page_size_bytes", value, "integer")

`render(value, kind, **opts)` returns the ordered `[(hypothesis_name, rendered_value), ...]` list
(testable with no ledger), and `pick(key, value, kind, **opts)` wraps it in `labels.candidates`.

KINDS (each ranks the author's most common spelling first):
  integer     1024               -> integer, 0x hex (padded to width if given), hex no-prefix
  hex         b"\\x04\\x00" / int  -> 0x lower/upper, bare lower/upper, padded (width=) first
  guid        16 bytes or a str  -> hyphen lower/upper, braces, compact, as_stored (if a str given)
  message_id  "<abc@h>" / "abc@h"-> with <>, without <>  (RFC 2822 Message-ID / Content-ID)
  list        ["b","a"]          -> document order and sorted, each x comma / comma-space / space / json
  intlist     [2,5]              -> same, numeric sort
  bool        True               -> true/false, True/False, 1/0, yes/no, on/off
  dims        (320,180)          -> 320x180, 320X180, 320*180, "320 x 180", json [w,h]
  digest      hex str            -> lower, upper
  path        "a/b/c"            -> forward slash, back slash, basename
  version     (3,51,3) or str    -> dotted as-is, trailing-zero trim, 2-digit minor
  encoding    "utf-8"            -> hyphen lower, compact lower, hyphen upper, compact upper

Everything is deterministic and order-stable; duplicate renderings are removed keeping first rank.
"""
import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE.parent / "common") not in sys.path:
    sys.path.insert(0, str(_HERE.parent / "common"))
import labels  # noqa: E402  (the unsure-answer contract; candidates()/pick())

MAX = labels.MAX_OPTIONS   # 12


# --------------------------------------------------------------------------- helpers

def _as_int(value):
    """An int from an int, a hex str (0x or bare), or big-endian bytes. None if it is not one."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(bytes(value), "big") if value else 0
    if isinstance(value, str):
        s = value.strip()
        try:
            return int(s, 16) if s[:2].lower() == "0x" else int(s)
        except ValueError:
            try:
                return int(s, 16)
            except ValueError:
                return None
    return None


def _hex_digits(value, width_bits=None):
    """The lowercase hex digits (no 0x) of a value, zero-padded to width_bits/4 if given.
    bytes keep their own length; an int with no width is minimal (even number of digits)."""
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
        raw = raw.rjust(width_bits // 4, "0")[-(width_bits // 4) :] if len(raw) <= width_bits // 4 else raw
        raw = raw.rjust(width_bits // 4, "0")
    return raw


def _dedup(options):
    """Keep the first (name, value) for each distinct rendered value; cap at MAX. A value that
    cannot be rendered (None) is dropped. Names are kept distinct by suffixing a counter."""
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


def _compact_json(obj):
    import json
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _compact_json_ascii(obj):
    import json
    return json.dumps(obj, separators=(",", ":"))


# --------------------------------------------------------------------------- per-kind renderers

def _r_integer(value, width_bits=None, **_):
    n = _as_int(value)
    if n is None:
        return []
    opts = [("integer", str(n))]
    if n >= 0:
        minimal = format(n, "x")          # 0x400, no byte padding
        byte_even = _hex_digits(n)         # 0x0400, padded to a whole byte
        if width_bits:
            opts.append(("hex_0x_padded", "0x" + _hex_digits(n, width_bits)))
        opts.append(("hex_0x", "0x" + minimal))
        opts.append(("hex_0x_byte", "0x" + byte_even))
        opts.append(("hex_bare", minimal))
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


def _guid_hex32(value):
    """32 lowercase hex digits of a GUID, from 16 bytes or a textual GUID. None otherwise."""
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


def _order_variants(seq, numeric):
    """Document order first, then ASCENDING sorted (the judge's collation for a sorted collection is
    plain ascending -- Python's `sorted`: lexicographic by code point for strings, numeric for ints --
    as confirmed on Day 23's zip.central_directory_member_names and macho.cpu_type_set)."""
    doc = list(seq)
    try:
        srt = sorted(doc)
    except TypeError:
        srt = doc
    out = [("document_order", doc)]
    if srt != doc:
        out.append(("sorted", srt))
    return out


def _render_list(seq, numeric):
    opts = []
    for oname, items in _order_variants(seq, numeric):
        if numeric:
            texts = [str(int(x)) for x in items]
            opts.append((f"{oname}+comma", ",".join(texts)))
            opts.append((f"{oname}+comma_space", ", ".join(texts)))
            opts.append((f"{oname}+space", " ".join(texts)))
            opts.append((f"{oname}+json", _compact_json([int(x) for x in items])))
        else:
            texts = [str(x) for x in items]
            opts.append((f"{oname}+comma", ",".join(texts)))
            opts.append((f"{oname}+comma_space", ", ".join(texts)))
            opts.append((f"{oname}+space", " ".join(texts)))
            opts.append((f"{oname}+json", _compact_json(list(items))))
    return opts


def _r_list(value, **_):
    if not isinstance(value, (list, tuple)):
        return []
    return _render_list(value, numeric=False)


def _r_intlist(value, **_):
    if not isinstance(value, (list, tuple)):
        return []
    try:
        ints = [int(x) for x in value]
    except (TypeError, ValueError):
        return []
    return _render_list(ints, numeric=True)


def _r_bool(value, **_):
    b = bool(value) if not isinstance(value, str) else value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, str) and value.strip().lower() not in ("1", "0", "true", "false", "yes", "no", "on", "off"):
        return []
    t = [("true_false", "true"), ("True_False", "True"), ("one_zero", "1"), ("yes_no", "yes"), ("on_off", "on")]
    f = [("true_false", "false"), ("True_False", "False"), ("one_zero", "0"), ("yes_no", "no"), ("on_off", "off")]
    return t if b else f


def _r_dims(value, **_):
    if isinstance(value, (list, tuple)) and len(value) == 2:
        try:
            w, h = int(value[0]), int(value[1])
        except (TypeError, ValueError):
            return []
    else:
        return []
    return [
        ("x_lower", f"{w}x{h}"),
        ("x_upper", f"{w}X{h}"),
        ("star", f"{w}*{h}"),
        ("spaced_x", f"{w} x {h}"),
        ("json", _compact_json([w, h])),
    ]


def _r_digest(value, **_):
    if not isinstance(value, str):
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value).hex()
        else:
            return []
    s = value.strip()
    return [("lower", s.lower()), ("upper", s.upper())]


def _r_path(value, **_):
    if not isinstance(value, str):
        return []
    s = value.strip()
    fwd = s.replace("\\", "/")
    back = s.replace("/", "\\")
    base = fwd.rstrip("/").split("/")[-1]
    return [("forward_slash", fwd), ("back_slash", back), ("basename", base)]


def _r_version(value, **_):
    if isinstance(value, (list, tuple)):
        parts = [str(int(x)) for x in value]
        dotted = ".".join(parts)
    elif isinstance(value, str):
        dotted = value.strip().lstrip("vV")
        parts = dotted.split(".")
    else:
        return []
    trimmed = ".".join(parts).rstrip("0").rstrip(".") if len(parts) > 1 else dotted
    opts = [("dotted", dotted)]
    if trimmed and trimmed != dotted:
        opts.append(("dotted_trimmed", trimmed))
    if len(parts) >= 2 and parts[1].isdigit():
        two = parts[0] + "." + parts[1].zfill(2)
        opts.append(("minor_2_digits", two))
    return opts


def _r_encoding(value, **_):
    if not isinstance(value, str):
        return []
    s = value.strip().lower()
    hy = s
    compact = s.replace("-", "")
    return [
        ("hyphen_lower", hy),
        ("compact_lower", compact),
        ("hyphen_upper", hy.upper()),
        ("compact_upper", compact.upper()),
    ]


_KINDS = {
    "integer": _r_integer,
    "hex": _r_hex,
    "guid": _r_guid,
    "uuid": _r_guid,
    "message_id": _r_message_id,
    "list": _r_list,
    "intlist": _r_intlist,
    "bool": _r_bool,
    "dims": _r_dims,
    "digest": _r_digest,
    "path": _r_path,
    "version": _r_version,
    "encoding": _r_encoding,
}

KINDS = tuple(_KINDS)


# --------------------------------------------------------------------------- public API

def render(value, kind, **opts):
    """The ordered [(hypothesis_name, rendered_value), ...] renderings for a KNOWN value, best
    (the author's most common spelling) first, at most MAX, each value distinct. [] when the kind
    is unknown or the value cannot be rendered in it. No bytes are read and nothing is guessed:
    the caller established `value`; this only spells it. Pure, so testable with no ledger."""
    fn = _KINDS.get(kind)
    if fn is None:
        return []
    try:
        raw = fn(value, **opts)
    except Exception:  # a renderer must never raise into a solver
        return []
    return _dedup(raw)


def render_all(value, kind, **opts):
    """Every (hypothesis_name, rendered_value) the kind produces for `value`, in rank order, with NO
    de-duplication and NO cap (two names may render one text: that is what accepted_formats.classify
    needs to see). [] when the kind is unknown or the value cannot be rendered in it."""
    fn = _KINDS.get(kind)
    if fn is None:
        return []
    try:
        raw = fn(value, **opts)
    except Exception:  # a renderer must never raise into a solver
        return []
    return [(n, v if isinstance(v, str) else _compact_json(v)) for n, v in raw if v is not None]


# A value per kind that makes every hypothesis of the kind distinct (kind_names): an unsorted list, an
# integer whose minimal, byte-even and padded hex differ, a version with a trailing zero and one-digit minor.
_NAME_SAMPLES = {
    "integer": (0x123, {"width_bits": 32}), "hex": (b"\x01\x23", {"width_bits": 32}),
    "guid": (bytes(range(16)), {}), "uuid": (bytes(range(16)), {}), "message_id": ("a@b", {}),
    "list": (["b", "a"], {}), "intlist": ([2, 1], {}), "bool": (True, {}), "dims": ((1, 2), {}),
    "digest": ("ab", {}), "path": ("a/b", {}), "version": ((1, 2, 0), {}), "encoding": ("utf-8", {}),
}


def kind_names(kind):
    """Every hypothesis name `kind` can offer, in rank order (value-free: for a probe plan and for
    checking a catalog's names). `as_stored`, a GUID text's own spelling, is value-dependent and not
    listed. () for an unknown kind."""
    if kind not in _NAME_SAMPLES:
        return ()
    value, opts = _NAME_SAMPLES[kind]
    return tuple(dict.fromkeys(n for n, _ in render_all(value, kind, **opts)))


def order(options, prefer=(), last=(), names_only=False):
    """`options` [(name, value), ...] reordered: the names in `prefer` first, in prefer's order, then
    the rest in their own order, then the names in `last`, in last's order. Nothing is added or
    dropped. names_only: return the names alone."""
    last = list(dict.fromkeys(last))
    tail_names = set(last)
    prefer = [n for n in dict.fromkeys(prefer) if n not in tail_names]
    by_name = {}
    for n, v in options:
        by_name.setdefault(n, (n, v))
    head = [by_name[n] for n in prefer if n in by_name]
    mid = [(n, v) for n, v in options if n not in set(prefer) and n not in tail_names]
    end = [by_name[n] for n in last if n in by_name]
    out = head + mid + end
    return [n for n, _ in out] if names_only else out


_AF = {}


def _accepted_formats():
    """accepted_formats.py beside this file (the accepted-format catalog, B-218), loaded once."""
    if "mod" not in _AF:
        try:
            from ctf import packs as _packs
        except ModuleNotFoundError:
            sys.path.append(str(_HERE.parents[1]))
            from ctf import packs as _packs
        _AF["mod"] = _packs.load_module("metadata_accepted_formats", _HERE / "accepted_formats.py",
                                        pack="metadata accepted_formats")
    return _AF["mod"]


def ranked(value, kind, key=None, prop=None, catalog=None, answer_format=None, **opts):
    """render(value, kind) in the accepted-format catalog's probe order for the key's property (B-218):
    names the judge accepted for this property first, then for its class, then for its kind; names the
    question's answer_format rules out and names refused for the property last. At most MAX, each value
    distinct; when two names render one value the better-ranked name is the one offered.

    prop      the property (`pe.coff_machine_u16_hex`); default: read from `key`
              (accepted_formats.property_of_key). No property: the class/kind priors still apply.
    catalog   an accepted_formats.Catalog; None: the tracked catalog (CatalogError when it is missing or
              broken, never a silent fallback); False: no catalog, exactly render()'s order.
    answer_format  the question's answer_format (with `normalization`), whose stated words order too."""
    raw = render_all(value, kind, **opts)
    if not raw:
        return []
    if catalog is False:
        return _dedup(raw)
    AF = _accepted_formats()
    cat = AF.load_default() if catalog is None else catalog
    if prop is None and key is not None:
        prop = AF.property_of_key(key)
    prefer, last = cat.preference(prop, kind, opts, answer_format)
    return _dedup(order(raw, prefer, last))


def pick(key, value, kind, prop=None, catalog=None, answer_format=None, **opts):
    """`labels.candidates(key, ranked(value, kind, ...))`: an unsure candidate pick over the plausible
    renderings of a known value, in the accepted-format catalog's probe order (see ranked). NEVER plain
    before the judge accepts a hypothesis for `key`, so it can never sink a batch: the catalog only
    orders the probes. None when there is nothing to offer. `key` is a labels key
    `<lane>.<field>/<shape>`; CANDIDATE_MARK is added by candidates(). catalog=False: render()'s order."""
    options = ranked(value, kind, key=key, prop=prop, catalog=catalog, answer_format=answer_format, **opts)
    if not options:
        return None
    return labels.candidates(key, options)


if __name__ == "__main__":  # a quick manual look, no network
    for k, v in [("integer", 1024), ("hex", b"\x04\x00"), ("guid", "{0C9E...}"),
                 ("list", ["evidence", "timeline"]), ("dims", (320, 180)), ("bool", True)]:
        print(k, v, "->", render(v, k)[:4])
