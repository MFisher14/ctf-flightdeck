#!/usr/bin/env python3
"""The accepted-format catalog and the pre-event vocabulary harvest (B-218).

format_candidates.py spells a value that is already read as ranked, unsure candidates (row 346). What
it did not have is memory: every new property started from the same fixed order, so the judge's
earlier verdicts on the SAME kind of field (a `_u16_hex` is answered `0x014c`, a GUID with hyphens and
no braces, a member list as compact JSON) did not reach the next property's first probe. This module is
that memory, and the harvest that fills it before an event.

The catalog (`accepted_formats.json` beside this file, tracked) holds, per property name
(`pe.coff_machine_u16_hex`):

  kind / opts        the format_candidates kind the property is rendered as (and its width)
  accepted           {hypothesis name: count}: judged-correct answers whose text only that name renders
  consistent         {hypothesis name: count}: judged-correct answers whose text several names render
                     (a degenerate accept, as labels.degenerate_accept: banked as evidence, never as a
                     confirmed name)
  rejected           names a single-id probe sent and the judge refused, where the same attempt had the
                     same VALUE accepted under another spelling (a format verdict, not a value verdict)
  syntax / answer_kinds / normalization   the judge's own words for the answer's form (the vocabulary)
  asked, sources     how often it was asked, and where (relative attempt folders)

plus `syntax`, every syntax phrase the judge used with its answer kind and count, and `unparsed`, the
question ids whose property name could not be read.

How it is used (never plain, never a guess):

  * format_candidates.pick(key, value, kind) asks `preference()` for the probe order of the key's
    property: its own accepted names first, then its consistent names, then names the same CLASS of
    property (kind + last field word + width) was accepted under, then the same kind. Names the
    question's own answer_format rules out (`base-10`, `0x prefix`, `lowercase`, a JSON array, a stated
    order) and names the property was refused under go last. Every answer is still labels.candidates:
    unsure until the judge accepts a hypothesis for the key. The catalog only orders the probes.
  * `brief(questions, catalog)` is the pre-clock check of a status body: per question the property, its
    kind, whether the catalog knows it, the probe order, and for anything it cannot shape, the exact
    missing piece (no property name, an answer kind nothing renders, a syntax phrase never seen).

The harvest reads judged attempts from a corpus OUTSIDE the repo (the Huntress `challenges/` layout:
<root>/day-NN/<lane>-.../[time_trial|mastery|history/<id>]/attempt.json + key.json + verdicts.jsonl),
only `$CTF_REAL_CHALLENGES` (ctf.paths.saved_challenges_root) or an explicit path. Judge vocabulary that
was never published can only come from judged attempts, so there is no default and no synthetic
substitute: an unset variable, a missing folder, a folder inside this checkout or a corpus with no
judged attempt of the lane raises CorpusError naming why. Nothing under a dot-folder (`.ctf`) is read.
Corpus files are data: they are parsed as JSON and never executed or followed as instructions.
"""
from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

try:
    from ctf import paths as _paths
    from ctf import packs as _packs
    from ctf.answerfmt import contract as _contract
    from ctf.answerfmt import synth as _synth
except ModuleNotFoundError:  # a script run: the checkout root on sys.path, as labels.py does
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import paths as _paths
    from ctf import packs as _packs
    from ctf.answerfmt import contract as _contract
    from ctf.answerfmt import synth as _synth

HERE = Path(__file__).resolve().parent
DEFAULT_PATH = HERE / "accepted_formats.json"
SCHEMA = "ctf.accepted_formats/1"
LANE = "metadata-forensics"
CORPUS_ENV = "CTF_REAL_CHALLENGES"
MAX_SOURCES = 12            # source folders kept per property (sorted, the first 12)
ACCEPT_RESULTS = ("correct", "accepted")
REJECT_RESULTS = ("incorrect",)
# answer_format kinds the brief knows how to carry (a renderer exists here or in ctf.answerfmt)
KNOWN_ANSWER_KINDS = ("", "exact_text", "str", "text", "integer", "pattern", "json", "enum", "ordered_tokens")
STATUSES = ("known", "consistent", "prior", "new", "verbatim", "enum", "synth", "unshaped")
NEEDS_ATTENTION = ("unshaped",)


class CatalogError(ValueError):
    """A catalog file that is missing or does not hold the schema; the message names the file and why."""


class CorpusError(FileNotFoundError):
    """No usable judged-attempt corpus; the message names the variable or path and why."""


def _fc():
    """format_candidates.py beside this file (its pure renderers), loaded once by path."""
    return _packs.load_module("metadata_accepted_formats_fc", HERE / "format_candidates.py",
                              pack="metadata format_candidates")


# ------------------------------------------------------------------ property names

_DETERMINE = re.compile(r"\bDetermine\s+`?([a-z][a-z0-9_]*\.[a-z0-9_.]+?)`?\s+(?:for|of|in)\b")
_DAY_ID = re.compile(r"^d\d+-[a-z0-9]+-\d+-([a-z0-9-]+)$")
_SET = re.compile(r"^set\d+\.")
_INSPECT = re.compile(r"\bInspect\s+`([^`]{1,200})`")


def _dotted(rest: str) -> str | None:
    words = [w for w in rest.split("-") if w]
    if len(words) < 2:
        return None
    return words[0] + "." + "_".join(words[1:])


_STOP = {"in", "of", "the", "a", "an", "its", "as", "is", "what", "are", "exact"}


def _qid_words(question) -> list:
    qid = question.get("id") or question.get("answer_id") or ""
    return [w for w in _SET.sub("", str(qid).strip().lower()).split("-") if w]


def stem_field(question: dict) -> str | None:
    """The field of a stem id anchored by the file the question inspects, or None: `roster-size-bytes`
    beside ``Inspect `roster.csv` `` is `size_bytes`, `evidence-note-copy-md5` beside
    ``Inspect `evidence-note-copy-6c89c5.txt` `` is `md5` (the id's leading words the file's stem shares
    are the stem; the rest is the field)."""
    if not isinstance(question, dict):
        return None
    text = question.get("question") if isinstance(question.get("question"), str) else ""
    words = _qid_words(question)
    m = _INSPECT.search(text)
    if not m or len(words) < 2 or _DETERMINE.search(text):
        return None
    stem = Path(m.group(1)).name.lower().split(".", 1)[0]
    stem_words = [w for w in re.split(r"[^a-z0-9]+", stem) if w]
    n = 0
    while n < min(len(stem_words), len(words) - 1) and stem_words[n] == words[n]:
        n += 1
    return "_".join(words[n:]) if n else None


def property_of(question: dict, known_fields=()) -> str | None:
    """The property a question asks, as the judge writes it (`sqlite.page_size_bytes`), or None.

    In this order: the question text (`Determine <property> for <file>`); a day id
    (`d23-sqlite-001-sqlite-page-size-bytes`, a `setN.` prefix dropped); a stem id anchored by the
    inspected file (stem_field); the longest of `known_fields` (stem fields harvested from anchored
    questions, `size_bytes`) the id ends in; the longest proper suffix of the id, at most three words,
    the question text says in so many words (stop words aside: "exact size in bytes" says `size bytes`)."""
    if not isinstance(question, dict):
        return None
    text = question.get("question") if isinstance(question.get("question"), str) else ""
    m = _DETERMINE.search(text)
    if m:
        return m.group(1).rstrip(".")
    words = _qid_words(question)
    m = _DAY_ID.match("-".join(words))
    if m:
        return _dotted(m.group(1))
    if len(words) < 2:
        return None
    anchored = stem_field(question)
    if anchored:
        return anchored
    qid = "-".join(words)
    for f in sorted(known_fields or (), key=lambda f: (-len(f), f)):
        tail = "-" + f.replace("_", "-")
        if "." not in f and qid.endswith(tail) and len(qid) > len(tail):
            return f
    said = [w for w in re.split(r"[^a-z0-9]+", text.lower()) if w and w not in _STOP]
    for k in range(min(3, len(words) - 1), 0, -1):
        if _says(said, "".join(words[-k:])):
            return "_".join(words[-k:])
    return None


def _says(tokens, joined) -> bool:
    """True when whole consecutive tokens of the text spell `joined` (`sha 1` spells `sha1`, `something`
    does not spell `thing`)."""
    for i in range(len(tokens)):
        acc = ""
        for t in tokens[i:]:
            acc += t
            if acc == joined:
                return True
            if not joined.startswith(acc):
                break
    return False


def property_of_key(key) -> str | None:
    """The property a labels key names: `metadata.sqlite/page_size_bytes` -> `sqlite.page_size_bytes`,
    `metadata.format/pe.coff_machine_u16_hex` -> `pe.coff_machine_u16_hex`; a candidate mark and a
    `+...` shape suffix are dropped. None for anything else."""
    if not isinstance(key, str):
        return None
    k = key.strip().lower()
    if k.endswith("#candidates"):
        k = k[: -len("#candidates")]
    lane, dot, rest = k.partition(".")
    if not dot or "/" not in rest:
        return None
    head, _, shape = rest.partition("/")
    shape = shape.split("+", 1)[0]
    if not head or not shape:
        return None
    if head == "format":
        return shape or None
    return f"{head}.{shape}"


def _words(prop: str) -> list[str]:
    field_ = prop.split(".", 1)[1] if "." in prop else prop
    return [w for w in re.split(r"[^a-z0-9]+", field_.lower()) if w]


_WIDTH = re.compile(r"^u(8|16|32|64)$")
_DIGESTS = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "crc32", "digest"}
_BYTES_WORDS = {"prefix", "magic", "bytes", "signature", "header", "raw"}
_BOOL_TAIL = {"present", "enabled", "signed", "encrypted", "compressed", "valid", "matches", "exists"}
_LIST_TAIL = {"set", "list", "names", "targets", "ids", "members", "paths", "values", "order", "groups"}
_INT_TAIL = {"bytes", "count", "size", "entries", "offset", "rva", "length", "number", "total", "index"}
_BOOL_WORDS = {"true", "false", "yes", "no", "on", "off", "1", "0"}
_DWORD_WORDS = {"rva", "va", "checksum", "crc32", "timestamp"}


def infer_kind(prop: str | None, answer_format=None) -> tuple[str, dict] | None:
    """(format_candidates kind, renderer opts) for a property, or None when it has no rendering axis
    known here (a verbatim text, an enum of labels). The answer_format's kind wins where it decides
    (a JSON answer is a list, a true/false enum a bool, an integer answer an integer); otherwise the
    field's words do (`_u16_hex` an integer of width 16, `_guid` a GUID, `_dimensions` dims)."""
    af = answer_format if isinstance(answer_format, dict) else {}
    akind = str(af.get("kind") or "").strip().lower()
    words = _words(prop) if prop else []
    tail = words[-1] if words else ""
    if akind == "enum":
        acc = af.get("accepted_values")
        vals = {str(v).strip().lower() for v in acc} if isinstance(acc, list) else set()
        return ("bool", {}) if vals and vals <= _BOOL_WORDS else None
    if akind == "json":
        if "dimensions" in words:
            return ("dims", {})
        return ("list", {})
    if not words:
        return ("integer", {}) if akind == "integer" else None
    if tail in ("guid", "uuid") or "mvid" in words:
        return ("guid", {})
    if tail in _DIGESTS or (tail in ("fingerprint", "thumbprint") and _DIGESTS & set(words)):
        return ("digest", {})
    if tail == "hex" or (len(words) >= 2 and words[-2] == "hex" and words[-1].isdigit()):
        width = next((int(_WIDTH.match(w).group(1)) for w in words if _WIDTH.match(w)), None)
        if not width and _DWORD_WORDS & set(words):
            width = 32      # an RVA, a virtual address, a checksum: 32-bit fields of the formats asked
        if width:
            return ("integer", {"width_bits": width})
        if _BYTES_WORDS & set(words):
            return ("hex", {})
        return ("integer", {})
    if tail in ("dimensions", "resolution") or (tail == "pixels" and "dimensions" in words):
        return ("dims", {})
    if tail == "version" and "original" not in words:
        return ("version", {})
    if tail == "id" and ("message" in words or "content" in words):
        return ("message_id", {})
    if "path" in words:
        return ("path", {})
    if tail in ("encoding", "charset"):
        return ("encoding", {})
    if tail in _BOOL_TAIL or words[0] in ("is", "has"):
        return ("bool", {})
    if akind == "integer" or tail in _INT_TAIL:
        return ("integer", {})
    if tail in _LIST_TAIL and akind == "ordered_tokens":
        return ("list", {})
    return None


def class_of(prop: str | None, kind: str, opts: dict | None = None) -> str:
    """The class a property's rendering is shared with: `<kind>/<last field word>/<width or ->`."""
    words = _words(prop) if prop else []
    width = (opts or {}).get("width_bits")
    return f"{kind}/{words[-1] if words else '-'}/{width or '-'}"


# ------------------------------------------------------------------ the judge's syntax words

_BASE10 = re.compile(r"\bbase[- ]?10\b|\bdecimal\b")
_NO_0X = re.compile(r"\bno\s+`?0x`?\b|\bwithout\s+(?:a\s+|the\s+|any\s+)?`?0x`?|\bno\s+prefix\b")
_0X = re.compile(r"\b0x\s+prefix\b|\bprefixed\s+(?:with|by)\s+`?0x`?|\bwith\s+(?:a|the)\s+`?0x`?")
_LOWER = re.compile(r"\blower[- ]?case\b")
_UPPER = re.compile(r"\bupper[- ]?case\b")
_HYPHEN_GUID = re.compile(r"8-4-4-4-12|\bincluding\s+hyphens\b|\bwith\s+hyphens\b")
_NO_BRACES = re.compile(r"\bno\s+(?:curly\s+)?braces\b|\bwithout\s+(?:curly\s+)?braces\b")
_BRACES = re.compile(r"\b(?:in|with|inside)\s+(?:curly\s+)?braces\b")


def _syntax_text(answer_format) -> str:
    af = answer_format if isinstance(answer_format, dict) else {}
    return " ".join(str(af.get(k) or "") for k in ("syntax",)).lower()


def norm_phrase(text) -> str:
    """A syntax phrase as the catalog keys it: lowercase, blanks collapsed."""
    return re.sub(r"\s+", " ", str(text or "")).strip().lower()


def _read_contract(answer_format):
    if not isinstance(answer_format, dict):
        return None
    try:
        return _contract.read(answer_format)
    except _contract.AnswerFormatError:
        return None


def allows(name: str, kind: str, answer_format=None) -> bool:
    """False when the question's answer_format rules the hypothesis `name` out: `base-10` keeps only
    `integer`, a stated `0x` prefix (or `no 0x`) the matching hex names, `lowercase`/`uppercase` the
    names of that case, `8-4-4-4-12` the hyphenated GUIDs, a JSON array the JSON joins, a stated comma
    join the comma joins, a stated ascending or file order that order, a closed enum the names whose
    rendering it lists. True when nothing is stated. The phrases are the judge's; nothing is inferred."""
    if not isinstance(answer_format, dict):
        return True
    syn = _syntax_text(answer_format)
    low = name.lower()
    if kind == "integer" and _BASE10.search(syn) and name != "integer":
        return False
    if kind in ("integer", "hex"):
        if _NO_0X.search(syn):
            if low.startswith("hex_0x"):
                return False
        elif _0X.search(syn) and not low.startswith("hex_0x"):
            return False
    if _LOWER.search(syn) and ("upper" in low or name == "True_False"):
        return False
    if _UPPER.search(syn) and "lower" in low:
        return False
    if kind in ("guid", "uuid"):
        if _HYPHEN_GUID.search(syn) and low.startswith("compact_"):
            return False
        if _NO_BRACES.search(syn) and low.startswith("braces_"):
            return False
        if _BRACES.search(syn) and not _NO_BRACES.search(syn) and not low.startswith("braces_"):
            return False
    c = _read_contract(answer_format)
    if c is not None and kind in ("list", "intlist", "dims"):
        if c.container == "json_array" and not (low.endswith("+json") or low == "json"):
            return False
        if c.container is None and c.separator == "," and kind != "dims":
            join = low.split("+", 1)[-1]
            spaced = "comma_space"
            if join not in ("comma", spaced):
                return False
            if c.tight and join == spaced:
                return False
        if kind != "dims" and c.order == "ascending" and low.startswith("document_order"):
            return False
        if kind != "dims" and c.order == "file" and low.startswith("sorted"):
            return False
    if kind == "bool" and c is not None and c.accepted:
        acc = {a.lower() if c.case_insensitive else a for a in c.accepted}
        fc = _fc()
        texts = [v for n, v in fc.render_all(True, "bool") + fc.render_all(False, "bool") if n == name]
        if texts and not all((t.lower() if c.case_insensitive else t) in acc for t in texts):
            return False
    return True


# ------------------------------------------------------------------ classifying a judged text

def _values_of(text: str, kind: str):
    """The underlying values whose rendering under `kind` could be `text` exactly, as
    (canonical, value) pairs: two texts with one canonical value are the same fact spelled twice."""
    s = text.strip()
    out = []
    if kind == "integer":
        if re.fullmatch(r"-?\d+", s):
            out.append(int(s))
        h = s[2:] if s[:2].lower() == "0x" else s
        if re.fullmatch(r"[0-9a-fA-F]+", h):
            out.append(int(h, 16))
        return [(v, v) for v in out]
    if kind == "hex":
        h = s[2:] if s[:2].lower() == "0x" else s
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", h):
            b = bytes.fromhex(h)
            return [(b.hex(), b)]
        return []
    if kind in ("guid", "uuid"):
        digs = "".join(c for c in s if c in "0123456789abcdefABCDEF")
        if len(digs) == 32 and re.fullmatch(r"\{?[0-9a-fA-F-]{32,36}\}?", s):
            b = bytes.fromhex(digs)
            return [(b.hex(), b)]
        return []
    if kind == "message_id":
        inner = s[1:-1] if s.startswith("<") and s.endswith(">") else s
        return [(inner, inner)] if inner and "<" not in inner and ">" not in inner else []
    if kind in ("list", "intlist"):
        lists = []
        if s.startswith("["):
            try:
                v = json.loads(s)
            except ValueError:
                v = None
            if isinstance(v, list) and all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in v):
                lists.append(v)
        else:
            # one separator, the most specific the text holds (`b, a` is never the items `b` and ` a`)
            sep = next((x for x in (", ", ",", " ") if x in s), None)
            lists.append(s.split(sep) if sep else [s])
        if kind == "intlist":
            ints = []
            for items in lists:
                try:
                    ints.append([int(x) for x in items])
                except (TypeError, ValueError):
                    continue
            lists = ints
        out = []
        for items in lists:
            canon = tuple(sorted(str(x) for x in items))
            out.append((canon, list(items)))
            rev = list(reversed(items))
            if rev != list(items):
                out.append((canon, rev))      # any other order: the `sorted` names render it too
        return out
    if kind == "bool":
        low = s.lower()
        if low in ("true", "yes", "on", "1"):
            return [(True, True)]
        if low in ("false", "no", "off", "0"):
            return [(False, False)]
        return []
    if kind == "dims":
        m = re.fullmatch(r"(\d+)\s*[xX*]\s*(\d+)", s)
        if m:
            v = (int(m.group(1)), int(m.group(2)))
            return [(v, v)]
        if s.startswith("["):
            try:
                v = json.loads(s)
            except ValueError:
                return []
            if isinstance(v, list) and len(v) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in v):
                return [(tuple(v), tuple(v))]
        return []
    if kind == "digest":
        if re.fullmatch(r"[0-9a-fA-F]+", s):
            return [(s.lower(), s.lower())]
        return []
    if kind == "path":
        canon = s.replace("\\", "/")
        vals = [s, canon, s.replace("/", "\\")]
        if "/" not in s and "\\" not in s and s:
            vals.append("dir/" + s)
        return [(canon, v) for v in dict.fromkeys(vals)]
    if kind == "version":
        parts = s.lstrip("vV").split(".")
        if not s or not all(p.isdigit() for p in parts):
            return []
        canon = tuple(int(p) for p in parts)
        while len(canon) > 1 and canon[-1] == 0:
            canon = canon[:-1]
        vals = [s, s + ".0", s + ".0.0"]
        if len(parts) >= 2 and len(parts[1]) == 2 and parts[1].startswith("0"):
            vals.append(".".join([parts[0], str(int(parts[1]))] + parts[2:]))
        return [(canon, v) for v in dict.fromkeys(vals)]
    if kind == "encoding":
        low = s.lower()
        vals = [low]
        if "-" not in low:
            m = re.fullmatch(r"([a-z]+)(\d+)", low)
            if m:
                vals.append(f"{m.group(1)}-{m.group(2)}")
        return [(low.replace("-", ""), v) for v in dict.fromkeys(vals)]
    return []


def _is_sorted(items) -> bool:
    try:
        return list(items) == sorted(items)
    except TypeError:
        return False


def canonical(text: str, kind: str) -> set:
    """The canonical values `text` can be under `kind` (empty when it is no value of the kind)."""
    return {c for c, _ in _values_of(text, kind)}


def classify(text, kind: str, answer_format=None, **opts) -> frozenset:
    """The hypothesis names (format_candidates names) whose rendering of some value of `kind` is exactly
    `text`. More than one name: the text cannot tell them apart (a degenerate accept). With an
    answer_format, the names it rules out (`allows`) are dropped, unless that would drop every name (the
    judge accepted a text our reading of its words rules out: our reading is not trusted over the
    verdict). Empty when `text` is no rendering of the kind. `as_stored` is never a hypothesis here."""
    if not isinstance(text, str) or not text.strip():
        return frozenset()
    fc = _fc()
    names = set()
    for _, value in _values_of(text, kind):
        for name, rendered in fc.render_all(value, kind, **opts):
            if rendered == text and name != "as_stored":
                names.add(name)
                # An already-sorted list (one item included) is also its own `sorted` rendering, which
                # format_candidates leaves out only because the two texts coincide.
                if kind in ("list", "intlist") and name.startswith("document_order+") and _is_sorted(value):
                    names.add("sorted+" + name.split("+", 1)[1])
    if answer_format is not None and names:
        kept = {n for n in names if allows(n, kind, answer_format)}
        if kept:
            names = kept
    return frozenset(names)


# ------------------------------------------------------------------ the catalog

@dataclass
class Entry:
    """What the judge has shown about one property's rendering."""
    kind: str
    opts: dict = field(default_factory=dict)
    accepted: Counter = field(default_factory=Counter)
    consistent: Counter = field(default_factory=Counter)
    rejected: set = field(default_factory=set)
    asked: int = 0
    syntax: set = field(default_factory=set)
    answer_kinds: set = field(default_factory=set)
    normalization: set = field(default_factory=set)
    sources: set = field(default_factory=set)
    unclassified: int = 0

    @property
    def split(self) -> bool:
        """A name both confirmed and refused for this property: the judge's rule is not one name."""
        return bool(set(self.accepted) & self.rejected)

    def to_json(self) -> dict:
        return {
            "kind": self.kind, "opts": dict(sorted(self.opts.items())),
            "accepted": dict(sorted(self.accepted.items())), "consistent": dict(sorted(self.consistent.items())),
            "rejected": sorted(self.rejected), "split": self.split, "asked": self.asked,
            "syntax": sorted(self.syntax), "answer_kinds": sorted(self.answer_kinds),
            "normalization": sorted(self.normalization), "sources": sorted(self.sources)[:MAX_SOURCES],
            "unclassified": self.unclassified,
        }


_ENTRY_KEYS = {"kind", "opts", "accepted", "consistent", "rejected", "split", "asked", "syntax", "answer_kinds",
               "normalization", "sources", "unclassified"}


def _need(cond, where, why):
    if not cond:
        raise CatalogError(f"{where}: {why}")


def _counter(raw, where, what) -> Counter:
    _need(isinstance(raw, dict), where, f"{what} must be an object of name -> count")
    for k, v in raw.items():
        _need(isinstance(k, str) and k, where, f"{what} has an empty name")
        _need(isinstance(v, int) and not isinstance(v, bool) and v > 0, where, f"{what}[{k!r}] must be a positive integer")
    return Counter(raw)


def _strings(raw, where, what) -> set:
    _need(isinstance(raw, list) and all(isinstance(x, str) for x in raw), where, f"{what} must be a list of strings")
    return set(raw)


def _entry(prop, e, where) -> Entry:
    """One property's Entry from its JSON, every key checked (CatalogError names the property and why)."""
    w = f"{where}: property {prop!r}"
    _need(isinstance(prop, str) and prop == prop.strip().lower() and prop, w, "must be a lowercase name")
    _need(isinstance(e, dict), w, "must be an object")
    extra = set(e) - _ENTRY_KEYS
    _need(not extra, w, f"unknown keys {sorted(extra)}")
    missing = _ENTRY_KEYS - set(e)
    _need(not missing, w, f"missing keys {sorted(missing)}")
    _need(e["kind"] in _fc().KINDS, w, f"kind {e['kind']!r} is not a format_candidates kind")
    _need(isinstance(e["opts"], dict) and set(e["opts"]) <= {"width_bits"}, w, "opts may hold only width_bits")
    wb = e["opts"].get("width_bits")
    _need(wb is None or wb in (8, 16, 32, 64), w, "width_bits must be 8, 16, 32 or 64")
    for n in ("asked", "unclassified"):
        _need(isinstance(e[n], int) and not isinstance(e[n], bool) and e[n] >= 0, w, f"{n} must be a count")
    entry = Entry(kind=e["kind"], opts=dict(e["opts"]),
                  accepted=_counter(e["accepted"], w, "accepted"),
                  consistent=_counter(e["consistent"], w, "consistent"),
                  rejected=_strings(e["rejected"], w, "rejected"), asked=e["asked"],
                  syntax=_strings(e["syntax"], w, "syntax"),
                  answer_kinds=_strings(e["answer_kinds"], w, "answer_kinds"),
                  normalization=_strings(e["normalization"], w, "normalization"),
                  sources=_strings(e["sources"], w, "sources"), unclassified=e["unclassified"])
    _need(e["split"] is entry.split, w, "split does not match accepted and rejected")
    known = set(_fc().kind_names(entry.kind))
    bad = (set(entry.accepted) | set(entry.consistent) | entry.rejected) - known
    _need(not bad, w, f"names {sorted(bad)} are not {entry.kind} hypotheses")
    return entry


@dataclass
class Catalog:
    properties: dict = field(default_factory=dict)      # property -> Entry
    syntax: dict = field(default_factory=dict)          # phrase -> {"answer_kind": str, "asked": int}
    unparsed: set = field(default_factory=set)          # question ids whose property could not be read
    lane: str = LANE
    # Corpus files a harvest could not read (`<relative path>: <why>`), so a partly broken corpus is never a
    # silently smaller catalog. A report of that harvest run only: not persisted, not compared.
    unreadable: list = field(default_factory=list, compare=False)

    # ---------------------------------------------------------------- persistence

    def to_json(self) -> dict:
        return {
            "schema": SCHEMA, "lane": self.lane,
            "properties": {p: self.properties[p].to_json() for p in sorted(self.properties)},
            "syntax": {s: dict(sorted(self.syntax[s].items())) for s in sorted(self.syntax)},
            "unparsed": sorted(self.unparsed),
        }

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=1, sort_keys=False, ensure_ascii=True) + "\n"

    def save(self, path) -> Path:
        path = Path(path)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(self.dumps(), encoding="utf-8")
        os.replace(tmp, path)
        return path

    @classmethod
    def from_json(cls, raw, where="catalog") -> "Catalog":
        _need(isinstance(raw, dict), where, "not a JSON object")
        _need(raw.get("schema") == SCHEMA, where, f"schema must be {SCHEMA!r}, not {raw.get('schema')!r}")
        _need(isinstance(raw.get("lane"), str) and raw["lane"], where, "lane must be a non-empty string")
        props = raw.get("properties")
        _need(isinstance(props, dict), where, "properties must be an object")
        out = {prop: _entry(prop, e, where) for prop, e in props.items()}
        syn = raw.get("syntax")
        _need(isinstance(syn, dict), where, "syntax must be an object")
        for phrase, s in syn.items():
            w = f"{where}: syntax {phrase!r}"
            _need(phrase == norm_phrase(phrase) and phrase, w, "must be a normalised phrase")
            _need(isinstance(s, dict) and set(s) == {"answer_kind", "asked"}, w, "must hold answer_kind and asked")
            _need(isinstance(s["answer_kind"], str), w, "answer_kind must be a string")
            _need(isinstance(s["asked"], int) and not isinstance(s["asked"], bool) and s["asked"] > 0, w,
                  "asked must be a positive count")
        unparsed = _strings(raw.get("unparsed"), where, "unparsed")
        extra = set(raw) - {"schema", "lane", "properties", "syntax", "unparsed"}
        _need(not extra, where, f"unknown keys {sorted(extra)}")
        return cls(properties=out, syntax={k: dict(v) for k, v in syn.items()}, unparsed=unparsed, lane=raw["lane"])

    @classmethod
    def load(cls, path=None) -> "Catalog":
        path = Path(path) if path is not None else DEFAULT_PATH
        if not path.is_file():
            raise CatalogError(f"{path}: accepted-format catalog not found")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise CatalogError(f"{path}: unreadable ({e})") from e
        return cls.from_json(raw, where=str(path))

    # ---------------------------------------------------------------- merging

    def entry(self, prop, kind, opts) -> Entry:
        e = self.properties.get(prop)
        if e is None:
            e = self.properties[prop] = Entry(kind=kind, opts=dict(opts or {}))
        return e

    def merge(self, other: "Catalog") -> "Catalog":
        """This catalog with `other`'s evidence added (counts summed, sets joined). A property both
        catalogs render under different kinds raises CatalogError: one of them misread it."""
        out = Catalog.from_json(self.to_json())
        for prop, e in other.properties.items():
            mine = out.properties.get(prop)
            if mine is None:
                out.properties[prop] = _entry(prop, e.to_json(), "merge")
                continue
            if (mine.kind, mine.opts) != (e.kind, e.opts):
                raise CatalogError(f"property {prop!r}: kind {mine.kind} {mine.opts} here, {e.kind} {e.opts} there")
            mine.accepted.update(e.accepted)
            mine.consistent.update(e.consistent)
            mine.rejected |= e.rejected
            mine.asked += e.asked
            mine.unclassified += e.unclassified
            for a in ("syntax", "answer_kinds", "normalization", "sources"):
                getattr(mine, a).update(getattr(e, a))
        for phrase, s in other.syntax.items():
            have = out.syntax.setdefault(phrase, {"answer_kind": s["answer_kind"], "asked": 0})
            have["asked"] += s["asked"]
        out.unparsed |= other.unparsed
        out.unreadable = list(self.unreadable) + list(other.unreadable)
        return out

    # ---------------------------------------------------------------- using it

    def _class_counts(self, cls_key, kind, skip=None):
        """Votes of the other properties of a class and of a kind: one per property for each name it
        was accepted (or consistently accepted) under, so a property asked often does not outvote the
        rest. A split property does not vote."""
        acc, con, kacc, kcon = Counter(), Counter(), Counter(), Counter()
        for prop, e in self.properties.items():
            if e.kind != kind or e.split or prop == skip:
                continue
            kacc.update(set(e.accepted))
            kcon.update(set(e.consistent))
            if class_of(prop, e.kind, e.opts) == cls_key:
                acc.update(set(e.accepted))
                con.update(set(e.consistent))
        return acc, con, kacc, kcon

    def preference(self, prop, kind, opts=None, answer_format=None) -> tuple[list, list]:
        """(prefer, last): hypothesis names to probe first, best first, and names to probe last, for
        `prop` rendered as `kind`. prefer: the property's accepted names (most often first), its
        consistent names, then names of the same class, then of the same kind (each accepted before
        consistent). last: names the answer_format rules out (`allows`) and names the property was
        refused under. A split property gives no preference of its own. Both lists only order the
        candidates; neither adds or removes one."""
        names = list(_fc().kind_names(kind))
        e = self.properties.get(prop) if prop else None
        own_acc, own_con = Counter(), Counter()
        if e is not None and e.kind == kind and not e.split:
            own_acc, own_con = e.accepted, e.consistent
        acc, con, kacc, kcon = self._class_counts(class_of(prop, kind, opts), kind, skip=prop)
        tables = (own_acc, own_con, acc, con, kacc, kcon)
        # Each name's evidence, strongest table first: a tie in one table is broken by the next (two
        # names that fit every accept of this property are told apart by what its class was accepted under).
        score = {n: tuple(t.get(n, 0) for t in tables) for n in set().union(*tables)}
        rank = {n: i for i, n in enumerate(names)}
        ranked = sorted((n for n, s in score.items() if any(s)), key=lambda n: (tuple(-x for x in score[n]),
                                                                                  rank.get(n, len(rank)), n))
        last = [n for n in names if not allows(n, kind, answer_format)]
        if e is not None and e.kind == kind:
            last += sorted(e.rejected - set(e.accepted))
        last = list(dict.fromkeys(last))
        prefer = [n for n in ranked if n not in last]
        return prefer, last

    def probe_order(self, prop, kind, opts=None, answer_format=None) -> list:
        """Every hypothesis name of `kind`, in the order a probe should try them (value-free)."""
        prefer, last = self.preference(prop, kind, opts, answer_format)
        return _fc().order([(n, n) for n in _fc().kind_names(kind)], prefer, last, names_only=True)


_DEFAULT = {}


def load_default() -> Catalog:
    """The tracked catalog beside this file, re-read when it changes. CatalogError when it is missing
    or broken: the probe order is never silently the uncatalogued one."""
    try:
        st = DEFAULT_PATH.stat()
    except OSError as e:
        raise CatalogError(f"{DEFAULT_PATH}: accepted-format catalog not found ({e.strerror})") from e
    sig = (st.st_mtime_ns, st.st_size)
    hit = _DEFAULT.get("cat")
    if hit and hit[0] == sig:
        return hit[1]
    cat = Catalog.load(DEFAULT_PATH)
    _DEFAULT["cat"] = (sig, cat)
    return cat


# ------------------------------------------------------------------ the harvest

def corpus_root(explicit=None) -> Path:
    """The judged-attempt corpus: `explicit`, else $CTF_REAL_CHALLENGES. CorpusError when neither is
    set, the folder is missing, or it lies inside this checkout (a corpus is never committed)."""
    if explicit is not None:
        p = Path(explicit).expanduser()
        if not p.is_dir():
            raise CorpusError(f"judged-attempt corpus not found at {p}")
    else:
        try:
            p = _paths.saved_challenges_root()
        except FileNotFoundError as e:
            raise CorpusError(str(e)) from e
        if p is None:
            raise CorpusError(f"no judged-attempt corpus: set {CORPUS_ENV} (or pass --corpus) to the saved "
                              f"challenges folder of a past event, outside this checkout")
    p = p.resolve()
    repo = _paths.repo_root().resolve()
    if p == repo or repo in p.parents:
        raise CorpusError(f"judged-attempt corpus {p} is inside the checkout {repo}: keep corpora outside the repo")
    return p


def _attempt_dirs(root: Path, lane: str):
    """Every folder under `root` with an attempt.json, below a folder named for `lane`, sorted; nothing
    under a dot-folder is visited."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        rel = here.relative_to(root).parts
        in_lane = any(part == lane or part.startswith(lane + "-") for part in rel)
        keep = sorted(d for d in dirnames if not d.startswith("."))
        if not in_lane and len(rel) >= 1:
            # <root>/<lane>-*/ or <root>/<day>/<lane>-*/: below the first level only the lane's own folders
            keep = [d for d in keep if d == lane or d.startswith(lane + "-")]
        dirnames[:] = keep
        if in_lane and "attempt.json" in filenames:
            out.append(here)
    return sorted(out)


def _read_json(path: Path, bad: list, root: Path):
    """The JSON in `path`; None when the file is absent (nothing to report) or unreadable (reported in
    `bad` as `<path relative to root>: <why>`, so a corrupt corpus file is never skipped silently)."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError) as e:
        bad.append(f"{_rel(path, root)}: unreadable JSON ({type(e).__name__})")
        return None


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _verdict_rows(path: Path, bad: list, root: Path):
    """The verdict rows of a verdicts.jsonl (objects with a `values` object). Lines that are not such a
    row (blank lines aside) are counted into `bad` once per file."""
    if not path.is_file():
        return []
    rows, skipped = [], 0
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        bad.append(f"{_rel(path, root)}: unreadable ({type(e).__name__})")
        return []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if isinstance(row, dict) and isinstance(row.get("values"), dict):
            rows.append(row)
        else:
            skipped += 1
    if skipped:
        bad.append(f"{_rel(path, root)}: {skipped} line(s) that are no verdict row (JSON object with values)")
    return rows


def harvest(roots, lane: str = LANE) -> Catalog:
    """A catalog from the judged attempts under `roots` (each an existing folder outside the checkout,
    see corpus_root). Per attempt folder: its questions (attempt.json), its judged-correct answers
    (key.json of the same attempt id, and every verdict row whose result is correct/accepted), and its
    single-id rejections (a verdict row of one id whose result is incorrect). CorpusError when no folder
    of `lane` holds a readable attempt.json. A corpus file that is present but cannot be read (corrupt
    JSON, an attempt.json with no questions list, a key.json with no answers object, verdict lines that
    are no verdict row) is listed in the catalog's `unreadable`, never skipped silently."""
    if isinstance(roots, (str, Path)):
        roots = [roots]
    cat = Catalog(lane=lane)
    attempts = []
    roots = [corpus_root(r) for r in roots]
    for root in roots:
        for adir in _attempt_dirs(root, lane):
            attempt = _read_json(adir / "attempt.json", cat.unreadable, root)
            if isinstance(attempt, dict) and isinstance(attempt.get("questions"), list):
                attempts.append((root, adir, attempt))
            elif attempt is not None:
                cat.unreadable.append(f"{_rel(adir / 'attempt.json', root)}: no questions list")
    if not attempts:
        raise CorpusError(f"no judged attempt of lane {lane!r} (an attempt.json below a {lane}-* folder) under "
                          + ", ".join(str(r) for r in roots)
                          + (f"; unreadable: {'; '.join(cat.unreadable)}" if cat.unreadable else ""))
    # The stem fields the corpus anchors (`size_bytes` beside an inspected file) name the same field of an
    # unanchored stem id (`roster-size-bytes` with no file named).
    known = {f for _, _, a in attempts for q in a["questions"] if (f := stem_field(q))}
    for root, adir, attempt in attempts:
        _harvest_attempt(cat, adir, root, attempt, known)
    return cat


_UUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)


def _source(adir: Path, root: Path) -> str:
    """The attempt folder relative to the corpus, with attempt ids (`history/<uuid>`) left out."""
    return "/".join(p for p in adir.relative_to(root).parts if not _UUID.match(p))


def _harvest_attempt(cat: Catalog, adir: Path, root: Path, attempt: dict, known=()):
    source = _source(adir, root)
    questions = {}
    for q in attempt["questions"]:
        if isinstance(q, dict) and isinstance(q.get("id"), str):
            questions[q["id"]] = q
    accepted, rejected = {}, {}
    key = _read_json(adir / "key.json", cat.unreadable, root)
    if key is not None and not (isinstance(key, dict) and isinstance(key.get("answers"), dict)):
        cat.unreadable.append(f"{_rel(adir / 'key.json', root)}: no answers object")
    if isinstance(key, dict) and key.get("attempt_id") == attempt.get("attempt_id") and isinstance(key.get("answers"), dict):
        for qid, text in key["answers"].items():
            if qid in questions and isinstance(text, str):
                accepted.setdefault(qid, set()).add(text)
    for row in _verdict_rows(adir / "verdicts.jsonl", cat.unreadable, root):
        result = str(row.get("result") or "").strip().lower()
        values = {k: v for k, v in row["values"].items() if k in questions and isinstance(v, str)}
        if result in ACCEPT_RESULTS:
            for qid, text in values.items():
                accepted.setdefault(qid, set()).add(text)
        elif result in REJECT_RESULTS and len(row["values"]) == 1:
            for qid, text in values.items():
                rejected.setdefault(qid, set()).add(text)
    for qid, q in sorted(questions.items()):
        af = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        afn = {**af, "normalization": q.get("normalization")} if q.get("normalization") is not None else af
        akind = str(af.get("kind") or "").strip().lower()
        phrase = norm_phrase(af.get("syntax"))
        if phrase:
            s = cat.syntax.setdefault(phrase, {"answer_kind": akind, "asked": 0})
            s["asked"] += 1
        if _synth.route(_SET.sub("", qid)) is not None:
            continue            # a synthesis answer (ctf.answerfmt.synth): no property, its own handler
        prop = property_of(q, known)
        if prop is None:
            cat.unparsed.add(_SET.sub("", qid))
            continue
        shaped = infer_kind(prop, af)
        if shaped is None:
            continue
        kind, opts = shaped
        if kind == "list" and _all_int_lists(accepted.get(qid, ())):
            kind = "intlist"
        e = cat.properties.get(prop)
        if e is not None and (e.kind, e.opts) != (kind, opts):
            if {e.kind, kind} == {"list", "intlist"} and e.opts == opts:
                kind = e.kind       # one property, one kind: the first reading holds
            else:
                continue
        e = cat.entry(prop, kind, opts)
        e.asked += 1
        e.sources.add(source)
        if phrase:
            e.syntax.add(phrase)
        e.answer_kinds.add(akind)
        if q.get("normalization") is not None:
            e.normalization.add(str(q.get("normalization")))
        good = sorted(t for t in accepted.get(qid, ()) if t.strip().lower() != "none")
        good_names = {t: classify(t, kind, answer_format=afn, **opts) for t in good}
        refused = set()
        for text in sorted(rejected.get(qid, ())):
            if text in good_names:
                continue
            bad = classify(text, kind, **opts)
            same = [g for g in good if canonical(g, kind) & canonical(text, kind)]
            if not same or not bad:
                continue            # the value itself was refused, not its spelling
            if kind in ("list", "intlist") and all(n.startswith("document_order+") for n in bad):
                # The refused text is in no sorted order, so it can only be the document order of this
                # value: an accepted text of the same items in another order is no document_order rendering.
                order_r = _items(text, kind)
                for g in same:
                    if _items(g, kind) != order_r:
                        good_names[g] = frozenset(n for n in good_names[g] if not n.startswith("document_order+"))
            ok = set().union(*(good_names[g] for g in same))
            refused |= set(bad) - ok
        e.rejected |= refused
        for text in good:
            names = good_names[text]
            if len(names) == 1:
                e.accepted.update(names)
            elif names:
                e.consistent.update(names)
            else:
                e.unclassified += 1


def _items(text, kind):
    """The items of a list text in the order written (None when it is no list of the kind)."""
    vals = _values_of(text, kind)
    return list(vals[0][1]) if vals else None


def _all_int_lists(texts) -> bool:
    seen = False
    for t in texts:
        try:
            v = json.loads(t)
        except ValueError:
            return False
        if not (isinstance(v, list) and v and all(isinstance(x, int) and not isinstance(x, bool) for x in v)):
            return False
        seen = True
    return seen


# ------------------------------------------------------------------ the pre-clock brief

@dataclass
class Finding:
    qid: str
    prop: str | None
    status: str                 # one of STATUSES
    kind: str | None = None
    opts: dict = field(default_factory=dict)
    probe: list = field(default_factory=list)
    new_syntax: str | None = None
    missing: str | None = None

    @property
    def attention(self) -> bool:
        return self.status in NEEDS_ATTENTION or self.new_syntax is not None

    def to_json(self) -> dict:
        return {"id": self.qid, "property": self.prop, "status": self.status, "kind": self.kind,
                "opts": self.opts, "probe": self.probe, "new_syntax": self.new_syntax, "missing": self.missing,
                "attention": self.attention}

    def line(self) -> str:
        head = f"{self.qid}: {self.status}"
        if self.prop:
            head += f" {self.prop}"
        if self.kind:
            head += f" [{self.kind}{'/' + str(self.opts['width_bits']) if self.opts.get('width_bits') else ''}]"
        parts = [head]
        if self.probe:
            parts.append("probe " + ", ".join(self.probe[:6]) + (" ..." if len(self.probe) > 6 else ""))
        if self.new_syntax:
            parts.append(f"NEW SYNTAX {self.new_syntax!r}")
        if self.missing:
            parts.append(f"MISSING {self.missing}")
        return "; ".join(parts)


def brief(questions, catalog: Catalog) -> list:
    """One Finding per question of a status body, in its order.

    status  known       the catalog holds a confirmed rendering of this property
            consistent  only degenerate accepts: the names that fit them are probed first
            prior       a new property; its class or kind has judged renderings, probed first
            new         a renderable kind with nothing judged: every rendering, in format_candidates order
            verbatim    a property with no rendering axis here (the reader's text is the answer)
            enum        a closed enum of labels (ctf.answerfmt takes the listed spelling)
            synth       a synthesis id a ctf.answerfmt.synth handler routes and settles
            unshaped    the exact missing piece is named: no property name, an answer kind nothing renders,
                        judged answers no kind renders, a synthesis transform the question does not settle
    new_syntax  the answer_format's syntax phrase, when the catalog never saw the judge use it."""
    out = []
    known = {p for p in catalog.properties if "." not in p}
    for q in questions or ():
        if not isinstance(q, dict):
            continue
        qid = str(q.get("id") or q.get("answer_id") or "?")
        af = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
        afn = {**af, "normalization": q.get("normalization")} if q.get("normalization") is not None else af
        akind = str(af.get("kind") or "").strip().lower()
        phrase = norm_phrase(af.get("syntax"))
        new_syntax = phrase if phrase and phrase not in catalog.syntax else None
        bare = _SET.sub("", qid.strip().lower())
        if _synth.route(bare) is not None:
            why = _synth.covered(bare, q.get("question"), af)
            out.append(Finding(qid, None, "synth" if why is None else "unshaped", new_syntax=new_syntax,
                               missing=None if why is None else f"the synthesis transform: {why}"))
            continue
        prop = property_of(q, known)
        if prop is None:
            out.append(Finding(qid, None, "unshaped", new_syntax=new_syntax,
                               missing="the property name: neither the question text (`Determine <property> for "
                                       "<file>`) nor the id (`d<NN>-<type>-<NNN>-<property>`, `<stem>-<field>` "
                                       "beside `Inspect <stem>.<ext>`) names it"))
            continue
        if akind not in KNOWN_ANSWER_KINDS:
            out.append(Finding(qid, prop, "unshaped", new_syntax=new_syntax,
                               missing=f"a rendering for answer_format kind {akind!r}: neither this catalog nor "
                                       f"ctf.answerfmt reads it"))
            continue
        shaped = infer_kind(prop, af)
        if shaped is None:
            status = "enum" if akind == "enum" else "verbatim"
            out.append(Finding(qid, prop, status, new_syntax=new_syntax))
            continue
        kind, opts = shaped
        e = catalog.properties.get(prop)
        if e is not None and {e.kind, kind} == {"list", "intlist"}:
            kind = e.kind
        if e is not None and e.kind == kind and e.unclassified and not e.accepted and not e.consistent:
            out.append(Finding(qid, prop, "unshaped", kind=kind, opts=dict(opts), new_syntax=new_syntax,
                               missing=f"a rendering kind for {prop}: {e.unclassified} judged answer(s) are no "
                                       f"{kind} rendering format_candidates knows"))
            continue
        if e is not None and e.kind == kind and not e.split and e.accepted:
            status = "known"
        elif e is not None and e.kind == kind and not e.split and e.consistent:
            status = "consistent"
        else:
            prefer, _ = catalog.preference(prop, kind, opts, afn)
            status = "prior" if prefer else "new"
        out.append(Finding(qid, prop, status, kind=kind, opts=dict(opts),
                           probe=catalog.probe_order(prop, kind, opts, afn), new_syntax=new_syntax))
    return out


def questions_of(body) -> list:
    """The questions of a status body or attempt.json (`questions`, with `answer_ids` zipped in when the
    platform lists them apart), or of a bare list of questions."""
    if isinstance(body, list):
        return [q for q in body if isinstance(q, dict)]
    if not isinstance(body, dict) or not isinstance(body.get("questions"), list):
        return []
    qs = [q for q in body["questions"] if isinstance(q, dict)]
    ids = body.get("answer_ids")
    if isinstance(ids, list) and len(ids) == len(qs):
        qs = [{**q, "id": q.get("id") or a} for q, a in zip(qs, ids)]
    return qs
