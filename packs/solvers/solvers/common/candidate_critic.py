#!/usr/bin/env python3
"""Deterministic, demote-only PRE-SUBMIT critic (ticket A'1, the second-wave #1 build).

The judge banks a batch only when EVERY answer in it is right; one wrong plain answer sinks the
whole all-or-nothing submission (Day 8 Binary: `ELF64` where an integer was asked sank the base
and 13 submissions bisected it; Day 23 Metadata: one unjudged rendering of `sqlite.page_size_bytes`
sank a 28-id batch all morning). This module looks at a PROPOSED batch of {id: answer} before it is
sent and flags the answers that are LIKELY WRONG PLAINS, so a runner can withhold/demote them to a
probe (labels.pick / labels.candidates) before submission instead of losing the batch.

    critique(answers, questions, files) -> {id: reason}

`answers` is {answer id: value} about to be sent. `questions` is the attempt's questions (a list
aligned with answer_ids, or a {id: question} map; each question has `answer_format`, maybe `field`,
`artifact`/`member`, `question`). `files` is {name: bytes} for the delivery and its members (the
runner contract), or None. The return is {id: reason} for the ids that should be DEMOTED (withheld
from the plain batch and sent as an unsure probe instead); an empty dict means nothing is flagged.

CONTRACT (this is the whole point; it is why the critic is safe to run on every batch):
  * DEMOTE-ONLY. It never promotes, never invents a value, never changes an answer to something
    new. It only names ids to withhold. A false demote turns a plain answer into a withheld/probe,
    which is SAFE (never-wrong): the worst case is one extra probe, never a wrong value sent.
  * DETERMINISTIC. No model, no network, no clock, no randomness. Same inputs -> same output.
  * PURE and BOUNDED. Reads no file it is not handed (it may consult the labels ledger only through
    `labels`, read-only), bounded by the batch size and the bytes handed in, and NEVER RAISES: any
    error inside a check is swallowed and that check simply does not fire (a critic that raised
    would be worse than one that said nothing).
  * NEVER-WRONG, the strong form: it must not flag a CORRECT plain answer that is genuinely
    canonical. The corpus of saved key.json answers proves that document-order collections,
    uppercase/braced GUIDs, bare-lower and 0x-lower hex and `WxH` dims are all accepted PLAIN in
    lane-specific forms, so the critic NEVER flags on shape/ambiguity alone. Every flag is a
    PROVABLE inconsistency: a kind violation the contract itself states, a malformed transform, a
    cross-id contradiction, a known placeholder/template, or a rendering that violates the
    question's OWN stated syntax / an archive's stored order read from `files`.

The checks (each provable, each demote-only):
  1. FORMAT        a plain answer whose shape violates its answer_format (reuses tools/kinds.py,
                   the shipped "certainly wrong" kind check: uppercase under a lowercase syntax,
                   non-0x hex where 0x is required, a JSON array where an integer is asked, ...).
  2. TRANSFORM     a plain answer the question declares to be a self-invertible encoding
                   (base64/base32/hex) that is MALFORMED in that encoding, or a collection the
                   syntax declares sorted/ascending that is not sorted (a non-round-tripping plain).
  3. CONTRADICTION two ids that must agree and do not: the same member's digest asked twice with
                   different values, or a count that disagrees with a sibling list's length.
  4. PLACEHOLDER   a value equal to a known placeholder/example token, the literal field name, or
                   an unresolved template (`{{..}}`, `${..}`, `<token>`, `CHANGEME`, ...).
  5. RENDERING     order/rendering that is provably one choice among several (ties into
                   render_candidates): a collection equal to an archive's STORED-order entry names
                   that is not sorted (the Day-23 CD-order class), or a GUID/hex rendering that
                   VIOLATES a case/brace policy the question's own syntax states (the Day-23
                   unjudged-GUID-case class). Flagged as "should be a candidate, not plain".

It is advisory. Wiring it into tools/run.py and tools/verify.py (withhold the flagged ids and probe
them) is a separate step; this module only decides and explains.
"""
from __future__ import annotations

import base64
import binascii
import io
import json
import re
import sys
import zipfile
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

# labels is the unsure-answer contract (is_unsure / SENTINEL): the critic never flags a value that
# is already unsure, only a PLAIN one. Imported read-only; a failure to import leaves `labels` None
# and the critic treats every string as plain (still correct, just slightly less precise).
try:  # pragma: no cover - import guard
    import labels as _labels
except Exception:  # noqa: BLE001
    _labels = None

# tools/kinds.py is the shipped "certainly wrong" kind check, already proven (tests/test_kinds.py)
# never to withhold a saved key.json answer. The critic reuses it for check 1 instead of restating
# it, so check 1 inherits that proof. tools/ is a sibling of solvers/; the import is guarded so the
# critic degrades to "no format check" rather than raising if the layout ever changes.
_kinds = None
try:  # pragma: no cover - import guard
    _tools = _HERE.parent.parent / "tools"
    if str(_tools) not in sys.path:
        sys.path.insert(0, str(_tools))
    import kinds as _kinds  # type: ignore
except Exception:  # noqa: BLE001
    _kinds = None

SENTINEL = getattr(_labels, "SENTINEL", "??")
MAX_SCAN_BYTES = 4 << 20       # a member larger than this is not scanned (never a slow check)
MAX_ARCHIVE_ENTRIES = 4096     # a zip with more entries than this is not read for stored order


# --------------------------------------------------------------------------- shared helpers

def _is_plain(value) -> bool:
    """A real plain answer: not None, and not an unsure (`??`) pick. Only a plain answer can be a
    wrong plain, so only a plain answer is ever flagged."""
    if value is None:
        return False
    if isinstance(value, str) and value.lstrip().startswith(SENTINEL):
        return False
    if _labels is not None:
        try:
            if _labels.is_unsure(value):
                return False
        except Exception:  # noqa: BLE001
            pass
    return True


def _wire_text(value):
    """The answer as it goes on the wire: a string as-is, anything else as compact JSON (the form
    every runner sends a plain answer in, grade.wire_text). None only for a value with no text."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return None


def _fmt(q) -> dict:
    fmt = q.get("answer_format") if isinstance(q, dict) else None
    return fmt if isinstance(fmt, dict) else {}


def _syntax(q) -> str:
    s = _fmt(q).get("syntax")
    return s if isinstance(s, str) else ""


def _kind(q) -> str:
    k = _fmt(q).get("kind")
    return k.strip().lower() if isinstance(k, str) else ""


_PREFIX_RE = re.compile(r"^(?:set\d+\.)?(?:d\d{1,2}[_-])?", re.I)


def _field_word(q, aid) -> str:
    """A best-effort field word for an id, the way the lanes name a field: the question's own
    `field` when it has one, else the id with a leading setN./dNN_/dNN- stripped, lowercased. Used
    only to recognise a digest id, a count id and the literal-field-name placeholder; never to pick
    an answer by the words of the question text."""
    if isinstance(q, dict):
        got = q.get("field")
        if isinstance(got, str) and got.strip():
            return got.strip().lower()
    base = str(aid or "")
    base = _PREFIX_RE.sub("", base)
    return base.strip().lower()


def _member_of(q) -> str:
    """The member/artifact an id names (after '->' in its artifact, or q['member']), lowercased leaf
    name, or '' when none is stated. Two digest ids are 'the same file' only when this matches."""
    if not isinstance(q, dict):
        return ""
    mem = q.get("member")
    if not (isinstance(mem, str) and mem.strip()):
        art = q.get("artifact")
        if isinstance(art, str) and "->" in art:
            mem = art.split("->")[-1]
        else:
            mem = art if isinstance(art, str) else ""
    mem = str(mem or "").strip().lower()
    return mem.split("/")[-1]


def _question_map(questions, answers) -> dict:
    """{answer id: question}. Accepts a {id: question} map or a list aligned with answer_ids, and
    falls back to each question's own answer_id/id/qid. Ids not matched map to {} (no question)."""
    out = {}
    if isinstance(questions, dict):
        for k, v in questions.items():
            if isinstance(v, dict):
                out[str(k)] = v
        return out
    if isinstance(questions, (list, tuple)):
        for q in questions:
            if not isinstance(q, dict):
                continue
            for k in ("answer_id", "id", "qid"):
                v = q.get(k)
                if isinstance(v, str) and v and v not in out:
                    out[v] = q
    return out


# --------------------------------------------------------------------------- 1. FORMAT (kinds.py)

def _check_format(value, q):
    """Reuse tools/kinds.py: why a PLAIN answer certainly cannot be right for its answer_format,
    or None. kinds only speaks when the contract itself states the rule (a kind word, a digit
    count, a 0x prefix, a stated case), and tests/test_kinds.py proves it withholds no saved
    key.json answer, so this check inherits never-wrong."""
    if _kinds is None:
        return None
    try:
        why = _kinds.problem(value, _fmt(q))
    except Exception:  # noqa: BLE001
        return None
    if why:
        return f"format: {why}"
    return None


# --------------------------------------------------------------------------- 2. TRANSFORM round-trip

_B64_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")
_B64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+={0,2}\Z")
_B32_RE = re.compile(r"\A[A-Z2-7]+={0,6}\Z")
_HEX_RE = re.compile(r"\A(?:0x)?[0-9a-fA-F]+\Z")


def _declares(word_set, q) -> bool:
    """True when the id's field word or its syntax names one of `word_set` as the answer's own
    transform (not merely mentions it). Read from field + syntax only, bounded."""
    hay = (_field_word(q, "") + " " + _syntax(q)).lower()
    return any(re.search(r"\b" + re.escape(w) + r"\b", hay) for w in word_set)


def _b64_ok(s: str) -> bool:
    """s decodes as base64/base64url AND re-encodes to itself (a true round-trip), standard OR url
    alphabet. A trailing-pad-free form is accepted too (many judges strip '='). False only when it
    cannot be valid base64 at all."""
    s = s.strip()
    if not s or (_B64_RE.match(s) is None and _B64URL_RE.match(s) is None):
        return False
    for alt in {s, s + "=" * (-len(s) % 4)}:
        for altmap in (alt, alt.replace("-", "+").replace("_", "/")):
            try:
                raw = base64.b64decode(altmap, validate=True)
            except (binascii.Error, ValueError):
                continue
            re_enc = base64.b64encode(raw).decode("ascii")
            if re_enc.rstrip("=") == altmap.rstrip("="):
                return True
    return False


def _b32_ok(s: str) -> bool:
    s = s.strip()
    if not s or _B32_RE.match(s) is None:
        return False
    try:
        raw = base64.b32decode(s + "=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        return False
    return base64.b32encode(raw).decode("ascii").rstrip("=") == s.rstrip("=")


def _as_list(value):
    """A list from a list/tuple value or a JSON-array string, else None."""
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str):
        s = value.strip()
        if s[:1] == "[" and s[-1:] == "]":
            try:
                p = json.loads(s)
                if isinstance(p, list):
                    return p
            except (ValueError, TypeError):
                return None
    return None


def _check_transform(value, q):
    """A plain answer the question declares to be an encoding that is malformed in it, or a
    collection the syntax declares sorted that is not sorted. Only fires on a DECLARED transform,
    so a value that merely looks like base64 is never flagged."""
    text = _wire_text(value)
    # base64 / base32 / hex that the question declares and the value is not valid in.
    if isinstance(text, str) and text.strip():
        s = text.strip()
        if _declares({"base64", "b64", "base64url"}, q) and not _declares({"hex", "base32"}, q):
            if not _b64_ok(s):
                return "transform: declared base64 but the value is not valid base64 (does not round-trip)"
        elif _declares({"base32", "b32"}, q):
            if not _b32_ok(s):
                return "transform: declared base32 but the value is not valid base32 (does not round-trip)"
        elif _declares({"hexadecimal", "hex", "hexdigest", "hex-encoded", "hex_encoded"}, q) \
                and _kind(q) in ("exact_text", "", "digest", "hash"):
            body = s[2:] if s[:2].lower() == "0x" else s
            if body and (_HEX_RE.match(s) is None or len(body) % 2 == 1):
                return "transform: declared hex but the value is not an even-length hex string"
    # a collection the syntax says is sorted/ascending/alphabetical but is not sorted.
    seq = _as_list(value)
    if seq is not None and len(seq) >= 2:
        low = _syntax(q).lower()
        wants_sorted = bool(re.search(r"\b(sorted|ascending|alphabetical(?:ly)?|lexicographic(?:al)?)\b", low)) \
            and not re.search(r"\b(descending|reverse[ds]?|file order|document order|as (?:they )?appear)\b", low)
        if wants_sorted:
            try:
                if list(seq) != sorted(seq):
                    return "transform: the syntax says the list is sorted, but this order is not sorted"
            except TypeError:
                pass
    return None


# --------------------------------------------------------------------------- 3. CONTRADICTION (cross-id)

_DIGEST_ALGOS = ("sha512", "sha384", "sha256", "sha224", "sha1", "md5", "crc32", "crc", "sha3", "blake2")
_DIGEST_GENERIC = ("digest", "hash", "checksum", "fingerprint", "thumbprint")
_DIGEST_LEN = {32, 40, 56, 64, 96, 128}
_ARCHIVE_EXT = (".zip", ".apk", ".jar", ".war", ".aar", ".ipa", ".nupkg", ".7z", ".tar", ".gz",
                ".tgz", ".bz2", ".xz", ".rar", ".cab", ".iso", ".dmg")
_SET_RE = re.compile(r"^(set\d+)\.", re.I)
_COMPONENT_RE = re.compile(r"^(d\d{1,2})(?=[._\- ]|$)", re.I)


def _is_archive_name(name: str) -> bool:
    low = str(name or "").lower()
    return any(low.endswith(ext) for ext in _ARCHIVE_EXT)


def _scope(aid) -> tuple:
    """The (set, component) an id belongs to: its Mastery set prefix (setN) and its cumulative-lane
    component (leading dNN). Each Mastery set and each per-day component is a DIFFERENT delivery, so
    scoping by them keeps per-set / per-day digests of a same-named member from reading as a clash."""
    raw = str(aid or "")
    m = _SET_RE.match(raw)
    setpfx = m.group(1).lower() if m else ""
    rest = raw[m.end():] if m else raw
    mc = _COMPONENT_RE.match(rest)
    return (setpfx, mc.group(1).lower() if mc else "")


def _digest_subject(q, aid):
    """(scope, member, algo) when an id names a digest of a CONCRETE member (a specific file, not
    the delivery container archive), else None. Two such ids with the same subject MUST carry the
    same value, so a disagreement is certainly a wrong plain. The container archive is excluded
    (the cumulative lanes name every per-day digest `evidence.zip` while the bytes differ), and the
    scope separates each Mastery set and each day; only a concrete named member in one delivery is
    a real 'same file asked twice'."""
    fw = _field_word(q, aid)
    algo = next((a for a in _DIGEST_ALGOS if a in fw), None)
    if algo is None and not any(w in fw for w in _DIGEST_GENERIC):
        return None
    mem = _member_of(q)
    if not mem or _is_archive_name(mem):
        return None
    return (_scope(aid), mem, algo or "digest")


def _count_token(fw):
    """The 'subject' of a count id (`section_count` -> 'section', `num_entries` -> 'entries'), or
    None when the field word is not a count. Used to pair a count with its sibling list."""
    m = re.search(r"^(?:num|number|count)[ _-]?(?:of[ _-]?)?(.+)$", fw)
    if m:
        return re.sub(r"[^a-z0-9]+", "", m.group(1))
    m = re.search(r"^(.+?)[ _-]?(?:count|total|num|number)$", fw)
    if m:
        return re.sub(r"[^a-z0-9]+", "", m.group(1))
    return None


def _check_contradictions(answers, qmap) -> dict:
    """{id: reason} for ids that provably contradict a sibling id in the same batch."""
    out = {}
    # (a) the same concrete member's digest asked twice with different plain values. Only a value
    # that is actually a digest (pure hex of the algo's length) counts: a list answer whose field
    # word happens to contain a digest word (Day 23 `..-synthesis-sha256-order`, a JSON array) is
    # not a digest and never groups with one.
    by_subject = {}
    for aid, val in answers.items():
        if not _is_plain(val):
            continue
        subj = _digest_subject(qmap.get(aid, {}), aid)
        if subj is None:
            continue
        algo = subj[2]
        t = _wire_text(val)
        if not isinstance(t, str):
            continue
        body = t.strip()
        body = body[2:] if body[:2].lower() == "0x" else body
        if not re.fullmatch(r"[0-9a-fA-F]+", body or ""):
            continue
        if algo in ("crc", "crc32"):
            if not 1 <= len(body) <= 16:
                continue
        elif len(body) not in _DIGEST_LEN:
            continue
        by_subject.setdefault(subj, []).append((aid, body.lower()))
    for subj, items in by_subject.items():
        vals = {v for _, v in items}
        if len(items) >= 2 and len(vals) > 1:
            for aid, _ in items:
                out[aid] = (f"contradiction: {subj[2]} of '{subj[1]}' is asked by {len(items)} ids with "
                            f"{len(vals)} different values; at most one can be right")
    # (b) a count vs a same-token list's length is NOT a provable contradiction and is no longer
    # flagged (never-wrong fix, new-code audit H1). A count and a same-token list legitimately
    # enumerate different universes: `section_count` = 7 counts all SHT entries while `sections` =
    # [4 allocated names] lists only the named ones (count > len, the ordinary "counts more than it
    # names" shape), and `import_count` vs a deduped DLL list is the same; a count UNDER a list's
    # length is as explainable (a filtered or distinct count of a list that holds extras/dupes).
    # Neither direction proves at least one id wrong, so demoting both violated the module's own
    # "every flag PROVABLE" contract and wrongly withheld BOTH correct answers from an all-or-nothing
    # batch (inside a deadline a demoted plain is not probed, so the whole batch is lost). Only the
    # digest branch (a) above -- the SAME concrete member's digest asked twice with different values,
    # where at most one can be right -- is a genuine, kept contradiction.
    return out


# --------------------------------------------------------------------------- 4. PLACEHOLDER / template

# High-specificity placeholder/example tokens only: a value equal (case-insensitively) to one of
# these is almost never a real judged answer. Generic single words (foo, value, sample, test) are
# NOT here: the corpus shows such words occur as legitimate answers, and a demote-only critic earns
# nothing by risking them. `none`/`null`/`n/a` are NEVER placeholders: `none` is a real answer
# (AGENTS.md: the member is absent).
_PLACEHOLDERS = frozenset({
    "changeme", "change_me", "change-me", "replaceme", "replace_me", "replace-me",
    "placeholder", "your_value_here", "yourvaluehere", "insert_value_here", "value_here",
    "todo", "tbd", "fixme", "to_be_determined", "lorem ipsum", "lorem_ipsum",
    "example_value", "your_answer_here", "answer_here", "fill_me_in", "fillme",
    "<value>", "<answer>", "<redacted>", "redacted", "xxxxxxxx",
})
_TEMPLATE_RE = re.compile(r"\{\{.*?\}\}|\$\{[^}]*\}|%\([^)]*\)[sd]|<%[-=]?.*?%>|\{%.*?%\}")
_ANGLE_PLACEHOLDER_RE = re.compile(r"\A<[a-z][a-z0-9_ .-]{0,40}>\Z")   # <token>, no '@', no '/'
_UNDERSCORE_RUN_RE = re.compile(r"_{5,}")


def _check_placeholder(value, q, aid):
    text = _wire_text(value)
    if not isinstance(text, str):
        return None
    s = text.strip()
    if not s:
        return None
    low = s.lower()
    if low in _PLACEHOLDERS:
        return f"placeholder: {s!r} is a known placeholder/example token, not a read value"
    # an unresolved template fragment anywhere in the value.
    if _TEMPLATE_RE.search(s):
        return "placeholder: the value holds an unresolved template fragment ({{..}}, ${..}, %(..)s)"
    if _UNDERSCORE_RUN_RE.search(s):
        return "placeholder: the value holds a run of underscores (an unfilled blank)"
    # a lone <token> placeholder (but not a Message-ID <a@b> or a path/url inside angles).
    if _ANGLE_PLACEHOLDER_RE.match(s) and "@" not in s and "/" not in s and "." not in low.split(">")[0][1:]:
        return f"placeholder: {s!r} looks like an unfilled <placeholder> token"
    # the literal field name as the answer (e.g. field 'package_name', answer 'package_name').
    fw = _field_word(q, aid)
    if fw and len(fw) >= 4 and low == fw and _kind(q) not in ("enum",):
        return f"placeholder: the answer equals the field name {fw!r} (an unfilled field)"
    return None


# --------------------------------------------------------------------------- 5. RENDERING / order

def _archive_entry_names(files) -> list:
    """Every (archive, [entry leaf names in stored order]) the runner's `files` reveals.

    Two shapes are read: the runner's expanded form, where members are keys '<archive> -> <name>'
    kept in central-directory order; and a raw zip's own bytes (PK..), whose central directory is
    read with zipfile. Nothing is decompressed. Bounded and never-raising."""
    out = []
    if not isinstance(files, dict):
        return out
    # expanded form: '<archive> -> <member>' keys, in the order files preserves them.
    grouped = {}
    for name in files:
        if isinstance(name, str) and " -> " in name:
            arch, _, member = name.partition(" -> ")
            leaf = member.strip().split("/")[-1]
            if leaf:
                grouped.setdefault(arch.strip(), []).append(leaf)
    for arch, names in grouped.items():
        if 1 <= len(names) <= MAX_ARCHIVE_ENTRIES:
            out.append((arch, names))
    # raw zip bytes.
    for name, data in files.items():
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_SCAN_BYTES:
            continue
        if bytes(data[:4]) != b"PK\x03\x04":
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(bytes(data))) as zf:
                names = [n.split("/")[-1] for n in zf.namelist() if n and not n.endswith("/")]
        except Exception:  # noqa: BLE001
            continue
        if 1 <= len(names) <= MAX_ARCHIVE_ENTRIES:
            out.append((name, names))
    return out


def _stated_case(syntax: str):
    """The letter case the syntax states for a hex/GUID rendering: 'lower', 'upper', or None when
    it states none or states that case is ignored. (Only a STATED case makes a rendering provably
    wrong; an unstated case is never held against an answer.)"""
    low = syntax.lower()
    if "case is ignored" in low or "case-insensitive" in low or "case insensitive" in low:
        return None
    has_lower = "lowercase" in low or "lower case" in low or "lower-case" in low
    has_upper = "uppercase" in low or "upper case" in low or "upper-case" in low
    if has_lower and not has_upper:
        return "lower"
    if has_upper and not has_lower:
        return "upper"
    return None


_GUIDRE = re.compile(r"\A\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?\Z")


def _check_rendering(value, q, files):
    """Order/rendering that is provably one choice among several -> 'should be a candidate'.

    (a) the value equals an archive's STORED-order entry names (read from `files`) and that order
        is not sorted: the author's order is a choice the judge has not pinned (Day 23 CD-order
        zip names). Source-grounded, so it never fires on an ELF/document-order list the critic
        cannot re-derive.
    (b) a GUID or hex rendering whose letter case / brace form VIOLATES a case the question's own
        syntax states. Only a stated policy makes it provable; an unstated case is left alone, so
        a lane-conventional rendering (an uppercase MSI GUID whose syntax states no case) is safe.
    """
    syntax = _syntax(q)
    # (b) stated-case / brace violation on a GUID or hex-looking scalar.
    text = _wire_text(value)
    if isinstance(text, str) and text.strip():
        s = text.strip()
        want = _stated_case(syntax)
        is_guid = bool(_GUIDRE.match(s))
        is_hex = bool(_HEX_RE.match(s)) and len(s.replace("0x", "")) >= 6
        if (is_guid or is_hex) and want is not None:
            letters = [c for c in s if c.isalpha()]
            if letters:
                if want == "lower" and any(c.isupper() for c in letters):
                    return ("rendering: the syntax states lowercase but the value has uppercase letters; "
                            "an unjudged rendering should be a candidate, not plain")
                if want == "upper" and any(c.islower() for c in letters):
                    return ("rendering: the syntax states uppercase but the value has lowercase letters; "
                            "an unjudged rendering should be a candidate, not plain")
        if is_guid:
            low = syntax.lower()
            has_braces = s.startswith("{") and s.endswith("}")
            if has_braces and re.search(r"\b(no braces|without braces|unbraced|no curly)\b", low):
                return ("rendering: the syntax says no braces but the GUID is braced; an unjudged "
                        "rendering should be a candidate, not plain")
            if not has_braces and re.search(r"\b(with braces|braced|curly brace)\b", low):
                return ("rendering: the syntax says braces but the GUID is unbraced; an unjudged "
                        "rendering should be a candidate, not plain")
    # (a) archive stored-order collection.
    seq = _as_list(value)
    if seq is not None and len(seq) >= 2 and all(isinstance(x, str) for x in seq):
        leaves = [x.split("/")[-1] for x in seq]
        for _arch, names in _archive_entry_names(files):
            if sorted(names) != sorted(leaves):
                continue           # not this archive's entry set
            if names == leaves and leaves != sorted(leaves):
                return ("rendering: this is the archive's stored (central-directory) order, which is "
                        "not sorted; the order is unjudged and should be a candidate, not plain")
    return None


# --------------------------------------------------------------------------- the public critic

def critique(answers, questions=None, files=None) -> dict:
    """{id: reason} for the ids of `answers` that should be DEMOTED before this batch is sent.

    Pure, bounded, demote-only, never raises. An empty dict means nothing is flagged. A reason is
    a short human string naming the check and why. Only PLAIN answers are ever flagged (an unsure
    `??` value and None are left untouched); a value is never changed."""
    if not isinstance(answers, dict) or not answers:
        return {}
    try:
        qmap = _question_map(questions, answers)
    except Exception:  # noqa: BLE001
        qmap = {}
    flagged = {}
    # Per-id checks (first provable reason wins).
    for aid, value in answers.items():
        if not _is_plain(value):
            continue
        q = qmap.get(aid, {})
        for check in (_check_format, _check_transform):
            try:
                why = check(value, q)
            except Exception:  # noqa: BLE001
                why = None
            if why:
                flagged[aid] = why
                break
        if aid in flagged:
            continue
        try:
            why = _check_placeholder(value, q, aid)
        except Exception:  # noqa: BLE001
            why = None
        if not why:
            try:
                why = _check_rendering(value, q, files)
            except Exception:  # noqa: BLE001
                why = None
        if why:
            flagged[aid] = why
    # Cross-id checks (do not override a per-id reason already found).
    try:
        for aid, why in _check_contradictions(answers, qmap).items():
            flagged.setdefault(aid, why)
    except Exception:  # noqa: BLE001
        pass
    return flagged


def main(argv) -> int:  # a manual look: critique a saved attempt's key.json offline, no network
    if not argv:
        print("usage: candidate_critic.py <attempt dir> [answers.json]", file=sys.stderr)
        return 2
    folder = Path(argv[0])
    try:
        attempt = json.loads((folder / "attempt.json").read_text())
        src = Path(argv[1]) if len(argv) > 1 else folder / "key.json"
        answers = json.loads(src.read_text())
    except (OSError, ValueError) as e:
        print(f"candidate_critic.py: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if isinstance(answers, dict) and isinstance(answers.get("answers"), dict):
        answers = answers["answers"]
    files = {}
    flags = critique(answers if isinstance(answers, dict) else {}, attempt.get("questions"), files)
    for aid, why in flags.items():
        print(f"DEMOTE {aid}: {why}")
    print(f"CRITIC checked={len(answers)} flagged={len(flags)}")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
