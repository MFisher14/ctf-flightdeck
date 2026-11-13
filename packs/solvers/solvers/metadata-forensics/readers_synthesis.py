#!/usr/bin/env python3
"""Metadata Forensics cross-file synthesis handler (row 311).

properties_strict.py loads this file by name and calls it from the solve loop, before any property
lookup, for a question whose answer id ends in `synthesis-<algo>-order`. It is NOT a property
reader: it registers nothing, and it reads only the question's own text and the delivered files.

The question (a timed variant only; the base never asks it) states the whole transform:

    "... Compute the full-file <ALGO> digest of each named file, then submit a compact JSON array of
     their filenames in ascending digest order. Files: ["a.txt","b.jpg","c.exe"]"

So the answer is PLAIN: every named file's full-file digest under <algo>, the filenames ordered by
that digest, written as the compact JSON array the answer format asks for. It is withdrawn (None,
nothing sent) when anything about it is not settled:

  - the id does not name an algorithm hashlib has;
  - the answer format's kind is not json;
  - the text has no `Files:` list, the list does not parse, is empty, is not a list of names, or
    names a file more than once;
  - a named file is not in the delivery;
  - two of the named files share a digest (the ascending order would then be ambiguous).

B-248 widens the stated orders (the `largest, smallest, size, descending` row): a descending digest order, and an
id ending `synthesis-size-order` asking the filenames in ascending or descending size order (`ascending size
order`, `smallest first`, `largest first`, ...). Those are read from the same files but answered UNSURE (one
option, under `metadata.synthesis/<algo|size>+<direction>`), never plain, until the judge accepts the reading.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

_COMMON = str(Path(__file__).resolve().parent.parent / "common")
if _COMMON not in sys.path:
    sys.path.insert(0, _COMMON)
import labels  # noqa: E402

# An id of the form '...synthesis-<algo>-order' (hyphens or underscores): <algo> is a hashlib name, or (B-248)
# the word `size`.
_SUFFIX = re.compile(r"synthesis[-_]([0-9a-z]+)[-_]order$")
SIZE = "size"
KEY = "metadata.synthesis/"


def route(answer_id):
    """The hashlib algorithm name (or `size`, B-248) for an id that ends in synthesis-<algo>-order, or None (which
    tells properties_strict this is not a synthesis question and the normal property path should run)."""
    if not answer_id:
        return None
    m = _SUFFIX.search(str(answer_id).lower())
    if not m:
        return None
    algo = m.group(1)
    return algo if algo in hashlib.algorithms_available or algo == SIZE else None


# The order this handler writes: ascending by digest. The question must say exactly that (review of the Day 19 build:
# 'descending digest order' was answered plain ascending), and no word that turns or qualifies an order.
_ASCENDING = re.compile(r"\bascending\s+(?:[\w-]+\s+){0,2}(?:digest|hash)\s+order\b"
                        r"|\bascending\s+order\s+of\s+(?:their\s+|the\s+)?(?:[\w-]+\s+){0,2}(?:digests?|hash(?:es)?)\b", re.I)
_OTHER_ORDER = re.compile(r"\b(?:descending|decreasing|increasing|reverse[ds]?|reversed|inverted?|not|never|unless|except|"
                          r"largest|highest|biggest|greatest|smallest|lowest|alphabetical(?:ly)?|lexicographic(?:al(?:ly)?)?|"
                          r"numeric(?:al(?:ly)?)?|size|sizes)\b", re.I)


# Review of the Day 19 build (second round): the order words alone were read, while the digest algorithm came from
# the answer id and nothing held the text to a whole-file digest ('the full-file MD5 digest' under a sha256 id, 'the
# SHA-256 digest of the first 16 bytes', '..., last one first' were answered plain). The text must name exactly one
# digest algorithm, the id's, as 'full-file <ALGO> digest', and no word that narrows the bytes digested, changes the
# digest's written form or turns the order.
_FULL_FILE = re.compile(r"\bfull[- ]file\s+([A-Za-z0-9][\w/-]*?)\s+(?:digest|hash)\b", re.I)
_ALGO_WORD = re.compile(r"\b(md5|md4|sha-?(?:1|224|256|384|512)(?:[-/_](?:224|256))?|sha3[-_ ]?(?:224|256|384|512)|"
                        r"shake[-_ ]?(?:128|256)|blake2[bs]?|blake3|ripemd-?160|sm3|crc-?32c?|adler-?32|xxh(?:ash)?\w*|"
                        r"murmur\w*|fnv\w*|ssdeep|tlsh|imphash|whirlpool)\b", re.I)
_NARROW = re.compile(r"\b(?:first|last|bytes?|header|headers|prefix|suffix|trailing|leading|offset|chunks?|blocks?|"
                     r"truncated?|excluding|without|skip(?:ping)?|partial|portion|part|range|sections?|members?|"
                     r"base64|base32|base58|base85|b64|reversed?|salt(?:ed)?|hmac|keyed|twice|double)\b", re.I)


def _algo_name(word):
    """A hashlib name of an algorithm word as a question writes it ('SHA-256' sha256, 'SHA3-256' sha3_256,
    'SHA-512/256' sha512_256), or the word itself lowercased when it is none."""
    w = word.lower().replace(" ", "")
    m = re.fullmatch(r"sha-?(1|224|256|384|512)(?:[-/_](224|256))?", w)
    if m:
        return f"sha{m.group(1)}" + (f"_{m.group(2)}" if m.group(2) else "")
    m = re.fullmatch(r"(sha3|shake)[-_]?(\d+)", w)
    if m:
        return f"{m.group(1)}_{m.group(2)}"
    return w.replace("-", "")


def _transform_why(sentence, algo):
    """None when the question names one whole-file digest under the id's algorithm and nothing that narrows it."""
    full = _FULL_FILE.findall(sentence)
    if len(full) != 1:
        return "the question does not ask a full-file <ALGO> digest in so many words"
    named = {_algo_name(w) for w in _ALGO_WORD.findall(sentence)} | {_algo_name(full[0])}
    if named != {algo}:
        return f"the question names the digest {sorted(named)}, the id {algo!r}"
    narrow = _NARROW.search(sentence)
    if narrow:
        return f"the question says {narrow.group(0)!r} of the digest or its order"
    return None


def _order_why(sentence):
    """None when the question (the text before 'Files:') asks ascending digest order and nothing else about order."""
    if len(_ASCENDING.findall(sentence)) != 1:
        return "the question does not ask ascending digest order in so many words"
    other = _OTHER_ORDER.search(sentence)
    if other:
        return f"the question says {other.group(0)!r} beside its order"
    return None


# Review round 3: the order and the digest were read, never WHAT is submitted ('a compact JSON array of the digests',
# 'a JSON object mapping each filename to its position', 'their filenames in uppercase' were answered plain with the
# filenames). The object must be stated as '(a) (compact) JSON array of their|the filenames' directly before the order,
# and no word that names another object, a letter case or another form may stand anywhere before 'Files:'.
_OUTPUT = re.compile(r"\bsubmit\s+(?:an?\s+)?(?:compact\s+)?json\s+array\s+of\s+(?:their|the)\s+file\s?names\s+"
                     r"(?:sorted\s+)?in\s+ascending\b", re.I)
_OTHER_OUTPUT = re.compile(r"\b(?:upper|lower|title|camel|snake)(?:[- ]?case[ds]?)?\b|\b(?:case|cased|capital\w*|"
                           r"objects?|mapping|maps?|map(?:ped|s)\s+to|dict(?:ionar(?:y|ies))?|keys?|values?|pairs?|tuples?|"
                           r"positions?|index(?:es)?|indices|ranks?|ranking|numbers?|counts?|stems?|extensions?|suffix(?:es)?|"
                           r"paths?|basenames?|full[- ]path|directory|folders?|prefixed|quoted|escaped|joined|"
                           r"comma[- ]separated|newline|lines?|strings?\s+of|digests\s+(?:in|sorted)|each\s+digest|"
                           r"together\s+with|along\s+with|and\s+their|with\s+their|followed\s+by|plus)\b", re.I)


def _output_why(sentence):
    """None when the question asks the filenames themselves, as a JSON array, and nothing else about the output."""
    if len(_OUTPUT.findall(sentence)) != 1:
        return "the question does not ask 'a JSON array of their filenames in ascending ...' in so many words"
    other = _OTHER_OUTPUT.search(sentence)
    if other:
        return f"the question says {other.group(0)!r} of what is submitted"
    return None


def _names(answer_id, question_text, answer_format):
    """(the named files, None), or (None, why) where the question itself does not settle the transform."""
    if route(answer_id) is None:
        return None, "the id does not end in synthesis-<algo>-order with an algorithm hashlib has"
    if not isinstance(answer_format, dict) or answer_format.get("kind") != "json":
        return None, "the answer format is not json"
    text = str(question_text or "")
    i = text.rfind("Files:")
    if i < 0:
        return None, "the question has no 'Files:' list"
    why = _order_why(text[:i]) or _transform_why(text[:i], route(answer_id)) or _output_why(text[:i])
    if why:
        return None, why
    try:
        names = json.loads(text[i + len("Files:"):].strip())
    except Exception:
        return None, "the 'Files:' list does not parse as JSON"
    if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
        return None, "the 'Files:' list is empty or is not a list of filenames"
    if len(set(names)) != len(names):
        return None, "the 'Files:' list names a file more than once"
    return names, None


# ------------------------------------------------------------------ B-248: the wider stated orders, all UNSURE
# Descending digest order, and ascending or descending SIZE order (an id ending synthesis-size-order). The judge has
# accepted only the ascending digest order above; these read the same stated transform from the same files but are
# offered UNSURE (labels.pick under 'metadata.synthesis/<algo>+<direction>'), so the first probe settles them and a
# misread word costs a probe, never a wrong plain answer. Ties (two equal digests or sizes) are None.
_DESCENDING = re.compile(r"\bdescending\s+(?:[\w-]+\s+){0,2}(?:digest|hash)\s+order\b"
                         r"|\bdescending\s+order\s+of\s+(?:their\s+|the\s+)?(?:[\w-]+\s+){0,2}(?:digests?|hash(?:es)?)\b", re.I)
_SIZE_ORDER = {
    "ascending": re.compile(r"\bascending\s+(?:(?:file|byte)\s+)?size\s+order\b|\bascending\s+order\s+of\s+(?:their\s+|"
                            r"the\s+)?(?:file\s+|byte\s+)?sizes?\b|\bsmallest\s+(?:file\s+)?first\b", re.I),
    "descending": re.compile(r"\bdescending\s+(?:(?:file|byte)\s+)?size\s+order\b|\bdescending\s+order\s+of\s+(?:their\s+|"
                             r"the\s+)?(?:file\s+|byte\s+)?sizes?\b|\blargest\s+(?:file\s+)?first\b", re.I)}
_SIZE_OTHER = re.compile(r"\b(?:reverse[ds]?|reversed|inverted?|not|never|unless|except|alphabetical(?:ly)?|"
                         r"lexicographic(?:al(?:ly)?)?|digests?|hash(?:es)?|compressed|uncompressed|on-disk|lines?|words?|"
                         r"characters?|pixels?|duration|members?|entries)\b", re.I)
_OUTPUT_WIDE = re.compile(r"\bsubmit\s+(?:an?\s+)?(?:compact\s+)?json\s+array\s+of\s+(?:their|the)\s+file\s?names\b", re.I)


def _files_list(text):
    i = text.rfind("Files:")
    if i < 0:
        return None, None, "the question has no 'Files:' list"
    try:
        names = json.loads(text[i + len("Files:"):].strip())
    except Exception:
        return None, None, "the 'Files:' list does not parse as JSON"
    if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
        return None, None, "the 'Files:' list is empty or is not a list of filenames"
    if len(set(names)) != len(names):
        return None, None, "the 'Files:' list names a file more than once"
    return names, text[:i], None


def _wide(answer_id, question_text, answer_format):
    """(names, algo, direction, None) for a B-248 order the question states in so many words, else
    (None, None, None, why)."""
    algo = route(answer_id)
    if algo is None:
        return None, None, None, "the id does not end in synthesis-<algo|size>-order"
    if not isinstance(answer_format, dict) or answer_format.get("kind") != "json":
        return None, None, None, "the answer format is not json"
    names, head, why = _files_list(str(question_text or ""))
    if names is None:
        return None, None, None, why
    if len(_OUTPUT_WIDE.findall(head)) != 1:
        return None, None, None, "the question does not ask 'a JSON array of their filenames' in so many words"
    other = _OTHER_OUTPUT.search(head)
    if other:
        return None, None, None, f"the question says {other.group(0)!r} of what is submitted"
    if algo == SIZE:
        hits = [(d, m) for d, rx in _SIZE_ORDER.items() for m in rx.findall(head)]
        if len(hits) != 1:
            return None, None, None, "the question does not state one size order in so many words"
        bad = _SIZE_OTHER.search(head) or _ALGO_WORD.search(head)
        if bad:
            return None, None, None, f"the question says {bad.group(0)!r} beside its size order"
        return names, SIZE, hits[0][0], None
    if len(_DESCENDING.findall(head)) != 1 or _ASCENDING.search(head):
        return None, None, None, "the question does not ask descending digest order in so many words"
    other = _OTHER_ORDER.search(_DESCENDING.sub(" ", head))
    if other:
        return None, None, None, f"the question says {other.group(0)!r} beside its order"
    why = _transform_why(head, algo)
    if why:
        return None, None, None, why
    return names, algo, "descending", None


def _wide_answer(names, algo, direction, files):
    keyed = []
    for n in names:
        d = files.get(n)
        if not isinstance(d, (bytes, bytearray)):
            return None, f"the delivery has no file named {n!r}"
        keyed.append((len(d) if algo == SIZE else hashlib.new(algo, bytes(d)).hexdigest(), n))
    if len({k for k, _ in keyed}) != len(keyed):
        return None, f"two of the named files share a {'size' if algo == SIZE else 'digest'}; the order is ambiguous"
    order = [n for _, n in sorted(keyed, reverse=direction == "descending")]
    value = json.dumps(order, separators=(",", ":"), ensure_ascii=False)
    return labels.pick(f"{KEY}{algo}+{direction}", [(f"{algo}_{direction}", value)]), None


def covered(answer_id, question_text, answer_format):
    """None when this handler answers the question plain once its files are delivered (rows 320 and 344: the
    contract hook, which has no files before the clock), else why it would not. What only the files settle (a
    named file missing, two equal digests) cannot be known before the start and is not held against it."""
    why = _names(answer_id, question_text, answer_format)[1]
    if why is None:
        return None
    names, algo, direction, _ = _wide(answer_id, question_text, answer_format)
    if names is not None:
        return f"the {algo} {direction} order is read but answered unsure (not judged; B-248)"
    return why


def answer(answer_id, question_text, answer_format, files):
    """(value, why): the compact JSON array of the named filenames in ascending digest order, or
    (None, reason) when the fact is not settled. The transform and the output form are both stated
    by the question, so a non-None value is a plain answer. B-248: a descending digest order or a size
    order stated in so many words is answered too, UNSURE (a labels.pick string)."""
    algo = route(answer_id)
    names, why = _names(answer_id, question_text, answer_format)
    if names is None:
        wide, w_algo, direction, _ = _wide(answer_id, question_text, answer_format)
        if wide is None:
            return None, why
        return _wide_answer(wide, w_algo, direction, files)
    digs = []
    for n in names:
        d = files.get(n)
        if not isinstance(d, (bytes, bytearray)):
            return None, f"the delivery has no file named {n!r}"
        digs.append((hashlib.new(algo, bytes(d)).hexdigest(), n))
    if len({h for h, _ in digs}) != len(digs):
        return None, "two of the named files share a digest; the ascending order is ambiguous"
    return json.dumps([n for _, n in sorted(digs)], separators=(",", ":"), ensure_ascii=False), None
