"""Multi-file synthesis answers, routed by answer-id suffix (B-232).

Some questions are about no single file's property but about the delivery as a whole. Huntress Day 15's
timed modes asked one that the base never showed:

    id      ...-synthesis-sha256-order
    text    "Compute the full-file SHA-256 digest of each named file, then submit a compact JSON array of
             their filenames in ascending digest order. Files: ["a.txt","b.jpg","c.exe"]"

A handler is registered against an id-suffix pattern; `route(answer_id)` finds it, and
`answer(answer_id, question_text, answer_format, files)` returns a Rendering (ctf.answerfmt.rendering):
the handler orders the names, and the question's own answer_format renders them (a JSON array, or a
stated separator) with `ordered=True`. Every fact the question does not settle withholds the answer
with a named reason; a handler never guesses. `covered(answer_id, question_text, answer_format)`
answers before the files are delivered: None when the question settles the transform, else why not.

Shipped handler `digest_order`: ids ending in `[synthesis-]<algo>-[digest-]order` (`<algo>` one of
md5, sha1, sha224, sha256, sha384, sha512, sha3-224/256/384/512, blake2b, blake2s). The text must:
  - carry a `Files: [...]` JSON list of distinct names (the last one in the text);
  - say ascending or descending, and not both;
  - name no digest algorithm other than the id's;
  - say nothing that narrows the bytes digested (first/last N bytes, header, offset, chunk,
    excluding, salted, HMAC, twice, encoded ...);
  - ask the file names, not the digests.
Each named file must be in `files` (by its exact key, else by a unique basename) and no two may share
a digest. `register(name, suffix, handler, covered=None)` adds another handler; a later registration
under the same name replaces the earlier one.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .contract import Contract, read
from .rendering import Rendering, _withheld, render

__all__ = ["Handler", "SynthError", "register", "route", "handlers", "answer", "covered", "files_from_dir",
           "DIGESTS"]

DIGESTS = {"md5": "md5", "sha1": "sha1", "sha224": "sha224", "sha256": "sha256", "sha384": "sha384",
           "sha512": "sha512", "sha3-224": "sha3_224", "sha3-256": "sha3_256", "sha3-384": "sha3_384",
           "sha3-512": "sha3_512", "blake2b": "blake2b", "blake2s": "blake2s"}

MAX_FILE_BYTES = 512 * 1024 * 1024     # files_from_dir refuses a larger member (a named error, not a skip)


class SynthError(ValueError):
    """A synthesis call that cannot run at all (a bad registration, a files folder that is not one)."""


@dataclass(frozen=True)
class Handler:
    name: str
    suffix: re.Pattern
    # (match, question text, contract, files) -> (ordered list, None) | (None, why)
    solve: Callable
    # (match, question text, contract) -> None | why; None means the text settles the transform
    settles: Callable | None = None


_HANDLERS: dict[str, Handler] = {}


def register(name: str, suffix: str | re.Pattern, handler: Callable, covered: Callable | None = None) -> Handler:
    """Register `handler` for answer ids whose lowercased form the `suffix` pattern finds (searched;
    anchor it with `$`)."""
    if not name or not callable(handler):
        raise SynthError("a handler needs a name and a callable")
    rx = re.compile(suffix) if isinstance(suffix, str) else suffix
    if not rx.pattern.endswith("$"):
        raise SynthError(f"handler {name!r}: the suffix pattern {rx.pattern!r} must be anchored with $")
    h = Handler(name, rx, handler, covered)
    _HANDLERS[name] = h
    return h


def handlers() -> list[Handler]:
    return list(_HANDLERS.values())


def route(answer_id) -> tuple[Handler, re.Match] | None:
    """(handler, match) for the first handler whose suffix the id ends in, or None."""
    aid = str(answer_id or "").strip().lower()
    if not aid:
        return None
    for h in _HANDLERS.values():
        m = h.suffix.search(aid)
        if m:
            return h, m
    return None


def files_from_dir(folder) -> dict[str, bytes]:
    """{relative posix path: bytes} of every regular file under `folder` (symlinks are not followed).
    SynthError for a folder that is not one or a member over MAX_FILE_BYTES."""
    root = Path(folder)
    if not root.is_dir():
        raise SynthError(f"files folder {root} is not a directory")
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink() or not p.is_file():
            continue
        if p.stat().st_size > MAX_FILE_BYTES:
            raise SynthError(f"{p.name}: {p.stat().st_size} bytes is over the {MAX_FILE_BYTES}-byte limit")
        out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


def _member(files: Mapping[str, bytes], name: str) -> tuple[bytes | None, str]:
    data = files.get(name)
    if isinstance(data, (bytes, bytearray)):
        return bytes(data), ""
    hits = [k for k in files if str(k).replace("\\", "/").rsplit("/", 1)[-1] == name]
    if len(hits) == 1 and isinstance(files[hits[0]], (bytes, bytearray)):
        return bytes(files[hits[0]]), ""
    if len(hits) > 1:
        return None, f"{len(hits)} delivered files are named {name!r}"
    return None, f"the delivery has no file named {name!r}"


def covered(answer_id, question_text, answer_format) -> str | None:
    """None when a handler routes this id and its question settles the transform; else why not."""
    hit = route(answer_id)
    if hit is None:
        return "no synthesis handler routes this answer id"
    h, m = hit
    if h.settles is None:
        return None
    return h.settles(m, str(question_text or ""), read(answer_format, None))


def answer(answer_id, question_text, answer_format, files: Mapping[str, bytes]) -> Rendering:
    """The synthesis answer for one question, as a Rendering (withheld with the reason when not settled)."""
    hit = route(answer_id)
    if hit is None:
        return _withheld("no synthesis handler routes this answer id")
    h, m = hit
    text = str(question_text or "")
    c = read(answer_format, None)    # the handler reads the order itself; the contract gives the form
    if h.settles is not None:
        why = h.settles(m, text, c)
        if why:
            return _withheld(why)
    seq, why = h.solve(m, text, c, files or {})
    if seq is None:
        return _withheld(why or f"handler {h.name} gave no answer")
    return render(list(seq), answer_format, ordered=True, contract=c)


# ------------------------------------------------------------------------------------------- digest_order

_ALGO_ID = "|".join(re.escape(a) for a in sorted(DIGESTS, key=len, reverse=True)).replace(r"\-", "[-_]?")
_DIGEST_SUFFIX = re.compile(rf"(?:^|[-_.])(?:synthesis[-_])?(?P<algo>{_ALGO_ID})[-_](?:digest[-_])?order$")
_ALGO_WORDS = re.compile(r"\b(md5|md4|sha-?(?:1|224|256|384|512)(?:[-/_](?:224|256))?|sha3[-_ ]?(?:224|256|384|512)|"
                         r"shake[-_ ]?(?:128|256)|blake2[bs]?|blake3|ripemd-?160|crc-?32c?|adler-?32|xxh\w*|"
                         r"murmur\w*|fnv\w*|ssdeep|tlsh|imphash|whirlpool)\b", re.I)
_NARROW = re.compile(r"\b(?:first|last|header|headers|prefix|trailing|leading|offset|chunks?|blocks?|truncated?|"
                     r"excluding|skip(?:ping)?|partial|portion|range|sections?|salt(?:ed)?|hmac|keyed|twice|double|"
                     r"base64|base32|hex-?encoded|encoded|reversed?)\b"
                     r"|\b\d+\s+bytes?\b", re.I)
_ASC_WORD = re.compile(r"\bascending\b|\bincreasing\b|\bsmallest\s+first\b|\blowest\s+first\b", re.I)
_DESC_WORD = re.compile(r"\bdescending\b|\bdecreasing\b|\blargest\s+first\b|\bhighest\s+first\b", re.I)
_NAMES = re.compile(r"\bfile\s?names\b|\bnames\s+of\s+the\s+files\b|\btheir\s+names\b", re.I)
_DIGEST_OUT = re.compile(r"\bsubmit\s+(?:the\s+|their\s+|a\s+\w+\s+(?:\w+\s+)?of\s+(?:the\s+|their\s+)?)?(?:digests|hashes)\b", re.I)


def _algo(word: str) -> str:
    w = word.lower().replace(" ", "").replace("_", "-")
    m = re.fullmatch(r"sha-?(1|224|256|384|512)", w)
    if m:
        return "sha" + m.group(1)
    m = re.fullmatch(r"sha3-?(224|256|384|512)", w)
    if m:
        return "sha3-" + m.group(1)
    return w


def _files_list(text: str) -> tuple[list[str] | None, str, str]:
    """(names, the text before the list, why not)."""
    i = text.rfind("Files:")
    if i < 0:
        return None, text, "the question has no 'Files:' list"
    head, tail = text[:i], text[i + len("Files:"):].strip()
    try:
        names, _end = json.JSONDecoder().raw_decode(tail)
    except ValueError:
        return None, head, "the 'Files:' list does not parse as JSON"
    if not isinstance(names, list) or not names or not all(isinstance(n, str) and n for n in names):
        return None, head, "the 'Files:' list is empty or is not a list of file names"
    if len(set(names)) != len(names):
        return None, head, "the 'Files:' list names a file more than once"
    return names, head, ""


def _digest_settles(m: re.Match, text: str, c: Contract) -> str | None:
    algo = _algo(m.group("algo"))
    names, head, why = _files_list(text)
    if names is None:
        return why
    named = {_algo(w) for w in _ALGO_WORDS.findall(head)}
    if named - {algo}:
        return f"the question names the digest {sorted(named)}, the id {algo!r}"
    narrow = _NARROW.search(head)
    if narrow:
        return f"the question says {narrow.group(0)!r}: the digest may not be of the whole file"
    asc, desc = bool(_ASC_WORD.search(head)), bool(_DESC_WORD.search(head))
    if asc == desc:
        return "the question does not say ascending or descending (or says both)"
    if _DIGEST_OUT.search(head) or not _NAMES.search(head):
        return "the question does not ask the file names themselves"
    if c.present and c.container == "json_object":
        return "the answer format asks a JSON object, not a list of names"
    return None


def _digest_solve(m: re.Match, text: str, c: Contract, files: Mapping[str, bytes]):
    algo = DIGESTS[_algo(m.group("algo"))]
    names, head, why = _files_list(text)
    if names is None:
        return None, why
    pairs = []
    for n in names:
        data, why = _member(files, n)
        if data is None:
            return None, why
        pairs.append((hashlib.new(algo, data).hexdigest(), n))
    if len({d for d, _ in pairs}) != len(pairs):
        return None, "two of the named files share a digest; the order between them is not settled"
    pairs.sort()
    if _DESC_WORD.search(head):
        pairs.reverse()
    return [n for _, n in pairs], None


register("digest_order", _DIGEST_SUFFIX, _digest_solve, _digest_settles)
