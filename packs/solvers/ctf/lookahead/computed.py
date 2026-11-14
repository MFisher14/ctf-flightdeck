"""The computed-field reader tier (B-174): stated computations over the delivered members.

Huntress Day 28: Binary met twenty questions that were not new reverse engineering but explicit
computations over members it already read (set counts, digest of digests, ...). The lane left them
"safe None", and building the readers after the release cost +15:56. This tier answers the member-level
ones from the question text alone, strictly:

    answer(question, files) -> str | int | None     # None: no template holds exactly, or it is ambiguous
    fill(questions, files, answers) -> (answers, filled_ids)   # only empty ids (None, missing, blank text)
    wrapped = wrap(solve_set)                        # a lane's solve_set with this tier behind it

Templates (TEMPLATES; the question text is matched whole, case and spacing folded, a trailing `?`
optional; `<name>` is a delivered member's base name, quoted with ` ' or "):

    count      "How many members (files) are in the delivered evidence set (delivery)"  kind integer
    size       "What is the size in bytes of member <name>"                           kind integer
    digest     "What is the <algo> of member <name>"                                   lowercase hex
    digests    "What is the <algo> of the concatenation of the members' <algo2> hex digests in name
               order[, separated by newlines]"                                         lowercase hex

<algo> is md5, sha1 or sha256 (also spelled sha-1, sha-256). A digest question whose answer format
asks upper case or a 0x prefix is not answered (the tier never guesses a spelling). A member name
that matches no member, or more than one, is not answered. Members are the keys of `files` (paths;
the base name is compared). New wordings are added as templates with a test, never as a looser
pattern.

The gate (ctf.lookahead.gate) runs this tier on the deterministic ids a lane's reader left
unanswered and shows the value it has, but still reports the id as a gap until the lane's own
reader answers it (for example by returning `wrap(solve_set)`): what the live runner calls is what
the release gets.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import PurePosixPath

_ALGO = r"(md5|sha-?1|sha-?256)"
_NAME = r"[`'\"]([^`'\"]+)[`'\"]"

TEMPLATES = {
    "count": re.compile(r"how many (?:members|files) (?:are|were) (?:in|delivered in) the "
                        r"(?:delivered evidence set|delivered set|delivery)"),
    "size": re.compile(r"what is the size in bytes of (?:the )?(?:member|file) " + _NAME),
    "digest": re.compile(r"what is the " + _ALGO + r"(?: digest| hash)? of (?:the )?(?:member|file) " + _NAME),
    "digests": re.compile(r"what is the " + _ALGO + r" of the concatenation of the (?:members'|files') "
                          + _ALGO + r" hex digests in (?:member |file )?name order"
                          r"(, separated by newlines)?"),
}
_INTEGER_KINDS = ("integer",)
_TEXT_KINDS = ("exact_text", "pattern")


def _text(q: dict) -> str:
    t = " ".join(str(q.get("question") or q.get("text") or "").split()).lower()
    return t[:-1] if t.endswith("?") else t


def _fmt(q: dict) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _hashfn(algo: str):
    return {"md5": hashlib.md5, "sha1": hashlib.sha1, "sha256": hashlib.sha256}[algo.replace("-", "")]


def _member(files: dict, name: str):
    hits = [k for k in files if PurePosixPath(str(k)).name == name]
    return files[hits[0]] if len(hits) == 1 else None


def _plain_hex_ok(q: dict) -> bool:
    syntax = str(_fmt(q).get("syntax") or "").lower()
    return not ("upper" in syntax or "0x" in syntax)


def answer(question: dict, files: dict):
    """The stated computation's answer, or None when no template holds exactly."""
    text, kind = _text(question), _fmt(question).get("kind")
    m = TEMPLATES["count"].fullmatch(text)
    if m:
        return len(files) if kind in _INTEGER_KINDS and files else None
    m = TEMPLATES["size"].fullmatch(text)
    if m:
        data = _member(files, m.group(1))
        return len(data) if kind in _INTEGER_KINDS and data is not None else None
    m = TEMPLATES["digest"].fullmatch(text)
    if m:
        data = _member(files, m.group(2))
        if data is None or kind not in _TEXT_KINDS or not _plain_hex_ok(question):
            return None
        return _hashfn(m.group(1))(data).hexdigest()
    m = TEMPLATES["digests"].fullmatch(text)
    if m:
        if not files or kind not in _TEXT_KINDS or not _plain_hex_ok(question):
            return None
        names = [PurePosixPath(str(k)).name for k in files]
        if len(set(names)) != len(names):
            return None                                   # name order is ambiguous
        inner = _hashfn(m.group(2))
        order = sorted(files, key=lambda k: PurePosixPath(str(k)).name)
        parts = [inner(files[k]).hexdigest() for k in order]
        joined = ("\n" if m.group(3) else "").join(parts)
        return _hashfn(m.group(1))(joined.encode("ascii")).hexdigest()
    return None


def _empty(v) -> bool:
    """None, or text that is blank: what the gate (gate.classify) counts as unanswered."""
    return v is None or (isinstance(v, str) and not v.strip())


def fill(questions, files: dict, answers: dict) -> tuple[dict, list[str]]:
    """A copy of `answers` with each empty id (None, missing, or blank text, as the gate counts it) the
    tier can compute filled; never overrides a real answer."""
    out, filled = dict(answers or {}), []
    for q in questions or []:
        if not isinstance(q, dict):
            continue
        qid = str(q.get("qid") or q.get("id") or "")
        if not qid or not _empty(out.get(qid)):
            continue
        v = answer(q, files)
        if v is not None:
            out[qid] = v
            filled.append(qid)
    return out, filled


def wrap(solve_set):
    """solve_set(questions, files, ctx) with this tier behind it: the lane's answers first."""
    def solve_with_computed(questions, files, ctx):
        got = solve_set(questions, files, ctx)
        if not isinstance(got, dict):
            return got
        return fill(questions, files, got)[0]
    solve_with_computed.__wrapped__ = solve_set
    return solve_with_computed
