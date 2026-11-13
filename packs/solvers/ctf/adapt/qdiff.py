"""The question-contract diff of a timed start (B-036).

Huntress Day 17, Binary Time Trial: the timed questions changed one answer's kind from integer to
exact_text and added a sentence allowing the literal `none` for `analysis_recover_code`. Nothing compared
the timed start's questions with the base's, so the change surfaced after 1h43m instead of at the gate.
`qdiff` makes that comparison the moment the start reply (or a saved status body) is in hand:

    d = qdiff(base_body, timed_body)          # bodies with "questions", or the question lists
    d.attention                               # the changes a lane reader may not survive
    print("\\n".join(d.lines()))

Per id (`id`, else `qid`): `added`, `removed`, `kind` (answer_format.kind), `none` (the literal `none`
newly allowed or no longer allowed, by `ctf.idresolve.permits_literal_none`, B-010's rule), `syntax`,
`accepted` (accepted_values) and `text` (the question wording). Every change but `text` needs attention:
a reader proven on the base may answer it wrongly. Ids renamed wholesale show as removed + added; run
`python -m ctf resolve-ids` (B-010) on the timed questions for those. QDiffError for a body without a
question list or a question without an id.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import idresolve as _idresolve
from . import AdaptError

INFO_ONLY = ("text",)


class QDiffError(AdaptError):
    """A body or question the diff cannot read."""


@dataclass(frozen=True)
class QChange:
    what: str                  # added | removed | kind | none | syntax | accepted | text
    qid: str
    before: str | None = None
    after: str | None = None

    @property
    def attention(self) -> bool:
        return self.what not in INFO_ONLY

    def line(self) -> str:
        tag = "ATTN" if self.attention else "info"
        if self.what in ("added", "removed"):
            return f"{tag} {self.what:<8} {self.qid}"
        return f"{tag} {self.what:<8} {self.qid}: {self.before!s} -> {self.after!s}"


@dataclass(frozen=True)
class QDiff:
    changes: tuple[QChange, ...]

    @property
    def attention(self) -> tuple[QChange, ...]:
        return tuple(c for c in self.changes if c.attention)

    def lines(self) -> list[str]:
        if not self.changes:
            return ["same questions: no change from the base"]
        return [c.line() for c in self.changes]


def questions_of(body) -> list[dict]:
    qs = body.get("questions") if isinstance(body, dict) else body
    if not isinstance(qs, list):
        raise QDiffError("no question list: pass an attempt/status body with 'questions', or the list itself")
    out = []
    for i, q in enumerate(qs):
        if not isinstance(q, dict) or not isinstance(q.get("id") or q.get("qid"), str):
            raise QDiffError(f"question #{i + 1} has no string id")
        out.append(q)
    return out


def _fmt(q: dict) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _accepted(q: dict) -> str | None:
    a = _fmt(q).get("accepted_values")
    return None if a is None else ", ".join(sorted(str(x) for x in a)) if isinstance(a, list) else str(a)


def qdiff(before, after) -> QDiff:
    """The changes from the base's questions (`before`) to the timed start's (`after`), in the timed
    start's order, removed ids last."""
    b = {(q.get("id") or q.get("qid")): q for q in questions_of(before)}
    a_list = questions_of(after)
    a = {(q.get("id") or q.get("qid")): q for q in a_list}
    out: list[QChange] = []
    for q in a_list:
        qid = q.get("id") or q.get("qid")
        old = b.get(qid)
        if old is None:
            out.append(QChange("added", qid))
            continue
        ok, nk = _fmt(old).get("kind"), _fmt(q).get("kind")
        if ok != nk:
            out.append(QChange("kind", qid, ok, nk))
        on, nn = _idresolve.permits_literal_none(old), _idresolve.permits_literal_none(q)
        if on != nn:
            out.append(QChange("none", qid, "allowed" if on else "not allowed", "allowed" if nn else "not allowed"))
        os_, ns = _fmt(old).get("syntax"), _fmt(q).get("syntax")
        if os_ != ns:
            out.append(QChange("syntax", qid, os_, ns))
        oa, na = _accepted(old), _accepted(q)
        if oa != na:
            out.append(QChange("accepted", qid, oa, na))
        ot, nt = old.get("question"), q.get("question")
        if ot != nt:
            out.append(QChange("text", qid, ot, nt))
    for qid in b:
        if qid not in a:
            out.append(QChange("removed", qid))
    return QDiff(tuple(out))
