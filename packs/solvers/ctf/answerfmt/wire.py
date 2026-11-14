"""From a Rendering to the answer a lane returns: plain text, the labels unsure form, or None (B-232).

    wire(question, value, lane)                  -> str | None
    to_wire(rendering, key, labels=None)         -> str | None
    key_for(lane, field, rendering, kind="")     -> "<lane>.<field>/answer_format.<kind>.<axes>"

A plain rendering is returned as its text. A withheld one is None (nothing sent). One with options goes
to solvers/common/labels.py: `labels.candidates` when the order axis is open (file order and ascending
are different lists, so different candidate facts, row 346) or the split axis is (a string read as
several tokens or as one), else `labels.pick` (spellings of one fact).
Either returns the plain text once the judge has accepted a name for the key, the `??` unsure string
the runners probe otherwise, or None when every option was rejected.

labels.py is loaded by path through ctf.packs (pack `solvers/common/labels.py`): a missing or broken
file raises PackMissing / PackLoadError, never a silent plain answer. Tests pass their own `labels`.
labels decides which key prefixes it accepts (its lane check raises ValueError for an unknown lane
while the judge ledger is on); that error is not caught here.
"""
from __future__ import annotations

import re

from .. import packs as _packs, paths as _paths
from .contract import read
from .rendering import OPTIONS, PLAIN, Rendering, render

__all__ = ["wire", "to_wire", "key_for", "load_labels"]

LABELS_MODULE = "ctf_answerfmt_labels"
# axes whose options are different facts (a different list, or one token against several), not spellings
CANDIDATE_AXES = frozenset({"order", "split"})


def load_labels():
    """solvers/common/labels.py of this checkout (ctf.packs; PackMissing / PackLoadError on a miss)."""
    path = _paths.repo_root() / "solvers" / "common" / "labels.py"
    return _packs.load_module(LABELS_MODULE, path, pack="solvers/common/labels.py")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9_-]+", "_", str(text).strip().lower()).strip("_") or "answer"


def key_for(lane: str, field: str, rendering: Rendering, kind: str = "") -> str:
    """The labels key of a rendering's options: the field and the open axes are in it, so every list of
    the same field under the same open axes shares the judge's accepted hypothesis."""
    axes = "+".join(rendering.axes) or "none"
    return f"{_slug(lane)}.{_slug(field)}/answer_format.{_slug(kind or 'any')}.{axes}"


def to_wire(rendering: Rendering, key: str, labels=None):
    """The answer to return for `rendering` under labels key `key`."""
    if rendering.status == PLAIN:
        return rendering.value
    if rendering.status != OPTIONS:
        return None
    labels = labels if labels is not None else load_labels()
    if CANDIDATE_AXES & set(rendering.axes):
        return labels.candidates(key, list(rendering.options))
    return labels.pick(key, list(rendering.options))


def wire(question: dict, value, lane: str, *, field: str | None = None, labels=None, ordered: bool = False):
    """render() a value from the question's own answer_format, then to_wire() it. `field` defaults to
    the question's id (`id`, `qid` or `answer_id`)."""
    if not isinstance(question, dict):
        raise TypeError(f"question is a {type(question).__name__}, not a mapping")
    fmt = question.get("answer_format")
    text = next((question[k] for k in ("question", "text", "prompt") if isinstance(question.get(k), str)), None)
    c = read(fmt, text)
    r = render(value, fmt, question_text=text, ordered=ordered, contract=c)
    if r.status != OPTIONS:
        return to_wire(r, "", labels=labels) if r.status == PLAIN else None
    fid = field or next((question[k] for k in ("id", "qid", "answer_id") if isinstance(question.get(k), str)), None)
    if not fid:
        raise ValueError("the question has no id and no field was given: the labels key would be shared by every question")
    return to_wire(r, key_for(lane, fid, r, c.kind), labels=labels)
