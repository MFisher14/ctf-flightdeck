"""Drafted-text markers and the review-pass gate (B-097).

Text a model drafted into a staged writeup or retro sits between two markers:

    <!-- drafted by=claude-sonnet-5-5 task=writeup pass=pending -->
    ...the drafted prose...
    <!-- /drafted -->

`by` is the model that wrote it (as the harness reported it), `task` the routing task type
(ctf.writeup.assist.TASKS) and `pass` the state of the one review pass on the primary model:

    pending      drafted on another model; the review pass has not run
    none         needs no review pass (retro open questions only); never publishable
    <model id>   the pass ran on that model (or the block was drafted on the primary model itself)
    person       a person reviewed it (written by hand)

Only `person`, models.primary and a models.fallback id count as reviewed (`reviewed`, compared
case-insensitively). Any other value, a typo, `PENDING` or a model outside the primary tier (a review
the harness moved to the docs model), is not a pass and blocks.

Model output is neutralized before it is written (ctf.writeup.common.neutralize), so drafted text can
never open, close or forge a marker; only a person editing the file can.

Gate (pass_findings): `pending`, a block with no `pass`, any value that is not a reviewer (above),
an unclosed block and a close without an open are blocking everywhere (`ctf writeup check`, publish). `none` is accepted by check only on a
retro-questions block and is always blocking at publish: published text gets its pass.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .. import event as _event
from . import scan as _scan

OPEN_RX = re.compile(r"<!--\s*drafted\b([^>]*?)\s*-->", re.I)
CLOSE_RX = re.compile(r"<!--\s*/drafted\s*-->", re.I)
ATTR_RX = re.compile(r"([a-z_]+)=(\S+)")
PENDING = "pending"
NONE = "none"
PERSON = "person"
UNREVIEWED_OK_TASKS = frozenset({"retro-questions"})


@dataclass
class Block:
    start: int          # offset of the open marker
    body_start: int     # first character after the open marker
    body_end: int       # offset of the close marker
    end: int            # first character after the close marker
    attrs: dict

    @property
    def by(self) -> str:
        return self.attrs.get("by", "?")

    @property
    def task(self) -> str:
        return self.attrs.get("task", "?")

    @property
    def pass_(self) -> str:
        return self.attrs.get("pass", PENDING)

    def body(self, text: str) -> str:
        return text[self.body_start:self.body_end]


def open_marker(by: str, task: str, pass_: str) -> str:
    return f"<!-- drafted by={by} task={task} pass={pass_} -->"


def wrap(text: str, by: str, task: str, pass_: str) -> str:
    return f"{open_marker(by, task, pass_)}\n{text.strip()}\n<!-- /drafted -->"


def blocks(text: str) -> tuple[list[Block], list[tuple[str, int]]]:
    """(well-formed blocks, problems). A problem is (kind, offset): `unclosed-draft` for an open
    marker with no close before the next open or the end, `stray-draft-close` for a close with no
    open."""
    out: list[Block] = []
    problems: list[tuple[str, int]] = []
    opens = list(OPEN_RX.finditer(text))
    closes = list(CLOSE_RX.finditer(text))
    used: set[int] = set()
    for i, m in enumerate(opens):
        limit = opens[i + 1].start() if i + 1 < len(opens) else len(text)
        close = next((c for c in closes if m.end() <= c.start() < limit and c.start() not in used), None)
        if close is None:
            problems.append(("unclosed-draft", m.start()))
            continue
        used.add(close.start())
        out.append(Block(m.start(), m.end(), close.start(), close.end(), dict(ATTR_RX.findall(m.group(1)))))
    for c in closes:
        if c.start() not in used:
            problems.append(("stray-draft-close", c.start()))
    return out, problems


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def reviewers(models: _event.Models) -> frozenset[str]:
    """The pass values that mean the review pass ran: a person, or a primary-tier model."""
    return frozenset({PERSON, models.primary.casefold(), *(m.casefold() for m in models.fallback)})


def reviewed(pass_: str, models: _event.Models) -> bool:
    return pass_.casefold() in reviewers(models)


def pass_findings(text: str, path: str = "", *, publish: bool, models: _event.Models) -> list[_scan.Finding]:
    """Blocking findings for drafted text that has not had its review pass (see the module doc).
    `models` is the event profile's: only its primary tier (or a person) clears a block."""
    found, problems = blocks(text)
    out = [_scan.Finding(kind, _line(text, off), "drafted-text marker", True, path) for kind, off in problems]
    for b in found:
        p = b.pass_.casefold()
        if p == NONE:
            if not publish and b.task in UNREVIEWED_OK_TASKS:
                continue
            why = f"drafted by {b.by} with pass=none; published text needs the review pass"
        elif p == PENDING:
            why = f"drafted by {b.by}; review pass pending (`ctf writeup review`)"
        elif reviewed(p, models):
            continue
        else:
            why = (f"drafted by {b.by} with pass={b.pass_}: not a review pass (only person, models.primary "
                   f"{models.primary} or a models.fallback id clears a block)")
        out.append(_scan.Finding("unreviewed-draft", _line(text, b.start), why, True, path))
    return out
