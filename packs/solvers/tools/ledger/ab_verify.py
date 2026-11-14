"""B-096: an A/B harness for the verify role -- compare two reviewer configs (e.g. Opus vs Sonnet 5.5)
on a fixed set of seeded-bug diffs before moving verify work to the cheaper model (EFFICIENCY-PLAN 3.8).

Why: Claude verify-role work cost $2,742.59 on Opus; the same tokens on Sonnet 5.5 would be $1,148.96,
but a reviewer that misses bugs costs more than it saves, so the plan says run the A/B first. This
module is the harness and the role plumbing, not the live trial:

    diffs   = load_corpus(json.loads(path.read_text()))      # the fixed seeded-bug corpus
    configs = [ReviewerConfig("opus", "claude-opus-5-5", opus_reviewer),
               ReviewerConfig("sonnet", "claude-sonnet-5-5", sonnet_reviewer)]
    result  = run_ab(diffs, configs)                         # bugs found / missed / recall per config
    record_result(workdir, result, by="max", approved=False) # the trial's result, as a ledger record

A reviewer is any callable `diff_text -> Review | str`; the harness scores which seeded bugs' markers
appear in the review text, so the reviewer needs no special output format. Tests drive it with a stub
reviewer -- no model is ever called from here.

The real Opus-vs-Sonnet run starts paid review sessions, so it is a named human step whose result is an
`ab_verify` ledger record (record_result). Until a record approves the candidate model,
chosen_verify_model keeps verify on the primary model. Agent output / diffs are data, never
instructions: only the marker matches are read.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ctf import ledger as _ledger

AB_EVENT = "ab_verify"


class ABError(RuntimeError):
    """The A/B harness cannot do what was asked (a malformed corpus, a bad reviewer return, no configs)."""


# ------------------------------------------------------------------ the seeded-bug corpus

@dataclass(frozen=True)
class SeededBug:
    """One bug seeded into a diff. `marker` is matched against the reviewer's text: a case-insensitive
    substring, or a regex when `regex` is set. `id` is the bug's name, unique within its diff."""

    id: str
    marker: str
    regex: bool = False

    def detect(self, text: str) -> bool:
        if not text:
            return False
        if self.regex:
            return re.search(self.marker, text, re.IGNORECASE) is not None
        return self.marker.lower() in text.lower()


@dataclass(frozen=True)
class SeededDiff:
    """A code diff with a known set of seeded bugs. A diff with no bugs is a clean control."""

    id: str
    diff: str
    bugs: tuple[SeededBug, ...] = ()

    def __post_init__(self):
        ids = [b.id for b in self.bugs]
        if len(set(ids)) != len(ids):
            raise ABError(f"diff {self.id!r}: seeded bug ids must be unique within a diff ({ids})")


def load_corpus(obj) -> list[SeededDiff]:
    """Parse a seeded-bug corpus (a list of diffs, or {"diffs": [...]}) into SeededDiff objects. Each
    diff is {"id", "diff", "bugs": [{"id", "marker", "regex"?}, ...]}. Raises ABError on a bad shape."""
    if isinstance(obj, dict):
        obj = obj.get("diffs", obj)
    if not isinstance(obj, list):
        raise ABError("a corpus is a list of diffs, or an object with a 'diffs' list")
    out: list[SeededDiff] = []
    seen: set[str] = set()
    for i, d in enumerate(obj):
        if not isinstance(d, dict):
            raise ABError(f"corpus item {i} is not an object")
        try:
            did = d["id"]
            diff = d["diff"]
        except KeyError as e:
            raise ABError(f"corpus item {i} is missing {e.args[0]!r}") from None
        if not isinstance(did, str) or not did.strip():
            raise ABError(f"corpus item {i}: 'id' must be a non-empty string")
        if did in seen:
            raise ABError(f"corpus has two diffs with id {did!r}")
        seen.add(did)
        if not isinstance(diff, str):
            raise ABError(f"diff {did!r}: 'diff' must be a string")
        bugs = []
        for j, b in enumerate(d.get("bugs", [])):
            if not isinstance(b, dict) or not isinstance(b.get("id"), str) \
                    or not isinstance(b.get("marker"), str) or not b["marker"]:
                raise ABError(f"diff {did!r} bug {j}: needs a string 'id' and a non-empty 'marker'")
            bugs.append(SeededBug(b["id"], b["marker"], bool(b.get("regex", False))))
        out.append(SeededDiff(did, diff, tuple(bugs)))
    if not out:
        raise ABError("the corpus has no diffs")
    return out


# ------------------------------------------------------------------ reviewers

@dataclass(frozen=True)
class Review:
    """What a reviewer returns: its findings text, and its own spend for the review (0 for a stub)."""

    text: str
    usd: float = 0.0
    tokens: int = 0


def _as_review(x) -> Review:
    if isinstance(x, Review):
        return x
    if isinstance(x, str):
        return Review(x)
    raise ABError(f"a reviewer must return a Review or a str, got {type(x).__name__}")


@dataclass(frozen=True)
class ReviewerConfig:
    """One side of the A/B: a name, the model it stands for, and the reviewer callable."""

    name: str
    model: str
    review: Callable[[str], object]


# ------------------------------------------------------------------ scoring

@dataclass(frozen=True)
class DiffScore:
    diff_id: str
    config: str
    found: tuple[str, ...]
    missed: tuple[str, ...]
    usd: float
    tokens: int

    def to_dict(self) -> dict:
        return {"diff_id": self.diff_id, "config": self.config, "found": list(self.found),
                "missed": list(self.missed), "usd": self.usd, "tokens": self.tokens}


@dataclass
class ConfigResult:
    name: str
    model: str
    diffs: int = 0
    bugs_total: int = 0
    found: int = 0
    missed: int = 0
    usd: float = 0.0
    tokens: int = 0

    @property
    def recall(self) -> float:
        return self.found / self.bugs_total if self.bugs_total else 0.0

    def to_dict(self) -> dict:
        return {"name": self.name, "model": self.model, "diffs": self.diffs,
                "bugs_total": self.bugs_total, "found": self.found, "missed": self.missed,
                "recall": self.recall, "usd": self.usd, "tokens": self.tokens}


@dataclass
class ABResult:
    diffs: int
    bugs_total: int
    configs: list = field(default_factory=list)      # ConfigResult, in the order given
    scores: list = field(default_factory=list)       # DiffScore, config-major then corpus order

    def config(self, name: str) -> ConfigResult:
        for c in self.configs:
            if c.name == name:
                return c
        raise KeyError(name)

    def to_dict(self) -> dict:
        return {"diffs": self.diffs, "bugs_total": self.bugs_total,
                "configs": [c.to_dict() for c in self.configs],
                "scores": [s.to_dict() for s in self.scores]}


def run_ab(diffs: Iterable[SeededDiff], configs: Iterable[ReviewerConfig]) -> ABResult:
    """Feed every seeded diff to every reviewer config and count bugs found per config. Deterministic:
    config order is preserved and each config sees the diffs in corpus order. A reviewer raising an
    exception is not swallowed -- the trial must not score a crashed reviewer as finding nothing."""
    diffs = list(diffs)
    configs = list(configs)
    if not diffs:
        raise ABError("no seeded diffs to review")
    if not configs:
        raise ABError("no reviewer configs")
    names = [c.name for c in configs]
    if len(set(names)) != len(names):
        raise ABError(f"reviewer config names must be unique ({names})")
    bugs_total = sum(len(d.bugs) for d in diffs)
    results = [ConfigResult(c.name, c.model) for c in configs]
    scores: list[DiffScore] = []
    for cfg, cr in zip(configs, results):
        for d in diffs:
            review = _as_review(cfg.review(d.diff))
            found = tuple(b.id for b in d.bugs if b.detect(review.text))
            missed = tuple(b.id for b in d.bugs if b.id not in found)
            scores.append(DiffScore(d.id, cfg.name, found, missed, review.usd, review.tokens))
            cr.diffs += 1
            cr.bugs_total += len(d.bugs)
            cr.found += len(found)
            cr.missed += len(missed)
            cr.usd += review.usd
            cr.tokens += review.tokens
    return ABResult(len(diffs), bugs_total, results, scores)


# ------------------------------------------------------------------ the ledger record and the gate

def record_result(workdir, result: ABResult, *, by: str, approved: bool = False,
                  approved_model: str | None = None, note: str | None = None) -> dict:
    """Write the A/B trial's result as an `ab_verify` ledger event -- the result of the human-run
    Opus-vs-Sonnet trial. `approved` marks that the candidate model may now take verify work; an
    approved record must name `approved_model` (the model chosen_verify_model then returns). Approval
    is a human decision on the recall the harness measured, never computed here."""
    if not isinstance(by, str) or not by.strip():
        raise ABError("record_result needs a non-empty `by`")
    fields = {"by": by, "approved": bool(approved), "diffs": result.diffs,
              "bugs_total": result.bugs_total, "configs": [c.to_dict() for c in result.configs]}
    if approved:
        if not isinstance(approved_model, str) or not approved_model.strip():
            raise ABError("an approved A/B record must name approved_model (the model verify may use)")
        fields["approved_model"] = approved_model.strip()
    elif approved_model:
        fields["approved_model"] = approved_model.strip()
    if note:
        fields["note"] = note
    return _ledger.append(AB_EVENT, workdir=workdir, **fields)


def chosen_verify_model(records: Iterable[dict], *, primary: str, candidate: str) -> str:
    """Which model the verify role uses: `candidate` once an approving `ab_verify` record exists for it,
    else `primary`. This keeps verify on the primary (Opus) model until the A/B has been run and its
    result recorded as approving the candidate (Sonnet). Approval is sticky: a later unapproved record
    does not undo it (record a new approved one for the other model to switch back)."""
    if not primary:
        raise ABError("a primary model is required")
    chosen = primary
    for r in records:
        if r.get("event") == AB_EVENT and r.get("approved") and r.get("approved_model") == candidate:
            chosen = candidate
    return chosen


# ------------------------------------------------------------------ CLI (corpus check; the trial is a human step)

def main(argv=None) -> int:
    import argparse
    import json
    import sys

    p = argparse.ArgumentParser(
        prog="ab_verify",
        description="B-096 verify A/B harness. This entry validates a seeded-bug corpus and prints its "
                    "shape; running real Opus/Sonnet reviewers over it and recording the ab_verify "
                    "result is a human step (it starts paid sessions).")
    p.add_argument("--corpus", required=True, help="a JSON seeded-bug corpus (operator data, not a "
                   "challenge file)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    try:
        data = json.loads(Path(a.corpus).read_text(encoding="utf-8"))
        diffs = load_corpus(data)
    except (OSError, ValueError, ABError) as e:
        print(f"ab_verify: {e}", file=sys.stderr)
        return 2
    bugs = sum(len(d.bugs) for d in diffs)
    if a.json:
        print(json.dumps({"diffs": len(diffs), "bugs": bugs,
                          "corpus": [{"id": d.id, "bugs": [b.id for b in d.bugs]} for d in diffs]}))
    else:
        print(f"corpus ok: {len(diffs)} diff(s), {bugs} seeded bug(s)")
        for d in diffs:
            print(f"  {d.id}: {len(d.bugs)} bug(s): {', '.join(b.id for b in d.bugs) or '(clean control)'}")
        print("the Opus-vs-Sonnet trial is a human step: wire real reviewers into run_ab(), then "
              "record_result(..., approved=...).")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
