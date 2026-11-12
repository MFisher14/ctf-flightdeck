"""The light role's evaluation (D15): score a light model on small jobs before switching it on.

The orchestrator is code; a light model (light.py) only does small jobs, and only after the
player has measured it against the rules. This module runs a synthetic case set through any
light engines (rules, an OpenAI-compatible model, Claude, Cactus Needle, a Strands Decider
server) and scores each, so the player can compare them: accuracy per job, refusals and
failures (and a decision model's unsure answers), time and cost per job.

Six jobs, one per case kind:

- **hint**: name the technique a challenge description points at, or "none". Every engine
  answers from the same label space, the HINT lexicon's ids (ctf_flightdeck.detect.hints) plus
  "none", never from the case file's own answers. A hint case must expect one of those labels:
  any other id is refused before anything runs.
- **judge**: say whether a lane's steps use the technique the description hints at ("yes" or
  "no"): the hint judge's job in a run (detect/judge.py). A judge case names a lexicon technique.
  The rules answer from the technique's action cues, as the "ignores the hint" detector does.
- **summary**: write a short escalation summary of a lane's steps. Scored by keyword groups.
- **route**: three choice questions about a challenge (light.ROUTE_QUESTIONS): its category,
  the specialist family it suits, whether it needs a live instance. A route case expects an
  object with the three answers. The rules answer the category (the board's, as flightdeck
  reads it) and the instance (a URL on the board, or a service the description names), not
  the family.
- **recon**: write a first-pass brief on a challenge for the stronger model. A recon case
  holds `required` keyword groups and `traps`, phrases no brief may contain.
- **flagcheck**: say whether a flag-shaped string a lane found is the challenge's real flag or
  a stand-in. A flagcheck case says whether the candidate is written in the challenge's own
  text (`own_text`), which a run already holds for the player whatever the light model says.

A text job (summary, recon) is right when every required group is present, each group a
keyword or a list of alternatives, and no trap phrase is. Keywords match whole words only,
ignoring letter case and runs of white space ("stegano" is not in "steganography"), and a brief's
length is said against what its prompt asks (light.BRIEF_WORDS) and the run's cap
(light.BRIEF_CHARS): keyword verdicts under-credit, so the scorecard can list every miss for the
player to read.

Each engine answers each job it can do with one try, within its time limit, so a paid engine
makes at most as many calls as there are jobs (a route case is three). A job that fails (the
model declined, the API failed or timed out, the reply was cut off or empty, or it named no
allowed option) scores wrong, and the scorecard counts it by kind next to the accuracy: a model
that never answers does not read as a weak one, nor a refusing one as a wrong one. A reply that
is exactly one option's whole line is read as that option and counted in a row of its own. A
decision model's unsure answer (its confidence below its threshold: in a run, the rules' answer
stands) is neither right nor wrong: it is left out of the accuracy, which for a decision model
is over the answers it was sure of (and any jobs it failed); the unsure answers have a row of
their own, and a table reads the one run at other thresholds. An engine whose first jobs all
fail with an error (a server that is down, a model that is not there) is stopped with
EngineFailed rather than run through the whole set.

As a run uses each job, beside the stand-alone figure: the judge is asked only where the rules
see no action cue (the "ignores the hint" alert is up), and can only take an alert down;
route's category comes from the board wherever flightdeck reads a known code there, its
instance always from the rule, its family from the engine; flagcheck holds a flag only beyond
the planted-flag hold, and a hold is all it can do. The rules column is a run with no light
model. Each engine is compared with the rules and with the best column by McNemar's exact test
on the same cases.

Untrusted text. A case's text goes to a model inside the harness's data fence, folded, and a
model's answer is read strictly (light.py). Nothing a model answers here changes a setting; it
is only scored.

The lexicon is imported when a hint or judge case needs it. When it cannot be imported or
loaded, scoring fails loudly with LocalModelError, never with an empty or guessed baseline.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .agent.prompts import FENCE_CLOSE as FENCE_CLOSE
from .agent.prompts import FENCE_OPEN as FENCE_OPEN
from .light import (
    BRIEF_CHARS,
    BRIEF_WORDS,
    DECIDER,
    ERROR,
    FLAG_QUESTION,
    FLAGCHECK,
    HINT,
    JUDGE,
    NO,
    NO_ANSWER,
    NONE,
    OUTSIDE,
    REAL,
    RECON,
    REFUSED,
    ROUTE,
    ROUTE_QUESTIONS,
    RULES,
    STAND_IN,
    SUMMARY,
    TIMEOUT,
    UNSURE,
    YES,
    Answer,
    Choice,
    Light,
    Question,
    RulesLight,
    shown,
    technique_choices,
)
from .text import untrusted

KINDS = (HINT, JUDGE, SUMMARY, ROUTE, RECON, FLAGCHECK)
TEXT_KINDS = (SUMMARY, RECON)
MIN_KEYWORD = 3  # letters or digits a keyword or trap needs
STOP_AFTER = 3  # an engine whose first jobs (this many, or all it has) all fail with an error is stopped
THRESHOLDS = (0.5, 0.7, 0.9)  # a decider column's threshold table, beside its best guess
SIGNIFICANT = 0.05  # McNemar's p below which a case set tells two columns apart
CASE_KEYS = ("kind", "input", "expected", "required", "traps", "own_text", "id")


class LocalModelError(Exception):
    """An evaluation could not run for a named reason (no silent fallback)."""


class CaseError(LocalModelError):
    """A case file is malformed; the message names the line and the problem."""


class EngineFailed(LocalModelError):
    """An engine failed on every one of its first jobs; the message is the last failure's reason."""


@dataclass(frozen=True)
class Case:
    """One evaluation case.

    `kind` is one of KINDS. `input` is the data the job reads: a hint case has `description`; a
    judge case has `description`, `technique` (a lexicon id) and `steps` (a list of {command,
    output}); a summary case has `steps` and may carry `plan` and `challenge`; a route or recon
    case is a challenge as the board gives it (name, category, points, solves, description,
    files, urls); a flagcheck case is a found flag (name, category, flag_format, description,
    candidate, where). `expected` is the answer to score against: a technique id or "none",
    "yes" or "no", a summary's keywords (comma-separated), route's {category, family, instance},
    a model brief for recon (kept, not scored), "real" or "stand-in". `required` (recon; a
    summary may have it in place of its keywords) is keyword groups, each a tuple of
    alternatives; `traps` (recon) phrases no brief may hold; `own_text` (flagcheck) whether the
    candidate is written in the challenge's own text; `ident` a name for the case ("route-18").
    """

    kind: str
    input: dict
    expected: str | dict
    required: tuple[tuple[str, ...], ...] = ()
    traps: tuple[str, ...] = ()
    own_text: bool | None = None
    ident: str = ""


@dataclass(frozen=True)
class CaseResult:
    """How one job scored. `predicted` is what the engine answered, folded to one safe line for
    display. `applicable` is False for a job the engine does not do (a summary, for the rules):
    it is left out of its accuracy. `answered` is False when the job failed or a decision model
    was unsure, and `failure` says how (light.REFUSED, ERROR, TIMEOUT, NO_ANSWER, OUTSIDE, or
    UNSURE), `detail` in words. An UNSURE result is never `correct`, and is left out of the
    accuracy too: it is neither right nor wrong.

    `question` is route's question (category, family, instance); `case` the case's number in the
    set, from 1, and `ident` its name. `in_run` is whether a run would have got it right (None:
    a job no run uses, or one the engine does not do): see the module doc. `alert` and
    `taken_down` (judge): the rules raised the alert, and the engine took it down; `planted` and
    `held` (flagcheck): the candidate is in the challenge's own text, and the engine held it.
    `leaned` and `confidence`: a decision model's choice, sure or not, and how sure. `echoed`:
    the answer was an option's whole line. `reply`, `missing`, `traps_hit`, `words` and `chars`:
    a text job's reply (untrusted), the required groups it lacks, the traps it holds, its
    length."""

    kind: str
    expected: str
    predicted: str
    correct: bool
    applicable: bool = True
    detail: str = ""
    answered: bool = True
    failure: str = ""
    seconds: float = 0.0
    question: str = ""
    case: int = 0
    ident: str = ""
    in_run: bool | None = None
    alert: bool = False
    taken_down: bool = False
    planted: bool | None = None
    held: bool = False
    leaned: str | None = None
    confidence: float | None = None
    echoed: bool = False
    reply: str = ""
    missing: tuple[str, ...] = ()
    traps_hit: tuple[str, ...] = ()
    words: int = 0
    chars: int = 0

    @property
    def row(self) -> str:
        """The scorecard row it counts in: its kind, or route's question ("route family")."""
        return f"{self.kind} {self.question}" if self.question else self.kind

    @property
    def name(self) -> str:
        """How a miss names it: its id or its number, and route's question."""
        name = self.ident or f"case {self.case}"
        return f"{name}/{self.question}" if self.question else name


ROWS = (HINT, JUDGE, SUMMARY, *(f"{ROUTE} {q.key}" for q in ROUTE_QUESTIONS), RECON, FLAGCHECK)


@dataclass(frozen=True)
class EvalReport:
    """The scores of one engine over the cases. `dollars` is None once any job's cost was
    unknown."""

    label: str
    results: tuple[CaseResult, ...]
    tokens: int = 0
    dollars: float | None = None
    engine: str = ""

    @property
    def scored(self) -> tuple[CaseResult, ...]:
        """The results of the jobs run (the applicable ones): one per job."""
        return tuple(r for r in self.results if r.applicable)

    @property
    def graded(self) -> tuple[CaseResult, ...]:
        """The results the accuracy is over: every job run but a decision model's unsure ones,
        which are neither right nor wrong (in a run, the rules' answer stands on them)."""
        return tuple(r for r in self.scored if r.failure != UNSURE)

    @property
    def correct(self) -> int:
        return sum(1 for r in self.graded if r.correct)

    @property
    def total(self) -> int:
        """How many jobs were run, unsure ones included: what the rates and the time and cost
        per job are over."""
        return len(self.scored)

    @property
    def accuracy(self) -> float:
        graded = len(self.graded)
        return self.correct / graded if graded else 0.0

    @property
    def unanswered(self) -> int:
        """How many jobs failed to answer (refused, failed, cut off, empty, not an option); a
        decision model's unsure answers are counted apart (`unsure`)."""
        return sum(1 for r in self.scored if not r.answered and r.failure != UNSURE)

    @property
    def unsure(self) -> int:
        """How many jobs a decision model answered below its confidence threshold."""
        return self.count(UNSURE)

    @property
    def echoed(self) -> int:
        """How many answers were an option's whole line, read as that option."""
        return sum(1 for r in self.scored if r.echoed)

    def count(self, *failures: str) -> int:
        """How many jobs failed in one of these ways."""
        return sum(1 for r in self.scored if r.failure in failures)

    @property
    def seconds(self) -> float:
        return sum(r.seconds for r in self.scored)

    def kinds(self) -> list[str]:
        """The rows (kinds, and route's questions) this engine scored, in ROWS order."""
        return [k for k in ROWS if any(r.row == k for r in self.scored)]

    def by_kind(self, kinds: Sequence[str] | None = None) -> dict[str, tuple[int, int]]:
        """{row: (correct, graded)} for each row it ran jobs of (of `kinds`, when given): a row
        whose every job was unsure is (0, 0)."""
        out: dict[str, tuple[int, int]] = {}
        for result in self.scored:
            if kinds is not None and result.row not in kinds:
                continue
            got, had = out.get(result.row, (0, 0))
            graded = result.failure != UNSURE
            out[result.row] = (got + int(graded and result.correct), had + int(graded))
        return out


# --------------------------------------------------------------------------- loading cases


def default_cases_path() -> Path:
    """The synthetic case set bundled with flightdeck."""
    path = Path(str(files("ctf_flightdeck").joinpath("localmodel_cases.jsonl")))
    if not path.is_file():
        raise FileNotFoundError(f"the local-model case set is missing from this installation (looked in {path})")
    return path


def load_cases(path: Path) -> list[Case]:
    """Read a JSONL case file. One JSON object per line; blank lines and `#` comments are
    skipped. Every problem raises CaseError naming the line, so a malformed set never runs
    as a shorter one. (Whether a technique id is a lexicon id is checked when the cases are
    scored, against the lexicon itself.)"""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CaseError(f"cannot read the case file {path}: {exc.strerror or exc}") from None
    cases: list[Case] = []
    seen: dict[str, int] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise CaseError(f"line {number}: not valid JSON ({exc})") from None
        case = _case(obj, number)
        if case.ident:
            if case.ident in seen:
                raise CaseError(f"line {number}: id {case.ident!r} is used on line {seen[case.ident]} too")
            seen[case.ident] = number
        cases.append(case)
    if not cases:
        raise CaseError(f"no cases in {path}")
    return cases


def _case(obj: object, number: int) -> Case:
    if not isinstance(obj, dict):
        raise CaseError(f"line {number}: a case must be a JSON object, got {type(obj).__name__}")
    extra = set(obj) - set(CASE_KEYS)
    if extra:
        raise CaseError(f"line {number}: unknown field(s) {', '.join(sorted(extra))}")
    kind = obj.get("kind")
    if kind not in KINDS:
        raise CaseError(f"line {number}: kind must be one of {', '.join(KINDS)}, got {kind!r}")
    data = obj.get("input")
    if not isinstance(data, dict):
        raise CaseError(f"line {number}: input must be an object")
    ident = obj.get("id", "")
    if not isinstance(ident, str) or ("id" in obj and not ident.strip()):
        raise CaseError(f"line {number}: id must be a non-empty string")
    for key, kinds in (("required", (SUMMARY, RECON)), ("traps", (RECON,)), ("own_text", (FLAGCHECK,))):
        if key in obj and kind not in kinds:
            raise CaseError(f"line {number}: {key} is for {' and '.join(kinds)} cases only")
    expected = obj.get("expected")
    if kind == ROUTE:
        return Case(kind, data, _route_expected(expected, data, number), ident=ident)
    if not isinstance(expected, str):
        raise CaseError(f"line {number}: expected must be a string")
    if kind in (HINT, JUDGE):
        description = data.get("description")
        if not isinstance(description, str) or not description.strip():
            raise CaseError(f"line {number}: a {kind} case needs a non-empty input.description")
    if kind == HINT and not expected.strip():
        raise CaseError(f"line {number}: a hint case needs an expected technique id (or 'none')")
    if kind == JUDGE:
        technique = data.get("technique")
        if not isinstance(technique, str) or not technique.strip():
            raise CaseError(f"line {number}: a judge case needs input.technique, the id of a lexicon technique")
        if expected.strip().lower() not in (YES, NO):
            raise CaseError(f"line {number}: a judge case expects 'yes' or 'no'")
    if kind in (JUDGE, SUMMARY):
        steps = data.get("steps")
        if not isinstance(steps, list) or not steps:
            raise CaseError(f"line {number}: a {kind} case needs a non-empty input.steps list")
        for index, step in enumerate(steps):
            if not isinstance(step, dict) or not isinstance(step.get("command"), str):
                raise CaseError(f"line {number}: step {index} must be an object with a string 'command'")
    if kind == FLAGCHECK:
        if expected not in (REAL, STAND_IN):
            raise CaseError(f"line {number}: a flagcheck case expects {REAL!r} or {STAND_IN!r}")
        candidate = data.get("candidate")
        if not isinstance(candidate, str) or not candidate:
            raise CaseError(f"line {number}: a flagcheck case needs input.candidate, the flag-shaped string found")
        own_text = obj.get("own_text")
        if not isinstance(own_text, bool):
            raise CaseError(f"line {number}: a flagcheck case needs own_text: true when the candidate is written in "
                            "the challenge's own text (its description, or its handout as shipped), which a run "
                            "holds for the player anyway, else false")
        return Case(kind, data, expected, own_text=own_text, ident=ident)
    if kind == SUMMARY:
        keywords = _keywords(expected)
        if not keywords:
            raise CaseError(f"line {number}: a summary case needs expected keywords (comma-separated)")
        for keyword in keywords:
            _check_phrase(keyword, number, "summary keyword")
        groups = _groups(obj["required"], number) if "required" in obj else ()
        return Case(kind, data, expected, required=groups, ident=ident)
    if kind == RECON:
        if "required" not in obj:
            raise CaseError(f"line {number}: a recon case needs required: a non-empty list of keyword groups")
        groups = _groups(obj["required"], number)
        traps = _traps(obj.get("traps", []), number)
        clash = {k.lower() for group in groups for k in group} & {t.lower() for t in traps}
        if clash:
            raise CaseError(f"line {number}: {', '.join(sorted(clash))} is both required and a trap")
        return Case(kind, data, expected, required=groups, traps=traps, ident=ident)
    return Case(kind=kind, input=data, expected=expected, ident=ident)


def _route_expected(expected: object, data: dict, number: int) -> dict:
    """A route case's three answers, each one of its question's options."""
    keys = [q.key for q in ROUTE_QUESTIONS]
    if not isinstance(expected, dict) or set(expected) != set(keys):
        raise CaseError(f"line {number}: a route case expects an object with exactly {', '.join(keys)}")
    for question in ROUTE_QUESTIONS:
        ids = [c.id for c in question.choices]
        if expected[question.key] not in ids:
            raise CaseError(f"line {number}: a route case's {question.key} must be one of {', '.join(ids)}")
    if not isinstance(data.get("description", ""), str):
        raise CaseError(f"line {number}: a route case's input.description must be a string")
    return dict(expected)


def _groups(value: object, number: int) -> tuple[tuple[str, ...], ...]:
    if not isinstance(value, list) or not value:
        raise CaseError(f"line {number}: required must be a non-empty list of keyword groups")
    groups = []
    for group in value:
        alternatives = [group] if isinstance(group, str) else group
        if not isinstance(alternatives, list) or not alternatives or not all(isinstance(a, str) for a in alternatives):
            raise CaseError(f"line {number}: each required group is a keyword or a non-empty list of keywords")
        for keyword in alternatives:
            _check_phrase(keyword, number, "required keyword")
        groups.append(tuple(a.strip() for a in alternatives))
    return tuple(groups)


def _traps(value: object, number: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CaseError(f"line {number}: traps must be a list of phrases")
    phrases = []
    for trap in value:
        group = [trap] if isinstance(trap, str) else trap
        if not isinstance(group, list) or not group or not all(isinstance(p, str) for p in group):
            raise CaseError(f"line {number}: each trap is a phrase or a non-empty list of phrases")
        for phrase in group:
            _check_phrase(phrase, number, "trap")
            phrases.append(phrase.strip())
    return tuple(phrases)


def _check_phrase(phrase: str, number: int, what: str) -> None:
    if "|" in phrase:
        raise CaseError(f"line {number}: {what} {phrase!r} holds '|': alternatives go in a list, not one string")
    if sum(ch.isalnum() for ch in phrase) < MIN_KEYWORD:
        raise CaseError(f"line {number}: {what} {phrase!r} is too short to check: it is matched anywhere in the "
                        f"reply, so it needs at least {MIN_KEYWORD} letters or digits")


# --------------------------------------------------------------------------- the HINT lexicon


@dataclass(frozen=True)
class _Lexicon:
    """What the evaluation uses of the HINT lexicon: its label space and its techniques."""

    lexicon: object  # detect.hints.Lexicon
    ids: tuple[str, ...]  # the technique ids, in lexicon order
    choices: tuple[Choice, ...]  # the hint job's options: the techniques, then "none"
    get: Callable[[str], object]  # id -> detect.hints.Technique

    @property
    def labels(self) -> tuple[str, ...]:
        """Every answer a hint case can have: the ids, then "none"."""
        return (*self.ids, NONE)


def _hint_lexicon() -> _Lexicon:
    """The HINT lexicon of ctf_flightdeck.detect.hints, or LocalModelError naming what is
    missing (the module, a name it should export, or a lexicon file that will not load)."""
    try:
        from .detect.hints import LexiconError, lexicon
    except ImportError as exc:
        raise LocalModelError(
            f"the HINT lexicon (ctf_flightdeck.detect.hints) cannot be imported ({exc}), so hint "
            "and judge cases cannot be scored"
        ) from exc
    try:
        loaded = lexicon()
    except LexiconError as exc:
        raise LocalModelError(f"the HINT lexicon (ctf_flightdeck.detect.hints) cannot be loaded: {exc}") from exc
    return _Lexicon(loaded, loaded.ids, tuple(technique_choices(loaded)), loaded.get)


def _prepare(cases: Sequence[Case]) -> _Lexicon | None:
    """Check the cases before anything is scored or spent: every kind is known, a route case's
    answers are its questions' options and, when there are hint or judge cases, the lexicon
    loads and every technique they name is one of its ids. Returns the lexicon (None when no
    case needs it). Cases are numbered from 1."""
    for number, case in enumerate(cases, start=1):
        if case.kind not in KINDS:
            raise LocalModelError(f"case {number}: unknown kind {case.kind!r}; use one of {', '.join(KINDS)}")
        if case.kind == ROUTE:
            try:
                _route_expected(case.expected, case.input, number)
            except CaseError as exc:
                raise LocalModelError(str(exc).replace(f"line {number}", f"case {number}")) from None
    if not any(case.kind in (HINT, JUDGE) for case in cases):
        return None
    lexicon = _hint_lexicon()
    unknown: dict[str, list[str]] = {}
    for number, case in enumerate(cases, start=1):
        if case.kind == HINT and _norm_id(case.expected) not in lexicon.labels:
            unknown.setdefault(_norm_id(case.expected), []).append(str(number))
        if case.kind == JUDGE and _norm_id(case.input.get("technique")) not in lexicon.ids:
            unknown.setdefault(_norm_id(case.input.get("technique")), []).append(str(number))
    if unknown:
        listed = "; ".join(f"{ident!r} (case {', '.join(numbers)})" for ident, numbers in sorted(unknown.items()))
        raise LocalModelError(
            f"cases name technique ids the HINT lexicon does not have: {listed}. A hint case must "
            "expect one of the lexicon's ids (ctf_flightdeck/detect/hints.toml) or 'none', and a judge "
            "case must name one, or no engine can be scored on it fairly"
        )
    return lexicon


# --------------------------------------------------------------------------- the jobs


@dataclass(frozen=True)
class _Item:
    """One job of a case: a case is one job, a route case three (one per question)."""

    number: int  # the case's number in the set, from 1
    case: Case
    question: Question | None = None

    @property
    def expected(self) -> str:
        case = self.case
        if case.kind == ROUTE:
            assert self.question is not None and isinstance(case.expected, dict)
            return str(case.expected[self.question.key])
        if case.kind == RECON:
            return "; ".join(" / ".join(group) for group in case.required)
        return str(case.expected) if case.kind == SUMMARY else _norm_id(case.expected)


def _items(cases: Sequence[Case]) -> list[_Item]:
    """Every job of the cases, in case order, but route's grouped by question at the first
    route case (all category questions, then family, then instance), so a model server's
    prefix cache sees one prompt shape at a time."""
    items: list[_Item] = []
    routed = False
    for number, case in enumerate(cases, start=1):
        if case.kind != ROUTE:
            items.append(_Item(number, case, FLAG_QUESTION if case.kind == FLAGCHECK else None))
        elif not routed:
            routed = True
            route = [(n, c) for n, c in enumerate(cases, start=1) if c.kind == ROUTE]
            items += [_Item(n, c, question) for question in ROUTE_QUESTIONS for n, c in route]
    return items


def count_jobs(cases: Sequence[Case], does: Callable[[str], bool]) -> int:
    """How many jobs an engine that does `does` is asked over the cases: one a case, three a
    route case."""
    return sum(3 if case.kind == ROUTE else 1 for case in cases if does(case.kind))


def _applies(engine: Light, item: _Item) -> bool:
    if not engine.does(item.case.kind):
        return False
    return engine.engine != RULES or item.question is None or item.question.ruled


def _steps(case: Case) -> tuple[list[str], list[str]]:
    steps = [s for s in case.input.get("steps", []) if isinstance(s, dict)]
    return [str(s.get("command", "")) for s in steps], [str(s.get("output", "") or "") for s in steps]


async def _job(engine: Light, item: _Item, lexicon: _Lexicon | None) -> Answer:
    case = item.case
    description = str(case.input.get("description", ""))
    if case.kind == HINT:
        assert lexicon is not None  # _prepare loads it whenever there is a hint case
        return await engine.ask_technique(description, lexicon.choices)
    if case.kind == JUDGE:
        assert lexicon is not None
        commands, outputs = _steps(case)
        return await engine.judge_hint(lexicon.get(_norm_id(case.input.get("technique"))), description, commands, outputs)
    if case.kind in (ROUTE, FLAGCHECK):
        assert item.question is not None
        return await engine.ask_choice(case.kind, case.input, item.question, item.question.choices)
    if case.kind == RECON:
        return await engine.write_brief(case.input)
    challenge = case.input.get("challenge")
    return await engine.summarize(challenge if isinstance(challenge, dict) else {}, str(case.input.get("plan", "")),
                                  [s for s in case.input.get("steps", []) if isinstance(s, dict)])


def _rules_answer(item: _Item, rules: RulesLight, lexicon: _Lexicon | None) -> Answer | None:
    """The rules' answer to a job a run reads with the rules first (the judge, route's category
    and instance), else None."""
    case = item.case
    if case.kind == JUDGE:
        assert lexicon is not None
        commands, outputs = _steps(case)
        return rules.judge(lexicon.get(_norm_id(case.input.get("technique"))), commands, outputs)
    if case.kind == ROUTE and item.question is not None and item.question.ruled:
        return rules.choose(ROUTE, case.input, item.question, item.question.choices)
    return None


# --------------------------------------------------------------------------- scoring


def _norm_id(value: object) -> str:
    """A technique id as compared: lower-case, trimmed; an empty value means 'none'."""
    text = str(value or "").strip().lower()
    return text or NONE


def _keywords(expected: str) -> list[str]:
    return [k.strip() for k in expected.split(",") if k.strip()]


_SPACE = re.compile(r"\s+")


def _fold(text: str) -> str:
    return _SPACE.sub(" ", text.lower()).strip()


def has_word(text: str, phrase: str) -> bool:
    """Whether `phrase` is in `text` as whole words: no letter or digit right before or after
    it, letter case and runs of white space aside ("stegano" is not in "steganography", nor
    "sage" in "message")."""
    return re.search(rf"(?<![a-z0-9]){re.escape(_fold(phrase))}(?![a-z0-9])", _fold(text)) is not None


def check_text(text: str, groups: Sequence[Sequence[str]], traps: Sequence[str] = ()) -> tuple[list[str], list[str]]:
    """(the required groups `text` lacks, each shown as "a / b"; the traps it holds)."""
    missing = [" / ".join(group) for group in groups if not any(has_word(text, keyword) for keyword in group)]
    return missing, [trap for trap in traps if has_word(text, trap)]


def _score(item: _Item, answer: Answer, rules_answer: Answer | None, *, rules: bool) -> CaseResult:
    case = item.case
    base = {"question": item.question.key if case.kind == ROUTE and item.question else "", "case": item.number,
            "ident": case.ident, "seconds": answer.seconds, "echoed": answer.echoed}
    expected = item.expected
    if answer.confidence is not None:  # a decision model's, sure or not
        base.update(confidence=answer.confidence, leaned=answer.choice or answer.text or None)
    run = _in_run(item, answer, rules_answer, rules=rules)
    if not answer.ok:
        return CaseResult(case.kind, expected, shown(answer.text), False, detail=answer.why, answered=False,
                          failure=answer.failure, reply=answer.text, **base, **run)
    if case.kind in TEXT_KINDS:
        groups = case.required or tuple((k,) for k in _keywords(str(case.expected)))
        missing, hit = check_text(answer.text, groups, case.traps)
        detail = "; ".join(part for part in ("missing: " + ", ".join(missing) if missing else "",
                                              "traps: " + ", ".join(hit) if hit else "") if part)
        return CaseResult(case.kind, expected, shown(answer.text), not missing and not hit, detail=detail,
                          reply=answer.text, missing=tuple(missing), traps_hit=tuple(hit), words=len(answer.text.split()),
                          chars=len(answer.text), **base, **run)
    if answer.choice is None:  # an engine that says it answered but named no option: no answer, never "none"
        return CaseResult(case.kind, expected, shown(answer.text), False, detail="no answer: no option named",
                          answered=False, failure=OUTSIDE, reply=answer.text, **base, **run)
    return CaseResult(case.kind, expected, answer.choice, answer.choice == expected, reply=answer.text, **base, **run)


def _in_run(item: _Item, answer: Answer, rules_answer: Answer | None, *, rules: bool) -> dict:
    """How a run would have used this job (the rules first), as CaseResult fields: see the
    module doc. `rules`: the engine is the rules, so the run has no light model."""
    case = item.case
    expected = item.expected
    said = answer.choice if answer.ok and not rules else None
    if case.kind == JUDGE:
        assert rules_answer is not None
        alert = rules_answer.choice == NO  # no action cue: the alert is up, and a run asks the judge
        down = alert and said == YES
        verdict = YES if (not alert or down) else NO
        return {"in_run": verdict == expected, "alert": alert, "taken_down": down}
    if case.kind == ROUTE and item.question is not None:
        key = item.question.key
        if key == "instance":  # no model: the rule
            assert rules_answer is not None
            return {"in_run": rules_answer.choice == expected}
        if key == "category":
            assert rules_answer is not None
            chosen = rules_answer.choice if rules_answer.ok else said  # the board's, where it names a known code
            return {"in_run": chosen == expected}
        return {"in_run": None if rules else said == expected}
    if case.kind == FLAGCHECK:
        planted = bool(case.own_text)
        held = said == STAND_IN
        return {"in_run": (planted or held) == (expected == STAND_IN), "planted": planted, "held": held}
    return {}


async def evaluate_engine(engine: Light, cases: Sequence[Case], *, stop_after: int = STOP_AFTER) -> EvalReport:
    """Run every job `engine` does through it and score it; a job it does not do is not
    applicable. One try per job; tokens and dollars are summed (dollars is None once any job's
    cost is unknown). The cases are checked first (LocalModelError), so a bad set spends
    nothing. EngineFailed when the engine's first jobs all fail with an error or a timeout:
    `stop_after` of them, or every job it has when it has fewer."""
    lexicon = _prepare(cases)
    rules = RulesLight(lexicon.lexicon if lexicon is not None else None)  # type: ignore[arg-type]
    items = _items(cases)
    jobs = sum(1 for item in items if _applies(engine, item))
    is_rules = engine.engine == RULES
    results: list[CaseResult] = []
    tokens = 0
    dollars: float | None = 0.0
    answered = False
    errors = 0
    for item in items:
        if not _applies(engine, item):
            results.append(_not_applicable(item, f"{engine.label} does not do {item.case.kind} cases", rules_column=is_rules))
            continue
        answer = await _job(engine, item, lexicon)
        tokens += answer.tokens
        if answer.cost is None:
            dollars = None
        elif dollars is not None:
            dollars += answer.cost
        if answer.failure in (ERROR, TIMEOUT):
            errors += 1
            if not answered and errors >= min(stop_after, jobs):
                raise EngineFailed(answer.why)
        else:
            answered = True
        results.append(_score(item, answer, _rules_answer(item, rules, lexicon), rules=is_rules))
    return EvalReport(engine.label, tuple(results), tokens, dollars, engine.engine)


def _not_applicable(item: _Item, why: str, *, rules_column: bool) -> CaseResult:
    """A job the engine does not do. For the rules column, a run with no light model still
    reads flagcheck (the planted-flag hold alone)."""
    case = item.case
    question = item.question.key if case.kind == ROUTE and item.question else ""
    fields: dict = {}
    if rules_column and case.kind == FLAGCHECK:
        fields = _in_run(item, Answer(None, failure=ERROR), None, rules=True)
    return CaseResult(case.kind, item.expected, "", False, applicable=False, detail=why, question=question,
                      case=item.number, ident=case.ident, **fields)


def rules_baseline(cases: Sequence[Case]) -> EvalReport:
    """The rules on the same cases, at once and with no network: the HINT lexicon's first
    technique for a hint case, its action cues for a judge case, the board's category and the
    instance rule for route's two questions they answer; summary, recon, route's family and
    flagcheck are not applicable (flagcheck in a run is the planted-flag hold alone). Raises
    LocalModelError when the lexicon cannot be imported or loaded, or a case names an id it
    does not have, so the baseline is never silently empty or skewed."""
    lexicon = _prepare(cases)
    rules = RulesLight(lexicon.lexicon if lexicon is not None else None)  # type: ignore[arg-type]
    results: list[CaseResult] = []
    for item in _items(cases):
        case = item.case
        if case.kind == HINT:
            assert lexicon is not None
            answer = rules.technique(str(case.input.get("description", "")), lexicon.choices)
        elif case.kind == JUDGE or (case.kind == ROUTE and item.question is not None and item.question.ruled):
            answer = _rules_answer(item, rules, lexicon)
            assert answer is not None
        else:
            why = "rules do not summarise" if case.kind == SUMMARY else f"the rules do not do {item.case.kind} cases"
            if case.kind == ROUTE:
                why = "the rules name no family"
            results.append(_not_applicable(item, why, rules_column=True))
            continue
        results.append(_score(item, answer, _rules_answer(item, rules, lexicon), rules=True))
    return EvalReport(rules.label, tuple(results), 0, 0.0, rules.engine)


def mcnemar(only_one: int, only_other: int) -> float:
    """McNemar's exact test: the two-sided p that two columns are as good as each other, from
    the cases only one got right and those only the other did (a binomial test at 1/2)."""
    n = only_one + only_other
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(only_one, only_other) + 1)) / 2**n
    return min(1.0, 2 * tail)


# --------------------------------------------------------------------------- the scorecard


LABEL = 14  # the row label's width
RUN_LABEL = 24  # the in-a-run table's
CASES_WIDTH = 6
MIN_COLUMN = 16


def format_scorecard(reports: Sequence[EvalReport], *, show_misses: bool = False) -> str:
    """The reports side by side, one column each, as plain text for the terminal: accuracy per
    job and overall, a decision model's unsure answers (a row only when a decider is one of the
    columns), refusals, failures, replies with no answer and answers given as an option's line,
    time and cost per job; then each job as a run uses it, a decider column's threshold table,
    a text job's length, and each column compared with the rules and the best column.
    `show_misses`: also every job a column got wrong, with what it answered.

    All must be over the same cases. A column shows n/a for a job its engine does not do, and
    the overall row is over the jobs every column does, so no two columns are compared over
    different jobs. A decision model's accuracy leaves out the jobs it was unsure of (its own
    row counts them): it is how often an answer it was sure of is right, and "all unsure" when
    it was sure of none."""
    if not reports:
        raise LocalModelError("no reports to show")
    first = reports[0]
    for report in reports[1:]:
        if [r.row for r in report.results] != [r.row for r in first.results]:
            raise LocalModelError("the reports are not over the same cases")
    present = [k for k in ROWS if any(r.row == k for r in first.results)]
    shared = [k for k in present if all(k in report.kinds() for report in reports)]
    width = max(MIN_COLUMN, *(len(report.label) + 2 for report in reports))
    counts = {k: sum(1 for r in first.results if r.row == k) for k in present}
    numbered = all(r.case for r in first.results)  # results made by evaluate_engine know their case

    def cases_of(kind: str | None = None) -> int:
        mine = [r for r in first.results if kind is None or r.kind == kind]
        return len({r.case for r in mine}) if numbered else len(mine)

    def row(label: str, n: object, cells: Sequence[str], size: int = LABEL) -> str:
        return f"{label:<{size}}{str(n):>{CASES_WIDTH}}  " + "".join(f"{cell:<{width}}" for cell in cells).rstrip()

    cases = cases_of()
    kinds = [k for k in KINDS if any(r.kind == k for r in first.results)]
    listed = ", ".join(f"{k} {cases_of(k)}" for k in kinds)
    routed = " (a route case is three questions)" if ROUTE in kinds else ""
    lines = [f"eval-local: {cases} cases ({listed}); one job per case{routed}, one try each", ""]
    lines.append(row("", "cases", [report.label for report in reports]))
    for kind in present:
        lines.append(row(kind, counts[kind], [_accuracy(report, [kind]) for report in reports]))
    lines.append(row("overall", sum(counts[k] for k in shared), [_accuracy(report, shared) for report in reports]))
    if any(r.engine == DECIDER for r in reports):  # only a decision model says how sure it is
        lines.append(row("unsure", "", [_rate(r, r.unsure) if r.engine == DECIDER else "-" for r in reports]))
    lines.append(row("refused", "", [_rate(r, r.count(REFUSED)) for r in reports]))
    lines.append(row("failed", "", [_rate(r, r.count(ERROR, TIMEOUT)) for r in reports]))
    lines.append(row("no answer", "", [_rate(r, r.count(NO_ANSWER, OUTSIDE)) for r in reports]))
    if any(r.echoed for r in reports):
        lines.append(row("option line", "", [_rate(r, r.echoed) for r in reports]))
    lines.append(row("time per job", "", [_time(r) for r in reports]))
    lines.append(row("cost per job", "", [_cost(r) for r in reports]))
    lines.append("")
    skipped = [k for k in present if k not in shared]
    if skipped:
        lines.append(f"overall: over {_listed(shared) or 'no'} cases, which every column does; "
                     + "; ".join(f"{_listed(k)}: {_listed([r.label for r in reports if k not in r.kinds()])} "
                                 f"{'does' if sum(1 for r in reports if k not in r.kinds()) == 1 else 'do'} not do these"
                                 for k in skipped) + ".")
    if any(r.count(REFUSED) for r in reports):
        lines.append("refused: the model declined the job. In a run the rules' answer stands when it does; an "
                     "open-weight model on your own machine has no provider classifier to decline security work.")
    if any(r.unsure for r in reports):
        lines.append("unsure: the decision model's confidence was below its threshold, so in a run the rules' "
                     "answer stands. An unsure job counts neither right nor wrong: the decision model's accuracy "
                     "is over the jobs it answered at or above its threshold, and any it failed.")
    if any(r.count(NO_ANSWER, OUTSIDE) for r in reports):
        rules = " (the rules': a route case whose board names no category flightdeck knows)" if any(
            r.engine == RULES and r.count(NO_ANSWER, OUTSIDE) for r in reports) else ""
        lines.append("no answer: replies cut off at the token cap, empty, or not exactly one of the options"
                     f"{rules}; each counts as wrong.")
    if any(r.echoed for r in reports):
        lines.append("option line: answers given as one option's whole line as the prompt listed it (\"id: "
                     "description\"), read as that option; they count as answers, right or wrong.")
    spent = [f"{r.label} {r.tokens:,} tokens" + (f", ${r.dollars:.4f}" if r.dollars else "") for r in reports if r.tokens]
    if spent:
        lines.append("spent: " + "; ".join(spent) + ".")
    lines += _run_table(reports, row)
    lines += _thresholds(reports)
    lines += _lengths(reports)
    lines += _comparisons(reports)
    if show_misses:
        lines += _misses(reports)
    return "\n".join(lines).rstrip() + "\n"


def _run_rows(report: EvalReport) -> dict[str, list[bool]]:
    """{row: [right in a run, a case each]} for the rows a run reads (the judge, route, flagcheck)."""
    out: dict[str, list[bool]] = {}
    for result in report.results:
        if result.in_run is not None:
            out.setdefault(f"{result.row} in a run", []).append(result.in_run)
    by_case: dict[int, list[bool | None]] = {}
    for result in report.results:
        if result.kind == ROUTE:
            by_case.setdefault(result.case, []).append(result.in_run)
    if by_case and all(len(v) == len(ROUTE_QUESTIONS) and None not in v for v in by_case.values()):
        out["route all three in a run"] = [all(v) for v in by_case.values()]
    return out


RUN_ORDER = ("judge in a run", "route category in a run", "route family in a run", "route instance in a run",
             "route all three in a run", "flagcheck in a run")


def _run_table(reports: Sequence[EvalReport], row: Callable) -> list[str]:
    """Each job as a run uses it, the rules first: the rules column is a run with no light model."""
    readings = [_run_rows(report) for report in reports]
    present = [name for name in RUN_ORDER if any(name in reading for reading in readings)]
    if not present:
        return []
    lines = ["", "in a run: the rules first, and the light model only where a run asks it (the rules column is a run "
                 "with no light model; route's instance is the rule's in every column)"]
    lines.append(row("", "cases", [report.label for report in reports], RUN_LABEL))
    first = max(reports, key=lambda report: sum(r.in_run is not None for r in report.results))  # one a run reads
    for name in present:
        size = max(len(reading.get(name, ())) for reading in readings)
        lines.append(row(name, size, [_cell(sum(r[name]), len(r[name])) if name in r else "n/a" for r in readings],
                         RUN_LABEL))
        if name == "judge in a run":
            judged = [r for r in first.results if r.kind == JUDGE]
            false_alerts = sum(1 for r in judged if r.alert and r.expected == YES)
            true_alerts = sum(1 for r in judged if r.alert and r.expected == NO)
            lines.append(row("  false alerts down", false_alerts, [str(sum(1 for r in rep.results if r.kind == JUDGE and r.taken_down and r.expected == YES)) for rep in reports], RUN_LABEL))
            lines.append(row("  true alerts down", true_alerts, [str(sum(1 for r in rep.results if r.kind == JUDGE and r.taken_down and r.expected == NO)) for rep in reports], RUN_LABEL))
        if name == "flagcheck in a run":
            loose = [r for r in first.results if r.kind == FLAGCHECK and r.planted is False]
            stand_ins = sum(1 for r in loose if r.expected == STAND_IN)
            reals = sum(1 for r in loose if r.expected == REAL)
            lines.append(row("  stand-ins held", stand_ins, [str(_held(rep, STAND_IN)) for rep in reports], RUN_LABEL))
            lines.append(row("  real flags held", reals, [str(_held(rep, REAL)) for rep in reports], RUN_LABEL))
            called = [str(sum(1 for r in rep.scored if r.kind == FLAGCHECK and r.expected == STAND_IN
                              and r.answered and r.predicted == REAL)) if any(r.kind == FLAGCHECK for r in rep.scored)
                      else "n/a" for rep in reports]
            lines.append(row("  stand-ins called real", sum(1 for r in first.results if r.kind == FLAGCHECK
                                                             and r.expected == STAND_IN), called, RUN_LABEL))
    lines.append("")
    if "judge in a run" in present:
        lines.append("judge in a run: asked only where the rules see no action cue (the 'ignores the hint' alert is "
                     "up); false alerts down: alerts it rightly took down; true alerts down: alerts it took down "
                     "wrongly.")
    if "route category in a run" in present:
        lines.append("route in a run: the category is the board's wherever flightdeck reads a known code there, the "
                     "engine's elsewhere; the instance is the rule's (a URL on the board, or a service the description "
                     "names); the family is the engine's.")
    if "flagcheck in a run" in present:
        lines.append("flagcheck in a run: a flag written in the challenge's own text is held anyway (the planted-flag "
                     "hold); held: a flag the engine held beyond it (a stand-in held is a submit saved, a real flag "
                     "held waits for your approval); stand-ins called real: over every case, the costly error.")
    return lines


def _held(report: EvalReport, expected: str) -> int:
    return sum(1 for r in report.results if r.kind == FLAGCHECK and r.planted is False and r.held and r.expected == expected)


def _thresholds(reports: Sequence[EvalReport]) -> list[str]:
    """A decider column's answers read at other thresholds, from its one run: how many it
    answered at each, and how many of those were right."""
    lines: list[str] = []
    for report in reports:
        if report.engine != DECIDER:
            continue
        rows = [k for k in ROWS if any(r.row == k and r.leaned is not None for r in report.scored)]
        if not rows:
            continue
        lines += ["", f"{report.label}, right of answered at each threshold, read from this one run (below the "
                      "threshold an answer is unsure, and in a run the rules' answer stands):"]
        for name in rows:
            mine = [r for r in report.scored if r.row == name]
            cells = []
            for threshold in (0.0, *THRESHOLDS):
                sure = [r for r in mine if r.leaned is not None and (r.confidence or 0.0) >= threshold]
                said = f"{sum(1 for r in sure if r.leaned == r.expected)} of {len(sure)}"
                cells.append(f"best guess {said}" if threshold == 0.0 else f"at {threshold:g} {said}")
            lines.append(f"- {name} ({len(mine)} jobs): " + "; ".join(cells))
    return lines


def _lengths(reports: Sequence[EvalReport]) -> list[str]:
    """How long each column's briefs and summaries were, against what the prompt asks."""
    lines: list[str] = []
    for kind in TEXT_KINDS:
        said = []
        for report in reports:
            written = [r for r in report.scored if r.kind == kind and r.answered]
            if not written:
                continue
            longest = max(r.chars for r in written)
            text = f"{report.label}: the longest {longest:,} characters"
            if kind == RECON:
                over = sum(1 for r in written if r.words > BRIEF_WORDS)
                cut = sum(1 for r in written if r.chars > BRIEF_CHARS)
                text += f", {over} of {len(written)} over the {BRIEF_WORDS} words asked, {cut} over the run's {BRIEF_CHARS:,}-character cap"
            said.append(text)
        if said:
            lines += ["", f"{kind} length: " + "; ".join(said) + "."]
    return lines


def _readings(report: EvalReport) -> dict[str, dict[int, bool]]:
    """{row: {item index: right}}: each job as a run reads it where a run uses it, else as it
    stands; an unsure answer, which counts neither way, is left out."""
    out: dict[str, dict[int, bool]] = {}
    for index, result in enumerate(report.results):
        if result.in_run is not None:
            out.setdefault(f"{result.row} in a run", {})[index] = result.in_run
        elif result.applicable and result.failure != UNSURE and result.kind not in (JUDGE, FLAGCHECK, ROUTE):
            out.setdefault(result.row, {})[index] = result.correct
    run = _run_rows(report)
    if "route all three in a run" in run:
        out["route all three in a run"] = dict(enumerate(run["route all three in a run"]))
    return out


COMPARED = (HINT, "judge in a run", SUMMARY, "route category in a run", "route family in a run",
            "route all three in a run", RECON, "flagcheck in a run")


def _comparisons(reports: Sequence[EvalReport]) -> list[str]:
    """Each light model's column against the rules and against the best column, row by row,
    with McNemar's exact test over the cases both answered."""
    readings = [_readings(report) for report in reports]
    lines: list[str] = []
    for name in COMPARED:
        have = [(report, reading[name]) for report, reading in zip(reports, readings) if reading.get(name)]
        if len(have) < 2:
            continue
        best = max(have, key=lambda pair: sum(pair[1].values()))
        rules = next((pair for pair in have if pair[0].engine == RULES), None)
        for pair in have:
            if pair[0].engine == RULES:
                continue
            for other, against in ((rules, "the rules"), (best, "the best column")):
                if other is None or other is pair or (against == "the best column" and other is rules):
                    continue
                lines.append(_compared(name, pair, other, against))
    if lines:
        lines = ["", f"compared (McNemar's exact test over the cases both answered; p < {SIGNIFICANT:g} tells two "
                     "columns apart):"] + lines
    return lines


def _compared(name: str, mine: tuple, other: tuple, against: str) -> str:
    (report, right), (theirs, their_right) = mine, other
    both = sorted(set(right) & set(their_right))
    only_mine = sum(1 for i in both if right[i] and not their_right[i])
    only_theirs = sum(1 for i in both if their_right[i] and not right[i])
    p = mcnemar(only_mine, only_theirs)
    mine_n, theirs_n = sum(right[i] for i in both), sum(their_right[i] for i in both)
    shown_p = "p < 0.001" if p < 0.001 else f"p = {p:.3f}"
    verdict = ("this set cannot tell them apart" if p >= SIGNIFICANT
               else ("better" if only_mine > only_theirs else "worse") + " on this set")
    label = against if against == "the rules" else f"{theirs.label} ({against})"
    return (f"- {name}: {report.label} {mine_n}/{len(both)} against {label} {theirs_n}/{len(both)}: {only_mine} right "
            f"only for it, {only_theirs} only for the other; {shown_p}: {verdict}")


def _misses(reports: Sequence[EvalReport]) -> list[str]:
    """Every job each column got wrong or gave no answer to, with what it said, folded to one
    line: keyword verdicts under-credit, so the player reads them."""
    lines = ["", "misses (what each column got wrong, as it said it; replies are untrusted text):"]
    for report in reports:
        wrong = [r for r in report.graded if not r.correct]
        lines.append(f"{report.label}: {len(wrong)} of {len(report.graded)}")
        for result in wrong:
            said = " ".join(untrusted(result.reply, one_line=True).split())
            said = said if len(said) <= 600 else said[:599] + "…"
            if result.failure:
                what = f"{result.failure}: {result.detail}"
            elif result.kind in TEXT_KINDS:
                what = result.detail
            else:
                what = f"answered {result.predicted}"
            text = f"  {result.name} ({result.row}): expected {result.expected}; {what}"
            if said and (result.kind in TEXT_KINDS or result.failure):
                text += f"; it said: {said}"
            lines.append(text)
    return lines


def _cell(correct: int, total: int) -> str:
    if not total:
        return "n/a"
    return f"{correct}/{total} {round(100 * correct / total)}%"


def _accuracy(report: EvalReport, kinds: Sequence[str]) -> str:
    """Right answers over graded jobs, for these rows: n/a when the engine does none of them,
    "all unsure" when it ran them and a decision model was unsure on every one."""
    got = report.by_kind(kinds)
    if not got:
        return "n/a"
    graded = sum(t for _, t in got.values())
    return _cell(sum(c for c, _ in got.values()), graded) if graded else "all unsure"


def _rate(report: EvalReport, count: int) -> str:
    if report.engine == "rules" and not count:
        return "-"  # the rules answer every hint and judge job
    return _cell(count, report.total) if report.total else "n/a"


def _time(report: EvalReport) -> str:
    if not report.total:
        return "n/a"
    seconds = report.seconds / report.total
    if seconds < 0.001:
        return f"{seconds * 1000:.2f} ms"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    return f"{seconds:.1f} s"


def _cost(report: EvalReport) -> str:
    if not report.total:
        return "n/a"
    if report.dollars is None:
        return "unknown"
    if report.dollars == 0:
        return "$0"
    per = report.dollars / report.total
    return f"${per:.6f}".rstrip("0")


def _listed(words: Sequence[str] | str) -> str:
    if isinstance(words, str):
        return words
    words = list(words)
    if not words:
        return ""
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]
