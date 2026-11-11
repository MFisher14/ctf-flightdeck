"""The light role's evaluation (D15): score a light model on small jobs before switching it on.

The orchestrator is code; a light model (light.py) only does small jobs, and only after the
player has measured it against the rules. This module runs a synthetic case set through any
light engines (rules, an OpenAI-compatible model, Claude, Cactus Needle) and scores each, so
the player can compare them: accuracy per job, refusals and failures, time and cost per job.

Three jobs, one per case kind:

- **hint**: name the technique a challenge description points at, or "none". Every engine
  answers from the same label space, the HINT lexicon's ids (ctf_flightdeck.detect.hints) plus
  "none", never from the case file's own answers. A hint case must expect one of those labels:
  any other id is refused before anything runs.
- **judge**: say whether a lane's steps use the technique the description hints at ("yes" or
  "no"): the hint judge's job in a run (detect/judge.py). A judge case names a lexicon technique.
  The rules answer from the technique's action cues, as the "ignores the hint" detector does.
- **summary**: write a short escalation summary of a lane's steps. Scored by whether it names
  every keyword a correct summary must contain (case-insensitive). The rules and Cactus write no
  summaries, so they report these as not applicable, and the scorecard compares columns only
  over the kinds each one does.

Each engine answers each case it can do with one job: one try, within its time limit, so a
paid engine makes at most as many calls as there are cases. A job that fails (the model
declined, the API failed or timed out, the reply was cut off or empty, or it named no allowed
option) scores wrong, and the scorecard counts it by kind next to the accuracy: a model that
never answers does not read as a weak one, nor a refusing one as a wrong one. An engine whose
first jobs all fail with an error (a server that is down, a model that is not there) is
stopped with EngineFailed rather than run through the whole set.

Untrusted text. A case's text goes to a model inside the harness's data fence, folded, and a
model's answer is read strictly (light.py). Nothing a model answers here changes a setting; it
is only scored.

The lexicon is imported when a hint or judge case needs it. When it cannot be imported or
loaded, scoring fails loudly with LocalModelError, never with an empty or guessed baseline.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .agent.prompts import FENCE_CLOSE as FENCE_CLOSE
from .agent.prompts import FENCE_OPEN as FENCE_OPEN
from .light import (
    ERROR,
    HINT,
    JUDGE,
    NO,
    NO_ANSWER,
    NONE,
    OUTSIDE,
    REFUSED,
    SUMMARY,
    TIMEOUT,
    YES,
    Answer,
    Choice,
    Light,
    RulesLight,
    shown,
    technique_choices,
)

KINDS = (HINT, JUDGE, SUMMARY)
MIN_KEYWORD = 3  # letters or digits a summary keyword needs: it is matched anywhere in the summary
STOP_AFTER = 3  # an engine whose first jobs (this many, or all it has) all fail with an error is stopped


class LocalModelError(Exception):
    """An evaluation could not run for a named reason (no silent fallback)."""


class CaseError(LocalModelError):
    """A case file is malformed; the message names the line and the problem."""


class EngineFailed(LocalModelError):
    """An engine failed on every one of its first jobs; the message is the last failure's reason."""


@dataclass(frozen=True)
class Case:
    """One evaluation case.

    `kind` is "hint", "judge" or "summary". `input` is the data the job reads: a hint case has
    `description`; a judge case has `description`, `technique` (a lexicon id) and `steps` (a
    list of {command, output}); a summary case has `steps` and may carry `plan` and
    `challenge`. Any case may carry `name` and `category`, which no job uses. `expected` is the
    answer to score against: a technique id or "none", "yes" or "no", or a summary's keywords,
    comma-separated.
    """

    kind: str
    input: dict
    expected: str


@dataclass(frozen=True)
class CaseResult:
    """How one case scored. `predicted` is what the engine answered, folded to one safe line
    for display. `applicable` is False for a case the engine does not do (a summary, for the
    rules): it is left out of its accuracy. `answered` is False when the job failed, and
    `failure` says how (light.REFUSED, ERROR, TIMEOUT, NO_ANSWER, OUTSIDE), `detail` in words."""

    kind: str
    expected: str
    predicted: str
    correct: bool
    applicable: bool = True
    detail: str = ""
    answered: bool = True
    failure: str = ""
    seconds: float = 0.0


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
        """The results that count toward accuracy (applicable ones): one per job run."""
        return tuple(r for r in self.results if r.applicable)

    @property
    def correct(self) -> int:
        return sum(1 for r in self.scored if r.correct)

    @property
    def total(self) -> int:
        return len(self.scored)

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    @property
    def unanswered(self) -> int:
        """How many jobs held no answer (refused, failed, cut off, empty, not an option)."""
        return sum(1 for r in self.scored if not r.answered)

    def count(self, *failures: str) -> int:
        """How many jobs failed in one of these ways."""
        return sum(1 for r in self.scored if r.failure in failures)

    @property
    def seconds(self) -> float:
        return sum(r.seconds for r in self.scored)

    def kinds(self) -> list[str]:
        """The kinds this engine scored, in KINDS order."""
        return [k for k in KINDS if any(r.kind == k for r in self.scored)]

    def by_kind(self, kinds: Sequence[str] | None = None) -> dict[str, tuple[int, int]]:
        """{kind: (correct, total)} over the scored results (of `kinds`, when given)."""
        out: dict[str, tuple[int, int]] = {}
        for result in self.scored:
            if kinds is not None and result.kind not in kinds:
                continue
            got, had = out.get(result.kind, (0, 0))
            out[result.kind] = (got + int(result.correct), had + 1)
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
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except ValueError as exc:
            raise CaseError(f"line {number}: not valid JSON ({exc})") from None
        cases.append(_case(obj, number))
    if not cases:
        raise CaseError(f"no cases in {path}")
    return cases


def _case(obj: object, number: int) -> Case:
    if not isinstance(obj, dict):
        raise CaseError(f"line {number}: a case must be a JSON object, got {type(obj).__name__}")
    extra = set(obj) - {"kind", "input", "expected"}
    if extra:
        raise CaseError(f"line {number}: unknown field(s) {', '.join(sorted(extra))}")
    kind = obj.get("kind")
    if kind not in KINDS:
        raise CaseError(f"line {number}: kind must be one of {', '.join(KINDS)}, got {kind!r}")
    data = obj.get("input")
    if not isinstance(data, dict):
        raise CaseError(f"line {number}: input must be an object")
    expected = obj.get("expected")
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
    if kind == SUMMARY:
        keywords = _keywords(expected)
        if not keywords:
            raise CaseError(f"line {number}: a summary case needs expected keywords (comma-separated)")
        for keyword in keywords:
            if sum(ch.isalnum() for ch in keyword) < MIN_KEYWORD:
                raise CaseError(
                    f"line {number}: summary keyword {keyword!r} is too short to check: it is matched "
                    f"anywhere in the summary, so it needs at least {MIN_KEYWORD} letters or digits"
                )
    return Case(kind=kind, input=data, expected=expected)


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
    """Check the cases before anything is scored or spent: every kind is known and, when there
    are hint or judge cases, the lexicon loads and every technique they name is one of its
    ids. Returns the lexicon (None when no case needs it). Cases are numbered from 1."""
    for number, case in enumerate(cases, start=1):
        if case.kind not in KINDS:
            raise LocalModelError(f"case {number}: unknown kind {case.kind!r}; use one of {', '.join(KINDS)}")
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


# --------------------------------------------------------------------------- scoring


def _norm_id(value: object) -> str:
    """A technique id as compared: lower-case, trimmed; an empty value means 'none'."""
    text = str(value or "").strip().lower()
    return text or NONE


def _keywords(expected: str) -> list[str]:
    return [k.strip() for k in expected.split(",") if k.strip()]


def _summary_score(summary: str, expected: str) -> tuple[bool, str]:
    """Whether every required keyword appears in the summary (case-insensitive), and which
    are missing."""
    keywords = _keywords(expected)
    low = summary.lower()
    missing = [k for k in keywords if k.lower() not in low]
    return (not missing, "missing: " + ", ".join(missing) if missing else "")


def _steps(case: Case) -> tuple[list[str], list[str]]:
    steps = [s for s in case.input.get("steps", []) if isinstance(s, dict)]
    return [str(s.get("command", "")) for s in steps], [str(s.get("output", "") or "") for s in steps]


async def _job(engine: Light, case: Case, lexicon: _Lexicon | None) -> Answer:
    description = str(case.input.get("description", ""))
    if case.kind == HINT:
        assert lexicon is not None  # _prepare loads it whenever there is a hint case
        return await engine.ask_technique(description, lexicon.choices)
    if case.kind == JUDGE:
        assert lexicon is not None
        commands, outputs = _steps(case)
        return await engine.judge_hint(lexicon.get(_norm_id(case.input.get("technique"))), description, commands, outputs)
    challenge = case.input.get("challenge")
    return await engine.summarize(challenge if isinstance(challenge, dict) else {}, str(case.input.get("plan", "")),
                                  [s for s in case.input.get("steps", []) if isinstance(s, dict)])


def _score(case: Case, answer: Answer) -> CaseResult:
    expected = case.expected if case.kind == SUMMARY else _norm_id(case.expected)
    if not answer.ok:
        return CaseResult(case.kind, expected, shown(answer.text), False, detail=answer.why, answered=False,
                          failure=answer.failure, seconds=answer.seconds)
    if case.kind == SUMMARY:
        correct, detail = _summary_score(answer.text, case.expected)
        return CaseResult(SUMMARY, expected, shown(answer.text), correct, detail=detail, seconds=answer.seconds)
    predicted = answer.choice or ""
    return CaseResult(case.kind, expected, predicted, predicted == expected, seconds=answer.seconds)


async def evaluate_engine(engine: Light, cases: Sequence[Case], *, stop_after: int = STOP_AFTER) -> EvalReport:
    """Run every case `engine` does through it and score it; a case it does not do is not
    applicable. One job per case; tokens and dollars are summed (dollars is None once any
    job's cost is unknown). The cases are checked first (LocalModelError), so a bad set
    spends nothing. EngineFailed when the engine's first jobs all fail with an error or a
    timeout: `stop_after` of them, or every job it has when it has fewer."""
    lexicon = _prepare(cases)
    jobs = sum(1 for case in cases if engine.does(case.kind))
    results: list[CaseResult] = []
    tokens = 0
    dollars: float | None = 0.0
    answered = False
    errors = 0
    for case in cases:
        if not engine.does(case.kind):
            results.append(CaseResult(case.kind, case.expected, "", False, applicable=False,
                                      detail=f"{engine.label} does not do {case.kind} cases"))
            continue
        answer = await _job(engine, case, lexicon)
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
        results.append(_score(case, answer))
    return EvalReport(engine.label, tuple(results), tokens, dollars, engine.engine)


def rules_baseline(cases: Sequence[Case]) -> EvalReport:
    """The rules on the same cases, at once and with no network: the HINT lexicon's first
    technique for a hint case, its action cues for a judge case; summary cases are not
    applicable. Raises LocalModelError when the lexicon cannot be imported or loaded, or a
    case names an id it does not have, so the baseline is never silently empty or skewed."""
    lexicon = _prepare(cases)
    rules = RulesLight(lexicon.lexicon if lexicon is not None else None)  # type: ignore[arg-type]
    results: list[CaseResult] = []
    for case in cases:
        if case.kind == HINT:
            assert lexicon is not None
            answer = rules.technique(str(case.input.get("description", "")), lexicon.choices)
        elif case.kind == JUDGE:
            assert lexicon is not None
            commands, outputs = _steps(case)
            answer = rules.judge(lexicon.get(_norm_id(case.input.get("technique"))), commands, outputs)
        else:
            results.append(CaseResult(SUMMARY, case.expected, "", False, applicable=False, detail="rules do not summarise"))
            continue
        results.append(_score(case, answer))
    return EvalReport(rules.label, tuple(results), 0, 0.0, rules.engine)


# --------------------------------------------------------------------------- the scorecard


LABEL = 14  # the row label's width
CASES_WIDTH = 6
MIN_COLUMN = 16


def format_scorecard(reports: Sequence[EvalReport]) -> str:
    """The reports side by side, one column each, as plain text for the terminal: accuracy per
    kind and overall, refusals, failures and replies with no answer, time and cost per job.

    All must be over the same cases. A column shows n/a for a kind its engine does not do, and
    the overall row is over the kinds every column does, so no two columns are compared over
    different cases."""
    if not reports:
        raise LocalModelError("no reports to show")
    first = reports[0]
    for report in reports[1:]:
        if [r.kind for r in report.results] != [r.kind for r in first.results]:
            raise LocalModelError("the reports are not over the same cases")
    present = [k for k in KINDS if any(r.kind == k for r in first.results)]
    shared = [k for k in present if all(k in report.kinds() for report in reports)]
    width = max(MIN_COLUMN, *(len(report.label) + 2 for report in reports))
    counts = {k: sum(1 for r in first.results if r.kind == k) for k in present}

    def row(label: str, cases: object, cells: Sequence[str]) -> str:
        return f"{label:<{LABEL}}{str(cases):>{CASES_WIDTH}}  " + "".join(f"{cell:<{width}}" for cell in cells).rstrip()

    listed = ", ".join(f"{k} {counts[k]}" for k in present)
    lines = [f"eval-local: {len(first.results)} cases ({listed}); one job per case, one try each", ""]
    lines.append(row("", "cases", [report.label for report in reports]))
    for kind in present:
        lines.append(row(kind, counts[kind], [_cell(*report.by_kind([kind]).get(kind, (0, 0))) for report in reports]))
    overall = []
    for report in reports:
        got = report.by_kind(shared)
        overall.append(_cell(sum(c for c, _ in got.values()), sum(t for _, t in got.values())))
    lines.append(row("overall", sum(counts[k] for k in shared), overall))
    lines.append(row("refused", "", [_rate(r, r.count(REFUSED)) for r in reports]))
    lines.append(row("failed", "", [_rate(r, r.count(ERROR, TIMEOUT)) for r in reports]))
    lines.append(row("no answer", "", [_rate(r, r.count(NO_ANSWER, OUTSIDE)) for r in reports]))
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
    if any(r.count(NO_ANSWER, OUTSIDE) for r in reports):
        lines.append("no answer: replies cut off at the token cap, empty, or not exactly one of the options; "
                     "each counts as wrong.")
    spent = [f"{r.label} {r.tokens:,} tokens" + (f", ${r.dollars:.4f}" if r.dollars else "") for r in reports if r.tokens]
    if spent:
        lines.append("spent: " + "; ".join(spent) + ".")
    return "\n".join(lines).rstrip() + "\n"


def _cell(correct: int, total: int) -> str:
    if not total:
        return "n/a"
    return f"{correct}/{total} {round(100 * correct / total)}%"


def _rate(report: EvalReport, count: int) -> str:
    if report.engine == "rules":
        return "-"  # the rules answer every job they do
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
