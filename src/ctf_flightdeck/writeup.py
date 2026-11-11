"""Writeup drafts: one Markdown file per challenge a run solved, from what the run recorded.

`draft(record, challenge_id)` writes up one solve from a run folder (runrecord.load_run):

- solved by a lane: from that lane's transcript (lanes/<id>.jsonl), the approach (its plan
  changes and your redirects, in order), the steps that mattered, the files it wrote, your
  interventions, and the flag;
- solved by L1: a no-model solver found the flag, which then went through a lane's approval
  like any candidate (Deck.record_l1). The draft names the engine and what it recorded.

Solved means accepted: a submit event with `correct` true. A flag an L1 engine found that was
never accepted is not a solve ("flag found" is never "accepted"). A solve is L1's when the
accepted flag is one an `l1` event on that challenge reported before it was accepted.

The steps that mattered: the first step whose output holds the flag; failing that, the last
step that ran a file the lane wrote (a shell command naming it, not one that only shows or
edits it); failing that, the last step before the flag was accepted. The draft says which
rule picked it, and shows it with the 5 steps before it, outputs cut to 20 lines. A plan the
lane stated is not a step: it is in the approach.

What the transcript cannot tell. A lane's plan change shows up only when it was all the lane
did in that turn (a "plan: ..." step); otherwise only its last plan, in the transcript's
header, is known, and the draft says so. The transcript keeps the newest change to each file,
so a file the lane added and then edited shows as modified, with its last diff.

Untrusted text. Everything read from a run came from a challenge, a model, a tool or a file
a lane wrote, and a draft is meant to be read, edited and published. So nothing in it may act
as Markdown:

- each value has the flag redacted first (when asked), so no cut can leave part of it, and is
  folded with text.untrusted() (control and invisible characters made visible);
- a one-line value stays plain text only when it is letters, digits, spaces and a few marks
  that mean nothing in Markdown (inline()); anything else becomes a code span whose backtick
  run is longer than any inside it (code());
- multi-line text (outputs, files, diffs, the flag) goes in a fenced block whose fence is
  longer than any backtick run inside, with an info string of ours (fenced()).

A draft therefore never holds raw HTML, an entity, a link, an image or a mention from the
run, and nothing from the run can end a block early or start one. Our own words never use
backticks, brackets or angle brackets.

Polish (`polish()`, optional): a model tidies the draft's prose. It never sees anything from
the run: every value and every block is replaced by a placeholder before the draft is sent
and put back after, so the model cannot read the flag, be steered by challenge text, or
change a command. Its reply is checked (every placeholder once, blocks alone on their lines
and in order, no code, HTML, link, address or number the draft did not have) and refused,
with the reason, when it fails a check.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from . import fmt
from .runrecord import ActionLine, EventLine, FileLine, LaneRecord, RunRecord
from .text import untrusted

if TYPE_CHECKING:
    from .agent.client import ModelClient, Usage
    from .platform.manual import Board

WINDOW = 5  # steps shown before the one that mattered
OUTPUT_LINES = 20  # lines of a step's output shown
LINE_CHARS = 500  # characters of one output line shown
FILE_LINES = 200  # a file the lane added is shown whole when it has fewer lines than this
WHOLE_FILES = 10  # files shown whole at most; the rest are listed by name
REDACTED = "<flag>"

PLAN = "plan: "  # agent/tools.py: a turn that only set the plan
NEW_PLAN = "new plan: "  # core/deck.py: the player's redirect

_PLAIN_MARKS = frozenset(" ,'\"-()?!%+/;")
_NUMBERED = re.compile(r"\d+\)")  # "1) x" would start an ordered list
_TICKS = re.compile(r"`+")
_LANG = re.compile(r"[a-z]*")
_MORE = re.compile(r"\s+\(\+\d+ more\)$")  # agent/driver.py: a turn with several tool calls
_SEPARATORS = re.compile(r"&&|\|\||[;|&\n]")
_REDIRECT = re.compile(r"\d*(?:>>?|<<?<?)\s*(?:'[^']*'|\"[^\"]*\"|\S+)")  # > out.txt, < in.txt, <<'EOF'
_VIEWERS = frozenset(
    "cat less more head tail nano vi vim nvim emacs ed echo printf tee wc file ls stat xxd hexdump od "
    "strings grep egrep fgrep rg diff cmp cp mv rm touch mkdir chmod chown ln sed awk sort uniq cut tr "
    "base64 md5sum sha1sum sha256sum".split()
)
"""First words of shell commands that show, edit or move a file rather than run it."""

_LANGUAGES = {
    ".py": "python", ".sage": "python", ".sh": "bash", ".bash": "bash", ".js": "javascript",
    ".mjs": "javascript", ".ts": "typescript", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
    ".hpp": "cpp", ".rs": "rust", ".go": "go", ".rb": "ruby", ".php": "php", ".java": "java",
    ".pl": "perl", ".lua": "lua", ".sql": "sql", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
    ".toml": "toml", ".html": "html", ".xml": "xml", ".s": "asm", ".asm": "asm", ".gdb": "text",
}

_INTERVENTIONS = (  # the deck's own wording for what the player did (core/deck.py), most specific first
    ("approved more budget: ", "more budget"),
    ("approved: ", "approval"),
    ("declined: ", "decline"),
    (NEW_PLAN, "redirect"),
    ("forked to ", "fork to"),
    ("fork queued first ", "fork, queued"),
    ("escalated ", "escalation"),
    ("taken over by the player", "take-over"),
    ("handed back by the player", "hand-back"),
    ("paused by the player", "pause"),
    ("resumed by the player", "resume"),
)


class WriteupError(Exception):
    """No draft for this challenge: it is not in the run, or the run did not solve it."""


class PolishError(Exception):
    """The model's tidied draft was refused; the message says which check it failed. `usage`
    is what the refused call used (None when no call was made), so its cost is still counted."""

    def __init__(self, message: str, usage: Usage | None = None) -> None:
        super().__init__(message)
        self.usage = usage


# ---------------------------------------------------------------------- what the run solved


@dataclass(frozen=True)
class L1Result:
    """One L1 engine's run on a challenge, as the event log has it."""

    engine: str
    status: str
    flags: tuple[str, ...]
    seconds: float | None
    notes: str
    evidence: tuple[str, ...]  # one line per item, when the log has an evidence list
    lane: str | None  # the lane it ran for
    at: float


@dataclass(frozen=True)
class Solve:
    """A challenge the run solved: its first accepted flag."""

    challenge: str
    flag: str  # "" when the submit event does not hold it
    at: float  # when it was accepted (the deck's clock)
    lane: str | None  # the lane it was submitted on
    judged_by: str  # "platform": the board checked it; "player": you said it was accepted
    l1: L1Result | None  # the L1 run that found the flag, when one did before it was accepted
    l1_runs: tuple[L1Result, ...] = ()  # every L1 run on the challenge, in order


def solves(record: RunRecord) -> dict[str, Solve]:
    """Every challenge the run solved, by id, in the order they were solved."""
    runs: dict[str, list[L1Result]] = {}
    found: dict[str, Solve] = {}
    for event in record.events:
        cid = event.challenge
        if not cid:
            continue
        if event.kind == "l1":
            runs.setdefault(cid, []).append(_l1_result(event))
        elif event.kind == "submit" and event.data.get("correct") is True and cid not in found:
            flag = _str(event.data.get("flag"))
            source = next((run for run in runs.get(cid, ()) if flag and flag in run.flags), None)
            found[cid] = Solve(cid, flag, event.at, event.lane, _str(event.data.get("by")), source)
    return {cid: replace(solve, l1_runs=tuple(runs.get(cid, ()))) for cid, solve in found.items()}


def draft(record: RunRecord, challenge_id: str, *, board: Board | None = None, redact: bool = False) -> str:
    """The Markdown draft for one solved challenge. `board` gives names and points the run
    log lacks; `redact` writes <flag> in place of every copy of the flag. WriteupError when
    the run did not solve it."""
    return _Writer(record, _solve(record, challenge_id), board=board, redact=redact).markdown()


def file_name(challenge_id: str) -> str | None:
    """`<id>.md`, or None when the id cannot safely name a file (it comes from the run log)."""
    from .platform.manual import ID, MAX_ID

    if len(challenge_id) > MAX_ID or not ID.fullmatch(challenge_id):
        return None
    return f"{challenge_id}.md"


def _solve(record: RunRecord, challenge_id: str) -> Solve:
    solve = solves(record).get(challenge_id)
    if solve is None:
        shown = untrusted(challenge_id, one_line=True)
        known = any(e.challenge == challenge_id for e in record.events) or any(
            lane.challenge == challenge_id for lane in record.lanes.values()
        )
        why = "has no accepted flag in this run" if known else "is not in this run"
        raise WriteupError(f"challenge {shown!r} {why}: nothing to write up")
    return solve


def _l1_result(event: EventLine) -> L1Result:
    data = event.data
    flags = data.get("flags")
    seconds = data.get("seconds")
    return L1Result(
        engine=_str(data.get("engine")),
        status=_str(data.get("status")),
        flags=tuple(f for f in flags if isinstance(f, str) and f) if isinstance(flags, list) else (),
        seconds=float(seconds) if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) else None,
        notes=_str(data.get("notes")),
        evidence=_evidence(data.get("evidence")),
        lane=event.lane,
        at=event.at,
    )


def _evidence(value: object) -> tuple[str, ...]:
    """An evidence list (l1.result.Evidence as dicts: kind, detail, path, offset) as one line each."""
    if not isinstance(value, list):
        return ()
    lines = []
    for item in value:
        if isinstance(item, str):
            lines.append(item)
        elif isinstance(item, Mapping):
            line = f"{_str(item.get('kind')) or 'evidence'}: {_str(item.get('detail'))}"
            path, offset = item.get("path"), item.get("offset")
            if isinstance(path, str) and path:
                at = f" at offset {offset}" if isinstance(offset, int) and not isinstance(offset, bool) else ""
                line += f" (in {path}{at})"
            lines.append(line)
    return tuple(lines)


def _str(value: object) -> str:
    return value if isinstance(value, str) else ""


# ---------------------------------------------------------------------- Markdown for untrusted text


def inline(text: str) -> str:
    """One line of untrusted text for Markdown prose: plain when it holds only letters,
    digits, spaces and marks that mean nothing in Markdown (so it reads the same anywhere on
    a line, even first), otherwise a code span. "(empty)" for empty text."""
    text = untrusted(text, one_line=True)
    if _plain(text):
        return text
    return code(text)


def code(text: str) -> str:
    """Untrusted text as a code span: one line, delimited by a backtick run longer than any
    inside it, padded with a space when it starts or ends with a backtick or a space (the
    renderer takes one space off each side). "(empty)" for empty text."""
    text = untrusted(text, one_line=True)
    if not text:
        return "(empty)"
    tick = "`" * (max((len(run) for run in _TICKS.findall(text)), default=0) + 1)
    pad = " " if text.strip(" ") and (text[0] in "` " or text[-1] in "` ") else ""
    return f"{tick}{pad}{text}{pad}{tick}"


def fenced(text: str, lang: str = "text") -> str:
    """Untrusted text as a fenced code block: a fence of backticks longer than any backtick
    run inside it (and at least three), so no line of the text can close it, and `lang`, one
    of our own info strings, never text from the run."""
    if not _LANG.fullmatch(lang):
        raise ValueError(f"info string {lang!r} is not a plain language name")
    body = untrusted(text.replace("\r\n", "\n"))
    if body.endswith("\n"):
        body = body[:-1]
    fence = "`" * max(3, max((len(run) for run in _TICKS.findall(body)), default=0) + 1)
    return f"{fence}{lang}\n{body}\n{fence}"


def _plain(text: str) -> bool:
    if not text or text != text.strip() or _NUMBERED.match(text):
        return False
    if not (text[0].isalnum() or text[0] in "\"'("):
        return False
    return all(ch.isalnum() or ch in _PLAIN_MARKS for ch in text)


# ---------------------------------------------------------------------- reading a transcript


def added_content(diff: str) -> str | None:
    """The content of a file the lane added, from its unified diff (agent.workspace.changed_files);
    None when the diff is not one of an added text file (a binary file, one over 64 KB). Ends
    with a newline when the file does."""
    lines = diff.split("\n")
    if len(lines) < 2 or lines[0] != "--- /dev/null" or not lines[1].startswith("+++ "):
        return None
    content: list[str] = []
    newline = True
    for line in lines[2:]:  # after the header, every line is a hunk header, content or the marker
        if line.startswith("@@"):
            continue  # content that starts with @@ reads +@@ here
        if line.startswith("+"):
            content.append(line[1:])
        elif line == "\\ No newline at end of file":
            newline = False
        else:
            return None
    if not content:
        return ""
    return "\n".join(content) + ("\n" if newline else "")


def _line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _language(path: str) -> str:
    return _LANGUAGES.get(PurePosixPath(path).suffix.lower(), "text")


def _command(step: ActionLine) -> str | None:
    """A shell step's command line ("$ ..."), without the "(+N more)" a multi-call turn adds."""
    if not step.text.startswith("$ "):
        return None
    return _MORE.sub("", step.text[2:])


def _ran(step: ActionLine, paths: Sequence[str]) -> str | None:
    """The first of `paths` this step ran: a simple command in its shell line names the file
    (or its base name) outside a redirect, and does not start with a command that only shows,
    edits or moves files."""
    command = _command(step)
    if command is None:
        return None
    for part in _SEPARATORS.split(command):
        part = _REDIRECT.sub(" ", part)
        words = [w for w in part.split() if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=\S*", w)]
        if not words or PurePosixPath(words[0]).name in _VIEWERS:
            continue
        for path in paths:
            if _names(part, path) or _names(part, PurePosixPath(path).name):
                return path
    return None


def _names(text: str, path: str) -> bool:
    return bool(path) and re.search(r"(?<![\w.-])" + re.escape(path) + r"(?![\w.-])", text) is not None


def _same_plan(listed: str, final: str) -> bool:
    """Whether `final` is the plan already listed (a plan step's text is cut with a …)."""
    a, b = untrusted(listed, one_line=True), untrusted(final, one_line=True)
    return a == b or (a.endswith("…") and b.startswith(a[:-1]))


def _intervention(action: ActionLine) -> tuple[str, str]:
    """(what the player did, the rest of the transcript's text) for one of their entries."""
    if action.kind == "message":
        return "hint", action.text
    for prefix, label in _INTERVENTIONS:
        if action.text.startswith(prefix):
            return label, action.text[len(prefix):].lstrip(":").strip()
    return "other", action.text


def _cut(text: str) -> tuple[str, str]:
    """The first OUTPUT_LINES lines of text, each cut to LINE_CHARS, and what was cut ("" if nothing)."""
    lines = text.replace("\r\n", "\n").split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    notes = []
    if len(lines) > OUTPUT_LINES:
        notes.append(f"the first {OUTPUT_LINES} of its {len(lines)} lines are shown")
        lines = lines[:OUTPUT_LINES]
    if any(len(line) > LINE_CHARS for line in lines):
        notes.append(f"lines over {LINE_CHARS} characters are cut short")
        lines = [line[:LINE_CHARS] for line in lines]
    return "\n".join(lines), "; ".join(notes)


# ---------------------------------------------------------------------- the draft


class _Writer:
    """Builds one draft. With `held` (polish), every untrusted piece is a placeholder and its
    Markdown goes in `held`, so the text holds nothing from the run."""

    def __init__(self, record: RunRecord, solve: Solve, *, board: Board | None, redact: bool,
                 held: dict[str, str] | None = None) -> None:
        self.record = record
        self.solve = solve
        self.lane = record.lanes.get(solve.lane) if solve.lane else None
        self.secret = solve.flag if redact and solve.flag else ""
        self.board = next((b.challenge for b in board.challenges if b.challenge.id == solve.challenge), None) if board else None
        self.held = held
        self.nonce = secrets.token_hex(4)
        self.blocks: list[str] = []  # placeholders of held blocks, in order
        self.lines: list[str] = []

    # ------------------------------------------------------------ pieces

    def _clean(self, text: str) -> str:
        """Redacted, before any folding or cutting (so a cut never leaves part of the flag)."""
        return text.replace(self.secret, REDACTED) if self.secret else text

    def _piece(self, markdown: str, *, block: bool = False) -> str:
        if self.held is None:
            return markdown
        kind = "block-" if block else ""
        key = f"{{{{{self.nonce}-{kind}{len(self.held) + 1}}}}}"
        self.held[key] = markdown
        if block:
            self.blocks.append(key)
        return key

    def t(self, text: str) -> str:
        """Untrusted text, inline."""
        return self._piece(inline(self._clean(text)))

    def ours(self, text: str) -> str:
        """Our own text as a code span (held when polishing: the reply may not hold backticks)."""
        return self._piece(code(text))

    def block(self, text: str, lang: str = "text", *, cleaned: bool = False) -> None:
        """Untrusted text as a fenced block, with blank lines around it."""
        self.out(self._piece(fenced(text if cleaned else self._clean(text), lang), block=True), "")

    def out(self, *lines: str) -> None:
        self.lines.extend(lines)

    # ------------------------------------------------------------ the whole

    def markdown(self) -> str:
        self._head()
        if self.solve.l1 is not None:
            self._l1()
        elif self.lane is not None:
            self._approach(self.lane)
            steps = self._steps(self.lane)
            self._files(self.lane, steps)
            self._interventions(self.lane)
        else:
            self._no_transcript()
        self._flag()
        self._problems()
        return "\n".join(self.lines).rstrip("\n") + "\n"

    def _facts(self) -> tuple[str, str, int | None]:
        """Name, category and points: from the run's lanes on the challenge, else the board."""
        cid = self.solve.challenge
        lanes = ([self.lane] if self.lane else []) + [
            lane for lane in self.record.lanes.values() if lane.challenge == cid and lane is not self.lane
        ]
        for lane in lanes:
            if lane.name:
                return lane.name, lane.category, lane.points
        if self.board is not None:
            return self.board.name, self.board.category, self.board.points
        return cid, "", None

    def _head(self) -> None:
        solve, lane = self.solve, self.lane
        name, category, points = self._facts()
        self.out(f"# {self.t(name)}", "")
        self.out(f"- Category: {self.t(category) if category else 'unknown (not in the run log)'}")
        self.out(f"- Points: {points if points is not None else 'unknown (not in the run log)'}")
        if solve.l1 is not None:
            self.out(f"- Solved by: the L1 engine {self.t(solve.l1.engine)}, with no model, at {fmt.clock(solve.at)}")
        elif solve.lane is None:
            self.out(f"- Solved at {fmt.clock(solve.at)}; the run log does not say on which lane")
        else:
            after = f", {fmt.duration(solve.at - lane.started_at)} after it started" if lane else ""
            self.out(f"- Solved by: lane {self.t(solve.lane)} at {fmt.clock(solve.at)}{after}")
        if lane is not None and solve.l1 is None:
            self.out(f"- Model: {', then '.join(self.t(m) for m in self._models(lane))}")
            self.out(f"- Spent: {self._spent(lane)}")
            self.out(f"- Started as: {self._origin(lane)}")
        others = [x for x in self.record.lanes.values() if x.challenge == solve.challenge and x is not lane]
        if others:
            self.out("- Other lanes on it: " + "; ".join(self._other(x) for x in others))
        self.out("")

    def _models(self, lane: LaneRecord) -> list[str]:
        """The models the lane's turns ran on, in order (it changes on an escalation)."""
        models: list[str] = []
        for event in self.record.events:
            model = event.data.get("model") if event.kind == "turn" and event.lane == lane.lane else None
            if isinstance(model, str) and model and (not models or models[-1] != model):
                models.append(model)
        return models or [lane.model]

    def _spent(self, lane: LaneRecord) -> str:
        turns = f"{lane.turns} turn{'s' if lane.turns != 1 else ''}"
        tokens = f"{fmt.tokens(lane.tokens)} tokens"
        if lane.tokens > 0 and lane.cached_tokens > 0:
            tokens += f" ({round(100 * lane.cached_tokens / lane.tokens)}% cached)"
        cost = f"${fmt.dollars(lane.dollars)}" if lane.dollars is not None else "cost unknown"
        return f"{turns}, {tokens}, {cost}"

    def _origin(self, lane: LaneRecord) -> str:
        if lane.parent:
            return f"your fork of lane {self.t(lane.parent)}"
        if lane.attempt > 1:
            return f"attempt {lane.attempt}, after you re-queued the challenge"
        return "a fresh lane from the queue"

    def _other(self, other: LaneRecord) -> str:
        text = f"{self.t(other.lane)} ({self.t(other.state)})"
        return text + (f": {self.t(other.result)}" if other.result else "")

    # ------------------------------------------------------------ a lane's solve

    def _start(self, lane: LaneRecord) -> EventLine | None:
        return next((e for e in self.record.events if e.kind == "lane.start" and e.lane == lane.lane), None)

    def _approach(self, lane: LaneRecord) -> None:
        self.out("## Approach", "")
        items: list[str] = []
        if lane.parent:
            start = self._start(lane)
            approach = _str(start.data.get("approach")) if start is not None else ""
            given = f", with the approach {self.t(approach)}" if approach else ", with no approach given"
            items.append(f"You forked it from lane {self.t(lane.parent)}{given}.")
        last = ""
        for action in lane.actions:
            if action.kind == "step" and action.text.startswith(PLAN):
                last = action.text[len(PLAN):]
                items.append(f"Turn {action.turn}, the lane's plan: {self.t(last)}")
            elif action.by == "player" and action.text.startswith(NEW_PLAN):
                last = action.text[len(NEW_PLAN):]
                items.append(f"Turn {action.turn}, you redirected it: {self.t(last)}")
        if lane.plan and not (last and _same_plan(last, lane.plan)):
            items.append(
                f"Its plan at the end, set in a turn that also did other work (so the log does not "
                f"say when): {self.t(lane.plan)}"
            )
        if not items:
            self.out("The lane recorded no plan.", "")
            return
        self.out(*(f"{n}. {item}" for n, item in enumerate(items, 1)), "")

    def _steps(self, lane: LaneRecord) -> list[ActionLine]:
        """The steps that mattered; returns every step of the lane up to the solve."""
        self.out("## Steps that mattered", "")
        steps = [
            a for a in lane.actions if a.kind == "step" and not a.text.startswith(PLAN) and a.at <= self.solve.at
        ]
        if not steps:
            self.out("The transcript has no steps before the flag was accepted.", "")
            return steps
        index, why, mark = self._key(lane, steps)
        shown = steps[max(0, index - WINDOW): index + 1]
        before = len(shown) - 1
        with_it = f" Here it is with the {before} step{'s' if before != 1 else ''} before it." if before else ""
        self.out(why + with_it, "")
        for step in shown:
            key = step is steps[index]
            self.out(f"### Turn {step.turn}" + (f" ({mark})" if key else ""), "")
            self.out(self.t(step.text) if step.text else "(no command recorded)", "")
            text, cut = _cut(self._clean(step.output))
            if not text.strip():
                self.out("No output recorded.", "")
                continue
            self.block(text, cleaned=True)
            if cut:
                self.out(f"Output cut: {cut}.", "")
        return steps

    def _key(self, lane: LaneRecord, steps: list[ActionLine]) -> tuple[int, str, str]:
        """The step that mattered, why, and how its heading marks it."""
        flag = self.solve.flag
        if flag:
            for i, step in enumerate(steps):
                if flag in step.output:
                    return i, f"The flag first shows in the output of turn {step.turn}.", "the flag shows here"
        written = [f.file for f in lane.files if f.status in ("added", "modified")]
        for i in range(len(steps) - 1, -1, -1):
            path = _ran(steps[i], written)
            if path is not None:
                why = (f"No step's output shows the flag; the last step that ran a file the lane "
                       f"wrote is turn {steps[i].turn}, which ran {self.t(path)}.")
                return i, why, "this ran a file the lane wrote"
        why = ("No step's output shows the flag and no step ran a file the lane wrote, so this is the "
               "last step before the flag was accepted.")
        return len(steps) - 1, why, "the last step"

    def _files(self, lane: LaneRecord, steps: list[ActionLine]) -> None:
        self.out("## Files the lane wrote", "")
        written = [f for f in lane.files if f.status != "deleted"]
        deleted = [f for f in lane.files if f.status == "deleted"]
        if not written and not deleted:
            self.out("None: the lane changed no files in its workspace.", "")
            return
        paths = [f.file for f in written]
        ran = {path for step in steps if (path := _ran(step, paths)) is not None}
        written.sort(key=lambda f: (f.file not in ran, f.turn, f.file))
        for change in written[:WHOLE_FILES]:
            self._file(change, lane)
        rest = written[WHOLE_FILES:]
        if rest:
            where = self.t(f"lanes/{lane.lane}.jsonl")
            self.out(f"{len(rest)} more, not shown here (their diffs are in {where}):", "")
            self.out(*(f"- {self.t(f.file)}, {self.t(f.status)} in turn {f.turn}" for f in rest), "")
        if deleted:
            self.out("Deleted: " + ", ".join(self.t(f.file) for f in deleted) + ".", "")

    def _file(self, change: FileLine, lane: LaneRecord) -> None:
        heading = f"### {self.t(change.file)}, {self.t(change.status)} in turn {change.turn}"
        description = change.diff.split("\n", 1)[0]
        if change.status == "added":
            content = added_content(change.diff)
            if content is None:
                self.out(heading, "", f"Not shown: {self.t(description)}.", "")
                return
            count = _line_count(content)
            if count == 0:
                self.out(heading, "", "An empty file.", "")
            elif count < FILE_LINES:
                self.out(f"{heading}, {count} line{'s' if count != 1 else ''}", "")
                self.block(content, _language(change.file))
            else:
                self.out(f"{heading}, {count} lines", "",
                         f"Too long to show here (a draft shows files under {FILE_LINES} lines); its diff is in "
                         f"{self.t(f'lanes/{lane.lane}.jsonl')}.", "")
            return
        if change.diff.startswith("--- "):
            count = _line_count(change.diff)
            if count < FILE_LINES:
                self.out(heading, "", "Its last change, as the transcript keeps it:", "")
                self.block(change.diff, "diff")
            else:
                self.out(heading, "", f"Its last change is a diff of {count} lines, too long to show here.", "")
            return
        self.out(heading, "", f"Not shown: {self.t(description) if description else 'no diff recorded'}.", "")

    def _interventions(self, lane: LaneRecord) -> None:
        self.out("## Your interventions", "")
        mine = [a for a in lane.actions if a.by == "player"]
        if not mine:
            self.out("None: the lane worked on its own.", "")
            return
        for action in mine:
            label, detail = _intervention(action)
            self.out(f"- Turn {action.turn}, {label}" + (f": {self.t(detail)}" if detail else ""))
        self.out("")

    def _no_transcript(self) -> None:
        lane = self.solve.lane
        self.out("## Steps, files and interventions", "")
        if lane is None:
            self.out("The run log does not say which lane found the flag, so its approach, steps, files and "
                     "your interventions are not known.", "")
            return
        self.out(f"The run folder has no transcript for lane {self.t(lane)} ({self.t(f'lanes/{lane}.jsonl')} "
                 "is missing or could not be read), so its approach, steps, files and your interventions are "
                 "not known.", "")

    # ------------------------------------------------------------ an L1 solve

    def _l1(self) -> None:
        result = self.solve.l1
        assert result is not None
        self.out("## How L1 solved it", "")
        took = f", in {result.seconds:.1f} s" if result.seconds is not None else ""
        self.out(f"The L1 engine {self.t(result.engine)} found the flag with no model{took}.", "")
        self.out(f"- Status: {self.t(result.status)}")
        self.out("- Flags it reported: " + ", ".join(self.t(flag) for flag in result.flags))
        self.out(f"- Notes: {self.t(result.notes) if result.notes else 'none'}")
        if result.evidence:
            self.out(*(f"- Evidence: {self.t(item)}" for item in result.evidence))
        else:
            self.out("- Evidence: the run log keeps the engine's notes, not its evidence list")
        if self.solve.lane:
            self.out(f"- Reported on lane {self.t(self.solve.lane)}, where you approved it")
        self.out("")
        others = [run for run in self.solve.l1_runs if run is not result]
        if others:
            self.out("Other L1 engines that ran on it:", "")
            for run in others:
                notes = f": {self.t(run.notes)}" if run.notes else ""
                self.out(f"- {self.t(run.engine)}, {self.t(run.status)}{notes}")
            self.out("")

    # ------------------------------------------------------------ the flag and the log's gaps

    def _flag(self) -> None:
        solve = self.solve
        self.out("## Flag", "")
        if not solve.flag:
            self.out("The run log does not hold the accepted flag.", "")
        else:
            self.block(solve.flag)
            if self.secret:
                self.out(f"Redacted: every copy of the flag in this draft reads {self.ours(REDACTED)}.", "")
        where = f" on lane {self.t(solve.lane)}" if solve.lane else ""
        how = {"platform": ": the board checked it", "player": ": you said the platform accepted it"}.get(solve.judged_by, "")
        self.out(f"Accepted at {fmt.clock(solve.at)}{where}{how}.", "")

    def _problems(self) -> None:
        if not self.record.problems:
            return
        self.out("## Gaps in the run log", "", "These lines of the run folder could not be read, so this draft may "
                 "miss something:", "")
        self.out(*(f"- {self.t(problem)}" for problem in self.record.problems), "")


# ---------------------------------------------------------------------- polish


POLISH_INSTRUCTIONS = """\
You tidy the prose of a draft CTF writeup, written in Markdown, so that it reads well.

The draft holds placeholders written as two braces, an id and two closing braces. Each one
stands for something you cannot see: a name, a command, an output, a file, a flag. One with
"block" in its id stands for a code block.

Rules:
- Keep every placeholder exactly as written, once each. A block placeholder stays alone on
  its line, and the blocks stay in the order they are in.
- Only reword the prose around the placeholders: join list items into sentences, fix the
  grammar, keep the headings.
- Never add a fact: no name, number, tool, step, cause or result that the draft does not
  state. Keep every number as written.
- No links, no web addresses, no images, no HTML, no code, no backticks, no square brackets.
- Answer with the Markdown only.
"""

_TOKEN = re.compile(r"\{\{[0-9a-f]{8}-(?:block-)?\d+\}\}")
_HTML = re.compile(r"<[A-Za-z/!?]|&#?[A-Za-z0-9]+;")
_FENCE = re.compile(r"^ {0,3}~{3,}", re.MULTILINE)
_ADDRESS = re.compile(r"://|\bwww\.|@\w", re.IGNORECASE)
_DIGITS = re.compile(r"\d+")


@dataclass(frozen=True)
class Polished:
    markdown: str
    usage: Usage  # what the model call used, for the cost


async def polish(
    record: RunRecord,
    challenge_id: str,
    *,
    client: ModelClient,
    model: str,
    board: Board | None = None,
    redact: bool = False,
) -> Polished:
    """The draft with its prose tidied by `model`. The model sees our words and placeholders
    only, never a value from the run. PolishError when its reply fails a check; ModelError
    (agent.client) when the call fails."""
    held: dict[str, str] = {}
    writer = _Writer(record, _solve(record, challenge_id), board=board, redact=redact, held=held)
    frozen = writer.markdown()
    messages = [
        {"role": "system", "content": POLISH_INSTRUCTIONS},
        {"role": "user", "content": frozen},
    ]
    reply = await client.chat(model, messages, [], session_id=f"flightdeck-writeup-{secrets.token_hex(8)}")
    try:
        checked = checked_reply(reply.content, frozen, held, writer.blocks)
    except PolishError as refused:
        refused.usage = reply.usage
        raise
    return Polished(thaw(checked, held, writer.blocks), reply.usage)


def checked_reply(reply: str, frozen: str, held: Mapping[str, str], blocks: Sequence[str]) -> str:
    """The model's reply, folded, once it passes every check; PolishError naming the first it fails."""
    text = untrusted(reply.replace("\r\n", "\n")).strip("\n")
    if not text.strip():
        raise PolishError("the model's reply is empty")
    tokens = _TOKEN.findall(text)
    unknown = sorted(set(tokens) - set(held))
    if unknown:
        raise PolishError(f"the reply has {len(unknown)} placeholder(s) the draft does not have")
    for n, key in enumerate(held, 1):
        if (count := tokens.count(key)) != 1:
            raise PolishError(f"the reply has placeholder {n} of {len(held)} {count} times; it must keep each once")
    lines = text.split("\n")
    alone = set(blocks)
    for key in blocks:
        if next(line for line in lines if key in line).strip() != key:
            raise PolishError("the reply moved a code block into a line of prose")
    if [line.strip() for line in lines if line.strip() in alone] != list(blocks):
        raise PolishError("the reply changed the order of the code blocks")
    prose, ours = _TOKEN.sub(" ", text), _TOKEN.sub(" ", frozen)
    for pattern, what in (
        (re.compile("`"), "code (a backtick)"),
        (_FENCE, "a code block"),
        (_HTML, "HTML or an HTML entity"),
        (re.compile(r"[\[\]]"), "a link or an image (a square bracket)"),
        (_ADDRESS, "a web address, an email address or a mention"),
        (re.compile(r"\{\{|\}\}"), "a changed placeholder"),
    ):
        if pattern.search(prose):
            raise PolishError(f"the reply adds {what}")
    new = sorted(set(_DIGITS.findall(prose)) - set(_DIGITS.findall(ours)), key=lambda d: (len(d), d))
    if new:
        raise PolishError(f"the reply has numbers the draft does not: {', '.join(new[:5])}")
    if len(prose) > 2 * len(ours) + 500:
        raise PolishError(f"the reply is {len(prose)} characters of prose against the draft's {len(ours)}")
    return text


def thaw(text: str, held: Mapping[str, str], blocks: Iterable[str]) -> str:
    """Put every placeholder's Markdown back; a block takes its whole line, with blank lines
    around it. The blocks come back exactly as they were (blank lines inside them included)."""
    alone = set(blocks)
    out: list[str] = []
    for line in text.split("\n"):
        key = line.strip()
        if key in alone:
            if out and out[-1].strip():
                out.append("")
            out.extend([held[key], ""])
            continue
        if not line.strip() and out and not out[-1].strip():
            continue  # one blank line is enough between paragraphs
        out.append(_TOKEN.sub(lambda m: held[m.group()], line))
    return "\n".join(out).strip("\n") + "\n"
