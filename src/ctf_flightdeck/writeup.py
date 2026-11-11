"""Writeup drafts: one Markdown file per challenge a run solved, from what the run recorded.

`draft(record, challenge_id)` writes up one solve from a run folder (runrecord.load_run):

- solved by a lane: from that lane's transcript (lanes/<id>.jsonl), the approach (its plan
  changes and your redirects, in order), the steps that mattered, the files it wrote, your
  interventions, and the flag;
- solved by L1: a no-model solver found the flag, which then went through a lane's approval
  like any candidate (Deck.record_l1), or was submitted at once when submit is "auto". The
  draft names the engine and what it recorded.

Solved means accepted: a submit event with `correct` true. A flag an L1 engine found that was
never accepted is not a solve ("flag found" is never "accepted"). A solve is L1's when the
accepted flag is one an `l1` event on that challenge reported before it was accepted.

Where the run's text holds the flag. A transcript holds more than exact copies of it:
agent/tools.py folds every action with text.untrusted() (an invisible character in the flag
becomes U+FFFD there) and cuts long text short with a "…", and a solver often prints only the
part inside the braces, which the lane then wraps in the flag format. So a copy of the flag is
any of: the flag as found or folded; its start, at least CUT_MIN characters and past its
opening brace, cut short at a "…" or at the end of a line; and, when the flag reads
prefix{body} with a body of at least CUT_MIN characters, that body, whole or cut short at a
"…". `redact` writes <flag> in place of every copy; a copy a tool encoded or split over lines
is not found, and the draft says so.

The steps that mattered: the first step whose output holds a copy of the flag; failing that,
the last step that ran a file the lane wrote (a shell command naming it, not one that only
shows or edits it, nor a line inside a heredoc; a newline the transcript folded splits
commands as a real one does); failing that, the last step before the flag was accepted. The
draft says which rule picked it, and shows it with the 5 steps before it: each command in a
fenced block (a multi-line one with its lines back), each output in another, cut to 20 lines.
A plan the lane stated is not a step: it is in the approach (a turn that set the plan and also
submitted a flag stays a step).

The files: those with something to show (an added text file under 200 lines, a diff that
short) are shown whole, at most 10, files a step ran first; every other file is listed with
one line on what it is.

What the transcript cannot tell. A lane's plan change shows up only when it was the first
thing the lane did in that turn and nothing else acted (a "plan: ..." step); otherwise only
its last plan, in the transcript's header, is known, and the draft says so. A turn with
several tool calls keeps one in the transcript, and the draft says how many more it made.
The transcript keeps the newest change to each file, so a file the lane added and then edited
shows as modified, with its last diff.

Untrusted text. Everything read from a run came from a challenge, a model, a tool or a file
a lane wrote, and a draft is meant to be read, edited and published. So nothing in it may act
as Markdown:

- each value has the flag redacted first (when asked), so no cut can leave part of it, and is
  folded with text.untrusted() (control and invisible characters made visible), lone
  surrogates included (JSON from a model can hold one; no UTF-8 file can);
- a one-line value stays plain text only when it is letters, digits, spaces and a few marks
  that mean nothing in Markdown (inline()); anything else becomes a code span whose backtick
  run is longer than any inside it (code());
- multi-line text (commands, outputs, files, diffs, the flag) goes in a fenced block whose
  fence is longer than any backtick run inside, with an info string of ours (fenced()).

A draft therefore never holds raw HTML, an entity, a link, an image or a mention from the
run, and nothing from the run can end a block early or start one. Our own words never use
backticks, brackets or angle brackets.

Polish (`polish()`, optional): a model tidies the draft's prose. It never sees anything from
the run: every value and every block is replaced by a placeholder before the draft is sent
and put back after, so the model cannot read the flag, be steered by challenge text, or
change a command. Our own lines that state facts (the challenge's facts at the top, why a
step was picked, the L1 engine's record, when and how the flag was accepted) are placeholders
too, so the model can reword only the prose that connects them. Its reply is checked, and
refused with the reason when it fails a check: every placeholder once; blocks and fact lines
alone on their lines and in order; nothing against a placeholder but a space, a line's edge,
"(" before it or a mark of punctuation after it (so no markup can be built around a value);
no code, HTML, link, address or domain; and the draft's numbers, as written and in order.
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
from .text import MARK, NEWLINE, untrusted

if TYPE_CHECKING:
    from .agent.client import ModelClient, Usage
    from .platform.manual import Board

WINDOW = 5  # steps shown before the one that mattered
OUTPUT_LINES = 20  # lines of a step's output shown
LINE_CHARS = 500  # characters of one output line shown
FILE_LINES = 200  # a file the lane added is shown whole when it has fewer lines than this
WHOLE_FILES = 10  # files shown whole at most; the rest are listed, one line each
CUT_MIN = 6  # a cut copy of the flag, or the part inside its braces alone, has at least this many characters
REDACTED = "<flag>"

PLAN = "plan: "  # agent/tools.py: a turn that only set the plan
NEW_PLAN = "new plan: "  # core/deck.py: the player's redirect
APPROVED = "approved: "  # core/deck.py: the player approved what the lane waited for
CLIP = "…"  # agent/tools.py: where it cut text short

_PLAIN_MARKS = frozenset(" ,'\"-()?!%+/;")
_NUMBERED = re.compile(r"\d+\)")  # "1) x" would start an ordered list
_TICKS = re.compile(r"`+")
_LANG = re.compile(r"[a-z]*")
_SURROGATE = re.compile("[\ud800-\udfff]")  # half of a UTF-16 pair: JSON allows one alone; UTF-8 cannot hold it
_MORE = re.compile(r"  \(\+(\d+) more\)$")  # agent/driver.py: a turn with several tool calls
_BODY = re.compile(r"[^{}]*\{(.+)\}", re.DOTALL)
_CLIP_ENDS = re.compile(CLIP)
_LINE_ENDS = re.compile(CLIP + "|$", re.MULTILINE)
_SEPARATORS = re.compile(r"&&|\|\||[;|&\n]")
_REDIRECT = re.compile(r"\d*(?:>>?|<<?<?)\s*(?:'[^']*'|\"[^\"]*\"|\S+)")  # > out.txt, < in.txt, <<'EOF'
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(?:'([^']*)'|\"([^\"]*)\"|\\?([^\s;&|<>()'\"]+))")  # not <<< (a here-string)
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")
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
    (APPROVED, "approval"),
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

_SHOWS = {  # why the step that mattered was picked, by what its output holds of the flag
    "whole": "The flag first shows in the output of turn {turn}.",
    "cut": "The flag first shows, cut short, in the output of turn {turn}.",
    "body": "The part inside the flag's braces first shows in the output of turn {turn}.",
}


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
    log lacks; `redact` writes <flag> in place of every copy of the flag (see the module
    docstring for what counts as one). WriteupError when the run did not solve it."""
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
        shown = _fold(challenge_id, one_line=True)
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
    text = _fold(text, one_line=True)
    if _plain(text):
        return text
    return code(text)


def code(text: str) -> str:
    """Untrusted text as a code span: one line, delimited by a backtick run longer than any
    inside it, padded with a space when it starts or ends with a backtick or a space (the
    renderer takes one space off each side). "(empty)" for empty text."""
    text = _fold(text, one_line=True)
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
    body = _fold(text.replace("\r\n", "\n"))
    if body.endswith("\n"):
        body = body[:-1]
    fence = "`" * max(3, max((len(run) for run in _TICKS.findall(body)), default=0) + 1)
    return f"{fence}{lang}\n{body}\n{fence}"


def _fold(text: str, *, one_line: bool = False) -> str:
    """text.untrusted(), with each lone surrogate shown as U+FFFD too."""
    return _SURROGATE.sub(MARK, untrusted(text, one_line=one_line))


def _plain(text: str) -> bool:
    if not text or text != text.strip() or _NUMBERED.match(text):
        return False
    if not (text[0].isalnum() or text[0] in "\"'("):
        return False
    return all(ch.isalnum() or ch in _PLAIN_MARKS for ch in text)


# ---------------------------------------------------------------------- copies of the flag


class _Copies:
    """The accepted flag, and the forms the run's text can hold it in (see the module docstring)."""

    def __init__(self, flag: str) -> None:
        self.whole = _forms(flag)
        body = _BODY.fullmatch(flag)
        self.body = _forms(body.group(1)) if body and len(body.group(1)) >= CUT_MIN else ()

    def kind(self, text: str) -> str | None:
        """What `text` holds of the flag: "whole" (as found or folded), "cut" (its start, cut
        short), "body" (the part inside its braces, whole or cut short), or None."""
        if any(form in text for form in self.whole):
            return "whole"
        if any(_cut_spans(text, form, _cut_min(form), line_ends=True) for form in self.whole):
            return "cut"
        if any(form in text for form in self.body) or any(
            _cut_spans(text, form, CUT_MIN, line_ends=False) for form in self.body
        ):
            return "body"
        return None

    def redact(self, text: str) -> str:
        """`text` with <flag> in place of every copy: whole ones first, so a body is never
        left between the flag's braces."""
        for form in self.whole:
            text = text.replace(form, REDACTED)
        for form in self.whole:
            text = _replaced(text, _cut_spans(text, form, _cut_min(form), line_ends=True))
        for form in self.body:
            text = text.replace(form, REDACTED)
        for form in self.body:
            text = _replaced(text, _cut_spans(text, form, CUT_MIN, line_ends=False))
        return text


def _forms(text: str) -> tuple[str, ...]:
    """`text` as found, and folded as the run's tools fold text (agent/tools.py runs every
    action through text.untrusted(), one line), and as a draft folds it."""
    folds = (text, untrusted(text), untrusted(text, one_line=True), _fold(text), _fold(text, one_line=True))
    return tuple(form for form in dict.fromkeys(folds) if form)


def _cut_min(form: str) -> int:
    """How much of the flag a cut copy keeps, at least: CUT_MIN characters, and one past the
    opening brace (a cut that keeps only "picoCTF{" says nothing of the flag)."""
    brace = form.find("{")
    return max(CUT_MIN, brace + 2) if brace >= 0 else CUT_MIN


def _cut_spans(text: str, form: str, minimum: int, *, line_ends: bool) -> list[tuple[int, int]]:
    """Where `text` holds the start of `form`, at least `minimum` characters of it but not all,
    right before a clip mark ("…") or, with line_ends, at the end of a line."""
    if len(form) <= minimum or form[:minimum] not in text:
        return []
    spans: list[tuple[int, int]] = []
    last = 0
    for mark in (_LINE_ENDS if line_ends else _CLIP_ENDS).finditer(text):
        end = mark.start()
        for size in range(min(len(form) - 1, end - last), minimum - 1, -1):
            if text.startswith(form[:size], end - size):
                spans.append((end - size, end))
                last = end
                break
    return spans


def _replaced(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    out, at = [], 0
    for start, end in spans:
        out += [text[at:start], REDACTED]
        at = end
    return "".join(out) + text[at:]


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


def _showable(change: FileLine) -> tuple[str, str] | None:
    """What a draft shows of a file the lane wrote, and the language of its block: an added
    text file under FILE_LINES lines, whole; a modified file's diff, when that short. None when
    it has nothing to show: a binary file, an empty one, one too long."""
    if change.status == "added":
        content = added_content(change.diff)
        if content and _line_count(content) < FILE_LINES:
            return content, _language(change.file)
    elif change.status == "modified" and change.diff.startswith("--- ") and _line_count(change.diff) < FILE_LINES:
        return change.diff, "diff"
    return None


def _line_count(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _language(path: str) -> str:
    return _LANGUAGES.get(PurePosixPath(path).suffix.lower(), "text")


def _without_more(text: str) -> tuple[str, int]:
    """A step's text without the "  (+N more)" that agent/driver.py adds for a turn with
    several tool calls (it keeps one), and N (0 when there is none)."""
    match = _MORE.search(text)
    return (text[: match.start()], int(match.group(1))) if match else (text, 0)


def _only_plan(text: str) -> bool:
    """A step that only set the plan. A turn whose other calls did not act either, such as a
    submit, reads "plan: ...  (+1 more)": it did more than set a plan, so it stays a step."""
    return text.startswith(PLAN) and _MORE.search(text) is None


def _command(step: ActionLine) -> str | None:
    """A shell step's command line ("$ ..."), without the "(+N more)" a multi-call turn adds."""
    if not step.text.startswith("$ "):
        return None
    return _without_more(step.text)[0][2:]


def _simple_commands(command: str) -> list[str]:
    """The simple commands of a shell command line, in order, with no heredoc's lines. A newline
    the transcript folded (text.NEWLINE: agent/tools.py keeps each action on one line) splits
    commands as a raw one does."""
    parts: list[str] = []
    heredocs: list[tuple[str, bool]] = []  # opened and not yet closed: (the word that ends it, <<- so indented)
    for line in command.replace(NEWLINE, "\n").split("\n"):
        if heredocs:
            word, indented = heredocs[0]
            if (line.lstrip(" \t") if indented else line) == word:  # <<- strips tabs: folding made them spaces
                heredocs.pop(0)
            continue
        for match in _HEREDOC.finditer(line):
            word = next(group for group in match.groups()[1:] if group is not None)
            heredocs.append((word, bool(match.group(1))))
        parts.extend(_SEPARATORS.split(line))
    return parts


class _Runs:
    """Which file the lane wrote each step ran. Made once per draft: a long lane has hundreds
    of steps and files, and each step is looked at for each file."""

    def __init__(self, paths: Iterable[str]) -> None:
        self.names: list[tuple[str, str, re.Pattern[str]]] = []  # (what a command names, the path, a pattern for it)
        for path in paths:
            for name in dict.fromkeys((path, PurePosixPath(path).name)):
                if name:
                    self.names.append((name, path, re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])")))
        self.seen: dict[ActionLine, str | None] = {}

    def of(self, step: ActionLine) -> str | None:
        """The first of the paths this step ran: a simple command in its shell line names the
        file (or its base name) outside a redirect, and does not start with a command that only
        shows, edits or moves files."""
        if step not in self.seen:
            self.seen[step] = self._ran(step)
        return self.seen[step]

    def _ran(self, step: ActionLine) -> str | None:
        command = _command(step)
        if command is None or not self.names:
            return None
        for part in _simple_commands(command):
            part = _REDIRECT.sub(" ", part)
            words = [w for w in part.split() if not _ASSIGNMENT.fullmatch(w)]
            if not words or PurePosixPath(words[0]).name in _VIEWERS:
                continue
            for name, path, pattern in self.names:
                if name in part and pattern.search(part):
                    return path
        return None


def _same_plan(listed: str, final: str) -> bool:
    """Whether `final` is the plan already listed (a plan step's text is cut with a …)."""
    a, b = _fold(listed, one_line=True), _fold(final, one_line=True)
    return a == b or (a.endswith(CLIP) and b.startswith(a[:-1]))


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
    """Builds one draft. With `held` (polish), every untrusted piece and every line of ours
    that states a fact is a placeholder, with its Markdown in `held`: the text holds nothing
    from the run, and no fact the model could reword."""

    def __init__(self, record: RunRecord, solve: Solve, *, board: Board | None, redact: bool,
                 held: dict[str, str] | None = None) -> None:
        self.record = record
        self.solve = solve
        self.lane = record.lanes.get(solve.lane) if solve.lane else None
        self.copies = _Copies(solve.flag) if solve.flag else None
        self.redact = redact and self.copies is not None
        self.board = next((b.challenge for b in board.challenges if b.challenge.id == solve.challenge), None) if board else None
        self.held = held
        self.nonce = secrets.token_hex(4)
        self.count = 0
        self.alone: list[str] = []  # placeholders that stand for a whole line (blocks, facts), in order
        self.lines: list[str] = []
        self._runs: _Runs | None = None

    def runs(self, lane: LaneRecord) -> _Runs:
        if self._runs is None:
            self._runs = _Runs(f.file for f in lane.files if f.status != "deleted")
        return self._runs

    # ------------------------------------------------------------ pieces

    def _clean(self, text: str) -> str:
        """Redacted, before any folding or cutting (so a cut never leaves part of the flag)."""
        return self.copies.redact(text) if self.redact and self.copies is not None else text

    def _piece(self, markdown: str, kind: str = "") -> str:
        """`markdown`, or when polishing a placeholder holding it. `kind` is "block-" or "line-"
        for one that stands for a whole line."""
        if self.held is None:
            return markdown
        self.count += 1
        key = f"{{{{{self.nonce}-{kind}{self.count}}}}}"
        self.held[key] = markdown
        if kind:
            self.alone.append(key)
        return key

    def t(self, text: str) -> str:
        """Untrusted text, inline."""
        return self._piece(inline(self._clean(text)))

    def ours(self, text: str) -> str:
        """Our own text as a code span (held when polishing: the reply may not hold backticks)."""
        return self._piece(code(text))

    def block(self, text: str, lang: str = "text", *, cleaned: bool = False) -> None:
        """Untrusted text as a fenced block, with blank lines around it."""
        self.out(self._piece(fenced(text if cleaned else self._clean(text), lang), "block-"), "")

    def fact(self, *lines: str) -> None:
        """Our lines that state facts. When polishing, each is held whole, the values in it
        included, so the model sees one placeholder for it and cannot reword the fact."""
        held = self.held
        for line in lines:
            if held is not None:
                line = self._piece(_TOKEN.sub(lambda m: held.pop(m.group()), line), "line-")
            self.out(line)

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
        facts = [
            f"- Category: {self.t(category) if category else 'unknown (not in the run log)'}",
            f"- Points: {points if points is not None else 'unknown (not in the run log)'}",
        ]
        if solve.l1 is not None:
            facts.append(f"- Solved by: the L1 engine {self.t(solve.l1.engine)}, with no model, at {fmt.clock(solve.at)}")
        elif solve.lane is None:
            facts.append(f"- Solved at {fmt.clock(solve.at)}; the run log does not say on which lane")
        else:
            after = f", {fmt.duration(solve.at - lane.started_at)} after it started" if lane else ""
            facts.append(f"- Solved by: lane {self.t(solve.lane)} at {fmt.clock(solve.at)}{after}")
        if lane is not None and solve.l1 is None:
            facts.append(f"- Model: {', then '.join(self.t(m) for m in self._models(lane))}")
            facts.append(f"- Spent: {self._spent(lane)}")
            facts.append(f"- Started as: {self._origin(lane)}")
        others = [x for x in self.record.lanes.values() if x.challenge == solve.challenge and x is not lane]
        if others:
            facts.append("- Other lanes on it: " + "; ".join(self._other(x) for x in others))
        self.fact(*facts)
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
                last = _without_more(action.text)[0][len(PLAN):]
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
        steps = [a for a in lane.actions if a.kind == "step" and not _only_plan(a.text) and a.at <= self.solve.at]
        if not steps:
            self.out("The transcript has no steps before the flag was accepted.", "")
            return steps
        index, why, mark = self._key(lane, steps)
        shown = steps[max(0, index - WINDOW): index + 1]
        before = len(shown) - 1
        with_it = f" Here it is with the {before} step{'s' if before != 1 else ''} before it." if before else ""
        self.fact(why + with_it)
        self.out("")
        for step in shown:
            self._step(step, mark if step is steps[index] else "")
        return steps

    def _step(self, step: ActionLine, mark: str) -> None:
        self.out(f"### Turn {step.turn}" + (f" ({mark})" if mark else ""), "")
        text, more = _without_more(step.text)
        if text:  # a multi-line command, one line in the transcript, gets its lines back
            self.block(self._clean(text).replace(NEWLINE, "\n"), cleaned=True)
        else:
            self.out("No command recorded.", "")
        if more:
            self.out(f"The turn made {more} more tool call{'s' if more != 1 else ''}; the transcript keeps only this one.", "")
        output, cut = _cut(self._clean(step.output))
        if not output.strip():
            self.out("No output recorded.", "")
            return
        self.block(output, cleaned=True)
        if cut:
            self.out(f"Output cut: {cut}.", "")

    def _key(self, lane: LaneRecord, steps: list[ActionLine]) -> tuple[int, str, str]:
        """The step that mattered, why, and how its heading marks it."""
        if self.copies is not None:
            for i, step in enumerate(steps):
                kind = self.copies.kind(step.output)
                if kind is not None:
                    return i, _SHOWS[kind].format(turn=step.turn), "the flag shows here"
        runs = self.runs(lane)
        for i in range(len(steps) - 1, -1, -1):
            path = runs.of(steps[i])
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
        runs = self.runs(lane)
        ran = {path for step in steps if (path := runs.of(step)) is not None}
        written.sort(key=lambda f: (f.file not in ran, f.turn, f.file))
        shown: list[tuple[FileLine, tuple[str, str]]] = []
        rest: list[FileLine] = []
        for change in written:  # only a file with something to show takes one of the WHOLE_FILES places
            whole = _showable(change) if len(shown) < WHOLE_FILES else None
            if whole is None:
                rest.append(change)
            else:
                shown.append((change, whole))
        for change, (text, lang) in shown:
            self._file(change, text, lang)
        if rest:
            more = "more " if shown else ""
            self.out(f"{len(rest)} {more}file{'s' if len(rest) != 1 else ''}, not shown here "
                     f"(see {self.t(f'lanes/{lane.lane}.jsonl')}):", "")
            self.out(*(f"- {self.t(f.file)}, {self.t(f.status)} in turn {f.turn}: {self._about(f)}" for f in rest), "")
        if deleted:
            self.out("Deleted: " + ", ".join(self.t(f.file) for f in deleted) + ".", "")

    def _file(self, change: FileLine, text: str, lang: str) -> None:
        heading = f"### {self.t(change.file)}, {self.t(change.status)} in turn {change.turn}"
        if change.status == "added":
            count = _line_count(text)
            self.out(f"{heading}, {count} line{'s' if count != 1 else ''}", "")
        else:
            self.out(heading, "", "Its last change, as the transcript keeps it:", "")
        self.block(text, lang)

    def _about(self, change: FileLine) -> str:
        """One line on a file the draft does not show."""
        if change.status == "added":
            content = added_content(change.diff)
            if content is not None:
                count = _line_count(content)
                if count == 0:
                    return "an empty file"
                lines = f"{count} line{'s' if count != 1 else ''}"
                return f"{lines}, too long to show here (a draft shows files under {FILE_LINES} lines)" if count >= FILE_LINES else lines
        elif change.diff.startswith("--- "):
            count = _line_count(change.diff)
            return f"a diff of {count} lines" + (", too long to show here" if count >= FILE_LINES else "")
        description = change.diff.split("\n", 1)[0]
        return self.t(description) if description else "no diff recorded"

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
            self.fact("The run log does not say which lane found the flag, so its approach, steps, files and "
                      "your interventions are not known.")
        else:
            self.fact(f"The run folder has no transcript for lane {self.t(lane)} ({self.t(f'lanes/{lane}.jsonl')} "
                      "is missing or could not be read), so its approach, steps, files and your interventions are "
                      "not known.")
        self.out("")

    # ------------------------------------------------------------ an L1 solve

    def _l1(self) -> None:
        result = self.solve.l1
        assert result is not None
        self.out("## How L1 solved it", "")
        took = f", in {result.seconds:.1f} s" if result.seconds is not None else ""
        self.fact(f"The L1 engine {self.t(result.engine)} found the flag with no model{took}.")
        self.out("")
        facts = [
            f"- Status: {self.t(result.status)}",
            "- Flags it reported: " + ", ".join(self.t(flag) for flag in result.flags),
            f"- Notes: {self.t(result.notes) if result.notes else 'none'}",
        ]
        if result.evidence:
            facts += [f"- Evidence: {self.t(item)}" for item in result.evidence]
        else:
            facts.append("- Evidence: the run log keeps the engine's notes, not its evidence list")
        if self.solve.lane:
            facts.append(self._reported(self.solve.lane))
        self.fact(*facts)
        self.out("")
        others = [run for run in self.solve.l1_runs if run is not result]
        if others:
            self.out("Other L1 engines that ran on it:", "")
            self.fact(*(f"- {self.t(run.engine)}, {self.t(run.status)}" + (f": {self.t(run.notes)}" if run.notes else "")
                        for run in others))
            self.out("")

    def _reported(self, lane_id: str) -> str:
        """How the L1 flag went from the lane it was reported on to the board: what the
        lane's transcript says the player did with it (core/deck.py's wording)."""
        where, flag = f"lane {self.t(lane_id)}", self.solve.flag
        if self.lane is None:
            return f"- Reported on {where}, whose transcript is missing, so whether you approved it is not known"
        said = {a.text for a in self.lane.actions if a.by == "player"}
        if flag and f"{APPROVED}submit {flag}" in said:
            return f"- Reported on {where}, where you approved it"
        if flag and f"{APPROVED}did the platform accept {flag}? (you submit it)" in said:
            return f"- Reported on {where}, where you submitted it by hand and said the platform accepted it"
        if self.solve.judged_by == "platform":
            return f"- Reported on {where} and submitted at once, with no approval asked (submit is set to auto)"
        return f"- Reported on {where}"

    # ------------------------------------------------------------ the flag and the log's gaps

    def _flag(self) -> None:
        solve = self.solve
        self.out("## Flag", "")
        if not solve.flag:
            self.fact("The run log does not hold the accepted flag.")
            self.out("")
        else:
            self.block(solve.flag)
            if self.redact:
                self.fact(f"Redacted: {self.ours(REDACTED)} stands for the flag wherever the run's text held it: whole, "
                          "cut short, with characters folded, or the part inside its braces. A copy a tool encoded or "
                          "split over lines is not found, so read the draft before you publish it.")
                self.out("")
        where = f" on lane {self.t(solve.lane)}" if solve.lane else ""
        how = {"platform": ": the board checked it", "player": ": you said the platform accepted it"}.get(solve.judged_by, "")
        self.fact(f"Accepted at {fmt.clock(solve.at)}{where}{how}.")
        self.out("")

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
"block" in its id stands for a code block, and one with "line" in its id for a whole line
that states a fact.

Rules:
- Keep every placeholder exactly as written, once each. A block or line placeholder stays
  alone on its line, and those stay in the order they are in.
- Put a space, or the start or end of a line, on each side of a placeholder. Only "(" may
  come right before one, and only , . : ; ) or ' right after one.
- Only reword the prose around the placeholders: join list items into sentences, fix the
  grammar, keep the headings.
- Never add a fact: no name, number, tool, step, cause or result that the draft does not
  state. Keep every number as written, in the order it comes.
- No links, no web addresses or domains, no file names, no word with a dot inside it (not
  even e.g.), no images, no HTML, no code, no backticks, no square brackets.
- Answer with the Markdown only.
"""

_TOKEN = re.compile(r"\{\{[0-9a-f]{8}-(?:block-|line-)?\d+\}\}")
_HTML = re.compile(r"<[A-Za-z/!?]|&#?[A-Za-z0-9]+;")
_FENCE = re.compile(r"^ {0,3}~{3,}", re.MULTILINE)
_ADDRESS = re.compile(r"://|\bwww\.|@\w", re.IGNORECASE)
_DOTTED = re.compile(r"[A-Za-z0-9]\.[A-Za-z]")  # a domain ("evil.com") or a file name: a renderer may link it
_DIGITS = re.compile(r"\d+")
_LIST_NUMBER = re.compile(r"^[ \t]*\d+[.)](?=[ \t]|$)", re.MULTILINE)
_WRAPPED = re.compile(r"```[A-Za-z]*\n(.*)\n```", re.DOTALL)
_AFTER = frozenset(",.:;)'")  # what may come right after a placeholder, besides a space or a line's end
_REFUSED = (
    (re.compile("`"), "code (a backtick)"),
    (_FENCE, "a code block"),
    (_HTML, "HTML or an HTML entity"),
    (re.compile(r"[\[\]]"), "a link or an image (a square bracket)"),
    (_ADDRESS, "a web address, an email address or a mention"),
    (_DOTTED, "a domain or a file name (a dot inside a word)"),
    (re.compile(r"\{\{|\}\}"), "a changed placeholder"),
)


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
    """The draft with its prose tidied by `model`. The model sees our connecting words and
    placeholders only, never a value from the run nor a line of ours that states a fact.
    PolishError when its reply fails a check; ModelError (agent.client) when the call fails."""
    held: dict[str, str] = {}
    writer = _Writer(record, _solve(record, challenge_id), board=board, redact=redact, held=held)
    frozen = writer.markdown()
    messages = [
        {"role": "system", "content": POLISH_INSTRUCTIONS},
        {"role": "user", "content": frozen},
    ]
    reply = await client.chat(model, messages, [], session_id=f"flightdeck-writeup-{secrets.token_hex(8)}")
    try:
        checked = checked_reply(reply.content, frozen, held, writer.alone)
    except PolishError as refused:
        refused.usage = reply.usage
        raise
    return Polished(thaw(checked, held, writer.alone), reply.usage)


def checked_reply(reply: str, frozen: str, held: Mapping[str, str], alone: Sequence[str]) -> str:
    """The model's reply, folded, once it passes every check; PolishError naming the first it
    fails. `alone` are the placeholders that stand for a whole line (blocks and our lines that
    state facts), in the draft's order."""
    text = _fold(reply.replace("\r\n", "\n")).strip("\n")
    wrapped = _WRAPPED.fullmatch(text.strip())
    if wrapped:  # the whole answer in one ```markdown block, as models like to send it; the inside is checked
        text = wrapped.group(1)
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
    for key in alone:
        if next(line for line in lines if key in line).strip() != key:
            what = "a code block" if "-block-" in key else "a line that states a fact"
            raise PolishError(f"the reply moved {what} into a line of prose")
    whole = set(alone)
    if [line.strip() for line in lines if line.strip() in whole] != list(alone):
        raise PolishError("the reply changed the order of the code blocks and the lines that state facts")
    for match in _TOKEN.finditer(text):
        before = text[match.start() - 1] if match.start() > 0 else "\n"
        after = text[match.end()] if match.end() < len(text) else "\n"
        if not (before.isspace() or before == "(") or not (after.isspace() or after in _AFTER):
            raise PolishError("the reply puts text right against a placeholder, where it could build markup around it")
    ours, prose = _TOKEN.sub(" ", frozen), _TOKEN.sub(" ", text)
    for version in (prose, _TOKEN.sub("x", text)):  # a value is never a space: see what it may run into
        for pattern, what in _REFUSED:
            if pattern.search(version):
                raise PolishError(f"the reply adds {what}")
    found, wanted = _numbers(prose), _numbers(ours)
    if found != wanted:
        at = next((i for i, (a, b) in enumerate(zip(found, wanted)) if a != b), min(len(found), len(wanted)))
        has = found[at] if at < len(found) else "none"
        had = wanted[at] if at < len(wanted) else "none"
        raise PolishError(f"the reply does not keep the draft's numbers as written and in order: number {at + 1} "
                          f"is {has} where the draft has {had}")
    if len(prose) > 2 * len(ours) + 500:
        raise PolishError(f"the reply is {len(prose)} characters of prose against the draft's {len(ours)}")
    return text


def _numbers(prose: str) -> list[str]:
    """The numbers in prose, in order, but those that number a list (a reply may join a list
    into sentences, or make one)."""
    return _DIGITS.findall(_LIST_NUMBER.sub("", prose))


def thaw(text: str, held: Mapping[str, str], alone: Iterable[str]) -> str:
    """Put every placeholder's Markdown back. One that stands for a whole line takes it; a
    block also gets blank lines around it, and comes back exactly as it was (blank lines
    inside it included)."""
    whole = set(alone)
    out: list[str] = []
    for line in text.split("\n"):
        key = line.strip()
        if key in whole:
            block = "-block-" in key
            if block and out and out[-1].strip():
                out.append("")
            out.append(held[key])
            if block:
                out.append("")
            continue
        if not line.strip() and out and not out[-1].strip():
            continue  # one blank line is enough between paragraphs
        out.append(_TOKEN.sub(lambda m: held[m.group()], line))
    return "\n".join(out).strip("\n") + "\n"
