"""The rules-first detectors for the five course alerts.

Each detector reads one lane and its challenge and returns a Signal when its alert holds
now, else None. They never change anything; the Watch raises and clears alerts through the
deck. Every reason names the numbers or commands it used, so the player can check it. All
lane and challenge text is untrusted: it is matched against flightdeck's own rules and word
lists only, and anything quoted back is folded to one short line.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Sequence

from .. import fmt
from ..core.model import ActionKind, Actor, AlertKind, Challenge, Lane
from .base import DetectConfig, Detector, Signal, quote, steps, suggestions
from .hints import Hinted, Lexicon, lexicon, normalize

# ---------------------------------------------------------------------- shared helpers

_DIGITS = re.compile(r"\d+")
_WS = re.compile(r"\s+")
_MORE = re.compile(r"\s+\(\+\d+ more\)\s*$")  # the agent driver's "  (+N more)" step suffix

SOURCE_EXTENSIONS = (".py", ".js", ".ts", ".php", ".go", ".rb", ".java", ".rs")
SOURCE_NAMES = ("dockerfile", "package.json", "requirements.txt")
SHOWN_SOURCES = 5  # source file names a DIRECTION reason names; the rest are counted

SCANNERS = ("ffuf", "gobuster", "dirb", "dirsearch", "feroxbuster", "wfuzz", "hydra")
READ_VERBS = frozenset({
    "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag", "ack",
    "bat", "batcat", "view", "vi", "vim", "nvim", "nano", "sed", "awk", "strings", "open",
    "nl", "xxd", "od", "hexdump", "jq",
})
SEARCHERS = frozenset({"rg", "ag", "ack"})  # recursive by default
GREPS = frozenset({"grep", "egrep", "fgrep"})  # recursive with -r / -R
WRAPPERS = frozenset({"sudo", "env", "time", "command", "builtin", "exec", "nohup", "nice", "xargs", "timeout"})
WORKSPACE_DIRS = frozenset({"", ".", "*", "/work", "~", "$pwd", "${pwd}"})  # where the handout is, for a recursive search
_ARG_OPTIONS = frozenset({  # search options that take the next word as their argument
    "-e", "-f", "-m", "-A", "-B", "-C", "-g", "-t", "-T", "--regexp", "--file", "--max-count",
    "--glob", "--type", "--include", "--exclude", "--exclude-dir",
})
_PATTERN_OPTIONS = frozenset({"-e", "-f", "--regexp", "--file"})
_SHELL_OPERATORS = set("();<>|&")
_LINE_BREAK = re.compile("[\n⏎]")  # a newline, or how untrusted() folds one in a step's text
_FALLBACK_TOKENS = re.compile(r"[();<>|&]+|[^\s();<>|&]+")

# What the real Toolbox reports for a command that printed nothing (agent/tools.py _brief and
# read_file): "(no output)", "exit 1 · (no output)", "empty file". Saying nothing is no output.
_STATUS = re.compile(r"(?:exit -?\d+|timed out after [\d.]+s|killed) · ")
_NOTHING = frozenset({"", "(no output)", "empty file", "(empty file)", "(empty body)"})


def command_of(text: str) -> str | None:
    """The shell command in a step's text ('$ ...'), without the driver's '(+N more)' tail."""
    if not text.startswith("$ "):
        return None
    return _MORE.sub("", text[2:]).strip() or None


def has_output(output: str) -> bool:
    """Whether a step's output says anything: a status with "(no output)" says nothing."""
    text = output.strip()
    status = _STATUS.match(text)
    if status is not None:
        text = text[status.end():].strip()
    return text not in _NOTHING


def is_source_name(name: str) -> bool:
    low = name.lower()
    base = low.rsplit("/", 1)[-1]
    return base in SOURCE_NAMES or base.startswith("dockerfile") or low.endswith(SOURCE_EXTENSIONS)


def source_files(challenge: Challenge) -> tuple[str, ...]:
    return tuple(f for f in challenge.files if is_source_name(f))


def is_web(challenge: Challenge) -> bool:
    """Whether the challenge's category is web ("web", "Web Exploitation", "web/pwn")."""
    return "web" in normalize(challenge.category).split()


def simple_commands(command: str) -> list[list[str]]:
    """The words of each simple command in a shell command line: split at newlines and at
    the operators && || ; | & ( ), quotes removed. An output redirect's target is dropped;
    an input redirect's file stays (it is read)."""
    out: list[list[str]] = []
    for line in _LINE_BREAK.split(command):
        current: list[str] = []
        skip = False
        for token in _shell_tokens(line):
            if skip:
                skip = False
                continue
            if token and set(token) <= _SHELL_OPERATORS:
                if ">" in token:
                    skip = True  # an output redirect: its target is written, not read
                elif "<" not in token and current:
                    out.append(current)
                    current = []
                continue
            current.append(token)
        if current:
            out.append(current)
    return out


def _shell_tokens(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:  # an unbalanced quote: split by hand
        return [token.strip("'\"") for token in _FALLBACK_TOKENS.findall(line)]


def _verb_and_args(words: list[str]) -> tuple[str, list[str]]:
    """The command a simple command runs and its arguments, past VAR=value assignments and
    wrappers such as sudo, env, time and xargs."""
    i = 0
    while i < len(words):
        word = words[i]
        name = word.rsplit("/", 1)[-1]
        if "=" in word and not word.startswith("-") and word.split("=", 1)[0].isidentifier():
            i += 1
        elif name in WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-"):
                i += 1
            if name == "timeout" and i < len(words):
                i += 1  # its duration
        else:
            return name, words[i + 1:]
    return "", []


# ---------------------------------------------------------------------- effort vs value


class EffortDetector:
    kind = AlertKind.EFFORT

    def __init__(self, config: DetectConfig) -> None:
        self.config = config

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        cfg = self.config
        points, solves = challenge.points, challenge.solves
        budget_tokens = cfg.effort_tokens(points, solves)
        budget_turns = cfg.effort_turns(points, solves)
        over_tokens = lane.tokens >= budget_tokens
        over_turns = lane.turns >= budget_turns
        if not (over_tokens or over_turns):
            return None
        hit = []
        if over_turns:
            hit.append(f"{lane.turns} turns (budget {budget_turns})")
        if over_tokens:
            hit.append(f"{fmt.tokens(lane.tokens)} tokens (budget {fmt.tokens(budget_tokens)})")
        reason = (
            f"{' and '.join(hit)} on a {points}-point challenge with {solves} solves. "
            "The budget shrinks as points fall and solves rise; this is past it, so the work "
            "looks harder than the challenge is."
        )
        return Signal(
            self.kind,
            reason,
            suggestions(
                ("h", "Hint: it is simpler than this",
                 f"This is a {points}-point challenge with {solves} solves: look for the simple path first."),
                ("k", "Kill and re-queue fresh"),
            ),
        )


# ---------------------------------------------------------------------- ignores the hint


class HintDetector:
    kind = AlertKind.HINT

    def __init__(self, config: DetectConfig, lex: Lexicon | None = None) -> None:
        self.config = config
        self.lexicon = lex or lexicon()
        self._named: dict[str, tuple[str, list[Hinted]]] = {}  # challenge id -> (description, what it names)

    def named(self, challenge: Challenge) -> list[Hinted]:
        """What the challenge's description hints at, matched once per description."""
        cached = self._named.get(challenge.id)
        if cached is not None and cached[0] == challenge.description:
            return cached[1]
        named = self.lexicon.named_in(challenge.description)
        self._named[challenge.id] = (challenge.description, named)
        return named

    def following(self, lane: Lane, named: Sequence[Hinted]) -> Hinted | None:
        """A hinted technique the lane shows an action cue for, in its steps of the last
        hint_window turns or in its plan. The plan counts only when the model wrote it: a
        redirect makes the player's words the plan (and lane.approach), and the player
        asking for a technique is no sign that the lane uses it."""
        window = steps(lane, self.config.hint_window)
        texts = [a.text for a in window] + [a.output for a in window]
        if lane.plan and lane.plan != lane.approach:
            texts.insert(0, lane.plan)
        for hinted in named:
            if hinted.technique.action_cue(texts) is not None:
                return hinted
        return None

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        if lane.turns <= self.config.hint_grace_turns:
            return None
        named = self.named(challenge)
        if not named:
            return None
        if self.following(lane, named) is not None:
            return None  # the lane is on at least one of the hinted techniques
        top = named[0]
        technique = top.technique
        words = ", ".join(f'"{quote(c, 40)}"' for c in top.cues[:3])
        reason = (
            f"The description points at {technique.name} ({words}), but nothing the lane did in its "
            f"last {self.config.hint_window} turns, nor its plan, uses it (after {lane.turns} turns)."
        )
        return Signal(
            self.kind,
            reason,
            suggestions(
                ("r", "Redirect with the hinted technique", f"Follow the description's hint: {technique.advice}"),
                ("h", "Hint", f"The description points at {technique.name}."),
            ),
            technique=technique,
        )


# ---------------------------------------------------------------------- wrong direction (web)


class DirectionDetector:
    kind = AlertKind.DIRECTION

    def __init__(self, config: DetectConfig) -> None:
        self.config = config

    @staticmethod
    def is_fuzz(command: str) -> bool:
        head = command.lstrip()
        first = head.split(" ", 1)[0].rsplit("/", 1)[-1]
        if first in SCANNERS or any(f" {s} " in f" {head} " for s in SCANNERS):
            return True
        if "sqlmap" in head and not re.search(r"(^|\s)-r(\s|$)", head):
            return True
        if "curl" in head and re.search(r"(^|\s)(for|while|xargs)(\s|$)", head):
            return True
        return False

    @staticmethod
    def reads_source(text: str, sources: Sequence[str] = ()) -> bool:
        """Whether a step reads source code: read_file of a source file, a shell command
        (any simple command of it) that reads, greps or pages one (by name or by a glob that
        takes in the handout's `sources`), a recursive search over a directory that holds
        `sources`, or python that opens a source file."""
        if text.startswith("read "):  # the read_file tool
            return _names_source(text[5:], sources)
        low = text.lower()
        if not _mentions_source(low, sources) and not any(s in low for s in ("grep", "rg", "ag", "ack", "*")):
            return False  # names no source and searches nothing: no need to parse it
        if text.startswith("python: "):  # the python tool: its first line
            return _mentions_source(low, sources) and any(f in low for f in ("open(", "read_text(", "read_bytes("))
        command = command_of(text)
        if command is None:
            return False
        for words in simple_commands(command):
            verb, args = _verb_and_args(words)
            if verb not in READ_VERBS:
                continue
            if any(_names_source(arg, sources) for arg in args if not arg.startswith("-")):
                return True
            if (verb in SEARCHERS or (verb in GREPS and _recursive(args))) and _searches_sources(args, sources):
                return True
        return False

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        if not is_web(challenge):
            return None
        source = source_files(challenge)
        if not source:
            return None
        if any(self.reads_source(a.text, source) for a in steps(lane)):
            return None  # some step, however long ago, read the source
        window = steps(lane, self.config.direction_window)
        fuzzed = [command_of(a.text) for a in window]
        fuzzed = [c for c in fuzzed if c and self.is_fuzz(c)]
        if len(fuzzed) < self.config.direction_min_fuzz:
            return None
        shown = "; ".join(quote(c, 40) for c in fuzzed[:3])
        files = ", ".join(quote(name, 60) for name in source[:SHOWN_SOURCES])
        if len(source) > SHOWN_SOURCES:
            files += f" and {len(source) - SHOWN_SOURCES} more"
        reason = (
            f"{len(fuzzed)} fuzzing/brute-force commands in the last {self.config.direction_window} turns ({shown}) "
            f"while the source in the handout ({files}) has not been read."
        )
        return Signal(
            self.kind,
            reason,
            suggestions(
                ("r", "Redirect: read the source", "Read the source in the handout before attacking the instance."),
                ("f", "Fork with a source-first approach", "Read the source first"),
            ),
        )


def _mentions_source(low: str, sources: Sequence[str]) -> bool:
    """Whether lower-case text mentions a source file: a name of the handout's, or a source
    extension or name anywhere."""
    return (
        any(s.rsplit("/", 1)[-1].lower() in low for s in sources)
        or any(ext in low for ext in SOURCE_EXTENSIONS)
        or any(name in low for name in SOURCE_NAMES)
    )


def _names_source(word: str, sources: Sequence[str]) -> bool:
    """Whether a path names a source file, or a glob (*.py, src/*) takes in one of `sources`."""
    path = word.strip().strip("'\",;)").lower()
    base = path.rstrip("/").rsplit("/", 1)[-1]
    if is_source_name(base):
        return True
    if any(c in path for c in "*?["):
        where = path.removeprefix("./").removeprefix("/work/")
        return any(
            fnmatch.fnmatchcase(s.lower(), where) or fnmatch.fnmatchcase(s.lower().rsplit("/", 1)[-1], base)
            for s in sources
        )
    return False


def _recursive(args: Sequence[str]) -> bool:
    return any(
        a in ("--recursive", "--dereference-recursive")
        or (a.startswith("-") and not a.startswith("--") and ("r" in a[1:] or "R" in a[1:]))
        for a in args
    )


def _searches_sources(args: Sequence[str], sources: Sequence[str]) -> bool:
    """Whether a recursive search's paths (none means the current directory) take in a
    directory that holds the handout's sources."""
    given = False
    paths: list[str] = []
    words = iter(args)
    for word in words:
        if word.startswith("-") and len(word) > 1:
            if word in _PATTERN_OPTIONS:
                given = True
            if word in _ARG_OPTIONS:
                next(words, None)
            continue
        if not given:
            given = True  # the first word that is not an option is the pattern
            continue
        paths.append(word)
    if not paths:
        return True
    for path in paths:
        where = path.strip().lower()
        where = where.removeprefix("./").removeprefix("/work/").rstrip("/")
        if where in WORKSPACE_DIRS or any(s.lower().startswith(f"{where}/") for s in sources):
            return True
    return False


# ---------------------------------------------------------------------- loop


class LoopDetector:
    kind = AlertKind.LOOP

    def __init__(self, config: DetectConfig) -> None:
        self.config = config

    def normalize(self, text: str) -> str:
        command = command_of(text)
        base = command if command is not None else text
        masked = _DIGITS.sub(lambda m: "#" if len(m.group()) >= self.config.loop_digit_run else m.group(), base)
        return _WS.sub(" ", masked).strip()

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        cfg = self.config
        window = steps(lane, cfg.loop_window)
        span = min(cfg.loop_window, lane.turns)
        commands: dict[str, tuple[set[int], str]] = {}  # normalised command -> (turns that ran it, the latest text)
        for action in window:
            key = self.normalize(action.text)
            if not key:
                continue
            turns = commands.get(key, (set(), ""))[0]
            turns.add(action.turn)
            commands[key] = (turns, action.text)
        for turns, original in commands.values():
            if len(turns) >= cfg.loop_same_command:
                command = command_of(original) or original
                reason = f"The same command ran {len(turns)} times in the last {span} turns: {quote(command)}."
                return Signal(
                    self.kind,
                    reason,
                    suggestions(
                        ("h", "Hint", f"You are repeating {quote(command, 60)}: it gives the same result. Try something else."),
                        ("k", "Kill and re-queue fresh"),
                    ),
                )
        outputs: dict[str, set[int]] = {}  # an output's first loop_output_chars -> turns that got it
        for action in window:
            if not has_output(action.output):
                continue  # "(no output)" from four different quiet commands is not a loop
            outputs.setdefault(action.output[: cfg.loop_output_chars], set()).add(action.turn)
        for key, turns in outputs.items():
            if len(turns) >= cfg.loop_same_output:
                reason = f"The same output came back {len(turns)} times in the last {span} turns: {quote(key)}."
                return Signal(
                    self.kind,
                    reason,
                    suggestions(
                        ("h", "Hint", "The last commands keep giving the same output. Try something else."),
                        ("k", "Kill and re-queue fresh"),
                    ),
                )
        return None


# ---------------------------------------------------------------------- stall


CANDIDATE_NOTE = "candidate flag "  # the deck's note for a new candidate (core/deck.py _candidate)


def last_candidate_turn(lane: Lane) -> int:
    """The turn of the lane's newest candidate flag, from the deck's own notes (a lane's
    steps, which a model writes, never count); 0 if none."""
    return max(
        (a.turn for a in lane.actions
         if a.kind is ActionKind.NOTE and a.by is Actor.DECK and a.text.startswith(CANDIDATE_NOTE)),
        default=0,
    )


def last_file_turn(lane: Lane) -> int:
    return max((f.turn for f in lane.files.values()), default=0)


class StallDetector:
    """No new file, artifact, plan or candidate flag for stall_turns turns.

    File changes and the deck's candidate-flag notes carry their turn, so they are read
    straight from the lane: a candidate the deck notes after the turn's event is still dated
    to its own turn. Artifacts and the plan carry no turn, so this detector remembers them
    per lane and dates a change to the turn it first sees it; the Watch checks every turn,
    so that is the turn they changed. On its first look at a lane it dates a plan or an
    artifact it finds to that turn too (they may be older; it cannot know, so it never calls
    a lane stalled early). The Watch keeps one instance for the run, so the memory spans the
    lane's life.
    """

    kind = AlertKind.STALL

    def __init__(self, config: DetectConfig) -> None:
        self.config = config
        self._seen: dict[str, tuple[tuple[int, str], int]] = {}  # lane id -> (fingerprint, progress turn)

    @staticmethod
    def _fingerprint(lane: Lane) -> tuple[int, str]:
        return (len(lane.artifacts), lane.plan)

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        fingerprint = self._fingerprint(lane)
        floor = max(last_file_turn(lane), last_candidate_turn(lane))
        remembered = self._seen.get(lane.id)
        if remembered is None:
            progress = lane.turns if fingerprint != (0, "") else floor
        elif remembered[0] != fingerprint:
            progress = lane.turns
        else:
            progress = remembered[1]
        progress = max(progress, floor)
        self._seen[lane.id] = (fingerprint, progress)
        idle = lane.turns - progress
        if idle < self.config.stall_turns:
            return None
        last = quote(lane.artifacts[-1]) if lane.artifacts else "none"
        reason = (
            f"No new file, artifact, plan or candidate flag for {idle} turns "
            f"(now turn {lane.turns}; the last new finding was at turn {progress}, last artifact: {last})."
        )
        return Signal(
            self.kind,
            reason,
            suggestions(
                ("e", "Escalate to a stronger model with a summary"),
                ("r", "Redirect with a new approach"),
            ),
        )

    def forget(self, lane_id: str) -> None:
        self._seen.pop(lane_id, None)


# ---------------------------------------------------------------------- the default set


def default_detectors(config: DetectConfig | None = None) -> list[Detector]:
    """Every course detector, in attention order (hint and direction before loop and stall)."""
    cfg = config or DetectConfig()
    return [
        EffortDetector(cfg),
        HintDetector(cfg),
        DirectionDetector(cfg),
        LoopDetector(cfg),
        StallDetector(cfg),
    ]
