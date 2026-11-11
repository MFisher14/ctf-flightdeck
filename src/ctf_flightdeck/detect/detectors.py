"""The rules-first detectors for the five course alerts.

Each detector reads one lane and its challenge and returns a Signal when its alert holds
now, else None. They never change anything; the Watch raises and clears alerts through the
deck. Every reason names the numbers or commands it used, so the player can check it. All
lane and challenge text is untrusted: it is matched against flightdeck's own rules and word
lists only, and anything quoted back is folded to one short line.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from .. import fmt
from ..core.model import ActionKind, AlertKind, Challenge, Lane
from .base import DetectConfig, Detector, Signal, quote, steps, suggestions
from .hints import Hinted, Lexicon, lexicon

# ---------------------------------------------------------------------- shared helpers

_DIGITS = re.compile(r"\d+")
_WS = re.compile(r"\s+")
_MORE = re.compile(r"\s+\(\+\d+ more\)\s*$")  # the agent driver's "  (+N more)" step suffix

SOURCE_EXTENSIONS = (".py", ".js", ".ts", ".php", ".go", ".rb", ".java", ".rs")
SOURCE_NAMES = ("dockerfile", "package.json", "requirements.txt")

SCANNERS = ("ffuf", "gobuster", "dirb", "dirsearch", "feroxbuster", "wfuzz", "hydra")
READ_VERBS = ("cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg",
              "bat", "view", "vi", "vim", "nano", "sed", "awk", "strings", "open")


def command_of(text: str) -> str | None:
    """The shell command in a step's text ('$ ...'), without the driver's '(+N more)' tail."""
    if not text.startswith("$ "):
        return None
    return _MORE.sub("", text[2:]).strip() or None


def is_source_name(name: str) -> bool:
    low = name.lower()
    base = low.rsplit("/", 1)[-1]
    return base in SOURCE_NAMES or base.startswith("dockerfile") or low.endswith(SOURCE_EXTENSIONS)


def source_files(challenge: Challenge) -> tuple[str, ...]:
    return tuple(f for f in challenge.files if is_source_name(f))


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

    def named(self, challenge: Challenge) -> list[Hinted]:
        return self.lexicon.named_in(challenge.description)

    def following(self, lane: Lane, named: Sequence[Hinted]) -> Hinted | None:
        """A hinted technique the lane shows an action cue for, in its recent steps or plan."""
        window = steps(lane, self.config.hint_window)
        texts = [lane.plan] + [a.text for a in window] + [a.output for a in window]
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
            f"The description points at {technique.name} ({words}), but none of the lane's last "
            f"{self.config.hint_window} steps or its plan uses it (after {lane.turns} turns)."
        )
        return Signal(
            self.kind,
            reason,
            suggestions(
                ("r", "Redirect with the hinted technique", f"Follow the description's hint: {technique.advice}"),
                ("h", "Hint", f"The description points at {technique.name}."),
            ),
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
    def reads_source(text: str) -> bool:
        if text.startswith("read "):  # the read_file tool
            return is_source_name(text[5:].strip())
        command = command_of(text)
        if command is None:
            return False
        tokens = command.split()
        if not tokens:
            return False
        verb = tokens[0].rsplit("/", 1)[-1]
        if verb not in READ_VERBS:
            return False
        return any(is_source_name(token) for token in tokens[1:])

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        if challenge.category.strip().lower() != "web":
            return None
        source = source_files(challenge)
        if not source:
            return None
        all_steps = steps(lane)
        if any(self.reads_source(a.text) for a in all_steps):
            return None
        window = all_steps[-self.config.direction_window:]
        fuzzed = [command_of(a.text) for a in window]
        fuzzed = [c for c in fuzzed if c and self.is_fuzz(c)]
        if len(fuzzed) < self.config.direction_min_fuzz:
            return None
        shown = "; ".join(quote(c, 40) for c in fuzzed[:3])
        reason = (
            f"{len(fuzzed)} fuzzing/brute-force commands in the last {len(window)} steps ({shown}) "
            f"while the source in the handout ({', '.join(source)}) has not been read."
        )
        return Signal(
            self.kind,
            reason,
            suggestions(
                ("r", "Redirect: read the source", "Read the source in the handout before attacking the instance."),
                ("f", "Fork with a source-first approach", "Read the source first"),
            ),
        )


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
        window = steps(lane, self.config.loop_window)
        commands: dict[str, tuple[int, str]] = {}
        for action in window:
            key = self.normalize(action.text)
            if not key:
                continue
            count, _ = commands.get(key, (0, action.text))
            commands[key] = (count + 1, action.text)
        for count, original in commands.values():
            if count >= self.config.loop_same_command:
                command = command_of(original) or original
                reason = f"The same command ran {count} times in the last {len(window)} steps: {quote(command)}."
                return Signal(
                    self.kind,
                    reason,
                    suggestions(
                        ("h", "Hint", f"You are repeating {quote(command, 60)}: it gives the same result. Try something else."),
                        ("k", "Kill and re-queue fresh"),
                    ),
                )
        outputs: dict[str, int] = {}
        cut = self.config.loop_output_chars
        for action in window:
            if not action.output:
                continue
            key = action.output[:cut]
            outputs[key] = outputs.get(key, 0) + 1
        for key, count in outputs.items():
            if count >= self.config.loop_same_output:
                reason = f"The same output came back {count} times in the last {len(window)} steps: {quote(key)}."
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


def candidate_count(lane: Lane) -> int:
    return sum(1 for a in lane.actions if a.kind is ActionKind.NOTE and a.text.startswith("candidate flag "))


def last_file_turn(lane: Lane) -> int:
    return max((f.turn for f in lane.files.values()), default=0)


class StallDetector:
    """No new file, artifact, plan or candidate flag for stall_turns turns.

    File changes carry a turn, so they are read straight from the lane. Artifacts, the plan
    and the candidate count are not turn-stamped, so this detector remembers them per lane
    and dates a change to the turn it first sees it. The Watch keeps one instance for the
    run, so the memory spans the lane's life; a freshly constructed lane with no memory
    falls back to its turn-stamped evidence (file changes), which is enough to test.
    """

    kind = AlertKind.STALL

    def __init__(self, config: DetectConfig) -> None:
        self.config = config
        self._seen: dict[str, tuple[tuple[int, str, int], int]] = {}  # lane id -> (fingerprint, progress turn)

    @staticmethod
    def _fingerprint(lane: Lane) -> tuple[int, str, int]:
        return (len(lane.artifacts), lane.plan, candidate_count(lane))

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        fingerprint = self._fingerprint(lane)
        floor = last_file_turn(lane)
        remembered = self._seen.get(lane.id)
        if remembered is None or remembered[0] != fingerprint:
            progress = max(floor, lane.turns if remembered is not None else floor)
            self._seen[lane.id] = (fingerprint, progress)
        else:
            progress = max(remembered[1], floor)
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
