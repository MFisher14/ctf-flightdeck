"""Slash commands for the command bar.

The same commands work in both views: in the fleet view they act on the selected lane
(or on a lane named first, `/kill L07`), in the focus view on the open lane. Plain
text with no slash is a message to the lane; it goes into the lane's next turn.

Two rules, kept apart (P62). The menu is loose: `complete` lists a command from the start
of its name, of an alias or of a word inside its name, and then the words the command
takes. What runs is strict: `parse` takes a whole name or a whole alias and nothing
nearer, and a word it does not know is refused, never guessed at.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum

from ..config import LAYOUTS
from ..core.attention import SortMode

LANE_ID = re.compile(r"^[Ll](\d+)$")


@dataclass(frozen=True)
class Word:
    """One thing a command takes after its name, as the menu offers it."""

    text: str  # what goes into the bar
    help: str = ""
    name: str = ""  # what else it is called (a lane's challenge, a challenge's name): typing that finds it too


@dataclass(frozen=True)
class State:
    """What the console has now, for the words that depend on it (FlightdeckApp.command_state)."""

    lanes: tuple[Word, ...] = ()  # every lane, by id
    queueable: tuple[Word, ...] = ()  # the challenges /queue is for: parked and new
    themes: tuple[Word, ...] = ()  # built in, then the player's own
    layout: str = ""  # the layout in use


LAYOUT_HELP = {"simple": "the lanes and what needs you", "deck": "the board and every column"}
SORT_HELP = {
    SortMode.ATTENTION: "what needs you first",
    SortMode.IDLE: "longest idle first",
    SortMode.COST: "most spent first",
    SortMode.TURNS: "most turns first",
    SortMode.LANE: "by lane number",
}


# What /copy takes, with the menu's words for each; alone it is the first (views.lane_copy).
COPY_HELP = {
    "output": "the last output (also /copy alone)",
    "command": "that call's command, to paste in a shell",
    "flag": "the flag that waits for you, else the newest",
    "all": "the whole transcript, every line",
}
COPY_WHAT = tuple(COPY_HELP)


def _copies(state: State) -> tuple[Word, ...]:
    return tuple(Word(what, help) for what, help in COPY_HELP.items())


def _layouts(state: State) -> tuple[Word, ...]:
    return tuple(Word(name, LAYOUT_HELP[name] + (" (in use)" if name == state.layout else "")) for name in LAYOUTS)


def _sorts(state: State) -> tuple[Word, ...]:
    return tuple(Word(mode.value, SORT_HELP[mode]) for mode in SortMode)


def _on_off(state: State) -> tuple[Word, ...]:
    return (Word("on", "engage autopilot (it needs a run budget)"), Word("off", "take the controls back"))


@dataclass(frozen=True)
class Command:
    name: str
    args: str
    help: str
    lane: bool = True  # acts on a lane
    aliases: tuple[str, ...] = ()  # other names parse takes for it, whole
    words: Callable[[State], Sequence[Word]] | None = None  # what the menu offers after its name


COMMANDS = (
    Command("hint", "<text>", "message the lane; it reads it on its next turn"),
    Command("redirect", "<plan>", "replace the lane's plan"),
    Command("fork", "[approach]", "a sibling lane on another model"),
    Command("kill", "[park]", "end the lane: re-queue it fresh, or park it"),
    Command("approve", "[all]", "approve what the lane waits for; all: every flag that waits for a plain yes, after a prompt that lists them"),
    Command("decline", "", "say no: not submitted, or off the box (the lane carries on); no more budget (it stops)"),
    Command("dismiss", "", "take down the lane's alert about its course: you judge it wrong; it stays quiet as an answered one does"),
    Command("escalate", "", "hand a summary to a stronger model"),
    Command("pause", "", "pause or resume the lane"),
    Command("takeover", "", "a shell in the lane's workspace; exit it to hand the lane back"),
    Command("diff", "[file]", "show the files the lane changed"),
    Command("copy", "[output|command|flag|all]", "copy from the lane with no mouse: its last output, that call's command, its flag, or all",
            words=_copies),
    Command("open", "<lane>", "open a lane in the focus view", words=lambda state: state.lanes),
    Command("note", "<text>", "a note for every lane: running ones read it on their next turn, later ones at their start", lane=False),
    Command("settings", "", "your setup and its health: the config, the key, the models, and doctor's checks; "
                           "c there changes this run's", lane=False),
    Command("config", "[lanes N|unlimited | submit auto|confirm | file]", "this run's settings: lanes at once, auto approve (submit auto)", lane=False),
    Command("theme", "[name]", "the console's colours; alone: try the themes you have, and save one", lane=False,
            words=lambda state: state.themes),
    Command("layout", "[simple|deck]", "simple: the lanes and what needs you; deck: the board and every column; alone: try both, and save one",
            lane=False, words=_layouts),
    Command("details", "", "in a lane's view: every line and every alert, or the calm view (ctrl+o)", lane=False),
    Command("new", "[name]", "hand a challenge to a lane: its name, text, files and address", lane=False),
    Command("attach", "[challenge] <files>", "add files to a challenge (drag them here, or none to choose); its lane restarts", lane=False),
    Command("queue", "<challenge>", "queue a parked or new challenge", lane=False, words=lambda state: state.queueable),
    Command("unhold", "", "lift the hold on the queue once its cause is fixed (a key or model id changed in "
                          "your config needs a new run)", lane=False),
    Command("autopilot", "[on|off]", "engage autopilot (it needs a run budget), or take the controls back", lane=False, words=_on_off),
    Command("claim", "[challenge]", "team mode: claim or release a challenge", lane=False),
    Command("filter", "[words]", "filter the lane list", lane=False),
    Command("sort", "[mode]", "sort lanes: attention, idle, cost, turns, lane", lane=False, words=_sorts),
    Command("back", "", "back to the fleet", lane=False, aliases=("lanes",)),
    Command("help", "", "keys and commands", lane=False),
    Command("quit", "", "quit flightdeck (asks first while lanes are open)", lane=False, aliases=("q", "exit")),
)
BY_NAME = {command.name: command for command in COMMANDS}


def by_alias(commands: Iterable[Command]) -> dict[str, Command]:
    """Each alias and the command it names. An alias that is a command's name, or two commands'
    alias, is a mistake in the table above: said here, when the module loads."""
    commands = tuple(commands)
    names = {command.name for command in commands}
    out: dict[str, Command] = {}
    for command in commands:
        for alias in command.aliases:
            if alias in names or alias in out:
                raise ValueError(f"/{alias} cannot be an alias of /{command.name}: it already names a command")
            out[alias] = command
    return out


BY_ALIAS = by_alias(COMMANDS)
# A name made of two words is also found from its second: /over lists /takeover.
SECOND_WORD = {"takeover": "over", "unhold": "hold", "autopilot": "pilot", "redirect": "direct"}


def find(name: str) -> Command | None:
    """The command `name` names, whole: its name or one of its aliases, in any case."""
    name = name.lower()
    return BY_NAME.get(name) or BY_ALIAS.get(name)


def also(command: Command) -> str:
    """A command's aliases as the menu and the help show them: '/q, /exit'."""
    return ", ".join(f"/{alias}" for alias in command.aliases)


# With no lane to act on, the menu lists these first: what can work now.
NO_LANE_FIRST = ("new", "help", "config", "queue")

# Alert suggestions name a key; in the command bar they become these commands.
KEY_COMMAND = {
    "h": "hint",
    "r": "redirect",
    "f": "fork",
    "k": "kill",
    "e": "escalate",
    "a": "approve",
    "d": "decline",
    "x": "dismiss",
    "p": "pause",
    "t": "takeover",
}


class CommandError(ValueError):
    """The text starts with a slash but is not a known command, or its arguments do not fit."""


@dataclass(frozen=True)
class Parsed:
    command: Command | None  # None: a plain message to the lane
    lane: str | None  # a lane named in the command, e.g. "L07"
    arg: str  # everything after the command (and lane)


ALL = "all"  # /approve all: every waiting flag, not one lane's approval


def needs_lane(parsed: Parsed) -> bool:
    """Whether what was typed acts on a lane: a plain message, or a lane command (but not
    /approve all, which goes over every lane)."""
    if parsed.command is None:
        return True
    return parsed.command.lane and not (parsed.command.name == "approve" and parsed.arg == ALL)


class Ask(Enum):
    """What the text typed asks of the lane it goes to: which lanes still take it (Aim.ask)."""

    TURN = "turn"  # a message, /hint, /redirect, /escalate: read on the lane's next turn, so it must have one to come
    ACT = "act"  # /kill, /approve, /pause, a bare /fork (its prompt) and the rest: the lane must still be open
    FORK = "fork"  # /fork with its approach: also a lane that ended without the flag (a sibling takes up its challenge)
    READ = "read"  # /open, /diff, /copy: any lane, ended or not: they ask nothing of it


ASKS_A_TURN = frozenset({"hint", "redirect", "escalate"})
READS = frozenset({"open", "diff", "copy"})


def ask(parsed: Parsed) -> Ask:
    """What `parsed`, a plain message or a lane command, asks of its lane."""
    if parsed.command is None or parsed.command.name in ASKS_A_TURN:
        return Ask.TURN
    if parsed.command.name in READS:
        return Ask.READ
    return Ask.FORK if parsed.command.name == "fork" and parsed.arg else Ask.ACT


@dataclass(frozen=True)
class Aim:
    """Where what is typed would go if it were sent now (goes_to)."""

    run: bool = False  # a command that takes no lane: it is the run's
    lane: str | None = None  # the lane the command names; None: the lane the bar acts on
    ask: Ask = Ask.TURN  # what it asks of that lane (nothing typed is a message not written yet)


def goes_to(typed: str) -> Aim:
    """Where the text typed so far would go: read by `parse`, so it is what enter would do.
    A command that takes no lane (/note, /config, /approve all) is the run's; a lane command
    that names a lane (`/kill L07`) goes to that one; everything else goes to the lane the
    bar acts on: a plain message, a lane command that names none, and text `parse` refuses
    (a name not typed whole yet, a stray word), which goes nowhere until it is put right.
    What goes to a lane also says what it asks of it (Ask): a lane that has ended, or one
    that takes no more turns, refuses some of it."""
    try:
        parsed = parse(typed)
    except CommandError:
        return Aim()
    return Aim(lane=parsed.lane, ask=ask(parsed)) if needs_lane(parsed) else Aim(run=True)


def lane_id(token: str) -> str | None:
    """'l7' or 'L07' -> 'L07'; anything else -> None."""
    match = LANE_ID.match(token)
    return f"L{int(match.group(1)):02d}" if match else None


def parse(text: str) -> Parsed:
    text = text.strip()
    if not text.startswith("/"):
        return Parsed(None, None, text)
    head, _, rest = text[1:].partition(" ")
    command = find(head)  # whole, or not at all: the menu's loose matching stops here
    if not head:  # `/` alone, sent once its list was closed: "unknown command /, type /" would send the player round
        raise CommandError("/ alone is no command: type a command's name after it, the list shows them; esc clears the bar")
    if command is None:
        raise CommandError(f"Unknown command /{head}: type / to see the list")
    rest = rest.strip()
    first, _, tail = rest.partition(" ")
    named = lane_id(first) if command.lane else None
    arg = tail.strip() if named is not None else rest
    if command.name == "approve" and arg.lower() == ALL:
        if named is not None:
            raise CommandError("/approve all names no lane: it approves every flag that waits for a plain yes")
        return Parsed(command, None, ALL)
    if arg and (not command.args or command.name == "approve"):
        # a stray word must not fall back to the selected lane: /approve 2 is not L02
        where = f"; name a lane like /{command.name} L02" if command.lane else ""
        where += " (or /approve all)" if command.name == "approve" else ""
        if command.name == "settings":  # it was /config's alias until P90: say where the run's settings went
            where = f": /config {arg} changes this run's" if arg.split()[0].lower() in ("lanes", "submit", "file") else ""
        raise CommandError(f"/{command.name} takes no argument{where}")
    if arg and command.name == "open":
        raise CommandError("/open takes a lane, like /open L02")
    return Parsed(command, named, arg)


@dataclass(frozen=True)
class Completion:
    text: str  # what tab puts in the bar
    label: str  # what the menu shows
    help: str
    suggested: bool = False
    also: str = ""  # the command's aliases, shown beside its name


def _name_rank(command: Command, typed: str) -> int | None:
    """How `typed` (lower case, no slash) finds a command, best first: 0 it is its name or an
    alias, whole; 1 its name starts with it; 2 an alias does; 3 the second word of its name
    does. None: it does not."""
    if typed == command.name or typed in command.aliases:
        return 0
    if command.name.startswith(typed):
        return 1
    if any(alias.startswith(typed) for alias in command.aliases):
        return 2
    second = SECOND_WORD.get(command.name)
    if second is not None and second.startswith(typed):
        return 3
    return None


def _word_rank(word: Word, typed: str) -> int | None:
    """How `typed` (lower case) finds a word: 0 the word starts with it, or it is the lane id
    the word is ('l1' is L01); 1 a word of its other name does. None: it does not."""
    if word.text.lower().startswith(typed) or lane_id(typed) == word.text:
        return 0
    if word.name and f" {typed}" in f" {' '.join(word.name.lower().split())}":
        return 1
    return None


def complete(typed: str, suggestions: tuple[tuple[str, str], ...] = (), *, lane: bool = True,
             state: Callable[[], State] | None = None) -> list[Completion]:
    """Menu entries for the text typed so far.

    `suggestions` are full commands taken from the lane's alerts, as (command, why);
    they come first while they still match what is typed. `lane`: whether there is a lane
    to act on; with none, the commands that need none come first (NO_LANE_FIRST), then
    the rest in their usual order.

    While the name is typed, a command is listed when its name, an alias or the second word
    of its name starts with what is typed (_name_rank; the nearest first). After the name
    and a space come the command's own words (Command.words) that start with what follows;
    `state` is asked for what the console has now only then, and only by a command whose
    words depend on it (none given: such a command has none to offer). A row is something
    tab would change: a word typed whole is not listed. Nothing here says what runs: parse does.
    """
    if not typed.startswith("/"):
        return []
    out = [
        Completion(text, text, why, suggested=True)
        for text, why in suggestions
        if text.lower().startswith(typed.lower()) and text != typed
    ]
    name, space, rest = typed[1:].partition(" ")
    if space:
        command = find(name)
        if command is None or command.words is None:
            return out
        rest = rest.strip().lower()
        ranked = [(rank, word) for word in command.words(state() if state is not None else State())
                  if (rank := _word_rank(word, rest)) is not None and word.text.lower() != rest]
        return out + [Completion(f"/{command.name} {word.text}", f"/{command.name} {word.text}", word.help)
                      for _, word in sorted(ranked, key=lambda pair: pair[0])]
    commands = COMMANDS if lane else (*(BY_NAME[first] for first in NO_LANE_FIRST), *(c for c in COMMANDS if c.name not in NO_LANE_FIRST))
    found = [(rank, command) for command in commands if (rank := _name_rank(command, name.lower())) is not None]
    for _, command in sorted(found, key=lambda pair: pair[0]):
        label = f"/{command.name} {command.args}".rstrip()
        out.append(Completion(f"/{command.name} ", label, command.help, also=also(command)))
    return out


def no_match(typed: str) -> str:
    """The menu's one row when it has nothing to list because `typed` names no command; ""
    when the text is no command, or its name is one (the menu then has nothing to add)."""
    if not typed.startswith("/"):
        return ""
    name = typed[1:].partition(" ")[0]
    return "" if find(name) is not None else f'No commands match "/{name}"'
