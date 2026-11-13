"""Slash commands for the command bar.

The same commands work in both views: in the fleet view they act on the selected lane
(or on a lane named first, `/kill L07`), in the focus view on the open lane. Plain
text with no slash is a message to the lane; it goes into the lane's next turn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

LANE_ID = re.compile(r"^[Ll](\d+)$")


@dataclass(frozen=True)
class Command:
    name: str
    args: str
    help: str
    lane: bool = True  # acts on a lane


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
    Command("open", "<lane>", "open a lane in the focus view"),
    Command("note", "<text>", "a note for every lane: running ones read it on their next turn, later ones at their start", lane=False),
    Command("config", "[lanes N|unlimited | submit auto|confirm | file]", "this run's settings: lanes at once, auto approve (submit auto)", lane=False),
    Command("new", "[name]", "hand a challenge to a lane: its name, text, files and address", lane=False),
    Command("attach", "[challenge] <files>", "add files to a challenge (drag them onto this bar); its lane restarts with them", lane=False),
    Command("queue", "<challenge>", "queue a parked or new challenge", lane=False),
    Command("unhold", "", "lift the hold on the queue once its cause is fixed (a key or model id changed in "
                          "your config needs a new run)", lane=False),
    Command("autopilot", "[on|off]", "engage autopilot (it needs a run budget), or take the controls back", lane=False),
    Command("claim", "[challenge]", "team mode: claim or release a challenge", lane=False),
    Command("filter", "[words]", "filter the lane list", lane=False),
    Command("sort", "[mode]", "sort lanes: attention, idle, cost, turns, lane", lane=False),
    Command("back", "", "back to the fleet", lane=False),
    Command("help", "", "keys and commands", lane=False),
    Command("quit", "", "quit flightdeck (asks first while lanes are open)", lane=False),
)
BY_NAME = {command.name: command for command in COMMANDS}

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


def lane_id(token: str) -> str | None:
    """'l7' or 'L07' -> 'L07'; anything else -> None."""
    match = LANE_ID.match(token)
    return f"L{int(match.group(1)):02d}" if match else None


def parse(text: str) -> Parsed:
    text = text.strip()
    if not text.startswith("/"):
        return Parsed(None, None, text)
    head, _, rest = text[1:].partition(" ")
    command = BY_NAME.get(head.lower())
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


def complete(typed: str, suggestions: tuple[tuple[str, str], ...] = ()) -> list[Completion]:
    """Menu entries for the text typed so far.

    `suggestions` are full commands taken from the lane's alerts, as (command, why);
    they come first while they still match what is typed.
    """
    if not typed.startswith("/"):
        return []
    out = [
        Completion(text, text, why, suggested=True)
        for text, why in suggestions
        if text.lower().startswith(typed.lower()) and text != typed
    ]
    name, space, _ = typed[1:].partition(" ")
    if space:
        return out
    for command in COMMANDS:
        if command.name.startswith(name.lower()):
            label = f"/{command.name} {command.args}".rstrip()
            out.append(Completion(f"/{command.name} ", label, command.help))
    return out
