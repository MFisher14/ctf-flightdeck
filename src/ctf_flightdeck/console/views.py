"""Rendering for the console: header, board and lane rows, the fleet's "why" line, and the
focus view's transcript (every line: transcript_lines; calm: entries, entry_text), "needs you
now" card, files and diff.

The console has two layouts (config.LAYOUTS): `deck`, the whole dashboard, and `simple`, which
shows what needs the player and little else. The functions here that draw differently in
`simple` take `simple=True`; the compact layout (a narrow terminal) wins over both.

Everything that comes from a challenge or a lane (names, descriptions, commands, tool
output, flags, diffs) is untrusted. It goes through text.untrusted() and is wrapped in
rich Text, never parsed as markup, so "[@click=app.quit]" or an escape sequence shows
literally and cannot steer the console.

What a lane did is shown as its transcript keeps it (lane_text): its steps and their output,
flightdeck's notes and alerts, the commands an alert suggests (a loop's hint quotes the
command it repeats), the hints it has not read yet, its plan, its result and the diffs of the
files it changed have the value of anything shaped like a credential taken out
(credentials.py), and the flags the run knows for its challenge stay. A screen is shared or
screenshotted like a run folder.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from weakref import WeakKeyDictionary

from rich import box
from rich.cells import cell_len, set_cell_size
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.style import Style
from rich.syntax import Syntax
from rich.text import Text

from .. import fmt
from ..core.attention import ALERT_URGENCY, SortMode
from ..core.deck import Deck
from ..core.model import (
    COURSE_ALERTS,
    INFORMATIONAL_ALERTS,
    ME,
    Action,
    ActionKind,
    Actor,
    Alert,
    AlertKind,
    Call,
    Challenge,
    ChallengeStatus,
    Event,
    FileChange,
    Lane,
    LaneState,
    PendingKind,
    lanes_text,
)
from ..credentials import named_flags, redact
from ..runrecord import L1 as BY_L1
from ..runrecord import Credit, EventLine, Solve, accepted
from ..text import NEWLINE, untrusted
from . import theme
from .commands import KEY_COMMAND, lane_id

CATEGORY_ORDER = ("web", "for", "rev", "pwn", "cry", "misc", "osint")

_STATE_ROLE = {  # a lane state's colour, as a role of the palette (themes.ROLES)
    LaneState.RUNNING: "ok",
    LaneState.WAITING: "pending",
    LaneState.PAUSED: "warn",
    LaneState.TAKEOVER: "info",
    LaneState.SOLVED: "ok",
    LaneState.KILLED: "error",
    LaneState.STOPPED: "muted",
    LaneState.GAVE_UP: "muted",
}

_BOARD_MARK = {  # a challenge status's mark, and its colour as a role of the palette
    ChallengeStatus.NEW: ("·", "muted"),
    ChallengeStatus.QUEUED: ("…", "muted"),
    ChallengeStatus.RUNNING: ("▶", "ok"),
    ChallengeStatus.SOLVED: ("✓", "ok"),
    ChallengeStatus.TEAMMATE: ("✓", "info"),
    ChallengeStatus.BLOCKED: ("✗", "error"),
    ChallengeStatus.PARKED: ("‖", "warn"),
}


def state_color(state: LaneState) -> str:
    """The colour of a lane's state, in the palette in use (read when drawn: theme.py)."""
    return getattr(theme.active(), _STATE_ROLE[state])


def board_mark(status: ChallengeStatus) -> tuple[str, str]:
    """(mark, colour) for a challenge's status on the board, in the palette in use."""
    mark, role = _BOARD_MARK[status]
    return mark, getattr(theme.active(), role)


PENDING_TAG = {
    PendingKind.SUBMIT: "submit",
    PendingKind.CONFIRM: "confirm",
    PendingKind.BUDGET: "budget",
    PendingKind.LIVE_BOX: "box",
}
# (approve, decline) in words, for each kind of approval
PENDING_ANSWERS = {
    PendingKind.SUBMIT: ("submit it", "do not submit"),
    PendingKind.CONFIRM: ("accepted", "rejected"),
    PendingKind.BUDGET: ("more budget", "stop the lane"),
    PendingKind.LIVE_BOX: ("use the live box", "stay off it"),
}


COMPACT_MAX_WIDTH = 64  # columns: at this width or narrower both views use the compact layout (a phone over SSH)


def compact(columns: int) -> bool:
    """Whether a terminal `columns` wide gets the compact layout (CONSOLE-SPEC "Compact layout")."""
    return columns <= COMPACT_MAX_WIDTH


def safe(value: object, style: str | Style = "", *, justify: str | None = None) -> Text:
    """Untrusted text as one literal line: control characters made visible, never markup."""
    return Text(untrusted(str(value), one_line=True), style=style, justify=justify, overflow="ellipsis", no_wrap=True)


class _Flags:
    """The flags the run knows for each challenge, read from the deck's events as they come:
    what its lanes proposed (waiting or submitted) and what L1 engines reported
    (credentials.named_flags), the flags a lane's transcript keeps."""

    def __init__(self) -> None:
        self.read = 0
        self.of: dict[str, tuple[str, ...]] = {}

    def update(self, events: Sequence[Event]) -> None:
        for event in events[self.read :]:
            found = named_flags(event.data)
            if found and event.challenge:
                self.of[event.challenge] = tuple(dict.fromkeys((*self.of.get(event.challenge, ()), *found)))
        self.read = len(events)


_FLAGS: WeakKeyDictionary[Deck, _Flags] = WeakKeyDictionary()
LINE_CHARS = 1000  # a one-line cell (the last action, the why line) shows no more of a text than this: no terminal is that wide


def known_flags(deck: Deck, challenge_id: str) -> tuple[str, ...]:
    """The flags the run knows for a challenge, each once, in the order it first met them."""
    flags = _FLAGS.get(deck)
    if flags is None:
        flags = _FLAGS[deck] = _Flags()
    flags.update(deck.events)
    return flags.of.get(challenge_id, ())


def lane_text(deck: Deck, lane: Lane, text: str) -> str:
    """`text` from what `lane` did, as the console shows it: the value of anything shaped like
    a credential taken out (credentials.py), but the flags the run knows for its challenge.
    The deck keeps the text as it was, for the lane's model, which has read it already."""
    return _redacted(text, known_flags(deck, lane.challenge_id))


@lru_cache(maxsize=256)
def _redacted(text: str, keep: tuple[str, ...]) -> str:
    """Kept for the next refresh, which draws every lane's last action, the why line and the
    open diff again: taking credentials out costs time in proportion to the text, and an
    output can be a megabyte."""
    return redact(text, keep=keep)


def lane_line(deck: Deck, lane: Lane, text: str) -> str:
    """`text` from what `lane` did, for a one-line cell: lane_text cut to LINE_CHARS (after
    the credentials are out, so no part of one is left) and made safe to draw."""
    return untrusted(lane_text(deck, lane, text)[:LINE_CHARS], one_line=True)


def alert_style(kind: AlertKind | None) -> str:
    if kind is None:
        return f"bold {theme.RED}"
    return f"bold {theme.alert_colors(kind)[1]}"


def top_answerable(lane: Lane) -> Alert | None:
    answer = [a for a in lane.alerts if a.kind not in INFORMATIONAL_ALERTS]
    return min(answer, key=lambda a: ALERT_URGENCY[a.kind]) if answer else None


@dataclass(frozen=True)
class QuickAnswer:
    """One numbered answer to what the lane needs: press its number, no enter."""

    number: str  # "1".."9", or "0" for no
    key: str  # the intervention, as its fleet key: a, d, h, r, f, k, e, p, t
    text: str  # the suggested text (a hint, a plan, an approach), "" if none
    label: str  # what it does, in words


def quick_answers(lane: Lane) -> list[QuickAnswer]:
    """The answers the why line and the "needs you now" card number. An approval waiting
    comes first: 1 approves, 0 declines. Otherwise the most urgent alert's suggestions,
    numbered from 1."""
    if lane.finished:
        return []
    if lane.pending is not None:
        yes, no = PENDING_ANSWERS[lane.pending.kind]
        if lane.pending.kind is PendingKind.SUBMIT:
            yes = lane.pending.detail
        return [QuickAnswer("1", "a", "", yes), QuickAnswer("0", "d", "", no)]
    top = top_answerable(lane)
    if top is None:
        return []
    out: list[QuickAnswer] = []
    for s in top.suggestions:
        if s.key in KEY_COMMAND and len(out) < 9:
            out.append(QuickAnswer(str(len(out) + 1), s.key, s.text, s.label))
    return out


# ---------------------------------------------------------------------- approving several flags


@dataclass(frozen=True)
class FlagBatch:
    """What "approve all" would do: the flags it approves, and the approvals it leaves."""

    send: tuple[tuple[str, str], ...]  # (lane id, flag): the submit approval each lane asks about now
    left: tuple[tuple[str, str, str], ...]  # (lane id, why it is left as it is: in a few words, in full)


# Why an approval is left, in a few words (the status line) and in full (the prompt).
LEFT_TRIES = ("counted tries", "the platform counts the tries at its flag: approve it on its own (a)")
LEFT_CONFIRM = ("hand submit", "you submit it by hand, then say how it went (a accepted, d rejected)")
LEFT_BUDGET = ("budget", "more budget is not a flag")
LEFT_BOX = ("live box", "live-box access is not a flag")
LEFT_NO_FLAG = ("no flag", "its approval names no flag")
LEFT_TAKEN = ("taken over", "you have its shell: hand it back first")


def flag_batch(deck: Deck) -> FlagBatch:
    """The lanes that need the player, most urgent first, split into the flags one yes can
    approve and the approvals that keep their own answer: a flag of a challenge whose tries
    the platform counts (DeckConfig.holds), a hand submit to confirm, more budget, the live
    box, and a lane the player has taken over (the deck would refuse it)."""
    send: list[tuple[str, str]] = []
    left: list[tuple[str, str, str]] = []
    for lane in deck.needing():
        pending = lane.pending
        if pending is None:
            continue
        if pending.kind is PendingKind.CONFIRM:
            left.append((lane.id, *LEFT_CONFIRM))
        elif pending.kind is PendingKind.BUDGET:
            left.append((lane.id, *LEFT_BUDGET))
        elif pending.kind is PendingKind.LIVE_BOX:
            left.append((lane.id, *LEFT_BOX))
        elif pending.flag is None:
            left.append((lane.id, *LEFT_NO_FLAG))
        elif lane.state is LaneState.TAKEOVER:
            left.append((lane.id, *LEFT_TAKEN))
        elif deck.config.holds(deck.challenges[lane.challenge_id]):
            left.append((lane.id, *LEFT_TRIES))
        else:
            send.append((lane.id, pending.flag))
    return FlagBatch(tuple(send), tuple(left))


def batch_refusal(deck: Deck, lane_id: str, flag: str) -> str | None:
    """Why a flag the approve-all prompt listed is not approved after all (None: approve it), in a few words:
    its lane no longer waits with that flag, since it was answered, or dropped as known
    wrong, while the prompt was open or by an approval earlier in the same batch."""
    lane = deck.lanes.get(lane_id)
    if lane is None:
        return "lane gone"
    pending = lane.pending
    if not lane.finished and pending is not None and pending.kind is PendingKind.SUBMIT and pending.flag == flag:
        return LEFT_TRIES[0] if deck.config.holds(deck.challenges[lane.challenge_id]) else None
    if deck.not_flag(lane.challenge_id, flag) is not None:
        return "known wrong, not sent"
    if lane.finished:
        return f"lane {lane.state.value}"
    return "answered meanwhile"


def left_text(left: Sequence[tuple[str, str, str]]) -> str:
    """The approvals left, for the status line (one row): "L02 (why), L05 (why)", each why
    in a few words."""
    return ", ".join(f"{lane_id} ({untrusted(short, one_line=True)})" for lane_id, short, _ in left)


def approve_summary(deck: Deck, batch: FlagBatch) -> Text:
    """The approve-all prompt: each flag by lane and challenge, then what is left and why."""

    def name(lane_id: str) -> str:
        return untrusted(deck.challenges[deck.lanes[lane_id].challenge_id].name, one_line=True)

    count = len(batch.send)
    out = Text()
    out.append(f"{count} flag{'' if count == 1 else 's'} to approve", "bold")
    for lane_id, flag in batch.send:
        out.append(f"\n  {lane_id} ", "bold")
        out.append(name(lane_id), "bold")
        out.append("  ")
        out.append(untrusted(flag, one_line=True), theme.PURPLE)
    if batch.left:
        out.append(f"\nLeft as {'it is' if len(batch.left) == 1 else 'they are'} ({len(batch.left)})", "bold")
        for lane_id, _, why in batch.left:
            out.append(f"\n  {lane_id} ", "bold")
            out.append(name(lane_id), "bold")
            out.append(f"  {untrusted(why, one_line=True)}", theme.MUTED)
    out.append(
        "\n\nEach is approved as the a key approves it, one approval per lane: the flags of one challenge go to the "
        "platform one at a time, and a flag known wrong is never sent. Nothing is sent before you answer.",
        theme.MUTED,
    )
    return out


# ---------------------------------------------------------------------- header


@dataclass(frozen=True)
class HeaderFacts:
    """What the header shows (header_facts() reads them off a deck)."""

    event: str
    team: bool
    containerized: bool
    lanes: int  # active lanes
    max_lanes: int
    queue: int
    need: int  # lanes that need the player
    held: str  # why the queue is held (Deck.held); "" while lanes start
    tokens: int
    dollars: float  # known dollars
    unpriced: bool  # some spend has no price
    clock: float  # seconds since the event started
    mock: str = ""  # the mock's tag; "" in a run
    later: bool = False  # a lane's coding-agent CLI turn is under way (an ended lane's too): its cost is still to come
    autopilot: bool = False  # autopilot is engaged (Deck.autopilot): the header says so


def header_facts(deck: Deck, mock: str = "") -> HeaderFacts:
    cfg = deck.config
    tokens, dollars, unpriced = deck.totals()
    return HeaderFacts(
        cfg.event, cfg.team, cfg.containerized, len(deck.active_lanes()), cfg.max_lanes, len(deck.queue),
        len(deck.needing()), deck.held, tokens, dollars, unpriced, deck.now, mock,
        later=any(lane.dollars_later for lane in deck.lanes.values()),
        autopilot=deck.autopilot is not None and bool(deck.autopilot.engaged),
    )


HELD = "queue held"
AUTOPILOT, AUTOPILOT_SHORT = "AUTOPILOT", "AP"  # the header's chip while autopilot is engaged; the compact layout's
HELD_WHY_MIN = 12  # cells: less room than this after the other pieces, and the header names no reason
WHY_OUTRANKS = 3  # pieces of this drop rank or more (the event's name, the clock, tokens, dollars) make room for it
HEADER_WORDS = {  # the pieces that can drop, as doctor names them (console/room.py)
    "event": "the event's name", "mock": "the mock tag", "runtime": "the runtime (docker or host)",
    "tokens": "tokens", "dollars": "dollars", "clock": "the event clock",
    "flightdeck": "the flightdeck name", "mode": "solo or team",  # these two give way in the compact layout only
    "team": "the team tag", "host": "the host tag", "queue": "the queue",  # the simple layout's own pieces
}
COMPACT_HEADER_OMITS = ("tokens", "clock", "event", "mock", "runtime")  # never in the compact header, in their usual drop order


def header_pieces(facts: HeaderFacts, *, compact: bool = False, simple: bool = False) -> list[tuple[str, int, tuple[str, str, str, bool]]]:
    """(name, drop rank, segment) for each piece, in order. Rank 0 never drops; on a narrow
    terminal the highest rank drops first, the later piece first on a tie (D16). The compact
    layout's header has what needs the player and the dollars, which never drop, the lanes and
    the queue in short, and the flightdeck name and solo/team, which give way in that order.

    The simple layout's header (`simple`; the compact one wins over it) says only what is not
    the usual: team mode, lanes on the host, a queue that is not empty, autopilot, who needs
    the player, a held queue. Those last three and the dollars never drop. It has no solo,
    docker, lane count, "all clear", tokens or clock."""
    if compact:
        out = [
            ("flightdeck", 2, ("flightdeck", theme.WHITE, theme.BLUE, True)),
            ("mode", 1, ("team" if facts.team else "solo", theme.CYAN if facts.team else theme.TEXT, theme.SEGMENT, True)),
            ("lanes", 0, (f"{facts.lanes}/{lanes_text(facts.max_lanes)} · q{facts.queue}", theme.TEXT, theme.SEGMENT, False)),
        ]
    elif simple:
        out = [
            ("flightdeck", 0, ("flightdeck", theme.WHITE, theme.BLUE, True)),
            ("event", 3, (untrusted(facts.event, one_line=True), theme.TEXT, theme.SEGMENT, True)),
        ]
        if facts.mock:
            out.append(("mock", 2, (facts.mock, theme.INK, theme.ACCENT, True)))
        if facts.team:
            out.append(("team", 1, ("team", theme.CYAN, theme.SEGMENT, True)))
        if not facts.containerized:
            out.append(("host", 1, ("host", theme.INK, theme.YELLOW, True)))
        if facts.queue:
            out.append(("queue", 1, (f"queue {facts.queue}", theme.TEXT, theme.SEGMENT, False)))
    else:
        out = [
            ("flightdeck", 0, ("flightdeck", theme.WHITE, theme.BLUE, True)),
            ("event", 3, (untrusted(facts.event, one_line=True), theme.TEXT, theme.SEGMENT, True)),
        ]
        if facts.mock:
            out.append(("mock", 2, (facts.mock, theme.INK, theme.ACCENT, True)))
        out += [
            ("mode", 0, ("team" if facts.team else "solo", theme.CYAN if facts.team else theme.TEXT, theme.SEGMENT, True)),
            ("runtime", 1, ("docker", theme.TEXT, theme.SEGMENT, False) if facts.containerized else ("host", theme.INK, theme.YELLOW, True)),
            ("lanes", 0, (f"lanes {facts.lanes}/{lanes_text(facts.max_lanes)} · queue {facts.queue}", theme.TEXT, theme.SEGMENT, False)),
        ]
    if facts.autopilot:  # never dropped: who has the controls is not a detail
        out.append(("autopilot", 0, (AUTOPILOT_SHORT if compact else AUTOPILOT, theme.INK, theme.GREEN, True)))
    if facts.need:
        out.append(("need", 0, (f"▲ {facts.need} need you", theme.WHITE, theme.RED, True)))
    elif not facts.held and (compact or not simple):  # a held queue is not all clear: nothing starts until the player lifts it
        out.append(("need", 0, ("all clear", theme.MUTED, theme.SEGMENT, False)))
    if facts.held:
        out.append(("held", 0, (HELD, theme.INK, theme.YELLOW, True)))
    dollars = f"${fmt.dollars(facts.dollars)}" + ("+" if facts.unpriced else "") + (LATER if facts.later else "")  # as lane_dollars
    if compact or simple:
        out.append(("dollars", 0, (dollars, theme.TEXT, theme.SEGMENT, False)))
        return out
    out += [
        ("tokens", 4, (f"tok {fmt.tokens(facts.tokens)}", theme.TEXT, theme.SEGMENT, False)),
        ("dollars", 4, (dollars, theme.TEXT, theme.SEGMENT, False)),
        ("clock", 3, (fmt.clock(facts.clock), theme.TEXT, theme.SEGMENT, False)),
    ]
    return out


def fit_header(facts: HeaderFacts, width: int, *, compact: bool = False, simple: bool = False) -> tuple[Text, list[str]]:
    """The header in `width` cells, and the names of the pieces it leaves out, in the order
    they drop. While the queue is held, why follows "queue held": the event's name, the clock,
    tokens and dollars give way to it (in their usual order), and it is cut to the room left.
    The compact layout's header (header_pieces) never has tokens, the clock, the event's name,
    the mock tag or the runtime: they come first in what it leaves out. The simple layout's
    header leaves out only what a narrow terminal makes it drop: what it never shows is not
    missing from it."""
    pieces = header_pieces(facts, compact=compact, simple=simple)
    left_out: list[str] = [name for name in COMPACT_HEADER_OMITS if name != "mock" or facts.mock] if compact else []
    text = theme.segments([part for _, _, part in pieces])

    def drop() -> None:
        nonlocal text
        index = max(range(len(pieces)), key=lambda i: (pieces[i][1], i))
        left_out.append(pieces.pop(index)[0])
        text = theme.segments([part for _, _, part in pieces])

    while text.cell_len > width and any(rank for _, rank, _ in pieces):
        drop()
    if not facts.held:
        return text, left_out
    why = untrusted(facts.held, one_line=True)
    while width - text.cell_len - len(": ") < cell_len(why) and any(rank >= WHY_OUTRANKS for _, rank, _ in pieces):
        drop()
    room = width - text.cell_len - len(": ")
    if room >= HELD_WHY_MIN:
        index = next(i for i, (name, _, _) in enumerate(pieces) if name == "held")
        name, rank, (_, fg, bg, bold) = pieces[index]
        pieces[index] = (name, rank, (f"{HELD}: {_cut(why, room)}", fg, bg, bold))
        text = theme.segments([part for _, _, part in pieces])
    return text, left_out


def _cut(text: str, cells: int) -> str:
    """`text` in at most `cells` cells, ending in "…" when it was cut."""
    return text if cell_len(text) <= cells else set_cell_size(text, cells - 1) + "…"


def header(deck: Deck, *, mock: str = "", note: str = "", width: int = 200, compact: bool = False, simple: bool = False) -> Text:
    """The slanted header. Low-priority pieces drop out first when the terminal is narrow.
    While the queue is held it says so, never "all clear", and why, as room allows."""
    text, _ = fit_header(header_facts(deck, mock), width, compact=compact, simple=simple)
    if note and text.cell_len + len(note) + 2 <= width:
        text.append("  " + note, theme.MUTED)
    return text


# ---------------------------------------------------------------------- board

# (key, label, width, drop rank: 0 never, higher drops first). "name" stretches. "cat" fits a
# light model's guess with its question mark ("osint?").
BOARD_COLUMNS = (
    ("cat", "cat", 6, 2),
    ("name", "name", 0, 0),
    ("pts", "pts", 4, 0),
    ("solv", "solv", 5, 3),
    ("mark", "", 1, 0),
    ("own", "own", 5, 1),
)
BOARD_NAME_MIN = 10


def board_order(challenges: list[Challenge]) -> list[Challenge]:
    def key(ch: Challenge):
        cat = CATEGORY_ORDER.index(ch.category) if ch.category in CATEGORY_ORDER else len(CATEGORY_ORDER)
        return (cat, ch.points, ch.name)

    return sorted(challenges, key=key)


class _Solves:
    """Who solved what on a live deck, by the rule every report uses (runrecord.Credit), read
    from the deck's events as they come: the list only grows, so each event is read once."""

    def __init__(self) -> None:
        self.credit = Credit()
        self.read = 0
        self.first: dict[str, Solve] = {}  # challenge id -> its first solve

    def update(self, events: Sequence[Event]) -> None:
        for index in range(self.read, len(events)):
            event = events[index]
            line = EventLine(event.at, "", event.kind.value, event.text, event.lane, event.challenge,
                             event.alert.value if event.alert is not None else None, event.data)
            self.credit.see(index, line)
            cid = line.challenge
            if not cid or cid in self.first:
                continue
            if accepted(line):
                flag = line.data.get("flag")
                self.first[cid] = self.credit.flag(index, line, flag if isinstance(flag, str) else "")
            elif (solve := Credit.other(index, line)) is not None:
                self.first[cid] = solve
        self.read = len(events)


_SOLVES: WeakKeyDictionary[Deck, _Solves] = WeakKeyDictionary()


def first_solve(deck: Deck, challenge_id: str) -> Solve | None:
    """The challenge's first solve on this deck, credited as every report credits it
    (runrecord.Credit), or None."""
    solves = _SOLVES.get(deck)
    if solves is None:
        solves = _SOLVES[deck] = _Solves()
    solves.update(deck.events)
    return solves.first.get(challenge_id)


def owner(deck: Deck, ch: Challenge) -> tuple[str, str]:
    """Who has the challenge, and what kind of owner that is: lane, l1, me, mate or "". A solve
    goes where every report credits it (runrecord.Credit): the flag an L1 engine reported
    first is that engine's solve, "L1·<engine>", whichever lane submitted it."""
    if ch.closed and ch.solved_by:
        if ch.status is ChallengeStatus.TEAMMATE:
            return ch.solved_by, "mate"
        solve = first_solve(deck, ch.id)
        if solve is not None and solve.by == BY_L1:
            return f"L1·{solve.who}", "l1"
        return ch.solved_by, ("me" if ch.solved_by == ME else "lane")
    if ch.claimed_by and ch.claimed_by != ME:
        return ch.claimed_by, "mate"
    lanes = deck.lanes_on(ch.id)
    if lanes:
        first = min(lanes, key=lambda lane: lane.number).id
        return (first if len(lanes) == 1 else f"{first}+{len(lanes) - 1}"), "lane"
    if ch.claimed_by == ME:
        return ME, "me"
    return "", ""


def owner_style(kind: str) -> str:
    """The style of the board's owner cell, for a kind owner() gives."""
    return {"mate": theme.CYAN, "me": "bold", "lane": "", "l1": theme.GREEN, "": ""}[kind]


GUESSED = "?"  # after a light model's guess at a category the board does not name


def category_cell(ch: Challenge) -> Text:
    """The board's category; where the board names none flightdeck knows and a light model
    guessed one (agent/facts.py), the guess with a question mark, in italics: never the board's
    own word dressed up as one."""
    if ch.category_guess:
        return safe(f"{ch.category_guess}{GUESSED}", f"italic {theme.YELLOW}")
    return safe(ch.category, theme.MUTED)


def route_text(ch: Challenge) -> str:
    """What a light model said of the challenge's route, for a why line: its family, and its
    guess at the category ("" when it said nothing)."""
    parts = []
    if ch.family:
        parts.append(f"family {untrusted(ch.family, one_line=True)}")
    if ch.category_guess:
        parts.append(f"category {untrusted(ch.category_guess, one_line=True)}{GUESSED}")
    return "light model: " + ", ".join(parts) if parts else ""


def board_cells(deck: Deck, ch: Challenge) -> dict[str, Text]:
    mark, mark_color = board_mark(ch.status)
    dim = theme.MUTED if ch.status in (ChallengeStatus.SOLVED, ChallengeStatus.TEAMMATE, ChallengeStatus.BLOCKED) else ""
    own, kind = owner(deck, ch)
    if ch.claimed_by == ME and kind == "lane":
        own = f"{own}*"  # ours, and claimed for the team
    return {
        "cat": category_cell(ch),
        "name": safe(ch.name, dim),
        "pts": safe(ch.points, dim, justify="right"),
        "solv": safe(ch.solves, theme.MUTED, justify="right"),
        "mark": Text(mark, style=mark_color),
        "own": safe(own, owner_style(kind)),
    }


def board_title(deck: Deck) -> Text:
    challenges = list(deck.challenges.values())
    ours = sum(ch.status is ChallengeStatus.SOLVED for ch in challenges)
    mates = sum(ch.status is ChallengeStatus.TEAMMATE for ch in challenges)
    text = Text("board ", "bold")
    text.append(f"{len(challenges)}")
    text.append(f" · ✓ {ours}", theme.GREEN)
    if deck.config.team:
        text.append(f" · team ✓ {mates}", theme.CYAN)
    return text


# ---------------------------------------------------------------------- lanes

# (key, label, width, drop rank). "last" stretches.
LANE_COLUMNS = (
    ("bar", "", 1, 0),
    ("!", "!", 12, 0),
    ("lane", "lane", 4, 0),
    ("chall", "chall", 16, 0),
    ("model", "model", 6, 4),
    ("state", "state", 8, 0),
    ("turns", "turns", 5, 3),
    ("cost", "cost", 8, 2),  # "$12.34+…": lane_dollars' markers are never cut off
    ("idle", "idle", 4, 0),
    ("last", "last action", 0, 1),
)
LAST_MIN = 12
LANE_SHRINK = {"chall": 8}  # on a narrow terminal the challenge name narrows before a column is cut
# The compact layout's lane row: what needs you, the lane, its state and cost, then its challenge,
# which takes the room left: last, so the edge of a narrow terminal (or the scrollbar) cuts the name
# and never the state or the cost.
COMPACT_LANE_COLUMNS = (
    ("bar", "", 1, 0),
    ("!", "!", 6, 0),  # a chip of four letters
    ("lane", "lane", 4, 0),
    ("state", "state", 5, 0),
    ("cost", "cost", 8, 0),  # as wide as the full layout's: lane_dollars' markers are never cut off
    ("chall", "chall", 0, 0),
)
COMPACT_CHALL_MIN = 8
# The simple layout's lane row: what needs you, the lane, its challenge, state and cost, and what
# it did last. Its model, turns and idle time are in the lane's own view (focus_title). Only the
# last action can go, and only once the challenge's name has narrowed (simple_lane_columns): what
# a lane has spent is in the list at every width, as in the compact layout.
SIMPLE_LANE_COLUMNS = (
    ("bar", "", 1, 0),
    ("!", "!", 12, 0),
    ("lane", "lane", 4, 0),
    ("chall", "chall", 20, 0),
    ("state", "state", 8, 0),
    ("cost", "cost", 8, 0),
    ("last", "last action", 0, 1),
)
COMPACT_ALERT_TAG = {
    AlertKind.FLAG: "flag", AlertKind.BUDGET: "budg", AlertKind.LOOP: "loop", AlertKind.EFFORT: "efrt",
    AlertKind.HINT: "hint", AlertKind.DIRECTION: "wway", AlertKind.STALL: "stal", AlertKind.TEAMMATE: "mate",
}
COMPACT_PENDING_TAG = {
    PendingKind.SUBMIT: "sub", PendingKind.CONFIRM: "conf", PendingKind.BUDGET: "budg", PendingKind.LIVE_BOX: "box",
}
COMPACT_SENDING = "send"
COMPACT_STATE = {
    LaneState.RUNNING: "run", LaneState.WAITING: "wait", LaneState.PAUSED: "pause", LaneState.TAKEOVER: "take",
    LaneState.SOLVED: "done", LaneState.KILLED: "kill", LaneState.STOPPED: "stop", LaneState.GAVE_UP: "gave",
}
FINISHED_ROW = "__finished__"


def fit_columns(
    columns: tuple[tuple[str, str, int, int], ...],
    stretch: str,
    stretch_min: int,
    available: int,
    padding: int,
    shrink: dict[str, int] | None = None,
    *,
    shrink_first: bool = False,
) -> list[tuple[str, str, int]]:
    """Drop columns by rank (highest first) until they fit `available` cells; the
    `stretch` column takes what is left. If the columns that never drop still do not
    fit, the `shrink` columns narrow, each down to its floor.

    `shrink_first`: the `shrink` columns narrow before any column drops, and a column drops
    only when that was not enough. If the `stretch` column is the one that went, the columns
    that narrowed take the room back, each up to its own width."""
    kept = [list(column) for column in columns]
    full = {key: width for key, _, width, _ in columns}

    def needed() -> int:
        fixed = sum(width if key != stretch else stretch_min for key, _, width, _ in kept)
        return fixed + 2 * padding * len(kept)

    def drop() -> None:
        while needed() > available and any(rank for *_, rank in kept):
            worst = max(range(len(kept)), key=lambda i: (kept[i][3], i))
            kept.pop(worst)

    def narrow() -> None:
        for key, floor in (shrink or {}).items():
            over = needed() - available
            for column in kept:
                if over > 0 and column[0] == key and column[2] > floor:
                    cut = min(over, column[2] - floor)
                    column[2] -= cut
                    over -= cut

    if shrink_first:
        narrow()
        drop()
        if all(column[0] != stretch for column in kept):
            spare = available - needed()
            for column in kept:
                if spare > 0 and column[0] in (shrink or {}):
                    back = min(spare, full[column[0]] - column[2])
                    column[2] += back
                    spare -= back
    else:
        drop()
        narrow()
    spare = available - needed()
    return [(key, label, width if key != stretch else stretch_min + max(0, spare)) for key, label, width, _ in kept]


def simple_lane_columns(available: int, padding: int) -> list[tuple[str, str, int]]:
    """The simple layout's lane columns (SIMPLE_LANE_COLUMNS) for a lane list with `available`
    cells: the challenge's name narrows first (LANE_SHRINK), then the last action goes and the
    name is whole again. The cost never goes."""
    return fit_columns(SIMPLE_LANE_COLUMNS, "last", LAST_MIN, available, padding, LANE_SHRINK, shrink_first=True)


SENDING = "sending"  # the attention cell while a flag of the lane is on its way to the platform


def sending_chip() -> Text:
    return theme.chip(SENDING, theme.WHITE, theme.BLUE)


def attention_cell(lane: Lane, sending: bool = False, *, compact: bool = False) -> Text:
    """The lane's most urgent alert or approval; else, when `sending`, that a flag of it is on
    its way to the platform (nothing to answer: its answer comes back on its own). The compact
    layout's chip has four letters at most and no count of what else waits (the why line and
    the needs-you card have the rest)."""
    if lane.finished:
        return Text("")
    top = top_answerable(lane)
    if top is not None:
        cell = theme.chip(COMPACT_ALERT_TAG[top.kind] if compact else top.kind.tag, *theme.alert_colors(top.kind))
        extra = len(lane.alerts) - 1 + (1 if lane.pending is not None and top.kind is not AlertKind.FLAG and top.kind is not AlertKind.BUDGET else 0)
        if extra > 0 and not compact:
            cell.append(f"+{extra}", theme.MUTED)
        return cell
    if lane.pending is not None:
        tags = COMPACT_PENDING_TAG if compact else PENDING_TAG
        return theme.chip(tags[lane.pending.kind], *theme.pending_colors())
    if sending:
        return theme.chip(COMPACT_SENDING, theme.WHITE, theme.BLUE) if compact else sending_chip()
    if lane.alerts:
        kind = lane.alerts[0].kind
        return theme.chip(COMPACT_ALERT_TAG[kind] if compact else kind.tag, *theme.alert_colors(kind))
    return Text("")


LATER = "…"  # after a lane's dollars: a coding-agent CLI's turn is under way, and it reports the cost when the turn ends


def lane_dollars(lane: Lane, *, short: bool = False) -> str:
    """The lane's dollars: $0.42; $0.42+ when some of its spend has no price (what is known,
    as "at least"), "-" when none of it has; and LATER after it while a coding-agent CLI's
    turn is under way, whose cost comes when the turn ends: never a settled number then."""
    if lane.dollars is not None:
        cost = f"${fmt.dollars(lane.dollars, short=short)}"
    else:
        cost = f"${fmt.dollars(lane.known_dollars, short=short)}+" if lane.known_dollars else "-"
    return cost + LATER if lane.dollars_later else cost


def lane_cells(deck: Deck, lane: Lane, selected: bool = False, *, compact: bool = False) -> dict[str, Text]:
    """A lane's row, by column. `compact`: the attention chip and the state in short
    (COMPACT_LANE_COLUMNS has no room for more)."""
    ch = deck.challenges[lane.challenge_id]
    dim = theme.MUTED if lane.finished else ""
    idle = lane.idle(deck.now)
    cost = lane_dollars(lane, short=True)
    return {
        "bar": Text("▌", style=theme.ACCENT) if selected else Text(" "),
        "!": attention_cell(lane, bool(deck.sending(lane.id)), compact=compact),
        "lane": Text(lane.id, style=theme.MUTED if lane.finished else "bold"),
        "chall": safe(ch.name, dim),
        "model": safe(lane.model, dim or theme.CYAN),
        "state": Text(COMPACT_STATE[lane.state] if compact else lane.state.value, style=state_color(lane.state)),
        "turns": Text(str(lane.turns), style=dim, justify="right"),
        "cost": Text(cost, style=dim or theme.MUTED, justify="right"),
        "idle": Text("-" if lane.finished else fmt.duration(idle), style=dim or (theme.ACCENT if idle >= 600 else ""), justify="right"),
        "last": safe(lane_text(deck, lane, lane.last_action)[:LINE_CHARS], theme.MUTED),
    }


def finished_cells(lanes: list[Lane], expanded: bool) -> dict[str, Text]:
    counts: dict[str, int] = {}
    for lane in lanes:
        counts[lane.state.value] = counts.get(lane.state.value, 0) + 1
    parts = " · ".join(f"{n} {state}" for state, n in counts.items())
    hint = "enter to collapse" if expanded else "enter to expand"
    return {
        "!": Text("▾" if expanded else "▸", style=f"bold {theme.MUTED}"),
        "chall": Text(f"{len(lanes)} finished", style=f"bold {theme.MUTED}"),
        "last": Text(f"{parts}  ({hint})", style=theme.MUTED),
    }


OPEN_STATE_WORDS = {
    LaneState.RUNNING: "running",
    LaneState.WAITING: "waiting for you",
    LaneState.PAUSED: "paused",
    LaneState.TAKEOVER: "taken over",
}
QUIT_SHOWN = 5  # lanes waiting for the player, and flags on their way, that the quit prompt names; the rest are counted


def on_their_way(deck: Deck) -> list[tuple[str, str, str, bool]]:
    """The flags on their way to the platform whose answer is not in yet, as (lane id,
    challenge id, flag, sent): the one handed over for each challenge (sent), then those
    waiting their turn behind it (Deck.submitting), challenges in board order. A lane that
    ended meanwhile still has its flag here: the answer would still count for it."""
    return [(lane_id, cid, flag, i == 0) for cid in deck.challenges for i, (lane_id, flag) in enumerate(deck.submitting(cid))]


def quit_summary(deck: Deck, run_dir: str = "") -> Text:
    """What quitting would stop: the open lanes, what waits for the player, the flags on their
    way to the platform (quitting leaves their answer unknown), the queue; and what quitting
    does."""
    live = sorted((lane for lane in deck.lanes.values() if not lane.finished), key=lambda lane: lane.number)
    counts: dict[str, int] = {}
    for lane in live:
        word = OPEN_STATE_WORDS[lane.state]
        counts[word] = counts.get(word, 0) + 1
    out = Text()
    if live:
        out.append(f"{len(live)} lane{'' if len(live) == 1 else 's'} still open", "bold")
        out.append(": " + ", ".join(f"{n} {word}" for word, n in counts.items()))
    else:
        out.append("No lane is still open", "bold")
    waiting = [lane for lane in live if lane.pending is not None]
    for lane in waiting[:QUIT_SHOWN]:
        assert lane.pending is not None
        out.append(f"\n  {lane.id} ", "bold")
        out.append(untrusted(deck.challenges[lane.challenge_id].name, one_line=True), "bold")
        out.append("  ")
        out.append(untrusted(lane.pending.detail, one_line=True), theme.PURPLE)
        if lane.waiting:
            out.append(f"  (then {len(lane.waiting)} more)", theme.MUTED)
    if len(waiting) > QUIT_SHOWN:
        out.append(f"\n  and {len(waiting) - QUIT_SHOWN} more lanes waiting for you", theme.MUTED)
    going = on_their_way(deck)
    if going:
        one = len(going) == 1
        out.append(f"\n{len(going)} flag{'' if one else 's'} on {'its' if one else 'their'} way to the platform: "
                   f"quitting leaves {'its answer' if one else 'their answers'} unknown", "bold")
        for lane_id, cid, flag, sent in going[:QUIT_SHOWN]:
            out.append(f"\n  {lane_id} ", "bold")
            out.append(untrusted(deck.challenges[cid].name, one_line=True), "bold")
            out.append("  ")
            out.append(untrusted(flag, one_line=True), theme.CYAN)
            if not sent:
                out.append("  (waiting its turn: never sent if you quit)", theme.MUTED)
        if len(going) > QUIT_SHOWN:
            out.append(f"\n  and {len(going) - QUIT_SHOWN} more on their way", theme.MUTED)
    if deck.queue:
        out.append(f"\n{len(deck.queue)} challenge{'' if len(deck.queue) == 1 else 's'} queued, not started")
    out.append(
        "\n\nQuitting stops every lane and closes its workspace, and a run cannot be resumed. "
        "Nothing that waits for you is submitted or approved."
    )
    if run_dir:
        out.append(" The run's log and transcripts stay in ")
        out.append(untrusted(run_dir, one_line=True), "bold")
        out.append(".")
    return out


def lane_matches(deck: Deck, lane: Lane, query: str) -> bool:
    if not query:
        return True
    ch = deck.challenges[lane.challenge_id]
    hay = " ".join(
        [lane.id, ch.name, ch.category, ch.category_guess, ch.family, lane.model, lane.state.value, lane.last_action, lane.plan]
        + [a.kind.tag for a in lane.alerts]
        + ([PENDING_TAG[lane.pending.kind]] if lane.pending else [])
    ).lower()
    return all(word in hay for word in query.lower().split())


def lanes_title(deck: Deck, sort: SortMode, query: str, *, board_hidden: bool = False, compact: bool = False, simple: bool = False) -> Text:
    """The lane list's title. In the simple layout (`simple`; the compact one wins over it) it
    carries what the board and the header would: the challenges that wait for a lane and the
    ones solved, each only when there are any, and the sort only when it is not by attention."""
    if simple and not compact:
        text = Text("lanes ", "bold")
        text.append(f"{len(deck.active_lanes())}/{lanes_text(deck.config.max_lanes)}")
        if deck.queue:
            text.append(f" · {len(deck.queue)} waiting", theme.MUTED)
        solved = sum(ch.status is ChallengeStatus.SOLVED for ch in deck.challenges.values())
        if solved:
            text.append(f" · ✓ {solved} solved", theme.GREEN)
        if sort is not SortMode.ATTENTION:
            text.append(f" · sort {sort.value}", theme.MUTED)
    else:
        text = Text("fleet ", "bold")
        text.append(f"{len(deck.active_lanes())}/{lanes_text(deck.config.max_lanes)}")
        text.append(f" · sort {sort.value}", theme.MUTED)
        if board_hidden and not compact:  # the compact layout never has the board, and no room to say so
            text.append(" · board hidden: narrow terminal", theme.MUTED)
    if query:
        text.append(" · filter ", theme.MUTED)
        text.append(untrusted(query, one_line=True), f"bold {theme.YELLOW}")
        hidden = sum(1 for lane in deck.needing() if not lane_matches(deck, lane, query))
        if hidden:
            text.append(f" · {hidden} needing you hidden", f"bold {theme.RED}")
    return text


# ---------------------------------------------------------------------- fleet: the "why" line


def _answers(lane: Lane, alert: Alert | None) -> Text:
    """The numbered quick answers, then any suggestion that has no key (advice only)."""
    out = Text()
    for answer in quick_answers(lane):
        out.append("  ")
        out.append_text(theme.key_chip(answer.number))
        out.append(f" {untrusted(answer.label, one_line=True).lower()}", theme.MUTED)
    for s in (alert.suggestions if alert is not None and lane.pending is None else ()):
        if s.key not in KEY_COMMAND:
            out.append(f"  {untrusted(s.label, one_line=True)}", theme.MUTED)
    return out


def lane_why(deck: Deck, lane: Lane, *, simple: bool = False) -> Text:
    """Two lines under the lane list: why the selected lane is flagged, and the answers. In the
    simple layout (`simple`) they are blank for a lane with no alert and no approval waiting:
    its row says what it is doing, and enter opens the rest."""
    if simple and not lane.alerts and lane.pending is None:
        return Text("")
    out = Text(no_wrap=True, overflow="ellipsis")
    out.append("▌", theme.ACCENT)
    out.append(f"{lane.id} ", "bold")
    if lane.finished:
        out.append(f"{lane.state.value}: ", f"bold {state_color(lane.state)}")
        out.append(lane_line(deck, lane, lane.result))
        out.append("\n  enter opens its transcript", theme.MUTED)
        return out
    top = top_answerable(lane)
    if top is not None:
        out.append(f"▲ {top.kind.label}: ", alert_style(top.kind))
        out.append(lane_line(deck, lane, top.reason))
        out.append("\n")
        out.append_text(_answers(lane, top))
        if top.kind in COURSE_ALERTS:
            out.append("  ")
            out.append_text(theme.key_chip("x"))
            out.append(" dismiss", theme.MUTED)
        out.append("   enter open", theme.MUTED)
        return out
    if lane.pending is not None:
        out.append("◆ waiting for you: ", f"bold {theme.PURPLE}")
        out.append(untrusted(lane.pending.detail, one_line=True))
        out.append("\n")
        out.append_text(_answers(lane, None))
        out.append("   enter open", theme.MUTED)
        return out
    if lane.alerts:
        out.append(f"▲ {lane.alerts[0].kind.label}: ", alert_style(lane.alerts[0].kind))
        out.append(lane_line(deck, lane, lane.alerts[0].reason), theme.MUTED)
        out.append("\n  nothing to do   enter open", theme.MUTED)
        return out
    family = deck.challenges[lane.challenge_id].family
    if family:  # the specialist a light model routed the challenge to
        out.append(untrusted(family, one_line=True), theme.CYAN)
        out.append(" · ", theme.MUTED)
    out.append("plan: ", theme.MUTED)
    out.append(lane_line(deck, lane, lane.plan or "-"))
    out.append("\n  last: ", theme.MUTED)
    last = next((a for a in reversed(lane.actions) if a.kind is ActionKind.STEP), None)
    if last is not None:
        out.append(lane_line(deck, lane, last.text))
        if last.output:
            out.append(f" → {lane_line(deck, lane, last.output)}", theme.MUTED)
    out.append("   enter open", theme.MUTED)
    return out


WHY_ROWS = 2  # the why line's rows
COMPACT_WHY_ROWS = 6  # in the compact layout: the reason on two, three answers at most, and the last row
COMPACT_REASON_ROWS = 2
COMPACT_ANSWERS = 3
_WRAP = Console(width=COMPACT_MAX_WIDTH, color_system=None)  # Text.wrap wants a console; nothing is printed on it


def _rows(text: Text, width: int, rows: int) -> list[Text]:
    """`text` wrapped to at most `rows` rows of `width` cells; the last ends in "…" when it was cut."""
    lines = list(text.wrap(_WRAP, max(8, width)))
    out = lines[:rows]
    if len(lines) > rows:
        out[-1].truncate(max(8, width) - 1)
        out[-1].rstrip()
        out[-1].append("…")
    return out


def compact_why(deck: Deck, lane: Lane, width: int) -> Text:
    """The why line of the compact layout, in `width` cells and COMPACT_WHY_ROWS rows at most:
    why the selected lane is flagged, wrapped onto two rows; its numbered answers, one a row
    and none cut off at the edge of a phone; then the keys that are not numbers."""
    head = Text()
    head.append("▌", theme.ACCENT)
    head.append(f"{lane.id} ", "bold")
    answers: list[QuickAnswer] = []
    extra: list[Text] = []
    last = ["enter open"]
    top = top_answerable(lane)
    if lane.finished:
        head.append(f"{lane.state.value}: ", f"bold {state_color(lane.state)}")
        head.append(lane_line(deck, lane, lane.result))
        last = ["enter opens its transcript"]
    elif top is not None:
        head.append(f"▲ {top.kind.label}: ", alert_style(top.kind))
        head.append(lane_line(deck, lane, top.reason))
        answers = quick_answers(lane)
        if lane.pending is None:  # suggestions with no key: advice only
            extra = [Text(f"  {untrusted(s.label, one_line=True)}", theme.MUTED) for s in top.suggestions if s.key not in KEY_COMMAND]
        if top.kind in COURSE_ALERTS:
            last.insert(0, "x dismiss")
    elif lane.pending is not None:
        head.append("◆ waiting for you: ", f"bold {theme.PURPLE}")
        head.append(untrusted(lane.pending.detail, one_line=True))
        answers = quick_answers(lane)
    elif lane.alerts:
        head.append(f"▲ {lane.alerts[0].kind.label}: ", alert_style(lane.alerts[0].kind))
        head.append(lane_line(deck, lane, lane.alerts[0].reason), theme.MUTED)
        last.insert(0, "nothing to do")
    else:
        head.append("plan: ", theme.MUTED)
        head.append(lane_line(deck, lane, lane.plan or "-"))
        step = next((a for a in reversed(lane.actions) if a.kind is ActionKind.STEP), None)
        if step is not None:
            extra = [Text.assemble(("  last: ", theme.MUTED), lane_line(deck, lane, step.text))]
    rows = _rows(head, width, COMPACT_REASON_ROWS)
    for answer in answers[:COMPACT_ANSWERS]:
        row = Text("  ")
        row.append_text(theme.key_chip(answer.number))
        row.append(f" {untrusted(answer.label, one_line=True).lower()}", theme.MUTED)
        rows.append(row)
    if len(answers) > COMPACT_ANSWERS:
        last.insert(0, f"+{len(answers) - COMPACT_ANSWERS} more answers")
    rows += extra[: COMPACT_WHY_ROWS - 1 - len(rows)]
    rows.append(Text("  " + "   ".join(last), theme.MUTED))
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, row in enumerate(rows):
        out.append("\n" if i else "")
        out.append_text(row)
    return out


def challenge_why(deck: Deck, ch: Challenge) -> Text:
    out = Text(no_wrap=True, overflow="ellipsis")
    mark, color = board_mark(ch.status)
    out.append(untrusted(ch.name, one_line=True), "bold")
    out.append(f"  {untrusted(ch.category, one_line=True)} {ch.points} · {ch.solves} solves · ", theme.MUTED)
    out.append(f"{mark} {ch.status.value}", color)
    if ch.status is ChallengeStatus.SOLVED:  # by whom, in full: the board's own column is narrow
        own, _ = owner(deck, ch)
        if own:
            out.append(f" by {untrusted(own, one_line=True)}", color)
    if ch.note:
        out.append(f" ({untrusted(ch.note, one_line=True)})", theme.YELLOW)
    route = route_text(ch)
    if route:
        out.append(f" · {route}", theme.CYAN)
    out.append("\n  ")
    out.append(untrusted(ch.description or "-", one_line=True), theme.MUTED)
    out.append("   enter for more", theme.MUTED)
    return out


# ---------------------------------------------------------------------- focus view


def focus_title(deck: Deck, lane: Lane, *, compact: bool = False) -> Text:
    """The open lane's title. In the compact layout: the lane, its state and its cost, then
    the challenge's name, which is what the edge of a phone cuts."""
    ch = deck.challenges[lane.challenge_id]
    out = Text()
    if compact:
        out.append(f"{lane.id} ", "bold")
        out.append(lane.state.value, state_color(lane.state))
        out.append(f" {lane_dollars(lane)}", theme.MUTED)
        out.append(" · ")
        out.append(untrusted(ch.name, one_line=True), "bold")
        return out
    out.append(f"{lane.id} · ", "bold")
    out.append(untrusted(ch.name, one_line=True), "bold")
    out.append(f"  {untrusted(ch.category, one_line=True)} {ch.points} · ", theme.MUTED)
    out.append(untrusted(lane.model, one_line=True), theme.CYAN)
    out.append(" · ")
    out.append(lane.state.value, state_color(lane.state))
    spent = lane_dollars(lane) + (" (this turn's cost comes when it ends)" if lane.dollars_later else "")
    out.append(f" · turn {lane.turns} · {fmt.tokens(lane.tokens)} tok · {spent}", theme.MUTED)
    if not lane.finished:
        out.append(f" · idle {fmt.duration(lane.idle(deck.now))}", theme.MUTED)
    return out


def plan_line(deck: Deck, lane: Lane) -> Text:
    return Text.assemble(("plan ", theme.MUTED), untrusted(lane_text(deck, lane, lane.plan or "-"), one_line=True))


def transcript_lines(deck: Deck, lane: Lane, action: Action) -> list[Text]:
    """One entry of `lane`'s log as transcript lines, its text and output as the lane's
    transcript keeps them (lane_text)."""
    text = untrusted(lane_text(deck, lane, action.text), one_line=True)
    output = lane_text(deck, lane, action.output)
    if action.kind is ActionKind.STEP:
        lines = [Text.assemble(("⏺ ", theme.GREEN), (text, "bold"))]
        if output:
            lines.append(Text.assemble(("  ⎿  ", theme.MUTED), (untrusted(output, one_line=True), theme.MUTED)))
        return lines
    if action.kind is ActionKind.MESSAGE:
        return [Text.assemble(("› you  ", f"bold {theme.ACCENT}"), (text, theme.ACCENT))]
    if action.kind is ActionKind.PLAYER:
        who = "› autopilot  " if action.by is Actor.AUTOPILOT else "› you  "  # an intervention by rule is not yours
        lines = [Text.assemble((who, f"bold {theme.ACCENT}"), (text, f"italic {theme.ACCENT}"))]
        lines += [Text.assemble(("       ", ""), (untrusted(line, one_line=True), theme.MUTED)) for line in output.splitlines()]
        return lines
    if action.kind is ActionKind.ALERT:
        style = alert_style(action.alert)
        return [
            Text.assemble(("▲ ", style), (text, style)),
            Text.assemble(("  ", ""), (untrusted(output, one_line=True), theme.TEXT)),
        ]
    if action.kind is ActionKind.APPROVAL:
        return [Text.assemble(("◆ waiting for you: ", f"bold {theme.PURPLE}"), (text, theme.PURPLE))]
    return [Text.assemble(("· flightdeck  ", f"bold {theme.BLUE}"), (text, theme.MUTED))]


# ---------------------------------------------------------------------- the calm transcript (details off)

SAYS = "says: "  # how a step that is the model's own words starts (agent/driver.py: _step, agent/external.py: report_text)
_ENTRY_KIND = {
    ActionKind.MESSAGE: "message",
    ActionKind.PLAYER: "player",
    ActionKind.NOTE: "note",
    ActionKind.ALERT: "alert",
    ActionKind.APPROVAL: "approval",
}


@dataclass(frozen=True)
class Entry:
    """One entry of the calm transcript: one action of the lane's log, or a run of tool calls."""

    first: int  # the index of its first action in the lane's log: its key, which stays as a run grows
    kind: str  # calls | says | message | player | note | alert | approval
    actions: tuple[Action, ...]


def _is_call(action: Action) -> bool:
    """A tool call: a step that is not the model's own words."""
    return action.kind is ActionKind.STEP and not action.text.startswith(SAYS)


def calls_of(action: Action) -> tuple[Call, ...]:
    """The tool calls of a step: every call of its turn (flightdeck's own loop keeps them), or
    the step itself as one call (a coding-agent CLI's lane reports each call as a step)."""
    return action.calls or (Call(action.text, action.output),)


def entries(actions: Sequence[Action]) -> list[Entry]:
    """A lane's log as the entries the calm transcript shows, in order. Consecutive tool calls
    are one entry (a run); anything else (the model's words, a note, an alert, an approval,
    the player's message or intervention) is an entry of its own and ends the run."""
    out: list[Entry] = []
    i = 0
    while i < len(actions):
        action = actions[i]
        if not _is_call(action):
            kind = "says" if action.kind is ActionKind.STEP else _ENTRY_KIND[action.kind]
            out.append(Entry(i, kind, (action,)))
            i += 1
            continue
        end = i
        while end < len(actions) and _is_call(actions[end]):
            end += 1
        out.append(Entry(i, "calls", tuple(actions[i:end])))
        i = end
    return out


def _first_line(text: str) -> tuple[str, int]:
    """The first line of a text folded to one (untrusted(one_line=True), by this console or by
    the lane's runtime before it), and how many lines it has after that one. Blank lines at
    either end are not lines of it."""
    lines = [line.strip() for line in text.split(NEWLINE.strip())]
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()
    return (lines[0][:LINE_CHARS], len(lines) - 1) if lines else ("", 0)


def _more_lines(count: int) -> str:
    return f" …+{count} line{'' if count == 1 else 's'}"


def _call_row(deck: Deck, lane: Lane, call: Call, out: Text) -> None:
    """One tool call on one row: the first line of the call, then of its output, each with
    how many lines more it has."""
    first, more = _first_line(untrusted(lane_text(deck, lane, call.text), one_line=True))
    out.append(first, "bold")
    if more:
        out.append(_more_lines(more), theme.MUTED)
    first, more = _first_line(untrusted(lane_text(deck, lane, call.output), one_line=True))
    if first:
        out.append(f" → {first}", theme.MUTED)
        if more:
            out.append(_more_lines(more), theme.MUTED)


def entry_text(deck: Deck, lane: Lane, entry: Entry) -> Text:
    """One entry of the calm transcript, its text as the lane's transcript keeps it (lane_text).
    Each line of it is one row, which the view cuts at its edge: a run of tool calls is two
    (how many, and the last one, which is what the lane is doing now), anything else is one,
    with how many lines more it has. The model's words are the exception: the view wraps them."""
    action = entry.actions[0]
    out = Text()
    if entry.kind == "calls":
        calls = [call for step in entry.actions for call in calls_of(step)]
        out.append("⏺ ", theme.GREEN)
        if len(calls) > 1:
            out.append(f"{len(calls)} tool calls", "bold")
            out.append("\n  ⎿ ", theme.MUTED)
        _call_row(deck, lane, calls[-1], out)
        return out
    if entry.kind == "message":
        return transcript_lines(deck, lane, action)[0]
    if entry.kind == "player":
        out = transcript_lines(deck, lane, action)[0]
        more = len(action.output.splitlines())
        if more:
            out.append(_more_lines(more), theme.MUTED)
        return out
    text = untrusted(lane_text(deck, lane, action.text), one_line=True)
    if entry.kind == "says":
        return out.append("⏺ ", theme.TEXT).append(text.removeprefix(SAYS), theme.TEXT)
    if entry.kind == "approval":
        return out.append(f"◆ asked you · turn {action.turn}: {text}", theme.MUTED)
    first, more = _first_line(text)
    if entry.kind == "alert":
        style = alert_style(action.alert)
        return out.append("▲ ", style).append(first, style).append(f" alert · turn {action.turn}", theme.MUTED)
    out.append("· ", f"bold {theme.BLUE}").append(first, theme.MUTED)  # flightdeck's note
    if more:
        out.append(_more_lines(more), theme.MUTED)
    return out


# ---------------------------------------------------------------------- /copy: a lane's text for the clipboard

COPY_WHAT = ("output", "command", "flag", "all")  # what /copy takes; alone it is `output`
SHELL_MARK = "$ "  # how every runtime starts the line of a shell call


class NothingToCopy(Exception):
    """The lane has nothing of what /copy was asked for; the message says so."""


def _lines(text: str) -> str:
    return _count(len(text.splitlines()), "line", "lines")


def lane_copy(deck: Deck, lane: Lane, what: str) -> tuple[str, str]:
    """What /copy puts on the clipboard for `lane`, and what the status line calls it
    ("L01's last output: 38 lines"). NothingToCopy when the lane has none of it.

    `output`: the output of the lane's last tool call that printed something, as its
    transcript keeps it (the longer excerpt of a call of flightdeck's own loop, else the
    step's output), with real newlines. `command`: that call's line (when no call has printed
    anything, the last call's), its folded newlines real again and without the mark of a shell
    call, so it can be pasted into a shell. `flag`: the flag that waits for the player's
    approval, else the newest flag the run knows for the lane's challenge. `all`: every line of
    the transcript in detail (transcript_lines).

    Each is as the console shows the lane's text: no value of anything shaped like a
    credential (lane_text; the flags the run knows stay), control and invisible characters
    made visible (text.untrusted), so nothing reaches a paste that the screen did not show."""
    if what == "all":
        text = "\n".join(line.plain for action in lane.actions for line in transcript_lines(deck, lane, action))
        if not text:
            raise NothingToCopy(f"{lane.id} has nothing in its transcript yet")
        return text, f"{lane.id}'s transcript: {_lines(text)}"
    if what == "flag":
        waiting = lane.pending.flag if lane.pending is not None else None
        flag = waiting or next(iter(reversed(known_flags(deck, lane.challenge_id))), "")
        if not flag:
            raise NothingToCopy(f"{lane.id} has no flag yet")
        return untrusted(flag), f"{lane.id}'s flag"
    # (the call, whether it is the step itself: a coding-agent CLI's lane, whose runtime folded the newlines of its output)
    calls = [(call, not step.calls) for step in lane.actions if _is_call(step) for call in calls_of(step)]
    printed = [(call, folded) for call, folded in calls if call.output.strip()]
    if what == "output":
        if not printed:
            raise NothingToCopy(f"{lane.id} has no output yet")
        call, folded = printed[-1]
        text = lane_text(deck, lane, call.output)
        text = untrusted(text.replace(NEWLINE, "\n") if folded else text)
        return text, f"{lane.id}'s last output: {_lines(text)}"
    if not calls:
        raise NothingToCopy(f"{lane.id} has made no tool call yet")
    call, _ = (printed or calls)[-1]
    text = untrusted(lane_text(deck, lane, call.text).replace(NEWLINE, "\n").removeprefix(SHELL_MARK))
    return text, f"{lane.id}'s last command: {_lines(text)}"


def suggestion_command(key: str, text: str, lane: str | None = None, *, show_lane: bool = True) -> str | None:
    """The command an alert's suggested key stands for, e.g. /redirect <text>. The lane id
    is left out when `show_lane` is False, unless the text starts with a word that would
    read as a lane id (a hint "L02 is a decoy" must not go to L02)."""
    name = KEY_COMMAND.get(key)
    if name is None:
        return None
    first = text.split(" ", 1)[0] if text else ""
    named = lane if lane and (show_lane or lane_id(first) is not None) else None
    return " ".join([f"/{name}"] + ([named] if named else []) + ([text] if text else []))


def card_border(lane: Lane) -> str:
    """The colour of the border of `lane`'s "needs you now" card: the most urgent alert's that
    wants an answer, else an approval's, else the plain one (a message not read yet, an alert
    that needs no answer). "" when the lane has no card: it has ended, or nothing is open on it."""
    if lane.finished or not (lane.alerts or lane.pending is not None or lane.hints):
        return ""
    top = top_answerable(lane)
    if top is not None:
        return theme.alert_colors(top.kind)[1]
    return theme.PURPLE if lane.pending is not None else theme.BORDER


def now_card(deck: Deck, lane: Lane, *, compact: bool = False, simple: bool = False, calm: bool = False,
             width: int | None = None) -> RenderableType:
    """What the lane needs from the player right now, with the answers as commands: the
    approval it waits for first, then every open alert with its reason and its suggestions,
    then the messages it has not read yet. In the compact layout each answer is one row, its
    number first and its command cut at the edge: the reasons wrap, and every answer's number
    stays on the card. In the simple layout (`simple`) a lane that needs nothing has no card:
    an empty Text, and a lane that has ended says esc goes back to the lanes (that layout's
    word for the fleet). `calm`: the rows of calm_card, as Text; the view draws their border
    (card_border), and `width` is the cells a row has in it."""
    one_row = {"no_wrap": True, "overflow": "ellipsis"} if compact else {}
    if lane.finished:
        return Text.assemble(
            (f"{lane.state.value}: ", f"bold {state_color(lane.state)}"),
            (untrusted(lane_text(deck, lane, lane.result), one_line=True), theme.TEXT),
            (f"   this lane has ended; esc goes back to the {'lanes' if simple else 'fleet'}", theme.MUTED),
        )
    border = card_border(lane)
    if not border:
        if simple:
            return Text("")
        return Text("Nothing needs you on this lane. Type below to message it, or / for commands.", theme.MUTED)
    if calm:
        return calm_card(deck, lane, width)
    rows: list[RenderableType] = []
    numbered = {(answer.key, answer.text): answer.number for answer in quick_answers(lane)}
    top = top_answerable(lane)
    if lane.pending is not None:  # first: its numbers are the ones a digit answers, and the first rows are never the ones cut
        yes, no = PENDING_ANSWERS[lane.pending.kind]
        rows.append(Text.assemble(("◆ waiting for you: ", f"bold {theme.PURPLE}"), (untrusted(lane_text(deck, lane, lane.pending.detail), one_line=True), theme.TEXT)))
        indent = " " if compact else "   "
        rows.append(Text.assemble((indent, ""), _number("1"), ("/approve", f"bold {theme.ACCENT}"), (f"   {yes}", theme.MUTED), **one_row))
        rows.append(Text.assemble((indent, ""), _number("0"), ("/decline", f"bold {theme.ACCENT}"), (f"   {no}", theme.MUTED), **one_row))
        for later in lane.waiting:
            rows.append(Text.assemble(("   then: ", theme.MUTED), (untrusted(lane_text(deck, lane, later.detail), one_line=True), theme.MUTED)))
    for alert in sorted(lane.alerts, key=lambda a: ALERT_URGENCY[a.kind]):
        label = Text.assemble(("▲ ", alert_style(alert.kind)), (alert.kind.label, alert_style(alert.kind)), ("  ", ""))
        if alert.kind in INFORMATIONAL_ALERTS:
            label.append(untrusted(lane_text(deck, lane, alert.reason), one_line=True), theme.MUTED)
            rows.append(label)
            continue
        label.append(untrusted(lane_text(deck, lane, alert.reason), one_line=True), theme.TEXT)
        rows.append(label)
        for s in alert.suggestions:
            if s.key in ("a", "d") and lane.pending is not None:
                continue  # the approval's rows above say it
            command = suggestion_command(s.key, lane_text(deck, lane, s.text), lane.id, show_lane=False)
            number = numbered.get((s.key, s.text)) if alert is top else None
            line = Text(" " if compact else "   ", **one_row)
            line.append_text(_number(number))
            label = untrusted(s.label, one_line=True)
            if command:
                line.append(untrusted(command, one_line=True), f"bold {theme.ACCENT}")
                line.append(f"   {label.lower()}", theme.MUTED)
            else:
                line.append(label, theme.MUTED)
            rows.append(line)
        if alert is top and alert.kind in COURSE_ALERTS:  # what /dismiss would take down
            rows.append(Text.assemble(("     " if compact else "       ", ""), ("/dismiss", f"bold {theme.ACCENT}"),
                                      ("   not a problem: take the alert down, the lane carries on", theme.MUTED), **one_row))
    for hint in lane.hints:
        rows.append(Text.assemble(("› sent, not read yet: ", theme.MUTED), (untrusted(lane_text(deck, lane, hint), one_line=True), theme.ACCENT)))
    if top is not None or lane.pending is not None:
        rows.append(Text("a number answers (chat box empty)" if compact else
                         "press a number to answer (chat box empty), / to pick a command, or write a message", theme.MUTED))
    return Panel(Group(*rows), box=box.ROUNDED, border_style=border, padding=(0, 1), title=Text("needs you now", "bold"), title_align="left")


# ---------------------------------------------------------------------- the calm card (details off)

ALSO_WORDS = {  # an alert that is open beside the card's question, in a word or two
    AlertKind.LOOP: "looping",
    AlertKind.EFFORT: "past its effort budget",
    AlertKind.HINT: "ignores the hint",
    AlertKind.DIRECTION: "wrong direction",
    AlertKind.STALL: "stalled",
    AlertKind.BUDGET: "near its cap",
    AlertKind.FLAG: "a flag to check",
    AlertKind.TEAMMATE: "teammate",
}
_ASKED_BY = {  # the alert an approval is about: the approval is the question, so the alert is not named beside it
    PendingKind.BUDGET: AlertKind.BUDGET,
    PendingKind.SUBMIT: AlertKind.FLAG,
    PendingKind.CONFIRM: AlertKind.FLAG,
}
CALM_ANSWERS = 3  # the numbered answers the calm card shows; the rest are counted
CALM_QUOTE = 48  # characters of the text an answer sends that the calm card quotes
CALM_QUOTE_MIN = 12  # in a card too narrow for that, the quotes shorten to this; then there are none
SENDS_TEXT = ("h", "r", "f")  # the answers that send their suggested text at once (FlightdeckApp.answer)


def _count(count: int, one: str, many: str) -> str:
    return f"{count} {one if count == 1 else many}"


def _shows_all(out: Text) -> None:
    """After a row that leaves something out: the key that shows the full card."""
    out.append("   ")
    out.append("ctrl+o", f"bold {theme.ACCENT}")
    out.append(" shows all", theme.MUTED)


def calm_card(deck: Deck, lane: Lane, width: int | None = None) -> Text:
    """The "needs you now" card with details off: three rows at most, each cut at the edge by
    the view, and never a list of commands (the full card has them: ctrl+o).

    Row 1 is the question: the approval the lane waits for, else its most urgent alert that
    wants an answer, with its reason. Row 2 is its numbered answers, in the order and with the
    numbers of quick_answers, so a digit answers what row 1 asks; an answer that sends a text
    at once quotes the start of it. Row 3, only when something else is open, names it: the
    other alerts in a word or two each, further approvals, messages the lane has not read yet.

    `width`: the cells a row has. The quotes of row 2 shorten until the row fits, and go when
    CALM_QUOTE_MIN characters of each do not fit either: the edge would cut the answers after
    the first quote, and their numbers with them.

    With no question (no approval, no alert that wants an answer): an alert that needs no
    answer as the full card shows it, and the message not read yet, or how many there are.
    Empty when nothing is open on the lane.

    Every text of the lane's on it (the approval's detail too, which a lane words itself) is as
    the lane's transcript keeps it: lane_line."""
    pending, top = lane.pending, top_answerable(lane)
    alerts = sorted(lane.alerts, key=lambda a: ALERT_URGENCY[a.kind])
    rows: list[Text] = []
    if pending is None and top is None:
        for alert in alerts:
            rows.append(Text.assemble((f"▲ {alert.kind.label}  ", alert_style(alert.kind)), (lane_line(deck, lane, alert.reason), theme.MUTED)))
        if len(lane.hints) == 1:
            rows.append(Text.assemble(("› sent, not read yet: ", theme.MUTED), (lane_line(deck, lane, lane.hints[0]), theme.ACCENT)))
        elif lane.hints:
            unread = Text(f"› {len(lane.hints)} messages sent, not read yet", theme.MUTED)
            _shows_all(unread)
            rows.append(unread)
        return Text("\n").join(rows)
    answers = Text()
    if pending is not None:
        asked = _ASKED_BY.get(pending.kind)
        rows.append(Text.assemble(("◆ waiting for you: ", f"bold {theme.PURPLE}"), (lane_line(deck, lane, pending.detail), theme.TEXT)))
        # in the approval's own words: a flag's answer in quick_answers is the detail, which row 1 has
        for answer, label in zip(quick_answers(lane), PENDING_ANSWERS[pending.kind]):
            answers.append("   " if answers else "  ")
            answers.append(answer.number, f"bold {theme.ACCENT}")
            answers.append(f" {label}", theme.MUTED)
    else:
        asked = top.kind
        rows.append(Text.assemble((f"▲ {top.kind.label}: ", alert_style(top.kind)), (lane_line(deck, lane, top.reason), theme.TEXT)))
        numbered = quick_answers(lane)
        quotes = {answer.number: lane_line(deck, lane, answer.text)  # cut after the credentials are out: no part of one is left
                  for answer in numbered[:CALM_ANSWERS] if answer.text and answer.key in SENDS_TEXT}

        def row(quoted: int) -> Text:
            out = Text()
            for answer in numbered[:CALM_ANSWERS]:
                out.append("   " if out else "  ")
                out.append(answer.number, f"bold {theme.ACCENT}")
                out.append(f" {untrusted(answer.label, one_line=True).lower()}", theme.MUTED)
                quote = quotes.get(answer.number, "")
                if quote and quoted:
                    out.append(f' "{quote[:quoted]}{"…" if len(quote) > quoted else ""}"', theme.TEXT)
            if len(numbered) > CALM_ANSWERS:
                out.append(f"   +{len(numbered) - CALM_ANSWERS} more", theme.MUTED)
            if top.kind in COURSE_ALERTS:  # what /dismiss would take down
                out.append("   " if out else "  ")
                out.append("/dismiss", f"bold {theme.ACCENT}")
                out.append(" not a problem", theme.MUTED)
            return out

        quoted = CALM_QUOTE
        answers = row(quoted)
        while width is not None and quotes and quoted and answers.cell_len > width:
            quoted = quoted - 1 if quoted > CALM_QUOTE_MIN else 0
            answers = row(quoted)
    if answers:
        rows.append(answers)
    also = [ALSO_WORDS[kind] for kind in dict.fromkeys(alert.kind for alert in alerts) if kind is not asked]
    if pending is not None and lane.waiting:
        also.append(f"{_count(len(lane.waiting), 'more approval', 'more approvals')} after this one")
    if lane.hints:
        also.append(f"{_count(len(lane.hints), 'message', 'messages')} it has not read yet")
    if also:
        last = Text(f"  also: {' · '.join(also)}", theme.MUTED)
        _shows_all(last)
        rows.append(last)
    return Text("\n").join(rows)


def _number(number: str | None) -> Text:
    """A quick answer's number as a chip and a space, or the same width blank."""
    if number is None:
        return Text("    ")
    chip = theme.key_chip(number)
    chip.append(" ")
    return chip


def file_label(change: FileChange) -> Text:
    out = Text(no_wrap=True, overflow="ellipsis")
    out.append(untrusted(change.path, one_line=True), "bold")
    out.append(f"  +{change.added}", theme.GREEN)
    out.append(f" −{change.removed}", theme.RED)
    status = "new" if change.status == "added" else untrusted(change.status, one_line=True)
    out.append(f"  {status} · turn {change.turn}", theme.MUTED)
    return out


def diff_view(deck: Deck, lane: Lane, change: FileChange) -> RenderableType:
    """The diff of a file `lane` changed, as its transcript keeps it (lane_text)."""
    return Syntax(untrusted(lane_text(deck, lane, change.diff)), "diff", theme=theme.active().syntax, background_color=theme.PAGE, word_wrap=False)


def needing(deck: Deck, exclude: str | None = None) -> list[Lane]:
    return [lane for lane in deck.needing() if lane.id != exclude]


def _need_chip(lane: Lane) -> Text:
    top = top_answerable(lane)
    if top is not None:
        fg, bg = theme.alert_colors(top.kind)
        tag = top.kind.tag
    else:
        fg, bg = theme.pending_colors()
        tag = PENDING_TAG[lane.pending.kind] if lane.pending else "?"
    chip = theme.chip(f"{lane.id} {tag}", fg, bg)
    chip.stylize(Style(meta={"@click": f"app.open_lane('{lane.id}')"}))
    return chip


def others_strip(deck: Deck, lane: Lane, *, compact: bool = False, simple: bool = False) -> Text:
    """The other lanes that need the player, each a chip that opens it. With none: a line that
    says so, or in the simple layout (`simple`) nothing."""
    others = needing(deck, exclude=lane.id)
    out = Text(no_wrap=True, overflow="ellipsis")
    if not others:
        if not simple:
            out.append("No other lane needs you.", theme.MUTED)
        return out
    if compact:  # the key first: the chips are what the edge cuts
        out.append(f"{len(others)} more need{'' if len(others) > 1 else 's'} you (ctrl+n): ", theme.MUTED)
        for other in others[:8]:
            out.append_text(_need_chip(other))
            out.append(" ")
        return out
    out.append(f"{len(others)} other lane{'s' if len(others) > 1 else ''} need{'' if len(others) > 1 else 's'} you: ", theme.MUTED)
    for other in others[:8]:
        out.append_text(_need_chip(other))
        out.append(" ")
    if len(others) > 8:
        out.append(f"+{len(others) - 8} more ", theme.MUTED)
    out.append("  ctrl+n next", theme.MUTED)
    return out
