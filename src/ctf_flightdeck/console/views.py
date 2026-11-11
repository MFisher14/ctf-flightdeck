"""Rendering for the console: header, board and lane rows, the fleet's "why" line, and the
focus view's transcript, "needs you now" card, files and diff.

Everything that comes from a challenge or a lane (names, descriptions, commands, tool
output, flags, diffs) is untrusted. It goes through text.untrusted() and is wrapped in
rich Text, never parsed as markup, so "[@click=app.quit]" or an escape sequence shows
literally and cannot steer the console.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from rich import box
from rich.cells import cell_len, set_cell_size
from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.style import Style
from rich.syntax import Syntax
from rich.text import Text

from .. import fmt
from ..core.attention import ALERT_URGENCY, SortMode
from ..core.deck import Deck
from ..core.model import (
    INFORMATIONAL_ALERTS,
    ME,
    Action,
    ActionKind,
    Alert,
    AlertKind,
    Challenge,
    ChallengeStatus,
    Event,
    FileChange,
    Lane,
    LaneState,
    PendingKind,
)
from ..runrecord import L1 as BY_L1
from ..runrecord import Credit, EventLine, Solve, accepted
from ..text import untrusted
from . import theme
from .commands import KEY_COMMAND, lane_id

CATEGORY_ORDER = ("web", "for", "rev", "pwn", "cry", "misc", "osint")

STATE_COLOR = {
    LaneState.RUNNING: theme.GREEN,
    LaneState.WAITING: theme.PURPLE,
    LaneState.PAUSED: theme.YELLOW,
    LaneState.TAKEOVER: theme.CYAN,
    LaneState.SOLVED: theme.GREEN,
    LaneState.KILLED: theme.RED,
    LaneState.STOPPED: theme.MUTED,
    LaneState.GAVE_UP: theme.MUTED,
}

BOARD_MARK = {
    ChallengeStatus.NEW: ("·", theme.MUTED),
    ChallengeStatus.QUEUED: ("…", theme.MUTED),
    ChallengeStatus.RUNNING: ("▶", theme.GREEN),
    ChallengeStatus.SOLVED: ("✓", theme.GREEN),
    ChallengeStatus.TEAMMATE: ("✓", theme.CYAN),
    ChallengeStatus.BLOCKED: ("✗", theme.RED),
    ChallengeStatus.PARKED: ("‖", theme.YELLOW),
}

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


def safe(value: object, style: str | Style = "", *, justify: str | None = None) -> Text:
    """Untrusted text as one literal line: control characters made visible, never markup."""
    return Text(untrusted(str(value), one_line=True), style=style, justify=justify, overflow="ellipsis", no_wrap=True)


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


def header_facts(deck: Deck, mock: str = "") -> HeaderFacts:
    cfg = deck.config
    tokens, dollars, unpriced = deck.totals()
    return HeaderFacts(
        cfg.event, cfg.team, cfg.containerized, len(deck.active_lanes()), cfg.max_lanes, len(deck.queue),
        len(deck.needing()), deck.held, tokens, dollars, unpriced, deck.now, mock,
        later=any(lane.dollars_later for lane in deck.lanes.values()),
    )


HELD = "queue held"
HELD_WHY_MIN = 12  # cells: less room than this after the other pieces, and the header names no reason
WHY_OUTRANKS = 3  # pieces of this drop rank or more (the event's name, the clock, tokens, dollars) make room for it
HEADER_WORDS = {  # the pieces that can drop, as doctor names them (console/room.py)
    "event": "the event's name", "mock": "the mock tag", "runtime": "the runtime (docker or host)",
    "tokens": "tokens", "dollars": "dollars", "clock": "the event clock",
}


def header_pieces(facts: HeaderFacts) -> list[tuple[str, int, tuple[str, str, str, bool]]]:
    """(name, drop rank, segment) for each piece, in order. Rank 0 never drops; on a narrow
    terminal the highest rank drops first, the later piece first on a tie (D16)."""
    out: list[tuple[str, int, tuple[str, str, str, bool]]] = [
        ("flightdeck", 0, ("flightdeck", theme.WHITE, theme.BLUE, True)),
        ("event", 3, (untrusted(facts.event, one_line=True), theme.TEXT, theme.SEGMENT, True)),
    ]
    if facts.mock:
        out.append(("mock", 2, (facts.mock, theme.INK, theme.ACCENT, True)))
    out += [
        ("mode", 0, ("team" if facts.team else "solo", theme.CYAN if facts.team else theme.TEXT, theme.SEGMENT, True)),
        ("runtime", 1, ("docker", theme.TEXT, theme.SEGMENT, False) if facts.containerized else ("host", theme.INK, theme.YELLOW, True)),
        ("lanes", 0, (f"lanes {facts.lanes}/{facts.max_lanes} · queue {facts.queue}", theme.TEXT, theme.SEGMENT, False)),
    ]
    if facts.need:
        out.append(("need", 0, (f"▲ {facts.need} need you", theme.WHITE, theme.RED, True)))
    elif not facts.held:  # a held queue is not all clear: nothing starts until the player lifts it
        out.append(("need", 0, ("all clear", theme.MUTED, theme.SEGMENT, False)))
    if facts.held:
        out.append(("held", 0, (HELD, theme.INK, theme.YELLOW, True)))
    dollars = f"${fmt.dollars(facts.dollars)}" + ("+" if facts.unpriced else "") + (LATER if facts.later else "")  # as lane_dollars
    out += [
        ("tokens", 4, (f"tok {fmt.tokens(facts.tokens)}", theme.TEXT, theme.SEGMENT, False)),
        ("dollars", 4, (dollars, theme.TEXT, theme.SEGMENT, False)),
        ("clock", 3, (fmt.clock(facts.clock), theme.TEXT, theme.SEGMENT, False)),
    ]
    return out


def fit_header(facts: HeaderFacts, width: int) -> tuple[Text, list[str]]:
    """The header in `width` cells, and the names of the pieces it leaves out, in the order
    they drop. While the queue is held, why follows "queue held": the event's name, the clock,
    tokens and dollars give way to it (in their usual order), and it is cut to the room left."""
    pieces = header_pieces(facts)
    left_out: list[str] = []
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


def header(deck: Deck, *, mock: str = "", note: str = "", width: int = 200) -> Text:
    """The slanted header. Low-priority pieces drop out first when the terminal is narrow.
    While the queue is held it says so, never "all clear", and why, as room allows."""
    text, _ = fit_header(header_facts(deck, mock), width)
    if note and text.cell_len + len(note) + 2 <= width:
        text.append("  " + note, theme.MUTED)
    return text


# ---------------------------------------------------------------------- board

# (key, label, width, drop rank: 0 never, higher drops first). "name" stretches.
BOARD_COLUMNS = (
    ("cat", "cat", 5, 2),
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


OWNER_STYLE = {"mate": theme.CYAN, "me": "bold", "lane": "", "l1": theme.GREEN, "": ""}


def board_cells(deck: Deck, ch: Challenge) -> dict[str, Text]:
    mark, mark_color = BOARD_MARK[ch.status]
    dim = theme.MUTED if ch.status in (ChallengeStatus.SOLVED, ChallengeStatus.TEAMMATE, ChallengeStatus.BLOCKED) else ""
    own, kind = owner(deck, ch)
    if ch.claimed_by == ME and kind == "lane":
        own = f"{own}*"  # ours, and claimed for the team
    return {
        "cat": safe(ch.category, theme.MUTED),
        "name": safe(ch.name, dim),
        "pts": safe(ch.points, dim, justify="right"),
        "solv": safe(ch.solves, theme.MUTED, justify="right"),
        "mark": Text(mark, style=mark_color),
        "own": safe(own, OWNER_STYLE[kind]),
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
FINISHED_ROW = "__finished__"


def fit_columns(
    columns: tuple[tuple[str, str, int, int], ...],
    stretch: str,
    stretch_min: int,
    available: int,
    padding: int,
    shrink: dict[str, int] | None = None,
) -> list[tuple[str, str, int]]:
    """Drop columns by rank (highest first) until they fit `available` cells; the
    `stretch` column takes what is left. If the columns that never drop still do not
    fit, the `shrink` columns narrow, each down to its floor."""
    kept = [list(column) for column in columns]

    def needed() -> int:
        fixed = sum(width if key != stretch else stretch_min for key, _, width, _ in kept)
        return fixed + 2 * padding * len(kept)

    while needed() > available and any(rank for *_, rank in kept):
        worst = max(range(len(kept)), key=lambda i: (kept[i][3], i))
        kept.pop(worst)
    for key, floor in (shrink or {}).items():
        over = needed() - available
        for column in kept:
            if over > 0 and column[0] == key and column[2] > floor:
                cut = min(over, column[2] - floor)
                column[2] -= cut
                over -= cut
    spare = available - needed()
    return [(key, label, width if key != stretch else stretch_min + max(0, spare)) for key, label, width, _ in kept]


def attention_cell(lane: Lane, sending: bool = False) -> Text:
    """The lane's most urgent alert or approval; else, when `sending`, that a flag of it is on
    its way to the platform (nothing to answer: its answer comes back on its own)."""
    if lane.finished:
        return Text("")
    top = top_answerable(lane)
    if top is not None:
        cell = theme.chip(top.kind.tag, *theme.alert_colors(top.kind))
        extra = len(lane.alerts) - 1 + (1 if lane.pending is not None and top.kind is not AlertKind.FLAG and top.kind is not AlertKind.BUDGET else 0)
        if extra > 0:
            cell.append(f"+{extra}", theme.MUTED)
        return cell
    if lane.pending is not None:
        return theme.chip(PENDING_TAG[lane.pending.kind], *theme.PENDING_COLORS)
    if sending:
        return theme.chip("sending", theme.WHITE, theme.BLUE)
    if lane.alerts:
        return theme.chip(lane.alerts[0].kind.tag, *theme.alert_colors(lane.alerts[0].kind))
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


def lane_cells(deck: Deck, lane: Lane, selected: bool = False) -> dict[str, Text]:
    ch = deck.challenges[lane.challenge_id]
    dim = theme.MUTED if lane.finished else ""
    idle = lane.idle(deck.now)
    cost = lane_dollars(lane, short=True)
    return {
        "bar": Text("▌", style=theme.ACCENT) if selected else Text(" "),
        "!": attention_cell(lane, bool(deck.sending(lane.id))),
        "lane": Text(lane.id, style=theme.MUTED if lane.finished else "bold"),
        "chall": safe(ch.name, dim),
        "model": safe(lane.model, dim or theme.CYAN),
        "state": Text(lane.state.value, style=STATE_COLOR[lane.state]),
        "turns": Text(str(lane.turns), style=dim, justify="right"),
        "cost": Text(cost, style=dim or theme.MUTED, justify="right"),
        "idle": Text("-" if lane.finished else fmt.duration(idle), style=dim or (theme.ACCENT if idle >= 600 else ""), justify="right"),
        "last": safe(lane.last_action, theme.MUTED),
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
QUIT_SHOWN = 5  # lanes waiting for the player that the quit prompt names; the rest are counted


def quit_summary(deck: Deck, run_dir: str = "") -> Text:
    """What quitting would stop: the open lanes, what waits for the player, the queue; and
    what quitting does."""
    live = sorted((lane for lane in deck.lanes.values() if not lane.finished), key=lambda lane: lane.number)
    counts: dict[str, int] = {}
    for lane in live:
        word = OPEN_STATE_WORDS[lane.state]
        counts[word] = counts.get(word, 0) + 1
    out = Text()
    out.append(f"{len(live)} lane{'' if len(live) == 1 else 's'} still open", "bold")
    out.append(": " + ", ".join(f"{n} {word}" for word, n in counts.items()))
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
        [lane.id, ch.name, ch.category, lane.model, lane.state.value, lane.last_action, lane.plan]
        + [a.kind.tag for a in lane.alerts]
        + ([PENDING_TAG[lane.pending.kind]] if lane.pending else [])
    ).lower()
    return all(word in hay for word in query.lower().split())


def lanes_title(deck: Deck, sort: SortMode, query: str, *, board_hidden: bool = False) -> Text:
    text = Text("fleet ", "bold")
    text.append(f"{len(deck.active_lanes())}/{deck.config.max_lanes}")
    text.append(f" · sort {sort.value}", theme.MUTED)
    if board_hidden:
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


def lane_why(deck: Deck, lane: Lane) -> Text:
    """Two lines under the lane list: why the selected lane is flagged, and the answers."""
    out = Text(no_wrap=True, overflow="ellipsis")
    out.append("▌", theme.ACCENT)
    out.append(f"{lane.id} ", "bold")
    if lane.finished:
        out.append(f"{lane.state.value}: ", f"bold {STATE_COLOR[lane.state]}")
        out.append(untrusted(lane.result, one_line=True))
        out.append("\n  enter opens its transcript", theme.MUTED)
        return out
    top = top_answerable(lane)
    if top is not None:
        out.append(f"▲ {top.kind.label}: ", alert_style(top.kind))
        out.append(untrusted(top.reason, one_line=True))
        out.append("\n")
        out.append_text(_answers(lane, top))
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
        out.append(untrusted(lane.alerts[0].reason, one_line=True), theme.MUTED)
        out.append("\n  nothing to do   enter open", theme.MUTED)
        return out
    out.append("plan: ", theme.MUTED)
    out.append(untrusted(lane.plan or "-", one_line=True))
    out.append("\n  last: ", theme.MUTED)
    last = next((a for a in reversed(lane.actions) if a.kind is ActionKind.STEP), None)
    if last is not None:
        out.append(untrusted(last.text, one_line=True))
        if last.output:
            out.append(f" → {untrusted(last.output, one_line=True)}", theme.MUTED)
    out.append("   enter open", theme.MUTED)
    return out


def challenge_why(deck: Deck, ch: Challenge) -> Text:
    out = Text(no_wrap=True, overflow="ellipsis")
    mark, color = BOARD_MARK[ch.status]
    out.append(untrusted(ch.name, one_line=True), "bold")
    out.append(f"  {untrusted(ch.category, one_line=True)} {ch.points} · {ch.solves} solves · ", theme.MUTED)
    out.append(f"{mark} {ch.status.value}", color)
    if ch.status is ChallengeStatus.SOLVED:  # by whom, in full: the board's own column is narrow
        own, _ = owner(deck, ch)
        if own:
            out.append(f" by {untrusted(own, one_line=True)}", color)
    if ch.note:
        out.append(f" ({untrusted(ch.note, one_line=True)})", theme.YELLOW)
    out.append("\n  ")
    out.append(untrusted(ch.description or "-", one_line=True), theme.MUTED)
    out.append("   enter for more", theme.MUTED)
    return out


# ---------------------------------------------------------------------- focus view


def focus_title(deck: Deck, lane: Lane) -> Text:
    ch = deck.challenges[lane.challenge_id]
    out = Text()
    out.append(f"{lane.id} · ", "bold")
    out.append(untrusted(ch.name, one_line=True), "bold")
    out.append(f"  {untrusted(ch.category, one_line=True)} {ch.points} · ", theme.MUTED)
    out.append(untrusted(lane.model, one_line=True), theme.CYAN)
    out.append(" · ")
    out.append(lane.state.value, STATE_COLOR[lane.state])
    spent = lane_dollars(lane) + (" (this turn's cost comes when it ends)" if lane.dollars_later else "")
    out.append(f" · turn {lane.turns} · {fmt.tokens(lane.tokens)} tok · {spent}", theme.MUTED)
    if not lane.finished:
        out.append(f" · idle {fmt.duration(lane.idle(deck.now))}", theme.MUTED)
    return out


def plan_line(lane: Lane) -> Text:
    return Text.assemble(("plan ", theme.MUTED), untrusted(lane.plan or "-", one_line=True))


def transcript_lines(action: Action) -> list[Text]:
    """One log entry as transcript lines."""
    text = untrusted(action.text, one_line=True)
    if action.kind is ActionKind.STEP:
        lines = [Text.assemble(("⏺ ", theme.GREEN), (text, "bold"))]
        if action.output:
            lines.append(Text.assemble(("  ⎿  ", theme.MUTED), (untrusted(action.output, one_line=True), theme.MUTED)))
        return lines
    if action.kind is ActionKind.MESSAGE:
        return [Text.assemble(("› you  ", f"bold {theme.ACCENT}"), (text, theme.ACCENT))]
    if action.kind is ActionKind.PLAYER:
        lines = [Text.assemble(("› you  ", f"bold {theme.ACCENT}"), (text, f"italic {theme.ACCENT}"))]
        lines += [Text.assemble(("       ", ""), (untrusted(line, one_line=True), theme.MUTED)) for line in action.output.splitlines()]
        return lines
    if action.kind is ActionKind.ALERT:
        style = alert_style(action.alert)
        return [
            Text.assemble(("▲ ", style), (text, style)),
            Text.assemble(("  ", ""), (untrusted(action.output, one_line=True), theme.TEXT)),
        ]
    if action.kind is ActionKind.APPROVAL:
        return [Text.assemble(("◆ waiting for you: ", f"bold {theme.PURPLE}"), (text, theme.PURPLE))]
    return [Text.assemble(("· flightdeck  ", f"bold {theme.BLUE}"), (text, theme.MUTED))]


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


def now_card(deck: Deck, lane: Lane) -> RenderableType:
    """What the lane needs from the player right now, with the answers as commands."""
    if lane.finished:
        return Text.assemble(
            (f"{lane.state.value}: ", f"bold {STATE_COLOR[lane.state]}"),
            (untrusted(lane.result, one_line=True), theme.TEXT),
            ("   this lane has ended; esc goes back to the fleet", theme.MUTED),
        )
    rows: list[RenderableType] = []
    border = ""
    numbered = {(answer.key, answer.text): answer.number for answer in quick_answers(lane)}
    top = top_answerable(lane)
    for alert in sorted(lane.alerts, key=lambda a: ALERT_URGENCY[a.kind]):
        label = Text.assemble(("▲ ", alert_style(alert.kind)), (alert.kind.label, alert_style(alert.kind)), ("  ", ""))
        if alert.kind in INFORMATIONAL_ALERTS:
            label.append(untrusted(alert.reason, one_line=True), theme.MUTED)
            rows.append(label)
            continue
        border = border or theme.alert_colors(alert.kind)[1]
        label.append(untrusted(alert.reason, one_line=True), theme.TEXT)
        rows.append(label)
        for s in alert.suggestions:
            if s.key in ("a", "d") and lane.pending is not None:
                continue  # the approval lines below say it
            command = suggestion_command(s.key, s.text, lane.id, show_lane=False)
            number = numbered.get((s.key, s.text)) if alert is top else None
            line = Text("   ")
            line.append_text(_number(number))
            label = untrusted(s.label, one_line=True)
            if command:
                line.append(untrusted(command, one_line=True), f"bold {theme.ACCENT}")
                line.append(f"   {label.lower()}", theme.MUTED)
            else:
                line.append(label, theme.MUTED)
            rows.append(line)
    if lane.pending is not None:
        border = border or theme.PURPLE
        yes, no = PENDING_ANSWERS[lane.pending.kind]
        rows.append(Text.assemble(("◆ waiting for you: ", f"bold {theme.PURPLE}"), (untrusted(lane.pending.detail, one_line=True), theme.TEXT)))
        rows.append(Text.assemble(("   ", ""), _number("1"), ("/approve", f"bold {theme.ACCENT}"), (f"   {yes}", theme.MUTED)))
        rows.append(Text.assemble(("   ", ""), _number("0"), ("/decline", f"bold {theme.ACCENT}"), (f"   {no}", theme.MUTED)))
        for later in lane.waiting:
            rows.append(Text.assemble(("   then: ", theme.MUTED), (untrusted(later.detail, one_line=True), theme.MUTED)))
    for hint in lane.hints:
        rows.append(Text.assemble(("› sent, not read yet: ", theme.MUTED), (untrusted(hint, one_line=True), theme.ACCENT)))
    if not rows:
        return Text("Nothing needs you on this lane. Type below to message it, or / for commands.", theme.MUTED)
    if border:
        rows.append(Text("press a number to answer (chat box empty), / to pick a command, or write a message", theme.MUTED))
    return Panel(Group(*rows), box=box.ROUNDED, border_style=border or theme.BORDER, padding=(0, 1), title=Text("needs you now", "bold"), title_align="left")


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


def diff_view(change: FileChange) -> RenderableType:
    return Syntax(untrusted(change.diff), "diff", theme="monokai", background_color=theme.PAGE, word_wrap=False)


def needing(deck: Deck, exclude: str | None = None) -> list[Lane]:
    return [lane for lane in deck.needing() if lane.id != exclude]


def _need_chip(lane: Lane) -> Text:
    top = top_answerable(lane)
    if top is not None:
        fg, bg = theme.alert_colors(top.kind)
        tag = top.kind.tag
    else:
        fg, bg = theme.PENDING_COLORS
        tag = PENDING_TAG[lane.pending.kind] if lane.pending else "?"
    chip = theme.chip(f"{lane.id} {tag}", fg, bg)
    chip.stylize(Style(meta={"@click": f"app.open_lane('{lane.id}')"}))
    return chip


def others_strip(deck: Deck, lane: Lane) -> Text:
    others = needing(deck, exclude=lane.id)
    out = Text(no_wrap=True, overflow="ellipsis")
    if not others:
        out.append("No other lane needs you.", theme.MUTED)
        return out
    out.append(f"{len(others)} other lane{'s' if len(others) > 1 else ''} need{'' if len(others) > 1 else 's'} you: ", theme.MUTED)
    for other in others[:8]:
        out.append_text(_need_chip(other))
        out.append(" ")
    if len(others) > 8:
        out.append(f"+{len(others) - 8} more ", theme.MUTED)
    out.append("  ctrl+n next", theme.MUTED)
    return out
