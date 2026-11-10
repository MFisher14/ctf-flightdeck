"""Rendering for the console: header, board rows, lane rows and the detail pane.

Everything that comes from a challenge or a lane (names, descriptions, commands,
tool output, flags) is untrusted text. It is always wrapped in rich.text.Text and never
parsed as markup, so text like "[@click=app.quit]" or "flag{[/]}" shows literally
and cannot steer the console.
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

from .. import fmt
from ..core.attention import ALERT_URGENCY, SortMode
from ..core.deck import Deck
from ..core.model import (
    ME,
    AlertKind,
    Actor,
    Challenge,
    ChallengeStatus,
    Lane,
    LaneState,
    PendingKind,
)

CATEGORY_ORDER = ("web", "for", "rev", "pwn", "cry", "misc", "osint")

ALERT_STYLE = {
    AlertKind.FLAG: "bold green",
    AlertKind.BUDGET: "bold yellow",
    AlertKind.TEAMMATE: "bold cyan",
}
COURSE_STYLE = "bold red"

STATE_STYLE = {
    LaneState.RUNNING: "green",
    LaneState.WAITING: "bold magenta",
    LaneState.PAUSED: "yellow",
    LaneState.TAKEOVER: "bold cyan",
    LaneState.SOLVED: "bold green",
    LaneState.KILLED: "red",
    LaneState.STOPPED: "dim",
    LaneState.GAVE_UP: "dim",
}

BOARD_MARK = {
    ChallengeStatus.NEW: ("·", "dim"),
    ChallengeStatus.QUEUED: ("…", "dim"),
    ChallengeStatus.RUNNING: ("▶", "green"),
    ChallengeStatus.SOLVED: ("✓", "bold green"),
    ChallengeStatus.TEAMMATE: ("✓", "bold cyan"),
    ChallengeStatus.BLOCKED: ("✗", "red"),
    ChallengeStatus.PARKED: ("‖", "yellow"),
}

PENDING_TAG = {PendingKind.SUBMIT: "submit", PendingKind.BUDGET: "budget", PendingKind.LIVE_BOX: "box"}


def alert_style(kind: AlertKind) -> str:
    return ALERT_STYLE.get(kind, COURSE_STYLE)


def plain(value: object, style: str = "", *, justify: str | None = None) -> Text:
    """Literal text, never markup."""
    return Text(str(value), style=style, justify=justify, overflow="ellipsis", no_wrap=True)


# ---------------------------------------------------------------------- header


def header(deck: Deck, *, mock: str = "", clock_note: str = "") -> Text:
    cfg = deck.config
    tokens, dollars, unpriced = deck.totals()
    text = Text(no_wrap=True, overflow="ellipsis")
    text.append(" flightdeck ", "bold reverse")
    text.append(" ")
    text.append(cfg.event, "bold")
    if mock:
        text.append("  ")
        text.append(f" {mock} ", "bold black on yellow")
    sep = ("  │  ", "dim")
    text.append(*sep)
    text.append("team" if cfg.team else "solo", "bold cyan" if cfg.team else "bold")
    text.append(*sep)
    if cfg.containerized:
        text.append("docker", "bold")
    else:
        text.append("host", "bold yellow")
    text.append(*sep)
    text.append(f"lanes {len(deck.active_lanes())}/{cfg.max_lanes}")
    text.append(f" (queue {len(deck.queue)})", "bold" if deck.queue else "dim")
    text.append(*sep)
    text.append(f"tok {fmt.tokens(tokens)}")
    text.append(*sep)
    text.append(f"${fmt.dollars(dollars)}" + ("+" if unpriced else ""))
    text.append(*sep)
    text.append(fmt.clock(deck.now))
    if clock_note:
        text.append(f"  {clock_note}", "dim")
    return text


# ---------------------------------------------------------------------- board


BOARD_COLUMNS = (("cat", 4), ("name", 15), ("pts", 3), ("solv", 4), ("", 1), ("own", 5))


def board_order(challenges: list[Challenge]) -> list[Challenge]:
    def key(ch: Challenge):
        cat = CATEGORY_ORDER.index(ch.category) if ch.category in CATEGORY_ORDER else len(CATEGORY_ORDER)
        return (cat, ch.points, ch.name)

    return sorted(challenges, key=key)


def owner(deck: Deck, ch: Challenge) -> tuple[str, str]:
    """Who has the challenge, and what kind of owner that is: lane, me, mate or ""."""
    if ch.closed and ch.solved_by:
        if ch.status is ChallengeStatus.TEAMMATE:
            return ch.solved_by, "mate"
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


OWNER_STYLE = {"mate": "cyan", "me": "bold", "lane": "", "": ""}


def board_row(deck: Deck, ch: Challenge) -> tuple[Text, ...]:
    mark, mark_style = BOARD_MARK[ch.status]
    dim = "dim" if ch.status in (ChallengeStatus.SOLVED, ChallengeStatus.TEAMMATE, ChallengeStatus.BLOCKED) else ""
    own, kind = owner(deck, ch)
    own_style = OWNER_STYLE[kind]
    if ch.claimed_by == ME and kind == "lane":
        own = f"{own}*"  # ours, claimed for the team
    return (
        plain(ch.category, "dim"),
        plain(ch.name, dim),
        plain(ch.points, dim, justify="right"),
        plain(ch.solves, "dim", justify="right"),
        plain(mark, mark_style),
        plain(own, own_style),
    )


# ---------------------------------------------------------------------- lanes


LANE_COLUMNS = (
    ("!", 10),
    ("lane", 4),
    ("chall", 15),
    ("model", 6),
    ("state", 8),
    ("turns", 5),
    ("tok", 5),
    ("$", 5),
    ("idle", 4),
)
LAST_COLUMN = "last action"
FINISHED_ROW = "__finished__"


def attention_cell(lane: Lane) -> Text:
    if lane.alerts and not lane.finished:
        top = min(lane.alerts, key=lambda a: ALERT_URGENCY[a.kind])
        extra = f"+{len(lane.alerts) - 1}" if len(lane.alerts) > 1 else ""
        return plain(f"▲ {top.kind.tag}{extra}", alert_style(top.kind))
    if lane.pending is not None and not lane.finished:
        return plain(f"◆ {PENDING_TAG[lane.pending.kind]}", "bold magenta")
    return plain("")


def lane_row(deck: Deck, lane: Lane) -> tuple[Text, ...]:
    ch = deck.challenges[lane.challenge_id]
    now = deck.now
    dim = "dim" if lane.finished else ""
    idle = "-" if lane.finished else fmt.duration(lane.idle(now))
    return (
        attention_cell(lane),
        plain(lane.id, "bold" if not lane.finished else "dim"),
        plain(ch.name, dim),
        plain(lane.model, dim or "cyan"),
        plain(lane.state.value, STATE_STYLE[lane.state]),
        plain(lane.turns, dim, justify="right"),
        plain(fmt.tokens(lane.tokens), dim, justify="right"),
        plain(fmt.dollars(lane.dollars, short=True), dim, justify="right"),
        plain(idle, dim or ("yellow" if lane.idle(now) >= 600 else ""), justify="right"),
        plain(lane.last_action, "dim"),
    )


def finished_row(lanes: list[Lane], expanded: bool) -> tuple[Text, ...]:
    counts: dict[str, int] = {}
    for lane in lanes:
        counts[lane.state.value] = counts.get(lane.state.value, 0) + 1
    parts = " · ".join(f"{n} {state}" for state, n in counts.items())
    arrow = "▾" if expanded else "▸"
    hint = "enter to collapse" if expanded else "enter to expand"
    cells = [plain("")] * len(LANE_COLUMNS)
    cells[0] = plain(arrow, "bold dim")
    cells[2] = plain(f"{len(lanes)} finished", "bold dim")
    cells.append(plain(f"{parts}  ({hint})", "dim"))
    return tuple(cells)


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


def lanes_title(deck: Deck, sort: SortMode, query: str) -> Text:
    text = Text("lanes ", "bold")
    text.append(f"{len(deck.active_lanes())}/{deck.config.max_lanes}")
    text.append(f" · sort {sort.value}", "dim")
    if query:
        text.append(" · filter ", "dim")
        text.append(query, "bold yellow")
    return text


def board_title(deck: Deck) -> Text:
    challenges = list(deck.challenges.values())
    ours = sum(ch.status is ChallengeStatus.SOLVED for ch in challenges)
    mates = sum(ch.status is ChallengeStatus.TEAMMATE for ch in challenges)
    text = Text("board ", "bold")
    text.append(f"{len(challenges)}")
    text.append(f" · ✓ {ours}", "green")
    if deck.config.team:
        text.append(f" · team ✓ {mates}", "cyan")
    return text


# ---------------------------------------------------------------------- detail


def _grid() -> Table:
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold dim", width=9, no_wrap=True)
    grid.add_column(ratio=1)
    return grid


def lane_detail(deck: Deck, lane: Lane, *, recent: int = 5) -> RenderableType:
    ch = deck.challenges[lane.challenge_id]
    now = deck.now
    head = Text(no_wrap=False)
    head.append(f"{ch.category} {ch.points} pts · {ch.solves} solves · ", "dim")
    head.append(lane.model, "cyan")
    head.append(" · ")
    head.append(lane.state.value, STATE_STYLE[lane.state])
    head.append(f" · turn {lane.turns} · {fmt.tokens(lane.tokens)} tok · ${fmt.dollars(lane.dollars)}", "dim")
    if not lane.finished:
        head.append(f" · idle {fmt.duration(lane.idle(now))}", "dim")

    grid = _grid()
    if lane.finished:
        grid.add_row("result", Text(f"{lane.state.value}: {lane.result}", STATE_STYLE[lane.state]))
    grid.add_row("plan", Text(lane.plan or "-"))
    for alert in lane.alerts:
        line = Text()
        line.append(f"▲ {alert.kind.label}", alert_style(alert.kind))
        line.append(f" ({fmt.duration(max(0.0, now - alert.at))} ago): ", "dim")
        line.append(alert.reason)
        grid.add_row("alert", line)
        for s in alert.suggestions:
            if s.key == "a" and lane.pending is not None:
                continue  # the "waiting" row below says it
            hint = Text("  → ", "dim")
            if s.key:
                hint.append(f"[{s.key}] ", "bold reverse")
                hint.append(" ")
            hint.append(s.label, "bold")
            if s.text:
                hint.append(": ")
                hint.append(f"\"{s.text}\"", "italic")
            grid.add_row("", hint)
    if lane.pending is not None and not lane.finished:
        line = Text()
        line.append(f"◆ {lane.pending.detail}", "bold magenta")
        line.append("   press ", "dim")
        line.append("[a]", "bold reverse")
        line.append(" to approve", "dim")
        grid.add_row("waiting", line)
    for hint_text in lane.hints:
        grid.add_row("hint", Text.assemble(("queued for the next turn: ", "dim"), hint_text))
    actions = lane.actions[-recent:]
    for i, action in enumerate(actions):
        line = Text(no_wrap=True, overflow="ellipsis")
        line.append(f"t{action.turn:<3} ", "dim")
        if action.by is Actor.PLAYER:
            line.append("you: ", "bold yellow")
        elif action.by is Actor.DECK:
            line.append("flightdeck: ", "bold blue")
        else:
            line.append("$ ", "dim")
        line.append(action.text.splitlines()[0] if action.text else "")
        if action.output:
            line.append("  → ", "dim")
            line.append(action.output.splitlines()[0], "dim")
        grid.add_row("recent" if i == 0 else "", line)
    grid.add_row("found", Text(", ".join(lane.artifacts) or "-"))
    grid.add_row("files", Text(", ".join(ch.files) or "-", "dim"))
    meta = []
    if lane.parent:
        meta.append(f"fork of {lane.parent}")
    forks = [x.id for x in deck.lanes.values() if x.parent == lane.id]
    if forks:
        meta.append("forks: " + ", ".join(forks))
    if lane.attempt > 1:
        meta.append(f"attempt {lane.attempt}")
    used = lane.budget_used()
    if used is not None:
        cap = []
        if lane.token_cap:
            cap.append(f"{fmt.tokens(lane.tokens)} of {fmt.tokens(lane.token_cap)} tokens")
        if lane.dollar_cap:
            cap.append(f"${fmt.dollars(lane.dollars)} of ${fmt.dollars(lane.dollar_cap)}")
        meta.append(f"cap {', '.join(cap)} ({used:.0%})")
    if meta:
        grid.add_row("lane", Text(" · ".join(meta), "dim"))
    return Group(head, grid)


def challenge_detail(deck: Deck, ch: Challenge) -> RenderableType:
    head = Text()
    head.append(f"{ch.category} · {ch.points} pts · {ch.solves} solves · ", "dim")
    mark, style = BOARD_MARK[ch.status]
    head.append(f"{mark} {ch.status.value}", style)
    own, _ = owner(deck, ch)
    if own:
        head.append(f" · {own}", "dim")
    grid = _grid()
    grid.add_row("about", Text(ch.description or "-"))
    grid.add_row("files", Text((", ".join(ch.files) or "-") + (" · live instance" if ch.live else ""), "dim"))
    if ch.note:
        grid.add_row("note", Text(ch.note, "yellow"))
    if ch.claimed_by:
        grid.add_row("claim", Text("you" if ch.claimed_by == ME else ch.claimed_by, "bold"))
    lanes = [lane for lane in deck.lanes.values() if lane.challenge_id == ch.id]
    for i, lane in enumerate(sorted(lanes, key=lambda x: x.number)):
        line = Text()
        line.append(lane.id, "bold")
        line.append(f" {lane.model} ")
        line.append(lane.state.value, STATE_STYLE[lane.state])
        line.append(f" · {lane.turns} turns · {fmt.tokens(lane.tokens)} tok · ", "dim")
        line.append(lane.result or lane.last_action, "dim")
        grid.add_row("lanes" if i == 0 else "", line)
    if not lanes:
        grid.add_row("lanes", Text("queued" if deck.queued(ch.id) else "none", "dim"))
    return Group(head, grid)
