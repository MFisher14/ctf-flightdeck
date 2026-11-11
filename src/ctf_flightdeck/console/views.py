"""Rendering for the console: header, board and lane rows, the fleet's "why" line, and the
focus view's transcript, "needs you now" card, files and diff.

Everything that comes from a challenge or a lane (names, descriptions, commands, tool
output, flags, diffs) is untrusted. It goes through text.untrusted() and is wrapped in
rich Text, never parsed as markup, so "[@click=app.quit]" or an escape sequence shows
literally and cannot steer the console.
"""

from __future__ import annotations

from rich import box
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
    FileChange,
    Lane,
    LaneState,
    PendingKind,
)
from ..text import untrusted
from . import theme
from .commands import KEY_COMMAND

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

PENDING_TAG = {PendingKind.SUBMIT: "submit", PendingKind.BUDGET: "budget", PendingKind.LIVE_BOX: "box"}


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


# ---------------------------------------------------------------------- header


def header(deck: Deck, *, mock: str = "", note: str = "", width: int = 200) -> Text:
    """The slanted header. Low-priority pieces drop out first when the terminal is narrow."""
    cfg = deck.config
    tokens, dollars, unpriced = deck.totals()
    need = len(deck.needing())
    pieces: list[tuple[int, tuple[str, str, str, bool]]] = [
        (0, ("flightdeck", theme.WHITE, theme.BLUE, True)),
        (3, (untrusted(cfg.event, one_line=True), theme.TEXT, theme.SEGMENT, True)),
    ]
    if mock:
        pieces.append((2, (mock, theme.INK, theme.ACCENT, True)))
    pieces += [
        (0, ("team" if cfg.team else "solo", theme.CYAN if cfg.team else theme.TEXT, theme.SEGMENT, True)),
        (1, ("docker", theme.TEXT, theme.SEGMENT, False) if cfg.containerized else ("host", theme.INK, theme.YELLOW, True)),
        (0, (f"lanes {len(deck.active_lanes())}/{cfg.max_lanes} · queue {len(deck.queue)}", theme.TEXT, theme.SEGMENT, False)),
        (0, (f"▲ {need} need you", theme.WHITE, theme.RED, True) if need else ("all clear", theme.MUTED, theme.SEGMENT, False)),
        (4, (f"tok {fmt.tokens(tokens)}", theme.TEXT, theme.SEGMENT, False)),
        (4, (f"${fmt.dollars(dollars)}" + ("+" if unpriced else ""), theme.TEXT, theme.SEGMENT, False)),
        (3, (fmt.clock(deck.now), theme.TEXT, theme.SEGMENT, False)),
    ]
    text = theme.segments([part for _, part in pieces])
    while text.cell_len > width and any(rank for rank, _ in pieces):
        drop = max(range(len(pieces)), key=lambda i: (pieces[i][0], i))
        pieces.pop(drop)
        text = theme.segments([part for _, part in pieces])
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


OWNER_STYLE = {"mate": theme.CYAN, "me": "bold", "lane": "", "": ""}


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
    ("cost", "cost", 6, 2),
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


def attention_cell(lane: Lane) -> Text:
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
    if lane.alerts:
        return theme.chip(lane.alerts[0].kind.tag, *theme.alert_colors(lane.alerts[0].kind))
    return Text("")


def lane_cells(deck: Deck, lane: Lane, selected: bool = False) -> dict[str, Text]:
    ch = deck.challenges[lane.challenge_id]
    dim = theme.MUTED if lane.finished else ""
    idle = lane.idle(deck.now)
    cost = f"${fmt.dollars(lane.dollars, short=True)}" if lane.dollars is not None else "-"
    return {
        "bar": Text("▌", style=theme.ACCENT) if selected else Text(" "),
        "!": attention_cell(lane),
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


def _answers(alert: Alert) -> Text:
    out = Text()
    for s in alert.suggestions:
        label = untrusted(s.label, one_line=True)
        if not s.key:
            out.append(f"  {label}", theme.MUTED)
            continue
        out.append("  ")
        out.append_text(theme.key_chip(untrusted(s.key, one_line=True)))
        out.append(f" {label.lower()}", theme.MUTED)
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
        if lane.pending is not None:
            out.append("  ")
            out.append_text(theme.key_chip("a"))
            out.append(f" {untrusted(lane.pending.detail, one_line=True)}", theme.MUTED)
        else:
            out.append_text(_answers(top))
        out.append("   enter open", theme.MUTED)
        return out
    if lane.pending is not None:
        out.append("◆ waiting for you: ", f"bold {theme.PURPLE}")
        out.append(untrusted(lane.pending.detail, one_line=True))
        out.append("\n  ")
        out.append_text(theme.key_chip("a"))
        out.append(" approve   enter open", theme.MUTED)
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
    out.append(f" · turn {lane.turns} · {fmt.tokens(lane.tokens)} tok · ${fmt.dollars(lane.dollars)}", theme.MUTED)
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


def suggestion_command(key: str, text: str, lane_id: str | None = None) -> str | None:
    """The command an alert's suggested key stands for, e.g. /redirect <text>."""
    name = KEY_COMMAND.get(key)
    if name is None:
        return None
    return " ".join([f"/{name}"] + ([lane_id] if lane_id else []) + ([text] if text else []))


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
            if s.key == "a" and lane.pending is not None:
                continue  # the approval line below says it
            command = suggestion_command(s.key, s.text)
            line = Text("   ")
            label = untrusted(s.label, one_line=True)
            if command:
                line.append(untrusted(command, one_line=True), f"bold {theme.ACCENT}")
                line.append(f"   {label.lower()}", theme.MUTED)
            else:
                line.append(label, theme.MUTED)
            rows.append(line)
    if lane.pending is not None:
        border = border or theme.PURPLE
        rows.append(Text.assemble(("◆ waiting for you: ", f"bold {theme.PURPLE}"), (untrusted(lane.pending.detail, one_line=True), theme.TEXT)))
        rows.append(Text.assemble(("   /approve", f"bold {theme.ACCENT}"), ("   approve it", theme.MUTED)))
        for later in lane.waiting:
            rows.append(Text.assemble(("   then: ", theme.MUTED), (untrusted(later.detail, one_line=True), theme.MUTED)))
    for hint in lane.hints:
        rows.append(Text.assemble(("› sent, not read yet: ", theme.MUTED), (untrusted(hint, one_line=True), theme.ACCENT)))
    if not rows:
        return Text("Nothing needs you on this lane. Type below to message it, or / for commands.", theme.MUTED)
    if border:
        rows.append(Text("type / to pick one of these, or write your own message", theme.MUTED))
    return Panel(Group(*rows), box=box.ROUNDED, border_style=border or theme.BORDER, padding=(0, 1), title=Text("needs you now", "bold"), title_align="left")


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
