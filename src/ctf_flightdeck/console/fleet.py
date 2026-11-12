"""The fleet view: the board and every lane, sorted by what needs the player.

Keys act on the selected lane. `enter` or `o` opens it in the focus view; `/` opens the
command bar. A line under the lane list says why the selected lane is flagged and what
to do about it. The command bar acts on the same lane the keys do. Under 100 columns the
board hides so the lane list keeps its columns. The key line at the bottom always shows
`? help` and `q quit`; on a narrow terminal the keys needed least are left out of it first.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.style import Style
from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Static

from ..core.attention import SortMode, sort_lanes
from ..core.model import Lane
from . import theme, views
from .commands import CommandError, needs_lane, parse
from .widgets import CommandBar

if TYPE_CHECKING:
    from .app import FlightdeckApp

BOARD_MIN_WIDTH = 100  # narrower than this, the board hides and the lanes get the room
# The key line on a narrow terminal: the highest rank is left out first (the later key, on a tie).
# Help and quit always stay: help lists every key.
KEY_RANK = {
    "question_mark": 0, "q": 0,
    "a": 1, "d": 1, "slash": 1,
    "o": 2, "k": 2, "A": 2,
    "p": 3, "h": 3, "r": 3, "x": 3, "c": 3,
    "f": 4, "e": 4, "t": 4,
    "s": 5, "tab": 5,
}
KEY_MARGIN = 2  # the key line has a margin of one cell each side
# The rows that are not lane rows: the header and the gap under it, the lane list's border and
# column labels, the why line and the gap over it, the status line, the command bar, the key line.
FLEET_ROWS = 13


def lane_rows(lines: int) -> int:
    """How many lane rows the lane list shows at once on a terminal `lines` tall (it scrolls to the rest)."""
    return max(0, lines - FLEET_ROWS)


class FleetScreen(Screen, inherit_bindings=False):
    DEFAULT_CSS = """
    FleetScreen { layout: vertical; }
    FleetScreen #header { height: 1; margin: 0 1; }
    FleetScreen #main { height: 1fr; margin-top: 1; }
    FleetScreen #board-pane { width: 30%; min-width: 30; max-width: 52; }
    FleetScreen #lanes-pane { width: 1fr; }
    FleetScreen #board, FleetScreen #lanes { height: 1fr; }
    FleetScreen #lanes, FleetScreen #board { overflow-x: hidden; }
    FleetScreen #why { height: 2; margin-top: 1; text-wrap: nowrap; text-overflow: ellipsis; }
    FleetScreen #status { height: 1; margin: 0 2; text-wrap: nowrap; text-overflow: ellipsis; }
    FleetScreen #keys { height: 1; margin: 0 1; link-style: none; link-style-hover: underline; }
    """
    BINDINGS = [
        Binding("o", "open_lane", "open"),
        Binding("question_mark", "app.help", "help", key_display="?"),
        Binding("p", "lane('pause')", "pause"),
        Binding("h", "lane('hint')", "hint"),
        Binding("r", "lane('redirect')", "redirect"),
        Binding("f", "lane('fork')", "fork"),
        Binding("k", "lane('kill')", "kill"),
        Binding("e", "lane('escalate')", "escalate"),
        Binding("t", "lane('takeover')", "take over"),
        Binding("a", "lane('approve')", "approve"),
        Binding("d", "lane('decline')", "decline"),
        Binding("A", "approve_all", "approve all"),
        Binding("x", "lane('dismiss')", "dismiss"),
        Binding("c", "claim", "claim"),
        Binding("slash", "command", "commands", key_display="/"),
        Binding("s", "sort", "sort"),
        Binding("tab", "app.focus_next", "focus"),
        Binding("shift+tab", "app.focus_previous", "focus back", show=False),
        Binding("q", "app.quit", "quit"),
        Binding("escape", "escape", "back", show=False),
        Binding("space", "app.toggle_clock", "freeze clock", show=False),
        Binding("full_stop", "app.step_clock", "step clock", show=False),
        *(Binding(str(n), f"quick('{n}')", f"answer {n}", show=False) for n in range(10)),
    ]

    def __init__(self) -> None:
        super().__init__(id="_default")
        self.sort = SortMode.ATTENTION
        self.filter_text = ""
        self.show_finished = False
        self.selected_lane: str | None = None  # the lane the keys act on
        self.selected_challenge: str | None = None
        self.board_focused = False
        self._lane_cursor: str | None = None  # row key under the cursor: a lane or the finished row
        self._lane_columns: list[tuple[str, str, int]] = []
        self._board_columns: list[tuple[str, str, int]] = []
        self._ready = False  # widgets composed; set at the start of on_mount

    @property
    def fd(self) -> FlightdeckApp:
        return self.app  # type: ignore[return-value]

    # ------------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        yield Static(id="header")
        with Horizontal(id="main"):
            with Vertical(id="board-pane", classes="panel"):
                yield DataTable(id="board", cursor_type="row")
            with Vertical(id="lanes-pane", classes="panel"):
                yield DataTable(id="lanes", cursor_type="row")
                yield Static(id="why")
        yield Static(id="status")
        yield CommandBar("/ for commands · enter opens the selected lane · or type a message to it", id="bar")
        yield Static(id="keys")

    def on_mount(self) -> None:
        self._ready = True
        self._show_keys(self.size.width)
        self._fit_board(self.size.width)
        self._set_columns()
        self.refresh_view()
        self.query_one("#lanes", DataTable).focus()

    def on_resize(self, event: events.Resize) -> None:
        self._show_keys(event.size.width)
        self._fit_board(event.size.width)
        self.call_after_refresh(self._set_columns)

    def _show_keys(self, width: int) -> None:
        self.query_one("#keys", Static).update(self.key_line(width - KEY_MARGIN))

    @property
    def board_hidden(self) -> bool:
        return not self.query_one("#board-pane").display

    def _fit_board(self, width: int) -> None:
        """Hide the board on a narrow terminal (the lane list needs the room)."""
        show = width >= BOARD_MIN_WIDTH
        pane = self.query_one("#board-pane")
        if pane.display == show:
            return
        pane.display = show
        if not show and self.board_focused:
            self.board_focused = False
            self.query_one("#lanes", DataTable).focus()

    def on_screen_resume(self) -> None:
        self.refresh_view()

    def _set_columns(self) -> None:
        """Fit both tables to their panes: low-value columns drop first, one column stretches."""
        board = self.query_one("#board", DataTable)
        lanes = self.query_one("#lanes", DataTable)
        board_cols = views.fit_columns(views.BOARD_COLUMNS, "name", views.BOARD_NAME_MIN, max(20, board.size.width - 1), board.cell_padding)
        lane_cols = views.fit_columns(
            views.LANE_COLUMNS, "last", views.LAST_MIN, max(30, lanes.size.width - 1), lanes.cell_padding, views.LANE_SHRINK
        )
        if board_cols != self._board_columns:
            self._board_columns = board_cols
            board.clear(columns=True)
            for key, label, width in board_cols:
                board.add_column(label, width=width, key=key)
            self._render_board(rebuild=True)
        if lane_cols != self._lane_columns:
            self._lane_columns = lane_cols
            lanes.clear(columns=True)
            for key, label, width in lane_cols:
                lanes.add_column(label, width=width, key=key)
            self._render_lanes(rebuild=True)

    # ------------------------------------------------------------------ refresh

    def refresh_view(self) -> None:
        if not self._ready or not self.app.is_running:
            return  # not composed yet, or the app is shutting down
        with self.app.batch_update():
            header = self.query_one("#header", Static)
            header.update(self.fd.header_text(max(40, header.size.width or self.size.width - 2)))
            self._render_board()
            self._render_lanes()
            self._render_why()
            self.query_one("#status", Static).update(self.fd.status_text())

    def _render_board(self, rebuild: bool = False) -> None:
        deck = self.fd.deck
        table = self.query_one("#board", DataTable)
        if not table.columns:
            return
        order = views.board_order(list(deck.challenges.values()))
        keys = [ch.id for ch in order]
        columns = [key for key, _, _ in self._board_columns]
        if not rebuild and keys == [row.key.value for row in table.ordered_rows]:
            for ch in order:
                cells = views.board_cells(deck, ch)
                for column in columns:
                    table.update_cell(ch.id, column, cells[column])
        else:
            with self.prevent(DataTable.RowHighlighted):
                table.clear()
                for ch in order:
                    cells = views.board_cells(deck, ch)
                    table.add_row(*(cells[c] for c in columns), key=ch.id)
                if self.selected_challenge in keys:
                    table.move_cursor(row=keys.index(self.selected_challenge), animate=False)
            if self.selected_challenge not in keys:
                self.selected_challenge = _cursor_key(table)
        self.query_one("#board-pane").border_title = views.board_title(deck)

    def _lane_rows(self) -> list[tuple[str, dict[str, Text]]]:
        deck = self.fd.deck
        lanes = [
            lane
            for lane in sort_lanes(deck.lanes.values(), self.sort, deck.now)
            if views.lane_matches(deck, lane, self.filter_text)
        ]
        active = [lane for lane in lanes if not lane.finished]
        done = [lane for lane in lanes if lane.finished]
        rows = [(lane.id, views.lane_cells(deck, lane, lane.id == self.selected_lane)) for lane in active]
        if done:
            rows.append((views.FINISHED_ROW, views.finished_cells(done, self.show_finished)))
            if self.show_finished:
                rows += [(lane.id, views.lane_cells(deck, lane, lane.id == self.selected_lane)) for lane in done]
        return rows

    def _render_lanes(self, rebuild: bool = False) -> None:
        table = self.query_one("#lanes", DataTable)
        if not table.columns:
            return
        rows = self._lane_rows()
        keys = [key for key, _ in rows]
        columns = [key for key, _, _ in self._lane_columns]
        if not rebuild and keys == [row.key.value for row in table.ordered_rows]:
            for key, cells in rows:
                for column in columns:
                    table.update_cell(key, column, cells.get(column, Text("")))
        else:
            old_row = table.cursor_coordinate.row
            scroll_y = table.scroll_y
            selected_hidden = self.selected_lane is not None and self.selected_lane not in keys
            if self._lane_cursor in keys and not (selected_hidden and self._lane_cursor != views.FINISHED_ROW):
                target = self._lane_cursor
            elif self.selected_lane in keys:
                target = self.selected_lane
            elif selected_hidden and views.FINISHED_ROW in keys:
                target = views.FINISHED_ROW  # the selected lane finished: point at where it went
            else:
                target = None
            with self.prevent(DataTable.RowHighlighted):
                table.clear()
                for key, cells in rows:
                    table.add_row(*(cells.get(c, Text("")) for c in columns), key=key)
                if target is not None:
                    table.move_cursor(row=keys.index(target), animate=False, scroll=False)
                elif keys:
                    table.move_cursor(row=min(old_row, len(keys) - 1), animate=False, scroll=False)
                table.scroll_to(y=scroll_y, animate=False, immediate=True)
            self._lane_cursor = _cursor_key(table)
            if self.selected_lane is None and self._lane_cursor not in (None, views.FINISHED_ROW):
                self.selected_lane = self._lane_cursor  # first lanes on screen: select the top one
                self._render_lanes()
        self.query_one("#lanes-pane").border_title = views.lanes_title(
            self.fd.deck, self.sort, self.filter_text, board_hidden=self.board_hidden
        )

    def _render_why(self) -> None:
        deck = self.fd.deck
        why = self.query_one("#why", Static)
        lane = self.bar_lane()
        self.query_one("#bar", CommandBar).set_suggestions(
            self.fd.command_suggestions(lane.id if lane else None, with_lane=True)
        )
        if self.board_focused and self.selected_challenge in deck.challenges:
            why.update(views.challenge_why(deck, deck.challenges[self.selected_challenge]))
            return
        lane = deck.lanes.get(self.selected_lane or "")
        why.update(views.lane_why(deck, lane) if lane else Text(" No lane yet: lanes start when challenges are released.", theme.MUTED))

    # ------------------------------------------------------------------ selection

    @on(DataTable.RowHighlighted, "#lanes")
    def _lane_highlighted(self, event: DataTable.RowHighlighted) -> None:
        key = _cursor_key(event.data_table)  # the live cursor, not a stale event
        self._lane_cursor = key
        if key and key != views.FINISHED_ROW and key != self.selected_lane:
            self.selected_lane = key
            self._render_lanes()
            self._follow_on_board(key)
        self.board_focused = False
        self._render_why()

    def _follow_on_board(self, lane_id: str) -> None:
        """Keep the board cursor on the selected lane's challenge."""
        board = self.query_one("#board", DataTable)
        cid = self.fd.deck.lanes[lane_id].challenge_id
        if board.row_count and cid != _cursor_key(board):
            with self.prevent(DataTable.RowHighlighted):
                board.move_cursor(row=board.get_row_index(cid), animate=False)
            self.selected_challenge = cid

    @on(DataTable.RowSelected, "#lanes")
    def _lane_selected(self, event: DataTable.RowSelected) -> None:
        if self.app.screen is not self:
            return  # a second enter queued behind the one that opened a lane
        key = _cursor_key(event.data_table)
        if key == views.FINISHED_ROW:
            self.show_finished = not self.show_finished
            self._render_lanes(rebuild=True)
        elif key:
            self.fd.open_lane(key)

    @on(DataTable.RowHighlighted, "#board")
    def _board_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.selected_challenge = _cursor_key(event.data_table)
        self.board_focused = True
        self._render_why()

    @on(DataTable.RowSelected, "#board")
    def _board_selected(self, event: DataTable.RowSelected) -> None:
        if self.app.screen is not self:
            return  # a second enter queued behind the one that opened a card or lane
        cid = _cursor_key(event.data_table)
        if cid:
            self.fd.open_challenge(cid)

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        if event.widget.id == "board":
            self.board_focused = True
            self.selected_challenge = self.selected_challenge or _cursor_key(event.widget)
        elif event.widget.id == "lanes":
            self.board_focused = False
        self._render_why()

    def select_lane(self, lane_id: str) -> None:
        """Show a lane in the list (expanding finished lanes or clearing the filter if needed)."""
        deck = self.fd.deck
        lane = deck.lanes[lane_id]
        if lane.finished:
            self.show_finished = True
        if not views.lane_matches(deck, lane, self.filter_text):
            self.filter_text = ""
        self.selected_lane = self._lane_cursor = lane_id
        self.board_focused = False
        self._render_lanes(rebuild=True)
        table = self.query_one("#lanes", DataTable)
        table.move_cursor(row=table.get_row_index(lane_id), animate=False, scroll=True)
        table.focus()
        self._follow_on_board(lane_id)
        self._render_why()

    def select_challenge(self, challenge_id: str) -> None:
        self.selected_challenge = challenge_id
        table = self.query_one("#board", DataTable)
        table.move_cursor(row=table.get_row_index(challenge_id), animate=False)
        table.focus()
        self.board_focused = True
        self._render_why()

    def bar_lane(self) -> Lane | None:
        """The lane keys and the command bar act on, if there is one (no warnings)."""
        deck = self.fd.deck
        if self.board_focused and self.selected_challenge in deck.challenges:
            lanes = deck.lanes_on(self.selected_challenge)
            return lanes[0] if len(lanes) == 1 else None
        lane = deck.lanes.get(self.selected_lane or "")
        if lane is None or not views.lane_matches(deck, lane, self.filter_text):
            return None
        return lane

    def target_lane(self) -> Lane | None:
        """The lane a key acts on: the selected lane, or the board challenge's only lane.
        Says why when there is none."""
        deck = self.fd.deck
        if self.board_focused and self.selected_challenge:
            ch = deck.challenges[self.selected_challenge]
            lanes = deck.lanes_on(ch.id)
            if len(lanes) == 1:
                return lanes[0]
            self.fd.warn(
                f"{len(lanes)} lanes work {ch.name}: pick one in the lane list (tab)" if lanes
                else f"No lane is working {ch.name}"
            )
            return None
        lane = deck.lanes.get(self.selected_lane or "")
        if lane is None:
            self.fd.warn("Select a lane first")
        elif not views.lane_matches(deck, lane, self.filter_text):
            self.fd.warn(f"{lane.id} is hidden by the filter; esc clears it")
            return None
        return lane

    # ------------------------------------------------------------------ actions

    def action_lane(self, verb: str) -> None:
        lane = self.target_lane()
        if lane is None:
            return
        if verb == "hint":
            self.start_command(f"/hint {lane.id} {self.fd.suggested(lane, 'h')}".rstrip() + " ")
        elif verb == "redirect":
            suggestion = self.fd.suggested(lane, "r")
            self.start_command(f"/redirect {lane.id} {suggestion}" if suggestion else f"/redirect {lane.id} ")
        else:
            self.fd.lane_verb(lane, verb)

    def action_approve_all(self) -> None:
        """Every flag that waits for a plain yes, after a prompt that lists them (not the
        selected lane's alone)."""
        self.fd.approve_all()

    def action_open_lane(self) -> None:
        lane = self.target_lane()
        if lane is not None:
            self.fd.open_lane(lane.id)

    def action_quick(self, number: str) -> None:
        """A number answers what the lane needs (the why line numbers the answers)."""
        lane = self.target_lane()
        if lane is not None and not self.fd.answer(lane, number):
            self.fd.warn(f"{lane.id} has no answer {number}")

    def action_claim(self) -> None:
        deck = self.fd.deck
        cid = self.selected_challenge if self.board_focused else None
        if cid is None:
            lane = deck.lanes.get(self.selected_lane or "")
            cid = lane.challenge_id if lane else None
        if cid is None:
            self.fd.warn("Select a challenge on the board first")
            return
        self.fd.claim_toggle(cid)

    def action_command(self) -> None:
        self.start_command("/")

    def start_command(self, text: str) -> None:
        bar = self.query_one("#bar", CommandBar)
        lane = self.bar_lane()
        bar.set_suggestions(self.fd.command_suggestions(lane.id if lane else None, with_lane=True))
        bar.start(text)

    @on(CommandBar.Submitted, "#bar")
    def _command(self, event: CommandBar.Submitted) -> None:
        """Run what was typed on the lane the keys point at (the bar's placeholder says so)."""
        self._leave_bar()
        if not event.value:
            self.action_open_lane()  # enter on an empty bar opens the selected lane
            return
        try:
            parsed = parse(event.value)
        except CommandError as exc:
            self.fd.warn(str(exc))
            return
        lane_id = self.selected_lane
        if needs_lane(parsed) and parsed.lane is None:
            lane = self.target_lane()  # warns when the board has no single lane or the filter hides it
            if lane is None:
                return
            lane_id = lane.id
        self.fd.run_command(event.value, lane_id)

    def action_sort(self) -> None:
        self.set_sort(self.sort.next())

    def set_sort(self, mode: SortMode) -> None:
        self.sort = mode
        self._render_lanes(rebuild=True)
        self.fd.inform(f"Lanes sorted by {mode.value}")

    def set_filter(self, text: str) -> None:
        self.filter_text = text.strip()
        self._render_lanes(rebuild=True)
        self._render_why()

    def _leave_bar(self) -> None:
        """Back to the table the bar was opened from."""
        table = "#board" if self.board_focused and not self.board_hidden else "#lanes"
        self.query_one(table, DataTable).focus()

    def action_escape(self) -> None:
        bar = self.query_one("#bar", CommandBar)
        if bar.field.has_focus or bar.field.value:
            bar.clear()
            self._leave_bar()
        elif self.filter_text:
            self.set_filter("")

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "claim":
            return self.fd.deck.config.team  # hidden in solo mode
        return True

    def key_line(self, width: int | None = None) -> Text:
        """Every shown key this screen allows (claim only in team mode), each clickable. When
        they do not all fit in `width` cells, the keys needed least are left out (KEY_RANK);
        help and quit always stay.

        One Text drawn with the screen, so it is complete on the first frame (Textual's
        Footer fills in after a later refresh, which made screenshots and tests flaky)."""
        shown = [b for b in self.BINDINGS if b.show and self._allowed(b.action)]
        return self._keys_text(fit_keys(shown, width)[0])

    @staticmethod
    def _keys_text(bindings: list[Binding]) -> Text:
        out = Text(no_wrap=True, overflow="ellipsis")
        for i, binding in enumerate(bindings):
            action = binding.action if "." in binding.action.partition("(")[0] else f"screen.{binding.action}"
            click = {"@click": action}
            out.append("  " if i else "")
            out.append(binding.key_display or binding.key, Style(color=theme.ACCENT, bold=True, meta=click))
            out.append(f" {binding.description}", Style(color=theme.MUTED, meta=click))
        return out

    def _allowed(self, action: str) -> bool:
        name = action.partition("(")[0]
        return "." in name or bool(self.check_action(name, ()))


def fit_keys(bindings: list[Binding], width: int | None) -> tuple[list[Binding], list[Binding]]:
    """The keys a key line `width` cells wide shows, and the keys it leaves out in the order
    they go: the highest KEY_RANK first (the later key, on a tie); help and quit always stay."""
    shown, left = list(bindings), []
    while width is not None and FleetScreen._keys_text(shown).cell_len > width and any(KEY_RANK.get(b.key, 9) for b in shown):
        left.append(shown.pop(max(range(len(shown)), key=lambda i: (KEY_RANK.get(shown[i].key, 9), i))))
    return shown, left


def key_room(columns: int, *, team: bool) -> tuple[list[str], int]:
    """The keys the key line leaves out on a terminal `columns` wide ("s sort", in the order
    they go), and the columns it needs to show every key. Claim is a team-mode key (check_action)."""
    keys = [b for b in FleetScreen.BINDINGS if b.show and (team or b.action != "claim")]
    _, left = fit_keys(keys, columns - KEY_MARGIN)
    return [f"{b.key_display or b.key} {b.description}" for b in left], FleetScreen._keys_text(keys).cell_len + KEY_MARGIN


def _cursor_key(table: DataTable) -> str | None:
    if table.row_count == 0:
        return None
    return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
