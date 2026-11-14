"""The fleet view: the board and every lane, sorted by what needs the player.

Keys act on the selected lane. `enter` or `o` opens it in the focus view; `/` opens the
command bar. A line under the lane list says why the selected lane is flagged and what
to do about it. The command bar acts on the same lane the keys do. Under 100 columns the
board hides so the lane list keeps its columns. The key line at the bottom always shows
`? help` and `q quit`; on a narrow terminal the keys needed least are left out of it first.
The status line is one row, and while what it says is longer than the terminal is wide it
takes a second or a third from the lane list: an answer's last words (the config file to
change, why something was refused) are often the ones the player needs.

While the board has no challenge, the page says so where the tables would be, and what to do
about it (EMPTY_BY_HAND, EMPTY_PLATFORM): it stays until there is one, unlike a status line.

In the simple layout (FlightdeckApp.layout; `deck` is the view as described above) there is no
board: one list of lanes with fewer columns (views.SIMPLE_LANE_COLUMNS: under 74 columns the
last action is left out, never the cost), a why line only for a
lane that needs something, and a key line of the keys that apply to the selected lane now
(context_keys). Every key still acts, and `?` lists them all. The compact layout wins over both.

At 64 columns or fewer (views.compact: a phone over SSH) the view is compact: each lane's
row has what needs you, the lane, its challenge, state and cost; the why line has six rows,
with the answers one a row; the key line has the answers, the commands, help and quit.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.style import Style
from rich.text import Text
from textual import events, on
from textual.actions import SkipAction
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Static

from ..core.attention import SortMode, sort_lanes
from ..core.model import COURSE_ALERTS, Lane
from . import theme, views
from .commands import CommandError, needs_lane, parse
from .widgets import BAR, CommandBar

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
SCROLLBAR = 2  # cells the lane list's scrollbar takes once it has more rows than room
LANE_LIST_EDGES = 6  # cells of the terminal's width that are not the lane list's, with no board: the panel's margin, frame and padding
LANE_PADDING = 1  # cells each side of a cell of the lane list (DataTable.cell_padding)
# The rows that are not lane rows: the header and the gap under it, the lane list's border and
# column labels, the why line and the gap over it, the status line, the command bar, the key line.
FLEET_ROWS = 13
# The compact layout: no gap under the header or over the why line, and a why line of six rows.
COMPACT_FLEET_ROWS = FLEET_ROWS - 2 - views.WHY_ROWS + views.COMPACT_WHY_ROWS
# The compact layout's key line: (binding key or "" for no binding, key as shown, label).
COMPACT_KEYS = (
    ("a", "a", "yes"), ("d", "d", "no"), ("", "1-9", "answer"), ("slash", "/", "cmd"),
    ("question_mark", "?", "help"), ("q", "q", "quit"),
)
# The simple layout's key line: (what a click does: a binding's key, an action, or "" for
# nothing; the key as shown; its label). Which of them a lane gets: context_keys().
NEW_KEY = ("app.new", "/new", "add a challenge")
APPROVE_KEY, DECLINE_KEY = ("a", "a", "approve"), ("d", "d", "decline")
ANSWER_KEY, DISMISS_KEY = ("", "1-9", "answer"), ("x", "x", "dismiss")
OPEN_KEY, COMMANDS_KEY = ("o", "enter", "open"), ("slash", "/", "commands")
HELP_KEY, QUIT_KEY = ("question_mark", "?", "help"), ("q", "q", "quit")
# What the page says while the board has no challenge: on a board the player fills (/new works
# there), and on one that comes from a platform or a script.
EMPTY_BY_HAND = "No challenges yet. Type /new to hand one over (its text, files, a screenshot)."
EMPTY_PLATFORM = "Waiting for the board: challenges appear here when the event releases them."
# The command bar's placeholder: widgets.BAR with challenges on the board (the bar's title names
# the lane a message goes to), and these on an empty board the player fills and on one that
# fills by itself.
BAR_EMPTY_BY_HAND = "/new to add a challenge · / for commands"
BAR_EMPTY_PLATFORM = "/ for commands"


def lane_rows(lines: int, *, compact: bool = False) -> int:
    """How many lane rows the lane list shows at once on a terminal `lines` tall (it scrolls to the rest)."""
    return max(0, lines - (COMPACT_FLEET_ROWS if compact else FLEET_ROWS))


class FittedTable(DataTable):
    """One of the fleet view's tables: its columns are fitted again whenever its own width
    changes. A change of layout (/layout, the board coming or going) gives the lane list its
    new width only once the screen is laid out again, and that can be after anything the
    fleet view asked to run "after the refresh": fitted then, the columns would keep the old
    width until the terminal is resized. The table's own resize cannot come too early."""

    def on_resize(self, event: events.Resize) -> None:
        screen = self.screen
        if event.size.width and isinstance(screen, FleetScreen) and screen._ready:  # no width: it is not shown
            screen._set_columns()


class FleetScreen(Screen, inherit_bindings=False):
    DEFAULT_CSS = """
    FleetScreen { layout: vertical; }
    FleetScreen #header { height: 1; margin: 0 1; }
    FleetScreen #main { height: 1fr; margin-top: 1; }
    FleetScreen #empty { height: 1fr; margin: 1 1 0 1; padding: 1 2; border: round $fd-border; display: none; }
    FleetScreen #board-pane { width: 30%; min-width: 30; max-width: 52; }
    FleetScreen #lanes-pane { width: 1fr; }
    FleetScreen #board, FleetScreen #lanes { height: 1fr; }
    FleetScreen #lanes, FleetScreen #board { overflow-x: hidden; }
    FleetScreen #why { height: 2; margin-top: 1; text-wrap: nowrap; text-overflow: ellipsis; }
    FleetScreen #status { height: auto; min-height: 1; max-height: 3; margin: 0 2; }
    FleetScreen #keys { height: 1; margin: 0 1; link-style: none; link-style-hover: underline; }
    FleetScreen.-compact #main { margin-top: 0; width: 100%; }
    FleetScreen.-compact #empty { margin: 0; padding: 0 1; }
    FleetScreen.-compact #why { height: 6; margin-top: 0; }
    FleetScreen.-simple #main { width: 100%; }
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
        Binding("ctrl+c,super+c", "copy", "copy the selection", show=False),
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
        self.compact = False  # the compact layout (views.compact of the terminal's width)
        self._lane_cursor: str | None = None  # row key under the cursor: a lane or the finished row
        self._lane_columns: list[tuple[str, str, int]] = []
        self._board_columns: list[tuple[str, str, int]] = []
        self._empty: bool | None = None  # the board has no challenge, so the page says so (None: not drawn yet)
        self._ready = False  # widgets composed; set at the start of on_mount

    @property
    def fd(self) -> FlightdeckApp:
        return self.app  # type: ignore[return-value]

    # ------------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        yield Static(id="header")
        yield Static(id="empty")
        with Horizontal(id="main"):
            with Vertical(id="board-pane", classes="panel"):
                yield FittedTable(id="board", cursor_type="row")
            with Vertical(id="lanes-pane", classes="panel"):
                yield FittedTable(id="lanes", cursor_type="row")
                yield Static(id="why")
        yield Static(id="status")
        yield CommandBar(BAR, id="bar", title=self._bar_title)
        yield Static(id="keys")

    def on_mount(self) -> None:
        self._ready = True
        self._fit_layout(self.size.width)
        self._show_keys(self.size.width)
        self._fit_board(self.size.width)
        self._set_columns()
        self.refresh_view()
        if not self._empty:  # on an empty board nothing has the focus: the keys act all the same
            self.query_one("#lanes", DataTable).focus()

    def on_resize(self, event: events.Resize) -> None:
        changed = self._fit_layout(event.size.width)
        self._show_keys(event.size.width)
        self._fit_board(event.size.width)
        self.call_after_refresh(self._set_columns)
        if changed:  # the header and the why line are drawn another way
            self.call_after_refresh(self.refresh_view)

    def _fit_layout(self, width: int) -> bool:
        """Switch to or from the compact layout for a terminal `width` wide. True if it changed."""
        compact = views.compact(width)
        changed, self.compact = compact != self.compact, compact
        self.set_class(compact, "-compact")
        self.set_class(self.simple, "-simple")
        return changed

    def _show_keys(self, width: int) -> None:
        self.query_one("#keys", Static).update(self.key_line(width - KEY_MARGIN))

    def repaint(self) -> None:
        """Draw everything again in the palette now in use (/theme): the key line is only
        drawn when the width changes, so it is drawn here."""
        if not self._ready:
            return
        self._show_keys(self.size.width)
        self.refresh_view()

    def relayout(self) -> None:
        """Draw in the layout now in use (/layout): the board comes or goes, the lane list
        takes that layout's columns once it has its new width, and the header, the titles,
        the why line and the key line are drawn again. The selection, the filter, the sort
        and what is typed in the bar stay."""
        if not self._ready:
            return
        self.set_class(self.simple, "-simple")
        self._fit_board(self.size.width)
        self._show_keys(self.size.width)
        self.call_after_refresh(self._set_columns)
        self.refresh_view()

    @property
    def simple(self) -> bool:
        """The simple layout is drawn: the app's layout, unless the terminal is narrow enough
        for the compact one."""
        return self.fd.layout == "simple" and not self.compact

    @property
    def board_hidden(self) -> bool:
        return not self.query_one("#board-pane").display

    def _fit_board(self, width: int) -> None:
        """Hide the board on a narrow terminal (the lane list needs the room), and in the
        simple layout, which has none."""
        show = width >= BOARD_MIN_WIDTH and self.fd.layout == "deck"
        pane = self.query_one("#board-pane")
        if pane.display == show:
            return
        pane.display = show
        if not show and self.board_focused:
            self.board_focused = False
            self.query_one("#lanes", DataTable).focus()

    def on_screen_resume(self) -> None:
        self.refresh_view()
        self.fd.open_first_lane()  # back from the /new form: the lane it started may be there already

    def _set_columns(self) -> None:
        """Fit both tables to their panes: low-value columns drop first, one column stretches."""
        board = self.query_one("#board", DataTable)
        lanes = self.query_one("#lanes", DataTable)
        board_cols = views.fit_columns(views.BOARD_COLUMNS, "name", views.BOARD_NAME_MIN, max(20, board.size.width - 1), board.cell_padding)
        if self.compact:
            lane_cols = views.fit_columns(
                views.COMPACT_LANE_COLUMNS, "chall", views.COMPACT_CHALL_MIN,
                max(30, self.query_one("#lanes-pane").size.width - 1 - SCROLLBAR), lanes.cell_padding,
            )  # the pane's width less the scrollbar's, whether it shows yet or not: the columns do not move when it comes
        elif self.simple:
            lane_cols = views.simple_lane_columns(max(30, lanes.size.width - 1), lanes.cell_padding)
        else:
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
            header.update(self.fd.header_text(max(40, header.size.width or self.size.width - 2), compact=self.compact))
            self._render_empty()
            self._render_board()
            self._render_lanes()
            self._render_why()
            self.query_one("#status", Static).update(self.fd.status_text())

    def _render_empty(self) -> None:
        """While the board has no challenge, say so in the page, in place of the tables: what
        to do on a board the player fills, or that it fills by itself. A status line would
        expire; this stays until a challenge is there. The command bar's placeholder follows."""
        empty = not self.fd.deck.challenges
        by_hand = self.fd.adder is not None
        page = self.query_one("#empty", Static)
        bar = self.query_one("#bar", CommandBar)
        if empty:  # each time: /theme changes its colours, and Textual gives a screen it comes back to a focus
            page.update(empty_text(by_hand))
            if self.focused is not None and self.focused.id in ("board", "lanes"):
                self.set_focus(None)  # a table that is not shown takes no keys: the screen's own keys act all the same
            self.board_focused = False  # nor is the player on a board that is not shown: see on_descendant_focus
        if empty == self._empty:
            return
        self._empty = empty
        page.display = empty
        self.query_one("#main").display = not empty
        bar.set_placeholder((BAR_EMPTY_BY_HAND if by_hand else BAR_EMPTY_PLATFORM) if empty else BAR)
        if not empty:  # the tables are back: they take their columns once they have a size, and the lane list the focus
            self.call_after_refresh(self._set_columns)
            if not bar.field.has_focus:  # a player typing in the bar goes on typing
                self.query_one("#lanes", DataTable).focus()

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
        rows = [(lane.id, views.lane_cells(deck, lane, lane.id == self.selected_lane, compact=self.compact)) for lane in active]
        if done:
            rows.append((views.FINISHED_ROW, views.finished_cells(done, self.show_finished)))
            if self.show_finished:
                rows += [(lane.id, views.lane_cells(deck, lane, lane.id == self.selected_lane, compact=self.compact)) for lane in done]
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
            self.fd.deck, self.sort, self.filter_text, board_hidden=self.board_hidden, compact=self.compact, simple=self.simple
        )

    def _render_why(self) -> None:
        deck = self.fd.deck
        why = self.query_one("#why", Static)
        lane = self.bar_lane()
        bar = self.query_one("#bar", CommandBar)
        bar.set_suggestions(self.fd.command_suggestions(lane.id if lane else None, with_lane=True), lane=lane is not None)
        bar.show_title()  # the lane the bar acts on follows the selection
        if self.board_focused and self.selected_challenge in deck.challenges:
            why.update(views.challenge_why(deck, deck.challenges[self.selected_challenge]))
            return
        lane = deck.lanes.get(self.selected_lane or "")
        if lane is None:
            why.update(Text(" No lanes yet.", theme.MUTED))
        elif self.compact:
            why.update(views.compact_why(deck, lane, why.size.width or self.size.width - 2))
        else:
            why.update(views.lane_why(deck, lane, simple=self.simple))
        if self.simple:  # its key line is the selected lane's: drawn again when the selection or the lane changes
            self._show_keys(self.size.width)

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
        """The player is on the board while it has the focus, and only a board that is shown:
        on an empty board, or in a layout with none, Textual may still hand the board's table
        the focus as the screen opens. Counted, it would stay "on the board" after the focus
        went, and the bar, the why line and the keys would act on the board's first challenge
        instead of the lane selected in the lane list."""
        if event.widget.id == "board":
            self.board_focused = bool(self.fd.deck.challenges) and not self.board_hidden
            if self.board_focused:
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

    def _bar_title(self, typed: str) -> Text:
        """The command bar's title for what is typed: the lane the keys point at, by name."""
        return views.bar_title(self.fd.deck, typed, self.bar_lane())

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
        bar.set_suggestions(self.fd.command_suggestions(lane.id if lane else None, with_lane=True), lane=lane is not None)
        bar.start(text)

    @on(CommandBar.Submitted, "#bar")
    def _command(self, event: CommandBar.Submitted) -> None:
        """Run what was typed on the lane the keys point at (the bar's title names it)."""
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
        selected = self.get_selected_text()
        self.clear_selection()
        if selected:  # text selected with the mouse: esc takes the selection down, and no more
            return
        bar = self.query_one("#bar", CommandBar)
        if bar.field.has_focus or bar.field.value:
            bar.clear()
            self._leave_bar()
        elif self.filter_text:
            self.set_filter("")

    def key_escape(self) -> None:
        """esc reaches a screen as a key before its binding runs, and Textual's own screen takes
        the selection down there. This one leaves it to the binding (action_escape), which then knows
        there was one."""

    def action_copy(self) -> None:
        """ctrl+c: copy the selected text. With none selected the key goes on, to Textual's
        own hint that ctrl+q quits."""
        if not self.fd.copy_selection():
            raise SkipAction()

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
        if self.compact:
            return compact_keys_text()
        if self.simple:
            lane = self.fd.deck.lanes.get(self.selected_lane or "")  # the lane the why line is about
            return keys_text(context_keys(lane, by_hand=self.fd.adder is not None))
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


def empty_text(by_hand: bool) -> Text:
    """What the page says while the board has no challenge (EMPTY_BY_HAND, EMPTY_PLATFORM)."""
    if not by_hand:
        return Text(EMPTY_PLATFORM, theme.MUTED)
    before, command, after = EMPTY_BY_HAND.partition("/new")
    return Text.assemble((before, theme.TEXT), (command, f"bold {theme.ACCENT}"), (after, theme.TEXT))


def fit_keys(bindings: list[Binding], width: int | None) -> tuple[list[Binding], list[Binding]]:
    """The keys a key line `width` cells wide shows, and the keys it leaves out in the order
    they go: the highest KEY_RANK first (the later key, on a tie); help and quit always stay."""
    shown, left = list(bindings), []
    while width is not None and FleetScreen._keys_text(shown).cell_len > width and any(KEY_RANK.get(b.key, 9) for b in shown):
        left.append(shown.pop(max(range(len(shown)), key=lambda i: (KEY_RANK.get(shown[i].key, 9), i))))
    return shown, left


def compact_keys_text() -> Text:
    """The compact layout's key line (COMPACT_KEYS): the answers, the commands, help and quit,
    each clickable as on the full line; cut at the edge of a terminal too narrow for it."""
    return keys_text(COMPACT_KEYS)


def keys_text(keys: tuple[tuple[str, str, str], ...]) -> Text:
    """A key line of (what a click does, the key as shown, its label): a binding's key clicks
    as that binding, an action ("app.new") as itself, and "" does nothing."""
    by_key = {b.key: b for b in FleetScreen.BINDINGS}
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, (key, shown, label) in enumerate(keys):
        binding = by_key.get(key)
        if binding is None:
            action = key if "." in key else ""
        else:
            action = binding.action if "." in binding.action.partition("(")[0] else f"screen.{binding.action}"
        click = {"@click": action} if action else {}
        out.append("  " if i else "")
        out.append(shown, Style(color=theme.ACCENT, bold=True, meta=click))
        out.append(f" {label}", Style(color=theme.MUTED, meta=click))
    return out


def context_keys(lane: Lane | None, *, by_hand: bool) -> tuple[tuple[str, str, str], ...]:
    """The simple layout's key line for the selected lane: only the keys that apply to it now.
    Every other key still acts, and help lists them all. With no lane: how to add a challenge
    (on a board the player fills), help and quit. With one: what answers it (approve and
    decline while it waits for the player; else the numbers of its alert's answers, and dismiss
    for an alert about its course), then open, the commands, help and quit."""
    if lane is None:
        return ((NEW_KEY,) if by_hand else ()) + (HELP_KEY, QUIT_KEY)
    answers: tuple[tuple[str, str, str], ...] = ()
    if lane.finished:
        pass
    elif lane.pending is not None:
        answers = (APPROVE_KEY, DECLINE_KEY)
    else:
        top = views.top_answerable(lane)
        if views.quick_answers(lane):
            answers += (ANSWER_KEY,)
        if top is not None and top.kind in COURSE_ALERTS:
            answers += (DISMISS_KEY,)
    return answers + (OPEN_KEY, COMMANDS_KEY, HELP_KEY, QUIT_KEY)


# The longest key line the simple layout draws: a lane with numbered answers and an alert to dismiss.
SIMPLE_LONGEST = (ANSWER_KEY, DISMISS_KEY, OPEN_KEY, COMMANDS_KEY, HELP_KEY, QUIT_KEY)
# Every key a lane's line can have, each once, in the order of a line.
SIMPLE_KEYS = (APPROVE_KEY, DECLINE_KEY, ANSWER_KEY, DISMISS_KEY, OPEN_KEY, COMMANDS_KEY, HELP_KEY, QUIT_KEY)


def simple_key_room(columns: int) -> tuple[list[str], int]:
    """The keys the simple layout's key line does not show whole on a terminal `columns` wide,
    and the columns its longest line (SIMPLE_LONGEST) needs. From the compact layout's width
    down, the line is the compact one: it leaves out the keys it does not have, then any of
    its own that the terminal's edge cuts."""
    needed = keys_text(SIMPLE_LONGEST).cell_len + KEY_MARGIN
    if views.compact(columns):
        kept = {shown for _, shown, _ in COMPACT_KEYS}
        left = [f"{shown} {label}" for _, shown, label in SIMPLE_KEYS if shown not in kept]
        return left + cut_keys([(shown, label) for _, shown, label in COMPACT_KEYS], columns - KEY_MARGIN), needed
    return cut_keys([(shown, label) for _, shown, label in SIMPLE_LONGEST], columns - KEY_MARGIN), needed


def simple_lane_room(columns: int) -> tuple[bool, int]:
    """Whether the simple layout's lane list has each lane's last action on a terminal
    `columns` wide, and the columns it needs for it. Fitted as the list fits itself
    (_set_columns)."""
    def has_last(width: int) -> bool:
        return any(key == "last" for key, _, _ in views.simple_lane_columns(max(30, width - LANE_LIST_EDGES - 1), LANE_PADDING))

    needed = next(width for width in range(views.COMPACT_MAX_WIDTH + 1, 400) if has_last(width))
    return has_last(columns), needed


def key_room(columns: int, *, team: bool) -> tuple[list[str], int]:
    """The keys the key line leaves out on a terminal `columns` wide ("s sort", in the order
    they go), and the columns it needs to show every key. Claim is a team-mode key (check_action).
    The compact layout's line (COMPACT_KEYS) leaves out every key it does not have, then any
    of its own that the terminal's edge cuts."""
    keys = [b for b in FleetScreen.BINDINGS if b.show and (team or b.action != "claim")]
    needed = FleetScreen._keys_text(keys).cell_len + KEY_MARGIN
    if views.compact(columns):
        kept = {key for key, _, _ in COMPACT_KEYS}
        _, order = fit_keys(keys, 0)  # every key in the order it goes
        left = [f"{b.key_display or b.key} {b.description}" for b in order + [b for b in keys if b not in order] if b.key not in kept]
        return left + cut_keys([(shown, label) for _, shown, label in COMPACT_KEYS], columns - KEY_MARGIN), needed
    _, left = fit_keys(keys, columns - KEY_MARGIN)
    return [f"{b.key_display or b.key} {b.description}" for b in left], needed


def cut_keys(labels: list[tuple[str, str]], width: int) -> list[str]:
    """The keys of a key line drawn whole and cut at its edge ("key label", two cells apart)
    that a line `width` cells wide does not show whole: the last ones."""
    end, cut = 0, []
    for i, (key, label) in enumerate(labels):
        end += (2 if i else 0) + len(f"{key} {label}")
        if end > width:
            cut.append(f"{key} {label}")
    return cut


def _cursor_key(table: DataTable) -> str | None:
    if table.row_count == 0:
        return None
    return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
