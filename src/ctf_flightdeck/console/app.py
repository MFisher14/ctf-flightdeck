"""The flightdeck console: header, board, lanes, detail pane and key bar (CONSOLE-SPEC).

The console only reads the Deck and sends it interventions, so the same app runs on
the M0 mock and, in M1, on real lanes. In the mock a `ticker` advances the fake
world on a timer; without one, nothing moves unless the caller ticks it (tests).
"""

from __future__ import annotations

from collections.abc import Callable

from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import DataTable, Footer, Input, Static

from ..core import interventions as iv
from ..core.attention import SortMode, sort_lanes
from ..core.deck import Deck
from ..core.model import ME, Challenge, Event, EventKind, Lane, LaneState
from . import views
from .screens import ForkPrompt, HelpScreen, KillPrompt, TakeOverScreen, TextPrompt

TOAST_EVENTS = (EventKind.RELEASE, EventKind.TEAMMATE, EventKind.SUBMIT)


class DeckScreen(Screen, inherit_bindings=False):
    """The console's main screen. It holds the keys, in the key-bar order of the spec;
    the actions themselves live on the app."""

    BINDINGS = [
        Binding("p", "app.pause", "pause"),
        Binding("h", "app.hint", "hint"),
        Binding("r", "app.redirect", "redirect"),
        Binding("f", "app.fork", "fork"),
        Binding("k", "app.kill", "kill"),
        Binding("e", "app.escalate", "escalate"),
        Binding("t", "app.take_over", "take over"),
        Binding("a", "app.approve", "approve"),
        Binding("c", "app.claim", "claim"),
        Binding("slash", "app.filter", "filter", key_display="/"),
        Binding("s", "app.sort", "sort"),
        Binding("tab", "app.focus_next", "focus"),
        Binding("shift+tab", "app.focus_previous", "focus back", show=False),
        Binding("question_mark", "app.help", "help", key_display="?"),
        Binding("q", "app.quit", "quit"),
        Binding("escape", "app.escape", "clear filter", show=False),
        Binding("space", "app.toggle_clock", "freeze clock", show=False),
        Binding("full_stop", "app.step_clock", "step clock", show=False),
    ]


class FlightdeckApp(App[None]):
    TITLE = "flightdeck"
    ENABLE_COMMAND_PALETTE = False
    CSS = """
    Screen { layout: vertical; }
    #header { height: 1; background: $boost; }
    #main { height: 1fr; }
    .pane { border: round $secondary; border-title-color: $text; }
    .pane:focus-within { border: round $accent; }
    #board-pane { width: 50; }
    #lanes-pane { width: 1fr; }
    #detail-pane { height: 17; max-height: 45%; padding: 0 1; }
    #board, #lanes { height: 1fr; }
    #lanes { overflow-x: hidden; }
    #filter { display: none; }
    #filter.-visible { display: block; }
    """
    def __init__(
        self,
        deck: Deck,
        *,
        ticker: Callable[[], None] | None = None,
        tick_seconds: float | None = None,
        mock: str = "",
    ) -> None:
        super().__init__()
        self.deck = deck
        self.mock = mock
        self._ticker = ticker
        self._tick_seconds = tick_seconds
        self._timer: Timer | None = None
        self.frozen = False
        self.sort = SortMode.ATTENTION
        self.filter_text = ""
        self.show_finished = False
        self.selected_lane: str | None = None  # the lane the keys act on
        self.selected_challenge: str | None = None
        self._lane_cursor: str | None = None  # row key under the cursor: a lane or the finished row
        self.detail_mode = "lane"  # or "challenge"
        self._lane_width = 0
        self._unsubscribe = deck.subscribe(self._on_deck_event)

    # ------------------------------------------------------------------ layout

    def get_default_screen(self) -> Screen:
        return DeckScreen(id="_default")

    def compose(self) -> ComposeResult:
        yield Static(id="header")
        with Horizontal(id="main"):
            with Vertical(id="board-pane", classes="pane"):
                yield DataTable(id="board", cursor_type="row")
            with Vertical(id="lanes-pane", classes="pane"):
                yield DataTable(id="lanes", cursor_type="row")
                yield Input(placeholder="filter lanes: words match name, category, model, state, alert", id="filter")
        with VerticalScroll(id="detail-pane", classes="pane"):
            yield Static(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        board = self.query_one("#board", DataTable)
        for label, width in views.BOARD_COLUMNS:
            board.add_column(label, width=width, key=label or "mark")
        self._set_lane_columns()
        self.refresh_view()
        self.query_one("#lanes", DataTable).focus()
        if self._ticker is not None and self._tick_seconds:
            self._timer = self.set_interval(self._tick_seconds, self._on_timer)

    def on_unmount(self) -> None:
        self._unsubscribe()

    def on_resize(self, event: events.Resize) -> None:
        self.call_after_refresh(self._set_lane_columns)

    def _set_lane_columns(self) -> None:
        """Give the last-action column whatever width the fixed columns leave."""
        table = self.query_one("#lanes", DataTable)
        fixed = sum(width for _, width in views.LANE_COLUMNS)
        padding = 2 * table.cell_padding * (len(views.LANE_COLUMNS) + 1)
        width = max(12, table.size.width - fixed - padding - 2)
        if width == self._lane_width and table.columns:
            return
        self._lane_width = width
        table.clear(columns=True)
        for label, w in views.LANE_COLUMNS:
            table.add_column(label, width=w, key=label)
        table.add_column(views.LAST_COLUMN, width=width, key="last")
        self._render_lanes(rebuild=True)

    # ------------------------------------------------------------------ refresh

    def refresh_view(self) -> None:
        with self.batch_update():
            self._render_header()
            self._render_board()
            self._render_lanes()
            self._render_detail()

    def _render_header(self) -> None:
        note = ""
        if self._ticker is not None:
            note = "⏸ frozen: space resumes, . steps" if self.frozen else "▶ live: space freezes"
        self.query_one("#header", Static).update(views.header(self.deck, mock=self.mock, clock_note=note))

    def _render_board(self) -> None:
        table = self.query_one("#board", DataTable)
        order = views.board_order(list(self.deck.challenges.values()))
        keys = [ch.id for ch in order]
        if keys != [row.key.value for row in table.ordered_rows]:
            with self.prevent(DataTable.RowHighlighted):
                table.clear()
                for ch in order:
                    table.add_row(*views.board_row(self.deck, ch), key=ch.id)
                if self.selected_challenge in keys:
                    table.move_cursor(row=keys.index(self.selected_challenge), animate=False)
            if self.selected_challenge not in keys:
                self.selected_challenge = self._cursor_key(table)
        else:
            columns = [label or "mark" for label, _ in views.BOARD_COLUMNS]
            for ch in order:
                for column, cell in zip(columns, views.board_row(self.deck, ch)):
                    table.update_cell(ch.id, column, cell)
        title = self.query_one("#board-pane")
        title.border_title = views.board_title(self.deck)

    def _lane_rows(self) -> list[tuple[str, tuple[Text, ...]]]:
        deck = self.deck
        lanes = [
            lane
            for lane in sort_lanes(deck.lanes.values(), self.sort, deck.now)
            if views.lane_matches(deck, lane, self.filter_text)
        ]
        active = [lane for lane in lanes if not lane.finished]
        done = [lane for lane in lanes if lane.finished]
        rows = [(lane.id, views.lane_row(deck, lane)) for lane in active]
        if done:
            rows.append((views.FINISHED_ROW, views.finished_row(done, self.show_finished)))
            if self.show_finished:
                rows += [(lane.id, views.lane_row(deck, lane)) for lane in done]
        return rows

    def _render_lanes(self, rebuild: bool = False) -> None:
        table = self.query_one("#lanes", DataTable)
        if not table.columns:
            return
        rows = self._lane_rows()
        keys = [key for key, _ in rows]
        columns = [label for label, _ in views.LANE_COLUMNS] + ["last"]
        if not rebuild and keys == [row.key.value for row in table.ordered_rows]:
            for key, cells in rows:
                for column, cell in zip(columns, cells):
                    table.update_cell(key, column, cell)
        else:
            old_row = table.cursor_coordinate.row
            target = next((k for k in (self._lane_cursor, self.selected_lane) if k in keys), None)
            with self.prevent(DataTable.RowHighlighted):
                table.clear()
                for key, cells in rows:
                    table.add_row(*cells, key=key)
                if target is not None:
                    table.move_cursor(row=keys.index(target), animate=False)
                elif keys:
                    table.move_cursor(row=min(old_row, len(keys) - 1), animate=False)
            self._lane_cursor = self._cursor_key(table)
            if self.selected_lane not in keys and self._lane_cursor != views.FINISHED_ROW:
                self.selected_lane = self._lane_cursor
        self.query_one("#lanes-pane").border_title = views.lanes_title(self.deck, self.sort, self.filter_text)

    def _render_detail(self) -> None:
        pane = self.query_one("#detail-pane")
        detail = self.query_one("#detail", Static)
        if self.detail_mode == "challenge" and self.selected_challenge in self.deck.challenges:
            ch = self.deck.challenges[self.selected_challenge]
            pane.border_title = Text.assemble(("challenge · ", "bold"), (ch.name, "bold"))
            detail.update(views.challenge_detail(self.deck, ch))
            return
        lane = self.deck.lanes.get(self.selected_lane or "")
        if lane is None:
            pane.border_title = Text("detail", "bold")
            detail.update(Text("No lane selected. Lanes appear here once challenges are released.", "dim"))
            return
        ch = self.deck.challenges[lane.challenge_id]
        pane.border_title = Text.assemble((f"{lane.id} · ", "bold"), (ch.name, "bold"))
        detail.update(views.lane_detail(self.deck, lane))

    @staticmethod
    def _cursor_key(table: DataTable) -> str | None:
        if table.row_count == 0:
            return None
        return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value

    # ------------------------------------------------------------------ selection

    @on(DataTable.RowHighlighted, "#lanes")
    def _lane_highlighted(self, event: DataTable.RowHighlighted) -> None:
        key = self._cursor_key(event.data_table)  # the live cursor, not a stale event
        self._lane_cursor = key
        if key and key != views.FINISHED_ROW:
            self.selected_lane = key
        self.detail_mode = "lane"
        self._render_detail()

    @on(DataTable.RowSelected, "#lanes")
    def _lane_selected(self, event: DataTable.RowSelected) -> None:
        if self._cursor_key(event.data_table) == views.FINISHED_ROW:
            self.show_finished = not self.show_finished
            self._render_lanes(rebuild=True)

    @on(DataTable.RowHighlighted, "#board")
    def _board_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.selected_challenge = self._cursor_key(event.data_table)
        self.detail_mode = "challenge"
        self._render_detail()

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        if event.widget.id == "board":
            self.detail_mode = "challenge"
            self.selected_challenge = self.selected_challenge or self._cursor_key(event.widget)
        elif event.widget.id == "lanes":
            self.detail_mode = "lane"
        self._render_detail()

    def select_lane(self, lane_id: str) -> None:
        """Show a lane in the list (expanding finished lanes or clearing the filter if needed)."""
        lane = self.deck.lanes[lane_id]
        if lane.finished:
            self.show_finished = True
        if not views.lane_matches(self.deck, lane, self.filter_text):
            self._set_filter("")
        self.selected_lane = self._lane_cursor = lane_id
        self.detail_mode = "lane"
        self._render_lanes(rebuild=True)
        table = self.query_one("#lanes", DataTable)
        table.focus()
        self._render_detail()

    def select_challenge(self, challenge_id: str) -> None:
        self.selected_challenge = challenge_id
        table = self.query_one("#board", DataTable)
        table.move_cursor(row=table.get_row_index(challenge_id), animate=False)
        table.focus()
        self.detail_mode = "challenge"
        self._render_detail()

    # ------------------------------------------------------------------ clock (mock)

    def _on_timer(self) -> None:
        if not self.frozen:
            self.step()

    def step(self, ticks: int = 1) -> None:
        """Advance the mock world and redraw."""
        if self._ticker is None:
            raise RuntimeError("this console has no mock clock to step")
        for _ in range(ticks):
            self._ticker()
        self.refresh_view()

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action == "claim":
            return self.deck.config.team  # hidden in solo mode
        if action in ("toggle_clock", "step_clock"):
            return self._ticker is not None
        return True

    def action_toggle_clock(self) -> None:
        self.frozen = not self.frozen
        self._render_header()

    def action_step_clock(self) -> None:
        self.step()

    # ------------------------------------------------------------------ interventions

    def _target_lane(self) -> Lane | None:
        """The lane a lane key acts on: the one in the detail pane."""
        if self.detail_mode == "challenge" and self.selected_challenge:
            ch = self.deck.challenges[self.selected_challenge]
            lanes = self.deck.lanes_on(ch.id)
            if len(lanes) == 1:
                return lanes[0]
            if lanes:
                self._warn(f"{len(lanes)} lanes work {ch.name}: pick one in the lane list (tab)")
            else:
                self._warn(f"No lane is working {ch.name}")
            return None
        lane = self.deck.lanes.get(self.selected_lane or "")
        if lane is None:
            self._warn("Select a lane first")
        return lane

    def _warn(self, message: str) -> None:
        self.notify(message, markup=False, severity="warning", timeout=4)

    def _apply(self, intervention: iv.Intervention) -> iv.Outcome:
        outcome = self.deck.apply(intervention)
        self.notify(outcome.message, markup=False, severity="information" if outcome.ok else "warning", timeout=4)
        self.refresh_view()
        return outcome

    def _challenge(self, lane: Lane) -> Challenge:
        return self.deck.challenges[lane.challenge_id]

    @staticmethod
    def _suggested(lane: Lane, key: str) -> str:
        for alert in lane.alerts:
            for suggestion in alert.suggestions:
                if suggestion.key == key and suggestion.text:
                    return suggestion.text
        return ""

    def _title(self, verb: str, lane: Lane) -> Text:
        return Text.assemble((f"{verb} ", "bold"), (lane.id, "bold"), " · ", (self._challenge(lane).name, "bold"))

    def action_pause(self) -> None:
        lane = self._target_lane()
        if lane is not None:
            self._apply(iv.Resume(lane.id) if lane.state is LaneState.PAUSED else iv.Pause(lane.id))

    def action_hint(self) -> None:
        lane = self._target_lane()
        if lane is None:
            return
        context = Text.assemble("Goes into the lane's next turn. Its plan now: ", (lane.plan or "-", "italic"))
        prompt = TextPrompt(self._title("Hint for", lane), context, self._suggested(lane, "h"), "free text")
        lane_id = lane.id

        def done(text: str | None) -> None:
            if text is not None:
                self._apply(iv.Hint(lane_id, text))

        self.push_screen(prompt, done)

    def action_redirect(self) -> None:
        lane = self._target_lane()
        if lane is None:
            return
        context = Text.assemble("Replaces the plan. Plan now: ", (lane.plan or "-", "italic"))
        value = self._suggested(lane, "r") or lane.plan
        prompt = TextPrompt(self._title("Redirect", lane), context, value, "the new direction")
        lane_id = lane.id

        def done(text: str | None) -> None:
            if text is not None:
                self._apply(iv.Redirect(lane_id, text))

        self.push_screen(prompt, done)

    def action_fork(self) -> None:
        lane = self._target_lane()
        if lane is None:
            return
        models = self.deck.config.models or (lane.model,)
        prompt = ForkPrompt(self._title("Fork", lane), self._suggested(lane, "f"), models, self.deck.fork_model(lane.model))
        lane_id = lane.id

        def done(result: tuple[str, str] | None) -> None:
            if result is not None:
                approach, model = result
                self._apply(iv.Fork(lane_id, approach=approach, model=model))

        self.push_screen(prompt, done)

    def action_kill(self) -> None:
        lane = self._target_lane()
        if lane is None:
            return
        lane_id = lane.id

        def done(choice: str | None) -> None:
            if choice is not None:
                self._apply(iv.Kill(lane_id, requeue=choice == "requeue"))

        self.push_screen(KillPrompt(self._title("Kill", lane)), done)

    def action_escalate(self) -> None:
        lane = self._target_lane()
        if lane is not None:
            self._apply(iv.Escalate(lane.id))

    def action_take_over(self) -> None:
        lane = self._target_lane()
        if lane is None or not self._apply(iv.TakeOver(lane.id)).ok:
            return
        lane_id = lane.id

        def done(_: None) -> None:
            self._apply(iv.HandBack(lane_id))

        screen = TakeOverScreen(lane.id, self._challenge(lane).name, self.deck.config.containerized)
        self.push_screen(screen, done)

    def action_approve(self) -> None:
        lane = self._target_lane()
        if lane is not None:
            self._apply(iv.Approve(lane.id))

    def action_claim(self) -> None:
        cid = self.selected_challenge if self.detail_mode == "challenge" else None
        if cid is None:
            lane = self.deck.lanes.get(self.selected_lane or "")
            cid = lane.challenge_id if lane else None
        if cid is None:
            self._warn("Select a challenge on the board first")
            return
        ch = self.deck.challenges[cid]
        self._apply(iv.Release(cid) if ch.claimed_by == ME else iv.Claim(cid))

    # ------------------------------------------------------------------ view keys

    def action_sort(self) -> None:
        self.sort = self.sort.next()
        self._render_lanes(rebuild=True)
        self.notify(f"Lanes sorted by {self.sort.value}", markup=False, timeout=3)

    def action_filter(self) -> None:
        field = self.query_one("#filter", Input)
        field.add_class("-visible")
        field.focus()

    @on(Input.Changed, "#filter")
    def _filter_changed(self, event: Input.Changed) -> None:
        self.filter_text = event.value.strip()
        self._render_lanes(rebuild=True)
        self._render_detail()

    @on(Input.Submitted, "#filter")
    def _filter_submitted(self, event: Input.Submitted) -> None:
        if not event.value.strip():
            self.query_one("#filter", Input).remove_class("-visible")
        self.query_one("#lanes", DataTable).focus()

    def _set_filter(self, text: str) -> None:
        field = self.query_one("#filter", Input)
        field.value = text
        self.filter_text = text
        if not text:
            field.remove_class("-visible")

    def action_escape(self) -> None:
        if self.filter_text or self.query_one("#filter", Input).has_class("-visible"):
            self._set_filter("")
            self._render_lanes(rebuild=True)
            self.query_one("#lanes", DataTable).focus()

    def action_help(self) -> None:
        self.push_screen(HelpScreen(mock=self._ticker is not None))

    # ------------------------------------------------------------------ deck events

    def _on_deck_event(self, event: Event) -> None:
        if event.kind in TOAST_EVENTS:
            self.notify(event.text, markup=False, timeout=6)
