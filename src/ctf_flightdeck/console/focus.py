"""The focus view: one lane, full screen, like a conversation.

Left: the lane's transcript (its steps, your messages, flightdeck's notes) and, under
it, what the lane needs from you now with the suggested commands. Right: the files it
changed and the diff of the selected one. Bottom: the chat box. Plain text is a message
the lane reads on its next turn; `/` runs a command on this lane. Typing goes to the chat
box from any pane. `esc` goes back to the fleet; a strip on top lists other lanes that
need you (`ctrl+n` goes through them in attention order). An unsent message stays with
the lane it was written for.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.text import Text
from textual import events, on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import OptionList, RichLog, Static
from textual.widgets.option_list import Option

from ..core.model import Lane
from . import theme, views
from .widgets import CommandBar

if TYPE_CHECKING:
    from .app import FlightdeckApp


def _key_line() -> Text:
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, (key, label) in enumerate(
        (("esc", "fleet"), ("enter", "send"), ("/", "commands"), ("ctrl+n", "next lane needing you"), ("tab", "files"), ("pgup pgdn", "scroll"))
    ):
        out.append("  " if i else "")
        out.append(key, f"bold {theme.ACCENT}")
        out.append(f" {label}", theme.MUTED)
    return out


KEYS = _key_line()


class FocusScreen(Screen, inherit_bindings=False):
    DEFAULT_CSS = """
    FocusScreen { layout: vertical; }
    FocusScreen #header { height: 1; margin: 0 1; }
    FocusScreen #others { height: 1; margin: 0 1; text-wrap: nowrap; text-overflow: ellipsis; }
    FocusScreen #main { height: 1fr; margin-top: 1; }
    FocusScreen #talk-pane { width: 3fr; }
    FocusScreen #files-pane { width: 2fr; }
    FocusScreen #transcript { height: 1fr; min-height: 3; background: transparent; }
    FocusScreen #now { height: auto; max-height: 50%; }
    FocusScreen #files { height: auto; max-height: 8; background: transparent; border: none; }
    FocusScreen #diff-scroll { height: 1fr; }
    FocusScreen #status { height: 1; margin: 0 2; text-wrap: nowrap; text-overflow: ellipsis; }
    FocusScreen #keys { height: 1; margin: 0 1; }
    """
    BINDINGS = [
        Binding("escape", "back", "fleet"),
        Binding("ctrl+n", "next_needing", "next lane needing you"),
        Binding("tab", "app.focus_next", "panes"),
        Binding("shift+tab", "app.focus_previous", "panes back", show=False),
        Binding("pageup", "scroll(-1)", "scroll", show=False),
        Binding("pagedown", "scroll(1)", "scroll", show=False),
    ]

    def __init__(self, lane_id: str, file: str | None = None) -> None:
        super().__init__()
        self.lane_id = lane_id
        self._first_file = file
        self._written = 0  # transcript entries already written
        self._file_paths: list[str] | None = None  # None: the list must be rebuilt
        self._drafts: dict[str, str] = {}  # unsent chat text, by lane
        self.diff_path: str | None = None
        self._ready = False  # widgets composed; set at the start of on_mount

    @property
    def fd(self) -> FlightdeckApp:
        return self.app  # type: ignore[return-value]

    @property
    def lane(self) -> Lane:
        return self.fd.deck.lanes[self.lane_id]

    def compose(self) -> ComposeResult:
        yield Static(id="header")
        yield Static(id="others")
        with Horizontal(id="main"):
            with Vertical(id="talk-pane", classes="panel"):
                yield RichLog(id="transcript", wrap=True, min_width=20, auto_scroll=True)
                yield Static(id="now")
            with Vertical(id="files-pane", classes="panel"):
                yield OptionList(id="files")
                with VerticalScroll(id="diff-scroll"):
                    yield Static(id="diff")
        yield Static(id="status")
        yield CommandBar("message this lane (it reads it on its next turn) · / for commands", id="chat")
        yield Static(KEYS, id="keys")

    def on_mount(self) -> None:
        self._ready = True
        # pgup/pgdn scroll the transcript from anywhere, so tab goes chat -> files -> diff
        self.query_one("#transcript", RichLog).can_focus = False
        self.show_lane(self.lane_id, self._first_file)

    def show_lane(self, lane_id: str, file: str | None = None) -> None:
        """Switch this view to another lane (or reopen it).

        Before the view is composed (a second open queued right behind the one that pushed
        it), only remember the lane: on_mount draws it."""
        if not self._ready:
            self.lane_id, self._first_file = lane_id, file
            return
        chat = self.query_one("#chat", CommandBar)
        if lane_id != self.lane_id:
            if chat.field.value:
                self._drafts[self.lane_id] = chat.field.value  # kept for when you come back
            chat.clear()
            draft = self._drafts.pop(lane_id, "")
            chat.field.value = draft
            chat.field.cursor_position = len(draft)
        else:
            chat.hide_menu()
        self.lane_id = lane_id
        self._written = 0
        self._file_paths = None
        self.diff_path = file or None  # "" means: the newest file
        self.query_one("#transcript", RichLog).clear()
        self.refresh_view()
        if file is not None:
            self.query_one("#files", OptionList).focus()
        else:
            self.query_one("#chat", CommandBar).field.focus()

    # ------------------------------------------------------------------ refresh

    def refresh_view(self) -> None:
        if not self._ready or not self.app.is_running:
            return  # not composed yet, or the app is shutting down
        lane, deck = self.lane, self.fd.deck
        with self.app.batch_update():
            header = self.query_one("#header", Static)
            header.update(self.fd.header_text(max(40, header.size.width or self.size.width - 2), clock_keys=False))
            self.query_one("#status", Static).update(self.fd.status_text())
            self.query_one("#others", Static).update(views.others_strip(deck, lane))
            pane = self.query_one("#talk-pane")
            pane.border_title = views.focus_title(deck, lane)
            pane.border_subtitle = views.plan_line(lane)
            log = self.query_one("#transcript", RichLog)
            at_end = log.scroll_y >= log.max_scroll_y  # a player reading back stays where they are
            for action in lane.actions[self._written :]:
                for line in views.transcript_lines(action):
                    log.write(line, scroll_end=at_end)
            self._written = len(lane.actions)
            self.query_one("#now", Static).update(views.now_card(deck, lane))
            self._render_files()
            chat = self.query_one("#chat", CommandBar)
            chat.set_suggestions(self.fd.command_suggestions(lane.id, with_lane=False))

    def _render_files(self) -> None:
        lane = self.lane
        paths = list(reversed(lane.files))  # newest first
        files = self.query_one("#files", OptionList)
        pane = self.query_one("#files-pane")
        pane.border_title = Text.assemble(("files changed", "bold"), (f"  {len(paths)}", theme.MUTED))
        if paths != self._file_paths:
            self._file_paths = paths
            files.clear_options()
            for path in paths:
                files.add_option(Option(views.file_label(lane.files[path]), id=path))
            if self.diff_path not in paths:
                self.diff_path = paths[0] if paths else None
            if self.diff_path is not None:
                files.highlighted = paths.index(self.diff_path)
        diff = self.query_one("#diff", Static)
        change = lane.files.get(self.diff_path or "")
        diff.update(views.diff_view(change) if change else Text("No files changed yet.", theme.MUTED))

    @on(OptionList.OptionHighlighted, "#files")
    def _file_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id and event.option.id != self.diff_path:
            self.diff_path = event.option.id
            self._render_files()

    # ------------------------------------------------------------------ actions

    @on(CommandBar.Submitted, "#chat")
    def _chat(self, event: CommandBar.Submitted) -> None:
        if event.value:
            self.fd.run_command(event.value, self.lane_id)

    def on_key(self, event: events.Key) -> None:
        """Typing goes to the chat box from any pane (the files list, the diff)."""
        chat = self.query_one("#chat", CommandBar)
        if event.is_printable and event.character and not chat.field.has_focus:
            event.stop()
            event.prevent_default()
            chat.start(chat.field.value + event.character)

    def action_back(self) -> None:
        self.fd.show_fleet(select=self.lane_id)

    def action_next_needing(self) -> None:
        """The next lane that needs you, in attention order; after the last, the first again."""
        ids = [lane.id for lane in self.fd.deck.needing()]
        if not [lane_id for lane_id in ids if lane_id != self.lane_id]:
            self.fd.inform("No other lane needs you right now")
            return
        nxt = ids[(ids.index(self.lane_id) + 1) % len(ids)] if self.lane_id in ids else ids[0]
        self.show_lane(nxt)

    def action_scroll(self, direction: int) -> None:
        log = self.query_one("#transcript", RichLog)
        if direction < 0:
            log.scroll_page_up(animate=False)
        else:
            log.scroll_page_down(animate=False)
