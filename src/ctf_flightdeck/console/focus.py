"""The focus view: one lane, full screen, like a conversation.

Left: the lane's transcript (its steps, your messages, flightdeck's notes) and, under
it, what the lane needs from you now with the suggested commands. Right: the files it
changed and the diff of the selected one. Bottom: the chat box. Plain text is a message
the lane reads on its next turn; `/` runs a command on this lane. Typing goes to the chat
box from any pane. `esc` goes back to the fleet; a strip on top lists other lanes that
need you (`ctrl+n` goes through them in attention order). An unsent message stays with
the lane it was written for. When the lane is ended to start afresh (/attach, a kill that
re-queues), the view goes to the fresh lane, and the unsent message with it
(FlightdeckApp.follow_restart).

The view has one switch, `details` (`ctrl+o`, /details), for the transcript and the card
together. On: every line the lane's log keeps, each action as views.transcript_lines draws it,
and the full card: every open alert with its reason and its commands. Off, the calm
transcript: one row for each entry, a run of tool calls on two (views.entries,
views.entry_text), and the calm card: the question, its numbered answers, what else is open
(views.calm_card). It starts off in the simple layout and on in the deck and compact layouts,
and follows the layout until the player switches it by hand in this view. The compact layout's
card is never calm: every answer's number stays on it.

The card is in a box that scrolls (#now-scroll) and takes half the pane at most: a full card
taller than that keeps its first rows, the approval's, in view, and the mouse wheel shows the
rest.

Text in the view selects with the mouse (the transcript's rows, the calm card, the header,
the status line: each is text in a widget of its own) and is copied when the button comes up
(FlightdeckApp.on_text_selected). `ctrl+c` copies the selection again, and `esc` takes a
selection down before it goes back. The transcript and the card's box take no focus, so the
chat box keeps the keys through a drag.

At 64 columns or fewer (views.compact: a phone over SSH) the view is compact: one pane, with
what the lane needs from you above its transcript, and no files pane.

In the simple layout (FlightdeckApp.layout) the view shows a part only when it has something
in it: the files pane once the lane changed a file, the strip on top while another lane needs
you, the card while this one does. Its key line is short (SIMPLE_KEY_LABELS). The title is
the same in both layouts: the lane's model, turns, tokens and idle time are there.

`?` while the chat box is empty opens help, from any pane and in every layout; with text in
the box it is a question mark (P65). Help then opens on this lane: the keys the simple key line
has for it now, each with its sentence, and this view's keys before the lane list's
(help_now, screens.HelpScreen).

In every layout the chat box's border names the lane a message goes to (views.bar_title, P64):
this lane, another one while a command names it (`/kill L07`), `the run` while a command
that takes no lane is typed, and `L01 has finished` once the lane has ended and would refuse
what is typed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.cells import cell_len
from rich.text import Text
from textual import events, on
from textual.actions import SkipAction
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from ..core.model import Lane
from . import theme, views
from .lanelog import LaneLog, Row
from .widgets import BAR, CommandBar

if TYPE_CHECKING:
    from .app import FlightdeckApp


KEY_LABELS = (
    ("esc", "fleet"), ("enter", "send"), ("/", "commands"), ("1-9 0", "answer"), ("ctrl+n", "next lane needing you"),
    ("tab", "files"), ("pgup pgdn", "scroll"),
)
# The compact layout's key line: back, the answers, the commands, the next lane that needs you.
COMPACT_KEY_LABELS = (("esc", "fleet"), ("1-9 0", "answer"), ("/", "cmd"), ("ctrl+n", "next"))
# The simple layout's key line: back, the commands, help (`?` on the empty chat box, P65) and
# the details switch, which the edge would cut first; the answers lead while the lane has any.
# These are also the keys help opens on from a lane, in every layout (FocusScreen.help_now).
SIMPLE_KEY_LABELS = (("esc", "lanes"), ("/", "commands"), ("?", "help"), ("ctrl+o", "details"))
SIMPLE_ANSWER_LABEL = ("1-9", "answer")
# While the lane waits for the player its answers are 1 (yes) and 0 (no), in the card's words
# (P98); as wide as SIMPLE_ANSWER_LABEL, so the line's longest stays what P65 fixed.
SIMPLE_YES_NO_LABEL = ("1 0", "answer")
KEY_MARGIN = 2  # the key line has a margin of one cell each side
# What the status line says when the details switch is turned (ctrl+o, /details).
DETAILS_ON = "details on: every line and every alert (ctrl+o hides them)"
DETAILS_OFF = "details off (ctrl+o shows every line)"


def _key_line(labels: tuple[tuple[str, str], ...] = KEY_LABELS) -> Text:
    """The key line, in the colours of the palette in use: drawn when it is shown, never kept."""
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, (key, label) in enumerate(labels):
        out.append("  " if i else "")
        out.append(key, f"bold {theme.ACCENT}")
        out.append(f" {label}", theme.MUTED)
    return out


def key_room(columns: int, *, simple: bool = False) -> tuple[list[str], int]:
    """The keys the key line does not show whole on a terminal `columns` wide (it is cut at its
    edge, the last keys first), and the columns it needs to show every key. The compact
    layout's line leaves out every key it does not have, then any of its own that the edge cuts.
    `simple`: of the simple layout's line at its longest, with the answers."""
    whole = (SIMPLE_ANSWER_LABEL, *SIMPLE_KEY_LABELS) if simple else KEY_LABELS
    labels, left = whole, []
    if views.compact(columns):
        kept = {key for key, _ in COMPACT_KEY_LABELS}
        labels, left = COMPACT_KEY_LABELS, [f"{key} {label}" for key, label in whole if key not in kept and key != "1-9"]
    width, end, cut = columns - KEY_MARGIN, 0, []
    for i, (key, label) in enumerate(labels):
        end += (2 if i else 0) + cell_len(f"{key} {label}")
        if end > width:
            cut.append(f"{key} {label}")
    return left + cut, _key_line(whole).cell_len + KEY_MARGIN


CALM_EDGE = 4  # cells of the calm card's width that are not its rows': the border and the padding, each side


class CardScroll(VerticalScroll, can_focus=False):
    """The box the "needs you now" card is in: it carries the card's share of the pane, and
    scrolls a card taller than that. Not focusable: tab goes chat -> files -> diff."""

    def on_resize(self, event: events.Resize) -> None:
        if isinstance(self.screen, FocusScreen):
            self.screen.card_resized()  # the calm card's rows are fitted to its width


class FocusScreen(Screen, inherit_bindings=False):
    DEFAULT_CSS = """
    FocusScreen { layout: vertical; }
    FocusScreen #header { height: 1; margin: 0 1; }
    FocusScreen #others { height: 1; margin: 0 1; text-wrap: nowrap; text-overflow: ellipsis; link-style: none; link-style-hover: underline; }
    FocusScreen #main { height: 1fr; margin-top: 1; }
    FocusScreen #talk-pane { width: 3fr; }
    FocusScreen #files-pane { width: 2fr; }
    FocusScreen #transcript { height: 1fr; min-height: 3; background: transparent; overflow-y: scroll; }
    FocusScreen.-simple #transcript { overflow-y: auto; }
    FocusScreen #now-scroll { height: auto; max-height: 50%; }
    FocusScreen #now { height: auto; }
    FocusScreen #now.-calm { padding: 0 1; text-wrap: nowrap; text-overflow: ellipsis; border-title-style: bold; }
    FocusScreen #files { height: auto; max-height: 8; background: transparent; border: none; }
    FocusScreen #diff-scroll { height: 1fr; }
    FocusScreen #status { height: auto; min-height: 1; max-height: 3; margin: 0 2; }
    FocusScreen #keys { height: 1; margin: 0 1; }
    FocusScreen.-compact #main { margin-top: 0; width: 100%; }
    FocusScreen.-compact #now-scroll { max-height: 60%; }
    FocusScreen.-compact #files-pane { display: none; }
    FocusScreen .-nothing { display: none; }
    FocusScreen.-simple #main { width: 100%; }
    """
    BINDINGS = [
        Binding("escape", "back", "fleet"),
        Binding("ctrl+n", "next_needing", "next lane needing you"),
        Binding("tab", "app.focus_next", "panes"),
        Binding("shift+tab", "app.focus_previous", "panes back", show=False),
        Binding("pageup", "scroll(-1)", "scroll", show=False),
        Binding("pagedown", "scroll(1)", "scroll", show=False),
        Binding("ctrl+o", "details", "details", show=False),
        Binding("ctrl+c,super+c", "copy", "copy the selection", show=False),
    ]

    def __init__(self, lane_id: str, file: str | None = None) -> None:
        super().__init__()
        self.lane_id = lane_id
        self._first_file = file
        self._details: bool | None = None  # the details switch as the player set it in this view; None: the layout's
        self._file_paths: list[str] | None = None  # None: the list must be rebuilt
        self._drafts: dict[str, str] = {}  # unsent chat text, by lane
        self.diff_path: str | None = None
        self.compact = False  # the compact layout (views.compact of the terminal's width)
        self._labels: tuple[tuple[str, str], ...] = ()  # the key line as drawn
        self._card_room = 0  # the width of the card's box when the card was last drawn; 0: not known then
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
                yield LaneLog(id="transcript")  # not focusable: pgup/pgdn scroll it from anywhere, so tab goes chat -> files -> diff
                with CardScroll(id="now-scroll"):
                    yield Static(id="now")
            with Vertical(id="files-pane", classes="panel"):
                yield OptionList(id="files")
                with VerticalScroll(id="diff-scroll"):
                    yield Static(id="diff")
        yield Static(id="status")
        yield CommandBar(BAR, id="chat", title=self._chat_title, history=self.fd.bar_history)
        yield Static(_key_line(), id="keys")

    def on_mount(self) -> None:
        self._ready = True
        field = self.query_one("#chat", CommandBar).field
        field.quick, field.help = self._quick, self.fd.action_help
        self.query_one("#now", Static).border_title = "needs you now"  # drawn on the calm card's border (_show_card)
        self._fit_layout(self.size.width)
        self.show_lane(self.lane_id, self._first_file)

    def on_screen_resume(self) -> None:
        self.fd.follow_restart()  # back from under a prompt: the lane this one restarted as may have started meanwhile

    def on_resize(self, event: events.Resize) -> None:
        if self._ready and self._fit_layout(event.size.width):
            self.call_after_refresh(self.refresh_view)

    def _fit_layout(self, width: int) -> bool:
        """Switch to or from the compact layout for a terminal `width` wide: one pane, what the
        lane needs above its transcript, a shorter key line. True if it changed."""
        compact = views.compact(width)
        if compact == self.compact:
            return False
        self.compact = compact
        self.set_class(compact, "-compact")
        pane, now, log = self.query_one("#talk-pane"), self.query_one("#now-scroll"), self.query_one("#transcript")
        if compact:
            pane.move_child(now, before=log)
            if self.focused is not None and self.focused.id in ("files", "diff-scroll"):
                self.query_one("#chat", CommandBar).field.focus()  # the files pane is gone
        else:
            pane.move_child(now, after=log)
        self._show_keys()
        return True

    @property
    def simple(self) -> bool:
        """The simple layout is drawn: the app's layout, unless the terminal is narrow enough
        for the compact one."""
        return self.fd.layout == "simple" and not self.compact

    def key_labels(self) -> tuple[tuple[str, str], ...]:
        """The key line's keys now: the layout's, and in the simple one the answers first
        while the lane has any."""
        if self.compact:
            return COMPACT_KEY_LABELS
        return self._simple_labels() if self.simple else KEY_LABELS

    def _simple_labels(self) -> tuple[tuple[str, str], ...]:
        """The simple layout's key line for this lane now: the answers first while it has any
        (1 and 0 while it waits for the player, else the numbers of its alert's)."""
        lane = self.fd.deck.lanes.get(self.lane_id)
        if lane is None or not views.quick_answers(lane):
            return SIMPLE_KEY_LABELS
        return (SIMPLE_YES_NO_LABEL if lane.pending is not None else SIMPLE_ANSWER_LABEL,) + SIMPLE_KEY_LABELS

    def help_now(self) -> tuple[Lane | None, tuple[str, ...]]:
        """What help opens on from this view (P65): the lane, and the keys the simple layout's
        key line has for it now, as that line shows them. In every layout: the deck's and the
        compact one's lines are not about the lane's state, and help's first rows are."""
        return self.fd.deck.lanes.get(self.lane_id), tuple(key for key, _ in self._simple_labels())

    def _show_keys(self, *, again: bool = True) -> None:
        """Draw the key line; with `again` False, only if its keys changed."""
        labels = self.key_labels()
        if again or labels != self._labels:
            self._labels = labels
            self.query_one("#keys", Static).update(_key_line(labels))

    def repaint(self) -> None:
        """Draw everything again in the palette now in use (/theme): the transcript's rows
        were drawn in the old one, so each is drawn again (its token names the palette:
        _rows), where the player was reading; the key line too."""
        if not self._ready:
            return
        self._file_paths = None  # the files list's labels too
        self._show_keys()
        self.refresh_view()

    def relayout(self) -> None:
        """Draw in the layout now in use (/layout): refresh_view shows or hides the parts
        the simple layout shows only when they have something in them, and the key line. The
        transcript is drawn again in the layout's form (calm or in detail), unless the player
        set the details switch by hand in this view."""
        self.refresh_view()

    @property
    def details(self) -> bool:
        """The details switch: as the player set it in this view (ctrl+o, /details), else the
        layout's: off in the simple layout, on in the deck and compact ones."""
        if self._details is not None:
            return self._details
        return self.fd.layout == "deck" or self.compact

    def action_details(self) -> None:
        """ctrl+o, /details: details on or off, and the status line says which."""
        self._details = not self.details
        self.fd.say(DETAILS_ON if self._details else DETAILS_OFF)
        self.refresh_view()

    def _rows(self, lane: Lane) -> list[Row]:
        """The lane's log as the transcript's rows: in detail, each action as
        views.transcript_lines draws it; calm, each entry of views.entries. A row's token is
        all that can change what it draws: the lane, the switch, the palette, and for a run
        of tool calls how far it has grown (the log itself is only added to)."""
        deck, palette = self.fd.deck, theme.active()
        if self.details:
            return [Row(i, (lane.id, True, palette), lambda action=action: Text("\n").join(views.transcript_lines(deck, lane, action)))
                    for i, action in enumerate(lane.actions)]
        return [Row(entry.first, (lane.id, False, palette, len(entry.actions), len(entry.actions[-1].calls)),
                    lambda entry=entry: views.entry_text(deck, lane, entry), one_row=entry.kind != "says")
                for entry in views.entries(lane.actions)]

    def show_lane(self, lane_id: str, file: str | None = None, *, carry: bool = False) -> None:
        """Switch this view to another lane (or reopen it). `carry`: what is typed in the chat
        box goes along (the lane was restarted as `lane_id`: the message is for the fresh one).

        Before the view is composed (a second open queued right behind the one that pushed
        it), only remember the lane: on_mount draws it."""
        if not self._ready:
            self.lane_id, self._first_file = lane_id, file
            return
        chat = self.query_one("#chat", CommandBar)
        if lane_id != self.lane_id and not carry:
            if chat.field.value:
                self._drafts[self.lane_id] = chat.field.value  # kept for when you come back
            chat.clear()
            draft = self._drafts.pop(lane_id, "")
            chat.field.value = draft
            chat.field.cursor_position = len(draft)
        elif not carry:  # carried: the chat box stays as it is (its text, the cursor, an open menu)
            chat.hide_menu()
        if lane_id != self.lane_id:
            self.query_one("#transcript", LaneLog).clear()  # another lane's transcript starts at its end
            self.query_one("#now-scroll", CardScroll).scroll_home(animate=False)  # and its card at its first row
        self.lane_id = lane_id
        self._file_paths = None
        self.diff_path = file or None  # "" means: the newest file
        self.refresh_view()
        if file is not None and not self.compact:
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
            width = max(40, header.size.width or self.size.width - 2)
            header.update(self.fd.header_text(width, clock_keys=False, compact=self.compact))
            self.query_one("#status", Static).update(self.fd.status_text())
            simple = self.simple
            self.set_class(simple, "-simple")
            others = self.query_one("#others", Static)
            others.update(views.others_strip(deck, lane, compact=self.compact, simple=simple))
            others.set_class(simple and not views.needing(deck, exclude=lane.id), "-nothing")
            pane = self.query_one("#talk-pane")
            pane.border_title = views.focus_title(deck, lane, compact=self.compact)
            pane.border_subtitle = views.plan_line(deck, lane)
            self.query_one("#transcript", LaneLog).show(self._rows(lane))  # a player reading back stays where they are
            self._show_card(lane, simple)
            self._render_files()
            self._show_keys(again=False)
            chat = self.query_one("#chat", CommandBar)
            chat.set_suggestions(self.fd.command_suggestions(lane.id, with_lane=False))
            chat.show_title()  # the view may be on another lane now

    def _chat_title(self, typed: str) -> Text:
        """The chat box's title for what is typed: this lane, by name."""
        return views.bar_title(self.fd.deck, typed, self.lane)

    def _show_card(self, lane: Lane, simple: bool) -> None:
        """What the lane needs from the player: the full card, or with details off the calm
        one, its rows fitted to the card's width and cut at its edge, inside a border this
        view draws (the compact layout's card is never calm). No card: no blank row either."""
        calm = not self.details and not self.compact
        self._card_room = self.query_one("#now-scroll", CardScroll).scrollable_content_region.width
        # no room known: the box is not laid out or not shown yet, and the rows are fitted when it is (card_resized)
        width = self._card_room - CALM_EDGE if self._card_room else None
        card = views.now_card(self.fd.deck, lane, compact=self.compact, simple=simple, calm=calm, width=width)
        border = views.card_border(lane) if calm else ""  # "" too for the one line of a lane that ended or needs nothing
        now = self.query_one("#now", Static)
        now.set_class(bool(border), "-calm")
        now.styles.border = ("round", border) if border else None  # its title (on_mount) shows with it
        now.update(card)
        nothing = isinstance(card, Text) and not card.plain
        for part in (now, self.query_one("#now-scroll")):
            part.set_class(nothing, "-nothing")

    def card_resized(self) -> None:
        """The card's box has another width (the terminal's changed, the files pane came or
        went, the box was first shown): the calm card's rows are fitted to it again."""
        if self._ready and self.app.is_running and self.query_one("#now-scroll", CardScroll).scrollable_content_region.width != self._card_room:
            self._show_card(self.lane, self.simple)

    def _render_files(self) -> None:
        lane = self.lane
        paths = list(reversed(lane.files))  # newest first
        files = self.query_one("#files", OptionList)
        pane = self.query_one("#files-pane")
        pane.border_title = Text.assemble(("files changed", "bold"), (f"  {len(paths)}", theme.MUTED))
        hidden = self.simple and not paths  # the simple layout: no pane until the lane changed a file
        if hidden and self.focused is not None and self.focused.id in ("files", "diff-scroll"):
            self.query_one("#chat", CommandBar).field.focus()  # the pane is going: the chat box takes the keys
        pane.set_class(hidden, "-nothing")
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
        diff.update(views.diff_view(self.fd.deck, lane, change) if change else Text("No files changed yet.", theme.MUTED))

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
        """Typing goes to the chat box from any pane (the files list, the diff). `?` while the
        box is empty opens help from there too, as it does in the box (P65)."""
        chat = self.query_one("#chat", CommandBar)
        if event.is_printable and event.character and not chat.field.has_focus:
            event.stop()
            event.prevent_default()
            if event.character == "?" and not chat.field.value:
                self.fd.action_help()
            else:
                chat.start(chat.field.value + event.character)

    def _quick(self, number: str) -> bool:
        """A digit typed into the empty chat box answers the lane, if it has that answer."""
        return self.fd.answer(self.lane, number)

    def action_back(self) -> None:
        """esc: back to the lanes. With text selected it only takes the selection down, and the
        view stays: the next esc goes back."""
        selected = self.get_selected_text()
        self.clear_selection()
        if not selected:
            self.fd.show_fleet(select=self.lane_id)

    def key_escape(self) -> None:
        """esc reaches a screen as a key before its binding runs, and Textual's own screen takes
        the selection down there. This one leaves it to the binding (action_back), which then knows
        there was one."""

    def action_copy(self) -> None:
        """ctrl+c: copy the selected text. With none selected the key goes on, to Textual's
        own hint that ctrl+q quits."""
        if not self.fd.copy_selection():
            raise SkipAction()

    def action_next_needing(self) -> None:
        """The next lane that needs you, in attention order; after the last, the first again."""
        ids = [lane.id for lane in self.fd.deck.needing()]
        if not [lane_id for lane_id in ids if lane_id != self.lane_id]:
            self.fd.inform("No other lane needs you right now")
            return
        nxt = ids[(ids.index(self.lane_id) + 1) % len(ids)] if self.lane_id in ids else ids[0]
        self.show_lane(nxt)

    def action_scroll(self, direction: int) -> None:
        self.query_one("#transcript", LaneLog).page(direction)

    def on_mouse_up(self, event: events.MouseUp) -> None:
        self.query_one("#transcript", LaneLog).released()  # wherever the button came up
