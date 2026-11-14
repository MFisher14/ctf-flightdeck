"""The command bar: plain text messages a lane, `/` runs a command with a completion menu.
The menu lists every command that matches what is typed and scrolls with the arrow keys;
with no lane to act on, the commands that need none come first (commands.complete).
After a command's name it lists the words that command takes, and when what is typed
names no command it says so in one row and stays open (P62).

The menu only ever fills the bar: tab takes a row, and so does enter while the name is
not yet a command or once the arrow keys have chosen a row. Anything else enter sends as
typed, and commands.parse decides what it is.

Menu entries can carry lane text (a suggested redirect, a candidate flag), so they are
drawn through text.untrusted() like everything else from a lane.

The bar's border carries a title: who what is typed goes to (P64). The screen that hosts
the bar says it (views.bar_title: the lane, `no lane`, `the run`, or that the lane has
finished or takes no more turns), for the text typed so far; the bar asks again at every key, and the screen has it ask whenever its lane changes.

Up and down walk back through what the player sent this run, as a shell's history does (P71):
the bars of both views share one History, which the app keeps (in memory only, never in a
file). The bar is one line, so the arrows never moved a cursor; while the menu is open they
move in the menu, as before. ctrl+g opens what is typed in the player's editor (editor.py),
and what it holds when the editor exits is the bar's text again: nothing is sent until enter.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.text import Text
from textual import events, on
from textual.actions import SkipAction
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Input, OptionList
from textual.widgets.option_list import Option

from ..text import untrusted
from . import editor, theme
from .commands import Completion, State, complete, find, no_match

# What the empty bar says, in the lane list and in a lane's view: the border's title names the lane.
BAR = "a message, or / for commands"


class BarInput(Input):
    """The bar's text field. While it is empty, a digit can answer the lane instead, and `?`
    opens help (P65): the screen that hosts the bar says how (`quick`, `help`). With anything
    in the field, a space too, both are text: a message can begin with a `?` typed after a
    space (what is sent has no blanks at its ends), or pasted."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.quick: Callable[[str], bool] | None = None  # a digit: True if it answered the lane
        self.help: Callable[[], None] | None = None  # `?`: open help for where the player is

    async def _on_key(self, event: events.Key) -> None:
        if not self.value and event.character:
            if event.character.isdigit() and self.quick and self.quick(event.character):
                event.stop()
                event.prevent_default()
                return
            if event.character == "?" and self.help:
                event.stop()
                event.prevent_default()
                self.help()
                return
        await super()._on_key(event)


class History:
    """What the player sent from a command bar this run, oldest first: every message and
    command enter sent, a repeat of the last one kept once, the oldest let go past LIMIT."""

    LIMIT = 500

    def __init__(self) -> None:
        self.entries: list[str] = []

    def add(self, text: str) -> None:
        if text and (not self.entries or self.entries[-1] != text):
            self.entries.append(text)
            del self.entries[:-self.LIMIT]


class CommandBar(Vertical):
    DEFAULT_CSS = """
    CommandBar { height: auto; padding: 0 1; }
    CommandBar > #menu {
        display: none; height: auto; max-height: 10;
        border: round $fd-accent; background: $fd-surface; padding: 0 1;
    }
    CommandBar > #menu.-open { display: block; }
    CommandBar > Input { border: round $fd-border; background: transparent; padding: 0 1; }
    CommandBar > Input:focus { border: round $fd-accent; }
    """
    BINDINGS = [
        Binding("up", "menu(-1)", show=False),
        Binding("down", "menu(1)", show=False),
        Binding("tab", "accept", "complete", show=False),
        Binding("escape", "dismiss", show=False),
        Binding("ctrl+g", "editor", "edit in your editor", show=False),
    ]

    class Submitted(Message):
        """The player pressed enter on a message or a complete command ("" for an empty bar)."""

        def __init__(self, bar: CommandBar, value: str) -> None:
            super().__init__()
            self.bar = bar
            self.value = value

        @property
        def control(self) -> CommandBar:
            return self.bar

    def __init__(self, placeholder: str, *, id: str | None = None, title: Callable[[str], Text] | None = None,
                 history: History | None = None) -> None:
        """`history`: what was sent, shared with the other bars of the run (None: this bar's own)."""
        super().__init__(id=id)
        self.history = history if history is not None else History()
        self._recalled: int | None = None  # the entry of the history up and down have put in the field; None: not walking it
        self._recalled_text = ""  # that entry's text
        self._draft = ""  # what was typed before the walk began: down past the newest entry brings it back
        self.bar_placeholder = placeholder
        self.title = title  # the border's title for the text typed so far (None: the bar has none)
        self._title: tuple | None = None  # the one shown: its text and its colours
        self.suggestions: tuple[tuple[str, str], ...] = ()  # (command, why), from the lane's alerts
        self.has_lane = True  # there is a lane the bar acts on (the fleet with none selected: False)
        self.completions: list[Completion] = []
        self.no_match = ""  # the menu's one row while what is typed names no command
        self._chosen = False  # the arrow keys moved to a row: enter takes it

    def compose(self) -> ComposeResult:
        yield OptionList(id="menu")
        yield BarInput(placeholder=self.bar_placeholder, id="bar-input", select_on_focus=False)

    def on_mount(self) -> None:
        self.field.cursor_blink = False  # a steady cursor keeps screenshots deterministic

    @property
    def field(self) -> BarInput:
        return self.query_one("#bar-input", BarInput)

    @property
    def menu(self) -> OptionList:
        return self.query_one("#menu", OptionList)

    @property
    def menu_open(self) -> bool:
        return self.menu.has_class("-open")

    def start(self, text: str = "") -> None:
        """Focus the bar with `text` in it."""
        self._recalled = None
        field = self.field
        field.value = text
        field.cursor_position = len(text)
        field.focus()
        self.refresh_menu()

    def clear(self) -> None:
        self._recalled = None
        self.field.value = ""
        self.hide_menu()

    def show_title(self) -> None:
        """The title on the bar's border, for what is typed now: who it goes to, as the screen
        that hosts the bar says. The screen calls this when the lane the bar acts on may have
        changed (another is selected, the board took the focus, the theme's colours changed)."""
        if self.title is None:
            return
        title = self.title(self.field.value)
        shown = (title.plain, str(title.style), tuple(title.spans))  # Text's own == passes over its base style
        if shown != self._title:  # only a title that changed, in words or in colours, is drawn again
            self._title = shown
            self.field.border_title = title

    def set_placeholder(self, text: str) -> None:
        """What the empty bar says (it changes with what the player can do now)."""
        self.bar_placeholder = text
        self.field.placeholder = text

    def set_suggestions(self, suggestions: tuple[tuple[str, str], ...], *, lane: bool = True) -> None:
        """New suggestions (the lane's changed, or another lane is selected), and whether there
        is a lane to act on; an open menu follows. The screens call this each time they draw, so
        an open menu also follows the console: a lane it lists changed state, a challenge was parked."""
        changed = suggestions != self.suggestions or lane != self.has_lane
        self.suggestions, self.has_lane = suggestions, lane
        if self.menu_open and (changed or self._listed() != (self.completions, self.no_match)):
            self.refresh_menu(keep=True)

    def _state(self) -> State:
        """What the console has now, for the words that depend on it. The app that hosts the bar
        says (FlightdeckApp.command_state); in an app that does not, those words are not offered."""
        ask = getattr(self.app, "command_state", None)
        return ask() if ask is not None else State()

    def _listed(self) -> tuple[list[Completion], str]:
        """The menu's rows for what is typed, and its one row when there are none to list."""
        typed = self.field.value
        completions = complete(typed, self.suggestions, lane=self.has_lane, state=self._state)
        return completions, "" if completions else no_match(typed)

    def refresh_menu(self, *, keep: bool = False) -> None:
        """Every entry that matches what is typed: the menu shows eight rows and scrolls to the rest.
        With none, and no command named: one muted row that says so. The first row is highlighted
        only while the name is being typed, which is when enter takes it; `keep` leaves a row
        the arrow keys chose highlighted, if it is still listed."""
        menu = self.menu
        at = menu.highlighted
        held = self.completions[at].text if keep and self._chosen and at is not None and at < len(self.completions) else None
        self.completions, self.no_match = self._listed()
        menu.clear_options()
        self._chosen = False
        if not self.completions and not self.no_match:
            self.hide_menu()
            return
        if self.no_match:
            menu.add_option(Option(Text(untrusted(self.no_match, one_line=True), style=theme.MUTED, no_wrap=True, overflow="ellipsis"),
                                   disabled=True))
        for completion in self.completions:
            label = Text(untrusted(completion.label, one_line=True), style="bold" if completion.suggested else "", no_wrap=True, overflow="ellipsis")
            if completion.also:
                label.append(f" ({completion.also})", style=theme.MUTED)
            if completion.suggested:
                label.append("   suggested", style=f"italic {theme.ACCENT}")
            label.append(f"   {untrusted(completion.help, one_line=True)}", style=theme.MUTED)
            menu.add_option(Option(label))
        texts = [completion.text for completion in self.completions]
        if held in texts:
            menu.highlighted, self._chosen = texts.index(held), True
        else:
            menu.highlighted = 0 if texts and " " not in self.field.value else None
        menu.add_class("-open")

    def hide_menu(self) -> None:
        self.menu.remove_class("-open")
        self.completions, self.no_match, self._chosen = [], "", False

    @on(Input.Changed, "#bar-input")
    def _changed(self, event: Input.Changed) -> None:
        event.stop()
        if self._recalled is not None and self.field.value == self._recalled_text:
            self.show_title()  # an entry up or down put there: no menu, so the next arrow goes on through the history
            return
        self._recalled = None  # typed: the walk is over, and the next up starts it again from what is in the field
        self.refresh_menu()
        self.show_title()

    @on(Input.Submitted, "#bar-input")
    def _submitted(self, event: Input.Submitted) -> None:
        event.stop()
        value = event.value.strip()
        at = self.menu.highlighted
        if self.menu_open and at is not None and at < len(self.completions) and (self._incomplete(value) or self._chosen):
            self._fill(self.completions[at])
            return
        self.clear()
        self.history.add(value)
        self.post_message(self.Submitted(self, value))

    @on(OptionList.OptionSelected, "#menu")
    def _picked(self, event: OptionList.OptionSelected) -> None:
        event.stop()
        self._fill(self.completions[event.option_index])

    @staticmethod
    def _incomplete(value: str) -> bool:
        """A slash with no known command name yet: enter completes instead of running."""
        return value.startswith("/") and find(value[1:].partition(" ")[0]) is None

    def _fill(self, completion: Completion) -> None:
        text = untrusted(completion.text, one_line=True)
        self.field.value = text
        self.field.cursor_position = len(text)
        self.field.focus()

    def action_menu(self, step: int) -> None:
        """Up and down: a row of the open menu, else the history."""
        if not self.menu_open:
            self._walk(step)
            return
        if step < 0:
            self.menu.action_cursor_up()
        else:
            self.menu.action_cursor_down()
        self._chosen = self.menu.highlighted is not None

    def _walk(self, step: int) -> None:
        """One entry back (-1) or on (1) through what was sent. The first step back keeps what
        is typed, and a step on past the newest entry brings it back; at the oldest, up stays."""
        entries = self.history.entries
        if step < 0:
            if not entries:
                raise SkipAction()
            if self._recalled is None:
                self._draft, at = self.field.value, len(entries) - 1
            else:
                at = max(self._recalled - 1, 0)
        else:
            if self._recalled is None:
                raise SkipAction()
            at = self._recalled + 1
            if at >= len(entries):  # past the newest
                self._recalled = None
                self._put(self._draft)
                return
        at = min(at, len(entries) - 1)
        self._recalled, self._recalled_text = at, entries[at]
        self.hide_menu()
        self._put(entries[at])

    def _put(self, text: str) -> None:
        self.field.value = text
        self.field.cursor_position = len(text)

    def action_editor(self) -> None:
        """ctrl+g: what is typed, in the player's editor; back in the bar when it exits."""
        self.run_worker(self._edit(self.field.value), name="editor", group="editor", exclusive=True, exit_on_error=False)

    async def _edit(self, text: str) -> None:
        try:
            line, lines = await editor.edit(self.app, text)
        except editor.EditorError as exc:
            self._say(str(exc), warn=True)
            return
        self.start(line)
        if lines > 1:
            self._say(f"Your editor's {lines} lines are one line here, joined by spaces: enter sends it")
        else:
            self._say("Back from your editor: enter sends it")

    def _say(self, text: str, *, warn: bool = False) -> None:
        """On the status line of the app that hosts the bar (FlightdeckApp.say); an app with
        none shows it as a notification."""
        say = getattr(self.app, "say", None)
        if say is not None:
            say(text, "warning" if warn else "information")
        else:
            self.notify(text, severity="warning" if warn else "information")

    def action_accept(self) -> None:
        """Tab: the highlighted row into the bar, or the first when none is."""
        if not self.menu_open or not self.completions:
            raise SkipAction()
        index = self.menu.highlighted
        self._fill(self.completions[index if index is not None and index < len(self.completions) else 0])

    def action_dismiss(self) -> None:
        if not self.menu_open:
            raise SkipAction()
        self.hide_menu()
