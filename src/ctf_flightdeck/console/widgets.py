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
from . import theme
from .commands import Completion, State, complete, find, no_match


class BarInput(Input):
    """The bar's text field. While it is empty, a digit can answer the lane instead."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.quick: Callable[[str], bool] | None = None

    async def _on_key(self, event: events.Key) -> None:
        if not self.value and event.character and event.character.isdigit() and self.quick and self.quick(event.character):
            event.stop()
            event.prevent_default()
            return
        await super()._on_key(event)


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

    def __init__(self, placeholder: str, *, id: str | None = None) -> None:
        super().__init__(id=id)
        self.bar_placeholder = placeholder
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
        field = self.field
        field.value = text
        field.cursor_position = len(text)
        field.focus()
        self.refresh_menu()

    def clear(self) -> None:
        self.field.value = ""
        self.hide_menu()

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
        only while the name is being typed, which is when enter takes it; `keep` leaves the
        highlight on the row it was on, if that row is still listed."""
        menu = self.menu
        at = menu.highlighted
        held = self.completions[at].text if keep and at is not None and at < len(self.completions) else None
        chosen = self._chosen
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
            menu.highlighted, self._chosen = texts.index(held), chosen
        else:
            menu.highlighted = 0 if texts and " " not in self.field.value else None
        menu.add_class("-open")

    def hide_menu(self) -> None:
        self.menu.remove_class("-open")
        self.completions, self.no_match, self._chosen = [], "", False

    @on(Input.Changed, "#bar-input")
    def _changed(self, event: Input.Changed) -> None:
        event.stop()
        self.refresh_menu()

    @on(Input.Submitted, "#bar-input")
    def _submitted(self, event: Input.Submitted) -> None:
        event.stop()
        value = event.value.strip()
        at = self.menu.highlighted
        if self.menu_open and at is not None and at < len(self.completions) and (self._incomplete(value) or self._chosen):
            self._fill(self.completions[at])
            return
        self.clear()
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
        if not self.menu_open:
            raise SkipAction()
        if step < 0:
            self.menu.action_cursor_up()
        else:
            self.menu.action_cursor_down()
        self._chosen = self.menu.highlighted is not None

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
