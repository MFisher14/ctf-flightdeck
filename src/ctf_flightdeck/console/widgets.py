"""The command bar: plain text messages a lane, `/` runs a command with a completion menu.

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
from .commands import BY_NAME, Completion, complete


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
    DEFAULT_CSS = f"""
    CommandBar {{ height: auto; padding: 0 1; }}
    CommandBar > #menu {{
        display: none; height: auto; max-height: 10;
        border: round {theme.ACCENT}; background: $surface; padding: 0 1;
    }}
    CommandBar > #menu.-open {{ display: block; }}
    CommandBar > Input {{ border: round {theme.BORDER}; background: transparent; padding: 0 1; }}
    CommandBar > Input:focus {{ border: round {theme.ACCENT}; }}
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
        self.completions: list[Completion] = []

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

    def set_suggestions(self, suggestions: tuple[tuple[str, str], ...]) -> None:
        """New suggestions (the lane's changed, or another lane is selected); an open menu follows."""
        if suggestions == self.suggestions:
            return
        self.suggestions = suggestions
        if self.menu_open:
            self.refresh_menu()

    def refresh_menu(self) -> None:
        self.completions = complete(self.field.value, self.suggestions)[:8]
        menu = self.menu
        menu.clear_options()
        if not self.completions:
            self.hide_menu()
            return
        for completion in self.completions:
            label = Text(untrusted(completion.label, one_line=True), style="bold" if completion.suggested else "", no_wrap=True, overflow="ellipsis")
            if completion.suggested:
                label.append("   suggested", style=f"italic {theme.ACCENT}")
            label.append(f"   {untrusted(completion.help, one_line=True)}", style=theme.MUTED)
            menu.add_option(Option(label))
        menu.highlighted = 0
        menu.add_class("-open")

    def hide_menu(self) -> None:
        self.menu.remove_class("-open")
        self.completions = []

    @on(Input.Changed, "#bar-input")
    def _changed(self, event: Input.Changed) -> None:
        event.stop()
        self.refresh_menu()

    @on(Input.Submitted, "#bar-input")
    def _submitted(self, event: Input.Submitted) -> None:
        event.stop()
        value = event.value.strip()
        if self.menu_open and self._incomplete(value):
            self.action_accept()
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
        return value.startswith("/") and value[1:].partition(" ")[0].lower() not in BY_NAME

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

    def action_accept(self) -> None:
        index = self.menu.highlighted
        if not self.menu_open or index is None or index >= len(self.completions):
            raise SkipAction()
        self._fill(self.completions[index])

    def action_dismiss(self) -> None:
        if not self.menu_open:
            raise SkipAction()
        self.hide_menu()
