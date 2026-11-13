"""The home screen: what `flightdeck` alone opens. Resume an event, start a new one (a form,
here), the practice set, the mock, the solver pack.

It is an app of its own that ends with the player's choice; the command line then does it
(cli._home): the console of a run is another app, and setup that needs a password (sudo, a
package manager) belongs to the plain terminal.

    ("resume", folder) | ("new", NewEvent) | ("practice",) | ("mock",) | ("pack",) | ("setup",) | None
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Input, OptionList, Select, Static
from textual.widgets.option_list import Option

from .. import start
from ..text import untrusted
from . import theme


@dataclass(frozen=True)
class Item:
    choice: tuple  # what the app ends with; ("new",) opens the form instead
    title: str
    detail: str = ""


@dataclass(frozen=True)
class NewEvent:
    answers: start.EventAnswers
    folder: Path
    token: str  # "" for none; never shown, never kept here past the hand-over
    vpn: Path | None


def items(*, have_config: bool, events=(), pack_installed: bool = False) -> list[Item]:
    """The menu, top to bottom: the most recent event first, so Enter resumes it."""
    from ..events import ago

    if not have_config:
        return [Item(("setup",), "Get started", "set flightdeck up: a few questions about your model API, then your first CTF"),
                Item(("mock",), "See a demo", "the console on fake data: no setup, nothing spent")]
    out = []
    for event in events:
        count = f"{event.challenges} challenge{'' if event.challenges == 1 else 's'}"
        out.append(Item(("resume", event.folder), f"Resume {untrusted(event.title, one_line=True)}",
                        f"{count} · played {ago(event.played)} · {event.folder}"))
    out.append(Item(("new",), "Start a new CTF", "its name, site, flag format, token and VPN file; then it launches"))
    out.append(Item(("practice",), "Practice", "14 small challenges on your model (spends tokens)"))
    out.append(Item(("mock",), "Demo", "the console on fake data: nothing spent"))
    if not pack_installed:
        out.append(Item(("pack",), "Install the solver pack", "some 800 no-model solvers that run first on every challenge"))
    return out


def _label(item: Item) -> Text:
    text = Text(no_wrap=True, overflow="ellipsis")
    text.append(item.title, style="bold")
    if item.detail:
        text.append(f"\n{item.detail}", style=theme.MUTED)
    return text


class Menu(Screen):
    BINDINGS = [Binding("q", "quit", "quit"), Binding("escape", "quit", "quit")]

    def __init__(self, menu: list[Item], status: str) -> None:
        super().__init__()
        self.menu, self.status = menu, status

    def compose(self) -> ComposeResult:
        with Vertical(id="home"):
            yield Static(theme.segments([("flightdeck", theme.WHITE, theme.BLUE, True)]), id="brand")
            yield Static(Text("Play CTFs with a fleet of AI agents, and stay the pilot.", style=theme.MUTED))
            yield Static(Text("What would you like to do?", style="bold"), id="ask")
            yield OptionList(*(Option(_label(item), id=str(n)) for n, item in enumerate(self.menu)), id="menu")
            if self.status:
                yield Static(Text(self.status, style=theme.MUTED), id="status")
            keys = Text()
            for key, what in (("↑↓", "move"), ("enter", "choose"), ("q", "quit")):
                keys.append_text(theme.key_chip(key))
                keys.append(f" {what}   ")
            yield Static(keys, id="keys")

    def on_mount(self) -> None:
        self.query_one(OptionList).focus()

    @on(OptionList.OptionSelected)
    def _chosen(self, event: OptionList.OptionSelected) -> None:
        item = self.menu[int(event.option.id)]
        if item.choice == ("new",):
            self.app.push_screen(NewEventForm())
        else:
            self.app.exit(item.choice)

    def action_quit(self) -> None:
        self.app.exit(None)


class NewEventForm(Screen):
    """Start a new CTF: the questions `flightdeck start` asks, as one form."""

    BINDINGS = [Binding("escape", "back", "back"), Binding("ctrl+s", "launch", "launch", priority=True)]

    def compose(self) -> ComposeResult:
        def ask(text: str) -> Static:
            return Static(Text(text, style=theme.MUTED), classes="q")

        yield Static(Text("Start a new CTF", style="bold"), id="formtitle")
        with VerticalScroll(id="form"):
            yield ask("Event name:")
            yield Input(placeholder='e.g. Example CTF 2026', id="name")
            yield ask("How does flightdeck get the challenges?")
            yield Select([(Text("CTFd: the site runs CTFd; flightdeck pulls the board and submits flags"), "ctfd"),
                          (Text("By hand: any other site; you hand challenges over in the console (/new)"), "manual")],
                         value="ctfd", allow_blank=False, id="platform")
            yield ask("The event site's address (CTFd only):")
            yield Input(placeholder="https://ctf.example.org", id="url")
            yield ask("Your CTFd access token (CTFd only; the site's Settings, Access Tokens). It is hidden and goes to your keys file:")
            yield Input(password=True, id="token")
            yield ask("Flag format: what comes before the { in a flag (optional):")
            yield Input(placeholder="PP for PP{...}", id="flag")
            yield ask("When a lane finds a flag (CTFd only):")
            yield Select([(Text("confirm: it waits for you, one key sends it"), "confirm"),
                          (Text("auto: it is sent at once (auto approve)"), "auto")], value="confirm", allow_blank=False, id="submit")
            yield ask("VPN file for live targets (optional: drag the .conf or .ovpn in):")
            yield Input(id="vpn")
            yield ask("Folder for this event (optional; made for you):")
            yield Input(placeholder="~/ctf/<the event's name>", id="folder")
            yield ask("Do this event's rules allow AI tools? flightdeck does not play an event that forbids them:")
            yield Select([(Text("not answered yet"), ""), (Text("yes, the rules allow AI tools"), "yes"),
                          (Text("no"), "no")], value="", allow_blank=False, id="ai")
        yield Static(Text(""), id="problem")  # under the scrolling questions, so it and the keys always show
        keys = Text()
        for key, what in (("ctrl+s", "set it up and launch"), ("tab", "next field"), ("esc", "back")):
            keys.append_text(theme.key_chip(key))
            keys.append(f" {what}   ")
        yield Static(keys, id="formkeys")

    def on_mount(self) -> None:
        self.query_one("#name", Input).focus()

    def _value(self, field: str) -> str:
        return self.query_one(f"#{field}", Input).value.strip()

    def read(self) -> NewEvent:
        """The form as a NewEvent; start.StartError (or ValueError) with what to fix."""
        from .. import vpn as vpns
        from ..config import ConfigError, expand

        name = start.name_answer(self._value("name"))
        platform = str(self.query_one("#platform", Select).value)
        url = start.url_answer(self._value("url")) if platform == "ctfd" else None
        flag = start.flag_format_answer(self._value("flag"))
        submit = str(self.query_one("#submit", Select).value) if platform == "ctfd" else "confirm"
        ai = str(self.query_one("#ai", Select).value)
        if ai != "yes":
            raise start.StartError("answer the last question: flightdeck's lanes are AI agents, and it sets up no event whose "
                                   "rules forbid them")
        try:
            folder = expand(Path(self._value("folder"))) if self._value("folder") else Path.home() / "ctf" / start.slug(name)
            typed = self._value("vpn").strip("'\"").replace("\\ ", " ")
            vpn_file = expand(Path(typed)) if typed else None
        except ConfigError as exc:
            raise start.StartError(str(exc)) from None
        if vpn_file is not None:
            if not vpn_file.is_file():
                raise start.StartError(f"VPN file: {vpn_file}: no such file")
            try:
                vpns.kind_of(vpn_file)
            except vpns.VPNError as exc:
                raise start.StartError(f"VPN file: {exc}") from None
        if start.is_event_folder(folder):
            raise start.StartError(f"{folder} is already an event: go back and resume it, or give another folder")
        token = self.query_one("#token", Input).value.strip() if platform == "ctfd" else ""
        answers = start.EventAnswers(name=name, platform=platform, url=url, flag_format=flag, submit=submit,
                                     token_env=start.token_variable(name) if platform == "ctfd" else None)
        return NewEvent(answers, folder, token, vpn_file)

    def action_launch(self) -> None:
        try:
            new = self.read()
        except (start.StartError, ValueError) as exc:
            self.query_one("#problem", Static).update(Text(str(exc), style=theme.YELLOW))
            return
        self.app.exit(("new", new))

    def action_back(self) -> None:
        self.app.pop_screen()


class HomeApp(App):
    TITLE = "flightdeck"
    CSS = f"""
    Screen {{ background: {theme.PAGE}; align: center middle; }}
    #home {{ width: 100; max-width: 100%; height: auto; border: round {theme.BORDER}; padding: 1 3; }}
    #ask {{ margin-top: 1; }}
    #menu {{ height: auto; max-height: 24; margin-top: 1; border: none; background: transparent; padding: 0; }}
    #menu > .option-list--option-highlighted {{ background: {theme.SELECTED}; }}
    #status, #keys, #formkeys {{ margin-top: 1; }}
    NewEventForm {{ align: center top; padding: 1 2; }}
    #formtitle, #problem, #formkeys {{ width: 110; max-width: 100%; padding: 0 3; height: auto; }}
    #form {{ width: 110; max-width: 100%; height: 1fr; border: round {theme.BORDER}; padding: 0 3 1 3; }}
    #form .q {{ margin-top: 1; }}
    #form Input {{ border: round {theme.BORDER}; }}
    #form Input:focus {{ border: round {theme.ACCENT}; }}
    """

    def __init__(self, menu: list[Item], status: str = "") -> None:
        super().__init__()
        self.menu, self.status = menu, status

    def get_default_screen(self) -> Screen:
        return Menu(self.menu, self.status)
