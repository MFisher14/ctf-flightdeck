"""The home screen: what `flightdeck` alone opens. Resume an event, start a new one (a form,
here), the practice set, the mock, the solver pack; with no config yet, first-time setup (a
form, here) and then the practice set.

It is an app of its own that ends with the player's choice; the command line then does it
(cli._home) and opens the home screen again when a run ends: the console of a run is another
app, and setup that needs a password (sudo, a package manager) belongs to the plain
terminal. Neither form writes anything: each ends the app with its answers, checked.

    ("resume", folder) | ("new", NewEvent) | ("setup", Setup) | ("image", then) | ("practice",) | ("mock",) | ("pack",) | None

Settings and health (health.py) is a screen here too, and ends nothing: esc comes back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Input, OptionList, Select, Static
from textual.widgets.option_list import Option

from .. import setup as setups
from .. import start, themes
from ..platform.http import PRESETS
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
    notes: tuple[str, ...] = ()  # what the player is told once the form has closed (a token variable that was not used, and why)


@dataclass(frozen=True)
class Setup:
    """What the setup form ends with: the config to write and the key to keep."""

    answers: setups.Answers
    provider: str  # as the player chose it (setup.PROVIDER_CHOICES): what is said afterwards depends on it
    key: str = field(default="", repr=False)  # "" for none; never shown, never kept here past the hand-over
    then: str = "practice"  # what the player came for, offered first once it is set up: "practice" | "new"


@dataclass(frozen=True)
class Ready:
    """What the home screen opens on once flightdeck is set up: what was done, and what next."""

    notes: tuple[str, ...] = ()
    build: bool = False  # the lane image is still to build: offered first, since Docker lanes cannot start without it
    first: str = "practice"  # what the player came for: "practice" | "new"


NEW_CTF = "its name, site, flag format, token and VPN file; then it launches"
HEALTH = "what your config sets, and whether this machine is ready to play (flightdeck doctor's checks)"


def items(*, have_config: bool, events=(), pack_installed: bool = False) -> list[Item]:
    """The menu, top to bottom: the most recent event first, so Enter resumes it. With no
    config the first choice is setup, which leads to the practice set; starting an event is
    one below, and asks the same setup first."""
    from ..events import ago

    if not have_config:
        return [Item(("setup", "practice"), "Get started",
                     "set flightdeck up here (your model API, its key, where lanes run), then try the practice set"),
                Item(("setup", "new"), "Start a new CTF", "the same setup first, then your event: its name, site, token and VPN file"),
                Item(("mock",), "See a demo", "the console on fake data: no setup, nothing spent")]
    out = []
    for event in events:
        count = f"{event.challenges} challenge{'' if event.challenges == 1 else 's'}"
        out.append(Item(("resume", event.folder), f"Resume {untrusted(event.title, one_line=True)}",
                        f"{count} · played {ago(event.played)} · {event.folder}"))
    out.append(Item(("new",), "Start a new CTF", NEW_CTF))
    out.append(Item(("practice",), "Practice", "14 small challenges on your model (spends tokens)"))
    out.append(Item(("mock",), "Demo", "the console on fake data: nothing spent"))
    if not pack_installed:
        out.append(Item(("pack",), "Install the solver pack", "some 800 no-model solvers that run first on every challenge"))
    out.append(Item(("health",), "Settings and health", HEALTH))
    return out


def ready_items(ready: Ready) -> list[Item]:
    """What the home screen offers once flightdeck is set up: the practice set first (the
    bundled challenges, before any question about an event), then starting an event; the
    other way round for a player who came to start one. Before both, building the lane image
    when Docker lanes still need it."""
    practice = Item(("practice",), "Practice", "the 14 small challenges that ship with flightdeck, on your model (spends tokens)")
    new = Item(("new",), "Start a new CTF", NEW_CTF)
    out = [new, practice] if ready.first == "new" else [practice, new]
    if ready.build:
        out.insert(0, Item(("image", ready.first), "Build the lane image",
                           "what a Docker lane's shell has inside: built once (about 830 MB), then you are back here"))
    out.append(Item(("menu",), "Home", "everything else: the demo, the solver pack, settings and health"))
    return out


def _label(item: Item) -> Text:
    text = Text(no_wrap=True, overflow="ellipsis")
    text.append(item.title, style="bold")
    if item.detail:
        text.append(f"\n{item.detail}", style=theme.MUTED)
    return text


class Menu(Screen):
    BINDINGS = [Binding("q", "quit", "quit"), Binding("escape", "quit", "quit")]

    def __init__(self, menu: list[Item], status: str, *, ask: str = "What would you like to do?", notes: tuple[str, ...] = ()) -> None:
        """`notes`: lines above the question (what setup did, once it is done)."""
        super().__init__()
        self.menu, self.status, self.ask, self.notes = menu, status, ask, notes

    def compose(self) -> ComposeResult:
        with Vertical(id="home"):
            yield Static(theme.segments([("flightdeck", theme.WHITE, theme.BLUE, True)]), id="brand")
            yield Static(Text("Play CTFs with a fleet of AI agents, and stay the pilot.", style=theme.MUTED))
            if self.notes:
                yield Static(Text("\n".join(self.notes), style=theme.MUTED), id="notes")
            yield Static(Text(self.ask, style="bold"), id="ask")
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
        elif item.choice[0] == "setup":
            self.app.push_screen(SetupForm(then=item.choice[1]))
        elif item.choice == ("health",):
            from .health import HealthScreen

            self.app.push_screen(HealthScreen())
        elif item.choice == ("menu",):  # from what setup offers, to everything else (over it: q there quits the app all the same)
            self.app.push_screen(Menu(self.app.menu, self.app.status))
        else:
            self.app.exit(item.choice)

    def action_quit(self) -> None:
        self.app.exit(None)


class SetupForm(Screen):
    """First-time setup: the questions `flightdeck init` asks, as one form, checked by init's
    own answer functions (setup.py). Every provider has models to offer, so no choice stops
    at an empty field; the key is typed out of sight. Like the event form it writes nothing:
    the app ends with the answers (Setup), and the command line writes the config and puts
    the key in the keys file (cli._set_up)."""

    BINDINGS = [Binding("escape", "back", "back"), Binding("ctrl+s", "save", "save", priority=True)]
    RUNTIMES = (("docker", "docker: a container per lane"),
                ("host", "host: lanes run as you, on this machine, and can read your files and keys"))
    UNDECIDED = ("", "not decided yet: looking for Docker (or choose one yourself)")  # no runtime: nothing is saved with it

    def __init__(self, then: str = "practice") -> None:
        super().__init__()
        self.then = then
        self._offered = ""  # the models this form put in the field: replaced with the next provider's unless the player changed them

    def compose(self) -> ComposeResult:
        def ask(text: str, **more) -> Static:
            return Static(Text(text, style=theme.MUTED), classes="q", **more)

        yield Static(Text("Set flightdeck up", style="bold"), id="formtitle")
        with VerticalScroll(id="form"):
            yield ask(setups.PROVIDER_QUESTION)
            menu = setups.provider_menu()
            yield Select([(Text(label), name) for name, label in menu], value=menu[0][0], allow_blank=False, id="provider")
            yield Static(Text(setups.AGENT_NOTE, style=theme.MUTED))
            yield ask("The API's address (OpenAI-compatible, usually ending in /v1):", id="urlq")
            yield Input(placeholder="https://models.example.org/v1", id="url")
            yield ask("The environment variable that will hold its key (its name, never the key; empty for a server that needs none):",
                      id="keyenvq")
            yield Input(placeholder="MY_MODEL_KEY", id="keyenv")
            yield ask("", id="keyq")  # what is asked depends on the provider: _key_question
            yield Input(password=True, id="key")
            yield ask("Models, weakest first, comma-separated (a lane starts on the first and escalates to the next):")
            yield Input(id="models")
            yield Static(Text(""), id="modelswhy")
            yield ask(setups.RUNTIME_QUESTION + ":")
            yield Select([(Text(label), name) for name, label in (self.UNDECIDED, *self.RUNTIMES)], value=self.UNDECIDED[0],
                         allow_blank=False, id="runtime")
            yield Static(Text("Looking for Docker… what is offered depends on whether it runs here.", style=theme.MUTED),
                         id="dockerfound")
        yield Static(Text(""), id="problem")  # under the scrolling questions, so it and the keys always show
        keys = Text()
        for key, what in (("ctrl+s", "save and go on"), ("tab", "next field"), ("esc", "back")):
            keys.append_text(theme.key_chip(key))
            keys.append(f" {what}   ")
        yield Static(keys, id="formkeys")

    def on_mount(self) -> None:
        self._provider_shown()
        self.query_one("#provider", Select).focus()
        self.run_worker(self._find_docker(), name="docker")  # this screen's: cancelled when it closes or the app ends

    def _value(self, field: str) -> str:
        return self.query_one(f"#{field}", Input).value.strip()

    def _provider(self) -> str:
        return str(self.query_one("#provider", Select).value)

    # ---- the runtime: Docker when it can run lanes here, else this machine

    async def _find_docker(self) -> None:
        """`docker version` can take seconds, or 20 of them when the daemon hangs: it is asked
        beside the form, which stays the player's, and killed when the form closes or the
        app ends, so leaving never waits for it. Until it answers the runtime is not decided
        (UNDECIDED), and read() saves none."""
        from ..agent.workspace import docker_unavailable_stoppable

        self._docker_found(await docker_unavailable_stoppable())

    def _docker_found(self, reason: str | None) -> None:
        """Offer the runtime Docker's answer decides, unless the player chose one meanwhile:
        any choice of theirs stands, docker too. "Not decided" is no choice from here on."""
        if not self.is_attached:  # the form has closed. Not is_mounted: an answer that comes while
            return  # the form's on_mount is still being handled (no Docker on PATH answers at once) would be dropped
        select = self.query_one("#runtime", Select)
        chosen = str(select.value)  # "" when the player has chosen none
        found = "Docker is running here" if reason is None else f"Docker cannot run lanes here ({reason})"
        if chosen:
            said = f"{found}. Your choice, {chosen}, stands"
            if reason is not None and chosen == "docker":
                said += ": install or start Docker before a run, or choose host"
            elif reason is None and chosen == "host":
                said += ": docker is the safer one"
            said += "."
        elif reason is None:
            said = f"{found}, so docker is offered: the safe choice."
        else:
            said = f"{found}, so host is offered. For the safer setup, install or start Docker and choose docker."
        select.set_options([(Text(label), name) for name, label in self.RUNTIMES])
        select.value = chosen or ("docker" if reason is None else "host")
        self.query_one("#dockerfound", Static).update(Text(said, style=theme.MUTED))

    # ---- what the provider decides: the fields shown, the models offered, the key asked for

    @on(Select.Changed, "#provider")
    def _provider_changed(self, event: Select.Changed) -> None:
        self._provider_shown()

    @on(Input.Changed, "#keyenv")
    def _key_variable_typed(self, event: Input.Changed) -> None:
        self._key_question()

    def _provider_shown(self) -> None:
        provider = self._provider()
        for field in ("urlq", "url", "keyenvq", "keyenv"):  # a custom API alone has an address and a variable to name
            self.query_one(f"#{field}").display = provider == "custom"
        models = self.query_one("#models", Input)
        offered, why = setups.default_models(provider)
        if models.value.strip() in ("", self._offered):  # never over what the player typed
            models.value = offered
        self._offered = offered
        said = f"Offered: {why}. Any model ids your API serves will do." if why else "The ids your server gives its models."
        self.query_one("#modelswhy", Static).update(Text(said, style=theme.MUTED))
        self._key_question()

    def _key_variable(self) -> str | None:
        """The variable the provider's key goes under: "" when it needs no key, None when a
        custom API's variable is not a name yet."""
        variable = setups.provider_api(self._provider())[1]
        if variable is None:
            try:
                return setups.key_env_answer(self._value("keyenv"))
            except setups.AnswerError:
                return None
        return variable

    def _key_question(self) -> None:
        """Ask for the key the provider needs, saying where it goes; or say that none is
        needed, or that one is set already. Never anything of a key itself."""
        from .. import keys

        variable = self._key_variable()
        style = theme.MUTED
        if variable is None:
            said = "Your API key: asked for once the variable above is named."
        elif not variable:
            said = "Your API key: none needed" + (" for a server on this machine." if self._provider() in setups.LOCAL_PROVIDERS else ".")
        else:
            try:
                where = keys.source(variable)
            except keys.KeysError as exc:
                said, style = f"Your API key: {exc}", theme.YELLOW
            else:
                if where is None:
                    said = f"Your API key (hidden as you paste; it goes to your keys file as {variable}, never into the config):"
                else:
                    said = (f"Your API key: {variable} is already set in your {where}. Leave this empty to use it, or paste "
                            "another for your keys file (hidden):")
        self.query_one("#key", Input).display = bool(variable)
        self.query_one("#keyq", Static).update(Text(said, style=style))

    # ---- the answers

    def read(self) -> Setup:
        """The form as a Setup; setup.AnswerError with what to fix. Everything that can stop
        the config being written or the key kept is found here, while the form is open and
        the answers are still in it; no message shows an answer (one may be a key typed in
        the wrong field)."""
        from .. import keys
        from ..config import ConfigError, default_config_path

        def checked(label: str, check, text: str):
            try:
                return check(text)
            except setups.AnswerError as exc:
                raise setups.AnswerError(f"{label}: {exc}") from None

        provider = self._provider()
        base_url = key_env = None
        if provider == "custom":
            base_url = checked("Address", setups.base_url_answer, self._value("url"))
            key_env = checked("Variable", setups.key_env_answer, self._value("keyenv"))
        ladder = checked("Models", setups.models_answer, self._value("models"))
        chosen = str(self.query_one("#runtime", Select).value)
        if chosen == self.UNDECIDED[0]:  # never a runtime that nobody chose and nothing decided
            raise setups.AnswerError("Runtime: still looking for Docker, which decides what is offered (up to 20 s when Docker "
                                     "does not answer). Wait for it, or choose docker or host yourself")
        runtime = checked("Runtime", setups.runtime_answer, chosen)
        answers = setups.answers_for(provider, ladder, runtime, base_url=base_url, key_env=key_env)
        key = self.query_one("#key", Input).value.strip() if answers.key_env else ""
        if answers.key_env:
            if key and keys.value_problem(key) is not None:
                raise setups.AnswerError(f"API key: it {keys.value_problem(key)}")
            try:
                where = keys.source(answers.key_env)
                keys.load_keys()  # a keys file flightdeck refuses would refuse this key too
            except keys.KeysError as exc:
                raise setups.AnswerError(f"API key: {exc}") from None
            if not key and where is None:
                raise setups.AnswerError(f"API key: paste your key (it is kept in your keys file as {answers.key_env}); or quit, "
                                         f"export {answers.key_env} and run flightdeck again")
        try:
            path = default_config_path()
            setups.check_config(answers, path)
        except ConfigError as exc:
            raise setups.AnswerError(str(exc)) from None
        except FileExistsError:
            raise setups.AnswerError(f"{path} was written while this form was open: quit (esc, then q) and run flightdeck "
                                     "again to use it") from None
        return Setup(answers, provider, key, self.then)

    def action_save(self) -> None:
        try:
            done = self.read()
        except ValueError as exc:  # setup.AnswerError is one
            self.query_one("#problem", Static).update(Text(str(exc), style=theme.YELLOW))
            return
        self.app.exit(("setup", done))

    def action_back(self) -> None:
        self.app.pop_screen()


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
                          (Text("rCTF, rCTF v2, noCTF or GZCTF: the same, through the site's JSON API"), "http"),
                          (Text("By hand: any other site; you hand challenges over in the console (/new)"), "manual")],
                         value="ctfd", allow_blank=False, id="platform")
            yield ask("Which of them the site runs (rCTF, noCTF or GZCTF only; when you cannot tell rCTF from v2, rCTF plays both):")
            yield Select([(Text(start.PRESET_LABELS[preset]), preset) for preset in PRESETS], value=PRESETS[0], allow_blank=False,
                         id="preset")
            yield ask("The event site's address (not by hand; noCTF: its API's, from the browser's network tab; GZCTF: the game's page will do):")
            yield Input(placeholder="https://ctf.example.org", id="url")
            yield ask("The game's number (GZCTF only, unless the address above is the game's page: https://.../games/3):")
            yield Input(placeholder="3", id="game")
            yield Static(Text(start.token_help("ctfd").capitalize() + ". It is hidden and goes to your keys file:", style=theme.MUTED),
                         classes="q", id="tokenq")
            yield Input(password=True, id="token")
            yield ask("Flag format: what comes before the { in a flag, or an example flag from the rules (optional):")
            yield Input(placeholder="PP for PP{...}", id="flag")
            yield Static(Text(""), id="flagread")  # what was made of it, as it is typed: an example flag is read as its prefix
            yield ask("When a lane finds a flag (not by hand):")
            yield Select([(Text("confirm: it waits for you, one key sends it"), "confirm"),
                          (Text("auto: it is sent at once (auto approve)"), "auto")], value="confirm", allow_blank=False, id="submit")
            yield ask("VPN file for live targets (optional: drag the .conf or .ovpn in):")
            yield Input(id="vpn")
            yield ask("Folder for this event (optional; made for you):")
            yield Input(placeholder="~/ctf/<the event's name>", id="folder")
            yield ask("Label your team declared to the event for its AI use, in the event's words (optional; like Human-Led AI):")
            yield Input(id="label")
            yield ask("Do this event's rules allow AI agents on the challenges, with each challenge's text and files given to a model? "
                      "flightdeck's lanes do both, and it does not play an event that forbids either:")
            yield Select([(Text("not answered yet"), ""), (Text("yes, the rules allow both"), "yes"),
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

    @on(Select.Changed, "#platform")
    @on(Select.Changed, "#preset")
    def _token_said(self, _event: Select.Changed) -> None:
        """Say where this platform's token is, above its field: CTFd's, rCTF's, noCTF's and
        GZCTF's are each somewhere else on the site."""
        platform = str(self.query_one("#platform", Select).value)
        preset = str(self.query_one("#preset", Select).value)
        help = start.token_help(platform, preset) if platform in start.SIGNS_IN else "the token (none: by hand, flightdeck never signs in)"
        self.query_one("#tokenq", Static).update(Text(help[0].upper() + help[1:] + ". It is hidden and goes to your keys file:",
                                                      style=theme.MUTED))

    @on(Input.Changed, "#flag")
    def _flag_read(self, event: Input.Changed) -> None:
        """Say what the flag format was understood as, under the field, while it is typed."""
        try:
            pattern, understood = start.flag_format_read(event.value)
            said = Text(understood if pattern is not None else "", style=theme.MUTED)
        except start.StartError as exc:
            said = Text(str(exc), style=theme.YELLOW)
        self.query_one("#flagread", Static).update(said)

    def read(self) -> NewEvent:
        """The form as a NewEvent; start.StartError (or ValueError) with what to fix. Everything
        that can stop the event being set up is found here, while the form is open and the
        answers are still in it: the folder, the VPN file, the token, the keys file."""
        from .. import keys
        from .. import vpn as vpns
        from ..config import ConfigError, expand

        name = start.name_answer(self._value("name"))
        platform = str(self.query_one("#platform", Select).value)
        preset = game = None
        if platform == "http":
            preset = start.preset_answer(str(self.query_one("#preset", Select).value))
            url, game, _ = start.http_url_read(preset, self._value("url"))
            if self._value("game") and preset != "gzctf":
                raise start.StartError(f"Game: only GZCTF's routes name a game, and {start.PRESET_LABELS[preset]}'s do not: "
                                       "leave it empty")
            if preset == "gzctf":
                typed = start.game_answer(self._value("game")) if self._value("game") else None
                if typed is not None and game is not None and typed != game:
                    raise start.StartError(f"Game: {typed}, and the address names game {game}: give one of them")
                game = typed or game
                if game is None:
                    raise start.StartError("Game: give the game's number, as its page's address shows it (3 for "
                                           "https://.../games/3), or that page's address as the site's")
        else:
            url = start.url_answer(self._value("url")) if platform == "ctfd" else None
        flag = start.flag_format_answer(self._value("flag"))
        submit = str(self.query_one("#submit", Select).value) if platform in start.SIGNS_IN else "confirm"
        ai = str(self.query_one("#ai", Select).value)
        if ai != "yes":
            raise start.StartError("answer the last question: flightdeck's lanes are AI agents that are given each challenge's "
                                   "text and files, and it sets up no event whose rules forbid either")
        label = start.label_answer(self._value("label"))
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
        unusable = start.folder_problem(folder)
        if unusable is not None:
            raise start.StartError(f"Folder: {unusable}")
        token, token_env, notes = "", None, ()
        if platform in start.SIGNS_IN:
            token = self.query_one("#token", Input).value.strip()
            if token and keys.value_problem(token) is not None:
                raise start.StartError(f"Token: it {keys.value_problem(token)}")
            try:  # this site's variable: never one that is another site's
                chosen = start.token_variable_for(name, url, prefix=start.token_prefix(platform, preset))
            except keys.KeysError as exc:
                raise start.StartError(f"Token: {exc}") from None
            token_env = chosen.name
            notes = tuple(f"{line}, so it is not used for this event" for line in chosen.passed)
            if notes and not token and chosen.source is None:
                raise start.StartError(f"Token: {'; '.join(notes)}. Paste this event's token: it is kept as {token_env}")
        answers = start.EventAnswers(name=name, platform=platform, url=url, flag_format=flag, submit=submit, token_env=token_env,
                                     label=label, preset=preset, game=game)
        return NewEvent(answers, folder, token, vpn_file, notes)

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
    ENABLE_COMMAND_PALETTE = False  # no Textual palette: its theme picker would repaint half the screen
    CSS = """
    Screen { background: $fd-page; align: center middle; }
    #home { width: 100; max-width: 100%; height: auto; border: round $fd-border; padding: 1 3; }
    #ask { margin-top: 1; }
    #menu { height: auto; max-height: 24; margin-top: 1; border: none; background: transparent; padding: 0; }
    #menu > .option-list--option-highlighted { background: $fd-selected; }
    #status, #keys, #formkeys, #notes { margin-top: 1; }
    NewEventForm, SetupForm, HealthScreen { align: center top; padding: 1 2; }
    #formtitle, #problem, #formkeys { width: 110; max-width: 100%; padding: 0 3; height: auto; }
    #form { width: 110; max-width: 100%; height: 1fr; border: round $fd-border; padding: 0 3 1 3; }
    #form .q { margin-top: 1; }
    #form Input { border: round $fd-border; }
    #form Input:focus { border: round $fd-accent; }
    """

    def __init__(self, menu: list[Item], status: str = "", palette: themes.Palette | None = None,
                 ready: Ready | None = None) -> None:
        """`palette`: the theme of the player's config (None: the default). `ready`: flightdeck
        was just set up, so the app opens on what was done and what next, not on the menu."""
        theme.use(palette or themes.DEFAULT)  # before Textual reads the styles' variables, which it does as it is built
        super().__init__()
        textual_theme = theme.textual()
        self.register_theme(textual_theme)
        self.theme = textual_theme.name  # set here, so $TEXTUAL_THEME does not colour half of it
        self.menu, self.status, self.ready = menu, status, ready

    def get_theme_variable_defaults(self) -> dict[str, str]:
        return theme.css_variables()

    def get_default_screen(self) -> Screen:
        if self.ready is not None:
            return Menu(ready_items(self.ready), "", ask="flightdeck is set up. What next?", notes=self.ready.notes)
        return Menu(self.menu, self.status)
