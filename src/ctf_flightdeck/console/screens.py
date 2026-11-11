"""Modal screens: fork and kill prompts, the take-over placeholder, a challenge card and help."""

from __future__ import annotations

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from ..core.model import AlertKind, Challenge, ChallengeStatus
from ..text import untrusted
from . import theme
from .commands import COMMANDS

MODAL_CSS = """
{name} {{ align: center middle; background: $background 60%; }}
{name} > Vertical {{
    width: 100; max-width: 100%; height: auto; max-height: 90%;
    border: round $accent; background: $surface; padding: 1 2;
}}
{name} .muted {{ color: $text-muted; }}
{name} .keys {{ color: $text-muted; margin-top: 1; }}
{name} Input {{ margin-top: 1; border: round #3c4146; }}
{name} Input:focus {{ border: round $accent; }}
{name} Select {{ margin-top: 1; }}
{name} Horizontal {{ height: auto; margin-top: 1; }}
{name} Button {{ margin-right: 2; }}
"""


def _keys(*pairs: tuple[str, str]) -> Text:
    text = Text()
    for i, (key, label) in enumerate(pairs):
        if i:
            text.append("   ")
        text.append_text(theme.key_chip(key))
        text.append(f" {label}")
    return text


class ForkPrompt(ModalScreen[tuple[str, str] | None]):
    """Fork: an optional approach and a model for the sibling lane."""

    DEFAULT_CSS = MODAL_CSS.format(name="ForkPrompt") + "ForkPrompt > Vertical { width: 124; }"
    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(self, title: Text, approach: str, models: tuple[str, ...], model: str) -> None:
        super().__init__()
        self.fork_heading, self.fork_approach = title, approach
        self.fork_models, self.fork_model = models, model

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self.fork_heading)
            yield Static(Text("Approach for the new lane (optional; it becomes its plan):"), classes="muted")
            yield Input(value=self.fork_approach, placeholder="e.g. read the source before touching the instance", id="fork-approach")
            yield Static(Text("Model:"), classes="muted")
            # Text prompts: a str prompt would be parsed as markup
            options = [(Text(untrusted(m, one_line=True)), m) for m in self.fork_models]
            yield Select(options, value=self.fork_model, allow_blank=False, id="fork-model")
            yield Static(_keys(("enter", "fork"), ("tab", "next field"), ("esc", "cancel")), classes="keys")

    def on_mount(self) -> None:
        field = self.query_one(Input)
        field.cursor_blink = False  # a steady cursor keeps screenshots deterministic
        field.focus()

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss((event.value, str(self.query_one(Select).value)))

    def action_cancel(self) -> None:
        self.dismiss(None)


class KillPrompt(ModalScreen[str | None]):
    """Kill: re-queue the challenge fresh, or park it. Enter cancels: it is the safe choice."""

    DEFAULT_CSS = MODAL_CSS.format(name="KillPrompt")
    BINDINGS = [
        Binding("r", "choose('requeue')", "re-queue"),
        Binding("p", "choose('park')", "park"),
        Binding("escape", "choose('')", "cancel"),
    ]

    def __init__(self, title: Text) -> None:
        super().__init__()
        self.kill_heading = title

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self.kill_heading)
            yield Static(
                Text(
                    "Re-queue fresh: the challenge goes to the front of the queue and a new lane "
                    "starts with a clean context.\nPark: the challenge is set aside; queue it again "
                    "from its board card (enter on the board) or with /queue."
                ),
                classes="muted",
            )
            with Horizontal():
                yield Button("Cancel (esc)", id="cancel")
                yield Button("Re-queue fresh (r)", id="requeue", variant="warning")
                yield Button("Park (p)", id="park", variant="error")

    def on_mount(self) -> None:
        self.query_one("#cancel", Button).focus()

    @on(Button.Pressed)
    def _pressed(self, event: Button.Pressed) -> None:
        self.action_choose("" if event.button.id == "cancel" else str(event.button.id))

    def action_choose(self, choice: str) -> None:
        self.dismiss(choice or None)


class TakeOverScreen(ModalScreen[None]):
    """M0 placeholder for taking over a lane's shell."""

    DEFAULT_CSS = MODAL_CSS.format(name="TakeOverScreen")
    BINDINGS = [
        Binding("enter", "hand_back", "hand back"),
        Binding("escape", "hand_back", "hand back"),
    ]

    def __init__(self, lane_id: str, challenge: str, containerized: bool) -> None:
        super().__init__()
        self.lane_id, self.challenge_name, self.containerized = lane_id, challenge, containerized

    def compose(self) -> ComposeResult:
        lane = self.lane_id
        title = Text()
        title.append(f"Take over {lane}", "bold")
        title.append(" · ")
        title.append(untrusted(self.challenge_name, one_line=True), "bold")
        title.append("    ")
        title.append_text(theme.chip("placeholder: this is the M0 mock", theme.INK, theme.ACCENT))
        here = Text()
        here.append("In M1 this drops you into a shell in the lane's workspace:\n")
        docker, host = ("bold", "dim") if self.containerized else ("dim", "bold")
        here.append("  • runtime docker: ", docker)
        here.append(f"a shell inside {lane}'s container, in /work (the handout and the lane's files)\n", docker)
        here.append("  • runtime host:   ", host)
        here.append(f"a shell on this machine in the run's {lane}/work directory\n", host)
        here.append(
            "\nThe lane stays paused while you are in. When you exit the shell you hand it back: "
            "flightdeck records the commands you ran and the files you changed, and the lane "
            "resumes with a note about them on its next turn.\n\n"
        )
        here.append("Right now ", "dim")
        here.append(lane, "bold")
        here.append(" is in state ", "dim")
        here.append("takeover", f"bold {theme.CYAN}")
        here.append(" and does not run.", "dim")
        with Vertical():
            yield Static(title)
            yield Static(here)
            with Horizontal():
                yield Button("Hand back (enter)", id="hand-back", variant="primary")

    @on(Button.Pressed)
    def _pressed(self, event: Button.Pressed) -> None:
        self.action_hand_back()

    def action_hand_back(self) -> None:
        self.dismiss(None)


class ChallengeCard(ModalScreen[str | None]):
    """A challenge from the board: what it is, who has it, and what you can do with it.

    Dismissed with "queue", "claim", "open:<lane id>" or None."""

    DEFAULT_CSS = MODAL_CSS.format(name="ChallengeCard")
    BINDINGS = [
        Binding("q", "choose('queue')", "queue"),
        Binding("c", "choose('claim')", "claim"),
        Binding("escape", "choose('')", "close"),
        *(Binding(str(n), f"open_lane({n})", show=False) for n in range(1, 10)),
    ]

    def __init__(self, challenge: Challenge, lanes: list[str], owner: str, team: bool) -> None:
        super().__init__()
        self.card_challenge, self.card_lanes, self.card_owner, self.card_team = challenge, lanes, owner, team

    def compose(self) -> ComposeResult:
        from .views import BOARD_MARK

        ch = self.card_challenge
        mark, color = BOARD_MARK[ch.status]
        title = Text()
        title.append(untrusted(ch.name, one_line=True), "bold")
        title.append(f"   {untrusted(ch.category, one_line=True)} · {ch.points} pts · {ch.solves} solves · ", "dim")
        title.append(f"{mark} {ch.status.value}", color)
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold dim", no_wrap=True)
        grid.add_column()
        grid.add_row("about", Text(untrusted(ch.description or "-", one_line=True)))
        grid.add_row("files", Text(untrusted(", ".join(ch.files) or "-", one_line=True) + (" · live instance" if ch.live else ""), "dim"))
        if self.card_owner:
            grid.add_row("owner", Text(untrusted(self.card_owner, one_line=True)))
        if ch.note:
            grid.add_row("note", Text(untrusted(ch.note, one_line=True), theme.YELLOW))
        lanes = Text("none", "dim") if not self.card_lanes else Text()
        for n, lane_id in enumerate(self.card_lanes[:9], start=1):
            lanes.append("   " if n > 1 else "")
            lanes.append_text(theme.key_chip(str(n)))
            lanes.append(f" {lane_id}")
        if len(self.card_lanes) > 9:
            lanes.append(f"   +{len(self.card_lanes) - 9} more in the lane list", "dim")
        grid.add_row("lanes", lanes)
        keys: list[tuple[str, str]] = []
        if self.card_lanes:
            last = min(len(self.card_lanes), 9)
            keys.append(("1" if last == 1 else f"1-{last}", "open that lane"))
        if ch.status in (ChallengeStatus.PARKED, ChallengeStatus.NEW) and not self.card_lanes:
            keys.append(("q", "queue a fresh lane"))
        if self.card_team and not ch.closed:
            keys.append(("c", "claim or release"))
        keys.append(("esc", "close"))
        with Vertical():
            yield Static(Group(title, Text(""), grid))
            yield Static(_keys(*keys), classes="keys")

    def action_choose(self, choice: str) -> None:
        self.dismiss(choice or None)

    def action_open_lane(self, number: int) -> None:
        if 1 <= number <= min(len(self.card_lanes), 9):
            self.dismiss(f"open:{self.card_lanes[number - 1]}")


KEY_HELP = (
    ("enter / o", "Open the selected lane full screen (its transcript, files and a chat box)"),
    ("p", "Pause or resume the selected lane"),
    ("h", "Hint: a message the lane reads on its next turn (opens /hint in the bar)"),
    ("r", "Redirect: replace the lane's plan (opens /redirect, with the suggestion)"),
    ("f", "Fork: a sibling lane on the same challenge, another approach or model"),
    ("k", "Kill the lane: re-queue the challenge fresh, or park it"),
    ("e", "Escalate: hand a compact summary to the next stronger model"),
    ("t", "Take over: a shell in the lane's workspace (placeholder in M0)"),
    ("a", "Approve what the lane waits for: submit, more budget, live-box access"),
    ("d", "Decline it: do not submit, stay off the box, no more budget (the lane stops)"),
    ("1-9, 0", "Quick answers, no enter: the numbers in the why line and the needs-you card (0 says no)"),
    ("c", "Team mode: claim or release the selected challenge"),
    ("/", "Command bar: slash commands with completion; plain text messages the lane"),
    ("s", "Change the lane sort: attention, idle, cost, turns, lane"),
    ("tab", "Move focus: board, lanes, command bar (the board hides under 100 columns)"),
    ("enter on ▸", "Expand or collapse finished lanes"),
    ("enter on board", "Open the challenge's lane; with none or several, its card: queue, claim, 1-9 open a lane"),
    ("esc", "Leave the command bar, clear the filter, or go back to the fleet"),
    ("ctrl+n", "In a lane: the next lane that needs you, in attention order, round to the first"),
    ("q", "Quit"),
)
MOCK_KEYS = (
    ("space", "Freeze or restart the mock clock"),
    (".", "Step the mock clock one tick"),
)
ALERT_HELP = (
    (AlertKind.EFFORT, "Turns or tokens are high for a low-point challenge with many solves"),
    (AlertKind.HINT, "The description hints at something the lane is not doing"),
    (AlertKind.DIRECTION, "A web lane fuzzes or brute-forces when the source is given"),
    (AlertKind.LOOP, "The same command or near-same action repeats"),
    (AlertKind.STALL, "No new artifact or hypothesis for many turns"),
    (AlertKind.TEAMMATE, "A teammate solved the challenge or holds its live box"),
    (AlertKind.BUDGET, "The lane is near or at its token or dollar cap"),
    (AlertKind.FLAG, "A candidate flag matches the flag format"),
)
BOARD_HELP = (
    ("·", "new"), ("…", "queued"), ("▶", "running"), ("✓", "solved (green: us, cyan: teammate)"),
    ("✗", "blocked"), ("‖", "parked"), ("*", "after a lane id: claimed by you"),
)


class HelpScreen(ModalScreen[None]):
    DEFAULT_CSS = MODAL_CSS.format(name="HelpScreen") + """
    HelpScreen > Vertical { width: 112; }
    HelpScreen #help-body { height: auto; max-height: 1fr; }
    """
    BINDINGS = [
        Binding("escape", "close", "close"),
        Binding("question_mark", "close", "close"),
        Binding("q", "close", "close"),
    ]

    def __init__(self, mock: bool) -> None:
        super().__init__()
        self.show_mock_keys = mock

    def compose(self) -> ComposeResult:
        keys = Table.grid(padding=(0, 2))
        keys.add_column(style="bold", no_wrap=True)
        keys.add_column()
        for key, text in KEY_HELP + (MOCK_KEYS if self.show_mock_keys else ()):
            keys.add_row(Text(key), Text(text))
        commands = Table.grid(padding=(0, 2))
        commands.add_column(style=f"bold {theme.ACCENT}", no_wrap=True)
        commands.add_column()
        for command in COMMANDS:
            commands.add_row(Text(f"/{command.name} {command.args}".rstrip()), Text(command.help))
        alerts = Table.grid(padding=(0, 2))
        alerts.add_column(no_wrap=True)
        alerts.add_column()
        for kind, text in ALERT_HELP:
            alerts.add_row(theme.chip(kind.tag, *theme.alert_colors(kind)), Text(f"{kind.label}: {text}"))
        alerts.add_row(theme.chip("submit", *theme.PENDING_COLORS), Text("Waiting for your approval (press a, or /approve)"))
        board = Text()
        for mark, meaning in BOARD_HELP:
            board.append(f"{mark} ", "bold")
            board.append(f"{meaning}   ")
        body = Group(
            Text("Keys (fleet)", "bold underline"), keys, Text(""),
            Text("Commands (the bar at the bottom; plain text is a message to the lane)", "bold underline"), commands, Text(""),
            Text("Alerts (lanes that need you come first, most urgent first)", "bold underline"), alerts, Text(""),
            Text("Board", "bold underline"), board,
        )
        with Vertical():
            with VerticalScroll(id="help-body"):
                yield Static(body)
            yield Static(_keys(("esc", "close"), ("↑↓", "scroll")), classes="keys")

    def action_close(self) -> None:
        self.dismiss(None)
