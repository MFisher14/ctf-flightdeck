"""Modal screens: prompts for interventions, the take-over placeholder and help."""

from __future__ import annotations

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from ..core.model import AlertKind

MODAL_CSS = """
{name} {{ align: center middle; background: $background 60%; }}
{name} > Vertical {{
    width: 96; max-width: 100%; height: auto; max-height: 90%;
    border: thick $accent; background: $surface; padding: 1 2;
}}
{name} .muted {{ color: $text-muted; }}
{name} .keys {{ color: $text-muted; margin-top: 1; }}
{name} Input, {name} Select {{ margin-top: 1; }}
{name} Horizontal {{ height: auto; margin-top: 1; }}
{name} Button {{ margin-right: 2; }}
"""


def _keys(*pairs: tuple[str, str]) -> Text:
    text = Text()
    for i, (key, label) in enumerate(pairs):
        if i:
            text.append("   ")
        text.append(f" {key} ", "bold reverse")
        text.append(f" {label}")
    return text


class TextPrompt(ModalScreen[str | None]):
    """Free text for a hint or a redirect. A suggested text arrives prefilled and selected."""

    DEFAULT_CSS = MODAL_CSS.format(name="TextPrompt") + "TextPrompt > Vertical { width: 124; }"
    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(self, title: Text, context: Text | None, value: str = "", placeholder: str = "") -> None:
        super().__init__()
        self.prompt_heading, self.prompt_context = title, context
        self.prompt_value, self.prompt_placeholder = value, placeholder

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(self.prompt_heading)
            if self.prompt_context is not None:
                yield Static(self.prompt_context, classes="muted")
            yield Input(value=self.prompt_value, placeholder=self.prompt_placeholder, id="prompt-input")
            yield Static(_keys(("enter", "send"), ("esc", "cancel")), classes="keys")

    def on_mount(self) -> None:
        field = self.query_one(Input)
        field.cursor_blink = False  # steady cursor: screenshots stay deterministic
        field.focus()

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


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
            yield Static(Text("Approach for the new lane (optional; becomes its plan):"), classes="muted")
            yield Input(value=self.fork_approach, placeholder="e.g. read the source before touching the instance", id="fork-approach")
            yield Static(Text("Model:"), classes="muted")
            yield Select([(m, m) for m in self.fork_models], value=self.fork_model, allow_blank=False, id="fork-model")
            yield Static(_keys(("enter", "fork"), ("tab", "next field"), ("esc", "cancel")), classes="keys")

    def on_mount(self) -> None:
        field = self.query_one(Input)
        field.cursor_blink = False
        field.focus()

    @on(Input.Submitted)
    def _submit(self, event: Input.Submitted) -> None:
        self.dismiss((event.value, str(self.query_one(Select).value)))

    def action_cancel(self) -> None:
        self.dismiss(None)


class KillPrompt(ModalScreen[str | None]):
    """Kill: re-queue the challenge fresh, or park it."""

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
                    "starts with a clean context.\nPark: the challenge is set aside until you start it again."
                ),
                classes="muted",
            )
            with Horizontal():
                yield Button("Re-queue fresh (r)", id="requeue", variant="warning")
                yield Button("Park (p)", id="park", variant="error")
                yield Button("Cancel (esc)", id="cancel")

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
        title.append(self.challenge_name, "bold")
        title.append("    placeholder: this is the M0 mock", "bold black on yellow")
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
        here.append("takeover", "bold cyan")
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


KEY_HELP = (
    ("p", "Pause or resume the selected lane"),
    ("h", "Hint: free text injected into the lane's next turn"),
    ("r", "Redirect: replace the lane's plan with a new direction"),
    ("f", "Fork: a sibling lane on the same challenge, another approach or model"),
    ("k", "Kill the lane: re-queue the challenge fresh, or park it"),
    ("e", "Escalate: hand a compact summary to the next stronger model"),
    ("t", "Take over: a shell in the lane's workspace (placeholder in M0)"),
    ("a", "Approve what the lane waits for: submit, more budget, live-box access"),
    ("c", "Team mode: claim or release the selected challenge"),
    ("/", "Filter lanes (words match name, category, model, state, alert)"),
    ("s", "Change the lane sort: attention, idle, cost, turns, lane"),
    ("tab", "Move focus: board, lanes, detail"),
    ("enter", "On the 'finished' row: expand or collapse finished lanes"),
    ("q", "Quit"),
)
MOCK_KEYS = (
    ("space", "Freeze or restart the mock clock"),
    (".", "Step the mock clock one tick (while frozen)"),
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
    DEFAULT_CSS = MODAL_CSS.format(name="HelpScreen") + "HelpScreen > Vertical { width: 110; }"
    BINDINGS = [
        Binding("escape", "close", "close"),
        Binding("question_mark", "close", "close"),
        Binding("q", "close", "close"),
    ]

    def __init__(self, mock: bool) -> None:
        super().__init__()
        self.show_mock_keys = mock

    def compose(self) -> ComposeResult:
        from .views import alert_style

        keys = Table.grid(padding=(0, 2))
        keys.add_column(style="bold", no_wrap=True)
        keys.add_column()
        for key, text in KEY_HELP + (MOCK_KEYS if self.show_mock_keys else ()):
            keys.add_row(Text(key), Text(text))
        alerts = Table.grid(padding=(0, 2))
        alerts.add_column(no_wrap=True)
        alerts.add_column()
        for kind, text in ALERT_HELP:
            alerts.add_row(Text(f"▲ {kind.tag}", alert_style(kind)), Text(f"{kind.label}: {text}"))
        alerts.add_row(Text("◆ ...", "bold magenta"), Text("Waiting for your approval (press a)"))
        board = Text()
        for mark, meaning in BOARD_HELP:
            board.append(f"{mark} ", "bold")
            board.append(f"{meaning}   ")
        body = Group(
            Text("Keys", "bold underline"), keys, Text(""),
            Text("Alerts (lanes are sorted with alerts first, then approvals, then running by idle time)", "bold underline"),
            alerts, Text(""),
            Text("Board", "bold underline"), board,
        )
        with Vertical():
            yield Static(body)
            yield Static(_keys(("esc", "close")), classes="keys")

    def action_close(self) -> None:
        self.dismiss(None)
