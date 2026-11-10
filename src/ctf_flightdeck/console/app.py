"""The flightdeck console: a fleet view of every lane and a focus view for one lane
(route C, chosen at the M0 review). One-key interventions in the fleet; a chat box and
slash commands in both.

The console only reads the Deck and sends it interventions, so the same app runs on the
M0 mock and, in M1, on real lanes. It redraws on its own timer and whenever the deck
emits an event, whether or not a mock clock is ticking.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from rich.text import Text
from textual.app import App
from textual.screen import Screen

from ..core import interventions as iv
from ..core.attention import SortMode
from ..core.deck import Deck
from ..core.model import ME, Event, EventKind, Lane, LaneState
from ..text import untrusted
from . import theme, views
from .commands import CommandError, parse
from .fleet import FleetScreen
from .focus import FocusScreen
from .screens import ChallengeCard, ForkPrompt, HelpScreen, KillPrompt, TakeOverScreen

STATUS_EVENTS = (EventKind.RELEASE, EventKind.TEAMMATE, EventKind.SUBMIT, EventKind.WARNING)
STATUS_SECONDS = 12.0


class FlightdeckApp(App[None]):
    TITLE = "flightdeck"
    ENABLE_COMMAND_PALETTE = False
    CSS = f"""
    Screen {{ background: {theme.PAGE}; }}
    .panel {{
        border: round {theme.BORDER}; border-title-color: $text; border-subtitle-color: {theme.MUTED};
        padding: 0 1; margin: 0 1;
    }}
    .panel:focus-within {{ border: round {theme.ACCENT}; }}
    DataTable {{ background: transparent; }}
    DataTable > .datatable--header {{ background: transparent; color: {theme.MUTED}; text-style: bold; }}
    DataTable > .datatable--cursor {{ background: {theme.SELECTED}; text-style: bold; }}
    DataTable:focus > .datatable--cursor {{ background: #22324a; }}
    Footer {{ background: transparent; }}
    """

    def __init__(
        self,
        deck: Deck,
        *,
        ticker: Callable[[], None] | None = None,
        tick_seconds: float | None = None,
        mock: str = "",
        refresh_seconds: float | None = 0.5,
    ) -> None:
        super().__init__()
        self.deck = deck
        self.mock = mock
        self._ticker = ticker
        self._tick_seconds = tick_seconds
        self._refresh_seconds = refresh_seconds
        self.frozen = False
        self._fleet = FleetScreen()
        self._status: tuple[str, str, float] | None = None  # (text, severity, when)
        self._redraw_queued = False
        self._unsubscribe = deck.subscribe(self._on_deck_event)

    def get_default_screen(self) -> Screen:
        return self._fleet

    @property
    def fleet(self) -> FleetScreen:
        return self._fleet

    @property
    def focus_screen(self) -> FocusScreen | None:
        return next((s for s in reversed(self.screen_stack) if isinstance(s, FocusScreen)), None)

    def on_mount(self) -> None:
        if self._ticker is not None and self._tick_seconds:
            self.set_interval(self._tick_seconds, self._on_tick)
        if self._refresh_seconds:
            self.set_interval(self._refresh_seconds, self.refresh_view)

    def on_unmount(self) -> None:
        self._unsubscribe()

    # ------------------------------------------------------------------ drawing

    def refresh_view(self) -> None:
        for screen in self.screen_stack:
            if isinstance(screen, (FleetScreen, FocusScreen)):
                screen.refresh_view()

    def header_text(self, width: int) -> Text:
        note = ""
        if self._ticker is not None:
            note = "⏸ frozen: space resumes, . steps" if self.frozen else "▶ live: space freezes"
        return views.header(self.deck, mock=self.mock, note=note, width=width)

    def status_text(self) -> Text:
        if self._status is None:
            return Text("")
        text, severity, when = self._status
        if self._refresh_seconds and time.monotonic() - when > STATUS_SECONDS:
            return Text("")
        color = {"warning": theme.YELLOW, "error": theme.RED}.get(severity, theme.ACCENT)
        return Text.assemble(("● ", color), (untrusted(text, one_line=True), theme.TEXT if severity == "information" else color))

    def say(self, text: str, severity: str = "information") -> None:
        """One line above the command bar: the latest outcome or event."""
        self._status = (text, severity, time.monotonic())
        if not self.is_running:
            return
        for screen in self.screen_stack:
            if isinstance(screen, (FleetScreen, FocusScreen)) and screen._ready:
                screen.query_one("#status").update(self.status_text())

    def warn(self, text: str) -> None:
        self.say(text, "warning")

    def inform(self, text: str) -> None:
        self.say(text)

    # ------------------------------------------------------------------ mock clock

    def _on_tick(self) -> None:
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
        if action in ("toggle_clock", "step_clock"):
            return self._ticker is not None
        return True

    def action_toggle_clock(self) -> None:
        self.frozen = not self.frozen
        self.refresh_view()

    def action_step_clock(self) -> None:
        self.step()

    def _on_deck_event(self, event: Event) -> None:
        if event.kind in STATUS_EVENTS:
            self.say(event.text, "warning" if event.kind is EventKind.WARNING else "information")
        if self.is_running and not self._redraw_queued:  # one redraw for a burst of events
            self._redraw_queued = True
            self.call_later(self._redraw)

    def _redraw(self) -> None:
        self._redraw_queued = False
        self.refresh_view()

    # ------------------------------------------------------------------ navigation

    def open_lane(self, lane_id: str, file: str | None = None) -> None:
        if lane_id not in self.deck.lanes:
            self.warn(f"No lane {lane_id}")
            return
        focus = self.focus_screen
        if focus is not None:
            focus.show_lane(lane_id, file)
        else:
            self.push_screen(FocusScreen(lane_id, file))

    def action_open_lane(self, lane_id: str) -> None:
        self.open_lane(lane_id)

    def show_fleet(self, select: str | None = None) -> None:
        while len(self.screen_stack) > 1:
            self.pop_screen()
        if select is not None and select in self.deck.lanes:
            self._fleet.select_lane(select)
        self._fleet.refresh_view()

    def open_challenge(self, challenge_id: str) -> None:
        deck = self.deck
        ch = deck.challenges[challenge_id]
        lanes = deck.lanes_on(ch.id)
        if len(lanes) == 1:
            self.open_lane(lanes[0].id)
            return
        own, _ = views.owner(deck, ch)

        def done(choice: str | None) -> None:
            if choice == "queue":
                self.apply(iv.Queue(challenge_id))
            elif choice == "claim":
                self.claim_toggle(challenge_id)

        self.push_screen(ChallengeCard(ch, [lane.id for lane in lanes], own, deck.config.team), done)

    def action_help(self) -> None:
        self.push_screen(HelpScreen(mock=self._ticker is not None))

    # ------------------------------------------------------------------ interventions

    def apply(self, intervention: iv.Intervention) -> iv.Outcome:
        outcome = self.deck.apply(intervention)
        self.say(outcome.message, "information" if outcome.ok else "warning")
        self.refresh_view()
        return outcome

    def suggested(self, lane: Lane, key: str) -> str:
        for alert in lane.alerts:
            for suggestion in alert.suggestions:
                if suggestion.key == key and suggestion.text:
                    return suggestion.text
        return ""

    def command_suggestions(self, lane_id: str | None, *, with_lane: bool) -> tuple[tuple[str, str], ...]:
        """The lane's suggested answers as full commands, for the command bar's menu."""
        lane = self.deck.lanes.get(lane_id or "")
        if lane is None or lane.finished:
            return ()
        out: list[tuple[str, str]] = []
        if lane.pending is not None:
            out.append(("/approve" + (f" {lane.id}" if with_lane else ""), lane.pending.detail))
        for alert in sorted(lane.alerts, key=lambda a: views.ALERT_URGENCY[a.kind]):
            for s in alert.suggestions:
                command = views.suggestion_command(s.key, s.text, lane.id if with_lane else None)
                if command and all(command != c for c, _ in out):
                    out.append((command, alert.kind.label.lower()))
        return tuple(out)

    def lane_verb(self, lane: Lane, verb: str) -> None:
        if verb == "pause":
            self.apply(iv.Resume(lane.id) if lane.state is LaneState.PAUSED else iv.Pause(lane.id))
        elif verb == "fork":
            self.ask_fork(lane)
        elif verb == "kill":
            self.ask_kill(lane)
        elif verb == "escalate":
            self.apply(iv.Escalate(lane.id))
        elif verb == "takeover":
            self.take_over(lane)
        elif verb == "approve":
            self.apply(iv.Approve(lane.id))
        else:
            raise ValueError(f"unknown lane verb {verb!r}")

    def _title(self, verb: str, lane: Lane) -> Text:
        name = untrusted(self.deck.challenges[lane.challenge_id].name, one_line=True)
        return Text.assemble((f"{verb} ", "bold"), (lane.id, "bold"), " · ", (name, "bold"))

    def ask_fork(self, lane: Lane) -> None:
        if lane.finished:
            self.warn(f"{lane.id} has finished ({lane.state.value})")
            return
        models = self.deck.config.models or (lane.model,)
        prompt = ForkPrompt(self._title("Fork", lane), self.suggested(lane, "f"), models, self.deck.fork_model(lane.model))
        lane_id = lane.id

        def done(result: tuple[str, str] | None) -> None:
            if result is not None:
                approach, model = result
                self.apply(iv.Fork(lane_id, approach=approach, model=model))

        self.push_screen(prompt, done)

    def ask_kill(self, lane: Lane) -> None:
        if lane.finished:
            self.warn(f"{lane.id} has finished ({lane.state.value})")
            return
        lane_id = lane.id

        def done(choice: str | None) -> None:
            if choice is not None:
                self.apply(iv.Kill(lane_id, requeue=choice == "requeue"))

        self.push_screen(KillPrompt(self._title("Kill", lane)), done)

    def take_over(self, lane: Lane) -> None:
        if not self.apply(iv.TakeOver(lane.id)).ok:
            return
        lane_id = lane.id

        def done(_: None) -> None:
            self.apply(iv.HandBack(lane_id))

        name = self.deck.challenges[lane.challenge_id].name
        self.push_screen(TakeOverScreen(lane.id, name, self.deck.config.containerized), done)

    def claim_toggle(self, challenge_id: str) -> None:
        ch = self.deck.challenges[challenge_id]
        self.apply(iv.Release(challenge_id) if ch.claimed_by == ME else iv.Claim(challenge_id))

    # ------------------------------------------------------------------ commands

    def run_command(self, text: str, lane_id: str | None) -> None:
        """Plain text messages the lane; a slash runs a command (on `lane_id` unless named)."""
        try:
            parsed = parse(text)
        except CommandError as exc:
            self.warn(str(exc))
            return
        if parsed.command is None:
            target = self._lane(lane_id)
            if target is not None:
                self.apply(iv.Hint(target.id, parsed.arg))
            return
        name, arg = parsed.command.name, parsed.arg
        lane: Lane | None = None
        if parsed.command.lane:
            lane = self._lane(parsed.lane or lane_id)
            if lane is None:
                return
        if lane is not None:
            self._lane_command(name, arg, lane)
            return
        if name == "queue":
            cid = self._challenge_arg(arg, lane_id)
            if cid is not None:
                self.apply(iv.Queue(cid))
        elif name == "claim":
            cid = self._challenge_arg(arg, lane_id)
            if cid is not None:
                self.claim_toggle(cid)
        elif name == "filter":
            self.show_fleet()
            self._fleet.set_filter(arg)
        elif name == "sort":
            modes = {mode.value: mode for mode in SortMode}
            if arg and arg not in modes:
                self.warn(f"/sort takes one of: {', '.join(modes)}")
                return
            self.show_fleet()
            self._fleet.set_sort(modes[arg] if arg else self._fleet.sort.next())
        elif name == "back":
            self.show_fleet(select=lane_id if self.focus_screen else None)
        elif name == "help":
            self.action_help()
        elif name == "quit":
            self.exit()

    def _lane_command(self, name: str, arg: str, lane: Lane) -> None:
        if name == "hint":
            self.apply(iv.Hint(lane.id, arg))
        elif name == "redirect":
            self.apply(iv.Redirect(lane.id, arg))
        elif name == "fork":
            if arg:
                self.apply(iv.Fork(lane.id, approach=arg))
            else:
                self.ask_fork(lane)
        elif name == "kill":
            if arg.lower() not in ("", "park"):
                self.warn("/kill takes nothing (re-queue fresh) or 'park'")
                return
            self.apply(iv.Kill(lane.id, requeue=arg.lower() != "park"))
        elif name == "approve":
            self.apply(iv.Approve(lane.id))
        elif name == "escalate":
            self.apply(iv.Escalate(lane.id))
        elif name == "pause":
            self.lane_verb(lane, "pause")
        elif name == "takeover":
            self.take_over(lane)
        elif name == "diff":
            if arg and arg not in lane.files:
                self.warn(f"{lane.id} has not changed {arg}")
                return
            self.open_lane(lane.id, file=arg)
        elif name == "open":
            self.open_lane(lane.id)
        else:
            raise ValueError(f"/{name} is not a lane command")

    def _lane(self, lane_id: str | None) -> Lane | None:
        lane = self.deck.lanes.get(lane_id or "")
        if lane is None:
            self.warn(f"No lane {lane_id}" if lane_id else "Select a lane first")
        return lane

    def _challenge_arg(self, arg: str, lane_id: str | None) -> str | None:
        """A challenge named by id or name; else the board selection or the lane's challenge."""
        deck = self.deck
        arg = arg.strip()
        if not arg:
            if self._fleet.board_focused and self._fleet.selected_challenge:
                return self._fleet.selected_challenge
            lane = deck.lanes.get(lane_id or "")
            if lane is not None:
                return lane.challenge_id
            self.warn("Name a challenge, e.g. /queue pocket-litter")
            return None
        if arg in deck.challenges:
            return arg
        by_name = [ch.id for ch in deck.challenges.values() if ch.name.lower() == arg.lower()]
        if by_name:
            return by_name[0]
        self.warn(f"No challenge {arg}")
        return None
