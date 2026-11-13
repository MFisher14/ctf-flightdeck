"""The flightdeck console: a fleet view of every lane and a focus view for one lane
(route C, chosen at the M0 review). One-key interventions in the fleet; a chat box and
slash commands in both.

The console only reads the Deck and sends it interventions, so the same app runs on the
M0 mock and, in M1, on real lanes. It redraws on its own timer and whenever the deck
emits an event, whether or not a mock clock is ticking.

In a real run, a hang-up (the terminal window closed) or a SIGTERM stops the run the way
quitting does: every lane stops and every workspace closes before the console exits, and
`stopped_by` names the signal (terminal.py has why a dead terminal cannot stop that).
"""

from __future__ import annotations

import asyncio
import signal
import time
from collections.abc import Awaitable, Callable

from rich.text import Text
from textual.app import App
from textual.driver import Driver
from textual.drivers.linux_driver import LinuxDriver
from textual.screen import Screen

from ..core import interventions as iv
from ..core.attention import SortMode
from ..core.deck import Deck
from ..core.driver import TakeoverRefused
from ..core.model import ME, Event, EventKind, Lane, LaneState
from ..text import untrusted
from . import theme, views
from .commands import CommandError, needs_lane, parse
from .fleet import FleetScreen
from .focus import FocusScreen
from .screens import ApprovePrompt, ChallengeCard, ForkPrompt, HelpScreen, KillPrompt, QuitPrompt, TakeOverScreen
from .terminal import STOP_SIGNALS, TerminalDriver

STATUS_EVENTS = (EventKind.RELEASE, EventKind.TEAMMATE, EventKind.SUBMIT, EventKind.WARNING)
STATUS_SECONDS = 12.0


class FlightdeckApp(App[None]):
    TITLE = "flightdeck"
    ENABLE_COMMAND_PALETTE = False
    CSS = f"""
    FleetScreen, FocusScreen {{ background: {theme.PAGE}; }}
    .panel {{
        border: round {theme.BORDER}; border-title-color: $text; border-subtitle-color: {theme.MUTED};
        padding: 0 1; margin: 0 1;
    }}
    .panel:focus-within {{ border: round {theme.ACCENT}; }}
    .-compact .panel {{ margin: 0; padding: 0; }}
    DataTable {{ background: transparent; }}
    DataTable > .datatable--header {{ background: transparent; color: {theme.MUTED}; text-style: bold; }}
    DataTable > .datatable--cursor {{ background: {theme.SELECTED}; text-style: bold; }}
    DataTable:focus > .datatable--cursor {{ background: #22324a; }}
    """

    def __init__(
        self,
        deck: Deck,
        *,
        ticker: Callable[[], None] | None = None,
        tick_seconds: float | None = None,
        mock: str = "",
        refresh_seconds: float | None = 0.5,
        on_start: Callable[[], None] | None = None,
        on_exit: Callable[[], Awaitable[None]] | None = None,
        run_dir: str = "",
    ) -> None:
        """`on_start` runs once the console's event loop is up (a real run releases the board
        there, so lanes start on this loop); `on_exit` is awaited before the console quits
        (a real run stops its lanes and closes their workspaces), also on SIGHUP or SIGTERM.
        `run_dir` is where the run's log goes (the quit prompt says it stays there)."""
        super().__init__()
        self.deck = deck
        self.mock = mock
        self._on_start = on_start
        self._on_exit = on_exit
        self._run_dir = run_dir
        self._exiting = False
        self.stopped_by: signal.Signals | None = None  # the signal that stopped the run, if one did
        self._signals: list[int] = []  # the signals this console catches while it runs
        self._ticker = ticker
        self._tick_seconds = tick_seconds
        self._refresh_seconds = refresh_seconds
        self.frozen = False
        self.status_clock: Callable[[], float] = time.monotonic  # when a status line expires
        self._fleet = FleetScreen()
        self._status: tuple[str, str, float] | None = None  # (text, severity, when)
        self._redraw_queued = False
        self._unsubscribe = deck.subscribe(self._on_deck_event)

    def get_default_screen(self) -> Screen:
        return self._fleet

    def get_driver_class(self) -> type[Driver]:
        driver = super().get_driver_class()
        return TerminalDriver if driver is LinuxDriver else driver

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
        if self._on_exit is not None:
            self._catch_signals()  # before any lane starts
        if self._on_start is not None:
            self._on_start()

    async def action_quit(self) -> None:
        """Quit (q, /quit, ctrl+q): stop the run's lanes (on_exit) before the console exits.
        While lanes are still open, or a flag is on its way to the platform, ask first:
        quitting stops them all and leaves that flag's answer unknown, and a run cannot be
        resumed. (A signal does not ask: see _on_signal.)"""
        if self._exiting or isinstance(self.screen, QuitPrompt):
            return
        deck = self.deck
        lanes_open = any(not lane.finished for lane in deck.lanes.values())
        if self._on_exit is not None and (lanes_open or views.on_their_way(deck)):
            self.push_screen(QuitPrompt(views.quit_summary(deck, self._run_dir)), self._quit_answered)
            return
        await self._quit_now()

    def _quit_answered(self, yes: bool | None) -> None:
        if yes:
            self.call_later(self._quit_now)

    async def _quit_now(self, why: str = "") -> None:
        if self._exiting:
            return
        self._exiting = True
        if self._on_exit is not None:
            self.say(f"{why}Stopping lanes and closing their workspaces...")
            await self._on_exit()
        self.exit()

    def stop_run(self, why: str = "") -> None:
        """Quit as the player would, without asking (nobody may be there to answer): the run's
        own end, such as the event's end under autopilot. `why` starts the line the console
        shows while the lanes stop ("the event ended (...): ")."""
        self.call_later(self._quit_now, why)

    def _catch_signals(self) -> None:
        """SIGHUP and SIGTERM stop the run as quitting does, instead of ending flightdeck
        with its lanes still running. A signal ignored when flightdeck started (nohup) stays
        ignored."""
        loop = asyncio.get_running_loop()
        for sig in STOP_SIGNALS:
            if signal.getsignal(sig) is signal.SIG_IGN:
                continue
            loop.add_signal_handler(sig, self._on_signal, sig)
            self._signals.append(sig)

    def _on_signal(self, sig: int) -> None:
        """Stop the run without asking: nobody may be there to answer."""
        first = self.stopped_by is None
        if first:
            self.stopped_by = signal.Signals(sig)
        if sig == signal.SIGHUP and isinstance(self._driver, TerminalDriver):
            self._driver.let_go()  # the terminal is gone: nothing reads or writes it from now on
        if first:
            self.call_later(self._quit_now, f"{signal.Signals(sig).name}: ")

    def on_unmount(self) -> None:
        self._unsubscribe()
        loop = asyncio.get_running_loop()
        for sig in self._signals:
            loop.remove_signal_handler(sig)
        self._signals.clear()

    # ------------------------------------------------------------------ drawing

    def refresh_view(self) -> None:
        for screen in self.screen_stack:
            if isinstance(screen, (FleetScreen, FocusScreen)):
                screen.refresh_view()

    def header_text(self, width: int, *, clock_keys: bool = True, compact: bool = False) -> Text:
        """The header; `clock_keys` says how to freeze the mock clock (only where space does).
        `compact`: the compact layout's header (views.header_pieces)."""
        note = ""
        if self._ticker is not None:
            if clock_keys:
                note = "⏸ frozen: space resumes, . steps" if self.frozen else "▶ live: space freezes"
            else:
                note = "⏸ frozen" if self.frozen else "▶ live"
        return views.header(self.deck, mock=self.mock, note=note, width=width, compact=compact)

    def status_text(self) -> Text:
        if self._status is None:
            return Text("")
        text, severity, when = self._status
        if self._refresh_seconds and self.status_clock() - when > STATUS_SECONDS:
            return Text("")
        color = {"warning": theme.YELLOW, "error": theme.RED}.get(severity, theme.ACCENT)
        return Text.assemble(("● ", color), (untrusted(text, one_line=True), theme.TEXT if severity == "information" else color))

    def say(self, text: str, severity: str = "information") -> None:
        """One line above the command bar: the latest outcome or event."""
        self._status = (text, severity, self.status_clock())
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
            text = event.text
            if event.kind is EventKind.WARNING and event.data.get("held") is True:  # the deck held the queue
                text = f"queue held until you /unhold it: {event.data.get('reason')}"
            self.say(text, "warning" if event.kind is EventKind.WARNING else "information")
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
            elif choice and choice.startswith("open:"):
                self.open_lane(choice.removeprefix("open:"))

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
        """The text an alert suggests for `key` (to prefill a field), as the console shows
        what the lane did (views.lane_text: a loop's hint quotes its command) and made safe
        to draw. A field sends what it shows."""
        for alert in lane.alerts:
            for suggestion in alert.suggestions:
                if suggestion.key == key and suggestion.text:
                    return untrusted(views.lane_text(self.deck, lane, suggestion.text), one_line=True)
        return ""

    def command_suggestions(self, lane_id: str | None, *, with_lane: bool) -> tuple[tuple[str, str], ...]:
        """The lane's suggested answers as full commands, for the command bar's menu; while the
        queue is held, /unhold first, whatever lane is selected."""
        out: list[tuple[str, str]] = []
        if self.deck.held:
            out.append(("/unhold", f"the queue is held: {untrusted(self.deck.held, one_line=True)}"))
        lane = self.deck.lanes.get(lane_id or "")
        if lane is None or lane.finished:
            return tuple(out)
        if lane.pending is not None:
            out.append(("/approve" + (f" {lane.id}" if with_lane else ""), untrusted(lane.pending.detail, one_line=True)))
        for alert in sorted(lane.alerts, key=lambda a: views.ALERT_URGENCY[a.kind]):
            for s in alert.suggestions:
                command = views.suggestion_command(s.key, views.lane_text(self.deck, lane, s.text), lane.id, show_lane=with_lane)
                if command:
                    command = untrusted(command, one_line=True)
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
        elif verb == "decline":
            self.apply(iv.Decline(lane.id))
        elif verb == "dismiss":
            self.apply(iv.Dismiss(lane.id))
        else:
            raise ValueError(f"unknown lane verb {verb!r}")

    def approve_all(self) -> None:
        """A, /approve all: approve every flag that waits for a plain yes (views.flag_batch),
        after a prompt that lists them and what is left out. Nothing is sent before the yes."""
        if isinstance(self.screen, ApprovePrompt):
            return
        batch = views.flag_batch(self.deck)
        if not batch.send:
            self.warn("No flag waits for a plain yes" + (f"; left: {views.left_text(batch.left)}" if batch.left else ""))
            return

        def done(yes: bool | None) -> None:
            if yes:
                self._approve_listed(batch)

        self.push_screen(ApprovePrompt(views.approve_summary(self.deck, batch)), done)

    def _approve_listed(self, batch: views.FlagBatch) -> None:
        """Approve the flags the prompt listed, each as `a` would (one intervention per lane,
        so the deck's rules for sending hold). A lane that no longer waits with the flag listed
        for it is left: the first rejection takes the same flag off every other lane, and a
        flag can be answered while the prompt is open."""
        deck = self.deck
        approved: list[str] = []
        left = list(batch.left)
        for lane_id, flag in batch.send:
            why = views.batch_refusal(deck, lane_id, flag)
            if why is None:
                outcome = deck.apply(iv.Approve(lane_id))
                why = None if outcome.ok else outcome.message
            if why is None:
                approved.append(lane_id)
            else:
                left.append((lane_id, why, why))
        count = len(approved)
        text = f"Approved {count} flag{'' if count == 1 else 's'}" + (f": {', '.join(approved)}" if approved else "")
        if left:
            text += f"; left {len(left)}: {views.left_text(left)}"
        self.say(text, "information" if approved else "warning")
        self.refresh_view()

    def answer(self, lane: Lane, number: str) -> bool:
        """Apply the lane's quick answer `number` at once. False if it has none."""
        answer = next((a for a in views.quick_answers(lane) if a.number == number), None)
        if answer is None:
            return False
        key, text = answer.key, answer.text
        if key == "h" and text:
            self.apply(iv.Hint(lane.id, text))
        elif key == "r" and text:
            self.apply(iv.Redirect(lane.id, text))
        elif key == "f" and text:
            self.apply(iv.Fork(lane.id, approach=text))
        elif key in ("h", "r"):  # nothing suggested to send: open the command for typing
            self.start_command(f"/{views.KEY_COMMAND[key]} " + (f"{lane.id} " if self.screen is self._fleet else ""))
        else:
            self.lane_verb(lane, views.KEY_COMMAND[key])  # kill and a bare fork open their prompts
        return True

    def start_command(self, text: str) -> None:
        """Open the current screen's command bar with `text` in it."""
        screen = self.screen
        if isinstance(screen, FleetScreen):
            screen.start_command(text)
        elif isinstance(screen, FocusScreen):
            screen.query_one("#chat").start(text)

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
        """The lane's shell for the player (its driver's), or the M0 placeholder.

        The driver is asked first, so a lane whose shell cannot open now (its workspace is
        still being prepared) is never left taken over."""
        lane_id = lane.id
        offer = getattr(self.deck.driver, "takeover", None)
        if offer is None:
            if not self.apply(iv.TakeOver(lane_id)).ok:
                return

            def done(_: None) -> None:
                self.apply(iv.HandBack(lane_id))

            name = self.deck.challenges[lane.challenge_id].name
            self.push_screen(TakeOverScreen(lane_id, name, self.deck.config.containerized), done)
            return
        if lane.finished:
            self.warn(f"{lane_id} has finished ({lane.state.value})")
            return
        try:
            session = offer(lane)
        except TakeoverRefused as exc:
            self.warn(str(exc))
            return
        if not self.apply(iv.TakeOver(lane_id)).ok:
            return
        self.run_worker(self._shell(lane_id, session), name=f"take over {lane_id}", exit_on_error=False)

    async def _shell(self, lane_id: str, session) -> None:
        """Open the shell, then always hand the lane back, with what happened: a lane must
        never stay taken over with no way back. A problem shows after the hand-back's own
        outcome, so it is what the status line says."""
        try:
            note, problem = await self._open_shell(lane_id, session)
        except Exception as exc:
            note = problem = f"the take-over failed: {exc}"
        lane = self.deck.lanes.get(lane_id)
        if lane is not None and lane.state is LaneState.TAKEOVER:
            self.apply(iv.HandBack(lane_id, note))
        if problem:
            self.warn(f"{lane_id}: {problem}")

    async def _open_shell(self, lane_id: str, session) -> tuple[str, str]:
        """(the hand-back note, a problem to warn about or "")."""
        from textual.app import SuspendNotSupported

        from .takeover import run_in_terminal

        if getattr(session, "busy", False):
            self.inform(f"{lane_id} is finishing a command; your shell opens when it ends")
        try:
            shell = await session.begin()
        except TakeoverRefused as exc:
            return str(exc), str(exc)
        try:
            await run_in_terminal(self, shell.argv, shell.cwd, shell.env)
        except SuspendNotSupported:
            return "no shell: this console cannot hand over the terminal", "this console cannot hand over the terminal; the lane carries on"
        except OSError as exc:
            return f"the shell did not start: {exc}", f"the shell did not start: {exc}"
        try:
            return session.finish(), ""
        except Exception as exc:
            return f"the workspace could not be checked: {exc}", f"handed back, but its workspace could not be checked: {exc}"

    def autopilot(self, arg: str) -> None:
        """/autopilot on: engage autopilot (refused, with the reason, without a run budget, off
        Docker, while the queue is held or once the budget is spent). /autopilot off: take the
        controls back. /autopilot: say which it is."""
        pilot = self.deck.autopilot
        word = arg.strip().lower()
        if pilot is None:
            self.warn("This run has no autopilot (the mock has one in its autopilot scenario; a real run always has)")
            return
        if word == "on":
            outcome = pilot.engage()
        elif word == "off":
            outcome = pilot.off()
        elif not word:
            state = {"engaged": "engaged", "disengaged": f"disengaged ({pilot.reason}); its guardrails hold until you "
                     "touch the controls", "off": "off"}[pilot.state.value]
            self.say(f"Autopilot is {state}; run budget {pilot.budget.text()}. /autopilot on engages it, /autopilot off "
                     "takes the controls back")
            return
        else:
            self.warn("/autopilot takes on or off")
            return
        self.say(outcome.message, "information" if outcome.ok else "warning")
        self.refresh_view()

    def unhold(self) -> None:
        """/unhold: lift the hold on the queue (Deck.release_hold), so queued lanes start again."""
        outcome = self.deck.release_hold()
        self.say(outcome.message, "information" if outcome.ok else "warning")
        self.refresh_view()

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
        if parsed.command.lane and needs_lane(parsed):
            lane = self._lane(parsed.lane or lane_id)
            if lane is None:
                return
        if lane is not None:
            self._lane_command(name, arg, lane)
            return
        if name == "approve":  # /approve all: no lane
            self.approve_all()
        elif name == "queue":
            cid = self._challenge_arg(arg, lane_id)
            if cid is not None:
                self.apply(iv.Queue(cid))
        elif name == "claim":
            cid = self._challenge_arg(arg, lane_id)
            if cid is not None:
                self.claim_toggle(cid)
        elif name == "note":
            outcome = self.deck.tell_all(arg)
            self.say(outcome.message, "information" if outcome.ok else "warning")
            self.refresh_view()
        elif name == "unhold":
            self.unhold()
        elif name == "autopilot":
            self.autopilot(arg)
        elif name == "filter":
            self.show_fleet()
            self._fleet.set_filter(arg)
        elif name == "sort":
            modes = {mode.value: mode for mode in SortMode}
            arg = arg.lower()
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
            self.call_later(self.action_quit)

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
        elif name == "decline":
            self.apply(iv.Decline(lane.id))
        elif name == "dismiss":
            self.apply(iv.Dismiss(lane.id))
        elif name == "escalate":
            self.apply(iv.Escalate(lane.id))
        elif name == "pause":
            self.lane_verb(lane, "pause")
        elif name == "takeover":
            self.take_over(lane)
        elif name == "diff":
            if not lane.files:
                self.warn(f"{lane.id} has not changed any files yet")
                return
            if arg and arg not in lane.files:
                self.warn(f"{lane.id} has not changed {untrusted(arg, one_line=True)}")
                return
            if views.compact(self.size.width):  # no silent nothing: the compact layout has no files pane
                self.warn(f"No files pane under {views.COMPACT_MAX_WIDTH + 1} columns (diffs need it)")
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
        """A challenge named by id or name; else the board selection (in the fleet) or the
        lane's challenge (the open lane, in the focus view)."""
        deck = self.deck
        arg = arg.strip()
        if not arg:
            fleet = self._fleet
            if self.screen is fleet and fleet.board_focused and fleet.selected_challenge:
                return fleet.selected_challenge
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
