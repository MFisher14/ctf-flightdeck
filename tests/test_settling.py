"""settling.py: what every `await pilot.pause()` of the console tests waits for (conftest.py).

The load that made pause() return early cannot be made on purpose, so these tests give
settle() a pause that returns at once, which is what Pilot.pause() does on a machine busy
enough: what settle() then waits for is its own doing. The app is a plain Textual one, a
scroll and nothing else of flightdeck's.
"""

from __future__ import annotations

import asyncio

import pytest
from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.pilot import Pilot
from textual.widgets import Static

import settling
from settling import settle, unsettled


class Tall(App):
    def compose(self) -> ComposeResult:
        with VerticalScroll(id="body"):
            for n in range(100):
                yield Static(f"row {n}")


async def returns_at_once(pilot) -> None:
    """Pilot.pause() on a machine too busy for it: it waits for nothing."""


def drive(script) -> None:
    async def main() -> None:
        app = Tall()
        async with app.run_test(size=(40, 10)) as pilot:
            await Pilot.pause(pilot, 0.05)  # the delay form: Textual's own, laid out once
            await script(app, pilot)

    asyncio.run(main())


def test_settle_waits_out_an_animated_scroll():
    async def script(app, pilot):
        body = app.query_one("#body", VerticalScroll)
        assert body.max_scroll_y > 0
        body.scroll_end(animate=True, duration=0.5)
        assert unsettled(app)  # the scroll has only begun
        await settle(pilot, returns_at_once)
        assert body.scroll_y == body.max_scroll_y and unsettled(app) == ""

    drive(script)


def test_settle_waits_for_the_layout_a_change_asks_for():
    async def script(app, pilot):
        app.query_one("#body").mount(Static("one more row", id="more"))
        assert unsettled(app)
        await settle(pilot, returns_at_once)
        assert app.query_one("#more").region.height == 1 and unsettled(app) == ""

    drive(script)


def test_a_screen_that_never_settles_fails_the_test_naming_what_it_was_doing(monkeypatch):
    monkeypatch.setattr(settling, "SETTLE_TIMEOUT", 0.3)

    async def script(app, pilot):
        app.query_one("#body", VerticalScroll).scroll_end(animate=True, duration=60.0)
        with pytest.raises(AssertionError, match=r"did not settle in 0 s: an animation"):
            await settle(pilot, returns_at_once)

    drive(script)


def test_an_app_that_has_quit_is_not_waited_for(monkeypatch):
    monkeypatch.setattr(settling, "SETTLE_TIMEOUT", 0.3)

    async def script(app, pilot):
        app.query_one("#body", VerticalScroll).scroll_end(animate=True, duration=60.0)
        app.exit()
        await settle(pilot, returns_at_once)  # no AssertionError: nothing is waited for

    drive(script)


def test_every_pause_without_a_delay_is_a_settle(monkeypatch):
    async def idle_at_once(*args, **kwargs) -> None:
        """Textual's test of idleness, on a machine too busy for it: idle at once."""

    monkeypatch.setattr("textual.pilot.wait_for_idle", idle_at_once)

    async def script(app, pilot):
        body = app.query_one("#body", VerticalScroll)
        body.scroll_end(animate=True, duration=0.5)
        await pilot.pause()
        assert body.scroll_y == body.max_scroll_y

    drive(script)
