"""Waiting for a console under test to show what it was asked to (conftest.py makes every
`await pilot.pause()` do this).

Textual's Pilot.pause() waits for the messages queued when it is called, then for the process
to look idle: it compares the CPU time the process used with 20 ms of the clock. On a loaded
machine a process the scheduler leaves out uses little CPU time too, so pause() can return
before a resize's second round of layout, before callbacks run after the next refresh, or
half-way through an animated scroll (a scroll to the end takes a second). A test that reads
the screen then reads one a player sees only for a moment, and fails only when the machine
is busy. settle() waits for the condition itself: nothing left to do on the screen.
"""

from __future__ import annotations

import asyncio

SETTLE_TIMEOUT = 30.0  # seconds: a screen still busy after this never settles, and the test fails saying why


def unsettled(app) -> str:
    """What `app` has still to do before its screen shows the state it is in, or "" when
    nothing: a message or callback queued for the app or a widget of its screen, a layout,
    scroll or repaint the screen has not done yet, callbacks it runs after its next refresh,
    or an animation still running."""
    screen = app.screen
    for node in (app, *screen.walk_children(with_self=True)):
        if not node._message_queue.empty() or node._next_callbacks:
            return f"messages queued for {node!r}"
    for flag in ("_layout_required", "_scroll_required", "_repaint_required", "_recompose_required"):
        if getattr(screen, flag):
            return f"the screen's {flag.strip('_').replace('_', ' ')}"
    if screen._dirty_widgets or screen._callbacks:
        return "the screen's refresh"
    if not app.animator._complete_event.is_set():
        return "an animation"
    return ""


def ended(app) -> bool:
    """The app is quitting or has quit: its screen is left as it was, and nothing more is done."""
    return app._exit or app._closing or app._closed or not app.is_running


async def settle(pilot, pause) -> None:
    """Pilot.pause() (`pause`, the real one), then, for as long as unsettled() names
    something, let the app run and redraw the screen, and look again. An app that has quit is
    not waited for. A screen still busy after SETTLE_TIMEOUT fails the test, naming what it
    was still doing."""
    await pause(pilot)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + SETTLE_TIMEOUT
    while not ended(pilot.app) and (busy := unsettled(pilot.app)):
        if loop.time() > deadline:
            raise AssertionError(f"the screen did not settle in {SETTLE_TIMEOUT:.0f} s: {busy}")
        await asyncio.sleep(0.01)
        await pilot._wait_for_screen()
        if not ended(pilot.app):
            pilot.app.screen._on_timer_update()  # the redraw pause() ends with: what waits for the next refresh runs
        await asyncio.sleep(0)
