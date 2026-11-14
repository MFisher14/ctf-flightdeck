"""The 60-second demo at the top of the README, built from this script.

    uv run python scripts/demo.py --check                       # play it; write nothing
    uv run python scripts/demo.py docs/screenshots/demo.gif     # play it and write the GIF
    uv run python scripts/demo.py --frames DIR                  # the frames alone, as SVGs

It opens `flightdeck mock` (the default scenario, the simple layout, the default theme: what
`uvx ctf-flightdeck mock` shows somebody new) at 120 by 36 with no terminal, presses the keys
in DEMO as a player would, and moves the mock's clock itself, so the same frames come out
every time. Nothing here calls a model or the network.

Every step says what must be true once it is done (`then`): the flag is submitted, the lane has
its new plan, the wave is on the board. A step whose `then` does not hold stops the demo with
that step's name: the console or the mock changed, and the demo would no longer show what its
caption says. `--check` is that and nothing else, and tests/test_demo.py runs it on every push.

The GIF needs two tools this script does not bring: `rsvg-convert` draws each frame and
`ffmpeg` joins them. A missing one is named and no GIF is written. The first and the last
frames are drawn, not played: a shell prompt with the command that was typed at it.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import shutil
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.style import Style
from rich.text import Text

from ctf_flightdeck import themes
from ctf_flightdeck.console.app import FlightdeckApp
from ctf_flightdeck.console.fleet import FleetScreen
from ctf_flightdeck.console.focus import FocusScreen
from ctf_flightdeck.console.screens import HelpScreen, KillPrompt, WelcomeScreen
from ctf_flightdeck.core.deck import Deck
from ctf_flightdeck.core.model import AlertKind, ChallengeStatus, Lane, LaneState, PendingKind
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.world import FakeWorld

SIZE = (120, 36)  # columns, rows: wide enough for the console, narrow enough to read in a README
SCENARIO = "default"
WIDTH = 960  # the GIF's width in pixels (its height follows the frames' shape)
COLOURS = 48  # the GIF's palette: the console draws in under twenty colours, the rest smooths the letters
TOOLS = {
    "rsvg-convert": "it draws each frame (librsvg: `brew install librsvg`, or `apt install librsvg2-bin`)",
    "ffmpeg": "it joins the frames into the GIF (`brew install ffmpeg`, or `apt install ffmpeg`)",
}


class DemoError(Exception):
    """The demo cannot be played or written as asked; the message says why."""


# ---------------------------------------------------------------------- what a step must leave behind


@dataclass
class Stage:
    """What a step's `then` looks at: the console and the mock's world behind it."""

    app: FlightdeckApp
    world: FakeWorld

    @property
    def deck(self) -> Deck:
        return self.world.deck

    def selected(self) -> Lane | None:
        """The lane the fleet's keys act on."""
        return self.deck.lanes.get(self.app.fleet.selected_lane or "")

    def on(self, challenge: str, state: LaneState | None = None) -> list[Lane]:
        """The lanes still working on `challenge`, or (`state`) its lanes in that state."""
        lanes = [lane for lane in self.deck.lanes.values() if lane.challenge_id == challenge]
        return [lane for lane in lanes if (not lane.finished if state is None else lane.state is state)]


@dataclass(frozen=True)
class Check:
    what: str  # said when it does not hold
    holds: Callable[[Stage], bool]


def showing(screen: type) -> Check:
    return Check(f"the console shows its {screen.__name__}", lambda s: isinstance(s.app.screen, screen))


def selected(challenge: str, *, alert: AlertKind | None = None, flag: bool = False, need_you: int | None = None) -> Check:
    """The fleet is up and its selected lane works on `challenge`: with `alert` raised, or
    (`flag`) with a flag waiting to be submitted; and (`need_you`) that many lanes need the
    player."""

    def holds(s: Stage) -> bool:
        lane = s.selected()
        if not isinstance(s.app.screen, FleetScreen) or lane is None or lane.challenge_id != challenge or lane.finished:
            return False
        if alert is not None and lane.alert(alert) is None:
            return False
        if need_you is not None and len(s.deck.needing()) != need_you:
            return False
        return not flag or _waits_to_submit(lane)

    what = f"the selected lane works on {challenge}"
    what += f" and has the {alert.value} alert" if alert else ""
    what += " and a flag waiting" if flag else ""
    return Check(what + (f", and {need_you} lanes need you" if need_you is not None else ""), holds)


def _waits_to_submit(lane: Lane) -> bool:
    return lane.pending is not None and lane.pending.kind is PendingKind.SUBMIT


def solved(challenge: str) -> Check:
    return Check(f"{challenge} is solved", lambda s: s.deck.challenges[challenge].status is ChallengeStatus.SOLVED)


def opened(challenge: str) -> Check:
    def holds(s: Stage) -> bool:
        screen = s.app.screen
        return isinstance(screen, FocusScreen) and screen.lane.challenge_id == challenge

    return Check(f"the lane on {challenge} is open full screen", holds)


def redirected(challenge: str) -> Check:
    def holds(s: Stage) -> bool:
        lanes = s.on(challenge)
        return len(lanes) == 1 and lanes[0].alert(AlertKind.HINT) is None and lanes[0].state is LaneState.RUNNING

    return Check(f"the lane on {challenge} runs on with no hint alert", holds)


def flag_found(challenge: str) -> Check:
    return Check(f"a lane on {challenge} has a flag waiting", lambda s: any(_waits_to_submit(lane) for lane in s.on(challenge)))


def restarted(challenge: str) -> Check:
    def holds(s: Stage) -> bool:
        return len(s.on(challenge, LaneState.KILLED)) == 1 and len(s.on(challenge)) == 1 and isinstance(s.app.screen, FleetScreen)

    return Check(f"the lane on {challenge} is killed and a fresh one has started", holds)


def wave_dropped(challenges: int, *, lanes: int) -> Check:
    def holds(s: Stage) -> bool:
        wave = len(s.deck.challenges) - len(scenarios.EARLY)
        return wave == challenges and len(s.deck.active_lanes()) == lanes and len(s.deck.queue) > 0

    return Check(f"the wave put {challenges} challenges on the board, {lanes} lanes run and the rest are queued", holds)


QUIT = Check("the console has quit", lambda s: s.app.return_code is not None)
NOTHING = Check("nothing", lambda s: True)


# ---------------------------------------------------------------------- the demo, step by step


@dataclass(frozen=True)
class Card:
    """A frame that is drawn, not played: a shell prompt and what was typed at it."""

    say: str  # the caption, in the window's title bar
    hold: float  # seconds the frame stays
    lines: tuple[str, ...]


@dataclass(frozen=True)
class Beat:
    """A frame of the console: after `key` was pressed (Textual's name for it) or the mock's
    clock moved `ticks`, or as it stands when neither is given."""

    say: str
    hold: float
    then: Check
    key: str = ""
    ticks: int = 0


Step = Card | Beat
MOCK = "$ uvx ctf-flightdeck mock"

DEMO: tuple[Step, ...] = (
    Card("flightdeck: play CTFs with a fleet of AI agents, and stay the pilot", 0.6, ("$ ▌",)),
    Card("flightdeck: play CTFs with a fleet of AI agents, and stay the pilot", 0.3, ("$ uvx▌",)),
    Card("flightdeck: play CTFs with a fleet of AI agents, and stay the pilot", 0.3, ("$ uvx ctf-flightdeck▌",)),
    Card("flightdeck: play CTFs with a fleet of AI agents, and stay the pilot", 1.4,
         (MOCK + "▌", "", "# the demo: scripted data. No install, no API key, nothing spent.")),
    Beat("the demo opens on an event in progress", 4.0, showing(WelcomeScreen)),
    Beat("enter  ·  one AI agent per challenge, each in its own lane. Three need you.", 3.6,
         selected("ticket-desk", flag=True, need_you=3), key="enter"),
    Beat("1  ·  submit the flag the top lane found: Ticket Desk is solved", 1.8, solved("ticket-desk"), key="1"),
    Beat("1  ·  submit the flag the top lane found: Ticket Desk is solved", 1.2, NOTHING, ticks=1),
    Beat("page up  ·  the next lane ignores the hint in its challenge's description", 3.6,
         selected("static-hiss", alert=AlertKind.HINT), key="pageup"),
    Beat("enter  ·  open the lane: what it did, what it needs from you, the files it changed", 4.4,
         opened("static-hiss"), key="enter"),
    Beat("1  ·  redirect it to the technique the description hints at", 2.2, redirected("static-hiss"), key="1"),
    Beat("the lane takes the new plan ...", 1.6, redirected("static-hiss"), ticks=1),
    Beat("... and finds the flag", 2.4, flag_found("static-hiss"), ticks=1),
    Beat("1  ·  submit it: Static Hiss is solved", 2.0, solved("static-hiss"), key="1"),
    Beat("esc  ·  back to the lanes", 1.0, showing(FleetScreen), key="escape"),
    Beat("page up  ·  this lane brute-forces a server whose source code is in its files", 3.6,
         selected("paper-trail", alert=AlertKind.DIRECTION), key="pageup"),
    Beat("k  ·  kill it", 2.0, showing(KillPrompt), key="k"),
    Beat("r  ·  re-queue fresh: a new lane starts on Paper Trail with a clean context", 3.0,
         restarted("paper-trail"), key="r"),
    Beat("a wave drops: 43 new challenges. 16 lanes run at once, the rest wait their turn.", 4.4,
         wave_dropped(43, lanes=16), ticks=1),
    Beat("a wave drops: 43 new challenges. 16 lanes run at once, the rest wait their turn.", 1.0, NOTHING, ticks=1),
    Beat("the fresh lane read the source first, and has a flag", 2.4, flag_found("paper-trail"), ticks=1),
    Beat("page up  ·  the lane that needs you is always on top", 1.2, selected("paper-trail", flag=True), key="pageup"),
    Beat("1  ·  submit it: Paper Trail is solved", 2.6, solved("paper-trail"), key="1"),
    Beat("?  ·  every key, any time", 3.4, showing(HelpScreen), key="question_mark"),
    Beat("esc  ·  back to the lanes", 0.8, showing(FleetScreen), key="escape"),
    Beat("q  ·  quit", 0.0, QUIT, key="q"),
    Card("that was scripted data. Next: the same console, on your own model.", 5.2,
         (f"{MOCK:<36}# what you just watched",
          f"{'$ uv tool install ctf-flightdeck':<36}# install it",
          f"{'$ flightdeck▌':<36}# the home screen: \"Get started\", then \"Practice\"",
          "",
          "# Practice: 14 small challenges for your own model, in this console.")),
)


# ---------------------------------------------------------------------- playing it


@dataclass(frozen=True)
class Frame:
    svg: str  # the terminal at SIZE, with the step's caption in its title bar
    seconds: float
    say: str


@dataclass
class Played:
    frames: list[Frame]
    stage: Stage  # the console (closed by now) and the world as the demo left them

    @property
    def seconds(self) -> float:
        return round(sum(frame.seconds for frame in self.frames), 2)


def play(steps: Sequence[Step] = DEMO, *, size: tuple[int, int] = SIZE) -> Played:
    """Play `steps` on the mock with no terminal and return every frame. DemoError names the
    first step whose `then` does not hold."""
    return asyncio.run(_play(tuple(steps), size))


async def _play(steps: tuple[Step, ...], size: tuple[int, int]) -> Played:
    world = FakeWorld(scenarios.get(SCENARIO))
    # as `flightdeck mock` opens for a player with no config, on its welcome screen; the clock is the script's
    app = FlightdeckApp(world.deck, ticker=world.tick, mock=f"MOCK · {SCENARIO}", refresh_seconds=None,
                        palette=themes.DEFAULT, layout="simple", welcome=True)
    stage = Stage(app, world)
    frames: list[Frame] = []
    async with app.run_test(size=size) as pilot:
        for number, step in enumerate(steps, 1):
            if isinstance(step, Card):
                frames.append(Frame(card(step, size), step.hold, step.say))
                continue
            where = f"step {number} ({_does(step)}: {step.say!r})"
            if app.return_code is not None:
                raise DemoError(f"{where}: the console has quit, so nothing can be played after it")
            if step.key:
                await pilot.press(step.key)
            if step.ticks:
                app.step(step.ticks)  # what the live mock's timer does once a second: the clock moves, the console redraws
            if not await _settled(pilot, step.then, stage):
                raise DemoError(
                    f"{where}: after it, this should hold and does not: {step.then.what}. The console or the mock "
                    "changed, so the demo no longer shows what its caption says: change DEMO in scripts/demo.py"
                )
            if app.return_code is not None:
                if step.hold:
                    raise DemoError(f"{where}: the console has quit, so there is no frame to hold for {step.hold} s")
                continue
            frames.append(Frame(app.export_screenshot(title=step.say), step.hold, step.say))
    return Played(frames, stage)


async def _settled(pilot, check: Check, stage: Stage) -> bool:
    """Whether `check` holds once the console has done what the step asked. It is waited for,
    not timed: a key's effect may take the console a few turns of its loop on a busy machine."""
    for _ in range(40):
        await pilot.pause()
        if check.holds(stage):
            await pilot.pause()  # and what it queued to draw is drawn
            return True
        await asyncio.sleep(0.05)
    return False


def _does(step: Beat) -> str:
    parts = ([f"key {step.key}"] if step.key else []) + ([f"{step.ticks} tick"] if step.ticks else [])
    return ", ".join(parts) or "look"


def card(step: Card, size: tuple[int, int]) -> str:
    """`step` drawn as a terminal of `size` in the default theme, shaped like a frame of the console."""
    columns, rows = size
    palette = themes.DEFAULT
    page = Style(color=palette.text, bgcolor=palette.page)
    console = Console(width=columns, height=rows, file=io.StringIO(), force_terminal=True, color_system="truecolor",
                      record=True, legacy_windows=False, safe_box=False)
    lines = ["", *step.lines]
    if len(lines) > rows or any(len(line) + 2 > columns for line in lines):
        raise DemoError(f"the card {step.say!r} does not fit in {columns} by {rows}")
    for row in range(rows):
        line = lines[row] if row < len(lines) else ""
        text = Text("  " + line.ljust(columns - 2), style=page, no_wrap=True, end="")
        if line.startswith("$"):  # a command: its prompt, then what it is for
            text.stylize(Style(color=palette.ok, bold=True), 2, 3)
        note = line.find("# ")
        if note >= 0:
            text.stylize(Style(color=palette.muted), 2 + note)
        console.print(text, end="\n" if row < rows - 1 else "")
    return console.export_svg(title=step.say)


# ---------------------------------------------------------------------- writing it


def write_frames(frames: Sequence[Frame], folder: Path) -> list[Path]:
    """Each frame as NN.svg in `folder` (made if it is not there), in order."""
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for number, frame in enumerate(frames, 1):
        path = folder / f"{number:02d}.svg"
        path.write_text(frame.svg, encoding="utf-8")
        paths.append(path)
    return paths


def missing_tools() -> list[str]:
    return [name for name in TOOLS if shutil.which(name) is None]


def _no_gif_without(absent: Sequence[str]) -> str:
    why = "; ".join(f"`{name}` is not on the PATH: {TOOLS[name]}" for name in absent)
    return f"no GIF was written: {why}. `--check` and `--frames DIR` need neither tool."


def write_gif(frames: Sequence[Frame], out: Path, *, width: int = WIDTH, colours: int = COLOURS) -> None:
    """The frames as one looping GIF at `out`, each shown for its seconds. Needs TOOLS: a
    missing one is a DemoError and nothing is written. The pictures in between are made in a
    folder beside `out` that is gone afterwards."""
    absent = missing_tools()
    if absent:
        raise DemoError(_no_gif_without(absent))
    if not frames:
        raise DemoError("no GIF was written: the demo has no frames")
    if not out.parent.is_dir():
        raise DemoError(f"no GIF was written: {out.parent} is not a folder")
    with tempfile.TemporaryDirectory(dir=out.parent, prefix=".demo-frames-") as work:
        folder = Path(work)
        listing = ["ffconcat version 1.0"]
        for number, frame in enumerate(frames, 1):
            svg, png = folder / f"{number:02d}.svg", folder / f"{number:02d}.png"
            svg.write_text(_keep_spaces(frame.svg), encoding="utf-8")
            _run(["rsvg-convert", "--width", str(width), "--output", str(png), str(svg)], "rsvg-convert")
            listing += [f"file '{png.name}'", f"duration {frame.seconds:.2f}"]
        (folder / "frames.txt").write_text("\n".join(listing) + "\n", encoding="utf-8")
        made = folder / "demo.gif"
        _run([
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(folder / "frames.txt"),
            "-filter_complex", f"[0:v]split[a][b];[a]palettegen=max_colors={colours}:stats_mode=full[p];"
                               "[b][p]paletteuse=dither=none:diff_mode=rectangle",
            "-fps_mode", "vfr", "-final_delay", str(round(frames[-1].seconds * 100)), "-loop", "0", str(made),
        ], "ffmpeg")
        made.replace(out)


def _keep_spaces(svg: str) -> str:
    """`svg` for rsvg-convert, which drops the blank a piece of text starts or ends with unless
    the text says to keep it (a browser keeps Rich's no-break spaces as they are)."""
    return svg.replace("<text class=", '<text xml:space="preserve" class=')


def _run(argv: list[str], tool: str) -> None:
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DemoError(f"no GIF was written: {tool} did not run: {exc}") from exc
    if done.returncode != 0:
        said = (done.stderr or done.stdout).strip().splitlines()
        raise DemoError(f"no GIF was written: {tool} failed (exit {done.returncode}): {said[-1] if said else 'it said nothing'}")


@dataclass(frozen=True)
class Gif:
    width: int
    height: int
    frames: int
    seconds: float  # one loop: the sum of the frames' delays
    size: int  # bytes


def gif_facts(path: Path) -> Gif:
    """What the GIF file at `path` is, read from its blocks."""
    data = path.read_bytes()
    if data[:6] not in (b"GIF87a", b"GIF89a"):
        raise DemoError(f"{path} is not a GIF")
    try:
        width, height, flags = struct.unpack_from("<HHB", data, 6)
        at = 13 + (3 << ((flags & 7) + 1) if flags & 0x80 else 0)
        frames = hundredths = 0
        while data[at] != 0x3B:  # the trailer
            if data[at] == 0x21:  # an extension; 0xF9 is a frame's graphic control, with its delay
                if data[at + 1] == 0xF9:
                    hundredths += struct.unpack_from("<H", data, at + 4)[0]
                at += 2
            elif data[at] == 0x2C:  # a frame's picture
                frames += 1
                local = data[at + 9]
                at += 10 + (3 << ((local & 7) + 1) if local & 0x80 else 0) + 1
            else:
                raise DemoError(f"{path} is not a GIF this script can read (block {data[at]:#x} at byte {at})")
            while data[at]:  # the block's data, in pieces of up to 255 bytes
                at += data[at] + 1
            at += 1
    except (IndexError, struct.error):
        raise DemoError(f"{path} is a GIF that ends before its last block") from None
    return Gif(width, height, frames, hundredths / 100, len(data))


# ---------------------------------------------------------------------- the command


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="demo.py", description="Play the README's demo on `flightdeck mock` and write it as a GIF.")
    parser.add_argument("gif", nargs="?", type=Path, help="where to write the GIF (needs rsvg-convert and ffmpeg)")
    parser.add_argument("--check", action="store_true", help="play the demo and say how it went; write nothing")
    parser.add_argument("--frames", type=Path, metavar="DIR", help="write each frame to DIR as NN.svg (needs no tool)")
    parser.add_argument("--width", type=int, default=WIDTH, metavar="PIXELS", help=f"the GIF's width (default {WIDTH})")
    args = parser.parse_args(argv)
    if args.gif is None and args.frames is None and not args.check:
        parser.error("give a GIF to write, --frames DIR, or --check")
    if args.check and (args.gif is not None or args.frames is not None):
        parser.error("--check writes nothing: give it alone")
    if args.width < 320:
        parser.error("--width must be 320 pixels or more")
    if args.gif is not None and (absent := missing_tools()):  # before the demo is played: it could not be written
        print(f"demo: {_no_gif_without(absent)}", file=sys.stderr)
        return 2
    try:
        played = play()
        print(f"demo: {len(played.frames)} frames, {played.seconds:g} s, {len(DEMO)} steps, every step did what it says")
        if args.frames is not None:
            paths = write_frames(played.frames, args.frames)
            print(f"demo: wrote {len(paths)} frames to {args.frames}")
        if args.gif is not None:
            write_gif(played.frames, args.gif, width=args.width)
            gif = gif_facts(args.gif)
            print(f"demo: wrote {args.gif}: {gif.width} by {gif.height}, {gif.frames} frames, {gif.seconds:g} s, {gif.size / 1000:.0f} kB")
    except DemoError as exc:
        print(f"demo: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
