"""scripts/demo.py: the README's 60-second demo, played on the mock with no terminal.

The check that runs everywhere is the play itself: every key the script presses must still do
what its caption says (a flag submitted, a lane redirected, a lane killed and started fresh,
the wave on the board), and a step that no longer does stops the demo by name. Writing the GIF
needs rsvg-convert and ffmpeg: the test that writes one reports as not run where either is
missing, and what the script says without them is tested with a PATH that has neither.
Nothing here opens a terminal, and every file is written under tmp_path.
"""

from __future__ import annotations

import dataclasses
import html
import importlib.util
import re
import struct
import sys
from pathlib import Path

import pytest
from rich.cells import cell_len

from ctf_flightdeck.core.model import ChallengeStatus, EventKind, LaneState

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "demo.py"
GIF = ROOT / "docs" / "screenshots" / "demo.gif"
README = ROOT / "README.md"
RAW = "https://raw.githubusercontent.com/MFisher14/ctf-flightdeck/main/"
WARN_BYTES = 2 * 1024 * 1024  # the commit guard calls a file over this large (.githooks/secret_scan.py)

SPAN = re.compile(r'<text class="[^"]*-r\d+" x="([\d.]+)" y="([\d.]+)" textLength="([\d.]+)"[^>]*>(.*?)</text>')
TITLE = re.compile(r'<text class="[^"]*-title"[^>]*>(.*?)</text>')
CLIP = re.compile(r'-clip-terminal">\s*<rect x="0" y="0" width="([\d.]+)" height="([\d.]+)"')
CELL = (12.2, 24.4)  # the width and height Rich gives a terminal cell in its SVG (20 px letters)


def _load():
    spec = importlib.util.spec_from_file_location("flightdeck_demo_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up by name
    spec.loader.exec_module(module)
    return module


demo = _load()


@pytest.fixture(scope="module")
def played():
    return demo.play()


def shown(frame) -> str:
    """The frame's screen as text, one line per row. Rich writes a run of one style as a piece
    of text at x = column * cell width, and nothing for blanks between two runs."""
    lines: dict[float, list[str]] = {}
    for x, y, length, body in SPAN.findall(frame.svg):
        text = html.unescape(body).replace("\xa0", " ")
        column = round(float(x) / (float(length) / len(text)))
        cells = [part for ch in text for part in ((ch, "") if cell_len(ch) == 2 else (ch,))]
        line = lines.setdefault(float(y), [])
        line.extend(" " * (column - len(line)))
        line[column : column + len(cells)] = cells
    return "\n".join("".join(lines[y]).rstrip() for y in sorted(lines))


def caption(frame) -> str:
    """What the frame's window says in its title bar."""
    return html.unescape(TITLE.search(frame.svg).group(1)).replace("\xa0", " ")


def frame_of(played, caption: str):
    """(index, frame) of the first frame whose caption has `caption` in it."""
    found = [(n, frame) for n, frame in enumerate(played.frames) if caption in frame.say]
    assert found, f"no frame is captioned {caption!r}: {[frame.say for frame in played.frames]}"
    return found[0]


# ---------------------------------------------------------------------- the play


def test_the_keys_do_what_the_captions_say(played):
    deck = played.stage.deck
    on = {lane.id: lane.challenge_id for lane in deck.lanes.values()}
    did = [(e.data["intervention"], on[e.lane]) for e in deck.events if e.kind is EventKind.INTERVENTION]
    assert did == [
        ("approve", "ticket-desk"), ("redirect", "static-hiss"), ("approve", "static-hiss"),
        ("kill", "paper-trail"), ("approve", "paper-trail"),
    ]
    for challenge in ("ticket-desk", "static-hiss", "paper-trail"):
        assert deck.challenges[challenge].status is ChallengeStatus.SOLVED, challenge
    # the lane that was redirected is the one that solved it; the killed lane's challenge was solved by a fresh one
    assert [lane.state for lane in deck.lanes.values() if lane.challenge_id == "static-hiss"] == [LaneState.SOLVED]
    assert [lane.state for lane in deck.lanes.values() if lane.challenge_id == "paper-trail"] == [LaneState.KILLED, LaneState.SOLVED]
    assert played.stage.app.return_code == 0  # q quit the console


def test_the_wave_the_caption_counts_is_the_wave_on_the_board(played):
    deck = played.stage.deck
    wave = [e for e in deck.events if e.kind is EventKind.RELEASE][-1]
    _, frame = frame_of(played, "a wave drops")
    assert len(wave.data["challenges"]) == 43 and "43 new challenges" in frame.say
    assert wave.data["started"] + 4 == deck.config.max_lanes == 16 and "16 lanes run at once" in frame.say
    assert wave.data["queued"] > 0  # "the rest wait their turn"


def test_a_frame_shows_the_console_as_the_step_left_it(played):
    # a frame taken before the console redrew would show the step before it
    at, found = frame_of(played, "finds the flag")
    assert "mock{static_hiss_" in shown(found) and "mock{static_hiss_" not in shown(played.frames[at - 1])
    at, wave = frame_of(played, "a wave drops")
    assert "Form Letter" in shown(wave) and "Form Letter" not in shown(played.frames[at - 1])  # a challenge of the wave
    _, submitted = frame_of(played, "Ticket Desk is solved")
    assert "mock{ticket_desk_" in shown(submitted)


def test_every_frame_is_one_terminal_of_120_by_36_with_its_caption(played):
    assert demo.SIZE == (120, 36)
    for number, frame in enumerate(played.frames, 1):
        width, height = (float(n) for n in CLIP.search(frame.svg).groups())  # Rich clips the screen a pixel short
        assert (round((width + 1) / CELL[0]), round((height + 1) / CELL[1])) == (120, 36), f"frame {number} ({frame.say})"
        assert frame.say and caption(frame) == frame.say, number
    assert len({re.search(r'viewBox="[^"]*"', frame.svg).group() for frame in played.frames}) == 1


def test_the_demo_is_a_minute_long_and_starts_and_ends_at_a_shell_prompt(played):
    assert 58 <= played.seconds <= 62
    assert all(0.2 <= frame.seconds <= 6 for frame in played.frames)
    first, last = shown(played.frames[0]), shown(played.frames[-1])
    assert "$ ▌" in first and "MOCK" not in first  # the prompt, before anything is typed
    assert "$ uvx ctf-flightdeck mock" in shown(played.frames[3])
    for command in ("$ uvx ctf-flightdeck mock", "$ uv tool install ctf-flightdeck", "$ flightdeck▌"):
        assert command in last
    assert "Practice" in last


def test_the_frames_come_out_the_same_every_time(played):
    again = demo.play()
    assert [(f.say, f.seconds, f.svg) for f in again.frames] == [(f.say, f.seconds, f.svg) for f in played.frames]


def test_a_step_that_no_longer_does_what_it_says_stops_the_demo_by_name():
    steps = list(demo.DEMO)
    at = next(n for n, step in enumerate(steps) if isinstance(step, demo.Beat) and step.key == "1")
    steps[at] = dataclasses.replace(steps[at], key="0")  # 0 answers "do not submit": the flag is not sent
    with pytest.raises(demo.DemoError) as caught:
        demo.play(steps)
    said = str(caught.value)
    assert said.startswith(f"step {at + 1} (key 0: ") and "ticket-desk is solved" in said and "scripts/demo.py" in said


def test_nothing_is_played_after_the_console_has_quit():
    from ctf_flightdeck.console.fleet import FleetScreen
    from ctf_flightdeck.console.screens import WelcomeScreen

    to_quit = (
        demo.Beat("the welcome screen", 1.0, demo.showing(WelcomeScreen)),
        demo.Beat("the lanes", 1.0, demo.showing(FleetScreen), key="enter"),
        demo.Beat("quit", 0.0, demo.QUIT, key="q"),
    )
    played = demo.play(to_quit)
    assert [frame.say for frame in played.frames] == ["the welcome screen", "the lanes"]  # q leaves no frame
    assert played.stage.app.return_code == 0
    extra = demo.Beat("one more", 1.0, demo.NOTHING, key="enter")
    with pytest.raises(demo.DemoError, match=r"step 4 \(key enter: 'one more'\): the console has quit, so nothing can be played"):
        demo.play((*to_quit, extra))
    held = (*to_quit[:2], dataclasses.replace(to_quit[2], hold=2.0))
    with pytest.raises(demo.DemoError, match=r"step 3 \(key q: 'quit'\): the console has quit, so there is no frame to hold for 2.0 s"):
        demo.play(held)


def test_a_card_that_does_not_fit_the_terminal_is_refused():
    wide = demo.Card("too wide", 1.0, ("$ " + "x" * 120,))
    with pytest.raises(demo.DemoError, match="the card 'too wide' does not fit in 120 by 36"):
        demo.play((wide,))


# ---------------------------------------------------------------------- the command


def test_check_plays_the_demo_and_writes_nothing(tmp_path, monkeypatch, capsys, played):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))  # no tool: --check needs none
    assert demo.main(["--check"]) == 0
    out, err = capsys.readouterr()
    frames = len([step for step in demo.DEMO if not (isinstance(step, demo.Beat) and step.key == "q")])  # q leaves no frame
    assert out == f"demo: {frames} frames, {played.seconds:g} s, {len(demo.DEMO)} steps, every step did what it says\n"
    assert err == ""
    assert list(tmp_path.iterdir()) == []


def test_frames_writes_each_frame_as_an_svg_without_any_tool(tmp_path, monkeypatch, capsys, played):
    monkeypatch.setenv("PATH", str(tmp_path / "nothing-here"))
    out_dir = tmp_path / "frames"
    assert demo.main(["--frames", str(out_dir)]) == 0
    written = sorted(out_dir.iterdir())
    assert [path.name for path in written] == [f"{n:02d}.svg" for n in range(1, len(played.frames) + 1)]
    assert [path.read_text(encoding="utf-8") for path in written] == [frame.svg for frame in played.frames]
    assert f"demo: wrote {len(written)} frames to {out_dir}\n" in capsys.readouterr().out


@pytest.mark.parametrize("argv, said", [
    ([], "give a GIF to write, --frames DIR, or --check"),
    (["--check", "demo.gif"], "--check writes nothing: give it alone"),
    (["demo.gif", "--width", "100"], "--width must be 320 pixels or more"),
])
def test_a_call_that_asks_for_nothing_or_too_much_is_a_usage_error(argv, said, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        demo.main(argv)
    assert stopped.value.code == 2 and said in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------- the GIF


def stub(folder: Path, name: str, body: str = "exit 0") -> None:
    folder.mkdir(exist_ok=True)
    (folder / name).write_text(f"#!/bin/sh\n{body}\n")
    (folder / name).chmod(0o755)


def test_without_its_tools_no_gif_is_written_and_each_missing_tool_is_named(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    out = tmp_path / "demo.gif"
    assert demo.main([str(out)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("demo: no GIF was written: `rsvg-convert` is not on the PATH: it draws each frame")
    assert "`ffmpeg` is not on the PATH: it joins the frames" in err and "`--check` and `--frames DIR` need neither tool" in err
    assert not out.exists()
    stub(tmp_path / "bin", "ffmpeg")  # one of the two is there: the other alone is named
    frame = demo.Frame("<svg/>", 1.0, "a frame")
    with pytest.raises(demo.DemoError) as caught:
        demo.write_gif([frame], out)
    assert "`rsvg-convert` is not on the PATH" in str(caught.value) and "`ffmpeg`" not in str(caught.value)
    assert sorted(path.name for path in tmp_path.iterdir()) == ["bin"]


def test_a_tool_that_fails_is_named_with_what_it_said_and_leaves_nothing_behind(tmp_path, monkeypatch):
    stub(tmp_path / "bin", "rsvg-convert", "echo 'boom: cannot draw' >&2; exit 3")
    stub(tmp_path / "bin", "ffmpeg")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    out = tmp_path / "out" / "demo.gif"
    out.parent.mkdir()
    with pytest.raises(demo.DemoError, match=r"no GIF was written: rsvg-convert failed \(exit 3\): boom: cannot draw"):
        demo.write_gif([demo.Frame("<svg/>", 1.0, "a frame")], out)
    assert list(out.parent.iterdir()) == []  # no GIF, and the folder of pictures in between is gone


def test_a_gif_is_not_written_into_a_folder_that_is_not_there(tmp_path, monkeypatch):
    stub(tmp_path / "bin", "rsvg-convert")
    stub(tmp_path / "bin", "ffmpeg")
    monkeypatch.setenv("PATH", str(tmp_path / "bin"))
    with pytest.raises(demo.DemoError, match="no GIF was written: .*missing is not a folder"):
        demo.write_gif([demo.Frame("<svg/>", 1.0, "a frame")], tmp_path / "missing" / "demo.gif")
    assert not (tmp_path / "missing").exists()


def test_the_gif_has_every_frame_for_its_seconds(tmp_path, played):
    absent = demo.missing_tools()
    if absent:
        pytest.skip(f"not run: writing the GIF needs rsvg-convert and ffmpeg, and {' and '.join(absent)} is not on the PATH")
    out = tmp_path / "demo.gif"
    demo.write_gif(played.frames, out, width=480)
    gif = demo.gif_facts(out)
    assert (gif.width, gif.frames, gif.seconds) == (480, len(played.frames), played.seconds)
    assert gif.height == round(480 * 928.4 / 1482) and gif.size == out.stat().st_size
    assert [path.name for path in tmp_path.iterdir()] == ["demo.gif"]


def _gif(*delays: int) -> bytes:
    """A 1 by 1 GIF with one frame per delay (hundredths of a second), written by hand."""
    data = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0) + bytes(6)  # a global table of two colours
    data += b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"  # loop for ever: an extension that is no frame
    for delay in delays:
        data += b"\x21\xf9\x04\x00" + struct.pack("<H", delay) + b"\x00\x00"
        data += b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0) + b"\x02\x02\x44\x01\x00"
    return data + b"\x3b"


def test_gif_facts_reads_size_frames_and_seconds_from_the_file(tmp_path):
    path = tmp_path / "two.gif"
    path.write_bytes(_gif(150, 250))
    assert demo.gif_facts(path) == demo.Gif(width=1, height=1, frames=2, seconds=4.0, size=len(_gif(150, 250)))
    path.write_bytes(_gif(150, 250)[:-8])
    with pytest.raises(demo.DemoError, match="two.gif is a GIF that ends before its last block"):
        demo.gif_facts(path)
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(40))
    with pytest.raises(demo.DemoError, match="two.gif is not a GIF"):
        demo.gif_facts(path)


def test_the_gif_in_the_repository_is_the_one_this_script_writes_and_small(played):
    gif = demo.gif_facts(GIF)
    # rebuilt after the last change to the demo's steps: `uv run python scripts/demo.py docs/screenshots/demo.gif`
    assert (gif.frames, gif.seconds, gif.width) == (len(played.frames), played.seconds, demo.WIDTH)
    assert gif.size < WARN_BYTES


def test_the_readme_opens_on_the_demo():
    readme = README.read_text(encoding="utf-8")
    link = f"]({RAW}docs/screenshots/demo.gif)"
    assert link in readme
    # above the first section (that the link names a file the tree has is test_docs_links.py's)
    assert readme.index(link) < readme.index("\n## ")
