"""A challenge the player hands over: /new in the console, `flightdeck add`, and a run that
takes it. The model is the fake server (no spend); every file is the test's own."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import addchallenge, cli, start
from ctf_flightdeck.addchallenge import AddError, NewChallenge
from ctf_flightdeck.core.model import LaneState
from ctf_flightdeck.platform.manual import load_board, load_challenge
from ctf_flightdeck.run import RunError, RunOptions, prepare_run
from fake_model import FakeModelServer, tool_call_reply
from test_run import config

FLAG = "t{handed_over}"


# ---------------------------------------------------------------------- the pasted text


def test_pasted_text_is_sorted_into_description_files_and_addresses(tmp_path):
    shot, spaced = tmp_path / "shot.png", tmp_path / "my notes.txt"
    shot.write_bytes(b"png")
    spaced.write_text("n")
    text = (f"Find the flag in the service.\n{shot}\n'{spaced}'\nnc chal.example.org 1337\n"
            "https://web.example.org:8443/login?x=1\nSee https://en.wikipedia.org/wiki/RSA for background.\n")
    description, files, urls = addchallenge.parse(text)
    assert files == (shot, spaced)
    assert urls == ("tcp://chal.example.org:1337", "https://web.example.org:8443")  # a link inside a sentence is not an instance
    assert description.startswith("Find the flag") and "nc chal.example.org 1337" in description and "wikipedia" in description
    assert str(shot) not in description


def test_files_a_terminal_pasted_side_by_side_with_escaped_spaces_are_all_taken(tmp_path):
    one, two = tmp_path / "a b.bin", tmp_path / "c.txt"
    one.write_bytes(b"1")
    two.write_text("2")
    _, files, _ = addchallenge.parse(f"{str(one).replace(' ', chr(92) + ' ')} {two}\n")
    assert files == (one, two)


def test_a_word_or_a_path_that_does_not_exist_stays_description(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "flag").write_text("x")  # a file named like a word of the text, in the folder flightdeck runs in
    description, files, urls = addchallenge.parse("flag\n/no/such/file.bin\n")
    assert files == () and urls == () and description == "flag\n/no/such/file.bin"


# ---------------------------------------------------------------------- the folder


def test_a_handed_over_challenge_is_a_folder_the_board_loads(tmp_path):
    handout = tmp_path / "postcard.txt"
    handout.write_text("hello")
    folder = addchallenge.create(tmp_path, NewChallenge(name="Crab  Walk!", category="crypto", points=50, description='say "hi"',
                                                        files=(handout,), urls=("tcp://chal.example.org:1337",)))
    assert folder == tmp_path / "crab-walk"
    item = load_challenge(folder)
    assert (item.challenge.name, item.challenge.points, item.challenge.description) == ("Crab Walk!", 50, 'say "hi"')
    assert item.challenge.files == ("postcard.txt",) and item.urls == ("tcp://chal.example.org:1337",)
    assert (folder / "postcard.txt").read_text() == "hello" and handout.exists()  # copied, the player's own left alone


def test_two_challenges_of_one_name_get_folders_of_their_own_and_a_bare_one_is_misc(tmp_path):
    first = addchallenge.create(tmp_path, NewChallenge(name="Same"))
    second = addchallenge.create(tmp_path, NewChallenge(name="Same"))
    assert (first.name, second.name) == ("same", "same-2")
    assert json.loads((second / "challenge.json").read_text())["category"] == "misc"
    assert len(load_board(tmp_path).challenges) == 2


@pytest.mark.parametrize("new", [NewChallenge(name="  "), NewChallenge(name="!!!"), NewChallenge(name="x", points=-1),
                                 NewChallenge(name="x", files=(Path("/no/such/file"),))])
def test_a_challenge_that_cannot_be_written_leaves_nothing_behind(tmp_path, new):
    with pytest.raises(AddError):
        addchallenge.create(tmp_path, new)
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------- the command


def test_flightdeck_add_puts_a_challenge_on_an_events_board(tmp_path):
    start.write(tmp_path / "event", start.EventAnswers(name="One", platform="manual"))
    handout = tmp_path / "capture.pcap"
    handout.write_bytes(b"pcap")
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path / "event"), "--name", "Wire Tap", "--text", "-", "--file", str(handout),
                                          "--url", "nc chal.example.org 9", "--category", "forensics", "--points", "100"],
                                input="Listen in.\n")
    assert result.exit_code == 0, result.output
    item = load_challenge(tmp_path / "event" / "board" / "wire-tap")
    assert (item.challenge.description, item.challenge.files, item.urls) == ("Listen in.", ("capture.pcap",), ("tcp://chal.example.org:9",))


def test_flightdeck_add_refuses_an_address_it_cannot_use_and_writes_nothing(tmp_path):
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "X", "--url", "somewhere"])
    assert result.exit_code == 2 and "--url" in result.output and list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------- a run


def event(tmp_path: Path) -> Path:
    start.write(tmp_path / "event", start.EventAnswers(name="Hand CTF", platform="manual", flag_format=r"t\{[a-z_]+\}"))
    return tmp_path / "event"


def options(tmp_path: Path, server) -> RunOptions:
    folder = event(tmp_path)
    board, profile = start.resolve(folder, None)
    return RunOptions(board=board, event=profile, config=config(tmp_path, server.base_url), folder_seconds=0.05)


def test_a_by_hand_events_empty_board_plays_but_a_plain_empty_folder_does_not(tmp_path):
    with FakeModelServer([]) as server:
        run = prepare_run(options(tmp_path, server))
        assert run.board.challenges == () and run.watches_folder
        assert any("/new adds a challenge" in note for note in run.notes())
        run.close()
        (tmp_path / "plain").mkdir()
        with pytest.raises(RunError, match="no challenge directories"):
            prepare_run(RunOptions(board=tmp_path / "plain", config=config(tmp_path, server.base_url)))


def test_new_in_the_console_hands_a_challenge_with_its_file_to_a_lane_that_solves_it(tmp_path):
    handout = tmp_path / "note.txt"
    handout.write_text(f"the flag is {FLAG}\n")
    server = FakeModelServer([tool_call_reply("shell", {"command": "cat note.txt"}), tool_call_reply("submit_flag", {"flag": FLAG})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                assert not run.deck.lanes and "/new" in app._status[0]
                await pilot.press(*"/new Read Me", "enter")
                await pilot.pause()
                box = app.screen.query_one("#new-text")
                box.text = f"Read the note.\n{handout}\n"
                await pilot.press("ctrl+s")
                for _ in range(500):
                    lanes = list(run.deck.lanes.values())
                    if lanes and lanes[0].pending is not None:
                        break
                    await pilot.pause(0.01)
                (lane,) = run.deck.lanes.values()
                assert lane.challenge_id == "read-me" and lane.pending.flag == FLAG
                assert "added read-me: 1 file" in app._status[0]
                spec = json.loads((run.options.board / "read-me" / "challenge.json").read_text())
                assert spec["description"] == "Read the note." and spec["name"] == "Read Me"
                brief = server.chats()[0]["json"]["messages"][1]["content"]
                assert "Read the note." in brief and "note.txt" in brief
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_new_without_a_name_says_so_and_adds_nothing(tmp_path):
    async def main():
        with FakeModelServer([]) as server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await pilot.press(*"/new", "enter")
                await pilot.pause()
                await pilot.press("ctrl+s")
                await pilot.pause()
                assert "name" in str(app.screen.query_one("#new-problem").render())
                await pilot.press("escape")
                await pilot.pause()
                assert not run.deck.challenges and list(run.options.board.iterdir()) == []
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_a_folder_added_while_the_run_plays_gets_a_lane_and_a_broken_one_is_a_warning_until_fixed(tmp_path):
    server = FakeModelServer([tool_call_reply("submit_flag", {"flag": FLAG})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            warnings = []
            run.deck.subscribe(lambda e: warnings.append(e.text) if e.kind.value == "warning" else None)
            run.release()
            board = run.options.board
            (board / "bad").mkdir()
            (board / "bad" / "challenge.json").write_text("{not json")
            addchallenge.create(board, NewChallenge(name="Later", description="d"))  # as `flightdeck add` does, from another terminal
            for _ in range(400):
                if run.deck.lanes and any("bad" in w for w in warnings):
                    break
                await asyncio.sleep(0.01)
            assert [lane.challenge_id for lane in run.deck.lanes.values()] == ["later"]
            assert sum("bad" in w for w in warnings) == 1
            await asyncio.sleep(0.2)
            assert sum("bad" in w for w in warnings) == 1  # said once while the file stays as it is
            (board / "bad" / "challenge.json").write_text(json.dumps({"name": "Bad", "category": "misc", "points": 1}))
            import os
            os.utime(board / "bad" / "challenge.json", (1, 1))  # a different time than the one it was read at
            for _ in range(400):
                if "bad" in run.deck.challenges:
                    break
                await asyncio.sleep(0.01)
            assert "bad" in run.deck.challenges
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_new_is_refused_on_the_mocks_board(tmp_path):
    from ctf_flightdeck.console.app import FlightdeckApp
    from ctf_flightdeck.mock import scenarios
    from ctf_flightdeck.mock.world import FakeWorld

    async def main():
        world = FakeWorld(scenarios.get("default"))
        app = FlightdeckApp(world.deck, ticker=world.tick, tick_seconds=None, refresh_seconds=None, mock="MOCK")
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            await pilot.press(*"/new", "enter")
            await pilot.pause()
            assert "scripted" in app._status[0] and app._status[1] == "warning"

    asyncio.run(main())


# ---------------------------------------------------------------------- screenshots


PNG = bytes.fromhex("89504e470d0a1a0a") + b"synthetic image bytes"


def test_the_anthropic_client_sends_a_pasted_image_as_an_image_block():
    from ctf_flightdeck import imageread
    from ctf_flightdeck.agent.anthropic_client import to_anthropic

    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "shot.png"
        path.write_bytes(PNG)
        turns = to_anthropic(imageread.message(path)[1:])
    (turn,) = turns
    kinds = [block["type"] for block in turn["content"]]
    assert kinds == ["text", "image"]
    source = turn["content"][1]["source"]
    import base64

    assert (source["type"], source["media_type"]) == ("base64", "image/png") and base64.b64decode(source["data"]) == PNG


def test_an_image_that_is_no_image_or_too_big_is_refused_before_any_model_is_asked(tmp_path):
    from ctf_flightdeck import imageread

    (tmp_path / "notes.txt").write_text("x")
    big = tmp_path / "big.png"
    big.write_bytes(b"0" * (imageread.MAX_BYTES + 1))
    for path, why in [(tmp_path / "notes.txt", "not a PNG"), (big, "at most 4 MB")]:
        with pytest.raises(imageread.ImageError, match=why):
            imageread.message(path)


@pytest.mark.parametrize(("platform", "tools", "code", "out", "error"), [
    ("linux", {"xclip"}, 0, PNG, None),
    ("linux", {"wl-paste", "xclip"}, 1, b"", "no image on the clipboard"),
    ("linux", set(), 0, PNG, "needs wl-paste"),
    ("darwin", set(), 0, b"", "needs osascript"),
])
def test_the_clipboards_image_is_saved_as_a_file_or_the_reason_is_said(tmp_path, platform, tools, code, out, error):
    from types import SimpleNamespace

    from ctf_flightdeck import imageread

    calls = []

    def run(argv, **kwargs):
        calls.append(argv[0])
        return SimpleNamespace(returncode=code, stdout=out)

    which = lambda tool: f"/usr/bin/{tool}" if tool in tools else None  # noqa: E731
    if error:
        with pytest.raises(imageread.ImageError, match=error):
            imageread.clipboard_image(tmp_path / "pasted", platform=platform, which=which, run=run)
        assert not list((tmp_path / "pasted").glob("*.png"))  # nothing half-written is left
    else:
        saved = imageread.clipboard_image(tmp_path / "pasted", platform=platform, which=which, run=run)
        assert saved.read_bytes() == PNG and saved.name == "screenshot-1.png" and calls == ["xclip"]
        assert imageread.clipboard_image(tmp_path / "pasted", platform=platform, which=which, run=run).name == "screenshot-2.png"


def test_a_screenshot_pasted_into_new_is_read_by_the_model_and_its_text_reaches_the_lane(tmp_path):
    from fake_model import text_reply

    shot = tmp_path / "clip.png"
    shot.write_bytes(PNG)
    server = FakeModelServer([text_reply("Unholy Trinity\ncrypto 200\nRecover the key.\nPicture: a dark page."),
                              tool_call_reply("submit_flag", {"flag": FLAG})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            app.paster = lambda: shot  # the clipboard, as the run would save it
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await pilot.press(*"/new Trinity", "enter")
                await pilot.pause()
                await pilot.press("ctrl+v")
                await pilot.pause()
                assert str(shot) in app.screen.query_one("#new-text").text
                await pilot.press("ctrl+s")
                for _ in range(500):
                    if run.deck.lanes:
                        break
                    await pilot.pause(0.01)
                (lane,) = run.deck.lanes.values()
                for _ in range(500):
                    if len(server.chats()) >= 2:
                        break
                    await pilot.pause(0.01)
            await run.shutdown()
            run.close()
            asked, brief = server.chats()[0]["json"]["messages"], server.chats()[1]["json"]["messages"][1]["content"]
            assert asked[1]["content"][1]["image_url"]["url"].startswith("data:image/png;base64,")  # the image went to the model once
            assert "Recover the key." in brief and "clip.png" in brief  # and its text, and the file, to the lane
            spec = json.loads((run.options.board / "trinity" / "challenge.json").read_text())
            assert "[Text read from the image clip.png by fake/small:]" in spec["description"]
            assert (run.options.board / "trinity" / "clip.png").read_bytes() == PNG

    asyncio.run(main())


def test_an_image_the_model_cannot_read_is_a_warning_and_the_challenge_is_added_with_the_file(tmp_path):
    from fake_model import FakeReply

    shot = tmp_path / "clip.png"
    shot.write_bytes(PNG)
    server = FakeModelServer([FakeReply(status=400, body={"error": {"message": "this model takes no images"}})])

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            warnings = []
            run.deck.subscribe(lambda e: warnings.append(e.text) if e.kind.value == "warning" else None)
            run.release()
            ok, said = run.add_challenge(NewChallenge(name="Blind", description="typed text", files=(shot,)))
            assert ok and "reading 1 image" in said
            for _ in range(500):
                if "blind" in run.deck.challenges:
                    break
                await asyncio.sleep(0.01)
            assert run.deck.challenges["blind"].description == "typed text"
            assert any("could not read clip.png" in w and "without that image's text" in w for w in warnings)
            await run.shutdown()
            run.close()

    asyncio.run(main())
