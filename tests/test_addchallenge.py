"""A challenge the player hands over: /new in the console, `flightdeck add`, and a run that
takes it. The model is the fake server (no spend); every file is the test's own."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from textual import events
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


def test_the_text_is_kept_as_given_and_only_addresses_on_lines_of_their_own_are_read_from_it(tmp_path):
    shot, spaced = tmp_path / "shot.png", tmp_path / "my notes.txt"
    shot.write_bytes(b"png")
    spaced.write_text("n")
    text = (f"Find the flag in the service.\n{shot}\n'{spaced}'\nnc chal.example.org 1337\n"
            "https://web.example.org:8443/login?x=1\nSee https://en.wikipedia.org/wiki/RSA for background.")
    description, urls = addchallenge.parse(text + "\n")
    assert description == text  # every line as it was given: a path on a line of its own is text too, and attaches nothing
    assert urls == ("tcp://chal.example.org:1337", "https://web.example.org:8443")  # a link inside a sentence is not an instance


def test_a_path_inside_a_description_is_text_never_a_file(tmp_path):
    """A description names paths all the time (/etc/passwd, /bin/sh, ~/.ssh). One that
    happens to exist on the player's machine stays in the text and attaches nothing."""
    secret, folder = tmp_path / "id_rsa", tmp_path / "Documents"
    secret.write_text("the player's own")
    folder.mkdir()
    for text in [f"Can you read {secret} through the viewer? The admin keeps notes in {folder}.",
                 f"spawn {secret} to win", f"The flag is at {secret}, go.", f"cat {secret} | nc host 1",
                 "AES key: 16 bytes read from /dev/null at boot.", f"Hint:\n{secret} is where it lives"]:
        assert addchallenge.parse(text) == (text, ())
        assert addchallenge.dropped(text) == []  # prose with a path in it is not a drop either


def test_a_paste_that_is_only_paths_is_a_drop_whatever_way_the_terminal_wrote_them(tmp_path):
    one, two, three = tmp_path / "a b.bin", tmp_path / "c.txt", tmp_path / "it's.txt"
    for file in (one, two, three):
        file.write_bytes(b"1")
    escaped = str(one).replace(" ", "\\ ")
    assert addchallenge.dropped(f"{escaped} {two}\n") == [one, two]  # side by side, spaces escaped
    assert addchallenge.dropped(f"'{one}' \"{two}\"") == [one, two]  # quoted
    assert addchallenge.dropped(f"{one}\n{two}\n") == [one, two]  # a line each, the spaces as they are
    assert addchallenge.dropped(f"file://{two}") == [two]
    assert addchallenge.dropped(f"{two} {two}") == [two]  # the same file twice is one file
    assert addchallenge.dropped("'" + str(three).replace("'", "'\\''") + "'") == [three]  # a quote in a quoted name, as a shell writes it
    for file in (one, two, three):
        assert addchallenge.dropped(addchallenge.quote(file)) == [file]  # what the console writes on the command bar reads back


def test_a_word_a_path_that_does_not_exist_or_a_path_among_words_is_not_a_drop(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "flag").write_text("x")  # a file named like a word of the text, in the folder flightdeck runs in
    there = tmp_path / "there.bin"
    there.write_bytes(b"1")
    for text in ["flag", "/no/such/file.bin", f"{there} /no/such/file.bin", f"see {there}", f"{there} is it", f"'{there}", "", "  \n"]:
        assert addchallenge.dropped(text) == []
    assert addchallenge.dropped(f"{there} " * 5000) == []  # too long to be a drop
    assert addchallenge.parse("flag\n/no/such/file.bin\n") == ("flag\n/no/such/file.bin", ())


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


def test_an_add_that_loses_the_race_for_a_name_leaves_the_winners_folder_alone(tmp_path, monkeypatch):
    """Two adds of one name at once (the console's /new and `flightdeck add` in another
    terminal): the folder is there by the time this one makes its own. It belongs to the
    other add, so this one takes the next name and removes nothing."""
    board = tmp_path / "board"
    board.mkdir()
    handout = tmp_path / "note.txt"
    handout.write_text("mine")
    real_mkdir = Path.mkdir

    def mkdir(self, *args, **kwargs):
        if self == board / "baby-rsa" and not self.exists():  # the other add gets there first
            real_mkdir(self)
            (self / "theirs.bin").write_bytes(b"the other add's file")
        return real_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", mkdir)
    made = addchallenge.create(board, NewChallenge(name="Baby RSA", files=(handout,)))
    assert made == board / "baby-rsa-2" and (made / "note.txt").read_text() == "mine"
    assert (board / "baby-rsa" / "theirs.bin").read_bytes() == b"the other add's file"


def test_a_folder_that_cannot_be_filled_is_removed_but_only_the_one_this_add_made(tmp_path):
    board, handout = tmp_path / "board", tmp_path / "handout"
    (board / "doll").mkdir(parents=True)
    (board / "doll" / "theirs.bin").write_bytes(b"1")
    handout.mkdir()
    (handout / "a.txt").write_text("a")
    import os

    os.mkfifo(handout / "pipe")  # found only while the folder is copied
    with pytest.raises(AddError, match="named pipe"):
        addchallenge.create(board, NewChallenge(name="Doll", files=(handout,)))
    assert [entry.name for entry in board.iterdir()] == ["doll"] and (board / "doll" / "theirs.bin").exists()


def test_a_file_that_cannot_be_read_is_named_in_the_refusal_and_nothing_is_left(tmp_path):
    import os

    if os.geteuid() == 0:
        pytest.skip("root reads any file, so no copy fails this way")
    board, good, locked = tmp_path / "board", tmp_path / "good.txt", tmp_path / "locked.bin"
    board.mkdir()
    good.write_text("good")
    locked.write_bytes(b"x")
    locked.chmod(0)
    with pytest.raises(AddError, match=r"cannot write .*/board/doll: Permission denied \(.*locked\.bin\)"):
        addchallenge.create(board, NewChallenge(name="Doll", files=(good, locked)))
    assert list(board.iterdir()) == []


# ---------------------------------------------------------------------- what may be attached


def test_only_a_regular_file_or_a_folder_is_attached_and_each_refusal_names_its_reason(tmp_path, monkeypatch):
    import os
    import socket

    home, keys = tmp_path / "home", tmp_path / "elsewhere" / "keys.env"
    config = home / ".config" / "ctf-flightdeck"
    config.mkdir(parents=True)
    (config / "config.toml").write_text("")
    keys.parent.mkdir()
    keys.write_text("")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    pipe, sock, link = tmp_path / "pipe", tmp_path / "s", tmp_path / "innocent.txt"
    os.mkfifo(pipe)
    listener = socket.socket(socket.AF_UNIX)
    monkeypatch.chdir(tmp_path)  # a socket's path is short: bound by its name alone
    listener.bind("s")
    link.symlink_to(keys)  # a link the player names is followed: it is the keys file
    try:
        for path, why in [(Path("/dev/null"), "is a device"), (pipe, "is a named pipe"), (sock, "is a socket"),
                          (Path("/"), "is the root folder"), (home, "is your home folder itself"),
                          (config, "is flightdeck's config folder"), (home / ".config", "holds flightdeck's config folder"),
                          (config / "config.toml", "is in flightdeck's config folder"), (keys, "is flightdeck's keys file"),
                          (keys.parent, "holds flightdeck's keys file"), (link, "is flightdeck's keys file"),
                          (tmp_path / "gone.bin", "no such file")]:
            said = addchallenge.refusal(path)
            assert said is not None and why in said and str(path) in said, (path, said)
            with pytest.raises(AddError, match=why):
                addchallenge.create(tmp_path / "elsewhere", NewChallenge(name="X", files=(path,)))
    finally:
        listener.close()
    assert sorted(entry.name for entry in keys.parent.iterdir()) == ["keys.env"]  # no challenge folder was left
    handout = home / "ctf" / "handout"
    handout.mkdir(parents=True)
    (handout / "a.txt").write_text("a")
    assert addchallenge.refusal(handout) is None and addchallenge.refusal(handout / "a.txt") is None


def test_a_folder_that_holds_the_board_is_not_copied_into_it(tmp_path):
    board = tmp_path / "ctf" / "event" / "board"
    board.mkdir(parents=True)
    with pytest.raises(AddError, match="holds the folder it would be copied into"):
        addchallenge.create(board, NewChallenge(name="X", files=(tmp_path / "ctf",)))
    assert list(board.iterdir()) == []


def test_a_copied_folder_keeps_a_link_as_a_link_and_a_link_the_player_names_gives_the_file(tmp_path):
    outside, handout, board = tmp_path / "outside.txt", tmp_path / "handout", tmp_path / "board"
    outside.write_text("not the challenge's")
    (handout / "sub").mkdir(parents=True)
    (handout / "sub" / "real.txt").write_text("real")
    (handout / "sub" / "out").symlink_to(outside)
    named = tmp_path / "named.txt"
    named.symlink_to(handout / "sub" / "real.txt")
    board.mkdir()
    made = addchallenge.create(board, NewChallenge(name="Links", files=(handout, named)))
    copied = made / "handout" / "sub" / "out"
    assert copied.is_symlink() and (made / "handout" / "sub" / "real.txt").read_text() == "real"  # never followed
    assert not (made / "named.txt").is_symlink() and (made / "named.txt").read_text() == "real"
    assert load_challenge(made).challenge.files == ("handout/sub/real.txt", "named.txt")


# ---------------------------------------------------------------------- the addresses


@pytest.mark.parametrize("line", ["http://chal.example.org:1337.", "https://example.org,", "http://exämple.org", "http://a.org:99999",
                                  "nc 10.0.0.256 1337", "http://player@example.org"])
def test_an_address_the_board_could_not_load_is_not_taken_as_one(tmp_path, line):
    """What add writes, the board loads: a line that looks like an address but is not one
    manual.py takes stays description, and the challenge still loads."""
    description, urls = addchallenge.parse(f"Reach it here:\n{line}\n")
    assert urls == () and line in description
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "Odd", "--text", f"Reach it here:\n{line}\n"])
    assert result.exit_code == 0, result.output
    item = load_challenge(tmp_path / "odd")
    assert item.urls == () and line in item.challenge.description
    refused = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "Odd Url", "--url", line])
    assert refused.exit_code == 2 and "--url" in refused.output and not (tmp_path / "odd-url").exists()


def test_an_address_is_kept_in_the_form_the_board_loads_and_create_refuses_any_other(tmp_path):
    assert addchallenge.address("https://Web.Example.org:8443/login?x=1") == "https://web.example.org:8443"
    assert addchallenge.address("`nc Chal.example.org 01337`") == "tcp://chal.example.org:1337"
    assert addchallenge.address("http://chal.example.org:1337/x.") == "http://chal.example.org:1337"
    for url in ["http://chal.example.org:1337.", "https://example.org/path", "tcp://chal.example.org", "ftp://example.org", "HTTP://EXAMPLE.org"]:
        with pytest.raises(AddError, match="not an address the board can hold"):
            addchallenge.create(tmp_path, NewChallenge(name="X", urls=(url,)))
    assert list(tmp_path.iterdir()) == []
    made = addchallenge.create(tmp_path, NewChallenge(name="X", urls=("https://example.org", "tcp://h.example.org:9", "https://example.org")))
    assert load_challenge(made).urls == ("https://example.org", "tcp://h.example.org:9")  # one given twice is kept once


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
    assert "attached capture.pcap (4 B)" in result.output.splitlines()  # every file attached is shown


def test_flightdeck_add_keeps_the_text_as_given_and_attaches_only_what_file_names(tmp_path):
    """The description is the event's text. A path in it that exists on this machine is not
    copied into the handout the lanes read, and is not cut out of the text."""
    secret, handout = tmp_path / "private" / "id_rsa", tmp_path / "given.bin"
    secret.parent.mkdir()
    secret.write_text("the player's own")
    handout.write_bytes(b"x" * 2048)
    text = f"Can you read {secret} through the viewer?\nThe admin keeps his notes in {secret.parent}.\n{secret}\nread from /dev/null at boot."
    board = tmp_path / "board"
    board.mkdir()
    result = CliRunner().invoke(cli.app, ["add", str(board), "--name", "Viewer", "--text", "-"], input=text + "\n")
    assert result.exit_code == 0, result.output
    assert json.loads((board / "viewer" / "challenge.json").read_text())["description"] == text
    assert sorted(entry.name for entry in (board / "viewer").iterdir()) == ["challenge.json"]
    assert "no file attached" in result.output and "id_rsa" not in result.output
    result = CliRunner().invoke(cli.app, ["add", str(board), "--name", "Viewer", "--text", text, "--file", str(handout), "--file", str(handout)])
    assert result.exit_code == 0, result.output
    assert sorted(entry.name for entry in (board / "viewer-2").iterdir()) == ["challenge.json", "given.bin"]
    assert [line for line in result.output.splitlines() if line.startswith("attached")] == ["attached given.bin (2.0 KB)"]


def test_flightdeck_add_refuses_a_file_that_is_not_one_with_the_reason_and_writes_nothing(tmp_path):
    result = CliRunner().invoke(cli.app, ["add", str(tmp_path), "--name", "X", "--file", "/dev/null"])
    assert result.exit_code == 2 and "/dev/null is a device" in result.output and list(tmp_path.iterdir()) == []


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
                box.text = "Read the note.\n"
                await app.on_event(events.Paste(f"{handout}\n"))  # the file dropped on the terminal
                await pilot.pause()
                assert box.text == "Read the note.\n" and app.screen.files == [handout]
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
                for _ in range(200):
                    if app.screen.files:
                        break
                    await pilot.pause(0.01)
                assert app.screen.files == [shot] and app.screen.query_one("#new-text").text == ""
                assert "1 file attached: clip.png" in str(app.screen.query_one("#new-attached").render())
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
            ok, told = await run.add_challenge(NewChallenge(name="Blind", description="typed text", files=(shot,)))
            assert ok and "reading 1 image" in told
            for _ in range(500):
                if "blind" in run.deck.challenges:
                    break
                await asyncio.sleep(0.01)
            assert run.deck.challenges["blind"].description == "typed text"
            assert any("could not read clip.png" in w and "without that image's text" in w for w in warnings)
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_a_path_in_the_middle_of_a_line_stays_in_the_text_quoted_or_escaped_or_bare(tmp_path):
    plain, spaced = tmp_path / "matryoshka.bin", tmp_path / "Screenshot 2026 at 4.38 PM.png"
    plain.write_bytes(b"1")
    spaced.write_bytes(b"2")
    escaped = str(spaced).replace(" ", "\\ ")
    text = f"Open the doll {plain} and look inside. Also see '{spaced}'\nand {escaped}."
    assert addchallenge.parse(text + "\n") == (text, ()) and addchallenge.dropped(text) == []


def test_the_form_says_what_it_found(tmp_path):
    file = tmp_path / "a.bin"
    file.write_bytes(b"x" * 2048)
    assert addchallenge.attached_text((file,), ("tcp://h:1",)) == "1 file attached: a.bin (2.0 KB) · target: tcp://h:1"
    assert addchallenge.attached_text((), ()) == "no file attached"


# ---------------------------------------------------------------------- what is attached, and /attach


def in_console(tmp_path, body, server=None) -> None:
    """Run `body(run, app, pilot)` in the console of a run on an empty by-hand board."""
    async def main():
        with server or FakeModelServer([]) as model:
            run = prepare_run(options(tmp_path, model))
            app = run.app(refresh_seconds=None)
            try:
                async with app.run_test(size=(160, 46)) as pilot:
                    await pilot.pause()
                    await body(run, app, pilot)
            finally:
                await run.shutdown()
                run.close()

    asyncio.run(main())


def busy_lanes() -> FakeModelServer:
    """A model whose lanes stay at work, so one is there to restart."""
    return FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"}))


async def until(pilot, done, tries: int = 500) -> None:
    for _ in range(tries):
        if done():
            return
        await pilot.pause(0.01)
    raise AssertionError("waited too long")


def said(form) -> str:
    return str(form.query_one("#new-problem").render())


def test_the_name_takes_any_character_and_a_file_dropped_while_it_has_the_focus_is_attached(tmp_path):
    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"x" * 10)

    async def body(run, app, pilot):
        await pilot.press(*"/new", "enter")
        await pilot.pause()
        form = app.screen
        shown = lambda: str(form.query_one("#new-attached").render())  # noqa: E731
        assert shown() == "no file attached"
        name = form.query_one("#new-name")
        await pilot.press(*"~home /dev/null /")  # a name may start with ~ or /, and be a path that exists
        await pilot.pause()
        assert name.value == "~home /dev/null /" and form.files == [] and form.query_one("#new-text").text == ""
        assert shown() == "no file attached"
        await app.on_event(events.Paste(f"{handout} "))  # a drop, while the name has the focus
        await pilot.pause()
        assert name.value == "~home /dev/null /" and form.files == [handout]
        assert shown() == "1 file attached: doll.bin (10 B)" and "attached doll.bin" in said(form)
        await pilot.press("ctrl+r")  # and off again
        await pilot.pause()
        assert form.files == [] and shown() == "no file attached" and "removed doll.bin" in said(form)
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_a_description_with_paths_in_it_attaches_nothing_and_reaches_the_board_as_given(tmp_path):
    secret = tmp_path / "private" / "id_rsa"
    secret.parent.mkdir()
    secret.write_text("the player's own")
    pasted = f"Can you read {secret} through the viewer?\nThe admin keeps notes in {secret.parent}. Pop a shell: /dev/null"
    typed = f"\n{secret}"  # typed, on a line of its own: text all the same

    async def body(run, app, pilot):
        await pilot.press(*"/new Viewer", "enter")
        await pilot.pause()
        form = app.screen
        box = form.query_one("#new-text")
        await app.on_event(events.Paste(pasted))  # prose: an ordinary paste, into the box
        await pilot.pause()
        box.text = box.text + typed
        await pilot.pause()
        assert box.text == pasted + typed and form.files == []
        assert str(form.query_one("#new-attached").render()) == "no file attached"
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "viewer" in run.deck.challenges)
        assert run.deck.challenges["viewer"].description == pasted + typed
        assert sorted(entry.name for entry in (run.options.board / "viewer").iterdir()) == ["challenge.json"]
        assert "with NO file" in app._status[0]

    in_console(tmp_path, body)


def test_a_refused_challenge_keeps_the_form_open_with_everything_typed_and_says_why(tmp_path):
    handout, other = tmp_path / "a" / "Dockerfile", tmp_path / "b" / "Dockerfile"
    for file in (handout, other):
        file.parent.mkdir()
        file.write_text("FROM scratch")

    async def body(run, app, pilot):
        await pilot.press(*"/new", "enter")
        await pilot.pause()
        form = app.screen
        name, box = form.query_one("#new-name"), form.query_one("#new-text")
        name.value, box.text = "N" * 121, "Open the doll.\nnc chal.example.org 1337"
        form.query_one("#new-category").value = "rev"
        assert form.add_files([handout]) and not form.add_files([other])  # a second file of that name: said at once
        assert form.files == [handout] and "a file named Dockerfile is already attached" in said(form)

        def kept() -> bool:
            return (app.screen is form and box.text == "Open the doll.\nnc chal.example.org 1337" and form.files == [handout]
                    and form.query_one("#new-category").value == "rev" and list(run.options.board.iterdir()) == [])

        await pilot.press("ctrl+s")
        await until(pilot, lambda: "at most 120 characters" in said(form))
        assert kept() and name.value == "N" * 121
        name.value = "Doll"
        handout.unlink()  # the file went away after it was attached
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "no such file" in said(form))
        assert kept() and not run.deck.challenges
        handout.write_text("FROM scratch")
        await pilot.press("ctrl+s")
        await until(pilot, lambda: "doll" in run.deck.challenges)
        await until(pilot, lambda: app.screen is not form)  # added: now the form closes
        assert "added doll: 1 file, 1 address" in app._status[0] and app._status[1] == "information"

    in_console(tmp_path, body, busy_lanes())


def test_points_that_are_not_ascii_digits_are_refused_not_a_crash(tmp_path):
    async def body(run, app, pilot):
        await pilot.press(*"/new Squared", "enter")
        await pilot.pause()
        form = app.screen
        for points in ["²", "①", "٣", "1e3", "-1"]:  # isdigit() is true of the first three; int() cannot read the first two
            form.query_one("#new-points").value = points
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert "points must be a whole number" in said(form) and app.screen is form
        assert not run.deck.challenges and list(run.options.board.iterdir()) == []
        await pilot.press("escape")

    in_console(tmp_path, body)


def test_the_file_window_does_not_hold_the_keys_up_while_it_is_open(tmp_path, monkeypatch):
    import threading

    from ctf_flightdeck import filepick

    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"inside")
    opened, close, closed = threading.Event(), threading.Event(), threading.Event()

    def choose(**kwargs):  # the window: it stays open until the player closes it
        opened.set()
        close.wait(5)
        closed.set()
        return [handout]

    monkeypatch.setattr(filepick, "choose", choose)

    async def body(run, app, pilot):
        try:
            await pilot.press(*"/new", "enter")
            await pilot.pause()
            form = app.screen
            await pilot.press("ctrl+o")
            await until(pilot, opened.is_set)
            await pilot.press(*"Doll")  # the keys go on working: typed while the window is open
            await pilot.pause()
            assert form.query_one("#new-name").value == "Doll" and not closed.is_set()
            assert "the file window is open" in said(form)
            await pilot.press("ctrl+o")
            await pilot.pause()
            assert "already open" in said(form) and not closed.is_set()
            close.set()
            await until(pilot, lambda: form.files == [handout])
            assert "1 file attached: doll.bin" in str(form.query_one("#new-attached").render())
            opened.clear(), close.clear(), closed.clear()
            await pilot.press("ctrl+o")
            await until(pilot, opened.is_set)
            await pilot.press("escape")  # and esc closes the form with the window still open
            await pilot.pause()
            assert app.screen is not form and not closed.is_set()
        finally:
            close.set()

    in_console(tmp_path, body)


def test_the_clipboard_tool_runs_off_the_ui_thread_and_the_keys_go_on(tmp_path):
    import threading

    shot = tmp_path / "clip.png"
    shot.write_bytes(PNG)
    started, go, threads = threading.Event(), threading.Event(), []

    def paster():  # a clipboard tool that is slow to answer
        threads.append(threading.current_thread())
        started.set()
        go.wait(5)
        return shot

    async def body(run, app, pilot):
        app.paster = paster
        try:
            await pilot.press(*"/new", "enter")
            await pilot.pause()
            form = app.screen
            await pilot.press("ctrl+v")
            await until(pilot, started.is_set)
            await pilot.press(*"Shot")
            await pilot.pause()
            assert len(threads) == 1 and threads[0] is not threading.main_thread()
            assert form.query_one("#new-name").value == "Shot" and "reading the clipboard" in said(form)
            assert form.files == []
            go.set()
            await until(pilot, lambda: form.files == [shot])
            assert "pasted the clipboard's image as clip.png" in said(form)
            await pilot.press("escape")
        finally:
            go.set()

    in_console(tmp_path, body)


def test_new_and_attach_copy_in_a_thread_and_say_so_while_the_console_goes_on(tmp_path, monkeypatch):
    import threading

    handout, more = tmp_path / "doll.bin", tmp_path / "more.bin"
    handout.write_bytes(b"inside")
    more.write_bytes(b"more")
    go, threads = threading.Event(), []

    def slow(copy):  # a copy that takes its time, as a disk image's would
        def copying(*args):
            threads.append(threading.current_thread())
            go.wait(5)
            return copy(*args)
        return copying

    monkeypatch.setattr(addchallenge, "create", slow(addchallenge.create))
    monkeypatch.setattr(addchallenge, "attach", slow(addchallenge.attach))

    async def body(run, app, pilot):
        try:
            await pilot.press(*"/new Doll", "enter")
            await pilot.pause()
            form = app.screen
            form.add_files([handout])
            await pilot.press("ctrl+s")
            await until(pilot, lambda: len(threads) == 1)
            assert app.screen is form and "adding it: copying 1 file..." in said(form)  # open, and saying so
            await pilot.press("ctrl+s")
            await pilot.pause()
            assert "still adding it" in said(form) and len(threads) == 1  # not added twice
            await pilot.press("escape")  # the keys work: the form closes, the copy goes on
            await pilot.pause()
            assert app.screen is not form and "still adding the challenge" in app._status[0]
            assert not run.deck.challenges and threads[0] is not threading.main_thread()
            go.set()
            await until(pilot, lambda: "added doll: 1 file" in app._status[0])
            assert (run.options.board / "doll" / "doll.bin").read_bytes() == b"inside"
            go.clear()
            await pilot.press(*f"/attach doll {more}", "enter")
            await until(pilot, lambda: len(threads) == 2)
            assert app._status[0] == "copying 1 file into doll..." and threads[1] is not threading.main_thread()
            await pilot.press(*"/sort")  # the command bar takes keys meanwhile
            await pilot.pause()
            assert app.screen.query_one("#bar-input").value == "/sort"
            go.set()
            await until(pilot, lambda: "attached more.bin to doll" in app._status[0])
            assert (run.options.board / "doll" / "more.bin").read_bytes() == b"more"
        finally:
            go.set()

    in_console(tmp_path, body, busy_lanes())


def test_a_challenge_added_with_nothing_says_so_and_its_lane_is_told_to_stop_not_wait(tmp_path):
    from fake_model import text_reply

    server = FakeModelServer([text_reply("A sample file is missing.")] * 3)

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            run.release()
            ok, told = await run.add_challenge(NewChallenge(name="Matryoshka", description="Open the doll."))
            assert ok and "with NO file and no target" in told and "/attach matryoshka" in told
            for _ in range(500):
                if server.chats():
                    break
                await asyncio.sleep(0.01)
            brief = server.chats()[0]["json"]["messages"][1]["content"]
            assert "came with no files and no live instance" in brief and "do not wait" in brief
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_attach_puts_a_file_in_the_challenge_and_restarts_its_lane_with_it(tmp_path):
    from fake_model import text_reply

    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"inside")
    server = FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"}))

    async def main():
        with server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await run.add_challenge(NewChallenge(name="Matryoshka", description="Open the doll."))
                for _ in range(500):
                    if run.deck.lanes:
                        break
                    await pilot.pause(0.01)
                (first,) = run.deck.lanes
                await pilot.press(*f"/attach matryoshka {handout}", "enter")
                for _ in range(500):
                    if len(run.deck.lanes) == 2 and "attached" in app._status[0]:
                        break
                    await pilot.pause(0.01)
                assert "attached doll.bin to matryoshka" in app._status[0] and f"{first} restarted" in app._status[0]
                assert (run.options.board / "matryoshka" / "doll.bin").read_bytes() == b"inside"
                second = [lane for lane in run.deck.lanes.values() if lane.id != first][0]
                for _ in range(500):
                    if second.id in run.driver.runs and run.driver.runs[second.id].messages:
                        break
                    await pilot.pause(0.01)
                assert "doll.bin" in run.driver.runs[second.id].messages[1]["content"]
            await run.shutdown()
            run.close()

    asyncio.run(main())


# ---------------------------------------------------------------------- a drop anywhere, and the file window


def test_attach_refuses_two_sources_of_one_name_and_never_copies_over_a_file(tmp_path):
    import os

    folder = tmp_path / "board" / "crab"
    folder.mkdir(parents=True)
    one, two, tree_a, tree_b = tmp_path / "a" / "data.bin", tmp_path / "b" / "data.bin", tmp_path / "a" / "src", tmp_path / "b" / "src"
    for file, text in ((one, "from a"), (two, "from b")):
        file.parent.mkdir()
        file.write_text(text)
    for tree in (tree_a, tree_b):
        tree.mkdir()
        (tree / "main.c").write_text(tree.parent.name)
    for pair in ([one, two], [tree_a, tree_b]):
        with pytest.raises(AddError, match="two files named"):
            addchallenge.attach(folder, pair)
        assert list(folder.iterdir()) == []  # refused before anything was copied
    assert addchallenge.attach(folder, [one, tree_a]) == ["data.bin", "src"]
    with pytest.raises(AddError, match="already has a file of that name"):
        addchallenge.attach(folder, [two])
    assert (folder / "data.bin").read_text() == "from a" and (folder / "src" / "main.c").read_text() == "a"
    piped, good = tmp_path / "piped", tmp_path / "good.txt"
    piped.mkdir()
    good.write_text("good")
    os.mkfifo(piped / "pipe")
    with pytest.raises(AddError, match="named pipe"):
        addchallenge.attach(folder, [good, piped])  # the second fails while it is copied
    assert sorted(entry.name for entry in folder.iterdir()) == ["data.bin", "src"]  # the first went out again: a retry is clean
    with pytest.raises(AddError, match="is a device"):
        addchallenge.attach(folder, [Path("/dev/null")])


def test_attachs_argument_is_a_challenge_then_files_and_a_file_that_is_not_there_is_said(tmp_path):
    one, two = tmp_path / "a b.bin", tmp_path / "c.txt"
    one.write_bytes(b"1")
    two.write_text("2")
    assert addchallenge.attach_arg("") == ("", []) and addchallenge.attach_arg("Crab Walk") == ("Crab Walk", [])
    assert addchallenge.attach_arg(f"Crab Walk '{one}' {two}") == ("Crab Walk", [one, two])
    assert addchallenge.attach_arg(f"{addchallenge.quote(one)} {addchallenge.quote(two)} ") == ("", [one, two])
    assert addchallenge.attach_arg(f"crab {one}") == ("crab", [one])  # one path, its spaces as they are
    with pytest.raises(AddError, match="/no/such/doll.bin: no such file"):
        addchallenge.attach_arg(f"crab {two} /no/such/doll.bin")


def test_attach_to_a_challenge_no_lane_can_start_on_says_so_instead_of_promising_one(tmp_path):
    from ctf_flightdeck.core import interventions as iv

    more, last = tmp_path / "more.bin", tmp_path / "last.bin"
    more.write_bytes(b"more")
    last.write_bytes(b"last")

    async def main():
        with busy_lanes() as server:
            run = prepare_run(options(tmp_path, server))
            run.release()
            await run.add_challenge(NewChallenge(name="Done", description="d"))
            for _ in range(500):
                if run.deck.lanes:
                    break
                await asyncio.sleep(0.01)
            apply = run.deck.apply
            run.deck.apply = lambda what, **kw: iv.Outcome(False, "not now") if isinstance(what, iv.Kill) else apply(what, **kw)
            ok, told = await run.attach_files("done", [more])  # the deck would not restart its lane: said, not "restarted"
            assert ok and told == "attached more.bin to done; its lane was not restarted: not now" and len(run.deck.lanes) == 1
            run.deck.apply = apply
            run.deck.platform_solved("done", "you")  # solved meanwhile: its lane stops, and none may start
            ok, told = await run.attach_files("done", [last])
            await run.shutdown()
            run.close()
            assert ok and (run.options.board / "done" / "last.bin").read_bytes() == b"last"
            assert told.startswith("attached last.bin to done; no lane was started on it: Done is already solved")
            assert "a lane starts" not in told and len(run.deck.lanes) == 1

    asyncio.run(main())


def test_a_pasted_path_never_replaces_what_was_typed_in_the_command_bar(tmp_path, monkeypatch):
    handout, home = tmp_path / "rockyou.txt", tmp_path / "home"
    handout.write_text("words")
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    async def body(run, app, pilot):
        bar = app.screen.query_one("#bar-input")
        await pilot.press(*"/hint L01 look at the header of ")
        await app.on_event(events.Paste(str(handout)))  # an existing path, meant as text
        await pilot.pause()
        assert bar.value == f"/hint L01 look at the header of {handout}"  # an ordinary paste, where the cursor is
        bar.value = "a half-written message"
        app.screen.set_focus(None)  # a drop while the bar holds text and something else has the focus
        await app.on_event(events.Paste(str(handout)))
        await pilot.pause()
        assert bar.value == "a half-written message"
        assert "1 file not taken: the command bar holds what you typed" in app._status[0] and app._status[1] == "warning"
        bar.value = "/attach doll "  # an /attach being written: the file is added to it
        await app.on_event(events.Paste(str(handout)))
        await pilot.pause()
        assert bar.value == f"/attach doll '{handout}' " and bar.has_focus
        bar.value = "/att"  # the start of that very command: nothing is lost by finishing it
        await app.on_event(events.Paste(str(handout)))
        await pilot.pause()
        assert bar.value == f"/attach '{handout}' "
        bar.value = "/hint L01 "
        await app.on_event(events.Paste("~"))  # the home folder is never an attachment: said, and pasted as the text it is
        await pilot.pause()
        assert bar.value == "/hint L01 ~" and "is your home folder itself" in app._status[0]

    in_console(tmp_path, body)


def test_a_drop_in_the_fleet_names_the_challenge_enter_attaches_to(tmp_path):
    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"x")
    calls = []

    async def attacher(cid, files):
        calls.append((cid, files))
        return True, f"attached to {cid}"

    async def body(run, app, pilot):
        await run.add_challenge(NewChallenge(name="Static Hiss", description="d"))
        await until(pilot, lambda: app.fleet.selected_lane in run.deck.lanes)
        app.attacher = attacher
        await app.on_event(events.Paste(f"{handout} "))  # the lanes table has the focus, and a lane is selected
        await pilot.pause()
        bar = app.screen.query_one("#bar-input")
        assert bar.value == f"/attach static-hiss '{handout}' " and bar.has_focus  # the bar says where Enter sends it
        assert "1 file ready: press Enter to attach to static-hiss" in app._status[0]
        await pilot.press("enter")
        await until(pilot, lambda: calls)
        assert calls == [("static-hiss", [handout])]
        await until(pilot, lambda: app._status[0] == "attached to static-hiss")
        app.open_lane(app.fleet.selected_lane)  # the same in a lane's own view
        await pilot.pause()
        await app.on_event(events.Paste(f"{handout} "))
        await pilot.pause()
        assert app.screen.query_one("#bar-input").value == f"/attach static-hiss '{handout}' "

    in_console(tmp_path, body, busy_lanes())


def test_files_dropped_on_the_console_go_to_the_new_form_or_onto_an_attach_whatever_has_the_focus(tmp_path):
    handout = tmp_path / "my doll.bin"
    handout.write_bytes(b"x")
    dropped = str(handout).replace(" ", "\\ ") + " "  # as a terminal pastes a dropped file

    async def main():
        with FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"})) as server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await app.on_event(events.Paste(dropped))  # the fleet: the board has the focus, not the bar
                await pilot.pause()
                bar = app.screen.query_one("#bar-input")
                assert bar.value == f"/attach '{handout}' " and bar.has_focus and "1 file ready" in app._status[0]
                bar.value = ""
                await app.on_event(events.Paste("just some words"))  # not files: an ordinary paste
                await pilot.pause()
                assert bar.value == "just some words"
                bar.value = ""
                await pilot.press(*"/new Doll", "enter")
                await pilot.pause()
                app.screen.query_one("#new-category").focus()  # the focus is not on the box
                await app.on_event(events.Paste(dropped))
                await pilot.pause()
                assert app.screen.files == [handout] and app.screen.query_one("#new-category").value == ""
                assert app.screen.query_one("#new-text").text == ""  # attached, not written into the description
                assert "1 file attached: my doll.bin" in str(app.screen.query_one("#new-attached").render())
                await pilot.press("escape")
            await run.shutdown()
            run.close()

    asyncio.run(main())


def test_ctrl_o_and_a_bare_attach_open_the_file_window_and_take_what_was_chosen(tmp_path, monkeypatch):
    from ctf_flightdeck import filepick

    handout = tmp_path / "doll.bin"
    handout.write_bytes(b"inside")
    asked = []
    monkeypatch.setattr(filepick, "choose", lambda **kw: asked.append(kw) or [handout])

    async def main():
        with FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "sleep 0.2"})) as server:
            run = prepare_run(options(tmp_path, server))
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                await pilot.press(*"/new Doll", "enter")
                await pilot.pause()
                await pilot.press("ctrl+o")
                for _ in range(200):
                    if app.screen.files:
                        break
                    await pilot.pause(0.01)
                assert app.screen.files == [handout] and app.screen.query_one("#new-text").text == ""
                assert "1 file attached: doll.bin" in str(app.screen.query_one("#new-attached").render())
                await pilot.press("escape")
                await run.add_challenge(NewChallenge(name="Bare", description="d"))
                await pilot.pause()
                await pilot.press(*"/attach bare", "enter")
                for _ in range(300):
                    if (run.options.board / "bare" / "doll.bin").exists():
                        break
                    await pilot.pause(0.01)
                assert (run.options.board / "bare" / "doll.bin").read_bytes() == b"inside" and len(asked) == 2
            await run.shutdown()
            run.close()

    asyncio.run(main())


@pytest.mark.parametrize(("platform", "tools", "code", "out", "expected"), [
    ("darwin", {"osascript"}, 0, "{a}\n{b}\n", 2),
    ("darwin", {"osascript"}, 1, "", 0),  # cancelled
    ("linux", {"zenity"}, 0, "{a}\n/no/such/file\n", 1),
])
def test_the_file_window_returns_the_files_chosen_that_exist(tmp_path, platform, tools, code, out, expected):
    from types import SimpleNamespace

    from ctf_flightdeck import filepick

    a, b = tmp_path / "a.bin", tmp_path / "b c.txt"
    a.write_bytes(b"1")
    b.write_text("2")
    run = lambda argv, **kw: SimpleNamespace(returncode=code, stdout=out.format(a=a, b=b))  # noqa: E731
    chosen = filepick.choose(platform=platform, which=lambda t: t if t in tools else None, run=run)
    assert len(chosen) == expected and all(path.exists() for path in chosen)


def test_no_file_window_on_this_machine_is_said():
    from ctf_flightdeck import filepick

    with pytest.raises(filepick.PickError, match="paste the file's full path"):
        filepick.choose(platform="linux", which=lambda t: None)
