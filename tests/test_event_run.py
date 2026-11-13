"""`flightdeck play` on an event: the event profile's policies (pre-flight), a CTFd board
(pulled before the start, new waves, flags submitted through CTFd, solves followed) and the
team channel, wired into a real run.

The CTFd is tests/fake_ctfd.py and the model tests/fake_model.py, both on 127.0.0.1: nothing
real is contacted, and nothing is mocked in between. Lanes run on host workspaces in
tmp_path; their fake model lists files, or submits the flags a test scripts for its
challenge. The CTFd token is synthetic (fake_ctfd.TOKEN), and is checked never to show.
pytest has no async plugin here: each run plays on a fresh loop with asyncio.run().
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import threading
import time
from collections import deque
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck.console.screens import QuitPrompt
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.model import ChallengeStatus, DeckConfig, EventKind, LaneState, PendingKind
from ctf_flightdeck.platform.ctfd import CTFdVerifier
from ctf_flightdeck.platform.manual import cannot_check
from ctf_flightdeck.run import YOU, YOU_OR_YOUR_TEAM, YOUR_TEAM, RunError, RunOptions, prepare_run, variant_tries_note
from ctf_flightdeck.team import TeamChannel, init_folder

from fake_ctfd import FLAG_FORMAT, TOKEN, FakeChallenge, FakeCTFd, Reply, sample
from fake_model import FakeModelServer, tool_call_reply

TOKEN_VAR = "FLIGHTDECK_TEST_CTFD_TOKEN"
BOARD_FORMAT = r"t\{[a-z0-9_]+\}"


# ---------------------------------------------------------------------- setting up


def three() -> list[FakeChallenge]:
    """Three of the fake CTFd's invented challenges, none with a web instance a lane could reach."""
    warmup, rsa, _web, echo = sample()
    return [warmup, rsa, echo]


def folder_board(tmp_path: Path, names: tuple[str, ...] = ("note",), *, urls: tuple[str, ...] = ()) -> Path:
    """A folder board: a challenge per name (50 points, then 60, ...) whose note.txt holds its
    flag t{<name>}, and an answers file with their hashes."""
    root = tmp_path / "board"
    answers = {}
    for n, name in enumerate(names):
        folder = root / name
        folder.mkdir(parents=True)
        flag = f"t{{{name}}}"
        (folder / "note.txt").write_text(f"the flag is {flag}\n")
        spec = {"name": name.title(), "category": "misc", "points": 50 + 10 * n, "solves": 9, "description": "Read the note."}
        if urls:
            spec["urls"] = list(urls)
        (folder / "challenge.json").write_text(json.dumps(spec))
        answers[name] = hashlib.sha256(flag.encode()).hexdigest()
    (root / "board.json").write_text(json.dumps({"event": "Board Event", "flag_format": BOARD_FORMAT}))
    (root / "answers.sha256.json").write_text(json.dumps(answers))
    return root


LADDER = ("fake/small", "fake/big")
IDLE_API: list[str] = []  # the base URL of the module's idle model API (model_api below)


@pytest.fixture(scope="module", autouse=True)
def model_api():
    """A model API that serves the configs' ladder, for the runs whose lanes never call a model:
    a run asks the API for its models before anything starts."""
    with FakeModelServer(models=LADDER, responder=lambda record: tool_call_reply("shell", {"command": "ls"})) as server:
        IDLE_API.append(server.base_url)
        yield server
        IDLE_API.clear()


def config(where: Path, base_url: str | None = None, *, max_lanes: int = 4) -> Path:
    """A config for lanes on this machine, priced models (no note about prices) and no key;
    its API is the module's idle one unless `base_url` names another."""
    base_url = base_url or IDLE_API[-1]
    where.mkdir(parents=True, exist_ok=True)
    path = where / "config.toml"
    path.write_text(
        f'[api]\nbase_url = "{base_url}"\nkey_env = ""\n'
        '[models]\nladder = ["fake/small", "fake/big"]\n'
        '[prices."fake/small"]\ninput = 1.0\noutput = 2.0\n'
        '[prices."fake/big"]\ninput = 2.0\noutput = 4.0\n'
        f'[lanes]\nmax_lanes = {max_lanes}\nruntime = "host"\n'
        f'[run]\ndir = "{where / "runs"}"\n'
    )
    return path


def event(
    tmp_path: Path,
    *,
    platform: str = "ctfd",
    url: str = "",
    board: Path | None = None,
    team: bool = False,
    flag_format: str | None = FLAG_FORMAT,
    ai: bool = True,
    automation: bool = True,
    live: str = "allowed",
    max_lanes: int | None = None,
    name: str = "event.toml",
    **policies: str,
) -> Path:
    """An event profile; keyword arguments left over are its [policies]."""
    lines = ["[event]", 'name = "Fake CTF"', f'platform = "{platform}"']
    if platform == "ctfd":
        lines += [f'url = "{url}"', f'token_env = "{TOKEN_VAR}"']
    if board is not None:
        lines.append(f"board = '{board}'")
    if flag_format is not None:
        lines.append(f"flag_format = '{flag_format}'")
    lines.append(f"team = {str(team).lower()}")
    lines += [
        "[rules]",
        f"ai_allowed = {str(ai).lower()}",
        f"platform_automation = {str(automation).lower()}",
        f'live_targets = "{live}"',
    ]
    if max_lanes is not None:
        lines.append(f"max_lanes = {max_lanes}")
    if policies:
        lines.append("[policies]")
        lines += [f'{stage} = "{policy}"' for stage, policy in policies.items()]
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n")
    return path


def submit(flag: str) -> dict:
    return tool_call_reply("submit_flag", {"flag": flag})


class Model:
    """The fake model's responder: each lane gets the replies scripted for its challenge
    (named in its brief), in order, then lists files, a little slowly."""

    def __init__(self, scripts: dict[str, list[dict]] | None = None) -> None:
        self.scripts = {name: deque(replies) for name, replies in (scripts or {}).items()}
        self.lock = threading.Lock()

    def __call__(self, record: dict) -> dict:
        brief = record["json"]["messages"][1]["content"]
        name = re.search(r"^Challenge: (.+?) \(", brief, re.MULTILINE).group(1)
        with self.lock:
            queue = self.scripts.get(name)
            if queue:
                return queue.popleft()
        time.sleep(0.02)
        return tool_call_reply("shell", {"command": "ls"})


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, TOKEN)


async def wait_for(cond, what: str, seconds: float = 20.0) -> None:
    for _ in range(int(seconds * 100)):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(f"timed out waiting for {what}")


def play(run, body) -> None:
    """Release the run on a fresh loop, as the console does, await `body(run)`, then shut the
    run down and close it."""

    async def main():
        run.release()
        try:
            await body(run)
        finally:
            await run.shutdown()

    try:
        asyncio.run(main())
    finally:
        run.close()


def log(run) -> list[dict]:
    return [json.loads(line) for line in run.log.path.read_text().splitlines()]


def ctfd_warnings(run) -> list[dict]:
    return [e for e in log(run) if e["kind"] == "warning" and e["data"].get("source") == "ctfd"]


# ---------------------------------------------------------------------- the event profile's policies


def test_agents_off_by_the_rules_refuses_the_run_and_says_to_play_by_hand(tmp_path):
    root = folder_board(tmp_path)
    with pytest.raises(RunError) as caught:
        prepare_run(RunOptions(event=event(tmp_path, platform="manual", board=root, ai=False), config=config(tmp_path)))
    said = str(caught.value)
    assert "the event's rules do not allow AI help (rules.ai_allowed = false), so agents are off" in said
    assert "Play by hand; `flightdeck l1 run` runs your no-model solvers" in said
    with pytest.raises(RunError, match='the event profile sets agents = "manual": .*Play by hand'):
        prepare_run(RunOptions(event=event(tmp_path, platform="manual", board=root, agents="manual"), config=config(tmp_path)))
    assert not (tmp_path / "runs").exists()


def test_a_refusal_from_the_profile_check_stops_the_run_in_preflights_words(tmp_path, token):
    cfg = config(tmp_path)
    with FakeCTFd(three()) as fake:
        profile = event(tmp_path, url=fake.base_url, live="off", max_lanes=1)  # lanes on this machine, 3 at once
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=tmp_path / "board", event=profile, config=cfg, max_lanes=3))
        assert fake.requests == []
    checked = CliRunner().invoke(cli.app, ["preflight", str(profile), "--config", str(cfg), "--host", "--max-lanes", "3"])
    refusals = [line for line in checked.output.splitlines() if line.startswith("refuse: ")]
    head, *lines = str(caught.value).splitlines()
    assert len(refusals) == 2 and lines == refusals
    assert head.startswith("the event profile refuses this run (2 refusals; `flightdeck preflight ")
    assert not (tmp_path / "board").exists() and not (tmp_path / "runs").exists()


def test_submit_manual_never_hands_a_flag_to_the_board_even_one_with_answers(tmp_path):
    root = folder_board(tmp_path)
    profile = event(tmp_path, platform="manual", board=root, flag_format=None, submit="manual")
    with FakeModelServer(responder=Model({"Note": [submit("t{note}")]})) as server:
        run = prepare_run(RunOptions(event=profile, config=config(tmp_path, server.base_url)))
        assert run.deck.verify is cannot_check and run.deck.config.submit == "auto"
        assert run.deck.config.flag_format == BOARD_FORMAT  # the profile sets none: the board's

        async def body(run):
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: lane.pending is not None, "the flag")
            # the handout's note.txt holds t{note}, so the lane's flag waits for the player first
            assert lane.pending.kind is PendingKind.SUBMIT and lane.pending.flag == "t{note}"
            assert run.deck.apply(iv.Approve(lane.id)).ok
            assert lane.pending.kind is PendingKind.CONFIRM and lane.pending.flag == "t{note}"  # you submit it

        play(run, body)
    assert [e for e in log(run) if e["kind"] == "submit"] == []
    notes = run.notes()
    assert any(n.startswith('submit is "manual" in the event profile: flightdeck never submits a flag') for n in notes)
    assert any(n.startswith("event profile: event.flag_format is not set") for n in notes)  # check()'s warning


@pytest.mark.parametrize(
    "live, policies, expected",
    [
        ("allowed", {}, "auto"),
        ("confirm", {}, "confirm"),
        ("allowed", {"instance": "confirm"}, "confirm"),
        ("allowed", {"instance": "manual"}, "off"),  # the player works the instance, not a lane
        ("allowed", {"instance": "off"}, "off"),
    ],
)
def test_the_instance_policy_is_the_runs(tmp_path, live, policies, expected):
    root = folder_board(tmp_path, urls=("http://127.0.0.1:9",))
    run = prepare_run(RunOptions(event=event(tmp_path, platform="manual", board=root, live=live, **policies), config=config(tmp_path)))
    run.close()
    assert run.options.instance == expected and run.driver.instance == expected


def test_under_instance_confirm_a_lane_asks_before_its_first_model_call(tmp_path):
    root = folder_board(tmp_path, urls=("http://127.0.0.1:9",))
    with FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(event=event(tmp_path, platform="manual", board=root, live="confirm"), config=config(tmp_path, server.base_url)))

        async def body(run):
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: lane.pending is not None, "the live-box question")
            assert lane.pending.kind is PendingKind.LIVE_BOX and server.chats() == []

        play(run, body)


def test_the_profiles_name_board_flag_format_and_lane_limit_apply(tmp_path):
    root = folder_board(tmp_path)
    profile = event(tmp_path, platform="manual", board=root, flag_format=r"x\{\w+\}", max_lanes=1)
    run = prepare_run(RunOptions(event=profile, config=config(tmp_path, max_lanes=4)))  # no BOARD: the profile's
    run.close()
    assert run.board.event == "Board Event" and [b.challenge.id for b in run.board.challenges] == ["note"]
    cfg = run.deck.config
    assert (cfg.event, cfg.flag_format, cfg.max_lanes) == ("Fake CTF", r"x\{\w+\}", 1)
    assert "1 lane at a time, the most the event's rules allow (rules.max_lanes; your config says 4)" in run.notes()
    with pytest.raises(RunError, match="3 lanes at once is more than the rules allow"):
        prepare_run(RunOptions(event=profile, config=config(tmp_path), max_lanes=3))


def test_the_notes_say_the_flag_format_is_the_event_profiles(tmp_path):
    root = folder_board(tmp_path)
    profile = event(tmp_path, platform="manual", board=root, flag_format=r"x\{\w+\}")
    run = prepare_run(RunOptions(event=profile, config=config(tmp_path)))
    run.close()
    assert "flag format: " + r"x\{\w+\}" + f", from the event profile {profile} (event.flag_format)" in run.notes()


def test_l1_off_leaves_the_pack_out_and_confirm_runs_it_saying_play_is_the_yes(tmp_path):
    from l1_kit import python_engine

    pack = tmp_path / "pack"
    python_engine(pack, "reader", "def solve(challenge_dir):\n    return None\n", route='keywords = ["note"]')
    root = folder_board(tmp_path)
    off = prepare_run(RunOptions(event=event(tmp_path, platform="manual", board=root, l1="off"), config=config(tmp_path), pack=pack))
    off.close()
    assert off.driver.l1 is None and off.options.pack is None
    assert 'l1 is "off" in the event profile, so your L1 pack does not run in lanes: nothing runs it' in off.notes()
    sure = prepare_run(RunOptions(event=event(tmp_path, platform="manual", board=root, l1="confirm", agents="confirm"),
                                  config=config(tmp_path), pack=pack))
    sure.close()
    assert sure.driver.l1 is not None
    notes = sure.notes()
    assert any(n.startswith('l1 is "confirm" in the event profile: starting play is your yes') for n in notes)
    assert any(n.startswith('agents is "confirm" in the event profile: starting play is your yes') for n in notes)


def test_submit_may_be_made_stricter_than_the_profile_never_looser(tmp_path):
    root = folder_board(tmp_path)
    confirm = event(tmp_path, platform="manual", board=root)  # submit: confirm, the default
    with pytest.raises(RunError, match='--submit auto is looser than the event profile\'s submit policy "confirm"'):
        prepare_run(RunOptions(event=confirm, config=config(tmp_path), submit="auto"))
    auto = event(tmp_path, platform="manual", board=root, submit="auto", name="auto.toml")
    run = prepare_run(RunOptions(event=auto, config=config(tmp_path), submit="confirm"))
    run.close()
    assert run.deck.config.submit == "confirm" and run.options.submit == "confirm"


def test_a_board_named_to_play_wins_over_the_profiles_and_a_note_says_so(tmp_path):
    root = folder_board(tmp_path)
    other = folder_board(tmp_path / "elsewhere")
    run = prepare_run(RunOptions(board=other, event=event(tmp_path, platform="manual", board=root), config=config(tmp_path)))
    run.close()
    assert run.board.challenges[0].handout == (other / "note").resolve()
    assert f"board: {other}, as you asked (the event profile names {root})" in run.notes()


@pytest.mark.parametrize(
    "case, expected",
    [
        ("solo and team folder", "--solo and --team-dir do not go together"),
        ("handle alone", "--handle is your name in the team folder: give the folder with --team-dir FOLDER too"),
        ("ctfd without a folder", "a CTFd event needs the folder its board is pulled into: `flightdeck play FOLDER --event"),
        ("ctfd with answers", "a CTFd event checks them on CTFd: drop --answers"),
        ("no board", "name the board: `flightdeck play BOARD`"),
        ("a wave every 0 s", "wave_seconds must be a positive number of seconds, not 0"),
    ],
)
def test_options_that_cannot_work_are_refused_with_what_to_do(tmp_path, token, case, expected):
    root = folder_board(tmp_path)
    shared = init_folder(tmp_path / "team")
    ctfd = event(tmp_path, url="http://127.0.0.1:9", name="ctfd.toml")
    options = {
        "solo and team folder": RunOptions(board=root, team=False, team_dir=shared),
        "handle alone": RunOptions(board=root, handle="alpha"),
        "ctfd without a folder": RunOptions(event=ctfd),
        "ctfd with answers": RunOptions(board=tmp_path / "pulled", event=ctfd, answers=root / "answers.sha256.json"),
        "no board": RunOptions(),
        "a wave every 0 s": RunOptions(board=root, wave_seconds=0),
    }[case]
    with pytest.raises(RunError) as caught:
        prepare_run(replace(options, config=config(tmp_path)))
    assert expected in str(caught.value)
    assert not (tmp_path / "runs").exists()


# ---------------------------------------------------------------------- a CTFd board


def test_a_ctfd_event_pulls_the_board_before_anything_starts(tmp_path, token):
    folder = tmp_path / "board"
    with FakeCTFd(three()) as fake:
        run = prepare_run(RunOptions(board=folder, event=event(tmp_path, url=fake.base_url), config=config(tmp_path)))
        run.close()
        routes = [r.route for r in fake.requests]
    assert {b.challenge.id for b in run.board.challenges} == {"warmup", "baby-rsa", "echo-service"}
    assert (folder / "warmup" / "hello.txt").read_text() == "hello\n"
    # the solves, read once pulled: the team's, and which are this user's own
    assert routes[0] == "/api/v1/challenges" and routes[-2:] == ["/api/v1/teams/me/solves", "/api/v1/users/me/solves"]
    assert isinstance(run.verifier, CTFdVerifier)  # the flags test below shows the deck submits through it
    assert run.verifier.ids == {"warmup": 1, "baby-rsa": 2, "echo-service": 4} == run.ctfd.ids
    assert (run.deck.config.event, run.deck.config.flag_format) == ("Fake CTF", FLAG_FORMAT)
    assert run.deck.challenges == {} and run.ctfd.waves  # the board goes on the deck once the console runs
    assert f"board: 3 challenges from CTFd at {fake.base_url} in {folder} (3 new)" in run.notes()


def test_a_coding_agent_lane_on_a_ctfd_event_shows_the_token_by_its_name(tmp_path, token, monkeypatch):
    """The CTFd token is a secret the run holds: a lane that learned it (here the fake CLI
    echoes it) shows it as [NAME] in the run's events and transcripts (agent/external.py)."""
    from test_external import Fake

    agent = Fake(tmp_path, {"turns": [{"calls": [{"tools": [{"bash": f"echo token {TOKEN}"}]}]}]})
    path = [d for d in os.environ.get("PATH", "").split(os.pathsep)
            if d and not any(os.access(os.path.join(d, cli), os.X_OK) for cli in ("claude", "codex"))]
    monkeypatch.setenv("PATH", os.pathsep.join([str(agent.bin), *path]))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-anthropic-credential-for-tests")
    try:
        with FakeCTFd(three()) as fake:
            run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url),
                                         config=config(tmp_path, max_lanes=1), agent="claude", runtime="host"))

            async def body(run):
                (lane,) = run.deck.lanes.values()
                await wait_for(lambda: any(a.output.startswith("token ") for a in lane.actions), "the step")

            play(run, body)
    finally:
        agent.kill_leftovers()
    (lane,) = run.deck.lanes.values()
    assert [a.output for a in lane.actions if a.output.startswith("token ")] == [f"token [{TOKEN_VAR}]"]
    for kept in (run.log.path, *(run.dir / "lanes").iterdir()):
        assert TOKEN not in kept.read_text(), kept.name


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, f"the CTFd token variable {TOKEN_VAR} (event.token_env) is not set or is empty: put FLIGHTDECK_TEST_CTFD_TOKEN=<token> in your keys file or export it"),
        ("  ", f"the CTFd token variable {TOKEN_VAR} (event.token_env) is not set or is empty: put FLIGHTDECK_TEST_CTFD_TOKEN=<token> in your keys file or export it"),
        (f"Token {TOKEN}", "holds characters an HTTP header cannot carry (spaces, line breaks, non-ASCII); check the "
                           f"variable it came from ({TOKEN_VAR}, the variable event.token_env names)"),
    ],
)
def test_a_ctfd_event_without_a_usable_token_stops_before_any_request(tmp_path, monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv(TOKEN_VAR, raising=False)
    else:
        monkeypatch.setenv(TOKEN_VAR, value)  # the last: pasted with its "Token " scheme
    with FakeCTFd(three()) as fake:
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url), config=config(tmp_path)))
        assert fake.requests == []
    assert expected in str(caught.value) and TOKEN not in str(caught.value)
    assert not (tmp_path / "board").exists() and not (tmp_path / "runs").exists()


def test_a_ctfd_run_can_be_prepared_on_a_loop_that_is_already_running(tmp_path, token):
    with FakeCTFd(three()) as fake:
        async def main():
            return prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url), config=config(tmp_path)))

        run = asyncio.run(main())
        run.close()
    assert {b.challenge.id for b in run.board.challenges} == {"warmup", "baby-rsa", "echo-service"}


def test_pull_confirm_asks_first_and_no_pulls_nothing(tmp_path, token):
    folder = tmp_path / "board"
    asked: list[str] = []

    def answer(yes: bool):
        def confirm(question: str) -> bool:
            asked.append(question)
            return yes

        return confirm

    with FakeCTFd(three()) as fake:
        options = RunOptions(board=folder, event=event(tmp_path, url=fake.base_url, pull="confirm"), config=config(tmp_path))
        with pytest.raises(RunError, match="you said no to the pull, so nothing was pulled and the run did not start"):
            prepare_run(replace(options, confirm=answer(False)))
        with pytest.raises(RunError, match="cannot ask here \\(not at a terminal, or a headless run\\): start play at a terminal without --headless"):
            prepare_run(options)  # nobody to ask
        assert fake.requests == [] and not folder.exists()
        run = prepare_run(replace(options, confirm=answer(True)))
        run.close()
    assert asked == [f"Pull the board from {fake.base_url} into {folder}?"] * 2
    assert len(run.board.challenges) == 3 and not run.ctfd.waves
    assert any(n.startswith('pull is "confirm" in the event profile: flightdeck pulled the board once') for n in run.notes())


def test_a_new_wave_on_ctfd_is_pulled_and_released_on_the_deck(tmp_path, token):
    folder = tmp_path / "board"
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=folder, event=event(tmp_path, url=fake.base_url),
                                     config=config(tmp_path, server.base_url, max_lanes=5), wave_seconds=0.05))

        async def body(run):
            await wait_for(lambda: len(fake.to("/api/v1/challenges")) >= 3, "two waves with nothing new")
            assert set(run.deck.challenges) == {"warmup", "baby-rsa", "echo-service"}
            fake.add(FakeChallenge(5, "Second Wave", category="Forensics", value=150, files={"disk.img": b"\0" * 64}))
            await wait_for(lambda: "second-wave" in run.deck.challenges, "the second wave")
            (lane,) = run.deck.lanes_on("second-wave")
            workspace = run.driver.runs[lane.id].workspace
            assert workspace.handout == (folder / "second-wave").resolve()
            await wait_for(lambda: (workspace.root / "disk.img").is_file(), "the wave's file in its lane")

        play(run, body)
    releases = [(e["data"]["label"], e["data"]["challenges"]) for e in log(run) if e["kind"] == "release"]
    assert releases == [("Board", ["baby-rsa", "echo-service", "warmup"]), ("Wave 2", ["second-wave"])]
    assert run.verifier.ids["second-wave"] == 5 and run.driver.files["second-wave"] == ("disk.img",)
    assert ctfd_warnings(run) == []


def test_a_challenge_the_first_pull_left_out_is_a_note_and_a_later_wave_pulls_it(tmp_path, token):
    far = FakeChallenge(5, "Far Away", file_urls=["https://cdn.example.org/files/far.zip"])  # refused before any request
    locked = FakeChallenge(6, "Locked", type="hidden")
    with FakeCTFd(three() + [far, locked]) as fake, FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url),
                                     config=config(tmp_path, server.base_url, max_lanes=1), wave_seconds=0.05))
        notes = run.notes()

        async def body(run):
            await wait_for(lambda: len(fake.to("/api/v1/challenges")) >= 4, "waves that leave it out again")
            fake.challenges[5].file_urls = None
            fake.challenges[5].files = {"far.zip": b"PK fake"}
            await wait_for(lambda: "far-away" in run.deck.challenges, "the wave that pulls it")

        play(run, body)
    (left_out,) = [n for n in notes if n.startswith("not pulled: ")]
    assert left_out.startswith('not pulled: challenge 5 ("Far Away"): ') and left_out.endswith("; the next wave tries it again")
    assert "1 challenge is locked on CTFd until a prerequisite is solved; a later wave pulls them once they unlock" in notes
    assert ctfd_warnings(run) == []  # the same problem again is not news
    releases = [(e["data"]["label"], e["data"]["challenges"]) for e in log(run) if e["kind"] == "release"]
    assert releases[1:] == [("Wave 2", ["far-away"])]


def test_flags_go_to_ctfd_through_the_verifier_a_wrong_one_then_the_right_one(tmp_path, token):
    model = Model({"Warmup": [submit("test{nope}"), submit("test{hello}")]})
    with FakeCTFd(three()) as fake, FakeModelServer(responder=model) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url),
                                     config=config(tmp_path, server.base_url, max_lanes=1)))

        async def body(run):
            (lane,) = run.deck.lanes.values()
            assert lane.challenge_id == "warmup"
            for flag in ("test{nope}", "test{hello}"):
                await wait_for(lambda: lane.pending is not None and lane.pending.flag == flag, f"{flag} to approve")
                assert lane.pending.kind is PendingKind.SUBMIT  # submit confirm: the player approves first
                assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.state is LaneState.SOLVED, "CTFd's answer to the right flag")

        play(run, body)
        sent = [r.json for r in fake.to("/api/v1/challenges/attempt")]
    assert sent == [{"challenge_id": 1, "submission": "test{nope}"}, {"challenge_id": 1, "submission": "test{hello}"}]
    assert fake.solved == {1}
    submits = [(e["data"]["flag"], e["data"]["correct"], e["data"]["by"]) for e in log(run) if e["kind"] == "submit"]
    assert submits == [("test{nope}", False, "platform"), ("test{hello}", True, "platform")]


def test_a_flag_ctfd_does_not_judge_says_why_and_waits_for_the_player(tmp_path, token):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url),
                                     config=config(tmp_path, server.base_url, max_lanes=1)))
        fake.paused = True

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the flag")
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.pending is not None, "CTFd's answer")
            assert lane.pending.kind is PendingKind.CONFIRM and lane.pending.flag == "test{hello}"  # you submit it

        play(run, body)
    (warning,) = ctfd_warnings(run)
    assert warning["challenge"] == "warmup" and warning["text"] == (
        "CTFd did not judge test{hello} for Warmup: CTFd is paused, so it did not check the flag (CTFd says: Fake CTF "
        "is paused). Submit it by hand when CTFd runs again"
    )


def platform_solves(run) -> list[tuple[str, str, bool]]:
    """(challenge, who, before_run) of each solve the platform listed, in the run log."""
    return [(e["challenge"], e["data"]["who"], e["data"]["before_run"]) for e in log(run)
            if e["kind"] == "teammate" and e["data"].get("source") == "platform"]


@pytest.mark.parametrize("team", [True, False])
def test_already_solved_from_ctfd_closes_the_challenge_at_once_in_solo_and_team_mode(tmp_path, token, team):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{maybe}")]})) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url), team=team,
                                     config=config(tmp_path, server.base_url, max_lanes=1),
                                     solves_seconds=3600))  # no poll in this test: only CTFd's answer to the flag tells

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the flag")
            fake.solved.add(1)  # Warmup was solved on the website meanwhile
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.finished, "the lane to stop")

        play(run, body)
    assert [r.json for r in fake.to("/api/v1/challenges/attempt")] == [{"challenge_id": 1, "submission": "test{maybe}"}]
    warmup = run.deck.challenges["warmup"]
    assert warmup.status is ChallengeStatus.TEAMMATE and warmup.solved_by == YOU_OR_YOUR_TEAM  # "already solved" says not by whom
    assert run.deck.lanes["L01"].state is LaneState.STOPPED and ctfd_warnings(run) == []
    assert platform_solves(run) == [("warmup", YOU_OR_YOUR_TEAM, False)]


def test_a_solve_on_ctfd_stops_our_lane_on_it_in_team_mode(tmp_path, token):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url), team=True,
                                     config=config(tmp_path, server.base_url, max_lanes=1), solves_seconds=0.05))

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.turns > 0, "the lane at work")
            fake.user_solved = set()
            fake.solved.add(1)  # a teammate solved Warmup on the website
            await wait_for(lambda: lane.finished, "the lane to stop")

        play(run, body)
    warmup = run.deck.challenges["warmup"]
    assert run.deck.lanes["L01"].state is LaneState.STOPPED
    assert warmup.status is ChallengeStatus.TEAMMATE and warmup.solved_by == YOUR_TEAM
    assert [e["text"] for e in log(run) if e["kind"] == "teammate"] == [
        f"the platform lists Warmup as solved ({YOUR_TEAM}) · stopped L01"
    ]
    assert platform_solves(run) == [("warmup", YOUR_TEAM, False)]
    assert run.deck.lanes["L02"].challenge_id == "baby-rsa"  # the slot went to the next challenge
    assert any(n.startswith("team mode with no team folder: your claims stay on your flightdeck, and CTFd's solves") for n in run.notes())


def test_a_flag_the_player_is_submitting_by_hand_is_not_taken_for_a_teammates_solve(tmp_path, token):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url, submit="manual"),
                                     team=True, config=config(tmp_path, server.base_url, max_lanes=1), solves_seconds=0.05))

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the flag")
            assert lane.pending.kind is PendingKind.CONFIRM  # submit manual: the player submits it on CTFd
            fake.solved.add(1)  # ... and CTFd took it
            polls = len(fake.to("/api/v1/teams/me/solves"))
            await wait_for(lambda: len(fake.to("/api/v1/teams/me/solves")) >= polls + 3, "polls that see it solved")
            assert not lane.finished
            assert run.deck.apply(iv.Approve(lane.id)).ok  # "it was accepted"
            assert lane.state is LaneState.SOLVED

        play(run, body)
    assert run.deck.challenges["warmup"].solved_by == "L01" and fake.to("/api/v1/challenges/attempt") == []


def test_in_solo_mode_a_solve_on_ctfd_stops_the_lane_too_and_in_users_mode_it_is_yours(tmp_path, token):
    with FakeCTFd(three(), team_mode=False) as fake, FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url),
                                     config=config(tmp_path, server.base_url, max_lanes=1), solves_seconds=0.05))

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.turns > 0, "the lane at work")
            fake.solved.add(1)  # the player solved Warmup by hand on the website
            await wait_for(lambda: lane.finished, "the lane to stop")

        play(run, body)
    warmup = run.deck.challenges["warmup"]
    assert run.deck.lanes["L01"].state is LaneState.STOPPED and not run.deck.config.team
    assert warmup.status is ChallengeStatus.TEAMMATE and warmup.solved_by == YOU
    assert platform_solves(run) == [("warmup", YOU, False)] and ctfd_warnings(run) == []


@pytest.mark.parametrize("team", [False, True])
def test_challenges_already_solved_on_ctfd_get_no_lane_and_are_credited_as_ctfd_says(tmp_path, token, team):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model()) as server:
        fake.solved, fake.user_solved = {1, 2}, {1}  # before the run: Warmup by this user, Baby RSA by a teammate
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url), team=team,
                                     config=config(tmp_path, server.base_url, max_lanes=3)))

        async def body(run):
            assert [lane.challenge_id for lane in run.deck.lanes.values()] == ["echo-service"]

        play(run, body)
    status = {cid: ch.status for cid, ch in run.deck.challenges.items()}
    assert status == {"baby-rsa": ChallengeStatus.TEAMMATE, "echo-service": ChallengeStatus.RUNNING, "warmup": ChallengeStatus.TEAMMATE}
    assert {cid: run.deck.challenges[cid].solved_by for cid in ("warmup", "baby-rsa")} == {"warmup": YOU, "baby-rsa": YOUR_TEAM}
    assert sorted(platform_solves(run)) == [("baby-rsa", YOUR_TEAM, True), ("warmup", YOU, True)]
    assert ctfd_warnings(run) == []


def test_a_failed_poll_is_one_warning_while_it_lasts_and_the_run_goes_on(tmp_path, token):
    broken = Reply(400, {"message": "the database is broken"})
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url), team=True,
                                     config=config(tmp_path, server.base_url, max_lanes=1),
                                     wave_seconds=0.05, solves_seconds=0.05))
        fake.script("GET", "/api/v1/challenges", *[broken] * 3)
        fake.script("GET", "/api/v1/teams/me/solves", *[broken] * 3)

        async def body(run):
            # one request each before the run, three broken ones, then answers again
            await wait_for(lambda: len(fake.to("/api/v1/challenges")) >= 6 and len(fake.to("/api/v1/teams/me/solves")) >= 6,
                           "the polls to fail and recover")
            fake.user_solved = set()
            fake.solved.add(1)  # a teammate's solve
            await wait_for(lambda: run.deck.challenges["warmup"].closed, "a solve after the failures")

        play(run, body)
    texts = sorted(w["text"] for w in ctfd_warnings(run))  # the two tasks fail in either order
    assert texts == [
        f"could not pull new challenges from CTFd: CTFd at {fake.base_url} answered HTTP 400 (Bad Request) at "
        "GET /api/v1/challenges (CTFd says: the database is broken); flightdeck tries again in 0.05 s",
        f"could not read the solves from CTFd: CTFd at {fake.base_url} answered HTTP 400 (Bad Request) at "
        "GET /api/v1/teams/me/solves (CTFd says: the database is broken); flightdeck tries again in 0.05 s",
    ]
    assert run.deck.challenges["warmup"].solved_by == YOUR_TEAM


def test_the_ctfd_token_never_shows_in_notes_logs_transcripts_files_or_errors(tmp_path, token):
    echo = Reply(400, {"message": f"bad header: Token {TOKEN}"})  # a server that echoes what it got
    model = Model({"Warmup": [tool_call_reply("shell", {"command": "env"}), submit("test{nope}"), submit("test{hello}")]})
    with FakeCTFd(three()) as fake, FakeModelServer(responder=model) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url), team=True,
                                     config=config(tmp_path, server.base_url, max_lanes=1),
                                     wave_seconds=0.05, solves_seconds=0.05))
        fake.script("GET", "/api/v1/challenges", echo)
        fake.script("GET", "/api/v1/teams/me/solves", echo)

        async def body(run):
            lane = run.deck.lanes["L01"]
            for flag in ("test{nope}", "test{hello}"):
                await wait_for(lambda: lane.pending is not None and lane.pending.flag == flag, f"{flag} to approve")
                run.deck.apply(iv.Approve(lane.id))
            await wait_for(lambda: len([e for e in run.deck.events if e.kind is EventKind.WARNING]) >= 2, "the echoed failures")

        play(run, body)
    shown = [*run.notes(), *run.errors, repr(run), repr(run.ctfd), repr(run.verifier),
             *(e.text for e in run.deck.events), json.dumps([dict(e.data) for e in run.deck.events], default=str)]
    assert all(TOKEN not in text for text in shown)
    assert sum("Token [token]" in e.text for e in run.deck.events) == 2  # CTFd's words kept, the token cut out
    files = [p for p in [*run.dir.rglob("*"), *(tmp_path / "board").rglob("*")] if p.is_file()]
    assert any(p.name == "L01.jsonl" for p in files) and any(p.name == "ctfd.json" for p in files)
    assert all(TOKEN.encode() not in p.read_bytes() for p in files)
    with FakeCTFd(three(), token="the-token-this-ctfd-wants") as other:  # a pull CTFd refuses
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=tmp_path / "other", event=event(tmp_path, url=other.base_url, name="other.toml"),
                                   config=config(tmp_path)))
    assert "refused the API token (HTTP 401)" in str(caught.value) and TOKEN not in str(caught.value)


def test_shutdown_stops_the_polls_and_closes_the_ctfd_clients(tmp_path, token):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url),
                                     config=config(tmp_path, server.base_url, max_lanes=1),
                                     wave_seconds=0.02, solves_seconds=0.02))

        async def main() -> tuple[int, int, int, int, list]:
            run.release()
            await wait_for(lambda: len(fake.to("/api/v1/challenges")) >= 3 and len(fake.to("/api/v1/teams/me/solves")) >= 3,
                           "a few polls")
            await run.shutdown()
            left = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
            asked, events = len(fake.requests), len(run.deck.events)
            await asyncio.sleep(0.2)  # ten intervals, on the same loop
            with pytest.raises(RuntimeError, match="closed"):
                await run.ctfd.client.solved_ids()
            return asked, len(fake.requests), events, len(run.deck.events), left

        asked, later, events, more_events, left = asyncio.run(main())
        run.close()
        assert left == []  # nothing of the run still runs on the console's loop
        assert later == asked and more_events == events
        with pytest.raises(RuntimeError, match="closed"):
            run.verifier("warmup", "test{hello}")


def test_the_console_starts_the_event_tasks_and_quitting_stops_them(tmp_path, token):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url),
                                     config=config(tmp_path, server.base_url, max_lanes=1),
                                     wave_seconds=0.05, solves_seconds=0.05))

        async def main() -> list[str]:
            app = run.app(refresh_seconds=None)
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                fake.add(FakeChallenge(5, "Second Wave", value=150))
                await wait_for(lambda: "second-wave" in run.deck.challenges, "the wave, released by the console's task")
                await pilot.press("q")
                await pilot.pause()
                assert isinstance(app.screen, QuitPrompt)  # a lane is at work: quitting asks first
                assert str(run.dir) in app.screen.quit_summary.plain  # and says where the run's log stays
                await pilot.press("y")
                await wait_for(lambda: not app.is_running, "the console to quit")
            return [t.get_name() for t in asyncio.all_tasks() if t.get_name().startswith("flightdeck ")]

        left = asyncio.run(main())
        run.close()
    assert left == []  # quitting ran shutdown(): no wave, solves or lane task outlives the console
    assert [e["data"]["label"] for e in log(run) if e["kind"] == "release"] == ["Board", "Wave 2"]


# ---------------------------------------------------------------------- the team channel


def test_two_runs_on_one_team_folder_see_each_others_claims_and_solves(tmp_path):
    shared = init_folder(tmp_path / "team")
    root = folder_board(tmp_path, ("note", "memo", "card"))
    with FakeModelServer(responder=Model({"Note": [submit("t{note}")]})) as a, FakeModelServer(responder=Model()) as b:
        # alpha's watcher reads the folder at the start only: what alpha does reaches the folder through mirror()
        alpha = prepare_run(RunOptions(board=root, config=config(tmp_path / "a", a.base_url, max_lanes=1),
                                       team_dir=shared, handle="alpha", team_seconds=3600))
        bravo = prepare_run(RunOptions(board=root, config=config(tmp_path / "b", b.base_url, max_lanes=1),
                                       team_dir=shared, handle="bravo", team_seconds=0.05))

        async def main():
            alpha.release()
            bravo.release()
            try:
                ours, theirs = alpha.deck.lanes["L01"], bravo.deck.lanes["L01"]
                assert ours.challenge_id == theirs.challenge_id == "note"  # nothing was claimed yet
                await wait_for(lambda: theirs.turns > 0, "bravo's lane at work")  # alpha's watcher has read the folder
                assert alpha.deck.apply(iv.Claim("memo")).ok
                await wait_for(lambda: bravo.deck.challenges["memo"].claimed_by == "alpha", "alpha's claim on bravo's deck")
                assert not bravo.deck.queued("memo")
                await wait_for(lambda: ours.pending is not None, "alpha's flag")
                assert alpha.deck.apply(iv.Approve(ours.id)).ok and ours.state is LaneState.SOLVED
                await wait_for(lambda: theirs.finished, "bravo's lane on the solved challenge to stop")
            finally:
                await alpha.shutdown()
                await bravo.shutdown()

        try:
            asyncio.run(main())
        finally:
            alpha.close()
            bravo.close()
    note = bravo.deck.challenges["note"]
    assert bravo.deck.lanes["L01"].state is LaneState.STOPPED
    assert note.status is ChallengeStatus.TEAMMATE and note.solved_by == "alpha"
    assert bravo.deck.lanes["L02"].challenge_id == "card"  # memo is alpha's
    teammate = [e for e in log(bravo) if e["kind"] == "teammate"]
    assert [e["text"] for e in teammate] == ["alpha claimed Memo", "alpha solved Note · stopped L01"]
    assert "before_run" not in teammate[1]["data"]  # a solve that came during the run


def test_a_challenge_a_teammate_claimed_or_solved_gets_no_lane_at_the_start(tmp_path):
    shared = init_folder(tmp_path / "team")
    bravo = TeamChannel(shared, "bravo")
    bravo.claim("note")
    bravo.solved("memo")
    root = folder_board(tmp_path, ("note", "memo", "card"))
    with FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=root, config=config(tmp_path, server.base_url, max_lanes=3), team_dir=shared, handle="alpha"))

        async def body(run):
            assert [lane.challenge_id for lane in run.deck.lanes.values()] == ["card"]
            assert run.deck.challenges["note"].claimed_by == "bravo"
            assert run.deck.challenges["memo"].status is ChallengeStatus.TEAMMATE

        play(run, body)
    (solve,) = [e for e in log(run) if e["kind"] == "teammate" and e["data"].get("solved")]
    assert (solve["challenge"], solve["data"]["before_run"]) == ("memo", True)  # in the folder before the run started


@pytest.mark.parametrize("folder_gone", [False, True])
def test_shutdown_frees_our_live_box_holds_or_says_why_it_could_not(tmp_path, folder_gone):
    shared = init_folder(tmp_path / "team")
    root = folder_board(tmp_path, urls=("http://127.0.0.1:9",))
    teammate = TeamChannel(shared, "bravo")
    with FakeModelServer(responder=Model()) as server:
        run = prepare_run(RunOptions(board=root, config=config(tmp_path, server.base_url), team_dir=shared, handle="alpha",
                                     instance="confirm"))

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the live-box question")
            assert run.deck.apply(iv.Approve(lane.id)).ok
            assert teammate.current("boxes", "note").who == "alpha"  # mirror() wrote our hold
            if folder_gone:
                (shared / "flightdeck-team.txt").rename(tmp_path / "away.txt")  # the drive went away

        play(run, body)
    if folder_gone:
        (problem,) = run.errors
        assert problem.startswith("team: could not free your live-box holds in the team folder: ") and "flightdeck team init" in problem
    else:
        assert teammate.current("boxes", "note") is None and run.errors == []


def test_the_team_handle_is_the_login_name_unless_given_and_a_note_says_which(tmp_path, monkeypatch):
    shared = init_folder(tmp_path / "team")
    root = folder_board(tmp_path)
    monkeypatch.setenv("LOGNAME", "player1")
    run = prepare_run(RunOptions(board=root, config=config(tmp_path), team_dir=shared))
    run.close()
    assert run.team.me == "player1" and run.deck.config.team
    assert f"team: you are player1 in the team folder {shared} (your login name; --handle NAME sets another)" in run.notes()
    run = prepare_run(RunOptions(board=root, config=config(tmp_path), team_dir=shared, handle="alpha"))
    run.close()
    assert run.team.me == "alpha" and f"team: you are alpha in the team folder {shared} (from --handle)" in run.notes()
    monkeypatch.setenv("LOGNAME", "me")  # the deck's word for the player
    with pytest.raises(RunError, match='your login name "me" is not a usable team handle .*: give one with --handle NAME'):
        prepare_run(RunOptions(board=root, config=config(tmp_path), team_dir=shared))


def test_a_team_event_needs_the_team_folder_or_solo(tmp_path):
    root = folder_board(tmp_path)
    profile = event(tmp_path, platform="manual", board=root, team=True)
    with pytest.raises(RunError, match="sets team = true.*--team-dir FOLDER.*`flightdeck team init FOLDER`.*--solo"):
        prepare_run(RunOptions(event=profile, config=config(tmp_path)))
    solo = prepare_run(RunOptions(event=profile, config=config(tmp_path), team=False))
    solo.close()
    assert solo.deck.config.team is False and solo.team is None
    shared = init_folder(tmp_path / "team")
    team = prepare_run(RunOptions(event=profile, config=config(tmp_path), team_dir=shared, handle="alpha"))
    team.close()
    assert team.deck.config.team and team.team.folder == shared


def test_a_team_folder_without_its_marker_is_refused_with_how_to_make_one(tmp_path):
    (tmp_path / "team").mkdir()
    with pytest.raises(RunError, match="is not a team folder .*`flightdeck team init "):
        prepare_run(RunOptions(board=folder_board(tmp_path), config=config(tmp_path), team_dir=tmp_path / "team", handle="alpha"))
    assert not (tmp_path / "runs").exists()


def test_variant_tries_in_the_config_reaches_the_deck_and_the_runs_notes_say_so(tmp_path):
    root = folder_board(tmp_path)
    off = prepare_run(RunOptions(board=root, config=config(tmp_path)))
    off.close()
    assert off.deck.config.variant_tries == 0 and not any(note.startswith("variant_tries = ") for note in off.notes())
    cfg = config(tmp_path)
    cfg.write_text(cfg.read_text().replace('runtime = "host"\n', 'runtime = "host"\nvariant_tries = 2\n'))
    run = prepare_run(RunOptions(board=root, config=cfg))
    run.close()
    assert run.deck.config.variant_tries == 2 and run.deck.config.submit == "confirm"
    said = ("variant_tries = 2 in your config: when the platform calls a flag wrong, flightdeck proposes up to 2 other "
            "spellings of it per challenge, one at a time")
    assert said + "; each waits for you, as every flag does" in run.notes()
    auto = variant_tries_note(DeckConfig(event="t", submit="auto", variant_tries=1))
    assert auto.endswith("up to 1 other spelling of it per challenge, one at a time; under submit auto each goes out as a "
                         "lane's own flag would, and a wrong one is a wrong try")
