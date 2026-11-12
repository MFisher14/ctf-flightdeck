"""Autopilot in a real run (run.py): engaging it at the start, an event played by rule against
the fake CTFd (tests/fake_ctfd.py) and the fake model (tests/fake_model.py), both on
127.0.0.1, the schedule, and the platform needing a human.

Autopilot needs the Docker runtime. These runs ask for it, and the `docker` fixture stands a
folder on this machine in for each lane's container (and skips the checks that ask Docker),
so no test here needs Docker: what is tested is the run's wiring of autopilot, not a
workspace. Everything else is the real run, as in test_event_run.py, whose helpers these use.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import cli
from ctf_flightdeck import run as run_module
from ctf_flightdeck.agent.anthropic_client import AnthropicClient
from ctf_flightdeck.agent.workspace import HostWorkspace
from ctf_flightdeck.autopilot import NEEDS_BUDGET, NEEDS_DOCKER, State
from ctf_flightdeck.core.model import ChallengeStatus, PendingKind
from ctf_flightdeck.leftovers import Swept
from ctf_flightdeck.run import RunError, RunOptions, prepare_run

from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd, Reply
from fake_model import FakeModelServer
from test_event_run import LADDER, TOKEN_VAR, Model, config, event, folder_board, log, play, submit, three, wait_for

PAGE = "<!DOCTYPE html><html><body><h1>Checking you are human</h1></body></html>"


@pytest.fixture
def docker(monkeypatch):
    """The Docker runtime without Docker: see the module doc."""
    monkeypatch.setattr(run_module, "_check_docker", lambda image: None)
    monkeypatch.setattr(run_module, "sweep", lambda runs, **how: Swept())
    monkeypatch.setattr(run_module, "DockerWorkspace", lambda root, handout, **how: HostWorkspace(root, handout))


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, TOKEN)


def options(tmp_path, server, **more) -> RunOptions:
    if "config" not in more:
        more["config"] = config(tmp_path, server.base_url)
    more.setdefault("budget_tokens", 5_000_000)
    return RunOptions(runtime="docker", autopilot=True, **more)


def spending(tmp_path, server, **how):
    """A config whose [lanes] opt in to spending counted tries (D21)."""
    path = config(tmp_path, server.base_url, **how)
    path.write_text(path.read_text().replace('runtime = "host"\n', 'runtime = "host"\nsubmit_limited = "auto"\n'))
    return path


def scheduled(profile, **times: datetime):
    lines = "".join(f'{name} = "{when.isoformat()}"\n' for name, when in times.items())
    profile.write_text(profile.read_text().replace("[event]\n", "[event]\n" + lines, 1))
    return profile


def autopilot_events(run, what: str) -> list[dict]:
    return [e for e in log(run) if e["kind"] == "warning" and e["data"].get("autopilot") == what]


# ---------------------------------------------------------------------- engaging at the start


def test_play_refuses_to_start_autopilot_without_a_run_budget_in_one_line(tmp_path):
    root = folder_board(tmp_path)
    with FakeModelServer(models=LADDER) as server:
        cfg = config(tmp_path, server.base_url)
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=root, config=cfg, runtime="docker", autopilot=True))
        assert str(caught.value) == NEEDS_BUDGET and "\n" not in NEEDS_BUDGET
        shown = CliRunner().invoke(cli.app, ["play", str(root), "--config", str(cfg), "--docker", "--autopilot"])
    assert shown.exit_code == 2 and shown.output.strip() == f"flightdeck: {NEEDS_BUDGET}"
    assert not (tmp_path / "runs").exists()  # nothing started


def test_play_refuses_to_start_autopilot_on_the_host_runtime_and_says_why(tmp_path):
    root = folder_board(tmp_path)
    with FakeModelServer(models=LADDER) as server:
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=root, config=config(tmp_path, server.base_url), runtime="host", autopilot=True,
                                   budget_dollars=5.0))
    assert str(caught.value) == f"{NEEDS_DOCKER}: drop --host, or play without --autopilot"
    assert not (tmp_path / "runs").exists()


def test_the_config_can_engage_autopilot_and_hold_its_budget_and_the_options_win(tmp_path, docker):
    root = folder_board(tmp_path)
    with FakeModelServer(models=LADDER) as server:
        cfg = config(tmp_path, server.base_url)
        cfg.write_text(cfg.read_text() + "[autopilot]\nengage = true\nbudget_dollars = 3.0\n")
        run = prepare_run(RunOptions(board=root, config=cfg, runtime="docker"))
        run.close()
        assert run.engage and (run.autopilot.budget.dollars, run.autopilot.budget.tokens) == (3.0, None)
        off = prepare_run(RunOptions(board=root, config=cfg, runtime="docker", autopilot=False, budget_tokens=900))
        off.close()
    assert not off.engage and (off.autopilot.budget.dollars, off.autopilot.budget.tokens) == (3.0, 900)
    assert off.autopilot.state is State.OFF and not any(n.startswith("autopilot:") for n in off.notes())


def test_a_run_without_autopilot_still_has_one_to_engage_from_the_console_and_it_names_what_is_missing(tmp_path):
    root = folder_board(tmp_path)
    with FakeModelServer(models=LADDER) as server:
        run = prepare_run(RunOptions(board=root, config=config(tmp_path, server.base_url)))  # host, no budget
        run.close()
    assert run.deck.autopilot is run.autopilot and not run.engage
    assert run.autopilot.engage().message == f"Autopilot not engaged: {NEEDS_BUDGET}"


def test_the_notes_say_what_autopilot_will_and_will_not_do_under_this_events_policies(tmp_path, docker):
    root = folder_board(tmp_path)
    with FakeModelServer(models=LADDER) as server:
        profile = event(tmp_path, platform="manual", board=root, live="confirm")  # submit: confirm, the default
        run = prepare_run(options(tmp_path, server, event=profile, budget_dollars=4.0, budget_tokens=None))
        run.close()
    notes = run.notes()
    assert "autopilot: submit is confirm under this event's rules, so every flag waits for you" in notes
    assert "autopilot: the instance policy is confirm, so a lane's request to reach its live instance waits for you" in notes
    assert any(n.startswith("autopilot: engaged, with a run budget of $4.00; at the budget it holds the queue") for n in notes)
    assert "autopilot: a request a model declines is never sent on to another model or provider" in notes
    assert run.deck.config.submit == "confirm"  # autopilot changed no policy


# ---------------------------------------------------------------------- an event, by rule


def test_an_event_under_autopilot_submits_claimed_flags_takes_a_new_wave_and_keeps_the_last_try(tmp_path, token, docker):
    warmup, rsa, echo = three()
    rsa.max_attempts = 2
    folder = tmp_path / "board"
    model = Model({"Warmup": [submit("test{hello}")], "Baby RSA": [submit("test{wrong}"), submit("test{rsa}")]})
    with FakeCTFd([warmup, rsa, echo]) as fake, FakeModelServer(models=LADDER, responder=model) as server:
        profile = event(tmp_path, url=fake.base_url, submit="auto")
        run = prepare_run(options(tmp_path, server, board=folder, event=profile, config=spending(tmp_path, server, max_lanes=5),
                                  wave_seconds=0.05))
        assert run.deck.config.spends_tries and run.autopilot.state is State.OFF  # engaged when the board is released

        async def body(run):
            deck = run.deck
            assert run.autopilot.engaged
            await wait_for(lambda: deck.challenges["warmup"].status is ChallengeStatus.SOLVED, "the claimed flag's solve")
            (lane,) = deck.lanes_on("baby-rsa")
            await wait_for(lambda: lane.pending is not None, "the flag that would spend the last try")
            assert (lane.pending.kind, lane.pending.flag) == (PendingKind.SUBMIT, "test{rsa}")
            assert deck.challenges["baby-rsa"].tries_left == 1
            fake.add(FakeChallenge(5, "Second Wave", category="Forensics", value=150, files={"disk.img": b"\0" * 64}))
            await wait_for(lambda: deck.lanes_on("second-wave"), "a lane on the new wave")
            assert run.autopilot.engaged and not deck.held  # the run went on

        play(run, body)
        sent = [request.json["submission"] for request in fake.to("/api/v1/challenges/attempt")]
    assert sent == ["test{hello}", "test{wrong}"] or sorted(sent) == ["test{hello}", "test{wrong}"]
    assert "test{rsa}" not in sent  # the right flag, and still not sent: the last try is the player's
    (kept,) = autopilot_events(run, "last_try")
    assert kept["data"]["flag"] == "test{rsa}" and kept["data"]["tries_left"] == 1
    assert [e["data"]["autopilot"] for e in log(run) if e["kind"] == "warning" and "autopilot" in e["data"]][0] == "engaged"
    assert not autopilot_events(run, "disengaged")
    notes = run.notes()
    assert any(n.startswith("autopilot: submit is auto, so a flag a lane claims is submitted") for n in notes)
    assert any("but never the last one" in n for n in notes) and "autopilot: new waves are pulled on the timer" in notes


def test_a_page_for_a_person_where_ctfd_should_answer_disengages_autopilot_at_once(tmp_path, token, docker):
    folder = tmp_path / "board"
    with FakeCTFd(three()) as fake, FakeModelServer(models=LADDER, responder=Model()) as server:
        run = prepare_run(options(tmp_path, server, board=folder, event=event(tmp_path, url=fake.base_url),
                                  config=config(tmp_path, server.base_url, max_lanes=1), wave_seconds=0.05))

        async def body(run):
            assert run.autopilot.engaged
            fake.script("GET", "/api/v1/challenges", Reply(403, PAGE))
            await wait_for(lambda: run.autopilot.state is State.DISENGAGED, "the disengage")
            assert run.deck.held.startswith("autopilot disengaged: the platform needs you: CTFd at ")
            assert len(run.deck.queue) == 2  # held: the queued challenges do not start

        play(run, body)
    (event_,) = autopilot_events(run, "disengaged")
    reason = event_["data"]["reason"]
    assert set(event_["data"]) == {"autopilot", "reason"}  # what a notifier listens for
    assert "a web page for a person, not a CTFd API answer" in reason and "(not JSON, HTTP 403 (Forbidden))" in reason
    assert TOKEN not in str(log(run))


def test_a_ctfd_poll_that_keeps_failing_disengages_and_one_that_recovers_does_not(tmp_path, token, docker):
    folder = tmp_path / "board"
    refused = Reply(403, {"success": False, "message": "the CTF is not running"})
    with FakeCTFd(three()) as fake, FakeModelServer(models=LADDER, responder=Model()) as server:
        run = prepare_run(options(tmp_path, server, board=folder, event=event(tmp_path, url=fake.base_url), wave_seconds=0.05))

        async def body(run):
            before = len(fake.to("/api/v1/challenges"))
            fake.script("GET", "/api/v1/challenges", refused, refused)
            await wait_for(lambda: len(fake.to("/api/v1/challenges")) >= before + 4, "two failures, then answers again")
            assert run.autopilot.engaged and run.ctfd.failing == {}  # it passed
            fake.script("GET", "/api/v1/challenges", refused, refused, refused)
            await wait_for(lambda: run.autopilot.state is State.DISENGAGED, "the disengage")

        play(run, body)
    (event_,) = autopilot_events(run, "disengaged")
    assert event_["data"]["reason"].startswith(
        "the platform needs you: pulling new challenges from CTFd has failed 3 times in a row: CTFd at ")


def test_a_flag_ctfd_does_not_judge_disengages_autopilot_and_waits_for_the_player(tmp_path, token, docker):
    folder = tmp_path / "board"
    with FakeCTFd(three()) as fake, FakeModelServer(models=LADDER, responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        fake.paused = True
        run = prepare_run(options(tmp_path, server, board=folder, event=event(tmp_path, url=fake.base_url, submit="auto")))

        async def body(run):
            (lane,) = run.deck.lanes_on("warmup")
            await wait_for(lambda: run.autopilot.state is State.DISENGAGED, "the disengage")
            assert lane.pending is not None and lane.pending.kind is PendingKind.CONFIRM  # yours to submit by hand

        play(run, body)
    (event_,) = autopilot_events(run, "disengaged")
    assert event_["data"]["reason"].startswith("the platform needs you: CTFd did not judge a flag: ")


# ---------------------------------------------------------------------- the schedule


def test_autopilot_waits_for_the_events_start_before_anything_is_pulled(tmp_path, token, docker):
    start = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc)
    clock = [start - timedelta(seconds=75)]
    said, sleeps = [], []
    folder = tmp_path / "board"
    with FakeCTFd(three()) as fake, FakeModelServer(models=LADDER) as server:

        def sleep(seconds: float) -> None:
            assert fake.requests == [] and not folder.exists()  # nothing is pulled while it waits
            sleeps.append(seconds)
            clock[0] += timedelta(seconds=seconds)

        profile = scheduled(event(tmp_path, url=fake.base_url), start=start)
        run = prepare_run(options(tmp_path, server, board=folder, event=profile, say=said.append, now=lambda: clock[0], sleep=sleep))
        run.close()
        assert fake.requests != []  # then the pull
    assert sleeps == [30.0, 30.0, 15.0]
    assert said == ["autopilot: the event starts at 2026-11-14T09:00:00+00:00 (event.start), in 1m: waiting until then "
                    "before anything is pulled or started. Ctrl-C stops the wait"]
    assert "autopilot: the event starts 2026-11-14T09:00:00+00:00" in run.notes()


def test_without_autopilot_a_start_in_the_future_is_not_waited_for(tmp_path, token):
    start = datetime(2026, 11, 14, 9, 0, tzinfo=timezone.utc)

    def never(seconds: float) -> None:
        raise AssertionError("a run without autopilot does not wait")

    with FakeCTFd(three()) as fake, FakeModelServer(models=LADDER) as server:
        profile = scheduled(event(tmp_path, url=fake.base_url), start=start)
        run = prepare_run(RunOptions(board=tmp_path / "board", event=profile, config=config(tmp_path, server.base_url),
                                     now=lambda: start - timedelta(hours=2), sleep=never))
        run.close()
    assert len(run.board.challenges) == 3


def test_stopping_the_wait_for_the_start_leaves_nothing_pulled_or_started(tmp_path, token, docker, monkeypatch):
    start = datetime.now(timezone.utc) + timedelta(hours=3)

    def interrupted(seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(run_module.time, "sleep", interrupted)
    folder = tmp_path / "board"
    with FakeCTFd(three()) as fake, FakeModelServer(models=LADDER) as server:
        profile = scheduled(event(tmp_path, url=fake.base_url), start=start)
        cfg = config(tmp_path, server.base_url)
        shown = CliRunner().invoke(cli.app, ["play", str(folder), "--event", str(profile), "--config", str(cfg), "--docker",
                                             "--autopilot", "--budget-tokens", "1000"])
        assert fake.requests == [] and not folder.exists()
    assert shown.exit_code == 130
    assert "waiting until then before anything is pulled or started" in shown.output
    assert shown.output.strip().endswith("flightdeck: stopped before the run started: nothing was pulled and no lane started")


def test_an_event_that_has_ended_is_refused_under_autopilot(tmp_path, docker):
    root = folder_board(tmp_path)
    end = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)
    with FakeModelServer(models=LADDER) as server:
        profile = scheduled(event(tmp_path, platform="manual", board=root), end=end)
        with pytest.raises(RunError, match=r"the event ended at 2026-11-10T09:00:00\+00:00 \(event.end in the event profile\)"):
            prepare_run(options(tmp_path, server, event=profile, now=lambda: end + timedelta(minutes=1)))


def test_at_the_events_end_the_run_stops_as_quitting_does(tmp_path, docker):
    root = folder_board(tmp_path)
    end = datetime.now(timezone.utc) + timedelta(seconds=0.6)
    with FakeModelServer(models=LADDER, responder=Model()) as server:
        profile = scheduled(event(tmp_path, platform="manual", board=root), end=end)
        run = prepare_run(options(tmp_path, server, event=profile))

        async def body(run):
            assert run.autopilot.engaged and not run.deck.closing
            await wait_for(lambda: run.deck.closing, "the run stopping at the end")
            assert datetime.now(timezone.utc) >= end and run.autopilot.state is State.DISENGAGED

        play(run, body)
    (event_,) = autopilot_events(run, "disengaged")
    assert event_["data"]["reason"] == (
        f"the event ended ({end.isoformat()}, event.end in the event profile): the run stops as when you quit")


def test_at_the_events_end_whoever_flies_the_run_is_asked_to_stop_it_unless_the_player_has_the_controls(tmp_path, docker):
    root = folder_board(tmp_path)
    with FakeModelServer(models=LADDER, responder=Model()) as server:
        stopped: list[str] = []
        for taken_back in (False, True):
            end = datetime.now(timezone.utc) + timedelta(seconds=0.4)
            profile = scheduled(event(tmp_path, platform="manual", board=root, name=f"event{taken_back}.toml"), end=end)
            run = prepare_run(options(tmp_path, server, event=profile))
            run.stopper = stopped.append

            async def body(run):
                if taken_back:
                    assert run.autopilot.off().ok
                await asyncio.sleep(0.8)
                assert not run.deck.closing  # the stopper's to do, or nobody's

            play(run, body)
            assert stopped == [f"the event ended ({end.isoformat()}): "] if not taken_back else len(stopped) == 1


# ---------------------------------------------------------------------- no refusal rerouted


def test_while_autopilot_guards_the_run_requests_carry_no_server_side_refusal_fallback():
    model = "claude-opus-5-5"
    client = AnthropicClient("https://api.anthropic.com", "k")
    light = AnthropicClient("https://api.anthropic.com", "k", server_fallback=False)
    pair = SimpleNamespace(primary=client, fallback=light)  # as agent/fallback.py's FallbackClient holds them
    switch, any_to_switch = run_module._refusal_switch(pair, (model,))
    ask = lambda: client._params(model, [{"role": "user", "content": "hi"}], [], None, fast=False)  # noqa: E731
    assert any_to_switch and ask().get("fallbacks") == "default"
    switch(False)  # autopilot engages
    assert "fallbacks" not in ask() and client.server_fallback is False
    switch(True)  # the player has the controls back
    assert ask().get("fallbacks") == "default" and light.server_fallback is False  # one that never had it stays without
    assert run_module._refusal_switch(None, (model,)) == (None, False)
    assert run_module._refusal_switch(client, ("claude-haiku-5-5",))[1] is False  # no model of the ladder has one


def test_engaging_in_a_run_switches_the_clients_refusal_fallback_off_and_taking_over_puts_it_back(tmp_path, docker):
    root = folder_board(tmp_path)
    with FakeModelServer(models=LADDER, responder=Model()) as server:
        run = prepare_run(options(tmp_path, server, board=root))
        run.client.server_fallback = True  # as an Anthropic client has it
        run.autopilot._refusals = run_module._refusal_switch(run.client, LADDER)[0]

        async def body(run):
            assert run.autopilot.engaged and run.client.server_fallback is False
            run.autopilot.off()
            assert run.client.server_fallback is True

        play(run, body)
