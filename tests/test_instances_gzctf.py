"""Instances on the http platform: GZCTF's containers through [instances] plugin = "gzctf",
asked with the gzctf preset's cookie (HttpCaller.instance_wire) and the game's number, against
tests/fake_gzctf.py's FakeGZCTF on 127.0.0.1. Nothing real is contacted; every host,
container and challenge is invented. The shapes are GZCTF's as its public source has them
(fake_gzctf.py names the files)."""

from __future__ import annotations

import asyncio
import json

import pytest

from ctf_flightdeck.core.model import ChallengeStatus
from ctf_flightdeck.platform.http import HttpCaller, parse_config as parse_http
from ctf_flightdeck.platform.instances import (
    UNITS, InstanceClient, InstanceError, InstanceRefused, parse_config,
)
from ctf_flightdeck.plugins.board import pull_into
from ctf_flightdeck.preflight import describe, load_profile
from ctf_flightdeck.run import RunOptions, prepare_run

from fake_ctfd import Reply
from fake_gzctf import COOKIE, GAME, GUID, FakeGZCTF, GTask, problem
from fake_model import FakeModelServer
from test_event_run import Model, config, play, submit, wait_for
from test_http_event import event_file

GZ = {"preset": "gzctf", "game": GAME}
CONTAINER = f"/api/game/{GAME}/container/{{}}"


def tasks() -> list[GTask]:
    return [
        GTask(21, "Pwn Box", category="Pwn", container="DynamicContainer", entry="box-21.gz.example.test:31021"),
        GTask(22, "Web Box", category="Web", container="StaticContainer", entry="web-22.gz.example.test:8080"),
        GTask(23, "Plain", category="Misc"),
    ]


def connect(fake: FakeGZCTF, *, naps: list | None = None, game: str = GAME, **table) -> InstanceClient:
    """An instance client that goes through the gzctf preset's wire: the board's ids are the
    challenges' own numbers as strings, as a pull writes them."""
    caller = HttpCaller(parse_http({**GZ, "game": game}), fake.url, COOKIE)
    ids = {task.title.lower().replace(" ", "-"): str(task.id) for task in fake.tasks.values()}
    return InstanceClient(None, None, ids, parse_config({"plugin": "gzctf", **table}), wire=caller.instance_wire(), timeout=5,
                          sleep=(naps if naps is not None else []).append)


def asked(fake: FakeGZCTF) -> list[tuple[str, str]]:
    return [(r.method, r.route) for r in fake.requests]


# ---------------------------------------------------------------- the shape


def test_gzctfs_shape_is_the_container_route_the_challenges_detail_and_milliseconds_for_the_http_platform():
    config = parse_config({"plugin": "gzctf"})
    path = "/api/game/{game}/container/{id}"
    assert (config.routes.start, config.routes.renew, config.routes.stop, config.routes.status) == (
        ("POST", path), ("POST", path + "/extend"), ("DELETE", path), ("GET", "/api/game/{game}/challenges/{id}"))
    assert config.platform == "http" and config.routes.body_key is None and not config.routes.api
    assert config.routes.empty == ("stop",) and config.routes.language == "en-US"
    assert config.answers.address == ("entry", "instanceEntry") and config.answers.expires == ("expectStopAt", "closeTime")
    assert config.answers.scopes == ("context",) and config.answers.errors == ("title",) and config.answers.pending == ("Pending",)
    assert config.answers.expires_unit == UNITS["ms"] and config.gap == 10.0 and config.max_running == 3


@pytest.mark.parametrize("path", ["/api/game/{gam}/container/{id}", "/x/{id}/{", "/x/{ref}"])
def test_a_route_with_a_brace_that_is_neither_id_nor_game_is_refused(path):
    with pytest.raises(ValueError, match="a brace in the path must be \\{id\\} .* or \\{game\\}"):
        parse_config({"plugin": "gzctf", "start": ["POST", path]})


# ---------------------------------------------------------------- the wire


def test_the_container_is_asked_for_with_the_cookie_and_the_games_number_and_its_entry_is_the_address():
    with FakeGZCTF(tasks()) as fake:
        client = connect(fake)
        assert client.status("pwn-box") is None  # the detail's context names no entry: no container
        clock = client._clock()
        got = client.start("pwn-box")
        status, start = fake.requests
        assert (status.method, status.route, start.method, start.route) == (
            "GET", f"/api/game/{GAME}/challenges/21", "POST", CONTAINER.format(21))
        assert {r.headers["cookie"] for r in fake.requests} == {f"GZCTF_Token={COOKIE}"}
        assert {r.headers["accept-language"] for r in fake.requests} == {"en-US"}
        assert start.body == b"" and "content-type" not in start.headers  # CreateContainer reads no body
    assert (got.scheme, got.host, got.port) == (None, "box-21.gz.example.test", 31021)
    assert got.urls(web=False) == ("tcp://box-21.gz.example.test:31021",)
    assert 7199 <= got.expires_at - clock <= 7201  # expectStopAt in milliseconds since 1970: two hours from now


def test_the_status_reads_the_entry_and_the_end_from_the_challenges_context():
    with FakeGZCTF(tasks()) as fake:
        client = connect(fake)
        started = client.start("web-box")
        found = client.status("web-box")
    assert found is not None and (found.host, found.port) == ("web-22.gz.example.test", 8080)
    assert found.expires_at == started.expires_at  # closeTime is the container's expectStopAt
    assert found.urls(web=True) == ("http://web-22.gz.example.test:8080",)  # a web challenge's bare host:port is http


def test_a_start_that_answers_pending_is_looked_at_until_its_detail_names_the_entry():
    with FakeGZCTF(tasks()) as fake:
        fake.pending_starts = 1
        naps: list = []
        client = connect(fake, naps=naps)
        got = client.start("pwn-box")
        assert [m for m, _ in asked(fake)] == ["POST", "GET"]  # the start went once
    assert got.host == "box-21.gz.example.test"


def test_a_container_behind_gzctfs_own_proxy_runs_at_no_address_flightdeck_uses_and_says_why():
    with FakeGZCTF(tasks()) as fake:
        fake.proxy = True
        client = connect(fake)
        with pytest.raises(InstanceError, match="through its own WebSocket proxy .* open it from the challenge on the site") as caught:
            client.start("pwn-box")
        assert caught.value.up and caught.value.maybe_done  # it runs, it is this client's, and it holds a slot
        assert GUID in fake.containers[21]["entry"]
        with pytest.raises(InstanceError, match="WebSocket proxy") as later:
            client.status("pwn-box")
        assert later.value.up


def test_the_teams_cap_is_a_full_refusal_in_gzctfs_words():
    with FakeGZCTF(tasks()) as fake:
        fake.container_limit = 1
        client = connect(fake)
        client.start("pwn-box")
        with pytest.raises(InstanceRefused, match="The number of team containers cannot exceed 1") as caught:
            client.start("web-box")
    assert caught.value.full and not caught.value.human and not caught.value.maybe_done


def test_a_second_start_and_a_challenge_with_no_container_are_refused_in_gzctfs_own_title():
    with FakeGZCTF(tasks()) as fake:
        client = connect(fake)
        client.start("pwn-box")
        with pytest.raises(InstanceRefused, match="The container of this challenge already exists") as again:
            client.start("pwn-box")
        with pytest.raises(InstanceRefused, match="This challenge cannot create a container"):
            client.start("plain")
        assert client.status("plain") is None  # its detail names no entry
    assert not again.value.full


def test_two_changes_wait_out_gzctfs_ten_seconds_between_container_operations():
    with FakeGZCTF(tasks()) as fake:
        naps: list = []
        client = connect(fake, naps=naps)
        client.start("pwn-box")
        client.stop("pwn-box")
    assert len(naps) == 1 and 9.0 < naps[0] <= 10.0


def test_a_stop_answered_with_no_body_is_done_and_frees_the_slot():
    with FakeGZCTF(tasks()) as fake:
        client = connect(fake)
        client.start("pwn-box")
        client.stop("pwn-box")  # ASP.NET's Ok(): a 200 with nothing in it
        assert fake.containers == {} and asked(fake)[-1] == ("DELETE", CONTAINER.format(21))
        assert client.status("pwn-box") is None


def test_an_empty_answer_to_a_start_is_still_no_instance():
    """Only the stop's empty 200 is a done: a start that answers nothing names no container."""
    with FakeGZCTF(tasks()) as fake:
        fake.script("container-start", Reply(200, b""))
        client = connect(fake)
        with pytest.raises(InstanceError, match="not JSON") as caught:
            client.start("pwn-box")
    assert caught.value.maybe_done


def test_an_extend_before_the_renewal_window_is_refused_and_one_inside_it_reads_the_new_end():
    with FakeGZCTF(tasks()) as fake:
        client = connect(fake)
        started = client.start("pwn-box")
        with pytest.raises(InstanceRefused, match="Container's lifetime cannot be extended yet"):
            client.renew("pwn-box")
        fake.window = 10_000.0  # the end is now inside the window
        renewed = client.renew("pwn-box")
        assert asked(fake)[-1] == ("POST", CONTAINER.format(21) + "/extend")
    assert renewed is not None and 7199 <= renewed.expires_at - started.expires_at <= 7201


def test_a_wire_with_no_game_sends_nothing_for_a_route_with_game_in_it():
    with FakeGZCTF(tasks()) as fake:
        client = InstanceClient(fake.url, "fake-token", {"pwn-box": 21}, parse_config({"plugin": "gzctf"}), timeout=5)
        with pytest.raises(InstanceError, match="the route has \\{game\\} in it, and the platform has no game") as caught:
            client.start("pwn-box")
        assert fake.requests == [] and not caught.value.maybe_done


def test_a_game_that_would_name_another_route_is_never_sent():
    with FakeGZCTF(tasks()) as fake:
        client = connect(fake, game="..")
        with pytest.raises(InstanceError, match="the game would name another route"):
            client.status("pwn-box")
        assert fake.requests == []


def test_the_cookie_never_shows_in_a_refusal():
    with FakeGZCTF(tasks()) as fake:
        fake.script("container-start", problem(400, f"bad ticket {COOKIE}"))
        client = connect(fake)
        with pytest.raises(InstanceRefused) as caught:
            client.start("pwn-box")
    assert COOKIE not in str(caught.value) and "<token>" in str(caught.value)


# ---------------------------------------------------------------- the board and the plan


def test_the_gzctf_preset_marks_a_container_challenge_on_demand_and_an_attachment_one_not(tmp_path):
    with FakeGZCTF(tasks()) as fake:
        caller = HttpCaller(parse_http(GZ), fake.url, COOKIE)
        asyncio.run(pull_into(caller, tmp_path / "board", plugin="http", url=fake.url))
    found = {json.loads(path.read_text())["name"]: json.loads(path.read_text()).get("instance")
             for path in (tmp_path / "board").glob("*/challenge.json")}
    assert found == {"Pwn Box": "on-demand", "Web Box": "on-demand", "Plain": None}


@pytest.mark.parametrize(("value", "marked"), [("DynamicContainer", True), ("StaticContainer", True), ("StaticAttachment", False),
                                               ("DynamicAttachment", False), (3, False), (None, False)])
def test_instance_values_mark_only_the_values_they_name(value, marked):
    caller = HttpCaller(parse_http(GZ), "https://ctf.example.test", COOKIE)
    assert ("instance" in caller._read_fields("detail", caller.config.detail.fields, {"type": value})) is marked


OWN = {"auth": {"kind": "cookie", "cookie": "c"}, "list": {"request": ["GET", "/l"], "items": "$[*]", "ref": "$.id", "name": "$.n"},
       "solved": {"request": ["GET", "/s"], "refs": "$[*]"}}


@pytest.mark.parametrize(("detail", "message"), [
    ({"instance_values": ["x"]}, "http.detail.instance_values names values of http.detail.instance, which is missing"),
    ({"instance": "$.type", "instance_values": []}, "instance_values must be a list of 1 to 16 distinct strings"),
    ({"instance": "$.type", "instance_values": ["a", "a"]}, "instance_values must be a list"),
    ({"instance": "$.type", "instance_values": "StaticContainer"}, "instance_values must be a list"),
    ({"instance": "$.type", "instance_values": ["bad\u202eword"]}, "instance_values must be a list"),
])
def test_a_bad_instance_values_is_named(detail, message):
    table = {**OWN, "detail": {"request": ["GET", "/d/{ref}"], "description": "$.content", **detail}}
    with pytest.raises(ValueError, match=message):
        parse_http(table)


def test_the_plan_shows_gzctfs_container_routes_with_the_cookie(tmp_path):
    profile, chosen = load_profile(event_file(tmp_path, http=f'preset = "gzctf"\ngame = "{GAME}"', token_env="GZCTF_TOKEN",
                                              extra='\n[instances]\nplugin = "gzctf"\n'))
    shown = [line for line in describe(profile, chosen, environ={}) if line.startswith("http      instance")]
    assert [line.split(",")[0] for line in shown] == [
        "http      instance  status GET /api/game/{game}/challenges/{id}", "http      instance  start POST /api/game/{game}/container/{id}",
        "http      instance  renew POST /api/game/{game}/container/{id}/extend",
        "http      instance  stop DELETE /api/game/{game}/container/{id}"]
    assert all("GZCTF_Token" in line for line in shown)


# ---------------------------------------------------------------- a whole run


def test_a_run_on_gzctf_starts_a_challenges_container_hands_the_lane_its_entry_and_stops_it_on_the_solve(tmp_path, monkeypatch):
    monkeypatch.setenv("GZCTF_TOKEN", COOKIE)
    gz_tasks = [GTask(31, "Boxed", category="Pwn", flag="t{boxed}", container="DynamicContainer", entry="box-31.gz.example.test:31031"),
                GTask(32, "Plain", flag="t{plain}")]
    model = Model({"Boxed": [submit("t{boxed}")], "Plain": [submit("t{plain}")]})
    with FakeGZCTF(gz_tasks) as fake, FakeModelServer(responder=model) as server:
        event = event_file(tmp_path, fake.url, http=f'preset = "gzctf"\ngame = "{GAME}"', token_env="GZCTF_TOKEN",
                           board=str(tmp_path / "board"), pull="auto", submit="auto", extra='\n[instances]\nplugin = "gzctf"\n')
        run = prepare_run(RunOptions(event=event, config=config(tmp_path, server.base_url, max_lanes=2)))
        run.instances.every = 0.05
        run.instances.client._sleep = lambda _seconds: None  # GZCTF's 10 s between two changes, not waited in a test
        assert json.loads((tmp_path / "board" / "boxed" / "challenge.json").read_text())["instance"] == "on-demand"

        async def body(run):
            await wait_for(lambda: run.deck.challenges["boxed"].status is ChallengeStatus.SOLVED, "the boxed challenge solved")
            await wait_for(lambda: 31 not in fake.containers and "boxed" not in run.instances.running, "its container stopped after the solve")

        play(run, body)
        changes = [(r.method, r.route) for r in fake.requests if r.route.startswith(f"/api/game/{GAME}/container/")]
        assert changes == [("POST", CONTAINER.format(31)), ("DELETE", CONTAINER.format(31))]  # one start, one stop, of the on-demand one
    briefs = {r["json"]["messages"][1]["content"].split("Challenge: ", 1)[1].split(" (", 1)[0]: r["json"]["messages"][1]["content"]
              for r in server.chats()}
    assert "\nLive instance: tcp://box-31.gz.example.test:31031" in briefs["Boxed"]
    assert "\nLive instance: none\n" in briefs["Plain"]
    everything = run.log.path.read_text() + "\n".join(run.notes())
    assert COOKIE not in everything
