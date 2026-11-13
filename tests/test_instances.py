"""A challenge's own container through a CTFd container plugin: the [instances] table, and the
client against tests/fake_ctfd.py's docker_per_team routes on 127.0.0.1. Nothing real is asked."""

from __future__ import annotations

import pytest

from ctf_flightdeck.platform.instances import (
    Instance, InstanceClient, InstanceError, InstanceRefused, Routes, _address, parse_config,
)

from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd, Reply

PLUGIN = {"plugin": "docker_per_team", "types": ["container"]}
REQUEST = "/containers/api/request"


def board() -> list[FakeChallenge]:
    return [FakeChallenge(1, "Boxed", category="Web", type="container"), FakeChallenge(2, "Second", category="Pwn", type="container"),
            FakeChallenge(3, "Plain", category="Misc")]


def client(fake: FakeCTFd, ids=None, **config) -> InstanceClient:
    return InstanceClient(fake.base_url, TOKEN, ids or {"boxed": 1, "second": 2, "plain": 3}, parse_config({**PLUGIN, **config}), timeout=5)


# ---------------------------------------------------------------- the [instances] table


def test_a_named_plugin_gives_its_routes_and_the_table_its_types_and_cap():
    config = parse_config({"plugin": "docker_per_team", "types": ["container", "docker"], "max_running": 2})
    assert config.routes.start == ("POST", "/containers/api/request") and config.routes.body_key == "chal_id" and not config.routes.api
    assert (config.types, config.max_running, config.plugin) == (("container", "docker"), 2, "docker_per_team")
    assert parse_config({"plugin": "docker_per_team"}).max_running == 3


def test_routes_can_be_given_one_by_one_and_override_a_plugins():
    own = parse_config({"start": ["post", "/x/start?c={id}"], "stop": ["DELETE", "/x/stop?c={id}"],
                        "renew": ["PATCH", "/x/renew?c={id}"], "status": ["GET", "/x?c={id}"], "api": True})
    assert own.routes == Routes(("POST", "/x/start?c={id}"), ("DELETE", "/x/stop?c={id}"), ("PATCH", "/x/renew?c={id}"),
                                ("GET", "/x?c={id}"), None, True)
    mixed = parse_config({"plugin": "docker_per_team", "status": ["POST", "/containers/api/info"]})
    assert mixed.routes.status == ("POST", "/containers/api/info") and mixed.routes.start == ("POST", "/containers/api/request")


@pytest.mark.parametrize(("table", "message"), [
    ({}, "needs plugin .* or all four routes; missing: start, stop, renew, status"),
    ({"plugin": "whale"}, "is not a plugin flightdeck knows"),
    ({"plugin": "docker_per_team", "tpyes": []}, "instances.tpyes is not a key"),
    ({"plugin": "docker_per_team", "start": "/containers/api/request"}, "instances.start must be \\[METHOD, PATH\\]"),
    ({"plugin": "docker_per_team", "start": ["FETCH", "/x"]}, "the method must be one of"),
    ({"plugin": "docker_per_team", "start": ["POST", "https://elsewhere.example/x"]}, "the path must start with /"),
    ({"plugin": "docker_per_team", "start": ["POST", "/a/../b"]}, "the path must start with /"),
    ({"plugin": "docker_per_team", "body_key": None, "start": ["POST", "/x"]}, "must say where the challenge's number goes"),
    ({"plugin": "docker_per_team", "max_running": 0}, "max_running must be a whole number from 1 to 64"),
    ({"plugin": "docker_per_team", "max_running": True}, "max_running must be a whole number"),
    ({"plugin": "docker_per_team", "types": ["a", "a"]}, "types must be a list of distinct"),
    ({"plugin": "docker_per_team", "api": "yes"}, "instances.api must be true or false"),
])
def test_a_bad_instances_table_names_what_is_wrong(table, message):
    with pytest.raises(ValueError, match=message):
        parse_config(table)


# ---------------------------------------------------------------- the client


def test_start_gives_the_address_and_expiry_and_a_second_start_takes_no_second_slot():
    with FakeCTFd(board()) as fake:
        ours = client(fake)
        first = ours.start("boxed")
        assert (first.challenge, first.host, first.port, first.scheme) == ("boxed", "instances.example.test", 31000, None)
        assert first.url(web=True) == "http://instances.example.test:31000" and first.url(web=False) == "tcp://instances.example.test:31000"
        assert first.expires_at is not None
        again = ours.start("boxed")
        assert (again.host, again.port) == (first.host, first.port) and len(fake.containers) == 1
        sent = fake.to(REQUEST)[0]
        assert sent.json == {"chal_id": 1} and sent.headers["authorization"] == f"Token {TOKEN}"


def test_status_renew_and_stop():
    with FakeCTFd(board()) as fake:
        ours = client(fake)
        assert ours.status("boxed") is None  # nothing runs yet
        started = ours.start("boxed")
        seen = ours.status("boxed")
        assert seen is not None and (seen.host, seen.port) == (started.host, started.port)
        assert ours.renew("boxed") is None  # this plugin's renew names no address: the time was extended
        ours.stop("boxed")
        assert fake.containers == {} and ours.status("boxed") is None
        with pytest.raises(InstanceRefused, match="the platform refused instance stop for challenge 1: No instance found"):
            ours.stop("boxed")


def test_a_start_past_the_teams_cap_is_refused_as_full_with_the_plugins_words():
    with FakeCTFd(board()) as fake:
        fake.container_cap = 1
        ours = client(fake)
        ours.start("boxed")
        with pytest.raises(InstanceRefused, match=r"refused instance start for challenge 2: Max containers \(1\) reached") as caught:
            ours.start("second")
        assert caught.value.full and list(fake.containers) == [1]


def test_only_a_challenge_of_the_board_is_ever_asked_about():
    with FakeCTFd(board()) as fake:
        ours = client(fake, ids={"boxed": 1})
        with pytest.raises(InstanceError, match="second is not a challenge of this board"):
            ours.start("second")
        assert fake.to(REQUEST) == []  # no request was made


def test_a_challenge_with_no_container_is_refused_and_not_called_full():
    with FakeCTFd(board()) as fake:
        with pytest.raises(InstanceRefused, match="Challenge not found") as caught:
            client(fake).start("plain")
        assert not caught.value.full


@pytest.mark.parametrize(("reply", "message"), [
    (Reply(200, {"status": "created"}), "names no address"),
    (Reply(200, {"hostname": "bad host name", "port": 1}), "names no usable address"),
    (Reply(200, {"hostname": "h.example.test", "port": 70000}), "names no usable address"),
    (Reply(200, {"hostname": "h.example.test"}), "names no usable address"),
    (Reply(200, "<html>log in</html>"), "is not JSON"),
    (Reply(500, {"message": "boom"}), "the platform refused instance start for challenge 1: boom"),
    (Reply(200, {"success": False, "error": "disabled"}), "refused instance start for challenge 1: disabled"),
])
def test_an_answer_that_is_no_instance_is_an_error_never_an_instance(reply, message):
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, reply)
        with pytest.raises(InstanceError, match=message):
            client(fake).start("boxed")


def test_the_token_is_never_in_a_message_and_what_the_plugin_says_is_made_safe():
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, Reply(400, {"error": f"bad token {TOKEN} \x1b[31mred\nsecond line"}))
        with pytest.raises(InstanceRefused) as caught:
            client(fake).start("boxed")
    text = str(caught.value)
    assert TOKEN not in text and "\x1b" not in text and "\n" not in text and "[token]" in text


def test_no_answer_in_time_says_so_and_that_it_may_have_been_done():
    import threading

    with FakeCTFd(board()) as fake:
        gate = threading.Event()
        held = Reply(200, {"hostname": "h.example.test", "port": 1})
        held.hold = gate
        fake.script("POST", REQUEST, held)
        slow = InstanceClient(fake.base_url, TOKEN, {"boxed": 1}, parse_config(PLUGIN), timeout=0.3)
        with pytest.raises(InstanceError, match="no answer from the platform to instance start for challenge 1 .*; it may have been done"):
            slow.start("boxed")
        gate.set()


@pytest.mark.parametrize(("text", "parts"), [
    ("http://box.example.test:8080/", ("http", "box.example.test", 8080)),
    ("https://box.example.test", ("https", "box.example.test", None)),
    ("box.example.test:31337", (None, "box.example.test", 31337)),
    ("nc box.example.test 31337", (None, "box.example.test", 31337)),
    ("10.0.0.5", (None, "10.0.0.5", None)),
    ("box.example.test; rm -rf /", (None, None, None)),
    ("-oProxyCommand=x", (None, None, None)),
])
def test_an_address_is_read_out_of_a_url_a_host_and_port_or_an_nc_line(text, parts):
    assert _address(text) == parts


def test_the_plugins_own_scheme_wins_over_the_category():
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, Reply(200, {"url": "https://box.example.test:8443/app", "remaining": 600}))
        got = client(fake).start("second")
    assert isinstance(got, Instance) and got.url(web=False) == "https://box.example.test:8443"


# ---------------------------------------------------------------- the event profile


PROFILE = """
[event]
name = "Ev"
platform = "ctfd"
url = "https://ctf.example.test"
token_env = "CTFD_TOKEN"

[rules]
ai_allowed = true
platform_automation = true
live_targets = "allowed"
"""


def test_an_event_profile_reads_its_instances_table_and_says_when_it_does_nothing(tmp_path):
    from ctf_flightdeck import preflight

    path = tmp_path / "event.toml"
    path.write_text(PROFILE + '\n[instances]\nplugin = "docker_per_team"\ntypes = ["container"]\nmax_running = 2\n')
    profile, policies = preflight.load_profile(path)
    assert profile.instances is not None and profile.instances.max_running == 2 and profile.instances.types == ("container",)
    assert preflight.instances_off(profile, policies) == ""  # live_targets allowed: the instance policy is auto
    path.write_text(PROFILE.replace('"allowed"', '"confirm"') + '\n[instances]\nplugin = "docker_per_team"\n')
    profile, policies = preflight.load_profile(path)
    assert 'the instance policy is "confirm"' in preflight.instances_off(profile, policies)
    problems = preflight.check(profile, policies, max_lanes=None, environ={"CTFD_TOKEN": "x"})
    assert any("the [instances] table does nothing in this run" in p.message and not p.refuse for p in problems)
    path.write_text(PROFILE)
    assert preflight.load_profile(path)[0].instances is None


def test_a_bad_instances_table_in_a_profile_names_the_file_and_the_key(tmp_path):
    from ctf_flightdeck import preflight

    path = tmp_path / "event.toml"
    path.write_text(PROFILE + '\n[instances]\nplugin = "whale"\n')
    with pytest.raises(preflight.ProfileError, match="event.toml: instances.plugin whale is not a plugin flightdeck knows"):
        preflight.load_profile(path)


def test_the_example_profile_still_loads_and_shows_the_table_commented(tmp_path):
    from ctf_flightdeck import preflight

    path = tmp_path / "event.toml"
    path.write_text(preflight.example_profile())
    assert preflight.load_profile(path)[0].instances is None and "# [instances]" in preflight.example_profile()
