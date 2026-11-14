"""Instances on the http platform: rCTF v2's own instancer through [instances] plugin = "rctf",
asked with the [http] table's own sign-in (HttpCaller.instance_wire) and the challenges'
string ids, against tests/fake_http.py's FakeRCTF(v2=True) on 127.0.0.1. Nothing real is
contacted; every host and challenge is invented. The CTFd plugins' shapes are
tests/test_instances.py's and tests/test_instance_plugins.py's."""

from __future__ import annotations

import asyncio
import json

import pytest

from ctf_flightdeck.platform.http import HttpCaller, parse_config as parse_http
from ctf_flightdeck.platform.instances import (
    STATUS_TRIES, UNITS, InstanceClient, InstanceError, InstancePending, InstanceRefused, parse_config,
)
from ctf_flightdeck.plugins.board import pull_into

from fake_http import AUTH_TOKEN, TEAM_TOKEN, FakeRCTF, Instancer, RTask, answer

ROUTE = "/api/v2/integrations/challs/{}/instance"


def tasks() -> list[RTask]:
    return [
        RTask("pwn-box", "Pwn Box", category="pwn", instancer=Instancer()),
        RTask("web+api", "Web And Api", category="web", instancer=Instancer(
            endpoints=[("https", "web-7.chal.example.test", 443), ("tcp", "api-7.chal.example.test", 1337)])),
        RTask("plain-1", "Plain", category="misc"),
    ]


def connect(fake: FakeRCTF, *, naps: list | None = None, **table) -> tuple[HttpCaller, InstanceClient]:
    """A caller of the rctf2 preset and an instance client that goes through its wire: the
    board's ids are the challenges' own (strings), as a pull writes them."""
    caller = HttpCaller(parse_http({"preset": "rctf2"}), fake.url, TEAM_TOKEN)
    ids = {task.id.replace("+", "-"): task.id for task in fake.tasks.values()}
    client = InstanceClient(None, None, ids, parse_config({"plugin": "rctf", **table}), wire=caller.instance_wire(), timeout=5,
                            sleep=(naps if naps is not None else []).append)
    return caller, client


def instance_requests(fake: FakeRCTF) -> list[tuple[str, str]]:
    return [(r.method, r.path) for r in fake.of("instance")]


# ---------------------------------------------------------------- the shape


def test_rctfs_shape_is_one_route_with_four_methods_for_the_http_platform():
    config = parse_config({"plugin": "rctf"})
    path = "/api/v2/integrations/challs/{id}/instance"
    assert (config.routes.start, config.routes.status, config.routes.renew, config.routes.stop) == (
        ("PUT", path), ("GET", path), ("PATCH", path), ("DELETE", path))
    assert config.platform == "http" and config.routes.body_key is None and not config.routes.api and config.routes.empty_body
    assert config.answers.endpoints == ("endpoints",) and config.answers.state == ("status",)
    assert config.answers.running == ("running",) and config.answers.pending == ("starting", "stopping")
    assert config.answers.expires == ("timeLeftMilliseconds",) and config.answers.expires_unit == UNITS["ms"]
    assert parse_config({"plugin": "docker_per_team"}).platform == "ctfd"


@pytest.mark.parametrize(("table", "message"), [
    ({"plugin": "rctf", "expires_unit": "minutes"}, "instances.expires_unit must be one of s, ms"),
    ({"plugin": "rctf", "running_states": "running"}, "instances.running_states must be a list of up to 16 distinct words"),
    ({"plugin": "rctf", "pending_states": ["running"]}, "running_states and pending_states must not share a word"),
    ({"plugin": "docker_per_team", "running_states": ["up"]}, "running_states and pending_states need state_key"),
    ({"plugin": "chall_manager", "endpoints_key": "a b"}, "instances.endpoints_key must be a JSON key name"),
])
def test_a_bad_state_or_endpoints_key_is_named(table, message):
    with pytest.raises(ValueError, match=message):
        parse_config(table)


# ---------------------------------------------------------------- the wire


def test_the_instancer_is_asked_with_the_sign_ins_session_and_the_challenges_own_string_id():
    with FakeRCTF(tasks(), v2=True) as fake:
        _, client = connect(fake)
        assert client.status("pwn-box") is None  # "stopped": no instance
        got = client.start("pwn-box")
        assert fake.kinds() == ["login", "instance", "instance"]  # one sign-in, then the session for both
        status, start = fake.of("instance")
        assert (status.method, status.path, start.method, start.path) == ("GET", ROUTE.format("pwn-box"), "PUT", ROUTE.format("pwn-box"))
        assert {r.headers["authorization"] for r in fake.of("instance")} == {f"Bearer {AUTH_TOKEN}"}
        assert start.json == {} and status.body == b"" and "content-type" not in status.headers  # a GET carries no body
        assert all(TEAM_TOKEN not in json.dumps(r.headers) + r.path for r in fake.of("instance"))
    assert (got.scheme, got.host, got.port) == ("tcp", "pwn-1.chal.example.test", 31337)
    assert got.urls(web=True) == ("tcp://pwn-1.chal.example.test:31337",)  # rCTF says tcp: the category does not make it http


def test_a_string_id_is_percent_encoded_whole_and_a_dot_id_is_never_sent():
    with FakeRCTF(tasks(), v2=True) as fake:
        _, client = connect(fake)
        client.status("web-api")
        assert fake.of("instance")[0].path == ROUTE.format("web%2Bapi")
        client.ids["dots"] = ".."
        with pytest.raises(InstanceError, match="the challenge's id would name another route, so flightdeck did not send it"):
            client.status("dots")
        assert len(fake.of("instance")) == 1


def test_an_instance_with_several_endpoints_gives_every_address_in_order_and_its_end_in_milliseconds():
    with FakeRCTF(tasks(), v2=True) as fake:
        _, client = connect(fake)
        clock = client._clock()
        got = client.start("web-api")
    assert got.urls(web=True) == ("https://web-7.chal.example.test:443", "tcp://api-7.chal.example.test:1337")
    assert got.places() == (("web-7.chal.example.test", 443), ("api-7.chal.example.test", 1337))
    assert 599 <= got.expires_at - clock <= 601  # 600000 ms: ten minutes, not a week


def test_a_start_that_answers_starting_is_looked_at_until_it_runs():
    with FakeRCTF(tasks(), v2=True) as fake:
        fake.tasks["pwn-box"].instancer.slow = 1  # one look answers "starting", the next "running"
        naps: list = []
        _, client = connect(fake, naps=naps)
        got = client.start("pwn-box")
        assert [m for m, _ in instance_requests(fake)] == ["PUT", "GET", "GET"] and naps == [2.0]
    assert got.host == "pwn-1.chal.example.test"


def test_a_start_still_starting_after_its_looks_is_pending_and_may_be_done_and_its_status_says_so():
    with FakeRCTF(tasks(), v2=True) as fake:
        fake.tasks["pwn-box"].instancer.slow = STATUS_TRIES + 5
        _, client = connect(fake)
        with pytest.raises(InstancePending) as caught:
            client.start("pwn-box")
        assert caught.value.maybe_done and caught.value.up  # it holds a slot, and this client's start was taken
        assert [m for m, _ in instance_requests(fake)] == ["PUT"] + ["GET"] * STATUS_TRIES  # the start went once
        with pytest.raises(InstancePending, match="is on its way up or down on the platform \\(starting\\)") as later:
            client.status("pwn-box")
        assert not later.value.maybe_done


def test_a_tls_endpoint_is_left_out_by_name_and_an_instance_with_only_that_is_unusable():
    mixed = Instancer(endpoints=[("tcp-ssl", "tls-3.chal.example.test", 443), ("tcp", "pwn-3.chal.example.test", 1337)])
    only = Instancer(endpoints=[("tcp-ssl", "tls-4.chal.example.test", 443)])
    with FakeRCTF([RTask("mixed", "Mixed", instancer=mixed), RTask("only", "Only", instancer=only)], v2=True) as fake:
        _, client = connect(fake)
        got = client.start("mixed")
        assert got.urls(web=False) == ("tcp://pwn-3.chal.example.test:1337",)
        assert got.left_out == ("tls-3.chal.example.test:443 (tcp-ssl: a kind flightdeck cannot hand a lane yet)",)
        with pytest.raises(InstanceError, match="names no address flightdeck can use \\(tls-4.chal.example.test:443 \\(tcp-ssl") as caught:
            client.start("only")
        assert caught.value.up and caught.value.maybe_done  # it runs all the same, and it is this client's


def test_an_endpoint_that_is_not_a_host_and_a_port_is_never_taken():
    bad = Instancer(endpoints=[("tcp", "evil host;rm", 1), ("tcp", "ok.chal.example.test", 70000), ("http", "web.chal.example.test", 80)])
    with FakeRCTF([RTask("bad", "Bad", instancer=bad)], v2=True) as fake:
        _, client = connect(fake)
        got = client.start("bad")
    assert got.urls(web=False) == ("http://web.chal.example.test:80",) and len(got.left_out) == 2


def test_a_start_the_platform_guards_with_a_captcha_is_refused_by_name_for_a_person():
    with FakeRCTF(tasks(), v2=True, captcha=True) as fake:
        _, client = connect(fake)
        with pytest.raises(InstanceRefused) as caught:
            client.start("pwn-box")
        assert caught.value.human and not caught.value.full and not caught.value.maybe_done
        assert "The captcha verification failed." in str(caught.value)
        assert "start the instance on the site yourself, and flightdeck finds it there" in str(caught.value)
        assert client.status("pwn-box") is None  # the status wants no captcha


def test_a_refusal_says_the_answers_words_and_its_datas_why():
    with FakeRCTF(tasks(), v2=True) as fake:
        _, client = connect(fake)
        client.start("pwn-box")
        with pytest.raises(InstanceRefused, match="Instancer precondition not met.: Instance already running.") as caught:
            client.start("pwn-box")
        assert not caught.value.human


def test_a_challenge_with_no_instancer_has_no_instance_and_its_start_is_refused_in_rctfs_words():
    with FakeRCTF(tasks(), v2=True) as fake:
        _, client = connect(fake)
        assert client.status("plain-1") is None  # 404 badEndpoint
        with pytest.raises(InstanceRefused, match="The request endpoint could not be found."):
            client.start("plain-1")


@pytest.mark.parametrize("ref", [0, True, "", "line\nbreak", "x" * 129, 2.5])
def test_an_id_that_is_neither_a_ctfd_number_nor_a_ref_is_refused_when_it_is_put_in(ref):
    client = InstanceClient("https://ctf.example.test", "fake-token", {"ok": 1, "also": "a-ref"}, parse_config({"plugin": "rctf"}))
    with pytest.raises(ValueError, match="ids must map board ids"):
        client.ids.update({"bad": ref})
    with pytest.raises(ValueError, match="ids must map board ids"):
        InstanceClient("https://ctf.example.test", "fake-token", {"bad": ref}, parse_config({"plugin": "rctf"}))
    assert dict(client.ids) == {"ok": 1, "also": "a-ref"}


def test_the_session_never_shows_in_a_message():
    with FakeRCTF(tasks(), v2=True) as fake:
        fake.script("instance", answer(400, "badInstancerError", f"bad session {AUTH_TOKEN}", {"message": f"echo {AUTH_TOKEN}"}))
        _, client = connect(fake)
        with pytest.raises(InstanceRefused) as caught:
            client.start("pwn-box")
    assert AUTH_TOKEN not in str(caught.value) and "<token>" in str(caught.value)


def test_a_sign_in_that_fails_is_an_instance_error_and_nothing_else_is_sent():
    with FakeRCTF(tasks(), v2=True, team_token="another-team's-token") as fake:
        _, client = connect(fake)
        with pytest.raises(InstanceError, match="could not sign in") as caught:
            client.start("pwn-box")
        assert fake.kinds() == ["login"] and not caught.value.maybe_done


def test_renew_and_stop_go_to_the_same_route_and_renew_reads_the_new_end():
    with FakeRCTF(tasks(), v2=True) as fake:
        _, client = connect(fake)
        client.start("pwn-box")
        renewed = client.renew("pwn-box")
        client.stop("pwn-box")
        assert [m for m, _ in instance_requests(fake)] == ["PUT", "PATCH", "DELETE"]
        patch, delete = fake.of("instance")[1:]
        assert patch.json == {} and delete.body == b""
        assert fake.tasks["pwn-box"].instancer.status == "stopped"
    assert renewed is not None and renewed.expires_at is not None


# ---------------------------------------------------------------- the board


def test_the_rctf2_preset_marks_a_challenge_with_an_instancer_on_demand_on_the_board(tmp_path):
    with FakeRCTF(tasks(), v2=True) as fake:
        caller = HttpCaller(parse_http({"preset": "rctf2"}), fake.url, TEAM_TOKEN)
        asyncio.run(pull_into(caller, tmp_path / "board", plugin="http", url=fake.url))
        assert fake.kinds()[:2] == ["login", "challs2"]
    found = {json.loads(path.read_text())["name"]: json.loads(path.read_text()).get("instance")
             for path in (tmp_path / "board").glob("*/challenge.json")}
    assert found == {"Pwn Box": "on-demand", "Web And Api": "on-demand", "Plain": None}


@pytest.mark.parametrize(("value", "marked"), [(600000, True), ("yes", True), (None, False), (0, False), (False, False), ("", False)])
def test_the_instance_field_marks_a_challenge_by_any_value_but_an_empty_one(value, marked):
    caller = HttpCaller(parse_http({"preset": "rctf2"}), "https://ctf.example.test", TEAM_TOKEN)
    item = {"id": "x", "name": "X", "instancerLifetime": value}
    assert ("instance" in caller._challenge(item)) is marked
