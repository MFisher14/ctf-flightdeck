"""A challenge's own container through a CTFd container plugin: the [instances] table, and the
client against tests/fake_ctfd.py's docker_per_team routes on 127.0.0.1. Nothing real is asked.
The ctfd-owl and ctfd-chall-manager shapes are tests/test_instance_plugins.py's."""

from __future__ import annotations

import pytest

from ctf_flightdeck.platform.instances import (
    HOST_KEYS, PORT_KEYS, REMAINING_KEYS, STATUS_GAP, STATUS_TRIES, Answers, Instance, InstanceClient, InstanceError,
    InstanceRefused, Routes, _address, _ends, _within, parse_config,
)

from fake_ctfd import HANG_UP, TOKEN, FakeChallenge, FakeCTFd, Reply

PLUGIN = {"plugin": "docker_per_team", "types": ["container"]}
REQUEST = "/containers/api/request"
STATUS = "/containers/api/view_info"
OWN = {"start": ["POST", "/x/start?c={id}"], "stop": ["DELETE", "/x/stop?c={id}"], "renew": ["PATCH", "/x/renew?c={id}"],
       "status": ["GET", "/x?c={id}"]}  # a plugin flightdeck has no name for, as a profile gives its routes


def board() -> list[FakeChallenge]:
    return [FakeChallenge(1, "Boxed", category="Web", type="container"), FakeChallenge(2, "Second", category="Pwn", type="container"),
            FakeChallenge(3, "Plain", category="Misc")]


def client(fake: FakeCTFd, ids=None, naps=None, **config) -> InstanceClient:
    """`naps` collects the seconds the client would have slept: no test waits them."""
    table = config if "start" in config else {**PLUGIN, **config}
    return InstanceClient(fake.base_url, TOKEN, ids or {"boxed": 1, "second": 2, "plain": 3}, parse_config(table), timeout=5,
                          sleep=(naps if naps is not None else []).append)


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


def test_the_answers_keys_are_the_lists_as_they_were_unless_the_table_names_them():
    assert parse_config(OWN).answers == Answers(HOST_KEYS, PORT_KEYS, REMAINING_KEYS) == parse_config(PLUGIN).answers
    assert HOST_KEYS == ("hostname", "host", "ip", "connect", "url", "address") and PORT_KEYS == ("port",)
    assert REMAINING_KEYS == ("remaining_time", "remaining", "expires", "timeout")
    named = parse_config({**OWN, "address_key": "where", "port_key": ["tcp_port", "port"], "expires_key": "ends"})
    assert named.answers == Answers(("where",), ("tcp_port", "port"), ("ends",))
    assert parse_config({**OWN, "port_key": []}).answers.port == ()  # the address carries its own port
    over = parse_config({"plugin": "docker_per_team", "expires_key": "until"})  # a named plugin's keys can be named too
    assert over.answers == Answers(HOST_KEYS, PORT_KEYS, ("until",)) and over.routes.body_key == "chal_id"


def test_a_plugin_with_one_container_per_account_keeps_one_running():
    owl = parse_config({"plugin": "ctfd_owl"})
    assert owl.single and owl.max_running == 1 and owl.gap == 1.0
    assert parse_config({"plugin": "ctfd_owl", "max_running": 1}).max_running == 1
    with pytest.raises(ValueError, match="instances.max_running must be 1 with plugin ctfd_owl: it runs one container per account"):
        parse_config({"plugin": "ctfd_owl", "max_running": 3})
    whale = parse_config({"plugin": "ctfd_whale"})
    assert whale.single and whale.replaces and whale.max_running == 1 and whale.gap == 60.0 and whale.busy is not None
    with pytest.raises(ValueError, match="must be 1 with plugin ctfd_whale: it runs one container per account, and a start "
                                         "removes the one that runs"):
        parse_config({"plugin": "ctfd_whale", "max_running": 2})
    assert not owl.replaces and owl.busy is None  # owl's start refuses while anything runs: it takes nothing away
    others = [parse_config(table) for table in ({"plugin": "docker_per_team"}, {"plugin": "chall_manager"}, OWN)]
    assert [(c.single, c.max_running, c.gap, c.replaces, c.busy) for c in others] == [(False, 3, 0.0, False, None)] * 3


@pytest.mark.parametrize(("table", "message"), [
    ({}, "needs plugin .* or all four routes; missing: start, stop, renew, status"),
    ({"plugin": "whale"}, "is not a plugin flightdeck knows \\(known: docker_per_team, ctfd_owl, chall_manager, ctfd_whale\\)"),
    ({"plugin": ["ctfd_owl"]}, "is not a plugin flightdeck knows .*; give the four routes instead"),
    ({"plugin": "ctfd_docker"}, "instances.plugin ctfd_docker is no longer a plugin flightdeck knows: its routes were a guess .* "
                                "CTFd-Docker-Plugin and its forks are docker_per_team; for any other plugin give the four routes"),
    ({**OWN, "address_key": "data.where"}, "instances.address_key must be a JSON key name"),
    ({**OWN, "address_key": []}, "instances.address_key must name at least one key"),
    ({**OWN, "port_key": 80}, "instances.port_key must be a JSON key name"),
    ({**OWN, "expires_key": ["until", "until"]}, "instances.expires_key must be a JSON key name .* distinct"),
    ({**OWN, "error_key": "msg"}, "instances.error_key is not a key"),
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
    (Reply(200, {"status": "created"}), "neither its answer nor its status names an address"),
    (Reply(200, {"hostname": "bad host name", "port": 1}), "names no usable address"),
    (Reply(200, {"hostname": "h.example.test", "port": 70000}), "names no usable address"),
    (Reply(200, {"hostname": "h.example.test"}), "names no usable address"),
    (Reply(200, "<html>log in</html>"), "is not JSON"),
    (Reply(500, {"message": "boom"}), "the platform refused instance start for challenge 1: boom"),
    (Reply(200, {"success": False, "error": "disabled"}), "refused instance start for challenge 1: disabled"),
    (Reply(200, {"success": False, "msg": "not now"}), "refused instance start for challenge 1: not now"),  # not "HTTP 200"
    (Reply(200, {"success": False}), "refused instance start for challenge 1: HTTP 200"),
])
def test_an_answer_that_is_no_instance_is_an_error_never_an_instance(reply, message):
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, reply)
        with pytest.raises(InstanceError, match=message):
            client(fake).start("boxed")


def test_a_start_whose_own_answer_names_an_address_flightdeck_will_not_use_may_have_been_done():
    """The platform started the container: the run must take it for its own, and stop it."""
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, Reply(200, {"hostname": "chal_web.ctf.test", "port": 4000}))
        with pytest.raises(InstanceError, match="names no usable address") as caught:
            client(fake).start("boxed")
        assert caught.value.maybe_done and caught.value.up and not isinstance(caught.value, InstanceRefused)
        assert len(fake.to(REQUEST)) == 1 and fake.to(STATUS) == []


def test_a_start_that_answers_no_address_asks_the_status_and_is_sent_once():
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, Reply(200, {"success": True}))
        waiting = Reply(200, {"status": "Challenge not started"})
        fake.script("POST", STATUS, waiting, waiting, Reply(200, {"hostname": "late.example.test", "port": 4000, "expires": 900}))
        naps: list[float] = []
        got = client(fake, naps=naps).start("boxed")
        assert (got.host, got.port) == ("late.example.test", 4000) and got.expires_at is not None
        assert len(fake.to(REQUEST)) == 1 and len(fake.to(STATUS)) == 3 == STATUS_TRIES  # the start is never sent again
        assert naps == [STATUS_GAP, STATUS_GAP]  # the first status is asked at once


def test_a_start_whose_status_never_names_an_address_gives_up_with_the_plugins_words():
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, Reply(200, {"success": True, "msg": "queued \x1b[31mbehind 40 others"}))
        naps: list[float] = []
        with pytest.raises(InstanceError, match=r"took the start for boxed, but neither its answer nor its status names an "
                                                r"address \(queued .*behind 40 others\); is \[instances\] right") as caught:
            client(fake, naps=naps).start("boxed")
        assert not isinstance(caught.value, InstanceRefused) and "\x1b" not in str(caught.value)
        assert len(fake.to(REQUEST)) == 1 and len(fake.to(STATUS)) == STATUS_TRIES and naps == [STATUS_GAP] * (STATUS_TRIES - 1)


def test_a_status_that_refuses_after_a_start_is_the_error():
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, Reply(200, {"success": True}))
        fake.script("POST", STATUS, Reply(403, {"message": "Container already started but not from this challenge"}))
        with pytest.raises(InstanceRefused, match="refused instance status for challenge 1: Container already started"):
            client(fake).start("boxed")
        assert len(fake.to(STATUS)) == 1


def test_named_keys_are_the_only_ones_read():
    with FakeCTFd(board()) as fake:
        answer = {"success": True, "data": {"where": "named.example.test", "tcp_port": "4100", "ends": 120, "hostname": "wrong.example.test",
                                            "port": 1, "expires": 5}}
        fake.script("POST", "/api/v1/x/start", Reply(200, answer))
        fake.script("GET", "/api/v1/x", Reply(200, {"hostname": "wrong.example.test", "port": 1}), Reply(200, answer))
        ours = client(fake, **OWN, api=True, address_key="where", port_key="tcp_port", expires_key="ends")
        before = ours._clock()
        got = ours.start("boxed")
        assert (got.host, got.port) == ("named.example.test", 4100) and before + 119 < got.expires_at < before + 125
        assert ours.status("boxed") is None  # `hostname` is not the key this table names
        seen = ours.status("boxed")
        assert seen is not None and seen.host == "named.example.test"
        sent = fake.to("/api/v1/x/start")[0]
        assert sent.path == "/api/v1/x/start?c=1" and sent.body == b""  # the path carries the number: no body


def test_a_path_with_the_number_carries_no_body_and_one_without_it_the_body_key():
    with FakeCTFd(board()) as fake:
        routes = {**OWN, "start": ["POST", "/x/start"], "body_key": "challenge"}
        fake.script("POST", "/x/start", Reply(200, {"host": "h.example.test", "port": 9}))
        fake.script("GET", "/x", Reply(200, {"host": "h.example.test", "port": 9}))
        ours = client(fake, **routes)
        ours.start("second")
        ours.status("second")
        assert fake.to("/x/start")[0].json == {"challenge": 2}
        asked = fake.to("/x")[0]
        assert (asked.method, asked.path, asked.body) == ("GET", "/x?c=2", b"")


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
        with pytest.raises(InstanceError, match="no answer from the platform to instance start for challenge 1 .*; it may have been done") as caught:
            slow.start("boxed")
        gate.set()
    assert caught.value.maybe_done  # for a run: an instance of this challenge that turns up next is its own


@pytest.mark.parametrize(("start", "status", "maybe"), [
    (HANG_UP, None, True),  # the request went out and the line dropped: done or not, nobody said
    (Reply(200, "<html>a proxy's page</html>"), None, True),  # an answer, and not the plugin's: the plugin may have acted
    (Reply(200, {"success": True}), Reply(200, {"status": "Challenge not started"}), True),  # taken, and no address yet
    (Reply(200, {"success": True}), Reply(403, {"message": "not now"}), True),  # taken, and the status refuses
    (Reply(400, {"error": "image build failed"}), None, False),  # the plugin said no
    (Reply(200, {"success": False, "msg": "You have boot Second before."}), None, False),
    (Reply(302, "<html>log in</html>"), None, False),  # sent to the login page: the plugin was never asked
    (Reply(200, {"hostname": "h.example.test", "port": 70000}), None, True),  # started, at an address flightdeck will not use
])
def test_a_failed_start_says_whether_the_platform_may_have_done_it(start, status, maybe):
    with FakeCTFd(board()) as fake:
        fake.script("POST", REQUEST, start)
        if status is not None:
            fake.script("POST", STATUS, status, status, status)
        with pytest.raises(InstanceError) as caught:
            client(fake).start("boxed")
        assert caught.value.maybe_done is maybe, str(caught.value)


def test_a_start_that_never_left_was_not_done():
    with FakeCTFd(board()) as fake:
        ours = client(fake)
    with pytest.raises(InstanceError, match="no answer from the platform to instance start for challenge 1") as caught:
        ours.start("boxed")  # the site is gone: nothing connects
    assert not caught.value.maybe_done and "it may have been done" not in str(caught.value)
    with pytest.raises(InstanceError) as caught:
        ours.start("not-on-the-board")
    assert not caught.value.maybe_done


@pytest.mark.parametrize(("text", "parts"), [
    ("http://box.example.test:8080/", ("http", "box.example.test", 8080)),
    ("https://box.example.test", ("https", "box.example.test", None)),
    ("box.example.test:31337", (None, "box.example.test", 31337)),
    ("nc box.example.test 31337", (None, "box.example.test", 31337)),
    ("10.0.0.5", (None, "10.0.0.5", None)),
    ("box.example.test; rm -rf /", (None, None, None)),
    ("challenge:1337", (None, "challenge", 1337)),  # the whole answer is host:port: a name with no dot is a host there
    ("-oProxyCommand=x", (None, None, None)),
])
def test_an_address_is_read_out_of_a_url_a_host_and_port_or_an_nc_line(text, parts):
    assert _address(text) == parts


@pytest.mark.parametrize(("text", "parts"), [
    ("curl -v http://box.example.test:8080/health", ("http", "box.example.test", 8080)),
    ('<a target="_blank" href="https://box.example.test/">Link to the Challenge</a>', ("https", "box.example.test", None)),
    ("Connect with: nc box.example.test 31337 (TCP)", (None, "box.example.test", 31337)),
    ("socat - tcp:box.example.test:31337", (None, "box.example.test", 31337)),
    ("the service listens on 10.0.0.5:9000.", (None, "10.0.0.5", 9000)),
    ("ssh ctf@box.example.test -p 2222", (None, None, None)),  # no form flightdeck reads: an error, never a guess
    ("ask an admin", (None, None, None)),
    ("http://bad_host$(id):80", (None, None, None)),
    # a URL's name and password are not its host: the host is what follows the last @
    ("http://ctf:s3cret@box.example.test/", ("http", "box.example.test", None)),
    ("curl -u x http://admin:1234@box.example.test:8080/login", ("http", "box.example.test", 8080)),
    ("http://ctf@box.example.test:8080", ("http", "box.example.test", 8080)),
    ("open http://box.example.test:8080.", ("http", "box.example.test", 8080)),  # the sentence's full stop is not the address's
    ("(see https://box.example.test:8443)", ("https", "box.example.test", 8443)),
    ("http://box.example.test:8080abc", (None, None, None)),  # a port with letters after it is no port: no part of it is taken
    ("http://box.example.test:80:90/", (None, None, None)),
    ("http://ctf:1234@/", (None, None, None)),
    # a word and a number with a colon between them is not a host and a port: a time, a name and password, a version
    ("ssh -p 2222 ctf@box.example.test (up since 12:30)", (None, None, None)),
    ("ssh ctf@box.example.test -p 2222, password ctf:1234", (None, None, None)),
    ("ssh box.example.test -l ctf -p 2222 # login ctf.player:1234@box", (None, None, None)),
    ("build 1.5:30 of the service, started 2026.11.14:12", (None, None, None)),
    ("the box is at challenge:1337", (None, None, None)),  # in a sentence, only a dotted name or an IPv4 address is a host
    ("up since 12:30 at box.example.test:31337", (None, "box.example.test", 31337)),
    ("nc box 31337", (None, "box", 31337)),  # after nc the word is a host, dotted or not
])
def test_an_address_is_found_in_a_line_a_person_wrote(text, parts):
    assert _within(text) == parts


@pytest.mark.parametrize(("said", "ends"), [
    (600, 1600.0),  # a small number: seconds left
    (600.5, 1600.5),
    ("600", 1600.0),
    (1_800_000_000, 1_800_000_000.0),  # a large one: the moment itself
    ("2026-11-14T12:00:00Z", 1794657600.0),
    ("2026-11-14T12:00:00.123456789Z", 1794657600.123456),  # nanoseconds, as an RFC 3339 writer may send
    ("2026-11-14T13:00:00+01:00", 1794657600.0),
    ("2026-11-14 12:00:00", 1794657600.0),  # no zone: read as UTC
    (0, None), (-5, None), (True, None), (float("inf"), None), (None, None), ("soon", None), ("", None), ([600], None),
])
def test_an_end_is_seconds_left_a_moment_or_a_timestamp(said, ends):
    assert _ends(said, 1000.0) == ends


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
    path.write_text(PROFILE + '\n[instances]\nplugin = "ctfd_docker"\n')  # a profile written for an earlier flightdeck
    with pytest.raises(preflight.ProfileError, match="event.toml: instances.plugin ctfd_docker is no longer a plugin flightdeck knows"):
        preflight.load_profile(path)


@pytest.mark.parametrize(("table", "expected"), [
    ('plugin = "ctfd_owl"\ntypes = ["dynamic_check_docker"]', ("ctfd_owl", ("dynamic_check_docker",), 1)),
    ('plugin = "chall_manager"\ntypes = ["dynamic_iac"]\nmax_running = 4', ("chall_manager", ("dynamic_iac",), 4)),
    ('start = ["POST", "/p/c?id={id}"]\nstop = ["DELETE", "/p/c?id={id}"]\nrenew = ["PATCH", "/p/c?id={id}"]\n'
     'status = ["GET", "/p/c?id={id}"]\naddress_key = ["ip", "domain"]\nexpires_key = "until"', (None, (), 3)),
])
def test_an_event_profile_takes_the_new_plugins_and_the_named_keys(tmp_path, table, expected):
    from ctf_flightdeck import preflight

    path = tmp_path / "event.toml"
    path.write_text(PROFILE + "\n[instances]\n" + table + "\n")
    config = preflight.load_profile(path)[0].instances
    assert config is not None and (config.plugin, config.types, config.max_running) == expected


def test_the_example_profile_still_loads_and_shows_the_table_commented(tmp_path):
    from ctf_flightdeck import preflight

    path = tmp_path / "event.toml"
    path.write_text(preflight.example_profile())
    assert preflight.load_profile(path)[0].instances is None and "# [instances]" in preflight.example_profile()
