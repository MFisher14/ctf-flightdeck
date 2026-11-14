"""The ctfd_owl and chall_manager shapes of [instances], against fakes of the two plugins
shaped from their public source (tests/fake_instance_plugins.py) inside the fake CTFd on
127.0.0.1. Nothing real is asked, and neither plugin was run: these tests show flightdeck
against what the plugins' code says, not against a site."""

from __future__ import annotations

import pytest

from ctf_flightdeck.platform.instances import InstanceClient, InstanceError, InstanceRefused, parse_config

from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd
from fake_instance_plugins import CHALL_MANAGER_ROUTE, CHALL_MANAGER_TYPE, OWL_ROUTE, OWL_TYPE

IDS = {"boxed": 1, "second": 2, "plain": 3}
START = 1_794_650_000.0  # the fakes' clock starts here, in whole seconds


class Clock:
    """One clock for the plugin and the client: a sleep moves it, and nothing waits."""

    def __init__(self) -> None:
        self.now = START
        self.naps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.naps.append(seconds)
        self.now += seconds


def board(kind: str) -> list[FakeChallenge]:
    return [FakeChallenge(1, "Boxed", category="Web", type=kind), FakeChallenge(2, "Second", category="Pwn", type=kind),
            FakeChallenge(3, "Plain", category="Misc")]


def client(fake: FakeCTFd, plugin: str, clock: Clock, **table) -> InstanceClient:
    fake.owl.clock = fake.chall_manager.clock = clock.time
    return InstanceClient(fake.base_url, TOKEN, IDS, parse_config({"plugin": plugin, **table}), timeout=5,
                          clock=clock.time, sleep=clock.sleep, monotonic=clock.time)


def asked(fake: FakeCTFd, route: str) -> list[tuple[str, str]]:
    return [(r.method, r.path) for r in fake.to(route)]


# ---------------------------------------------------------------- ctfd-owl


def test_owl_a_start_names_no_address_so_the_status_gives_it():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        got = client(fake, "ctfd_owl", clock).start("second")
        assert (got.host, got.port, got.scheme) == ("198.51.100.7", 28001, None) and got.url(web=False) == "tcp://198.51.100.7:28001"
        assert got.expires_at == START + 3600  # remaining_time: the seconds left
        assert asked(fake, OWL_ROUTE) == [("POST", f"{OWL_ROUTE}?challenge_id=2"), ("GET", f"{OWL_ROUTE}?challenge_id=2")]
        assert all(r.body == b"" and r.headers["authorization"] == f"Token {TOKEN}" for r in fake.to(OWL_ROUTE))
        assert clock.naps == []  # the status had it at once


@pytest.mark.parametrize(("port", "url"), [(80, "http://box0001.owl.example.test"), (8080, "http://box0001.owl.example.test:8080")])
def test_owl_a_domain_is_a_web_address_whatever_the_category(port, url):
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        fake.owl.http, fake.owl.http_port = {2}, port
        got = client(fake, "ctfd_owl", clock).start("second")  # a pwn challenge: tcp, had the plugin not said http
        assert got.url(web=False) == url == got.url(web=True) and got.scheme == "http"


def test_owl_status_is_none_with_nothing_running_and_for_another_challenges_container():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        ours = client(fake, "ctfd_owl", clock)
        assert ours.status("boxed") is None  # {"success": true}
        fake.owl.boot(2)  # a teammate's
        assert ours.status("boxed") is None  # {}: the account's container is another challenge's
        theirs = ours.status("second")
        assert theirs is not None and theirs.port == 28001


def test_owl_a_refusal_is_read_from_msg_and_one_container_per_account_is_the_cap():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        ours = client(fake, "ctfd_owl", clock)
        fake.owl.boot(2)
        with pytest.raises(InstanceRefused, match=r"the platform refused instance start for challenge 1: You have boot Second before\.") as caught:
            ours.start("boxed")
        assert caught.value.full and fake.owl.container["challenge"] == 2  # theirs still runs
        fake.owl.container, fake.owl.max_containers, fake.owl.others = None, 10, 10
        clock.sleep(5)
        with pytest.raises(InstanceRefused, match="refused instance start for challenge 1: Max container count exceed") as caught:
            ours.start("boxed")
        assert caught.value.full
        fake.owl.max_containers = None
        clock.sleep(5)
        with pytest.raises(InstanceRefused, match="refused instance start for challenge 3: 404 Not Found") as caught:
            ours.start("plain")  # not an owl challenge: the plugin's 404, sent as msg with HTTP 200
        assert not caught.value.full


def test_owl_a_launch_that_failed_is_answered_as_success_and_is_an_error_with_its_words():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        fake.owl.launch_fails = True
        with pytest.raises(InstanceError, match=r"neither its answer nor its status names an address \(Failed when launch instance, "
                                                r"please contact with the admin\.\)"):
            client(fake, "ctfd_owl", clock).start("boxed")
        assert [method for method, _ in asked(fake, OWL_ROUTE)] == ["POST", "GET", "GET", "GET"] and clock.naps == [2.0, 2.0]


def test_owl_a_stop_asks_first_and_never_takes_another_challenges_container():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        ours = client(fake, "ctfd_owl", clock)
        fake.owl.boot(2)  # a teammate's container of another challenge: owl's stop route would destroy it
        ours.stop("boxed")
        assert fake.owl.container is not None and fake.owl.container["challenge"] == 2
        assert asked(fake, OWL_ROUTE) == [("GET", f"{OWL_ROUTE}?challenge_id=1")]  # no DELETE was sent
        ours.stop("second")
        assert fake.owl.container is None and asked(fake, OWL_ROUTE)[-1] == ("DELETE", f"{OWL_ROUTE}?challenge_id=2")


def test_owl_a_stop_takes_this_challenges_container_even_at_an_address_flightdeck_will_not_use():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        ours = client(fake, "ctfd_owl", clock)
        fake.owl.direct_ip = "box_1.owl.example.test"  # an underscore: no host name flightdeck will use
        fake.owl.boot(1)
        with pytest.raises(InstanceError, match="names no usable address") as caught:
            ours.status("boxed")
        assert caught.value.up
        ours.stop("boxed")
        assert fake.owl.container is None and asked(fake, OWL_ROUTE)[-1] == ("DELETE", f"{OWL_ROUTE}?challenge_id=1")


def test_owl_a_renew_puts_the_hour_back_until_the_plugin_says_no_more():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        fake.owl.max_renews = 1
        ours = client(fake, "ctfd_owl", clock)
        first = ours.start("boxed")
        clock.sleep(3000)
        assert ours.status("boxed").expires_at == first.expires_at
        assert ours.renew("boxed") is None  # the answer names no address: the status has the rest
        assert ours.status("boxed").expires_at == clock.now + 3600
        clock.sleep(5)
        with pytest.raises(InstanceRefused, match="refused instance renew for challenge 1: Max renewal times exceed"):
            ours.renew("boxed")


def test_owl_two_changes_in_the_same_second_are_spaced_by_the_client():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        ours = client(fake, "ctfd_owl", clock)
        ours.start("boxed")
        ours.stop("boxed")  # at once: the plugin would refuse a second change within the second
        ours.start("second")
        assert clock.naps == [1.0, 1.0] and fake.owl.container["challenge"] == 2
        assert [method for method, _ in asked(fake, OWL_ROUTE)] == ["POST", "GET", "GET", "DELETE", "POST", "GET"]


def test_owl_refuses_changes_that_come_too_close_and_says_so_in_msg():
    clock = Clock()
    with FakeCTFd(board(OWL_TYPE)) as fake:
        ours = client(fake, "ctfd_owl", clock)
        ours._sleep = lambda seconds: None  # a client that does not wait, to show what the plugin then says
        ours.start("boxed")
        with pytest.raises(InstanceRefused, match=r"refused instance stop for challenge 1: Frequency limit, You should wait at least 1 min\."):
            ours.stop("boxed")
        assert fake.owl.container is not None


# ---------------------------------------------------------------- ctfd-chall-manager


def test_chall_manager_a_start_gives_the_address_and_the_end_as_a_timestamp():
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        ours = client(fake, "chall_manager", clock)
        assert ours.status("boxed") is None  # the manager's 404: no instance
        got = ours.start("boxed")
        assert (got.host, got.port, got.scheme) == ("cm.example.test", 30001, None) and got.expires_at == START + 600
        assert got.url(web=True) == "http://cm.example.test:30001" and got.url(web=False) == "tcp://cm.example.test:30001"
        seen = ours.status("boxed")
        assert seen == got and seen.expires_at == START + 600
        status, start, again = fake.to(CHALL_MANAGER_ROUTE)
        assert (status.method, status.path, status.body) == ("GET", f"{CHALL_MANAGER_ROUTE}?challengeId=1", b"")
        assert (start.method, start.path, start.json) == ("POST", CHALL_MANAGER_ROUTE, {"challengeId": 1})
        assert again.path == status.path and clock.naps == []


def test_chall_manager_renew_and_stop_carry_the_number_in_the_body():
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        ours = client(fake, "chall_manager", clock)
        ours.start("boxed")
        clock.sleep(400)
        assert ours.renew("boxed") is None  # {"data": {"message": "Your instance has been renewed !"}}: not an error, no address
        assert ours.status("boxed").expires_at == START + 400 + 600
        ours.stop("boxed")
        assert fake.chall_manager.instances == {} and ours.status("boxed") is None
        assert [(r.method, r.json) for r in fake.to(CHALL_MANAGER_ROUTE) if r.method in ("PATCH", "DELETE")] == [
            ("PATCH", {"challengeId": 1}), ("DELETE", {"challengeId": 1})]
        with pytest.raises(InstanceRefused, match="refused instance stop for challenge 1: error while deleting instance, contact admins"):
            ours.stop("boxed")


def test_chall_manager_an_instance_with_no_timeout_has_no_end():
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        fake.chall_manager.seconds = None
        assert client(fake, "chall_manager", clock).start("boxed").expires_at is None


@pytest.mark.parametrize(("line", "url"), [
    ("http://{host}:{port}", "http://cm.example.test:30001"),
    ("curl -v https://{host}:{port}/", "https://cm.example.test:30001"),
    ('<a href="http://{host}:{port}/">open the challenge</a>', "http://cm.example.test:30001"),
    ("Connect with: nc {host} {port}", "tcp://cm.example.test:30001"),
    ("{host}:{port}", "tcp://cm.example.test:30001"),
])
def test_chall_manager_the_address_is_found_in_the_organisers_line(line, url):
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        fake.chall_manager.connection = line
        assert client(fake, "chall_manager", clock).start("second").url(web=False) == url


def test_chall_manager_a_line_with_no_address_flightdeck_reads_is_an_error_that_shows_it():
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        fake.chall_manager.connection = "ssh ctf@{host} -p {port} \x1b[2J"
        with pytest.raises(InstanceError, match=r"names no usable address \(ssh ctf@cm\.example\.test -p 30001") as caught:
            client(fake, "chall_manager", clock).start("boxed")
        assert "\x1b" not in str(caught.value)


@pytest.mark.parametrize("line", [
    "ssh -p {port} ctf@{host} (up since 12:30)",  # a time
    "ssh ctf@{host} -p {port}, password ctf:1234",  # a name and a password
])
def test_chall_manager_a_stray_word_and_number_in_the_line_is_never_taken_for_the_address(line):
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        fake.chall_manager.connection = line
        with pytest.raises(InstanceError, match=r"names no usable address \(ssh .*cm\.example\.test"):
            client(fake, "chall_manager", clock).start("boxed")


def test_chall_manager_a_url_with_a_name_and_password_gives_its_host_not_the_name():
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        fake.chall_manager.connection = "http://admin:1234@{host}:{port}/"
        got = client(fake, "chall_manager", clock).start("boxed")
        assert (got.scheme, got.host, got.port) == ("http", "cm.example.test", 30001)
        assert "admin:1234@cm.example.test" in got.said  # the organiser's line, for the player


def test_chall_manager_refusals_mana_is_the_cap_and_the_rest_is_not():
    clock = Clock()
    with FakeCTFd(board(CHALL_MANAGER_TYPE)) as fake:
        fake.chall_manager.mana_total, fake.chall_manager.mana_cost = 5, 5
        ours = client(fake, "chall_manager", clock)
        ours.start("boxed")
        with pytest.raises(InstanceRefused, match=r"refused instance start for challenge 2: You or your team used up all your mana\.") as caught:
            ours.start("second")
        assert caught.value.full and list(fake.chall_manager.instances) == [1]
        fake.chall_manager.mana_total = 0
        with pytest.raises(InstanceRefused, match="refused instance start for challenge 1: instance already exists") as caught:
            ours.start("boxed")  # HTTP 200 with success false: a run asks the status first and never sends this
        assert not caught.value.full
        with pytest.raises(InstanceRefused, match="refused instance start for challenge 3: Internal Server Error"):
            ours.start("plain")  # not a chall-manager challenge
        fake.challenges[2].type = "hidden"
        with pytest.raises(InstanceRefused, match="refused instance status for challenge 2: challenge not visible"):
            ours.status("second")  # a 403 is a refusal, not "no instance"
