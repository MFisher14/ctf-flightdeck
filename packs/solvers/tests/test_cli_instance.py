"""B-003: the `ctf instance` CLI (ctf/cli/instance.py) against a fake instance gate."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field

import pytest
import requests

from ctf import env, event, instsched
from ctf.cli import instance as cli
from ctf.cli import main as cli_main
from ctf.platform import NotSupported, PlatformError, SubmitGate, get_adapter, supports_instances
from platform_fixture_session import FakeSession, load


@pytest.fixture(autouse=True)
def _workdir(tmp_path, monkeypatch):
    """The slot ledger lives under the event workdir: keep it in the test's tmp dir."""
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))


# --------------------------------------------------------------------------------- fakes
@dataclass
class _Ch:
    id: str
    points: int = 0
    tags: tuple = ()
    solved_by_team: bool = False


@dataclass
class _Info:
    challenge_id: str
    state: str
    connection_info: str = ""
    expires_at: float | None = None


class FakeGate:
    """Implements the InstanceCapability methods, so supports_instances() is True."""
    kind = "ctfd"

    def __init__(self, board, running=(), fail_status=(), expires=None):
        self.board = board
        self._running = {str(x) for x in running}
        self._fail_status = {str(x) for x in fail_status}
        self._expires = {str(k): v for k, v in (expires or {}).items()}
        self.started: list[str] = []
        self.stopped: list[str] = []
        self.renewed: list[str] = []

    def list_challenges(self):
        return self.board

    def instance_status(self, cid):
        cid = str(cid)
        if cid in self._fail_status:
            raise PlatformError(f"status blew up for {cid}")
        running = cid in self._running
        return _Info(cid, "running" if running else "stopped",
                     f"host:{cid}" if running else "",
                     expires_at=self._expires.get(cid, 900.0) if running else None)

    def start_instance(self, cid):
        cid = str(cid)
        self.started.append(cid)
        self._running.add(cid)
        return _Info(cid, "running", f"host:{cid}", expires_at=3600.0)

    def stop_instance(self, cid):
        cid = str(cid)
        self.stopped.append(cid)
        self._running.discard(cid)
        return _Info(cid, "stopped")

    def renew_instance(self, cid):
        self.renewed.append(str(cid))
        return _Info(str(cid), "running", f"host:{cid}", expires_at=3600.0)


@dataclass
class _StubProfile:
    slug: str = "demo"
    instances: object = field(default_factory=lambda: type("I", (), {"cap": 2})())


def _args(**kw):
    base = dict(event=None, profile=None, json=False)
    base.update(kw)
    return argparse.Namespace(**base)


# --------------------------------------------------------------------------------- schedule
def _board():
    return [_Ch("1", 100, tags=("container",)), _Ch("2", 500, tags=("web", "container")),
            _Ch("3", 300, tags=("container",), solved_by_team=True), _Ch("9", 999, tags=("crypto",))]


def test_schedule_starts_top_value_and_releases_solved(capsys):
    gate = FakeGate(_board(), running=["3"])      # challenge 3 is solved AND running -> release it
    args = _args(action="schedule", challenge=None, cap=2, renew_within=None, dry_run=False)
    rc = cli._cmd_schedule(args, gate, _StubProfile())
    assert rc == 0
    assert gate.stopped == ["3"]                  # slot freed on solve
    assert gate.started == ["2", "1"]             # highest value first, within cap 2
    out = capsys.readouterr().out
    assert "start 2: ok  host:2" in out


def test_schedule_dry_run_touches_nothing(capsys):
    gate = FakeGate(_board())
    args = _args(action="schedule", challenge=None, cap=1, renew_within=None, dry_run=True)
    rc = cli._cmd_schedule(args, gate, _StubProfile())
    assert rc == 0 and gate.started == [] and gate.stopped == []
    assert "start ['2']" in capsys.readouterr().out    # cap 1 -> only the top one planned


def test_schedule_explicit_challenge_overrides_tags(capsys):
    gate = FakeGate(_board())
    # name challenge 9 (crypto, untagged) explicitly; it must be scheduled, tagged ones ignored
    args = _args(action="schedule", challenge=["9"], cap=3, renew_within=None, dry_run=True)
    cli._cmd_schedule(args, gate, _StubProfile())
    assert "start ['9']" in capsys.readouterr().out


def test_schedule_no_container_challenges_is_rc1(capsys):
    gate = FakeGate([_Ch("9", 999, tags=("crypto",))])
    args = _args(action="schedule", challenge=None, cap=2, renew_within=None, dry_run=False)
    assert cli._cmd_schedule(args, gate, _StubProfile()) == 1
    assert "no container challenges selected" in capsys.readouterr().err


def test_schedule_reports_a_failed_start_as_rc1(capsys, monkeypatch):
    gate = FakeGate(_board())

    def boom(cid):
        raise PlatformError(f"plugin refused {cid}")
    monkeypatch.setattr(gate, "start_instance", boom)
    args = _args(action="schedule", challenge=None, cap=2, renew_within=None, dry_run=False)
    assert cli._cmd_schedule(args, gate, _StubProfile()) == 1
    assert "FAILED" in capsys.readouterr().err


# --------------------------------------------------------------------------------- list / stop-all
def test_list_sweeps_state(capsys):
    gate = FakeGate(_board(), running=["2"])
    rc = cli._cmd_list(_args(action="list"), gate, _StubProfile())
    assert rc == 0
    out = capsys.readouterr().out
    assert "running" in out and "host:2" in out and "cap: 2" in out


def test_list_survives_a_status_error(capsys):
    gate = FakeGate(_board(), running=["2"], fail_status=["1"])
    assert cli._cmd_list(_args(action="list"), gate, _StubProfile()) == 0
    assert "status 1" in capsys.readouterr().err


def test_stop_all_stops_only_running(capsys):
    gate = FakeGate(_board(), running=["1", "2"])
    rc = cli._cmd_stop_all(_args(action="stop-all"), gate, _StubProfile())
    assert rc == 0 and sorted(gate.stopped) == ["1", "2"]


# --------------------------------------------------------------------------------- single ops
def test_one_start_prints_connect(capsys):
    gate = FakeGate(_board())
    assert cli._one(gate, "start", "2", False, _StubProfile()) == 0
    assert "host:2" in capsys.readouterr().out
    assert gate.started == ["2"]


def test_one_renew_requires_route():
    gate = FakeGate(_board())
    del_gate = FakeGate(_board())
    object.__setattr__(del_gate, "renew_instance", None)   # a plugin with no renew route
    from ctf.platform import NotSupported
    with pytest.raises(NotSupported):
        cli._one(del_gate, "renew", "1", False)


# --------------------------------------------------------------------------------- run() dispatch
def test_run_permissions_needs_no_platform(capsys):
    rc = cli.run(_args(action="permissions", python="py"))
    assert rc == 0
    out = capsys.readouterr().out
    assert '"Bash(py -m ctf instance start:*)"' in out
    assert '"Bash(py -m ctf instance:*)"' not in out          # no whole-CLI catch-all


def test_run_refuses_when_no_instance_plugin(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_profile", lambda a: _StubProfile())
    monkeypatch.setattr(cli, "get_adapter", lambda p: object())   # not an InstanceCapability
    rc = cli.run(_args(action="start", id="1"))
    assert rc == cli.REFUSED_EXIT
    assert "refused" in capsys.readouterr().err


def test_run_start_through_dispatch(capsys, monkeypatch):
    gate = FakeGate(_board())
    monkeypatch.setattr(cli, "_profile", lambda a: _StubProfile())
    monkeypatch.setattr(cli, "get_adapter", lambda p: gate)
    rc = cli.run(_args(action="start", id="2"))
    assert rc == 0 and gate.started == ["2"]


# --------------------------------------------------------------------------------- schedule --renew-within
def _sched_args(**kw):
    base = dict(action="schedule", challenge=None, cap=3, renew_within=None, dry_run=False)
    base.update(kw)
    return _args(**base)


def test_schedule_renews_near_expiry_running_unsolved_only(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_now", lambda: 10_000.0)
    # 1 expires in 60 s (renew), 2 in 1800 s (leave), 3 is solved+running (stopped, never renewed)
    gate = FakeGate(_board(), running=["1", "2", "3"],
                    expires={"1": 10_060.0, "2": 11_800.0, "3": 10_010.0})
    rc = cli._cmd_schedule(_sched_args(renew_within=120), gate, _StubProfile())
    assert rc == 0
    assert gate.renewed == ["1"]
    assert gate.stopped == ["3"]
    assert "renew 1: ok  host:1" in capsys.readouterr().out


def test_schedule_without_renew_within_renews_nothing(monkeypatch):
    monkeypatch.setattr(cli, "_now", lambda: 10_000.0)
    gate = FakeGate(_board(), running=["1"], expires={"1": 10_001.0})
    assert cli._cmd_schedule(_sched_args(), gate, _StubProfile()) == 0
    assert gate.renewed == []


def test_schedule_dry_run_lists_renewals_and_renews_nothing(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_now", lambda: 10_000.0)
    gate = FakeGate(_board(), running=["1", "2"], expires={"1": 10_030.0, "2": 99_999.0})
    rc = cli._cmd_schedule(_sched_args(renew_within=60, dry_run=True, json=True), gate, _StubProfile())
    assert rc == 0 and gate.renewed == []
    assert json.loads(capsys.readouterr().out)["to_renew"] == ["1"]


def test_schedule_renew_within_without_a_renew_route_is_refused():
    gate = FakeGate(_board(), running=["1"])
    object.__setattr__(gate, "renew_instance", None)
    with pytest.raises(NotSupported, match="renew route"):
        cli._cmd_schedule(_sched_args(renew_within=60), gate, _StubProfile())


def test_schedule_reports_a_failed_renewal_as_rc1(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_now", lambda: 10_000.0)
    gate = FakeGate(_board(), running=["1"], expires={"1": 10_005.0})

    def boom(cid):
        raise PlatformError(f"renew refused {cid}")
    monkeypatch.setattr(gate, "renew_instance", boom)
    assert cli._cmd_schedule(_sched_args(renew_within=60), gate, _StubProfile()) == 1
    assert "renew 1: FAILED" in capsys.readouterr().err


# --------------------------------------------------------------------------------- cap across processes
def test_start_cap_binds_across_separate_invocations():
    gate = FakeGate(_board())                      # one plugin, several CLI processes
    prof = _StubProfile()                           # cap 2
    assert cli._one(gate, "start", "1", False, prof) == 0
    assert cli._one(gate, "start", "2", False, prof) == 0
    with pytest.raises(instsched.CapReached, match="1, 2"):
        cli._one(gate, "start", "9", False, prof)
    assert gate.started == ["1", "2"]
    cli._one(gate, "stop", "1", False, prof)       # frees a slot for the next process
    assert cli._one(gate, "start", "9", False, prof) == 0
    assert gate.started == ["1", "2", "9"]


def test_run_maps_cap_reached_to_exit_1(capsys, monkeypatch):
    gate = FakeGate(_board())
    monkeypatch.setattr(cli, "_profile", lambda a: _StubProfile())
    monkeypatch.setattr(cli, "get_adapter", lambda p: gate)
    assert cli.run(_args(action="start", id="1")) == 0
    assert cli.run(_args(action="start", id="2")) == 0
    assert cli.run(_args(action="start", id="9")) == cli.CAP_EXIT == 1
    assert "local instance cap" in capsys.readouterr().err
    assert gate.started == ["1", "2"]


def test_schedule_counts_a_ledger_slot_on_an_untagged_challenge():
    gate = FakeGate(_board())
    prof = _StubProfile()                           # cap 2
    cli._one(gate, "start", "9", False, prof)       # 9 is a crypto (untagged) challenge
    rc = cli._cmd_schedule(_sched_args(cap=2), gate, prof)
    assert rc == 0
    assert gate.started == ["9", "2"]               # only one slot was left: the top tagged challenge


def test_schedule_keeps_an_unreadable_ledger_slot_counted_and_drops_a_stopped_one(capsys):
    gate = FakeGate(_board())
    prof = _StubProfile()                           # cap 2
    cli._one(gate, "start", "9", False, prof)
    cli._one(gate, "start", "1", False, prof)
    gate._fail_status.add("9")                      # 9's status read fails: assume the slot is held
    gate._running.discard("1")                      # 1 was reaped by the plugin: its slot is free
    assert cli._cmd_schedule(_sched_args(cap=2), gate, prof) == 0
    assert gate.started == ["9", "1", "2"]          # one free slot -> the top open challenge only
    assert "status 9" in capsys.readouterr().err
    with cli._ledger(prof) as led:
        assert led.ids == {"9", "2"}


def test_schedule_records_its_starts_in_the_ledger():
    gate = FakeGate(_board())
    prof = _StubProfile()                           # cap 2
    assert cli._cmd_schedule(_sched_args(cap=2), gate, prof) == 0     # starts 2 and 1
    with pytest.raises(instsched.CapReached):
        cli._one(gate, "start", "9", False, prof)   # a later single start sees the scheduler's slots


# --------------------------------------------------------------------------------- --profile fence
def test_profile_outside_events_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr("ctf.paths.events_root", lambda: tmp_path / "events")
    evil = tmp_path / "elsewhere" / "event.toml"
    evil.parent.mkdir()
    evil.write_text("slug = 'x'\n")
    with pytest.raises(event.EventError, match="outside the repo's events/"):
        cli._profile(_args(profile=str(evil)))
    # a ../ path that only looks like it is under events/ is refused too
    (tmp_path / "events").mkdir()
    with pytest.raises(event.EventError, match="outside"):
        cli._profile(_args(profile=str(tmp_path / "events" / ".." / "elsewhere" / "event.toml")))


# --------------------------------------------------------------------------------- the real adapter path
_DEMO_TOML = """
slug = "demo"
name = "Demo"
[dates]
start = 2026-01-01T00:00:00Z
end = 2026-01-02T00:00:00Z
[platform]
kind = "ctfd"
base_url = "{base}"
[flag]
prefixes = ["CSCTF"]
[rules]
submit_mode = "auto"
flag_sharing = "allowed"
ai_on_platform = "allowed"
"""
_INSTANCES = '[instances]\ncap = 3\n[instances.endpoints]\nplugin = "docker_per_team"\n'


@pytest.fixture
def real_event(tmp_path, monkeypatch):
    """An events/<slug>/event.toml under a scratch events root, the real get_adapter, and
    requests.Session replaced by the recorded-fixture session (nothing leaves the process)."""
    fx = load("ctfd_api.json")
    s = FakeSession(fx["routes"])
    monkeypatch.setattr(requests, "Session", lambda: s)
    monkeypatch.setenv("CTF_TOKEN", "tok-test-value")
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL"), "CTF_COOKIE",
                 *env.legacy_names("CTF_COOKIE"), "CTF_EVENT", *env.legacy_names("CTF_EVENT")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CTF_SUBMIT_STATE_DIR", str(tmp_path / "pace"))
    root = tmp_path / "events"
    monkeypatch.setattr("ctf.paths.events_root", lambda: root)

    def write(extra=""):
        d = root / "demo"
        d.mkdir(parents=True, exist_ok=True)
        (d / "event.toml").write_text(_DEMO_TOML.format(base=fx["base_url"]) + extra)
        return d / "event.toml"
    return write, s


def test_supports_instances_sees_through_the_real_gate(real_event):
    write, _ = real_event
    gate = get_adapter(event.load_path(write(_INSTANCES)))
    assert isinstance(gate, SubmitGate)
    assert supports_instances(gate)
    plain = get_adapter(event.load_path(write()))
    assert not supports_instances(plain)


def test_cli_start_through_the_real_adapter(real_event, capsys):
    write, s = real_event
    path = write(_INSTANCES)
    rc = cli_main(["instance", "--profile", str(path), "start", "1"])
    out = capsys.readouterr()
    assert rc == 0, out.err
    assert "start 1: running" in out.out and "inst.ctf.example:31337" in out.out
    assert s.sent("POST", "https://ctf.example/containers/api/request")
    # the plugin's own refusal (a teammate holds the slots) surfaces as rc 1, named
    rc = cli_main(["instance", "--event", "demo", "start", "2"])
    assert rc == 1 and "Max containers" in capsys.readouterr().err


def test_cli_status_and_renew_through_the_real_adapter(real_event, capsys):
    write, s = real_event
    write(_INSTANCES)
    assert cli_main(["instance", "--event", "demo", "--json", "status", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["connect"] == "inst.ctf.example:31337"
    assert cli_main(["instance", "--event", "demo", "renew", "1"]) == 0
    assert s.sent("POST", "https://ctf.example/containers/api/renew")


def test_cli_refuses_an_event_without_instances_through_the_real_adapter(real_event, capsys):
    write, s = real_event
    write()
    assert cli_main(["instance", "--event", "demo", "start", "1"]) == cli.REFUSED_EXIT
    assert "no container-instance plugin" in capsys.readouterr().err
    assert not s.sent("POST")
