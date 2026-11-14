"""`ctf wait`: first-wave (403 -> 200) and later-wave (count growth, start time) open detection.

Offline: a scripted challenge-list callable plus a fake clock whose `sleep` advances time, so no
network and no real waiting.
"""
from __future__ import annotations

import pytest

from ctf import cli
from ctf.client import CTFdError


class FakeClock:
    def __init__(self, t0=1_000_000.0):
        self.t = t0
        self.sleeps = []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


class Board:
    """Each call returns the next scripted result: an int count, or an exception to raise.
    Records the clock time of every poll."""
    def __init__(self, clock, *script):
        self.clock = clock
        self.script = list(script)
        self.polls = []

    def __call__(self):
        self.polls.append(self.clock())
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, Exception):
            raise item
        return [{"id": i} for i in range(item)]


FORBIDDEN = CTFdError("GET https://x/api/v1/challenges -> HTTP 403: closed")


def _run(board, clock, **kw):
    kw.setdefault("interval", 15)
    kw.setdefault("timeout", 3600)
    return cli.wait_for_open(board, clock=clock, sleep=clock.sleep, log=lambda m: None, **kw)


def test_first_wave_opens_on_403_to_200():
    clk = FakeClock()
    board = Board(clk, FORBIDDEN, FORBIDDEN, 12)
    code, msg = _run(board, clk)
    assert code == 0 and "12 challenges" in msg
    assert len(board.polls) == 3


def test_later_wave_does_not_fire_on_the_old_board():
    clk = FakeClock()
    board = Board(clk, 20, 20, 20, 27)       # wave 1 already open with 20; wave 2 adds 7
    code, msg = _run(board, clk, grow_from=20)
    assert code == 0
    assert "27 challenges" in msg and "7 new" in msg
    assert len(board.polls) == 4


def test_later_wave_times_out_when_count_never_grows():
    clk = FakeClock()
    board = Board(clk, 20)
    code, msg = _run(board, clk, grow_from=20, timeout=60)
    assert code == 1 and "need more than 20" in msg


def test_grow_from_now_uses_first_count_as_baseline():
    clk = FakeClock()
    board = Board(clk, 20, 20, 21)
    code, msg = _run(board, clk, grow_from="now")
    assert code == 0 and "baseline 20" in msg


def test_grow_from_now_waits_through_403_before_taking_baseline():
    clk = FakeClock()
    board = Board(clk, FORBIDDEN, 5, 5, 9)
    code, msg = _run(board, clk, grow_from="now")
    assert code == 0 and "4 new since baseline 5" in msg


def test_not_before_sends_no_poll_until_the_start_time():
    clk = FakeClock()
    start = clk.t + 1800
    board = Board(clk, 30)
    code, _ = _run(board, clk, grow_from=20, not_before=start)
    assert code == 0
    assert board.polls and board.polls[0] >= start


def test_timeout_counts_from_not_before():
    clk = FakeClock()
    start = clk.t + 7200                     # well past the 3600s timeout if it counted from now
    board = Board(clk, FORBIDDEN, FORBIDDEN, 10)
    code, _ = _run(board, clk, not_before=start, timeout=3600)
    assert code == 0


def test_non_403_error_exits_2():
    clk = FakeClock()
    board = Board(clk, CTFdError("GET https://x/api/v1/challenges -> HTTP 500: boom"))
    code, msg = _run(board, clk)
    assert code == 2 and "500" in msg


def test_parse_when_requires_offset_and_accepts_epoch():
    assert cli._parse_when("1700000000") == 1700000000.0
    assert cli._parse_when("2026-11-07T13:00:00Z") == cli._parse_when("2026-11-07T08:00:00-05:00")
    with pytest.raises(ValueError, match="UTC offset"):
        cli._parse_when("2026-11-07T08:00:00")
    with pytest.raises(ValueError):
        cli._parse_when("tomorrow")


def test_parse_grow_from():
    assert cli._parse_grow_from("now") == "now"
    assert cli._parse_grow_from("20") == 20
    for bad in ("-1", "twenty"):
        with pytest.raises(ValueError):
            cli._parse_grow_from(bad)


def test_cli_rejects_bad_flags_before_any_network(monkeypatch):
    def boom():
        raise AssertionError("must not connect")
    monkeypatch.setattr(cli, "_ctfd", boom)
    assert cli.main(["wait", "--grow-from", "lots"]) == 2
    assert cli.main(["wait", "--not-before", "2026-11-07T08:00"]) == 2


def test_cli_wait_wires_flags_through(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))      # B-101: a successful wait writes wave_open
    seen = {}

    class FakeCfg:
        def require_auth(self):
            pass

    class FakeC:
        cfg = FakeCfg()

        def challenges(self):
            return []

    def fake_wait(fn, **kw):
        seen.update(kw)
        return 0, "OPEN"
    monkeypatch.setattr(cli, "_ctfd", lambda: FakeC())
    monkeypatch.setattr(cli, "wait_for_open", fake_wait)
    assert cli.main(["wait", "--grow-from", "20", "--not-before", "1700000000", "--interval", "5"]) == 0
    assert seen["grow_from"] == 20 and seen["not_before"] == 1700000000.0 and seen["interval"] == 5


def test_cmd_wait_tolerates_an_args_namespace_without_a_wave_attribute(monkeypatch, tmp_path):
    # Integration (batch 12, B-017 + B-101): direct callers of cmd_wait build an argparse.Namespace
    # without the B-101 `--wave` flag. cmd_wait must read `wave` defensively, not raise AttributeError.
    import argparse

    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))

    class FakeCfg:
        def require_auth(self):
            pass

    class FakeC:
        cfg = FakeCfg()

        def challenges(self):
            return [{"id": 1}, {"id": 2}]

    recorded = {}

    def fake_record_wave(ids, *, label, announced):
        recorded["ids"] = list(ids)
        recorded["label"] = label

    monkeypatch.setattr(cli, "_ctfd", lambda: FakeC())
    monkeypatch.setattr(cli, "wait_for_open", lambda fn, **kw: (fn(), (0, "OPEN — 2 challenges visible."))[1])
    monkeypatch.setattr(cli, "_record_wave", fake_record_wave)
    # No `wave` attribute on the namespace: before the fix this raised AttributeError.
    args = argparse.Namespace(grow_from=None, not_before=None, interval=1, timeout=5)
    assert cli.cmd_wait(args) == 0
    assert recorded["label"] is None and recorded["ids"] == [1, 2]
