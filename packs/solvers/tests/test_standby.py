"""B-037: the warm standby agent pool (ctf/standby.py, ctf/cli/standby.py).

Offline. Claims are written with the real no-model dispatcher (ctf.dispatch.dispatch_one) straight to a
temp workdir; no platform, no model, no network. The tests drive the queue that warm agents block on and
assert the two properties that matter: exactly one warm agent is ever handed a given claim, and a claim
that appears while an agent waits is handed over on the next look (fast wake).
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from ctf import cli, dispatch, event, ledger, paths, standby


@pytest.fixture
def prof():
    return event.load("csctf")


def _claim(wd, cid, name, category, seq):
    """Write one real claim + handout with the no-model dispatcher (no ledger)."""
    return dispatch.dispatch_one(dispatch.Detected(str(cid), name, category, seq=seq),
                                 event.load("csctf"), workdir=wd, record=False)


def _dead_pid() -> int:
    """A pid that is certainly not a live process (spawned, waited on, reaped)."""
    p = subprocess.Popen([sys.executable, "-c", ""])
    p.wait()
    return p.pid


# ------------------------------------------------------------------------------- take: one claim + handout

def test_take_returns_the_lowest_seq_claim_with_its_handout(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=2)
    c_lo = _claim(tmp_path, "2", "Beta", "pwn", seq=1)
    a = standby.take(tmp_path, "standby-01", timeout=1, poll=0.02, record=False)
    assert a.challenge_id == "2"                       # seq 1 beats seq 2: earliest detected first
    assert a.lane == "pwn"
    # the handout the agent woke to is exactly the file the dispatcher wrote for this claim
    assert a.handout_path == c_lo.to_dict()["handout"]
    from pathlib import Path
    assert a.handout == Path(a.handout_path).read_text(encoding="utf-8")
    assert a.handout.startswith("# handout:")


def test_a_taken_claim_is_not_handed_out_again(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    _claim(tmp_path, "2", "Beta", "pwn", seq=2)
    first = standby.take(tmp_path, "a1", timeout=1, poll=0.02, record=False)
    second = standby.take(tmp_path, "a2", timeout=1, poll=0.02, record=False)
    assert {first.challenge_id, second.challenge_id} == {"1", "2"}   # distinct claims, none twice


def test_only_one_warm_agent_wins_a_single_claim(tmp_path, prof):
    """The core guarantee: with one claim and many warm agents racing, exactly one is handed it."""
    _claim(tmp_path, "7", "Solo", "misc", seq=1)
    n = 12
    barrier = threading.Barrier(n)

    def grab(i):
        barrier.wait()                                  # all pounce together to force the race
        try:
            a = standby.take(tmp_path, f"agent-{i:02d}", timeout=0.6, poll=0.01, record=False)
            return a.challenge_id
        except standby.StandbyTimeout:
            return None

    with ThreadPoolExecutor(max_workers=n) as ex:
        got = [f.result() for f in [ex.submit(grab, i) for i in range(n)]]
    winners = [g for g in got if g is not None]
    assert winners == ["7"], f"exactly one agent should win the claim, got {winners}"
    # and the lease on disk names a single owner
    leases = standby.read_leases(tmp_path)
    assert set(leases) == {"7"}


def test_each_claim_goes_to_exactly_one_agent_under_contention(tmp_path, prof):
    for i in range(1, 6):
        _claim(tmp_path, str(i), f"C{i}", "crypto", seq=i)
    n = 5
    barrier = threading.Barrier(n)

    def grab(i):
        barrier.wait()
        return standby.take(tmp_path, f"w{i}", timeout=2, poll=0.01, record=False).challenge_id

    with ThreadPoolExecutor(max_workers=n) as ex:
        got = [f.result() for f in [ex.submit(grab, i) for i in range(n)]]
    assert sorted(got) == ["1", "2", "3", "4", "5"]     # a partition: every claim once, none shared


# ------------------------------------------------------------------------------- fast wake

def test_a_claim_that_appears_while_waiting_is_taken_on_the_next_look(tmp_path, prof):
    """Deterministic wake: the agent blocks on an empty pool; the claim is written during the sleep, and
    the very next look hands it over. No oversleep, no missed claim."""
    clock = iter([0.0, 0.0, 0.0, 0.1, 0.1, 0.1, 0.1]).__next__
    sleeps: list[float] = []

    def fake_sleep(dt):
        sleeps.append(dt)
        if len(sleeps) == 1:                            # a claim lands mid-wait, after the first empty look
            _claim(tmp_path, "9", "Late", "web", seq=1)

    a = standby.take(tmp_path, "warm-1", timeout=5, poll=0.2,
                     clock=clock, wall=lambda: 100.0, sleep=fake_sleep, record=False)
    assert a.challenge_id == "9"
    assert len(sleeps) == 1                             # returned on the look right after the claim appeared
    pres = standby.read_presence(tmp_path)["warm-1"]
    assert pres["status"] == standby.ASSIGNED
    assert pres["challenge_id"] == "9"                  # the presence record names the claim it took


def test_wake_is_prompt_in_real_time(tmp_path, prof):
    """A real-thread sanity check that the queue wakes within a small bound once a claim exists."""
    result: dict = {}

    def waiter():
        try:
            result["a"] = standby.take(tmp_path, "warm-rt", timeout=5, poll=0.05, record=False)
        except standby.StandbyError as e:
            result["err"] = e

    t = threading.Thread(target=waiter)
    import time
    t.start()
    time.sleep(0.2)                                     # the agent is now blocked on an empty pool
    _claim(tmp_path, "3", "Now", "rev", seq=1)
    took_at = time.monotonic()
    t.join(timeout=3)
    assert not t.is_alive(), "take did not wake within the bound"
    assert result["a"].challenge_id == "3"
    assert time.monotonic() - took_at < 2.0            # woke well under the cold-launch 11.5-24.6 s


# ------------------------------------------------------------------------------- timeout

def test_timeout_raises_and_marks_the_agent_left(tmp_path, prof):
    with pytest.raises(standby.StandbyTimeout):
        standby.take(tmp_path, "idle-1", timeout=0.0, poll=0.01, record=False)
    assert standby.read_presence(tmp_path)["idle-1"]["status"] == standby.LEFT


def test_timeout_fires_exactly_at_the_boundary(tmp_path, prof):
    """Elapsed == timeout ends the wait: no further sleep, no further look."""
    clock = iter([0.0, 5.0, 5.0]).__next__

    def no_sleep(dt):
        raise AssertionError(f"take slept ({dt}) although the full timeout had elapsed")

    with pytest.raises(standby.StandbyTimeout):
        standby.take(tmp_path, "edge-1", timeout=5.0, poll=0.1, clock=clock, wall=lambda: 1.0,
                     sleep=no_sleep, record=False)


class _FakeClock:
    """A monotonic clock that advances only when `take` sleeps."""

    def __init__(self):
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self):
        return self.t

    def sleep(self, dt):
        self.sleeps.append(dt)
        self.t += dt


def test_take_never_sleeps_past_the_timeout_whatever_the_poll(tmp_path, prof):
    """A poll longer than the timeout must not push take past it (the CLI caps --timeout to end before the
    tool wall; an unbounded sleep(poll) would defeat that cap)."""
    fc = _FakeClock()
    with pytest.raises(standby.StandbyTimeout):
        standby.take(tmp_path, "slow-poll", timeout=540, poll=1000, clock=fc, wall=lambda: 1.0,
                     sleep=fc.sleep, record=False)
    assert fc.sleeps == [540]
    assert fc.t == 540


def test_the_last_sleep_is_only_the_time_left(tmp_path, prof):
    fc = _FakeClock()
    with pytest.raises(standby.StandbyTimeout):
        standby.take(tmp_path, "rem", timeout=10, poll=4, clock=fc, wall=lambda: 1.0,
                     sleep=fc.sleep, record=False)
    assert fc.sleeps == [4, 4, 2]


def test_cli_take_with_a_huge_poll_still_ends_at_its_timeout(tmp_path, prof, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    t0 = time.monotonic()
    rc = cli.main(["standby", "--event", "csctf", "take", "--agent", "cli-p", "--timeout", "0.3",
                   "--poll", "1000"])
    assert rc == 4
    assert time.monotonic() - t0 < 5.0                  # not 1000 s


# ------------------------------------------------------------------------------- release

def test_release_returns_the_claim_to_the_pool_only_for_its_owner(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    a = standby.take(tmp_path, "owner", timeout=1, poll=0.02, record=False)
    assert standby.pool_status(tmp_path)["available"] == []
    # a non-owner cannot release it
    assert standby.release(tmp_path, "stranger", a.challenge_id, record=False) is False
    assert standby.pool_status(tmp_path)["leased"] == ["1"]
    # the owner can
    assert standby.release(tmp_path, "owner", a.challenge_id, record=False) is True
    assert standby.pool_status(tmp_path)["available"] == ["1"]
    # and a fresh agent can now take it
    assert standby.take(tmp_path, "owner2", timeout=1, poll=0.02, record=False).challenge_id == "1"


# ------------------------------------------------------------------------------- stale-lease reclaim

def test_a_live_lease_is_never_stolen(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    standby.take(tmp_path, "holder", timeout=1, poll=0.02, record=False)   # live pid = this process
    # even far in the future, a live owner keeps the claim
    assert standby.try_lease(tmp_path, "1", "thief",
                             clock=lambda: 1e12, stale_after=1.0) is None
    with pytest.raises(standby.StandbyTimeout):
        standby.take(tmp_path, "thief", timeout=0.0, poll=0.01, record=False)


def test_a_dead_agents_stale_lease_is_reclaimed(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    dead = _dead_pid()
    # forge a lease owned by a dead pid, leased long ago
    lp = standby.lease_path(tmp_path, "1")
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.write_text(json.dumps({"schema": 1, "challenge_id": "1", "agent": "ghost",
                              "pid": dead, "leased_at": 1000.0}) + "\n", encoding="utf-8")
    # not yet old enough -> not reclaimed
    assert standby.try_lease(tmp_path, "1", "rescuer", clock=lambda: 1000.0 + 10, stale_after=120) is None
    assert standby.try_lease(tmp_path, "1", "rescuer", clock=lambda: 1000.0 + 119.9, stale_after=120) is None
    # exactly stale_after old with a dead owner -> reclaimed by the new agent (the boundary is inclusive)
    lease = standby.try_lease(tmp_path, "1", "rescuer", clock=lambda: 1000.0 + 120, stale_after=120)
    assert lease is not None and lease["agent"] == "rescuer"
    assert standby.read_leases(tmp_path)["1"]["agent"] == "rescuer"


# ------------------------------------------------------------------------------- loud failures

def test_a_missing_handout_fails_loudly(tmp_path, prof):
    c = _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    from pathlib import Path
    Path(c.handout).unlink()                            # the handout the claim points at is gone
    with pytest.raises(standby.StandbyError) as e:
        standby.take(tmp_path, "a1", timeout=0.2, poll=0.02, record=False)
    # an error naming the bad claim, not a quiet timeout
    assert not isinstance(e.value, standby.StandbyTimeout)
    assert "handout" in str(e.value) and "missing" in str(e.value) and "'1'" in str(e.value)
    assert standby.read_presence(tmp_path)["a1"]["status"] == standby.LEFT
    # the failure strands no lease: the claim is still available, and once the handout is back it is taken
    assert standby.read_leases(tmp_path) == {}
    st = standby.pool_status(tmp_path)
    assert st["available"] == ["1"] and st["bad_handouts"] == ["1"]
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)     # the dispatcher rewrites the handout
    assert standby.pool_status(tmp_path)["bad_handouts"] == []
    assert standby.take(tmp_path, "a2", timeout=1, poll=0.02, record=False).challenge_id == "1"


def test_one_bad_handout_does_not_stop_the_pool(tmp_path, prof):
    """The lowest-seq claim has no handout: it is skipped (recorded once, no lease) and the next claim is
    handed out; the assignment names what was skipped."""
    from pathlib import Path
    bad = _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    Path(bad.handout).unlink()
    fc = _FakeClock()
    real_sleep = fc.sleep

    def sleep(dt):
        real_sleep(dt)
        if len(fc.sleeps) == 3:                         # three looks see only the bad claim, then a good one
            _claim(tmp_path, "2", "Beta", "pwn", seq=2)

    a = standby.take(tmp_path, "a1", timeout=5, poll=0.1, clock=fc, wall=lambda: 1.0, sleep=sleep,
                     record=True)
    assert a.challenge_id == "2"
    assert [cid for cid, _ in a.skipped] == ["1"] and "missing" in a.skipped[0][1]
    assert set(standby.read_leases(tmp_path)) == {"2"}  # nothing leased for the bad claim
    rows = [r for r in ledger.read(workdir=tmp_path) if r.get("event") == standby.BAD_HANDOUT_EVENT]
    assert len(rows) == 1 and rows[0]["challenge_id"] == "1" and rows[0]["agent"] == "a1"
    # a second agent with only the bad claim left gets an error naming it
    with pytest.raises(standby.StandbyError) as e:
        standby.take(tmp_path, "a2", timeout=0.0, poll=0.01, record=False)
    assert not isinstance(e.value, standby.StandbyTimeout) and "'1'" in str(e.value)


def test_a_handout_that_comes_back_is_not_reported_as_skipped(tmp_path, prof):
    from pathlib import Path
    c = _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    Path(c.handout).unlink()
    fc = _FakeClock()

    def sleep(dt):
        fc.sleep(dt)
        _claim(tmp_path, "1", "Alpha", "crypto", seq=1)  # the dispatcher rewrites it during the wait

    a = standby.take(tmp_path, "a1", timeout=5, poll=0.1, clock=fc, wall=lambda: 1.0, sleep=sleep,
                     record=False)
    assert a.challenge_id == "1" and a.skipped == ()


def test_cli_take_names_a_skipped_claim_and_still_takes_the_next(tmp_path, prof, monkeypatch, capsys):
    from pathlib import Path
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    Path(_claim(tmp_path, "1", "Alpha", "crypto", seq=1).handout).unlink()
    _claim(tmp_path, "2", "Beta", "pwn", seq=2)
    rc = cli.main(["standby", "--event", "csctf", "take", "--agent", "cli-s", "--timeout", "1",
                   "--poll", "0.02", "--json"])
    assert rc == 0
    cap = capsys.readouterr()
    out = json.loads(cap.out)
    assert out["challenge_id"] == "2" and [s[0] for s in out["skipped"]] == ["1"]
    assert "skipped claim 1:" in cap.err
    # with only the bad claim left, the CLI exits 2 (an error), not 4 (a quiet timeout)
    rc = cli.main(["standby", "--event", "csctf", "take", "--agent", "cli-t", "--timeout", "0.1",
                   "--poll", "0.02"])
    assert rc == 2
    assert "bad handout" in capsys.readouterr().err


def test_a_failure_after_the_lease_drops_the_lease(tmp_path, prof, monkeypatch):
    """If the hand-off fails after the lease was won (here the ledger write), the lease is removed before
    the error propagates, so the claim goes straight back to the pool."""
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)

    def broken_append(*a, **k):
        raise OSError("ledger disk full")

    monkeypatch.setattr(standby._ledger, "append", broken_append)
    with pytest.raises(OSError):
        standby.take(tmp_path, "a1", timeout=1, poll=0.02, record=True)
    assert standby.read_leases(tmp_path) == {}
    monkeypatch.undo()
    assert standby.take(tmp_path, "a2", timeout=1, poll=0.02, record=False).challenge_id == "1"


def test_a_corrupt_claim_is_not_silently_skipped(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    (dispatch.dispatch_dir(tmp_path) / dispatch.CLAIMS / "2.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(standby.StandbyError):
        standby.take(tmp_path, "a1", timeout=1, poll=0.02, record=False)


@pytest.mark.parametrize("bad", ["", "../x", "a/b", "name with space", "x" * 65, "."])
def test_a_bad_agent_name_is_rejected(tmp_path, bad):
    with pytest.raises(standby.StandbyError):
        standby.take(tmp_path, bad, timeout=0.0, poll=0.01, record=False)


# ------------------------------------------------------------------------------- ledger

def test_take_records_a_standby_take_ledger_row(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    standby.take(tmp_path, "a1", timeout=1, poll=0.02, record=True)
    rows = list(ledger.read(workdir=tmp_path))
    takes = [r for r in rows if r.get("event") == standby.TAKE_EVENT]
    assert len(takes) == 1
    assert takes[0]["challenge_id"] == "1" and takes[0]["agent"] == "a1"


# ------------------------------------------------------------------------------- plan

def test_plan_names_stable_slots_and_the_blocking_argv(tmp_path):
    rows = standby.plan(3)
    assert [r["agent"] for r in rows] == ["standby-01", "standby-02", "standby-03"]
    for r in rows:
        assert "take" in r["argv"] and "--agent" in r["argv"]
        assert r["argv"][r["argv"].index("--agent") + 1] == r["agent"]
    # re-running the plan addresses the same slots
    assert standby.plan(3) == rows
    with pytest.raises(standby.StandbyError):
        standby.plan(0)


# ------------------------------------------------------------------------------- pool status

def test_pool_status_counts_claims_leases_and_waiting_agents(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    _claim(tmp_path, "2", "Beta", "pwn", seq=2)
    standby.register(tmp_path, "idle-1", status=standby.WAITING)
    standby.take(tmp_path, "worker", timeout=1, poll=0.02, record=False)
    st = standby.pool_status(tmp_path)
    assert st["claims"] == 2
    assert len(st["leased"]) == 1 and len(st["available"]) == 1
    assert st["waiting"] == 1 and st["assigned"] == 1
    names = {a["agent"]: a for a in st["agents"]}
    assert names["worker"]["status"] == standby.ASSIGNED
    assert names["idle-1"]["status"] == standby.WAITING


# ------------------------------------------------------------------------------- CLI

def test_cli_take_prints_the_handout_and_exits_0(tmp_path, prof, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    rc = cli.main(["standby", "--event", "csctf", "take", "--agent", "cli-1", "--timeout", "1", "--poll", "0.02"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "claimed 1" in out and "cli-1" in out
    assert "recon/index.md" in out or "triage" in out.lower()   # the handout body printed


def test_cli_take_times_out_with_exit_4(tmp_path, prof, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    rc = cli.main(["standby", "--event", "csctf", "take", "--agent", "cli-x", "--timeout", "0", "--poll", "0.01"])
    assert rc == 4


def test_cli_take_rejects_an_over_cap_timeout(tmp_path, prof, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    rc = cli.main(["standby", "--event", "csctf", "take", "--agent", "cli-1", "--timeout", "999"])
    assert rc == 2


def test_cli_plan_lists_each_slots_argv(tmp_path, capsys):
    rc = cli.main(["standby", "plan", "--size", "2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "standby-01" in out and "standby-02" in out
    assert "standby take --agent standby-01" in out


def test_cli_status_reports_the_pool(tmp_path, prof, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    standby.take(tmp_path, "w1", timeout=1, poll=0.02, record=False)
    rc = cli.main(["standby", "--event", "csctf", "status"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "claims 1" in out and "leased 1" in out
    assert "  w1: assigned -> 1\n" in out               # the agent line names the claim it holds


# ------------------------------------------------------------------------------- lease liveness (CLI take)

def _run_ctf(tmp_path, *args, timeout=60):
    """Run `python -m ctf standby ...` as a real, separate process (like a warm agent's tool call)."""
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_EVENT="csctf")
    return subprocess.run([sys.executable, "-m", "ctf", "standby", *args], cwd=paths.repo_root(), env=e,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=timeout)


def _sleeper() -> subprocess.Popen:
    """A live stand-in for a warm agent's harness process."""
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])


def test_a_cli_take_lease_survives_the_take_process_exiting(tmp_path, prof):
    """The take process exits as soon as it prints the handout. Its lease must not die with it: a second
    warm agent must never be handed the claim while the first is still working it, however long that is."""
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    r = _run_ctf(tmp_path, "take", "--agent", "warm-a", "--timeout", "5", "--poll", "0.02")
    assert r.returncode == 0, r.stderr
    assert "lease held until `standby release`" in r.stdout
    lease = standby.read_leases(tmp_path)["1"]
    assert lease["agent"] == "warm-a" and lease["pid"] is None and lease["ttl"] is None
    far = lease["leased_at"] + 1e6                       # long past any stale_after
    assert standby.try_lease(tmp_path, "1", "warm-b", clock=lambda: far, stale_after=1.0) is None
    st = standby.pool_status(tmp_path, clock=lambda: far, stale_after=1.0)
    assert st["leased"] == ["1"] and st["held_until_release"] == ["1"] and st["available"] == []
    r2 = _run_ctf(tmp_path, "take", "--agent", "warm-b", "--timeout", "0.3", "--poll", "0.05",
                  "--stale-after", "0")
    assert r2.returncode == 4, (r2.stdout, r2.stderr)     # warm-b waits and times out; claim stays warm-a's
    assert standby.read_leases(tmp_path)["1"]["agent"] == "warm-a"
    names = {a["agent"]: a for a in st["agents"]}
    assert names["warm-a"]["pid"] is None and names["warm-a"]["alive"] is None


def test_a_cli_take_with_owner_pid_lives_and_dies_with_that_pid(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    harness = _sleeper()
    try:
        r = _run_ctf(tmp_path, "take", "--agent", "warm-a", "--owner-pid", str(harness.pid),
                     "--timeout", "5", "--poll", "0.02")
        assert r.returncode == 0, r.stderr
        lease = standby.read_leases(tmp_path)["1"]
        assert lease["pid"] == harness.pid
        t0 = lease["leased_at"]
        # the harness is alive: the lease holds however old it is
        assert standby.try_lease(tmp_path, "1", "warm-b", clock=lambda: t0 + 1e6, stale_after=1.0) is None
    finally:
        harness.kill()
        harness.wait()
    # harness gone: recent -> still held; older than stale_after -> reclaimable
    assert standby.try_lease(tmp_path, "1", "warm-b", clock=lambda: t0 + 10, stale_after=120) is None
    got = standby.try_lease(tmp_path, "1", "warm-b", clock=lambda: t0 + 300, stale_after=120)
    assert got is not None and standby.read_leases(tmp_path)["1"]["agent"] == "warm-b"


def test_a_dead_owner_pid_is_refused_and_takes_nothing(tmp_path, prof, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    rc = cli.main(["standby", "--event", "csctf", "take", "--agent", "w", "--owner-pid", str(_dead_pid()),
                   "--timeout", "1", "--poll", "0.02"])
    assert rc == 2
    assert standby.read_leases(tmp_path) == {}
    for bad in (0, -5, True, "12"):
        with pytest.raises(standby.StandbyError):
            standby.try_lease(tmp_path, "1", "w", owner_pid=bad)


def test_a_ttl_lease_expires_without_renewal_and_renew_extends_it(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    a = standby.take(tmp_path, "warm-a", timeout=1, poll=0.02, wall=lambda: 1000.0,
                     owner_pid=None, ttl=30, record=False)
    assert a.lease["ttl"] == 30 and a.lease["pid"] is None
    assert standby.try_lease(tmp_path, "1", "warm-b", clock=lambda: 1029.9) is None   # within the ttl
    assert standby.renew(tmp_path, "warm-a", "1", clock=lambda: 1020.0)["renewed_at"] == 1020.0
    assert standby.renew(tmp_path, "warm-b", "1") is None                         # not the holder
    assert standby.try_lease(tmp_path, "1", "warm-b", clock=lambda: 1049.9) is None   # renewal counted
    got = standby.try_lease(tmp_path, "1", "warm-b", clock=lambda: 1050.0)          # exactly ttl after it
    assert got is not None and got["agent"] == "warm-b" and got["ttl"] is None
    # the first agent has lost the claim: renew says so, and the CLI exits 1
    assert standby.renew(tmp_path, "warm-a", "1") is None
    r = _run_ctf(tmp_path, "renew", "--agent", "warm-a", "1")
    assert r.returncode == 1 and "no longer holds 1" in r.stderr


def test_cli_renew_heartbeats_the_holders_lease(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    r = _run_ctf(tmp_path, "take", "--agent", "warm-a", "--ttl", "60", "--timeout", "5", "--poll", "0.02")
    assert r.returncode == 0, r.stderr
    assert "run `standby renew` within 60s" in r.stdout
    before = standby.read_leases(tmp_path)["1"]
    assert before["ttl"] == 60.0 and before["pid"] is None
    time.sleep(0.05)
    r2 = _run_ctf(tmp_path, "renew", "--agent", "warm-a", "1")
    assert r2.returncode == 0, r2.stderr
    assert standby.read_leases(tmp_path)["1"]["renewed_at"] > before["renewed_at"]


def test_release_force_frees_a_crashed_holders_claim(tmp_path, prof, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    standby.take(tmp_path, "warm-a", timeout=1, poll=0.02, owner_pid=None, record=False)   # held lease
    # an operator without --force cannot touch another agent's lease
    assert cli.main(["standby", "--event", "csctf", "release", "--agent", "operator", "1"]) == 1
    assert standby.read_leases(tmp_path)["1"]["agent"] == "warm-a"
    assert cli.main(["standby", "--event", "csctf", "release", "--agent", "operator", "--force", "1"]) == 0
    assert standby.read_leases(tmp_path) == {}
    assert standby.read_presence(tmp_path)["warm-a"]["status"] == standby.LEFT
    assert "operator" not in standby.read_presence(tmp_path)
    assert standby.pool_status(tmp_path)["available"] == ["1"]


# ------------------------------------------------------------------------------- reclaim is atomic

def _forge_stale_lease(wd, cid="1", agent="ghost"):
    lp = standby.lease_path(wd, cid)
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.write_text(json.dumps({"schema": 1, "challenge_id": cid, "agent": agent,
                              "pid": _dead_pid(), "leased_at": 1000.0}) + "\n", encoding="utf-8")
    return lp


def test_a_reclaim_waits_for_a_concurrent_reclaim_and_then_backs_off(tmp_path, prof):
    """Two reclaimers of one stale lease: while reclaimer A holds the lease lock and installs its lease,
    reclaimer B blocks; when B gets the lock it re-reads the lease, finds A's live lease and backs off.
    Without the lock (or without the re-read under it) B would overwrite A's lease and both would own it."""
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    lp = _forge_stale_lease(tmp_path)
    fd = os.open(str(lp) + ".lock", os.O_CREAT | os.O_RDWR, 0o644)   # reclaimer A, another process's view
    fcntl.flock(fd, fcntl.LOCK_EX)
    out: dict = {}
    t = threading.Thread(target=lambda: out.setdefault(
        "b", standby.try_lease(tmp_path, "1", "rescuer-b", clock=lambda: 5000.0, stale_after=120)))
    try:
        t.start()
        time.sleep(0.3)
        assert t.is_alive(), "reclaimer B did not wait for the lease lock"
        lp.write_text(json.dumps({"schema": 1, "challenge_id": "1", "agent": "rescuer-a",
                                  "pid": os.getpid(), "leased_at": 5000.0}) + "\n", encoding="utf-8")
    finally:
        os.close(fd)                                     # A done: drops the lock
    t.join(timeout=5)
    assert not t.is_alive()
    assert out["b"] is None
    assert standby.read_leases(tmp_path)["1"]["agent"] == "rescuer-a"


_RECLAIMER = r"""
import sys, time
from ctf import standby
wd, agent, start = sys.argv[1], sys.argv[2], float(sys.argv[3])
while time.time() < start:
    time.sleep(0.001)
got = standby.try_lease(wd, "1", agent, clock=lambda: 9e9, stale_after=1.0)
print("WIN" if got else "LOSE")
"""


def test_reclaimers_in_separate_processes_produce_exactly_one_winner(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    _forge_stale_lease(tmp_path)
    start = time.time() + 1.5
    procs = [subprocess.Popen([sys.executable, "-c", _RECLAIMER, str(tmp_path), f"r{i}", str(start)],
                              cwd=paths.repo_root(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for i in range(6)]
    results = {}
    for i, p in enumerate(procs):
        so, se = p.communicate(timeout=60)
        assert p.returncode == 0, se
        results[f"r{i}"] = so.strip()
    winners = [a for a, r in results.items() if r == "WIN"]
    assert len(winners) == 1, results
    assert standby.read_leases(tmp_path)["1"]["agent"] == winners[0]
    # and no temp files are left beside the lease
    left = sorted(p.name for p in standby.leases_dir(tmp_path).iterdir())
    assert left == ["1.json", "1.json.lock"], left


# ------------------------------------------------------------------------------- claim records

@pytest.mark.parametrize("bad_seq", ["x", None, 1.5, True])
def test_a_claim_with_no_integer_seq_is_a_loud_error(tmp_path, prof, bad_seq):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    _claim(tmp_path, "2", "Beta", "pwn", seq=2)
    dispatch.update_claim(tmp_path, "2", seq=bad_seq)
    with pytest.raises(standby.StandbyError) as e:
        standby.take(tmp_path, "a1", timeout=1, poll=0.02, record=False)
    assert "'2'" in str(e.value) and "seq" in str(e.value)
    assert standby.read_leases(tmp_path) == {}          # nothing was handed out on a bad pool


def test_a_claim_no_longer_dispatched_is_not_handed_out(tmp_path, prof):
    _claim(tmp_path, "1", "Alpha", "crypto", seq=1)
    _claim(tmp_path, "2", "Beta", "pwn", seq=2)
    dispatch.update_claim(tmp_path, "1", status="solved")   # a lifecycle (B-015) marked it solved
    assert standby.pool_status(tmp_path)["available"] == ["2"]
    assert standby.take(tmp_path, "a1", timeout=1, poll=0.02, record=False).challenge_id == "2"
    with pytest.raises(standby.StandbyTimeout):
        standby.take(tmp_path, "a2", timeout=0.0, poll=0.01, record=False)


def test_plan_ttl_adds_the_heartbeat_flag(tmp_path, capsys):
    rows = standby.plan(2, ttl=90)
    assert all(r["argv"][-2:] == ["--ttl", "90"] for r in rows)
    assert "--ttl" not in standby.plan(2)[0]["argv"]
    assert cli.main(["standby", "plan", "--size", "1", "--ttl", "45"]) == 0
    assert "standby take --agent standby-01 --timeout 540 --ttl 45" in capsys.readouterr().out
