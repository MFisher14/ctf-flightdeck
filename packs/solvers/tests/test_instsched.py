"""B-003: the value-ordered slot scheduler (ctf.instsched). Pure policy + the apply driver."""
from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from ctf import instsched as s


# --------------------------------------------------------------------------------- plan: value order
def test_plan_starts_highest_value_first_within_cap():
    needs = [s.InstanceNeed("low", value=100), s.InstanceNeed("mid", value=300),
             s.InstanceNeed("high", value=500), s.InstanceNeed("top", value=900)]
    p = s.plan(needs, cap=2)
    assert p.to_start == ("top", "high")        # 900, 500 chosen; 300, 100 blocked
    assert p.blocked == ("mid", "low")
    assert p.free_after == 0


def test_plan_ties_break_by_id_deterministically():
    needs = [s.InstanceNeed("b", value=200), s.InstanceNeed("a", value=200), s.InstanceNeed("c", value=200)]
    assert s.plan(needs, cap=2).to_start == ("a", "b")


def test_plan_releases_a_slot_on_solve():
    # 'solved_running' is solved while we hold its slot -> stop it; that frees room for 'open'.
    needs = [s.InstanceNeed("solved_running", value=500, solved=True, running=True),
             s.InstanceNeed("busy", value=400, running=True),
             s.InstanceNeed("open", value=600)]
    p = s.plan(needs, cap=2)
    assert p.to_stop == ("solved_running",)     # released on solve
    assert p.keep == ("busy",)                  # running, unsolved: left alone
    assert p.to_start == ("open",)              # the freed slot goes to the top open challenge
    assert p.blocked == ()


def test_plan_never_evicts_a_running_unsolved_challenge():
    needs = [s.InstanceNeed("working", value=100, running=True),
             s.InstanceNeed("worth_more", value=999)]
    p = s.plan(needs, cap=1)
    assert p.keep == ("working",)
    assert p.to_start == () and p.blocked == ("worth_more",)   # no slot, and we do not evict 'working'


def test_plan_no_cap_starts_everything_open():
    needs = [s.InstanceNeed(str(i), value=i) for i in range(5)]
    p = s.plan(needs, cap=None)
    assert len(p.to_start) == 5 and p.blocked == () and p.free_after is None


def test_plan_solved_not_running_is_neither_started_nor_stopped():
    p = s.plan([s.InstanceNeed("done", value=500, solved=True)], cap=3)
    assert p.to_start == () and p.to_stop == () and p.keep == ()


def test_plan_rejects_bad_cap():
    with pytest.raises(s.ScheduleError):
        s.plan([], cap=0)
    with pytest.raises(s.ScheduleError):
        s.plan([], cap=True)        # bool is not an int here


def test_plan_rejects_duplicate_ids():
    with pytest.raises(s.ScheduleError, match="twice"):
        s.plan([s.InstanceNeed("x", value=1), s.InstanceNeed("x", value=2)], cap=2)


def test_instance_need_requires_id():
    with pytest.raises(s.ScheduleError):
        s.InstanceNeed("")


# --------------------------------------------------------------------------------- renewal
def test_due_for_renewal_picks_running_unsolved_near_expiry():
    needs = [s.InstanceNeed("soon", running=True, remaining_s=60),
             s.InstanceNeed("later", running=True, remaining_s=800),
             s.InstanceNeed("solved", running=True, solved=True, remaining_s=30),
             s.InstanceNeed("unknown", running=True, remaining_s=None),
             s.InstanceNeed("not_running", remaining_s=10)]
    assert s.due_for_renewal(needs, within_s=120) == ["soon"]


# --------------------------------------------------------------------------------- select_needs
@dataclass
class _Ch:
    id: str
    points: int = 0
    tags: tuple = ()
    solved_by_team: bool = False


def test_select_needs_by_container_tag():
    board = [_Ch("1", 100, tags=("web", "container")), _Ch("2", 200, tags=("crypto",)),
             _Ch("3", 300, tags=("docker",))]
    needs = s.select_needs(board)
    assert {n.challenge_id for n in needs} == {"1", "3"}
    assert next(n for n in needs if n.challenge_id == "3").value == 300


def test_select_needs_only_ids_overrides_tags():
    board = [_Ch("1", tags=("container",)), _Ch("2", tags=("crypto",))]
    needs = s.select_needs(board, only=["2"])
    assert [n.challenge_id for n in needs] == ["2"]   # explicit id wins even without a container tag


def test_select_needs_layers_solved_and_running():
    board = [_Ch("1", tags=("container",)), _Ch("2", tags=("container",), solved_by_team=True)]
    needs = {n.challenge_id: n for n in s.select_needs(board, solved_ids={"1"}, running_ids={"1"})}
    assert needs["1"].solved and needs["1"].running
    assert needs["2"].solved and not needs["2"].running    # solved from the board


# --------------------------------------------------------------------------------- apply_plan
@dataclass
class _Info:
    challenge_id: str
    state: str
    connection_info: str = ""


class _Controller:
    def __init__(self, fail_start=()):
        self.started, self.stopped = [], []
        self.fail_start = set(fail_start)

    def start_instance(self, cid):
        if cid in self.fail_start:
            raise _Boom(f"plugin refused {cid}")
        self.started.append(cid)
        return _Info(cid, "running", f"inst.host:3{cid}")

    def stop_instance(self, cid):
        self.stopped.append(cid)
        return _Info(cid, "stopped")


class _Boom(RuntimeError):
    pass


def test_apply_plan_stops_before_starting():
    c = _Controller()
    p = s.SlotPlan(to_stop=("old",), to_start=("new",), keep=(), blocked=(), cap=2)
    acts = s.apply_plan(c, p)
    assert c.stopped == ["old"] and c.started == ["new"]
    assert acts[0].op == "stop" and acts[1].op == "start"
    assert acts[1].connect == "inst.host:3new"
    assert all(a.ok for a in acts)


def test_apply_plan_records_a_failure_without_stopping_the_rest():
    c = _Controller(fail_start=("bad",))
    p = s.SlotPlan(to_stop=(), to_start=("bad", "good"), keep=(), blocked=(), cap=3)
    acts = s.apply_plan(c, p, errors=_Boom)
    failed = [a for a in acts if not a.ok]
    assert [a.challenge_id for a in failed] == ["bad"]
    assert "plugin refused bad" in failed[0].error
    assert c.started == ["good"]        # the good one still started


def test_apply_plan_propagates_an_unlisted_error_type():
    c = _Controller(fail_start=("bad",))
    p = s.SlotPlan(to_stop=(), to_start=("bad",), keep=(), blocked=(), cap=1)
    with pytest.raises(_Boom):
        s.apply_plan(c, p, errors=ValueError)   # _Boom is not caught


# --------------------------------------------------------------------------------- permissions
def _prefix_allows(entries, command):
    """Claude Code `Bash(<prefix>:*)` semantics: an entry allows a command that starts with its prefix."""
    for e in entries:
        assert e.startswith("Bash(") and e.endswith(":*)"), e
        prefix = e[len("Bash("):-len(":*)")]
        if command == prefix or command.startswith(prefix + " "):
            return True
    return False


def test_permission_allowlist_is_per_verb_with_no_catch_all():
    allow = s.permission_allowlist(python="/v/bin/python")
    base = "/v/bin/python -m ctf instance"
    assert f"Bash({base}:*)" not in allow                       # no whole-CLI catch-all
    assert all(e.startswith(f"Bash({base} ") for e in allow)
    for verb in ("start 7", "status 7", "renew 7", "stop 7", "list", "--json start 7"):
        assert _prefix_allows(allow, f"{base} {verb}"), verb
    # the event-selecting options and the team-wide verbs are not allowed to a solver
    for cmd in ("--profile /tmp/evil.toml start 7", "--event other start 7", "stop-all", "schedule",
                "--json schedule", "--json --profile x start 7"):
        assert not _prefix_allows(allow, f"{base} {cmd}"), cmd
    # it never allows raw container endpoints, curl, or a blanket Bash
    assert not any("curl" in e or "containers/api" in e or e == "Bash(:*)" for e in allow)


def test_permission_profile_shape_and_denies():
    prof = s.permission_profile(python="py")
    assert set(prof) == {"permissions"}
    assert prof["permissions"]["allow"] == s.permission_allowlist(python="py")
    deny = prof["permissions"]["deny"]
    for cmd in ("--profile x start 1", "--event e list", "stop-all", "schedule --cap 9", "--json stop-all"):
        assert _prefix_allows(deny, f"py -m ctf instance {cmd}"), cmd
    assert not set(deny) & set(prof["permissions"]["allow"])


# --------------------------------------------------------------------------------- renewal helpers
def test_due_for_renewal_boundary_is_inclusive():
    needs = [s.InstanceNeed("edge", running=True, remaining_s=120.0),
             s.InstanceNeed("past", running=True, remaining_s=120.5)]
    assert s.due_for_renewal(needs, within_s=120) == ["edge"]


def test_due_for_renewal_rejects_negative_window():
    with pytest.raises(s.ScheduleError):
        s.due_for_renewal([], within_s=-1)


def test_remaining_from_is_relative_to_now():
    assert s.remaining_from(_Info("1", "running"), 100.0) is None      # no expires_at attribute
    info = type("I", (), {"expires_at": 1_000.0})()
    assert s.remaining_from(info, 940.0) == 60.0
    assert s.remaining_from(type("I", (), {"expires_at": True})(), 0.0) is None
    assert s.remaining_from(None, 0.0) is None


class _Renewer(_Controller):
    def __init__(self, fail=()):
        super().__init__()
        self.renewed, self.fail = [], set(fail)

    def renew_instance(self, cid):
        if cid in self.fail:
            raise _Boom(f"renew refused {cid}")
        self.renewed.append(cid)
        return _Info(cid, "running", f"inst.host:3{cid}")


def test_apply_renewals_renews_each_and_isolates_failures():
    c = _Renewer(fail=("b",))
    acts = s.apply_renewals(c, ["a", "b", "c"], errors=_Boom)
    assert c.renewed == ["a", "c"]
    assert [(a.op, a.challenge_id, a.ok) for a in acts] == [("renew", "a", True), ("renew", "b", False),
                                                            ("renew", "c", True)]
    assert "renew refused b" in acts[1].error


def test_apply_renewals_without_a_route_is_loud():
    with pytest.raises(s.ScheduleError, match="renew route"):
        s.apply_renewals(_Controller(), ["a"])
    assert s.apply_renewals(_Controller(), []) == []      # nothing due: no route needed


# --------------------------------------------------------------------------------- slot ledger
class _Plugin(_Controller):
    """A plugin view shared by several 'processes' (each builds its own ledger handle)."""

    def __init__(self, live=(), fail_status=()):
        super().__init__()
        self.live = set(live)
        self.fail_status = set(fail_status)

    def start_instance(self, cid):
        info = super().start_instance(cid)
        self.live.add(cid)
        return info

    def stop_instance(self, cid):
        self.live.discard(cid)
        return super().stop_instance(cid)

    def instance_status(self, cid):
        if cid in self.fail_status:
            raise _Boom(f"status down {cid}")
        return _Info(cid, "running" if cid in self.live else "stopped", "h:1" if cid in self.live else "")


def test_slot_ledger_cap_binds_across_separate_handles(tmp_path):
    path = s.slot_ledger_path(tmp_path)
    plug = _Plugin()
    for cid in ("1", "2"):                       # two separate CLI processes, one start each
        with s.SlotLedger(path) as led:
            s.start_capped(plug, led, cid, cap=2)
    with s.SlotLedger(path) as led:              # a third process: the cap is already held
        with pytest.raises(s.CapReached, match="1, 2"):
            s.start_capped(plug, led, "3", cap=2)
    assert plug.started == ["1", "2"]
    assert json.loads(path.read_text())["running"] == ["1", "2"]


def test_slot_ledger_drops_slots_the_plugin_no_longer_runs(tmp_path):
    path = s.slot_ledger_path(tmp_path)
    plug = _Plugin()
    with s.SlotLedger(path) as led:
        s.start_capped(plug, led, "1", cap=1)
    plug.live.discard("1")                       # reaped by the plugin
    with s.SlotLedger(path) as led:
        s.start_capped(plug, led, "2", cap=1)    # the reaped slot is not counted
        assert led.ids == {"2"}


def test_start_capped_rereads_an_already_live_slot(tmp_path):
    plug = _Plugin()
    with s.SlotLedger(s.slot_ledger_path(tmp_path)) as led:
        s.start_capped(plug, led, "1", cap=1)
        info = s.start_capped(plug, led, "1", cap=1)   # at the cap, but it is our own live slot
    assert plug.started == ["1"] and info.state == "running"


def test_start_capped_counts_an_unreadable_slot(tmp_path):
    plug = _Plugin()
    seen = []
    with s.SlotLedger(s.slot_ledger_path(tmp_path)) as led:
        s.start_capped(plug, led, "1", cap=1)
        plug.fail_status.add("1")
        with pytest.raises(s.CapReached):
            s.start_capped(plug, led, "2", cap=1, errors=_Boom, on_error=lambda c, e: seen.append(c))
    assert seen == ["1"]


def test_start_capped_no_cap_and_bad_cap(tmp_path):
    plug = _Plugin()
    with s.SlotLedger(s.slot_ledger_path(tmp_path)) as led:
        for cid in ("1", "2", "3"):
            s.start_capped(plug, led, cid, cap=None)
        with pytest.raises(s.ScheduleError, match="cap"):
            s.start_capped(plug, led, "4", cap=0)
    assert plug.started == ["1", "2", "3"]


def test_stop_tracked_frees_the_slot_only_on_success(tmp_path):
    plug = _Plugin()
    with s.SlotLedger(s.slot_ledger_path(tmp_path)) as led:
        s.start_capped(plug, led, "1", cap=None)
        s.start_capped(plug, led, "2", cap=None)
        s.stop_tracked(plug, led, "1")
        assert led.ids == {"2"}

        def boom(cid):
            raise _Boom("stop failed")
        plug.stop_instance = boom
        with pytest.raises(_Boom):
            s.stop_tracked(plug, led, "2")
        assert led.ids == {"2"}                  # a failed stop keeps the slot counted


def test_slot_ledger_writes_even_after_an_error(tmp_path):
    path = s.slot_ledger_path(tmp_path)
    with pytest.raises(RuntimeError):
        with s.SlotLedger(path) as led:
            led.add("5")
            raise RuntimeError("later step failed")
    with s.SlotLedger(path) as led:
        assert led.ids == {"5"}


def test_slot_ledger_corrupt_file_is_loud(tmp_path):
    path = s.slot_ledger_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("{not json")
    with pytest.raises(s.ScheduleError, match="unreadable"):
        with s.SlotLedger(path):
            pass
    path.write_text(json.dumps({"running": [1, 2]}))
    with pytest.raises(s.ScheduleError, match="malformed"):
        with s.SlotLedger(path):
            pass


def test_slot_ledger_outside_with_is_an_error(tmp_path):
    led = s.SlotLedger(s.slot_ledger_path(tmp_path))
    with pytest.raises(s.ScheduleError, match="outside"):
        led.add("1")


def test_slot_ledger_lock_excludes_another_process(tmp_path):
    """While one handle holds the ledger, a second process cannot take the lock."""
    import subprocess
    import sys
    path = s.slot_ledger_path(tmp_path)
    probe = ("import fcntl,os,sys; fd=os.open(sys.argv[1], os.O_RDWR); "
             "\ntry:\n fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB); print('free')"
             "\nexcept BlockingIOError:\n print('held')")
    lock = str(path) + ".lock"
    with s.SlotLedger(path):
        held = subprocess.run([sys.executable, "-I", "-c", probe, lock], capture_output=True, text=True)
    free = subprocess.run([sys.executable, "-I", "-c", probe, lock], capture_output=True, text=True)
    assert held.stdout.strip() == "held" and free.stdout.strip() == "free"
