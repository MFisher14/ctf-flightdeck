"""B-018: agent capacity past the harness subagent cap -- host sizing and board planning.

Every behaviour is exercised against a *synthetic* HostResources so the arithmetic is pinned
regardless of the machine the suite runs on; one test touches the real host only to confirm
measure_host() returns sane positive facts.
"""
from __future__ import annotations

import argparse

import pytest

from ctf import capacity
from ctf.cli import capacity as cli_capacity

GiB = 1024 ** 3
MiB = 1024 ** 2


def host(cpu=14, total_gib=64, avail_gib=None):
    avail = total_gib if avail_gib is None else avail_gib
    return capacity.HostResources(total_ram_bytes=total_gib * GiB,
                                  available_ram_bytes=avail * GiB,
                                  cpu_count=cpu, source="synthetic")


# --- budget arithmetic ---------------------------------------------------------------------------

def test_budget_is_the_min_of_ram_and_cpu():
    # 14 CPU * 4 = 56 by CPU; (64 - 4) GiB / 512 MiB = 120 by RAM -> CPU binds at 56.
    pol = capacity.CapacityPolicy(per_agent_ram_mb=512, reserve_ram_mb=4096,
                                  agents_per_cpu=4.0, per_worker_cap=20)
    b = capacity.concurrency_budget(host(cpu=14, total_gib=64), pol)
    assert b.by_cpu == 56
    assert b.by_ram == 120
    assert b.capacity == 56
    assert b.binding == "cpu"


def test_budget_is_ram_bound_when_memory_is_tight():
    # 8 GiB usable after a 2 GiB reserve on a 10 GiB host / 1 GiB per agent = 8; CPU would allow 32.
    pol = capacity.CapacityPolicy(per_agent_ram_mb=1024, reserve_ram_mb=2048, agents_per_cpu=4.0)
    b = capacity.concurrency_budget(host(cpu=8, total_gib=10), pol)
    assert b.by_ram == 8
    assert b.by_cpu == 32
    assert b.capacity == 8
    assert b.binding == "ram"


def test_reserve_can_exhaust_ram_to_zero_not_negative():
    pol = capacity.CapacityPolicy(per_agent_ram_mb=512, reserve_ram_mb=100_000, agents_per_cpu=4.0)
    b = capacity.concurrency_budget(host(cpu=8, total_gib=16), pol)
    assert b.by_ram == 0
    assert b.capacity == 0  # min with cpu, floored at 0


def test_available_vs_total_ram_basis_changes_the_budget():
    pol_avail = capacity.CapacityPolicy(per_agent_ram_mb=1024, reserve_ram_mb=0, agents_per_cpu=100.0,
                                        use_available_ram=True)
    pol_total = capacity.CapacityPolicy(per_agent_ram_mb=1024, reserve_ram_mb=0, agents_per_cpu=100.0,
                                        use_available_ram=False)
    h = host(cpu=8, total_gib=32, avail_gib=8)
    assert capacity.concurrency_budget(h, pol_avail).capacity == 8   # 8 GiB available
    assert capacity.concurrency_budget(h, pol_total).capacity == 32  # 32 GiB total


# --- board planning ------------------------------------------------------------------------------

def test_w1_board_seated_at_t0_across_multiple_workers_with_no_denials():
    # The acceptance: a 54-challenge wave board on a host sized for it -> zero denials, and more than
    # one worker (so it is genuinely past a single 20-subagent harness cap).
    pol = capacity.CapacityPolicy(per_agent_ram_mb=256, reserve_ram_mb=2048,
                                  agents_per_cpu=5.0, per_worker_cap=20)
    plan = capacity.plan_board(54, host(cpu=16, total_gib=64), pol)
    assert plan.capacity >= 54
    assert plan.granted == 54
    assert plan.satisfied and plan.denied == 0
    assert plan.workers == 3            # ceil(54/20)
    assert plan.multi_process
    # every challenge index 0..53 is seated exactly once, no lane over the per-worker cap
    seated = [cid for lane in plan.lanes for cid in lane]
    assert sorted(seated) == list(range(54))
    assert all(len(lane) <= 20 for lane in plan.lanes)


def test_undersized_host_queues_the_remainder_with_a_named_reason_never_drops():
    # Host seats only 12; a 54-board grants 12 and queues 42 -- all accounted for, none dropped.
    pol = capacity.CapacityPolicy(per_agent_ram_mb=512, reserve_ram_mb=0, agents_per_cpu=3.0,
                                  per_worker_cap=20)
    plan = capacity.plan_board(54, host(cpu=4, total_gib=64), pol)
    assert plan.capacity == 12
    assert plan.granted == 12
    assert plan.denied == 42
    assert not plan.satisfied
    seated = [cid for lane in plan.lanes for cid in lane]
    assert sorted(seated + list(plan.queued)) == list(range(54))  # nothing lost
    assert "queued" in plan.reason and "CPU-bound" in plan.reason


def test_ram_bound_shortfall_names_ram_in_the_reason():
    pol = capacity.CapacityPolicy(per_agent_ram_mb=1024, reserve_ram_mb=0, agents_per_cpu=100.0)
    plan = capacity.plan_board(40, host(cpu=16, total_gib=10, avail_gib=10), pol)
    assert plan.granted == 10 and plan.denied == 30
    assert "RAM-bound" in plan.reason


def test_max_workers_caps_seats_below_host_budget_and_is_the_named_reason():
    pol = capacity.CapacityPolicy(per_agent_ram_mb=256, reserve_ram_mb=0, agents_per_cpu=10.0,
                                  per_worker_cap=20, max_workers=1)
    plan = capacity.plan_board(54, host(cpu=16, total_gib=64), pol)
    assert plan.capacity >= 54          # host could run them all
    assert plan.granted == 20           # but one worker * 20 cap
    assert plan.workers == 1
    assert plan.denied == 34
    assert "CTF_CAPACITY_MAX_WORKERS=1" in plan.reason


def test_board_within_a_single_worker_uses_one_lane():
    pol = capacity.CapacityPolicy(agents_per_cpu=10.0, per_worker_cap=20)
    plan = capacity.plan_board(12, host(cpu=16, total_gib=64), pol)
    assert plan.satisfied and plan.workers == 1 and not plan.multi_process


def test_explicit_ids_are_preserved_in_lanes_and_queue():
    pol = capacity.CapacityPolicy(agents_per_cpu=0.5, per_worker_cap=2)  # cap=1 -> seats 1
    ids = ["a", "b", "c"]
    plan = capacity.plan_board(3, host(cpu=2, total_gib=64), pol, ids=ids)
    assert plan.capacity == 1
    seated = [cid for lane in plan.lanes for cid in lane]
    assert seated == ["a"]
    assert list(plan.queued) == ["b", "c"]


def test_empty_board_is_satisfied_with_no_workers():
    plan = capacity.plan_board(0, host(), capacity.CapacityPolicy())
    assert plan.granted == 0 and plan.workers == 0 and plan.satisfied


# --- validation / loud failure -------------------------------------------------------------------

def test_bad_policy_values_fail_loudly():
    with pytest.raises(capacity.CapacityError):
        capacity.CapacityPolicy(per_agent_ram_mb=0)
    with pytest.raises(capacity.CapacityError):
        capacity.CapacityPolicy(agents_per_cpu=0)
    with pytest.raises(capacity.CapacityError):
        capacity.CapacityPolicy(per_worker_cap=0)
    with pytest.raises(capacity.CapacityError):
        capacity.CapacityPolicy(max_workers=0)


def test_zero_cpu_host_is_rejected():
    with pytest.raises(capacity.CapacityError):
        capacity.HostResources(total_ram_bytes=GiB, available_ram_bytes=GiB, cpu_count=0)


def test_available_over_total_is_rejected():
    with pytest.raises(capacity.CapacityError):
        capacity.HostResources(total_ram_bytes=GiB, available_ram_bytes=2 * GiB, cpu_count=4)


def test_negative_demand_is_rejected():
    with pytest.raises(capacity.CapacityError):
        capacity.plan_board(-1, host(), capacity.CapacityPolicy())


def test_ids_length_must_match_demand():
    with pytest.raises(capacity.CapacityError):
        capacity.plan_board(3, host(), capacity.CapacityPolicy(), ids=["a", "b"])


# --- env overrides -------------------------------------------------------------------------------

def test_from_env_applies_ctf_overrides():
    pol = capacity.CapacityPolicy.from_env(environ={
        "CTF_CAPACITY_AGENT_RAM_MB": "256", "CTF_CAPACITY_RESERVE_MB": "8192",
        "CTF_CAPACITY_AGENTS_PER_CPU": "6", "CTF_CAPACITY_SUBAGENT_CAP": "25",
        "CTF_CAPACITY_MAX_WORKERS": "4", "CTF_CAPACITY_RAM_BASIS": "total",
    })
    assert pol.per_agent_ram_mb == 256
    assert pol.reserve_ram_mb == 8192
    assert pol.agents_per_cpu == 6.0
    assert pol.per_worker_cap == 25
    assert pol.max_workers == 4
    assert pol.use_available_ram is False


def test_from_env_defaults_when_unset():
    pol = capacity.CapacityPolicy.from_env(environ={})
    assert pol.per_agent_ram_mb == capacity.DEFAULT_PER_AGENT_RAM_MB
    assert pol.max_workers is None
    assert pol.use_available_ram is True


def test_from_env_bad_value_fails_loudly():
    with pytest.raises(capacity.CapacityError):
        capacity.CapacityPolicy.from_env(environ={"CTF_CAPACITY_AGENT_RAM_MB": "lots"})
    with pytest.raises(capacity.CapacityError):
        capacity.CapacityPolicy.from_env(environ={"CTF_CAPACITY_AGENTS_PER_CPU": "many"})
    with pytest.raises(capacity.CapacityError):
        capacity.CapacityPolicy.from_env(environ={"CTF_CAPACITY_RAM_BASIS": "swap"})


# --- real host -----------------------------------------------------------------------------------

def test_measure_host_returns_sane_facts():
    h = capacity.measure_host()
    assert h.source == "measured"
    assert h.cpu_count >= 1
    assert h.total_ram_bytes > 0
    assert 0 <= h.available_ram_bytes <= h.total_ram_bytes


# --- CLI -----------------------------------------------------------------------------------------

_ENV_NAMES = ("CTF_CAPACITY_AGENT_RAM_MB", "CTF_CAPACITY_RESERVE_MB", "CTF_CAPACITY_AGENTS_PER_CPU",
              "CTF_CAPACITY_SUBAGENT_CAP", "CTF_CAPACITY_MAX_WORKERS", "CTF_CAPACITY_RAM_BASIS")


def _run(argv, monkeypatch, *, host_obj=None, environ=None):
    """Drive the CLI in-process against a synthetic host (never the real machine's numbers)."""
    if host_obj is not None:
        monkeypatch.setattr(capacity, "measure_host", lambda: host_obj)
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    for k, v in (environ or {}).items():
        monkeypatch.setenv(k, v)
    p = argparse.ArgumentParser()
    cli_capacity.add_arguments(p)
    return cli_capacity.run(p.parse_args(argv))


def test_cli_show_json_reports_budget(monkeypatch, capsys):
    import json
    rc = _run(["show", "--json"], monkeypatch,
              host_obj=host(cpu=14, total_gib=64),
              environ={"CTF_CAPACITY_AGENT_RAM_MB": "512", "CTF_CAPACITY_RESERVE_MB": "4096",
                       "CTF_CAPACITY_AGENTS_PER_CPU": "4", "CTF_CAPACITY_SUBAGENT_CAP": "20"})
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["cpu_count"] == 14
    assert out["capacity"] == 56
    assert out["workers"] == 3


def test_cli_plan_no_denials_exits_zero(monkeypatch, capsys):
    import json
    rc = _run(["plan", "--board", "54", "--json"], monkeypatch,
              host_obj=host(cpu=16, total_gib=64),
              environ={"CTF_CAPACITY_AGENT_RAM_MB": "256", "CTF_CAPACITY_RESERVE_MB": "2048",
                       "CTF_CAPACITY_AGENTS_PER_CPU": "5", "CTF_CAPACITY_SUBAGENT_CAP": "20"})
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["granted"] == 54 and out["queued"] == 0 and out["workers"] == 3
    assert out["satisfied"] is True


def test_cli_plan_with_denials_exits_one_and_names_reason(monkeypatch, capsys):
    rc = _run(["plan", "--board", "54"], monkeypatch,
              host_obj=host(cpu=4, total_gib=64),
              environ={"CTF_CAPACITY_AGENT_RAM_MB": "512", "CTF_CAPACITY_RESERVE_MB": "0",
                       "CTF_CAPACITY_AGENTS_PER_CPU": "3", "CTF_CAPACITY_SUBAGENT_CAP": "20"})
    assert rc == 1
    err = capsys.readouterr()
    assert "queued" in err.err


# --- round-1 verification additions ----------------------------------------------------------------

def test_cli_plan_json_with_denials_exits_one(monkeypatch, capsys):
    import json
    rc = _run(["plan", "--board", "54", "--json"], monkeypatch,
              host_obj=host(cpu=4, total_gib=64),
              environ={"CTF_CAPACITY_AGENT_RAM_MB": "512", "CTF_CAPACITY_RESERVE_MB": "0",
                       "CTF_CAPACITY_AGENTS_PER_CPU": "3", "CTF_CAPACITY_SUBAGENT_CAP": "20"})
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["satisfied"] is False and out["granted"] == 12 and out["queued"] == 42


def test_cli_plan_lanes_prints_each_worker_slot_count(monkeypatch, capsys):
    rc = _run(["plan", "--board", "54", "--lanes"], monkeypatch,
              host_obj=host(cpu=16, total_gib=64),
              environ={"CTF_CAPACITY_AGENT_RAM_MB": "256", "CTF_CAPACITY_RESERVE_MB": "2048",
                       "CTF_CAPACITY_AGENTS_PER_CPU": "5", "CTF_CAPACITY_SUBAGENT_CAP": "20"})
    assert rc == 0
    out = capsys.readouterr().out
    assert "worker 0: 20 slots" in out
    assert "worker 1: 20 slots" in out
    assert "worker 2: 14 slots" in out
    assert "worker 3" not in out


def test_cli_show_honours_max_workers_and_agrees_with_plan(monkeypatch, capsys):
    import json
    env = {"CTF_CAPACITY_AGENT_RAM_MB": "512", "CTF_CAPACITY_RESERVE_MB": "0",
           "CTF_CAPACITY_AGENTS_PER_CPU": "100", "CTF_CAPACITY_SUBAGENT_CAP": "20",
           "CTF_CAPACITY_MAX_WORKERS": "1"}
    h = host(cpu=16, total_gib=11)   # 11 GiB / 512 MiB = 22 agents, RAM-bound
    assert _run(["show", "--json"], monkeypatch, host_obj=h, environ=env) == 0
    show = json.loads(capsys.readouterr().out)
    assert show["capacity"] == 22          # the host budget
    assert show["workers"] == 1            # but CTF_CAPACITY_MAX_WORKERS=1
    assert show["seatable"] == 20
    assert _run(["plan", "--board", "54", "--json"], monkeypatch, host_obj=h, environ=env) == 1
    plan = json.loads(capsys.readouterr().out)
    assert plan["workers"] == show["workers"]
    assert plan["granted"] == show["seatable"]


def test_seating_without_max_workers_is_host_bounded():
    pol = capacity.CapacityPolicy(per_agent_ram_mb=512, reserve_ram_mb=0, agents_per_cpu=100.0,
                                  per_worker_cap=20)
    seat = capacity.seating(host(cpu=16, total_gib=11), pol)
    assert seat.budget.capacity == 22 and seat.workers == 2 and seat.seatable == 22


def test_negative_reserve_is_rejected():
    with pytest.raises(capacity.CapacityError, match="reserve_ram_mb"):
        capacity.CapacityPolicy(reserve_ram_mb=-1)
    capacity.CapacityPolicy(reserve_ram_mb=0)  # zero is allowed


def test_negative_ram_field_is_rejected():
    with pytest.raises(capacity.CapacityError, match="available_ram_bytes is negative"):
        capacity.HostResources(total_ram_bytes=GiB, available_ram_bytes=-1, cpu_count=4)


def test_fractional_agents_per_cpu_floors():
    # 3 CPUs * 1.5 = 4.5 -> 4 agents (never round a CPU share up into an extra lane).
    pol = capacity.CapacityPolicy(per_agent_ram_mb=256, reserve_ram_mb=0, agents_per_cpu=1.5)
    b = capacity.concurrency_budget(host(cpu=3, total_gib=64), pol)
    assert b.by_cpu == 4 and b.capacity == 4


def test_measure_host_fails_loudly_when_cpu_count_is_unknown(monkeypatch):
    import psutil
    monkeypatch.setattr(psutil, "cpu_count", lambda logical=True: None)
    with pytest.raises(capacity.CapacityError, match="CPU count"):
        capacity.measure_host()


def test_tie_reason_names_both_ram_and_cpu():
    # 8 GiB / 512 MiB = 16 by RAM; 4 CPU * 4 = 16 by CPU.
    pol = capacity.CapacityPolicy(per_agent_ram_mb=512, reserve_ram_mb=0, agents_per_cpu=4.0)
    plan = capacity.plan_board(20, host(cpu=4, total_gib=8), pol)
    assert plan.budget.binding == "tie" and plan.granted == 16 and plan.denied == 4
    assert "RAM- and CPU-bound" in plan.reason
    assert "512 MiB per agent" in plan.reason and "4.0/CPU" in plan.reason


def test_ids_with_no_demand_take_their_length():
    pol = capacity.CapacityPolicy(agents_per_cpu=10.0, per_worker_cap=2)
    plan = capacity.plan_board(None, host(cpu=4, total_gib=64), pol, ids=["x", "y", "z"])
    assert plan.demand == 3 and plan.satisfied
    assert plan.lanes == (("x", "y"), ("z",))


def test_no_demand_and_no_ids_fails_loudly():
    with pytest.raises(capacity.CapacityError, match="demand"):
        capacity.plan_board(None, host(), capacity.CapacityPolicy())


def test_from_env_reads_only_the_canonical_capacity_names():
    # The old generic names are not policy knobs; only CTF_CAPACITY_* is.
    pol = capacity.CapacityPolicy.from_env(environ={"CTF_MAX_WORKERS": "1", "CTF_AGENT_RAM_MB": "64"})
    assert pol.max_workers is None
    assert pol.per_agent_ram_mb == capacity.DEFAULT_PER_AGENT_RAM_MB


def test_from_env_bad_int_names_the_variable():
    with pytest.raises(capacity.CapacityError, match="CTF_CAPACITY_MAX_WORKERS"):
        capacity.CapacityPolicy.from_env(environ={"CTF_CAPACITY_MAX_WORKERS": "two"})


def test_cli_show_bad_env_exits_two(monkeypatch, capsys):
    rc = _run(["show"], monkeypatch, host_obj=host(), environ={"CTF_CAPACITY_SUBAGENT_CAP": "x"})
    assert rc == 2
    assert "CTF_CAPACITY_SUBAGENT_CAP" in capsys.readouterr().err


# --- verification round 2 ------------------------------------------------------------------------

@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", "NaN", "Infinity"])
def test_non_finite_agents_per_cpu_from_env_fails_loudly(raw):
    # float() accepts these; nan slips past `<= 0` and inf passes it, then math.floor crashes later.
    with pytest.raises(capacity.CapacityError, match="CTF_CAPACITY_AGENTS_PER_CPU must be a finite"):
        capacity.CapacityPolicy.from_env(environ={"CTF_CAPACITY_AGENTS_PER_CPU": raw})


def test_non_finite_agents_per_cpu_in_policy_is_rejected():
    for bad in (float("nan"), float("inf")):
        with pytest.raises(capacity.CapacityError, match="agents_per_cpu must be a finite"):
            capacity.CapacityPolicy(agents_per_cpu=bad)


@pytest.mark.parametrize("action", [["show"], ["plan", "--board", "5"]])
@pytest.mark.parametrize("raw", ["nan", "inf"])
def test_cli_non_finite_agents_per_cpu_exits_two(monkeypatch, capsys, raw, action):
    rc = _run(action, monkeypatch, host_obj=host(), environ={"CTF_CAPACITY_AGENTS_PER_CPU": raw})
    assert rc == 2
    assert "CTF_CAPACITY_AGENTS_PER_CPU" in capsys.readouterr().err


def test_max_workers_set_but_not_binding_names_the_host_resource():
    # 16 CPU * 1 = 16 by CPU; 64 GiB / 256 MiB = 256 by RAM -> CPU-bound at 16.
    # max_workers=5 * cap 20 = 100 seats, far above 16, so the worker ceiling does not bind.
    pol = capacity.CapacityPolicy(per_agent_ram_mb=256, reserve_ram_mb=0, agents_per_cpu=1.0,
                                  per_worker_cap=20, max_workers=5)
    plan = capacity.plan_board(30, host(cpu=16, total_gib=64), pol)
    assert plan.capacity == 16 and plan.granted == 16 and plan.denied == 14
    assert "CPU-bound" in plan.reason
    assert "MAX_WORKERS" not in plan.reason


def test_max_workers_seating_exactly_the_budget_is_not_blamed():
    # max_workers * cap == budget (2 * 20 == 40): the ceiling does not bite below the host budget.
    pol = capacity.CapacityPolicy(per_agent_ram_mb=256, reserve_ram_mb=0, agents_per_cpu=2.5,
                                  per_worker_cap=20, max_workers=2)
    plan = capacity.plan_board(54, host(cpu=16, total_gib=64), pol)
    assert plan.capacity == 40 and plan.granted == 40 and plan.workers == 2
    assert "CPU-bound" in plan.reason
    assert "MAX_WORKERS" not in plan.reason


def test_seating_budget_an_exact_multiple_of_the_cap():
    # 16 CPU * 2.5 = 40 agents, cap 20 -> exactly 2 workers, not 3.
    pol = capacity.CapacityPolicy(per_agent_ram_mb=256, reserve_ram_mb=0, agents_per_cpu=2.5,
                                  per_worker_cap=20)
    seat = capacity.seating(host(cpu=16, total_gib=64), pol)
    assert seat.budget.capacity == 40 and seat.workers == 2 and seat.seatable == 40


def test_cli_show_exact_multiple_budget_reports_exact_workers(monkeypatch, capsys):
    import json
    env = {"CTF_CAPACITY_AGENT_RAM_MB": "256", "CTF_CAPACITY_RESERVE_MB": "0",
           "CTF_CAPACITY_AGENTS_PER_CPU": "2.5", "CTF_CAPACITY_SUBAGENT_CAP": "20"}
    assert _run(["show", "--json"], monkeypatch, host_obj=host(cpu=16, total_gib=64), environ=env) == 0
    show = json.loads(capsys.readouterr().out)
    assert show["capacity"] == 40 and show["workers"] == 2 and show["seatable"] == 40
