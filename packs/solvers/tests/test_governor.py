"""B-176: host resource governor -- readings, policy, decision, host-wide slots, RSS watchdog, measure,
doctor checks and the `ctf governor` CLI. Every host reading here is synthetic except the two smoke tests
that read this host (load/RAM/disk and the process table), which assert only what any host satisfies."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ctf import governor as gov
from ctf.cli import governor as cli

GiB = gov.GiB
MiB = gov.MiB


def state(**kw) -> gov.HostState:
    base = dict(cpu_count=10, load1=1.0, load5=1.0, load15=1.0, total_ram_bytes=64 * GiB,
                available_ram_bytes=48 * GiB, disk_path="/x", disk_free_bytes=200 * GiB,
                disk_total_bytes=500 * GiB, pressure="normal", battery=gov.Battery(present=False),
                thermal=gov.Thermal(speed_limit=100), source="synthetic")
    base.update(kw)
    return gov.HostState(**base)


# ------------------------------------------------------------------------------------------ parsers

PMSET_CHARGED = ("Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; charged; 0:00 remaining "
                 "present: true\n")
PMSET_DEFICIT = ("Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t12%; discharging; 0:40 remaining "
                 "present: true\n")
PMSET_ON_BATT = ("Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t64%; discharging; 3:10 "
                 "remaining present: true\n")
PMSET_NOT_CHARGING = ("Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t80%; AC attached; not "
                      "charging present: true\n")
PMSET_DESKTOP = "Now drawing from 'AC Power'\n"
THERM_NOMINAL = ("Note: No thermal warning level has been recorded\nNote: No performance warning level has "
                 "been recorded\nNote: No CPU power status has been recorded\n")
THERM_INTEL = "CPU_Scheduler_Limit \t= 100\nCPU_Available_CPUs \t= 8\nCPU_Speed_Limit \t= 70\n"
THERM_WARN = ("Thermal warning level set to 2.\nNote: No performance warning level has been recorded\n")


def test_pmset_batt_charged_on_ac():
    b = gov.parse_pmset_batt(PMSET_CHARGED)
    assert (b.present, b.percent, b.plugged, b.state) == (True, 100.0, True, "charged")
    assert not b.charger_deficit


def test_pmset_batt_discharging_on_ac_is_a_charger_deficit():
    b = gov.parse_pmset_batt(PMSET_DEFICIT)
    assert (b.percent, b.plugged, b.state) == (12.0, True, "discharging")
    assert b.charger_deficit


def test_pmset_batt_on_battery_is_not_a_charger_deficit():
    b = gov.parse_pmset_batt(PMSET_ON_BATT)
    assert (b.plugged, b.state, b.charger_deficit) == (False, "discharging", False)


def test_pmset_batt_ac_attached_not_charging():
    assert gov.parse_pmset_batt(PMSET_NOT_CHARGING).state == "not-charging"


def test_pmset_batt_no_battery_line_means_no_battery():
    b = gov.parse_pmset_batt(PMSET_DESKTOP)
    assert b.present is False and b.plugged is True


def test_pmset_batt_unparseable_battery_line_raises_not_no_battery():
    with pytest.raises(gov.GovernorError, match="not understood"):
        gov.parse_pmset_batt(" -InternalBattery-0 (id=1)\tgarbled\n")


def test_pmset_therm_nominal_apple_silicon():
    t = gov.parse_pmset_therm(THERM_NOMINAL)
    assert t == gov.Thermal(speed_limit=None, warning_level=0, performance_level=0)


def test_pmset_therm_speed_limit_and_warning_level():
    assert gov.parse_pmset_therm(THERM_INTEL).speed_limit == 70
    t = gov.parse_pmset_therm(THERM_WARN)
    assert t.warning_level == 2 and t.performance_level == 0


def test_pmset_therm_unknown_output_is_none():
    assert gov.parse_pmset_therm("something else entirely\n") is None


def test_pressure_levels():
    assert [gov.parse_pressure_level(x) for x in ("1\n", "2", "4", "7", "x")] == [
        "normal", "warn", "critical", None, None]


# ------------------------------------------------------------------------------------------ probe

class FakePsutil:
    def __init__(self, battery=None, cpus=8, total=32 * GiB, avail=16 * GiB):
        self._b, self._cpus, self._t, self._a = battery, cpus, total, avail

    def virtual_memory(self):
        return SimpleNamespace(total=self._t, available=self._a)

    def cpu_count(self, logical=True):
        return self._cpus

    def sensors_battery(self):
        return self._b


def fake_run(outputs):
    calls = []

    def run(argv):
        calls.append(tuple(argv))
        out = outputs.get(tuple(argv))
        if isinstance(out, BaseException):
            raise out
        if out is None:
            return 1, ""
        return 0, out
    run.calls = calls
    return run


def test_probe_darwin_reads_battery_state_thermal_and_pressure(tmp_path):
    run = fake_run({("pmset", "-g", "batt"): PMSET_DEFICIT, ("pmset", "-g", "therm"): THERM_WARN,
                    ("sysctl", "-n", "kern.memorystatus_vm_pressure_level"): "4\n"})
    ps = FakePsutil(battery=SimpleNamespace(percent=12, power_plugged=True))
    s = gov.probe_host(tmp_path, run=run, psutil_mod=ps, loadavg=lambda: (9.0, 8.0, 7.0), platform="darwin")
    assert (s.cpu_count, s.load1, s.available_ram_bytes) == (8, 9.0, 16 * GiB)
    assert s.battery.charger_deficit and s.battery.percent == 12
    assert s.thermal.warning_level == 2 and s.pressure == "critical"
    assert s.unknown == () and s.disk_free_bytes > 0 and s.disk_path == str(tmp_path)


def test_probe_missing_pmset_is_unknown_with_reason_not_a_guess(tmp_path):
    run = fake_run({("pmset", "-g", "batt"): FileNotFoundError(), ("pmset", "-g", "therm"): FileNotFoundError(),
                    ("sysctl", "-n", "kern.memorystatus_vm_pressure_level"): "1"})
    ps = FakePsutil(battery=SimpleNamespace(percent=50, power_plugged=True))
    s = gov.probe_host(tmp_path, run=run, psutil_mod=ps, loadavg=lambda: (1, 1, 1), platform="darwin")
    unk = dict(s.unknown)
    assert unk["thermal"] == "pmset not found" and unk["battery-state"] == "pmset not found"
    assert s.thermal is None and s.battery.state == "" and s.pressure == "normal"


def test_probe_non_darwin_names_thermal_and_pressure_unknown(tmp_path):
    s = gov.probe_host(tmp_path, run=fake_run({}), psutil_mod=FakePsutil(), loadavg=lambda: (1, 1, 1),
                       platform="linux")
    unk = dict(s.unknown)
    assert "macOS only" in unk["thermal"] and "macOS only" in unk["pressure"]
    assert s.battery == gov.Battery(present=False)


def test_probe_nonzero_exit_is_unknown(tmp_path):
    run = fake_run({("sysctl", "-n", "kern.memorystatus_vm_pressure_level"): "1"})  # pmset -> rc 1
    s = gov.probe_host(tmp_path, run=run, psutil_mod=FakePsutil(), loadavg=lambda: (1, 1, 1), platform="darwin")
    assert "exited 1" in dict(s.unknown)["thermal"]


def test_probe_disk_uses_nearest_existing_ancestor(tmp_path):
    s = gov.probe_host(tmp_path / "not" / "yet", run=fake_run({}), psutil_mod=FakePsutil(),
                       loadavg=lambda: (1, 1, 1), platform="linux")
    assert s.disk_path == str(tmp_path)


def test_probe_load_unreadable_raises(tmp_path):
    def bad():
        raise OSError("no loadavg")
    with pytest.raises(gov.GovernorError, match="load average"):
        gov.probe_host(tmp_path, run=fake_run({}), psutil_mod=FakePsutil(), loadavg=bad, platform="linux")


def test_probe_real_host_smoke(tmp_path):
    s = gov.probe_host(tmp_path)
    assert s.cpu_count == os.cpu_count()
    assert 0 < s.available_ram_bytes <= s.total_ram_bytes and s.disk_free_bytes > 0
    assert s.source == "measured"


def test_hoststate_rejects_inconsistent_readings():
    with pytest.raises(gov.GovernorError):
        state(cpu_count=0)
    with pytest.raises(gov.GovernorError):
        state(available_ram_bytes=65 * GiB)
    with pytest.raises(gov.GovernorError):
        state(load1=float("nan"))


def test_hoststate_resources_feeds_b018_capacity():
    r = state().resources()
    assert (r.total_ram_bytes, r.available_ram_bytes, r.cpu_count) == (64 * GiB, 48 * GiB, 10)


# ------------------------------------------------------------------------------------------ decide

def test_idle_host_seats_the_policy_cap_with_nothing_binding():
    d = gov.decide(state(), gov.GovernorPolicy())
    assert d.cap == gov.DEFAULT_HEAVY_CAP == 6 and d.slots == 6 and d.binding == ()
    assert "policy cap 6" in d.reason


def test_pink_plus_load_140_stops_new_heavy_agents():
    d = gov.decide(state(cpu_count=14, load1=140.0), gov.GovernorPolicy())
    assert d.cap == 0 and d.slots == 0
    assert [l.resource for l in d.binding] == ["load"] and "hard 3.0/CPU" in d.reason


def test_load_thresholds_are_inclusive():
    p = gov.GovernorPolicy(heavy_cap=6, load_soft=1.5, load_hard=3.0)
    assert gov.decide(state(load1=14.9), p).cap == 6
    assert gov.decide(state(load1=15.0), p).cap == 3        # 1.5/CPU on 10 CPUs: halved
    assert gov.decide(state(load1=29.9), p).cap == 3
    assert gov.decide(state(load1=30.0), p).cap == 0        # 3.0/CPU: none


def test_ram_headroom_adds_to_running_agents():
    p = gov.GovernorPolicy(heavy_cap=10, heavy_ram_mb=2048, reserve_ram_mb=4096)
    s = state(available_ram_bytes=(4096 + 2 * 2048 + 100) * MiB)
    d = gov.decide(s, p, running=3)
    assert d.cap == 5 and d.slots == 2 and d.binding[0].resource == "ram"
    assert "room for 2 more" in d.reason


def test_ram_below_reserve_gives_no_room():
    p = gov.GovernorPolicy(reserve_ram_mb=4096)
    d = gov.decide(state(available_ram_bytes=1 * GiB), p, running=2)
    assert d.cap == 2 and d.slots == 0


def test_memory_pressure_levels():
    assert gov.decide(state(pressure="critical")).cap == 0
    assert gov.decide(state(pressure="warn")).cap == 3
    assert gov.decide(state(pressure=None)).cap == 6


@pytest.mark.parametrize("battery,cap", [
    (gov.Battery(True, 64.0, False, "discharging"), 3),     # on battery: halved
    (gov.Battery(True, 20.0, False, "discharging"), 0),     # on battery under the floor
    (gov.Battery(True, 50.0, True, "discharging"), 3),      # charger cannot keep up
    (gov.Battery(True, 12.0, True, "discharging"), 0),      # Huntress: 100% -> 12% on a 128 W charger
    (gov.Battery(True, 100.0, True, "charged"), 6),
    (gov.Battery(True, 80.0, True, "not-charging"), 6),
    (gov.Battery(False), 6),
])
def test_battery_limits(battery, cap):
    assert gov.decide(state(battery=battery), gov.GovernorPolicy(battery_low=25)).cap == cap


def test_battery_floor_is_strict_less_than():
    p = gov.GovernorPolicy(battery_low=25)
    assert gov.decide(state(battery=gov.Battery(True, 25.0, False, "discharging")), p).cap == 3
    assert gov.decide(state(battery=gov.Battery(True, 24.9, False, "discharging")), p).cap == 0


@pytest.mark.parametrize("thermal,cap", [
    (gov.Thermal(speed_limit=100), 6),
    (gov.Thermal(speed_limit=None), 6),
    (gov.Thermal(speed_limit=99), 3),
    (gov.Thermal(speed_limit=60), 3),
    (gov.Thermal(speed_limit=59), 0),
    (gov.Thermal(warning_level=1), 3),
    (gov.Thermal(performance_level=1), 3),
    (gov.Thermal(warning_level=2), 0),
])
def test_thermal_limits(thermal, cap):
    assert gov.decide(state(thermal=thermal)).cap == cap


def test_disk_floor_stops_new_agents_spooky_806mb():
    p = gov.GovernorPolicy(disk_min_gb=10)
    d = gov.decide(state(disk_free_bytes=806 * MiB), p)
    assert d.cap == 0 and d.binding[0].resource == "disk" and "CTF_GOVERNOR_DISK_MIN_GB" in d.reason
    assert gov.decide(state(disk_free_bytes=10 * GiB), p).cap == 6


def test_unknown_reading_is_reported_and_blocks_only_when_strict():
    s = state(thermal=None, unknown=(("thermal", "pmset not found"),))
    d = gov.decide(s, gov.GovernorPolicy())
    assert d.cap == 6 and dict(d.unknown) == {"thermal": "pmset not found"}
    ds = gov.decide(s, gov.GovernorPolicy(strict=True))
    assert ds.cap == 0 and "pmset not found" in ds.reason and "CTF_GOVERNOR_STRICT" in ds.reason


def test_lowest_ceiling_wins_and_ties_are_all_named():
    s = state(pressure="warn", thermal=gov.Thermal(warning_level=1))
    d = gov.decide(s)
    assert d.cap == 3 and {l.resource for l in d.binding} == {"pressure", "thermal"}


def test_admit_queues_the_rest_with_the_binding_reason():
    d = gov.decide(state(cpu_count=14, load1=21.0), gov.GovernorPolicy(heavy_cap=6), running=1)
    a = d.admit(["a", "b", "c", "d"])
    assert a.granted == ("a", "b") and a.queued == ("c", "d")
    assert "2 queued: 1 running, cap 3" in a.reason and "load" in a.reason
    assert d.admit(["x"]).reason == ""


def test_running_over_cap_gives_zero_slots_not_negative():
    d = gov.decide(state(pressure="critical"), running=4)
    assert d.slots == 0 and d.to_dict()["slots"] == 0


def test_negative_running_rejected():
    with pytest.raises(gov.GovernorError):
        gov.decide(state(), running=-1)


# ------------------------------------------------------------------------------------------ policy

def test_policy_from_env_overrides():
    p = gov.GovernorPolicy.from_env(environ={
        "CTF_GOVERNOR_HEAVY_CAP": "4", "CTF_GOVERNOR_HEAVY_RAM_MB": "3000", "CTF_GOVERNOR_LOAD_SOFT": "1",
        "CTF_GOVERNOR_LOAD_HARD": "2.5", "CTF_GOVERNOR_BATTERY_LOW": "40", "CTF_GOVERNOR_DISK_MIN_GB": "2.5",
        "CTF_GOVERNOR_RSS_ALERT_MB": "4096", "CTF_GOVERNOR_STRICT": "1", "CTF_CAPACITY_RESERVE_MB": "1024",
        "CTF_GOVERNOR_AGENT_NAMES": "claude, codex ,aider"})
    assert (p.heavy_cap, p.heavy_ram_mb, p.load_soft, p.load_hard, p.battery_low, p.disk_min_gb,
            p.rss_alert_mb, p.strict, p.reserve_ram_mb, p.agent_names) == (
        4, 3000, 1.0, 2.5, 40, 2.5, 4096, True, 1024, ("claude", "codex", "aider"))


def test_policy_from_env_defaults():
    assert gov.GovernorPolicy.from_env(environ={}) == gov.GovernorPolicy()


@pytest.mark.parametrize("env", [
    {"CTF_GOVERNOR_HEAVY_CAP": "six"}, {"CTF_GOVERNOR_HEAVY_CAP": "0"}, {"CTF_GOVERNOR_LOAD_SOFT": "nan"},
    {"CTF_GOVERNOR_LOAD_HARD": "x"}, {"CTF_GOVERNOR_LOAD_SOFT": "4", "CTF_GOVERNOR_LOAD_HARD": "2"},
    {"CTF_GOVERNOR_BATTERY_LOW": "101"}, {"CTF_GOVERNOR_DISK_MIN_GB": "inf"}, {"CTF_GOVERNOR_STRICT": "maybe"},
    {"CTF_GOVERNOR_AGENT_NAMES": " , "}, {"CTF_CAPACITY_RESERVE_MB": "-1"},
])
def test_policy_bad_env_fails_loudly(env):
    with pytest.raises(gov.GovernorError):
        gov.GovernorPolicy.from_env(environ=env)


# ------------------------------------------------------------------------------------------ slots

def make_gov(tmp_path, cap=2, alive=None, clock=None):
    p = gov.GovernorPolicy(heavy_cap=cap)
    kw = {}
    if alive is not None:
        kw["pid_alive"] = alive
    if clock is not None:
        kw["clock"] = clock
    return gov.Governor(tmp_path / "gov", p, probe=lambda: state(), **kw)


def test_slots_cap_then_release_admits_the_next(tmp_path):
    g = make_gov(tmp_path, cap=2)
    a, b = g.acquire("a", timeout=0), g.acquire("b", timeout=0)
    assert len(g.leases()) == 2
    t = g.enqueue("c")
    assert g.try_acquire(t) is None and g.last.slots == 0
    g.release(a)
    lease = g.try_acquire(t)
    assert lease is not None and lease.label == "c"
    assert sorted(l.label for l in g.leases()) == ["b", "c"] and g.queue() == []


def test_queue_is_fifo(tmp_path):
    g = make_gov(tmp_path, cap=1)
    first, second = g.enqueue("first"), g.enqueue("second")
    assert g.try_acquire(second) is None          # one slot, and "first" is ahead
    assert g.try_acquire(first) is not None
    assert g.try_acquire(second) is None          # the slot is taken now


def test_two_queued_with_two_slots_both_admitted(tmp_path):
    g = make_gov(tmp_path, cap=2)
    first, second = g.enqueue("first"), g.enqueue("second")
    assert g.try_acquire(second) is not None      # position 1 < 2 free slots
    assert g.try_acquire(first) is not None


def test_dead_lease_is_reaped_and_frees_its_slot(tmp_path):
    dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                          capture_output=True, text=True).stdout.strip()
    g = make_gov(tmp_path, cap=1)
    leases = g.dir / "leases"
    leases.mkdir(parents=True)
    (leases / "0-x.json").write_text(json.dumps({"id": "0-x", "pid": int(dead), "label": "ghost"}))
    (leases / "1-y.json").write_text("{not json")
    lease = g.acquire("live", timeout=0)
    assert lease.label == "live"
    assert any("gone" in r for r in g.reaped) and any("unreadable" in r for r in g.reaped)
    assert [p.name for p in leases.iterdir()] == [f"{lease.id}.json"]


def test_acquire_times_out_naming_the_binding_limit(tmp_path):
    now = [0.0]
    sleeps, waits = [], []

    def sleep(s):
        sleeps.append(s)
        now[0] += s
    g = gov.Governor(tmp_path / "gov", gov.GovernorPolicy(), probe=lambda: state(load1=100.0),
                     clock=lambda: now[0])
    with pytest.raises(gov.GovernorTimeout, match="load"):
        g.acquire("x", timeout=10, poll=4, sleep=sleep, on_wait=lambda d, pos: waits.append(pos))
    assert sleeps == [4, 4, 4] and waits == [0, 0, 0]
    assert g.queue() == []                         # the ticket is withdrawn on timeout


def test_acquire_waits_then_is_admitted_when_the_host_recovers(tmp_path):
    loads = iter([100.0, 100.0, 1.0])
    g = gov.Governor(tmp_path / "gov", gov.GovernorPolicy(), probe=lambda: state(load1=next(loads)))
    slept = []
    lease = g.acquire("x", timeout=None, poll=1, sleep=slept.append)
    assert lease.label == "x" and slept == [1, 1]


def test_acquire_rejects_nonpositive_poll(tmp_path):
    with pytest.raises(gov.GovernorError):
        make_gov(tmp_path).acquire("x", poll=0)


# ------------------------------------------------------------------------------------------ watchdog

def procs():
    return [
        gov.Proc(1, 0, "launchd", 10 * MiB),
        gov.Proc(100, 1, "zsh", 5 * MiB),
        gov.Proc(101, 100, "2.1.319", 900 * MiB, 10.0, exe="/opt/x/claude/versions/2.1.319"),
        gov.Proc(102, 101, "python3", 7 * GiB, 50.0),
        gov.Proc(103, 102, "qemu-system-x86_64", 2 * GiB, 30.0),
        gov.Proc(104, 101, "claude", 100 * MiB, 1.0),          # nested agent: counted in 101's tree
        gov.Proc(200, 1, "codex", 300 * MiB, 5.0),
        gov.Proc(300, 1, "Claude", 4 * GiB, 1.0, exe="/Applications/Claude.app/Contents/MacOS/Claude"),
    ]


def test_agent_trees_group_descendants_once_and_skip_the_desktop_app():
    trees = gov.agent_trees(procs())
    assert [(t.root, t.pids) for t in trees] == [(101, (101, 102, 103, 104)), (200, (200,))]
    assert trees[0].rss_bytes == 900 * MiB + 7 * GiB + 2 * GiB + 100 * MiB
    assert trees[0].cpu_seconds == 91.0


def test_rss_alert_fires_at_threshold_per_tree():
    trees = gov.agent_trees(procs())
    p = gov.GovernorPolicy(rss_alert_mb=10 * 1024)
    alerts = gov.rss_alerts(trees, p, total_ram_bytes=64 * GiB)
    assert len(alerts) == 0
    p = gov.GovernorPolicy(rss_alert_mb=int(trees[0].rss_bytes // MiB))
    alerts = gov.rss_alerts(trees, p, total_ram_bytes=64 * GiB)
    assert len(alerts) == 1 and "pid 101" in alerts[0] and "4 processes" in alerts[0]


def test_rss_alert_on_all_agents_holding_half_of_ram():
    trees = gov.agent_trees(procs())
    total = sum(t.rss_bytes for t in trees)
    p = gov.GovernorPolicy(rss_alert_mb=1024 * 1024)
    assert any("half of" in a for a in gov.rss_alerts(trees, p, total_ram_bytes=total * 2))
    assert gov.rss_alerts(trees, p, total_ram_bytes=total * 2 + 2) == []


def test_record_alerts_appends_jsonl(tmp_path):
    gov.record_alerts(tmp_path, ["a", "b"], clock=lambda: 5.0)
    gov.record_alerts(tmp_path, [])
    lines = (tmp_path / "alerts.jsonl").read_text().splitlines()
    assert [json.loads(l) for l in lines] == [{"ts": 5.0, "alert": "a"}, {"ts": 5.0, "alert": "b"}]


def test_snapshot_processes_real_host_sees_this_process():
    ps, unreadable = gov.snapshot_processes()
    me = [p for p in ps if p.pid == os.getpid()]
    assert me and me[0].rss_bytes > 0 and unreadable >= 0


# ------------------------------------------------------------------------------------------ measure

def test_measure_rss_p90_and_cpu_from_deltas():
    before = procs()
    after = [gov.Proc(p.pid, p.ppid, p.name, p.rss_bytes, p.cpu_seconds + (2.0 if p.pid in (102, 200) else 0),
                      p.exe) for p in before]
    m = gov.measure(before, after, 4.0)
    assert m.agents == 2
    assert m.cpu_percent == (50.0, 50.0)                    # 2 CPU-s over 4 s each
    assert m.agents_per_cpu == 2.0
    big = (900 * MiB + 7 * GiB + 2 * GiB + 100 * MiB) / MiB
    assert m.rss_mib == (round(big, 1), 300.0)
    assert m.per_agent_ram_mb == int(-(-round(big, 1) * 1.25 // 1))


def test_measure_clamps_near_idle_cpu():
    m = gov.measure(procs(), [gov.Proc(p.pid, p.ppid, p.name, p.rss_bytes, p.cpu_seconds + 0.05, p.exe)
                              for p in procs()], 10.0)
    assert m.agents_per_cpu == gov.MAX_AGENTS_PER_CPU


def test_measure_without_agents_raises_naming_why():
    with pytest.raises(gov.GovernorError, match="no agent processes"):
        gov.measure([], [gov.Proc(1, 0, "launchd", 1)], 1.0)


# ------------------------------------------------------------------------------------------ checks

def by_name(checks):
    return {c.name: c for c in checks}


def test_host_checks_on_an_overloaded_host():
    s = state(cpu_count=14, load1=140.0, battery=gov.Battery(True, 12.0, True, "discharging"))
    p = gov.GovernorPolicy()
    c = by_name(gov.host_checks(s, gov.decide(s, p), p, trees=[]))
    assert c["host-load"].status == "fail" and c["host-battery"].status == "fail"
    assert c["governor"].status == "warn" and c["host-disk"].status == "ok"
    assert c["agent-rss"].status == "ok" and c["agent-budget"].status == "skip"


def test_host_checks_unread_is_skip_and_strict_is_fail():
    s = state(thermal=None, battery=None, unknown=(("thermal", "pmset not found"), ("battery", "boom")))
    for strict, want in ((False, "skip"), (True, "fail")):
        p = gov.GovernorPolicy(strict=strict)
        c = by_name(gov.host_checks(s, gov.decide(s, p), p))
        assert c["host-thermal"].status == want and "pmset not found" in c["host-thermal"].detail
        assert c["host-battery"].status == want and c["agent-rss"].status == want


def test_host_checks_ram_and_rss_alert_and_measurement():
    s = state(available_ram_bytes=2 * GiB, pressure="warn")
    p = gov.GovernorPolicy(rss_alert_mb=1024)
    trees = gov.agent_trees(procs())
    m = gov.measure(procs(), procs(), 1.0)
    c = by_name(gov.host_checks(s, gov.decide(s, p), p, trees=trees, measurement=m))
    assert c["host-ram"].status == "fail"
    assert c["agent-rss"].status == "fail" and "pid 101" in c["agent-rss"].detail
    assert c["agent-budget"].status == "ok" and f"CTF_CAPACITY_AGENT_RAM_MB={m.per_agent_ram_mb}" in \
        c["agent-budget"].detail


def test_host_checks_pressure_warn_with_room_is_warn():
    s = state(pressure="warn")
    p = gov.GovernorPolicy()
    assert by_name(gov.host_checks(s, gov.decide(s, p), p))["host-ram"].status == "warn"


# ------------------------------------------------------------------------------------------ CLI

def parse(*argv):
    ap = argparse.ArgumentParser()
    cli.add_arguments(ap)
    return ap.parse_args(list(argv))


@pytest.fixture
def gstate(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GOVERNOR_STATE", str(tmp_path / "gov"))
    return tmp_path / "gov"


def test_cli_status_json(gstate, monkeypatch, capsys):
    monkeypatch.setattr(gov, "probe_host", lambda disk: state(cpu_count=14, load1=21.0))
    assert cli.run(parse("status", "--json", "--disk-path", str(gstate.parent))) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"]["cap"] == 3 and out["decision"]["slots"] == 3 and out["host"]["cpu_count"] == 14
    assert out["disk_basis"] == "--disk-path"


def test_cli_run_holds_a_slot_while_the_command_runs_and_frees_it(gstate, monkeypatch, tmp_path):
    monkeypatch.setattr(gov, "probe_host", lambda disk: state())
    seen = tmp_path / "seen.txt"
    code = ("import pathlib,sys; d=pathlib.Path(sys.argv[1]); "
            "pathlib.Path(sys.argv[2]).write_text(str(len(list(d.glob('*.json'))))); sys.exit(7)")
    rc = cli.run(parse("run", "--label", "probe", "--", sys.executable, "-c", code,
                       str(gstate / "leases"), str(seen)))
    assert rc == 7 and seen.read_text() == "1"
    assert list((gstate / "leases").glob("*.json")) == []


def test_cli_run_times_out_with_exit_3(gstate, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(gov, "probe_host", lambda disk: state(disk_free_bytes=1))
    marker = tmp_path / "ran"
    rc = cli.run(parse("run", "--timeout", "0", "--", sys.executable, "-c",
                       f"open({str(marker)!r}, 'w')"))
    assert rc == cli.TIMEOUT_EXIT and not marker.exists()
    assert "disk" in capsys.readouterr().err


def test_cli_run_without_command_is_an_error(gstate):
    assert cli.run(parse("run")) == 2


def test_cli_check_exit_codes(gstate, monkeypatch, capsys):
    monkeypatch.setenv("CTF_GOVERNOR_RSS_ALERT_MB", "1000000")
    monkeypatch.setattr(gov, "probe_host", lambda disk: state())
    monkeypatch.setattr(gov, "snapshot_processes", lambda: (procs(), 0))
    assert cli.run(parse("check", "--disk-path", str(gstate.parent))) == 0
    assert "HOST OK" in capsys.readouterr().out
    assert cli.run(parse("check", "--strict", "--disk-path", str(gstate.parent))) == 1   # agent-budget skip
    assert "FAILED: agent-budget" in capsys.readouterr().out
    monkeypatch.setattr(gov, "probe_host", lambda disk: state(load1=100.0))
    assert cli.run(parse("check", "--json", "--disk-path", str(gstate.parent))) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["passed"] is False
    assert {c["name"]: c["status"] for c in out["checks"]}["host-load"] == "fail"


def test_cli_bad_env_exits_2(gstate, monkeypatch, capsys):
    monkeypatch.setenv("CTF_GOVERNOR_HEAVY_CAP", "lots")
    assert cli.run(parse("status")) == 2
    assert "CTF_GOVERNOR_HEAVY_CAP" in capsys.readouterr().err


def test_cli_watch_once_alerts_and_records(gstate, monkeypatch, capsys):
    monkeypatch.setenv("CTF_GOVERNOR_RSS_ALERT_MB", "8192")
    monkeypatch.setattr(gov, "snapshot_processes", lambda: (procs(), 0))
    assert cli.run(parse("watch", "--once")) == 1
    assert "ALERT agent 2.1.319 pid 101" in capsys.readouterr().err
    assert "pid 101" in (gstate / "alerts.jsonl").read_text()
    monkeypatch.setenv("CTF_GOVERNOR_RSS_ALERT_MB", "1000000")
    assert cli.run(parse("watch", "--once")) == 0


def test_notify_sanitises_the_message():
    calls = []
    cli._notify('agent "x"; do shell script "rm" pid 1', run=lambda argv, **kw: calls.append(argv))
    assert calls[0][:2] == ["osascript", "-e"]
    assert calls[0][2] == 'display notification "agent x do shell script rm pid 1" with title "ctf governor"'


def test_cli_measure_no_agents_exits_2(gstate, monkeypatch, capsys):
    monkeypatch.setattr(gov, "snapshot_processes", lambda: ([gov.Proc(1, 0, "launchd", 1)], 0))
    monkeypatch.setattr(cli.time, "sleep", lambda s: None)
    assert cli.run(parse("measure", "--interval", "1")) == 2
    assert "no agent processes" in capsys.readouterr().err


def test_halving_never_drops_below_one():
    p = gov.GovernorPolicy(heavy_cap=1)
    assert gov.decide(state(load1=15.0), p).cap == 1           # soft load: max(1, 1 // 2)
    assert gov.decide(state(load1=30.0), p).cap == 0


def test_try_acquire_unknown_ticket_raises(tmp_path):
    with pytest.raises(gov.GovernorError, match="not queued"):
        make_gov(tmp_path).try_acquire("123-1")


def test_dead_queue_ticket_does_not_block_the_queue(tmp_path):
    dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                          capture_output=True, text=True).stdout.strip()
    g = make_gov(tmp_path, cap=1)
    q = g.dir / "queue"
    q.mkdir(parents=True)
    (q / "00000000000000000001-1.json").write_text(json.dumps({"id": "x", "pid": int(dead), "label": "ghost"}))
    t = g.enqueue("live")
    assert g.try_acquire(t) is not None and any("gone" in r for r in g.reaped)


def test_cli_status_defaults_disk_to_the_event_workdir(gstate, monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(gov, "probe_host", lambda disk: seen.append(Path(disk)) or state())
    assert cli.run(parse("status", "--json")) == 0
    from ctf import paths
    assert seen and seen[0] == paths.workdir()
    assert json.loads(capsys.readouterr().out)["disk_basis"] == "event workdir"


def test_cli_check_strict_turns_an_unread_reading_into_a_governor_fail(gstate, monkeypatch, capsys):
    monkeypatch.setenv("CTF_GOVERNOR_RSS_ALERT_MB", "1000000")
    monkeypatch.setattr(gov, "probe_host",
                        lambda disk: state(thermal=None, unknown=(("thermal", "pmset not found"),)))
    monkeypatch.setattr(gov, "snapshot_processes", lambda: (procs(), 0))
    assert cli.run(parse("check", "--json", "--disk-path", str(gstate.parent))) == 0
    c = {x["name"]: x for x in json.loads(capsys.readouterr().out)["checks"]}
    assert c["host-thermal"]["status"] == "skip" and c["governor"]["status"] == "ok"
    assert cli.run(parse("check", "--strict", "--json", "--disk-path", str(gstate.parent))) == 1
    c = {x["name"]: x for x in json.loads(capsys.readouterr().out)["checks"]}
    assert c["host-thermal"]["status"] == "fail"
    assert c["governor"]["status"] == "warn" and "CTF_GOVERNOR_STRICT" in c["governor"]["detail"]


# -------------------------------------------- verification round 1: readers never reap a half-written file

@pytest.mark.parametrize("sub", ["queue", "leases"])
def test_a_reader_waits_for_the_lock_and_never_reaps_a_half_written_file(tmp_path, sub):
    """A writer holds the lock while its file is still empty (truncated, not yet written). Another
    process's status/on_wait listing must wait for the lock, not reap the file as unreadable."""
    import threading
    writer = make_gov(tmp_path)
    reader = make_gov(tmp_path)
    d = writer.dir / sub
    d.mkdir(parents=True)
    f = d / f"{1:020d}-{os.getpid()}.json"
    got = {}

    def listing():
        got["r"] = reader.queue() if sub == "queue" else reader.leases()
    fh = writer._locked()
    try:
        f.write_text("")                                   # mid-write: truncated, nothing written yet
        t = threading.Thread(target=listing, daemon=True)
        t.start()
        t.join(0.5)
        assert t.is_alive(), "the reader listed the folder without taking the lock"
        assert f.exists() and reader.reaped == []
        f.write_text(json.dumps({"id": f.stem, "pid": os.getpid(), "label": "half"}))
    finally:
        fh.close()
    t.join(5)
    assert not t.is_alive() and reader.reaped == [] and f.exists()
    labels = [r["label"] for r in got["r"]] if sub == "queue" else [l.label for l in got["r"]]
    assert labels == ["half"]


def test_ticket_and_lease_files_are_written_atomically(tmp_path, monkeypatch):
    """At the moment the bytes reach the disk, no reader can list a partial ``*.json``: the data goes to
    a hidden temp file that is renamed into place whole."""
    g = make_gov(tmp_path, cap=1)
    seen = []
    real_fsync = os.fsync

    def fsync(fd):
        real_fsync(fd)
        seen.append(sorted(p.name for d in ("queue", "leases") if (g.dir / d).is_dir()
                           for p in (g.dir / d).glob("*.json")))
    monkeypatch.setattr(gov.os, "fsync", fsync)
    t = g.enqueue("x")
    assert seen == [[]]                                    # the ticket was not visible mid-write
    lease = g.try_acquire(t)
    assert seen[1] == [f"{t}.json"]                        # only the whole ticket, not the lease yet
    assert json.loads(lease.path.read_text())["label"] == "x"
    assert sorted(p.name for p in (g.dir / "leases").iterdir()) == [f"{t}.json"]


def test_a_failed_ticket_write_leaves_no_partial_file(tmp_path, monkeypatch):
    g = make_gov(tmp_path)

    def fsync(fd):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(gov.os, "fsync", fsync)
    with pytest.raises(OSError):
        g.enqueue("x")
    assert list((g.dir / "queue").iterdir()) == []         # neither a truncated ticket nor a temp file


def test_cli_run_says_where_the_disk_floor_is_measured_when_no_event_workdir(gstate, monkeypatch, capsys):
    monkeypatch.setattr(gov, "probe_host", lambda disk: state())

    def no_event():
        raise RuntimeError("no current event")
    monkeypatch.setattr(cli._paths, "workdir", no_event)
    assert cli.run(parse("run", "--timeout", "0", "--", sys.executable, "-c", "pass")) == 0
    err = capsys.readouterr().err
    assert f"disk floor measured at {gstate}" in err and "no event workdir: no current event" in err
    assert cli.run(parse("run", "--timeout", "0", "--disk-path", str(gstate.parent), "--",
                         sys.executable, "-c", "pass")) == 0
    assert "disk floor" not in capsys.readouterr().err
