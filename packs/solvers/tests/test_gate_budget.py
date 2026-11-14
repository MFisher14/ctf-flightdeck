"""B-153: a lane gate fits its budget (300 s by default, never more) or fails loudly (exit 3), costed in
load-independent terms: CPU seconds plus the unstretched waiting part of the wall. Synthetic checkouts only; the
over-budget runs use a test that burns a known amount of CPU and an explicit tiny --budget, so nothing
here depends on how loaded the host is (rule 16: lower bounds on real time, never upper ones)."""
from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET

import pytest

from ctf.cli import gate
from ctf.gate import GateError, budget, config
from ctf.gate.impact import Graph, Selection
from ctf.gate.runner import run_file, run_gate
from gate_repo import make_repo

BURN = ("import time\n"
        "def test_burns():\n"
        "    t = time.process_time()\n"
        "    while time.process_time() - t < 1.0:\n"
        "        pass\n")
FILES = {
    "lib/fast.txt": "1\n",
    "lib/burn.txt": "1\n",
    "tests/test_fast.py": 'F = "lib/fast.txt"\ndef test_fast():\n    pass\n',
    "tests/test_burn.py": 'B = "lib/burn.txt"\n' + BURN,
}
LANES = '\n[lanes]\nfast = ["lib/fast.txt"]\nburn = ["lib/burn.txt"]\n'


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", FILES, extra_config=LANES)


def cli(repo, state, *argv):
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    return gate.run(p.parse_args(["--root", str(repo), "--config", str(repo / "gate.toml"), "--state", str(state),
                                  "--python", sys.executable, *argv]))


# ----------------------------------------------------------------------------------- the arithmetic

def test_file_cost_is_cpu_plus_the_unstretched_wait():
    # r = 56/14 = 4: 10 s of CPU took about 40 s of wall, the other 60 s were waiting -> 10 + 60
    assert budget.file_cost(seconds=100, cpu=10, load=56, cpus=14) == 70.0
    assert budget.file_cost(seconds=100, cpu=40, load=56, cpus=14) == 40.0        # all stretch: CPU is the floor
    assert budget.file_cost(seconds=120, cpu=10, load=168, cpus=14) == 10.0       # CPU-bound at r = 12
    assert budget.file_cost(seconds=30, cpu=0, load=7, cpus=14) == 30.0           # an idle host: ratio 1
    assert budget.file_cost(seconds=30, cpu=0, load=0, cpus=14) == 30.0           # unknown load: ratio 1
    assert budget.file_cost(seconds=30, cpu=2, load=0, cpus=14) == 30.0           # ratio 1: the whole wall
    # a lightly loaded host (load below the core count): the ratio floors at 1, never below, so a file
    # never costs more than its own wall time (an unfloored r = 0.5 would give 100 - 10 * -0.5 = 105)
    assert budget.file_cost(seconds=100, cpu=10, load=7, cpus=14) == 100.0


def test_a_file_that_mostly_waits_is_not_made_cheap_by_load():
    """At load 168 on 14 cores a file that sleeps or waits on a socket for 100 s still costs about 100 s
    on an idle host: waiting does not stretch with load, so its wait is never divided by the load ratio
    (the old wall / r gave 8.3 s and let a 100 s file through a lane budget)."""
    cost = budget.file_cost(seconds=100, cpu=1, load=168, cpus=14)
    assert cost == 89.0                                          # 1 s CPU + (100 - 1 * 12) s of waiting
    est = budget.estimate("x", ["tests/a.py", "tests/b.py", "tests/c.py", "tests/d.py"],
                          {f"tests/{n}.py": {"seconds": 100, "cpu": 1, "load": 168, "cpus": 14} for n in "abcd"},
                          budget=150, jobs=2)
    assert est.over and est.cost == 178.0


def test_makespan_packs_longest_first_onto_the_least_loaded_worker():
    assert budget.makespan([], 2) == 0.0
    assert budget.makespan([5, 4, 3, 3, 3], 1) == 18
    assert budget.makespan([5, 4, 3, 3, 3], 2) == 10           # LPT: 5|4 -> 5|7 -> 8|7 -> 8|10
    assert budget.makespan([6, 5, 4, 3], 2) == 9               # 6|5 -> 6|9 -> 9|9
    assert budget.makespan([10, 1, 1, 1], 4) == 10             # one big file bounds it
    assert budget.makespan([3, 3, 3, 3], 2) == 6


def test_jobs_to_fit():
    assert budget.jobs_to_fit([100, 100, 100], 300) == 1
    assert budget.jobs_to_fit([100, 100, 100], 150) == 3
    assert budget.jobs_to_fit([100, 100, 100], 200) == 2
    assert budget.jobs_to_fit([400, 1], 300) is None           # one file alone is over: no job count helps
    assert budget.jobs_to_fit([], 300) == 1


# ------------------------------------------------------------------------------------ the config

def _cfg(tmp_path, extra):
    root = make_repo(tmp_path / "c", {}, extra_config=extra, commit=False)
    return config.load(root, root / "gate.toml")


def test_budget_defaults_to_300_seconds(tmp_path):
    cfg = _cfg(tmp_path, LANES)
    assert cfg.lane_budget == 300.0 and cfg.lane_budgets == {}
    assert budget.lane_budget(cfg, "fast") == 300.0


def test_budget_per_lane_and_override(tmp_path):
    cfg = _cfg(tmp_path, LANES + "\n[budget]\nlane_seconds = 200\n[budget.lanes]\nburn = 60\n")
    assert budget.lane_budget(cfg, "fast") == 200.0 and budget.lane_budget(cfg, "burn") == 60.0
    assert budget.lane_budget(cfg, "burn", override=900) == 900.0                # explicit, printed by the CLI
    with pytest.raises(GateError, match="positive"):
        budget.lane_budget(cfg, "burn", override=0)


@pytest.mark.parametrize("extra,msg", [
    ("\n[budget]\nlane_seconds = 301\n", "over 300s: a lane gate must fit in five minutes"),
    ("\n[budget]\nlane_seconds = 0\n", "positive number"),
    ("\n[budget]\nlane_seconds = true\n", "positive number"),
    ("\n[budget]\n", "needs lane_seconds"),
    ("\n[budget]\nlane_seconds = 100\nwall = 3\n", "unknown key"),
    ("\n[budget]\nlane_seconds = 100\n[budget.lanes]\nnope = 10\n", "not a lane"),
    ("\n[budget]\nlane_seconds = 100\n[budget.lanes]\nfast = 400\n", "over 300s"),
    ("\n[budget]\nlane_seconds = 100\nfull_only = \"tests/test_burn.py\"\n", "must be a list of strings"),
    ("\n[budget]\nlane_seconds = 100\nfull_only = [\"\"]\n", "full_only has an empty glob"),
])
def test_a_bad_budget_fails_loudly(tmp_path, extra, msg):
    with pytest.raises(GateError, match=msg):
        _cfg(tmp_path, LANES + extra)


def test_the_repo_config_keeps_every_lane_within_five_minutes():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    cfg = config.load(root)
    assert cfg.lane_budget <= 300 and all(v <= 300 for v in cfg.lane_budgets.values())
    # every full-only file is a real test file (a stale entry would silently stop meaning anything)
    assert cfg.full_only and all((root / f).is_file() and cfg.is_test(f) for f in cfg.full_only)


def test_the_repo_lanes_keep_the_hubs_out_and_still_cover_each_area():
    """The hubs nearly every test imports put no test in a lane (that made `core` most of the suite);
    a module next to them still does."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    cfg = config.load(root)
    for hub in ("ctf/__init__.py", "ctf/paths.py", "ctf/env.py", "ctf/event.py", "ctf/flagfmt.py",
                "ctf/cli/__init__.py"):
        assert not [lane for lane, globs in cfg.lanes.items() if config.lane_matches(hub, globs)], hub
    for f, lane in (("ctf/scope.py", "core-s-z"), ("ctf/budget.py", "core-a-e"), ("ctf/ledger.py", "ledger"),
                    ("ctf/cli/gate.py", "cli"), ("ctf/gate/budget.py", "gate"), ("ctf/pyinterp.py", "core-m-r"),
                    ("solvers/toolkits/mmm_probe.py", "toolkits"), ("solvers/toolkits/www_probe.py", "toolkits-p-z"),
                    ("solvers/toolkits/data/x.json", "toolkits-p-z")):
        assert config.lane_matches(f, cfg.lanes[lane]), (f, lane)
    # the two toolkits lanes split the folder: a top-level toolkit is in exactly one of them
    # (made-up names: the coverage matrix counts a test that names a real engine file as covering it)
    for f in ("solvers/toolkits/aaa_probe.py", "solvers/toolkits/ooo_probe.py", "solvers/toolkits/ppp_probe.py",
              "solvers/toolkits/zzz_probe.py"):
        assert [config.lane_matches(f, cfg.lanes[x]) for x in ("toolkits", "toolkits-p-z")].count(True) == 1, f


# ------------------------------------------------------------------- lane exclusions and full-only

HUB_FILES = {
    "lib/hub.py": "X = 1\n",
    "lib/area.py": "Y = 2\n",
    "tests/test_hub_only.py": "import hub\ndef test_h():\n    assert hub.X == 1\n",
    "tests/test_area.py": "import area, hub\ndef test_a():\n    assert area.Y == 2\n",
}


def test_a_lane_exclusion_drops_a_hub_but_not_what_imports_the_area(tmp_path):
    with_hub = make_repo(tmp_path / "a", HUB_FILES, extra_config='\n[lanes]\narea = ["lib/**"]\n')
    g = Graph(with_hub, config.load(with_hub, with_hub / "gate.toml"), tmp_path / "sa")
    assert g.lane_tests("area") == ["tests/test_area.py", "tests/test_hub_only.py"]
    no_hub = make_repo(tmp_path / "b", HUB_FILES, extra_config='\n[lanes]\narea = ["lib/**", "!lib/hub.py"]\n')
    g = Graph(no_hub, config.load(no_hub, no_hub / "gate.toml"), tmp_path / "sb")
    assert g.lane_tests("area") == ["tests/test_area.py"]          # still in: it imports lib/area.py
    assert config.lane_matches("lib/area.py", ["lib/**", "!lib/hub.py"])
    assert not config.lane_matches("lib/hub.py", ["lib/**", "!lib/hub.py"])
    assert not config.lane_matches("other/x.py", ["lib/**", "!other/x.py"])   # an exclusion never adds


@pytest.mark.parametrize("lanes,msg", [
    ('area = ["!lib/hub.py"]', "only \"!\" exclusions"),
    ('area = ["lib/**", "!"]', "empty or doubled exclusion"),
    ('area = ["lib/**", "!!lib/hub.py"]', "empty or doubled exclusion"),
])
def test_a_lane_made_only_of_exclusions_fails_loudly(tmp_path, lanes, msg):
    with pytest.raises(GateError, match=msg):
        _cfg(tmp_path, f"\n[lanes]\n{lanes}\n")


FULL_ONLY = LANES + '\n[budget]\nlane_seconds = 300\nfull_only = ["tests/test_burn.py"]\n'
BOTH = {**FILES, "tests/test_both.py": 'F = "lib/fast.txt"\nB = "lib/burn.txt"\ndef test_both():\n    pass\n'}


@pytest.fixture
def fo_repo(tmp_path):
    return make_repo(tmp_path / "fo", BOTH, extra_config=FULL_ONLY)


def test_a_lane_run_leaves_a_full_only_file_and_says_so(fo_repo, tmp_path, capsys):
    st = tmp_path / "st"
    # recorded over budget: were it in the lane run, the run would be refused (exit 3)
    budget.Timings(st).update({"tests/test_burn.py": {"seconds": 900.0, "cpu": 900.0, "load": 0, "cpus": 14}})
    assert cli(fo_repo, st, "run", "--lane", "burn") == 0
    out = capsys.readouterr().out
    assert "full-only file(s) NOT run here" in out and "tests/test_burn.py" in out
    assert "tests/test_both.py" in out and "PASS" in out
    rows = [ln for ln in out.splitlines() if "tests/test_burn.py" in ln and "NOT run" not in ln]
    assert rows == [], rows                                       # no row: it did not run
    last = out.splitlines()[-1]
    assert last.startswith("GATE result=pass mode=lane files=1 ") and " budget=ok:" in last
    # the plan says the same, and so does an impact run filtered by the lane
    assert cli(fo_repo, st, "plan", "--lane", "burn") == 0
    plan = capsys.readouterr().out
    assert "NOT run here" in plan and "RUN   tests/test_burn.py" not in plan
    assert cli(fo_repo, st, "plan", "--changed", "lib/burn.txt", "--lane", "burn") == 0
    plan = capsys.readouterr().out
    assert "NOT run here" in plan and "RUN   tests/test_burn.py" not in plan and "PLAN mode=impact files=1" in plan
    # a plain impact run (no lane) and a full run still run it
    assert cli(fo_repo, st, "plan", "--changed", "lib/burn.txt") == 0
    assert "RUN   tests/test_burn.py" in capsys.readouterr().out
    assert cli(fo_repo, st, "run", "--full", "--lane", "burn") == 0
    full = capsys.readouterr().out
    assert "NOT run here" not in full and any(ln.startswith("PASS") and "tests/test_burn.py" in ln
                                              for ln in full.splitlines())


def test_a_lane_of_only_full_only_files_fails_loudly(tmp_path, capsys):
    repo = make_repo(tmp_path / "r", FILES, extra_config=FULL_ONLY)
    assert cli(repo, tmp_path / "st", "run", "--lane", "burn") == 2
    out, err = capsys.readouterr()
    assert "every file it selects is full-only (tests/test_burn.py)" in err and "GATE" not in out


def test_an_impact_run_filtered_to_a_lane_with_only_full_only_files_is_empty_not_an_error(tmp_path, capsys):
    """--changed/--base with --lane: when every impacted lane file is full-only the change has nothing a
    lane gate may run. That is an empty run with the NOT-run reason line (exit 0), unlike a plain --lane
    run of such a lane, which fails loudly: the change itself chose nothing runnable here."""
    repo = make_repo(tmp_path / "r", FILES, extra_config=FULL_ONLY)
    st = tmp_path / "st"
    assert cli(repo, st, "plan", "--changed", "lib/burn.txt", "--lane", "burn") == 0
    out, err = capsys.readouterr()
    assert "lane burn: 1 full-only file(s) NOT run here" in out and "tests/test_burn.py" in out
    assert "PLAN mode=impact files=0 " in out and "RUN   tests/test_burn.py" not in out and err == ""
    assert cli(repo, st, "run", "--changed", "lib/burn.txt", "--lane", "burn") == 0
    out, err = capsys.readouterr()
    assert "lane burn: 1 full-only file(s) NOT run here" in out
    assert out.splitlines()[-1].startswith("GATE result=pass mode=impact files=0 ")
    assert not any(ln.startswith("PASS") for ln in out.splitlines())


def test_budget_and_plan_name_the_test_files_in_no_lane(tmp_path, capsys):
    """A test that only imports an excluded hub sits in no lane: a lane gate never runs it, and the tools
    say so by name instead of leaving the gap silent."""
    repo = make_repo(tmp_path / "h", HUB_FILES, extra_config='\n[lanes]\narea = ["lib/**", "!lib/hub.py"]\n')
    st = tmp_path / "st"
    assert cli(repo, st, "budget") == 0
    out = capsys.readouterr().out
    assert ("gate: 1 test file(s) are in no lane: a lane gate never runs them, only an impact run "
            "(--base/--changed) and the full gate do: tests/test_hub_only.py") in out
    assert cli(repo, st, "plan", "--lane", "area") == 0
    out = capsys.readouterr().out
    assert "gate: 1 test file(s) are in no lane and never run by a lane gate" in out
    assert cli(repo, st, "plan", "--lane", "area", "--json") == 0
    assert json.loads(capsys.readouterr().out)["no_lane"] == ["tests/test_hub_only.py"]
    # with the hub in the lane, nothing is left out
    covered = make_repo(tmp_path / "c", HUB_FILES, extra_config='\n[lanes]\narea = ["lib/**"]\n')
    assert cli(covered, tmp_path / "st2", "budget") == 0
    assert "gate: 0 test file(s) are in no lane" in capsys.readouterr().out


def test_budget_command_leaves_full_only_files_out_of_the_estimate(fo_repo, tmp_path, capsys):
    st = tmp_path / "st"
    budget.Timings(st).update({"tests/test_burn.py": {"seconds": 900.0, "cpu": 900.0, "load": 0, "cpus": 14},
                               "tests/test_both.py": {"seconds": 2.0, "cpu": 2.0, "load": 0, "cpus": 14}})
    assert cli(fo_repo, st, "budget", "--lane", "burn") == 0
    out = capsys.readouterr().out
    assert "BUDGET lane=burn limit=300s estimate=2s jobs=2 known=1 unknown=0 verdict=ok" in out
    assert "lane burn leaves 1 full-only file(s) to the full gate: tests/test_burn.py" in out
    assert cli(fo_repo, st, "budget", "--lane", "burn", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d[0]["full_only"] == ["tests/test_burn.py"] and d[0]["estimate"] == 2.0


# ------------------------------------------------------------------------------- timings store

def test_timings_record_merge_and_reject_a_foreign_file(tmp_path):
    t = budget.Timings(tmp_path)
    assert t.load() == {}
    t.update({"tests/a.py": {"seconds": 4.0, "cpu": 1.0, "load": 28.0, "cpus": 14}})
    t.update({"tests/b.py": {"seconds": 2.0, "cpu": 2.0, "load": 0.0, "cpus": 14}})
    files = t.load()
    assert set(files) == {"tests/a.py", "tests/b.py"}
    # a: r = 2, so its 1 s of CPU took 2 s of the 4 s wall and the other 2 s were waiting: 1 + 2
    assert t.cost("tests/a.py") == 3.0 and t.cost("tests/b.py") == 2.0 and t.cost("tests/c.py") is None
    (tmp_path / budget.TIMINGS).write_text(json.dumps({"version": 99, "files": {}}))
    with pytest.raises(GateError, match="not version"):
        t.load()
    (tmp_path / budget.TIMINGS).write_text("{nope")
    with pytest.raises(GateError, match="unreadable"):
        t.load()


def _junit(path, cases):
    suite = ET.Element("testsuite")
    for cls, name, secs in cases:
        ET.SubElement(suite, "testcase", classname=cls, name=name, time=str(secs))
    root = ET.Element("testsuites")
    root.append(suite)
    ET.ElementTree(root).write(path)


def test_junit_seconds_are_summed_per_file_and_classes_map_to_their_file(tmp_path):
    j = tmp_path / "s.xml"
    _junit(j, [("tests.test_a", "t1", 1.5), ("tests.test_a.TestK", "t2", 2.0), ("tests.sub.test_b", "t", 4)])
    assert budget.junit_file_seconds(j) == {"tests/test_a.py": 3.5, "tests/sub/test_b.py": 4.0}


def test_import_junit_seeds_only_known_files_and_never_overwrites_a_gate_record(tmp_path):
    j = tmp_path / "s.xml"
    _junit(j, [("tests.test_a", "t", 9), ("tests.test_b", "t", 7), ("tests.test_gone", "t", 1)])
    t = budget.Timings(tmp_path / "st")
    t.update({"tests/test_a.py": {"seconds": 1.0, "cpu": 1.0, "load": 0, "cpus": 1, "source": "gate"}})
    n, unknown = budget.import_junit(tmp_path / "st", j, ["tests/test_a.py", "tests/test_b.py"])
    files = t.load()
    assert n == 1 and unknown == ["tests/test_gone.py"]
    assert files["tests/test_a.py"]["seconds"] == 1.0 and files["tests/test_a.py"]["source"] == "gate"
    assert files["tests/test_b.py"]["seconds"] == 7.0 and files["tests/test_b.py"]["source"] == "junit"


# ---------------------------------------------------------------------- measurement in the runner

def test_run_file_measures_the_childs_cpu_time(repo, tmp_path):
    row = run_file(repo, "tests/test_burn.py", out_dir=tmp_path / "o", wall=600)
    assert row.status == "PASS"
    assert row.cpu >= 1.0                       # the test burned >= 1 s of its own CPU (a lower bound)
    fast = run_file(repo, "tests/test_fast.py", out_dir=tmp_path / "o", wall=600)
    assert fast.status == "PASS" and 0 < fast.cpu < row.cpu


def test_run_gate_records_timings_for_files_that_ran_not_warm_ones(repo, tmp_path):
    state = tmp_path / "st"
    g = Graph(repo, config.load(repo, repo / "gate.toml"), state / "co")
    sel = Selection("impact", ["tests/test_burn.py", "tests/test_fast.py"], [], {})
    run_gate(g, sel, state=state, out_dir=state / "o", emit=lambda s: None, load_fn=lambda: 28.0, cpus=14)
    files = budget.Timings(state).load()
    assert files["tests/test_burn.py"]["cpu"] >= 1.0 and files["tests/test_burn.py"]["load"] == 28.0
    assert files["tests/test_burn.py"]["cpus"] == 14 and files["tests/test_burn.py"]["source"] == "gate"
    before = files["tests/test_fast.py"]["ts"]
    rep = run_gate(g, sel, state=state, out_dir=state / "o2", emit=lambda s: None, load_fn=lambda: 0.0, cpus=4)
    assert all(r.warm for r in rep.rows)                         # both reused warm ...
    assert budget.Timings(state).load()["tests/test_fast.py"]["ts"] == before   # ... so nothing re-recorded


# --------------------------------------------------------------------------------- the CLI

def test_a_lane_run_over_its_measured_budget_exits_3_and_says_so(repo, tmp_path, capsys):
    rc = cli(repo, tmp_path / "st", "run", "--lane", "burn", "--budget", "0.5")
    out, err = capsys.readouterr()
    assert rc == budget.EXIT_OVER_BUDGET
    assert "PASS" in out and "GATE result=pass" in out          # the tests passed ...
    assert " budget=over:" in out.splitlines()[-1]              # ... but the lane blew its budget
    assert "OVER BUDGET" in err and "tests/test_burn.py" in err


def test_a_lane_run_within_budget_passes_and_reports_it(repo, tmp_path, capsys):
    assert cli(repo, tmp_path / "st", "run", "--lane", "fast") == 0
    last = capsys.readouterr().out.splitlines()[-1]
    assert last.startswith("GATE result=pass") and " budget=ok:" in last and "/300s" in last


def test_a_lane_whose_recorded_cost_is_over_is_refused_before_it_runs(repo, tmp_path, capsys):
    st = tmp_path / "st"
    budget.Timings(st).update({"tests/test_burn.py": {"seconds": 400.0, "cpu": 390.0, "load": 0, "cpus": 14}})
    rc = cli(repo, st, "run", "--lane", "burn")
    out, err = capsys.readouterr()
    assert rc == budget.EXIT_OVER_BUDGET
    assert "refused before running" in err and "tests/test_burn.py 400s" in err
    assert "GATE" not in out and "PASS" not in out              # nothing ran
    assert not (st / "runs").exists()
    # the plan says the same, with the verdict on its BUDGET line
    assert cli(repo, st, "plan", "--lane", "burn") == budget.EXIT_OVER_BUDGET
    assert "verdict=over" in capsys.readouterr().out
    # an explicit --budget is the one override
    assert cli(repo, st, "run", "--lane", "burn", "--budget", "900") == 0


def test_a_warm_file_does_not_count_against_the_budget(repo, tmp_path, capsys):
    st = tmp_path / "st"
    assert cli(repo, st, "run", "--lane", "fast") == 0           # stores the green result warm
    budget.Timings(st).update({"tests/test_fast.py": {"seconds": 900.0, "cpu": 900.0, "load": 0, "cpus": 14}})
    capsys.readouterr()
    assert cli(repo, st, "run", "--lane", "fast") == 0           # reused warm: nothing to run, nothing to cost
    assert "budget=ok:0/300s" in capsys.readouterr().out


def test_a_full_run_has_no_lane_budget(repo, tmp_path, capsys):
    st = tmp_path / "st"
    budget.Timings(st).update({"tests/test_burn.py": {"seconds": 900.0, "cpu": 900.0, "load": 0, "cpus": 14}})
    assert cli(repo, st, "run", "--full", "--lane", "burn") == 0
    assert "budget=" not in capsys.readouterr().out.splitlines()[-1]
    # a batch's first run is a full selection too, whatever --lane says: no lane budget, no refusal
    st2 = tmp_path / "st2"                                       # fresh: nothing warm
    budget.Timings(st2).update({"tests/test_burn.py": {"seconds": 900.0, "cpu": 900.0, "load": 0, "cpus": 14}})
    assert cli(repo, st2, "plan", "--lane", "burn") == budget.EXIT_OVER_BUDGET    # (a lane run would refuse)
    capsys.readouterr()
    assert cli(repo, st2, "run", "--batch", "b1", "--lane", "burn") == 0
    assert "budget=" not in capsys.readouterr().out.splitlines()[-1]


def test_budget_command_lists_lanes_and_exits_3_when_one_is_over(repo, tmp_path, capsys):
    st = tmp_path / "st"
    budget.Timings(st).update({"tests/test_burn.py": {"seconds": 500.0, "cpu": 10, "load": 0, "cpus": 14},
                               "tests/test_fast.py": {"seconds": 1.0, "cpu": 0.5, "load": 0, "cpus": 14}})
    assert cli(repo, st, "budget") == budget.EXIT_OVER_BUDGET
    out = capsys.readouterr().out
    assert "BUDGET lane=burn limit=300s estimate=500s" in out and "verdict=over" in out
    assert "fits_at_jobs=none" in out
    assert "BUDGET lane=fast limit=300s estimate=1s jobs=2 known=1 unknown=0 verdict=ok" in out
    assert "BUDGETS lanes=2 over=1 (burn)" in out
    assert cli(repo, st, "budget", "--lane", "fast", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d[0]["lane"] == "fast" and d[0]["over"] is False and d[0]["known"] == 1


def test_budget_command_imports_a_junit(repo, tmp_path, capsys):
    j = tmp_path / "s.xml"
    _junit(j, [("tests.test_burn", "test_burns", 350.0), ("tests.test_fast", "test_fast", 0.2)])
    assert cli(repo, tmp_path / "st", "budget", "--import-junit", str(j)) == budget.EXIT_OVER_BUDGET
    out = capsys.readouterr().out
    assert "imported 2 file timing(s)" in out and "BUDGET lane=burn limit=300s estimate=350s" in out


def test_estimate_counts_unknown_files_as_a_floor():
    est = budget.estimate("x", ["a", "b"], {"a": {"seconds": 10, "cpu": 0, "load": 0, "cpus": 1}},
                          budget=300, jobs=2)
    assert est.known == 1 and est.unknown == ["b"] and est.cost == 10 and not est.over
    assert "unknown=1" in est.line()
    over = budget.estimate("x", ["a"], {"a": {"seconds": 400, "cpu": 0, "load": 0, "cpus": 1}}, budget=300, jobs=2)
    assert over.over and "split the costliest file" in over.explain()
