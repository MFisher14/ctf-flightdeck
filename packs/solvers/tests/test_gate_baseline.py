"""B-153: the tracked baseline ledger (tests/gate_baseline.toml, ctf/gate/baseline.py). It validates
strictly, names every red as new or baseline with the ledger's reason and date, never turns a red green,
and junit_diff lists ledger hits apart. Synthetic repos and junit files only."""
from __future__ import annotations

import argparse
import ast
import datetime as dt
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

import junit_diff
from ctf.cli import gate
from ctf.gate import GateError, baseline, config
from ctf.gate.impact import Graph, Selection
from ctf.gate.runner import run_gate
from gate_repo import make_repo

REPO = Path(__file__).resolve().parent.parent
TODAY = dt.date(2026, 11, 12)

GOOD = """\
version = 1

[[red]]
id = "tests/test_a.py::test_flaky"
kind = "flaky"
reason = "fails under load, passes alone"
since = 2026-11-01

[[red]]
id = "tests/test_a.py::TestK::test_p[x-1]"
kind = "stale"
reason = "expects the old output format"
since = 2026-10-30
owner = "B-999"
"""


def test_a_good_ledger_loads_with_reason_and_date(tmp_path):
    led = baseline.parse(GOOD, tmp_path / "l.toml", today=TODAY)
    e = led.get("tests/test_a.py::test_flaky")
    assert (e.kind, e.reason, e.since, e.owner) == ("flaky", "fails under load, passes alone", dt.date(2026, 11, 1), "")
    assert led.get("tests/test_a.py::TestK::test_p[x-1]").owner == "B-999"
    assert led.keys() == ["tests.test_a.TestK::test_p[x-1]", "tests.test_a::test_flaky"]
    assert "flaky since 2026-11-01: fails under load" in e.describe()


@pytest.mark.parametrize("nodeid,key", [
    ("tests/test_x.py::test_y", "tests.test_x::test_y"),
    ("tests/sub/test_x.py::TestC::test_y[a-b]", "tests.sub.test_x.TestC::test_y[a-b]"),
])
def test_junit_key_matches_what_pytest_writes(nodeid, key):
    assert baseline.junit_key(nodeid) == key


@pytest.mark.parametrize("bad", ["tests/test_x.py", "test_y", "tests/test_x.txt::t", "tests/test_x.py::"])
def test_junit_key_refuses_what_is_not_a_node_id(bad):
    with pytest.raises(GateError, match="not a pytest node id"):
        baseline.junit_key(bad)


def _entry(**over):
    d = {"id": '"tests/test_a.py::t"', "kind": '"flaky"', "reason": '"a reason long enough"', "since": "2026-11-01"}
    d.update(over)
    return "version = 1\n[[red]]\n" + "".join(f"{k} = {v}\n" for k, v in d.items() if v is not None)


@pytest.mark.parametrize("text,msg", [
    ("version = 2\n", "version must be 1"),
    ("version = 1\nextra = 1\n", "unknown key"),
    ("version = 1\nred = 3\n", "array of tables"),
    (_entry(kind='"sometimes"'), "kind 'sometimes' is not one of"),
    (_entry(reason='"short"'), "at least 10 characters"),
    (_entry(since='"yesterday"'), "TOML date"),
    (_entry(since="2026-12-25"), "in the future"),
    (_entry(since=None), "missing \\['since'\\]"),
    (_entry(color='"red"'), "unknown \\['color'\\]"),
    (_entry(id='"test_a::t"'), "not a pytest node id"),
    (_entry(owner="3"), "'owner' must be a string"),
    (_entry() + '[[red]]\nid = "tests/test_a.py::t"\nkind = "env"\nreason = "a reason long enough"\n'
                'since = 2026-11-01\n', "duplicate id"),
    ("version = 1\n[[red\n", "not valid TOML"),
])
def test_a_malformed_ledger_fails_loudly(tmp_path, text, msg):
    with pytest.raises(GateError, match=msg):
        baseline.parse(text, tmp_path / "l.toml", today=TODAY)


@pytest.mark.parametrize("value", ['"/abs/ledger.toml"', '"../out.toml"', "3"])
def test_the_config_refuses_a_ledger_path_outside_the_checkout(tmp_path, value):
    root = make_repo(tmp_path / "c", {}, commit=False)
    toml = (root / "gate.toml").read_text().replace("no_warm =", f"baseline = {value}\nno_warm =")
    (root / "gate.toml").write_text(toml)
    with pytest.raises(GateError, match="repo-relative path to the baseline ledger"):
        config.load(root, root / "gate.toml")


def test_a_missing_ledger_is_named(tmp_path):
    with pytest.raises(GateError, match="baseline ledger not found"):
        baseline.load(tmp_path / "nope.toml")


def test_attribute_splits_new_and_baseline():
    led = baseline.parse(GOOD, Path("l.toml"), today=TODAY)
    att = baseline.attribute(["tests.test_a::test_flaky", "tests.test_a::test_new"], led)
    assert att.new == ["tests.test_a::test_new"] and [k for k, _ in att.baseline] == ["tests.test_a::test_flaky"]
    assert not att.all_baseline
    assert "baseline red: tests.test_a::test_flaky (flaky since 2026-11-01" in att.detail()
    assert "NEW red: tests.test_a::test_new" in att.detail()
    assert baseline.attribute(["tests.test_a::test_flaky"], led).all_baseline
    assert baseline.attribute(["x::y"], None).new == ["x::y"]


def test_append_entry_dates_it_and_refuses_a_duplicate(tmp_path):
    p = tmp_path / "l.toml"
    p.write_text("version = 1\n", encoding="utf-8")
    e = baseline.append_entry(p, "tests/test_a.py::t", "env", 'needs "ghidra" headless', today=TODAY)
    assert e.since == TODAY and baseline.load(p, today=TODAY).get("tests/test_a.py::t").reason == 'needs "ghidra" headless'
    with pytest.raises(GateError, match="already in the ledger"):
        baseline.append_entry(p, "tests/test_a.py::t", "env", "a second reason here", today=TODAY)
    with pytest.raises(GateError, match="is not one of"):
        baseline.append_entry(p, "tests/test_a.py::u", "nope", "a reason long enough", today=TODAY)
    assert "tests/test_a.py::u" not in p.read_text()          # a refused entry never reaches the file


# ------------------------------------------------------------------------- the shipped ledger

def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_the_shipped_ledger_is_valid_and_every_entry_names_a_real_test():
    cfg = config.load(REPO)
    assert cfg.baseline == "tests/gate_baseline.toml"
    led = baseline.load(REPO / cfg.baseline)
    assert len(led) > 0
    assert led.stale(REPO) == []
    for e in led.entries.values():
        name = e.id.split("::")[-1].split("[", 1)[0]
        assert name in _test_names(REPO / e.file), f"{e.id}: no test function {name} in {e.file}"


# ------------------------------------------------------------------------------ through the gate

FILES = {
    "tests/test_a.py": ("def test_flaky():\n    assert 0, 'load'\n\n"
                        "def test_new():\n    assert 0, 'a real break'\n\n"
                        "def test_ok():\n    pass\n"),
    "tests/test_b.py": "def test_flaky():\n    assert 0, 'load'\n",
    "tests/test_c.py": "def test_ok():\n    pass\n",
    "base.toml": ('version = 1\n[[red]]\nid = "tests/test_a.py::test_flaky"\nkind = "flaky"\n'
                  'reason = "fails under load, passes alone"\nsince = 2026-11-01\n'
                  '[[red]]\nid = "tests/test_b.py::test_flaky"\nkind = "flaky"\n'
                  'reason = "fails under load, passes alone"\nsince = 2026-11-01\n'),
}


def _with_baseline(tmp_path):
    root = make_repo(tmp_path / "repo", FILES)
    toml = (root / "gate.toml").read_text().replace("no_warm =", 'baseline = "base.toml"\nno_warm =')
    (root / "gate.toml").write_text(toml)
    return root


def test_run_gate_attributes_each_red_and_keeps_it_red(tmp_path):
    root = _with_baseline(tmp_path)
    cfg = config.load(root, root / "gate.toml")
    led = baseline.for_config(root, cfg)
    g = Graph(root, cfg, tmp_path / "st" / "co")
    tests = ["tests/test_a.py", "tests/test_b.py", "tests/test_c.py"]
    rep = run_gate(g, Selection("full", tests, [], {}), state=tmp_path / "st", out_dir=tmp_path / "o",
                   warm=False, emit=lambda s: None, load_fn=lambda: 0.0, cpus=4, baseline=led)
    rows = {r.test: r for r in rep.rows}
    a, b = rows["tests/test_a.py"], rows["tests/test_b.py"]
    assert (a.status, a.red_new, a.red_baseline) == ("FAIL", 1, 1)
    assert "NEW red: tests.test_a::test_new" in a.detail and "baseline red: tests.test_a::test_flaky" in a.detail
    assert (b.status, b.red_new, b.red_baseline) == ("FAIL", 0, 1)      # all baseline: still red
    assert not rep.ok
    from ctf.gate.runner import format_summary
    assert format_summary(rep).endswith("red_new=1 red_baseline=2")


def test_a_red_with_no_failing_case_to_name_counts_as_new(tmp_path):
    """A child that dies without a junit (a crash, a timeout) is red with nothing the ledger could list:
    it must count as a new red, never vanish from the attribution."""
    root = _with_baseline(tmp_path)
    cfg = config.load(root, root / "gate.toml")
    crash = tmp_path / "crash-py"
    crash.write_text("#!/bin/sh\necho 'Segmentation fault'\nexit 1\n")
    crash.chmod(0o755)
    g = Graph(root, cfg, tmp_path / "st" / "co")
    rep = run_gate(g, Selection("full", ["tests/test_b.py"], [], {}), state=tmp_path / "st",
                   out_dir=tmp_path / "o", warm=False, emit=lambda s: None, load_fn=lambda: 0.0, cpus=4,
                   python=str(crash), baseline=baseline.for_config(root, cfg))
    row = rep.rows[0]
    assert row.status == "FAIL" and (row.red_new, row.red_baseline) == (1, 0)


def test_without_a_ledger_the_summary_has_no_attribution(tmp_path):
    root = make_repo(tmp_path / "repo", FILES)
    cfg = config.load(root, root / "gate.toml")
    g = Graph(root, cfg, tmp_path / "st" / "co")
    rep = run_gate(g, Selection("full", ["tests/test_b.py"], [], {}), state=tmp_path / "st",
                   out_dir=tmp_path / "o", warm=False, emit=lambda s: None, load_fn=lambda: 0.0, cpus=4)
    from ctf.gate.runner import format_summary
    assert "red_new" not in format_summary(rep) and rep.rows[0].red_new == 0


def _cli(root, state, *argv):
    p = argparse.ArgumentParser()
    gate.add_arguments(p)
    return gate.run(p.parse_args(["--root", str(root), "--config", str(root / "gate.toml"), "--state", str(state),
                                  "--python", sys.executable, *argv]))


def test_the_cli_run_prints_attribution_and_exits_red(tmp_path, capsys):
    root = _with_baseline(tmp_path)
    assert _cli(root, tmp_path / "st", "run", "--full") == 1
    out = capsys.readouterr().out
    assert "baseline ledger" in out and out.splitlines()[-1].endswith("red_new=1 red_baseline=2")
    import json
    doc = json.loads((tmp_path / "st" / "last-run.json").read_text())
    items = {i["test"]: i for i in doc["items"]}
    assert items["tests/test_b.py"]["red_baseline"] == 1 and items["tests/test_b.py"]["red_new"] == 0
    assert "baseline red" in (tmp_path / "st" / "last-fail.log").read_text()


def test_the_cli_baseline_commands(tmp_path, capsys):
    root = _with_baseline(tmp_path)
    st = tmp_path / "st"
    assert _cli(root, st, "baseline", "check") == 0
    assert "BASELINE entries=2 stale=0 result=ok" in capsys.readouterr().out
    assert _cli(root, st, "baseline", "keys") == 0
    assert capsys.readouterr().out.split() == ["tests.test_a::test_flaky", "tests.test_b::test_flaky"]
    assert _cli(root, st, "baseline", "add", "tests/test_c.py::test_ok", "--kind", "env",
                "--reason", "needs a tool this host lacks") == 0
    capsys.readouterr()
    assert _cli(root, st, "baseline", "list") == 0
    assert "tests/test_c.py::test_ok  needs a tool this host lacks" in capsys.readouterr().out
    assert _cli(root, st, "baseline", "add", "tests/test_zz.py::t", "--kind", "env", "--reason", "x" * 12) == 2
    assert "no such test file" in capsys.readouterr().err
    assert _cli(root, st, "baseline", "add", "tests/test_c.py::t2") == 2
    (root / "tests" / "test_b.py").unlink()
    assert _cli(root, st, "baseline", "check") == 1
    assert "stale baseline entry (its test file is gone): tests/test_b.py::test_flaky" in capsys.readouterr().err


def test_baseline_commands_need_a_configured_ledger(tmp_path, capsys):
    root = make_repo(tmp_path / "repo", FILES)
    assert _cli(root, tmp_path / "st", "baseline", "check") == 2
    assert "names no baseline ledger" in capsys.readouterr().err


# ---------------------------------------------------------------------------------- junit_diff

def _junit(path: Path, cases: dict) -> Path:
    root = ET.Element("testsuites")
    s = ET.SubElement(root, "testsuite")
    for key, st in cases.items():
        cls, name = key.split("::")
        tc = ET.SubElement(s, "testcase", classname=cls, name=name)
        if st == "failed":
            ET.SubElement(tc, "failure", message="x")
    ET.ElementTree(root).write(path)
    return path


def test_junit_diff_lists_ledger_hits_apart_with_reason_and_date(tmp_path, capsys):
    led = tmp_path / "l.toml"
    led.write_text(GOOD.replace("2026-11-01", "2026-01-01").replace("2026-10-30", "2026-01-02"))
    old = _junit(tmp_path / "o.xml", {"tests.test_a::test_flaky": "passed", "tests.test_a::test_new": "passed"})
    new = _junit(tmp_path / "n.xml", {"tests.test_a::test_flaky": "failed", "tests.test_a::test_new": "failed"})
    base = junit_diff.load_baseline(led)
    res = junit_diff.compare(junit_diff.load(old), junit_diff.load(new), set(), base)
    assert res["newly_bad"] == ["tests.test_a::test_new"]
    assert res["baseline_failed"] == [{"key": "tests.test_a::test_flaky", "id": "tests/test_a.py::test_flaky",
                                       "kind": "flaky", "since": "2026-01-01",
                                       "reason": "fails under load, passes alone"}]
    assert junit_diff.main([str(old), str(new), "--baseline", str(led), "--fail-on-regression"]) == 1
    out = capsys.readouterr().out
    assert "baseline_failed 1" in out and "BASELINE tests.test_a::test_flaky  (flaky since 2026-01-01" in out
    assert junit_diff.main([str(old), str(new), "--baseline", str(tmp_path / "missing.toml")]) == 2
    assert "baseline ledger not found" in capsys.readouterr().err
