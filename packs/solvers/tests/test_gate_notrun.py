"""B-196: strict not-run in the regression gate. A file whose tests passed but where a test (or a recorded
part of one) did not run is NOTRUN (red) unless its kind is accepted: tests/gate.toml not_run_ok or
`ctf gate run --allow-not-run KIND`. Synthetic checkouts, real pytest children, no network."""
from __future__ import annotations

import argparse

import pytest

from ctf.cli import gate as gate_cli
from ctf.gate import GateError, config, notrun
from ctf.gate.impact import Graph, Selection
from ctf.gate.runner import BAD, format_summary, run_file, run_gate
from ctf.gate.warm import WarmResult, WarmStore, file_key
from gate_repo import make_repo

FILES = {
    "tests/test_green.py": "def test_a():\n    pass\n",
    "tests/test_tool.py": ("import pytest\ndef test_runs():\n    pass\n"
                           "@pytest.mark.skip(reason='needs_tool: radare2 not available')\n"
                           "def test_needs_r2():\n    pass\n"),
    "tests/test_live.py": ("import pytest\ndef test_runs():\n    pass\n"
                           "@pytest.mark.skip(reason='live: not run by default (pass --run-live)')\n"
                           "def test_live():\n    pass\n"),
    "tests/test_xf.py": ("import pytest\ndef test_runs():\n    pass\n"
                         "@pytest.mark.xfail(reason='known-fail: owner fixes it', strict=True)\n"
                         "def test_known():\n    assert 0\n"),
    "tests/test_part.py": ("def test_partly(request):\n"
                           "    request.node.user_properties.append(('ctf_not_run', [['needs_realdata: corpus absent', 'case 3']]))\n"),
    "tests/test_red.py": "def test_red():\n    assert 0\n",
}

JUNIT = """<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" errors="0" failures="0"
skipped="3" tests="5"><testcase classname="tests.test_x" name="test_ok" time="0"/>
<testcase classname="tests.test_x" name="test_tool"><skipped type="pytest.skip" message="needs_tool: r2 not available">x</skipped></testcase>
<testcase classname="tests.test_x" name="test_plain"><skipped type="pytest.skip" message="Skipped: no reason given"/></testcase>
<testcase classname="tests.test_x" name="test_known"><skipped type="pytest.xfail" message="known-fail: owner"/></testcase>
<testcase classname="tests.test_x" name="test_xf"><skipped type="pytest.xfail" message="flaky upstream"/></testcase>
<testcase classname="tests.test_x" name="test_part"><properties><property name="ctf_not_run" value="[['live: off', 'leg 2'], ['needs_realdata: gone', 'leg 3']]"/></properties></testcase>
</testsuite></testsuites>
"""


@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", FILES)


# ---------------------------------------------------------------------------------------------- notrun.py

def test_kinds_from_a_junit_report(tmp_path):
    p = tmp_path / "r.xml"
    p.write_text(JUNIT)
    got = [(x.test, x.kind, x.reason) for x in notrun.from_junit(p)]
    assert got == [
        ("tests.test_x::test_tool", "needs_tool", "needs_tool: r2 not available"),
        ("tests.test_x::test_plain", "skip", "Skipped: no reason given"),
        ("tests.test_x::test_known", "known-fail", "known-fail: owner"),
        ("tests.test_x::test_xf", "xfail", "flaky upstream"),
        ("tests.test_x::test_part [leg 2]", "live", "live: off"),
        ("tests.test_x::test_part [leg 3]", "needs_realdata", "needs_realdata: gone"),
    ]


def test_kind_of_matches_the_plugin_prefixes():
    assert notrun.kind_of("needs_tool: x") == "needs_tool"
    assert notrun.kind_of("Skipped: needs_realdata: y") == "needs_realdata"
    assert notrun.kind_of("live") == "live"
    assert notrun.kind_of("needs_toolbox: z") == "skip"          # a prefix of a kind name is not that kind
    assert notrun.kind_of("known-fail: a", xfail=True) == "known-fail"
    assert notrun.kind_of("anything", xfail=True) == "xfail"
    from ctf.testing import pytest_plugin
    for reason in ("needs_tool: x", "needs_realdata: y", "live: z", "skip", "whatever", "known-fail: k"):
        assert notrun.kind_of(reason) == pytest_plugin.kind_of(reason)   # the plugin's report agrees


def test_blocking_and_the_allow_list():
    items = [notrun.NotRun("a", "needs_tool: x", "needs_tool"), notrun.NotRun("b", "live: y", "live")]
    assert notrun.blocking(items, ()) == items
    assert notrun.blocking(items, ("live",)) == [items[0]]
    assert notrun.blocking(items, ("live", "needs_tool")) == []
    assert notrun.blocking(items, ("any",)) == []
    assert notrun.check_allow(["live", "any"]) == ("live", "any")
    with pytest.raises(ValueError, match="unknown not-run kind"):
        notrun.check_allow(["needs-tool"])


def test_reasons_fall_back_to_the_text_then_the_kind(tmp_path):
    p = tmp_path / "r.xml"
    p.write_text('<testsuites><testsuite>'
                 '<testcase classname="c" name="a"><skipped type="pytest.skip">needs_tool: from the text</skipped></testcase>'
                 '<testcase classname="c" name="b"><skipped type="pytest.xfail"/></testcase>'
                 '<testcase classname="c" name="c"><skipped type="pytest.skip"/></testcase>'
                 '<testcase classname="c" name="d"><properties><property name="ctf_not_run" '
                 'value="[\'ab\', [\'live: x\', \'leg\', \'extra\'], [\'live: y\', \'ok\']]"/></properties></testcase>'
                 '</testsuite></testsuites>')
    got = [(x.test, x.reason, x.kind) for x in notrun.from_junit(p)]
    assert got == [("c::a", "needs_tool: from the text", "needs_tool"), ("c::b", "xfail", "xfail"),
                   ("c::c", "skip", "skip"), ("c::d", "unreadable ctf_not_run part 'ab'", "skip"),
                   ("c::d", "unreadable ctf_not_run part ['live: x', 'leg', 'extra']", "skip"),
                   ("c::d [ok]", "live: y", "live")]                  # a malformed part is never dropped


def test_an_unreadable_property_is_itself_not_run(tmp_path):
    p = tmp_path / "r.xml"
    p.write_text('<testsuites><testsuite><testcase classname="c" name="t"><properties>'
                 '<property name="ctf_not_run" value="[[unclosed"/></properties></testcase></testsuite></testsuites>')
    assert [(x.kind, x.reason) for x in notrun.from_junit(p)] == [("skip", "unreadable ctf_not_run property")]


# ------------------------------------------------------------------------------------------------ runner

def _row(repo, tmp_path, test, allow):
    return run_file(repo, test, out_dir=tmp_path / "out", wall=300, allow_not_run=allow)


def test_a_disallowed_not_run_makes_a_green_file_notrun(repo, tmp_path):
    row = _row(repo, tmp_path, "tests/test_tool.py", ())
    assert row.status == "NOTRUN" and "NOTRUN" in BAD
    assert "needs_tool: radare2 not available" in row.detail
    assert [x.kind for x in row.not_run] == ["needs_tool"]
    assert _row(repo, tmp_path, "tests/test_tool.py", ("needs_tool",)).status == "PASS"
    assert _row(repo, tmp_path, "tests/test_tool.py", ("any",)).status == "PASS"
    assert _row(repo, tmp_path, "tests/test_tool.py", None).status == "PASS"   # the API default: not strict


def test_xfail_and_recorded_parts_are_judged_by_kind(repo, tmp_path):
    assert _row(repo, tmp_path, "tests/test_xf.py", ()).status == "NOTRUN"
    assert _row(repo, tmp_path, "tests/test_xf.py", ("known-fail",)).status == "PASS"
    part = _row(repo, tmp_path, "tests/test_part.py", ("live",))
    assert part.status == "NOTRUN" and "case 3" in part.detail          # a passed test with a not-run part
    assert _row(repo, tmp_path, "tests/test_part.py", ("needs_realdata",)).status == "PASS"


def test_a_fully_run_file_and_a_red_file_are_unchanged(repo, tmp_path):
    assert _row(repo, tmp_path, "tests/test_green.py", ()).status == "PASS"
    assert _row(repo, tmp_path, "tests/test_red.py", ()).status == "FAIL"   # a failure stays FAIL, not NOTRUN


def _graph(repo, state):
    return Graph(repo, config.load(repo, repo / "gate.toml"), state / "co")


def test_run_gate_counts_notrun_red_and_drops_its_warm_result(repo, tmp_path):
    g = _graph(repo, tmp_path / "s")
    sel = Selection("impact", ["tests/test_green.py", "tests/test_tool.py"], [], {})
    store = WarmStore(tmp_path / "s")
    key = file_key(g, "tests/test_tool.py", ())
    store.put(WarmResult(test="tests/test_tool.py", key=key, seconds=1.0, passed=1, xfailed=0, ts=0.0))
    rep = run_gate(g, sel, state=tmp_path / "s", out_dir=tmp_path / "o", warm=False, emit=lambda s: None,
                   load_fn=lambda: 0.0, cpus=4, allow_not_run=())
    assert not rep.ok and rep.count("NOTRUN") == 1
    assert format_summary(rep).startswith("GATE result=fail") and format_summary(rep).endswith("notrun=1")
    assert store.get(key, "tests/test_tool.py") is None


def test_a_stored_result_with_xfails_is_not_reused_by_a_strict_run(repo, tmp_path):
    state = tmp_path / "s"
    g = _graph(repo, state)
    sel = Selection("impact", ["tests/test_xf.py"], [], {})
    kw = dict(state=state, out_dir=tmp_path / "o", emit=lambda s: None, load_fn=lambda: 0.0, cpus=4)
    both = ("xfail", "known-fail")
    first = run_gate(g, sel, warm=True, allow_not_run=both, **kw)                  # PASS, stored
    assert first.ok and first.rows[0].xfailed == 1 and not first.rows[0].warm
    again = run_gate(_graph(repo, state), sel, warm=True, allow_not_run=both, **kw)
    assert again.rows[0].warm                                                     # both allowed: reused
    # the stored result does not say which xfail kind it had, so a run allowing only one kind reruns it
    one = run_gate(_graph(repo, state), sel, warm=True, allow_not_run=("known-fail",), **kw)
    assert not one.rows[0].warm and one.rows[0].status == "PASS"
    strict = run_gate(_graph(repo, state), sel, warm=True, allow_not_run=(), **kw)
    assert not strict.rows[0].warm and strict.rows[0].status == "NOTRUN"
    # the NOTRUN run dropped the stored result: even a non-strict run now runs the file again
    assert not run_gate(_graph(repo, state), sel, warm=True, allow_not_run=None, **kw).rows[0].warm


def test_a_recorded_not_run_part_is_never_stored_so_a_later_strict_run_sees_it(repo, tmp_path):
    # test_part.py has skipped == 0: its not-run part is reported only through the ctf_not_run property.
    state = tmp_path / "s"
    sel = Selection("impact", ["tests/test_part.py"], [], {})
    kw = dict(state=state, out_dir=tmp_path / "o", emit=lambda s: None, load_fn=lambda: 0.0, cpus=4, warm=True)
    lax = run_gate(_graph(repo, state), sel, allow_not_run=("any",), **kw)
    assert lax.ok and lax.rows[0].status == "PASS" and lax.rows[0].skipped == 0 and lax.rows[0].not_run
    strict = run_gate(_graph(repo, state), sel, allow_not_run=(), **kw)
    assert not strict.rows[0].warm and strict.rows[0].status == "NOTRUN"
    # a green file with nothing not run is still stored and reused
    g = _graph(repo, state)
    green = Selection("impact", ["tests/test_green.py"], [], {})
    run_gate(g, green, allow_not_run=("any",), **kw)
    assert run_gate(_graph(repo, state), green, allow_not_run=(), **kw).rows[0].warm


# ---------------------------------------------------------------------------------------------- config + CLI

def test_config_not_run_ok_is_validated(tmp_path):
    root = make_repo(tmp_path / "r", {}, extra_config="", commit=False)
    text = (root / "gate.toml").read_text()
    (root / "gate.toml").write_text(text.replace("no_warm =", 'not_run_ok = ["live"]\nno_warm ='))
    assert config.load(root, root / "gate.toml").not_run_ok == ("live",)
    (root / "gate.toml").write_text(text.replace("no_warm =", 'not_run_ok = ["any"]\nno_warm ='))
    with pytest.raises(GateError, match="never the config"):
        config.load(root, root / "gate.toml")
    (root / "gate.toml").write_text(text.replace("no_warm =", 'not_run_ok = ["tool"]\nno_warm ='))
    with pytest.raises(GateError, match="not_run_ok kind 'tool'"):
        config.load(root, root / "gate.toml")
    (root / "gate.toml").write_text(text)
    assert config.load(root, root / "gate.toml").not_run_ok == ()


def test_the_repo_config_accepts_only_declared_kinds():
    from ctf import paths
    cfg = config.load(paths.repo_root())
    assert set(cfg.not_run_ok) == {"live", "xfail", "known-fail"}


def cli(repo, tmp_path, *argv):
    p = argparse.ArgumentParser()
    gate_cli.add_arguments(p)
    common = ["--root", str(repo), "--config", str(repo / "gate.toml"), "--state", str(tmp_path / "state")]
    return gate_cli.run(p.parse_args(common + list(argv)))


def test_the_cli_is_strict_by_default(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--changed", "tests/test_tool.py", "tests/test_green.py", "--jobs", "1") == 1
    out = capsys.readouterr().out
    assert "not-run: strict, accepted kinds: none" in out
    assert any(ln.startswith("NOTRUN") and "tests/test_tool.py" in ln for ln in out.splitlines())
    assert "GATE result=fail" in out
    assert cli(repo, tmp_path, "run", "--changed", "tests/test_tool.py", "--allow-not-run", "needs_tool") == 0
    assert "accepted kinds: needs_tool" in capsys.readouterr().out
    assert cli(repo, tmp_path, "run", "--changed", "tests/test_tool.py", "--allow-not-run", "any") == 0
    assert "not strict" in capsys.readouterr().out


def test_the_config_kinds_are_accepted_by_the_cli(tmp_path, capsys):
    repo = make_repo(tmp_path / "repo", FILES)
    text = (repo / "gate.toml").read_text()
    (repo / "gate.toml").write_text(text.replace("no_warm =", 'not_run_ok = ["live"]\nno_warm ='))
    assert cli(repo, tmp_path, "run", "--changed", "tests/test_live.py") == 0
    assert "accepted kinds: live" in capsys.readouterr().out
    assert cli(repo, tmp_path, "run", "--changed", "tests/test_tool.py") == 1


def test_a_bad_allow_kind_is_a_usage_error(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--changed", "tests/test_tool.py", "--allow-not-run", "tools") == 2
    assert "unknown not-run kind" in capsys.readouterr().err


def test_mark_green_is_refused_when_strictness_is_off(repo, tmp_path, capsys):
    assert cli(repo, tmp_path, "run", "--full", "--allow-not-run", "any", "--mark-green", "demo") == 2
    assert "needs strict not-run" in capsys.readouterr().err


def test_allowed_not_run_merges_config_and_flags():
    cfg = argparse.Namespace(not_run_ok=("live",))
    assert gate_cli.allowed_not_run(cfg, ["needs_tool", "live"]) == ("live", "needs_tool")
    with pytest.raises(GateError):
        gate_cli.allowed_not_run(cfg, ["nope"])

