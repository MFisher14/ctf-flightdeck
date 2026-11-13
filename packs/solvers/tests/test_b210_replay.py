"""B-210: `ctf show replay` / `lane-profile` (ctf.treereplay): one fresh process per attempt on each tree,
answer diff across trees, per-attempt CPU, cProfile.

Each test builds synthetic checkouts (tests/adapt_repo.py: a probe engine whose answer is a hash of its
input, a one-lane opener) and, where CPU matters, a burn engine written here. The engines really run under
the intake audit-hook guard; nothing in the replay is mocked. Time: CPU assertions use the engine's own
CPU (getrusage), which load does not inflate; the only wall-clock assertions are lower bounds or a cut at a
cap far below the engine's sleep.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf import cli
from ctf import treereplay as TR

import adapt_repo as AR

pytestmark = pytest.mark.needs_tool("git")

IDLE = dict(load=0.0, cpus=1, guard="hook")

BURN = '''\
import sys, time
from pathlib import Path


def burn_loop(limit):
    t0, x = time.process_time(), 0
    while time.process_time() - t0 < limit:
        for i in range(20000):
            x += i
    return x


burn_loop(float(Path(sys.argv[1]).read_text().strip() or "0"))
print("BURNED " + Path(sys.argv[1]).name)
'''


@pytest.fixture
def trees(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    a = AR.make_repo(tmp_path / "a")
    b = AR.make_repo(tmp_path / "b")
    wd = tmp_path / "work"
    wd.mkdir()
    return a, b, wd


def _burn_engine(root: Path) -> None:
    AR.write(root, "solvers/toolkits/burn_probe.py", BURN)
    AR.write(root, "solvers/toolkits/burn_probe.manifest.toml",
             'id = "toolkits.burn_probe"\nlane = "toolkits"\nentry = "cli:python solvers/toolkits/burn_probe.py"\n'
             'capabilities = ["analysis", "cli"]\ncost_class = "cheap"\n')


def test_same_trees_agree_and_every_attempt_is_a_fresh_process(trees, monkeypatch):
    a, b, wd = trees
    # each run lists then litters its workdir: a shared workdir would make the second repeat differ
    monkeypatch.setenv("ADAPT_PROBE_LITTER", "1")
    rep = TR.replay([str(a), str(b)], lane="probe", repeat=2, workdir=wd, **IDLE)
    assert rep.trees == {"A": str(a.resolve()), "B": str(b.resolve())}
    assert len(rep.attempts) == 2 * 3 * 2                       # trees x cases x repeats
    assert all(a_.lines[0] == "WORKDIR_HAS" for a_ in rep.attempts)
    d = TR.diff(rep)
    assert [(c.case, c.verdict) for c in d] == [(f"opener:{AR.BASE_FIXTURE}", TR.SAME),
                                                (f"opener:{AR.CASE_FIXTURE}", TR.SAME),
                                                (f"control:{AR.CONTROL_FIXTURE}", TR.SAME)]
    assert not TR.has_difference(d)
    base = [x for x in rep.attempts if x.case == f"opener:{AR.BASE_FIXTURE}"]
    assert all(x.status == TR.OK and x.expect_ok is True and x.code == 0 for x in base)
    ctrl = [x for x in rep.attempts if x.case.startswith("control:")]
    assert all(x.expect_ok is None for x in ctrl)
    assert not list(wd.glob("replay-*")), "run folders are removed after the replay"


def test_a_changed_tree_differs_and_shows_the_lines_only_each_gives(trees, tmp_path):
    a, b, wd = trees
    AR.write(b, "solvers/common/adapt_probe_lib.py", 'PREFIX = "ANSWER2: "\n')
    rep = TR.replay([str(a), f"after={b}"], lane="probe", workdir=wd, cases=[f"opener:{AR.BASE_FIXTURE}"], **IDLE)
    assert list(rep.trees) == ["A", "after"]
    (c,) = TR.diff(rep)
    want = AR.fixture_answer(AR.BASE_FIXTURE, tmp_path)
    assert c.verdict == TR.DIFFERS
    assert c.only == {"A": (want,), "after": ("ANSWER2: " + want.split(": ", 1)[1],)}
    assert c.status == {"A": TR.OK, "after": TR.FAIL}            # the after tree misses the expect key
    text = "\n".join(TR.render(rep, [c]))
    assert f"only A: {want}" in text and "DIFF differs" in text and "summary: differs 1" in text


def test_a_status_change_with_the_same_lines_differs(trees, capsys):
    a, b, wd = trees
    # tree B's library makes the probe exit 4 after printing the very same answer
    AR.write(b, "solvers/common/adapt_probe_lib.py",
             'import sys\nPREFIX = "ANSWER: "\n_exit = sys.exit\nsys.exit = lambda code=0: _exit(4)\n')
    case = f"opener:{AR.BASE_FIXTURE}"
    rep = TR.replay([str(a), str(b)], lane="probe", workdir=wd, cases=[case], **IDLE)
    assert rep.of("A", case)[0].lines == rep.of("B", case)[0].lines
    assert rep.of("B", case)[0].code == 4
    (c,) = TR.diff(rep)
    assert c.verdict == TR.DIFFERS and c.only == {}
    assert c.status == {"A": TR.OK, "B": TR.FAIL} and c.note == "status A=ok, B=fail"
    assert TR.has_difference([c])
    code = cli.main(["show", "replay", "--tree", str(a), "--tree", str(b), "--lane", "probe", "--workdir", str(wd),
                     "--guard", "hook", "--case", case])
    assert code == 1 and "DIFF differs" in capsys.readouterr().out


def test_lines_regex_compares_only_matching_lines(trees, monkeypatch):
    a, b, wd = trees
    monkeypatch.setenv("ADAPT_PROBE_SHOW", "HOME")          # prints INPUT/CWD lines that differ per run
    rep = TR.replay([str(a), str(b)], lane="probe", workdir=wd, cases=[f"opener:{AR.BASE_FIXTURE}"], **IDLE)
    assert TR.diff(rep)[0].verdict == TR.DIFFERS              # the run folders differ, so the lines do
    rep = TR.replay([str(a), str(b)], lane="probe", workdir=wd, cases=[f"opener:{AR.BASE_FIXTURE}"],
                    lines=r"^ANSWER", **IDLE)
    assert TR.diff(rep)[0].verdict == TR.SAME
    assert all(len(x.lines) == 1 and x.lines[0].startswith("ANSWER: ") for x in rep.attempts)


def test_repeats_that_disagree_are_unstable(trees, tmp_path, monkeypatch):
    a, b, wd = trees
    monkeypatch.setenv("ADAPT_PROBE_ONCE", str(tmp_path / "once-marker"))   # the very first run answers wrong
    rep = TR.replay([str(a), str(b)], lane="probe", repeat=2, workdir=wd, cases=[f"opener:{AR.BASE_FIXTURE}"],
                    **IDLE)
    (c,) = TR.diff(rep)
    assert c.verdict == TR.UNSTABLE and "tree(s) A" in c.note and "B" not in c.note.split("tree(s)")[1]
    assert [x.status for x in rep.of("A", c.case)] == [TR.FAIL, TR.OK]


def test_a_key_that_holds_on_the_control_fails_it(trees, tmp_path, monkeypatch):
    a, _, wd = trees
    monkeypatch.setenv("ADAPT_PROBE_ALWAYS", AR.fixture_answer(AR.BASE_FIXTURE, tmp_path))
    rep = TR.replay([str(a)], lane="probe", workdir=wd, cases=[f"control:{AR.CONTROL_FIXTURE}"], **IDLE)
    (x,) = rep.attempts
    assert x.status == TR.FAIL and "also holds on this control" in x.reason
    monkeypatch.delenv("ADAPT_PROBE_ALWAYS")
    rep = TR.replay([str(a)], lane="probe", workdir=wd, cases=[f"control:{AR.CONTROL_FIXTURE}"], **IDLE)
    assert rep.attempts[0].status == TR.OK


def test_a_case_one_tree_lacks_is_missing(trees, tmp_path):
    a, _, wd = trees
    b = AR.make_repo(tmp_path / "c", extra_case=False)
    rep = TR.replay([str(a), str(b)], lane="probe", workdir=wd, **IDLE)
    d = {c.case: c for c in TR.diff(rep)}
    assert d[f"opener:{AR.CASE_FIXTURE}"].verdict == TR.MISSING
    assert "not in tree(s) B" in d[f"opener:{AR.CASE_FIXTURE}"].note
    assert d[f"opener:{AR.BASE_FIXTURE}"].verdict == TR.SAME


def test_a_run_past_its_cap_is_cut(trees, monkeypatch):
    a, _, wd = trees
    monkeypatch.setenv("ADAPT_PROBE_SLEEP", "60")
    rep = TR.replay([str(a)], lane="probe", workdir=wd, cases=[f"opener:{AR.BASE_FIXTURE}"], cap=1.0, **IDLE)
    (x,) = rep.attempts
    assert x.status == TR.CUT and x.code is None and x.seconds >= 1.0      # a lower bound only


def test_cpu_is_measured_per_attempt(trees, tmp_path):
    a, _, wd = trees
    _burn_engine(a)
    burn = tmp_path / "in" / "burn.txt"
    idle = tmp_path / "in" / "idle.txt"
    burn.parent.mkdir()
    burn.write_text("1.0")
    idle.write_text("0")
    rep = TR.replay([str(a)], engine="toolkits.burn_probe", inputs=[burn, idle], workdir=wd, **IDLE)
    got = {x.case: x for x in rep.attempts}
    assert got["input:burn.txt"].lines == ("BURNED burn.txt",)
    assert got["input:burn.txt"].cpu >= 0.9                         # it burned 1.0 s of its own CPU
    assert got["input:burn.txt"].cpu - got["input:idle.txt"].cpu >= 0.7


def test_cprofile_keeps_stats_and_names_the_hot_function(trees, tmp_path):
    a, _, wd = trees
    _burn_engine(a)
    burn = tmp_path / "burn.txt"
    burn.write_text("0.5")
    prof = tmp_path / "prof"
    rep = TR.replay([str(a)], engine="toolkits.burn_probe", inputs=[burn], workdir=wd, cprofile=True,
                    profile_dir=prof, **IDLE)
    (x,) = rep.attempts
    assert x.status == TR.OK and x.lines == ("BURNED burn.txt",)        # the engine still answers under the shim
    assert x.profile and Path(x.profile).is_file() and Path(x.profile).parent == prof
    assert rep.top and "burn_loop" in rep.top[0][0]
    lines = TR.lane_profile(rep, top=3)
    assert lines[0].startswith("lane profile -: 1 case(s)")
    assert "A input:burn.txt" in lines[1]
    assert any("burn_loop" in ln for ln in lines[3:])


def test_cprofile_without_a_dir_keeps_only_the_summary(trees, tmp_path):
    a, _, wd = trees
    _burn_engine(a)
    burn = tmp_path / "burn.txt"
    burn.write_text("0.3")
    rep = TR.replay([str(a)], engine="toolkits.burn_probe", inputs=[burn], workdir=wd, cprofile=True, **IDLE)
    assert rep.attempts[0].profile is None and any("burn_loop" in t[0] for t in rep.top)
    assert any("not kept" in n for n in rep.notes)


def test_profile_shim_does_not_change_the_answer(trees):
    a, _, wd = trees
    plain = TR.replay([str(a)], lane="probe", workdir=wd, **IDLE)
    prof = TR.replay([str(a)], lane="probe", workdir=wd, cprofile=True, **IDLE)
    assert [x.lines for x in plain.attempts] == [x.lines for x in prof.attempts]


def test_bad_arguments_fail_with_a_named_reason(trees, tmp_path):
    a, _, wd = trees
    with pytest.raises(TR.ReplayError, match="not a ctf-tools checkout"):
        TR.replay([str(tmp_path)], lane="probe", workdir=wd, **IDLE)
    with pytest.raises(TR.ReplayError, match="not both"):
        TR.replay([str(a)], lane="probe", engine="x", workdir=wd, **IDLE)
    with pytest.raises(TR.ReplayError, match="at least 1"):
        TR.replay([str(a)], lane="probe", repeat=0, workdir=wd, **IDLE)
    with pytest.raises(TR.ReplayError, match="--lines"):
        TR.replay([str(a)], lane="probe", lines="(", workdir=wd, **IDLE)
    with pytest.raises(TR.ReplayError, match="in no tree"):
        TR.replay([str(a)], lane="probe", cases=["opener:nope"], workdir=wd, **IDLE)
    with pytest.raises(TR.ReplayError, match="no regression set"):
        TR.replay([str(a)], lane="nolane", workdir=wd, **IDLE)
    with pytest.raises(TR.ReplayError, match="given twice"):
        TR.labels_for([f"X={a}", f"X={a}"])
    with pytest.raises(TR.ReplayError, match="--input"):
        TR.replay([str(a)], engine="toolkits.adapt_probe", inputs=[tmp_path / "missing"], workdir=wd, **IDLE)


def test_an_unresolvable_engine_fails_the_attempt(trees, tmp_path):
    a, _, wd = trees
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    rep = TR.replay([str(a)], engine="toolkits.no_such_engine", inputs=[f], workdir=wd, **IDLE)
    assert rep.attempts[0].status == TR.FAIL and "does not resolve" in rep.attempts[0].reason


def test_cli_replay_writes_answers_and_times_and_exits_on_difference(trees, tmp_path, capsys):
    a, b, wd = trees
    out = tmp_path / "out" / "answers-and-times.json"
    code = cli.main(["show", "replay", "--tree", str(a), "--tree", str(b), "--lane", "probe", "--workdir", str(wd),
                     "--guard", "hook", "--case", f"opener:{AR.BASE_FIXTURE}", "--out", str(out)])
    text = capsys.readouterr().out
    assert code == 0 and "summary: same 1" in text
    body = json.loads(out.read_text())
    assert [x["tree"] for x in body["attempts"]] == ["A", "B"]
    assert all(x["cpu"] >= 0 and x["seconds"] > 0 and x["lines"] for x in body["attempts"])
    assert body["diff"][0]["verdict"] == "same"
    AR.write(b, "solvers/common/adapt_probe_lib.py", 'PREFIX = "OTHER: "\n')
    code = cli.main(["show", "replay", "--tree", str(a), "--tree", str(b), "--lane", "probe", "--workdir", str(wd),
                     "--guard", "hook", "--case", f"opener:{AR.BASE_FIXTURE}"])
    assert code == 1 and "DIFF differs" in capsys.readouterr().out
    code = cli.main(["show", "replay", "--tree", str(tmp_path), "--lane", "probe", "--workdir", str(wd)])
    assert code == 2 and "not a ctf-tools checkout" in capsys.readouterr().err


def test_cli_lane_profile(trees, capsys):
    a, _, wd = trees
    code = cli.main(["show", "lane-profile", "--lane", "probe", "--tree", str(a), "--workdir", str(wd),
                     "--guard", "hook", "--top", "5"])
    text = capsys.readouterr().out
    assert code == 0 and text.startswith("lane profile probe: 3 case(s)")
    assert "top 5 functions by own time:" in text
    code = cli.main(["show", "lane-profile", "--tree", str(a), "--workdir", str(wd)])
    assert code == 2 and "needs --lane" in capsys.readouterr().err
