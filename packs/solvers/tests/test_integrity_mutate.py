"""B-196: the shipped mutation check (ctf/integrity/mutate.py). Mutant generation is pure and checked
operator by operator; the run builds a small synthetic git checkout and runs real pytest children in a
temporary copy of it (nothing is run in place, no network)."""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from ctf.cli import integrity as integrity_cli
from ctf.gate.runner import Row
from ctf.integrity import IntegrityError, mutate
from gate_repo import make_repo, write

CALC = '''\
"""calc: a module docstring is never mutated."""
LIMIT = 10


def clamp(x: int, lo: int = 0, hi: int = LIMIT) -> int:
    """Clamp x into [lo, hi]."""
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def guarded(flag):
    if flag:
        raise ValueError("refused")
    return "ok"  # pragma: no mutate


def untested(a, b):
    return a + b


def count_up(n):
    i = 0
    while i < n:
        i = i + 1
    return i
'''

TEST_CALC = '''\
import pytest
from lib import calc


def test_clamp():
    assert calc.clamp(-5) == 0
    assert calc.clamp(50) == 10
    assert calc.clamp(7) == 7


def test_guarded():
    with pytest.raises(ValueError):
        calc.guarded(True)
    assert calc.guarded(False) == "ok"


def test_count_up():
    assert calc.count_up(3) == 3
'''


def _src(tmp_path, text, rel="m.py"):
    (tmp_path / rel).write_text(text)
    return tmp_path


def _ops(ms):
    return [(m.op, " ".join(m.before.split()), m.after) for m in ms]


# -------------------------------------------------------------------------------------------- generation

def test_each_operator_makes_its_mutant(tmp_path):
    root = _src(tmp_path, "def f(a, b, xs):\n"
                          "    if a == b and not xs:\n"
                          "        g(a)\n"
                          "        raise ValueError('x')\n"
                          "    return a + 1 if a in xs else True\n")
    got = _ops(mutate.generate(root, "m.py")[0])
    assert ("cmp", "a == b", "(a != b)") in got
    assert ("bool", "a == b and not xs", "(a == b or not xs)") in got
    assert ("not", "not xs", "(xs)") in got
    assert ("if", "a == b and not xs", "not (a == b and not xs)") in got
    assert ("call", "g(a)", "None") in got
    assert ("raise", "raise ValueError('x')", "pass") in got
    assert ("return", "a + 1 if a in xs else True", "None") in got
    assert ("arith", "a + 1", "(a - 1)") in got
    assert ("const", "1", "(2)") in got
    assert ("const", "True", "(False)") in got
    assert ("if", "a in xs", "not (a in xs)") in got          # a ternary's condition
    assert ("cmp", "a in xs", "(a not in xs)") in got


def test_boundary_and_negation_tables(tmp_path):
    root = _src(tmp_path, "def f(a, b):\n    return [a < b, a <= b, a > b, a >= b, a is b]\n")
    got = {(op, b, a) for op, b, a in _ops(mutate.generate(root, "m.py", ops=("cmp", "boundary"))[0])}
    assert got == {("cmp", "a < b", "(a >= b)"), ("boundary", "a < b", "(a <= b)"),
                   ("cmp", "a <= b", "(a > b)"), ("boundary", "a <= b", "(a < b)"),
                   ("cmp", "a > b", "(a <= b)"), ("boundary", "a > b", "(a >= b)"),
                   ("cmp", "a >= b", "(a < b)"), ("boundary", "a >= b", "(a > b)"),
                   ("cmp", "a is b", "(a is not b)")}


def test_what_is_never_mutated(tmp_path):
    root = _src(tmp_path, CALC)
    ms, counts = mutate.generate(root, "m.py")
    assert all(m.function in ("clamp", "guarded", "untested", "count_up") for m in ms)   # no module level
    lines = {m.line for m in ms}
    assert 2 not in lines and 1 not in lines                                  # LIMIT and the docstring
    assert 5 not in lines                                                     # annotations and defaults
    assert 6 not in lines                                                     # the function docstring
    assert 17 not in lines and counts["pragma"] >= 1                          # the pragma line
    text = (root / "m.py").read_text()
    for m in ms:
        assert m.apply(text) != text and text[m.start:m.end] == m.before


def test_nested_functions_are_their_own(tmp_path):
    root = _src(tmp_path, "class C:\n    def outer(self):\n        def inner(x):\n            return x > 1\n"
                          "        return inner\n")
    ms = mutate.generate(root, "m.py", ops=("cmp",))[0]
    assert [(m.function, m.before) for m in ms] == [("C.outer.inner", "x > 1")]
    for name in ("C.outer.inner", "inner"):                       # a qualified or a simple name selects it
        assert [m.function for m in mutate.generate(root, "m.py", ops=("cmp",), functions=(name,))[0]] == \
            ["C.outer.inner"]


def test_filters_and_errors(tmp_path):
    root = _src(tmp_path, CALC)
    only = mutate.generate(root, "m.py", functions=("guarded",))[0]
    assert only and {m.function for m in only} == {"guarded"}
    ranged = mutate.generate(root, "m.py", lines=(7, 8))[0]
    assert ranged and all(7 <= m.line <= 8 for m in ranged)
    with pytest.raises(IntegrityError, match="no function named"):
        mutate.generate(root, "m.py", functions=("nope",))
    with pytest.raises(IntegrityError, match="unknown mutation operator"):
        mutate.generate(root, "m.py", ops=("swap",))
    with pytest.raises(IntegrityError, match="not a Python file"):
        mutate.generate(root, "missing.py")
    (root / "bad.py").write_text("def f(:\n")
    with pytest.raises(IntegrityError, match="does not parse"):
        mutate.generate(root, "bad.py")


def test_duplicate_texts_are_dropped(tmp_path):
    # `not x` -> `x` and the if-negation of `x` would be different texts; two identical constants in one
    # expression give two distinct mutants (different spans), never the same text twice
    root = _src(tmp_path, "def f(x):\n    if x:\n        return 1\n")
    ms, counts = mutate.generate(root, "m.py")
    texts = [m.apply((root / "m.py").read_text()) for m in ms]
    assert len(texts) == len(set(texts))


def test_unicode_columns_are_character_offsets(tmp_path):
    root = _src(tmp_path, "def f(s):\n    return 'é' == s or s > 'ü'\n")
    text = (root / "m.py").read_text()
    for m in mutate.generate(root, "m.py", ops=("cmp", "bool"))[0]:
        assert text[m.start:m.end] == m.before
        compile(m.apply(text), "m.py", "exec")


def test_spread_keeps_n_evenly():
    xs = list(range(10))
    assert mutate.spread(xs, None) == xs and mutate.spread(xs, 20) == xs
    assert mutate.spread(xs, 5) == [0, 2, 4, 6, 8]
    assert mutate.spread(xs, 1) == [0]
    assert mutate.spread(xs, 0) == []


def test_write_refreshes_mtime_and_drops_bytecode(tmp_path):
    f = tmp_path / "m.py"
    f.write_text("A = 1\n")
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    pyc = cache / "m.cpython-312.pyc"
    pyc.write_bytes(b"stale")
    other = cache / "n.cpython-312.pyc"
    other.write_bytes(b"keep")
    before = f.stat().st_mtime
    mutate._write(f, "A = 2\n", 0)
    assert f.read_text() == "A = 2\n" and not pyc.exists() and other.exists()
    assert f.stat().st_mtime >= before + 2           # a same-size edit can never look unchanged


# ----------------------------------------------------------------------------------------------- running

@pytest.fixture
def repo(tmp_path):
    return make_repo(tmp_path / "repo", {"lib/calc.py": CALC, "tests/test_calc.py": TEST_CALC,
                                         "lib/orphan.py": "def f():\n    return 1\n"})


def _run(repo, tmp_path, **kw):
    kw.setdefault("load_fn", lambda: 0.0)
    kw.setdefault("cpus", 4)
    lines = []
    rep = mutate.run(repo, "lib/calc.py", state=tmp_path / "state", config=repo / "gate.toml",
                     work=tmp_path, emit=lines.append, **kw)
    return rep, lines


def test_a_run_kills_tested_mutants_and_reports_untested_ones(repo, tmp_path):
    original = (repo / "lib/calc.py").read_bytes()
    mtime = (repo / "lib/calc.py").stat().st_mtime_ns
    rep, lines = _run(repo, tmp_path, functions=("guarded", "untested"), ops=("raise", "if", "arith"))
    assert rep.tests == ["tests/test_calc.py"]                                   # the gate's selection
    by = {(o.mutant.function, o.mutant.op): o for o in rep.mutants}
    assert set(by) == {("guarded", "raise"), ("guarded", "if"), ("untested", "arith")}
    assert by[("guarded", "raise")].status == "KILLED" and by[("guarded", "raise")].by == "tests/test_calc.py"
    assert by[("guarded", "if")].status == "KILLED"
    assert by[("untested", "arith")].status == "SURVIVED"
    assert rep.killed == 2 and [o.mutant.function for o in rep.survived] == ["untested"]
    assert rep.summary().startswith("MUTATE file=lib/calc.py tests=1 mutants=3 killed=2 survived=1")
    assert any(ln.startswith("SURVIVED") and "untested" in ln for ln in lines)
    assert (repo / "lib/calc.py").read_bytes() == original                       # never in place
    assert (repo / "lib/calc.py").stat().st_mtime_ns == mtime
    assert not list(tmp_path.glob("ctf-mutate-*"))                               # the copy is removed


def test_a_mutant_that_hangs_is_killed_by_the_wall(repo, tmp_path):
    # wall-clock by design: the mutant loops forever, so it is cut at the (load-scaled) wall
    rep, _ = _run(repo, tmp_path, functions=("count_up",), ops=("arith",), min_wall=3.0, wall_factor=1.0)
    assert [(o.status, o.how) for o in rep.mutants] == [("KILLED", "TIMEOUT")]


def test_a_red_baseline_refuses(repo, tmp_path):
    write(repo, {"tests/test_calc.py": TEST_CALC + "\n\ndef test_red():\n    assert calc.clamp(1) == 2\n"})
    with pytest.raises(IntegrityError, match="baseline is not green.*tests/test_calc.py is FAIL"):
        _run(repo, tmp_path, functions=("untested",))
    assert not list(tmp_path.glob("ctf-mutate-*"))


def test_an_unmapped_file_needs_named_tests(repo, tmp_path):
    with pytest.raises(IntegrityError, match="cannot narrow a change to lib/orphan.py"):
        mutate.run(repo, "lib/orphan.py", state=tmp_path / "s", config=repo / "gate.toml", emit=lambda s: None)
    with pytest.raises(IntegrityError, match="no such file"):
        mutate.run(repo, "lib/orphan.py", tests=["tests/test_nope.py"], emit=lambda s: None)


def test_named_tests_replace_the_selection_and_files_run_fastest_first(repo, tmp_path):
    write(repo, {"tests/test_more.py": "def test_x():\n    pass\n"})
    calls = []

    def fake_run_file(root, test, *, out_dir, wall, python=None, pytest_args=()):
        calls.append((test, "baseline" in str(out_dir), pytest_args))
        assert (Path(root) / "lib/calc.py").read_text() != "" and Path(root) != repo   # the copy, not the repo
        secs = {"tests/test_calc.py": 5.0, "tests/test_more.py": 1.0}[test]
        killed = not ("baseline" in str(out_dir)) and test == "tests/test_calc.py"
        return Row(test=test, status="FAIL" if killed else "PASS", seconds=secs)

    rep, _ = _run(repo, tmp_path, tests=["tests/test_calc.py", "tests/test_more.py"], functions=("untested",),
                  ops=("arith",), run_file=fake_run_file)
    assert calls[:2] == [("tests/test_calc.py", True, ()), ("tests/test_more.py", True, ())]
    assert calls[2:] == [("tests/test_more.py", False, ("-x",)), ("tests/test_calc.py", False, ("-x",))]
    assert [(o.status, o.by, o.how) for o in rep.mutants] == [("KILLED", "tests/test_calc.py", "FAIL")]


def test_the_first_killing_file_stops_the_mutant(repo, tmp_path):
    write(repo, {"tests/test_more.py": "def test_x():\n    pass\n"})
    calls = []

    def fake_run_file(root, test, *, out_dir, wall, python=None, pytest_args=()):
        calls.append(test)
        base = "baseline" in str(out_dir)
        return Row(test=test, status="PASS" if base else "FAIL", seconds=1.0 if test.endswith("calc.py") else 2.0)

    rep, _ = _run(repo, tmp_path, tests=["tests/test_calc.py", "tests/test_more.py"], functions=("untested",),
                  ops=("arith",), run_file=fake_run_file)
    assert calls == ["tests/test_calc.py", "tests/test_more.py", "tests/test_calc.py"]
    assert rep.mutants[0].by == "tests/test_calc.py"


def test_the_cli_exit_follows_the_score(repo, tmp_path, capsys):
    def cli(*argv):
        p = argparse.ArgumentParser()
        integrity_cli.add_arguments(p)
        return integrity_cli.run(p.parse_args(["--root", str(repo), *argv]))
    common = ["mutate", "lib/calc.py", "--state", str(tmp_path / "s"), "--config", str(repo / "gate.toml"),
              "--op", "arith"]
    assert cli(*common, "--function", "untested") == 1                    # 0 of 1 killed
    assert "survived=1" in capsys.readouterr().out
    assert cli(*common, "--function", "untested", "--min-score", "0") == 0
    capsys.readouterr()
    assert cli(*common, "--function", "count_up", "--list") == 0
    out = capsys.readouterr().out
    assert "arith 'i + 1' -> '(i - 1)' in count_up" in out and out.strip().endswith("pragma=0")
    assert cli(*common, "--lines", "9-3") == 2
    assert "need 1 <= A <= B" in capsys.readouterr().err
    assert cli("mutate", "lib/missing.py") == 2


def test_the_repo_gate_config_selects_tests_for_a_core_module(tmp_path):
    from ctf import paths
    sel = mutate.select_tests(paths.repo_root(), "ctf/gate/notrun.py", state=tmp_path / "s")
    assert "tests/test_gate_notrun.py" in sel


def test_the_copy_holds_the_listed_files_and_is_a_git_checkout(repo, tmp_path):
    from ctf.gate.impact import list_files
    write(repo, {".gitignore": "secret.out\n", "secret.out": "ignored\n", "lib/new.py": "X = 1\n"})
    dest = mutate.copy_checkout(repo, tmp_path / "copy")
    assert (dest / "lib/new.py").read_text() == "X = 1\n"                 # untracked, not ignored: copied
    assert not (dest / "secret.out").exists()                             # ignored: left out
    assert sorted(list_files(dest)) == sorted(list_files(repo))           # git lists the copy like the repo



def test_keyword_only_defaults_are_not_mutated(tmp_path):
    root = _src(tmp_path, "def f(a, *, b, c=3, d=True):\n    return a > c\n")
    ms = mutate.generate(root, "m.py", ops=("const", "cmp"))[0]
    assert [(m.op, m.before) for m in ms] == [("cmp", "a > c")]


def test_mutant_ids_descriptions_and_json(tmp_path):
    root = _src(tmp_path, "def f(a):\n    return a == '" + "x" * 50 + "'\n")
    m = mutate.generate(root, "m.py", ops=("cmp",))[0][0]
    assert m.id == "m.py:2:11:cmp"
    assert m.describe() == ("m.py:2:11 cmp " + repr("a == '" + "x" * 50 + "'") + " -> "
                            + repr("(a != '" + "x" * 50 + "')") + " in f")      # 56 and 58 chars: not clipped
    assert mutate._clip("y" * 60) == "y" * 60 and mutate._clip("y" * 61) == "y" * 57 + "..."
    rep = mutate.MutationReport("m.py", ["tests/t.py"], mutants=[mutate.Outcome(m, "KILLED", "tests/t.py", "FAIL")],
                                counts={"invalid": 0, "duplicate": 0, "pragma": 0, "generated": 1})
    d = rep.to_json()
    assert (d["file"], d["killed"], d["survived"], d["score"]) == ("m.py", 1, 0, 1.0)
    assert d["mutants"][0]["id"] == "m.py:2:11:cmp" and d["mutants"][0]["by"] == "tests/t.py"


def test_an_inert_file_selects_no_test(repo, tmp_path):
    write(repo, {"docs/helper.py": "def f(x):\n    return x + 1\n"})
    with pytest.raises(IntegrityError, match="no test file selects docs/helper.py"):
        mutate.run(repo, "docs/helper.py", state=tmp_path / "s", config=repo / "gate.toml", emit=lambda s: None)
