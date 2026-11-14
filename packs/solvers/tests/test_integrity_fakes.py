"""B-196: the fake-branch audit (ctf/integrity/fakes.py). A synthetic tree holds one source module with
each kind of testing-flag branch and test files that do or do not reach it with the flag off; the audit
is static, so nothing here is imported or run."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from ctf.integrity import IntegrityError, fakes

MOD = '''\
import os
from ctf import env as ctf_env


def get_bool(name, environ=None):
    return (environ or os.environ).get(name) == "1"


def proc_branch():
    if os.environ.get("CTF_TESTING"):
        return "fake"
    return "real"


def injected(environ=None):
    e = os.environ if environ is None else environ
    if get_bool("CTF_TESTING", environ=e):
        return "fake"
    return "real"


def _under_test(e):
    return bool(e.get("PYTEST_CURRENT_TEST")) or "CTF_TESTING" in os.environ


def uses_predicate(e):
    if _under_test(e):
        return 1
    return 2


def tainted():
    testing = os.getenv("CTF_TESTING") == "1"
    return 1 if testing else 2


def caller():
    return proc_branch()


def unrelated(x):
    if x:
        return 3
    return 4


def module_receiver():
    if ctf_env.get("CTF_TESTING"):
        return 1
    return 2


def mixed(e, opts):
    if e.get("CTF_TESTING") and opts.verbose:
        return 1
    if e["PYTEST_CURRENT_TEST"]:
        return 3
    return 2


class Box:
    def method(self):
        if os.environ["CTF_TESTING"]:
            return 1
        return 2
'''

TESTS = '''\
import os
import pytest
from pkg import mod
from pkg.mod import tainted


@pytest.fixture
def no_flag(monkeypatch):
    monkeypatch.delenv("CTF_TESTING", raising=False)


def test_proc_off(monkeypatch):
    monkeypatch.delenv("CTF_TESTING", raising=False)
    assert mod.proc_branch() == "real"


def test_proc_on():
    assert mod.proc_branch() == "fake"


def test_injected_dict():
    assert mod.injected(environ={"PATH": "/x"}) == "real"


def test_injected_spread():
    assert mod.injected(environ={**os.environ}) == "fake"


def test_caller_off(monkeypatch):
    monkeypatch.setenv("CTF_TESTING", "0")
    assert mod.caller() == "real"


def test_predicate_half_off(monkeypatch):
    monkeypatch.delenv("CTF_TESTING", raising=False)
    assert mod.uses_predicate({}) == 1


def test_predicate_off(monkeypatch):
    monkeypatch.delenv("CTF_TESTING", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert mod.uses_predicate({}) == 2


def test_tainted_via_fixture(no_flag):
    assert tainted() == 2


def test_method_off():
    os.environ.pop("CTF_TESTING", None)
    assert mod.Box().method() == 2


class TestBox:
    flag = "CTF_TESTING"

    def helper(self):
        os.environ.pop("CTF_TESTING", None)
        return mod.Box().method()

    def test_in_class(self, monkeypatch):
        monkeypatch.delenv("CTF_TESTING", raising=False)
        assert mod.Box().method() == 2
'''

OTHER = '''\
def test_names_proc_branch_without_importing(monkeypatch):
    monkeypatch.delenv("CTF_TESTING", raising=False)
    proc_branch = lambda: "real"
    assert proc_branch() == "real"
'''


def tree(tmp_path: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text))
    return tmp_path


@pytest.fixture
def root(tmp_path):
    return tree(tmp_path, {"pkg/__init__.py": "", "pkg/mod.py": MOD, "tests/test_mod.py": TESTS,
                           "tests/test_other.py": OTHER})


def _by_fn(res):
    return {b.function: b for b in res.branches}


def test_branch_lines_say_status_and_evidence(root):
    b = _by_fn(fakes.audit(root, source_dirs=("pkg",)))
    assert b["proc_branch"].text() == ("COVERED  pkg/mod.py:10 proc_branch reads CTF_TESTING (process env)  "
                                       "<- tests/test_mod.py::test_proc_off (+1)")
    assert b["module_receiver"].text() == "MISSING  pkg/mod.py:48 module_receiver reads CTF_TESTING (process env)"
    b["module_receiver"].waived = "decided at import"
    assert b["module_receiver"].text().endswith("(process env)  waived: decided at import")


CYCLE = """\
import pytest
from pkg import mod


@pytest.fixture
def a(b, monkeypatch):
    monkeypatch.delenv("CTF_TESTING", raising=False)


@pytest.fixture
def b(a):
    return 1


def test_cycle(a):
    assert mod.module_receiver() == 2
"""


def test_a_fixture_cycle_terminates(root):
    tree(root, {"tests/test_cycle.py": CYCLE})
    b = _by_fn(fakes.audit(root, source_dirs=("pkg",)))
    assert b["module_receiver"].evidence == ["tests/test_cycle.py::test_cycle"]


def test_every_kind_of_flag_branch_is_found(root):
    res = fakes.audit(root, source_dirs=("pkg",))
    got = {(b.function, b.flags, b.process) for b in res.branches}
    assert len(res.branches) == 8
    assert got == {
        ("proc_branch", ("CTF_TESTING",), True),
        ("injected", ("CTF_TESTING",), False),
        ("uses_predicate", ("CTF_TESTING", "PYTEST_CURRENT_TEST"), True),
        ("tainted", ("CTF_TESTING",), True),
        ("Box.method", ("CTF_TESTING",), True),
        ("module_receiver", ("CTF_TESTING",), True),          # `from ctf import env as ctf_env`: a module
        ("mixed", ("CTF_TESTING",), False),                   # .get on a local mapping, beside an attribute
        ("mixed", ("PYTEST_CURRENT_TEST",), False),           # a subscript of a local mapping
    }
    assert "unrelated" not in _by_fn(res) and "get_bool" not in _by_fn(res)


def test_evidence_needs_the_import_the_call_and_the_flag_off(root):
    b = _by_fn(fakes.audit(root, source_dirs=("pkg",)))
    assert b["proc_branch"].evidence == ["tests/test_mod.py::test_proc_off", "tests/test_mod.py::test_caller_off"]
    assert b["injected"].evidence == ["tests/test_mod.py::test_injected_dict"]      # not the ** spread
    assert b["uses_predicate"].evidence == ["tests/test_mod.py::test_predicate_off"]  # both flags off
    assert b["tainted"].evidence == ["tests/test_mod.py::test_tainted_via_fixture"]  # off in a fixture
    assert b["Box.method"].evidence == ["tests/test_mod.py::test_method_off",
                                        "tests/test_mod.py::TestBox::test_in_class"]   # not the helper
    assert all(x.status == "COVERED" for k, x in b.items() if k not in ("module_receiver", "mixed"))


def test_an_injected_mapping_does_not_turn_off_a_process_read(root):
    tree(root, {"tests/test_mod.py": TESTS + '''

def test_proc_with_env_dict():
    assert mod.proc_branch(**{}) is not None and mod.injected(env={"A": "1"}) == "real"
'''})
    b = _by_fn(fakes.audit(root, source_dirs=("pkg",)))
    assert "tests/test_mod.py::test_proc_with_env_dict" not in b["proc_branch"].evidence
    assert "tests/test_mod.py::test_proc_with_env_dict" in b["injected"].evidence


def test_a_branch_without_evidence_is_missing(root):
    tree(root, {"tests/test_mod.py": "from pkg import mod\n\ndef test_on():\n    assert mod.proc_branch()\n"})
    res = fakes.audit(root, source_dirs=("pkg",))
    assert not res.ok
    assert {b.status for b in res.branches} == {"MISSING"}
    assert any(f.startswith("MISSING pkg/mod.py:10 proc_branch") for f in res.findings)


def test_an_autouse_conftest_fixture_counts(root):
    tree(root, {"tests/conftest.py": "import pytest\n\n@pytest.fixture(autouse=True)\n"
                                     "def _off(monkeypatch):\n    monkeypatch.setenv('CTF_TESTING', 'false')\n",
                "tests/test_mod.py": "from pkg import mod\n\ndef test_on():\n    assert mod.proc_branch()\n"})
    b = _by_fn(fakes.audit(root, source_dirs=("pkg",)))
    assert b["proc_branch"].evidence == ["tests/test_mod.py::test_on"]
    assert b["injected"].evidence == []


def test_an_uncollected_test_file_is_no_evidence(root):
    tree(root, {"tests/conftest.py": 'collect_ignore = ["test_mod.py"]\n'})
    assert all(b.status == "MISSING" for b in fakes.audit(root, source_dirs=("pkg",)).branches)


def test_test_files_under_the_source_folders_are_not_source(root):
    tree(root, {"pkg/test_selfcheck.py": 'import os\nif os.environ.get("CTF_TESTING"):\n    pass\n',
                "pkg/selftest.py": 'import os\nX = 1 if os.environ.get("CTF_TESTING") else 2\n'})
    assert {b.path for b in fakes.audit(root, source_dirs=("pkg",)).branches} == {"pkg/mod.py"}


def test_module_level_branches_are_found_and_need_a_waiver(root):
    tree(root, {"pkg/top.py": 'import os\nMODE = "fake" if os.environ.get("CTF_TESTING") else "real"\n'})
    res = fakes.audit(root, source_dirs=("pkg",))
    top = [b for b in res.branches if b.path == "pkg/top.py"]
    assert [(b.function, b.status) for b in top] == [("<module>", "MISSING")]


WAIVERS = '''\
["pkg/top.py::<module>"]
reason = "decided at import: no test can import it twice"

["pkg/mod.py::proc_branch"]
tests = ["tests/test_other.py::test_names_proc_branch_without_importing"]

["pkg/gone.py::f"]
reason = "the module was deleted"
'''


def test_waivers_cover_list_and_go_stale(root):
    tree(root, {"pkg/top.py": 'import os\nMODE = "fake" if os.environ.get("CTF_TESTING") else "real"\n',
                "tests/fake_branches.toml": WAIVERS,
                "tests/test_mod.py": "from pkg import mod\n\ndef test_on():\n    assert mod.injected()\n"})
    res = fakes.audit(root, source_dirs=("pkg",))
    b = {x.key: x for x in res.branches}
    assert b["pkg/top.py::<module>"].status == "WAIVED"
    assert b["pkg/top.py::<module>"].waived.startswith("decided at import")
    assert b["pkg/mod.py::proc_branch"].evidence == ["tests/test_other.py::test_names_proc_branch_without_importing"]
    assert any(f.startswith("STALE-WAIVER") and "pkg/gone.py::f" in f for f in res.findings)
    assert not res.ok


def test_a_waiver_naming_a_missing_test_is_a_finding(root):
    tree(root, {"tests/fake_branches.toml": '["pkg/mod.py::injected"]\ntests = ["tests/test_mod.py::test_nope"]\n'})
    res = fakes.audit(root, source_dirs=("pkg",))
    assert any(f.startswith("BAD-WAIVER") and "test_nope" in f for f in res.findings)


@pytest.mark.parametrize("text,match", [
    ('["no-separator"]\nreason = "x"\n', "keyed <file>::<function>"),
    ('["a.py::f"]\nreason = "x"\nowner = "y"\n', "unknown key"),
    ('["a.py::f"]\nreason = ""\n', "non-empty reason or tests"),
    ('["a.py::f"]\ntests = "tests/x.py::t"\n', "list of node ids"),
    ('not toml [', "not valid TOML"),
])
def test_bad_waiver_files_fail_loudly(root, text, match):
    tree(root, {"tests/fake_branches.toml": text})
    with pytest.raises(IntegrityError, match=match):
        fakes.load_waivers(root)


def test_no_tests_folder_is_loud(tmp_path):
    tree(tmp_path, {"pkg/mod.py": MOD})
    with pytest.raises(IntegrityError, match="no tests/ folder"):
        fakes.audit(tmp_path, source_dirs=("pkg",))


def test_turns_off_reads_each_spelling():
    import ast

    def off(src, flag="CTF_TESTING", injected=False):
        return fakes.turns_off(ast.parse(textwrap.dedent(src)).body[0], flag, injected)
    assert off("def t(m):\n    m.setenv('CTF_TESTING', 'off')\n")
    assert not off("def t(m):\n    m.setenv('CTF_TESTING', '1')\n")
    assert off("def t():\n    del os.environ['CTF_TESTING']\n")
    assert off("def t():\n    os.environ['CTF_TESTING'] = ''\n")
    assert not off("def t():\n    os.environ['CTF_TESTING'] = '1'\n")
    assert off("def t():\n    with patch.dict(os.environ, clear=True):\n        pass\n")
    assert off("def t():\n    with patch.dict(os.environ, {'CTF_TESTING': '0'}):\n        pass\n")
    assert not off("def t():\n    with patch.dict(os.environ, {'X': '0'}):\n        pass\n")
    assert off("def t():\n    with env(CTF_TESTING=None):\n        pass\n")
    assert off("def t():\n    with env(CTF_TESTING=0):\n        pass\n")
    assert not off("def t():\n    with env(CTF_TESTING=1):\n        pass\n")
    assert not off("def t():\n    f(environ=make_env())\n", injected=True)   # not a literal: unknown
    assert not off("def t(m):\n    m.setenv('CTF_TESTING')\n")                  # no value: not off
    assert off("def t():\n    e = {'PATH': 'x'}\n    f(environ=e)\n", injected=True)
    assert not off("def t():\n    e = {'PATH': 'x'}\n    f(environ=e)\n", injected=False)
    assert off("def t():\n    f(environ=dict(PATH='x'))\n", injected=True)
    assert not off("def t():\n    f(environ=dict(os.environ))\n", injected=True)
    assert not off("def t():\n    f(environ={'CTF_TESTING': '1'})\n", injected=True)
    assert off("def t(m):\n    m.delenv('PYTEST_CURRENT_TEST')\n", flag="PYTEST_CURRENT_TEST")
    assert not off("def t(m):\n    m.delenv('CTF_TESTING')\n", flag="PYTEST_CURRENT_TEST")


def test_only_autouse_fixtures_apply_unrequested(root):
    tree(root, {"tests/conftest.py": "import pytest\n\n@pytest.fixture(scope='module')\n"
                                     "def _off(monkeypatch):\n    monkeypatch.delenv('CTF_TESTING')\n",
                "tests/test_mod.py": "from pkg import mod\n\ndef test_on():\n    assert mod.proc_branch()\n"})
    assert _by_fn(fakes.audit(root, source_dirs=("pkg",)))["proc_branch"].evidence == []


def test_an_import_alias_reaches_the_module(root):
    tree(root, {"tests/test_mod.py": "import pkg.mod as m2\n\ndef test_off(monkeypatch):\n"
                                     "    monkeypatch.delenv('CTF_TESTING', raising=False)\n"
                                     "    assert m2.proc_branch() == 'real'\n"})
    assert _by_fn(fakes.audit(root, source_dirs=("pkg",)))["proc_branch"].evidence == ["tests/test_mod.py::test_off"]


# ------------------------------------------------------------------ round 1: more flags, flags as constants

def test_the_offline_audit_flag_is_a_fake_flag(tmp_path):
    root = tree(tmp_path, {"pkg/__init__.py": "",
                           "pkg/cli.py": "from ctf import env as ctf_env\n\n\ndef main():\n"
                                         "    if ctf_env.get('CTF_OFFLINE_AUDIT') == '1':\n        return 2\n    return 0\n",
                           "tests/test_cli.py": "from pkg import cli\n\n\ndef test_real(monkeypatch):\n"
                                                "    monkeypatch.delenv('CTF_OFFLINE_AUDIT', raising=False)\n"
                                                "    assert cli.main() == 0\n"})
    assert "CTF_OFFLINE_AUDIT" in fakes.FLAGS
    b = _by_fn(fakes.audit(root, source_dirs=("pkg",)))["main"]
    assert b.flags == ("CTF_OFFLINE_AUDIT",) and b.process and b.evidence == ["tests/test_cli.py::test_real"]
    # a flag list without it does not see the branch
    assert fakes.audit(root, source_dirs=("pkg",), flags=("CTF_TESTING",)).branches == []


def test_a_flag_list_is_configurable_and_checked(tmp_path):
    root = tree(tmp_path, {"pkg/__init__.py": "",
                           "pkg/m.py": "import os\n\n\ndef f():\n    if os.environ.get('MY_STUB'):\n        return 1\n    return 2\n",
                           "tests/test_m.py": "def test_x():\n    assert 1\n"})
    assert fakes.audit(root, source_dirs=("pkg",)).branches == []
    res = fakes.audit(root, source_dirs=("pkg",), flags=["MY_STUB"])
    assert [(b.function, b.flags, b.status) for b in res.branches] == [("f", ("MY_STUB",), "MISSING")]
    for bad in ((), ("",), (None,)):
        with pytest.raises(IntegrityError, match="flags must be a non-empty list"):
            fakes.audit(root, source_dirs=("pkg",), flags=bad)


CONSTS = {
    "pkg/__init__.py": "",
    "pkg/flagnames.py": 'TESTING_FLAG = "CTF_TESTING"\nOTHER: str = "PYTEST_CURRENT_TEST"\nNOT_A_FLAG = "PATH"\n',
    # names no flag literally: found only through the constant it imports
    "pkg/uses_import.py": ("import os\nfrom pkg.flagnames import TESTING_FLAG\n\n\ndef f():\n"
                           "    if os.environ.get(TESTING_FLAG):\n        return 'fake'\n    return 'real'\n"),
    "pkg/uses_attr.py": ("import os\nfrom pkg import flagnames\n\n\ndef g():\n"
                         "    if flagnames.OTHER in os.environ:\n        return 1\n    return 2\n"),
    "pkg/uses_local.py": ('import os\nFLAG = "CTF_TESTING"\n\n\ndef h():\n'
                          "    if os.environ[FLAG]:\n        return 1\n    return 2\n"),
    "pkg/plain.py": "import os\n\n\ndef k():\n    if os.environ.get(NOT_A_FLAG):\n        return 1\n    return 2\n",
    "tests/test_consts.py": (
        'from pkg import uses_import, uses_attr, uses_local\nOFF = "CTF_TESTING"\n\n\n'
        "def test_f(monkeypatch):\n    monkeypatch.delenv(OFF, raising=False)\n    assert uses_import.f() == 'real'\n\n\n"
        "def test_g(monkeypatch):\n    monkeypatch.delenv('PYTEST_CURRENT_TEST', raising=False)\n    assert uses_attr.g() == 2\n\n\n"
        "def test_h_on():\n    assert uses_local.h() == 1\n"),
}


def test_flags_written_as_module_constants_are_resolved(tmp_path):
    root = tree(tmp_path, CONSTS)
    res = fakes.audit(root, source_dirs=("pkg",))
    got = {b.function: (b.path, b.flags, b.status) for b in res.branches}
    assert got == {"f": ("pkg/uses_import.py", ("CTF_TESTING",), "COVERED"),      # imported constant; test's own constant
                   "g": ("pkg/uses_attr.py", ("PYTEST_CURRENT_TEST",), "COVERED"),  # mod.CONST, annotated
                   "h": ("pkg/uses_local.py", ("CTF_TESTING",), "MISSING")}         # local constant; no flag-off test
    assert _by_fn(res)["f"].evidence == ["tests/test_consts.py::test_f"]


def test_module_constants_reads_only_module_level_flag_strings():
    import ast
    tree_ = ast.parse('A = "CTF_TESTING"\nB: str = "CTF_OFFLINE_AUDIT"\nC = "PATH"\nD = E = "PYTEST_CURRENT_TEST"\n'
                      'x.y = "CTF_TESTING"\n\ndef f():\n    L = "CTF_TESTING"\n')
    assert fakes.module_constants(tree_) == {"A": "CTF_TESTING", "B": "CTF_OFFLINE_AUDIT",
                                             "D": "PYTEST_CURRENT_TEST", "E": "PYTEST_CURRENT_TEST"}
    assert fakes.module_constants(tree_, ("PATH",)) == {"C": "PATH"}
    fl = fakes.Flags(fakes.FLAGS, {"A": "CTF_TESTING"})
    assert fl.of(ast.parse("A").body[0].value) == "CTF_TESTING"
    assert fl.of(ast.parse("m.A").body[0].value) == "CTF_TESTING"
    assert fl.of(ast.parse("m.n.A").body[0].value) is None              # only a module's own attribute
    assert fl.of(ast.parse("B").body[0].value) is None
    assert fl.of(ast.parse("'CTF_OFFLINE_AUDIT'").body[0].value) == "CTF_OFFLINE_AUDIT"
    assert fl.of(ast.parse("'PATH'").body[0].value) is None
