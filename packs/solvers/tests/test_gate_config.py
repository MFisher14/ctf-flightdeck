"""B-195: the gate config (tests/gate.toml) and its glob rules."""
from __future__ import annotations

import pytest

from ctf import paths
from ctf.gate import GateError, config

GOOD = """\
version = 1
tests = ["tests/test_*.py"]
roots = [""]
global = ["pytest.ini"]
inert = ["docs/**"]
[wall]
base_seconds = 30
max_scale = 2.5
"""


@pytest.mark.parametrize("pattern,path,expected", [
    ("tests/test_*.py", "tests/test_a.py", True),
    ("tests/test_*.py", "tests/sub/test_a.py", False),          # * stays inside one segment
    ("tests/**/test_*.py", "tests/sub/deep/test_a.py", True),
    ("tests/**/test_*.py", "tests/test_a.py", True),            # **/ matches zero folders
    ("docs/**", "docs/a/b.md", True),
    ("docs/**", "docsx/a.md", False),
    ("*.md", "deep/folder/README.md", True),                    # no slash: base name anywhere
    ("*.md", "deep/folder/README.mdx", False),
    ("a?c.py", "abc.py", True),
    ("a?c.py", "a/c.py", False),                                # ? never matches a slash
    ("lib/x.py", "other/lib/x.py", False),                      # a slashed pattern is anchored
])
def test_glob_rules(pattern, path, expected):
    assert config.matches(path, [pattern]) is expected


def _write(tmp_path, text):
    p = tmp_path / "gate.toml"
    p.write_text(text)
    return p


def test_loads_a_valid_config(tmp_path):
    cfg = config.load(tmp_path, _write(tmp_path, GOOD + '[lanes]\nweb = ["solvers/web/**"]\n'
                                                       '[[scan]]\nwhy = "walks"\ntests = ["tests/test_s.py"]\n'
                                                       'inputs = ["**/*.py"]\n'))
    assert cfg.wall_base == 30.0 and cfg.wall_max_scale == 2.5
    assert cfg.lanes == {"web": ("solvers/web/**",)}
    assert cfg.scan[0].tests == ("tests/test_s.py",) and cfg.scan[0].why == "walks"
    assert cfg.is_test("tests/test_x.py") and not cfg.is_test("tests/x.py")
    assert cfg.is_global("pytest.ini") and cfg.is_inert("docs/a.md") and not cfg.is_inert("ctf/a.py")
    assert cfg.basename_max == 8                                 # the default


@pytest.mark.parametrize("text,needle", [
    (GOOD.replace("version = 1", "version = 2"), "version must be 1"),
    (GOOD.replace("[wall]", "tset = []\n[wall]"), "unknown key"),
    (GOOD.replace('roots = [""]\n', ""), "missing required key 'roots'"),
    (GOOD.replace("max_scale = 2.5", "max_scale = 0.5"), "max_scale must be at least 1"),
    (GOOD.replace("base_seconds = 30", "base_seconds = -1"), "base_seconds must be a positive number"),
    (GOOD.replace("base_seconds = 30\n", ""), "[wall] needs exactly"),
    (GOOD.replace('inert = ["docs/**"]', 'inert = ["/abs/**"]'), "must be repo-relative"),
    (GOOD.replace('inert = ["docs/**"]', 'inert = ["../up"]'), "must be repo-relative"),
    (GOOD.replace("[wall]", 'env = ["HOME"]\n[wall]'), "not a CTF_ name"),
    (GOOD + '[[scan]]\nwhy = ""\ntests = ["a"]\ninputs = ["b"]\n', "'why' must say"),
    (GOOD + '[[scan]]\nwhy = "w"\ntests = []\ninputs = ["b"]\n', "must be non-empty"),
    (GOOD + '[lanes]\n"Web Lane" = ["x/**"]\n', "bad lane name"),
    (GOOD + '[lanes]\nweb = []\n', "has no globs"),
    ("version = 1\ntests = [", "not valid TOML"),
])
def test_bad_configs_fail_loudly(tmp_path, text, needle):
    with pytest.raises(GateError) as e:
        config.load(tmp_path, _write(tmp_path, text))
    assert needle in str(e.value)


def test_missing_config_names_the_path(tmp_path):
    with pytest.raises(GateError, match="gate config not found"):
        config.load(tmp_path)


def test_the_repo_config_loads_and_names_every_lane_folder():
    root = paths.repo_root()
    cfg = config.load(root)
    assert cfg.path == root / "tests" / "gate.toml"
    assert cfg.is_test("tests/test_gate_config.py") and cfg.is_test("tests/real/test_real_web.py")
    assert cfg.is_global("conftest.py") and cfg.is_global("tests/known_failures.toml")
    for lane in ("web", "binary", "toolkits", "core-a-e"):
        assert lane in cfg.lanes
    # each import root the root conftest.py puts on sys.path is a gate root too
    conftest = (root / "conftest.py").read_text()
    for r in cfg.roots:
        if r and r != "tests":
            assert f'"{r}"' in conftest, r
