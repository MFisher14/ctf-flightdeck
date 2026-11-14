"""The machine-checked coverage matrix docs/coverage/ENGINES.md (B-186)."""
from __future__ import annotations

from pathlib import Path

from ctf.engines import coverage as C


def _w(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _repo(root: Path) -> Path:
    _w(root, "solvers/common/shared.py", "def solve(d, p): pass\n")
    _w(root, "solvers/web/shared.py", "def solve(d, p): pass\n")
    _w(root, "solvers/web/lone.py", "def solve(d, p): pass\n")
    for lane, name, caps, routes in (("common", "shared", '["executes"]', '[[routes]]\nkeywords = ["s1"]\n'),
                                     ("web", "shared", '["plan"]', '[[routes]]\ncategory = ["web"]\npriority = 40\n'),
                                     ("web", "lone", '["library"]', "")):
        _w(root, f"solvers/{lane}/{name}.manifest.toml",
           f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "solvers.{lane}.{name}:solve"\n'
           f"capabilities = {caps}\n{routes}")
    _w(root, "tests/test_a.py", "import shared\n")                      # flat: resolves to web/shared
    _w(root, "tests/test_b.py", "p = 'solvers/common/shared.py'\n")     # by path
    _w(root, "tests/test_c.py", "from solvers.web import lone\n")       # does not resolve to a module path
    return root


def test_flat_imports_are_credited_to_the_file_the_engine_sys_path_picks(tmp_path):
    refs = C.tests_referencing(_repo(tmp_path))
    assert refs[tmp_path / "solvers/web/shared.py"] == {"tests/test_a.py"}
    assert refs[tmp_path / "solvers/common/shared.py"] == {"tests/test_b.py"}


def test_render_counts_classes_routes_and_tests(tmp_path):
    text = C.render(_repo(tmp_path))
    assert "| common | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |" in text
    assert "| web | 2 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 1 |" in text
    assert "| **total** | **3** |" in text
    assert "| `web.lone` | library | active | medium | UNROUTED |  | 0 |" in text
    assert "| `common.shared` | executes | active | medium | any |  | 1 |" in text


def test_matrix_goes_stale_when_a_manifest_changes_and_write_fixes_it(tmp_path):
    root = _repo(tmp_path)
    C.write(root)
    assert not C.is_stale(root)
    _w(root, "solvers/web/lone.manifest.toml",
       'id = "web.lone"\nlane = "web"\nentry = "solvers.web.lone:solve"\ncapabilities = ["library"]\n'
       '[[routes]]\nkeywords = ["lonely"]\n')
    assert C.is_stale(root)
    C.write(root)
    assert not C.is_stale(root)


def test_unmanifested_engines_are_listed(tmp_path):
    root = _repo(tmp_path)
    _w(root, "solvers/web/newbie.py", "def solve(d, p): pass\n")
    assert "- `solvers/web/newbie.py`" in C.render(root)


def test_committed_matrix_is_current():
    """docs/coverage/ENGINES.md must equal a fresh render: regenerate with
    `python -m ctf engines coverage --write` after adding or changing an engine or its tests."""
    assert not C.is_stale(), "docs/coverage/ENGINES.md is stale: run `python -m ctf engines coverage --write`"
