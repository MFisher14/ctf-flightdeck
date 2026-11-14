"""File routes inferred from the formats an engine's code tests for (R-10)."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from ctf.engines import fileroutes as F
from ctf.engines import lint as L
from ctf.engines import manifest as M
from ctf.engines import router


def _eng(root: Path, lane: str, name: str, code: str, body: str = ""):
    d = root / "solvers" / lane
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.py").write_text(textwrap.dedent(code), encoding="utf-8")
    (d / f"{name}.manifest.toml").write_text(
        f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "solvers.{lane}.{name}:solve"\n' + body, encoding="utf-8")


def test_distinctive_drops_generic_exts_short_and_container_magic():
    got = F.distinctive({".dex", ".json", ".txt", ".zip", ".PCAPNG"},
                        {"magic:0x6465780a", "magic:PK", "magic:0x504b0304", "magic:0x1f8b08", "magic:MZ",
                         "magic:0xefbbbf", "magic:<?xml", "magic:%PDF-", "magic:   "})
    assert got == ["ext:.dex", "ext:.pcapng", "magic:%PDF-", "magic:0x6465780a"]
    # MIN_MAGIC_BYTES is inclusive: a distinctive 3-byte magic is kept, a 2-byte one is not
    assert F.MIN_MAGIC_BYTES == 3
    assert F.distinctive(set(), {"magic:0x000102", "magic:0x0001"}) == ["magic:0x000102"]
    assert F.distinctive({".pcapng"}, set()) == ["ext:.pcapng"]
    assert F.distinctive(set(), set()) == []


def test_key_certificate_and_env_files_are_generic():
    """Any challenge may ship a PEM, a key or an .env: such a file names no engine (R-10 round 1)."""
    assert F.distinctive({".pem", ".key", ".env", ".p12", ".pfx", ".crt", ".cer", ".der", ".pub"}, set()) == []
    assert F.distinctive({".pem", ".node"}, {"magic:rem ", "magic:@echo"}) == ["ext:.node", "magic:@echo"]


def test_assign_gives_engines_sharing_a_matcher_distinct_priorities_specific_first():
    got, skipped = F.assign([("wide", ["ext:.dex", "ext:.so"]), ("narrow", ["ext:.dex"]), ("other", ["ext:.wasm"])],
                            taken={"ext:.dex": {30}})
    assert skipped == []
    assert got == {"narrow": 29, "other": 30, "wide": 28}       # 30 taken on .dex; narrow chooses before wide


def test_assign_skips_with_a_reason_when_no_priority_is_free():
    got, skipped = F.assign([("a", ["ext:.dex"])], taken={"ext:.dex": set(range(1, 31))})
    assert got == {} and "no free priority" in skipped[0] and "a:" in skipped[0]


def test_plan_routes_only_unrouted_live_engines_with_an_obvious_input(tmp_path):
    _eng(tmp_path, "x", "dexer", '''
        def solve(d, p):
            return d.suffix == ".dex" or open(d, "rb").read(4).startswith(b"dex\\n")
    ''')
    _eng(tmp_path, "x", "routed", 'def solve(d, p):\n    return d.suffix == ".wasm"\n',
         '[[routes]]\nkeywords = ["wasm"]\npriority = 60\n')
    _eng(tmp_path, "x", "old", 'def solve(d, p):\n    return d.suffix == ".wasm"\n', 'status = "retired"\n')
    _eng(tmp_path, "x", "texty", 'def solve(d, p):\n    return d.suffix == ".txt"\n')
    exts = ", ".join(f'".e{i}"' for i in range(F.MAX_MATCHERS + 1))
    _eng(tmp_path, "x", "dispatch", f"def solve(d, p):\n    return d.name.endswith(({exts}))\n")
    planned, skipped = F.plan(tmp_path)
    assert [(p.manifest.id, p.files, p.priority) for p in planned] == [
        ("x.dexer", ["ext:.dex", "magic:0x6465780a"], F.BASE_PRIORITY)]
    assert len(skipped) == 1 and skipped[0].startswith("x.dispatch:") and "dispatcher" in skipped[0]


def test_apply_appends_a_valid_route_that_routes_and_lints_clean(tmp_path):
    _eng(tmp_path, "x", "dexer", 'def solve(d, p):\n    return d.suffix == ".dex"\n')
    side = tmp_path / "solvers/x/dexer.manifest.toml"
    before = side.read_text()
    planned, _ = F.plan(tmp_path)
    assert F.apply(planned) == 1
    after = side.read_text()
    assert after.startswith(before) and "--file-routes" in after       # appended, original kept
    (r,) = M.load(side).routes
    assert r.files == ("ext:.dex",) and r.priority == F.BASE_PRIORITY and not r.category and not r.keywords
    files = tmp_path / "files"
    files.mkdir()
    (files / "classes.dex").write_bytes(b"x")
    assert [h.manifest.id for h in router.route("misc", "", files, root=tmp_path)] == ["x.dexer"]
    assert [f for f in L.lint(tmp_path, baseline=set(), known_categories=set()) if f.severity == "error"] == []
    assert F.plan(tmp_path) == ([], [])                                  # routed now: nothing more to add


def test_apply_refuses_when_the_manifest_gained_a_route_meanwhile(tmp_path):
    _eng(tmp_path, "x", "dexer", 'def solve(d, p):\n    return d.suffix == ".dex"\n')
    planned, _ = F.plan(tmp_path)
    side = tmp_path / "solvers/x/dexer.manifest.toml"
    side.write_text(side.read_text() + '[[routes]]\nkeywords = ["dex"]\npriority = 60\n', encoding="utf-8")
    text = side.read_text()
    with pytest.raises(RuntimeError, match="has a route now"):
        F.apply(planned)
    assert side.read_text() == text
