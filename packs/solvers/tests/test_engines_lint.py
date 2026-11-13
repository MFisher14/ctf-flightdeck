"""Route lint (B-186): conflicts, missing entries, unrouted engines, baseline ratchet."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf.engines import lint as L

CATS = {"crypto", "web", "misc", "forensics"}


def _engine(root: Path, lane: str, name: str, manifest_body: str | None, code: str = "def solve(d, p):\n    pass\n"):
    d = root / "solvers" / lane
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.py").write_text(code, encoding="utf-8")
    if manifest_body is not None:
        head = f'id = "{lane.replace("-", "_")}.{name}"\nlane = "{lane}"\nentry = "solvers.{lane}.{name}:solve"\n'
        (d / f"{name}.manifest.toml").write_text(head + manifest_body, encoding="utf-8")


def _codes(findings, severity="error"):
    return sorted((f.code, f.subject) for f in findings if f.severity == severity)


def _lint(root, baseline=None):
    return L.lint(root, baseline=set() if baseline is None else baseline, known_categories=CATS)


def test_clean_tree_has_no_findings(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\ncategory = ["crypto"]\nkeywords = ["rsa"]\npriority = 60\n')
    _engine(tmp_path, "crypto", "b", '[[routes]]\ncategory = ["crypto"]\nkeywords = ["ecc"]\n')
    assert _lint(tmp_path) == []


def test_two_engines_one_keyword_without_priority_conflict(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\nkeywords = ["rsa"]\n')
    _engine(tmp_path, "crypto", "b", '[[routes]]\nkeywords = ["rsa", "ecc"]\npriority = 70\n')
    f = [x for x in _lint(tmp_path) if x.code == "route-conflict"]
    assert len(f) == 1 and f[0].severity == "error" and f[0].subject == "crypto.a~crypto.b"
    assert "priority missing" in f[0].message


def test_equal_priorities_conflict_distinct_priorities_do_not(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\nkeywords = ["rsa"]\npriority = 60\n')
    _engine(tmp_path, "crypto", "b", '[[routes]]\nkeywords = ["rsa"]\npriority = 60\n')
    assert ("route-conflict", "crypto.a~crypto.b") in _codes(_lint(tmp_path))
    (tmp_path / "solvers/crypto/b.manifest.toml").write_text(
        'id = "crypto.b"\nlane = "crypto"\nentry = "solvers.crypto.b:solve"\n'
        '[[routes]]\nkeywords = ["rsa"]\npriority = 61\n', encoding="utf-8")
    assert _lint(tmp_path) == []


def test_bare_category_routes_conflict_only_in_the_same_category(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\ncategory = ["crypto"]\npriority = 40\n')
    _engine(tmp_path, "web", "b", '[[routes]]\ncategory = ["web"]\npriority = 40\n')
    assert _lint(tmp_path) == []
    _engine(tmp_path, "crypto", "c", '[[routes]]\ncategory = ["crypto", "misc"]\npriority = 40\n')
    assert _codes(_lint(tmp_path)) == [("route-conflict", "crypto.a~crypto.c")]


def test_keyword_in_disjoint_categories_is_not_a_conflict_but_any_category_overlaps(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\ncategory = ["crypto"]\nkeywords = ["jwt"]\n')
    _engine(tmp_path, "web", "b", '[[routes]]\ncategory = ["web"]\nkeywords = ["jwt"]\n')
    assert _lint(tmp_path) == []
    _engine(tmp_path, "misc", "c", '[[routes]]\nkeywords = ["jwt"]\n')       # any category
    assert _codes(_lint(tmp_path)) == [("route-conflict", "crypto.a~misc.c"), ("route-conflict", "misc.c~web.b")]


def test_one_engine_may_repeat_its_own_keyword(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\nkeywords = ["rsa"]\n\n[[routes]]\ncategory = ["crypto"]\nkeywords = ["rsa"]\n')
    assert _lint(tmp_path) == []


def test_retired_engines_neither_need_routes_nor_conflict(tmp_path):
    _engine(tmp_path, "crypto", "a", 'status = "retired"\n[[routes]]\nkeywords = ["rsa"]\n')
    _engine(tmp_path, "crypto", "b", '[[routes]]\nkeywords = ["rsa"]\n')
    _engine(tmp_path, "crypto", "c", 'status = "retired"\n')
    assert _lint(tmp_path) == []


def test_no_route_is_an_error_and_baseline_makes_it_known(tmp_path):
    _engine(tmp_path, "crypto", "a", "")
    assert _codes(_lint(tmp_path)) == [("no-route", "crypto.a")]
    found = _lint(tmp_path, baseline={("no-route", "crypto.a")})
    assert _codes(found) == [] and _codes(found, "known") == [("no-route", "crypto.a")]


def test_stale_baseline_lines_are_detected(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\nkeywords = ["rsa"]\n')
    base = {("no-route", "crypto.a"), ("no-route", "crypto.gone")}
    assert L.stale_baseline(_lint(tmp_path, base), base) == base


def test_baseline_file_round_trip_and_rejects_other_codes(tmp_path):
    L.write_baseline({("no-route", "a.b"), ("duplicate-basename", "x")}, tmp_path)
    assert L.load_baseline(tmp_path) == {("no-route", "a.b"), ("duplicate-basename", "x")}
    L.baseline_path(tmp_path).write_text("route-conflict a~b\n", encoding="utf-8")
    with pytest.raises(ValueError, match="lint-baseline.txt:1"):
        L.load_baseline(tmp_path)


def test_missing_entries(tmp_path):
    _engine(tmp_path, "crypto", "nofunc", '[[routes]]\nkeywords = ["a1"]\n', code="def other():\n    pass\n")
    d = tmp_path / "solvers/crypto"
    (d / "badmod.py").write_text("def solve():\n    pass\n", encoding="utf-8")
    (d / "badmod.manifest.toml").write_text('id = "crypto.badmod"\nlane = "crypto"\nentry = "solvers.crypto.gone:solve"\n'
                                            '[[routes]]\nkeywords = ["a2"]\n', encoding="utf-8")
    (d / "cli.py").write_text("print(1)\nif __name__ == '__main__':\n    pass\n", encoding="utf-8")
    (d / "cli.manifest.toml").write_text('id = "crypto.cli"\nlane = "crypto"\nentry = "cli:python solvers/crypto/nope.py"\n'
                                         '[[routes]]\nkeywords = ["a3"]\n', encoding="utf-8")
    got = _codes(_lint(tmp_path))
    assert got == [("missing-entry", "crypto.badmod"), ("missing-entry", "crypto.cli"), ("missing-entry", "crypto.nofunc")]


def test_entry_may_name_an_imported_or_assigned_callable(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\nkeywords = ["x"]\n', code="from math import gcd as solve\n")
    assert _lint(tmp_path) == []


def test_unmanifested_engine_orphan_manifest_and_data_modules(tmp_path):
    _engine(tmp_path, "crypto", "bare", None)                                         # engine, no sidecar
    _engine(tmp_path, "crypto", "table", None, code="TABLE = {1: 2}\n")               # data only: not an engine
    _engine(tmp_path, "crypto", "_helper", None)                                      # private helper
    d = tmp_path / "solvers/crypto"
    (d / "ghost.manifest.toml").write_text('id = "crypto.ghost"\nlane = "crypto"\nentry = "cli:python solvers/crypto/bare.py"\n'
                                           '[[routes]]\nkeywords = ["g"]\n', encoding="utf-8")
    got = _codes(_lint(tmp_path))
    assert ("unmanifested-engine", "solvers/crypto/bare.py") in got
    assert ("orphan-manifest", "crypto.ghost") in got
    assert not any("table" in s or "_helper" in s for _, s in got)


def test_match_all_route_and_schema_errors(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\npriority = 10\n')
    d = tmp_path / "solvers/crypto"
    (d / "b.py").write_text("def solve():\n    pass\n", encoding="utf-8")
    (d / "b.manifest.toml").write_text('id = "crypto.b"\n', encoding="utf-8")
    got = _codes(_lint(tmp_path))
    assert ("match-all-route", "crypto.a") in got
    assert ("schema", "solvers/crypto/b.manifest.toml") in got


def test_duplicate_basenames_name_the_winner(tmp_path):
    _engine(tmp_path, "common", "dup", '[[routes]]\nkeywords = ["d1"]\n')
    _engine(tmp_path, "web", "dup", '[[routes]]\nkeywords = ["d2"]\n')
    f = [x for x in _lint(tmp_path) if x.code == "duplicate-basename"]
    assert len(f) == 1 and f[0].subject == "dup"
    assert "gets solvers/web/dup.py" in f[0].message        # web precedes common on the engine sys.path


def _dup_doc(root: Path, body: str) -> None:
    p = root / L.DUPLICATES_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


DUP_DOC = ('[[duplicate]]\nbasename = "dup"\nfiles = ["solvers/web/dup.py", "solvers/common/dup.py"]\n'
           'flat_import = "solvers/web/dup.py"\nreason = "reader and face"\n')


def test_a_documented_duplicate_is_accepted_only_while_the_doc_matches(tmp_path):
    _engine(tmp_path, "common", "dup", '[[routes]]\nkeywords = ["d1"]\n')
    _engine(tmp_path, "web", "dup", '[[routes]]\nkeywords = ["d2"]\n')
    _dup_doc(tmp_path, DUP_DOC)
    assert _codes(_lint(tmp_path)) == []
    _engine(tmp_path, "warmups", "dup", '[[routes]]\nkeywords = ["d3"]\n')       # a third copy, and it wins
    [f] = [x for x in _lint(tmp_path) if x.code == "duplicate-basename"]
    assert f.severity == "error" and "out of date" in f.message and "solvers/warmups/dup.py" in f.message


def test_a_documented_duplicate_with_a_wrong_flat_import_is_out_of_date(tmp_path):
    """Same files, but the doc names the losing file as the flat-import winner."""
    _engine(tmp_path, "common", "dup", '[[routes]]\nkeywords = ["d1"]\n')
    _engine(tmp_path, "web", "dup", '[[routes]]\nkeywords = ["d2"]\n')
    _dup_doc(tmp_path, DUP_DOC.replace('flat_import = "solvers/web/dup.py"', 'flat_import = "solvers/common/dup.py"'))
    [f] = [x for x in _lint(tmp_path) if x.code == "duplicate-basename"]
    assert f.severity == "error" and "out of date" in f.message
    assert "flat import solvers/common/dup.py" in f.message and "flat import solvers/web/dup.py" in f.message


def test_a_doc_entry_for_a_name_no_longer_shared_is_stale(tmp_path):
    _engine(tmp_path, "common", "dup", '[[routes]]\nkeywords = ["d1"]\n')
    _dup_doc(tmp_path, DUP_DOC)
    assert _codes(_lint(tmp_path)) == [("stale-duplicate-doc", "dup")]


@pytest.mark.parametrize("body, why", [
    ('[[duplicate]]\nbasename = "dup"\n', "exactly the keys"),
    (DUP_DOC.replace('files = ["solvers/web/dup.py", "solvers/common/dup.py"]', 'files = ["solvers/web/dup.py"]'),
     "at least two"),
    (DUP_DOC.replace('reason = "reader and face"', 'reason = " "'), "reason"),
    (DUP_DOC + DUP_DOC, "documented twice"),
    ("[other]\nx = 1\n", "unknown key"),
    ("[[duplicate]\n", "not valid TOML"),
])
def test_a_malformed_duplicate_doc_is_a_schema_error(tmp_path, body, why):
    _engine(tmp_path, "common", "dup", '[[routes]]\nkeywords = ["d1"]\n')
    _engine(tmp_path, "web", "dup", '[[routes]]\nkeywords = ["d2"]\n')
    _dup_doc(tmp_path, body)
    found = [f for f in _lint(tmp_path) if f.code == "schema"]
    assert len(found) == 1 and found[0].subject == L.DUPLICATES_REL and why in found[0].message
    assert ("duplicate-basename", "dup") in _codes(_lint(tmp_path))          # undocumented again


def test_a_flat_import_of_a_shared_name_is_ambiguous_outside_the_winning_folder(tmp_path):
    _engine(tmp_path, "common", "dup", '[[routes]]\nkeywords = ["d1"]\n')
    _engine(tmp_path, "web", "dup", '[[routes]]\nkeywords = ["d2"]\n')
    _dup_doc(tmp_path, DUP_DOC)
    _engine(tmp_path, "common", "user", '[[routes]]\nkeywords = ["u"]\n',
            code="import json\ntry:\n    import dup as D\nexcept ImportError:\n    D = None\ndef solve(d, p):\n    pass\n")
    _engine(tmp_path, "web", "fine", '[[routes]]\nkeywords = ["f"]\n',
            code="from dup import x\ndef solve(d, p):\n    pass\n")
    _engine(tmp_path, "common", "byname", '[[routes]]\nkeywords = ["b"]\n',
            code='from _shadowed import common_module\nD = common_module("dup")  # import dup\ndef solve(d, p):\n'
                 '    pass\n')
    (tmp_path / "solvers/common/test_lane.py").write_text("from dup import y\n", encoding="utf-8")
    errs = _codes(_lint(tmp_path))
    assert errs == [("ambiguous-import", "solvers/common/test_lane.py:dup"),
                    ("ambiguous-import", "solvers/common/user.py:dup")]
    [f] = [x for x in _lint(tmp_path) if x.subject == "solvers/common/user.py:dup"]
    assert "line 3" in f.message and "resolves to solvers/web/dup.py" in f.message
    known = _lint(tmp_path, baseline={("ambiguous-import", "solvers/common/user.py:dup")})
    assert _codes(known, "known") == [("ambiguous-import", "solvers/common/user.py:dup")]


def test_warnings_do_not_count_as_errors(tmp_path):
    _engine(tmp_path, "crypto", "a", '[[routes]]\ncategory = ["astrology"]\n')
    d = tmp_path / "solvers/crypto"
    (d / "t.py").write_text("def solve():\n    pass\n", encoding="utf-8")
    (d / "t.manifest.toml").write_text('id = "crypto.t"\nlane = "crypto"\nentry = "cli:hashcat -m 0"\n'
                                       '[[routes]]\nkeywords = ["hashcat"]\n', encoding="utf-8")
    found = _lint(tmp_path)
    assert _codes(found) == []
    assert _codes(found, "warning") == [("cli-tool-undeclared", "crypto.t"), ("unknown-category", "crypto.a")]


def test_repo_lints_clean_against_its_baseline():
    """The real tree: no lint error outside the baseline, and no stale baseline line."""
    baseline = L.load_baseline()
    findings = L.lint(baseline=baseline)
    errors = [f.line() for f in findings if f.severity == "error"]
    assert errors == [], "\n".join(errors[:40])
    stale = L.stale_baseline(findings, baseline)
    assert not stale, f"baseline lines that no longer fire (run `python -m ctf engines lint --shrink-baseline`): {sorted(stale)[:20]}"
