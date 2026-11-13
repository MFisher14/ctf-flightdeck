"""`python -m ctf engines generate` writes the manifests and every file generated from them (R-10)."""
from __future__ import annotations

import argparse

import pytest

from ctf import paths
from ctf.cli import engines as cli
from ctf.engines import derived, manifest as M


def _args(*argv: str) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    return p.parse_args(list(argv))


@pytest.fixture
def root(tmp_path, monkeypatch):
    d = tmp_path / "solvers" / "x"
    d.mkdir(parents=True)
    (d / "kept.py").write_text('"""Kept engine."""\ndef solve(d, p): pass\n', encoding="utf-8")
    (d / "kept.manifest.toml").write_text(
        'id = "x.kept"\nlane = "x"\nentry = "solvers.x.kept:solve"\ncapabilities = ["analysis"]\n'
        '[[routes]]\ncategory = ["crypto"]\npriority = 40\n', encoding="utf-8")
    (d / "dexer.py").write_text('"""Dex reader."""\ndef solve(d, p):\n    return d.suffix == ".dex"\n',
                                encoding="utf-8")
    monkeypatch.setattr(paths, "repo_root", lambda: tmp_path)
    return tmp_path


def test_check_reports_missing_manifests_and_stale_files_and_writes_nothing(root, capsys):
    assert cli.run(_args("generate", "--check")) == 1
    out = capsys.readouterr().out
    assert "missing manifest: " in out and "dexer.manifest.toml" in out
    for rel, _, _ in derived.DERIVED:
        assert f"stale: {rel}" in out
        assert not (root / rel).exists()
    assert not (root / "solvers/x/dexer.manifest.toml").exists()


def test_generate_writes_manifests_then_derived_files_and_check_passes(root, capsys):
    assert cli.run(_args("generate")) == 0
    err = capsys.readouterr().err
    assert "wrote 1 manifest(s)" in err
    assert sorted(derived.stale(root)) == []
    for rel, _, _ in derived.DERIVED:
        assert f"regenerated {rel}" in err
    (r,) = M.load(root / "solvers/x/dexer.manifest.toml").routes          # new engine: inferred file route
    assert r.files == ("ext:.dex",)
    table = (root / "ctf/engines/route_table.jsonl").read_text()
    assert '"id": "x.dexer"' in table and '"id": "x.kept"' in table
    assert "x.dexer" in (root / "docs/CAPABILITIES.md").read_text()
    assert cli.run(_args("generate", "--check")) == 0
    # a manifest edit makes the derived files stale until the next generate
    side = root / "solvers/x/kept.manifest.toml"
    side.write_text(side.read_text().replace("priority = 40", "priority = 45"), encoding="utf-8")
    assert cli.run(_args("generate", "--check")) == 1
    assert "stale: ctf/engines/route_table.jsonl" in capsys.readouterr().out
    assert derived.write_all(root) == ["ctf/engines/route_table.jsonl", "docs/CAPABILITIES.md"]
    assert derived.stale(root) == []


def test_file_routes_flag_appends_to_an_unrouted_existing_manifest(root, capsys):
    side = root / "solvers/x/dexer.manifest.toml"
    side.write_text('id = "x.dexer"\nlane = "x"\nentry = "solvers.x.dexer:solve"\n', encoding="utf-8")
    assert cli.run(_args("generate")) == 0
    assert M.load(side).routes == ()                     # without the flag an existing manifest is untouched
    assert cli.run(_args("generate", "--check", "--file-routes")) == 1
    assert "file route: x.dexer ext:.dex priority 30" in capsys.readouterr().out
    assert cli.run(_args("generate", "--file-routes")) == 0
    assert M.load(side).routes[0].files == ("ext:.dex",)
    assert cli.run(_args("generate", "--check", "--file-routes")) == 0


def test_triage_without_a_route_table_fails_loudly_while_engines_route_still_reads_manifests(root, capsys):
    from ctf import triage
    from ctf.engines.routetable import RouteTableError
    with pytest.raises(RouteTableError, match="route table is missing"):
        triage.suggest("crypto")
    assert cli.run(_args("route", "crypto")) == 0
    assert "x.kept" in capsys.readouterr().out
