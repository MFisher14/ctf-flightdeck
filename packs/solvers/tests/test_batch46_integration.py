"""Batch-46 integration fix.

B-217: `script_analysis.lang_table` landed with no `[[routes]]`, which the route lint rejects for an
engine that is not retired (tests/test_engines_lint.py). It now has one keyword route, one priority
below `script_analysis.blind_reader`: a brief that names a carrier language or a composite descriptor
tag lists the lang_table CLI. These tests fail if the route goes away, starts fronting the
language-blind reader, fires on a brief that names neither, or points at a CLI that cannot read the
file the dispatch brief hands it.

Offline and synthetic: no network, no challenge files; the carrier text is written by the test.
"""
import subprocess
import sys

from ctf import paths, triage
from ctf.engines import lint, manifest

ENGINE = "solvers/script-analysis/lang_table.py"
ENGINE_ID = "script_analysis.lang_table"
BLIND_ID = "script_analysis.blind_reader"


def _routes(category, description):
    return triage.suggest(category, description)["routes"]


def test_manifest_has_the_one_keyword_route_and_lints_clean():
    root = paths.repo_root()
    m = manifest.load(root / "solvers/script-analysis/lang_table.manifest.toml")
    assert m.status == "active" and len(m.routes) == 1
    route = m.routes[0]
    assert not route.category and not route.files and route.priority == 57
    assert set(route.keywords) == {"next_language", "carrier language", "composite tag",
                                   "composite label", "composite descriptor"}
    about_it = [f.line() for f in lint.lint(baseline=lint.load_baseline()) if ENGINE_ID in f.line()]
    assert about_it == []                                      # no no-route, no route-conflict


def test_each_keyword_makes_triage_name_the_engine():
    for brief in ("the v=3 descriptor carries next_language=lua",
                  "the marker sits in a comment of the carrier language",
                  "the container has a composite tag GZ+B64",
                  "decode the composite label of the block",
                  "a composite descriptor nobody has seen"):
        hits = [r for r in _routes("script", brief) if r["id"] == ENGINE_ID]
        assert len(hits) == 1, brief
        assert hits[0]["engine"] == ENGINE and hits[0]["priority"] == 57 and "keyword" in hits[0]["reason"]


def test_the_language_blind_reader_still_comes_first():
    rs = _routes("script", "the reconstructed plan is under a composite tag")
    ids = [r["id"] for r in rs]
    assert BLIND_ID in ids and ENGINE_ID in ids
    assert ids.index(BLIND_ID) < ids.index(ENGINE_ID)


def test_not_suggested_for_a_brief_that_names_neither():
    for brief in ("a powershell loader with a base64 blob", "the composite of two images", ""):
        assert ENGINE_ID not in [r["id"] for r in _routes("script", brief)], brief


def test_the_routed_cli_reads_a_carrier_file(tmp_path):
    """The dispatch brief runs `<engine> <file>`: that line must give the carrier, not a usage error."""
    src = tmp_path / "carrier.py"
    src.write_text('print("HUNTRESS_ANALYSIS_V1:B64-DECOYPAYLOAD")\n'
                   '# HUNTRESS_ANALYSIS_V2:GZ-Qm9keQ==\n', encoding="utf-8")
    out = subprocess.run([sys.executable, "-I", str(paths.repo_root() / ENGINE), str(src)],
                         capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    rows = [line.split("\t") for line in out.stdout.splitlines()]
    assert len(rows) == 1                                      # the marker inside the string is a decoy
    assert rows[0][1] == "GZ" and rows[0][2] == "['b64', 'inflate']" and rows[0][3] == "Qm9keQ=="
