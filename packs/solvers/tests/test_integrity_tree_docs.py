"""B-196: doc lint as a gate. Docs are inert to the gate's import graph; tests/gate.toml's [[scan]] rule maps
every maintained doc (and the command folder) to this file, so a doc edit that names a missing path, link
or `python -m ctf` command fails here instead of waiting for a hand sweep."""
from __future__ import annotations

from ctf import paths
from ctf.gate import config
from ctf.integrity import doclint

ROOT = paths.repo_root()


def test_the_maintained_docs_name_only_what_exists():
    res = doclint.audit(ROOT)
    assert [f.text() for f in res.new] == []
    assert res.stale == []


def test_a_doc_edit_selects_this_file():
    cfg = config.load(ROOT)
    rules = [r for r in cfg.scan if config.matches("tests/test_integrity_tree_docs.py", r.tests)]
    assert rules, "the doc lint lost its [[scan]] rule: doc edits would select nothing"
    for doc in ("docs/BUILDING.md", "docs/toolkits/web.md", "README.md", "CLAUDE.md"):
        assert any(config.matches(doc, r.inputs) for r in rules), doc
