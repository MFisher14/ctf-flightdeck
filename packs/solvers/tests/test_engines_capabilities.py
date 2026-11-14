"""docs/CAPABILITIES.md generated from the manifests (R-10)."""
from __future__ import annotations

from pathlib import Path

import pytest

from ctf.engines import capabilities as C


def _eng(root: Path, lane: str, name: str, body: str, doc: str = "", caps: str = '["analysis"]'):
    d = root / "solvers" / lane
    d.mkdir(parents=True, exist_ok=True)
    src = (f'"""{doc}"""\n' if doc else "") + "def solve(d, p): pass\n"
    (d / f"{name}.py").write_text(src, encoding="utf-8")
    (d / f"{name}.manifest.toml").write_text(
        f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "solvers.{lane}.{name}:solve"\n'
        f"capabilities = {caps}\n" + body, encoding="utf-8")


@pytest.fixture
def root(tmp_path):
    _eng(tmp_path, "crypto", "lister", '[[routes]]\ncategory = ["crypto"]\npriority = 40\n',
         doc="Lists RSA keys. Second sentence is not shown.\n\nMore detail.", caps='["analysis", "rsa"]')
    _eng(tmp_path, "crypto", "rsa", '[[routes]]\ncategory = ["crypto"]\nkeywords = ["modulus", " hci"]\n'
                                    'priority = 70\n',
         doc="RSA a|b attacks", caps='["library", "rsa", "lattice"]')
    _eng(tmp_path, "net", "dex", '[[routes]]\nfiles = ["magic:0x6465780a", "ext:.dex"]\npriority = 30\n'
                                 '[[routes]]\nkeywords = ["k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8"]\n'
                                 'priority = 61\n', doc="Dex reader.", caps='["executes"]')
    _eng(tmp_path, "net", "lonely", "", doc="No route here.")
    _eng(tmp_path, "net", "gone", 'status = "retired"\n[[routes]]\nkeywords = ["x"]\npriority = 1\n',
         doc="Old.")
    _eng(tmp_path, "zz", "astro", '[[routes]]\ncategory = ["astrology"]\npriority = 5\n', doc="Stars.")
    return tmp_path


def test_summary_is_the_first_sentence_on_one_line(tmp_path):
    p = tmp_path / "m.py"
    p.write_text('"""First line\n   continues here. Second sentence.\n\nBody."""\n', encoding="utf-8")
    assert C.summary(p) == "First line continues here."
    p.write_text('"""' + "word " * 60 + '"""\n', encoding="utf-8")
    s = C.summary(p)
    assert len(s) == C.SUMMARY_CHARS and s.endswith("…")
    p.write_text("x = 1\n", encoding="utf-8")
    assert C.summary(p) == ""
    p.write_text("def (:\n", encoding="utf-8")
    assert C.summary(p) == ""


def test_render_groups_engines_by_category_with_priority_and_trigger(root):
    text = C.render(root)
    crypto = text.split("\n## crypto\n", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in crypto.splitlines() if line.startswith("| [")]
    assert rows[0] == ("| [`crypto.rsa`](../solvers/crypto/rsa.py) | library | 70 | `modulus`, `hci` | "
                       "RSA a\\|b attacks |")                       # best priority first; `|` escaped
    assert rows[1] == ("| [`crypto.lister`](../solvers/crypto/lister.py) | analysis | 40 | always | "
                       "Lists RSA keys. |")
    assert "| crypto | 2 | 1 | 1 |" in text                         # engines, always, on a keyword
    assert "\n## astrology\n" in text                                # a category triage does not list still shows


def test_any_category_lists_file_and_keyword_routes_with_overflow(root):
    text = C.render(root)
    anycat = text.split("\n## Any category\n", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in anycat.splitlines() if line.startswith("| [")]
    assert rows == [
        "| [`net.dex`](../solvers/net/dex.py) | executes | 61 | `k1`, `k2`, `k3`, `k4`, `k5`, `k6` +2 more | Dex reader. |",
        "| [`net.dex`](../solvers/net/dex.py) | executes | 30 | file `magic:0x6465780a`, `ext:.dex` | Dex reader. |",
    ]
    assert "| any category | 1 | 0 | 1 |" in text


def test_unrouted_retired_and_topics(root):
    text = C.render(root)
    unrouted = text.split("\n## Not routed\n", 1)[1].split("\n## ", 1)[0]
    assert "| [`net.lonely`](../solvers/net/lonely.py) | analysis | No route here. |" in unrouted
    assert "net.dex" not in unrouted and "net.gone" not in unrouted
    assert "- [`net.gone`](../solvers/net/gone.py): Old.\n" in text.split("\n## Retired\n", 1)[1]
    topics = text.split("\n## Topic index\n", 1)[1]
    assert "- **rsa**: `crypto.lister`, `crypto.rsa`\n" in topics
    assert "- **lattice**: `crypto.rsa`\n" in topics
    assert "**analysis**" not in topics and "**library**" not in topics      # class tags are not topics
    assert "6 engines: 4 routed, 1 not routed, 1 retired." in text


def test_stale_until_written_and_after_a_docstring_changes(root):
    assert C.is_stale(root)
    C.write(root)
    assert not C.is_stale(root)
    (root / "solvers/net/lonely.py").write_text('"""Now documented differently."""\n', encoding="utf-8")
    assert C.is_stale(root)


def test_committed_capabilities_is_current():
    """docs/CAPABILITIES.md must equal a fresh render: run `python -m ctf engines generate`."""
    assert not C.is_stale(), "docs/CAPABILITIES.md is stale: run `python -m ctf engines generate`"
