"""Manifest generation (B-186, R-10): static facts, carried-router routes, priorities, file routes, writing."""
from __future__ import annotations

import textwrap
import tomllib
from pathlib import Path

import pytest

from ctf.engines import generate as G
from ctf.engines import legacy_routes as LR
from ctf.engines import lint as L
from ctf.engines import manifest as M


def _mod(tmp_path: Path, rel: str, src: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")
    return p


def test_analyze_reads_main_guard_nested_under_a_top_level_if(tmp_path):
    p = _mod(tmp_path, "solvers/x/a.py", '''
        """Doc."""
        import sys as _sys
        if not getattr(_sys, "x", False):
            def main(argv):
                return 0
            if __name__ == "__main__":
                raise SystemExit(main(_sys.argv[1:]))
    ''')
    f = G.analyze(p)
    assert f.has_main and "main" in f.defs


def test_needs_tools_counts_unconditional_imports_which_and_subprocess_only(tmp_path):
    p = _mod(tmp_path, "solvers/x/a.py", '''
        import json, shutil, subprocess
        import numpy as np
        from scapy.all import rdpcap
        import network
        try:
            import cv2
        except ImportError:
            cv2 = None
        def run(path):
            if shutil.which("tshark"):
                subprocess.run(["tshark", "-r", path])
            subprocess.run(["sh", "-c", "true"])
            subprocess.check_output(["binwalk", path])
    ''')
    _mod(tmp_path, "solvers/x/network.py", "def x(): pass\n")
    f = G.analyze(p)
    needs = G.needs_tools(f, G._repo_module_names(tmp_path))
    assert needs == ["binwalk", "py:numpy", "py:scapy", "tshark"]      # no cv2 (guarded), no sh, no network (repo)


def test_inputs_from_suffix_endswith_and_magic(tmp_path):
    p = _mod(tmp_path, "solvers/x/a.py", '''
        def run(p, data):
            if p.suffix == ".pcapng" or p.name.endswith((".pcap", ".CAP", "notext")):
                pass
            if data.startswith(b"\\x89PNG") or data.startswith((b"PK", b"%PDF")):
                pass
    ''')
    f = G.analyze(p)
    assert f.exts == {".pcapng", ".pcap", ".cap"}
    assert f.magics == {"magic:0x89504e47", "magic:PK", "magic:%PDF"}


@pytest.mark.parametrize("name, src, want", [
    ("shell_jail_planner.py", "def f(): pass\nif __name__ == '__main__': f()\n", "plan"),
    ("x.py", '"""Builds inert candidates; never sends them."""\ndef f(): pass\n', "plan"),
    ("x.py", "def f(): pass\n", "library"),
    ("x.py", "import re\nFLAG_RE = re.compile('x')\ndef f(): pass\nif __name__ == '__main__': f()\n", "executes"),
    ("x.py", "def f(): pass\nif __name__ == '__main__': f()\n", "analysis"),
])
def test_classify(tmp_path, name, src, want):
    assert G.classify(G.analyze(_mod(tmp_path, f"solvers/x/{name}", src))) == want


TRIAGE = '''
CATEGORY_ENGINES = {
    "crypto": ["solvers/c/a.py", "solvers/c/b.py"],
    "web": ["solvers/w/w.py"],
}
def suggest(category, description="", files_dir=None):
    cat = category
    engines = list(CATEGORY_ENGINES.get(cat, []))
    text = description.lower()
    if any(k in text for k in ("base64", "xor")) and "solvers/c/b.py" not in engines:
        engines.append("solvers/c/b.py")
    if any(k in text for k in ("pcap",)) and "solvers/c/n.py" not in engines:
        engines.insert(0, "solvers/c/n.py")
    def _nudge(keys, mod):
        pass
    _nudge(("rsa", "modulus"), "solvers/c/a.py")
    _nudge(("rsa",), "solvers/c/b.py")
    if cat == "web":
        _nudge(("jwt",), "solvers/w/w.py")
    files = []
    return {"engines": engines}
'''


def test_legacy_routes_reads_every_shape(tmp_path):
    t = _mod(tmp_path, "ctf/triage.py", TRIAGE)
    rs = LR.parse(t)
    got = [(r.path, r.category, r.keywords, r.kind) for r in rs]
    assert got == [
        ("solvers/c/a.py", ("crypto",), (), "category"),
        ("solvers/c/b.py", ("crypto",), (), "category"),
        ("solvers/w/w.py", ("web",), (), "category"),
        ("solvers/c/b.py", (), ("base64", "xor"), "append"),
        ("solvers/c/n.py", (), ("pcap",), "insert"),
        ("solvers/c/a.py", (), ("rsa", "modulus"), "nudge"),
        ("solvers/c/b.py", (), ("rsa",), "nudge"),
        ("solvers/w/w.py", ("web",), ("jwt",), "nudge"),
    ]


def test_legacy_routes_fails_loudly_on_an_unknown_routing_shape(tmp_path):
    t = _mod(tmp_path, "ctf/triage.py", TRIAGE.replace('    files = []\n',
                                                       '    engines.extend(["solvers/c/z.py"])\n    files = []\n'))
    with pytest.raises(LR.LegacyParseError, match="solvers/c/z.py"):
        LR.parse(t)


def test_priorities_reproduce_triage_order(tmp_path):
    rs = LR.parse(_mod(tmp_path, "ctf/triage.py", TRIAGE))
    pr = G.assign_priorities(rs)
    by = {(r.path, r.kind, r.keywords): pr[i] for i, r in enumerate(rs)}
    assert by[("solvers/c/a.py", "category", ())] > by[("solvers/c/b.py", "category", ())]   # list order
    assert by[("solvers/c/b.py", "append", ("base64", "xor"))] < by[("solvers/c/b.py", "category", ())]
    # b's later "rsa" nudge lands in front of a's earlier one in triage, so it must outrank it
    assert by[("solvers/c/b.py", "nudge", ("rsa",))] > by[("solvers/c/a.py", "nudge", ("rsa", "modulus"))]
    assert min(v for (p, k, _), v in by.items() if k == "nudge") >= 60
    # an insert that applies only when the engine is not listed: above every list, below every nudge
    assert by[("solvers/c/n.py", "insert", ("pcap",))] == 50
    # the category-guarded nudge ran after all the others in the carried router
    assert by[("solvers/w/w.py", "nudge", ("jwt",))] > max(v for (p, k, kw), v in by.items()
                                                          if k == "nudge" and p != "solvers/w/w.py")


SUBSTR = TRIAGE.replace('    _nudge(("rsa",), "solvers/c/b.py")\n',
                        '    _nudge(("rsa",), "solvers/c/b.py")\n'
                        '    _nudge(("ecc",), "solvers/c/n.py")\n'
                        '    _nudge(("small rsa key",), "solvers/c/n.py")\n')


def test_a_later_nudge_whose_keyword_contains_an_earlier_one_outranks_it(tmp_path):
    """"small rsa key" fires "rsa" too, and the carried router put the later nudge first; "ecc" fires
    with nothing earlier, so it stays at the floor."""
    rs = LR.parse(_mod(tmp_path, "ctf/triage.py", SUBSTR))
    pr = G.assign_priorities(rs)
    by = {(r.path, r.keywords): pr[i] for i, r in enumerate(rs) if r.kind == "nudge"}
    assert by[("solvers/c/n.py", ("small rsa key",))] > by[("solvers/c/b.py", ("rsa",))]
    assert by[("solvers/c/n.py", ("ecc",))] == 60


def _fake_repo(tmp_path):
    _mod(tmp_path, "ctf/triage.py", TRIAGE)
    _mod(tmp_path, "solvers/c/a.py", '"""RSA and lattice helpers."""\ndef solve(d, p): pass\n')
    _mod(tmp_path, "solvers/c/b.py", "import re\nFLAG_RE = 1\ndef f(): pass\nif __name__ == '__main__': f()\n")
    _mod(tmp_path, "solvers/c/n.py", "def f(): pass\nif __name__ == '__main__': f()\n")
    _mod(tmp_path, "solvers/c/lonely.py", "def f(): pass\n")
    _mod(tmp_path, "solvers/c/data.py", "TABLE = {}\n")
    _mod(tmp_path, "solvers/w/w.py", "def f(): pass\nif __name__ == '__main__': f()\n")
    return tmp_path


def test_plan_writes_valid_lint_clean_manifests_and_never_overwrites(tmp_path):
    root = _fake_repo(tmp_path)
    planned, skipped = G.plan(root, triage_path=root / "ctf/triage.py")
    assert skipped == []
    assert sorted(p.module.name for p in planned) == ["a.py", "b.py", "lonely.py", "n.py", "w.py"]   # not data.py
    G.write(planned)
    ms = {m.id: m for m in M.discover(root)}
    a, b, lonely = ms["c.a"], ms["c.b"], ms["c.lonely"]
    assert a.entry_raw == "solvers.c.a:solve" and a.has("library") and "rsa" in a.capabilities
    assert b.entry_raw == "cli:python solvers/c/b.py" and b.has("executes") and b.has("legacy-output")
    assert lonely.routes == () and a.routes and all(r.priority is not None for r in a.routes)
    findings = L.lint(root, baseline=set(), known_categories={"crypto", "web"})
    assert [(f.code, f.subject) for f in findings if f.severity == "error"] == [("no-route", "c.lonely")]
    # a hand edit survives a second run
    side = M.sidecar_for(root / "solvers/c/a.py")
    side.write_text(side.read_text() + "# edited\n", encoding="utf-8")
    again, _ = G.plan(root, triage_path=root / "ctf/triage.py")
    assert again == [] and side.read_text().endswith("# edited\n")


def test_plan_reads_no_router_unless_given_one(tmp_path):
    """Since R-10 the manifests are the routing source: ctf/triage.py in the tree is not read."""
    root = _fake_repo(tmp_path)
    planned, _ = G.plan(root)
    for p in planned:
        assert "[[routes]]" not in p.text, p.module.name


def test_plan_gives_a_new_engine_a_file_route_clear_of_existing_claims(tmp_path):
    root = tmp_path
    _mod(root, "solvers/c/dex_a.py", 'def solve(d, p):\n    return d.suffix == ".dex"\n')
    (root / "solvers/c/dex_a.manifest.toml").write_text(
        'id = "c.dex_a"\nlane = "c"\nentry = "solvers.c.dex_a:solve"\n'
        '[[routes]]\nfiles = ["ext:.dex"]\npriority = 30\n', encoding="utf-8")
    _mod(root, "solvers/c/dex_b.py", 'def solve(d, p):\n    return d.name.endswith(".dex")\n')
    _mod(root, "solvers/c/plain.py", 'def solve(d, p):\n    return d.name.endswith(".txt")\n')
    planned, skipped = G.plan(root)
    assert skipped == []
    G.write(planned)
    ms = {m.id: m for m in M.discover(root)}
    (r,) = ms["c.dex_b"].routes
    assert r.files == ("ext:.dex",) and r.priority == 29 and not r.category and not r.keywords
    assert ms["c.plain"].routes == ()                         # .txt is not a distinctive format
    findings = L.lint(root, baseline=set(), known_categories=set())
    assert [(f.code, f.subject) for f in findings if f.severity == "error"] == [("no-route", "c.plain")]


def test_plan_refuses_a_route_to_a_missing_file(tmp_path):
    root = _fake_repo(tmp_path)
    (root / "solvers/c/n.py").unlink()
    with pytest.raises(FileNotFoundError, match="solvers/c/n.py"):
        G.plan(root, triage_path=root / "ctf/triage.py")


def test_rendered_manifest_round_trips_odd_strings(tmp_path):
    text = G.render_manifest(mid="x.y", lane="x", entry="cli:python solvers/x/y.py", capabilities=["plan"],
                             inputs=['magic:"q"\\'], needs=[], cost="cheap", status="plan-only",
                             routes=[("c", {"category": [], "keywords": [" hci", "vigenère", 'a"b'], "priority": 61})])
    m = M.parse(tomllib.loads(text), tmp_path / "solvers/x/y.manifest.toml")
    assert m.inputs == ('magic:"q"\\',) and m.routes[0].keywords == (" hci", "vigenère", 'a"b')
