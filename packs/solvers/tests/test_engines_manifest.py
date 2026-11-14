"""Engine manifest schema and discovery (B-186; docs/CONTRACTS.md section 6)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctf.engines import manifest as M

GOOD = """
id = "crypto.rsa_small"
lane = "crypto"
entry = "solvers.crypto.rsa_small:solve"
capabilities = ["rsa", "executes"]
inputs = ["pem", "ext:.pub"]
needs_tools = ["py:gmpy2"]
cost_class = "cheap"
status = "active"

[[routes]]
category = ["crypto"]
keywords = ["rsa", "modulus"]
files = ["magic:-----BEGIN PUBLIC KEY", "ext:.pem", "name:*.pub"]
priority = 70

[[routes]]
keywords = ["small e"]
"""


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def test_full_manifest_parses_with_every_field(tmp_path):
    p = _write(tmp_path, "solvers/crypto/rsa_small.manifest.toml", GOOD)
    m = M.load(p)
    assert m.id == "crypto.rsa_small" and m.lane == "crypto" and m.name == "rsa_small"
    assert m.entry.kind == "function" and m.entry.module == "solvers.crypto.rsa_small"
    assert m.entry.function == "solve"
    assert m.capabilities == ("rsa", "executes") and m.needs_tools == ("py:gmpy2",)
    assert m.cost_class == "cheap" and m.status == "active"
    assert m.routes[0].priority == 70 and m.routes[0].files[0] == "magic:-----BEGIN PUBLIC KEY"
    # an omitted priority stays None (lint needs to know it was not set); routing uses 50
    assert m.routes[1].priority is None and m.routes[1].effective_priority == 50
    assert m.module_path == tmp_path / "solvers/crypto/rsa_small.py"
    assert m.entry.target_file(tmp_path) == tmp_path / "solvers/crypto/rsa_small.py"


def test_defaults_for_optional_keys(tmp_path):
    p = _write(tmp_path, "solvers/x/a.manifest.toml", 'id = "x.a"\nlane = "x"\nentry = "cli:python solvers/x/a.py"\n')
    m = M.load(p)
    assert (m.capabilities, m.inputs, m.needs_tools, m.routes) == ((), (), (), ())
    assert m.cost_class == "medium" and m.status == "active"
    assert m.entry.kind == "cli" and m.entry.is_python_cli and m.entry.argv == ("python", "solvers/x/a.py")


@pytest.mark.parametrize("text, needle", [
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\nbogus = 1\n', "bogus: unknown key"),
    ('lane = "x"\nentry = "m:f"\n', "id: required key missing"),
    ('id = "x.a"\nentry = "m:f"\n', "lane: required key missing"),
    ('id = "X.A"\nlane = "x"\nentry = "m:f"\n', "id:"),
    ('id = "nodot"\nlane = "x"\nentry = "m:f"\n', "id:"),
    ('id = "x.a"\nlane = "x"\nentry = "no_colon"\n', "entry:"),
    ('id = "x.a"\nlane = "x"\nentry = "m:not-a-name"\n', "entry:"),
    ('id = "x.a"\nlane = "x"\nentry = "cli:"\n', "entry:"),
    ('id = "x.a"\nlane = "x"\nentry = "cli:python"\n', "needs a script"),
    ('id = "x.a"\nlane = "x"\nentry = "cli:python /abs/x.py"\n', "repo-relative"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\nstatus = "live"\n', "status:"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\ncost_class = "free"\n', "cost_class:"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\ncapabilities = "rsa"\n', "capabilities:"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\ncapabilities = ["a", "a"]\n', "duplicate"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\ncapabilities = ["Bad Tag"]\n', "capabilities[0]"),
    ('id = "x.a"\nlane = "x"\nentry = true\n', "entry:"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\n[[routes]]\nkeywords = ["a"]\nweight = 3\n', "routes[0].weight"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\n[[routes]]\nkeywords = ["a"]\npriority = true\n', "priority"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\n[[routes]]\nkeywords = ["a"]\npriority = 101\n', "outside 0-100"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\n[[routes]]\nkeywords = ["RSA"]\n', "lower-case"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\n[[routes]]\ncategory = ["Crypto"]\n', "lower-case"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\n[[routes]]\nfiles = ["pcap"]\n', "files[0]"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\n[[routes]]\nfiles = ["ext:pcap"]\n', "starts with a dot"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\nroutes = 3\n', "routes:"),
    ('id = "x.a"\nlane = "x"\nentry = "m:f"\nthis is not toml\n', "not valid TOML"),
])
def test_invalid_manifests_raise_naming_the_key(tmp_path, text, needle):
    p = _write(tmp_path, "solvers/x/a.manifest.toml", text)
    with pytest.raises(M.ManifestError) as ei:
        M.load(p)
    assert needle in str(ei.value) and str(p) in str(ei.value)


def test_dash_lane_entry_resolves_to_its_folder(tmp_path):
    _write(tmp_path, "solvers/metadata-forensics/props.py", "def run(): pass\n")
    p = _write(tmp_path, "solvers/metadata-forensics/props.manifest.toml",
               'id = "metadata_forensics.props"\nlane = "metadata-forensics"\n'
               'entry = "solvers.metadata-forensics.props:run"\n')
    m = M.load(p)
    assert m.entry.target_file(tmp_path) == tmp_path / "solvers/metadata-forensics/props.py"


def test_discover_sorts_and_rejects_duplicate_ids(tmp_path):
    _write(tmp_path, "solvers/b/z.manifest.toml", 'id = "b.z"\nlane = "b"\nentry = "m:f"\n')
    _write(tmp_path, "tools/a.manifest.toml", 'id = "tools.a"\nlane = "tools"\nentry = "m:f"\n')
    _write(tmp_path, "elsewhere/q.manifest.toml", 'id = "q.q"\nlane = "q"\nentry = "m:f"\n')  # not an engine root
    assert [m.id for m in M.discover(tmp_path)] == ["b.z", "tools.a"]
    _write(tmp_path, "solvers/c/z.manifest.toml", 'id = "b.z"\nlane = "c"\nentry = "m:f"\n')
    with pytest.raises(M.ManifestError, match="already used"):
        M.discover(tmp_path)


def test_discover_reports_every_bad_file(tmp_path):
    _write(tmp_path, "solvers/a/one.manifest.toml", 'id = "a.one"\n')
    _write(tmp_path, "solvers/a/two.manifest.toml", 'id = "a.two"\nlane = "a"\nentry = "m:f"\nzzz = 1\n')
    with pytest.raises(M.ManifestError) as ei:
        M.discover(tmp_path)
    assert "2 bad engine manifest" in str(ei.value)
    assert "one.manifest.toml" in str(ei.value) and "two.manifest.toml" in str(ei.value)


def test_discover_cache_sees_an_edited_file(tmp_path):
    p = _write(tmp_path, "solvers/a/one.manifest.toml", 'id = "a.one"\nlane = "a"\nentry = "m:f"\n')
    assert M.discover(tmp_path)[0].status == "active"
    p.write_text('id = "a.one"\nlane = "a"\nentry = "m:f"\nstatus = "retired"\n', encoding="utf-8")
    st = p.stat()
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))   # guarantee a new mtime
    assert M.discover(tmp_path)[0].status == "retired"


def test_every_repo_manifest_parses():
    ms = M.discover()
    assert len(ms) > 600, "the generated manifests for the carried engines are missing"
    assert len({m.id for m in ms}) == len(ms)
