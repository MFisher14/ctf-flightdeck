"""The triage route table generated from the manifests, and triage ranking from it (R-10)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf import paths, triage
from ctf.engines import router
from ctf.engines import routetable as RT


def _eng(root: Path, lane: str, name: str, body: str, caps: str = '["analysis"]'):
    d = root / "solvers" / lane
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.py").write_text(f'"""{name} engine."""\ndef solve(d, p): pass\n', encoding="utf-8")
    (d / f"{name}.manifest.toml").write_text(
        f'id = "{lane}.{name}"\nlane = "{lane}"\nentry = "solvers.{lane}.{name}:solve"\n'
        f"capabilities = {caps}\n" + body, encoding="utf-8")


@pytest.fixture
def root(tmp_path, monkeypatch):
    _eng(tmp_path, "crypto", "lister", '[[routes]]\ncategory = ["crypto"]\npriority = 40\n')
    _eng(tmp_path, "crypto", "rsa", '[[routes]]\ncategory = ["crypto"]\npriority = 30\n'
                                    '[[routes]]\nkeywords = ["modulus"]\npriority = 70\n', caps='["library", "rsa"]')
    _eng(tmp_path, "net", "dex", '[[routes]]\nfiles = ["magic:0x6465780a"]\n', caps='["executes"]')
    _eng(tmp_path, "net", "gone", 'status = "retired"\n[[routes]]\nkeywords = ["modulus"]\npriority = 99\n')
    _eng(tmp_path, "net", "lonely", "")
    monkeypatch.setattr(paths, "repo_root", lambda: tmp_path)
    return tmp_path


def _rows(text):
    return [json.loads(line) for line in text.splitlines()[1:]]


def test_render_has_one_row_per_route_sorted_retired_and_unrouted_left_out(root):
    text = RT.render(root)
    head = json.loads(text.splitlines()[0])
    assert head["schema"] == RT.SCHEMA and "generate" in head["generated_by"]
    rows = _rows(text)
    assert [(r["id"], r["priority"]) for r in rows] == [
        ("crypto.lister", 40), ("crypto.rsa", 30), ("crypto.rsa", 70), ("net.dex", 50)]   # omitted priority = 50
    rsa = rows[1]
    assert rsa == {"id": "crypto.rsa", "path": "solvers/crypto/rsa.py", "class": "library", "priority": 30,
                   "category": ["crypto"], "keywords": [], "files": []}
    assert rows[3]["files"] == ["magic:0x6465780a"] and rows[3]["class"] == "executes"


def test_stale_until_written_and_after_a_manifest_changes(root):
    assert RT.is_stale(root)                                  # never written
    RT.write(root)
    assert not RT.is_stale(root)
    side = root / "solvers/crypto/lister.manifest.toml"
    side.write_text(side.read_text().replace("priority = 40", "priority = 41"), encoding="utf-8")
    assert RT.is_stale(root)
    RT.write(root)
    assert not RT.is_stale(root) and RT.load(root)[0].priority == 41


def test_load_refuses_a_missing_table_naming_the_command(root):
    with pytest.raises(RT.RouteTableError, match="python -m ctf engines generate"):
        RT.load(root)
    with pytest.raises(RT.RouteTableError, match="missing"):
        triage.suggest("crypto", "x")


@pytest.mark.parametrize("bad, why", [
    ("", "empty"),
    ('{"schema": 2}\n', "schema 1"),
    ('{"schema": 1}\nnot json\n', "not JSON"),
    ('{"schema": 1}\n{"id": "a.b"}\n', "exactly the keys"),
    ('{"schema": 1}\n{"id": "a.b", "path": "p", "class": "x", "priority": true, "category": [], '
     '"keywords": ["k"], "files": []}\n', "priority"),
    ('{"schema": 1}\n{"id": "a.b", "path": "p", "class": "x", "priority": 101, "category": [], '
     '"keywords": ["k"], "files": []}\n', "priority"),
    ('{"schema": 1}\n{"id": "a.b", "path": "p", "class": "x", "priority": 5, "category": [], '
     '"keywords": [], "files": []}\n', "no category, keyword or file"),
    ('{"schema": 1}\n{"id": "a.b", "path": "p", "class": "x", "priority": 5, "category": "web", '
     '"keywords": [], "files": []}\n', "list of strings"),
])
def test_parse_rejects_malformed_tables(bad, why):
    with pytest.raises(RT.RouteTableError, match=why):
        RT.parse(bad)


def test_triage_ranks_by_manifest_priority_from_the_table(root):
    RT.write(root)
    files = root / "files"
    files.mkdir()
    s = triage.suggest("Cryptography", "find the MODULUS", files)
    assert s["category"] == "crypto"
    assert s["engines"] == ["solvers/crypto/rsa.py", "solvers/crypto/lister.py"]   # 70 (keyword) over 40
    assert [r["priority"] for r in s["routes"]] == [70, 40]
    assert "modulus" in s["routes"][0]["reason"]
    s = triage.suggest("crypto", "", files)
    assert s["engines"] == ["solvers/crypto/lister.py", "solvers/crypto/rsa.py"]   # 40 over 30
    (files / "classes.dex").write_bytes(b"dex\n035\x00" + bytes(16))
    s = triage.suggest("crypto", "", files)
    assert s["engines"] == ["solvers/net/dex.py", "solvers/crypto/lister.py", "solvers/crypto/rsa.py"]
    assert triage.suggest("web", "modulus")["engines"] == ["solvers/crypto/rsa.py"]   # retired 99 never routed


def test_triage_reads_the_committed_table_not_the_live_manifests(root):
    """A manifest edit reaches triage only through `ctf engines generate` (the currency test guards it)."""
    RT.write(root)
    side = root / "solvers/crypto/lister.manifest.toml"
    side.write_text(side.read_text().replace("priority = 40", "priority = 10"), encoding="utf-8")
    assert triage.suggest("crypto")["routes"][0]["engine"] == "solvers/crypto/lister.py"
    RT.write(root)
    assert triage.suggest("crypto")["routes"][0]["engine"] == "solvers/crypto/rsa.py"


def test_render_marks_library_engines_import_only_and_shows_why(root):
    RT.write(root)
    text = triage.render(triage.suggest("crypto", "modulus"))
    lines = text.splitlines()
    assert lines[2] == "engines to try first:"
    assert lines[3].startswith("  (import-only, no CLI") and "solvers/crypto/rsa.py" in lines[3]
    assert "# priority 70: " in lines[3] and "keyword 'modulus'" in lines[3]
    assert lines[4] == "  .venv/bin/python solvers/crypto/lister.py <file>  # priority 40: category crypto"


def test_category_engines_and_import_only_views_follow_the_table(root):
    RT.write(root)
    assert triage.CATEGORY_ENGINES == {"crypto": ["solvers/crypto/lister.py", "solvers/crypto/rsa.py"]}
    assert triage.IMPORT_ONLY == frozenset({"solvers/crypto/rsa.py"})
    with pytest.raises(AttributeError):
        triage.NO_SUCH_NAME


def test_category_engines_view_orders_by_each_engines_best_bare_category_route(root):
    """An engine with two bare-category routes for one category is listed at the higher priority."""
    _eng(root, "crypto", "twice", '[[routes]]\ncategory = ["crypto"]\npriority = 20\n'
                                  '[[routes]]\ncategory = ["crypto"]\npriority = 45\n')
    _eng(root, "crypto", "twice_rev", '[[routes]]\ncategory = ["crypto"]\npriority = 35\n'
                                      '[[routes]]\ncategory = ["crypto"]\npriority = 10\n')
    RT.write(root)
    assert triage.CATEGORY_ENGINES == {"crypto": [
        "solvers/crypto/twice.py",          # 45 (its 20 route ignored)
        "solvers/crypto/lister.py",         # 40
        "solvers/crypto/twice_rev.py",      # 35 (its 10 route ignored)
        "solvers/crypto/rsa.py",            # 30
    ]}


def test_match_equals_the_manifest_router(root):
    RT.write(root)
    files = root / "files"
    files.mkdir()
    (files / "x.dex").write_bytes(b"dex\n")
    for cat, desc in (("crypto", ""), ("crypto", "modulus"), ("misc", "modulus"), ("web", "")):
        got = [(h.id, h.priority) for h in RT.match(cat, desc, files, root=root)]
        want = [(h.manifest.id, h.priority) for h in router.route(cat, desc, files, root=root)]
        assert got == want, (cat, desc)


def test_committed_route_table_is_current():
    """ctf/engines/route_table.jsonl must equal a fresh render of the manifests: run
    `python -m ctf engines generate` after changing a manifest."""
    assert not RT.is_stale(), "ctf/engines/route_table.jsonl is stale: run `python -m ctf engines generate`"


def test_repo_triage_ranks_the_specific_engine_over_the_category_list():
    """On the real table: a description keyword (a nudge, 60+) outranks the category lists (<= 49),
    and a web-only nudge applies only in web."""
    s = triage.suggest("crypto", "a padding oracle")
    assert s["engines"][0] == "solvers/common/crypto_oracles.py"
    assert s["routes"][0]["priority"] >= 60 > s["routes"][-1]["priority"]
    assert [r["priority"] for r in s["routes"]] == sorted((r["priority"] for r in s["routes"]), reverse=True)
    assert "solvers/web/ssti_helper.py" not in triage.suggest("forensics", "jinja template injection")["engines"]
    assert triage.suggest("web", "jinja template injection")["engines"][0] == "solvers/web/ssti_helper.py"


def test_repo_keys_certificates_env_and_rem_text_name_no_engine(tmp_path):
    """On the real table: a PEM, a key, a certificate, an .env or a text file opening with `rem ` ships with
    challenges of every category, so it adds no engine to the list (R-10 round 1: these were inferred from
    archive-member and in-file checks)."""
    files = tmp_path / "files"
    files.mkdir()
    for cat in ("crypto", "web", "misc"):
        bare = triage.suggest(cat, "", files)["engines"]
        (files / "key.pem").write_bytes(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
        (files / "id.key").write_bytes(b"\x30\x82\x01\x0a")
        (files / "server.crt").write_bytes(b"-----BEGIN CERTIFICATE-----\n")
        (files / "bundle.p12").write_bytes(b"\x30\x82\x09\x00")
        (files / ".env").write_bytes(b"SECRET=x\n")
        (files / "notes.txt").write_bytes(b"rem remember to rotate the key\n")
        assert triage.suggest(cat, "", files)["engines"] == bare, cat
        for f in files.iterdir():
            f.unlink()


def test_repo_container_runtime_engine_is_routed_by_its_domain_words():
    got = triage.suggest("misc", "a privileged container escape via cgroup release_agent")["engines"]
    assert "solvers/toolkits/cloud_runtime_depth.py" in got
