"""B-179: lane result manifests, per-lane checks against the branch, and integration (collision
checks, merge, CAPABILITIES entries). Lane work is made directly in each lane checkout here; the
runner end-to-end lives in test_lanes_runner.py."""
from __future__ import annotations

import json

import pytest

from _lanes_fixtures import CAPS, git, git_env, manifest, src_repo, fake_venv  # noqa: F401
from ctf.lanes import backlog as bl
from ctf.lanes import checkout as co
from ctf.lanes import layout, results


def lane_def(lid, *, owns=None, depends=()):
    owns = owns or [f"solvers/crypto/{lid}*", f"tests/test_{lid}.py"]
    return {"id": lid, "title": lid.title(), "goal": f"build {lid}", "acceptance": [f"{lid} ok"],
            "owns": owns, "tests": [f"tests/test_{lid}.py"], "depends": list(depends)}


def make(lanes):
    return bl.parse({"batch": "ib", "base": "main", "lanes": lanes})


@pytest.fixture
def dirs(tmp_path):
    return layout.batch_dirs("ib", tmp_path / "state")


def engine_files(lid, eid=None, base=None, keyword=None, priority=50):
    base = base or lid
    eid = eid or f"crypto.{base}"
    return {f"solvers/crypto/{base}.py": "def solve(challenge_dir, profile, **opts):\n    return None\n",
            f"solvers/crypto/{base}.manifest.toml": manifest(eid, base, keyword=keyword or f"kw{lid}",
                                                              priority=priority),
            f"tests/test_{lid}.py": "def test_x():\n    assert 1 + 1 == 2\n"}


def finish(b, dirs, lid, files, *, status="built", commit=True, engines=None, caps=(), shared=(),
           extra=None, state="done"):
    c = dirs.checkout(lid)
    for rel, text in files.items():
        p = c / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    if commit and files:
        git(c, "add", "-A")
        git(c, "commit", "-q", "-m", f"{lid}: work")
    res = {"schema": 1, "lane": lid, "status": status, "summary": f"{lid} summary",
           "engines": engines if engines is not None else [
               {"id": f"crypto.{lid}", "manifest": f"solvers/crypto/{lid}.manifest.toml"}],
           "capabilities": [dict(zip(("section", "key", "text"), x)) for x in caps],
           "tests": [f"tests/test_{lid}.py"], "shared_files": list(shared)}
    res.update(extra or {})
    layout.write_json(dirs.result(lid), res)
    layout.write_json(dirs.status(lid), {"lane": lid, "state": state})


def setup(src_repo, b, dirs, fake_venv):
    co.setup(src_repo, b, dirs, venv=fake_venv)


# ------------------------------------------------------------------------------------ result.json

@pytest.mark.parametrize("data, msg", [
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s", "extra": 1}, "unknown key(s) extra"),
    ({"schema": 2, "lane": "a", "status": "built", "summary": "s"}, "schema: must be 1"),
    ({"schema": True, "lane": "a", "status": "built", "summary": "s"}, "schema: must be 1"),
    ({"schema": 1, "lane": "b", "status": "built", "summary": "s"}, "names 'b', expected 'a'"),
    ({"schema": 1, "lane": "a", "status": "done", "summary": "s"}, "status: must be one of"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": " "}, "summary: must be a non-empty string"),
    ({"schema": 1, "lane": "a", "status": "built"}, "summary: required key missing"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s", "commit": "<sha>"}, "commit: must be a hex"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s", "engines": "x"}, "engines: must be a list"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s", "engines": [{"id": "x"}]}, "engines[0]"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s",
      "engines": [{"id": "x.y", "manifest": "solvers/x/y.py"}]}, "must be a repo-relative *.manifest.toml"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s",
      "capabilities": [{"section": "S", "key": "Bad Key", "text": "t"}]}, "capabilities[0].key"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s",
      "capabilities": [{"section": "S", "key": "k", "text": "two\nlines"}]}, "single lines"),
    ({"schema": 1, "lane": "a", "status": "built", "summary": "s", "tests": "t.py"}, "tests: must be a list"),
    (["not", "a", "dict"], "must be a JSON object"),
])
def test_parse_result_rejects(data, msg):
    with pytest.raises(results.ResultError, match=__import__("re").escape(msg)):
        results.parse_result(data, "a")


def test_load_result_names_missing_and_bad_json(tmp_path):
    with pytest.raises(results.ResultError, match="no result.json"):
        results.load_result(tmp_path / "result.json", "a")
    (tmp_path / "result.json").write_text("{nope")
    with pytest.raises(results.ResultError, match="not valid JSON"):
        results.load_result(tmp_path / "result.json", "a")


def test_capability_bullet_and_keys():
    assert results.CapEntry("S", "k1", "Does a thing").bullet() == "- Does a thing (`k1`)"
    assert results.CapEntry("S", "k1", "Does `k1.py`  things").bullet() == "- Does `k1.py` things"
    keys = results.capability_keys(CAPS)
    assert {"rsa_old", "lattice_tool.py", "lattice_tool", "sanity"} <= keys


def test_apply_capabilities_inserts_at_the_end_of_each_section():
    out = results.apply_capabilities(CAPS, [results.CapEntry("Crypto", "new1", "New one"),
                                            results.CapEntry("Misc", "new2", "New two"),
                                            results.CapEntry("Crypto", "new3", "New three")])
    lines = out.splitlines()
    i = lines.index("- Lattice things (`lattice_tool.py`)")
    assert lines[i + 1: i + 4] == ["- New one (`new1`)", "- New three (`new3`)", ""]
    assert lines[i + 4] == "## Misc"
    assert lines[-1] == "- New two (`new2`)" and out.endswith("\n")
    with pytest.raises(KeyError, match="no section '## Nope'"):
        results.apply_capabilities(CAPS, [results.CapEntry("Nope", "k", "t")])


# ----------------------------------------------------------------------------------- lane checks

def test_clean_lane_has_no_problems(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", engine_files("alpha"))
    rep = results.check_lane(b, dirs, "alpha")
    assert rep.problems == [] and rep.warnings == [] and rep.commits == 1
    assert rep.changed == ["solvers/crypto/alpha.manifest.toml", "solvers/crypto/alpha.py", "tests/test_alpha.py"]
    assert rep.state == "done" and rep.result.status == "built"


def test_lane_checks_catch_scope_protected_and_claims(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha")])
    setup(src_repo, b, dirs, fake_venv)
    files = engine_files("alpha")
    files["ctf/other.py"] = "x = 1\n"
    files["docs/CAPABILITIES.md"] = CAPS + "- sneaky\n"
    files["docs/CONTRACTS.md"] = "changed\n"
    finish(b, dirs, "alpha", files, shared=["docs/CONTRACTS.md"],
           engines=[{"id": "crypto.alpha", "manifest": "solvers/crypto/alpha.manifest.toml"},
                    {"id": "crypto.wrong", "manifest": "solvers/crypto/alpha.manifest.toml"},
                    {"id": "crypto.ghost", "manifest": "solvers/crypto/ghost.manifest.toml"}],
           extra={"commit": "0000000"})
    (dirs.checkout("alpha") / "scratch.txt").write_text("left over")
    rep = results.check_lane(b, dirs, "alpha")
    p = "\n".join(rep.problems)
    assert "out of scope: ctf/other.py" in p
    assert "changed protected file docs/CAPABILITIES.md (declare capabilities in result.json instead)" in p
    assert "result commit 0000000 is not on the lane branch" in p
    assert "engine crypto.wrong: solvers/crypto/alpha.manifest.toml declares id 'crypto.alpha'" in p
    assert "engine crypto.ghost: solvers/crypto/ghost.manifest.toml is not committed" in p
    assert "docs/CONTRACTS.md" not in p, "a declared shared file is a warning, not a problem"
    assert "declared shared file docs/CONTRACTS.md" in rep.warnings
    assert any("1 uncommitted path(s): scratch.txt" in w for w in rep.warnings)
    assert not any("crypto.alpha:" in x for x in rep.problems)


def test_built_lane_without_commits_or_tests_is_a_problem(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", {}, engines=[])
    p = "\n".join(results.check_lane(b, dirs, "alpha").problems)
    assert "status built but the branch has no commits past the base" in p
    assert "test file tests/test_alpha.py is not committed on the branch" in p
    # a blocked lane with nothing committed is reported, not a problem
    finish(b, dirs, "alpha", {}, engines=[], status="blocked")
    assert results.check_lane(b, dirs, "alpha").problems == []


def test_missing_checkout_and_result_are_problems(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha")])
    assert "no checkout" in results.check_lane(b, dirs, "alpha").problems[0]
    setup(src_repo, b, dirs, fake_venv)
    rep = results.check_lane(b, dirs, "alpha")
    assert rep.state == "not-run" and any("no result.json" in x for x in rep.problems)


# ------------------------------------------------------------------------------------- integrate

def test_integrate_merges_clean_lanes_and_applies_capabilities(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha"), lane_def("beta", depends=["alpha"])])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", engine_files("alpha"), caps=[("Crypto", "alpha", "Alpha decoder")])
    co.merge_dependencies(dirs.checkout("beta"), [(b.branch("alpha"), dirs.checkout("alpha"))])
    finish(b, dirs, "beta", engine_files("beta"), caps=[("Misc", "beta", "Beta helper")])

    dry = results.integrate(b, dirs, src_repo)
    assert {k: v["integrated"] for k, v in dry["lanes"].items()} == {"alpha": "ready", "beta": "ready"}
    assert (src_repo / "docs/CAPABILITIES.md").read_text() == CAPS, "no write without apply"
    assert git(src_repo, "branch", "--list", "lane/*") == ""

    rep = results.integrate(b, dirs, src_repo, merge=True, apply=True)
    assert {k: v["integrated"] for k, v in rep["lanes"].items()} == {"alpha": "merged", "beta": "merged"}
    assert rep["merged"] == ["alpha: merged lane/ib/alpha", "beta: merged lane/ib/beta"]
    assert (src_repo / "solvers/crypto/alpha.py").is_file() and (src_repo / "solvers/crypto/beta.py").is_file()
    assert git(src_repo, "log", "-1", "--format=%s") == "Merge lane beta (ib): Beta"
    caps = (src_repo / "docs/CAPABILITIES.md").read_text()
    assert "- Alpha decoder (`alpha`)\n\n## Misc" in caps and caps.endswith("- Beta helper (`beta`)\n")
    assert rep["capabilities_applied"] == ["Crypto: alpha", "Misc: beta"]
    assert git(src_repo, "status", "--porcelain") == "M docs/CAPABILITIES.md", "left for review"
    assert json.loads(dirs.integration.read_text())["lanes"]["alpha"]["integrated"] == "merged"


def test_integrate_holds_every_lane_in_a_collision(src_repo, dirs, fake_venv):
    lanes = [lane_def(x) for x in ("idone", "idtwo", "base1", "capold", "capsec", "capa", "capb",
                                   "routea", "routeb", "noroute", "after")]
    lanes[-1]["depends"] = ["noroute"]
    lanes[2]["owns"] = ["solvers/web/*", "tests/test_base1.py"]
    b = make(lanes)
    setup(src_repo, b, dirs, fake_venv)
    # the same engine id from two lanes
    finish(b, dirs, "idone", engine_files("idone", eid="crypto.dup"),
           engines=[{"id": "crypto.dup", "manifest": "solvers/crypto/idone.manifest.toml"}])
    finish(b, dirs, "idtwo", engine_files("idtwo", eid="crypto.dup"),
           engines=[{"id": "crypto.dup", "manifest": "solvers/crypto/idtwo.manifest.toml"}])
    # an engine basename the target already has (solvers/crypto/existing.py)
    f = {"solvers/web/existing.py": "def solve(challenge_dir, profile, **opts):\n    return None\n",
         "solvers/web/existing.manifest.toml": manifest("web.existing", "existing", keyword="kwbase1")
         .replace("solvers.web.existing", "solvers.web.existing"),
         "tests/test_base1.py": "def test_x():\n    assert 2 > 1\n"}
    finish(b, dirs, "base1", f, engines=[{"id": "web.existing", "manifest": "solvers/web/existing.manifest.toml"}])
    # capability keys: already present, unknown section, claimed by two lanes
    finish(b, dirs, "capold", engine_files("capold"), caps=[("Crypto", "lattice_tool", "dup of an old one")])
    finish(b, dirs, "capsec", engine_files("capsec"), caps=[("Nowhere", "capsec", "lost")])
    finish(b, dirs, "capa", engine_files("capa"), caps=[("Crypto", "shared_key", "a")])
    finish(b, dirs, "capb", engine_files("capb"), caps=[("Misc", "shared_key", "b")])
    # the same route keyword at the same priority from two lanes
    finish(b, dirs, "routea", engine_files("routea", keyword="clash"))
    finish(b, dirs, "routeb", engine_files("routeb", keyword="clash"))
    # an engine with no route: route lint (relative to the target) holds it, and its dependent
    finish(b, dirs, "noroute", {**engine_files("noroute"),
                                "solvers/crypto/noroute.manifest.toml": manifest("crypto.noroute", "noroute",
                                                                                 keyword=None)})
    finish(b, dirs, "after", engine_files("after"))

    rep = results.integrate(b, dirs, src_repo, merge=True, apply=True)
    held = {k: "\n".join(v["held"]) for k, v in rep["lanes"].items()}
    assert all(v["integrated"] is None for v in rep["lanes"].values()), held
    assert "engine id crypto.dup also claimed by lane(s) idtwo" in held["idone"]
    assert "engine id crypto.dup also claimed by lane(s) idone" in held["idtwo"]
    assert "engine basename existing already used by solvers/crypto/existing.py" in held["base1"]
    assert "capability key lattice_tool already in docs/CAPABILITIES.md" in held["capold"]
    assert "no section '## Nowhere'" in held["capsec"]
    assert "capability key shared_key also claimed by lane(s) capb" in held["capa"]
    assert "capability key shared_key also claimed by lane(s) capa" in held["capb"]
    assert "route conflict with lane routeb" in held["routea"] and "('keyword', 'clash')" in held["routea"]
    assert "route conflict with lane routea" in held["routeb"]
    assert "route lint no-route crypto.noroute" in held["noroute"]
    assert "dependency noroute is not integrable" in held["after"]
    assert rep["merged"] == [] and rep["capabilities_applied"] == []
    assert (src_repo / "docs/CAPABILITIES.md").read_text() == CAPS


def test_distinct_priorities_are_not_a_route_conflict(src_repo, dirs, fake_venv):
    b = make([lane_def("routea"), lane_def("routeb")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "routea", engine_files("routea", keyword="clash", priority=60))
    finish(b, dirs, "routeb", engine_files("routeb", keyword="clash", priority=40))
    rep = results.integrate(b, dirs, src_repo)
    assert {k: v["integrated"] for k, v in rep["lanes"].items()} == {"routea": "ready", "routeb": "ready"}


def test_partial_lanes_wait_unless_included(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", engine_files("alpha"), status="partial")
    assert results.integrate(b, dirs, src_repo)["lanes"]["alpha"]["held"] == ["status partial"]
    assert results.integrate(b, dirs, src_repo, include_partial=True)["lanes"]["alpha"]["integrated"] == "ready"


def test_merge_conflict_is_aborted_and_held(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha"), lane_def("beta")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", {**engine_files("alpha"), "docs/CONTRACTS.md": "alpha says\n"},
           shared=["docs/CONTRACTS.md"])
    finish(b, dirs, "beta", {**engine_files("beta"), "docs/CONTRACTS.md": "beta says\n"},
           shared=["docs/CONTRACTS.md"])
    rep = results.integrate(b, dirs, src_repo, merge=True)
    assert rep["lanes"]["alpha"]["integrated"] == "merged"
    assert rep["lanes"]["beta"]["integrated"] is None
    assert any(h.startswith("merge conflict") for h in rep["lanes"]["beta"]["held"])
    assert rep["merged"] == ["alpha: merged lane/ib/alpha", "beta: conflict, aborted"]
    assert git(src_repo, "status", "--porcelain", "--untracked-files=no") == ""
    assert (src_repo / "docs/CONTRACTS.md").read_text() == "alpha says\n"


def test_dependent_of_a_conflicted_merge_is_held_not_merged(src_repo, dirs, fake_venv):
    # beta depends on alpha and resolves alpha's change itself, so beta's own branch would merge
    # cleanly into the target and carry alpha's commits with it: only the dependency hold stops it.
    b = make([lane_def("alpha"), lane_def("beta", depends=["alpha"])])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", {**engine_files("alpha"), "docs/CONTRACTS.md": "alpha says\n"},
           shared=["docs/CONTRACTS.md"])
    co.merge_dependencies(dirs.checkout("beta"), [(b.branch("alpha"), dirs.checkout("alpha"))])
    finish(b, dirs, "beta", {**engine_files("beta"), "docs/CONTRACTS.md": "target says\n"},
           shared=["docs/CONTRACTS.md"])
    (src_repo / "docs/CONTRACTS.md").write_text("target says\n")
    git(src_repo, "commit", "-qam", "target moved on")
    before = git(src_repo, "rev-parse", "HEAD")
    rep = results.integrate(b, dirs, src_repo, merge=True, apply=True, lint=False)
    lanes = rep["lanes"]
    assert lanes["alpha"]["integrated"] is None and any(h.startswith("merge conflict") for h in lanes["alpha"]["held"])
    assert lanes["beta"]["integrated"] is None
    assert "a dependency was not merged" in lanes["beta"]["held"]
    assert rep["merged"] == ["alpha: conflict, aborted"]
    assert git(src_repo, "rev-parse", "HEAD") == before, "nothing of alpha reached the target"
    assert not (src_repo / "solvers/crypto/alpha.py").exists() and not (src_repo / "solvers/crypto/beta.py").exists()


@pytest.mark.parametrize("lint", [True, False])
def test_engine_id_the_target_already_uses_elsewhere_is_held(src_repo, dirs, fake_venv, lint):
    b = make([lane_def("dupid")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "dupid", engine_files("dupid", eid="crypto.existing"),
           engines=[{"id": "crypto.existing", "manifest": "solvers/crypto/dupid.manifest.toml"}])
    rep = results.integrate(b, dirs, src_repo, lint=lint)
    assert rep["lanes"]["dupid"]["integrated"] is None
    assert ("engine id crypto.existing already used by solvers/crypto/existing.manifest.toml in the target"
            in rep["lanes"]["dupid"]["held"])


def test_lane_editing_the_targets_own_manifest_is_not_an_id_collision(src_repo, dirs, fake_venv):
    b = make([lane_def("exist", owns=["solvers/crypto/existing*", "tests/test_exist.py"])])
    setup(src_repo, b, dirs, fake_venv)
    files = {"solvers/crypto/existing.manifest.toml": manifest("crypto.existing", "existing", keyword="newword"),
             "tests/test_exist.py": "def test_x():\n    assert 3 > 2\n"}
    finish(b, dirs, "exist", files,
           engines=[{"id": "crypto.existing", "manifest": "solvers/crypto/existing.manifest.toml"}])
    rep = results.integrate(b, dirs, src_repo, lint=False)
    assert rep["lanes"]["exist"]["held"] == [] and rep["lanes"]["exist"]["integrated"] == "ready"


def test_one_lane_declaring_a_capability_key_twice_is_held(src_repo, dirs, fake_venv):
    b = make([lane_def("twice"), lane_def("other")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "twice", engine_files("twice"), caps=[("Crypto", "twice", "a"), ("Misc", "twice", "b")])
    finish(b, dirs, "other", engine_files("other"), caps=[("Crypto", "other", "c")])
    rep = results.integrate(b, dirs, src_repo, lint=False, apply=True)
    assert rep["lanes"]["twice"]["integrated"] is None
    assert "capability key twice declared twice" in rep["lanes"]["twice"]["held"]
    assert not any("also claimed" in h for h in rep["lanes"]["twice"]["held"])
    assert rep["lanes"]["other"]["integrated"] == "ready"
    assert rep["capabilities_applied"] == ["Crypto: other"]


def test_protected_glob_blocks_a_declared_shared_file(src_repo, dirs, fake_venv):
    b = bl.parse({"batch": "ib", "base": "main", "protected": ["ctf/platform/*"], "lanes": [lane_def("alpha")]})
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", {**engine_files("alpha"), "ctf/platform/x.py": "x = 1\n", "ctf/other.py": "y = 1\n"},
           shared=["ctf/platform/x.py", "ctf/other.py"])
    rep = results.check_lane(b, dirs, "alpha")
    assert "changed protected file ctf/platform/x.py" in rep.problems
    assert rep.warnings == ["declared shared file ctf/other.py"], "a shared file outside the glob is only a warning"
    assert results.integrate(b, dirs, src_repo, lint=False)["lanes"]["alpha"]["held"] == ["lane checks failed"]


def test_merge_refuses_a_dirty_or_detached_target(src_repo, dirs, fake_venv):
    b = make([lane_def("alpha")])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", engine_files("alpha"))
    (src_repo / "AGENTS.md").write_text("local edit\n")
    with pytest.raises(co.CheckoutError, match="uncommitted changes"):
        results.integrate(b, dirs, src_repo, merge=True)
    git(src_repo, "checkout", "-q", "AGENTS.md")
    git(src_repo, "checkout", "-q", "--detach")
    with pytest.raises(co.CheckoutError, match="HEAD is detached"):
        results.integrate(b, dirs, src_repo, merge=True)


def test_cli_integrate_reports_and_exits_nonzero_when_held(src_repo, dirs, fake_venv, tmp_path):
    import subprocess
    import sys

    import yaml

    from ctf import paths
    data = {"batch": "ib", "base": "main", "lanes": [lane_def("alpha"), lane_def("beta")]}
    bfile = tmp_path / "b.yaml"
    bfile.write_text(yaml.safe_dump(data))
    b = make(data["lanes"])
    setup(src_repo, b, dirs, fake_venv)
    finish(b, dirs, "alpha", engine_files("alpha"), caps=[("Crypto", "alpha", "Alpha")])
    finish(b, dirs, "beta", engine_files("beta"), caps=[("Crypto", "rsa_old", "dup")])
    r = subprocess.run([sys.executable, "-m", "ctf", "lanes", "integrate", str(bfile), "--target", str(src_repo),
                        "--lanes-dir", str(dirs.root.parent), "--apply"], cwd=paths.repo_root(),
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "alpha                    ready" in r.stdout
    assert "beta                     held" in r.stdout and "capability key rsa_old already in" in r.stdout
    assert "CAPABILITIES += Crypto: alpha" in r.stdout
    assert "- Alpha (`alpha`)" in (src_repo / "docs/CAPABILITIES.md").read_text()
