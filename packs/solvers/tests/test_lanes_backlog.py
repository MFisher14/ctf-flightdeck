"""B-179: the lane backlog (YAML/TOML), structural checks, and the self-contained prompt pack."""
from __future__ import annotations

import copy
import json
import re
import textwrap

import pytest

from ctf import paths
from ctf.lanes import backlog as bl
from ctf.lanes import layout, prompt, results

YAML = textwrap.dedent("""\
    batch: crypto-r3
    base: main
    concurrency: 2
    timeout_minutes: 30
    preamble: Batch-wide note about the crypto lane.
    context: [docs/CONTRACTS.md]
    codex:
      model: gpt-test
      effort: high
    lanes:
      - id: alpha
        title: Alpha engine
        goal: Build the alpha engine.
        acceptance: [alpha decodes the sample, alpha has a manifest]
        owns: [solvers/crypto/alpha*.py, solvers/crypto/alpha.manifest.toml, tests/test_crypto_alpha.py]
        tests: [tests/test_crypto_alpha.py]
      - id: beta
        title: Beta engine
        goal: Build beta on top of alpha.
        acceptance: [beta works]
        owns: [solvers/crypto/beta.py, tests/test_crypto_beta.py]
        tests: [tests/test_crypto_beta.py]
        depends: [alpha]
        notes: Beta specific note.
    """)

TOML = textwrap.dedent("""\
    batch = "crypto-r3"
    base = "main"
    concurrency = 2
    timeout_minutes = 30
    preamble = "Batch-wide note about the crypto lane."
    context = ["docs/CONTRACTS.md"]
    [codex]
    model = "gpt-test"
    effort = "high"
    [[lanes]]
    id = "alpha"
    title = "Alpha engine"
    goal = "Build the alpha engine."
    acceptance = ["alpha decodes the sample", "alpha has a manifest"]
    owns = ["solvers/crypto/alpha*.py", "solvers/crypto/alpha.manifest.toml", "tests/test_crypto_alpha.py"]
    tests = ["tests/test_crypto_alpha.py"]
    [[lanes]]
    id = "beta"
    title = "Beta engine"
    goal = "Build beta on top of alpha."
    acceptance = ["beta works"]
    owns = ["solvers/crypto/beta.py", "tests/test_crypto_beta.py"]
    tests = ["tests/test_crypto_beta.py"]
    depends = ["alpha"]
    notes = "Beta specific note."
    """)


def base_data():
    import yaml
    return yaml.safe_load(YAML)


def lane(**kw):
    d = {"id": "x", "title": "X", "goal": "do x", "acceptance": ["x ok"], "owns": ["solvers/x.py", "tests/test_x.py"],
         "tests": ["tests/test_x.py"]}
    d.update(kw)
    return d


def test_yaml_and_toml_backlogs_load_identically(tmp_path):
    (tmp_path / "b.yaml").write_text(YAML)
    (tmp_path / "b.toml").write_text(TOML)
    y = bl.load(tmp_path / "b.yaml")
    t = bl.load(tmp_path / "b.toml")
    assert y.batch == "crypto-r3" and y.base == "main" and y.concurrency == 2 and y.timeout_minutes == 30
    assert y.codex == bl.CodexOpts(model="gpt-test", effort="high")
    assert y.lane("beta").depends == ("alpha",)
    assert y.protected == ("docs/CAPABILITIES.md",)
    assert (y.lanes, y.codex, y.preamble, y.context) == (t.lanes, t.codex, t.preamble, t.context)
    assert y.branch("beta") == "lane/crypto-r3/beta"


def test_defaults(tmp_path):
    d = base_data()
    del d["concurrency"], d["timeout_minutes"], d["codex"]
    b = bl.parse(d)
    assert b.concurrency == 4 and b.timeout_minutes == 120 and b.codex == bl.CodexOpts()


def test_dependency_order_puts_dependencies_first():
    d = base_data()
    d["lanes"].reverse()            # beta listed before alpha
    d["lanes"].append(lane(id="gamma", owns=["solvers/g.py", "tests/test_g.py"], tests=["tests/test_g.py"],
                           depends=["beta"]))
    order = bl.parse(d).order()
    assert order.index("alpha") < order.index("beta") < order.index("gamma")


@pytest.mark.parametrize("mutate, msg", [
    (lambda d: d.update(colour="red"), "unknown key(s) colour"),
    (lambda d: d["lanes"][0].update(colour="red"), "lanes[0]: unknown key(s) colour"),
    (lambda d: d["codex"].update(sandbox="x"), "codex: unknown key(s) sandbox"),
    (lambda d: d.pop("base"), "base: required key missing"),
    (lambda d: d["lanes"][0].pop("tests"), "lanes[0].tests: required key missing"),
    (lambda d: d["lanes"][0].update(acceptance=[]), "acceptance: must not be empty"),
    (lambda d: d.update(batch="Crypto R3"), "batch: 'Crypto R3' must match"),
    (lambda d: d["lanes"][0].update(id="Alpha_1"), "lanes[0].id: 'Alpha_1' must match"),
    (lambda d: d.update(concurrency=True), "concurrency: must be an integer"),
    (lambda d: d.update(concurrency=0), "concurrency: must be between 1 and 16"),
    (lambda d: d.update(concurrency=17), "concurrency: must be between 1 and 16"),
    (lambda d: d.update(base="--upload-pack=x"), "is not a git ref"),
    (lambda d: d["lanes"][1].update(id="alpha"), "duplicate lane id(s) alpha"),
    (lambda d: d["lanes"][1].update(depends=["nope"]), "unknown lane 'nope'"),
    (lambda d: d["lanes"][1].update(depends=["beta"]), "cannot depend on itself"),
    (lambda d: d["lanes"][0].update(depends=["beta"]), "dependency cycle"),
    (lambda d: d["lanes"][1].update(owns=["solvers/crypto/*.py", "tests/test_crypto_beta.py"]),
     "both own 'solvers/crypto/alpha*.py' / 'solvers/crypto/*.py'"),
    (lambda d: d["lanes"][1].update(owns=["tests/test_crypto_alpha.py", "tests/test_crypto_beta.py"]),
     "both own"),
    (lambda d: d["lanes"][0].update(owns=["docs/*.md", "tests/test_crypto_alpha.py"]),
     "covers protected path 'docs/CAPABILITIES.md'"),
    (lambda d: (d.update(protected=["ctf/triage.py"]),
                d["lanes"][0]["owns"].append("ctf/triage.py")), "covers protected path 'ctf/triage.py'"),
    (lambda d: d["lanes"][0].update(tests=["tests/test_other.py"]), "is not matched by the lane's owns"),
    (lambda d: d["lanes"][0].update(owns=["/etc/passwd", "tests/test_crypto_alpha.py"]), "repo-relative"),
    (lambda d: d["lanes"][0].update(owns=["../x.py", "tests/test_crypto_alpha.py"]), "repo-relative"),
    (lambda d: d["lanes"][0].update(context=["~/notes.md"]), "repo-relative"),
    (lambda d: d["codex"].update(extra=["--yolo"]), "refused codex argument --yolo"),
    (lambda d: d["codex"].update(extra=["-c", "service_tier=fast"]), "refused codex override"),
    (lambda d: d["codex"].update(strict_home="yes"), "strict_home: must be true or false"),
    (lambda d: d.update(lanes=[]), "lanes: must be a non-empty list"),
])
def test_structural_errors_are_named(mutate, msg):
    d = copy.deepcopy(base_data())
    mutate(d)
    with pytest.raises(bl.BacklogError) as ei:
        bl.parse(d, "b.yaml")
    assert msg in str(ei.value)
    assert str(ei.value).startswith("b.yaml: ")


def test_file_errors_are_named(tmp_path):
    with pytest.raises(bl.BacklogError, match="backlog file not found"):
        bl.load(tmp_path / "nope.yaml")
    (tmp_path / "b.json").write_text("{}")
    with pytest.raises(bl.BacklogError, match="must be .yaml, .yml or .toml"):
        bl.load(tmp_path / "b.json")
    (tmp_path / "bad.yaml").write_text("batch: [unclosed\n")
    with pytest.raises(bl.BacklogError, match="not valid YAML"):
        bl.load(tmp_path / "bad.yaml")
    (tmp_path / "bad.toml").write_text("batch = \n")
    with pytest.raises(bl.BacklogError, match="not valid TOML"):
        bl.load(tmp_path / "bad.toml")
    (tmp_path / "list.yaml").write_text("- a\n- b\n")
    with pytest.raises(bl.BacklogError, match="top level must be a table"):
        bl.load(tmp_path / "list.yaml")


def test_owns_path_matches_globs():
    b = bl.parse(base_data())
    a = b.lane("alpha")
    assert a.owns_path("solvers/crypto/alpha_tables.py")
    assert not a.owns_path("solvers/crypto/beta.py")


# ------------------------------------------------------------------------------------- the prompt

@pytest.fixture
def dirs(tmp_path):
    return layout.batch_dirs("crypto-r3", tmp_path / "lanes")


def test_batch_dirs_follow_ctf_lanes_dir_and_refuse_the_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_LANES_DIR", str(tmp_path / "L"))
    assert paths.lanes_root() == (tmp_path / "L").resolve()
    assert layout.batch_dirs("b1").root == (tmp_path / "L" / "b1").resolve()
    monkeypatch.delenv("CTF_LANES_DIR")
    assert paths.lanes_root() == paths.DEFAULT_LANES_BASE.expanduser().resolve()
    with pytest.raises(ValueError, match="inside the repo"):
        layout.batch_dirs("b1", paths.repo_root() / "lanes-state")


def test_prompt_is_self_contained(dirs):
    b = bl.parse(base_data())
    text = prompt.render(b, b.lane("beta"), dirs)
    co = dirs.checkout("beta")
    assert f"Checkout: {co}" in text
    assert "Branch: lane/crypto-r3/beta (created from main)" in text
    assert f"Python: {co}/.venv/bin/python" in text
    assert f"-m pytest -n 2 tests/test_crypto_beta.py" in text
    assert f"Write the result manifest to {dirs.result('beta')} as JSON" in text
    assert "beta works" in text and "Build beta on top of alpha." in text
    assert "Beta specific note." in text and "Batch-wide note about the crypto lane." in text
    assert "lane/crypto-r3/alpha (their finished work is merged" in text
    assert "- docs/CONTRACTS.md" in text and "- AGENTS.md" in text
    assert "Do not edit docs/CAPABILITIES.md" in text
    assert "Never edit protected files: docs/CAPABILITIES.md." in text
    assert text.rstrip().endswith("`LANE DONE beta` as your last message.")
    assert "{protected}" not in text
    # the JSON shape in the prompt is exactly what the result validator accepts
    block = re.search(r"```json\n(.*?)\n```", text, re.S).group(1)
    shown = json.loads(block)
    assert set(shown) == results._KEYS
    assert shown["lane"] == "beta" and shown["schema"] == results.SCHEMA
    filled = dict(shown, commit="abc1234", engines=[], capabilities=[])
    assert results.parse_result(filled, "beta").status == "built"


def test_prompt_with_no_dependencies_says_none(dirs):
    b = bl.parse(base_data())
    assert "Lanes this one depends on: none" in prompt.render(b, b.lane("alpha"), dirs)


@pytest.mark.parametrize("goal, msg", [
    ("Do what the previous prompt said.", "refers to text it does not contain"),
    ("Same as above lane, but for beta.", "refers to text it does not contain"),
    ("See lane alpha for details.", "refers to text it does not contain"),
    ("This is part 1 of 2; part two follows.", "refers to text it does not contain"),
    ("Use {{engine_name}} as the module.", "unfilled placeholder"),
    ("Use <<ENGINE>> as the module.", "unfilled placeholder"),
])
def test_prompt_check_refuses_external_references_and_placeholders(dirs, goal, msg):
    d = base_data()
    d["lanes"][0]["goal"] = goal
    b = bl.parse(d)
    with pytest.raises(prompt.PromptError, match=msg):
        prompt.render(b, b.lane("alpha"), dirs)


def test_prompt_check_requires_every_part(dirs):
    b = bl.parse(base_data())
    ln = b.lane("alpha")
    text = prompt.render(b, ln, dirs)
    for missing in (str(dirs.result("alpha")), "lane/crypto-r3/alpha", "alpha has a manifest",
                    "tests/test_crypto_alpha.py", "LANE DONE alpha"):
        with pytest.raises(prompt.PromptError, match="prompt lacks"):
            prompt.check(text.replace(missing, "X"), b, ln, dirs)


def test_write_pack_writes_each_prompt_and_the_pack(dirs):
    b = bl.parse(base_data())
    texts = prompt.write_pack(b, dirs)
    assert list(texts) == ["alpha", "beta"]
    for lid in texts:
        assert dirs.prompt(lid).read_text() == texts[lid]
    pack = (dirs.prompts / "PACK.md").read_text()
    assert "batch crypto-r3 (2 lanes, base main)" in pack
    assert pack.count("````markdown") == 2
    assert texts["alpha"].rstrip() in pack and texts["beta"].rstrip() in pack
    # a selection writes only those lanes
    other = layout.batch_dirs("crypto-r3", dirs.root.parent.parent / "other")
    assert list(prompt.write_pack(b, other, ["beta"])) == ["beta"]
    assert not other.prompt("alpha").exists()


def test_write_pack_writes_nothing_when_one_prompt_is_bad(dirs):
    d = base_data()
    d["lanes"][1]["goal"] = "See lane alpha."
    with pytest.raises(prompt.PromptError):
        prompt.write_pack(bl.parse(d), dirs)
    assert not dirs.prompts.exists()
