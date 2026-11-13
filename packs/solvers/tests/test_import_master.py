"""Tests for tools/migrate/import_master.py: the rules that decide what enters the master tree.

Pure-function tests on synthetic paths; nothing here reads the source repos or the analysis tree.
"""
import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "import_master", Path(__file__).resolve().parents[1] / "tools/migrate/import_master.py")
im = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(im)


@pytest.mark.parametrize("rel, rule", [
    ("workspace/9061-x/flag.txt", "never-import dir workspace/"),
    ("solvers/web/__pycache__/a.cpython-312.pyc", "never-import dir __pycache__/"),
    (".ctf/config.example.json", "never-import dir .ctf/"),
    ("writeups-public/day1/README.md", "never-import writeups*/"),
    ("docs/writeups/organizer/assemble.py", "never-import docs/writeups/"),
    ("tests/fixtures/day27_mobile_splits/d25_set6_native.apk",
     "never-import real challenge files (synthetic in the master, R-04)"),
    ("tests/fixtures/day27_mobile_splits/truths.json",
     "never-import real challenge files (synthetic in the master, R-04)"),
    ("Claude outputs/x.md", "never-import dir Claude outputs/"),
    ("tools/token", "credential-shaped file name"),
    ("ctf/session.cookies", "credential-shaped file name"),
    ("conf/.env.local", "credential-shaped file name"),
    (".claude/settings.local.json", "credential-shaped file name"),
    ("blackout.py", "event-specific root file"),
    ("builder9c.py", "event-specific root file"),
    ("codex_result-.md", "event-specific root file"),
    (".gitignore", "source root .gitignore (master keeps its own)"),
    ("dashboard/csctf/src/worker.mjs", "event-specific dashboard/"),
])
def test_never_rule_excludes(rel, rule):
    assert im.never_rule(rel, None) == rule


@pytest.mark.parametrize("rel", [
    "solvers/toolkits/token_depth.py",      # 'token' inside a code name is not a credential file
    "tests/test_writeups_lint.py",          # a file named writeups*, not a writeups*/ directory
    "solvers/blackout.py",                  # event root names only apply at the root
    "solvers/web/fixtures/.gitignore",      # only the root .gitignore is the master's own
    "tests/day27_mobile_splits_lib.py",     # the synthetic builder shares the stem, not the fixture folder
])
def test_never_rule_keeps_code(rel):
    assert im.never_rule(rel, None) is None


def test_never_rule_rejects_oversize_and_symlink(tmp_path):
    big = tmp_path / "big.bin"
    with big.open("wb") as f:
        f.truncate(im.MAX_BYTES + 1)
    assert im.never_rule("solvers/big.bin", big) == "file over 10 MB"
    small = tmp_path / "small.bin"
    small.write_bytes(b"x")
    link = tmp_path / "link.bin"
    link.symlink_to(small)
    assert im.never_rule("solvers/link.bin", link) == "symlink"
    assert im.never_rule("solvers/small.bin", small) is None


def test_agent_config_goes_to_legacy_names_no_harness_loads():
    assert im.agent_target("csctf", ".claude/skills/wave/SKILL.md") == \
        "events/csctf/legacy-agent-config/dot-claude/skills/wave/SKILL.md"
    assert im.agent_target("huntress", "CLAUDE.md") == "events/huntress/legacy-agent-config/CLAUDE.legacy.md"
    assert im.agent_target("csctf", "AGENTS.md") == "events/csctf/legacy-agent-config/AGENTS.legacy.md"
    assert im.agent_target("csctf", ".codex/config.toml") == "events/csctf/legacy-agent-config/dot-codex/config.toml"
    assert im.agent_target("csctf", "docs/CLAUDE.md") is None
    for rel in (".claude/x", ".codex/y", "CLAUDE.md", "AGENTS.md"):
        target = im.agent_target("csctf", rel)
        parts = target.split("/")
        assert ".claude" not in parts and ".codex" not in parts
        assert parts[-1] not in ("CLAUDE.md", "AGENTS.md")


def _decision(path, action="archive"):
    return im.Decision("g", path, action, "r", None)


def test_decision_exact_and_patterns():
    assert _decision("solvers/web/xxe_read.py").exact
    d = _decision("tools/launchd/")
    assert d.matches("tools/launchd/a.plist") and not d.matches("tools/launchd.py")
    g = _decision(".claude/agents/lane-*.md")
    assert g.matches(".claude/agents/lane-owner.md") and not g.matches(".claude/agents/solver.md")


def test_decision_comma_list_with_trailing_note():
    d = _decision("solvers/web/d22_*,d23_*,d31_* (49 Huntress day one-offs)")
    assert d.matches("solvers/web/d22_probe.py")
    assert d.matches("solvers/web/d31_chain.py")
    assert not d.matches("solvers/web/d24_x.py")
    assert not d.matches("solvers/web/deser_detect.py")


def test_decision_brace_list_matches_stems_and_globs():
    d = _decision("solvers/web/{webdepth_*,*_jail_planner,api_protocols} (3 engines)", "keep_both")
    assert d.matches("solvers/web/webdepth_cache.py")
    assert d.matches("solvers/web/py_jail_planner.py")
    assert d.matches("solvers/web/api_protocols.py")
    assert not d.matches("solvers/web/api_protocols_extra.py")
    assert not d.matches("solvers/web/proof_hunt.py")


def test_more_specific_pattern_wins():
    broad, narrow = _decision("tests/fixtures/"), _decision("tests/fixtures/native_image/", "take_huntress")
    assert narrow.specificity() > broad.specificity()


@pytest.mark.parametrize("reason, have, side", [
    ("Take pink's version verbatim (enum has no take_pink)", {"csctf": 1, "pink": 1}, "pink"),
    ("conflict: Base on huntress (ledger needed), add csctf show()", {"csctf": 1, "huntress": 1}, "huntress"),
    ("Keep Huntress's file in the adapter, but edit it first", {"csctf": 1, "huntress": 1}, "huntress"),
    ("csctf base for the token and rebrand, but restore Huntress labels", {"csctf": 1, "huntress": 1}, "csctf"),
    ("unclear wording", {"csctf": 1, "huntress": 1}, "csctf"),
    ("Base on huntress", {"csctf": 1}, "csctf"),             # only one side exists: that side
    ("anything", {"huntress": 1}, "huntress"),
])
def test_hand_merge_start_side(reason, have, side):
    assert im.start_side(reason, have) == side


def test_batches_respect_caps_and_keep_affinity_groups_together():
    queue = {}
    for i in range(23):
        queue[f"tests/test_web_case{i:02d}.py"] = {"live_delta": False}
    for p in ("solvers/web/a.py", "solvers/web/b.py", "solvers/web/c.py", "solvers/web/d.py", "solvers/web/e.py"):
        queue[p] = {"live_delta": False}
    for p in ("ctf/submit.py", "tests/test_submit_guard.py", "ctf/client.py", "ctf/workspace.py"):
        queue[p] = {"live_delta": True}
    batches = im.make_batches(queue)
    cap = {"test": 10, "code": 4, "live-delta": 5}
    assert all(len(b["files"]) <= cap[b["kind"]] for b in batches)
    assert sorted(f for b in batches for f in b["files"]) == sorted(queue)
    assert [b["id"] for b in batches] == [f"hm-{i:02d}" for i in range(1, len(batches) + 1)]
    guard = [b for b in batches if "ctf/submit.py" in b["files"]]
    assert len(guard) == 1 and set(guard[0]["files"]) == {
        "ctf/submit.py", "tests/test_submit_guard.py", "ctf/client.py", "ctf/workspace.py"}
    assert guard[0]["kind"] == "live-delta"
    assert batches[0]["kind"] == "live-delta"
    assert sum(1 for b in batches if b["subsystem"] == "tests-web") == 3


def test_plan_refuses_protected_paths(tmp_path):
    src = tmp_path / "f"
    src.write_text("x")
    plan = im.Plan()
    for target in ("BUILD-PLAN.md", ".githooks/pre-commit", "analysis/x.py", "CLAUDE.md",
                   "docs/migration/BASELINE.md", "tests/test_import_master.py"):
        with pytest.raises(im.ImportError_):
            plan.add(target, "csctf", "f", src, "t")
    plan.add("solvers/x.py", "csctf", "f", src, "t")
    assert "solvers/x.py" in plan.files


def test_plan_refuses_two_different_sources_for_one_path(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_text("one")
    b.write_text("two")
    plan = im.Plan()
    plan.add("tools/x.py", "csctf", "x", a, "t")
    with pytest.raises(im.ImportError_):
        plan.add("tools/x.py", "huntress", "x", b, "t")


# --- commit-guard pass ---------------------------------------------------------------------------
GUARD = im.load_guard()
FAKE_HOST_LABEL = b"made-up-host-label"          # synthetic stand-in for a denylisted value
FAKE_KEY_NAME = b"made_up_config_key"


def _redactor(monkeypatch):
    import hashlib
    host_h = hashlib.sha256(FAKE_HOST_LABEL).hexdigest()
    key_h = hashlib.sha256(FAKE_KEY_NAME).hexdigest()
    monkeypatch.setattr(im, "DENY_REPLACE", {
        host_h[:8]: {"what": "host", "to": "ctf-platform", "tld": ("ro", "example")},
        key_h[:8]: {"what": "key", "to": "renamed_key"},
    })
    return im.Redactor(GUARD, {host_h, key_h})


def test_redactor_replaces_denylisted_values_everywhere_and_swaps_the_tld(monkeypatch):
    red = _redactor(monkeypatch)
    src = (b'URL = "https://2026.' + FAKE_HOST_LABEL + b'.ro"\n'
           b'odd = "2026\xe3\x80\x82' + FAKE_HOST_LABEL + b'\xe3\x80\x82ro"\n'
           b'mail = "x@' + FAKE_HOST_LABEL + b'.ro"\n'
           b'cfg.' + FAKE_KEY_NAME + b' = 3\n')
    red.discover("a.py", src)
    out = red.apply("a.py", src)
    assert FAKE_HOST_LABEL not in out and FAKE_KEY_NAME not in out
    assert b'"https://2026.ctf-platform.example"' in out
    assert b"2026\xe3\x80\x82ctf-platform\xe3\x80\x82example" in out
    assert b"x@ctf-platform.example" in out
    assert b"cfg.renamed_key = 3" in out
    # a file where the value only occurs inside a longer token is still cleaned once discovered
    other = b"prefix-" + FAKE_HOST_LABEL + b"-suffix"
    assert FAKE_HOST_LABEL not in red.apply("b.txt", other)
    assert red.text("note about " + FAKE_KEY_NAME.decode()) == "note about renamed_key"


def test_redactor_fails_on_unknown_denylisted_value(monkeypatch):
    import hashlib
    monkeypatch.setattr(im, "DENY_REPLACE", {})
    red = im.Redactor(GUARD, {hashlib.sha256(FAKE_KEY_NAME).hexdigest()})
    with pytest.raises(im.ImportError_, match="no replacement rule"):
        red.discover("a.py", b"x = '" + FAKE_KEY_NAME + b"'\n")


def test_redactor_refuses_binary_hits(monkeypatch):
    red = _redactor(monkeypatch)
    with pytest.raises(im.ImportError_, match="binary"):
        red.discover("blob.bin", b"\0\0" + FAKE_KEY_NAME + b"\0")


AKIA_FAKE = b"AKIA" + b"IOSFODNN7EXAMPLE"     # AWS's documented example key, assembled at run time
AKIA_REAL_LOOKING = b"AKIA" + b"Q7Z2M4K9W1R8P3X6"   # invented; no fake marker, so treated as real


def test_pragma_goes_on_python_code_lines_with_hash():
    src = b'KEY = "' + AKIA_FAKE + b'"\nprint(KEY)\n'
    out, notes = im.add_pragmas("tests/test_x.py", src, GUARD)
    assert out.split(b"\n")[0].endswith(b"# secret-scan: allow")
    assert out.split(b"\n")[1] == b"print(KEY)"
    assert GUARD.scan("tests/test_x.py", out, set())[0] == []
    assert GUARD.scan("tests/test_x.py", src, set())[0] != []      # the guard did block it before


def test_pragma_inside_a_string_needs_the_embedded_language_comment(monkeypatch):
    src = b'JS = """\nconst k = "' + AKIA_FAKE + b'";\n"""\n'
    with pytest.raises(im.ImportError_, match="inside a multi-line string"):
        im.add_pragmas("tests/test_js.py", src, GUARD)
    monkeypatch.setitem(im.PRAGMA_STYLE_OVERRIDE, "tests/test_js.py", "//")
    out, _ = im.add_pragmas("tests/test_js.py", src, GUARD)
    assert b'const k = "' + AKIA_FAKE + b'";  // secret-scan: allow' in out
    assert out.endswith(b'"""\n')


def test_pragma_json_key_form_keeps_valid_json(monkeypatch):
    import json
    src = b'{\n "a": {\n  "id": "' + AKIA_FAKE + b'",\n  "user": "u"\n }\n}\n'
    monkeypatch.setitem(im.PRAGMA_STYLE_OVERRIDE, "f.json", "json-key")
    out, _ = im.add_pragmas("f.json", src, GUARD)
    assert json.loads(out)["a"]["id"] == AKIA_FAKE.decode()
    assert GUARD.scan("f.json", out, set())[0] == []


def test_real_looking_value_drops_the_file():
    out, notes = im.add_pragmas("tests/test_y.py", b'K = "' + AKIA_REAL_LOOKING + b'"\n', GUARD)
    assert out is None and "known-fake" in notes[0]
