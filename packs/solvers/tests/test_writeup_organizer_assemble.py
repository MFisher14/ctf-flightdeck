"""Tests for the event-agnostic organizer writeup assembler and its brief templates.

docs/writeups/organizer/assemble.py was carried from CSCTF 2026 with the hardcoded flag regex, URL
allowlist and template path lifted into writeups/<event>/event.json. Every fixture here is a synthetic
event folder built in tmp_path; no real event data is read.
"""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

DIR = Path(__file__).resolve().parents[1] / "docs" / "writeups" / "organizer"
_spec = importlib.util.spec_from_file_location("organizer_assemble", DIR / "assemble.py")
asm = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = asm  # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(asm)

MY_BRIEFS = ["REPRO_BRIEF.md", "REVIEW_BRIEF.md", "VERIFY_BRIEF.md"]
FLAG = "ZZCTF{" + "real_value_1234" + "}"


def make_event(tmp_path, *, writeup=None, redact=True, flag_format="ZZCTF{...}", with_template=True):
    ev = tmp_path / "2099-zz"
    (ev / "cards").mkdir(parents=True)
    tpl = tmp_path / "template.md"
    if with_template:
        tpl.write_text(
            "# Template\n\nIntro text.\n\n## Challenge writeups\n\n"
            "## Web\n\n### Alpha\n\n### Ghost\n\n"
            "## Rev\n\n### Beta\n\n"
            "## Crypto\n\n### Gamma\n"
        )
    wr = {"organizer_template": str(tpl), "url_allowlist": ["example.org", "github.com/team/"]}
    wr.update(writeup or {})
    (ev / "event.json").write_text(json.dumps({
        "name": "ZZ CTF 2099", "flag_format": flag_format, "redact_flags": redact, "writeup": wr}))
    (ev / "HEADER.md").write_text("# ZZ team writeup\n\n## Challenge writeups\n")
    (ev / "solves.json").write_text(json.dumps([
        {"id": 1, "name": "Alpha", "solver": "a"},
        {"id": 2, "name": "Beta", "solver": "b"},
        {"id": 3, "name": "Gamma", "solver": "c"},
        {"id": 4, "name": "Delta", "solver": "d"},  # credited but not in the template
    ]))
    (ev / "cards" / "1-alpha.md").write_text("### Alpha\n\nAlpha body.\n")
    (ev / "cards" / "2.md").write_text("### Beta\n\nBeta body.\n")
    (ev / "cards" / "4-delta.md").write_text("### Delta\n\nDelta body.\n")
    # card 3 (Gamma) is deliberately missing
    return ev


# ---------------------------------------------------------------- build

def test_build_orders_by_template_and_aliases_rev(tmp_path):
    cfg = asm.load_event(make_event(tmp_path))
    r = asm.build(cfg)
    assert r.used == [1, 2]
    assert r.missing == ["3 Gamma"]
    assert r.unplaced == ["4 Delta"]
    assert r.text.startswith("# ZZ team writeup")
    # template order (Web then Rev), Rev renamed via the default alias, Ghost (no solve) skipped
    assert r.text.index("## Web") < r.text.index("Alpha body") < r.text.index("## Reverse engineering")
    assert r.text.index("## Reverse engineering") < r.text.index("Beta body")
    assert "Ghost" not in r.text and "## Crypto" not in r.text and "Delta" not in r.text
    assert not r.ok  # a missing card fails the build


def test_category_aliases_come_from_config(tmp_path):
    cfg = asm.load_event(make_event(tmp_path, writeup={"category_aliases": {"web": "Web exploitation"}}))
    text = asm.build(cfg).text
    assert "## Web exploitation" in text
    assert "## Rev\n" in text  # the default alias is replaced, not merged


def test_build_without_template_fails_loudly(tmp_path):
    ev = make_event(tmp_path, writeup={"organizer_template": None})
    with pytest.raises(asm.ConfigError, match="no template"):
        asm.build(asm.load_event(ev))
    ev2 = make_event(tmp_path / "b", with_template=False)
    with pytest.raises(asm.ConfigError, match="template not found"):
        asm.build(asm.load_event(ev2))


def test_template_without_marker_fails(tmp_path):
    ev = make_event(tmp_path, writeup={"template_marker": "## Not there"})
    with pytest.raises(asm.ConfigError, match="section marker"):
        asm.build(asm.load_event(ev))


def test_strip_checks_removes_multiline_check(tmp_path):
    ev = make_event(tmp_path)
    (ev / "cards" / "1-alpha.md").write_text("### Alpha\n\nBody.\n<!-- CHECK: confirm\nthe port -->\n")
    cfg = asm.load_event(ev)
    kept = asm.build(cfg)
    assert any(f.kind == "open-check" and f.blocking for f in kept.findings)
    stripped = asm.build(cfg, strip_checks=True)
    assert "CHECK" not in stripped.text
    assert not any(f.kind == "open-check" for f in stripped.findings)


# ---------------------------------------------------------------- lint

def test_flag_regex_derived_from_flag_format(tmp_path):
    cfg = asm.load_event(make_event(tmp_path))
    kinds = [f.kind for f in asm.lint_text(f"got {FLAG} here", cfg)]
    assert kinds == ["flag"]
    # the format template itself is not a leak, and another event's prefix is not this event's flag
    assert asm.lint_text("format ZZCTF{...} or ZZCTF{<answer>}; other CSCTF{abc}", cfg) == []


def test_flag_is_masked_in_findings(tmp_path):
    cfg = asm.load_event(make_event(tmp_path))
    (f,) = asm.lint_text(FLAG, cfg)
    assert "real_value_1234" not in str(f)


def test_redact_flags_false_notes_but_does_not_block(tmp_path):
    cfg = asm.load_event(make_event(tmp_path, redact=False))
    (f,) = asm.lint_text(FLAG, cfg)
    assert f.kind == "flag" and not f.blocking
    cfg2 = asm.load_event(make_event(tmp_path / "b", redact=True))
    assert asm.lint_text(FLAG, cfg2)[0].blocking


def test_missing_redact_flags_is_treated_as_redact(tmp_path):
    ev = make_event(tmp_path)
    data = json.loads((ev / "event.json").read_text())
    del data["redact_flags"]
    (ev / "event.json").write_text(json.dumps(data))
    assert asm.lint_text(FLAG, asm.load_event(ev))[0].blocking


def test_flag_regex_override(tmp_path):
    cfg = asm.load_event(make_event(tmp_path, writeup={"flag_regex": r"flag\{[^}]*\}"}))
    assert [f.kind for f in asm.lint_text("flag{abc} ZZCTF{xyz}", cfg)] == ["flag"]
    assert asm.lint_text("flag{...}", cfg) == []


def test_bad_flag_format_needs_override(tmp_path):
    with pytest.raises(asm.ConfigError, match="flag_regex"):
        asm.load_event(make_event(tmp_path, flag_format="any 32 hex chars"))


@pytest.mark.parametrize("url,allowed", [
    ("https://example.org", True),
    ("https://example.org/writeups/a", True),
    ("http://example.org:8080/x", True),
    ("https://example.org.evil.net/", False),   # the CSCTF lookahead allowed this
    ("https://notexample.org/", False),
    ("https://github.com/team/repo", True),
    ("https://github.com/teammate/repo", False),
    ("https://github.com/other", False),
])
def test_url_allowlist_boundaries(url, allowed):
    assert asm.url_allowed(url, ["example.org", "github.com/team/"]) is allowed


def test_lint_blocks_unlisted_url_ip_jwt_uuid(tmp_path):
    cfg = asm.load_event(make_event(tmp_path))
    text = ("see https://example.org/a and https://instance.zz:31337/\n"
            "host 10.1.2.3\n"
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig\n"
            "id 123e4567-e89b-12d3-a456-426614174000\n")
    found = {(f.kind, f.line) for f in asm.lint_text(text, cfg) if f.blocking}
    assert found == {("url", 1), ("ipv4", 2), ("jwt", 3), ("uuid", 4)}


def test_cli_exit_codes(tmp_path, capsys):
    ev = make_event(tmp_path)
    clean = tmp_path / "clean.md"
    clean.write_text("nothing to see at https://example.org/\n")
    dirty = tmp_path / "dirty.md"
    dirty.write_text(f"{FLAG}\n")
    assert asm.main(["lint", "--event-dir", str(ev), str(clean)]) == 0
    assert asm.main(["lint", "--event-dir", str(ev), str(dirty)]) == 1
    assert "real_value_1234" not in capsys.readouterr().out
    assert asm.main(["lint", "--event-dir", str(tmp_path / "nope"), str(clean)]) == 2
    out = tmp_path / "built.md"
    assert asm.main(["build", "--event-dir", str(ev), "--out", str(out)]) == 1  # card 3 missing
    assert out.read_text().startswith("# ZZ team writeup")
    (ev / "cards" / "3.md").write_text("### Gamma\n\nGamma body.\n")
    assert asm.main(["build", "--event-dir", str(ev), "--out", str(out)]) == 0


# ---------------------------------------------------------------- briefs

FULL_WRITEUP = {
    "context": "We placed first.",
    "workspace_glob": "workspace/<id>-*/",
    "model_card": "The Alpha card",
    "sources": ["attempt logs in workspace/<id>-*/tried.json", "notes.md"],
}


@pytest.mark.parametrize("name", MY_BRIEFS)
def test_brief_declares_exactly_what_it_uses(name):
    text = (DIR / name).read_text()
    m = re.match(r"\A<!-- config: ([^>]*?) -->\n", text)
    assert m, f"{name} must open with a config declaration"
    declared = {k.strip() for k in m.group(1).split(",")}
    body = asm.LEADING_COMMENTS_RX.sub("", text, count=1)
    used = {f"{a}.{b}" for a, b in asm.PLACEHOLDER_RX.findall(body)}
    assert used == declared


@pytest.mark.parametrize("name", MY_BRIEFS)
def test_brief_body_has_no_csctf_residue(name):
    body = asm.LEADING_COMMENTS_RX.sub("", (DIR / name).read_text(), count=1)
    for pat in [r"CSCTF", r"Chronos", r"secret\.team", r"Velora", r"\b9\d{3}\b", r"/private/tmp",
                r"Downloads", r"devzip", r"\.dev\b", r"~/\.codex", r"~/\.claude", r"won 1st",
                r"[0-9a-f]{8}-[0-9a-f]{4}-"]:
        assert not re.search(pat, body), f"{name}: {pat}"


@pytest.mark.parametrize("which", ["REPRO", "REVIEW", "VERIFY"])
def test_render_brief_fills_every_placeholder(tmp_path, which):
    cfg = asm.load_event(make_event(tmp_path, writeup=FULL_WRITEUP))
    text = asm.render_brief(which, cfg)
    assert "{{" not in text and "config:" not in text.splitlines()[0]
    assert text.startswith("# ")
    assert "ZZ CTF 2099" in text and "We placed first." in text


def test_render_brief_lists_and_paths(tmp_path):
    ev = make_event(tmp_path, writeup=FULL_WRITEUP)
    cfg = asm.load_event(ev)
    verify = asm.render_brief("VERIFY", cfg)
    assert "- attempt logs in workspace/<id>-*/tried.json\n- notes.md" in verify
    assert f"{ev.resolve()}/solves.json" in verify
    review = asm.render_brief("review_brief.md", cfg)
    assert str(tmp_path / "template.md") in review


def test_render_brief_missing_key_names_it(tmp_path):
    cfg = asm.load_event(make_event(tmp_path, writeup={"context": "x", "workspace_glob": "w/"}))
    with pytest.raises(asm.ConfigError, match=r"writeup\.model_card"):
        asm.render_brief("REPRO", cfg)
    with pytest.raises(asm.ConfigError, match=r"writeup\.sources"):
        asm.render_brief("VERIFY", cfg)
    with pytest.raises(asm.ConfigError, match="unknown brief"):
        asm.render_brief("NOPE", cfg)
