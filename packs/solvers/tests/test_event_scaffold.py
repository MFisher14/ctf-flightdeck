"""B-189: event profile scaffold (`ctf new-event`) and one policy generating CLAUDE.md and AGENTS.md
(`ctf check-event`). Platform reads use a fixture adapter module; nothing touches the network."""
from __future__ import annotations

import dataclasses
import datetime as _dt
import os
import shutil
import subprocess
import sys
import tomllib
import types
from pathlib import Path

import pytest

from ctf import env, event, eventrules, paths
from ctf import eventscaffold as sc
from ctf.cli import main as ctf_main
from ctf.platform import base as pbase

PAST = ("csctf", "huntress", "pink", "spooky")
SECRET = "tok-FIXTURE-never-printed-123"


def _clear_platform_env(monkeypatch):
    for canon in ("CTF_TOKEN", "CTF_PLATFORM_URL", "CTF_COOKIE"):
        for n in (canon, *env.legacy_names(canon)):
            monkeypatch.delenv(n, raising=False)


@pytest.fixture
def root(tmp_path, monkeypatch):
    _clear_platform_env(monkeypatch)
    r = tmp_path / "events"
    r.mkdir()
    return r


def new_event(root: Path, *argv: str) -> int:
    return ctf_main(["new-event", *argv, "--events-root", str(root)])


def check_event(root: Path, *argv: str) -> int:
    return ctf_main(["check-event", *argv, "--events-root", str(root)])


BASIC = ("--start", "2027-03-01T09:00:00Z", "--end", "2027-03-03T09:00:00Z")


# ------------------------------------------------------------------------------------------ renderer

def test_render_text_substitutes_and_gates():
    tpl = ("{{!-- dropped {{nope}} --}}\nA={{a}}\n{{#if on}}\nON\n{{else}}\nOFF\n{{/if}}\n"
           "{{#unless on}}\nNOT-ON\n{{/unless}}\nend ${{a}}\n")
    assert eventrules.render_text(tpl, {"a": "x", "on": True}) == "A=x\nON\nend $x\n"
    assert eventrules.render_text(tpl, {"a": "y", "on": False}) == "A=y\nOFF\nNOT-ON\nend $y\n"


def test_render_text_nested_blocks():
    tpl = "{{#if a}}\n{{#if b}}\nAB\n{{else}}\nA\n{{/if}}\nafter\n{{/if}}\n"
    assert eventrules.render_text(tpl, {"a": True, "b": True}) == "AB\nafter\n"
    assert eventrules.render_text(tpl, {"a": True, "b": False}) == "A\nafter\n"
    assert eventrules.render_text(tpl, {"a": False, "b": True}) == ""


@pytest.mark.parametrize("tpl,ctx,msg", [
    ("{{missing}}", {}, "does not define"),
    ("{{#if s}}x{{/if}}", {"s": "str"}, "must be a boolean"),
    ("{{v}}", {"v": True}, "must be a string"),
    ("{{#if a}}x", {"a": True}, "unclosed"),
    ("x{{/if}}", {}, "does not close"),
    ("{{#unless a}}x{{else}}y{{/unless}}", {"a": True}, "outside an"),
    ("a }} b", {}, "stray brace"),
    ("{{two words}}", {}, "unknown template tag"),
    ("{{!-- never closed", {}, "unterminated"),
])
def test_render_text_is_strict(tpl, ctx, msg):
    with pytest.raises(eventrules.TemplateError, match=msg):
        eventrules.render_text(tpl, ctx)


def test_template_with_file_specific_body_is_refused(tmp_path):
    src = eventrules.template_path().read_text()
    bad = tmp_path / "bad.tmpl"
    bad.write_text(src + "\nThis is {{agent_file}}.\n")
    with pytest.raises(eventrules.TemplateError, match="different rules for CLAUDE.md and AGENTS.md"):
        eventrules.render(event.load("csctf"), bad)


# ------------------------------------------------------------------------------------------ one policy, two files

def _body(text: str) -> str:
    return eventrules.split_header(text)[1]


@pytest.mark.parametrize("slug", PAST)
def test_both_files_share_one_body_and_name_themselves(slug):
    out = eventrules.render(event.load(slug))
    assert set(out) == {"CLAUDE.md", "AGENTS.md"}
    assert _body(out["CLAUDE.md"]) == _body(out["AGENTS.md"])
    assert "file=CLAUDE.md" in out["CLAUDE.md"] and "file=AGENTS.md" in out["AGENTS.md"]
    for text in out.values():
        assert "{{" not in text and "}}" not in text


def test_spooky_no_ai_on_infrastructure_rule_reaches_agents_md():
    # The regression this unit exists for: the rule was only in CLAUDE.md, so Codex never saw it.
    out = eventrules.render(event.load("spooky"))
    for name in ("CLAUDE.md", "AGENTS.md"):
        assert "No AI on the platform or the competition infrastructure" in out[name]
        assert "No live challenge hosts" in out[name]
        assert "Never submit a flag anywhere" in out[name]
        assert "Guarded auto-submit" not in out[name]


def _variant(base: event.EventProfile, **rules) -> event.EventProfile:
    return dataclasses.replace(base, rules=dataclasses.replace(base.rules, **rules))


def test_each_policy_field_changes_both_files():
    base = event.load("csctf")
    b = eventrules.render(base)["AGENTS.md"]
    assert "Guarded auto-submit is authorized" in b
    assert "`*.ctf-platform.example`" in b
    assert "No AI on the platform" not in b and "No live challenge hosts" not in b
    assert "Never buy or request a hint" in b
    assert "No state-changing web requests" in b

    cases = [
        (dict(submit_mode="confirm"), "Ask before every submission", "Guarded auto-submit"),
        (dict(submit_mode="manual"), "Never submit a flag anywhere", "Guarded auto-submit"),
        (dict(live_service_scope=()), "No live challenge hosts", "Live targets: only these hosts"),
        (dict(hints_allowed=True), "The event allows hints", "Never buy or request a hint"),
        (dict(web_state_changing=True), None, "No state-changing web requests"),
        (dict(wrong_answer_stop=5), "Stop and ask after 5 wrong", "Stop and ask after 3 wrong"),
        (dict(guess_budget=2), "Guess budget: 2", "Never guess or sweep"),
        (dict(flag_sharing="forbidden"), "Flags stay in the team", "does not forbid sharing"),
        (dict(ai_on_platform="forbidden", submit_mode="manual"), "No AI on the platform",
         "Platform only through the master's client"),
    ]
    for change, present, absent in cases:
        out = eventrules.render(_variant(base, **change))
        for name in ("CLAUDE.md", "AGENTS.md"):
            if present:
                assert present in out[name], (change, name)
            assert absent not in out[name], (change, name)


def test_flag_format_unknown_and_proof_render():
    base = event.load("huntress")
    out = eventrules.render(base)["CLAUDE.md"]
    assert "`flag{...}`" in out and base.proof.pattern in out and "$50 per challenge-day" in out
    unknown = dataclasses.replace(base, flag=dataclasses.replace(base.flag, prefixes=()), proof=None)
    out = eventrules.render(unknown)["AGENTS.md"]
    assert "Format: not known yet" in out and "Proof tokens" not in out


# ------------------------------------------------------------------------------------------ check

def _copy_event(root: Path, slug: str) -> Path:
    d = root / slug
    d.mkdir()
    shutil.copyfile(paths.event_dir(slug) / "event.toml", d / "event.toml")
    eventrules.write(event.load(slug, root), d)
    return d


def test_check_passes_on_fresh_files(root):
    d = _copy_event(root, "pink")
    assert eventrules.check(event.load("pink", root), d) == []


def test_check_reports_missing(root):
    d = _copy_event(root, "pink")
    (d / "AGENTS.md").unlink()
    probs = eventrules.check(event.load("pink", root), d)
    assert len(probs) == 1 and "AGENTS.md: missing" in probs[0]


def test_check_reports_stale_profile_but_not_comment_edits(root):
    d = _copy_event(root, "pink")
    toml = d / "event.toml"
    toml.write_text("# a new comment line only\n" + toml.read_text())
    assert eventrules.check(event.load("pink", root), d) == []
    toml.write_text(toml.read_text().replace('flag_sharing = "forbidden"', 'flag_sharing = "allowed"'))
    probs = eventrules.check(event.load("pink", root), d)
    assert len(probs) == 2 and all("stale: the profile changed" in p for p in probs)


def test_check_reports_stale_template(root, tmp_path):
    d = _copy_event(root, "csctf")
    tpl = tmp_path / "t.tmpl"
    tpl.write_text(eventrules.template_path().read_text().replace("## Budget", "## Spend budget"))
    probs = eventrules.check(event.load("csctf", root), d, tpl)
    assert len(probs) == 2 and all("stale: the template changed" in p for p in probs)


def test_check_reports_hand_edit_and_disagreement(root):
    d = _copy_event(root, "spooky")
    agents = d / "AGENTS.md"
    agents.write_text(agents.read_text().replace(
        "- **No live challenge hosts.**", "- **Live hosts are fine.**"))
    probs = eventrules.check(event.load("spooky", root), d)
    assert any("AGENTS.md: edited by hand" in p and "No live challenge hosts" in p for p in probs)
    assert any("CLAUDE.md and AGENTS.md carry different rules" in p for p in probs)
    assert not any("CLAUDE.md: " in p for p in probs)


def test_check_reports_file_for_another_event(root):
    d = _copy_event(root, "pink")
    shutil.copyfile(paths.event_dir("csctf") / "CLAUDE.md", d / "CLAUDE.md")
    probs = eventrules.check(event.load("pink", root), d)
    assert any("generated as CLAUDE.md for event 'csctf'" in p for p in probs)


# ------------------------------------------------------------------------------------------ shipped fixtures

def test_shipped_past_events_have_matching_agent_files(capsys):
    assert ctf_main(["check-event"]) == 0
    out = capsys.readouterr().out
    for slug in PAST:
        assert f"ok    {slug}" in out
        for name in ("CLAUDE.md", "AGENTS.md"):
            assert (paths.event_dir(slug) / name).is_file()


def test_check_event_cli_fails_and_names_the_problem(root, capsys):
    d = _copy_event(root, "huntress")
    _copy_event(root, "pink")
    (d / "CLAUDE.md").unlink()
    (root / "orphan").mkdir()
    (root / "orphan" / "AGENTS.md").write_text("x")
    assert check_event(root) == 1
    out = capsys.readouterr().out
    assert "FAIL  huntress:" in out and "CLAUDE.md: missing" in out
    assert "ok    pink" in out
    assert "FAIL  orphan:" in out and "no event.toml" in out
    assert check_event(root, "pink") == 0
    assert check_event(root, "nope") == 1
    assert "no event profile 'nope'" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------ new-event

def test_new_event_writes_valid_profile_and_both_files(root, capsys):
    rc = new_event(root, "acme", *BASIC, "--name", "ACME CTF", "--base-url", "https://ctf.acme.example",
                   "--flag-prefix", "ACME", "--category", "Web", "--category", "web", "--category", "Pwn",
                   "--sector", "energy", "--scope", "*.acme.example", "--team", "us")
    assert rc == 0
    prof = event.load("acme", root)
    assert prof.name == "ACME CTF" and prof.platform.kind == "ctfd"
    assert prof.platform.base_url == "https://ctf.acme.example" and prof.platform.team == "us"
    assert prof.categories == ("Web", "Pwn") and prof.sectors == ("energy",)
    assert prof.flag.prefixes == ("ACME",)
    assert prof.start == _dt.datetime(2027, 3, 1, 9, tzinfo=_dt.timezone.utc)
    # cautious defaults
    assert prof.rules.submit_mode == "confirm" and prof.rules.flag_sharing == "forbidden"
    assert prof.rules.ai_on_platform == "allowed" and prof.rules.live_service_scope == ("*.acme.example",)
    assert eventrules.check(prof, root / "acme") == []
    assert "CTF_TOKEN is not set" in capsys.readouterr().out
    text = (root / "acme" / "AGENTS.md").read_text()
    assert "ACME CTF" in text and "Ask before every submission" in text and "Team.** us." in text


def test_new_event_manual_preset(root):
    assert new_event(root, "spookier", "--manual", "--start", "2027-10-30", "--end", "2027-10-31",
                     "--flag-prefix", "spooky") == 0
    prof = event.load("spookier", root)
    assert prof.platform.kind == "manual" and prof.manual
    assert prof.rules.submit_mode == "manual" and prof.rules.ai_on_platform == "forbidden"
    assert prof.rules.live_service_scope == ()
    for name in ("CLAUDE.md", "AGENTS.md"):
        assert "No AI on the platform" in (root / "spookier" / name).read_text()


@pytest.mark.parametrize("argv,msg", [
    (("--base-url", "https://x.example"), "--start and --end are required"),
    (BASIC, "needs --base-url"),
    ((*BASIC, "--manual", "--platform", "ctfd"), "conflicts with --platform"),
    ((*BASIC, "--base-url", "https://x.example", "--submit-mode", "auto"), "needs known flag.prefixes"),
    (("--start", "tomorrow", "--end", "2027-01-01", "--manual"), "not an ISO date"),
    ((*BASIC, "--manual", "--submit-mode", "auto", "--flag-prefix", "X"), "requires rules.submit_mode"),
])
def test_new_event_rejects_bad_options_and_writes_nothing(root, capsys, argv, msg):
    assert new_event(root, "bad", *argv) == 1
    assert msg in capsys.readouterr().err
    assert not (root / "bad" / "event.toml").exists()
    assert not (root / "bad" / "CLAUDE.md").exists()


def test_new_event_bad_slug(root, capsys):
    assert new_event(root, "Bad_Slug", "--manual", *BASIC) == 1
    assert "slug" in capsys.readouterr().err


def test_new_event_refuses_overwrite_without_force(root, capsys):
    assert new_event(root, "acme", "--manual", *BASIC) == 0
    before = (root / "acme" / "event.toml").read_text()
    assert new_event(root, "acme", "--manual", *BASIC, "--name", "Other") == 1
    assert "already exists" in capsys.readouterr().err
    assert (root / "acme" / "event.toml").read_text() == before
    assert new_event(root, "acme", "--manual", *BASIC, "--name", "Other", "--force") == 0
    assert event.load("acme", root).name == "Other"
    assert "Other" in (root / "acme" / "CLAUDE.md").read_text()


def test_regen_after_hand_edit_and_workdir_copies(root, tmp_path, capsys):
    assert new_event(root, "acme", "--manual", *BASIC) == 0
    toml = root / "acme" / "event.toml"
    toml.write_text(toml.read_text().replace("hints_allowed = false", "hints_allowed = true"))
    assert check_event(root, "acme") == 1
    assert "stale: the profile changed" in capsys.readouterr().out
    assert new_event(root, "acme", "--regen", "--name", "x") == 1
    assert "takes no profile options" in capsys.readouterr().err
    wd = tmp_path / "work"
    assert new_event(root, "acme", "--regen", "--workdir", str(wd)) == 0
    assert check_event(root, "acme", "--workdir", str(wd)) == 0
    assert "The event allows hints" in (wd / "AGENTS.md").read_text()
    # a stale copy in the session workdir is caught too
    toml.write_text(toml.read_text().replace("hints_allowed = true", "hints_allowed = false"))
    assert new_event(root, "acme", "--regen") == 0
    assert check_event(root, "acme") == 0
    assert check_event(root, "acme", "--workdir", str(wd)) == 1
    assert str(wd / "CLAUDE.md") in capsys.readouterr().out


def test_regen_without_profile_fails(root, capsys):
    assert new_event(root, "ghost", "--regen") == 1
    assert "no event profile 'ghost'" in capsys.readouterr().err


# ------------------------------------------------------------------------------------------ categories from the platform

class _FixtureAdapter:
    kind = "ctfd"

    def __init__(self, calls, challenges=None, error=None):
        self.calls, self.challenges, self.error = calls, challenges or [], error

    def list_challenges(self):
        self.calls.append("list_challenges")
        if self.error:
            raise self.error
        return self.challenges

    def get_challenge(self, cid):
        raise AssertionError("not used")

    def download_files(self, cid, dest):
        raise AssertionError("not used")

    def submit(self, cid, flag):
        raise AssertionError("the scaffold must never submit")

    def team_solves(self):
        raise AssertionError("not used")

    def scoreboard(self):
        raise AssertionError("not used")


FIXTURE_CHALLENGES = [
    pbase.Challenge(id="1", name="a", category="Web"),
    pbase.Challenge(id="2", name="b", category="Crypto"),
    pbase.Challenge(id="3", name="c", category="Web"),
    pbase.Challenge(id="4", name="d", category="Operational security"),
]


@pytest.fixture
def fixture_platform(monkeypatch):
    """Install a fixture `ctf.platform.ctfd` adapter module; the real get_adapter() and submit gate
    load it exactly as they would load B-005's adapter."""
    state = {"calls": [], "profiles": [], "challenges": FIXTURE_CHALLENGES, "error": None}

    def make_adapter(profile):
        state["profiles"].append(profile)
        return _FixtureAdapter(state["calls"], state["challenges"], state["error"])

    mod = types.ModuleType("ctf.platform.ctfd")
    mod.make_adapter = make_adapter
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    return state


def test_categories_come_from_list_challenges_when_url_and_token_set(root, fixture_platform, monkeypatch, capsys):
    monkeypatch.setenv("CTF_TOKEN", SECRET)
    monkeypatch.setenv("CTF_PLATFORM_URL", "https://ctf.acme.example")
    assert new_event(root, "acme", *BASIC, "--flag-prefix", "ACME", "--category", "Hardware",
                     "--category", "web") == 0
    prof = event.load("acme", root)
    assert prof.categories == ("Web", "Crypto", "Operational security", "Hardware")
    assert prof.platform.base_url == "https://ctf.acme.example"
    assert fixture_platform["calls"] == ["list_challenges"]
    assert fixture_platform["profiles"][0].platform.base_url == "https://ctf.acme.example"
    out = capsys.readouterr()
    assert "3 from the platform's list_challenges (4 challenges)" in out.out
    assert SECRET not in out.out + out.err
    for f in (root / "acme").iterdir():
        assert SECRET not in f.read_text()
    assert "Web, Crypto, Operational security, Hardware" in (root / "acme" / "CLAUDE.md").read_text()


def test_legacy_token_name_also_counts_as_configured(root, fixture_platform, monkeypatch):
    monkeypatch.setenv(env.legacy_names("CTF_TOKEN")[0], SECRET)   # CSCTF's old spelling, mapped by ctf.env
    with pytest.warns(DeprecationWarning):
        assert new_event(root, "acme", *BASIC, "--base-url", "https://ctf.acme.example") == 0
    assert event.load("acme", root).categories == ("Web", "Crypto", "Operational security")


def test_platform_failure_stops_the_scaffold(root, fixture_platform, monkeypatch, capsys):
    monkeypatch.setenv("CTF_TOKEN", SECRET)
    fixture_platform["error"] = pbase.PlatformError("GET /api/v1/challenges: 403")
    assert new_event(root, "acme", *BASIC, "--base-url", "https://ctf.acme.example") == 1
    err = capsys.readouterr().err
    assert "could not list challenges" in err and "403" in err and SECRET not in err
    assert not (root / "acme" / "event.toml").exists()


@pytest.mark.parametrize("extra", [
    ("--no-fetch",),
    ("--ai-on-platform", "forbidden"),
    ("--manual",),
])
def test_no_platform_read_when_forbidden_or_declined(root, fixture_platform, monkeypatch, capsys, extra):
    monkeypatch.setenv("CTF_TOKEN", SECRET)
    argv = [*BASIC, *extra]
    if "--manual" not in extra:
        argv += ["--base-url", "https://ctf.acme.example"]
    assert new_event(root, "acme", *argv) == 0
    assert fixture_platform["calls"] == []
    assert event.load("acme", root).categories == ()
    assert "categories: not fetched" in capsys.readouterr().out


def test_fetch_categories_refuses_manual_profile_directly(fixture_platform):
    with pytest.raises(sc.ScaffoldError, match="manual"):
        sc.fetch_categories(event.load("spooky"))
    assert fixture_platform["calls"] == []


# ------------------------------------------------------------------------------------------ TOML writer

def test_toml_writer_round_trips_awkward_values(tmp_path):
    data = sc.profile_data(
        "odd", name='Q "quoted" \\ back\nline \x7f é', start=_dt.date(2027, 1, 1),
        end=_dt.datetime(2027, 1, 2, 3, 4, 5, tzinfo=_dt.timezone.utc), kind="manual",
        sectors=["a,b", "c]d"], prefixes=["X_1"], body=r"[^}\n]{1,9}", case="insensitive",
        proof_pattern=r"proof_[0-9a-f]{4}", submit_mode="manual", ai_on_platform="forbidden",
        public_repo="https://example.invalid/w")
    prof = sc.write_profile(data, tmp_path / "odd" / "event.toml", header=["h1", "h2 # inner"])
    assert prof.name == 'Q "quoted" \\ back\nline \x7f é'
    assert prof.sectors == ("a,b", "c]d") and prof.flag.body == r"[^}\n]{1,9}"
    assert prof.writeups.public_repo == "https://example.invalid/w"
    assert tomllib.loads((tmp_path / "odd" / "event.toml").read_text()) == data


# ------------------------------------------------------------------------------------------ discovery

def test_commands_are_discovered_by_python_m_ctf():
    e = dict(os.environ)
    r = subprocess.run([sys.executable, "-m", "ctf", "--help"], cwd=paths.repo_root(), env=e,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "new-event" in r.stdout and "check-event" in r.stdout and "BROKEN" not in r.stdout
    r = subprocess.run([sys.executable, "-m", "ctf", "check-event"], cwd=paths.repo_root(), env=e,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr
