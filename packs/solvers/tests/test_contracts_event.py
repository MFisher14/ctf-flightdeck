"""B-001 contracts: event profiles (ctf.event) and the four shipped past-event fixtures."""
from __future__ import annotations

import datetime as dt
import textwrap

import pytest

from ctf import event

BASE = textwrap.dedent("""\
    slug = "demo"
    name = "Demo CTF"
    categories = ["Web"]
    dates = { start = 2027-01-01, end = 2027-01-02 }

    [platform]
    kind = "ctfd"
    base_url = "https://demo.example/"

    [flag]
    prefixes = ["DEMO"]

    [rules]
    submit_mode = "auto"
    flag_sharing = "allowed"
    ai_on_platform = "allowed"
    """)


def write(root, text, slug="demo"):
    d = root / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "event.toml").write_text(text)
    return root


def load(tmp_path, text, slug="demo"):
    return event.load(slug, root=write(tmp_path, text, slug))


def test_minimal_profile_gets_documented_defaults(tmp_path):
    p = load(tmp_path, BASE)
    assert p.slug == "demo" and p.name == "Demo CTF"
    assert p.platform.base_url == "https://demo.example"          # trailing slash trimmed
    assert p.start == dt.date(2027, 1, 1)
    assert p.flag.body == event.DEFAULT_BODY and p.flag.case == "exact"
    r = p.rules
    assert (r.wrong_answer_stop, r.guess_budget, r.hints_allowed, r.web_state_changing) == (3, 0, False, False)
    assert r.live_service_scope == ()
    assert (p.budget.per_point, p.budget.floor, p.budget.ceiling, p.budget.per_challenge_day) == (0.5, 25.0, 250.0, None)
    assert p.writeups.redact_flags is True and p.proof is None
    assert p.path == tmp_path / "demo" / "event.toml"


@pytest.mark.parametrize("extra, where", [
    ("colour = 'red'\n", "colour"),
    ("[platform2]\nkind='x'\n", "platform2"),
])
def test_unknown_top_level_key_is_an_error(tmp_path, extra, where):
    text = BASE.replace('dates =', extra.split("\n")[0] + "\ndates =") if "[" not in extra else BASE + extra
    with pytest.raises(event.EventError, match=f"unknown key.*{where}"):
        load(tmp_path, text)


def test_unknown_nested_key_is_an_error(tmp_path):
    with pytest.raises(event.EventError, match=r"unknown key\(s\): rules.submit_mod\b"):
        load(tmp_path, BASE + 'submit_mod = "auto"\n')


@pytest.mark.parametrize("old, new, msg", [
    ('kind = "ctfd"', 'kind = "hackthebox"', "platform.kind must be one of"),
    ('submit_mode = "auto"', 'submit_mode = "yolo"', "rules.submit_mode must be one of"),
    ('flag_sharing = "allowed"', 'flag_sharing = "maybe"', "rules.flag_sharing must be one of"),
    ('flag_sharing = "allowed"\n', '', "rules.flag_sharing is required"),
    ('ai_on_platform = "allowed"\n', '', "rules.ai_on_platform is required"),
    ('base_url = "https://demo.example/"', 'base_url = "demo.example"', "must start with http"),
    ('base_url = "https://demo.example/"\n', '', "base_url is required for kind 'ctfd'"),
    ('prefixes = ["DEMO"]', 'prefixes = ["DE MO"]', "prefixes"),
    ('prefixes = ["DEMO"]', 'prefixes = ["DEMO"]\nbody = ".+"', "must not be able to match '}'"),
    ('prefixes = ["DEMO"]', 'prefixes = ["DEMO"]\nbody = "[a-z"', "not a valid regex"),
    ('prefixes = ["DEMO"]', 'prefixes = ["DEMO"]\ncase = "loose"', "flag.case must be one of"),
    ('slug = "demo"', 'slug = "other"', "lives in events/demo"),
    ('end = 2027-01-02', 'end = 2026-01-02', "dates.end is before"),
])
def test_bad_values_fail_with_named_key(tmp_path, old, new, msg):
    assert old in BASE
    with pytest.raises(event.EventError, match=msg):
        load(tmp_path, BASE.replace(old, new))


def test_bool_is_not_accepted_as_a_number(tmp_path):
    with pytest.raises(event.EventError, match="wrong_answer_stop must be int, got a boolean"):
        load(tmp_path, BASE + "wrong_answer_stop = true\n")


def test_manual_platform_requires_manual_submit(tmp_path):
    t = BASE.replace('kind = "ctfd"', 'kind = "manual"')
    with pytest.raises(event.EventError, match="kind 'manual' requires rules.submit_mode = 'manual'"):
        load(tmp_path, t)
    p = load(tmp_path, t.replace('submit_mode = "auto"', 'submit_mode = "manual"')
             .replace('base_url = "https://demo.example/"\n', ''))
    assert p.manual and p.platform.base_url is None


def test_ai_forbidden_requires_manual_submit(tmp_path):
    t = BASE.replace('ai_on_platform = "allowed"', 'ai_on_platform = "forbidden"')
    with pytest.raises(event.EventError, match="ai_on_platform = 'forbidden' requires"):
        load(tmp_path, t)


def test_auto_submit_needs_a_known_flag_format(tmp_path):
    t = BASE.replace('prefixes = ["DEMO"]', 'prefixes = []')
    with pytest.raises(event.EventError, match="needs known flag.prefixes"):
        load(tmp_path, t)
    p = load(tmp_path, t.replace('submit_mode = "auto"', 'submit_mode = "confirm"'))
    assert not p.flag.known


def test_budget_floor_above_ceiling_is_an_error(tmp_path):
    with pytest.raises(event.EventError, match="floor .* is above budget.ceiling"):
        load(tmp_path, BASE + "\n[budget]\nfloor = 300\nceiling = 250\n")


def test_invalid_toml_and_missing_profile(tmp_path):
    with pytest.raises(event.EventError, match="not valid TOML"):
        load(tmp_path, "slug = \n")
    with pytest.raises(event.EventError, match="no event profile 'nope'"):
        event.load("nope", root=tmp_path)


def test_current_uses_ctf_event_else_the_only_profile(tmp_path, monkeypatch):
    for v in ("CTF_EVENT", "HUNTRESS_EVENT", "CSCTF_EVENT"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(event.EventError, match="no event profile found"):
        event.current(root=tmp_path)
    write(tmp_path, BASE)
    assert event.current(root=tmp_path).slug == "demo"
    write(tmp_path, BASE.replace('slug = "demo"', 'slug = "two"'), slug="two")
    with pytest.raises(event.EventError, match="2 profiles exist"):
        event.current(root=tmp_path)
    monkeypatch.setenv("CTF_EVENT", "two")
    assert event.current(root=tmp_path).slug == "two"


# ------------------------------------------------------------------ shipped fixtures

def test_four_past_event_profiles_ship_and_validate():
    assert {"huntress", "csctf", "pink", "spooky"} <= set(event.available())
    for slug in ("huntress", "csctf", "pink", "spooky"):
        assert event.load(slug).slug == slug


def test_past_event_policies():
    h, c, p, s = (event.load(x) for x in ("huntress", "csctf", "pink", "spooky"))
    assert h.platform.kind == "gamemaster" and c.platform.kind == "ctfd" and p.platform.kind == "ctfd"
    assert s.platform.kind == "manual" and s.rules.submit_mode == "manual" and s.manual
    assert s.rules.ai_on_platform == "forbidden"
    assert p.rules.flag_sharing == "forbidden" and s.rules.flag_sharing == "forbidden"
    assert h.rules.flag_sharing == "allowed" and c.rules.flag_sharing == "allowed"
    assert h.proof is not None and h.budget.per_challenge_day == 50.0
    assert all(not x.rules.hints_allowed and not x.rules.web_state_changing for x in (h, c, p, s))
    assert all(x.platform.base_url is None or ".example" in x.platform.base_url for x in (h, c, p, s))


# B-098: writeup policy fields.

def test_writeups_publish_hold_defaults_true_and_parses(tmp_path):
    assert load(tmp_path, BASE, slug="demo").writeups.publish_hold is True
    held = BASE.replace('slug = "demo"', 'slug = "pub"') + "\n[writeups]\npublish_hold = false\npublic_repo = \"https://github.com/x/y\"\n"
    p = load(tmp_path, held, slug="pub")
    assert p.writeups.publish_hold is False and p.writeups.public_repo == "https://github.com/x/y"


def test_writeups_publish_hold_must_be_boolean(tmp_path):
    with pytest.raises(event.EventError, match="writeups.publish_hold must be bool"):
        load(tmp_path, BASE + "\n[writeups]\npublish_hold = \"no\"\n")


def test_forbidden_flag_sharing_requires_redaction(tmp_path):
    text = BASE.replace('flag_sharing = "allowed"', 'flag_sharing = "forbidden"')
    with pytest.raises(event.EventError, match="redact_flags = false contradicts"):
        load(tmp_path, text + "\n[writeups]\nredact_flags = false\n")
    assert load(tmp_path, BASE + "\n[writeups]\nredact_flags = false\n").writeups.redact_flags is False
