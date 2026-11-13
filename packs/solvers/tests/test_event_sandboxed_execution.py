"""B-242: the per-event policy value that lets the runtime adapters run a delivered artifact.

rules.sandboxed_execution is read by ctf.event, summarised by ctf.eventpolicy (Policy, lines,
execution_refusal: the gate), written by the scaffold and settable from `ctf new-event`. It is off
unless the profile says "allowed". No network, no docker.
"""
from __future__ import annotations

import datetime as dt

import pytest

import ctf.cli as cli
from ctf import event, eventpolicy, eventscaffold


def make(**rules_kw) -> event.EventProfile:
    r = {"submit_mode": "confirm", "flag_sharing": "allowed", "ai_on_platform": "allowed"}
    r.update(rules_kw)
    return event.parse({"slug": "rt-test", "name": "runtime policy test",
                        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
                        "platform": {"kind": "ctfd", "base_url": "https://board.rt.test"},
                        "flag": {"prefixes": ["RT"]}, "rules": r}, src="test")


def test_the_default_is_forbidden():
    p = make()
    assert p.rules.sandboxed_execution == "forbidden"
    assert eventpolicy.summary(p).sandboxed_execution == "forbidden"


def test_allowed_is_read_from_the_profile():
    p = make(sandboxed_execution="allowed")
    assert p.rules.sandboxed_execution == "allowed"
    assert eventpolicy.summary(p).to_dict()["sandboxed_execution"] == "allowed"


@pytest.mark.parametrize("bad", ["yes", "", "Allowed", True, 1])
def test_any_other_value_is_an_error_naming_the_key(bad):
    with pytest.raises(event.EventError, match="rules.sandboxed_execution"):
        make(sandboxed_execution=bad)


def test_the_gate_refuses_by_default_and_names_the_key_and_the_event():
    why = eventpolicy.execution_refusal(make())
    assert why is not None
    assert "rules.sandboxed_execution = 'forbidden'" in why
    assert "'rt-test'" in why


def test_the_gate_opens_only_on_allowed():
    assert eventpolicy.execution_refusal(make(sandboxed_execution="allowed")) is None


def test_policy_show_lines_state_it_both_ways():
    off = [ln for ln in eventpolicy.lines(eventpolicy.summary(make())) if ln.startswith("execution")]
    on = [ln for ln in eventpolicy.lines(eventpolicy.summary(make(sandboxed_execution="allowed")))
          if ln.startswith("execution")]
    assert len(off) == 1 and "forbidden" in off[0] and "allowed" not in off[0]
    assert len(on) == 1 and "allowed" in on[0] and "forbidden" not in on[0]
    assert "no network" in on[0] and "no host mount" in on[0]


def test_every_shipped_event_keeps_it_off():
    for slug in event.available():
        assert event.load(slug).rules.sandboxed_execution == "forbidden", slug


def test_the_scaffold_writes_the_field_with_its_default_and_when_set(tmp_path):
    base = dict(name="ACME", start=dt.date(2027, 1, 1), end=dt.date(2027, 1, 2), kind="ctfd",
                base_url="https://acme.example", submit_mode="confirm", ai_on_platform="allowed")
    plain = eventscaffold.profile_data("acme", **base)
    assert plain["rules"]["sandboxed_execution"] == "forbidden"
    prof = eventscaffold.write_profile(eventscaffold.profile_data("acme", sandboxed_execution="allowed", **base),
                                       tmp_path / "acme" / "event.toml")
    assert prof.rules.sandboxed_execution == "allowed"
    assert 'sandboxed_execution = "allowed"' in (tmp_path / "acme" / "event.toml").read_text()


def _new_event(tmp_path, *extra):
    return cli.main(["new-event", "acme", "--events-root", str(tmp_path), "--start", "2027-01-01",
                     "--end", "2027-01-02", "--base-url", "https://acme.example", "--no-fetch", *extra])


def test_new_event_leaves_it_off_unless_asked(tmp_path, capsys):
    assert _new_event(tmp_path) == 0, capsys.readouterr()
    assert event.load("acme", tmp_path).rules.sandboxed_execution == "forbidden"


def test_new_event_option_reaches_the_profile(tmp_path, capsys):
    assert _new_event(tmp_path, "--sandboxed-execution", "allowed") == 0, capsys.readouterr()
    assert event.load("acme", tmp_path).rules.sandboxed_execution == "allowed"


def test_regen_refuses_the_option_because_it_edits_no_profile(tmp_path, capsys):
    assert _new_event(tmp_path) == 0
    capsys.readouterr()
    code = cli.main(["new-event", "acme", "--events-root", str(tmp_path), "--regen",
                     "--sandboxed-execution", "allowed"])
    assert code == 1 and "--sandboxed-execution" in capsys.readouterr().err
    assert event.load("acme", tmp_path).rules.sandboxed_execution == "forbidden"


def test_policy_show_prints_the_execution_line(capsys):
    assert cli.main(["policy", "show", "--event", "pink"]) == 0
    assert "execution      forbidden" in capsys.readouterr().out
