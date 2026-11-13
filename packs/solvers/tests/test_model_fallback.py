"""B-100: the Opus 4.8 safety-classifier fallback -- profile [models] table, the log detector
(tools/ledger/fallback.py), `python -m tools.ledger fallback` and `python -m ctf access`.
Every session log here is built in the test; no real log is read and no model is contacted."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap

import pytest

from ctf import event, eventscaffold, ledger, paths
from ctf.cli import access as cli_access
from tools.ledger import __main__ as ledger_main
from tools.ledger import fallback, pricing

PRICES = pricing.load_prices()
P, F = "claude-opus-5-5", "claude-opus-4-8"

BASE = textwrap.dedent("""\
    slug = "demo"
    name = "Demo CTF"
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


def load_demo(tmp_path, extra=""):
    d = tmp_path / "events" / "demo"
    d.mkdir(parents=True, exist_ok=True)
    (d / "event.toml").write_text(BASE + extra)
    return event.load("demo", root=tmp_path / "events")


# ------------------------------------------------------------------ synthetic Claude Code logs

def line(mid, ts, model=P, *, inp=0, cr=0, c5=0, out=0):
    return json.dumps({"type": "assistant", "timestamp": ts,
                       "message": {"id": mid, "model": model,
                                   "usage": {"input_tokens": inp, "cache_read_input_tokens": cr,
                                             "cache_creation": {"ephemeral_5m_input_tokens": c5,
                                                                "ephemeral_1h_input_tokens": 0},
                                             "output_tokens": out},
                                   "content": [{"type": "text", "text": "switch to another model now"}]}})


def user_line(ts):
    return json.dumps({"type": "user", "timestamp": ts, "message": {"content": "hi"}})


def write(path, lines):
    path.write_text("".join(l + "\n" for l in lines))
    return path


def stuck_log(tmp_path, name="s1.jsonl"):
    """Two primary responses, then a fallback 30 minutes in that never returns to the primary."""
    return write(tmp_path / name, [
        user_line("2026-11-06T13:00:00Z"),
        line("m1", "2026-11-06T13:00:00Z", P, inp=1000, out=100),
        line("m2", "2026-11-06T13:10:00Z", P, cr=50_000, out=100),
        line("m3", "2026-11-06T13:30:00Z", F, cr=1_000_000, out=0),
        line("m4", "2026-11-06T13:40:00Z", F, out=1_000_000),
    ])


def clean_log(tmp_path, name="clean.jsonl"):
    return write(tmp_path / name, [line("c1", "2026-11-06T13:00:00Z", P, cr=1000, out=10),
                                   line("c2", "2026-11-06T13:05:00Z", P, cr=2000, out=10)])


# ------------------------------------------------------------------ profile [models]

def test_models_table_defaults_when_absent(tmp_path):
    m = load_demo(tmp_path).models
    assert (m.primary, m.fallback, m.cyber_verified) == (P, (F,), "unknown")
    assert m.verified is False


@pytest.mark.parametrize("status, verified", [("unknown", False), ("requested", False),
                                              ("denied", False), ("granted", True)])
def test_models_table_parses_and_only_granted_is_verified(tmp_path, status, verified):
    m = load_demo(tmp_path, f'\n[models]\nprimary = "claude-opus-5"\nfallback = ["claude-opus-4-7", "claude-opus-4-8"]\n'
                            f'cyber_verified = "{status}"\n').models
    assert m.primary == "claude-opus-5" and m.fallback == ("claude-opus-4-7", "claude-opus-4-8")
    assert m.cyber_verified == status and m.verified is verified


@pytest.mark.parametrize("extra, msg", [
    ('cyber_verified = "yes"\n', "models.cyber_verified must be one of"),
    ('primary = "claude-opus-4-8"\n', "also listed in models.fallback"),
    ('fallback = ["Claude Opus"]\n', "is not a model id"),
    ('primary = "x"\n', "is not a model id"),
    ('fallback = "claude-opus-4-8"\n', "models.fallback must be list"),
    ('extra = 1\n', "unknown key.*models.extra"),
    ('cyber_verified = true\n', "models.cyber_verified must be str"),
])
def test_models_table_rejects_bad_values(tmp_path, extra, msg):
    with pytest.raises(event.EventError, match=msg):
        load_demo(tmp_path, "\n[models]\n" + extra)


def test_shipped_profiles_load_with_models():
    for slug in event.available():
        assert event.load(slug).models.primary


def test_scaffold_writes_models_table_with_unknown_status(tmp_path):
    data = eventscaffold.profile_data("newev", name="New", start="2027-01-01", end="2027-01-02",
                                      kind="manual", submit_mode="manual", ai_on_platform="allowed")
    # B-095: the scaffold also writes the launch-pinned effort (default medium).
    assert data["models"] == {"primary": P, "fallback": [F], "cyber_verified": "unknown",
                              "effort": "medium"}
    prof = eventscaffold.write_profile(data, tmp_path / "newev" / "event.toml")
    assert prof.models.cyber_verified == "unknown" and prof.models.effort == "medium"
    assert "[models]" in (tmp_path / "newev" / "event.toml").read_text()


# ------------------------------------------------------------------ detector

def test_stuck_fallback_is_found_timed_and_priced(tmp_path):
    rep = fallback.detect([stuck_log(tmp_path)], P, [F], PRICES)
    s = rep.sessions[0]
    assert s.fell_back and s.stuck and not s.fallback_only
    assert (s.primary_responses, s.fallback_responses, s.other_responses) == (2, 2, 0)
    assert s.first_fallback_ts == "2026-11-06T13:30:00Z" and s.first_primary_ts == "2026-11-06T13:00:00Z"
    assert s.minutes_to_fallback == pytest.approx(30.0)
    assert s.fallback_models == [F]
    # 1M cache reads: 0.50 on 4.8 vs 0.20 on 5.5; 1M output: 25 vs 20
    assert s.fallback_usd == pytest.approx(25.50)
    assert s.at_primary_usd == pytest.approx(20.20)
    assert s.premium_usd == pytest.approx(5.30)
    assert rep.premium_usd == pytest.approx(5.30)
    assert rep.observed_factor == pytest.approx(25.50 / 20.20)
    d = rep.to_dict()
    assert d["sessions_fell_back"] == 1 and d["sessions_stuck"] == 1


def test_clean_session_has_no_fallback(tmp_path):
    rep = fallback.detect([clean_log(tmp_path)], P, [F], PRICES)
    s = rep.sessions[0]
    assert not s.fell_back and not s.stuck and s.primary_responses == 2
    assert rep.premium_usd == 0 and rep.observed_factor is None and rep.fell_back == []


def test_return_to_primary_is_not_stuck(tmp_path):
    log = write(tmp_path / "r.jsonl", [line("a", "2026-11-06T13:00:00Z", P, out=1),
                                       line("b", "2026-11-06T13:20:00Z", F, out=1),
                                       line("c", "2026-11-06T13:25:00Z", P, out=1)])
    s = fallback.detect([log], P, [F], PRICES).sessions[0]
    assert s.fell_back and not s.stuck and s.primary_after_fallback == 1


def test_primary_at_the_same_instant_as_the_fallback_is_not_a_return(tmp_path):
    # the primary row sorts after the fallback (same timestamp, later in the file): it is concurrent with
    # the switch, not a later return to the primary, so the session is still stuck
    log = write(tmp_path / "tie.jsonl", [line("a", "2026-11-06T13:00:00Z", P, out=1),
                                         line("b", "2026-11-06T13:20:00Z", F, out=1),
                                         line("c", "2026-11-06T13:20:00Z", P, out=1)])
    s = fallback.detect([log], P, [F], PRICES).sessions[0]
    assert s.primary_responses == 2 and s.fallback_responses == 1
    assert s.primary_after_fallback == 0 and s.stuck is True


def test_order_comes_from_timestamps_not_file_order(tmp_path):
    log = write(tmp_path / "o.jsonl", [line("late", "2026-11-06T14:00:00Z", F, out=1),
                                       line("p", "2026-11-06T13:00:00Z", P, out=1),
                                       line("early", "2026-11-06T13:45:00Z", F, out=1)])
    s = fallback.detect([log], P, [F], PRICES).sessions[0]
    assert s.first_fallback_ts == "2026-11-06T13:45:00Z" and s.minutes_to_fallback == pytest.approx(45.0)
    assert s.stuck


def test_fallback_only_session_is_flagged_and_untimed(tmp_path):
    log = write(tmp_path / "fo.jsonl", [line("a", "2026-11-06T13:00:00Z", F, out=1)])
    s = fallback.detect([log], P, [F], PRICES).sessions[0]
    assert s.fallback_only and s.stuck and s.minutes_to_fallback is None


def test_other_models_are_not_fallback(tmp_path):
    log = write(tmp_path / "h.jsonl", [line("a", "2026-11-06T13:00:00Z", P, out=1),
                                       line("b", "2026-11-06T13:01:00Z", "claude-haiku-4-5", out=1)])
    s = fallback.detect([log], P, [F], PRICES).sessions[0]
    assert not s.fell_back and s.other_responses == 1 and s.fallback_usd == 0
    assert s.other_models == ["claude-haiku-4-5"] and s.to_dict()["other_models"] == ["claude-haiku-4-5"]


def test_repeated_message_lines_count_once(tmp_path):
    log = write(tmp_path / "d.jsonl", [line("a", "2026-11-06T13:00:00Z", P, out=1),
                                       line("b", "2026-11-06T13:30:00Z", F, out=10),
                                       line("b", "2026-11-06T13:30:00Z", F, out=1_000_000)])
    s = fallback.detect([log], P, [F], PRICES).sessions[0]
    assert s.fallback_responses == 1 and s.fallback_usd == pytest.approx(25.0)


def test_each_log_is_its_own_session(tmp_path):
    rep = fallback.detect([stuck_log(tmp_path), clean_log(tmp_path)], P, [F], PRICES)
    assert [s.fell_back for s in rep.sessions] == [True, False]


@pytest.mark.parametrize("make, exc, msg", [
    (lambda t: write(t / "u.jsonl", [user_line("2026-11-06T13:00:00Z")]), fallback.FallbackError,
     "no Claude assistant usage"),
    (lambda t: write(t / "nt.jsonl", [line("a", "2026-11-06T13:00:00Z", P, out=1), line("b", "", F, out=1)]),
     fallback.FallbackError, "no readable timestamp"),
    (lambda t: t / "missing.jsonl", FileNotFoundError, "session log not found"),
])
def test_unjudgeable_logs_fail_loudly(tmp_path, make, exc, msg):
    with pytest.raises(exc, match=msg):
        fallback.detect([make(tmp_path)], P, [F], PRICES)


def test_bad_model_lists_fail_loudly(tmp_path):
    log = clean_log(tmp_path)
    with pytest.raises(fallback.FallbackError, match="also listed as a fallback"):
        fallback.detect([log], P, [P, F], PRICES)
    with pytest.raises(fallback.FallbackError, match="at least one fallback"):
        fallback.detect([log], P, [], PRICES)
    with pytest.raises(fallback.FallbackError, match="no session logs"):
        fallback.detect([], P, [F], PRICES)
    with pytest.raises(pricing.PricingError, match="primary model 'claude-opus-9'"):
        fallback.detect([log], "claude-opus-9", [F], PRICES)


def test_rate_ratios_and_worst_case():
    r = fallback.rate_ratios(PRICES, P, F)
    assert r["cache_read"] == pytest.approx(2.5) and r["input"] == pytest.approx(1.25)
    assert r["output"] == pytest.approx(1.25) and set(r) == set(fallback.TOKEN_CLASSES)
    assert fallback.worst_case_factor(PRICES, P, [F]) == pytest.approx(2.5)
    # Fable 5 cache reads are 1.0 against 5.5's 0.20: the worst case takes the max over fallbacks
    assert fallback.worst_case_factor(PRICES, P, [F, "claude-fable-5"]) == pytest.approx(5.0)
    with pytest.raises(pricing.PricingError, match="claude-opus-9"):
        fallback.rate_ratios(PRICES, P, "claude-opus-9")


def test_record_appends_once_per_fallen_back_session(tmp_path):
    wd = tmp_path / "wd"
    rep = fallback.detect([stuck_log(tmp_path), clean_log(tmp_path)], P, [F], PRICES)
    new = fallback.record(rep, workdir=wd, cyber_verified="requested", challenge_id="9158")
    assert len(new) == 1
    ev = [r for r in ledger.read(wd) if r["event"] == fallback.LEDGER_EVENT]
    assert len(ev) == 1
    e = ev[0]
    assert e["log"] == "s1.jsonl" and e["from_model"] == P and e["to_models"] == [F]
    assert e["stuck"] is True and e["responses"] == 2 and e["cyber_verified"] == "requested"
    assert e["challenge_id"] == "9158" and e["premium_usd"] == pytest.approx(5.30)
    assert e["first_fallback_ts"] == "2026-11-06T13:30:00Z" and e["minutes_to_fallback"] == pytest.approx(30.0)
    # a later poll of the same (grown) log does not record it again; a new session does
    assert fallback.record(rep, workdir=wd) == []
    other = fallback.detect([stuck_log(tmp_path, "s2.jsonl")], P, [F], PRICES)
    assert len(fallback.record(other, workdir=wd)) == 1


def test_guidance_never_suggests_working_around_the_classifier():
    g = fallback.GUIDANCE.format(primary=P, fallback=F).lower()
    assert "do not switch models" in g and "cyber verified profile" in g
    assert "o-3" in fallback.HUMAN_STEP.lower() and "cyber_verified" in fallback.HUMAN_STEP


# ------------------------------------------------------------------ python -m tools.ledger fallback

def run_ledger(tmp_path, *args):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path / "wd"), CTF_EVENT="csctf")
    return subprocess.run([sys.executable, "-m", "tools.ledger", "fallback", *map(str, args)],
                          cwd=paths.repo_root(), env=e, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=60)


def test_cli_clean_logs_exit_zero(tmp_path):
    r = run_ledger(tmp_path, clean_log(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "no fallback" in r.stdout and "0 of 1 session(s) fell back" in r.stdout
    assert "Human step" not in r.stdout


def test_cli_warns_on_unmatched_model_ids(tmp_path):
    # a dated spelling of the fallback model is not matched: the session is not called a fallback, but
    # the text output must say so instead of a bare "no fallback"
    dated = "claude-opus-4-8-20261101"
    log = write(tmp_path / "dated.jsonl", [line("a", "2026-11-06T13:00:00Z", P, out=1),
                                           line("b", "2026-11-06T13:30:00Z", dated, out=1),
                                           line("c", "2026-11-06T13:40:00Z", dated, out=1)])
    r = run_ledger(tmp_path, log)
    assert r.returncode == 0, r.stderr
    assert "1 on claude-opus-5-5, 2 on other model(s), no fallback" in r.stdout
    assert f"WARN      {log}: 2 response(s) on {dated}" in r.stdout and "--fallback" in r.stdout
    # JSON keeps stdout one object and puts the warning on stderr
    r = run_ledger(tmp_path, "--json", log)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["sessions"][0]["other_responses"] == 2 and d["sessions"][0]["other_models"] == [dated]
    assert f"2 response(s) on {dated}" in r.stderr
    # the clean log draws no warning
    assert "WARN" not in run_ledger(tmp_path, clean_log(tmp_path)).stdout
    # passing the dated id as a fallback needs a price for it: without one it fails loudly ...
    r = run_ledger(tmp_path, "--fallback", dated, log)
    assert r.returncode == 2 and f"no price for claude model '{dated}'" in r.stderr
    # ... and with one it is a detected fallback, with no warning left
    table = json.loads(pricing.PRICING_PATH.read_text(encoding="utf-8"))
    table["claude"][dated] = table["claude"][F]
    priced = tmp_path / "pricing.json"
    priced.write_text(json.dumps(table))
    r = run_ledger(tmp_path, "--fallback", dated, "--pricing", priced, log)
    assert r.returncode == ledger_main.FALLBACK_EXIT, r.stderr
    assert "STUCK" in r.stdout and "WARN" not in r.stdout


def test_cli_fallback_session_with_other_models_warns(tmp_path):
    log = write(tmp_path / "mix.jsonl", [line("a", "2026-11-06T13:00:00Z", P, out=1),
                                         line("b", "2026-11-06T13:10:00Z", "claude-haiku-4-5", out=1),
                                         line("c", "2026-11-06T13:30:00Z", F, out=1)])
    r = run_ledger(tmp_path, log)
    assert r.returncode == ledger_main.FALLBACK_EXIT, r.stderr
    assert "STUCK" in r.stdout and "1 response(s) on claude-haiku-4-5" in r.stdout


def test_cli_fallback_exits_5_with_guidance_and_records(tmp_path):
    r = run_ledger(tmp_path, "--record", "--challenge", "9158", stuck_log(tmp_path), clean_log(tmp_path))
    assert r.returncode == ledger_main.FALLBACK_EXIT, r.stderr
    assert "STUCK" in r.stdout and "30 min in" in r.stdout and "premium $5.30" in r.stdout
    assert "1 of 2 session(s) fell back" in r.stdout
    assert "Human step" in r.stdout and "events/csctf/event.toml" in r.stdout
    assert "recorded 1 new model_fallback" in r.stdout
    assert [e["challenge_id"] for e in ledger.read(tmp_path / "wd") if e["event"] == "model_fallback"] == ["9158"]


def test_cli_json_and_overrides(tmp_path):
    log = write(tmp_path / "f.jsonl", [line("a", "2026-11-06T13:00:00Z", "claude-opus-5", out=1),
                                       line("b", "2026-11-06T13:05:00Z", "claude-opus-4-7", out=1)])
    r = run_ledger(tmp_path, "--json", "--primary", "claude-opus-5", "--fallback", "claude-opus-4-7", log)
    assert r.returncode == ledger_main.FALLBACK_EXIT, r.stderr
    d = json.loads(r.stdout)
    assert d["primary"] == "claude-opus-5" and d["fallback"] == ["claude-opus-4-7"]
    assert d["sessions_fell_back"] == 1 and d["event"] == "csctf" and d["cyber_verified"] == "unknown"
    assert "Human step" in r.stderr
    # with the profile's models (5.5 / 4.8) the same log shows no fallback
    assert run_ledger(tmp_path, log).returncode == 0


def test_cli_errors_exit_2(tmp_path):
    r = run_ledger(tmp_path, write(tmp_path / "u.jsonl", [user_line("2026-11-06T13:00:00Z")]))
    assert r.returncode == 2 and "no Claude assistant usage" in r.stderr
    r = run_ledger(tmp_path, "--challenge", "1", clean_log(tmp_path))
    assert r.returncode == 2 and "--challenge needs --record" in r.stderr


def test_cli_granted_but_fell_back_says_so(tmp_path, monkeypatch, capsys):
    real = event.load
    load_demo(tmp_path, '\n[models]\ncyber_verified = "granted"\n')
    monkeypatch.setattr(event, "load", lambda slug, root=None: real(slug, root=tmp_path / "events"))
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "wd"))
    rc = ledger_main.main(["fallback", "--event", "demo", str(stuck_log(tmp_path))])
    out = capsys.readouterr().out
    assert rc == ledger_main.FALLBACK_EXIT
    assert "granted" in out and "still fell back" in out and "Human step" not in out


# ------------------------------------------------------------------ python -m ctf access

def access(monkeypatch, tmp_path, *argv, extra=None):
    if extra is not None:
        real = event.load
        load_demo(tmp_path, extra)
        monkeypatch.setattr(event, "load", lambda slug, root=None: real(slug, root=tmp_path / "events"))
        argv = ("--event", "demo", *argv)
    p = argparse.ArgumentParser()
    cli_access.add_arguments(p)
    return cli_access.run(p.parse_args(list(argv)))


def test_access_unknown_status_shows_human_step_and_budget(tmp_path):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_EVENT="csctf")
    r = subprocess.run([sys.executable, "-m", "ctf", "access", "--plan-usd", "400"], cwd=paths.repo_root(),
                       env=e, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "cyber verified profile (O-3): unknown" in r.stdout and "fallback EXPECTED" in r.stdout
    assert "cache_read x2.50" in r.stdout
    assert "up to $1000.00 on the fallback (reserve $600.00)" in r.stdout
    assert "Human step" in r.stdout


def test_access_check_exits_3_unless_granted(tmp_path, monkeypatch, capsys):
    assert access(monkeypatch, tmp_path, "--check", extra='\n[models]\ncyber_verified = "requested"\n') \
        == cli_access.NOT_GRANTED_EXIT
    assert "'requested', not 'granted'" in capsys.readouterr().err


def test_access_granted_check_passes_without_human_step(tmp_path, monkeypatch, capsys):
    assert access(monkeypatch, tmp_path, "--check", "--json", extra='\n[models]\ncyber_verified = "granted"\n') == 0
    d = json.loads(capsys.readouterr().out)
    assert d["fallback_expected"] is False and d["human_step"] is None
    assert d["worst_case_factor"] == pytest.approx(2.5)


def test_access_json_plan_numbers(tmp_path, monkeypatch, capsys):
    assert access(monkeypatch, tmp_path, "--json", "--plan-usd", "100", extra="") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["fallback_expected"] is True and d["cyber_verified"] == "unknown"
    assert d["plan_worst_case_usd"] == pytest.approx(250.0) and d["plan_reserve_usd"] == pytest.approx(150.0)
    assert d["rate_ratios"][F]["cache_read"] == pytest.approx(2.5)
    assert "events/demo/event.toml" in d["human_step"]


def test_access_errors_exit_2(tmp_path, monkeypatch, capsys):
    assert access(monkeypatch, tmp_path, "--plan-usd", "-1", extra="") == 2
    assert "--plan-usd must be >= 0" in capsys.readouterr().err
    assert access(monkeypatch, tmp_path, extra='\n[models]\nprimary = "claude-opus-9"\n') == 2
    assert "claude-opus-9" in capsys.readouterr().err


def test_access_without_tools_ledger_fails_with_a_named_reason(tmp_path, monkeypatch, capsys):
    # ctf/cli/access.py is the one ctf module that imports tools/; when it cannot, it must say so and
    # exit 2, not raise a traceback
    monkeypatch.setitem(sys.modules, "tools.ledger", None)
    assert access(monkeypatch, tmp_path, extra="") == 2
    err = capsys.readouterr().err
    assert "ctf access: needs tools.ledger" in err and "run from the repo root" in err
