"""B-211: the clock line and its hook -- Eastern time and the next-release countdown, driven by an
injected clock (rule 16: no wall-clock assertions). Offline: tracked profiles and synthetic ones."""
from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import subprocess
import zoneinfo

import pytest

from ctf import clockline, event, paths
from ctf.cli import main as ctf_main
from ctf.event import Allowance

ET = zoneinfo.ZoneInfo("America/New_York")
UTC = _dt.timezone.utc


def _t(y, mo, d, h=0, mi=0, s=0, tz=ET) -> float:
    return _dt.datetime(y, mo, d, h, mi, s, tzinfo=tz).timestamp()


def _profile(start, end, **allowance):
    base = event.load("huntress")
    return dataclasses.replace(base, start=start, end=end, allowance=Allowance(**allowance))


# ------------------------------------------------------------------ formatting

def test_fmt_et_names_weekday_and_daylight_zone():
    assert clockline.fmt_et(_t(2026, 7, 4, 9, 5)) == "Sat 2026-07-04 09:05 EDT"
    assert clockline.fmt_et(_t(2026, 12, 1, 23, 59)) == "Tue 2026-12-01 23:59 EST"


def test_fmt_et_across_the_dst_change():
    """2026-11-01 06:00 UTC is 01:00 EST (after fall-back); 05:00 UTC is 01:00 EDT."""
    assert clockline.fmt_et(_t(2026, 11, 1, 5, tz=UTC)) == "Sun 2026-11-01 01:00 EDT"
    assert clockline.fmt_et(_t(2026, 11, 1, 6, tz=UTC)) == "Sun 2026-11-01 01:00 EST"


def test_fmt_utc():
    assert clockline.fmt_utc(_t(2026, 12, 1, 9, 30)) == "14:30 UTC"


@pytest.mark.parametrize("secs,want", [
    (0, "0s"), (45.9, "45s"), (60, "1m 00s"), (65, "1m 05s"), (3599, "59m 59s"),
    (3600, "1h 00m"), (3600 * 3 + 4 * 60 + 59, "3h 04m"), (86400, "1d 00h 00m"),
    (2 * 86400 + 3 * 3600 + 4 * 60, "2d 03h 04m"),
])
def test_fmt_delta(secs, want):
    assert clockline.fmt_delta(secs) == want


def test_fmt_delta_refuses_a_past_time():
    with pytest.raises(ValueError, match="past"):
        clockline.fmt_delta(-1)


# ------------------------------------------------------------------ the clock block

def test_clock_line_daily_release_countdown_in_et():
    prof = _profile(_dt.date(2026, 11, 10), _dt.date(2026, 11, 20), daily_release="15:00",
                    tz="America/New_York")
    now = _t(2026, 11, 12, 14, 3, 30)
    lines = clockline.clock_line(now, prof).splitlines()
    assert lines[0].startswith("CLOCK: now Thu 2026-11-12 14:03 EST (19:03 UTC).")
    assert lines[1] == "Next release (huntress): Thu 2026-11-12 15:00 EST, in 56m 30s"
    assert lines[2] == "Event huntress: running; ends Sat 2026-11-21 00:00 EST, in 8d 09h 56m"


def test_after_todays_release_the_countdown_is_to_tomorrows():
    prof = _profile(_dt.date(2026, 11, 10), _dt.date(2026, 11, 20), daily_release="15:00",
                    tz="America/New_York")
    text = clockline.clock_line(_t(2026, 11, 12, 15, 0, 1), prof)
    assert "Next release (huntress): Fri 2026-11-13 15:00 EST, in 23h 59m" in text


def test_listed_release_in_another_zone_is_shown_in_et():
    rel = _dt.datetime(2026, 11, 14, 18, 0, tzinfo=UTC)
    prof = _profile(_dt.date(2026, 11, 10), _dt.date(2026, 11, 20), releases=(rel,))
    text = clockline.clock_line(_t(2026, 11, 14, 12, 0), prof)
    assert "Next release (huntress): Sat 2026-11-14 13:00 EST, in 1h 00m" in text


def test_before_the_event_the_start_is_the_next_release():
    prof = _profile(_dt.date(2026, 11, 20), _dt.date(2026, 11, 22), tz="America/New_York")
    text = clockline.clock_line(_t(2026, 11, 19, 22, 0), prof)
    assert "Next release (huntress): Fri 2026-11-20 00:00 EST, in 2h 00m" in text
    assert "Event huntress: not started; starts Fri 2026-11-20 00:00 EST, in 2h 00m" in text


def test_after_the_event_nothing_is_ahead_and_it_says_over():
    prof = _profile(_dt.date(2026, 10, 1), _dt.date(2026, 10, 31), daily_release="12:00",
                    tz="America/New_York")
    text = clockline.clock_line(_t(2026, 11, 12, 9, 0), prof)
    assert "Next release (huntress): none ahead" in text
    assert "Event huntress: over; ended Sun 2026-11-01 00:00 EDT" in text
    assert "running" not in text


def test_event_state_boundaries_are_start_inclusive_end_exclusive():
    """At the start instant the event is running; at the end instant it is over."""
    prof = _profile(_dt.date(2026, 11, 10), _dt.date(2026, 11, 20), tz="America/New_York")
    at_start = clockline.clock_line(_t(2026, 11, 10), prof)
    assert "Event huntress: running; ends Sat 2026-11-21 00:00 EST, in 11d 00h 00m" in at_start
    at_end = clockline.clock_line(_t(2026, 11, 21), prof)
    assert "Event huntress: over; ended Sat 2026-11-21 00:00 EST" in at_end
    just_before = clockline.clock_line(_t(2026, 11, 20, 23, 59, 59), prof)
    assert "Event huntress: running; ends Sat 2026-11-21 00:00 EST, in 1s" in just_before


def test_datetime_edges_are_exact_and_naive_ones_are_in_the_allowance_zone():
    """A datetime end is the instant itself (no whole-day extension); a naive one is read in the
    [allowance] zone, an aware one in its own zone."""
    naive = _profile(_dt.datetime(2026, 11, 10, 9, 0), _dt.datetime(2026, 11, 12, 18, 0),
                     tz="America/Chicago")
    text = clockline.clock_line(_t(2026, 11, 12, 18, 0), naive)
    assert "Event huntress: running; ends Thu 2026-11-12 19:00 EST, in 1h 00m" in text
    aware = _profile(_dt.datetime(2026, 11, 10, 9, 0, tzinfo=UTC),
                     _dt.datetime(2026, 11, 12, 18, 0, tzinfo=UTC), tz="America/Chicago")
    text = clockline.clock_line(_t(2026, 11, 12, 12, 0), aware)
    assert "Event huntress: running; ends Thu 2026-11-12 13:00 EST, in 1h 00m" in text
    text = clockline.clock_line(_t(2026, 11, 10, 3, 0), aware)
    assert "Event huntress: not started; starts Tue 2026-11-10 04:00 EST, in 1h 00m" in text


def test_hook_response_defaults_to_user_prompt_submit():
    assert clockline.hook_response("CLOCK: y")["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"


def test_no_profile_names_the_reason():
    text = clockline.clock_line(_t(2026, 11, 12, 9, 0), None, reason="no event: CTF_EVENT unset")
    assert text.splitlines()[1] == "Release countdown: unavailable (no event: CTF_EVENT unset)"


def test_no_profile_and_no_reason_is_refused():
    with pytest.raises(ValueError, match="reason"):
        clockline.clock_line(_t(2026, 11, 12, 9, 0), None)


def test_hook_response_shape_and_events():
    r = clockline.hook_response("CLOCK: x", "SessionStart")
    assert r == {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": "CLOCK: x"}}
    with pytest.raises(ValueError, match="unsupported"):
        clockline.hook_response("x", "Stop")


# ------------------------------------------------------------------ the CLI

@pytest.fixture
def no_event(monkeypatch):
    monkeypatch.delenv("CTF_EVENT", raising=False)


def test_cli_prints_the_block_for_an_injected_time(capsys, no_event):
    rc = ctf_main(["clock", "--event", "huntress", "--now", "2026-10-15T14:30"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("CLOCK: now Thu 2026-10-15 14:30 EDT (18:30 UTC).")
    # huntress's [allowance] tz is Eastern: its date-only end is the whole of 31 Oct in Eastern time
    assert "Event huntress: running; ends Sun 2026-11-01 00:00 EDT, in 16d 09h 30m" in out


# ------------------------------------------------------------------ the tracked profiles

def test_huntress_profile_counts_down_to_the_0900_eastern_daily_release(capsys, no_event):
    """Mid-event, the tracked Huntress profile names the next day's 09:00 ET release (its source repo
    and retrospectives: challenges released daily at 09:00 Eastern), not "none ahead"."""
    assert ctf_main(["clock", "--event", "huntress", "--now", "2026-10-14T11:00"]) == 0
    out = capsys.readouterr().out
    assert "Next release (huntress): Thu 2026-10-15 09:00 EDT, in 22h 00m" in out
    assert ctf_main(["clock", "--event", "huntress", "--now", "2026-10-14T08:59:30"]) == 0
    assert "Next release (huntress): Wed 2026-10-14 09:00 EDT, in 30s" in capsys.readouterr().out
    # the last release is 31 Oct 09:00; after it, the event still runs to the end of the day
    assert ctf_main(["clock", "--event", "huntress", "--now", "2026-10-31T10:00"]) == 0
    out = capsys.readouterr().out
    assert "Next release (huntress): none ahead" in out and "Event huntress: running" in out


def test_csctf_profile_counts_down_to_its_second_wave(capsys, no_event):
    """CSCTF released in two waves, 6 and 7 Nov at 13:00 UTC (08:00 EST); mid-event the countdown is
    to the second wave, and after it nothing is ahead."""
    assert ctf_main(["clock", "--event", "csctf", "--now", "2026-11-06T20:00"]) == 0
    out = capsys.readouterr().out
    assert "Next release (csctf): Sat 2026-11-07 08:00 EST, in 12h 00m" in out
    assert "Event csctf: running; ends Sun 2026-11-08 08:00 EST, in 1d 12h 00m" in out
    assert ctf_main(["clock", "--event", "csctf", "--now", "2026-11-07T09:00"]) == 0
    assert "Next release (csctf): none ahead" in capsys.readouterr().out


def test_default_allowance_zone_reads_a_date_only_end_in_utc():
    """With no [allowance] tz (UTC), a date-only end is the end of the last day in UTC."""
    prof = _profile(_dt.date(2026, 11, 5), _dt.date(2026, 11, 9))
    text = clockline.clock_line(_t(2026, 11, 9, 18, 0), prof)
    assert "Event huntress: running; ends Mon 2026-11-09 19:00 EST, in 1h 00m" in text


def test_clock_line_and_next_release_share_one_reading_of_the_dates(monkeypatch):
    """The event-state line takes start and end from ctf.quota.event_span, the helper next_release
    uses, so the two can never read the dates differently."""
    from ctf import quota
    prof = _profile(_dt.date(2026, 11, 10), _dt.date(2026, 11, 20), tz="America/New_York")
    fake = (_t(2026, 11, 12, 13, 0), _t(2026, 11, 12, 15, 0))
    monkeypatch.setattr(quota, "event_span", lambda p: fake)
    text = clockline.clock_line(_t(2026, 11, 12, 14, 0), prof)
    assert "Event huntress: running; ends Thu 2026-11-12 15:00 EST, in 1h 00m" in text
    assert quota.next_release(prof, _t(2026, 11, 12, 12, 0)) == fake[0]


def test_cli_now_accepts_epoch_and_zoned_iso(capsys, no_event):
    ctf_main(["clock", "--event", "huntress", "--now", str(_t(2026, 10, 15, 14, 30))])
    a = capsys.readouterr().out
    ctf_main(["clock", "--event", "huntress", "--now", "2026-10-15T18:30:00+00:00"])
    b = capsys.readouterr().out
    assert a == b and "14:30 EDT" in a


def test_cli_bad_now_is_exit_2(capsys, no_event):
    assert ctf_main(["clock", "--event", "huntress", "--now", "teatime"]) == 2
    assert "teatime" in capsys.readouterr().err


def test_cli_named_event_that_does_not_load_is_exit_2(capsys, no_event):
    assert ctf_main(["clock", "--event", "no-such-event", "--now", "0"]) == 2
    err = capsys.readouterr().err
    assert "no-such-event" in err and "did not load" in err


def test_cli_ctf_event_that_does_not_load_is_exit_2(capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "no-such-event")
    assert ctf_main(["clock", "--now", "0"]) == 2


def test_cli_no_event_named_still_prints_with_reason(capsys, no_event):
    """Four profiles and no CTF_EVENT: the clock prints, and the missing countdown is named."""
    assert ctf_main(["clock", "--now", "2026-11-12T09:00"]) == 0
    out = capsys.readouterr().out
    assert "now Thu 2026-11-12 09:00 EST" in out
    assert "Release countdown: unavailable (no event: EventError: CTF_EVENT is not set" in out


def test_cli_hook_json_and_never_fails(capsys, no_event):
    assert ctf_main(["clock", "--hook", "--hook-event", "SessionStart", "--event", "huntress",
                     "--now", "2026-10-15T14:30"]) == 0
    r = json.loads(capsys.readouterr().out)
    ctx = r["hookSpecificOutput"]["additionalContext"]
    assert r["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert ctx.startswith("CLOCK: now Thu 2026-10-15 14:30 EDT")
    assert ctf_main(["clock", "--hook", "--event", "no-such-event", "--now", "0"]) == 0
    ctx = json.loads(capsys.readouterr().out)["hookSpecificOutput"]["additionalContext"]
    assert "Release countdown: unavailable (event 'no-such-event' did not load" in ctx
    assert ctf_main(["clock", "--hook", "--event", "huntress", "--now", "teatime"]) == 0
    ctx = json.loads(capsys.readouterr().out)["hookSpecificOutput"]["additionalContext"]
    assert "Clock hook error: --now 'teatime'" in ctx


# ------------------------------------------------------------------ the hook script

HOOK = paths.repo_root() / "tools" / "clock_hook"


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if k != "CTF_EVENT"}
    env.update(extra)
    return env


def test_hook_script_prints_hook_json(tmp_path):
    p = subprocess.run([str(HOOK), "--event", "huntress", "--now", "2026-10-15T14:30"], cwd=tmp_path,
                       capture_output=True, text=True, env=_env(), timeout=300)
    assert p.returncode == 0, p.stderr
    r = json.loads(p.stdout)
    assert r["hookSpecificOutput"]["hookEventName"] == "UserPromptSubmit"
    assert "Thu 2026-10-15 14:30 EDT" in r["hookSpecificOutput"]["additionalContext"]


def test_hook_script_resolves_its_checkout_through_a_symlink(tmp_path):
    """Installed as a symlink somewhere else, the hook still finds the checkout it belongs to."""
    link_dir = tmp_path / "bin"
    link_dir.mkdir()
    link = link_dir / "clock_hook"
    link.symlink_to(HOOK)
    p = subprocess.run([str(link), "--hook-event", "SessionStart", "--event", "huntress", "--now",
                        "2026-10-15T14:30"], cwd=tmp_path, capture_output=True, text=True, env=_env(),
                       timeout=300)
    assert p.returncode == 0, p.stderr
    r = json.loads(p.stdout)
    assert r["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert "Thu 2026-10-15 14:30 EDT" in r["hookSpecificOutput"]["additionalContext"]


def test_hook_script_never_blocks_the_prompt_when_ctf_cannot_run(tmp_path):
    """No interpreter: `ctfpy` exits 2 (which would block a Claude prompt); the hook exits 0 and
    puts a named CLOCK line in the context instead."""
    p = subprocess.run([str(HOOK), "--event", "huntress"], cwd=tmp_path, capture_output=True, text=True,
                       env=_env(CTF_PYTHON=str(tmp_path / "no-python")), timeout=300)
    assert p.returncode == 0
    assert p.stdout.startswith("CLOCK: unavailable (tools/clock_hook: `ctf clock --hook` exited 2;")
