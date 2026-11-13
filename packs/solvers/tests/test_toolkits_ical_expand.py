"""B-103: the RFC 5545 recurrence expander (solvers/toolkits/ical_expand.py).

Every expected instance below is hand-computed from the calendar text in the test (weekday and DST
dates of 2026 worked out by hand: 2026-07-20 is a Monday; US DST starts 2026-03-08 and ends
2026-11-01; EU summer time is +02:00 in July), never produced by the code under test.
"""
from __future__ import annotations

import datetime as dt
import json

import pytest

import ical_expand as ix

UTC = dt.timezone.utc


def U(y, mo, d, h=0, mi=0, s=0):
    return dt.datetime(y, mo, d, h, mi, s, tzinfo=UTC)


def cal(*events: str, extra: str = "") -> str:
    return "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//b103 test//EN\r\n" + extra + "".join(
        "BEGIN:VEVENT\r\n" + e.strip().replace("\n", "\r\n") + "\r\nEND:VEVENT\r\n" for e in events) + \
        "END:VCALENDAR\r\n"


def starts(occs, uid=None):
    return [o.start for o in occs if uid is None or o.uid == uid]


# The challenge-9102 shape (synthetic): three masters, RDATE adds, EXDATE removes, and detached
# RECURRENCE-ID overrides that move one instance out of the window and one into it.
RELAY_1 = """UID:relay-1
DTSTART:20260716T070000Z
DTEND:20260716T080000Z
RRULE:FREQ=DAILY;INTERVAL=2;COUNT=12
RDATE:20260721T070000Z
EXDATE:20260726T070000Z
SUMMARY:Relay one
CATEGORIES:RELAY,NORTH"""
RELAY_1_OUT = """UID:relay-1
RECURRENCE-ID:20260720T070000Z
DTSTART:20260719T070000Z
DTEND:20260719T080000Z
SUMMARY:Relay one (moved)
CATEGORIES:RELAY"""
RELAY_1_IN = """UID:relay-1
RECURRENCE-ID:20260805T070000Z
DTSTART:20260803T100000Z
DTEND:20260803T110000Z
SUMMARY:Relay one (moved)
CATEGORIES:RELAY"""
RELAY_2 = """UID:relay-2
DTSTART:20260720T090000Z
DTEND:20260720T093000Z
RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR;COUNT=12
RDATE:20260725T090000Z
SUMMARY:Relay two
CATEGORIES:RELAY"""
RELAY_3 = """UID:relay-3
DTSTART:20260717T130000Z
DURATION:PT2H
RRULE:FREQ=DAILY;INTERVAL=2;UNTIL=20260804T130000Z
RDATE:20260720T130000Z
SUMMARY:Relay three
CATEGORIES:BACKUP"""
CASE = cal(RELAY_1, RELAY_1_OUT, RELAY_1_IN, RELAY_2, RELAY_3)
LO, HI = U(2026, 7, 20), U(2026, 8, 4)

EXPECTED_IN_WINDOW = sorted(
    [(U(2026, 7, d, 7), "relay-1") for d in (21, 22, 24, 28, 30)]
    + [(U(2026, 8, 1, 7), "relay-1"), (U(2026, 8, 3, 7), "relay-1"), (U(2026, 8, 3, 10), "relay-1")]
    + [(U(2026, 7, d, 9), "relay-2") for d in (20, 22, 24, 25, 27, 29, 31)] + [(U(2026, 8, 3, 9), "relay-2")]
    + [(U(2026, 7, d, 13), "relay-3") for d in (20, 21, 23, 25, 27, 29, 31)] + [(U(2026, 8, 2, 13), "relay-3")])


# ------------------------------------------------------------------------------------------- parser
def test_unfold_quoted_params_and_text_escapes():
    text = ("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:a\r\nDTSTART:20260720T070000Z\r\n"
            "SUMMARY:Line one\\nwith a comma\\, a semi\\; and a back\\\\slash\r\n"
            "LOCATION;ALTREP=\"http://x.test/a:b;c\":Ro\r\n om 4\r\n"
            "CATEGORIES:A\\,B,C\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
    root = ix.parse(text)[0]
    ev = root.children[0]
    assert ev.get("LOCATION").param("ALTREP") == "http://x.test/a:b;c"
    assert ev.get("LOCATION").value == "Room 4"          # folded line joined, one leading space dropped
    occ = ix.expand(ix.parse(text)).occurrences[0]
    assert occ.summary == "Line one\nwith a comma, a semi; and a back\\slash"
    assert occ.categories == ("A,B", "C")
    assert occ.location == "Room 4"


@pytest.mark.parametrize("text, needle", [
    ("BEGIN:VCALENDAR\nBEGIN:VEVENT\nEND:VCALENDAR\n", "END:VCALENDAR but VEVENT is open"),
    ("UID:x\n", "outside any component"),
    ("BEGIN:VCALENDAR\nBEGIN:VEVENT\n", "unterminated component"),
    ("BEGIN:VCALENDAR\nX;Y:1\nEND:VCALENDAR\n", "malformed parameter"),
    ("BEGIN:VCALENDAR\nNOCOLON\nEND:VCALENDAR\n", "expected ':'"),
    ("\r\n\r\n", "no iCalendar component"),
])
def test_malformed_calendars_raise_with_a_reason(text, needle):
    with pytest.raises(ix.IcalError, match=needle):
        ix.parse(text)


def test_values_parse_and_refuse_garbage():
    assert ix.parse_datetime_value("20260720T070000Z") == ix.When(dt.datetime(2026, 7, 20, 7), "utc")
    assert ix.parse_datetime_value("2026-07-20T07:00:00Z").kind == "utc"
    assert ix.parse_datetime_value("20260720T070000", tzid="Europe/Berlin").kind == "tz"
    assert ix.parse_datetime_value("20260720").kind == "date"
    assert ix.parse_duration("P1W2DT3H4M5S") == ix.Duration(days=9, seconds=3 * 3600 + 4 * 60 + 5)
    assert ix.parse_duration("-PT15M") == ix.Duration(seconds=-900)
    assert ix.parse_offset("-0430") == -dt.timedelta(hours=4, minutes=30)
    for bad in ("2026072", "20261340T000000Z", "20260720T250000Z"):
        with pytest.raises(ix.IcalError):
            ix.parse_datetime_value(bad)
    with pytest.raises(ix.IcalError, match="also has TZID"):
        ix.parse_datetime_value("20260720T070000Z", tzid="Europe/Berlin")
    for bad in ("P", "PT", "1D", "P1H"):
        with pytest.raises(ix.IcalError):
            ix.parse_duration(bad)


@pytest.mark.parametrize("rule, needle", [
    ("FREQ=DAILY;BYFOO=1", "unknown rule part"),
    ("FREQ=SOMETIMES", "FREQ missing or unknown"),
    ("INTERVAL=2", "FREQ missing"),
    ("FREQ=DAILY;COUNT=0", "must be >= 1"),
    ("FREQ=DAILY;COUNT=2;COUNT=3", "given twice"),
    ("FREQ=MONTHLY;BYMONTHDAY=0", "out of range"),
    ("FREQ=DAILY;BYHOUR=24", "out of range"),
    ("FREQ=WEEKLY;BYDAY=XX", "BYDAY value"),
])
def test_bad_rules_are_errors_not_guesses(rule, needle):
    exp = ix.expand_text(cal(f"UID:r\nDTSTART:20260720T070000Z\nRRULE:{rule}"))
    assert exp.occurrences == []
    assert len(exp.errors) == 1 and needle in exp.errors[0] and "UID r" in exp.errors[0]


# ------------------------------------------------------------------------------ the 9102 shape
def test_window_selection_matches_the_hand_computed_activations():
    exp = ix.expand_text(CASE, start=LO, end=HI)
    assert exp.errors == []
    sel = ix.select(exp.occurrences, LO, HI)
    assert [(o.start, o.uid) for o in sel] == EXPECTED_IN_WINDOW
    assert len(sel) == 24


def test_overrides_move_instances_out_of_and_into_the_window():
    exp = ix.expand_text(CASE, start=LO, end=HI)
    by_rid = {(o.uid, o.recurrence_id): o for o in exp.occurrences}
    moved_out = by_rid[("relay-1", U(2026, 7, 20, 7))]
    assert moved_out.start == U(2026, 7, 19, 7) and moved_out.overridden
    assert not ix.in_window(moved_out, LO, HI)
    moved_in = by_rid[("relay-1", U(2026, 8, 5, 7))]        # RID outside the window, start inside
    assert (moved_in.start, moved_in.end) == (U(2026, 8, 3, 10), U(2026, 8, 3, 11))
    assert moved_in.summary == "Relay one (moved)" and moved_in.categories == ("RELAY",)
    assert moved_in.flags == ()                              # the override stated every property
    # the nominal relay-1 08-05 instance is gone (replaced), and the EXDATE'd 07-26 never appears
    assert U(2026, 8, 5, 7) not in starts(exp.occurrences, "relay-1")
    assert U(2026, 7, 26, 7) not in starts(exp.occurrences, "relay-1")


def test_an_override_whose_rid_is_months_outside_the_window_is_placed_cleanly():
    # The RID (03-01) is four months before the July window, far past the 2-day pad, so the
    # windowed generation never produces it: the override must still be matched to its real
    # instance (no exdate-override / orphan flag) and land at its new start inside the window.
    text = cal("UID:mo\nDTSTART:20260101T090000Z\nDTEND:20260101T100000Z\nRRULE:FREQ=MONTHLY\n"
               "SUMMARY:monthly\nCATEGORIES:OPS",
               "UID:mo\nRECURRENCE-ID:20260301T090000Z\nDTSTART:20260715T090000Z\nDTEND:20260715T100000Z\n"
               "SUMMARY:moved\nCATEGORIES:OPS")
    lo, hi = U(2026, 7, 1), U(2026, 8, 1)
    exp = ix.expand_text(text, start=lo, end=hi)
    assert exp.errors == []
    sel = ix.select(exp.occurrences, lo, hi)
    assert [(o.start, o.recurrence_id, o.source) for o in sel] == [
        (U(2026, 7, 1, 9), U(2026, 7, 1, 9), "rrule"),
        (U(2026, 7, 15, 9), U(2026, 3, 1, 9), "override")]
    moved = sel[1]
    assert moved.overridden and moved.end == U(2026, 7, 15, 10) and moved.flags == ()
    assert all(o.flags == () for o in exp.occurrences)


def test_an_override_and_a_dtstart_exactly_on_until_are_instances():
    # UNTIL is inclusive (RFC 5545 3.3.10): an instance at UNTIL exists, so an override naming it
    # is no orphan and replaces it, and a DTSTART equal to UNTIL is on its rule (not unsynced).
    text = cal(RELAY_3,
               "UID:relay-3\nRECURRENCE-ID:20260804T130000Z\nDTSTART:20260721T150000Z\n"
               "DURATION:PT2H\nSUMMARY:Relay three (moved)\nCATEGORIES:BACKUP")
    lo, hi = U(2026, 7, 20), U(2026, 7, 22)          # padded window ends 07-24, well before UNTIL
    exp = ix.expand_text(text, start=lo, end=hi)
    assert exp.errors == []
    by = {o.recurrence_id: o for o in exp.occurrences}
    moved = by[U(2026, 8, 4, 13)]
    assert (moved.start, moved.end, moved.source) == (U(2026, 7, 21, 15), U(2026, 7, 21, 17), "override")
    assert moved.flags == ()
    assert [o.start for o in ix.select(exp.occurrences, lo, hi)] == [
        U(2026, 7, 20, 13), U(2026, 7, 21, 13), U(2026, 7, 21, 15)]
    # unwindowed: the 08-04 instance is replaced, not doubled, and nothing is flagged
    full = ix.expand_text(text)
    assert U(2026, 8, 4, 13) not in starts(full.occurrences) and len(full.occurrences) == 11
    assert all(o.flags == () for o in full.occurrences)
    one = ix.expand_text(cal("UID:one\nDTSTART:20260804T130000Z\nRRULE:FREQ=DAILY;UNTIL=20260804T130000Z"))
    assert [(o.start, o.flags) for o in one.occurrences] == [(U(2026, 8, 4, 13), ())]


def test_durations_from_dtend_and_duration():
    sel = ix.select(ix.expand_text(CASE, start=LO, end=HI).occurrences, LO, HI)
    for o in sel:
        want = {"relay-1": dt.timedelta(hours=1), "relay-2": dt.timedelta(minutes=30),
                "relay-3": dt.timedelta(hours=2)}[o.uid]
        assert o.end - o.start == want, o


def test_finite_rules_expand_fully_without_a_window_and_until_is_inclusive():
    exp = ix.expand_text(CASE)
    assert exp.errors == []
    # relay-1: 12 nominal + 1 RDATE - 1 EXDATE (overrides replace); relay-2: 12 + 1; relay-3: 07-17..08-04
    # every 2nd day = 10 (UNTIL equals the last instance, so it is included) + 1 RDATE
    assert [len(starts(exp.occurrences, u)) for u in ("relay-1", "relay-2", "relay-3")] == [12, 13, 11]
    assert U(2026, 8, 4, 13) in starts(exp.occurrences, "relay-3")
    one_sec_less = ix.expand_text(cal(RELAY_3.replace("UNTIL=20260804T130000Z", "UNTIL=20260804T125959Z")))
    assert U(2026, 8, 4, 13) not in starts(one_sec_less.occurrences)
    assert len(one_sec_less.occurrences) == 10


def test_unbounded_rule_needs_a_window_and_does_not_sink_the_rest():
    text = cal("UID:forever\nDTSTART:20260701T060000Z\nRRULE:FREQ=WEEKLY", RELAY_2)
    exp = ix.expand_text(text)
    assert len(exp.errors) == 1 and "forever" in exp.errors[0] and "never ends" in exp.errors[0]
    assert len(starts(exp.occurrences, "relay-2")) == 13
    win = ix.expand_text(text, start=U(2026, 7, 20), end=U(2026, 8, 4))
    assert win.errors == []
    got = starts(ix.select(win.occurrences, U(2026, 7, 20), U(2026, 8, 4)), "forever")
    assert got == [U(2026, 7, 22, 6), U(2026, 7, 29, 6)]        # 07-01 is a Wednesday


def test_max_instances_cap_is_loud():
    exp = ix.expand_text(cal("UID:many\nDTSTART:20260101T000000Z\nRRULE:FREQ=HOURLY;COUNT=500"),
                         max_instances=100)
    assert exp.occurrences == [] and "more than 100 instances" in exp.errors[0]


def test_monthly_last_friday_and_bysetpos():
    exp = ix.expand_text(cal(
        "UID:lastfri\nDTSTART:20260731T120000Z\nRRULE:FREQ=MONTHLY;BYDAY=-1FR;COUNT=3",
        "UID:setpos\nDTSTART:20260731T080000Z\nRRULE:FREQ=MONTHLY;BYDAY=MO,TU,WE,TH,FR;BYSETPOS=-1;COUNT=2"))
    assert starts(exp.occurrences, "lastfri") == [U(2026, 7, 31, 12), U(2026, 8, 28, 12), U(2026, 9, 25, 12)]
    # last weekday of July 2026 is Fri 07-31; of August 2026 is Mon 08-31
    assert starts(exp.occurrences, "setpos") == [U(2026, 7, 31, 8), U(2026, 8, 31, 8)]


# ----------------------------------------------------------------------------------- time zones
def test_tzid_series_keeps_local_wall_clock_across_dst():
    exp = ix.expand_text(cal(
        "UID:ny\nDTSTART;TZID=America/New_York:20261030T090000\nDTEND;TZID=America/New_York:20261030T100000\n"
        "RRULE:FREQ=DAILY;COUNT=4"))
    assert starts(exp.occurrences) == [U(2026, 10, 30, 13), U(2026, 10, 31, 13), U(2026, 11, 1, 14),
                                       U(2026, 11, 2, 14)]


def test_dst_gap_uses_the_offset_before_the_gap():
    exp = ix.expand_text(cal("UID:gap\nDTSTART;TZID=America/New_York:20260307T023000\nRRULE:FREQ=DAILY;COUNT=3"))
    # 03-08 02:30 does not exist in New York: read with EST (-5), i.e. 03:30 EDT
    assert starts(exp.occurrences) == [U(2026, 3, 7, 7, 30), U(2026, 3, 8, 7, 30), U(2026, 3, 9, 6, 30)]


def test_duration_is_nominal_but_dtend_is_exact_across_dst():
    exp = ix.expand_text(cal(
        "UID:nominal\nDTSTART;TZID=America/New_York:20261031T120000\nDURATION:P1D\nRRULE:FREQ=DAILY;COUNT=2",
        "UID:exact\nDTSTART;TZID=America/New_York:20261031T120000\n"
        "DTEND;TZID=America/New_York:20261101T120000\nRRULE:FREQ=DAILY;COUNT=2"))
    nom = [(o.start, o.end) for o in exp.occurrences if o.uid == "nominal"]
    exa = [(o.start, o.end) for o in exp.occurrences if o.uid == "exact"]
    assert nom == [(U(2026, 10, 31, 16), U(2026, 11, 1, 17)), (U(2026, 11, 1, 17), U(2026, 11, 2, 17))]
    # DTEND fixes an exact 25 h length (it spans the fall-back), applied to every instance
    assert exa == [(U(2026, 10, 31, 16), U(2026, 11, 1, 17)), (U(2026, 11, 1, 17), U(2026, 11, 2, 18))]


VTZ_FIXED = """BEGIN:VTIMEZONE
TZID:America/New_York
BEGIN:STANDARD
DTSTART:19700101T000000
TZOFFSETFROM:-0400
TZOFFSETTO:-0400
END:STANDARD
END:VTIMEZONE
"""
VTZ_RELAY = """BEGIN:VTIMEZONE
TZID:Relay Standard Time
BEGIN:STANDARD
DTSTART:19701025T030000
TZOFFSETFROM:+0300
TZOFFSETTO:+0200
RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:19700329T020000
TZOFFSETFROM:+0200
TZOFFSETTO:+0300
RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU
END:DAYLIGHT
END:VTIMEZONE
"""


def test_a_vtimezone_in_the_file_wins_over_the_iana_zone_of_the_same_name():
    exp = ix.expand_text(cal("UID:v\nDTSTART;TZID=America/New_York:20260115T100000", extra=VTZ_FIXED))
    assert starts(exp.occurrences) == [U(2026, 1, 15, 14)]        # IANA would give 15:00Z (EST)


def test_vtimezone_with_dst_rules():
    exp = ix.expand_text(cal(
        "UID:s\nDTSTART;TZID=Relay Standard Time:20260720T100000",
        "UID:w\nDTSTART;TZID=Relay Standard Time:20260115T100000",
        "UID:g\nDTSTART;TZID=Relay Standard Time:20260329T023000", extra=VTZ_RELAY))
    got = {o.uid: o.start for o in exp.occurrences}
    assert got["s"] == U(2026, 7, 20, 7)          # summer: +03:00
    assert got["w"] == U(2026, 1, 15, 8)          # winter: +02:00
    assert got["g"] == U(2026, 3, 29, 0, 30)      # 2026-03-29 02:30 is in the gap: +02:00 before it


def test_unknown_tzid_is_an_error_and_a_vendor_prefixed_tzid_is_read_with_a_warning():
    bad = ix.expand_text(cal("UID:x\nDTSTART;TZID=Mars/Olympus:20260720T100000"))
    assert bad.occurrences == [] and "Mars/Olympus" in bad.errors[0]
    pre = ix.expand_text(cal("UID:y\nDTSTART;TZID=/example.test/20260101_1/Europe/Berlin:20260720T100000"))
    assert starts(pre.occurrences) == [U(2026, 7, 20, 8)]
    assert any("Europe/Berlin" in w for w in pre.warnings)


def test_exdate_and_recurrence_id_match_across_spellings():
    exp = ix.expand_text(cal(
        "UID:b\nDTSTART;TZID=Europe/Berlin:20260720T090000\nRRULE:FREQ=DAILY;COUNT=4\nEXDATE:20260721T070000Z",
        "UID:b\nRECURRENCE-ID;TZID=Europe/Berlin:20260722T090000\nDTSTART:20260722T120000Z\nDTEND:20260722T130000Z"))
    assert starts(exp.occurrences) == [U(2026, 7, 20, 7), U(2026, 7, 22, 12), U(2026, 7, 23, 7)]
    assert exp.occurrences[1].recurrence_id == U(2026, 7, 22, 7)


def test_floating_and_all_day_need_an_explicit_zone():
    text = cal("UID:f\nDTSTART:20260720T090000\nDTEND:20260720T100000",
               "UID:d\nDTSTART;VALUE=DATE:20260721\nRRULE:FREQ=DAILY;COUNT=2", RELAY_2)
    exp = ix.expand_text(text)
    assert {e.split(":")[0] for e in exp.errors} == {"UID f", "UID d"}
    assert all("floating_tz" in e for e in exp.errors)
    assert len(starts(exp.occurrences, "relay-2")) == 13
    ok = ix.expand_text(text, floating_tz="UTC")
    assert ok.errors == []
    f = [o for o in ok.occurrences if o.uid == "f"][0]
    assert (f.start, f.end) == (U(2026, 7, 20, 9), U(2026, 7, 20, 10))
    d = [(o.start, o.end, o.all_day) for o in ok.occurrences if o.uid == "d"]
    assert d == [(U(2026, 7, 21), U(2026, 7, 22), True), (U(2026, 7, 22), U(2026, 7, 23), True)]
    berlin = ix.expand_text(text, floating_tz="Europe/Berlin")
    assert [o.start for o in berlin.occurrences if o.uid == "f"] == [U(2026, 7, 20, 7)]


def test_rdate_period_carries_its_own_length():
    exp = ix.expand_text(cal("UID:p\nDTSTART:20260720T070000Z\nDTEND:20260720T080000Z\n"
                             "RDATE;VALUE=PERIOD:20260722T100000Z/PT30M,20260723T100000Z/20260723T130000Z"))
    assert [(o.start, o.end) for o in exp.occurrences] == [
        (U(2026, 7, 20, 7), U(2026, 7, 20, 8)), (U(2026, 7, 22, 10), U(2026, 7, 22, 10, 30)),
        (U(2026, 7, 23, 10), U(2026, 7, 23, 13))]


def test_thisandfuture_shifts_the_rest_of_the_series():
    exp = ix.expand_text(cal(
        "UID:t\nDTSTART:20260720T070000Z\nDTEND:20260720T080000Z\nRRULE:FREQ=DAILY;COUNT=5",
        "UID:t\nRECURRENCE-ID;RANGE=THISANDFUTURE:20260722T070000Z\nDTSTART:20260722T090000Z\n"
        "DTEND:20260722T103000Z\nSUMMARY:later"))
    got = [(o.start, o.end, o.overridden) for o in exp.occurrences]
    assert got == [(U(2026, 7, 20, 7), U(2026, 7, 20, 8), False), (U(2026, 7, 21, 7), U(2026, 7, 21, 8), False),
                   (U(2026, 7, 22, 9), U(2026, 7, 22, 10, 30), True),
                   (U(2026, 7, 23, 9), U(2026, 7, 23, 10, 30), True),
                   (U(2026, 7, 24, 9), U(2026, 7, 24, 10, 30), True)]
    assert [o.summary for o in exp.occurrences][2:] == ["later"] * 3


# --------------------------------------------------------------------------- flags (undefined cases)
def test_undefined_cases_are_flagged_not_hidden():
    exp = ix.expand_text(cal(
        # DTSTART is a Tuesday, the rule says Mondays
        "UID:u\nDTSTART:20260721T070000Z\nRRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=2",
        # an override naming no instance, and one of an EXDATE'd instance
        "UID:o\nDTSTART:20260720T070000Z\nDTEND:20260720T080000Z\nRRULE:FREQ=DAILY;COUNT=3\n"
        "EXDATE:20260721T070000Z\nSUMMARY:base",
        "UID:o\nRECURRENCE-ID:20260725T070000Z\nDTSTART:20260725T090000Z\nDTEND:20260725T100000Z\nSUMMARY:x",
        "UID:o\nRECURRENCE-ID:20260721T070000Z\nDTSTART:20260721T090000Z\nDTEND:20260721T100000Z\nSUMMARY:y",
        "UID:cu\nDTSTART:20260720T070000Z\nRRULE:FREQ=DAILY;COUNT=5;UNTIL=20260721T070000Z"))
    by = {(o.uid, o.recurrence_id): o for o in exp.occurrences}
    assert starts(exp.occurrences, "u") == [U(2026, 7, 21, 7), U(2026, 7, 27, 7), U(2026, 8, 3, 7)]
    assert all(ix.FLAG_DTSTART_UNSYNCED in o.flags for o in exp.occurrences if o.uid == "u")
    assert ix.FLAG_ORPHAN in by[("o", U(2026, 7, 25, 7))].flags
    assert ix.FLAG_EXDATE_OVERRIDE in by[("o", U(2026, 7, 21, 7))].flags
    assert by[("o", U(2026, 7, 20, 7))].flags == ()
    assert starts(exp.occurrences, "cu") == [U(2026, 7, 20, 7), U(2026, 7, 21, 7)]
    assert all(ix.FLAG_COUNT_AND_UNTIL in o.flags for o in exp.occurrences if o.uid == "cu")


def test_duplicate_override_keeps_the_highest_sequence():
    exp = ix.expand_text(cal(
        "UID:d\nDTSTART:20260720T070000Z\nRRULE:FREQ=DAILY;COUNT=2",
        "UID:d\nRECURRENCE-ID:20260721T070000Z\nSEQUENCE:3\nDTSTART:20260721T100000Z",
        "UID:d\nRECURRENCE-ID:20260721T070000Z\nSEQUENCE:1\nDTSTART:20260721T120000Z"))
    o = exp.occurrences[1]
    assert o.start == U(2026, 7, 21, 10) and o.sequence == 3 and ix.FLAG_DUPLICATE_OVERRIDE in o.flags


def test_override_inherits_missing_properties_and_says_so():
    exp = ix.expand_text(cal(
        "UID:i\nDTSTART:20260720T070000Z\nDTEND:20260720T080000Z\nRRULE:FREQ=DAILY;COUNT=2\n"
        "SUMMARY:base\nCATEGORIES:OPS",
        "UID:i\nRECURRENCE-ID:20260721T070000Z\nDTSTART:20260721T100000Z\nSUMMARY:moved"))
    o = exp.occurrences[1]
    assert (o.start, o.end) == (U(2026, 7, 21, 10), U(2026, 7, 21, 11))      # master's 1 h kept
    assert o.summary == "moved" and o.categories == ("OPS",)
    assert set(o.flags) == {"inherited:END", "inherited:CATEGORIES"}


def test_until_type_mismatch_is_flagged():
    exp = ix.expand_text(cal("UID:m\nDTSTART:20260720T070000Z\nRRULE:FREQ=DAILY;UNTIL=20260722"))
    assert starts(exp.occurrences) == [U(2026, 7, 20, 7), U(2026, 7, 21, 7), U(2026, 7, 22, 7)]
    assert all(ix.FLAG_UNTIL_TYPE in o.flags for o in exp.occurrences)


def test_two_masters_with_one_uid_are_refused():
    exp = ix.expand_text(cal("UID:dup\nDTSTART:20260720T070000Z", "UID:dup\nDTSTART:20260721T070000Z"))
    assert exp.occurrences == [] and "2 master components" in exp.errors[0]


def test_dtend_before_dtstart_is_an_error():
    exp = ix.expand_text(cal("UID:neg\nDTSTART:20260720T070000Z\nDTEND:20260720T060000Z"))
    assert exp.occurrences == [] and "DTEND is before DTSTART" in exp.errors[0]


# --------------------------------------------------------------------------------- membership
def test_window_bounds_basis_and_cancelled():
    exp = ix.expand_text(cal(
        "UID:edge\nDTSTART:20260804T000000Z\nDTEND:20260804T010000Z",          # starts exactly at HI
        "UID:early\nDTSTART:20260720T000000Z",                                 # zero length, exactly at LO
        "UID:span\nDTSTART:20260719T230000Z\nDTEND:20260720T010000Z",          # starts before, ends inside
        "UID:touch\nDTSTART:20260719T220000Z\nDTEND:20260720T000000Z",         # ends exactly at LO
        "UID:gone\nDTSTART:20260725T000000Z\nSTATUS:CANCELLED"))
    occ = exp.occurrences

    def ids(**kw):
        return sorted(o.uid for o in ix.select(occ, LO, HI, **kw))

    assert ids() == ["early"]
    assert ids(end_inclusive=True) == ["early", "edge"]
    assert ids(start_inclusive=False) == []
    assert ids(basis="overlap") == ["early", "span"]
    assert ids(cancelled="keep") == ["early", "gone"]
    with pytest.raises(ix.IcalError):
        ix.select(occ, LO, HI, basis="sometime")
    with pytest.raises(ix.IcalError, match="naive"):
        ix.select(occ, dt.datetime(2026, 7, 20), HI)


def test_parse_instant_requires_a_zone():
    assert ix.parse_instant("2026-07-20T00:00:00Z") == U(2026, 7, 20)
    assert ix.parse_instant("2026-07-20T02:00:00+02:00") == U(2026, 7, 20)
    assert ix.parse_instant("20260720T000000Z") == U(2026, 7, 20)
    with pytest.raises(ix.IcalError, match="no UTC offset"):
        ix.parse_instant("2026-07-20T00:00:00")


# ---------------------------------------------------------------------------- engine entry + CLI
def test_solve_expands_a_handout_calendar_offline(tmp_path):
    from ctf import event
    (tmp_path / "files").mkdir()
    (tmp_path / "files" / "case.ics").write_text(CASE)
    (tmp_path / "files" / "export.txt").write_text(cal(RELAY_2))      # sniffed by its BEGIN line
    r = ix.solve(tmp_path, event.current())
    assert r.status == "unsure" and r.engine == "toolkits.ical_expand" and r.flags == ()
    assert sorted(e.path for e in r.evidence) == ["files/case.ics", "files/export.txt"]
    assert "36 instance(s)" in r.notes and "13 instance(s)" in r.notes


def test_solve_without_a_calendar_is_none(tmp_path):
    from ctf import event
    (tmp_path / "notes.md").write_text("nothing here")
    assert ix.solve(tmp_path, event.current()).status == "none"


def test_cli_selects_the_window_as_json(tmp_path, capsys):
    p = tmp_path / "case.ics"
    p.write_text(CASE)
    assert ix.main([str(p), "--from", "2026-07-20T00:00:00Z", "--to", "2026-08-04T00:00:00Z", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert [(o["start"], o["uid"]) for o in out["occurrences"]] == [
        (s.strftime("%Y-%m-%dT%H:%M:%SZ"), u) for s, u in EXPECTED_IN_WINDOW]
    assert ix.main([str(tmp_path / "missing.ics")]) == 2
    bad = tmp_path / "bad.ics"
    bad.write_text("BEGIN:VCALENDAR\nBEGIN:VEVENT\n")
    assert ix.main([str(bad)]) == 2


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
