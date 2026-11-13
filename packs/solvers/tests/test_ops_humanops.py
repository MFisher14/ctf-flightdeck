"""B-169: human-only work surfaced early -- task cards, OSINT pin queue, confirm list, reconcile,
the evening checklist, the [human] profile table and the `ctf human` command."""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import subprocess
import sys
import textwrap

import pytest

from ctf import event, humanops, ledger, paths
from ctf.cli import human as cli_human
from ctf.humanops import HumanOps, HumanOpsError

FLAG_A = "flag{" + "a" * 32 + "}"
FLAG_B = "flag{" + "b" * 32 + "}"


class Clock:
    def __init__(self, t=1_760_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def huntress():
    return event.load("huntress")


def with_(prof, **kw):
    """A copy of a shipped profile with some sections replaced."""
    return dataclasses.replace(prof, **kw)


def ops_for(tmp_path, prof=None, clock=None):
    return HumanOps(prof or huntress(), workdir=tmp_path, clock=clock or Clock())


def recs(tmp_path, kind):
    return [r for r in ledger.read(tmp_path) if r["event"] == kind]


# ------------------------------------------------------------------------------- profile table

BASE = textwrap.dedent("""\
    slug = "demo"
    name = "Demo"
    dates = { start = 2027-01-01, end = 2027-01-03 }
    [platform]
    kind = "gamemaster"
    base_url = "https://gm.demo.example"
    [flag]
    prefixes = ["flag"]
    [rules]
    submit_mode = "auto"
    flag_sharing = "allowed"
    ai_on_platform = "allowed"
    """)


def load_demo(tmp_path, extra=""):
    d = tmp_path / "events" / "demo"
    d.mkdir(parents=True)
    (d / "event.toml").write_text(BASE + extra)
    return event.load("demo", root=tmp_path / "events")


def test_profile_human_table_defaults_and_values(tmp_path):
    p = load_demo(tmp_path / "a")
    assert p.human.confirm_system is None and p.human.checklist == ()
    p = load_demo(tmp_path / "b", '[human]\nconfirm_system = "CourseStack"\nchecklist = ["Charge the phone"]\n')
    assert p.human.confirm_system == "CourseStack" and p.human.checklist == ("Charge the phone",)
    p = load_demo(tmp_path / "c", '[human]\nconfirm_system = "  "\n')
    assert p.human.confirm_system is None


@pytest.mark.parametrize("extra, msg", [
    ('[human]\nconfirm_systm = "x"\n', "unknown key(s): human.confirm_systm"),
    ('[human]\nconfirm_system = 3\n', "human.confirm_system must be str"),
    ('[human]\nchecklist = [""]\n', "human.checklist must be a list of non-empty strings"),
])
def test_profile_human_table_rejects_bad_values(tmp_path, extra, msg):
    with pytest.raises(event.EventError, match=msg.replace("(", r"\(").replace(")", r"\)")):
        load_demo(tmp_path, extra)


def test_shipped_huntress_profile_names_coursestack_and_others_do_not():
    assert huntress().human.confirm_system == "CourseStack"
    for slug in ("csctf", "pink", "spooky"):
        assert event.load(slug).human.confirm_system is None


# ------------------------------------------------------------------------------- pins

def test_parse_pin_counts_decimals_and_checks_ranges():
    p = humanops.parse_pin("14.5995,120.9842")
    assert (p.lat, p.lon, p.decimals, p.text) == (14.5995, 120.9842, 4, "14.5995,120.9842")
    assert humanops.parse_pin("-33.86, 151.2").decimals == 1       # the fewer of the two
    assert humanops.parse_pin("10,20").decimals == 0
    q = humanops.parse_pin("14.59,120.98 old walled city", allow_note=True)
    assert q.note == "old walled city" and q.text == "14.59,120.98"
    assert "query=14.59,120.98" in q.map_url
    for bad in ("91.0,10.0", "-90.5,1", "10,180.01", "10,-181"):
        with pytest.raises(HumanOpsError, match="outside"):
            humanops.parse_pin(bad)
    for bad in ("14.5 120.9", "14°35'N,120°59'E", "", "abc", "14.59,120.98 note"):
        with pytest.raises(HumanOpsError, match="is not a pin"):
            humanops.parse_pin(bad)
    assert humanops.parse_pin("90,-180").lat == 90.0


def test_pin_queue_requires_the_cards_decimals_on_the_answer(tmp_path):
    ops = ops_for(tmp_path)
    pin = ops.add_pin("77", ask="the bench in photo 2", decimals=4,
                      candidates=["14.59,120.98 Intramuros", "14.6,121.0"])
    other = ops.add_card("discord", ask="read #comms", need="the word", challenge_id="9091")
    assert [c.id for c in ops.pin_queue()] == [pin.id]                 # cards of other kinds are not pins
    assert [c.text for c in pin.candidates] == ["14.59,120.98", "14.6,121.0"]
    assert pin.candidates[0].note == "Intramuros" and pin.decimals == 4
    with pytest.raises(HumanOpsError, match="at least 4 decimals"):
        ops.answer(pin.id, "14.592,120.9842")
    with pytest.raises(HumanOpsError, match="is not a pin"):
        ops.answer(pin.id, "the bench by the gate")
    done = ops.answer(pin.id, "14.5921, 120.98425", by="max")
    assert done.status == "answered" and done.answer == "14.5921,120.98425" and done.by == "max"
    assert ops.pin_queue() == [] and [c.id for c in ops.cards()] == [other.id]


def test_add_pin_validation(tmp_path):
    ops = ops_for(tmp_path)
    with pytest.raises(HumanOpsError, match="decimals must be"):
        ops.add_pin("1", ask="x", decimals=9)
    with pytest.raises(HumanOpsError, match="decimals must be"):
        ops.add_pin("1", ask="x", decimals=True)
    with pytest.raises(HumanOpsError, match="is not a pin"):
        ops.add_pin("1", ask="x", candidates=["nowhere"])
    with pytest.raises(HumanOpsError, match="challenge is required"):
        ops.add_pin("", ask="x")
    with pytest.raises(HumanOpsError, match="add_pin"):
        ops.add_card("pin", ask="x", need="y")
    assert recs(tmp_path, "human.card") == []                          # nothing half-written


# ------------------------------------------------------------------------------- cards

def test_card_lifecycle_is_replayed_from_the_ledger(tmp_path):
    clock = Clock()
    ops = ops_for(tmp_path, clock=clock)
    a = ops.add_card("discord", ask="Read the #comms-check channel description", need="the recognition word",
                     challenge_id="9091", why="Discord is not reachable by agents", source="lane misc")
    clock.t += 60
    b = ops.add_card("lookup", ask="Censys: hosts with this cert hash", need="the IP list")
    assert a.id != b.id and a.id.startswith("h")
    rec = recs(tmp_path, "human.card")[0]
    assert rec["event_slug"] == "huntress" and rec["kind"] == "discord" and rec["challenge_id"] == "9091"
    # a fresh store over the same ledger sees the same cards, oldest first
    again = HumanOps(huntress(), workdir=tmp_path, clock=clock)
    assert [c.id for c in again.cards()] == [a.id, b.id]
    assert again.card(a.id).why == "Discord is not reachable by agents"
    clock.t += 3600
    assert again.card(a.id).age(clock.t) == pytest.approx(3660)
    again.answer(a.id, "pumpkin", by="max")
    again.drop(b.id, "solved without it")
    assert ops.cards() == []
    assert {c.id: c.status for c in ops.cards(status=None)} == {a.id: "answered", b.id: "dropped"}
    assert ops.cards(status="answered")[0].answer == "pumpkin"
    assert ops.cards(status="dropped")[0].reason == "solved without it"
    assert [c.id for c in ops.cards(status=None, kind="lookup")] == [b.id]
    with pytest.raises(HumanOpsError, match="already answered"):
        ops.answer(a.id, "again")
    with pytest.raises(HumanOpsError, match="already dropped"):
        ops.drop(b.id, "again")
    with pytest.raises(HumanOpsError, match="no task card"):
        ops.answer("hdeadbeef", "x")
    with pytest.raises(HumanOpsError, match="status must be"):
        ops.cards(status="closed")


def test_cards_are_per_event(tmp_path):
    ops_for(tmp_path).add_card("other", ask="x", need="y")
    csctf = HumanOps(event.load("csctf"), workdir=tmp_path)
    assert csctf.cards() == []


@pytest.mark.parametrize("kw, msg", [
    (dict(kind="phone", ask="a", need="b"), "card kind must be one of"),
    (dict(kind="discord", ask="  ", need="b"), "ask is required"),
    (dict(kind="discord", ask="a", need=""), "need is required"),
])
def test_add_card_rejects_bad_cards(tmp_path, kw, msg):
    with pytest.raises(HumanOpsError, match=msg):
        ops_for(tmp_path).add_card(kw.pop("kind"), **kw)
    assert recs(tmp_path, "human.card") == []


def test_answer_with_a_flag_is_refused_when_flag_sharing_is_forbidden(tmp_path):
    prof = huntress()
    closed = with_(prof, rules=dataclasses.replace(prof.rules, flag_sharing="forbidden"))
    ops = ops_for(tmp_path, closed)
    c = ops.add_card("discord", ask="a", need="b")
    with pytest.raises(HumanOpsError, match="forbids flag sharing"):
        ops.answer(c.id, f"it says {FLAG_A}")
    assert recs(tmp_path, "human.card_answer") == []
    assert ops.answer(c.id, "pumpkin").answer == "pumpkin"
    # an event that allows sharing keeps the value
    ops2 = ops_for(tmp_path / "open")
    c2 = ops2.add_card("discord", ask="a", need="b")
    assert ops2.answer(c2.id, FLAG_A).answer == FLAG_A


@pytest.mark.parametrize("field", ["ask", "need", "why", "source"])
def test_card_text_with_a_flag_is_refused_when_flag_sharing_is_forbidden(tmp_path, field):
    prof = huntress()
    closed = ops_for(tmp_path, with_(prof, rules=dataclasses.replace(prof.rules, flag_sharing="forbidden")))
    kw = dict(ask="read #comms", need="the word", why="no Discord", source="lane misc")
    kw[field] = f"check whether {FLAG_A} is right"
    with pytest.raises(HumanOpsError, match=f"forbids flag sharing.*card's {field} contains a flag"):
        closed.add_card("discord", **kw)
    pin_kw = {k: v for k, v in kw.items() if k != "need"}
    if field != "need":                                    # a pin card's need is generated
        with pytest.raises(HumanOpsError, match=f"card's {field} contains a flag"):
            closed.add_pin("77", **pin_kw)
    assert recs(tmp_path, "human.card") == []
    # the same text is kept when the event allows sharing
    shared = ops_for(tmp_path / "open")
    assert FLAG_A in getattr(shared.add_card("discord", **kw), field)


# ------------------------------------------------------------------------------- confirm list

def submit_rec(tmp_path, cid, status, flag=FLAG_A, slug="huntress", **extra):
    ledger.append("platform.submit", workdir=tmp_path, event_slug=slug, challenge_id=cid, status=status,
                  judged=True, guess=False, confirmed=False, provenance="t", flag=flag, **extra)


def test_confirm_list_needs_a_confirm_system(tmp_path):
    ops = HumanOps(event.load("csctf"), workdir=tmp_path)
    for call in (lambda: ops.confirm_list(), lambda: ops.add_confirm("1", flag="CSCTF{x}"),
                 lambda: ops.mark_confirmed("1"), lambda: ops.reconcile([])):
        with pytest.raises(HumanOpsError, match=r"no off-platform confirm system.*\[human\] confirm_system"):
            call()


def test_confirm_list_merges_explicit_items_and_game_master_accepts(tmp_path):
    clock = Clock()
    ops = ops_for(tmp_path, clock=clock)
    submit_rec(tmp_path, "5#q1", "correct", FLAG_A)
    submit_rec(tmp_path, "6", "incorrect", FLAG_B)                    # never on the list
    submit_rec(tmp_path, "7", "already_solved", FLAG_B)
    submit_rec(tmp_path, "8", "rate_limited", FLAG_B)                 # unjudged: not on the list
    submit_rec(tmp_path, "9", "correct", FLAG_B, slug="csctf")         # another event
    ops.add_confirm("12", flag=FLAG_B, points=50, name="Timed Trial", note="from the timed result")
    ops.add_confirm("7", flag=FLAG_A, points=10)                       # explicit beats the GM record
    items = {i.challenge_id: i for i in ops.confirm_list()}
    assert set(items) == {"5#q1", "7", "12"}
    assert items["5#q1"].source == "game master" and items["5#q1"].flag == FLAG_A
    assert items["7"].source == "agent" and items["7"].flag == FLAG_A and items["7"].points == 10
    assert items["12"].name == "Timed Trial"


def test_already_solved_accept_without_an_explicit_item_is_listed(tmp_path):
    ops = ops_for(tmp_path)
    submit_rec(tmp_path, "21", "already_solved", FLAG_B)
    items = ops.confirm_list()
    assert [(i.challenge_id, i.source, i.flag) for i in items] == [("21", "game master", FLAG_B)]


def test_first_accepted_submit_for_a_challenge_is_kept(tmp_path, monkeypatch):
    ops = ops_for(tmp_path)
    for ts, status, flag in ((1_760_000_100.0, "correct", FLAG_A), (1_760_000_900.0, "already_solved", FLAG_B)):
        with monkeypatch.context() as m:
            m.setattr(ledger.time, "time", lambda ts=ts: ts)
            submit_rec(tmp_path, "30", status, flag)
    assert [r["ts"] for r in recs(tmp_path, "platform.submit")] == [1_760_000_100.0, 1_760_000_900.0]
    [it] = ops.confirm_list()
    assert (it.challenge_id, it.flag, it.since) == ("30", FLAG_A, 1_760_000_100.0)


def test_mark_confirmed_and_readd_reopens(tmp_path):
    ops = ops_for(tmp_path)
    submit_rec(tmp_path, "5", "correct")
    ops.add_confirm("12", flag=FLAG_B)
    it = ops.mark_confirmed("5", by="max")
    assert it.done and it.done_by == "max"
    assert [i.challenge_id for i in ops.confirm_list()] == ["12"]
    assert {i.challenge_id for i in ops.confirm_list(include_done=True)} == {"5", "12"}
    with pytest.raises(HumanOpsError, match="already confirmed"):
        ops.mark_confirmed("5")
    with pytest.raises(HumanOpsError, match="not on the confirm list"):
        ops.mark_confirmed("99")
    ops.mark_confirmed(" 12 ")                                          # whitespace-insensitive id
    assert ops.confirm_list() == []
    ops.add_confirm("12", flag=FLAG_A)                                  # a corrected flag: pending again
    assert [(i.challenge_id, i.flag, i.done) for i in ops.confirm_list()] == [("12", FLAG_A, False)]


def test_add_confirm_validation_and_flag_sharing(tmp_path):
    ops = ops_for(tmp_path)
    with pytest.raises(HumanOpsError, match="needs the flag"):
        ops.add_confirm("1")
    with pytest.raises(HumanOpsError, match="points must be"):
        ops.add_confirm("1", flag=FLAG_A, points=-1)
    prof = huntress()
    closed = ops_for(tmp_path / "closed", with_(prof, rules=dataclasses.replace(prof.rules, flag_sharing="forbidden")))
    with pytest.raises(HumanOpsError, match="give --where"):
        closed.add_confirm("1", flag=FLAG_A)
    it = closed.add_confirm("1", flag=FLAG_A, where="challenges/1/FLAG")
    assert it.flag is None and it.flag_sha256 == humanops._sha(FLAG_A) and it.where == "challenges/1/FLAG"
    raw = (tmp_path / "closed" / "ledger.jsonl").read_text()
    assert FLAG_A not in raw
    assert "value in challenges/1/FLAG" in humanops.confirm_line(it)


def test_live_solves_add_what_the_ledger_lacks(tmp_path):
    ops = ops_for(tmp_path)
    submit_rec(tmp_path, "5#q1", "correct")

    class Solve:
        def __init__(self, cid):
            self.challenge_id = cid

    items = ops.confirm_list(live_solves=[Solve("5"), Solve("44"), Solve("")])
    got = {i.challenge_id: i.source for i in items}
    assert got == {"5#q1": "game master", "44": "game master (live)"}   # "5" is covered by "5#q1"
    assert "find the flag" in humanops.confirm_line([i for i in items if i.challenge_id == "44"][0])


# ------------------------------------------------------------------------------- reconcile

def write_truth(tmp_path, text, name="cs.csv"):
    p = tmp_path / name
    p.write_text(textwrap.dedent(text))
    return p


def test_read_truth_parses_and_rejects(tmp_path):
    rows = humanops.read_truth(write_truth(tmp_path, """\
        # exported 2026-10-20
        Challenge,Points,Flag
        12,50,%s

        5#q1,,
        """ % FLAG_A))
    assert [(r.challenge_id, r.points, r.flag, r.line) for r in rows] == [
        ("12", 50.0, FLAG_A, 2), ("5#q1", None, None, 3)]
    for text, msg in [("id,points\n1,2\n", "must name a 'challenge' column"),
                      ("challenge,score\n1,2\n", "unknown column"),
                      ("challenge,points\n1,ten\n", "is not a number"),
                      ("challenge\n1\n 1 \n", "listed twice"),
                      ("challenge,points\n,5\n", "no challenge"),
                      ("# only a comment\n\n", "empty")]:
        with pytest.raises(HumanOpsError, match=msg):
            humanops.read_truth(write_truth(tmp_path, text, "bad.csv"))
    with pytest.raises(HumanOpsError, match="no truth file"):
        humanops.read_truth(tmp_path / "absent.csv")


def test_reconcile_reports_every_kind_of_disagreement(tmp_path):
    ops = ops_for(tmp_path)
    submit_rec(tmp_path, "1", "correct", FLAG_A)        # agrees (flag + no points)
    submit_rec(tmp_path, "2", "correct", FLAG_A)        # missing from CourseStack
    submit_rec(tmp_path, "3", "correct", FLAG_A)        # flag differs
    submit_rec(tmp_path, "5#q1", "correct", FLAG_A)     # matches a bare challenge row
    ops.add_confirm("4", flag=FLAG_B, points=50)       # points differ
    ops.add_confirm("6", flag=FLAG_B, points=20)       # agrees on points
    ops.mark_confirmed("2")                              # ticked here, but absent there
    truth = humanops.read_truth(write_truth(tmp_path, f"""\
        challenge,points,flag
        1,,{FLAG_A}
        3,,{FLAG_B}
        4,40,
        5,,
        6,20,{FLAG_B}
        99,10,
        """))
    rep = ops.reconcile(truth)
    assert sorted(i.challenge_id for i in rep.agree) == ["1", "5#q1", "6"]
    assert [i.challenge_id for i in rep.missing] == ["2"] and rep.missing[0].done
    assert [t.challenge_id for t in rep.extra] == ["99"]
    assert [(i.challenge_id, t.flag) for i, t in rep.flag_mismatch] == [("3", FLAG_B)]
    assert [(i.points, t.points) for i, t in rep.points_mismatch] == [(50.0, 40.0)]
    assert not rep.clean
    text = humanops.render_reconciliation(rep)
    assert "MARKED CONFIRMED HERE BUT ABSENT" in text and "ACTION NEEDED" in text and "99" in text
    rec = recs(tmp_path, "human.reconcile")[-1]
    assert rec["system"] == "CourseStack" and rec["missing"] == 1 and rec["extra"] == 1 \
        and rec["flag_mismatch"] == 1 and rec["points_mismatch"] == 1 and rec["agree"] == 3


def test_reconcile_clean_and_hash_only_flags(tmp_path):
    prof = huntress()
    closed = ops_for(tmp_path, with_(prof, rules=dataclasses.replace(prof.rules, flag_sharing="forbidden")))
    closed.add_confirm("1", flag=FLAG_A, where="f")
    closed.add_confirm("2", flag=FLAG_A, where="f")
    truth = [humanops.TruthRow("1", None, FLAG_A, 2), humanops.TruthRow("2", None, FLAG_B, 3)]
    rep = closed.reconcile(truth, record=False)
    assert [i.challenge_id for i in rep.agree] == ["1"]
    assert [i.challenge_id for i, _ in rep.flag_mismatch] == ["2"]
    assert recs(tmp_path, "human.reconcile") == []
    rep2 = closed.reconcile(truth[:1] + [humanops.TruthRow("2", None, None, 3)])
    assert rep2.clean and "ALL AGREE" in humanops.render_reconciliation(rep2)


def test_reconcile_exact_answer_row_does_not_match_another_answer(tmp_path):
    ops = ops_for(tmp_path)
    submit_rec(tmp_path, "5#q1", "correct")
    submit_rec(tmp_path, "5#q2", "correct")
    rep = ops.reconcile([humanops.TruthRow("5#q1", None, None, 2)], record=False)
    assert [i.challenge_id for i in rep.agree] == ["5#q1"]
    assert [i.challenge_id for i in rep.missing] == ["5#q2"]


# ------------------------------------------------------------------------------- checklist

def test_checklist_lists_standing_event_and_open_items(tmp_path):
    clock = Clock(dt.datetime(2026, 10, 4, 20, 0).timestamp())
    prof = huntress()
    prof = with_(prof, human=dataclasses.replace(prof.human, checklist=("Charge the backup phone",)))
    ops = ops_for(tmp_path, prof, clock)
    card = ops.add_card("discord", ask="read #comms", need="the word", challenge_id="9091")
    pin = ops.add_pin("77", ask="bench", candidates=["14.59,120.98 gate", "14.6,121.0"])
    ops.add_confirm("12", flag=FLAG_A, points=50)
    cl = ops.checklist()
    assert cl.for_date == dt.date(2026, 10, 5) and cl.when == "day 5 of 31"
    assert [i.ref for i in cl.section("standing")] == [r for r, _ in humanops.STANDING]
    event_text = " | ".join(i.text for i in cl.section("event"))
    assert "Charge the backup phone" in event_text
    assert "CourseStack" in event_text and "1 item(s) pending" in event_text
    assert "*.huntress.example" in event_text
    assert "Manual mode" not in event_text and "your yes" not in event_text and "unknown" not in event_text
    assert [i.ref for i in cl.section("card")] == [card.id]
    assert [i.ref for i in cl.section("pin")] == [pin.id]
    assert "candidates: 14.59,120.98 (gate), 14.6,121.0" in cl.section("pin")[0].text
    assert [i.ref for i in cl.section("confirm")] == ["12"] and FLAG_A in cl.section("confirm")[0].text
    md = humanops.render_checklist(cl)
    assert md.startswith("# Evening checklist: huntress, for 2026-10-05 (day 5 of 31)")
    assert "## OSINT final-pin queue" in md and "## Confirm list" in md and f"[{card.id}]" in md
    assert md.count("- [ ] ") == len(cl.items)
    # answered/dropped cards and confirmed items leave the checklist
    ops.answer(card.id, "pumpkin")
    ops.drop(pin.id, "solved otherwise")
    ops.mark_confirmed("12")
    cl2 = ops.checklist(dt.date(2026, 9, 29))
    assert cl2.section("card") == cl2.section("pin") == cl2.section("confirm") == []
    assert cl2.when == "before the event: it starts 2026-10-01 (2 day(s) later)"
    assert "0 item(s) pending" in " ".join(i.text for i in cl2.section("event"))
    assert "- none open" in humanops.render_checklist(cl2)
    assert ops.checklist(dt.date(2026, 11, 2)).when == "after the event: it ended 2026-10-31"


def test_checklist_rules_items_follow_the_profile(tmp_path):
    prof = huntress()
    confirm = with_(prof, rules=dataclasses.replace(prof.rules, submit_mode="confirm", live_service_scope=()),
                    flag=dataclasses.replace(prof.flag, prefixes=()), human=event.Human())
    text = " | ".join(i.text for i in ops_for(tmp_path, confirm).checklist(dt.date(2026, 10, 2)).items)
    assert "your yes" in text and "Flag format unknown" in text
    assert "Manual mode" not in text and "Live targets" not in text and "Confirm points" not in text
    manual = with_(prof, rules=dataclasses.replace(prof.rules, submit_mode="manual"))
    text = " | ".join(i.text for i in ops_for(tmp_path / "m", manual).checklist(dt.date(2026, 10, 2)).items)
    assert "Manual mode" in text and "your yes" not in text


# ------------------------------------------------------------------------------- CLI

def call(monkeypatch, tmp_path, *argv, slug="huntress"):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setenv("CTF_EVENT", slug)
    p = argparse.ArgumentParser()
    cli_human.add_arguments(p)
    return cli_human.run(p.parse_args(list(argv)))


def test_cli_cards_pins_answer_and_checklist(monkeypatch, tmp_path, capsys):
    assert call(monkeypatch, tmp_path, "add-card", "discord", "--challenge", "9091", "--ask", "read #comms",
                "--need", "the word") == 0
    cid = capsys.readouterr().out.split()[1]
    assert call(monkeypatch, tmp_path, "add-pin", "77", "--ask", "bench", "--candidate",
                "14.59,120.98 gate") == 0
    pid = capsys.readouterr().out.split()[1]
    assert call(monkeypatch, tmp_path, "pins") == 0
    out = capsys.readouterr().out
    assert pid in out and cid not in out and "candidate 14.59,120.98 (2 decimals)  gate" in out
    assert call(monkeypatch, tmp_path, "cards", "--json") == 0
    rows = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert [r["id"] for r in rows] == [cid, pid] and rows[1]["candidates"][0]["text"] == "14.59,120.98"
    assert call(monkeypatch, tmp_path, "answer", pid, "14.59,120.98") == 2
    assert "at least 4 decimals" in capsys.readouterr().err
    assert call(monkeypatch, tmp_path, "answer", pid, "14.5900,120.9800", "--by", "max") == 0
    assert call(monkeypatch, tmp_path, "drop", cid, "--reason", "teammate read it") == 0
    capsys.readouterr()
    assert call(monkeypatch, tmp_path, "cards") == 0
    assert capsys.readouterr().out.strip() == "no open task cards"
    out_file = tmp_path / "checklist.md"
    assert call(monkeypatch, tmp_path, "checklist", "--for", "2026-10-05", "--out", str(out_file)) == 0
    printed = capsys.readouterr().out
    assert printed.startswith("# Evening checklist: huntress, for 2026-10-05") and out_file.read_text() == printed
    assert call(monkeypatch, tmp_path, "checklist", "--for", "tomorrow") == 2
    assert "not a date" in capsys.readouterr().err


def test_cli_confirm_and_reconcile_exit_codes(monkeypatch, tmp_path, capsys):
    assert call(monkeypatch, tmp_path, "confirm", "12", "--flag", FLAG_A, "--points", "50") == 0
    assert call(monkeypatch, tmp_path, "confirm-list") == 0
    out = capsys.readouterr().out
    assert "CourseStack confirm list: 1 pending" in out and f"[ ] 12: {FLAG_A}, 50 pts [agent]" in out
    good = write_truth(tmp_path, f"challenge,points,flag\n12,50,{FLAG_A}\n")
    assert call(monkeypatch, tmp_path, "reconcile", str(good)) == 0
    assert "ALL AGREE" in capsys.readouterr().out
    bad = write_truth(tmp_path, "challenge,points\n12,40\n", "bad.csv")
    assert call(monkeypatch, tmp_path, "reconcile", str(bad), "--json") == 1
    rep = json.loads(capsys.readouterr().out)
    assert rep["clean"] is False and rep["counts"]["points_mismatch"] == 1
    assert call(monkeypatch, tmp_path, "confirmed", "12") == 0
    assert call(monkeypatch, tmp_path, "confirm-list", "--all") == 0
    assert "[x] 12" in capsys.readouterr().out
    assert call(monkeypatch, tmp_path, "confirm-list", slug="csctf") == 2
    assert "no off-platform confirm system" in capsys.readouterr().err


def test_cli_live_reads_team_solves_through_get_adapter(monkeypatch, tmp_path, capsys):
    import ctf.platform as platform

    class FakeGate:
        def team_solves(self):
            return [platform.base.TeamSolve(challenge_id="31")]

    seen = []
    monkeypatch.setattr(platform, "get_adapter", lambda prof: seen.append(prof.slug) or FakeGate())
    assert call(monkeypatch, tmp_path, "confirm-list", "--live") == 0
    assert seen == ["huntress"] and "31: value unknown" in capsys.readouterr().out

    def boom(prof):
        raise platform.PlatformError("list: connection refused")
    monkeypatch.setattr(platform, "get_adapter", boom)
    assert call(monkeypatch, tmp_path, "confirm-list", "--live") == 2
    assert "platform: list: connection refused" in capsys.readouterr().err


def test_ctf_human_is_discovered_by_the_cli(tmp_path):
    e = dict(os.environ, CTF_WORKDIR=str(tmp_path), CTF_EVENT="huntress")
    r = subprocess.run([sys.executable, "-m", "ctf", "human", "add-card", "lookup", "--ask", "Censys: cert",
                        "--need", "the host"], cwd=paths.repo_root(), env=e, capture_output=True,
                       text=True, timeout=60, stdin=subprocess.DEVNULL)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("card h") and recs(tmp_path, "human.card")[0]["kind"] == "lookup"
