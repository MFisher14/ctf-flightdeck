"""B-203: the stuck-id protocol (ctf/stuck.py, ctf/cli/stuck.py).

Offline. Every test drives the real module against a tmp workdir and a synthetic ledger / brief; the
routing test uses the real csctf profile. No network, no model, no challenge files: a "delivered file"
is bytes built inside the test. Nothing here sends anything or starts a session.
"""
from __future__ import annotations

import argparse
import json
import time

import pytest

from ctf import event, ledger, paths, watch
from ctf import stuck
from ctf.cli import stuck as cli


@pytest.fixture
def wd(tmp_path):
    return tmp_path / "work"


@pytest.fixture
def csctf():
    return event.load("csctf")


# --------------------------------------------------------------------- synthetic ledger / brief helpers

def reject(wd, cid, *, n=1, status="incorrect", slug=None):
    """Append n judged-wrong platform.submit records for an id (as ctf.platform.rules writes them)."""
    for _ in range(n):
        f = {"challenge_id": cid, "status": status, "judged": status != "rate_limited"}
        if slug is not None:
            f["event_slug"] = slug
        ledger.append("platform.submit", workdir=wd, **f)


def spawn(wd, cid, spawn_id, *, role="owner"):
    ledger.append("spawn", workdir=wd, challenge_id=cid, spawn_id=spawn_id, role=role)


def write_brief(wd, cid, version, ts, *, fields=None, prev_sha=None):
    fields = fields or {"name": cid, "category": "x", "description": "", "connection_info": "",
                        "files": [], "tags": []}
    rec = {"challenge_id": cid, "version": version, "ts": ts, "fields": fields,
           "sha256": watch.fields_sha256(fields), "prev_sha256": prev_sha}
    d = watch.brief_dir(wd, cid)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"v{version}.json").write_text(json.dumps(rec), encoding="utf-8")
    return rec["sha256"]


def watch_event(wd, seq, event, **fields):
    p = watch.events_path(wd)
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {"seq": seq, "ts": fields.pop("ts", time.time()), "event": event, **fields}
    with open(p, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


# --------------------------------------------------------------------- vocabulary

def test_vocabulary_strips_set_prefix_drops_generic_and_short_tokens():
    v = stuck.vocabulary("set2.d12_hcfg_storage")
    assert v == {"hcfg", "storage"}          # setN. gone, d12 too short


def test_vocabulary_drops_generic_field_words_only_the_distinctive_anchor_survives():
    # "sha256" and "value" are generic; "machine" is the one anchor a file could carry.
    assert stuck.vocabulary("pe_machine_sha256_value") == {"machine"}


def test_vocabulary_from_a_question_dict_uses_its_id():
    assert stuck.vocabulary({"id": "x#hcfg_storage"}) == {"hcfg", "storage"}


def test_material_tokens_reads_brief_filenames_and_bytes_as_strings():
    # the filename "hcfg_table.bin" tokenizes the same way an id does (split on non-alnum, >= 4 chars),
    # so a file literally named for the asked field anchors it; "bin" (3) is dropped.
    mt = stuck.material_tokens("the config section", {"hcfg_table.bin": b"\x00\x01storage blob\xff"})
    assert {"config", "section", "hcfg", "table", "storage", "blob"} <= mt
    assert "bin" not in mt


def test_a_question_without_an_id_is_a_loud_error():
    with pytest.raises(stuck.StuckError):
        stuck.vocabulary({"question": "what is the value"})


# --------------------------------------------------------------------- reject_count

def test_reject_count_counts_only_judged_wrong_sends_for_the_exact_id(wd):
    reject(wd, "12#k", n=3)
    reject(wd, "12#k", n=1, status="correct")       # a correct send is not a rejection
    reject(wd, "12#k", n=1, status="rate_limited")  # unjudged: not a rejection
    reject(wd, "12#other", n=5)                      # a different id
    assert stuck.reject_count(wd, "12#k") == 3


def test_reject_count_filters_by_event_slug_when_given(wd):
    reject(wd, "9", n=2, slug="csctf")
    reject(wd, "9", n=1, slug="pink")
    assert stuck.reject_count(wd, "9", event_slug="csctf") == 2
    assert stuck.reject_count(wd, "9") == 3


# --------------------------------------------------------------------- assess

def test_a_derivable_id_is_ok_even_past_the_rejection_threshold(wd):
    # the anchor "storage" is right there in the file, so the spelling IS derivable: not stuck.
    a = stuck.assess("d12_hcfg_storage", question="d12_hcfg_storage",
                     files={"dump.bin": b"hcfg_storage = 0x40"}, rejections=12)
    assert a.status == stuck.OK and a.derivable and "storage" in a.vocabulary_found
    assert not a.is_stuck


def test_no_vocabulary_plus_the_threshold_is_stuck(wd):
    a = stuck.assess("d12_hcfg_storage", question="d12_hcfg_storage",
                     brief_text="solve the binary", files={"x.bin": b"nothing to anchor on"},
                     rejections=8)
    assert a.status == stuck.STUCK and a.is_stuck and not a.derivable


def test_below_the_threshold_with_no_vocabulary_is_still_ok(wd):
    a = stuck.assess("zz_underivable", question="zz_underivable", files={"x.bin": b"blank"},
                     rejections=stuck.DEFAULT.stuck_after - 1)
    assert a.status == stuck.OK and not a.is_stuck


def test_a_derivable_id_is_probe_capped_at_the_hard_ceiling(wd):
    # derivable (anchor present) but it has absorbed the hard ceiling of sends: stop anyway.
    a = stuck.assess("x_storage", question="x_storage", files={"f.bin": b"storage"},
                     rejections=stuck.DEFAULT.probe_cap)
    assert a.status == stuck.PROBE_CAPPED and a.is_stuck


def test_untried_format_candidates_keep_an_id_out_of_stuck(wd):
    # a value WAS read (1024); the plain spelling was rejected but re-spellings remain -> not stuck.
    a = stuck.assess("x#page_size", question="x#page_size", rejections=10,
                     read_value=1024, answer_format={"kind": "integer"}, rejected_values=["1024"])
    assert a.status == stuck.TRY_FORMAT_CANDIDATES and not a.is_stuck
    assert a.untried_format_candidates


def test_untried_format_candidates_still_yield_to_the_hard_probe_cap(wd):
    # the hard ceiling is hard: at probe_cap, PROBE_CAPPED wins even when cheap re-spellings remain
    # untried. Proves the `rejections < probe_cap` guard on the format-candidate branch (stuck.py:301);
    # dropping it would wrongly report TRY_FORMAT_CANDIDATES past the ceiling ("derivable or not").
    # The id is derivable (the anchor is in the file) so it cannot fall into STUCK: this isolates the
    # format-candidate branch against the probe cap, not against the no-vocabulary rule.
    a = stuck.assess("page_size", question="page_size", files={"f.bin": b"page_size table"},
                     rejections=stuck.DEFAULT.probe_cap,
                     read_value=1024, answer_format={"kind": "integer"}, rejected_values=["1024"])
    assert a.derivable and a.untried_format_candidates      # untried re-spellings DO exist here
    assert a.status == stuck.PROBE_CAPPED and a.is_stuck    # ...and the ceiling overrides them anyway


def test_format_candidate_ranking_can_be_turned_off(wd):
    # same value, ranking off: with no vocabulary and past the threshold it is stuck.
    a = stuck.assess("page_size_thing", question="page_size_thing", rejections=10,
                     read_value=1024, answer_format={"kind": "integer"}, rejected_values=["1024"],
                     format_candidates_on=False)
    assert a.status == stuck.STUCK


def test_assess_reads_the_rejection_count_from_the_ledger_when_not_given(wd):
    reject(wd, "k_underivable", n=stuck.DEFAULT.stuck_after)
    a = stuck.assess("k_underivable", question="k_underivable", files={"x": b"blank"}, workdir=wd)
    assert a.rejections == stuck.DEFAULT.stuck_after and a.status == stuck.STUCK


# --------------------------------------------------------------------- format_candidates

def test_format_candidates_drops_the_already_rejected_rendering():
    cands = stuck.format_candidates(1024, {"kind": "integer"}, rejected=["1024"])
    vals = [v for _, v in cands]
    assert "1024" not in vals and "0x400" in vals


# --------------------------------------------------------------------- thresholds

def test_probe_cap_below_stuck_after_is_rejected():
    with pytest.raises(stuck.StuckError):
        stuck.Thresholds(stuck_after=10, probe_cap=5)


def test_a_zero_threshold_is_rejected():
    with pytest.raises(stuck.StuckError):
        stuck.Thresholds(agent_cap=0)


# --------------------------------------------------------------------- the stuck record

def _stuck_assessment(cid="d12_x", rejections=8):
    return stuck.assess(cid, question=cid, files={"f": b"blank"}, rejections=rejections)


def test_mark_stuck_writes_one_record_and_is_idempotent(wd):
    a = _stuck_assessment()
    rec = stuck.mark_stuck(a, workdir=wd)
    assert rec is not None and rec["status"] == stuck.STUCK
    assert stuck.mark_stuck(a, workdir=wd) is None       # already marked at this status: no new record
    recs = [r for r in ledger.read(wd) if r.get("event") == "stuck"]
    assert len(recs) == 1


def test_mark_stuck_refuses_a_non_stuck_assessment(wd):
    ok = stuck.assess("d12_storage", question="d12_storage", files={"f": b"storage"}, rejections=1)
    with pytest.raises(stuck.StuckError):
        stuck.mark_stuck(ok, workdir=wd)


def test_marked_stuck_is_cancelled_by_a_later_clear(wd):
    stuck.mark_stuck(_stuck_assessment(), workdir=wd)
    assert stuck.marked_stuck(wd, "d12_x") is not None
    stuck.clear_stuck("d12_x", workdir=wd, reason="rewritten")
    assert stuck.marked_stuck(wd, "d12_x") is None
    assert stuck.stuck_ids(wd) == []


def test_clear_stuck_on_an_unstuck_id_writes_nothing(wd):
    assert stuck.clear_stuck("never", workdir=wd) is None
    assert list(ledger.read(wd)) == []


def test_mark_stuck_routes_to_the_player_with_a_profile(wd, csctf):
    from ctf import humanops
    a = _stuck_assessment()
    rec = stuck.mark_stuck(a, workdir=wd, profile=csctf)
    assert rec["routed"] is True and rec.get("card_id")
    cards = humanops.HumanOps(csctf, workdir=wd).cards()
    assert any(c.id == rec["card_id"] and c.challenge_id == "d12_x" for c in cards)


def test_mark_stuck_without_a_profile_records_but_does_not_route(wd):
    rec = stuck.mark_stuck(_stuck_assessment(), workdir=wd, profile=None)
    assert rec["routed"] is False
    assert not any(r.get("event") == "human.card" for r in ledger.read(wd))


# --------------------------------------------------------------------- the caps

def test_probe_allowed_refuses_a_stuck_id_and_allows_a_derivable_one(wd):
    reject(wd, "d12_x", n=8)
    d = stuck.probe_allowed("d12_x", question="d12_x", files={"f": b"blank"}, workdir=wd)
    assert not d.allowed and "route to the player" in d.reason
    # a derivable id with the same rejection count is allowed: the brake is for underivable ids.
    reject(wd, "d12_storage", n=8)
    ok = stuck.probe_allowed("d12_storage", question="d12_storage", files={"f": b"storage here"},
                             workdir=wd)
    assert ok.allowed


def test_agents_on_consumes_the_spawn_gate_count(wd):
    spawn(wd, "77", "s1")
    spawn(wd, "77", "s2", role="helper")
    spawn(wd, "88", "s3")
    assert stuck.agents_on(wd, "77") == 2
    assert stuck.agents_on(wd, "77#part") == 2        # keyed by challenge, '#part' shares it
    assert stuck.agents_on(wd, "99") == 0


def test_agent_allowed_refuses_at_the_agent_cap_even_before_stuck(wd):
    th = stuck.Thresholds(agent_cap=2)
    spawn(wd, "55", "s1")
    spawn(wd, "55", "s2")
    d = stuck.agent_allowed("55", question="55_derivable_storage", files={"f": b"storage"},
                            workdir=wd, thresholds=th)
    assert not d.allowed and d.agents == 2 and "agent_cap" in d.reason


def test_agent_allowed_refuses_a_stuck_id_regardless_of_count(wd):
    reject(wd, "55", n=8)
    d = stuck.agent_allowed("55", question="55_underivable", files={"f": b"blank"}, workdir=wd)
    assert not d.allowed and d.assessment.is_stuck


def test_agent_allowed_allows_under_the_cap(wd):
    th = stuck.Thresholds(agent_cap=3)
    spawn(wd, "55", "s1")
    d = stuck.agent_allowed("55", question="55_storage", files={"f": b"storage"}, workdir=wd,
                            thresholds=th)
    assert d.allowed and d.agents == 1


# --------------------------------------------------------------------- the live re-read

def test_last_read_ts_is_the_newest_stored_brief(wd):
    s1 = write_brief(wd, "42", 1, ts=1000.0)
    write_brief(wd, "42", 2, ts=2000.0, prev_sha=s1)
    assert stuck.last_read_ts(wd, "42") == 2000.0
    assert stuck.last_read_ts(wd, "nobrief") is None


def test_reread_due_lists_stuck_ids_overdue_for_a_reread(wd):
    stuck.mark_stuck(_stuck_assessment("overdue"), workdir=wd)
    stuck.mark_stuck(_stuck_assessment("fresh"), workdir=wd)
    stuck.mark_stuck(_stuck_assessment("neverread"), workdir=wd)
    write_brief(wd, "overdue", 1, ts=0.0)         # read long ago
    write_brief(wd, "fresh", 1, ts=10_000.0)      # read just now
    now = 10_000.0 + stuck.DEFAULT.reread_interval_s - 1   # "fresh" is just under the interval
    due_ids = {cid for cid, _, _ in stuck.reread_due(wd, clock=lambda: now)}
    assert "overdue" in due_ids and "neverread" in due_ids and "fresh" not in due_ids


def test_a_brief_change_after_the_stuck_record_reconsiders_the_id(wd):
    rec = stuck.mark_stuck(_stuck_assessment("rw"), workdir=wd)
    # the organizer rewrites the question AFTER the id went stuck.
    watch_event(wd, 1, "brief_changed", challenge_id="rw", ts=rec["ts"] + 5)
    assert stuck.brief_changed_since_stuck(wd, "rw") is True
    cleared = stuck.reconsider(wd)
    assert cleared == ["rw"] and stuck.stuck_ids(wd) == []


def test_a_brief_change_before_the_stuck_record_does_not_reconsider(wd):
    watch_event(wd, 1, "brief_changed", challenge_id="rw2", ts=1.0)
    stuck.mark_stuck(_stuck_assessment("rw2"), workdir=wd)   # went stuck AFTER the change
    assert stuck.brief_changed_since_stuck(wd, "rw2") is False
    assert stuck.reconsider(wd) == []


# --------------------------------------------------------------------- CLI

def _args(**kw):
    ns = argparse.Namespace(event=None, workdir=None, event_profile=None,
                            stuck_after=None, probe_cap=None, agent_cap=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_cli_check_exits_1_on_a_stuck_id(wd, capsys):
    reject(wd, "d12_x", n=8)
    rc = cli.run(_args(action="check", workdir=str(wd), id="d12_x", question="d12_x",
                       brief=None, brief_file=None, file=[], read_value=None, rejections=None,
                       json=False))
    assert rc == 1 and "REFUSE" in capsys.readouterr().out


def test_cli_check_exits_0_on_a_derivable_id(wd, capsys, tmp_path):
    f = tmp_path / "d.bin"
    f.write_bytes(b"hcfg_storage = 1")
    rc = cli.run(_args(action="check", workdir=str(wd), id="d12_hcfg_storage",
                       question="d12_hcfg_storage", brief=None, brief_file=None, file=[str(f)],
                       read_value=None, rejections=8, json=False))
    assert rc == 0 and "PROBE" in capsys.readouterr().out


def test_cli_mark_then_list_and_clear(wd, capsys):
    rc = cli.run(_args(action="mark", workdir=str(wd), id="d12_x", question="d12_x",
                       brief=None, brief_file=None, file=[], read_value=None, rejections=8,
                       json=False, no_route=True, agent="tester"))
    assert rc == 0
    cli.run(_args(action="list", workdir=str(wd), json=True))
    assert "d12_x" in capsys.readouterr().out
    rc = cli.run(_args(action="clear", workdir=str(wd), id="d12_x", reason="done", by="op"))
    assert rc == 0 and stuck.stuck_ids(wd) == []


def test_cli_mark_exits_1_and_writes_nothing_when_not_stuck(wd, tmp_path):
    f = tmp_path / "d.bin"
    f.write_bytes(b"storage is here")
    rc = cli.run(_args(action="mark", workdir=str(wd), id="d12_storage", question="d12_storage",
                       brief=None, brief_file=None, file=[str(f)], read_value=None, rejections=1,
                       json=False, no_route=True, agent=None))
    assert rc == 1 and stuck.stuck_ids(wd) == []


def test_cli_unknown_event_exits_2(wd, capsys):
    rc = cli.run(_args(action="list", event="no-such-event", json=False))
    assert rc == 2 and "ctf stuck" in capsys.readouterr().err
