"""B-172: the solver contract (ctf/solver_contract.py, ctf/cli/contract.py).

Offline. Ledger records, dispatch claims and challenge folders are written to a temp workdir; the
contract reads them. No model, no platform call, no network.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from ctf import cli, dispatch, event, eventrules, ledger, paths
from ctf import solver_contract as sc
from ctf.result import Evidence, SolverResult


@pytest.fixture
def prof():
    return event.load("csctf")          # wrong_answer_stop 3, approved_extras true, floor $25


def write_ledger(workdir, event_type, *, ts=None, **fields):
    """Append one raw ledger line (a chosen ts; ledger.append forbids setting it)."""
    rec = {"ts": float(ts if ts is not None else 1000.0), "event": event_type, **fields}
    p = ledger.path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def submit(workdir, prof, cid, status, **extra):
    return write_ledger(workdir, "platform.submit", challenge_id=cid, status=status,
                        event_slug=prof.slug, judged=True, **extra)


def codes(vs):
    return sorted(v.code for v in vs)


# ----------------------------------------------------------------------------------- the rules text

def test_rules_md_carries_every_rule_and_status_word():
    md = sc.rules_md()
    for r in sc.RULES:
        assert f"(`{r.id}`)" in md
    for s in sc.STATUSES:
        assert f"`{s}`" in md
    assert md.startswith("## Solver contract")
    assert sc.rules_md(heading_level=3).startswith("### Solver contract")
    assert {"simplest-first", "evidence-before-claims", "flag-in-artifact", "solves-before-broken",
            "oracle-before-submit", "persist", "next-action", "status-vocabulary", "fresh-eyes"} == set(sc.RULE_IDS)


def test_every_event_agent_file_carries_the_contract(prof):
    files = eventrules.render(prof)
    body = sc.rules_md(heading_level=2).rstrip("\n")
    for name in eventrules.AGENT_FILES:
        assert body in files[name], name
    # the checked-in event files are current with this contract (regenerated)
    for slug in ("csctf", "huntress", "pink", "spooky"):
        p = event.load(slug)
        assert eventrules.check(p, paths.repo_root() / "events" / slug) == []


def test_a_contract_change_marks_the_event_files_stale(prof, tmp_path, monkeypatch):
    eventrules.write(prof, tmp_path)
    assert eventrules.check(prof, tmp_path) == []
    changed = sc.RULES[:-1] + (dataclasses.replace(sc.RULES[-1], text=sc.RULES[-1].text + " Changed."),)
    monkeypatch.setattr(sc, "RULES", changed)
    problems = eventrules.check(prof, tmp_path)
    assert problems and all("stale" in p for p in problems)


def test_ladder_for_canonicalises_the_lane_and_falls_back_loudly_to_the_generic_ladder():
    assert sc.ladder_for("Cryptography") == sc.LADDERS["crypto"]
    assert sc.ladder_for("rev") == sc.LADDERS["reverse"]
    assert sc.ladder_for("Web") == sc.LADDERS["web"]
    assert sc.ladder_for("hardware") == sc.DEFAULT_LADDER
    assert sc.ladder_for("") == sc.DEFAULT_LADDER
    for lane, rungs in sc.LADDERS.items():
        assert rungs[-1].startswith("only then"), lane      # the complex rung is last


def test_the_handout_carries_the_contract_and_the_lanes_ladder(prof, tmp_path):
    h = dispatch.handout_md(dispatch.Detected("77", "Login", "Web", 100), prof, workdir=tmp_path)
    assert "## solver contract" in h
    assert sc.LADDERS["web"][0] in h and sc.LADDERS["crypto"][0] not in h
    assert sc.rules_md(heading_level=3).rstrip("\n") in h
    assert "python -m ctf contract may-stop 77" in h and "python -m ctf contract fresh-eyes 77" in h
    assert "FLAG_FOUND, never SOLVED" in h
    c = dispatch.handout_md(dispatch.Detected("78", "RSA", "Crypto", 100), prof, workdir=tmp_path)
    assert sc.LADDERS["crypto"][0] in c and sc.LADDERS["web"][0] not in c


def test_handout_section_shell_quotes_a_hostile_id():
    s = sc.handout_section("web", "1; rm -rf x")
    assert "may-stop '1; rm -rf x'" in s


def test_agent_status_for_maps_engine_results_never_to_solved():
    ev = (Evidence("decode", "base64 of a.txt"),)
    assert sc.agent_status_for(SolverResult("solved", flags=["F{x}"], evidence=ev)) == "FLAG_FOUND"
    assert sc.agent_status_for(SolverResult("candidate", flags=["F{x}"])) == "WORKING"
    assert sc.agent_status_for(SolverResult("none")) == "WORKING"
    assert sc.agent_status_for(SolverResult("unsure")) == "WORKING"
    assert sc.agent_status_for(SolverResult("blocked", notes="no tshark")) == "BLOCKED"
    with pytest.raises(sc.ContractError):
        sc.agent_status_for({"status": "solved"})


# ----------------------------------------------------------------------------------- acceptance

def test_acceptance_reads_only_real_acceptances(prof, tmp_path):
    assert sc.acceptance("5", workdir=tmp_path) is None
    submit(tmp_path, prof, "5", "incorrect")
    write_ledger(tmp_path, "candidate", challenge_id="5")
    write_ledger(tmp_path, "stop", challenge_id="5", reason="no_progress")
    write_ledger(tmp_path, "solver_status", challenge_id="5", status="SOLVED")   # a claim is not proof
    assert sc.acceptance("5", workdir=tmp_path) is None
    submit(tmp_path, prof, "5", "correct")
    assert "correct" in sc.acceptance("5", workdir=tmp_path)
    assert sc.acceptance("6", workdir=tmp_path) is None


@pytest.mark.parametrize("rec", [
    {"event": "accepted"},
    {"event": "platform.submit", "status": "already_solved"},
    {"event": "stop", "reason": "team_solve"},
])
def test_acceptance_sources(tmp_path, rec):
    write_ledger(tmp_path, rec.pop("event"), challenge_id="8", **rec)
    assert sc.acceptance("8", workdir=tmp_path)


def test_a_partial_batch_or_open_answers_is_not_acceptance(prof, tmp_path):
    submit(tmp_path, prof, "9", "correct", partial=True)
    submit(tmp_path, prof, "9", "correct", remaining=2)
    assert sc.acceptance("9", workdir=tmp_path) is None
    submit(tmp_path, prof, "9#a", "correct", remaining=1)
    assert sc.acceptance("9", workdir=tmp_path) is None
    assert sc.acceptance("9#a", workdir=tmp_path)            # the part itself was accepted
    assert sc.acceptance("9#b", workdir=tmp_path) is None    # another part was not
    submit(tmp_path, prof, "9#b", "correct", remaining=0)
    assert sc.acceptance("9", workdir=tmp_path)              # the platform says none remain


def test_a_team_solve_stop_on_a_part_does_not_accept_the_bare_id(tmp_path):
    write_ledger(tmp_path, "stop", challenge_id="11#a", reason="team_solve")
    assert sc.acceptance("11", workdir=tmp_path) is None
    write_ledger(tmp_path, "stop", challenge_id="11", reason="team_solve")
    assert sc.acceptance("11", workdir=tmp_path)


def test_an_accepted_mark_on_a_part_accepts_that_part_only(tmp_path):
    write_ledger(tmp_path, "accepted", challenge_id="10#a")
    assert sc.acceptance("10#a", workdir=tmp_path)
    assert sc.acceptance("10", workdir=tmp_path) is None
    assert sc.acceptance("10#b", workdir=tmp_path) is None
    write_ledger(tmp_path, "accepted", challenge_id="10")         # the whole challenge
    assert sc.acceptance("10", workdir=tmp_path) and sc.acceptance("10#b", workdir=tmp_path)


# ----------------------------------------------------------------------------------- report checks

def test_a_report_needs_a_contract_status_word(prof, tmp_path):
    assert codes(sc.check_report("working on it", workdir=tmp_path)) == ["no-status"]
    assert codes(sc.check_report("STATUS: DONE\nNEXT: x", workdir=tmp_path)) == ["unknown-status"]
    assert codes(sc.check_report("Status: Flag found", workdir=tmp_path)) == ["unknown-status"]


def test_the_first_status_line_wins(tmp_path):
    rep = "STATUS: WORKING\nNEXT: decompile check()\nquoting the old note:\nSTATUS: SOLVED\nNEXT: done"
    r = sc.parse_report(rep)
    assert r.status == "WORKING" and r.next == "decompile check()"
    assert sc.check_report(rep, workdir=tmp_path, challenge_id="13") == []


def test_working_needs_a_next_action(prof, tmp_path):
    assert codes(sc.check_report("STATUS: WORKING", workdir=tmp_path)) == ["no-next"]
    assert codes(sc.check_report("STATUS: BLOCKED", workdir=tmp_path)) == ["no-next"]
    assert sc.check_report("**STATUS:** working\n- NEXT: decompile check()", workdir=tmp_path) == []


def test_solved_before_acceptance_is_refused(prof, tmp_path):
    rep = "STATUS: SOLVED\nCHALLENGE: 12"
    assert codes(sc.check_report(rep, workdir=tmp_path)) == ["solved-before-acceptance"]
    assert codes(sc.check_report("STATUS: SOLVED", workdir=tmp_path)) == ["solved-unverifiable"]
    submit(tmp_path, prof, "12", "correct")
    assert sc.check_report(rep, workdir=tmp_path) == []
    assert sc.check_report("STATUS: SOLVED", workdir=tmp_path, challenge_id="12") == []


def test_flag_found_needs_evidence_and_an_oracle_line(prof, tmp_path):
    base = "STATUS: FLAG_FOUND\nNEXT: submit it\n"
    assert codes(sc.check_report(base, workdir=tmp_path)) == ["flag-no-evidence", "flag-no-oracle"]
    assert codes(sc.check_report(base + "EVIDENCE: files/a.bin @0x40\nORACLE: pass", workdir=tmp_path)) \
        == ["flag-no-oracle"]                                # "pass" must say how
    assert codes(sc.check_report(base + "EVIDENCE: files/a.bin @0x40\nORACLE: maybe later",
                                 workdir=tmp_path)) == ["flag-no-oracle"]
    ok1 = base + "EVIDENCE: files/a.bin @0x40\nORACLE: pass the binary's check() returns 1"
    ok2 = base + "EVIDENCE: decoded files/msg.txt\nORACLE: none the artifact carries no check"
    assert sc.check_report(ok1, workdir=tmp_path) == []
    assert sc.check_report(ok2, workdir=tmp_path) == []
    assert codes(sc.check_report("STATUS: FLAG_FOUND\nEVIDENCE: x\nORACLE: none no check",
                                 workdir=tmp_path)) == ["no-next"]


def test_calling_it_broken_needs_a_solve_count(prof, tmp_path):
    rep = "STATUS: WORKING\nNEXT: ask the player\nThe challenge is broken: the server never answers."
    assert codes(sc.check_report(rep, workdir=tmp_path, challenge_id="3")) == ["broken-without-solves"]
    assert sc.check_report(rep + "\nSOLVES: 0 (board)", workdir=tmp_path, challenge_id="3") == []
    v = sc.check_report(rep + "\nSOLVES: 4 (board)", workdir=tmp_path, challenge_id="3")
    assert codes(v) == ["broken-but-solved"] and "4" in v[0].message
    for word in ("impossible", "unsolvable", "misconfigured"):
        assert codes(sc.check_report(f"STATUS: WORKING\nNEXT: x\nthis looks {word}",
                                     workdir=tmp_path)) == ["broken-without-solves"]


def test_a_single_solve_cited_or_recorded_is_enough_to_refute_broken(prof, tmp_path):
    rep = "STATUS: WORKING\nNEXT: x\nThe challenge is broken."
    v = sc.check_report(rep + "\nSOLVES: 1 (board)", workdir=tmp_path, challenge_id="2")
    assert codes(v) == ["broken-but-solved"] and "(1)" in v[0].message
    sc.record_solve_count("2", 1, source="board", workdir=tmp_path)
    assert codes(sc.check_report(rep + "\nSOLVES: 0 (stale)", workdir=tmp_path, challenge_id="2")) \
        == ["broken-but-solved"]


@pytest.mark.parametrize("prose", [
    "The signature uses MD5 which is broken; next I forge one.",
    "Its padding check is broken, so a padding oracle may apply.",
    "A broken RNG would explain the repeats.",
    "The service is not broken; my parser is.",
    "It is not really broken.",
])
def test_broken_about_a_primitive_or_negated_is_not_a_broken_claim(tmp_path, prose):
    assert sc.check_report(f"STATUS: WORKING\nNEXT: x\n{prose}", workdir=tmp_path) == []


@pytest.mark.parametrize("prose", [
    "The server is clearly broken.", "this challenge seems misconfigured",
    "It's impossible.", "The instance must be broken", "this cannot be solved",
])
def test_broken_about_the_challenge_is_a_claim(tmp_path, prose):
    assert codes(sc.check_report(f"STATUS: WORKING\nNEXT: x\n{prose}", workdir=tmp_path)) \
        == ["broken-without-solves"]


def test_a_recorded_solve_or_our_own_solve_contradicts_a_zero_citation(prof, tmp_path):
    rep = "STATUS: WORKING\nNEXT: x\nIt is broken.\nSOLVES: 0 (I guessed)"
    sc.record_solve_count("3", 7, source="board", workdir=tmp_path)
    assert codes(sc.check_report(rep, workdir=tmp_path, challenge_id="3")) == ["broken-but-solved"]
    submit(tmp_path, prof, "4", "correct")
    assert codes(sc.check_report(rep, workdir=tmp_path, challenge_id="4")) == ["broken-but-solved"]


def test_not_broken_is_not_a_broken_claim(prof, tmp_path):
    assert sc.check_report("STATUS: WORKING\nNEXT: x\nThe service is not broken; my parser is.",
                           workdir=tmp_path) == []
    assert sc.check_report("STATUS: WORKING\nNEXT: x\nIt isn't broken.", workdir=tmp_path) == []


def test_a_flag_elsewhere_claim_needs_evidence(prof, tmp_path):
    rep = "STATUS: WORKING\nNEXT: search\nThe other half of the flag lives on Discord."
    assert codes(sc.check_report(rep, workdir=tmp_path)) == ["flag-elsewhere-no-evidence"]
    assert codes(sc.check_report("STATUS: WORKING\nNEXT: x\nthe rest of the flag is hidden "
                                 "somewhere else", workdir=tmp_path)) == ["flag-elsewhere-no-evidence"]
    assert sc.check_report(rep + "\nEVIDENCE: files/readme.txt line 3 names the channel",
                           workdir=tmp_path) == []


@pytest.mark.parametrize("prose", [
    "The flag is not in the files list I grepped yet.",
    "The flag is not in the files I grepped; next I try the pcap.",
    "The rest of the flag is stored outside the main loop in a table.",
    "Part of the flag is in the .data section.",
])
def test_a_search_note_is_not_a_flag_elsewhere_claim(tmp_path, prose):
    assert sc.check_report(f"STATUS: WORKING\nNEXT: x\n{prose}", workdir=tmp_path) == []


@pytest.mark.parametrize("prose", [
    "The flag is not in the files at all.",
    "The second half of the flag lives outside the challenge files.",
    "The flag is outside.",
    "Part of the flag is posted on Twitter.",
])
def test_an_explicit_outside_location_is_a_flag_elsewhere_claim(tmp_path, prose):
    assert codes(sc.check_report(f"STATUS: WORKING\nNEXT: x\n{prose}", workdir=tmp_path)) \
        == ["flag-elsewhere-no-evidence"]


def test_a_stop_before_any_stop_loss_is_refused(prof, tmp_path):
    rep = "STATUS: STOPPED\nSTOP_LOSS: I am out of ideas"
    v = sc.check_report(rep, profile=prof, workdir=tmp_path, challenge_id="21")
    assert codes(v) == ["stop-before-stop-loss"]
    assert "no stop-loss has fired" in v[0].message
    assert codes(sc.check_report("STATUS: STOPPED", profile=prof, workdir=tmp_path, challenge_id="21")) \
        == ["stop-before-stop-loss", "stop-no-stop-loss"]
    # a stand-down in prose is a stop too
    assert codes(sc.check_report("STATUS: WORKING\nNEXT: none\nStanding down on this one.", profile=prof,
                                 workdir=tmp_path, challenge_id="21")) == ["stop-before-stop-loss"]
    assert codes(sc.check_report("STATUS: WORKING\nNEXT: x\nparking it", workdir=tmp_path)) \
        == ["stop-unverifiable"]


@pytest.mark.parametrize("prose", [
    "Ruled out rung 1; abandoned the padding-oracle theory.",
    "I parked the RSA idea; not giving up.",
    "Gave up on the SQLi hypothesis, moving to rung 3.",
    "I won't give up on this challenge.",
    "Not standing down: the timer has not fired.",
    "I am not going to give up.",
])
def test_dropping_a_theory_or_refusing_to_give_up_is_not_a_stand_down(prof, tmp_path, prose):
    rep = f"STATUS: WORKING\nNEXT: try rung 2\n{prose}"
    assert sc.check_report(rep, profile=prof, workdir=tmp_path, challenge_id="22") == []


@pytest.mark.parametrize("prose", [
    "Abandoned the theory and this challenge.",
    "Parking this challenge; the RSA idea failed.",
    "giving up, nothing else to try",
    "I gave up on it.",
    "I gave up on it; the RSA idea was wrong anyway.",     # a theory in a later clause is not the object
])
def test_giving_up_on_the_challenge_is_still_a_stand_down(prof, tmp_path, prose):
    rep = f"STATUS: WORKING\nNEXT: none\n{prose}"
    assert codes(sc.check_report(rep, profile=prof, workdir=tmp_path, challenge_id="22")) \
        == ["stop-before-stop-loss"]


def test_a_stop_after_a_stop_loss_passes(prof, tmp_path):
    for _ in range(3):
        submit(tmp_path, prof, "21", "incorrect")
    assert sc.check_report("STATUS: STOPPED\nSTOP_LOSS: wrong-answer stop", profile=prof,
                           workdir=tmp_path, challenge_id="21") == []


# ----------------------------------------------------------------------------------- may_stop

def test_may_stop_is_no_on_a_fresh_challenge(prof, tmp_path):
    v = sc.may_stop(prof, "30", workdir=tmp_path)
    assert not v.allowed and "still scores" in v.reasons[0]


def test_may_stop_on_a_solve(prof, tmp_path):
    submit(tmp_path, prof, "30", "correct")
    v = sc.may_stop(prof, "30", workdir=tmp_path)
    assert v.allowed and v.reasons[0].startswith("solved")


def test_may_stop_on_a_budget_stop_or_the_cap(prof, tmp_path):
    write_ledger(tmp_path, "stop", challenge_id="31", reason="manual", by="player")
    v = sc.may_stop(prof, "31", workdir=tmp_path)
    assert v.allowed and "budget stop: manual (by player)" in v.reasons
    write_ledger(tmp_path, "spend", challenge_id="32", usd=24.0, tok=1)
    assert not sc.may_stop(prof, "32", workdir=tmp_path).allowed      # under the $25 floor cap
    write_ledger(tmp_path, "spend", challenge_id="32", usd=1.0, tok=1)
    v = sc.may_stop(prof, "32", workdir=tmp_path)
    assert v.allowed and v.reasons[0].startswith("budget cap reached")


def test_may_stop_on_the_no_progress_timer_of_a_tail(prof, tmp_path):
    write_ledger(tmp_path, "budget_challenge", challenge_id="33", tail=True, ts=1000.0)
    assert not sc.may_stop(prof, "33", workdir=tmp_path, clock=lambda: 1000.0 + 60).allowed
    v = sc.may_stop(prof, "33", workdir=tmp_path, clock=lambda: 1000.0 + 21 * 60)
    assert v.allowed and v.reasons[0].startswith("no-progress timer")


def test_the_no_progress_timer_fires_exactly_at_its_threshold(prof, tmp_path):
    from ctf.budget import LedgerMeter
    write_ledger(tmp_path, "budget_challenge", challenge_id="36", tail=True, ts=1000.0)
    limit = LedgerMeter(prof, workdir=tmp_path).no_progress_seconds
    assert not sc.may_stop(prof, "36", workdir=tmp_path, clock=lambda: 1000.0 + limit - 1).allowed
    v = sc.may_stop(prof, "36", workdir=tmp_path, clock=lambda: 1000.0 + limit)
    assert v.allowed and v.reasons[0].startswith("no-progress timer")


def test_may_stop_on_the_wrong_answer_stop_unless_the_player_approved_more(prof, tmp_path):
    for _ in range(2):
        submit(tmp_path, prof, "34", "incorrect")
    assert not sc.may_stop(prof, "34", workdir=tmp_path).allowed
    submit(tmp_path, prof, "34", "incorrect")
    v = sc.may_stop(prof, "34", workdir=tmp_path)
    assert v.allowed and v.reasons[0].startswith("wrong-answer stop: 3")
    write_ledger(tmp_path, "platform.approval", challenge_id="34", count=1, reason="player ok",
                 event_slug=prof.slug)
    assert not sc.may_stop(prof, "34", workdir=tmp_path).allowed     # one more send approved
    final = dataclasses.replace(prof, rules=dataclasses.replace(prof.rules, approved_extras=False))
    assert sc.may_stop(final, "34", workdir=tmp_path).allowed        # no approval reopens it there


def test_may_stop_on_a_claim_marked_gone_or_solved(prof, tmp_path):
    d = dispatch.Detected("35", "Gone", "Web", 100)
    dispatch.dispatch_one(d, prof, workdir=tmp_path, record=False)
    assert not sc.may_stop(prof, "35", workdir=tmp_path).allowed
    dispatch.update_claim(tmp_path, "35", status="gone")
    v = sc.may_stop(prof, "35", workdir=tmp_path)
    assert v.allowed and "dispatch claim marked gone" in v.reasons


def test_may_stop_needs_an_id(prof, tmp_path):
    with pytest.raises(sc.ContractError):
        sc.may_stop(prof, "  ", workdir=tmp_path)


# ----------------------------------------------------------------------------------- record_status

def test_record_status_refuses_solved_before_acceptance_and_writes_nothing(prof, tmp_path):
    rec, v = sc.record_status(sc.parse_report("STATUS: SOLVED"), profile=prof, challenge_id="40",
                              workdir=tmp_path)
    assert rec is None and codes(v) == ["solved-before-acceptance"]
    assert [r for r in ledger.read(tmp_path) if r["event"] == sc.STATUS_EVENT] == []


def test_record_status_writes_a_passing_report(prof, tmp_path):
    rep = sc.parse_report("STATUS: WORKING\nNEXT: run the crypto ladder rung 2\nEVIDENCE: n in files/key.pem")
    rec, v = sc.record_status(rep, profile=prof, challenge_id="41", workdir=tmp_path, by="agent:claude")
    assert v == []
    (got,) = [r for r in ledger.read(tmp_path) if r["event"] == sc.STATUS_EVENT]
    assert got["challenge_id"] == "41" and got["status"] == "WORKING" and got["by"] == "agent:claude"
    assert got["next"] == "run the crypto ladder rung 2" and got["evidence"] == "n in files/key.pem"


def test_record_status_refuses_a_report_about_another_challenge(prof, tmp_path):
    rec, v = sc.record_status(sc.parse_report("STATUS: WORKING\nNEXT: x\nCHALLENGE: 99"), profile=prof,
                              challenge_id="41", workdir=tmp_path)
    assert rec is None and codes(v) == ["challenge-mismatch"]


# ----------------------------------------------------------------------------------- solve counts, facts

def test_solve_counts_latest_wins_and_bad_input_is_refused(tmp_path):
    assert sc.solve_count("50", workdir=tmp_path) is None
    sc.record_solve_count("50", 0, source="board", workdir=tmp_path)
    sc.record_solve_count("50", 3, source="board", workdir=tmp_path)
    got = sc.solve_count("50", workdir=tmp_path)
    assert got.count == 3 and got.source == "board"
    for bad in (-1, True, "3", 1.5):
        with pytest.raises(sc.ContractError):
            sc.record_solve_count("50", bad, source="board", workdir=tmp_path)
    with pytest.raises(sc.ContractError):
        sc.record_solve_count("50", 1, source=" ", workdir=tmp_path)


def test_a_fact_needs_evidence(tmp_path):
    with pytest.raises(sc.ContractError, match="evidence"):
        sc.record_fact("60", "the key is 16 bytes", evidence="  ", workdir=tmp_path)
    with pytest.raises(sc.ContractError):
        sc.record_fact("60", "", evidence="x", workdir=tmp_path)
    with pytest.raises(sc.ContractError):
        sc.record_fact("60", "x" * (sc.MAX_FACT_CHARS + 1), evidence="y", workdir=tmp_path)
    assert sc.facts("60", workdir=tmp_path) == []


def test_facts_returns_only_evidenced_facts_for_the_challenge(tmp_path):
    sc.record_fact("61", "the IV repeats across messages", evidence="files/c.bin offsets 0 and 64",
                   workdir=tmp_path, by="agent:a")
    write_ledger(tmp_path, "fact", challenge_id="61", fact="maybe a padding oracle")    # no evidence
    sc.record_fact("62", "other challenge", evidence="x", workdir=tmp_path)
    sc.record_fact("61#a", "part a's key length is 16", evidence="files/a.py line 4", workdir=tmp_path)
    fs = sc.facts("61", workdir=tmp_path)
    assert [f.fact for f in fs] == ["the IV repeats across messages", "part a's key length is 16"]
    assert fs[0].by == "agent:a"


# ----------------------------------------------------------------------------------- fresh eyes

def _challenge(prof, tmp_path, cid="70", name="Echo", cat="Crypto"):
    d = dispatch.Detected(cid, name, cat, 200)
    claim = dispatch.dispatch_one(d, prof, workdir=tmp_path, record=False)
    folder = Path(claim.recon_dir)
    (folder / "files").mkdir(parents=True, exist_ok=True)
    (folder / "files" / "cipher.bin").write_bytes(b"\x00" * 32)
    (folder / "notes.md").write_text("THEORY: it is a padding oracle, definitely\n")
    (folder / "recon").mkdir(exist_ok=True)
    (folder / "recon" / "index.md").write_text("# recon\n")
    return folder


def test_fresh_eyes_passes_the_artifact_and_verified_facts_only(prof, tmp_path):
    folder = _challenge(prof, tmp_path)
    sc.record_fact("70", "the ciphertext is 32 zero bytes", evidence="files/cipher.bin", workdir=tmp_path)
    write_ledger(tmp_path, "fact", challenge_id="70", fact="unverified hunch about RNG")
    write_ledger(tmp_path, "hypothesis", challenge_id="70", text="weak RNG seeded by time")
    md = sc.fresh_eyes_md("70", workdir=tmp_path)
    assert "# fresh eyes: Echo" in md
    assert "files/cipher.bin` (32 bytes)" in md
    assert "`recon/index.md` (present)" in md and "`triage.md` (not written yet)" in md
    assert "the ciphertext is 32 zero bytes" in md and "verified facts (1)" in md
    assert "padding oracle, definitely" not in md          # notes.md theories are not passed
    assert "unverified hunch" not in md and "weak RNG seeded" not in md
    assert sc.LADDERS["crypto"][0] in md                    # the lane's ladder and the contract
    assert sc.rules_md(heading_level=3).rstrip("\n") in md
    p = sc.write_fresh_eyes("70", workdir=tmp_path)
    assert p == folder / sc.FRESH_EYES_NAME and p.read_text() == md


def test_fresh_eyes_with_no_facts_says_so_and_quotes_fact_text_as_data(prof, tmp_path):
    _challenge(prof, tmp_path, cid="71")
    md = sc.fresh_eyes_md("71", workdir=tmp_path)
    assert "verified facts (0)" in md and "none recorded" in md
    sc.record_fact("71", "line\n```\n# injected heading", evidence="files/x", workdir=tmp_path)
    md = sc.fresh_eyes_md("71", workdir=tmp_path)
    assert "```\n# injected heading" not in md


def test_fresh_eyes_without_files_names_the_gap(prof, tmp_path):
    md = sc.fresh_eyes_md("72", workdir=tmp_path)
    assert "no `files/` folder" in md


# ----------------------------------------------------------------------------------- CLI

def run_cli(monkeypatch, tmp_path, *argv):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    return cli.main(["contract", "--event", "csctf", *argv])


def test_cli_show_prints_the_contract_and_the_ladder(monkeypatch, tmp_path, capsys):
    assert run_cli(monkeypatch, tmp_path, "show", "--lane", "pwn") == 0
    out = capsys.readouterr().out
    assert sc.LADDERS["pwn"][0] in out and "## Solver contract" in out


def test_cli_check_exits_1_on_a_violation_and_0_on_a_clean_report(monkeypatch, tmp_path, capsys):
    bad = tmp_path / "bad.txt"
    bad.write_text("STATUS: SOLVED\nCHALLENGE: 80\n")
    assert run_cli(monkeypatch, tmp_path, "check", str(bad)) == 1
    assert "solved-before-acceptance" in capsys.readouterr().err
    good = tmp_path / "good.txt"
    good.write_text("STATUS: WORKING\nNEXT: grep the strings\n")
    assert run_cli(monkeypatch, tmp_path, "check", str(good), "--challenge", "80") == 0
    assert run_cli(monkeypatch, tmp_path, "check", str(tmp_path / "missing.txt")) == 2


def test_cli_report_records_only_a_passing_report(monkeypatch, tmp_path, capsys):
    assert run_cli(monkeypatch, tmp_path, "report", "81", "--status", "SOLVED") == 1
    assert "nothing recorded" in capsys.readouterr().err
    assert run_cli(monkeypatch, tmp_path, "report", "81", "--status", "FLAG_FOUND", "--next", "submit",
                   "--evidence", "files/a @0x10", "--oracle", "pass check() accepts it") == 0
    recs = [r for r in ledger.read(tmp_path) if r["event"] == sc.STATUS_EVENT]
    assert [(r["challenge_id"], r["status"]) for r in recs] == [("81", "FLAG_FOUND")]
    assert run_cli(monkeypatch, tmp_path, "report", "81", "--status", "WORKING", "--next", "x",
                   "--note", "giving up, it is impossible") == 1
    err = capsys.readouterr().err
    assert "broken-without-solves" in err and "stop-before-stop-loss" in err


def test_cli_may_stop_exit_codes(monkeypatch, tmp_path, capsys):
    assert run_cli(monkeypatch, tmp_path, "may-stop", "82") == 1
    assert "KEEP WORKING" in capsys.readouterr().out
    write_ledger(tmp_path, "stop", challenge_id="82", reason="team_solve")
    assert run_cli(monkeypatch, tmp_path, "may-stop", "82", "--json") == 0
    got = json.loads(capsys.readouterr().out)
    assert got["allowed"] is True and got["challenge_id"] == "82"


def test_cli_solves_and_fact_and_fresh_eyes(monkeypatch, tmp_path, capsys):
    assert run_cli(monkeypatch, tmp_path, "solves", "83") == 1
    assert run_cli(monkeypatch, tmp_path, "solves", "83", "--record", "2") == 2       # --source needed
    assert run_cli(monkeypatch, tmp_path, "solves", "83", "--record", "2", "--source", "board") == 0
    capsys.readouterr()
    assert run_cli(monkeypatch, tmp_path, "solves", "83") == 0
    assert "2 solve(s) (board)" in capsys.readouterr().out
    assert run_cli(monkeypatch, tmp_path, "fact", "83", "x is y", "--evidence", " ") == 2
    assert run_cli(monkeypatch, tmp_path, "fact", "83", "the port is 31337", "--evidence", "brief") == 0
    capsys.readouterr()
    assert run_cli(monkeypatch, tmp_path, "fresh-eyes", "83") == 0
    assert "the port is 31337" in capsys.readouterr().out
