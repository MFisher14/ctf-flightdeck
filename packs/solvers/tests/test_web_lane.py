#!/usr/bin/env python3
"""B-007: ctf.web_lane -- the Huntress web Layer-1 release lane.

The lane drives the B-005 Game Master adapter (started here against a recorded fake Game Master, never
a live platform) and the real read-only proof reader (solvers/web/proof_hunt.py) against LOOPBACK fake
web targets (tests/web_fakes.py, 127.0.0.1 only). It never touches a live service.

Covered:
  * a web base row with a live backup target: the lane forces the attempt open, reads the proof and
    banks it through the SubmitGate (one submit POST carrying exactly that proof);
  * practice mode reads the same proof but sends NO submit;
  * the release scope fence: select_web_rows returns only released, unsolved, lane==web rows;
  * the opener-owns-the-clock rule: a timed id is never *started* here -- a non-running one is skipped
    and a running one is read without a start POST;
  * forced-start retry through a transient 503, and a persistent 503 that stays not-started;
  * provisioning-aware polling (preparing -> running);
  * only an is_proof() value is ever banked (an off-format value from the reader is dropped, no POST);
  * a missing proof_hunt fails loudly (no silent fallback).
"""
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))

import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # web answers are proof_<32 hex> (events/huntress [proof])

import web_fakes  # noqa: E402  -- the loopback Site/serve fakes + proof_hunt loader
from platform_fixture_session import FakeSession  # noqa: E402
from ctf import event, web_lane  # noqa: E402
from ctf.platform import SubmitStatus  # noqa: E402
from ctf.platform import gamemaster  # noqa: E402
from ctf.platform.policy import SubmitGate  # noqa: E402

GM = "http://127.0.0.1:8765/"
CID = "web-exploitation-day-01-backup-exposure"


def serve_backup():
    """A live loopback backup target holding a fresh proof. Returns (server, url, proof)."""
    proof = web_fakes.uuid_proof("web-lane-day01")
    srv, url = web_fakes.serve(web_fakes.Site(web_fakes.site_backup(proof)))
    return srv, url, proof


def attempt_body(url, *, answer_ids=("proof-1",)):
    return {"attempt_id": "a1", "name": "Backup Exposure", "prompt": "Find the leaked proof.",
            "questions": [{"id": a, "question": "Recover the proof."} for a in answer_ids],
            "answer_ids": list(answer_ids), "targets": [{"url": url}],
            "deadline": "2099-01-01T00:00:00Z"}


def list_body(rows):
    return {"challenges": rows}


def row(cid=CID, *, lane="web", mode="base", solved=False, day=1):
    return {"id": cid, "name": cid, "lane": lane, "mode": mode, "day": day, "solved": solved}


def make_gate(routes):
    s = FakeSession(routes)
    adapter = gamemaster.GameMasterAdapter(GM, session=s)
    return SubmitGate(adapter, event.load("huntress")), s


def submit_posts(s):
    """The POSTs that actually carried answers (the banking requests)."""
    return [c for c in s.sent("POST") if isinstance(c.get("json"), dict) and "answers" in c["json"]]


def start_posts(s):
    return [c for c in s.sent("POST") if isinstance(c.get("json"), dict) and "answers" not in c["json"]]


# --------------------------------------------------------------------------------------------------
def test_live_backup_row_is_read_and_banked():
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},            # start
            {"method": "POST", "url": GM, "body": {"result": "CORRECT", "flag": "flag{ok}"}},  # submit
        ])
        ch = web_lane.select_web_rows(gate)[0]
        res = web_lane.run_row(gate, ch, sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.BANKED, res
    assert res.proofs == {"proof-1": proof}
    assert res.submitted.status is SubmitStatus.CORRECT
    sent = submit_posts(s)
    assert len(sent) == 1 and sent[0]["json"]["answers"] == {"proof-1": proof}


def test_practice_reads_the_proof_but_sends_no_submit():
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "CORRECT", "flag": "flag{ok}"}},
        ])
        ch = web_lane.select_web_rows(gate)[0]
        res = web_lane.run_row(gate, ch, practice=True, sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.FOUND and res.proofs == {"proof-1": proof}
    assert res.submitted is None
    assert submit_posts(s) == []          # op=practice never banks


def test_release_fence_selects_only_released_unsolved_web_rows():
    gate, _s = make_gate([
        {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"}, "body": list_body([
            row("web-a", lane="web", solved=False),
            row("web-solved", lane="web", solved=True),
            row("crypto-1", lane="crypto", solved=False),
        ])},
    ])
    picked = [c.id for c in web_lane.select_web_rows(gate)]
    assert picked == ["web-a"]                         # not the solved web row, not the crypto row
    assert "web-solved" in [c.id for c in web_lane.select_web_rows(gate, include_solved=True)]


def test_timed_id_not_running_is_skipped_without_starting_the_clock():
    tid = CID + "/time_trial"
    gate, s = make_gate([
        {"method": "GET", "url": GM, "params": {"op": "status", "challenge": tid},
         "body": {"error": "start_required"}, "status": 409},
    ])
    from ctf.platform.base import Challenge
    res = web_lane.run_row(gate, Challenge(id=tid, name=tid, category="web", tags=("time_trial",)),
                           sleep=lambda _s: None)
    assert res.state == web_lane.SKIPPED_TIMED, res
    assert start_posts(s) == []           # the lane never starts a scored clock (the opener does)


def test_timed_id_already_running_is_read_without_a_start():
    tid = CID + "/mastery"
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row(tid, mode="mastery")])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": tid}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
        ])
        from ctf.platform.base import Challenge
        res = web_lane.run_row(gate, Challenge(id=tid, name=tid, category="web", tags=("mastery",)),
                               sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.BANKED and res.proofs == {"proof-1": proof}
    assert start_posts(s) == []           # a running timed attempt is read in place, never re-started


def test_forced_start_retries_through_a_transient_503():
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            # the first forced start answers 503 (a release-minute provisioning hiccup), then succeeds
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "status": 503,
             "body": {"error": "unavailable"}, "once": True},
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
        ])
        ch = web_lane.select_web_rows(gate)[0]
        res = web_lane.run_row(gate, ch, sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.BANKED and res.proofs == {"proof-1": proof}
    assert len(start_posts(s)) == 2       # the 503 try plus the successful one


def test_persistent_503_is_reported_not_started_and_nothing_is_submitted():
    gate, s = make_gate([
        {"method": "POST", "url": GM, "json": {"challenge": CID}, "status": 503,
         "body": {"error": "unavailable"}},
    ])
    from ctf.platform.base import Challenge
    res = web_lane.run_row(gate, Challenge(id=CID, name=CID, category="web"),
                           retries=1, sleep=lambda _s: None)
    assert res.state == web_lane.NOT_STARTED, res
    assert "503" in res.reason or "unavailable" in res.reason
    assert submit_posts(s) == []


def test_provisioning_poll_waits_for_running():
    srv, url, proof = serve_backup()
    clock = [0.0]
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "POST", "url": GM, "json": {"challenge": CID},
             "body": {"result": "preparing"}},                      # start -> still provisioning
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID},
             "body": {"result": "preparing"}, "once": True},         # first poll: not ready
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
        ])
        from ctf.platform.base import Challenge
        res = web_lane.run_row(
            gate, Challenge(id=CID, name=CID, category="web"),
            sleep=lambda _s: clock.__setitem__(0, clock[0] + 1.0),
            now=lambda: clock[0], poll_total_s=30.0, poll_interval_s=1.0)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.BANKED and res.proofs == {"proof-1": proof}


def test_no_proof_target_is_no_proof_and_sends_nothing():
    # a plain page with no backup, no proof anywhere reachable
    srv, url = web_fakes.serve(web_fakes.Site({"/": web_fakes.page("Quiet", "<p>Nothing here.</p>")}))
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
        ])
        from ctf.platform.base import Challenge
        res = web_lane.run_row(gate, Challenge(id=CID, name=CID, category="web"), sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.NO_PROOF, res
    assert submit_posts(s) == []


def test_only_is_proof_values_are_banked():
    """The lane banks a value only if proof_hunt.is_proof() accepts it. An off-format value the reader
    returns (not the proof_<32 hex> wire form) is dropped, and nothing is sent."""
    real = web_lane.load_proof_hunt()

    class OffFormatReader:
        is_proof = staticmethod(real.is_proof)   # the REAL gate

        @staticmethod
        def solve_targets(targets, ctx):
            return {t["answer_id"]: "flag{not-a-proof}" for t in targets}

    att = attempt_body("http://127.0.0.1:1/")   # never actually read (reader is stubbed)
    gate, s = make_gate([
        {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"}, "body": list_body([row()])},
        {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
        {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
        {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
    ])
    from ctf.platform.base import Challenge
    res = web_lane.run_row(gate, Challenge(id=CID, name=CID, category="web"),
                           proof_hunt=OffFormatReader, sleep=lambda _s: None)
    assert res.state == web_lane.NO_PROOF, res
    assert submit_posts(s) == []


def test_run_lane_banks_web_and_skips_the_rest():
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"}, "body": list_body([
                row(CID, lane="web"), row("crypto-1", lane="crypto"),
                row("web-solved", lane="web", solved=True)])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
        ])
        results = web_lane.run_lane(gate, sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert [r.challenge_id for r in results] == [CID]          # only the released, unsolved web row
    assert results[0].state == web_lane.BANKED and results[0].proofs == {"proof-1": proof}


def test_is_web_row_and_is_timed_units():
    from ctf.platform.base import Challenge
    assert web_lane.is_web_row(Challenge(id="x", name="x", category="web"))
    assert web_lane.is_web_row(Challenge(id="x", name="x", category="Web"))
    assert not web_lane.is_web_row(Challenge(id="x", name="x", category="crypto"))
    assert web_lane.is_timed("c/time_trial") and web_lane.is_timed("c/mastery/")
    assert not web_lane.is_timed("c") and not web_lane.is_timed("c/base")


def test_build_targets_pairs_answers_with_urls():
    status_one = {"answer_ids": ["proof-1", "proof-2"], "targets": [{"url": "http://h/"}],
                  "questions": [{"id": "proof-1", "question": "Q1"}, {"id": "proof-2", "question": "Q2"}]}
    built = web_lane.build_targets(status_one, None)
    # one target, two answers -> both run against the one target, carrying their own question text
    assert [t["url"] for t in built] == ["http://h/", "http://h/"]
    assert [t["answer_id"] for t in built] == ["proof-1", "proof-2"]
    assert built[0]["question"] == "Q1" and built[1]["question"] == "Q2"
    status_two = {"answer_ids": ["a", "b"], "targets": [{"url": "http://h1/"}, {"url": "http://h2/"}],
                  "questions": []}
    assert [t["url"] for t in web_lane.build_targets(status_two, None)] == ["http://h1/", "http://h2/"]
    assert web_lane.build_targets({"answer_ids": [], "targets": []}, None) == []


def test_missing_proof_hunt_fails_loudly(monkeypatch, tmp_path):
    monkeypatch.setattr(web_lane, "_PROOF_HUNT", None)
    monkeypatch.setattr(web_lane._paths, "repo_root", lambda: tmp_path)  # no solvers/web/proof_hunt.py
    with pytest.raises(web_lane.WebLaneError) as ei:
        web_lane.load_proof_hunt()
    assert "proof_hunt.py" in str(ei.value)


# --------------------------------------------------------------------------------------------------
#  the operator CLI (ctf web-lane), driven against the same fake Game Master
# --------------------------------------------------------------------------------------------------
def _cli_args(argv):
    import argparse
    from ctf.cli import web_lane as cli
    p = argparse.ArgumentParser()
    cli.add_arguments(p)
    return p.parse_args(argv)


def test_cli_is_discovered_as_web_lane():
    from ctf.cli import discover
    names = {name: (mod, err) for name, mod, err in discover()}
    assert "web-lane" in names, names.keys()
    mod, err = names["web-lane"]
    assert err is None and mod is not None       # HELP/add_arguments/run all present


def test_cli_list_prints_released_web_rows(monkeypatch, capsys):
    from ctf.cli import web_lane as cli
    gate, _s = make_gate([
        {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"}, "body": list_body([
            row(CID, lane="web"), row("crypto-1", lane="crypto")])},
    ])
    monkeypatch.setattr(cli, "_profile", lambda args: object())
    monkeypatch.setattr(cli, "build_gate", lambda profile: gate)
    rc = cli.run(_cli_args(["list"]))
    out = capsys.readouterr().out
    assert rc == 0 and CID in out and "crypto-1" not in out


def test_cli_run_practice_reads_but_does_not_submit(monkeypatch, capsys):
    from ctf.cli import web_lane as cli
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
        ])
        monkeypatch.setattr(cli, "_profile", lambda args: object())
        monkeypatch.setattr(cli, "build_gate", lambda profile: gate)
        rc = cli.run(_cli_args(["run", "--dry-run"]))
    finally:
        srv.shutdown()
        srv.server_close()
    assert rc == 0
    assert web_lane.FOUND in capsys.readouterr().out
    assert submit_posts(s) == []                 # dry-run: read, never bank


# --------------------------------------------------------------------------------------------------
#  round-1 verification fixes
# --------------------------------------------------------------------------------------------------
def test_forced_start_makes_three_tries_at_default_retries():
    """Mutation guard for ensure_running's range(retries + 1): at the default retries=2, two transient
    503s followed by success must send THREE forced-start POSTs and still bank. range(retries) would
    do only two tries, so both 503s would exhaust them and the row would never start -- this fails then."""
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "status": 503,
             "body": {"error": "unavailable"}, "once": True},   # try 1 -> 503
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "status": 503,
             "body": {"error": "unavailable"}, "once": True},   # try 2 -> 503
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},   # try 3 -> success
            {"method": "POST", "url": GM, "body": {"result": "CORRECT"}},
        ])
        ch = web_lane.select_web_rows(gate)[0]
        res = web_lane.run_row(gate, ch, sleep=lambda _s: None)   # default retries=2
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.BANKED and res.proofs == {"proof-1": proof}
    assert len(start_posts(s)) == 3        # retries + 1 == 3 forced starts; range(retries) would give 2


def test_get_only_webclient_refuses_a_non_get_before_the_wire():
    """The lane's enforced GET-only guarantee at the one chokepoint: a get_only WebClient answers a GET
    but refuses a POST with OutOfScope, and the loopback target records only GET -- so no state-changing
    request ever reaches it. This test fails if a non-GET reaches the target."""
    PH = web_fakes.PH
    site = web_fakes.Site({"/": web_fakes.page("Quiet", "<p>ok</p>")})
    srv, url = web_fakes.serve(site)
    try:
        wc = PH._web.WebClient(url, get_only=True)
        assert wc.get("/")["status"] == 200             # a GET reaches the site
        with pytest.raises(PH._web.OutOfScope):
            wc.post("/", data="x=1")                     # a POST is refused before any send
    finally:
        srv.shutdown()
        srv.server_close()
    assert {m for _t, m, _raw in site.hits} == {"GET"}   # nothing but GET ever hit the target


def test_hunter_builds_a_get_only_client_only_when_asked():
    """proof_hunt threads get_only onto the WebClient it builds (and off by default)."""
    srv, url = web_fakes.serve(web_fakes.Site({"/": web_fakes.page("Q", "<p>ok</p>")}))
    try:
        h_on = web_fakes.PH._Hunter(url, get_only=True)
        h_off = web_fakes.PH._Hunter(url)
        assert h_on.client is not None and h_on.client.get_only is True
        assert h_off.client is not None and h_off.client.get_only is False
    finally:
        srv.shutdown()
        srv.server_close()


def test_solve_targets_passes_get_only_to_each_hunter(monkeypatch):
    """solve_targets must read ctx['get_only'] and hand it to every _Hunter (killing a drop-the-kwarg
    mutant): a spy records the flag each hunter is built with."""
    import time as _t
    PH = web_fakes.PH
    seen = []
    real_hunter = PH._Hunter

    def spy(url, **kw):
        seen.append(kw.get("get_only"))
        return real_hunter(url, **kw)

    monkeypatch.setattr(PH, "_Hunter", spy)
    srv, url = web_fakes.serve(web_fakes.Site({"/": web_fakes.page("Q", "<p>ok</p>")}))
    try:
        PH.solve_targets([{"answer_id": "a", "url": url}],
                         {"get_only": True, "deadline": _t.time() + 1.0, "max_requests": 2})
    finally:
        srv.shutdown()
        srv.server_close()
    assert seen and all(v is True for v in seen)         # every hunter was built get_only


def test_run_row_drives_the_reader_get_only():
    """The lane sets get_only=True in the ctx it hands the reader (so the siblings cannot mutate)."""
    captured = {}

    class CaptureReader:
        is_proof = staticmethod(web_lane.load_proof_hunt().is_proof)

        @staticmethod
        def solve_targets(targets, ctx):
            captured.update(ctx)
            return {}

    att = attempt_body("http://127.0.0.1:1/")
    gate, _s = make_gate([
        {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"}, "body": list_body([row()])},
        {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
        {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
    ])
    ch = web_lane.select_web_rows(gate)[0]
    res = web_lane.run_row(gate, ch, proof_hunt=CaptureReader, sleep=lambda _s: None)
    assert res.state == web_lane.NO_PROOF
    assert captured.get("get_only") is True


def test_incorrect_verdict_is_not_reported_as_banked():
    """A wrong submission must NOT be reported banked (report status exactly)."""
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"result": "incorrect"}},
        ])
        ch = web_lane.select_web_rows(gate)[0]
        res = web_lane.run_row(gate, ch, sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.SUBMIT_INCORRECT, res   # a read-and-sent proof the platform judged wrong
    assert res.state != web_lane.BANKED and not res.ok
    assert len(submit_posts(s)) == 1                     # it WAS sent, just not banked


def test_refused_submission_is_not_reported_as_banked():
    """A platform refusal (NOT_ALLOWED) is its own state, never banked."""
    srv, url, proof = serve_backup()
    try:
        att = attempt_body(url)
        gate, s = make_gate([
            {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
             "body": list_body([row()])},
            {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
            {"method": "POST", "url": GM, "body": {"error": "invalid_answers"}},   # a known refusal word
        ])
        ch = web_lane.select_web_rows(gate)[0]
        res = web_lane.run_row(gate, ch, sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.SUBMIT_REFUSED, res
    assert res.state != web_lane.BANKED and not res.ok


def test_submit_state_maps_every_status():
    """_submit_state banks only a judged-correct (or already-solved) verdict."""
    S = SubmitStatus
    assert web_lane._submit_state(S.CORRECT)[0] == web_lane.BANKED
    assert web_lane._submit_state(S.ALREADY_SOLVED)[0] == web_lane.BANKED
    assert web_lane._submit_state(S.INCORRECT)[0] == web_lane.SUBMIT_INCORRECT
    assert web_lane._submit_state(S.NOT_ALLOWED)[0] == web_lane.SUBMIT_REFUSED
    assert web_lane._submit_state(S.RATE_LIMITED)[0] == web_lane.SUBMIT_RATE_LIMITED
    assert web_lane._submit_state(S.PAUSED)[0] == web_lane.SUBMIT_PENDING


def test_instances_not_allowed_is_reraised_not_retried():
    """A refusal that can never succeed (InstancesNotAllowed) must propagate out of ensure_running, not
    be retried as a transient error. We count start attempts to prove it was tried exactly once."""
    from ctf.platform.base import Challenge, InstancesNotAllowed

    tries = [0]

    class RefusingGate:
        kind = "gamemaster"

        def start_instance(self, cid):
            tries[0] += 1
            raise InstancesNotAllowed("instances are not allowed for this event (manual mode)")

    with pytest.raises(InstancesNotAllowed):
        web_lane.ensure_running(RefusingGate(), CID, retries=2, sleep=lambda _s: None)
    assert tries[0] == 1                 # tried once, not retries+1 times


def test_run_lane_refuses_a_non_gamemaster_event():
    """The lane drives the Game Master only; any other platform kind is refused before any start."""
    class CtfdishGate:
        kind = "ctfd"

        def list_challenges(self):
            raise AssertionError("must refuse before listing/starting")

    with pytest.raises(web_lane.WebLaneError) as ei:
        web_lane.run_lane(CtfdishGate())
    assert "gamemaster" in str(ei.value).lower()


def test_is_event_proof_uses_the_active_profile():
    """The lane cross-checks a banked value against the active event's [proof] format, not just
    proof_hunt.is_proof. (The fail-closed case, a profile with no [proof] token, is
    test_is_event_proof_fails_closed_without_a_proof_format.)"""
    from ctf import event as _event
    good_gate = type("G", (), {"profile": _event.load("huntress")})()
    proof = web_fakes.uuid_proof("event-proof-check")
    assert web_lane._is_event_proof(good_gate, proof) is True
    assert web_lane._is_event_proof(good_gate, "flag{not-a-proof}") is False


def test_cli_run_refuses_a_non_gamemaster_event(monkeypatch, capsys):
    """`ctf web-lane run` exits 2 with a named reason on a non-Game-Master event, before any start."""
    from ctf.cli import web_lane as cli

    class CtfdishGate:
        kind = "ctfd"

    monkeypatch.setattr(cli, "_profile", lambda args: object())
    monkeypatch.setattr(cli, "build_gate", lambda profile: CtfdishGate())
    rc = cli.run(_cli_args(["run"]))
    assert rc == 2
    assert "gamemaster" in capsys.readouterr().err.lower()


def test_cli_run_exits_4_when_instances_are_not_allowed(monkeypatch, capsys):
    """The documented exit-4 refusal path actually runs: an InstancesNotAllowed from the forced start
    reaches the CLI (ensure_running re-raises it) and exits 4, not 0."""
    from ctf.cli import web_lane as cli
    from ctf.platform.base import InstancesNotAllowed

    class RefusingGate:
        kind = "gamemaster"

        def list_challenges(self):
            from ctf.platform.base import Challenge
            return [Challenge(id=CID, name=CID, category="web")]

        def start_instance(self, cid):
            raise InstancesNotAllowed("instances are not allowed for this event (manual mode)")

    monkeypatch.setattr(cli, "_profile", lambda args: object())
    monkeypatch.setattr(cli, "build_gate", lambda profile: RefusingGate())
    rc = cli.run(_cli_args(["run"]))
    assert rc == 4                       # REFUSED_EXIT, not a silent 0
    assert "not allowed" in capsys.readouterr().err.lower()


# --------------------------------------------------------------------------------------------------
#  round-2 verification fixes
# --------------------------------------------------------------------------------------------------
def test_peer_client_factory_builds_get_only_clients():
    """GET-only on the SIBLING path: a get_only hunter hands its peers a client_factory whose clients
    refuse a POST before the wire (double_spend builds its race-burst clients from that factory). A
    fake peer module POSTs and GETs through the factory; the target must see only the GET."""
    PH = web_fakes.PH
    site = web_fakes.Site({"/": web_fakes.page("Q", "<p>ok</p>")})
    srv, url = web_fakes.serve(site)
    seen = {}

    class Peer:
        @staticmethod
        def solve(target, pctx):
            c = pctx["client_factory"](url)
            try:
                c.post("/", data="x=1")
                seen["post"] = "sent"
            except PH._web.OutOfScope:
                seen["post"] = "refused"
            seen["get"] = c.get("/")["status"]
            return None

    try:
        h = PH._Hunter(url, get_only=True)
        assert h.client is not None
        h.forge_target = {"answer_id": "proof-1", "url": url}
        site.hits.clear()
        h._run_peer(Peer, "test-peer")
    finally:
        srv.shutdown()
        srv.server_close()
    assert seen.get("post") == "refused", seen       # the factory client is get_only
    assert seen.get("get") == 200                    # and still reads
    assert site.hits and {m for _t, m, _raw in site.hits} == {"GET"}


def test_hunter_default_construction_passes_no_get_only_kwarg(monkeypatch):
    """Off by default means the default path builds WebClient(url, timeout=...) exactly as before B-007:
    a substitute client factory without a get_only parameter (as older tests use) must still work. With
    get_only=True the hunter does pass get_only=True."""
    PH = web_fakes.PH
    built = []

    class Legacy:
        def __init__(self, url, timeout=8.0):
            self.application_base = url
            built.append("legacy")

    monkeypatch.setattr(PH._web, "WebClient", Legacy)
    h = PH._Hunter("http://127.0.0.1:9/")
    assert isinstance(h.client, Legacy)              # TypeError on an unconditional get_only= kwarg

    class Modern:
        def __init__(self, url, timeout=8.0, **kw):
            self.application_base = url
            built.append(kw)

    monkeypatch.setattr(PH._web, "WebClient", Modern)
    h2 = PH._Hunter("http://127.0.0.1:9/", get_only=True)
    assert isinstance(h2.client, Modern) and built[-1] == {"get_only": True}


def test_get_only_webclient_refuses_a_websocket_conversation():
    """A WebSocket conversation sends application messages after the upgrade: a get_only client
    refuses it before any connection, so the target records nothing."""
    PH = web_fakes.PH
    site = web_fakes.Site({"/": web_fakes.page("Q", "<p>ok</p>")})
    srv, url = web_fakes.serve(site)
    try:
        wc = PH._web.WebClient(url, get_only=True)
        with pytest.raises(PH._web.OutOfScope):
            wc.websocket_conversation("/ws", ["hello"])
    finally:
        srv.shutdown()
        srv.server_close()
    assert site.hits == []


def test_is_event_proof_fails_closed_without_a_proof_format():
    """An event profile with no [proof] token (CSCTF: CTFd, flag{...} only) banks nothing, even for a
    value proof_hunt.is_proof accepts; a gate with no profile at all is refused loudly."""
    from ctf import event as _event
    proof = web_fakes.uuid_proof("no-proof-format")
    assert web_lane.load_proof_hunt().is_proof(proof)
    no_proof_gate = type("G", (), {"profile": _event.load("csctf")})()
    assert web_lane._is_event_proof(no_proof_gate, proof) is False
    with pytest.raises(web_lane.WebLaneError):
        web_lane._is_event_proof(type("G", (), {})(), proof)


def _solved_row_routes(url):
    att = attempt_body(url)
    return [
        {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"},
         "body": list_body([row(solved=True)])},
        {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
        {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
        {"method": "POST", "url": GM, "body": {"result": "ALREADY_SOLVED"}},
    ]


def test_include_solved_runs_a_solved_row():
    """include_solved is an opt-in to RUN a solved row, not only to list it: the row is forced open and
    read. Without it the same row is skipped with no start."""
    srv, url, proof = serve_backup()
    try:
        gate, s = make_gate(_solved_row_routes(url))
        ch = web_lane.select_web_rows(gate, include_solved=True)[0]
        skipped = web_lane.run_row(gate, ch, practice=True, sleep=lambda _s: None)
        assert skipped.state == web_lane.SKIPPED_SOLVED and start_posts(s) == []
        res = web_lane.run_row(gate, ch, practice=True, include_solved=True, sleep=lambda _s: None)
    finally:
        srv.shutdown()
        srv.server_close()
    assert res.state == web_lane.FOUND and res.proofs == {"proof-1": proof}
    assert len(start_posts(s)) == 1


def test_cli_include_solved_runs_a_solved_row(monkeypatch, capsys):
    """`run --include-solved --dry-run` reads a solved row (a start POST, state found), not skipped."""
    from ctf.cli import web_lane as cli
    srv, url, _proof = serve_backup()
    try:
        gate, s = make_gate(_solved_row_routes(url))
        monkeypatch.setattr(cli, "_profile", lambda args: object())
        monkeypatch.setattr(cli, "build_gate", lambda profile: gate)
        rc = cli.run(_cli_args(["run", "--dry-run", "--include-solved"]))
    finally:
        srv.shutdown()
        srv.server_close()
    out = capsys.readouterr().out
    assert rc == 0 and web_lane.FOUND in out and web_lane.SKIPPED_SOLVED not in out
    assert len(start_posts(s)) == 1 and submit_posts(s) == []


def test_cli_run_exits_4_on_a_manual_mode_event(monkeypatch, capsys, tmp_path):
    """A manual-mode event's SubmitGate has kind 'manual': the lane refuses it as forbidden by the
    event's rules (exit 4), before any start."""
    from ctf.cli import web_lane as cli
    from ctf.platform import NotAllowed
    from ctf.platform.manual import ManualAdapter
    spooky = event.load("spooky")
    gate = SubmitGate(ManualAdapter(spooky, drop_dir=tmp_path), spooky)
    assert gate.kind == "manual"
    with pytest.raises(NotAllowed):
        web_lane.run_lane(gate, rows=[])
    monkeypatch.setattr(cli, "_profile", lambda args: spooky)
    monkeypatch.setattr(cli, "build_gate", lambda profile: gate)
    rc = cli.run(_cli_args(["run"]))
    assert rc == cli.REFUSED_EXIT == 4
    assert "manual" in capsys.readouterr().err.lower()


def _capture_ctx(deadline_iso, deadline_s):
    captured = {}

    class CaptureReader:
        is_proof = staticmethod(web_lane.load_proof_hunt().is_proof)

        @staticmethod
        def solve_targets(targets, ctx):
            captured.update(ctx)
            return {}

    att = dict(attempt_body("http://127.0.0.1:1/"), deadline=deadline_iso)
    gate, _s = make_gate([
        {"method": "GET", "url": GM, "params": {"op": "list", "all": "true"}, "body": list_body([row()])},
        {"method": "GET", "url": GM, "params": {"op": "status", "challenge": CID}, "body": att},
        {"method": "POST", "url": GM, "json": {"challenge": CID}, "body": att},
    ])
    ch = web_lane.select_web_rows(gate)[0]
    import time as _t
    t0 = _t.time()
    web_lane.run_row(gate, ch, proof_hunt=CaptureReader, deadline_s=deadline_s, sleep=lambda _s: None)
    return captured["deadline"], t0


def test_read_budget_is_capped_by_deadline_s_even_when_the_attempt_names_a_later_one():
    """The 60 s bar: an attempt deadline far in the future (2099) must not let one row's read run past
    deadline_s; the reader's deadline is min(attempt deadline, now + deadline_s)."""
    got, t0 = _capture_ctx("2099-01-01T00:00:00Z", 7.0)
    assert t0 + 6.0 <= got <= t0 + 8.0


def test_read_budget_keeps_an_earlier_attempt_deadline():
    """An attempt deadline sooner than now + deadline_s wins (the read never outlives the attempt)."""
    import datetime as _dt
    import time as _t
    soon = _t.time() + 3.0
    iso = _dt.datetime.fromtimestamp(soon, _dt.timezone.utc).isoformat()
    got, _t0 = _capture_ctx(iso, 55.0)
    assert abs(got - soon) < 0.01


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
