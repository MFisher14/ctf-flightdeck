"""B-044: Hall of Fame eligibility check, start-origin classifier and the timed fast submit path.

The end-to-end tests run the real gate, rules, queue, ledger and Game Master adapter against a fake
Game Master this test starts on 127.0.0.1 (a real HTTP server: real Date headers, real elapsed
times). The queue-timing tests use a fake clock, like tests/test_submit_queue.py.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from wsgiref.handlers import format_date_time

import pytest
import requests

from ctf import env, event, ledger
from ctf.platform import (AttemptRef, NotSupported, SubmitGate, SubmitStatus, get_adapter, halloffame as hof,
                          queue, rules)
from ctf.platform.base import SubmitResult
from ctf.platform.policy import batch_flag

T0 = 1_800_000_000.0     # a fixed epoch for the pure classifier tests


def iso(t: float) -> str:
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def http_date(t: float) -> str:
    return format_date_time(t)          # an RFC 7231 HTTP-date, as a Date header carries it


# =============================================================================== eligibility

def test_day8_regular_attempt_on_a_timed_id_is_named():
    start = {"attempt_id": "a1", "run_for_time": False, "hall_of_fame_eligible": False, "deadline": None}
    el = hof.eligibility("warmups-day-08/time_trial", start, {"result": "CORRECT"})
    assert el.timed and el.regular and el.eligible is False
    assert el.unranked_by == ("run_for_time=false", "hall_of_fame_eligible=false")
    assert el.note.startswith(hof.REGULAR_NOTE + ": warmups-day-08/time_trial (run_for_time=false, "
                              "hall_of_fame_eligible=false)")
    assert "posts nothing to the fastest-times board" in el.note


@pytest.mark.parametrize("start,result,eligible,regular", [
    ({"hall_of_fame_eligible": True}, {"hall_of_fame_eligible": False}, False, True),    # the result wins
    ({"hall_of_fame_eligible": False}, {"hall_of_fame_eligible": True}, True, False),
    ({"hall_of_fame_eligible": True, "run_for_time": True}, {}, True, False),
    ({}, {}, None, False),                                    # a legacy route says nothing
    ({"hall_of_fame_eligible": True, "variant_fresh": False}, {}, False, False),   # unranked, not regular
    ({"run_for_time": False}, {}, False, True),
    ({"hall_of_fame_eligible": "false", "run_for_time": 0}, {}, None, False),       # only real booleans count
])
def test_later_bodies_win_and_only_explicit_booleans_count(start, result, eligible, regular):
    el = hof.eligibility("binary-day-03/mastery", start, result)
    assert (el.eligible, el.regular) == (eligible, regular)
    assert (el.note is not None) == regular


def test_a_non_timed_id_has_no_hall_of_fame_and_a_multi_answer_id_counts_as_its_challenge():
    el = hof.eligibility("metadata-day-01", {"hall_of_fame_eligible": False, "run_for_time": False})
    assert not el.timed and el.eligible is None and not el.regular and el.note is None
    el = hof.eligibility("metadata-day-01/mastery#q2", {"hall_of_fame_eligible": False})
    assert el.challenge_id == "metadata-day-01/mastery" and el.timed and el.eligible is False


def test_counts_are_kept_and_booleans_are_not_counts():
    el = hof.eligibility("x/time_trial", {"ranked_attempts_remaining": 3, "unique_attempts_remaining": True},
                         {"ranked_attempts_remaining": 2})
    assert el.counts == {"ranked_attempts_remaining": 2} and el.ranked_left == 2


# =============================================================================== start origin

def test_a_quick_fresh_start_is_ours():
    o = hof.classify_start({"attempt_id": "a1", "started_at": iso(T0 - 0.3)}, date=T0, elapsed_s=0.1)
    assert o.kind == "fresh" and not o.teammate and o.attempt_id == "a1"


def test_a_slow_start_is_not_a_teammate_once_its_round_trip_is_taken_off():
    """Day 19: web starts took 3-11 s. Without the round trip taken off, a 9 s reply reads as a
    teammate's attempt (the Day 1 false sign that cost 77 s)."""
    body = {"attempt_id": "a1", "started_at": iso(T0 - 9.0)}
    assert hof.classify_start(body, date=T0, elapsed_s=9.5).kind == "fresh"
    assert hof.classify_start(body, date=T0, elapsed_s=0.0).kind == "foreign"


def test_skew_tolerance_and_the_exact_boundary():
    body = {"started_at": iso(T0 - 1.5)}
    assert hof.classify_start(body, date=T0).kind == "fresh"                       # 1.5 <= 0 + 1 + 1
    assert hof.classify_start(body, date=T0, skew_tolerance_s=0.0).kind == "foreign"   # 1.5 > 1
    at = {"started_at": iso(T0 - 2.0)}
    assert hof.classify_start(at, date=T0).kind == "fresh"                         # exactly at the limit
    past = {"started_at": iso(T0 - 2.001)}
    assert hof.classify_start(past, date=T0).kind == "foreign"
    assert hof.classify_start(past, date=T0, resumed_after_s=1.01).kind == "fresh"


def test_a_teammate_attempt_and_our_own_rejoin():
    body = {"attempt_id": "att-9", "started_at": iso(T0 - 30)}
    o = hof.classify_start(body, date=http_date(T0), elapsed_s=0.2)
    assert o.kind == "foreign" and o.teammate and o.late_s == pytest.approx(30.0, abs=0.01)
    o = hof.classify_start(body, date=http_date(T0), elapsed_s=0.2, own_attempt_ids={"att-9"})
    assert o.kind == "own" and not o.teammate


@pytest.mark.parametrize("body,date", [
    ({"attempt_id": "a"}, T0),                                   # no started_at
    ({"started_at": "yesterday"}, T0),
    ({"started_at": "2026-10-08T13:00:00"}, T0),                # no time zone
    ({"started_at": iso(T0 - 60)}, None),                       # no Date header
    ({"started_at": iso(T0 - 60)}, "not a date"),
    ("not an object", T0),
])
def test_an_unreadable_reply_is_unknown_never_a_teammate(body, date):
    o = hof.classify_start(body, date=date, elapsed_s=0.0)
    assert o.kind == "unknown" and not o.teammate and o.reason


@pytest.mark.parametrize("kw", [{"elapsed_s": -0.1}, {"elapsed_s": float("nan")}, {"skew_tolerance_s": -1},
                                {"resumed_after_s": True}])
def test_bad_tolerances_fail_loudly(kw):
    with pytest.raises(ValueError):
        hof.classify_start({"started_at": iso(T0)}, date=T0, **kw)


def test_http_date_and_iso_date_agree():
    body = {"started_at": iso(T0 - 5)}
    a = hof.classify_start(body, date=http_date(T0))
    b = hof.classify_start(body, date=iso(T0))
    assert a.late_s == b.late_s == pytest.approx(5.0, abs=0.001)


# =============================================================================== fake Game Master

class FakeGM:
    """A Game Master on 127.0.0.1: POST {"challenge", "answers"} is judged from `key`; POST
    {"challenge"} alone is a start that takes `start_delay` seconds and stamps started_at when the
    request arrived. Every POST body is kept in `posts`."""

    def __init__(self):
        self.posts: list[dict] = []
        self.key: dict[str, dict[str, str]] = {}
        self.banked: dict[str, set] = {}     # answer ids banked per challenge (judged right earlier)
        self.extra: dict = {}               # fields added to every submit reply
        self.start_delay = 0.0
        gm = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                arrived = time.time()
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                gm.posts.append(body)
                if "answers" not in body:
                    time.sleep(gm.start_delay)
                    reply = {"attempt_id": "att-live", "started_at": iso(arrived),
                             "answer_ids": ["q1"], "deadline": iso(arrived + 30)}
                else:
                    want = gm.key.get(body["challenge"], {})
                    if all(want.get(k) == v for k, v in body["answers"].items()):
                        banked = gm.banked.setdefault(body["challenge"], set())
                        banked |= set(body["answers"])
                        left = len(set(want) - banked)
                        reply = ({"result": "accepted", "remaining": left} if left else
                                 {"result": "CORRECT", "flag": "flag{" + "0" * 32 + "}"})
                    else:
                        reply = {"result": "incorrect"}
                    reply.update(gm.extra)
                data = json.dumps(reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def answer_posts(self):
        return [p for p in self.posts if "answers" in p]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def fake_gm():
    gm = FakeGM()
    yield gm
    gm.close()


@pytest.fixture
def work(tmp_path, monkeypatch):
    w = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    for name in ("CTF_PLATFORM_URL", *env.legacy_names("CTF_PLATFORM_URL"), "CTF_TOKEN",
                 *env.legacy_names("CTF_TOKEN")):
        monkeypatch.delenv(name, raising=False)
    return w


def huntress_at(tmp_path: Path, url: str, extra: str = "") -> event.EventProfile:
    src = event.load("huntress").path.read_text()
    src = src.replace('base_url = "https://gamemaster.huntress.example"', f'base_url = "{url}"')
    assert url in src
    (tmp_path / "profiles" / "huntress").mkdir(parents=True)
    (tmp_path / "profiles" / "huntress" / "event.toml").write_text(src + extra)
    return event.load("huntress", root=tmp_path / "profiles")


FAST = "\n[submit]\nper_minute = 100\ninterval_s = 0.0\nper_challenge_interval_s = 0.0\nmax_hold_s = 30.0\n"


def start_body(*, aid="att-1", ids=("q1", "q2", "q3"), late=0.2, now=None, deadline_in=30.0, **pool):
    now = time.time() if now is None else now
    return {"attempt_id": aid, "started_at": iso(now - late), "answer_ids": list(ids),
            "deadline": iso(now + deadline_in) if deadline_in is not None else None, **pool}


def records(work, kind):
    return [r for r in ledger.read(work) if r["event"] == kind]


# =============================================================================== the fast path

def test_a_timed_attempt_sends_every_answer_in_one_request(tmp_path, work, fake_gm):
    cid = "metadata-day-09/mastery"
    fake_gm.key[cid] = {"q1": "Alice", "q2": "Bob", "q3": "Carol"}
    fake_gm.extra = {"hall_of_fame_eligible": True, "ranked_attempts_remaining": 4}
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    att = hof.TimedAttempt.from_reply(gate, cid, start_body(hall_of_fame_eligible=True, run_for_time=True),
                                      date=time.time(), elapsed_s=0.1)
    assert att.origin.kind == "fresh" and att.eligibility.eligible is True
    res = att.submit({"q1": "Alice", "q2": "Bob", "q3": "Carol"}, provenance="exif authors")
    assert res.result.status is SubmitStatus.CORRECT and res.eligibility.eligible is True and res.note is None
    assert fake_gm.answer_posts() == [{"challenge": cid, "answers": {"q1": "Alice", "q2": "Bob", "q3": "Carol"}}]
    (sub,) = records(work, "platform.submit")
    assert sub["challenge_id"] == cid and sub["answers"] == 3 and sub["attempt_id"] == "att-1"
    assert sub["flag"] == batch_flag({"q1": "Alice", "q2": "Bob", "q3": "Carol"}) and "partial" not in sub
    (st,) = records(work, "hof.start")
    assert st["origin"] == "fresh" and st["attempt_id"] == "att-1" and st["eligible"] is True
    (rs,) = records(work, "hof.result")
    assert rs["status"] == "correct" and rs["eligible"] is True and rs["counts"] == {"ranked_attempts_remaining": 4}
    assert hof.known_ranked_left(gate.profile, cid) == 4
    assert "flag" not in res.result.reply and res.result.reply["result"] == "CORRECT"


def test_a_regular_timed_result_is_recorded_and_said(tmp_path, work, fake_gm, capsys):
    """Day 8: the result body says run_for_time false: it scores, a NOTE says it, the ledger keeps it."""
    cid = "warmups-day-08/time_trial"
    fake_gm.key[cid] = {"q1": "slug"}
    fake_gm.extra = {"run_for_time": False, "hall_of_fame_eligible": False}
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    att = hof.TimedAttempt.from_reply(gate, cid, start_body(ids=("q1",)), date=time.time())
    res = att.submit({"q1": "slug"}, provenance="html entities")
    assert res.result.accepted and res.eligibility.regular and res.note.startswith(hof.REGULAR_NOTE)
    assert f"NOTE {hof.REGULAR_NOTE}: {cid}" in capsys.readouterr().err
    (rs,) = records(work, "hof.result")
    assert rs["regular"] is True and rs["eligible"] is False and rs["note"].startswith(hof.REGULAR_NOTE)
    warns = [r["warn"] for r in hof.report(gate.profile) if r["warn"]]
    assert warns and warns[0].startswith(hof.REGULAR_NOTE)


def test_a_regular_start_is_said_when_the_result_reply_is_silent(tmp_path, work, fake_gm, capsys):
    """Day 8, the unverified-live case: only the START reply says run_for_time / hall_of_fame_eligible
    false (and deadline null); the submit reply carries no pool field. The observer must merge the
    start pool, so the result is still recorded as regular and the NOTE is still printed."""
    cid = "warmups-day-08/mastery"
    fake_gm.key[cid] = {"q1": "slug"}
    assert fake_gm.extra == {}                              # the result reply says nothing
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    att = hof.TimedAttempt.from_reply(gate, cid, start_body(ids=("q1",), deadline_in=None, run_for_time=False,
                                                            hall_of_fame_eligible=False), date=time.time())
    assert att.deadline is None
    res = att.submit({"q1": "slug"}, provenance="p")
    assert res.result.accepted and "run_for_time" not in res.result.reply
    (rs,) = records(work, "hof.result")
    assert rs["regular"] is True and rs["eligible"] is False
    assert rs["pool"] == {"run_for_time": False, "hall_of_fame_eligible": False}
    assert f"NOTE {hof.REGULAR_NOTE}: {cid} (run_for_time=false, hall_of_fame_eligible=false)" in capsys.readouterr().err


def test_a_single_answer_submit_on_a_timed_id_is_checked_too(tmp_path, work, fake_gm, capsys):
    fake_gm.key["w-day-02/time_trial"] = {"q1": "x"}
    fake_gm.key["w-day-02"] = {"q1": "x"}
    fake_gm.extra = {"hall_of_fame_eligible": False}
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    res = gate.submit("w-day-02/time_trial#q1", "x", provenance="p", allow_nonstandard=True)
    assert res.accepted
    (rs,) = records(work, "hof.result")
    assert rs["challenge_id"] == "w-day-02/time_trial" and rs["regular"] is True and rs["attempt_id"] is None
    assert "NOTE" in capsys.readouterr().err
    gate.submit("w-day-02#q1", "x", provenance="p", allow_nonstandard=True)     # an untimed id
    assert len(records(work, "hof.result")) == 1


def test_a_teammates_attempt_gets_nothing_without_the_player(tmp_path, work, fake_gm):
    cid = "binary-day-05/time_trial"
    fake_gm.key[cid] = {"q1": "v"}
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    att = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-t", ids=("q1",), late=40.0),
                                      date=time.time(), elapsed_s=0.3)
    assert att.origin.teammate
    res = att.submit({"q1": "v"}, provenance="p")
    assert res.result.status is SubmitStatus.NOT_ALLOWED and not res.result.sent
    assert res.result.message.startswith(hof.TEAMMATE) and fake_gm.answer_posts() == []
    res = att.submit({"q1": "v"}, provenance="p", confirmed=True)
    assert res.result.accepted and len(fake_gm.answer_posts()) == 1
    assert [r["warn"] for r in hof.report(gate.profile) if r["event"] == "hof.start"][0].startswith(
        "start read as a teammate")


def test_our_own_recorded_start_is_never_a_teammate_on_rejoin(tmp_path, work, fake_gm):
    cid = "script-day-07/mastery"
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    first = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-own"), date=time.time())
    assert first.origin.kind == "fresh"
    again = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-own", late=50.0), date=time.time())
    assert again.origin.kind == "own"
    other = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-other", late=50.0), date=time.time())
    assert other.origin.kind == "foreign"
    assert hof.own_attempt_ids(gate.profile, cid) == {"att-own"}


def test_a_real_slow_start_reply_reads_as_ours(tmp_path, work, fake_gm):
    """A real HTTP reply 2.5 s slow: its Date trails started_at by the round trip. Classified with
    the round trip it is fresh; the same reply read without it is the false teammate sign."""
    fake_gm.start_delay = 2.5
    with requests.Session() as s:
        s.trust_env = False                     # no proxy between the test and its own loopback server
        resp = s.post(fake_gm.url + "/", json={"challenge": "web-day-20/time_trial"}, timeout=10)
    body, origin = hof.classify_response(resp)
    assert origin.kind == "fresh", origin.reason
    assert origin.elapsed_s >= 2.4
    naive = hof.classify_start(body, date=resp.headers["Date"], elapsed_s=0.0, skew_tolerance_s=0.0)
    assert naive.kind == "foreign"


def test_unsure_answers_hold_the_whole_batch(tmp_path, work, fake_gm):
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    att = hof.TimedAttempt.from_reply(gate, "m-day-01/mastery", start_body(ids=("q1", "q2")), date=time.time())
    res = att.submit({"q1": "sure", "q2": "??maybe"}, provenance="p")
    assert res.result.status is SubmitStatus.NOT_ALLOWED and not res.result.sent and "q2" in res.result.message
    assert fake_gm.answer_posts() == []


def test_answer_ids_the_attempt_does_not_list_are_refused_before_sending(tmp_path, work, fake_gm):
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    att = hof.TimedAttempt.from_reply(gate, "m-day-01/mastery", start_body(ids=("q1",)), date=time.time())
    with pytest.raises(ValueError, match="q9"):
        att.submit({"q1": "a", "q9": "b"}, provenance="p")
    assert fake_gm.posts == []


def test_a_partly_banked_batch_does_not_close_the_challenge(tmp_path, work, fake_gm):
    cid = "mobile-day-04/mastery"
    fake_gm.key[cid] = {"q1": "a", "q2": "b", "q3": "c"}
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url, FAST))
    att = hof.TimedAttempt.from_reply(gate, cid, start_body(), date=time.time())
    first = att.submit({"q1": "a", "q2": "b"}, provenance="p")
    assert first.result.status is SubmitStatus.CORRECT and "remaining" in first.result.message
    assert records(work, "platform.submit")[0]["partial"] is True
    rest = att.submit({"q3": "c"}, provenance="p")
    assert rest.result.sent and rest.result.message.startswith("CORRECT")
    after = att.submit({"q3": "c", "q1": "a"}, provenance="p")
    assert not after.result.sent and after.result.message.startswith(queue.SOLVED)


def test_ranked_retry_of_a_solved_id_is_sent_only_when_eligible(tmp_path, work, fake_gm):
    cid = "metadata-day-03/time_trial"
    fake_gm.key[cid] = {"q1": "v"}
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url, FAST))
    first = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-1", ids=("q1",)), date=time.time())
    assert first.submit({"q1": "v"}, provenance="p").result.accepted
    # a plain second attempt on the solved id: dedupe says solved
    again = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-2", ids=("q1",)), date=time.time())
    r = again.submit({"q1": "v"}, provenance="p").result
    assert not r.sent and r.message.startswith(queue.SOLVED)
    # a ranked retry the server calls eligible: its own attempt's records only, so it goes out
    ranked = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-3", ids=("q1",), hall_of_fame_eligible=True),
                                         date=time.time(), ranked_retry=True)
    assert ranked.submit({"q1": "v"}, provenance="p").result.accepted
    # a ranked retry the server calls not eligible: nothing is submitted
    unranked = hof.TimedAttempt.from_reply(gate, cid, start_body(aid="att-4", ids=("q1",), variant_fresh=False),
                                           date=time.time(), ranked_retry=True)
    r = unranked.submit({"q1": "v"}, provenance="p").result
    assert not r.sent and r.message.startswith(hof.NOT_ELIGIBLE) and "variant_fresh=false" in r.message
    assert len(fake_gm.answer_posts()) == 2
    sub = records(work, "platform.submit")
    assert [s.get("ranked_retry") for s in sub] == [None, True]


def test_a_ranked_retry_without_an_attempt_id_is_refused(tmp_path, work, fake_gm):
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    body = start_body(ids=("q1",))
    del body["attempt_id"]
    att = hof.TimedAttempt.from_reply(gate, "x-day-01/time_trial", body, date=time.time(), ranked_retry=True)
    r = att.submit({"q1": "v"}, provenance="p").result
    assert not r.sent and r.message.startswith(queue.DUPLICATE) and fake_gm.posts == []


def test_an_attempt_past_its_deadline_sends_nothing_and_spools_nothing(tmp_path, work, fake_gm):
    gate = get_adapter(huntress_at(tmp_path, fake_gm.url))
    att = hof.TimedAttempt.from_reply(gate, "x-day-01/time_trial", start_body(ids=("q1",), deadline_in=0.1),
                                      date=time.time())
    r = att.submit({"q1": "v"}, provenance="p").result
    assert r.status is SubmitStatus.NOT_ALLOWED and not r.sent and r.message.startswith(queue.EXPIRED)
    assert fake_gm.posts == [] and records(work, "platform.submit") == []
    assert not list(work.glob("submitq/pending/*.json"))


# =============================================================================== gate and queue

class Clock:
    def __init__(self, t: float = T0):
        self.t = t
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(round(s, 6))
        self.t += s


class BatchAdapter:
    kind = "gamemaster"

    def __init__(self, *answers):
        self.answers = list(answers)
        self.batches: list[tuple[str, dict]] = []

    def submit(self, cid, flag):
        raise AssertionError("a batch must not go out answer by answer")

    def submit_answers(self, cid, answers):
        self.batches.append((cid, dict(answers)))
        a = self.answers.pop(0) if self.answers else SubmitStatus.INCORRECT
        if isinstance(a, Exception):
            raise a
        return a if isinstance(a, SubmitResult) else SubmitResult(a)

    def list_challenges(self): return []
    def get_challenge(self, cid): raise NotImplementedError
    def download_files(self, cid, dest): return []
    def team_solves(self): return []
    def scoreboard(self): return []


def queued_gate(profile, adapter, work, clock):
    g = SubmitGate(adapter, profile)
    rules.install(g, work)
    hof.install(g, work)
    queue.install(g, work, clock=clock, sleep=clock.sleep)
    return g


def huntress(**submit):
    p = event.load("huntress")
    if submit:
        p = dataclasses.replace(p, submit=dataclasses.replace(p.submit, **submit))
    return p


def test_a_timed_batch_skips_the_per_challenge_spacing_and_an_untimed_one_does_not(work):
    clock = Clock()
    a = BatchAdapter()
    g = queued_gate(huntress(interval_s=1.0, per_challenge_interval_s=3.0), a, work, clock)
    timed = AttemptRef("att-1", deadline=clock.t + 30)
    g.submit_answers("c/mastery", {"q1": "a"}, provenance="p", attempt=timed, allow_nonstandard=True)
    g.submit_answers("c/mastery", {"q1": "b"}, provenance="p", attempt=timed, allow_nonstandard=True)
    assert clock.slept == [1.0], "a timed batch waits only for the team spacing"
    g.submit_answers("u-day-01", {"q1": "a"}, provenance="p", allow_nonstandard=True)
    clock.slept.clear()
    g.submit_answers("u-day-01", {"q1": "b"}, provenance="p", allow_nonstandard=True)
    assert clock.slept == [3.0], "an untimed batch keeps the per-challenge spacing"
    assert [b for _, b in a.batches] == [{"q1": "a"}, {"q1": "b"}, {"q1": "a"}, {"q1": "b"}]


def test_an_attempt_with_a_deadline_is_timed_even_on_an_unsuffixed_id(work):
    """A batch whose AttemptRef has a deadline is a timed result (a hof.result record) whatever its
    id; the same id without a deadline is not."""
    clock = Clock()
    a = BatchAdapter(SubmitResult(SubmitStatus.CORRECT, reply={"hall_of_fame_eligible": True}),
                     SubmitStatus.CORRECT)
    g = queued_gate(huntress(interval_s=0.0, per_challenge_interval_s=0.0), a, work, clock)
    g.submit_answers("u-day-05", {"q1": "a"}, provenance="p", allow_nonstandard=True,
                     attempt=AttemptRef("att-d", deadline=clock.t + 30))
    (rs,) = records(work, "hof.result")
    assert rs["challenge_id"] == "u-day-05" and rs["attempt_id"] == "att-d" and rs["eligible"] is True
    g.submit_answers("u-day-06", {"q1": "a"}, provenance="p", allow_nonstandard=True, attempt=AttemptRef("att-e"))
    assert len(records(work, "hof.result")) == 1 and len(a.batches) == 2


@pytest.mark.parametrize("ref,why", [
    (AttemptRef("att-r1", ranked_retry=True, eligible=None, pool=(("run_for_time", False),)), "run_for_time=false"),
    (AttemptRef("att-r2", ranked_retry=True, eligible=False, pool=()), "eligible=false"),
])
def test_a_ranked_retry_is_refused_on_either_sign_of_not_eligible(work, ref, why):
    """The check reads both the AttemptRef's own eligible and its pool: each alone refuses."""
    clock = Clock()
    a = BatchAdapter(SubmitStatus.CORRECT)
    g = queued_gate(huntress(interval_s=0.0, per_challenge_interval_s=0.0), a, work, clock)
    r = g.submit_answers("r-day-01/time_trial", {"q1": "v"}, provenance="p", allow_nonstandard=True, attempt=ref)
    assert not r.sent and r.message.startswith(hof.NOT_ELIGIBLE) and why in r.message and a.batches == []
    ok = AttemptRef("att-r3", ranked_retry=True, eligible=None, pool=())     # nothing said: it goes out
    assert g.submit_answers("r-day-01/time_trial", {"q1": "v"}, provenance="p", allow_nonstandard=True,
                            attempt=ok).accepted and len(a.batches) == 1


def test_a_ranked_retry_with_no_ranked_attempt_left_is_refused(work):
    clock = Clock()
    a = BatchAdapter(SubmitResult(SubmitStatus.CORRECT, reply={"ranked_attempts_remaining": 0}),
                     SubmitStatus.CORRECT, SubmitStatus.CORRECT)
    g = queued_gate(huntress(interval_s=0.0, per_challenge_interval_s=0.0), a, work, clock)
    cid = "n-day-01/time_trial"
    assert g.submit_answers(cid, {"q1": "v"}, provenance="p", allow_nonstandard=True,
                            attempt=AttemptRef("att-1", deadline=clock.t + 30)).accepted
    assert hof.known_ranked_left(g.profile, cid, workdir=work) == 0
    r = g.submit_answers(cid, {"q1": "v"}, provenance="p", allow_nonstandard=True,
                         attempt=AttemptRef("att-2", ranked_retry=True))
    assert not r.sent and r.message.startswith(hof.NO_RANKED_LEFT) and len(a.batches) == 1
    # the retry's own reply saying hall_of_fame_eligible true wins over an older 0
    ranked = AttemptRef("att-3", ranked_retry=True, eligible=True, pool=(("hall_of_fame_eligible", True),))
    assert g.submit_answers(cid, {"q1": "v"}, provenance="p", allow_nonstandard=True, attempt=ranked).accepted
    # an attempt's own start reply saying 0 (its count after taking this retry) does not block it
    cid2 = "n-day-02/time_trial"
    hof.record_start(g.profile, cid2, {"attempt_id": "att-9", "ranked_attempts_remaining": 0},
                     hof.StartOrigin("fresh", "att-9"), workdir=work)
    assert hof.known_ranked_left(g.profile, cid2, workdir=work) == 0
    assert hof.known_ranked_left(g.profile, cid2, workdir=work, exclude_attempt="att-9") is None
    assert g.submit_answers(cid2, {"q1": "v"}, provenance="p", allow_nonstandard=True,
                            attempt=AttemptRef("att-9", ranked_retry=True)).accepted
    assert len(a.batches) == 3


@pytest.mark.parametrize("cid,ref", [
    ("c/time_trial", AttemptRef("att-1")),                               # a timed id, deadline null
    ("u-day-07", AttemptRef("att-2", ranked_retry=True)),               # a ranked retry, deadline null
])
def test_a_timed_attempt_without_a_deadline_is_never_spooled_nor_spaced(work, cid, ref):
    """Day 8 replies carried deadline null: such a batch still skips the per-challenge spacing and
    is never spooled (drain would resend it against a dead attempt)."""
    from ctf.platform.base import PlatformError
    clock = Clock()
    a = BatchAdapter(SubmitStatus.INCORRECT, PlatformError("boom"), SubmitStatus.RATE_LIMITED)
    g = queued_gate(huntress(interval_s=1.0, per_challenge_interval_s=3.0, max_hold_s=10.0), a, work, clock)
    g.submit_answers(cid, {"q1": "a"}, provenance="p", allow_nonstandard=True, attempt=ref)
    with pytest.raises(PlatformError):
        g.submit_answers(cid, {"q1": "b"}, provenance="p", allow_nonstandard=True, attempt=ref)
    assert clock.slept == [1.0], "no per-challenge spacing, only the team spacing"
    assert g.queue.pending() == [] and records(work, "submit.done")[-1]["queued"] is False
    r = g.submit_answers(cid, {"q1": "c"}, provenance="p", allow_nonstandard=True, attempt=ref)
    assert r.status is SubmitStatus.RATE_LIMITED and "dropped, not queued" in r.message
    assert g.queue.pending() == [] and records(work, "submit.done")[-1]["queued"] is False


def test_a_timed_batch_is_held_only_until_its_deadline_and_never_spooled(work):
    clock = Clock()
    a = BatchAdapter(SubmitStatus.RATE_LIMITED)
    g = queued_gate(huntress(interval_s=0.0, per_challenge_interval_s=0.0, max_hold_s=600.0), a, work, clock)
    t0 = clock.t
    r = g.submit_answers("c/time_trial", {"q1": "a"}, provenance="p", allow_nonstandard=True,
                         attempt=AttemptRef("att-1", deadline=clock.t + 5.0))
    assert r.status is SubmitStatus.RATE_LIMITED and "deadline" in r.message and "drain" not in r.message
    assert clock.t - t0 <= 5.0 - queue.DEADLINE_MARGIN_S + 1e-6
    assert len(a.batches) == 1
    assert not list((work / "submitq" / "pending").glob("*.json"))
    (done,) = records(work, "submit.done")
    assert done["queued"] is False


def test_an_untimed_batch_is_spooled_and_drain_resends_it_whole(work):
    clock = Clock()
    from ctf.platform.base import PlatformError
    a = BatchAdapter(PlatformError("submit_answers: POST failed (Timeout)"), SubmitStatus.CORRECT)
    g = queued_gate(huntress(interval_s=0.0, per_challenge_interval_s=0.0), a, work, clock)
    with pytest.raises(PlatformError):
        g.submit_answers("u-day-02", {"q1": "a", "q2": "b"}, provenance="p", allow_nonstandard=True,
                         attempt=AttemptRef("att-5"))
    (spooled,) = g.queue.pending()
    assert spooled["answers"] == [["q1", "a"], ["q2", "b"]] and spooled["attempt"]["attempt_id"] == "att-5"
    ((rec, res),) = g.queue.drain(g)
    assert res.status is SubmitStatus.CORRECT
    assert a.batches == [("u-day-02", {"q1": "a", "q2": "b"})] * 2
    assert records(work, "platform.submit")[-1]["attempt_id"] == "att-5"


def test_a_timed_batch_whose_send_raises_is_not_kept(work):
    clock = Clock()
    from ctf.platform.base import PlatformError
    a = BatchAdapter(PlatformError("boom"))
    g = queued_gate(huntress(interval_s=0.0, per_challenge_interval_s=0.0), a, work, clock)
    with pytest.raises(PlatformError):
        g.submit_answers("c/mastery", {"q1": "a"}, provenance="p", allow_nonstandard=True,
                         attempt=AttemptRef("att-1", deadline=clock.t + 30))
    assert g.queue.pending() == []
    assert records(work, "submit.done")[-1]["queued"] is False


def test_the_format_check_applies_to_every_value_of_a_batch(work):
    clock = Clock()
    a = BatchAdapter(SubmitStatus.CORRECT)
    g = queued_gate(huntress(), a, work, clock)
    good = "flag{" + "a" * 32 + "}"
    r = g.submit_answers("u-day-03", {"q1": good, "q2": "Alice"}, provenance="p")
    assert not r.sent and "flag format" in r.message and a.batches == []
    r = g.submit_answers("u-day-03", {"q1": good, "q2": "flag{" + "b" * 32 + "}"}, provenance="p")
    assert r.accepted and len(a.batches) == 1


def test_manual_mode_events_refuse_the_batch_before_anything(work):
    a = BatchAdapter(SubmitStatus.CORRECT)
    p = huntress()
    manual = dataclasses.replace(p, rules=dataclasses.replace(p.rules, submit_mode="manual"))
    g = queued_gate(manual, a, work, Clock())
    r = g.submit_answers("x/time_trial", {"q1": "v"}, provenance="p", allow_nonstandard=True)
    assert r.status is SubmitStatus.NOT_ALLOWED and not r.sent and "manual" in r.message and a.batches == []
    spooky = get_adapter(event.load("spooky"))          # ai_on_platform forbidden: the manual adapter
    r = spooky.submit_answers("1", {"q1": "v"}, provenance="p", allow_nonstandard=True)
    assert r.status is SubmitStatus.NOT_ALLOWED and not r.sent and "manual" in r.message
    # automation forbidden on a Game Master event, submit_mode still auto: get_adapter picks manual mode
    forbidden = dataclasses.replace(p, rules=dataclasses.replace(p.rules, ai_on_platform="forbidden"))
    g = get_adapter(forbidden)
    assert g.kind == "manual"
    r = g.submit_answers("x/time_trial", {"q1": "v"}, provenance="p", allow_nonstandard=True)
    assert r.status is SubmitStatus.NOT_ALLOWED and not r.sent and "manual mode" in r.message
    assert not (work / "submitq").exists()


def test_an_adapter_without_a_batch_call_says_so():
    class OneByOne(BatchAdapter):
        kind = "ctfd"
        submit_answers = None
    with pytest.raises(NotSupported, match="submit_answers"):
        SubmitGate(OneByOne(), huntress()).submit_answers("1", {"q": "v"}, provenance="p", allow_nonstandard=True)


def test_a_wrong_batch_counts_once_toward_the_stop(work):
    clock = Clock()
    a = BatchAdapter()
    g = queued_gate(huntress(interval_s=0.0, per_challenge_interval_s=0.0), a, work, clock)
    for v in ("a", "b", "c"):
        assert g.submit_answers("u-day-04", {"q1": v, "q2": "z"}, provenance="p",
                                allow_nonstandard=True).status is SubmitStatus.INCORRECT
    r = g.submit_answers("u-day-04", {"q1": "d", "q2": "z"}, provenance="p", allow_nonstandard=True)
    assert not r.sent and r.message.startswith("wrong_answer_stop: 3 wrong")


# =============================================================================== CLI

def run_cli(argv):
    from ctf import cli
    return cli.main(argv)


def test_cli_check_reads_saved_bodies(tmp_path, capsys):
    s = tmp_path / "start.json"
    s.write_text(json.dumps({"hall_of_fame_eligible": True, "ranked_attempts_remaining": 2}))
    r = tmp_path / "result.json"
    r.write_text(json.dumps({"result": "CORRECT", "run_for_time": False}))
    assert run_cli(["hof", "check", str(s), "--id", "b-day-01/mastery"]) == 0
    assert "eligible: the server said hall_of_fame_eligible true" in capsys.readouterr().out
    assert run_cli(["hof", "check", str(s), str(r), "--id", "b-day-01/mastery"]) == 1
    out = capsys.readouterr().out
    assert "NOT ranked" in out and f"NOTE {hof.REGULAR_NOTE}" in out
    e = tmp_path / "empty.json"
    e.write_text("{}")
    assert run_cli(["hof", "check", str(e), "--id", "b-day-01/mastery"]) == 3
    bad = tmp_path / "bad.json"
    bad.write_text("[1]")
    assert run_cli(["hof", "check", str(bad), "--id", "x/mastery"]) == 2


def test_cli_classify_and_report(tmp_path, work, capsys, monkeypatch):
    monkeypatch.setenv("CTF_EVENT", "huntress")
    f = tmp_path / "start.json"
    f.write_text(json.dumps({"attempt_id": "att-r", "started_at": iso(T0 - 6.0)}))
    assert run_cli(["hof", "classify", str(f), "--date", http_date(T0), "--elapsed", "5.5"]) == 0
    assert capsys.readouterr().out.startswith("fresh: attempt att-r")
    assert run_cli(["hof", "classify", str(f), "--date", http_date(T0)]) == 1
    assert run_cli(["hof", "classify", str(f), "--date", http_date(T0), "--own", "att-r"]) == 0
    prof = event.load("huntress")
    hof.record_start(prof, "w-day-01/time_trial", {"attempt_id": "att-r"},
                     hof.StartOrigin("fresh", "att-r", 0.1, 0.1, "test"))
    capsys.readouterr()
    assert run_cli(["hof", "classify", str(f), "--date", http_date(T0), "--id", "w-day-01/time_trial"]) == 0
    assert capsys.readouterr().out.startswith("own:")
    assert run_cli(["hof", "classify", str(f), "--date", "garbage"]) == 3
    assert run_cli(["hof", "report", "--strict"]) == 0
    hof.record_start(prof, "w-day-02/time_trial", {"attempt_id": "x", "run_for_time": False},
                     hof.StartOrigin("fresh", "x", 0.1, 0.1, "test"))
    capsys.readouterr()
    assert run_cli(["hof", "report"]) == 0
    out = capsys.readouterr().out
    assert f"WARN {hof.REGULAR_NOTE}" in out and "2 record(s), 1 WARN" in out
    assert run_cli(["hof", "report", "--strict"]) == 1
