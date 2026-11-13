"""B-231: no-model timed-start routing. A refused timed start reads op=openapi once, retries once with
the body it lists (run_for_time:true) through latency.StartGuard, checks the pool fields with
halloffame, and remembers the body for every other lane of the event.

The live tests run against a fake Game Master this file starts on 127.0.0.1 whose timed route refuses
the default body ({"challenge": id}) with training_rotation_invalid, as on Huntress Day 8. Nothing
here leaves the machine.
"""
from __future__ import annotations

import copy
import datetime as dt
import io
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from ctf import env, event, ledger, paths
from ctf.platform import NotAllowed, get_adapter, latency, timedstart, wire
from ctf.platform.base import InstanceInfo

TT = "mobile-day-08/time_trial"
MA = "metadata-day-08/mastery"
BASE = "mobile-day-08"


def post_schema(**extra_props):
    props = {"challenge": {"type": "string"},
             "op": {"type": "string", "enum": ["retry", "practice"]},
             "answers": {"type": "object"},
             "run_for_time": {"type": "boolean", "description": "true asks for the timed attempt"}}
    props.update(extra_props)
    return {"type": "object", "required": ["challenge"], "properties": props}


def openapi_doc(schema=None):
    return {"openapi": "3.0.0", "paths": {"/": {
        "get": {"parameters": [{"name": "op", "in": "query"}]},
        "post": {"requestBody": {"content": {"application/json": {"schema": schema or post_schema()}}}}}}}


class FakeGM:
    """A fake Game Master. Timed route behaviour:
    needs        the start body must hold these items, else HTTP `refuse_status` `refuse_word`
    refuse_all   every start is refused with this word (409), whatever the body
    pool         pool fields the attempt reply carries
    openapi      the op=openapi document (None: HTTP 500 openapi_unavailable)
    ok_status    the HTTP status of a start that created an attempt (default 200)
    """

    def __init__(self, needs=None, refuse_word="training_rotation_invalid", refuse_status=409,
                 refuse_all=None, pool=None, openapi="default", listed=(TT, MA), ok_status=200):
        self.needs = {"run_for_time": True} if needs is None else needs
        self.refuse_word, self.refuse_status, self.refuse_all = refuse_word, refuse_status, refuse_all
        self.pool = {"run_for_time": True, "hall_of_fame_eligible": True} if pool is None else pool
        self.openapi = openapi_doc() if openapi == "default" else openapi
        self.listed = list(listed)
        self.ok_status = ok_status
        self.started: set[str] = set()
        self.posts: list[dict] = []
        self.gets: list[str] = []
        self.lock = threading.Lock()
        fake = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _reply(self, code, body, extra=None):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
                op, cid = q.get("op"), q.get("challenge")
                with fake.lock:
                    fake.gets.append(op)
                if op == "list":
                    return self._reply(200, {"challenges": [{"id": c, "name": c, "lane": "mobile", "day": 8}
                                                            for c in fake.listed]})
                if op == "openapi":
                    if fake.openapi is None:
                        return self._reply(500, {"error": "openapi_unavailable"})
                    return self._reply(200, fake.openapi)
                if op == "status":
                    if cid in fake.started:
                        return self._reply(200, fake.attempt(cid))
                    return self._reply(409, {"error": "start_required"})
                return self._reply(400, {"error": "invalid_request"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                cid = body.get("challenge")
                with fake.lock:
                    fake.posts.append(body)
                if fake.refuse_all == "rate_limited":
                    return self._reply(429, {"error": "rate_limited"}, {"Retry-After": "7"})
                if fake.refuse_all:
                    return self._reply(409, {"error": fake.refuse_all})
                if any(body.get(k) != v for k, v in fake.needs.items()):
                    return self._reply(fake.refuse_status, {"error": fake.refuse_word})
                with fake.lock:
                    fake.started.add(cid)
                return self._reply(fake.ok_status, fake.attempt(cid))

        class S(ThreadingHTTPServer):
            daemon_threads = True

        self.server = S(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def attempt(self, cid):
        now = dt.datetime.now(dt.timezone.utc)
        return {"attempt_id": f"att-{cid}", "challenge": cid, "questions": [{"id": "q1"}],
                "started_at": now.isoformat().replace("+00:00", "Z"),
                "deadline": (now + dt.timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
                **self.pool}

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def gm():
    servers = []

    def make(**kw):
        s = FakeGM(**kw)
        servers.append(s)
        return s
    yield make
    for s in servers:
        s.close()


@pytest.fixture
def loopback(tmp_path, monkeypatch):
    """(make gate from a fake's URL, workdir): a huntress profile pointed at the fake."""
    for name in ("CTF_PLATFORM_URL", "CTF_WIRE_LANE", "CTF_EVENT", *env.legacy_names("CTF_PLATFORM_URL")):
        monkeypatch.delenv(name, raising=False)
    wd = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(wd))

    def gate(url):
        root = tmp_path / "events"
        (root / "huntress").mkdir(parents=True, exist_ok=True)
        src = event.load("huntress").path.read_text().replace(
            'base_url = "https://gamemaster.huntress.example"', f'base_url = "{url}"')
        assert url in src
        (root / "huntress" / "event.toml").write_text(src)
        monkeypatch.setattr(paths, "events_root", lambda: root)
        return get_adapter(event.load("huntress"))
    return gate, wd


def starter_for(gate, wd):
    err = io.StringIO()
    return timedstart.TimedStarter(gate, workdir=wd, err=err), err


def journal_ops(wd):
    rows, _ = wire.read_journal(wd)
    return [r["op"] for r in rows]


def hof_starts(wd):
    return [r for r in ledger.read(wd) if r.get("event") == "hof.start"]


# ------------------------------------------------------------------------------------- the route

def test_a_refused_default_reads_openapi_once_and_retries_once_with_run_for_time(gm, loopback):
    srv = gm()
    make, wd = loopback
    gate = make(srv.url)
    st, err = starter_for(gate, wd)
    info = st(TT)
    assert isinstance(info, InstanceInfo) and info.state == "running" and info.expires_at is not None
    # exactly: the refused default, then the op=openapi body; one openapi read, no other GET
    assert srv.posts == [{"challenge": TT}, {"challenge": TT, "run_for_time": True}]
    assert srv.gets == ["openapi"]
    route = st.results[TT]
    assert route.refused == ["training_rotation_invalid"] and route.openapi and route.learned
    assert "retrying once" in err.getvalue() and "run_for_time" in err.getvalue()
    # journaled by the wire: start, openapi, start (in that order)
    assert journal_ops(wd) == ["start", "openapi", "start"]
    # the start record went through StartGuard (refused start left no record; the retry is ready)
    rec = latency.pending_starts(wd)[TT]
    assert rec["state"] == "ready" and rec["posts"] == 1
    # the pool fields were checked: eligible, recorded as a fresh own start
    assert route.eligibility.eligible is True and route.eligibility.regular is False
    [hs] = hof_starts(wd)
    assert hs["challenge_id"] == TT and hs["origin"] == "fresh" and hs["eligible"] is True


def test_the_learned_body_goes_first_for_every_other_lane(gm, loopback):
    srv = gm()
    make, wd = loopback
    gate = make(srv.url)
    st, _ = starter_for(gate, wd)
    st(TT)
    assert timedstart.remembered_body(wd) == {"run_for_time": True}
    # a second lane (a fresh starter, as another process would build) never pays the refusal
    srv.posts.clear()
    srv.gets.clear()
    other, _ = starter_for(make(srv.url), wd)
    info = other(MA)
    assert info.state == "running"
    assert srv.posts == [{"challenge": MA, "run_for_time": True}] and srv.gets == []
    assert other.results[MA].refused == [] and other.results[MA].openapi is False


def test_openapi_without_run_for_time_is_not_retried(gm, loopback):
    schema = post_schema()
    del schema["properties"]["run_for_time"]
    srv = gm(openapi=openapi_doc(schema))
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    with pytest.raises(timedstart.TimedStartError, match="no other start body than the refused one"):
        st(TT)
    assert srv.posts == [{"challenge": TT}] and srv.gets == ["openapi"]
    assert TT not in latency.pending_starts(wd) and timedstart.remembered_body(wd) is None


def test_a_refused_retry_is_final_no_third_post(gm, loopback):
    srv = gm(needs={"run_for_time": True, "pool": "ranked"})   # the fake wants more than openapi lists
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    with pytest.raises(timedstart.TimedStartError, match="refused twice") as e:
        st(TT)
    assert "training_rotation_invalid" in str(e.value)
    assert len(srv.posts) == 2 and srv.gets == ["openapi"]
    assert st.results[TT].refused == ["training_rotation_invalid", "training_rotation_invalid"]
    assert timedstart.remembered_body(wd) is None and hof_starts(wd) == []


@pytest.mark.parametrize("word", ["already_solved", "base_not_solved", "rate_limited"])
def test_a_refusal_another_body_cannot_cure_reads_no_openapi(gm, loopback, word):
    srv = gm(refuse_all=word)
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    with pytest.raises(timedstart.TimedStartError, match=word):
        st(TT)
    assert len(srv.posts) == 1 and srv.gets == []
    assert TT not in latency.pending_starts(wd)


def test_a_429_refusal_carries_the_retry_after_the_game_master_sent(gm, loopback):
    srv = gm(refuse_all="rate_limited")                 # the fake answers 429 with Retry-After: 7
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    with pytest.raises(timedstart.TimedStartError, match="rate_limited") as e:
        st(TT)
    refusal = e.value.__cause__
    assert isinstance(refusal, timedstart.TimedStartRefused)
    assert (refusal.status, refusal.word, refusal.retry_after) == (429, "rate_limited", 7.0)


@pytest.mark.parametrize("first_refused", [False, True])
def test_a_2xx_other_than_200_is_an_unknown_outcome_resolved_by_status(gm, loopback, first_refused):
    # Like gamemaster.start_instance, only HTTP 200 is a start reply we read the attempt from. A 201
    # (or any other 2xx) is resolved by status: no hof.start record from the reply, and a derived
    # body that got it is not remembered for the other lanes (its attempt was never read from it).
    srv = gm(ok_status=201, needs={"run_for_time": True} if first_refused else {})
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    info = st(TT)
    assert info.state == "running"                      # the status read found the attempt
    route = st.results[TT]
    assert route.attempt is None and route.learned is False
    assert srv.gets == (["openapi", "status"] if first_refused else ["status"])
    assert len(srv.posts) == (2 if first_refused else 1)
    assert hof_starts(wd) == []
    assert timedstart.remembered_body(wd) is None


def test_an_openapi_read_that_fails_is_named_and_not_retried(gm, loopback):
    srv = gm(openapi=None)
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    with pytest.raises(timedstart.TimedStartError, match="op=openapi -> HTTP 500 openapi_unavailable"):
        st(TT)
    assert len(srv.posts) == 1 and srv.gets == ["openapi"]


def test_a_required_property_with_one_named_value_is_filled_from_openapi(gm, loopback):
    schema = post_schema(pool={"type": "string", "enum": ["ranked"]})
    schema["required"] = ["challenge", "pool"]
    srv = gm(needs={"pool": "ranked"}, openapi=openapi_doc(schema))
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    assert st(TT).state == "running"
    assert srv.posts[-1] == {"challenge": TT, "run_for_time": True, "pool": "ranked"}


def test_a_regular_attempt_on_the_retry_is_said_out_loud(gm, loopback):
    srv = gm(pool={"run_for_time": False, "hall_of_fame_eligible": False})
    make, wd = loopback
    st, err = starter_for(make(srv.url), wd)
    info = st(TT)
    assert info.state == "running"                      # it scores: the clock runs
    el = st.results[TT].eligibility
    assert el.regular is True and el.eligible is False
    assert "NOTE: regular attempt on a timed id" in err.getvalue()
    [hs] = hof_starts(wd)
    assert hs["regular"] is True and hs["eligible"] is False


def test_a_pending_start_of_another_process_is_resolved_by_status_without_a_post(gm, loopback):
    srv = gm()
    make, wd = loopback
    gate = make(srv.url)
    srv.started.add(TT)                                 # another process's start landed
    latency.StartGuard(gate, workdir=wd)._update(TT, state="posting", posts=1, open_posts=1,
                                                  last_post=time.time(), first_post=time.time())
    st, _ = starter_for(gate, wd)
    info = st(TT)
    assert info.state == "running" and srv.posts == [] and srv.gets == ["status"]


@pytest.mark.parametrize("status", [503, 502, 500])
def test_a_5xx_with_a_word_is_an_unknown_outcome_not_a_refusal(gm, loopback, status):
    # a gateway can answer 5xx after the attempt was created: no openapi read, no second clock start
    srv = gm(refuse_status=status, refuse_word="upstream_timeout")
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    with pytest.raises(timedstart.TimedStartError, match="outcome unknown"):
        st(TT)
    assert srv.posts == [{"challenge": TT}]
    assert "openapi" not in srv.gets and srv.gets == ["status"]
    assert st.results[TT].refused == [] and st.results[TT].openapi is False
    # the start record is kept (not dropped as a refusal): no process POSTs a second clock start
    assert latency.pending_starts(wd)[TT]["state"] == "unknown"
    assert timedstart.remembered_body(wd) is None


def test_a_4xx_with_a_word_is_still_a_refusal_that_reroutes(gm, loopback):
    srv = gm(refuse_status=422)
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    assert st(TT).state == "running"
    assert len(srv.posts) == 2 and srv.gets == ["openapi"]


def test_a_retry_resolved_by_another_processs_pending_record_is_not_remembered(gm, loopback):
    # between the refusal and the retry another process starts TT: the retry sends no POST and is
    # resolved by status, so the derived body never got an attempt of ours and is not remembered
    srv = gm()
    make, wd = loopback
    gate = make(srv.url)
    st, _ = starter_for(gate, wd)
    read = st.read_openapi

    def read_then_other_process_starts():
        doc = read()
        srv.started.add(TT)
        latency.StartGuard(gate, workdir=wd)._update(TT, state="posting", posts=1, open_posts=1,
                                                      last_post=time.time(), first_post=time.time())
        return doc
    st.read_openapi = read_then_other_process_starts
    info = st(TT)
    assert info.state == "running"
    assert srv.posts == [{"challenge": TT}] and srv.gets == ["openapi", "status"]
    route = st.results[TT]
    assert route.openapi is True and route.attempt is None and route.learned is False
    assert timedstart.remembered_body(wd) is None
    assert hof_starts(wd) == []


def test_an_untimed_id_is_refused_before_any_request(gm, loopback):
    srv = gm()
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    with pytest.raises(NotAllowed, match="not a timed id"):
        st(BASE)
    assert srv.posts == [] and srv.gets == []


def test_a_corrupt_remembered_body_fails_loudly_with_no_post(gm, loopback):
    srv = gm()
    make, wd = loopback
    st, _ = starter_for(make(srv.url), wd)
    p = timedstart.body_path(wd)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json")
    with pytest.raises(timedstart.TimedStartError, match="does not parse"):
        st(TT)
    p.write_text(json.dumps({"body": {"challenge": "x"}}))
    with pytest.raises(timedstart.TimedStartError, match="no body template"):
        st(TT)
    assert srv.posts == []
    assert timedstart.forget_body(wd) is True and timedstart.forget_body(wd) is False


def test_a_stale_remembered_body_reroutes_through_openapi(gm, loopback):
    srv = gm()
    make, wd = loopback
    timedstart.remember_body(wd, {"challenge": "old", "run_for_time": False}, learned_from="old",
                             refused="x")
    st, _ = starter_for(make(srv.url), wd)
    assert st(TT).state == "running"
    assert srv.posts == [{"challenge": TT, "run_for_time": False}, {"challenge": TT, "run_for_time": True}]
    assert timedstart.remembered_body(wd) == {"run_for_time": True}


def test_the_starter_refuses_a_non_game_master_gate():
    class Ctfd:
        kind = "ctfd"
    with pytest.raises(NotAllowed, match="Game Master"):
        timedstart.TimedStarter(Ctfd(), workdir=".")


# ------------------------------------------------------------------------------------- the opener

def test_open_timed_routes_a_refused_default_with_no_starter_given(gm, loopback):
    srv = gm(listed=[TT])
    make, wd = loopback
    gate = make(srv.url)
    res = latency.open_timed(gate, TT, err=io.StringIO())
    assert res.ok and res.started and res.info.state == "running" and res.listed is True
    assert srv.posts == [{"challenge": TT}, {"challenge": TT, "run_for_time": True}]
    assert srv.gets.count("openapi") == 1


def test_open_timed_routes_into_its_explicit_workdir_not_the_environment(gm, loopback, tmp_path):
    srv = gm(listed=[TT])
    make, wd = loopback                                  # CTF_WORKDIR is wd
    other = tmp_path / "other-work"
    res = latency.open_timed(make(srv.url), TT, workdir=other, err=io.StringIO())
    assert res.ok and res.started
    assert latency.pending_starts(other)[TT]["state"] == "ready"
    assert timedstart.remembered_body(other) == {"run_for_time": True}
    assert TT not in latency.pending_starts(wd) and timedstart.remembered_body(wd) is None


def test_open_timed_reports_a_start_refused_for_good_as_an_opening_error(gm, loopback):
    srv = gm(listed=[TT], refuse_all="already_solved")
    make, wd = loopback
    res = latency.open_timed(make(srv.url), TT, err=io.StringIO())
    assert not res.ok and not res.started
    assert "already_solved" in res.errors["start"] and len(srv.posts) == 1


def test_ladder_on_green_starts_through_the_route_by_default(gm, loopback):
    from ctf.adapt import chain
    srv = gm(listed=[TT])
    make, wd = loopback
    gate = make(srv.url)
    ledger.append("adapt.gate", workdir=wd, lane="mobile", verdict="yes", lane_key="k")

    def planner(base, lane, *, workdir, root):
        return chain.ChainStep(base=base, challenge_id=TT, mode="time_trial", action="start", reason="r")
    res = latency.ladder_on_green(gate, BASE, "mobile", workdir=wd, planner=planner, err=io.StringIO())
    assert res.ok and res.started and len(srv.posts) == 2 and srv.posts[-1]["run_for_time"] is True


def test_start_guard_takes_a_timed_id_only_with_an_explicit_post(tmp_path):
    class Plat:
        kind = "gamemaster"

        def start_instance(self, cid):
            raise AssertionError("the guard must use the given post")

    g = latency.StartGuard(Plat(), workdir=tmp_path)
    with pytest.raises(NotAllowed, match="only the opener"):
        g.start(TT)
    out = g.start(TT, post=lambda cid: InstanceInfo(cid, "running"))
    assert out.state == "ready" and out.posted


# ------------------------------------------------------------------------------------- the contract

def test_start_body_follows_refs_allof_and_oneof_and_skips_the_submit_schema():
    doc = {"components": {"schemas": {
        "Base": {"type": "object", "required": ["challenge"],
                 "properties": {"challenge": {"type": "string"}}},
        "Timed": {"allOf": [{"$ref": "#/components/schemas/Base"},
                            {"type": "object", "required": ["mode"],
                             "properties": {"run_for_time": {"type": "boolean"},
                                            "mode": {"const": "ranked"}}}]},
        "Submit": {"type": "object", "required": ["challenge", "answers"],
                   "properties": {"challenge": {"type": "string"}, "answers": {"type": "object"},
                                  "flavour": {"type": "string"}}}}},
        "paths": {"/": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "oneOf": [{"$ref": "#/components/schemas/Submit"},
                      {"$ref": "#/components/schemas/Timed"}]}}}}}}}}
    assert timedstart.start_body_from_openapi(doc, TT) == {"challenge": TT, "run_for_time": True,
                                                           "mode": "ranked"}
    assert len(timedstart.start_schemas(doc)) == 1


def test_run_for_time_is_set_only_when_the_schema_allows_true():
    doc = openapi_doc(post_schema(run_for_time={"const": False}))
    assert timedstart.start_body_from_openapi(doc, TT) == {"challenge": TT}
    doc = openapi_doc(post_schema(run_for_time={"enum": [True]}))
    assert timedstart.start_body_from_openapi(doc, TT) == {"challenge": TT, "run_for_time": True}


@pytest.mark.parametrize("typ", ["string", "integer"])
def test_run_for_time_of_a_non_boolean_type_is_left_out(typ):
    doc = openapi_doc(post_schema(run_for_time={"type": typ}))
    assert timedstart.start_body_from_openapi(doc, TT) == {"challenge": TT}
    doc = openapi_doc(post_schema(run_for_time={}))       # untyped: true is allowed
    assert timedstart.start_body_from_openapi(doc, TT) == {"challenge": TT, "run_for_time": True}


def test_a_required_property_without_a_value_is_not_guessed():
    schema = post_schema(pool={"type": "string", "enum": ["ranked", "regular"]})
    schema["required"] = ["challenge", "pool"]
    with pytest.raises(timedstart.TimedStartError, match="requires pool"):
        timedstart.start_body_from_openapi(openapi_doc(schema), TT)
    schema["properties"]["pool"]["default"] = "ranked"
    assert timedstart.start_body_from_openapi(openapi_doc(schema), TT)["pool"] == "ranked"


@pytest.mark.parametrize("doc,match", [
    ([], "not answer a JSON object"),
    ({"paths": {}}, "lists no start body"),
    ({"paths": {"/": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "required": ["challenge", "answers"],
        "properties": {"challenge": {}, "answers": {}}}}}}}}}}, "lists no start body"),
])
def test_a_document_without_a_start_schema_is_named(doc, match):
    with pytest.raises(timedstart.TimedStartError, match=match):
        timedstart.start_body_from_openapi(copy.deepcopy(doc), TT)
