"""B-152: the carried Hall-of-Fame Web speed runtime (speedrun/web_target.py) and its day-range
fresh-target readers (speedrun/solvers/web*.py).

These modules were built only on the Huntress tag ``archive/speedrun-records`` and never reached
main; B-152 carries them into the master. The fixtures here are built synthetically: each test
starts a loopback HTTP server on 127.0.0.1 that answers the exact structural shape a reader
authorizes its one exploit request from (a robots/listing chain for backup exposure, an /api/clues
callback), plants a fresh ``proof_<32hex>`` token on only the payoff response, and asserts the reader
returns that one token and nothing else. No real challenge binary is executed and no challenge file
is read; the servers are described-shape fakes, never live replays.

The runtime primitives (target_identity, TargetClient bounds, solve_fresh_targets binding,
parallel_calls/barrier_calls caps) are exercised directly against the same loopback servers.
"""
from __future__ import annotations

import datetime as dt
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ctf import event, flagfmt, scope
from speedrun import web_target as wt
from speedrun.solvers import web as early
from speedrun.solvers import web_d06_d16 as mid
from speedrun.solvers import web_d17_d29 as late
from speedrun.solvers import web_d30_d31 as final


@pytest.fixture
def huntress_event(monkeypatch):
    """The Web speed readers hunt the active event's [proof] token (ctf.flagfmt, the single source).
    Huntress is the event these carried readers serve, and its profile defines proof_<hex32>."""
    monkeypatch.setenv("CTF_EVENT", "huntress")
    flagfmt.clear_current_cache()
    yield
    flagfmt.clear_current_cache()


def _proof() -> str:
    return "proof_" + os.urandom(16).hex()


class _Server:
    """A loopback HTTP fake. ``routes`` maps a raw request path (with query) to a
    (status, content_type, body_bytes) tuple, or to a callable(path, body, headers)->that tuple."""

    def __init__(self, routes):
        self.routes = routes
        self.hits = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _go(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.hits.append((self.command, self.path))
                route = outer.routes.get(self.path)
                if route is None:
                    # Fall back to a path-prefix lookup so query strings can be ignored by key.
                    route = outer.routes.get(self.path.split("?", 1)[0])
                if route is None:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if callable(route):
                    reply = route(self.path, body, {k.lower(): v for k, v in self.headers.items()})
                else:
                    reply = route
                # (status, content_type, body) or (status, content_type, body, extra_headers)
                status, ctype, data = reply[:3]
                extra = reply[3] if len(reply) > 3 else {}
                raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
                self.send_response(int(status))
                for name, value in extra.items():
                    self.send_header(name, value)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(raw)

            do_GET = do_POST = _go

            def log_message(self, *_a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_port}/"

    def __exit__(self, *_exc):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def test_proof_tokens_read_the_active_events_proof_format(monkeypatch):
    # The shape comes from ctf.flagfmt (the single flag/proof source), not a literal in the readers.
    monkeypatch.setenv("CTF_EVENT", "huntress")
    flagfmt.clear_current_cache()
    try:
        body = b"noise proof_" + b"a" * 32 + b" and junkproof_" + b"b" * 32 + b"tail"
        assert wt.proof_tokens(body) == ["proof_" + "a" * 32]          # word-boundary both sides
        assert wt.is_proof_value("proof_" + "a" * 32) is True
        assert wt.is_proof_value("proof_" + "a" * 31) is False
    finally:
        flagfmt.clear_current_cache()


@pytest.mark.parametrize("lead", [b"x", b"_", b"fake", b"9"])
def test_proof_tokens_keep_the_left_word_boundary(huntress_event, lead):
    # ctf.flagfmt's bytes regex drops the left boundary; the carried readers required one, so a decoy
    # such as fakeproof_<hex> on a payoff response must not be harvested.
    token = _proof()
    assert wt.proof_tokens(lead + token.encode()) == []
    assert wt.proof_tokens(b"<p>" + lead + token.encode() + b"</p>\n" + token.encode()) == [token]


def test_proof_tokens_read_non_utf8_bytes_around_a_token(huntress_event):
    token = _proof()
    assert wt.proof_tokens(b"\xff\xfe " + token.encode() + b" \x80") == [token]


@pytest.mark.parametrize("pad", [" {} ", "{}\n", "\t{}", "{} "])
def test_is_proof_value_refuses_a_padded_value(huntress_event, pad):
    token = _proof()
    assert wt.is_proof_value(token) is True
    assert wt.is_proof_value(pad.format(token)) is False


def test_proof_helpers_fail_loudly_when_the_event_defines_no_proof_token(monkeypatch):
    # csctf has no [proof]; the readers must not silently match nothing.
    monkeypatch.setenv("CTF_EVENT", "csctf")
    flagfmt.clear_current_cache()
    try:
        with pytest.raises(LookupError):
            wt.proof_tokens(b"proof_" + b"a" * 32)
        with pytest.raises(LookupError):
            wt.is_proof_value("proof_" + "a" * 32)
    finally:
        flagfmt.clear_current_cache()


def _time_trial(url: str, aid: str = "a1"):
    """The minimal one-target time_trial contract shape the readers accept."""
    return {"mode": "time_trial", "targets": [{"url": url}], "answer_ids": [aid],
            "questions": [{"id": aid}]}


# ---- target_identity -------------------------------------------------------------------------------

def test_target_identity_normalises_scheme_host_port_and_path():
    # The suite pins a loopback/.test scope profile (tests/conftest.py); these hosts are inside it.
    assert wt.target_identity("HTTP://Web-1.Example.TEST./a?b=1") == ("http", "web-1.example.test", 80, "/a?b=1")
    assert wt.target_identity("https://h.test") == ("https", "h.test", 443, "/")
    assert wt.target_identity("http://127.0.0.1:8080") == ("http", "127.0.0.1", 8080, "/")


@pytest.mark.parametrize("url", [
    "ftp://h.test/x",                       # not HTTP(S)
    "http://user:pw@h.test/x",              # credentials
    "http://h.test/x#frag",                 # fragment
    "http://h.test/\x01",                   # control character in path
    "",                                     # empty
])
def test_target_identity_refuses_unsafe_urls(url):
    with pytest.raises(wt.TargetError):
        wt.target_identity(url)


# ---- the live-service scope guard (ctf.scope) -------------------------------------------------------

@pytest.fixture
def huntress_scope():
    """Pin the Huntress profile's scope (*.huntress.example; platform gamemaster.huntress.example:443)
    for one test; the suite's loopback profile comes back afterwards."""
    before = scope.pinned()
    scope.pin(event.load("huntress"))
    yield
    if before is None:
        scope.unpin()
    else:
        scope.pin(before)


@pytest.mark.parametrize("url", [
    "http://example.org/",                    # a public host outside the event's scope
    "https://192.0.2.10/x",                   # an IP literal the Huntress scope does not list
    "http://127.0.0.1:8080/",                 # loopback is not in the Huntress scope
])
def test_target_identity_refuses_a_host_outside_the_event_scope(huntress_scope, url):
    with pytest.raises(wt.TargetOutOfScope) as info:
        wt.target_identity(url)
    # one refusal, catchable both as the runtime's error and as the shared scope error
    assert isinstance(info.value, wt.TargetError)
    assert isinstance(info.value, scope.OutOfScope)
    assert "live_service_scope" in str(info.value)


def test_target_identity_refuses_the_event_platform_even_inside_the_scope_glob(huntress_scope):
    # gamemaster.huntress.example matches *.huntress.example, but it is the profile's platform.
    with pytest.raises(wt.TargetOutOfScope, match="event platform"):
        wt.target_identity("https://gamemaster.huntress.example/api/start")
    with pytest.raises(wt.TargetOutOfScope, match="event platform"):
        wt.TargetClient("https://GameMaster.Huntress.Example./", deadline=time.time() + 5)


def test_target_identity_admits_a_host_inside_the_event_scope(huntress_scope):
    assert wt.target_identity("https://web-7.huntress.example/x?y=1") == (
        "https", "web-7.huntress.example", 443, "/x?y=1")


def test_target_identity_refuses_when_no_live_service_is_in_scope():
    # An event whose rules.live_service_scope is empty contacts no live service at all.
    before = scope.pinned()
    scope.pin(event.parse({
        "slug": "b152-empty-scope", "name": "B-152 empty scope",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": []},
    }, src="<b152 test>"))
    try:
        with pytest.raises(wt.TargetOutOfScope, match="empty rules.live_service_scope"):
            wt.target_identity("http://127.0.0.1:8080/")
    finally:
        if before is None:
            scope.unpin()
        else:
            scope.pin(before)


def test_an_out_of_scope_target_is_never_contacted_and_its_reader_never_runs(huntress_scope, huntress_event):
    # A loopback server that would answer; the Huntress scope does not include loopback, so the
    # client constructor refuses before any socket and the answer is omitted (never guessed).
    with _Server({"/": (200, "text/plain", "ok")}) as s:
        called = []

        def reader(client, _attempt):
            called.append(True)
            client.get("/")
            return "value"

        attempt = {"targets": [{"url": s.url}], "answer_ids": ["a"], "questions": [{"id": "a"}]}
        out = wt.solve_fresh_targets(attempt, reader, deadline=time.time() + 5)
        assert out == {}
        assert called == [] and s.hits == []
        assert [d["stage"] for d in out.target_diagnostics] == ["target_init_failed"]


# ---- TargetClient bounds ---------------------------------------------------------------------------

def test_client_reads_a_bounded_response_and_counts_the_request():
    with _Server({"/": (200, "text/plain", "hello")}) as s:
        c = wt.TargetClient(s.url, deadline=time.time() + 5)
        try:
            resp = c.get("/")
            assert resp.status == 200 and resp.body == b"hello"
            assert c.requests == 1
        finally:
            c.close()


def test_client_refuses_a_request_past_the_deadline():
    with _Server({"/": (200, "text/plain", "x")}) as s:
        c = wt.TargetClient(s.url, deadline=time.time() - 1)
        try:
            with pytest.raises(wt.TargetError):
                c.get("/")
        finally:
            c.close()


def test_client_enforces_the_request_budget():
    with _Server({"/": (200, "text/plain", "x")}) as s:
        c = wt.TargetClient(s.url, deadline=time.time() + 5, max_requests=2)
        try:
            c.get("/")
            c.get("/")
            with pytest.raises(wt.TargetError):
                c.get("/")
            assert c.requests == 2
        finally:
            c.close()


def test_client_refuses_an_off_origin_or_absolute_path():
    with _Server({"/": (200, "text/plain", "x")}) as s:
        c = wt.TargetClient(s.url, deadline=time.time() + 5)
        try:
            for bad in ("http://other.test/x", "relative", "/x\x01"):
                with pytest.raises(wt.TargetError):
                    c.get(bad)
        finally:
            c.close()


def test_client_refuses_a_header_outside_the_allowlist():
    with _Server({"/": (200, "text/plain", "x")}) as s:
        c = wt.TargetClient(s.url, deadline=time.time() + 5)
        try:
            with pytest.raises(wt.TargetError):
                c.get("/", headers={"authorization": "Bearer t"})
        finally:
            c.close()


# ---- solve_fresh_targets binding -------------------------------------------------------------------

def test_solve_fresh_targets_binds_answer_ids_and_runs_the_reader_once_per_target(huntress_event):
    with _Server({"/": (200, "text/plain", "ok")}) as s:
        attempt = {"targets": [{"url": s.url}, {"url": s.url}],
                   "answer_ids": ["a", "b"], "questions": [{"id": "a"}, {"id": "b"}]}
        seen = []

        def reader(client, _attempt):
            client.get("/")
            seen.append(True)
            return "v-" + str(len(seen))

        out = wt.solve_fresh_targets(attempt, reader, deadline=time.time() + 5)
        assert set(out) == {"a", "b"}
        assert sorted(out.values()) == ["v-1", "v-2"]
        assert out.target_requests == 2


def test_solve_fresh_targets_omits_a_target_whose_reader_declines_or_raises(huntress_event):
    with _Server({"/": (200, "text/plain", "ok")}) as s:
        attempt = {"targets": [{"url": s.url}, {"url": s.url}],
                   "answer_ids": ["a", "b"], "questions": [{"id": "a"}, {"id": "b"}]}

        def reader(client, _attempt):
            # the second target raises; only the first banks a value
            if client is None:
                return None
            return "value" if _first.pop() else (_ for _ in ()).throw(RuntimeError("boom"))

        _first = [True, False]
        out = wt.solve_fresh_targets(attempt, reader, deadline=time.time() + 5)
        # exactly one of the two answers is present; the raising one is dropped, not guessed
        assert len(out) == 1 and set(out) <= {"a", "b"}


def test_solve_fresh_targets_refuses_a_mismatched_cardinality(huntress_event):
    with _Server({"/": (200, "text/plain", "ok")}) as s:
        attempt = {"targets": [{"url": s.url}], "answer_ids": ["a", "b"],
                   "questions": [{"id": "a"}, {"id": "b"}]}
        assert wt.solve_fresh_targets(attempt, lambda c, a: "x", deadline=time.time() + 5) == {}


def test_solve_fresh_targets_refuses_a_repeated_answer_id(huntress_event):
    # Two targets bound to one answer id: whichever reader finished last would win, so the whole
    # binding is refused before any reader runs.
    with _Server({"/": (200, "text/plain", "ok")}) as s:
        attempt = {"targets": [{"url": s.url}, {"url": s.url + "other"}],
                   "answer_ids": ["a", "a"], "questions": [{"id": "a"}, {"id": "a"}]}
        called = []

        def reader(client, _attempt):
            called.append(True)
            return "value-" + str(len(called))

        assert wt.solve_fresh_targets(attempt, reader, deadline=time.time() + 5) == {}
        assert called == [] and s.hits == []


def test_solve_fresh_targets_refuses_a_target_bound_to_another_questions_artifact(huntress_event):
    # The target names artifact "t-2" but its question (answer "a") is for artifact "t-1": the
    # target would be read for the wrong answer, so the whole binding is refused before any request.
    with _Server({"/": (200, "text/plain", "ok")}) as s:
        attempt = {"targets": [{"id": "t-2", "url": s.url}], "answer_ids": ["a"],
                   "questions": [{"id": "a", "artifact": "t-1"}]}
        called = []

        def reader(client, _attempt):
            called.append(True)
            client.get("/")
            return "value"

        assert wt.solve_fresh_targets(attempt, reader, deadline=time.time() + 5) == {}
        assert called == [] and s.hits == []
        # Control: the same attempt with a matching artifact is read and answered.
        attempt["questions"][0]["artifact"] = "t-2"
        assert wt.solve_fresh_targets(attempt, reader, deadline=time.time() + 5) == {"a": "value"}
        assert called == [True] and len(s.hits) == 1


@pytest.fixture
def no_proof_event(monkeypatch):
    """csctf's profile defines no [proof] token."""
    monkeypatch.setenv("CTF_EVENT", "csctf")
    flagfmt.clear_current_cache()
    assert flagfmt.has_proof() is False
    yield
    flagfmt.clear_current_cache()


def test_solve_fresh_targets_fails_loudly_before_any_request_without_a_proof_format(no_proof_event):
    with _Server({"/": (200, "text/plain", "ok")}) as s:
        called = []

        def reader(client, _attempt):
            called.append(True)
            client.get("/")
            return None

        attempt = {"targets": [{"url": s.url}], "answer_ids": ["a"], "questions": [{"id": "a"}]}
        with pytest.raises(LookupError, match=r"no \[proof\] format"):
            wt.solve_fresh_targets(attempt, reader, deadline=time.time() + 5)
        assert called == [] and s.hits == []


# ---- parallel_calls / barrier_calls bounds ---------------------------------------------------------

def test_parallel_calls_preserves_order_and_caps_the_count():
    assert wt.parallel_calls([lambda i=i: i for i in range(4)]) == [0, 1, 2, 3]
    with pytest.raises(wt.TargetError):
        wt.parallel_calls([lambda: 1] * (wt.MAX_WORKERS + 1))


def test_barrier_calls_rejects_a_burst_wider_than_the_recorded_race():
    with pytest.raises(wt.TargetError):
        wt.barrier_calls([lambda: 1] * (wt.MAX_BARRIER_CALLS + 1), deadline=time.time() + 5)


# ---- day 1 (web.py) backup-exposure reader, end to end ---------------------------------------------

def _backup_site(proof: str, *, plant: bool = True, payoff_extra: str = "", listing_extra: str = "",
                 robots_extra: str = ""):
    payoff = (f"dump start\n{proof}\ndump end" if plant else "dump without a proof") + payoff_extra
    return {
        "/": (200, "text/html", "<html>home, nothing secret here</html>"),
        "/robots.txt": (200, "text/plain", "User-agent: *\nDisallow: /backups/\n" + robots_extra),
        "/backups/": (200, "text/html", "<a href='/backups/dump.sql'>dump</a>" + listing_extra),
        "/backups/dump.sql": (200, "application/sql", payoff),
    }


def _day1(url: str):
    ctx = {"day": 1, "mode": "time_trial", "deadline": time.time() + 10, "max_requests": 64}
    return early.solve_target(_time_trial(url), ctx)


@pytest.mark.parametrize("where", ["listing_extra", "robots_extra"])
def test_day1_reader_declines_when_the_payoff_proof_also_appears_on_a_control(huntress_event, where):
    # A token already visible on a read-only control (the listing or robots.txt) is not the objective
    # the exploit produced: subtracting the controls leaves nothing, so nothing is answered.
    proof = _proof()
    with _Server(_backup_site(proof, **{where: f"\n<!-- {proof} -->"})) as s:
        assert _day1(s.url) == {}


def test_day1_reader_subtracts_a_control_decoy_and_returns_the_novel_proof(huntress_event):
    proof, decoy = _proof(), _proof()
    site = _backup_site(proof, payoff_extra=f"\n-- {decoy}", listing_extra=f"\n<!-- {decoy} -->")
    with _Server(site) as s:
        assert _day1(s.url) == {"a1": proof}


def test_day1_reader_declines_a_payoff_with_two_novel_proofs(huntress_event):
    # Two distinct novel tokens on the payoff is ambiguous: never pick one.
    proof, other = _proof(), _proof()
    with _Server(_backup_site(proof, payoff_extra=f"\n{other}\n")) as s:
        assert _day1(s.url) == {}


def test_day1_backup_reader_returns_the_single_payoff_proof(huntress_event):
    proof = _proof()
    with _Server(_backup_site(proof)) as s:
        ctx = {"day": 1, "mode": "time_trial", "deadline": time.time() + 10, "max_requests": 64}
        out = early.solve_target(_time_trial(s.url), ctx)
        assert isinstance(out, wt.WebAnswers)
        assert out == {"a1": proof}
        assert out.target_requests and out.target_requests >= 4


def test_day1_backup_reader_returns_nothing_when_no_novel_proof_is_present(huntress_event):
    with _Server(_backup_site(_proof(), plant=False)) as s:
        ctx = {"day": 1, "mode": "time_trial", "deadline": time.time() + 10, "max_requests": 64}
        out = early.solve_target(_time_trial(s.url), ctx)
        assert out == {}


def test_day1_reader_declines_a_contract_whose_mode_does_not_match(huntress_event):
    with _Server(_backup_site(_proof())) as s:
        # the attempt says mastery but ctx asks for time_trial -> contract_problem, no solve
        attempt = _time_trial(s.url)
        attempt["mode"] = "mastery"
        ctx = {"day": 1, "mode": "time_trial", "deadline": time.time() + 10}
        assert early.solve_target(attempt, ctx) == {}


def test_day1_solve_fails_loudly_without_a_proof_format_and_sends_nothing(no_proof_event):
    # Before the up-front check the reader's LookupError was caught per target and became a quiet
    # {} with stage "reader_exception", after four live requests. It must raise, with no request.
    with _Server(_backup_site(_proof())) as s:
        with pytest.raises(LookupError, match=r"no \[proof\] format"):
            _day1(s.url)
        assert s.hits == []


def test_day1_refuses_two_answer_ids_naming_the_same_target(huntress_event):
    # Day 1 Mastery has two slots. Both URLs normalise to one origin and path (scheme case and an
    # explicit default port are the same target), so one proof would be sent under two answer ids.
    proof = _proof()
    with _Server(_backup_site(proof)) as s:
        port = s.httpd.server_port
        same = [f"HTTP://127.0.0.1:{port}/", f"http://127.0.0.1:{port}/"]
        attempt = {"mode": "mastery", "targets": [{"url": u} for u in same],
                   "answer_ids": ["a1", "a2"], "questions": [{"id": "a1"}, {"id": "a2"}]}
        ctx = {"day": 1, "mode": "mastery", "deadline": time.time() + 10, "max_requests": 64}
        assert early.contract_problem(attempt, ctx) == "multiple answer ids name the same assigned target"
        assert early.solve_target(attempt, ctx) == {}
        assert s.hits == []
        # Control: two distinct targets on the same server pass the contract (different paths).
        distinct = dict(attempt, targets=[{"url": same[1]}, {"url": same[1] + "?slot=2"}])
        assert early.contract_problem(distinct, ctx) is None


# ---- day 6 (web_d06_d16.py) callback reader, end to end --------------------------------------------

def test_day6_callback_reader_returns_the_nonce_authorised_proof(huntress_event):
    proof = _proof()
    nonce = "nonce-abc123"

    def cb(path, _body, _headers):
        # the payoff only appears when the clue-authored nonce is replayed to the callback route
        if f"={nonce}" in path:
            return (200, "application/json", f'{{"ok":true,"note":"{proof}"}}')
        return (200, "application/json", '{"ok":false}')

    routes = {
        "/": (200, "text/html", "<html>home</html>"),
        "/api/clues": (200, "application/json",
                       f'{{"feature_route":"/feature","secondary_route":"/cb",'
                       f'"callback_nonce":"{nonce}"}}'),
        "/feature": (200, "text/html", "<html>feature</html>"),
        "/cb": cb,
    }
    with _Server(routes) as s:
        ctx = {"day": 6, "mode": "time_trial", "deadline": time.time() + 10, "max_requests": 32}
        out = mid.solve_target(_time_trial(s.url), ctx)
        assert isinstance(out, wt.WebAnswers)
        assert out == {"a1": proof}


def test_day6_reader_declines_when_the_clue_contract_is_missing(huntress_event):
    with _Server({"/": (200, "text/html", "x"),
                  "/api/clues": (200, "application/json", "{}")}) as s:
        ctx = {"day": 6, "mode": "time_trial", "deadline": time.time() + 10, "max_requests": 32}
        assert mid.solve_target(_time_trial(s.url), ctx) == {}


# ---- days 17-31: the exact saved time-trial contract shape -------------------------------------------

def _saved_time_trial(module, day: int, url: str):
    """(attempt, ctx) in the exact saved Day 17-31 Time Trial shape the late/final modules accept."""
    slug, prompt = module.FAMILIES[day]
    base = f"web-exploitation-day-{day:02d}-{slug}"
    attempt = {
        "mode": "time_trial", "prompt": prompt,
        "targets": [{"id": "Target 1", "url": url}],
        "answer_ids": ["proof-1"],
        "questions": [{
            "id": "proof-1", "artifact": "Target 1", "question": "Recover the proof from Target 1.",
            "normalization": "trim",
            "answer_format": {"kind": "exact_text",
                              "syntax": "Submit the exact proof recovered from this target."},
        }],
    }
    ctx = {"day": day, "mode": "time_trial", "base": base, "challenge": base + "/time_trial",
           "deadline": time.time() + 10, "max_requests": 32}
    return attempt, ctx


# ---- day 23 (web_d17_d29.py) trusted-proxy reader, end to end ---------------------------------------

def _proxy_site(proof: str, *, control_leak: bool = False, extra_payoff: str = ""):
    def insider(_path, _body, headers):
        if headers.get("x-forwarded-for") == "127.0.0.1":
            return (200, "application/json",
                    '{"ok":true,"effect":"proxy_trust_admin_bypass","evaluated_client":"127.0.0.1",'
                    f'"objective":"{proof}"{extra_payoff}}}')
        leak = f',"hint":"{proof}"' if control_leak else ""
        return (403, "application/json", f'{{"error":"loopback_only"{leak}}}')

    return {
        "/": (200, "text/html", "<html>insider portal</html>"),
        "/api/clues": (200, "application/json",
                       '{"deployment":"trusted_reverse_proxy","feature_route":"/insider"}'),
        "/insider": insider,
    }


def test_day23_proxy_reader_returns_the_single_payoff_proof(huntress_event):
    proof = _proof()
    with _Server(_proxy_site(proof)) as s:
        attempt, ctx = _saved_time_trial(late, 23, s.url)
        assert late.contract_problem(attempt, ctx) is None
        out = late.solve_target(attempt, ctx)
        assert isinstance(out, wt.WebAnswers)
        assert out == {"proof-1": proof}
        assert out.target_requests == 3          # clues, the 403 control, the one exploit request
        assert ("GET", "/insider") in s.hits


def test_day23_reader_declines_a_proof_already_on_the_403_control(huntress_event):
    proof = _proof()
    with _Server(_proxy_site(proof, control_leak=True)) as s:
        attempt, ctx = _saved_time_trial(late, 23, s.url)
        assert late.solve_target(attempt, ctx) == {}


def test_day23_reader_declines_two_novel_proofs_on_the_payoff(huntress_event):
    proof = _proof()
    with _Server(_proxy_site(proof, extra_payoff=f',"second":"{_proof()}"')) as s:
        attempt, ctx = _saved_time_trial(late, 23, s.url)
        assert late.solve_target(attempt, ctx) == {}


def test_day23_reader_declines_a_contract_with_the_wrong_prompt(huntress_event):
    with _Server(_proxy_site(_proof())) as s:
        attempt, ctx = _saved_time_trial(late, 23, s.url)
        attempt["prompt"] = "a different challenge"
        assert late.contract_problem(attempt, ctx)
        assert late.solve_target(attempt, ctx) == {}
        assert s.hits == []                      # declined before any request


# ---- day 30 (web_d30_d31.py) framework-roulette reader, end to end ----------------------------------

ARENA = "x-arena-0a1b2c3d"


def _roulette_site(proof: str, *, vary: bool = True):
    def staff(_path, _body, headers):
        names = {"Vary": ARENA} if vary else {}
        if headers.get("x-forwarded-for") == "127.0.0.1" and headers.get(ARENA) == "administrator":
            return (200, "application/json",
                    f'{{"ok":true,"effect":"unseen_trust_boundary_generalized","objective":"{proof}"}}',
                    names)
        return (403, "application/json", '{"error":"topology_proof_rejected","policy":"staff_only"}', names)

    return {
        "/": (200, "text/html", "<html>roulette</html>"),
        "/api/clues": (200, "application/json",
                       '{"framework":"ASP.NET Core Blazor Server","feature_route":"/staff",'
                       '"component_route":"/blazor","current_role":"viewer"}'),
        "/staff": staff,
    }


def test_day30_reader_follows_the_vary_named_header_to_the_single_payoff_proof(huntress_event):
    proof = _proof()
    with _Server(_roulette_site(proof)) as s:
        attempt, ctx = _saved_time_trial(final, 30, s.url)
        assert final.contract_problem(attempt, ctx) is None
        out = final.solve_target(attempt, ctx)
        assert isinstance(out, wt.WebAnswers)
        assert out == {"proof-1": proof}
        assert out.target_requests == 3          # clues (replayed, not refetched), topology, payoff


def test_day30_reader_declines_when_no_arena_header_is_named(huntress_event):
    # Without the Vary contract the client never admits the x-arena-* header, and the reader stops
    # at the topology response instead of guessing a header name.
    with _Server(_roulette_site(_proof(), vary=False)) as s:
        attempt, ctx = _saved_time_trial(final, 30, s.url)
        assert final.solve_target(attempt, ctx) == {}


# ---- late / final modules: structural contract checks (no live server needed) ---------------------

@pytest.mark.parametrize("module,day", [(late, 18), (final, 30)])
def test_late_and_final_decline_a_malformed_contract(module, day):
    reason = module.contract_problem({"mode": "time_trial"}, {"day": day, "mode": "time_trial"})
    assert isinstance(reason, str) and reason
    out = module.solve_target({"mode": "time_trial"},
                              {"day": day, "mode": "time_trial", "deadline": time.time() + 5})
    assert isinstance(out, wt.WebAnswers) and out == {}


def test_late_and_final_cover_the_expected_day_ranges():
    assert set(late.FAMILIES) == set(range(17, 30))
    assert set(final.FAMILIES) == {30, 31}
    assert set(early.EARLY_READERS) == set(range(1, 6))
    assert set(mid.READERS) == set(range(6, 17))
