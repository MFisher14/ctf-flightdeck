"""B-233: clue-driven POST exploit class for Layer-1 proof_hunt.

Local fake POST-capable targets only (http.server on 127.0.0.1); no Game Master, no live target, no
challenge binary. Pinned to the Huntress profile so the banked value is judged against the real
proof_<32 hex> payoff format (events/huntress [proof]); the suite's conftest scope profile allows the
loopback target. Every behaviour the module adds has a check here that fails when the behaviour is wrong.
"""
import hashlib
import importlib.util
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "tests"))
import event_pin  # noqa: E402  (tests/event_pin.py)
event_pin.pin(globals(), "huntress")  # Huntress web: proof_<32 hex> payoffs


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


CP = _load("clue_post_class", "solvers/web/clue_post_class.py")
PH = _load("proof_hunt", "solvers/web/proof_hunt.py")
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import web as WEB  # noqa: E402


def uuid4_proof(seed):
    """A proof_<32 hex> with the UUID-v4 version/variant nibbles proof_hunt observes."""
    h = hashlib.sha256(seed.encode()).hexdigest()[:32]
    h = h[:12] + "4" + h[13:16] + "9" + h[17:]
    return "proof_" + h


# ---------------------------------------------------------------------------------------------------------
#  A POST-capable loopback target (web_fakes.Site is GET-only, so this test ships its own).
# ---------------------------------------------------------------------------------------------------------
class App:
    """routes: {(method, path): handler(query, body, store) -> (status, ctype, body_text)}; records hits."""

    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default
        self.hits = []          # (method, path)
        self.store = {}
        self.lock = threading.Lock()

    def handle(self, method, raw, body):
        with self.lock:
            self.hits.append((method, raw.split("?", 1)[0]))
        path, _, q = raw.partition("?")
        query = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        form = dict(urllib.parse.parse_qsl(body, keep_blank_values=True)) if body else {}
        fn = self.routes.get((method, path)) or self.default
        if fn is None:
            return 404, "text/plain", "not found"
        return fn(query, form, self.store)

    def posts(self):
        return [h for h in self.hits if h[0] == "POST"]


def serve(app):
    class H(BaseHTTPRequestHandler):
        def _do(self, method):
            n = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            status, ctype, text = app.handle(method, self.path, body)
            payload = text.encode() if isinstance(text, str) else text
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._do("GET")

        def do_POST(self):
            self._do("POST")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def stored_xss_app(proof, *, decoy=None, post_response_proof=None):
    """A stored-XSS-shaped app: POST /notes stores `content`; GET /notes/view renders it and, when the
    stored content carries the clue marker, serves `proof` (the moderator 'ran' the payload)."""
    def post_notes(query, form, store):
        store["content"] = form.get("content", "")
        body = "stored"
        if post_response_proof:  # a decoy in the POST RESPONSE: must never be banked
            body += " " + post_response_proof
        return 201, "text/plain", body

    def view(query, form, store):
        base = decoy or ""
        if "b233clue" in store.get("content", ""):
            return 200, "text/html", f"<p>note rendered {proof}</p>{base}"
        return 200, "text/html", f"<p>no note yet</p>{base}"

    return App({("POST", "/notes"): post_notes, ("GET", "/notes/view"): view})


STORED_XSS_CLUE = {
    "feature_route": "/notes",
    "content_parameter": "content",
    "render_route": "/notes/view",
    "hint": "reflected-on-render",
}


def client_for(url, *, get_only=False):
    return WEB.WebClient(url, get_only=get_only)


# ---------------------------------------------------------------------------------------------------------
#  Parsing & classification
# ---------------------------------------------------------------------------------------------------------
def test_parse_post_clue_derives_fields_and_read_routes():
    clue = CP.parse_post_clue(STORED_XSS_CLUE)
    assert clue is not None
    assert clue.feature_route == "/notes"
    assert "content" in clue.param_names
    # the render route is a read carrier, and the feature route is the final fallback carrier
    assert "/notes/view" in clue.read_routes
    assert "/notes" in clue.read_routes
    assert clue.read_routes.index("/notes/view") < clue.read_routes.index("/notes")


def test_parse_post_clue_rejects_offhost_and_missing_feature_route():
    assert CP.parse_post_clue({"content_parameter": "content"}) is None  # no feature_route
    assert CP.parse_post_clue({"feature_route": "http://evil.example/x"}) is None  # off-host
    assert CP.parse_post_clue({"feature_route": "/a/../../etc"}) is None  # traversal
    assert CP.parse_post_clue("not a dict") is None


def test_parse_post_clue_ignores_non_identifier_param_values():
    clue = CP.parse_post_clue({
        "feature_route": "/notes",
        "content_parameter": "content",
        "note_parameter": "please enter your message here",  # a sentence, not a field name
        "parameters": ["title", "x" * 200],
    })
    assert "content" in clue.param_names
    assert "title" in clue.param_names
    assert all(" " not in p and len(p) <= 64 for p in clue.param_names)


@pytest.mark.parametrize("doc,expected", [
    ({"feature_route": "/notes", "content_parameter": "c"}, "stored_xss"),
    ({"feature_route": "/render", "render_route": "/out", "template_parameter": "t"}, "ssti"),
    ({"feature_route": "/execute-task", "input_parameter": "cmd"}, "cmdi"),
    ({"feature_route": "/upload", "upload_shape": "multipart", "render_route": "/preview"}, "upload_template"),
    ({"feature_route": "/graphql", "query_document": "..."}, "graphql"),
    ({"feature_route": "/reset", "request_route": "/req", "redeem_route": "/red",
      "token_parameter": "t", "account_parameter": "a"}, "reset_rebind"),
    ({"feature_route": "/jobs", "owner_directory_route": "/owners", "job_id_required": True}, "queue_owner"),
    ({"feature_route": "/report", "audit_route": "/audit"}, "audit_report"),
    ({"feature_route": "/x", "foo": "bar"}, "generic_post"),
])
def test_classify_technique_from_clue_shape(doc, expected):
    assert CP.classify_technique(doc) == expected


# ---------------------------------------------------------------------------------------------------------
#  The guard: arming + clue-advertised routes
# ---------------------------------------------------------------------------------------------------------
def test_route_advertised_only_for_clue_named_routes():
    clue = CP.parse_post_clue(STORED_XSS_CLUE)
    assert CP.route_is_clue_advertised("/notes", clue)
    assert CP.route_is_clue_advertised("/notes/view", clue)
    assert CP.route_is_clue_advertised("/notes?x=1", clue)   # path compared, query ignored
    assert not CP.route_is_clue_advertised("/delete-all", clue)
    assert not CP.route_is_clue_advertised("/notes/other", clue)


def test_clue_post_allows_gets_always_writes_only_when_armed_and_advertised():
    clue = CP.parse_post_clue(STORED_XSS_CLUE)
    armed = CP.armed_for()
    disarmed = CP.disarmed()
    # GET is always allowed, even disarmed
    assert CP.clue_post_allows("GET", "/notes/view", arming=disarmed, clue=clue)[0] is True
    # disarmed write refused with an O-2 reason
    ok, why = CP.clue_post_allows("POST", "/notes", arming=disarmed, clue=clue)
    assert ok is False and "O-2" in why
    # armed write to an UNadvertised route is still refused
    ok, why = CP.clue_post_allows("POST", "/delete-all", arming=armed, clue=clue)
    assert ok is False and "not advertised" in why
    # armed write to the advertised route is allowed
    assert CP.clue_post_allows("POST", "/notes", arming=armed, clue=clue)[0] is True


def test_value_destructive_action_guard_blocks_verbs_not_payloads():
    assert CP.value_is_destructive_action("delete") is True
    assert CP.value_is_destructive_action("drop-table") is True
    # an exploit payload is not a bare action verb
    assert CP.value_is_destructive_action("<img src=x onerror=alert(1)>") is False
    assert CP.value_is_destructive_action("${7*7}") is False
    assert CP.value_is_destructive_action("id # marker") is False


def test_load_arming_defaults_disarmed_and_env_arms():
    assert CP.load_arming({}).armed is False
    assert CP.load_arming({"CTF_WEB_POST_CLASS": "off"}).armed is False
    on = CP.load_arming({"CTF_WEB_POST_CLASS": "on"})
    assert on.armed is True and "armed" in on.reason.lower()


# ---------------------------------------------------------------------------------------------------------
#  The runner
# ---------------------------------------------------------------------------------------------------------
def test_disarmed_sends_no_post():
    app = stored_xss_app(uuid4_proof("d7-disarmed"))
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url),
                               arming=CP.disarmed(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    assert res.proof is None
    assert res.refused is True and res.sent is False
    assert "O-2" in res.reason
    assert app.posts() == []  # the hard promise: disarmed => no state-changing request on the wire


def test_armed_banks_novel_proof_from_followup_get():
    proof = uuid4_proof("d7-armed")
    app = stored_xss_app(proof)
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    assert res.proof == proof
    assert res.sent is True and res.refused is False
    assert res.technique == "stored_xss"
    assert PH.is_proof(res.proof)             # judged against the event proof format
    assert len(app.posts()) >= 1             # a POST was actually sent to the advertised route


def test_proof_read_only_from_followup_not_from_post_response():
    real = uuid4_proof("d7-real")
    post_decoy = uuid4_proof("d7-postdecoy")
    app = stored_xss_app(real, post_response_proof=post_decoy)
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    # the token in the POST response is never banked; only the follow-up GET's novel proof is
    assert res.proof == real
    assert res.proof != post_decoy


def test_preexisting_decoy_on_read_route_is_not_banked():
    decoy = uuid4_proof("d7-predecoy")
    # the render route always shows `decoy`; the note payload elicits NOTHING new (proof == decoy)
    app = stored_xss_app(decoy, decoy=decoy)
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    # the only proof on the page was there before our POST -> baseline -> not banked
    assert res.proof is None
    assert res.sent is True  # we did POST, but banked nothing novel


def test_novel_proof_banked_even_when_a_decoy_coexists():
    real = uuid4_proof("d7-novel")
    decoy = uuid4_proof("d7-coexist")
    app = stored_xss_app(real, decoy=decoy)  # view shows decoy always + real once marker stored
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    assert res.proof == real  # the novel one, not the baseline decoy


def test_get_only_wire_gate_holds_even_when_armed():
    """The two gates layer: arming the class does NOT bypass B-007's get_only wire gate. A get_only
    client refuses the POST before the wire, so no state change reaches the target and nothing is banked."""
    app = stored_xss_app(uuid4_proof("d7-getonly"))
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url, get_only=True),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    assert res.proof is None
    assert app.posts() == []            # the wire gate stopped the POST
    assert "refused" in res.reason.lower()


def test_unadvertised_feature_route_is_never_posted():
    # clue advertises /notes, but suppose the parse yields a route the app treats as destructive-only
    app = stored_xss_app(uuid4_proof("d7-unadv"))
    srv, url = serve(app)
    bad_clue = dict(STORED_XSS_CLUE, feature_route="/delete-everything")
    try:
        res = CP.run_clue_post(bad_clue, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    # /delete-everything IS the advertised feature route here, so it is allowed as a route, but the app
    # has no such handler: the point of this test is that a write only ever goes to the advertised route
    # and never to /notes (which the clue did not name as feature). No POST to /notes.
    assert ("POST", "/notes") not in app.hits
    assert res.proof is None


def test_proof_in_both_post_response_and_followup_is_banked_as_baseline():
    """A proof_<hex> that appears in BOTH the POST response and the follow-up GET is never banked: the
    POST-response token is folded into the baseline, so it is a decoy even when it later shows on the GET.
    This exercises the 'fold POST-response tokens into baseline, never a payoff' line directly -- removing
    that fold would bank the shared token, which this test forbids."""
    shared = uuid4_proof("d7-shared")
    # same value in the POST response AND on the follow-up GET
    app = stored_xss_app(shared, post_response_proof=shared)
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    assert len(app.posts()) >= 1              # a POST was sent (the fold, not read-only banking, is at work)
    assert res.proof is None                  # folded into baseline from the POST response -> not novel
    assert res.sent is True


def test_request_budget_caps_total_requests_on_a_target_that_never_proves():
    """The armed class is request-bounded: against a target that never yields a proof, the total number of
    requests that reach the wire is capped at max_requests. With read_routes == 2 and max_requests == 2,
    the two baseline GETs exhaust the budget and no POST is attempted -- an off-by-one in the budget guard
    would let one extra request through."""
    def post_notes(query, form, store):
        store["content"] = form.get("content", "")
        return 201, "text/plain", "stored"       # never a proof

    def view(query, form, store):
        return 200, "text/html", "<p>nothing here</p>"  # never a proof

    app = App({("POST", "/notes"): post_notes, ("GET", "/notes/view"): view})
    srv, url = serve(app)
    try:
        res = CP.run_clue_post(STORED_XSS_CLUE, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1", max_requests=2)
    finally:
        srv.shutdown(); srv.server_close()
    assert res.proof is None
    # STORED_XSS_CLUE has two read routes (/notes/view, /notes); the two baseline GETs spend the budget,
    # so the POST is refused as budget-exhausted and never reaches the wire.
    assert len(app.hits) == 2
    assert app.posts() == []


def test_destructive_named_advertised_route_is_driven_but_unadvertised_is_refused():
    """The destructive-word guard is lifted ONLY for a route the clue advertises: a POST is actually
    attempted against a destructive-NAMED advertised route (/delete-everything), while a write to an
    unadvertised destructive route is refused by the guard."""
    proof = uuid4_proof("d7-destructive")

    def post_del(query, form, store):
        store["content"] = form.get("content", "")
        return 200, "text/plain", "queued"

    def render(query, form, store):
        if "b233clue" in store.get("content", ""):
            return 200, "text/html", f"<p>{proof}</p>"
        return 200, "text/html", "<p>empty</p>"

    app = App({("POST", "/delete-everything"): post_del, ("GET", "/render"): render})
    srv, url = serve(app)
    clue_doc = {"feature_route": "/delete-everything", "content_parameter": "content",
                "render_route": "/render"}
    try:
        res = CP.run_clue_post(clue_doc, client=client_for(url),
                               arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    # the destructive-named route the clue advertised was actually POSTed to, and it proved
    assert ("POST", "/delete-everything") in app.hits
    assert res.proof == proof
    # but a destructive route the clue did NOT advertise is still refused, armed or not
    parsed = CP.parse_post_clue(clue_doc)
    ok, why = CP.clue_post_allows("POST", "/drop-tables", arming=CP.armed_for(), clue=parsed)
    assert ok is False and "not advertised" in why


def test_clue_without_param_names_refuses_to_guess_a_field():
    app = stored_xss_app(uuid4_proof("d7-nofield"))
    srv, url = serve(app)
    try:
        res = CP.run_clue_post({"feature_route": "/notes", "render_route": "/notes/view"},
                               client=client_for(url), arming=CP.armed_for(), host="127.0.0.1")
    finally:
        srv.shutdown(); srv.server_close()
    assert res.proof is None
    assert res.refused is True
    assert "field" in res.reason or "parameter" in res.reason
    assert app.posts() == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
