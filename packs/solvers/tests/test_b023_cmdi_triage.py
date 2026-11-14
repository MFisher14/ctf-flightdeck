#!/usr/bin/env python3
"""B-023: command-injection TRIAGE row in solvers/web/recon_triage.py.

recon_triage already ranks SSRF/IDOR/LFI/SQLi from a target's own disclosed surface; B-023's proposal also
names command injection, which was the one non-gated class the triage front door did not emit. These tests
pin the new ``command_injection`` detection row: it must fire on an advertised command/lookup surface (a
landing link, a <form> control or the clue feed), point at the route that disclosed it, stay GET-only (no probe
is ever sent; a form is read, never submitted), not report an ambiguous SSRF parameter (``url``, ``target``) as
command injection without lookup text, ignore lookalike routes and body prose, and stay silent when nothing is
disclosed.

Real ``assert`` statements (not the print-and-collect ``check`` helper), so each behaviour fails loudly under
pytest when it is wrong. No Game Master request and no live target: the one network use is a local
http.server bound to 127.0.0.1 on an ephemeral port. Blind/OOB command injection is HELD for the verified
profile and is not exercised here -- this is detection only.
"""
import importlib.util
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ.pop("CTF_PLATFORM_URL", None)
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))


def _load():
    spec = importlib.util.spec_from_file_location(
        "recon_triage_b023", REPO / "solvers" / "web" / "recon_triage.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RT = _load()


class Site:
    def __init__(self, routes, default=None):
        self.routes = routes
        self.default = default
        self.hits = []
        self.lock = threading.Lock()

    def handle(self, method, raw):
        with self.lock:
            self.hits.append((method, raw))
        path, _, q = raw.partition("?")
        query = dict(urllib.parse.parse_qsl(q, keep_blank_values=True))
        fn = self.routes.get(path) or self.default
        if fn is None:
            return 404, "text/html", "<p>not found</p>", {}
        r = fn(query) if callable(fn) else fn
        return (tuple(r) + ({},))[:4]


def serve(site):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            st, ctype, body, hdrs = site.handle(self.command, self.path)
            data = body.encode() if isinstance(body, str) else body
            self.send_response(st)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (hdrs or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(data)
            except Exception:
                pass

        do_GET = do_POST = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def page(title, body):
    return 200, "text/html; charset=utf-8", f"<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>"


def js(obj, status=200):
    return status, "application/json", json.dumps(obj)


def run_recon(site, **kw):
    srv, url = serve(site)
    try:
        return RT.recon(url, **kw)
    finally:
        srv.shutdown()
        srv.server_close()


def class_names(out):
    return {c["vuln_class"] for c in out["classes"]}


def cmdi_row(out):
    rows = [c for c in out["classes"] if c["vuln_class"] == "command_injection"]
    return rows[0] if rows else None


def test_strong_param_fires_without_surface_text():
    # A host/ip/dns-style parameter is itself a command-injection hint even with no lookup prose, because it is
    # not shared with the SSRF fetch-param family.
    body = '<p>Tools: <a href="/diagnose?host=example.com">diagnose</a></p>'
    site = Site({"/": page("Tools", body)})
    out = run_recon(site)
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["host"], row["params"]
    assert row["confidence"] == "medium", row["confidence"]
    # The link that disclosed the strong parameter names the route to try.
    assert row["endpoints"] == ["/diagnose"], row["endpoints"]


def test_surface_text_plus_clue_param():
    # A ping/nslookup feature named in the clue feed, with an ambiguous param, reports medium via the surface
    # text, and points at the clue's own feature route.
    site = Site({
        "/": page("Home", "<p>hi</p>"),
        "/api/clues": lambda q: js({"feature_route": "/net/run-ab12",
                                    "description": "network diagnostics: ping a target host",
                                    "input_parameter": "target"}),
    })
    out = run_recon(site)
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["confidence"] == "medium", row
    assert "/net/run-ab12" in row["endpoints"], row["endpoints"]


def test_surface_only_low_confidence_from_openapi_route():
    # A lookup feature disclosed in text + an openapi /ping route, but no named parameter yet: low confidence,
    # endpoint surfaced, no param claimed.
    spec = {"paths": {"/api/ping": {}, "/health": {}}}
    site = Site({"/": page("Status", "<p>You can run a traceroute from the console.</p>"),
                 "/openapi.json": lambda q: js(spec)})
    out = run_recon(site)
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["confidence"] == "low", row
    # Only the lookup-named route: /health is not a command surface.
    assert row["endpoints"] == ["/api/ping"], row["endpoints"]
    assert row["params"] == [], row["params"]


def test_plain_ssrf_param_is_not_reported_as_cmdi():
    # A bare SSRF fetch parameter with no lookup surface must stay ssrf-only; "target"/"url" are not command
    # injection on their own.
    body = '<a href="/preview?url=http://example.invalid/x">preview</a>'
    site = Site({"/": page("Home", body)})
    out = run_recon(site)
    assert "ssrf" in class_names(out), class_names(out)
    assert "command_injection" not in class_names(out), class_names(out)


def test_no_cmdi_when_nothing_disclosed():
    site = Site({"/": page("Plain", "<p>nothing here</p>")})
    out = run_recon(site)
    assert "command_injection" not in class_names(out), class_names(out)


def test_detection_is_get_only_and_sends_no_probe():
    body = '<p>Tools: <a href="/diagnose?ip=10.0.0.1">diagnose</a></p>'
    site = Site({"/": page("Tools", body)})
    out = run_recon(site)
    assert cmdi_row(out) is not None, class_names(out)
    # Nothing offensive left the client: GET only, no injection metacharacters in any requested path.
    assert all(m == "GET" for m, _ in site.hits), site.hits
    assert all(ch not in raw for _, raw in site.hits for ch in (";", "|", "&&", "`", "$(")), site.hits
    # Bounded to the fixed recon surface (no per-target path growth).
    assert len(site.hits) <= len(RT.RECON_PATHS), len(site.hits)


def test_ambiguous_target_without_lookup_text_is_ssrf_only():
    # ``target`` is in both the SSRF and the cmdi word families. With no lookup surface it must stay ssrf only.
    body = '<a href="/fetch?target=http://example.invalid/x">fetch</a>'
    out = run_recon(Site({"/": page("Home", body)}))
    assert "ssrf" in class_names(out), class_names(out)
    assert "command_injection" not in class_names(out), class_names(out)


def test_ambiguous_target_with_lookup_heading_reports_both():
    # With lookup text beside it the param really is ambiguous: both rows fire, and the cmdi row points at the
    # route that took the param.
    body = '<h1>Ping a target</h1><a href="/net?target=10.0.0.1">go</a>'
    out = run_recon(Site({"/": page("Net", body)}))
    assert "ssrf" in class_names(out), class_names(out)
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["target"], row["params"]
    assert row["endpoints"] == ["/net"], row["endpoints"]


def test_strong_param_reported_without_weak_words():
    # When a strong word is present the weak ones are not claimed as cmdi params.
    body = '<h1>DNS lookup</h1><a href="/diag?host=a&server=b">diag</a>'
    out = run_recon(Site({"/": page("Diag", body)}))
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["host"], row["params"]


def test_surface_text_alone_without_route_or_param_gives_no_row():
    # A heading names a ping feature, but no route, form or parameter is disclosed: nothing to point at.
    out = run_recon(Site({"/": page("Soon", "<h1>Ping tool</h1><p>coming soon</p>")}))
    assert "command_injection" not in class_names(out), class_names(out)


def test_ping_post_form_with_unquoted_attributes():
    # The commonest CTF cmdi shape: a "Ping a host" POST form. Its control name and action are read from the
    # already-fetched landing page; the form is never submitted.
    body = "<h1>Ping a host</h1><form action=/ping method=post><input name=host><button>Go</button></form>"
    site = Site({"/": page("Ping", body)})
    out = run_recon(site)
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["confidence"] == "medium", row
    assert row["params"] == ["host"], row["params"]
    assert row["endpoints"] == ["/ping"], row["endpoints"]
    assert out["disclosed"]["forms"] == [{"action": "/ping", "method": "POST", "inputs": ["host"]}]
    assert all(m == "GET" for m, _ in site.hits), site.hits
    assert not any(raw.startswith("/ping") for _, raw in site.hits), site.hits


def test_get_form_weak_param_with_label_text():
    # A weak param (``address``) counts when the form's own label names the lookup feature; a relative action
    # resolves against the landing page.
    body = '<form action="tools/ping"><label>IP to ping</label><input name="address"></form>'
    out = run_recon(Site({"/": page("Tools", body)}))
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["address"], row["params"]
    assert row["endpoints"] == ["/tools/ping"], row["endpoints"]


def test_form_without_action_points_at_landing_page():
    out = run_recon(Site({"/": page("Check", "<form method=post><input name=ip></form>")}))
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["ip"], row["params"]
    assert row["endpoints"] == ["/"], row["endpoints"]


def test_input_outside_form_is_a_param_without_endpoint():
    out = run_recon(Site({"/": page("Check", '<input id="h" name="hostname"><p>nothing else</p>')}))
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["hostname"], row["params"]
    assert row["endpoints"] == [], row["endpoints"]


def test_off_host_form_is_ignored():
    body = '<form action="http://other.invalid/ping"><input name="host"></form>'
    out = run_recon(Site({"/": page("Ext", body)}))
    assert "command_injection" not in class_names(out), class_names(out)


def test_weak_param_with_lookup_word_only_in_body_prose_gives_no_row():
    # "dig" in a paragraph is prose, not a lookup feature; with only a weak param nothing is reported.
    body = '<p>Dig into the docs before you ping us.</p><a href="/settings?server=eu">settings</a>'
    out = run_recon(Site({"/": page("Docs", body)}))
    assert "command_injection" not in class_names(out), class_names(out)


def test_lookalike_routes_are_not_cmdi_routes():
    # Body text says "ping", but no disclosed route is a lookup feature: /api/digest, /digital, /dnsrecords and
    # /lookup-user only start with a lookup word, and /img/ping.png is an asset.
    spec = {"paths": {"/api/digest": {}, "/digital": {}, "/dnsrecords": {}, "/lookup-user": {}}}
    body = '<p>ping us anytime</p><img src="/img/ping.png">'
    out = run_recon(Site({"/": page("Shop", body), "/openapi.json": lambda q: js(spec)}))
    assert "command_injection" not in class_names(out), class_names(out)


def test_route_word_anchoring():
    yes = ["/ping", "/api/ping", "/api/ping/", "/ping.php", "/tools/dns-lookup", "/nslookup?x=1", "/diagnose",
           "/diagnostics", "/cgi-bin/traceroute.cgi", "/host_lookup"]
    no = ["/api/digest", "/digital", "/dnsrecords", "/lookup-user", "/pinged-users", "/img/ping.png",
          "/js/dig.js", "/health"]
    assert [r for r in yes if not RT._CMDI_ROUTE_WORD.search(r)] == []
    assert [r for r in no if RT._CMDI_ROUTE_WORD.search(r)] == []


def test_clue_feature_route_leads_when_the_param_comes_from_a_link():
    # The clue feed names the lookup feature's route; the strong param itself is on a landing link. The clue's
    # own route ranks first, the link's route after it.
    site = Site({
        "/": page("Home", '<a href="/legacy?host=x">old tool</a>'),
        "/api/clues": lambda q: js({"feature_route": "/net/run-cd34", "description": "ping a host"}),
    })
    row = cmdi_row(run_recon(site))
    assert row is not None
    assert row["endpoints"] == ["/net/run-cd34", "/legacy"], row["endpoints"]


def test_clue_feature_route_with_lookup_text_and_no_param_is_low():
    site = Site({
        "/": page("Home", "<p>hi</p>"),
        "/api/clues": lambda q: js({"feature_route": "/net/run-ef56", "description": "nslookup service"}),
    })
    out = run_recon(site)
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["confidence"] == "low", row
    assert row["endpoints"] == ["/net/run-ef56"], row["endpoints"]
    assert row["params"] == [], row["params"]


def test_ip_address_and_fqdn_params_fire():
    for word in ("ip_address", "fqdn"):
        body = f'<a href="/diag?{word}=x">diag</a>'
        out = run_recon(Site({"/": page("Diag", body)}))
        row = cmdi_row(out)
        assert row is not None, (word, class_names(out))
        assert row["params"] == [word], row["params"]


def test_word_lists_match_proof_hunt_and_strong_words_are_unambiguous():
    # Triage must point at the same surface proof_hunt's cmdi reader exploits: the word set may not drift.
    ph = RT._proof_hunt()
    assert ph is not None, "solvers/web/proof_hunt.py failed to load"
    assert set(RT._CMDI_PARAM_WORDS) == set(ph.CMDI_WORDS)
    assert set(RT._CMDI_STRONG_PARAM_WORDS) <= set(RT._CMDI_PARAM_WORDS)
    assert set(RT._CMDI_STRONG_PARAM_WORDS) & set(RT._SSRF_PARAM_WORDS) == set()


# --- round 2: form body text, script-driven and closed forms, focus capping, off-host by port ------------------
BASE = "http://127.0.0.1:8000/"


def test_lookup_text_in_form_body_counts_and_points_at_the_action():
    # The lookup word sits in the form's own body text (a <p>, not a label/heading): it is still the form's
    # feature text, so the weak ``address`` param fires, pointing at the form action.
    body = "<form action=/net><p>Enter an address to ping</p><input name=address></form>"
    out = run_recon(Site({"/": page("Tools", body)}))
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["confidence"] == "medium", row
    assert row["params"] == ["address"], row["params"]
    assert row["endpoints"] == ["/net"], row["endpoints"]


def test_script_driven_form_keeps_its_inputs_without_a_bogus_endpoint():
    # A JS-driven ping form (action="javascript:void(0)") names no route: its strong ``host`` control is still
    # reported, endpoint-less, and the form is not disclosed with a made-up action.
    body = '<h1>Ping</h1><form action="javascript:void(0)" onsubmit="go()"><input name=host></form>'
    out = run_recon(Site({"/": page("Ping", body)}))
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["host"], row["params"]
    assert row["endpoints"] == [], row["endpoints"]
    assert "forms" not in out["disclosed"], out["disclosed"].get("forms")


def test_mailto_form_action_gives_no_endpoint():
    forms, orphans, _ = RT._parse_surface('<form action="mailto:a@b.invalid"><input name=ip></form>', BASE)
    assert forms == [], forms
    assert orphans == ["ip"], orphans


def test_input_after_a_closed_form_is_not_credited_to_its_action():
    body = "<form action=/search><input name=q></form><input name=host>"
    out = run_recon(Site({"/": page("Mixed", body)}))
    row = cmdi_row(out)
    assert row is not None, class_names(out)
    assert row["params"] == ["host"], row["params"]
    assert row["endpoints"] == [], row["endpoints"]
    assert out["disclosed"]["forms"] == [{"action": "/search", "method": "GET", "inputs": ["q"]}]


def test_unclosed_link_does_not_make_following_prose_focused():
    body = '<a href=/home>Home<p>Dig into the docs</p><a href="/settings?server=eu">'
    out = run_recon(Site({"/": page("Docs", body)}))
    assert "command_injection" not in class_names(out), class_names(out)
    # ...while text inside a properly scoped link still counts.
    _, _, focus = RT._parse_surface('<a href=/home>Home<p>Dig into the docs</p><a href=/x>Ping it</a>', BASE)
    assert "Ping it" in focus and "Home" in focus, focus
    assert "Dig into" not in focus, focus


def test_second_link_implicitly_closes_an_open_one():
    _, _, focus = RT._parse_surface('<a href=/a>One<a href=/b>Two</a> ping prose after', BASE)
    assert "One" in focus and "Two" in focus, focus
    assert "ping prose" not in focus, focus


def test_script_and_style_text_is_not_focused():
    body = '<form action=/save><script>var x="ping"</script><style>.ping{}</style><input name=server></form>'
    out = run_recon(Site({"/": page("Save", body)}))
    assert "command_injection" not in class_names(out), class_names(out)
    _, _, focus = RT._parse_surface("<h1><script>nslookup()</script>Settings</h1>", BASE)
    assert "nslookup" not in focus and "Settings" in focus, focus


def test_form_on_same_host_other_port_is_off_host():
    forms, orphans, _ = RT._parse_surface('<form action="http://127.0.0.1:9999/ping"><input name=host></form>',
                                          BASE)
    assert forms == [] and orphans == [], (forms, orphans)
    # The same host and port (explicit, or implied by the scheme's default) is kept; another scheme's default
    # port is not.
    forms, _, _ = RT._parse_surface('<form action="http://127.0.0.1:8000/ping"><input name=host></form>', BASE)
    assert [f["action"] for f in forms] == ["/ping"], forms
    forms, _, _ = RT._parse_surface('<form action="http://site.invalid/ping"><input name=host></form>',
                                    "http://site.invalid:80/")
    assert [f["action"] for f in forms] == ["/ping"], forms
    forms, _, _ = RT._parse_surface('<form action="https://site.invalid/ping"><input name=host></form>',
                                    "http://site.invalid/")
    assert forms == [], forms


def test_same_host_other_port_form_gives_no_row_end_to_end():
    # The fake server listens on an ephemeral port, never port 1.
    body = '<form action="http://127.0.0.1:1/ping"><input name=host></form>'
    out = run_recon(Site({"/": page("Ext", body)}))
    assert "command_injection" not in class_names(out), class_names(out)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok   " + name)
    print("\nok")
