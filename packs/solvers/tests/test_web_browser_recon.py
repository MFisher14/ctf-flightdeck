#!/usr/bin/env python3
"""Adversarial offline tests for ``solvers/web/browser_recon.py``."""

from __future__ import annotations

import importlib.util
import json
import threading
import time
from itertools import repeat
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "browser_recon_under_test", ROOT / "solvers" / "web" / "browser_recon.py")
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


def work_clock():
    """This thread's CPU seconds: the clock the near-cap bounds read (SH-10)."""
    return time.thread_time()


def check(name, condition, detail=None):
    if not condition:
        raise AssertionError(f"{name}: {detail!r}")
    print("PASS", name)


def flows(result):
    return [row for row in result["javascript"]["findings"] if row.get("kind") == "source_to_sink"]


def test_csp_order_intersection_and_meta_limits():
    headers = [
        ("Content-Security-Policy",
         "default-src 'self'; script-src 'self' 'nonce-AbC123==' 'strict-dynamic'; "
         "script-src https://ignored.example; connect-src https://api.example; "
         "frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types app dompurify"),
        ("Content-Security-Policy",
         "default-src https:; script-src-elem 'sha256-YWJjZGVmZ2hpamtsbW5vcA=='; "
         "script-src-attr 'none'; form-action 'self'; base-uri 'none'"),
        ("Content-Security-Policy-Report-Only",
         "script-src 'unsafe-inline' 'unsafe-eval'; connect-src *"),
    ]
    html = """
      <meta http-equiv="Content-Security-Policy"
            content="script-src 'unsafe-inline' 'wasm-unsafe-eval'; frame-ancestors *; report-uri /csp; base-uri 'self'">
      <meta http-equiv="Content-Security-Policy-Report-Only" content="script-src *">
    """
    got = B.analyze(html=html, headers=headers, base_url="https://App.Example:443/a")
    csp = got["csp"]
    check("CSP preserves two headers plus one enforcing meta policy",
          len(csp["enforced"]) == 3 and len(csp["report_only"]) == 1, csp)
    first = csp["enforced"][0]
    check("duplicate CSP directives use first-wins",
          first["directives"]["script-src"][0] == "'self'"
          and first["duplicates_ignored"] == ["script-src"], first)
    meta = csp["enforced"][2]
    check("meta limitations remove frame-ancestors and reporting",
          set(meta["meta_ignored_directives"]) == {"frame-ancestors", "report-uri"}
          and "base-uri" in meta["directives"], meta)
    elem = csp["effective_after_last_meta"]["script-src-elem"]
    check("multiple policies are represented as conjunctive clauses with fallbacks",
          elem["semantics"] == "all_policy_clauses_must_allow"
          and [x["via"] for x in elem["clauses"]] == ["script-src", "script-src-elem", "script-src"], elem)
    check("report-only unsafe keywords stay separate from enforcement",
          any(row.get("disposition") == "report-only" and row.get("keyword") == "'unsafe-eval'"
              for row in csp["findings"]), csp["findings"])
    check("nonce/hash/strict-dynamic and Trusted Types are recognized",
          first["features"]["nonces"] and first["features"]["strict_dynamic"]
          and first["features"]["require_trusted_types_for_script"]
          and csp["enforced"][1]["features"]["hashes"], csp["enforced"])
    check("case-sensitive nonce/hash source expressions are preserved",
          "'nonce-AbC123=='" in first["directives"]["script-src"], first["directives"])
    check("report-only meta is explicitly ignored",
          any(row.get("reason") == "report_only_not_supported_in_meta" for row in csp["ignored"]), csp["ignored"])
    check("base URL is parsed without fetching",
          got["offline"] is True and got["base_origin"] == {"scheme": "https", "host": "app.example", "port": 443}, got)


def test_direct_optional_minified_and_two_sources():
    js = ("function render(){const p=new URLSearchParams(window?.location?.search);"
          "const a=p?.get('q');const b=sessionStorage?.getItem('draft');"
          "const both=a+b;panel.innerHTML=both;}")
    got = B.analyze(js=js)
    found = flows(got)
    check("optional-chaining/minified aliases reach innerHTML", len(found) == 1, got["javascript"])
    kinds = {source["kind"] for source in found[0]["sources"]}
    check("two independent browser sources are preserved",
          any("location_search" in kind for kind in kinds) and "session_storage" in kinds, found[0])


def test_sources_and_sink_families():
    js = """
      function a(){ let x=location.hash; box.outerHTML=x; }
      function b(){ let x=document.cookie; document.write(x); }
      function c(){ let x=window.name; setTimeout(x, 1); }
      function d(){ let x=localStorage.getItem('x'); new DOMParser().parseFromString(x, 'text/html'); }
      function e(){ let x=document.referrer; range.createContextualFragment(x); }
      function f(){ let x=location.href; node.insertAdjacentHTML('beforeend', x); }
      function g(){ let x=location.search; $(node).html(x); }
      function h(){ let x=location.hash; const view=<div dangerouslySetInnerHTML={{__html:x}}/>; }
      function i(){ let x=location.search; frame.srcdoc=x; }
      function j(){ let x=location.hash; window.location.href=x; }
    """
    got = B.analyze(js=js)
    sinks = {row["sink"] for row in flows(got)}
    wanted = {"outerHTML", "document.write", "string_timer", "DOMParser.parseFromString",
              "Range.createContextualFragment", "insertAdjacentHTML", "jquery_html",
              "react_dangerouslySetInnerHTML", "srcdoc", "url_navigation"}
    check("requested source/sink families are recognized", wanted <= sinks, (wanted - sinks, got["javascript"]))


def test_sanitizers_safe_text_and_context_mismatch():
    js = """
      function safeHtml(){ const x=location.hash; const y=DOMPurify.sanitize(x); out.innerHTML=y; }
      function safeText(){ const x=document.cookie; out.textContent=x; document.createTextNode(x); }
      function mismatch(){ const x=location.search; const y=encodeURIComponent(x); out.innerHTML=y; }
      function mismatchTwo(){ const x=location.hash; const y=escapeHTML(x); eval(y); }
    """
    got = B.analyze(js=js)
    found = flows(got)
    check("obvious HTML sanitization suppresses dangerous HTML finding",
          not any(row["scope"] == "safeHtml" for row in found), found)
    check("textContent/createTextNode are recorded as safe flows",
          {row["sink"] for row in got["javascript"]["safe_flows"]} >= {"textContent", "createTextNode"},
          got["javascript"]["safe_flows"])
    check("sanitizer context mismatch remains a finding",
          len([row for row in found if row["sanitizer_mismatch"]]) == 2, found)


def test_postmessage_origin_check_and_transport_messages():
    js = """
      const ws = new WebSocket('/events');
      const es = new EventSource('/sse');
      window.addEventListener?.('message', (event) => {
        if (event.origin !== 'https://trusted.example') return;
        const value = event.data;
        panel.insertAdjacentHTML('beforeend', value);
      });
      ws.onmessage = (msg) => { output.innerHTML = msg.data; };
      es.onmessage = evt => output.outerHTML=evt.data;
      navigator.serviceWorker.addEventListener('message', function(sw) { view.outerHTML=sw.data; });
      const channel = new BroadcastChannel('updates');
      channel.onmessage = event => { area.innerHTML=event.data; };
    """
    got = B.analyze(js=js)
    found = flows(got)
    kinds = {source["kind"] for row in found for source in row["sources"]}
    check("postMessage guard is attached to the guarded flow",
          any(row["message_origin_checked"] and any(s["kind"] == "postmessage_data" for s in row["sources"])
              for row in found), found)
    check("WebSocket/SSE/service-worker/BroadcastChannel data sources are distinguished",
          {"websocket_message", "sse_message", "service_worker_message", "broadcast_channel_message"} <= kinds,
          (kinds, found))


def test_false_positive_declines():
    js = r'''
      const fake = "location.hash; box.innerHTML = document.cookie";
      // box.innerHTML = location.search;
      const rx = /document\.cookie.*innerHTML/;
      function shadowed(location, document) { const x=location.hash; document.body.innerHTML=x; }
      function reassigned(){ let x=location.hash; x="safe"; box.innerHTML=x; }
      function conditional(flag){ let x; if(flag) x=location.hash; box.innerHTML=x; }
      function ambiguous(){ const x=location.search; const y=maybeClean(x); box.innerHTML=y; }
      const outside=location.hash;
      function crossFunction(){ box.innerHTML=outside; }
      function sourceFunction(){ return location.hash; }
      function sinkFunction(value){ box.innerHTML=value; }
      sinkFunction(sourceFunction());
      function outer(){ const nested=location.hash; function inner(){ box.innerHTML=nested; } }
      function handlers(){ let saved; window.addEventListener('message', e=>{ saved=e.data; });
        button.onclick=()=>{ box.innerHTML=saved; }; }
      function shadowedSink(document){ const x=location.hash; document.write(x); }
    '''
    got = B.analyze(js=js)
    check("strings/comments/regex/shadowing/reassignment/branches/unknown calls/cross-functions decline",
          flows(got) == [], got["javascript"])


def test_templates_static_javascript_and_caps():
    html = """
      <div v-html="location.hash"></div>
      <section v-html="serverRenderedValue"></section>
      <p>{@html location.search}</p>
      <a href="javascript:doThing()">x</a>
      <script>function inline(){const x=location.hash; target.innerHTML=x;}</script>
      <script src="/assets/app.js"></script>
    """
    got = B.analyze(html=html)
    sinks = {row.get("sink") for row in got["javascript"]["findings"]}
    check("Vue/Svelte direct sources, inline script and static javascript URL are surfaced",
          {"vue_v_html", "svelte_html", "innerHTML", "javascript_url"} <= sinks,
          got["javascript"])
    check("unresolved framework expression is a lead, not a claimed source flow",
          any(row.get("kind") == "unresolved_template_sink" for row in got["javascript"]["declined"]),
          got["javascript"]["declined"])
    check("external scripts are leads only",
          got["javascript"]["external_script_leads"] == [{"src": "/assets/app.js", "line": 7}],
          got["javascript"]["external_script_leads"])
    huge = B.analyze(html="x" * (B.MAX_HTML + 5), js="x" * (B.MAX_JS + 5),
                     headers=[("X", "y")] * (B.MAX_HEADERS + 1))
    check("hard input caps are explicit", all(huge["truncated"][key] for key in ("html", "javascript", "headers")), huge["truncated"])


def test_dropped_javascript_and_csp_inputs_are_explicitly_incomplete():
    scripts = ["const harmless_%d = %d;" % (index, index)
               for index in range(B.MAX_INLINE_SCRIPTS)]
    scripts.append("function late(){const x=location.hash; out.innerHTML=x;}")
    got = B.analyze(js=scripts)
    check("JavaScript item beyond the public list cap is reported as truncated",
          got["truncated"]["javascript"] and flows(got) == [], got["truncated"])

    headers = [("Content-Security-Policy-Report-Only", "script-src 'self'")
               for _ in range(B.MAX_POLICIES)]
    headers.append(("Content-Security-Policy", "default-src 'none'"))
    got = B.analyze(headers=headers)
    kinds = {row.get("kind") for row in got["csp"]["findings"]}
    check("a CSP policy dropped at the policy cap marks the result incomplete",
          got["csp"]["input_incomplete"] and got["truncated"]["csp"]
          and any(row.get("reason") == "policy_cap" for row in got["csp"]["ignored"]),
          got["csp"])
    check("an unseen enforcing CSP cannot become a high-confidence absence claim",
          "csp_absent" not in kinds and "csp_report_only_without_enforcement" not in kinds,
          got["csp"]["findings"])

    beyond_header_cap = B.analyze(headers=[("X-Filler", "x")] * B.MAX_HEADERS + [
        ("Content-Security-Policy", "default-src 'none'")])
    kinds = {row.get("kind") for row in beyond_header_cap["csp"]["findings"]}
    check("a CSP header beyond the general header cap also suppresses absence",
          beyond_header_cap["truncated"]["headers"]
          and beyond_header_cap["csp"]["input_incomplete"]
          and "csp_absent" not in kinds, beyond_header_cap["csp"])

    report_meta = ('<meta http-equiv="Content-Security-Policy-Report-Only" '
                   'content="script-src \'self\'">')
    enforce_meta = ('<meta http-equiv="Content-Security-Policy" '
                    'content="default-src \'none\'">')
    beyond_meta_cap = B.analyze(html=report_meta * (B.MAX_POLICIES * 2) + enforce_meta)
    kinds = {row.get("kind") for row in beyond_meta_cap["csp"]["findings"]}
    check("a CSP meta element beyond the inventory cap suppresses absence",
          beyond_meta_cap["csp"]["input_incomplete"]
          and beyond_meta_cap["truncated"]["csp"]
          and "csp_absent" not in kinds, beyond_meta_cap["csp"])


def test_json_serializable_and_no_payload_fields():
    got = B.analyze(js="function f(){const x=location.hash; out.innerHTML=x;}")
    encoded = json.dumps(got, sort_keys=True)
    check("result is JSON serializable", '"offline": true' in encoded)
    forbidden = ("payload", "exploit", "request_body", "fetch_url")
    check("recon result contains no exploit-generation fields",
          not any(f'"{word}"' in encoded for word in forbidden), encoded[:1000])


def test_cooperative_stop_deadline_and_unbounded_header_iterables():
    payload = "const x=location.hash; out.innerHTML=x;"
    stop = threading.Event()
    stop.set()
    stopped = B.analyze(js=payload, headers=repeat(("X-Test", "x")), stop=stop)
    check("pre-set stop skips offline browser analysis",
          stopped["stopped_early"] and flows(stopped) == [], stopped)

    expired = B.analyze(js=payload, deadline=time.time() - 1)
    check("expired deadline skips offline browser analysis",
          expired["stopped_early"] and flows(expired) == [], expired)

    bounded = B.analyze(headers=repeat(("X-Test", "x")))
    check("an arbitrary header iterable is consumed only to the public cap",
          bounded["truncated"]["headers"], bounded["truncated"])


def test_nested_near_cap_javascript_stops_during_preprocessing():
    # Every opening brace encloses almost the full 768 KiB input.  Re-scanning
    # for each close, then masking every nested body in every parent, used to
    # make this shape superlinear before the first cooperative stop check.
    count = B.MAX_SCOPES - 1
    openings = "".join(f"function nested_{index}(){{" for index in range(count))
    closings = "}" * count
    nested = openings + ";" * (B.MAX_JS - len(openings) - len(closings)) + closings
    check("nested JavaScript regression fixture reaches the exact public cap",
          len(nested) == B.MAX_JS, len(nested))

    class StopAfterPolls:
        def __init__(self, polls):
            self.polls = polls
            self.calls = 0

        def is_set(self):
            self.calls += 1
            return self.calls >= self.polls

    # SH-10: each bound is on this thread's CPU time (work_clock), not the wall clock: under the suite's load
    # the 3 s pass was seen at 4.85 s of wall time. A superlinear pass, or a stop/deadline observed late,
    # still costs more CPU than the bound. The analysis is single-threaded; thread CPU leaves out any other
    # thread in the process (a fake server another test left running).
    stop = StopAfterPolls(8)
    started = work_clock()
    stopped = B.analyze(js=nested, stop=stop)
    elapsed = work_clock() - started
    check("near-cap nested preprocessing observes a mid-pass stop promptly (CPU s)",
          stopped["stopped_early"] and flows(stopped) == [] and elapsed < 1.5,
          {"elapsed": elapsed, "polls": stop.calls, "truncated": stopped["truncated"]})

    started = work_clock()
    expired = B.analyze(js=nested, deadline=time.time() + 0.01)
    elapsed = work_clock() - started
    check("near-cap nested preprocessing observes a mid-pass deadline promptly (CPU s)",
          expired["stopped_early"] and flows(expired) == [] and elapsed < 1.5,
          {"elapsed": elapsed, "truncated": expired["truncated"]})

    started = work_clock()
    completed = B.analyze(js=nested)
    elapsed = work_clock() - started
    check("near-cap nested preprocessing completes within the bounded linear pass (CPU s)",
          not completed["stopped_early"]
          and completed["javascript"]["scopes_analyzed"] == B.MAX_SCOPES
          and not completed["truncated"]["scopes"]
          and not completed["truncated"]["preprocessing"]
          and elapsed < 3.0,
          {"elapsed": elapsed, "scopes": completed["javascript"]["scopes_analyzed"],
           "truncated": completed["truncated"]})


def main():
    test_csp_order_intersection_and_meta_limits()
    test_direct_optional_minified_and_two_sources()
    test_sources_and_sink_families()
    test_sanitizers_safe_text_and_context_mismatch()
    test_postmessage_origin_check_and_transport_messages()
    test_false_positive_declines()
    test_templates_static_javascript_and_caps()
    test_dropped_javascript_and_csp_inputs_are_explicitly_incomplete()
    test_json_serializable_and_no_payload_fields()
    test_cooperative_stop_deadline_and_unbounded_header_iterables()
    test_nested_near_cap_javascript_stops_during_preprocessing()
    print("PASS all offline browser/CSP reconnaissance tests")


if __name__ == "__main__":
    main()
