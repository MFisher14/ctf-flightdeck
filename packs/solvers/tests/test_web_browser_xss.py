#!/usr/bin/env python3
"""Tests for the B-122 browser-executed reflected/DOM XSS engine (solvers/web/browser_xss.py).

The pure probe builders are tested directly and offline. The confirmation path and the engine entry
are driven against a *synthetic worker* that returns ``ctf.web_browser`` result records (the same
``Evaluation``/``Observation`` shapes B-150's real worker returns), so the suite never starts a real
browser and never leaves loopback. The one end-to-end path that needs a real browser harness is
marked ``needs_tool`` so it reports as not run, never silently green.
"""
from __future__ import annotations

import sys
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import ctf  # noqa: E402  (installs the solvers meta-path finder)
from ctf import event as _event, web_browser as _wb  # noqa: E402
from ctf.result import SolverResult  # noqa: E402
from solvers.web import browser_xss as bx  # noqa: E402
import datetime as _dt  # noqa: E402


# ---- a synthetic browser worker ----------------------------------------------------------------
class FakeWorker:
    """Stands in for ctf.web_browser.BrowserWorker. ``responder(url)`` returns the Observations the
    page produced (or raises to simulate a scope/worker error). Records every URL it was asked to
    evaluate so a test can assert which probes were fired."""

    def __init__(self, responder):
        self._responder = responder
        self.seen: list[str] = []
        self.closed = False

    def evaluate(self, url, script, *, observe=(), budget_ms=None, max_events=None):
        self.seen.append(url)
        outcome = self._responder(url)
        if isinstance(outcome, BaseException):
            raise outcome
        obs = tuple(outcome)
        return _wb.Evaluation(ok=True, url=url, script=script, observations=obs)

    def close(self):
        self.closed = True


def _dialog(marker):
    return _wb.Observation(kind="dialog", detail={"type": "alert", "message": marker})


def _console(text):
    return _wb.Observation(kind="console", detail={"level": "log", "text": text})


def _profile(prefixes=("CSCTF",)):
    return _event.parse({
        "slug": "xss-test", "name": "xss test",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.suite-platform.test"},
        "flag": {"prefixes": list(prefixes)},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["127.0.0.0/8", "localhost", "*.test"]},
    }, src="tests/test_web_browser_xss.py")


TARGET = "http://127.0.0.1:9999/app"


# ==================================================================================================
#  pure probe builders
# ==================================================================================================
def test_make_marker_is_unique_and_prefixed():
    a, b = bx.make_marker(), bx.make_marker()
    assert a.startswith(bx.MARKER_PREFIX) and b.startswith(bx.MARKER_PREFIX)
    assert a != b


def test_payloads_for_rejects_unknown_context():
    with pytest.raises(bx.BrowserXssError):
        bx.payloads_for("not_a_context")
    assert all("{m}" in t for t in bx.payloads_for("html_body"))


def test_build_probe_url_query_encodes_payload_into_param():
    url = bx.build_probe_url(TARGET, "<script>alert('X')</script>", param="q", placement="query")
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert q["q"] == "<script>alert('X')</script>"   # decodes back to the exact payload


def test_build_probe_url_fragment_places_payload_in_fragment():
    url = bx.build_probe_url(TARGET, "<img onerror=alert(1)>", param="h", placement="fragment")
    frag = urllib.parse.urlsplit(url).fragment
    assert frag.startswith("h=")
    assert urllib.parse.unquote(frag[2:]) == "<img onerror=alert(1)>"


def test_build_probe_url_refuses_non_http_base_and_missing_param():
    with pytest.raises(bx.BrowserXssError):
        bx.build_probe_url("javascript:alert(1)", "x", param="q")
    with pytest.raises(bx.BrowserXssError):
        bx.build_probe_url(TARGET, "x", placement="query")   # query needs a param


def test_reflection_probes_cover_params_and_contexts_and_embed_marker():
    probes = bx.reflection_probes(TARGET, params=["q", "s"],
                                  contexts=["html_body", "html_attr_double"])
    # one probe per (param x context x template); marker is unique per probe and present in the URL.
    assert len({p.marker for p in probes}) == len(probes)
    for p in probes:
        assert p.origin == "reflection" and p.placement == "query"
        assert p.marker in p.url
        assert p.param in ("q", "s")


def test_reflection_probes_use_default_params_when_none_given_and_respect_limit():
    probes = bx.reflection_probes(TARGET, params=[], contexts=["html_body"], limit=3)
    assert len(probes) == 3
    assert {p.param for p in probes} <= set(bx.DEFAULT_PARAMS)


def test_build_probe_url_replaces_an_existing_value_of_the_param_and_keeps_others():
    url = bx.build_probe_url("http://h/a?q=1&z=2", "X", param="q", placement="query")
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert q["q"] == ["X"]          # the stale q=1 is dropped, not duplicated
    assert q["z"] == ["2"]          # unrelated params survive


def test_dom_flow_probes_map_source_and_sink_with_exact_counts():
    flows = [
        {"source": "location_hash", "sink_context": "html", "mitigated": False},     # reachable
        {"source": "location_search", "sink_context": "script", "mitigated": False}, # reachable
        {"source": "document_cookie", "sink_context": "html", "mitigated": False},   # not URL-controllable
    ]
    probes = bx.dom_flow_probes(TARGET, flows, params=["x"])
    assert all(p.origin == "dom_flow" for p in probes)
    by_kind = {}
    for p in probes:
        by_kind.setdefault((p.context, p.placement), []).append(p)
    # hash -> html: (bare fragment + #x=) x 2 dom_html templates = 4 probes, all in the fragment.
    # search -> script: ?x= x 2 dom_script templates = 2 probes.  The cookie flow adds nothing.
    assert {k: len(v) for k, v in by_kind.items()} == {("dom_html", "fragment"): 4,
                                                       ("dom_script", "query"): 2}
    assert len(probes) == 6


def test_dom_flow_probes_skip_a_mitigated_flow():
    # The same reachable shape, but a sanitizer covers the sink: no probe at all.
    mitigated = [{"source": "location_hash", "sink_context": "html", "mitigated": True}]
    assert bx.dom_flow_probes(TARGET, mitigated, params=["x"]) == ()
    unmitigated = [dict(mitigated[0], mitigated=False)]
    assert bx.dom_flow_probes(TARGET, unmitigated, params=["x"])     # the control fires


def test_dom_flow_probes_for_a_hash_flow_include_the_bare_fragment():
    # location.hash is usually read raw: one probe puts the payload as the whole fragment (no name=).
    flows = [{"source": "location_hash", "sink_context": "html", "mitigated": False}]
    probes = bx.dom_flow_probes(TARGET, flows, params=["x"])
    bare = [p for p in probes if p.param is None]
    assert len(bare) == 2              # one per dom_html template
    for p in bare:
        frag = urllib.parse.urlsplit(p.url).fragment
        assert urllib.parse.unquote(frag) == p.payload     # the raw payload, no "x=" prefix
        assert p.placement == "fragment"


def test_reflection_probes_fragment_placement_and_bad_placement():
    probes = bx.reflection_probes(TARGET, params=["q"], contexts=["html_body"], placement="fragment")
    assert probes and all(p.placement == "fragment" for p in probes)
    for p in probes:
        parts = urllib.parse.urlsplit(p.url)
        assert parts.query == ""
        assert urllib.parse.unquote(parts.fragment) == f"q={p.payload}"
    with pytest.raises(bx.BrowserXssError):
        bx.reflection_probes(TARGET, params=["q"], placement="body")


def test_probes_from_source_traces_hash_to_innerhtml_flow():
    js = "var h = location.hash.slice(1); document.getElementById('o').innerHTML = h;"
    probes = bx.probes_from_source(TARGET, js, params=["o"])
    assert probes and any(p.placement == "fragment" and p.context == "dom_html" for p in probes)


# ==================================================================================================
#  confirmation against the synthetic worker
# ==================================================================================================
def _one_probe(marker="XSSPROOFdeadbeef00"):
    return bx.XssProbe(url=f"{TARGET}?q=x#{marker}", marker=marker, context="html_body",
                       placement="query", param="q", origin="reflection", payload="p")


def test_confirm_reports_executed_when_dialog_carries_the_probe_marker():
    probe = _one_probe()
    worker = FakeWorker(lambda url: [_dialog(probe.marker)])
    res = bx.confirm(worker, probe)
    assert res.ok and res.executed
    assert probe.marker in res.reason


def test_confirm_rejects_a_dialog_with_a_different_marker():
    # Guards against "any dialog counts": a page alert that is not ours must not be a confirmation.
    probe = _one_probe("XSSPROOFaaaaaaaa11")
    worker = FakeWorker(lambda url: [_dialog("XSSPROOFbbbbbbbb22")])
    res = bx.confirm(worker, probe)
    assert res.ok and not res.executed


def test_confirm_rejects_a_dialog_that_only_echoes_the_probe_url():
    # alert(location.href) on a page that never runs our payload: the marker is a substring of the
    # dialog text, but the payload did not execute.
    probe = _one_probe()
    worker = FakeWorker(lambda url: [_dialog(url)])
    res = bx.confirm(worker, probe)
    assert probe.marker in probe.url
    assert res.ok and not res.executed


def test_confirm_not_executed_when_no_dialog():
    probe = _one_probe()
    worker = FakeWorker(lambda url: [_console("just a log line")])
    res = bx.confirm(worker, probe)
    assert res.ok and not res.executed


def test_confirm_scans_observations_for_event_flags():
    probe = _one_probe()
    ff = __import__("ctf.flagfmt", fromlist=["for_profile"]).for_profile(_profile())
    worker = FakeWorker(lambda url: [_console("leaked CSCTF{dom_xss_pop} to console")])
    res = bx.confirm(worker, probe, flag_scan=ff.find_flags)
    assert "CSCTF{dom_xss_pop}" in res.flags


def test_confirm_failed_evaluation_is_not_ok():
    probe = _one_probe()

    class _W:
        def evaluate(self, url, script, *, observe=(), budget_ms=None, max_events=None):
            return _wb.Evaluation(ok=False, url=url, script=script, reason="harness crashed")

        def close(self):
            pass

    res = bx.confirm(_W(), probe)
    assert not res.ok and not res.executed and "harness crashed" in res.reason


def test_confirm_propagates_browser_unavailable():
    probe = _one_probe()
    worker = FakeWorker(lambda url: _wb.BrowserUnavailable("no harness", tool="browser-harness"))
    with pytest.raises(_wb.BrowserUnavailable):
        bx.confirm(worker, probe)


def test_confirm_turns_scope_error_into_a_failed_probe_not_a_raise():
    probe = _one_probe()
    from ctf import scope
    worker = FakeWorker(lambda url: scope.OutOfScope("target not in scope"))
    res = bx.confirm(worker, probe)
    assert not res.ok and not res.executed and "OutOfScope" in res.reason


def test_confirm_transport_error_is_a_failed_probe():
    probe = _one_probe()
    res = bx.confirm(FakeWorker(lambda url: BrokenPipeError("harness pipe closed")), probe)
    assert not res.ok and not res.executed and "BrokenPipeError" in res.reason


def test_confirm_lets_a_worker_contract_error_propagate():
    # B-150 raises ValueError for a script / observation kind outside its closed registries. That is a
    # drift between this engine and the worker: it must be loud, not a quiet "failed probe" that turns
    # every run into "blocked".
    probe = _one_probe()
    worker = FakeWorker(lambda url: ValueError("unknown fixed script 'observe_xss_bogus'"))
    with pytest.raises(ValueError, match="unknown fixed script"):
        bx.confirm(worker, probe)


def test_run_probes_stops_on_first_confirmed_execution():
    probes = bx.reflection_probes(TARGET, params=["q"], contexts=["html_body"])
    hot = probes[1].marker

    def responder(url):
        return [_dialog(hot)] if hot in url else []

    worker = FakeWorker(responder)
    results = bx.run_probes(worker, probes, stop_on_first=True)
    assert results[-1].executed
    # stopped at the first firing probe, did not evaluate the rest.
    assert len(results) == 2


def test_run_probes_stops_on_a_flag_even_without_a_dialog():
    probes = bx.reflection_probes(TARGET, params=["q"], contexts=["html_body"])
    assert len(probes) == 3
    ff = __import__("ctf.flagfmt", fromlist=["for_profile"]).for_profile(_profile())
    worker = FakeWorker(lambda url: [_console("CSCTF{seen_in_console}")])
    results = bx.run_probes(worker, probes, stop_on_first=True, flag_scan=ff.find_flags)
    assert len(results) == 1 and len(worker.seen) == 1
    assert not results[0].executed and results[0].flags == ("CSCTF{seen_in_console}",)


def test_run_probes_without_stop_evaluates_all():
    probes = bx.reflection_probes(TARGET, params=["q"], contexts=["html_body"])
    worker = FakeWorker(lambda url: [])
    results = bx.run_probes(worker, probes, stop_on_first=False)
    assert len(results) == len(probes) and not any(r.executed for r in results)


# ==================================================================================================
#  the engine entry
# ==================================================================================================
def test_solve_blocked_without_target(tmp_path):
    r = bx.solve(tmp_path, _profile())
    assert isinstance(r, SolverResult) and r.status == "blocked"
    assert "no target" in r.notes


def test_solve_blocked_on_unknown_context(tmp_path):
    r = bx.solve(tmp_path, _profile(), target=TARGET, contexts="bogus_ctx")
    assert r.status == "blocked" and "context" in r.notes


def test_solve_unsure_when_a_vector_fires_but_no_flag(tmp_path):
    def responder(url):
        # the reflected marker in the probe URL "executes": echo it back as a dialog.
        for m in _markers_in(url):
            return [_dialog(m)]
        return []

    worker = FakeWorker(responder)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker)
    assert r.status == "unsure"
    assert any(e.kind == "oracle" for e in r.evidence)
    assert not r.flags


def test_solve_solved_when_observation_carries_a_flag(tmp_path):
    worker = FakeWorker(lambda url: [_console("CSCTF{reflected_into_dom}")])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker)
    assert r.status == "solved"
    assert "CSCTF{reflected_into_dom}" in r.flags
    assert [e.kind for e in r.evidence] == ["match"]
    # no dialog fired, so no oracle proof may be claimed.
    assert not any(e.kind == "oracle" for e in r.evidence)


def test_solve_solved_with_a_dialog_records_the_oracle_proof(tmp_path):
    def responder(url):
        return [_dialog(m) for m in _markers_in(url)] + [_console("CSCTF{popped_and_read}")]

    worker = FakeWorker(responder)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker)
    assert r.status == "solved" and r.flags == ("CSCTF{popped_and_read}",)
    assert [e.kind for e in r.evidence] == ["match", "oracle"]


def test_solve_mixed_failed_and_ok_probes_is_none_not_blocked(tmp_path):
    from ctf import scope
    first = {"done": False}

    def responder(url):
        if not first["done"]:
            first["done"] = True
            return scope.OutOfScope("one probe refused")
        return []

    worker = FakeWorker(responder)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker, stop_on_first=False)
    assert len(worker.seen) == 3
    assert r.status == "none"


def test_solve_sends_exactly_max_probes_urls(tmp_path):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, max_probes=5, worker=worker,
                 stop_on_first=False)
    assert r.status == "none"
    assert len(worker.seen) == 5
    assert len(set(worker.seen)) == 5


@pytest.mark.parametrize("bad", [0, -1, bx.MAX_PROBES + 1, "10", True])
def test_solve_rejects_max_probes_outside_the_range(tmp_path, bad):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", max_probes=bad, worker=worker)
    assert r.status == "blocked" and "max_probes" in r.notes
    assert worker.seen == []


def test_solve_accepts_max_probes_at_the_cap(tmp_path):
    worker = FakeWorker(lambda url: [])
    many = ",".join(f"p{i}" for i in range(12))    # 12 params x 6 default-context payloads = 72 > cap
    r = bx.solve(tmp_path, _profile(), target=TARGET, params=many, max_probes=bx.MAX_PROBES,
                 worker=worker, stop_on_first=False)
    assert r.status == "none" and len(worker.seen) == bx.MAX_PROBES


@pytest.mark.parametrize("bad", [0, _wb.MAX_BUDGET_MS + 1])
def test_solve_rejects_budget_outside_the_worker_range(tmp_path, bad):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", budget_ms=bad, worker=worker)
    assert r.status == "blocked" and "budget_ms" in r.notes and worker.seen == []


def test_solve_rejects_an_unknown_option(tmp_path):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", worker=worker, paramz="q")
    assert r.status == "blocked" and "paramz" in r.notes and worker.seen == []


def test_solve_passes_placement_through_to_the_reflection_sweep(tmp_path):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 placement="fragment", worker=worker, stop_on_first=False)
    assert r.status == "none" and len(worker.seen) == 3
    for url in worker.seen:
        parts = urllib.parse.urlsplit(url)
        assert parts.query == "" and parts.fragment.startswith("q=")
    bad = bx.solve(tmp_path, _profile(), target=TARGET, params="q", placement="header",
                   worker=FakeWorker(lambda url: []))
    assert bad.status == "blocked" and "placement" in bad.notes


def test_solve_runs_every_dom_flow_probe_before_the_reflection_guesses(tmp_path):
    # No params: the reflection sweep alone would fill the whole budget with DEFAULT_PARAMS guesses.
    js = "var h = location.hash.slice(1); document.body.innerHTML = h;"
    (tmp_path / "app.js").write_text(js)
    expected = bx.probes_from_source(TARGET, js)
    assert len(expected) == 2 * (1 + len(bx.DEFAULT_PARAMS))     # bare + one per default param
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, source="app.js", worker=worker,
                 stop_on_first=False)
    assert r.status == "none"
    assert len(worker.seen) == bx.MAX_PROBES
    dom = [u for u in worker.seen if urllib.parse.urlsplit(u).fragment]
    assert len(dom) == len(expected)                       # every traced-flow probe was sent ...
    assert worker.seen[:len(expected)] == dom              # ... and sent first


def test_page_inventory_mines_params_and_inline_script():
    page = (
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        "<form action='/search?lang=en'><input name='term'><textarea name=comment></textarea></form>"
        "<a href='/view?id=3&amp;tab=info'>x</a><script src='/ext.js?v=1'></script>"
        "<script>const p = new URLSearchParams(location.search); el.innerHTML = p.get('greet');</script>"
    )
    names, js = bx.page_inventory(page)
    assert set(names) == {"lang", "term", "comment", "id", "tab", "v", "greet"}
    assert "URLSearchParams" in js and "ext.js" not in js


def test_page_inventory_ignores_map_get_without_url_params():
    names, _js = bx.page_inventory("<script>const m = new Map(); m.get('secret');</script>")
    assert names == ()


def test_solve_uses_params_mined_from_a_saved_page(tmp_path):
    (tmp_path / "index.html").write_text("<form><input name='needle'></form>")
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, page="index.html", contexts="html_body",
                 worker=worker, stop_on_first=False)
    assert r.status == "none" and len(worker.seen) == 3
    for url in worker.seen:
        assert list(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)) == ["needle"]


def test_solve_traces_inline_script_of_a_saved_page(tmp_path):
    (tmp_path / "index.html").write_text(
        "<div id=o></div><script>document.getElementById('o').innerHTML = location.hash.slice(1);"
        "</script>")
    worker = FakeWorker(lambda url: [])
    bx.solve(tmp_path, _profile(), target=TARGET, page="index.html", worker=worker,
             stop_on_first=False, max_probes=2)
    # the two first probes are the bare-fragment DOM probes from the inline script's hash flow.
    assert len(worker.seen) == 2
    assert all(urllib.parse.urlsplit(u).fragment and not urllib.parse.urlsplit(u).query
               for u in worker.seen)


def test_solve_blocked_on_page_outside_challenge_dir(tmp_path):
    r = bx.solve(tmp_path, _profile(), target=TARGET, page="../x.html",
                 worker=FakeWorker(lambda url: []))
    assert r.status == "blocked" and "outside the challenge dir" in r.notes


def test_solve_none_when_nothing_fires(tmp_path):
    worker = FakeWorker(lambda url: [_console("harmless")])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker, stop_on_first=False)
    assert r.status == "none"


def test_solve_blocked_when_every_probe_is_out_of_scope(tmp_path):
    from ctf import scope
    worker = FakeWorker(lambda url: scope.OutOfScope("nope"))
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker)
    assert r.status == "blocked" and "no probe could be evaluated" in r.notes


def test_solve_blocked_when_browser_unavailable_by_default(tmp_path, monkeypatch):
    # No CTF_BROWSER_HARNESS configured -> availability() is False -> blocked naming the tool.
    monkeypatch.delenv("CTF_BROWSER_HARNESS", raising=False)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body")
    assert r.status == "blocked" and "browser-harness" in r.notes


def test_solve_uses_a_dom_flow_source_file(tmp_path):
    js = "var h = location.hash.slice(1); document.body.innerHTML = h;"
    (tmp_path / "app.js").write_text(js)
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="x", source="app.js",
                 worker=worker, stop_on_first=False)
    # a dom-flow (fragment) probe must have been fired at the browser.
    assert any("#" in u for u in worker.seen)
    assert r.status in ("none", "unsure")


def test_solve_blocked_on_source_outside_challenge_dir(tmp_path):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, source="../escape.js", worker=worker)
    assert r.status == "blocked" and "outside the challenge dir" in r.notes


def _markers_in(url):
    import re
    return re.findall(rf"{bx.MARKER_PREFIX}[0-9a-f]+", url)


# ==================================================================================================
#  B-150's real BrowserWorker, driven through its own transport seam (no browser, no process)
# ==================================================================================================
class StepClock:
    """A hand-advanced clock (rule 16): the worker's budgets never touch wall time."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class ScriptedTransport(_wb.Transport):
    """An in-memory harness speaking B-150's protocol: answers hello with ready and each evaluate
    with ``responder(message)`` -> a list of observation rows. Records every message it was sent."""

    def __init__(self, responder):
        self.responder = responder
        self.sent = []
        self.outbox = []
        self.closed = False

    def send(self, obj):
        self.sent.append(dict(obj))
        if obj.get("op") == "hello":
            self.outbox.append({"op": "ready", "version": _wb.PROTOCOL_VERSION})
        elif obj.get("op") == "evaluate":
            self.outbox.append({"id": obj["id"], "ok": True,
                                "observations": list(self.responder(obj))})

    def recv(self, deadline=None):
        return self.outbox.pop(0) if self.outbox else None

    def close(self):
        self.closed = True

    def evaluates(self):
        return [m for m in self.sent if m.get("op") == "evaluate"]


def _echo_marker_dialog(msg):
    return [{"kind": "dialog", "type": "alert", "message": m} for m in _markers_in(msg["url"])]


def _real_worker(profile, transport):
    return bx.make_worker(profile, config=_wb.BrowserConfig(harness="x", sandbox_mode="none"),
                          transport_factory=lambda cfg, clk: transport, clock=StepClock())


def test_real_worker_dialog_with_marker_is_unsure(tmp_path):
    transport = ScriptedTransport(_echo_marker_dialog)
    worker = _real_worker(_profile(), transport)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker)
    assert r.status == "unsure" and any(e.kind == "oracle" for e in r.evidence)
    sent = transport.evaluates()
    assert len(sent) == 1
    # what crossed B-150's allowlists: its closed script registry and observation kinds.
    assert sent[0]["script"] == bx.ORACLE_SCRIPT and bx.ORACLE_SCRIPT in _wb.FIXED_SCRIPTS
    assert "dialog" in sent[0]["observe"]
    assert set(sent[0]["observe"]) <= set(_wb.OBSERVATION_KINDS)


def test_real_worker_out_of_scope_target_is_blocked_before_any_navigation(tmp_path):
    transport = ScriptedTransport(_echo_marker_dialog)
    narrow = _event.parse({
        "slug": "xss-narrow", "name": "xss narrow",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.suite-platform.test"},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["10.99.0.0/16"]},
    }, src="tests/test_web_browser_xss.py")
    worker = _real_worker(narrow, transport)
    r = bx.solve(tmp_path, narrow, target=TARGET, params="q", contexts="html_body", worker=worker)
    assert r.status == "blocked" and "OutOfScope" in r.notes
    assert transport.evaluates() == []           # the harness was never told to navigate


def test_real_worker_flag_in_console_is_solved(tmp_path):
    transport = ScriptedTransport(lambda msg: [{"kind": "console", "level": "log",
                                                "text": "CSCTF{real_worker_flag}"}])
    worker = _real_worker(_profile(), transport)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body",
                 worker=worker)
    assert r.status == "solved" and r.flags == ("CSCTF{real_worker_flag}",)


def test_solve_builds_its_worker_with_scope_bound_to_the_given_profile(tmp_path, monkeypatch):
    # CTF_EVENT names an event that does not exist and nothing is pinned: the worker's *default*
    # scope check would load no profile and refuse everything.  solve() must check scope against the
    # profile it was handed, so the loopback target is allowed.
    from ctf import scope
    monkeypatch.setattr(scope, "_pinned", None)
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b122")
    monkeypatch.delenv("CTF_BROWSER_SANDBOX", raising=False)
    transport = ScriptedTransport(_echo_marker_dialog)
    monkeypatch.setattr(_wb, "availability", lambda config=None: (True, "synthetic harness"))
    monkeypatch.setattr(_wb, "default_transport_factory", lambda cfg, clk: transport)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body")
    assert r.status == "unsure", r.notes
    assert len(transport.evaluates()) == 1 and transport.closed      # the owned worker is closed


def _owned_worker_env(monkeypatch, sandbox):
    """Make solve() build its own B-150 worker over a scripted transport, under ``sandbox``."""
    from ctf import scope
    monkeypatch.setattr(scope, "_pinned", None)
    monkeypatch.setenv("CTF_BROWSER_SANDBOX", sandbox)
    transport = ScriptedTransport(_echo_marker_dialog)
    built = []

    def factory(cfg, clk):
        built.append(cfg.sandbox_mode)
        return transport

    monkeypatch.setattr(_wb, "availability", lambda config=None: (True, "synthetic harness"))
    monkeypatch.setattr(_wb, "default_transport_factory", factory)
    return transport, built


def test_solve_refuses_an_unsandboxed_owned_worker(tmp_path, monkeypatch):
    # B-150 allows CTF_BROWSER_SANDBOX=none; this engine runs target-authored JS only in a sandbox.
    transport, built = _owned_worker_env(monkeypatch, "none")
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body")
    assert r.status == "blocked" and "CTF_BROWSER_SANDBOX='none'" in r.notes
    assert transport.evaluates() == [] and built == []     # no harness started, nothing loaded


@pytest.mark.parametrize("sandbox", ["seatbelt", "docker"])
def test_solve_builds_its_owned_worker_under_the_configured_sandbox(tmp_path, monkeypatch, sandbox):
    # The control for the refusal above: a real sandbox mode runs, and the worker gets that config.
    transport, built = _owned_worker_env(monkeypatch, sandbox)
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body")
    assert r.status == "unsure", r.notes
    assert built == [sandbox] and len(transport.evaluates()) == 1


def test_solve_blocked_on_a_bad_sandbox_mode_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_BROWSER_SANDBOX", "wide-open")
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body")
    assert r.status == "blocked" and "not a sandbox mode" in r.notes


def test_docker_sandbox_argv_never_pulls_a_missing_image():
    # docker run pulls a missing image by default; the browser image is a human install step.
    cfg = _wb.BrowserConfig(harness="h", sandbox_mode="docker", docker_image="csctf-browser:9")
    argv = _wb.sandbox_launch_argv(cfg, ["/opt/harness"])
    assert "--pull=never" in argv
    assert argv.index("--pull=never") < argv.index("csctf-browser:9")   # an option, not a harness arg


# ---- CLI-shaped option values (the CLI JSON-decodes every --opt value) ----------------------------
def test_solve_takes_a_numeric_param_from_the_cli(tmp_path):
    # `--opt params=5` arrives as the int 5: a param literally named "5", not a crash.
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params=5, contexts="html_body",
                 worker=worker, stop_on_first=False)
    assert r.status == "none" and len(worker.seen) == 3
    for url in worker.seen:
        assert list(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)) == ["5"]


def test_solve_takes_a_json_list_of_params(tmp_path):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, params=["a", 7], contexts="html_body",
                 worker=worker, stop_on_first=False)
    assert r.status == "none"
    names = {next(iter(urllib.parse.parse_qs(urllib.parse.urlsplit(u).query))) for u in worker.seen}
    assert names == {"a", "7"}


@pytest.mark.parametrize("opt, bad", [("params", True), ("params", {"q": 1}), ("params", [["q"]]),
                                      ("contexts", False)])
def test_solve_blocks_an_option_value_of_the_wrong_type(tmp_path, opt, bad):
    worker = FakeWorker(lambda url: [])
    r = bx.solve(tmp_path, _profile(), target=TARGET, worker=worker, **{opt: bad})
    assert r.status == "blocked" and f"{opt}=" in r.notes and worker.seen == []


@pytest.mark.parametrize("bad", ["fake-worker", 5, ["w"]])
def test_solve_blocks_a_non_worker_worker_option(tmp_path, monkeypatch, bad):
    # `--opt worker=...` from the CLI is never a worker object; it must not crash at evaluate nor
    # silently fall through to building a worker.
    transport, built = _owned_worker_env(monkeypatch, "seatbelt")
    r = bx.solve(tmp_path, _profile(), target=TARGET, params="q", contexts="html_body", worker=bad)
    assert r.status == "blocked" and "worker=" in r.notes
    assert built == [] and transport.evaluates() == []


# ---- page inventory edges ---------------------------------------------------------------------
def test_page_inventory_caps_mined_params():
    fields = "".join(f"<input name='f{i:02d}'>" for i in range(bx.MAX_MINED_PARAMS + 9))
    names, _js = bx.page_inventory(f"<form>{fields}</form>")
    assert names == tuple(f"f{i:02d}" for i in range(bx.MAX_MINED_PARAMS))


def test_page_inventory_drops_the_http_header_block():
    # Headers are not page content: tag-like text in a header must not be mined, for both the CRLF
    # and the bare-LF separators; a header block with no body yields nothing.
    for sep in ("\r\n", "\n"):
        raw = (f"HTTP/1.1 200 OK{sep}X-Debug: <input name=fromheader>{sep}{sep}"
               "<form><input name='frombody'></form>")
        names, _js = bx.page_inventory(raw)
        assert names == ("frombody",), sep
    assert bx.page_inventory("HTTP/1.1 302 Found\r\nX-Debug: <input name=fromheader>")[0] == ()
    # a bare page (no status line) is read whole
    assert bx.page_inventory("<input name=bare>")[0] == ("bare",)


def test_page_inventory_ignores_the_body_of_an_external_script_tag():
    # A browser ignores the inline text of <script src=...>; so must the tracer and the miner.
    page = ("<script src='/a.js'>var p = new URLSearchParams(location.search);"
            "document.body.innerHTML = p.get('srcbody');</script>")
    names, js = bx.page_inventory(page)
    assert names == ()
    assert js == ""


# ==================================================================================================
#  the one path that needs a real browser harness (reports NOT RUN without it)
# ==================================================================================================
@pytest.mark.needs_tool("browser-harness")
def test_real_browser_round_trip(tmp_path):  # pragma: no cover - runs only where a harness is installed
    # With a real sandboxed harness configured (CTF_BROWSER_HARNESS), solve must drive it against a
    # loopback page that reflects ?q= raw into the body, and the dialog oracle must fire.
    import http.server
    import threading

    class Reflect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("q", [""])[0]
            body = f"<html><body>hello {q}</body></html>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    ok, detail = _wb.availability()
    assert ok, f"needs_tool gate should ensure a harness is resolvable: {detail}"
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Reflect)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        target = f"http://127.0.0.1:{srv.server_address[1]}/app"
        r = bx.solve(tmp_path, _profile(), target=target, params="q", contexts="html_body")
    finally:
        srv.shutdown()
        srv.server_close()
    assert isinstance(r, SolverResult)
    assert r.status == "unsure", r.notes
    assert "browser-harness" not in r.notes
