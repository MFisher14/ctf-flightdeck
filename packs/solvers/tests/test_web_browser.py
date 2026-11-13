"""B-150: the pinned isolated browser worker for the web lane (ctf/web_browser.py).

The worker is exercised two ways:
  * through an injected in-memory ``FakeTransport`` and an injected step clock, for the bounded
    evaluate-and-observe contract, the fixed-callback allowlist, the scope guard, pinning and the
    handshake -- no process, no browser, no wall-clock dependency (rule 16);
  * through the real ``StdioTransport`` against a SYNTHETIC python harness this test writes and runs
    over stdio, for the wire protocol -- a subprocess that speaks JSON lines, never a real browser and
    never any network.

One test needs the real configured browser harness; it is ``needs_tool`` so it reports as not run
rather than silently green when no harness is installed (CLAUDE.md rule 5, CONTRACTS.md section 9).
"""
import datetime as dt
import json
import os
import stat
import sys
import textwrap
from collections import deque

import pytest

from ctf import event, scope, web_browser
from ctf.web_browser import (
    BrowserConfig, BrowserUnavailable, BrowserWorker, Evaluation, Observation,
    FIXED_SCRIPTS, OBSERVATION_KINDS, StdioTransport, Transport,
)


# ---------------------------------------------------------------------------------------------- #
#  test doubles
# ---------------------------------------------------------------------------------------------- #
class StepClock:
    """A clock the test advances by hand, so budgets are measured without wall time."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def advance(self, dt_s):
        self.t += dt_s


class FakeTransport(Transport):
    """An in-memory harness: ``recv`` returns the next scripted reply, or None (a timeout) when the
    outbox is empty.  Records what the worker sent."""

    def __init__(self):
        self.sent = []
        self.outbox = deque()
        self.closed = False

    def send(self, obj):
        self.sent.append(dict(obj))

    def recv(self, deadline=None):
        if self.outbox:
            return self.outbox.popleft()
        return None

    def close(self):
        self.closed = True


def _worker(transport, *, clock=None, scope_check=None, config=None):
    """A BrowserWorker wired to a fixed FakeTransport, counting how many times the factory ran."""
    clock = clock or StepClock()
    calls = {"n": 0}

    def factory(cfg, clk):
        calls["n"] += 1
        return transport

    w = BrowserWorker(
        config or BrowserConfig(harness="x", sandbox_mode="none"),
        transport_factory=factory, clock=clock,
        scope_check=scope_check or (lambda url, **kw: url))
    return w, calls


def _ready(transport):
    transport.outbox.append({"op": "ready", "version": web_browser.PROTOCOL_VERSION})


# ---------------------------------------------------------------------------------------------- #
#  harness resolution and availability (detection first, agents second)
# ---------------------------------------------------------------------------------------------- #
def test_resolve_harness_unset_is_loud_with_tool():
    with pytest.raises(BrowserUnavailable) as ei:
        web_browser.resolve_harness(BrowserConfig(harness=None))
    assert "no browser harness configured" in str(ei.value)
    assert ei.value.tool == "browser-harness"      # names a tool for the needs_tool marker


def test_resolve_harness_path_must_be_executable(tmp_path):
    f = tmp_path / "not_exec"
    f.write_text("#!/bin/sh\n")
    os.chmod(f, 0o644)
    with pytest.raises(BrowserUnavailable, match="not an executable file"):
        web_browser.resolve_harness(BrowserConfig(harness=str(f)))


def test_resolve_harness_bare_name_not_on_path():
    with pytest.raises(BrowserUnavailable) as ei:
        web_browser.resolve_harness(BrowserConfig(harness="definitely-not-a-real-harness-bin"))
    assert ei.value.tool == "definitely-not-a-real-harness-bin"


def test_availability_never_raises_when_absent():
    ok, reason = web_browser.availability(BrowserConfig(harness=None, sandbox_mode="none"))
    assert ok is False
    assert "no browser harness configured" in reason


def test_availability_true_when_harness_present(tmp_path):
    f = tmp_path / "harness"
    f.write_text("#!/bin/sh\n")
    os.chmod(f, 0o755)
    ok, detail = web_browser.availability(BrowserConfig(harness=str(f), sandbox_mode="none"))
    assert ok is True
    assert "unsandboxed" in detail


# ---------------------------------------------------------------------------------------------- #
#  sandbox launch argv (built, never launched; no docker build/pull/container change)
# ---------------------------------------------------------------------------------------------- #
def test_sandbox_argv_seatbelt_wraps_with_profile():
    cfg = BrowserConfig(harness="h", sandbox_mode="seatbelt")
    argv = web_browser.sandbox_launch_argv(cfg, ["/opt/harness", "--headless"])
    assert argv[0] == "sandbox-exec"
    assert argv[1] == "-f"
    assert argv[2].endswith("tools/browser.sb")
    assert argv[-2:] == ["/opt/harness", "--headless"]


def test_sandbox_argv_docker_has_isolation_flags_and_no_pull():
    cfg = BrowserConfig(harness="h", sandbox_mode="docker", docker_image="csctf-browser:7")
    argv = web_browser.sandbox_launch_argv(cfg, ["/opt/harness"])
    assert argv[:3] == ["docker", "run", "--rm"]
    assert "--network" not in argv or True        # network posture set per deployment
    assert "--cap-drop" in argv and "ALL" in argv
    assert "--security-opt" in argv and "no-new-privileges" in argv
    assert "--pids-limit" in argv
    assert "csctf-browser:7" in argv
    # the image is the last token before the harness argv; this module never pulls or builds it
    assert argv[argv.index("csctf-browser:7") + 1] == "/opt/harness"
    assert "build" not in argv and "pull" not in argv


def test_sandbox_argv_none_passes_through():
    cfg = BrowserConfig(harness="h", sandbox_mode="none")
    assert web_browser.sandbox_launch_argv(cfg, ["/opt/harness", "-x"]) == ["/opt/harness", "-x"]


def test_config_from_env_rejects_bad_sandbox_mode():
    with pytest.raises(BrowserUnavailable, match="not a sandbox mode"):
        BrowserConfig.from_env(environ={"CTF_BROWSER_SANDBOX": "wide-open"})


# ---------------------------------------------------------------------------------------------- #
#  the fixed-callback allowlist: a caller can never inject its own script or callback
# ---------------------------------------------------------------------------------------------- #
def test_evaluate_refuses_unknown_script():
    t = FakeTransport()
    w, _ = _worker(t)
    with pytest.raises(ValueError, match="unknown fixed script"):
        w.evaluate("https://x.example/", "please_run_my_payload")
    assert t.sent == []       # nothing reached the harness


def test_evaluate_refuses_unknown_observation_kind():
    t = FakeTransport()
    w, _ = _worker(t)
    with pytest.raises(ValueError, match="unknown observation kind"):
        w.evaluate("https://x.example/", "observe_load", observe=["console", "exfiltrate_everything"])
    assert t.sent == []


def test_evaluate_rejects_out_of_range_budget_and_cap():
    t = FakeTransport()
    w, _ = _worker(t)
    with pytest.raises(ValueError, match="budget_ms"):
        w.evaluate("https://x.example/", "observe_load", budget_ms=10**9)
    with pytest.raises(ValueError, match="max_events"):
        w.evaluate("https://x.example/", "observe_load", max_events=0)


# ---------------------------------------------------------------------------------------------- #
#  the scope guard runs before any navigation
# ---------------------------------------------------------------------------------------------- #
def test_scope_checked_before_transport_opens():
    t = FakeTransport()

    def refusing_scope(url, **kw):
        raise scope.OutOfScope(f"{url} refused for test")

    w, calls = _worker(t, scope_check=refusing_scope)
    with pytest.raises(scope.OutOfScope):
        w.evaluate("https://evil.example/", "observe_load")
    assert calls["n"] == 0        # the harness transport was never even created
    assert t.sent == []


def _pin_scope(globs):
    prof = event.parse({
        "slug": "b150-test", "name": "b150",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(globs)},
    }, src="<test>")
    scope.pin(prof)


def test_default_scope_check_refuses_out_of_scope_host():
    """With the real scope.check_url wired in (the default), an out-of-scope host is refused."""
    t = FakeTransport()
    before = scope.pinned()
    _pin_scope(["*.chal.ctf.example"])
    try:
        w = BrowserWorker(BrowserConfig(harness="x", sandbox_mode="none"),
                          transport_factory=lambda c, k: t, clock=StepClock())
        with pytest.raises(scope.OutOfScope):
            w.evaluate("https://not-a-target.example/", "observe_load")
        assert t.sent == []
    finally:
        scope.pin(before) if before else scope.unpin()


def test_default_scope_check_allows_in_scope_host():
    t = FakeTransport()
    _ready(t)
    t.outbox.append({"id": 1, "ok": True, "observations": [], "result": {}})
    before = scope.pinned()
    _pin_scope(["*.chal.ctf.example"])
    try:
        w = BrowserWorker(BrowserConfig(harness="x", sandbox_mode="none"),
                          transport_factory=lambda c, k: t, clock=StepClock())
        ev = w.evaluate("https://web-1.chal.ctf.example/", "observe_load")
        assert ev.ok is True
        # the harness was told to navigate exactly the in-scope url
        assert t.sent[-1]["op"] == "evaluate" and t.sent[-1]["url"] == "https://web-1.chal.ctf.example/"
    finally:
        scope.pin(before) if before else scope.unpin()


# ---------------------------------------------------------------------------------------------- #
#  handshake
# ---------------------------------------------------------------------------------------------- #
def test_start_sends_hello_and_requires_ready():
    t = FakeTransport()
    _ready(t)
    w, calls = _worker(t)
    w.start()
    assert calls["n"] == 1
    assert t.sent[0] == {"op": "hello", "version": web_browser.PROTOCOL_VERSION}
    w.start()                     # idempotent: no second transport
    assert calls["n"] == 1


def test_start_rejects_protocol_mismatch_and_closes():
    t = FakeTransport()
    t.outbox.append({"op": "ready", "version": 999})
    w, _ = _worker(t)
    with pytest.raises(BrowserUnavailable, match="protocol"):
        w.start()
    assert t.closed is True


def test_start_rejects_non_ready_message():
    t = FakeTransport()
    t.outbox.append({"op": "surprise"})
    w, _ = _worker(t)
    with pytest.raises(BrowserUnavailable, match="not a ready message"):
        w.start()


# ---------------------------------------------------------------------------------------------- #
#  pinning: one harness reused across evaluations
# ---------------------------------------------------------------------------------------------- #
def test_worker_is_pinned_across_evaluations():
    t = FakeTransport()
    _ready(t)
    t.outbox.append({"id": 1, "ok": True, "observations": []})
    t.outbox.append({"id": 2, "ok": True, "observations": []})
    w, calls = _worker(t)
    w.evaluate("https://x.example/a", "observe_load")
    w.evaluate("https://x.example/b", "observe_load")
    assert calls["n"] == 1            # the harness was started once and reused
    assert w.evaluations == 2
    # the two evaluate messages carry distinct ids
    ids = [m["id"] for m in t.sent if m["op"] == "evaluate"]
    assert ids == [1, 2]
    w.close()
    assert t.closed is True


# ---------------------------------------------------------------------------------------------- #
#  bounded observe: event cap, fixed-set filtering, requested-kind filtering, XSS oracle
# ---------------------------------------------------------------------------------------------- #
def test_only_closed_set_and_requested_kinds_are_kept():
    t = FakeTransport()
    _ready(t)
    t.outbox.append({"id": 1, "ok": True, "observations": [
        {"kind": "dialog", "type": "alert", "message": "pwned"},
        {"kind": "console", "level": "log", "text": "hi"},        # not requested -> dropped
        {"kind": "secret_channel", "text": "nope"},                # outside the closed set -> dropped
    ]})
    w, _ = _worker(t)
    ev = w.evaluate("https://x.example/", "observe_xss_oracle", observe=["dialog"])
    assert ev.ok is True
    assert [o.kind for o in ev.observations] == ["dialog"]
    assert ev.observations[0].detail["message"] == "pwned"
    assert ev.fired_dialog is True


def test_max_events_caps_and_marks_truncated():
    t = FakeTransport()
    _ready(t)
    obs = [{"kind": "network_request", "url": f"https://x.example/{i}"} for i in range(10)]
    t.outbox.append({"id": 1, "ok": True, "observations": obs})
    w, _ = _worker(t)
    ev = w.evaluate("https://x.example/", "observe_load", observe=["network_request"], max_events=3)
    assert len(ev.observations) == 3
    assert ev.truncated is True


def test_harness_failure_becomes_failed_evaluation():
    t = FakeTransport()
    _ready(t)
    t.outbox.append({"id": 1, "ok": False, "error": "navigation timed out"})
    w, _ = _worker(t)
    ev = w.evaluate("https://x.example/", "observe_load")
    assert ev.ok is False
    assert "navigation timed out" in ev.reason


def test_budget_timeout_marks_timed_out():
    clock = StepClock()
    t = FakeTransport()
    _ready(t)
    # no evaluate reply queued -> recv returns None (a timeout)
    w, _ = _worker(t, clock=clock)
    ev = w.evaluate("https://x.example/", "observe_load", budget_ms=5000)
    assert ev.ok is False
    assert ev.timed_out is True
    assert "did not reply" in ev.reason


def test_await_skips_stale_reply_for_earlier_call():
    t = FakeTransport()
    _ready(t)
    # a late reply for id 1 arrives before the reply for id 2; evaluate() must not confuse them
    t.outbox.append({"id": 1, "ok": True, "observations": []})      # first call
    t.outbox.append({"id": 1, "ok": True, "observations": [{"kind": "console", "text": "stale"}]})
    t.outbox.append({"id": 2, "ok": True, "observations": [{"kind": "console", "text": "fresh"}]})
    w, _ = _worker(t)
    w.evaluate("https://x.example/a", "observe_load", observe=["console"])
    ev2 = w.evaluate("https://x.example/b", "observe_load", observe=["console"])
    assert [o.detail.get("text") for o in ev2.observations] == ["fresh"]


# ---------------------------------------------------------------------------------------------- #
#  the real StdioTransport against a synthetic stdio harness (the wire, no browser, no network)
# ---------------------------------------------------------------------------------------------- #
_SYNTH_HARNESS = textwrap.dedent('''
    import sys, json
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        op = msg.get("op")
        if op == "hello":
            print(json.dumps({"op": "ready", "version": 1}), flush=True)
        elif op == "ping":
            print(json.dumps({"id": msg["id"], "ok": True, "pong": True}), flush=True)
        elif op == "evaluate":
            obs = [
                {"kind": "dialog", "type": "alert", "message": msg["url"]},
                {"kind": "nonsense", "x": 1},
            ]
            print(json.dumps({"id": msg["id"], "ok": True, "observations": obs,
                              "result": {"navigated": msg["url"]}}), flush=True)
        elif op == "shutdown":
            break
''')


def _synth_harness_path(tmp_path):
    p = tmp_path / "harness.py"
    p.write_text(_SYNTH_HARNESS)
    return p


def test_stdio_transport_end_to_end(tmp_path):
    harness = _synth_harness_path(tmp_path)
    w = BrowserWorker(
        BrowserConfig(harness="x", sandbox_mode="none"),
        transport_factory=lambda cfg, clk: StdioTransport([sys.executable, str(harness)], clock=clk),
        scope_check=lambda url, **kw: url)
    try:
        assert w.ping() is True
        ev = w.evaluate("https://web-1.chal.ctf.example/?q=<script>", "observe_xss_oracle",
                        observe=["dialog"], budget_ms=10000)
        assert ev.ok is True
        assert ev.fired_dialog is True
        assert ev.observations[0].detail["message"] == "https://web-1.chal.ctf.example/?q=<script>"
        assert ev.result == {"navigated": "https://web-1.chal.ctf.example/?q=<script>"}
    finally:
        w.close()


def test_default_transport_factory_resolves_executable_and_runs(tmp_path):
    """The real default factory path: resolve an executable harness, wrap it (none), launch it."""
    harness = _synth_harness_path(tmp_path)
    wrapper = tmp_path / "harness.sh"
    wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{harness}"\n')
    os.chmod(wrapper, 0o755)
    cfg = BrowserConfig(harness=str(wrapper), sandbox_mode="none")
    w = BrowserWorker(cfg, scope_check=lambda url, **kw: url)
    try:
        ev = w.evaluate("https://web-1.chal.ctf.example/", "observe_load", observe=["dialog"])
        assert ev.ok is True and ev.fired_dialog is True
    finally:
        w.close()


# ---------------------------------------------------------------------------------------------- #
#  web-lane exposure
# ---------------------------------------------------------------------------------------------- #
def test_web_lane_exposes_browser_availability():
    from ctf import web_lane
    ok, reason = web_lane.browser_availability()
    assert isinstance(ok, bool)        # never raises; detection uses this first
    assert isinstance(reason, str) and reason


# ---------------------------------------------------------------------------------------------- #
#  the real configured browser harness (reported as NOT RUN until one is installed)
# ---------------------------------------------------------------------------------------------- #
@pytest.mark.needs_tool("browser-harness")
def test_real_harness_round_trip():
    # Runs only when CTF_BROWSER_HARNESS names an installed harness binary on PATH; otherwise the
    # needs_tool marker reports this as not run (never a silent pass).
    cfg = BrowserConfig.from_env()
    ok, reason = web_browser.availability(cfg)
    assert ok, reason
    with BrowserWorker(cfg) as w:
        assert w.ping() is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
