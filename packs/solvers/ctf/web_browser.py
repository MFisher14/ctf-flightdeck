"""ctf.web_browser: a pinned, isolated headless-browser worker for the web lane (B-150).

The browser-execution web classes (reflected/DOM XSS, postMessage, DOM sinks, CSP effects --
``B-122`` and the agent-only classes) need a *real* browser to run the target's own JavaScript and
report what it did.  Nothing in Phase 1 provides one: ``solvers/web/browser_recon.py`` is an offline
CSP/JS recognizer that never opens a URL or evaluates a script.  This module is the live piece it was
missing, built to the shape the item asks for:

  * **Pinned.**  One headless browser is started once (a *harness* process that drives it) and reused
    across evaluations, so the per-call cost is one message round trip, not a cold browser launch.
  * **Isolated.**  The harness runs inside a network + process sandbox: either the macOS Seatbelt
    profile ``tools/browser.sb`` (``sandbox-exec``) or an already-built Docker image run with
    ``--network``-scoped, ``--cap-drop ALL``, ``--pids-limit`` and memory limits -- the same posture
    ``tools/sandbox.py`` uses for hostile files.  This module **builds** the launch command and
    **refuses loudly** when the sandbox tool or the browser harness is absent; it never pulls, builds
    or changes a Docker image (that is a human step -- see ``docs/build-log/B-150.md``).
  * **Bounded evaluate-and-observe, with fixed callbacks.**  A caller does not inject arbitrary
    JavaScript.  It names one of a **closed registry** of instrumentation scripts (``FIXED_SCRIPTS``)
    and a subset of a **closed set** of observation kinds (``OBSERVATION_KINDS``) -- the "fixed
    callbacks".  The harness runs that fixed script against the target and streams back only those
    observations, capped by an explicit per-call event budget and time budget.

  * **Detection first, agents second.**  ``availability()`` is the one call detection makes before it
    reaches for the browser: it returns ``(False, reason)`` -- never an exception -- when the browser
    is not installed, so detection can fall back to a web agent with a named reason instead of
    crashing.  A *scope* violation is different: ``evaluate`` raises ``ctf.scope.OutOfScope`` before
    the harness is ever told to navigate, because visiting an out-of-scope host is never allowed.

Policy boundaries this worker keeps (it never relaxes them):

  * Every target URL passes ``ctf.scope.check_url`` before the harness is told to open it -- the same
    guard every network client runs.  An out-of-scope or platform host is refused before navigation.
  * The caller chooses only a *named* fixed script and *named* observation kinds; it can never hand
    the browser a payload of its own.  (The payloads a browser-XSS engine fires are B-122's job and
    go through its own reviewed path, not this API.)
  * No silent fallback: a missing harness, a missing sandbox tool, a protocol mismatch or a harness
    that dies each fails with a named reason (``BrowserUnavailable``), and tests that need the real
    harness are marked ``needs_tool`` so they report as not run, never silently green.

The worker talks to the harness over a tiny line-delimited JSON protocol (``PROTOCOL_VERSION``), so
the harness that actually drives Chromium (Playwright/Puppeteer, or a browser container) is a
separate, swappable process behind the ``Transport`` seam.  The suite exercises the worker and the
wire against a synthetic stdio harness; it never starts a real browser and never leaves loopback.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import subprocess
import time as _time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import env as _env
from . import paths as _paths
from . import scope as _scope

PROTOCOL_VERSION = 1

# The closed set of observation kinds the harness may report (the "fixed callbacks").  A caller asks
# for a subset of these; anything else is refused before a message is sent.
OBSERVATION_KINDS = (
    "navigation",       # the page navigated (url, status)
    "console",          # a console.* message (level, text)
    "dialog",           # alert/confirm/prompt fired (type, message)  -- the classic XSS oracle
    "page_error",       # an uncaught page exception (text)
    "network_request",  # the page issued a request (method, url)
    "cookie_read",      # script read document.cookie
    "postmessage",      # a window message was received (origin, data_preview)
    "dom_match",        # a fixed DOM query matched (selector, count, text_preview)
)

# The closed registry of instrumentation scripts.  The *value* is a human description only: the real
# instrumentation lives in the harness, keyed by this id, so this process never ships browser code.
# A caller names one of these; an unknown name is refused (it cannot smuggle arbitrary JavaScript in).
FIXED_SCRIPTS: Mapping[str, str] = {
    "observe_load":        "navigate and report navigations, console, page errors and requests",
    "observe_xss_oracle":  "navigate and report whether a dialog (alert/confirm/prompt) fired",
    "observe_dom":         "navigate and report matches of the fixed DOM sink selectors",
    "observe_postmessage": "navigate and report window 'message' events received",
    "observe_cookie":      "navigate and report script reads of document.cookie",
}

# Default bounds.  Time is a per-call budget; a real deadline is the caller's injected clock plus it.
DEFAULT_BUDGET_MS = 8000
DEFAULT_MAX_EVENTS = 64
READY_BUDGET_MS = 15000          # how long to wait for the harness to come up (cold browser launch)
RECV_SLACK_MS = 2000             # how far past the harness budget the worker waits for its reply
MAX_BUDGET_MS = 120000           # a single evaluation may never ask for more than this

SANDBOX_MODES = ("docker", "seatbelt", "none")
SEATBELT_PROFILE = "tools/browser.sb"      # repo-relative; the committed browser Seatbelt profile
DEFAULT_DOCKER_IMAGE = "csctf-browser:1"   # a human step builds/installs it; never pulled here

# Docker isolation flags (no image build/pull, no container lifecycle changes done by this module).
_DOCKER_LIMITS = {"pids": "256", "memory": "1g", "cpus": "2"}


class BrowserUnavailable(RuntimeError):
    """The isolated browser worker cannot run now, with a named reason (no silent fallback).

    ``tool`` names the missing binary (for a ``needs_tool`` test marker / a toolbox install step) when
    the reason is a missing executable, else "".
    """

    def __init__(self, message: str, *, tool: str = ""):
        super().__init__(message)
        self.tool = tool


# --------------------------------------------------------------------------------------------------
#  configuration
# --------------------------------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class BrowserConfig:
    """How to launch and bound the pinned browser harness.

    ``harness`` is the command that drives the browser and speaks this module's protocol on its
    stdio.  It is resolved from ``CTF_BROWSER_HARNESS`` (a path or a PATH name); there is no built-in
    default, because this repo ships no browser -- an absent harness is a loud, named failure, not a
    guess.  ``sandbox_mode`` must be set explicitly to "none" to run the harness unsandboxed (the
    suite's synthetic harness does so); production uses "docker" or "seatbelt".
    """

    harness: str | None = None
    harness_args: tuple[str, ...] = ()
    sandbox_mode: str = "seatbelt"
    docker_image: str = DEFAULT_DOCKER_IMAGE
    default_budget_ms: int = DEFAULT_BUDGET_MS
    default_max_events: int = DEFAULT_MAX_EVENTS

    @classmethod
    def from_env(cls, *, environ: Mapping[str, str] | None = None) -> "BrowserConfig":
        get = (lambda n, d=None: _env.get(n, d, environ=environ))
        mode = (get("CTF_BROWSER_SANDBOX") or "seatbelt").strip().lower()
        if mode not in SANDBOX_MODES:
            raise BrowserUnavailable(
                f"CTF_BROWSER_SANDBOX={mode!r} is not a sandbox mode ({', '.join(SANDBOX_MODES)})")
        raw_args = get("CTF_BROWSER_HARNESS_ARGS") or ""
        budget = _env.get_int("CTF_BROWSER_BUDGET_MS", DEFAULT_BUDGET_MS, environ=environ)
        max_events = _env.get_int("CTF_BROWSER_MAX_EVENTS", DEFAULT_MAX_EVENTS, environ=environ)
        return cls(
            harness=get("CTF_BROWSER_HARNESS"),
            harness_args=tuple(raw_args.split()),
            sandbox_mode=mode,
            docker_image=(get("CTF_BROWSER_IMAGE") or DEFAULT_DOCKER_IMAGE),
            default_budget_ms=int(budget),
            default_max_events=int(max_events),
        )


def resolve_harness(config: BrowserConfig) -> str:
    """The absolute harness command, or ``BrowserUnavailable`` with a named reason and ``tool`` set.

    A harness given as a path must exist and be executable; a bare name is looked up on PATH.  This
    does not start anything; it only proves the harness is installable, so detection can decide.
    """
    name = (config.harness or "").strip()
    if not name:
        raise BrowserUnavailable(
            "no browser harness configured: set CTF_BROWSER_HARNESS to the command that drives the "
            "headless browser and speaks the worker protocol (this repo ships no browser; see "
            "docs/build-log/B-150.md for the harness contract and the install step)",
            tool="browser-harness")
    if os.sep in name or (os.altsep and os.altsep in name):
        p = Path(name).expanduser()
        if not p.is_file() or not os.access(p, os.X_OK):
            raise BrowserUnavailable(
                f"the browser harness {name!r} is not an executable file (CTF_BROWSER_HARNESS)",
                tool="browser-harness")
        return str(p.resolve())
    found = shutil.which(name)
    if not found:
        raise BrowserUnavailable(
            f"the browser harness {name!r} is not on PATH (CTF_BROWSER_HARNESS)", tool=name)
    return found


def _require_sandbox_tool(config: BrowserConfig) -> None:
    """Prove the sandbox tool for this mode exists, else ``BrowserUnavailable`` naming it."""
    if config.sandbox_mode == "none":
        return
    if config.sandbox_mode == "seatbelt":
        if shutil.which("sandbox-exec") is None:
            raise BrowserUnavailable(
                "the Seatbelt sandbox (sandbox-exec) is not available; browser isolation needs it on "
                "macOS, or set CTF_BROWSER_SANDBOX=docker", tool="sandbox-exec")
        profile = _paths.repo_root() / SEATBELT_PROFILE
        if not profile.is_file():
            raise BrowserUnavailable(f"the browser Seatbelt profile {profile} is missing")
    elif config.sandbox_mode == "docker":
        if shutil.which("docker") is None:
            raise BrowserUnavailable(
                "docker is not installed; the docker browser sandbox needs it, or set "
                "CTF_BROWSER_SANDBOX=seatbelt", tool="docker")


def sandbox_launch_argv(config: BrowserConfig, harness_argv: Sequence[str]) -> list[str]:
    """Wrap ``harness_argv`` in the isolation for ``config.sandbox_mode``.  Pure: it builds the argv,
    it does not launch anything, pull an image or change a container.

    * ``seatbelt``: ``sandbox-exec -f tools/browser.sb <harness...>``.
    * ``docker``: ``docker run --rm --pull=never --init --cap-drop ALL --security-opt no-new-privileges
      --pids-limit N --memory M --cpus C <image> <harness...>`` -- the image must already exist
      (a human step builds it; ``--pull=never`` stops docker from pulling a missing image on its
      own, so a missing image fails loudly instead).
    * ``none``: the harness argv unchanged (must be chosen explicitly; used by the suite's stdio
      harness).
    """
    argv = list(harness_argv)
    if config.sandbox_mode == "none":
        return argv
    if config.sandbox_mode == "seatbelt":
        profile = _paths.repo_root() / SEATBELT_PROFILE
        return ["sandbox-exec", "-f", str(profile), *argv]
    if config.sandbox_mode == "docker":
        return ["docker", "run", "--rm", "--pull=never", "--init",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pids-limit", _DOCKER_LIMITS["pids"], "--memory", _DOCKER_LIMITS["memory"],
                "--memory-swap", _DOCKER_LIMITS["memory"], "--cpus", _DOCKER_LIMITS["cpus"],
                config.docker_image, *argv]
    raise BrowserUnavailable(f"unknown sandbox mode {config.sandbox_mode!r}")


def availability(config: BrowserConfig | None = None) -> tuple[bool, str]:
    """``(True, detail)`` when the isolated browser can be started now, else ``(False, reason)``.

    This is the call detection makes *first*: it never raises, so a browser that is not installed
    makes detection fall back to an agent with a named reason, not crash.  It resolves the harness and
    the sandbox tool; it does not start the browser (that is ``BrowserWorker.start``).
    """
    try:
        cfg = config or BrowserConfig.from_env()
        harness = resolve_harness(cfg)
        _require_sandbox_tool(cfg)
    except BrowserUnavailable as e:
        return False, str(e)
    sb = "unsandboxed (sandbox_mode=none)" if cfg.sandbox_mode == "none" else f"{cfg.sandbox_mode} sandbox"
    return True, f"browser harness {harness} under the {sb}"


# --------------------------------------------------------------------------------------------------
#  observation and evaluation records
# --------------------------------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Observation:
    kind: str
    detail: Mapping[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class Evaluation:
    ok: bool
    url: str
    script: str
    observations: tuple[Observation, ...] = ()
    result: Mapping[str, Any] | None = None
    truncated: bool = False
    timed_out: bool = False
    reason: str = ""
    seconds: float = 0.0

    def of_kind(self, kind: str) -> tuple[Observation, ...]:
        return tuple(o for o in self.observations if o.kind == kind)

    @property
    def fired_dialog(self) -> bool:
        """The XSS oracle: did a dialog (alert/confirm/prompt) fire?"""
        return bool(self.of_kind("dialog"))


# --------------------------------------------------------------------------------------------------
#  transport seam
# --------------------------------------------------------------------------------------------------
class Transport:
    """One line-delimited JSON channel to a harness process.  ``send`` writes one object; ``recv``
    reads one, waiting until ``deadline`` (an absolute value on the worker's clock) and returning
    ``None`` when that passes with nothing read.  ``close`` ends the harness."""

    def send(self, obj: Mapping[str, Any]) -> None:               # pragma: no cover - interface
        raise NotImplementedError

    def recv(self, deadline: float | None = None) -> dict | None:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:                                       # pragma: no cover - interface
        raise NotImplementedError


class StdioTransport(Transport):
    """Launch the sandboxed harness and speak the protocol over its stdin/stdout.

    The harness is started once and pinned; this transport only frames JSON lines.  It uses a reader
    thread so ``recv`` can honour a deadline without blocking forever on a dead harness.
    """

    def __init__(self, argv: Sequence[str], *, clock: Callable[[], float] = _time.monotonic):
        import queue
        import threading
        self._clock = clock
        try:
            self._proc = subprocess.Popen(
                list(argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, bufsize=1, text=True)
        except (OSError, ValueError) as e:
            raise BrowserUnavailable(f"could not start the browser harness ({type(e).__name__}: {e})")
        self._q: "queue.Queue[str | None]" = queue.Queue()

        def _pump(out, q):
            try:
                for line in out:
                    q.put(line)
            finally:
                q.put(None)

        self._reader = threading.Thread(target=_pump, args=(self._proc.stdout, self._q), daemon=True)
        self._reader.start()

    def send(self, obj: Mapping[str, Any]) -> None:
        if self._proc.poll() is not None:
            raise BrowserUnavailable(f"the browser harness exited (code {self._proc.returncode})")
        try:
            self._proc.stdin.write(json.dumps(obj) + "\n")
            self._proc.stdin.flush()
        except (OSError, ValueError) as e:
            raise BrowserUnavailable(f"writing to the browser harness failed ({type(e).__name__}: {e})")

    def recv(self, deadline: float | None = None) -> dict | None:
        import queue
        while True:
            timeout = None
            if deadline is not None:
                timeout = max(0.0, deadline - self._clock())
            try:
                line = self._q.get(timeout=timeout)
            except queue.Empty:
                return None
            if line is None:
                raise BrowserUnavailable(
                    f"the browser harness closed its output (code {self._proc.poll()})")
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue    # a non-JSON line from the harness is noise, not a message; skip it
            if isinstance(obj, dict):
                return obj

    def close(self) -> None:
        try:
            if self._proc.poll() is None:
                try:
                    self._proc.stdin.write(json.dumps({"op": "shutdown"}) + "\n")
                    self._proc.stdin.flush()
                except (OSError, ValueError):
                    pass
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
        finally:
            for stream in (self._proc.stdin, self._proc.stdout):
                try:
                    stream and stream.close()
                except OSError:
                    pass


def default_transport_factory(config: BrowserConfig,
                              clock: Callable[[], float] = _time.monotonic) -> Transport:
    """Build the real sandboxed stdio transport for ``config`` (resolving the harness and the sandbox
    tool first, so an absent one fails loudly before any process starts)."""
    harness = resolve_harness(config)
    _require_sandbox_tool(config)
    argv = sandbox_launch_argv(config, [harness, *config.harness_args])
    return StdioTransport(argv, clock=clock)


# --------------------------------------------------------------------------------------------------
#  the pinned worker
# --------------------------------------------------------------------------------------------------
class BrowserWorker:
    """A pinned, isolated headless browser exposed as a bounded evaluate-and-observe API.

    The harness is started lazily on the first ``evaluate`` (or an explicit ``start``) and reused for
    every later call.  ``transport_factory`` is the seam the suite injects a synthetic harness
    through; left out, the real sandboxed stdio harness is used.  ``clock`` is injected so a call's
    budget is measured without a wall-clock dependency (rule 16).
    """

    def __init__(self, config: BrowserConfig | None = None, *,
                 transport_factory: Callable[[BrowserConfig, Callable[[], float]], Transport] | None = None,
                 clock: Callable[[], float] = _time.monotonic,
                 scope_check: Callable[..., str] = _scope.check_url):
        self.config = config or BrowserConfig.from_env()
        self._factory = transport_factory or default_transport_factory
        self._clock = clock
        self._scope_check = scope_check
        self._transport: Transport | None = None
        self._next_id = 1
        self.evaluations = 0

    # -- lifecycle -------------------------------------------------------------------------------
    def start(self) -> None:
        """Start and handshake the pinned harness (idempotent).  ``BrowserUnavailable`` on any
        failure, so a caller that reached past ``availability()`` still gets a named reason."""
        if self._transport is not None:
            return
        transport = self._factory(self.config, self._clock)
        try:
            transport.send({"op": "hello", "version": PROTOCOL_VERSION})
            deadline = self._clock() + READY_BUDGET_MS / 1000.0
            reply = transport.recv(deadline)
            if reply is None:
                raise BrowserUnavailable(
                    f"the browser harness did not report ready within {READY_BUDGET_MS} ms")
            if reply.get("op") != "ready":
                raise BrowserUnavailable(f"the browser harness sent {reply!r}, not a ready message")
            got = reply.get("version")
            if got != PROTOCOL_VERSION:
                raise BrowserUnavailable(
                    f"the browser harness speaks protocol {got!r}, this worker speaks {PROTOCOL_VERSION}")
        except BrowserUnavailable:
            transport.close()
            raise
        self._transport = transport

    def close(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def __enter__(self) -> "BrowserWorker":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- the bounded evaluate-and-observe API ----------------------------------------------------
    def evaluate(self, url: str, script: str, *, observe: Sequence[str] = (),
                 budget_ms: int | None = None, max_events: int | None = None) -> Evaluation:
        """Have the pinned browser run the fixed instrumentation ``script`` against ``url`` and return
        the bounded observations.

        ``script`` must be a key of ``FIXED_SCRIPTS`` and every ``observe`` kind a member of
        ``OBSERVATION_KINDS`` (a caller can never inject its own JavaScript or callback): a bad one is
        a ``ValueError``.  ``url`` is checked against the event scope *before* the harness is told to
        navigate; an out-of-scope or platform host raises ``ctf.scope.OutOfScope``.  The call is
        bounded by ``budget_ms`` (wall time granted to the harness) and ``max_events`` (observations
        kept); exceeding either sets ``truncated``/``timed_out`` rather than running unbounded.
        """
        if script not in FIXED_SCRIPTS:
            raise ValueError(f"unknown fixed script {script!r}; choose one of {', '.join(FIXED_SCRIPTS)}")
        kinds = tuple(dict.fromkeys(observe))
        bad = [k for k in kinds if k not in OBSERVATION_KINDS]
        if bad:
            raise ValueError(f"unknown observation kind(s) {bad}; choose from {', '.join(OBSERVATION_KINDS)}")
        budget = int(budget_ms if budget_ms is not None else self.config.default_budget_ms)
        if budget <= 0 or budget > MAX_BUDGET_MS:
            raise ValueError(f"budget_ms={budget} out of range (1..{MAX_BUDGET_MS})")
        cap = int(max_events if max_events is not None else self.config.default_max_events)
        if cap <= 0:
            raise ValueError(f"max_events={cap} must be positive")

        # Scope guard before any navigation -- the same check every network client runs.  This raises
        # ctf.scope.OutOfScope and never opens the harness transport for an out-of-scope target.
        self._scope_check(url, what=f"BrowserWorker.evaluate({url!r})")

        self.start()
        assert self._transport is not None
        call_id = self._next_id
        self._next_id += 1
        t0 = self._clock()
        self._transport.send({"op": "evaluate", "id": call_id, "url": url, "script": script,
                              "observe": list(kinds), "budget_ms": budget, "max_events": cap})
        deadline = t0 + (budget + RECV_SLACK_MS) / 1000.0
        reply = self._await(call_id, deadline)
        secs = self._clock() - t0
        self.evaluations += 1
        if reply is None:
            return Evaluation(ok=False, url=url, script=script, timed_out=True, seconds=secs,
                              reason=f"the browser harness did not reply within {budget + RECV_SLACK_MS} ms")
        if not reply.get("ok"):
            return Evaluation(ok=False, url=url, script=script, seconds=secs,
                              reason=str(reply.get("error") or "the browser harness reported a failure"))
        raw = reply.get("observations") or []
        obs: list[Observation] = []
        for row in raw:
            if not isinstance(row, dict):
                continue
            kind = row.get("kind")
            if kind not in OBSERVATION_KINDS:
                continue        # the harness may only report from the closed set; drop anything else
            if kinds and kind not in kinds:
                continue        # and only the kinds this call asked to observe
            detail = {k: v for k, v in row.items() if k != "kind"}
            obs.append(Observation(kind=str(kind), detail=detail))
        truncated = bool(reply.get("truncated"))
        if len(obs) > cap:          # defence in depth: enforce the cap even if the harness ignored it
            obs = obs[:cap]
            truncated = True
        result = reply.get("result")
        return Evaluation(ok=True, url=url, script=script, observations=tuple(obs),
                          result=result if isinstance(result, dict) else None,
                          truncated=truncated, seconds=secs)

    def _await(self, call_id: int, deadline: float) -> dict | None:
        """Read until the reply for ``call_id`` arrives or ``deadline`` passes.  Replies for other
        ids (a slow earlier call) are skipped, not mistaken for this one."""
        while True:
            reply = self._transport.recv(deadline)
            if reply is None:
                return None
            if reply.get("id") == call_id:
                return reply

    def ping(self, *, budget_ms: int = 2000) -> bool:
        """A liveness round trip to the pinned harness."""
        self.start()
        assert self._transport is not None
        call_id = self._next_id
        self._next_id += 1
        self._transport.send({"op": "ping", "id": call_id})
        reply = self._await(call_id, self._clock() + budget_ms / 1000.0)
        return bool(reply and reply.get("ok"))


# --------------------------------------------------------------------------------------------------
#  the web-lane entry point (detection first, agents second)
# --------------------------------------------------------------------------------------------------
def observe(url: str, script: str = "observe_load", *, observe: Sequence[str] = OBSERVATION_KINDS,
            config: BrowserConfig | None = None, budget_ms: int | None = None,
            max_events: int | None = None) -> Evaluation:
    """One-shot bounded evaluate-and-observe for the web lane / detection.

    Detection calls this on a scope-locked target.  When the browser is not installed it raises
    ``BrowserUnavailable`` with a named reason, which the lane turns into "browser unavailable, hand
    to an agent" (agents second).  A scope violation raises ``ctf.scope.OutOfScope`` as always.  The
    worker is started and closed around the single call; a caller that runs many evaluations should
    hold a pinned ``BrowserWorker`` instead.
    """
    worker = BrowserWorker(config)
    try:
        return worker.evaluate(url, script, observe=observe, budget_ms=budget_ms, max_events=max_events)
    finally:
        worker.close()


__all__ = [
    "PROTOCOL_VERSION", "OBSERVATION_KINDS", "FIXED_SCRIPTS", "SANDBOX_MODES",
    "BrowserUnavailable", "BrowserConfig", "resolve_harness", "sandbox_launch_argv", "availability",
    "Observation", "Evaluation", "Transport", "StdioTransport", "default_transport_factory",
    "BrowserWorker", "observe",
]
