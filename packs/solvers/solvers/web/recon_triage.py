#!/usr/bin/env python3
"""recon_triage: web RECON and vuln-class TRIAGE, read-only.

Web is the lane's recurring long-pole (two days running the long pole was the web agent having to
find its own starting point by hand). `solvers/web/proof_hunt.py` already does the deep READ-BASED proof
recovery (LFI, IDOR, GraphQL field-read, the clue-driven and disclosed-URL SSRF-read classes, and more); what
was missing was the FIRST step most web write-ups describe an agent doing by hand before it could
even point a solver at the right place: read the target's OWN disclosed surface (its
`/api/clues`, `openapi.json`, landing page, headers, `robots.txt`, and the small set of conventional
files/paths a misconfigured target serves) and say, from that alone, which vuln class the challenge is most
likely testing and which endpoints/parameters to try first.

    recon(url, timeout=8.0, max_requests=24) -> {
        "host": str, "status": {path: int|None}, "headers": {name: value, ...} (the landing page's),
        "server_hint": str|None, "disclosed": {...: facts read from the target's own responses},
        "classes": [{"vuln_class": str, "confidence": "high"|"medium"|"low", "evidence": [str, ...],
                     "endpoints": [str, ...], "params": [str, ...]}, ...],   # ranked, most specific first
    }

STRICTLY BENIGN, GET-only recon of the target's own documented/conventional surface -- NOT a scan or a
brute-force of a large space. It:
  - reads a SMALL FIXED list of paths (RECON_PATHS below, 13 items: the landing page, robots.txt, the clue
    feed, an OpenAPI/Swagger document, and the handful of conventional exposure paths proof_hunt's own final
    wave already treats as "not a scan" -- .git/HEAD, .env, backup.zip, ...);
  - never guesses a parameter VALUE and sends no payload of any kind (no SQLi/SSTI/cmdi probe, no injection,
    no forged header, no auth bypass attempt): it only reads what each of those fixed GETs returns;
  - never follows a redirect off-host and never touches a path whose words say it changes or ends state (the
    same `is_destructive` guard proof_hunt uses, reused by import, never relaxed);
  - uses `solvers/toolkits/web.py`'s `WebClient`, so it inherits that client's scope lock (same host, port
    and scheme as the URL it is given; a private/loopback target without the VPN raises `VPNRequired`, a
    player stop, same as every other web tool) and never touches the challenge platform itself.

Nothing here performs or prepares an exploit: no port/loopback scan or sweep, no blind or time-based probe, no
out-of-band collector, no deserialization gadget, no JWT forging, no command/code injection payload, nothing
written to or executed on the target. Vuln-class triage only narrows WHERE `proof_hunt.py` (or an agent) should
look next; it never itself reads a flag, fabricates one, or submits anything. A flag is still
the player's to enter (`PLAYER FLAG <challenge>: <flag>`); this module never returns one.

CLI (debugging only; makes no challenge platform request, submits nothing):
    recon_triage.py <url> [--seconds N] [--max-requests N]
prints the `recon()` dict as JSON and exits 0; exits 1 on a usage or client-construction problem (a bad URL, a
private target with no VPN). Never prints a token (none is ever read).
"""
import importlib.util
import json
import re
import sys
import time
import urllib.parse
import zipfile
import io
from html.parser import HTMLParser
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))
if str(HERE) not in sys.path:
    # ``recon_triage.py`` is also loaded directly by path in the isolated
    # release regression; sibling security helpers must resolve there too.
    sys.path.insert(0, str(HERE))

import web as _web  # noqa: E402  (the scope-locked WebClient; same client proof_hunt.py uses)
import security_json as _security_json  # noqa: E402 -- bounded target-authored JSON

REQUEST_TIMEOUT = 8.0
DEFAULT_MAX_REQUESTS = 24
DEADLINE_PAD = 0.3
MAX_RECON_JSON = 1 << 20


def _json_document(text):
    value = str(text or "")
    if len(value) > MAX_RECON_JSON:
        return None
    try:
        return _security_json.loads(value, max_chars=MAX_RECON_JSON)
    except Exception:
        return None

# The small, fixed recon surface: the target's own documented entry points (landing page, robots.txt, the
# clue feed, an API spec) plus the short list of conventional exposure paths a prior recon pass already
# treats as bounded reads, not a scan (solvers/toolkits/web.py's COMMON_PATHS overlaps this on purpose: the
# same list is "not a scan" there and is not a scan here either). 13 fixed GETs, never grown per-target.
RECON_PATHS = (
    "/", "/robots.txt", "/api/clues", "/openapi.json", "/swagger.json",
    "/.git/HEAD", "/.env", "/backup.zip", "/config.json",
    "/debug/vars", "/actuator/env", "/server-status", "/graphql",
)

# Destructive-word guard, reused from proof_hunt by import (never redefined, never relaxed): a path or
# parameter name whose words say it changes or ends state is never requested, here or there.
_DESTRUCTIVE = re.compile(r"(?i)\b(delete|remove|reset|logout|drop|update|approve|destroy|wipe|purge|revoke|"
                          r"disable|deactivate|ban|kick|shutdown|restart|format|truncate|uninstall)\b")

CLUE_ROUTE_SUFFIX = "_route"
# Common framework/server fingerprints read from a Server or X-Powered-By header, informational only.
_FRAMEWORK_HINTS = (
    ("express", "node/express"), ("flask", "python/flask"), ("werkzeug", "python/flask-or-werkzeug"),
    ("django", "python/django"), ("gunicorn", "python/wsgi"), ("fastapi", "python/fastapi"),
    ("php", "php"), ("laravel", "php/laravel"), ("spring", "java/spring"), ("tomcat", "java/tomcat"),
    ("nginx", "nginx (reverse proxy; app server unnamed)"), ("apache", "apache httpd"),
    ("ruby", "ruby"), ("rails", "ruby/rails"), ("asp.net", "dotnet/aspnet"), ("kestrel", "dotnet/kestrel"),
)

# A page that links a reader-style parameter (reader.php?doc=, notes.php?page=) hints at LFI; these are the
# same family proof_hunt's FILE_WORDS already treats as a reader parameter, kept short here for triage only.
_LFI_PARAM_WORDS = ("doc", "file", "page", "path", "view", "template", "tpl", "include", "inc", "load", "read",
                    "document", "note", "src", "source")
_SSRF_PARAM_WORDS = ("url", "uri", "link", "href", "target", "dest", "feed", "fetch", "webhook", "callback",
                     "image", "img", "avatar", "proxy", "remote", "endpoint", "site", "resource", "preview")
_SEARCH_PARAM_WORDS = ("q", "query", "search", "term", "s", "keyword", "find", "lookup", "filter")
# Command-injection TRIAGE words, kept local the same way _LFI_PARAM_WORDS mirrors proof_hunt's FILE_WORDS:
# _CMDI_PARAM_WORDS is the same set as proof_hunt.py's CMDI_WORDS (tests/test_b023_cmdi_triage.py pins the two
# equal, so a word added there and forgotten here fails a test instead of drifting silently), so triage points
# at the SAME surface proof_hunt's (event-gated) cmdi reader would exploit. recon NEVER sends a cmdi probe -- it
# only reads the already-fetched bytes and reports "a command/lookup feature is advertised here" so an agent (or
# proof_hunt) starts in the right place. Blind/OOB command injection stays HELD for the verified profile and is
# never attempted here.
_CMDI_PARAM_WORDS = ("host", "hostname", "ip", "ipaddr", "ip_address", "ipaddress", "addr", "address", "domain",
                     "target", "dns", "server", "nslookup", "ping", "dig", "whois", "lookup", "traceroute",
                     "resolve", "fqdn")
# The subset that is UNAMBIGUOUS: not shared with the SSRF fetch-param family (_SSRF_PARAM_WORDS) and not a
# generic word (addr/address/server/lookup). Any of these named as a parameter is a strong cmdi hint on its own;
# the rest need lookup-surface text beside them. So a plain SSRF ``target`` with no lookup text is ``ssrf`` only;
# with lookup text it is genuinely ambiguous and BOTH the ssrf and the command_injection rows fire.
_CMDI_STRONG_PARAM_WORDS = ("host", "hostname", "ip", "ipaddr", "ip_address", "ipaddress", "domain", "dns",
                            "nslookup", "ping", "dig", "whois", "traceroute", "resolve", "fqdn")
_CMDI_SURFACE_TEXT = re.compile(
    r"(?i)\b(?:ping|nslookup|dig|whois|traceroute|dns[ _-]?lookup|host[ _-]?lookup|"
    r"network[ _-]?diagnostic|run[ _-]?command|command[ _-]?output)\b")
# A route SEGMENT that names a lookup feature. The trailing anchor keeps /api/digest, /digital, /dnsrecords,
# /pinged-users and /lookup-user out: the word must end the segment (or be one of the joined dns-/host-lookup
# forms), optionally with a server-side script extension (/ping.php) -- but not an asset (/img/ping.png).
_CMDI_ROUTE_WORD = re.compile(
    r"(?i)(?:^|/)(?:ping|nslookup|whois|dig|traceroute|tracert|dns(?:[-_]?lookup)?|host[-_]?lookup|lookup|"
    r"diagnose|diagnostics?|resolve)(?=$|[/?#]|\.(?:php\d?|aspx?|jspx?|cgi|pl|py|do|action)(?:$|[/?#]))")

_ATTR_URL = re.compile(r'(?is)\s(?:href|src|action)\s*=\s*"([^"]+)"|\s(?:href|src|action)\s*=\s*\'([^\']+)\'')


def _proof_hunt():
    """solvers/web/proof_hunt.py, loaded by path like proof_hunt's own `_exploit_classes()`: sits beside this
    file, so a package import is never needed. Used ONLY to re-use its read-only `parse_clue_hints` (what the
    target states about itself) and its proof regexes -- never to call anything that sends a request. Returns
    None if the file cannot be read; every caller here tolerates that (recon still works without it)."""
    try:
        spec = importlib.util.spec_from_file_location("csctf_proof_hunt_ro", HERE / "proof_hunt.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


# ---------------------------------------------------------------------------------------------------------
# Proof / flag extraction (item 3): robustly parse a proof or flag pattern out of a target response.
# ---------------------------------------------------------------------------------------------------------
# The event's exact payoff token is the only returnable wire form (ctf.flagfmt: a proof under an event
# whose profile defines [proof], e.g. Huntress proof_<32 hex>; else a flag in the event format). UUID-v4
# nibbles remain a strong observed validator (PAYOFF_V4), never the return gate.
PAYOFF_WIRE = flagfmt.PAYOFF_TEXT
PAYOFF_V4 = flagfmt.PAYOFF_UUID4
PAYOFF_LIKE = flagfmt.PAYOFF_SHAPE    # uppercase / future payoff shapes: candidates, never returned
PROOF_WIRE, PROOF_FORMAT = PAYOFF_WIRE, PAYOFF_V4   # the Huntress-era names (tests and callers read them)
# A generic CTF flag shape (word{...}), kept separate from PAYOFF_WIRE. It and a future/uppercase proof shape
# are evidence candidates for the agent, never values returned by best_proof().
OTHER_LIKE = flagfmt.PAYOFF_OTHER   # the other family's shape: generic confidence only, never returned


def extract_proof(text, *, allow_generic=True):
    """The proof(s) found in one response body/header text, as (value, confidence) pairs, best first.
    Read-only string matching: never fetches anything, never guesses a value that is not already in `text`.

    Confidence: ``exact`` for the exact payoff token, ``candidate`` for an uppercase or
    future ``proof_*`` shape, and ``generic`` for a word{...} flag when no flag-format value is present. UUID-v4
    nibbles do not change the confidence; callers may validate them with PAYOFF_V4. Multiple values are all
    returned: this function surfaces what is PRESENT and :func:`best_proof` applies the one-value return gate."""
    if not isinstance(text, str) or not text:
        return []
    exact = sorted(set(m.group(0) for m in PAYOFF_WIRE.finditer(text)))
    proof_like = sorted(set(m.group(0) for m in PAYOFF_LIKE.finditer(text)))
    candidates = [value for value in proof_like if value not in exact]
    if exact or candidates:
        return [(v, "exact") for v in exact] + [(v, "candidate") for v in candidates]
    if not allow_generic:
        return []
    # CSS (btn{color:red}) matches the broad shape but is not a flag: never surfaced as one (R-16)
    generic = sorted(set(m.group(0) for m in OTHER_LIKE.finditer(text) if flagfmt.shape_reportable(m.group(0))))
    return [(v, "generic") for v in generic]


def best_proof(responses, *, allow_generic=True):
    """The one safe auto-return across response texts, or ``None``.

    Exactly one exact payoff-token value returns as ``(value, "exact")``. A second
    flag-format value makes the result ambiguous. Uppercase, future shapes and generic flags remain available
    through :func:`extract_proof`, but are never returned here.
    """
    exact_seen, candidate_seen, generic_seen = set(), set(), set()
    for text in responses:
        for value, kind in extract_proof(text, allow_generic=allow_generic):
            if kind == "exact":
                exact_seen.add(value)
            elif kind == "candidate":
                candidate_seen.add(value)
            else:
                generic_seen.add(value)
    if len(exact_seen) == 1 and not candidate_seen:
        return next(iter(exact_seen)), "exact"
    return None


# ---------------------------------------------------------------------------------------------------------
# Recon: bounded GETs of the target's own disclosed/conventional surface.
# ---------------------------------------------------------------------------------------------------------
def _allowed(path):
    """Same guard proof_hunt applies before any GET: a destructive word in the path or its query refuses it.
    Every path in RECON_PATHS is fixed and harmless, so this only matters if a caller extends the list."""
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        return False
    base, _, query = path.partition("?")
    if _DESTRUCTIVE.search(base):
        return False
    for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if _DESTRUCTIVE.search(k):
            return False
    return True


def _links(text):
    """Same-ish-host hrefs/srcs/actions a page offers, read only for the parameter-name hints they carry
    (never followed off host; recon makes no request this function returns)."""
    if not isinstance(text, str) or not text:
        return []
    out = []
    for m in _ATTR_URL.finditer(text[:200_000]):
        raw = next(g for g in m.groups() if g is not None)
        if raw and not raw.startswith(("#", "mailto:", "javascript:", "data:", "tel:", "http://", "https://")):
            out.append(raw)
    return out


def _param_words_in(links):
    words = set()
    for link in links:
        q = urllib.parse.urlsplit(link).query
        for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True):
            words.add(k.lower())
    return words


def _link_path(raw):
    """The same-host path a relative href/action names ("/x", "x", "./x" -> "/x"), query dropped."""
    return urllib.parse.urlsplit(urllib.parse.urljoin("/", raw)).path or "/"


class _SurfaceParser(HTMLParser):
    """Read-only parse of the already-fetched landing page for command-injection triage: each <form>'s action,
    method and named controls (inputs outside any form are kept separately, with no endpoint), and the "focused"
    text an operator reads as a feature name -- title, headings, link/label/button text, form text and
    placeholders. Body prose is deliberately left out of the focused text, so "dig into the docs" in a paragraph
    is not a lookup feature. Never fetches anything.

    Focus is capped to each focus element: a block-level start tag (<p>, <div>, <li>, ...) ends any focus
    element left open, and a second <a>/<label>/<button> (or a heading) implicitly closes an open one, so an
    unclosed <a> cannot turn the rest of the page's prose into focused text. <script>/<style> data is never
    text, inside a form or out."""

    FOCUS_TAGS = frozenset(("title", "h1", "h2", "h3", "h4", "h5", "h6", "a", "label", "button", "legend"))
    HEADINGS = frozenset(("h1", "h2", "h3", "h4", "h5", "h6"))
    CONTROL_TAGS = frozenset(("input", "select", "textarea", "button"))
    BLOCK_TAGS = frozenset(("html", "head", "body", "p", "div", "section", "article", "main", "header", "footer",
                            "nav", "aside", "ul", "ol", "li", "dl", "dt", "dd", "table", "thead", "tbody",
                            "tfoot", "tr", "td", "th", "pre", "blockquote", "hr", "form", "fieldset", "figure",
                            "address", "details", "summary")) | HEADINGS
    RAW_TAGS = frozenset(("script", "style"))     # html.parser reads both as raw text (no nested tags)

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.orphan_inputs = []
        self.focus = []
        self._form = None
        self._open = []          # focus elements currently open (innermost last)
        self._raw = None         # inside <script>/<style>: data is not page text

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in self.RAW_TAGS:
            self._raw = tag
            return
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").upper(),
                          "inputs": []}
            self.forms.append(self._form)
        if tag in self.CONTROL_TAGS and a.get("name"):
            (self._form["inputs"] if self._form is not None else self.orphan_inputs).append(a["name"])
        if tag in self.CONTROL_TAGS and a.get("placeholder"):
            self.focus.append(a["placeholder"])
        if tag in self.BLOCK_TAGS:
            self._open = []
        elif tag in self._open:
            del self._open[self._open.index(tag):]
        if tag in self.FOCUS_TAGS:
            self._open.append(tag)

    def handle_endtag(self, tag):
        if self._raw is not None:
            if tag == self._raw:
                self._raw = None
            return
        if tag == "form":
            self._form = None
        if tag in self._open:
            del self._open[len(self._open) - 1 - self._open[::-1].index(tag):]

    def handle_data(self, data):
        if self._raw is not None:
            return
        if self._open or self._form is not None:
            self.focus.append(data)


_DEFAULT_PORTS = {"http": 80, "https": 443}


def _authority(parts, default_scheme):
    """(hostname, effective port) of a split URL, or ``None`` when its port is malformed."""
    scheme = (parts.scheme or default_scheme or "http").lower()
    try:
        port = parts.port
    except ValueError:
        return None
    return (parts.hostname or "").lower(), port or _DEFAULT_PORTS.get(scheme)


def _parse_surface(text, base_url):
    """(forms, orphan input names, focused text) of one page fetched from ``base_url``.

    A form posting to another host or another port is dropped (it is not this target's surface). A form whose
    action is not http(s) (``javascript:void(0)``, ``mailto:``) is a script-driven form: it names no route, so
    its named controls are kept as endpoint-less inputs rather than given a bogus endpoint."""
    parser = _SurfaceParser()
    if isinstance(text, str) and text:
        parser.feed(text[:200_000])
        parser.close()
    base = urllib.parse.urlsplit(base_url or "")
    here = _authority(base, base.scheme)
    forms, orphans = [], list(parser.orphan_inputs)
    for f in parser.forms:
        parts = urllib.parse.urlsplit(f["action"].strip())
        if parts.scheme and parts.scheme.lower() not in ("http", "https"):
            orphans.extend(f["inputs"])
            continue
        if parts.netloc and (here is None or _authority(parts, base.scheme) != here):
            continue
        query_words = [k for k, _ in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
        forms.append({"action": _link_path(parts.path) if parts.path else "/", "method": f["method"],
                      "inputs": [n.lower() for n in f["inputs"] + query_words]})
    return forms, [n.lower() for n in orphans], " ".join(parser.focus)


def recon(url, *, timeout=REQUEST_TIMEOUT, max_requests=DEFAULT_MAX_REQUESTS, deadline=None):
    """Bounded, read-only recon of one target: `RECON_PATHS` (13 fixed GETs at most), classified into likely
    vuln classes with the endpoints/params to try first. Never raises on a per-path failure (a 404, a refused
    connection on one path does not stop the rest); the client's own scope lock and `VPNRequired` (a player
    stop for a private target with no VPN) propagate, since those are not recon failures to paper over."""
    client = _web.WebClient(url, timeout=timeout)
    host = urllib.parse.urlsplit(url).hostname or ""
    pages = {}
    sent = 0
    t0 = time.time()
    for path in RECON_PATHS:
        if sent >= max_requests:
            break
        if deadline is not None and deadline - time.time() <= DEADLINE_PAD:
            break
        if not _allowed(path):
            continue
        sent += 1
        try:
            r = client.get(path, allow_redirects=False)
        except Exception:
            pages[path] = None
            continue
        body = r.get("body")
        raw = bytes(body) if isinstance(body, (bytes, bytearray)) else (body or "").encode("utf-8", "replace")
        text = raw.decode("utf-8", "replace")
        hdrs = {str(k): str(v) for k, v in (r.get("response_headers") or {}).items()}
        pages[path] = {"status": r.get("status"), "text": text, "raw": raw, "headers": hdrs}

    root = pages.get("/")
    headers = dict(root["headers"]) if root else {}
    server_hint = None
    hay = " ".join([headers.get("Server", ""), headers.get("X-Powered-By", "")]).lower()
    for needle, name in _FRAMEWORK_HINTS:
        if needle in hay:
            server_hint = name
            break

    status = {p: (pg.get("status") if pg else None) for p, pg in pages.items()}
    disclosed = {}

    # clue feed (/api/clues): read-only parse of what the target states about itself (a read-only parse).
    PH = _proof_hunt()
    clue_hints = {"params": [], "routes": {}, "examples": {}, "role": None, "framework": None}
    clue_page = pages.get("/api/clues")
    if clue_page and clue_page.get("status") == 200:
        doc = _json_document(clue_page["text"])
        if isinstance(doc, dict):
            if PH is not None:
                try:
                    clue_hints = PH.parse_clue_hints(doc)
                except Exception:
                    pass
            disclosed["clues"] = {k: v for k, v in doc.items() if isinstance(v, (str, int, float, bool))}

    # openapi.json / swagger.json: a route inventory, read-only.
    api_routes = []
    for spec_path in ("/openapi.json", "/swagger.json"):
        sp = pages.get(spec_path)
        if sp and sp.get("status") == 200:
            spec = _json_document(sp["text"])
            if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
                api_routes = [p for p in spec["paths"] if isinstance(p, str)]
                disclosed["openapi"] = {"source": spec_path, "route_count": len(api_routes),
                                        "routes": api_routes[:60]}
                break

    # robots.txt: Disallow paths (a listing/backup exposure hint, read-only; never fetched here beyond
    # robots.txt itself -- the Disallow targets are left for proof_hunt's own breadth, since fetching them is
    # already its job and duplicating it here would cost requests without adding triage value).
    robots_disallow = []
    rb = pages.get("/robots.txt")
    if rb and rb.get("status") == 200:
        for line in rb["text"].splitlines()[:200]:
            m = re.match(r"(?i)\s*disallow\s*:\s*(\S+)", line)
            if m and m.group(1).startswith("/"):
                robots_disallow.append(m.group(1))
    if robots_disallow:
        disclosed["robots_disallow"] = robots_disallow[:20]

    # landing page links: parameter-name hints only (no fetch beyond the already-fetched "/").
    landing_links = _links(root["text"]) if root else []
    landing_params = _param_words_in(landing_links)
    if landing_params:
        disclosed["landing_params"] = sorted(landing_params)

    git_exposed = status.get("/.git/HEAD") == 200 and (pages.get("/.git/HEAD") or {}).get("text", "").startswith("ref:")
    env_exposed = status.get("/.env") == 200
    backup_exposed = status.get("/backup.zip") == 200
    config_exposed = status.get("/config.json") == 200
    debug_exposed = status.get("/debug/vars") == 200 or status.get("/actuator/env") == 200 or status.get("/server-status") == 200
    graphql_exposed = (status.get("/graphql") not in (None, 404)
                      or any("graphql" in r.lower() for r in api_routes))

    # zip-exposure: the backup.zip (if present) names its members only, never extracted/executed here.
    backup_members = []
    if backup_exposed:
        bp = pages.get("/backup.zip")
        try:
            with zipfile.ZipFile(io.BytesIO(bp["raw"])) as zf:
                backup_members = zf.namelist()[:30]
        except Exception:
            pass
    if backup_members:
        disclosed["backup_zip_members"] = backup_members

    classes = []

    def add(vuln_class, confidence, evidence, endpoints=(), params=()):
        classes.append({"vuln_class": vuln_class, "confidence": confidence, "evidence": list(evidence),
                        "endpoints": list(dict.fromkeys(endpoints)), "params": list(dict.fromkeys(params))})

    # Clue-driven classes first (most specific: the target names its own vulnerable surface).
    if clue_hints.get("routes"):
        routes = clue_hints["routes"]
        feature = routes.get("feature_route")
        secondary = routes.get("secondary_route")
        session_hint = disclosed.get("clues", {}).get("session_hint")
        callback_nonce = disclosed.get("clues", {}).get("callback_nonce")
        protected_ref = disclosed.get("clues", {}).get("protected_reference")
        if feature and session_hint:
            add("session_fixation_or_idor", "high",
                ["/api/clues names feature_route and secondary_route with a session_hint"],
                endpoints=[feature, secondary] if secondary else [feature],
                params=clue_hints.get("params") or [])
        elif feature and callback_nonce:
            add("ssrf_or_callback_auth", "high",
                ["/api/clues names secondary_route and a callback_nonce"],
                endpoints=[feature, secondary] if secondary else [feature],
                params=clue_hints.get("params") or [])
        elif feature and protected_ref:
            add("broken_access_control", "high",
                ["/api/clues (or the inventory) advertises feature_route, fields/actions and a protected_reference"],
                endpoints=[feature], params=clue_hints.get("params") or [])
        elif feature:
            add("clue_advertised_route", "medium",
                ["/api/clues names a feature_route with no further hint"], endpoints=list(routes.values()),
                params=clue_hints.get("params") or [])

    if git_exposed:
        add("git_exposure", "high", ["/.git/HEAD is readable and looks like a git ref"], endpoints=["/.git/HEAD"])
    if env_exposed:
        add("secret_file_exposure", "high", ["/.env is readable"], endpoints=["/.env"])
    if backup_exposed:
        add("backup_exposure", "high", ["/backup.zip is readable" + (f", members: {backup_members[:3]}" if backup_members else "")],
            endpoints=["/backup.zip"])
    if config_exposed:
        add("config_exposure", "medium", ["/config.json is readable"], endpoints=["/config.json"])
    if debug_exposed:
        add("debug_endpoint_exposure", "medium",
            [p for p in ("/debug/vars", "/actuator/env", "/server-status") if status.get(p) == 200],
            endpoints=[p for p in ("/debug/vars", "/actuator/env", "/server-status") if status.get(p) == 200])
    if robots_disallow:
        add("robots_disclosed_path", "medium", [f"robots.txt disallows {robots_disallow[:3]}"],
            endpoints=robots_disallow)

    idor_params = {p for p in landing_params if p in ("id", "item", "object", "ref", "uid", "doc_id")}
    idor_feed = disclosed.get("openapi", {}).get("routes", []) or []
    idor_routes = [r for r in idor_feed if re.search(r"\{[a-zA-Z_]*id[a-zA-Z_]*\}|/\d|<int:", r)]
    if idor_routes or idor_params:
        add("idor", "medium" if idor_routes else "low",
            ["an openapi route names an id-like path parameter" if idor_routes else
             "the landing page links an id-like query parameter"],
            endpoints=idor_routes, params=sorted(idor_params))

    lfi_params = landing_params & set(_LFI_PARAM_WORDS)
    if lfi_params:
        add("lfi", "medium", ["the landing page links a reader-style parameter"], params=sorted(lfi_params))

    ssrf_params = (landing_params | set(clue_hints.get("params") or [])) & set(_SSRF_PARAM_WORDS)
    if ssrf_params:
        add("ssrf", "medium", ["the landing page or clue feed names a fetch-style parameter"],
            params=sorted(ssrf_params))

    # Command-injection TRIAGE (detection only, GET-only; no probe is ever sent). Point proof_hunt's gated cmdi
    # reader at an advertised command/lookup surface. Parameter words come from landing links, the clue feed and
    # the landing page's own <form> controls (a "Ping a host" form is the commonest CTF cmdi shape). A strong,
    # SSRF-unambiguous host/ip/dns/ping-style param is a hint on its own; an ambiguous one (e.g. ``target``)
    # only counts alongside lookup-surface text -- then both the ssrf and this row fire, since it really is
    # ambiguous. Lookup-surface text is read from the clue feed and the page's focused text (title, headings,
    # link/label/button/form text); body prose counts only when a lookup-named route is also disclosed.
    forms, orphan_inputs, focus_text = _parse_surface(root["text"], url) if root else ([], [], "")
    if forms:
        disclosed["forms"] = [{"action": f["action"], "method": f["method"], "inputs": f["inputs"][:12]}
                              for f in forms[:10]]
    param_paths = {}                 # parameter word -> the paths that disclosed it

    def disclose(word, path):
        param_paths.setdefault(word, [])
        if path and path not in param_paths[word]:
            param_paths[word].append(path)

    for link in landing_links:
        for k, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(link).query, keep_blank_values=True):
            disclose(k.lower(), _link_path(link))
    feature_route = (clue_hints.get("routes") or {}).get("feature_route")
    for word in clue_hints.get("params") or []:
        disclose(str(word).lower(), feature_route)
    for f in forms:
        for word in f["inputs"]:
            disclose(word, f["action"])
    for word in orphan_inputs:
        disclose(word, None)
    cmdi_param_words = set(param_paths)
    strong_cmdi = sorted(cmdi_param_words & set(_CMDI_STRONG_PARAM_WORDS))
    weak_cmdi = sorted(cmdi_param_words & set(_CMDI_PARAM_WORDS))
    clue_scalar_text = " ".join(str(v) for v in disclosed.get("clues", {}).values())
    route_endpoints = [p for p in ([_link_path(link) for link in landing_links] + [f["action"] for f in forms]
                                   + api_routes) if _CMDI_ROUTE_WORD.search(p)]
    focused_surface = bool(_CMDI_SURFACE_TEXT.search(focus_text + " " + clue_scalar_text))
    page_surface = bool(root and _CMDI_SURFACE_TEXT.search(root["text"][:200_000]))
    cmdi_surface = focused_surface or (page_surface and bool(route_endpoints))
    if strong_cmdi or (cmdi_surface and weak_cmdi):
        reported = strong_cmdi or weak_cmdi
        endpoints = [feature_route] if (cmdi_surface and feature_route) else []
        endpoints += [p for w in reported for p in param_paths[w]] + route_endpoints
        ev = []
        if strong_cmdi:
            ev.append("the landing page, a form or the clue feed names a command/lookup-style parameter")
        if cmdi_surface:
            ev.append("the disclosed surface names a ping/nslookup/dns-lookup feature")
        add("command_injection", "medium", ev, endpoints=endpoints, params=reported)
    elif cmdi_surface and (route_endpoints or feature_route):
        add("command_injection", "low",
            ["the disclosed surface names a ping/nslookup/dns-lookup feature (no named parameter yet)"],
            endpoints=([feature_route] if feature_route else []) + route_endpoints)

    search_params = landing_params & set(_SEARCH_PARAM_WORDS)
    if search_params:
        add("sqli_or_search_injection", "low", ["the landing page links a search parameter"],
            params=sorted(search_params))

    if graphql_exposed:
        add("graphql", "medium", ["/graphql answers or an openapi route names it"], endpoints=["/graphql"])

    if disclosed.get("openapi"):
        add("openapi_disclosed_surface", "low",
            [f"{disclosed['openapi']['route_count']} route(s) named in {disclosed['openapi']['source']}"],
            endpoints=disclosed["openapi"]["routes"][:12])

    if not classes:
        add("no_clear_signal", "low", ["recon found no disclosed vuln-class hint; fall back to proof_hunt's full breadth"])

    return {
        "host": host,
        "status": status,
        "headers": headers,
        "server_hint": server_hint,
        "disclosed": disclosed,
        "classes": classes,
        "requests": sent,
        "seconds": round(time.time() - t0, 3),
    }


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: recon_triage.py <url> [--seconds N] [--max-requests N]", file=sys.stderr)
        return 1
    url = argv[0]
    seconds = DEFAULT_MAX_REQUESTS
    max_requests = DEFAULT_MAX_REQUESTS
    i = 1
    while i < len(argv):
        if argv[i] == "--seconds" and i + 1 < len(argv):
            seconds = float(argv[i + 1]); i += 2
        elif argv[i] == "--max-requests" and i + 1 < len(argv):
            max_requests = int(argv[i + 1]); i += 2
        else:
            i += 1
    try:
        out = recon(url, max_requests=max_requests, deadline=time.time() + seconds)
    except Exception as e:
        print(f"recon_triage: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
