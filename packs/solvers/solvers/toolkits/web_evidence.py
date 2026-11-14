#!/usr/bin/env python3
"""Web lane, static form: access logs, HAR, tokens and cookies, source review (toolkit `web_evidence`).

  .venv/bin/python solvers/toolkits/web_evidence.py <file|dir|zip>... [--json] [--all]

Offline: no request, no token, stdlib only, nothing slow. It prints a triage of the files: what
each one is, the per-IP, per-route, per-status and per-user-agent tables, every request that
carries a payload (family, parameter, decoded value), every JWT and session cookie decoded, and
for a shipped application its route table, its dangerous calls, its hardcoded secrets and its
HTML forms, script blocks and comments.

Readers an agent can call by hand (all return plain dicts and lists):

  read_log(data, name)      [event, ...] of an Apache/nginx combined or common log, an IIS W3C log
                            (its #Fields line names the columns), a JSON-lines or JSON-array or CSV
                            proxy/WAF log, or a HAR. log_kind(data, name) says which it is.
  deep_unquote(text)        (decoded, rounds): percent-decoding repeated until nothing changes
  tables(events)            {"ip", "route", "status", "user_agent", "method"}: Counter each
  ip_activity(events)       {address: {requests, first, last, statuses, methods, paths, user_agents,
                            forwarded, forwarded_via}}: one row per client address, for a join with
                            another log by IP (cloudlogs.py's pivot). An address a proxy names in
                            X-Forwarded-For is counted apart (forwarded), never as a request of its own
  findings(events)          [{family, event, where, param, raw, payload, ...}]: SQL injection,
                            template injection, traversal, command injection, XSS, web shell
                            (upload and use), JNDI, and shellshock, XXE, SSRF, deserialization,
                            NoSQL injection; then brute force, enumeration and scanner by behaviour
  find_tokens(text)         JWTs in a text; decode_jwt(token) -> {header, claims, alg, kid, ...}
  decode_cookie(value)      a Flask session cookie (signed, zlib or not) or a base64 JSON cookie
  read_source(files)        {"routes", "sinks", "taint", "secrets", "forms", "scripts", "comments",
                            "regex_gates", "traps"} (the last two from web_traps.py, B-104)
  Evidence(files)           everything above over one delivery, built once
  live_target(attempt)      the URL or host a start response points at, or None
  client_constants(files)   the User-Agent and URL constants a shipped client hard-codes (B-131)

Nothing here signs, forges or verifies a token, and nothing here sends a request. A live target
(a URL or host in the start response) is not this module's: with nothing in the delivery to read,
solve_set answers nothing for it and says so on stderr; the lane's agent alerts and stops for the player
(AGENTS.md, "Private targets"). With a delivery beside the target (white-box source, the instance's
log, a HAR) the delivery's own facts are answered as without one, and every plain secret, password,
key, token or flag answer is made unsure under `web.live_secret/<what>+<scope>@<challenge>` (live_guard;
LIVE_TARGET_GUARD): what the running instance holds is the author's choice, not the bytes'.

The runner contract (never-guess, AGENTS.md "Uncertain answers"). `web` field names are not fixed,
so solve_set answers plain only a fact with one form, under the exactly-one rule:

  attacker IP            the one address that sent a payload request
  parameter              the one parameter name that carried a payload
  status, method         the one value over the payload requests (the first one's when asked)
  user agent             the one user agent of the payload requests, as logged
  route                  the one path of the payload requests, when its raw and decoded forms agree
  uploaded file name     the one name of the upload (multipart filename, or the shell requested)
  decoded payload        the one decoded value, when '+' cannot be read two ways
  token alg, kid, claim  the one value over every token in the delivery that carries it
  hardcoded secret       the one secret in the source; line number and route of the one sink
  counts                 distinct client addresses, requests with a status, requests of an address

Two or more candidates is None: a decoy, a second attack or a second token is the author's
choice, not the bytes'. Everything whose spelling the author chose is an unsure answer:
labels.pick('web.vuln/<family>', ...) for the vulnerability class, 'web.technique/<family>.<technique>'
for the one technique the payloads show (one key, one fact: a bare-label key answers its accepted name
on every later variant), 'web.cwe/<family>',
'web.attack/<family>', 'web.sink/<call>', 'web.tool/<tool>', and every time
('web.time/<log kind>', names raw, iso_utc_z, iso_utc, iso_offset, space_utc, epoch; plain only
when the answer format's own template or pattern leaves one). tools/verify.py probes them on the
untimed base.

`web` is a real labels prefix now (labels.TOOLKIT_PREFIXES includes "web"), shared by this toolkit
and `web.py`, so _pick reads the `web` seed/ledger and tools/verify.py probes an unsure `web.*`
answer on the untimed base. If labels.py is ever unavailable (an export with a different import
path), _pick writes the same wire form itself: such a value is never sent (gm.session() drops every
`??` value) and the answer shows as unsure in gaps.json for the lane's agent.

OWASP Top 10 coverage: broken access control / IDOR (A01), security
misconfiguration (A05), vulnerable components (A06), authentication abuse (A07), cryptographic
failures in a JWT (A02), open redirect (A03, request-derived only) and Flask debug mode are read
from response headers, request behaviour, tokens and the shipped source. Every class name is author
vocabulary and is returned UNSURE (never a plain class); which client is the actor is a human call
(None).
"""
import sys
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
# Run as a script, Python puts this folder first on the path, and a sibling toolkit named like a
# standard module (email.py) would then be imported in its place.
if __name__ == "__main__":
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != HERE]

import base64       # noqa: E402
import binascii     # noqa: E402
import bisect       # noqa: E402
import csv          # noqa: E402
import datetime as dt   # noqa: E402
import io           # noqa: E402
import ipaddress    # noqa: E402
import json         # noqa: E402
import os           # noqa: E402
import re           # noqa: E402
import zipfile      # noqa: E402
import zlib         # noqa: E402
from collections import Counter     # noqa: E402
from functools import lru_cache     # noqa: E402
from html import unescape as html_unescape     # noqa: E402
from urllib.parse import unquote, urlsplit      # noqa: E402

COMMON = HERE.parent / "common"
ARROW = " -> "
SENTINEL = "??"
MAX_OPTIONS = 12
MAX_LOG = 32 * 1024 * 1024      # bytes of one file read as a log
MAX_EVENTS = 400000
MAX_SOURCE = 2 * 1024 * 1024    # bytes of one source file read
MAX_VALUE = 4096                # characters of one request value matched against the payload patterns
UTC = dt.timezone.utc
MAX_JSON_MEMBERS = 4_000_000
MAX_JSON_NODES = 8_000_000
MAX_TOKEN_JSON = 256 * 1024
MAX_PCAP_BYTES = 64 * 1024 * 1024
MAX_PCAP_HTTP_BODY = 1 * 1024 * 1024
MAX_PCAP_HTTP_CHUNKS = 65_536
_SECURITY_JSON_MOD = None
_NETWORK_READER_MOD = None


def _bounded_decimal(value, max_digits=20):
    """Parse a small ASCII decimal without invoking unbounded ``int()`` work."""
    text = str(value)
    if not re.fullmatch(r"[0-9]{1,%d}" % max_digits, text):
        return None
    return int(text)


def _security_json_module():
    """Load solvers/web/security_json.py by path in script and imported modes."""
    global _SECURITY_JSON_MOD
    if _SECURITY_JSON_MOD is False:
        return None
    if _SECURITY_JSON_MOD is None:
        try:
            import importlib.util
            path = HERE.parent / "web" / "security_json.py"
            spec = importlib.util.spec_from_file_location(
                "csctf_security_json_web_evidence", path)
            if spec is None or spec.loader is None:
                raise ImportError("security_json loader unavailable")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _SECURITY_JSON_MOD = module
        except Exception:
            _SECURITY_JSON_MOD = False
            return None
    return _SECURITY_JSON_MOD


def _strict_json(data, *, max_chars=MAX_LOG, max_members=MAX_JSON_MEMBERS,
                 max_nodes=MAX_JSON_NODES, max_depth=64):
    """Bounded artifact JSON with duplicate/canonical-collision rejection."""
    module = _security_json_module()
    if module is None:
        return None
    try:
        if isinstance(data, (bytes, bytearray)):
            if len(data) > max_chars:
                return None
            text = bytes(data).decode("utf-8-sig", "strict")
        elif isinstance(data, str):
            text = data[1:] if data.startswith("\ufeff") else data
        else:
            return None
        if len(text.encode("utf-8")) > max_chars:
            return None
        return module.loads(text, max_chars=max_chars, max_members=max_members,
                            max_nodes=max_nodes, max_depth=max_depth)
    except Exception:
        return None


def _common(name):
    """A module of solvers/common (labels, triage), or None where it cannot be imported."""
    try:
        if str(COMMON) not in sys.path:
            sys.path.append(str(COMMON))
        return __import__(name)
    except Exception:
        return None


def _pairs(options) -> list:
    out, seen = [], set()
    for item in ([options] if isinstance(options, (str, bytes)) else (options or [])):
        if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
            name, value = item
        else:
            name, value = (item if isinstance(item, str) else str(item)), item
        if name == "" or value is None or name in seen:
            continue
        seen.add(name)
        out.append((name, value))
    return out


def _pick(key, options):
    """labels.pick; the same wire form written here while labels.py does not know the lane `web`
    (see the module text: such a value is never sent and never probed)."""
    pairs = _pairs(options)
    if not pairs:
        return None
    labels = _common("labels")
    if labels is not None:
        try:
            return labels.pick(key, pairs)
        except ValueError:
            pass
    body = {"k": str(key).strip().lower(), "o": [[n, v] for n, v in pairs[:MAX_OPTIONS]]}
    return SENTINEL + json.dumps(body, separators=(",", ":"))


# ---- text and decoding -----------------------------------------------------------------------------

def text_of(data):
    """The bytes as text when they are text (UTF-8, UTF-16 with a BOM, else Latin-1 when printable)."""
    if isinstance(data, str):
        return data
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data[:MAX_LOG])
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:4096]:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
        sample = text[:4096]
        return text if sum(c.isprintable() or c in "\r\n\t" for c in sample) >= 0.97 * max(1, len(sample)) else None


_PCT_U = re.compile(r"%u([0-9a-fA-F]{4})")


def deep_unquote(text, plus=False, rounds=6) -> tuple:
    """(decoded, rounds used): percent-decoding (and %uXXXX) repeated until nothing changes. With
    plus=True a '+' of the first round is a space, as in a query string or a form body."""
    text = "" if text is None else str(text)
    used = 0
    for i in range(rounds):
        step = text.replace("+", " ") if (plus and i == 0) else text
        step = unquote(_PCT_U.sub(lambda m: chr(int(m.group(1), 16)), step), errors="replace")
        if step == text:
            break
        text, used = step, used + 1
    return text, used


def _b64url(text, max_bytes=None):
    text = str(text).strip()
    if not text or not re.fullmatch(r"[A-Za-z0-9_\-+/]*={0,2}", text):
        return None
    if max_bytes is not None and len(text.rstrip("=")) > ((int(max_bytes) + 2) // 3) * 4:
        return None
    text = text.rstrip("=").replace("+", "-").replace("/", "_")
    if len(text) % 4 == 1:
        return None
    try:
        out = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        return out if max_bytes is None or len(out) <= int(max_bytes) else None
    except (binascii.Error, ValueError):
        return None


# ---- time ----------------------------------------------------------------------------------------------

_MONTHS = {m: i + 1 for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split())}
_CLF_TIME = re.compile(r"(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:\s*([+-])(\d{2}):?(\d{2}))?")


def parse_time(value):
    """A datetime (aware when the text carries a zone) from an access-log time, an ISO 8601 text or
    an epoch number in seconds or milliseconds; None when it is none of them."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        n = float(value)
        if n > 1e11:
            n /= 1000.0
        if not 1e8 < n < 4.2e9:
            return None
        return dt.datetime.fromtimestamp(n, UTC)
    s = str(value).strip().strip("[]")
    if not s:
        return None
    m = _CLF_TIME.fullmatch(s)
    if m:
        mon = _MONTHS.get(m.group(2).lower())
        if not mon:
            return None
        tz = None
        if m.group(7):
            off = dt.timedelta(hours=int(m.group(8)), minutes=int(m.group(9)))
            tz = dt.timezone(off if m.group(7) == "+" else -off)
        try:
            return dt.datetime(int(m.group(3)), mon, int(m.group(1)), int(m.group(4)), int(m.group(5)), int(m.group(6)), tzinfo=tz)
        except ValueError:
            return None
    if re.fullmatch(r"\d{9,10}(?:\.\d+)?|\d{13}", s):
        return parse_time(float(s))
    try:
        return dt.datetime.fromisoformat(s.replace(" UTC", "+00:00").replace(",", "."))
    except ValueError:
        return None


def _sort_key(ev):
    t = ev.get("ts")
    if t is None:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def time_options(t, raw) -> list:
    """[(name, value)] spellings of one moment, best first. A time with no zone is offered as it is
    written (its zone is not in the bytes)."""
    out = []
    if t is not None and t.tzinfo is not None:
        u = t.astimezone(UTC).replace(microsecond=0)
        out += [("iso_utc_z", u.strftime("%Y-%m-%dT%H:%M:%SZ")), ("iso_utc", u.strftime("%Y-%m-%dT%H:%M:%S")),
                ("space_utc", u.strftime("%Y-%m-%d %H:%M:%S")),
                ("iso_offset", t.replace(microsecond=0).isoformat()), ("epoch", str(int(u.timestamp())))]
    elif t is not None:
        n = t.replace(microsecond=0)
        out += [("iso_local", n.strftime("%Y-%m-%dT%H:%M:%S")), ("space_local", n.strftime("%Y-%m-%d %H:%M:%S"))]
    if raw and str(raw) not in [v for _, v in out]:
        out.append(("raw", str(raw)))
    return out


_TEMPLATES = (     # (the answer format's own template, the name it states, True when it states the zone itself)
    (r"yyyy-mm-ddthh:mm:ssz", "iso_utc_z", True), (r"yyyy-mm-dd hh:mm:ss utc", "space_utc", True),
    (r"yyyy-mm-ddthh:mm:ss", "iso_utc", False), (r"yyyy-mm-dd hh:mm:ss", "space_utc", False),
)


# ---- log readers ---------------------------------------------------------------------------------------

_ACCESS = re.compile(
    r'^(?:(?P<vhost>[\w.-]+(?::\d+)?) )?(?P<ip>[0-9a-fA-F:.]+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d{1,20}|-)(?!\d)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?(?P<rest>.*)$')
_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT", "PROPFIND", "MKCOL", "MOVE", "COPY")


def _is_ip(text) -> bool:
    try:
        ipaddress.ip_address(str(text))
        return True
    except ValueError:
        return False


def _event(src, line, kind) -> dict:
    return {"src": src, "line": line, "kind": kind, "ip": None, "ts": None, "ts_raw": None, "method": None,
            "target": None, "path_raw": None, "path": None, "query_raw": None, "params": [], "status": None,
            "size": None, "referer": None, "ua": None, "user": None, "host": None, "body": None, "headers": {},
            "extra": {}}


def _set_target(ev, target, query=None):
    """Fill path and params from a request target (path?query, or a full URL)."""
    target = "" if target is None else str(target)
    ev["target"] = target if query in (None, "", "-") else f"{target}?{query}"
    if re.match(r"[a-z][a-z0-9+.-]*://", target, re.I):
        parts = urlsplit(target)
        ev["host"] = ev["host"] or parts.netloc
        target = parts.path + ("?" + parts.query if parts.query else "")
    path, _, q = target.partition("?")
    if query not in (None, "", "-"):
        q = str(query).lstrip("?")
    ev["path_raw"], ev["query_raw"] = path, q
    ev["path"] = deep_unquote(path)[0]
    ev["params"] = _params(q, "query")


def _params(text, where) -> list:
    """[{where, name, raw, value, value_noplus}] of a query string or an urlencoded body."""
    out = []
    for piece in str(text or "").split("&"):
        if not piece:
            continue
        name, _, raw = piece.partition("=")
        out.append({"where": where, "name": deep_unquote(name, plus=True)[0], "raw": raw,
                    "value": deep_unquote(raw, plus=True)[0], "value_noplus": deep_unquote(raw)[0]})
    return out


def _clf_unescape(text):
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), text).replace('\\"', '"') if "\\" in text else text


def _access_match(line):
    """The match of one access-log line. A line that a spreadsheet or a data-set export wrapped in
    one more pair of double quotes (`"1.2.3.4 - - [..] "GET / HTTP/1.1" 200 5 "-" "ua""`) is read
    without them."""
    line = line.strip()
    m = _ACCESS.match(line)
    if not m and len(line) > 2 and line[0] == '"' and line[-1] == '"':
        m = _ACCESS.match(line[1:-1])
    return m


def parse_access(text, src="") -> list:
    """Apache/nginx common and combined lines (with or without a leading virtual host)."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _access_match(line)
        if not m:
            continue
        ev = _event(src, n, "access_combined" if m.group("ua") is not None else "access_common")
        ev["ip"], ev["ts_raw"], ev["ts"] = m.group("ip"), m.group("ts"), parse_time(m.group("ts"))
        ev["status"] = int(m.group("status"))
        ev["size"] = None if m.group("size") == "-" else int(m.group("size"))
        ev["user"] = None if m.group("user") == "-" else m.group("user")
        ev["host"] = m.group("vhost")
        req = _clf_unescape(m.group("req"))
        parts = req.split(" ")
        if len(parts) >= 2 and parts[0].upper() in _METHODS:
            ev["method"] = parts[0].upper()
            target = " ".join(parts[1:-1]) if len(parts) >= 3 and parts[-1].upper().startswith("HTTP/") else " ".join(parts[1:])
            _set_target(ev, target)
        else:
            ev["extra"]["request"] = req           # a request line that is no HTTP request (a TLS probe, shellcode)
            _set_target(ev, "")
        if m.group("ua") is not None:
            ev["referer"] = None if m.group("ref") in ("-", "") else _clf_unescape(m.group("ref"))
            ev["ua"] = None if m.group("ua") in ("-", "") else _clf_unescape(m.group("ua"))
        if m.group("rest").strip():
            ev["extra"]["rest"] = m.group("rest").strip()
            fwd = _forwarded_for(ev["extra"]["rest"])
            if fwd:
                ev["extra"]["forwarded_for"] = fwd
        out.append(ev)
        if len(out) >= MAX_EVENTS:
            break
    return out


_XFF_FIELD = re.compile(r'^"((?:[^"\\]|\\.)*)"')


def _forwarded_for(rest) -> list:
    """The addresses of the first quoted field after the user agent (nginx's "$http_x_forwarded_for",
    Apache's "%{X-Forwarded-For}i"), when every item of it is an IP address; [] for anything else (a
    request time, a "-", an upstream name). The client wrote that header: it is evidence of what was
    claimed, never the peer address."""
    m = _XFF_FIELD.match(rest)
    if not m:
        return []
    items = [x.strip() for x in m.group(1).split(",")]
    return items if items and all(_is_ip(x) for x in items) else []


def ip_key(text):
    """The one spelling of an IP address two logs can be joined on: brackets and a port dropped, IPv6
    compressed, an IPv4-mapped IPv6 address as its IPv4 one. None for text that is no address.

    cloudlogs.ip_key is a second copy (the cloud side of its --pivot join): change both together.
    tests/test_toolkits_cloudlogs_pivot.py test_ip_key_is_one_spelling_per_address pins that they agree."""
    s = str(text or "").strip()
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\](?::\d+)?", s) or re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):\d+", s)
    if m:
        s = m.group(1)
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped or ip)


def ip_activity(events) -> dict:
    """{address: row} over the events of read_log(), for a join with another log by IP. A row counts
    the requests whose peer address it is (requests, first and last as aware datetimes or None, and
    Counters of statuses, methods, paths and user_agents) and, apart, the requests of OTHER peers
    that name it in X-Forwarded-For (forwarded, forwarded_via: Counter of those peers). An address
    seen only in X-Forwarded-For has requests == 0: a proxy or the client claimed it, no connection
    came from it."""
    out = {}

    def row(key):
        return out.setdefault(key, {"requests": 0, "first": None, "last": None, "statuses": Counter(), "methods": Counter(),
                                    "paths": Counter(), "user_agents": Counter(), "forwarded": 0, "forwarded_via": Counter()})

    for ev in events:
        peer = ip_key(ev.get("ip"))
        if peer is not None:
            r = row(peer)
            r["requests"] += 1
            t = _sort_key(ev)
            if t is not None:
                r["first"] = t if r["first"] is None or t < r["first"] else r["first"]
                r["last"] = t if r["last"] is None or t > r["last"] else r["last"]
            for field, col in (("status", "statuses"), ("method", "methods"), ("path", "paths"), ("ua", "user_agents")):
                if ev.get(field) not in (None, ""):
                    r[col][ev[field]] += 1
        for claimed in dict.fromkeys(k for k in map(ip_key, (ev.get("extra") or {}).get("forwarded_for") or []) if k):
            if claimed != peer:
                r = row(claimed)
                r["forwarded"] += 1
                r["forwarded_via"][peer or "?"] += 1
    return out


def parse_iis(text, src="") -> list:
    """IIS W3C extended lines; the columns are the ones the last #Fields line names."""
    out, fields = [], None
    for n, line in enumerate(text.splitlines(), 1):
        if line.startswith("#"):
            if line.lower().startswith("#fields:"):
                fields = line.split(":", 1)[1].split()
            continue
        if not fields or not line.strip():
            continue
        cols = line.split(" ")
        if len(cols) != len(fields):
            continue
        row = {k.lower(): (None if v == "-" else v) for k, v in zip(fields, cols)}
        ev = _event(src, n, "iis_w3c")
        ev["ip"] = row.get("c-ip")
        if row.get("date") and row.get("time"):
            ev["ts_raw"] = f"{row['date']} {row['time']}"
            t = parse_time(ev["ts_raw"])
            ev["ts"] = t.replace(tzinfo=UTC) if t is not None else None      # W3C extended logs are written in UTC
        ev["method"] = (row.get("cs-method") or "").upper() or None
        _set_target(ev, row.get("cs-uri-stem") or "", row.get("cs-uri-query"))
        ev["status"] = _bounded_decimal(row.get("sc-status")) if row.get("sc-status") is not None else None
        ev["size"] = _bounded_decimal(row.get("sc-bytes")) if row.get("sc-bytes") is not None else None
        ev["ua"] = row.get("cs(user-agent)").replace("+", " ") if row.get("cs(user-agent)") else None
        ev["referer"] = row.get("cs(referer)")
        ev["user"] = row.get("cs-username")
        ev["host"] = row.get("cs-host") or row.get("s-ip")
        if row.get("cs(cookie)"):
            ev["headers"]["cookie"] = row["cs(cookie)"]
        ev["extra"] = {k: v for k, v in row.items() if v is not None and k in ("s-ip", "s-port", "sc-substatus", "sc-win32-status", "time-taken")}
        out.append(ev)
        if len(out) >= MAX_EVENTS:
            break
    return out


_FIELD = {      # the names a JSON or CSV log gives a column, lower case, last dotted part or the whole name
    "ip": ("client_ip", "clientip", "remote_addr", "remoteaddr", "src_ip", "srcip", "source_ip", "sourceip", "c-ip", "ip",
           "client", "remote_ip", "remoteip", "clientaddr", "client_addr", "remote_host", "src", "source.ip", "client.ip",
           "httprequest.clientip", "x_forwarded_for", "remote"),
    "ts": ("timestamp", "@timestamp", "time", "ts", "datetime", "date", "time_local", "time_iso8601", "eventtime",
           "starteddatetime", "start_time", "event_time", "request_time_iso"),
    "method": ("method", "http_method", "httpmethod", "verb", "request_method", "cs-method", "request.method",
               "httprequest.httpmethod"),
    "target": ("uri", "url", "path", "request_uri", "requesturi", "target", "request_path", "cs-uri-stem", "request.uri",
               "request.url", "request.path", "url.original", "uri_path", "httprequest.uri", "resource", "endpoint"),
    "query": ("query", "query_string", "querystring", "args", "cs-uri-query", "request.query", "url.query", "httprequest.args"),
    "status": ("status", "status_code", "statuscode", "response_code", "responsecode", "sc-status", "response.status",
               "http_status", "response_status", "code", "response.status_code", "http.response.status_code", "response",
               "http_response_code", "sc_status"),
    "ua": ("user_agent", "useragent", "ua", "http_user_agent", "agent", "user-agent", "request.headers.user-agent",
           "headers.user-agent", "user_agent.original", "cs(user-agent)"),
    "referer": ("referer", "referrer", "http_referer", "headers.referer"),
    "body": ("body", "request_body", "requestbody", "post_data", "postdata", "payload", "data", "request.body", "form"),
    "host": ("host", "http_host", "server_name", "vhost", "headers.host", "hostname"),
    "user": ("user", "username", "remote_user", "auth_user"),
    "size": ("bytes", "size", "body_bytes_sent", "bytes_sent", "response_size", "sc-bytes"),
    "request": ("request", "request_line", "requestline"),
}


def _flat(obj, prefix="", depth=0, _out=None) -> dict:
    """Flatten one log row while rejecting dotted-vs-nested key aliasing."""
    out = {} if _out is None else _out
    if isinstance(obj, dict) and depth < 5:
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                _flat(v, key, depth + 1, out)
            else:
                flat_key = key.lower()
                if flat_key in out:
                    raise ValueError("ambiguous flattened JSON field")
                out[flat_key] = v
    return out


def _field(flat, what):
    """The row's value for one of the fields above: a whole dotted name first, then a last part."""
    names = _FIELD[what]
    for name in names:
        if name in flat and flat[name] not in (None, "", "-"):
            return flat[name]
    for key, v in flat.items():
        if v in (None, "", "-") or isinstance(v, (dict, list)) and what != "body":
            continue
        if key.rsplit(".", 1)[-1] in names:
            return v
    return None


def _row_event(row, src, n, kind):
    try:
        flat = _flat(row)
    except ValueError:
        return None
    ev = _event(src, n, kind)
    target, method, query = _field(flat, "target"), _field(flat, "method"), _field(flat, "query")
    request = _field(flat, "request")
    if isinstance(request, str):
        parts = request.split(" ")
        if len(parts) >= 2 and parts[0].upper() in _METHODS:
            method = method or parts[0]
            if target is None:
                target = " ".join(parts[1:-1]) if len(parts) >= 3 and parts[-1].upper().startswith("HTTP/") else " ".join(parts[1:])
    if target is None and method is None:
        return None
    ip = _field(flat, "ip")
    ev["ip"] = str(ip).split(",")[0].strip() if ip is not None else None
    raw = _field(flat, "ts")
    ev["ts_raw"], ev["ts"] = (None if raw is None else str(raw)), parse_time(raw)
    ev["method"] = str(method).upper() if method else None
    if isinstance(query, dict):
        query = "&".join(f"{k}={v}" for k, v in query.items())
    _set_target(ev, target or "", query if isinstance(query, str) else None)
    status = _field(flat, "status")
    ev["status"] = _bounded_decimal(status) if status is not None else None
    for key in ("ua", "referer", "host", "user"):
        v = _field(flat, key)
        ev[key] = ev[key] if v is None else str(v)
    body = _field(flat, "body")
    if body is not None:
        ev["body"] = body if isinstance(body, str) else json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    for key, v in flat.items():
        if ".headers." in "." + key and isinstance(v, str):
            ev["headers"][key.rsplit(".", 1)[-1]] = v
        elif key.rsplit(".", 1)[-1] in ("cookie", "authorization", "set-cookie", "content-type") and isinstance(v, str):
            ev["headers"][key.rsplit(".", 1)[-1]] = v
        elif key.rsplit(".", 1)[-1] in ("action", "rule", "rule_id", "ruleid", "message", "msg", "signature", "severity",
                                         "terminatingruleid", "tags") and not isinstance(v, (dict, list)):
            ev["extra"][key.rsplit(".", 1)[-1]] = v
    return ev


def parse_jsonl(text, src="") -> list:
    """A JSON-lines log, or one JSON array of rows (or an object holding one under records, logs,
    events, entries, items, hits or data)."""
    if (not isinstance(text, str) or len(text) > MAX_LOG
            or len(text.encode("utf-8")) > MAX_LOG):
        return []
    rows = []
    stripped = text.lstrip()
    if stripped[:1] == "[" or (stripped[:1] == "{" and "\n" not in stripped.strip()[:2000].rstrip("}")):
        try:
            doc = _strict_json(text)
        except (ValueError, RecursionError):
            doc = None
        if isinstance(doc, dict):
            for key in ("records", "Records", "logs", "events", "entries", "items", "hits", "data"):
                if isinstance(doc.get(key), list):
                    doc = doc[key]
                    break
        if isinstance(doc, list):
            rows = [(i + 1, r) for i, r in enumerate(doc) if isinstance(r, dict)]
    if not rows:
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip().rstrip(",")
            if line[:1] != "{":
                continue
            try:
                r = _strict_json(line, max_chars=MAX_LOG, max_members=262_144,
                                 max_nodes=524_288, max_depth=64)
            except (ValueError, RecursionError):
                continue
            if r is None:
                # A JSON-looking record that the strict policy cannot interpret
                # may hide another actor/method/value. Do not derive facts from
                # only the remaining rows of that log.
                return []
            if isinstance(r, dict):
                rows.append((n, r))
            if len(rows) >= MAX_EVENTS:
                break
    out = []
    for n, r in rows:
        ev = _row_event(r.get("_source") if isinstance(r.get("_source"), dict) else r, src, n, "jsonl")
        if ev is not None:
            out.append(ev)
    return out


def _csv_dialect(text):
    try:
        return csv.Sniffer().sniff(text[:8192], delimiters=",;\t|")
    except csv.Error:
        return csv.excel


def rows_expected(text, kind):
    """How many records a log file holds by its own structure (every non-blank line of an access
    log, every data line of a W3C log, every entry of a HAR or a JSON array, every line of a JSON-lines
    file, every row of a CSV), or None when that cannot be told. A reader that returned fewer events
    skipped some (a line it could not parse, the MAX_EVENTS cut), and no count over them is a fact."""
    try:
        if kind in ("access_combined", "access_common", "access"):
            return sum(1 for ln in text.splitlines() if ln.strip())
        if kind == "iis_w3c":
            return sum(1 for ln in text.splitlines() if ln.strip() and not ln.startswith("#"))
        if kind == "har":
            doc = _strict_json(text)
            entries = doc["log"]["entries"]
            return len(entries) if isinstance(entries, list) else None
        if kind == "jsonl":
            if text.lstrip()[:1] == "[":
                doc = _strict_json(text)
                return len(doc) if isinstance(doc, list) else None
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            return len(lines) if lines and all(ln[:1] == "{" for ln in lines) else None
        if kind == "csv":
            return sum(1 for _ in csv.DictReader(io.StringIO(text), dialect=_csv_dialect(text)))
    except (ValueError, KeyError, TypeError, RecursionError, csv.Error):
        return None
    return None


def parse_csv(text, src="") -> list:
    dialect = _csv_dialect(text)
    out = []
    try:
        for n, row in enumerate(csv.DictReader(io.StringIO(text), dialect=dialect), 2):
            ev = _row_event({str(k).strip(): v for k, v in row.items() if k is not None}, src, n, "csv")
            if ev is not None:
                out.append(ev)
            if len(out) >= MAX_EVENTS:
                break
    except csv.Error:
        return []
    return out


def parse_har(text, src="") -> list:
    """The entries of a HAR (HTTP Archive). A HAR is recorded by the client, so it names the server's
    address, not the client's: `ip` stays None unless an entry carries one (_clientIP, clientIPAddress)."""
    try:
        doc = _strict_json(text)
        entries = doc["log"]["entries"]
    except (ValueError, KeyError, TypeError, RecursionError):
        return []
    if not isinstance(entries, list) or len(entries) > MAX_EVENTS:
        return []
    out = []
    for n, e in enumerate(entries, 1):
        if not isinstance(e, dict) or not isinstance(e.get("request"), dict):
            continue
        req, resp = e["request"], e.get("response") if isinstance(e.get("response"), dict) else {}
        ev = _event(src, n, "har")
        ev["ts_raw"], ev["ts"] = e.get("startedDateTime"), parse_time(e.get("startedDateTime"))
        ev["method"] = str(req.get("method") or "").upper() or None
        _set_target(ev, req.get("url") or "")
        ev["status"] = resp.get("status") if isinstance(resp.get("status"), int) and resp.get("status") else None
        for h in req.get("headers") or []:
            if isinstance(h, dict) and isinstance(h.get("name"), str):
                ev["headers"][h["name"].lower()] = str(h.get("value") or "")
        ev["ua"], ev["referer"] = ev["headers"].get("user-agent"), ev["headers"].get("referer")
        ev["host"] = ev["headers"].get("host") or ev["host"]
        ev["ip"] = e.get("_clientIP") or e.get("clientIPAddress") or None
        ev["extra"]["server_ip"] = e.get("serverIPAddress")
        post = req.get("postData") if isinstance(req.get("postData"), dict) else {}
        if isinstance(post.get("text"), str):
            ev["body"] = post["text"]
        elif isinstance(post.get("params"), list):
            ev["body"] = "&".join(f"{p.get('name')}={p.get('value')}" for p in post["params"] if isinstance(p, dict))
        if post.get("mimeType"):
            ev["headers"].setdefault("content-type", str(post["mimeType"]))
        content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
        if isinstance(content.get("text"), str):
            body = content["text"]
            if content.get("encoding") == "base64":
                body = (_b64url(body, 200000) or b"").decode("utf-8", "replace")
            ev["extra"]["response_body"] = body[:200000]
        sets = [str(h.get("value") or "") for h in resp.get("headers") or [] if isinstance(h, dict) and str(h.get("name")).lower() == "set-cookie"]
        if sets:
            ev["extra"]["set_cookie"] = sets
        rhdrs = {}
        for h in resp.get("headers") or []:         # response headers (row 208: misconfig and components read them)
            if isinstance(h, dict) and isinstance(h.get("name"), str) and str(h.get("name")).lower() != "set-cookie":
                rhdrs.setdefault(h["name"].lower(), str(h.get("value") or ""))
        if rhdrs:
            ev["extra"]["response_headers"] = rhdrs
        out.append(ev)
    return out


def log_kind(data, name="") -> str:
    """'har', 'iis_w3c', 'access', 'jsonl', 'csv' or '' for bytes that are no web log."""
    text = text_of(data[:200000] if isinstance(data, (bytes, bytearray)) else data)
    if not text or not text.strip():
        return ""
    head = text.lstrip()[:400]
    if head[:1] == "{" and '"log"' in text[:4000] and ('"entries"' in text or '"creator"' in text[:4000]):
        return "har"
    if re.search(r"^#Fields:.*\bcs-uri-stem\b", text, re.M | re.I):
        return "iis_w3c"
    lines = [ln for ln in text.splitlines()[:60] if ln.strip()]
    if lines and sum(1 for ln in lines if _access_match(ln)) >= max(1, 0.6 * len(lines)):
        return "access"
    if head[:1] in "{[":
        probe = parse_jsonl(text if len(text) < 200000 else "\n".join(text.splitlines()[:-1]), name)
        return "jsonl" if probe else ""
    first = lines[0].lower() if lines else ""
    cols = {c.strip().strip('"') for c in re.split(r"[,;\t|]", first)}
    if len(cols) >= 3 and cols & set(_FIELD["target"] + _FIELD["request"]) and cols & set(_FIELD["ip"] + _FIELD["status"] + _FIELD["method"]):
        return "csv"
    return ""


def read_log(data, name="") -> list:
    """The events of one log file, whatever its kind; [] for a file that is no web log."""
    if ((isinstance(data, (bytes, bytearray)) and len(data) > MAX_LOG)
            or (isinstance(data, str)
                and (len(data) > MAX_LOG or len(data.encode("utf-8")) > MAX_LOG))):
        return []
    kind = log_kind(data, name)
    if not kind:
        return []
    text = text_of(data)
    if text is None:
        return []
    return {"har": parse_har, "iis_w3c": parse_iis, "access": parse_access, "jsonl": parse_jsonl, "csv": parse_csv}[kind](text, name)


def tables(events) -> dict:
    return {"ip": Counter(e["ip"] for e in events if e["ip"]), "route": Counter(e["path"] for e in events if e["path"]),
            "status": Counter(e["status"] for e in events if e["status"] is not None),
            "user_agent": Counter(e["ua"] for e in events if e["ua"]), "method": Counter(e["method"] for e in events if e["method"])}


# ---- payload families ----------------------------------------------------------------------------------
#
# Every pattern is run over a decoded value. The order is the precedence of a request that fits
# several (a template payload that calls popen is template injection; a UNION that reads
# /etc/passwd is SQL injection; traversal is what is left).

_SHELL_WORDS = (r"cat|id|whoami|uname|ls|dir|wget|curl|nc|ncat|netcat|bash|sh|zsh|ping|powershell|pwsh|cmd|python3?|perl|php|"
                r"nslookup|ifconfig|ipconfig|net|type|echo|sleep|chmod|rm|touch|base64|certutil|bitsadmin|mshta|tasklist|ps|env|pwd|hostname")
FAMILY_RX = (
    ("jndi", re.compile(r"\$\{\s*jndi\s*:|\$\{[^}]{0,40}\$\{[^}]*\}[^}]{0,40}:|\$\{(?:lower|upper|env|sys|date|::-)[:\w-]*[^}]*\}\s*(?:ndi|[jndi${}:\-\w]*://)", re.I)),
    ("shellshock", re.compile(r"\(\s*\)\s*\{\s*[:\w]*\s*;\s*\}\s*;")),
    ("ssti", re.compile(r"\{\{.{1,400}?\}\}|\{%.{1,400}?%\}|\$\{\s*[\w.\"'(\[]*\s*[*+\-/]\s*[\w.\"']+\s*\}|\$\{[^}]*(?:Runtime|getClass|forName|T\(java)[^}]*\}"
                        r"|<%=?.{1,300}?%>|#\{[^}]*[*+(][^}]*\}|#set\s*\(|\*\{[^}]*[*+(][^}]*\}", re.S)),
    ("xxe", re.compile(r"<!ENTITY\s+[^>]*\b(?:SYSTEM|PUBLIC)\b|<!DOCTYPE[^>]*\[\s*<!ENTITY", re.I)),
    ("deserialization", re.compile(r"\brO0AB[A-Za-z0-9+/]{8,}|\bO:\d+:\"[\w\\]+\":\d+:\{|\bAAEAAAD/////|_\$\$ND_FUNC\$\$_|\bgASV[A-Za-z0-9+/]{6,}|\bKGRw[A-Za-z0-9+/]{6,}")),
    ("sqli", re.compile(r"\bunion\b(?:\s|/\*.*?\*/|\+)+(?:all(?:\s|/\*.*?\*/)+)?select\b|['\"]\s*\)?\s*(?:or|and|\|\||&&)\s*\(?\s*['\"]?\w+['\"]?\s*(?:=|like|<|>)\s*['\"]?\w*"
                        r"|\b(?:or|and)\s+\d+\s*=\s*\d+\b|\b(?:sleep|benchmark|pg_sleep|extractvalue|updatexml|load_file|group_concat)\s*\(|\bwaitfor\s+delay\b"
                        r"|\binformation_schema\b|\bxp_cmdshell\b|;\s*(?:drop|insert|update|delete|create|alter)\s+(?:table|into|from|database|\w+\s+set)\b"
                        r"|['\"]\s*;?\s*(?:--|#|/\*)\s*$|['\"]\s*;\s*select\b|\bselect\s+(?:\*|(?:distinct\s+)?[\w.`@]+\s*[,(]|null\b|\d+\b|@@\w+)[^\n]{0,80}\bfrom\b|\bselect\s+[\w.`]+\s+from\s+[\w.`]+\s*(?:--|#|;|$|\bwhere\s+[\w.`]+\s*(?:=|<|>|\blike\b|\bin\b))|\border\s+by\s+\d+\s*(?:--|#)", re.I | re.S)),
    ("nosqli", re.compile(r"\[\$(?:ne|gt|gte|lt|lte|regex|where|in|nin|exists)\]|\"\$(?:ne|gt|gte|lt|regex|where|in|nin)\"\s*:|\$where\s*:", re.I)),
    ("cmdi", re.compile(r"(?:[;|&`\n]|\|\||&&)\s*(?:/(?:usr/)?s?bin/)?(?:" + _SHELL_WORDS + r")\b(?!\s*=)|\$\(\s*(?:" + _SHELL_WORDS + r")\b[^)]*\)|`\s*(?:" + _SHELL_WORDS + r")\b[^`]*`"
                        r"|\b(?:bash|sh)\s+-[ci]\b|/dev/tcp/\d|\bnc(?:at)?\s+(?:-\w+\s+)*[\w.-]+\s+\d{2,5}\b", re.I)),
    ("xss", re.compile(r"<\s*script\b|<\s*/\s*script\s*>|\bjavascript\s*:|<[^>]{0,200}\bon(?:error|load|click|mouseover|focus|toggle|start|begin)\s*=|<\s*(?:svg|iframe|embed|object)\b[^>]*(?:on\w+|src|data)\s*="
                       r"|\b(?:alert|prompt|confirm)\s*[(`]|\bdocument\s*\.\s*(?:cookie|location|domain)\b|\bString\.fromCharCode\s*\(", re.I)),
    ("ssrf", re.compile(r"^(?:https?|gopher|dict|ftp)://(?:169\.254\.169\.254|metadata\.google\.internal|127\.\d+\.\d+\.\d+|localhost|0\.0\.0\.0|\[::1?\]|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)"
                        r"|^(?:gopher|dict)://|\b169\.254\.169\.254\b|/latest/meta-data\b|/computeMetadata/", re.I)),
    ("traversal", re.compile(r"(?:\.\.[\\/]){2,}|\.\.[\\/][^\s&]{0,80}(?:etc[\\/]|passwd|shadow|win\.ini|boot\.ini|web\.config|\.env\b|id_rsa|\.ssh|proc[\\/]self|wp-config|\.git[\\/])"
                             r"|(?:^|[=\s'\"])/(?:etc/(?:passwd|shadow|hosts)|proc/self/(?:environ|cmdline|maps))\b|[a-z]:[\\/]windows[\\/](?:win\.ini|system32)|\b(?:php|file|zip|phar|data|expect)://[\w/=.-]"
                             r"|(?:\.\.%2f|\.\.%5c|%2e%2e[/\\]|\.\.;/|\.%2e/|%c0%ae){1,}", re.I)),
)
PAYLOAD_FAMILIES = tuple(name for name, _ in FAMILY_RX) + ("webshell",)
BEHAVIOUR_FAMILIES = ("brute_force", "enumeration", "scanner")
_SCRIPT_EXT = r"(?:php\d?|phtml|phar|pht|jsp|jspx|jspf|asp|aspx|ashx|asmx|cfm|cgi|pl|py|sh|war)"
_SHELL_PARAMS = {"cmd", "c", "command", "exec", "execute", "e", "x", "shell", "sh", "run", "system", "code", "pass", "0", "1"}
_SHELL_PATH = re.compile(r"/[^/?]+\." + _SCRIPT_EXT + r"$", re.I)
_UPLOAD_NAME = re.compile(r'filename\*?=\s*"?([^";\r\n]+\.' + _SCRIPT_EXT + r'(?:\.\w{1,5})?)"?', re.I)
_ANY_UPLOAD_NAME = re.compile(r'filename\*?=\s*"?([^";\r\n]+)"?', re.I)
_COMMAND = re.compile(r"^\s*(?:/(?:usr/)?s?bin/)?(?:" + _SHELL_WORDS + r")\b", re.I)
SCANNERS = ("sqlmap", "nikto", "nmap", "gobuster", "dirbuster", "dirb", "ffuf", "wfuzz", "feroxbuster", "nuclei", "hydra",
            "masscan", "zgrab", "wpscan", "acunetix", "nessus", "burp", "owasp zap", "zap", "metasploit", "commix", "havij",
            "arachni", "whatweb", "joomscan", "medusa", "patator", "openvas", "w3af", "skipfish", "netsparker", "invicti",
            "appscan", "qualys")
_HEADER_FAMILIES = {"jndi", "shellshock", "sqli", "xss", "ssti"}


@lru_cache(maxsize=65536)
def _families(value) -> tuple:
    return tuple(name for name, rx in FAMILY_RX if rx.search(value))


def families_of(value) -> list:
    """Every payload family a decoded value fits, in the order of precedence."""
    if not value or len(value) < 3:
        return []
    return list(_families(value[:MAX_VALUE]))


@lru_cache(maxsize=65536)
def _header_value(value) -> str:
    return deep_unquote(value)[0]


def _surfaces(ev) -> list:
    """[(where, name, raw, decoded, decoded without '+' as space)] of everything a client controls."""
    out = []
    if ev["path_raw"]:
        out.append(("path", None, ev["path_raw"], ev["path"], ev["path"]))
    for p in ev["params"]:
        out.append((p["where"], p["name"], p["raw"], p["value"], p["value_noplus"]))
    body = ev.get("body")
    if body:
        ctype = (ev["headers"].get("content-type") or "").lower()
        looks_form = "urlencoded" in ctype or (not ctype and re.fullmatch(r"[^\s=&{}<>]+=[^\s&]*(?:&[^\s=&]+=[^\s&]*)*", body.strip() or " "))
        if looks_form:
            for p in _params(body.strip(), "body"):
                out.append((p["where"], p["name"], p["raw"], p["value"], p["value_noplus"]))
        else:
            fields = None
            if body.lstrip()[:1] == "{":
                try:
                    doc = _strict_json(body, max_chars=MAX_LOG, max_members=262_144,
                                       max_nodes=524_288, max_depth=64)
                    fields = [(k, v if isinstance(v, str) else json.dumps(v, separators=(",", ":"))) for k, v in _flat(doc).items()] if isinstance(doc, dict) else None
                except (ValueError, RecursionError):
                    fields = None
            if fields:
                out += [("body", k, v, v, v) for k, v in fields]
            else:
                out.append(("body", None, body, body, body))
    if ev["ua"]:
        out.append(("header", "user-agent", ev["ua"], _header_value(ev["ua"]), _header_value(ev["ua"])))
    if ev["referer"]:
        out.append(("header", "referer", ev["referer"], _header_value(ev["referer"]), _header_value(ev["referer"])))
    for name, value in ev["headers"].items():
        if name not in ("user-agent", "referer", "cookie", "accept", "accept-language", "accept-encoding", "content-type",
                        "content-length", "connection", "host", "authorization", "set-cookie") and isinstance(value, str):
            out.append(("header", name, value, _header_value(value), _header_value(value)))
    return out


_SCANNER_RX = re.compile(r"(?<![a-z])(" + "|".join(re.escape(t) for t in SCANNERS) + r")(?![a-z])")


@lru_cache(maxsize=65536)
def scanner_of(ua):
    """The scanner a user agent names (the first of SCANNERS in it), or None."""
    m = _SCANNER_RX.search((ua or "").lower())
    return m.group(1) if m else None


def findings(events) -> list:
    """[finding] over the events, in the order of the events. A finding of a payload family is one
    surface of one request: {family, families, event, where, param, raw, payload, payload_noplus}.
    Web shell findings carry `role`: 'upload' (a script file sent to the server, with `filename`) or
    'use' (a script requested with a command parameter). Behaviour findings (brute_force,
    enumeration, scanner) are one per client address, on its first such request."""
    out = []
    for i, ev in enumerate(events):
        hit = False
        for where, name, raw, value, noplus in _surfaces(ev):
            fams = families_of(value) or families_of(noplus)
            if where == "header":
                fams = [f for f in fams if f in _HEADER_FAMILIES and not (name == "referer" and f not in ("jndi", "xss"))]
            if where == "path":
                fams = [f for f in fams if f != "ssrf"]
            if not fams:
                continue
            hit = True
            out.append({"family": fams[0], "families": fams, "event": i, "where": where, "param": name, "raw": raw,
                        "payload": value, "payload_noplus": noplus})
        # a web shell in use: a script requested with a command in a command parameter
        if ev["path"] and _SHELL_PATH.search(ev["path"]):
            for where, name, raw, value, noplus in _surfaces(ev):
                if where in ("query", "body") and name is not None and name.lower() in _SHELL_PARAMS and _COMMAND.match(value or ""):
                    out.append({"family": "webshell", "families": ["webshell"], "event": i, "where": where, "param": name, "raw": raw,
                                "payload": value, "payload_noplus": noplus, "role": "use", "filename": ev["path"].rsplit("/", 1)[-1]})
                    hit = True
        # a web shell upload: a multipart part (or a PUT) whose file name is a server-side script
        body = ev.get("body") or ""
        m = _UPLOAD_NAME.search(body) if body else None
        if m:
            out.append({"family": "webshell", "families": ["webshell"], "event": i, "where": "body", "param": None, "raw": m.group(0),
                        "payload": m.group(1), "payload_noplus": m.group(1), "role": "upload", "filename": m.group(1).replace("\\", "/").rsplit("/", 1)[-1]})
            hit = True
        elif ev["method"] == "PUT" and ev["path"] and _SHELL_PATH.search(ev["path"]):
            out.append({"family": "webshell", "families": ["webshell"], "event": i, "where": "path", "param": None, "raw": ev["path_raw"],
                        "payload": ev["path"], "payload_noplus": ev["path"], "role": "upload", "filename": ev["path"].rsplit("/", 1)[-1]})
            hit = True
        ev["_hit"] = hit
    # An upload a body-less log shows only by its order: a POST by the address that then uses the shell,
    # before the shell's first request, to another path.
    uses = [f for f in out if f.get("role") == "use"]
    if uses and not any(f.get("role") == "upload" for f in out):
        first = uses[0]
        ip = events[first["event"]]["ip"]
        prior = [j for j in range(first["event"]) if events[j]["ip"] == ip and events[j]["method"] in ("POST", "PUT")
                 and events[j]["path"] != events[first["event"]]["path"]]
        if len({events[j]["path"] for j in prior}) == 1 and ip is not None:
            j = prior[0]
            out.append({"family": "webshell", "families": ["webshell"], "event": j, "where": "order", "param": None, "raw": events[j]["path_raw"],
                        "payload": first["filename"], "payload_noplus": first["filename"], "role": "upload", "filename": first["filename"],
                        "inferred": True})
    # behaviour, per client address
    fails, misses, tools = {}, {}, {}
    for i, ev in enumerate(events):
        ip = ev["ip"]
        if ip is None:
            continue
        if ev["method"] == "POST" and ev["status"] in (401, 403) :
            fails.setdefault((ip, ev["path"]), []).append(i)
        if ev["status"] == 404:
            misses.setdefault(ip, []).append(i)
        tool = scanner_of(ev["ua"])
        if tool:
            tools.setdefault((ip, tool), []).append(i)
    for (ip, path), idx in fails.items():
        if len(idx) >= 8:
            out.append({"family": "brute_force", "families": ["brute_force"], "event": idx[0], "where": "behaviour", "param": None,
                        "raw": None, "payload": None, "payload_noplus": None, "count": len(idx), "last": idx[-1]})
    for ip, idx in misses.items():
        if len({events[j]["path"] for j in idx}) >= 20:
            out.append({"family": "enumeration", "families": ["enumeration"], "event": idx[0], "where": "behaviour", "param": None,
                        "raw": None, "payload": None, "payload_noplus": None, "count": len(idx), "last": idx[-1]})
    for (ip, tool), idx in tools.items():
        out.append({"family": "scanner", "families": ["scanner"], "event": idx[0], "where": "header", "param": "user-agent",
                    "raw": events[idx[0]]["ua"], "payload": None, "payload_noplus": None, "tool": tool, "count": len(idx), "last": idx[-1]})
    out.sort(key=lambda f: (f["event"], f["family"] in BEHAVIOUR_FAMILIES))
    return out


# ---- tokens and cookies ----------------------------------------------------------------------------------

_JWT = re.compile(r"(?<![A-Za-z0-9_\-.])(eyJ[A-Za-z0-9_-]{4,})\.(eyJ[A-Za-z0-9_-]{2,})\.([A-Za-z0-9_-]*)(?![A-Za-z0-9_-])")
_FLASK = re.compile(r"(?<![A-Za-z0-9_\-])(\.?eJ[A-Za-z0-9_-]{6,}|eyJ[A-Za-z0-9_-]{4,})\.([A-Za-z0-9_-]{4,8})\.([A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])")
_COOKIE_PAIR = re.compile(r"(?:^|[;\s,])([A-Za-z0-9_.\-]{1,64})=([A-Za-z0-9_\-+/=%.]{12,})")


def decode_jwt(token):
    """{token, header, claims, alg, kid, signature, signed} of a JWT, or None. Nothing is verified."""
    m = _JWT.fullmatch(str(token).strip())
    if not m:
        return None
    try:
        header = _strict_json(_b64url(m.group(1), MAX_TOKEN_JSON) or b"", max_chars=MAX_TOKEN_JSON,
                              max_members=4096, max_nodes=8192, max_depth=32)
        claims = _strict_json(_b64url(m.group(2), MAX_TOKEN_JSON) or b"", max_chars=MAX_TOKEN_JSON,
                              max_members=16_384, max_nodes=32_768, max_depth=32)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    if not isinstance(header, dict) or not isinstance(claims, dict) or not ({"alg", "typ"} & set(header)):
        return None
    return {"kind": "jwt", "token": m.group(0), "header": header, "claims": claims, "alg": header.get("alg"),
            "kid": header.get("kid"), "signature": m.group(3), "signed": bool(m.group(3))}


def _jwt_candidates(text) -> list:
    """Every distinct JWT-shaped wire string, including ones strict JSON refuses."""
    out, seen = [], set()
    for t in (text, deep_unquote(text)[0] if "%" in text else ""):
        for m in _JWT.finditer(t or ""):
            if m.group(0) not in seen:
                seen.add(m.group(0))
                out.append(m.group(0))
    return out


def find_tokens(text) -> list:
    """Every distinct unambiguous JWT in text; rejected candidates are not facts."""
    return [decoded for token in _jwt_candidates(text)
            for decoded in [decode_jwt(token)] if decoded is not None]


def _bounded_token_zlib(raw):
    """Inflate one signed-cookie payload without allowing a decompression bomb."""
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_TOKEN_JSON:
        return None
    try:
        dec = zlib.decompressobj()
        out = dec.decompress(bytes(raw), MAX_TOKEN_JSON + 1)
        if len(out) > MAX_TOKEN_JSON or dec.unconsumed_tail:
            return None
        out += dec.flush(MAX_TOKEN_JSON + 1 - len(out))
        if len(out) > MAX_TOKEN_JSON or not dec.eof or dec.unused_data:
            return None
        return out
    except (ValueError, zlib.error):
        return None


def decode_cookie(value):
    """A cookie value read without its key: {kind: 'flask_session', data, compressed, timestamp} for
    itsdangerous' payload.timestamp.signature (a leading '.' means zlib), or {kind: 'base64_json',
    data} for base64 of a JSON object. None for anything else."""
    value = deep_unquote(str(value).strip().strip('"'))[0]
    m = _FLASK.fullmatch(value)
    if m and not _JWT.fullmatch(value):
        payload, compressed = m.group(1), m.group(1).startswith(".")
        raw = _b64url(payload.lstrip("."), MAX_TOKEN_JSON)
        try:
            if compressed and raw is not None:
                raw = _bounded_token_zlib(raw)
            data = _strict_json(raw or b"", max_chars=MAX_TOKEN_JSON,
                                max_members=16_384, max_nodes=32_768, max_depth=32)
        except (ValueError, zlib.error, UnicodeDecodeError, RecursionError):
            data = None
        if isinstance(data, dict):
            stamp = _b64url(m.group(2), 16)
            when = int.from_bytes(stamp, "big") if stamp and len(stamp) <= 8 else None
            return {"kind": "flask_session", "token": value, "data": data, "compressed": compressed, "timestamp": when}
    if re.fullmatch(r"[A-Za-z0-9_\-+/]{12,}={0,2}", value):
        raw = _b64url(value, MAX_TOKEN_JSON)
        try:
            data = _strict_json(raw or b"", max_chars=MAX_TOKEN_JSON,
                                max_members=16_384, max_nodes=32_768, max_depth=32)
        except (ValueError, UnicodeDecodeError, RecursionError):
            data = None
        if isinstance(data, dict):
            return {"kind": "base64_json", "token": value, "data": data}
    return None


def find_cookies(text) -> list:
    """Session cookies in a text: Flask-style signed values anywhere, base64 JSON values of name=value pairs."""
    out, seen = [], set()
    for t in (text, deep_unquote(text)[0] if "%" in text else ""):
        for m in _FLASK.finditer(t or ""):
            if m.group(0) in seen or _JWT.fullmatch(m.group(0)):
                continue
            d = decode_cookie(m.group(0))
            if d:
                seen.add(m.group(0))
                out.append(d)
        for m in _COOKIE_PAIR.finditer(t or ""):
            if m.group(2) in seen or m.group(2).startswith("eyJ") and "." in m.group(2):
                continue
            d = decode_cookie(m.group(2))
            if d and d["kind"] == "base64_json":
                seen.add(m.group(2))
                out.append({**d, "name": m.group(1)})
    return out


def _has_rejected_cookie_json(text) -> bool:
    """Whether an explicit cookie envelope contains JSON that strict parsing refused."""
    for candidate in (text, deep_unquote(text)[0] if "%" in text else ""):
        for match in _FLASK.finditer(candidate or ""):
            value = match.group(0)
            if not _JWT.fullmatch(value) and decode_cookie(value) is None:
                return True
        for match in _COOKIE_PAIR.finditer(candidate or ""):
            value = match.group(2)
            if value.startswith("eyJ") and "." in value:
                continue
            raw = _b64url(value, MAX_TOKEN_JSON)
            if raw is not None and raw.lstrip()[:1] in (b"{", b"[") \
                    and decode_cookie(value) is None:
                return True
    return False


# ---- source review ---------------------------------------------------------------------------------------

_LANG = {".py": "python", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".php": "php", ".phtml": "php", ".inc": "php",
         ".cs": "cs", ".cshtml": "cs", ".aspx": "cs", ".ashx": "cs", ".asp": "cs", ".java": "java", ".jsp": "java",
         ".rb": "ruby", ".go": "go"}
_TEMPLATE_EXT = (".html", ".htm", ".jinja", ".jinja2", ".j2", ".ejs", ".hbs", ".twig", ".tpl", ".cshtml", ".aspx", ".php", ".jsp", ".pug")
_CONFIG_EXT = (".env", ".ini", ".cfg", ".conf", ".yml", ".yaml", ".toml", ".json", ".config", ".properties", ".xml", ".txt")

# (sink id, family, language, pattern). The id is the call as a reader would name it.
SINKS = (
    ("yaml.load", "deserialization", "python", r"\byaml\.(?:load|load_all)\s*\((?![^)\n]*(?:SafeLoader|safe_load|BaseLoader))|\byaml\.(?:unsafe_load|full_load)\s*\("),
    ("pickle.loads", "deserialization", "python", r"\b(?:c?[pP]ickle|dill|cloudpickle|joblib)\.loads?\s*\(|\bmarshal\.loads\s*\(|\bjsonpickle\.decode\s*\(|\bshelve\.open\s*\("),
    ("eval", "code_injection", "python", r"(?<![\w.])eval\s*\("),
    ("exec", "code_injection", "python", r"(?<![\w.])exec\s*\("),
    ("render_template_string", "ssti", "python", r"\brender_template_string\s*\(|\b(?:jinja2\.)?Template\s*\([^)\n]*\)\s*\.render\s*\(|\bEnvironment\s*\([^)\n]*\)\s*\.from_string\s*\(|\.from_string\s*\("),
    ("subprocess", "cmdi", "python", r"\bsubprocess\.\w+\s*\([^\n]*shell\s*=\s*True|\bos\.(?:system|popen)\s*\(|\bcommands\.getoutput\s*\("),
    ("extractall", "zip_slip", "python", r"\.extractall\s*\(|\.extract\s*\(\s*(?:member|name|info|f|entry)\b"),
    ("re.multiline", "regex_multiline", "python", r"\bre\.(?:match|search|fullmatch|compile|findall)\s*\([^\n]*\bre\.(?:MULTILINE|M)\b|\(\?m\)"),
    ("sql.execute", "sqli", "python", r"\.execute(?:many|script)?\s*\(\s*(?:f\"[^\"\n]*\{|f'[^'\n]*\{|f[\"'][^\n]*[\"']\s*\+|[\"'][^\"'\n]*[\"']\s*(?:%|\+|\.format\s*\()|[\w.]+\s*\+)"
                                     r"|\.raw\s*\(\s*(?:f\"[^\"\n]*\{|f'[^'\n]*\{)"),
    ("open", "traversal", "python", r"\b(?:open|send_file|send_from_directory)\s*\([^\n]*\brequest\.|\bos\.path\.join\s*\([^\n]*\brequest\."),
    ("requests.get", "ssrf", "python", r"\b(?:requests\.(?:get|post|request)|urllib\.request\.urlopen|urlopen|httpx\.get)\s*\([^\n]*\b(?:request\.|url\b)"),
    ("eval", "code_injection", "js", r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.runIn\w+\s*\("),
    ("child_process.exec", "cmdi", "js", r"\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:`|[\"'][^\"'\n]*[\"']\s*\+|\w+\s*[+,)])|\bspawn(?:Sync)?\s*\([^\n]*shell\s*:\s*true"),
    ("unserialize", "deserialization", "js", r"\b(?:serialize\.)?unserialize\s*\(|\bnode-serialize\b|\byaml\.load\s*\("),
    ("res.render", "ssti", "js", r"\b(?:ejs|pug|nunjucks|handlebars|Handlebars|mustache|lodash|_)\.(?:render|renderString|compile|template)\s*\([^\n]*\breq\."),
    ("template.render", "ssti", "js", r"\b(?:ejs|pug|nunjucks|mustache|Mustache|swig|dot|doT)\.(?:render|renderString|compile|template)\s*\(\s*(?![\"'`])[A-Za-z_$][\w$.]*\s*[,)]"
                                      r"|\b[Hh]andlebars\.compile\s*\(\s*(?![\"'`])[A-Za-z_$][\w$.]*\s*[,)]"),
    ("sql.query", "sqli", "js", r"\.query\s*\(\s*(?:`[^`\n]*\$\{|[\"'][^\"'\n]*[\"']\s*\+)"),
    ("fs.readFile", "traversal", "js", r"\b(?:fs\.(?:readFile|readFileSync|createReadStream)|res\.sendFile|path\.join)\s*\([^\n]*\breq\."),
    ("regex.multiline", "regex_multiline", "js", r"/\^[^/\n]*\$/[gimsuy]*m[gimsuy]*"),
    ("eval", "code_injection", "php", r"(?<![\w>$])(?:eval|assert|create_function)\s*\(|\bpreg_replace\s*\(\s*[\"'][^\"'\n]*/[a-z]*e[a-z]*[\"']"),
    ("system", "cmdi", "php", r"(?<![\w>$])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`\n]*\$[^`\n]*`"),
    ("unserialize", "deserialization", "php", r"(?<![\w>$])unserialize\s*\("),
    ("include", "traversal", "php", r"\b(?:include|require)(?:_once)?\s*\(?[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)|\b(?:file_get_contents|readfile|fopen)\s*\([^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)"),
    ("move_uploaded_file", "upload", "php", r"\bmove_uploaded_file\s*\("),
    ("sql.query", "sqli", "php", r"\b(?:mysqli?_query|pg_query)\s*\([^;\n]*\$|->(?:query|exec)\s*\(\s*[\"'][^;\n]*\$|\"\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)"),
    ("extract", "code_injection", "php", r"(?<![\w>$])extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)"),
    ("Process.Start", "cmdi", "cs", r"\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\s*\("),
    ("BinaryFormatter", "deserialization", "cs", r"\b(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer|SoapFormatter)\b|TypeNameHandling\.(?:All|Auto|Objects|Arrays)"),
    ("SqlCommand", "sqli", "cs", r"\bnew\s+SqlCommand\s*\(\s*(?:\$\"|[\"'][^\"\n]*[\"']\s*\+|\w+\s*\+)|\bFromSqlRaw\s*\(\s*\$\""),
    ("Html.Raw", "xss", "cs", r"\bHtml\.Raw\s*\("),
    ("ZipFile.ExtractToDirectory", "zip_slip", "cs", r"\bExtractToDirectory\s*\(|\bExtractToFile\s*\("),
    ("RegexOptions.Multiline", "regex_multiline", "cs", r"\bRegexOptions\.Multiline\b"),
    ("XmlResolver", "xxe", "cs", r"\bDtdProcessing\.Parse\b|\bXmlUrlResolver\b"),
    ("Runtime.exec", "cmdi", "java", r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|\bnew\s+ProcessBuilder\s*\("),
    ("readObject", "deserialization", "java", r"\bObjectInputStream\b|\.readObject\s*\("),
    # XXE (python lxml), more XSS, open redirect (request-derived only), Flask debug.
    ("lxml.etree", "xxe", "python", r"\blxml\.etree\.(?:parse|fromstring|XML)\s*\(|\betree\.(?:parse|fromstring)\s*\([^\n]*\bresolve_entities\s*=\s*True"
                                    r"|\bXMLParser\s*\([^\n]*\b(?:resolve_entities|no_network\s*=\s*False|load_dtd|dtd_validation)\s*=\s*True|\bparseString\s*\([^\n]*\bParseError"),
    ("Markup", "xss", "python", r"\b(?:flask\.)?Markup\s*\([^\n]*\brequest\.|\bmark_safe\s*\([^\n]*\brequest\.|\bHttpResponse\s*\([^\n]*\brequest\.(?:GET|POST)\b"),
    ("innerHTML", "xss", "js", r"\.innerHTML\s*=\s*(?![\"'`]\s*[\"'`])|\binsertAdjacentHTML\s*\(|\bdocument\.write(?:ln)?\s*\(|\bdangerouslySetInnerHTML\b|\.outerHTML\s*=\s*\w"),
    ("echo", "xss", "php", r"\b(?:echo|print)\b[^;\n]*\$_(?:GET|POST|REQUEST|COOKIE)\b"),
    ("redirect", "open_redirect", "python", r"\bredirect\s*\([^)\n]*\brequest\.(?:args|form|values|headers|get_json)\b|\bredirect\s*\(\s*request\.|\bHttpResponseRedirect\s*\([^)\n]*\brequest\."),
    ("res.redirect", "open_redirect", "js", r"\bres\.redirect\s*\([^)\n]*\breq\.(?:query|body|params|headers)\b|\bwindow\.location\s*=\s*[^;\n]*\b(?:req|location\.(?:search|hash))\b"),
    ("header.location", "open_redirect", "php", r"\bheader\s*\(\s*[\"']Location:\s*[\"']?\s*\.\s*\$_(?:GET|POST|REQUEST)|\bheader\s*\(\s*[\"']Location:[^\"'\n]*\$_(?:GET|POST|REQUEST)"),
    ("app.run.debug", "flask_debug", "python", r"\bapp\.run\s*\([^)\n]*\bdebug\s*=\s*True|\bapp\.debug\s*=\s*True\b|\brun\s*\([^)\n]*\bdebug\s*=\s*True[^)\n]*\)|\bDEBUG\s*=\s*True\b"),
)
_SINKS = tuple((sid, fam, lang, re.compile(rx)) for sid, fam, lang, rx in SINKS)

_SECRET_RX = (
    ("secret_key", re.compile(r"(?i)\b(?:app\.)?(?:config\s*\[\s*[\"'])?(SECRET_KEY|secret_key|JWT_SECRET(?:_KEY)?|jwt_secret|SESSION_SECRET|session_secret|signing_key|SIGNING_KEY|secret)[\"'\]\s]*\s*[:=]\s*[bru]?[\"']([^\"'\n]{3,200})[\"']")),
    ("password", re.compile(r"(?i)\b(\w*(?:passwd|password|pwd|pass)\w*)[\"'\]\s]*\s*[:=]\s*[\"']([^\"'\n]{3,200})[\"']")),
    ("api_key", re.compile(r"(?i)\b(\w*(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\w*)[\"'\]\s]*\s*[:=]\s*[\"']([^\"'\n]{6,300})[\"']")),
    ("env", re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*([\"']?)([^\"'\s]{3,300})\2[ \t]*(?:[ \t]#.*)?$")),
    ("fallback", re.compile(r"(?i)(?:process\.env\.(\w+)\s*\|\|\s*|os\.environ\.get\s*\(\s*[\"'](\w+)[\"']\s*,\s*|os\.getenv\s*\(\s*[\"'](\w+)[\"']\s*,\s*|getenv\s*\(\s*[\"'](\w+)[\"']\s*\)\s*\?:\s*)[\"']([^\"'\n]{3,200})[\"']")),
    ("jwt_sign", re.compile(r"(?i)\bjwt\.(?:encode|decode|sign|verify)\s*\([^,\n]+,\s*[\"']([^\"'\n]{3,200})[\"']")),
    ("aws_key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("basic_auth_url", re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:@\"']{1,64}):([^/\s:@\"']{1,64})@[\w.-]+")),
)
_QUOTED_SECRETS = ("secret_key", "password", "api_key", "fallback", "jwt_sign")
_NOT_SECRET = re.compile(r"(?i)^(?:changeme|change[-_ ]me|your[-_ ].*|xxx+|\*+|<.*>|\{\{.*\}\}|\$\{.*\}|\{[\w.\[\]'\" ]*\}|%\(.*\)s|%s|none|null|true|false|example|todo|password|secret)$")

_PY_ROUTE = re.compile(r"^\s*@\s*([\w.]+)\.(route|get|post|put|delete|patch|api_route|websocket)\s*\(\s*[bru]?[\"']([^\"']*)[\"']([^\n]*)")
_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(")
_JS_ROUTE = re.compile(r"\b(\w+)\.(get|post|put|delete|patch|all|use)\s*\(\s*[\"'`](/[^\"'`]*)[\"'`]")
_CS_ATTR = re.compile(r"\[\s*(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\s*(?:\(\s*\"([^\"]*)\")?")
_CS_MAP = re.compile(r"\.Map(Get|Post|Put|Delete|Patch)\s*\(\s*\"([^\"]*)\"")
_CS_METHOD = re.compile(r"^\s*(?:public|private|protected|internal)\s+(?:async\s+)?(?:static\s+)?[\w<>\[\],. ?]+\s+(\w+)\s*\(")
_JS_DESTRUCTURE = re.compile(r"\b(?:const|let|var)\s*\{([^}\n]{1,200})\}\s*=\s*req\.(?:query|body|params|cookies)\b")
_PARAM_RX = {
    "python": re.compile(r"\brequest\.(?:args|form|values|json|cookies|headers|files)\s*(?:\.get(?:list)?\s*\(\s*|\[\s*)[\"']([^\"']+)[\"']|\brequest\.get_json\s*\(\s*\)\s*(?:\.get\s*\(\s*|\[\s*)[\"']([^\"']+)[\"']"),
    "js": re.compile(r"\breq\.(?:query|body|params|cookies|headers)\s*(?:\.\s*(\w+)|\[\s*[\"']([^\"']+)[\"']\s*\])"),
    "php": re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*[\"']([^\"']+)[\"']\s*\]"),
    "cs": re.compile(r"\bRequest\.(?:Query|Form|Cookies|Headers|QueryString|Params)\s*\[\s*\"([^\"]+)\"\s*\]|\bRequest\s*\[\s*\"([^\"]+)\"\s*\]"),
    "java": re.compile(r"\.getParameter\s*\(\s*\"([^\"]+)\"\s*\)"),
}
_FORM = re.compile(r"<form\b([^>]*)>(.*?)</form\s*>", re.I | re.S)
_INPUT = re.compile(r"<(?:input|select|textarea|button)\b([^>]{0,2000})>", re.I)
_ATTR = re.compile(r"([\w:-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+))")
_SCRIPT = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.I | re.S)
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)


def _blocks(text, low, opener, head_end, closer):
    """(head, inner) of every opener...closer block of a text, in one forward pass: `head` is what
    stands between the opener and `head_end` (a tag's attributes; '' for a comment), `inner` what
    stands between that and the closer. `low` is the text in lower case."""
    pos = 0
    while True:
        i = low.find(opener, pos)
        if i < 0:
            return
        j = i + len(opener)
        if head_end:
            if low[j:j + 1].isalnum() or low[j:j + 1] in ("-", "_"):      # <formula>, <scripts>
                pos = j
                continue
            k = low.find(head_end, j)
            if k < 0:
                return
            head, start = text[j:k][:4000], k + len(head_end)
        else:
            head, start = "", j
        end = low.find(closer, start)
        if end < 0:
            return
        yield head, text[start:end]
        pos = end + len(closer)


def _attrs(text) -> dict:
    return {m.group(1).lower(): next(g for g in m.groups()[1:] if g is not None) for m in _ATTR.finditer(text or "")}


def _comment_line(line, lang) -> bool:
    s = line.lstrip()
    return s.startswith("#") if lang in ("python", "ruby") else s.startswith(("//", "*", "/*")) or (lang == "php" and s.startswith("#"))


_TRAPS = None


def _traps():
    """solvers/toolkits/web_traps.py (B-104), loaded by path once. Missing: a loud error, never a review
    that silently drops the honeypot and regex-gate reads."""
    global _TRAPS
    if _TRAPS is None and "ctf_b104_web_traps" in sys.modules:
        _TRAPS = sys.modules["ctf_b104_web_traps"]
    if _TRAPS is None:
        import importlib.util
        path = HERE / "web_traps.py"
        if not path.is_file():
            raise RuntimeError(f"web_evidence: the honeypot / regex-gate reader is missing: {path}")
        spec = importlib.util.spec_from_file_location("ctf_b104_web_traps", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules["ctf_b104_web_traps"] = module
        spec.loader.exec_module(module)
        _TRAPS = module
    return _TRAPS


def read_source(files) -> dict:
    """The review of a shipped application: {routes, sinks, taint, secrets, forms, scripts, comments,
    regex_gates, traps}.

    routes   [{file, line, method, path, handler}]   Flask/FastAPI decorators, Express calls, ASP.NET
             attributes and Map* calls, and every .php/.aspx/.jsp page as its own path
    sinks    [{file, line, sink, family, code, handler, routes, params}]  the dangerous calls of SINKS,
             each with the handler it sits in, that handler's routes and the request values it reads
    taint    proved, handler-local source-to-sink flows.  Every row includes ``reads`` and a bounded
             ``provenance`` chain; ambiguous aliases, branches and unknown wrappers produce no row.
    secrets  [{file, line, kind, name, value}]       hardcoded keys, passwords and fallbacks
    forms    [{file, action, method, inputs: [{name, type, value}]}]; scripts [{file, src, inline}];
    comments [{file, text}] (HTML comments)
    regex_gates  web_traps.regex_gates rows (B-104): validation regexes that leave the input open (no end
             anchor on re.match, no start anchor on a search, MULTILINE / Ruby line anchors, ^a|b$, a
             trailing-newline $), with the literal marker the code then looks for and a candidate input
             checked offline against the pattern -- never sent
    traps    [{file, surface, verdict, signals, rules, findings}] of every source, template, config and
             text file web_traps.honeypot_scan does not call clean: anti-AI honeypot (exfiltration to a
             third-party collector, an ask for the solver's own prompt, an ask to read the CTF platform)
             or prompt-injection text. Detect and flag only: a `trap` is not solved, it is refused.
    trap_cuts [str]  every file the two B-104 readers saw only in part or not at all (over MAX_SOURCE
             bytes, or over web_traps.MAX_TEXT characters), by name: a clean read of a cut file is not
             a clean file"""
    routes, sinks, secrets, forms, scripts, comments, taint = [], [], [], [], [], [], []
    gates, traps, trap_cuts = [], [], []
    T = _traps()
    static_budget = [0]
    seen_secrets = set()
    for name, data in _unique(files):
        short = name.split(ARROW)[-1]
        ext = Path(short).suffix.lower()
        base = Path(short).name.lower()
        lang = _LANG.get(ext)
        is_config = ext in _CONFIG_EXT or base.startswith(".env") or base in ("dockerfile", "docker-compose.yml")
        if lang is None and ext not in _TEMPLATE_EXT and not is_config:
            continue
        if len(data) > MAX_SOURCE:
            trap_cuts.append(f"{short}: {len(data)} bytes, over {MAX_SOURCE}: not read for honeypot text or regex gates")
            continue
        text = text_of(data)
        if text is None:
            continue
        lines = text.splitlines()
        if lang:
            _review(short, lang, lines, routes, sinks)
            _static_review(short, lang, text, lines, routes, sinks, taint, static_budget)
            gates.extend(T.regex_gates(short, text, trap_cuts))
        hp = T.honeypot_scan(text, source=short, surface="code" if lang else "text")
        if hp["truncated"]:
            trap_cuts.append(f"{short}: {len(text)} characters, only the first {T.MAX_TEXT} scanned for honeypot text")
        if hp["verdict"] != T.CLEAN:
            traps.append({"file": short, "surface": hp["surface"], "verdict": hp["verdict"], "signals": hp["signals"],
                          "rules": hp["rules"], "findings": hp["findings"][:8], "truncated": hp["truncated"]})
        if lang in ("php", "java") and ext in (".php", ".jsp") or ext in (".aspx", ".ashx", ".asp"):
            routes.append({"file": short, "line": 1, "method": None, "path": "/" + Path(short).name, "handler": Path(short).name})
        if lang or is_config:
            for n, line in enumerate(lines, 1):
                if len(line) > 2000:
                    continue
                for kind, rx in _SECRET_RX:
                    for m in rx.finditer(line):
                        groups = [g for g in m.groups() if g is not None and (kind != "env" or g not in ("", '"', "'"))]
                        value = groups[-1] if groups else m.group(0)
                        label = groups[0] if len(groups) > 1 else kind
                        if kind in _QUOTED_SECRETS and m.lastindex:
                            # the literal must close with the quote that opened it, and not on an escaped one
                            a, b = m.start(m.lastindex), m.end(m.lastindex)
                            if a < 1 or b >= len(line) or line[a - 1] != line[b] or value.endswith("\\"):
                                continue
                        if kind == "password" and not re.search(r"(?i)pass|pwd", label):
                            continue
                        if _NOT_SECRET.match(value) or (short, n, value) in seen_secrets:
                            continue
                        seen_secrets.add((short, n, value))
                        secrets.append({"file": short, "line": n, "kind": kind, "name": label, "value": value})
        if ext in _TEMPLATE_EXT or "<form" in text[:200000].lower() or "<script" in text[:200000].lower():
            low = text.lower()
            for head, inner in _blocks(text, low, "<form", ">", "</form"):
                a = _attrs(head)
                inputs = [{"name": i.get("name"), "type": i.get("type"), "value": i.get("value")}
                          for i in (_attrs(x.group(1)) for x in _INPUT.finditer(inner[:200000])) if i.get("name")]
                forms.append({"file": short, "action": a.get("action"), "method": (a.get("method") or "get").upper(), "enctype": a.get("enctype"), "inputs": inputs})
            for head, inner in _blocks(text, low, "<script", ">", "</script"):
                a = _attrs(head)
                scripts.append({"file": short, "src": a.get("src"), "inline": inner.strip()[:4000]})
            for _, inner in _blocks(text, low, "<!--", "", "-->"):
                if inner.strip():
                    comments.append({"file": short, "text": html_unescape(inner.strip())[:2000]})
    _link_framework_routes(routes, sinks, taint)
    return {"routes": routes, "sinks": sinks, "taint": taint, "taint_cut": static_budget[0] < 0,
            "secrets": secrets, "forms": forms, "scripts": scripts, "comments": comments,
            "regex_gates": gates, "traps": traps, "trap_cuts": trap_cuts}


# W-B: a deserialization sink found by a TYPE name (`new BinaryFormatter()`,
# `new ObjectInputStream(in)`, `TypeNameHandling.All`) is not the line that deserializes; the call is.
_DESER_TYPE_SINKS = {"BinaryFormatter": "cs", "readObject": "java"}
_DESER_CALL = {
    "cs": re.compile(r"\.\s*(?:Deserialize(?:Object)?|ReadObject|UnsafeDeserialize\w*)\s*(?:<[^>\n]{0,120}>)?\s*\("),
    "java": re.compile(r"\.\s*(?:readObject|readUnshared)\s*\("),
}
# the variable a type line assigns: `var fmt = new BinaryFormatter(`, `ObjectInputStream ois = new ObjectInputStream(`
_DESER_BIND = re.compile(r"\b([A-Za-z_]\w*)\s*=\s*new\s+(?:BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer"
                         r"|SoapFormatter|ObjectInputStream)\s*\(")
_STRING_LIT = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')
_INLINE_COMMENT = re.compile(r"/\*.*?\*/")


def _code_of(line) -> str:
    """A C#/Java line without its string literals (blanked) and its comments."""
    code = _INLINE_COMMENT.sub(" ", _STRING_LIT.sub('""', line))
    return code.split("//", 1)[0]


def _deser_calls(lang, lines, handlers, sinks):
    """Give every type-name deserialization sink of one file its `call_line` (review of eb6699e, B3): its own
    line when the call stands on it; else the one call of its handler (from the handler's first line to the
    next handler's) made ON the variable the type line assigns; else None (no such call, two, a type line
    that assigns no variable, a call only in a string, a comment or on another object). One pass over the
    file. No sink is dropped (B2: a Java `new ObjectInputStream` and its `readObject()` stay two sinks)."""
    call_rx = _DESER_CALL.get(lang)
    # this file's sinks are the ones whose handler is not yet resolved (`_h`, popped when _review ends)
    mine = [s for s in sinks if "_h" in s and _DESER_TYPE_SINKS.get(s["sink"]) == lang] if call_rx else []
    if not mine:
        return
    recv_rx = re.compile(r"\b([A-Za-z_]\w*)\s*" + call_rx.pattern)
    by_recv, in_block = {}, False           # receiver -> [line of a call on it], in line order
    for n, line in enumerate(lines, 1):
        if in_block:
            if "*/" in line:
                in_block, line = False, line.split("*/", 1)[1]
            else:
                continue
        if len(line) > 2000 or _comment_line(line, lang):
            if line.lstrip().startswith("/*") and "*/" not in line:
                in_block = True
            continue
        code = _code_of(line)
        if "/*" in code:                    # a block comment that opens here and closes on a later line
            in_block, code = True, code.split("/*", 1)[0]
        for m in recv_rx.finditer(code):
            by_recv.setdefault(m.group(1), []).append(n)
    starts = sorted(h["start"] for h in handlers)
    for s in mine:
        own = _code_of(lines[s["line"] - 1])
        if call_rx.search(own):
            s["call_line"] = s["line"]
            continue
        h, b = s.get("_h"), _DESER_BIND.search(own)
        if h is None or b is None:
            s["call_line"] = None
            continue
        i = bisect.bisect_right(starts, h["start"])
        end = starts[i] if i < len(starts) else len(lines) + 1
        calls = by_recv.get(b.group(1), [])
        lo, hi = bisect.bisect_left(calls, h["start"]), bisect.bisect_left(calls, end)
        s["call_line"] = calls[lo] if hi - lo == 1 else None


def _review(short, lang, lines, routes, sinks):
    """Routes and sinks of one source file, each sink placed in the handler it sits in."""
    handlers = []       # [{name, start, routes: [...], params: set}]
    pending, current, indent = [], None, 0
    for n, line in enumerate(lines, 1):
        if lang == "python":
            m = _PY_ROUTE.match(line)
            if m:
                methods = re.findall(r"[\"']([A-Za-z]+)[\"']", (re.search(r"methods\s*=\s*[\[(]([^\])]*)", m.group(4)) or [None, ""])[1])
                verb = m.group(2).upper() if m.group(2) not in ("route", "api_route") else None
                for method in ([verb] if verb else (methods or ["GET"])):
                    pending.append({"file": short, "line": n, "method": method.upper(), "path": m.group(3), "handler": None})
                continue
            d = _PY_DEF.match(line)
            if d and (pending or len(d.group(1)) <= indent or current is None):
                current = {"name": d.group(2), "start": n, "routes": pending, "params": set()}
                indent = len(d.group(1))
                for r in pending:
                    r["handler"] = d.group(2)
                    routes.append(r)
                    for p in re.findall(r"<(?:\w+:)?(\w+)>|\{(\w+)(?::[^}]*)?\}", r["path"]):
                        current["params"].add(p[0] or p[1])
                pending = []
                handlers.append(current)
            elif line.strip() and not line[:1].isspace() and not line.lstrip().startswith(("@", "#", ")")) and current is not None and not d:
                current = None      # module-level code after a function
        elif lang == "js":
            for m in _JS_ROUTE.finditer(line):
                if m.group(2) == "use" and m.group(1) not in ("app", "router"):
                    continue
                r = {"file": short, "line": n, "method": m.group(2).upper() if m.group(2) not in ("all", "use") else None, "path": m.group(3),
                     "handler": f"{m.group(2)} {m.group(3)}"}
                routes.append(r)
                current = {"name": r["handler"], "start": n, "routes": [r], "params": set(re.findall(r":(\w+)", m.group(3)))}
                handlers.append(current)
        elif lang == "cs":
            for m in _CS_MAP.finditer(line):
                r = {"file": short, "line": n, "method": m.group(1).upper(), "path": m.group(2), "handler": f"Map{m.group(1)} {m.group(2)}"}
                routes.append(r)
                current = {"name": r["handler"], "start": n, "routes": [r], "params": set(re.findall(r"\{(\w+)", m.group(2)))}
                handlers.append(current)
            for m in _CS_ATTR.finditer(line):
                verb = None if m.group(1) == "Route" else m.group(1)[4:].upper()
                pending.append({"file": short, "line": n, "method": verb, "path": m.group(2) or "", "handler": None})
            d = _CS_METHOD.match(line)
            if d and "[" not in line.split("(")[0]:
                current = {"name": d.group(1), "start": n, "routes": pending, "params": set()}
                for r in pending:
                    r["handler"] = d.group(1)
                    routes.append(r)
                pending = []
                handlers.append(current)
            elif re.match(r"^\s*(?:public|internal)?\s*(?:sealed\s+|abstract\s+|static\s+)*class\s+\w+", line):
                for r in pending:           # class-level [Route]: kept as a prefix row
                    r["handler"] = "class"
                    routes.append(r)
                pending = []
        elif lang in ("php", "java") and current is None:
            # a page (.php, .jsp) is served at its own name; a Java class is not: `/LoadServlet.java` is no
            # route (review of eb6699e, B2), its @WebServlet/@*Mapping path is not read here, so it has none
            page = Path(short).suffix.lower() != ".java"
            current = {"name": Path(short).name, "start": 1, "params": set(),
                       "routes": [{"file": short, "line": 1, "method": None, "path": "/" + Path(short).name}] if page else []}
            handlers.append(current)
        prx = _PARAM_RX.get(lang)
        if prx and current is not None:
            for m in prx.finditer(line):
                current["params"].add(next(g for g in m.groups() if g))
            if lang == "js":            # const { emoji, size: n } = req.body
                for m in _JS_DESTRUCTURE.finditer(line):
                    for name in m.group(1).split(","):
                        name = name.split(":")[0].split("=")[0].strip().lstrip(".")
                        if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                            current["params"].add(name)
        if _comment_line(line, lang) or len(line) > 2000:
            continue
        for sid, fam, slang, rx in _SINKS:
            if slang == lang and rx.search(line):
                sinks.append({"file": short, "line": n, "sink": sid, "family": fam, "code": line.strip()[:240],
                              "handler": current["name"] if current else None, "_h": current})
    for h in handlers:
        for r in h["routes"]:
            r["reads"] = sorted(set(r.get("reads") or []) | h["params"])
    _deser_calls(lang, lines, handlers, sinks)
    for s in sinks:
        h = s.pop("_h", None) if "_h" in s else None
        if "routes" not in s:
            s["routes"] = [{"method": r["method"], "path": r["path"]} for r in (h["routes"] if h else [])]
            s["params"] = sorted(h["params"]) if h else []


# ---- bounded static source-to-sink review ---------------------------------------------------------------
#
# This is deliberately a small lexical reader, not a language parser.  It never imports, compiles or runs
# delivered code.  A row is emitted only when one request read, a short acyclic chain of local assignments,
# and a known sink all sit in one proved handler.  Anything the reader cannot model (a branch, two inputs,
# an unknown helper, a second assignment, or a broken scope) declines the row.  The older ``sinks`` list is
# kept for API compatibility; these stronger findings live in ``taint`` and carry their complete provenance.

STATIC_MAX_WORK = 2_000_000
STATIC_MAX_HANDLERS = 128
STATIC_MAX_STATEMENTS = 800
STATIC_MAX_VARS = 256
STATIC_MAX_CHAIN = 4
STATIC_MAX_FINDINGS = 256
STATIC_MAX_CALL = 16_000


def _blank(text, a, b):
    """Blank ``text[a:b]`` without moving newlines (position/line mappings remain exact)."""
    return "".join("\n" if c == "\n" else " " for c in text[a:b])


def _source_masks(text, lang):
    """Return (comments-blanked, comments-and-literals-blanked), both the input's exact length.

    The scanner is intentionally modest but stateful across lines: block comments, Python triple strings,
    JavaScript template strings and PHP/Ruby quoted strings cannot manufacture a route, source or sink.
    Literal route/parameter text remains in the first result.
    """
    comments, code = list(text), list(text)
    i, n, block, quote = 0, len(text), None, None
    quote_start, quote_interp, interpolated = None, False, []
    hash_comment = lang in ("python", "ruby", "php")
    slash_comment = lang in ("js", "php", "cs", "java", "go")
    while i < n:
        if block:
            end = text.find(block, i)
            stop = n if end < 0 else end + len(block)
            for j in range(i, stop):
                if text[j] != "\n":
                    comments[j] = code[j] = " "
            i, block = stop, None if end >= 0 else block
            continue
        if quote:
            q, triple = quote
            if triple and text.startswith(q, i):
                for j in range(i, min(n, i + len(q))):
                    code[j] = " "
                i += len(q)
                if quote_interp:
                    interpolated.append((quote_start, i, lang))
                quote = None
                continue
            c = text[i]
            if c == "\\":
                code[i] = " "
                if i + 1 < n and text[i + 1] != "\n":
                    code[i + 1] = " "
                i += 2
                continue
            code[i] = "\n" if c == "\n" else " "
            if not triple and c == q:
                if quote_interp:
                    interpolated.append((quote_start, i + 1, lang))
                quote = None
            i += 1
            continue
        if slash_comment and text.startswith("/*", i):
            comments[i] = comments[i + 1] = code[i] = code[i + 1] = " "
            block, i = "*/", i + 2
            continue
        if slash_comment and text.startswith("//", i):
            end = text.find("\n", i)
            end = n if end < 0 else end
            for j in range(i, end):
                comments[j] = code[j] = " "
            i = end
            continue
        if hash_comment and text[i] == "#" and not (lang == "php" and text.startswith("#[", i)):
            # Ruby interpolation only occurs while inside a quote, which is blanked as one unit above.
            end = text.find("\n", i)
            end = n if end < 0 else end
            for j in range(i, end):
                comments[j] = code[j] = " "
            i = end
            continue
        c = text[i]
        if c in "\"'`":
            q = c * 3 if lang == "python" and text.startswith(c * 3, i) else c
            prefix = text[max(0, i - 3):i]
            quote_start = i
            quote_interp = (lang == "js" and c == "`") or (lang == "python" and "f" in prefix.lower()) or (lang == "ruby" and c == '"')
            for j in range(i, min(n, i + len(q))):
                code[j] = " "
            quote, i = (q, len(q) == 3), i + len(q)
            continue
        # A JavaScript regex literal is data, not source.  Recognise only the unambiguous expression-start
        # form; division remains code.  A malformed literal simply makes the scan more conservative.
        if lang == "js" and c == "/" and re.search(r"(?:^|[=(:,!&|?{};])\s*$", "".join(code[max(0, i - 32):i])):
            j, cls = i + 1, False
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "[":
                    cls = True
                elif text[j] == "]":
                    cls = False
                elif text[j] == "/" and not cls:
                    j += 1
                    while j < n and text[j].isalpha():
                        j += 1
                    break
                elif text[j] == "\n":
                    break
                j += 1
            for k in range(i, min(j, n)):
                code[k] = " "
            i = max(i + 1, j)
            continue
        i += 1
    # Restore only the executable islands of interpolation.  Plain strings stay completely blank, so a
    # quoted example such as "eval(req.query.q)" remains inert.  Nested interpolation is declined.
    for a, b, il in interpolated:
        body = text[a:b]
        irx = re.compile(r"\$\{([^{}]{0,4000})\}", re.S) if il == "js" else \
              re.compile(r"#\{([^{}]{0,4000})\}", re.S) if il == "ruby" else re.compile(r"\{([^{}]{0,4000})\}", re.S)
        for m in irx.finditer(body):
            start, end = a + m.start(1), a + m.end(1)
            _, inner = _source_masks(text[start:end], il)
            code[start:end] = inner
    return "".join(comments), "".join(code)


def _line_at(text, pos):
    return text.count("\n", 0, max(0, pos)) + 1


def _brace_end(mask, start, opener="{", closer="}"):
    """End position of a braced body beginning at/after start, or a conservative short fallback."""
    a = mask.find(opener, start, min(len(mask), start + STATIC_MAX_CALL))
    if a < 0:
        return min(len(mask), start + STATIC_MAX_CALL)
    depth = 0
    for m in re.finditer("[" + re.escape(opener + closer) + "]", mask[a:min(len(mask), a + 200_000)]):
        depth += 1 if m.group() == opener else -1
        if depth == 0:
            return a + m.end()
    return min(len(mask), a + 200_000)


def _paren_end(mask, opening):
    if opening < 0 or opening >= len(mask) or mask[opening] != "(":
        return None
    depth = 0
    for i in range(opening, min(len(mask), opening + STATIC_MAX_CALL)):
        c = mask[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def _args(raw, mask, opening, end):
    """Top-level argument slices (absolute start/end), with all brackets balanced in the mask."""
    out, start, stack = [], opening + 1, []
    pairs = {")": "(", "]": "[", "}": "{"}
    for i in range(opening + 1, max(opening + 1, end - 1)):
        c = mask[i]
        if c in "([{":
            stack.append(c)
        elif c in ")]}":
            if stack and stack[-1] == pairs[c]:
                stack.pop()
        elif c == "," and not stack:
            out.append((start, i))
            start = i + 1
    out.append((start, max(start, end - 1)))
    return [(a, b, raw[a:b].strip()) for a, b in out]


def _literal(value):
    m = re.match(r"\s*(?:[rubfRUBF]{0,3})?([\"'`])([^\n]*?)\1\s*$", value or "")
    return m.group(2) if m else None


def _join_path(a, b):
    a, b = str(a or ""), str(b or "")
    if not a:
        return b or "/"
    if not b or b == "/":
        return a or "/"
    return a.rstrip("/") + "/" + b.lstrip("/")


def _dedup_route(routes, row):
    key = (row.get("file"), row.get("method"), row.get("path"), row.get("handler"))
    if not any((r.get("file"), r.get("method"), r.get("path"), r.get("handler")) == key for r in routes):
        routes.append(row)


def _handler(name, start, end, line, args=""):
    return {"name": name, "start": start, "end": max(start + 1, end), "line": line, "args": args,
            "routes": [], "params": set(), "param_vars": {}}


def _find_functions(lang, raw, mask):
    """Conservative named-function extents used to isolate data flow."""
    out = []
    if lang == "python":
        rx = re.compile(r"(?m)^(?P<i>[ \t]*)(?:async\s+)?def\s+(?P<n>[A-Za-z_]\w*)\s*\((?P<a>[^\n]*)\)\s*(?:->[^:\n]+)?\s*:")
        matches = list(rx.finditer(mask))
        for k, m in enumerate(matches):
            indent = len(m.group("i").replace("\t", "    "))
            end = len(mask)
            for lm in re.finditer(r"(?m)^(\s*)(\S.*)$", mask[m.end():]):
                text = lm.group(2)
                if text.startswith(("#", "@")):
                    continue
                ind = len(lm.group(1).replace("\t", "    "))
                if ind <= indent:
                    end = m.end() + lm.start()
                    break
            h = _handler(m.group("n"), m.start(), end, _line_at(raw, m.start()), raw[m.start("a"):m.end("a")])
            h["indent"] = indent
            out.append(h)
    elif lang == "ruby":
        rx = re.compile(r"(?m)^\s*def\s+(?:self\.)?(?P<n>[A-Za-z_]\w*[!?=]?)\s*(?:\((?P<a>[^)]*)\)|(?P<b>[^\n]*))")
        ms = list(rx.finditer(mask))
        for k, m in enumerate(ms):
            end = ms[k + 1].start() if k + 1 < len(ms) else len(mask)
            out.append(_handler(m.group("n"), m.start(), end, _line_at(raw, m.start()), m.group("a") or m.group("b") or ""))
    else:
        patterns = {
            "js": r"(?m)(?:^|[;}\n])\s*(?:export\s+)?(?:async\s+)?(?:function\s+(?P<n1>[A-Za-z_$][\w$]*)\s*\((?P<a1>[^)]*)\)|(?:const|let|var)\s+(?P<n2>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\((?P<a2>[^)]*)\)\s*=>)\s*\{",
            "java": r"(?m)^\s*(?:public|protected|private|static|final|synchronized|abstract|native|default|\s)+[\w<>,.?\[\]@]+\s+(?P<n1>[A-Za-z_]\w*)\s*\((?P<a1>[^)]*(?:\)[^\n{]*)?)\)\s*(?:throws[^\{]+)?\{",
            "cs": r"(?m)^\s*(?:public|protected|private|internal|static|async|virtual|override|sealed|\s)+[\w<>,.?\[\]]+\s+(?P<n1>[A-Za-z_]\w*)\s*\((?P<a1>[^)]*)\)\s*\{",
            "go": r"(?m)^\s*func\s+(?:\([^)]*\)\s*)?(?P<n1>[A-Za-z_]\w*)\s*\((?P<a1>[^)]*)\)[^{\n]*\{",
            "php": r"(?mi)^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+(?P<n1>[A-Za-z_]\w*)\s*\((?P<a1>[^)]*)\)[^{;]*\{",
        }
        rx = re.compile(patterns.get(lang, r"(?!x)x"))
        for m in rx.finditer(mask):
            name = m.groupdict().get("n1") or m.groupdict().get("n2")
            args = m.groupdict().get("a1") or m.groupdict().get("a2") or ""
            out.append(_handler(name, m.start(), _brace_end(mask, m.end() - 1), _line_at(raw, m.start()), args))
        if lang == "java":
            # Java parameter annotations contain their own parentheses.  The compact regex above refuses
            # some perfectly ordinary Spring/JAX-RS signatures, so locate the outer method parentheses with
            # the balanced scanner and recover the literal-bearing argument text from ``raw``.
            out = []
            head = re.compile(r"\b(?:public|protected|private)\s+(?:(?:static|final|synchronized|abstract|default)\s+)*"
                              r"[A-Za-z_$][\w$<>,.?\[\]]*\s+([A-Za-z_$][\w$]*)\s*\(")
            for m in head.finditer(mask):
                pend = _paren_end(mask, m.end() - 1)
                if pend is None or "{" not in mask[pend:min(len(mask), pend + 500)]:
                    continue
                brace = mask.find("{", pend, min(len(mask), pend + 500))
                if any(h["name"] == m.group(1) and abs(h["start"] - m.start()) < 100 for h in out):
                    continue
                out.append(_handler(m.group(1), m.start(), _brace_end(mask, brace), _line_at(raw, m.start()),
                                    raw[m.end():pend - 1]))
    return out[:STATIC_MAX_HANDLERS]


def _route_row(short, raw, method, path, name, pos):
    return {"file": short, "line": _line_at(raw, pos), "method": method, "path": path or "/", "handler": name}


def _python_routes(short, raw, comments, mask, handlers):
    prefixes = {}
    for m in re.finditer(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*(?:Blueprint|APIRouter)\s*\(([^\n]{0,1000})", comments):
        p = re.search(r"(?:url_prefix|prefix)\s*=\s*([\"'])(.*?)\1", m.group(2), re.S)
        prefixes[m.group(1)] = p.group(2) if p else ""
    for m in re.finditer(r"\b(?:include_router|register_blueprint)\s*\(\s*([A-Za-z_]\w*)\s*(?:,([\s\S]{0,1000}?))?\)", comments):
        p = re.search(r"\b(?:url_)?prefix\s*=\s*([\"'])(.*?)\1", m.group(2) or "", re.S)
        if m.group(1) in prefixes and p:
            prefixes[m.group(1)] = _join_path(p.group(2), prefixes[m.group(1)])
    dec = re.compile(r"@\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\.(route|get|post|put|delete|patch|options|head|api_route|websocket)\s*\(", re.I)
    for h in handlers:
        head = comments[max(0, h["start"] - 4000):h["start"]]
        floor = max(head.rfind("\ndef "), head.rfind("\nasync def "), head.rfind("\nclass "))
        head, base = head[floor + 1:], max(0, h["start"] - 4000) + floor + 1
        for m in dec.finditer(head):
            op = base + m.end() - 1
            end = _paren_end(mask, op)
            if end is None or end > h["start"]:
                continue
            aa = _args(comments, mask, op, end)
            path = _literal(aa[0][2]) if aa else None
            if path is None:
                continue
            obj, kind = m.group(1).split(".")[0], m.group(2).lower()
            tail = comments[op:end]
            methods = re.findall(r"[\"']([A-Za-z]+)[\"']", (re.search(r"\bmethods\s*=\s*[\[(]([\s\S]*?)[\])]", tail) or [None, ""])[1])
            verb = kind.upper() if kind not in ("route", "api_route") else None
            full = _join_path(prefixes.get(obj, ""), path)
            for method in ([verb] if verb else ([x.upper() for x in methods] or ["GET"])):
                h["routes"].append(_route_row(short, raw, method, full, h["name"], base + m.start()))


def _js_routes(short, raw, comments, mask, handlers):
    prefixes, mounts = {"app": "", "router": ""}, []
    for m in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:express\s*\.\s*Router|Router)\s*\(", mask):
        prefixes.setdefault(m.group(1), "")
    call_rx = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|delete|patch|options|head|all|use)\s*\(", re.I)
    calls = []
    for m in call_rx.finditer(mask):
        op, end = m.end() - 1, _paren_end(mask, m.end() - 1)
        if end is None:
            continue
        aa = _args(comments, mask, op, end)
        path = _literal(aa[0][2]) if aa else None
        if path is None:
            continue
        obj, kind = m.group(1), m.group(2).lower()
        if kind == "use" and len(aa) > 1:
            child = aa[1][2].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", child):
                mounts.append((obj, path, child))
            continue
        calls.append((m, end, aa, obj, kind, path))
    for _ in range(8):
        changed = False
        for parent, path, child in mounts:
            if parent in prefixes:
                value = _join_path(prefixes[parent], path)
                if prefixes.get(child) != value:
                    prefixes[child], changed = value, True
        if not changed:
            break
    by_name = {h["name"]: h for h in handlers}
    for m, end, aa, obj, kind, path in calls:
        full, target = _join_path(prefixes.get(obj, ""), path), None
        if len(aa) > 1:
            last = aa[-1][2].strip()
            named = re.fullmatch(r"[A-Za-z_$][\w$]*", last)
            if named:
                target = by_name.get(named.group())
            elif re.search(r"(?:=>|\bfunction\b)", last):
                brace = mask.find("{", aa[-1][0], end)
                start = brace + 1 if brace >= 0 else aa[-1][0]
                target = _handler(f"{kind} {full}", start, end, _line_at(raw, start), "")
                target["inline"] = True
                handlers.append(target)
        if target is None:
            target = _handler(f"{kind} {full}", m.start(), end, _line_at(raw, m.start()), "")
            target["inline"] = True
            handlers.append(target)
        method = None if kind == "all" else kind.upper()
        target["routes"].append(_route_row(short, raw, method, full, target["name"], m.start()))


def _java_routes(short, raw, comments, mask, handlers):
    class_prefix, servlet = "", None
    cm = re.search(r"(?s)([\s\S]{0,4000}?)\b(?:public\s+)?(?:abstract\s+)?class\s+\w+", comments)
    if cm:
        pre = cm.group(1)
        p = re.search(r"@(?:RequestMapping|Path)\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)", pre)
        class_prefix = p.group(1) if p else ""
        ws = re.search(r"@WebServlet\s*\(\s*(?:value\s*=\s*|urlPatterns\s*=\s*(?:\{\s*)?)?[\"']([^\"']+)", pre)
        servlet = ws.group(1) if ws else None
    for h in handlers:
        pre_start = max(0, h["start"] - 4000)
        pre = comments[pre_start:h["start"]]
        structural = mask[pre_start:h["start"]]
        pre = pre[max(structural.rfind("}"), structural.rfind("{")) + 1:]
        rows = []
        for m in re.finditer(r"@(Get|Post|Put|Delete|Patch)Mapping\s*(?:\(\s*(?:value\s*=\s*|path\s*=\s*)?[\"']([^\"']*)[\"']?[^)]*\))?", pre, re.I):
            rows.append((m.group(1).upper(), m.group(2) or ""))
        for m in re.finditer(r"@RequestMapping\s*\(([^)]*)\)", pre, re.I | re.S):
            p = re.search(r"(?:value|path)\s*=\s*[\"']([^\"']*)|^\s*[\"']([^\"']*)", m.group(1))
            path = (p.group(1) or p.group(2)) if p else ""
            verbs = re.findall(r"RequestMethod\.([A-Z]+)", m.group(1)) or [None]
            rows.extend((v, path) for v in verbs)
        jpath = re.search(r"@Path\s*\(\s*[\"']([^\"']*)", pre)
        jverbs = re.findall(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", pre)
        if jpath or jverbs:
            rows.extend((v, jpath.group(1) if jpath else "") for v in (jverbs or [None]))
        if servlet and h["name"] in ("doGet", "doPost", "doPut", "doDelete", "service"):
            rows.append((h["name"][2:].upper() if h["name"] != "service" else None, servlet))
        for method, path in rows:
            h["routes"].append(_route_row(short, raw, method, _join_path(class_prefix, path), h["name"], h["start"]))


def _ruby_routes(short, raw, comments, mask, handlers):
    # Rails config/routes.rb rows carry controller#action so a later global pass can attach them to the
    # corresponding controller method.  Sinatra's `get '/x' do` is itself the handler.
    for m in re.finditer(r"(?m)^\s*(get|post|put|patch|delete|options|head)\s+([\"'][^\"']+[\"'])([^\n]*)", comments, re.I):
        method, path, tail = m.group(1).upper(), _literal(m.group(2)), m.group(3)
        to = re.search(r"\bto\s*:\s*[\"']([A-Za-z0-9_/]+#[A-Za-z_]\w*)", tail)
        if to:
            name = to.group(1)
            h = _handler(name, m.start(), comments.find("\n", m.end()) if "\n" in comments[m.end():] else len(comments), _line_at(raw, m.start()))
            h["routes"].append(_route_row(short, raw, method, path, name, m.start()))
            handlers.append(h)
        elif re.search(r"\bdo\b", tail):
            end = next((x.start() for x in re.finditer(r"(?m)^\s*end\b", mask[m.end():])), len(mask) - m.end()) + m.end()
            name = f"{m.group(1).lower()} {path}"
            h = _handler(name, m.start(), end, _line_at(raw, m.start()))
            h["routes"].append(_route_row(short, raw, method, path, name, m.start()))
            handlers.append(h)


def _go_routes(short, raw, comments, mask, handlers):
    prefixes = {"r": "", "e": "", "app": "", "router": "", "mux": ""}
    for m in re.finditer(r"(?m)^\s*([A-Za-z_]\w*)\s*:?=\s*([A-Za-z_]\w*)\.Group\s*\(\s*([\"'][^\"']+[\"'])", comments):
        prefixes[m.group(1)] = _join_path(prefixes.get(m.group(2), ""), _literal(m.group(3)))
    by_name = {h["name"]: h for h in handlers}
    rx = re.compile(r"\b([A-Za-z_]\w*)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Get|Post|Put|Delete|Patch|HandleFunc|Handle)\s*\(")
    for m in rx.finditer(mask):
        end = _paren_end(mask, m.end() - 1)
        if end is None:
            continue
        aa = _args(comments, mask, m.end() - 1, end)
        path = _literal(aa[0][2]) if aa else None
        if path is None:
            continue
        kind = m.group(2)
        method = None if kind in ("Handle", "HandleFunc") else kind.upper()
        tail = comments[end:min(len(comments), end + 100)]
        methods = re.search(r"\.Methods\s*\(\s*[\"']([A-Z]+)", tail)
        if methods:
            method = methods.group(1)
        target = None
        if len(aa) > 1:
            name = re.sub(r"^\w+\.", "", aa[1][2].strip())
            target = by_name.get(name)
        if target is None:
            target = _handler(f"{kind} {path}", m.start(), end, _line_at(raw, m.start()))
            target["inline"] = True
            handlers.append(target)
        full = _join_path(prefixes.get(m.group(1), ""), path)
        target["routes"].append(_route_row(short, raw, method, full, target["name"], m.start()))


def _php_routes(short, raw, comments, mask, handlers):
    by_name = {h["name"]: h for h in handlers}
    rx = re.compile(r"(?:\bRoute\s*::|\$[A-Za-z_]\w*\s*->\s*)(get|post|put|delete|patch|options|any)\s*\(", re.I)
    for m in rx.finditer(mask):
        end = _paren_end(mask, m.end() - 1)
        if end is None:
            continue
        aa = _args(comments, mask, m.end() - 1, end)
        path = _literal(aa[0][2]) if aa else None
        if path is None:
            continue
        target = None
        if len(aa) > 1:
            fn = re.search(r"[\"']([A-Za-z_]\w*)[\"']\s*\]?\s*$", aa[-1][2])
            if fn:
                target = by_name.get(fn.group(1))
            elif re.search(r"\bfunction\s*\(", aa[-1][2]):
                brace = mask.find("{", aa[-1][0], end)
                start = brace + 1 if brace >= 0 else aa[-1][0]
                target = _handler(f"{m.group(1).lower()} {path}", start, end, _line_at(raw, start))
                target["inline"] = True
                handlers.append(target)
        if target is None:
            target = _handler(f"{m.group(1).lower()} {path}", m.start(), end, _line_at(raw, m.start()))
            target["inline"] = True
            handlers.append(target)
        method = None if m.group(1).lower() == "any" else m.group(1).upper()
        target["routes"].append(_route_row(short, raw, method, path, target["name"], m.start()))
    # Symfony/PHP 8 route attributes immediately above a controller method.
    for h in handlers:
        pre = comments[max(0, h["start"] - 1500):h["start"]]
        m = re.search(r"#\[\s*Route\s*\(\s*[\"']([^\"']+)[\"']([\s\S]*?)\)\s*\]\s*$", pre)
        if m:
            methods = re.findall(r"[\"'](GET|POST|PUT|DELETE|PATCH)[\"']", m.group(2)) or [None]
            for method in methods:
                h["routes"].append(_route_row(short, raw, method, m.group(1), h["name"], h["start"]))


def _cs_routes(short, raw, comments, mask, handlers):
    # The legacy reader already covers ASP.NET.  This pass only attaches its rows to the stronger extents.
    del short, raw, comments, mask, handlers


_SOURCE_RX = {
    "python": (
        ("query", re.compile(r"\brequest\.(?:args|form|values|json|cookies|headers|files)\s*(?:\.get(?:list)?\s*\(\s*|\[\s*)[\"']([^\"']+)[\"']")),
        ("json", re.compile(r"\brequest\.get_json\s*\(\s*\)\s*(?:\.get\s*\(\s*|\[\s*)[\"']([^\"']+)[\"']")),
    ),
    "js": (("request", re.compile(r"\b(?:req|request)\.(?:query|body|params|cookies|headers)\s*(?:\.\s*([A-Za-z_$][\w$]*)|\[\s*[\"']([^\"']+)[\"']\s*\])")),),
    "php": (
        ("superglobal", re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*[\"']([^\"']+)[\"']\s*\]")),
        ("request", re.compile(r"(?:\$(?:[A-Za-z_]*request|req)\s*->\s*(?:input|get|query|post|file|header|getQuery|getData|getGet|getPost)|\brequest)\s*\(\s*[\"']([^\"']+)[\"']", re.I)),
        ("request", re.compile(r"\brequest\s*\(\s*\)\s*->\s*(?:input|get|query|post|file|header)\s*\(\s*[\"']([^\"']+)[\"']")),
        ("request", re.compile(r"\$this\s*->\s*request\s*->\s*(?:getQuery|getData|getParam)\s*\(\s*[\"']([^\"']+)[\"']")),
        ("request", re.compile(r"\$[A-Za-z_]\w*\s*->\s*query\s*->\s*get\s*\(\s*[\"']([^\"']+)[\"']")),
        ("request", re.compile(r"\$this\s*->\s*input\s*->\s*(?:get|post)\s*\(\s*[\"']([^\"']+)[\"']")),
    ),
    "ruby": (("params", re.compile(r"\bparams\s*(?:\[\s*:?[\"']?([A-Za-z_]\w*)[\"']?\s*\]|\.fetch\s*\(\s*:?[\"']?([A-Za-z_]\w*)[\"']?)")),),
    "go": (
        ("query", re.compile(r"\b(?:r\.)?(?:URL\.Query\(\)\.Get|FormValue|PostFormValue)\s*\(\s*[\"']([^\"']+)[\"']")),
        ("framework", re.compile(r"\b(?:c|ctx)\.(?:Query|QueryParam|Param|Params|FormValue|PostForm|FormFile|Get)\s*\(\s*[\"']([^\"']+)[\"']")),
        ("path", re.compile(r"\bchi\.URLParam\s*\(\s*\w+\s*,\s*[\"']([^\"']+)[\"']|\bmux\.Vars\s*\([^)]*\)\s*\[\s*[\"']([^\"']+)[\"']")),
    ),
    "java": (("request", re.compile(r"\.(?:getParameter|getHeader|getCookie)\s*\(\s*[\"']([^\"']+)[\"']")),),
    "cs": (("request", re.compile(r"\bRequest\.(?:Query|Form|Cookies|Headers|QueryString|Params)\s*\[\s*[\"']([^\"']+)[\"']")),),
}


# (sink id, family, context, active call/statement head, mode).  A matching sanitizer suppresses only the
# named context.  ``code`` and ``template`` deliberately have no generic sanitizer.
_FLOW_SINKS = {
    "python": (
        ("eval", "code_injection", "code", r"(?<![\w.])(?:eval|exec)\s*\(", "call"),
        ("yaml.load", "deserialization", "object", r"\b(?:yaml\.(?:load|unsafe_load|full_load)|pickle\.loads?|dill\.loads?)\s*\(", "call"),
        ("subprocess", "cmdi", "shell", r"\b(?:os\.(?:system|popen)|subprocess\.(?:run|call|Popen|check_output|check_call|getoutput))\s*\(", "call"),
        ("sql.execute", "sqli", "sql", r"\.(?:execute|executemany|executescript|raw)\s*\(", "call"),
        ("open", "traversal", "path", r"(?<![\w.])(?:open|send_file|send_from_directory)\s*\(", "call"),
        ("requests.get", "ssrf", "url", r"\b(?:requests\.(?:get|post|request)|httpx\.(?:get|post|request)|urlopen)\s*\(", "call"),
        ("redirect", "open_redirect", "url", r"(?<![\w.])(?:redirect|HttpResponseRedirect)\s*\(", "call"),
        ("Markup", "xss", "html", r"\b(?:Markup|mark_safe|render_template_string)\s*\(", "call"),
    ),
    "js": (
        ("eval", "code_injection", "code", r"(?<![\w.])(?:eval|Function|setTimeout|setInterval)\s*\(", "call"),
        ("child_process.exec", "cmdi", "shell", r"\b(?:exec|execSync|spawn|spawnSync)\s*\(", "call"),
        ("sql.query", "sqli", "sql", r"\.(?:query|execute|raw)\s*\(", "call"),
        ("mongo.find", "nosqli", "object", r"\.(?:find|findOne|findOneAndUpdate|updateOne|updateMany|aggregate)\s*\(", "call"),
        ("merge", "prototype_pollution", "object", r"\b(?:_\.(?:merge|mergeWith|defaultsDeep|set)|Object\.assign|deepmerge|mergeDeep)\s*\(", "call"),
        ("fs.readFile", "traversal", "path", r"\b(?:fs\.(?:readFile|readFileSync|createReadStream)|res\.(?:sendFile|download)|path\.join)\s*\(", "call"),
        ("fetch", "ssrf", "url", r"\b(?:fetch|axios\.(?:get|post|request)|request)\s*\(", "call"),
        ("res.redirect", "open_redirect", "url", r"\bres\.redirect\s*\(", "call"),
        ("innerHTML", "xss", "html", r"\.(?:innerHTML|outerHTML)\s*=", "rhs"),
        ("insertAdjacentHTML", "xss", "html", r"\b(?:insertAdjacentHTML|document\.write(?:ln)?|\.html)\s*\(", "call"),
        ("template.render", "ssti", "template", r"\b(?:ejs|pug|nunjucks|handlebars|mustache)\.(?:render|compile)\s*\(", "call"),
    ),
    "php": (
        ("eval", "code_injection", "code", r"(?<![\w>$])(?:eval|assert)\s*\(", "call"),
        ("system", "cmdi", "shell", r"(?<![\w>$])(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(", "call"),
        ("unserialize", "deserialization", "object", r"(?<![\w>$])unserialize\s*\(", "call"),
        ("include", "traversal", "path", r"\b(?:include|require)(?:_once)?\b", "rest"),
        ("include", "traversal", "path", r"\b(?:file_get_contents|readfile|fopen)\s*\(", "call"),
        ("sql.query", "sqli", "sql", r"\b(?:mysqli?_query|pg_query)\s*\(|->(?:query|exec)\s*\(", "call"),
        ("echo", "xss", "html", r"(?<![\w>$])(?:echo|print)\b", "rest"),
        ("header.location", "open_redirect", "url", r"\bheader\s*\(", "call"),
    ),
    "ruby": (
        ("Marshal.load", "deserialization", "object", r"\b(?:Marshal\.(?:load|restore)|YAML\.load|Psych\.load)\s*\(", "call"),
        ("system", "cmdi", "shell", r"(?<![\w.])(?:system|exec|spawn)\s*\(?", "call_optional"),
        ("where", "sqli", "sql", r"\.(?:where|find_by_sql|exec_query|execute)\s*\(", "call"),
        ("ERB.new", "ssti", "template", r"\b(?:ERB\.new|render)\s*\(?", "call_optional"),
        ("File.read", "traversal", "path", r"\b(?:File\.(?:read|open)|send_file)\s*\(", "call"),
        ("redirect", "open_redirect", "url", r"(?<![\w.])redirect\s*\(?", "call_optional"),
    ),
    "go": (
        ("exec.Command", "cmdi", "shell", r"\bexec\.Command(?:Context)?\s*\(", "all"),
        ("db.Query", "sqli", "sql", r"\.(?:Query|QueryRow|Exec|QueryContext|ExecContext)\s*\(", "all"),
        ("os.Open", "traversal", "path", r"\b(?:os\.(?:Open|OpenFile|ReadFile)|ioutil\.ReadFile|http\.ServeFile|filepath\.Join)\s*\(", "all"),
        ("http.Get", "ssrf", "url", r"\b(?:http\.(?:Get|Post|Head)|client\.(?:Get|Post)|http\.NewRequest(?:WithContext)?)\s*\(", "all"),
        ("template.HTML", "xss", "html", r"\btemplate\.HTML\s*\(", "call"),
    ),
    "java": (
        ("Runtime.exec", "cmdi", "shell", r"\b(?:Runtime\.getRuntime\s*\(\s*\)\s*\.exec|ProcessBuilder)\s*\(", "call"),
        ("Statement.execute", "sqli", "sql", r"\.(?:execute|executeQuery|executeUpdate|queryForObject)\s*\(", "call"),
        ("File", "traversal", "path", r"\b(?:new\s+File|Paths\.get|Files\.(?:readString|readAllBytes|newInputStream))\s*\(", "call"),
        ("URL", "ssrf", "url", r"\b(?:new\s+URL|URI\.create)\s*\(", "call"),
        ("sendRedirect", "open_redirect", "url", r"\bsendRedirect\s*\(", "call"),
        ("writer.write", "xss", "html", r"\.(?:write|print|println)\s*\(", "call"),
    ),
    "cs": (
        ("Process.Start", "cmdi", "shell", r"\b(?:Process\.Start|new\s+ProcessStartInfo)\s*\(", "call"),
        ("SqlCommand", "sqli", "sql", r"\bnew\s+SqlCommand\s*\(|\.(?:ExecuteSqlRaw|FromSqlRaw)\s*\(", "call"),
        ("File.Read", "traversal", "path", r"\bFile\.(?:ReadAllText|ReadAllBytes|OpenRead)\s*\(", "call"),
        ("HttpClient", "ssrf", "url", r"\.(?:GetAsync|PostAsync|SendAsync)\s*\(", "call"),
        ("Html.Raw", "xss", "html", r"\bHtml\.Raw\s*\(", "call"),
        ("Redirect", "open_redirect", "url", r"\bRedirect\s*\(", "call"),
    ),
}

_SANITIZERS = {
    "html": re.compile(r"\b(?:DOMPurify\.sanitize|html\.escape|escapeHtml|htmlspecialchars|HtmlEncoder\.Default\.Encode|Encode\.forHtml|sanitize_html)\s*\(", re.I),
    "sql": re.compile(r"\b(?:escapeSql|mysql_real_escape_string|mysqli_real_escape_string|quoteSql|SqlLiteral\.Escape)\s*\(", re.I),
    "shell": re.compile(r"\b(?:shlex\.quote|escapeshellarg|shellescape|ShellEscape|quoteCommandArg)\s*\(", re.I),
    "path": re.compile(r"\b(?:secure_filename|sanitize_filename|path\.basename|filepath\.Base|Path\.GetFileName)\s*\(", re.I),
    "url": re.compile(r"\b(?:sanitizeUrl|validateUrl|allowlistedUrl|safeRedirectUrl|is_safe_url)\s*\(", re.I),
}
_TRANSPARENT_CALLS = frozenset({
    "str", "String", "String.valueOf", "fmt.Sprintf", "sprintf", "decodeURIComponent", "decodeURI",
    "urllib.parse.unquote", "unquote", "trim", "strip", "lstrip", "rstrip", "lower", "upper",
    "toLowerCase", "toUpperCase", "toString", "String.Trim", "strings.TrimSpace", "strings.ToLower",
    "strings.ToUpper", "bytes.NewBufferString",
})
_CALL_WORD = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*(?:(?:\.|::|->)[A-Za-z_$][\w$]*)*)\s*\(")
_BRANCH_EXPR = re.compile(r"(?<!\?)\?(?![.?])|\|\||&&|\bif\b[\s\S]*\belse\b|\bcase\b|\bswitch\b")


def _param_name(match):
    return next((g for g in match.groups() if g), None)


def _sources(lang, raw, code, line):
    out = []
    for kind, rx in _SOURCE_RX.get(lang, ()):
        for m in rx.finditer(raw):
            # The request object/call head must be active code.  Its quoted parameter may of course be blank
            # in ``code``; checking the first word rejects examples embedded in comments and strings.
            active = code[m.start():min(len(code), m.start() + 24)]
            if not re.search(r"[A-Za-z_$]", active):
                continue
            name = _param_name(m)
            if name:
                out.append({"kind": kind, "param": name, "line": line, "expression": m.group(0)[:200]})
    return out


def _var_rx(lang, name):
    return re.compile((r"\$" if lang == "php" else r"(?<![\w$])") + re.escape(name) + r"(?![\w$])")


def _call_names(code):
    return [m.group(1).replace("->", ".").replace("::", ".") for m in _CALL_WORD.finditer(code)]


def _eval_expr(lang, raw, code, line, states, advance=True):
    """A proved state for one expression, or None.  Unknown function calls are hard declines."""
    if len(raw) > STATIC_MAX_CALL or _BRANCH_EXPR.search(code):
        return None
    direct = _sources(lang, raw, code, line)
    refs = []
    for name, state in states.items():
        if _var_rx(lang, name).search(code):
            refs.append((name, state))
    # A competing alias, or two independently named sources, is intentionally not guessed through.
    origins = direct + [s["source"] for _, s in refs]
    uniq = {(x["kind"], x["param"], x["line"]) for x in origins}
    if len(uniq) != 1 or len(refs) + len(direct) != 1:
        return None
    source = origins[0]
    base = refs[0][1] if refs else None
    depth = (base["depth"] + (1 if advance else 0)) if base else 0
    if depth > STATIC_MAX_CHAIN:
        return None
    sanitizers = set(base["sanitizers"] if base else ())
    used_sanitizer_names = []
    for context, rx in _SANITIZERS.items():
        if rx.search(raw):
            sanitizers.add(context)
            used_sanitizer_names.append(context)
    calls = _call_names(code)
    allowed_source_fragments = ("request", "req", "params", "r.URL.Query", "URL.Query", "r.FormValue",
                                "r.PostFormValue", "c.Query", "ctx.Query", "c.QueryParam", "ctx.QueryParam",
                                "c.Param", "ctx.Param", "c.PostForm", "ctx.PostForm", "mux.Vars",
                                "chi.URLParam", "query.get", "input.get", "getParameter", "getHeader")
    sanitizer_heads = {m.group(0).split("(", 1)[0].strip().replace("->", ".").replace("::", ".")
                       for rx in _SANITIZERS.values() for m in rx.finditer(raw)}
    transforms = []
    for call in calls:
        leaf = call.split(".")[-1]
        if call in _TRANSPARENT_CALLS or leaf in _TRANSPARENT_CALLS:
            transforms.append(call)
            continue
        php_source_call = bool(direct) and lang == "php" and (
            re.match(r"\$(?:[A-Za-z_]*request|req)\.", call, re.I) is not None or
            call.startswith(("$this.input.", "$this.request.")))
        if any(call.startswith(x) or call.endswith(x) for x in allowed_source_fragments) or php_source_call or call in {
                "Get", "get", "input", "query", "post", "file", "header", "getQuery", "getData",
                "getGet", "getPost", "fetch", "URLParam", "FormValue", "PostFormValue"}:
            continue
        if call in sanitizer_heads or leaf in {x.split(".")[-1] for x in sanitizer_heads}:
            continue
        # Language casts and constructor-like string conversions are transparent; every other helper could
        # validate, select, decode, or replace the value and therefore ends the proof.
        if leaf in ("String", "str"):
            transforms.append(call)
            continue
        return None
    chain = list(base["chain"] if base else [])
    return {"source": source, "depth": depth, "chain": chain, "sanitizers": frozenset(sanitizers),
            "transforms": list(base["transforms"] if base else []) + transforms,
            "sanitizer_steps": list(base["sanitizer_steps"] if base else []) + used_sanitizer_names}


def _assignment(lang, raw, code):
    patterns = {
        "python": r"^\s*([A-Za-z_]\w*)\s*=(?!=)\s*([\s\S]*)$",
        "js": r"^\s*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([\s\S]*)$",
        "php": r"^\s*\$([A-Za-z_]\w*)\s*=(?![=>])\s*([\s\S]*)$",
        "ruby": r"^\s*([A-Za-z_]\w*)\s*=(?!=|>)\s*([\s\S]*)$",
        "go": r"^\s*(?:var\s+)?([A-Za-z_]\w*)\s*(?::=|=(?!=))\s*([\s\S]*)$",
        "java": r"^\s*(?:(?:final\s+)?[A-Za-z_$][\w$<>,.?\[\]]*\s+)?([A-Za-z_$][\w$]*)\s*=(?!=)\s*([\s\S]*)$",
        "cs": r"^\s*(?:(?:var|[A-Za-z_$][\w$<>,.?\[\]]*)\s+)?([A-Za-z_$][\w$]*)\s*=(?!=|>)\s*([\s\S]*)$",
    }
    m = re.match(patterns.get(lang, r"(?!x)x"), code.strip().rstrip(";"))
    if not m:
        return None
    # Offsets come from code; raw is the same length.  Locate the RHS in the unstripped original instead of
    # trusting a separately matched literal/comment string.
    eq = re.search(r":=|=(?!=|>)", code)
    return (m.group(1), raw[eq.end():].strip().rstrip(";"), code[eq.end():].strip().rstrip(";")) if eq else None


def _logical_statements(raw, comments, mask, h):
    """Bounded line-oriented statements.  Parenthesised multiline calls/assignments stay together."""
    out, pos = [], h["start"]
    while pos < h["end"] and len(out) < STATIC_MAX_STATEMENTS:
        nl = raw.find("\n", pos, h["end"])
        stop = h["end"] if nl < 0 else nl + 1
        start, depth = pos, 0
        # Function/body braces span many statements; only parentheses/brackets make a physical newline a
        # continuation.  Object literals that cross lines are conservatively not propagated.
        for c in mask[start:stop]:
            depth += 1 if c in "([" else -1 if c in ")]" else 0
        while depth > 0 and stop < h["end"] and stop - start < STATIC_MAX_CALL:
            nl = raw.find("\n", stop, h["end"])
            nxt = h["end"] if nl < 0 else nl + 1
            for c in mask[stop:nxt]:
                depth += 1 if c in "([" else -1 if c in ")]" else 0
            stop = nxt
        if comments[start:stop].strip():
            cuts, parens = [start], 0
            # A minified handler may put source, aliases and sink on one physical line.  Split only a
            # top-level semicolon; semicolons in `for (...)` and strings are masked/nested and stay put.
            if "\n" not in comments[start:stop] or ";" in mask[start:stop]:
                for absolute in range(start, stop):
                    c = mask[absolute]
                    parens += 1 if c in "([" else -1 if c in ")]" else 0
                    if c == ";" and parens == 0:
                        cuts.append(absolute + 1)
            cuts.append(stop)
            for a, b in zip(cuts, cuts[1:]):
                if comments[a:b].strip():
                    out.append({"start": a, "end": b, "line": _line_at(raw, a),
                                "raw": comments[a:b], "code": mask[a:b]})
        pos = max(stop, pos + 1)
    return out


def _control_lines(raw, mask, h, statements, lang):
    """(branched lines, dead lines) for simple, unambiguous control flow."""
    branch, dead = set(), set()
    if lang == "python":
        base = h.get("indent", 0) + 4
        dead_from = None
        controls = []
        for st in statements:
            first = st["code"].splitlines()[0] if st["code"].splitlines() else ""
            indent = len(first) - len(first.lstrip(" \t"))
            controls = [x for x in controls if x < indent]
            if re.match(r"\s*(?:if|elif|else|for|while|try|except|finally|with|match|case)\b", first):
                controls.append(indent)
            if controls or indent > base:
                branch.add(st["line"])
            if dead_from is not None:
                dead.add(st["line"])
            elif indent <= base and re.match(r"\s*(?:return|raise)\b", first):
                dead_from = st["line"] + 1
        return branch, dead
    depth, control_depths, dead_depth = 0, [], None
    for st in statements:
        c = st["code"]
        while control_depths and control_depths[-1] > depth:
            control_depths.pop()
        if control_depths:
            branch.add(st["line"])
        if dead_depth is not None and depth == dead_depth:
            dead.add(st["line"])
        if re.search(r"\b(?:if|else|for|while|switch|case|catch|try)\s*(?:\(|\{)", c):
            control_depths.append(depth + 1)
            branch.add(st["line"])
        if dead_depth is None and not control_depths and re.match(r"\s*(?:return|throw|panic\s*\()", c):
            dead_depth = depth
        depth += c.count("{") - c.count("}")
        if dead_depth is not None and depth < dead_depth:
            dead_depth = None
    return branch, dead


def _handler_param_states(lang, h):
    states = {}
    args = h.get("args") or ""
    rows = []
    if lang == "python":
        for part in re.split(r",(?![^()]*\))", args):
            m = re.match(r"\s*([A-Za-z_]\w*)\s*(?::[^=,]+)?(?:=\s*(Query|Path|Form|Body|Header|Cookie)\s*\(([^)]*)\))?", part)
            if m and m.group(2):
                alias = re.search(r"\balias\s*=\s*[\"']([^\"']+)", m.group(3) or "")
                rows.append((m.group(1), alias.group(1) if alias else m.group(1), m.group(2).lower()))
    elif lang == "java":
        for m in re.finditer(r"@(RequestParam|PathVariable|RequestHeader|CookieValue|QueryParam|FormParam|HeaderParam|CookieParam|PathParam)\s*(?:\(\s*(?:value\s*=\s*)?[\"']([^\"']+)[\"'][^)]*\))?\s+[\w<>,.?\[\]]+\s+([A-Za-z_]\w*)", args):
            rows.append((m.group(3), m.group(2) or m.group(3), m.group(1)))
    elif lang == "cs":
        for m in re.finditer(r"(?:\[(?:FromQuery|FromRoute|FromForm|FromHeader)[^\]]*\]\s*)?[\w<>,.?\[\]]+\s+([A-Za-z_]\w*)", args):
            if re.search(r"\[(?:FromQuery|FromRoute|FromForm|FromHeader)", m.group(0)):
                rows.append((m.group(1), m.group(1), "binding"))
    for var, param, kind in rows:
        source = {"kind": kind, "param": param, "line": h["line"], "expression": var}
        states[var] = {"source": source, "depth": 0, "chain": [], "sanitizers": frozenset(),
                       "transforms": [], "sanitizer_steps": []}
        h["params"].add(param)
        h["param_vars"][var] = param
    return states


def _destructure(lang, raw, code, line):
    if lang != "js":
        return []
    m = re.match(r"\s*(?:const|let|var)\s*\{([^}]{1,1000})\}\s*=\s*(?:req|request)\.(query|body|params|cookies|headers)\b", raw, re.S)
    if not m or not re.search(r"\b(?:req|request)\.", code):
        return []
    out = []
    for part in m.group(1).split(","):
        key, _, alias = part.partition(":")
        key = key.split("=")[0].strip()
        alias = (alias or key).split("=")[0].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", key) and re.fullmatch(r"[A-Za-z_$][\w$]*", alias):
            out.append((alias, key, m.group(2)))
    return out


def _sink_arg(st, match, mode):
    raw, code = st["raw"], st["code"]
    if mode == "rhs":
        eq = code.find("=", match.end())
        return (raw[eq + 1:], code[eq + 1:]) if eq >= 0 else ("", "")
    if mode == "rest":
        return raw[match.end():].split(";", 1)[0], code[match.end():].split(";", 1)[0]
    op = match.end() - 1 if match.end() and code[match.end() - 1:match.end()] == "(" else code.find("(", match.start(), match.end() + 2)
    if op < 0 and mode == "call_optional":
        return raw[match.end():].split(";", 1)[0], code[match.end():].split(";", 1)[0]
    end = _paren_end(code, op)
    if end is None:
        return "", ""
    if mode == "all":
        return raw[op + 1:end - 1], code[op + 1:end - 1]
    aa = _args(raw, code, op, end)
    return (aa[0][2], code[aa[0][0]:aa[0][1]]) if aa else ("", "")


def _analyze_handler(short, lang, raw, comments, mask, h, taint):
    statements = _logical_statements(raw, comments, mask, h)
    if len(statements) >= STATIC_MAX_STATEMENTS:
        return False, set()
    branches, dead = _control_lines(raw, mask, h, statements, lang)
    states, assigned, killed = _handler_param_states(lang, h), set(), set()
    sanitized_sites = set()
    for st in statements:
        if st["line"] in dead:
            continue
        # Java/Spring annotations are declarations, not statements whose text may look like a call.
        if st["code"].lstrip().startswith("@"):
            continue
        for alias, param, kind in _destructure(lang, st["raw"], st["code"], st["line"]):
            if alias in assigned or st["line"] in branches:
                states.pop(alias, None)
                killed.add(alias)
                continue
            source = {"kind": kind, "param": param, "line": st["line"], "expression": alias}
            states[alias] = {"source": source, "depth": 0, "chain": [{"line": st["line"], "var": alias, "op": "source"}],
                             "sanitizers": frozenset(), "transforms": [], "sanitizer_steps": []}
            h["params"].add(param)
            assigned.add(alias)
        assignment = _assignment(lang, st["raw"], st["code"])
        if assignment:
            name, eraw, ecode = assignment
            previous = states.get(name)
            # A second write is a kill even when its RHS looks transparent.  This is deliberately stricter
            # than normal data flow and prevents branch/order guesses in minified challenge code.
            if name in assigned or name in killed or st["line"] in branches:
                states.pop(name, None)
                killed.add(name)
            else:
                value = _eval_expr(lang, eraw, ecode, st["line"], states)
                assigned.add(name)
                if value:
                    value["chain"] = list(value["chain"]) + [{"line": st["line"], "var": name,
                                                               "op": "source" if value["depth"] == 0 else "alias"}]
                    states[name] = value
                    h["params"].add(value["source"]["param"])
                else:
                    states.pop(name, None)
            del previous
        for sid, family, context, pattern, mode in _FLOW_SINKS.get(lang, ()):
            for m in re.finditer(pattern, st["code"], re.I):
                arg_raw, arg_code = _sink_arg(st, m, mode)
                value = _eval_expr(lang, arg_raw, arg_code, st["line"], states, advance=False)
                if not value:
                    continue
                if context in value["sanitizers"]:
                    sanitized_sites.add((st["line"], family))
                    continue
                if len(taint) >= STATIC_MAX_FINDINGS:
                    return False, sanitized_sites
                source = value["source"]
                h["params"].add(source["param"])
                aliases = [x["var"] for x in value["chain"]]
                route_rows = [{"method": r.get("method"), "path": r.get("path")} for r in h["routes"]]
                row = {"file": short, "line": st["line"], "sink": sid, "family": family,
                       "context": context, "code": st["raw"].strip()[:240], "handler": h["name"],
                       "routes": route_rows, "params": sorted(h["params"]), "reads": [source["param"]],
                       "var": aliases[-1] if aliases else None, "from_line": source["line"],
                       "from_code": source["expression"][:240], "aliases": aliases,
                       "transforms": value["transforms"], "sanitizers": sorted(value["sanitizers"]),
                       "provenance": [{"kind": "source", **source}] + list(value["chain"]) +
                                     [{"kind": "sink", "line": st["line"], "sink": sid, "context": context}]}
                key = (row["file"], row["line"], row["sink"], tuple(row["reads"]), row["handler"])
                if not any((x["file"], x["line"], x["sink"], tuple(x["reads"]), x["handler"]) == key for x in taint):
                    taint.append(row)
    return True, sanitized_sites


def _active_direct_sinks(short, lang, lines, masks, sinks):
    """Drop legacy matches manufactured wholly by a comment/string; retain every real legacy match."""
    _, code = masks
    code_lines = code.splitlines()
    keep = []
    by_id = {(sid, fam): rx for sid, fam, slang, rx in _SINKS if slang == lang}
    for s in sinks:
        if s.get("file") != short:
            keep.append(s)
            continue
        line = lines[s["line"] - 1] if 0 < s["line"] <= len(lines) else ""
        masked = code_lines[s["line"] - 1] if 0 < s["line"] <= len(code_lines) else ""
        rx = by_id.get((s.get("sink"), s.get("family")))
        matches = list(rx.finditer(line)) if rx else []
        if any(re.search(r"[A-Za-z_$]", masked[m.start():min(len(masked), m.end())]) for m in matches):
            keep.append(s)
    sinks[:] = keep


def _active_legacy_routes(short, lang, lines, code, routes):
    code_lines, keep = code.splitlines(), []
    for r in routes:
        if r.get("file") != short:
            keep.append(r)
            continue
        n = r.get("line") or 0
        line = code_lines[n - 1] if 0 < n <= len(code_lines) else ""
        method = str(r.get("method") or "").lower()
        active = {
            "python": re.search(r"@\s*[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\.(?:route|get|post|put|delete|patch|api_route|websocket)\s*\(", line),
            "js": re.search(r"\.\s*(?:get|post|put|delete|patch|all|use)\s*\(", line),
            "cs": re.search(r"\b(?:HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route|MapGet|MapPost|MapPut|MapDelete|MapPatch)\b", line),
        }.get(lang, True)
        del method
        if active:
            keep.append(r)
    routes[:] = keep


def _static_review(short, lang, text, lines, routes, sinks, taint, budget):
    """Add route depth and proved local flows for one source file.  False/over-budget means fail closed."""
    if budget[0] < 0:
        return
    budget[0] += len(text) * 3
    if budget[0] > STATIC_MAX_WORK:
        budget[0] = -1
        taint[:] = []
        return
    comments, mask = _source_masks(text, lang)
    _active_direct_sinks(short, lang, lines, (comments, mask), sinks)
    _active_legacy_routes(short, lang, lines, mask, routes)
    if lang in ("python", "js"):
        # The compositional reader below is a strict superset of the old one-line Express reader and knows
        # mounts/prefixes. Keeping both would expose `/x` and `/api/x` as two endpoints for one registration.
        routes[:] = [r for r in routes if r.get("file") != short]
    handlers = _find_functions(lang, text, mask)
    if len(handlers) >= STATIC_MAX_HANDLERS:
        budget[0] = -1
        taint[:] = []
        return
    discover = {"python": _python_routes, "js": _js_routes, "java": _java_routes, "ruby": _ruby_routes,
                "go": _go_routes, "php": _php_routes, "cs": _cs_routes}.get(lang)
    if discover:
        discover(short, text, comments, mask, handlers)
    if lang == "js":
        # `app.use('/prefix', router)` is a mount, not an endpoint.  The legacy single-line reader exposed
        # it as a route; the composed child routes above supersede that bookkeeping row.
        routes[:] = [r for r in routes if r.get("file") != short or not str(r.get("handler") or "").startswith("use ")]
    # Attach legacy routes to the strongest matching handler, then add newly recognised rows.
    file_routes = [r for r in routes if r.get("file") == short]
    for h in handlers:
        for r in file_routes:
            if r.get("handler") == h["name"] and not any((x.get("method"), x.get("path")) == (r.get("method"), r.get("path")) for x in h["routes"]):
                h["routes"].append(r)
        for r in h["routes"]:
            for groups in re.findall(r":([A-Za-z_]\w*)|\{([A-Za-z_]\w*)(?::[^}]*)?\}|<(?:(?:\w+):)?([A-Za-z_]\w*)>", str(r.get("path") or "")):
                h["params"].add(next(x for x in groups if x))
        for r in h["routes"]:
            _dedup_route(routes, r)
    # Prefer the narrowest extent when an inline route is nested in a module/function extent.
    handlers = sorted(handlers, key=lambda h: (h["end"] - h["start"], h["start"]))
    sanitized = set()
    for h in handlers:
        if len(h.get("params", ())) > STATIC_MAX_VARS:
            budget[0] = -1
            taint[:] = []
            return
        ok, safe = _analyze_handler(short, lang, text, comments, mask, h, taint)
        sanitized |= safe
        if not ok:
            budget[0] = -1
            taint[:] = []
            return
        # Handler-local reads/routes improve legacy sink rows without changing their shape.
        for r in h["routes"]:
            r["reads"] = sorted(set(r.get("reads") or ()) | h["params"])
        for s in sinks:
            if s.get("file") == short and _line_at(text, h["start"]) <= s["line"] <= _line_at(text, h["end"]):
                s["handler"] = h["name"]
                s["routes"] = [{"method": r.get("method"), "path": r.get("path")} for r in h["routes"]]
                s["params"] = sorted(set(s.get("params") or ()) | h["params"])
    if sanitized:
        sinks[:] = [s for s in sinks if s.get("file") != short or (s.get("line"), s.get("family")) not in sanitized]


def _link_framework_routes(routes, sinks, taint):
    """Resolve the one safe cross-file relation: a declarative Rails controller#action route."""
    rails = [r for r in routes if isinstance(r.get("handler"), str) and "#" in r["handler"]]
    for finding in list(sinks) + list(taint):
        if not str(finding.get("file", "")).lower().endswith("_controller.rb"):
            continue
        controller = Path(finding["file"]).stem.removesuffix("_controller")
        own = [r for r in rails if r["handler"] == f"{controller}#{finding.get('handler')}"]
        if own:
            finding["routes"] = [{"method": r.get("method"), "path": r.get("path")} for r in own]
    pages = {r.get("file"): r for r in routes if r.get("method") is None and
             str(r.get("file") or "").lower().endswith((".php", ".phtml", ".inc", ".jsp", ".aspx", ".ashx", ".asp"))}
    for finding in list(sinks) + list(taint):
        if not finding.get("routes") and finding.get("file") in pages:
            r = pages[finding["file"]]
            finding["routes"] = [{"method": r.get("method"), "path": r.get("path")}]


# ---- one delivery -----------------------------------------------------------------------------------------

def _unique(files) -> list:
    """[(name, bytes)] once per file (tools/run.py files a member under two names, one bytes object)."""
    seen, out = set(), []
    for key in sorted(files, key=lambda k: (ARROW not in k, k)):
        data = files[key]
        if not isinstance(data, (bytes, bytearray)) or id(data) in seen:
            continue
        seen.add(id(data))
        out.append((key, bytes(data) if isinstance(data, bytearray) else data))
    return sorted(out, key=lambda kv: kv[0])


def _is_container(data) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06") or data[:2] == b"\x1f\x8b" or data[:6] == b"7z\xbc\xaf\x27\x1c"


_PCAP_MAGIC = frozenset((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
                         b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"))
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_HTTP_WIRE = re.compile(
    rb"(?:^|\r\n)(?:(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND|PROPPATCH|MKCOL|MOVE|COPY|LOCK|UNLOCK)\s+\S+\s+HTTP/1\.[01]|HTTP/1\.[01]\s+\d{3}\b)")
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def _looks_capture(data) -> bool:
    """Cheap exact magic check used by signals; parsing remains in the bounded bridge below."""
    return isinstance(data, (bytes, bytearray)) and (
        bytes(data[:4]) in _PCAP_MAGIC
        or (bytes(data[:4]) == _PCAPNG_MAGIC
            and bytes(data[8:12]) in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d")))


def _network_reader():
    """Load the sibling pure-Python capture reader by path without changing import precedence."""
    global _NETWORK_READER_MOD
    if _NETWORK_READER_MOD is False:
        return None
    if _NETWORK_READER_MOD is None:
        try:
            import importlib.util
            path = HERE / "network.py"
            # Reuse an already loaded copy when lane_match imported it first.
            for module in list(sys.modules.values()):
                if Path(getattr(module, "__file__", "") or ".").resolve() == path:
                    _NETWORK_READER_MOD = module
                    break
            else:
                name = "csctf_web_evidence_network_reader"
                spec = importlib.util.spec_from_file_location(name, path)
                if spec is None or spec.loader is None:
                    raise ImportError("network reader loader unavailable")
                module = importlib.util.module_from_spec(spec)
                sys.modules[name] = module
                spec.loader.exec_module(module)
                _NETWORK_READER_MOD = module
        except Exception:
            _NETWORK_READER_MOD = False
            return None
    return _NETWORK_READER_MOD


def _pcap_headers(stream, message, *, response=False):
    """(one-value headers, Set-Cookie values), or None on parser ambiguity.

    The network reader deliberately has permissive forensic parsing.  The Web
    bridge is stricter: every header line must survive byte-for-byte parsing,
    duplicate fields are refused (except independent Set-Cookie values), and
    ambiguous framing never becomes Web evidence.
    """
    try:
        start = int(message.offset)
        hend = stream.find(b"\r\n\r\n", start)
        if start < 0 or hend < 0 or hend - start > 256 * 1024:
            return None
        lines = stream[start:hend].split(b"\r\n")
        if (not lines or not lines[0]
                or any(ch < 0x20 or ch > 0x7e for ch in lines[0])):
            return None
        parsed = []
        for raw in lines[1:]:
            name, sep, value = raw.partition(b":")
            if (not sep or not _HEADER_NAME.fullmatch(name) or raw[:1] in b" \t"
                    or any(ch < 32 and ch != 9 or ch == 127 for ch in value)):
                return None
            parsed.append((name.decode("ascii").lower(), value.decode("latin-1").strip()))
        if len(parsed) != len(message.headers or ()):
            return None
        headers, cookies, seen = {}, [], set()
        for name, value in parsed:
            if name == "set-cookie" and response:
                cookies.append(value)
                continue
            if name in seen:
                return None
            seen.add(name)
            headers[name] = value
        transfer = headers.get("transfer-encoding", "").strip().lower()
        length = headers.get("content-length")
        if transfer and transfer != "chunked":
            return None
        if transfer and length is not None:
            return None
        if length is not None and not re.fullmatch(r"[0-9]{1,20}", length):
            return None
        if headers.get("content-encoding", "").strip().lower() not in ("", "identity"):
            return None
        return headers, cookies
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return None


def _pcap_strict_chunked(stream, message):
    """Validate one raw chunked body independently of network.py's forensic decoder.

    The sibling network reader intentionally salvages malformed captures.  Web
    evidence cannot: skipped chunk delimiters or malformed trailers would let a
    parser-dependent body become a proof.  Return true only when the strict raw
    grammar consumes exactly the message bytes and decodes the same body length.
    """
    try:
        start = stream.find(b"\r\n\r\n", int(message.offset))
        if start < 0:
            return False
        pos = start + 4
        decoded = chunks = trailers = 0
        trailer_start = None
        while chunks < MAX_PCAP_HTTP_CHUNKS:
            end = stream.find(b"\r\n", pos)
            if end < 0 or end - pos > 4096:
                return False
            line = stream[pos:end]
            size_text, separator, extension = line.partition(b";")
            if not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", size_text):
                return False
            if separator and (not extension or any(ch < 32 or ch > 126 for ch in extension)):
                return False
            size = int(size_text, 16)
            pos = end + 2
            if size == 0:
                trailer_start = pos
                break
            if size > MAX_PCAP_HTTP_BODY - decoded or pos + size + 2 > len(stream):
                return False
            if stream[pos + size:pos + size + 2] != b"\r\n":
                return False
            decoded += size
            chunks += 1
            pos += size + 2
        if trailer_start is None:
            return False
        while trailers <= 128 and pos - trailer_start <= 64 * 1024:
            end = stream.find(b"\r\n", pos)
            if end < 0:
                return False
            if end == pos:
                pos += 2
                return (pos == int(message.end)
                        and decoded == len(bytes(message.body)))
            raw = stream[pos:end]
            name, separator, value = raw.partition(b":")
            if (not separator or not _HEADER_NAME.fullmatch(name) or raw[:1] in b" \t"
                    or name.lower() in (b"content-length", b"transfer-encoding", b"host")
                    or any(ch < 32 and ch != 9 or ch == 127 for ch in value)):
                return False
            trailers += 1
            pos = end + 2
        return False
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False


def _pcap_request_target(method, target):
    """Accept only an unambiguous HTTP request-target before URL decoding."""
    try:
        raw = str(target).encode("ascii", "strict")
        if (not raw or len(raw) > 16_384 or any(ch < 0x21 or ch > 0x7e for ch in raw)
                or b"#" in raw or b"\\" in raw
                or re.search(rb"%(?![0-9A-Fa-f]{2})", raw)):
            return False
        if raw == b"*":
            return method == "OPTIONS"
        parts = urlsplit(raw.decode("ascii"))
        if parts.fragment or parts.username is not None or parts.password is not None:
            return False
        # Accessing these properties forces malformed bracketed hosts and
        # ports through urllib's validation instead of retaining raw text.
        _host, _port = parts.hostname, parts.port
        if parts.scheme:
            return parts.scheme.lower() in ("http", "https") and bool(parts.netloc and _host)
        return not parts.netloc and raw.startswith(b"/")
    except (TypeError, ValueError, UnicodeError):
        return False


def _pcap_http_events(name, data):
    """(events, searchable request/response texts) from one complete capture.

    This is intentionally narrower than a generic packet-to-HAR converter.  It
    accepts only complete, gap/conflict-free two-way HTTP/1.x connections that
    begin at a captured handshake, consume both reassembled directions exactly,
    have unambiguous headers/framing, and stay inside the capture/body limits.
    Any defect withdraws the whole capture from the Web reader so an ignored
    request can never make a different payload look unique.
    """
    if not _looks_capture(data) or len(data) > MAX_PCAP_BYTES:
        return None
    network = _network_reader()
    if network is None:
        return None
    try:
        cap = network.Capture(bytes(data), name, limit=network.MAX_PACKETS)
        if cap.damaged or cap.truncated:
            return None
        out, searchable, saw_http = [], [], False
        for conn in cap.conns():
            client = conn.c.data if conn.c is not None else b""
            server = conn.s.data if conn.s is not None else b""
            if not (_HTTP_WIRE.search(client) or _HTTP_WIRE.search(server)):
                continue
            saw_http = True
            if (conn.c is None or conn.s is None or not conn.handshake
                    or conn.c.isn is None or conn.s.isn is None
                    or not conn.c.sound or not conn.s.sound):
                return None
            reqs = network._http_messages(client, network._REQ)
            resps = network._http_messages(
                server, network._RESP,
                heads=[row.first[0] == "HEAD" for row in reqs])
            if (not reqs or len(reqs) != len(resps)
                    or int(reqs[-1].end) != len(client)
                    or int(resps[-1].end) != len(server)):
                return None
            for index, (request, response) in enumerate(zip(reqs, resps), 1):
                if request.complete is not True or response.complete is not True:
                    return None
                request_headers = _pcap_headers(client, request)
                response_headers = _pcap_headers(server, response, response=True)
                if request_headers is None or response_headers is None:
                    return None
                req_headers, _ = request_headers
                resp_headers, set_cookies = response_headers
                if len(request.body) > MAX_PCAP_HTTP_BODY or len(response.body) > MAX_PCAP_HTTP_BODY:
                    return None
                method, target = request.first[0], request.first[1]
                if method not in _METHODS or not _pcap_request_target(method, target):
                    return None
                if (req_headers.get("transfer-encoding") == "chunked"
                        and not _pcap_strict_chunked(client, request)):
                    return None
                status = int(response.first[1])
                response_has_no_body = method == "HEAD" or status in (101, 204, 304)
                if (not response_has_no_body
                        and resp_headers.get("transfer-encoding") == "chunked"
                        and not _pcap_strict_chunked(server, response)):
                    return None
                ev = _event(name, index, "pcap_http")
                ev["ip"], ev["method"] = conn.client, method
                _set_target(ev, target)
                ev["host"] = req_headers.get("host") or ev["host"]
                ev["headers"] = req_headers
                ev["ua"], ev["referer"] = req_headers.get("user-agent"), req_headers.get("referer")
                ev["body"] = bytes(request.body).decode("latin-1") if request.body else None
                ev["status"] = status
                ev["size"] = len(response.body)
                ts = cap.stream_time(conn.c, request.offset)
                if ts is not None:
                    try:
                        ev["ts"] = dt.datetime.fromtimestamp(ts / 1_000_000_000, UTC)
                        ev["ts_raw"] = ev["ts"].isoformat()
                    except (OverflowError, OSError, ValueError):
                        ev["ts"], ev["ts_raw"] = None, str(ts)
                ev["extra"]["server_ip"] = conn.server
                if resp_headers:
                    ev["extra"]["response_headers"] = resp_headers
                if set_cookies:
                    ev["extra"]["set_cookie"] = set_cookies
                response_text = text_of(response.body)
                if response_text is not None:
                    ev["extra"]["response_body"] = response_text
                out.append(ev)
                pieces = [target, *(f"{key}: {value}" for key, value in req_headers.items())]
                if ev["body"]:
                    pieces.append(ev["body"])
                pieces.extend(f"{key}: {value}" for key, value in resp_headers.items())
                pieces.extend(set_cookies)
                if response_text:
                    pieces.append(response_text)
                searchable.append("\n".join(pieces))
                if len(out) > MAX_EVENTS:
                    return None
        return (out, searchable) if saw_http else ([], [])
    except Exception:
        return None


class Evidence:
    """Everything this module reads from one delivery's files ({name: bytes}), built once:
    logs {file: [event]}, events (all, by time when every event has one, else by file and line),
    findings, tokens, cookies, source."""

    def __init__(self, files, only=None):
        self.files = files
        self.logs, self.kinds = {}, {}
        self._log_text, self._complete = {}, {}
        texts = []
        for name, data in _unique(files):
            short = name.split(ARROW)[-1]
            if only is not None and Path(short).name != Path(only).name:
                continue
            if _looks_capture(data):
                bridged = _pcap_http_events(short, data)
                if bridged is not None:
                    evs, wire_texts = bridged
                    if evs:
                        self.logs[short], self.kinds[short] = evs, "pcap_http"
                        # The bridge admits the capture only after every HTTP
                        # direction and message was consumed without ambiguity.
                        self._complete[short] = True
                        texts.extend((short + "#http", text) for text in wire_texts)
                continue
            if _is_container(data) or len(data) > MAX_LOG:
                continue
            kind = log_kind(data, short)
            if kind:
                evs = read_log(data, short)
                if evs:
                    self.logs[short], self.kinds[short] = evs, evs[0]["kind"]
            text = text_of(data)
            if text is not None:
                texts.append((short, text))
                if short in self.logs:
                    self._log_text[short] = text
        events = [e for evs in self.logs.values() for e in evs]
        if events and all(e["ts"] is not None for e in events):
            events.sort(key=lambda e: (_sort_key(e), e["src"], e["line"]))
        self.events = events
        self.timed = bool(events) and all(e["ts"] is not None for e in events)
        self.findings = findings(events) if events else []
        self.tokens, self.cookies = [], []
        self.token_parse_incomplete = False
        self.cookie_parse_incomplete = False
        seen = set()
        for short, text in texts:
            if "eyJ" not in text and "eJ" not in text and "%65%79" not in text.lower() and "=" not in text:
                continue
            for token in _jwt_candidates(text):
                if token in seen:
                    continue
                seen.add(token)
                decoded = decode_jwt(token)
                if decoded is None:
                    self.token_parse_incomplete = True
                else:
                    self.tokens.append({**decoded, "file": short})
            for c in find_cookies(text):
                if c["token"] not in seen:
                    seen.add(c["token"])
                    self.cookies.append({**c, "file": short})
            if _has_rejected_cookie_json(text):
                self.cookie_parse_incomplete = True
        self._source = None

    @property
    def source(self):
        if self._source is None:
            self._source = read_source(self.files)
        return self._source

    def complete(self, short) -> bool:
        """True when every record the log file holds was read as an event (see rows_expected)."""
        if short not in self._complete:
            text = self._log_text.get(short)
            want = rows_expected(text, self.kinds.get(short)) if text is not None else None
            self._complete[short] = want is not None and want == len(self.logs.get(short) or [])
        return self._complete[short]

    def payload_findings(self, family=None) -> list:
        out = [f for f in self.findings if f["family"] in PAYLOAD_FAMILIES]
        if not out:
            out = [f for f in self.findings if f["family"] in ("brute_force", "enumeration")]
        return [f for f in out if family is None or f["family"] == family or family in f["families"]]

    def families(self) -> list:
        return sorted({f["family"] for f in self.payload_findings()})


def client_constants(files) -> dict:
    """The User-Agent and URL constants a shipped client hard-codes (B-131), over one delivery
    ({name: bytes}, as load_paths builds it): {"user_agents": [{value, path, offset, how, stock,
    ...}], "urls": [{value, path, offset, near_ua, ...}], ...}. A `stock` User-Agent is a library or
    browser one; a URL is `near_ua` when it sits beside a custom User-Agent in the same file. Read
    offline (ctf.clientreplay.harvest_blobs); nothing here sends a request: replaying the constants
    is `python -m ctf client-replay run`, under the event's scope guard."""
    from ctf import clientreplay
    return clientreplay.harvest_blobs(files).to_dict()


def live_target(attempt):
    """The URL or host a start response points at (target, target_url, url, host, endpoint, instance,
    service, connection), or None. A challenge download link is not a target."""
    if not isinstance(attempt, dict):
        return None
    for key, v in attempt.items():
        if str(key).lower() in ("target", "target_url", "targets", "url", "host", "endpoint", "instance", "service", "connection",
                                 "connection_info", "target_host", "vpn"):
            for item in (v if isinstance(v, list) else [v]):
                if isinstance(item, dict):
                    item = item.get("url") or item.get("host") or item.get("address")
                if isinstance(item, str) and item.strip() and "/game-master/download" not in item and "op=artifact" not in item \
                        and re.search(r"://|^[\w.-]+:\d{2,5}$|^\d+\.\d+\.\d+\.\d+", item.strip()):
                    return item.strip()
    return None


# ---- OWASP Top 10 coverage ----------------------------------------------------------------------------------
#
# Request-payload families stay in FAMILY_RX. These detectors read the OWASP classes that are
# header/behaviour/token/source facts instead: broken access control (A01), security misconfiguration
# (A05), vulnerable components (A06), authentication abuse (A07), cryptographic failures in a JWT (A02),
# and Flask debug mode. Every one is author vocabulary, so the solver returns it UNSURE
# (labels.pick) and never a plain class; which client is the actor is a human call, so no plain IP is
# ever returned from here. Open redirect (A03/CWE-601, request-derived only) and Flask debug in source
# ride the source-review path through SINKS. `answer()` calls these only when the question NAMES the
# class and the bytes confirm it.

_SECURITY_HEADERS = {"missing_hsts": "strict-transport-security", "missing_csp": "content-security-policy",
                     "missing_xframe": "x-frame-options", "missing_xcto": "x-content-type-options"}
_COMPONENT_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime")
_WERKZEUG_RX = re.compile(r"Werkzeug Debugger|The debugger caught an exception|console\?__debugger__|__debugger__=yes"
                          r"|Traceback \(most recent call last\)[\s\S]{0,4000}?werkzeug", re.I)
_DIR_LISTING_RX = re.compile(r"<title>\s*Index of /|<h1>\s*Index of /|Directory listing for /", re.I)
_AUTH_PATH_RX = re.compile(r"log[- _]?in|log[- _]?on|auth|sign[- _]?in|session|token|oauth|account/login", re.I)
_USER_FIELDS = ("user", "username", "uname", "login", "email", "userid", "user_id", "account")
_PASS_FIELDS = ("pass", "password", "passwd", "pwd", "secret", "otp")


def _har_responses(ev):
    """[(event, response_headers, response_body)] for events that carry a response (HAR only): a
    headers dict (possibly empty) and the response body text, for any event that has either."""
    out = []
    for e in ev.events:
        extra = e.get("extra", {})
        rh = extra.get("response_headers")
        body = extra.get("response_body")
        if isinstance(rh, dict) or body is not None:
            out.append((e, {k.lower(): v for k, v in (rh or {}).items()}, str(body or "")))
    return out


def detect_misconfig(ev) -> list:
    """Security-misconfiguration facts proved from response headers and Set-Cookie flags (HAR only --
    access logs carry no headers), the response body (a directory listing), and source CORS config.
    Returns a sorted list of fact names; the class name itself is still unsure."""
    facts = set()
    for e, rh, body in _har_responses(ev):
        if isinstance(e.get("extra", {}).get("response_headers"), dict):     # read headers only where present
            acao = str(rh.get("access-control-allow-origin", "")).strip()
            if acao == "*" or (acao and str(rh.get("access-control-allow-credentials", "")).lower() == "true" and acao not in ("", "null")):
                facts.add("cors_wildcard")
            for fact, header in _SECURITY_HEADERS.items():
                if header not in rh:
                    facts.add(fact)
        if _DIR_LISTING_RX.search(body):
            facts.add("directory_listing")
    for e in ev.events:
        for sc in e.get("extra", {}).get("set_cookie") or []:
            if "=" in sc and "httponly" not in sc.lower():
                facts.add("cookie_not_httponly")
    for name, data in _unique(ev.files):
        if Path(name.split(ARROW)[-1]).suffix.lower() not in _LANG:
            continue
        text = text_of(data) or ""
        if re.search(r"Access-Control-Allow-Origin[\"'\]\s]*[:=]\s*[\"']\*|CORS\([^)\n]*origins\s*=\s*[\"']\*|cors\([^)\n]*\borigin\s*:\s*[\"']\*", text):
            facts.add("cors_wildcard")
    return sorted(facts)


def detect_components(ev) -> list:
    """Software components (and versions) the delivery discloses: Server / X-Powered-By response
    banners (HAR) and source manifests (requirements.txt, package.json). Returns 'name/version'-style
    strings; never a plain answer (whether a version is vulnerable is a human call/CVE lookup)."""
    out = []
    for _, rh, _ in _har_responses(ev):
        for h in _COMPONENT_HEADERS:
            v = rh.get(h)
            if v and re.search(r"[A-Za-z].*\d|\d", v):
                out.append(v.strip())
    for name, data in _unique(ev.files):
        base = Path(name.split(ARROW)[-1]).name.lower()
        text = text_of(data) or ""
        if base == "requirements.txt":
            out += [f"{m.group(1)}=={m.group(2)}" for m in re.finditer(r"^([A-Za-z0-9_.\-]+)\s*==\s*(\d[\w.\-]*)", text, re.M)]
        elif base in ("package.json", "composer.json"):
            try:
                # Package identifiers are case/punctuation-sensitive data, not policy keys:
                # ``foo-bar`` and ``foo_bar`` may both be real dependencies. This inventory
                # produces review-only component leads and never authorizes a request or emits
                # the vulnerable-component name plain, so do not apply policy canonicalization.
                doc = json.loads(text)
                for section in ("dependencies", "devDependencies", "require", "require-dev"):
                    for k, v in (doc.get(section) or {}).items():
                        out.append(f"{k}@{v}")
            except (ValueError, TypeError, AttributeError):
                pass
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res


def detect_idor(ev) -> bool:
    """Broken access control / IDOR: one client walking a run of consecutive object ids (/.../<n> or
    ?id=<n>), or the same client flipping a role/privilege parameter and getting a 2xx. Proof of the
    pattern only; the actor's address is never returned (a human call)."""
    _ID_PARAMS = ("id", "user_id", "userid", "account", "account_id", "uid", "oid", "doc", "docid",
                  "document", "order", "order_id", "invoice", "invoice_id", "num", "number", "pid")
    by_client = {}
    for e in ev.events:
        ids = []
        m = re.search(r"/(\d{1,9})(?:/|$)", e.get("path") or "")
        if m:
            ids.append(int(m.group(1)))
        for p in e.get("params") or []:
            value = str(p.get("value", ""))
            if str(p.get("name", "")).lower() in _ID_PARAMS and re.fullmatch(r"[0-9]{1,9}", value):
                ids.append(int(value))
        for i in ids:
            by_client.setdefault(e.get("ip"), []).append(i)
    for ip, ids in by_client.items():
        s = sorted(set(ids))
        run = best = 1
        for a, b in zip(s, s[1:]):
            run = run + 1 if b == a + 1 else 1
            best = max(best, run)
        if len(s) >= 5 and best >= 5:
            return True
    # role/privilege parameter flip from one client, ending in a 2xx
    flips = {}
    for e in ev.events:
        for p in e.get("params") or []:
            if str(p.get("name", "")).lower() in ("role", "admin", "is_admin", "isadmin", "privilege", "priv", "level", "access"):
                flips.setdefault((e.get("ip"), p["name"].lower()), set()).add(str(p.get("value")))
                if e.get("status") is not None and 200 <= e["status"] < 400 and len(flips[(e.get("ip"), p["name"].lower())]) >= 2:
                    return True
    return False


def _login_attempt(e):
    """(username, password_present, status) for a request that looks like an auth attempt, else None."""
    if e.get("method") not in ("POST", "PUT") and not (e.get("params")):
        return None
    path = (e.get("path") or "") + " " + (e.get("target") or "")
    surfaces = list(e.get("params") or [])
    body = e.get("body")
    if body:
        for piece in str(body).split("&"):
            name, _, val = piece.partition("=")
            surfaces.append({"name": unquote(name.replace("+", " ")), "value": unquote(val.replace("+", " "))})
        low = body.lstrip()[:1]
        if low == "{":
            try:
                doc = _strict_json(body, max_chars=MAX_LOG, max_members=262_144,
                                   max_nodes=524_288, max_depth=64)
                if isinstance(doc, dict):
                    surfaces += [{"name": k, "value": v} for k, v in doc.items()]
            except (ValueError, RecursionError):
                pass
    user = pw = None
    for s in surfaces:
        nm = str(s.get("name", "")).lower()
        if user is None and nm in _USER_FIELDS:
            user = str(s.get("value"))
        if nm in _PASS_FIELDS:
            pw = True
    if user is None and not _AUTH_PATH_RX.search(path):
        return None
    if user is None and pw is None:
        return None
    return (user, bool(pw), e.get("status"))


def detect_auth_abuse(ev) -> list:
    """A07 authentication-abuse facts, each from behaviour over the events: 'password_spraying' (one
    client, many distinct usernames, mostly failing), 'credential_stuffing' (one client, many distinct
    user+password attempts failing at volume), 'post_brute_success' (a client that failed auth many
    times then got a 2xx/3xx). Returns a sorted list; the actor is never returned plain."""
    per = {}
    for e in ev.events:
        att = _login_attempt(e)
        if att is None:
            continue
        user, has_pw, status = att
        d = per.setdefault(e.get("ip"), {"users": set(), "fail": 0, "ok": 0, "with_pw": 0, "seq": []})
        if user:
            d["users"].add(user)
        if has_pw:
            d["with_pw"] += 1
        if status in (401, 403) or status == 400:
            d["fail"] += 1
            d["seq"].append("f")
        elif status is not None and 200 <= status < 400:
            d["ok"] += 1
            d["seq"].append("s")
    facts = set()
    for ip, d in per.items():
        if ip is None:
            continue
        if len(d["users"]) >= 5 and d["fail"] >= 5 and d["fail"] >= d["ok"]:
            facts.add("password_spraying")
        if d["with_pw"] >= 8 and d["fail"] >= 8 and len(d["users"]) >= 5:
            facts.add("credential_stuffing")
        seq = "".join(d["seq"])
        if d["fail"] >= 6 and re.search(r"f{6,}.*s", seq):
            facts.add("post_brute_success")
    return sorted(facts)


def jwt_weakness_names(ev) -> list:
    """A02 cryptographic-failure facts from the delivery's JWTs (reusing decode_jwt's facts):
    'alg_none', 'alg_symmetric', 'no_signature', 'expired'. Sorted. Decode only, nothing verified."""
    if getattr(ev, "token_parse_incomplete", False):
        return []
    now = dt.datetime.now(UTC).timestamp()
    facts = set()
    for t in ev.tokens:
        alg = str(t.get("alg") or "").lower()
        if alg == "none":
            facts.add("alg_none")
        if alg in ("hs256", "hs384", "hs512"):
            facts.add("alg_symmetric")
        if not t.get("signed"):
            facts.add("no_signature")
        exp = (t.get("claims") or {}).get("exp")
        if isinstance(exp, (int, float)) and not isinstance(exp, bool) and exp < now:
            facts.add("expired")
    return sorted(facts)


def detect_flask_debug(ev) -> bool:
    """Flask debug mode / Werkzeug interactive debugger: an app.run(debug=True)/DEBUG=True config in
    source, or a Werkzeug traceback page in a response body (HAR)."""
    if any(s["family"] == "flask_debug" for s in ev.source["sinks"]):
        return True
    for _, _, body in _har_responses(ev):
        if _WERKZEUG_RX.search(body):
            return True
    return False


def _owasp_confirm(fam, ev) -> bool:
    """True when the bytes confirm the row-208 class the question named."""
    if fam == "broken_access_control":
        return detect_idor(ev)
    if fam == "misconfiguration":
        return bool(set(detect_misconfig(ev)) & _STRONG_MISCONFIG)
    if fam == "vulnerable_components":
        return bool(detect_components(ev))
    if fam == "jwt_crypto":
        return bool(set(jwt_weakness_names(ev)) & {"alg_none", "alg_symmetric"})
    if fam == "flask_debug":
        return detect_flask_debug(ev)
    if fam == "credential_stuffing":
        return "credential_stuffing" in detect_auth_abuse(ev)
    if fam == "password_spraying":
        return "password_spraying" in detect_auth_abuse(ev)
    return False


def _vuln_key(q, fam):
    """The labels key for an unsure attack-class / technique answer.

    An injection/attack *technique* ("what SQLi technique", an `-technique` id) is a DIFFERENT fact from
    the attack *class* ("attack-class", "type of attack"). They used to share `web.vuln/<fam>`, so a probe
    that learned the class name answered a technique id plain -> WRONG. Give a clear technique question its
    own key `web.technique/<fam>` so each is probed independently; both stay unsure, never plain. A question
    that names a class/category/type word (even beside "technique") keeps the `web.vuln/<fam>` key."""
    words = (str(q.get("question") or "") + " " + re.sub(r"[-_.]+", " ", _aid(q)))
    if re.search(r"\btechniques?\b", words, re.I) and not re.search(r"\b(?:class|category|family|kind|type)\b", words, re.I):
        return f"web.technique/{fam}"
    return f"web.vuln/{fam}"


# Technique vocabulary: a `web.technique/<fam>` question is offered the spellings of ONE
# technique the bytes show, never the attack-class names (W2 gave the key; its options were still the class
# list, a wasted probe each). SQL injection: the technique is read from the payloads, and two techniques
# shown (sqlmap tries several) is None. A behaviour family's technique is the behaviour itself.
TECHNIQUE_NAMES = {
    "union_based": ["union_based", "union_query", "union_based_injection", "union_select", "union"],
    "error_based": ["error_based", "error_based_injection", "error"],
    "boolean_blind": ["boolean_blind", "boolean_based_blind", "boolean_based", "blind_boolean"],
    "time_blind": ["time_blind", "time_based_blind", "time_based", "blind_time"],
    "stacked_queries": ["stacked_queries", "stacked", "stacked_query", "piggybacked_queries"],
    "brute_force": ["brute_force", "password_guessing"],
    "password_spraying": ["password_spraying", "password_spray"],
    "credential_stuffing": ["credential_stuffing"],
    "enumeration": ["forced_browsing", "directory_brute_force", "wordlist_scanning", "directory_enumeration"],
    "web_shell": ["web_shell", "webshell"],
    "none_algorithm": ["none_algorithm", "alg_none"],
}
_SQLI_UNION = re.compile(r"\bunion\b(?:\s+|/\*.{0,40}?\*/)+(?:all\s+|distinct\s+)?select\b", re.I | re.S)
_SQLI_TIME = re.compile(r"\b(?:sleep|pg_sleep|benchmark|randomblob)\s*\(|\bwaitfor\s+delay\b|\bdbms_lock\.sleep\b", re.I)
_SQLI_ERROR = re.compile(r"\b(?:extractvalue|updatexml|gtid_subset|json_keys)\s*\(|\bfloor\s*\(\s*rand\s*\(|\bexp\s*\(\s*~"
                         r"|\bconvert\s*\(\s*int\b|\bcast\s*\([^)]{0,80}\bas\s+(?:int|integer|numeric|signed)\b", re.I)
_SQLI_STACKED = re.compile(r"(?:^|['\"\d)\s]);\s*(?:select|insert|update|delete|drop|create|alter|exec|execute|declare|shutdown|waitfor)\b", re.I)
_SQLI_COMPARE = re.compile(r"\b(?:and|or)\s+(?:(\d+)\s*=\s*(\d+)\b|'(\w{0,8})'\s*=\s*'(\w{0,8})')", re.I)
_SQLI_INFER = re.compile(r"\b(?:ascii|ord|unicode)\s*\(\s*(?:substring|substr|mid)\s*\([^)]*\)\s*\)\s*[<>=]", re.I)


def sqli_techniques(payloads) -> set:
    """The SQL injection techniques a set of decoded payloads shows. Boolean-blind needs both a true and a
    false condition (a lone `AND 1=1` or `OR 1=1` tells nothing apart) or a character comparison with no
    time function."""
    found, true_cond, false_cond = set(), False, False
    for p in payloads:
        if not p:
            continue
        p = str(p)[:MAX_VALUE]
        timed = _SQLI_TIME.search(p) is not None
        if _SQLI_UNION.search(p):
            found.add("union_based")
        if timed:
            found.add("time_blind")
        if _SQLI_ERROR.search(p):
            found.add("error_based")
        if _SQLI_STACKED.search(p):
            found.add("stacked_queries")
        if _SQLI_INFER.search(p) and not timed:
            found.add("boolean_blind")
        for a, b, c, d in _SQLI_COMPARE.findall(p):
            same = (a == b) if a or b else (c == d)
            true_cond, false_cond = true_cond or same, false_cond or not same
    if true_cond and false_cond:
        found.add("boolean_blind")
    return found


def _technique_answer(q, fam, names, ev=None, found=(), suffix=""):
    """The unsure `web.technique/<fam>` answer, or None.

    A labels key of bare names answers its accepted name on every later variant (labels.pick), so a key
    holds ONE fact (review of eb6699e, B1): the technique read is part of the key
    (`web.technique/sqli.union_based`), and `web.technique/sqli = union_based` learned on one variant can
    never answer a time-blind variant. A question that names the attack ("which SQL injection technique")
    is offered the technique's spellings only; a generic one ("what technique did the attacker use") also
    the class names, which may be what it means (`suffix` carries what those names depend on)."""
    tech = None
    if fam == "sqli":
        shown = sqli_techniques({v for x in found if "sqli" in x["families"] for v in (x.get("payload"), x.get("payload_noplus"))})
        tech = next(iter(shown)) if len(shown) == 1 else None
    elif fam in ("brute_force", "password_spraying", "credential_stuffing", "enumeration"):
        tech = fam
    elif fam == "webshell" and any(x.get("role") == "use" for x in found):
        tech = "web_shell"
    elif fam == "jwt_crypto" and ev is not None and set(jwt_weakness_names(ev)) & {"alg_none", "alg_symmetric"} == {"alg_none"}:
        tech = "none_algorithm"
    generic = fam not in _named_families(" ".join(str(q.get("question") or "").split()))
    opts = list(TECHNIQUE_NAMES[tech]) if tech else []
    if generic:
        opts += [n for n in names if n not in opts]
    if not opts:
        return None
    # a generic question's options mix the technique and the class names, so it has its own key: a class
    # name accepted for it must never answer the question that names the attack, nor the reverse (re-review)
    key = f"web.technique/{fam}" + (f".{tech}" if tech and tech != fam else "") + ((".generic" + suffix) if generic else "")
    return _pick(key, _options(q, opts))


def _class_answer(q, fam, names, ev=None, found=(), suffix=""):
    """The unsure attack-class answer, or the technique's when the question asks for a technique. `suffix`
    ends the key when the names depend on the delivery (a JWT's weakness), so one key holds one fact."""
    key = _vuln_key(q, fam)
    if key.startswith("web.technique/"):
        return _technique_answer(q, fam, names, ev, found, suffix)
    return _pick(key + suffix, _options(q, names))


# a technique asked by its ATT&CK name or id is an ATT&CK technique, not an injection technique
_ATTACK_ID_WORDS = re.compile(r"\batt&ck\b|\bmitre\b|\bt1\d{3}(?:\.\d{3})?\b", re.I)


def _owasp_answer(q, ev, fam, intent):
    """The unsure class/CWE/technique for a named, confirmed row-208 class, or None. Never plain."""
    if not _owasp_confirm(fam, ev):
        return None
    if intent == "vuln":
        names, suffix = list(VULN_NAMES.get(fam, [fam])), ""
        if fam == "jwt_crypto":
            # The token's concrete weakness is one naming of the class the question asked: a "none"-alg
            # token's weakness is as likely to be named `alg_none`/`none_algorithm` as the OWASP class
            # name. These are spellings of the ONE established fact (this token is cryptographically
            # weak); offered unsure, never plain, so a human picks which spelling.
            weak = set(jwt_weakness_names(ev))
            if "alg_none" in weak:
                names = ["none_algorithm", "alg_none"] + names
            if "alg_symmetric" in weak:
                names = names + ["alg_symmetric", "symmetric_algorithm"]
            # Review of eb6699e (B1, the same idea): those names depend on the token, so the weakness is
            # part of the key; `none_algorithm` learned on an alg-none token never answers an HS256 one.
            shown = sorted(weak & {"alg_none", "alg_symmetric"})
            suffix = ("." + "+".join(shown)) if shown else ""
        return _class_answer(q, fam, names, ev, suffix=suffix)
    if intent == "cwe":
        return _pick(f"web.cwe/{fam}", [c for c in CWE.get(fam, []) if _fits(q, c)])
    return _pick(f"web.attack/{fam}", ATTACK.get(fam, ["T1190"]))


# ---- what a question asks -----------------------------------------------------------------------------------

INTENTS = (     # the order breaks a tie at the same place in the text
    ("count", r"\bhow many\b|\bnumber of\b|\bcount\b|\btotal\b"),
    ("alg", r"\balg\b|\balgorithm\b"),
    ("kid", r"\bkid\b|\bkey[- _]id\b"),
    ("claim", r"\bclaims?\b|\bcookie\b"),
    ("secret", r"\bsecret(?:[- _]key)?\b|\bhard-?coded\b|\bsigning[- _]key\b|\bapi[- _]?key\b|\bpassword\b|\bcredential"),
    ("line", r"\bline(?:[- _]?number)?\b"),
    ("sink", r"\bsink\b|\bfunction\b|\b(?:dangerous|unsafe|vulnerable|insecure)[- _](?:call|function|method|api)\b"),
    ("cwe", r"\bcwe\b"),
    ("time", r"\bwhen\b|\btime\b|\btimestamp\b|\bdate\b|\bdatetime\b"),
    ("status", r"\bstatus\b|\bresponse[- _]code\b|\bhttp[- _]code\b"),
    ("method", r"\b(?:http|request)[- _]method\b|\bmethod\b|\bverb\b"),
    ("ua", r"\buser[- _]?agent\b|\bua\b"),
    ("tool", r"\btool\b|\bscanner\b"),
    ("ip", r"\bips?\b|\bip[- _]address\b|\baddress\b"),
    ("param", r"\bparam(?:eter)?s?\b|\bargument\b|\bquery[- _]key\b"),
    ("filename", r"\bfile[- _]?name\b|\b(?:name of the|uploaded) (?:\w+ )?file\b|\bweb[- _]?shell\b|\bfile\b"),
    ("payload", r"\bpayload\b|\bcommand\b|\bdecoded\b|\binjected\b"),
    ("vuln", r"\bvulnerability\b|\bvuln\b|\b(?:attack|vulnerability|weakness)[- _](?:type|class|category|family|name)\b|\b(?:type|class|kind|category) of (?:attack|vulnerability|weakness)\b"
             r"|\bweakness\b|\battack[- _]?class\b|\btechnique\b|\bwhat attack\b|\bwhich attack\b"
             # row 208: class-naming phrases that carry no generic intent word of their own
             r"|cryptographic[- _]failure|algorithm[- _]confusion|security[- _]misconfiguration|\bmisconfig\w*|broken[- _]access[- _]control"
             r"|open[- _]redirect\w*|debug[- _]mode|vulnerable[- _](?:component|dependenc)\w*|credential[- _]stuffing|password[- _]spray\w*"),
    ("route", r"\broute\b|\bendpoint\b|\bpath\b|\buri\b|\burl\b|\bpage\b|\bresource\b"),
)
_ABOUT_ATTACK = re.compile(r"\battack|\bmalicious\b|\bexploit|\bpayload\b|\binject|\bsuspicious\b|\bintruder\b|\bthreat actor\b|\badversary\b|\bweb ?shell\b"
                           r"|\bupload|\bvulnerab|\btargeted\b|\bcompromis|\bbrute|\btraversal\b|\bxss\b|\bsqli\b|\bssti\b|\bjndi\b|\blog4|\bscann|\bhacker\b|\babuse", re.I)
_NOT_OURS = re.compile(r"\b(?:most|least|top|highest|lowest|largest|smallest|average|busiest|second|third|legitimate|benign|normal)\b", re.I)
_OTHER_END = re.compile(r"\bserver\b|\bdestination\b|\bvictim\b|\bc2\b|\bcallback\b|\breverse\b|\binternal\b|\bhost(?:ed|ing)?\b|\bconnect(?:ed|s)?(?: back)? to\b"
                        r"|\bexfil|\blistener\b|\bdownload(?:ed)? from\b|\bresolve", re.I)
_INTENT_RX = tuple((name, re.compile(rx, re.I)) for name, rx in INTENTS)
_FAMILY_WORDS = {
    "sqli": r"sql[- _]?injection|\bsqli\b", "ssti": r"template[- _]injection|\bssti\b", "traversal": r"traversal|\blfi\b|file[- _]inclusion|file[- _]read",
    "cmdi": r"command[- _]injection|\bcmdi\b|\brce\b|code[- _]execution", "xss": r"cross[- _]site[- _]scripting|\bxss\b",
    "webshell": r"web[- _]?shell|upload", "jndi": r"\bjndi\b|log4j|log4shell", "shellshock": r"shellshock", "xxe": r"\bxxe\b|external[- _]entit",
    "ssrf": r"\bssrf\b|request[- _]forgery", "deserialization": r"deseriali[sz]", "nosqli": r"nosql",
    "prototype_pollution": r"prototype[- _]pollution|proto[- _]pollution|\b__proto__\b|\bconstructor\.prototype\b",
    "brute_force": r"brute[- _]?forc|\bguess",
    "enumeration": r"enumerat|directory[- _](?:brute|bust|scan)|\bfuzz",
    "scanner": r"\bscann(?:er|ers|ing|ed)\b|\bscans?\b|(?<![a-z])(?:" + "|".join(re.escape(t) for t in SCANNERS) + r")(?![a-z])",
    # OWASP Top 10. Tight patterns so an existing single-family question is unchanged.
    "open_redirect": r"open[- _]?redirect|unvalidated[- _]redirect|open[- _]redirection|url[- _]redirection",
    "flask_debug": r"debug[- _]mode|werkzeug|flask[- _]debug|interactive[- _]debugger|\bdebugger\b",
    "broken_access_control": r"broken[- _]access[- _]control|\bidor\b|insecure[- _]direct[- _]object|direct[- _]object[- _]reference",
    "misconfiguration": r"misconfig|security[- _]misconfiguration|\bcors\b|directory[- _]listing|missing[- _](?:security[- _])?header",
    "vulnerable_components": r"vulnerable[- _](?:component|dependenc|librar|package)|outdated[- _](?:component|dependenc|librar)|known[- _]vulnerab|component[- _]with[- _]known",
    "credential_stuffing": r"credential[- _]?stuffing|account[- _]?takeover",
    "password_spraying": r"password[- _]?spray(?:ing)?",
    "jwt_crypto": r"cryptographic[- _]failure|algorithm[- _]confusion|\bnone[- _]algorithm\b|jwt[- _](?:weakness|vulnerab|forg)|weak[- _](?:jwt|signature|token)|unsigned[- _](?:jwt|token)",
}
# The row-208 classes answered from headers/behaviour/tokens (not request payloads): named + confirmed
# in the bytes -> unsure class/cwe/attack, never a plain IP/status/time.
_ROW208_BRANCH = frozenset(("broken_access_control", "misconfiguration", "vulnerable_components",
                            "credential_stuffing", "password_spraying", "jwt_crypto", "flask_debug"))
_STRONG_MISCONFIG = frozenset(("cors_wildcard", "directory_listing", "cookie_not_httponly"))
# words that tie "first" and "last" to the payload requests themselves, not to their sender's other requests
_TIED = re.compile(r"\bexploit|\bpayload|\binject|\bmalicious|\battack(?!er)|\bweb ?shell|\bcommand|\bupload", re.I)
# every word a count question may hold besides the address, the status code and the file it names
_COUNT_WORDS = frozenset(
    "how many unique distinct different client source remote ip ips address addresses clients are there were was is in the "
    "log logs file access appear appears appeared recorded logged seen present total of do does did make made request "
    "requests sent send http web server this evidence a an to it contain contains listed by from come came originate "
    "originated has have had returned return received receive got status code codes response responses with entries "
    "lines that which and overall altogether records number "
    # Count verbs: "how many requests does the log record / hold / show / handle" is the
    # same total as "are recorded"; the anaphoric per-actor count of W1 still declines (actor_anaphora). Not
    # "processed" or "held": on a WAF export "processed" can mean allowed, "held" can mean blocked (review).
    "record hold holds show shows showed shown handle handles handled capture captures captured".split())
VULN_NAMES = {      # spellings of one class, snake_case, the descriptive name first (the event's style)
    "sqli": ["sql_injection", "sqli", "sql_injection_attack", "injection"],
    "ssti": ["server_side_template_injection", "template_injection", "ssti"],
    "traversal": ["path_traversal", "directory_traversal", "local_file_inclusion", "lfi", "file_inclusion"],
    "cmdi": ["command_injection", "os_command_injection", "remote_code_execution", "rce", "cmdi"],
    "xss": ["cross_site_scripting", "xss", "reflected_xss", "stored_xss"],
    "webshell": ["web_shell_upload", "webshell_upload", "unrestricted_file_upload", "file_upload", "web_shell", "webshell"],
    "jndi": ["jndi_injection", "log4shell", "log4j", "jndi_lookup", "remote_code_execution"],
    "shellshock": ["shellshock", "command_injection", "bash_injection"],
    "xxe": ["xml_external_entity", "xxe", "xml_external_entity_injection"],
    "ssrf": ["server_side_request_forgery", "ssrf"],
    "deserialization": ["insecure_deserialization", "unsafe_deserialization", "deserialization", "object_injection"],
    "nosqli": ["nosql_injection", "nosqli", "injection"],
    "prototype_pollution": ["prototype_pollution", "object_prototype_pollution", "proto_pollution"],
    "brute_force": ["brute_force", "password_brute_force", "credential_brute_force", "password_guessing"],
    "enumeration": ["directory_enumeration", "content_discovery", "directory_brute_force", "forced_browsing"],
    "code_injection": ["code_injection", "eval_injection", "remote_code_execution", "rce"],
    "zip_slip": ["zip_slip", "path_traversal", "arbitrary_file_write", "archive_path_traversal"],
    "regex_multiline": ["regex_bypass", "multiline_regex_bypass", "input_validation_bypass", "allowlist_bypass"],
    "upload": ["unrestricted_file_upload", "file_upload", "arbitrary_file_upload"],
    # OWASP Top 10 header/behaviour/source classes. Author vocabulary, so unsure only.
    "open_redirect": ["open_redirect", "unvalidated_redirect", "open_redirection", "url_redirection"],
    "flask_debug": ["debug_mode_enabled", "werkzeug_debugger", "flask_debug_mode", "exposed_debugger"],
    "broken_access_control": ["broken_access_control", "insecure_direct_object_reference", "idor", "privilege_escalation"],
    "misconfiguration": ["security_misconfiguration", "misconfiguration", "insecure_configuration"],
    "vulnerable_components": ["vulnerable_components", "vulnerable_dependency", "outdated_component", "components_with_known_vulnerabilities"],
    "credential_stuffing": ["credential_stuffing", "account_takeover"],
    "password_spraying": ["password_spraying", "password_spray"],
    "jwt_crypto": ["cryptographic_failure", "jwt_none_algorithm", "jwt_algorithm_confusion", "weak_jwt_signature"],
}
CWE = {"sqli": ["CWE-89"], "ssti": ["CWE-1336", "CWE-94"], "traversal": ["CWE-22", "CWE-98"], "cmdi": ["CWE-78", "CWE-77"], "xss": ["CWE-79"],
       "webshell": ["CWE-434"], "jndi": ["CWE-917", "CWE-502", "CWE-20"], "shellshock": ["CWE-78"], "xxe": ["CWE-611"], "ssrf": ["CWE-918"],
       "deserialization": ["CWE-502"], "nosqli": ["CWE-943"], "prototype_pollution": ["CWE-1321"],
       "brute_force": ["CWE-307"], "enumeration": ["CWE-425"],
       "code_injection": ["CWE-94", "CWE-95"], "zip_slip": ["CWE-22"], "regex_multiline": ["CWE-185", "CWE-20"], "upload": ["CWE-434"],
       # Row 208
       "open_redirect": ["CWE-601"], "flask_debug": ["CWE-489", "CWE-215", "CWE-94"],
       "broken_access_control": ["CWE-639", "CWE-284", "CWE-862"], "misconfiguration": ["CWE-16", "CWE-942", "CWE-1021", "CWE-693"],
       "vulnerable_components": ["CWE-1035", "CWE-937", "CWE-1395"], "credential_stuffing": ["CWE-307", "CWE-799"],
       "password_spraying": ["CWE-307", "CWE-799"], "jwt_crypto": ["CWE-347", "CWE-327", "CWE-345"]}
ATTACK = {"webshell": ["T1505.003"], "brute_force": ["T1110"], "enumeration": ["T1595.003"], "scanner": ["T1595.002", "T1595"],  # every other family: T1190
          # Row 208
          "open_redirect": ["T1190"], "flask_debug": ["T1190"], "broken_access_control": ["T1190"], "misconfiguration": ["T1190", "T1595"],
          "vulnerable_components": ["T1190", "T1195.001"], "credential_stuffing": ["T1110.004"], "password_spraying": ["T1110.003"],
          "jwt_crypto": ["T1552", "T1606.001"]}


def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _fits(q, value) -> bool:
    rx = _fmt(q).get("pattern") or _fmt(q).get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, str(value)) is not None
        except re.error:
            return False
    return True


def _aid(q) -> str:
    return re.sub(r"^set\d+\.", "", str(q.get("answer_id") or q.get("qid") or q.get("id") or ""))


def intents_in(text) -> list:
    """[(position, intent)] of every intent word in a text, by position."""
    out = []
    for name, rx in _INTENT_RX:
        m = rx.search(text)
        if m:
            out.append((m.start(), name))
    return sorted(out, key=lambda x: (x[0], [n for n, _ in INTENTS].index(x[1])))


# W-A: nouns that name a host, never a path, a parameter or a file. "Strong" ones name a
# host whatever is asked; "weak" ones (host, server, site) are also how a question names a client by its
# address, so they never contradict an IP.
_HOST_STRONG = r"host[- _]?names?|host[- _]headers?|domain(?:[- _]names?)?|domains|v-?hosts?|virtual[- _]hosts?|fqdns?|server[- _]names?"
_HOST_WEAK = r"hosts?|(?:web[- _]?)?servers?|(?:web[- _]?)?sites?|websites?"
_HOST_STRONG_RX = re.compile(r"\b(?:" + _HOST_STRONG + r")\b", re.I)
# the noun a question asks for: the head of its what/which (or imperative) phrase, followed by a verb, a
# preposition, a determiner or the end; "which web server path" asks for a path, "what host did" for a host
_ASK_HEAD = (r"(?:^|[.?!;:,(]\s*)(?:what|which|name|give|identify|provide|report|state)\s+(?:is\s+|was\s+|are\s+|were\s+)?"
             r"(?:the\s+|a\s+|an\s+)?(?:[\w'-]+\s+){0,2}?(?:%s)"
             r"(?=\s+(?:did|does|do|was|were|is|are|has|had|have|of|that|which|whose|the|a|an|this|it|they|their|for|in|on|at"
             r"|[a-z]+ed|sent|hit|ran|got|made|took|saw|gave|held|kept|served|serves|hosts|sends|runs|receives|returns|handles)\b"
             r"|\s*[?,.;:()]|\s*$)")
_ASK_STRONG_RX = re.compile(_ASK_HEAD % _HOST_STRONG, re.I)
_ASK_WEAK_RX = re.compile(_ASK_HEAD % _HOST_WEAK, re.I)
_PREPOSITIONS = frozenset("of from on to at in into onto against toward towards via through for within by across over "
                          "behind with under".split())
# Answers that a host noun does not contradict: a token's own strings, a secret, a time, a count.
_HOST_EXEMPT = frozenset(("count", "claim", "kid", "alg", "secret", "time"))
# W-D: an attack family's own name inside an answer id ("webshell-class", "command-injection-class",
# "path-traversal-class", "file-upload-class") holds an intent word (file, command, path, password, alg)
# that is the family's, not the fact asked.
_FAMILY_IN_ID = re.compile(
    r"\bweb ?shells?\b|\b(?:os )?command (?:injection|execution)\b|\b(?:path|directory|dir) traversal\b"
    r"|\b(?:local |remote |unrestricted |arbitrary )?file (?:uploads?|inclusion|read|write|disclosure)\b"
    r"|\burl redirect(?:ion|s)?\b|\bpassword (?:spray(?:ing)?|guessing|brute ?force)\b|\bcredential (?:stuffing|spraying)\b"
    r"|\b(?:none|alg) algorithm\b|\balgorithm confusion\b|\btime (?:based|blind)\b", re.I)


# the class or CWE word that directly follows a family name in the question ("command injection TECHNIQUE")
_FAMILY_CLASS_WORD = re.compile(r"\s+(?:attack\s+|vulnerability\s+)?(technique|class|category|type|kind|vulnerability|vuln|weakness|cwe)\b", re.I)


def _named_outside_preposition(text, rx) -> bool:
    """True when rx names a noun of the text that is not the object of a preposition (the three words
    before it, back to the last punctuation, hold none): "(the Host header)" yes, "from the server" no."""
    for m in rx.finditer(text):
        before = re.split(r"[^\w'\s-]", text[:m.start()])[-1]
        if not any(w in _PREPOSITIONS for w in before.lower().split()[-3:]):
            return True
    return False


def _host_conflict(intent, text, id_only) -> bool:
    """W-A: the question asks for a host (domain, vhost, Host header) and the intent read is another fact.
    With the intent from the answer id alone, any host noun the text names outside a preposition counts;
    with the intent from the text, only the noun its what/which phrase asks for."""
    if intent is None or intent in _HOST_EXEMPT:
        return False
    if _ASK_STRONG_RX.search(text) or (intent != "ip" and _ASK_WEAK_RX.search(text)):
        return True
    return id_only and _named_outside_preposition(text, _HOST_STRONG_RX)


def intent_of(q):
    """What one question asks for: the first intent word of the question text, which the answer id
    must not contradict (an id that names other intents and not this one). None when nothing or two
    things are asked, and when the question asks for a host the intent read does not give (W-A)."""
    text = " ".join(str(q.get("question") or "").split())
    aid_words = re.sub(r"[-_.]+", " ", _aid(q))
    from_aid = [n for _, n in intents_in(aid_words)]
    from_text = [n for _, n in intents_in(text)]
    if not from_text:
        intent = from_aid[0] if len(from_aid) == 1 else None
        # W-A: `tr-url-host` read as a route from its id while the text asks for "the
        # Host header": the id may not answer what the text does not ask
        return None if _host_conflict(intent, text, id_only=True) else intent
    first = from_text[0]
    if first == "count":
        return "count"
    # W-D in the text (re-review): an attack family's own name holds an intent word ("command" injection,
    # "path" traversal, "web shell") that is not what is asked when a class or CWE word follows it: "which
    # command injection technique", "what path traversal CWE" asked the payload and the path. Only a class
    # or CWE word takes over; "which web shell did the attacker use to run the command" stays the file name.
    # Round-3 review: only the family name that holds the first intent word, and only when the class or CWE
    # word follows it directly ("which web shell TECHNIQUE"); a class word later in the question ("which web
    # shell was uploaded through the file upload vulnerability") does not take over
    norm = text.replace("-", " ").replace("_", " ")
    if _FAMILY_IN_ID.search(norm):          # most questions name no family: one search, nothing more
        pos = min(p for p, n in intents_in(text) if n == first)
        head = next((m for m in _FAMILY_IN_ID.finditer(norm) if m.start() <= pos < m.end()), None)
        nxt = _FAMILY_CLASS_WORD.match(norm, head.end()) if head else None
        if nxt:
            first = "cwe" if nxt.group(1).lower() == "cwe" else "vuln"
    # "the value of the `role` claim", "the algorithm of the token", "status code of ...": the first word decides
    if from_aid and first not in from_aid:
        # W-D: an id whose only intent words belong to an attack family's own name
        # ("webshell-class") does not contradict the text; any other intent word in it still does
        if [n for _, n in intents_in(_FAMILY_IN_ID.sub(" ", aid_words))]:
            return None
    return None if _host_conflict(first, text, id_only=False) else first


def _named_families(text) -> list:
    hits = [fam for fam, rx in _FAMILY_WORDS.items() if re.search(rx, text, re.I)]
    if "scanner" in hits and len(hits) > 1 and not _SCANNER_RX.search(text.lower()):
        hits.remove("scanner")      # "the directory enumeration scan", "scanned for SQL injection": the other word names it
    return hits


def _named_family(text):
    hits = _named_families(text)
    return hits[0] if len(hits) == 1 else None


def _count_question(text, drop=()) -> bool:
    """True when a count question holds nothing but the words of the three count shapes: any other
    word (a path, a method, 'failed', 'before', 'attacked') is a condition this module does not apply."""
    low = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ", text.lower())
    for word in drop:
        if word:
            low = low.replace(str(word).lower(), " ")
    words = [w.strip(".") for w in re.findall(r"[^\s?!,;:()\[\]\"'`]+", low)]
    return all(w in _COUNT_WORDS for w in words if w)


def _one(values):
    """The one distinct value, or None (nothing, or two)."""
    first, have = None, False
    for v in values:
        if v is None:
            continue
        if not have:
            first, have = v, True
        elif v != first:
            return None
    return first if have else None


def _options(q, names):
    """The names the question's own list allows, in our order; all of ours when it lists none."""
    tri = _common("triage")
    listed = []
    try:
        listed = tri.enum_options(q) if tri is not None else []
        # The challenge platform's enum lists its names under `accepted_values`, which
        # triage.enum_options does not read; a name outside the list is a wasted probe
        if not listed and isinstance(_fmt(q).get("accepted_values"), list):
            listed = [str(v) for v in _fmt(q)["accepted_values"]][:50]
        labels = _common("labels")
        if not listed and labels is not None and _fmt(q).get("kind") == "enum":
            listed = labels.enum_from_question(str(q.get("question") or ""))
    except Exception:
        listed = []
    if listed:
        norm = {re.sub(r"[^a-z0-9]+", "_", str(x).lower()).strip("_"): str(x) for x in listed}
        return [norm[n] for n in (re.sub(r"[^a-z0-9]+", "_", x.lower()).strip("_") for x in names) if n in norm]
    return [n for n in names if _fits(q, n)]


def _scalar(v):
    """(value as text, True when its form is the only one): strings and integers have one form."""
    if isinstance(v, bool):
        return None, False
    if isinstance(v, str):
        return v, True
    if isinstance(v, int):
        return str(v), True
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False), False


def _claim_name(text, aid, known):
    """The claim (or cookie field) a question names: in quotes or backticks, next to the word claim,
    or as the last part of the answer id. It must be a field some token carries."""
    cands = re.findall(r"[`'\"]([\w.:/-]{1,60})[`'\"]", text)
    cands += re.findall(r"\b([\w.-]{1,40})\s+claim\b", text, re.I) + re.findall(r"\bclaim\s+(?:named\s+|called\s+)?([\w.-]{1,40})", text, re.I)
    cands += re.findall(r"\b([\w.-]{1,40})\s+(?:field|key|value)\b", text, re.I)
    hits = [c for c in cands if c in known]
    if not hits:
        tail = re.split(r"[-.]", aid)[-1] if aid else ""
        hits = [k for k in known if k == tail or k == tail.replace("_", "-")] or [k for k in known if aid.endswith("-" + k) or aid.endswith("_" + k)]
    return _one(hits)


def _time_answer(q, ev, kind):
    opts = time_options(ev["ts"], ev["ts_raw"])
    if not opts:
        return None
    fitting = [(n, v) for n, v in opts if _fits(q, v)]
    f = _fmt(q)
    syntax = " ".join(str(f.get("syntax") or "").lower().split())
    aware_utc = ev["ts"] is not None and ev["ts"].tzinfo is not None
    zero = aware_utc and ev["ts"].utcoffset() == dt.timedelta(0)
    for template, name, states_zone in _TEMPLATES:
        if syntax and template in syntax.replace("'", "").replace('"', ""):
            value = dict(opts).get(name)
            if value is not None and _fits(q, value) and (states_zone or zero):
                return value
            break
    has_pattern = isinstance(f.get("pattern") or f.get("regex"), str)
    if has_pattern and zero:
        distinct = {v for _, v in fitting}
        if len(distinct) == 1:
            return fitting[0][1]
    return _pick(f"web.time/{kind}", fitting)


def _scope(q, files):
    """The file a question is about, when it names one: its member, or one log file named in its text."""
    if q.get("member"):
        return str(q["member"])
    text = str(q.get("question") or "")
    names = {Path(k.split(ARROW)[-1]).name for k in files}
    hits = [n for n in names if len(n) > 3 and re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", text)]
    return hits[0] if len(hits) == 1 else None


_NEGATED = re.compile(r"\bnot\b|n't\b|\bexcept\b|\bexcluding\b|\bother than\b|\bneither\b|\bnever\b|\binstead\b|\bshould\b|\blegitimate\b|\bbenign\b", re.I)
# A source-review question that negates, ranks or qualifies what it asks for is not about the one sink found.
_SRC_QUALIFIED = re.compile(
    r"\b(?:not|never|no longer|cannot|safe|safely|secure|securely|patched|fixed|parameteri[sz]ed|prepared|saniti[sz]ed|escaped|validated"
    r"|second|third|fourth|fifth|last|other|another|except|excluding|besides|without|instead|rather than|before the|after the)\b"
    r"|n't\b|\bnon-", re.I)


def _route_words(r) -> set:
    """The words a question would name a route by: its path as written, its path segments, its handler."""
    out = set()
    path = str(r.get("path") or "")
    if len(path) > 1:
        out.add(path.lower())
    for seg in re.split(r"[/.]", path):
        if len(seg) > 2 and re.fullmatch(r"[A-Za-z_][\w-]*", seg):
            out.add(seg.lower())
    for w in re.findall(r"[A-Za-z_]\w{2,}", str(r.get("handler") or "")):
        out.add(w.lower())
    return out


def _names_other_route(text, routes, sink) -> bool:
    """True when the question names (by path, path segment or handler) a route that does not hold the
    sink and that name is no name of the sink's own routes."""
    own = set()
    for r in sink.get("routes") or []:
        own |= _route_words(r)
    if sink.get("handler"):
        own.add(str(sink["handler"]).lower())
    mine = {(r.get("method"), r.get("path")) for r in sink.get("routes") or []}
    low = text.lower()
    for r in routes or []:
        if (r.get("method"), r.get("path")) in mine:
            continue
        for w in _route_words(r) - own - {"get", "post", "put", "delete", "patch", "api", "app", "route", "index", "map", "http"}:
            if re.search(r"(?<![\w/-])" + re.escape(w) + r"(?![\w-])", low):
                return True
    return False


_TAINT_INTENTS = frozenset(("line", "filename", "route", "method", "param"))


def _taint_fact(q, intent, finding):
    """A proved flow's locating fact, kept unsure under a provenance-specific key.

    The bytes prove both ends of the chain, but challenge authors have historically differed on whether
    "the vulnerable line" means the source assignment or the sink call.  Keeping both spellings under a
    separate key preserves the toolkit's never-guess contract while making the new coverage probeable.
    """
    if intent == "line":
        opts = [("sink", str(finding["line"])), ("source", str(finding["from_line"]))]
        return _pick("web.line/source.static_taint", [(n, v) for n, v in opts if _fits(q, v)])
    if intent == "filename":
        name, base = finding["file"], Path(finding["file"]).name
        opts = [("basename", base)] + ([("path", name)] if base != name else [])
        return _pick("web.file/source.static_taint", [(n, v) for n, v in opts if _fits(q, v)])
    if intent == "param":
        value = finding["reads"][0] if len(finding.get("reads") or ()) == 1 else None
    else:
        value = _one([r.get("path" if intent == "route" else "method") for r in finding.get("routes") or []])
    return _pick(f"web.{intent}/source.static_taint", [("proved_flow", value)] if value is not None and _fits(q, value) else [])


def answer(q, ev: Evidence, files=None):
    """One question's answer from the evidence: plain, unsure or None (see the module text)."""
    text = " ".join(str(q.get("question") or "").split())
    aid = _aid(q)
    words = text + " " + re.sub(r"[-_.]+", " ", aid)
    f = _fmt(q)
    kind = str(f.get("kind") or "")
    intent = intent_of(q)
    if kind == "mitre_attack_id" or (intent == "vuln" and _ATTACK_ID_WORDS.search(words)):
        intent = "attack"
    if intent is None or _NEGATED.search(text):
        return None             # what the evidence does NOT show, or what should be there instead: not the fact read
    token_words =re.search(r"\b(?:jwt|json web token|token|bearer|cookie|session|claim)\b", words, re.I) is not None

    # -- tokens and cookies
    if intent in ("alg", "kid", "claim") or (token_words and intent in ("time", "secret") and not ev.events):
        cookie_only = re.search(r"\bcookie\b|\bsession\b", words, re.I) and not re.search(r"\bjwt\b|json web token|\bbearer\b", words, re.I)
        if ((cookie_only and getattr(ev, "cookie_parse_incomplete", False))
                or (not cookie_only and getattr(ev, "token_parse_incomplete", False))):
            return None
        tokens = [] if (cookie_only and ev.cookies) else ev.tokens
        if not tokens and not ev.cookies:
            return None
        if intent == "alg":
            v, plain = _scalar(_one([t["alg"] for t in tokens]) if tokens and all(t["alg"] is not None for t in tokens) else None)
            return v if plain and v is not None and _fits(q, v) else None
        if intent == "kid":
            with_kid = [t["kid"] for t in tokens if t["kid"] is not None]
            v, plain = _scalar(_one(with_kid) if len({json.dumps(k) for k in with_kid}) == 1 else None)
            return v if plain and v is not None and _fits(q, v) else None
        if intent == "claim" or intent == "time":
            dicts = [t["claims"] for t in tokens] or [c["data"] for c in ev.cookies]
            headers = [t["header"] for t in tokens]
            known = {k for d in dicts for k in d}
            name = _claim_name(text, aid, known)
            if name is None and intent == "time":
                name = "exp" if re.search(r"\bexpir", words, re.I) else "iat" if re.search(r"\bissued\b", words, re.I) else None
            source = dicts
            if name is None:
                name = _claim_name(text, aid, {k for h in headers for k in h})
                source = headers
            if name is None:
                return None
            values = [d[name] for d in source if name in d]
            if not values or len({json.dumps(v, sort_keys=True) for v in values}) != 1:
                return None
            value = values[0]
            # A "when"/"date"/"time" question about a NUMERIC claim has a non-standard rendering (epoch vs
            # an ISO/space date), so it is offered unsure under the claim's own key, never plain. This
            # held for exp/iat/nbf from the start; a non-standard epoch claim (valid_until, issued_on, ...)
            # asked the same way used to fall through to a plain raw epoch integer -- a WRONG PLAIN whose
            # rendering is not established. A question that signals the raw value is wanted
            # (claim/value/epoch/unix/integer, or kind=integer) still answers the number plain below.
            if isinstance(value, (int, float)) and not isinstance(value, bool) \
                    and (intent == "time" or re.search(r"\bwhen\b|\bdate\b|\btime\b|\bexpir|\bissued\b", text, re.I)) \
                    and not re.search(r"\bclaim\b|\bvalue\b|\bepoch\b|\bunix\b|\binteger\b", text, re.I) and kind != "integer":
                opts = time_options(parse_time(value), str(int(value)))
                return _pick(f"web.time/jwt.{name}", [(n, v) for n, v in opts if _fits(q, v)])
            v, plain = _scalar(value)
            if v is None:
                return _pick(f"web.format/claim.bool", [(n, s) for n, s in (("json", json.dumps(value)), ("python", str(value))) if _fits(q, s)])
            if not _fits(q, v):
                return None
            return v if plain else _pick("web.format/claim.json", [("json_compact", v)])
        return None

    events = ev.events
    family_asked = _named_family(text)

    # -- OWASP Top 10 classes that are header/behaviour/token/source facts. Only when
    # the question NAMES one of these and the bytes confirm it: an unsure class/CWE/technique, never a
    # plain IP, status or time. (Open redirect and source-side Flask debug ride the source path below.)
    if intent in ("vuln", "cwe", "attack") and family_asked in _ROW208_BRANCH:
        return _owasp_answer(q, ev, family_asked, intent)

    # -- counts over a log (one log file, or the one the question names)
    if intent == "count":
        if not events or len(ev.logs) != 1:
            return None
        if kind not in ("integer", "exact_text", "pattern", ""):
            return None
        log_name = next(iter(ev.logs))
        if not ev.complete(log_name):       # a line the reader skipped: no count over the rest is a fact
            return None
        value = None
        # W1: "how many requests did THAT CLIENT / THE ATTACKER / THIS HOST make" scopes
        # the count to an actor named only by anaphora. With no IP literal the toolkit cannot resolve which
        # actor, so the per-actor count is not a fact here -> the total branch must not fire (-> None,
        # never-guess; the lane agent/probe resolves it). Gated on an anaphoric actor noun, NOT on the mere
        # absence of an IP, so a genuine total ("how many requests are in the log") still answers.
        actor_anaphora = re.search(
            r"\b(?:that|this|the|said|same)\s+(?:client|attacker|host|visitor|user|source|actor|adversary|"
            r"bot|scanner|crawler|machine|agent|ip|address|remote host)\b", text, re.I)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        m_status = re.search(r"\b(?:status(?: code)?|returned(?: a| an)?(?: http)?(?: status)?(?: code)?|responses? (?:of|with)(?: status)?(?: code)?|http)\s+([1-5]\d\d)\b|\b([1-5]\d\d)\s+(?:responses?|status|errors?)\b", text, re.I)
        code_text = (m_status.group(1) or m_status.group(2)) if m_status else None
        if not _count_question(text, (Path(log_name).name, code_text)):
            return None
        restrict = None
        if re.search(r"\bhow many (?:unique|distinct|different) (?:client |source |remote )?(?:ips?|ip addresses|addresses|clients)\b", text, re.I) and not ips and not m_status:
            value = len({e["ip"] for e in events if e["ip"]}) if all(e["ip"] for e in events) else None
        elif not ips and not m_status and re.search(
                # not "lines": a blank line is a line of the file and no record, so the two counts can differ
                r"\bhow many (?:http |web |log |total )*(?:requests|entries|records)\b|\b(?:total )?number of (?:http |web |log )*(?:requests|entries|records)\b",
                text, re.I) and not re.search(r"\b(?:unique|distinct|different)\b", text, re.I):
            # W1: an anaphoric actor count is not the grand total; decline it rather than answer len(events).
            value = len(events) if not actor_anaphora else None   # complete log: the total is a fact; an actor's is not
        elif len(ips) == 1 and re.search(r"\bhow many (?:http )?requests\b", text, re.I) and not m_status and not restrict:
            value = sum(1 for e in events if e["ip"] == ips[0])
        elif m_status and not ips and re.search(r"\bhow many (?:http )?(?:requests|responses|entries|lines)\b", text, re.I) \
                and not re.search(r"\b(?:to|for|against|on|from|by|post|get|put)\b", text[:m_status.start()].split("how many", 1)[-1] if "how many" in text.lower() else text, re.I):
            code = int(m_status.group(1) or m_status.group(2))
            value = sum(1 for e in events if e["status"] == code) if all(e["status"] is not None for e in events) else None
        return str(value) if value is not None and _fits(q, str(value)) else None

    # -- source-only facts
    src = None
    if intent in ("secret", "line", "sink") or (not events and intent in ("route", "param", "vuln", "cwe", "attack", "filename", "method")):
        src = ev.source
        sinks = src["sinks"]
        if _SRC_QUALIFIED.search(text):
            return None         # the safe route, the second parameter, the patched version: not the one sink's fact
        if family_asked:
            sinks = [s for s in sinks if s["family"] == family_asked or (family_asked == "traversal" and s["family"] == "zip_slip")]
        if intent == "secret":
            secrets = src["secrets"]
            wanted = [s for s in secrets if s["kind"] in ("secret_key", "jwt_sign", "fallback", "env")] if re.search(r"\bsecret\b|signing", words, re.I) else \
                [s for s in secrets if s["kind"] == "password"] if re.search(r"\bpassword\b", words, re.I) else \
                [s for s in secrets if s["kind"] in ("api_key", "aws_key")] if re.search(r"\bapi[- _]?key\b", words, re.I) else secrets
            value = _one([s["value"] for s in wanted])
            return value if value is not None and _fits(q, value) else None
        one_sink = sinks[0] if len(sinks) == 1 else None
        static_flow = False
        if one_sink is None and not sinks and not src.get("taint_cut"):
            flows = [s for s in src.get("taint") or [] if not family_asked or s["family"] == family_asked
                     or (family_asked == "traversal" and s["family"] == "zip_slip")]
            if len(flows) == 1:
                one_sink, static_flow = flows[0], True
        if one_sink is None:
            return None
        fam = one_sink["family"]
        if _names_other_route(text, src["routes"], one_sink):
            return None         # the question is about a route that does not hold the sink
        if static_flow and intent in _TAINT_INTENTS:
            return _taint_fact(q, intent, one_sink)
        if intent == "line":
            # W-B: a type-name deserialization sink answers the line of its call, or nothing
            line = one_sink["call_line"] if "call_line" in one_sink else one_sink["line"]
            return str(line) if line is not None and _fits(q, str(line)) else None
        if intent == "sink":
            sid = one_sink["sink"]
            spell = [sid, sid.replace(".", "_"), sid.split(".")[-1], sid + "()"]
            # the call as the source writes it (ejs.render for the id template.render) comes first
            written = [m for m in re.findall(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*\(", one_sink.get("code") or "")
                       if m.split(".")[-1] == sid.split(".")[-1]]
            if written and written[0] not in spell:
                spell.insert(0, written[0])
            return _pick(f"web.sink/{sid}" + (".static_taint" if static_flow else ""), _options(q, spell))
        if intent == "filename":
            name = one_sink["file"]
            base = Path(name).name
            return base if base == name and _fits(q, base) else _pick("web.file/source", [(n, v) for n, v in (("basename", base), ("path", name)) if _fits(q, v)])
        # The handler of the sink reads no request value: what reaches the sink came in by another
        # route (stored first, used here). Which of the two "the vulnerable route" means is the
        # author's choice, so both are offered, under names that hold on the next variant.
        feeders = [r for r in src["routes"] if r.get("reads") and (r["method"], r["path"]) not in
                   {(x["method"], x["path"]) for x in one_sink["routes"]}] if not one_sink["params"] else []
        if intent == "route":
            path = _one([r["path"] for r in one_sink["routes"]])
            if path and not one_sink["params"]:
                opts = [("sink_route", path)] + ([("input_route", feeders[0]["path"])] if len(feeders) == 1 else [])
                return _pick("web.route/source.indirect", [(n, v) for n, v in opts if _fits(q, v)])
            return path if path and _fits(q, path) else None
        if intent == "method":
            method = _one([r["method"] for r in one_sink["routes"]])
            if method and not one_sink["params"]:
                opts = [("sink_route", method)] + ([("input_route", feeders[0]["method"])] if len(feeders) == 1 and feeders[0]["method"] else [])
                return _pick("web.method/source.indirect", [(n, v) for n, v in opts if _fits(q, v)])
            return method if method and _fits(q, method) else None
        if intent == "param":
            p = one_sink["params"]
            if not p and len(feeders) == 1 and len(feeders[0]["reads"]) == 1:
                return _pick("web.param/source.indirect", [("input_route", v) for v in feeders[0]["reads"] if _fits(q, v)])
            return p[0] if len(p) == 1 and _fits(q, p[0]) else None
        tail = ".static_taint" if static_flow else ""
        if intent == "vuln":
            return _class_answer(q, fam, VULN_NAMES.get(fam, [fam]), suffix=tail)
        if intent == "cwe":
            return _pick(f"web.cwe/{fam}" + tail, [c for c in CWE.get(fam, []) if _fits(q, c)])
        if intent == "attack":
            return _pick(f"web.attack/{fam}" + tail, ATTACK.get(fam, ["T1190"]))
        return None

    if not events:
        return None

    # -- the payload requests. A question that is not about the attack, that asks for the other end
    # of it or for a ranking is not one of these.
    if intent not in ("tool", "vuln", "cwe", "attack") and not _ABOUT_ATTACK.search(words) and not family_asked:
        return None
    if _NOT_OURS.search(text) or (intent == "ip" and _OTHER_END.search(text)):
        return None
    named = _named_families(text)
    if len(named) > 1:
        return None             # two attacks in one question: which one's fact is asked is not told
    if intent == "tool":
        # a scanner is named by its user agent, or by the marker it writes into its own requests
        # (acunetix_wvs_security_test in a payload, a /Netsparker<hex>/ path, the method NETSPARKER);
        # this needs no scanner finding, so it runs before the family gate below
        counts = {}
        for x in ev.findings:
            if x["family"] == "scanner":
                counts[x["tool"]] = counts.get(x["tool"], 0) + x.get("count", 1)
        for e in events:
            if scanner_of(e["ua"]):
                continue
            m = _SCANNER_RX.search(" ".join(str(v or "") for v in (e["method"], e["path"], e.get("query_raw"), e["extra"].get("request"))).lower())
            if m:
                counts[m.group(1)] = counts.get(m.group(1), 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: -kv[1])
        if not ranked or (len(ranked) > 1 and ranked[0][1] < 10 * ranked[1][1]):
            return None             # no scanner named, or two with nothing between them
        tools = [ranked[0][0]]
        ua = _one([x["raw"] for x in ev.findings if x["family"] == "scanner" and x["tool"] == tools[0]])
        m = re.search(re.escape(tools[0]) + r"[/ ]v?([\w.#-]+)", ua or "", re.I)
        return _pick(f"web.tool/{tools[0].replace(' ', '_')}", _options(q, [tools[0].replace(" ", "_")] + ([f"{tools[0]}/{m.group(1)}"] if m else [])))
    if family_asked:
        # the attack the question names, and only that one: its fact is never another attack's
        found = [x for x in ev.findings if family_asked in x["families"]]
        if family_asked == "scanner":
            tools_named = [t for t in SCANNERS if re.search(r"(?<![a-z])" + re.escape(t) + r"(?![a-z])", text.lower())]
            if tools_named:
                found = [x for x in found if x.get("tool") in tools_named]
        if not found:
            return None
        fam = family_asked
    else:
        found = ev.payload_findings()
        fams = sorted({x["family"] for x in found})
        fam = fams[0] if len(fams) == 1 else None
        if not found and intent != "tool":
            return None
    # A behaviour finding (brute force, enumeration, a scanner's name) is one row per address, on its
    # first request: it proves who and what, not the status, time or path of the address's other requests.
    behaviour = bool(found) and all(x["family"] in BEHAVIOUR_FAMILIES for x in found)
    if behaviour:
        kinds_found = {x["family"] for x in found}
        allowed = {"ip", "vuln", "cwe", "attack", "tool"}
        if kinds_found == {"brute_force"}:
            allowed |= {"route", "method"}
        if kinds_found == {"scanner"}:
            allowed.add("ua")
        if intent not in allowed or re.search(r"\blast\b|\blatest\b|\bfinal\b|\bsuccess", text, re.I):
            return None
    if intent in ("payload", "param"):      # the requests that carry a value: not the upload itself
        found = [x for x in found if x.get("role") != "upload" and x["where"] != "order"]
    hit_events = sorted({x["event"] for x in found})
    hits = [events[i] for i in hit_events]
    first_asked = re.search(r"\bfirst\b|\bearliest\b|\binitial\b|\bbeg[ia]n|\bstart", text, re.I) is not None
    last_asked = re.search(r"\blast\b|\blatest\b|\bfinal\b", text, re.I) is not None
    success = re.search(r"\bsuccess", text, re.I) is not None
    if success:
        ok = [e for e in hits if e["status"] is not None and 200 <= e["status"] < 300]
        hits = ok or hits
        if not ok:
            return None
    if first_asked and last_asked:
        return None
    ordered = ev.timed or len(ev.logs) == 1
    chosen = hits
    if (first_asked or last_asked) and hits:
        if not ordered:
            return None
        chosen = [hits[0] if first_asked else hits[-1]]
        if not _TIED.search(text):
            # "the attacker's first request": the sender's first request of all, which is the payload
            # request only when nothing of that sender stands before (after) it
            same = [e for e in events if e["ip"] == chosen[0]["ip"]]
            if (same[0] if first_asked else same[-1]) is not chosen[0]:
                return None
    log_kind_name = _one(list(ev.kinds.values())) or "mixed"

    if intent in ("vuln", "cwe", "attack"):
        if fam is None:
            return None
        if intent == "vuln":
            chosen_set = {id(e) for e in chosen}
            return _class_answer(q, fam, VULN_NAMES.get(fam, [fam]), ev,
                                 [x for x in found if id(events[x["event"]]) in chosen_set])
        if intent == "cwe":
            return _pick(f"web.cwe/{fam}", [c for c in CWE.get(fam, []) if _fits(q, c)])
        return _pick(f"web.attack/{fam}", ATTACK.get(fam, ["T1190"]))
    if intent == "ip":
        value = _one([e["ip"] for e in hits]) if all(e["ip"] for e in hits) else None
        if value and not family_asked:
            # "the attacker" with no attack named: every hostile address of the log must be that one
            others = {events[x["event"]]["ip"] for x in ev.findings} - {value}
            if others:
                return None
        return value if value and _is_ip(value) and _fits(q, value) else None
    if intent == "time":
        if len(chosen) != 1 and not (ordered and not last_asked and len(hits) >= 1 and re.search(r"\bwhen did\b.*\b(?:attack|exploit)", text, re.I)):
            return None
        e = chosen[0] if len(chosen) == 1 else hits[0]
        return _time_answer(q, e, e["kind"])
    if intent == "status":
        value = _one([e["status"] for e in chosen]) if all(e["status"] is not None for e in chosen) else None
        return str(value) if value is not None and _fits(q, str(value)) else None
    if intent == "method":
        value = _one([e["method"] for e in chosen]) if all(e["method"] for e in chosen) else None
        return value if value and _fits(q, value) else None
    if intent == "ua":
        if behaviour:       # every request of the scanner's address under that tool's name
            keys = {(events[x["event"]]["ip"], x.get("tool")) for x in found}
            chosen = [e for e in events if (e["ip"], scanner_of(e["ua"])) in keys]
        value = _one([e["ua"] for e in chosen]) if chosen and all(e["ua"] for e in chosen) else None
        return value if value and _fits(q, value) else None
    chosen_ids = {id(e) for e in chosen}
    picked = [x for x in found if id(events[x["event"]]) in chosen_ids]
    if intent == "param":
        named = [x for x in picked if x["where"] in ("query", "body") and x.get("role") != "upload"]
        if len(named) != len([x for x in picked if x.get("role") != "upload" and x["where"] != "order"]):
            return None             # a payload in the path or a header: no one parameter carried it
        value = _one([x["param"] for x in named]) if all(x["param"] for x in named) else None
        return value if value and _fits(q, value) else None
    if intent == "filename":
        ups = [x for x in ev.findings if x["family"] == "webshell"]
        if not ups:
            return None
        value = _one([x["filename"] for x in ups])
        return value if value and _fits(q, value) else None
    if intent == "payload":
        vals = [x for x in picked if x.get("role") != "upload" and x["where"] != "order" and x["payload"] is not None]
        if not vals or len({(x["payload"], x["payload_noplus"]) for x in vals}) != 1:
            return None
        x = vals[0]
        if x["payload"] == x["payload_noplus"]:
            return x["payload"] if _fits(q, x["payload"]) else None
        return _pick(f"web.payload/{x['family']}", [(n, v) for n, v in (("form_decoded", x["payload"]), ("percent_decoded", x["payload_noplus"]), ("raw", x["raw"])) if _fits(q, v)])
    if intent == "route":
        rows = [e for e in chosen]
        if fam == "webshell" and not re.search(r"shell", text, re.I) and re.search(r"upload", text, re.I):
            rows = [events[x["event"]] for x in ev.findings if x.get("role") == "upload"]
        if not rows or len({(e["path_raw"], e["path"]) for e in rows}) != 1:
            return None
        e = rows[0]
        in_path = any(x["where"] == "path" and x.get("role") is None for x in picked)
        asks_url = re.search(r"\burl\b", text, re.I) is not None
        if e["path_raw"] == e["path"] and not in_path and not asks_url:
            return e["path"] if _fits(q, e["path"]) else None
        opts = [("decoded_path", e["path"]), ("raw_path", e["path_raw"]), ("raw_target", e["target"])]
        if e.get("host"):
            opts.append(("host_path", f"{e['host']}{e['path']}"))
        return _pick(f"web.route/{log_kind_name}", [(n, v) for n, v in opts if v and _fits(q, v)])
    return None


_CACHE = {}


def _evidence(files, only=None) -> Evidence:
    key = (id(files), len(files), only)
    hit = _CACHE.get(key)
    if hit is None or hit.files is not files:
        if len(_CACHE) > 8:
            _CACHE.clear()
        hit = _CACHE[key] = Evidence(files, only)
    return hit


def other_lane(questions, files):
    """The known lane a delivery belongs to by its own marks, or None: an HCFG container or dNN_ ids
    (Binary), an ANS- answer or the puzzle asset (Mobile), 'Determine <format>.<property> for <file>'
    (Metadata), a slug in `message` (Warmups), one specimen asked for two of -role, -attack, -steps,
    -adapter, -campaign, -scenario (Script Analysis).
    Such a delivery is that lane's: this module answers nothing for it."""
    aids = [_aid(q) for q in questions]
    marks = {}
    for a in aids:
        m = re.match(r"(.+)-(role|attack|steps|adapter|campaign|scenario)$", a)
        if m:
            marks.setdefault(m.group(1), set()).add(m.group(2))
    if any(len(v) >= 2 for v in marks.values()):       # one specimen asked for two of its plan's fields
        return "script-analysis"
    if any(re.match(r"d\d\d_", a) for a in aids):
        return "binary-reverse-engineering"
    if aids == ["message"]:
        return "warmups"
    for q in questions:
        text = " ".join(str(x or "") for x in (q.get("question"), _fmt(q).get("syntax"), _fmt(q).get("pattern")))
        if "ANS-" in text:
            return "mobile-android"
        if re.search(r"\bDetermine [a-z0-9_]+\.[a-z0-9_.]+ for \S+", str(q.get("question") or "")):
            return "metadata-forensics"
    for name in files:
        if name.endswith("assets/puzzle.json"):
            return "mobile-android"
    return None


# ---- a live target beside the delivery -----------------------------------------------------------------
#
# A start response that names a target (live_target) and also ships a delivery (white-box source, the
# instance's log, a HAR) is answered from the delivery as before: routes, sinks, parameters, lines, the
# attack in the log. What the running instance holds is not in the delivery: the flag, its password, its
# signing key. A shipped `ADMIN_PASSWORD = "admin123"` may or may not be what the instance uses (the
# author's choice; staged W19-A answered it plain for "the admin password on your instance"). So under a
# live target every plain answer that is a secret, password, key, token or flag is turned unsure, one
# option, under `web.live_secret/<what>+<scope>@<challenge>` (the key says which kind of value, whether the
# question asked about the instance, and which challenge: the attempt's `name`, which a base, its Time Trial
# and its Mastery share), never plain until the name is accepted there. The challenge is in the key
# because what the instance holds is one author's choice: a name accepted for one challenge never makes
# another challenge's shipped value plain, and a rejection there never closes the key for another. One exception:
# a question that states the value's place in the shipped source (hard-coded, in app.py, in the source)
# and names nothing live asks a fact of the bytes, which stays plain as it is without a target.
# Nothing changes without a target. The routing of web-exploitation here (W-3, B6) checks LIVE_TARGET_GUARD.

LIVE_TARGET_GUARD = True        # web B4 is in this file: under a live target no secret answer is plain

_LIVE_SECRET_WORDS = re.compile(
    r"\bpass(?:word|wd|phrase)s?\b|\bpwd\b|\bcredentials?\b|\bflags?\b|\bsecrets?\b|\bapi[- _]?keys?\b|\bprivate[- _]?keys?\b"
    r"|\bsigning[- _]?keys?\b|\bsecret[- _]?keys?\b|\benc(?:ryption)?[- _]?keys?\b|\bhmac[- _]?keys?\b"
    r"|\b(?:access|auth|bearer|session|api|refresh|csrf|reset|admin|jwt)[- _]?tokens?\b|\btoken[- _](?:value|string)\b"
    r"|\bpins?\b|\botp\b", re.I)
_LIVE_WORDS = re.compile(
    r"\binstances?\b|\brunning\b|\blive\b|\bdeployed\b|\bdeployment\b|\bproduction\b|\bprod\b|\btarget\b|\bremote\b"
    r"|\bvm\b|\bon the (?:web[- _]?)?server\b|\byour (?:web[- _]?)?(?:server|app|application|service|site|box|machine)\b"
    r"|\bin use\b|\bcurrently\b|\bactual\b|\breal\b", re.I)
_SOURCE_WORDS = re.compile(r"\bhard-?coded\b|\bsource(?:[- _]code)?\b|\bshipped\b|\bcommitted\b|\bin the code\b", re.I)
_FLAG_SHAPE = flagfmt.TEXT      # the event's flag format (ctf.flagfmt)


def _live_scope(q, files) -> str:
    """'instance' when the question names the running instance, 'source' when it names only the place in
    the shipped source (a source word or a delivered file's name), else 'unstated'."""
    text = " ".join(str(q.get("question") or "").split())
    words = text + " " + re.sub(r"[-_.]+", " ", _aid(q))
    if _LIVE_WORDS.search(words) or str(q.get("artifact") or "").strip().lower() == "target":
        return "instance"
    if _SOURCE_WORDS.search(text):
        return "source"
    names = {Path(n.split(ARROW)[-1]).name.lower() for n in (files or {})}
    if any(len(n) > 2 and "." in n and re.search(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", text.lower()) for n in names):
        return "source"
    return "unstated"


def _challenge_scope(attempt) -> str:
    """The challenge a guarded key belongs to: the attempt's `name` as a slug (a base, its Time Trial and its
    Mastery share it, so only that challenge's own variants inherit an accepted name). With no name, the
    attempt id (no other attempt inherits anything); with neither, `unscoped-` and a random tag, so the key
    is this call's own and nothing carries."""
    attempt = attempt if isinstance(attempt, dict) else {}
    slug = re.sub(r"[^a-z0-9]+", "-", str(attempt.get("name") or "").lower()).strip("-")[:48]
    if slug:
        return slug
    aid = re.sub(r"[^a-z0-9]+", "-", str(attempt.get("attempt_id") or "").lower()).strip("-")[:16]
    if aid:
        return "attempt-" + aid
    return "unscoped-" + os.urandom(4).hex()


def live_guard(q, value, ev, files=None, attempt=None):
    """B4: the answer as it may go out under a live target. A plain secret, password, key, token or flag
    becomes unsure (one option) under a key of this challenge (`attempt`, the start response); everything
    else, an unsure answer and None are returned as they are."""
    if value is None or not isinstance(value, str) or value.startswith(SENTINEL):
        return value
    intent = intent_of(q)
    text = " ".join(str(q.get("question") or "").split())
    words = text + " " + re.sub(r"[-_.]+", " ", _aid(q))
    flag_shaped = bool(_FLAG_SHAPE.fullmatch(value.strip()))
    secret_asked = intent == "secret" or (intent == "claim" and _LIVE_SECRET_WORDS.search(words) is not None)
    if not (flag_shaped or secret_asked):
        return value
    scope = _live_scope(q, files)
    if scope == "source" and not flag_shaped:
        return value            # "what key is hard-coded in app.py": a fact of the shipped bytes
    kinds = {s["kind"] for s in (ev.source.get("secrets") or []) if s.get("value") == value} if intent == "secret" else set()
    what = ("flag" if flag_shaped or re.search(r"\bflags?\b", words, re.I) else
            "password" if (kinds & {"password"}) or re.search(r"\bpass(?:word|wd|phrase)s?\b|\bpwd\b|\bcredentials?\b", words, re.I) else
            "api_key" if (kinds & {"api_key", "aws_key"}) or re.search(r"\bapi[- _]?keys?\b", words, re.I) else
            "token" if re.search(r"\btokens?\b", words, re.I) and intent != "secret" else
            "secret_key" if intent == "secret" else "claim")
    name = "as_in_source" if intent == "secret" else "as_delivered"
    key = f"web.live_secret/{what}+{scope}@{_challenge_scope(attempt)}"
    out = _pick(key, [(name, value)])
    if out is None:
        print(f"[web_evidence] LIVE {_aid(q)}: a {what} under a live target; {name} is rejected under {key}: no answer (B4)",
              file=sys.stderr)
    elif isinstance(out, str) and out.startswith(SENTINEL):
        print(f"[web_evidence] LIVE {_aid(q)}: a {what} under a live target is not plain; unsure under {key} (B4)", file=sys.stderr)
    else:
        print(f"[web_evidence] LIVE {_aid(q)}: a {what} under a live target; accepted {name} under {key}"
              f" for this challenge: answered plain (B4)", file=sys.stderr)
    return out


def solve_set(questions, files, ctx) -> dict:
    """The runner contract. Every answer is plain (proven, one form), unsure (labels.pick) or None."""
    out = {(q.get("qid") or q.get("id")): None for q in questions}
    if other_lane(questions, files):
        return out
    target = live_target((ctx or {}).get("attempt"))
    try:
        full = _evidence(files)
    except Exception as e:
        print(f"[web_evidence] the delivery could not be read ({type(e).__name__}: {str(e)[:120]})", file=sys.stderr)
        return out
    readable = full.events or full.tokens or full.cookies or full.source["routes"] or full.source["sinks"] or \
               full.source.get("taint") or full.source["secrets"]
    if target and not readable:
        print(f"[web_evidence] WEB LIVE TARGET {target}: not this module's; alert and stop for the player", file=sys.stderr)
        return out
    if not readable:
        return out
    if target:
        print(f"[web_evidence] WEB LIVE TARGET {target} beside the delivery: its own facts are answered; no secret, password,"
              f" key, token or flag is plain (B4)", file=sys.stderr)
    for q in questions:
        try:
            only = _scope(q, files)
            ev = _evidence(files, only) if only and len(full.logs) > 1 and Path(only).name in {Path(n).name for n in full.logs} else full
            value = answer(q, ev, files)
            out[q.get("qid") or q.get("id")] = live_guard(q, value, ev, files, (ctx or {}).get("attempt")) if target else value
        except Exception as e:      # a fact that cannot be read is no answer
            print(f"[web_evidence] {_aid(q)}: {type(e).__name__}: {str(e)[:120]}", file=sys.stderr)
    if (ctx or {}).get("partial") is not None and isinstance(ctx["partial"], dict):
        ctx["partial"].update({k: v for k, v in out.items() if v is not None})
    return out


_Q_WORDS = re.compile(r"\battacker\b|\bexploit|\bweb ?shell\b|\baccess[- _]log|\bhttp\b|\brequest\b|\bendpoint\b|\broute\b|\buser[- _]?agent\b|\bjwt\b"
                      r"|\bcookie\b|\bclaim\b|\bsql injection\b|\bxss\b|\btraversal\b|\bpayload\b|\bstatus code\b|\bhar\b|\bwaf\b|\bvulnerab"
                      r"|\bcwe\b|\binject|\btemplate\b|\bparameter\b|\bdeseriali[sz]|\bsink\b|\b(?:dangerous|unsafe|insecure) (?:function|call|method)\b"
                      r"|\bhard-?coded\b|\bsecret key\b|\bsource code\b", re.I)
_PCAP_WEB_WORDS = re.compile(
    r"\bweb\b|\battacker\b|\bexploit|\bvulnerab|\bpayload\b|\b(?:sql|nosql) injection\b|\bxss\b|\bxxe\b"
    r"|\bssti\b|\bssrf\b|\bcommand injection\b|\bpath traversal\b|\blfi\b|\bweb ?shell\b"
    r"|\bdeseriali[sz]|\bcwe\b|\battack class\b|\bmalicious\b", re.I)


def signals(questions, files) -> float:
    """0..1: how strongly a delivery and its questions look like static web evidence. Cheap: the first
    64 KiB of each file and the question texts only."""
    score = 0.0
    logs = tokens = source = captures = 0
    for name, data in _unique(files)[:400]:
        if _looks_capture(data):
            captures += 1
            continue
        if _is_container(data):
            continue
        short = name.split(ARROW)[-1]
        head = data[:65536]
        if log_kind(head, short):
            logs += 1
        elif b"eyJ" in head and _JWT.search(head.decode("latin-1")):
            tokens += 1
        elif Path(short).suffix.lower() in _LANG and re.search(
                rb"@\w+\.(?:route|get|post|put|delete|patch)\s*\(|\b(?:Blueprint|APIRouter)\s*\(|\b(?:app|router)\.(?:get|post|use)\s*\("
                rb"|\$_(?:GET|POST)\b|\bRoute::(?:get|post|put|delete)\s*\(|\bparams\s*\["
                rb"|\[(?:HttpGet|HttpPost)\b|\bMapGet\s*\(|@(?:GetMapping|PostMapping|RequestMapping|Path|WebServlet)\b"
                rb"|\bhttp\.HandleFunc\s*\(|\.(?:GET|POST|Get|Post)\s*\(", head):
            source += 1
    if logs:
        score += 0.5
    if source:
        score += 0.4 if not logs else 0.1
    if tokens:
        score += 0.2
    texts = [" ".join(str(x or "") for x in (q.get("question"), re.sub(r"[-_.]+", " ", _aid(q)))) for q in questions]
    worded = sum(1 for t in texts if _Q_WORDS.search(t))
    if texts and worded:
        score += 0.3 * worded / len(texts)
    capture_web = bool(captures and any(_PCAP_WEB_WORDS.search(t) for t in texts))
    if capture_web:
        # Packet magic alone belongs to the network toolkit.  Web only becomes
        # eligible when the questions explicitly ask about an attack/payload;
        # solve_set still has to prove complete HTTP from the capture.
        score += 0.4
    if any(re.match(r"web\b", _aid(q)) for q in questions):
        score += 0.1
    if not (logs or tokens or source or capture_web):
        score = min(score, 0.25)
    return round(min(1.0, score), 3)


# ---- the command -----------------------------------------------------------------------------------------

def load_paths(paths) -> dict:
    """{name: bytes} of files, folders and zips (members under '<zip> -> <member>'; an encrypted
    member is skipped: tools/run.py's reader opens those for a saved attempt)."""
    files = {}

    def add_zip(name, data, depth=0):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist()[:5000]:
                    if info.is_dir() or info.file_size > MAX_LOG:
                        continue
                    try:
                        body = zf.read(info)
                    except (RuntimeError, zipfile.BadZipFile, NotImplementedError, zlib.error):
                        continue
                    files[f"{name}{ARROW}{info.filename}"] = body
                    files.setdefault(info.filename, body)
                    if body[:4] == b"PK\x03\x04" and depth < 3:
                        add_zip(info.filename, body, depth + 1)
        except (zipfile.BadZipFile, OSError):
            pass

    for p in paths:
        p = Path(p)
        for f in (sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]):
            data = f.read_bytes()
            key = str(f.relative_to(p)) if p.is_dir() else f.name
            files[key] = data
            if data[:4] == b"PK\x03\x04":
                add_zip(key, data)
    return files


def _show_event(e) -> str:
    when = e["ts_raw"] or "-"
    return f"{e['src']}:{e['line']} {when} {e['ip'] or '-'} {e['method'] or '-'} {e['target'] or '-'} -> {e['status'] if e['status'] is not None else '-'}"


def report(files, show_all=False) -> dict:
    ev = Evidence(files)
    src = ev.source
    t = tables(ev.events)
    return {
        "logs": {name: {"kind": ev.kinds[name], "events": len(evs)} for name, evs in ev.logs.items()},
        "tables": {k: v.most_common(None if show_all else 15) for k, v in t.items()},
        "findings": [{**{k: v for k, v in f.items() if k not in ("payload_noplus",)}, "request": _show_event(ev.events[f["event"]])} for f in ev.findings],
        "families": ev.families(),
        "tokens": [{k: v for k, v in tok.items() if k != "signature"} for tok in ev.tokens],
        "cookies": ev.cookies, "source": src,
    }


def print_report(r, out=sys.stdout):
    w = lambda s="": print(s, file=out)
    w("== logs")
    for name, info in r["logs"].items():
        w(f"  {name}: {info['kind']}, {info['events']} requests")
    if not r["logs"]:
        w("  none")
    for key, title in (("ip", "client addresses"), ("status", "statuses"), ("method", "methods"), ("route", "routes"), ("user_agent", "user agents")):
        rows = r["tables"].get(key) or []
        if rows:
            w(f"== {title} ({len(rows)} shown)")
            for value, n in rows:
                w(f"  {n:>7}  {value}")
    w(f"== findings ({len(r['findings'])}); payload families: {', '.join(r['families']) or 'none'}")
    for f in r["findings"]:
        where = f["where"] + (f":{f['param']}" if f.get("param") else "")
        extra = f" role={f['role']} filename={f.get('filename')}" if f.get("role") else (f" tool={f['tool']}" if f.get("tool") else "")
        extra += f" count={f['count']}" if f.get("count") else ""
        w(f"  [{f['family']}] {f['request']}")
        w(f"      {where}{extra}" + (f"  decoded: {str(f['payload'])[:300]!r}" if f.get("payload") else ""))
    w(f"== tokens ({len(r['tokens'])}) and cookies ({len(r['cookies'])})   (decoded only: nothing is verified, signed or forged)")
    for tok in r["tokens"]:
        w(f"  jwt in {tok['file']}: alg={tok['alg']!r} kid={tok['kid']!r} signed={tok['signed']}")
        w(f"      header {json.dumps(tok['header'], ensure_ascii=False)}")
        w(f"      claims {json.dumps(tok['claims'], ensure_ascii=False)}")
    for c in r["cookies"]:
        w(f"  {c['kind']} in {c['file']}" + (f" ({c.get('name')})" if c.get("name") else "") + f": {json.dumps(c['data'], ensure_ascii=False)}")
    s = r["source"]
    if any(s[k] for k in s):
        w(f"== source: {len(s['routes'])} routes, {len(s['sinks'])} sinks, {len(s.get('taint') or [])} proved flows, "
          f"{len(s['secrets'])} secrets, {len(s['forms'])} forms, "
          f"{len(s['scripts'])} script blocks, {len(s['comments'])} comments, "
          f"{len(s.get('regex_gates') or [])} open regex gates, {len(s.get('traps') or [])} honeypot/injection texts")
        for x in s["routes"]:
            w(f"  route {x['method'] or '*':<6} {x['path']:<32} {x['file']}:{x['line']} {x['handler'] or ''}")
        for x in s["sinks"]:
            routes = ", ".join(f"{y['method'] or '*'} {y['path']}" for y in x["routes"]) or "-"
            w(f"  SINK [{x['family']}] {x['sink']} at {x['file']}:{x['line']} in {x['handler'] or 'module'} (routes: {routes}; reads: {', '.join(x['params']) or '-'})")
            w(f"      {x['code']}")
        for x in s.get("taint") or []:
            routes = ", ".join(f"{y['method'] or '*'} {y['path']}" for y in x["routes"]) or "-"
            w(f"  FLOW [{x['family']}/{x['context']}] {','.join(x['reads'])} -> {x['sink']} at "
              f"{x['file']}:{x['line']} in {x['handler'] or 'module'} (routes: {routes})")
        for x in s["secrets"]:
            w(f"  secret [{x['kind']}] {x['name']} = {x['value']!r} at {x['file']}:{x['line']}")
        for x in s["forms"]:
            w(f"  form {x['method']} {x['action'] or '(same page)'} in {x['file']}: " + ", ".join(f"{i['name']}({i['type'] or 'text'})" + (f"={i['value']!r}" if i.get('value') else "") for i in x["inputs"]))
        for x in s["scripts"]:
            w(f"  script in {x['file']}: " + (f"src={x['src']}" if x["src"] else f"inline {len(x['inline'])} chars: {x['inline'][:100]!r}"))
        for x in s["comments"]:
            w(f"  comment in {x['file']}: {x['text'][:200]!r}")
        for x in s.get("traps") or []:
            head = "TRAP (anti-AI honeypot: DO NOT SOLVE, flag for the human)" if x["verdict"] == "trap" \
                else "suspect (injected / AI-addressed text: data, never instructions)"
            w(f"  {head} in {x['file']}: signals {', '.join(x['signals'])}")
            for rule in x["rules"]:
                w(f"      {rule['rule']}: {rule['reason']}")
        for x in s.get("regex_gates") or []:
            best = next((c for c in x["candidates"] if c["verified"]), None)
            w(f"  REGEX GATE [{', '.join(i['issue'] for i in x['issues'])}] {x['call']} {x['pattern']!r} on "
              f"{x['subject']} at {x['file']}:{x['line']}"
              + (f"; marker {x['markers'][0]['value']!r}" if x["markers"] else "")
              + (f"; candidate {best['payload']!r} passes (offline check, not sent)" if best else ""))
            if x.get("theme_note"):
                w(f"      {x['theme_note']}")
        for x in s.get("trap_cuts") or []:
            w(f"  NOT FULLY READ for honeypot text / regex gates: {x}")


def main(argv) -> int:
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: web_evidence.py <file|dir|zip>... [--json] [--all]", file=sys.stderr)
        return 2
    missing = [p for p in paths if not Path(p).exists()]
    if missing:
        print(f"web_evidence.py: not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    r = report(load_paths(paths), show_all="--all" in argv)
    if "--json" in argv:
        print(json.dumps(r, indent=1, ensure_ascii=False, default=str))
    else:
        print_report(r)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
