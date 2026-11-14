#!/usr/bin/env python3
"""Build an offline ETag / conditional-request replay plan from a saved response.

The module parses response bytes already in hand and produces request descriptors;
it contains no HTTP client and sends nothing.  A player may copy one descriptor to
the repository's scope-locked ``WebClient`` for the one assigned challenge target.

Examples::

    .venv/bin/python solvers/web/etag_chain.py saved-response.txt --path /api/items/7
    .venv/bin/python solvers/web/etag_chain.py saved-response.txt --path /api/items/7 \
        --methods GET,HEAD,PUT --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from email.utils import parsedate_to_datetime
from pathlib import Path


MAX_RESPONSE = 16 * 1024 * 1024
MAX_METHODS = 8
ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_STATUS = re.compile(r"^HTTP/(\d(?:\.\d)?)\s+(\d{3})(?:\s+(.*))?$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
# RFC entity-tag opaque values are not quoted-strings: backslash is an
# ordinary etagc byte and DQUOTE is forbidden rather than escaped.
_ETAG = re.compile(r'^(?:W/)?"[\x21\x23-\x7e\x80-\xff]*"$')


def _bytes(data: bytes | bytearray | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("latin-1", "replace")
    value = bytes(data)
    if len(value) > MAX_RESPONSE:
        raise ValueError(f"saved response exceeds {MAX_RESPONSE} bytes")
    return value


def parse_saved_response(data: bytes | bytearray | str) -> dict:
    """Parse one raw HTTP response without interpreting or executing its body."""
    raw = _bytes(data)
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
    elif b"\n\n" in raw:
        head, body = raw.split(b"\n\n", 1)
        lines = head.split(b"\n")
    else:
        head, body = raw, b""
        lines = head.splitlines()
    if not lines:
        raise ValueError("saved response is empty")
    try:
        status_line = lines[0].decode("latin-1").rstrip("\r")
    except UnicodeDecodeError as exc:  # latin-1 is total; defensive for alternate runtimes
        raise ValueError("invalid status line") from exc
    match = _STATUS.fullmatch(status_line)
    if not match:
        raise ValueError("first line must be an HTTP status line, e.g. HTTP/1.1 200 OK")

    header_items: list[tuple[str, str]] = []
    grouped: dict[str, list[str]] = {}
    for raw_line in lines[1:]:
        line = raw_line.rstrip(b"\r")
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            raise ValueError("obsolete folded headers are refused; unfold the saved response first")
        if b":" not in line:
            raise ValueError(f"malformed response header: {line[:80]!r}")
        name_b, value_b = line.split(b":", 1)
        name = name_b.decode("latin-1")
        value = value_b.decode("latin-1").strip(" \t")
        if not _HEADER_NAME.fullmatch(name):
            raise ValueError(f"invalid response header name: {name!r}")
        if any(ord(c) < 32 and c != "\t" for c in value) or "\x7f" in value:
            raise ValueError(f"control byte in response header {name!r}")
        lower = name.lower()
        header_items.append((name, value))
        grouped.setdefault(lower, []).append(value)
    headers = {name: values[-1] for name, values in grouped.items()}
    return {
        "http_version": match.group(1),
        "status": int(match.group(2)),
        "reason": match.group(3) or "",
        "headers": headers,
        "header_values": grouped,
        "header_items": header_items,
        "body": body,
        "body_length": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "offline": True,
    }


def extract_validators(snapshot: dict) -> dict:
    """Extract safe replay validators and explain any value that was omitted."""
    headers = {str(k).lower(): str(v) for k, v in (snapshot.get("headers") or {}).items()}
    grouped = {}
    for key, values in (snapshot.get("header_values") or {}).items():
        grouped[str(key).lower()] = ([str(item) for item in values]
                                     if isinstance(values, (list, tuple)) else [str(values)])
    warnings: list[str] = []
    etag_values = grouped.get("etag", ([headers["etag"]] if "etag" in headers else []))
    if len(etag_values) > 1:
        warnings.append("multiple ETag fields are ambiguous; all were omitted")
        etag = None
    else:
        etag = etag_values[0] if etag_values else None
    if etag and not _ETAG.fullmatch(etag):
        warnings.append("ETag was present but is not a quoted strong/weak entity-tag; it was omitted")
        etag = None
    modified_values = grouped.get(
        "last-modified", ([headers["last-modified"]] if "last-modified" in headers else [])
    )
    if len(modified_values) > 1:
        warnings.append("multiple Last-Modified fields are ambiguous; all were omitted")
        modified = None
    else:
        modified = modified_values[0] if modified_values else None
    if modified:
        try:
            parsed = parsedate_to_datetime(modified)
            if parsed is None or parsed.tzinfo is None:
                raise ValueError
        except (TypeError, ValueError, OverflowError):
            warnings.append("Last-Modified was present but is not a valid HTTP date; it was omitted")
            modified = None
    return {"etag": etag, "last_modified": modified, "warnings": warnings}


def _path(value: str) -> str:
    value = str(value or "")
    if not value.startswith("/") or value.startswith("//") or "://" in value:
        raise ValueError("path must be a relative-origin path beginning with one slash")
    if "#" in value:
        raise ValueError("origin-form request paths cannot contain a fragment")
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in value):
        raise ValueError("path must contain only visible ASCII with spaces/control bytes percent-encoded")
    return value


def _methods(values) -> list[str]:
    if isinstance(values, str):
        values = values.split(",")
    out = []
    for value in values:
        method = str(value).strip().upper()
        if not method:
            continue
        if method not in ALLOWED_METHODS:
            raise ValueError(f"unsupported method {method!r}; choose {', '.join(sorted(ALLOWED_METHODS))}")
        if method not in out:
            out.append(method)
    if not out:
        raise ValueError("at least one replay method is required")
    if len(out) > MAX_METHODS:
        raise ValueError(f"at most {MAX_METHODS} methods may be described")
    return out


def _expected(method: str, condition: str) -> str:
    if method in ("GET", "HEAD"):
        return "304 Not Modified when the saved representation is still current; otherwise a normal response"
    if condition == "if_modified_since":
        return "If-Modified-Since is normally ignored for non-GET/HEAD methods; retain only to test routing behavior"
    return "412 Precondition Failed when the condition is false; otherwise the application may process the method"


def build_replay_sequence(snapshot_or_response, *, path: str = "/", methods=("GET",),
                          include_baseline: bool = True, include_combined: bool = True) -> dict:
    """Return a bounded ordered sequence of conditional request descriptors.

    ``snapshot_or_response`` may be :func:`parse_saved_response` output or raw
    response bytes.  Descriptors intentionally have ``body=None`` and
    ``sent=False``.  A state-changing method is therefore a recipe requiring an
    explicit player-supplied body, never an action this module can perform.
    """
    snapshot = (snapshot_or_response if isinstance(snapshot_or_response, dict)
                else parse_saved_response(snapshot_or_response))
    validators = extract_validators(snapshot)
    if not validators["etag"] and not validators["last_modified"]:
        detail = "; ".join(validators["warnings"]) or "response has neither ETag nor Last-Modified"
        raise ValueError(f"cannot build a conditional replay: {detail}")
    resource = _path(path)
    verbs = _methods(methods)
    requests = []

    def add(method: str, headers: dict[str, str], purpose: str, condition: str) -> None:
        requests.append({
            "rank": len(requests) + 1,
            "method": method,
            "path": resource,
            "headers": headers,
            "body": None,
            "body_required": method not in ("GET", "HEAD", "OPTIONS"),
            "condition": condition,
            "purpose": purpose,
            "expected": _expected(method, condition),
            "sent": False,
        })

    for method in verbs:
        if include_baseline:
            add(method, {}, "control replay without a conditional header", "baseline")
        if validators["etag"]:
            add(method, {"If-None-Match": validators["etag"]},
                "replay the exact saved entity-tag", "if_none_match")
        if validators["last_modified"]:
            add(method, {"If-Modified-Since": validators["last_modified"]},
                "replay the saved modification time", "if_modified_since")
        if include_combined and validators["etag"] and validators["last_modified"]:
            add(method, {"If-None-Match": validators["etag"],
                         "If-Modified-Since": validators["last_modified"]},
                "send both validators; standards-compliant caches give If-None-Match precedence",
                "combined")
        if method not in ("GET", "HEAD", "OPTIONS"):
            add(method, {"If-None-Match": "*"},
                "create-only precondition: proceed only if no current representation exists",
                "if_none_match_star")

    return {
        "offline": True,
        "sent": False,
        "source": {"status": snapshot.get("status"),
                   "body_length": snapshot.get("body_length"),
                   "body_sha256": snapshot.get("body_sha256")},
        "validators": validators,
        "requests": requests,
        "notes": [
            "No request was sent; replay only through the scope-locked client for the assigned target.",
            "A 304/412 is protocol evidence, not a flag and not proof of authorization bypass by itself.",
            "State-changing descriptors have no body; the player must decide whether and how to use one.",
        ],
    }


def render_request(descriptor: dict, host: str = "ASSIGNED_TARGET") -> str:
    """Render one descriptor as a copyable HTTP/1.1 skeleton; still sends nothing."""
    host = str(host or "")
    if (not host or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in host)
            or any(c in host for c in "/\\?#@")):
        raise ValueError("host placeholder must be a control-free host[:port] value")
    method = _methods([descriptor.get("method")])[0]
    path = _path(descriptor.get("path"))
    headers = descriptor.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError("descriptor headers must be a mapping")
    clean_headers = []
    for name, value in headers.items():
        name, value = str(name), str(value)
        if not _HEADER_NAME.fullmatch(name):
            raise ValueError(f"invalid request header name: {name!r}")
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
            raise ValueError(f"control byte in request header {name!r}")
        clean_headers.append((name, value))
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    lines.extend(f"{name}: {value}" for name, value in clean_headers)
    if descriptor.get("body_required"):
        lines.append("Content-Length: <PLAYER_SUPPLIED>")
    return "\r\n".join(lines) + "\r\n\r\n"


def _json_plan(plan: dict) -> dict:
    # build_replay_sequence already omits response body bytes.  This helper
    # makes a shallow JSON-safe copy and adds rendered request skeletons.
    out = dict(plan)
    out["requests"] = [dict(row, raw=render_request(row)) for row in plan["requests"]]
    return out


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="build offline conditional-request descriptors from a saved response")
    p.add_argument("response", type=Path, help="file containing one raw saved HTTP response")
    p.add_argument("--path", default="/", help="origin-relative path to replay (default: /)")
    p.add_argument("--methods", default="GET", help="comma-separated explicit methods (default: GET)")
    p.add_argument("--no-baseline", action="store_true", help="omit the unconditional control descriptor")
    p.add_argument("--no-combined", action="store_true", help="omit the descriptor containing both validators")
    p.add_argument("--json", action="store_true", help="print structured JSON")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        snapshot = parse_saved_response(args.response.read_bytes())
        plan = build_replay_sequence(snapshot, path=args.path, methods=args.methods,
                                     include_baseline=not args.no_baseline,
                                     include_combined=not args.no_combined)
        if args.json:
            print(json.dumps(_json_plan(plan), indent=2, sort_keys=True))
        else:
            vals = plan["validators"]
            print("OFFLINE ONLY - conditional replay plan; no request was sent")
            print(f"source status={plan['source']['status']} etag={vals['etag']!r} "
                  f"last_modified={vals['last_modified']!r}")
            for row in plan["requests"]:
                print(f"\n[{row['rank']}] {row['purpose']}\n{render_request(row)}", end="")
        return 0
    except (OSError, ValueError) as exc:
        print(f"etag_chain: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
