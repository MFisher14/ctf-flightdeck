#!/usr/bin/env python3
"""Polite, single-lead OSINT lookups against allow-listed public providers.

This module is deliberately *not* a general HTTP client.  It accepts one validated
lead, builds requests only for a small allow-list of public OSINT providers, validates
every redirect, sleeps between requests, and stops at hard global/per-provider caps.
CSCTF/Chronos names, local/private addresses, secrets, and un-attested e-mail
addresses are rejected before a transport is called.

Returned rows are evidence for human review, never a flag or an identity verdict.
Tests can inject ``transport``, ``clock`` and ``sleep``; the regression suite does so
and therefore never touches the network.
"""
from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_REQUESTS = 8
MAX_PER_PROVIDER = 3
MIN_INTERVAL_SECONDS = 1.5
TIMEOUT_SECONDS = 12.0
GENERIC_USER_AGENT = "Public-OSINT-Research-Client/1.0 (single-item; contact: none)"

# Exact public services used by the builders below.  A caller cannot add a URL.
ALLOWED_HOSTS = frozenset({
    "rdap.org", "rdap.arin.net", "rdap.db.ripe.net", "rdap.apnic.net",
    "rdap.lacnic.net", "rdap.afrinic.net",
    "cloudflare-dns.com", "crt.sh", "web.archive.org",
    "nominatim.openstreetmap.org", "html.duckduckgo.com",
    "api.github.com", "gitlab.com", "www.reddit.com", "keybase.io",
    "pypi.org", "registry.npmjs.org", "services.nvd.nist.gov",
})
BLOCKED_SUFFIXES = ("ctf-platform.example",)
SECRET_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|"
    r"(?:api[_-]?key|token|secret|password)\s*[:=]\s*\S+|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,})",
    re.I,
)
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]{1,255}\Z")
EMAIL_ANY_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}")
DOMAIN_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z", re.I,
)
USERNAME_RE = re.compile(r"[\w.@+-]{1,128}\Z", re.UNICODE)


DEFAULT_GUESS_BUDGET = 3  # candidate-feeding lookups a challenge gets before a player must approve more


class OSINTGuardError(ValueError):
    """A request was declined by a scope, privacy, or rate guard."""


def guess_budget_block(wrong_count: int, guess_budget: int = DEFAULT_GUESS_BUDGET,
                       approvals_left: int = 0) -> str | None:
    """None when a threat-intel lookup that feeds a submittable candidate may run, else the loud reason
    it is blocked.

    A lookup is allowed until the challenge's wrong-answer count reaches ``guess_budget``; after that
    only an unused player approval (the submit gate's post-guard approval) permits it. This is the
    guardrail that stops the kit from being used as an unbounded guess generator; the caller passes the
    challenge's ``Workspace.wrong_count()`` and ``post_guard_approvals_left()`` so it honours exactly
    the submit gate's accounting. A negative count or budget is a programming error, raised loudly.
    """
    if isinstance(wrong_count, bool) or not isinstance(wrong_count, int) or wrong_count < 0:
        raise OSINTGuardError("wrong_count must be an int >= 0")
    if isinstance(guess_budget, bool) or not isinstance(guess_budget, int) or guess_budget < 0:
        raise OSINTGuardError("guess_budget must be an int >= 0")
    if wrong_count < guess_budget:
        return None
    if max(0, int(approvals_left)) > 0:
        return None
    return (f"{wrong_count} wrong answer(s) already on this challenge; the guess budget of "
            f"{guess_budget} is spent -- stop and ask the player before another candidate lookup")


@dataclasses.dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: Mapping[str, str]
    body: bytes
    final_url: str


@dataclasses.dataclass(frozen=True)
class Evidence:
    rank: int
    provider: str
    kind: str
    value: Any
    source_url: str
    note: str = "candidate evidence only; a human must verify attribution and the requested format"


Transport = Callable[[str, Mapping[str, str], float, int], HTTPResult]


def _hostname(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise OSINTGuardError("public OSINT requests must use plain HTTPS on port 443")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host:
        raise OSINTGuardError("request URL has no hostname")
    return host


def _is_blocked_name(value: str, extra: tuple[str, ...] = ()) -> bool:
    low = value.rstrip(".").lower()
    return any(low == suffix or low.endswith("." + suffix)
               for suffix in BLOCKED_SUFFIXES + extra)


def _validate_provider_url(url: str) -> str:
    host = _hostname(url)
    if host not in ALLOWED_HOSTS:
        raise OSINTGuardError(f"provider host is not allow-listed: {host}")
    if _is_blocked_name(host) or host in {"localhost", "localhost.localdomain"}:
        raise OSINTGuardError("CTF/local infrastructure is forbidden")
    try:
        addr = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        addr = None
    if addr is not None:
        raise OSINTGuardError("literal-IP provider URLs are forbidden")
    return host


def _domain(value: str) -> str:
    raw = str(value).strip().rstrip(".")
    if "://" in raw or "/" in raw or "@" in raw:
        raise OSINTGuardError("expected one bare domain")
    try:
        result = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise OSINTGuardError("invalid internationalized domain") from exc
    if not DOMAIN_RE.fullmatch(result):
        raise OSINTGuardError("invalid domain")
    return result


def _public_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError as exc:
        raise OSINTGuardError("invalid IP address") from exc
    if not addr.is_global:
        raise OSINTGuardError("private/reserved IP lookups are forbidden")
    return str(addr)


def _coordinate(value: str | tuple[float, float]) -> tuple[float, float]:
    if isinstance(value, tuple):
        lat, lon = value
    else:
        parts = re.split(r"\s*[,;]\s*", str(value).strip())
        if len(parts) != 2:
            raise OSINTGuardError("coordinate must be latitude,longitude")
        try:
            lat, lon = map(float, parts)
        except ValueError as exc:
            raise OSINTGuardError("invalid coordinate") from exc
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise OSINTGuardError("coordinate is outside Earth bounds")
    return float(lat), float(lon)


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        _validate_provider_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _urllib_transport(url: str, headers: Mapping[str, str], timeout: float,
                      max_bytes: int) -> HTTPResult:
    """Default bounded transport.  Redirects are checked before they are followed."""
    opener = urllib.request.build_opener(_GuardedRedirect())
    req = urllib.request.Request(url, headers=dict(headers), method="GET")
    try:
        with opener.open(req, timeout=timeout) as response:  # noqa: S310 -- URL is allow-listed above
            final_url = response.geturl()
            _validate_provider_url(final_url)
            advertised = response.headers.get("Content-Length")
            if advertised and int(advertised) > max_bytes:
                raise OSINTGuardError("provider response exceeds the byte cap")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise OSINTGuardError("provider response exceeds the byte cap")
            return HTTPResult(int(response.status), dict(response.headers.items()), body, final_url)
    except urllib.error.HTTPError as exc:
        # A 404 is useful absence evidence.  Its body remains bounded.
        body = exc.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise OSINTGuardError("provider error response exceeds the byte cap") from exc
        return HTTPResult(int(exc.code), dict(exc.headers.items()), body, exc.geturl())


class PublicOSINTClient:
    """Sequential, capped public-source client for exactly one investigation lead.

    A client is intentionally single-lead: the first lookup binds ``lead_fingerprint``;
    a different lead is rejected.  Create a new client only after a human chooses the
    next pivot.  This makes the API inconvenient to misuse as an enumerator.
    """

    def __init__(self, *, transport: Transport | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep,
                 min_interval: float = MIN_INTERVAL_SECONDS,
                 request_cap: int = MAX_REQUESTS,
                 per_provider_cap: int = MAX_PER_PROVIDER,
                 protected_identifiers: tuple[str, ...] = (),
                 blocked_targets: tuple[str, ...] = ()) -> None:
        if min_interval < 1.0:
            raise ValueError("OSINT interval cannot be less than one second")
        if not 1 <= request_cap <= MAX_REQUESTS:
            raise ValueError(f"request cap must be 1..{MAX_REQUESTS}")
        if not 1 <= per_provider_cap <= MAX_PER_PROVIDER:
            raise ValueError(f"per-provider cap must be 1..{MAX_PER_PROVIDER}")
        self.transport = transport or _urllib_transport
        self.clock = clock
        self.sleep = sleep
        self.min_interval = float(min_interval)
        self.request_cap = int(request_cap)
        self.per_provider_cap = int(per_provider_cap)
        env_private = tuple(x.strip() for x in os.environ.get(
            "OSINT_PRIVATE_IDENTIFIERS", "").split(",") if x.strip())
        self.protected = frozenset(x.casefold() for x in protected_identifiers + env_private)
        self.blocked_targets = tuple(x.lower().rstrip(".") for x in blocked_targets if x)
        self._requests = 0
        self._per_provider: dict[str, int] = {}
        self._last_request: float | None = None
        self._lead_fingerprint: str | None = None
        self._lead_kind: str | None = None
        self._lead_value: str | None = None

    @property
    def request_count(self) -> int:
        return self._requests

    def _bind_lead(self, kind: str, value: str) -> None:
        normalized = " ".join(value.split()).casefold()
        # The same exact value may legitimately be checked in RDAP, DNS, CT and
        # Wayback.  Bind the value, not the provider-facing type label.
        fingerprint = normalized
        if self._lead_fingerprint is None:
            self._lead_fingerprint = fingerprint
            self._lead_kind = kind
            self._lead_value = value
        elif self._lead_fingerprint != fingerprint:
            raise OSINTGuardError("one client may investigate only one exact lead")

    def _guard_value(self, kind: str, value: str, *, email_attested: bool = False) -> str:
        text = str(value).strip()
        if not text or len(text) > 4096 or any(ord(ch) < 0x20 for ch in text):
            raise OSINTGuardError("lead is empty, overlong, or contains control characters")
        if SECRET_RE.search(text):
            raise OSINTGuardError("secret-shaped values must never be sent to a public provider")
        folded = text.casefold()
        if any(private == folded or private in folded for private in self.protected):
            raise OSINTGuardError("protected/player identity must never be sent to a third party")
        # Catch a forbidden name embedded in a URL, search query, or e-mail domain.
        tokens = re.findall(r"[a-z0-9.-]+", text.lower())
        if any(_is_blocked_name(token, self.blocked_targets) for token in tokens):
            raise OSINTGuardError("CSCTF/Chronos or another forbidden target is out of scope")
        if kind == "email":
            if not EMAIL_RE.fullmatch(text):
                raise OSINTGuardError("invalid e-mail address")
            if not email_attested:
                raise OSINTGuardError(
                    "raw e-mail lookup requires explicit challenge-identifier attestation")
        elif EMAIL_ANY_RE.search(text):
            raise OSINTGuardError(
                "e-mail inside a generic query is forbidden; use the attested e-mail lookup")
        self._bind_lead(kind, text)
        return text

    def _request(self, provider: str, url: str, *, accept: str = "application/json",
                 allow_not_found: bool = False) -> HTTPResult:
        _validate_provider_url(url)
        if self._requests >= self.request_cap:
            raise OSINTGuardError("global public-lookup request cap reached")
        used = self._per_provider.get(provider, 0)
        if used >= self.per_provider_cap:
            raise OSINTGuardError(f"per-provider request cap reached for {provider}")
        now = self.clock()
        if self._last_request is not None:
            remaining = self.min_interval - (now - self._last_request)
            if remaining > 0:
                self.sleep(remaining)
                now = self.clock()
        headers = {
            "User-Agent": GENERIC_USER_AGENT,
            "Accept": accept,
            "Cache-Control": "no-cache",
        }
        # Count attempts before transport: failures cannot be used for an unbounded retry loop.
        self._requests += 1
        self._per_provider[provider] = used + 1
        self._last_request = now
        result = self.transport(url, headers, TIMEOUT_SECONDS, MAX_RESPONSE_BYTES)
        _validate_provider_url(result.final_url)
        if len(result.body) > MAX_RESPONSE_BYTES:
            raise OSINTGuardError("transport returned an over-cap response")
        if not 200 <= int(result.status) < 300 and not (allow_not_found and result.status == 404):
            raise OSINTGuardError(f"{provider} returned HTTP status {result.status}")
        return result

    @staticmethod
    def _json(result: HTTPResult) -> Any:
        content_type = str(result.headers.get("Content-Type", "")).lower()
        if "json" not in content_type and not result.body.lstrip().startswith((b"{", b"[")):
            raise OSINTGuardError("provider response is not JSON")
        try:
            return json.loads(result.body.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise OSINTGuardError("provider returned malformed JSON") from exc

    def rdap(self, value: str) -> list[Evidence]:
        text = str(value).strip()
        try:
            parsed_ip = ipaddress.ip_address(text.strip("[]"))
        except ValueError:
            parsed_ip = None
        if parsed_ip is not None:
            query = _public_ip(text)
            kind = "ip"
        else:
            query = _domain(text)
            kind = "domain"
        query = self._guard_value(kind, query)
        url = "https://rdap.org/" + kind + "/" + urllib.parse.quote(query, safe="")
        result = self._request("rdap", url)
        doc = self._json(result)
        rows: list[Evidence] = []
        if isinstance(doc, dict):
            for rank, field in ((100, "name"), (96, "handle"), (92, "startAddress"),
                                (91, "endAddress"), (88, "port43")):
                if doc.get(field) not in (None, ""):
                    rows.append(Evidence(rank, "RDAP", field, doc[field], result.final_url))
            for event in doc.get("events", [])[:16] if isinstance(doc.get("events"), list) else []:
                if isinstance(event, dict) and event.get("eventAction") and event.get("eventDate"):
                    rows.append(Evidence(84, "RDAP", str(event["eventAction"]),
                                         event["eventDate"], result.final_url))
            for ns in doc.get("nameservers", [])[:32] if isinstance(doc.get("nameservers"), list) else []:
                if isinstance(ns, dict) and ns.get("ldhName"):
                    rows.append(Evidence(80, "RDAP", "nameserver", ns["ldhName"], result.final_url))
        return rows

    def dns(self, domain: str, record_type: str = "A") -> list[Evidence]:
        name = self._guard_value("domain", _domain(domain))
        rtype = record_type.upper()
        if rtype not in {"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV"}:
            raise OSINTGuardError("unsupported DNS record type")
        query = urllib.parse.urlencode({"name": name, "type": rtype})
        url = "https://cloudflare-dns.com/dns-query?" + query
        result = self._request("dns", url, accept="application/dns-json")
        doc = self._json(result)
        rows = []
        answers = doc.get("Answer", []) if isinstance(doc, dict) else []
        for answer in answers[:64] if isinstance(answers, list) else []:
            if isinstance(answer, dict) and "data" in answer:
                rows.append(Evidence(95, "Cloudflare DNS", rtype, answer["data"],
                                     result.final_url, "DNS evidence only; verify TTL/history and ownership"))
        return rows

    def certificate_transparency(self, domain: str) -> list[Evidence]:
        name = self._guard_value("domain", _domain(domain))
        query = urllib.parse.urlencode({"q": "%25." + name, "output": "json"})
        result = self._request("crt.sh", "https://crt.sh/?" + query)
        doc = self._json(result)
        seen: set[str] = set()
        rows = []
        for item in doc[:512] if isinstance(doc, list) else []:
            if not isinstance(item, dict):
                continue
            for candidate in str(item.get("name_value", "")).splitlines():
                candidate = candidate.strip().lower().removeprefix("*.")
                if (candidate == name or candidate.endswith("." + name)) and candidate not in seen:
                    seen.add(candidate)
                    rows.append(Evidence(90, "crt.sh", "certificate_name", candidate,
                                         result.final_url,
                                         "certificate observation only; it does not prove a live host"))
        return rows[:128]

    def wayback(self, target: str) -> list[Evidence]:
        raw = self._guard_value("url", target)
        parsed = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            raise OSINTGuardError("Wayback target must be one HTTP(S) URL/domain")
        if any(key.casefold() in {"token", "key", "api_key", "apikey", "secret", "password", "auth"}
               for key, _value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)):
            raise OSINTGuardError("credential-shaped Wayback query parameters are forbidden")
        host = _domain(parsed.hostname)
        if _is_blocked_name(host, self.blocked_targets):
            raise OSINTGuardError("forbidden Wayback target")
        query = urllib.parse.urlencode({
            "url": raw, "output": "json", "fl": "timestamp,original,statuscode,digest",
            "filter": "statuscode:200", "collapse": "digest", "limit": "25",
        })
        result = self._request("wayback", "https://web.archive.org/cdx/search/cdx?" + query)
        doc = self._json(result)
        rows = []
        if isinstance(doc, list) and doc:
            header = doc[0] if isinstance(doc[0], list) else []
            for item in doc[1:26]:
                if not isinstance(item, list):
                    continue
                record = dict(zip(header, item))
                rows.append(Evidence(92, "Wayback CDX", "capture", record,
                                     result.final_url,
                                     "archive metadata only; inspect the cited capture before concluding"))
        return rows

    def reverse_geocode(self, coordinate: str | tuple[float, float]) -> list[Evidence]:
        lat, lon = _coordinate(coordinate)
        canonical = f"{lat:.7f},{lon:.7f}"
        self._guard_value("coordinate", canonical)
        query = urllib.parse.urlencode({"format": "jsonv2", "lat": lat, "lon": lon,
                                        "addressdetails": 1, "zoom": 18})
        result = self._request("nominatim", "https://nominatim.openstreetmap.org/reverse?" + query)
        doc = self._json(result)
        if not isinstance(doc, dict) or doc.get("error"):
            return []
        value = {k: doc[k] for k in ("display_name", "lat", "lon", "type", "address") if k in doc}
        return [Evidence(100, "OpenStreetMap Nominatim", "reverse_geocode", value,
                         result.final_url,
                         "ranked location candidate; cross-check the visible scene and let the human pin")]

    def geocode(self, query_text: str) -> list[Evidence]:
        query_text = self._guard_value("place", query_text)
        query = urllib.parse.urlencode({"format": "jsonv2", "q": query_text,
                                        "addressdetails": 1, "limit": 5})
        result = self._request("nominatim", "https://nominatim.openstreetmap.org/search?" + query)
        doc = self._json(result)
        rows = []
        for index, item in enumerate(doc[:5] if isinstance(doc, list) else []):
            if isinstance(item, dict):
                value = {k: item[k] for k in ("display_name", "lat", "lon", "type", "importance")
                         if k in item}
                rows.append(Evidence(100 - index * 5, "OpenStreetMap Nominatim", "geocode", value,
                                     result.final_url,
                                     "ranked location candidate; cross-check scene, source, and requested precision"))
        return rows

    def search(self, query_text: str) -> list[Evidence]:
        query_text = self._guard_value("search", query_text)
        query = urllib.parse.urlencode({"q": query_text, "kl": "wt-wt"})
        result = self._request("duckduckgo", "https://html.duckduckgo.com/html/?" + query,
                               accept="text/html")
        text = result.body.decode("utf-8", "replace")
        rows = []
        # Deliberately tiny parser: result titles/URLs are leads, not trusted HTML.
        rx = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
        for index, match in enumerate(rx.finditer(text)):
            href = urllib.parse.unquote(match.group(1))
            parsed = urllib.parse.urlsplit(href)
            if parsed.hostname and (parsed.hostname == "duckduckgo.com"
                                    or parsed.hostname.endswith(".duckduckgo.com")):
                href = urllib.parse.parse_qs(parsed.query).get("uddg", [href])[0]
            title = re.sub(r"<[^>]+>", "", match.group(2))
            title = re.sub(r"\s+", " ", title).strip()
            if title and href.startswith(("http://", "https://")):
                rows.append(Evidence(90 - index, "DuckDuckGo HTML", "search_result",
                                     {"title": title[:300], "url": href[:2048]}, result.final_url,
                                     "search result is an unverified lead; open and corroborate manually"))
            if len(rows) >= 10:
                break
        return rows

    def username(self, username: str, providers: tuple[str, ...] = ("github",)) -> list[Evidence]:
        name = str(username).strip().lstrip("@")
        if not USERNAME_RE.fullmatch(name):
            raise OSINTGuardError("invalid username")
        name = self._guard_value("username", name)
        if not 1 <= len(providers) <= 3 or len(set(providers)) != len(providers):
            raise OSINTGuardError("choose one to three distinct profile providers")
        rows = []
        builders = {
            "github": ("GitHub", "https://api.github.com/users/" + urllib.parse.quote(name, safe="")),
            "gitlab": ("GitLab", "https://gitlab.com/api/v4/users?username=" + urllib.parse.quote(name, safe="")),
            "reddit": ("Reddit", "https://www.reddit.com/user/" + urllib.parse.quote(name, safe="") + "/about.json"),
            "keybase": ("Keybase", "https://keybase.io/_/api/1.0/user/lookup.json?username=" + urllib.parse.quote(name, safe="")),
        }
        for index, provider in enumerate(providers):
            if provider not in builders:
                raise OSINTGuardError(f"unsupported profile provider: {provider}")
            label, url = builders[provider]
            result = self._request(provider, url, allow_not_found=True)
            if result.status == 404:
                rows.append(Evidence(40, label, "profile_absence", {"username": name, "status": 404},
                                     result.final_url,
                                     "point-in-time absence only; never treat it as proof of identity"))
                continue
            doc = self._json(result)
            # Return bounded provider data; do not pronounce that accounts belong together.
            if isinstance(doc, list):
                doc = doc[:5]
            rows.append(Evidence(90 - index * 3, label, "profile_observation", doc,
                                 result.final_url,
                                 "exact-name observation only; human must compare independent attributes"))
        return rows

    def package_registry(self, package: str, provider: str = "pypi") -> list[Evidence]:
        """Fetch one exact public package record; never search prefixes or related names."""
        name = str(package).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.@/+~-]{1,214}", name):
            raise OSINTGuardError("invalid exact package name")
        name = self._guard_value("package", name)
        provider = provider.lower()
        if provider == "pypi":
            url = "https://pypi.org/pypi/" + urllib.parse.quote(name, safe="") + "/json"
        elif provider == "npm":
            url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
        else:
            raise OSINTGuardError("registry must be pypi or npm")
        result = self._request(provider, url, allow_not_found=True)
        if result.status == 404:
            return [Evidence(35, provider, "package_absence", {"name": name, "status": 404},
                             result.final_url, "point-in-time absence only; never infer ownership")]
        doc = self._json(result)
        if not isinstance(doc, dict):
            return []
        if provider == "pypi":
            info = doc.get("info", {}) if isinstance(doc.get("info"), dict) else {}
            value = {key: info.get(key) for key in
                     ("name", "version", "author", "author_email", "home_page", "project_urls")
                     if info.get(key) not in (None, "")}
        else:
            value = {key: doc.get(key) for key in
                     ("name", "dist-tags", "homepage", "repository", "maintainers")
                     if doc.get(key) not in (None, "")}
        return [Evidence(88, provider, "package_record", value, result.final_url,
                         "public registry metadata is a lead; corroborate maintainer attribution")]

    def email_public(self, email: str, *, challenge_identifier: bool = False) -> list[Evidence]:
        """Search one attested challenge e-mail via an exact public-search query.

        No breach API is called: HIBP requires credentials and may expose private data.  The
        explicit attestation plus ``OSINT_PRIVATE_IDENTIFIERS`` protects player identity; the
        returned public-index observations remain unverified leads.
        """
        address = self._guard_value("email", email.lower(), email_attested=challenge_identifier)
        return self.search_for_bound_lead('"' + address + '"')

    def search_for_bound_lead(self, query_text: str) -> list[Evidence]:
        """Search the exact attested e-mail already bound by :meth:`email_public`.

        This is intentionally not a general derived-query escape hatch: accepting arbitrary text
        here would bypass both the one-lead invariant and the normal e-mail/target guards.
        """
        expected = f'"{self._lead_value}"' if self._lead_value is not None else None
        if self._lead_kind != "email" or query_text != expected:
            raise OSINTGuardError("derived search must be the exact attested bound e-mail")
        # Re-run all value guards without rebinding.  This keeps later changes to the forbidden
        # target/privacy rules effective at the final transport boundary too.
        address = self._guard_value("email", self._lead_value, email_attested=True)
        if query_text != f'"{address}"':  # defensive equality after canonical validation
            raise OSINTGuardError("derived search differs from the bound lead")
        query = urllib.parse.urlencode({"q": query_text, "kl": "wt-wt"})
        result = self._request("duckduckgo", "https://html.duckduckgo.com/html/?" + query,
                               accept="text/html")
        text = result.body.decode("utf-8", "replace")
        rows = []
        rx = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.I | re.S)
        for index, match in enumerate(rx.finditer(text)):
            title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(2))).strip()
            href = urllib.parse.unquote(match.group(1))
            parsed = urllib.parse.urlsplit(href)
            if parsed.hostname and (parsed.hostname == "duckduckgo.com"
                                    or parsed.hostname.endswith(".duckduckgo.com")):
                href = urllib.parse.parse_qs(parsed.query).get("uddg", [href])[0]
            if title and href.startswith(("http://", "https://")):
                rows.append(Evidence(85 - index, "DuckDuckGo HTML", "public_occurrence",
                                     {"title": title[:300], "url": href[:2048]}, result.final_url))
            if len(rows) >= 10:
                break
        return rows


def lookup(client: PublicOSINTClient, kind: str, value: str, *, record_type: str = "A",
           challenge_identifier: bool = False) -> list[dict[str, Any]]:
    """Run one lookup kind and return serializable ranked evidence rows."""
    normalized = kind.strip().lower().replace("-", "_")
    if normalized in {"domain", "rdap", "whois", "ip"}:
        rows = client.rdap(value)
    elif normalized == "dns":
        rows = client.dns(value, record_type)
    elif normalized in {"ct", "certificate", "certificate_transparency"}:
        rows = client.certificate_transparency(value)
    elif normalized in {"wayback", "archive"}:
        rows = client.wayback(value)
    elif normalized in {"reverse_geocode", "gps", "coordinate"}:
        rows = client.reverse_geocode(value)
    elif normalized in {"geocode", "place", "landmark", "skyline"}:
        rows = client.geocode(value)
    elif normalized in {"search", "paste", "record"}:
        rows = client.search(value)
    elif normalized in {"username", "handle"}:
        rows = client.username(value, ("github", "gitlab", "reddit"))
    elif normalized in {"email", "e_mail"}:
        rows = client.email_public(value, challenge_identifier=challenge_identifier)
    elif normalized in {"pypi", "npm"}:
        rows = client.package_registry(value, normalized)
    else:
        raise OSINTGuardError(f"unsupported public lookup kind: {kind}")
    rows.sort(key=lambda row: (-row.rank, row.provider, row.kind))
    return [dataclasses.asdict(row) for row in rows]


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise OSINTGuardError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="one polite, capped public-source OSINT lookup")
    parser.add_argument("kind", help="rdap/domain/ip, dns, ct, wayback, geocode, gps, search, username, email")
    parser.add_argument("value", help="exact single challenge lead")
    parser.add_argument("--online", action="store_true", help="required acknowledgement that one public lookup may run")
    parser.add_argument("--record-type", default="A", help="DNS type (default A)")
    parser.add_argument("--challenge-identifier", action="store_true",
                        help="attest that an e-mail is challenge evidence, never player identity")
    parser.add_argument("--request-cap", type=int, default=4)
    parser.add_argument("--wrong-count", type=int, default=0,
                        help="wrong answers already on this challenge (Workspace.wrong_count); gates the "
                             "guess budget")
    parser.add_argument("--guess-budget", type=int, default=DEFAULT_GUESS_BUDGET,
                        help="candidate-feeding lookups allowed before a player must approve more")
    parser.add_argument("--approvals-left", type=int, default=0,
                        help="unused player post-guard approvals that still permit a lookup")
    try:
        args = parser.parse_args(argv)
        if not args.online:
            raise OSINTGuardError("online lookup is opt-in; add --online after reviewing the lead")
        blocked = guess_budget_block(args.wrong_count, args.guess_budget, args.approvals_left)
        if blocked is not None:
            print(f"osint_online: {blocked}", file=sys.stderr)
            return 3
        client = PublicOSINTClient(request_cap=args.request_cap)
        rows = lookup(client, args.kind, args.value, record_type=args.record_type,
                      challenge_identifier=args.challenge_identifier)
        print(json.dumps({
            "lead_kind": args.kind,
            "evidence": rows,
            "requests": client.request_count,
            "requires_human_pin": True,
            "warning": "candidates are unverified evidence; never submit the top row automatically",
        }, indent=2, ensure_ascii=False))
        return 0
    except (OSINTGuardError, OSError, ValueError, socket.timeout) as exc:
        print(f"osint_online: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
