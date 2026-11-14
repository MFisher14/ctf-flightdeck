"""Scan-index clients (B-114): keyed lookups on Shodan, Censys, FOFA and Netlas, unioned.

An origin behind Tor or a CDN, and the back-office panel next to it, are found by asking the internet
scan indexes: "which host:port serves this certificate / this favicon / this page title?" and then
"what else listens on that host?". At CSCTF the anonymous routes failed (bot checks, quota, a browser
User-Agent retry a classifier refused) and the scanners disagreed about one host's ports. This module
is the keyed, official-API route, and it unions the providers instead of trusting one.

    from ctf import scan_index
    client = scan_index.ScanIndexClient()                        # event profile, workdir and keys from env
    rep = client.lookup(scan_index.cert_pivot(sha256="ab12...", sha1="cd34...", serial="6FDB..."))
    rep = client.lookup(scan_index.favicon_pivot(mmh3=-123, md5="...", sha256="..."))
    rep = client.lookup(scan_index.title_pivot("NestEgg Capital"))
    rep = client.lookup(scan_index.host_pivot("203.0.113.5"))    # the back-office port union
    rep.results          # one ProviderResult per provider: ok / skipped / refused / no_key / budget / ...
    rep.services         # the union: one Service per ip:port, with who saw it and who did not
    scan_index.usage(workdir)                                    # the per-provider quota ledger

It is not a general HTTP client and not a scanner. The rules it keeps:

* **Closed hosts.** `OFFICIAL_ENDPOINTS` is the whole list; a caller cannot add one. The only override
  is a loopback literal (127.0.0.0/8, ::1), which is how the tests and a rehearsal point a provider at
  a local fake. Nothing here ever touches a challenge host: a lookup reads a third party's index.
* **Scope.** Every request runs `ctf.scope.check_public_fetch` first, so an event that does not list
  the provider's host in `rules.public_fetch_allow` is refused before any byte leaves.
* **Keys.** Read only from the named `CTF_SCAN_INDEX_*` variables through `ctf.env`. A key is never
  printed, logged, cached or written to the ledger; every reason string, row and cache file is scrubbed
  of it, and a redirect is never followed (Shodan and FOFA take the key in the query string, so a
  redirect would carry it to another host). Registering the accounts is a human step.
* **Official APIs only.** No anonymous scraping of result pages, no browser User-Agent, no retry
  around a bot check: a 401/403 is reported as `auth` and the provider is left alone.
* **Quota.** Every request that got an HTTP answer is one `scan_index.query` ledger row. A provider is
  asked at most `budget` times per workdir (default `DEFAULT_BUDGET`, `CTF_SCAN_INDEX_BUDGET[_<P>]`);
  over that it is not asked and says so. An answer is cached under `<workdir>/scan-index/`, so the same
  pivot (a sibling challenge on the same origin) costs nothing the second time.
* **No silent gaps.** A provider that was not asked (no key, no budget, pivot form it cannot take,
  scope) is a result with a named reason, never a missing row: "no hit" and "not asked" stay distinct.
* **Untrusted data.** Titles and archived bodies come from whoever runs the scanned host. They are
  data: control characters are stripped, lengths are capped, and nothing in them is acted on.

Each provider indexes a different form of the same thing, which is why a pivot carries several:

    pivot     Shodan                       Censys (Platform, CenQL)                      FOFA            Netlas
    cert      ssl.cert.fingerprint (SHA-1) host.services.cert.fingerprint_sha256         cert.sn         certificate.fingerprint_sha256
              or ssl.cert.serial (decimal)                                               (decimal serial)
    favicon   http.favicon.hash (mmh3)     ...http.favicons.hash_md5 / _sha256 / _shodan icon_hash (mmh3) http.favicon.hash_sha256
    title     http.title                   host.services.endpoints.http.html_title       title           http.title
    host      /shodan/host/{ip}            /v3/global/asset/host/{ip}                    ip="..."        ip:"..."

`ctf.favicon.fingerprint` (B-089) gives all three favicon hashes and `ctf.tor.leaf_cert_info` (B-091)
the SHA-256, SHA-1 and serial of a leaf, so a pivot built from the captured file reaches every provider.
InternetDB (Shodan's keyless port list) joins the host union only.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import html as _html
import http.client
import ipaddress
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import env, event, ledger, paths, scope

__all__ = [
    "OFFICIAL_ENDPOINTS", "KEY_ENV", "KEYED_PROVIDERS", "PROVIDERS", "DEFAULT_BUDGET", "EVENT",
    "ScanIndexError", "ScanIndexRefused", "PivotError", "Unsupported",
    "Pivot", "cert_pivot", "favicon_pivot", "title_pivot", "host_pivot",
    "Request", "build_request", "Row", "parse_rows", "Finding", "extract_findings",
    "Service", "union", "cdn_label", "ProviderResult", "Report", "ProviderUsage", "usage",
    "budget_for", "ScanIndexClient",
]

# The closed provider list. A request can be built for these hosts and no other.
OFFICIAL_ENDPOINTS: dict[str, str] = {
    "shodan": "https://api.shodan.io",
    "censys": "https://api.platform.censys.io",
    "fofa": "https://fofa.info",
    "netlas": "https://app.netlas.io",
    "internetdb": "https://internetdb.shodan.io",
}
PROVIDERS = tuple(OFFICIAL_ENDPOINTS)
# The one variable each key is read from. InternetDB takes no key.
KEY_ENV: dict[str, str] = {
    "shodan": "CTF_SCAN_INDEX_SHODAN_KEY",
    "censys": "CTF_SCAN_INDEX_CENSYS_TOKEN",      # a Censys Platform personal access token
    "fofa": "CTF_SCAN_INDEX_FOFA_KEY",
    "netlas": "CTF_SCAN_INDEX_NETLAS_KEY",
}
KEYED_PROVIDERS = tuple(KEY_ENV)
CENSYS_ORG_ENV = "CTF_SCAN_INDEX_CENSYS_ORG"      # optional: the organization id of a paid Censys plan
BUDGET_ENV = "CTF_SCAN_INDEX_BUDGET"              # requests per provider per workdir; _<PROVIDER> narrows it
DEFAULT_BUDGET = 25

EVENT = "scan_index.query"                        # the ledger row: one per request that got an HTTP answer
CACHE_DIR = "scan-index"
USER_AGENT = "ctf-tools-scan-index/1 (B-114; official API client)"
TIMEOUT_SECONDS = 20.0
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_SIZE = 50                                 # results asked of a provider that takes a page size
MAX_SIZE = 100
TITLE_MAX = 200                                   # a title pivot is one short line
BODY_SNIPPET = 4000                               # chars of an archived body kept on a row
BODY_SCAN = 512 * 1024                            # chars of an archived body searched for findings
MAX_FINDINGS = 20
FOFA_FIELDS = "ip,port,protocol,host,title,as_organization"
NETLAS_FIELDS = ("ip,port,protocol,host,uri,isp,last_updated,http.title,http.status_code,http.body,"
                 "certificate.fingerprint_sha256")
CENSYS_HOST_ACCEPT = "application/vnd.censys.api.v3.host.v1+json"
PIVOT_KINDS = ("cert", "favicon", "title", "host")
SEARCH_PROVIDERS = ("shodan", "censys", "fofa", "netlas")
HOST_PROVIDERS = ("shodan", "censys", "fofa", "netlas", "internetdb")
PUBLIC_PORTS = (80, 443)

# Statuses of a ProviderResult. Only "ok" is an answer; the rest say why there is none.
OK, SKIPPED, REFUSED, NO_KEY, BUDGET, QUOTA, AUTH, ERROR = (
    "ok", "skipped", "refused", "no_key", "budget", "quota", "auth", "error")

# Cloudflare's published edge ranges: a candidate inside one is the CDN, not the origin.
CLOUDFLARE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32"))
CDN_ORG_WORDS = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri",
                 "stackpath")


class ScanIndexError(RuntimeError):
    """A provider request failed in a way that is not a scope refusal (transport, malformed answer)."""


class ScanIndexRefused(scope.OutOfScope):
    """The event profile does not allow the provider's host (or there is no profile)."""


class PivotError(ValueError):
    """A pivot value is not a certificate hash, favicon hash, title or IP address."""


class Unsupported(Exception):
    """A provider cannot take this pivot in the form given; the message says which form it needs."""


# ---------------------------------------------------------------------------------------------- pivots

@dataclass(frozen=True)
class Pivot:
    """One thing to look up. `kind` is cert, favicon, title or host; the other fields are the forms of
    it the providers index (see the module table)."""
    kind: str
    sha256: str | None = None      # cert: fingerprint; favicon: SHA-256 of the icon bytes
    sha1: str | None = None        # cert fingerprint
    serial: str | None = None      # cert serial, uppercase hex
    mmh3: int | None = None        # favicon: signed Shodan MurmurHash3 (the icon_hash)
    md5: str | None = None         # favicon: MD5 of the icon bytes
    title: str | None = None
    ip: str | None = None

    @property
    def value(self) -> str:
        """The value shown in reports and written to the ledger."""
        if self.kind == "cert":
            return self.sha256 or self.sha1 or f"serial:{self.serial}"
        if self.kind == "favicon":
            if self.mmh3 is not None:
                return str(self.mmh3)
            return self.md5 or self.sha256 or ""
        return (self.title if self.kind == "title" else self.ip) or ""

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"kind": self.kind, "value": self.value}
        for name in ("sha256", "sha1", "serial", "mmh3", "md5", "title", "ip"):
            v = getattr(self, name)
            if v is not None:
                out[name] = v
        return out


def _hex(value: object, length: int, what: str) -> str:
    text = re.sub(r"[\s:]", "", str(value)).lower()
    if len(text) != length or not re.fullmatch(r"[0-9a-f]+", text):
        raise PivotError(f"{what} must be {length} hex characters (colons and spaces are ignored), "
                         f"got {len(text)} character(s)")
    return text


def cert_pivot(sha256: str | None = None, *, sha1: str | None = None,
               serial: str | None = None) -> Pivot:
    """A certificate pivot. Give every form you have: Censys and Netlas index the SHA-256, Shodan the
    SHA-1 (or the serial), FOFA the serial. `serial` is hex, the way `openssl x509 -serial` and
    `ctf tor-fetch` print it."""
    if not (sha256 or sha1 or serial):
        raise PivotError("a certificate pivot needs a SHA-256, a SHA-1 or a serial")
    ser = None
    if serial:
        ser = re.sub(r"[\s:]", "", str(serial)).upper()
        if ser.startswith("0X"):
            ser = ser[2:]
        if not re.fullmatch(r"[0-9A-F]{1,80}", ser):
            raise PivotError("a certificate serial must be hex (as `openssl x509 -serial` prints it)")
    return Pivot("cert", sha256=_hex(sha256, 64, "a certificate SHA-256") if sha256 else None,
                 sha1=_hex(sha1, 40, "a certificate SHA-1") if sha1 else None, serial=ser)


def favicon_pivot(mmh3: int | str | None = None, *, md5: str | None = None,
                  sha256: str | None = None) -> Pivot:
    """A favicon pivot. `mmh3` is the signed Shodan icon_hash (Shodan, FOFA), `md5` and `sha256` are
    over the raw icon bytes (Censys, Netlas). `ctf.favicon.fingerprint(data)` gives all three."""
    if mmh3 is None and not md5 and not sha256:
        raise PivotError("a favicon pivot needs the mmh3 icon_hash, an MD5 or a SHA-256")
    m = None
    if mmh3 is not None:
        if isinstance(mmh3, bool):
            raise PivotError("the icon_hash is a signed 32-bit integer")
        try:
            m = int(str(mmh3).strip())
        except ValueError:
            raise PivotError("the icon_hash is a signed 32-bit integer") from None
        if not -2**31 <= m < 2**32:
            raise PivotError("the icon_hash is a signed 32-bit integer")
        if m >= 2**31:                 # the unsigned spelling of the same hash
            m -= 2**32
    return Pivot("favicon", mmh3=m, md5=_hex(md5, 32, "a favicon MD5") if md5 else None,
                 sha256=_hex(sha256, 64, "a favicon SHA-256") if sha256 else None)


def title_pivot(title: str) -> Pivot:
    """A page-title pivot: one short printable line, sent as an exact phrase."""
    if not isinstance(title, str):
        raise PivotError("a title pivot is text")
    text = title.strip()
    if not text:
        raise PivotError("a title pivot is empty")
    if len(text) > TITLE_MAX:
        raise PivotError(f"a title pivot is at most {TITLE_MAX} characters, got {len(text)}")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise PivotError("a title pivot is one printable line (no control characters)")
    return Pivot("title", title=text)


def host_pivot(ip: str) -> Pivot:
    """A host pivot: one IP address whose indexed ports are unioned across the providers."""
    try:
        addr = ipaddress.ip_address(str(ip).strip().strip("[]"))
    except ValueError:
        raise PivotError(f"a host pivot is one IP address, got {str(ip)[:60]!r}") from None
    return Pivot("host", ip=str(addr))


# -------------------------------------------------------------------------------------------- requests

@dataclass(frozen=True)
class Request:
    """One provider request, without its key: the client adds the key when it sends."""
    provider: str
    op: str                                        # "search" or "host"
    method: str
    path: str
    params: tuple[tuple[str, str], ...] = ()
    body: Mapping[str, Any] | None = None
    query: str = ""                                # the provider-syntax query, for reports and the ledger
    accept: str = "application/json"

    def cache_key(self) -> str:
        blob = json.dumps([self.provider, self.op, self.method, self.path, list(self.params),
                           self.body], sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]


def _quoted(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _size(size: int) -> int:
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_SIZE:
        raise ValueError(f"size must be an int in 1..{MAX_SIZE}")
    return size


def build_request(provider: str, pivot: Pivot, *, size: int = DEFAULT_SIZE) -> Request:
    """The one request `provider` gets for `pivot`. Raises `Unsupported` (naming the form the provider
    needs) when the pivot does not carry it, and ValueError for an unknown provider or pivot kind."""
    if provider not in OFFICIAL_ENDPOINTS:
        raise ValueError(f"unknown scan-index provider {provider!r} (known: {', '.join(PROVIDERS)})")
    if pivot.kind not in PIVOT_KINDS:
        raise ValueError(f"unknown pivot kind {pivot.kind!r}")
    size = _size(size)
    kind = pivot.kind
    ip_path = urllib.parse.quote(pivot.ip or "", safe="")

    if provider == "internetdb":
        if kind != "host":
            raise Unsupported("InternetDB answers only an IP lookup (the host pivot)")
        return Request(provider, "host", "GET", f"/{ip_path}", query=f"host {pivot.ip}")

    if provider == "shodan":
        if kind == "host":
            return Request(provider, "host", "GET", f"/shodan/host/{ip_path}", query=f"host {pivot.ip}")
        if kind == "cert":
            if pivot.sha1:
                q = f"ssl.cert.fingerprint:{pivot.sha1}"
            elif pivot.serial:
                q = f"ssl.cert.serial:{int(pivot.serial, 16)}"
            else:
                raise Unsupported("Shodan indexes a certificate by its SHA-1 fingerprint or its serial, "
                                  "not the SHA-256: give the SHA-1 or the serial (or the certificate file)")
        elif kind == "favicon":
            if pivot.mmh3 is None:
                raise Unsupported("Shodan indexes a favicon by the mmh3 icon_hash: give the icon_hash "
                                  "(or the icon file)")
            q = f"http.favicon.hash:{pivot.mmh3}"
        else:
            q = f'http.title:"{_quoted(pivot.title or "")}"'
        return Request(provider, "search", "GET", "/shodan/host/search", params=(("query", q),), query=q)

    if provider == "censys":
        if kind == "host":
            return Request(provider, "host", "GET", f"/v3/global/asset/host/{ip_path}",
                           query=f"host {pivot.ip}", accept=CENSYS_HOST_ACCEPT)
        if kind == "cert":
            if not pivot.sha256:
                raise Unsupported("Censys host search pivots on the certificate SHA-256: give the SHA-256 "
                                  "(or the certificate file)")
            q = f'host.services.cert.fingerprint_sha256 = "{pivot.sha256}"'
        elif kind == "favicon":
            base = "host.services.endpoints.http.favicons"
            if pivot.md5:
                q = f'{base}.hash_md5 = "{pivot.md5}"'
            elif pivot.sha256:
                q = f'{base}.hash_sha256 = "{pivot.sha256}"'
            else:
                q = f'{base}.hash_shodan = "{pivot.mmh3}"'
        else:
            q = f'host.services.endpoints.http.html_title: "{_quoted(pivot.title or "")}"'
        return Request(provider, "search", "POST", "/v3/global/search/query",
                       body={"query": q, "page_size": size}, query=q)

    if provider == "fofa":
        if kind == "host":
            q = f'ip="{pivot.ip}"'
        elif kind == "cert":
            if not pivot.serial:
                raise Unsupported("FOFA pivots on the certificate serial (cert.sn): give the serial "
                                  "(or the certificate file)")
            q = f'cert.sn="{int(pivot.serial, 16)}"'
        elif kind == "favicon":
            if pivot.mmh3 is None:
                raise Unsupported("FOFA indexes a favicon by the mmh3 icon_hash: give the icon_hash "
                                  "(or the icon file)")
            q = f'icon_hash="{pivot.mmh3}"'
        else:
            q = f'title="{_quoted(pivot.title or "")}"'
        qb64 = base64.b64encode(q.encode("utf-8")).decode("ascii")
        return Request(provider, "host" if kind == "host" else "search", "GET", "/api/v1/search/all",
                       params=(("qbase64", qb64), ("fields", FOFA_FIELDS), ("page", "1"),
                               ("size", str(size))), query=q)

    # netlas
    if kind == "host":
        q = f'ip:"{pivot.ip}"'
    elif kind == "cert":
        if not pivot.sha256:
            raise Unsupported("Netlas pivots on the certificate SHA-256: give the SHA-256 "
                              "(or the certificate file)")
        q = f"certificate.fingerprint_sha256:{pivot.sha256}"
    elif kind == "favicon":
        if not pivot.sha256:
            raise Unsupported("Netlas indexes a favicon by the SHA-256 of its bytes: give the SHA-256 "
                              "(or the icon file)")
        q = f"http.favicon.hash_sha256:{pivot.sha256}"
    else:
        q = f'http.title:"{_quoted(pivot.title or "")}"'
    return Request(provider, "host" if kind == "host" else "search", "GET", "/api/responses/",
                   params=(("q", q), ("start", "0"), ("fields", NETLAS_FIELDS),
                           ("source_type", "include")), query=q)


# ------------------------------------------------------------------------------------- rows and findings

_UUID_RE = re.compile(r"(?<![0-9A-Fa-f-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
                      r"[0-9A-Fa-f]{12}(?![0-9A-Fa-f-])")
_HEX_RE = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,128}(?![0-9A-Za-z])")
_LABEL_RE = re.compile(
    r"(?i)\b((?:api|admin|access|auth|ops|recovery|session)?[ _-]?(?:key|token|secret|passcode|password|flag))"
    r"\s*(?:is|[:=])\s*[\"']?([A-Za-z0-9][A-Za-z0-9_\-./+{}]{5,120})")
_TAG_RE = re.compile(r"<[^>]{0,2000}>")


@dataclass(frozen=True)
class Finding:
    """A value lifted from an archived body: a lead to confirm on the live service, never an answer."""
    kind: str        # "uuid", "hex" or "labelled"
    value: str
    label: str = ""  # for "labelled": the word before the value ("admin key")

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, **({"label": self.label} if self.label else {})}


def extract_findings(body: str | None) -> tuple[Finding, ...]:
    """UUIDs, long hex strings and `label: value` pairs (key, token, secret, password, flag) in an
    archived page body, at most MAX_FINDINGS, each value once: UUIDs first, then labelled values, then
    hex. A UUID or hex value that also follows a label keeps its kind and gains the label. The body is
    scanned both raw (values in attributes) and with its tags removed (a label and its value in
    neighbouring elements)."""
    if not body:
        return ()
    raw = body[:BODY_SCAN]
    text = re.sub(r"\s+", " ", _html.unescape(_TAG_RE.sub(" ", raw)))
    out: list[Finding] = []
    at: dict[str, int] = {}                          # value (lower-cased) -> its place in `out`

    def _add(kind: str, value: str, label: str = "") -> None:
        key = value.lower()
        if key in at:
            if label and not out[at[key]].label:     # the same value, now with the word in front of it
                out[at[key]] = Finding(out[at[key]].kind, out[at[key]].value, label)
        elif len(out) < MAX_FINDINGS:
            at[key] = len(out)
            out.append(Finding(kind, value, label))

    for source in (text, raw):
        for m in _UUID_RE.finditer(source):
            _add("uuid", m.group(0))
    for m in _LABEL_RE.finditer(text):
        _add("labelled", m.group(2).rstrip(".,;"), re.sub(r"[ _-]+", " ", m.group(1).strip().lower()))
    for source in (text, raw):
        for m in _HEX_RE.finditer(source):
            _add("hex", m.group(0))
    return tuple(out)


@dataclass(frozen=True)
class Row:
    """One indexed service as one provider reported it."""
    provider: str
    ip: str
    port: int | None = None
    transport: str | None = None
    service: str | None = None
    title: str | None = None
    hostnames: tuple[str, ...] = ()
    org: str | None = None
    seen: str | None = None            # when the provider last scanned it, as the provider wrote it
    http_status: int | None = None
    body: str | None = None            # the first BODY_SNIPPET characters of the archived body
    cert_sha256: str | None = None
    findings: tuple[Finding, ...] = ()

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"provider": self.provider, "ip": self.ip, "port": self.port}
        for name in ("transport", "service", "title", "org", "seen", "http_status", "body", "cert_sha256"):
            v = getattr(self, name)
            if v is not None:
                out[name] = v
        if self.hostnames:
            out["hostnames"] = list(self.hostnames)
        if self.findings:
            out["findings"] = [f.to_dict() for f in self.findings]
        return out

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Row":
        return cls(provider=str(d["provider"]), ip=str(d["ip"]), port=d.get("port"),
                   transport=d.get("transport"), service=d.get("service"), title=d.get("title"),
                   hostnames=tuple(d.get("hostnames") or ()), org=d.get("org"), seen=d.get("seen"),
                   http_status=d.get("http_status"), body=d.get("body"), cert_sha256=d.get("cert_sha256"),
                   findings=tuple(Finding(f["kind"], f["value"], f.get("label", ""))
                                  for f in d.get("findings") or ()))


def _d(x: object) -> dict:
    return x if isinstance(x, dict) else {}


def _l(x: object) -> list:
    return x if isinstance(x, list) else []


def _line(value: object, cap: int = 300) -> str | None:
    """Provider text as one printable line: control characters become spaces, the length is capped."""
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    text = "".join(c if c.isprintable() else " " for c in str(value))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:cap] or None


def _block(value: object) -> str | None:
    """A provider body: printable characters, newlines and tabs kept; other control characters dropped."""
    if not isinstance(value, str) or not value:
        return None
    return "".join(c for c in value if c.isprintable() or c in "\n\t") or None


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        n = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return n


def _port(value: object) -> int | None:
    n = _int(value)
    return n if n is not None and 0 < n < 65536 else None


def _names(value: object) -> tuple[str, ...]:
    out = []
    for item in _l(value) if not isinstance(value, str) else [value]:
        name = _line(item, 253)
        if name and name not in out:
            out.append(name)
    return tuple(out[:20])


def _row(provider: str, ip: object, port: object = None, *, transport: object = None,
         service: object = None, title: object = None, hostnames: object = (), org: object = None,
         seen: object = None, http_status: object = None, body: object = None,
         cert_sha256: object = None) -> Row | None:
    try:
        addr = str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        return None                       # a row with no usable address is not a host:port candidate
    full = _block(body)
    cert = re.sub(r"[\s:]", "", str(cert_sha256)).lower() if cert_sha256 else None
    return Row(provider=provider, ip=addr, port=_port(port), transport=_line(transport, 16),
               service=_line(service, 40), title=_line(title), hostnames=_names(hostnames),
               org=_line(org, 120), seen=_line(seen, 40), http_status=_int(http_status),
               body=full[:BODY_SNIPPET] if full else None,
               cert_sha256=cert if cert and re.fullmatch(r"[0-9a-f]{64}", cert) else None,
               findings=extract_findings(full))


def _shodan_banner(b: dict, ip: object = None) -> Row | None:
    http = _d(b.get("http"))
    fp = _d(_d(_d(b.get("ssl")).get("cert")).get("fingerprint"))
    return _row("shodan", b.get("ip_str") or ip, b.get("port"), transport=b.get("transport"),
                service=_d(b.get("_shodan")).get("module"), title=http.get("title"),
                hostnames=b.get("hostnames"), org=b.get("org") or b.get("isp"), seen=b.get("timestamp"),
                http_status=http.get("status"), body=http.get("html"), cert_sha256=fp.get("sha256"))


def _censys_host(res: dict, services: list) -> list[Row | None]:
    ip = res.get("ip")
    names = _d(res.get("dns")).get("names")
    org = _d(res.get("autonomous_system")).get("name")
    out: list[Row | None] = []
    for s in services:
        s = _d(s)
        http: dict = {}
        for ep in _l(s.get("endpoints")):
            if _d(_d(ep).get("http")):
                http = _d(_d(ep).get("http"))
                break
        out.append(_row("censys", ip, s.get("port"), transport=s.get("transport_protocol"),
                        service=s.get("protocol"), title=http.get("html_title"), hostnames=names, org=org,
                        seen=s.get("scan_time"), http_status=http.get("status_code"),
                        body=http.get("body"), cert_sha256=_d(s.get("cert")).get("fingerprint_sha256")))
    if not services:
        out.append(_row("censys", ip, None, hostnames=names, org=org))
    return out


def parse_rows(provider: str, op: str, doc: object) -> tuple[Row, ...]:
    """The rows in one provider answer (a decoded JSON document). Raises ScanIndexError when the
    document is not the shape the provider documents: a wrong shape is never read as "no results"."""
    if not isinstance(doc, dict):
        raise ScanIndexError(f"{provider}: malformed answer (expected a JSON object, got "
                             f"{type(doc).__name__})")
    rows: list[Row | None] = []
    if provider == "shodan":
        if op == "host":
            if not isinstance(doc.get("data"), list) and not isinstance(doc.get("ports"), list):
                raise ScanIndexError("shodan: malformed host answer (neither 'data' nor 'ports')")
            banners = [_d(b) for b in _l(doc.get("data"))]
            rows = [_shodan_banner(b, doc.get("ip_str")) for b in banners]
            listed = {_port(b.get("port")) for b in banners}
            for p in _l(doc.get("ports")):          # a port Shodan lists without a banner
                if _port(p) not in listed:
                    rows.append(_row("shodan", doc.get("ip_str"), p, hostnames=doc.get("hostnames"),
                                     org=doc.get("org"), seen=doc.get("last_update")))
        else:
            if not isinstance(doc.get("matches"), list):
                raise ScanIndexError("shodan: malformed search answer (no 'matches' list)")
            rows = [_shodan_banner(_d(m)) for m in doc["matches"]]
    elif provider == "internetdb":
        if not isinstance(doc.get("ports"), list):
            raise ScanIndexError("internetdb: malformed answer (no 'ports' list)")
        rows = [_row("internetdb", doc.get("ip"), p, hostnames=doc.get("hostnames")) for p in doc["ports"]]
    elif provider == "censys":
        result = doc.get("result")
        if not isinstance(result, dict):
            raise ScanIndexError("censys: malformed answer (no 'result' object)")
        if op == "host":
            res = result.get("resource")
            if not isinstance(res, dict):
                raise ScanIndexError("censys: malformed host answer (no 'result.resource')")
            rows = _censys_host(res, _l(res.get("services")))
        else:
            if not isinstance(result.get("hits"), list):
                raise ScanIndexError("censys: malformed search answer (no 'result.hits' list)")
            for hit in result["hits"]:
                hv = _d(_d(hit).get("host_v1"))
                res = _d(hv.get("resource"))
                if res:                              # web-property and certificate hits carry no host
                    rows += _censys_host(res, _l(hv.get("matched_services")) or _l(res.get("services")))
    elif provider == "fofa":
        if not isinstance(doc.get("results"), list):
            raise ScanIndexError("fofa: malformed answer (no 'results' list)")
        names = FOFA_FIELDS.split(",")
        for item in doc["results"]:
            if not isinstance(item, list) or len(item) != len(names):
                raise ScanIndexError("fofa: malformed result row (not the fields that were asked for)")
            r = dict(zip(names, item))
            host = str(r.get("host") or "")
            name = urllib.parse.urlsplit(host if "://" in host else "//" + host).hostname or ""
            try:
                ipaddress.ip_address(name)
                name = ""                            # the host column repeats the address
            except ValueError:
                pass
            rows.append(_row("fofa", r.get("ip"), r.get("port"), service=r.get("protocol"),
                             title=r.get("title") or None, hostnames=[name] if name else (),
                             org=r.get("as_organization") or None))
    elif provider == "netlas":
        if not isinstance(doc.get("items"), list):
            raise ScanIndexError("netlas: malformed answer (no 'items' list)")
        for item in doc["items"]:
            d = _d(_d(item).get("data"))
            http = _d(d.get("http"))
            name = d.get("host") if d.get("host") != d.get("ip") else None
            rows.append(_row("netlas", d.get("ip"), d.get("port"), transport=d.get("prot4"),
                             service=d.get("protocol"), title=http.get("title"),
                             hostnames=[name] if name else (), org=d.get("isp"), seen=d.get("last_updated"),
                             http_status=http.get("status_code"), body=http.get("body"),
                             cert_sha256=_d(d.get("certificate")).get("fingerprint_sha256")))
    else:
        raise ValueError(f"unknown scan-index provider {provider!r}")
    return tuple(r for r in rows if r is not None)


# ----------------------------------------------------------------------------------------------- union

def cdn_label(ip: str, orgs: Iterable[str] = ()) -> str | None:
    """The CDN a candidate belongs to, or None: an address inside a Cloudflare edge range, or an
    organization name a CDN uses. A CDN edge serves the same page as the origin and is never it."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if any(addr.version == net.version and addr in net for net in CLOUDFLARE_NETS):
        return "cloudflare"
    for org in orgs:
        low = (org or "").lower()
        for word in CDN_ORG_WORDS:
            if word in low:
                return word
    return None


def _when(seen: str | None) -> _dt.datetime | None:
    if not seen:
        return None
    text = seen.strip().replace("Z", "+00:00")
    try:
        t = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=_dt.timezone.utc)


@dataclass(frozen=True)
class Service:
    """One ip:port in the union: who saw it, what each called it, and who indexed the host without it."""
    ip: str
    port: int | None
    transport: str | None
    providers: tuple[str, ...]                     # that list this ip:port, in PROVIDERS order
    missing_from: tuple[str, ...]                  # that have the host but not this port (scanners disagree)
    titles: Mapping[str, str] = field(default_factory=dict)        # provider -> title
    seen: Mapping[str, str] = field(default_factory=dict)          # provider -> last scan time
    freshest: str | None = None                    # the provider with the newest scan of this ip:port
    services: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()
    orgs: tuple[str, ...] = ()
    http_status: Mapping[str, int] = field(default_factory=dict)
    bodies: Mapping[str, str] = field(default_factory=dict)        # provider -> archived body snippet
    findings: tuple[tuple[str, Finding], ...] = ()                 # (provider, finding)
    cert_sha256: tuple[str, ...] = ()
    cdn: str | None = None

    @property
    def title(self) -> str | None:
        """The title to show: the freshest provider's, else the first provider's that has one."""
        if self.freshest and self.freshest in self.titles:
            return self.titles[self.freshest]
        for p in self.providers:
            if p in self.titles:
                return self.titles[p]
        return None

    def non_public(self, public_ports: Iterable[int] = PUBLIC_PORTS) -> bool:
        """True for a listed port that is not one of the public site's (the back-office candidates)."""
        return self.port is not None and self.port not in set(public_ports)

    def to_dict(self) -> dict:
        return {"ip": self.ip, "port": self.port, "transport": self.transport,
                "providers": list(self.providers), "missing_from": list(self.missing_from),
                "title": self.title, "titles": dict(self.titles), "seen": dict(self.seen),
                "freshest": self.freshest, "services": list(self.services),
                "hostnames": list(self.hostnames), "orgs": list(self.orgs),
                "http_status": dict(self.http_status), "bodies": dict(self.bodies),
                "findings": [{"provider": p, **f.to_dict()} for p, f in self.findings],
                "cert_sha256": list(self.cert_sha256), "cdn": self.cdn}


def _order(provider: str) -> int:
    return PROVIDERS.index(provider) if provider in PROVIDERS else len(PROVIDERS)


def union(rows: Iterable[Row]) -> tuple[Service, ...]:
    """Merge provider rows into one Service per ip:port. Nothing is dropped: a CDN edge is labelled
    and sorted last, and a port only one scanner lists is kept with the scanners that have the host
    but not the port named in `missing_from`. Order: origin candidates before CDN edges, then the
    services more providers agree on, then address and port."""
    rows = list(rows)
    by_key: dict[tuple[str, int | None], list[Row]] = {}
    hosts: dict[str, set[str]] = {}
    for r in rows:
        by_key.setdefault((r.ip, r.port), []).append(r)
        hosts.setdefault(r.ip, set()).add(r.provider)
    out: list[Service] = []
    for (ip, port), group in by_key.items():
        group.sort(key=lambda r: _order(r.provider))
        provs = tuple(dict.fromkeys(r.provider for r in group))
        titles, seen, status, bodies = {}, {}, {}, {}
        findings: list[tuple[str, Finding]] = []
        fseen: set[str] = set()
        for r in group:
            if r.title:
                titles.setdefault(r.provider, r.title)
            if r.seen:
                seen.setdefault(r.provider, r.seen)
            if r.http_status is not None:
                status.setdefault(r.provider, r.http_status)
            if r.body:
                bodies.setdefault(r.provider, r.body)
            for f in r.findings:
                if f.value.lower() not in fseen:
                    fseen.add(f.value.lower())
                    findings.append((r.provider, f))
        dated = [(t, p) for p, s in seen.items() if (t := _when(s)) is not None]
        orgs = tuple(dict.fromkeys(r.org for r in group if r.org))
        out.append(Service(
            ip=ip, port=port, transport=next((r.transport for r in group if r.transport), None),
            providers=provs,
            missing_from=tuple(sorted(hosts[ip] - set(provs), key=_order)) if port is not None else (),
            titles=titles, seen=seen,
            freshest=max(dated, key=lambda tp: (tp[0], -_order(tp[1])))[1] if dated else None,
            services=tuple(dict.fromkeys(r.service for r in group if r.service)),
            hostnames=tuple(dict.fromkeys(h for r in group for h in r.hostnames)),
            orgs=orgs, http_status=status, bodies=bodies, findings=tuple(findings),
            cert_sha256=tuple(dict.fromkeys(r.cert_sha256 for r in group if r.cert_sha256)),
            cdn=cdn_label(ip, orgs)))

    def _key(s: Service):
        addr = ipaddress.ip_address(s.ip)
        return (s.cdn is not None, -len(s.providers), addr.version, int(addr), s.port or 0)
    return tuple(sorted(out, key=_key))


# ------------------------------------------------------------------------------------- results and quota

@dataclass(frozen=True)
class ProviderResult:
    """What one provider did with one pivot. `status` "ok" is an answer (possibly zero rows); every
    other status carries the reason there is none."""
    provider: str
    status: str
    reason: str = ""
    query: str = ""
    rows: tuple[Row, ...] = ()
    http_status: int | None = None
    cached: bool = False
    cached_ts: float | None = None

    @property
    def answered(self) -> bool:
        return self.status == OK

    def to_dict(self) -> dict:
        out: dict[str, Any] = {"provider": self.provider, "status": self.status, "rows": len(self.rows)}
        if self.reason:
            out["reason"] = self.reason
        if self.query:
            out["query"] = self.query
        if self.http_status is not None:
            out["http_status"] = self.http_status
        if self.cached:
            out["cached"] = True
            out["cached_ts"] = self.cached_ts
        return out


@dataclass(frozen=True)
class Report:
    """One pivot across the providers: every provider's result and the union of the answers."""
    pivot: Pivot
    results: tuple[ProviderResult, ...]
    services: tuple[Service, ...]

    @property
    def answered(self) -> tuple[str, ...]:
        return tuple(r.provider for r in self.results if r.answered)

    @property
    def not_answered(self) -> tuple[ProviderResult, ...]:
        return tuple(r for r in self.results if not r.answered)

    def to_dict(self) -> dict:
        return {"pivot": self.pivot.to_dict(), "answered": list(self.answered),
                "complete": not self.not_answered,
                "results": [r.to_dict() for r in self.results],
                "services": [s.to_dict() for s in self.services]}


@dataclass(frozen=True)
class ProviderUsage:
    """One provider's line in the quota ledger."""
    provider: str
    used: int                     # requests that got an HTTP answer (each is one ledger row)
    budget: int
    last_status: str | None = None
    last_ts: float | None = None
    quota_hit_ts: float | None = None   # when the provider last said its own quota was spent

    @property
    def left(self) -> int:
        return max(0, self.budget - self.used)

    def to_dict(self) -> dict:
        return {"provider": self.provider, "used": self.used, "budget": self.budget, "left": self.left,
                "last_status": self.last_status, "last_ts": self.last_ts,
                "quota_hit_ts": self.quota_hit_ts}


def budget_for(provider: str, *, budget: int | Mapping[str, int] | None = None,
               environ: Mapping[str, str] | None = None) -> int:
    """Requests `provider` may be sent per workdir: the `budget` argument (one number for all, or a
    mapping by provider), else $CTF_SCAN_INDEX_BUDGET_<PROVIDER>, else $CTF_SCAN_INDEX_BUDGET, else
    DEFAULT_BUDGET. 0 turns a provider off. A negative or non-integer value is an error."""
    if provider not in OFFICIAL_ENDPOINTS:
        raise ValueError(f"unknown scan-index provider {provider!r}")
    value: object = None
    source = "budget"
    if isinstance(budget, Mapping):
        value = budget.get(provider)
    elif budget is not None:
        value = budget
    if value is None:
        for name in (f"{BUDGET_ENV}_{provider.upper()}", BUDGET_ENV):
            value = env.get_int(name, environ=environ)
            if value is not None:
                source = name
                break
    if value is None:
        return DEFAULT_BUDGET
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{source} for {provider} must be an int >= 0, got {value!r}")
    return value


def usage(workdir: Path | None = None, *, budget: int | Mapping[str, int] | None = None,
          environ: Mapping[str, str] | None = None) -> dict[str, ProviderUsage]:
    """The per-provider quota ledger of `workdir` (default: the current event's): requests sent and
    left, the last outcome, and when a provider last reported its own quota spent. Read from the
    `scan_index.query` rows of the event ledger; a corrupt ledger raises (ValueError), it is not
    counted as empty."""
    acc: dict[str, dict[str, Any]] = {p: {"used": 0, "last_status": None, "last_ts": None, "quota": None}
                                      for p in PROVIDERS}
    for rec in ledger.read(workdir):
        if rec.get("event") != EVENT or rec.get("provider") not in acc:
            continue
        a = acc[rec["provider"]]
        if rec.get("http_status") is not None:
            a["used"] += 1
        a["last_status"], a["last_ts"] = rec.get("status"), rec.get("ts")
        if rec.get("status") == QUOTA:
            a["quota"] = rec.get("ts")
    return {p: ProviderUsage(p, a["used"], budget_for(p, budget=budget, environ=environ),
                             a["last_status"], a["last_ts"], a["quota"]) for p, a in acc.items()}


# ---------------------------------------------------------------------------------------------- client

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A scan-index API never needs a redirect, and following one would carry the key (in the query
    string for Shodan and FOFA) to another host. Returning None makes urllib raise the 3xx."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _check_endpoint(provider: str, base: str) -> str:
    """`base` when it is the provider's official endpoint or a loopback literal, else ValueError."""
    if provider not in OFFICIAL_ENDPOINTS:
        raise ValueError(f"unknown scan-index provider {provider!r}")
    base = str(base).rstrip("/")
    if base == OFFICIAL_ENDPOINTS[provider]:
        return base
    parts = urllib.parse.urlsplit(base)
    try:
        loopback = ipaddress.ip_address(parts.hostname or "").is_loopback
    except ValueError:
        loopback = False
    if (not loopback or parts.scheme not in ("http", "https") or parts.username or parts.password
            or parts.path or parts.query or parts.fragment):
        raise ValueError(f"scan-index endpoint for {provider} must be {OFFICIAL_ENDPOINTS[provider]} "
                         f"or a loopback address (a local fake); the provider list is closed")
    return base


def _message(doc: object) -> str:
    """The provider's own error text in an answer, if it has one."""
    if isinstance(doc, dict):
        for key in ("errmsg", "error", "detail", "message", "title"):
            v = doc.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
            if isinstance(v, dict) and isinstance(v.get("message"), str):
                return v["message"].strip()
    return ""


class ScanIndexClient:
    """Asks the scan indexes about one pivot at a time and unions the answers. See the module rules.

    `profile` is the event profile whose `rules.public_fetch_allow` gates the providers (default: the
    pinned profile, else `event.current()`); `workdir` holds the ledger and the answer cache (default
    `paths.workdir(slug)`); `environ` is where the keys are read (default the process environment);
    `endpoints` may point a provider at a loopback fake; `budget` overrides the per-provider request
    budget; `refresh` re-asks instead of reading the cache; `challenge` tags the ledger rows.
    """

    def __init__(self, *, profile: event.EventProfile | None = None, workdir: Path | None = None,
                 environ: Mapping[str, str] | None = None, endpoints: Mapping[str, str] | None = None,
                 budget: int | Mapping[str, int] | None = None, refresh: bool = False,
                 challenge: str | None = None, size: int = DEFAULT_SIZE,
                 timeout: float = TIMEOUT_SECONDS) -> None:
        if profile is None:
            profile = scope.pinned()
        if profile is None:
            try:
                profile = event.current()
            except event.EventError as e:
                raise ScanIndexRefused(
                    f"scan-index lookups refused: the event profile did not load ({e}); set CTF_EVENT to "
                    f"an event whose rules.public_fetch_allow lists the providers") from e
        self.profile = profile
        self.workdir = Path(workdir) if workdir is not None else paths.workdir(profile.slug)
        self.environ = os.environ if environ is None else environ
        self.endpoints = dict(OFFICIAL_ENDPOINTS)
        for name, base in (endpoints or {}).items():
            self.endpoints[name] = _check_endpoint(name, base)
        self.budget = budget
        for name in PROVIDERS:                       # a bad budget fails here, not mid-lookup
            budget_for(name, budget=budget, environ=self.environ)
        self.refresh = bool(refresh)
        self.challenge = str(challenge) if challenge else None
        self.size = _size(size)
        self.timeout = float(timeout)

    # ------------------------------------------------------------------------------------ keys

    def key(self, provider: str) -> str | None:
        """The provider's key from its named variable, or None. Never print or log the value."""
        name = KEY_ENV.get(provider)
        return env.get(name, environ=self.environ) if name else None

    def has_key(self, provider: str) -> bool:
        return provider not in KEY_ENV or bool(self.key(provider))

    def _secrets(self) -> list[str]:
        vals = [self.key(p) for p in KEYED_PROVIDERS] + [env.get(CENSYS_ORG_ENV, environ=self.environ)]
        return sorted({v for v in vals if v and len(v) >= 4}, key=len, reverse=True)

    def scrub(self, text: str) -> str:
        """`text` with every configured key value replaced: nothing a provider echoes can leak one."""
        for secret in self._secrets():
            text = text.replace(secret, "<redacted>")
            # the spellings a URL gives it: a path or header (quote) and a query string (urlencode
            # uses quote_plus, so a space becomes "+")
            text = text.replace(urllib.parse.quote(secret, safe=""), "<redacted>")
            text = text.replace(urllib.parse.quote_plus(secret, safe=""), "<redacted>")
        return text

    def _scrub_row(self, row: Row) -> Row:
        d = json.loads(self.scrub(json.dumps(row.to_dict())))
        return Row.from_dict(d)

    # ----------------------------------------------------------------------------------- cache

    def _cache_path(self, req: Request) -> Path:
        return self.workdir / CACHE_DIR / f"{req.provider}-{req.op}-{req.cache_key()}.json"

    def _cache_read(self, req: Request) -> ProviderResult | None:
        p = self._cache_path(req)
        if not p.is_file():
            return None
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
            rows = tuple(Row.from_dict(r) for r in doc["rows"])
            ts = float(doc["ts"])
        except (OSError, ValueError, KeyError, TypeError) as e:
            raise ScanIndexError(f"{req.provider}: the cached answer {p} is unreadable ({e}); delete it "
                                 f"or re-ask with refresh") from e
        return ProviderResult(req.provider, OK, reason=doc.get("note", ""), query=req.query, rows=rows,
                              cached=True, cached_ts=ts)

    def _cache_write(self, req: Request, rows: tuple[Row, ...], note: str, ts: float) -> None:
        p = self._cache_path(req)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(f".{os.getpid()}.tmp")
        blob = json.dumps({"provider": req.provider, "op": req.op, "query": req.query, "ts": ts,
                           "note": note, "rows": [r.to_dict() for r in rows]}, indent=1)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(self.scrub(blob))
        os.replace(tmp, p)

    # ------------------------------------------------------------------------------------ send

    def _send(self, req: Request, key: str | None) -> tuple[int, bytes | None]:
        """(HTTP status, body). The body is None when the answer is over MAX_RESPONSE_BYTES: the
        provider still answered (and charged its quota), so the caller records the status."""
        params = list(req.params)
        headers = {"User-Agent": USER_AGENT, "Accept": req.accept}
        if req.provider in ("shodan", "fofa"):
            params.append(("key", key or ""))
        elif req.provider in ("censys", "netlas"):
            headers["Authorization"] = "Bearer " + (key or "")
        if req.provider == "censys":
            org = env.get(CENSYS_ORG_ENV, environ=self.environ)
            if org:
                headers["X-Organization-ID"] = org
        url = self.endpoints[req.provider] + req.path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None
        if req.body is not None:
            data = json.dumps(req.body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        http_req = urllib.request.Request(url, data=data, headers=headers, method=req.method)
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            try:
                with opener.open(http_req, timeout=self.timeout) as resp:  # noqa: S310 -- closed host list
                    status, body = int(resp.status), resp.read(MAX_RESPONSE_BYTES + 1)
            except urllib.error.HTTPError as e:
                status, body = int(e.code), e.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
            why = getattr(e, "reason", None) or e
            raise ScanIndexError(self.scrub(f"{req.provider}: no answer ({type(e).__name__}: {why})")) from None
        if len(body) > MAX_RESPONSE_BYTES:
            return status, None
        return status, body

    def _record(self, req: Request, pivot: Pivot, status: str, http_status: int | None, rows: int,
                reason: str) -> float:
        fields: dict[str, Any] = {"provider": req.provider, "op": req.op, "pivot": pivot.kind,
                                  "value": pivot.value[:TITLE_MAX], "status": status,
                                  "rows": rows, "event_slug": self.profile.slug}
        if http_status is not None:
            fields["http_status"] = http_status
        if reason and status != OK:
            fields["reason"] = reason[:200]
        if self.challenge:
            fields["challenge"] = self.challenge
        return float(ledger.append(EVENT, workdir=self.workdir, **fields)["ts"])

    # ------------------------------------------------------------------------------------- ask

    def ask(self, provider: str, pivot: Pivot) -> ProviderResult:
        """One provider, one pivot, at most one request. Never raises for a provider-side problem:
        the result says what happened."""
        try:
            req = build_request(provider, pivot, size=self.size)
        except Unsupported as e:
            return ProviderResult(provider, SKIPPED, reason=str(e))
        if not self.refresh:
            hit = self._cache_read(req)
            if hit is not None:
                return hit
        try:
            scope.check_public_fetch(self.endpoints[provider], profile=self.profile, error=ScanIndexRefused,
                                     purpose=f"scan-index {provider} {req.op} lookup")
        except ScanIndexRefused as e:
            return ProviderResult(provider, REFUSED, reason=str(e), query=req.query)
        key = self.key(provider)
        if provider in KEY_ENV and not key:
            return ProviderResult(provider, NO_KEY, query=req.query,
                                  reason=f"{KEY_ENV[provider]} is not set (registering the {provider} "
                                         f"account and exporting its key is a human step)")
        use = usage(self.workdir, budget=self.budget, environ=self.environ)[provider]
        if use.used >= use.budget:
            return ProviderResult(provider, BUDGET, query=req.query,
                                  reason=f"{use.used} of {use.budget} budgeted {provider} requests are "
                                         f"spent in this workdir; raise {BUDGET_ENV}_{provider.upper()} "
                                         f"(or --budget) to ask again")
        try:
            status, body = self._send(req, key)
        except ScanIndexError as e:
            reason = self.scrub(str(e))
            self._record(req, pivot, ERROR, None, 0, reason)
            return ProviderResult(provider, ERROR, reason=reason, query=req.query)
        if body is None:                             # answered, so it spent a request: it is counted
            reason = (f"HTTP {status}: the answer is over the {MAX_RESPONSE_BYTES}-byte cap and was "
                      f"not read")
            self._record(req, pivot, ERROR, status, 0, reason)
            return ProviderResult(provider, ERROR, reason=reason, query=req.query, http_status=status)
        try:
            doc = json.loads(body.decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError):
            doc = None
        outcome, reason, rows = self._classify(req, status, doc)
        reason = self.scrub(reason)[:300]
        rows = tuple(self._scrub_row(r) for r in rows)
        ts = self._record(req, pivot, outcome, status, len(rows), reason)
        if outcome == OK:
            self._cache_write(req, rows, reason, ts)
        return ProviderResult(provider, outcome, reason=reason, query=req.query, rows=rows,
                              http_status=status)

    def _classify(self, req: Request, status: int, doc: object) -> tuple[str, str, tuple[Row, ...]]:
        said = _line(_message(doc), 200) or ""
        tail = f": {said}" if said else ""
        if 300 <= status < 400:
            return ERROR, (f"HTTP {status}: the provider answered with a redirect, which is never "
                           f"followed (it could carry the key to another host)"), ()
        if status in (401, 403):
            return AUTH, (f"HTTP {status}{tail} (the key was refused, or the account's plan does not "
                          f"include this call; no other route is tried)"), ()
        if status in (402, 429):
            return QUOTA, f"HTTP {status}{tail} (the provider's own quota or rate limit)", ()
        if status == 404 and req.op == "host":
            note = "HTTP 404: the provider has no record of this host"
            if req.provider == "censys":
                note += " (Censys also answers 404 for a host the token's plan may not see)"
            return OK, note, ()
        if not 200 <= status < 300:
            return ERROR, f"HTTP {status}{tail}", ()
        if doc is None:
            return ERROR, f"HTTP {status} with a body that is not JSON", ()
        if isinstance(doc, dict) and doc.get("error"):
            # FOFA (and Shodan, rarely) report a failure inside a 200. 820031 is FOFA's "out of points".
            return (QUOTA if "820031" in said else ERROR), f"the provider reported an error{tail}", ()
        try:
            return OK, "", parse_rows(req.provider, req.op, doc)
        except ScanIndexError as e:
            return ERROR, str(e), ()

    # ---------------------------------------------------------------------------------- lookup

    def lookup(self, pivot: Pivot, providers: Iterable[str] | None = None) -> Report:
        """Ask every provider (default: all that take this pivot kind) once and union the answers."""
        if pivot.kind not in PIVOT_KINDS:
            raise ValueError(f"unknown pivot kind {pivot.kind!r}")
        names = list(providers) if providers is not None else list(
            HOST_PROVIDERS if pivot.kind == "host" else SEARCH_PROVIDERS)
        if not names:
            raise ValueError("no scan-index provider named")
        for name in names:
            if name not in OFFICIAL_ENDPOINTS:
                raise ValueError(f"unknown scan-index provider {name!r} (known: {', '.join(PROVIDERS)})")
        if self.scrub(json.dumps(pivot.to_dict())) != json.dumps(pivot.to_dict()):
            raise PivotError("the pivot value contains a configured scan-index key; a key is never sent "
                             "as a search term (it would reach the other providers and the ledger)")
        results = tuple(self.ask(name, pivot) for name in dict.fromkeys(names))
        rows = [row for r in results if r.answered for row in r.rows]
        return Report(pivot=pivot, results=results, services=union(rows))
