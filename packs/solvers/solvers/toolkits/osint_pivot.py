#!/usr/bin/env python3
"""Offline-first OSINT pivot-plan builder with an explicit public-source handoff.

The sibling :mod:`osint_leads` extracts evidence.  This module turns supplied ``kind/value``
leads into ranked URLs, query parameters and manual checks for a human investigator.  The default
path never resolves DNS or opens a URL.  ``--online`` hands exactly one reviewed lead to
``osint_online.PublicOSINTClient``: an allow-listed, throttled and request-capped public-source
client.  Online rows are still unverified evidence and always require the human pin.

Supported pivots include username platform matrices; e-mail Gravatar/HIBP/breach checks;
domain Certificate Transparency, RDAP, Wayback CDX, DNS and search-dork builders; IP RDAP;
CVE records; hashes; phone numbers; crypto addresses; and coordinates.  Secret-shaped leads
are deliberately redacted and receive containment advice rather than lookup URLs.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import ipaddress
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Iterable

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

MAX_LEADS = 500
MAX_VALUE = 4096


@dataclasses.dataclass(frozen=True)
class Pivot:
    rank: int
    action: str
    provider: str
    url: str | None = None
    query: str | None = None
    note: str = "manual lookup; do not infer a match from URL construction alone"


USERNAME_SITES: tuple[tuple[int, str, str], ...] = (
    (100, "GitHub", "https://github.com/{path}"),
    (94, "GitLab", "https://gitlab.com/{path}"),
    (90, "Reddit", "https://www.reddit.com/user/{path}/"),
    (86, "Keybase", "https://keybase.io/{path}"),
    (82, "Hacker News", "https://news.ycombinator.com/user?id={query}"),
    (78, "Docker Hub", "https://hub.docker.com/u/{path}"),
    (74, "PyPI", "https://pypi.org/user/{path}/"),
    (70, "npm", "https://www.npmjs.com/~{path}"),
)

SECRET_KINDS = {"api_key", "aws_key", "google_api_key", "github_token", "jwt", "secret"}


def _is_secret_kind(kind: object) -> bool:
    normalized = str(kind).strip().lower().replace("-", "_")
    return normalized in SECRET_KINDS or any(part in normalized for part in ("api_key", "token", "secret"))


def _bounded(value: object) -> str:
    text = str(value).strip()
    if (not text or len(text) > MAX_VALUE
            or any(ord(ch) < 0x20 or 0xD800 <= ord(ch) <= 0xDFFF for ch in text)):
        raise ValueError("lead value is empty, overlong, or contains control characters")
    return text


def _url(base: str, params: dict[str, str]) -> str:
    return base + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def _domain(value: str) -> str:
    value = value.rstrip(".").lower()
    if "://" in value or "/" in value or "@" in value:
        raise ValueError("domain lead must be a bare hostname")
    try:
        ascii_value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized domain") from exc
    if len(ascii_value) > 253 or not re.fullmatch(r"[a-z0-9.-]+", ascii_value):
        raise ValueError("invalid domain")
    return ascii_value


def username_plan(value: str) -> list[Pivot]:
    username = _bounded(value).lstrip("@")
    if len(username) > 128 or not re.fullmatch(r"[\w.@+-]+", username, re.UNICODE):
        raise ValueError("username contains unsupported characters")
    path = urllib.parse.quote(username, safe="")
    query = urllib.parse.quote(username, safe="")
    pivots = [Pivot(rank, "check exact username profile", site,
                    template.format(path=path, query=query))
              for rank, site, template in USERNAME_SITES]
    dork = f'"{username}" (site:github.com OR site:gitlab.com OR site:reddit.com)'
    pivots.append(Pivot(65, "search exact username across indexed profiles", "search dork",
                        _url("https://www.google.com/search", {"q": dork}), dork))
    return pivots


def email_plan(value: str) -> list[Pivot]:
    email = _bounded(value).lower()
    if len(email) > 320 or not re.fullmatch(r"[^@\s]+@[^@\s]+", email):
        raise ValueError("invalid e-mail lead")
    digest = hashlib.md5(email.encode("utf-8"), usedforsecurity=False).hexdigest()
    domain = _domain(email.rsplit("@", 1)[1])
    dork = f'"{email}"'
    return [
        Pivot(100, "inspect deterministic avatar/profile metadata", "Gravatar",
              f"https://www.gravatar.com/avatar/{digest}.json", digest,
              "HTTP 404 is absence; any profile data still needs attribution review"),
        Pivot(95, "enter exact address in breach-account search", "Have I Been Pwned",
              "https://haveibeenpwned.com/", email,
              "manual lookup may require consent/rate-limit handling; never enumerate variants"),
        Pivot(88, "check public breach corpus by exact address", "Mozilla Monitor",
              "https://monitor.mozilla.org/", email,
              "manual exact-value check only; do not credential-test"),
        Pivot(80, "pivot to mail-domain infrastructure", "domain plan", None, domain),
        Pivot(70, "search exact public occurrence", "search dork",
              _url("https://www.google.com/search", {"q": dork}), dork),
    ]


def domain_plan(value: str) -> list[Pivot]:
    domain = _domain(_bounded(value))
    wildcard = f"%.{domain}"
    cdx = _url("https://web.archive.org/cdx/search/cdx", {
        "url": f"*.{domain}/*", "output": "json", "fl": "timestamp,original,statuscode,digest",
        "filter": "statuscode:200", "collapse": "urlkey",
    })
    dorks = [f"site:{domain}", f"site:{domain} ext:pdf", f"site:{domain} (inurl:admin OR inurl:login)"]
    rows = [
        Pivot(100, "enumerate public certificate names", "crt.sh",
              _url("https://crt.sh/", {"q": wildcard, "output": "json"}), wildcard),
        Pivot(96, "retrieve registration and nameserver record", "IANA RDAP",
              f"https://rdap.org/domain/{urllib.parse.quote(domain, safe='')}", domain),
        Pivot(92, "list archived public URLs", "Wayback CDX", cdx, f"*.{domain}/*"),
        Pivot(86, "prepare DNS record queries", "DNS",
              None, " ; ".join(f"dig +short {shlex_record} {domain}" for shlex_record in
                               ("A", "AAAA", "MX", "NS", "TXT", "CAA"))),
    ]
    rows.extend(Pivot(74 - index * 2, "run narrowly scoped public search", "search dork",
                      _url("https://www.google.com/search", {"q": dork}), dork)
                for index, dork in enumerate(dorks))
    return rows


def ip_plan(value: str) -> list[Pivot]:
    address = ipaddress.ip_address(_bounded(value).strip("[]"))
    quoted = urllib.parse.quote(str(address), safe="")
    note = ("private/reserved address: public attribution services will not be meaningful"
            if not address.is_global else
            "public-IP attribution evidence only; the guarded RDAP adapter may fetch this one reviewed address")
    rows = [
        Pivot(100, "retrieve registration/network owner", "IANA RDAP",
              f"https://rdap.org/ip/{quoted}", str(address), note),
        Pivot(85, "inspect public routing prefix and ASN", "RIPEstat",
              f"https://stat.ripe.net/{quoted}", str(address), note),
    ]
    if address.is_global:
        # B-114: the keyed scan-index union (Shodan, Censys, FOFA, Netlas, InternetDB) lists the ports
        # the indexes saw on this host; a port only some list is a back-office candidate.
        rows.append(Pivot(90, "union the indexed ports of this host (back-office candidates)",
                          "scan index", None, f"python -m ctf scan-index host {address}",
                          "needs the CTF_SCAN_INDEX_* keys and the provider hosts in the event's "
                          "rules.public_fetch_allow; an indexed port is a lead, confirm it in scope"))
    return rows


def _simple_plan(kind: str, value: str) -> list[Pivot]:
    safe = _bounded(value)
    q = urllib.parse.quote(safe, safe="")
    if kind == "cve":
        cve = safe.upper().replace("_", "-").replace(" ", "-")
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            raise ValueError("invalid CVE id")
        return [Pivot(100, "read canonical vulnerability record", "NVD",
                      f"https://nvd.nist.gov/vuln/detail/{cve}", cve),
                Pivot(95, "read CNA/MITRE record", "CVE.org",
                      f"https://www.cve.org/CVERecord?id={cve}", cve)]
    if kind in {"hash", "sha1", "sha256", "md5"}:
        compact = safe.lower()
        if not re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}", compact):
            raise ValueError("hash must be MD5, SHA-1, or SHA-256 hexadecimal")
        return [Pivot(100, "look up public malware/file observations", "VirusTotal",
                      f"https://www.virustotal.com/gui/file/{compact}", compact,
                      "a match is an observation, not proof of challenge attribution")]
    if kind in {"coordinate", "gps", "coordinates"}:
        if not re.fullmatch(r"[-+]?\d{1,3}(?:\.\d+)?\s*[,;]\s*[-+]?\d{1,3}(?:\.\d+)?", safe):
            raise ValueError("coordinate must be a decimal latitude,longitude pair")
        lat_text, lon_text = re.split(r"\s*[,;]\s*", safe)
        if not (-90 <= float(lat_text) <= 90 and -180 <= float(lon_text) <= 180):
            raise ValueError("coordinate latitude/longitude is outside Earth ranges")
        pair = safe.replace(";", ",")
        return [Pivot(100, "inspect coordinate and surrounding landmarks", "OpenStreetMap",
                      _url("https://www.openstreetmap.org/search", {"query": pair}), pair),
                Pivot(94, "inspect imagery/map context", "Google Maps",
                      _url("https://www.google.com/maps/search/", {"api": "1", "query": pair}), pair)]
    if kind in {"phone", "telephone"}:
        return [Pivot(100, "normalize and inspect country/number plan", "libphonenumber demo",
                      "https://libphonenumber.appspot.com/", safe,
                      "do not attempt owner lookup through restricted/private data")]
    if kind in {"btc", "bitcoin", "eth", "ethereum", "crypto_wallet", "wallet"}:
        base = "https://blockchair.com/search?q=" + q
        return [Pivot(100, "inspect public-chain transactions", "Blockchair", base, safe,
                      "wallet activity does not prove real-world identity")]
    dork = f'"{safe}"'
    return [Pivot(50, "search the exact public value", "search dork",
                  _url("https://www.google.com/search", {"q": dork}), dork)]


def plan_lead(kind: str, value: object) -> list[dict]:
    """Return ranked, serializable pivots for one extracted lead."""
    normalized = str(kind).strip().lower().replace("-", "_")
    if not normalized or len(normalized) > 64:
        raise ValueError("invalid lead kind")
    if _is_secret_kind(normalized):
        raw = _bounded(value)
        redacted = raw[:4] + "…" + raw[-4:] if len(raw) > 10 else "<redacted>"
        pivots = [Pivot(100, "preserve locally, identify issuer, and rotate/revoke if owned",
                        "secret containment", None, redacted,
                        "never place a live secret in a search engine or third-party URL")]
    elif normalized in {"username", "handle", "social_handle"}:
        pivots = username_plan(str(value))
    elif normalized in {"email", "e_mail"}:
        pivots = email_plan(str(value))
    elif normalized in {"domain", "hostname", "fqdn"}:
        pivots = domain_plan(str(value))
    elif normalized in {"ip", "ipv4", "ipv6"}:
        pivots = ip_plan(str(value))
    else:
        pivots = _simple_plan(normalized, str(value))
    pivots.sort(key=lambda item: (-item.rank, item.provider, item.action))
    return [dataclasses.asdict(item) for item in pivots]


def build_plan(leads: Iterable[dict]) -> list[dict]:
    """Build a bounded plan for ``[{kind,value,...}]`` while retaining source metadata."""
    if isinstance(leads, (str, bytes, dict)) or not hasattr(leads, "__iter__"):
        raise ValueError("leads must be an iterable of lead mappings")
    rows = list(leads)
    if len(rows) > MAX_LEADS:
        raise ValueError(f"at most {MAX_LEADS} leads are accepted")
    output: list[dict] = []
    for index, lead in enumerate(rows):
        if not isinstance(lead, dict) or "kind" not in lead or "value" not in lead:
            raise ValueError(f"lead {index} must contain kind and value")
        output.append({
            "kind": str(lead["kind"]),
            "value": "<redacted>" if _is_secret_kind(lead["kind"]) else str(lead["value"]),
            "sources": list(lead.get("sources", []))[:32] if isinstance(lead.get("sources", []), list) else [],
            "pivots": plan_lead(str(lead["kind"]), lead["value"]),
        })
    return output


def render(plans: Iterable[dict]) -> str:
    lines = ["OSINT pivot plan (offline construction; no request unless --online was explicitly supplied):"]
    for number, plan in enumerate(plans, 1):
        lines.append(f"[{number}] {plan['kind']}: {plan['value']}")
        for pivot in plan["pivots"]:
            target = pivot["url"] or pivot["query"] or "(manual)"
            lines.append(f"    {pivot['rank']:>3} {pivot['provider']}: {pivot['action']}")
            lines.append(f"        {target}")
            lines.append(f"        note: {pivot['note']}")
    return "\n".join(lines) + "\n"


def _load_json_arg(raw: str) -> object:
    if raw.startswith("@"):
        path = Path(raw[1:])
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("JSON input is too large")
        raw = path.read_text(encoding="utf-8")
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("JSON input is too large")
    return json.loads(raw)


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="build an offline OSINT pivot plan; optionally query one public source")
    parser.add_argument("--lead", action="append", default=[], metavar="KIND=VALUE")
    parser.add_argument("--leads-json", help="JSON list (or @file) from osint_leads")
    parser.add_argument("--text", help="extract leads from literal text using osint_leads first")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--online", action="store_true",
                        help="query one allow-listed public source for exactly one reviewed lead")
    parser.add_argument("--online-kind",
                        help="override lookup kind (dns, ct, wayback, geocode, gps, search, username, email)")
    parser.add_argument("--record-type", default="A", help="DNS record type for --online-kind dns")
    parser.add_argument("--challenge-identifier", action="store_true",
                        help="attest an e-mail is challenge evidence and not player identity")
    parser.add_argument("--wrong-count", type=int, default=0,
                        help="wrong answers already on this challenge (Workspace.wrong_count); gates the "
                             "guess budget on the --online path")
    parser.add_argument("--guess-budget", type=int, default=None,
                        help="candidate-feeding online lookups allowed before a player must approve more "
                             "(default: osint_online.DEFAULT_GUESS_BUDGET, read on the --online path)")
    parser.add_argument("--approvals-left", type=int, default=0,
                        help="unused player post-guard approvals that still permit an online lookup")
    try:
        args = parser.parse_args(argv)
        leads: list[dict] = []
        for raw in args.lead:
            if "=" not in raw:
                raise ValueError("--lead must be KIND=VALUE")
            kind, value = raw.split("=", 1)
            leads.append({"kind": kind, "value": value})
        if args.leads_json:
            loaded = _load_json_arg(args.leads_json)
            if isinstance(loaded, dict) and "leads" in loaded:
                loaded = loaded["leads"]
            if not isinstance(loaded, list):
                raise ValueError("--leads-json must contain a list")
            leads.extend(loaded)
        if args.text is not None:
            import osint_leads  # local offline extractor
            leads.extend(osint_leads.mine(text=args.text))
        if not leads:
            raise ValueError("give --lead, --leads-json, or --text")
        plans = build_plan(leads)
        online_report = None
        if args.online:
            if len(leads) != 1:
                raise ValueError("--online accepts exactly one lead; review pivots one at a time")
            # Imported here, never on the offline path: the offline plan must run without the online
            # adapter. The default is read from the sibling toolkit so the two entrypoints cannot drift;
            # an explicit --guess-budget (0 included) is kept as given.
            import osint_online
            guess_budget = (osint_online.DEFAULT_GUESS_BUDGET if args.guess_budget is None
                            else args.guess_budget)
            blocked = osint_online.guess_budget_block(args.wrong_count, guess_budget, args.approvals_left)
            if blocked is not None:
                print(f"osint_pivot: {blocked}", file=sys.stderr)
                return 3
            lead = leads[0]
            online_kind = args.online_kind or str(lead["kind"])
            client = osint_online.PublicOSINTClient(request_cap=4)
            evidence = osint_online.lookup(
                client, online_kind, str(lead["value"]), record_type=args.record_type,
                challenge_identifier=args.challenge_identifier,
            )
            online_report = {
                "evidence": evidence,
                "requests": client.request_count,
                "requires_human_pin": True,
                "warning": "public-source observations are candidates, never an automatic answer",
            }
        if args.json:
            payload = {"plans": plans, "online": online_report} if args.online else plans
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(render(plans), end="")
            if online_report is not None:
                print("ONLINE PUBLIC-SOURCE EVIDENCE (human verification required):")
                print(json.dumps(online_report, indent=2, ensure_ascii=False))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"osint_pivot: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
