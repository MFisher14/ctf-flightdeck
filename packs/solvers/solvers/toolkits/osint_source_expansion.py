#!/usr/bin/env python3
"""Fixed-host, single-item public OSINT source expansion.

This client inherits the phase-1 value/privacy guard and shares its one-lead binding,
request/provider counters, global throttle, generic user-agent, bounded transport, and
failed-attempt accounting. New hosts are a closed constant; callers cannot provide URLs.
ORCID network access is deliberately unsupported because its public API requires credentials;
saved ORCID records belong in :mod:`osint_entity_graph`.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from typing import Any

try:  # package import in tests, script-local import at the CLI
    from . import blockchain
    from . import osint_online as online
except ImportError:  # pragma: no cover - script execution path
    import blockchain  # type: ignore
    import osint_online as online  # type: ignore


EXTRA_ALLOWED_HOSTS = frozenset({
    "api.gleif.org",
    "www.wikidata.org",
    "haveibeenpwned.com",
    "api.certspotter.com",
    "dns.google",
    "blockstream.info",
    "eth.blockscout.com",
})
ALL_ALLOWED_HOSTS = online.ALLOWED_HOSTS | EXTRA_ALLOWED_HOSTS
DNS_TYPES = frozenset({"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SOA", "TXT", "SRV",
                       "DS", "DNSKEY", "TLSA", "HTTPS", "SVCB", "NAPTR"})
LEI_RE = re.compile(r"[A-Z0-9]{20}\Z")
QID_RE = re.compile(r"Q[1-9]\d{0,11}\Z", re.I)
BREACH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,99}\Z")
ETH_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
MAX_JSON_NODES = 50_000
MAX_DEPTH = 12


def _host(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError, AttributeError) as exc:
        raise online.OSINTGuardError("malformed public-source URL") from exc
    if parsed.scheme != "https" or parsed.username or parsed.password or port not in (None, 443):
        raise online.OSINTGuardError("public sources require plain HTTPS on port 443")
    raw = (parsed.hostname or "").rstrip(".")
    try:
        canonical = raw.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise online.OSINTGuardError("invalid provider hostname") from exc
    if canonical not in ALL_ALLOWED_HOSTS:
        raise online.OSINTGuardError(f"provider host is not allow-listed: {canonical}")
    if online._is_blocked_name(canonical) or canonical in {"localhost", "localhost.localdomain"}:
        raise online.OSINTGuardError("CTF/local infrastructure is forbidden")
    try:
        ipaddress.ip_address(canonical.strip("[]"))
    except ValueError:
        pass
    else:
        raise online.OSINTGuardError("literal-IP provider URLs are forbidden")
    return canonical


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        if _host(req.full_url) != _host(newurl):
            raise online.OSINTGuardError("cross-host provider redirects are forbidden")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _transport(url: str, headers: Mapping[str, str], timeout: float,
               max_bytes: int) -> online.HTTPResult:
    expected_host = _host(url)
    request = urllib.request.Request(url, headers=dict(headers), method="GET")
    opener = urllib.request.build_opener(_Redirect())
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - fixed host allowlist
            final_url = response.geturl()
            if _host(final_url) != expected_host:
                raise online.OSINTGuardError("cross-host provider redirects are forbidden")
            advertised = response.headers.get("Content-Length")
            if advertised:
                try:
                    if int(advertised) > max_bytes:
                        raise online.OSINTGuardError("provider response exceeds the byte cap")
                except ValueError as exc:
                    raise online.OSINTGuardError("provider sent an invalid Content-Length") from exc
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise online.OSINTGuardError("provider response exceeds the byte cap")
            return online.HTTPResult(int(response.status), dict(response.headers.items()), body, final_url)
    except urllib.error.HTTPError as exc:
        final_url = exc.geturl()
        if _host(final_url) != expected_host:
            raise online.OSINTGuardError("cross-host provider redirects are forbidden") from exc
        body = exc.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise online.OSINTGuardError("provider error response exceeds the byte cap") from exc
        return online.HTTPResult(int(exc.code), dict(exc.headers.items()), body, final_url)


def _bounded(value: Any, budget: list[int] | None = None, depth: int = 0) -> Any:
    if budget is None:
        budget = [MAX_JSON_NODES]
    if budget[0] <= 0 or depth > MAX_DEPTH:
        raise online.OSINTGuardError("provider JSON exceeds structural bounds")
    budget[0] -= 1
    if value is None or isinstance(value, (bool, int, str)):
        return value[:4096] if isinstance(value, str) else value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Mapping):
        return {str(key)[:128]: _bounded(item, budget, depth + 1)
                for key, item in list(value.items())[:512]}
    if isinstance(value, list):
        return [_bounded(item, budget, depth + 1) for item in value[:1024]]
    return str(value)[:4096]


def _exact_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise online.OSINTGuardError(f"{field} must be text")
    if (not value.strip() or len(value) > limit or any(ord(char) < 0x20 for char in value)
            or any(0xD800 <= ord(char) <= 0xDFFF for char in value)):
        raise online.OSINTGuardError(f"invalid {field}")
    return re.sub(r" +", " ", value.strip())


def _valid_lei(value: str) -> bool:
    if not LEI_RE.fullmatch(value):
        return False
    expanded = "".join(str(ord(char) - 55) if char.isalpha() else char for char in value)
    return int(expanded) % 97 == 1


def _human(kind: str, client: "ExpandedPublicOSINTClient", lead: str,
           rows: list[online.Evidence], **fields: Any) -> dict[str, Any]:
    return {"kind": kind, "lead": lead, "requests": client.request_count,
            "evidence": [dataclasses.asdict(row) for row in rows], **fields,
            "automatic_answer": None, "identity_verdict": None,
            "attribution_verdict": None, "requires_human_pin": True,
            "note": "public observations are candidates; the player must corroborate and make the final pin"}


class ExpandedPublicOSINTClient(online.PublicOSINTClient):
    """One exact lead across a closed set of credential-free public providers."""

    def __init__(self, *, transport=None, **kwargs) -> None:
        interval = kwargs.get("min_interval", online.MIN_INTERVAL_SECONDS)
        if isinstance(interval, bool):
            raise ValueError("OSINT interval must be a finite number of at least one second")
        try:
            interval_number = float(interval)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("OSINT interval must be a finite number of at least one second") from exc
        if not math.isfinite(interval_number) or interval_number < 1.0:
            raise ValueError("OSINT interval must be a finite number of at least one second")
        kwargs["min_interval"] = interval_number
        for field, default in (("request_cap", online.MAX_REQUESTS),
                               ("per_provider_cap", online.MAX_PER_PROVIDER)):
            cap = kwargs.get(field, default)
            if isinstance(cap, bool) or not isinstance(cap, int):
                raise ValueError(f"{field} must be an integer")
        super().__init__(transport=transport or _transport, **kwargs)

    def _request(self, provider: str, url: str, *, accept: str = "application/json",
                 allow_not_found: bool = False) -> online.HTTPResult:
        expected_host = _host(url)
        if self._requests >= self.request_cap:
            raise online.OSINTGuardError("global public-lookup request cap reached")
        used = self._per_provider.get(provider, 0)
        if used >= self.per_provider_cap:
            raise online.OSINTGuardError(f"per-provider request cap reached for {provider}")
        now = self.clock()
        if isinstance(now, bool):
            raise online.OSINTGuardError("throttle clock returned a non-finite value")
        try:
            now = float(now)
        except (TypeError, ValueError, OverflowError) as exc:
            raise online.OSINTGuardError("throttle clock returned a non-finite value") from exc
        if not math.isfinite(now):
            raise online.OSINTGuardError("throttle clock returned a non-finite value")
        if self._last_request is not None:
            remaining = self.min_interval - (now - self._last_request)
            if remaining > 0:
                self.sleep(remaining)
                now = self.clock()
                if isinstance(now, bool):
                    raise online.OSINTGuardError("throttle clock returned a non-finite value")
                try:
                    now = float(now)
                except (TypeError, ValueError, OverflowError) as exc:
                    raise online.OSINTGuardError("throttle clock returned a non-finite value") from exc
                if not math.isfinite(now):
                    raise online.OSINTGuardError("throttle clock returned a non-finite value")
        headers = {"User-Agent": online.GENERIC_USER_AGENT, "Accept": accept,
                   "Cache-Control": "no-cache"}
        self._requests += 1
        self._per_provider[provider] = used + 1
        self._last_request = now
        result = self.transport(url, headers, online.TIMEOUT_SECONDS, online.MAX_RESPONSE_BYTES)
        if not isinstance(result, online.HTTPResult) or not isinstance(result.body, bytes):
            raise online.OSINTGuardError("transport returned an invalid response object")
        if _host(result.final_url) != expected_host:
            raise online.OSINTGuardError("cross-host provider redirects are forbidden")
        if len(result.body) > online.MAX_RESPONSE_BYTES:
            raise online.OSINTGuardError("transport returned an over-cap response")
        if isinstance(result.status, bool) or not isinstance(result.status, int):
            raise online.OSINTGuardError("transport returned an invalid HTTP status")
        if not 200 <= result.status < 300 and not (allow_not_found and result.status == 404):
            raise online.OSINTGuardError(f"{provider} returned HTTP status {result.status}")
        return result

    def _document(self, result: online.HTTPResult) -> Any:
        return _bounded(self._json(result))

    def orcid(self, _identifier: str) -> dict[str, Any]:
        raise online.OSINTGuardError(
            "ORCID online API requires credentials; analyze a saved public record offline instead")

    def gleif_lei(self, value: str) -> dict[str, Any]:
        lei = _exact_text(value, "LEI", 20).upper()
        if not _valid_lei(lei):
            raise online.OSINTGuardError("invalid checksum-bearing LEI")
        self._guard_value("lei", lei)
        url = "https://api.gleif.org/api/v1/lei-records/" + urllib.parse.quote(lei, safe="")
        result = self._request("gleif", url, accept="application/vnd.api+json", allow_not_found=True)
        if result.status == 404:
            rows = [online.Evidence(35, "GLEIF", "lei_absence", {"lei": lei, "status": 404},
                                    result.final_url, "point-in-time absence only")]
        else:
            document = self._document(result)
            data = document.get("data", {}) if isinstance(document, Mapping) else {}
            attrs = data.get("attributes", {}) if isinstance(data, Mapping) else {}
            entity = attrs.get("entity", {}) if isinstance(attrs, Mapping) else {}
            registration = attrs.get("registration", {}) if isinstance(attrs, Mapping) else {}
            observed_lei = attrs.get("lei") if isinstance(attrs, Mapping) else None
            rows = [] if observed_lei != lei else [online.Evidence(98, "GLEIF", "lei_record", {
                "lei": lei,
                "legalName": entity.get("legalName") if isinstance(entity, Mapping) else None,
                "registeredAddress": entity.get("registeredAddress") if isinstance(entity, Mapping) else None,
                "registration": registration,
            }, result.final_url, "registry record only; corroborate current legal identity")]
        return _human("exact_lei_lookup", self, lei, rows)

    def gleif_legal_name(self, value: str) -> dict[str, Any]:
        name = _exact_text(value, "exact legal name", 256)
        if len(name) < 2:
            raise online.OSINTGuardError("invalid exact legal name")
        self._guard_value("organization", name)
        query = urllib.parse.urlencode({"filter[entity.legalName]": name, "page[size]": "5"})
        result = self._request("gleif", "https://api.gleif.org/api/v1/lei-records?" + query,
                               accept="application/vnd.api+json")
        document = self._document(result)
        rows = []
        for index, item in enumerate(document.get("data", [])[:5] if isinstance(document, Mapping) else []):
            if not isinstance(item, Mapping):
                continue
            attrs = item.get("attributes", {})
            entity = attrs.get("entity", {}) if isinstance(attrs, Mapping) else {}
            legal_name = entity.get("legalName") if isinstance(entity, Mapping) else None
            observed_name = legal_name.get("name") if isinstance(legal_name, Mapping) else legal_name
            if not isinstance(observed_name, str) or observed_name.casefold() != name.casefold():
                continue
            rows.append(online.Evidence(90 - index * 4, "GLEIF", "legal_name_candidate", {
                "id": item.get("id"), "lei": attrs.get("lei") if isinstance(attrs, Mapping) else None,
                "legalName": entity.get("legalName") if isinstance(entity, Mapping) else None,
                "registeredAddress": entity.get("registeredAddress") if isinstance(entity, Mapping) else None,
            }, result.final_url, "exact-name registry candidate; human must disambiguate"))
        return _human("exact_legal_name_lookup", self, name, rows)

    def wikidata_qid(self, value: str) -> dict[str, Any]:
        qid = _exact_text(value, "Wikidata QID", 16).upper()
        if not QID_RE.fullmatch(qid):
            raise online.OSINTGuardError("invalid exact Wikidata QID")
        self._guard_value("public_identifier", qid)
        url = f"https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"
        result = self._request("wikidata", url, allow_not_found=True)
        if result.status == 404:
            rows = [online.Evidence(35, "Wikidata", "qid_absence", {"qid": qid, "status": 404},
                                    result.final_url, "point-in-time absence only")]
        else:
            document = self._document(result)
            entity = document.get("entities", {}).get(qid, {}) if isinstance(document, Mapping) else {}
            rows = [] if not isinstance(entity, Mapping) or not entity else [online.Evidence(90, "Wikidata", "entity_record", {
                "qid": qid, "labels": entity.get("labels") if isinstance(entity, Mapping) else None,
                "descriptions": entity.get("descriptions") if isinstance(entity, Mapping) else None,
            }, result.final_url, "community-maintained public record; corroborate primary sources")]
        return _human("exact_wikidata_lookup", self, qid, rows)

    def hibp_breach(self, value: str) -> dict[str, Any]:
        name = _exact_text(value, "public breach name", 100)
        if not BREACH_RE.fullmatch(name) or online.EMAIL_ANY_RE.search(name):
            raise online.OSINTGuardError("expected one exact public breach name, never an account/e-mail")
        self._guard_value("breach_name", name)
        url = "https://haveibeenpwned.com/api/v3/breach/" + urllib.parse.quote(name, safe="")
        result = self._request("hibp", url, allow_not_found=True)
        if result.status == 404:
            rows = [online.Evidence(35, "HIBP", "breach_absence", {"name": name, "status": 404},
                                    result.final_url, "catalog absence only")]
        else:
            document = self._document(result)
            allowed = ("Name", "Title", "Domain", "BreachDate", "AddedDate", "ModifiedDate",
                       "PwnCount", "DataClasses", "IsVerified", "IsFabricated", "IsSensitive",
                       "IsRetired", "IsSpamList")
            provider_name = document.get("Name") if isinstance(document, Mapping) else None
            rows = [] if not isinstance(provider_name, str) or provider_name.casefold() != name.casefold() else [online.Evidence(92, "HIBP", "breach_metadata",
                                    {key: document.get(key) for key in allowed if isinstance(document, Mapping)},
                                    result.final_url, "public breach metadata only; no account lookup or dump access")]
        return _human("exact_breach_metadata", self, name, rows,
                      warning="account, paste, password, stealer-log, and breach-dump endpoints are forbidden")

    def hibp_domain_breaches(self, value: str) -> dict[str, Any]:
        domain = online._domain(value)
        self._guard_value("domain", domain)
        query = urllib.parse.urlencode({"domain": domain})
        result = self._request("hibp", "https://haveibeenpwned.com/api/v3/breaches?" + query)
        document = self._document(result)
        rows = []
        for index, item in enumerate(document[:64] if isinstance(document, list) else []):
            if (isinstance(item, Mapping) and isinstance(item.get("Domain"), str)
                    and item["Domain"].rstrip(".").casefold() == domain):
                rows.append(online.Evidence(85 - min(index, 20), "HIBP", "domain_breach_metadata",
                                            {key: item.get(key) for key in ("Name", "Title", "Domain", "BreachDate",
                                                                           "PwnCount", "DataClasses", "IsVerified")},
                                            result.final_url, "catalog metadata only; it does not identify an account"))
        return _human("exact_domain_breach_catalog", self, domain, rows)

    def certspotter(self, value: str) -> dict[str, Any]:
        domain = online._domain(value)
        self._guard_value("domain", domain)
        query = urllib.parse.urlencode({"domain": domain, "include_subdomains": "true",
                                        "expand": ["dns_names", "issuer"]}, doseq=True)
        result = self._request("certspotter", "https://api.certspotter.com/v1/issuances?" + query)
        document = self._document(result)
        rows, seen = [], set()
        for item in document[:256] if isinstance(document, list) else []:
            if not isinstance(item, Mapping):
                continue
            names = []
            for name in item.get("dns_names", [])[:128] if isinstance(item.get("dns_names"), list) else []:
                candidate = str(name).casefold().removeprefix("*.").rstrip(".")
                if candidate == domain or candidate.endswith("." + domain):
                    names.append(candidate)
                    seen.add(candidate)
            if names:
                rows.append(online.Evidence(90, "Cert Spotter", "certificate_issuance", {
                    "dns_names": sorted(set(names)), "id": item.get("id"),
                    "not_before": item.get("not_before"), "not_after": item.get("not_after"),
                    "issuer": item.get("issuer"), "revoked": item.get("revoked"),
                }, result.final_url, "certificate observation only; it does not prove a live host"))
        return _human("exact_domain_certificate_history", self, domain, rows,
                      observed_names=sorted(seen)[:512])

    def google_dns(self, value: str, record_type: str = "A") -> dict[str, Any]:
        domain = online._domain(value)
        rtype = str(record_type).strip().upper()
        if rtype not in DNS_TYPES:
            raise online.OSINTGuardError("unsupported DNS record type")
        self._guard_value("domain", domain)
        query = urllib.parse.urlencode({"name": domain, "type": rtype, "do": "1", "cd": "0"})
        result = self._request("google_dns", "https://dns.google/resolve?" + query,
                               accept="application/dns-json")
        document = self._document(result)
        rows = []
        for item in document.get("Answer", [])[:128] if isinstance(document, Mapping) else []:
            if isinstance(item, Mapping):
                owner = str(item.get("name", "")).rstrip(".").casefold()
                if owner != domain and not owner.endswith("." + domain):
                    continue
                rows.append(online.Evidence(90, "Google Public DNS", rtype, {
                    "name": item.get("name"), "type": item.get("type"), "TTL": item.get("TTL"),
                    "data": item.get("data"), "AD": document.get("AD"),
                }, result.final_url, "point-in-time DNS evidence; corroborate ownership/history"))
        return _human("exact_domain_dns", self, domain, rows, record_type=rtype)

    def wayback_rich(self, value: str) -> dict[str, Any]:
        raw = str(value).strip()
        try:
            parsed = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
            port = parsed.port
        except ValueError as exc:
            raise online.OSINTGuardError("malformed archive target") from exc
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or port not in (None, 80, 443) or parsed.fragment):
            raise online.OSINTGuardError("archive target must be one HTTP(S) URL/domain")
        if any(key.casefold() in {"token", "key", "api_key", "apikey", "secret", "password", "auth"}
               for key, _item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)):
            raise online.OSINTGuardError("credential-shaped archive parameters are forbidden")
        host = online._domain(parsed.hostname)
        if online._is_blocked_name(host, self.blocked_targets):
            raise online.OSINTGuardError("forbidden archive target")
        # Bind the bare input so domain_bundle can share this lead across providers.
        self._guard_value("domain" if "://" not in raw else "url", raw)
        query = urllib.parse.urlencode({"url": raw, "output": "json",
                                        "fl": "timestamp,original,mimetype,statuscode,digest,redirect",
                                        "filter": "statuscode:200", "collapse": "digest", "limit": "50"})
        result = self._request("wayback_rich", "https://web.archive.org/cdx/search/cdx?" + query)
        document = self._document(result)
        rows = []
        if isinstance(document, list) and document:
            header = document[0] if isinstance(document[0], list) else []
            for item in document[1:51]:
                if isinstance(item, list):
                    record = dict(zip(header, item))
                    try:
                        archived_host = online._domain(urllib.parse.urlsplit(
                            str(record.get("original", ""))).hostname or "")
                    except online.OSINTGuardError:
                        continue
                    if archived_host != host:
                        continue
                    rows.append(online.Evidence(84, "Wayback CDX", "rich_capture", record,
                                                result.final_url, "archive index metadata; inspect capture manually"))
        return _human("exact_wayback_timeline", self, raw, rows)

    def bitcoin_address(self, value: str) -> dict[str, Any]:
        address = _exact_text(value, "Bitcoin address", 128)
        classified = blockchain.classify_btc_address(address)
        if not isinstance(classified, Mapping) or classified.get("kind") == "wif":
            raise online.OSINTGuardError("invalid public Bitcoin address")
        network = classified.get("network")
        if network not in {"mainnet", "testnet"}:
            raise online.OSINTGuardError("only public Bitcoin mainnet/testnet explorers are supported")
        self._guard_value("wallet", address)
        prefix = "/api/address/" if network == "mainnet" else "/testnet/api/address/"
        result = self._request("blockstream", "https://blockstream.info" + prefix +
                               urllib.parse.quote(address, safe=""), allow_not_found=True)
        if result.status == 404:
            rows = [online.Evidence(35, "Blockstream", "wallet_absence", {"address": address, "status": 404},
                                    result.final_url, "point-in-time explorer absence only")]
        else:
            document = self._document(result)
            rows = [online.Evidence(90, "Blockstream", "bitcoin_address_summary", {
                "address": address, "network": network,
                "provider_address_matches": (isinstance(document, Mapping)
                                             and document.get("address") == address),
                "chain_stats": document.get("chain_stats") if isinstance(document, Mapping) else None,
                "mempool_stats": document.get("mempool_stats") if isinstance(document, Mapping) else None,
            }, result.final_url, "public-chain activity does not prove real-world ownership")]
        return _human("exact_bitcoin_address", self, address, rows, network=network)

    def ethereum_address(self, value: str) -> dict[str, Any]:
        address = _exact_text(value, "Ethereum address", 42)
        if not ETH_RE.fullmatch(address):
            raise online.OSINTGuardError("invalid public Ethereum address")
        classified = blockchain.classify_eth_address(address)
        if not isinstance(classified, Mapping):
            raise online.OSINTGuardError("Ethereum checksum validation is unavailable")
        if classified.get("checksum") == "invalid":
            raise online.OSINTGuardError("invalid EIP-55 checksum")
        canonical = address.casefold()
        self._guard_value("wallet", canonical)
        result = self._request("blockscout", "https://eth.blockscout.com/api/v2/addresses/" +
                               urllib.parse.quote(canonical, safe=""), allow_not_found=True)
        if result.status == 404:
            rows = [online.Evidence(35, "Blockscout", "wallet_absence", {"address": canonical, "status": 404},
                                    result.final_url, "point-in-time explorer absence only")]
        else:
            document = self._document(result)
            keys = ("hash", "coin_balance", "exchange_rate", "is_contract", "name", "token")
            value = {key: document.get(key) for key in keys if isinstance(document, Mapping)}
            value["address"] = canonical
            value["provider_address_matches"] = (isinstance(document, Mapping)
                                                 and str(document.get("hash", "")).casefold() == canonical)
            rows = [online.Evidence(90, "Blockscout", "ethereum_address_summary", value,
                                    result.final_url, "public-chain activity does not prove real-world ownership")]
        return _human("exact_ethereum_address", self, canonical, rows)

    def domain_bundle(self, value: str, providers: Iterable[str] = ("certspotter", "google_dns", "wayback"),
                      *, record_type: str = "A") -> dict[str, Any]:
        domain = online._domain(value)
        if isinstance(providers, (str, bytes, bytearray, Mapping)):
            raise online.OSINTGuardError("domain providers must be a bounded iterable")
        iterator, selected = iter(providers), []
        for _index in range(5):
            try:
                selected.append(next(iterator))
            except StopIteration:
                break
        if not 1 <= len(selected) <= 4:
            raise online.OSINTGuardError("choose one to four distinct domain providers")
        allowed = {"certspotter", "google_dns", "wayback", "hibp"}
        if any(not isinstance(item, str) or item not in allowed for item in selected):
            raise online.OSINTGuardError("unsupported domain provider")
        if len(set(selected)) != len(selected):
            raise online.OSINTGuardError("choose one to four distinct domain providers")
        # Local options validate before the first method binds or spends a request.
        if "google_dns" in selected and str(record_type).upper() not in DNS_TYPES:
            raise online.OSINTGuardError("unsupported DNS record type")
        reports = []
        for provider in selected:
            if provider == "certspotter":
                reports.append(self.certspotter(domain))
            elif provider == "google_dns":
                reports.append(self.google_dns(domain, record_type))
            elif provider == "wayback":
                reports.append(self.wayback_rich(domain))
            else:
                reports.append(self.hibp_domain_breaches(domain))
        evidence = [item for report in reports for item in report["evidence"]]
        return {"kind": "expanded_exact_domain_bundle", "lead": domain,
                "providers": selected, "requests": self.request_count, "evidence": evidence,
                "automatic_answer": None, "identity_verdict": None, "attribution_verdict": None,
                "requires_human_pin": True,
                "note": "cross-source observations require human corroboration and final pin"}


__all__ = ["ALL_ALLOWED_HOSTS", "EXTRA_ALLOWED_HOSTS", "ExpandedPublicOSINTClient"]
