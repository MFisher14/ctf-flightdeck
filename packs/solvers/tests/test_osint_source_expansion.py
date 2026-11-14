from __future__ import annotations

import itertools
import json
import math
import sys
import urllib.parse
from pathlib import Path

import pytest


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))
import osint_online as O  # noqa: E402
import osint_source_expansion as S  # noqa: E402


LEI = "5493001KJTIIGC8Y1R12"
BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
TESTNET_BTC = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"
ETH = "0x" + "1" * 40


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], float, int]] = []
        self.final_url: str | None = None
        self.status = 200
        self.body_override: bytes | None = None

    def __call__(self, url, headers, timeout, max_bytes):  # noqa: ANN001
        self.calls.append((url, dict(headers), timeout, max_bytes))
        if self.body_override is not None:
            body = self.body_override
        elif "api.gleif.org" in url and "/lei-records/" in url:
            body = json.dumps({"data": {"id": LEI, "attributes": {
                "lei": LEI,
                "entity": {"legalName": {"name": "Example Holdings SA"},
                           "registeredAddress": {"country": "RO"}},
                "registration": {"status": "ISSUED"},
            }}}).encode()
        elif "api.gleif.org" in url:
            body = json.dumps({"data": [{"id": LEI, "attributes": {
                "lei": LEI, "entity": {"legalName": {"name": "Example Holdings SA"},
                                         "registeredAddress": {"country": "RO"}},
            }}]}).encode()
        elif "wikidata.org" in url:
            body = json.dumps({"entities": {"Q42": {
                "labels": {"en": {"language": "en", "value": "Douglas Adams"}},
                "descriptions": {"en": {"language": "en", "value": "English author"}},
            }}}).encode()
        elif "haveibeenpwned.com/api/v3/breach/" in url:
            body = json.dumps({"Name": "ExampleBreach", "Title": "Example Breach",
                               "Domain": "example.com", "BreachDate": "2024-01-02",
                               "PwnCount": 123, "DataClasses": ["Email addresses"],
                               "IsVerified": True, "Description": "intentionally omitted"}).encode()
        elif "haveibeenpwned.com/api/v3/breaches" in url:
            body = json.dumps([{"Name": "ExampleBreach", "Title": "Example Breach",
                                "Domain": "example.com", "BreachDate": "2024-01-02",
                                "PwnCount": 123, "DataClasses": ["Email addresses"],
                                "IsVerified": True}]).encode()
        elif "api.certspotter.com" in url:
            body = json.dumps([{"id": "cert-1", "dns_names": ["example.com", "www.example.com",
                                                                  "outside.example.net"],
                                "not_before": "2024-01-01T00:00:00Z",
                                "not_after": "2024-04-01T00:00:00Z",
                                "issuer": {"name": "Example CA"}, "revoked": False}]).encode()
        elif "dns.google" in url:
            body = json.dumps({"Status": 0, "AD": True, "Answer": [
                {"name": "example.com.", "type": 1, "TTL": 60, "data": "93.184.216.34"},
            ]}).encode()
        elif "web.archive.org" in url:
            body = json.dumps([
                ["timestamp", "original", "mimetype", "statuscode", "digest", "redirect"],
                ["20010101000000", "https://example.com/", "text/html", "200", "ABC", ""],
            ]).encode()
        elif "blockstream.info" in url:
            body = json.dumps({"address": urllib.parse.unquote(url.rsplit("/", 1)[-1]),
                               "chain_stats": {"funded_txo_sum": 50, "spent_txo_sum": 20},
                               "mempool_stats": {"funded_txo_sum": 0}}).encode()
        elif "eth.blockscout.com" in url:
            body = json.dumps({"hash": ETH, "coin_balance": "100", "is_contract": False,
                               "name": None, "private_tags": ["must not be copied"]}).encode()
        else:  # pragma: no cover - every URL must be a declared fixed adapter
            raise AssertionError(f"unexpected mock URL: {url}")
        return O.HTTPResult(self.status, {"Content-Type": "application/json"}, body,
                            self.final_url or url)


def client(*, cap=8, provider_cap=3, protected=(), blocked=()):
    clock = FakeClock()
    transport = FakeTransport()
    value = S.ExpandedPublicOSINTClient(
        transport=transport, clock=clock.clock, sleep=clock.sleep,
        min_interval=1.25, request_cap=cap, per_provider_cap=provider_cap,
        protected_identifiers=protected, blocked_targets=blocked,
    )
    return value, clock, transport


def assert_human(report):
    assert report["requires_human_pin"] is True
    assert report["automatic_answer"] is None
    assert report["identity_verdict"] is None
    assert report["attribution_verdict"] is None
    json.dumps(report, allow_nan=False)


def test_fixed_registry_and_public_metadata_adapters_are_candidate_only():
    c, _, _ = client()
    lei = c.gleif_lei(LEI)
    assert lei["evidence"][0]["value"]["legalName"]["name"] == "Example Holdings SA"
    assert_human(lei)

    c, _, _ = client()
    name = c.gleif_legal_name("Example Holdings SA")
    assert name["evidence"][0]["value"]["lei"] == LEI
    assert "candidate" in name["evidence"][0]["note"]
    assert_human(name)

    c, _, _ = client()
    wikidata = c.wikidata_qid("q42")
    assert wikidata["evidence"][0]["value"]["labels"]["en"]["value"] == "Douglas Adams"
    assert_human(wikidata)

    c, _, _ = client()
    breach = c.hibp_breach("ExampleBreach")
    value = breach["evidence"][0]["value"]
    assert value["PwnCount"] == 123
    assert "Description" not in value
    assert "account" in breach["warning"]
    assert_human(breach)

    c, _, _ = client()
    domain_breaches = c.hibp_domain_breaches("example.com")
    assert domain_breaches["evidence"][0]["value"]["Name"] == "ExampleBreach"
    assert_human(domain_breaches)


def test_domain_bundle_shares_global_throttle_count_and_generic_user_agent():
    c, clock, transport = client()
    report = c.domain_bundle("example.com", (name for name in
        ("certspotter", "google_dns", "wayback", "hibp")), record_type="A")
    assert report["providers"] == ["certspotter", "google_dns", "wayback", "hibp"]
    assert report["requests"] == c.request_count == 4
    assert clock.sleeps == pytest.approx([1.25, 1.25, 1.25])
    assert len(report["evidence"]) == 4
    assert all(headers["User-Agent"] == O.GENERIC_USER_AGENT
               for _url, headers, _timeout, _cap in transport.calls)
    assert all("maximus" not in json.dumps(headers).casefold()
               for _url, headers, _timeout, _cap in transport.calls)
    assert_human(report)


def test_certificate_dns_and_wayback_parsers_keep_exact_domain_scope():
    c, _, transport = client()
    cert = c.certspotter("example.com")
    assert cert["observed_names"] == ["example.com", "www.example.com"]
    parsed = urllib.parse.urlsplit(transport.calls[0][0])
    query = urllib.parse.parse_qs(parsed.query)
    assert query["domain"] == ["example.com"]
    assert query["include_subdomains"] == ["true"]
    assert_human(cert)

    c, _, _ = client()
    dns = c.google_dns("example.com", "HTTPS")
    assert dns["record_type"] == "HTTPS"
    assert_human(dns)

    c, _, _ = client()
    archive = c.wayback_rich("https://example.com/about")
    assert archive["evidence"][0]["value"]["digest"] == "ABC"
    assert_human(archive)


def test_orcid_and_sensitive_hibp_account_queries_are_not_supported_or_sent():
    c, _, transport = client()
    with pytest.raises(O.OSINTGuardError, match="requires credentials"):
        c.orcid("0000-0002-1825-0097")
    assert not hasattr(c, "hibp_account")
    assert not hasattr(c, "hibp_paste")
    with pytest.raises(O.OSINTGuardError, match="never an account/e-mail"):
        c.hibp_breach("player@example.net")
    assert c.request_count == 0
    assert transport.calls == []


def test_player_secret_email_ctf_and_custom_blocklist_guards_are_pretransport():
    cases = [
        (lambda c: c.certspotter("2026.ctf-platform.example"), "out of scope"),
        (lambda c: c.gleif_legal_name("api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "secret-shaped"),
        (lambda c: c.wayback_rich("https://example.com/?auth=do-not-send"), "credential-shaped"),
    ]
    for operation, message in cases:
        c, _, transport = client()
        with pytest.raises(O.OSINTGuardError, match=message):
            operation(c)
        assert c.request_count == 0 and transport.calls == []

    c, _, transport = client(protected=("Example Holdings SA",))
    with pytest.raises(O.OSINTGuardError, match="protected/player"):
        c.gleif_legal_name("Example Holdings SA")
    assert not transport.calls

    c, _, transport = client(blocked=("example.com",))
    with pytest.raises(O.OSINTGuardError, match="out of scope"):
        c.google_dns("example.com")
    assert not transport.calls

    c, _, transport = client()
    with pytest.raises(O.OSINTGuardError, match="invalid exact legal name"):
        c.gleif_legal_name("Example\nHoldings SA")
    with pytest.raises(O.OSINTGuardError, match="invalid public breach name"):
        c.hibp_breach("Example\tBreach")
    for operation in (
        lambda: c.gleif_lei(LEI + "\n"),
        lambda: c.wikidata_qid("Q42\n"),
        lambda: c.bitcoin_address(BTC + "\n"),
        lambda: c.ethereum_address(ETH + "\n"),
    ):
        with pytest.raises(O.OSINTGuardError, match="invalid"):
            operation()
    assert not transport.calls


def test_one_exact_lead_global_cap_and_provider_cap_are_shared():
    c, _, transport = client()
    c.certspotter("example.com")
    with pytest.raises(O.OSINTGuardError, match="one client"):
        c.google_dns("example.net")
    assert c.request_count == len(transport.calls) == 1

    c, _, _ = client(cap=2)
    c.google_dns("example.com", "A")
    c.google_dns("example.com", "MX")
    with pytest.raises(O.OSINTGuardError, match="global"):
        c.google_dns("example.com", "NS")
    assert c.request_count == 2

    c, _, _ = client(provider_cap=1)
    c.google_dns("example.com", "A")
    with pytest.raises(O.OSINTGuardError, match="per-provider"):
        c.google_dns("example.com", "AAAA")
    assert c.request_count == 1


def test_infinite_provider_iterable_is_consumed_only_to_cap_plus_one():
    c, _, transport = client()
    produced = []

    def forever():
        for index in itertools.count():
            produced.append(index)
            yield "google_dns"

    with pytest.raises(O.OSINTGuardError, match="one to four"):
        c.domain_bundle("example.com", forever())
    assert produced == [0, 1, 2, 3, 4]
    assert c.request_count == 0 and transport.calls == []
    with pytest.raises(O.OSINTGuardError, match="unsupported domain provider"):
        c.domain_bundle("example.com", [["google_dns"]])
    assert c.request_count == 0 and transport.calls == []


def test_host_canonicalization_userinfo_ports_literal_ips_and_redirects_fail_closed():
    bad_urls = (
        "http://api.certspotter.com/v1/issuances",
        "https://user@api.certspotter.com/v1/issuances",
        "https://api.certspotter.com:444/v1/issuances",
        "https://127.0.0.1/",
        "https://2026.ctf-platform.example/",
        "https://api.certspοtter.com/",  # Greek omicron is not the allow-listed ASCII host.
    )
    for url in bad_urls:
        with pytest.raises(O.OSINTGuardError):
            S._host(url)
    assert S._host("https://API.CERTSPOTTER.COM./v1/issuances") == "api.certspotter.com"

    c, _, transport = client()
    transport.final_url = "https://dns.google/resolve?name=example.com"
    with pytest.raises(O.OSINTGuardError, match="cross-host"):
        c.certspotter("example.com")
    assert c.request_count == len(transport.calls) == 1

    c, _, transport = client()
    transport.final_url = "https://2026.ctf-platform.example/api/v1/challenges"
    with pytest.raises(O.OSINTGuardError, match="allow-listed|forbidden"):
        c.certspotter("example.com")
    assert c.request_count == len(transport.calls) == 1


def test_transport_failures_count_before_attempt_and_next_provider_is_throttled():
    clock = FakeClock()
    calls = []

    def flaky(url, headers, timeout, max_bytes):  # noqa: ANN001
        calls.append((url, dict(headers), timeout, max_bytes))
        if len(calls) == 1:
            raise TimeoutError("synthetic timeout")
        return O.HTTPResult(200, {"Content-Type": "application/json"},
                            b'{"Answer":[]}', url)

    c = S.ExpandedPublicOSINTClient(
        transport=flaky, clock=clock.clock, sleep=clock.sleep,
        min_interval=1.25, request_cap=2,
    )
    with pytest.raises(TimeoutError, match="synthetic"):
        c.google_dns("example.com")
    assert c.request_count == 1
    c.google_dns("example.com", "MX")
    assert c.request_count == 2
    assert clock.sleeps == pytest.approx([1.25])
    assert all(call[1]["User-Agent"] == O.GENERIC_USER_AGENT for call in calls)


def test_throttle_rejects_nonfinite_or_boolean_intervals_and_clocks():
    for interval in (math.nan, math.inf, True, 0.99):
        with pytest.raises(ValueError, match="finite number"):
            S.ExpandedPublicOSINTClient(transport=FakeTransport(), min_interval=interval)

    c = S.ExpandedPublicOSINTClient(
        transport=FakeTransport(), clock=lambda: math.nan, min_interval=1.0)
    with pytest.raises(O.OSINTGuardError, match="throttle clock"):
        c.google_dns("example.com")
    assert c.request_count == 0
    with pytest.raises(ValueError, match="request_cap must be an integer"):
        S.ExpandedPublicOSINTClient(transport=FakeTransport(), min_interval=1.0,
                                    request_cap=True)


def test_provider_responses_are_correlated_back_to_the_exact_lead():
    c, _, transport = client()
    transport.body_override = json.dumps([{
        "Name": "Other", "Domain": "other.example", "BreachDate": "2020-01-01"}]).encode()
    assert c.hibp_domain_breaches("example.com")["evidence"] == []

    c, _, transport = client()
    transport.body_override = json.dumps({"Answer": [
        {"name": "other.example.", "type": 1, "TTL": 60, "data": "203.0.113.1"},
    ]}).encode()
    assert c.google_dns("example.com")["evidence"] == []

    c, _, transport = client()
    transport.body_override = json.dumps({"data": [{"id": LEI, "attributes": {
        "lei": LEI, "entity": {"legalName": {"name": "Different Holdings"}}}}]}).encode()
    assert c.gleif_legal_name("Example Holdings SA")["evidence"] == []

    c, _, transport = client()
    transport.body_override = json.dumps({"data": {"attributes": {
        "lei": "529900T8BM49AURSDO55", "entity": {"legalName": {"name": "Other"}}}}}).encode()
    assert c.gleif_lei(LEI)["evidence"] == []

    c, _, transport = client()
    transport.body_override = json.dumps({"Name": "DifferentBreach"}).encode()
    assert c.hibp_breach("ExampleBreach")["evidence"] == []


def test_response_status_size_type_and_structure_guards_count_attempts():
    c, _, transport = client()
    transport.status = 403
    with pytest.raises(O.OSINTGuardError, match="HTTP status 403"):
        c.google_dns("example.com")
    assert c.request_count == 1

    c, _, transport = client()
    transport.body_override = b"x" * (O.MAX_RESPONSE_BYTES + 1)
    with pytest.raises(O.OSINTGuardError, match="over-cap"):
        c.google_dns("example.com")
    assert c.request_count == 1

    def invalid_object(url, headers, timeout, max_bytes):  # noqa: ANN001
        del url, headers, timeout, max_bytes
        return {"status": 200}

    c = S.ExpandedPublicOSINTClient(transport=invalid_object, min_interval=1.0)
    with pytest.raises(O.OSINTGuardError, match="invalid response object"):
        c.google_dns("example.com")
    assert c.request_count == 1

    deep = b'{"Answer":' + b"[" * 20 + b"0" + b"]" * 20 + b"}"
    c, _, transport = client()
    transport.body_override = deep
    with pytest.raises(O.OSINTGuardError, match="structural bounds"):
        c.google_dns("example.com")


def test_bitcoin_network_selects_exact_explorer_path_and_invalid_checksum_is_blocked():
    c, _, transport = client()
    mainnet = c.bitcoin_address(BTC)
    assert mainnet["network"] == "mainnet"
    assert "/api/address/" in transport.calls[0][0]
    assert "/testnet/" not in transport.calls[0][0]
    assert_human(mainnet)

    c, _, transport = client()
    testnet = c.bitcoin_address(TESTNET_BTC)
    assert testnet["network"] == "testnet"
    assert "/testnet/api/address/" in transport.calls[0][0]
    assert_human(testnet)

    c, _, transport = client()
    with pytest.raises(O.OSINTGuardError, match="invalid public Bitcoin"):
        c.bitcoin_address(BTC[:-1] + "b")
    assert c.request_count == 0 and transport.calls == []


def test_credential_free_exact_ethereum_summary_is_bounded_and_non_attributing():
    c, _, transport = client()
    report = c.ethereum_address(ETH)
    assert transport.calls[0][0] == "https://eth.blockscout.com/api/v2/addresses/" + ETH
    value = report["evidence"][0]["value"]
    assert value["coin_balance"] == "100"
    assert "private_tags" not in value
    assert "ownership" in report["evidence"][0]["note"]
    assert_human(report)


def test_invalid_local_options_decline_before_binding_or_transport():
    c, _, transport = client()
    with pytest.raises(O.OSINTGuardError, match="unsupported DNS"):
        c.domain_bundle("example.com", ["certspotter", "google_dns"], record_type="AXFR")
    assert c.request_count == 0 and transport.calls == []
    assert c._lead_fingerprint is None
    with pytest.raises(O.OSINTGuardError, match="distinct"):
        c.domain_bundle("example.com", ["certspotter", "certspotter"])
    assert c._lead_fingerprint is None
