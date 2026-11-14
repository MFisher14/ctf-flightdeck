from __future__ import annotations

import json
import random
import string
import sys
from pathlib import Path

import pytest


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))
import osint_online as O  # noqa: E402
import osint_geo as G  # noqa: E402
import osint as LEGACY  # noqa: E402
import osint_leads as LEADS  # noqa: E402
from ctf import fastlane as F  # noqa: E402


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
        self.oversize = False

    def __call__(self, url, headers, timeout, max_bytes):  # noqa: ANN001
        self.calls.append((url, dict(headers), timeout, max_bytes))
        if self.oversize:
            body = b"x" * (O.MAX_RESPONSE_BYTES + 1)
            return O.HTTPResult(200, {"Content-Type": "text/plain"}, body,
                                self.final_url or url)
        if "rdap.org" in url:
            body = json.dumps({
                "name": "EXAMPLE-NET", "handle": "EXAMPLE",
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}],
                "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
            }).encode()
            content_type = "application/rdap+json"
        elif "cloudflare-dns.com" in url:
            body = json.dumps({"Answer": [{"name": "example.com", "type": 1,
                                           "TTL": 60, "data": "93.184.216.34"}]}).encode()
            content_type = "application/dns-json"
        elif "crt.sh" in url:
            body = json.dumps([{"name_value": "www.example.com\n*.example.com"}]).encode()
            content_type = "application/json"
        elif "web.archive.org" in url:
            body = json.dumps([["timestamp", "original", "statuscode", "digest"],
                               ["20010101000000", "http://example.com/", "200", "ABC"]]).encode()
            content_type = "application/json"
        elif "nominatim" in url and "/reverse?" in url:
            body = json.dumps({"display_name": "Bucharest, Romania", "lat": "44.4268",
                               "lon": "26.1025", "type": "city",
                               "address": {"city": "Bucharest", "country": "Romania"}}).encode()
            content_type = "application/json"
        elif "nominatim" in url:
            body = json.dumps([{"display_name": "Palace of Parliament, Bucharest",
                                "lat": "44.4275", "lon": "26.0874",
                                "type": "attraction", "importance": 0.8}]).encode()
            content_type = "application/json"
        elif "duckduckgo" in url:
            body = (b'<a class="result__a" href="https://public.example/article">'
                    b'Public <b>record</b></a>')
            content_type = "text/html"
        elif "api.github.com" in url:
            body = json.dumps({"login": "alice", "name": "Alice Example",
                               "html_url": "https://github.com/alice"}).encode()
            content_type = "application/json"
        elif "pypi.org" in url:
            body = json.dumps({"info": {"name": "ctf-helper", "version": "1.2.3",
                                         "author": "Public Maintainer",
                                         "project_urls": {"Source": "https://public.example/src"}}}).encode()
            content_type = "application/json"
        elif "registry.npmjs.org" in url:
            body = json.dumps({"name": "ctf-helper", "dist-tags": {"latest": "1.2.3"},
                               "repository": {"url": "https://public.example/src"}}).encode()
            content_type = "application/json"
        else:
            body = b"{}"
            content_type = "application/json"
        return O.HTTPResult(200, {"Content-Type": content_type}, body,
                            self.final_url or url)


def client(*, cap=8, protected=()):
    clock = FakeClock()
    transport = FakeTransport()
    value = O.PublicOSINTClient(
        transport=transport, clock=clock.clock, sleep=clock.sleep,
        min_interval=1.25, request_cap=cap, protected_identifiers=protected,
    )
    return value, clock, transport


def test_public_sources_parse_to_human_review_evidence():
    c, _, transport = client()
    rdap = c.rdap("example.com")
    dns = c.dns("example.com", "A")
    ct = c.certificate_transparency("example.com")
    assert rdap[0].value == "EXAMPLE-NET"
    assert dns[0].value == "93.184.216.34"
    assert {row.value for row in ct} == {"www.example.com", "example.com"}
    assert all("human" in row.note or "prove" in row.note or "evidence" in row.note
               for row in rdap + dns + ct)
    assert all(call[1]["User-Agent"] == O.GENERIC_USER_AGENT for call in transport.calls)
    assert all("maximus" not in str(call[1]).lower() for call in transport.calls)


def test_throttle_global_and_provider_caps_count_failed_attempts():
    c, clock, _ = client(cap=3)
    c.rdap("example.com")
    c.dns("example.com")
    c.certificate_transparency("example.com")
    assert clock.sleeps == pytest.approx([1.25, 1.25])
    with pytest.raises(O.OSINTGuardError, match="global"):
        c.wayback("example.com")
    assert c.request_count == 3


def test_single_lead_no_sweep_and_private_or_ctf_targets_decline():
    c, _, transport = client()
    c.rdap("example.com")
    with pytest.raises(O.OSINTGuardError, match="one client"):
        c.rdap("example.net")
    assert len(transport.calls) == 1
    for value in ("2026.ctf-platform.example", "sub.ctf-platform.example"):
        fresh, _, tx = client()
        with pytest.raises(O.OSINTGuardError, match="out of scope|forbidden"):
            fresh.rdap(value)
        assert not tx.calls
    fresh, _, tx = client()
    with pytest.raises(O.OSINTGuardError, match="private/reserved"):
        fresh.rdap("127.0.0.1")
    assert not tx.calls


def test_redirect_and_response_size_are_revalidated():
    c, _, transport = client()
    transport.final_url = "https://2026.ctf-platform.example/api/v1/challenges"
    with pytest.raises(O.OSINTGuardError, match="allow-listed|forbidden"):
        c.rdap("example.com")
    c, _, transport = client()
    transport.oversize = True
    with pytest.raises(O.OSINTGuardError, match="over-cap"):
        c.search("one exact public record")

    def recursive_json(url, headers, timeout, max_bytes):  # noqa: ANN001
        del headers, timeout, max_bytes
        return O.HTTPResult(200, {"Content-Type": "application/json"},
                            b"[" * 100_000 + b"0" + b"]" * 100_000, url)
    c = O.PublicOSINTClient(transport=recursive_json, min_interval=1.0)
    with pytest.raises(O.OSINTGuardError, match="malformed JSON"):
        c.rdap("example.com")


def test_player_identity_secret_and_email_guards_before_transport():
    c, _, transport = client(protected=("player@example.net", "private_handle"))
    with pytest.raises(O.OSINTGuardError, match="protected/player"):
        c.email_public("player@example.net", challenge_identifier=True)
    with pytest.raises(O.OSINTGuardError, match="attestation"):
        c.email_public("clue@example.com")
    assert not transport.calls
    fresh, _, tx = client()
    with pytest.raises(O.OSINTGuardError, match="secret-shaped"):
        fresh.search("api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    assert not tx.calls


def test_derived_search_cannot_escape_attested_bound_email_or_scope():
    c, _, transport = client()
    c.rdap("example.com")
    with pytest.raises(O.OSINTGuardError, match="exact attested"):
        c.search_for_bound_lead('"player@example.net"')
    with pytest.raises(O.OSINTGuardError, match="exact attested"):
        c.search_for_bound_lead("2026.ctf-platform.example")
    assert len(transport.calls) == 1

    c, _, transport = client()
    assert c.email_public("clue@example.com", challenge_identifier=True)
    with pytest.raises(O.OSINTGuardError, match="exact attested"):
        c.search_for_bound_lead('"other@example.com"')
    assert len(transport.calls) == 1


def test_provider_http_errors_never_become_profile_or_record_evidence():
    calls = []

    def denied(url, headers, timeout, max_bytes):  # noqa: ANN001
        del headers, timeout, max_bytes
        calls.append(url)
        return O.HTTPResult(403, {"Content-Type": "application/json"},
                            b'{"login":"false-positive","message":"rate limited"}', url)

    c = O.PublicOSINTClient(transport=denied, min_interval=1.0)
    with pytest.raises(O.OSINTGuardError, match="HTTP status 403"):
        c.username("alice")
    assert len(calls) == 1 and c.request_count == 1
    fresh, _, tx = client()
    with pytest.raises(O.OSINTGuardError, match="attested e-mail"):
        fresh.search('find "clue@example.com"')
    with pytest.raises(O.OSINTGuardError, match="credential-shaped"):
        fresh.wayback("https://example.com/?auth=do-not-leak")
    assert not tx.calls


def test_geocode_archive_search_username_and_email_remain_candidates():
    c, _, _ = client()
    reverse = c.reverse_geocode("44.4268,26.1025")
    assert reverse and reverse[0].value["address"]["city"] == "Bucharest"
    assert "human" in reverse[0].note

    c, _, _ = client()
    assert c.geocode("Palace of Parliament")[0].rank == 100
    c, _, _ = client()
    assert c.wayback("example.com")[0].value["timestamp"] == "20010101000000"
    c, _, _ = client()
    assert c.search("exact landmark skyline")[0].kind == "search_result"
    c, _, _ = client()
    assert c.username("alice")[0].kind == "profile_observation"
    c, _, _ = client()
    assert c.email_public("clue@example.com", challenge_identifier=True)[0].kind == "public_occurrence"
    c, _, _ = client()
    assert c.package_registry("ctf-helper", "pypi")[0].value["version"] == "1.2.3"


def test_geo_pipeline_hands_only_best_offline_clue_to_guarded_client():
    c, _, transport = client()
    report = {
        "metadata": {"gps": {"lat": 44.4268, "lon": 26.1025}},
        "clues": {"place_words": ["ignored second clue"], "candidate_names": ["also ignored"]},
    }
    online = G.enrich_online(report, c)
    assert online["basis"] == "EXIF GPS"
    assert online["requires_human_pin"] is True
    assert online["evidence"][0]["value"]["address"]["city"] == "Bucharest"
    assert len(transport.calls) == 1


def test_exif_dms_declines_missing_polarity_and_malformed_components():
    assert G._dms_to_decimal(((44, 1), (30, 1), (0, 1)), None, "lat") is None
    assert G._dms_to_decimal(((44, 1), (60, 1), (0, 1)), "N", "lat") is None
    assert G._dms_to_decimal(((91, 1), (0, 1), (0, 1)), "N", "lat") is None
    assert G._dms_to_decimal(((44, 1), (30, 1), (0, 1)), "S", "lat") == -44.5


def test_legacy_exif_coordinate_reader_never_invents_polarity_or_bad_dms():
    base = {"lat": [44.0, 30.0, 0.0], "lon": [26.0, 6.0, 0.0]}
    assert LEGACY._gps_to_decimal(base) is None
    assert LEGACY._gps_to_decimal({**base, "lat_ref": "N", "lon_ref": "E"}) == "44.5, 26.1"
    assert LEGACY._gps_to_decimal({**base, "lat": [44.0, 60.0, 0.0],
                                    "lat_ref": "N", "lon_ref": "E"}) is None
    assert LEGACY._gps_to_decimal({**base, "lat": [91.0, 0.0, 0.0],
                                    "lat_ref": "N", "lon_ref": "E"}) is None
    assert LEGACY._read_rationals(b"\x01\x00\x00\x00\x00\x00\x00\x00", "<", 1) is None


def test_fastlane_public_adapter_cannot_bypass_embedded_target_block(monkeypatch):
    calls = []

    def transport(url, headers, timeout, max_bytes):  # noqa: ANN001
        del headers, timeout, max_bytes
        calls.append(url)
        return O.HTTPResult(200, {"Content-Type": "application/json"}, b"[]", url)

    monkeypatch.setattr(O, "_urllib_transport", transport)
    fetch = F._public_osint_fetch()
    blocked = ("https://web.archive.org/cdx/search/cdx?output=json&"
               "url=https%3A%2F%2F2026.ctf-platform.example%2Frules")
    assert fetch(blocked) is None and not calls
    allowed = ("https://web.archive.org/cdx/search/cdx?output=json&"
               "url=https%3A%2F%2Fexample.org%2F")
    assert fetch(allowed) == "[]" and len(calls) == 1


def test_fastlane_declines_format_placeholders_and_competing_values():
    assert F._first_flag("Submit answers as CSCTF{...}") is None
    assert F._first_flag("Example CSCTF{example_flag}") is None
    assert F._first_flag("CSCTF{one} or CSCTF{two}") is None
    assert F._first_flag("the recovered value is CSCTF{one}") == "CSCTF{one}"


def test_cli_is_explicit_opt_in_and_never_fetches_without_online(capsys):
    assert O.main(["rdap", "example.com"]) == 2
    assert "opt-in" in capsys.readouterr().err
    assert O.main([]) == 2
    assert "osint_online:" in capsys.readouterr().err


def test_offline_first_pass_points_to_guarded_single_lead_handoff():
    rendered = LEGACY.leads_markdown([], {"clue.txt": b"see example.org"})
    assert "osint_pivot.py --online" in rendered
    assert "osint_online.py --online" in rendered
    assert "never script a sweep" in rendered
    gps_plan = LEADS.lookup_for("gps_coordinate")
    assert "osint_online gps" in gps_plan
    assert "Reverse-image upload remains manual" in gps_plan


def test_validation_mutation_fuzz_5000_cases_no_unexpected_exception():
    rng = random.Random(0x05_1A_7E)
    alphabet = string.printable + "\x00\ud800\uffff\u202e\U000e0001"
    accepted_domains = 0
    accepted_coordinates = 0
    for _ in range(5000):
        size = rng.randrange(0, 180)
        value = "".join(rng.choice(alphabet) for _ in range(size))
        try:
            O._domain(value)
            accepted_domains += 1
        except (O.OSINTGuardError, UnicodeError):
            pass
        try:
            O._coordinate(value)
            accepted_coordinates += 1
        except (O.OSINTGuardError, OverflowError):
            pass
    # The seeded corpus includes mostly mutations; acceptance is allowed but bounded.
    assert accepted_domains < 20
    assert accepted_coordinates < 20
