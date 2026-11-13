"""Independent vector locks for the offline-only OSINT pivot planner.

The oracles are Python's hashlib/ipaddress/urllib.parse implementations and
documented identifier syntax.  No generated URL is opened and no online
adapter is imported by these tests.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import random
import sys
import urllib.parse

import pytest

import osint_pivot as target


def _provider(rows, name):
    return next(row for row in rows if row["provider"] == name)


def test_username_plan_percent_encoding_and_rank_order():
    username = "Alice+CTF"
    rows = target.plan_lead("username", "@" + username)
    assert [row["rank"] for row in rows] == sorted(
        (row["rank"] for row in rows), reverse=True
    )
    quoted = urllib.parse.quote(username, safe="")
    assert _provider(rows, "GitHub")["url"] == f"https://github.com/{quoted}"
    assert _provider(rows, "Hacker News")["url"] == (
        "https://news.ycombinator.com/user?id=" + quoted
    )
    dork = _provider(rows, "search dork")
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(dork["url"]).query) == {
        "q": [f'"{username}" (site:github.com OR site:gitlab.com OR site:reddit.com)']
    }


def test_email_plan_gravatar_md5_and_idna_domain():
    original = "Analyst@B\u00dcCHER.Example"
    normalized = original.lower()
    expected_md5 = hashlib.md5(
        normalized.encode("utf-8"), usedforsecurity=False
    ).hexdigest()
    rows = target.email_plan(original)
    gravatar = _provider([vars(row) for row in rows], "Gravatar")
    assert gravatar["url"] == f"https://www.gravatar.com/avatar/{expected_md5}.json"
    assert gravatar["query"] == expected_md5
    domain = _provider([vars(row) for row in rows], "domain plan")
    assert domain["query"] == "xn--bcher-kva.example"


def test_domain_plan_urls_against_stdlib_url_encoding():
    rows = target.plan_lead("domain", "B\u00dcCHER.Example.")
    domain = "xn--bcher-kva.example"
    crt = _provider(rows, "crt.sh")
    assert urllib.parse.urlsplit(crt["url"]).netloc == "crt.sh"
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(crt["url"]).query) == {
        "q": [f"%.{domain}"], "output": ["json"]
    }
    rdap = _provider(rows, "IANA RDAP")
    assert rdap["url"] == "https://rdap.org/domain/" + urllib.parse.quote(domain, safe="")
    cdx = _provider(rows, "Wayback CDX")
    assert urllib.parse.parse_qs(urllib.parse.urlsplit(cdx["url"]).query) == {
        "url": [f"*.{domain}/*"],
        "output": ["json"],
        "fl": ["timestamp,original,statuscode,digest"],
        "filter": ["statuscode:200"],
        "collapse": ["urlkey"],
    }


def test_ipv6_plan_uses_ipaddress_canonical_form():
    supplied = "[2001:0db8:0000:0000:0000:ff00:0042:8329]"
    expected = str(ipaddress.ip_address(supplied.strip("[]")))
    rows = target.plan_lead("ipv6", supplied)
    assert rows[0]["provider"] == "IANA RDAP"
    assert rows[0]["query"] == expected
    assert rows[0]["url"] == "https://rdap.org/ip/" + urllib.parse.quote(expected, safe="")
    assert "reserved" in rows[0]["note"]


def test_documented_identifier_and_coordinate_plans():
    cve = target.plan_lead("cve", "cve 2024 12345")
    assert [row["query"] for row in cve] == ["CVE-2024-12345"] * 2
    digest = "A1" * 32
    row, = target.plan_lead("sha256", digest)
    assert row["query"] == digest.lower()
    assert row["url"].endswith("/" + digest.lower())
    coords = target.plan_lead("gps", "44.4268; 26.1025")
    assert all(row["query"] == "44.4268, 26.1025" for row in coords)
    for row in coords:
        parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(row["url"]).query)
        assert parsed["query"] == ["44.4268, 26.1025"]


@pytest.mark.parametrize("value", ["91,0", "-91,0", "0,181", "0,-181", "999,999"])
def test_out_of_range_coordinate_is_rejected(value):
    with pytest.raises(ValueError):
        target.plan_lead("coordinate", value)


def test_secret_plan_redacts_value_and_never_builds_external_url():
    secret = "ghp_abcdefghijklmnop"
    rows = target.plan_lead("github-token", secret)
    assert len(rows) == 1
    assert rows[0]["provider"] == "secret containment"
    assert rows[0]["url"] is None
    assert rows[0]["query"] == secret[:4] + "\u2026" + secret[-4:]
    plan, = target.build_plan([
        {"kind": "github-token", "value": secret, "sources": ["fixture.txt"]}
    ])
    assert plan["value"] == "<redacted>"
    assert plan["sources"] == ["fixture.txt"]
    assert secret not in json.dumps(plan)


def test_build_and_render_preserve_source_metadata_and_order():
    leads = [
        {"kind": "ipv4", "value": "192.0.2.4", "sources": ["a", "b"]},
        {"kind": "md5", "value": "01" * 16},
    ]
    plan = target.build_plan(leads)
    assert [(row["kind"], row["value"]) for row in plan] == [
        ("ipv4", "192.0.2.4"), ("md5", "01" * 16)
    ]
    assert plan[0]["sources"] == ["a", "b"]
    rendered = target.render(plan)
    assert rendered.startswith("OSINT pivot plan (offline construction")
    assert "[1] ipv4: 192.0.2.4" in rendered
    assert "[2] md5: " + "01" * 16 in rendered
    assert rendered.endswith("\n")


@pytest.mark.parametrize(
    "kind,value",
    [
        ("username", ""),
        ("username", "slash/name"),
        ("email", "missing-at.example"),
        ("domain", "https://example.test/path"),
        ("domain", "bad domain.test"),
        ("ipv4", "999.1.2.3"),
        ("cve", "CVE-24-1"),
        ("sha256", "not-a-hash"),
        ("coordinate", "north,east"),
        ("phone", "bad\nvalue"),
    ],
)
def test_malformed_lead_parsers_raise_exact_valueerror(kind, value):
    with pytest.raises(ValueError) as caught:
        target.plan_lead(kind, value)
    assert type(caught.value) is ValueError


def test_coordinate_surrogate_raises_only_public_valueerror():
    try:
        target.plan_lead("coordinate", "\ud800")
    except ValueError as exc:
        assert type(exc) is ValueError
    else:
        pytest.fail("malformed coordinate was accepted")


def test_deterministic_malformed_text_fuzz_never_leaks_stdlib_subclasses():
    rng = random.Random(0x0517A7)
    corpus = ["", "\x00", "\n", "\x1f", "x" * (target.MAX_VALUE + 1)]
    corpus += [rng.randbytes(length).decode("latin-1") for length in range(1, 96, 7)]
    readers = (
        lambda value: target.username_plan(value),
        lambda value: target.email_plan(value),
        lambda value: target.domain_plan(value),
        lambda value: target.ip_plan(value),
        lambda value: target.plan_lead("coordinate", value),
    )
    for value in corpus:
        for reader in readers:
            try:
                result = reader(value)
            except ValueError as exc:
                assert type(exc) is ValueError, (reader, repr(value), type(exc))
            else:
                assert isinstance(result, list)


def test_build_plan_malformed_shapes_and_bound_are_fail_closed(monkeypatch):
    for value in ("lead", [None], [{}], [{"kind": "ip"}], [{"value": "1.2.3.4"}]):
        with pytest.raises(ValueError) as caught:
            target.build_plan(value)
        assert type(caught.value) is ValueError
    monkeypatch.setattr(target, "MAX_LEADS", 2)
    with pytest.raises(ValueError) as caught:
        target.build_plan([
            {"kind": "ip", "value": "192.0.2.1"},
            {"kind": "ip", "value": "192.0.2.2"},
            {"kind": "ip", "value": "192.0.2.3"},
        ])
    assert type(caught.value) is ValueError


@pytest.mark.parametrize("value", [None, 1])
def test_build_plan_noniterable_raises_only_public_valueerror(value):
    try:
        target.build_plan(value)
    except ValueError as exc:
        assert type(exc) is ValueError
    else:
        pytest.fail("non-iterable lead collection was accepted")


def test_main_offline_path_never_imports_online_adapter(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "osint_online", None)
    assert target.main(["--lead", "domain=example.test", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["kind"] == "domain"
    assert target.main([]) == 2
    assert target.main(["--unknown"]) == 2

