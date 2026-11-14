"""B-114: the scan-index clients (ctf/scan_index.py).

The client is driven against loopback fakes of the four providers (tests/scan_index_fakes.py) with
dummy keys and synthetic answers in each provider's documented shape. No test contacts a real
provider, so none is marked `live`. What is proved here: the exact query each provider gets for each
pivot, the closed host list, the scope gate, where a key goes and where it never appears, the quota
ledger and the request budget, the answer cache, the union, and the back-office findings.
"""
from __future__ import annotations

import base64
import json
import socket
import sys
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import scan_index_fakes as fk
from ctf import ledger, scope
from ctf import scan_index as si


@pytest.fixture
def indexes():
    made = []

    def _make(overrides=None):
        ix = fk.Indexes(overrides)
        made.append(ix)
        return ix
    yield _make
    for ix in made:
        ix.close()


@pytest.fixture
def pinned():
    """Pin a profile for one test; the suite profile comes back afterwards."""
    before = scope.pinned()

    def _pin(**kw):
        prof = fk.profile(**kw)
        scope.pin(prof)
        return prof
    yield _pin
    scope.unpin() if before is None else scope.pin(before)


def _client(ix, tmp_path, **kw):
    kw.setdefault("profile", fk.profile())
    kw.setdefault("environ", dict(fk.ENV))
    return si.ScanIndexClient(workdir=tmp_path, endpoints=ix.endpoints, **kw)


def _rows(tmp_path):
    return [r for r in ledger.read(tmp_path) if r["event"] == si.EVENT]


CERT = si.cert_pivot(fk.CERT_SHA256, sha1=fk.CERT_SHA1, serial=fk.CERT_SERIAL)
ICON = si.favicon_pivot(fk.ICON_MMH3, md5=fk.ICON_MD5, sha256=fk.ICON_SHA256)


# ---------------------------------------------------------------------------------------------- pivots

def test_cert_pivot_normalises_every_form_and_rejects_wrong_lengths():
    p = si.cert_pivot("AB:" * 31 + "AB", sha1=" CD" * 20, serial="0x6f:db")
    assert (p.kind, p.sha256, p.sha1, p.serial) == ("cert", "ab" * 32, "cd" * 20, "6FDB")
    assert p.value == "ab" * 32
    assert si.cert_pivot(sha1="cd" * 20).value == "cd" * 20
    assert si.cert_pivot(serial="6fdb").value == "serial:6FDB"
    for bad in ({"sha256": "ab" * 31}, {"sha256": "zz" * 32}, {"sha1": "cd" * 19}, {"serial": "xyz"}, {}):
        with pytest.raises(si.PivotError):
            si.cert_pivot(**bad)


def test_favicon_pivot_accepts_signed_and_unsigned_and_bounds_the_hash():
    assert si.favicon_pivot("-1840324437").mmh3 == -1840324437
    assert si.favicon_pivot(2454642859).mmh3 == -1840324437          # the unsigned spelling
    assert si.favicon_pivot(0).mmh3 == 0 and si.favicon_pivot(0).value == "0"
    assert si.favicon_pivot(md5="AA" * 16).value == "aa" * 16
    assert si.favicon_pivot(sha256="ef" * 32).value == "ef" * 32
    assert si.favicon_pivot(2**31 - 1).mmh3 == 2**31 - 1
    assert si.favicon_pivot(-2**31).mmh3 == -2**31
    assert si.favicon_pivot(2**31).mmh3 == -2**31                    # the first unsigned-only spelling
    assert si.favicon_pivot(str(2**32 - 1)).mmh3 == -1
    for bad in ({"mmh3": 2**32}, {"mmh3": -2**31 - 1}, {"mmh3": "abc"}, {"mmh3": True}, {"md5": "aa" * 15},
                {"sha256": "ef" * 31}, {}):
        with pytest.raises(si.PivotError):
            si.favicon_pivot(**bad)


def test_title_and_host_pivots_validate():
    assert si.title_pivot("  Synthetic Capital ").title == "Synthetic Capital"
    assert si.title_pivot("x" * si.TITLE_MAX).title == "x" * si.TITLE_MAX
    for bad in ("", "   ", "x" * (si.TITLE_MAX + 1), "two\nlines", "bell\x07", "a\x1fb", "a\x7fb", 7):
        with pytest.raises(si.PivotError):
            si.title_pivot(bad)
    assert si.title_pivot("a ~b").title == "a ~b"                     # 0x20 and 0x7E are printable
    assert si.host_pivot(" 203.0.113.5 ").ip == "203.0.113.5"
    assert si.host_pivot("[2001:DB8::1]").ip == "2001:db8::1"
    for bad in ("origin.synthetic.test", "203.0.113", "203.0.113.5/24", ""):
        with pytest.raises(si.PivotError):
            si.host_pivot(bad)


# -------------------------------------------------------------------------------------------- requests

def _fofa_query(req):
    return base64.b64decode(dict(req.params)["qbase64"]).decode("utf-8")


def test_each_provider_gets_its_own_form_of_a_certificate():
    sh = si.build_request("shodan", CERT)
    assert (sh.method, sh.path, sh.op) == ("GET", "/shodan/host/search", "search")
    assert dict(sh.params) == {"query": f"ssl.cert.fingerprint:{fk.CERT_SHA1}"}
    # no SHA-1: the serial, in decimal (Shodan stores the serial as an integer)
    sh2 = si.build_request("shodan", si.cert_pivot(fk.CERT_SHA256, serial="8BB00EE"))
    assert dict(sh2.params) == {"query": "ssl.cert.serial:146473198"}

    ce = si.build_request("censys", CERT, size=7)
    assert (ce.method, ce.path) == ("POST", "/v3/global/search/query")
    assert ce.body == {"query": f'host.services.cert.fingerprint_sha256 = "{fk.CERT_SHA256}"', "page_size": 7}
    assert ce.params == ()

    fo = si.build_request("fofa", CERT, size=9)
    assert (fo.method, fo.path) == ("GET", "/api/v1/search/all")
    assert _fofa_query(fo) == f'cert.sn="{int(fk.CERT_SERIAL, 16)}"' == fo.query
    assert dict(fo.params)["fields"] == "ip,port,protocol,host,title,as_organization"
    assert dict(fo.params)["size"] == "9" and dict(fo.params)["page"] == "1"

    ne = si.build_request("netlas", CERT)
    assert (ne.method, ne.path) == ("GET", "/api/responses/")
    assert dict(ne.params)["q"] == f"certificate.fingerprint_sha256:{fk.CERT_SHA256}"
    assert dict(ne.params)["start"] == "0" and dict(ne.params)["source_type"] == "include"


def test_a_provider_that_lacks_the_form_it_indexes_says_which_form_it_needs():
    only_sha256 = si.cert_pivot(fk.CERT_SHA256)
    with pytest.raises(si.Unsupported, match="SHA-1"):
        si.build_request("shodan", only_sha256)
    with pytest.raises(si.Unsupported, match="serial"):
        si.build_request("fofa", only_sha256)
    assert si.build_request("censys", only_sha256).op == "search"
    assert si.build_request("netlas", only_sha256).op == "search"
    only_sha1 = si.cert_pivot(sha1=fk.CERT_SHA1)
    for name in ("censys", "netlas"):
        with pytest.raises(si.Unsupported, match="SHA-256"):
            si.build_request(name, only_sha1)
    only_mmh3 = si.favicon_pivot(fk.ICON_MMH3)
    with pytest.raises(si.Unsupported, match="SHA-256"):
        si.build_request("netlas", only_mmh3)
    only_md5 = si.favicon_pivot(md5=fk.ICON_MD5)
    for name in ("shodan", "fofa"):
        with pytest.raises(si.Unsupported, match="icon_hash"):
            si.build_request(name, only_md5)
    for pivot in (CERT, ICON, si.title_pivot("x")):
        with pytest.raises(si.Unsupported, match="IP lookup"):
            si.build_request("internetdb", pivot)


def test_each_provider_gets_its_own_form_of_a_favicon():
    assert dict(si.build_request("shodan", ICON).params) == {"query": f"http.favicon.hash:{fk.ICON_MMH3}"}
    assert _fofa_query(si.build_request("fofa", ICON)) == f'icon_hash="{fk.ICON_MMH3}"'
    assert dict(si.build_request("netlas", ICON).params)["q"] == f"http.favicon.hash_sha256:{fk.ICON_SHA256}"
    base = "host.services.endpoints.http.favicons"
    # Censys: the MD5 first, then the SHA-256, the Shodan-style hash only when nothing else is known
    assert si.build_request("censys", ICON).body["query"] == f'{base}.hash_md5 = "{fk.ICON_MD5}"'
    assert (si.build_request("censys", si.favicon_pivot(fk.ICON_MMH3, sha256=fk.ICON_SHA256)).body["query"]
            == f'{base}.hash_sha256 = "{fk.ICON_SHA256}"')
    assert (si.build_request("censys", si.favicon_pivot(fk.ICON_MMH3)).body["query"]
            == f'{base}.hash_shodan = "{fk.ICON_MMH3}"')


def test_title_queries_are_exact_phrases_with_quotes_escaped():
    p = si.title_pivot('Ops "panel" \\ v2')
    esc = 'Ops \\"panel\\" \\\\ v2'
    assert dict(si.build_request("shodan", p).params) == {"query": f'http.title:"{esc}"'}
    assert si.build_request("censys", p).body["query"] == f'host.services.endpoints.http.html_title: "{esc}"'
    assert _fofa_query(si.build_request("fofa", p)) == f'title="{esc}"'
    assert dict(si.build_request("netlas", p).params)["q"] == f'http.title:"{esc}"'


def test_host_requests_use_each_providers_host_call():
    p = si.host_pivot(fk.ORIGIN)
    sh = si.build_request("shodan", p)
    assert (sh.op, sh.method, sh.path, sh.params) == ("host", "GET", f"/shodan/host/{fk.ORIGIN}", ())
    ce = si.build_request("censys", p)
    assert (ce.op, ce.method, ce.path, ce.body) == ("host", "GET", f"/v3/global/asset/host/{fk.ORIGIN}", None)
    assert ce.accept == "application/vnd.censys.api.v3.host.v1+json"
    fo = si.build_request("fofa", p)
    assert (fo.op, _fofa_query(fo)) == ("host", f'ip="{fk.ORIGIN}"')
    ne = si.build_request("netlas", p)
    assert (ne.op, dict(ne.params)["q"]) == ("host", f'ip:"{fk.ORIGIN}"')
    idb = si.build_request("internetdb", p)
    assert (idb.op, idb.method, idb.path) == ("host", "GET", f"/{fk.ORIGIN}")
    v6 = si.build_request("shodan", si.host_pivot("2001:db8::1"))
    assert v6.path == "/shodan/host/2001%3Adb8%3A%3A1"            # an address never adds a path segment


def test_build_request_rejects_unknown_providers_and_sizes():
    with pytest.raises(ValueError, match="unknown scan-index provider"):
        si.build_request("zoomeye", CERT)
    for bad in (0, si.MAX_SIZE + 1, True, "5"):
        with pytest.raises(ValueError, match="size"):
            si.build_request("censys", CERT, size=bad)
    assert si.build_request("censys", CERT, size=si.MAX_SIZE).body["page_size"] == si.MAX_SIZE
    assert si.build_request("censys", CERT, size=1).body["page_size"] == 1


def test_cache_key_separates_provider_call_and_query():
    a = si.build_request("netlas", CERT)
    b = si.build_request("netlas", si.cert_pivot("12" * 32))
    assert a.cache_key() == si.build_request("netlas", CERT).cache_key()
    assert len({a.cache_key(), b.cache_key(), si.build_request("censys", CERT).cache_key(),
                si.build_request("censys", CERT, size=3).cache_key()}) == 4


# ----------------------------------------------------------------------------------------------- parse

def test_shodan_answers_parse_to_rows():
    (row,) = si.parse_rows("shodan", "search", fk.SHODAN_SEARCH)
    assert (row.provider, row.ip, row.port, row.transport, row.service) == ("shodan", fk.ORIGIN, 443, "tcp", "https")
    assert (row.title, row.org, row.http_status) == (fk.TITLE, "Synthetic Hosting", 200)
    assert row.hostnames == ("origin.synthetic.test",) and row.cert_sha256 == fk.CERT_SHA256
    assert row.seen == "2026-11-01T10:00:00.000000"
    rows = si.parse_rows("shodan", "host", fk.SHODAN_HOST)
    # 443 has a banner; 22 is listed in `ports` with none and still becomes a row
    assert sorted((r.port, r.title) for r in rows) == [(22, None), (443, fk.TITLE)]
    assert {r.ip for r in rows} == {fk.ORIGIN}


def test_censys_answers_parse_to_rows_and_prefer_the_matched_services():
    (row,) = si.parse_rows("censys", "search", fk.CENSYS_SEARCH)      # port 22 did not match the query
    assert (row.ip, row.port, row.transport, row.service) == (fk.ORIGIN, 443, "tcp", "HTTP")
    assert (row.title, row.http_status, row.org) == (fk.TITLE, 200, "SYNTHETIC-AS")
    assert row.cert_sha256 == fk.CERT_SHA256 and row.hostnames == ("origin.synthetic.test",)
    rows = {r.port: r for r in si.parse_rows("censys", "host", fk.CENSYS_HOST)}
    assert sorted(rows) == [22, 443, 8080]
    assert rows[8080].title == "Synthetic Internal Ops" and rows[8080].seen == "2026-11-07T09:30:00Z"
    assert rows[8080].findings == (si.Finding("uuid", fk.PANEL_UUID, "recovery token"),)
    # without matched_services every service of the hit is a row
    doc = json.loads(json.dumps(fk.CENSYS_SEARCH))
    del doc["result"]["hits"][0]["host_v1"]["matched_services"]
    assert sorted(r.port for r in si.parse_rows("censys", "search", doc)) == [22, 443]
    # a certificate or web-property hit carries no host and is not a row
    doc["result"]["hits"] = [{"certificate_v1": {"resource": {"fingerprint_sha256": "ab" * 32}}}]
    assert si.parse_rows("censys", "search", doc) == ()


def test_fofa_and_netlas_and_internetdb_answers_parse_to_rows():
    rows = si.parse_rows("fofa", "search", fk.FOFA_SEARCH)
    assert [(r.ip, r.port, r.service, r.title, r.org) for r in rows] == [
        (fk.ORIGIN, 443, "https", fk.TITLE, "Synthetic Hosting"),
        (fk.OTHER, 8443, "https", fk.TITLE, "Elsewhere Net"),
        (fk.EDGE, 443, "https", fk.TITLE, "CLOUDFLARENET")]
    # the host column is a name only when it is not the address again
    assert [r.hostnames for r in rows] == [(), ("alt.synthetic.test",), ("www.synthetic.test",)]
    (n,) = si.parse_rows("netlas", "search", fk.NETLAS_SEARCH)
    assert (n.ip, n.port, n.transport, n.service, n.title) == (fk.ORIGIN, 443, "tcp", "https", fk.TITLE)
    assert (n.org, n.seen, n.http_status) == ("Synthetic Hosting", "2026-11-05T03:00:00.000Z", 200)
    assert n.hostnames == ("origin.synthetic.test",) and n.cert_sha256 == fk.CERT_SHA256
    assert [r.hostnames for r in si.parse_rows("netlas", "host", fk.NETLAS_HOST)] == [(), ()]
    idb = si.parse_rows("internetdb", "host", fk.INTERNETDB_HOST)
    assert [(r.ip, r.port, r.title) for r in idb] == [(fk.ORIGIN, 22, None), (fk.ORIGIN, 443, None),
                                                      (fk.ORIGIN, 8080, None)]


@pytest.mark.parametrize("provider,op,doc", [
    ("shodan", "search", {"total": 0}),
    ("shodan", "search", {"matches": "none"}),
    ("shodan", "host", {"ip_str": fk.ORIGIN}),
    ("censys", "search", {"result": {"hits": None}}),
    ("censys", "search", {"hits": []}),
    ("censys", "host", {"result": {}}),
    ("fofa", "search", {"error": False}),
    ("fofa", "search", {"results": [[fk.ORIGIN, "443"]]}),          # not the fields that were asked for
    ("fofa", "search", {"results": [fk.ORIGIN]}),
    ("netlas", "search", {"took": 1}),
    ("internetdb", "host", {"ip": fk.ORIGIN}),
    ("shodan", "search", ["not", "an", "object"]),
    ("netlas", "search", None),
])
def test_an_answer_in_the_wrong_shape_is_an_error_not_zero_results(provider, op, doc):
    with pytest.raises(si.ScanIndexError, match="malformed"):
        si.parse_rows(provider, op, doc)


def test_rows_are_sanitised_and_rows_without_an_address_are_dropped():
    doc = {"matches": [
        {"ip_str": "not-an-ip", "port": 80},
        {"ip_str": fk.ORIGIN, "port": 99999, "http": {"title": "a\x1b[31mred\x07\nline two" + "x" * 500}},
        {"ip_str": fk.ORIGIN, "port": "8443", "ssl": {"cert": {"fingerprint": {"sha256": "AB:" * 31 + "AB"}}},
         "http": {"html": "<p>" + "A" * (si.BODY_SNIPPET + 50) + f" key: {fk.PANEL_UUID}</p>\x00"}}]}
    a, b = si.parse_rows("shodan", "search", doc)
    assert a.port is None                                    # an impossible port is no port
    assert "\x1b" not in a.title and "\x07" not in a.title and "\n" not in a.title
    assert a.title.startswith("a [31mred line two") and len(a.title) == 300
    assert b.port == 8443 and b.cert_sha256 == "ab" * 32
    assert len(b.body) == si.BODY_SNIPPET and "\x00" not in b.body
    # the finding sits past the kept snippet: findings are read from the whole body
    assert fk.PANEL_UUID not in b.body
    assert b.findings == (si.Finding("uuid", fk.PANEL_UUID, "key"),)


def test_row_round_trips_through_its_dict():
    for row in si.parse_rows("censys", "host", fk.CENSYS_HOST) + si.parse_rows("shodan", "host", fk.SHODAN_HOST):
        assert si.Row.from_dict(json.loads(json.dumps(row.to_dict()))) == row


# -------------------------------------------------------------------------------------------- findings

def test_findings_are_uuids_labelled_values_and_long_hex_in_first_seen_order():
    body = ('<div data-case="11111111-2222-3333-4444-555555555555"></div>'
            '<b>Admin key:</b> <code>zx81-ADMIN-77aa</code>. token = "tok_live_9f8e7d"'
            f' id {fk.PANEL_UUID} digest 0123456789abcdef0123456789ABCDEF short deadbeef'
            ' password is hunter2-synthetic')
    got = si.extract_findings(body)
    assert got == (
        si.Finding("uuid", fk.PANEL_UUID),                                   # text first, then attributes
        si.Finding("uuid", "11111111-2222-3333-4444-555555555555"),
        si.Finding("labelled", "zx81-ADMIN-77aa", "admin key"),
        si.Finding("labelled", "tok_live_9f8e7d", "token"),
        si.Finding("labelled", "hunter2-synthetic", "password"),
        si.Finding("hex", "0123456789abcdef0123456789ABCDEF"))
    # a UUID or hex value that follows a label is one finding, with the label
    assert si.extract_findings(f"<b>Ops key</b>: <i>{fk.PANEL_UUID}</i> and flag={'a1' * 16}") == (
        si.Finding("uuid", fk.PANEL_UUID, "ops key"), si.Finding("labelled", "a1" * 16, "flag"))
    assert si.extract_findings(None) == () and si.extract_findings("") == ()
    assert si.extract_findings("<p>nothing here, key: x</p>") == ()         # too short to be a value


def test_findings_are_deduplicated_and_capped():
    assert si.extract_findings(f"{fk.PANEL_UUID} {fk.PANEL_UUID.upper()}") == (si.Finding("uuid", fk.PANEL_UUID),)
    many = " ".join(f"{i:08x}-0000-0000-0000-000000000000" for i in range(si.MAX_FINDINGS + 15))
    got = si.extract_findings(many)
    assert len(got) == si.MAX_FINDINGS and got[0].value == "00000000-0000-0000-0000-000000000000"


def test_a_hex_value_only_inside_an_attribute_is_a_finding():
    digest = "9c" * 32
    body = f'<form><input type="hidden" name="csrf" value="{digest}"><p>Sign in</p></form>'
    assert si.extract_findings(body) == (si.Finding("hex", digest),)
    # the same value in two attributes, different case: one finding, first spelling kept
    assert si.extract_findings(f'<a href="/ops/{digest}">x</a> and <i data-x="{digest.upper()}"></i>') == (
        si.Finding("hex", digest),)


# ----------------------------------------------------------------------------------------------- union

def test_union_merges_by_ip_and_port_and_names_the_scanners_that_disagree():
    rows = (si.parse_rows("shodan", "host", fk.SHODAN_HOST) + si.parse_rows("censys", "host", fk.CENSYS_HOST)
            + si.parse_rows("netlas", "host", fk.NETLAS_HOST)
            + si.parse_rows("internetdb", "host", fk.INTERNETDB_HOST))
    services = {s.port: s for s in si.union(rows)}
    assert sorted(services) == [22, 443, 8080]
    panel = services[8080]
    assert panel.providers == ("censys", "netlas", "internetdb")
    assert panel.missing_from == ("shodan",)                 # Shodan has the host but not the port
    assert panel.titles == {"censys": "Synthetic Internal Ops", "netlas": "Synthetic Admin"}
    assert panel.freshest == "censys" and panel.title == "Synthetic Internal Ops"   # trust the freshest
    assert panel.seen == {"censys": "2026-11-07T09:30:00Z", "netlas": "2026-11-04T01:00:00.000Z"}
    assert panel.findings == (("censys", si.Finding("uuid", fk.PANEL_UUID, "recovery token")),)
    assert panel.bodies["netlas"] == "<html>old panel</html>"
    assert panel.http_status == {"censys": 200, "netlas": 200}
    assert services[443].providers == ("shodan", "censys", "netlas", "internetdb")
    assert services[443].missing_from == ()
    assert services[22].providers == ("shodan", "censys", "internetdb") and services[22].missing_from == ("netlas",)
    assert panel.non_public() and not services[443].non_public() and services[22].non_public()
    assert not panel.non_public(public_ports=(8080,)) and services[443].non_public(public_ports=(8080,))


def test_union_title_falls_back_to_the_first_provider_when_nothing_is_dated():
    rows = [si.Row("netlas", fk.ORIGIN, 80, title="from netlas"), si.Row("fofa", fk.ORIGIN, 80, title="from fofa")]
    (svc,) = si.union(rows)
    assert svc.freshest is None and svc.providers == ("fofa", "netlas") and svc.title == "from fofa"
    newer = [si.Row("shodan", fk.ORIGIN, 80, title="old", seen="2026-01-01 00:00:00"),
             si.Row("netlas", fk.ORIGIN, 80, title="new", seen="2026-01-01T00:00:01Z"),
             si.Row("fofa", fk.ORIGIN, 80, title="undated", seen="yesterday")]
    (svc,) = si.union(newer)
    assert svc.freshest == "netlas" and svc.title == "new"


def test_union_freshest_breaks_a_tie_in_provider_order():
    same = "2026-11-01T00:00:00Z"
    rows = [si.Row("netlas", fk.ORIGIN, 80, title="netlas says", seen=same),
            si.Row("censys", fk.ORIGIN, 80, title="censys says", seen=same),
            si.Row("fofa", fk.ORIGIN, 80, title="fofa says", seen=same)]
    (svc,) = si.union(rows)
    assert svc.freshest == "censys" and svc.title == "censys says"     # the earlier provider in PROVIDERS
    (svc,) = si.union(list(reversed(rows)))
    assert svc.freshest == "censys"                                     # not the order the rows came in


def test_a_censys_host_with_no_services_still_counts_as_having_the_host():
    no_services = {"result": {"resource": {"ip": fk.ORIGIN, "services": [],
                                           "autonomous_system": {"name": "SYNTHETIC-AS"}}}}
    (row,) = si.parse_rows("censys", "host", no_services)
    assert (row.provider, row.ip, row.port, row.org) == ("censys", fk.ORIGIN, None, "SYNTHETIC-AS")
    services = {s.port: s for s in si.union(si.parse_rows("shodan", "host", fk.SHODAN_HOST) + (row,))}
    # Censys indexed the host and listed none of Shodan's ports: that is a disagreement, named
    assert services[443].providers == ("shodan",) and services[443].missing_from == ("censys",)
    assert services[22].missing_from == ("censys",)
    assert services[None].providers == ("censys",) and services[None].missing_from == ()


def test_union_labels_cdn_edges_and_sorts_them_after_origin_candidates():
    services = si.union(si.parse_rows("fofa", "search", fk.FOFA_SEARCH) + si.parse_rows("shodan", "search", fk.SHODAN_SEARCH))
    assert [(s.ip, s.cdn) for s in services] == [(fk.ORIGIN, None), (fk.OTHER, None), (fk.EDGE, "cloudflare")]
    assert services[0].providers == ("shodan", "fofa")       # two indexes agree: listed first
    assert len(services) == 3                                 # labelled, never dropped


def test_cdn_label_knows_edge_ranges_and_cdn_organisations():
    assert si.cdn_label("104.16.0.1") == "cloudflare" and si.cdn_label("172.71.255.255") == "cloudflare"
    assert si.cdn_label("2606:4700::1") == "cloudflare"
    assert si.cdn_label("104.32.0.1") is None and si.cdn_label(fk.ORIGIN) is None
    assert si.cdn_label(fk.ORIGIN, ["Akamai Technologies"]) == "akamai"
    assert si.cdn_label(fk.ORIGIN, ["Synthetic Hosting", "FASTLY"]) == "fastly"
    assert si.cdn_label(fk.ORIGIN, ["Amazon.com"]) is None   # a cloud is where origins live
    assert si.cdn_label("not-an-ip") is None


def test_a_service_with_no_port_is_kept_without_a_disagreement_list():
    (svc,) = si.union([si.Row("censys", fk.ORIGIN, None)])
    assert svc.port is None and svc.missing_from == () and not svc.non_public()


# ----------------------------------------------------------------------------------------------- quota

def test_budget_precedence_argument_then_provider_variable_then_general_then_default():
    assert si.budget_for("shodan", environ={}) == si.DEFAULT_BUDGET == 25
    env_ = {"CTF_SCAN_INDEX_BUDGET": "7", "CTF_SCAN_INDEX_BUDGET_FOFA": "3"}
    assert si.budget_for("shodan", environ=env_) == 7 and si.budget_for("fofa", environ=env_) == 3
    assert si.budget_for("fofa", budget=9, environ=env_) == 9
    assert si.budget_for("fofa", budget={"shodan": 1}, environ=env_) == 3     # not in the mapping
    assert si.budget_for("shodan", budget={"shodan": 0}, environ=env_) == 0
    for bad in (-1, True, 2.5):
        with pytest.raises(ValueError, match="int >= 0"):
            si.budget_for("shodan", budget=bad, environ={})
    with pytest.raises(ValueError, match="CTF_SCAN_INDEX_BUDGET_FOFA"):
        si.budget_for("fofa", environ={"CTF_SCAN_INDEX_BUDGET_FOFA": "-2"})
    with pytest.raises(ValueError, match="unknown"):
        si.budget_for("zoomeye", environ={})


def test_usage_counts_only_requests_that_got_an_http_answer(tmp_path):
    assert {p: (u.used, u.left) for p, u in si.usage(tmp_path, environ={}).items()} == {
        p: (0, 25) for p in si.PROVIDERS}
    ledger.append(si.EVENT, workdir=tmp_path, provider="shodan", status="ok", http_status=200)
    ledger.append(si.EVENT, workdir=tmp_path, provider="shodan", status="error")            # no answer
    ledger.append(si.EVENT, workdir=tmp_path, provider="shodan", status="quota", http_status=429)
    ledger.append(si.EVENT, workdir=tmp_path, provider="netlas", status="ok", http_status=200)
    ledger.append("candidate", workdir=tmp_path, provider="fofa", http_status=200)           # another event
    use = si.usage(tmp_path, budget=3, environ={})
    assert (use["shodan"].used, use["shodan"].left, use["shodan"].last_status) == (2, 1, "quota")
    assert use["shodan"].quota_hit_ts is not None and use["netlas"].quota_hit_ts is None
    assert (use["netlas"].used, use["fofa"].used) == (1, 0)
    assert si.usage(tmp_path, budget=1, environ={})["shodan"].left == 0      # never negative


# ---------------------------------------------------------------------------------------------- client

def test_a_certificate_lookup_asks_each_provider_once_with_its_own_key(indexes, tmp_path):
    ix = indexes()
    rep = _client(ix, tmp_path, environ={**fk.ENV, "CTF_SCAN_INDEX_CENSYS_ORG": "org-synthetic-0005"}).lookup(CERT)
    assert rep.answered == ("shodan", "censys", "fofa", "netlas") and rep.not_answered == ()
    assert {name: len(ix[name].requests) for name in ix.fakes} == {
        "shodan": 1, "censys": 1, "fofa": 1, "netlas": 1, "internetdb": 0}

    sh = ix["shodan"].requests[0]
    assert (sh.method, sh.path) == ("GET", "/shodan/host/search")
    assert sh.query == {"query": [f"ssl.cert.fingerprint:{fk.CERT_SHA1}"], "key": [fk.KEYS["shodan"]]}
    assert "authorization" not in sh.headers

    ce = ix["censys"].requests[0]
    assert (ce.method, ce.path, ce.query) == ("POST", "/v3/global/search/query", {})
    assert json.loads(ce.body) == {"query": f'host.services.cert.fingerprint_sha256 = "{fk.CERT_SHA256}"',
                                   "page_size": si.DEFAULT_SIZE}
    assert ce.headers["authorization"] == "Bearer " + fk.KEYS["censys"]
    assert ce.headers["x-organization-id"] == "org-synthetic-0005"
    assert ce.headers["content-type"] == "application/json"

    fo = ix["fofa"].requests[0]
    assert fo.path == "/api/v1/search/all" and fo.query["key"] == [fk.KEYS["fofa"]]
    assert base64.b64decode(fo.query["qbase64"][0]).decode() == f'cert.sn="{int(fk.CERT_SERIAL, 16)}"'
    assert "authorization" not in fo.headers

    ne = ix["netlas"].requests[0]
    assert ne.path == "/api/responses/" and ne.query["q"] == [f"certificate.fingerprint_sha256:{fk.CERT_SHA256}"]
    assert ne.headers["authorization"] == "Bearer " + fk.KEYS["netlas"] and "key" not in ne.query

    # every key reached its own provider and no other
    for name, fake in ix.fakes.items():
        seen = " ".join(r.raw_path + json.dumps(r.headers) + r.body.decode() for r in fake.requests)
        for owner, key in fk.KEYS.items():
            assert (key in seen) == (owner == name), f"{owner} key at {name}"
        for r in fake.requests:                               # an API client, not a browser
            assert r.headers["user-agent"] == si.USER_AGENT and "Mozilla" not in r.headers["user-agent"]

    by = {(s.ip, s.port): s for s in rep.services}
    assert by[(fk.ORIGIN, 443)].providers == ("shodan", "censys", "fofa", "netlas")
    assert rep.services[0].ip == fk.ORIGIN and rep.services[-1].cdn == "cloudflare"
    doc = rep.to_dict()
    assert doc["complete"] is True and doc["pivot"]["sha1"] == fk.CERT_SHA1
    assert [r["status"] for r in doc["results"]] == ["ok"] * 4


def test_the_censys_organisation_header_is_sent_only_when_configured(indexes, tmp_path):
    ix = indexes()
    _client(ix, tmp_path).lookup(CERT, ["censys"])
    assert "x-organization-id" not in ix["censys"].requests[0].headers


def test_a_provider_without_a_key_is_not_asked_and_says_which_variable(indexes, tmp_path):
    ix = indexes()
    environ = {k: v for k, v in fk.ENV.items() if "CENSYS" not in k}
    rep = _client(ix, tmp_path, environ=environ).lookup(CERT)
    (missing,) = rep.not_answered
    assert (missing.provider, missing.status) == ("censys", si.NO_KEY)
    assert "CTF_SCAN_INDEX_CENSYS_TOKEN is not set" in missing.reason and "human step" in missing.reason
    assert ix["censys"].requests == [] and rep.answered == ("shodan", "fofa", "netlas")
    assert rep.to_dict()["complete"] is False
    assert [r["provider"] for r in _rows(tmp_path)] == ["shodan", "fofa", "netlas"]   # not asked: no row


def test_keys_are_read_only_from_the_named_variables(indexes, tmp_path):
    ix = indexes()
    wrong = {"SHODAN_API_KEY": "x" * 20, "CTF_SHODAN_KEY": "y" * 20, "CTF_SCAN_INDEX_SHODAN": "z" * 20}
    c = _client(ix, tmp_path, environ=wrong)
    assert c.key("shodan") is None and not c.has_key("shodan")
    assert c.has_key("internetdb") and c.key("internetdb") is None          # keyless by design
    assert c.lookup(CERT, ["shodan"]).results[0].status == si.NO_KEY
    assert ix.total_requests() == 0


def test_a_provider_that_cannot_take_the_pivot_is_skipped_with_the_form_it_needs(indexes, tmp_path):
    ix = indexes()
    rep = _client(ix, tmp_path).lookup(si.cert_pivot(fk.CERT_SHA256))
    status = {r.provider: r.status for r in rep.results}
    assert status == {"shodan": si.SKIPPED, "censys": si.OK, "fofa": si.SKIPPED, "netlas": si.OK}
    assert "SHA-1" in rep.results[0].reason and "serial" in rep.results[2].reason
    assert ix["shodan"].requests == [] and ix["fofa"].requests == []


def test_the_event_scope_gates_every_provider_before_any_request(indexes, tmp_path):
    ix = indexes()
    closed = fk.profile(public=())
    rep = _client(ix, tmp_path, profile=closed).lookup(CERT)
    assert [r.status for r in rep.results] == [si.REFUSED] * 4 and rep.services == ()
    assert all("rules.public_fetch_allow" in r.reason and "127.0.0.1" in r.reason for r in rep.results)
    assert ix.total_requests() == 0 and _rows(tmp_path) == []
    # a scope that opens live targets does not open a public fetch
    rep = _client(ix, tmp_path, profile=fk.profile(public=("mirror.example.org",))).lookup(CERT, ["netlas"])
    assert rep.results[0].status == si.REFUSED and ix.total_requests() == 0


def test_the_official_endpoints_are_refused_by_their_own_host_names(tmp_path):
    # No fake and no network: a profile that lists only the loopback fakes refuses every real
    # provider, and the refusal names that provider's official host. Keys are set, so only the
    # scope gate stops them (a request that got through would be an error row in the ledger).
    c = si.ScanIndexClient(profile=fk.profile(), workdir=tmp_path, environ=dict(fk.ENV))
    assert c.endpoints == si.OFFICIAL_ENDPOINTS
    for pivot, names in ((CERT, si.SEARCH_PROVIDERS), (si.host_pivot(fk.ORIGIN), si.HOST_PROVIDERS)):
        rep = c.lookup(pivot)
        assert [r.provider for r in rep.results] == list(names)
        for r in rep.results:
            host = urllib.parse.urlsplit(si.OFFICIAL_ENDPOINTS[r.provider]).hostname
            assert r.status == si.REFUSED and host in r.reason, (r.provider, r.reason)
    assert _rows(tmp_path) == [] and not (tmp_path / si.CACHE_DIR).exists()


def test_the_client_uses_the_pinned_profile_and_refuses_without_one(indexes, tmp_path, pinned, monkeypatch):
    ix = indexes()
    pinned(public=())
    c = si.ScanIndexClient(workdir=tmp_path, endpoints=ix.endpoints, environ=dict(fk.ENV))
    assert c.profile.slug == "scan-index-test"
    assert c.lookup(CERT, ["netlas"]).results[0].status == si.REFUSED
    pinned()
    c = si.ScanIndexClient(workdir=tmp_path, endpoints=ix.endpoints, environ=dict(fk.ENV))
    assert c.lookup(CERT, ["netlas"]).results[0].status == si.OK
    scope.unpin()
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b114")
    with pytest.raises(si.ScanIndexRefused, match="profile did not load"):
        si.ScanIndexClient(workdir=tmp_path, environ=dict(fk.ENV))


def test_the_provider_list_is_closed_only_a_loopback_fake_may_stand_in(tmp_path):
    kw = {"profile": fk.profile(), "workdir": tmp_path, "environ": dict(fk.ENV)}
    assert si.ScanIndexClient(**kw).endpoints == si.OFFICIAL_ENDPOINTS
    assert si.OFFICIAL_ENDPOINTS == {
        "shodan": "https://api.shodan.io", "censys": "https://api.platform.censys.io",
        "fofa": "https://fofa.info", "netlas": "https://app.netlas.io",
        "internetdb": "https://internetdb.shodan.io"}
    ok = si.ScanIndexClient(endpoints={"shodan": "http://127.0.0.1:9/", "fofa": "https://fofa.info",
                                       "netlas": "http://[::1]:9"}, **kw)
    assert ok.endpoints["shodan"] == "http://127.0.0.1:9" and ok.endpoints["censys"] == si.OFFICIAL_ENDPOINTS["censys"]
    for name, base in (("shodan", "https://api.shodan.io.evil.test"), ("shodan", "https://evil.test"),
                       ("censys", "http://10.0.0.5:8080"), ("fofa", "http://localhost.evil.test:80"),
                       ("netlas", "http://127.0.0.1:9/steal"), ("netlas", "ftp://127.0.0.1:9"),
                       ("netlas", "http://user@127.0.0.1:9"), ("shodan", "https://fofa.info")):
        with pytest.raises(ValueError, match="loopback|closed"):
            si.ScanIndexClient(endpoints={name: base}, **kw)
    with pytest.raises(ValueError, match="unknown scan-index provider"):
        si.ScanIndexClient(endpoints={"zoomeye": "http://127.0.0.1:9"}, **kw)


def test_every_answered_request_is_one_ledger_row_without_a_key(indexes, tmp_path):
    ix = indexes()
    _client(ix, tmp_path, challenge="9168").lookup(CERT)
    rows = _rows(tmp_path)
    assert [(r["provider"], r["op"], r["pivot"], r["status"], r["http_status"], r["rows"]) for r in rows] == [
        ("shodan", "search", "cert", "ok", 200, 1), ("censys", "search", "cert", "ok", 200, 1),
        ("fofa", "search", "cert", "ok", 200, 3), ("netlas", "search", "cert", "ok", 200, 1)]
    assert {r["value"] for r in rows} == {fk.CERT_SHA256} and {r["challenge"] for r in rows} == {"9168"}
    assert {r["event_slug"] for r in rows} == {"scan-index-test"} and all("reason" not in r for r in rows)
    raw = ledger.path(tmp_path).read_text()
    assert not any(key in raw for key in fk.KEYS.values())
    use = si.usage(tmp_path, environ={})
    assert {p: u.used for p, u in use.items()} == {"shodan": 1, "censys": 1, "fofa": 1, "netlas": 1, "internetdb": 0}
    # with no challenge the tag is absent, not empty
    _client(ix, tmp_path, refresh=True).lookup(CERT, ["netlas"])
    assert "challenge" not in _rows(tmp_path)[-1]


def test_the_budget_stops_a_provider_at_exactly_its_limit(indexes, tmp_path):
    ix = indexes()
    c = _client(ix, tmp_path, budget=2)
    assert c.lookup(CERT, ["netlas"]).results[0].status == si.OK
    assert c.lookup(ICON, ["netlas"]).results[0].status == si.OK              # the second and last
    over = c.lookup(si.title_pivot(fk.TITLE), ["netlas"]).results[0]
    assert over.status == si.BUDGET and "2 of 2" in over.reason
    assert "CTF_SCAN_INDEX_BUDGET_NETLAS" in over.reason
    assert len(ix["netlas"].requests) == 2 and len(_rows(tmp_path)) == 2
    # the budget is per provider: another one is still asked
    assert c.lookup(si.title_pivot(fk.TITLE), ["shodan"]).results[0].status == si.OK
    # and it reads the workdir's ledger, so a new client inherits what was spent
    assert _client(ix, tmp_path, budget=2).lookup(si.title_pivot("other"), ["netlas"]).results[0].status == si.BUDGET
    assert _client(ix, tmp_path, budget=3).lookup(si.title_pivot("other"), ["netlas"]).results[0].status == si.OK
    zero = _client(ix, tmp_path / "fresh", budget=0).lookup(CERT, ["censys"]).results[0]
    assert zero.status == si.BUDGET and ix["censys"].requests == []
    with pytest.raises(ValueError, match="int >= 0"):
        _client(ix, tmp_path, budget=-1)


def test_an_answer_is_cached_so_a_repeat_costs_no_request(indexes, tmp_path):
    ix = indexes()
    first = _client(ix, tmp_path).lookup(CERT, ["netlas"]).results[0]
    again = _client(ix, tmp_path, environ={}).lookup(CERT, ["netlas"]).results[0]     # even with no key now
    assert (first.cached, again.cached) == (False, True) and again.status == si.OK
    assert again.rows == first.rows and again.cached_ts == _rows(tmp_path)[0]["ts"]
    assert len(ix["netlas"].requests) == 1 and len(_rows(tmp_path)) == 1
    assert again.to_dict()["cached"] is True and "cached" not in first.to_dict()
    # a different pivot or provider is a different entry
    assert not _client(ix, tmp_path).lookup(ICON, ["netlas"]).results[0].cached
    assert not _client(ix, tmp_path).lookup(CERT, ["censys"]).results[0].cached
    # the cache is local evidence: it is read even where the event's scope would refuse a new request
    closed = _client(ix, tmp_path, profile=fk.profile(public=())).lookup(CERT, ["netlas", "shodan"])
    assert [(r.status, r.cached) for r in closed.results] == [(si.OK, True), (si.REFUSED, False)]
    assert len(ix["netlas"].requests) == 2 and ix["shodan"].requests == []
    # refresh asks again and rewrites the entry
    fresh = _client(ix, tmp_path, refresh=True).lookup(CERT, ["netlas"]).results[0]
    assert not fresh.cached and len([r for r in ix["netlas"].requests if "certificate" in r.query["q"][0]]) == 2
    files = sorted((tmp_path / si.CACHE_DIR).glob("*.json"))
    assert len(files) == 3 and all(f.stat().st_mode & 0o077 == 0 for f in files)
    assert not any(key in f.read_text() for f in files for key in fk.KEYS.values())


def test_a_failed_request_is_not_cached_and_a_broken_cache_file_is_loud(indexes, tmp_path):
    ix = indexes({"netlas": lambda rec: (500, {"detail": "boom"})})
    assert _client(ix, tmp_path).lookup(CERT, ["netlas"]).results[0].status == si.ERROR
    assert not (tmp_path / si.CACHE_DIR).exists()
    assert _client(ix, tmp_path).lookup(CERT, ["netlas"]).results[0].status == si.ERROR
    assert len(ix["netlas"].requests) == 2                                   # asked again, not served
    ok = indexes()
    _client(ok, tmp_path).lookup(CERT, ["censys"])
    (cache,) = (tmp_path / si.CACHE_DIR).glob("censys-*.json")
    cache.write_text("{not json")
    with pytest.raises(si.ScanIndexError, match="unreadable"):
        _client(ok, tmp_path).lookup(CERT, ["censys"])


def test_a_redirect_is_never_followed_so_a_key_cannot_travel(indexes, tmp_path):
    thief = fk.FakeIndex(lambda rec: (200, fk.SHODAN_SEARCH))
    try:
        ix = indexes({"shodan": lambda rec: (302, {}, {"Location": thief.base + rec.raw_path})})
        res = _client(ix, tmp_path).lookup(CERT, ["shodan"]).results[0]
        assert res.status == si.ERROR and res.http_status == 302 and "redirect" in res.reason
        assert thief.requests == [] and res.rows == ()
        assert len(ix["shodan"].requests) == 1
        assert _rows(tmp_path)[0]["status"] == "error"
    finally:
        thief.close()


def test_a_key_a_provider_echoes_never_reaches_a_result_the_ledger_or_the_cache(indexes, tmp_path):
    sk, nk = fk.KEYS["shodan"], fk.KEYS["netlas"]

    def shodan(rec):
        return 401, {"error": f"Invalid API key: {sk} (url {rec.raw_path})"}

    def netlas(rec):
        doc = json.loads(json.dumps(fk.NETLAS_SEARCH))
        doc["items"][0]["data"]["http"]["title"] = f"echo {nk}"
        doc["items"][0]["data"]["http"]["body"] = f"<p>token: {nk}</p>"
        return 200, doc

    ix = indexes({"shodan": shodan, "netlas": netlas})
    rep = _client(ix, tmp_path).lookup(CERT, ["shodan", "netlas"])
    sh, ne = rep.results
    assert sh.status == si.AUTH and "<redacted>" in sh.reason
    assert ne.status == si.OK and ne.rows[0].title == "echo <redacted>"
    everything = (json.dumps(rep.to_dict()) + repr(rep) + ledger.path(tmp_path).read_text()
                  + "".join(f.read_text() for f in (tmp_path / si.CACHE_DIR).glob("*.json")))
    assert sk not in everything and nk not in everything
    assert "<redacted>" in _rows(tmp_path)[0]["reason"]
    # the cache writer scrubs whatever it is handed, not only rows the client already cleaned
    c = _client(ix, tmp_path)
    req = si.build_request("netlas", si.title_pivot("scrub me"))
    c._cache_write(req, (si.Row("netlas", fk.ORIGIN, 80, title=f"raw {nk}"),), f"note {sk}", 1.0)
    written = c._cache_path(req).read_text()
    assert sk not in written and nk not in written and written.count("<redacted>") == 2
    # the scrubber also catches the URL-encoded spelling of a key
    c = _client(ix, tmp_path, environ={"CTF_SCAN_INDEX_SHODAN_KEY": "k/ey+with spaces"})
    assert c.scrub("a k/ey+with spaces b k%2Fey%2Bwith%20spaces c") == "a <redacted> b <redacted> c"
    # and the query-string spelling urlencode gives it (quote_plus: a space is "+")
    assert c.scrub("url ?key=k%2Fey%2Bwith+spaces&x=1") == "url ?key=<redacted>&x=1"


def test_a_key_with_a_space_or_plus_is_scrubbed_from_what_a_provider_echoes(indexes, tmp_path):
    odd = "ab cd+ef/gh-0009"
    plus = urllib.parse.quote_plus(odd, safe="")
    assert plus != urllib.parse.quote(odd, safe="")                         # the spelling that leaked
    ix = indexes({"shodan": lambda rec: (401, {"error": f"bad key in {rec.raw_path}"})})
    environ = {**fk.ENV, "CTF_SCAN_INDEX_SHODAN_KEY": odd}
    res = _client(ix, tmp_path, environ=environ).lookup(CERT, ["shodan"]).results[0]
    sent = ix["shodan"].requests[0]
    assert sent.query["key"] == [odd] and plus in sent.raw_path             # the key went, quote_plus'd
    assert res.status == si.AUTH and "<redacted>" in res.reason
    assert plus not in res.reason and odd not in res.reason
    assert plus not in ledger.path(tmp_path).read_text()


@pytest.mark.parametrize("status,payload,want,word", [
    (401, {"error": "bad key"}, si.AUTH, "bad key"),
    (403, {"detail": "plan lacks search"}, si.AUTH, "plan lacks search"),
    (402, {"detail": "Not Enough Coins"}, si.QUOTA, "Not Enough Coins"),
    (429, {"detail": "slow down"}, si.QUOTA, "slow down"),
    (500, {"detail": "boom"}, si.ERROR, "HTTP 500: boom"),
    (404, {"detail": "Not found."}, si.ERROR, "HTTP 404"),               # a 404 on a search is not "no results"
    (200, b"<html>bot check</html>", si.ERROR, "not JSON"),
    (200, {"took": 1}, si.ERROR, "malformed"),
    (200, [1, 2], si.ERROR, "malformed"),
])
def test_provider_failures_are_classified_and_never_read_as_zero_results(indexes, tmp_path, status, payload, want, word):
    ix = indexes({"netlas": lambda rec: (status, payload)})
    res = _client(ix, tmp_path).lookup(CERT, ["netlas"]).results[0]
    assert res.status == want and word in res.reason and res.rows == () and not res.answered
    assert res.http_status == status
    (row,) = _rows(tmp_path)
    assert (row["status"], row["http_status"], row["rows"]) == (want, status, 0) and word in row["reason"]
    assert si.usage(tmp_path, environ={})["netlas"].used == 1               # it still spent a request
    assert len(ix["netlas"].requests) == 1                                  # and was not retried


def test_a_key_is_never_accepted_as_a_search_term(indexes, tmp_path):
    ix = indexes()
    c = _client(ix, tmp_path)
    with pytest.raises(si.PivotError, match="never sent as a search term"):
        c.lookup(si.title_pivot(f"leak {fk.KEYS['fofa']} here"))
    assert ix.total_requests() == 0 and _rows(tmp_path) == []


def test_the_request_timeout_is_applied(indexes, tmp_path):
    import time

    def slow(rec):
        time.sleep(1.0)
        return 200, fk.NETLAS_SEARCH
    ix = indexes({"netlas": slow})
    # Wall-clock on purpose: the behaviour is a socket timeout. The fake answers after 1.0 s and the
    # client gives up after 0.25 s; a slower machine only makes the fake slower, never faster, so the
    # outcome cannot flip to "ok" under load. Without the timeout the answer would arrive and be ok.
    res = _client(ix, tmp_path, timeout=0.25).lookup(CERT, ["netlas"]).results[0]
    assert res.status == si.ERROR and "no answer" in res.reason and res.http_status is None
    assert si.usage(tmp_path, environ={})["netlas"].used == 0


def test_fofa_errors_inside_a_200_are_errors_and_its_points_code_is_quota(indexes, tmp_path):
    ix = indexes({"fofa": lambda rec: (200, {"error": True, "errmsg": "[820000] FOFA Query Syntax Incorrect"})})
    res = _client(ix, tmp_path).lookup(CERT, ["fofa"]).results[0]
    assert res.status == si.ERROR and "820000" in res.reason
    ix2 = indexes({"fofa": lambda rec: (200, {"error": True, "errmsg": "[820031] insufficient points"})})
    res = _client(ix2, tmp_path).lookup(ICON, ["fofa"]).results[0]
    assert res.status == si.QUOTA
    assert si.usage(tmp_path, environ={})["fofa"].quota_hit_ts == _rows(tmp_path)[-1]["ts"]


def test_a_404_on_a_host_lookup_is_an_answer_of_no_record(indexes, tmp_path):
    ix = indexes()
    rep = _client(ix, tmp_path).lookup(si.host_pivot("198.51.100.200"), ["shodan", "censys", "internetdb"])
    assert [r.status for r in rep.results] == [si.OK] * 3 and rep.services == ()
    assert all(r.rows == () and "no record" in r.reason for r in rep.results)
    assert "plan may not see" in rep.results[1].reason and "plan" not in rep.results[0].reason
    # the note is on the result, not the ledger: an ok row never carries a reason
    rows = _rows(tmp_path)
    assert [(r["status"], r["http_status"]) for r in rows] == [("ok", 404)] * 3
    assert all("reason" not in r for r in rows)


def test_an_oversized_answer_is_an_error(indexes, tmp_path, monkeypatch):
    ix = indexes()
    monkeypatch.setattr(si, "MAX_RESPONSE_BYTES", 64)
    res = _client(ix, tmp_path).lookup(CERT, ["netlas"]).results[0]
    assert res.status == si.ERROR and "64-byte cap" in res.reason and res.rows == ()
    # the provider answered (and charged its quota): the row carries the status and spends budget
    assert res.http_status == 200
    (row,) = _rows(tmp_path)
    assert (row["status"], row["http_status"], row["rows"]) == ("error", 200, 0) and "cap" in row["reason"]
    assert si.usage(tmp_path, environ={})["netlas"].used == 1
    assert not (tmp_path / si.CACHE_DIR).exists()                             # never cached
    monkeypatch.setattr(si, "MAX_RESPONSE_BYTES", len(json.dumps(fk.NETLAS_SEARCH).encode()))
    assert _client(ix, tmp_path).lookup(CERT, ["netlas"]).results[0].status == si.OK    # exactly at the cap


def test_no_answer_at_all_is_an_error_that_spends_no_budget(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead = f"http://127.0.0.1:{s.getsockname()[1]}"
    s.close()                                                # nothing listens here now
    c = si.ScanIndexClient(profile=fk.profile(), workdir=tmp_path, environ=dict(fk.ENV),
                           endpoints={"netlas": dead}, budget=1)
    res = c.lookup(CERT, ["netlas"]).results[0]
    assert res.status == si.ERROR and "no answer" in res.reason and res.http_status is None
    (row,) = _rows(tmp_path)
    assert row["status"] == "error" and "http_status" not in row
    assert si.usage(tmp_path, budget=1, environ={})["netlas"].used == 0
    assert c.lookup(CERT, ["netlas"]).results[0].status == si.ERROR          # still allowed to ask
    assert fk.KEYS["netlas"] not in res.reason


def test_the_host_lookup_unions_five_indexes_and_surfaces_the_back_office(indexes, tmp_path):
    ix = indexes()
    rep = _client(ix, tmp_path).lookup(si.host_pivot(fk.ORIGIN))
    assert rep.answered == ("shodan", "censys", "fofa", "netlas", "internetdb")
    assert len(ix["internetdb"].requests) == 1 and ix["internetdb"].requests[0].path == f"/{fk.ORIGIN}"
    assert "authorization" not in ix["internetdb"].requests[0].headers and ix["internetdb"].requests[0].query == {}
    assert ix["shodan"].requests[0].path == f"/shodan/host/{fk.ORIGIN}"
    assert ix["censys"].requests[0].headers["accept"] == "application/vnd.censys.api.v3.host.v1+json"
    services = {s.port: s for s in rep.services}
    assert sorted(services) == [22, 443, 8080]
    panel = services[8080]
    assert panel.providers == ("censys", "fofa", "netlas", "internetdb") and panel.missing_from == ("shodan",)
    assert panel.title == "Synthetic Internal Ops" and panel.non_public()
    assert panel.findings == (("censys", si.Finding("uuid", fk.PANEL_UUID, "recovery token")),)
    doc = rep.to_dict()
    assert [s["port"] for s in doc["services"]] == [443, 8080, 22]           # most agreed-on first
    assert doc["services"][1]["findings"] == [
        {"provider": "censys", "kind": "uuid", "value": fk.PANEL_UUID, "label": "recovery token"}]


def test_lookup_rejects_unknown_providers_and_asks_a_repeated_one_once(indexes, tmp_path):
    ix = indexes()
    c = _client(ix, tmp_path)
    with pytest.raises(ValueError, match="unknown scan-index provider"):
        c.lookup(CERT, ["shodan", "zoomeye"])
    with pytest.raises(ValueError, match="no scan-index provider"):
        c.lookup(CERT, [])
    assert ix.total_requests() == 0
    rep = c.lookup(CERT, ["netlas", "netlas"])
    assert len(rep.results) == 1 and len(ix["netlas"].requests) == 1
    # the search pivots never ask InternetDB by default; the host pivot does
    assert [r.provider for r in c.lookup(ICON).results] == ["shodan", "censys", "fofa", "netlas"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
