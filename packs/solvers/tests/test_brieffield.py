"""B-088: brief-URL fetch + labeled-field extractor (ctf/brieffield.py, the fastlane try_osint branch and
the intake worker's brief-url step).

A brief that names a site and asks for one field on it ("Find the company registration number
shown on the site") gets one scope-checked GET of the site and the page's label/value pair matched
to the noun (the "Reg. No." value and not the "Licence" value beside it). The value is a candidate
with an instruction, never a flag.

Every brief, page, name and value here is invented for these tests; only the structure follows the
item (a Reg. No. beside a Licence, in the title, a meta description and table cells). Live fetches go
only to a loopback HTTP server the test starts on 127.0.0.1, under a test profile whose
rules.live_service_scope lists it (or a `policy point` record); out-of-scope URLs are checked with
recorders that must stay untouched.

Run:  .venv/bin/python -m pytest tests/test_brieffield.py
"""
from __future__ import annotations

import datetime as dt
import http.server
import json
import threading

import pytest

from ctf import brieffield as B
from ctf import config as _config
from ctf import event, eventpolicy, fastlane, scope
from ctf import intake as I
from ctf.platform.base import Challenge, PlatformError

REG = "QH-4180-2263"
LIC = "FBMA-58-0316"


def brief(url: str) -> str:
    """An invented brief with the item's shape: markup, a site URL, a field asked three ways."""
    return (
        "\U0001f4e3 A forum advert for Quillmere Holdings promises fixed weekly payouts.<br>\n"
        "**Rules**: everything here is staged. Look, do not touch.<br>\n**Forum post A-63** (quoted):<br>\n"
        f"> The poster links the fund at {url} and says it is \"licensed by the Fenwick Bay Markets "
        "Authority\".<br>**Part one - The Site**<br>\n"
        "Find the company registration number shown on the Quillmere Holdings site.<br>\n"
        "**Answer**: the registration number.<br>\nFlag format: `CSCTF{<answer>}`<br><br>"
        "<strong>Format note:</strong> give the registration number in the same form the site uses.")


PAGE = f"""<!doctype html><html><head>
<title>Quillmere Holdings | Fixed Weekly Payouts | Reg. No. {REG}</title>
<meta name="description" content="Quillmere Holdings. Licensed. Reg. No. {REG}">
<script>var decoy = "Reg. No. SCRIPT-0000-1111";</script>
<style>.reg::after {{ content: "Reg. No. STYLE-2222" }}</style>
</head><body>
<header><div class="brand">Quillmere Holdings</div><div class="reg">Reg. No. {REG}</div></header>
<main><h1>Earn 3% every week</h1><p>Payouts land every Friday.</p></main>
<div class="trust">Licensed by the Fenwick Bay Markets Authority | Licence {LIC} | Reg. No. {REG}</div>
<table><tr><th>Registration date</th><td>2025-06-14</td></tr></table>
</body></html>"""


def profile(scope_list, *, slug="brief-test", base_url="https://board.brief-platform.test", pointed="forbidden"):
    return event.parse({
        "slug": slug, "name": "brief-url test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": base_url},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope_list), "pointed_services": pointed},
    }, src="tests/test_brieffield.py")


class _Site:
    """A loopback HTTP server: path -> (status, headers, body). Records every request path."""

    def __init__(self, routes):
        self.routes = routes
        self.seen: list[str] = []
        site = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                site.seen.append(self.path)
                status, headers, body = site.routes.get(self.path, (404, {}, b"not here"))
                body = body.encode() if isinstance(body, str) else body
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


HTML = {"Content-Type": "text/html; charset=utf-8"}


@pytest.fixture
def no_proxy_env(monkeypatch):
    for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(k, "http://127.0.0.1:9")          # a proxy would be refused; ours must not use it
    monkeypatch.delenv("CTF_PLATFORM_URL", raising=False)


# ------------------------------------------------------------------------------- the brief

def test_field_question_reads_the_noun_the_task_names():
    f = B.field_question(brief("https://x.test"))
    assert f is not None
    assert f.phrase == "company registration number"
    assert (f.key, f.head) == ("registration", "number")
    assert f.mentions == 3                                   # find / answer / submit all name it
    assert f.kind == "id"


def test_field_question_rejects_a_vague_or_absent_noun():
    assert B.field_question("Find the number on https://x.test") is None
    assert B.field_question("Exploit the service at https://x.test and read /flag") is None
    d = B.field_question("What is the registration date of https://x.test?")
    assert (d.key, d.head, d.kind) == ("registration", "date", "text")


def test_field_question_prefers_the_field_asked_most():
    f = B.field_question("Find the licence number. Answer: the registration number. "
                         "Submit the registration number.")
    assert (f.key, f.head) == ("registration", "number")


def test_brief_urls_in_order_deduplicated_without_trailing_punctuation():
    text = "Site is https://a.test/x. Mirror (https://b.test/y), again https://a.test/x; `https://c.test`"
    assert B.brief_urls(text) == ["https://a.test/x", "https://b.test/y", "https://c.test"]


def test_wrapped_uses_the_brief_answer_wrapper():
    assert B.wrapped(brief("https://x.test"), REG) == f"CSCTF{{{REG}}}"
    assert B.wrapped("no wrapper here", REG) is None


# ------------------------------------------------------------------------------- the page

def test_page_lines_keep_title_meta_and_body_and_drop_script_and_style():
    lines = B.page_lines(PAGE)
    wheres = [w for w, _ in lines]
    text = "\n".join(t for _, t in lines)
    assert "title" in wheres and "meta description" in wheres
    assert "SCRIPT-0000-1111" not in text and "STYLE-2222" not in text
    assert f"Licence {LIC} | Reg. No. {REG}" in text


def test_reg_no_is_matched_and_the_licence_and_registration_date_are_not():
    f = B.field_question(brief("https://x.test"))
    hits = B.label_values(B.page_lines(PAGE), f)
    assert {h.value for h in hits} == {REG}
    assert all(h.label == "Reg. No." for h in hits)
    assert {"title", "meta description", "body"} <= {h.where for h in hits}
    best, values = B.rank(hits)
    assert best.value == REG and len(values) == 1


def test_licence_question_reads_the_licence_not_the_registration():
    f = B.field_question("Find the licence number shown on https://x.test")
    best, _ = B.rank(B.label_values(B.page_lines(PAGE), f))
    assert best.value == LIC


def test_table_cell_label_takes_the_next_cell_as_value():
    f = B.field_question("What is the company registration number? See https://x.test")
    page = "<table><tr><th>Company Registration Number</th><td>HRB 12345</td></tr>" \
           "<tr><th>VAT</th><td>DE999</td></tr></table>"
    best, _ = B.rank(B.label_values(B.page_lines(page), f))
    assert best.value == "HRB 12345"


def test_identifier_stops_at_the_next_label():
    f = B.field_question("Find the registration number.")
    hits = B.label_values("Reg. No. 0042-77 VAT DE123 Phone +44 1", f)
    assert [h.value for h in hits] == ["0042-77"]


def test_company_no_spelling_means_the_registration_number():
    f = B.field_question("Find the company registration number.")
    hits = B.label_values("Registered office: 1 Main St\nCompany No: 09876543", f)
    assert [h.value for h in hits] == ["09876543"]


def test_label_without_a_value_gives_no_hit():
    f = B.field_question("Find the registration number.")
    assert B.label_values("Registration number: pending review", f) == []


def test_two_distinct_values_with_equal_labels_give_no_single_candidate():
    f = B.field_question("Find the registration number.")
    best, values = B.rank(B.label_values("Reg. No. AAA-1\nReg. No. BBB-2", f))
    assert best is None
    assert sorted(v["value"] for v in values) == ["AAA-1", "BBB-2"]


def test_a_strictly_better_label_wins_among_distinct_values():
    f = B.field_question("Find the company registration number.")
    best, values = B.rank(B.label_values("Registration: OLD-1\nCompany Registration Number: NEW-2", f))
    assert best.value == "NEW-2" and len(values) == 2


def test_email_field_reads_an_address():
    f = B.field_question("What is the support email of the shop at https://x.test?")
    assert f.kind == "email"
    hits = B.label_values("Support email: help@shop.test (24/7)", f)
    assert [h.value for h in hits] == ["help@shop.test"]


# ------------------------------------------------------------------------------- the fetch, in scope

def test_one_scoped_get_of_the_brief_url_gives_a_candidate_not_a_flag(no_proxy_env):
    with _Site({"/": (200, HTML, PAGE)}) as site:
        prof = profile(["127.0.0.0/8"])
        r = B.try_brief_url({"description": brief(site.url + "/")}, profile=prof)
        assert site.seen == ["/"]                           # exactly one GET
    assert r["klass"] == "osint:brief-url"
    assert r["flag"] is None
    assert r["candidate"] == REG
    assert r["confidence"] == "medium"
    assert r["wrapped"] == f"CSCTF{{{REG}}}"
    assert r["fetched"] == [site.url + "/"]
    assert LIC not in [c["value"] for c in r["candidates"]]
    assert "verify" in r["instruction"] and REG in r["instruction"]


def test_pointed_service_is_fetched_when_the_scope_does_not_list_it(no_proxy_env, tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    with _Site({"/": (200, HTML, PAGE)}) as site:
        prof = profile(["*.other-chal.test"], pointed="allowed")
        r0 = B.try_brief_url({"description": brief(site.url + "/")}, profile=prof)
        assert site.seen == [] and r0["candidate"] is None and r0["refused"]
        eventpolicy.point(prof, "4401", f"127.0.0.1:{site.port}", "the brief names this site", workdir=tmp_path)
        r = B.try_brief_url({"description": brief(site.url + "/")}, profile=prof)
        assert site.seen == ["/"]
    assert r["candidate"] == REG


def test_out_of_scope_url_is_never_fetched_and_is_named():
    calls = []
    prof = profile(["127.0.0.0/8"])
    r = B.try_brief_url({"description": brief("https://quillmere.example.org/")}, profile=prof,
                        fetch=lambda u: calls.append(u) or PAGE)
    assert calls == []                                       # the scope check runs before an injected fetch
    assert r["candidate"] is None and r["flag"] is None
    assert r["refused"][0]["url"] == "https://quillmere.example.org/"
    assert "live_service_scope" in r["refused"][0]["reason"]
    assert "policy point" in r["instruction"]


def test_the_event_platform_is_never_fetched_even_when_the_scope_matches(no_proxy_env):
    with _Site({"/": (200, HTML, PAGE)}) as site:
        prof = profile(["127.0.0.0/8"], base_url=site.url)
        r = B.try_brief_url({"description": brief(site.url + "/")}, profile=prof)
        assert site.seen == []
    assert r["candidate"] is None
    assert "event platform" in r["refused"][0]["reason"]


def test_redirect_to_an_out_of_scope_host_is_not_followed(no_proxy_env):
    with _Site({"/": (302, {"Location": "http://quillmere.example.org/"}, "")}) as site:
        prof = profile(["127.0.0.0/8"])
        with pytest.raises(scope.OutOfScope, match="redirect target"):
            B.scoped_get(site.url + "/", profile=prof)
        r = B.try_brief_url({"description": brief(site.url + "/")}, profile=prof)
    assert r["candidate"] is None
    assert any("redirect target" in x["reason"] for x in r["refused"])


def test_redirect_inside_the_scope_is_followed(no_proxy_env):
    with _Site({"/": (301, {"Location": "/home"}, ""), "/home": (200, HTML, PAGE)}) as site:
        r = B.try_brief_url({"description": brief(site.url + "/")}, profile=profile(["127.0.0.0/8"]))
        assert site.seen == ["/", "/home"]
    assert r["candidate"] == REG


def test_http_error_is_named_and_gives_no_candidate(no_proxy_env):
    with _Site({}) as site:
        r = B.try_brief_url({"description": brief(site.url + "/")}, profile=profile(["127.0.0.0/8"]))
    assert r["candidate"] is None
    assert "HTTP 404" in r["how"]
    assert site.url in r["instruction"]


def test_the_read_is_capped_at_max_bytes(no_proxy_env):
    body = "<html><body><p>" + "x" * 4000 + f"</p><div>Reg. No. {REG}</div></body></html>"
    with _Site({"/": (200, HTML, body)}) as site:
        prof = profile(["127.0.0.0/8"])
        cut = B.scoped_get(site.url + "/", profile=prof, max_bytes=1000)
        full = B.scoped_get(site.url + "/", profile=prof)
    assert len(cut) == 1000 and REG not in cut
    assert REG in full


def test_offline_gives_the_instruction_without_a_fetch():
    calls = []
    r = B.try_brief_url({"description": brief("http://127.0.0.1:1/")}, profile=profile(["127.0.0.0/8"]),
                        fetch=lambda u: calls.append(u) or PAGE, online=False)
    assert calls == []
    assert r["candidate"] is None and "http://127.0.0.1:1/" in r["instruction"]


def test_no_field_question_or_no_url_is_not_this_branch():
    calls = []
    prof = profile(["127.0.0.0/8"])
    fetch = lambda u: calls.append(u) or PAGE                               # noqa: E731
    assert B.try_brief_url({"description": "Pwn the service at http://127.0.0.1:1/"}, profile=prof,
                           fetch=fetch) is None
    assert B.try_brief_url({"description": "Find the company registration number."}, profile=prof,
                           fetch=fetch) is None
    assert calls == []


# ------------------------------------------------------------------------------- fastlane try_osint

def test_fastlane_try_solve_returns_the_brief_url_candidate(tmp_path):
    # The suite pins a profile whose scope lists *.test (tests/conftest.py); the fetch is injected.
    seen = []
    url = "https://quillmere.chal.test/"
    d = {"name": "Check the Site", "category": "OSINT", "description": brief(url)}
    r = fastlane.try_solve(d, tmp_path, cfg=_config.load(), fetch=lambda u: seen.append(u) or PAGE)
    assert seen == [url]
    assert r["klass"] == "osint:brief-url" and r["candidate"] == REG and r["flag"] is None


def test_fastlane_does_not_fetch_an_out_of_scope_brief_url(tmp_path):
    seen = []
    d = {"name": "Check the Site", "category": "OSINT", "description": brief("https://quillmere.example.org/")}
    r = fastlane.try_solve(d, tmp_path, cfg=_config.load(), fetch=lambda u: seen.append(u) or PAGE)
    assert seen == []
    assert r["klass"] == "osint:brief-url" and r["candidate"] is None and r["flag"] is None


# ------------------------------------------------------------------------------- intake

class FakeAdapter:
    kind = "fake"

    def __init__(self, ch):
        self.ch = ch
        self.submits = []

    def list_challenges(self):
        return [self.ch]

    def get_challenge(self, cid):
        if cid != self.ch.id:
            raise PlatformError(f"get_challenge({cid}): 404")
        return self.ch

    def download_files(self, cid, dest):
        return []

    def submit(self, cid, flag):
        self.submits.append((cid, flag))
        raise AssertionError("intake must never submit")


def _intake(tmp_path, url, prof, **opt):
    ch = Challenge(id="4401", name="Staged Fund: Check the Site", category="OSINT", points=200,
                   description=brief(url), files=(), solved_by_team=False)
    ad = FakeAdapter(ch)
    opts = I.Options(engines=False, net_guard="hook", record=False, **opt)
    rep = I.intake_one("4401", prof, adapter=ad, workdir=tmp_path / "wd", options=opts, manifests=[])
    assert ad.submits == []
    return rep


def test_intake_reads_the_brief_url_field_as_a_candidate(no_proxy_env, tmp_path):
    with _Site({"/": (200, HTML, PAGE)}) as site:
        rep = _intake(tmp_path, site.url + "/", profile(["127.0.0.0/8"]))
        assert site.seen == ["/"]
    assert rep.brief_url["candidate"] == REG and rep.brief_url["flag"] is None
    assert rep.status == "none"                              # a candidate value, not a found flag
    assert rep.result.flags == ()
    assert any("brief-url CANDIDATE" in n and REG in n for n in rep.notes)
    j = json.loads((rep.dir / I.REPORT).read_text())
    assert j["brief_url"]["candidate"] == REG
    assert REG in (rep.dir / I.INDEX).read_text()


def test_intake_no_brief_fetch_gives_the_instruction_without_a_get(no_proxy_env, tmp_path):
    with _Site({"/": (200, HTML, PAGE)}) as site:
        rep = _intake(tmp_path, site.url + "/", profile(["127.0.0.0/8"]), brief_fetch=False)
        assert site.seen == []
    assert rep.brief_url["candidate"] is None
    assert any("brief-url" in n and "not fetched" in n for n in rep.notes)


def test_intake_out_of_scope_brief_url_is_named_not_fetched(tmp_path):
    rep = _intake(tmp_path, "https://quillmere.example.org/", profile(["127.0.0.0/8"]))
    assert rep.brief_url["candidate"] is None
    assert rep.brief_url["refused"][0]["url"] == "https://quillmere.example.org/"
    assert any("out of scope" in n for n in rep.notes)


def test_options_argv_carries_no_brief_fetch_to_the_worker():
    assert "--no-brief-fetch" in I.Options(brief_fetch=False).argv()
    assert "--no-brief-fetch" not in I.Options().argv()


class _Captured(Exception):
    pass


def test_worker_and_cli_pass_no_brief_fetch_through(monkeypatch):
    import argparse
    from ctf.cli import intake as cli
    seen = []
    prof = profile(["127.0.0.0/8"])
    monkeypatch.setattr(event, "load", lambda slug: prof)

    def fake_one(cid, p, options=None, **kw):
        seen.append(options.brief_fetch)
        raise _Captured()
    monkeypatch.setattr(I, "intake_one", fake_one)
    assert I.worker_main(["--event", "x", "--id", "1", "--no-brief-fetch"]) == 1
    assert I.worker_main(["--event", "x", "--id", "1"]) == 1
    assert seen == [False, True]

    def fake_many(ids, p, jobs=None, options=None, on_done=None):
        seen.append(options.brief_fetch)
        raise I.IntakeError("captured")
    monkeypatch.setattr(I, "intake_many", fake_many)
    for argv in (["1", "--event", "x", "--no-brief-fetch"], ["1", "--event", "x"]):
        p = argparse.ArgumentParser()
        cli.add_arguments(p)
        assert cli.run(p.parse_args(argv)) == 2
    assert seen == [False, True, False, True]


def test_format_template_in_the_brief_is_not_a_sanity_flag():
    assert fastlane._first_flag("Flag format: `CSCTF{<answer>}`") is None
    assert fastlane._first_flag("Flag format: CSCTF{answer}") is None
    assert fastlane._first_flag("Here: CSCTF{real_one}") == "CSCTF{real_one}"


def test_a_specific_single_word_field_takes_an_id_label():
    f = B.field_question("What is the licence of the broker at https://x.test?")
    assert (f.key, f.head, f.kind) == ("licence", None, "id")
    best, _ = B.rank(B.label_values(B.page_lines(PAGE), f))
    assert best.value == LIC


# ------------------------------------------------------------------------------- caps and confidence

EMPTY = "<html><body><p>Nothing to read here.</p></body></html>"
SITE = "https://fund.brief-site.test/"          # in scope for scoped(); fetched only by an injected fetch


def scoped():
    return profile(["*.brief-site.test"])


def test_at_most_max_urls_in_scope_urls_are_fetched_and_refused_ones_do_not_count(no_proxy_env):
    assert B.MAX_URLS == 3
    paths = ("/a", "/b", "/c", "/d")
    with _Site({p: (200, HTML, EMPTY) for p in paths}) as site:
        urls = ["https://off-scope.example.org/"] + [site.url + p for p in paths]
        desc = "Find the company registration number. Pages: " + " ".join(urls)
        r = B.try_brief_url({"description": desc}, profile=profile(["127.0.0.0/8"]))
        assert site.seen == ["/a", "/b", "/c"]              # the fourth in-scope URL is never fetched
    assert r["fetched"] == [site.url + p for p in paths[:3]]
    assert [x["url"] for x in r["refused"]] == ["https://off-scope.example.org/"]
    assert r["candidate"] is None and r["flag"] is None


def test_more_than_max_redirects_fails_with_a_named_error(no_proxy_env):
    assert B.MAX_REDIRECTS == 2
    routes = {"/r1": (302, {"Location": "/r2"}, ""), "/r2": (302, {"Location": "/r3"}, ""),
              "/r3": (302, {"Location": "/home"}, ""), "/home": (200, HTML, PAGE)}
    with _Site(routes) as site:
        prof = profile(["127.0.0.0/8"])
        with pytest.raises(B.BriefFetchError, match=r"more than 2 redirects \(last .*/home\)"):
            B.scoped_get(site.url + "/r1", profile=prof)
        assert site.seen == ["/r1", "/r2", "/r3"]           # the third hop's target is never requested
        assert REG in B.scoped_get(site.url + "/r2", profile=prof)   # two hops: followed
        assert site.seen[3:] == ["/r2", "/r3", "/home"]
        r = B.try_brief_url({"description": brief(site.url + "/r1")}, profile=prof)
    assert r["candidate"] is None and "more than 2 redirects" in r["how"]


def test_redirect_to_a_non_http_url_is_refused_before_it_is_followed(no_proxy_env):
    # urllib's own redirect handler lets an ftp:// Location through and scope.check_url looks only at
    # host and port, so this guard is the only thing between a 302 and the FTP handler.
    with _Site({"/": (302, {"Location": "ftp://127.0.0.1:9/x"}, "")}) as site:
        prof = profile(["127.0.0.0/8"])
        with pytest.raises(B.BriefFetchError,
                           match=r"redirect to a non-http URL refused: ftp://127\.0\.0\.1:9/x"):
            B.scoped_get(site.url + "/", profile=prof)
        r = B.try_brief_url({"description": brief(site.url + "/")}, profile=prof)
        assert site.seen == ["/", "/"]
    assert r["candidate"] is None and r["flag"] is None
    assert "redirect to a non-http URL refused" in r["how"]


def test_scoped_get_refuses_a_non_http_url(tmp_path):
    local = tmp_path / "page.html"
    local.write_text(PAGE)
    prof = profile(["127.0.0.0/8", "localhost"])
    for url in (local.as_uri(), "ftp://127.0.0.1:9/page.html"):
        with pytest.raises(B.BriefFetchError, match=r"is not an http\(s\) URL"):
            B.scoped_get(url, profile=prof)


def test_confidence_is_low_with_several_values_or_a_weak_label_and_medium_otherwise():
    desc = f"Find the company registration number shown on {SITE}"

    def run(page):
        return B.try_brief_url({"description": desc}, profile=scoped(), fetch=lambda u: page)

    two = run("Registration: OLD-1\nCompany Registration Number: NEW-2")
    assert (two["candidate"], two["confidence"]) == ("NEW-2", "low")
    assert "OLD-1" in two["how"]
    weak = run("Registration: OLD-1")                          # one value, label scores 1 (< 2)
    assert (weak["candidate"], weak["confidence"]) == ("OLD-1", "low")
    strong = run("Company Registration Number: NEW-2")
    assert (strong["candidate"], strong["confidence"]) == ("NEW-2", "medium")


def test_many_values_are_listed_up_to_max_listed_with_a_count_of_the_rest():
    assert B.MAX_LISTED == 10
    many = [f"V{i:03d}-9" for i in range(25)]
    page = "\n".join(f"Reg. No. {v}" for v in many)
    r = B.try_brief_url({"description": f"Find the registration number on {SITE}"}, profile=scoped(),
                        fetch=lambda u: page)
    assert r["candidate"] is None
    assert [c["value"] for c in r["candidates"]] == many       # every value stays in the record
    for text in (r["how"], r["instruction"]):
        assert [v for v in many if v in text] == many[:10]
        assert "and 15 more" in text

    page2 = "Company Registration Number: NEW-2\n" + "\n".join(f"Registration: {v}" for v in many)
    r2 = B.try_brief_url({"description": f"Find the company registration number on {SITE}"},
                         profile=scoped(), fetch=lambda u: page2)
    assert r2["candidate"] == "NEW-2"
    assert [v for v in many if v in r2["how"]] == many[:10] and "and 15 more" in r2["how"]

    few = B.try_brief_url({"description": f"Find the registration number on {SITE}"}, profile=scoped(),
                          fetch=lambda u: "Reg. No. AAA-1\nReg. No. BBB-2")
    assert "AAA-1" in few["how"] and "BBB-2" in few["how"] and "more" not in few["how"]
