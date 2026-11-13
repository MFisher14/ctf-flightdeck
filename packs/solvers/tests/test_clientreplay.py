"""B-131: shipped-client constants and the User-Agent replay (ctf/clientreplay.py).

Harvest tests build their files in the test (source text, a raw "disk image" of zeros with strings in
it, a zip). Replay tests talk only to ctf.livereplay's web service on 127.0.0.1, or replace the one
function that sends a request; the scope tests put a recorder where the connection would be opened.
"""
from __future__ import annotations

import datetime as dt
import http.client
import io
import os
import zipfile

import pytest

from ctf import clientreplay as cr
from ctf import event, ledger, livereplay, scope
from ctf.platform.policy import SubmitRequest
from ctf.platform.rules import EventRules

UA = "PINK-OS-CTF/1.0"
HEAD = "PINK{W0w,_P1nk+_0S_1s"
TAIL = "_b3tt3r_th4n_W1ND0WS_4nd_L1NUX}"


def profile(scope_entries=("127.0.0.0/8",), **rules):
    return event.parse({
        "slug": "replay-test", "name": "replay test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.x-platform.test"},
        "flag": {"prefixes": ["PINK"]},
        "rules": {"submit_mode": "auto", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": list(scope_entries), **rules},
    }, src="tests/test_clientreplay.py")


# ------------------------------------------------------------------------------------------ harvest

def uas(data: bytes):
    return [(c.value, c.how, c.stock, c.encoding) for c in cr.scan_bytes(data) if c.kind == "user-agent"]


@pytest.mark.parametrize("source", [
    b"headers = {'User-Agent': 'PINK-OS-CTF/1.0'}",
    b'req.add_header("User-Agent", "PINK-OS-CTF/1.0")',
    b'xhr.setRequestHeader("user-agent","PINK-OS-CTF/1.0");',
    b"USER_AGENT = `PINK-OS-CTF/1.0`",
    b"GET / HTTP/1.1\r\nUser-Agent: PINK-OS-CTF/1.0\r\nHost: x\r\n\r\n",
    b"\x00\x01binary\x00User-Agent: PINK-OS-CTF/1.0\x00\x00more",
    b'sprintf(buf, "User-Agent: PINK-OS-CTF/1.0\\r\\n");',
    b"curl --user-agent 'PINK-OS-CTF/1.0' $URL",
    b"export USER_AGENT=PINK-OS-CTF/1.0\n",
])
def test_a_user_agent_constant_is_found_in_every_form_a_client_writes_it(source):
    assert uas(source) == [(UA, "direct", False, "ascii")]


@pytest.mark.parametrize("source", [
    b'"User-Agent: %s\\r\\n"',                       # a format template, not a value
    b"headers['User-Agent'] = '{}'.format(ua)",
    b"'User-Agent': self.ua,",                        # a variable, not a value
    b"The user agent of the browser is sent with every request",
    b"user_agent_string = 'PINK-OS-CTF/1.0'",        # another name
    b"User-Agent: ab",                                # too short to be one
    b"\"User-Agent\": \"unterminated value\nnext line\"",
])
def test_what_is_not_a_user_agent_constant_is_left_out(source):
    assert [u for u in uas(source) if u[1] == "direct"] == []


def test_stock_user_agents_are_marked_and_custom_ones_are_not():
    got = dict((v, s) for v, _h, s, _e in uas(
        b"User-Agent: curl/8.5.0\r\n 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)' "
        b"\"User-Agent\": \"python-requests/2.31\" 'User-Agent': 'PinkBrowser'"))
    assert got == {"curl/8.5.0": True, "Mozilla/5.0 (X11; Linux x86_64)": True, "python-requests/2.31": True,
                   "PinkBrowser": False}
    assert cr.is_stock_user_agent("Go-http-client/1.1") and not cr.is_stock_user_agent(UA)


def test_a_user_agent_passed_by_variable_is_found_nearby_and_ranked_after_direct_ones():
    src = b'UA = "PinkBrowser/2.0"\nLIB = "libcurl/8.5.0"\n' + b"#" * 300 + b'\nheaders = {"User-Agent": UA}\n'
    assert uas(src) == [("PinkBrowser/2.0", "nearby", False, "ascii")]         # the stock one is not offered
    h = cr.harvest_blobs({"a.py": src, "b.py": b"h = {'User-Agent': 'Direct/1.0'}"})
    assert [(c.value, c.how) for c in h.custom_user_agents()] == [("Direct/1.0", "direct"),
                                                                  ("PinkBrowser/2.0", "nearby")]


def test_utf16_strings_are_read():
    wide = "junk\0User-Agent: Wide-Client/3.1\0home=https://wide.example.org/start\0".encode("utf-16le")
    got = cr.scan_bytes(b"\x00\x00" + wide)
    assert [(c.kind, c.value, c.encoding) for c in got] == [
        ("user-agent", "Wide-Client/3.1", "utf-16le"), ("url", "https://wide.example.org/start", "utf-16le")]
    assert got[0].offset == 2 + len("junk\0".encode("utf-16le"))


def test_urls_are_cleaned_and_templates_dropped():
    src = (b"see https://pink.example.org/a_(b)), then (https://pink.example.org/x). "
           b"HOME='https://pink.example.org/'; api=http://10.1.2.3:8080/v1?x=1&y=2, "
           b"bad=http://%s/path http://{host}/p http://nodot/ http://a.example.org:99999/ end")
    urls = [c.value for c in cr.scan_bytes(src) if c.kind == "url"]
    assert urls == ["https://pink.example.org/a_(b)", "https://pink.example.org/x", "https://pink.example.org/",
                    "http://10.1.2.3:8080/v1?x=1&y=2"]


def test_offsets_point_at_the_constant():
    src = b"A" * 100 + b"User-Agent: Foo/1.0\n" + b"B" * 50 + b"http://foo.example.org/"
    got = {c.kind: c.offset for c in cr.scan_bytes(src, base=1000)}
    assert got == {"user-agent": 1100, "url": 1000 + 100 + 20 + 50}


def write(tmp_path, rel, data: bytes):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def test_harvest_reads_a_raw_image_across_window_boundaries(tmp_path, monkeypatch):
    monkeypatch.setattr(cr, "WINDOW", 4096)
    monkeypatch.setattr(cr, "OVERLAP", 1024)
    monkeypatch.setattr(cr, "HOLD", 512)
    img = bytearray(20000)
    ua = b"\x00User-Agent: PINK-OS-CTF/1.0\x00"
    url = b"HOME=https://pink.example.org/start\x00"
    img[4096 - 12: 4096 - 12 + len(ua)] = ua            # the name starts before the first window ends
    img[8192 - 20: 8192 - 20 + len(url)] = url          # the URL straddles the second boundary
    img[19990 - len(url): 19990] = url                   # and once more in the file's last bytes
    write(tmp_path, "files/data.img", bytes(img))
    h = cr.harvest([tmp_path])
    assert [(c.value, c.path, c.offset, c.count) for c in h.user_agents] == [(UA, "files/data.img", 4096 - 11, 1)]
    assert [(c.value, c.offset, c.count, c.near_ua) for c in h.urls] == [
        ("https://pink.example.org/start", 8192 - 20 + 5, 2, True)]
    assert h.files == 1 and h.scanned_bytes == 20000 and h.truncated == []


def test_a_url_is_the_clients_only_beside_a_custom_user_agent(tmp_path):
    far = cr.NEAR + 5000
    img = bytearray(far + 4096)
    img[100:100 + 28] = b"User-Agent: PINK-OS-CTF/1.0\x00"
    img[300:300 + 25] = b"https://near.example.org/"
    img[100 + far:100 + far + 24] = b"https://far.example.org/"
    write(tmp_path, "disk.img", bytes(img))
    write(tmp_path, "other.txt", b"User-Agent: curl/8.0\n https://beside-stock.example.org/")
    h = cr.harvest([tmp_path])
    assert {c.value: c.near_ua for c in h.urls} == {"https://near.example.org/": True,
                                                    "https://far.example.org/": False,
                                                    "https://beside-stock.example.org/": False}
    assert [c.value for c in h.client_urls()] == ["https://near.example.org/"]


def test_harvest_reads_zip_members_and_never_private_or_own_folders(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(zipfile.ZipInfo("app/pinkbrowser.py", date_time=(2026, 1, 1, 0, 0, 0)),
                    "HOME = 'https://pink.example.org/'\nH = {'User-Agent': 'PINK-OS-CTF/1.0'}\n" * 3)
        zf.writestr(zipfile.ZipInfo("inner.zip", date_time=(2026, 1, 1, 0, 0, 0)), b"PK\x05\x06" + bytes(18))
    write(tmp_path, "files/os.zip", buf.getvalue())
    write(tmp_path, ".ctf/config.json", b'{"User-Agent": "Secret-Client/9.9"}')
    write(tmp_path, "files/.git/config", b"User-Agent: Git-Hidden/1.0\n")
    write(tmp_path, "recon/client/constants.json", b'{"User-Agent": "Own-Report/1.0"}')
    os.symlink(tmp_path / ".ctf" / "config.json", tmp_path / "files" / "link.json")
    h = cr.harvest([tmp_path])
    assert [(c.value, c.path, c.count) for c in h.user_agents] == [(UA, "files/os.zip -> app/pinkbrowser.py", 3)]
    assert [(c.value, c.near_ua) for c in h.urls] == [("https://pink.example.org/", True)]
    assert any("inner.zip" in s and "nested archive" in s for s in h.skipped)
    assert any("link.json" in s and "symbolic link" in s for s in h.skipped)
    assert h.files == 1
    with pytest.raises(cr.ReplayError, match="never read"):
        cr.harvest([tmp_path / ".ctf" / "config.json"])


def test_the_byte_budget_is_explicit_and_a_cut_file_is_named(tmp_path):
    write(tmp_path, "a.bin", b"x" * 5000 + b"User-Agent: Late/1.0\n")
    full = cr.harvest([tmp_path])
    assert [c.value for c in full.user_agents] == ["Late/1.0"] and full.truncated == []
    cut = cr.harvest([tmp_path], max_bytes=1000)
    assert cut.user_agents == [] and cut.scanned_bytes == 1000
    assert cut.truncated == ["a.bin: the byte budget ran out after 1000 bytes"]
    for bad in (0, -1, True, 1.5):
        with pytest.raises(cr.ReplayError, match="max_bytes"):
            cr.harvest([tmp_path], max_bytes=bad)
    with pytest.raises(cr.ReplayError, match="not a file or folder"):
        cr.harvest([tmp_path / "missing"])


def test_an_encrypted_zip_member_is_skipped_by_name(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr(zipfile.ZipInfo("locked.py", date_time=(2026, 1, 1, 0, 0, 0)), "H = {'User-Agent': 'Locked/1.0'}")
    raw = bytearray(buf.getvalue())
    raw[6] |= 1                                              # local header: general-purpose bit 0 = encrypted
    central = raw.index(b"PK\x01\x02")
    raw[central + 8] |= 1
    write(tmp_path, "h.zip", bytes(raw))
    h = cr.harvest([tmp_path])
    assert h.user_agents == [] and h.skipped == ["h.zip -> locked.py: encrypted zip member"]


def test_zip_member_and_url_caps_are_reported(tmp_path, monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(3):
            zf.writestr(zipfile.ZipInfo(f"m{i}.txt", date_time=(2026, 1, 1, 0, 0, 0)), f"https://m{i}.example.org/")
    write(tmp_path, "many.zip", buf.getvalue())
    monkeypatch.setattr(cr, "MAX_ZIP_MEMBERS", 2)
    h = cr.harvest([tmp_path])
    assert [c.value for c in h.urls] == ["https://m0.example.org/", "https://m1.example.org/"]
    assert h.truncated == ["many.zip: 3 zip members, only the first 2 read"]
    monkeypatch.setattr(cr, "MAX_CONSTANTS", 2)
    blob = b" ".join(b"https://u%d.example.org/" % i for i in range(5)) + b" https://u0.example.org/"
    h = cr.harvest_blobs({"urls.txt": blob})
    assert [c.value for c in h.urls] == ["https://u0.example.org/", "https://u1.example.org/"]
    assert h.urls[0].count == 2 and "3 more URL occurrence(s)" in h.truncated[0]
    # a URL beside a custom User-Agent is kept whatever the cap
    h = cr.harvest_blobs({"c.py": blob + b" 'User-Agent': 'Keep/1.0' https://kept.example.org/"})
    assert "https://kept.example.org/" in [c.value for c in h.client_urls()]


# ------------------------------------------------------------------------------------------ replay

HOME = ('<html><a href="/ctf">PINK+ CTF</a> <img src="/logo.png"> <a href="#top">top</a>'
        '<a href="http://outside.example.org/x">elsewhere</a>'
        '<a href="https://board.x-platform.test/challenges">scoreboard</a>'
        '<a href="mailto:x@example.org">mail</a></html>')
ROUTES = {
    "/": {"body": HOME, "headers": {"Content-Type": "text/html"}},
    "/logo.png": {"body": "png", "headers": {"Content-Type": "image/png"}},
    "/ctf": {"body": "<html>please log in</html>", "headers": {"Content-Type": "text/html"},
             "variants": [{"when": {"User-Agent": UA}, "body": TAIL + "\n",
                           "headers": {"Content-Type": "text/plain"}}]},
}


def test_the_second_hop_is_where_the_shipped_user_agent_gets_another_reply():
    prof = profile()
    with livereplay.WebReplay(ROUTES) as svc:
        base = svc.base_url
        rep = cr.replay([base + "/"], [UA], profile=prof, hops=1, interval=0)
        seen = [(path, h.get("user-agent")) for _m, path, h in svc.requests]
    assert seen == [("/", cr.DEFAULT_BASELINE_UA), ("/", UA), ("/ctf", cr.DEFAULT_BASELINE_UA), ("/ctf", UA)]
    assert rep.requests == 4 and rep.skipped_assets == 1 and not rep.capped
    d, = rep.diffs
    assert (d.url, d.ua, d.hop, d.parent, d.unstable) == (base + "/ctf", UA, 1, base + "/", False)
    assert d.what == ["content type text/plain instead of text/html",
                      f"body differs ({len(TAIL) + 1} bytes instead of 26)"]
    assert d.excerpt == TAIL + "\n"
    assert [(f.kind, f.value, f.url, f.ua) for f in rep.fragments] == [("tail", TAIL, base + "/ctf", UA)]
    assert rep.flags == []                                                    # a fragment is not a flag
    assert [(r.url, r.via, r.parent) for r in rep.refused] == [
        ("http://outside.example.org/x", "link", base + "/"),
        ("https://board.x-platform.test/challenges", "link", base + "/")]
    assert "live_service_scope" in rep.refused[0].reason and "event platform" in rep.refused[1].reason
    steps = rep.operator_steps()
    assert len(steps) == 2 and "not contacted: http://outside.example.org/x" in steps[0] and UA in steps[0]
    assert cr.join_fragments(HEAD, rep.fragments[0].value, prof) == HEAD + TAIL


def test_stopping_at_the_home_page_misses_it():
    """hops=0 is what the two earlier passes did: the home page answers every User-Agent alike."""
    with livereplay.WebReplay(ROUTES) as svc:
        rep = cr.replay([svc.base_url + "/"], [UA], profile=profile(), hops=0, interval=0)
        assert [p for _m, p, _h in svc.requests] == ["/", "/"]
    assert rep.diffs == [] and rep.fragments == [] and rep.refused == [] and rep.requests == 2


def test_a_flag_only_the_shipped_user_agent_receives_is_marked():
    routes = {"/": {"body": "format: PINK{...} and PINK{flag}", "variants": [
        {"when": {"User-Agent": UA}, "body": "format: PINK{...} well done PINK{only_for_the_client}"}]},
        "/open": {"body": "everyone gets PINK{public_value}"}}
    with livereplay.WebReplay(routes) as svc:
        rep = cr.replay([svc.base_url + "/", svc.base_url + "/open"], [UA], profile=profile(), hops=0, interval=0)
        base = svc.base_url
    assert [(f.value, f.url, f.ua, f.ua_only) for f in rep.flags] == [
        ("PINK{only_for_the_client}", base + "/", UA, True),
        ("PINK{public_value}", base + "/open", None, False)]
    assert rep.fragments == []                               # a whole flag is not also reported as a tail


class Script:
    """Stands in for clientreplay.get: answers from a function, records every call, opens nothing."""

    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def __call__(self, url, ua, *, profile=None, timeout=None, max_bytes=None, connect=None):
        self.calls.append((url, ua))
        scope.check_url(url, profile=profile)
        got = self.answer(url, ua, len(self.calls))
        if isinstance(got, Exception):
            raise got
        status, headers, body = got
        return status, headers, body, False


def test_a_page_that_changes_by_itself_is_not_read_as_user_agent_gating(monkeypatch):
    fake = Script(lambda url, ua, n: (200, {"content-type": "text/html"}, f"time {n} tail_{n}}}".encode()))
    monkeypatch.setattr(cr, "get", fake)
    rep = cr.replay(["http://127.0.0.1:8000/"], [UA], profile=profile(), hops=0, interval=0)
    d, = rep.diffs
    assert d.unstable and "two normal requests differed as well" in d.what[-1]
    assert rep.gated() == [] and rep.fragments == []
    assert [ua for _u, ua in fake.calls] == [cr.DEFAULT_BASELINE_UA, UA, cr.DEFAULT_BASELINE_UA]


def test_a_whole_flag_on_a_page_that_changes_by_itself_is_not_called_user_agent_only(monkeypatch):
    """A nonce-bearing decoy: every reply carries a different whole flag-format value. The shipped
    User-Agent's value is new to it only because the page never repeats itself."""
    fake = Script(lambda url, ua, n: (200, {"content-type": "text/plain"}, f"nonce PINK{{n0nce_{n}}}".encode()))
    monkeypatch.setattr(cr, "get", fake)
    rep = cr.replay(["http://127.0.0.1:8000/"], [UA], profile=profile(), hops=0, interval=0)
    d, = rep.diffs
    assert d.unstable
    assert [(f.value, f.ua, f.ua_only) for f in rep.flags] == [("PINK{n0nce_1}", None, False),
                                                              ("PINK{n0nce_2}", UA, False)]
    assert rep.fragments == []


def test_a_stable_page_is_checked_once_more_and_stays_gated(monkeypatch):
    fake = Script(lambda url, ua, n: (200, {}, b"for the client" if ua == UA else b"for everyone"))
    monkeypatch.setattr(cr, "get", fake)
    rep = cr.replay(["http://127.0.0.1:8000/"], [UA], profile=profile(), hops=0, interval=0)
    assert [d.unstable for d in rep.diffs] == [False] and len(rep.gated()) == 1 and rep.requests == 3


def test_redirects_are_followed_only_inside_the_scope(monkeypatch):
    def answer(url, ua, n):
        if url.endswith("/old"):
            return 302, {"location": "/new"}, b""
        if url.endswith("/away"):
            return 301, {"location": "https://elsewhere.example.org/landing"}, b""
        if url.endswith("/loop"):
            return 302, {"location": "/loop"}, b""
        return 200, {"content-type": "text/plain"}, b"arrived"
    fake = Script(answer)
    monkeypatch.setattr(cr, "get", fake)
    base = "http://127.0.0.1:8000"
    rep = cr.replay([base + "/old", base + "/away", base + "/loop"], [UA], profile=profile(), hops=0, interval=0)
    by_url = {(r.url, r.ua): r for r in rep.responses}
    assert by_url[(base + "/old", None)].final_url == base + "/new" and by_url[(base + "/old", None)].status == 200
    assert by_url[(base + "/away", UA)].status == 301 and by_url[(base + "/away", UA)].final_url == base + "/away"
    assert [(r.url, r.via, r.parent) for r in rep.refused] == [
        ("https://elsewhere.example.org/landing", "redirect", base + "/away")]
    assert not any("elsewhere.example.org" in u for u, _ in fake.calls)
    loops = [u for u, ua in fake.calls if u.endswith("/loop") and ua == UA]
    assert len(loops) == cr.MAX_REDIRECTS + 1                 # bounded, not endless
    assert rep.diffs == []


def test_a_refused_redirect_is_worded_as_one(monkeypatch):
    fake = Script(lambda url, ua, n: (302, {"location": "https://away.example.org/"}, b""))
    monkeypatch.setattr(cr, "get", fake)
    rep = cr.replay(["http://127.0.0.1:8000/go"], [UA], profile=profile(), hops=0, interval=0)
    step, = rep.operator_steps()
    assert "https://away.example.org/ (redirect target of http://127.0.0.1:8000/go)" in step
    assert len(fake.calls) == 2                               # the refused target cost no request


def test_the_request_cap_holds_and_names_what_was_left_out(monkeypatch):
    fake = Script(lambda url, ua, n: (200, {}, b"same"))
    monkeypatch.setattr(cr, "get", fake)
    seeds = [f"http://127.0.0.1:8000/{i}" for i in range(3)]
    rep = cr.replay(seeds, [UA], profile=profile(), hops=0, interval=0, max_requests=5)
    assert rep.requests == 4 == len(fake.calls) and rep.capped and rep.not_fetched == [seeds[2]]


def test_the_last_request_the_cap_allows_is_sent(monkeypatch):
    """At exactly max_requests, every allowed request goes out: the cap is inclusive."""
    fake = Script(lambda url, ua, n: (200, {}, b"same"))
    monkeypatch.setattr(cr, "get", fake)
    seeds = [f"http://127.0.0.1:8000/{i}" for i in range(2)]
    rep = cr.replay(seeds, [UA], profile=profile(), hops=0, interval=0, max_requests=4)
    assert rep.requests == 4 == len(fake.calls) and not rep.capped and rep.not_fetched == []
    assert sorted({u for u, _ in fake.calls}) == seeds


def test_links_beyond_the_cap_are_named_not_dropped(monkeypatch):
    page = "".join(f'<a href="/p{i}">x</a>' for i in range(5)).encode()
    fake = Script(lambda url, ua, n: (200, {"content-type": "text/html"}, page if url.endswith("/") else b"leaf"))
    monkeypatch.setattr(cr, "get", fake)
    rep = cr.replay(["http://127.0.0.1:8000/"], [UA], profile=profile(), hops=1, interval=0, max_links=2)
    fetched = sorted({u for u, _ in fake.calls})
    assert fetched == ["http://127.0.0.1:8000/", "http://127.0.0.1:8000/p0", "http://127.0.0.1:8000/p1"]
    assert rep.capped and rep.not_fetched == [f"http://127.0.0.1:8000/p{i}" for i in (2, 3, 4)]


def test_links_of_a_deeper_hop_are_not_followed(monkeypatch):
    def answer(url, ua, n):
        nxt = {"/": "/one", "/one": "/two", "/two": "/three"}.get(url.split("8000")[1])
        return 200, {"content-type": "text/html"}, (f'<a href="{nxt}">n</a>' if nxt else "end").encode()
    fake = Script(answer)
    monkeypatch.setattr(cr, "get", fake)
    cr.replay(["http://127.0.0.1:8000/"], [UA], profile=profile(), hops=2, interval=0)
    assert sorted({u.split("8000")[1] for u, _ in fake.calls}) == ["/", "/one", "/two"]


def test_requests_are_paced_by_the_injected_sleep(monkeypatch):
    monkeypatch.setattr(cr, "get", Script(lambda url, ua, n: (200, {}, b"same")))
    waits = []
    rep = cr.replay(["http://127.0.0.1:8000/a", "http://127.0.0.1:8000/b"], [UA, "Other/2"], profile=profile(),
                    hops=0, interval=0.75, sleep=waits.append)
    assert rep.requests == 6 and waits == [0.75] * 5          # between requests, not before the first


def test_a_failed_request_is_recorded_not_raised(monkeypatch):
    def answer(url, ua, n):
        return ConnectionRefusedError("refused") if ua == UA else (200, {}, b"hello")
    monkeypatch.setattr(cr, "get", Script(answer))
    rep = cr.replay(["http://127.0.0.1:8000/"], [UA], profile=profile(), hops=0, interval=0)
    assert rep.responses[1].error == "ConnectionRefusedError: refused"
    assert rep.diffs[0].what == ["the normal request answered 200, the shipped User-Agent's failed: "
                                 "ConnectionRefusedError: refused"]
    monkeypatch.setattr(cr, "get", Script(lambda url, ua, n: http.client.BadStatusLine("x")))
    rep = cr.replay(["http://127.0.0.1:8000/"], [UA], profile=profile(), hops=0, interval=0)
    assert rep.diffs == [] and all(r.error for r in rep.responses)             # both failed: no difference


@pytest.mark.parametrize("kwargs, needle", [
    ({"user_agents": []}, "no shipped User-Agent"),
    ({"user_agents": ["Evil/1.0\r\nX-Injected: 1"]}, "line break"),
    ({"urls": ["/relative"]}, "not an absolute http"),
    ({"urls": ["ftp://127.0.0.1/x"]}, "not an absolute http"),
    ({"hops": -1}, "hops must be"),
    ({"max_requests": 0}, "max_requests must be"),
    ({"baseline_ua": "a\nb"}, "baseline"),
])
def test_unusable_arguments_are_named(kwargs, needle):
    args = {"urls": ["http://127.0.0.1:8000/"], "user_agents": [UA], "profile": profile(), **kwargs}
    with pytest.raises(cr.ReplayError, match=needle):
        cr.replay(args.pop("urls"), args.pop("user_agents"), **args)


# -------------------------------------------------------------------------------------------- scope

class Recorder:
    """Where the connection would be opened: records the attempt and refuses to go further."""

    def __init__(self):
        self.opened = []

    def __call__(self, scheme, host, port, timeout):
        self.opened.append((scheme, host, port))
        raise ConnectionRefusedError("recorder: no connection in this test")


@pytest.mark.parametrize("url, needle", [
    ("http://outside.example.org/x", "live_service_scope"),
    ("https://board.x-platform.test/api/v1/challenges", "event platform"),
    ("http://8.8.8.8/", "live_service_scope"),
])
def test_get_refuses_before_any_connection(url, needle):
    rec = Recorder()
    with pytest.raises(scope.OutOfScope, match=needle):
        cr.get(url, UA, profile=profile(), connect=rec)
    assert rec.opened == []


def test_get_connects_only_after_the_scope_guard_allows_it():
    rec = Recorder()
    with pytest.raises(ConnectionRefusedError):
        cr.get("http://127.0.0.1:8123/p?q=1", UA, profile=profile(), connect=rec)
    assert rec.opened == [("http", "127.0.0.1", 8123)]
    with pytest.raises(scope.OutOfScope, match="empty rules.live_service_scope"):
        cr.get("http://127.0.0.1:8123/", UA, profile=profile(scope_entries=()), connect=rec)
    assert len(rec.opened) == 1


def test_a_seed_outside_the_scope_is_reported_and_never_fetched():
    rec = Recorder()
    rep = cr.replay(["https://pink.example.org/", "https://board.x-platform.test/"], [UA], profile=profile(),
                    interval=0, connect=rec)
    assert rec.opened == [] and rep.requests == 0 and rep.responses == []
    assert [(r.url, r.via, r.hop) for r in rep.refused] == [("https://pink.example.org/", "seed", 0),
                                                           ("https://board.x-platform.test/", "seed", 0)]
    assert "event platform" in rep.refused[1].reason


def test_get_sends_the_user_agent_and_caps_the_body():
    routes = {"/big": {"body": "A" * 5000, "headers": {"Content-Type": "text/plain"}}}
    with livereplay.WebReplay(routes) as svc:
        status, headers, body, cut = cr.get(svc.base_url + "/big?x=1", UA, profile=profile(), max_bytes=1000)
        (method, path, sent), = svc.requests
    assert (status, len(body), cut) == (200, 1000, True) and headers["content-type"] == "text/plain"
    assert (method, path, sent["user-agent"]) == ("GET", "/big?x=1", UA) and "cookie" not in sent


def test_https_uses_a_verifying_tls_connection():
    conn = cr._connect("https", "127.0.0.1", 8443, 3.0)
    assert isinstance(conn, http.client.HTTPSConnection)
    plain = cr._connect("http", "127.0.0.1", 8080, 3.0)
    assert not isinstance(plain, http.client.HTTPSConnection)


# ---------------------------------------------------------------------------------- links, compare

def test_links_of_resolves_and_filters():
    body = (b'<a href="/a?x=1&amp;y=2">a</a> <A HREF=\'b/c#frag\'>b</A> <form action=/post> <img src=//cdn.test/i.png>'
            b' <a href="javascript:void(0)">j</a> <a href="/a?x=1&amp;y=2">again</a> text https://abs.test/z. end')
    assert cr.links_of(body, "http://127.0.0.1:8000/dir/page") == [
        "http://127.0.0.1:8000/a?x=1&y=2", "http://127.0.0.1:8000/dir/b/c", "http://127.0.0.1:8000/post",
        "http://cdn.test/i.png", "https://abs.test/z"]
    assert cr.links_of(body, "http://127.0.0.1:8000/", "image/png") == []
    assert cr.is_asset("http://x.test/a/logo.PNG?v=2") and not cr.is_asset("http://x.test/a/page.php")


def resp(**kw):
    base = {"url": "http://h.test/", "ua": None, "status": 200, "final_url": "http://h.test/",
            "content_type": "text/html; charset=utf-8", "length": 3, "sha256": "aa", "body": b"abc"}
    return cr.Response(**{**base, **kw})


def test_compare_names_each_difference():
    assert cr.compare(resp(), resp(ua=UA)) == []
    assert cr.compare(resp(), resp(ua=UA, content_type="text/html")) == []      # a charset is not a difference
    assert cr.compare(resp(), resp(ua=UA, status=403, sha256="bb", length=9)) == [
        "status 403 instead of 200", "body differs (9 bytes instead of 3)"]
    assert cr.compare(resp(), resp(ua=UA, final_url="http://h.test/in")) == [
        "ends at http://h.test/in instead of http://h.test/"]
    assert cr.compare(resp(error="timeout", status=None), resp(ua=UA)) == [
        "the normal request failed (timeout), the shipped User-Agent's answered 200"]


# ----------------------------------------------------------------------------- fragments and joins

def test_fragments_come_only_from_lines_the_normal_reply_lacks():
    prof = profile()
    base = b"body {color: red;}\nshared_tail}\n"
    ua = b"body {color: red;}\nshared_tail}\n" + TAIL.encode() + b"\nstart: PINK{W0w,_half\nwhole PINK{a_b}\n"
    assert cr.find_fragments(base, ua, prof) == [("tail", TAIL), ("head", "PINK{W0w,_half")]
    assert cr.find_fragments(ua, ua, prof) == []


def test_join_is_literal_or_nothing():
    prof = profile()
    assert cr.join_fragments(HEAD, TAIL, prof) == "PINK{W0w,_P1nk+_0S_1s_b3tt3r_th4n_W1ND0WS_4nd_L1NUX}"
    assert cr.join_fragments(HEAD, "no closing brace", prof) is None
    assert cr.join_fragments("W0w,_P1nk+", TAIL, prof) is None                 # no prefix: not this event's flag
    assert cr.join_fragments(HEAD, TAIL + " ", prof) is None                   # nothing is trimmed to make it fit
    assert cr.join_fragments("PINK{a}", "b}", prof) is None                    # two flags' worth is not one flag
    assert cr.join_fragments("", TAIL, prof) is None and cr.join_fragments(HEAD, None, prof) is None


# --------------------------------------------------------------------------------------- guess stop

def submit(wd, cid, status, **kw):
    ledger.append("platform.submit", workdir=wd, event_slug="replay-test", challenge_id=cid, status=status,
                  judged=status in ("correct", "incorrect"), **kw)


def test_guess_stop_reads_what_the_gate_enforces(tmp_path):
    prof = profile(wrong_answer_stop=3, guess_budget=1)
    gs = cr.guess_stop(prof, "19", tmp_path)
    assert (gs.wrong, gs.wrong_answer_stop, gs.guesses_used, gs.guess_budget, gs.stopped) == (0, 3, 0, 1, False)
    assert gs.guesses_left == 1 and "1 guess(es) left" in gs.line()
    submit(tmp_path, "19", "incorrect", guess=True)
    submit(tmp_path, "19#part2", "incorrect")
    submit(tmp_path, "20", "incorrect")                       # another challenge does not count
    submit(tmp_path, "19", "rate_limited", guess=True)        # unjudged: counts toward nothing
    gs = cr.guess_stop(prof, "19#part2", tmp_path)
    assert (gs.challenge_id, gs.wrong, gs.guesses_used, gs.stopped, gs.guesses_left) == ("19", 2, 1, False, 0)
    assert "no guess may be sent" in gs.line()
    rules = EventRules(prof, tmp_path)
    guess = SubmitRequest("19", "PINK{x}", "a variant", guess=True)
    assert "guess_budget" in rules.check(prof, guess)         # the gate agrees: it is the one that refuses
    submit(tmp_path, "19", "incorrect")
    gs = cr.guess_stop(prof, "19", tmp_path)
    assert gs.stopped and gs.line().startswith("STOP: ") and "only the player can approve" in gs.line()
    assert "wrong_answer_stop" in rules.check(prof, SubmitRequest("19", "PINK{y}", "derived"))
    final = profile(wrong_answer_stop=3, approved_extras=False)
    assert "the stop is final" in cr.guess_stop(final, "19", tmp_path).line()
    with pytest.raises(cr.ReplayError, match="needs the challenge id"):
        cr.guess_stop(prof, " ", tmp_path)
