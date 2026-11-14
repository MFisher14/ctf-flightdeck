"""B-113: the map-pin checker client (solvers/toolkits/_osint_geo_checker.py) and the checker-to-gate
step (osint_geolocate.check_and_submit).

The checker page is a fake this file starts on 127.0.0.1, or an injected transport; the platform is a
recording adapter behind the real SubmitGate. No test contacts a challenge host or a platform. Flags
and place names here are invented.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ctf import event, ledger, platform, scope
from ctf.platform.base import SubmitResult, SubmitStatus

TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
if str(TOOLKITS) not in sys.path:
    sys.path.insert(0, str(TOOLKITS))

import _osint_geo_checker as CHK  # noqa: E402
import osint_geolocate as GEO  # noqa: E402

PAGE = "http://127.0.0.1:8099/pin/"
OTHER_PAGE = "http://127.0.0.1:8099/other/"
TARGET = (12.3456, 65.4321)          # an invented pin: digits in a row, nowhere in particular
FLAG = "geo{Grün3_pin_dropped}"      # non-ASCII on purpose: it must reach the gate letter for letter

PAGE_HTML = """<!doctype html><html><head>
<link rel="stylesheet" href="https://unpkg.example/leaflet/leaflet.css">
<script src="pannellum.js"></script></head><body>
<div id="pano"></div><div id="map"></div>
<script>
pannellum.viewer('pano', {"type": "equirectangular", "panorama": "pano.jpg"});
var map = L.map('map').setView([48.1, 11.5], 6);
map.on('click', function (e) {
  var body = new URLSearchParams({lat: e.latlng.lat, lng: e.latlng.lng});
  fetch('?check=1', {method: 'POST', body: body}).then(r => r.json()).then(show);
});
</script></body></html>"""


def _profile(live=("127.0.0.1",), submit_mode="auto", prefix="geo", wrong_answer_stop=None):
    rules = {"submit_mode": submit_mode, "flag_sharing": "forbidden", "ai_on_platform": "allowed",
             "live_service_scope": list(live)}
    if wrong_answer_stop is not None:
        rules["wrong_answer_stop"] = wrong_answer_stop
    return event.parse({
        "slug": "geo-check-test", "name": "geo checker test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ctf.example"},
        "flag": {"prefixes": [prefix]},
        "rules": rules,
    }, src="<test>")


class _Transport:
    """An injected transport: records every call and answers from a list of (status, body)."""

    def __init__(self, replies=None, page=PAGE_HTML):
        self.calls = []
        self.replies = list(replies or [])
        self.page = page

    def __call__(self, method, url, body, headers, timeout):
        self.calls.append({"method": method, "url": url, "body": body, "headers": dict(headers)})
        if method == "GET":
            return 200, self.page.encode()
        status, payload = self.replies.pop(0) if self.replies else (200, {"ok": False, "message": "too far"})
        return status, (payload if isinstance(payload, bytes) else json.dumps(payload).encode())

    @property
    def posts(self):
        return [c for c in self.calls if c["method"] == "POST"]


def _checker(tmp_path, transport, page=PAGE, cid="chal-a", **kw):
    kw.setdefault("profile", _profile())
    kw.setdefault("min_interval_s", 0.0)
    return CHK.GeoChecker(page, cid, transport=transport, workdir=tmp_path, **kw)


# --------------------------------------------------------------------------- page detection

def test_detect_reads_endpoint_fields_encoding_and_images():
    found = CHK.detect_checker_page(PAGE_HTML, PAGE)
    assert found["is_map_pin_page"] is True
    assert found["signals"] == ["leaflet", "pannellum"]
    assert found["check_url"] == "http://127.0.0.1:8099/pin/?check=1"
    assert (found["lat_field"], found["lon_field"], found["fields_source"]) == ("lat", "lng", "page")
    assert (found["lat_field_source"], found["lon_field_source"]) == ("page", "page")
    assert (found["encoding"], found["encoding_source"]) == ("form", "page")
    assert found["images"] == ["http://127.0.0.1:8099/pin/pano.jpg"]


# A page that builds its body by hand: the field names are only inside the concatenated string.
CONCAT_PAGE = ("<script src='leaflet.js'></script><script>L.map('map').on('click', function (e) {"
               "var x = new XMLHttpRequest(); x.open('POST', '?check=1');"
               "x.send('latitude=' + e.latlng.lat + '&longitude=' + e.latlng.lng); });</script>")
# A page that shows the endpoint and nothing about what it takes.
BARE_PAGE = ("<script src='leaflet.js'></script><script>L.map('map').on('click', "
             "e => fetch('?check=1', {method: 'POST', body: pack(e.latlng)}))</script>")


def test_detect_reads_field_names_from_a_hand_built_query_string():
    found = CHK.detect_checker_page(CONCAT_PAGE, PAGE)
    assert (found["lat_field"], found["lon_field"], found["fields_source"]) == ("latitude", "longitude", "page")
    assert (found["encoding"], found["encoding_source"]) == ("form", "page")       # a query string is a form body
    templated = CHK.detect_checker_page("<script>L.map('m'); fetch('?check=1', {method: 'POST', "
                                        "body: `lat=${p.lat}&lng=${p.lng}`})</script>", PAGE)
    assert (templated["lat_field"], templated["lon_field"], templated["fields_source"]) == ("lat", "lng", "page")
    posting_form = CHK.detect_checker_page("<script>L.map('m')</script><form method=\"post\" action=\"?check=1\">"
                                           "<input name=\"lat\"><input name=\"lon\"></form>", PAGE)
    assert (posting_form["lat_field"], posting_form["lon_field"]) == ("lat", "lon")
    assert (posting_form["encoding"], posting_form["encoding_source"]) == ("form", "page")


def test_detect_marks_what_it_could_not_read_as_a_guess():
    bare = CHK.detect_checker_page(BARE_PAGE, PAGE)
    assert bare["check_url"] == "http://127.0.0.1:8099/pin/?check=1" and bare["is_map_pin_page"]
    assert (bare["lat_field"], bare["lon_field"], bare["encoding"]) == ("lat", "lon", "form")
    assert (bare["lat_field_source"], bare["lon_field_source"], bare["fields_source"], bare["encoding_source"]) == (
        "default", "default", "default", "default")
    # one name shown, the other not
    half = CHK.detect_checker_page("<script>L.map('m'); fetch('?check=1', {method: 'POST', "
                                   "body: new URLSearchParams({lat: p.lat, x: p.lng})})</script>", PAGE)
    assert (half["lat_field_source"], half["lon_field_source"], half["fields_source"]) == ("page", "default", "default")
    # both a JSON body and a form object on the page: which one the checker takes is not known
    both = CHK.detect_checker_page("<script>L.map('m'); fetch('?check=1', {headers: {'Content-Type': "
                                   "'application/json'}, body: JSON.stringify({lat: 1, lon: 2})}); "
                                   "new FormData(search)</script>", PAGE)
    assert both["encoding_source"] == "default" and both["fields_source"] == "page"


def test_detect_json_checker_and_pages_that_are_not_checkers():
    json_page = ("<script src='maplibre-gl.js'></script><script>fetch(\"/api/guess?check=1\", {method: 'POST', "
                 "headers: {'Content-Type': 'application/json'}, "
                 "body: JSON.stringify({latitude: p.lat, longitude: p.lng})})</script>")
    found = CHK.detect_checker_page(json_page.encode(), PAGE)
    assert found["check_url"] == "http://127.0.0.1:8099/api/guess?check=1"
    assert (found["encoding"], found["lat_field"], found["lon_field"]) == ("json", "latitude", "longitude")
    assert found["signals"] == ["maplibre"] and found["is_map_pin_page"]
    plain = CHK.detect_checker_page("<html><body><p>Where was this taken?</p></body></html>", PAGE)
    assert plain["is_map_pin_page"] is False and plain["check_url"] is None and plain["signals"] == []
    assert (plain["encoding_source"], plain["fields_source"]) == ("default", "default")
    # a map with no checker endpoint is a map, not a checker
    only_map = CHK.detect_checker_page("<script>L.map('m')</script>", PAGE)
    assert only_map["signals"] == ["leaflet"] and only_map["is_map_pin_page"] is False


# --------------------------------------------------------------------------- scope and construction

def test_page_outside_the_live_scope_is_refused_before_any_request(tmp_path):
    transport = _Transport()
    with pytest.raises(scope.OutOfScope, match="live_service_scope"):
        _checker(tmp_path, transport, profile=_profile(live=["*.ctf.example"]))
    with pytest.raises(scope.OutOfScope, match="event platform"):
        CHK.GeoChecker("https://board.ctf.example/pin/", "chal-a", transport=transport, workdir=tmp_path,
                       profile=_profile(live=["*.ctf.example"]))
    with pytest.raises(scope.OutOfScope):
        CHK.GeoChecker.from_page(PAGE, "chal-a", transport=transport, workdir=tmp_path,
                                 profile=_profile(live=["*.ctf.example"]))
    assert transport.calls == []


def test_endpoint_must_be_on_the_pages_origin(tmp_path):
    transport = _Transport()
    for elsewhere in ("http://127.0.0.1:9000/pin/?check=1", "https://127.0.0.1:8099/pin/?check=1",
                      "http://evil.test/pin/?check=1"):
        with pytest.raises(CHK.GeoCheckError, match="not on the page's origin"):
            _checker(tmp_path, transport, check_url=elsewhere)
    cross = _Transport(page="<script>L.map('m'); fetch('http://evil.test/x?check=1')</script>")
    with pytest.raises(CHK.GeoCheckError, match="not on the page's origin"):
        CHK.GeoChecker.from_page(PAGE, "chal-a", transport=cross, workdir=tmp_path, profile=_profile())
    assert cross.posts == [] and transport.calls == []


def test_constructor_validates_its_inputs(tmp_path):
    transport = _Transport()
    with pytest.raises(CHK.GeoCheckError, match="max_checks must be 1..10"):
        _checker(tmp_path, transport, max_checks=11)
    with pytest.raises(CHK.GeoCheckError, match="max_checks must be 1..10"):
        _checker(tmp_path, transport, max_checks=0)
    with pytest.raises(CHK.GeoCheckError, match="encoding must be one of"):
        _checker(tmp_path, transport, encoding="xml")
    with pytest.raises(CHK.GeoCheckError, match="plain form field name"):
        _checker(tmp_path, transport, lat_field="lat&admin=1")
    with pytest.raises(CHK.GeoCheckError, match="http\\(s\\) URL"):
        CHK.GeoChecker("ftp://127.0.0.1/pin/", "chal-a", transport=transport, workdir=tmp_path, profile=_profile())
    with pytest.raises(CHK.GeoCheckError, match="credentials"):
        CHK.GeoChecker("http://u:p@127.0.0.1/pin/", "chal-a", transport=transport, workdir=tmp_path, profile=_profile())
    with pytest.raises(CHK.GeoCheckError, match="challenge id"):
        CHK.GeoChecker(PAGE, "", transport=transport, workdir=tmp_path, profile=_profile())
    default = _checker(tmp_path, transport)
    assert default.check_url == "http://127.0.0.1:8099/pin/?check=1" and default.max_checks == CHK.DEFAULT_MAX_CHECKS == 3


# --------------------------------------------------------------------------- one check

def test_check_posts_form_fields_and_reads_the_flag_from_the_reply(tmp_path):
    transport = _Transport([(200, {"ok": True, "message": f"Correct! {FLAG}"})])
    checker = _checker(tmp_path, transport, lon_field="lng")
    outcome = checker.check(*TARGET)
    (post,) = transport.posts
    assert post["url"] == "http://127.0.0.1:8099/pin/?check=1"
    assert post["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert urllib.parse.parse_qs(post["body"].decode()) == {"lat": ["12.3456"], "lng": ["65.4321"]}
    assert outcome.flags == (FLAG,) and outcome.ok is True and outcome.http_status == 200
    assert outcome.message == f"Correct! {FLAG}"
    assert (outcome.attempts_used, outcome.attempts_left) == (1, 2)
    assert outcome.to_dict()["flags"] == [FLAG] and outcome.to_dict()["check_host"] == "127.0.0.1"


def test_check_json_encoding_and_a_wrong_pin(tmp_path):
    transport = _Transport([(200, {"ok": False, "message": "412 km away\x07"})])
    checker = _checker(tmp_path, transport, encoding="json", lat_field="latitude", lon_field="longitude")
    outcome = checker.check(48.0, 11.0)
    (post,) = transport.posts
    assert post["headers"]["Content-Type"] == "application/json"
    assert json.loads(post["body"]) == {"latitude": 48.0, "longitude": 11.0}
    assert outcome.flags == () and outcome.ok is False
    assert outcome.message == "412 km away"                       # control characters do not survive


def test_reply_shapes(tmp_path):
    transport = _Transport([
        (200, {"result": {"note": [f"nested {FLAG}"]}}),           # no verdict key, flag nested
        (200, f"plain text {FLAG}".encode()),                      # not JSON at all
        (200, {"correct": True, "message": "well done"}),          # a verdict, no flag
        (200, {"ok": True, "message": "geo{first} or geo{second}"}),
    ])
    checker = _checker(tmp_path, transport, max_checks=10, cap_note="test: four reply shapes")
    nested = checker.check(1.0, 1.0)
    assert nested.flags == (FLAG,) and nested.ok is True          # a flag implies the pin was right
    text = checker.check(2.0, 2.0)
    assert text.flags == (FLAG,) and text.ok is True
    no_flag = checker.check(3.0, 3.0)
    assert no_flag.flags == () and no_flag.ok is True
    two = checker.check(4.0, 4.0)
    assert two.flags == ("geo{first}", "geo{second}")


def test_bad_coordinates_and_oversized_reply(tmp_path):
    transport = _Transport([(200, b"x" * (CHK.MAX_REPLY_BYTES + 1))])
    checker = _checker(tmp_path, transport)
    for lat, lon in ((91.0, 0.0), (0.0, 181.0), (float("nan"), 0.0), (True, 0.0)):
        with pytest.raises(CHK.GeoCheckError):
            checker.check(lat, lon)
    assert transport.posts == [] and checker.history() == []      # nothing counted, nothing sent
    with pytest.raises(CHK.GeoCheckError, match="reply is larger"):
        checker.check(1.0, 1.0)
    bad = _checker(tmp_path, lambda *a: "not a tuple")
    with pytest.raises(CHK.GeoCheckError, match="transport must return"):
        bad.check(5.0, 5.0)


# --------------------------------------------------------------------------- cap, repeats, pacing

def test_cap_holds_per_challenge_across_instances(tmp_path):
    transport = _Transport()
    checker = _checker(tmp_path, transport, max_checks=2)
    assert checker.attempts_left() == 2
    assert checker.check(1.0, 1.0).attempts_left == 1
    assert checker.check(2.0, 2.0).attempts_left == 0
    with pytest.raises(CHK.CheckRefused, match="used 2 of 2 checker posts"):
        checker.check(3.0, 3.0)
    assert len(transport.posts) == 2
    # a new process (a new object over the same workdir) is still capped ...
    again = _checker(tmp_path, transport, max_checks=2)
    assert again.attempts_left() == 0
    with pytest.raises(CHK.CheckRefused):
        again.check(4.0, 4.0)
    assert len(transport.posts) == 2
    # ... another challenge on another page is not, and a higher cap allows exactly one more
    other = _checker(tmp_path, transport, page=OTHER_PAGE, cid="chal-b", max_checks=2)
    assert other.check(1.0, 1.0).attempts_used == 1
    raised = _checker(tmp_path, transport, max_checks=3)
    assert raised.check(5.0, 5.0).attempts_left == 0
    with pytest.raises(CHK.CheckRefused):
        raised.check(6.0, 6.0)
    assert len(transport.posts) == 4


def test_cap_counts_one_endpoint_under_any_challenge_id(tmp_path):
    """One page posted to under three spellings of its challenge id is one count, not three."""
    transport = _Transport()
    assert _checker(tmp_path, transport, cid="7", max_checks=1).check(1.0, 1.0).attempts_left == 0
    for alias in ("7-some-title", "seven"):
        again = _checker(tmp_path, transport, cid=alias, max_checks=1)
        assert again.attempts_left() == 0
        with pytest.raises(CHK.CheckRefused, match=r"checker 127\.0\.0\.1:8099/pin\) has used 1 of 1"):
            again.check(2.0, 2.0)
    # the same endpoint spelled another way (no trailing slash, another value for `check`)
    spelled = _checker(tmp_path, transport, page="http://127.0.0.1:8099/pin", cid="eight", max_checks=1,
                       check_url="http://127.0.0.1:8099/pin?check=true")
    assert spelled.attempts_left() == 0
    # the repeat guard follows the endpoint too: a pin already posted there is not re-sent under a new id
    with pytest.raises(CHK.CheckRefused, match="already posted"):
        _checker(tmp_path, transport, cid="nine", max_checks=2).check(1.0, 1.0)
    assert len(transport.posts) == 1
    # the id still counts by itself: challenge 7 moved to another page keeps its one spent post ...
    assert _checker(tmp_path, transport, page=OTHER_PAGE, cid="7", max_checks=1).attempts_left() == 0
    # ... and another id on another page, or on the same path with another query id, starts fresh
    assert _checker(tmp_path, transport, page=OTHER_PAGE, cid="ten", max_checks=1).attempts_left() == 1
    by_query = _checker(tmp_path, transport, cid="eleven", max_checks=1,
                        check_url="http://127.0.0.1:8099/pin/?id=11&check=1")
    assert by_query.attempts_left() == 1


def test_endpoint_key_is_host_port_path_and_the_other_query_parameters():
    assert CHK.endpoint_key("http://127.0.0.1:8099/pin/?check=1") == "127.0.0.1:8099/pin"
    assert CHK.endpoint_key("http://127.0.0.1:8099/pin?check=true") == "127.0.0.1:8099/pin"
    assert CHK.endpoint_key("http://127.0.0.1:8099/?check=1") == "127.0.0.1:8099/"
    assert CHK.endpoint_key("https://Maps.CTF.example/play?id=4&check=1&b=2") == "maps.ctf.example:443/play?b=2&id=4"
    assert CHK.endpoint_key("https://maps.ctf.example/play?id=3&check=1") != CHK.endpoint_key(
        "https://maps.ctf.example/play?id=4&check=1")
    assert CHK.endpoint_key("http://127.0.0.1:8099/pin/?check=1") != CHK.endpoint_key("http://127.0.0.1:8098/pin/?check=1")


def test_a_raised_cap_needs_the_players_note_and_is_written_to_the_ledger(tmp_path):
    transport = _Transport()
    with pytest.raises(CHK.GeoCheckError, match="above this event's default of 3.*cap_note"):
        _checker(tmp_path, transport, max_checks=4)
    with pytest.raises(CHK.GeoCheckError, match="cap_note must be"):
        _checker(tmp_path, transport, max_checks=4, cap_note="   ")
    with pytest.raises(CHK.GeoCheckError, match="cap_note must be"):
        _checker(tmp_path, transport, max_checks=4, cap_note="x" * 301)
    assert list(ledger.read(tmp_path)) == [] and transport.calls == []
    raised = _checker(tmp_path, transport, max_checks=4, cap_note="player:  one more try,\nno penalty here")
    raised.check(1.0, 1.0)
    raised.check(2.0, 2.0)
    records = list(ledger.read(tmp_path))
    assert [r["event"] for r in records] == ["geo.check_cap_raised", "geo.check", "geo.check_result",
                                             "geo.check", "geo.check_result"]          # the raise once, first
    cap = records[0]
    assert (cap["challenge_id"], cap["endpoint"], cap["max_checks"], cap["default_checks"]) == (
        "chal-a", "127.0.0.1:8099/pin", 4, 3)
    assert cap["note"] == "player: one more try, no penalty here"
    assert records[1]["of"] == 4
    # a cap at the default needs no note and writes no such record; a second, higher raise is its own record
    _checker(tmp_path, transport, page=OTHER_PAGE, cid="chal-b").check(1.0, 1.0)
    _checker(tmp_path, transport, max_checks=5, cap_note="player: and one more").check(3.0, 3.0)
    caps = [r for r in ledger.read(tmp_path) if r["event"] == "geo.check_cap_raised"]
    assert [(r["challenge_id"], r["max_checks"]) for r in caps] == [("chal-a", 4), ("chal-a", 5)]


def test_default_cap_is_never_above_the_events_wrong_answer_stop(tmp_path):
    transport = _Transport()
    strict = _profile(wrong_answer_stop=1)
    one = _checker(tmp_path, transport, profile=strict)
    assert (one.max_checks, one.default_checks) == (1, 1)
    one.check(1.0, 1.0)
    with pytest.raises(CHK.CheckRefused, match="used 1 of 1"):
        one.check(2.0, 2.0)
    with pytest.raises(CHK.GeoCheckError, match="default of 1"):
        _checker(tmp_path, transport, profile=strict, max_checks=2)
    assert _checker(tmp_path, transport, profile=strict, max_checks=2, cap_note="player said two").max_checks == 2
    # a lenient event does not lift the default: whether a wrong pin costs anything is still not known
    assert _checker(tmp_path, transport, profile=_profile(wrong_answer_stop=8)).max_checks == 3
    assert len(transport.posts) == 1


def test_a_repeated_coordinate_is_refused_not_resent(tmp_path):
    transport = _Transport()
    checker = _checker(tmp_path, transport)
    checker.check(12.3456, 65.4321)
    with pytest.raises(CHK.CheckRefused, match="already posted"):
        checker.check(12.34560004, 65.43209996)                    # the same pin to six decimals
    assert len(transport.posts) == 1 and checker.attempts_left() == 2


def test_a_failed_post_still_counts(tmp_path):
    def dies(method, url, body, headers, timeout):
        raise OSError("connection reset")

    checker = _checker(tmp_path, dies, max_checks=1)
    with pytest.raises(OSError):
        checker.check(1.0, 1.0)
    assert checker.attempts_left() == 0                             # it may have reached the page


def test_pacing_waits_out_the_interval_between_posts(tmp_path):
    now = [1000.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    transport = _Transport()
    checker = _checker(tmp_path, transport, min_interval_s=5.0, clock=lambda: now[0], sleep=sleep, max_checks=3)
    checker.check(1.0, 1.0)
    assert sleeps == []                                             # nothing to wait for on the first post
    now[0] += 1.5
    checker.check(2.0, 2.0)
    assert sleeps == [pytest.approx(3.5)]
    now[0] += 60.0
    checker.check(3.0, 3.0)
    assert len(sleeps) == 1                                         # the interval had already passed


def test_pacing_is_measured_from_the_latest_post_not_the_first(tmp_path):
    now = [1000.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        now[0] += seconds

    checker = _checker(tmp_path, _Transport(), min_interval_s=5.0, clock=lambda: now[0], sleep=sleep)
    checker.check(1.0, 1.0)                                         # sent at 1000
    now[0] += 60.0
    checker.check(2.0, 2.0)                                         # sent at 1060, long after the first
    now[0] += 1.5
    checker.check(3.0, 3.0)                                         # 1.5 s after the SECOND post
    assert sleeps == [pytest.approx(3.5)]
    assert [r["sent_at"] for r in ledger.read(tmp_path) if r["event"] == "geo.check"] == [1000.0, 1060.0, 1065.0]


def test_ledger_records_attempts_without_the_flag_and_fails_closed(tmp_path):
    transport = _Transport([(200, {"ok": True, "message": FLAG})])
    checker = _checker(tmp_path, transport)
    checker.check(*TARGET)
    records = list(ledger.read(tmp_path))
    assert [r["event"] for r in records] == ["geo.check", "geo.check_result"]
    assert records[0]["challenge_id"] == "chal-a" and records[0]["coordinate"] == "12.345600,65.432100"
    assert records[0]["attempt"] == 1 and records[0]["of"] == 3
    assert records[0]["endpoint"] == "127.0.0.1:8099/pin" and records[0]["host"] == "127.0.0.1"
    assert records[1]["flag_found"] is True and len(records[1]["flag_sha256"]) == 12
    assert FLAG not in ledger.path(tmp_path).read_text(encoding="utf-8")
    assert "pin_dropped" not in ledger.path(tmp_path).read_text(encoding="utf-8")
    # a ledger that cannot be read: the count is unknown, so nothing is sent
    with ledger.path(tmp_path).open("a", encoding="utf-8") as fh:
        fh.write("{corrupt\n")
    with pytest.raises(CHK.GeoCheckError, match="ledger is unreadable"):
        checker.check(1.0, 1.0)
    assert len(transport.posts) == 1


# --------------------------------------------------------------------------- from_page

def test_from_page_reads_the_page_once_and_uses_what_it_says(tmp_path):
    transport = _Transport([(200, {"ok": True, "message": FLAG})])
    checker = CHK.GeoChecker.from_page(PAGE, "chal-a", transport=transport, workdir=tmp_path,
                                       profile=_profile(), min_interval_s=0.0)
    assert [c["method"] for c in transport.calls] == ["GET"] and transport.calls[0]["url"] == PAGE
    assert checker.detection["signals"] == ["leaflet", "pannellum"]
    assert (checker.lat_field, checker.lon_field, checker.encoding) == ("lat", "lng", "form")
    assert checker.attempts_left() == 3                            # reading the page is not a check
    assert checker.check(*TARGET).flags == (FLAG,)
    assert urllib.parse.parse_qs(transport.posts[0]["body"].decode()) == {"lat": ["12.3456"], "lng": ["65.4321"]}
    # explicit field names override the page's
    forced = CHK.GeoChecker.from_page(PAGE, "chal-c", transport=_Transport(), workdir=tmp_path,
                                      profile=_profile(), lon_field="lon", encoding="json")
    assert (forced.lon_field, forced.encoding) == ("lon", "json")


def test_from_page_posts_the_names_of_a_hand_built_query_string(tmp_path):
    transport = _Transport(page=CONCAT_PAGE)
    checker = CHK.GeoChecker.from_page(PAGE, "chal-a", transport=transport, workdir=tmp_path,
                                       profile=_profile(), min_interval_s=0.0)
    checker.check(*TARGET)
    assert transport.posts[0]["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert urllib.parse.parse_qs(transport.posts[0]["body"].decode()) == {"latitude": ["12.3456"],
                                                                          "longitude": ["65.4321"]}


def test_from_page_refuses_to_post_on_guessed_field_names_or_encoding(tmp_path):
    """A page that shows the endpoint but not what it takes: nothing is posted with lat / lon / form
    as a guess, and no attempt is spent; the caller names what is missing."""
    transport = _Transport(page=BARE_PAGE)
    build = lambda **named: CHK.GeoChecker.from_page(PAGE, "chal-a", transport=transport, workdir=tmp_path,  # noqa: E731
                                                     profile=_profile(), min_interval_s=0.0, **named)
    with pytest.raises(CHK.GeoCheckError, match=r"does not show the latitude field name.*the longitude field "
                                                r"name.*the post encoding.*nothing is posted on a guess"):
        build()
    # each of the three is checked by itself: naming two still leaves the third a guess
    with pytest.raises(CHK.GeoCheckError, match=r"does not show the post encoding \(encoding"):
        build(lat_field="y", lon_field="x")
    with pytest.raises(CHK.GeoCheckError, match=r"does not show the latitude field name \(lat_field"):
        build(lon_field="x", encoding="json")
    with pytest.raises(CHK.GeoCheckError, match=r"does not show the longitude field name \(lon_field"):
        build(lat_field="y", encoding="json")
    assert transport.posts == [] and list(ledger.read(tmp_path)) == []
    named = build(lat_field="y", lon_field="x", encoding="json")
    assert named.attempts_left() == 3
    named.check(*TARGET)
    assert json.loads(transport.posts[0]["body"]) == {"y": 12.3456, "x": 65.4321}
    # a page that shows the names but is ambiguous about the encoding is refused for the encoding only
    mixed = _Transport(page="<script>L.map('m'); fetch('?check=1', {headers: {'Content-Type': 'application/json'}, "
                            "body: JSON.stringify({lat: 1, lon: 2})}); new FormData(search)</script>")
    with pytest.raises(CHK.GeoCheckError, match=r"does not show the post encoding"):
        CHK.GeoChecker.from_page(PAGE, "chal-c", transport=mixed, workdir=tmp_path, profile=_profile())
    assert mixed.posts == []


def test_from_page_refuses_a_page_without_a_checker(tmp_path):
    no_endpoint = _Transport(page="<html><script>L.map('m')</script></html>")
    with pytest.raises(CHK.GeoCheckError, match="no checker endpoint"):
        CHK.GeoChecker.from_page(PAGE, "chal-a", transport=no_endpoint, workdir=tmp_path, profile=_profile())

    def gone(method, url, body, headers, timeout):
        return 404, b"not found"

    with pytest.raises(CHK.GeoCheckError, match="HTTP 404"):
        CHK.GeoChecker.from_page(PAGE, "chal-a", transport=gone, workdir=tmp_path, profile=_profile())
    assert no_endpoint.posts == []


# --------------------------------------------------------------------------- the default transport, on loopback

class _FakeCheckerPage:
    """A map-pin challenge page on 127.0.0.1: GET /pin/ is the page, POST /pin/?check=1 judges the pin."""

    def __init__(self, redirect_posts=False):
        fake = self
        self.posts = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, status, body, ctype="application/json", extra=()):
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", ctype + "; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                for name, value in extra:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/pin/":
                    self._reply(200, PAGE_HTML, "text/html")
                else:
                    self._reply(404, "{}")

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
                fake.posts.append({"path": self.path, "type": self.headers.get("Content-Type"), "body": raw,
                                   "agent": self.headers.get("User-Agent")})
                if redirect_posts:
                    self._reply(302, "{}", extra=[("Location", "/elsewhere")])
                    return
                if self.path != "/pin/?check=1":
                    self._reply(404, "{}")
                    return
                form = urllib.parse.parse_qs(raw)
                lat, lon = float(form["lat"][0]), float(form["lng"][0])
                near = abs(lat - TARGET[0]) < 0.001 and abs(lon - TARGET[1]) < 0.001
                self._reply(200, json.dumps({"ok": near, "message": FLAG if near else "too far"}, ensure_ascii=False))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/pin/"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake_page():
    fake = _FakeCheckerPage()
    yield fake
    fake.close()


def test_default_transport_checks_a_pin_against_a_loopback_page(fake_page, tmp_path):
    checker = CHK.GeoChecker.from_page(fake_page.url, "chal-a", workdir=tmp_path, profile=_profile(),
                                       min_interval_s=0.0)
    wrong = checker.check(48.0, 11.0)
    assert wrong.ok is False and wrong.flags == () and wrong.message == "too far"
    right = checker.check(*TARGET)
    assert right.ok is True and right.flags == (FLAG,) and right.attempts_left == 1
    assert [p["path"] for p in fake_page.posts] == ["/pin/?check=1", "/pin/?check=1"]
    assert fake_page.posts[1]["type"] == "application/x-www-form-urlencoded"
    assert urllib.parse.parse_qs(fake_page.posts[1]["body"]) == {"lat": ["12.3456"], "lng": ["65.4321"]}
    assert fake_page.posts[1]["agent"] == CHK.USER_AGENT


def test_default_transport_does_not_follow_a_redirect(tmp_path):
    fake = _FakeCheckerPage(redirect_posts=True)
    try:
        checker = CHK.GeoChecker.from_page(fake.url, "chal-a", workdir=tmp_path, profile=_profile(),
                                           min_interval_s=0.0)
        outcome = checker.check(*TARGET)
        assert outcome.http_status == 302 and outcome.flags == () and outcome.ok is None
        assert [p["path"] for p in fake.posts] == ["/pin/?check=1"]      # one request, not two
    finally:
        fake.close()


# --------------------------------------------------------------------------- checker -> submit gate

class _RecordingAdapter:
    kind = "ctfd"

    def __init__(self):
        self.sent = []

    def submit(self, challenge_id, flag):
        self.sent.append((challenge_id, flag))
        return SubmitResult(SubmitStatus.CORRECT, "ok")


def _gate(submit_mode="auto"):
    raw = _RecordingAdapter()
    return platform.SubmitGate(raw, _profile(submit_mode=submit_mode)), raw


def test_check_and_submit_sends_the_returned_flag_through_the_gate(tmp_path):
    transport = _Transport([(200, {"ok": True, "message": f"Correct! {FLAG}"})])
    gate, raw = _gate()
    both = GEO.check_and_submit(_checker(tmp_path, transport), *TARGET, provenance="model named the venue",
                                gate=gate)
    assert both["check"].flags == (FLAG,)
    assert both["submit"].accepted and both["submit_skipped"] is None
    assert raw.sent == [("chal-a", FLAG)]                         # as the page spelled it, to this challenge


def test_check_and_submit_keeps_confirm_mode_and_skips_when_there_is_no_single_flag(tmp_path):
    held_gate, held_raw = _gate("confirm")
    transport = _Transport([(200, {"ok": True, "message": FLAG}),
                            (200, {"ok": False, "message": "too far"}),
                            (200, {"ok": True, "message": "geo{first} geo{second}"})])
    checker = _checker(tmp_path, transport)
    held = GEO.check_and_submit(checker, 1.0, 1.0, provenance="p", gate=held_gate)
    assert held["submit"].status is SubmitStatus.NOT_ALLOWED and not held["submit"].sent
    assert held_raw.sent == []
    gate, raw = _gate()
    wrong = GEO.check_and_submit(checker, 2.0, 2.0, provenance="p", gate=gate)
    assert wrong["submit"] is None and "no flag" in wrong["submit_skipped"]
    two = GEO.check_and_submit(checker, 3.0, 3.0, provenance="p", gate=gate)
    assert two["submit"] is None and "2 flag-shaped values" in two["submit_skipped"]
    assert raw.sent == []


def test_check_and_submit_sends_the_flag_as_a_flag_never_as_a_nonstandard_answer(tmp_path):
    """The checker's flag goes to the gate under the gate's own format rule. A gate whose event has
    another flag format refuses it; marked non-standard, it would have been sent."""
    raw = _RecordingAdapter()
    other_event = platform.SubmitGate(raw, _profile(prefix="other"))
    transport = _Transport([(200, {"ok": True, "message": FLAG})])
    both = GEO.check_and_submit(_checker(tmp_path, transport), *TARGET, provenance="p", gate=other_event)
    assert both["check"].flags == (FLAG,)
    assert both["submit"].status is SubmitStatus.NOT_ALLOWED and not both["submit"].sent
    assert "flag format" in both["submit"].message
    assert raw.sent == []


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
