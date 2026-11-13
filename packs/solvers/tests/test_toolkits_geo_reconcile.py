"""B-111: geo-sensor reconciliation + report-POST harness (solvers/toolkits/geo_reconcile.py,
ctf/cli/geo_reconcile.py).

Every networked test runs against a fake judge the test starts on 127.0.0.1, under the suite's loopback
scope pin (tests/conftest.py). The evidence is synthetic: `_Scenario` builds six vessels on straight
courses, an AIS log in UTC, a radar log on a clock 60 minutes ahead with shuffled anonymous track ids,
one AIS broadcast displaced by a constant (+360, +300) m for four samples, and a reference point the
displaced vessel really passes 40 m from, between two samples. No challenge file is used.

Time in the POST tests is an injected step clock (`_Clock`): pacing is asserted on the waits the code
asked for, never on wall-clock time (rule 16).
"""
import datetime as _dt
import http.server
import itertools
import json
import math
import random
import threading

import pytest

import geo_reconcile as g
import ics_mirror
from ctf import event as _event
from ctf import instsched as _sched
from ctf import scope as _scope
from ctf.platform.base import InstanceInfo

R = 6_371_000.0
LAT0, LON0 = 44.5, 29.25
T0 = _dt.datetime(2026, 3, 4, 11, 20, tzinfo=_dt.timezone.utc).timestamp()
STEP, SAMPLES = 120, 16
T_CPA = T0 + 11 * 60 + 38          # 11:31:38Z, between the 11:30 and 11:32 samples
SPOOF = 3
FLAG = "flag{geo_sensor_reconciled_7f3a}"


def _iso(t, suffix="Z"):
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + suffix


def _latlon(east, north, radius=R):
    return (round(LAT0 + math.degrees(north / radius), 9),
            round(LON0 + math.degrees(east / (radius * math.cos(math.radians(LAT0)))), 9))


class _Scenario:
    """Truth, the two sensor logs built from it, and the report a correct solver would send."""

    def __init__(self, *, radar_offset_s=3600, radar_header=True, note_offset=True):
        vx, vy = 3.0, -2.0
        perp = (40.0 * 2 / math.sqrt(13), 40.0 * 3 / math.sqrt(13))     # 40 m off the point, _|_ to the course
        self.mmsi = [271000100 + k for k in range(6)]
        self.track_of = {0: "R-04", 1: "R-11", 2: "R-02", 3: "R-10", 4: "R-07", 5: "R-01"}
        starts = [(-2500, 1800), (3000, 2600), (-3200, -2900), None, (2400, -3300), (600, 4100)]
        vels = [(1.5, 0.4), (-2.2, 0.9), (0.7, 2.4), (vx, vy), (-0.9, -1.8), (2.6, -0.3)]
        self.times = [T0 + i * STEP for i in range(SAMPLES)]

        def truth(k, t):
            if k == SPOOF:
                return perp[0] + vx * (t - T_CPA), perp[1] + vy * (t - T_CPA)
            return starts[k][0] + vels[k][0] * (t - T0), starts[k][1] + vels[k][1] * (t - T0)

        self.truth = truth
        self.spoof_window = (T0 + 14 * 60, T0 + 20 * 60)                 # 11:34 .. 11:40, four samples
        ais = []
        for k in range(6):
            for t in self.times:
                e, n = truth(k, t)
                if k == SPOOF and self.spoof_window[0] <= t <= self.spoof_window[1]:
                    e, n = e + 360.0, n + 300.0
                lat, lon = _latlon(e, n)
                ais.append({"mmsi": self.mmsi[k], "utc": _iso(t), "lat": lat, "lon": lon,
                            "name": f"VESSEL-{k}"})
        self.ais = "\n".join(json.dumps(r) for r in ais) + "\n"
        rows = []
        for k in sorted(range(6), key=lambda k: self.track_of[k]):
            for t in self.times:
                lat, lon = _latlon(*truth(k, t))
                rows.append(f"{self.track_of[k]},{_iso(t + radar_offset_s, '')},{lat},{lon}")
        header = ["# coastal radar plot extract"]
        if radar_header:
            header.append(f"# local_time = UTC+{radar_offset_s // 60} min")
        self.radar = "\n".join(header + ["track,local_time,lat,lon"] + rows) + "\n"
        self.reference = (f"Cable fault notice\nfault point: {LAT0:.6f}, {LON0:.6f}\n"
                          "fault window 11:28Z - 11:42Z\n")
        self.note = ("Method: " + ("radar local_time = UTC+60 min; " if note_offset else "")
                     + "project to a local plane, east = R cos(lat0) dlon, north = R dlat, R = 6371000 m; "
                     "associate tracks by median residual.\n")
        self.schema = {
            "$schema": "http://json-schema.org/draft-07/schema#", "type": "object",
            "additionalProperties": False, "required": ["associations", "divergence", "closest_approach"],
            "properties": {
                "associations": {"type": "array", "minItems": 1, "items": {
                    "type": "object", "additionalProperties": False, "required": ["radar_track", "mmsi"],
                    "properties": {"radar_track": {"type": "string"}, "mmsi": {"type": "integer"}}}},
                "divergence": {"type": "object", "additionalProperties": False,
                               "required": ["mmsi", "start_utc", "end_utc", "ais_minus_radar_east_m",
                                            "ais_minus_radar_north_m"],
                               "properties": {"mmsi": {"type": "integer"},
                                              "start_utc": {"type": "string", "format": "date-time"},
                                              "end_utc": {"type": "string", "format": "date-time"},
                                              "ais_minus_radar_east_m": {"type": "number"},
                                              "ais_minus_radar_north_m": {"type": "number"}}},
                "closest_approach": {"type": "object", "additionalProperties": False,
                                     "required": ["mmsi", "utc", "distance_m"],
                                     "properties": {"mmsi": {"type": "integer"},
                                                    "utc": {"type": "string", "format": "date-time"},
                                                    "distance_m": {"type": "number", "minimum": 0}}}}}
        self.expected = {
            "associations": [{"radar_track": self.track_of[k], "mmsi": self.mmsi[k]}
                             for k in sorted(range(6), key=lambda k: self.track_of[k])],
            "divergence": {"mmsi": self.mmsi[SPOOF], "start_utc": _iso(self.spoof_window[0]),
                           "end_utc": _iso(self.spoof_window[1]),
                           "ais_minus_radar_east_m": 360.0, "ais_minus_radar_north_m": 300.0},
            "closest_approach": {"mmsi": self.mmsi[SPOOF], "utc": _iso(T_CPA), "distance_m": 40.0}}

    def evidence(self):
        return {"schema": json.dumps(self.schema).encode(), "ais": self.ais.encode(),
                "radar": self.radar.encode(), "reference": self.reference.encode(),
                "note": self.note.encode()}

    def judge(self, report):
        """The fake judge's verdict: "invalid" (not the report shape), "incorrect", or "correct"."""
        if g.validate_report(self.schema, report)[0]:
            return "invalid"
        exp = self.expected
        pairs = lambda rows: sorted((r["radar_track"], r["mmsi"]) for r in rows)  # noqa: E731
        same = (pairs(report["associations"]) == pairs(exp["associations"])
                and report["divergence"]["mmsi"] == exp["divergence"]["mmsi"]
                and report["divergence"]["start_utc"] == exp["divergence"]["start_utc"]
                and report["divergence"]["end_utc"] == exp["divergence"]["end_utc"]
                and abs(report["divergence"]["ais_minus_radar_east_m"] - 360.0) <= 0.05
                and abs(report["divergence"]["ais_minus_radar_north_m"] - 300.0) <= 0.05
                and report["closest_approach"]["mmsi"] == exp["closest_approach"]["mmsi"]
                and report["closest_approach"]["utc"] == exp["closest_approach"]["utc"]
                and abs(report["closest_approach"]["distance_m"] - 40.0) <= 0.05)
        return "correct" if same else "incorrect"


class _Judge:
    """A loopback instance: GET /schema and /files/*, POST /reconcile judged by `_Scenario.judge`.
    `ratelimit` = how many POSTs to answer 429 (with `retry_after`) before judging."""

    def __init__(self, scenario, *, ratelimit=0, retry_after=7, missing=(), drop=False):
        self.scenario, self.gets, self.posts = scenario, [], []
        self.ratelimit, self.retry_after, self.drop = ratelimit, retry_after, drop
        ev = scenario.evidence()
        routes = {"/schema": ev["schema"], "/files/ais.ndjson": ev["ais"], "/files/radar.csv": ev["radar"],
                  "/files/cable-fault.txt": ev["reference"], "/files/method-note.txt": ev["note"]}
        for path in missing:
            routes.pop(path)
        judge = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body, headers=()):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                for k, v in headers:
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                judge.gets.append(self.path)
                body = routes.get(self.path)
                self._send(200, body) if body is not None else self._send(404, b"{}")

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                judge.posts.append((self.path, self.headers.get("Content-Type"), raw))
                if judge.drop:                                    # read the report, then hang up unanswered
                    self.close_connection = True
                    return
                if self.path != "/reconcile":
                    return self._send(404, b"{}")
                if judge.ratelimit > 0:
                    judge.ratelimit -= 1
                    return self._send(429, b'{"error":"slow down"}', [("Retry-After", str(judge.retry_after))])
                try:
                    verdict = judge.scenario.judge(json.loads(raw))
                except (ValueError, TypeError, KeyError):
                    verdict = "invalid"
                if verdict == "invalid":
                    return self._send(400, b'{"error":"invalid report"}')
                if verdict == "incorrect":
                    return self._send(422, b'{"error":"report does not reconcile"}')
                self._send(200, json.dumps({"status": "incident export verified", "code": FLAG}).encode())

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class _Clock:
    """A step clock: `sleep` advances it and records the wait; nothing really sleeps."""

    def __init__(self, now=1_000_000.0):
        self.now, self.slept = now, []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def _profile(web_state_changing):
    return _event.parse({
        "slug": "geo-test", "name": "geo reconcile test",
        "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.geo.test"},
        "flag": {"prefixes": ["flag"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "web_state_changing": web_state_changing,
                  "live_service_scope": ["127.0.0.0/8", "*.test"]},
    }, src="tests/test_toolkits_geo_reconcile.py")


@pytest.fixture
def scenario():
    return _Scenario()


@pytest.fixture
def judge(scenario):
    srv = _Judge(scenario)
    yield srv
    srv.stop()


def _track(ident, points):
    return g.Track(ident, [p[0] for p in points], [p[1] for p in points], [p[2] for p in points])


# --------------------------------------------------------------------------- time

def test_parse_time_forms():
    assert g.parse_time("2026-03-04T11:20:00Z") == (T0, True)
    assert g.parse_time("2026-03-04 12:20:00+01:00") == (T0, True)
    assert g.parse_time("2026-03-04T11:20:00") == (T0, False)          # the sensor's own clock
    assert g.parse_time(T0) == (T0, True)
    assert g.parse_time(str(int(T0 * 1000))) == (T0, True)             # epoch milliseconds
    assert g.parse_time("11:20:30", date=_dt.date(2026, 3, 4)) == (T0 + 30, False)


def test_parse_time_time_only_needs_a_date_and_garbage_is_named():
    with pytest.raises(g.EvidenceError, match="needs a date"):
        g.parse_time("11:20:30")
    with pytest.raises(g.EvidenceError, match="not a timestamp"):
        g.parse_time("yesterday")
    with pytest.raises(g.EvidenceError):
        g.parse_time(None)


def test_format_time_rounds_to_the_nearest_second_and_formats():
    assert g.format_time(T_CPA + 0.6) == _iso(T_CPA + 1)
    assert g.format_time(T_CPA + 0.4) == _iso(T_CPA)
    assert g.format_time(T_CPA, "iso_offset") == _iso(T_CPA, "+00:00")
    assert g.format_time(T_CPA + 0.25, "iso_z", 2) == _iso(T_CPA, ".25Z")
    assert g.format_time(T_CPA + 0.6, "epoch") == int(T_CPA) + 1
    assert g.format_time(T_CPA, "%H:%M:%SZ") == "11:31:38Z"
    with pytest.raises(g.MethodError):
        g.format_time(T_CPA, "rfc-nonsense")


def test_clock_offset_hints():
    assert [h[0] for h in g.clock_offset_hints("local_time = UTC+60 min")] == [3600]
    assert [h[0] for h in g.clock_offset_hints("stamps are UTC-2h")] == [-7200]
    assert [h[0] for h in g.clock_offset_hints("zone UTC+01:30")] == [5400]
    assert [h[0] for h in g.clock_offset_hints("UTC+3 everywhere")] == [10800]
    assert [h[0] for h in g.clock_offset_hints("UTC+90")] == [5400]     # a bare number above 14 is minutes
    assert g.clock_offset_hints("all times are UTC") == []


# --------------------------------------------------------------------------- projection

def test_local_plane_is_the_method_note_form():
    plane = g.Plane(60.0, 10.0, "local_plane", 6_371_000.0)
    east, north = plane.project(60.001, 10.002)
    assert east == pytest.approx(6_371_000.0 * math.cos(math.radians(60.0)) * math.radians(0.002), abs=1e-6)
    assert north == pytest.approx(6_371_000.0 * math.radians(0.001), abs=1e-6)
    assert plane.project(60.0, 10.0) == (0.0, 0.0)


def test_local_plane_agrees_with_great_circle_distance():
    import osint_geo_math
    plane = g.Plane(LAT0, LON0, "local_plane", osint_geo_math.EARTH_RADIUS_M)
    east, north = plane.project(LAT0 + 0.004, LON0 - 0.006)
    great_circle = osint_geo_math.distance_bearing(LAT0, LON0, LAT0 + 0.004, LON0 - 0.006)
    assert math.hypot(east, north) == pytest.approx(great_circle["distance_m"], rel=2e-4)
    assert math.degrees(math.atan2(east, north)) % 360 == pytest.approx(great_circle["initial_bearing_deg"], abs=0.05)


def test_wgs84_enu_differs_from_the_sphere_by_the_known_amounts():
    # WGS-84 at the equator: 0.001 deg of latitude is 110.574 m of meridian, 0.001 deg of longitude
    # 111.319 m. The mean sphere gives 111.195 m for both, so the two models are told apart.
    enu = g.Plane(0.0, 0.0, "wgs84_enu")
    assert enu.project(0.001, 0.0)[1] == pytest.approx(110.574, abs=0.002)
    assert enu.project(0.0, 0.001)[0] == pytest.approx(111.319, abs=0.002)
    sphere = g.Plane(0.0, 0.0, "local_plane")
    assert sphere.project(0.001, 0.0)[1] == pytest.approx(111.195, abs=0.002)
    with pytest.raises(g.MethodError):
        g.Plane(0.0, 0.0, "mercator").project(0.0, 0.0)
    with pytest.raises(g.EvidenceError):
        enu.project(91.0, 0.0)


def test_polar_to_en_is_clockwise_from_north():
    assert g.polar_to_en(100.0, 90.0) == pytest.approx((100.0, 0.0), abs=1e-9)
    assert g.polar_to_en(100.0, 180.0) == pytest.approx((0.0, -100.0), abs=1e-9)


# --------------------------------------------------------------------------- evidence parsing

def test_parse_ndjson_names_the_bad_line():
    assert g.parse_ndjson(b'{"a": 1}\n\n{"a": 2}\n') == [{"a": 1}, {"a": 2}]
    assert g.parse_ndjson('[{"a": 1}]') == [{"a": 1}]
    with pytest.raises(g.EvidenceError, match="line 2"):
        g.parse_ndjson('{"a": 1}\nnot json\n')
    with pytest.raises(g.EvidenceError):
        g.parse_ndjson("[1, 2]")


def test_parse_csv_keeps_comments_and_sniffs_the_delimiter():
    comments, rows = g.parse_csv("# local_time = UTC+60 min\ntrack;lat;lon\nR-1; 1.5;2.5\n")
    assert comments == ["local_time = UTC+60 min"]
    assert rows == [{"track": "R-1", "lat": "1.5", "lon": "2.5"}]
    with pytest.raises(g.EvidenceError):
        g.parse_csv("# only a comment\ntrack,lat\n")


def test_reference_hints_reads_point_window_and_radius():
    hints = g.reference_hints("fault point: 44.500000, 29.250000\nwindow 11:28Z - 11:42Z; R = 6371000 m")
    assert hints["points"] == [(44.5, 29.25)]
    assert hints["windows"] == [("11:28Z", "11:42Z")]
    assert hints["radii"] == [6371000.0]
    assert g.reference_hints("use 6378.137 km")["radii"] == [6378137.0]
    assert g.reference_hints("nothing here") == {"points": [], "windows": [], "radii": []}


# --------------------------------------------------------------------------- pairing and assignment

def test_residuals_exact_and_interpolated():
    ais = _track("a", [(0, 10.0, 0.0), (60, 20.0, 0.0), (120, 30.0, 5.0)])
    radar = _track("r", [(0, 0.0, 0.0), (120, 20.0, 0.0)])
    assert g.residuals(ais, radar, pairing="exact") == [(0, 10.0, 0.0), (120, 10.0, 5.0)]
    # the radar has no sample at t=60: only interpolation reads it there (10 m east at mid-segment)
    assert g.residuals(ais, radar, pairing="interpolate") == [(0, 10.0, 0.0), (60, 10.0, 0.0), (120, 10.0, 5.0)]
    assert g.residuals(ais, radar, pairing="interpolate", max_gap_s=100) == [(0, 10.0, 0.0), (120, 10.0, 5.0)]
    late = _track("r", [(0.8, 0.0, 0.0), (130, 20.0, 0.0)])
    assert [t for t, _, _ in g.residuals(ais, late, pairing="exact", tolerance_s=1.0)] == [0]
    with pytest.raises(g.MethodError):
        g.residuals(ais, radar, pairing="closest")


def test_assign_optimal_matches_brute_force():
    rng = random.Random(111)
    for n, m in ((1, 1), (4, 4), (5, 5), (3, 5), (5, 3)):
        for _ in range(12):
            cost = [[rng.uniform(0, 100) for _ in range(m)] for _ in range(n)]
            pairs = g.assign_optimal(cost)
            assert len(pairs) == min(n, m)
            assert len({r for r, _ in pairs}) == len(pairs) == len({c for _, c in pairs})
            total = sum(cost[r][c] for r, c in pairs)
            if n <= m:
                best = min(sum(cost[i][p[i]] for i in range(n)) for p in itertools.permutations(range(m), n))
            else:
                best = min(sum(cost[p[j]][j] for j in range(m)) for p in itertools.permutations(range(n), m))
            assert total == pytest.approx(best, abs=1e-9)


def test_assign_optimal_beats_row_greedy_and_skips_unassignable():
    # greedy by row takes (0,0)=1 and is left with (1,1)=100; the optimum is (0,1)+(1,0)=4
    assert g.assign_optimal([[1.0, 2.0], [2.0, 100.0]]) == [(0, 1), (1, 0)]
    assert g.assign_optimal([[1.0, math.inf], [math.inf, math.inf]]) == [(0, 0)]
    assert g.assign_optimal([]) == []


def test_statistic_and_natural_id_order():
    values = [1.0, 2.0, 9.0]
    assert g._statistic(values, "median") == 2.0
    assert g._statistic(values, "mean") == pytest.approx(4.0)
    assert g._statistic(values, "rms") == pytest.approx(math.sqrt(86 / 3))
    assert g._statistic(values, "max") == 9.0
    with pytest.raises(g.MethodError):
        g._statistic(values, "mode")
    assert sorted(["R-10", "R-2", "R-1", 7], key=g._id_key) == [7, "R-1", "R-2", "R-10"]


def test_load_method_merges_and_rejects():
    method = g.load_method({"routes": {"ais": "/v2/ais.json", "extra": "/x"}, "match": {"tolerance_s": 5}})
    assert method["routes"]["ais"] == "/v2/ais.json" and method["routes"]["schema"] == "/schema"
    assert method["routes"]["extra"] == "/x"
    assert method["match"]["tolerance_s"] == 5 and method["match"]["statistic"] == "median"
    assert g.default_method()["routes"]["ais"] == "/files/ais.ndjson"     # the default is not mutated
    with pytest.raises(g.MethodError, match="unknown method key 'match.tolerance'"):
        g.load_method({"match": {"tolerance": 5}})
    with pytest.raises(g.MethodError):
        g.load_method(["not", "an", "object"])


def test_assign_mutual_nearest_leaves_contested_tracks_out():
    cost = [[1.0, 50.0, 60.0], [2.0, 55.0, 65.0], [70.0, 80.0, 3.0]]
    assert g.assign_mutual_nearest(cost) == [(0, 0), (2, 2)]             # row 1 also wants column 0
    assert g.assign_optimal(cost) == [(0, 1), (1, 0), (2, 2)]            # 50 + 2 + 3 beats 1 + 55 + 3


# --------------------------------------------------------------------------- divergence, closest approach

def test_divergence_windows_bounds_offset_and_threshold():
    res = [(0, 0.2, 0.1), (120, 360.0, 300.0), (240, 360.0, 300.0), (360, 361.0, 299.0), (480, 0.0, 0.3),
           (600, 90.0, 0.0)]
    [window] = g.divergence_windows(res, threshold_m=50.0, min_samples=2)
    assert (window["start_utc"], window["end_utc"], window["samples"]) == (120, 360, 3)
    assert window["east_m"] == pytest.approx(360.3333, abs=1e-3)
    assert window["north_m"] == pytest.approx(299.6667, abs=1e-3)
    assert window["magnitude_m"] == pytest.approx(math.hypot(360.3333, 299.6667), abs=1e-2)
    assert window["constant"] is True and window["duration_s"] == 240
    # the lone 90 m sample is a window only when one sample is enough
    assert len(g.divergence_windows(res, threshold_m=50.0, min_samples=1)) == 2
    assert g.divergence_windows(res, threshold_m=500.0) == []
    drifting = [(0, 100.0, 0.0), (120, 200.0, 0.0), (240, 300.0, 0.0)]
    assert g.divergence_windows(drifting, threshold_m=50.0)[0]["constant"] is False
    # a sample exactly on the threshold (3-4-5) is not past it
    edge = [(0, 3.0, 4.0), (120, 30.0, 40.0), (240, 30.0, 40.0), (360, 3.0, 4.0)]
    [window] = g.divergence_windows(edge, threshold_m=5.0)
    assert (window["start_utc"], window["end_utc"], window["samples"]) == (120, 240, 2)


def test_closest_approach_track_stops_short_or_window_ends_while_approaching():
    # eastbound at 10 m/s, 10 m north of the origin's line, and still 100 m short at its last sample:
    # the closest approach is that last sample, not the unreached (0, 10) point 10 m away
    track = _track("r", [(0, -200.0, 10.0), (10, -100.0, 10.0)])
    end = g.closest_approach(track, (0.0, 0.0))
    assert end["utc"] == pytest.approx(10.0)
    assert end["distance_m"] == pytest.approx(math.hypot(100.0, 10.0))            # 100.5 m
    assert (end["east_m"], end["north_m"]) == pytest.approx((-100.0, 10.0))
    # the window closes at t=5 while the track is still approaching: the window end is the answer
    cut = g.closest_approach(track, (0.0, 0.0), window=(0.0, 5.0))
    assert cut["utc"] == pytest.approx(5.0)
    assert cut["distance_m"] == pytest.approx(math.hypot(150.0, 10.0))            # 150.3 m


def test_closest_approach_to_a_point_interpolates_between_samples():
    # the track passes 30 m north of the origin, 40 s into a 100 s segment
    track = _track("r", [(0, -200.0, 30.0), (100, 300.0, 30.0), (200, 800.0, 30.0)])
    found = g.closest_approach(track, (0.0, 0.0))
    assert found["utc"] == pytest.approx(40.0) and found["distance_m"] == pytest.approx(30.0)
    assert (found["east_m"], found["north_m"]) == pytest.approx((0.0, 30.0))
    samples_only = g.closest_approach(track, (0.0, 0.0), interpolate=False)
    assert samples_only["utc"] == 0 and samples_only["distance_m"] == pytest.approx(math.hypot(200, 30))


def test_closest_approach_window_clips_the_search():
    track = _track("r", [(0, -200.0, 30.0), (100, 300.0, 30.0), (200, 800.0, 30.0)])
    clipped = g.closest_approach(track, (0.0, 0.0), window=(60.0, 150.0))
    assert clipped["utc"] == pytest.approx(60.0)                          # already past the point: the window start
    assert clipped["distance_m"] == pytest.approx(math.hypot(100.0, 30.0))
    assert g.closest_approach(track, (0.0, 0.0), window=(300.0, 400.0)) is None
    assert g.closest_approach(track, (0.0, 0.0), window=(300.0, 400.0), interpolate=False) is None


def test_closest_approach_between_two_tracks():
    # a heads east along y=0 at 1 m/s, b heads north along x=100 at 2 m/s: a-b = (t-100, 100-2t),
    # smallest at t=60 (inside b's second segment), where it is (-40, -20)
    a = _track("a", [(0, 0.0, 0.0), (100, 100.0, 0.0)])
    b = _track("b", [(0, 100.0, -100.0), (50, 100.0, 0.0), (100, 100.0, 100.0)])
    found = g.closest_approach(a, b)
    assert found["utc"] == pytest.approx(60.0)
    assert found["distance_m"] == pytest.approx(math.hypot(40.0, 20.0))
    assert (found["east_m"], found["north_m"]) == pytest.approx((60.0, 0.0))
    sampled = g.closest_approach(a, b, interpolate=False)                # a's own samples only: t=0 or t=100
    assert sampled["utc"] == 100 and sampled["distance_m"] == pytest.approx(100.0)
    apart = _track("c", [(500, 0.0, 0.0), (600, 1.0, 0.0)])
    assert g.closest_approach(a, apart) is None                          # no common time


def test_estimate_clock_offset_recovers_the_skew_and_refuses_an_ambiguous_one():
    moving_a = _track("a", [(i * 120.0, 5.0 * i * 120, 0.0) for i in range(12)])
    moving_b = _track("b", [(i * 120.0, 4000.0, -3.0 * i * 120) for i in range(12)])
    radar = [moving_b.shifted(1800), moving_a.shifted(1800)]
    offset, score = g.estimate_clock_offset([moving_a, moving_b], radar)
    assert offset == 1800 and score == pytest.approx(0.0, abs=1e-6)
    still = _track("s", [(i * 900.0, 10.0, 10.0) for i in range(12)])
    with pytest.raises(g.MethodError, match="ambiguous"):
        g.estimate_clock_offset([still], [still.shifted(900)])
    with pytest.raises(g.MethodError, match="no candidate"):
        g.estimate_clock_offset([moving_a], [moving_a.shifted(37)])       # off the quarter-hour grid


def test_estimate_clock_offset_refuses_a_runner_up_within_twice_the_best():
    ais = _track("a", [(i * 900.0, 10.0 * i, 0.0) for i in range(12)])
    radar = [_track("r", [(i * 900.0, 10.0 * i + 10.0, 0.0) for i in range(12)])]
    # offset 0 leaves 10 m and offset 900 leaves 20 m: within twice the best, so not a call to make
    with pytest.raises(g.MethodError, match=r"ambiguous .* score 10\.0 m and 20\.0 m"):
        g.estimate_clock_offset([ais], radar, candidates=[0.0, 900.0])
    # offset 1800 leaves 30 m, more than twice the best: offset 0 stands
    assert g.estimate_clock_offset([ais], radar, candidates=[0.0, 1800.0]) == (0.0, pytest.approx(10.0))


def test_residual_matrix_scores_too_few_shared_samples_as_unpairable():
    ais = _track("a", [(0, 0.0, 0.0), (60, 6.0, 8.0)])
    radar = _track("r", [(60, 0.0, 0.0), (120, 5.0, 5.0)])               # one common stamp, t=60
    kw = dict(pairing="exact", tolerance_s=1.0, max_gap_s=600.0, statistic="median")
    assert g.residual_matrix([radar], [ais], min_common=2, **kw) == [[math.inf]]
    assert g.residual_matrix([radar], [ais], min_common=1, **kw) == [[pytest.approx(10.0)]]


# --------------------------------------------------------------------------- the pipeline

def test_reconcile_recovers_the_scenario(scenario):
    rec = g.reconcile(scenario.evidence())
    facts = rec.facts
    assert facts["clock_offset_s"] == {"ais": 0.0, "radar": 3600.0}
    assert facts["projection"] == {"model": "local_plane", "radius_m": 6371000.0}
    assert facts["pairing"] == "exact"
    got = {(a["radar_id"], a["ais_id"]) for a in facts["associations"]}
    assert got == {(scenario.track_of[k], scenario.mmsi[k]) for k in range(6)}
    assert [a["radar_id"] for a in facts["associations"]] == ["R-01", "R-02", "R-04", "R-07", "R-10", "R-11"]
    assert all(a["residual_m"] < 0.01 for a in facts["associations"])    # the median ignores 4 displaced samples
    assert facts["unmatched"] == {"radar": [], "ais": []}
    d = facts["divergence"]
    assert (d["ais_id"], d["radar_id"]) == (scenario.mmsi[SPOOF], "R-10")
    assert (d["start_utc"], d["end_utc"], d["samples"]) == (*scenario.spoof_window, 4)
    assert d["east_m"] == pytest.approx(360.0, abs=0.01) and d["north_m"] == pytest.approx(300.0, abs=0.01)
    assert d["constant"] is True
    c = facts["closest_approach"]
    assert (c["ais_id"], c["radar_id"], c["source"]) == (scenario.mmsi[SPOOF], "R-10", "radar")
    assert c["utc"] == pytest.approx(T_CPA, abs=0.01) and c["distance_m"] == pytest.approx(40.0, abs=0.01)
    assert facts["reference"]["window_start_utc"] == T0 + 8 * 60
    # the choices the method left open are all reported
    text = "\n".join(rec.decisions)
    for needle in ("radar id: read from column 'track'", "UTC+60 min", "reference point 44.5, 29.25",
                   "stated in the method note", "sample pairing: exact", "reference window 11:28Z to 11:42Z"):
        assert needle in text
    assert rec.warnings == []


def test_reconcile_without_the_clock_correction_does_not_reproduce_the_truth(scenario):
    # the skew is the point of the challenge: read as UTC, the radar log (an hour ahead) shares no
    # sample time with AIS, and a clock four minutes out pairs each ship with where it was two
    # samples earlier (the slowest moves 372 m in that time). Either result would be the truth if
    # the offset were ignored somewhere.
    with pytest.raises(g.ReconcileError, match="no radar track could be associated"):
        g.reconcile(scenario.evidence(), {"radar": {"clock_offset_s": 0}})
    rec = g.reconcile(scenario.evidence(), {"radar": {"clock_offset_s": 3360}})
    assert min(a["residual_m"] for a in rec.facts["associations"]) > 300
    assert rec.facts["divergence"] is None and len(rec.facts["divergences"]) > 1


def test_reconcile_estimates_the_clock_when_nothing_states_it():
    scenario = _Scenario(radar_header=False, note_offset=False)
    rec = g.reconcile(scenario.evidence())
    assert rec.facts["clock_offset_s"]["radar"] == 3600.0
    assert any("estimated" in d for d in rec.decisions)
    assert rec.facts["divergence"]["ais_id"] == scenario.mmsi[SPOOF]
    with pytest.raises(g.MethodError, match="hint"):
        g.reconcile(scenario.evidence(), {"radar": {"clock_offset_s": "hint"}})


def test_reconcile_refuses_conflicting_clock_hints():
    scenario = _Scenario()
    evidence = scenario.evidence()
    evidence["note"] = b"radar local_time = UTC+120 min"
    with pytest.raises(g.MethodError, match="several clock offsets"):
        g.reconcile(evidence)
    rec = g.reconcile(evidence, {"radar": {"clock_offset_s": 3600}})     # an explicit number wins
    assert rec.facts["divergence"]["ais_id"] == scenario.mmsi[SPOOF]


def test_reconcile_method_options_change_the_answer(scenario):
    ev = scenario.evidence()
    # a window that starts after the pass: the closest approach is the window start, not 11:31:38
    late = g.reconcile(ev, {"closest_approach": {"window": ["11:36Z", "11:42Z"]}}).facts["closest_approach"]
    assert late["utc"] == pytest.approx(T0 + 16 * 60) and late["distance_m"] > 500
    # samples only: the nearest radar sample is 11:32 (22 s after the pass)
    coarse = g.reconcile(ev, {"closest_approach": {"interpolate": False}}).facts["closest_approach"]
    assert coarse["utc"] == T0 + 12 * 60
    assert coarse["distance_m"] == pytest.approx(math.hypot(40.0, 22 * math.hypot(3.0, 2.0)), abs=0.01)
    # the broadcast (AIS) track of the same vessel is displaced: its own closest approach differs
    ais = g.reconcile(ev, {"closest_approach": {"source": "ais"}}).facts["closest_approach"]
    assert ais["source"] == "ais" and ais["distance_m"] == pytest.approx(40.0, abs=0.01)
    # a threshold above the displacement finds no divergence, and says why there is no closest approach
    none = g.reconcile(ev, {"divergence": {"threshold_m": 1000.0}})
    assert none.facts["divergence"] is None and none.facts["closest_approach"] is None
    assert any("no single divergence" in w for w in none.warnings)
    # the WGS-84 plane is 0.28% wider east-west than the note's sphere at this latitude (the prime
    # vertical radius is 6388.7 km): the 360 m east offset reads about 361 m
    enu = g.reconcile(ev, {"projection": {"model": "wgs84_enu"}}).facts["divergence"]
    assert enu["east_m"] == pytest.approx(360.0 * 6388651 / 6371000, abs=0.05)
    assert 0.05 < abs(enu["north_m"] - 300.0) < 0.5


def _radar_csv(scenario, stamp, *, shift_s=0.0, header="# local_time = UTC+60 min"):
    """The radar log with each row's time written by `stamp(t_utc)`, sampled `shift_s` after AIS."""
    rows = [header, "track,local_time,lat,lon"]
    for k in range(6):
        for t in scenario.times:
            lat, lon = _latlon(*scenario.truth(k, t + shift_s))
            rows.append(f"{scenario.track_of[k]},{stamp(t + shift_s)},{lat},{lon}")
    return ("\n".join(rows) + "\n").encode()


def _pairs(rec):
    return {(a["radar_id"], a["ais_id"]) for a in rec.facts["associations"]}


def test_reconcile_interpolates_when_the_sensors_sample_at_different_times(scenario):
    truth = {(scenario.track_of[k], scenario.mmsi[k]) for k in range(6)}
    evidence = {**scenario.evidence(), "radar": _radar_csv(scenario, lambda t: _iso(t + 3600, ""), shift_s=30.0)}
    rec = g.reconcile(evidence)
    assert rec.facts["pairing"] == "interpolate" and _pairs(rec) == truth
    assert any("sample pairing: interpolate (0% of AIS samples" in d for d in rec.decisions)
    assert rec.facts["divergence"]["east_m"] == pytest.approx(360.0, abs=0.01)
    assert rec.facts["closest_approach"]["utc"] == pytest.approx(T_CPA, abs=0.01)
    with pytest.raises(g.ReconcileError, match="no radar track could be associated"):
        g.reconcile(evidence, {"match": {"pairing": "exact"}})            # forced exact finds no common time
    with pytest.raises(g.MethodError, match="match.pairing"):
        g.reconcile(evidence, {"match": {"pairing": "nearest"}})


def test_reconcile_time_only_radar_stamps_and_stamps_with_their_own_offset(scenario):
    truth = {(scenario.track_of[k], scenario.mmsi[k]) for k in range(6)}
    clock_only = {**scenario.evidence(), "radar": _radar_csv(scenario, lambda t: _iso(t + 3600, "")[11:])}
    rec = g.reconcile(clock_only)
    assert _pairs(rec) == truth and rec.facts["clock_offset_s"]["radar"] == 3600.0
    assert "time-only stamps are read on 2026-03-04 (the first AIS sample's date)" in rec.decisions
    assert rec.facts["divergence"]["start_utc"] == scenario.spoof_window[0]
    wrong_day = g.reconcile(clock_only, {"date": "2026-03-05", "radar": {"clock_offset_s": 3600 + 86400}})
    assert _pairs(wrong_day) == truth                                     # the date is the method's when given
    with pytest.raises(g.MethodError, match="YYYY-MM-DD"):
        g.reconcile(clock_only, {"date": "4 March"})
    # stamps that say +01:00 themselves are already absolute: the header's hint must not be subtracted too
    zoned = {**scenario.evidence(), "radar": _radar_csv(scenario, lambda t: _iso(t + 3600, "+01:00"))}
    rec = g.reconcile(zoned)
    assert rec.facts["clock_offset_s"]["radar"] == 0.0 and _pairs(rec) == truth
    assert any("carry their own UTC offset, so none was subtracted" in d for d in rec.decisions)
    twice = g.reconcile(zoned, {"radar": {"clock_offset_s": 240}})
    assert any("not applied twice" in w for w in twice.warnings)


def test_reconcile_ais_clock_offset(scenario):
    rows = [json.loads(line) for line in scenario.ais.splitlines()]
    for row in rows:                                                      # the AIS logger runs 120 s fast
        row["utc"] = _iso(g.parse_time(row["utc"])[0] + 120)
    evidence = {**scenario.evidence(), "ais": "\n".join(json.dumps(r) for r in rows).encode()}
    rec = g.reconcile(evidence, {"ais": {"clock_offset_s": 120}})
    assert rec.facts["clock_offset_s"]["ais"] == 120.0
    assert rec.facts["divergence"]["start_utc"] == scenario.spoof_window[0]
    assert all(a["residual_m"] < 0.01 for a in rec.facts["associations"])
    with pytest.raises(g.MethodError, match="ais.clock_offset_s"):
        g.reconcile(evidence, {"ais": {"clock_offset_s": "auto"}})


def test_reconcile_origin_and_closest_approach_targets(scenario):
    ev = scenario.evidence()
    no_reference = g.reconcile({k: v for k, v in ev.items() if k != "reference"})
    assert any("origin" in d and "mean sample position" in d for d in no_reference.decisions)
    assert no_reference.facts["reference"] is None and no_reference.facts["closest_approach"] is None
    assert any("no reference point" in w for w in no_reference.warnings)
    assert no_reference.facts["divergence"]["east_m"] == pytest.approx(360.0, abs=0.05)
    # the same answer when the point is given by the method instead of read from the notice
    given = g.reconcile({k: v for k, v in ev.items() if k != "reference"},
                        {"origin": {"lat": LAT0, "lon": LON0},
                         "closest_approach": {"to": {"lat": LAT0, "lon": LON0}, "window": None}})
    assert given.facts["closest_approach"]["distance_m"] == pytest.approx(40.0, abs=0.01)
    # target: every track (the spoofed one is nearest), or one named track
    everyone = g.reconcile(ev, {"closest_approach": {"target": "all"}}).facts["closest_approach"]
    assert everyone["radar_id"] == "R-10" and everyone["distance_m"] == pytest.approx(40.0, abs=0.01)
    named = g.reconcile(ev, {"closest_approach": {"target": "R-04", "window": None}}).facts["closest_approach"]
    k = 0                                                                 # R-04 is vessel 0
    brute = min(math.hypot(*scenario.truth(k, T0 + s)) for s in range(0, 15 * STEP + 1))
    assert named["radar_id"] == "R-04" and named["ais_id"] == scenario.mmsi[0]
    assert named["distance_m"] == pytest.approx(brute, abs=0.05)
    # to another track: R-10 against R-04, checked against a one-second brute force over the truth
    pair = g.reconcile(ev, {"closest_approach": {"target": "R-10", "to": {"sensor": "radar", "id": "R-04"},
                                                 "window": None}}).facts["closest_approach"]
    gap = lambda t: math.hypot(scenario.truth(SPOOF, t)[0] - scenario.truth(0, t)[0],   # noqa: E731
                               scenario.truth(SPOOF, t)[1] - scenario.truth(0, t)[1])
    brute_t = min((T0 + s for s in range(0, 15 * STEP + 1)), key=gap)
    assert pair["distance_m"] == pytest.approx(gap(brute_t), abs=0.05) and abs(pair["utc"] - brute_t) <= 1.0
    with pytest.raises(g.MethodError, match="no track with id 'R-99'"):
        g.reconcile(ev, {"closest_approach": {"target": "R-99"}})
    with pytest.raises(g.MethodError, match="ends before it starts"):
        g.reconcile(ev, {"closest_approach": {"window": ["11:42Z", "11:28Z"]}})


def test_reconcile_assignment_and_statistic_options(scenario):
    ev = scenario.evidence()
    truth = {(scenario.track_of[k], scenario.mmsi[k]) for k in range(6)}
    assert _pairs(g.reconcile(ev, {"match": {"assignment": "mutual_nearest"}})) == truth
    worst = g.reconcile(ev, {"match": {"statistic": "max"}})
    spoofed = [a for a in worst.facts["associations"] if a["radar_id"] == "R-10"][0]
    assert spoofed["residual_m"] == pytest.approx(math.hypot(360.0, 300.0), abs=0.01)   # max sees the displacement
    with pytest.raises(g.MethodError, match="match.assignment"):
        g.reconcile(ev, {"match": {"assignment": "greedy"}})
    with pytest.raises(g.MethodError, match="match.statistic"):
        g.reconcile(ev, {"match": {"statistic": "mode"}})


def test_reconcile_max_residual_leaves_far_tracks_unmatched(scenario):
    evidence = scenario.evidence()
    rows = [json.loads(line) for line in scenario.ais.splitlines()]
    for row in rows:                                                     # vessel 0 broadcasts a place 5.5 km away
        if row["mmsi"] == scenario.mmsi[0]:
            row["lat"] += 0.05
    evidence["ais"] = "\n".join(json.dumps(r) for r in rows).encode()
    # six radar tracks and six AIS ids: the optimal assignment pairs the leftovers, 5.5 km apart
    forced = g.reconcile(evidence)
    assert ("R-04", scenario.mmsi[0]) in _pairs(forced)
    assert [a["residual_m"] for a in forced.facts["associations"] if a["radar_id"] == "R-04"][0] > 5000
    # a residual limit refuses that pairing ...
    rec = g.reconcile(evidence, {"match": {"max_residual_m": 100.0}})
    assert rec.facts["unmatched"] == {"radar": ["R-04"], "ais": [scenario.mmsi[0]]}
    assert len(rec.facts["associations"]) == 5
    assert any("not a bijection" in w for w in rec.warnings)
    # ... and so does mutual-nearest matching, which never forces a pair
    mutual = g.reconcile(evidence, {"match": {"assignment": "mutual_nearest"}})
    assert mutual.facts["unmatched"] == {"radar": ["R-04"], "ais": [scenario.mmsi[0]]}
    # one vessel stops broadcasting altogether: its radar track is simply left over
    silent = [r for r in rows if r["mmsi"] != scenario.mmsi[0]]
    evidence["ais"] = "\n".join(json.dumps(r) for r in silent).encode()
    assert g.reconcile(evidence).facts["unmatched"] == {"radar": ["R-04"], "ais": []}


def test_reconcile_multiple_divergences_need_a_pick(scenario):
    evidence = scenario.evidence()
    rows = [json.loads(line) for line in scenario.ais.splitlines()]
    for row in rows:                                                     # a second, shorter, larger displacement
        if row["mmsi"] == scenario.mmsi[1] and row["utc"] in (_iso(T0 + 240), _iso(T0 + 360)):
            row["lat"] += 0.009
    evidence["ais"] = "\n".join(json.dumps(r) for r in rows).encode()
    rec = g.reconcile(evidence)
    assert len(rec.facts["divergences"]) == 2 and rec.facts["divergence"] is None
    assert any("set divergence.pick" in w for w in rec.warnings)
    assert g.reconcile(evidence, {"divergence": {"pick": "longest"}}).facts["divergence"]["ais_id"] == scenario.mmsi[SPOOF]
    assert g.reconcile(evidence, {"divergence": {"pick": "largest"}}).facts["divergence"]["ais_id"] == scenario.mmsi[1]
    assert g.reconcile(evidence, {"divergence": {"pick": scenario.mmsi[1]}}).facts["divergence"]["samples"] == 2
    with pytest.raises(g.MethodError, match="selects 0"):
        g.reconcile(evidence, {"divergence": {"pick": "999"}})


def test_reconcile_named_failures(scenario):
    ev = scenario.evidence()
    with pytest.raises(g.EvidenceError, match="no radar evidence"):
        g.reconcile({**ev, "radar": b""})
    with pytest.raises(g.EvidenceError, match="no column 'callsign'"):
        g.reconcile(ev, {"ais": {"id": "callsign"}})
    with pytest.raises(g.MethodError, match="unknown method key 'matching'"):
        g.reconcile(ev, {"matching": {}})
    with pytest.raises(g.MethodError, match="must be an object"):
        g.reconcile(ev, {"match": "exact"})
    with pytest.raises(g.MethodError, match="several lat/lon pairs"):
        g.reconcile({**ev, "reference": b"points 44.500000, 29.250000 and 44.600000, 29.350000"})
    bad = scenario.radar.replace("track,local_time,lat,lon", "track,local_time,northing,easting")
    with pytest.raises(g.EvidenceError, match="no lat/lon columns and no range/bearing"):
        g.reconcile({**ev, "radar": bad.encode()})
    first = scenario.radar.splitlines()[3]                                # one track, one time, two positions
    twice = scenario.radar + first.rsplit(",", 1)[0] + ",29.9\n"
    with pytest.raises(g.EvidenceError, match="two different positions at one time"):
        g.reconcile({**ev, "radar": twice.encode()})
    with pytest.raises(g.EvidenceError, match="radar row 1: not a timestamp"):
        g.reconcile({**ev, "radar": b"track,local_time,lat,lon\nR-1,soon,44.5,29.2\nR-1,later,44.5,29.2\n"})


def test_reconcile_reads_a_range_bearing_radar(scenario):
    site = _latlon(-5000.0, -4000.0)
    rows = ["track,local_time,range_m,bearing_deg"]
    for k in range(6):
        for t in scenario.times:
            e, n = scenario.truth(k, t)
            de, dn = e + 5000.0, n + 4000.0
            rows.append(f"{scenario.track_of[k]},{_iso(t + 3600, '')},{math.hypot(de, dn):.4f},"
                        f"{math.degrees(math.atan2(de, dn)) % 360:.7f}")
    evidence = {**scenario.evidence(), "radar": ("# local_time = UTC+60 min\n" + "\n".join(rows)).encode()}
    with pytest.raises(g.MethodError, match="radar.site"):
        g.reconcile(evidence)
    rec = g.reconcile(evidence, {"radar": {"site": {"lat": site[0], "lon": site[1]}}})
    assert {(a["radar_id"], a["ais_id"]) for a in rec.facts["associations"]} == \
        {(scenario.track_of[k], scenario.mmsi[k]) for k in range(6)}
    assert rec.facts["divergence"]["east_m"] == pytest.approx(360.0, abs=0.05)
    assert rec.facts["closest_approach"]["distance_m"] == pytest.approx(40.0, abs=0.05)


# --------------------------------------------------------------------------- the schema-shaped report

def test_build_report_fills_a_json_schema(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    built = g.build_report(scenario.schema, facts)
    assert built.kind == "json-schema" and built.complete
    assert built.report == scenario.expected
    assert scenario.judge(built.report) == "correct"
    assert g.validate_report(scenario.schema, built.report) == ([], [])
    sources = {t["path"]: t["source"] for t in built.trace}
    assert sources["divergence.ais_minus_radar_east_m"] == "divergence.east_m"
    assert sources["associations[].mmsi"] == "associations.ais_id"
    assert sources["closest_approach.utc"] == "closest_approach.utc"


def test_build_report_coerces_to_the_schema_types(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    schema = json.loads(json.dumps(scenario.schema))
    schema["properties"]["divergence"]["properties"]["mmsi"] = {"type": "string"}
    schema["properties"]["closest_approach"]["properties"]["utc"] = {"type": "number"}
    schema["properties"]["closest_approach"]["properties"]["distance_m"] = {"type": "integer"}
    built = g.build_report(schema, facts, decimals=1)
    assert built.report["divergence"]["mmsi"] == str(scenario.mmsi[SPOOF])
    assert built.report["closest_approach"]["utc"] == T_CPA              # epoch seconds for a number
    assert built.report["closest_approach"]["distance_m"] == 40 and isinstance(
        built.report["closest_approach"]["distance_m"], int)
    assert built.report["divergence"]["ais_minus_radar_east_m"] == 360.0
    bad = json.loads(json.dumps(scenario.schema))
    bad["properties"]["associations"]["items"]["properties"]["radar_track"] = {"type": "integer"}
    with pytest.raises(g.ReportError, match="wants a integer"):
        g.build_report(bad, facts)                                       # "R-10" is not a number


def test_build_report_negates_a_radar_minus_ais_field(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    schema = {"type": "object", "required": ["spoof"], "properties": {"spoof": {
        "type": "object", "required": ["vessel", "radar_minus_ais_east_m", "radar_minus_ais_north_m"],
        "properties": {"vessel": {"type": "integer"}, "radar_minus_ais_east_m": {"type": "number"},
                       "radar_minus_ais_north_m": {"type": "number"}}}}}
    built = g.build_report(schema, facts, decimals=1)
    assert built.report == {"spoof": {"vessel": scenario.mmsi[SPOOF], "radar_minus_ais_east_m": -360.0,
                                      "radar_minus_ais_north_m": -300.0}}


def test_build_report_unresolved_required_leaf_is_named_not_guessed(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    schema = json.loads(json.dumps(scenario.schema))
    schema["properties"]["analyst"] = {"type": "string"}
    schema["properties"]["confidence"] = {"type": "number"}
    schema["required"].append("analyst")
    built = g.build_report(schema, facts)
    assert not built.complete
    assert built.unresolved == ["analyst: no known source for 'analyst' outside any known section; "
                                "add it to report.fields"]
    assert "analyst" not in built.report and "confidence" not in built.report   # optional + unknown: left out
    fixed = g.build_report(schema, facts, fields={"analyst": {"value": "team"},
                                                  "confidence": "-divergence.magnitude_m"})
    assert fixed.complete and fixed.report["analyst"] == "team"
    assert fixed.report["confidence"] == pytest.approx(-math.hypot(360.0, 300.0), abs=0.01)
    with pytest.raises(g.ReportError, match="does not have: analyzt"):
        g.build_report(schema, facts, fields={"analyzt": {"value": "team"}})


def test_build_report_missing_fact_and_enum_are_unresolved(scenario):
    facts = g.reconcile(scenario.evidence(), {"divergence": {"threshold_m": 1000.0}}).facts
    built = g.build_report(scenario.schema, facts)
    assert not built.complete
    assert any(u.startswith("divergence.mmsi: the method produced no divergence.ais_id") for u in built.unresolved)
    assert any(u.startswith("closest_approach.distance_m") for u in built.unresolved)
    facts = g.reconcile(scenario.evidence()).facts
    schema = json.loads(json.dumps(scenario.schema))
    schema["properties"]["divergence"]["properties"]["mmsi"]["enum"] = [1, 2]
    built = g.build_report(schema, facts)
    assert any("is not one of the schema's enum values" in u for u in built.unresolved)


def test_build_report_rounding_and_time_format(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    schema = {"type": "object", "properties": {"divergence": {"type": "object", "properties": {
        "displacement_m": {"type": "number"}, "start": {"type": "string"}, "duration_s": {"type": "integer"}}}}}
    exact = math.hypot(360.0, 300.0)                                      # 468.6150...
    coarse = g.build_report(schema, facts, decimals=1, time_format="%H:%M")
    assert coarse.report == {"divergence": {"displacement_m": 468.6, "start": "11:34", "duration_s": 360}}
    fine = g.build_report(schema, facts, decimals=3, time_format="iso_offset")
    assert fine.report["divergence"]["displacement_m"] == pytest.approx(round(exact, 3), abs=2e-3)
    assert fine.report["divergence"]["displacement_m"] != 468.6
    assert fine.report["divergence"]["start"] == _iso(scenario.spoof_window[0], "+00:00")


def test_build_report_optional_section_is_dropped_whole_when_incomplete(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    schema = json.loads(json.dumps(scenario.schema))
    schema["properties"]["audit"] = {"type": "object", "required": ["mmsi", "reviewer"], "properties": {
        "mmsi": {"type": "integer"}, "reviewer": {"type": "string"}}}
    built = g.build_report(schema, facts)
    assert built.complete and "audit" not in built.report                # never sent half-built
    assert g.validate_report(schema, built.report)[0] == []


def test_build_report_example_shaped_and_flat_schemas(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    example = {"report": {"pairs": [{"track": "string", "mmsi": 0}],
                          "cpa": {"vessel": "string", "time": "iso8601", "range_m": 0.0},
                          "spoofed_mmsi": 0, "divergence_start_utc": "string", "cpa_distance_m": 1.5}}
    built = g.build_report(example, facts, pointer="/report", decimals=2)
    assert built.kind == "example" and built.complete
    assert built.report["pairs"][4] == {"track": "R-10", "mmsi": scenario.mmsi[SPOOF]}
    assert built.report["cpa"] == {"vessel": str(scenario.mmsi[SPOOF]), "time": _iso(T_CPA), "range_m": 40.0}
    assert built.report["spoofed_mmsi"] == scenario.mmsi[SPOOF]
    assert built.report["divergence_start_utc"] == _iso(scenario.spoof_window[0])
    assert built.report["cpa_distance_m"] == 40.0
    assert g.validate_report(example, built.report, pointer="/report") == ([], [])
    problems, _ = g.validate_report(example, {**built.report, "cpa": {"vessel": 5}, "extra": 1}, pointer="/report")
    assert "cpa: missing 'time'" in problems and "cpa.vessel: expected string, got int" in problems
    assert "<root>: unexpected 'extra'" in problems
    with pytest.raises(g.ReportError, match="no 'nope'"):
        g.build_report(example, facts, pointer="/nope")


def test_build_report_follows_local_refs_and_refuses_unsupported_keywords(scenario):
    facts = g.reconcile(scenario.evidence()).facts
    schema = {"type": "object", "required": ["closest_approach"],
              "definitions": {"cpa": scenario.schema["properties"]["closest_approach"]},
              "properties": {"closest_approach": {"$ref": "#/definitions/cpa"}}}
    assert g.build_report(schema, facts).report == {"closest_approach": scenario.expected["closest_approach"]}
    assert g.validate_report(schema, {"closest_approach": {"mmsi": 1}})[0] == [
        "closest_approach: missing required 'utc'", "closest_approach: missing required 'distance_m'"]
    with pytest.raises(g.ReportError, match="oneOf"):
        g.build_report({"type": "object", "properties": {"x": {"oneOf": [{"type": "string"}]}}}, facts)
    with pytest.raises(g.ReportError, match="only local references"):
        g.build_report({"$ref": "https://schemas.test/report.json"}, facts)


def test_validate_report_catches_each_kind_of_violation(scenario):
    good = scenario.expected

    def problems(mutate):
        report = json.loads(json.dumps(good))
        mutate(report)
        return g.validate_report(scenario.schema, report)[0]

    assert problems(lambda r: None) == []
    assert problems(lambda r: r.pop("divergence")) == ["<root>: missing required 'divergence'"]
    assert problems(lambda r: r.update(extra=1)) == ["<root>: unexpected property 'extra'"]
    assert problems(lambda r: r["divergence"].update(mmsi="271000103")) == ["divergence.mmsi: expected integer, got str"]
    assert problems(lambda r: r["divergence"].update(mmsi=True)) == ["divergence.mmsi: expected integer, got bool"]
    assert problems(lambda r: r["closest_approach"].update(distance_m=-1.0)) == [
        "closest_approach.distance_m: -1.0 violates minimum 0"]
    assert problems(lambda r: r["closest_approach"].update(utc="11:31:38")) == [
        "closest_approach.utc: not an RFC 3339 date-time: '11:31:38'"]
    assert problems(lambda r: r["closest_approach"].update(utc="2026-03-04T11:31:38")) == [
        "closest_approach.utc: not an RFC 3339 date-time: '2026-03-04T11:31:38'"]
    assert problems(lambda r: r.update(associations=[])) == ["associations: fewer than 1 items"]
    assert problems(lambda r: r["associations"][2].pop("mmsi")) == ["associations[2]: missing required 'mmsi'"]


def test_validate_report_names_the_keywords_it_did_not_apply():
    schema = {"type": "object", "properties": {
        "kind": {"type": "string", "enum": ["a", "b"], "pattern": "^[ab]$", "maxLength": 1},
        "n": {"type": "number", "multipleOf": 5}, "email": {"type": "string", "format": "email"}},
        "dependentRequired": {"kind": ["n"]}}
    problems, unchecked = g.validate_report(schema, {"kind": "c", "n": 7, "email": "x"})
    assert problems == ["kind: 'c' is not one of ['a', 'b']", "kind: does not match pattern '^[ab]$'"]
    assert unchecked == ["<root>: dependentRequired", "n: multipleOf", "email: format email"]
    assert g.validate_report(schema, {"kind": "ab"})[0] == [
        "kind: 'ab' is not one of ['a', 'b']", "kind: longer than 1", "kind: does not match pattern '^[ab]$'"]


def test_prepare_blocks_a_report_that_is_incomplete_or_invalid(scenario):
    ready = g.prepare(scenario.evidence())
    assert ready.ready and ready.blockers() == [] and ready.report == scenario.expected
    evidence = scenario.evidence()
    schema = json.loads(json.dumps(scenario.schema))
    schema["properties"]["closest_approach"]["properties"]["distance_m"]["minimum"] = 100
    evidence["schema"] = json.dumps(schema).encode()
    invalid = g.prepare(evidence)
    assert not invalid.ready
    assert invalid.blockers() == ["invalid: closest_approach.distance_m: 40.0 violates minimum 100"]
    with pytest.raises(g.EvidenceError, match="not JSON"):
        g.prepare({**scenario.evidence(), "schema": b"<html>"})
    with pytest.raises(g.EvidenceError, match="no schema evidence"):
        g.prepare({k: v for k, v in scenario.evidence().items() if k != "schema"})


# --------------------------------------------------------------------------- live: fetch + dry run

def test_fetch_client_is_get_only_and_scope_checked(judge):
    client = g.default_fetch_client(judge.base_url)
    assert client.get_only is True
    with pytest.raises(_scope.OutOfScope):
        client.post("/reconcile", data="{}")
    assert judge.posts == []
    with pytest.raises(_scope.OutOfScope):
        g.default_fetch_client("http://reconcile.example.org:8080/")    # outside the event's scope: no socket
    with pytest.raises(_scope.OutOfScope):
        g.default_post_client("http://reconcile.example.org:8080/")


def test_run_live_dry_run_writes_pack_and_report_and_sends_nothing(scenario, judge, tmp_path):
    result = g.run_live(judge.base_url, None, tmp_path / "out", profile=_profile(True), challenge_id="9101")
    assert result.post is None and result.flags == []
    assert judge.posts == []                                              # the default is a dry run
    assert sorted(judge.gets) == ["/files/ais.ndjson", "/files/cable-fault.txt", "/files/method-note.txt",
                                  "/files/radar.csv", "/schema"]          # each documented route once
    out = tmp_path / "out"
    assert json.loads((out / g.REPORT_NAME).read_text()) == scenario.expected
    index = json.loads((out / "index.json").read_text())                  # B-081's pack layout
    assert index["challenge_id"] == "9101" and index["endpoint"]["port"] == judge.httpd.server_address[1]
    saved = {e["route"]: (out / e["saved_as"]).read_bytes() for e in index["http"]}
    assert saved["/files/radar.csv"] == scenario.radar.encode()
    doc = json.loads((out / g.RECONCILIATION_NAME).read_text())
    assert doc["ready"] is True and doc["unresolved"] == [] and doc["facts"]["pairing"] == "exact"
    assert not (out / g.POST_LEDGER_NAME).exists()


def test_fetch_missing_required_route_is_named_and_optional_one_is_noted(scenario, tmp_path):
    srv = _Judge(scenario, missing=("/files/radar.csv",))
    try:
        with pytest.raises(g.EvidenceError, match=r"radar evidence from '/files/radar.csv': HTTP 404"):
            g.run_live(srv.base_url, None, tmp_path / "a", profile=_profile(True))
    finally:
        srv.stop()
    srv = _Judge(scenario, missing=("/files/method-note.txt",))
    try:
        result = g.run_live(srv.base_url, None, tmp_path / "b", profile=_profile(True))
        notes = json.loads((tmp_path / "b" / "index.json").read_text())["notes"]
        assert notes == ["optional note route '/files/method-note.txt' not fetched: HTTP 404"]
        assert result.prepared.ready                                      # the radar header still gives the clock
    finally:
        srv.stop()
    with pytest.raises(g.MethodError, match="no route for 'schema'"):
        g.fetch_evidence(object(), {"ais": "/a", "radar": "/r"})


def test_run_offline_recomputes_from_the_mirrored_pack(scenario, judge, tmp_path):
    g.run_live(judge.base_url, None, tmp_path / "pack", profile=_profile(True))
    gets = len(judge.gets)
    (tmp_path / "pack" / g.REPORT_NAME).unlink()
    result = g.run_offline(tmp_path / "pack", {"report": {"decimals": 1}})
    assert len(judge.gets) == gets and judge.posts == []                  # no network
    assert json.loads((tmp_path / "pack" / g.REPORT_NAME).read_text()) == scenario.expected
    assert result.prepared.ready
    with pytest.raises(g.EvidenceError, match="no evidence folder"):
        g.run_offline(tmp_path / "absent")
    (tmp_path / "empty").mkdir()
    with pytest.raises(g.EvidenceError, match="holds no evidence pack"):
        g.run_offline(tmp_path / "empty")
    # an index that points outside the pack is not followed
    (tmp_path / "secret.txt").write_text("x")
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "index.json").write_text(json.dumps({"http": [{"route": "/schema", "saved_as": "../secret.txt"}]}))
    with pytest.raises(g.EvidenceError, match="lists none of the method's routes"):
        g.load_pack(evil, g.default_method()["routes"])


# --------------------------------------------------------------------------- live: the gated, paced POST

def _send(judge, tmp_path, *, profile, approved=True, method=None, clock=None, out="out", **kw):
    clock = clock or _Clock()
    return g.run_live(judge.base_url, method, tmp_path / out, profile=profile, send=True, approved=approved,
                      ledger_path=tmp_path / out / g.POST_LEDGER_NAME, clock=clock, sleep=clock.sleep,
                      **kw), clock


def test_run_live_send_needs_a_ledger(judge, tmp_path):
    with pytest.raises(g.PostRefused, match="a send needs a POST ledger"):
        g.run_live(judge.base_url, None, tmp_path / "o", profile=_profile(True), send=True, approved=True)
    assert judge.posts == [] and judge.gets == []


def test_send_refused_unless_the_profile_allows_and_the_player_approved(judge, tmp_path):
    with pytest.raises(ics_mirror.StateChangeRefused, match="web_state_changing = false"):
        _send(judge, tmp_path, profile=_profile(False), approved=True)
    with pytest.raises(ics_mirror.StateChangeRefused, match="explicit player approval"):
        _send(judge, tmp_path, profile=_profile(True), approved=False)
    assert judge.posts == []
    assert not (tmp_path / "out" / g.POST_LEDGER_NAME).exists()


def test_send_builds_no_post_client_when_refused(scenario, tmp_path):
    prepared = g.prepare(scenario.evidence())
    built = []
    with pytest.raises(ics_mirror.StateChangeRefused):
        g.submit_report(lambda: built.append(1), "/reconcile", prepared, profile=_profile(False),
                        approved=True, ledger_path=tmp_path / "posts.jsonl")
    assert built == []


def test_send_posts_once_and_returns_the_flag(scenario, judge, tmp_path):
    result, clock = _send(judge, tmp_path, profile=_profile(True))
    assert result.post["outcome"] == "accepted" and result.post["status"] == 200
    assert result.flags == [FLAG]
    assert len(judge.posts) == 1
    path, content_type, raw = judge.posts[0]
    assert path == "/reconcile" and content_type == "application/json"
    assert json.loads(raw) == scenario.expected
    assert raw.decode() == (tmp_path / "out" / g.REPORT_NAME).read_text().strip()   # what was reviewed is what was sent
    assert clock.slept == []                                              # the first POST waits for nothing
    assert FLAG.encode() in (tmp_path / "out" / g.RESPONSE_NAME).read_bytes()
    rows = [json.loads(line) for line in (tmp_path / "out" / g.POST_LEDGER_NAME).read_text().splitlines()]
    assert [r["kind"] for r in rows] == ["intent", "result"] and rows[1]["outcome"] == "accepted"
    assert FLAG not in (tmp_path / "out" / g.POST_LEDGER_NAME).read_text()


def test_send_never_repeats_a_judged_report(judge, tmp_path):
    _send(judge, tmp_path, profile=_profile(True))
    with pytest.raises(g.PostRefused, match="already sent and came back 'accepted'"):
        _send(judge, tmp_path, profile=_profile(True))
    assert len(judge.posts) == 1


def test_send_refuses_an_unready_report(scenario, judge, tmp_path):
    with pytest.raises(g.PostRefused, match="not ready to send: unresolved: divergence.mmsi"):
        _send(judge, tmp_path, profile=_profile(True), method={"divergence": {"threshold_m": 1000.0}})
    assert judge.posts == []


def test_send_is_paced_between_posts_and_capped(scenario, judge, tmp_path):
    profile = _profile(True)
    wrong = {"report": {"fields": {"closest_approach.distance_m": {"value": 1.0}}}}
    first, clock = _send(judge, tmp_path, profile=profile, method=wrong)
    assert first.post["outcome"] == "rejected" and first.post["status"] == 422 and first.flags == []
    clock.now += 12.0                                                     # 12 s later: 18 s of the 30 s remain
    wrong2 = {"report": {"fields": {"closest_approach.distance_m": {"value": 2.0}}}}
    second, _ = _send(judge, tmp_path, profile=profile, method=wrong2, clock=clock)
    assert second.post["outcome"] == "rejected" and second.post["waited_s"] == pytest.approx(18.0)
    assert clock.slept == [pytest.approx(18.0)]
    # the wait would exceed post.max_wait_s: refused, not slept
    slow = {"report": {"fields": {"closest_approach.distance_m": {"value": 3.0}}},
            "post": {"min_interval_s": 900.0}}
    with pytest.raises(g.PostRefused, match="paced: the next POST is allowed in 900 s"):
        _send(judge, tmp_path, profile=profile, method=slow, clock=clock)
    assert len(judge.posts) == 2 and len(clock.slept) == 1
    clock.now += 60.0
    third, _ = _send(judge, tmp_path, profile=profile, clock=clock)       # the right report, third look
    assert third.post["outcome"] == "accepted" and len(judge.posts) == 3
    clock.now += 60.0
    wrong4 = {"report": {"fields": {"closest_approach.distance_m": {"value": 4.0}}}}
    with pytest.raises(g.PostRefused, match=r"POST budget is used up \(3 of post.max_posts = 3"):
        _send(judge, tmp_path, profile=profile, method=wrong4, clock=clock)
    with pytest.raises(g.PostRefused, match="already sent and came back 'rejected'"):
        _send(judge, tmp_path, profile=profile, method={**wrong, "post": {"max_posts": 9}}, clock=clock)
    assert len(judge.posts) == 3
    state = g.ledger_state(tmp_path / "out" / g.POST_LEDGER_NAME)
    assert state["judged"] == 3 and sorted(state["by_sha"].values()) == ["accepted", "rejected", "rejected"]


def test_send_waits_out_a_rate_limit_once_then_is_judged(scenario, tmp_path):
    srv = _Judge(scenario, ratelimit=1, retry_after=45)
    try:
        result, clock = _send(srv, tmp_path, profile=_profile(True))
        assert result.post["outcome"] == "accepted" and result.post["posts"] == 2
        assert clock.slept == [pytest.approx(45.0)]                      # Retry-After, above the 30 s pace
        assert len(srv.posts) == 2 and srv.posts[0][2] == srv.posts[1][2]
        assert g.ledger_state(tmp_path / "out" / g.POST_LEDGER_NAME)["judged"] == 1   # a 429 uses no look
    finally:
        srv.stop()


def test_send_stops_when_rate_limited_again_or_asked_to_wait_too_long(scenario, tmp_path):
    srv = _Judge(scenario, ratelimit=5, retry_after=10)
    try:
        result, clock = _send(srv, tmp_path, profile=_profile(True))
        assert result.post["outcome"] == "ratelimited" and result.flags == []
        assert len(srv.posts) == 2                                        # one retry (post.ratelimit_retries), no loop
        assert clock.slept == [pytest.approx(30.0)]                      # never faster than the pacing interval
        state = g.ledger_state(tmp_path / "out" / g.POST_LEDGER_NAME)
        assert state["judged"] == 0 and state["by_sha"] == {}
    finally:
        srv.stop()
    srv = _Judge(scenario, ratelimit=5, retry_after=600)
    try:
        result, clock = _send(srv, tmp_path, profile=_profile(True), out="long")
        assert result.post["outcome"] == "ratelimited" and result.post["retry_after_s"] == pytest.approx(600.0)
        assert len(srv.posts) == 1 and clock.slept == []                  # 600 s is over post.max_wait_s: no wait
    finally:
        srv.stop()


def test_ledger_counts_a_crashed_send_and_refuses_a_corrupt_file(scenario, tmp_path):
    prepared = g.prepare(scenario.evidence())
    ledger = tmp_path / "posts.jsonl"

    class _Dies:
        def post(self, path, data=None, headers=None):
            raise ConnectionRefusedError("refused")

    with pytest.raises(g.ReconcileError, match="did not reach the judge: ConnectionRefusedError"):
        g.submit_report(_Dies, "/reconcile", prepared, profile=_profile(True), approved=True,
                        ledger_path=ledger, clock=_Clock(), sleep=lambda s: None)
    assert g.ledger_state(ledger)["judged"] == 0                          # unreachable: no look used
    ledger.write_text(json.dumps({"kind": "intent", "n": 9, "ts": 5.0, "sha256": "x", "route": "/reconcile"}) + "\n")
    state = g.ledger_state(ledger)
    assert state["judged"] == 1 and state["by_sha"] == {"x": "unknown"}   # an intent with no result counts
    ledger.write_text("{not json\n")
    sent = []
    with pytest.raises(g.PostRefused, match="unreadable"):
        g.submit_report(lambda: sent.append(1), "/reconcile", prepared, profile=_profile(True),
                        approved=True, ledger_path=ledger)
    assert sent == []


def _raised_from(inner):
    """`inner` wrapped the way web.WebClient wraps a transport error: VPNRequired from it."""
    import web
    try:
        try:
            raise inner
        except Exception as e:
            raise web.VPNRequired("could not reach the target") from e
    except web.VPNRequired as outer:
        return outer


def test_send_failure_outcome_counts_everything_after_the_connection():
    import http.client
    import socket
    import urllib.error
    import web
    assert g.send_failure_outcome(web.OutOfScope("off target")) == "not_sent"
    assert g.send_failure_outcome(_scope.OutOfScope("off scope")) == "not_sent"
    assert g.send_failure_outcome(ConnectionRefusedError(61, "refused")) == "unreachable"
    assert g.send_failure_outcome(_raised_from(urllib.error.URLError(ConnectionRefusedError(61, "refused")))) \
        == "unreachable"
    assert g.send_failure_outcome(_raised_from(urllib.error.URLError(socket.gaierror(8, "no such host")))) \
        == "unreachable"
    for after in (ConnectionResetError(54, "reset"), TimeoutError("timed out"),
                  http.client.RemoteDisconnected("closed without response"),
                  urllib.error.URLError(TimeoutError("timed out")),
                  ValueError("refusing ambiguous HTTP response framing")):
        assert g.send_failure_outcome(_raised_from(after)) == "unknown", after
        assert g.send_failure_outcome(after) == "unknown", after


def test_send_that_reached_the_judge_unanswered_counts_and_is_not_resent(scenario, tmp_path):
    srv = _Judge(scenario, drop=True)
    try:
        profile = _profile(True)
        ledger = tmp_path / "out" / g.POST_LEDGER_NAME
        with pytest.raises(g.ReconcileError, match="may have reached the judge.*outcome 'unknown'"):
            _send(srv, tmp_path, profile=profile)
        assert len(srv.posts) == 1 and json.loads(srv.posts[0][2]) == scenario.expected
        state = g.ledger_state(ledger)
        assert state["judged"] == 1 and list(state["by_sha"].values()) == ["unknown"]
        clock = _Clock(now=2_000_000.0)                                   # long after the pacing interval
        with pytest.raises(g.PostRefused, match="no answer came back .*--resend-unknown"):
            _send(srv, tmp_path, profile=profile, clock=clock)
        assert len(srv.posts) == 1
        # the player's override resends it, and each resend still counts; the cap binds regardless
        for k in (2, 3):
            with pytest.raises(g.ReconcileError, match="outcome 'unknown'"):
                _send(srv, tmp_path, profile=profile, clock=clock, resend_unknown=True)
            assert len(srv.posts) == k and g.ledger_state(ledger)["judged"] == k
        clock.now += 60.0
        with pytest.raises(g.PostRefused, match=r"POST budget is used up \(3 of post.max_posts = 3"):
            _send(srv, tmp_path, profile=profile, clock=clock, resend_unknown=True)
        assert len(srv.posts) == 3
    finally:
        srv.stop()


def test_send_to_a_closed_port_is_unreachable_and_uses_no_look(scenario, tmp_path):
    import socket
    prepared = g.prepare(scenario.evidence())
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()                                                         # nothing listens there now
    ledger = tmp_path / "posts.jsonl"
    with pytest.raises(g.ReconcileError, match="did not reach the judge"):
        g.submit_report(lambda: g.default_post_client(f"http://127.0.0.1:{port}/"), "/reconcile", prepared,
                        profile=_profile(True), approved=True, ledger_path=ledger, clock=_Clock(),
                        sleep=lambda s: None)
    state = g.ledger_state(ledger)
    assert state["judged"] == 0 and state["by_sha"] == {}


def test_scope_refused_send_is_reraised_and_uses_no_look(scenario, judge, tmp_path):
    away = {"submit": "http://reconcile.example.org/reconcile"}
    with pytest.raises(_scope.OutOfScope):
        _send(judge, tmp_path, profile=_profile(True), method=away)
    assert judge.posts == []
    ledger = tmp_path / "out" / g.POST_LEDGER_NAME
    rows = [json.loads(line) for line in ledger.read_text().splitlines()]
    assert rows[-1]["kind"] == "result" and rows[-1]["outcome"] == "not_sent"
    assert g.ledger_state(ledger)["judged"] == 0


def test_the_ledger_is_locked_for_the_whole_check_and_send(scenario, tmp_path, monkeypatch):
    import fcntl
    import os
    prepared = g.prepare(scenario.evidence())
    ledger = tmp_path / "posts.jsonl"
    lock = ledger.with_name(ledger.name + ".lock")

    def held():
        fd = os.open(lock, os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        finally:
            os.close(fd)
        return False

    seen = []
    real_state = g.ledger_state

    def probing_state(path):
        seen.append(("state", held()))
        return real_state(path)

    class _Probe:
        def post(self, path, data=None, headers=None):
            seen.append(("post", held()))
            return {"status": 422, "body": b"{}"}

    monkeypatch.setattr(g, "ledger_state", probing_state)
    result = g.submit_report(_Probe, "/reconcile", prepared, profile=_profile(True), approved=True,
                             ledger_path=ledger, clock=_Clock(), sleep=lambda s: None)
    assert result["outcome"] == "rejected"
    assert seen and all(locked for _, locked in seen) and ("post", True) in seen
    assert held() is False                                                # released afterwards


def test_post_ledger_is_keyed_by_challenge_or_instance(tmp_path):
    posts = tmp_path / "geo-reconcile" / "posts"
    assert g.post_ledger_path(tmp_path, challenge_id="9101", base_url="http://judge.instances.test:8080/") \
        == posts / "challenge-9101.jsonl"
    assert g.post_ledger_path(tmp_path, base_url="http://Judge.Instances.test:31337/") \
        == posts / "instance-judge.instances.test_31337.jsonl"
    assert g.post_ledger_path(tmp_path, challenge_id="../a/b") == posts / "challenge-.._a_b.jsonl"
    with pytest.raises(g.PostRefused, match="no challenge id and no instance address"):
        g.post_ledger_path(tmp_path)
    with pytest.raises(g.PostRefused, match="cannot key the POST ledger"):
        g.post_ledger_path(tmp_path, base_url="not an address")


def test_classify_response():
    profile = _profile(True)
    assert g.classify_response({"status": 200, "body": f'{{"code": "{FLAG}"}}'.encode()}, profile) == ("accepted", [FLAG])
    assert g.classify_response({"status": 200, "body": b'{"ok": true}'}, profile) == ("judged", [])
    assert g.classify_response({"status": 400, "body": b"invalid report"}, profile) == ("rejected", [])
    assert g.classify_response({"status": 429, "body": FLAG.encode()}, profile) == ("ratelimited", [])
    assert g.classify_response({"status": 502, "body": FLAG.encode()}, profile) == ("error", [])


# --------------------------------------------------------------------------- engine contract + routing

def test_solve_offline_reports_unsure_with_the_facts(scenario, tmp_path):
    files = tmp_path / "ch" / "files"
    files.mkdir(parents=True)
    ev = scenario.evidence()
    for name, role in (("ais.ndjson", "ais"), ("radar.csv", "radar"), ("cable-fault.txt", "reference"),
                       ("method-note.txt", "note"), ("schema.json", "schema")):
        (files / name).write_bytes(ev[role])
    result = g.solve(tmp_path / "ch", _profile(False))
    assert result.status == "unsure" and result.flags == () and result.engine == "toolkits.geo_reconcile"
    details = [e.detail for e in result.evidence]
    assert details[0].startswith("6 radar/AIS associations")
    assert "east +360.0 m north +300.0 m (4 samples)" in details[1]
    assert details[2].endswith("at 2026-03-04T11:31:38Z, 40.0 m")
    assert result.evidence[0].path == "geo-reconcile/report.json"
    assert json.loads((tmp_path / "ch" / "geo-reconcile" / "report.json").read_text()) == scenario.expected
    assert not (files / "report.json").exists()                           # the handout folder is not written
    assert "ready to send" in result.notes and "Nothing was sent" in result.notes


def test_solve_offline_none_and_blocked(scenario, tmp_path):
    (tmp_path / "empty").mkdir()
    assert g.solve(tmp_path / "empty", _profile(False)).status == "none"
    files = tmp_path / "ch" / "files"
    files.mkdir(parents=True)
    (files / "ais.ndjson").write_bytes(scenario.evidence()["ais"])
    (files / "radar.csv").write_bytes(scenario.evidence()["radar"])
    blocked = g.solve(tmp_path / "ch", _profile(False))                    # sensors but no schema
    assert blocked.status == "blocked" and "no schema evidence" in blocked.notes
    assert g.solve(tmp_path / "ch", _profile(False), method=str(tmp_path / "nope.json")).status == "blocked"


def test_route_and_manifest():
    from ctf.engines import manifest as _manifest, router
    hits = router.route("networking", "AIS says no vessel crossed, coastal radar disagrees: produce the "
                                      "sensor-reconciliation report")
    assert hits and hits[0].manifest.id == "toolkits.geo_reconcile"
    mine = [m for m in _manifest.discover() if m.id == "toolkits.geo_reconcile"]
    assert len(mine) == 1 and mine[0].entry_raw == "solvers.toolkits.geo_reconcile:solve"
    assert not [h for h in router.route("networking", "a pcap with dns tunnelling")
                if h.manifest.id == "toolkits.geo_reconcile"]


def test_script_cli(scenario, tmp_path, capsys):
    assert g.main(["method"]) == 0
    assert json.loads(capsys.readouterr().out) == g.default_method()
    assert g.main(["offline", str(tmp_path / "absent")]) == 2
    assert "no evidence folder" in capsys.readouterr().err
    assert g.main(["bogus"]) == 2


# --------------------------------------------------------------------------- ctf geo-reconcile

def _cli(argv, monkeypatch, profile):
    import argparse
    from ctf.cli import geo_reconcile as cli
    monkeypatch.setattr(cli, "_profile", lambda args: profile)
    parser = argparse.ArgumentParser()
    cli.add_arguments(parser)
    return cli, cli.run(parser.parse_args(argv))


def test_cli_dry_run_then_gated_send(scenario, judge, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    out = str(tmp_path / "out")
    _, code = _cli(["run", "--url", judge.base_url, "--out", out], monkeypatch, _profile(True))
    printed = capsys.readouterr().out
    assert code == 0 and judge.posts == []
    assert "dry run: nothing was sent" in printed and "decision: radar clock is +3600 s" in printed
    assert json.loads((tmp_path / "out" / "report.json").read_text()) == scenario.expected

    gets = len(judge.gets)
    _, code = _cli(["run", "--url", judge.base_url, "--out", out, "--send"], monkeypatch, _profile(True))
    assert code == 4 and "explicit player approval" in capsys.readouterr().err
    _, code = _cli(["run", "--url", judge.base_url, "--out", out, "--send", "--player-approved"],
                   monkeypatch, _profile(False))
    assert code == 4 and "web_state_changing = false" in capsys.readouterr().err
    assert judge.posts == [] and len(judge.gets) == gets                  # refused before touching the instance

    # a report the judge refuses: sent once, exit 1, no flag. Both sends below share the instance's
    # POST ledger, so the pacing interval is set to 0 (the CLI sleeps in real time).
    fast = {"post": {"min_interval_s": 0}}
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"report": {"fields": {"closest_approach.distance_m": {"value": 1.0}}}, **fast}))
    right = tmp_path / "right.json"
    right.write_text(json.dumps(fast))
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "wrong"), "--method", str(wrong),
                    "--send", "--player-approved"], monkeypatch, _profile(True))
    printed = capsys.readouterr().out
    assert code == 1 and len(judge.posts) == 1
    assert "POST: rejected (HTTP 422, 1 request(s)" in printed and "candidate flag" not in printed
    judge.posts.clear()

    _, code = _cli(["run", "--url", judge.base_url, "--out", out, "--method", str(right), "--send",
                    "--player-approved", "--json"], monkeypatch, _profile(True))
    doc = json.loads(capsys.readouterr().out)
    assert code == 0 and len(judge.posts) == 1
    assert doc["post"]["outcome"] == "accepted" and doc["post"]["flags"] == [FLAG] and "body" not in doc["post"]


def test_cli_post_ledger_is_the_instances_not_the_out_folders(scenario, judge, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"report": {"fields": {"closest_approach.distance_m": {"value": 1.0}}},
                                 "post": {"min_interval_s": 0}}))
    send = ["--method", str(wrong), "--send", "--player-approved"]
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "a"), *send], monkeypatch, _profile(True))
    printed = capsys.readouterr().out
    ledger = g.post_ledger_path(tmp_path / "work", base_url=judge.base_url)
    assert code == 1 and len(judge.posts) == 1
    assert f"POST ledger: {ledger}" in printed and g.ledger_state(ledger)["judged"] == 1
    assert not (tmp_path / "a" / g.POST_LEDGER_NAME).exists()
    # a fresh --out is the same judge: the report already judged is not sent again
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "b"), *send], monkeypatch, _profile(True))
    assert code == 4 and "already sent and came back 'rejected'" in capsys.readouterr().err
    assert len(judge.posts) == 1


def test_cli_exit_codes(scenario, judge, tmp_path, monkeypatch, capsys):
    method = tmp_path / "method.json"
    method.write_text(json.dumps({"divergence": {"threshold_m": 1000.0}}))
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "o"), "--method", str(method)],
                   monkeypatch, _profile(True))
    assert code == 1 and "NOT READY: unresolved: divergence.mmsi" in capsys.readouterr().out
    _, code = _cli(["run", "--url", "http://reconcile.example.org:8080/", "--out", str(tmp_path / "x")],
                   monkeypatch, _profile(True))
    assert code == 4 and "outside event" in capsys.readouterr().err
    # the event given to the command is the one checked, whatever profile the process has pinned (the
    # suite's pin allows loopback; this event does not)
    narrow = _event.parse({
        "slug": "geo-narrow", "name": "narrow", "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.geo.test"}, "flag": {"prefixes": ["flag"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["*.instances.test"]}}, src="tests/test_toolkits_geo_reconcile.py")
    assert _scope.pinned() is not None
    gets = len(judge.gets)
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "n")], monkeypatch, narrow)
    assert code == 4 and "outside event 'geo-narrow'" in capsys.readouterr().err and len(judge.gets) == gets
    _, code = _cli(["run", "--url", judge.base_url], monkeypatch, _profile(True))
    assert code == 2 and "--url needs --out" in capsys.readouterr().err
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "y"), "--start"],
                   monkeypatch, _profile(True))
    assert code == 2 and "--start needs --challenge" in capsys.readouterr().err
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "y"), "--player-approved"],
                   monkeypatch, _profile(True))
    assert code == 2 and "only applies to --send" in capsys.readouterr().err
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "y"), "--resend-unknown"],
                   monkeypatch, _profile(True))
    assert code == 2 and "--resend-unknown only applies to --send" in capsys.readouterr().err
    assert not (tmp_path / "y").exists()
    # a submit route the scope guard refuses: nothing sent, and a refusal (4), not an error (2)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    away = tmp_path / "away.json"
    away.write_text(json.dumps({"submit": "http://reconcile.example.org/reconcile"}))
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "away"), "--method", str(away),
                    "--send", "--player-approved"], monkeypatch, _profile(True))
    assert code == 4 and "refused" in capsys.readouterr().err and judge.posts == []
    method.write_text("{")
    _, code = _cli(["offline", str(tmp_path / "o"), "--method", str(method)], monkeypatch, _profile(True))
    assert code == 2 and "cannot read method" in capsys.readouterr().err
    _, code = _cli(["offline", str(tmp_path / "o")], monkeypatch, _profile(True))
    assert code == 0 and "dry run" in capsys.readouterr().out
    _, code = _cli(["method"], monkeypatch, _profile(True))
    assert code == 0 and json.loads(capsys.readouterr().out)["submit"] == "/reconcile"


def test_cli_scopes_the_web_client_to_the_chosen_event(scenario, judge, tmp_path, monkeypatch, capsys):
    # Outside the suite nothing pins a scope profile: the web client's own guard then reads the
    # process profile, so the CLI must make that the event it was given, and restore it after.
    monkeypatch.setattr(_scope, "_pinned", None)
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "o")], monkeypatch, _profile(True))
    assert code == 0, capsys.readouterr().err
    assert _scope.pinned() is None
    narrow = _event.parse({
        "slug": "geo-narrow", "name": "narrow", "dates": {"start": _dt.date(2026, 1, 1), "end": _dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.geo.test"}, "flag": {"prefixes": ["flag"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["*.instances.test"]}}, src="tests/test_toolkits_geo_reconcile.py")
    gets = len(judge.gets)
    _, code = _cli(["run", "--url", judge.base_url, "--out", str(tmp_path / "n")], monkeypatch, narrow)
    assert code == 4 and "outside event 'geo-narrow'" in capsys.readouterr().err
    assert len(judge.gets) == gets and _scope.pinned() is None


class _Gate:
    """An instance-capable adapter fake: one running instance at the judge's address."""

    def __init__(self, connection_info, state="running"):
        self.info = InstanceInfo("9101", state, connection_info)
        self.started = []

    def instance_status(self, cid):
        return self.info

    def start_instance(self, cid):
        self.started.append(cid)
        self.info = InstanceInfo(str(cid), "running", self.info.connection_info)
        return self.info


def test_cli_reads_the_instance_address_and_only_starts_when_asked(scenario, judge, tmp_path, monkeypatch, capsys):
    from ctf.cli import geo_reconcile as cli
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    gate = _Gate(judge.base_url, state="stopped")
    monkeypatch.setattr(cli, "_adapter", lambda profile: gate)
    _, code = _cli(["run", "--challenge", "9101"], monkeypatch, _profile(True))
    assert code == 2 and "ctf instance start 9101" in capsys.readouterr().err
    assert gate.started == [] and judge.gets == []                       # never starts (or relaunches) unasked

    _, code = _cli(["run", "--challenge", "9101", "--start"], monkeypatch, _profile(True))
    assert code == 0 and gate.started == ["9101"]
    out = tmp_path / "work" / "geo-reconcile" / "9101"
    assert json.loads((out / "report.json").read_text()) == scenario.expected
    assert json.loads((out / "index.json").read_text())["challenge_id"] == "9101"
    with _sched.SlotLedger(_sched.slot_ledger_path(tmp_path / "work")) as ledger:
        assert "9101" in ledger.ids                                       # started through the capped ledger
    capsys.readouterr()
    _, code = _cli(["run", "--challenge", "9101"], monkeypatch, _profile(True))
    assert code == 0 and gate.started == ["9101"] and judge.posts == []  # running now: read-only status
