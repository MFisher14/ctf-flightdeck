from __future__ import annotations

import json
import itertools
import math
import sys
from pathlib import Path

import pytest


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers" / "toolkits"
sys.path.insert(0, str(TOOLKITS))

import osint_geo_math as BASE_GEO  # noqa: E402
import osint_online as ONLINE  # noqa: E402
import osint_depth as DEPTH  # noqa: E402


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

    def __call__(self, url, headers, timeout, max_bytes):  # noqa: ANN001
        self.calls.append((url, dict(headers), timeout, max_bytes))
        if "rdap.org" in url:
            body = json.dumps({
                "name": "EXAMPLE-NET",
                "handle": "EXAMPLE",
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14"}],
                "nameservers": [{"ldhName": "ns1.example.com"}],
            }).encode()
            content_type = "application/rdap+json"
        elif "cloudflare-dns.com" in url:
            body = json.dumps({
                "Answer": [{"name": "example.com", "type": 1, "data": "93.184.216.34"}]
            }).encode()
            content_type = "application/dns-json"
        elif "crt.sh" in url:
            body = json.dumps([{"name_value": "www.example.com\nexample.com"}]).encode()
            content_type = "application/json"
        elif "web.archive.org" in url:
            body = json.dumps([
                ["timestamp", "original", "statuscode", "digest"],
                ["20010101000000", "https://www.example.com/", "200", "ABC"],
            ]).encode()
            content_type = "application/json"
        elif "api.github.com" in url:
            body = json.dumps({"login": "alice", "name": "Alice", "location": "Bucharest"}).encode()
            content_type = "application/json"
        elif "gitlab.com" in url:
            body = json.dumps([{"username": "alice", "name": "Alice"}]).encode()
            content_type = "application/json"
        elif "reddit.com" in url:
            body = json.dumps({"data": {"name": "alice"}}).encode()
            content_type = "application/json"
        elif "duckduckgo.com" in url:
            body = (
                b'<a class="result__a" href="https://public.example/report">'
                b'Exact public observation</a>'
            )
            content_type = "text/html"
        else:  # pragma: no cover - unexpected adapter is a test failure
            raise AssertionError(f"unexpected mock URL: {url}")
        return ONLINE.HTTPResult(200, {"Content-Type": content_type}, body, url)


def guarded_client(*, cap=8, protected=()):
    clock = FakeClock()
    transport = FakeTransport()
    client = ONLINE.PublicOSINTClient(
        transport=transport,
        clock=clock.clock,
        sleep=clock.sleep,
        min_interval=1.25,
        request_cap=cap,
        protected_identifiers=protected,
    )
    return client, clock, transport


def assert_human(report):
    assert report["requires_human_pin"] is True
    assert report["automatic_answer"] is None
    assert "final" in report["note"]


def test_shadow_length_multi_observation_ranks_only_supplied_places():
    stamps = ["2024-03-20T09:00:00Z", "2024-03-20T15:00:00Z"]
    observations = []
    for index, stamp in enumerate(stamps):
        sun = BASE_GEO.solar_position(stamp, 0, 0)
        elevation = sun["geometric_elevation_deg"]
        height = 2.0
        length = height / math.tan(math.radians(elevation))
        observations.append({
            "timestamp": stamp,
            "object_height_m": height,
            "shadow_length_m": length,
            "shadow_bearing_deg": (sun["azimuth_deg"] + 180) % 360,
            "terrain_horizon_deg": 0,
            "label": f"shadow-{index}",
        })
    report = DEPTH.rank_shadow_length_candidates(
        observations,
        [
            {"name": "equator", "latitude": 0, "longitude": 0},
            {"name": "distractor", "latitude": 55, "longitude": 100},
        ],
        elevation_tolerance_deg=0.2,
        bearing_tolerance_deg=0.2,
    )
    assert report["candidates"][0]["name"] == "equator"
    assert report["candidates"][0]["consistent_across_all_observations"] is True
    assert len(report["candidates"][0]["observations"]) == 2
    assert_human(report)
    with pytest.raises(ValueError, match="positive"):
        DEPTH.shadow_elevation_deg(2, 0)


def test_terrain_orientation_and_landmark_feature_consensus():
    ridge = [(0, 0), (90, 9), (180, 2), (270, 6)]
    observed = [
        # These are candidate azimuths 30/120/210/300 after a +30 true-north offset.
        (0, 3), (90, 20 / 3), (180, 10 / 3), (270, 4),
    ]
    terrain = DEPTH.rank_terrain_horizons(
        observed,
        {"ridge": ridge, "flat": [(0, 1), (90, 1), (180, 1), (270, 1)]},
        north_offset_hypotheses_deg=[0, 30, 60],
        tolerance_deg=0.01,
    )
    assert terrain["candidates"][0]["name"] == "ridge"
    assert terrain["candidates"][0]["best_north_offset_deg"] == 30
    assert terrain["candidates"][0]["rmse_deg"] == pytest.approx(0, abs=1e-10)
    assert_human(terrain)

    landmarks = DEPTH.rank_landmark_candidates(
        {
            "signage": ["Central Clock Tower"],
            "skyline": ["needle spire", "twin domes"],
            "terrain": ["waterfront"],
            "scripts": ["Latin"],
            "coordinate": (44.4268, 26.1025),
        },
        [
            {
                "name": "Central Clock Tower",
                "aliases": ["Clock Tower"],
                "signage": ["Central Clock Tower"],
                "skyline": ["needle spire", "twin domes"],
                "terrain": ["waterfront"],
                "scripts": ["Latin"],
                "coordinate": (44.4269, 26.1025),
            },
            {
                "name": "Mountain Fort",
                "skyline": ["square keep"],
                "terrain": ["mountain"],
                "scripts": ["Cyrillic"],
                "coordinate": (46, 25),
            },
        ],
    )
    assert landmarks["candidates"][0]["name"] == "Central Clock Tower"
    assert landmarks["candidates"][0]["rank"] > landmarks["candidates"][1]["rank"]
    assert landmarks["candidates"][0]["coordinate_distance_m"] < 20
    assert_human(landmarks)


def test_manual_reverse_image_manifest_never_contains_or_uploads_pixels():
    image = b"synthetic inert image bytes"
    manifest = DEPTH.build_reverse_image_manifest(
        image,
        source_name="/private/path/scene.jpg",
        width=1000,
        height=600,
        crops=[
            {"box": [0, 0, 500, 300], "reason": "skyline"},
            {"box": [400, 250, 800, 500], "reason": "signage"},
        ],
    )
    assert manifest["source_name"] == "scene.jpg"
    assert manifest["automatic_upload"] is False
    assert manifest["image_bytes_in_manifest"] is False
    assert image not in repr(manifest).encode()
    assert len({row["crop_id"] for row in manifest["crops"]}) == 2

    crop = manifest["crops"][0]["crop_id"]
    candidates = [
        {
            "name": "Central Clock Tower",
            "aliases": ["Clock Tower"],
            "signage": ["Central"],
            "skyline": ["needle spire"],
            "reverse_caption": ["Central Clock Tower waterfront"],
            "coordinate": (44.4268, 26.1025),
        },
        {"name": "Other Tower", "skyline": ["brick tower"], "coordinate": (50, 20)},
    ]
    fused = DEPTH.ingest_manual_reverse_image_results(
        manifest,
        [
            {
                "provider": "manual-lens",
                "caption": "Central Clock Tower waterfront",
                "candidate": "Central Clock Tower",
                "source_url": "https://public.example/landmark",
                "crop_id": crop,
            },
            {
                "provider": "manual-visual-search",
                "caption": "Clock Tower needle spire",
                "candidate": "Clock Tower",
                "source_url": "https://public.example/second",
                "crop_id": crop,
            },
        ],
        observed={
            "signage": ["Central"],
            "skyline": ["needle spire"],
            "coordinate": (44.4268, 26.1025),
        },
        landmark_candidates=candidates,
    )
    assert fused["automatic_upload"] is False
    assert fused["candidates"][0]["name"] == "Central Clock Tower"
    assert fused["candidates"][0]["manual_provider_count"] == 2
    assert all(row["status"] == "unverified_manual_observation" for row in fused["results"])
    assert_human(fused)

    tampered = dict(manifest)
    tampered["crops"] = [dict(manifest["crops"][0], crop_id="0" * 20)]
    with pytest.raises(ValueError, match="does not match"):
        DEPTH.ingest_manual_reverse_image_results(
            tampered,
            [{"provider": "manual", "caption": "one", "crop_id": "0" * 20}],
            observed={"skyline": ["spire"]}, landmark_candidates=candidates,
        )


def test_domain_graph_correlates_only_same_domain_evidence_offline():
    rows = [
        {"provider": "crt.sh", "kind": "certificate_name", "value": "www.example.com",
         "source_url": "https://crt.sh/?q=example.com"},
        {"provider": "Cloudflare DNS", "kind": "CNAME", "value": "www.example.com",
         "source_url": "https://cloudflare-dns.com/dns-query"},
        {"provider": "Wayback CDX", "kind": "capture",
         "value": {"timestamp": "20010101000000", "original": "https://www.example.com/"},
         "source_url": "https://web.archive.org/cdx/search/cdx"},
        {"provider": "crt.sh", "kind": "certificate_name", "value": "unrelated.invalid"},
        {"provider": "RDAP", "kind": "nameserver", "value": "ns1.example.com"},
    ]
    graph = DEPTH.build_domain_evidence_graph("example.com", rows)
    match = next(item for item in graph["correlations"] if item["node"] == "host:www.example.com")
    assert match["provider_count"] == 3
    assert "unrelated.invalid" not in graph["exact_same_domain_pivots"]
    assert graph["chronology"][0]["timestamp"] == "20010101000000"
    assert_human(graph)


def test_exact_handle_fusion_never_pronounces_identity():
    report = DEPTH.fuse_exact_handle_evidence("alice", [
        {"provider": "GitHub", "kind": "profile_observation",
         "value": {"login": "alice", "name": "Alice Example", "location": "Bucharest"}},
        {"provider": "GitLab", "kind": "profile_observation",
         "value": [{"username": "alice", "name": "Alice Example", "location": "Bucharest"}]},
        {"provider": "Reddit", "kind": "profile_observation",
         "value": {"data": {"name": "different"}}},
        {"provider": "Keybase", "kind": "profile_absence",
         "value": {"username": "alice", "status": 404}},
    ])
    assert report["exact_provider_count"] == 2
    assert report["identity_verdict"] is None
    assert any(item["field"] == "location" and len(item["providers"]) == 2
               for item in report["shared_attributes"])
    assert report["point_in_time_absences"] == ["Keybase"]
    assert_human(report)


def test_gps_provenance_surfaces_exif_xmp_conflict_instead_of_hiding_it():
    report = DEPTH.score_gps_provenance([
        {"source": "exif_gps", "lat": 44.426800, "lon": 26.102500, "reference": "APP1"},
        {"source": "xmp_gps", "lat": 44.426805, "lon": 26.102505, "reference": "XMP"},
        {"source": "ocr_coordinate", "lat": 45.0, "lon": 25.0, "reference": "sign"},
    ], conflict_distance_m=25)
    assert report["conflict"] is True
    assert len(report["candidates"]) == 2
    assert report["candidates"][0]["sources"] == ["exif_gps", "xmp_gps"]
    assert report["candidates"][0]["coordinate_is_observed_medoid"] is True
    assert_human(report)


def test_guarded_domain_orchestration_preserves_global_throttle_and_generic_ua():
    client, clock, transport = guarded_client(cap=4)
    report = DEPTH.GuardedOSINTOrchestrator(client).investigate(
        "domain", "example.com", providers=["rdap", "dns", "ct", "wayback"]
    )
    assert len(transport.calls) == 4
    assert clock.sleeps == pytest.approx([1.25, 1.25, 1.25])
    assert all(call[1]["User-Agent"] == ONLINE.GENERIC_USER_AGENT for call in transport.calls)
    assert report["providers"] == ["rdap", "dns", "ct", "wayback"]
    assert report["correlation"]["requires_human_pin"] is True
    assert_human(report)

    capped, _, capped_transport = guarded_client(cap=2)
    with pytest.raises(ONLINE.OSINTGuardError, match="global"):
        DEPTH.GuardedOSINTOrchestrator(capped).domain(
            "example.com", providers=["rdap", "dns", "ct"]
        )
    assert len(capped_transport.calls) == 2
    assert capped.request_count == 2


def test_guarded_exact_lead_binding_and_profile_fusion():
    client, clock, transport = guarded_client(cap=4)
    orchestrator = DEPTH.GuardedOSINTOrchestrator(client)
    first = orchestrator.handle("@alice", providers=["github", "gitlab", "reddit"])
    assert first["fusion"]["identity_verdict"] is None
    assert len(transport.calls) == 3
    assert clock.sleeps == pytest.approx([1.25, 1.25])
    before = len(transport.calls)
    with pytest.raises(ONLINE.OSINTGuardError, match="one client"):
        orchestrator.handle("bob", providers=["github"])
    assert len(transport.calls) == before
    assert_human(first)


@pytest.mark.parametrize(
    ("kind", "value", "protected", "message"),
    [
        ("domain", "2026.ctf-platform.example", (), "out of scope|forbidden"),
        ("public_record", "127.0.0.1", (), "private/reserved"),
        ("public_record", "private_handle", ("private_handle",), "protected/player"),
        ("paste", "api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ", (), "secret-shaped"),
        ("breach", "player@example.net", (), "e-mail is forbidden"),
    ],
)
def test_guarded_forbidden_values_fail_before_transport(kind, value, protected, message):
    client, _, transport = guarded_client(protected=protected)
    with pytest.raises((ONLINE.OSINTGuardError, ValueError), match=message):
        DEPTH.GuardedOSINTOrchestrator(client).investigate(kind, value)
    assert transport.calls == []
    assert client.request_count == 0


def test_exact_public_record_paste_breach_use_one_guarded_public_search_only():
    for kind, value in (
        ("public_record", "EXAMPLE-INCIDENT-2026"),
        ("paste", "0123456789abcdef0123456789abcdef"),
        ("breach", "example.com"),
    ):
        client, _, transport = guarded_client(cap=1)
        report = DEPTH.GuardedOSINTOrchestrator(client).investigate(kind, value)
        assert len(transport.calls) == 1
        assert report["evidence_kind"] == kind
        assert "no breach dumps" in report["warning"]
        assert_human(report)


def test_bounds_and_malformed_inputs_fail_deterministically():
    with pytest.raises(ValueError, match="outside"):
        DEPTH.build_reverse_image_manifest(b"x", source_name="x", width=1, height=1,
                                           crops=[{"box": [0, 0, 2, 1]}])
    with pytest.raises(ValueError, match="operators"):
        DEPTH._exact_public_search_lead("site:example.com alice")
    with pytest.raises(ValueError, match="CTF/local"):
        DEPTH._safe_reference_url("https://2026.ctf-platform.example/result")
    with pytest.raises(ValueError, match="private/reserved"):
        DEPTH._safe_reference_url("http://127.0.0.1/result")
    with pytest.raises(ValueError, match="forbidden"):
        DEPTH.build_domain_evidence_graph(
            "ctf-platform.example", [{"provider": "RDAP", "kind": "name", "value": "x"}]
        )


def test_iterators_are_consumed_once_and_stop_at_hard_caps():
    with pytest.raises(ValueError, match="at most 64"):
        DEPTH.rank_shadow_length_candidates(
            itertools.repeat({
                "timestamp": "2024-03-20T09:00:00Z",
                "object_height_m": 2,
                "shadow_length_m": 2,
            }),
            [("place", 0, 0)],
        )
    with pytest.raises(ValueError, match="at most 32"):
        DEPTH.build_reverse_image_manifest(
            b"x", source_name="scene.jpg", width=10, height=10,
            crops=itertools.repeat({"box": [0, 0, 1, 1]}),
        )

    # One-shot iterators remain usable in the intended bounded case.
    candidates = (
        row for row in [{"name": "Only", "skyline": ["spire"], "coordinate": (0, 0)}]
    )
    report = DEPTH.rank_landmark_candidates(
        {"skyline": (value for value in ["spire"]), "coordinate": (0, 0)}, candidates
    )
    assert report["candidates"][0]["name"] == "Only"
    assert_human(report)


@pytest.mark.parametrize(
    "operation",
    [
        lambda: DEPTH.shadow_elevation_deg(float("nan"), 1),
        lambda: DEPTH.rank_shadow_length_candidates(
            [DEPTH.ShadowLengthObservation(
                "2024-03-20T09:00:00Z", 1, 1, terrain_horizon_deg=float("nan")
            )],
            [("place", 0, 0)],
        ),
        lambda: DEPTH.build_reverse_image_manifest(
            b"x", source_name="scene.jpg", width=float("inf"), height=1
        ),
        lambda: DEPTH.build_reverse_image_manifest(
            b"x", source_name="scene.jpg", width=2, height=2,
            crops=[{"box": [0, 0, float("nan"), 1]}],
        ),
        lambda: DEPTH.score_gps_provenance(
            [{"lat": 0, "lon": 0, "weight": float("inf")}]
        ),
        lambda: DEPTH.score_gps_provenance(
            [{"lat": 0, "lon": 0, "weight": 101}]
        ),
    ],
)
def test_nan_inf_and_unbounded_weights_fail_closed(operation):
    with pytest.raises((ValueError, OverflowError)):
        operation()


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@public.example/result",
        "https://2026。ctf-platform。example/result",
        "https://ctf-platform.example.evil.example/result",
        "https://public.example/?next=https%253A%252F%252F2026.ctf-platform.example",
        "https://public.example/?next=http%3A%2F%2F127.0.0.1%2Fadmin",
        "https://public.example/?next=http%3A%2F%2Flocalhost%2Fadmin",
        "https://public.example/%2500hidden",
        "https://public.example/player@example.net",
        "http://[::1]/result",
        "http://2130706433/result",
        "https://public.example:444/result",
    ],
)
def test_manual_evidence_url_rejects_userinfo_idna_embeds_and_local_tricks(url):
    with pytest.raises(ValueError):
        DEPTH._safe_reference_url(url)


def test_manual_evidence_url_canonicalizes_public_idna_without_fetching():
    assert DEPTH._safe_reference_url("https://bücher.example/path") == (
        "https://xn--bcher-kva.example/path"
    )
    with pytest.raises(ONLINE.OSINTGuardError, match="e-mail"):
        DEPTH._exact_public_search_lead("player＠example.net")
    with pytest.raises((ONLINE.OSINTGuardError, ValueError), match="invisible|control"):
        DEPTH._exact_public_search_lead("public\U000E0001record")
    with pytest.raises(ONLINE.OSINTGuardError, match="forbidden"):
        DEPTH._exact_public_search_lead("2026。ctf-platform。example")
    with pytest.raises(ONLINE.OSINTGuardError, match="identifier, not a URL"):
        DEPTH._exact_public_search_lead("http://127.0.0.1/private")
    with pytest.raises(ONLINE.OSINTGuardError, match="private/reserved"):
        DEPTH._exact_public_search_lead("incident at 127.0.0.1")
    with pytest.raises(ONLINE.OSINTGuardError, match="private/reserved"):
        DEPTH._exact_public_search_lead("incident at 2130706433")


def test_provider_output_is_globally_bounded_and_nonfinite_json_is_sanitized():
    enormous = {
        "provider": "mock",
        "kind": "profile_observation",
        "value": {
            "items": ["x" * 10_000 for _ in range(10_000)],
            "nan": float("nan"),
            "inf": float("inf"),
            "blocked_url": "https://2026.ctf-platform.example/api/v1/challenges",
            "private_url": "http://127.0.0.1/admin",
        },
        "source_url": "https://public.example/evidence",
    }
    rows = DEPTH._serialize_evidence([enormous])
    encoded = json.dumps(rows, allow_nan=False)
    assert len(encoded) < 600_000
    assert "<nan>" in encoded and "<inf>" in encoded
    assert "<truncated>" in encoded
    assert "ctf-platform.example/api" not in encoded and "127.0.0.1/admin" not in encoded


def test_partial_provider_failure_counts_attempt_and_preserves_next_throttle():
    clock = FakeClock()
    base = FakeTransport()
    calls = []

    def partial(url, headers, timeout, max_bytes):  # noqa: ANN001
        calls.append(url)
        if "cloudflare-dns.com" in url:
            return ONLINE.HTTPResult(503, {"Content-Type": "application/json"}, b"{}", url)
        # Delegate response construction but keep this test's call accounting separate.
        return base(url, headers, timeout, max_bytes)

    client = ONLINE.PublicOSINTClient(
        transport=partial, clock=clock.clock, sleep=clock.sleep,
        min_interval=1.25, request_cap=4,
    )
    orchestrator = DEPTH.GuardedOSINTOrchestrator(client)
    with pytest.raises(ONLINE.OSINTGuardError, match="503"):
        orchestrator.domain("example.com", providers=["rdap", "dns"])
    assert client.request_count == 2
    assert clock.sleeps == pytest.approx([1.25])
    recovered = orchestrator.domain("example.com", providers=["ct"])
    assert recovered["requests"] == 3
    assert clock.sleeps == pytest.approx([1.25, 1.25])
    assert len(calls) == 3
    assert_human(recovered)


def test_bad_local_options_do_not_bind_lead_or_spend_request():
    client, _, transport = guarded_client(cap=2)
    orchestrator = DEPTH.GuardedOSINTOrchestrator(client)
    with pytest.raises(ONLINE.OSINTGuardError, match="unsupported domain provider"):
        orchestrator.domain("example.com", providers=["bogus"])
    with pytest.raises(ONLINE.OSINTGuardError, match="DNS record"):
        orchestrator.domain("example.com", providers=["rdap", "dns"], record_type="ANY")
    assert client.request_count == 0 and transport.calls == []
    # The invalid calls did not bind example.com, so a separately reviewed lead can proceed.
    report = orchestrator.domain("example.net", providers=["rdap"])
    assert report["lead"] == "example.net" and client.request_count == 1
    assert_human(report)


def test_complete_link_gps_clusters_do_not_hide_transitive_conflict():
    report = DEPTH.score_gps_provenance([
        {"source": "exif_gps", "lat": 0, "lon": 0, "polarity_attested": True},
        {"source": "xmp_gps", "lat": 0, "lon": 0.0005, "polarity_attested": True},
        {"source": "manual", "lat": 0, "lon": 0.0010},
    ], conflict_distance_m=75)
    assert report["conflict"] is True
    assert sorted(row["record_count"] for row in report["candidates"]) == [1, 2]
    assert_human(report)


def test_handle_display_name_and_mismatched_absence_cannot_fake_exact_profile():
    report = DEPTH.fuse_exact_handle_evidence("alice", [
        {"provider": "GitHub", "kind": "profile_observation", "value": {"name": "alice"}},
        {"provider": "Reddit", "kind": "profile_observation",
         "value": {"data": {"name": "alice"}}},
        {"provider": "Keybase", "kind": "profile_absence", "value": {"username": "bob"}},
    ])
    assert report["exact_provider_count"] == 1
    assert report["observations"][0]["provider"] == "Reddit"
    assert report["point_in_time_absences"] == []
    assert report["identity_verdict"] is None
    assert_human(report)
    for malformed in ("@@alice", "alice@example", "player@example.net"):
        with pytest.raises(ValueError, match="handle"):
            DEPTH.fuse_exact_handle_evidence(
                malformed,
                [{"provider": "GitHub", "kind": "profile_observation",
                  "value": {"login": "alice"}}],
            )


def test_domain_graph_rejects_deceptive_archive_and_blocked_related_host():
    graph = DEPTH.build_domain_evidence_graph("example.com", [
        {"provider": "Wayback CDX", "kind": "capture",
         "value": {"timestamp": "20010101000000",
                   "original": "https://ctf-platform.example@www.example.com/"}},
        {"provider": "RDAP", "kind": "nameserver", "value": "ns.ctf-platform.example"},
    ])
    assert graph["exact_same_domain_pivots"] == []
    assert {row["reason"] for row in graph["ignored"]} == {
        "invalid_archive_url", "blocked_ctf_host"
    }
    assert_human(graph)
