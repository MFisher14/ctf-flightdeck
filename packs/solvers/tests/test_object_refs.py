#!/usr/bin/env python3
"""Synthetic tests for bounded, offline object-reference generation."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import itertools
import json
import sys
import uuid
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
import object_refs as refs  # noqa: E402


def test_explicit_sequential_md5_and_base64_transforms():
    sequential = refs.enumerate_references("sequential", [41, "invoice-42"])
    assert [row["reference"] for row in sequential] == ["41", "invoice-42"]
    assert all(row["candidate_only"] and row["network_requests"] == 0 for row in sequential)

    md5_rows = refs.enumerate_references("md5(id)", [7, 8], prefix="user:")
    assert [row["reference"] for row in md5_rows] == [
        hashlib.md5(b"user:7").hexdigest(), hashlib.md5(b"user:8").hexdigest(),
    ]
    base64_rows = refs.enumerate_references("base64", ["\u00ff/7"], url_safe=True,
                                            strip_padding=True)
    assert base64_rows[0]["reference"] == base64.urlsafe_b64encode("\u00ff/7".encode()).decode().rstrip("=")


def test_integer_ranges_are_inclusive_directional_and_strictly_capped():
    assert refs.explicit_integer_range(3, 7, step=2) == [3, 5, 7]
    assert refs.explicit_integer_range(7, 3, step=-2) == [7, 5, 3]
    assert refs.explicit_integer_range(2, -2) == [2, 1, 0, -1, -2]
    with pytest.raises(refs.ObjectRefError, match="cap"):
        refs.explicit_integer_range(1, 5, max_candidates=4)
    with pytest.raises(refs.ObjectRefError, match="does not move"):
        refs.explicit_integer_range(1, 5, step=-1)
    with pytest.raises(refs.ObjectRefError, match="identifier list"):
        refs.enumerate_references("md5", range(4), max_candidates=3)


def test_uuid1_construct_inspect_and_iso_timestamp_round_trip():
    instant = dt.datetime(2026, 11, 6, 13, 0, 0, 123456, tzinfo=dt.timezone.utc)
    ticks = refs.timestamp_to_uuid_ticks(instant)
    built = refs.uuid1_from_parts(ticks, 0x1234, "02:42:ac:11:00:02")
    assert built.version == 1 and built.variant == uuid.RFC_4122
    details = refs.inspect_uuid1(str(built))
    assert details["timestamp_100ns"] == ticks
    assert details["timestamp_utc"] == "2026-11-06T13:00:00.123456Z"
    assert details["clock_seq"] == 0x1234
    assert details["node_hex"] == "0242ac110002"
    assert details["network_requests"] == 0
    assert refs.timestamp_to_uuid_ticks("2026-11-06T15:00:00.123456+02:00") == ticks


def test_uuid1_neighborhood_is_deterministic_nearest_first():
    anchor = refs.uuid1_from_parts(0x1ED000000000000, 77, 0x0242AC110002)
    rows = refs.uuid1_neighborhood(anchor=str(anchor), before=2, after=3, step=1)
    assert [row["offset_100ns"] for row in rows] == [0, -1, 1, -2, 2, 3]
    assert [uuid.UUID(row["reference"]).time for row in rows] == [
        anchor.time, anchor.time - 1, anchor.time + 1,
        anchor.time - 2, anchor.time + 2, anchor.time + 3,
    ]
    assert all(uuid.UUID(row["reference"]).node == anchor.node for row in rows)
    assert all(uuid.UUID(row["reference"]).clock_seq == anchor.clock_seq for row in rows)

    overridden = refs.uuid1_neighborhood(anchor=str(anchor), timestamp_100ns=anchor.time + 50,
                                         node="abcdef123456", clock_seq=4)[0]
    candidate = uuid.UUID(overridden["reference"])
    assert candidate.time == anchor.time + 50
    assert candidate.node == 0xABCDEF123456 and candidate.clock_seq == 4


def test_uuid1_requires_explicit_parts_and_rejects_non_v1_or_large_neighborhoods():
    with pytest.raises(refs.ObjectRefError, match="all required"):
        refs.uuid1_neighborhood(timestamp_100ns=123)
    with pytest.raises(refs.ObjectRefError, match="version 1"):
        refs.inspect_uuid1(str(uuid.UUID("12345678-1234-4234-9234-123456789abc")))
    anchor = refs.uuid1_from_parts(0x1ED000000000000, 1, 2)
    with pytest.raises(refs.ObjectRefError, match="cap"):
        refs.uuid1_neighborhood(anchor=str(anchor), before=256, max_candidates=256)
    with pytest.raises(refs.ObjectRefError, match="positive"):
        refs.uuid1_neighborhood(anchor=str(anchor), after=2, step=0)
    # The cap is checked arithmetically before any range proportional to this
    # attacker-controlled value is materialized.
    with pytest.raises(refs.ObjectRefError, match="cap"):
        refs.uuid1_neighborhood(anchor=str(anchor), before=10**100, max_candidates=2)


def test_identifier_iterables_are_consumed_only_through_the_cap():
    infinite = (str(index) for index in itertools.count())
    with pytest.raises(refs.ObjectRefError, match="identifier list"):
        refs.enumerate_references("md5", infinite, max_candidates=3)


def test_uuid1_scheme_and_cli_output_are_ranked_candidates(capsys):
    anchor = refs.uuid1_from_parts(0x1ED000000000000, 1, 2)
    rows = refs.enumerate_references("uuidv1", [str(anchor)], uuid_before=1, uuid_after=1)
    assert [row["rank"] for row in rows] == [1, 2, 3]
    assert [row["offset_100ns"] for row in rows] == [0, -1, 1]

    assert refs.main(["generate", "md5", "--start", "9", "--stop", "11"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert [row["source_id"] for row in output] == ["9", "10", "11"]
    assert all(row["offline_only"] for row in output)

