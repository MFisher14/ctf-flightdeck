#!/usr/bin/env python3
"""B-048: ctf.fastlane.try_race wiring -- the race/TOCTOU class of the in-process fast lane.

All targets are in-process fakes; the burst never leaves the test. The lane only ever fires a burst
when the caller hands in BOTH an explicit plan and a scope-locked client_factory, so these tests also
pin that it never auto-bursts from a brief alone.
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from ctf import config as _config          # noqa: E402
from ctf import fastlane                    # noqa: E402

FLAG = "CSCTF{tw0_k3y_turn_r4ced}"

RACE_DESC = {
    "name": "Two-Key Turn", "category": "web",
    "description": ("A fire order arms only when two DISTINCT officers approve it -- the two-person "
                    "rule. Drive the pending order to ARMED with your single credential."),
}
PLAIN_DESC = {"name": "Static Site", "category": "web",
              "description": "Find the flag hidden in the page source."}


class AlwaysArmsModel:
    """Arms as soon as >=2 concurrent approvals land (window always open); no retry needed."""

    def __init__(self):
        self.lock = threading.Lock()
        self.state = "PENDING_AUTH"
        self.calls = 0

    def handle(self, method, path):
        path = path.split("?", 1)[0]
        if method == "POST" and path == "/orders/ord-7/approve":
            with self.lock:
                self.calls += 1
                if self.calls >= 2:
                    self.state = "ARMED"
                code = 200 if self.state == "ARMED" else 409
                doc = {"ok": self.state == "ARMED", "state": self.state}
                if code == 409:
                    doc["retry_after_ms"] = 100
                return code, doc
        if method == "GET" and path == "/orders/ord-7":
            with self.lock:
                doc = {"state": self.state}
                if self.state == "ARMED":
                    doc["arming_authorization"] = FLAG
                return code_ok(doc)
        return 404, {"error": "not_found"}


def code_ok(doc):
    return 200, doc


class FakeClient:
    def __init__(self, base, model):
        self.base = base
        self.origin = base
        self._scope = ("http", "race.test", 80)
        self.timeout = 5.0
        self.model = model

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        status, doc = self.model.handle(method.upper(), path)
        return {"status": status, "body": json.dumps(doc).encode(),
                "response_headers": {"Content-Type": "application/json"}}


def _factory(model):
    def make(url, timeout=None):
        return FakeClient(url or "http://race.test/", model)
    return make


@pytest.fixture(scope="module")
def cfg():
    return _config.load()


def _plan():
    return {"url": "http://race.test/", "route": "/orders/ord-7/approve",
            "readback_route": "/orders/ord-7", "success_state": "ARMED",
            "flag_field": "arming_authorization", "width": 6, "retries": 2, "mode": "separate",
            "headers": {"Authorization": "Bearer opk_vega7_SECRET"}}


def test_looks_race_detects_two_person_brief_and_ignores_plain_web():
    assert fastlane._looks_race(RACE_DESC) is True
    assert fastlane._looks_race(PLAIN_DESC) is False


def test_try_race_without_plan_gives_instruction_and_never_bursts(cfg):
    r = fastlane.try_race(RACE_DESC, cfg, client_factory=None, plan=None, online=True)
    assert r is not None and r.get("flag") is None
    assert r["klass"] == "race" and r.get("instruction")


def test_try_race_offline_does_not_run(cfg):
    model = AlwaysArmsModel()
    r = fastlane.try_race(RACE_DESC, cfg, client_factory=_factory(model), plan=_plan(), online=False)
    assert r is not None and r.get("flag") is None and r["confidence"] == "low"
    assert model.calls == 0  # nothing fired


def test_try_race_wins_returns_flag_with_transition_report_and_no_credential(cfg):
    model = AlwaysArmsModel()
    r = fastlane.try_race(RACE_DESC, cfg, client_factory=_factory(model), plan=_plan(), online=True)
    assert r is not None and r["flag"] == FLAG, r
    assert r["klass"] == "race" and r["confidence"] == "high"
    assert r["source"] == "/orders/ord-7/approve"
    # The credential-free transition report rides along for the operator.
    assert isinstance(r.get("race"), dict) and r["race"]["won"] is True
    assert r["race"]["transitions"], r["race"]
    blob = json.dumps(r)
    assert "SECRET" not in blob and "Bearer" not in blob, "the bearer credential must never be echoed"


def test_try_solve_runs_the_race_first_when_a_plan_is_supplied(cfg):
    model = AlwaysArmsModel()
    r = fastlane.try_solve(RACE_DESC, None, cfg=cfg, online=True,
                           race=_plan(), race_client_factory=_factory(model))
    assert r is not None and r["flag"] == FLAG and r["klass"] == "race", r


def test_try_solve_without_a_plan_is_unchanged(cfg):
    # No plan -> the race lane is inert and an unrelated web brief falls through to None.
    assert fastlane.try_solve(PLAIN_DESC, None, cfg=cfg, online=False) is None
