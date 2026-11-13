#!/usr/bin/env python3
"""B-124: business-logic state-invariant harness (solvers/web/invariant_harness.py, ctf invariant).

Every target is an in-memory SYNTHETIC shop driven through fake scope-locked clients; nothing is a
real challenge and nothing leaves the process.  The shop's coupon logic can be switched between a
correct once-only check, a double-apply bug (no once check) and a check-then-act TOCTOU, so each test
proves the harness reports exactly the rung the stated invariant breaks at -- and nothing when it
holds.  Concurrency in the TOCTOU burst is enforced structurally by a barrier inside the model (every
burst request checks before any acts), never by a wall-clock bound (rule 16).
"""
from __future__ import annotations

import contextlib
import datetime as dt
import importlib
import json
import sys
import threading
import urllib.parse
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO), str(REPO / "solvers" / "web"), str(REPO / "solvers" / "toolkits")]

H = importlib.import_module("invariant_harness")
from ctf import event as _event, scope as _scope  # noqa: E402

BASE = "http://shop.test/"
SECRET = "Bearer synthetic-invariant-harness-marker"


# ---------------------------------------------------------------------------------------------------
# profile pinning (the O-2 gate)
# ---------------------------------------------------------------------------------------------------
def _profile(web_state_changing):
    return _event.parse({
        "slug": "invariant-test", "name": "invariant harness test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.invariant-platform.test"},
        "flag": {"prefixes": []},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "web_state_changing": bool(web_state_changing),
                  "live_service_scope": ["127.0.0.0/8", "localhost", "*.test"]},
    }, src="tests/test_invariant_harness.py")


@contextlib.contextmanager
def pinned(web_state_changing=True):
    prev = _scope.pinned()
    _scope.pin(_profile(web_state_changing))
    try:
        yield
    finally:
        if prev is not None:
            _scope.pin(prev)
        else:  # pragma: no cover - the suite always pins a profile
            _scope.unpin()


@pytest.fixture(autouse=True)
def _allow_state_change():
    with pinned(True):
        yield


# ---------------------------------------------------------------------------------------------------
# synthetic shop + fake clients
# ---------------------------------------------------------------------------------------------------
class Shop:
    """cart.total starts at 100; coupon SAVE10 takes 10 off and must apply at most once.

    mode "correct": a second apply is refused 409.  mode "double": no once-check (the bug).
    mode "toctou": the once-check and the apply are split, so concurrent applies all pass the check.
    """

    def __init__(self, mode="correct", *, apply_status=None, reverse_status=None, noisy=False,
                 start_coupons=0, reverse_noop=False, apply_raises=False, lost_update=False,
                 truncate_apply=False):
        self.mode = mode
        self.reverse_noop = reverse_noop
        self.apply_raises = apply_raises
        self.lost_update = lost_update        # toctou: each apply writes (total read at check) - 10
        self.truncate_apply = truncate_apply  # apply answers 200 with a body marked truncated
        self.apply_calls = 0
        self.fail_on_call = {}   # apply call number (1-based) -> forced status
        self.lock = threading.Lock()
        self.total = 100 - 10 * start_coupons
        self.coupons = ["SAVE10"] * start_coupons
        self.views = 0
        self.log = []          # (method, path) for every request, in order
        self.headers_seen = []
        self.apply_status = apply_status
        self.reverse_status = reverse_status
        self.noisy = noisy

    def cart(self):
        doc = {"total": self.total, "coupons": list(self.coupons), "currency": "credits"}
        if self.noisy:
            self.views += 1
            doc["views"] = self.views
        return doc

    def handle(self, method, path, data, headers, arrive):
        path = path.split("?", 1)[0]
        with self.lock:
            self.log.append((method, path))
            self.headers_seen.append(dict(headers or {}))
        if method == "GET" and path == "/api/cart":
            with self.lock:
                return 200, self.cart()
        if path == "/api/cart/coupon" and method == "POST":
            if self.apply_raises:
                raise ConnectionResetError("synthetic transport failure mid-mutation")
            if self.apply_status is not None:
                return self.apply_status, {"error": "forced"}
            code = json.loads(data or "{}").get("code")
            with self.lock:
                self.apply_calls += 1
                call = self.apply_calls
                already = code in self.coupons
                seen_total = self.total
            if self.mode == "toctou" and arrive is not None:
                arrive.wait(timeout=10.0)  # every burst request has checked before any acts
            if call in self.fail_on_call:  # after the barrier, so a forced burst slot never breaks it
                return self.fail_on_call[call], {"error": "forced"}
            with self.lock:
                if self.mode == "correct":
                    already = code in self.coupons
                if already and self.mode != "double":
                    return 409, {"error": "already_applied"}
                self.coupons.append(code)
                self.total = (seen_total if self.lost_update else self.total) - 10
                return 200, {"ok": True, "total": self.total}
        if path == "/api/cart/coupon" and method == "DELETE":
            if self.reverse_status is not None:
                return self.reverse_status, {"error": "forced"}
            if self.reverse_noop:  # claims success, changes nothing
                return 200, {"ok": True}
            with self.lock:
                if not self.coupons:
                    return 404, {"error": "no_coupon"}
                self.coupons.pop()
                self.total += 10
                return 200, {"ok": True, "total": self.total}
        return 404, {"error": "not_found"}

    def mutations(self):
        return [entry for entry in self.log if entry[0] != "GET"]


class FakeClient:
    def __init__(self, base, shop, arrive=None):
        self.base = base
        self.origin = base
        parts = urllib.parse.urlsplit(base)
        self._scope = (parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
        self.timeout = 5.0
        self.shop = shop
        self.arrive = arrive

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        status, doc = self.shop.handle(method.upper(), path, data, headers, self.arrive)
        resp = {"status": status, "body": json.dumps(doc).encode(),
                "response_headers": {"Content-Type": "application/json"}}
        if self.shop.truncate_apply and method.upper() == "POST":
            resp["truncated"] = True  # the shape web.WebClient returns for a body over MAX_BODY
        return resp


def factory(shop, *, burst_width=None, base=None):
    """The first client built is the lead (no barrier); later ones are burst clients that share a
    ``burst_width``-party barrier so the TOCTOU model's check-before-act is deterministic."""
    arrive = threading.Barrier(burst_width) if burst_width else None
    built = []

    def make(url, timeout=None):
        client = FakeClient(base or url or BASE, shop, arrive if built else None)
        built.append(client)
        return client
    make.built = built
    return make


def spec(**over):
    raw = {
        "name": "SAVE10 applies at most once",
        "stated_by": "model",
        "snapshot": "/api/cart",
        "invariants": [
            {"id": "once", "path": "state.coupons", "measure": "len", "op": "<=", "value": 1},
            {"id": "floor", "path": "state.total", "op": ">=", "value": 90},
        ],
        "transition": {"method": "POST", "route": "/api/cart/coupon", "body": {"code": "SAVE10"},
                       "headers": {"Authorization": SECRET}},
        "reverse": {"method": "DELETE", "route": "/api/cart/coupon",
                    "headers": {"Authorization": SECRET}},
        "allow_actions": ["delete"],  # the reverse is method DELETE
        "ladder": {"sequential_max": 2},
    }
    raw.update(over)
    return raw


# ---------------------------------------------------------------------------------------------------
# pure evaluation
# ---------------------------------------------------------------------------------------------------
def test_absolute_len_bound_is_inclusive_and_reports_the_violation():
    inv = [{"id": "once", "path": "cart.coupons", "measure": "len", "op": "<=", "value": 1}]
    one = {"cart": {"coupons": ["A"]}}
    two = {"cart": {"coupons": ["A", "A"]}}
    assert H.check(inv, one, one)["verdict"] == "holds"
    out = H.check(inv, one, two)
    assert out["verdict"] == "violated" and out["violations"] == ["once"]
    assert out["checks"][0]["after"] == "2"


@pytest.mark.parametrize("op,value,after,expect", [
    ("<", 5, 4, "holds"), ("<", 5, 5, "violated"), (">", 5, 6, "holds"), (">", 5, 5, "violated"),
    (">=", 5, 5, "holds"), (">=", 5, 4, "violated"), ("==", 5, 5, "holds"), ("!=", 5, 5, "violated"),
    ("in", [1, 2], 2, "holds"), ("in", [1, 2], 3, "violated"), ("not_in", [1, 2], 3, "holds"),
    ("not_in", [1, 2], 1, "violated"),
])
def test_every_operator_compares_exactly(op, value, after, expect):
    inv = [{"id": "x", "path": "s.v", "op": op, "value": value}]
    assert H.check(inv, {"s": {"v": 0}}, {"s": {"v": after}})["verdict"] == expect


def test_delta_per_accepted_scales_by_the_accepted_count():
    inv = [{"id": "stock", "kind": "delta", "path": "s.stock", "op": "==", "value": -1, "per": "accepted"}]
    before = {"s": {"stock": 10}}
    # two accepted orders that only decremented once: the classic double-sell
    out = H.check(inv, before, {"s": {"stock": 9}}, accepted=2)
    assert out["verdict"] == "violated"
    assert out["checks"][0]["expected"] == -2 and out["checks"][0]["delta"] == -1
    assert H.check(inv, before, {"s": {"stock": 8}}, accepted=2)["verdict"] == "holds"
    # per "once" does not scale
    once = [dict(inv[0], per="once")]
    assert H.check(once, before, {"s": {"stock": 9}}, accepted=2)["verdict"] == "holds"


def test_unchanged_is_type_exact_and_monotonic_has_a_direction():
    inv = [{"id": "flag", "kind": "unchanged", "path": "s.paid"}]
    assert H.check(inv, {"s": {"paid": True}}, {"s": {"paid": 1}})["verdict"] == "violated"
    assert H.check(inv, {"s": {"paid": 1}}, {"s": {"paid": 1.0}})["verdict"] == "holds"
    up = [{"id": "seq", "kind": "monotonic", "path": "s.n", "direction": "nondecreasing"}]
    assert H.check(up, {"s": {"n": 3}}, {"s": {"n": 3}})["verdict"] == "holds"
    assert H.check(up, {"s": {"n": 3}}, {"s": {"n": 2}})["verdict"] == "violated"
    down = [{"id": "seq", "kind": "monotonic", "path": "s.n", "direction": "nonincreasing"}]
    assert H.check(down, {"s": {"n": 3}}, {"s": {"n": 4}})["verdict"] == "violated"


def test_unchanged_with_tolerance_holds_at_exactly_the_tolerance():
    inv = [{"id": "bal", "kind": "unchanged", "path": "s.v", "tolerance": 2}]
    before = {"s": {"v": 10}}
    assert H.check(inv, before, {"s": {"v": 12}})["verdict"] == "holds"   # change == tol
    assert H.check(inv, before, {"s": {"v": 8}})["verdict"] == "holds"
    assert H.check(inv, before, {"s": {"v": 13}})["verdict"] == "violated"
    assert H.check(inv, before, {"s": {"v": 7}})["verdict"] == "violated"
    # the tolerance is numeric only: an equal string is unchanged, a changed one is not, and a
    # number that became a string is a change however close it reads
    assert H.check(inv, {"s": {"v": "a"}}, {"s": {"v": "a"}})["verdict"] == "holds"
    assert H.check(inv, {"s": {"v": "a"}}, {"s": {"v": "b"}})["verdict"] == "violated"
    assert H.check(inv, before, {"s": {"v": "10"}})["verdict"] == "violated"


def test_sum_conserved_with_tolerance():
    inv = [{"id": "money", "kind": "sum_conserved", "paths": ["w.balance", "w.spent"], "tolerance": 0.01}]
    before = {"w": {"balance": 10.1, "spent": 0.2}}
    assert H.check(inv, before, {"w": {"balance": 0.3, "spent": 10.0}})["verdict"] == "holds"
    out = H.check(inv, before, {"w": {"balance": 10.1, "spent": 10.0}})
    assert out["verdict"] == "violated"
    # float rounding (10.1 + 0.2 != 10.3) is exactly what the tolerance absorbs
    assert H.check(inv, before, {"w": {"balance": 10.3, "spent": 0.0}})["verdict"] == "holds"
    strict = [dict(inv[0], tolerance=0)]
    ints = {"w": {"balance": 10, "spent": 2}}
    assert H.check(strict, ints, {"w": {"balance": 5, "spent": 7}})["verdict"] == "holds"
    assert H.check(strict, ints, {"w": {"balance": 5, "spent": 8}})["verdict"] == "violated"
    assert H.check(strict, before, {"w": {"balance": 10.3, "spent": 0.0}})["verdict"] == "violated"


def test_missing_path_is_unevaluable_never_holds_and_a_violation_outranks_it():
    inv = [{"id": "gone", "path": "s.nope", "op": "==", "value": 1}]
    out = H.check(inv, {"s": {}}, {"s": {}})
    assert out["verdict"] == "unevaluable" and out["unevaluable"] == ["gone"]
    both = inv + [{"id": "neg", "path": "s.v", "op": ">=", "value": 0}]
    out = H.check(both, {"s": {"v": 0}}, {"s": {"v": -1}})
    assert out["verdict"] == "violated" and out["unevaluable"] == ["gone"]
    # a numeric op on a string is unevaluable, not a silent pass or fail
    typed = [{"id": "t", "path": "s.v", "op": "<", "value": 3}]
    assert H.check(typed, {"s": {"v": "2"}}, {"s": {"v": "2"}})["verdict"] == "unevaluable"


def test_list_index_paths_and_list_form_paths():
    inv = [{"id": "first", "path": "s.items.0.qty", "op": ">=", "value": 1},
           {"id": "dotted", "path": ["s", "a.b"], "op": "==", "value": "x"}]
    doc = {"s": {"items": [{"qty": 0}], "a.b": "x"}}
    out = H.check(inv, doc, doc)
    assert out["violations"] == ["first"]
    assert [c["status"] for c in out["checks"]] == ["violated", "holds"]


@pytest.mark.parametrize("bad,needle", [
    ([{"id": "a", "path": "s.v", "op": "<", "value": "3"}], "numeric value"),
    ([{"id": "a", "path": "s.v", "op": "~", "value": 3}], "op must be"),
    ([{"id": "a", "kind": "sum_conserved", "path": "s.v"}], "paths"),
    ([{"id": "a", "path": "s.v", "op": "==", "value": 1, "extra": 1}], "unknown field"),
    ([{"id": "a", "path": "s.v", "op": "==", "value": 1}, {"id": "a", "path": "s.w", "op": "==", "value": 1}],
     "unique"),
    ([{"id": "a", "kind": "unchanged", "path": "s.v", "op": "=="}], "does not take"),
    ([{"id": "a", "kind": "delta", "path": "s.v", "op": "in", "value": [1]}], "delta compares numbers"),
    ([], "1.."),
])
def test_compile_invariants_refuses_malformed_input(bad, needle):
    with pytest.raises(H.InvariantSpecError) as exc:
        H.compile_invariants(bad)
    assert needle in str(exc.value)


# ---------------------------------------------------------------------------------------------------
# spec compilation (safety)
# ---------------------------------------------------------------------------------------------------
def test_spec_requires_who_stated_the_invariant():
    raw = spec()
    del raw["stated_by"]
    with pytest.raises(H.InvariantSpecError, match="stated_by"):
        H.compile_spec(raw, BASE)


def test_destructive_verb_needs_allow_actions_and_some_verbs_never_pass():
    raw = spec(transition={"method": "POST", "route": "/api/order/cancel"})
    with pytest.raises(H.InvariantSpecError, match="'cancel'"):
        H.compile_spec(raw, BASE)
    assert H.compile_spec(dict(raw, allow_actions=["cancel", "delete"]),
                          BASE)["transition"]["route"] == "/api/order/cancel"
    pw = spec(transition={"method": "POST", "route": "/api/user/password"}, allow_actions=["admin"])
    with pytest.raises(H.InvariantSpecError, match="never drives"):
        H.compile_spec(pw, BASE)
    with pytest.raises(H.InvariantSpecError, match="cannot waive"):
        H.compile_spec(spec(allow_actions=["password"]), BASE)
    assert H.action_words("/api/a/delete/x_transfer") == ["delete", "transfer"]


def test_method_delete_is_gated_like_a_delete_route():
    raw = spec()
    del raw["allow_actions"]
    # the default reverse is DELETE /api/cart/coupon: no destructive word in the route
    assert H.action_words("/api/cart/coupon") == []
    with pytest.raises(H.InvariantSpecError, match="method DELETE") as exc:
        H.compile_spec(raw, BASE)
    assert "reverse" in str(exc.value)
    # a DELETE transition is refused the same way (the transition is compiled first)
    bare = dict(raw, transition={"method": "delete", "route": "/api/cart"})
    with pytest.raises(H.InvariantSpecError, match="transition uses method DELETE"):
        H.compile_spec(bare, BASE)
    ok = H.compile_spec(dict(raw, allow_actions=["delete"]), BASE)
    assert ok["reverse"]["method"] == "DELETE" and ok["allow_actions"] == ["delete"]
    # other methods on the same bare route need nothing
    post_only = dict(raw, reverse={"method": "POST", "route": "/api/cart/coupon/undo"})
    assert H.compile_spec(post_only, BASE)["reverse"]["method"] == "POST"


def test_action_words_cover_every_state_transaction_fatal_verb():
    st = importlib.import_module("state_transaction")
    words = ["delete", "destroy", "drop", "wipe", "purge", "truncate", "erase", "revoke", "logout",
             "signout", "disable", "deactivate", "uninstall", "kill", "shutdown", "reboot", "ban",
             "suspend", "cancel", "transfer", "pay", "admin", "account", "password"]
    for word in words:
        route = f"/api/{word}"
        assert st.FATAL_ROUTE.search(route), word
        assert H.action_words(route) == [word]
    assert H.action_words("/api/payments") == []  # "pay" only as a whole path word


def test_off_origin_and_unsafe_routes_are_refused():
    for bad in ("http://evil.test/api/cart", "//evil.test/x", "/x\\y", "api#frag", "https://shop.test/api/cart"):
        with pytest.raises(H.InvariantSpecError, match="not a safe path"):
            H.compile_spec(spec(snapshot=bad), BASE)


def test_irreversible_needs_ack_and_can_never_burst():
    raw = spec()
    del raw["reverse"]
    with pytest.raises(H.InvariantSpecError, match="irreversible_ack"):
        H.compile_spec(raw, BASE)
    ok = H.compile_spec(dict(raw, irreversible_ack=True), BASE)
    assert ok["reverse"] is None
    with pytest.raises(H.InvariantSpecError, match="burst"):
        H.compile_spec(dict(raw, irreversible_ack=True, ladder={"burst_width": 4}), BASE)


def test_paths_must_name_a_declared_snapshot_and_ladder_is_bounded():
    with pytest.raises(H.InvariantSpecError, match="snapshot name"):
        H.compile_spec(spec(invariants=[{"id": "x", "path": "cart.total", "op": ">=", "value": 0}]), BASE)
    for ladder in ({"sequential_max": 0}, {"sequential_max": H.MAX_SEQUENTIAL + 1},
                   {"burst_width": 1}, {"burst_width": H.MAX_BURST + 1}, {"burst_mode": "h3"}):
        with pytest.raises(H.InvariantSpecError, match="ladder"):
            H.compile_spec(spec(ladder=ladder), BASE)


def test_ladder_reserves_the_whole_rung_group():
    raw = {k: v for k, v in spec().items() if k != "snapshot"}
    raw.update(snapshots={"state": "/api/cart", "wallet": "/api/wallet"},
               ladder={"sequential_max": 3, "burst_width": 4})
    compiled = H.compile_spec(raw, BASE)
    rungs = H.ladder(compiled)
    assert [(r["rung"], r["reserve"]) for r in rungs] == [
        ("baseline", 4),                 # two reads of two snapshot routes
        ("sequential-1", 1 + 2 + 1 + 2),  # transition, after, reverse, restore
        ("sequential-2", 2 + 2 + 2 + 2),
        ("sequential-3", 3 + 2 + 3 + 2),
        ("burst-4", 4 + 2 + 4 + 2),
    ]
    raw = {k: v for k, v in spec().items() if k != "reverse"}
    irreversible = H.compile_spec(dict(raw, irreversible_ack=True), BASE)
    assert [r["reserve"] for r in H.ladder(irreversible)][1:] == [1 + 1, 2 + 1]


# ---------------------------------------------------------------------------------------------------
# live driver against the synthetic shop
# ---------------------------------------------------------------------------------------------------
def test_double_apply_bug_is_found_at_the_second_sequential_rung_and_state_restored():
    shop = Shop("double")
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    assert report["verdict"] == "violated", report
    v = report["violation"]
    assert v["rung"] == "sequential-2" and v["accepted"] == 2 and v["invariants"] == ["once", "floor"]
    assert [r["rung"] for r in report["rungs"]] == ["sequential-1", "sequential-2"]
    assert report["rungs"][0]["check"]["verdict"] == "holds"
    # every accepted apply was reversed and the shop is back at its baseline
    assert report["rungs"][1]["reversed"] == 2 and report["state_restored"] is True
    assert shop.total == 100 and shop.coupons == []
    assert shop.mutations() == [("POST", "/api/cart/coupon"), ("DELETE", "/api/cart/coupon"),
                                ("POST", "/api/cart/coupon"), ("POST", "/api/cart/coupon"),
                                ("DELETE", "/api/cart/coupon"), ("DELETE", "/api/cart/coupon")]
    # baseline(2) + rung1(1+1+1+1) + rung2(2+1+2+1)
    assert report["requests"] == 2 + 4 + 6 == len(shop.log)
    assert report["mutations"] == 6


def test_correct_shop_holds_through_the_whole_ladder():
    shop = Shop("correct")
    report = H.run_harness(spec(ladder={"sequential_max": 3}), factory(shop), base_url=BASE)
    assert report["verdict"] == "holds" and report["violation"] is None and report["stopped"] is None
    assert [r["accepted"] for r in report["rungs"]] == [1, 1, 1]
    assert [r["rejected"] for r in report["rungs"]] == [0, 1, 2]
    assert [r["statuses"] for r in report["rungs"]] == [[200], [200, 409], [200, 409, 409]]
    # one reverse per ACCEPTED transition only
    assert [r["reversed"] for r in report["rungs"]] == [1, 1, 1]
    assert report["state_restored"] is True and shop.coupons == []


def test_toctou_only_breaks_under_the_b048_burst_rung():
    shop = Shop("toctou")
    make = factory(shop, burst_width=3)
    report = H.run_harness(spec(ladder={"sequential_max": 2, "burst_width": 3}), make, base_url=BASE)
    assert report["verdict"] == "violated", report
    assert [r["rung"] for r in report["rungs"]] == ["sequential-1", "sequential-2", "burst-3"]
    assert [r["check"]["verdict"] for r in report["rungs"]] == ["holds", "holds", "violated"]
    burst = report["rungs"][2]
    assert burst["accepted"] == 3 and burst["statuses"] == [200, 200, 200]
    assert burst["race"]["width"] == 3 and burst["race"]["attempts"] == 1
    assert report["violation"]["rung"] == "burst-3"
    # the burst ran on distinct factory-built clients, besides the lead
    assert len(make.built) == 1 + 3
    assert report["state_restored"] is True and shop.coupons == [] and shop.total == 100


def test_baseline_already_violated_sends_no_mutation():
    shop = Shop("double", start_coupons=2)
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    assert report["verdict"] == "inconclusive"
    assert "already false" in report["stopped"] and "nothing was sent" in report["stopped"]
    assert shop.mutations() == [] and report["mutations"] == 0 and report["requests"] == 2


def test_noise_control_refuses_an_invariant_on_a_field_that_moves_by_itself():
    shop = Shop("double", noisy=True)
    raw = spec(invariants=[{"id": "views", "kind": "unchanged", "path": "state.views"}])
    report = H.run_harness(raw, factory(shop), base_url=BASE)
    assert "state.views" in report["stopped"] and report["baseline"]["unstable_paths"] == ["state.views"]
    assert shop.mutations() == []


def test_reserve_before_mutate_never_starts_a_rung_it_cannot_finish():
    # baseline needs 2; rung 1 needs 4. 5 leaves room for the transition but not its readback group.
    shop = Shop("double")
    report = H.run_harness(spec(max_requests=5), factory(shop), base_url=BASE)
    assert shop.mutations() == [] and report["mutations"] == 0
    assert "cannot reserve sequential-1" in report["stopped"]
    assert report["verdict"] == "inconclusive"
    # exactly enough for baseline + rung 1: rung 1 runs whole, rung 2 never starts
    shop = Shop("double")
    report = H.run_harness(spec(max_requests=6), factory(shop), base_url=BASE)
    assert shop.mutations() == [("POST", "/api/cart/coupon"), ("DELETE", "/api/cart/coupon")]
    assert [r["rung"] for r in report["rungs"]] == ["sequential-1"]
    assert "cannot reserve sequential-2" in report["stopped"] and report["verdict"] == "inconclusive"


@pytest.mark.parametrize("status", [500, 503, 429, 408, 425])
def test_ambiguous_mutation_reads_back_once_and_sends_nothing_more(status):
    shop = Shop("double", apply_status=status)
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    assert shop.mutations() == [("POST", "/api/cart/coupon")]   # no reverse, no second rung
    assert shop.log[-1] == ("GET", "/api/cart")                  # the reserved after-read happened
    assert report["rungs"][0]["ambiguous"] is True
    assert "ambiguous_mutation" in report["stopped"] and report["verdict"] == "inconclusive"
    # the forced status changed nothing, and the after-read says so
    assert report["state_restored"] is True and shop.coupons == []


def test_truncated_mutation_response_is_ambiguous():
    # 200, but the body was cut at the client's read cap: the outcome is not known
    shop = Shop("double", truncate_apply=True)
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    assert report["rungs"][0]["statuses"] == [200] and report["rungs"][0]["ambiguous"] is True
    assert report["rungs"][0]["accepted"] == 0
    assert shop.mutations() == [("POST", "/api/cart/coupon")]   # no blind reverse
    assert "sequential-1: ambiguous_mutation" in report["stopped"]
    # the apply did land: the after-read reports the target off its baseline
    assert report["state_restored"] is False and shop.coupons == ["SAVE10"]


@pytest.mark.parametrize("status", [403, 409, 300, 499])
def test_explicit_rejection_is_not_ambiguous(status):
    shop = Shop("double", apply_status=status)
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    assert report["verdict"] == "holds"
    assert [r["rejected"] for r in report["rungs"]] == [1, 2]
    assert all(r["ambiguous"] is False for r in report["rungs"])


def test_failed_reverse_stops_the_ladder_and_flags_state_not_restored():
    shop = Shop("correct", reverse_status=500)
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    assert report["rungs"][0]["restored"] is False and report["state_restored"] is False
    assert "not restored" in report["stopped"]
    assert [r["rung"] for r in report["rungs"]] == ["sequential-1"]
    assert shop.mutations() == [("POST", "/api/cart/coupon"), ("DELETE", "/api/cart/coupon")]
    assert any("NOT restored" in line for line in H.summary_lines(report))


def test_irreversible_ack_chains_each_rung_from_the_previous_after_state():
    shop = Shop("correct")
    raw = {k: v for k, v in spec().items() if k != "reverse"}
    raw.update(irreversible_ack=True, invariants=[
        {"id": "step", "kind": "delta", "path": "state.total", "op": "==", "value": -10, "per": "accepted"}])
    report = H.run_harness(raw, factory(shop), base_url=BASE)
    # rung 1: 100 -> 90 (one accepted, delta -10 holds). rung 2 starts from 90: both 409, delta 0 holds
    assert report["verdict"] == "holds"
    assert [r["accepted"] for r in report["rungs"]] == [1, 0]
    assert report["rungs"][1]["check"]["checks"][0]["before"] == "90"
    assert report["state_restored"] is None and shop.total == 90
    assert all(m[0] == "POST" for m in shop.mutations())


def test_o2_gate_refuses_before_any_client_is_built():
    shop = Shop("double")
    make = factory(shop)
    with pinned(False):
        report = H.run_harness(spec(), make, base_url=BASE)
    assert report["error"] == "refused" and "web_state_changing" in report["stopped"]
    assert make.built == [] and shop.log == []


def test_client_off_the_spec_origin_is_refused():
    shop = Shop("double")
    report = H.run_harness(spec(), factory(shop, base="http://other.test/"), base_url=BASE)
    assert report["error"] == "no scoped client" and shop.log == []


def test_invalid_spec_sends_nothing():
    shop = Shop("double")
    make = factory(shop)
    report = H.run_harness(spec(stated_by="nobody"), make, base_url=BASE)
    assert report["error"] == "invalid spec" and make.built == [] and shop.log == []


def test_report_never_echoes_request_headers_or_bodies():
    shop = Shop("double")
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    text = json.dumps(report, default=str)
    assert SECRET not in text and "SAVE10\"}" not in text
    # the credential did reach the target (the harness sends the declared headers)
    assert any(h.get("Authorization") == SECRET for h in shop.headers_seen)


def test_single_packet_burst_over_tls_is_refused_before_it_sends():
    shop = Shop("toctou")
    tls = "https://shop.test/"
    report = H.run_harness(spec(ladder={"sequential_max": 1, "burst_width": 2, "burst_mode": "single-packet"}),
                           factory(shop, base=tls), base_url=tls)
    assert [r["rung"] for r in report["rungs"]] == ["sequential-1"]
    assert "burst unsupported" in report["stopped"] and "TLS" in report["stopped"]
    assert len(shop.mutations()) == 2  # only rung 1's apply + reverse


def test_external_stop_and_injected_deadline_halt_before_mutation():
    stop = threading.Event()
    stop.set()
    shop = Shop("double")
    report = H.run_harness(spec(), factory(shop), base_url=BASE, stop=stop)
    assert report["stopped"] == "stopped" and shop.log == []
    now = [1000.0]
    shop = Shop("double")
    report = H.run_harness(spec(), factory(shop), base_url=BASE, clock=lambda: now[0], deadline=1000.1)
    assert report["stopped"] == "deadline" and shop.log == []


def test_unevaluable_after_transition_stops_after_reversing():
    shop = Shop("double")
    raw = spec(invariants=[{"id": "gone", "path": "state.total", "op": ">=", "value": 0},
                           {"id": "missing", "kind": "delta", "path": "state.coupons", "op": "<=", "value": 1}])
    report = H.run_harness(raw, factory(shop), base_url=BASE)
    assert report["rungs"][0]["check"]["verdict"] == "unevaluable"
    assert "unevaluable" in report["stopped"] and report["verdict"] == "inconclusive"
    assert shop.coupons == [] and len(report["rungs"]) == 1


def test_ambiguity_inside_a_multi_transition_rung_sends_no_further_transition():
    # correct shop: rung1 = apply#1 (200); rung2 = apply#2 (200), apply#3 (409);
    # rung3 = apply#4 (200), apply#5 (forced 503) -> apply#6 must never be sent
    shop = Shop("correct")
    shop.fail_on_call = {5: 503}
    report = H.run_harness(spec(ladder={"sequential_max": 3}), factory(shop), base_url=BASE)
    assert shop.apply_calls == 5
    assert report["rungs"][2]["statuses"] == [200, 503] and report["rungs"][2]["ambiguous"] is True
    assert shop.log[-1] == ("GET", "/api/cart")          # the after-read; no reverse after ambiguity
    assert "sequential-3: ambiguous_mutation" in report["stopped"]
    # apply#4 landed and was not reversed: the report must not carry rung 2's "restored"
    assert report["state_restored"] is False and shop.coupons == ["SAVE10"]


def test_transport_failure_mid_mutation_is_ambiguous():
    shop = Shop("double", apply_raises=True)
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    assert report["rungs"][0]["ambiguous"] is True and report["rungs"][0]["statuses"] == [None]
    assert shop.mutations() == [("POST", "/api/cart/coupon")]
    assert "ambiguous_mutation" in report["stopped"]


def test_a_reverse_that_claims_success_but_changes_nothing_is_caught_by_the_restore_read():
    shop = Shop("correct", reverse_noop=True)
    report = H.run_harness(spec(), factory(shop), base_url=BASE)
    row = report["rungs"][0]
    assert row["reversed"] == 1 and row["restored"] is False
    assert report["state_restored"] is False and "not restored" in report["stopped"]
    assert len(report["rungs"]) == 1


def test_baseline_only_checks_single_snapshot_invariants():
    # a per-once delta cannot hold on an idle baseline (0 != -10); it must only be judged after a rung
    shop = Shop("correct")
    raw = spec(invariants=[{"id": "step", "kind": "delta", "path": "state.total", "op": "==", "value": -10}],
               ladder={"sequential_max": 1})
    report = H.run_harness(raw, factory(shop), base_url=BASE)
    assert report["verdict"] == "holds" and report["baseline"]["check"]["checks"] == []
    assert report["rungs"][0]["check"]["checks"][0]["delta"] == -10


def test_burst_accounting_counts_every_burst_request():
    shop = Shop("toctou")
    report = H.run_harness(spec(ladder={"sequential_max": 2, "burst_width": 3}),
                           factory(shop, burst_width=3), base_url=BASE)
    # rung1: 1 apply + 1 reverse; rung2: 2 applies (1 accepted) + 1 reverse; burst: 3 applies + 3 reverses
    assert report["mutations"] == 2 + 3 + 6 == len(shop.mutations())
    assert report["requests"] == len(shop.log)


def test_burst_client_off_the_target_origin_is_refused_before_the_burst():
    shop = Shop("toctou")
    built = []

    def make(url, timeout=None):
        client = FakeClient(BASE if not built else "http://elsewhere.test/", shop)
        built.append(client)
        return client
    report = H.run_harness(spec(ladder={"sequential_max": 1, "burst_width": 2}), make, base_url=BASE)
    assert "burst unsupported" in report["stopped"] and "scope-locked" in report["stopped"]
    assert len(shop.mutations()) == 2 and [r["rung"] for r in report["rungs"]] == ["sequential-1"]


def test_snapshot_must_be_2xx_unambiguous_json_or_nothing_is_sent():
    shop = Shop("double")
    report = H.run_harness(spec(snapshot="/api/nope"), factory(shop), base_url=BASE)
    assert "snapshot 'state' unavailable (HTTP 404)" in report["stopped"] and shop.mutations() == []

    class DupClient(FakeClient):
        def request(self, method, path, data=None, headers=None, allow_redirects=True):
            self.shop.log.append((method, path))
            return {"status": 200, "body": b'{"total": 100, "total": 0, "coupons": []}'}
    shop = Shop("double")
    report = H.run_harness(spec(), lambda url, timeout=None: DupClient(BASE, shop), base_url=BASE)
    assert "not unambiguous JSON" in report["stopped"] and shop.mutations() == []


def test_unstable_paths_also_flags_a_field_that_appears_or_vanishes():
    inv = H.compile_invariants([{"id": "a", "path": "s.x", "op": "==", "value": 1}])
    assert H.unstable_paths(inv, {"s": {}}, {"s": {"x": 1}}) == ["s.x"]
    assert H.unstable_paths(inv, {"s": {"x": 1}}, {"s": {}}) == ["s.x"]
    assert H.unstable_paths(inv, {"s": {}}, {"s": {}}) == []
    assert H.unstable_paths(inv, {"s": {"x": 1}}, {"s": {"x": True}}) == ["s.x"]


def test_equality_tolerance_applies_to_numbers_only():
    inv = [{"id": "p", "path": "s.v", "op": "==", "value": 0.3, "tolerance": 1e-9}]
    assert H.check(inv, {}, {"s": {"v": 0.1 + 0.2}})["verdict"] == "holds"
    assert H.check([dict(inv[0], tolerance=0)], {}, {"s": {"v": 0.1 + 0.2}})["verdict"] == "violated"
    txt = [{"id": "p", "path": "s.v", "op": "==", "value": "ok", "tolerance": 0.5}]
    assert H.check(txt, {}, {"s": {"v": "ok"}})["verdict"] == "holds"
    assert H.check(txt, {}, {"s": {"v": "no"}})["verdict"] == "violated"


# ---------------------------------------------------------------------------------------------------
# burst rung: ambiguity, per-accepted scaling, a primitive failing mid-send (verification round 1)
# ---------------------------------------------------------------------------------------------------
BURST_LADDER = {"sequential_max": 2, "burst_width": 3}
# toctou apply calls: rung1 = #1 (200); rung2 = #2 (200), #3 (409); the burst = #4, #5, #6
DEBIT = [{"id": "debit", "kind": "delta", "path": "state.total", "op": "==", "value": -10,
          "per": "accepted"}]


def _burst_tail(shop):
    """The requests after the burst's last apply (the burst is the shop's last three POSTs)."""
    posts = [i for i, entry in enumerate(shop.log) if entry == ("POST", "/api/cart/coupon")]
    return shop.log[posts[-1] + 1:]


def test_ambiguous_slot_in_a_partly_accepted_burst_sends_no_reversal():
    shop = Shop("toctou")
    shop.fail_on_call = {5: 503}  # one burst slot is ambiguous, the other two land
    report = H.run_harness(spec(ladder=BURST_LADDER), factory(shop, burst_width=3), base_url=BASE)
    burst = report["rungs"][2]
    assert burst["rung"] == "burst-3" and sorted(burst["statuses"]) == [200, 200, 503]
    assert burst["accepted"] == 2 and burst["ambiguous"] is True and burst["reversed"] is None
    # the two landed applies break the stated invariant; the violation is still reported ...
    assert report["verdict"] == "violated" and report["violation"]["rung"] == "burst-3"
    # ... but nothing is reversed blind: the reserved after-read is the only request after it
    assert _burst_tail(shop) == [("GET", "/api/cart")]
    assert report["stopped"] == "burst-3: ambiguous_mutation (no reversal sent)"
    assert report["state_restored"] is False and shop.coupons == ["SAVE10", "SAVE10"]
    assert report["mutations"] == len(shop.mutations()) and report["requests"] == len(shop.log)


def test_ambiguous_burst_that_holds_stops_without_reversing():
    shop = Shop("toctou")
    shop.fail_on_call = {5: 503}
    report = H.run_harness(spec(ladder=BURST_LADDER, invariants=DEBIT),
                           factory(shop, burst_width=3), base_url=BASE)
    burst = report["rungs"][2]
    assert burst["accepted"] == 2 and burst["check"]["verdict"] == "holds"
    assert report["verdict"] == "inconclusive"
    assert report["stopped"] == "burst-3: ambiguous_mutation (no reversal sent)"
    assert _burst_tail(shop) == [("GET", "/api/cart")]
    assert report["state_restored"] is False and shop.total == 80


def test_burst_per_accepted_delta_scales_by_the_burst_accepted_count():
    # every burst apply debits 10: delta -30 == -10 x 3 accepted, so the stated invariant holds
    shop = Shop("toctou")
    report = H.run_harness(spec(ladder=BURST_LADDER, invariants=DEBIT),
                           factory(shop, burst_width=3), base_url=BASE)
    burst = report["rungs"][2]
    assert burst["accepted"] == 3
    row = burst["check"]["checks"][0]
    assert (row["delta"], row["expected"], row["status"]) == (-30, -30, "holds")
    assert report["verdict"] == "holds" and report["state_restored"] is True


def test_burst_lost_update_is_the_double_sell_the_per_accepted_delta_catches():
    # three accepted applies, one debit: each wrote (total read at its check) - 10
    shop = Shop("toctou", lost_update=True)
    report = H.run_harness(spec(ladder=BURST_LADDER, invariants=DEBIT),
                           factory(shop, burst_width=3), base_url=BASE)
    assert [r["check"]["verdict"] for r in report["rungs"]] == ["holds", "holds", "violated"]
    v = report["violation"]
    assert v["rung"] == "burst-3" and v["accepted"] == 3
    assert (v["checks"][0]["delta"], v["checks"][0]["expected"]) == (-10, -30)
    # all three were reversed; reversing a lost update over-credits, and the restore read says so
    assert report["rungs"][2]["reversed"] == 3
    assert report["state_restored"] is False and shop.total == 120


def test_burst_primitive_failing_mid_send_is_counted_and_ambiguous(monkeypatch):
    real = H._race.burst_separate

    def sends_then_raises(*args, **kwargs):
        real(*args, **kwargs)
        raise RuntimeError("synthetic failure after the burst left")
    monkeypatch.setattr(H._race, "burst_separate", sends_then_raises)
    shop = Shop("toctou")
    report = H.run_harness(spec(ladder=BURST_LADDER), factory(shop, burst_width=3), base_url=BASE)
    burst = report["rungs"][2]
    assert burst["statuses"] == [None, None, None] and burst["ambiguous"] is True
    assert report["stopped"] == "burst-3: ambiguous_mutation (no reversal sent)"
    # the three applies that did go out are in the report's counts, and nothing was reversed
    assert report["mutations"] == len(shop.mutations()) == 2 + 3 + 3
    assert report["requests"] == len(shop.log)
    assert _burst_tail(shop) == [("GET", "/api/cart")]
    assert report["state_restored"] is False


def test_tls_single_packet_refusal_gives_its_counted_burst_back():
    # the burst is counted before the primitive runs; B-048's pre-send TLS refusal returns it
    shop = Shop("toctou")
    tls = "https://shop.test/"
    report = H.run_harness(spec(ladder={"sequential_max": 1, "burst_width": 2,
                                        "burst_mode": "single-packet"}),
                           factory(shop, base=tls), base_url=tls)
    assert "TLS" in report["stopped"]
    assert report["mutations"] == len(shop.mutations()) == 2
    assert report["requests"] == len(shop.log)
