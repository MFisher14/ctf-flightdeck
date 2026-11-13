"""B-106: the integrity-binding-gap (partial-signature TOCTOU) engine (solvers/web/integrity_binding.py).

Offline: field-path normalisation, the covered-vs-mutable diff over JSON / YAML / OpenAPI / text specs,
fail-closed parsing, the gap ranking and the digest recompute. Live: the amend-after-approval probe
against a synthetic freight-clearance app served on 127.0.0.1 through the real scope-locked WebClient,
with the Open O-2 gate (rules.web_state_changing) enforced before any request. Every spec, record and
flag here is synthetic; no challenge file is read and no challenge binary is run.
"""
import contextlib
import copy
import datetime as dt
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import integrity_binding as ib
from ctf import event as _event, scope as _scope

FLAG = "SYNTH{binding_gap_release_7c1e}"
REF = "MFC-TEST01"
COVERED = ["ref", "origin", "destination", "declared_value_eur", "carrier",
           "lineitems[].description", "lineitems[].quantity"]
EMBARGO = {"8544.42", "9306.90"}

SCHEMA = {
    "service": "freight clearance",
    "approval": {
        "description": "Approval binds a SHA-256 manifest_hash over the covered fields.",
        "algorithm": "sha256", "stored_in": "manifest_hash", "covered_fields": COVERED,
    },
    "release_requires": ["approval.status == APPROVED", "manifest_hash equals the current hash",
                         "no line item carries an embargoed hs_code"],
    "endpoints": [
        {"method": "GET", "path": "/consignments/{ref}"},
        {"method": "PATCH", "path": "/consignments/{ref}/lineitems/{index}",
         "body": {"hs_code": "string", "justification": "string"}},
        {"method": "PATCH", "path": "/consignments/{ref}", "body": ["carrier", "declared_value_eur"]},
        {"method": "POST", "path": "/consignments/{ref}/release", "body": {}},
    ],
}

TEXT_SPEC = """Approval model: approval binds a sha256 over covered_fields = ref, origin, destination, \
declared_value_eur, carrier, lineitems[].description, lineitems[].quantity -- hs_code is not listed.
The digest is stored as manifest_hash.
Release requires approval APPROVED, manifest_hash unchanged, and no line item with an embargoed hs_code.
PATCH /consignments/{ref}/lineitems/{index} {hs_code, justification}
POST /consignments/{ref}/release
"""

OPENAPI_YAML = """openapi: 3.0.0
info: {title: shop, version: '1'}
x-integrity:
  signed_fields: [order_id, customer_id, total]
  algorithm: hmac-sha256
  signature_field: order_signature
  note: checkout verifies order_signature; the unit_price of each item sets the charge.
paths:
  /orders/{id}:
    patch:
      requestBody:
        content:
          application/json:
            schema: {$ref: '#/components/schemas/OrderPatch'}
  /orders/{id}/items/{n}:
    put:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties: {unit_price: {type: number}, gift_wrap: {type: boolean}}
  /orders/{id}/checkout:
    post: {}
components:
  schemas:
    OrderPatch:
      type: object
      properties:
        total: {type: number}
        shipping_note: {type: string}
"""


def _record(hs="8544.42"):
    return {"ref": REF, "origin": "XA", "destination": "XB", "declared_value_eur": 125000,
            "carrier": "Northwind", "lineitems": [
                {"description": "shielded cable", "quantity": 40, "hs_code": hs},
                {"description": "fasteners", "quantity": 900, "hs_code": "7318.15"}],
            "approval": {"status": "APPROVED"}}


def _digest(rec):
    proj = {k: rec[k] for k in ("ref", "origin", "destination", "declared_value_eur", "carrier")}
    proj["lineitems"] = [{"description": li["description"], "quantity": li["quantity"]}
                         for li in rec["lineitems"]]
    return hashlib.sha256(json.dumps(proj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ----------------------------------------------------------------------------------- field paths

@pytest.mark.parametrize("raw, want", [
    ("lineitems[].hs_code", "lineitems[].hs_code"),
    ("$.lineItems[*].hsCode", "line_items[].hs_code"),
    ("lineitems[0].hs_code", "lineitems[].hs_code"),
    ("lineitems.*.hs-code", "lineitems[].hs_code"),
    ("/lineitems/0/hs_code", "lineitems[].hs_code"),
    ("declaredValueEur", "declared_value_eur"),
    ("approval.status", "approval.status"),
])
def test_norm_path_canonicalises_spellings(raw, want):
    assert ib.norm_path(raw) == want


@pytest.mark.parametrize("raw", ["", "   ", "0.hs_code", "a..b", "x" * 300, None, 5])
def test_norm_path_rejects_non_paths(raw):
    assert ib.norm_path(raw) is None


def test_covers_is_segment_prefix_not_substring():
    assert ib.covers("lineitems[].description", "lineitems[].description")
    assert ib.covers("lineitems", "lineitems[].hs_code")       # whole array covered
    assert ib.covers("lineitems[]", "lineitems[].hs_code")
    assert not ib.covers("lineitems[].description", "lineitems[].hs_code")
    assert not ib.covers("line", "lineitems[].hs_code")         # not a substring match
    assert not ib.covers("lineitems[].hs_code", "lineitems")    # a child does not cover its parent
    # a camelCase spec name and a lower-case route segment name the same field
    assert ib.covers(ib.norm_path("lineItems[*].hsCode"), "lineitems[].hs_code")
    assert not ib.covers(ib.norm_path("lineItems[*].hsCode"), "lineitems[].description")


# ----------------------------------------------------------------------------------- routes

@pytest.mark.parametrize("method, path, fields, kind, prefix", [
    ("PATCH", "/consignments/{ref}/lineitems/{index}", ["hs_code"], "write", "lineitems[]"),
    ("PATCH", "/api/v1/consignments/:ref", ["carrier"], "write", ""),
    ("POST", "/consignments/{ref}/release", [], "action", ""),
    ("POST", "/consignments/{ref}/lineitems", ["hs_code"], "write", "lineitems[]"),
    ("PUT", "/users/<id>/profile", ["email"], "write", "profile"),
    ("GET", "/consignments/{ref}", [], "read", ""),
    ("DELETE", "/consignments/{ref}", [], "delete", ""),
])
def test_classify_route(method, path, fields, kind, prefix):
    ep = ib.classify_route(method, path, fields)
    assert (ep.kind, ep.prefix) == (kind, prefix)


# ----------------------------------------------------------------------------------- spec + diff

def _check_9144_shape(report):
    assert report.binding.covered == tuple(ib.norm_path(c) for c in COVERED)
    assert report.binding.binding_field == "manifest_hash"
    paths = [g.path for g in report.gaps]
    assert paths[0] == "lineitems[].hs_code"
    top = report.gaps[0]
    assert top.decision_mentions and "hs_code" in top.decision_mentions[0]
    assert "classification" in top.gate_classes
    assert any("lineitems/{index}" in v for v in top.via)
    # request metadata is set aside, covered writable fields are not gaps
    assert "lineitems[].justification" in report.meta_ignored
    assert "lineitems[].justification" not in paths
    assert set(report.covered_writable) == {"carrier", "declared_value_eur"}
    assert "carrier" not in paths and "declared_value_eur" not in paths
    assert report.action_endpoints == ["POST /consignments/{ref}/release"]


def test_json_spec_finds_the_uncovered_mutable_field():
    doc = ib.parse_spec(json.dumps(SCHEMA), "schema.json")
    assert doc.form == "json"
    assert doc.bindings[0].algorithm == "sha256"
    _check_9144_shape(ib.find_gaps(doc))


def test_text_spec_finds_the_same_gap():
    doc = ib.parse_spec(TEXT_SPEC, "schema.txt")
    assert doc.form == "text"
    assert doc.bindings[0].raw_covered[-1] == "lineitems[].quantity"   # the prose after the list is not read as fields
    report = ib.find_gaps(doc)
    assert report.binding.binding_field == "manifest_hash"
    assert [g.path for g in report.gaps] == ["lineitems[].hs_code"]


def test_openapi_yaml_with_refs():
    doc = ib.parse_spec(OPENAPI_YAML, "openapi.yaml")
    assert doc.form == "yaml"
    b = doc.bindings[0]
    assert b.covered == ("order_id", "customer_id", "total")
    assert b.binding_field == "order_signature" and b.algorithm == "hmac-sha256"
    report = ib.find_gaps(doc)
    by_path = {g.path: g for g in report.gaps}
    # $ref-resolved body field (shipping_note) and the nested route's fields are all found
    assert set(by_path) == {"shipping_note", "items[].unit_price", "items[].gift_wrap"}
    assert "total" in report.covered_writable
    # the field the decision wording names and a price-class field ranks first
    assert report.gaps[0].path == "items[].unit_price"
    assert "price" in by_path["items[].unit_price"].gate_classes
    assert by_path["items[].unit_price"].score > by_path["items[].gift_wrap"].score
    assert "POST /orders/{id}/checkout" in report.action_endpoints


def test_decision_wording_outranks_an_otherwise_equal_gap():
    spec = {"binding": {"signed_fields": ["id"], "signature_field": "sig"},
            "checkout": "checkout charges the stored b_price; the signature must verify",
            "endpoints": [{"method": "PATCH", "path": "/carts/{id}", "body": ["a_price", "b_price"]}]}
    report = ib.find_gaps(ib.parse_spec(json.dumps(spec)))
    assert [g.path for g in report.gaps] == ["b_price", "a_price"]   # not alphabetical: b is named
    assert report.gaps[0].score > report.gaps[1].score


def test_fully_covered_spec_has_no_gap():
    spec = copy.deepcopy(SCHEMA)
    spec["approval"]["covered_fields"] = COVERED + ["lineitems"]
    report = ib.find_gaps(ib.parse_spec(json.dumps(spec)))
    assert report.gaps == []


def test_declared_exclusions_are_gaps_with_reason():
    spec = {"signature": {"signed_fields": ["id", "amount"], "excluded_fields": ["payee_iban"]}}
    report = ib.find_gaps(ib.parse_spec(json.dumps(spec)))
    assert [g.path for g in report.gaps] == ["payee_iban"]
    assert any("does not cover" in r for r in report.gaps[0].reasons)


def test_sample_record_adds_unknown_mutability_candidates_ranked_below_writable():
    spec = copy.deepcopy(SCHEMA)
    report = ib.find_gaps(ib.parse_spec(json.dumps(spec)), sample=_record())
    by_path = {g.path: g for g in report.gaps}
    assert "approval.status" in by_path
    assert by_path["approval.status"].via == ("sample record (mutability unknown)",)
    assert by_path["lineitems[].hs_code"].score > by_path["approval.status"].score
    assert "manifest_hash" not in by_path   # the binding field itself is never a gap


def test_no_binding_reports_reason():
    report = ib.find_gaps(ib.parse_spec('{"endpoints": []}'))
    assert report.binding is None and report.gaps == []
    assert "no covered-field list" in report.notes[0]


def test_ambiguous_json_spec_fails_closed():
    dup = '{"approval": {"covered_fields": ["ref"], "covered_fields": ["ref", "hs_code"]}}'
    with pytest.raises(ib.SpecError):
        ib.parse_spec(dup)
    collide = '{"coveredFields": ["ref"], "covered_fields": ["ref", "hs_code"]}'
    with pytest.raises(ib.SpecError):
        ib.parse_spec(collide)


def test_duplicate_yaml_key_fails_closed():
    with pytest.raises(ib.SpecError, match="duplicate"):
        ib.parse_spec("openapi: 3.0.0\nx:\n  signed_fields: [a]\n  signed_fields: [a, b]\n", "s.yaml")


def test_oversized_spec_refused():
    with pytest.raises(ib.SpecError, match="cap"):
        ib.parse_spec("x" * (ib.MAX_SPEC_CHARS + 1))


# ----------------------------------------------------------------------------------- recompute

def test_recompute_reproduces_digest_over_documented_fields():
    rec = _record()
    rec["manifest_hash"] = _digest(rec)
    b = ib.parse_spec(json.dumps(SCHEMA)).bindings[0]
    rc = ib.recompute_binding(rec, b)
    assert rc["reproduced"] and rc["scheme"] == "sha256/json-sorted-compact"
    # an uncovered field can change without moving the digest...
    moved = copy.deepcopy(rec)
    moved["lineitems"][0]["hs_code"] = "8543.70"
    assert ib.recompute_binding(moved, b)["reproduced"]
    # ...a covered one cannot
    moved["lineitems"][0]["quantity"] = 41
    assert not ib.recompute_binding(moved, b)["reproduced"]


def test_recompute_wrong_covered_set_is_not_reproduced():
    rec = _record()
    rec["manifest_hash"] = _digest(rec)
    b = ib.Binding(("ref", "origin"), ("ref", "origin"), "sha256", "manifest_hash", "test")
    assert not ib.recompute_binding(rec, b)["reproduced"]


def test_recompute_keyed_scheme_says_so():
    rec = _record()
    rec["manifest_hash"] = "ab" * 32
    b = ib.Binding(("ref",), ("ref",), "HMAC-SHA256", "manifest_hash", "test")
    rc = ib.recompute_binding(rec, b)
    assert not rc["reproduced"] and "keyed" in rc["reason"]


def test_get_concrete():
    rec = _record()
    assert ib.get_concrete(rec, "lineitems[0].hs_code") == "8544.42"
    assert ib.get_concrete(rec, "lineItems.1.hsCode") == "7318.15"
    with pytest.raises(KeyError):
        ib.get_concrete(rec, "lineitems[5].hs_code")
    # two keys that name one field are ambiguous: no value is picked
    with pytest.raises(KeyError):
        ib.get_concrete({"lineItems": 1, "line_items": 2}, "line_items")
    # the separator-insensitive match: one candidate is found, two are ambiguous (fail closed, no pick)
    assert ib.get_concrete({"lineItems": 1}, "lineitems") == 1
    with pytest.raises(KeyError):
        ib.get_concrete({"lineItems": 1, "line__items": 2}, "lineitems")
    with pytest.raises(KeyError):
        ib.get_concrete({"line__items": 2, "lineItems": 1}, "lineitems")


# ----------------------------------------------------------------------------------- live probe

def _profile(web_state_changing):
    return _event.parse({
        "slug": "ib-test", "name": "integrity binding test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.ib-platform.test"},
        "flag": {"prefixes": ["SYNTH"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "web_state_changing": bool(web_state_changing),
                  "live_service_scope": ["127.0.0.0/8", "localhost"]},
    }, src="tests/test_web_integrity_binding.py")


@contextlib.contextmanager
def pinned(profile):
    prev = _scope.pinned()
    _scope.pin(profile)
    try:
        yield profile
    finally:
        if prev is not None:
            _scope.pin(prev)
        else:  # pragma: no cover - the suite always pins a profile
            _scope.unpin()


class _App:
    """A synthetic clearance portal. mode: vulnerable | rebind | reopen | reject | error | truncate
    (truncate: once amended, the record GET is padded past the WebClient's body cap, so the client
    hands back a truncated body that still parses as the complete, amended record)."""

    def __init__(self, mode="vulnerable"):
        self.mode = mode
        self.lock = threading.Lock()
        self.hits = []
        self.amended = False
        self.rec = _record()
        self.rec["manifest_hash"] = _digest(self.rec)

    def handle(self, method, path, body):
        with self.lock:
            self.hits.append((method, path))
            if path == "/schema" and method == "GET":
                return 200, json.dumps(SCHEMA)
            if path == f"/consignments/{REF}" and method == "GET":
                if self.mode == "truncate" and self.amended:
                    return 200, json.dumps(self.rec) + " " * (ib._web_toolkit().MAX_BODY + 16)
                return 200, json.dumps(self.rec)
            if path == f"/consignments/{REF}/lineitems/0" and method == "PATCH":
                if self.mode == "reject":
                    return 403, '{"error": "amendment locked after approval"}'
                if self.mode == "error":
                    return 500, "boom"
                data = json.loads(body or "{}")
                self.rec["lineitems"][0]["hs_code"] = data["hs_code"]
                self.amended = True
                if self.mode == "rebind":
                    self.rec["manifest_hash"] = hashlib.sha256(
                        json.dumps(self.rec["lineitems"], sort_keys=True).encode()).hexdigest()
                if self.mode == "reopen":
                    self.rec["approval"]["status"] = "PENDING"
                return 200, '{"ok": true}'
            if path == f"/consignments/{REF}/release" and method == "POST":
                ok = (self.rec["approval"]["status"] == "APPROVED"
                      and self.rec["manifest_hash"] == _digest(self.rec)
                      and not any(li["hs_code"] in EMBARGO for li in self.rec["lineitems"]))
                if ok:
                    return 200, json.dumps({"status": "RELEASED", "certificate": {"clearance_token": FLAG}})
                return 409, '{"error": "hold remains"}'
            return 404, '{"error": "nope"}'


@contextlib.contextmanager
def serving(app):
    class H(BaseHTTPRequestHandler):
        def _go(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            st, payload = app.handle(self.command, self.path, body)
            data = payload.encode()
            self.send_response(st)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            with contextlib.suppress(Exception):
                self.wfile.write(data)

        do_GET = do_POST = do_PATCH = do_PUT = _go

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def _probe(app, profile, **kw):
    with serving(app) as url, pinned(profile):
        client = ib._web_toolkit().WebClient(url)
        args = dict(resource_route=f"/consignments/{REF}", field="lineitems[0].hs_code",
                    value="8543.70", write_route=f"/consignments/{REF}/lineitems/0",
                    binding_field="manifest_hash", status_field="approval.status",
                    body_extra={"justification": "reclassified"},
                    decision_route=f"/consignments/{REF}/release",
                    find_flags=__import__("ctf.flagfmt", fromlist=["x"]).for_profile(profile).find_flags)
        args.update(kw)
        return ib.probe_gap(client, profile, **args)


def test_probe_confirms_gap_and_fires_decision():
    app = _App("vulnerable")
    res = _probe(app, _profile(True))
    assert res.verdict == "gap_confirmed"
    assert res.before["binding"] == res.after["binding"]
    assert res.before["field"] == "8544.42" and res.after["field"] == "8543.70"
    assert res.decision_status == 200 and res.flags == [FLAG]
    assert [m for m, _ in app.hits] == ["GET", "PATCH", "GET", "POST"]


def test_probe_without_decision_route_never_fires_it():
    app = _App("vulnerable")
    res = _probe(app, _profile(True), decision_route=None)
    assert res.verdict == "gap_confirmed" and res.flags == []
    assert ("POST", f"/consignments/{REF}/release") not in app.hits


@pytest.mark.parametrize("mode, verdict", [("rebind", "rebound"), ("reopen", "reopened"),
                                           ("reject", "write_rejected")])
def test_probe_recognises_a_server_that_holds_the_binding(mode, verdict):
    app = _App(mode)
    res = _probe(app, _profile(True))
    assert res.verdict == verdict
    assert res.flags == []
    assert ("POST", f"/consignments/{REF}/release") not in app.hits   # no decision on a closed gap


def test_probe_stops_after_ambiguous_write():
    app = _App("error")
    res = _probe(app, _profile(True))
    assert res.verdict == "ambiguous_mutation"
    assert [m for m, _ in app.hits] == ["GET", "PATCH"]   # no readback, no decision after a 5xx write


def test_probe_refused_without_o2_and_sends_nothing():
    app = _App("vulnerable")
    with pytest.raises(ib.StateChangeRefused, match="web_state_changing"):
        _probe(app, _profile(False))
    assert app.hits == []


def test_probe_reserves_the_whole_group_before_sending():
    app = _App("vulnerable")
    res = _probe(app, _profile(True), max_requests=3)   # decision route needs a 4th
    assert res.verdict == "budget" and app.hits == []


def test_probe_precondition_when_binding_field_absent():
    app = _App("vulnerable")
    res = _probe(app, _profile(True), binding_field="approval_signature")
    assert res.verdict == "precondition"
    assert [m for m, _ in app.hits] == ["GET"]   # nothing written


# ----------------------------------------------------------------------------------- solve()

def test_solve_offline_over_challenge_files(tmp_path):
    (tmp_path / "schema.json").write_text(json.dumps(SCHEMA))
    (tmp_path / "readme.md").write_text("nothing to see")
    r = ib.solve(tmp_path, _profile(False))
    assert r.status == "unsure" and not r.flags
    gaps = [e for e in r.evidence if e.kind == "binding-gap"]
    assert gaps and gaps[0].detail.startswith("lineitems[].hs_code")
    assert "write_route=/consignments/{ref}/lineitems/{index}" in r.notes


def test_solve_offline_with_sample_reports_reproduced_binding(tmp_path):
    rec = _record()
    rec["manifest_hash"] = _digest(rec)
    (tmp_path / "spec.txt").write_text(TEXT_SPEC)
    (tmp_path / "record.json").write_text(json.dumps(rec))
    r = ib.solve(tmp_path, _profile(False), spec="spec.txt", sample="record.json")
    assert any(e.kind == "binding-reproduced" and "sha256/json-sorted-compact" in e.detail for e in r.evidence)


def test_solve_no_spec_is_none(tmp_path):
    (tmp_path / "notes.txt").write_text("hello")
    r = ib.solve(tmp_path, _profile(False))
    assert r.status == "none" and "no binding spec" in r.notes


def test_solve_missing_spec_path_is_blocked(tmp_path):
    r = ib.solve(tmp_path, _profile(False), spec="absent.json")
    assert r.status == "blocked" and "absent.json" in r.notes


def test_solve_ambiguous_spec_is_not_read_last_wins(tmp_path):
    (tmp_path / "schema.json").write_text('{"covered_fields": ["a"], "covered_fields": ["a", "b"]}')
    r = ib.solve(tmp_path, _profile(False))
    assert r.status == "none" and "ambiguous" in r.notes


def test_solve_live_reads_schema_then_probes_to_flag(tmp_path):
    app = _App("vulnerable")
    profile = _profile(True)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource=f"/consignments/{REF}",
                     field="lineitems[0].hs_code", value="8543.70",
                     write_route=f"/consignments/{REF}/lineitems/0", status_field="approval.status",
                     extra='{"justification": "reclassified"}',
                     decision_route=f"/consignments/{REF}/release")
    assert r.status == "solved" and r.flags == (FLAG,)
    assert app.hits[0] == ("GET", "/schema")
    assert any(e.kind == "binding-reproduced" for e in r.evidence)
    assert any(e.kind == "binding-probe" and "gap_confirmed" in e.detail for e in r.evidence)


def test_solve_live_without_o2_reads_but_never_writes(tmp_path):
    app = _App("vulnerable")
    profile = _profile(False)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource=f"/consignments/{REF}",
                     field="lineitems[0].hs_code", value="8543.70",
                     write_route=f"/consignments/{REF}/lineitems/0")
    assert r.status == "blocked" and "web_state_changing" in r.notes
    assert all(m == "GET" for m, _ in app.hits)
    assert app.rec["lineitems"][0]["hs_code"] == "8544.42"


def test_solve_live_analysis_only(tmp_path):
    app = _App("vulnerable")
    profile = _profile(False)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url)
    assert r.status == "unsure"
    assert app.hits == [("GET", "/schema")]


def test_solve_target_out_of_scope_is_blocked(tmp_path):
    with pinned(_profile(True)):
        r = ib.solve(tmp_path, _profile(True), target="http://203.0.113.9:8080")
    assert r.status == "blocked" and "scope" in r.notes.lower()


# ----------------------------------------------------------------------------------- CLI

def test_cli_json(tmp_path, capsys):
    p = tmp_path / "schema.json"
    p.write_text(json.dumps(SCHEMA))
    assert ib.main([str(p), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["gaps"][0]["path"] == "lineitems[].hs_code"


def test_cli_ambiguous_spec_exits_2(tmp_path, capsys):
    p = tmp_path / "schema.json"
    p.write_text('{"covered_fields": ["a"], "covered_fields": ["b"]}')
    assert ib.main([str(p)]) == 2
    assert "error" in capsys.readouterr().err


# ----------------------------------------------------------------------------------- verification round 1

def test_probe_gate_is_the_active_profile_not_the_argument():
    """A caller cannot widen O-2: the pinned (active) profile says false, the argument says true."""
    app = _App("vulnerable")
    with serving(app) as url, pinned(_profile(False)):
        client = ib._web_toolkit().WebClient(url)   # a full client: only the gate stands in the way
        with pytest.raises(ib.StateChangeRefused, match="disagrees with the active event profile"):
            ib.probe_gap(client, _profile(True), resource_route=f"/consignments/{REF}",
                         field="lineitems[0].hs_code", value="8543.70",
                         write_route=f"/consignments/{REF}/lineitems/0", binding_field="manifest_hash")
    assert app.hits == []
    assert app.rec["lineitems"][0]["hs_code"] == "8544.42"


def test_probe_gate_refuses_an_argument_that_disagrees_either_way():
    app = _App("vulnerable")
    with serving(app) as url, pinned(_profile(True)):
        client = ib._web_toolkit().WebClient(url)
        with pytest.raises(ib.StateChangeRefused, match="disagrees"):
            ib.probe_gap(client, _profile(False), resource_route=f"/consignments/{REF}",
                         field="lineitems[0].hs_code", value="8543.70",
                         write_route=f"/consignments/{REF}/lineitems/0", binding_field="manifest_hash")
    assert app.hits == []


def test_probe_gate_fails_closed_without_an_active_profile(monkeypatch):
    def no_profile(*a, **k):
        raise FileNotFoundError("no event.toml")
    monkeypatch.setattr(_event, "current", no_profile)
    prev = _scope.pinned()
    _scope.unpin()
    try:
        allowed, why = ib.o2_gate(_profile(True))
    finally:
        if prev is not None:
            _scope.pin(prev)
    assert allowed is False and "no active event profile (FileNotFoundError)" in why


def test_state_change_refused_is_an_out_of_scope():
    app = _App("vulnerable")
    with pytest.raises(_scope.OutOfScope):          # the tree's `except ctf.scope.OutOfScope` handlers
        _probe(app, _profile(False))
    assert issubclass(ib.StateChangeRefused, ib._web_toolkit().OutOfScope)
    assert app.hits == []


def test_probe_truncated_readback_is_ambiguous():
    app = _App("truncate")
    res = _probe(app, _profile(True))
    assert res.verdict == "ambiguous_mutation" and "readback" in res.notes[-1]
    assert [m for m, _ in app.hits] == ["GET", "PATCH", "GET"]   # no decision on an unreadable readback
    assert res.flags == []


def test_probe_precondition_when_field_already_holds_the_value():
    app = _App("vulnerable")
    res = _probe(app, _profile(True), value="8544.42")
    assert res.verdict == "precondition" and "already holds" in res.notes[-1]
    assert [m for m, _ in app.hits] == ["GET"]   # nothing written


@pytest.mark.parametrize("mode", ["rebind", "reopen", "reject"])
def test_solve_probe_of_a_held_binding_is_none(tmp_path, mode):
    app = _App(mode)
    profile = _profile(True)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource=f"/consignments/{REF}",
                     field="lineitems[0].hs_code", value="8543.70",
                     write_route=f"/consignments/{REF}/lineitems/0", status_field="approval.status",
                     decision_route=f"/consignments/{REF}/release")
    assert r.status == "none" and not r.flags


def test_solve_confirmed_gap_without_decision_is_unsure(tmp_path):
    app = _App("vulnerable")
    profile = _profile(True)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource=f"/consignments/{REF}",
                     field="lineitems[0].hs_code", value="8543.70",
                     write_route=f"/consignments/{REF}/lineitems/0", status_field="approval.status")
    assert r.status == "unsure" and "gap_confirmed" in r.notes


def test_find_spec_files_skips_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "schema.json").write_text(json.dumps(SCHEMA))
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "schema.json").symlink_to(outside / "schema.json")
    assert ib.find_spec_files(chal) == []
    r = ib.solve(chal, _profile(False))
    assert r.status == "none" and "no binding spec" in r.notes
    (chal / "real-schema.json").write_text(json.dumps(SCHEMA))   # a regular file is still found
    assert [p.name for p in ib.find_spec_files(chal)] == ["real-schema.json"]


class _ClientSpy:
    """Records the real scope-locked WebClients solve() builds (the client is not under test)."""

    def __init__(self, monkeypatch):
        mod = ib._web_toolkit()
        real = mod.WebClient
        made = self.made = []

        class Spy(real):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                made.append(self)

        monkeypatch.setattr(mod, "WebClient", Spy)


def test_solve_analysis_only_client_is_get_only(tmp_path, monkeypatch):
    spy = _ClientSpy(monkeypatch)
    app = _App("vulnerable")
    profile = _profile(True)   # even with O-2 true, no probe asked for -> read-only client
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource=f"/consignments/{REF}")
        assert r.status == "unsure"
        assert len(spy.made) == 1 and spy.made[0].get_only is True
        with pytest.raises(_scope.OutOfScope):
            spy.made[0].request("PATCH", f"/consignments/{REF}/lineitems/0", data="{}")
    assert all(m == "GET" for m, _ in app.hits)


def test_solve_probe_without_o2_builds_a_get_only_client(tmp_path, monkeypatch):
    spy = _ClientSpy(monkeypatch)
    app = _App("vulnerable")
    profile = _profile(False)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource=f"/consignments/{REF}",
                     field="lineitems[0].hs_code", value="8543.70",
                     write_route=f"/consignments/{REF}/lineitems/0")
    assert r.status == "blocked"
    assert [c.get_only for c in spy.made] == [True]


def test_solve_probe_with_o2_builds_a_full_client(tmp_path, monkeypatch):
    spy = _ClientSpy(monkeypatch)
    app = _App("vulnerable")
    profile = _profile(True)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource=f"/consignments/{REF}",
                     field="lineitems[0].hs_code", value="8543.70",
                     write_route=f"/consignments/{REF}/lineitems/0")
    assert r.status == "unsure"
    assert [c.get_only for c in spy.made] == [False]


def test_solve_record_read_failure_is_named(tmp_path):
    app = _App("vulnerable")
    profile = _profile(False)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource="http://203.0.113.9:8080/rec")
    assert r.status == "unsure"
    assert "record GET http://203.0.113.9:8080/rec failed (OutOfScope)" in r.notes
    assert not any(e.kind == "binding-reproduced" for e in r.evidence)


def test_solve_record_non_json_answer_is_named(tmp_path):
    app = _App("vulnerable")
    profile = _profile(False)
    with serving(app) as url, pinned(profile):
        r = ib.solve(tmp_path, profile, target=url, resource="/consignments/NOPE")
    assert "record GET /consignments/NOPE answered 404" in r.notes
    assert "recompute:" not in r.notes   # no sample record was used


def test_solve_default_schema_routes_name_each_miss(tmp_path):
    app = _App("vulnerable")
    app.handle = lambda method, path, body: (app.hits.append((method, path)) or (404, "{}"))
    with serving(app) as url, pinned(_profile(False)):
        r = ib.solve(tmp_path, _profile(False), target=url)
    assert r.status == "blocked"
    for route in ib.DEFAULT_SCHEMA_ROUTES:
        assert f"{route}: 404" in r.notes


def test_solve_default_schema_routes_name_the_transport_error(tmp_path):
    import socket
    with socket.socket() as s:      # a loopback port with nothing listening
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    with pinned(_profile(False)):
        r = ib.solve(tmp_path, _profile(False), target=f"http://127.0.0.1:{port}")
    assert r.status == "blocked"
    assert "no spec served at" not in r.notes
    for route in ib.DEFAULT_SCHEMA_ROUTES:
        assert f"{route}: VPNRequired" in r.notes


def _truncating_schema_app():
    """/schema answers 200 with the complete SCHEMA padded past the WebClient body cap: the client
    hands back a truncated body (still valid JSON, so only the truncated flag can reject it)."""
    app = _App("vulnerable")
    real = app.handle

    def handle(method, path, body):
        if path == "/schema" and method == "GET":
            app.hits.append((method, path))
            return 200, json.dumps(SCHEMA) + " " * (ib._web_toolkit().MAX_BODY + 16)
        return real(method, path, body)
    app.handle = handle
    return app


def test_solve_rejects_a_truncated_spec_from_schema_route(tmp_path):
    app = _truncating_schema_app()
    with serving(app) as url, pinned(_profile(False)):
        r = ib.solve(tmp_path, _profile(False), target=url, schema_route="/schema")
    assert r.status == "blocked"
    assert "/schema: 200 truncated" in r.notes
    assert ("GET", "/schema") in app.hits


def test_solve_rejects_a_truncated_spec_from_the_default_routes(tmp_path):
    app = _truncating_schema_app()
    with serving(app) as url, pinned(_profile(False)):
        r = ib.solve(tmp_path, _profile(False), target=url)
    assert r.status == "blocked"
    assert "/schema: 200 truncated" in r.notes
    for route in ib.DEFAULT_SCHEMA_ROUTES[1:]:
        assert f"{route}: 404" in r.notes
