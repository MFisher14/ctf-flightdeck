#!/usr/bin/env python3
"""Local regression for the live mass-assignment / BOLA / OpenAPI privesc probe (B-020).

The only "network" is an in-process stateful fake target that duck-types the
scope-locked web.WebClient. Each assertion proves a real before/after effect, so
a detector that fires on the mere fact a field was sent (rather than on an
observed escalation) fails: the SAFE servers below strip the injected authority
and the probe must then report no confirmed escalation.
"""

import json
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "web"))
import privesc_probe as pp  # noqa: E402


OPENAPI = {
    "openapi": "3.0.0",
    "components": {"schemas": {"Account": {
        "type": "object",
        "properties": {
            "display_name": {"type": "string"},
            "role": {"type": "string", "readOnly": True},
        },
    }}},
    "paths": {
        "/api/account": {"patch": {"requestBody": {"content": {
            "application/json": {"schema": {"$ref": "#/components/schemas/Account"}}}}}},
        "/api/me": {"get": {"operationId": "whoami"}},
        "/api/admin/export": {"get": {"operationId": "export"}},
        "/api/orders/{id}": {"get": {"operationId": "readOrder", "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}]}},
    },
}

FLAG = "CSCTF{mass_assign_to_admin_export}"
BOLA_FLAG = "CSCTF{bola_cross_tenant_order}"


class FakeTarget:
    """A stateful fake web app. One instance == one authenticated session.

    ``mass_assign`` True: PATCH /api/account honours a client-sent ``role`` (the bug).
    ``bola`` True: GET /api/orders/{id} returns any order regardless of owner (the bug).
    Both False: the app strips the authority field / denies cross-owner reads (safe).
    """

    base = "https://target.test/"

    def __init__(self, *, mass_assign=False, bola=False, require_login=True,
                 reflect_benign=False, neighbour_flag=True, neighbour_owner="victim"):
        self.mass_assign = mass_assign
        self.bola = bola
        self.require_login = require_login
        # reflect_benign: PATCH changes a tracked identity field (tier) but only to
        # another *non-privileged* value -- a changed-but-safe identity.
        self.reflect_benign = reflect_benign
        self.authed = not require_login
        self.role = "user"
        self.tier = "free"
        self.user_id = 1001
        self.seen = []
        # Orders keyed by id; each belongs to an owner. neighbour_flag / neighbour_owner
        # shape order 1002 (the first sibling id probed from 1001) so the owner-mismatch
        # gate can be exercised on its own, with and without a flag present.
        order_1002 = {"id": 1002, "owner": neighbour_owner, "item": "contract"}
        if neighbour_flag:
            order_1002["note"] = BOLA_FLAG
        self.orders = {
            "1001": {"id": 1001, "owner": "user", "item": "pens"},
            "1002": order_1002,
            "1000": {"id": 1000, "owner": "victim", "item": "ledger"},
        }

    def _resp(self, status, obj=None, raw=None):
        if raw is not None:
            body = raw if isinstance(raw, bytes) else raw.encode()
        else:
            body = json.dumps(obj).encode() if obj is not None else b""
        return {"status": status, "body": body,
                "response_headers": {"Content-Type": "application/json"}}

    def request(self, method, path, data=None, headers=None, allow_redirects=True):
        self.seen.append((method, path))
        assert path.startswith("/") and not path.startswith("//")
        method = method.upper()

        if path == "/login" and method == "POST":
            self.authed = True
            return self._resp(200, {"ok": True})

        if self.require_login and not self.authed:
            return self._resp(401, {"error": "login required"})

        if path == "/openapi.json" and method == "GET":
            return self._resp(200, OPENAPI)
        if path == "/schema" and method == "GET":
            return self._resp(404, {"error": "nope"})

        if path == "/api/me" and method == "GET":
            return self._resp(200, {"id": self.user_id, "role": self.role, "tier": self.tier})

        if path == "/api/account" and method == "PATCH":
            body = json.loads(data) if data else {}
            if self.mass_assign and isinstance(body.get("role"), str):
                self.role = body["role"]
            if self.reflect_benign:
                # The request mutated something, and identity visibly changed -- but
                # only to another ordinary tier, never to a privileged value.
                self.tier = "pro"
            return self._resp(200, {"id": self.user_id, "role": self.role})

        if path == "/api/admin/export" and method == "GET":
            if self.role in ("admin", "administrator"):
                return self._resp(200, {"records": 3, "secret": FLAG})
            return self._resp(403, {"error": "forbidden"})

        if path.startswith("/api/orders/") and method == "GET":
            oid = path.rsplit("/", 1)[-1]
            order = self.orders.get(oid)
            if order is None:
                return self._resp(404, {"error": "no order"})
            if not self.bola and order["owner"] != "user":
                return self._resp(403, {"error": "not your order"})
            return self._resp(200, order)

        return self._resp(404, {"error": "not found"})


def _ctx(client):
    return {
        "client": client,
        "login": {"path": "/login", "method": "POST", "data": {"u": "a", "p": "b"}},
        "identity": {"path": "/api/me", "role_field": "role", "owner_field": "owner"},
        "own_ids": {"/api/orders/{id}": 1001},
        "max_requests": 60,
        "deadline": time.time() + 15,
    }


# -- schema ingestion -------------------------------------------------------------------

def test_extract_operations_resolves_refs_and_marks_mutating():
    ops = pp.extract_operations(json.dumps(OPENAPI).encode())
    by_key = {(o["method"], o["path"]): o for o in ops}
    assert ("PATCH", "/api/account") in by_key and ("GET", "/api/orders/{id}") in by_key
    account = by_key[("PATCH", "/api/account")]
    assert account["mutating"] is True
    # display_name is writable; role is readOnly and dropped from writable fields.
    assert account["body_fields"] == ["display_name"]
    assert by_key[("GET", "/api/orders/{id}")]["path_params"] == ["id"]


def test_extract_operations_ignores_non_json_and_external_refs():
    assert pp.extract_operations(b"not json at all") == []
    spec = {"paths": {"/x": {"post": {"requestBody": {"content": {"application/json": {
        "schema": {"$ref": "https://evil.test/remote#/X"}}}}}}}}
    ops = pp.extract_operations(json.dumps(spec).encode())
    assert ops and ops[0]["body_fields"] == []  # external ref never fetched


# -- mass assignment --------------------------------------------------------------------

def test_mass_assignment_confirmed_unlocks_admin_export_and_flag():
    target = FakeTarget(mass_assign=True, bola=False)
    result = pp.probe(target.base, _ctx(target))

    assert result["login"]["ok"] is True
    assert result["baseline"]["identity"]["role"] == "user"
    assert result["baseline"]["privileged_access"]["/api/admin/export"] == 403

    escs = result["escalations"]
    assert any(e["family"] == "mass-assignment" and e["confirmed"] for e in escs)
    massrow = next(e for e in escs if e["family"] == "mass-assignment")
    ev = " ".join(massrow["evidence"])
    assert "PATCH /api/account" in ev
    assert "role=" in ev and "admin" in ev
    assert "/api/admin/export: 403 -> 200" in ev
    # The flag the export unlocked is recovered (returned, never auto-submitted).
    assert result["flag"] == FLAG and FLAG in result["flags"]


def test_mass_assignment_safe_server_reports_no_confirmed_escalation():
    target = FakeTarget(mass_assign=False, bola=False)
    result = pp.probe(target.base, _ctx(target))

    # The field was injected, but the server stripped it: nothing escalated.
    assert result["baseline"]["identity"]["role"] == "user"
    assert all(not e["confirmed"] or e["family"] != "mass-assignment"
               for e in result["escalations"])
    assert not any(e["confirmed"] and e["family"] == "mass-assignment"
                   for e in result["findings"])
    assert result["flag"] is None
    # The identity was re-read and still shows the ordinary role.
    assert target.role == "user"


def test_mass_assignment_benign_identity_change_is_not_confirmed():
    # The mutating PATCH causes a tracked identity field (tier) to *change*, but
    # only from one non-privileged value to another (free -> pro). The escalation
    # gate must require an actually-escalated before/after, so a detector that
    # confirms on any identity diff is wrong: no mass-assignment may be confirmed.
    target = FakeTarget(mass_assign=False, bola=False, reflect_benign=True)
    result = pp.probe(target.base, _ctx(target))

    # The identity genuinely moved, so this is not the "field stripped" path.
    assert result["baseline"]["identity"]["tier"] == "free"
    assert target.tier == "pro"
    # ... but the change was benign, so nothing is confirmed.
    assert not any(e["confirmed"] and e["family"] == "mass-assignment"
                   for e in result["escalations"])
    assert not any(e["confirmed"] and e["family"] == "mass-assignment"
                   for e in result["findings"])
    assert result["flag"] is None


# -- BOLA / IDOR ------------------------------------------------------------------------

def test_bola_confirmed_reads_neighbour_owners_object():
    target = FakeTarget(mass_assign=False, bola=True)
    result = pp.probe(target.base, _ctx(target))

    bola = [e for e in result["escalations"] if e["family"] == "BOLA"]
    assert bola and bola[0]["confirmed"]
    ev = " ".join(bola[0]["evidence"])
    assert "/api/orders/1001" in ev and ("1002" in ev or "1000" in ev)
    assert "owner='victim'" in ev
    # The cross-tenant order carried a flag; it is recovered.
    assert BOLA_FLAG in result["flags"]


def test_bola_safe_server_denies_cross_owner_and_reports_nothing():
    target = FakeTarget(mass_assign=False, bola=False)
    result = pp.probe(target.base, _ctx(target))
    assert not any(e["family"] == "BOLA" for e in result["escalations"])
    assert BOLA_FLAG not in result["flags"]


def test_bola_cross_owner_without_flag_is_flagged_by_owner_mismatch():
    # The cross-owner neighbour returns 2xx but carries NO flag: the only signal is
    # owner(own) != owner(neighbour). BOLA must still be confirmed -- a detector that
    # relies on a flag, or that treats same/cross owner alike, is wrong.
    target = FakeTarget(mass_assign=False, bola=True, neighbour_flag=False)
    result = pp.probe(target.base, _ctx(target))

    bola = [e for e in result["escalations"] if e["family"] == "BOLA"]
    assert bola and bola[0]["confirmed"]
    ev = " ".join(bola[0]["evidence"])
    assert "owner='user'" in ev and "owner='victim'" in ev
    # No flag existed anywhere; detection came from the owner mismatch alone.
    assert BOLA_FLAG not in result["flags"]


def test_bola_same_owner_neighbour_is_not_flagged():
    # The sibling id probed from our own object is readable (2xx) but belongs to the
    # same owner: that is our own second object, not a BOLA. The owner-match gate must
    # suppress it, so a detector that fires on any readable neighbour is wrong.
    target = FakeTarget(mass_assign=False, bola=False,
                        neighbour_flag=False, neighbour_owner="user")
    result = pp.probe(target.base, _ctx(target))

    assert not any(e["family"] == "BOLA" for e in result["escalations"])
    assert BOLA_FLAG not in result["flags"]


def test_bola_same_owner_neighbour_with_flag_is_flagged():
    # The sibling id probed from our own object belongs to the SAME owner (not a
    # cross-owner leak), but its body carries a flag -- a same-owner object that
    # nonetheless exposes secret material is still a BOLA finding. cross_owner is
    # False here, so the flag-in-body branch is the only deciding signal: a probe
    # that drops it (relying on owner mismatch alone) raises no finding and fails.
    target = FakeTarget(mass_assign=False, bola=False,
                        neighbour_flag=True, neighbour_owner="user")
    result = pp.probe(target.base, _ctx(target))

    bola = [e for e in result["escalations"] if e["family"] == "BOLA"]
    assert bola and bola[0]["confirmed"]
    ev = " ".join(bola[0]["evidence"])
    # Both own and neighbour are owner 'user': the mismatch gate did NOT fire; the
    # flag carried in the neighbour body is what raised the finding.
    assert ev.count("owner='user'") == 2


def test_bola_uuid_neighbours_degrade_loudly_when_helper_raises(monkeypatch):
    # The uuid1 sibling-reference helper IS importable but raises at call time
    # (e.g. a missing corpus). That failure must surface as a named reason in
    # result["errors"], never be swallowed into a silently empty neighbour list.
    class BoomRefs:
        def uuid1_neighborhood(self, *args, **kwargs):
            raise RuntimeError("corpus missing")

    monkeypatch.setattr(pp, "_object_refs", BoomRefs())
    own_uuid = "22222222-2222-2222-2222-222222222222"

    class DocTarget(FakeTarget):
        def request(self, method, path, data=None, headers=None, allow_redirects=True):
            if path.startswith("/api/docs/") and method == "GET":
                self.seen.append((method, path))
                if self.require_login and not self.authed:
                    return self._resp(401, {"error": "login required"})
                did = path.rsplit("/", 1)[-1]
                if did == own_uuid:
                    return self._resp(200, {"id": did, "owner": "user"})
                return self._resp(404, {"error": "no doc"})
            return super().request(method, path, data, headers, allow_redirects)

    target = DocTarget(mass_assign=False, bola=False)
    ctx = _ctx(target)
    ctx["object_routes"] = [{"path": "/api/docs/{uuid}", "method": "GET"}]
    ctx["own_ids"] = {"/api/docs/{uuid}": own_uuid}
    result = pp.probe(target.base, ctx)

    assert any("object_refs failed" in e for e in result["errors"])


def test_bola_uuid_neighbours_degrade_loudly_without_object_refs(monkeypatch):
    # When the own object id is a uuid and the sibling-reference helper is absent,
    # the BOLA phase cannot enumerate neighbours. That degradation must be named in
    # result["errors"], never a silent empty neighbour list.
    monkeypatch.setattr(pp, "_object_refs", None)
    own_uuid = "11111111-1111-1111-1111-111111111111"

    class DocTarget(FakeTarget):
        def request(self, method, path, data=None, headers=None, allow_redirects=True):
            if path.startswith("/api/docs/") and method == "GET":
                self.seen.append((method, path))
                if self.require_login and not self.authed:
                    return self._resp(401, {"error": "login required"})
                did = path.rsplit("/", 1)[-1]
                if did == own_uuid:
                    return self._resp(200, {"id": did, "owner": "user"})
                return self._resp(404, {"error": "no doc"})
            return super().request(method, path, data, headers, allow_redirects)

    target = DocTarget(mass_assign=False, bola=False)
    ctx = _ctx(target)
    ctx["object_routes"] = [{"path": "/api/docs/{uuid}", "method": "GET"}]
    ctx["own_ids"] = {"/api/docs/{uuid}": own_uuid}
    result = pp.probe(target.base, ctx)

    assert any("object_refs unavailable" in e for e in result["errors"])


# -- contract / safety ------------------------------------------------------------------

def test_scope_mismatch_client_is_inert():
    class OtherOrigin(FakeTarget):
        base = "https://elsewhere.test/"

    result = pp.probe("https://target.test/", {"client": OtherOrigin(), "max_requests": 5})
    assert result["stopped"] == "client_scope_mismatch"
    assert result["requests"] == 0 and result["escalations"] == []


def test_request_budget_is_honoured():
    target = FakeTarget(mass_assign=True, bola=True)
    ctx = _ctx(target)
    ctx["max_requests"] = 3
    result = pp.probe(target.base, ctx)
    assert result["requests"] <= 3
    assert result["stopped"] == "max_requests"


def test_bad_target_raises():
    with pytest.raises(pp.PrivescProbeError):
        pp.probe(123)
    with pytest.raises(pp.PrivescProbeError):
        pp.probe({"no": "url"})


def test_no_client_when_webclient_cannot_build(monkeypatch):
    # With no injected client and the scope guard refusing an out-of-scope host,
    # the probe degrades loudly (no_client*) rather than opening a socket.
    result = pp.probe("https://public.example.com/", {"max_requests": 2})
    assert result["stopped"] and result["stopped"].startswith("no_client")
    assert result["flag"] is None and result["escalations"] == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
