"""B-124: `ctf invariant` (ctf/cli/invariant.py) -- check / plan / run a stated invariant.

Runs through `ctf.cli.main`.  `check` and `plan` are offline (JSON files in a temp folder).  `run`
drives the synthetic shop from tests/test_invariant_harness.py through the CLI's client-factory seam,
under a synthetic event profile; the refusals (O-2 off, URL outside the live-service scope) are proven
to build no client at all.  Nothing leaves the process.
"""
from __future__ import annotations

import json

import pytest

import ctf.cli as cli
from ctf import scope as _scope
from ctf.cli import invariant as inv_cli

import test_invariant_harness as T


def _write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


INVARIANTS = [{"id": "once", "path": "cart.coupons", "measure": "len", "op": "<=", "value": 1}]


@pytest.mark.parametrize("after,code,verdict", [
    ({"cart": {"coupons": ["A"]}}, 0, "holds"),
    ({"cart": {"coupons": ["A", "A"]}}, 1, "violated"),
    ({"cart": {}}, 2, "unevaluable"),
])
def test_check_exit_code_follows_the_verdict(tmp_path, capsys, after, code, verdict):
    spec = _write(tmp_path, "spec.json", {"name": "once", "invariants": INVARIANTS})
    before = _write(tmp_path, "before.json", {"cart": {"coupons": []}})
    after_p = _write(tmp_path, "after.json", after)
    rc = cli.main(["invariant", "--json", "check", "--spec", spec, "--before", before, "--after", after_p])
    assert rc == code
    assert json.loads(capsys.readouterr().out)["verdict"] == verdict


def test_check_accepts_a_bare_invariant_list_and_scales_by_accepted(tmp_path, capsys):
    spec = _write(tmp_path, "spec.json", [{"id": "stock", "kind": "delta", "path": "s.n", "op": "==",
                                           "value": -1, "per": "accepted"}])
    before = _write(tmp_path, "b.json", {"s": {"n": 10}})
    after = _write(tmp_path, "a.json", {"s": {"n": 9}})
    assert cli.main(["invariant", "check", "--spec", spec, "--before", before, "--after", after,
                     "--accepted", "2"]) == 1
    assert "stock: violated" in capsys.readouterr().out
    assert cli.main(["invariant", "check", "--spec", spec, "--before", before, "--after", after,
                     "--accepted", "1"]) == 0


def test_check_bad_spec_or_file_is_a_named_error(tmp_path, capsys):
    spec = _write(tmp_path, "spec.json", [{"id": "x", "path": "s.v", "op": "<", "value": "3"}])
    snap = _write(tmp_path, "s.json", {})
    assert cli.main(["invariant", "check", "--spec", spec, "--before", snap, "--after", snap]) == 2
    assert "numeric value" in capsys.readouterr().err
    assert cli.main(["invariant", "check", "--spec", str(tmp_path / "missing.json"),
                     "--before", snap, "--after", snap]) == 2
    assert "cannot read spec" in capsys.readouterr().err


def test_plan_prints_the_ladder_without_headers(tmp_path, capsys):
    spec = _write(tmp_path, "spec.json", T.spec(ladder={"sequential_max": 2, "burst_width": 3}))
    assert cli.main(["invariant", "--json", "plan", "--spec", spec, "--url", T.BASE]) == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert [r["rung"] for r in payload["ladder"]] == ["baseline", "sequential-1", "sequential-2", "burst-3"]
    assert payload["reserved_total"] == 2 + 4 + 6 + 8
    assert payload["reverse"] == {"method": "DELETE", "route": "/api/cart/coupon"}
    assert T.SECRET not in out


def test_plan_refuses_an_unsafe_spec(tmp_path, capsys):
    spec = _write(tmp_path, "spec.json", T.spec(transition={"method": "POST", "route": "/api/user/logout"}))
    assert cli.main(["invariant", "plan", "--spec", spec, "--url", T.BASE]) == 2
    assert "never drives" in capsys.readouterr().err


def _wire(monkeypatch, *, web_state_changing, shop):
    built = []
    profile = T._profile(web_state_changing)
    monkeypatch.setattr(inv_cli, "_profile", lambda args: profile)

    def factory_for(prof):
        make = T.factory(shop)
        built.append(make)
        return make
    monkeypatch.setattr(inv_cli, "build_client_factory", factory_for)
    return built


def test_run_refuses_when_the_event_forbids_state_changes(tmp_path, capsys, monkeypatch):
    shop = T.Shop("double")
    built = _wire(monkeypatch, web_state_changing=False, shop=shop)
    spec = _write(tmp_path, "spec.json", T.spec())
    assert cli.main(["invariant", "run", "--spec", spec, "--url", T.BASE]) == inv_cli.REFUSED_EXIT
    assert "web_state_changing" in capsys.readouterr().err
    assert built == [] and shop.log == []


def test_run_refuses_a_url_outside_the_live_service_scope(tmp_path, capsys, monkeypatch):
    shop = T.Shop("double")
    built = _wire(monkeypatch, web_state_changing=True, shop=shop)
    spec = _write(tmp_path, "spec.json", T.spec())
    rc = cli.main(["invariant", "run", "--spec", spec, "--url", "http://203.0.113.9.nip.io/"])
    assert rc == inv_cli.REFUSED_EXIT and "outside" in capsys.readouterr().err
    assert built == [] and shop.log == []


def test_run_reports_the_violation_and_restores_the_pin(tmp_path, capsys, monkeypatch):
    shop = T.Shop("double")
    _wire(monkeypatch, web_state_changing=True, shop=shop)
    before_pin = _scope.pinned()
    spec = _write(tmp_path, "spec.json", T.spec())
    rc = cli.main(["invariant", "--json", "run", "--spec", spec, "--url", T.BASE])
    report = json.loads(capsys.readouterr().out)
    assert rc == 1 and report["verdict"] == "violated"
    assert report["violation"]["rung"] == "sequential-2" and shop.coupons == []
    assert _scope.pinned() is before_pin


def test_run_exit_codes_for_holds_and_inconclusive(tmp_path, capsys, monkeypatch):
    shop = T.Shop("correct")
    _wire(monkeypatch, web_state_changing=True, shop=shop)
    spec = _write(tmp_path, "spec.json", T.spec())
    assert cli.main(["invariant", "run", "--spec", spec, "--url", T.BASE]) == 0
    assert "holds" in capsys.readouterr().out
    shop = T.Shop("double", start_coupons=2)          # baseline already false: stops, nothing sent
    _wire(monkeypatch, web_state_changing=True, shop=shop)
    assert cli.main(["invariant", "run", "--spec", spec, "--url", T.BASE]) == inv_cli.INCONCLUSIVE_EXIT
    assert shop.mutations() == []


def test_real_client_factory_builds_a_scope_locked_state_changing_client():
    make = inv_cli.build_client_factory(None)
    client = make(T.BASE, 3.0)
    assert client.get_only is False and client.base.startswith("http://shop.test")
    with pytest.raises(_scope.OutOfScope):
        make("http://203.0.113.9.nip.io/", 3.0)
