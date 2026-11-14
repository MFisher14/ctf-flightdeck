#!/usr/bin/env python3
"""Offline tests for the B-021 parser-differential / vhost / NFKC engine.

No network, no live service, no event pin: the engine is plan-only and its
inputs are inert synthetic strings and files built inside each test.
"""
from __future__ import annotations

import json
import sys
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "solvers" / "web"))

import parser_differential as P  # noqa: E402
from ctf.result import SolverResult  # noqa: E402


# --- NFKC / casefold aliases ---------------------------------------------

def test_fold_collapses_nfkc_and_case():
    assert P.fold("K.Vostra") == P.fold("k.vostra")
    # the feminine ordinal U+00AA folds to 'a'
    assert P.fold("k.vostrª") == P.fold("k.vostra")


def test_nfkc_aliases_satisfy_the_bypass_invariant():
    target = "k.vostra"
    aliases = P.nfkc_casefold_aliases(target, limit=20)
    assert aliases, "expected at least one alias"
    for a in aliases:
        # same identity after a full fold...
        assert P.fold(a) == P.fold(target)
        # ...but a plain-casefold distinctness check reads it as different
        assert a.casefold() != target.casefold()
        assert a != target


def test_nfkc_aliases_reach_the_feminine_ordinal_confusable():
    # with enough room the 'a' -> U+00AA substitution must appear
    aliases = P.nfkc_casefold_aliases("k.vostra", limit=500, max_subs=1)
    assert "k.vostrª" in aliases


def test_nfkc_aliases_reject_pure_case_variants():
    # a mere case change is caught by casefold already, so it is not a bypass
    aliases = P.nfkc_casefold_aliases("admin", limit=200, max_subs=2)
    assert "ADMIN" not in aliases
    assert "Admin" not in aliases


def test_nfkc_aliases_deterministic():
    a = P.nfkc_casefold_aliases("root", limit=10)
    b = P.nfkc_casefold_aliases("root", limit=10)
    assert a == b


def test_nfkc_aliases_rejects_bad_input():
    with pytest.raises(ValueError):
        P.nfkc_casefold_aliases("")


# --- URL parser differentials --------------------------------------------

def test_url_backslash_authority_differential():
    out = P.url_parser_differentials("sg-kr.grid.test", target="example.invalid", path="/dispatch")
    mechs = {x["mechanism"]: x["payload"] for x in out}
    assert "backslash-authority" in mechs
    assert mechs["backslash-authority"] == "http://sg-kr.grid.test\\@example.invalid/dispatch"
    assert "userinfo-at" in mechs and "fragment-at" in mechs


def test_url_without_target_still_gives_host_equivalence():
    out = P.url_parser_differentials("allowed.test")
    mechs = {x["mechanism"] for x in out}
    assert "trailing-dot-host" in mechs and "host-case" in mechs
    # cross-host mechanisms need a target and must be absent
    assert "backslash-authority" not in mechs


def test_url_requires_allowed_host():
    with pytest.raises(ValueError):
        P.url_parser_differentials("")


def test_path_normalization_includes_dot_segment():
    out = P.path_normalization_variants("/ops")
    payloads = {x["payload"] for x in out}
    assert "/./ops" in payloads
    assert "//ops" in payloads
    assert any(x["mechanism"] == "encoded-dot-segment" for x in out)


# --- dual-key / case-variant JSON ----------------------------------------

def test_dual_key_json_preserves_duplicates_that_json_dumps_drops():
    raw = P.dual_key_json([("courier", "a"), ("Courier", "b"), ("courier", "c")])
    # the raw text keeps every pair, in order
    assert raw.count('"courier"') == 2 and '"Courier"' in raw
    # proof this is not reproducible with json.dumps on a dict
    assert json.dumps({"courier": "a", "Courier": "b"}).count('"courier"') == 1


def test_case_variant_body_builds_the_vesper_quay_shape():
    raw = P.case_variant_body(
        {"courier": "c-615d02", "argv": ["-c", "CODE"]},
        {"courier": "c-f7dd2a", "argv": []},
        shadow_case="title",
    )
    assert '"courier":"c-615d02"' in raw
    assert '"Courier":"c-f7dd2a"' in raw
    assert '"Argv":[]' in raw
    # it is valid JSON a case-sensitive parser can load
    parsed = json.loads(raw)
    assert parsed["courier"] == "c-615d02" and parsed["Courier"] == "c-f7dd2a"


def test_dual_key_json_refuses_sort_keys():
    with pytest.raises(ValueError):
        P.dual_key_json([("a", 1)], sort_keys=True)


# --- static duplicate-case-key detector ----------------------------------

def test_detect_case_variant_keys():
    out = P.detect_duplicate_case_keys('{"courier":"a","Courier":"b","argv":[1],"Argv":[]}')
    kinds = {tuple(sorted(f["keys"])): f["kind"] for f in out}
    assert kinds[("Courier", "courier")] == "case-variant"
    assert kinds[("Argv", "argv")] == "case-variant"


def test_detect_exact_duplicate_keys():
    out = P.detect_duplicate_case_keys('{"a":1,"a":2}')
    assert len(out) == 1 and out[0]["kind"] == "exact-duplicate"


def test_detect_nested_and_pointer():
    out = P.detect_duplicate_case_keys('{"outer":{"Key":1,"key":2}}')
    assert len(out) == 1
    assert out[0]["path"] == "/outer" and out[0]["kind"] == "case-variant"


def test_detect_clean_json_has_no_findings():
    # guards against a detector that fires on everything
    assert P.detect_duplicate_case_keys('{"a":1,"b":2,"c":{"d":3}}') == []


def test_detect_non_json_raises():
    with pytest.raises(ValueError):
        P.detect_duplicate_case_keys("not json at all")


# --- base64 vhost discovery ----------------------------------------------

def test_base64_internal_host_decoded():
    js = "const h = atob('ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA=='); connect(h);"
    out = P.base64_internal_hosts(js)
    assert out and out[0]["decoded"] == "exch-ctl.vjod.internal"
    assert out[0]["looks_internal"] is True


def test_base64_ignores_non_host_blobs():
    # a base64 blob that decodes to non-host bytes must not be reported
    import base64 as _b64
    blob = _b64.b64encode(b"\x00\x01\x02 just some binary payload here").decode()
    assert P.base64_internal_hosts(f"x = '{blob}'") == []


def test_base64_ignores_plain_identifiers():
    assert P.base64_internal_hosts("someLongCamelCaseIdentifierHere = 1") == []


def test_vhost_header_variants():
    out = P.vhost_header_variants("exch-ctl.vjod.internal")
    headers = {v.get("header") for v in out}
    assert "Host" in headers and "X-Forwarded-Host" in headers
    assert any("absolute-form" == v["mechanism"] for v in out)


def test_vhost_requires_host():
    with pytest.raises(ValueError):
        P.vhost_header_variants("")


def test_openapi_case_collisions():
    doc = '{"Courier":{"type":"string"},"paths":{"properties":{"courier":1}}}'
    out = P.openapi_case_collisions(doc)
    assert out and out[0]["variants"] == ["Courier", "courier"]


# --- the solve() contract engine -----------------------------------------

def _write(d: Path, name: str, text: str) -> None:
    p = d / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_solve_fires_on_artifacts(tmp_path):
    _write(tmp_path, "seq5.json", '{"courier":"a","Courier":"b","argv":["-c","x"],"Argv":[]}')
    _write(tmp_path, "static/switchboard.js",
           "var h = atob('ZXhjaC1jdGwudmpvZC5pbnRlcm5hbA=='); go(h);")
    res = P.solve(tmp_path, None)
    assert isinstance(res, SolverResult)
    assert res.status == "unsure"
    assert res.flags == ()  # plan-only: never a flag
    catalog = json.loads(res.notes)
    assert "duplicate_case_keys" in catalog["detectors"]
    assert "base64_hosts" in catalog["detectors"]
    assert catalog["payloads"]["vhost"]  # vhost probes generated from the decoded host
    kinds = {e.kind for e in res.evidence}
    assert "match" in kinds and "decode" in kinds


def test_solve_none_on_empty_dir(tmp_path):
    res = P.solve(tmp_path, None)
    assert res.status == "none" and res.flags == ()


def test_solve_blocked_on_missing_dir(tmp_path):
    res = P.solve(tmp_path / "does-not-exist", None)
    assert res.status == "blocked"
    assert "not found" in res.notes or "directory" in res.notes


def test_solve_opt_driven_generation(tmp_path):
    res = P.solve(
        tmp_path, None,
        target="k.vostra",
        allowed_host="sg-kr.grid.test",
        internal_host="example.invalid",
        restricted_path="/dispatch",
        dual_primary={"courier": "a"},
        dual_shadow={"courier": "b"},
    )
    assert res.status == "unsure"
    cat = json.loads(res.notes)["payloads"]
    assert cat["nfkc_aliases"]
    assert any(x["mechanism"] == "backslash-authority" for x in cat["url_differentials"])
    assert cat["path_variants"]
    assert '"Courier":"b"' in cat["dual_key_body"]


def test_solve_skips_ctf_and_dotfiles(tmp_path):
    # artifacts under a .ctf directory must never be read (secrets rule)
    _write(tmp_path, ".ctf/secret.json", '{"a":1,"A":2}')
    res = P.solve(tmp_path, None)
    assert res.status == "none"


def test_solve_result_round_trips(tmp_path):
    _write(tmp_path, "a.json", '{"k":1,"K":2}')
    res = P.solve(tmp_path, None)
    assert SolverResult.from_json(res.to_json()) == res


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
