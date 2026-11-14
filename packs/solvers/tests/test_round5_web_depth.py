from __future__ import annotations

import json
import random
import string
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


WEB = Path(__file__).resolve().parents[1] / "solvers" / "web"
sys.path.insert(0, str(WEB))
import ssti_helper as S  # noqa: E402
import web_attack_depth as W  # noqa: E402
import authflow_exploit as A  # noqa: E402
import exploit_classes as E  # noqa: E402
import http_desync as H  # noqa: E402
import ssrf_chains as R  # noqa: E402
import upload_builder as U  # noqa: E402
from ctf import triage as T  # noqa: E402


def test_ssti_additional_engines_require_wrapped_evaluation():
    probes = {row["name"]: row for row in S.fingerprint_probes()}
    assert {"smarty_math", "handlebars_block", "pug_interpolation"} <= probes.keys()
    response = " / ".join([
        probes["smarty_math"]["expected"]["smarty"],
        probes["handlebars_block"]["expected"]["handlebars"],
        probes["pug_interpolation"]["expected"]["pug"],
    ])
    detected = S.detect_response(response)
    assert {row["engine"] for row in detected} == {"smarty", "handlebars", "pug"}
    # Raw/reflected probes and an unwrapped arithmetic value are not proof.
    reflected = " ".join(probes[name]["payload"] for name in probes) + " 49 HB_OK"
    assert S.detect_response(reflected) == []
    assert S.detect_response("Missing helper: 'foo'") == []


def test_surveyed_existing_depth_matrix_remains_output_only():
    desync = H.generate_desync_candidates("app.example")
    assert {row["technique"] for row in desync} >= {
        "CL.TE", "TE.CL", "TE.TE", "CL.0", "H2.CL", "H2.TE",
    }
    cache = H.cache_candidates("app.example")
    assert cache["poisoning"] and cache["deception"]
    assert all(row["network_requests"] == 0 for row in cache["poisoning"] + cache["deception"])
    assert E.nosql_payloads() and E.xxe_payloads() and E.imds_probes("aws")
    assert R.url_parser_confusion_candidates("http://127.0.0.1/admin")
    assert all(row["offline"] for row in U.generate_candidates(max_candidates=12))
    assert A.credentialed_cors_candidates("https://app.example/api")
    assert A.cswsh_candidates("wss://app.example/ws")


def test_ssti_payloads_are_context_labelled_and_escape_input():
    smarty = S.build_payloads("smarty", read_file="/tmp/a'b")
    assert smarty[0]["engine"] == "smarty" and "\\'" in smarty[0]["payload"]
    handlebars = S.build_payloads("handlebars", command='echo "x"')
    assert handlebars[0]["engine"] == "handlebars"
    assert "core has no command primitive" in handlebars[0]["note"]
    pug = S.build_payloads("pug", command='printf "x"')
    assert json.loads(pug[0]["payload"].split("execSync(", 1)[1].split(").toString", 1)[0]) == 'printf "x"'
    assert all(row["offline"] and "candidate" in row["note"] for row in smarty + pug)


def test_ldap_xpath_are_fragments_and_never_verified_as_success():
    ldap = W.ldap_injection_candidates("uid")
    xpath = W.xpath_injection_candidates("username")
    assert any("*)(|" in row["value"] for row in ldap)
    assert any("or '1'='1" in row["value"] for row in xpath)
    assert all(row["candidate_only"] and not row["verified_syntax"] for row in ldap + xpath)
    assert all(row["sent"] is False and row["network_requests"] == 0 for row in ldap + xpath)


def test_xinclude_is_well_formed_but_not_claimed_as_inclusion():
    row = W.xinclude_payload("/etc/passwd")
    root = ET.fromstring(row["value"])
    child = list(root)[0]
    assert child.tag == "{%s}include" % W.XI_NS
    assert child.attrib == {"href": "file:///etc/passwd", "parse": "text"}
    assert row["verified_syntax"] is True
    assert "remains unverified" in row["note"]
    for bad in ("https://public.example/file", "relative/file"):
        with pytest.raises(W.WebDepthInputError):
            W.xinclude_payload(bad)
    with pytest.raises(W.WebDepthInputError):
        W.xinclude_payload("/etc/passwd", root="bad;tag")


def test_lfi_candidates_have_exact_decode_depth_and_decline_ambiguous_target():
    rows = W.lfi_traversal_candidates("/etc/passwd", depth=3)
    by_name = {row["name"]: row for row in rows}
    assert by_name["plain"]["value"] == "../../../etc/passwd"
    assert urllib.parse.unquote(by_name["url_encoded_separator"]["value"]) == "../../../etc/passwd"
    assert urllib.parse.unquote(urllib.parse.unquote(by_name["double_encoded_separator"]["value"])) == "../../../etc/passwd"
    assert by_name["php_filter_base64"]["value"].endswith("resource=/etc/passwd")
    assert all(row["candidate_only"] and not row["verified_syntax"] for row in rows)
    with pytest.raises(W.WebDepthInputError):
        W.lfi_traversal_candidates("../../flag")


def test_header_candidates_use_marker_only_and_reject_preinjected_path():
    rows = W.header_chain_candidates("app.example", "marker.invalid", path="/reset?u=alice")
    assert rows[0]["value"].startswith("/reset?u=alice%0d%0a")
    host = next(row for row in rows if row["name"] == "x_forwarded_host")
    assert host["value"]["headers"]["X-Forwarded-Host"] == "marker.invalid"
    assert host["value"]["send"] if "send" in host["value"] else host["sent"] is False
    with pytest.raises(W.WebDepthInputError):
        W.header_chain_candidates("app.example", path="/x%0d%0aEvil:yes")


def test_race_and_business_plans_never_run_or_claim_a_result():
    race = W.race_condition_plan("coupon")
    assert race["value"]["parallelism"] == 2
    assert all(step["send"] is False for step in race["value"]["requests"])
    assert "sequentially" in race["value"]["negative_control"]
    plans = W.business_logic_plans("2fa")
    assert any(row["name"] == "reuse_or_cross_account_code" for row in plans)
    assert all(row["sent"] is False and "never enumerate" in row["note"] for row in plans)


def test_waf_reversible_encodings_crosscheck_stdlib_and_lossy_are_unverified():
    payload = "<script>alert('π')</script>"
    rows = {row["name"]: row for row in W.waf_encoding_candidates(payload)}
    assert urllib.parse.unquote(rows["url_percent"]["value"]) == payload
    assert urllib.parse.unquote(urllib.parse.unquote(rows["double_url_percent"]["value"])) == payload
    assert rows["url_percent"]["verified_syntax"] is True
    assert rows["fullwidth_nfkc"]["verified_syntax"] is False
    assert rows["alternating_case"]["verified_syntax"] is False


def test_cli_boundaries_are_guarded(capsys):
    assert W.main([]) == 2
    assert "web_attack_depth:" in capsys.readouterr().err
    assert W.main(["xinclude", "relative"]) == 2
    assert "web_attack_depth:" in capsys.readouterr().err
    assert W.main(["business", "2fa", "--json"]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed and all(row["candidate_only"] for row in parsed)


def test_seeded_mutation_boundaries_5000_cases_no_escaped_exception():
    rng = random.Random(0x5EBD3E7)
    alphabet = string.printable + "\x00\ud800\uffff\u202e\U000e0001"
    functions = (
        lambda value: W.ldap_injection_candidates(value),
        lambda value: W.xpath_injection_candidates(value),
        lambda value: W.xinclude_payload(value),
        lambda value: W.lfi_traversal_candidates(value),
        lambda value: W.header_chain_candidates(value),
        lambda value: W.waf_encoding_candidates(value),
        lambda value: S.build_payloads("pug", read_file=value),
        lambda value: S.detect_response(value),
    )
    for function in functions:
        accepted = 0
        for _ in range(5000):
            value = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 180)))
            try:
                function(value)
                accepted += 1
            except (W.WebDepthInputError, ValueError, TypeError, UnicodeError,
                    OverflowError, RecursionError, MemoryError):
                pass
        assert 0 <= accepted <= 5000


def test_triage_routes_new_depth_without_displacing_existing_specific_engines():
    suggested = T.suggest("web", "LDAP injection and password reset host-header poisoning")
    assert suggested["engines"][0] == "solvers/web/web_attack_depth.py"
    suggested = T.suggest("web", "MongoDB NoSQL $ne authentication bypass")
    assert suggested["engines"][0] == "solvers/web/exploit_classes.py"
    suggested = T.suggest("web", "XXE parameter entity against an XML parser")
    assert suggested["engines"][0] == "solvers/toolkits/web_xxe_ssrf.py"
    suggested = T.suggest("web", "Handlebars template injection")
    assert suggested["engines"][0] == "solvers/web/ssti_helper.py"
    suggested = T.suggest("web", "CL.TE HTTP request smuggling")
    assert suggested["engines"][0] == "solvers/web/http_desync.py"
