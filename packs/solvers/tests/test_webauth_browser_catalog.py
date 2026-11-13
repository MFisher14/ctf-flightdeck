"""Published-vector tests for the offline webauth browser-policy catalog.

The DOM fixtures are the named-property shapes documented by the OWASP DOM
Clobbering Prevention Cheat Sheet and vendor DOM-clobbering advisories.  CSP
host outcomes follow CSP3 and Google CSP Evaluator commit ad530f3.  Package
boundaries are the fixed versions in the reviewed GitHub advisories.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import webauth_browser_catalog as browser  # noqa: E402


def test_owasp_named_anchor_and_collection_shapes_reach_sensitive_uses():
    # OWASP examples:
    #   <a id=redirectTo href=javascript:...>
    #   <a id=config></a><a id=config name=url href=...></a>
    html = """
<a id=redirectTo href="javascript:alert(1)"></a>
<a id=config></a><a id=config name=url href="https://attacker.invalid/x.js"></a>
<form id=profile><input name=next value="javascript:alert(1)"></form>
"""
    javascript = """
location.assign(window.redirectTo);
const script = document.createElement('script'); script.src = window.config.url || 'safe.js';
location.href = document.profile.next.value;
"""
    report = browser.analyze_dom_clobbering(html, javascript)
    chains = {row["chain"]: row for row in report["chains"]}
    assert {"redirectTo", "config", "config.url", "profile.next"} <= set(chains)
    assert chains["config.url"]["mechanism"] == "duplicate named elements / HTMLCollection"
    assert chains["profile.next"]["mechanism"] == "form named-property access"

    findings = {(row["chain"], row["sink"]) for row in report["findings"]}
    assert ("redirectTo", "navigation") in findings
    assert ("config.url", "script_or_resource_url") in findings
    assert ("profile.next", "navigation") in findings
    assert report["offline"] and not report["browser_started"]
    assert report["network_requests"] == 0


def test_dom_clobbering_does_not_equate_an_id_with_a_sensitive_use():
    report = browser.analyze_dom_clobbering(
        '<div id="message"></div>',
        'document.querySelector("#message").textContent = "safe";',
    )
    assert {row["chain"] for row in report["chains"]} == {"message"}
    assert report["findings"] == []


def test_html_named_access_eligibility_and_external_form_ownership():
    # WHATWG named access: arbitrary IDs are supported names, while name= is
    # restricted to legacy eligible elements.  A reassociateable control's
    # explicit form= owner is resolved by form ID.
    html = """
<div id=idRoot name=notARoot></div>
<a name=anchorName></a>
<img name=imageRoot>
<iframe name=frameRoot></iframe>
<form id=profile></form><input form=profile name=next>
<div id=notAForm></div>
<form id=ancestor><input form=notAForm name=blocked></form>
<div id=shadowed></div><form id=shadowed></form><input form=shadowed name=lost>
"""
    chains = {row["chain"] for row in browser.analyze_dom_clobbering(html)["chains"]}
    assert {"idRoot", "imageRoot", "frameRoot", "profile.next"} <= chains
    assert "notARoot" not in chains
    assert "anchorName" not in chains
    assert "ancestor.blocked" not in chains
    assert "shadowed.lost" not in chains


def test_current_script_catalog_uses_published_webpack_fixed_boundary():
    html = '<img name="currentScript" src="https://attacker.invalid/runtime.js">'
    javascript = "const here = document.currentScript.src; __webpack_require__.p = here;"

    affected = browser.analyze_dom_clobbering(
        html,
        javascript,
        '{"dependencies":{"webpack":"5.93.0"}}',
    )
    row = affected["current_script_catalog_matches"][0]
    assert row["cve"] == "CVE-2024-43788"
    assert row["version_status"] == "affected-version"
    assert row["named_currentScript_present"] is True

    fixed = browser.analyze_dom_clobbering(
        html,
        javascript,
        '{"dependencies":{"webpack":"5.94.0"}}',
    )
    assert fixed["current_script_catalog_matches"][0]["version_status"] == "fixed-boundary-or-newer"
    assert {row.cve for row in browser.current_script_catalog()} >= {
        "CVE-2024-43788", "CVE-2024-45812", "CVE-2024-47068",
        "CVE-2024-47885", "CVE-2024-47075",
    }


def test_published_astro_document_scripts_shape_and_catalog_metadata():
    html = '<iframe name="scripts">alert(1)</iframe><iframe name="scripts">alert(1)</iframe>'
    javascript = "for (const script of Array.from(document.scripts)) { void script.dataset.astroExec; }"
    report = browser.analyze_dom_clobbering(
        html, javascript, '{"dependencies":{"astro":"4.16.0"}}'
    )
    astro = next(row for row in report["current_script_catalog_matches"]
                 if row["cve"] == "CVE-2024-47885")
    assert astro["required_access"] == "document.scripts"
    assert astro["clobber_name"] == "scripts"
    assert astro["minimum_named_elements"] == 2
    assert astro["clobber_shape_present"] is True
    assert astro["version_status"] == "affected-version"

    one = browser.analyze_dom_clobbering(
        '<iframe name="scripts">alert(1)</iframe>', javascript,
        '{"dependencies":{"astro":"4.16.1"}}',
    )
    astro_one = next(row for row in one["current_script_catalog_matches"]
                     if row["cve"] == "CVE-2024-47885")
    assert astro_one["clobber_shape_present"] is False
    assert astro_one["version_status"] == "fixed-boundary-or-newer"

    catalog = {row.package: row for row in browser.current_script_catalog()}
    assert catalog["rollup"].affected == "<2.79.2; >=3.0.0,<3.29.5; >=4.0.0,<4.22.4"
    assert catalog["rollup"].fixed.startswith("2.79.2, 3.29.5, or 4.22.4")
    assert catalog["layui"].affected == "<2.9.17"
    assert catalog["layui"].fixed == "2.9.17"


@pytest.mark.parametrize(
    ("package", "marker", "version", "expected"),
    [
        ("rollup", "ROLLUP_FILE_URL", "2.79.1", "affected-version"),
        ("rollup", "ROLLUP_FILE_URL", "2.79.2", "fixed-boundary-or-newer"),
        ("rollup", "ROLLUP_FILE_URL", "3.29.4", "affected-version"),
        ("rollup", "ROLLUP_FILE_URL", "3.29.5", "fixed-boundary-or-newer"),
        ("rollup", "ROLLUP_FILE_URL", "4.22.3", "affected-version"),
        ("rollup", "ROLLUP_FILE_URL", "4.22.4", "fixed-boundary-or-newer"),
        ("layui", "layui", "2.9.16", "affected-version"),
        ("layui", "layui", "2.9.17", "fixed-boundary-or-newer"),
    ],
)
def test_vendor_published_rollup_and_layui_branch_boundaries(
    package, marker, version, expected
):
    report = browser.analyze_dom_clobbering(
        '<img name="currentScript" src="https://attacker.invalid/x.js">',
        f"const u = document.currentScript.src; void {marker};",
        json.dumps({"dependencies": {package: version}}),
    )
    row = next(item for item in report["current_script_catalog_matches"]
               if item["package"] == package)
    assert row["version_status"] == expected


def test_csp_preserves_duplicates_and_applies_element_and_attribute_fallbacks():
    parsed = browser.parse_csp_policies(
        "default-src 'none'; script-src https://clients1.google.com; "
        "script-src 'none'; script-src-attr 'none'"
    )[0]
    script_rows = [row for row in parsed.directives if row.name == "script-src"]
    assert [row.occurrence for row in script_rows] == [1, 2]

    report = browser.analyze_csp(parsed.raw)
    policy = report["policies"][0]
    assert policy["effective_script_src_elem"] == {
        "directive": "script-src",
        "values": ("https://clients1.google.com",),
    }
    assert policy["effective_script_src_attr"] == {
        "directive": "script-src-attr",
        "values": ("'none'",),
    }
    assert policy["duplicate_directives_ignored_after_first"] == ("script-src",)
    names = {row["name"] for row in report["catalog_matches"]}
    assert "google_complete_jsonp" in names


def test_pinned_google_catalog_hosts_match_only_when_every_policy_allows_them():
    one = browser.analyze_csp("default-src 'none'; script-src https://clients1.google.com")
    assert {row["name"] for row in one["catalog_matches"]} == {"google_complete_jsonp"}
    match = one["catalog_matches"][0]
    assert match["url"] == "https://clients1.google.com/complete/search"
    assert "ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822" in match["provenance"]
    assert "not probed" in match["stale_warning"]

    intersected = browser.analyze_csp([
        "default-src 'none'; script-src https://clients1.google.com",
        "default-src 'none'; script-src 'none'",
    ])
    assert intersected["multiple_policies_intersect"] is True
    assert intersected["catalog_matches"] == []
    candidate = next(row for row in intersected["catalog_candidates"]
                     if row["name"] == "google_complete_jsonp")
    assert candidate["allowed_by_all_policies"] is False


def test_csp_catalog_urls_are_exact_entries_from_the_pinned_google_snapshot():
    # Hand-transcribed from google/csp-evaluator commit ad530f3, rather than
    # derived from this engine's output.
    expected = {
        "google_complete_jsonp": (
            "https://clients1.google.com/complete/search",
            "allowlist_bypasses/json/jsonp.json",
        ),
        "google_cse_jsonp": (
            "https://cse.google.com/api/007627024705277327428/cse/"
            "r3vs7b0fcli/queries/js",
            "allowlist_bypasses/json/jsonp.json",
        ),
        "googleapis_angular": (
            "https://ajax.googleapis.com/ajax/libs/angularjs/1.2.0rc1/angular-route.min.js",
            "allowlist_bypasses/json/angular.json",
        ),
        "cdnjs_angular": (
            "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.2.16/angular.min.js",
            "allowlist_bypasses/json/angular.json",
        ),
        "jsdelivr_angular": (
            "https://cdn.jsdelivr.net/angularjs/1.1.2/angular.min.js",
            "allowlist_bypasses/json/angular.json",
        ),
    }
    observed = {row.name: row for row in browser.csp_gadget_catalog()}
    assert set(observed) == set(expected)
    for name, (url, source_file) in expected.items():
        assert observed[name].url == url
        assert "ad530f3ae5473f9e03c8bf500ee0ada8d9e9b822" in observed[name].provenance
        assert source_file in observed[name].provenance


def test_strict_dynamic_and_trusted_types_are_modeled_without_live_probe():
    policy = (
        "default-src 'none'; "
        "script-src 'nonce-YWJjZGVmZ2g=' 'strict-dynamic' https://clients1.google.com; "
        "object-src 'none'; base-uri 'none'; trusted-types safe; "
        "require-trusted-types-for 'script'"
    )
    report = browser.analyze_csp(policy)
    row = report["policies"][0]
    assert row["strict_dynamic_active"] is True
    assert row["base_uri"] == ("'none'",)
    assert row["trusted_types"] == ("safe",)
    assert row["require_trusted_types_for_script"] is True
    assert report["catalog_matches"] == []
    google = next(item for item in report["catalog_candidates"]
                  if item["name"] == "google_complete_jsonp")
    assert "strict-dynamic" in google["policy_decisions"][0]["reason"]
    assert report["endpoint_probes"] == report["network_requests"] == 0


def test_csp3_absent_directive_wildcards_default_ports_and_secure_upgrade():
    # CSP3: with no effective script directive, its request check does not run.
    unrestricted = browser.analyze_csp("object-src 'none'")
    assert {row["name"] for row in unrestricted["catalog_matches"]} == {
        "google_complete_jsonp", "google_cse_jsonp", "googleapis_angular",
        "cdnjs_angular", "jsdelivr_angular",
    }
    decision = unrestricted["catalog_matches"][0]["policy_decisions"][0]
    assert decision["unrestricted"] is True

    # CSP3 removes only '*' from '*.host'; the remaining leading dot means the
    # wildcard cannot match the bare apex.
    apex = browser.analyze_csp(
        "script-src https://*.clients1.google.com",
        document_origin="https://app.example",
    )
    assert "google_complete_jsonp" not in {row["name"] for row in apex["catalog_matches"]}
    parent = browser.analyze_csp(
        "script-src https://*.google.com",
        document_origin="https://app.example",
    )
    assert "google_complete_jsonp" in {row["name"] for row in parent["catalog_matches"]}

    explicit_default = browser.analyze_csp(
        "script-src https://clients1.google.com:443"
    )
    assert "google_complete_jsonp" in {
        row["name"] for row in explicit_default["catalog_matches"]
    }
    upgraded = browser.analyze_csp("script-src http://clients1.google.com")
    assert "google_complete_jsonp" in {row["name"] for row in upgraded["catalog_matches"]}
    upgraded_default_port = browser.analyze_csp(
        "script-src http://clients1.google.com:80"
    )
    assert "google_complete_jsonp" in {
        row["name"] for row in upgraded_default_port["catalog_matches"]
    }
    schemeless = browser.analyze_csp(
        "script-src clients1.google.com", document_origin="http://app.example"
    )
    assert "google_complete_jsonp" in {
        row["name"] for row in schemeless["catalog_matches"]
    }
    wildcard = browser.analyze_csp("script-src *")
    assert len(wildcard["catalog_matches"]) == 5


def test_csp3_self_and_strict_dynamic_require_valid_source_grammar():
    same_origin = browser.analyze_csp(
        "script-src 'self'", document_origin="https://clients1.google.com:443"
    )
    assert {row["name"] for row in same_origin["catalog_matches"]} == {
        "google_complete_jsonp"
    }
    upgraded_self = browser.analyze_csp(
        "script-src 'self'", document_origin="http://clients1.google.com:80"
    )
    assert {row["name"] for row in upgraded_self["catalog_matches"]} == {
        "google_complete_jsonp"
    }

    invalid = browser.analyze_csp(
        "script-src 'nonce-!' 'strict-dynamic' https://clients1.google.com"
    )
    assert invalid["policies"][0]["strict_dynamic_active"] is False
    assert "google_complete_jsonp" in {row["name"] for row in invalid["catalog_matches"]}

    valid = browser.analyze_csp(
        "script-src 'nonce-YWJjZA==' 'strict-dynamic' https://clients1.google.com"
    )
    assert valid["policies"][0]["strict_dynamic_active"] is True
    assert valid["catalog_matches"] == []


def test_angular_catalog_obeys_script_src_elem_path_and_default_fallback():
    allowed = browser.analyze_csp(
        "default-src 'none'; script-src 'none'; "
        "script-src-elem https://ajax.googleapis.com/ajax/libs/"
    )
    assert {row["name"] for row in allowed["catalog_matches"]} == {"googleapis_angular"}
    policy = allowed["policies"][0]
    assert policy["effective_script_src_elem"]["directive"] == "script-src-elem"
    assert policy["effective_script_src_attr"]["directive"] == "script-src"

    blocked_path = browser.analyze_csp(
        "default-src 'none'; script-src-elem https://ajax.googleapis.com/not-angular/"
    )
    assert "googleapis_angular" not in {row["name"] for row in blocked_path["catalog_matches"]}


def test_published_jquery_and_lodash_cve_boundaries_are_semantic():
    source = "$.extend(true, {}, input); _.zipObjectDeep(paths, values);"
    affected_manifest = json.dumps({
        "dependencies": {"jquery": "3.3.1", "lodash": "4.17.18"}
    })
    rows = {row["name"]: row for row in browser.match_prototype_gadgets(source, affected_manifest)}
    assert rows["jquery_deep_extend"]["cve"] == "CVE-2019-11358"
    assert rows["jquery_deep_extend"]["version_status"] == "affected-version"
    assert rows["lodash_zip_object_deep"]["cve"] == "CVE-2020-8203"
    assert rows["lodash_zip_object_deep"]["version_status"] == "affected-version"
    assert rows["lodash_zip_object_deep"]["declared_version"] == "4.17.18"
    assert rows["lodash_zip_object_deep"]["version_source"] == "package manifest declaration"

    fixed_manifest = json.dumps({
        "dependencies": {"jquery": "3.4.0", "lodash": "4.17.19"}
    })
    fixed = {row["name"]: row for row in browser.match_prototype_gadgets(source, fixed_manifest)}
    assert fixed["jquery_deep_extend"]["version_status"] == "fixed-boundary-or-newer"
    assert fixed["lodash_zip_object_deep"]["version_status"] == "fixed-boundary-or-newer"

    prerelease = browser.match_prototype_gadgets(
        "$.extend(true, {}, input)",
        '{"dependencies":{"jquery":"3.4.0-beta.2"}}',
    )[0]
    assert prerelease["version_status"] == "affected-version"


def test_requested_library_gadget_families_are_cataloged_and_require_preconditions():
    catalog = browser.prototype_gadget_catalog()
    names = {row.name for row in catalog}
    assert {
        "google_analytics_hit_callback",
        "google_tag_manager_sequence",
        "google_tag_manager_event_callback",
        "adobe_dtm_csp_nonce",
        "adobe_dtm_body_hidden_style",
        "adobe_dtm_tracking_server",
        "recaptcha_srcdoc",
        "closure_base_path",
        "vue_template",
        "zepto_html_onerror",
        "dompurify_config",
    } <= names
    assert len(names) == len(catalog)
    source = "const hitCallback = options.hitCallback; setTimeout(hitCallback, 10);"
    row = browser.match_prototype_gadgets(source)[0]
    assert row["name"] == "google_analytics_hit_callback"
    assert row["confidence"] == "medium"
    assert "prototype-pollution source" in row["precondition"]
    assert row["offline"] is True


def test_malformed_inputs_raise_only_declared_error():
    with pytest.raises(browser.WebauthBrowserError, match="exceeds"):
        browser.analyze_dom_clobbering("x" * (browser.MAX_HTML_BYTES + 1))
    with pytest.raises(browser.WebauthBrowserError, match="valid bounded JSON"):
        browser.match_prototype_gadgets("", "{not-json")
    with pytest.raises(browser.WebauthBrowserError, match="duplicate key"):
        browser.match_prototype_gadgets(
            "", '{"dependencies":{"jquery":"3.3.1","jquery":"3.4.0"}}'
        )
    with pytest.raises(browser.WebauthBrowserError, match="control character"):
        browser.parse_csp_policies("script-src 'self'\nInjected: value")
    with pytest.raises(browser.WebauthBrowserError, match="origin is malformed"):
        browser.analyze_csp("script-src 'self'", document_origin="https://example.test:bad")
    with pytest.raises(browser.WebauthBrowserError, match=r"HTTP\(S\) origin"):
        browser.analyze_csp(
            "script-src 'self'", document_origin="https://user:pass@example.test"
        )
    with pytest.raises(browser.WebauthBrowserError, match="port is over limit"):
        browser.analyze_csp("script-src https://example.test:" + "9" * 5000)
    with pytest.raises(browser.WebauthBrowserError, match="conflicting versions"):
        browser.match_prototype_gadgets(
            "",
            '{"dependencies":{"lodash":"4.17.18"},'
            '"resolutions":{"lodash":"4.17.19"}}',
        )
    with pytest.raises(browser.WebauthBrowserError, match="must be text"):
        browser.analyze_dom_clobbering(123)  # type: ignore[arg-type]

    # Repeating the same declaration across sections is deterministic rather
    # than ambiguous and therefore remains admissible.
    assert browser.match_prototype_gadgets(
        "_.zipObjectDeep(paths, values)",
        '{"dependencies":{"lodash":"4.17.18"},'
        '"resolutions":{"lodash":"4.17.18"}}',
    )[0]["version_status"] == "affected-version"


def test_guarded_cli_and_basename_import(tmp_path, capsys):
    html = tmp_path / "sample.html"
    javascript = tmp_path / "sample.js"
    html.write_text('<a id="next" href="javascript:alert(1)"></a>', encoding="utf-8")
    javascript.write_text("location.assign(window.next);", encoding="utf-8")
    assert browser.main(["dom", str(html), "--javascript", str(javascript)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"][0]["chain"] == "next"
    assert browser.main(["csp"]) == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert browser.main(["prototype", str(tmp_path / "missing.js")]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_module_has_no_network_browser_execution_or_dynamic_deserialization_surface():
    tree = ast.parse((WEB / "webauth_browser_catalog.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    direct_calls: set[str] = set()
    attribute_calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                direct_calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                attribute_calls.add(node.func.attr)
    assert not imports.intersection({
        "socket", "requests", "http.client", "urllib.request", "subprocess",
        "selenium", "playwright", "pickle", "marshal",
    })
    assert not direct_calls.intersection({"eval", "exec", "compile", "open", "__import__"})
    assert not attribute_calls.intersection({
        "connect", "request", "send", "sendall", "urlopen", "post", "system",
        "popen", "run",
    })
