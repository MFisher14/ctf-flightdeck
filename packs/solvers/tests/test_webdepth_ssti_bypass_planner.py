"""Deterministic tests for the offline SSTI constraint planner.

The policy oracle below is deliberately independent of the engine: it checks
the final emitted text directly rather than reusing planner internals.  Only
benign Jinja identify expressions are rendered by a real library.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

import webdepth_ssti_bypass_planner as planner


def _independent_policy_allows(payload: str, tokens=(), characters=()) -> bool:
    folded = payload.casefold()
    return not any(token.casefold() in folded for token in tokens) and not any(
        character.casefold() in folded for character in characters
    )


def _row(report, candidate_id):
    rows = report["accepted"] + report["rejected"]
    return next(item for item in rows if item["candidate_id"] == candidate_id)


@pytest.mark.parametrize("engine", planner.ENGINES)
def test_every_engine_has_identify_read_and_command_families(engine):
    calls = (
        ("identify", {}),
        ("read", {"path": "/etc/passwd"}),
        ("command", {"command": "printf CSCTF"}),
    )
    for action, values in calls:
        report = planner.plan_ssti_bypasses(engine, action, **values)
        assert report["candidate_count"] >= 1
        assert report["candidate_count"] == len(report["accepted"]) + len(report["rejected"])
        assert report["offline"] is True
        assert report["rendered"] is report["executed"] is False
        assert report["network_requests"] == 0
        for candidate in report["accepted"] + report["rejected"]:
            assert candidate["engine"] == engine
            assert candidate["action"] == action
            assert candidate["payload"]
            assert candidate["prerequisites"]
            assert candidate["inert"] is candidate["offline"] is True


def test_real_jinja_oracle_renders_only_benign_identify_candidates():
    jinja2 = pytest.importorskip("jinja2")
    sandbox = pytest.importorskip("jinja2.sandbox")
    report = planner.plan_ssti_bypasses(
        "jinja2", "identify", marker="SAFE_MARKER", enabled_features=["string_concat"]
    )
    assert {row["status"] for row in report["accepted"]} == {"compatible"}
    for row in report["accepted"]:
        assert jinja2.Environment().from_string(row["payload"]).render() == "SAFE_MARKER"
        assert sandbox.SandboxedEnvironment().from_string(row["payload"]).render() == "SAFE_MARKER"


def test_jinja_attr_hex_route_survives_dot_and_underscore_policy():
    banned = (".", "_")
    report = planner.plan_ssti_bypasses(
        "jinja2",
        "command",
        command="id",
        banned_characters=banned,
        enabled_features=["jinja_default_globals", "attr_filter"],
        sandbox="disabled",
    )
    accepted = report["accepted"]
    assert [row["candidate_id"] for row in accepted] == ["jinja_command_attr_hex"]
    assert r"\x5f\x5fglobals\x5f\x5f" in accepted[0]["payload"]
    assert _independent_policy_allows(accepted[0]["payload"], characters=banned)
    assert all(not _independent_policy_allows(row["payload"], characters=banned)
               for row in report["rejected"] if row["candidate_id"] != "jinja_command_attr_hex")


def test_nunjucks_computed_properties_are_a_real_policy_alternative():
    report = planner.plan_ssti_bypasses(
        "nunjucks",
        "command",
        command="id",
        banned_tokens=["constructor"],
        enabled_features=["constructor_access", "node_main_module", "item_lookup"],
        sandbox="disabled",
    )
    direct = _row(report, "nunjucks_command_range_constructor")
    split = _row(report, "nunjucks_command_split_constructor")
    assert direct["status"] == "rejected"
    assert "constructor" in direct["payload"].casefold()
    assert split["status"] == "compatible"
    assert '"con"+"structor"' in split["payload"]
    assert _independent_policy_allows(split["payload"], tokens=["constructor"])


def test_nunjucks_context_require_bracket_route_avoids_dots():
    report = planner.plan_ssti_bypasses(
        "nunjucks",
        "command",
        command="id",
        banned_characters=["."],
        enabled_features=["require_in_context", "item_lookup"],
        sandbox="disabled",
    )
    row = _row(report, "nunjucks_command_context_require_brackets")
    assert row["status"] == "compatible"
    assert '["exe"+"cSync"]' in row["payload"]
    assert _independent_policy_allows(row["payload"], characters=["."])


def test_freemarker_and_twig_split_sensitive_names():
    fm = planner.plan_ssti_bypasses(
        "freemarker",
        "command",
        command="id",
        banned_tokens=["execute"],
        enabled_features=["string_concat", "new_builtin", "execute_utility"],
        sandbox="disabled",
    )
    assert _row(fm, "freemarker_command_execute")["status"] == "rejected"
    fm_split = _row(fm, "freemarker_command_split_execute")
    assert fm_split["status"] == "compatible"
    assert 'utility.Exe"+"cute"' in fm_split["payload"]
    assert _independent_policy_allows(fm_split["payload"], tokens=["execute"])

    twig = planner.plan_ssti_bypasses(
        "twig",
        "command",
        command="id",
        banned_tokens=["system"],
        enabled_features=["php_callbacks", "filter_filter", "string_concat"],
        sandbox="disabled",
    )
    assert _row(twig, "twig_command_filter_callback")["status"] == "rejected"
    twig_split = _row(twig, "twig_command_split_callback")
    assert twig_split["status"] == "compatible"
    assert '"sys"~"tem"' in twig_split["payload"]
    assert _independent_policy_allows(twig_split["payload"], tokens=["system"])


def test_documented_engine_routes_and_prerequisites_are_preserved():
    velocity = planner.plan_ssti_bypasses("velocity", "read", path="/flag", facts={"java_version": 17})
    assert "java.nio.file.Files" in _row(velocity, "velocity_read_nio")["payload"]
    assert "readString" in _row(velocity, "velocity_read_nio")["payload"]

    thymeleaf = planner.plan_ssti_bypasses("thymeleaf", "read", path="/flag", facts={"java_version": 17})
    trow = _row(thymeleaf, "thymeleaf_read_files")
    assert "T(java.nio.file.Files).readString" in trow["payload"]
    assert trow["sandbox_gate"] == "disabled"

    twig = planner.plan_ssti_bypasses("twig", "read", path="flag.twig")
    assert _row(twig, "twig_read_source")["payload"] == '{{source("flag.twig")}}'
    assert "template_loader" in _row(twig, "twig_read_source")["required_features"]

    tornado = planner.plan_ssti_bypasses("tornado", "command", command="id")
    assert _row(tornado, "tornado_command_import_os")["payload"].startswith("{% import os %}")
    assert "import_directive" in _row(tornado, "tornado_command_import_os")["required_features"]


def test_explicit_sandbox_rejects_unsafe_routes_but_not_identification():
    command = planner.plan_ssti_bypasses("jinja2", "command", command="id", sandbox="enabled")
    assert not command["accepted"]
    assert command["rejected_count"] == command["candidate_count"]
    assert all(any("unsandboxed" in reason for reason in row["rejected_reasons"])
               for row in command["rejected"])

    identify = planner.plan_ssti_bypasses("jinja2", "identify", sandbox="enabled")
    assert identify["accepted"]
    assert _row(identify, "jinja2_literal")["status"] == "compatible"


def test_unknown_and_closed_world_features_have_distinct_semantics():
    unknown = planner.plan_ssti_bypasses("tornado", "read", path="/flag", sandbox="disabled")
    assert all(row["status"] == "review" for row in unknown["accepted"])
    assert any("unverified feature" in reason for row in unknown["accepted"] for reason in row["blockers"])

    empty = planner.plan_ssti_bypasses(
        "tornado", "read", path="/flag", sandbox="disabled", enabled_features=[]
    )
    assert not empty["accepted"]
    assert all(any("not enabled" in reason for reason in row["rejected_reasons"])
               for row in empty["rejected"])


def test_pebble_published_version_gates_fail_closed():
    common = {
        "path": "/etc/passwd",
        "enabled_features": ["literal_template", "file_loader"],
    }
    allowed = planner.plan_ssti_bypasses("pebble", "read", version="3.2.3", **common)
    row = _row(allowed, "pebble_read_literal_include")
    assert row["status"] == "compatible"
    assert row["payload"] == '{% include "/etc/passwd" %}'
    assert row["version_gate"] == "<=3.2.3"

    blocked = planner.plan_ssti_bypasses("pebble", "read", version="3.2.4", **common)
    assert _row(blocked, "pebble_read_literal_include")["status"] == "rejected"

    legacy_features = ["context_object", "reflection"]
    old = planner.plan_ssti_bypasses(
        "pebble", "command", command="id", version="3.0.8",
        enabled_features=legacy_features, sandbox="disabled"
    )
    assert _row(old, "pebble_command_legacy_getclass")["status"] == "compatible"
    fixed = planner.plan_ssti_bypasses(
        "pebble", "command", command="id", version="3.0.9",
        enabled_features=legacy_features, sandbox="disabled"
    )
    assert _row(fixed, "pebble_command_legacy_getclass")["status"] == "rejected"


def test_java_runtime_fact_gates_files_readstring_routes():
    features = ["spring_el", "type_access", "text_inlining"]
    old = planner.plan_ssti_bypasses(
        "thymeleaf", "read", path="/flag", enabled_features=features,
        sandbox="disabled", facts={"java_version": 8}
    )
    assert _row(old, "thymeleaf_read_files")["status"] == "rejected"
    assert any("below required 11" in reason for reason in _row(old, "thymeleaf_read_files")["rejected_reasons"])

    current = planner.plan_ssti_bypasses(
        "thymeleaf", "read", path="/flag", enabled_features=features,
        sandbox="disabled", facts={"java_version": 17}
    )
    assert _row(current, "thymeleaf_read_files")["status"] == "compatible"


def test_case_insensitive_token_filter_and_supplied_value_are_checked():
    report = planner.plan_ssti_bypasses(
        "tornado", "command", command="Echo SeCrEt", banned_tokens=["secret"],
        enabled_features=["import_directive", "getattr", "string_concat", "os_in_context"],
        sandbox="disabled",
    )
    assert not report["accepted"]
    assert all(any("banned token" in reason for reason in row["rejected_reasons"])
               for row in report["rejected"])
    assert all(not _independent_policy_allows(row["payload"], tokens=["secret"])
               for row in report["rejected"])


@pytest.mark.parametrize(
    ("args", "kwargs"),
    [
        ((None, "identify"), {}),
        (("made-up", "identify"), {}),
        (("jinja2", None), {}),
        (("jinja2", "made-up"), {}),
        (("jinja2", "read"), {}),
        (("jinja2", "command"), {"command": {"not": "text"}}),
        (("jinja2", "identify"), {"path": "/x"}),
        (("jinja2", "read"), {"path": "/x", "command": "id"}),
        (("jinja2", "identify"), {"marker": "x" * (planner.MAX_VALUE_CHARS + 1)}),
        (("jinja2", "identify"), {"banned_tokens": "not-an-iterable-policy"}),
        (("jinja2", "identify"), {"banned_characters": ["ab"]}),
        (("jinja2", "identify"), {"enabled_features": "string_concat"}),
        (("jinja2", "identify"), {"facts": []}),
        (("jinja2", "identify"), {"facts": {"java_version": object()}}),
        (("jinja2", "identify"), {"sandbox": "maybe"}),
        (("pebble", "identify"), {"version": "v3.2.3"}),
        (("pebble", "identify"), {"version": "3.2.3.4.5"}),
    ],
)
def test_malformed_public_inputs_raise_only_declared_error(args, kwargs):
    with pytest.raises(planner.SSTIBypassInputError):
        planner.plan_ssti_bypasses(*args, **kwargs)


def test_cli_json_and_guarded_argparse_contract(capsys):
    assert planner.main(["--help"]) == 0
    capsys.readouterr()
    assert planner.main(["--not-a-real-option"]) == 2
    capsys.readouterr()
    assert planner.main([
        "twig", "read", "--path", "flag.twig", "--feature", "source_function",
        "--feature", "template_loader", "--json",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["engine"] == "twig"
    assert _row(report, "twig_read_source")["status"] == "compatible"


def test_cli_noninteger_systemexit_code_is_normalized(monkeypatch):
    class Parser:
        def parse_args(self, _argv):
            raise SystemExit("non-integer")

    monkeypatch.setattr(planner, "_build_parser", lambda: Parser())
    assert planner.main([]) == 2


def test_module_has_no_render_eval_process_or_network_runtime():
    source = Path(planner.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports: set[str] = set()
    calls: set[str] = set()
    attributes: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                attributes.add(node.func.attr)
    assert not imports.intersection({
        "socket", "requests", "httpx", "urllib", "subprocess", "os", "jinja2",
        "mako", "tornado", "pickle", "marshal",
    })
    assert not calls.intersection({"eval", "exec", "compile", "__import__", "open"})
    assert not attributes.intersection({
        "connect", "send", "sendall", "request", "urlopen", "system", "popen",
        "run", "Popen", "render", "render_string", "from_string",
    })

