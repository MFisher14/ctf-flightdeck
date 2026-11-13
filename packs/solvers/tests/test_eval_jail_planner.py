"""Tests for safe eval/calculator/template-expression planning."""

import ast
from pathlib import Path

import pytest

import eval_jail_planner as jail


def by_id(rows, name):
    return next(row for row in rows if row.candidate_id == name)


@pytest.mark.parametrize("mode", jail.MODES)
def test_each_mode_has_stable_inert_candidates(mode):
    profile = jail.EvalJailProfile(mode)
    first = jail.generate_eval_candidates(profile)
    second = jail.generate_eval_candidates(profile)
    assert first == second
    assert first
    assert first[0].candidate_id == "constant_arithmetic"
    assert all(row.inert and row.offline and not row.active_effect for row in first)
    assert all(row.derivation and row.preconditions for row in first)


def test_calculator_function_and_operator_allowlists_are_separate():
    profile = jail.EvalJailProfile(
        "calculator",
        allowed_operators=frozenset({"*"}),
        allowed_functions=frozenset({"sqrt"}),
    )
    rows = jail.generate_eval_candidates(profile)
    assert by_id(rows, "constant_arithmetic").compatible
    assert by_id(rows, "sqrt_probe").compatible
    assert not by_id(rows, "precedence_probe").compatible
    assert not by_id(rows, "sin_zero_probe").compatible


def test_no_calls_attributes_strings_or_indexing_filters_capability_probes():
    profile = jail.EvalJailProfile(
        "python_eval",
        strings_allowed=False,
        calls_allowed=False,
        attributes_allowed=False,
        indexing_allowed=False,
    )
    rows = jail.generate_eval_candidates(profile, include_blocked=False)
    assert [row.candidate_id for row in rows] == ["constant_arithmetic"]


def test_template_expression_is_delimiter_free_and_not_ssti_fingerprinting():
    rows = jail.generate_eval_candidates(jail.EvalJailProfile("template_expression"))
    values = "\n".join(row.value for row in rows)
    assert all(token not in values for token in ("{{", "}}", "${", "<%", "%>", "<#"))
    assert by_id(rows, "constant_addition").expected_observation == "49"


def test_language_specific_constant_concatenation_is_explicit():
    expected = {
        "python_eval": "+", "javascript_eval": "+", "ruby_eval": "+", "php_eval": ".",
    }
    for mode, operator in expected.items():
        row = by_id(jail.generate_eval_candidates(jail.EvalJailProfile(mode)), "marker_concatenation")
        assert row.operators == (operator,)
        assert row.expected_observation == "R5D_MARKER"


def test_character_and_token_restrictions_are_checked_on_rendered_value():
    profile = jail.EvalJailProfile(
        "javascript_eval",
        allowed_characters=frozenset("0123456789*"),
        banned_tokens=("constructor",),
    )
    rows = jail.generate_eval_candidates(profile)
    assert by_id(rows, "constant_arithmetic").compatible
    assert not by_id(rows, "constructor_name").compatible


def test_saved_policy_analyzer_is_static_and_offset_sorted():
    text = "allowed_functions = ['sqrt']\nresult = simpleeval(expr)\nblacklist = ['import']"
    first = jail.analyze_eval_policy(text)
    second = jail.analyze_eval_policy(text)
    assert first == second
    assert {row.name for row in first} == {"allowlist", "math_parser", "denylist"}
    assert [row.offset for row in first] == sorted(row.offset for row in first)


def test_mapping_aliases_and_bounds(monkeypatch):
    profile = jail.profile_from_mapping({
        "mode": "calc", "allowed_operators": ["*"], "allowed_functions": ["sqrt"],
        "strings_allowed": False,
    })
    assert profile.mode == "calculator" and not profile.strings_allowed
    with pytest.raises(jail.EvalJailInputError, match="boolean"):
        jail.profile_from_mapping({"mode": "calc", "calls_allowed": "yes"})
    with pytest.raises(jail.EvalJailInputError, match="mode must be text"):
        jail.profile_from_mapping({"mode": {"bad": "type"}})
    with pytest.raises(jail.EvalJailInputError, match="single characters"):
        jail.EvalJailProfile("calculator", allowed_characters=frozenset({"12"})).validate()
    with pytest.raises(jail.EvalJailInputError, match="profile flags"):
        jail.EvalJailProfile("calculator", calls_allowed="yes").validate()
    with pytest.raises(jail.EvalJailInputError, match="unknown mode"):
        jail.EvalJailProfile("unknown").validate()
    with pytest.raises(jail.EvalJailInputError, match="marker"):
        jail.generate_eval_candidates(jail.EvalJailProfile("calculator"), marker="bad marker")
    monkeypatch.setattr(jail, "MAX_TEXT_CHARS", 8)
    with pytest.raises(jail.EvalJailInputError, match="exceeds"):
        jail.analyze_eval_policy("x" * 9)
    monkeypatch.setattr(jail, "MAX_TEXT_BYTES", 8)
    with pytest.raises(jail.EvalJailInputError, match="bytes"):
        jail.analyze_eval_policy(b"x" * 9)


def test_candidates_have_no_import_file_process_or_network_sink():
    values = "\n".join(
        row.value for mode in jail.MODES
        for row in jail.generate_eval_candidates(jail.EvalJailProfile(mode))
    )
    forbidden = ("import", "open(", "system(", "popen(", "subprocess", "socket", "fetch(", "require(")
    assert all(token not in values for token in forbidden)


def test_module_has_no_evaluator_renderer_process_or_network_runtime():
    tree = ast.parse(Path(jail.__file__).read_text(encoding="utf-8"))
    forbidden_imports = {"os", "subprocess", "socket", "requests", "httpx", "jinja2", "mako", "ast"}
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            calls.add(node.func.id)
    assert not imports.intersection(forbidden_imports)
    assert not calls.intersection({"eval", "exec", "compile", "__import__"})

