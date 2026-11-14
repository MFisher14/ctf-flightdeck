"""Tests for semantic restricted-character construction planning."""

import ast
from dataclasses import replace
from pathlib import Path

import pytest

import restricted_charset_planner as chars


def by_id(rows, name):
    return next(row for row in rows if row.plan_id == name)


def test_direct_literal_plan_is_stable_and_verified():
    profile = chars.RestrictionProfile(frozenset("R5D"), frozenset({"literal"}))
    first = chars.plan_restricted_text("R5D", profile)
    second = chars.plan_restricted_text("R5D", profile)
    assert first == second
    assert [row.plan_id for row in first] == ["literal"]
    assert chars.verify_plan(first[0])
    assert first[0].expression_emitted is False


def test_case_swap_plan_derives_blocked_case_without_encoding():
    profile = chars.RestrictionProfile(
        frozenset("r5d"), frozenset({"literal", "case_swap", "concat"})
    )
    plans = chars.plan_restricted_text("R5D", profile)
    plan = by_id(plans, "case_swap")
    assert chars.verify_plan(plan)
    assert [step.operation for step in plan.steps] == ["case_swap", "literal", "case_swap"]


def test_fragment_slice_uses_minimum_stable_cover():
    profile = chars.RestrictionProfile(
        frozenset(),
        frozenset({"fragment_slice", "concat"}),
        (
            chars.NamedFragment("banner", "prefix-R5D-suffix"),
            chars.NamedFragment("other", "R5D"),
        ),
    )
    plan = by_id(chars.plan_restricted_text("R5D", profile), "fragment_slice")
    assert len(plan.steps) == 1
    assert plan.steps[0].operands[0] == "banner"  # stable fragment order on equal cost
    assert chars.verify_plan(plan)


def test_repeating_fragment_search_remains_bounded_and_correct():
    profile = chars.RestrictionProfile(
        frozenset(),
        frozenset({"fragment_slice"}),
        (chars.NamedFragment("repeat", "a" * 1024),),
    )
    plan = chars.plan_restricted_text("a" * 256, profile)[0]
    assert len(plan.steps) == 1
    assert chars.verify_plan(plan)


def test_codepoint_add_and_xor_derivations_reconstruct_target():
    profile = chars.RestrictionProfile(
        frozenset(),
        frozenset({"codepoint", "add", "xor", "concat"}),
        operand_min=1,
        operand_max=127,
    )
    plans = chars.plan_restricted_text("R5D", profile)
    assert {"codepoint", "add_codepoint", "xor_codepoint"}.issubset(row.plan_id for row in plans)
    assert all(chars.verify_plan(row) for row in plans)
    assert by_id(plans, "add_codepoint").required_operations[:2] == ("add", "codepoint")


def test_mixed_plan_chooses_literal_case_and_codepoint_per_character():
    profile = chars.RestrictionProfile(
        frozenset("r5"),
        frozenset({"literal", "case_swap", "codepoint", "concat"}),
    )
    plan = by_id(chars.plan_restricted_text("R5D", profile), "mixed_character")
    assert [step.operation for step in plan.steps] == ["case_swap", "literal", "codepoint"]
    assert chars.verify_plan(plan)


def test_impossible_profile_returns_no_guess():
    profile = chars.RestrictionProfile(frozenset("abc"), frozenset({"literal"}))
    assert chars.plan_restricted_text("R5D", profile) == ()


def test_descriptor_is_non_wire_and_has_no_target_expression():
    profile = chars.RestrictionProfile(frozenset(), frozenset({"codepoint", "concat"}))
    plan = chars.plan_restricted_text("R5D", profile)[0]
    assert plan.descriptor.startswith("R5D_CHAR_PLAN|")
    assert "expression=NOT_EMITTED" in plan.descriptor
    assert "|target=R5D" not in plan.descriptor
    assert plan.derivation and plan.preconditions


def test_verifier_rejects_tampered_steps_without_eval():
    profile = chars.RestrictionProfile(frozenset(), frozenset({"codepoint", "concat"}))
    plan = chars.plan_restricted_text("R5D", profile)[0]
    bad_step = replace(plan.steps[0], operands=("99999999",))
    assert not chars.verify_plan(replace(plan, steps=(bad_step,) + plan.steps[1:]))


def test_mapping_and_bounds_validation():
    profile = chars.profile_from_mapping({
        "allowed_characters": "r5d",
        "operations": ["literal", "case_swap", "concat"],
        "fragments": {"banner": "R5D marker"},
    })
    assert profile.fragments[0].name == "banner"
    with pytest.raises(chars.RestrictedCharsetInputError, match="unknown operations"):
        chars.RestrictionProfile(frozenset(), frozenset({"url_encode"})).validate()
    with pytest.raises(chars.RestrictedCharsetInputError, match="operand span"):
        chars.RestrictionProfile(
            frozenset(), frozenset({"codepoint", "xor"}), operand_min=0, operand_max=5000
        ).validate()
    with pytest.raises(chars.RestrictedCharsetInputError, match="target"):
        chars.plan_restricted_text("", profile)
    with pytest.raises(chars.RestrictedCharsetInputError, match="target"):
        chars.plan_restricted_text("x" * 257, profile)
    with pytest.raises(chars.RestrictedCharsetInputError, match="limit"):
        chars.plan_restricted_text("x", profile, limit=0)


def test_no_waf_transport_or_normalization_transform_exists():
    source = Path(chars.__file__).read_text(encoding="utf-8")
    forbidden = ("urllib.parse", "base64.", "html.escape(", "url_encode(", "normalize(")
    assert all(item not in source.casefold() for item in forbidden)
    assert set(chars.OPERATIONS) == {
        "literal", "concat", "case_swap", "fragment_slice", "codepoint", "add", "xor"
    }


def test_module_has_no_eval_compile_process_deserializer_or_network_runtime():
    tree = ast.parse(Path(chars.__file__).read_text(encoding="utf-8"))
    forbidden_imports = {"os", "subprocess", "socket", "requests", "httpx", "pickle", "marshal", "base64", "urllib", "html"}
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

