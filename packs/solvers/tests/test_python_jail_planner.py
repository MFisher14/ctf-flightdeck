"""Deterministic tests for the inert Python-jail planner."""

import ast
from pathlib import Path

import pytest

import python_jail_planner as jail


def by_id(rows, name):
    return next(row for row in rows if row.candidate_id == name)


def test_default_candidates_are_stable_constant_or_discovery_only():
    profile = jail.PythonJailProfile()
    first = jail.generate_python_candidates(profile)
    second = jail.generate_python_candidates(profile)
    assert first == second
    assert first[0].candidate_id == "constant_arithmetic"
    assert all(row.inert and row.offline and not row.active_effect for row in first)
    assert all(row.derivation and row.preconditions for row in first)


def test_builtins_stripped_and_no_import_are_distinct_constraints():
    builtins = jail.generate_python_candidates(
        jail.PythonJailProfile(builtins_stripped=True)
    )
    assert not by_id(builtins, "import_name_probe").compatible
    assert not by_id(builtins, "function_builtins_discovery").compatible
    assert by_id(builtins, "subclasses_discovery").compatible

    no_import = jail.generate_python_candidates(jail.PythonJailProfile(imports_blocked=True))
    assert not by_id(no_import, "import_name_probe").compatible
    assert by_id(no_import, "importless_warning_class").compatible


def test_no_underscore_derivation_contains_no_literal_underscore():
    rows = jail.generate_python_candidates(jail.PythonJailProfile(underscores_blocked=True))
    derived = by_id(rows, "underscore_derivation")
    assert derived.compatible
    assert "_" not in derived.value
    assert not by_id(rows, "subclasses_discovery").compatible


def test_dunder_attribute_call_and_comprehension_restrictions_are_explicit():
    profile = jail.PythonJailProfile(
        dunders_blocked=True,
        attributes_allowed=False,
        calls_allowed=False,
        comprehensions_allowed=False,
    )
    rows = jail.generate_python_candidates(profile)
    discovery = by_id(rows, "subclasses_discovery")
    assert not discovery.compatible
    assert any("dunder" in item for item in discovery.violations)
    assert any("attribute" in item for item in discovery.violations)
    assert any("call" in item for item in discovery.violations)
    assert not by_id(rows, "underscore_derivation").compatible
    assert any("dunder semantics" in item for item in by_id(rows, "underscore_derivation").violations)
    assert any("comprehension" in item for item in by_id(rows, "importless_warning_class").violations)


def test_character_allowlist_selects_only_arithmetic_control():
    profile = jail.PythonJailProfile(allowed_characters=frozenset("0123456789*"))
    rows = jail.generate_python_candidates(profile, include_blocked=False)
    assert [row.candidate_id for row in rows] == ["constant_arithmetic"]
    assert set(rows[0].value) <= profile.allowed_characters


def test_audit_hook_marks_discovery_events_but_not_constants():
    rows = jail.generate_python_candidates(jail.PythonJailProfile(audit_hook=True))
    assert by_id(rows, "constant_arithmetic").compatible
    audited = by_id(rows, "subclasses_discovery")
    assert not audited.compatible
    assert any("audited events" in item for item in audited.violations)


@pytest.mark.parametrize(
    ("version", "selected", "blocked"),
    [
        ("3.10", "bytecode_constant_pre311", "bytecode_constant_311plus"),
        ("3.11", "bytecode_constant_311plus", "bytecode_constant_pre311"),
        ("3.13.1", "bytecode_constant_311plus", "bytecode_constant_pre311"),
    ],
)
def test_bytecode_profiles_emit_metadata_only_versioned_plans(version, selected, blocked):
    rows = jail.generate_python_candidates(jail.PythonJailProfile(
        bytecode_allowed=True, python_version=version
    ))
    chosen = by_id(rows, selected)
    assert chosen.compatible
    assert chosen.kind == "bytecode_plan"
    assert chosen.submitted_value is False
    assert "BYTECODE_PLAN" in chosen.value
    assert not by_id(rows, blocked).compatible


def test_profile_matrix_names_every_requested_archetype():
    assert [name for name, _ in jail.profile_matrix()] == [
        "builtins_stripped", "no_import", "no_underscore", "no_dunder",
        "audit_hook", "bytecode_310", "bytecode_311",
    ]


def test_mapping_validation_and_generator_bounds():
    profile = jail.profile_from_mapping({
        "builtins_stripped": True,
        "banned_characters": "_",
        "banned_tokens": ["help"],
        "python_version": "3.12",
    })
    assert profile.builtins_stripped and "_" in profile.banned_characters
    with pytest.raises(jail.PythonJailInputError, match="boolean"):
        jail.profile_from_mapping({"audit_hook": "yes"})
    with pytest.raises(jail.PythonJailInputError, match="allowed_characters"):
        jail.PythonJailProfile(allowed_characters=frozenset({"ab"})).validate()
    with pytest.raises(jail.PythonJailInputError, match="profile flags"):
        jail.PythonJailProfile(audit_hook="yes").validate()
    with pytest.raises(jail.PythonJailInputError, match="ban cap"):
        jail.PythonJailProfile(banned_tokens=tuple(str(i) for i in range(129))).validate()
    with pytest.raises(jail.PythonJailInputError, match="limit"):
        jail.generate_python_candidates(jail.PythonJailProfile(), limit=0)
    with pytest.raises(jail.PythonJailInputError, match="marker"):
        jail.generate_python_candidates(jail.PythonJailProfile(), marker="bad marker")


def test_candidates_contain_no_active_file_process_or_network_sink():
    values = "\n".join(row.value for row in jail.generate_python_candidates(jail.PythonJailProfile()))
    forbidden = ("system(", "popen(", "subprocess", "socket", "open(", "exec(", "eval(", "compile(")
    assert all(item not in values for item in forbidden)


def test_module_has_no_dynamic_execution_process_or_network_runtime():
    tree = ast.parse(Path(jail.__file__).read_text(encoding="utf-8"))
    forbidden_imports = {"os", "subprocess", "socket", "requests", "httpx", "importlib", "marshal", "pickle"}
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

