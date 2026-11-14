"""Deterministic tests for inert rbash/shell-restriction candidates."""

import ast
from pathlib import Path

import pytest

import shell_jail_planner as shell


def by_id(rows, name):
    return next(row for row in rows if row.candidate_id == name)


def test_default_catalog_is_stable_and_marker_only():
    first = shell.generate_shell_candidates(shell.ShellJailProfile())
    second = shell.generate_shell_candidates(shell.ShellJailProfile())
    assert first == second
    assert first[0].candidate_id == "literal_space_marker"
    assert all(row.inert and row.offline and not row.process_invoked for row in first)
    assert all(row.derivation and row.preconditions for row in first)


def test_no_space_profile_selects_ifs_brace_and_here_string_candidates():
    rows = shell.generate_shell_candidates(
        shell.ShellJailProfile(no_space=True), include_blocked=False
    )
    names = {row.candidate_id for row in rows}
    assert {"ifs_marker", "brace_marker", "herestring_marker"}.issubset(names)
    assert all(" " not in row.value for row in rows)


def test_no_slash_derivation_has_no_literal_slash():
    rows = shell.generate_shell_candidates(shell.ShellJailProfile(no_space=True, no_slash=True))
    candidate = by_id(rows, "slash_from_path")
    assert candidate.compatible
    assert "/" not in candidate.value
    assert candidate.effect == "capability_discovery"


def test_feature_switches_block_exact_expansion_families():
    profile = shell.ShellJailProfile(
        no_space=True,
        parameter_expansion=False,
        brace_expansion=False,
        globbing=False,
        input_redirection=False,
        command_substitution=False,
    )
    rows = shell.generate_shell_candidates(profile)
    assert not by_id(rows, "ifs_marker").compatible
    assert not by_id(rows, "brace_marker").compatible
    assert not by_id(rows, "glob_marker").compatible
    assert not by_id(rows, "herestring_marker").compatible
    assert any("command_substitution" in item for item in by_id(rows, "nested_builtin_marker").violations)


def test_rbash_profile_prioritizes_builtin_lookups_without_paths():
    profile = shell.rbash_profile(no_space=True)
    rows = shell.generate_shell_candidates(profile, include_blocked=False)
    lookup = by_id(rows, "rbash_builtin_lookup")
    assert lookup.compatible
    assert lookup.effect == "capability_discovery"
    assert "/" not in lookup.value and " " not in lookup.value
    assert all("builtin" in row.features for row in rows)


def test_glob_candidate_is_explicitly_conditional_not_assumed_successful():
    row = by_id(shell.generate_shell_candidates(shell.ShellJailProfile()), "glob_marker")
    assert "unique" in " ".join(row.preconditions)
    assert "or the literal pattern" in row.expected_observation


def test_allowed_characters_and_banned_tokens_are_enforced():
    allowed = frozenset("printf${IFS}%sR5D_MARKER")
    rows = shell.generate_shell_candidates(shell.ShellJailProfile(
        no_space=True,
        allowed_characters=allowed,
        banned_tokens=("command", "type"),
    ))
    assert by_id(rows, "ifs_marker").compatible
    assert not by_id(rows, "rbash_builtin_lookup").compatible


def test_mapping_and_bounds_validation():
    profile = shell.profile_from_mapping({"rbash": True, "no_space": True, "banned_characters": ["/"]})
    assert profile.rbash and profile.no_space and "/" in profile.banned_characters
    with pytest.raises(shell.ShellJailInputError, match="boolean"):
        shell.profile_from_mapping({"globbing": "yes"})
    with pytest.raises(shell.ShellJailInputError, match="single characters"):
        shell.ShellJailProfile(allowed_characters=frozenset({"ab"})).validate()
    with pytest.raises(shell.ShellJailInputError, match="profile flags"):
        shell.ShellJailProfile(rbash="yes").validate()
    with pytest.raises(shell.ShellJailInputError, match="ban cap"):
        shell.ShellJailProfile(banned_tokens=tuple(str(i) for i in range(129))).validate()
    with pytest.raises(shell.ShellJailInputError, match="marker"):
        shell.generate_shell_candidates(shell.ShellJailProfile(), marker="bad marker!")
    with pytest.raises(shell.ShellJailInputError, match="limit"):
        shell.generate_shell_candidates(shell.ShellJailProfile(), limit=33)


def test_no_candidate_reads_files_spawns_shells_or_uses_network_tools():
    values = "\n".join(row.value for row in shell.generate_shell_candidates(shell.ShellJailProfile()))
    forbidden = ("cat", "bash", "sh -", "curl", "wget", "nc ", "/dev/", "/flag", "python")
    assert all(item not in values for item in forbidden)


def test_module_has_no_process_shell_eval_or_network_runtime():
    tree = ast.parse(Path(shell.__file__).read_text(encoding="utf-8"))
    forbidden_imports = {"os", "subprocess", "socket", "requests", "httpx", "pty", "shlex"}
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

