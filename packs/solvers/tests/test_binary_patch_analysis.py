"""Deterministic tests for structural binary patch analysis."""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import binary_patch_analysis as diff  # noqa: E402


def test_equal_length_hunks_classify_control_flow_and_nop_edits():
    before = b"HEAD" + b"\x74" + b"middle" + b"\xcc\xcc" + b"TAIL"
    after = b"HEAD" + b"\x75" + b"middle" + b"\x90\x90" + b"TAIL"
    report = diff.analyze_binary_patch(before, after, move_block_size=16)
    assert report.identical is False
    assert report.common_prefix == 4
    assert len(report.hunks) == 2
    assert "control-flow-edit" in report.hunks[0].classification
    assert report.hunks[0].confidence == 98
    assert "nop-fill" in report.hunks[1].classification
    assert report.to_dict()["before_size"] == len(before)


def test_size_change_uses_bounded_prefix_suffix_splice():
    before = b"prefix-OLD-suffix"
    after = b"prefix-NEW-LONG-suffix"
    hunks, truncated = diff.byte_hunks(before, after)
    assert not truncated and len(hunks) == 1
    assert hunks[0].before_size == 3
    assert hunks[0].after_size == 8
    assert "size changed by +5 bytes" in hunks[0].evidence


def test_regions_match_by_name_not_position_and_capture_structure():
    before = b"A" * 16 + b"CODE" * 4 + b"DATA" * 4
    after = b"A" * 16 + b"DATA" * 4 + b"C0DE" * 4
    old_regions = [
        {"name": ".text", "offset": 16, "size": 16, "virtual_address": 0x1000, "flags": "rx"},
        {"name": ".data", "offset": 32, "size": 16, "virtual_address": 0x2000, "flags": "rw"},
    ]
    new_regions = [
        {"name": ".data", "offset": 16, "size": 16, "virtual_address": 0x2000, "flags": "rw"},
        {"name": ".text", "offset": 32, "size": 16, "virtual_address": 0x1000, "flags": "rwx"},
    ]
    changes = diff.diff_regions(before, after, old_regions, new_regions)
    by_name = {row.name: row for row in changes}
    assert by_name[".data"].status == "relocated" and not by_name[".data"].content_changed
    assert by_name[".text"].status == "modified" and by_name[".text"].content_changed
    assert any("flags changed" in fact for fact in by_name[".text"].evidence)


def test_metadata_and_unique_block_moves_are_stable():
    block_a = bytes(range(16))
    block_b = bytes(range(16, 32))
    moves = diff.find_unique_moved_blocks(block_a + block_b, block_b + block_a, block_size=16)
    assert [(row.before_offset, row.after_offset) for row in moves] == [(0, 16), (16, 0)]
    metadata = diff.diff_metadata(
        {"entry": 0x1000, "signed": True, "build": "old"},
        {"entry": 0x1010, "signed": False, "new_field": 7},
    )
    assert [row.key for row in metadata] == ["build", "entry", "new_field", "signed"]


def test_report_marks_move_cap_truncation(monkeypatch):
    block_a = bytes(range(16))
    block_b = bytes(range(16, 32))
    block_c = bytes(range(32, 48))
    monkeypatch.setattr(diff, "MAX_MOVES", 1)
    report = diff.analyze_binary_patch(
        block_a + block_b + block_c, block_b + block_a + block_c, move_block_size=16,
    )
    assert len(report.moved_blocks) == 1
    assert report.truncated is True


def test_identical_inputs_and_hunk_truncation_are_explicit():
    same = diff.analyze_binary_patch(b"same", b"same", move_block_size=16)
    assert same.identical and same.hunks == () and same.common_prefix == 4
    before = bytes([0, 0, 0, 0, 0])
    after = bytes([1, 0, 1, 0, 1])
    hunks, truncated = diff.byte_hunks(before, after, max_hunks=2)
    assert len(hunks) == 2 and truncated


def test_region_overlap_caps_and_nonprimitive_metadata_fail_closed(monkeypatch):
    with pytest.raises(diff.DiffInputError, match="overlap"):
        diff.normalize_regions([
            {"name": "a", "offset": 0, "size": 4},
            {"name": "b", "offset": 3, "size": 2},
        ], 8)
    with pytest.raises(diff.DiffInputError, match="primitive"):
        diff.diff_metadata({"nested": {"x": 1}}, {})
    with pytest.raises(TypeError, match="mappings"):
        diff.analyze_binary_patch(b"", b"", before_metadata=[])  # type: ignore[arg-type]
    with pytest.raises(diff.DiffInputError, match="regions"):
        diff.analyze_binary_patch(b"", b"", before_regions=None)  # type: ignore[arg-type]
    with pytest.raises(diff.DiffInputError, match="blob_size"):
        diff.normalize_regions([], -1)
    monkeypatch.setattr(diff, "MAX_MOVE_BLOCKS", 1)
    with pytest.raises(diff.DiffInputError, match="block cap"):
        diff.find_unique_moved_blocks(b"A" * 32, b"B" * 32, block_size=16)
    monkeypatch.setattr(diff, "MAX_BINARY", 3)
    with pytest.raises(diff.DiffInputError, match="cap"):
        diff.byte_hunks(b"1234", b"1234")


def test_module_ast_has_no_io_execution_network_or_deserialization():
    tree = ast.parse((REPO / "solvers" / "binary" / "binary_patch_analysis.py").read_text())
    imports = {alias.name.split(".")[0] for node in ast.walk(tree)
               if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names}
    calls = {node.func.id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    assert not imports & {"subprocess", "socket", "requests", "marshal", "pickle", "importlib"}
    assert not calls & {"open", "exec", "eval", "compile", "__import__"}
