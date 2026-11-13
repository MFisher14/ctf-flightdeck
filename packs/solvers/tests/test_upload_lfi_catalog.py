"""Deterministic tests for upload/polyglot and traversal/LFI catalogs."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "solvers" / "web"
sys.path.insert(0, str(WEB))

import upload_lfi_catalog as uplfi  # noqa: E402


def test_upload_matrix_covers_names_media_magic_and_polyglots():
    rows = uplfi.upload_bypass_catalog("probe", "php", "jpg", "ROUND5")
    assert len(rows) == 17
    assert [row.family for row in rows].count("filename") == 9
    assert [row.family for row in rows].count("media_type") == 2
    assert [row.family for row in rows].count("magic_prefix") == 3
    assert [row.family for row in rows].count("polyglot") == 3
    values = {row.name: row for row in rows}
    assert values["double_extension"].filename == "probe.php.jpg"
    assert values["mixed_case_extension"].filename == "probe.PHP"
    assert values["fullwidth_dot"].filename == "probe．php"
    assert values["gif89a_marker"].content_literal == "GIF89a\\nROUND5"
    assert values["jpeg_marker"].content_literal.startswith("\\xFF\\xD8\\xFF")
    assert values["svg_text_marker"].content_literal.endswith("ROUND5</text></svg>")
    assert all(row.to_dict()["inert"] and row.to_dict()["network_requests"] == 0 for row in rows)


def test_multipart_preview_is_exact_text_and_rejects_header_breakout():
    candidate = uplfi.upload_bypass_catalog("probe", marker="ROUND5")[0]
    body = uplfi.multipart_preview(candidate, field="artifact", boundary="BOUNDARY5")
    assert body == (
        "--BOUNDARY5\r\n"
        'Content-Disposition: form-data; name="artifact"; filename="probe.php.jpg"\r\n'
        "Content-Type: text/plain\r\n\r\n"
        "ROUND5\r\n"
        "--BOUNDARY5--\r\n"
    )
    forged = uplfi.UploadCandidate(
        "filename", "bad", 'x"\r\nX-Test: y', "text/plain", "marker", "test"
    )
    with pytest.raises(uplfi.UploadLFIInputError, match="filename"):
        uplfi.multipart_preview(forged)
    with pytest.raises(uplfi.UploadLFIInputError, match="basename"):
        uplfi.upload_bypass_catalog("../escape")


def test_traversal_catalog_tracks_decode_layers_and_platforms():
    rows = uplfi.traversal_catalog("etc/passwd", depth=3)
    assert [row.name for row in rows] == [
        "plain",
        "backslash",
        "percent_slash",
        "percent_backslash",
        "double_encoded",
        "mixed_encoded",
        "collapsed_dots",
        "absolute_posix",
        "file_uri",
        "null_suffix",
    ]
    values = {row.name: row for row in rows}
    assert values["plain"].value == "../../../etc/passwd"
    assert values["backslash"].value == "..\\..\\..\\etc\\passwd"
    assert values["double_encoded"].decode_layers == 2
    assert values["file_uri"].value == "file:///etc/passwd"
    assert values["null_suffix"].value.endswith("etc/passwd%00.r5d")
    with pytest.raises(uplfi.UploadLFIInputError, match="depth"):
        uplfi.traversal_catalog(depth=0)
    with pytest.raises(uplfi.UploadLFIInputError, match="normalized relative"):
        uplfi.traversal_catalog("../secret")


def test_lfi_wrappers_are_read_oriented_and_omit_execution_deserialization():
    rows = uplfi.lfi_wrapper_catalog("var/www/config.php")
    assert [row.name for row in rows] == [
        "php_filter_base64",
        "php_filter_named_read",
        "php_filter_chain",
        "php_rot13_control",
        "file_uri",
        "percent_encoded_file_uri",
        "jar_entry_example",
        "data_marker_control",
    ]
    values = "\n".join(row.value.lower() for row in rows)
    assert "php://filter/convert.base64-encode/resource=/var/www/config.php" in values
    assert "expect://" not in values
    assert "phar://" not in values
    assert "pickle" not in values
    assert all(row.to_dict()["offline"] for row in rows)


def test_lfi_chains_compose_traversal_and_read_filters_only():
    rows = uplfi.lfi_chain_catalog("etc/passwd", depth=2)
    assert [row.name for row in rows] == [
        "php_filter_after_traversal",
        "encoded_php_filter_after_traversal",
        "double_encoded_traversal_in_filter",
        "rot13_traversal_control",
    ]
    assert rows[0].value == "php://filter/convert.base64-encode/resource=../../etc/passwd"
    assert rows[1].decode_layers == 1 and "php:%2f%2ffilter" in rows[1].value
    assert rows[2].decode_layers == 2 and "%252e%252e%252f" in rows[2].value
    assert all(row.family == "lfi_chain" and row.to_dict()["inert"] for row in rows)


def test_static_surface_analyzer_finds_controls_and_sinks_in_offset_order():
    source = """
allowed_extensions = {'png', 'jpg'}
kind = finfo_file(upload)
image = Image.open(upload)
saved = path.join(root, original_filename)
archive.extractall(root)
data = include(user_path)
safe = realpath(user_path).startswith(realpath(root))
decoded = unquote(user_path).resolve()
"""
    rows = uplfi.analyze_upload_lfi_surface(source)
    names = [row.name for row in rows]
    assert {
        "extension_allowlist",
        "magic_inspection",
        "image_reencode",
        "path_join",
        "archive_extraction",
        "file_read_sink",
        "canonical_prefix_check",
        "decode_before_normalize",
    } <= set(names)
    assert [row.offset for row in rows] == sorted(row.offset for row in rows)
    assert all(row.kind in {"risk", "control", "context"} for row in rows)
    with pytest.raises(uplfi.UploadLFIInputError, match="exceeds"):
        uplfi.analyze_upload_lfi_surface("x" * (uplfi.MAX_TEXT + 1))


def test_module_has_no_transport_execution_or_archive_opening_calls():
    tree = ast.parse((WEB / "upload_lfi_catalog.py").read_text(encoding="utf-8"))
    imports: set[str] = set()
    calls: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                calls.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                calls.add(node.func.attr)
    assert not imports.intersection(
        {"socket", "requests", "http.client", "urllib.request", "zipfile", "tarfile", "pickle", "marshal"}
    )
    assert not calls.intersection(
        {"connect", "send", "sendall", "urlopen", "request", "extract", "extractall", "loads", "eval", "exec"}
    )
