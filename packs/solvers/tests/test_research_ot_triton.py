"""Reference tests for the static HatMan/TRITON artifact inspector.

The payload literals are hand-transcribed from the layout in CISA
MAR-17-352-01 Update B.  They are not produced by the parser under test.
ZIP fixtures use Python's independent standard-library ZIP encoder and the
artifact names/hash table published in that MAR.
"""
from __future__ import annotations

import ast
import io
import json
import zipfile
from pathlib import Path

import pytest

import research_ot_triton as triton


# inject="INJ", imain=de ad be ef, n=len(imain)+8=12.  Marker values are
# 0x00001234 and 0x0056789a.  The MAR Appendix A YARA rule publishes the
# little-endian marker byte strings.  The big-endian lookalike is negative.
BIG_ENDIAN_PAYLOAD = bytes.fromhex(
    "49 4e 4a  00 00 00 0c  00 00 12 34  de ad be ef"
    " 00 00 00 0c  00 56 78 9a"
)
LITTLE_ENDIAN_PAYLOAD = bytes.fromhex(
    "49 4e 4a  0c 00 00 00  34 12 00 00  de ad be ef"
    " 0c 00 00 00  9a 78 56 00"
)


def _zip(entries, *, compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return output.getvalue()


def test_cisa_hash_indicators_are_exact_and_lookup_is_case_insensitive():
    assert triton.KNOWN_SHA1_BY_NAME["trilog.exe"] == "dc81f383624955e0c0441734f9f1dabfe03f373c"
    assert triton.KNOWN_SHA1_BY_NAME["inject.bin"] == "f403292f6cb315c84f84f6c51490e2e8cd03c686"
    assert triton.KNOWN_SHA1_BY_NAME["imain.bin"] == "b47ad4840089247b058121e95732beb82e6311d0"
    assert triton.KNOWN_SHA1_BY_NAME["TsLow.pyc"] == "a6357a8792e68b05690a9736bc3051cba4b43227"
    by_name = triton.identify_name(r"bundle\TSLOW.PYC")
    assert by_name["name"] == "TsLow.pyc"
    assert by_name["evidence"] == "filename-only"
    by_hash = triton.identify_sha1("DC81F383624955E0C0441734F9F1DABFE03F373C")
    assert [item["name"] for item in by_hash] == ["trilog.exe"]
    assert by_hash[0]["evidence"] == "exact-sha1"
    assert triton.identify_sha1("0" * 40) == []


def test_cisa_combined_payload_layout():
    result = triton.parse_combined_payload(LITTLE_ENDIAN_PAYLOAD)
    assert result["format"] == "hatman-combined-payload"
    assert result["evidence"] == "validated-combined-payload-structure"
    assert result["byte_order"] == "little"
    assert result["marker_evidence"] == "CISA MAR Appendix A YARA byte sequence"
    assert result["length_encoding"] == "little-endian structural interpretation"
    assert result["declared_imain_plus_trailer"] == 12
    assert result["inject"]["offset"] == 0
    assert result["inject"]["length"] == 3
    assert result["imain"]["offset"] == 11
    assert result["imain"]["length"] == 4
    assert result["markers"] == ["0x00001234", "0x0056789a"]
    assert result["layout"] == {
        "length_offset": 3,
        "first_marker_offset": 7,
        "second_length_offset": 15,
        "second_marker_offset": 19,
    }


@pytest.mark.parametrize(
    "payload",
    [
        LITTLE_ENDIAN_PAYLOAD[:-1],
        BIG_ENDIAN_PAYLOAD,
        LITTLE_ENDIAN_PAYLOAD + b"trailing",
        LITTLE_ENDIAN_PAYLOAD[:3] + b"\x0d\x00\x00\x00" + LITTLE_ENDIAN_PAYLOAD[7:],
        LITTLE_ENDIAN_PAYLOAD[:-4] + b"\x9b\x78\x56\x00",
        b"prefix\x34\x12\x00\x00partial",
        b"INJ\x08\x00\x00\x00\x34\x12\x00\x00\x08\x00\x00\x00\x9a\x78\x56\x00",
        b"\x00" * 32,
    ],
)
def test_combined_payload_rejects_truncation_mismatch_and_trailing_bytes(payload):
    with pytest.raises(triton.TritonArtifactError):
        triton.parse_combined_payload(payload)


def test_zip_inventory_recognizes_complete_runtime_without_opening_members(monkeypatch):
    names = ["TsLow.pyc", "TsBase.pyc", "TsHi.pyc", "TS_cnames.pyc", "crc.pyc", "sh.pyc"]
    blob = _zip([(name, ("inert-" + name).encode()) for name in names], compression=zipfile.ZIP_DEFLATED)

    def forbidden_open(*args, **kwargs):
        raise AssertionError("ZIP member content must never be opened")

    monkeypatch.setattr(zipfile.ZipFile, "open", forbidden_open)
    result = triton.inspect_zip(blob)
    assert result["format"] == "zip-inventory"
    assert result["member_count"] == 6
    assert result["runtime_module_completeness"]["missing"] == []
    assert result["runtime_module_completeness"]["present"] == sorted(names)
    assert {item["name"] for item in result["recognized_hatman_names"]} == set(names)
    assert result["limitations"] == [
        "Central-directory metadata only; members were not opened, decompressed, or extracted."
    ]


def test_zip_inventory_reports_traversal_and_casefold_duplicate():
    blob = _zip([("../crc.pyc", b"x"), ("Folder/TsLow.pyc", b"y"), ("folder/tslow.pyc", b"z")])
    result = triton.inspect_zip(blob)
    assert {item["kind"] for item in result["findings"]} == {"unsafe-path", "duplicate-member"}
    assert result["runtime_module_completeness"]["present"] == ["TsLow.pyc", "crc.pyc"]


def test_auto_analysis_preserves_independent_name_and_hash_evidence():
    result = triton.analyze_bytes(b"not the known executable", name="TRILOG.EXE")
    assert result["format"] == "artifact"
    assert result["identity"]["known_name_match"]["name"] == "trilog.exe"
    assert result["identity"]["known_hash_matches"] == []
    payload = triton.analyze_bytes(LITTLE_ENDIAN_PAYLOAD, name="combined.bin")
    assert payload["format"] == "hatman-combined-payload"


def test_malformed_zip_and_declared_limits_fail_closed(monkeypatch):
    with pytest.raises(triton.TritonArtifactError):
        triton.inspect_zip(b"PK\x03\x04not-a-zip")
    blob = _zip([("a", b"1234")])
    monkeypatch.setattr(triton, "MAX_ZIP_MEMBER_UNCOMPRESSED", 3)
    with pytest.raises(triton.TritonArtifactError, match="member uncompressed"):
        triton.inspect_zip(blob)
    monkeypatch.setattr(triton, "MAX_ZIP_MEMBER_UNCOMPRESSED", 100)
    monkeypatch.setattr(triton, "MAX_ZIP_UNCOMPRESSED", 3)
    with pytest.raises(triton.TritonArtifactError, match="uncompressed"):
        triton.inspect_zip(blob)
    monkeypatch.setattr(triton, "MAX_ZIP_UNCOMPRESSED", 100)
    monkeypatch.setattr(triton, "MAX_ZIP_COMPRESSION_RATIO", 0.5)
    with pytest.raises(triton.TritonArtifactError, match="compression ratio"):
        triton.inspect_zip(blob)
    monkeypatch.setattr(triton, "MAX_INPUT", 8)
    with pytest.raises(triton.TritonArtifactError, match="size limit"):
        triton.analyze_bytes(b"123456789")


def test_marker_scan_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(triton, "MAX_MARKER_CANDIDATES", 2)
    marker = bytes.fromhex("34 12 00 00")
    with pytest.raises(triton.TritonArtifactError, match="candidate limit"):
        triton.parse_combined_payload(b"prefix" + marker * 3)


@pytest.mark.parametrize(
    ("function", "args", "kwargs"),
    [
        (triton.identify_name, (None,), {}),
        (triton.identify_sha1, (None,), {}),
        (triton.identify_sha1, ("xyz",), {}),
        (triton.parse_combined_payload, (None,), {}),
        (triton.parse_combined_payload, (b"",), {}),
        (triton.inspect_zip, ({},), {}),
        (triton.analyze_bytes, ([],), {}),
        (triton.analyze_bytes, (b"x",), {"name": None}),
        (triton.analyze_bytes, (b"x",), {"kind": "invalid"}),
        (triton.analyze_file, (123,), {}),
    ],
)
def test_all_public_failures_use_declared_exception(function, args, kwargs):
    with pytest.raises(triton.TritonArtifactError):
        function(*args, **kwargs)


def test_cli_guarded_argparse_success_and_error(tmp_path, capsys):
    assert triton.main([]) == 2
    assert triton.main(["--help"]) == 0
    capsys.readouterr()

    artifact = tmp_path / "combined.bin"
    artifact.write_bytes(LITTLE_ENDIAN_PAYLOAD)
    assert triton.main([str(artifact), "--kind", "payload"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["format"] == "hatman-combined-payload"
    assert output["identity"]["name"] == "combined.bin"

    assert triton.main([str(tmp_path / "missing")]) == 2
    assert "error:" in capsys.readouterr().err


def test_module_is_static_only():
    source = Path(triton.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imports.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert not imports.intersection({"socket", "requests", "httpx", "subprocess", "scapy"})
