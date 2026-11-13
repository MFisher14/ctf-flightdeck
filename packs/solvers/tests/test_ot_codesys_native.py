"""Independent fixtures for static CODESYS containers, symbols and boot evidence.

The Symbolconfiguration fixture follows Eaton MN048008ZU_EN, page 63:
https://www.eaton.com/content/dam/eaton/technicaldocumentation/mn/MN048008ZU_EN.pdf
INI application registration follows the CODESYS 'Creating a Boot Application'
manual. ZIPs use Python's independent ZIP writer; no engine encoder exists.
"""
import io
import json
import os
import random
import struct
import zipfile

import pytest

import ot_codesys_native as engine


SYMBOL_XML = b'''<?xml version="1.0" encoding="utf-8"?>
<Symbolconfiguration xmlns="http://www.3s-software.com/schemas/Symbolconfiguration.xsd">
  <Header><Version>3.3.0.0</Version><SymbolConfigObject version="3.3.0.0"/>
    <ProjectInfo name="CANbus_Project" devicename="Device" appname="Application"/>
  </Header>
  <TypeList><TypeSimple name="T_INT" size="2" swapsize="2" typeclass="Int" iecname="INT"/></TypeList>
  <NodeList><Node name="Application"><Node name="PLC_PRG">
    <Node name="iCounter" type="T_INT" access="ReadWrite"/>
  </Node></Node></NodeList>
</Symbolconfiguration>'''

CONFIG = b"; offline fixture\n[CmpApp]\nApplication.1=MyApplication\n[SysFileMap]\nFile1=/PLC/boot.app;/PLC/boot.app\n"


def zip_fixture(members, compression=zipfile.ZIP_DEFLATED):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, payload in members:
            info = zipfile.ZipInfo(name, (2020, 1, 2, 3, 4, 6))
            info.compress_type = compression
            archive.writestr(info, payload)
    return output.getvalue()


def test_published_vendor_symbol_layout():
    result = engine.parse_symbol_xml(SYMBOL_XML)
    assert result["format"] == "codesys-symbolconfiguration"
    assert result["types"] == [{
        "kind": "TypeSimple", "attributes": {"name": "T_INT", "size": "2",
        "swapsize": "2", "typeclass": "Int", "iecname": "INT"},
        "text": "", "children": []}]
    assert result["header"]["children"][0]["text"] == "3.3.0.0"
    assert result["header"]["children"][2]["attributes"] == {
        "name": "CANbus_Project", "devicename": "Device", "appname": "Application"}
    assert result["symbols"] == [
        {"path": "Application", "components": ["Application"],
         "attributes": {"name": "Application"}, "container": True},
        {"path": "Application.PLC_PRG", "components": ["Application", "PLC_PRG"],
         "attributes": {"name": "PLC_PRG"}, "container": True},
        {"path": "Application.PLC_PRG.iCounter", "components": ["Application", "PLC_PRG", "iCounter"],
         "attributes": {"name": "iCounter", "type": "T_INT", "access": "ReadWrite"}, "container": False}]


def test_symbol_layout_offsets_preserved_not_assigned_runtime_addresses():
    sample = SYMBOL_XML.replace(b'access="ReadWrite"', b'access="Read" offset="8"')
    result = engine.parse_symbol_xml(sample)
    assert result["symbols"][-1]["attributes"]["offset"] == "8"
    assert result["symbols"][-1]["attributes"]["access"] == "Read"
    assert "address" not in result["symbols"][-1]
    assert "runtime addresses" in result["limitations"][0]


def test_documented_boot_registration_and_literal_paths():
    result = engine.parse_runtime_config(CONFIG)
    assert result == {
        "format": "codesys-runtime-ini",
        "sections": [{"name": "CmpApp", "line": 2}, {"name": "SysFileMap", "line": 4}],
        "entries": [
            {"section": "CmpApp", "key": "Application.1", "value": "MyApplication", "line": 3},
            {"section": "SysFileMap", "key": "File1", "value": "/PLC/boot.app;/PLC/boot.app", "line": 5}]}
    duplicate = engine.parse_runtime_config(b"[CmpApp]\nApplication.1=A\nApplication.1=B\n[CmpApp]\nApplication.2=${HOME}\n")
    assert [item["value"] for item in duplicate["entries"]] == ["A", "B", "${HOME}"]
    assert len(duplicate["sections"]) == 2


def test_known_native_opaque_string_offsets_and_hints():
    # Hand-built evidence, not a claim to encode a proprietary CODESYS boot header.
    # A valid structured native header is deliberately NOT fabricated.
    prefix = (b"\x01\x02\x03\x00Application.PLC_PRG.iCounter\x00"
              b"CSCTF{static_boot_evidence}\x00\x00")
    payload = prefix + "MyApplication".encode("utf-16le") + b"\x00\x00"
    result = engine.analyze_bytes(payload, name="MyApplication.app")
    assert result["format"] == "opaque"
    assert result["signature"] == "unrecognized"
    assert result["role_hint"] == "boot-application"
    assert {"value": "Application.PLC_PRG.iCounter", "string_offset": 4,
            "encoding": "ascii", "evidence": "printable-string-only"} in result["symbol_candidates"]
    assert result["findings"][0] == {"kind": "flag", "value": "CSCTF{static_boot_evidence}", "string_offset": 33}
    expected_offset = len(prefix)
    assert any(item["value"] == "MyApplication" and item["offset"] == expected_offset
               and item["encoding"] == "utf-16le" for item in result["strings"])
    assert engine.analyze_bytes(payload, name="x.application")["role_hint"] == "application-artifact"


def test_utf16be_strings_and_binary_signature_are_evidence_only():
    payload = b"\x7fELF\x00\x00" + "Application.PLC_PRG.tag".encode("utf-16be") + b"\x00\x00"
    result = engine.analyze_bytes(payload, name="boot.app")
    assert result["signature"] == "elf"
    assert result["format"] == "opaque"
    assert any(item["encoding"] == "utf-16be" and item["value"] == "Application.PLC_PRG.tag"
               for item in result["symbol_candidates"])


def test_signature_driven_project_inventory_known_payloads():
    archive = zip_fixture([
        ("Project/Objects.bin", b"\x00Application.PLC_PRG.iCounter\x00"),
        ("Project.Device.Application.xml", SYMBOL_XML),
        ("CODESYSControl.cfg", CONFIG),
        ("MyApplication.crc", b"\x01\x02\x03\x04"),
        ("empty", b"")])
    result = engine.analyze_bytes(archive, name="example.project")
    assert result["format"] == "zip-container"
    assert result["signature"] == "zip"
    assert result["role_hint"] == "project"
    members = {item["name"]: item for item in result["archive"]["members"]}
    assert members["Project/Objects.bin"]["artifact"]["symbol_candidates"][0]["value"] == "Application.PLC_PRG.iCounter"
    assert members["Project.Device.Application.xml"]["artifact"]["detail"]["symbols"][-1]["path"] == "Application.PLC_PRG.iCounter"
    assert members["CODESYSControl.cfg"]["artifact"]["detail"]["entries"][0]["value"] == "MyApplication"
    assert members["MyApplication.crc"]["artifact"]["role_hint"] == "boot-crc-sidecar"
    assert members["MyApplication.crc"]["crc32"] == "b63cfbcd"  # ZIP CRC-32 of 01 02 03 04
    assert members["empty"]["artifact"]["format"] == "empty-member"
    # 'abc' SHA-256 is the NIST FIPS 180-4 example vector, independent of engine.
    assert engine.analyze_bytes(b"abc", name="x.app")["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_project_archive_nested_container_and_depth_bound():
    nested = zip_fixture([("inner.project", zip_fixture([("symbols.xml", SYMBOL_XML)]))])
    result = engine.analyze_bytes(nested, name="x.projectarchive")
    project = result["archive"]["members"][0]["artifact"]
    assert project["archive"]["members"][0]["artifact"]["format"] == "codesys-symbolconfiguration"
    third = zip_fixture([("second.project", nested)])
    deep = engine.analyze_bytes(third)
    cutoff = deep["archive"]["members"][0]["artifact"]["archive"]["members"][0]["artifact"]
    assert cutoff["archive"]["status"] == "opaque-depth-limit"


def test_existing_readable_export_parser_is_reused(monkeypatch):
    calls = []

    def existing(data, *, name):
        calls.append((data, name))
        return {"format": "codesys-export-xml", "logic": [{"text": "existing extractor"}]}

    monkeypatch.setattr(engine, "parse_export", existing)
    sample = b"<ExportFile><StructuredView/></ExportFile>"
    result = engine.analyze_bytes(zip_fixture([("code.export", sample)]), name="x.project")
    assert calls == [(sample, "code.export")]
    assert result["archive"]["members"][0]["artifact"]["detail"]["logic"][0]["text"] == "existing extractor"


def test_actual_readable_export_delegation():
    result = engine.analyze_bytes(b"<ExportFile><StructuredView/></ExportFile>", name="x.export")
    assert result["format"] == "codesys-export-xml"
    assert result["detail"]["format"] == "codesys-export-xml"


def test_unsafe_archive_paths_and_symlink_remain_opaque(tmp_path):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../outside.cfg", CONFIG)
        archive.writestr("C:\\outside.cfg", CONFIG)
        archive.writestr("/outside.cfg", CONFIG)
        symlink = zipfile.ZipInfo("link.cfg")
        symlink.create_system = 3
        symlink.external_attr = 0o120777 << 16
        archive.writestr(symlink, b"/etc/passwd")
    result = engine.analyze_bytes(output.getvalue())
    assert [member["status"] for member in result["archive"]["members"]] == [
        "opaque-unsafe-name", "opaque-unsafe-name", "opaque-unsafe-name", "opaque-symlink"]
    assert all("artifact" not in member for member in result["archive"]["members"])
    assert list(tmp_path.iterdir()) == []


def test_encrypted_member_and_unsupported_method_are_inventory_only():
    original = zip_fixture([("opaque.bin", b"DATA")], compression=zipfile.ZIP_STORED)
    encrypted = bytearray(original)
    central = encrypted.index(b"PK\x01\x02")
    struct.pack_into("<H", encrypted, 6, 1)  # ZIP APPNOTE local general-purpose flags
    struct.pack_into("<H", encrypted, central + 8, 1)  # central flags
    result = engine.analyze_bytes(bytes(encrypted))
    assert result["archive"]["members"][0]["status"] == "opaque-encrypted"
    unsupported = bytearray(original)
    struct.pack_into("<H", unsupported, 8, 99)  # local compression method
    struct.pack_into("<H", unsupported, central + 10, 99)  # central compression method
    assert engine.analyze_bytes(bytes(unsupported))["archive"]["members"][0]["status"] == "opaque-unsupported-compression"


def test_archive_crc_and_truncation_fail_closed():
    data = zip_fixture([("payload.bin", b"CORRECT")], compression=zipfile.ZIP_STORED)
    corrupt = data.replace(b"CORRECT", b"INCORRT")
    for candidate in (corrupt, data[:-4], b"PK\x03\x04", data[:40]):
        with pytest.raises(engine.CodesysError):
            engine.analyze_bytes(candidate)


def test_zip_directory_preflight_rejects_before_zipinfo_allocation(monkeypatch):
    # Offsets come from PKWARE APPNOTE: EOCD count +8/+10, size +12,
    # offset +16; central file header name/extra/comment lengths +28/+30/+32.
    original = zip_fixture([("first", b"x"), ("second", b"y")])
    eocd = original.rindex(b"PK\x05\x06")
    central = original.index(b"PK\x01\x02")
    candidates = []
    for alleged_count in (0, 257, 0xffff):
        damaged = bytearray(original)
        struct.pack_into("<HH", damaged, eocd + 8, alleged_count, alleged_count)
        candidates.append(bytes(damaged))
    wrong_extent = bytearray(original)
    struct.pack_into("<L", wrong_extent, eocd + 16, central + 1)
    candidates.append(bytes(wrong_extent))
    wrong_record_length = bytearray(original)
    struct.pack_into("<H", wrong_record_length, central + 28, 65535)
    candidates.append(bytes(wrong_record_length))
    multi_volume = bytearray(original)
    struct.pack_into("<H", multi_volume, eocd + 4, 1)
    candidates.append(bytes(multi_volume))
    candidates.append(original + b"trailing bytes")
    constructed = []

    def forbidden_constructor(*args, **kwargs):
        constructed.append(True)
        raise AssertionError("ZipFile must not be constructed for invalid directory")

    monkeypatch.setattr(engine.zipfile, "ZipFile", forbidden_constructor)
    for damaged in candidates:
        with pytest.raises(engine.CodesysError):
            engine.analyze_bytes(damaged)
    assert constructed == []
    # A false count must not bypass the cap on ACTUAL directory records.
    monkeypatch.setattr(engine, "MAX_MEMBERS", 1)
    with pytest.raises(engine.CodesysError, match="member count"):
        engine.analyze_bytes(candidates[0])
    assert constructed == []


def test_empty_zip_directory_and_comment():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.comment = b"offline project archive"
    result = engine.analyze_bytes(output.getvalue())
    assert result["archive"]["members"] == []
    assert result["archive"]["comment_hex"] == b"offline project archive".hex()


def test_duplicate_members_and_resource_limits(monkeypatch):
    with pytest.warns(UserWarning, match="Duplicate name"):
        duplicated = zip_fixture([("same", b"x"), ("same", b"y")])
    with pytest.raises(engine.CodesysError, match="duplicate"):
        engine.analyze_bytes(duplicated)
    monkeypatch.setattr(engine, "MAX_MEMBER", 8)
    with pytest.raises(engine.CodesysError, match="member size"):
        engine.analyze_bytes(zip_fixture([("large", b"x" * 9)]))
    monkeypatch.setattr(engine, "MAX_MEMBERS", 1)
    with pytest.raises(engine.CodesysError, match="member count"):
        engine.analyze_bytes(zip_fixture([("a", b"x"), ("b", b"y")]))


def test_aggregate_expansion_and_evidence_limits(monkeypatch):
    monkeypatch.setattr(engine, "MAX_EXPANDED", 10)
    with pytest.raises(engine.CodesysError, match="expansion"):
        engine.analyze_bytes(zip_fixture([("a", b"1" * 6), ("b", b"2" * 6)]))
    monkeypatch.setattr(engine, "MAX_STRINGS", 2)
    result = engine.analyze_bytes(b"AAAA\x00BBBB\x00CCCC\x00")
    assert len(result["strings"]) == 2
    assert result["string_limit_reached"] is True
    monkeypatch.setattr(engine, "MAX_EVIDENCE", 5)
    with pytest.raises(engine.CodesysError, match="evidence"):
        engine.analyze_bytes(b"AAAA")


@pytest.mark.parametrize("payload", [
    b'<!DOCTYPE x [<!ENTITY a "secret">]><Symbolconfiguration><NodeList/></Symbolconfiguration>',
    b'<!DOCTYPE x SYSTEM "file:///etc/passwd"><Symbolconfiguration><NodeList/></Symbolconfiguration>',
    b'<Symbolconfiguration><NodeList><Node/></NodeList></Symbolconfiguration>',
    b'<Symbolconfiguration><NodeList/><NodeList/></Symbolconfiguration>',
    b'<Symbolconfiguration>', b'<wrong/>',
    ("<!DOCTYPE x [<!ENTITY a 'secret'>]><Symbolconfiguration><NodeList/></Symbolconfiguration>").encode("utf-16"),
    b'<Symbolconfiguration><NodeList>' + b'<Node name="x">' * 80 + b'</Node>' * 80 + b'</NodeList></Symbolconfiguration>',
])
def test_malformed_symbol_xml_fails_closed(payload):
    with pytest.raises(engine.CodesysError):
        engine.parse_symbol_xml(payload)


@pytest.mark.parametrize("payload", [b"[CmpApp", b"[]", b"broken line", b"=value", b"[CmpApp]\nA=\x00", b"\xff\xfe"])
def test_malformed_runtime_config_fails_closed(payload):
    with pytest.raises(engine.CodesysError):
        engine.parse_runtime_config(payload)


def test_file_and_cli_entrypoints(tmp_path, capsys):
    artifact = tmp_path / "MyApplication.Device.Application.xml"
    artifact.write_bytes(SYMBOL_XML)
    assert engine.analyze_file(artifact)["detail"]["symbols"][-1]["path"] == "Application.PLC_PRG.iCounter"
    assert engine.main([str(artifact)]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "codesys-symbolconfiguration"
    assert engine.main(["--help"]) == 0
    assert engine.main([]) == 2
    assert engine.main([str(tmp_path / "missing")]) == 2
    for path in (None, 3, [], tmp_path / "missing", tmp_path):
        with pytest.raises(engine.CodesysError):
            engine.analyze_file(path)


def test_fifo_refused_before_open(tmp_path, monkeypatch):
    fifo = tmp_path / "boot.app"
    os.mkfifo(fifo)
    opened = []

    def forbidden_open(*args, **kwargs):
        opened.append(True)
        raise AssertionError("nonregular files must be rejected before open")

    monkeypatch.setattr(engine.os, "open", forbidden_open)
    with pytest.raises(engine.CodesysError, match="regular local file"):
        engine.analyze_file(fifo)
    assert opened == []


@pytest.mark.parametrize("argv", [[None], [1], 1, object()])
def test_malformed_cli_types_return_two(argv):
    assert engine.main(argv) == 2


@pytest.mark.parametrize("value", [None, "text", 1, [], {}, object(), bytearray(b"text"), b""])
def test_public_parser_type_and_empty_contract(value):
    for function in (engine.analyze_bytes, engine.parse_symbol_xml, engine.parse_runtime_config):
        with pytest.raises(engine.CodesysError):
            function(value)
    if not isinstance(value, str):
        with pytest.raises(engine.CodesysError):
            engine.analyze_bytes(b"data", name=value)


def test_seeded_fail_closed_fuzz_public_parsers():
    rng = random.Random(0xC0DE535)
    for size in [0, 1, 2, 3, 4, 7, 8, 16, 31, 64, 128, 255]:
        for _ in range(10):
            candidate = rng.randbytes(size)
            for function in (engine.analyze_bytes, engine.parse_symbol_xml, engine.parse_runtime_config):
                try:
                    function(candidate)
                except engine.CodesysError:
                    pass
            for prefix in (b"PK\x03\x04", b"<Symbolconfiguration>", b"[CmpApp]\n"):
                try:
                    engine.analyze_bytes(prefix + candidate, name="fuzz.project")
                except engine.CodesysError:
                    pass
