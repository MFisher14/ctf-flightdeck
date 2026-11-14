"""Independent vectors for the mobile2 Android storage extension.

Oracles are hand-authored AOSP XML, literal protobuf bytes from the published wire
grammar, and a dynamic ``google.protobuf`` class built from AndroidX's published
``preferences.proto`` schema.  The engine has no encoder and supplies none of the
expected bytes below.
"""
from __future__ import annotations

import json
import random
import struct

import pytest
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

import mobile2_android_storage as storage
import wire_decode


def _varint(value: int) -> bytes:
    """Small independent protobuf varint encoder used only by fixtures."""
    if value < 0:
        value &= (1 << 64) - 1
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _length_field(number: int, payload: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(payload)) + payload


def _map_entry(key: str, value: bytes) -> bytes:
    return _length_field(1, key.encode()) + _length_field(2, value)


def _preference(key: str, value: bytes) -> bytes:
    return _length_field(1, _map_entry(key, value))


def _oracle_class():
    """Build the current AndroidX schema without importing engine definitions."""
    field = descriptor_pb2.FieldDescriptorProto
    file_desc = descriptor_pb2.FileDescriptorProto(
        name="androidx_preferences.proto", package="androidx.oracle", syntax="proto2"
    )

    string_set = file_desc.message_type.add()
    string_set.name = "StringSet"
    item = string_set.field.add()
    item.name = "strings"
    item.number = 1
    item.label = field.LABEL_REPEATED
    item.type = field.TYPE_STRING

    value = file_desc.message_type.add()
    value.name = "Value"
    choice = value.oneof_decl.add()
    choice.name = "value"
    alternatives = (
        ("boolean", 1, field.TYPE_BOOL, None),
        ("float", 2, field.TYPE_FLOAT, None),
        ("integer", 3, field.TYPE_INT32, None),
        ("long", 4, field.TYPE_INT64, None),
        ("string", 5, field.TYPE_STRING, None),
        ("string_set", 6, field.TYPE_MESSAGE, ".androidx.oracle.StringSet"),
        ("double", 7, field.TYPE_DOUBLE, None),
        ("bytes", 8, field.TYPE_BYTES, None),
    )
    for name, number, kind, type_name in alternatives:
        member = value.field.add()
        member.name = name
        member.number = number
        member.label = field.LABEL_OPTIONAL
        member.type = kind
        member.oneof_index = 0
        if type_name is not None:
            member.type_name = type_name

    preference_map = file_desc.message_type.add()
    preference_map.name = "PreferenceMap"
    entry = preference_map.nested_type.add()
    entry.name = "PreferencesEntry"
    entry.options.map_entry = True
    key_field = entry.field.add()
    key_field.name = "key"
    key_field.number = 1
    key_field.label = field.LABEL_OPTIONAL
    key_field.type = field.TYPE_STRING
    value_field = entry.field.add()
    value_field.name = "value"
    value_field.number = 2
    value_field.label = field.LABEL_OPTIONAL
    value_field.type = field.TYPE_MESSAGE
    value_field.type_name = ".androidx.oracle.Value"
    map_field = preference_map.field.add()
    map_field.name = "preferences"
    map_field.number = 1
    map_field.label = field.LABEL_REPEATED
    map_field.type = field.TYPE_MESSAGE
    map_field.type_name = ".androidx.oracle.PreferenceMap.PreferencesEntry"

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_desc)
    return message_factory.GetMessageClass(
        pool.FindMessageTypeByName("androidx.oracle.PreferenceMap")
    )


def test_shared_preferences_types_duplicates_and_effective_state():
    raw = b"""<?xml version="1.0" encoding="utf-8"?>
<map>
  <string name="token">old</string>
  <int name="count" value="-17"/>
  <long name="large" value="4294967296"/>
  <float name="ratio" value="1.25"/>
  <boolean name="enabled" value="TRUE"/>
  <set name="servers"><string>one</string><string>one</string><string>two</string></set>
  <string name="token">CSCTF{last_wins}</string>
</map>"""
    report = storage.parse_shared_preferences(raw, source="settings.xml")

    assert report["entry_count"] == 7
    assert [entry["name"] for entry in report["entries"]] == [
        "token", "count", "large", "ratio", "enabled", "servers", "token"
    ]
    assert report["entries"][5]["value"] == ["one", "one", "two"]
    assert report["duplicates"] == [{
        "name": "token", "entry_indices": [0, 6], "effective_entry_index": 6
    }]
    assert report["effective"] == {
        "token": "CSCTF{last_wins}", "count": -17, "large": 4294967296,
        "ratio": 1.25, "enabled": True, "servers": ["one", "two"],
    }


def test_shared_preferences_backup_is_authoritative_without_merging():
    main = b'<map><string name="state">new-main</string><int name="only_main" value="1"/></map>'
    backup = b'<map><string name="state">old-backup</string></map>'
    report = storage.analyze_shared_preferences(main, backup)

    assert report["authoritative_source"] == "backup"
    assert report["main_discarded_on_next_load"] is True
    assert report["main"]["effective"]["only_main"] == 1
    assert report["effective"] == {"state": "old-backup"}
    assert "renames .bak to main" in report["aosp_recovery_rule"]


@pytest.mark.parametrize("raw", [
    b'<!DOCTYPE map [<!ENTITY x "boom">]><map><string name="x">&x;</string></map>',
    b'<map><int name="x" value="nope"/></map>',
    b'<map><int name="x" value="2147483648"/></map>',
    b'<map><boolean name="x" value="truthy"/></map>',
    b'<map><string>missing name</string></map>',
    b'<map><set name="x"><int value="1"/></set></map>',
    b'<map><string name="x"><string>nested</string></string></map>',
    b'<map><double name="x" value="1.0"/></map>',
    b'<map><broken></map>',
])
def test_shared_preferences_malformed_input_uses_declared_error(raw):
    with pytest.raises(storage.Mobile2AndroidStorageError):
        storage.parse_shared_preferences(raw)


def test_published_protobuf_vector_and_literal_datastore_values():
    # protobuf.dev's published field-1 int32(150) example is 08 96 01.
    published = bytes.fromhex("08 96 01")
    assert wire_decode.decode_protobuf(published) == [{
        "field": 1, "wire_type": 0, "wire_name": "varint", "value": 150
    }]
    # It is not the length-delimited map field required by PreferenceMap, so it
    # remains unknown rather than being assigned an invented preference meaning.
    unknown = storage.decode_preferences_datastore(published)
    assert unknown["entry_count"] == 0
    assert unknown["unknown_outer_fields"][0]["value"] == 150

    # Published-schema literals independently hand-packed in the research phase.
    theme = bytes.fromhex("0a0f0a057468656d6512062a046461726b")
    count = bytes.fromhex("0a0b0a05636f756e7412021807")
    assert storage.decode_preferences_datastore(theme)["effective"] == {
        "theme": {"type": "string", "value": "dark"}
    }
    assert storage.decode_preferences_datastore(count)["effective"] == {
        "count": {"type": "integer", "value": 7}
    }


def test_preferences_datastore_all_eight_types_against_real_protobuf():
    oracle_type = _oracle_class()
    oracle = oracle_type()
    oracle.preferences["bool"].boolean = True
    oracle.preferences["float"].float = 1.25
    oracle.preferences["integer"].integer = -7
    oracle.preferences["long"].long = -(1 << 40)
    oracle.preferences["string"].string = "snowman \u2603"
    oracle.preferences["set"].string_set.strings.extend(["a", "a", "b"])
    oracle.preferences["double"].double = -0.125
    oracle.preferences["bytes"].bytes = b"\x00\xff"
    raw = oracle.SerializeToString(deterministic=True)

    # The independent library must round-trip its own bytes before comparison.
    round_trip = oracle_type.FromString(raw)
    assert round_trip == oracle
    report = storage.decode_preferences_datastore(raw)
    assert report["valid_for_androidx_serializer"] is True
    assert report["effective"] == {
        "bool": {"type": "boolean", "value": True},
        "float": {"type": "float", "value": 1.25},
        "integer": {"type": "integer", "value": -7},
        "long": {"type": "long", "value": -(1 << 40)},
        "string": {"type": "string", "value": "snowman \u2603"},
        "set": {"type": "string_set", "value": {
            "strings": ["a", "a", "b"],
            "effective_strings": ["a", "b"],
            "unknown_fields": [],
        }},
        "double": {"type": "double", "value": -0.125},
        "bytes": {"type": "bytes", "value": {"length": 2, "hex": "00ff"}},
    }


def test_duplicate_map_keys_and_merged_oneof_occurrences():
    # Concatenating two complete messages is protobuf's defined merge operation.
    first = _preference("same", bytes.fromhex("2a056669727374"))
    second = _preference("same", bytes.fromhex("2a067365636f6e64"))
    duplicate = storage.decode_preferences_datastore(first + second)
    assert duplicate["duplicate_map_keys"] == [{
        "key": "same", "entry_indices": [0, 1], "effective_entry_index": 1
    }]
    assert duplicate["effective"]["same"] == {"type": "string", "value": "second"}

    # A singular message field merges repeated wire occurrences.  The empty
    # second Value must not erase the boolean from the first Value.
    entry = _length_field(1, b"x") + _length_field(2, b"\x08\x01") + _length_field(2, b"")
    merged_raw = _length_field(1, entry)
    oracle = _oracle_class().FromString(merged_raw)
    assert oracle.preferences["x"].WhichOneof("value") == "boolean"
    assert oracle.preferences["x"].boolean is True
    merged = storage.decode_preferences_datastore(merged_raw)
    assert merged["entries"][0]["duplicate_value_fields"] is True
    assert merged["effective"]["x"] == {"type": "boolean", "value": True}

    # Different alternatives across merged Values retain the conflict evidence,
    # while the oneof's final occurrence is effective.
    conflict_entry = (_length_field(1, b"x") + _length_field(2, b"\x08\x01")
                      + _length_field(2, b"\x2a\x01y"))
    conflict = storage.decode_preferences_datastore(_length_field(1, conflict_entry))
    value = conflict["entries"][0]["value"]
    assert [item["type"] for item in value["members"]] == ["boolean", "string"]
    assert value["oneof_conflict"] is True
    assert conflict["effective"]["x"] == {"type": "string", "value": "y"}


def test_value_without_oneof_is_reported_as_serializer_invalid():
    raw = _preference("unset", b"\x48\x7b")  # unknown Value field 9 = 123
    report = storage.decode_preferences_datastore(raw)
    assert report["valid_for_androidx_serializer"] is False
    assert report["effective"] == {}
    value = report["entries"][0]["value"]
    assert value["effective"] is None
    assert value["unknown_fields"][0]["field"] == 9


@pytest.mark.parametrize("path,role,schema_required", [
    ("files/datastore/settings.preferences_pb", "preferences-datastore", False),
    ("files/datastore/settings.preferences_pb.tmp", "atomic-write-temporary", False),
    ("files/datastore/settings.pb.tmp", "atomic-write-temporary", True),
    ("files/datastore/settings.pb.lock", "multiprocess-lock", False),
    ("files/datastore/settings.pb.version", "multiprocess-version", False),
    ("files/datastore/settings.pb", "custom-datastore-candidate", True),
])
def test_datastore_path_roles(path, role, schema_required):
    report = storage.classify_datastore_path(path)
    assert report["role"] == role
    assert report["schema_required"] is schema_required
    if schema_required:
        assert report["unknown_schema_plan"]["engine"] == "wire_decode.py"
        assert "do not invent" in report["unknown_schema_plan"]["warning"]
    else:
        assert report["unknown_schema_plan"] is None


@pytest.mark.parametrize("raw", [
    bytes.fromhex("08 80"),                 # truncated varint
    bytes.fromhex("12 05 61"),              # LEN extends beyond input
    bytes.fromhex("00"),                    # field zero
    bytes.fromhex("0e"),                    # reserved wire type 6
    bytes.fromhex("0b 14"),                 # mismatched/deprecated groups
    bytes.fromhex("08 80 80 80 80 80 80 80 80 80 80 02"),  # >64-bit varint
])
def test_malformed_datastore_wire_uses_declared_error(raw):
    with pytest.raises(storage.Mobile2AndroidStorageError):
        storage.decode_preferences_datastore(raw)


def test_seeded_malformed_inputs_never_leak_stdlib_exceptions():
    rng = random.Random(0xC5C7F)
    corpus = [b"", b"\xff", b"<map/>", bytes.fromhex("0a00")]
    corpus.extend(rng.randbytes(size) for size in range(1, 128))
    for parser in (storage.parse_shared_preferences, storage.decode_preferences_datastore):
        for raw in corpus:
            try:
                parser(raw)
            except Exception as exc:  # the contract is the assertion under test
                assert type(exc) is storage.Mobile2AndroidStorageError
    for bad in (None, 7, object(), "", "/", "bad\x00name"):
        with pytest.raises(storage.Mobile2AndroidStorageError):
            storage.classify_datastore_path(bad)


def test_guarded_cli_success_failure_and_argparse(tmp_path, capsys):
    main_path = tmp_path / "settings.xml"
    backup_path = tmp_path / "settings.xml.bak"
    store_path = tmp_path / "settings.preferences_pb"
    main_path.write_bytes(b'<map><string name="v">main</string></map>')
    backup_path.write_bytes(b'<map><string name="v">backup</string></map>')
    store_path.write_bytes(bytes.fromhex("0a0f0a057468656d6512062a046461726b"))

    assert storage.main(["shared-prefs", str(main_path), "--backup", str(backup_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["authoritative_source"] == "backup"
    assert report["effective"] == {"v": "backup"}

    assert storage.main(["preferences-datastore", str(store_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["effective"]["theme"] == {"type": "string", "value": "dark"}

    assert storage.main(["classify", "files/datastore/x.pb.lock"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["artifacts"][0]["role"] == "multiprocess-lock"

    main_path.write_bytes(b"<map><broken>")
    assert storage.main(["shared-prefs", str(main_path)]) == 2
    assert "invalid shared-preference XML" in capsys.readouterr().err
    assert storage.main([]) == 2
    assert storage.main(["--not-an-option"]) == 2
    capsys.readouterr()
    assert storage.main(["--help"]) == 0

