"""Independent vectors and fail-closed fuzz for mobile storage/instrumentation."""
from __future__ import annotations

import io
import json
import random
import zipfile

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
import pytest

import mobile2_android_storage as storage
import mobile2_instrumentation as instrumentation


def _preferences_oracle_class():
    field = descriptor_pb2.FieldDescriptorProto
    descriptor = descriptor_pb2.FileDescriptorProto(
        name="r3mob_preferences.proto", package="r3mob.oracle", syntax="proto2"
    )
    value = descriptor.message_type.add()
    value.name = "Value"
    value.oneof_decl.add().name = "value"
    for name, number, kind in (
        ("boolean", 1, field.TYPE_BOOL), ("string", 5, field.TYPE_STRING),
    ):
        member = value.field.add()
        member.name, member.number = name, number
        member.label, member.type, member.oneof_index = field.LABEL_OPTIONAL, kind, 0
    entry = descriptor.message_type.add()
    entry.name = "Entry"
    key = entry.field.add()
    key.name, key.number = "key", 1
    key.label, key.type = field.LABEL_OPTIONAL, field.TYPE_STRING
    item = entry.field.add()
    item.name, item.number = "value", 2
    item.label, item.type = field.LABEL_OPTIONAL, field.TYPE_MESSAGE
    item.type_name = ".r3mob.oracle.Value"
    preference_map = descriptor.message_type.add()
    preference_map.name = "PreferenceMap"
    repeated = preference_map.field.add()
    repeated.name, repeated.number = "preferences", 1
    repeated.label, repeated.type = field.LABEL_REPEATED, field.TYPE_MESSAGE
    repeated.type_name = ".r3mob.oracle.Entry"
    pool = descriptor_pool.DescriptorPool()
    pool.Add(descriptor)
    return message_factory.GetMessageClass(
        pool.FindMessageTypeByName("r3mob.oracle.PreferenceMap")
    )


def _zip(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in entries:
            archive.writestr(name, body)
    return output.getvalue()


def _only_declared(error, call) -> None:
    try:
        result = call()
    except Exception as exc:
        assert type(exc) is error
    else:
        assert result is None or isinstance(result, dict)


def test_vector_lock_shared_preferences_and_google_protobuf() -> None:
    xml = (b'<?xml version="1.0" encoding="utf-8"?>'
           b'<map><string name="route">north \xe2\x98\x83</string>'
           b'<boolean name="enabled" value="true"/></map>')
    import xml.etree.ElementTree as element_tree
    root = element_tree.fromstring(xml)
    expected = {root[0].attrib["name"]: root[0].text,
                root[1].attrib["name"]: root[1].attrib["value"] == "true"}
    assert storage.parse_shared_preferences(xml, source="settings.xml")["effective"] == expected

    backup = b'<map><string name="route">backup</string></map>'
    pair = storage.analyze_shared_preferences(xml, backup)
    assert pair["authoritative_source"] == "backup"
    assert pair["effective"] == {"route": "backup"}

    oracle_type = _preferences_oracle_class()
    oracle = oracle_type()
    first = oracle.preferences.add()
    first.key, first.value.boolean = "enabled", True
    second = oracle.preferences.add()
    second.key, second.value.string = "route", "north ☃"
    wire = oracle.SerializeToString(deterministic=True)
    assert oracle_type.FromString(wire) == oracle
    assert storage.decode_preferences_datastore(wire)["effective"] == {
        "enabled": {"type": "boolean", "value": True},
        "route": {"type": "string", "value": "north ☃"},
    }
    role = storage.classify_datastore_path("files/datastore/routes.preferences_pb.tmp")
    assert (role["role"], role["schema"], role["schema_required"]) == (
        "atomic-write-temporary", "androidx-preferences", False,
    )


def test_vector_lock_frida_config_script_and_stdlib_zip() -> None:
    config = json.dumps({"interaction": {
        "type": "connect", "address": "portal.example.invalid", "port": 27052,
        "certificate": "CERT-SECRET", "token": "TOKEN-SECRET", "acl": ["fleet"],
    }}).encode()
    parsed = instrumentation.parse_gadget_config(config)
    assert parsed["behavior"]["endpoint"] == "portal.example.invalid:27052"
    assert parsed["interaction"]["acl"] == ["fleet"]
    assert parsed["interaction"]["tls_configured"] is True
    assert parsed["interaction"]["authentication_configured"] is True
    assert "SECRET" not in json.dumps(parsed)

    script = (b"Java.perform(function () { Java.use('example.Route'); });\n"
              b"Interceptor.attach(Module.getGlobalExportByName('open'), {});\n")
    profile = instrumentation.profile_script(script, path="agent.js")
    counts = {item["api"]: item["count"] for item in profile["fingerprints"]}
    assert counts == {"java-perform": 1, "java-use": 1,
                      "interceptor-attach": 1, "module-lookup": 1}
    assert profile["platform_hints"] == ["android-java", "native"]

    entries = [
        ("lib/arm64-v8a/libgadget.so", b"inert"),
        ("assets/libgadget.config.so", b"{}"),
        ("assets/agent.js", script),
    ]
    supplied = instrumentation.inspect_files(dict(entries), container_name="fixture.apk")
    archived = instrumentation.inspect_archive(_zip(entries), container_name="fixture.apk")
    assert archived["member_count"] == supplied["member_count"] == len(entries)
    assert archived["libraries"] == supplied["libraries"]
    assert archived["configs"] == supplied["configs"]
    assert archived["scripts"] == supplied["scripts"]
    assert archived["confidence"] == supplied["confidence"] == "high"


@pytest.mark.parametrize("value", [b'{"interaction":{"type":[]}}',
                                   b'{"interaction":{"type":{}}}'])
def test_gadget_non_string_interaction_type_is_declared_error(value) -> None:
    with pytest.raises(instrumentation.Mobile2InstrumentationError):
        instrumentation.parse_gadget_config(value)


def test_fail_closed_android_storage_entrypoints(monkeypatch) -> None:
    oracle = _preferences_oracle_class()()
    item = oracle.preferences.add()
    item.key, item.value.string = "x", "value"
    wire = oracle.SerializeToString()
    xml = b'<map><string name="x">value</string></map>'
    corpus = [b"", random.Random(0x53544F52).randbytes(73), "💥".encode(),
              xml[:-1], wire[:-1], bytes([wire[0] ^ 0x80]) + wire[1:]]
    for raw in corpus:
        _only_declared(storage.Mobile2AndroidStorageError,
                       lambda: storage.parse_shared_preferences(raw))
        _only_declared(storage.Mobile2AndroidStorageError,
                       lambda: storage.analyze_shared_preferences(raw, raw))
        _only_declared(storage.Mobile2AndroidStorageError,
                       lambda: storage.decode_preferences_datastore(raw))
    for path in (None, b"bytes", "", "bad\0path", "💥" * (storage.MAX_PATH + 1)):
        _only_declared(storage.Mobile2AndroidStorageError,
                       lambda path=path: storage.classify_datastore_path(path))
    monkeypatch.setattr(storage, "MAX_INPUT", 32)
    for parser in (storage.parse_shared_preferences, storage.decode_preferences_datastore):
        with pytest.raises(storage.Mobile2AndroidStorageError):
            parser(b"x" * 33)
    assert storage.main([]) == 2
    assert storage.main(["--not-an-option"]) == 2


def test_fail_closed_instrumentation_entrypoints(monkeypatch) -> None:
    valid_zip = _zip([("agent.js", b"rpc.exports = {}; Interceptor.attach(ptr('0'), {});")])
    flipped = bytearray(valid_zip)
    flipped[len(flipped) // 2] ^= 0x80
    corpus = [b"", random.Random(0x46524944).randbytes(91), "💥".encode(),
              valid_zip[:11], valid_zip[:-1], bytes(flipped)]
    released = memoryview(b"released")
    released.release()
    corpus.append(released)
    for raw in corpus:
        for parser in (instrumentation.parse_gadget_config,
                       instrumentation.profile_script, instrumentation.inspect_archive):
            _only_declared(instrumentation.Mobile2InstrumentationError,
                           lambda parser=parser, raw=raw: parser(raw))
    for mapping in ({}, {"": b"x"}, {"../escape.js": b"x"},
                    {"agent.js": object()}, {"agent.js": b"\xff"}):
        _only_declared(instrumentation.Mobile2InstrumentationError,
                       lambda mapping=mapping: instrumentation.inspect_files(mapping))

    monkeypatch.setattr(instrumentation, "MAX_CONFIG", 8)
    monkeypatch.setattr(instrumentation, "MAX_SCRIPT", 8)
    monkeypatch.setattr(instrumentation, "MAX_INPUT", 8)
    monkeypatch.setattr(instrumentation, "MAX_MEMBER", 8)
    with pytest.raises(instrumentation.Mobile2InstrumentationError):
        instrumentation.parse_gadget_config(b'{"long":true}')
    with pytest.raises(instrumentation.Mobile2InstrumentationError):
        instrumentation.profile_script(b"x" * 9)
    with pytest.raises(instrumentation.Mobile2InstrumentationError):
        instrumentation.inspect_archive(valid_zip)
    with pytest.raises(instrumentation.Mobile2InstrumentationError):
        instrumentation.inspect_files({"agent.js": b"x" * 9})
    assert instrumentation.main([]) == 2
    assert instrumentation.main(["--not-an-option"]) == 2
