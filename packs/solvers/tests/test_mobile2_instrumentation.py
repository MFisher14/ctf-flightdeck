"""Deterministic tests for the offline Frida/Objection artifact profiler.

Configuration expectations come from Frida's published Gadget documentation:
https://frida.re/docs/gadget/ . ZIP fixtures are independently produced by the
stdlib and scripts are inert hand-authored text; none is executed or extracted.
"""
from __future__ import annotations

import io
import json
import random
import zipfile

import pytest

import mobile2_instrumentation as m


def _zip(entries, *, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name, body in entries:
            archive.writestr(name, body)
    return stream.getvalue()


def test_official_default_listen_semantics_and_secret_redaction():
    report = m.parse_gadget_config(b"{}")
    assert report["interaction"] == {
        "type": "listen",
        "address": "127.0.0.1",
        "port": 27042,
        "on_port_conflict": "fail",
        "on_load": "wait",
        "tls_configured": False,
        "authentication_configured": False,
        "origin_restricted": False,
        "serves_asset_root": False,
        "unknown_keys": [],
    }
    assert report["behavior"] == {
        "network": "listen",
        "endpoint": "127.0.0.1:27042",
        "exposure": "loopback",
        "blocks_on_load": True,
        "runtime_activation": "unverified",
    }
    assert report["default_interaction_used"] is True
    assert set(report["defaulted_fields"]) == {
        "teardown", "runtime", "code_signing", "interaction.address", "interaction.port",
        "interaction.on_port_conflict", "interaction.on_load",
    }

    configured = m.parse_gadget_config(json.dumps({
        "teardown": "full",
        "runtime": "v8",
        "code_signing": "required",
        "interaction": {
            "type": "listen", "address": "0.0.0.0", "port": 31337,
            "on_port_conflict": "pick-next", "on_load": "resume",
            "certificate": "CERTIFICATE-MATERIAL", "token": "CSCTF{not_printed}",
            "origin": "https://controller.invalid", "asset_root": "assets",
        },
    }).encode())
    assert configured["interaction"]["tls_configured"] is True
    assert configured["interaction"]["authentication_configured"] is True
    assert configured["behavior"]["exposure"] == "non-loopback-or-named"
    assert configured["behavior"]["blocks_on_load"] is False
    assert configured["interceptor_api_configured_available"] is False
    assert configured["defaults_used"] is False
    serialized = json.dumps(configured)
    assert "CERTIFICATE-MATERIAL" not in serialized
    assert "CSCTF{not_printed}" not in serialized


def test_official_connect_script_and_script_directory_semantics():
    connect = m.parse_gadget_config(json.dumps({
        "interaction": {"type": "connect", "acl": ["team-a", "team-b"]},
    }).encode())
    assert connect["interaction"]["address"] == "127.0.0.1"
    assert connect["interaction"]["port"] == 27052
    assert connect["interaction"]["acl"] == ["team-a", "team-b"]
    assert connect["behavior"] == {
        "network": "outbound-connect",
        "endpoint": "127.0.0.1:27052",
        "destination_role": "frida-portal cluster interface",
        "runtime_activation": "unverified",
    }

    script = m.parse_gadget_config(json.dumps({
        "interaction": {
            "type": "script", "path": "libfrida-gadget.script.so",
            "parameters": {"challenge": "fixture"}, "on_change": "reload",
        },
    }).encode())
    assert script["interaction"]["parameters"] == {"challenge": "fixture"}
    assert script["behavior"] == {
        "network": "none-by-interaction",
        "loads_script": "libfrida-gadget.script.so",
        "reloads_on_change": True,
        "runs_before_entrypoint": True,
        "runtime_activation": "unverified",
    }

    directory = m.parse_gadget_config(json.dumps({
        "interaction": {"type": "script-directory", "path": "scripts", "on_change": "rescan"},
    }).encode())
    assert directory["behavior"] == {
        "network": "none-by-interaction",
        "loads_script_directory": "scripts",
        "rescans_on_change": True,
        "runtime_activation": "unverified",
    }


@pytest.mark.parametrize("value", [
    b"null",
    b"[]",
    b'{"interaction":{}}',
    b'{"interaction":{"type":"unknown"}}',
    b'{"interaction":{"type":"listen","address":""}}',
    b'{"interaction":{"type":"listen","port":true}}',
    b'{"interaction":{"type":"listen","on_load":"later"}}',
    b'{"interaction":{"type":"connect","acl":[1]}}',
    b'{"interaction":{"type":"script"}}',
    b'{"interaction":{"type":"script-directory"}}',
    b'{"interaction":{},"interaction":{}}',
    b'{"runtime":NaN}',
    b"\xff",
])
def test_malformed_gadget_configs_fail_with_declared_error(value):
    with pytest.raises(m.Mobile2InstrumentationError):
        m.parse_gadget_config(value)


def test_frida_javascript_fingerprints_are_byte_independent_and_not_executed():
    source = (
        "Java.perform(function () {\n"
        "  const C = Java.use('example.Challenge');\n"
        "  C.answer.implementation = function () { throw new Error('must never execute'); };\n"
        "});\n"
        "rpc.exports = {};\n"
        "Interceptor.attach(Module.getGlobalExportByName('open'), {});\n"
    )
    report = m.profile_script(source.encode(), path="agent.js")
    by_api = {item["api"]: item for item in report["fingerprints"]}
    assert set(by_api) == {
        "java-perform", "java-use", "java-implementation", "interceptor-attach",
        "module-lookup", "rpc-exports",
    }
    assert by_api["java-perform"]["offsets"] == [source.index("Java.perform")]
    assert by_api["interceptor-attach"]["offsets"] == [source.index("Interceptor.attach")]
    assert report["likely_frida_script"] is True
    assert report["platform_hints"] == ["android-java", "native"]
    assert report["runtime_activation"] == "unverified"

    weak = m.profile_script(b"function ordinary() { send(value); }")
    assert [item["api"] for item in weak["fingerprints"]] == ["frida-send"]
    assert weak["likely_frida_script"] is False


def test_fingerprint_offsets_and_counts_are_bounded(monkeypatch):
    monkeypatch.setattr(m, "MAX_HITS", 3)
    report = m.profile_script(("Java.use('X');" * 20 + "Java.perform(function(){});").encode())
    item = next(hit for hit in report["fingerprints"] if hit["api"] == "java-use")
    assert item["count"] == 20
    assert len(item["offsets"]) == 3
    assert item["offsets_truncated"] is True


def test_android_objection_archive_correlates_companions_without_extraction(monkeypatch):
    config = json.dumps({
        "interaction": {"type": "script", "path": "libfrida-gadget.script.so"},
    }).encode()
    script = b"Java.perform(function(){ Java.use('C').m.implementation = function(){}; });"
    smali = (b'const-string v0, "frida-gadget"\n'
             b'invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')
    archive = _zip([
        ("lib/arm64-v8a/libfrida-gadget.so", b"ELF fixture"),
        ("lib/arm64-v8a/libfrida-gadget.config.so", config),
        ("lib/arm64-v8a/libfrida-gadget.script.so", script),
        ("smali/example/MainActivity.smali", smali),
        ("res/xml/network_security_config.xml", b"<network-security-config/>")
    ], compression=zipfile.ZIP_DEFLATED)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("archive extraction must never be used")

    monkeypatch.setattr(zipfile.ZipFile, "extract", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "extractall", forbidden)
    report = m.inspect_archive(archive, container_name="challenge.objection.apk")
    assert report["confidence"] == "high"
    assert report["runtime_activation"].startswith("unverified")
    assert [item["role"] for item in report["libraries"]] == [
        "android-frida-gadget-objection-default-name"]
    assert report["configs"][0]["report"]["interaction"]["type"] == "script"
    assert report["scripts"][0]["report"]["likely_frida_script"] is True
    kinds = {item["kind"] for item in report["correlations"]}
    assert kinds == {
        "library-plus-config", "library-plus-script", "library-plus-load-reference",
        "objection-patch-correlation",
    }
    evidence = {item["kind"] for item in report["evidence"]}
    assert {"objection-output-name", "gadget-load-library", "valid-gadget-config"} <= evidence
    assert report["objection_artifacts"] == [{
        "path": "res/xml/network_security_config.xml",
        "role": "network-security-config",
        "strength": "weak",
    }]


def test_ios_gadget_archive_and_generic_script_are_not_called_objection():
    config = json.dumps({
        "interaction": {"type": "listen", "address": "127.0.0.1", "port": 27042,
                        "on_port_conflict": "fail", "on_load": "wait"},
    }).encode()
    script = b"rpc.exports = {}; Interceptor.attach(Module.getGlobalExportByName('open'), {});"
    archive = _zip([
        ("Payload/Demo.app/Frameworks/FridaGadget.dylib", b"Mach-O fixture"),
        ("Payload/Demo.app/FridaGadget.config", config),
        ("Payload/Demo.app/agent.js", script),
    ])
    report = m.inspect_archive(archive, container_name="Demo.ipa")
    assert report["confidence"] == "high"
    assert report["objection_artifacts"] == []
    assert not any(item["kind"].startswith("objection") for item in report["evidence"])
    assert report["behavior"][0]["endpoint"] == "127.0.0.1:27042"
    assert any(item["path"].endswith("agent.js") for item in report["scripts"])


@pytest.mark.parametrize("entries, expected_score", [
    ([('res/xml/network_security_config.xml', b'<x/>')], 3),
    ([('AndroidManifest.xml', b'android.permission.INTERNET 27042')], 0),
    ([('Frameworks/Gadget.dylib', b'ordinary')], 0),
])
def test_weak_or_collision_prone_signals_do_not_claim_instrumentation(entries, expected_score):
    report = m.inspect_archive(_zip(entries), container_name="ordinary.apk")
    assert report["score"] == expected_score
    assert report["confidence"] == {3: "low", 0: "none"}[expected_score]
    assert report["runtime_activation"].startswith("unverified")


def test_frida_default_name_alone_does_not_claim_objection():
    report = m.inspect_files({"lib/arm64-v8a/libfrida-gadget.so": b"ELF"})
    assert report["libraries"]
    assert report["objection_artifacts"] == []
    assert not any(item["kind"].startswith("objection") for item in report["evidence"])


@pytest.mark.parametrize("name", [
    "../escape.js",
    "/absolute/agent.js",
    "C:/absolute/agent.js",
    "safe/../../escape.js",
    "safe\\..\\escape.js",
])
def test_zip_paths_are_never_extractable(name):
    with pytest.raises(m.Mobile2InstrumentationError):
        m.inspect_archive(_zip([(name, b"rpc.exports={};")]))


def test_duplicate_normalized_zip_paths_are_rejected():
    raw = _zip([("assets/./agent.js", b"one"), ("assets/agent.js", b"two")])
    with pytest.raises(m.Mobile2InstrumentationError):
        m.inspect_archive(raw)


def test_archive_and_mapping_bounds(monkeypatch):
    monkeypatch.setattr(m, "MAX_ARCHIVE_EXPANDED", 10)
    with pytest.raises(m.Mobile2InstrumentationError):
        m.inspect_archive(_zip([("asset.bin", b"x" * 11)]))

    monkeypatch.setattr(m, "MAX_ARCHIVE_EXPANDED", 100)
    monkeypatch.setattr(m, "MAX_SCANNED_TOTAL", 4)
    with pytest.raises(m.Mobile2InstrumentationError):
        m.inspect_archive(_zip([("agent.js", b"x" * 5)]))

    monkeypatch.setattr(m, "MAX_MEMBER", 3)
    with pytest.raises(m.Mobile2InstrumentationError):
        m.inspect_files({"agent.js": b"1234"})

    monkeypatch.setattr(m, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(m.Mobile2InstrumentationError):
        m.inspect_files({"one": b"", "two": b""})


def test_corrupt_crc_truncation_and_noise_fail_closed():
    payload = b"rpc.exports={}; Interceptor.attach(ptr('0'), {});"
    valid = _zip([("agent.js", payload)])
    corrupt = bytearray(valid)
    payload_at = valid.index(payload)
    corrupt[payload_at] ^= 0x40
    invalid = [b"", b"PK", bytes(corrupt)]
    invalid.extend(valid[:size] for size in (1, 4, 12, 30, len(valid) - 1))
    invalid.extend(random.Random(0xC5C7F).randbytes(size) for size in (1, 8, 32, 128))
    for raw in invalid:
        with pytest.raises(m.Mobile2InstrumentationError):
            m.inspect_archive(raw)


def test_parser_prefixes_and_invalid_types_never_leak_stdlib_exceptions():
    config = b'{"interaction":{"type":"connect","address":"portal","port":27052}}'
    for raw in [config[:size] for size in range(len(config))] + [b"\xff" * 32]:
        try:
            m.parse_gadget_config(raw)
        except m.Mobile2InstrumentationError:
            pass

    released = memoryview(b"data")
    released.release()
    for parser in (m.parse_gadget_config, m.profile_script, m.inspect_archive):
        with pytest.raises(m.Mobile2InstrumentationError):
            parser(released)
    with pytest.raises(m.Mobile2InstrumentationError):
        m.inspect_files({"agent.js": object()})


def test_guarded_cli_config_archive_errors_and_help(tmp_path, capsys):
    config_path = tmp_path / "FridaGadget.config"
    config_path.write_bytes(b'{"interaction":{"type":"connect"}}')
    assert m.main([str(config_path), "--kind", "config"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["behavior"]["endpoint"] == "127.0.0.1:27052"

    archive_path = tmp_path / "sample.ipa"
    archive_path.write_bytes(_zip([
        ("Payload/A.app/Frameworks/FridaGadget.dylib", b"fixture"),
        ("Payload/A.app/FridaGadget.config", b"{}"),
    ]))
    assert m.main([str(archive_path)]) == 0
    assert json.loads(capsys.readouterr().out)["confidence"] == "high"

    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"not a zip")
    assert m.main([str(bad), "--kind", "archive"]) == 2
    assert "bounded readable ZIP" in capsys.readouterr().err
    assert m.main([]) == 2
    assert m.main(["--not-an-option"]) == 2
    assert m.main(["--help"]) == 0
