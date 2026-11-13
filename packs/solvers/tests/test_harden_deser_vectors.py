"""Independent serialization vectors and fail-closed hardening checks.

Oracle provenance:
* PHP and Ruby samples are produced by their installed real serializers.
* Java samples are produced by Java ObjectOutputStream/DataOutputStream.
* pickle and PyYAML samples are produced by the Python standard library/PyYAML.
* the minimal NRBF sample follows the published MS-NRBF record grammar.

No sample is ever loaded, restored, unmarshaled, or deserialized.
"""

from __future__ import annotations

import base64
import gzip
import os
import pickle
import pickletools
import random
import shutil
import socket
import struct
import subprocess
import urllib.request
from pathlib import Path

import pytest
import yaml

import deser_chain as passive
import deser_detect
import deser_gadgets
import deserialization_chains as chains
import java_deser


NRBF_STRING = bytes.fromhex(
    # SerializationHeaderRecord(root=1, header=-1, version=1.0),
    # BinaryObjectString(object=1, "safe"), MessageEnd.
    "00 01000000 ffffffff 01000000 00000000 06 01000000 04 73616665 0b"
)


def _run_oracle(argv: list[str], *, cwd: Path | None = None) -> bytes:
    if shutil.which(argv[0]) is None:
        pytest.skip(f"independent oracle runtime is unavailable: {argv[0]}")
    return subprocess.run(
        argv, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=30,
    ).stdout


@pytest.fixture(scope="session")
def vectors(tmp_path_factory):
    php_object = _run_oracle([
        "php", "-r",
        '$o=new stdClass();$o->flag="CSCTF{php_oracle}";$o->n=7;echo serialize($o);',
    ])
    php_simple = _run_oracle([
        "php", "-r", '$o=new stdClass();$o->x="safe";echo serialize($o);',
    ])
    php_empty = _run_oracle(["php", "-r", 'echo serialize("");'])
    ruby_hash = _run_oracle([
        "ruby", "-e",
        'STDOUT.binmode; print Marshal.dump({"flag" => "CSCTF{ruby_oracle}", "n" => 7})',
    ])
    ruby_float = _run_oracle([
        "ruby", "-e", "STDOUT.binmode; print Marshal.dump(1.5)",
    ])

    java_dir = tmp_path_factory.mktemp("harden_deser_java_oracle")
    source = java_dir / "SerializeOracle.java"
    source.write_text(
        r"""
import java.io.*;
import java.util.Base64;

public final class SerializeOracle {
    private static byte[] object(Object value) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        }
        return bytes.toByteArray();
    }
    private static byte[] utf(String value) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream out = new DataOutputStream(bytes)) {
            out.writeUTF(value);
        }
        return bytes.toByteArray();
    }
    private static void line(byte[] value) {
        System.out.println(Base64.getEncoder().encodeToString(value));
    }
    public static void main(String[] args) throws Exception {
        line(object("safe"));
        line(object(null));
        line(object("A\u0000\uD83D\uDE00"));
        line(utf("A\u0000\uD83D\uDE00"));
    }
}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    _run_oracle(["javac", str(source)], cwd=java_dir)
    java_lines = _run_oracle(["java", "-cp", str(java_dir), "SerializeOracle"], cwd=java_dir).splitlines()
    assert len(java_lines) == 4

    py_object = {"flag": "CSCTF{pickle_oracle}", "n": [1, 2]}
    pickles = {protocol: pickle.dumps(py_object, protocol=protocol) for protocol in range(6)}
    for stream in pickles.values():
        # pickletools is a symbolic opcode parser and never constructs objects.
        assert list(pickletools.genops(stream))[-1][0].name == "STOP"

    # Dumping a callable records its name; it does not call it. Loading is never used.
    yaml_unsafe_tag = yaml.dump(os.system).encode("utf-8")
    assert yaml_unsafe_tag.startswith(b"!!python/name:")

    return {
        "php_object": php_object,
        "php_simple": php_simple,
        "php_empty": php_empty,
        "ruby_hash": ruby_hash,
        "ruby_float": ruby_float,
        "java_string": base64.b64decode(java_lines[0], validate=True),
        "java_null": base64.b64decode(java_lines[1], validate=True),
        "java_special_string": base64.b64decode(java_lines[2], validate=True),
        "java_write_utf": base64.b64decode(java_lines[3], validate=True),
        "pickles": pickles,
        "yaml": yaml_unsafe_tag,
        "dotnet": NRBF_STRING,
    }


def _formats(rows):
    return {row["format"] for row in rows}


def test_deser_detect_real_serializer_vector_lock(vectors):
    assert _formats(deser_detect.detect(vectors["php_object"])) == {"php_object_injection"}
    assert _formats(deser_detect.detect(vectors["ruby_hash"])) == {"ruby_marshal"}
    assert _formats(deser_detect.detect(vectors["java_string"])) == {"java_serialized_stream"}
    assert _formats(deser_detect.detect(vectors["dotnet"])) == {"dotnet_binaryformatter"}
    assert _formats(deser_detect.detect(vectors["yaml"])) == {"unsafe_yaml"}
    for protocol in range(2, 6):
        rows = deser_detect.detect(vectors["pickles"][protocol])
        assert _formats(rows) == {"python_pickle"}
        assert f"protocol {protocol}" in rows[0]["note"]


def test_deser_detect_php_empty_string_vector(vectors):
    assert _formats(deser_detect.detect(vectors["php_empty"])) == {"php_serialized"}


@pytest.mark.parametrize("protocol", [0, 1])
def test_deser_detect_pickle_legacy_container_vectors(vectors, protocol):
    assert _formats(deser_detect.detect(vectors["pickles"][protocol])) == {"python_pickle"}


def test_deser_detect_ruby_float_vector(vectors):
    assert _formats(deser_detect.detect(vectors["ruby_float"])) == {"ruby_marshal"}


def test_deser_detect_transport_cookie_response_and_scan(vectors):
    java_b64 = base64.b64encode(vectors["java_string"])
    rows = deser_detect.detect(java_b64, "cookie")
    assert any(row["format"] == "java_serialized_stream"
               and row["outer_encoding"] == ["base64"] for row in rows)

    scanned = deser_detect.scan({"php": vectors["php_object"], "java": java_b64})
    assert scanned["flag"] is None
    assert scanned["has_serialized"] is True
    assert {row["format"] for row in scanned["findings"]} >= {
        "php_object_injection", "java_serialized_stream",
    }
    assert all(row["source"] in {"php", "java"} for row in scanned["findings"])

    cookie = deser_detect.scan_cookies(b"Set-Cookie: session=" + java_b64 + b"; Path=/; HttpOnly")
    assert cookie["has_serialized"] is True
    assert any(row["format"] == "java_serialized_stream" for row in cookie["findings"])

    html = b'<input type="hidden" name="state" value="' + java_b64 + b'">'
    response = deser_detect.from_response(html, "saved.html")
    assert response["has_serialized"] is True
    assert response["findings"][0]["source"] == "saved.html#input:state"


def _phar_with_metadata(metadata: bytes) -> bytes:
    # PHP PHAR manifest layout: count, API version, flags, alias length,
    # alias, global-metadata length, serialized metadata.
    body = struct.pack("<IHII", 0, 0x0011, 0, 0)
    body += struct.pack("<I", len(metadata)) + metadata
    return b"<?php __HALT_COMPILER(); ?>\r\n" + struct.pack("<I", len(body)) + body


def test_passive_structural_parsers_against_real_and_documented_vectors(vectors):
    php = passive.parse_php(vectors["php_object"])
    assert php["format"] == "php" and php["complete"] is True
    assert php["classes"] == ["stdClass"]
    assert php["root"][0] == "stdClass"
    assert set(php["root"][1]) == {"flag", "n"}
    assert php["root"][2] == 2

    java = passive.parse_java(vectors["java_string"])
    assert java == {
        "format": "java", "complete": True, "classes": [], "serial_uids": {},
        "object_count": 0, "string_count": 1, "strings": ["safe"],
        "root_class": None, "class_count": 0,
    }

    dotnet = passive.parse_dotnet(vectors["dotnet"])
    assert dotnet["format"] == "dotnet" and dotnet["complete"] is True
    assert dotnet["strings"] == ["safe"]
    assert dotnet["record_count"] == 3
    assert dotnet["_consumed"] == len(vectors["dotnet"])

    phar = passive.parse_phar(_phar_with_metadata(vectors["php_object"]))
    assert phar["has_phar"] is True
    assert phar["phar_files"] == 0
    assert phar["classes"] == ["stdClass"]

    assert passive.classify(vectors["php_object"])["format"] == "php"
    java64 = base64.b64encode(vectors["java_string"])
    assert passive.classify(java64)["outer_encoding"] == ["base64"]
    for protocol in range(2, 6):
        assert passive.looks_like_pickle(vectors["pickles"][protocol]) is True
    assert passive.looks_like_pickle(vectors["pickles"][0]) is False


def test_passive_java_null_stream_vector(vectors):
    report = passive.parse_java(vectors["java_null"])
    assert report is not None
    assert report["format"] == "java" and report["complete"] is True


def test_passive_java_modified_utf8_vector(vectors):
    report = passive.parse_java(vectors["java_special_string"])
    assert report["complete"] is True
    assert report["strings"] == ["A\x00😀"]


def test_passive_java_dangling_reference_is_incomplete():
    # Oracle: Java serialization grammar permits TC_REFERENCE only for a prior handle.
    report = passive.parse_java(bytes.fromhex("aced0005 71 12345678"))
    assert report["complete"] is False


def test_passive_dotnet_requires_message_end():
    # SerializationHeaderRecord alone; MS-NRBF MessageEnd (record 11) is absent.
    header_only = bytes.fromhex("00 01000000 ffffffff 01000000 00000000")
    assert passive.parse_dotnet(header_only)["complete"] is False


def test_static_chain_analyzer_finds_real_vectors(vectors):
    expected = [
        (vectors["php_object"], "php_pop", "serialized_object_grammar"),
        (vectors["pickles"][4], "python_pickle", "pickle_protocol_magic"),
        (vectors["yaml"], "python_pyyaml", "python_object_tag"),
        (vectors["ruby_hash"], "ruby_marshal", "marshal_stream_magic"),
        (vectors["java_string"], "java_serialization", "java_stream_magic"),
        (vectors["dotnet"], "dotnet_serialization", "binaryformatter_stream_header"),
    ]
    for raw, family, kind in expected:
        result = chains.analyze_artifact(raw, source="oracle.bin")
        assert family in result.families
        assert any(row.kind == kind and row.source == "oracle.bin" for row in result.findings)
        assert result.offline is True
        assert result.deserialized is result.executed is False
        assert result.bytes_inspected == len(raw)


def test_static_chain_plans_remain_inert_metadata():
    assert chains.normalize_family("java") == "java_serialization"
    plans = chains.build_chain_plans(
        "java", marker="SAFE_MARKER",
        observed_components=["org.apache.commons.collections Transformer"],
    )
    assert plans[0].candidate == "commons_collections_metadata"
    assert plans[0].confidence == "evidence_supported"
    assert all(plan.inert and plan.offline and not plan.serialized_payload
               and not plan.executable for plan in plans)
    catalog = chains.plan_catalog(marker="SAFE_MARKER")
    assert {plan.family for plan in catalog} == set(chains.FAMILIES)


def test_gadget_source_detection_and_php_builder_oracle(vectors):
    assert deser_gadgets.analyze_source is deser_gadgets.synthesize
    assert deser_gadgets.synthesize_gadgets is deser_gadgets.synthesize
    source = r"""
    <?php unserialize($blob); function __destruct() {} ?>
    yaml.load(blob, Loader=yaml.UnsafeLoader); def __reduce__(self): pass
    Marshal.load(blob); def marshal_load(x); end
    new BinaryFormatter(); JsonConvert.DeserializeObject(x, settings)
    new ObjectInputStream(input).readObject(); // commons-collections
    """
    detected = deser_gadgets.detect_languages(source)
    assert set(detected) == {"php", "python", "ruby", "dotnet", "java"}
    result = deser_gadgets.synthesize(
        source, "printf SAFE_MARKER", ["php", "python", "ruby", "dotnet", "java"],
    )
    assert result["detected"] == detected
    assert result["offline"] is True
    assert result["deserialized"] is result["executed"] is False
    assert result["network_requests"] == 0
    assert result["candidates"]
    assert all(row["candidate_only"] and row["offline"] and not row["executed"]
               for row in result["candidates"])

    # Real PHP serialize() is the oracle for this byte-length-sensitive builder.
    assert deser_gadgets.php_serialize_object("stdClass", {"x": "safe"}) == vectors["php_simple"].decode()


def test_gadget_synthesize_declared_error_contract():
    with pytest.raises(deser_gadgets.DeserInputError):
        deser_gadgets.synthesize("x", languages=1)


def test_chain_analyzer_declared_error_contract():
    with pytest.raises(chains.DeserializationInputError):
        chains.analyze_artifact("\ud800")


def test_java_deser_pure_helpers_against_java_and_standard_codecs(vectors):
    # DataOutput.writeUTF prefixes its modified UTF-8 bytes with a big-endian u16.
    java_utf = vectors["java_write_utf"]
    length = struct.unpack(">H", java_utf[:2])[0]
    assert length == len(java_utf) - 2
    assert java_deser.mutf8("A\x00😀") == java_utf[2:]

    raw = vectors["java_string"]
    assert java_deser.java_encode(raw, "raw") == raw
    assert java_deser.java_encode(raw, "base64") == base64.b64encode(raw).decode()
    assert java_deser.java_encode(raw, "base64url") == base64.urlsafe_b64encode(raw).decode()
    assert java_deser.java_encode(raw, "hex") == raw.hex()
    encoded_gzip = java_deser.java_encode(raw, "gzip")
    assert gzip.decompress(encoded_gzip) == raw
    assert encoded_gzip[4:8] == b"\x00\x00\x00\x00"
    assert base64.b64decode(java_deser.java_encode(raw, "gzip_base64")) == encoded_gzip


def test_detection_paths_never_call_load_execute_process_or_network(vectors, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("detector attempted deserialization, execution, process launch, or network I/O")

    # Vectors are generated before these guards are installed.
    for module, names in (
        (pickle, ("load", "loads")),
        (yaml, ("load", "load_all", "full_load", "unsafe_load")),
        (subprocess, ("run", "Popen", "call", "check_call", "check_output")),
        (os, ("system", "popen")),
        (urllib.request, ("urlopen",)),
    ):
        for name in names:
            if hasattr(module, name):
                monkeypatch.setattr(module, name, forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)

    samples = [
        vectors["php_object"], vectors["ruby_hash"], vectors["java_string"],
        vectors["dotnet"], vectors["pickles"][4], vectors["yaml"],
    ]
    for raw in samples:
        deser_detect.detect(raw)
        deser_detect.scan({"sample": raw})
        deser_detect.scan_cookies(b"sample=" + base64.b64encode(raw))
        deser_detect.from_response(b'<input type="hidden" value="' + base64.b64encode(raw) + b'">')
        passive.classify(raw)
        chains.analyze_artifact(raw)
    result = deser_gadgets.synthesize(
        "unserialize($x); pickle.loads(x); Marshal.load(x); BinaryFormatter; ObjectInputStream",
        languages=["php", "python", "ruby", "dotnet", "java"],
    )
    assert result["deserialized"] is result["executed"] is False
    assert result["network_requests"] == 0


def _mutations(vectors):
    valid = [
        vectors["php_object"], vectors["ruby_hash"], vectors["java_string"],
        vectors["dotnet"], vectors["pickles"][4], vectors["yaml"],
    ]
    out = [b"", b"\x00", b"\xff" * 4096]
    rng = random.Random(0xDE5E2026)
    for length in (1, 2, 3, 4, 8, 16, 31, 64, 127, 255, 1024, 4096):
        out.append(rng.randbytes(length))
    for raw in valid:
        out.extend(raw[:at] for at in range(len(raw)))
        for at in range(len(raw)):
            changed = bytearray(raw)
            changed[at] ^= 1 << (at % 8)
            out.append(bytes(changed))
    return out


def test_fail_closed_fuzz_all_passive_detection_entrypoints(vectors):
    for raw in _mutations(vectors):
        # These APIs declare clean-return behavior for arbitrary byte blobs.
        assert isinstance(deser_detect.detect(raw), list)
        assert isinstance(deser_detect.scan({"fuzz": raw}), dict)
        assert isinstance(deser_detect.scan_cookies(b"x=" + raw), dict)
        assert isinstance(deser_detect.from_response(raw), dict)

        for parser in (
            passive.parse_java, passive.parse_php, passive.parse_phar,
            passive.parse_dotnet, passive.looks_like_pickle, passive.classify,
        ):
            parser(raw)

        analysis = chains.analyze_artifact(raw)
        assert analysis.bytes_inspected == len(raw)

        text = raw.decode("latin-1")
        try:
            assert isinstance(deser_gadgets.detect_languages(text), dict)
            report = deser_gadgets.synthesize(text, languages=[])
        except deser_gadgets.DeserInputError:
            continue
        assert report["deserialized"] is report["executed"] is False
        assert report["network_requests"] == 0


def test_oversized_inputs_obey_each_public_boundary():
    # deser_detect deliberately truncates to its documented inspection cap.
    assert deser_detect.detect(b"A" * (deser_detect.MAX_BLOB + 1)) == []
    assert passive.classify(b"A" * (passive.MAX_FILE + 1)) is None
    with pytest.raises(chains.DeserializationInputError):
        chains.analyze_artifact(b"A" * (chains.MAX_ARTIFACT_BYTES + 1))
    with pytest.raises(deser_gadgets.DeserInputError):
        deser_gadgets.detect_languages("A" * (deser_gadgets.MAX_SOURCE + 1))

