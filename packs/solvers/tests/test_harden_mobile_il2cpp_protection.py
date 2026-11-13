"""Independent format locks and bounded malformed-input probes (tests only).

IL2CPP reference: Perfare/Il2CppDumper MetadataClass.cs version annotations,
https://github.com/Perfare/Il2CppDumper/blob/master/Il2CppDumper/Il2Cpp/MetadataClass.cs
The v27 structs below do NOT use il2cpp.LAYOUTS or its encoder/fixtures.
Mapping: https://r8.googlesource.com/r8/+/refs/heads/main/doc/retrace.md
String transforms: RFC 4648 vectors, stdlib codecs, and Java UTF-16 semantics:
https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/String.html
ZIP, XML, JSON and SHA256 oracles are Python's independent standard library.
No supplied bytecode or application is executed.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import io
import json
import random
import struct
import xml.etree.ElementTree as ET
import zipfile

import pytest

import android_depth
import il2cpp
import mobile_protection as p


LITERAL = b"CSCTF{independent_IL2CPP}"


def metadata_v27():
    """Encode published v27 structs: method32, field12, type88 bytes."""
    heap = b"\0FirstMethod\0SecondMethod\0TokenField\0GateType\0Example\0"
    name = lambda s: heap.index(s.encode() + b"\0")
    # Six 32-bit words then flags/iflags/slot/parameterCount as uint16.
    methods = b"".join(struct.pack("<IiiiiIHHHH", name(n), 0, 0, 0, -1,
                                    0x06000001 + i, 6, 0, 0xffff, 0)
                       for i, n in enumerate(("FirstMethod", "SecondMethod")))
    fields = struct.pack("<IiI", name("TokenField"), 0, 0x04000001)
    # Type: seven 32-bit indexes, flags, eight start indexes, eight uint16
    # counts, bitfield and token. v27 removed the older byrefTypeIndex.
    types = struct.pack("<16I8H2I", name("GateType"), name("Example"),
                        0, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                        1, 0, 0, 0, 0, 0, 0, 0, 0,
                        2, 0, 1, 0, 0, 0, 0, 0, 0, 0x02000001)
    assert len(methods) == 64 and len(types) == 88 and len(fields) == 12
    header = [0] * 64
    header[0:2] = [0xFAB11BAF, 27]
    body = bytearray()
    # Header word indexes follow the independent serialized header above.
    for word, chunk in ((2, struct.pack("<Ii", len(LITERAL), 0)),
                        (4, LITERAL), (6, heap), (12, methods),
                        (24, fields), (40, types)):
        header[word:word + 2] = [256 + len(body), len(chunk)]
        body.extend(chunk)
    return struct.pack("<64I", *header) + body


def test_il2cpp_literal_and_field_vector():
    raw = metadata_v27()
    report = il2cpp.parse_metadata(raw)
    assert report["version"] == 27 and report["supported"] is True
    assert report["literals"]["literals"] == [{
        "index": 0, "offset": 264, "length": len(LITERAL),
        "text": LITERAL.decode(), "bytes_hex": LITERAL.hex(), "clean": True}]
    assert report["counts"]["string_literals"] == 1
    assert report["fields"] == [{"index": 0, "name": "TokenField", "namespace": None}]


def test_il2cpp_v27_method_struct_vector():
    report = il2cpp.parse_metadata(metadata_v27())
    assert [x["name"] for x in report["methods"]] == ["FirstMethod", "SecondMethod"]
    assert report["counts"]["method_entries"] == 2


def test_il2cpp_v27_type_struct_vector():
    report = il2cpp.parse_metadata(metadata_v27())
    assert report["types"] == [
        {"index": 0, "name": "GateType", "namespace": "Example"}]
    assert report["counts"]["type_entries"] == 1


def test_android_il2cpp_literal_vector():
    report = android_depth.parse_il2cpp_metadata(metadata_v27())
    assert report["version"] == 27
    assert report["literals"] == [{"index": 0, "offset": 264,
                                    "bytes_hex": LITERAL.hex(), "text": LITERAL.decode()}]
    assert report["notes"] == []


def test_il2cpp_public_wrappers_vector(tmp_path, capsys):
    files = {"global-metadata.dat": metadata_v27()}
    out = il2cpp.report(files)
    assert len(out) == 1 and out[0][0] == "global-metadata.dat"
    assert out[0][1]["literals"]["literals"][0]["bytes_hex"] == LITERAL.hex()
    assert il2cpp.signals([], files) == 0.5
    questions = [{"id": "version", "question": "metadata version"},
                 {"id": "count", "question": "How many string literals?"}]
    assert il2cpp.solve_set(questions, files, {}) == {"version": 27, "count": 1}
    path = tmp_path / "global-metadata.dat"
    path.write_bytes(metadata_v27())
    assert il2cpp.main([str(path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["version"] == 27


def binary_corpus(valid, seed):
    rng = random.Random(seed)
    values = [b"", b"\xff" * 128, b"\0" * 128]
    values += [rng.randbytes(n) for n in (1, 4, 8, 16, 31, 64, 127, 255)]
    values += [valid[:n] for n in sorted(set(range(min(40, len(valid)))) | set(range(40, len(valid), 7)))]
    for _ in range(48):
        changed = bytearray(valid)
        index = rng.randrange(len(changed))
        changed[index] ^= 1 << rng.randrange(8)
        values.append(bytes(changed))
    return values


def test_il2cpp_parse_and_wrappers_fail_closed_fuzz():
    # Neither IL2CPP parser declares a parser exception: any exception is a bug.
    for raw in binary_corpus(metadata_v27(), 27032):
        assert il2cpp.parse_metadata(raw) is None or isinstance(il2cpp.parse_metadata(raw), dict)
        assert android_depth.parse_il2cpp_metadata(raw) is None or isinstance(android_depth.parse_il2cpp_metadata(raw), dict)
        files = {"global-metadata.dat": raw}
        assert isinstance(il2cpp.report(files), list)
        assert isinstance(il2cpp.signals([], files), float)
        assert isinstance(il2cpp.solve_set([{"id": "v", "question": "version"}], files, {}), dict)


MAPPING = ("some.package.Class -> foo.a:\n"
           "    int someField -> a\n"
           "    void someMethod() -> b\n")
XML_MAPPING = ('<allatori><class old="some.package.Class" new="foo.a">'
               '<field old="someField" new="a"/><method old="someMethod" new="b"/>'
               '</class></allatori>')


def mapping_oracle():
    # Independent literal facts from the published R8 mapping grammar.
    return {"classes": {"foo.a": {"original": "some.package.Class",
            "members": [{"original": "someField", "obfuscated": "a"},
                        {"original": "someMethod", "obfuscated": "b"}]}}}


@pytest.mark.parametrize("parser", [p.parse_proguard_mapping, p.parse_obfuscation_mapping])
def test_proguard_mapping_published_vector(parser):
    report = parser(MAPPING)
    assert report["class_count"] == 1 and report["member_count"] == 2
    cls = report["classes"]["foo.a"]
    assert cls["original"] == "some.package.Class"
    assert [(m["type"], m["original"], m["obfuscated"]) for m in cls["members"]] == [
        ("int", "someField", "a"), ("void", "someMethod", "b")]


@pytest.mark.parametrize("parser", [p.parse_allatori_mapping, p.parse_obfuscation_mapping])
def test_allatori_xml_library_oracle(parser):
    element = ET.fromstring(XML_MAPPING)[0]
    report = parser(XML_MAPPING)
    entry = report["classes"][element.attrib["new"]]
    assert entry["original"] == element.attrib["old"]
    assert report["member_count"] == len(element)
    assert [(m["kind"], m["original"], m["obfuscated"]) for m in entry["members"]] == [
        (child.tag, child.attrib["old"], child.attrib["new"]) for child in element]


def test_mapping_deobfuscation_vector():
    oracle = mapping_oracle()  # no parser output fed back as the oracle
    assert p.deobfuscate_descriptor("([Lfoo/a;)Lfoo/a;", oracle) == "([Lsome/package/Class;)Lsome/package/Class;"
    assert p.deobfuscate_stacktrace("\tat foo.a.b(Source.java:7)", oracle) == "\tat some.package.Class.someMethod(Source.java:7)"


SMALI = (".class public Lexample/Gate;\n.super Ljava/lang/Object;\n"
         ".method public isRooted()Z\n    .locals 1\n"
         "    const-string v0, \"/system/xbin/su\"\n"
         "    const/4 v0, 0x1\n    return v0\n.end method\n")
EXPECTED_PATCHED = (".class public Lexample/Gate;\n.super Ljava/lang/Object;\n"
                    ".method public isRooted()Z\n    .locals 1\n"
                    "    const/4 v0, 0x0\n    return v0\n.end method\n")


def hand_plan():
    original = ['    .locals 1', '    const-string v0, "/system/xbin/su"',
                '    const/4 v0, 0x1', '    return v0']
    replacement = ['    .locals 1', '    const/4 v0, 0x0', '    return v0']
    payload = ["Gate.smali", "replace-method-body", 4, original, replacement]
    identifier = hashlib.sha256(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()[:20]
    return {"path": "Gate.smali", "source_sha256": hashlib.sha256(SMALI.encode()).hexdigest(),
            "patches": [{"path": "Gate.smali", "kind": "replace-method-body", "start_line": 4,
                         "end_line": 7, "original": original, "replacement": replacement,
                         "safe": True, "id": identifier}]}


def test_smali_plan_and_application_independent_hash_and_text():
    generated = p.plan_smali_patches(SMALI, path="Gate.smali")
    oracle = hand_plan()
    assert generated["source_sha256"] == hashlib.sha256(SMALI.encode()).hexdigest()
    assert generated["patches"][0]["original"] == oracle["patches"][0]["original"]
    assert generated["patches"][0]["replacement"] == oracle["patches"][0]["replacement"]
    # Apply independently authored patch, not the generated plan.
    out = p.apply_smali_plan(SMALI, oracle)
    assert out["patched_text"] == EXPECTED_PATCHED
    assert out["patched_sha256"] == hashlib.sha256(EXPECTED_PATCHED.encode()).hexdigest()
    out = p.apply_smali_files({"Gate.smali": SMALI}, [oracle])
    assert out["files"] == {"Gate.smali": EXPECTED_PATCHED}


CALLS = ('const-string v0, "CSCTF{call_literal}"\n'
         'invoke-static {v0}, Lexample/Cipher;->decode(Ljava/lang/String;)Ljava/lang/String;\n')


def test_static_evidence_entrypoints_vector():
    assert p.encrypted_string_calls(CALLS, path="calls.smali") == [{
        "path": "calls.smali", "literal_line": 1, "call_line": 2, "register": "v0",
        "literal": json.loads('"CSCTF{call_literal}"'),
        "target": "Lexample/Cipher;->decode(Ljava/lang/String;)Ljava/lang/String;"}]
    detected = p.detect_obfuscation({"Gate.smali": SMALI})
    assert detected["class_count"] == 1 and detected["method_count"] == 1
    assert detected["families"] == [] and detected["short_method_ratio"] == 0
    native = b"\x7fELF\0TracerPid\0frida\0"
    manifest = '<manifest xmlns:a="http://schemas.android.com/apk/res/android"><application a:debuggable="true"/></manifest>'
    report = p.analyze_rasp({}, manifest=manifest, native_files={"lib/gate.so": native})
    assert report["manifest"] == {"debuggable": ET.fromstring(manifest)[0].attrib['{http://schemas.android.com/apk/res/android}debuggable']}
    assert report["native"][0]["sha256"] == hashlib.sha256(native).hexdigest()
    assert [(e["marker"], e["offsets"]) for e in report["native"][0]["evidence"]] == [
        ("TracerPid", [5]), ("frida", [15])]


@pytest.mark.parametrize("value,operations,expected", [
    (b"Zm9vYmFy", [{"op": "base64"}], b"foobar"),  # RFC4648 section10
    (b"-_8=", [{"op": "base64url"}], b"\xfb\xff"),
    (b"4353435446", [{"op": "hex"}], binascii.unhexlify("4353435446")),
    (b"ABC", [{"op": "reverse"}], b"CBA"),
    (b"ABC", [{"op": "xor", "key": 32}], b"abc"),
    (b"ABC", [{"op": "add", "key": 1}], b"BCD"),
    (b"BCD", [{"op": "sub", "key": 1}], b"ABC"),
    (bytes([0x81, 0xff, 0x10]), [{"op": "rol", "key": 1}], bytes([0x03, 0xff, 0x20])),
    (bytes([0x81, 0xff, 0x10]), [{"op": "ror", "key": 1}], bytes([0xc0, 0xff, 0x08])),
    (b"ABC", [{"op": "xor-index", "key": 1}], b"@@@"),
])
def test_transform_library_and_literal_vectors(value, operations, expected):
    result = p.transform_string(value, operations)
    assert result["bytes"] == expected
    assert result["hex"] == expected.hex()
    assert result["trace"][0]["input_sha256"] == hashlib.sha256(value).hexdigest()
    assert result["trace"][-1]["output_sha256"] == hashlib.sha256(expected).hexdigest()


def utf16_xor_oracle(value, even, odd):
    raw = value.encode("utf-16le", "surrogatepass")
    units = struct.unpack("<" + "H" * (len(raw) // 2), raw)
    encoded = b"".join(struct.pack("<H", x ^ (even if i % 2 == 0 else odd)) for i, x in enumerate(units))
    return encoded.decode("utf-16le", "surrogatepass")


def test_alternating_xor_bmp_java_units():
    assert p.recover_alternating_xor("ABéΩ", 1, 2) == utf16_xor_oracle("ABéΩ", 1, 2)


def test_alternating_xor_astral_java_units():
    assert p.recover_alternating_xor("\U0001f600", 1, 2) == utf16_xor_oracle("\U0001f600", 1, 2)


@pytest.mark.parametrize("value", ["A\U0001f600B", "\ud800X", "\ud83d\ude00"])
def test_alternating_xor_code_unit_parity(value):
    assert p.recover_alternating_xor(value, 1, 2) == utf16_xor_oracle(value, 1, 2)


def zip_oracle():
    entries = {"Gate.smali": SMALI.encode(), "mapping.txt": MAPPING.encode(),
               "assets/note.txt": b"CSCTF{zip_payload}"}
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, body in entries.items():
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(info, body)
    return stream.getvalue()


def test_bundle_zipfile_oracle_and_cli(tmp_path, capsys):
    raw = zip_oracle()
    with zipfile.ZipFile(io.BytesIO(raw)) as oracle:
        report = p.inspect_protection_bundle(raw)
        assert report["member_count"] == len(oracle.infolist())
        assert report["plans"][0]["source_sha256"] == hashlib.sha256(oracle.read("Gate.smali")).hexdigest()
        assert report["mappings"][0]["report"]["class_count"] == 1
    path = tmp_path / "sample.zip"
    path.write_bytes(raw)
    assert p.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["member_count"] == 3


def text_corpus():
    rng = random.Random(61070)
    return ["", "\xff" * 96, "\0" * 96] + [rng.randbytes(n).decode("latin1") for n in range(1, 100, 7)]


def text_mutations(valid):
    rng = random.Random(913)
    values = [valid[:i] for i in range(len(valid))]
    for _ in range(32):
        data = bytearray(valid.encode("ascii"))
        data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        values.append(data.decode("latin1"))
    return values


@pytest.mark.parametrize("parser", [p.plan_smali_patches, p.parse_proguard_mapping,
                                     p.parse_allatori_mapping, p.parse_obfuscation_mapping,
                                     p.encrypted_string_calls])
def test_text_entrypoints_fail_closed(parser):
    valid = {p.parse_allatori_mapping: XML_MAPPING,
             p.parse_obfuscation_mapping: XML_MAPPING,
             p.parse_proguard_mapping: MAPPING,
             p.encrypted_string_calls: CALLS}.get(parser, SMALI)
    texts = text_corpus() + text_mutations(valid)
    if parser is p.parse_obfuscation_mapping:
        texts += text_mutations(MAPPING)
    for text in texts:
        try:
            result = parser(text)
            assert result is None or isinstance(result, (dict, list))
        except p.ProtectionError:
            pass


def test_other_public_entrypoints_fail_closed():
    for text in text_corpus() + text_mutations(SMALI):
        for call in (lambda: p.detect_obfuscation({"a.smali": text}),
                     lambda: p.analyze_rasp({"a.smali": text}),
                     lambda: p.analyze_rasp({}, manifest=text),
                     lambda: p.deobfuscate_descriptor(text, mapping_oracle()),
                     lambda: p.deobfuscate_stacktrace(text, mapping_oracle()),
                     lambda: p.recover_alternating_xor(text, 1, 2),
                     lambda: p.apply_smali_plan(text, hand_plan()),
                     lambda: p.apply_smali_files({"Gate.smali": text}, [hand_plan()])):
            try:
                call()
            except p.ProtectionError:
                pass
    for raw in binary_corpus(b"Zm9vYmFy", 6464):
        for operation in ("base64", "base64url", "hex", "reverse", "xor", "add", "sub", "rol", "ror", "xor-index"):
            try:
                p.transform_string(raw, [{"op": operation, "key": 1}])
            except p.ProtectionError:
                pass


def test_bundle_prefix_magic_and_noise_fail_closed():
    raw = zip_oracle()
    values = [raw[:i] for i in range(len(raw))]
    rng = random.Random(9001)
    values += [b"", b"\xff" * 256, b"\0" * 256]
    values += [b"PK\x03\x04" + rng.randbytes(i) for i in range(0, 100, 3)]
    for value in values:
        try:
            assert isinstance(p.inspect_protection_bundle(value), dict)
        except p.ProtectionError:
            pass


def test_bundle_single_bit_crc_failure_is_declared_error():
    raw = bytearray(zip_oracle())
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.getinfo("assets/note.txt")
        offset = info.header_offset + 30 + len(info.filename.encode()) + len(info.extra)
    raw[offset] ^= 1
    # zipfile independently verifies this is a CRC error, not a guessed format.
    with zipfile.ZipFile(io.BytesIO(raw)) as oracle:
        with pytest.raises(zipfile.BadZipFile, match="CRC"):
            oracle.read("assets/note.txt")
    with pytest.raises(p.ProtectionError):
        p.inspect_protection_bundle(bytes(raw))


def test_plan_unicode_error_is_declared():
    with pytest.raises(p.ProtectionError):
        p.plan_smali_patches("\ud800")


def test_allatori_unicode_error_is_declared():
    with pytest.raises(p.ProtectionError):
        p.parse_allatori_mapping("\ud800")


def test_rasp_manifest_unicode_error_is_declared():
    with pytest.raises(p.ProtectionError):
        p.analyze_rasp({}, manifest="\ud800")


def test_transform_invalid_encoding_is_declared():
    with pytest.raises(p.ProtectionError):
        p.transform_string(b"x", [{"op": "reverse", "encoding": 3}])


def test_apply_plan_equal_spans_are_declared_error():
    plan = hand_plan()
    other = copy.deepcopy(plan["patches"][0])
    other["replacement"] = ["    .locals 0"]
    payload = [other["path"], other["kind"], other["start_line"], other["original"], other["replacement"]]
    other["id"] = hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()[:20]
    plan["patches"].append(other)
    with pytest.raises(p.ProtectionError):
        p.apply_smali_plan(SMALI, plan)
