"""Independent Android artifact locks and deterministic malformed-input probes.

Sources: AOSP dex-format and ResourceTypes.h; Flutter message_codecs.dart and
foundation/serialization.dart. Existing DEX/DLL fixtures are real D8/.NET output
(see fixtures/mobile_code/README.md), never executed. Androguard, pyelftools,
dnfile, zipfile, plistlib and gzip are independent oracles, not solver encoders.
"""
import base64
import gzip
import hashlib
import io
from pathlib import Path
import plistlib
import random
import struct
import zipfile
import zlib

from androguard.core.axml import AXMLPrinter, ARSCParser
from androguard.core.dex import DEX
import dnfile
from elftools.elf.elffile import ELFFile
from loguru import logger
import pytest

import android_depth as android
import app_bundles
import apk_container
import apk_facts
import apk_resources as resources
import native_arm64

logger.disable("androguard")
FIXTURES = Path(__file__).parent / "fixtures" / "mobile_code"


def dex_fixture():
    return (FIXTURES / "method.dex").read_bytes()


def modified_utf8_dex():
    """Replace same-sized string_data_item; update real DEX integrity fields."""
    data = bytearray(dex_fixture())
    offset = data.index(b"\x05hello\x00")
    data[offset:offset + 7] = b"\x04hi\xc0\x80X\x00"
    data[12:32] = hashlib.sha1(data[32:]).digest()
    data[8:12] = struct.pack("<I", zlib.adler32(data[12:]) & 0xffffffff)
    return bytes(data)


def string_pool(strings):
    """Hand encoding of AOSP ResStringPool UTF8 chunks (not solver code)."""
    offsets, content = [], b""
    for value in strings:
        encoded = value.encode("utf-8")
        assert len(encoded) < 128
        offsets.append(len(content))
        content += bytes([len(value), len(encoded)]) + encoded + b"\0"
    content += b"\0" * (-len(content) % 4)
    start = 28 + 4 * len(strings)
    return (struct.pack("<HH6I", 1, 28, start + len(content), len(strings), 0, 256, start, 0)
            + b"".join(struct.pack("<I", value) for value in offsets) + content)


AXML_STRINGS = ["manifest", "package", "org.csctf.fixture", "application", "label", "CSCTF{resource}"]


def binary_manifest():
    def start(name, attrs):
        node = struct.pack("<HHIIIiiHHHHHH", 0x102, 16, 36 + 20 * len(attrs),
                           1, 0xffffffff, -1, name, 20, 20, len(attrs), 0, 0, 0)
        return node + b"".join(struct.pack("<iiiHBBI", -1, key, val, 8, 0, 3, val)
                               for key, val in attrs)

    def end(name):
        return struct.pack("<HHIIIii", 0x103, 16, 24, 1, 0xffffffff, -1, name)

    content = string_pool(AXML_STRINGS) + start(0, [(1, 2)]) + start(3, [(4, 5)]) + end(3) + end(0)
    return struct.pack("<HHI", 3, 8, len(content) + 8) + content


def arsc_fixture():
    # AOSP ResTable_package, ResTable_typeSpec, ResTable_type, ResTable_entry.
    pool = string_pool(["CSCTF{arsc}", "\u00e9"])
    types, keys = string_pool(["string"]), string_pool(["secret"])
    specification = struct.pack("<HHIBBHI I", 0x202, 16, 20, 1, 0, 0, 1, 0)
    config = struct.pack("<I", 64) + bytes(60)
    entry = struct.pack("<HHIHBBI", 8, 0, 0, 8, 0, 3, 0)
    table = (struct.pack("<HHIBBHII", 0x201, 84, 104, 1, 0, 0, 1, 88)
             + config + struct.pack("<I", 0) + entry)
    content = types + keys + specification + table
    package = (struct.pack("<HHII", 0x200, 288, 288 + len(content), 0x7f)
               + "org.csctf.fixture".encode("utf-16le").ljust(256, b"\0")
               + struct.pack("<5I", 288, 1, 288 + len(types), 1, 0) + content)
    return struct.pack("<HHII", 2, 12, 12 + len(pool) + len(package), 1) + pool + package


def elf_fixture():
    # ELF64, little-endian AArch64 shared object, zero program/section entries.
    return (b"\x7fELF\x02\x01\x01" + bytes(9)
            + struct.pack("<HHIQQQIHHHHHH", 3, 183, 1, 0x12340000,
                          0, 0, 0, 64, 56, 0, 64, 0, 0))


def zip_fixture(entries=None, compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    if entries is None:
        entries = {"AndroidManifest.xml": binary_manifest(), "classes.dex": dex_fixture(),
                   "assets/flag.txt": b"CSCTF{zip}", "assets/": b""}
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, content in entries.items():
            info = zipfile.ZipInfo(name, (2020, 1, 2, 3, 4, 6))
            info.compress_type = compression
            archive.writestr(info, content)
    return output.getvalue()


def malformed_cases(seed, valid):
    rng = random.Random(seed)
    yield b""
    for size in (1, 3, 4, 7, 8, 15, 16, 31, 32, 52, 64, 111, 112, 255):
        yield b"\xff" * size
        yield rng.randbytes(size)
    for offset in range(min(len(valid), 160)):
        yield valid[:offset]
    for _ in range(80):
        changed = bytearray(valid)
        at = rng.randrange(len(changed))
        changed[at] ^= 1 << rng.randrange(8)
        yield bytes(changed)


def test_dex_real_compiler_output_against_androguard():
    raw = dex_fixture()
    oracle = DEX(raw)
    result = android.parse_dex(raw)
    assert result["file_size"] == oracle.header.file_size == len(raw)
    assert result["version"] == "035"
    assert result["checksum"] == zlib.adler32(raw[12:]) & 0xffffffff
    assert result["sha1"] == hashlib.sha1(raw[32:]).hexdigest()
    assert result["strings"] == list(oracle.get_strings())
    methods = [(m.get_class_name(), m.get_name(), m.get_descriptor()) for m in oracle.get_methods()]
    actual = [(m["class"], m["name"], "(" + "".join(m["proto"]["parameters"]) + ")" + m["proto"]["return"])
              for m in result["methods"]]
    assert actual == methods
    assert android.plan_dex_patches(raw) == []  # fixture has no security gate methods


@pytest.mark.parametrize("name", ["method", "fields"])
def test_app_bundles_dex_tables_and_code_against_androguard(name):
    raw = (FIXTURES / (name + ".dex")).read_bytes()
    oracle = DEX(raw)
    dex = app_bundles.Dex(raw)
    assert app_bundles.is_dex(raw) is True
    assert dex.n_str == oracle.header.string_ids_size
    assert [dex.string(i) for i in range(dex.n_str)] == list(oracle.get_strings())
    assert [dex.type(i) for i in range(dex.n_type)] == [oracle.get_cm_type(i) for i in range(oracle.header.type_ids_size)]
    assert [dex.field(i) for i in range(dex.n_field)] == [
        (f.get_class_name(), f.get_type(), f.get_name()) for f in oracle.get_fields()]
    assert [dex.method(i) for i in range(dex.n_method)] == [
        (m.get_class_name(), m.get_name()) for m in oracle.get_methods()]
    classes = list(dex.classes())
    assert [item[0] for item in classes] == oracle.get_classes_names()
    for item, ref_class in zip(classes, oracle.get_classes()):
        assert item[3] == [(m.get_method_idx(), m.get_code_off()) for m in ref_class.get_methods()]
        for m in ref_class.get_methods():
            if m.get_code() is not None:
                code = m.get_code().get_bc().get_raw()
                assert dex.code(m.get_code_off()) == struct.unpack("<" + "H" * (len(code) // 2), code)


@pytest.mark.parametrize("encoded,expected", [(b"\x04\x2a", 42), (b"\x04\xff", -1),
                                                (b"\x1e", None), (b"\x1f", False),
                                                (b"\x3f", True), (b"\x1c\x02\x04\x01\x04\x02", [1, 2])])
def test_app_bundles_encoded_values_published_dex_grammar(encoded, expected):
    raw = dex_fixture()
    dex = app_bundles.Dex(raw + encoded)
    assert dex.value(len(raw)) == (expected, len(raw) + len(encoded))


def test_app_bundles_modified_utf8_bug():
    raw = modified_utf8_dex()
    oracle = DEX(raw)
    dex = app_bundles.Dex(raw)
    assert [dex.string(i) for i in range(dex.n_str)] == list(oracle.get_strings())


@pytest.mark.parametrize("data", [b"", b"\xff" * 128, random.Random(721).randbytes(128), b"dex\n035\0" + bytes(103)])
def test_app_bundles_constructor_rejection_bug(data):
    with pytest.raises(app_bundles.DexError):
        app_bundles.Dex(data)


@pytest.mark.parametrize("header_offset,method", [(0x3c, "string"), (0x44, "type"), (0x54, "field"), (0x5c, "method")])
def test_app_bundles_out_of_bounds_tables_bug(header_offset, method):
    raw = bytearray((FIXTURES / "fields.dex").read_bytes())
    # A single high bit flip changes a valid header offset beyond EOF.
    raw[header_offset + 3] ^= 0x80
    with pytest.raises(app_bundles.DexError):
        dex = app_bundles.Dex(bytes(raw))
        getattr(dex, method)(0)


def test_app_bundles_value_and_code_payload_bitflip_fuzz():
    raw = dex_fixture()
    oracle = DEX(raw)
    method = next(m for c in oracle.get_classes() for m in c.get_methods() if m.get_code())
    code_offset = method.get_code_off()
    code_bytes = method.get_code().get_bc().get_raw()
    rng = random.Random(0xD3C)
    for _ in range(64):
        payload = rng.randbytes(4)
        # AOSP encoded_value VALUE_INT, value_arg3 (four little-endian bytes).
        dex = app_bundles.Dex(raw + b"\x64" + payload)
        assert dex.value(len(raw)) == (int.from_bytes(payload, "little", signed=True), len(raw) + 5)
        changed = bytearray(raw)
        position = code_offset + 16 + rng.randrange(len(code_bytes))
        changed[position] ^= 1 << rng.randrange(8)
        dex = app_bundles.Dex(bytes(changed))
        # Parse classes and raw instruction units only; never interpret changed code.
        assert list(dex.classes())[0][0] == "Lcom/huntress/fixture/Puzzle;"
        assert len(dex.code(code_offset)) == len(code_bytes) // 2


def test_app_bundles_classes_truncation_bug():
    raw = dex_fixture()
    class_defs = int.from_bytes(raw[0x64:0x68], "little")
    class_data = int.from_bytes(raw[class_defs + 24:class_defs + 28], "little")
    with pytest.raises(app_bundles.DexError):
        list(app_bundles.Dex(raw[:class_data]).classes())


def test_app_bundles_code_header_truncation_bug():
    raw = dex_fixture()
    oracle = DEX(raw)
    code_offset = next(m.get_code_off() for c in oracle.get_classes() for m in c.get_methods() if m.get_code())
    with pytest.raises(app_bundles.DexError):
        app_bundles.Dex(raw[:code_offset + 15]).code(code_offset)


@pytest.mark.parametrize("encoded", [b"", b"\x64\xff", b"\x1c\x80"])
def test_app_bundles_value_truncation_bug(encoded):
    raw = dex_fixture()
    with pytest.raises(app_bundles.DexError):
        app_bundles.Dex(raw + encoded).value(len(raw))


def test_apk_facts_dex_against_androguard_and_zipfile():
    raw = zip_fixture()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = {info.filename: archive.read(info) for info in archive.infolist() if not info.is_dir()}
    result = apk_facts.read(members, raw)
    assert result["dex"] == list(DEX(members["classes.dex"]).get_strings())
    assert result["dexes"] == ["classes.dex"]
    assert result["blob"] == raw
    assert result["manifest"]["package"] == "org.csctf.fixture"


def test_android_dex_modified_utf8_null_against_androguard():
    raw = modified_utf8_dex()
    expected = list(DEX(raw).get_strings())
    assert raw[12:32] == hashlib.sha1(raw[32:]).digest()
    assert int.from_bytes(raw[8:12], "little") == zlib.adler32(raw[12:]) & 0xffffffff
    assert "hi\0X" in expected
    assert android.parse_dex(raw)["strings"] == expected


def test_apk_facts_modified_utf8_null_bug():
    raw = modified_utf8_dex()
    expected = list(DEX(raw).get_strings())
    assert apk_facts.read({"classes.dex": raw})["dex"] == expected


def test_axml_and_manifest_against_androguard():
    raw = binary_manifest()
    oracle = AXMLPrinter(raw)
    assert oracle.is_valid()
    root = oracle.get_xml_obj()
    assert resources.is_axml(raw) is True
    assert resources.pool_strings(raw) == AXML_STRINGS
    result = resources.axml_tree(raw)
    assert [(el["tag"], el["attrs"]) for el in result] == [(el.tag, dict(el.attrib)) for el in root.iter()]
    facts = apk_facts.manifest_facts(raw)
    assert facts["package"] == root.attrib["package"]
    assert facts["application"]["label"] == root.find("application").attrib["label"]


def test_arsc_global_pool_published_layout():
    raw = arsc_fixture()
    oracle = ARSCParser(raw)
    assert oracle.get_packages_names() == ["org.csctf.fixture"]
    assert resources.is_arsc(raw) is True
    assert resources.arsc_strings(raw) == ["CSCTF{arsc}", "\u00e9"]
    expected = oracle.get_string("org.csctf.fixture", "secret")[1]
    assert expected == "CSCTF{arsc}"
    assert resources.arsc_values(raw) == {("string", "secret"): expected}


def test_elf_against_pyelftools():
    raw = elf_fixture()
    oracle = ELFFile(io.BytesIO(raw))
    result = android.parse_elf(raw)
    assert result["bits"] == oracle.elfclass == 64
    assert result["endian"] == ("little" if oracle.little_endian else "big")
    assert result["entry"] == oracle.header["e_entry"] == 0x12340000
    assert oracle.header["e_machine"] == "EM_AARCH64"
    assert result["machine"] == "aarch64"
    assert result["program_headers"] == list(oracle.iter_segments()) == []
    assert result["sections"] == list(oracle.iter_sections()) == []
    assert resources.is_elf(raw) is True
    assert resources.elf_strings(raw + b"\0CSCTF{native}\0")[-1] == b"CSCTF{native}"
    assert native_arm64.elf_machine(raw) == 183
    assert native_arm64.aarch64_functions(raw) == {}  # no symbol table


def test_dotnet_real_compiler_output_against_dnfile():
    raw = (FIXTURES / "Fix.dll").read_bytes()
    oracle = dnfile.dnPE(data=raw)
    result = android.parse_dotnet_metadata(raw)
    assert result["managed"] is True
    assert result["runtime_version"] == oracle.net.metadata.struct.Version.rstrip(b"\0").decode()
    assert {s["name"] for s in result["streams"]} == {key.decode() for key in oracle.net.metadata.streams}
    assert "Puzzle" in [item["value"] for item in result["strings"]]
    for item in result["strings"]:
        assert item["value"] == oracle.net.strings.get(item["offset"]).value
    for item in result["user_strings"]:
        assert item["value"] == oracle.net.user_strings.get(item["offset"]).value


@pytest.mark.parametrize("raw,expected", [
    (b"\0", None), (b"\1", True), (b"\2", False),
    (b"\x07\x03abc", "abc"), (b"\x08\x03\0\x80\xff", b"\0\x80\xff"),
    (b"\x0c\x02\x01\x02", [True, False]),
    (b"\x0d\x01\x07\x01k\x01", {"k": True}),
    (b"\x06" + b"\0" * 7 + struct.pack("<d", 1.5), 1.5),
    (b"\x09\x02\0\0" + struct.pack("<ii", -1, 2147483647), [-1, 2147483647]),
])
def test_flutter_published_wire_grammar(raw, expected):
    result = android.parse_flutter_message(raw)
    assert result["value"] == expected
    assert result["consumed"] == len(raw)


@pytest.mark.parametrize("raw,expected", [(b"\3" + struct.pack("<i", 42), 42),
                                        (b"\4" + struct.pack("<q", 1 << 40), 1 << 40)])
def test_flutter_scalar_integer_alignment_bug(raw, expected):
    # Official WriteBuffer.putInt32/putInt64 append directly; only float/arrays align.
    result = android.parse_flutter_message(raw)
    assert result is not None and result["value"] == expected


def test_smali_source_semantics():
    source = ".method public static isRooted()Z\n.locals 1\nconst/4 v0, 0x1\nreturn v0\n.end method\n"
    result = android.plan_smali_patches(source)
    assert result[0]["method"] == "isRooted"
    assert result[0]["return_type"] == "Z"
    assert result[0]["replacement"] == {"value": False, "smali": ["const/4 v0, 0x0", "return v0"]}
    assert result[0]["apply"] is False


def test_apk_zip_members_against_zipfile():
    for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raw = zip_fixture(compression=method)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            expected_dex = archive.read("classes.dex")
        result = android.inspect_apk(raw)
        assert result["member_count"] == len(infos) == 3
        assert result["sha256"] == hashlib.sha256(raw).hexdigest()
        assert result["dex"][0]["path"] == "classes.dex"
        assert result["dex"][0]["dex"]["strings"] == list(DEX(expected_dex).get_strings())
        assert apk_container.read(raw)[0] is None  # no hidden central-directory entry


def test_apk_hidden_entry_against_original_zipfile():
    # This legacy reader's documented code grammar is ANS-..., not CSCTF flags.
    code = b"ANS-0123456789ABCDEF"
    raw = zip_fixture({"visible.txt": b"visible", "hidden.txt": code}, zipfile.ZIP_DEFLATED)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        expected = archive.read("hidden.txt").decode()
        start = archive.start_dir
    eocd = raw.rindex(b"PK\x05\x06")
    name_len, extra_len, comment_len = struct.unpack_from("<HHH", raw, start + 28)
    first_cd = raw[start:start + 46 + name_len + extra_len + comment_len]
    trailer = bytearray(raw[eocd:])
    struct.pack_into("<HHI", trailer, 8, 1, 1, len(first_cd))
    hidden = raw[:start] + first_cd + trailer
    with zipfile.ZipFile(io.BytesIO(hidden)) as archive:
        assert archive.namelist() == ["visible.txt"]
    result, notes = apk_container.read(hidden)
    assert result == {"code": expected, "route": "apk-zip-hidden:hidden.txt"}


def test_ipa_binary_plist_against_plistlib():
    info = {"CFBundleIdentifier": "org.csctf.fixture", "CFBundleVersion": "7",
            "CFBundleShortVersionString": "1.2", "CFBundleDisplayName": "Fixture",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": ["csctf"]}],
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}}
    raw = plistlib.dumps(info, fmt=plistlib.FMT_BINARY, sort_keys=True)
    oracle = plistlib.loads(raw)
    result = apk_facts.ipa_facts({"Payload/Fixture.app/Info.plist": raw})
    assert result["package"] == oracle["CFBundleIdentifier"]
    assert result["version_name"] == oracle["CFBundleShortVersionString"]
    assert result["application"]["usesCleartextTraffic"] is False
    assert result["components"][0]["filters"][0]["data"] == [{"scheme": "csctf"}]


def test_resource_gzip_against_stdlib():
    payload = b"CSCTF{nested_resource}"
    compressed = gzip.compress(payload, mtime=0)
    assert resources.expand("assets/a.gz", compressed) == [("assets/a.gz!gunzip", gzip.decompress(compressed))]


def test_legacy_native_code_reader_independent_encodings():
    # These two inherited functions intentionally use the documented ANS format.
    code = b"ANS-0123456789ABCDEF"
    assert resources.native_secret([b"\0" + code + b"\0"]) == code.decode()
    encoded = base64.b64encode(code)
    assert resources.native_derive([encoded]) == [("native:so-base64", base64.b64decode(encoded).decode())]
    assert resources.native_secret([b"CSCTF{current_event_format}"]) is None


@pytest.mark.parametrize("parser,valid", [
    (android.parse_dex, dex_fixture()), (android.plan_dex_patches, dex_fixture()),
    (android.parse_elf, elf_fixture()),
    (android.parse_dotnet_metadata, (FIXTURES / "Fix.dll").read_bytes()),
    (android.parse_flutter_message, b"\x0d\x01\x07\x01k\x01"),
    (resources.is_axml, binary_manifest()), (resources.is_arsc, arsc_fixture()),
    (resources.is_elf, elf_fixture()), (resources.pool_strings, binary_manifest()),
    (native_arm64.elf_machine, elf_fixture()), (native_arm64.aarch64_functions, elf_fixture()),
    (app_bundles.is_dex, dex_fixture()),
    (resources.axml_tree, binary_manifest()), (resources.arsc_strings, arsc_fixture()),
    (resources.arsc_values, arsc_fixture()), (resources.elf_strings, elf_fixture()),
    (apk_facts.manifest_facts, binary_manifest()), (apk_container.read, zip_fixture()),
], ids=lambda x: x.__name__ if callable(x) else None)
def test_parse_entrypoints_fail_closed_fuzz(parser, valid):
    # These modules declare no custom error type: *no* escaped error is allowed.
    for data in malformed_cases(0xA9C, valid):
        parser(data)


def test_member_wrappers_fail_closed_fuzz():
    for data in malformed_cases(0xFACA, dex_fixture()):
        apk_facts.read({"classes.dex": data})
    for data in malformed_cases(0xB1157, plistlib.dumps({"CFBundleIdentifier": "org.test"}, fmt=plistlib.FMT_BINARY)):
        apk_facts.ipa_facts({"Payload/Test.app/Info.plist": data})
    for data in malformed_cases(0xC0DE, gzip.compress(b"CSCTF{nested}", mtime=0)):
        resources.expand("assets/data", data)
        resources.native_secret([data])
        resources.native_derive([data])
    for data in malformed_cases(0x5A11, b".method public static f()V\nreturn-void\n.end method"):
        android.plan_smali_patches(data.decode("latin-1"))


def test_apk_parser_embedded_malformed_members():
    for data in malformed_cases(0xA9C, dex_fixture()):
        raw = zip_fixture({"classes.dex": data, "lib/arm64-v8a/libx.so": data,
                           "assets/flutter_assets/AssetManifest.bin": data})
        android.inspect_apk(raw)


@pytest.mark.parametrize("data", [b"", b"\xff" * 64, random.Random(722).randbytes(80), b"PK\x03\x04", zip_fixture()[:52]])
def test_apk_malformed_envelope_builtin_rejection_bug(data):
    with pytest.raises(android.AndroidError):
        android.inspect_apk(data)


def test_apk_crc_exception_bug():
    raw = bytearray(zip_fixture({"assets/test.txt": b"CSCTF{zip_oracle}"}))
    raw[30 + len("assets/test.txt")] ^= 1
    with pytest.raises(android.AndroidError):
        android.inspect_apk(raw)


def test_apk_compression_exception_bug():
    raw = bytearray(zip_fixture({"assets/test.txt": b"CSCTF{zip_oracle}"}))
    raw[8:10] = struct.pack("<H", 99)
    cd = raw.index(b"PK\x01\x02")
    raw[cd + 10:cd + 12] = struct.pack("<H", 99)
    with pytest.raises(android.AndroidError):
        android.inspect_apk(raw)
