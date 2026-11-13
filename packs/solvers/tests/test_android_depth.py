import io
import json
import struct
import zipfile

from solvers.toolkits import android_depth as android


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _minimal_dex():
    strings = [b"Lcom/example/Security;", b"isRooted", b"Z"]
    string_count = len(strings)
    cursor = 0x70
    string_ids_off = cursor
    cursor += 4 * string_count
    type_ids_off = cursor
    cursor += 4 * 2
    proto_ids_off = cursor
    cursor += 12
    method_ids_off = cursor
    cursor += 8
    class_defs_off = cursor
    cursor += 32
    data_off = cursor
    string_offsets = []
    string_blob = bytearray()
    for value in strings:
        string_offsets.append(cursor + len(string_blob))
        string_blob += _uleb(len(value)) + value + b"\x00"
    cursor += len(string_blob)
    cursor = (cursor + 3) & ~3
    class_data_off = cursor
    cursor += 16
    code_off = (cursor + 3) & ~3
    cursor = code_off + 20
    raw = bytearray(cursor)
    raw[:8] = b"dex\n035\x00"
    struct.pack_into("<I", raw, 0x20, len(raw))
    struct.pack_into("<I", raw, 0x24, 0x70)
    struct.pack_into("<I", raw, 0x28, 0x12345678)
    struct.pack_into("<III", raw, 0x2C, 0, 0, 0)
    pairs = (
        (string_count, string_ids_off), (2, type_ids_off), (1, proto_ids_off),
        (0, 0), (1, method_ids_off), (1, class_defs_off), (len(raw) - data_off, data_off),
    )
    for index, pair in enumerate(pairs):
        struct.pack_into("<II", raw, 0x38 + index * 8, *pair)
    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", raw, string_ids_off + index * 4, offset)
    struct.pack_into("<II", raw, type_ids_off, 0, 2)
    struct.pack_into("<III", raw, proto_ids_off, 2, 1, 0)
    struct.pack_into("<HHI", raw, method_ids_off, 0, 0, 1)
    struct.pack_into("<8I", raw, class_defs_off, 0, 1, 0xFFFFFFFF, 0, 0xFFFFFFFF, 0, class_data_off, 0)
    raw[data_off:data_off + len(string_blob)] = string_blob
    class_data = b"\x00\x00\x01\x00" + b"\x00\x01" + _uleb(code_off)
    raw[class_data_off:class_data_off + len(class_data)] = class_data
    # registers/ins/outs/tries, debug-info, instruction count, const/4 v0,true; return v0
    struct.pack_into("<HHHHIIHH", raw, code_off, 1, 0, 0, 0, 0, 2, 0x1012, 0x000F)
    return bytes(raw)


def _elf64():
    raw = bytearray(64 + 56 * 2)
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", raw, 64, 0x6474E551, 6, 0, 0, 0, 0, 0, 16)
    struct.pack_into("<IIQQQQQQ", raw, 120, 0x6474E552, 4, 0, 0, 0, 0, 0, 8)
    return bytes(raw) + b"\x00frida-gadget\x00https://example.test/api?token=secret\x00"


def _elf64_dynamic():
    shstr = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.dynamic\x00.text\x00"
    dynstr = b"\x00libc.so\x00JNI_OnLoad\x00__stack_chk_fail\x00__memcpy_chk\x00Java_com_test_nativeFoo\x00"
    shstr_off, dynstr_off, dynsym_off, dynamic_off, text_off, headers_off = 0x100, 0x140, 0x1C0, 0x260, 0x2A0, 0x300
    raw = bytearray(headers_off + 6 * 64)
    raw[:16] = b"\x7fELF\x02\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIQQQIHHHHHH", raw, 16, 3, 183, 1, 0, 0, headers_off, 0, 64, 56, 0, 64, 6, 1)
    raw[shstr_off:shstr_off + len(shstr)] = shstr
    raw[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    names = {name: dynstr.index(name.encode()) for name in (
        "libc.so", "JNI_OnLoad", "__stack_chk_fail", "__memcpy_chk", "Java_com_test_nativeFoo")}
    symbols = bytearray(24)
    symbols += struct.pack("<IBBHQQ", names["JNI_OnLoad"], 0x12, 0, 5, 0x1000, 4)
    symbols += struct.pack("<IBBHQQ", names["Java_com_test_nativeFoo"], 0x12, 0, 5, 0x1010, 4)
    symbols += struct.pack("<IBBHQQ", names["__stack_chk_fail"], 0x12, 0, 0, 0, 0)
    symbols += struct.pack("<IBBHQQ", names["__memcpy_chk"], 0x12, 0, 0, 0, 0)
    raw[dynsym_off:dynsym_off + len(symbols)] = symbols
    dynamic = struct.pack("<qQ", 1, names["libc.so"]) + struct.pack("<qQ", 24, 0) + struct.pack("<qQ", 0, 0)
    raw[dynamic_off:dynamic_off + len(dynamic)] = dynamic
    raw[text_off:text_off + 4] = b"\xc0\x03\x5f\xd6"

    def section(index, name, kind, flags, offset, size, link=0, info=0, align=1, entsize=0):
        at = headers_off + index * 64
        struct.pack_into("<IIQQQQIIQQ", raw, at, shstr.index(name.encode()) if name else 0, kind, flags,
                         0, offset, size, link, info, align, entsize)

    section(1, ".shstrtab", 3, 0, shstr_off, len(shstr))
    section(2, ".dynstr", 3, 2, dynstr_off, len(dynstr))
    section(3, ".dynsym", 11, 2, dynsym_off, len(symbols), link=2, info=1, align=8, entsize=24)
    section(4, ".dynamic", 6, 2, dynamic_off, len(dynamic), link=2, align=8, entsize=16)
    section(5, ".text", 1, 6, text_off, 4, align=4)
    return bytes(raw)


def _flutter_manifest_bin():
    def string(value):
        raw = value.encode()
        return b"\x07" + bytes([len(raw)]) + raw

    return b"\x0d\x01" + string("flag.txt") + b"\x0c\x01\x0d\x01" + string("asset") + string("flag.txt")


def _il2cpp_metadata():
    literal = b"CSCTF{unity}"
    identifier = b"ApiTokenSecret\x00ordinary\x00"
    raw = bytearray(0x80)
    raw[:4] = b"\xaf\x1b\xb1\xfa"
    struct.pack_into("<I", raw, 4, 24)
    struct.pack_into("<6I", raw, 8, 0x40, 8, 0x48, len(literal), 0x60, len(identifier))
    struct.pack_into("<II", raw, 0x40, len(literal), 0)
    raw[0x48:0x48 + len(literal)] = literal
    raw[0x60:0x60 + len(identifier)] = identifier
    return bytes(raw)


def _dotnet_assembly():
    strings = b"\x00Chronos.Mobile\x00ApiToken\x00"
    user_value = "CSCTF{xamarin}".encode("utf-16le") + b"\x00"
    user_strings = b"\x00" + bytes([len(user_value)]) + user_value
    version = b"v4.0.30319\x00"
    root = bytearray(struct.pack("<IHHII", 0x424A5342, 1, 1, 0, len(version)) + version)
    root += b"\x00" * (-len(root) % 4)
    root += struct.pack("<HH", 0, 2)
    headers_size = 20 + 12  # #Strings header + #US header
    strings_offset = len(root) + headers_size
    us_offset = strings_offset + len(strings)
    root += struct.pack("<II", strings_offset, len(strings)) + b"#Strings\x00\x00\x00\x00"
    root += struct.pack("<II", us_offset, len(user_strings)) + b"#US\x00"
    root += strings + user_strings

    raw = bytearray(0x600)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, 0x80)
    raw[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", raw, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    optional = 0x98
    struct.pack_into("<H", raw, optional, 0x20B)
    struct.pack_into("<I", raw, optional + 108, 16)
    # CLI header resides at RVA 0x2000 (raw 0x200).
    struct.pack_into("<II", raw, optional + 112 + 14 * 8, 0x2000, 0x48)
    section = optional + 240
    raw[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", raw, section + 8, 0x400, 0x2000, 0x400, 0x200)
    struct.pack_into("<IHHII", raw, 0x200, 0x48, 2, 5, 0x2080, len(root))
    raw[0x280:0x280 + len(root)] = root
    return bytes(raw)


def test_parse_dex_and_evidence_backed_patch_plan():
    raw = _minimal_dex()
    report = android.parse_dex(raw)
    assert report["version"] == "035"
    assert report["strings"][:3] == ["Lcom/example/Security;", "isRooted", "Z"]
    method = report["defined_methods"][0]
    assert method["name"] == "isRooted"
    assert method["proto"]["return"] == "Z"
    assert method["code"]["code_units"] == 2
    plans = android.plan_dex_patches(raw)
    assert plans[0]["categories"] == ["root-detection"]
    assert plans[0]["replacement"]["smali"] == ["const/4 v0, 0x0", "return v0"]
    assert plans[0]["apply"] is False
    assert android.parse_dex(b"not dex") is None


def test_dex_direct_and_virtual_method_deltas_reset_independently():
    raw = bytearray(_minimal_dex())
    class_defs_off = struct.unpack_from("<I", raw, 0x64)[0]
    class_data_off = struct.unpack_from("<I", raw, class_defs_off + 24)[0]
    original = android.parse_dex(bytes(raw))["defined_methods"][0]
    code_off = original["code_offset"]
    encoded = b"\x00\x00\x01\x01" + b"\x00\x01" + _uleb(code_off) + b"\x00\x01" + _uleb(code_off)
    raw[class_data_off:class_data_off + len(encoded)] = encoded
    methods = android.parse_dex(bytes(raw))["defined_methods"]
    assert [(item["method_kind"], item["method_index"]) for item in methods] == [("direct", 0), ("virtual", 0)]


def test_smali_patch_plans_cover_gate_families_without_mutation():
    source = """
.class public Lcom/example/Gates;
.method public isDebuggerConnected()Z
    .locals 1
    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z
    move-result v0
    return v0
.end method
.method public checkServerTrusted()V
    .locals 0
    new-instance v0, Ljavax/net/ssl/SSLPeerUnverifiedException;
    return-void
.end method
"""
    plans = android.plan_smali_patches(source)
    assert [plan["method"] for plan in plans] == ["isDebuggerConnected", "checkServerTrusted"]
    assert plans[0]["categories"] == ["debugger-detection"]
    assert plans[0]["replacement"]["value"] is False
    assert plans[1]["categories"] == ["tls-pinning"]
    assert plans[1]["replacement"]["smali"] == ["return-void"]
    assert all(plan["apply"] is False for plan in plans)


def test_elf_native_security_and_static_markers():
    report = android.parse_elf(_elf64())
    assert report["bits"] == 64 and report["machine"] == "aarch64"
    assert report["hardening"] == {
        "pie": True, "nx_stack": True, "relro": "partial", "stack_canary": False, "fortify": False,
    }
    assert report["frida"][0]["marker"] == "frida-gadget"
    assert report["interesting_strings"][0]["value"].startswith("frida-gadget")
    assert android.parse_elf(b"not elf") is None


def test_elf_dynamic_symbols_dependencies_and_header_variants():
    report = android.parse_elf(_elf64_dynamic())
    assert report["needed"] == ["libc.so"]
    assert report["jni_exports"] == ["JNI_OnLoad", "Java_com_test_nativeFoo"]
    assert report["imports"] == ["__memcpy_chk", "__stack_chk_fail"]
    assert report["hardening"]["stack_canary"] is True
    assert report["hardening"]["fortify"] is True

    elf32 = bytearray(52)
    elf32[:16] = b"\x7fELF\x01\x02\x01" + b"\x00" * 9
    struct.pack_into(">HHIIIIIHHHHHH", elf32, 16, 2, 3, 1, 0x1000, 0, 0, 0, 52, 32, 0, 40, 0, 0)
    parsed32 = android.parse_elf(bytes(elf32))
    assert parsed32["bits"] == 32 and parsed32["endian"] == "big" and parsed32["machine"] == "x86"

    short64 = b"\x7fELF\x02\x01\x01" + b"\x00" * (52 - 7)
    assert android.parse_elf(short64) is None


def test_il2cpp_literal_and_identifier_heap_extraction():
    report = android.parse_il2cpp_metadata(_il2cpp_metadata())
    assert report["version"] == 24
    assert report["literals"][0]["text"] == "CSCTF{unity}"
    assert report["identifier_leads"][0]["value"] == "ApiTokenSecret"
    broken = bytearray(_il2cpp_metadata())
    struct.pack_into("<I", broken, 8, len(broken) + 1)
    assert "inconsistent" in android.parse_il2cpp_metadata(bytes(broken))["notes"][0]


def test_xamarin_dotnet_metadata_streams_and_user_strings():
    report = android.parse_dotnet_metadata(_dotnet_assembly())
    assert report["managed"] is True
    assert report["runtime_version"] == "v4.0.30319"
    assert [stream["name"] for stream in report["streams"]] == ["#Strings", "#US"]
    assert [item["value"] for item in report["strings"]] == ["Chronos.Mobile", "ApiToken"]
    assert report["user_strings"][0]["value"] == "CSCTF{xamarin}"
    assert report["interesting_strings"][-1]["heap"] == "#US"
    assert android.parse_dotnet_metadata(b"not a PE") is None

    virtual_only = bytearray(_dotnet_assembly())
    optional = 0x98
    section = optional + 240
    struct.pack_into("<I", virtual_only, section + 16, 0x60)  # metadata begins at delta 0x80
    assert android.parse_dotnet_metadata(bytes(virtual_only))["error"] == "metadata root range is invalid"


def test_flutter_standard_message_manifest_and_malformed_values():
    report = android.parse_flutter_message(_flutter_manifest_bin())
    assert report["value"] == {"flag.txt": [{"asset": "flag.txt"}]}
    assert report["trailing_bytes"] == 0
    assert android.parse_flutter_message(b"\x0d\x01") is None
    assert android.parse_flutter_message(b"\x07\xff\xff\xff\xff\xff") is None


def test_apk_framework_inventory_xamarin_unity_flutter_and_native():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("classes.dex", _minimal_dex())
        archive.writestr("lib/arm64-v8a/libnative.so", _elf64())
        archive.writestr("lib/arm64-v8a/libil2cpp.so", _elf64())
        archive.writestr("lib/arm64-v8a/libapp.so", _elf64() + b"dart:core\x00package:ctf/main.dart\x00")
        archive.writestr("assemblies/Challenge.dll", _dotnet_assembly())
        archive.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", _il2cpp_metadata())
        archive.writestr("assets/flutter_assets/AssetManifest.json", json.dumps({"flag.txt": ["flag.txt"]}))
        archive.writestr("assets/flutter_assets/AssetManifest.bin", _flutter_manifest_bin())
        archive.writestr("assets/flutter_assets/isolate_snapshot_data", b"dart:core\x00https://api.test/token\x00")
    report = android.inspect_apk(stream.getvalue())
    assert report["frameworks"] == ["xamarin", "unity-il2cpp", "flutter"]
    assert report["dex"][0]["patch_plans"][0]["method"] == "isRooted"
    assert report["native_libraries"][0]["abi"] == "arm64-v8a"
    assert report["xamarin"]["artifacts"][0]["interesting_strings"]
    assert report["xamarin"]["artifacts"][0]["dotnet_metadata"]["managed"] is True
    assert report["unity"]["metadata"][0]["report"]["literals"][0]["text"] == "CSCTF{unity}"
    assert any(item["path"].endswith("isolate_snapshot_data") for item in report["flutter"]["reports"])
    binary_manifest = next(item for item in report["flutter"]["reports"] if item["path"].endswith("AssetManifest.bin"))
    assert binary_manifest["standard_message"]["value"]["flag.txt"][0]["asset"] == "flag.txt"
    assert report["member_count"] == 9 and len(report["sha256"]) == 64


def test_split_bundle_paths_are_inventoried():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("base/dex/classes2.dex", _minimal_dex())
        archive.writestr("base/lib/x86_64/libchallenge.so", _elf64())
    report = android.inspect_apk(stream.getvalue())
    assert report["dex"][0]["path"] == "base/dex/classes2.dex"
    assert report["native_libraries"][0]["abi"] == "x86_64"


def test_android_binary_parsers_fail_closed_for_every_fixture_truncation():
    fixtures = (
        (android.parse_dex, _minimal_dex()),
        (android.parse_elf, _elf64_dynamic()),
        (android.parse_dotnet_metadata, _dotnet_assembly()),
        (android.parse_il2cpp_metadata, _il2cpp_metadata()),
        (android.parse_flutter_message, _flutter_manifest_bin()),
    )
    for parser, fixture in fixtures:
        for cut in range(len(fixture) + 1):
            parser(fixture[:cut])
