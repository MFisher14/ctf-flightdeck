import io
import plistlib
import struct
import zipfile

from solvers.toolkits import ios_depth as ios


def _align(blob, width=8):
    return blob + b"\x00" * (-len(blob) % width)


def _macho64(*, frida=False):
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__cstring", b"__TEXT", 0x100001000, 0x20, 0x1000, 2, 0, 0, 2, 0, 0, 0,
    )
    segment = struct.pack(
        "<II16sQQQQIIII",
        0x19, 72 + len(section), b"__TEXT", 0x100000000, 0x2000, 0, 0x2000, 7, 5, 1, 0,
    ) + section
    uuid = struct.pack("<II", 0x1B, 24) + bytes(range(16))
    rpath_value = b"@executable_path/Frameworks\x00"
    rpath = _align(struct.pack("<III", 0x8000001C, 12 + len(rpath_value), 12) + rpath_value)
    rpath = struct.pack("<II", 0x8000001C, len(rpath)) + rpath[8:]
    dylib_value = (b"@rpath/FridaGadget.dylib\x00" if frida else b"/usr/lib/libSystem.B.dylib\x00")
    dylib = _align(struct.pack("<IIIIII", 0x0C, 24 + len(dylib_value), 24, 0, 0x10000, 0x10000) + dylib_value)
    dylib = struct.pack("<II", 0x0C, len(dylib)) + dylib[8:]
    build = struct.pack("<IIIIIIII", 0x32, 32, 2, 0x00100000, 0x00110000, 1, 3, 0x000F0000)
    encryption = struct.pack("<IIIIII", 0x2C, 24, 0x1000, 0x200, 1, 0)

    entitlements = plistlib.dumps({
        "application-identifier": "TEAM.example.app",
        "keychain-access-groups": ["TEAM.shared"],
        "get-task-allow": True,
        "com.apple.developer.associated-domains": ["applinks:example.test"],
    })
    entitlement_blob = struct.pack(">II", 0xFADE7171, 8 + len(entitlements)) + entitlements
    signature = struct.pack(">III", 0xFADE0CC0, 20 + len(entitlement_blob), 1)
    signature += struct.pack(">II", 5, 20) + entitlement_blob
    commands_without_tables = segment + uuid + rpath + dylib + build + encryption
    signature_offset = 32 + len(commands_without_tables) + 16 + 24
    string_table = b"\x00_FridaGadget\x00_main\x00"
    symbols = struct.pack("<IBBHQ", 1, 0x01, 0, 0, 0)
    symbols += struct.pack("<IBBHQ", 14, 0x0F, 1, 0, 0x100001000)
    symbols_offset = signature_offset + len(signature)
    strings_offset = symbols_offset + len(symbols)
    signature_command = struct.pack("<IIII", 0x1D, 16, signature_offset, len(signature))
    symbol_command = struct.pack("<IIIIII", 2, 24, symbols_offset, 2, strings_offset, len(string_table))
    commands = commands_without_tables + signature_command + symbol_command
    header = b"\xcf\xfa\xed\xfe" + struct.pack(
        "<IIIIIII", 0x0100000C, 2, 2, 8, len(commands), 0x01200000, 0,
    )
    tail = b"frida_agent_main" if frida else b"normal payload"
    return header + commands + signature + symbols + string_table + tail


def _macho32_big_endian():
    version = struct.pack(">IIII", 0x25, 16, 0x000C0100, 0x00110000)
    return b"\xfe\xed\xfa\xce" + struct.pack(">IIIIII", 12, 0, 2, 1, len(version), 0) + version


def test_parse_thin_macho_load_commands_entitlements_and_frida():
    report = ios.parse_macho(_macho64(frida=True))
    assert report["architecture"] == "arm64e"
    assert report["file_type"] == "execute"
    assert report["uuid"] == "00010203-0405-0607-0809-0a0b0c0d0e0f"
    assert report["segments"][0]["sections"][0]["name"] == "__cstring"
    assert report["rpaths"] == ["@executable_path/Frameworks"]
    assert report["dylibs"][0]["path"] == "@rpath/FridaGadget.dylib"
    assert report["build_versions"][0]["platform"] == "ios"
    assert report["encryption"][0]["encrypted"] is True
    assert report["pie"] is True and report["no_heap_execution"] is True
    assert report["code_signature"]["entitlements"]["get-task-allow"] is True
    assert report["imports"] == ["_FridaGadget"]
    assert report["exports"] == ["_main"]
    assert report["frida"]["detected"] is True


def test_universal_macho_and_truncated_tables_fail_closed():
    thin = _macho64()
    offset = 28
    fat = b"\xca\xfe\xba\xbe" + struct.pack(">I", 1)
    fat += struct.pack(">IIIII", 0x0100000C, 2, offset, len(thin), 2) + thin
    report = ios.parse_macho(fat)
    assert report["kind"] == "universal"
    assert report["slices"][0]["macho"]["architecture"] == "arm64e"
    malformed = b"\xca\xfe\xba\xbe" + struct.pack(">I", ios.MAX_SLICES + 1)
    assert "cap" in ios.parse_macho(malformed)["notes"][0]
    assert ios.parse_macho(b"not a macho") is None


def test_macho_32bit_big_endian_fat64_little_endian_and_bad_command():
    thin = _macho32_big_endian()
    parsed = ios.parse_macho(thin)
    assert parsed["bits"] == 32 and parsed["endian"] == "big"
    assert parsed["architecture"] == "arm"
    assert parsed["build_versions"] == [{"platform": "iphoneos", "minimum": "12.1.0", "sdk": "17.0.0"}]

    offset = 40
    fat64 = b"\xbf\xba\xfe\xca" + struct.pack("<I", 1)
    fat64 += struct.pack("<IIQQII", 12, 0, offset, len(thin), 3, 0) + thin
    universal = ios.parse_macho(fat64)
    assert universal["slice_count"] == 1
    assert universal["slices"][0]["reserved"] == 0
    assert universal["slices"][0]["macho"]["bits"] == 32

    bad = b"\xce\xfa\xed\xfe" + struct.pack("<IIIIII", 7, 0, 2, 1, 8, 0)
    bad += struct.pack("<II", 1, 4)
    assert "invalid size" in ios.parse_macho(bad)["notes"][0]


def test_parse_dyld_cache_mapping_and_images():
    blob = bytearray(0x140)
    blob[:16] = b"dyld_v1  arm64e\x00"
    struct.pack_into("<IIII", blob, 16, 0x80, 1, 0xA0, 1)
    blob[0x58:0x68] = bytes(range(16))
    struct.pack_into("<QQQII", blob, 0x80, 0x180000000, 0x20, 0x100, 5, 5)
    struct.pack_into("<QQQII", blob, 0xA0, 0x180001000, 123, 456, 0xC0, 0)
    blob[0xC0:0xC0 + 30] = b"/usr/lib/libSystem.B.dylib\x00"
    report = ios.parse_dyld_shared_cache(bytes(blob))
    assert report["architecture"] == "arm64e"
    assert report["mappings"][0]["file_offset"] == 0x100
    assert report["images"][0]["path"] == "/usr/lib/libSystem.B.dylib"
    assert report["uuid"] == bytes(range(16)).hex()
    assert ios.parse_dyld_shared_cache(b"dyld but not a cache") is None


def test_dyld_ranges_and_frida_detection_fail_closed():
    blob = bytearray(0x80)
    blob[:16] = b"dyld_v1  arm64\x00\x00"
    struct.pack_into("<IIII", blob, 16, 0x70, 2, 0x70, 2)
    report = ios.parse_dyld_shared_cache(bytes(blob))
    assert report["images"] == [] and report["mappings"] == []
    assert len(report["notes"]) == 2
    assert ios.detect_frida(b"ordinary", paths=["Frameworks/Gadget.dylib"])["detected"] is False
    evidence = ios.detect_frida(b"xxfrida_agent_mainxx", paths=[])
    assert evidence["detected"] is True and evidence["evidence"][0]["offsets"] == [2]


def test_inspect_ipa_plists_provisioning_macho_and_paths():
    info = {
        "CFBundleIdentifier": "ro.chronos.sample",
        "CFBundleExecutable": "Sample",
        "CFBundleDisplayName": "Sample App",
        "CFBundleShortVersionString": "1.2.3",
        "CFBundleVersion": "7",
        "MinimumOSVersion": "15.0",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["chronos", "csctf"]}],
        "LSApplicationQueriesSchemes": ["otherapp"],
        "NSCameraUsageDescription": "Puzzle camera",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
    provision = plistlib.dumps({
        "Name": "Development",
        "UUID": "00000000-0000-0000-0000-000000000001",
        "Entitlements": {"application-identifier": "TEAM.ro.chronos.sample"},
    })
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("Payload/Sample.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        archive.writestr("Payload/Sample.app/Sample", _macho64(frida=True))
        archive.writestr("Payload/Sample.app/embedded.mobileprovision", b"CMS" + provision + b"TRAILER")
        archive.writestr("Payload/Sample.app/Frameworks/FridaGadget.dylib", b"frida-gum")
        archive.writestr("Payload/Sample.app/Other.plist", plistlib.dumps({"x": 1}))
        archive.writestr("Payload/Sample.app/PlugIns/Widget.appex/Info.plist", plistlib.dumps({
            "CFBundleIdentifier": "ro.chronos.sample.widget", "CFBundleExecutable": "Widget",
        }))
        archive.writestr("Payload/Sample.app/PlugIns/Widget.appex/Widget", _macho64())
    report = ios.inspect_ipa(stream.getvalue())
    app = report["apps"][0]
    assert app["bundle_id"] == "ro.chronos.sample"
    assert app["url_schemes"] == ["chronos", "csctf"]
    assert app["query_schemes"] == ["otherapp"]
    assert app["privacy_usage"]["NSCameraUsageDescription"] == "Puzzle camera"
    assert app["provisioning"]["name"] == "Development"
    assert app["signature_entitlements"]["keychain-access-groups"] == ["TEAM.shared"]
    assert app["associated_domains"] == ["applinks:example.test"]
    assert app["frida"]["detected"] is True
    assert report["apps"][1]["bundle_kind"] == "extension"
    assert report["apps"][1]["bundle_id"] == "ro.chronos.sample.widget"
    assert report["sha256"] and report["member_count"] == 7


def test_ipa_rejects_non_zip_and_malformed_macho_is_reported():
    try:
        ios.inspect_ipa(b"not a zip")
    except ValueError as exc:
        assert "readable ZIP" in str(exc)
    else:
        raise AssertionError("invalid IPA was accepted")

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("Payload/Broken.app/Info.plist", plistlib.dumps({"CFBundleExecutable": "Broken"}))
        archive.writestr("Payload/Broken.app/Broken", b"\xcf\xfa\xed\xfe")
    report = ios.inspect_ipa(stream.getvalue())
    assert report["apps"][0]["macho"]["error"] == "truncated Mach-O header"


def test_ios_binary_parsers_fail_closed_for_every_fixture_truncation():
    cache = bytearray(0x140)
    cache[:16] = b"dyld_v1  arm64e\x00"
    struct.pack_into("<IIII", cache, 16, 0x80, 1, 0xA0, 1)
    struct.pack_into("<QQQII", cache, 0x80, 0x180000000, 0x20, 0x100, 5, 5)
    struct.pack_into("<QQQII", cache, 0xA0, 0x180001000, 0, 0, 0xC0, 0)
    cache[0xC0:0xC5] = b"/lib\x00"
    for parser, fixture in ((ios.parse_macho, _macho64(frida=True)),
                            (ios.parse_dyld_shared_cache, bytes(cache))):
        for cut in range(len(fixture) + 1):
            parser(fixture[:cut])
