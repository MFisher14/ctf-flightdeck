"""Independent iOS/container vector locks and deterministic malformed input tests.

Oracles: macholib 1.16.4, plistlib, zipfile, and Apple public structure definitions:
https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h
No engine encoder or existing test fixture establishes expected output.
"""
import hashlib
import io
import plistlib
import random
import struct
import uuid
import zipfile

import pytest
from macholib import mach_o as mo
from macholib.MachO import MachO

import ios_depth as ios
import mobile_depth as mobile
import mobile_rf_depth as mrf


def _thin(bits=64, endian="<", commands=(), cpu=None):
    # Fixture writer derives constants from macholib, independent of ios_depth.
    cpu = cpu if cpu is not None else (0x0100000c if bits == 64 else 12)
    fields = [mo.MH_MAGIC_64 if bits == 64 else mo.MH_MAGIC,
              cpu, 0, mo.MH_EXECUTE, len(commands), sum(map(len, commands)), mo.MH_PIE]
    if bits == 64:
        fields.append(0)
    return struct.pack(endian + "I" * len(fields), *fields) + b"".join(commands)


def _dylib(kind):
    name = b"/usr/lib/libSystem.B.dylib\x00"
    name += b"\x00" * (-len(name) % 8)
    return struct.pack("<6I", kind, 24 + len(name), 24, 17, 0x10203, 0x10000) + name


def _oracle(tmp_path, raw):
    path = tmp_path / "oracle.macho"
    path.write_bytes(raw)
    return MachO(str(path))


@pytest.mark.parametrize("bits,endian", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_thin_headers_against_macholib(tmp_path, bits, endian):
    raw = _thin(bits, endian)
    oracle = _oracle(tmp_path, raw).headers[0]
    result = ios.parse_macho(raw)
    expected = oracle.header
    assert result["bits"] == (64 if isinstance(expected, mo.mach_header_64) else 32)
    assert result["endian"] == {"<": "little", ">": "big"}[oracle.endian]
    assert result["cpu_type"] == expected.cputype
    assert result["cpu_subtype"] == expected.cpusubtype
    assert result["commands_count"] == expected.ncmds
    assert result["commands_size"] == expected.sizeofcmds
    assert result["flags"] == expected.flags
    assert result["file_type"] == "execute"  # mo.MH_EXECUTE above, Apple loader.h


def _fat(wide=False):
    slices = (_thin(32), _thin(64, cpu=0x01000007))
    offsets = (256, 512)
    result = bytearray(struct.pack(">II", mo.FAT_MAGIC_64 if wide else mo.FAT_MAGIC, 2))
    for cpu, data, offset in zip((12, 0x01000007), slices, offsets):
        result += (struct.pack(">IIQQII", cpu, 0, offset, len(data), 8, 0) if wide
                   else struct.pack(">IIIII", cpu, 0, offset, len(data), 8))
    for data, offset in zip(slices, offsets):
        result += b"\0" * (offset - len(result)) + data
    return bytes(result)


@pytest.mark.parametrize("wide", [False, True])
def test_fat_headers_against_macholib(tmp_path, wide):
    raw = _fat(wide)
    oracle = _oracle(tmp_path, raw)
    result = ios.parse_macho(raw)
    assert result["slice_count"] == len(oracle.headers) == 2
    for actual, header in zip(result["slices"], oracle.headers):
        assert actual["offset"] == header.offset
        assert actual["size"] == header.size
        assert actual["cpu_type"] == header.header.cputype
        assert actual["macho"]["flags"] == header.header.flags
        assert actual["macho"]["file_offset"] == header.offset


@pytest.mark.parametrize("kind", [mo.LC_LOAD_DYLIB, mo.LC_ID_DYLIB,
    mo.LC_LOAD_WEAK_DYLIB, mo.LC_LAZY_LOAD_DYLIB, mo.LC_LOAD_UPWARD_DYLIB,
    mo.LC_REEXPORT_DYLIB])
def test_dylib_commands_against_macholib(tmp_path, kind):
    raw = _thin(commands=(_dylib(kind),))
    command, body, payload = _oracle(tmp_path, raw).headers[0].commands[0]
    assert command.cmd == kind
    expected_name = payload.split(b"\0", 1)[0].decode()
    actual = ios.parse_macho(raw)
    assert [item["path"] for item in actual["dylibs"]] == [expected_name]


def test_uuid_and_build_commands_against_macholib(tmp_path):
    raw_uuid = bytes(range(16))
    raw = _thin(commands=(struct.pack("<II", mo.LC_UUID, 24) + raw_uuid,
                          struct.pack("<6I", mo.LC_BUILD_VERSION, 24, 2, 0x110201, 0x120000, 0)))
    commands = _oracle(tmp_path, raw).headers[0].commands
    result = ios.parse_macho(raw)
    assert result["uuid"] == str(uuid.UUID(bytes=commands[0][1].uuid))
    b = commands[1][1]
    version = lambda v: ".".join(str((int(v) >> s) & mask) for s, mask in ((16, 65535), (8, 255), (0, 255)))
    assert result["build_versions"] == [{"platform": "ios", "minimum": version(b.minos),
                                           "sdk": version(b.sdk), "tools": []}]


def _dyld():
    # Apple dyld_cache_header legacy image fields, mapping/image_info layouts.
    raw = bytearray(320)
    raw[:16] = b"dyld_v1  arm64e\0\0"
    struct.pack_into("<4I", raw, 16, 128, 1, 160, 1)
    raw[88:104] = bytes(range(16))
    struct.pack_into("<3Q2I", raw, 128, 0x180000000, 32, 256, 7, 5)
    struct.pack_into("<3Q2I", raw, 160, 0x180001000, 123456789, 321, 192, 0)
    name = b"/usr/lib/libSystem.B.dylib\0"
    raw[192:192 + len(name)] = name
    return bytes(raw)


def test_dyld_published_structures():
    result = ios.parse_dyld_shared_cache(_dyld())
    assert result["uuid"] == bytes(range(16)).hex()
    assert result["architecture"] == "arm64e"
    assert result["mappings"] == [{"index": 0, "address": 0x180000000, "size": 32,
        "file_offset": 256, "max_protection": 7, "initial_protection": 5, "range_valid": True}]
    assert result["images"] == [{"index": 0, "address": 0x180001000,
        "modification_time": 123456789, "inode": 321, "path_offset": 192,
        "path": "/usr/lib/libSystem.B.dylib", "padding": 0}]


def _archive(items):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in items:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(info, data)
    return stream.getvalue()


def _ipa(info=None, executable=None):
    if info is None:
        info = {"CFBundleIdentifier": "ro.chronos.lock", "CFBundleExecutable": "Lock",
                "CFBundleDisplayName": "Vector Lock", "CFBundleShortVersionString": "1.2.3",
                "CFBundleVersion": "77", "CFBundleURLTypes": [{"CFBundleURLSchemes": ["csctf", "lock"]}],
                "NSCameraUsageDescription": "CSCTF{binary_plist}",
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    info_data = plistlib.dumps(info, fmt=plistlib.FMT_BINARY) if isinstance(info, dict) else info
    return _archive([("Payload/Lock.app/", b""), ("Payload/Lock.app/Info.plist", info_data),
        ("Payload/Lock.app/Lock", executable if executable is not None else _thin()),
        ("Payload/Lock.app/entitlements.plist", plistlib.dumps({"get-task-allow": True}, fmt=plistlib.FMT_BINARY)),
        ("__MACOSX/._ignored", b"metadata")])


def test_ipa_binary_plist_against_plistlib_and_zipfile():
    raw = _ipa()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = plistlib.loads(archive.read("Payload/Lock.app/Info.plist"))
        count = sum(not item.is_dir() for item in archive.infolist())
    result = ios.inspect_ipa(raw)
    app = result["apps"][0]
    assert result["member_count"] == count
    assert result["sha256"] == hashlib.sha256(raw).hexdigest()
    assert app["bundle_id"] == info["CFBundleIdentifier"]
    assert app["display_name"] == info["CFBundleDisplayName"]
    assert app["version"] == info["CFBundleShortVersionString"]
    assert app["build"] == info["CFBundleVersion"]
    assert app["url_schemes"] == sorted(info["CFBundleURLTypes"][0]["CFBundleURLSchemes"])
    assert app["ats"] == info["NSAppTransportSecurity"]
    assert app["privacy_usage"] == {"NSCameraUsageDescription": info["NSCameraUsageDescription"]}


def test_mobile_depth_ipa_binary_plist_against_plistlib():
    raw = _ipa()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = plistlib.loads(archive.read("Payload/Lock.app/Info.plist"))
        entitlements = plistlib.loads(archive.read("Payload/Lock.app/entitlements.plist"))
    result = mobile.triage_ipa(raw)
    assert result["bundle_id"] == info["CFBundleIdentifier"]
    assert result["versions"] == {"short": "1.2.3", "build": "77"}
    assert result["url_schemes"] == info["CFBundleURLTypes"][0]["CFBundleURLSchemes"]
    assert result["entitlements"] == [{"member": "Payload/Lock.app/entitlements.plist", "values": entitlements}]


def test_mobile_crossplatform_zipfile_oracle():
    entries = [("assets/index.android.bundle", b"CSCTF{react}\0"),
               ("assets/flutter_assets/key.bin", b"\0https://example.invalid\0"),
               ("assets/", b""), ("lib/arm64-v8a/libapp.so", b"ELF-like bytes")]
    raw = _archive(entries)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        bodies = {i.filename: archive.read(i) for i in archive.infolist() if not i.is_dir()}
    out = mobile.extract_crossplatform(raw)
    assert out["react_native_members"] == ["assets/index.android.bundle"]
    assert out["flutter_members"] == ["assets/flutter_assets/key.bin", "lib/arm64-v8a/libapp.so"]
    assert out["frameworks"] == ["react-native", "flutter"]
    for item in out["candidates"]:
        assert bodies[item["origin"]][item["offset"]:].startswith(item["value"].encode())
    assert {item["value"] for item in out["candidates"]} == {"CSCTF{react}", "https://example.invalid"}


def test_static_frida_evidence_offsets():
    # Public Frida artifact/symbol names, compared with independent bytes search.
    raw = b"\0frida_agent_main\0ordinary\0frida_agent_main\0"
    out = ios.detect_frida(raw, paths=["Frameworks/FridaGadget.dylib"])
    assert out["detected"] is True
    item = next(i for i in out["evidence"] if i["kind"] == "byte-marker")
    marker = b"frida_agent_main"
    assert item["offsets"] == [raw.index(marker), raw.rindex(marker)]
    assert {i["value"] for i in out["evidence"] if i["kind"] == "path"} == {"Frameworks/FridaGadget.dylib"}


def _mutations(valid):
    yield b""
    for n in (1, 2, 3, 4, 7, 15, 31, 63, 127):
        yield b"\xff" * n
    rng = random.Random(0x105)
    for n in range(64):
        yield rng.randbytes(n)
    for cut in range(len(valid)):
        yield valid[:cut]
    for index in range(len(valid)):
        changed = bytearray(valid)
        changed[index] ^= 1 << (index % 8)
        yield bytes(changed)


@pytest.mark.parametrize("parser,raw", [(ios.parse_macho, _thin(commands=(_dylib(mo.LC_LOAD_DYLIB),))),
    (ios.parse_macho, _fat()), (ios.parse_macho, _fat(True)),
    (ios.parse_dyld_shared_cache, _dyld()), (ios.detect_frida, b"frida-gadget\0frida_agent_main")])
def test_binary_fuzz_has_no_undeclared_exception(parser, raw):
    # Structured partial reports are intentional API behavior for these readers.
    for value in _mutations(raw):
        result = parser(value)
        assert result is None or isinstance(result, dict)


@pytest.mark.parametrize("parser", [ios.inspect_ipa, mobile.triage_ipa, mobile.extract_crossplatform])
def test_package_parsers_fuzz_embedded_bytes(parser):
    for value in _mutations(_thin()):
        assert isinstance(parser(_ipa(executable=value)), dict)


@pytest.mark.parametrize("parser,error", [(ios.inspect_ipa, ios.ArtifactError),
    (mobile.triage_ipa, mobile.ArtifactError), (mobile.extract_crossplatform, mobile.ArtifactError)])
@pytest.mark.parametrize("value", [b"", b"\xff" * 64, random.Random(105).randbytes(64),
    b"PK\x03\x04", _ipa()[:31], _ipa()[:-22]])
def test_archive_fuzz_rejection_uses_declared_error(parser, error, value):
    with pytest.raises(error):
        parser(value)


def _bad_crc():
    raw = bytearray(_ipa())
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.getinfo("Payload/Lock.app/Info.plist")
        filename, extra = struct.unpack_from("<HH", raw, info.header_offset + 26)
        start = info.header_offset + 30 + filename + extra
    raw[start] ^= 1
    return bytes(raw)


@pytest.mark.parametrize("parser,error", [(ios.inspect_ipa, ios.ArtifactError),
    (mobile.triage_ipa, mobile.ArtifactError), (mobile.extract_crossplatform, mobile.ArtifactError)])
def test_archive_bitflip_crc_uses_declared_error(parser, error):
    with pytest.raises(error):
        parser(_bad_crc())


@pytest.mark.parametrize("parser", [ios.inspect_ipa, mobile.triage_ipa])
@pytest.mark.parametrize("info", [b'<?xml version="1.0"?><plist><dict>',
    b'<?xml version="1.0" encoding="unknown-csctf"?><plist><dict/></plist>'])
def test_truncated_xml_plist_uses_declared_error(parser, info):
    if parser is ios.inspect_ipa:
        assert parser(_ipa(info=info))["apps"] == [
            {"path": "Payload/Lock.app/", "error": "Info.plist is invalid"}]
    else:
        with pytest.raises(mobile.ArtifactError, match="Info.plist is invalid"):
            parser(_ipa(info=info))


@pytest.mark.parametrize("parser", [ios.inspect_ipa, mobile.triage_ipa])
@pytest.mark.parametrize("schemes", [7, "csctf", {"csctf": True}])
def test_plist_field_mutation_uses_declared_error(parser, schemes):
    out = parser(_ipa(info={"CFBundleURLTypes": [{"CFBundleURLSchemes": schemes}]}))
    assert (out["apps"][0] if parser is ios.inspect_ipa else out)["url_schemes"] == []


@pytest.mark.parametrize("bits,endian", [(32, "<"), (32, ">"), (64, "<"), (64, ">")])
def test_mobile_rf_thin_macho_against_macholib(tmp_path, bits, endian):
    raw = _thin(bits, endian)
    header = _oracle(tmp_path, raw).headers[0].header
    out = mrf.parse_macho(raw)
    assert out["format"] == f"macho{bits}"
    assert out["byte_order"] == {"<": "little", ">": "big"}[endian]
    assert (out["cpu_type"], out["cpu_subtype"], out["file_type"], out["flags"]) == (
        header.cputype, header.cpusubtype, header.filetype, header.flags)


@pytest.mark.parametrize("wide", [False, True])
def test_mobile_rf_fat_macho_against_macholib(tmp_path, wide):
    raw = _fat(wide)
    oracle = _oracle(tmp_path, raw)
    out = mrf.parse_macho(raw)
    assert out["format"] == ("fat64" if wide else "fat")
    assert len(out["slices"]) == len(oracle.headers)
    for actual, expected in zip(out["slices"], oracle.headers):
        assert (actual["cpu_type"], actual["offset"], actual["size"]) == (
            expected.header.cputype, expected.offset, expected.size)


@pytest.mark.parametrize("kind", [mo.LC_LOAD_DYLIB, mo.LC_ID_DYLIB,
    mo.LC_LOAD_WEAK_DYLIB, mo.LC_LAZY_LOAD_DYLIB, mo.LC_LOAD_UPWARD_DYLIB, mo.LC_REEXPORT_DYLIB])
def test_mobile_rf_dylibs_against_macholib(tmp_path, kind):
    raw = _thin(commands=(_dylib(kind),))
    _, _, payload = _oracle(tmp_path, raw).headers[0].commands[0]
    assert mrf.parse_macho(raw)["dylibs"] == [payload.split(b"\0", 1)[0].decode()]


def test_mobile_rf_dyld_published_layout():
    out = mrf.parse_dyld_cache(_dyld())
    assert out["mappings"] == [{"address": 0x180000000, "size": 32, "file_offset": 256,
                                "max_protection": 7, "initial_protection": 5}]
    assert out["images"] == [{"address": 0x180001000, "mod_time": 123456789,
                              "inode": 321, "path": "/usr/lib/libSystem.B.dylib"}]


def test_mobile_rf_bundle_zipfile_names():
    entries = [("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"metadata"),
               ("lib/arm64-v8a/libil2cpp.so", b"native"),
               ("assets/flutter_assets/AssetManifest.json", b"{}"),
               ("lib/arm64-v8a/libapp.so", b"aot"),
               ("assemblies/Mono.Android.dll", b"assembly")]
    raw = _archive(entries)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = archive.namelist()
    out = mrf.inspect_mobile_bundle(raw)
    assert out["member_count"] == len(names)
    assert out["unity_metadata"] == [names[0]]
    assert out["unity_native"] == [names[1]]
    assert out["flutter_assets"] == [names[2]]
    assert out["flutter_aot"] == [names[3]]
    assert out["xamarin_dotnet"] == [names[4]]
    assert out["runtime_pairs"] == {"xamarin_or_maui": True, "unity_il2cpp": True, "flutter_aot": True}


@pytest.mark.parametrize("parser,raw", [(mrf.parse_macho, _thin(commands=(_dylib(mo.LC_REEXPORT_DYLIB),))),
    (mrf.parse_macho, _fat()), (mrf.parse_macho, _fat(True)),
    (mrf.parse_dyld_cache, _dyld()), (mrf.inspect_mobile_bundle, _ipa())],
    ids=["thin", "fat32", "fat64", "dyld", "bundle"])
def test_mobile_rf_byte_fuzz_declared_error_only(parser, raw):
    for value in _mutations(raw):
        try:
            assert isinstance(parser(value), dict)
        except mrf.ArtifactError:
            pass


def _bad_extract_version(index):
    raw = bytearray(_ipa())
    pos = -1
    for _ in range(index + 1):
        pos = raw.index(b"PK\x01\x02", pos + 1)
    raw[pos + 6] ^= 64  # version needed: 20 -> 84
    return bytes(raw)


@pytest.mark.parametrize("index", [0, 2])
def test_mobile_rf_bad_extract_version_rejected(index):
    with pytest.raises(mrf.ArtifactError):
        mrf.inspect_mobile_bundle(_bad_extract_version(index))


def test_mobile_rf_recursive_fat_rejected():
    # One FAT32 slice refers to exactly the same bytes as its parent envelope.
    raw = struct.pack(">7I", mo.FAT_MAGIC, 1, 12, 0, 0, 28, 0)
    with pytest.raises(mrf.ArtifactError):
        mrf.parse_macho(raw)


def test_mobile_rf_nested_fat_rejected():
    # FAT architecture data must be thin Mach-O, even when the ranges do not overlap.
    child = _fat()
    raw = struct.pack(">7I", mo.FAT_MAGIC, 1, 12, 0, 28, len(child), 0) + child
    with pytest.raises(mrf.ArtifactError, match="thin Mach-O"):
        mrf.parse_macho(raw)


@pytest.mark.parametrize("main", [ios.main, mobile.main, mrf.main])
@pytest.mark.parametrize("argv,code", [(["--help"], 0), ([], 2), (["--not-an-option"], 2)])
def test_mobile_cli_argument_exits_are_guarded(main, argv, code, capsys):
    assert main(argv) == code
