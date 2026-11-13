"""Spec-derived tests for fwboot_inventory.

Every fixture below is assembled directly from the published wire layout.  The
builders deliberately do not import or call any engine encoder.
"""
from __future__ import annotations

import hashlib
import random
import struct
import uuid

import fdt as fdt_oracle
import pytest

import fwboot_inventory as engine


def _align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def _u24le(value: int) -> bytes:
    return bytes((value & 0xFF, value >> 8 & 0xFF, value >> 16 & 0xFF))


def _build_fdt(events, reservations=()):
    """Independent DTSpec v17 serializer used only as a test oracle."""
    property_names = []
    for event in events:
        if event[0] == "prop" and event[1] not in property_names:
            property_names.append(event[1])
    name_offsets = {}
    strings = bytearray()
    for name in property_names:
        name_offsets[name] = len(strings)
        strings += name.encode("ascii") + b"\0"

    structure = bytearray()
    stack = []
    nodes_local = {}
    values_local = {}
    for event in events:
        if event[0] == "begin":
            name = event[1]
            token_at = len(structure)
            structure += struct.pack(">I", 1)
            structure += name.encode("utf-8") + b"\0"
            structure += b"\0" * (-len(structure) % 4)
            if not stack:
                path = "/"
            else:
                path = stack[-1].rstrip("/") + "/" + name
            stack.append(path)
            nodes_local[path] = token_at
        elif event[0] == "prop":
            name, value = event[1], event[2]
            token_at = len(structure)
            structure += struct.pack(">III", 3, len(value), name_offsets[name])
            value_at = len(structure)
            structure += value
            structure += b"\0" * (-len(structure) % 4)
            values_local[(stack[-1], name)] = (token_at, value_at)
        elif event[0] == "end":
            structure += struct.pack(">I", 2)
            stack.pop()
        else:  # pragma: no cover - test builder misuse
            raise AssertionError(event)
    assert not stack
    structure += struct.pack(">I", 9)

    reserve = bytearray()
    for address, size in reservations:
        reserve += struct.pack(">QQ", address, size)
    reserve += b"\0" * 16
    reserve_offset = 40
    structure_offset = _align(reserve_offset + len(reserve), 4)
    strings_offset = structure_offset + len(structure)
    total_size = strings_offset + len(strings)
    header = struct.pack(
        ">10I", 0xD00DFEED, total_size, structure_offset, strings_offset,
        reserve_offset, 17, 16, 0, len(strings), len(structure),
    )
    blob = header + bytes(reserve)
    blob += b"\0" * (structure_offset - len(blob))
    blob += bytes(structure) + bytes(strings)
    assert len(blob) == total_size
    return blob, {
        "total_size": total_size,
        "structure_offset": structure_offset,
        "strings_offset": strings_offset,
        "nodes": {path: structure_offset + local for path, local in nodes_local.items()},
        "values": {key: (structure_offset + token, structure_offset + value)
                   for key, (token, value) in values_local.items()},
    }


def _overlay_fixture():
    events = [
        ("begin", ""),
        ("begin", "fragment@0"),
        ("prop", "target-path", b"/soc\0"),
        ("begin", "__overlay__"),
        ("begin", "uart@1000"),
        ("prop", "compatible", b"vendor,uart\0"),
        ("prop", "clocks", struct.pack(">I", 0x1234)),
        ("end",), ("end",), ("end",),
        ("begin", "__symbols__"),
        ("prop", "uart0", b"/fragment@0/__overlay__/uart@1000\0"),
        ("end",),
        ("begin", "__fixups__"),
        ("prop", "soc", b"/fragment@0:target:0\0"),
        ("end",),
        ("begin", "__local_fixups__"),
        ("begin", "fragment@0"), ("begin", "__overlay__"),
        ("begin", "uart@1000"),
        ("prop", "clocks", struct.pack(">I", 0)),
        ("end",), ("end",), ("end",), ("end",),
        ("end",),
    ]
    return _build_fdt(events, reservations=((0x1000, 0x200),))


def _fit_fixture():
    kernel = b"BOOT CSCTF{fit_fixture}\0"
    external = b"DTBO external-device-tree\0"
    kernel_hash = hashlib.sha256(kernel).digest()
    external_hash = hashlib.sha256(external).digest()
    events = [
        ("begin", ""),
        ("prop", "description", b"CSCTF FIT fixture\0"),
        ("prop", "timestamp", struct.pack(">I", 1_700_000_000)),
        ("prop", "#address-cells", struct.pack(">I", 2)),
        ("begin", "images"),
        ("begin", "kernel"),
        ("prop", "description", b"fixture kernel\0"),
        ("prop", "type", b"kernel\0"),
        ("prop", "arch", b"arm64\0"),
        ("prop", "os", b"linux\0"),
        ("prop", "compression", b"none\0"),
        ("prop", "load", struct.pack(">Q", 0x80080000)),
        ("prop", "entry", struct.pack(">Q", 0x80080040)),
        ("prop", "data", kernel),
        ("begin", "hash-1"),
        ("prop", "algo", b"sha256\0"),
        ("prop", "value", kernel_hash),
        ("end",),
        ("begin", "signature-1"),
        ("prop", "algo", b"sha256,rsa2048\0"),
        ("prop", "key-name-hint", b"dev\0"),
        ("prop", "signer-name", b"fixture signer\0"),
        ("prop", "value", bytes(range(64))),
        ("end",),
        ("end",),
        ("begin", "board-dtbo"),
        ("prop", "type", b"flat_dt\0"),
        ("prop", "arch", b"arm64\0"),
        ("prop", "compression", b"none\0"),
        ("prop", "data-size", struct.pack(">I", len(external))),
        ("prop", "data-offset", struct.pack(">I", 0)),
        ("begin", "hash-1"),
        ("prop", "algo", b"sha256\0"),
        ("prop", "value", external_hash),
        ("end",),
        ("end",),
        ("end",),
        ("begin", "configurations"),
        ("prop", "default", b"conf-1\0"),
        ("begin", "conf-1"),
        ("prop", "kernel", b"kernel\0"),
        ("prop", "fdt", b"board-dtbo\0missing-overlay\0"),
        ("prop", "compatible", b"vendor,board\0"),
        ("begin", "signature-1"),
        ("prop", "algo", b"sha256,rsa2048\0"),
        ("prop", "key-name-hint", b"dev\0"),
        ("prop", "sign-images", b"kernel\0fdt\0"),
        ("prop", "hashed-nodes", b"/\0/configurations/conf-1\0/images/kernel\0"),
        ("prop", "hashed-strings", struct.pack(">II", 0, 16)),
        ("prop", "value", b"S" * 256),
        ("end",),
        ("end",),
        ("end",),
        ("begin", "signature"),
        ("prop", "required-mode", b"all\0"),
        ("begin", "key-dev"),
        ("prop", "algo", b"sha256,rsa2048\0"),
        ("prop", "key-name-hint", b"dev\0"),
        ("prop", "required", b"conf\0"),
        ("prop", "rsa,num-bits", struct.pack(">I", 256)),
        ("prop", "rsa,exponent", struct.pack(">Q", 65537)),
        ("prop", "rsa,modulus", bytes(range(32))),
        ("end",),
        ("end",),
        ("end",),
    ]
    fit, meta = _build_fdt(events)
    external_offset = _align(len(fit), 4)
    artifact = fit + b"\0" * (external_offset - len(fit)) + external
    meta.update(kernel=kernel, external=external, external_offset=external_offset)
    return artifact, meta


FFS2_GUID = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3")


def _uefi_fixture():
    """PI FV with one checksummed FREEFORM FFS file and two sections."""
    ui_text = "CSCTF{uefi_fixture}"
    ui_body = (ui_text + "\0").encode("utf-16-le")
    ui_section = _u24le(4 + len(ui_body)) + b"\x15" + ui_body
    section_stream = bytearray(ui_section)
    section_stream += b"\0" * (-len(section_stream) % 4)

    definition_guid = uuid.UUID("12345678-9abc-def0-1234-56789abcdef0")
    vendor_header = b"AUTH"
    section_data = b"KEY=fixture-public-key\0"
    guid_size = 4 + 16 + 2 + 2 + len(vendor_header) + len(section_data)
    guid_section = (_u24le(guid_size) + b"\x02" + definition_guid.bytes_le
                    + struct.pack("<HH", 28, 2) + vendor_header + section_data)
    section_stream += guid_section
    file_data = bytes(section_stream)

    file_guid = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    file_size = 24 + len(file_data)
    file_checksum = (-sum(file_data)) & 0xFF
    ffs_header = bytearray(file_guid.bytes_le)
    ffs_header += bytes((0, file_checksum, 0x02, 0x40))
    ffs_header += _u24le(file_size) + b"\xf8"
    checksum_view = bytearray(ffs_header)
    checksum_view[17] = 0
    checksum_view[23] = 0
    ffs_header[16] = (-sum(checksum_view)) & 0xFF
    assert sum(bytes(ffs_header[:17]) + b"\0" + bytes(ffs_header[18:23]) + b"\0") & 0xFF == 0

    fv_size = 0x200
    header_size = 72
    fv = bytearray(b"\xff" * fv_size)
    fixed = bytearray(b"\0" * 16 + FFS2_GUID.bytes_le)
    fixed += struct.pack("<Q", fv_size)
    fixed += b"_FVH"
    fixed += struct.pack("<IHHHBB", 0x800, header_size, 0, 0, 0, 2)
    fixed += struct.pack("<II", 1, fv_size) + struct.pack("<II", 0, 0)
    assert len(fixed) == header_size
    words = struct.unpack("<" + "H" * (header_size // 2), fixed)
    struct.pack_into("<H", fixed, 50, (-sum(words)) & 0xFFFF)
    assert sum(struct.unpack("<" + "H" * (header_size // 2), fixed)) & 0xFFFF == 0
    fv[:header_size] = fixed
    fv[header_size:header_size + file_size] = ffs_header + file_data

    capsule_guid = uuid.UUID("0d4e0f72-4f1f-4f80-9f4b-f8530e4c2e34")
    capsule_size = 32 + len(fv)
    capsule = (capsule_guid.bytes_le
               + struct.pack("<III", 32, 0x00010000, capsule_size)
               + b"\0" * 4 + bytes(fv))
    return capsule, {
        "fv": bytes(fv), "fv_offset": 32, "file_offset": 32 + header_size,
        "file_guid": str(file_guid), "definition_guid": str(definition_guid),
        "ui_text": ui_text, "section_data": section_data,
    }


def _cbfs_entry(name: str, file_type: int, payload: bytes, attributes: bytes = b""):
    name_raw = name.encode("utf-8") + b"\0"
    attributes_offset = _align(24 + len(name_raw), 4) if attributes else 0
    data_offset = ((attributes_offset + len(attributes)) if attributes
                   else _align(24 + len(name_raw), 4))
    metadata = bytearray(struct.pack(">8sIIII", b"LARCHIVE", len(payload), file_type,
                                         attributes_offset, data_offset))
    metadata += name_raw
    metadata += b"\0" * ((attributes_offset or data_offset) - len(metadata))
    metadata += attributes
    metadata += b"\0" * (data_offset - len(metadata))
    return bytes(metadata) + payload, {"attributes_offset": attributes_offset,
                                       "data_offset": data_offset}


def _cbfs_fixture(legacy=False):
    stage_data = b"ROMSTAGE CSCTF{cbfs_fixture}\0"
    compression = struct.pack(">IIII", 0x42435A4C, 16, 2, 0x1234)
    digest = hashlib.sha256(stage_data).digest()
    hash_attr = struct.pack(">II", 0x68736148, 44) + b"\0\0\0\x02" + digest
    stage = struct.pack(">IIQII", 0x53746748, 24, 0x80000000, 0x40, 0x2000)
    first, first_meta = _cbfs_entry("fallback/romstage", 0x11, stage_data,
                                    compression + hash_attr + stage)
    second_data = b"board=chronos\0serial=42\0"
    second, _ = _cbfs_entry("config", 0x50, second_data)

    if not legacy:
        region = bytearray(first)
        region += b"\xff" * (_align(len(region), 64) - len(region))
        second_offset = len(region)
        region += second
        region += b"\xff" * (_align(len(region), 64) - len(region))
        return bytes(region), {"first": 0, "second": second_offset,
                               "stage_data": stage_data, "first_meta": first_meta}

    region = bytearray(b"\xff" * 512)
    first_offset = 64
    region[first_offset:first_offset + len(first)] = first
    master_offset = 400
    master = struct.pack(">8I", 0x4F524243, 0x31313132, len(region), 32,
                         64, first_offset, 1, 0)
    region[master_offset:master_offset + len(master)] = master
    struct.pack_into("<i", region, len(region) - 4, master_offset - len(region))
    return bytes(region), {"first": first_offset, "master": master_offset,
                           "stage_data": stage_data, "first_meta": first_meta}


def test_dtb_overlay_inventory_matches_independent_fdt_library():
    blob, meta = _overlay_fixture()
    oracle = fdt_oracle.parse_dtb(blob)
    assert oracle.exist_node("/fragment@0/__overlay__/uart@1000")
    assert oracle.get_property("target-path", "/fragment@0").value == "/soc"

    report = engine.parse_dtb(blob)
    assert report["kind"] == "dtb"
    assert report["header"]["reservations"] == [
        {"offset": 40, "address": 0x1000, "size": 0x200}
    ]
    assert report["overlay"]["is_overlay"] is True
    assert report["overlay"]["fragments"] == [{
        "node": "/fragment@0", "offset": meta["nodes"]["/fragment@0"],
        "target_path": "/soc", "overlay_node": "/fragment@0/__overlay__",
    }]
    assert report["overlay"]["symbols"]["uart0"] == "/fragment@0/__overlay__/uart@1000"
    assert report["overlay"]["fixups"]["soc"] == ["/fragment@0:target:0"]
    assert report["overlay"]["local_fixups"][0]["offsets"] == [0]
    target = next(node for node in report["nodes"] if node["path"] == "/fragment@0")
    target_prop = next(prop for prop in target["properties"] if prop["name"] == "target-path")
    assert target_prop["offset"] == meta["values"][("/fragment@0", "target-path")][1]
    assert report["header"]["sha256"] == hashlib.sha256(blob).hexdigest()


def test_fit_images_configurations_signatures_and_control_keys():
    artifact, meta = _fit_fixture()
    oracle = fdt_oracle.parse_dtb(artifact[:meta["total_size"]])
    assert oracle.exist_node("/images/kernel/hash-1")
    assert oracle.exist_node("/configurations/conf-1/signature-1")

    report = engine.parse_fit(artifact)
    assert report["description"] == "CSCTF FIT fixture"
    assert report["timestamp"] == 1_700_000_000
    images = {image["name"]: image for image in report["images"]}
    kernel = images["kernel"]
    assert kernel["load"] == 0x80080000
    assert kernel["entry"] == 0x80080040
    assert kernel["data"]["offset"] == meta["values"][("/images/kernel", "data")][1]
    assert kernel["data"]["sha256"] == hashlib.sha256(meta["kernel"]).hexdigest()
    assert kernel["hashes"][0]["valid"] is True
    assert kernel["signatures"][0]["algo"] == "sha256,rsa2048"
    external = images["board-dtbo"]
    assert external["data"]["storage"] == "external-offset"
    assert external["data"]["offset"] == meta["external_offset"]
    assert external["data"]["sha256"] == hashlib.sha256(meta["external"]).hexdigest()
    assert external["hashes"][0]["valid"] is True

    configuration = report["configurations"][0]
    assert configuration["default"] is True
    assert configuration["image_references"]["fdt"] == ["board-dtbo", "missing-overlay"]
    assert configuration["unresolved_references"] == ["missing-overlay"]
    signature = configuration["signatures"][0]
    assert signature["sign_images"] == ["kernel", "fdt"]
    assert signature["hashed_strings"] == [0, 16]
    assert signature["value"]["sha256"] == hashlib.sha256(b"S" * 256).hexdigest()
    assert "/images/kernel/hash-1" in signature["reconstructed_coverage_nodes"]
    assert "/images/kernel/hash-1" in signature["coverage_missing_from_claim"]
    assert signature["verification"] == "not-performed"
    key = report["keys"][0]
    assert key["rsa_num_bits"] == 256
    assert key["rsa_exponent"]["hex"] == struct.pack(">Q", 65537).hex()
    assert "control FDT" in key["trust"]
    assert report["key_required_mode"] == "all"


def test_uefi_capsule_fv_ffs_and_sections_from_pi_layout():
    capsule, meta = _uefi_fixture()
    capsule_report = engine.parse_uefi_capsule(capsule)
    assert capsule_report["header_size"] == 32
    assert capsule_report["flag_names"] == ["persist-across-reset"]
    assert capsule_report["payload_sha256"] == hashlib.sha256(meta["fv"]).hexdigest()
    assert len(capsule_report["firmware_volumes"]) == 1
    volume = capsule_report["firmware_volumes"][0]
    assert volume["offset"] == meta["fv_offset"]
    assert volume["file_system_guid"] == str(FFS2_GUID)
    assert volume["block_map"] == [{
        "offset": meta["fv_offset"] + 56, "count": 1,
        "block_length": 0x200, "total_length": 0x200,
    }]
    assert volume["header_checksum_ok"] is True
    ffs = volume["files"][0]
    assert ffs["offset"] == meta["file_offset"]
    assert ffs["name_guid"] == meta["file_guid"]
    assert ffs["logical_state"] == 0x07
    assert ffs["header_checksum_ok"] is True
    assert ffs["file_checksum_ok"] is True
    assert ffs["sections"][0]["type"] == "user-interface"
    assert ffs["sections"][0]["user_interface"] == meta["ui_text"]
    guid_section = ffs["sections"][1]
    assert guid_section["definition_guid"] == meta["definition_guid"]
    assert guid_section["attributes"] == 2
    assert guid_section["data_offset"] + len(meta["section_data"]) <= ffs["end_offset"]

    direct = engine.parse_firmware_volume(meta["fv"])
    assert direct["files"][0]["offset"] == 72
    assert direct["sha256"] == hashlib.sha256(meta["fv"]).hexdigest()


def test_cbfs_attributes_hashes_strings_and_legacy_master_header():
    region, meta = _cbfs_fixture()
    report = engine.parse_cbfs(region)
    assert report["file_count"] == 2
    first, second = report["files"]
    assert first["offset"] == meta["first"]
    assert second["offset"] == meta["second"]
    assert first["name"] == "fallback/romstage"
    assert first["type"] == "stage"
    assert first["sha256"] == hashlib.sha256(meta["stage_data"]).hexdigest()
    attrs = {row["kind"]: row for row in first["attributes"]}
    assert attrs["compression"]["algorithm"] == "lz4"
    assert attrs["compression"]["decompressed_size"] == 0x1234
    assert attrs["hash"]["algorithm"] == "sha256"
    assert attrs["hash"]["valid"] is True
    assert attrs["stage-header"]["entry_address"] == 0x80000040
    assert second["embedded_strings"] == [
        {"offset": second["data_offset"], "text": "board=chronos", "truncated": False},
        {"offset": second["data_offset"] + 14, "text": "serial=42", "truncated": False},
    ]
    assert report["legacy_master_header"] is None

    legacy, legacy_meta = _cbfs_fixture(legacy=True)
    legacy_report = engine.parse_cbfs(legacy)
    master = legacy_report["legacy_master_header"]
    assert master["offset"] == legacy_meta["master"]
    assert master["version"] == "1112"
    assert master["architecture"] == "x86"
    assert master["first_file_offset"] == legacy_meta["first"]
    assert master["tail_relative_pointer"] == legacy_meta["master"] - len(legacy)


@pytest.mark.parametrize("parser,fixture", [
    (engine.parse_dtb, lambda: _overlay_fixture()[0]),
    (engine.parse_fit, lambda: _fit_fixture()[0]),
    (engine.parse_uefi_capsule, lambda: _uefi_fixture()[0]),
    (engine.parse_firmware_volume, lambda: _uefi_fixture()[1]["fv"]),
    (engine.parse_cbfs, lambda: _cbfs_fixture()[0]),
])
def test_each_parser_fails_closed_on_truncation_random_and_bitflips(parser, fixture):
    valid = fixture()
    deterministic = random.Random(0xF00B007)
    bitflip = bytearray(valid)
    bitflip[0] ^= 0x80
    corpus = [
        b"", b"\xff" * 256, deterministic.randbytes(257), bytes(bitflip),
        valid[:1], valid[:4], valid[:27], valid[:len(valid) // 2], valid[:-1],
    ]
    for malformed in corpus:
        try:
            parser(malformed)
        except Exception as exc:  # The assertion ensures no stdlib exception escapes.
            assert type(exc) is engine.FWBootError


def test_specific_integrity_and_geometry_corruptions_fail_closed():
    capsule, meta = _uefi_fixture()
    bad_fv = bytearray(meta["fv"])
    bad_fv[60] ^= 1  # block map and therefore the FV header checksum
    with pytest.raises(engine.FWBootError):
        engine.parse_firmware_volume(bytes(bad_fv))

    fit, fit_meta = _fit_fixture()
    bad_fit = bytearray(fit)
    data_position = fit_meta["values"][("/images/kernel", "data")][1]
    bad_fit[data_position - 12:data_position - 8] = struct.pack(">I", len(fit) * 2)
    with pytest.raises(engine.FWBootError):
        engine.parse_fit(bytes(bad_fit))

    cbfs, cbfs_meta = _cbfs_fixture()
    bad_cbfs = bytearray(cbfs)
    attr = cbfs_meta["first_meta"]["attributes_offset"]
    struct.pack_into(">I", bad_cbfs, attr + 4, 7)  # attribute len must be >=8 and /4
    with pytest.raises(engine.FWBootError):
        engine.parse_cbfs(bytes(bad_cbfs))

    with pytest.raises(engine.FWBootError):
        engine.parse_uefi_capsule(capsule[:27])
    with pytest.raises(engine.FWBootError):
        engine.parse_dtb(bytearray(_overlay_fixture()[0]))


def test_auto_dispatch_and_guarded_cli(tmp_path, capsys):
    fit, _ = _fit_fixture()
    assert engine.parse_boot(fit)["kind"] == "fit"
    fv = _uefi_fixture()[1]["fv"]
    assert engine.parse_boot(fv)["kind"] == "uefi-firmware-volume"
    cbfs = _cbfs_fixture()[0]
    assert engine.parse_boot(cbfs)["kind"] == "cbfs"

    path = tmp_path / "fixture.fit"
    path.write_bytes(fit)
    assert engine.main([str(path), "--format", "fit", "--compact"]) == 0
    output = capsys.readouterr().out
    assert json_kind(output) == "fit"
    assert engine.main(["--help"]) == 0
    capsys.readouterr()
    assert engine.main([]) == 2
    capsys.readouterr()


def json_kind(output: str) -> str:
    # Avoid importing the engine's JSON rendering path as an oracle.
    import json
    return json.loads(output)["kind"]
