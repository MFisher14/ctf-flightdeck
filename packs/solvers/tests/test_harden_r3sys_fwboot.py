"""Independent spec vectors and fail-closed checks for fwboot_inventory.

The packers transcribe DTSpec v17, PI FV/FFS, EFI_CAPSULE_HEADER, and CBFS
layouts directly.  They never call an encoder or use output from the engine.
"""
from __future__ import annotations

import hashlib
import json
import random
import struct
import uuid

import pytest

import fwboot_inventory as engine


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def u24le(value: int) -> bytes:
    return bytes((value & 0xFF, value >> 8 & 0xFF, value >> 16 & 0xFF))


def fdt_blob(events):
    """Small independent DTSpec v17 structure/string-block serializer."""
    names = []
    for event in events:
        if event[0] == "prop" and event[1] not in names:
            names.append(event[1])
    strings = bytearray()
    name_offsets = {}
    for name in names:
        name_offsets[name] = len(strings)
        strings += name.encode("ascii") + b"\0"

    structure = bytearray()
    stack = []
    nodes = {}
    values = {}
    for event in events:
        if event[0] == "begin":
            name = event[1]
            local = len(structure)
            structure += struct.pack(">I", 1) + name.encode() + b"\0"
            structure += b"\0" * (-len(structure) % 4)
            path = "/" if not stack else stack[-1].rstrip("/") + "/" + name
            stack.append(path)
            nodes[path] = local
        elif event[0] == "prop":
            name, value = event[1:]
            token = len(structure)
            structure += struct.pack(">III", 3, len(value), name_offsets[name])
            value_at = len(structure)
            structure += value
            structure += b"\0" * (-len(structure) % 4)
            values[(stack[-1], name)] = (token, value_at)
        elif event[0] == "end":
            structure += struct.pack(">I", 2)
            stack.pop()
        else:  # pragma: no cover - builder misuse
            raise AssertionError(event)
    assert not stack
    structure += struct.pack(">I", 9)

    reserve = b"\0" * 16
    reserve_offset = 40
    structure_offset = align(reserve_offset + len(reserve), 4)
    strings_offset = structure_offset + len(structure)
    total = strings_offset + len(strings)
    header = struct.pack(
        ">10I", 0xD00DFEED, total, structure_offset, strings_offset,
        reserve_offset, 17, 16, 0x10203040, len(strings), len(structure),
    )
    blob = header + reserve + bytes(structure) + bytes(strings)
    assert len(blob) == total
    return blob, {
        "nodes": {path: structure_offset + offset for path, offset in nodes.items()},
        "values": {key: structure_offset + value for key, (_, value) in values.items()},
        "total": total,
    }


def dtb_fixture():
    return fdt_blob([
        ("begin", ""),
        ("prop", "compatible", b"chronos,fixture\0"),
        ("begin", "chosen"),
        ("prop", "bootargs", b"console=ttyS0\0"),
        ("end",), ("end",),
    ])


def fit_fixture():
    payload = b"synthetic FIT payload\0"
    digest = hashlib.sha256(payload).digest()
    blob, meta = fdt_blob([
        ("begin", ""),
        ("prop", "description", b"independent FIT\0"),
        ("begin", "images"),
        ("begin", "kernel-1"),
        ("prop", "type", b"kernel\0"),
        ("prop", "arch", b"arm64\0"),
        ("prop", "compression", b"none\0"),
        ("prop", "load", struct.pack(">Q", 0x80200000)),
        ("prop", "data", payload),
        ("begin", "hash-1"),
        ("prop", "algo", b"sha256\0"),
        ("prop", "value", digest),
        ("end",), ("end",), ("end",),
        ("begin", "configurations"),
        ("prop", "default", b"conf-1\0"),
        ("begin", "conf-1"),
        ("prop", "kernel", b"kernel-1\0"),
        ("end",), ("end",), ("end",),
    ])
    meta.update(payload=payload, digest=digest)
    return blob, meta


FFS2 = uuid.UUID("8c8ce578-8a3d-4f1c-9935-896185c32dd3")
FILE_GUID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
CAPSULE_GUID = uuid.UUID("0d4e0f72-4f1f-4f80-9f4b-f8530e4c2e34")


def fv_fixture():
    """PI FV revision 2 with one checksummed raw FFS file."""
    payload = b"RAW-FIRMWARE-DATA"
    file_size = 24 + len(payload)
    file_header = bytearray(FILE_GUID.bytes_le)
    file_header += bytes((0, (-sum(payload)) & 0xFF, 0x01, 0x40))
    file_header += u24le(file_size) + b"\xf8"
    checksum_view = bytearray(file_header)
    checksum_view[17] = checksum_view[23] = 0
    file_header[16] = (-sum(checksum_view)) & 0xFF

    size, header_size = 0x200, 72
    volume = bytearray(b"\xff" * size)
    header = bytearray(b"\0" * 16 + FFS2.bytes_le)
    header += struct.pack("<Q", size) + b"_FVH"
    header += struct.pack("<IHHHBB", 0x800, header_size, 0, 0, 0, 2)
    header += struct.pack("<II", 1, size) + struct.pack("<II", 0, 0)
    words = struct.unpack("<" + "H" * (header_size // 2), header)
    struct.pack_into("<H", header, 50, (-sum(words)) & 0xFFFF)
    volume[:header_size] = header
    volume[header_size:header_size + file_size] = file_header + payload
    return bytes(volume), {
        "payload": payload, "file_offset": header_size,
        "file_size": file_size, "header_size": header_size,
    }


def capsule_fixture():
    volume, meta = fv_fixture()
    size = 28 + len(volume)
    capsule = (CAPSULE_GUID.bytes_le
               + struct.pack("<III", 28, 0x00010000, size) + volume)
    meta.update(volume=volume, volume_offset=28)
    return capsule, meta


def cbfs_fixture():
    payload = b"CBFS synthetic bytes\0"
    name = b"fallback/payload\0"
    data_offset = align(24 + len(name), 4)
    entry = bytearray(struct.pack(">8sIIII", b"LARCHIVE", len(payload), 0x50,
                                  0, data_offset))
    entry += name
    entry += b"\0" * (data_offset - len(entry)) + payload
    entry += b"\xff" * (align(len(entry), 64) - len(entry))
    return bytes(entry), {"payload": payload, "data_offset": data_offset}


def test_dtb_documented_spans_and_hashes():
    blob, meta = dtb_fixture()
    report = engine.parse_dtb(blob)
    assert report["kind"] == "dtb"
    assert report["header"]["size"] == len(blob) == meta["total"]
    assert report["header"]["end_offset"] == len(blob)
    assert report["header"]["sha256"] == hashlib.sha256(blob).hexdigest()
    assert report["header"]["boot_cpuid"] == 0x10203040
    assert [(node["path"], node["offset"]) for node in report["nodes"]] == [
        ("/", meta["nodes"]["/"]), ("/chosen", meta["nodes"]["/chosen"]),
    ]
    chosen = report["nodes"][1]["properties"][0]
    assert chosen["offset"] == meta["values"][("/chosen", "bootargs")]
    assert chosen["sha256"] == hashlib.sha256(b"console=ttyS0\0").hexdigest()


def test_fit_documented_payload_span_hash_and_configuration():
    blob, meta = fit_fixture()
    report = engine.parse_fit(blob)
    assert report["kind"] == "fit" and report["description"] == "independent FIT"
    assert report["header"]["sha256"] == hashlib.sha256(blob).hexdigest()
    image = report["images"][0]
    assert image["name"] == "kernel-1" and image["load"] == 0x80200000
    assert image["data"] == {
        "storage": "embedded",
        "offset": meta["values"][("/images/kernel-1", "data")],
        "size": len(meta["payload"]),
        "end_offset": meta["values"][("/images/kernel-1", "data")] + len(meta["payload"]),
        "sha256": hashlib.sha256(meta["payload"]).hexdigest(),
    }
    assert image["hashes"][0]["expected"]["sha256"] == hashlib.sha256(
        meta["digest"]).hexdigest()
    assert image["hashes"][0]["calculated_hex"] == meta["digest"].hex()
    assert image["hashes"][0]["valid"] is True
    assert report["configurations"][0]["image_references"] == {"kernel": ["kernel-1"]}


def test_uefi_fv_and_capsule_documented_spans_and_hashes():
    volume, meta = fv_fixture()
    report = engine.parse_firmware_volume(volume)
    assert (report["offset"], report["size"], report["end_offset"]) == (
        0, len(volume), len(volume))
    assert report["sha256"] == hashlib.sha256(volume).hexdigest()
    assert report["header_length"] == 72 and report["header_checksum_ok"] is True
    assert report["block_map"] == [{
        "offset": 56, "count": 1, "block_length": len(volume),
        "total_length": len(volume),
    }]
    ffs = report["files"][0]
    assert (ffs["offset"], ffs["size"], ffs["end_offset"]) == (
        meta["file_offset"], meta["file_size"],
        meta["file_offset"] + meta["file_size"])
    assert ffs["name_guid"] == str(FILE_GUID) and ffs["logical_state"] == 7
    assert ffs["payload_sha256"] == hashlib.sha256(meta["payload"]).hexdigest()
    assert ffs["header_checksum_ok"] is True and ffs["file_checksum_ok"] is True

    capsule, capsule_meta = capsule_fixture()
    capsule_report = engine.parse_uefi_capsule(capsule)
    assert capsule_report["sha256"] == hashlib.sha256(capsule).hexdigest()
    assert capsule_report["payload_offset"] == 28
    assert capsule_report["payload_sha256"] == hashlib.sha256(
        capsule_meta["volume"]).hexdigest()
    nested = capsule_report["firmware_volumes"][0]
    assert (nested["offset"], nested["end_offset"]) == (28, len(capsule))
    assert nested["sha256"] == hashlib.sha256(capsule_meta["volume"]).hexdigest()


def test_cbfs_documented_file_span_and_hash():
    blob, meta = cbfs_fixture()
    report = engine.parse_cbfs(blob)
    assert report["kind"] == "cbfs" and report["file_count"] == 1
    assert report["sha256"] == hashlib.sha256(blob).hexdigest()
    item = report["files"][0]
    assert item["name"] == "fallback/payload" and item["type"] == "raw"
    assert item["offset"] == 0 and item["data_offset"] == meta["data_offset"]
    assert item["end_offset"] == meta["data_offset"] + len(meta["payload"])
    assert item["sha256"] == hashlib.sha256(meta["payload"]).hexdigest()


def test_dispatch_vector_locks_every_supported_format():
    dtb, _ = dtb_fixture()
    fit, _ = fit_fixture()
    fv, _ = fv_fixture()
    capsule, _ = capsule_fixture()
    cbfs, _ = cbfs_fixture()
    assert engine.parse_boot(dtb)["kind"] == "dtb"
    assert engine.parse_boot(fit)["kind"] == "fit"
    assert engine.parse_boot(fv)["kind"] == "uefi-firmware-volume"
    assert engine.parse_boot(capsule, "capsule")["kind"] == "uefi-capsule"
    assert engine.parse_boot(cbfs)["kind"] == "cbfs"


def clean_or_declared(call):
    try:
        call()
    except BaseException as exc:  # Includes accidental SystemExit leaks.
        assert type(exc) is engine.FWBootError


@pytest.mark.parametrize("parser,fixture", [
    (engine.parse_dtb, lambda: dtb_fixture()[0]),
    (engine.parse_fit, lambda: fit_fixture()[0]),
    (engine.parse_firmware_volume, lambda: fv_fixture()[0]),
    (engine.parse_uefi_capsule, lambda: capsule_fixture()[0]),
    (engine.parse_cbfs, lambda: cbfs_fixture()[0]),
    (engine.parse_boot, lambda: fit_fixture()[0]),
])
def test_all_public_parsers_fail_closed_on_truncation_random_and_bitflip(parser, fixture):
    valid = fixture()
    rng = random.Random(0xF17B007)
    flipped = bytearray(valid)
    flipped[0] ^= 0x80
    corpus = [
        b"", b"\xff" * 257, rng.randbytes(333), bytes(flipped),
        valid[:1], valid[:4], valid[:28], valid[:len(valid) // 2], valid[:-1],
    ]
    for sample in corpus:
        clean_or_declared(lambda sample=sample: parser(sample))


@pytest.mark.parametrize("bad", [None, bytearray(), memoryview(b"x"), "bytes", 1, {}])
def test_all_public_parsers_reject_wrong_input_type(bad):
    for parser in (engine.parse_dtb, engine.parse_fit, engine.parse_firmware_volume,
                   engine.parse_uefi_capsule, engine.parse_cbfs, engine.parse_boot):
        with pytest.raises(engine.FWBootError):
            parser(bad)


def test_offsets_lengths_and_oversize_fail_closed(monkeypatch):
    fit, _ = fit_fixture()
    cbfs, _ = cbfs_fixture()
    for offset in (-1, True, "0", len(fit) + 1):
        for parser in (engine.parse_dtb, engine.parse_fit, engine.parse_firmware_volume,
                       engine.parse_uefi_capsule, engine.parse_cbfs):
            clean_or_declared(lambda parser=parser, offset=offset: parser(fit, offset))
        clean_or_declared(lambda offset=offset: engine.parse_boot(fit, offset=offset))
    for length in (-1, True, "1", len(cbfs) + 1):
        clean_or_declared(lambda length=length: engine.parse_cbfs(cbfs, 0, length))
        clean_or_declared(lambda length=length: engine.parse_boot(
            cbfs, "cbfs", 0, length))
    for format_name in (None, 1, b"fit", "unknown"):
        with pytest.raises(engine.FWBootError):
            engine.parse_boot(fit, format_name)

    monkeypatch.setattr(engine, "MAX_INPUT", 64)
    oversized = b"x" * 65
    for parser in (engine.parse_dtb, engine.parse_fit, engine.parse_firmware_volume,
                   engine.parse_uefi_capsule, engine.parse_cbfs, engine.parse_boot):
        with pytest.raises(engine.FWBootError):
            parser(oversized)


def test_cli_vector_and_guarded_argparse(tmp_path, capsys):
    fixtures = {
        "dtb": dtb_fixture()[0], "fit": fit_fixture()[0],
        "fv": fv_fixture()[0], "capsule": capsule_fixture()[0],
        "cbfs": cbfs_fixture()[0],
    }
    for kind, blob in fixtures.items():
        path = tmp_path / f"fixture.{kind}"
        path.write_bytes(blob)
        assert engine.main([str(path), "--format", kind, "--compact"]) == 0
        assert json.loads(capsys.readouterr().out)["kind"]
    assert engine.main(["--help"]) == 0
    capsys.readouterr()
    for argv in ([], ["--bad"], [str(tmp_path / "missing")]):
        assert engine.main(argv) == 2
        capsys.readouterr()


def test_cli_non_string_argv_is_fail_closed():
    assert isinstance(engine.main([None]), int)
