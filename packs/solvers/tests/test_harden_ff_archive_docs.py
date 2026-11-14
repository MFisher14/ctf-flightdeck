"""Independent vector locks and fail-closed fuzz for archive/document engines.

Fixtures come from python-snappy, stdlib zipfile/tarfile/zlib, or documented
wire layouts.  No fixture is produced from an engine under test.
"""

from dataclasses import replace
import hashlib
import io
import random
import tarfile
import zipfile
import zlib

import pytest
import snappy

import ff_androidab_backup as androidab
import ff_iwork_inspect as iwork
import ff_zipdiff_diagnostics as zipdiff


def _varint(value):
    """Encode an unsigned protobuf varint from the published wire format."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _iwa_vector():
    # Known protobuf payload: field 1 = varint 150; field 2 = bytes b"CTF".
    payload = b"\x08\x96\x01\x12\x03CTF"
    # iWork ArchiveInfo field 2 contains MessageInfo; its field 3 is the
    # following payload length.  These are the documented protobuf tags.
    message_info = b"\x18" + _varint(len(payload))
    archive_info = b"\x12" + _varint(len(message_info)) + message_info
    plain = _varint(len(archive_info)) + archive_info + payload

    raw_snappy = snappy.compress(plain)
    assert snappy.decompress(raw_snappy) == plain  # external codec oracle
    framed = b"\x00" + len(raw_snappy).to_bytes(3, "little") + raw_snappy
    return framed, plain, payload


def _zip_vector(entries, *, compression=zipfile.ZIP_STORED, comment=b""):
    sink = io.BytesIO()
    with zipfile.ZipFile(sink, "w") as archive:
        for index, (name, body) in enumerate(entries):
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 2, 3, 4, 6))
            info.compress_type = compression if index else zipfile.ZIP_STORED
            archive.writestr(info, body)
        archive.comment = comment
    return sink.getvalue()


def _android_vector():
    sink = io.BytesIO()
    body = b"CSCTF-independent-oracle\n"
    with tarfile.open(fileobj=sink, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo("apps/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.mtime = 1_700_000_000
        archive.addfile(directory)

        info = tarfile.TarInfo("apps/state.txt")
        info.size = len(body)
        info.mode = 0o640
        info.mtime = 1_700_000_001
        archive.addfile(info, io.BytesIO(body))
    tar_bytes = sink.getvalue()
    compressed = zlib.compress(tar_bytes)
    assert zlib.decompress(compressed) == tar_bytes  # external codec oracle
    # Literal from AOSP's documented adb-backup header, not the engine constant.
    header = b"ANDROID BACKUP\n5\n1\nnone\n"
    return header + compressed, tar_bytes, body, header


def _mutations(valid, seed):
    """Small deterministic empty/random/truncated/bit-flipped corpus."""
    rng = random.Random(seed)
    cases = [b""]
    cases.extend(rng.randbytes(size) for size in (1, 2, 7, 15, 22, 63, 257))

    cuts = {1, 2, 3, 4, len(valid) // 4, len(valid) // 2,
            (3 * len(valid)) // 4, len(valid) - 2, len(valid) - 1}
    cases.extend(valid[:cut] for cut in sorted(cuts) if 0 < cut < len(valid))

    positions = {0, 1, 2, 3, len(valid) // 4, len(valid) // 2,
                 (3 * len(valid)) // 4, len(valid) - 2, len(valid) - 1}
    for index in sorted(position for position in positions if 0 <= position < len(valid)):
        changed = bytearray(valid)
        changed[index] ^= 1 << (index % 8)
        cases.append(bytes(changed))
    return cases


def _assert_fail_closed(call, declared_error):
    try:
        call()
    except declared_error:
        return
    except BaseException as exc:  # SystemExit and leaked stdlib errors also fail.
        pytest.fail(
            f"leaked {type(exc).__name__}; expected only {declared_error.__name__}: {exc}"
        )


def test_iwork_vector_lock_against_snappy_zipfile_and_protobuf_semantics():
    iwa_bytes, plain, payload = _iwa_vector()
    report = iwork.inspect_iwa(iwa_bytes, framing="iwa")

    assert report["format"] == "iwa"
    assert report["uncompressed_size"] == len(plain)
    assert report["sha256"] == hashlib.sha256(plain).hexdigest()
    assert len(report["records"]) == 1
    recovered = report["records"][0]["payloads"]
    assert len(recovered) == 1
    assert recovered[0]["length"] == len(payload)
    assert recovered[0]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert [(row["field_number"], row["wire_type"], row["value_length"])
            for row in recovered[0]["fields"]] == [(1, 0, 2), (2, 2, 3)]

    bundle = _zip_vector([("Index/Document.iwa", iwa_bytes)])
    with zipfile.ZipFile(io.BytesIO(bundle)) as oracle:
        oracle_info = oracle.infolist()[0]
        assert oracle.read(oracle_info) == iwa_bytes
    bundle_report = iwork.inspect_bundle(bundle)
    member = bundle_report["members"][0]
    assert member["path"] == oracle_info.filename == "Index/Document.iwa"
    assert member["size"] == oracle_info.file_size == len(iwa_bytes)
    assert member["compressed_size"] == oracle_info.compress_size
    assert member["sha256"] == hashlib.sha256(iwa_bytes).hexdigest()
    assert member["iwa"]["records"][0]["payloads"][0]["length"] == len(payload)


def test_zipdiff_vector_lock_against_zipfile_metadata():
    archive = _zip_vector(
        [("alpha.txt", b"alpha"), ("dir/beta.bin", bytes(range(64)))],
        compression=zipfile.ZIP_DEFLATED,
        comment=b"independent-oracle",
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as oracle:
        expected = [
            (info.filename, info.CRC, info.file_size, info.compress_size,
             info.compress_type, info.header_offset)
            for info in oracle.infolist()
        ]

    report = zipdiff.analyze_zip(archive)
    assert report["format"] == "zip"
    assert report["input_bytes"] == len(archive)
    assert report["payloads_verified"] is False
    assert report["findings"] == []
    assert report["rejected_eocd"] == []
    assert len(report["views"]) == 1
    view = report["views"][0]
    observed = [
        (entry["name"]["name"], entry["crc32"], entry["uncompressed_size"],
         entry["compressed_size"], entry["method"], entry["local_offset"])
        for entry in view["entries"]
    ]
    assert observed == expected
    assert view["declared_uncompressed_total"] == sum(row[2] for row in expected)
    assert view["findings"] == []


def test_android_backup_vector_lock_against_tarfile_and_zlib():
    backup, tar_bytes, body, header = _android_vector()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as oracle:
        expected = [(item.name.rstrip("/"), item.size, item.mode, item.mtime)
                    for item in oracle]
        assert oracle.extractfile("apps/state.txt").read() == body

    report = androidab.parse_backup(backup)
    assert report["header"] == {
        "format": "android-backup",
        "version": 5,
        "compressed": True,
        "encryption": "none",
        "data_offset": len(header),
    }
    assert report["status"] == "inventoried"
    inventory = report["inventory"]
    observed = [(item["path"], item["size"], item["mode"], item["mtime"])
                for item in inventory["members"]]
    assert observed == expected
    assert inventory["member_count"] == len(expected) == 2
    assert inventory["tar_bytes"] == len(tar_bytes)
    assert inventory["total_member_bytes"] == len(body)
    assert inventory["members"][1]["sha256"] == hashlib.sha256(body).hexdigest()


def test_iwork_fail_closed_empty_random_truncated_flipped_and_oversized():
    iwa_bytes, _, _ = _iwa_vector()
    bundle = _zip_vector([("Index/Document.iwa", iwa_bytes)])
    for value in _mutations(iwa_bytes, 0x1A2026):
        _assert_fail_closed(
            lambda value=value: iwork.inspect_iwa(value, framing="iwa"),
            iwork.IWorkError,
        )
    for value in _mutations(bundle, 0x1B2026):
        _assert_fail_closed(
            lambda value=value: iwork.inspect_bundle(value), iwork.IWorkError
        )

    # A lowered bound exercises the same oversized-input branch without a
    # wasteful allocation near the production 64 MiB ceiling.
    for value, call in ((iwa_bytes, iwork.inspect_iwa),
                        (bundle, iwork.inspect_bundle)):
        limits = replace(iwork.Limits(), max_input=len(value) - 1)
        _assert_fail_closed(lambda value=value, call=call, limits=limits:
                            call(value, limits=limits), iwork.IWorkError)


def test_zipdiff_fail_closed_empty_random_truncated_flipped_and_oversized():
    archive = _zip_vector(
        [("alpha.txt", b"alpha"), ("dir/beta.bin", bytes(range(64)))],
        compression=zipfile.ZIP_DEFLATED,
    )
    for value in _mutations(archive, 0x5A2026):
        _assert_fail_closed(
            lambda value=value: zipdiff.analyze_zip(value), zipdiff.ZipDiffError
        )
    _assert_fail_closed(
        lambda: zipdiff.analyze_zip(archive, max_input_bytes=len(archive) - 1),
        zipdiff.ZipDiffError,
    )


def test_android_backup_fail_closed_empty_random_truncated_flipped_and_oversized():
    backup, tar_bytes, _, _ = _android_vector()
    for value in _mutations(backup, 0xAB2026):
        _assert_fail_closed(
            lambda value=value: androidab.parse_backup(value),
            androidab.AndroidBackupError,
        )
    for value in _mutations(tar_bytes, 0x7A2026):
        _assert_fail_closed(
            lambda value=value: androidab.inventory_tar(value),
            androidab.AndroidBackupError,
        )

    input_limits = replace(androidab.Limits(), max_input=len(backup) - 1)
    _assert_fail_closed(
        lambda: androidab.parse_backup(backup, limits=input_limits),
        androidab.AndroidBackupError,
    )
    output_limits = replace(androidab.Limits(), max_output=len(tar_bytes) - 1)
    _assert_fail_closed(
        lambda: androidab.inventory_tar(tar_bytes, limits=output_limits),
        androidab.AndroidBackupError,
    )
