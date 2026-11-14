"""Independent byte-level fixtures for the FLAC metadata auditor.

The builders below follow RFC 9639's on-wire layout directly.  They do not use
an encoder or any output from the engine under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import stegodepth_flac as flac


def _u24(value: int) -> bytes:
    return value.to_bytes(3, "big")


def _u32be(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u32le(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _metadata_block(type_id: int, body: bytes, *, last: bool = False) -> bytes:
    assert 0 <= type_id <= 127
    assert len(body) < 1 << 24
    return bytes([type_id | (0x80 if last else 0)]) + _u24(len(body)) + body


def _streaminfo(
    *,
    minimum_block: int = 4096,
    maximum_block: int = 8192,
    minimum_frame: int = 123,
    maximum_frame: int = 4567,
    sample_rate: int = 48_000,
    channels: int = 2,
    bits_per_sample: int = 24,
    total_samples: int = 0x123456789,
    md5: bytes = bytes(range(16)),
) -> bytes:
    packed = (
        (sample_rate << 44)
        | ((channels - 1) << 41)
        | ((bits_per_sample - 1) << 36)
        | total_samples
    )
    body = (
        minimum_block.to_bytes(2, "big")
        + maximum_block.to_bytes(2, "big")
        + _u24(minimum_frame)
        + _u24(maximum_frame)
        + packed.to_bytes(8, "big")
        + md5
    )
    assert len(body) == 34
    return body


def _vorbis(vendor: str, fields: list[str]) -> bytes:
    vendor_bytes = vendor.encode("utf-8")
    result = _u32le(len(vendor_bytes)) + vendor_bytes + _u32le(len(fields))
    for field in fields:
        encoded = field.encode("utf-8")
        result += _u32le(len(encoded)) + encoded
    return result


def _picture(
    payload: bytes,
    *,
    picture_type: int = 3,
    media_type: str = "image/png",
    description: str = "cover π",
    width: int = 32,
    height: int = 24,
    depth: int = 8,
    colors: int = 0,
) -> bytes:
    mime = media_type.encode("ascii")
    description_bytes = description.encode("utf-8")
    return b"".join([
        _u32be(picture_type),
        _u32be(len(mime)),
        mime,
        _u32be(len(description_bytes)),
        description_bytes,
        _u32be(width),
        _u32be(height),
        _u32be(depth),
        _u32be(colors),
        _u32be(len(payload)),
        payload,
    ])


def _native_flac(
    blocks: list[tuple[int, bytes]], audio: bytes = b"\xff\xf8FRAME-BYTES"
) -> tuple[bytes, list[tuple[int, int]], int]:
    """Return bytes, independently calculated (header, body) offsets, audio offset."""
    chunks = [b"fLaC"]
    offsets: list[tuple[int, int]] = []
    cursor = 4
    for index, (type_id, body) in enumerate(blocks):
        offsets.append((cursor, cursor + 4))
        encoded = _metadata_block(type_id, body, last=index == len(blocks) - 1)
        chunks.append(encoded)
        cursor += len(encoded)
    chunks.append(audio)
    return b"".join(chunks), offsets, cursor


def _syncsafe(value: int) -> bytes:
    assert 0 <= value < 1 << 28
    return bytes([
        (value >> 21) & 0x7F,
        (value >> 14) & 0x7F,
        (value >> 7) & 0x7F,
        value & 0x7F,
    ])


def _complex_fixture() -> tuple[bytes, list[tuple[int, int]], int, dict[str, bytes]]:
    application_payload = b"CSCTF{application_metadata_carrier}"
    picture_payload = b"\x89PNG\r\n\x1a\ncomplete-picture-payload\x00"
    reserved_payload = b"reserved\x00carrier\xff"
    padding = b"\x00\x00hidden-in-padding\x00"
    vendor = "independent fixture"
    comment_fields = ["TITLE=Total Warfare", "NOTE=flag π"]
    blocks = [
        (0, _streaminfo()),
        (2, b"tst0" + application_payload),
        (4, _vorbis(vendor, comment_fields)),
        (1, padding),
        (6, _picture(picture_payload)),
        (7, reserved_payload),
    ]
    data, offsets, audio_offset = _native_flac(blocks)
    values = {
        "application": application_payload,
        "picture": picture_payload,
        "reserved": reserved_payload,
        "padding": padding,
        "vendor": vendor.encode(),
        "first_comment": comment_fields[0].encode(),
    }
    return data, offsets, audio_offset, values


def test_audits_all_requested_metadata_carriers_and_provenance() -> None:
    data, expected_offsets, expected_audio_offset, values = _complex_fixture()

    report = flac.audit_flac(data)

    assert report is not None
    assert report.signature_offset == 0
    assert report.id3_size == 0
    assert report.audio_offset == expected_audio_offset
    assert data[report.audio_offset:] == b"\xff\xf8FRAME-BYTES"
    assert [block.type_id for block in report.blocks] == [0, 2, 4, 1, 6, 7]
    assert [block.name for block in report.blocks] == [
        "STREAMINFO", "APPLICATION", "VORBIS_COMMENT", "PADDING", "PICTURE", "RESERVED"
    ]
    assert [(block.header_offset, block.data_offset) for block in report.blocks] == expected_offsets
    assert [block.last for block in report.blocks] == [False, False, False, False, False, True]

    stream = report.streaminfo
    assert (stream.minimum_block_size, stream.maximum_block_size) == (4096, 8192)
    assert (stream.minimum_frame_size, stream.maximum_frame_size) == (123, 4567)
    assert (stream.sample_rate, stream.channels, stream.bits_per_sample) == (48_000, 2, 24)
    assert stream.total_samples == 0x123456789
    assert stream.md5_hex == bytes(range(16)).hex()

    artifacts = {artifact.kind: artifact for artifact in report.artifacts}
    application = artifacts["application-data"]
    assert application.data == values["application"]
    assert application.application_id == b"tst0"
    assert application.offset == expected_offsets[1][1] + 4
    assert application.suspicious is False
    assert "legal" in application.evidence

    padding = artifacts["nonzero-padding"]
    assert padding.data == values["padding"]
    assert padding.offset == expected_offsets[3][1]
    assert padding.suspicious is True
    assert "zero" in padding.evidence

    picture_artifact = artifacts["picture-data"]
    picture = report.pictures[0]
    description_size = len("cover π".encode("utf-8"))
    picture_payload_delta = 32 + len(b"image/png") + description_size
    assert picture.data == values["picture"] == picture_artifact.data
    assert picture.data_offset == expected_offsets[4][1] + picture_payload_delta
    assert picture_artifact.offset == picture.data_offset
    assert picture_artifact.suspicious is False
    assert (picture.picture_type, picture.media_type, picture.description) == (3, "image/png", "cover π")
    assert (picture.width, picture.height, picture.depth, picture.colors) == (32, 24, 8, 0)

    reserved = artifacts["reserved-block"]
    assert reserved.data == values["reserved"]
    assert reserved.offset == expected_offsets[5][1]
    assert reserved.suspicious is False
    assert "type 7" in reserved.evidence


def test_vorbis_comments_decode_utf8_and_retain_exact_raw_offsets() -> None:
    data, offsets, _, values = _complex_fixture()
    report = flac.audit_flac(data)
    assert report is not None

    first, second = report.comments
    expected_first = offsets[2][1] + 4 + len(values["vendor"]) + 4 + 4
    expected_second = expected_first + len(values["first_comment"]) + 4
    assert (first.vendor, first.key, first.value, first.raw) == (
        "independent fixture", "TITLE", "Total Warfare", b"TITLE=Total Warfare"
    )
    assert (second.key, second.value, second.raw) == ("NOTE", "flag π", "NOTE=flag π".encode())
    assert (first.offset, second.offset) == (expected_first, expected_second)


def test_json_report_labels_legal_carriers_separately_from_anomaly() -> None:
    data, _, expected_audio_offset, values = _complex_fixture()
    report = flac.audit_flac(data)
    assert report is not None

    serialized = flac.report_dict(report)
    assert serialized["audio_offset"] == expected_audio_offset
    artifacts = {item["kind"]: item for item in serialized["artifacts"]}
    assert artifacts["nonzero-padding"]["suspicious"] is True
    assert artifacts["application-data"]["suspicious"] is False
    assert artifacts["reserved-block"]["suspicious"] is False
    assert artifacts["picture-data"]["suspicious"] is False
    assert artifacts["application-data"]["application_id_hex"] == b"tst0".hex()
    assert artifacts["application-data"]["length"] == len(values["application"])
    assert "data" not in artifacts["application-data"]
    assert serialized["pictures"][0]["length"] == len(values["picture"])


def test_optional_bounded_id3v24_prefix() -> None:
    native, native_offsets, native_audio_offset = _native_flac([(0, _streaminfo())])
    tag_body = b"offline-id3-prefix"
    id3 = b"ID3" + bytes([4, 0, 0]) + _syncsafe(len(tag_body)) + tag_body

    report = flac.audit_flac(id3 + native)

    assert report is not None
    assert report.id3_size == len(id3)
    assert report.signature_offset == len(id3)
    assert report.blocks[0].header_offset == len(id3) + native_offsets[0][0]
    assert report.audio_offset == len(id3) + native_audio_offset


def test_non_flac_is_none_but_identified_malformed_input_is_declared_error() -> None:
    assert flac.audit_flac(b"not a FLAC stream") is None
    assert flac.audit_flac(b"") is None
    with pytest.raises(flac.StegodepthFLACError):
        flac.audit_flac("fLaC")  # type: ignore[arg-type]
    with pytest.raises(flac.StegodepthFLACError):
        flac.audit_flac(b"ID3\x04")
    assert flac.audit_flac(
        b"ID3" + bytes([4, 0, 0]) + b"\x00\x00\x00\x00" + b"mp3-data"
    ) is None


def test_every_metadata_prefix_truncation_raises_only_declared_error() -> None:
    data, _, audio_offset, _ = _complex_fixture()
    for cut in range(4, audio_offset):
        with pytest.raises(flac.StegodepthFLACError):
            flac.audit_flac(data[:cut])


@pytest.mark.parametrize(
    "blocks",
    [
        [(1, b"")],
        [(0, _streaminfo()[:-1])],
        [(0, _streaminfo()), (0, _streaminfo())],
        [(0, _streaminfo()), (127, b"forbidden")],
        [(0, _streaminfo()), (2, b"abc")],
        [(0, _streaminfo()), (4, b"\x01\x00\x00")],
        [(0, _streaminfo()), (4, _vorbis("vendor", ["BADFIELD"]))],
        [(0, _streaminfo()), (6, _u32be(3) + _u32be(99))],
    ],
)
def test_malformed_metadata_shapes_raise_declared_error(
    blocks: list[tuple[int, bytes]],
) -> None:
    data, _, _ = _native_flac(blocks)
    with pytest.raises(flac.StegodepthFLACError):
        flac.audit_flac(data)


def test_streaminfo_enforces_rfc_block_and_bit_depth_ranges() -> None:
    invalid_bodies = [
        _streaminfo(minimum_block=15),
        _streaminfo(minimum_block=8192, maximum_block=4096),
        _streaminfo(bits_per_sample=3),
    ]
    for body in invalid_bodies:
        data, _, _ = _native_flac([(0, body)])
        with pytest.raises(flac.StegodepthFLACError):
            flac.audit_flac(data)


def test_rfc_singleton_metadata_constraints() -> None:
    duplicate_comments, _, _ = _native_flac([
        (0, _streaminfo()),
        (4, _vorbis("one", [])),
        (4, _vorbis("two", [])),
    ])
    icon = _picture(b"png", picture_type=1)
    duplicate_icons, _, _ = _native_flac([(0, _streaminfo()), (6, icon), (6, icon)])

    for data in (duplicate_comments, duplicate_icons):
        with pytest.raises(flac.StegodepthFLACError):
            flac.audit_flac(data)


def test_caps_are_enforced_without_large_allocations(monkeypatch: pytest.MonkeyPatch) -> None:
    minimal, _, _ = _native_flac([(0, _streaminfo())])
    monkeypatch.setattr(flac, "MAX_INPUT", len(minimal) - 1)
    with pytest.raises(flac.StegodepthFLACError, match="input exceeds"):
        flac.audit_flac(minimal)


def test_metadata_block_comment_and_id3_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    two_blocks, _, _ = _native_flac([(0, _streaminfo()), (1, b"")])
    monkeypatch.setattr(flac, "MAX_BLOCKS", 1)
    with pytest.raises(flac.StegodepthFLACError, match="block count"):
        flac.audit_flac(two_blocks)

    monkeypatch.setattr(flac, "MAX_BLOCKS", 4096)
    monkeypatch.setattr(flac, "MAX_METADATA", 37)
    with pytest.raises(flac.StegodepthFLACError, match="metadata exceeds"):
        flac.audit_flac(two_blocks)

    monkeypatch.setattr(flac, "MAX_METADATA", 64 << 20)
    monkeypatch.setattr(flac, "MAX_COMMENTS", 1)
    comments, _, _ = _native_flac([
        (0, _streaminfo()),
        (4, _vorbis("vendor", ["ONE=1", "TWO=2"])),
    ])
    with pytest.raises(flac.StegodepthFLACError, match="comment count"):
        flac.audit_flac(comments)

    monkeypatch.setattr(flac, "MAX_ID3", 3)
    id3 = b"ID3" + bytes([4, 0, 0]) + _syncsafe(0) + two_blocks
    with pytest.raises(flac.StegodepthFLACError, match="ID3v2"):
        flac.audit_flac(id3)


def test_path_errors_are_converted_to_declared_error(tmp_path: Path) -> None:
    with pytest.raises(flac.StegodepthFLACError):
        flac.audit_path(tmp_path / "missing.flac")
    with pytest.raises(flac.StegodepthFLACError):
        flac.report_dict(None)  # type: ignore[arg-type]

    data, _, _, _ = _complex_fixture()
    report = flac.audit_flac(data)
    assert report is not None
    occupied = tmp_path / "occupied"
    occupied.write_bytes(b"file, not directory")
    with pytest.raises(flac.StegodepthFLACError):
        flac.extract_artifacts(report, occupied)


def test_guarded_cli_help_usage_success_and_failure(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert flac.main(["--help"]) == 0
    assert "Audit FLAC metadata" in capsys.readouterr().out

    assert flac.main([]) == 2
    assert "usage:" in capsys.readouterr().err

    data, _, expected_audio_offset, _ = _complex_fixture()
    source = tmp_path / "fixture.flac"
    source.write_bytes(data)
    extraction = tmp_path / "extracted"
    assert flac.main([str(source), "--extract", str(extraction)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["audio_offset"] == expected_audio_offset
    assert {item["kind"] for item in output["artifacts"]} == {
        "application-data", "nonzero-padding", "picture-data", "reserved-block"
    }
    extracted = {Path(path).name for path in output["extracted"]}
    assert extracted == {
        "block-0001-application-data.bin",
        "block-0003-nonzero-padding.bin",
        "block-0004-picture-data.bin",
        "block-0005-reserved-block.bin",
    }
    assert (extraction / "block-0001-application-data.bin").read_bytes() == (
        b"CSCTF{application_metadata_carrier}"
    )
    assert (extraction / "block-0004-picture-data.bin").read_bytes() == (
        b"\x89PNG\r\n\x1a\ncomplete-picture-payload\x00"
    )

    invalid = tmp_path / "invalid.bin"
    invalid.write_bytes(b"not flac")
    assert flac.main([str(invalid)]) == 2
    assert "not a native FLAC" in capsys.readouterr().err
