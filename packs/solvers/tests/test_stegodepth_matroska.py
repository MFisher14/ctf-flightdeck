"""Independent, hand-encoded EBML fixtures for stegodepth_matroska."""

from __future__ import annotations

import json

import pytest

import stegodepth_matroska as matroska


EBML = 0x1A45DFA3
DOCTYPE = 0x4282
SEGMENT = 0x18538067


def _id(value: int) -> bytes:
    """Encode a known EBML ID from its on-wire integer representation."""

    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _size(value: int) -> bytes:
    """Reference EBML known-size encoder (unknown all-one values are skipped)."""

    assert value >= 0
    for width in range(1, 9):
        if value <= (1 << (7 * width)) - 2:
            return ((1 << (7 * width)) | value).to_bytes(width, "big")
    raise ValueError("fixture is too large")


def _element(element_id: int, payload: bytes = b"") -> bytes:
    return _id(element_id) + _size(len(payload)) + payload


def _master(element_id: int, *children: bytes) -> bytes:
    return _element(element_id, b"".join(children))


def _text(element_id: int, value: str) -> bytes:
    return _element(element_id, value.encode("utf-8"))


def _uint(element_id: int, value: int) -> bytes:
    width = max(1, (value.bit_length() + 7) // 8)
    return _element(element_id, value.to_bytes(width, "big"))


def _header(doc_type: str = "matroska") -> bytes:
    return _master(
        EBML,
        _uint(0x4286, 1),
        _uint(0x42F7, 1),
        _uint(0x42F2, 4),
        _uint(0x42F3, 8),
        _text(DOCTYPE, doc_type),
        _uint(0x4287, 4),
        _uint(0x4285, 2),
    )


ATTACHED = b"CSCTF{matroska_attachment}"
TAGGED = b"CSCTF{matroska_tag_binary}"
ADDITIONAL = b"CSCTF{block_additional}"
UNKNOWN = b"CSCTF{unknown_ebml}"
VOID = b"padding-depth"
TAIL = b"PK\x03\x04post-segment"


def _rich_file(*, tail: bytes = TAIL) -> bytes:
    track = _master(
        0x1654AE6B,
        _master(
            0xAE,
            _uint(0xD7, 1),
            _uint(0x73C5, 0x10203040),
            _uint(0x83, 1),
            _text(0x536E, "relay camera"),
            _text(0x22B59C, "eng"),
            _text(0x86, "V_VP9"),
        ),
    )
    attachment = _master(
        0x1941A469,
        _master(
            0x61A7,
            _text(0x467E, "operator note"),
            _text(0x466E, "evidence.bin"),
            _text(0x4660, "application/octet-stream"),
            _element(0x465C, ATTACHED),
            _uint(0x46AE, 0xA11CE),
        ),
    )
    tags = _master(
        0x1254C367,
        _master(
            0x7373,
            _master(0x67C8, _text(0x45A3, "ROLE"), _text(0x4487, "relay")),
            _master(0x67C8, _text(0x45A3, "PAYLOAD"), _element(0x4485, TAGGED)),
        ),
    )
    chapter = _master(
        0x1043A770,
        _master(
            0x45B9,
            _master(
                0xB6,
                _uint(0x91, 123_456_789),
                _uint(0x92, 987_654_321),
                _master(0x80, _text(0x85, "Phase Zero")),
                _master(0x80, _text(0x85, "Fase Cero")),
            ),
        ),
    )
    cluster = _master(
        0x1F43B675,
        _uint(0xE7, 0),
        # Block bytes deliberately resemble EBML; they must stay opaque.
        _element(0xA3, b"\x81\x00\x00\x80\x1a\x45\xdf\xa3"),
        _master(
            0xA0,
            _master(
                0x75A1,
                _master(0xA6, _uint(0xEE, 5), _element(0xA5, ADDITIONAL)),
            ),
        ),
    )
    segment = _master(
        SEGMENT,
        track,
        attachment,
        tags,
        chapter,
        _element(0xEC, VOID),
        cluster,
        _element(0x4FFF, UNKNOWN),
    )
    return _header() + segment + tail


def _artifact(report: matroska.MatroskaReport, kind: str) -> matroska.Artifact:
    return next(item for item in report.artifacts if item.kind == kind)


def test_extracts_carrier_surfaces_inventory_and_exact_provenance() -> None:
    raw = _rich_file()
    report = matroska.inspect_matroska(raw)

    assert report is not None
    assert report.doc_type == "matroska"
    assert not report.segment_unknown_size
    assert report.segment_end == len(raw) - len(TAIL)
    assert report.tail_offset == len(raw) - len(TAIL)
    assert report.tail_size == len(TAIL)
    assert report.tail == TAIL

    assert len(report.attachments) == 1
    attachment = report.attachments[0]
    assert (attachment.filename, attachment.media_type, attachment.description) == (
        "evidence.bin", "application/octet-stream", "operator note"
    )
    assert attachment.uid == 0xA11CE
    assert attachment.data == ATTACHED
    assert attachment.data_offset == raw.index(ATTACHED)

    tags = {tag.name: tag for tag in report.tags}
    assert tags["ROLE"].string == "relay"
    assert tags["PAYLOAD"].binary == TAGGED
    assert report.chapters[0].display_strings == ("Phase Zero", "Fase Cero")
    assert report.chapters[0].title == "Phase Zero"
    assert (report.chapters[0].start_ns, report.chapters[0].end_ns) == (
        123_456_789, 987_654_321
    )
    assert len(report.tracks) == 1
    track = report.tracks[0]
    assert (track.number, track.uid, track.track_type) == (1, 0x10203040, 1)
    assert (track.name, track.language, track.codec_id) == (
        "relay camera", "eng", "V_VP9"
    )
    assert raw[track.offset:track.offset + 1] == b"\xae"

    expected = {
        "attachment": (ATTACHED, "legal-carrier"),
        "tag-binary": (TAGGED, "legal-carrier"),
        "void": (VOID, "legal-carrier"),
        "block-additional": (ADDITIONAL, "legal-carrier"),
        "unknown-element": (UNKNOWN, "legal-extension-surface"),
        "post-segment-tail": (TAIL, "anomaly"),
    }
    for kind, (payload, status) in expected.items():
        artifact = _artifact(report, kind)
        assert artifact.data == payload
        assert artifact.offset == raw.index(payload)
        assert artifact.size == len(payload)
        assert artifact.status == status
    assert _artifact(report, "block-additional").name == "5"
    assert any("0x4FFF" in issue for issue in report.issues)
    assert any("bounded Segment" in issue for issue in report.issues)

    # The fake EBML header inside SimpleBlock is not recursively interpreted.
    simple_blocks = [item for item in report.elements if item.element_id == 0xA3]
    assert len(simple_blocks) == 1
    assert not any(item.offset == raw.index(b"\x1a\x45\xdf\xa3", simple_blocks[0].data_offset)
                   for item in report.elements)


def test_unknown_sized_segment_runs_to_physical_eof_without_tail() -> None:
    body = _element(0xEC, b"live-padding") + _element(0x4FFE, b"extension")
    raw = _header("webm") + _id(SEGMENT) + b"\xff" + body

    report = matroska.inspect_matroska(raw)

    assert report is not None
    assert report.doc_type == "webm"
    assert report.segment_unknown_size
    assert report.segment_end == len(raw)
    assert report.tail_offset is None
    assert report.tail_size == 0
    assert report.tail == b""
    assert _artifact(report, "void").data == b"live-padding"
    assert _artifact(report, "unknown-element").data == b"extension"
    assert not any(item.kind == "post-segment-tail" for item in report.artifacts)


def test_non_matroska_inputs_return_none() -> None:
    assert matroska.inspect_matroska(b"not ebml") is None
    assert matroska.inspect_matroska(None) is None
    assert matroska.inspect_matroska(_header("other") + _master(SEGMENT)) is None

    class BadBytes(bytes):
        def __len__(self):
            raise RuntimeError("hostile length")

    assert matroska.inspect_matroska(BadBytes(b"\x1a\x45\xdf\xa3")) is None


@pytest.mark.parametrize(
    "raw",
    [
        _header()[:-1],
        _header() + _id(SEGMENT) + b"\x00",
        _header() + _master(SEGMENT, _id(0xEC) + b"\xff"),
        _header() + _master(SEGMENT, b"\xff\x80"),
        _header() + _master(SEGMENT, b"\x40\x7e\x80"),
        _header() + _master(SEGMENT, _id(0x4FFF) + _size(5) + b"x"),
    ],
)
def test_malformed_vints_sizes_and_unknown_leaf_fail_closed(raw: bytes) -> None:
    with pytest.raises(matroska.StegodepthMatroskaError):
        matroska.inspect_matroska(raw)


def test_all_truncations_never_leak_stdlib_exceptions() -> None:
    raw = _rich_file(tail=b"")
    for cut in range(1, len(raw)):
        try:
            matroska.inspect_matroska(raw[:cut])
        except Exception as exc:  # public contract assertion
            assert isinstance(exc, matroska.StegodepthMatroskaError)


def test_binary_and_tail_extraction_caps_preserve_sizes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(matroska, "MAX_ARTIFACT_BYTES", 8)
    raw = _rich_file()
    report = matroska.inspect_matroska(raw)

    assert report is not None
    assert report.attachments[0].data is None
    assert _artifact(report, "attachment").size == len(ATTACHED)
    assert _artifact(report, "attachment").data is None
    assert report.tail_size == len(TAIL)
    assert report.tail is None
    assert any("extraction caps" in issue for issue in report.issues)


def test_input_text_depth_and_element_caps_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = _rich_file(tail=b"")
    if len(raw) % 2:
        raw += b"X"
    view = memoryview(raw).cast("H")
    assert view.nbytes == len(raw) and len(view) < view.nbytes
    monkeypatch.setattr(matroska, "MAX_INPUT_BYTES", len(view))
    assert matroska.inspect_matroska(view) is None

    monkeypatch.setattr(matroska, "MAX_INPUT_BYTES", len(raw) + 1)
    monkeypatch.setattr(matroska, "MAX_TEXT_BYTES", 3)
    with pytest.raises(matroska.StegodepthMatroskaError):
        matroska.inspect_matroska(raw)

    monkeypatch.setattr(matroska, "MAX_TEXT_BYTES", 1 << 20)
    monkeypatch.setattr(matroska, "MAX_DEPTH", 2)
    with pytest.raises(matroska.StegodepthMatroskaError):
        matroska.inspect_matroska(raw)

    monkeypatch.setattr(matroska, "MAX_DEPTH", 12)
    monkeypatch.setattr(matroska, "MAX_ELEMENTS", 2)
    with pytest.raises(matroska.StegodepthMatroskaError):
        matroska.inspect_matroska(raw)


def test_cli_json_help_usage_and_missing_file(tmp_path, capsys) -> None:
    sample = tmp_path / "sample.mkv"
    sample.write_bytes(_rich_file(tail=b""))

    assert matroska.main([str(sample), "--pretty"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["doc_type"] == "matroska"
    assert result["attachments"][0]["filename"] == "evidence.bin"

    assert matroska.main(["--help"]) == 0
    capsys.readouterr()
    assert matroska.main([]) == 2
    capsys.readouterr()
    assert matroska.main([str(tmp_path / "absent.mkv")]) == 2
    assert "absent.mkv" in capsys.readouterr().err
