"""Independent RIFF fixtures for the codec-free WebP depth auditor."""

from __future__ import annotations

import json

import pytest

import stegodepth_webp as webp


def _chunk(kind: bytes, body: bytes, *, pad: bytes = b"\x00") -> bytes:
    """Reference RIFF chunk writer used only by the tests."""
    assert len(kind) == 4 and len(pad) == 1
    return kind + len(body).to_bytes(4, "little") + body + (pad if len(body) & 1 else b"")


def _webp(*chunks: bytes, tail: bytes = b"") -> bytes:
    payload = b"WEBP" + b"".join(chunks)
    return b"RIFF" + len(payload).to_bytes(4, "little") + payload + tail


def _vp8x(flags: int) -> bytes:
    # Flags, three reserved bytes, then 24-bit width-1 and height-1.
    return bytes([flags, 0, 0, 0, 0, 0, 0, 0, 0, 0])


def test_nested_chunks_metadata_unknown_and_tail_have_exact_provenance():
    nested = _chunk(b"VP8 ", b"frame") + _chunk(b"HIDE", b"inside")
    anmf = bytes(16) + nested
    artifact = _webp(
        _chunk(b"VP8X", _vp8x(0x20 | 0x08 | 0x04 | 0x02)),
        _chunk(b"ICCP", b"profile"),
        _chunk(b"ANIM", bytes(6)),
        _chunk(b"ANMF", anmf),
        _chunk(b"EXIF", b"Exif\x00\x00secret"),
        _chunk(b"XMP ", b"<xmp>secret</xmp>"),
        _chunk(b"SECR", b"top-secret"),
        tail=b"PK\x03\x04tail",
    )

    report = webp.audit_webp(artifact)
    assert report is not None
    assert report.declared_end == len(artifact) - len(b"PK\x03\x04tail")
    assert report.vp8x_flags == 0x2E

    by_key = {(item.kind, item.fourcc): item for item in report.artifacts}
    assert by_key[("metadata", "ICCP")].data == b"profile"
    assert by_key[("metadata", "EXIF")].data == b"Exif\x00\x00secret"
    assert by_key[("metadata", "XMP ")].data == b"<xmp>secret</xmp>"
    assert by_key[("unknown-chunk", "HIDE")].data == b"inside"
    assert by_key[("unknown-chunk", "SECR")].data == b"top-secret"
    assert by_key[("post-riff-tail", "TAIL")].data == b"PK\x03\x04tail"

    hide_header = artifact.index(b"HIDE")
    nested_row = next(row for row in report.chunks if row.fourcc == "HIDE")
    frame_row = next(row for row in report.chunks if row.fourcc == "ANMF")
    assert nested_row.offset == hide_header
    assert nested_row.data_offset == hide_header + 8
    assert nested_row.depth == 1
    assert nested_row.parent_offset == frame_row.offset
    assert any(row.code == "post-riff-tail" for row in report.findings)


def test_vp8x_feature_animation_and_alpha_mismatches_are_reported():
    anmf = bytes(16) + _chunk(b"ALPH", b"a") + _chunk(b"VP8L", b"lossless")
    artifact = _webp(
        _chunk(b"VP8X", _vp8x(0)),
        _chunk(b"ANMF", anmf),
        _chunk(b"EXIF", b"hidden"),
    )
    report = webp.audit_webp(artifact)
    assert report is not None
    codes = [row.code for row in report.findings]
    assert codes.count("vp8x-feature-mismatch") >= 3  # animation, EXIF and alpha
    assert "animation-control-missing" in codes


def test_duplicate_order_reserved_bits_and_nonzero_padding():
    artifact = _webp(
        _chunk(b"JUNK", b"x", pad=b"Z"),
        _chunk(b"VP8X", bytes([0xC1]) + bytes(9)),
        _chunk(b"EXIF", b"one"),
        _chunk(b"EXIF", b"two"),
        _chunk(b"VP8 ", b"pixels"),
    )
    report = webp.audit_webp(artifact)
    assert report is not None
    codes = {row.code for row in report.findings}
    assert {"nonzero-padding", "vp8x-order", "vp8x-reserved-bits", "duplicate-chunk"} <= codes
    pad = next(item for item in report.artifacts if item.kind == "nonzero-padding")
    assert pad.data == b"Z"


@pytest.mark.parametrize(
    "artifact",
    [
        # RIFF extent larger than the physical object.
        b"RIFF" + (100).to_bytes(4, "little") + b"WEBP",
        # Complete RIFF header followed by a truncated chunk body.
        b"RIFF" + (14).to_bytes(4, "little") + b"WEBP" + b"TEST" + (8).to_bytes(4, "little") + b"xx",
        # ANMF is required to have a 16-byte frame header.
        _webp(_chunk(b"ANMF", b"short")),
    ],
)
def test_malformed_webp_raises_only_declared_error(artifact):
    with pytest.raises(webp.StegodepthWebPError):
        webp.audit_webp(artifact)


def test_non_webp_declines_and_bad_public_types_are_declared_errors(monkeypatch):
    assert webp.audit_webp(b"not a webp") is None
    with pytest.raises(webp.StegodepthWebPError):
        webp.audit_webp(None)
    monkeypatch.setattr(webp, "MAX_INPUT_BYTES", 4)
    with pytest.raises(webp.StegodepthWebPError):
        webp.audit_webp(b"12345")

    class BadBytes(bytes):
        def __len__(self):
            raise RuntimeError("hostile length")

    with pytest.raises(webp.StegodepthWebPError):
        webp.audit_webp(BadBytes(b"RIFF"))


def test_json_summary_never_embeds_raw_artifact_bytes():
    report = webp.audit_webp(_webp(_chunk(b"SECR", b"CSCTF{hidden}")))
    assert report is not None
    assert any(item.code == "image-data-missing" for item in report.findings)
    encoded = json.dumps(report.to_dict())
    assert "CSCTF{hidden}" not in encoded
    assert report.artifacts[0].data == b"CSCTF{hidden}"


def test_guarded_cli_help_bad_args_and_valid_report(tmp_path, capsys):
    assert webp.main(["--help"]) == 0
    assert webp.main([]) == 2
    path = tmp_path / "sample.webp"
    path.write_bytes(_webp(_chunk(b"VP8 ", b"frame")))
    assert webp.main([str(path), "--pretty"]) == 0
    captured = capsys.readouterr()
    # Help output precedes the report in the shared capture; find the JSON object directly.
    start = captured.out.find('{"artifacts"')
    if start < 0:
        start = captured.out.find("{\n")
    assert start >= 0
    decoded = json.loads(captured.out[start:])
    assert decoded["format"] == "WebP"

