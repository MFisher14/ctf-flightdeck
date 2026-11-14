"""Independent fixtures for the bounded JP2/J2K structural inspector.

The helpers below serialize the published ITU-T T.800 marker fields and the
JP2 length/type box grammar directly.  They do not call any encoder or helper
from the engine under test.
"""

from __future__ import annotations

import json
import struct

import pytest

import stegodepth_jp2 as jp2


def _segment(code: int, body: bytes) -> bytes:
    """Serialize one T.800 length-bearing marker segment independently."""
    return struct.pack(">HH", code, len(body) + 2) + body


def _siz() -> bytes:
    # Rsiz; reference grid, image origin, tile grid, tile origin; Csiz; Ssiz/XR/YR.
    fixed = struct.pack(
        ">HIIIIIIIIH",
        0,       # baseline profile
        66, 51,  # Xsiz/Ysiz
        2, 3,    # XOsiz/YOsiz -> a 64 x 48 image
        64, 48,  # XTsiz/YTsiz
        0, 0,    # XTOsiz/YTOsiz
        3,
    )
    components = b"".join(bytes((7, 1, 1)) for _ in range(3))
    return _segment(0xFF51, fixed + components)


def _cod(*, progression: int = 0, levels: int = 5, transform: int = 1) -> bytes:
    # Scod, progression, layers, MCT, levels, cb width/height exponents,
    # code-block style, transform.
    body = bytes((0, progression)) + struct.pack(">H", 1)
    body += bytes((0, levels, 4, 4, 0, transform))
    return _segment(0xFF52, body)


def _qcd(*, levels: int = 5) -> bytes:
    # Two guard bits and style zero (no quantization), one exponent byte for
    # the LL band and three for every decomposition level.
    body = bytes((2 << 5,)) + bytes((0x28,)) * (1 + 3 * levels)
    return _segment(0xFF5C, body)


def _sot(psot: int) -> bytes:
    # Isot=0, Psot, TPsot=0, TNsot=1.
    return _segment(0xFF90, struct.pack(">HIBB", 0, psot, 0, 1))


def _codestream(*, internal_tail: bytes = b"", psot_zero: bool = False,
                unknown_marker: bool = True) -> bytes:
    comment = _segment(0xFF64, struct.pack(">H", 1) + b"CSCTF{jp2_comment}")
    private = _segment(0xFF79, b"CSCTF{marker_segment}") if unknown_marker else b""
    tile_data = b"\x12\x34\x56\x78\x9a\xbc"
    provisional = _sot(0)
    declared = 0 if psot_zero else len(provisional) + 2 + len(tile_data)
    tile_part = _sot(declared) + b"\xff\x93" + tile_data
    return (
        b"\xff\x4f" + _siz() + _cod() + _qcd() + comment + private +
        tile_part + b"\xff\xd9" + internal_tail
    )


def _box(kind: bytes, body: bytes, *, extended: bool = False) -> bytes:
    assert len(kind) == 4
    if extended:
        return struct.pack(">I4sQ", 1, kind, 16 + len(body)) + body
    return struct.pack(">I4s", 8 + len(body), kind) + body


def _jp2_file(*, post_container: bytes = b"", internal_tail: bytes = b"",
              short_uuid: bool = False, brand: bytes = b"jp2 ") -> bytes:
    signature = struct.pack(">I4s", 12, b"jP  ") + b"\x0d\x0a\x87\x0a"
    ftyp = _box(b"ftyp", brand + b"\x00\x00\x00\x00" + brand)
    ihdr = _box(
        b"ihdr",
        struct.pack(">IIHBBBB", 48, 64, 3, 7, 7, 0, 0),
    )
    # Enumerated sRGB colourspace: METH=1, PREC=APPROX=0, EnumCS=16.
    colr = _box(b"colr", struct.pack(">BBBI", 1, 0, 0, 16))
    header = _box(b"jp2h", ihdr + colr)
    xml = _box(b"xml ", b"<flag>CSCTF{xml_box}</flag>")
    uuid_body = (b"\x01\x23" if short_uuid else bytes(range(16)) + b"CSCTF{uuid_box}")
    uuid = _box(b"uuid", uuid_body)
    private = _box(b"stEg", b"CSCTF{unknown_box}", extended=True)
    codestream = _box(b"jp2c", _codestream(internal_tail=internal_tail))
    return signature + ftyp + header + xml + uuid + private + codestream + post_container


def test_raw_codestream_reports_published_marker_fields_and_exact_tail():
    tail = b"CSCTF{after_eoc}"
    raw = _codestream(internal_tail=tail)
    report = jp2.inspect_codestream(raw)
    assert report is not None
    assert (report.width, report.height, report.x_origin, report.y_origin) == (64, 48, 2, 3)
    assert len(report.components) == 3
    assert all(component.precision == 8 and not component.signed
               for component in report.components)
    assert report.progression == "LRCP"
    assert report.decomposition_levels == 5
    assert report.transform == "reversible 5/3"
    assert report.quantization_style == "no quantization"
    assert report.guard_bits == 2
    assert report.comments[0].text == "CSCTF{jp2_comment}"
    assert report.eoc_offset == len(raw) - len(tail) - 2
    assert report.logical_end == len(raw) - len(tail)
    assert report.tail == tail and report.tail_size == len(tail)
    assert [marker.name for marker in report.markers] == [
        "SOC", "SIZ", "COD", "QCD", "COM", "0xFF79", "SOT", "SOD", "EOC"
    ]
    unknown = [item for item in report.artifacts if item.kind == "unknown_marker_segment"]
    assert len(unknown) == 1
    assert unknown[0].identifier == "0xFF79"
    assert unknown[0].data == b"CSCTF{marker_segment}"
    assert report.tile_parts[0].data_size == 6
    assert report.tile_parts[0].declared_size == 20


def test_psot_zero_last_tile_and_irreversible_transform_are_structural_only():
    raw = bytearray(_codestream(psot_zero=True, unknown_marker=False))
    cod_at = raw.index(b"\xff\x52")
    # Transform byte is the last byte of the COD body. Replace 5/3 (1) by 9/7 (0).
    cod_length = struct.unpack_from(">H", raw, cod_at + 2)[0]
    raw[cod_at + 2 + cod_length - 1] = 0
    report = jp2.inspect_codestream(bytes(raw))
    assert report is not None
    assert report.transform == "irreversible 9/7"
    assert report.tile_parts[0].declared_size == 0
    assert report.tile_parts[0].data_size == 6


def test_jp2_boxes_extract_xml_uuid_unknown_and_both_depth_tails():
    post = b"CSCTF{post_container}"
    inner = b"CSCTF{inside_jp2c}"
    raw = _jp2_file(post_container=post, internal_tail=inner)
    report = jp2.inspect_jp2(raw)
    assert report is not None
    assert report.container_format == "jp2"
    assert report.post_container == post
    assert report.post_container_size == len(post)
    assert report.logical_end == len(raw) - len(post)
    assert report.codestreams[0].tail == inner

    kinds = {item.kind for item in report.artifacts}
    assert {"xml", "uuid", "unknown_box", "unknown_marker_segment",
            "codestream_tail", "post_container"} <= kinds
    xml = next(item for item in report.artifacts if item.kind == "xml")
    uuid = next(item for item in report.artifacts if item.kind == "uuid")
    private = next(item for item in report.artifacts if item.kind == "unknown_box")
    assert xml.data == b"<flag>CSCTF{xml_box}</flag>"
    assert uuid.identifier == bytes(range(16)).hex()
    assert uuid.data == b"CSCTF{uuid_box}"
    assert private.identifier == "stEg"
    assert private.data == b"CSCTF{unknown_box}"
    assert private.path.endswith("/stEg[3]")
    assert any(box.box_type == "ihdr" and box.depth == 1 for box in report.boxes)
    assert any(box.box_type == "stEg" and box.header_size == 16 for box in report.boxes)


def test_raw_dispatch_preserves_eoc_tail_as_post_container():
    tail = b"trailing"
    report = jp2.inspect(_codestream(internal_tail=tail))
    assert report is not None
    assert report.container_format == "j2k"
    assert report.boxes == ()
    assert report.post_container == tail
    assert report.codestreams[0].eoc_offset + 2 == report.logical_end


def test_jpx_brand_uses_the_same_bounded_box_grammar():
    report = jp2.inspect_jp2(_jp2_file(brand=b"jpx "))
    assert report is not None
    assert report.container_format == "jpx"


def test_free_space_and_unparsed_jpx_boxes_remain_visible_artifacts():
    raw = _jp2_file(brand=b"jpx ")
    codestream_at = raw.index(b"jp2c") - 4
    free = _box(b"free", b"CSCTF{free_box_carrier}")
    private_child = _box(b"stEg", b"CSCTF{nested_jpx_private}")
    opaque = _box(b"jpch", private_child)
    report = jp2.inspect_jp2(raw[:codestream_at] + free + opaque + raw[codestream_at:])
    assert report is not None
    free_artifact = next(item for item in report.artifacts if item.kind == "free_space")
    jpx_artifact = next(item for item in report.artifacts if item.kind == "opaque_jpx_box")
    assert free_artifact.data == b"CSCTF{free_box_carrier}"
    assert jpx_artifact.data == private_child
    assert jpx_artifact.identifier == "jpch"
    assert any("opaque JPX" in finding for finding in report.findings)


def test_malformed_inputs_and_caps_fail_closed(monkeypatch):
    raw = _codestream()
    for cut in (0, 1, 2, 3, 8, 20, len(raw) - 1):
        assert jp2.inspect_jp2(raw[:cut]) is None

    bad_length = bytearray(raw)
    siz_at = bad_length.index(b"\xff\x51")
    struct.pack_into(">H", bad_length, siz_at + 2, 0xFFFF)
    assert jp2.inspect_codestream(bytes(bad_length)) is None

    bad_psot = bytearray(raw)
    sot_at = bad_psot.index(b"\xff\x90")
    struct.pack_into(">I", bad_psot, sot_at + 6, len(raw) + 100)
    assert jp2.inspect_codestream(bytes(bad_psot)) is None

    container = _jp2_file()
    assert jp2.inspect_jp2(container[:-1]) is None
    assert jp2.inspect_jp2(_jp2_file(short_uuid=True)) is None
    assert jp2.inspect_jp2(object()) is None

    monkeypatch.setattr(jp2, "MAX_INPUT_BYTES", 32)
    assert jp2.inspect_jp2(raw) is None


def test_parameter_errors_are_declared_and_artifact_retention_is_capped(monkeypatch):
    raw = _codestream()
    for kwargs in ({"offset": -1}, {"offset": "0"}, {"end": len(raw) + 1}, {"end": 1.5}):
        with pytest.raises(jp2.StegodepthJP2Error):
            jp2.inspect_codestream(raw, **kwargs)

    monkeypatch.setattr(jp2, "MAX_ARTIFACT_BYTES", 5)
    report = jp2.inspect_jp2(_jp2_file(post_container=b"CSCTF{long_tail}"))
    assert report is not None
    post = next(item for item in report.artifacts if item.kind == "post_container")
    assert post.truncated is True
    assert post.size == len(b"CSCTF{long_tail}")
    assert post.data == b"CSCTF"


def test_hostile_protocol_subclasses_cannot_leak_their_exceptions():
    class HostileBytes(bytes):
        def __len__(self):
            raise RuntimeError("hostile length")

    class HostileInt(int):
        def __lt__(self, other):
            raise RuntimeError("hostile comparison")

    assert jp2.inspect_jp2(HostileBytes(_codestream())) is None
    with pytest.raises(jp2.StegodepthJP2Error):
        jp2.inspect_codestream(_codestream(), offset=HostileInt(0))


def test_aggregate_artifact_and_count_caps_bound_retained_data(monkeypatch):
    monkeypatch.setattr(jp2, "MAX_ARTIFACT_BYTES", 100)
    monkeypatch.setattr(jp2, "MAX_SAVED_ARTIFACT_BYTES", 7)
    report = jp2.inspect_jp2(_jp2_file(post_container=b"CSCTF{tail}"))
    assert report is not None
    assert sum(len(item.data) for item in report.artifacts) <= 7
    assert any(item.truncated for item in report.artifacts)
    assert report.post_container_size == len(b"CSCTF{tail}")

    monkeypatch.setattr(jp2, "MAX_ARTIFACTS", 2)
    assert jp2.inspect_jp2(_jp2_file()) is None


def test_memoryview_cap_uses_total_bytes_not_first_dimension(monkeypatch):
    raw = bytearray(_codestream())
    matrix = memoryview(raw).cast("B", shape=(1, len(raw)))
    assert len(matrix) == 1 and matrix.nbytes == len(raw)
    monkeypatch.setattr(jp2, "MAX_INPUT_BYTES", len(raw) - 1)
    assert jp2.inspect_jp2(matrix) is None


def test_cli_is_guarded_and_emits_json(tmp_path, capsys):
    path = tmp_path / "fixture.jp2"
    path.write_bytes(_jp2_file(post_container=b"tail"))
    assert jp2.main([str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["recognized"] is True
    assert output["container_format"] == "jp2"
    assert output["codestreams"][0]["transform"] == "reversible 5/3"
    assert output["post_container"]["hex"] == b"tail".hex()

    assert jp2.main(["--help"]) == 0
    capsys.readouterr()
    assert jp2.main([]) == 2
    capsys.readouterr()
    assert jp2.main([str(tmp_path / "missing.jp2")]) == 2

