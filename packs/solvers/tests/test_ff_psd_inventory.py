"""PSD/PSB vectors packed independently from Adobe's documented structures.

psd-tools is a second independent reader for layer flags, names, lengths and links.
The fixtures never call ff_psd_inventory helpers to encode their expected input.
"""
from io import BytesIO
import json
from pathlib import Path
import random
import struct
import sys

from PIL import Image
from psd_tools import PSDImage
from psd_tools.constants import Tag
from psd_tools.psd import PSD
import pytest

import ff_psd_inventory as psd


def _u32(value):
    return struct.pack(">I", value)


def _length(value, version):
    return struct.pack(">I" if version == 1 else ">Q", value)


def _pascal(value, alignment):
    result = bytes([len(value)]) + value
    return result + b"\0" * (-len(result) % alignment)


def _unicode(value):
    value = value.encode("utf-16-be")
    return _u32(len(value) // 2) + value


def _tag(key, value, version=1, alignment=1):
    # Only keys used by these hand-built fixtures need the PSB eight-byte field.
    wide = version == 2 and key in (b"lnk2", b"Lr16", b"Lr32")
    return b"8BIM" + key + struct.pack(">Q" if wide else ">I", len(value)) + value + b"\0" * (-len(value) % alignment)


def _resource(number, value, name=b""):
    return b"8BIM" + struct.pack(">H", number) + _pascal(name, 2) + _u32(len(value)) + value + b"\0" * (len(value) % 2)


def _layer(name, unicode_name, version, hidden=False, opacity=255, mode=b"norm", depth=8):
    channel = struct.pack(">H", 0) + b"\x11\x22" * (depth // 8)
    extra = _u32(0) + _u32(0) + _pascal(name, 4) + _tag(b"luni", _unicode(unicode_name))
    extra += _tag(b"lyid", _u32(123))
    header = struct.pack(">4iH", 0, 0, 1, 2, 3)
    header += b"".join(struct.pack(">h", i) + _length(len(channel), version) for i in range(3))
    header += b"8BIM" + mode + bytes([opacity, 0, 2 if hidden else 0, 0])
    return header + _u32(len(extra)) + extra, channel * 3


def _jpeg():
    out = BytesIO()
    Image.new("RGB", (1, 1), (255, 0, 0)).save(out, format="JPEG")
    return out.getvalue()


def _linked(payload, *, descriptor=False):
    body = b"liFD" + _u32(1) + _pascal(b"fixture-id", 1) + _unicode("../never-follow.bin")
    body += b"BINA" + b"8BIM" + struct.pack(">Q", len(payload)) + bytes([descriptor])
    body += payload
    return struct.pack(">Q", len(body)) + body + b"\0" * (-len(body) % 4)


def _document(version=1, *, resources=None, body=None, global_tags=None, depth=8, tail=b"", composite=None):
    header = b"8BPS" + struct.pack(">H", version) + b"\0" * 6 + struct.pack(">HIIHH", 3, 1, 2, depth, 3)
    if resources is None:
        thumb = _jpeg()
        resource_header = struct.pack(">6I2H", 1, 1, 1, 4, 4, len(thumb), 24, 1)
        resources = _resource(1036, resource_header + thumb, b"preview")
        resources += _resource(1060, b"<xmp>CSCTF{metadata}</xmp>", b"XMP")
    if body is None:
        first, c1 = _layer(b"visible", "Visible \u03a9", version, depth=depth)
        second, c2 = _layer(b"hidden", "CSCTF{hidden_\U0001f511}", version, True, 73, b"mul ", depth)
        body = struct.pack(">h", -2) + first + second + c1 + c2
        body += b"\0" * (len(body) % 2)
    if global_tags is None:
        global_tags = _tag(b"lnk2", _linked(b"CSCTF{embedded_original}"), version, 4)
    layer_mask = _length(len(body), version) + body + _u32(0) + global_tags
    image = composite if composite is not None else b"\0\0" + bytes(range(6 * depth // 8))
    return header + _u32(0) + _u32(len(resources)) + resources + _length(len(layer_mask), version) + layer_mask + image + tail


@pytest.mark.parametrize("version", [1, 2])
def test_hand_packed_inventory_and_independent_reader(version):
    data = _document(version)
    report = psd.inventory(data)
    oracle = PSD.read(BytesIO(data))
    records = oracle.layer_and_mask_information.layer_info.layer_records
    assert report["format"] == ("PSD" if version == 1 else "PSB")
    assert report["header"]["width"] == 2 and report["header"]["height"] == 1
    assert report["layer_count"] == 2
    assert report["layer_sets"][0]["merged_transparency"] is True
    assert [layer["name"] for layer in report["layers"]] == ["Visible \u03a9", "CSCTF{hidden_\U0001f511}"]
    for actual, expected in zip(report["layers"], records):
        assert actual["pascal_name"] == expected.name
        assert actual["unicode_name"] == expected.tagged_blocks.get_data(Tag.UNICODE_LAYER_NAME)
        assert actual["visible"] == expected.flags.visible
        assert actual["opacity"] == expected.opacity
        assert actual["blend_mode"] == expected.blend_mode.value.decode("ascii")
        assert [channel["length"] for channel in actual["channels"]] == [item.length for item in expected.channel_info]
        assert all(data[item["offset"]:item["offset"] + 2] == b"\0\0" for item in actual["channels"])
    assert report["layers"][1]["visible"] is False
    assert report["layers"][1]["opacity"] == 73
    assert report["layers"][1]["blend_name"] == "multiply"
    assert [entry["id"] for entry in report["resources"]] == [1036, 1060]
    assert report["thumbnails"][0]["offset"] == data.index(_jpeg())
    assert psd.extract_payload(data, "thumbnail") == _jpeg()
    assert psd.extract_payload(data, "resource", 1) == b"<xmp>CSCTF{metadata}</xmp>"
    assert report["embedded_objects"][0]["filename"] == "../never-follow.bin"
    assert psd.extract_payload(data, "embedded") == b"CSCTF{embedded_original}"
    linked = oracle.layer_and_mask_information.tagged_blocks.get_data(Tag.LINKED_LAYER2)[0]
    assert linked.data == psd.extract_payload(data, "embedded")


@pytest.mark.parametrize("depth,key", [(16, b"Lr16"), (32, b"Lr32")])
@pytest.mark.parametrize("version", [1, 2])
def test_alternate_layer_info_without_inner_length(depth, key, version):
    record, channels = _layer(b"alt", "Alternative", version, depth=depth)
    info = struct.pack(">h", 1) + record + channels
    data = _document(version, body=b"", global_tags=_tag(key, info, version, 4), depth=depth)
    result = psd.inventory(data)
    assert result["layer_sets"][0]["source"] == key.decode()
    assert result["layer_count"] == 1
    assert result["layers"][0]["name"] == "Alternative"
    oracle = PSD.read(BytesIO(data))
    assert oracle._get_layer_info().layer_records[0].name == "alt"


def test_real_library_writer_flattened_document():
    source = PSDImage.new("RGB", (3, 2), color=(10, 20, 30))
    stream = BytesIO()
    source.save(stream)
    report = psd.inventory(stream.getvalue())
    assert report["header"]["width"] == 3
    assert report["header"]["height"] == 2
    assert report["layers"] == []


def test_raw_thumbnail_and_nonzero_padding_are_inventoried():
    pixels = b"\x11\x22\x33\0"
    thumbnail = struct.pack(">6I2H", 0, 1, 1, 4, 4, 4, 24, 1) + pixels
    # Resource-data padding is outside the one-byte payload.
    resources = _resource(1033, thumbnail) + _resource(4000, b"a")[:-1] + b"X"
    result = psd.inventory(_document(resources=resources))
    assert result["thumbnails"][0]["format"] == "raw_rgb"
    assert result["thumbnails"][0]["channel_order"] == "BGR"
    assert psd.extract_payload(_document(resources=resources), "thumbnail") == pixels
    assert any(entry["scope"] == "resource[1].data_padding" and entry["preview_hex"] == "58"
               for entry in result["slack"])


@pytest.mark.parametrize("version", [1, 2])
def test_resource_pascal_padding_unknown_keys_and_section_slack(version):
    resources = _resource(4000, b"abc", b"AB") + _resource(4000, b"de", b"C") + b"CSCTF{resource_slack}"
    tags = _tag(b"zzzz", b"opaque", version, 4) + b"tail"
    data = _document(version, resources=resources, body=struct.pack(">h", 0) + b"CSCTF{layer_slack}",
                     global_tags=tags, tail=b"CSCTF{after_image}")
    result = psd.inventory(data)
    assert [entry["name"] for entry in result["resources"]] == ["AB", "C"]
    assert psd.extract_payload(data, "resource", 0) == b"abc"
    assert psd.extract_payload(data, "resource", 1) == b"de"
    assert result["additional_info"][0]["key"] == "zzzz"
    contents = {entry["scope"]: data[entry["offset"]:entry["offset"] + entry["length"]] for entry in result["slack"]}
    assert contents["image_resources"] == b"CSCTF{resource_slack}"
    assert contents["primary.layer_info"] == b"CSCTF{layer_slack}"
    assert contents["global"] == b"tail"
    assert contents["composite.trailing"] == b"CSCTF{after_image}"
    assert all(section["end"] == section["offset"] + section["length"] for section in result["sections"])


@pytest.mark.parametrize("version", [1, 2])
def test_rle_row_count_extents_and_trailing_slack(version):
    table = struct.pack(">3H" if version == 1 else ">3I", 3, 3, 3)
    image = b"\0\1" + table + b"\x01\x11\x22" * 3
    data = _document(version, composite=image, tail=b"trailing")
    result = psd.inventory(data)
    assert result["composite"]["length"] == len(image)
    assert result["composite"]["extent_verified"] is True
    assert result["slack"][-1]["scope"] == "composite.trailing"
    broken = _document(version, composite=image[:-1])
    with pytest.raises(psd.PSDInventoryError):
        psd.inventory(broken)


def test_compressed_pixels_and_descriptor_objects_stay_opaque():
    data = _document(global_tags=_tag(b"lnk2", _linked(b"unparsed descriptor", descriptor=True), alignment=4),
                     composite=b"\0\2opaque compressed pixel bytes")
    result = psd.inventory(data)
    assert result["composite"]["status"] == "opaque_zip_pixels"
    assert result["composite"]["extent_verified"] is False
    assert result["embedded_objects"][0]["status"] == "opaque_descriptor"
    with pytest.raises(psd.PSDInventoryError):
        psd.extract_payload(data, "embedded")


def test_file_cli_json_and_explicit_extraction(tmp_path, capsys):
    data = _document()
    path = tmp_path / "known.psd"
    path.write_bytes(data)
    assert psd.inventory_file(path)["layer_count"] == 2
    assert psd.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["layers"][1]["opacity"] == 73
    out = tmp_path / "chosen.bin"
    assert psd.main([str(path), "--extract", "embedded", "--output", str(out)]) == 0
    assert out.read_bytes() == b"CSCTF{embedded_original}"
    assert not (tmp_path.parent / "never-follow.bin").exists()
    assert psd.main(["--help"]) == 0
    assert psd.main([]) == 2
    assert psd.main([str(path), "--extract", "resource"]) == 2
    assert psd.main([str(path), "--index", "not-integer"]) == 2
    assert psd.main([str(path / "missing")]) == 2


@pytest.mark.parametrize("kind,index", [("unknown", 0), ("thumbnail", -1), ("embedded", True),
                                        ("resource", 999), (None, 0)])
def test_invalid_extraction_args(kind, index):
    with pytest.raises(psd.PSDInventoryError):
        psd.extract_payload(_document(), kind, index)


def test_cli_noninteger_exit_code_and_invalid_argv(monkeypatch):
    def exit_with_message(*args, **kwargs):
        raise SystemExit("usage")

    assert psd.main([None]) == 2
    monkeypatch.setattr(psd.argparse.ArgumentParser, "parse_args", exit_with_message)
    assert psd.main([]) == 2


def test_size_and_record_caps(monkeypatch):
    data = _document()
    monkeypatch.setattr(psd, "MAX_BYTES", len(data) - 1)
    with pytest.raises(psd.PSDInventoryError):
        psd.inventory(data)
    monkeypatch.setattr(psd, "MAX_BYTES", len(data))
    monkeypatch.setattr(psd, "MAX_RECORDS", 1)
    with pytest.raises(psd.PSDInventoryError):
        psd.inventory(data)
    monkeypatch.setattr(psd, "MAX_RECORDS", 8192)
    monkeypatch.setattr(psd, "MAX_LAYERS", 1)
    with pytest.raises(psd.PSDInventoryError):
        psd.inventory(data)


def test_deterministic_malformed_fuzz_no_foreign_exceptions(tmp_path):
    rng = random.Random(0x8B5053)
    corpus = [b"", b"8BPS", b"\xff" * 80, b"\0" * 128]
    corpus += [rng.randbytes(rng.randrange(1, 160)) for _ in range(60)]
    for version in (1, 2):
        good = _document(version)
        corpus += [good[:end] for end in range(0, len(good), 7)]
        for _ in range(100):
            changed = bytearray(good)
            at = rng.randrange(len(changed))
            changed[at] ^= 1 << rng.randrange(8)
            corpus.append(bytes(changed))
    path = tmp_path / "artifact.bin"
    for data in corpus:
        for call in (lambda: psd.inventory(data), lambda: psd.extract_payload(data, "thumbnail")):
            try:
                call()
            except Exception as exc:
                assert type(exc) is psd.PSDInventoryError
    for data in corpus[:30]:
        path.write_bytes(data)
        try:
            psd.inventory_file(path)
        except Exception as exc:
            assert type(exc) is psd.PSDInventoryError
    for data in (None, 1, "8BPS", [], bytearray(b"8BPS")):
        with pytest.raises(psd.PSDInventoryError):
            psd.inventory(data)
    for value in (None, 1, [], "\0"):
        with pytest.raises(psd.PSDInventoryError):
            psd.inventory_file(value)


def test_overlong_extents_and_invalid_utf16_reject():
    data = _document()
    # Color-mode size claims bytes beyond EOF, without allocating that size.
    broken = data[:26] + b"\xff" * 4 + data[30:]
    with pytest.raises(psd.PSDInventoryError):
        psd.inventory(broken)
    broken = data.replace(_unicode("Visible \u03a9"), _u32(9) + b"\xd8\x00" + b"\0V" * 8, 1)
    with pytest.raises(psd.PSDInventoryError):
        psd.inventory(broken)
    broken = _document(2)
    at = broken.index(b"8BIMlnk2") + 8
    broken = broken[:at] + b"\xff" * 8 + broken[at + 8:]
    with pytest.raises(psd.PSDInventoryError):
        psd.inventory(broken)


def test_module_basename_unique_and_not_stdlib():
    root = Path(__file__).resolve().parents[1]
    assert len(list((root / "solvers").rglob("ff_psd_inventory.py"))) == 1
    assert "ff_psd_inventory" not in sys.stdlib_module_names
