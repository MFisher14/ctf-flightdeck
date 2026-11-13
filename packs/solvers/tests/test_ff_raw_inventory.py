"""Independent TIFF/DNG/CR2/CR3 fixtures for offline RAW recovery.

The TIFF writer below hand-packs directory records and absolute offsets; it does
not call the engine or its metadata dependency to create any expected value.
Pillow supplies a real, deterministic tiny JPEG. DNG original-data packing follows
Adobe's OriginalRawFileData specification, with zlib as the compression oracle.
"""
from io import BytesIO
import json
import random
import struct
import zlib

from PIL import Image
import pytest

import ff_raw_inventory as raw


# Adobe DNG 1.7.1, OriginalRawFileData, pp. 42-43:
# https://helpx.adobe.com/content/dam/help/en/camera-raw/digital-negative/jcr_content/root/content/flex/items/position/position-par/download_section_733958301/download-1/DNG_Spec_1_7_1_0.pdf
# ExifTool independently implements the layout in Image/ExifTool/DNG.pm,
# ProcessOriginalRaw. Canon THMB layout: Image/ExifTool/Canon.pm, uuid table.


def _jpeg():
    out = BytesIO()
    Image.new("RGB", (4, 3), (17, 29, 43)).save(out, "JPEG")
    return out.getvalue()


JPEG = _jpeg()
PREVIEW_AT = 4096


class _Tiff:
    """Minimal independent TIFF/BigTIFF writer, with fixed directory locations."""

    def __init__(self, endian="<", big=False, cr2=False):
        self.endian, self.big = endian, big
        self.data = bytearray(8192)
        self.inline = 8 if big else 4
        self.ptr_type = 16 if big else 4
        magic = b"II" if endian == "<" else b"MM"
        if big:
            self.data[:16] = magic + struct.pack(endian + "HHHQ", 43, 8, 0, 32)
        else:
            self.data[:8] = magic + struct.pack(endian + "HI", 42, 32)
        if cr2:
            assert not big
            self.data[8:16] = b"CR\x02\x00" + struct.pack(endian + "I", 512)

    def put(self, at, value):
        self.data[at:at + len(value)] = value

    def directory(self, at, entries, next_ifd=0):
        parts = [struct.pack(self.endian + ("Q" if self.big else "H"), len(entries))]
        codes = {3: "H", 4: "I", 13: "I", 16: "Q", 18: "Q"}
        for tag, typ, value in sorted(entries):
            if typ in (1, 2, 7):
                encoded = bytes(value)
                count = len(encoded)
            else:
                count = len(value)
                encoded = struct.pack(self.endian + str(count) + codes[typ], *value)
            if len(encoded) > self.inline:
                off = len(self.data)
                self.data.extend(encoded)
                encoded = struct.pack(self.endian + ("Q" if self.big else "I"), off)
            parts.append(struct.pack(self.endian + ("HHQ" if self.big else "HHI"), tag, typ, count))
            parts.append(encoded.ljust(self.inline, b"\0"))
        parts.append(struct.pack(self.endian + ("Q" if self.big else "I"), next_ifd))
        table = b"".join(parts)
        assert at + len(table) < PREVIEW_AT
        self.put(at, table)

    def finish(self):
        return bytes(self.data)


def _preview_entries(t, kind="jpeg", offset=PREVIEW_AT, length=None):
    entries = [(256, 4, [4]), (257, 4, [3]), (259, 3, [7]), (254, 4, [1])]
    tags = (513, 514) if kind == "jpeg" else (273, 279)
    entries += [(tags[0], t.ptr_type, [offset]),
                (tags[1], t.ptr_type, [len(JPEG) if length is None else length])]
    return entries


def _tiff_preview(endian="<", big=False, subifd=False, kind="jpeg", cr2=False,
                  offset=PREVIEW_AT, length=None):
    t = _Tiff(endian, big, cr2)
    entries = _preview_entries(t, kind, offset, length)
    if subifd or cr2:
        t.directory(32, [(330, t.ptr_type, [512])])
        t.directory(512, entries)
    else:
        t.directory(32, entries)
    t.put(PREVIEW_AT, JPEG)
    return t.finish()


@pytest.mark.parametrize("endian,big", [("<", False), (">", False), ("<", True), (">", True)])
def test_tiff_bigtiff_known_preview_extents(endian, big):
    data = _tiff_preview(endian, big)
    report = raw.inventory(data)
    assert report["format"] == "tiff"
    assert report["ifds"][0]["offset"] == 32
    preview = report["previews"][0]
    assert (preview["offset"], preview["length"]) == (PREVIEW_AT, len(JPEG))
    assert preview["recoverable"] is True
    assert raw.extract_preview(data) == JPEG


@pytest.mark.parametrize("big", [False, True])
def test_subifd_preview_is_followed(big):
    data = _tiff_preview(big=big, subifd=True)
    report = raw.inventory(data)
    assert {item["offset"] for item in report["ifds"]} == {32, 512}
    assert raw.extract_preview(data) == JPEG


def test_bigtiff_ifd8_pointer_uses_existing_reader_extension():
    t = _Tiff(big=True)
    t.directory(32, [(330, 18, [512])])
    t.directory(512, _preview_entries(t))
    t.put(PREVIEW_AT, JPEG)
    assert raw.extract_preview(t.finish()) == JPEG


def test_jpeg_strip_preview_and_cr2_raw_ifd_pointer():
    assert raw.extract_preview(_tiff_preview(kind="strip")) == JPEG
    data = _tiff_preview(cr2=True)
    report = raw.inventory(data)
    assert report["format"] == "cr2"
    assert 512 in {item["offset"] for item in report["ifds"]}
    assert raw.extract_preview(data) == JPEG


@pytest.mark.parametrize("offset,length", [(8190, 32), (0xFFFFFFFF, 2), (PREVIEW_AT, 100000)])
def test_preview_extents_must_stay_within_file(offset, length):
    with pytest.raises(raw.RawError):
        raw.inventory(_tiff_preview(offset=offset, length=length))


def test_ifd_cycle_and_missing_extent_pair_are_rejected():
    t = _Tiff()
    t.directory(32, _preview_entries(t), next_ifd=32)
    t.put(PREVIEW_AT, JPEG)
    with pytest.raises(raw.RawError):
        raw.inventory(t.finish())
    t = _Tiff()
    t.directory(32, [(513, 4, [PREVIEW_AT])])
    with pytest.raises(raw.RawError):
        raw.inventory(t.finish())


def test_maker_note_contents_stay_opaque():
    t = _Tiff()
    t.directory(32, [(37500, 7, _tiff_preview())])
    result = raw.inventory(t.finish())
    assert len(result["ifds"]) == 1
    assert result["previews"] == []


def test_invalid_jpeg_bytes_never_recover_as_preview():
    data = bytearray(_tiff_preview())
    data[PREVIEW_AT:PREVIEW_AT + 2] = b"NO"
    try:
        report = raw.inventory(bytes(data))
    except raw.RawError:
        return
    assert not any(item["recoverable"] for item in report["previews"])
    with pytest.raises(raw.RawError):
        raw.extract_preview(bytes(data))


def _fork(content):
    """Adobe's big-endian fork index, followed by independently zipped 64KiB blocks."""
    if not content:
        return b"\0\0\0\0"
    chunks = [zlib.compress(content[at:at + 65536]) for at in range(0, len(content), 65536)]
    offsets = [4 * (len(chunks) + 2)]
    for compressed in chunks:
        offsets.append(offsets[-1] + len(compressed))
    return struct.pack(">I", len(content)) + b"".join(struct.pack(">I", n) for n in offsets) + b"".join(chunks)


def _original(content, resource=b"", thumbnail=b"", trailing=b""):
    return (_fork(content) + _fork(resource) + b"NEF " + b"NIKO" +
            _fork(thumbnail) + _fork(b"") + b"JPEG" + b"prvw" + trailing)


def _dng(content, endian="<", name=b"camera-original.nef\0", big=False):
    original = _original(content, b"resource-fork")
    t = _Tiff(endian, big)
    # Filename precedes data in sorted tag order and is the only prior external value.
    original_at = 8192 + len(name)
    t.directory(32, [*_preview_entries(t), (50706, 1, b"\x01\x04\0\0"),
                     (0xC68B, 2, name), (0xC68C, 7, original)])
    t.put(PREVIEW_AT, JPEG)
    return t.finish(), original_at, len(original)


@pytest.mark.parametrize("endian,big", [("<", False), (">", False), ("<", True), (">", True)])
def test_dng_filename_and_original_data_are_distinct_tags(endian, big):
    expected = b"CSCTF{independent_embedded_original}\0\xff\x10"
    data, offset, length = _dng(expected, endian, big=big)
    result = raw.inventory(data)
    assert result["format"] == "dng"
    original = result["originals"][0]
    assert original["name"] == "camera-original.nef"
    assert (original["offset"], original["length"]) == (offset, length)
    assert raw.extract_original(data) == expected
    assert raw.extract_preview(data) == JPEG


def test_filename_tag_alone_is_not_an_embedded_original():
    t = _Tiff()
    t.directory(32, [(50706, 1, b"\x01\x04\0\0"), (0xC68B, 2, b"only-a-name.nef\0")])
    assert raw.inventory(t.finish())["originals"] == []
    with pytest.raises(raw.RawError):
        raw.extract_original(t.finish())


def test_original_two_chunks_resource_fork_and_trailing_extension():
    expected = bytes(range(256)) * 300  # 76800 bytes crosses the 64KiB chunk boundary.
    result = raw.decode_original(_original(expected, b"known-resource", JPEG, b"future-extension"))
    assert result["data_fork"] == expected
    assert result["resource_fork"] == b"known-resource"
    assert result["thm_data_fork"] == JPEG
    assert result["file_type"] == b"NEF "
    assert result["file_creator"] == b"NIKO"
    assert result["trailing"]["length"] == len(b"future-extension")


def test_original_missing_trailing_blocks_have_zero_defaults():
    assert raw.decode_original(_fork(b"data-only"))["data_fork"] == b"data-only"
    assert raw.decode_original(_fork(b"data-only"))["resource_fork"] == b""


@pytest.mark.parametrize("length", [0, 1, 65535, 65536, 65537])
def test_original_chunk_boundaries(length):
    expected = b"a" * length
    assert raw.decode_original(_original(expected))["data_fork"] == expected


def test_original_output_limit_and_corrupt_indexes_are_rejected():
    with pytest.raises(raw.RawError):
        raw.decode_original(_original(b"x" * 1000), max_output=999)
    valid = _original(b"hello")
    for offset, value in ((4, 4), (8, 11), (8, 0xFFFFFFFF)):
        damaged = bytearray(valid)
        damaged[offset:offset + 4] = struct.pack(">I", value)
        with pytest.raises(raw.RawError):
            raw.decode_original(bytes(damaged))
    damaged = bytearray(valid)
    damaged[12] ^= 0xFF
    with pytest.raises(raw.RawError):
        raw.decode_original(bytes(damaged))


def test_original_declared_length_must_match_inflated_bytes():
    encoded = bytearray(_original(b"abcdef"))
    encoded[:4] = struct.pack(">I", 5)
    with pytest.raises(raw.RawError):
        raw.decode_original(bytes(encoded))


def _box(kind, payload, extended=False):
    if extended:
        return struct.pack(">I4sQ", 1, kind, len(payload) + 16) + payload
    return struct.pack(">I4s", len(payload) + 8, kind) + payload


def _cr3_thumbnail(extended=False):
    # ExifTool Canon.pm THMB uses a sixteen-byte body prefix before the JPEG.
    thmb = struct.pack(">IHHIHH", 0, 4, 3, len(JPEG), 1, 0) + JPEG
    canon_uuid = bytes.fromhex("85c0b687820f11e08111f4ce462b6a48")
    canon = _box(b"uuid", canon_uuid + _box(b"THMB", thmb), extended)
    return _box(b"ftyp", b"crx " + b"\0\0\0\0" + b"crx isom") + _box(b"moov", canon)


@pytest.mark.parametrize("extended", [False, True])
def test_cr3_canon_uuid_thumbnail(extended):
    data = _cr3_thumbnail(extended)
    report = raw.inventory(data)
    assert report["format"] == "cr3"
    assert raw.extract_preview(data) == JPEG
    preview = report["previews"][0]
    assert data[preview["offset"]:preview["offset"] + preview["length"]] == JPEG


def test_cr3_preview_uuid_preamble_and_prvw_fields():
    # Clevy's CR3 reverse engineering: eight bytes precede the PRVW child box;
    # PRVW has a sixteen-byte big-endian header with dimensions and JPEG length.
    preview_uuid = bytes.fromhex("eaf42b5e1c984b88b9fbb7dc406e4d16")
    preview_body = struct.pack(">IHHHHI", 0, 1, 4, 3, 1, len(JPEG)) + JPEG
    # ExifTool QuickTime.pm records the observed prefix as int32u[2] = 0, 1.
    preview_box = _box(b"uuid", preview_uuid + struct.pack(">II", 0, 1) + _box(b"PRVW", preview_body))
    data = _box(b"ftyp", b"crx " + b"\0" * 4 + b"crx ") + preview_box
    assert raw.inventory(data)["format"] == "cr3"
    assert raw.extract_preview(data) == JPEG


def test_cr3_cmt_metadata_offsets_and_opaque_maker_notes():
    t = _Tiff()
    t.directory(32, [(271, 2, b"Canon\0")])
    # CMT3 is deliberately not TIFF: maker-note bytes must remain opaque.
    children = _box(b"CMT1", t.finish()) + _box(b"CMT3", b"opaque-maker-bytes")
    filetype = _box(b"ftyp", b"crx " + b"\0" * 4 + b"crx ")
    canon = _box(b"uuid", bytes.fromhex("85c0b687820f11e08111f4ce462b6a48") + children)
    data = filetype + _box(b"moov", canon)
    report = raw.inventory(data)
    ifd = report["ifds"][0]
    assert ifd["tags"] == [271]
    assert ifd["offset"] == len(filetype) + 8 + 8 + 16 + 8 + 32
    assert len(report["ifds"]) == 1
    assert next(box for box in report["boxes"] if box["type"] == "CMT3")["status"] == "opaque maker notes"


@pytest.mark.parametrize("data", [None, 1, "II*", [], {}])
def test_public_wrong_types_raise_only_declared_error(data):
    for fn in (raw.inventory, raw.extract_preview, raw.extract_original, raw.decode_original):
        with pytest.raises(raw.RawError):
            fn(data)


def test_configured_input_graph_and_box_caps(monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(raw, "MAX_INPUT", 64)
        with pytest.raises(raw.RawError):
            raw.inventory(_tiff_preview())
    with monkeypatch.context() as patch:
        patch.setattr(raw, "MAX_IFDS", 1)
        with pytest.raises(raw.RawError):
            raw.inventory(_tiff_preview(subifd=True))
    with monkeypatch.context() as patch:
        patch.setattr(raw, "MAX_BOXES", 1)
        with pytest.raises(raw.RawError):
            raw.inventory(_cr3_thumbnail())


@pytest.mark.parametrize("index", [-1, 1, None, "0"])
def test_invalid_extraction_index_is_declined(index):
    with pytest.raises(raw.RawError):
        raw.extract_preview(_tiff_preview(), index=index)
    data, _, _ = _dng(b"original")
    with pytest.raises(raw.RawError):
        raw.extract_original(data, index=index)


def test_seeded_malformed_input_contract():
    rng = random.Random(0xC68C)
    valid = _tiff_preview()
    cr3 = _cr3_thumbnail()
    corpus = [b"", b"\xff" * 128, b"II*\0", b"MM\0+", b"\0\0\0\x20ftypcrx "]
    corpus += [rng.randbytes(n) for n in (1, 4, 8, 16, 32, 256)]
    corpus += [valid[:n] for n in (7, 15, 31, 33, 100, 4096, 4100)]
    corpus += [cr3[:n] for n in (8, 16, 32, 50, len(cr3) - 1)]
    for specimen in (valid, cr3):
        for _ in range(12):
            changed = bytearray(specimen)
            at = rng.randrange(min(128, len(changed)))
            changed[at] ^= 1 << rng.randrange(8)
            corpus.append(bytes(changed))
    for data in corpus:
        for fn in (raw.inventory, raw.extract_preview, raw.extract_original, raw.decode_original):
            try:
                fn(data)
            except raw.RawError:
                pass


def test_cli_guard_and_known_preview(tmp_path, capsys):
    source = tmp_path / "camera.tif"
    source.write_bytes(_tiff_preview())
    assert raw.main(["--help"]) == 0
    capsys.readouterr()
    assert raw.main([]) == 2
    capsys.readouterr()
    assert raw.main([str(source)]) == 0
    assert json.loads(capsys.readouterr().out)["previews"][0]["offset"] == PREVIEW_AT
    destination = tmp_path / "out"
    assert raw.main([str(source), "--extract", str(destination)]) == 0
    assert JPEG in [path.read_bytes() for path in destination.iterdir() if path.is_file()]
    source.write_bytes(b"II*\0")
    assert raw.main([str(source)]) == 2


def test_cli_never_uses_embedded_filename_as_output_path(tmp_path, capsys):
    original = b"CSCTF{contained_export}"
    source = tmp_path / "camera.dng"
    data, _, _ = _dng(original, name=b"../../escaped.raw\0")
    source.write_bytes(data)
    destination = tmp_path / "extracted"
    assert raw.main([str(source), "--extract", str(destination)]) == 0
    assert original in [path.read_bytes() for path in destination.iterdir() if path.is_file()]
    assert not (tmp_path.parent / "escaped.raw").exists()


def test_cli_combined_extraction_budget_is_checked_before_writes(tmp_path, monkeypatch):
    data, _, _ = _dng(b"data")
    source = tmp_path / "camera.dng"
    source.write_bytes(data)
    destination = tmp_path / "out"
    monkeypatch.setattr(raw, "MAX_OUTPUT", len(JPEG) + 3)
    assert raw.main([str(source), "--extract", str(destination)]) == 2
    assert not destination.exists()


def test_cli_decompression_budget_also_counts_discarded_forks(tmp_path, monkeypatch):
    t = _Tiff()
    packed = _original(b"x", resource=b"r" * 1500)
    t.directory(32, [(0xC68C, 7, packed)], next_ifd=512)
    t.directory(512, [(0xC68C, 7, packed)])
    source = tmp_path / "camera.dng"
    source.write_bytes(t.finish())
    destination = tmp_path / "out"
    monkeypatch.setattr(raw, "MAX_OUTPUT", 2000)
    assert raw.main([str(source), "--extract", str(destination)]) == 2
    assert not destination.exists()


def test_cli_guard_noninteger_system_exit(monkeypatch):
    def stop(*args, **kwargs):
        raise SystemExit("bad arguments")
    monkeypatch.setattr(raw.argparse.ArgumentParser, "parse_args", stop)
    assert raw.main([]) == 2
