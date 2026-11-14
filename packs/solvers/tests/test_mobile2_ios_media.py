"""Independent vectors for the mobile2 iOS snapshot/media engine."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import liblzfse
import pytest
from PIL import Image

import mobile2_ios_media as media


FIXTURES = Path(__file__).parent / "fixtures" / "meta_formats"


def _kv1(key: str, value: bytes, endian: str = "<") -> bytes:
    body = key.encode() + b"\0" + value
    return struct.pack(endian + "I", len(body)) + body + bytes((-len(body)) % 4)


def _ktx1(
    payload: bytes,
    width: int,
    height: int,
    *,
    kind: str = "rgba",
    endian: str = "<",
    key_values: bytes = b"",
) -> bytes:
    marker = b"\x01\x02\x03\x04" if endian == "<" else b"\x04\x03\x02\x01"
    if kind == "rgba":
        format_fields = (media.GL_UNSIGNED_BYTE, 1, media.GL_RGBA, media.GL_RGBA8, media.GL_RGBA)
    elif kind == "bgra":
        format_fields = (media.GL_UNSIGNED_BYTE, 1, media.GL_BGRA, media.GL_RGBA8, media.GL_RGBA)
    elif kind == "astc":
        format_fields = (0, 1, 0, media.GL_COMPRESSED_RGBA_ASTC_4X4, media.GL_RGBA)
    else:  # deliberately unsupported but structurally valid
        format_fields = (media.GL_UNSIGNED_BYTE, 1, 0x1907, 0x8051, 0x1907)
    header = media.KTX1_MAGIC + marker + struct.pack(
        endian + "12I", *format_fields, width, height, 0, 0, 1, 1, len(key_values)
    )
    return header + key_values + struct.pack(endian + "I", len(payload)) + payload + bytes((-len(payload)) % 4)


def _kv2(key: str, value: bytes) -> bytes:
    body = key.encode() + b"\0" + value
    return struct.pack("<I", len(body)) + body + bytes((-len(body)) % 4)


def _ktx2(payload: bytes, width: int, height: int, *, vk_format: int = 37, key_values: bytes = b"") -> bytes:
    # A structural KHR_DF descriptor: total size plus one 24-byte descriptor block.
    dfd = struct.pack("<III", 28, 0, 24 << 16) + bytes(16)
    dfd_offset = 80 + 24
    kvd_offset = dfd_offset + len(dfd) if key_values else 0
    after_metadata = dfd_offset + len(dfd) + len(key_values)
    alignment = 16 if vk_format in (157, 158) else 4
    level_offset = (after_metadata + alignment - 1) // alignment * alignment
    header = media.KTX2_MAGIC + struct.pack(
        "<13I2Q",
        vk_format,
        1,
        width,
        height,
        0,
        0,
        1,
        1,
        0,
        dfd_offset,
        len(dfd),
        kvd_offset,
        len(key_values),
        0,
        0,
    )
    level = struct.pack("<QQQ", level_offset, len(payload), len(payload))
    prefix = header + level + dfd + key_values
    return prefix + bytes(level_offset - len(prefix)) + payload


def _void_extent(red: int, green: int, blue: int, alpha: int = 0xFFFF) -> bytes:
    # ASTC specification's LDR void-extent block, with 16-bit unorm RGBA endpoints.
    return b"\xfc\xfd" + b"\xff" * 6 + struct.pack("<4H", red, green, blue, alpha)


def _atx_chunk(tag: bytes, payload: bytes) -> bytes:
    return struct.pack("<I4s", len(payload), tag) + payload


def _atx_head(width: int, height: int, discriminator: tuple[int, int] = (3, 5)) -> bytes:
    head = bytearray(0x54)
    struct.pack_into("<III", head, 0x18, width, height, 1)
    struct.pack_into("<II", head, 0x28, 1, 1)
    head[0x3C:0x4C] = bytes(range(16))
    struct.pack_into("<II", head, 0x4C, *discriminator)
    return bytes(head)


def _morton(index: int) -> tuple[int, int]:
    x = y = 0
    for bit in range(5):
        x |= ((index >> (2 * bit)) & 1) << bit
        y |= ((index >> (2 * bit + 1)) & 1) << bit
    return x, y


def test_ktx1_rgba_little_and_big_endian_published_layout() -> None:
    rgba = bytes((255, 0, 0, 255, 0, 255, 0, 128))
    for endian in ("<", ">"):
        encoded = _ktx1(rgba, 2, 1, endian=endian)
        report = media.parse_ktx(encoded)
        decoded = media.decode_ktx(encoded)
        assert report["container"] == "ktx1"
        assert report["endianness"] == ("little" if endian == "<" else "big")
        assert decoded["rgba"] == rgba


def test_ktx1_orientation_and_bgra_are_materialized_as_top_left_rgba() -> None:
    # File order A B / C D; S=l,T=u requests both axis reversals -> D C / B A.
    pixels = bytes(range(1, 17))
    orientation = _kv1("KTXorientation", b"S=l,T=u\0")
    assert media.decode_ktx(_ktx1(pixels, 2, 2, key_values=orientation))["rgba"] == (
        pixels[12:16] + pixels[8:12] + pixels[4:8] + pixels[0:4]
    )
    bgra = bytes((30, 20, 10, 40, 3, 2, 1, 4))
    assert media.decode_ktx(_ktx1(bgra, 2, 1, kind="bgra"))["rgba"] == bytes(
        (10, 20, 30, 40, 1, 2, 3, 4)
    )


def test_ktx2_offset_index_dfd_and_orientation() -> None:
    rgba = bytes((1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16))
    encoded = _ktx2(rgba, 2, 2, key_values=_kv2("KTXorientation", b"lu\0"))
    report = media.parse_ktx(encoded)
    assert report["container"] == "ktx2"
    assert report["data_format_descriptor"]["length"] == 28
    assert media.decode_ktx(encoded)["rgba"] == rgba[12:16] + rgba[8:12] + rgba[4:8] + rgba[:4]


def test_astc_void_extent_and_apple_lzfse_ktx_wrapper() -> None:
    red_block = _void_extent(0xFFFF, 0, 0)
    plain = _ktx1(red_block, 4, 4, kind="astc")
    rgba = media.decode_ktx(plain)["rgba"]
    assert set(tuple(rgba[pos:pos + 4]) for pos in range(0, len(rgba), 4)) == {(255, 0, 0, 255)}

    key_values = _kv1("Compression_APPLE", b"LZFSE\0")
    fields = (0, 1, 0, media.GL_COMPRESSED_RGBA_ASTC_4X4, media.GL_RGBA)
    header = media.KTX1_MAGIC + b"\x01\x02\x03\x04" + struct.pack(
        "<12I", *fields, 4, 4, 0, 0, 1, 1, len(key_values)
    )
    compressed = liblzfse.compress(red_block)  # independent real encoder oracle
    wrapped = header + key_values + struct.pack("<III", len(red_block), 0, 0) + compressed
    report = media.parse_ktx(wrapped)
    assert report["apple_lzfse"] is True
    assert media.decode_ktx(wrapped)["rgba"] == rgba


def test_atx_lzfs_layout_and_discriminator_confidence() -> None:
    blue_block = _void_extent(0, 0, 0xFFFF)
    compressed = liblzfse.compress(blue_block)
    encoded = (
        media.AAPL_MAGIC
        + _atx_chunk(b"HEAD", _atx_head(4, 4))
        + _atx_chunk(b"LZFS", struct.pack("<I", len(blue_block)) + compressed)
    )
    report = media.parse_ktx(encoded)
    decoded = media.decode_ktx(encoded)
    assert report["head"]["texture_uuid"] == bytes(range(16)).hex()
    assert decoded["format_confidence"] == "confirmed"
    assert set(tuple(decoded["rgba"][pos:pos + 4]) for pos in range(0, 64, 4)) == {(0, 0, 255, 255)}


def test_atx_raw_morton_tiling_reference() -> None:
    colors = {
        (False, False): _void_extent(0xFFFF, 0, 0),
        (True, False): _void_extent(0, 0xFFFF, 0),
        (False, True): _void_extent(0, 0, 0xFFFF),
        (True, True): _void_extent(0xFFFF, 0xFFFF, 0xFFFF),
    }
    blocks = []
    for index in range(32 * 32):
        x, y = _morton(index)
        blocks.append(colors[(x >= 16, y >= 16)])
    payload = b"".join(blocks)
    encoded = (
        media.AAPL_MAGIC
        + _atx_chunk(b"HEAD", _atx_head(128, 128))
        + _atx_chunk(b"astc", struct.pack("<I", len(payload)) + payload)
    )
    rgba = media.decode_ktx(encoded)["rgba"]

    def pixel(x: int, y: int) -> tuple[int, int, int, int]:
        offset = (y * 128 + x) * 4
        return tuple(rgba[offset:offset + 4])

    assert pixel(8, 8) == (255, 0, 0, 255)
    assert pixel(120, 8) == (0, 255, 0, 255)
    assert pixel(8, 120) == (0, 0, 255, 255)
    assert pixel(120, 120) == (255, 255, 255, 255)


def test_heic_real_encoder_fixture_matches_independent_heif_convert_oracle() -> None:
    raw = (FIXTURES / "sample.heic").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == "2478d864aa4be63204f6a03afa3ae5dad0f24a1936434939584a961ca12f835e"
    report = media.inspect_heif(raw)
    decoded = media.decode_heif(raw)
    assert report["category"] == "heic"
    assert report["major_brand"] == "heic"
    assert decoded["image_count"] == 1
    image = decoded["images"][0]
    assert (image["width"], image["height"]) == (64, 48)
    # Captured from Homebrew heif-convert + Pillow RGBA, independent of this engine.
    assert hashlib.sha256(image["rgba"]).hexdigest() == "ca24291d90498469cd9aba6f68de532f358ecccfc3c3d84dd4dd9353b2a2e7c9"


def test_detected_unknown_formats_decline_instead_of_guessing() -> None:
    unsupported = _ktx1(bytes(4), 1, 1, kind="unknown")
    assert media.parse_ktx(unsupported)["decodable"] is False
    with pytest.raises(media.Mobile2MediaError, match="not decodable|unsupported"):
        media.decode_ktx(unsupported)

    head = _atx_head(4, 4, discriminator=(99, 77))
    atx = media.AAPL_MAGIC + _atx_chunk(b"HEAD", head) + _atx_chunk(
        b"LZFS", struct.pack("<I", 16) + liblzfse.compress(_void_extent(0, 0, 0))
    )
    assert media.parse_ktx(atx)["decodable"] is False
    with pytest.raises(media.Mobile2MediaError, match="discriminator"):
        media.decode_ktx(atx)


def test_malformed_inputs_never_leak_stdlib_exceptions() -> None:
    malformed = [
        b"",
        b"not an image",
        media.KTX1_MAGIC,
        media.KTX2_MAGIC + bytes(100),
        media.AAPL_MAGIC + struct.pack("<I4s", 999, b"HEAD") + b"x",
        struct.pack(">I4s4sI", 16, b"ftyp", b"heic", 0),
    ]
    released = memoryview(b"KTX")
    released.release()
    malformed.append(released)
    for function in (media.parse_ktx, media.decode_ktx, media.inspect_heif, media.decode_heif):
        for value in malformed:
            try:
                function(value)
            except Exception as exc:  # contract assertion
                assert type(exc) is media.Mobile2MediaError


def test_cli_guard_and_png_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert media.main(["--help"]) == 0
    assert media.main([]) == 2
    assert media.main(["inspect", "missing", "--kind", "invalid"]) == 2
    capsys.readouterr()

    source = tmp_path / "snapshot.ktx"
    output = tmp_path / "snapshot.png"
    source.write_bytes(_ktx1(bytes((9, 8, 7, 255)), 1, 1))
    assert media.main(["decode", str(source), str(output)]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["outputs"] == [str(output)]
    with Image.open(output) as image:
        assert image.mode == "RGBA"
        assert image.size == (1, 1)
        assert image.getpixel((0, 0)) == (9, 8, 7, 255)
