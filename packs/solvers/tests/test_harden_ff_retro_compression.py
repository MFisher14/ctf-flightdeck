"""Independent vectors and fail-closed checks for retro/container inspectors.

The fixtures are assembled from the documented wire layouts, never from an
encoder in the engines under test: NESdev's NES 2.0 header, the PICO-8 manual's
cartridge formats, ZPAQ 2.06 sections 2/4, and lrzip's magic.header.txt.  Pillow
is used as an independent PNG writer and liblzma parses the LZMA property bytes.
"""

from __future__ import annotations

import hashlib
import io
import lzma
import random

from PIL import Image
import pytest

import ff_lrzip_header as lrzip
import ff_pico8_cart as pico8
import ff_rom_headers as rom
import ff_zpaq_inventory as zpaq


def _bitflip(data: bytes, index: int, bit: int) -> bytes:
    changed = bytearray(data)
    changed[index] ^= 1 << bit
    return bytes(changed)


def _assert_only_declared(call, declared, corpus) -> None:
    """A malformed sample may parse, but may not leak another exception."""
    for label, sample in corpus:
        try:
            result = call(sample)
        except declared:
            continue
        except BaseException as exc:  # SystemExit/assertions are leaks too.
            pytest.fail(f"{label} leaked {type(exc).__name__}: {exc}")
        assert isinstance(result, dict), label


def _nes2_exponent_fixture() -> bytes:
    # Byte 9's two F nibbles select EEEEEEMM sizing.  With E=MM=0 each
    # ROM is one byte; mapper 0xCAB and submapper 5 span bytes 6--8.
    return bytes.fromhex("4e45531a 0000 b1a8 5cff 2100 00000000") + b"PC"


def test_rom_headers_nes2_documented_exponent_vector_lock() -> None:
    result = rom.parse_nes(_nes2_exponent_fixture())
    assert (result["format"], result["mapper"], result["submapper"]) == (
        "nes2", 0xCAB, 5
    )
    assert (result["prg_rom_bytes"], result["chr_rom_bytes"]) == (1, 1)
    assert result["ram"] == {
        "prg_ram_bytes": 128,
        "prg_nvram_bytes": 256,
        "chr_ram_bytes": 0,
        "chr_nvram_bytes": 0,
    }
    assert [(item["name"], item["offset"], item["declared_bytes"])
            for item in result["regions"]] == [
        ("prg_rom", 16, 1), ("chr_rom", 17, 1)
    ]
    assert result["size"]["matches"] is True


def test_rom_headers_fail_closed_fuzz_and_oversize(monkeypatch) -> None:
    valid = _nes2_exponent_fixture()
    rng = random.Random(0x4E455332)
    corpus = [("empty", b"")]
    corpus += [(f"random-{size}", rng.randbytes(size))
               for size in (1, 4, 15, 16, 31, 257)]
    corpus += [(f"truncated-{end}", valid[:end]) for end in range(len(valid))]
    corpus += [(f"bitflip-{index}-{bit}", _bitflip(valid, index, bit))
               for index in range(len(valid)) for bit in (0, 3, 7)]
    _assert_only_declared(rom.inspect_rom, rom.RomError, corpus)

    monkeypatch.setattr(rom, "MAX_IMAGE_BYTES", len(valid) - 1)
    with pytest.raises(rom.RomError):
        rom.inspect_rom(valid)


_P8_HEADER = b"pico-8 cartridge // http://www.pico-8.com\nversion 41\n"


def _p8_text_fixture() -> bytes:
    return _P8_HEADER + b"__lua__\nprint('CSCTF{harden_text}')\n"


def _p8_png(payload: bytes) -> bytes:
    """Independent inverse of PICO-8's documented two-bits-per-channel map."""
    assert len(payload) == 160 * 205
    rgba = bytearray()
    for value in payload:
        rgba.extend((0xA0 | ((value >> 4) & 3),
                     0x50 | ((value >> 2) & 3),
                     0x08 | (value & 3),
                     0xFC | ((value >> 6) & 3)))
    image = Image.frombytes("RGBA", (160, 205), bytes(rgba))
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _p8_png_fixture() -> tuple[bytes, bytes]:
    payload = bytearray(160 * 205)
    payload[:8] = bytes.fromhex("0123456789abcdef")
    lua = b"print('CSCTF{harden_png}')"
    payload[0x4300:0x4300 + len(lua)] = lua
    payload[0x8000] = 41
    payload[0x8001:] = bytes(range(31))
    return _p8_png(bytes(payload)), bytes(payload)


def test_pico8_independent_text_and_png_vector_lock() -> None:
    text = _p8_text_fixture()
    text_result = pico8.parse_p8(text)
    lua = b"print('CSCTF{harden_text}')\n"
    assert text_result["version"] == 41
    assert text_result["sections"]["lua"]["sha256"] == hashlib.sha256(lua).hexdigest()
    assert text_result["flags"] == ["CSCTF{harden_text}"]

    png, payload = _p8_png_fixture()
    png_result = pico8.parse_p8_png(png)
    assert png_result["version"] == 41
    assert png_result["payload"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert png_result["sections"]["gfx"]["data_hex"].startswith("0123456789abcdef")
    assert png_result["sections"]["lua"]["text"] == "print('CSCTF{harden_png}')"
    assert png_result["flags"] == ["CSCTF{harden_png}"]


def test_pico8_fail_closed_fuzz_and_oversize(monkeypatch) -> None:
    text = _p8_text_fixture()
    png, _ = _p8_png_fixture()
    rng = random.Random(0x5049434F)
    corpus = [("empty", b"")]
    corpus += [(f"random-{size}", rng.randbytes(size))
               for size in (1, 8, 32, 255, 1024)]
    corpus += [(f"text-truncated-{end}", text[:end])
               for end in (1, 8, len(_P8_HEADER) - 1, len(text) - 1)]
    corpus += [(f"png-truncated-{end}", png[:end])
               for end in (1, 8, 32, len(png) // 2, len(png) - 1)]
    corpus += [(f"text-bitflip-{index}", _bitflip(text, index, index % 8))
               for index in (0, 7, len(_P8_HEADER), len(text) - 1)]
    corpus += [(f"png-bitflip-{index}", _bitflip(png, index, index % 8))
               for index in (0, 8, 20, len(png) // 2, len(png) - 1)]
    _assert_only_declared(pico8.inspect_cart, pico8.P8CartError, corpus)

    monkeypatch.setattr(pico8, "MAX_INPUT", len(text) - 1)
    with pytest.raises(pico8.P8CartError):
        pico8.inspect_cart(text)


def _zpaq_fixture() -> bytes:
    # Level 2, HPROG 1, seven-byte empty model; one unmodeled segment with
    # a big-endian four-byte chunk length, zero length terminator, FE trailer.
    header = b"zPQ\x02\x01\x07\x00" + b"\0" * 7
    segment = (b"\x01flag.txt\0" + b"4 demo\0" + b"\0"
               + b"\0\0\0\x04DATA" + b"\0\0\0\0" + b"\xfe")
    return header + segment + b"\xff"


def test_zpaq_documented_unmodeled_framing_vector_lock() -> None:
    raw = _zpaq_fixture()
    result = zpaq.inspect_zpaq(raw)
    assert (result["block_count"], result["segment_count"]) == (1, 1)
    block = result["blocks"][0]
    segment = block["segments"][0]
    assert (block["offset"], block["end_offset"], block["header_size"]) == (0, 46, 7)
    assert (segment["filename"], segment["comment"], segment["declared_size"]) == (
        "flag.txt", "4 demo", 4
    )
    assert (segment["encoded_offset"], segment["encoded_size"]) == (32, 12)
    assert (segment["chunk_count"], segment["framed_payload_size"]) == (1, 4)
    assert segment["encoded_sha256"] == hashlib.sha256(raw[32:44]).hexdigest()
    assert result["payload_verified"] is False


def test_zpaq_fail_closed_fuzz_and_oversize(monkeypatch) -> None:
    valid = _zpaq_fixture()
    rng = random.Random(0x5A504151)
    corpus = [("empty", b"")]
    corpus += [(f"random-{size}", rng.randbytes(size))
               for size in (1, 3, 7, 15, 64, 511)]
    corpus += [(f"truncated-{end}", valid[:end]) for end in range(len(valid))]
    corpus += [(f"bitflip-{index}-{bit}", _bitflip(valid, index, bit))
               for index in range(len(valid)) for bit in (0, 4, 7)]
    _assert_only_declared(zpaq.inspect_zpaq, zpaq.ZpaqError, corpus)

    monkeypatch.setattr(zpaq, "MAX_INPUT", len(valid) - 1)
    with pytest.raises(zpaq.ZpaqError):
        zpaq.inspect_zpaq(valid)


def _lrzip_v03_fixture() -> bytes:
    # Versions 0.2/0.3 store two BE u32 words low word first.  The resulting
    # value is 0x1122334455667788.  5d00008000 is the standard LZMA1 property
    # tuple (lc=3, lp=0, pb=2, 8 MiB dictionary).
    return bytes.fromhex(
        "4c525a49 0003 55667788 11223344 0000 5d00008000 000000"
    )


def test_lrzip_legacy_split_size_and_liblzma_vector_lock() -> None:
    wire = _lrzip_v03_fixture()
    result = lrzip.parse_header(wire)
    oracle = lzma._decode_filter_properties(lzma.FILTER_LZMA1, wire[16:21])
    assert result["version"] == "0.3"
    assert result["size_encoding"] == "two-big-endian-u32-low-first"
    assert result["declared_uncompressed_size"] == 0x1122334455667788
    assert {name: result["lzma_properties"][name] for name in ("lc", "lp", "pb")} == {
        name: oracle[name] for name in ("lc", "lp", "pb")
    }
    assert result["lzma_properties"]["dictionary_size"] == oracle["dict_size"]
    assert result["header_sha256"] == hashlib.sha256(wire).hexdigest()


def test_lrzip_fail_closed_fuzz_and_oversize() -> None:
    valid = _lrzip_v03_fixture()
    rng = random.Random(0x4C525A49)
    oversized = valid + rng.randbytes(1 << 20)
    corpus = [("empty", b""), ("oversized-tail", oversized)]
    corpus += [(f"random-{size}", rng.randbytes(size))
               for size in (1, 4, 23, 24, 64, 1024)]
    corpus += [(f"truncated-{end}", valid[:end]) for end in range(len(valid))]
    corpus += [(f"bitflip-{index}-{bit}", _bitflip(valid, index, bit))
               for index in range(len(valid)) for bit in (0, 2, 7)]
    _assert_only_declared(lrzip.parse_header, lrzip.LRZIPError, corpus)
    assert lrzip.parse_header(oversized)["payload_examined"] is False
