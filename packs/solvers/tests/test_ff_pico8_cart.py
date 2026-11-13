"""Independent PICO-8 layout fixtures, with no engine encoder as an oracle.

Layouts: https://www.lexaloffle.com/dl/docs/pico-8_manual.html
https://github.com/dansanderson/picotool/tree/main/pico8
Compression: Lexaloffle's published p8_compress.c/pxa_compress_snippets.c at
https://github.com/dansanderson/lexaloffle (LSB-first PXA bitstream).
Pillow writes RGBA PNGs from hand-constructed channel samples.
"""

import io
import json
import random
import struct
import zlib

from PIL import Image
import pytest

import ff_pico8_cart as engine


HEADER = b"pico-8 cartridge // http://www.pico-8.com\nversion 42\n"
LUA = b'-- CSCTF{p8_text}\n#include missing.p8\nprint("hello")\n'


def text_fixture():
    # The first note is pitch 42, custom instrument 12, volume 7, effect 5.
    return (HEADER + b"__lua__\n" + LUA + b"__gfx__\n" +
            b"0123456789abcdef" * 8 + b"\n__map__\n" +
            bytes(range(128)).hex().encode() + b"\n__gff__\n" +
            b"f0" * 128 + b"\n__sfx__\n01100203" +
            b"2ac75" + b"00000" * 31 + b"\n__music__\n05 00013f44\n" +
            b"__label__\n" + b"12" * 64 + b"\n")


def make_png(payload, trailing=b""):
    assert len(payload) == 160 * 205
    # Independent inverse of the documented bit positions. Upper six bits
    # differ by channel, deliberately preventing an ordinary byte/RGB decode.
    rgba = [(0xA0 + ((v // 16) % 4), 0x50 + ((v // 4) % 4),
             0x08 + (v % 4), 0xF0 + (v // 64)) for v in payload]
    image = Image.new("RGBA", (160, 205))
    image.putdata(rgba)
    stream = io.BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue() + trailing


def code_payload(code):
    data = bytearray(32800)
    data[0x4300:0x4300 + len(code)] = code
    data[0x8000] = 42
    return bytes(data)


def pack_lsb_fields(fields):
    """Small reference writer driven by manually chosen PXA grammar tokens."""
    bit_string = []
    for value, width in fields:
        bit_string.extend((value // (2 ** bit)) % 2 for bit in range(width))
    return bytes(sum(bit_string[j + k] * (2 ** k)
                     for k in range(min(8, len(bit_string) - j)))
                 for j in range(0, len(bit_string), 8))


def pxa_stream(raw_size, fields):
    body = pack_lsb_fields(fields)
    return b"\x00pxa" + raw_size.to_bytes(2, "big") + (8 + len(body)).to_bytes(2, "big") + body


def test_text_sections_from_documented_layouts():
    result = engine.parse_p8(text_fixture())
    assert result["format"] == "p8" and result["version"] == 42
    sections = result["sections"]
    assert sections["lua"]["text"] == LUA.decode()
    assert bytes.fromhex(sections["lua"]["data_hex"]) == LUA
    assert sections["lua"]["byte_size"] == len(LUA)
    assert sections["gfx"]["data_hex"] == "1032547698badcfe" * 8
    assert sections["gfx"]["byte_size"] == 64
    assert sections["map"]["data_hex"] == bytes(range(128)).hex()
    assert sections["gff"]["data_hex"] == "f0" * 128
    assert sections["label"]["data_hex"] == "21" * 64
    assert sections["sfx"]["data_hex"] == "2adf" + "0000" * 31 + "01100203"
    sound = sections["sfx"]["records"][0]
    assert sound["notes"][0] == {"pitch": 42, "waveform": 12, "volume": 7, "effect": 5}
    assert (sound["editor_mode"], sound["speed"], sound["loop_start"], sound["loop_end"]) == (1, 16, 2, 3)
    assert sections["music"]["data_hex"] == "8001bf44"
    assert sections["music"]["records"] == [{"channels": [0, 1, 63, 68],
                                             "begin_loop": True, "end_loop": False, "stop": True}]
    assert result["flags"] == ["CSCTF{p8_text}"]
    assert result["trailing"]["byte_size"] == 0


def test_png_low_bits_regions_and_external_tail():
    payload = bytearray((i * 13 + 71) % 256 for i in range(32800))
    source = b'-- CSCTF{png_lua}\nprint("hello")\n'
    payload[0x4300:0x8000] = bytes(0x3D00)
    payload[0x4300:0x4300 + len(source)] = source
    payload[0x7FFC:0x8000] = b"HIDE"
    payload[0x8000] = 42
    tail = b"\0CSCTF{png_trailer}\xff"
    result = engine.parse_p8_png(make_png(payload, tail))
    assert bytes.fromhex(result["payload"]["data_hex"]) == bytes(payload)
    for name, a, b in [("gfx", 0, 0x2000), ("map", 0x2000, 0x3000),
                       ("gff", 0x3000, 0x3100), ("music", 0x3100, 0x3200),
                       ("sfx", 0x3200, 0x4300)]:
        assert result["sections"][name]["byte_size"] == b - a
        assert bytes.fromhex(result["sections"][name]["data_hex"]) == payload[a:b]
    lua = result["sections"]["lua"]
    assert lua["text"] == source.decode() and lua["compression"] == "uncompressed"
    assert lua["stored_byte_size"] == len(source) + 1
    assert lua["unused_storage"]["data_hex"].endswith(b"HIDE".hex())
    assert result["extra_payload"]["data_hex"] == payload[0x8001:].hex()
    assert result["extra_payload"]["byte_size"] == 31
    assert result["trailing"]["data_hex"] == tail.hex()
    assert result["flags"] == ["CSCTF{png_lua}", "CSCTF{png_trailer}"]


def test_legacy_literals_escape_and_back_reference():
    # Table indexes 13/14/15 => abc; 0x3c,0x13 => distance 3,length 3;
    # 0x00,0x40 => escaped @. Declared raw length is seven bytes.
    code = b":c:\0\0\x07\0\0\x0d\x0e\x0f\x3c\x13\0@"
    lua = engine.parse_p8_png(make_png(code_payload(code)))["sections"]["lua"]
    assert lua["text"] == "abcabc@"
    assert lua["compression"] == "legacy :c:"
    assert lua["stored_byte_size"] == len(code)


def test_pxa_move_to_front_and_overlapping_back_reference():
    # Literal 'a': index97, categories skip16 then32, payload49/6bits.
    # Literal 'b': after MTF(a), b remains index98 => payload50/6bits.
    # a is now index1 => four-bit payload1. Output is aba.
    # Block distance2,length6 overlaps and extends it to ababababa.
    fields = [(1, 1), (1, 1), (1, 1), (0, 1), (49, 6),
              (1, 1), (1, 1), (1, 1), (0, 1), (50, 6),
              (1, 1), (0, 1), (1, 4),
              (0, 1), (1, 1), (1, 1), (1, 5), (3, 3)]
    code = pxa_stream(9, fields)
    lua = engine.parse_p8_png(make_png(code_payload(code)))["sections"]["lua"]
    assert lua["text"] == "ababababa"
    assert lua["compression"] == "pxa" and lua["stored_byte_size"] == len(code)


def test_pxa_raw_block_with_unaligned_bytes():
    text = b"CSCTF{pxa_raw}"
    # block, 10-bit distance field0 is a raw-run marker; NUL ends the run.
    code = pxa_stream(len(text), [(0, 1), (1, 1), (0, 1), (0, 10)] +
                      [(c, 8) for c in text + b"\0"])
    result = engine.parse_p8_png(make_png(code_payload(code)))
    assert result["sections"]["lua"]["data_hex"] == text.hex()
    assert result["flags"] == [text.decode()]


def test_pxa_long_length_chain_and_15_bit_distance():
    # Raw ABC, then length10 at distance3: length chain 7,0 -> 3+7.
    fields = [(0, 1), (1, 1), (0, 1), (0, 10)] + [(c, 8) for c in b"ABC\0"]
    fields += [(0, 1), (0, 1), (2, 15), (7, 3), (0, 3)]
    lua = engine.parse_p8_png(make_png(code_payload(pxa_stream(13, fields))))["sections"]["lua"]
    assert lua["text"] == "ABCABCABCABCA"


@pytest.mark.parametrize("code", [
    b":c:\0\0\x01\0\0\x3c\0",  # distance zero
    b":c:\0\0\x01\0\0\x3c\x01",  # distance before output
    b":c:\0\0\x01\0\x01a",  # reserved header nonzero
    b"\0pxa\0\x01\0\x07",  # compressed size less than header
    b"\0pxa\0\x01\xff\xff",  # compressed size exceeds region
    pxa_stream(1, [(0, 1), (1, 1), (1, 1), (0, 5), (0, 3)]),  # bad reference
    pxa_stream(1, [(1, 1)] * 8),  # literal index overflow
    pxa_stream(1, [(0, 1), (1, 1), (0, 1), (0, 10), (65, 8), (66, 8), (0, 8)]),
])
def test_malformed_compression_is_declared_error(code):
    with pytest.raises(engine.P8CartError):
        engine.parse_p8_png(make_png(code_payload(code)))


@pytest.mark.parametrize("data", [
    HEADER, HEADER + b"garbage\n", HEADER + b"__unknown__\n", HEADER + b"__lua__\n__lua__\n",
    HEADER + b"__gfx__\n00\n", HEADER + b"__map__\n" + b"z" * 256,
    HEADER + b"__music__\n08 00000000\n", HEADER + b"__music__\n01 ff000000\n",
    HEADER + b"__gff__\n" + (b"00" * 128 + b"\n") * 3,
    HEADER + b"__sfx__\n0000000040000" + b"00000" * 31 + b"\n",
    HEADER + b"__lua__\n" + b"a" * (engine.MAX_LUA + 1),
    HEADER + b"__lua__\n" + b"\n" * 65537,
])
def test_malformed_text_is_declared_error(data):
    with pytest.raises(engine.P8CartError):
        engine.parse_p8(data)


def test_dispatch_file_and_guarded_cli(tmp_path, capsys, monkeypatch):
    fixture = text_fixture()
    path = tmp_path / "sample.p8"
    path.write_bytes(fixture)
    for report in (engine.inspect_file(path), engine.inspect_cart(fixture, "p8")):
        assert report["sections"]["lua"]["data_hex"] == LUA.hex()
        assert report["sections"]["gfx"]["data_hex"] == "1032547698badcfe" * 8
        assert report["sections"]["sfx"]["data_hex"] == "2adf" + "0000" * 31 + "01100203"
    assert engine.inspect_cart(make_png(code_payload(b"x")))["sections"]["lua"]["text"] == "x"
    assert engine.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == 42
    assert engine.main(["--help"]) == 0
    assert engine.main([]) == 2
    assert engine.main([str(tmp_path / "missing")]) == 2
    with pytest.raises(engine.P8CartError):
        engine.inspect_file(tmp_path / "missing")
    with pytest.raises(engine.P8CartError):
        engine.inspect_cart(fixture, "invalid")
    def non_integer_exit(*args, **kwargs):
        raise SystemExit("bad")
    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", non_integer_exit)
    assert engine.main([]) == 2


@pytest.mark.parametrize("parser", [engine.parse_p8, engine.parse_p8_png, engine.inspect_cart])
def test_multibyte_view_cannot_bypass_input_limit(parser):
    # len(view) counts elements while nbytes counts the actual input bytes.
    view = memoryview(b"a" * (engine.MAX_INPUT + 4)).cast("I")
    assert len(view) < engine.MAX_INPUT
    with pytest.raises(engine.P8CartError, match="4 MiB"):
        parser(view)


@pytest.mark.parametrize("parser", [engine.parse_p8, engine.parse_p8_png, engine.inspect_cart])
def test_fail_closed_deterministic_mutations(parser):
    rng = random.Random(20261105)
    png = make_png(code_payload(b"print(1)"))
    text = text_fixture()
    samples = [b"", b"\xff" * 100, b"\0" * 100, None, "text", 123,
               memoryview(b"bad"), b"x" * (engine.MAX_INPUT + 1)]
    for size in [1, 2, 7, 8, 13, 16, 32, 100, 1024]:
        samples.extend([rng.randbytes(size), png[:size], text[:size]])
    for source in (text, png):
        for _ in range(40):
            changed = bytearray(source)
            pos = rng.randrange(len(changed))
            changed[pos] ^= 1 << rng.randrange(8)
            samples.append(bytes(changed))
    for sample in samples:
        try:
            result = parser(sample)
            assert isinstance(result, dict)
        except engine.P8CartError:
            pass


def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def test_png_valid_crc_but_bad_dimensions_and_payload():
    # Valid PNG chunk CRCs ensure metadata validation, not only CRC failure,
    # rejects decompression bombs and unsupported color layouts.
    for width, height, color in [(0x7FFFFFFF, 205, 6), (160, 205, 2), (1, 1, 6)]:
        header = struct.pack(">IIBBBBB", width, height, 8, color, 0, 0, 0)
        data = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header) + png_chunk(b"IDAT", b"bad") + png_chunk(b"IEND", b"")
        with pytest.raises(engine.P8CartError):
            engine.parse_p8_png(data)
    header = struct.pack(">IIBBBBB", 160, 205, 8, 6, 0, 0, 0)
    data = b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", header) + png_chunk(b"IDAT", b"bad") + png_chunk(b"IEND", b"")
    with pytest.raises(engine.P8CartError):
        engine.parse_p8_png(data)
