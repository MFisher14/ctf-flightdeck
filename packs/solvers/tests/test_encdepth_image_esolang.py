"""Independent PNG fixtures and published image-language mappings.

No production encoder or Brainfuck runtime is used. The fixture encoder writes
PNG signature/IHDR/zlib IDAT/IEND with PNG filter 0 directly, independently of PIL.
"""
import binascii
import struct
import zlib

import pytest

import encdepth_image_esolang as engine


def png(rows):
    height, width = len(rows), len(rows[0])
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", binascii.crc32(kind + body))
    pixels = b"".join(b"\0" + bytes(c for rgb in row for c in rgb) for row in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


# Independently transcribed published Brainloller table, not imported from engine.
COLORS = {
    ">": (255, 0, 0), "<": (128, 0, 0), "+": (0, 255, 0), "-": (0, 128, 0),
    ".": (0, 0, 255), ",": (0, 0, 128), "[": (255, 255, 0), "]": (128, 128, 0),
    "R": (0, 255, 255), "L": (0, 128, 128), " ": (255, 255, 255),
}


def image_of(text_rows):
    return png([[COLORS[char] for char in row] for row in text_rows])


def test_published_palette_all_commands_round_trip():
    expected = "><+-.,[]"
    report = engine.transcribe(image_of([expected]), dialect="brainloller")
    assert report["source"] == expected
    assert report["source_coordinates"] == [[i, 0] for i in range(8)]
    assert report["exit"] == [8, 0]
    assert report["executed"] is False


def test_turns_snake_orientation_and_provenance():
    # Four boundary turns: clockwise twice, then anticlockwise twice.
    report = engine.transcribe(image_of(["+[>+R", "L<-]R", "L.++."]), dialect="brainloller")
    assert report["source"] == "+[>+]-<.++."
    assert report["turns"] == 4
    assert report["path_pixels"] == 15
    assert report["source_coordinates"][4:7] == [[3, 1], [2, 1], [1, 1]]
    assert report["exit"] == [5, 2]


def test_anticlockwise_turn_exits_top():
    report = engine.transcribe(image_of(["+L", ".."]), dialect="brainloller")
    assert report["source"] == "+"
    assert report["exit"] == [1, -1]


def test_nonpalette_pixels_are_comments_without_rounding():
    report = engine.transcribe(png([[(0, 254, 0), COLORS["+"], (3, 3, 3)]]), dialect="brainloller")
    assert report["source"] == "+"
    assert report["comments"] == 2


def test_published_copter_formula_multiple_rgb_values_round_trip():
    # Reference encoder: choose nearest RGB integer with desired remainder.
    # Decoder equivalence is independently checked via -2R+3G+B modulo 11.
    source = "><+-.,[]" * 20
    pixels = []
    for index, op in enumerate(source):
        command = "><+-.,[]".index(op)
        color = (index * 7919 + 65536) // 11 * 11 + command
        rgb = (color >> 16, color >> 8 & 255, color & 255)
        assert (-2 * rgb[0] + 3 * rgb[1] + rgb[2]) % 11 == command
        pixels.append(rgb)
    result = engine.transcribe(png([pixels]), dialect="braincopter")
    assert result["source"] == source


def test_copter_turns_and_nop():
    # Codes 2 plus, 8 clockwise, 9 anticlockwise, 10 nop.
    rows = [[(0, 0, x) for x in row] for row in [[2, 10, 8], [4, 4, 8]]]
    report = engine.transcribe(png(rows), dialect="braincopter")
    assert report["source"] == "+.."
    assert report["comments"] == 1
    assert report["turns"] == 2


def test_nonterminating_bf_is_only_transcribed():
    report = engine.transcribe(image_of(["+[+]" ]), dialect="brainloller")
    assert report["source"] == "+[+]"
    assert report["path_pixels"] == 4
    assert report["executed"] is False


@pytest.mark.parametrize("text", ["[", "]", "+][+", "[[+]"])
def test_unbalanced_brackets_refuse(text):
    with pytest.raises(engine.ImageEsolangError, match="bracket"):
        engine.transcribe(image_of([text]), dialect="brainloller")


@pytest.mark.parametrize("bad", [None, 1, "PNG", bytearray(b"PNG"), b"", b"PNG", b"\x89PNG\r\n\x1a\n"])
def test_malformed_input_declared_error(bad):
    with pytest.raises(engine.ImageEsolangError):
        engine.transcribe(bad, dialect="brainloller")


@pytest.mark.parametrize("dialect", [None, [], {}, "unknown"])
def test_invalid_dialect_declared_error(dialect):
    with pytest.raises(engine.ImageEsolangError):
        engine.transcribe(image_of(["+"]), dialect=dialect)


def test_all_comments_refuse():
    with pytest.raises(engine.ImageEsolangError, match="no Brainfuck"):
        engine.transcribe(image_of(["   "]), dialect="brainloller")


def test_bad_crc_refuse():
    data = bytearray(image_of(["+"]))
    data[29] ^= 0x80  # IHDR CRC
    with pytest.raises(engine.ImageEsolangError):
        engine.transcribe(bytes(data), dialect="brainloller")


@pytest.mark.parametrize("limit", ["MAX_FILE", "MAX_PIXELS", "MAX_PATH", "MAX_SOURCE"])
def test_resource_bounds(limit, monkeypatch):
    monkeypatch.setattr(engine, limit, 1)
    with pytest.raises(engine.ImageEsolangError):
        engine.transcribe(image_of(["++"]), dialect="brainloller")


def test_cli_guard_and_source(tmp_path, capsys):
    assert engine.main(["--help"]) == 0
    assert engine.main([]) == 2
    assert engine.main(["missing.png", "--dialect", "braincopter"]) == 2
    path = tmp_path / "program.png"
    path.write_bytes(image_of(["+."]))
    assert engine.main([str(path), "--dialect", "brainloller", "--source"]) == 0
    assert capsys.readouterr().out.endswith("+.\n")
