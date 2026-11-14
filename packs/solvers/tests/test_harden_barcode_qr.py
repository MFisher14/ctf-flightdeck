"""Independent QR vector locks and deterministic fail-closed regressions.

Oracles: ISO/IEC 18004:2015 Annex C Table C.1 and Annex I.2 published words;
handwritten version-1 placement below, reedsolo GF(256) encoding, and python-qrcode.
https://nuintun.github.io/qrcode/spec/ISO-IEC-18004-2015.pdf
No qr_matrix encoder/helper is used to construct expected symbols or bytes.
The module explicitly raises ValueError for validation: only that exact type
is permitted, never its UnicodeError subclasses or incidental runtime errors.
"""
from io import BytesIO
import json
import random

from PIL import Image
import pytest
import qrcode
from qrcode.util import QRData, MODE_8BIT_BYTE, mask_func
from reedsolo import RSCodec

import qr_matrix as qr


# Published masked format words, ISO 18004:2015 Table C.1, indexed by mask.
FORMATS = {
    "M": [0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0],
    "L": [0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976],
    "H": [0x1689, 0x13BE, 0x1CE7, 0x19D0, 0x0762, 0x0255, 0x0D0C, 0x083B],
    "Q": [0x355F, 0x3068, 0x3F31, 0x3A06, 0x24B4, 0x2183, 0x2EDA, 0x2BED],
}
FORMAT_BITS = {"M": 0, "L": 1, "H": 2, "Q": 3}
PARITY = {"L": 7, "M": 10, "Q": 13, "H": 17}
# ISO Annex I.2 step 2 (numeric 01234567, version 1-M).
ANNEX_WORDS = bytes.fromhex("10200c566180ec11ec11ec11ec11ec11a524d4c1ed36c7872c55")
ALPHANUMERIC = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def _bits(value, width):
    assert 0 <= value < 1 << width
    return f"{value:0{width}b}"


def _byte_segment(value):
    return "0100" + _bits(len(value), 8) + "".join(_bits(x, 8) for x in value)


def _alpha_segment(value):
    out = "0010" + _bits(len(value), 9)
    for at in range(0, len(value) - 1, 2):
        out += _bits(ALPHANUMERIC.index(value[at]) * 45 + ALPHANUMERIC.index(value[at + 1]), 11)
    if len(value) % 2:
        out += _bits(ALPHANUMERIC.index(value[-1]), 6)
    return out


def _pad_and_encode(bits, ecl):
    size = 26 - PARITY[ecl]
    assert len(bits) <= size * 8
    bits += "0" * min(4, size * 8 - len(bits))
    bits += "0" * (-len(bits) % 8)
    words = bytearray(int(bits[n:n + 8], 2) for n in range(0, len(bits), 8))
    pads = (0xEC, 0x11)
    i = 0
    while len(words) < size:
        words.append(pads[i % 2])
        i += 1
    return bytes(RSCodec(PARITY[ecl], prim=0x11D, fcr=0, generator=2).encode(words))


def _v1_symbol(words, ecl="M", mask=2):
    """Small test-only ISO encoder: reserve/draw functions, then place 26 words.

    Uses its own cell reservations and published format words. qrcode's independent
    mask functions supply the eight masking predicates, never qr_matrix's helpers.
    """
    assert len(words) == 26
    m = [[None for _ in range(21)] for _ in range(21)]
    for top, left in ((0, 0), (0, 14), (14, 0)):
        for dy in range(-1, 8):
            for dx in range(-1, 8):
                y, x = top + dy, left + dx
                if 0 <= y < 21 and 0 <= x < 21:
                    m[y][x] = (0 <= dy <= 6 and 0 <= dx <= 6 and
                               (dy in (0, 6) or dx in (0, 6) or (2 <= dy <= 4 and 2 <= dx <= 4)))
    for at in range(8, 13):
        m[6][at] = m[at][6] = at % 2 == 0
    fmt = FORMATS[ecl][mask]
    vertical = [0, 1, 2, 3, 4, 5, 7, 8, 14, 15, 16, 17, 18, 19, 20]
    horizontal = [20, 19, 18, 17, 16, 15, 14, 13, 7, 5, 4, 3, 2, 1, 0]
    for bit in range(15):
        m[vertical[bit]][8] = bool((fmt >> bit) & 1)
        m[8][horizontal[bit]] = bool((fmt >> bit) & 1)
    m[13][8] = True
    stream = "".join(_bits(x, 8) for x in words)
    locations = []
    predicate = mask_func(mask)
    for stripe, right in enumerate((20, 18, 16, 14, 12, 10, 8, 5, 3, 1)):
        ys = range(20, -1, -1) if stripe % 2 == 0 else range(21)
        for y in ys:
            for x in (right, right - 1):
                if m[y][x] is None:
                    m[y][x] = (stream[len(locations)] == "1") ^ predicate(y, x)
                    locations.append((y, x))
    assert len(locations) == 208
    return m, locations


def _ascii(matrix):
    return "\n".join("".join("1" if c else "0" for c in row) for row in matrix)


def _png(matrix, scale=4, border=4):
    side = len(matrix)
    image = Image.new("L", ((side + 2 * border) * scale,) * 2, 255)
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                image.paste(0, ((x + border) * scale, (y + border) * scale,
                               (x + border + 1) * scale, (y + border + 1) * scale))
    return image


def _checked(call, allowed_value_error=True):
    try:
        return call()
    except Exception as exc:
        assert allowed_value_error and type(exc) is ValueError, f"foreign exception {type(exc).__name__}: {exc}"
        return None


def test_iso_annex_i_published_codewords_and_symbol():
    bits = "0001" + _bits(8, 10) + _bits(12, 10) + _bits(345, 10) + _bits(67, 7)
    assert _pad_and_encode(bits, "M") == ANNEX_WORDS
    symbol, _ = _v1_symbol(ANNEX_WORDS)
    # Independent library corroborates the test encoder's function modules and placement.
    reference = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M,
                              mask_pattern=2, border=0)
    reference.add_data("01234567", optimize=0)
    reference.make(fit=False)
    assert symbol == reference.get_matrix()
    result = qr.decode_matrix(symbol)[0]
    assert (result["bytes"], result["text"], result["ecl"], result["mask"]) == (b"01234567", "01234567", "M", 2)
    assert result["segments"][0]["mode"] == "numeric"


@pytest.mark.parametrize("ecl", ["L", "M", "Q", "H"])
@pytest.mark.parametrize("mask", range(8))
def test_all_format_words_masks_and_payload_bytes(ecl, mask):
    payload = b"A\x00\xff"
    words = _pad_and_encode(_byte_segment(payload), ecl)
    symbol, _ = _v1_symbol(words, ecl, mask)
    assert qr._format_code((FORMAT_BITS[ecl] << 3) | mask) == FORMATS[ecl][mask]
    assert qr._extract(symbol, 1, mask) == words
    result = qr.decode_matrix(symbol)[0]
    assert result["bytes"] == payload
    assert (result["ecl"], result["mask"], result["format_distance"]) == (ecl, mask, 0)
    assert result["corrected_symbols"] == 0


def test_published_bch_and_rs_recovery_after_independent_damage():
    symbol, positions = _v1_symbol(ANNEX_WORDS)
    # Three damaged format bits and five byte errors exactly fill 1-M RS capacity.
    for y in (0, 1, 2):
        symbol[y][8] ^= True
    for index in (0, 4, 9, 16, 24):
        y, x = positions[index * 8]
        symbol[y][x] ^= True
    result = qr.decode_matrix(symbol)[0]
    assert result["bytes"] == b"01234567"
    assert result["format_distance"] == 3
    assert result["corrected_symbols"] == 5


@pytest.mark.parametrize("text", ["A", "AB", "AC-42", "HELLO WORLD"])
def test_handbuilt_alphanumeric_mode(text):
    symbol, _ = _v1_symbol(_pad_and_encode(_alpha_segment(text), "M"))
    result = qr.decode_matrix(symbol)[0]
    assert result["bytes"] == text.encode("ascii")
    assert result["segments"][0]["mode"] == "alphanumeric"


def test_handbuilt_kanji_and_mixed_mode():
    text = "漢字"
    raw = text.encode("shift_jis")  # Python's independent character-set mapping.
    bits = "1000" + _bits(len(text), 8)
    for at in range(0, len(raw), 2):
        code = int.from_bytes(raw[at:at + 2], "big")
        reduced = code - (0x8140 if code <= 0x9FFC else 0xC140)
        bits += _bits((reduced >> 8) * 0xC0 + (reduced & 255), 13)
    symbol, _ = _v1_symbol(_pad_and_encode(bits + _byte_segment(b"abc"), "L"), "L")
    result = qr.decode_matrix(symbol)[0]
    assert result["text"] == "漢字abc"
    assert result["bytes"] == "漢字abc".encode("utf-8")
    assert [x["mode"] for x in result["segments"]] == ["kanji", "byte"]


@pytest.mark.parametrize("assignment", [0, 3, 20, 26, 127, 128, 16383, 16384, 999999])
def test_handbuilt_eci_width_boundaries(assignment):
    prefix = (_bits(assignment, 8) if assignment < 128 else
              _bits(0x8000 | assignment, 16) if assignment < 16384 else
              _bits(0xC00000 | assignment, 24))
    symbol, _ = _v1_symbol(_pad_and_encode("0111" + prefix + _byte_segment(b"A"), "M"))
    result = qr.decode_matrix(symbol)[0]
    assert result["bytes"] == b"A"
    assert result["segments"][0] == {"mode": "eci", "assignment": assignment}


@pytest.mark.parametrize("parity,length", [(7, 19), (10, 16), (18, 31), (30, 225)])
def test_rs_matches_independent_reedsolo(parity, length):
    original = bytes((i * 37 + 19) % 256 for i in range(length))
    codec = RSCodec(parity, prim=0x11D, fcr=0, generator=2)
    expected = bytes(codec.encode(original))
    assert qr.rs_correct(expected, parity) == (expected, 0)
    damaged = bytearray(expected)
    positions = list(range(parity // 2))
    for i in positions:
        damaged[i] ^= 91 + i
    assert bytes(codec.decode(damaged)[0]) == original
    assert qr.rs_correct(bytes(damaged), parity) == (expected, len(positions))
    # Mixed known erasures + unknown errors satisfy 2e+s = parity (or parity-1).
    damaged = bytearray(expected)
    erasures = list(range(parity - 4))
    positions = erasures + [parity, parity + 1]
    for i in positions:
        damaged[i] ^= 137
    assert bytes(codec.decode(damaged, erase_pos=erasures)[0]) == original
    assert qr.rs_correct(bytes(damaged), parity, erasures) == (expected, len(positions))


@pytest.mark.parametrize("version", [5, 7, 10, 27])
def test_multiblock_version_count_width_against_qrcode(version):
    payload = b"CSCTF{interleaved_and_versioned}"
    reference = qrcode.QRCode(version=version, error_correction=qrcode.constants.ERROR_CORRECT_Q,
                              mask_pattern=5, border=0)
    reference.add_data(QRData(payload, mode=MODE_8BIT_BYTE), optimize=0)
    reference.make(fit=False)
    matrix = reference.get_matrix()
    assert qr._extract(matrix, version, 5) == bytes(reference.data_cache)
    result = qr.decode_matrix(matrix)[0]
    assert result["bytes"] == payload
    assert result["version"] == version


def test_ascii_transformations_and_sampler_public_entrypoints():
    symbol, _ = _v1_symbol(ANNEX_WORDS)
    assert qr.parse_ascii(_ascii(symbol)) == symbol
    assert qr.parse_ascii_rect("1 0 1\n0 1 0") == [[True, False, True], [False, True, False]]
    seen = set()
    for actual, info in qr.transformations(symbol):
        expected = [[not x if info["inverted"] else x for x in row] for row in symbol]
        if info["mirrored"]:
            expected = [list(row) for row in zip(*expected)]
        for _ in range(info["rotation"] // 90):
            expected = [[expected[20 - x][y] for x in range(21)] for y in range(21)]
        assert actual == expected
        seen.add((info["inverted"], info["mirrored"], info["rotation"]))
    assert len(seen) == 16
    assert qr.parse_dimensions("21x21") == (21, 21)
    assert qr.parse_dimensions("720,1") == (720, 1)
    corners = ((0.0, 0.0), (84.0, 0.0), (84.0, 84.0), (0.0, 84.0))
    assert qr.parse_corners("0,0;84,0;84,84;0,84") == corners
    pixels = [0 if symbol[y // 4][x // 4] else 255 for y in range(84) for x in range(84)]
    assert qr.projective_sample(pixels, 84, 84, (21, 21), corners) == symbol
    # Structural-only DM: independent solid L + alternating opposite edges, no payload.
    dm = [[False] * 12 for _ in range(12)]
    for i in range(12):
        dm[i][0] = dm[11][i] = True
        dm[0][i] = i % 2 == 0
        dm[i][11] = i % 2 == 1
    result = qr.recognize_other(dm)
    assert result[0]["symbology"] == "datamatrix" and result[0]["payload"] is None


def test_raster_path_and_cli_public_entrypoints(tmp_path, capsys):
    symbol, _ = _v1_symbol(ANNEX_WORDS)
    text = tmp_path / "annex.txt"
    text.write_text(_ascii(symbol))
    raster = tmp_path / "annex.png"
    _png(symbol).save(raster)
    assert symbol in qr.raster_matrices(raster, dimensions=(21, 21), curvatures=(0.0,))
    assert qr.decode_path(text)[0]["bytes"] == b"01234567"
    assert qr.decode_path(raster, dimensions=(21, 21), curvatures=(0.0,))[0]["bytes"] == b"01234567"
    assert qr.main([str(text), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["candidates"][0]["bytes"] == b"01234567".hex()
    assert qr.main([str(text), "--bad"]) == 2


def test_seeded_matrix_text_rs_and_sampler_fuzz():
    rng = random.Random(0xBADC0DE)
    symbol, _ = _v1_symbol(ANNEX_WORDS)
    corpus = [[], [[255] * 21 for _ in range(21)], [[False] * 21 for _ in range(21)]]
    corpus += [symbol[:i] for i in (1, 8, 20)]
    for _ in range(30):
        side = rng.choice((1, 9, 21, 25, 29))
        corpus.append([[bool(rng.getrandbits(1)) for _ in range(side)] for _ in range(side)])
    for _ in range(20):
        changed = [row[:] for row in symbol]
        for __ in range(rng.randrange(1, 12)):
            changed[rng.randrange(21)][rng.randrange(21)] ^= True
        corpus.append(changed)
    for m in corpus:
        for fn in (qr.decode_matrix, qr.recognize_other):
            _checked(lambda: fn(m))
        _checked(lambda: list(qr.transformations(m)))
    for text in ("", "\xff" * 32, "\x00", "101\n010", _ascii(symbol)[:-3]):
        for fn in (qr.parse_ascii, qr.parse_ascii_rect, qr.parse_dimensions, qr.parse_corners):
            _checked(lambda: fn(text))
    for _ in range(100):
        value = rng.randbytes(rng.randrange(0, 48))
        qr.rs_correct(value, 7)
        qr.rs_correct(b"\xff" * len(value), 7)
        qr._payload(value, 1)
        for fn in (qr.parse_ascii, qr.parse_ascii_rect, qr.parse_dimensions, qr.parse_corners):
            _checked(lambda: fn(value.decode("latin-1")))
    for value in ([], [0] * 63, [255] * 64, [rng.randrange(256) for _ in range(64)]):
        _checked(lambda: qr.projective_sample(value, 8, 8, (2, 2), ((0, 0), (8, 0), (8, 8), (0, 8))))


def test_cli_empty_random_ff_and_png_prefixes(tmp_path, capsys):
    path = tmp_path / "invalid.bin"
    for raw in (b"", b"\xff" * 32, random.Random(127).randbytes(64),
                b"\x89PNG\r\n\x1a\n", b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"):
        path.write_bytes(raw)
        assert qr.main([str(path), "--json"]) == 2
        assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize("entrypoint", ["raster_matrices", "decode_path"])
def test_malformed_file_fuzz_is_fail_closed(entrypoint, tmp_path):
    symbol, _ = _v1_symbol(ANNEX_WORDS)
    stream = BytesIO()
    _png(symbol).save(stream, format="PNG")
    real = stream.getvalue()
    rng = random.Random(18004)
    corpus = [b"", b"\xff" * 64, rng.randbytes(64), real[:8], real[:24], real[:-10]]
    for _ in range(12):
        changed = bytearray(real)
        at = rng.randrange(len(changed))
        changed[at] ^= 1 << rng.randrange(8)
        corpus.append(bytes(changed))
    leaks = []
    path = tmp_path / "untrusted.bin"
    for index, raw in enumerate(corpus):
        path.write_bytes(raw)
        try:
            getattr(qr, entrypoint)(path)
        except Exception as exc:
            if type(exc) is not ValueError:
                leaks.append((index, type(exc).__name__))
    assert leaks == []


@pytest.mark.parametrize("entrypoint,args", [
    ("rs_correct", (b"abc", None)), ("rs_correct", (b"abc", 1, [None])),
    ("parse_dimensions", (1,)), ("parse_corners", (1,)),
    ("projective_sample", ([None] * 4, 2, 2, (1, 1), ((0, 0), (2, 0), (2, 2), (0, 2)))),
])
def test_bad_argument_boundary_is_fail_closed(entrypoint, args):
    _checked(lambda: getattr(qr, entrypoint)(*args))


def test_cli_help_returns_normally():
    try:
        actual = qr.main(["--help"])
    except SystemExit as exc:
        actual = ("SystemExit", exc.code)
    assert actual == 0


def test_fnc1_handbuilt_symbol_payload():
    bits = "0101" + _alpha_segment("A%B%%C")
    symbol, _ = _v1_symbol(_pad_and_encode(bits, "M"))
    assert qr.decode_matrix(symbol)[0]["bytes"] == b"A\x1dB%C"


@pytest.mark.parametrize("header,expected_alpha", [
    ("", b"A%%%B%"),
    ("0101", b"A%\x1dB\x1d"),
    ("1001" + _bits(42, 8), b"A%\x1dB\x1d"),
])
def test_fnc1_percent_scope_and_segment_offsets(header, expected_alpha):
    # FNC1 transforms only alphanumeric data; byte-mode percent signs stay literal.
    bits = header + _alpha_segment("A%%%B%") + _byte_segment(b"%%")
    symbol, _ = _v1_symbol(_pad_and_encode(bits, "M"))
    result = qr.decode_matrix(symbol)[0]
    assert result["bytes"] == expected_alpha + b"%%"
    assert result["segments"][-2]["length"] == len(expected_alpha)
    assert result["segments"][-1]["offset"] == len(expected_alpha)
    if header.startswith("1001"):
        assert result["segments"][0] == {"mode": "fnc1", "second": True, "indicator": 42}


def test_eci4_handbuilt_symbol_text():
    symbol, _ = _v1_symbol(_pad_and_encode("0111" + _bits(4, 8) + _byte_segment(b"\xa1"), "M"))
    assert qr.decode_matrix(symbol)[0]["text"] == b"\xa1".decode("iso8859_2")


def test_truncated_fnc1_payload_rejected():
    assert qr._payload(bytes.fromhex("90"), 1) is None


def test_eci_out_of_range_payload_rejected():
    assert qr._payload(bytes.fromhex("7cf4240401a100"), 1) is None
