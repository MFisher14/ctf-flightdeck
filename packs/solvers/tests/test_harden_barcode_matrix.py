"""Independent vector locks and fail-closed probes for matrix_barcodes.

Oracles: reedsolo RSCodec (GF(2^m)), pdf417gen (GF(929), pattern writer),
zxing-cpp (independent symbol writer/reader), and small handwritten ISO encoders.
No fixture or expected value is produced by a matrix_barcodes encoder/helper.

ECI formula: ISO/IEC 16022:2000 table 10 (2024 table 9), independently
implemented by https://github.com/zxing-cpp/zxing-cpp/blob/master/core/src/datamatrix/DMDecoder.cpp
Aztec mode placement: ISO/IEC 24778; https://github.com/zxing/zxing/blob/master/core/src/main/java/com/google/zxing/aztec/encoder/Encoder.java
PDF byte/ECI rules: https://github.com/zxing/zxing/blob/master/core/src/main/java/com/google/zxing/pdf417/encoder/PDF417HighLevelEncoder.java
"""
from functools import lru_cache
import random

import pytest
import reedsolo
import zxingcpp
from pdf417gen.encoding import encode_rows
from pdf417gen.error_correction import compute_error_correction_code_words
from PIL import Image

import matrix_barcodes as barcode


def _eci_words(n):
    """ISO 16022 table 10 forward encoding, including the full 0..999999 range."""
    assert 0 <= n <= 999999
    if n < 127:
        return [241, n + 1]
    if n < 16383:
        a, b = divmod(n - 127, 254)
        return [241, a + 128, b + 1]
    a, remainder = divmod(n - 16383, 64516)
    b, c = divmod(remainder, 254)
    return [241, a + 192, b + 1, c + 1]


def _dm10(payload=b"A"):
    """Hand-built 10x10 ECC200 ASCII symbol, standard 8x8 Utah placements.

    Supports 1..3 ordinary ASCII bytes. Three data bytes + five RS bytes.
    The fixed anchors follow the ISO Annex M diagonal walk for this one size;
    this does not call the engine's placement/extraction routines.
    """
    assert 1 <= len(payload) <= 3 and all(v < 128 for v in payload)
    data = [v + 1 for v in payload]
    if len(data) < 3:
        data.append(129)
    while len(data) < 3:
        position = len(data) + 1
        value = 129 + (149 * position) % 253 + 1
        data.append(value if value <= 254 else value - 254)
    words = list(reedsolo.RSCodec(5, prim=0x12D, fcr=1).encode(bytes(data)))
    matrix = [[False] * 10 for _ in range(10)]
    for x in range(10):
        matrix[0][x], matrix[9][x] = x % 2 == 0, True
    for y in range(1, 9):
        matrix[y][0], matrix[y][9] = True, y % 2 == 1
    anchors = ((4, 0), (2, 2), (0, 4), (1, 7), (3, 5), (5, 3), (7, 1), (6, 6))
    shape = ((-2, -2), (-2, -1), (-1, -2), (-1, -1), (-1, 0), (0, -2), (0, -1), (0, 0))
    for word, (y, x) in zip(words, anchors):
        for bit, (dy, dx) in enumerate(shape):
            matrix[(y + dy) % 8 + 1][(x + dx) % 8 + 1] = bool(word & (128 >> bit))
    return matrix


@lru_cache(maxsize=16)
def _zx_symbol(name, payload=b"CSCTF{oracle}"):
    symbol = zxingcpp.create_barcode(payload, getattr(zxingcpp, name))
    image = zxingcpp.write_barcode_to_image(symbol, scale=1, add_quiet_zones=False)
    h, w = image.shape
    pixels = memoryview(image).cast("B")
    return tuple(tuple(pixels[y * w + x] == 0 for x in range(w)) for y in range(h))


def _pdf_symbol(data, level=0, columns=3):
    """Hand-specified high-level words; independent library adds ECC/row patterns."""
    words = data + compute_error_correction_code_words(data, level)
    assert len(words) % columns == 0
    rows = [words[i:i + columns] for i in range(0, len(words), columns)]
    patterns = encode_rows(rows, columns, level)
    return [[bit == "1" for bit in "".join(f"{p:0{18 if i == len(row)-1 else 17}b}"
                                         for i, p in enumerate(row))] for row in patterns]


def _reference_read(matrix):
    image = Image.new("L", (len(matrix[0]) + 8, len(matrix) + 8), 255)
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            image.putpixel((x + 4, y + 4), 0 if dark else 255)
    image = image.resize((image.width * 4, image.height * 4), Image.Resampling.NEAREST)
    return zxingcpp.read_barcode(image, is_pure=True)


@pytest.mark.parametrize("start,stop", [(0, 127), (127, 16383), (16383, 1000000)])
def test_datamatrix_every_valid_eci_assignment(start, stop):
    # Exhaustive, not sampled: every legal ECI assignment passes the forward
    # encoder through the decoder. The prior +1/-1 bug cannot hide in a boundary.
    for assignment in range(start, stop):
        result = barcode._dm_payload(_eci_words(assignment) + [66, 129])
        assert result is not None, assignment
        assert result["segments"] == [{"mode": "eci", "assignment": assignment}], assignment
        assert result["bytes"] == b"A", assignment


@pytest.mark.parametrize("assignment,words", [(0, [241, 1]), (126, [241, 127]),
    (127, [241, 128, 1]), (16382, [241, 191, 254]), (16383, [241, 192, 1, 1]),
    (15000, [241, 186, 142]), (90000, [241, 193, 36, 212]),
    (999999, [241, 207, 63, 129])])
def test_datamatrix_eci_published_arithmetic_boundaries(assignment, words):
    assert _eci_words(assignment) == words
    assert barcode._dm_payload(words)["segments"][0]["assignment"] == assignment


@pytest.mark.parametrize("payload", [b"A", b"ABC", b"\0\x7f"])
def test_handbuilt_datamatrix_symbol_and_public_aggregate(payload):
    matrix = _dm10(payload)
    assert _reference_read(matrix).bytes == payload
    assert barcode.decode_datamatrix(matrix)[0]["bytes"] == payload
    assert barcode.decode_other(matrix)[0]["bytes"] == payload
    # A single known data module changes the first codeword; RS must repair it.
    matrix[3][7] ^= True
    result = barcode.decode_datamatrix(matrix)[0]
    assert result["bytes"] == payload
    assert result["corrected_symbols"] == 1


@pytest.mark.parametrize("name,decoder,symbology", [
    ("DataMatrix", barcode.decode_datamatrix, "datamatrix"),
    ("Aztec", barcode.decode_aztec, "aztec"),
    ("PDF417", barcode.decode_pdf417, "pdf417"),
    ("CompactPDF417", barcode.decode_pdf417, "compact_pdf417"),
    ("MicroPDF417", barcode.decode_micropdf417, "micropdf417"),
])
def test_public_symbol_decoders_independent_writer_reader(name, decoder, symbology):
    payload = b"CSCTF{oracle}"
    matrix = _zx_symbol(name, payload)
    result = decoder(matrix)
    assert result and result[0]["bytes"] == payload
    assert result[0]["symbology"] == symbology
    assert result[0]["corrected_symbols"] == 0
    assert any(x["bytes"] == payload for x in barcode.decode_other(matrix))
    symbol = zxingcpp.create_barcode(payload, getattr(zxingcpp, name))
    image = zxingcpp.write_barcode_to_image(symbol, scale=3, add_quiet_zones=True)
    oracle = zxingcpp.read_barcode(image, is_pure=True)
    assert oracle is not None and oracle.bytes == payload


@pytest.mark.parametrize("bits,primitive,parity", [(4, 0x13, 5), (6, 0x43, 6),
    (8, 0x12D, 8), (10, 0x409, 10), (12, 0x1069, 12)])
def test_binary_rs_all_barcode_fields_against_reedsolo(bits, primitive, parity):
    data = [1, 2, 3] if bits == 4 else [1, 2, 3, 7, 17, 31]
    size = 1 << bits
    oracle = reedsolo.RSCodec(parity, nsize=size - 1, fcr=1, prim=primitive, c_exp=bits)
    encoded = list(oracle.encode(data))
    field = barcode._GF(primitive, size, 1)
    assert barcode.rs_binary(encoded, parity, field) == (encoded, 0)
    for errors in range(1, parity // 2 + 1):
        damaged = encoded[:]
        for i in range(errors):
            damaged[i * 2] ^= i + 1
        assert barcode.rs_binary(damaged, parity, field) == (encoded, errors)


@pytest.mark.parametrize("level", [0, 1, 2, 3])
def test_pdf417_rs_against_independent_library(level):
    data = [10, 900, 2, 18, 2, 19, 5, 900, 901, 65]
    parity = 2 ** (level + 1)
    encoded = data + compute_error_correction_code_words(data, level)
    assert barcode.rs_pdf417(encoded, parity) == (encoded, 0)
    for errors in range(1, parity // 2 + 1):
        damaged = encoded[:]
        for i in range(errors):
            damaged[i] = (damaged[i] + 37 + i) % 929
        assert barcode.rs_pdf417(damaged, parity) == (encoded, errors)


@pytest.mark.parametrize("compact,layers,data_words", [(True, 1, 1), (True, 4, 64),
    (False, 1, 1), (False, 32, 2048)])
def test_handbuilt_aztec_mode_information(compact, layers, data_words):
    # Forward construction of only the mode ring, with independent GF(16) ECC.
    payload_width = 8 if compact else 16
    value = ((layers - 1) << (6 if compact else 11)) | (data_words - 1)
    nibbles = [(value >> shift) & 15 for shift in range(payload_width - 4, -1, -4)]
    encoded = reedsolo.RSCodec(5 if compact else 6, nsize=15, fcr=1,
                              prim=0x13, c_exp=4).encode(nibbles)
    bits = [bool(v & (1 << shift)) for v in encoded for shift in range(3, -1, -1)]
    size = 15 if compact else 19
    matrix, center = [[False] * size for _ in range(size)], size // 2
    count, distance = (7, 5) if compact else (10, 7)
    for i in range(count):
        offset = i - count // 2 + (i // 5 if not compact else 0)
        matrix[center - distance][center + offset] = bits[i]
        matrix[center + offset][center + distance] = bits[count + i]
        matrix[center + distance][center + offset] = bits[3 * count - 1 - i]
        matrix[center + offset][center - distance] = bits[4 * count - 1 - i]
    assert barcode._aztec_parameters(matrix, compact) == (layers, data_words, 0)
    matrix[center - distance][center - count // 2] ^= True
    assert barcode._aztec_parameters(matrix, compact) == (layers, data_words, 1)


def test_handencoded_datamatrix_compaction_modes_and_eci_bytes():
    # C40 triplet ABC: values 14,15,16 -> 1600*14+40*15+16+1.
    c40 = 1600 * 14 + 40 * 15 + 16 + 1
    assert barcode._dm_payload([230, c40 >> 8, c40 & 255, 254, 129])["bytes"] == b"ABC"
    assert barcode._dm_payload([239, c40 >> 8, c40 & 255, 254, 129])["bytes"] == b"abc"
    # Base256 bytes are randomized by their absolute 1-based codeword positions.
    raw = b"\0\xff\xc3\xa9"
    plain = [len(raw), *raw]
    randomized = [(n + (149 * pos) % 255 + 1) % 256 for pos, n in enumerate(plain, 2)]
    result = barcode._dm_payload([231, *randomized])
    assert result["bytes"] == raw
    # ASCII upper shift supplies UTF-8 bytes under ECI 26.
    result = barcode._dm_payload([241, 27, 235, 68, 235, 42, 129])
    assert result["bytes"] == b"\xc3\xa9" and result["text"] == "é"


def test_published_pdf417_numeric_example_and_handencoded_bytes():
    # ZXing's normative worked example (ISO 15438 numeric compaction).
    words = [8, 902, 1, 624, 434, 632, 282, 200]
    assert barcode._pdf_payload(words)["bytes"] == b"000213298174000"
    raw = b"ABCDEF"
    value, encoded = int.from_bytes(raw, "big"), []
    for _ in range(5):
        value, word = divmod(value, 900)
        encoded.insert(0, word)
    assert barcode._pdf_payload([7, 924, *encoded])["bytes"] == raw


def test_bug_pdf417_901_final_five_bytes():
    assert barcode._pdf_payload([7, 901, 65, 66, 67, 68, 69])["bytes"] == b"ABCDE"


@pytest.mark.parametrize("groups", [0, 1, 2])
@pytest.mark.parametrize("tail", [1, 2, 3, 4, 5])
def test_pdf417_901_compressed_groups_and_literal_tail(groups, tail):
    raw = bytes(range(6 * groups + tail))
    encoded = []
    for offset in range(0, groups * 6, 6):
        value = int.from_bytes(raw[offset:offset + 6], "big")
        words = []
        for _ in range(5):
            value, word = divmod(value, 900)
            words.insert(0, word)
        encoded.extend(words)
    encoded.extend(raw[groups * 6:])
    assert barcode._pdf_payload([len(encoded) + 2, 901, *encoded])["bytes"] == raw


def test_pdf417_901_five_byte_fixture_reference_decode():
    assert _reference_read(_pdf_symbol([7, 901, 65, 66, 67, 68, 69])).bytes == b"ABCDE"


def test_bug_public_pdf417_901_final_five_bytes():
    matrix = _pdf_symbol([7, 901, 65, 66, 67, 68, 69])
    assert barcode.decode_pdf417(matrix)[0]["bytes"] == b"ABCDE"


@pytest.mark.parametrize("eci", [900, 901, 1799, 1800, 810899])
def test_bug_pdf417_general_eci(eci):
    first, second = divmod(eci, 900)
    assert barcode._pdf_payload([4, 926, first - 1, second])["segments"][0]["assignment"] == eci


@pytest.mark.parametrize("words", [[241, 0], [241, 128, 0], [241, 128, 255],
    [241, 192, 0, 1], [241, 192, 1, 0], [241, 208, 1, 1], [241, 207, 254, 254]])
def test_bug_datamatrix_invalid_eci(words):
    assert barcode._dm_payload(words + [66, 129]) is None


_DECODERS = (barcode.decode_datamatrix, barcode.decode_aztec,
             barcode.decode_pdf417, barcode.decode_micropdf417, barcode.decode_other)


@pytest.mark.parametrize("decoder", _DECODERS)
def test_public_matrix_decoders_fail_closed_deterministic_corpus(decoder):
    rng = random.Random(0x16022)
    cases = [None, [], (), b"", b"\xff" * 32, [[0], []], [[2]], [[255]], [[None]]]
    for side in (1, 8, 10, 15, 19, 21, 32):
        cases += [[[False] * side for _ in range(side)], [[True] * side for _ in range(side)]]
    for _ in range(24):
        h, w = rng.randrange(1, 25), rng.randrange(1, 60)
        cases.append([[bool(rng.getrandbits(1)) for _ in range(w)] for _ in range(h)])
    for name in ("DataMatrix", "Aztec", "PDF417", "MicroPDF417"):
        valid = [list(row) for row in _zx_symbol(name)]
        # Real finder/start patterns survive while their symbols are cut short.
        cases.extend([valid[:1], valid[:-1], [row[:-1] for row in valid]])
        for flips in (1, 2, 8, 32):
            mutated = [row[:] for row in valid]
            for _ in range(flips):
                y, x = rng.randrange(len(mutated)), rng.randrange(len(mutated[0]))
                mutated[y][x] ^= True
            cases.append(mutated)
    for matrix in cases:
        # This module declares no custom exception and promises [] on malformed
        # matrix input; no stdlib exception is accepted here.
        result = decoder(matrix)
        assert isinstance(result, list)
        assert all(isinstance(x.get("bytes"), bytes) for x in result)


def test_rs_fail_closed_random_words_and_real_prefixes():
    rng = random.Random(0xB4AC0DE)
    field = barcode._GF(0x12D, 256, 1)
    data = [1, 2, 3, 4, 5, 6]
    binary = list(reedsolo.RSCodec(8, fcr=1, prim=0x12D).encode(bytes(data)))
    prime = data + compute_error_correction_code_words(data, 2)
    for fn, valid, maximum, extra in ((barcode.rs_binary, binary, 255, (field,)),
                                     (barcode.rs_pdf417, prime, 928, ())):
        cases = [None, [], b"", [maximum] * 14, [-1] * 14, [maximum + 1] * 14, ["x"] * 14]
        cases.extend(valid[:i] for i in range(len(valid)))
        for _ in range(64):
            cases.append([rng.randrange(maximum + 1) for _ in range(rng.randrange(1, 30))])
        for words in cases:
            result = fn(words, 8, *extra)
            assert result is None or (isinstance(result, tuple) and len(result) == 2)


@pytest.mark.parametrize("fn,extra", [(barcode.rs_binary, (barcode._GF(0x12D, 256, 1),)),
                                     (barcode.rs_pdf417, ())])
@pytest.mark.parametrize("parity", [None, 0, -1, 1.0, "1", True, {}, []])
def test_bug_rs_noninteger_parity_leaks_stdlib(fn, extra, parity):
    assert fn([1, 2, 3], parity, *extra) is None
