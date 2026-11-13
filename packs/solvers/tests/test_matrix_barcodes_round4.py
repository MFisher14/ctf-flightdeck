"""Standards-derived matrices and deterministic mutation checks for the pure barcode decoders."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import matrix_barcodes as barcode  # noqa: E402
import qr_matrix  # noqa: E402
from ctf import triage  # noqa: E402


DM = """10101010101010101010
10110001011110000011
10100110100010011000
11000000101110101101
10011111100101101010
10111010001101010111
11100110110010010010
10101010111101101101
11110101110110101000
10000011111110011011
10101011010100100100
10000001100111110001
10110011001111011100
10011100000100100111
11111111000001000010
11000011011010010001
11001001111010011100
10100101011100010101
10000101100001011010
11111111111111111111"""

AZTEC = """0011100010111101101
1010110010011001101
0111011001001111101
0100101000111011000
0010110101011011000
0011111111111110011
1010110000000100110
0100110111110101101
0111110100010100100
0111010101010110011
0000110100010110011
1100110111110100011
1011010000000100001
0001011111111110010
0000001110101001111
1101111101100011110
1001010000011000111
1100100001010000100
1100010110100100010"""

PDF417 = """111111110101010001111101010111110011101011001111000110100010001100001110100010001110011111010101111100111111101000101001
111111110101010001111110101000111011010000111000010111000001011000101101011100100000011110101001000000111111101000101001
111111110101010001010100111100000010000100010011110111011100010111101111100101110100011101010001111110111111101000101001
111111110101010001101011110011111010110111100011100111011101000100001111001101000111011010111100111110111111101000101001
111111110101010001110101110000110011100000100011010100111110100011101011111101011000011110101110011100111111101000101001
111111110101010001111101011110110011000111110010010110001000101111101001100111011111011101011111010000111111101000101001
111111110101010001110100111011111010001100011000010100001000110110001011110111100010011101001110111110111111101000101001
111111110101010001111101001011000011100110111000010110101111000110001010000011110001010101111110111000111111101000101001"""


def _matrix(text):
    return [[cell == "1" for cell in row] for row in text.splitlines()]


def test_dependency_free_datamatrix_aztec_pdf417_known_symbols():
    expected = b"CSCTF{barcode_round4}"
    decoders = (
        (barcode.decode_datamatrix, _matrix(DM), "datamatrix"),
        (barcode.decode_aztec, _matrix(AZTEC), "aztec"),
        (barcode.decode_pdf417, _matrix(PDF417), "pdf417"),
    )
    for decoder, matrix, name in decoders:
        result = decoder(matrix)
        assert result and result[0]["symbology"] == name
        assert result[0]["bytes"] == expected and result[0]["text"] == expected.decode()
        assert result[0]["corrected_symbols"] == 0


def test_each_barcode_reed_solomon_repairs_a_real_symbol_error():
    dm = _matrix(DM)
    symbol = barcode._DM_SYMBOLS[(20, 20)]
    region = barcode._dm_data_region(dm, symbol)
    first = next(cell for cell, value in barcode._dm_placement(len(region), len(region[0])).items()
                 if value[0] == 0)
    dm[first[0] + 1][first[1] + 1] ^= True
    result = barcode.decode_datamatrix(dm)
    assert result[0]["text"] == "CSCTF{barcode_round4}"
    assert result[0]["corrected_symbols"] == 1

    aztec = _matrix(AZTEC)
    aztec[0][0] ^= True
    result = barcode.decode_aztec(aztec)
    assert result[0]["text"] == "CSCTF{barcode_round4}"
    assert result[0]["corrected_symbols"] == 1

    pdf = _matrix(PDF417)
    rows = barcode._pdf_rows(pdf)
    old, cluster = rows[0]["data"][0], rows[0]["cluster"]
    inverse = {(value, group): pattern for pattern, (value, group) in
               barcode.PDF417_PATTERNS.items()}
    replacement = inverse[((old + 1) % 929, cluster)] | 0x10000
    for bit in range(17):
        pdf[0][34 + bit] = bool(replacement & (1 << (16 - bit)))
    result = barcode.decode_pdf417(pdf)
    assert result[0]["text"] == "CSCTF{barcode_round4}"
    assert result[0]["corrected_symbols"] == 1


def test_datamatrix_144_short_blocks_deinterleave_in_standard_order():
    field = barcode._DM_FIELD

    def multiply(left, right):
        out = [0] * (len(left) + len(right) - 1)
        for i, a in enumerate(left):
            for j, b in enumerate(right):
                out[i + j] ^= field.mul(a, b)
        return out

    generator = [1]
    for index in range(62):
        generator = multiply(generator, [1, field.exp[field.base + index]])

    def encode(data):
        work = list(data) + [0] * 62
        for at in range(len(data)):
            factor = work[at]
            if factor:
                for offset, coefficient in enumerate(generator):
                    work[at + offset] ^= field.mul(factor, coefficient)
        return list(data) + work[-62:]

    lengths = [156] * 8 + [155] * 2
    blocks = [encode([(block * 37 + index * 11) & 0xFF for index in range(length)])
              for block, length in enumerate(lengths)]
    raw = []
    for column in range(max(lengths)):
        raw.extend(block[column] for block, length in zip(blocks, lengths) if column < length)
    for column in range(62):
        raw.extend(block[length + column] for block, length in zip(blocks, lengths))
    symbol = barcode._DM_SYMBOLS[(144, 144)]
    decoded = barcode._dm_deinterleave(raw, symbol)
    assert decoded is not None and decoded[1] == 0
    expected = []
    for column in range(max(lengths)):
        expected.extend(block[column] for block, length in zip(blocks, lengths) if column < length)
    assert decoded[0] == expected

def test_rotations_mirrors_polarity_and_ascii_cli(tmp_path, capsys):
    expected = b"CSCTF{barcode_round4}"
    for decoder, original in ((barcode.decode_datamatrix, _matrix(DM)),
                              (barcode.decode_aztec, _matrix(AZTEC)),
                              (barcode.decode_pdf417, _matrix(PDF417))):
        variants = [barcode._rotate(original), barcode._transpose(original),
                    [[not cell for cell in row] for row in original]]
        for variant in variants:
            assert decoder(variant)[0]["bytes"] == expected

    fixture = tmp_path / "datamatrix.txt"
    fixture.write_text(DM, encoding="ascii")
    assert qr_matrix.main([str(fixture), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["candidates"][0]["symbology"] == "datamatrix"
    assert report["candidates"][0]["bytes"] == expected.hex()


def test_triage_to_matrix_engine_to_flag_value_integration():
    routed = triage.suggest("misc", "Recover the damaged DataMatrix with Reed-Solomon")
    assert routed["engines"][0] == "solvers/toolkits/qr_matrix.py"
    result = barcode.decode_datamatrix(_matrix(DM))[0]
    assert result["text"] == "CSCTF{barcode_round4}"

    esolang = triage.suggest("programming", "Run this wrapping Hexagony program")
    assert esolang["engines"][0] == "solvers/warmups/esolang_tail.py"


def test_mode_decoders_and_fail_closed_corruption():
    # Data Matrix ASCII two-digit compaction and upper-shift.
    parsed = barcode._dm_payload([ord("A") + 1, 130 + 42, 235, ord("B") + 1, 129])
    assert parsed["bytes"] == b"A42\xc2"

    # PDF417 numeric compaction: base-900 value 112345 carries the mandatory leading sentinel 1.
    parsed = barcode._pdf_payload([4, 902, 124, 745])
    assert parsed["bytes"] == b"12345"

    corrupt = _matrix(DM)
    rng = random.Random(20261104)
    for _ in range(30):
        y, x = rng.randrange(1, 19), rng.randrange(1, 19)
        corrupt[y][x] ^= True
    assert barcode.decode_datamatrix(corrupt) == []


def test_seeded_mutation_fuzz_never_escapes_public_parser_boundaries():
    rng = random.Random(0xB4AC0DE)
    decoders = (barcode.decode_datamatrix, barcode.decode_aztec, barcode.decode_pdf417,
                barcode.decode_other)
    for _ in range(500):
        height, width = rng.randrange(1, 45), rng.randrange(1, 130)
        matrix = [[bool(rng.getrandbits(1)) for _ in range(width)] for _ in range(height)]
        for decoder in decoders:
            result = decoder(matrix)
            assert isinstance(result, list)
            assert len(result) <= 64
