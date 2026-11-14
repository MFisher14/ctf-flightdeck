"""Round-5 DMRE/PDF417 variants and perspective/cylindrical sampling regressions."""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import qrcode
import zxingcpp
from PIL import Image, ImageDraw


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import matrix_barcodes as barcode  # noqa: E402
import qr_matrix  # noqa: E402
from ctf import triage  # noqa: E402


def _zx_image(content, fmt, **options):
    symbol = zxingcpp.create_barcode(content, fmt, **options)
    return zxingcpp.write_barcode_to_image(symbol, scale=1, add_quiet_zones=False)


def _zx_matrix(content, fmt, **options):
    image = _zx_image(content, fmt, **options)
    height, width = image.shape
    pixels = memoryview(image).cast("B")
    return [[pixels[y * width + x] < 128 for x in range(width)] for y in range(height)]


def _logical_rows(matrix):
    rows = []
    for row in matrix:
        if not rows or row != rows[-1]:
            rows.append(row)
    return rows


def test_all_18_dmre_versions_agree_with_local_zxing_reference():
    expected = "CSCTF{dmre5}"
    observed = set()
    for version in range(31, 49):
        matrix = _zx_matrix(expected, zxingcpp.DataMatrix, version=version)
        result = barcode.decode_datamatrix(matrix)
        assert result and result[0]["text"] == expected
        assert result[0]["corrected_symbols"] == 0
        observed.add((len(matrix), len(matrix[0])))
    assert len(observed) == 18
    assert {(8, 48), (12, 88), (20, 36), (26, 64)} <= observed

    # Independent decode by the installed reference engine (scaled to exercise its image reader).
    symbol = zxingcpp.create_barcode(expected, zxingcpp.DataMatrix, version=31)
    image = zxingcpp.write_barcode_to_image(symbol, scale=4, add_quiet_zones=True)
    reference = zxingcpp.read_barcode(image, formats=zxingcpp.DataMatrix, is_pure=True)
    assert reference is not None and reference.bytes == expected.encode()


def test_compact_pdf417_and_all_34_micropdf417_variants_crosscheck():
    expected = "CSCTF{compact5}"
    for columns in range(1, 7):
        matrix = _zx_matrix(expected, zxingcpp.CompactPDF417, columns=columns, ec_level=2)
        result = barcode.decode_pdf417(matrix)
        assert result and result[0]["symbology"] == "compact_pdf417"
        assert result[0]["text"] == expected and result[0]["columns"] == columns

    seen = {}
    # The reference writer chooses the smallest standardized variant that fits.  Sweeping bounded
    # payload lengths/preferences reaches each of the 34 finite variants; it is not a network or
    # candidate-value sweep.
    for preferred_columns in range(1, 5):
        for length in range(1, 251):
            try:
                matrix = _zx_matrix("A" * length, zxingcpp.MicroPDF417,
                                    columns=preferred_columns)
            except ValueError:
                continue
            logical = _logical_rows(matrix)
            columns = barcode._MICRO_WIDTH_COLUMNS[len(matrix[0])]
            key = (columns, len(logical))
            if key in seen:
                continue
            result = barcode.decode_micropdf417(matrix)
            assert result and result[0]["text"] == "A" * length
            assert result[0]["corrected_symbols"] == 0
            seen[key] = result[0]["ecc_codewords"]
    assert set(seen) == set(barcode._MICRO_VARIANTS)
    assert len(seen) == 34

    symbol = zxingcpp.create_barcode(expected, zxingcpp.MicroPDF417, columns=4)
    image = zxingcpp.write_barcode_to_image(symbol, scale=4, add_quiet_zones=True)
    reference = zxingcpp.read_barcode(image, formats=zxingcpp.MicroPDF417, is_pure=True)
    assert reference is not None and reference.bytes == expected.encode()


def _render_warp(matrix, size, corners, curvature, path):
    image = Image.new("L", size, 255)
    draw = ImageDraw.Draw(image)
    coefficients = qr_matrix._homography(corners)
    height, width = len(matrix), len(matrix[0])
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if not dark:
                continue
            polygon = []
            for px, py in ((x, y), (x + 1, y), (x + 1, y + 1), (x, y + 1)):
                u = qr_matrix._cylindrical_u(px / width, curvature)
                polygon.append(qr_matrix._project_point(coefficients, u, py / height))
            draw.polygon(polygon, fill=0)
    image.save(path)


def test_projective_and_cylindrical_raster_sampling_cli(tmp_path, capsys):
    code = qrcode.QRCode(version=4, error_correction=qrcode.constants.ERROR_CORRECT_H,
                         box_size=1, border=0)
    code.add_data("CSCTF{curved_projective5}")
    code.make(fit=False)
    matrix = code.get_matrix()
    corners = ((25, 20), (292, 42), (265, 290), (40, 270))
    fixture = tmp_path / "curved.png"
    _render_warp(matrix, (320, 320), corners, 0.7, fixture)

    result = qr_matrix.decode_path(fixture, dimensions=(len(matrix), len(matrix)),
                                   corners=corners, curvatures=(0.7,))
    assert result and result[0]["text"] == "CSCTF{curved_projective5}"

    corner_arg = ";".join(f"{x},{y}" for x, y in corners)
    assert qr_matrix.main([str(fixture), "--dimensions", f"{len(matrix)}x{len(matrix)}",
                           "--corners", corner_arg, "--curve", "0.7", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["candidates"][0]["text"] == "CSCTF{curved_projective5}"

    # A wide DMRE symbol follows the same sampler and is still accepted only after ECC200 RS.
    dmre = _zx_matrix("CSCTF{warped_dmre}", zxingcpp.DataMatrix, version=32)
    dm_corners = ((18, 18), (497, 31), (488, 105), (24, 119))
    dm_fixture = tmp_path / "dmre-perspective.png"
    _render_warp(dmre, (520, 140), dm_corners, 0.0, dm_fixture)
    result = qr_matrix.decode_path(dm_fixture, dimensions=(64, 8), corners=dm_corners,
                                   curvatures=(0.0,))
    assert result and result[0]["text"] == "CSCTF{warped_dmre}"


def test_wrong_value_adversary_and_triage_routing():
    micro = _logical_rows(_zx_matrix("CSCTF{verified_micro}", zxingcpp.MicroPDF417, columns=4))
    # One RAP error is explicitly measured; two errors in one RAP exceed the structural allowance,
    # so even otherwise valid data/RS must not leak a payload.
    one = [row[:] for row in micro]
    one[0][0] ^= True
    assert barcode.decode_micropdf417(one)[0]["text"] == "CSCTF{verified_micro}"
    one[0][1] ^= True
    assert barcode.decode_micropdf417(one) == []

    routed = triage.suggest("stego", "curved perspective DMRE MicroPDF417 barcode image")
    assert "solvers/toolkits/qr_matrix.py" in routed["engines"]


def test_5000_seeded_mutations_per_new_parser_boundary():
    rng = random.Random(0xB4_2026_05)
    base = _logical_rows(_zx_matrix("FUZZ", zxingcpp.MicroPDF417, columns=4))
    variant = barcode._MICRO_VARIANTS[(4, len(base))]
    for _ in range(5_000):
        mutated = [row[:] for row in base]
        for __ in range(rng.randrange(1, 5)):
            y, x = rng.randrange(len(mutated)), rng.randrange(len(mutated[0]))
            mutated[y][x] ^= True
        result = barcode._micro_rows(mutated, variant)
        assert result is None or (len(result) == 3 and len(result[0]) == 4 * len(base))

    for _ in range(5_000):
        width = rng.randrange(1, 140)
        rows = [[bool(rng.getrandbits(1)) for __ in range(width)]
                for __ in range(rng.randrange(1, 12))]
        result = barcode._pdf_rows(rows)
        assert result is None or isinstance(result, list)

    for _ in range(5_000):
        raw_dimensions = f"{rng.randrange(-50, 900)}x{rng.randrange(-50, 300)}"
        try:
            parsed = qr_matrix.parse_dimensions(raw_dimensions)
            assert 1 <= parsed[0] <= 720 and 1 <= parsed[1] <= 180
        except ValueError:
            pass
        raw_corners = ";".join(f"{rng.randrange(-5, 20)},{rng.randrange(-5, 20)}"
                               for __ in range(rng.randrange(1, 6)))
        try:
            parsed = qr_matrix.parse_corners(raw_corners)
            assert len(parsed) == 4
        except ValueError:
            pass
