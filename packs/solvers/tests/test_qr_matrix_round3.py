"""Synthetic QR matrices for the dependency-free decoder and fast-path fallback."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import qrcode


REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import qr_matrix as qr  # noqa: E402
import qr_decode  # noqa: E402


def _make(payload="CSCTF{matrix_round3}", version=5, ecl=qrcode.constants.ERROR_CORRECT_H):
    code = qrcode.QRCode(version=version, error_correction=ecl, box_size=1, border=0)
    code.add_data(payload)
    code.make(fit=False)
    return code.get_matrix()


def test_all_geometric_transforms_and_polarity_decode_identically():
    matrix = _make()
    variants = [
        matrix,
        qr._rotate(matrix),
        qr._rotate(qr._rotate(qr._rotate(matrix))),
        qr._transpose(matrix),
        [[not cell for cell in row] for row in qr._rotate(qr._transpose(matrix))],
    ]
    for variant in variants:
        result = qr.decode_matrix(variant)
        assert result and result[0]["text"] == "CSCTF{matrix_round3}"
        assert result[0]["format_distance"] == 0


def test_reed_solomon_repairs_errors_and_format_search_exceeds_bch_radius():
    matrix = _make("RS repair across interleaved QR blocks", version=7)
    functions = qr._function_modules(7)
    data_cells = [(y, x) for y in range(len(matrix)) for x in range(len(matrix)) if not functions[y][x]]
    damaged = [row[:] for row in matrix]
    for y, x in data_cells[::max(1, len(data_cells) // 10)][:10]:
        damaged[y][x] = not damaged[y][x]
    result = qr.decode_matrix(damaged)
    assert result and result[0]["text"] == "RS repair across interleaved QR blocks"
    assert result[0]["corrected_symbols"] >= 1

    # Four format-bit errors exceed BCH's nominal correction radius. The engine tries every
    # mask/ECL pair, but still accepts only a zero-syndrome RS/payload result.
    format_damaged = [row[:] for row in matrix]
    for x, y in [(8, 0), (8, 1), (8, 2), (8, 3)]:
        format_damaged[y][x] = not format_damaged[y][x]
    result = qr.decode_matrix(format_damaged)
    assert result and result[0]["text"] == "RS repair across interleaved QR blocks"
    assert result[0]["format_distance"] == 4


def test_rs_erasure_api_corrects_beyond_plain_error_budget():
    matrix = _make("HELLO", version=1, ecl=qrcode.constants.ERROR_CORRECT_L)
    _, ecl, mask = qr._format_candidates(matrix)[0]
    raw = qr._extract(matrix, 1, mask)
    corrupted = bytearray(raw)
    positions = [0, 3, 5, 8]
    for position in positions:
        corrupted[position] ^= 0x7B
    fixed = qr.rs_correct(bytes(corrupted), qr.ECC_PER_BLOCK[ecl][1], positions)
    assert fixed == (raw, len(positions))


def test_ascii_and_raster_inputs_and_qr_decode_fallback(tmp_path, monkeypatch):
    matrix = _make("CSCTF{ascii_and_raster}", version=4, ecl=qrcode.constants.ERROR_CORRECT_Q)
    ascii_path = tmp_path / "qr.txt"
    ascii_path.write_text("\n".join("".join("1" if cell else "0" for cell in row) for row in matrix),
                          encoding="utf-8")
    assert qr.decode_path(ascii_path)[0]["text"] == "CSCTF{ascii_and_raster}"

    image_path = tmp_path / "qr.png"
    code = qrcode.QRCode(version=4, error_correction=qrcode.constants.ERROR_CORRECT_Q,
                         box_size=5, border=4)
    code.add_data("CSCTF{ascii_and_raster}")
    code.make(fit=False)
    code.make_image().save(image_path)
    assert qr.decode_path(image_path)[0]["text"] == "CSCTF{ascii_and_raster}"

    monkeypatch.setattr(qr_decode, "_pyzbar", lambda: None)
    monkeypatch.setattr(qr_decode.shutil, "which", lambda _name: None)
    assert qr_decode.decode_image(image_path) == ["CSCTF{ascii_and_raster}"]


def test_non_qr_structural_recognizer_does_not_invent_payload(tmp_path):
    side = 12
    matrix = [[False] * side for _ in range(side)]
    for y in range(side):
        matrix[y][0] = True
        matrix[y][side - 1] = y % 2 == 1
    for x in range(side):
        matrix[side - 1][x] = True
        matrix[0][x] = x % 2 == 0
    result = qr.recognize_other(matrix)
    assert result[0]["symbology"] == "datamatrix"
    assert result[0]["payload"] is None
    assert "validation failed" in result[0]["status"]

    start, stop = "11111111010101000", "111111101000101001"
    pdf = [[cell == "1" for cell in start + "01010101010101010" + stop] for _ in range(6)]
    result = qr.recognize_other(pdf)
    assert result[0]["symbology"] == "pdf417"
    assert result[0]["payload"] is None

    # The file/CLI path routes a rectangular ASCII symbol too; it never invents a payload.
    routed = tmp_path / "pdf417.txt"
    routed.write_text("\n".join("".join("1" if cell else "0" for cell in row) for row in pdf),
                      encoding="utf-8")
    decoded = qr.decode_path(routed)
    assert decoded[0]["symbology"] == "pdf417"
    assert decoded[0]["payload"] is None


def test_guarded_cli_and_garbage(tmp_path, capsys):
    fixture = tmp_path / "qr.txt"
    matrix = _make("CLI")
    fixture.write_text("\n".join("".join("#" if cell else "." for cell in row) for row in matrix),
                       encoding="utf-8")
    assert qr.main([str(fixture), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["candidates"][0]["text"] == "CLI"

    bad = tmp_path / "bad.txt"
    bad.write_text("not a matrix", encoding="utf-8")
    assert qr.main([str(bad)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("qr_matrix: ")
    assert "Traceback" not in captured.err

