"""Independent barcode wrapper vectors and fail-closed regression probes.

Oracle writers: python-qrcode 8.2 (https://github.com/lincolnloop/python-qrcode)
and pdf417gen 0.8.1 (https://github.com/ihabunek/pdf417-py). No engine encoder,
decoder result, or private engine table is used to construct expected symbols.
qr_decode declares no exception class: malformed file content must return a
normal empty result rather than leak a Pillow/stdlib exception. These regressions
also lock argument validation and the optional-backend contract.
"""
from __future__ import annotations

import io
import random

import pytest
import qrcode
from PIL import Image
from pdf417gen.codes import CODES

import pdf417_patterns
import qr_decode


def _oracle_image(payload):
    code = qrcode.QRCode(version=3, error_correction=qrcode.constants.ERROR_CORRECT_H,
                         box_size=5, border=4, mask_pattern=3)
    code.add_data(payload, optimize=0)
    code.make(fit=False)
    return code.make_image(fill_color="black", back_color="white").convert("RGB")


@pytest.fixture
def oracle_single(tmp_path):
    path = tmp_path / "oracle.png"
    _oracle_image(b"CSCTF{wrapper_vector}").save(path)
    return path


@pytest.fixture
def oracle_grid(tmp_path):
    texts = ["DECOY00", "CSCTF{grid_vector}", "DECOY10", "DECOY11"]
    images = [_oracle_image(text.encode("ascii")) for text in texts]
    width, height = images[0].size
    sheet = Image.new("RGB", (2 * width, 2 * height), "white")
    for i, image in enumerate(images):
        sheet.paste(image, ((i % 2) * width, (i // 2) * height))
    path = tmp_path / "grid.png"
    sheet.save(path)
    return path, texts


def test_pdf417_all_published_codeword_patterns_against_independent_library():
    # The engine stores the low 16 bits; ISO PDF417 codeword patterns always have
    # a leading bar, so the 17th bit is constant and recoverable. Cluster indices
    # 0/1/2 denote standard row clusters 0/3/6 in both representations.
    expected = {pattern & 0xffff: (value, cluster)
                for cluster, codewords in enumerate(CODES)
                for value, pattern in enumerate(codewords)}
    assert len(expected) == 2787
    assert pdf417_patterns.PDF417_PATTERNS == expected
    # Verify the reconstruction invariant from the independent writer as well.
    assert all(pattern & 0x10000 for cluster in CODES for pattern in cluster)


def test_decode_image_vector(oracle_single):
    assert qr_decode.decode_image(oracle_single) == ["CSCTF{wrapper_vector}"]


def test_decode_grid_vector(oracle_grid):
    path, texts = oracle_grid
    expected = [(i // 2, i % 2, text) for i, text in enumerate(texts)]
    assert qr_decode.decode_grid(path, 2, 2) == expected


def test_decode_grid_auto_vector(oracle_grid):
    path, texts = oracle_grid
    expected = [(i // 2, i % 2, text) for i, text in enumerate(texts)]
    assert qr_decode.decode_grid_auto(path) == expected


def test_decode_report_vectors(oracle_single, oracle_grid):
    single = qr_decode.decode(oracle_single)
    assert (single["mode"], single["symbol_count"], single["payloads"], single["flag_matches"]) == (
        "single", 1, ["CSCTF{wrapper_vector}"], ["CSCTF{wrapper_vector}"])
    path, texts = oracle_grid
    grid = qr_decode.decode(path, grid=(2, 2))
    assert (grid["mode"], grid["symbol_count"], grid["payloads"], grid["flag_matches"]) == (
        "grid 2x2", 4, texts, ["CSCTF{grid_vector}"])


def test_find_flag_literal_filter_contract():
    # An explicit list of expected substrings, independent of the engine regex.
    # The over-long body is one past the cap: the event profile's (events/csctf/event.toml [flag] body,
    # 1..256 since B-001a made ctf.flagfmt the single flag-format source), not CSCTF's old 120.
    payloads = ["junk", "prefix CSCTF{alpha} suffix", "CSCTF{alpha}", "CTF{beta}",
                "CSCTF{}", "CSCTF{" + "x" * 257 + "}", "CSCTF{gamma}CTF{delta}"]
    assert qr_decode.find_flag(payloads) == ["CSCTF{alpha}", "CTF{beta}", "CSCTF{gamma}", "CTF{delta}"]
    assert qr_decode.find_flag(payloads, r"CSCTF\{(?:alpha|gamma)\}") == ["CSCTF{alpha}", "CSCTF{gamma}"]


def _malformed_image_corpus():
    buffer = io.BytesIO()
    _oracle_image(b"CSCTF{mutation_seed}").save(buffer, format="PNG")
    seed = buffer.getvalue()
    rng = random.Random(0xBADC0DE)
    cases = {"empty": b"", "all_ff": b"\xff" * 256,
             "random_31": rng.randbytes(31), "random_257": rng.randbytes(257)}
    for size in (1, 7, 8, 16, 33, len(seed) // 2):
        cases[f"png_truncated_{size}"] = seed[:size]
    for offset in (0, 8, 12, 29):
        changed = bytearray(seed)
        changed[offset] ^= 0x80
        cases[f"png_bit_flip_{offset}"] = bytes(changed)
    return cases


def _file_fuzz_failures(tmp_path, parser):
    failures = []
    for name, raw in _malformed_image_corpus().items():
        path = tmp_path / (name + ".png")
        path.write_bytes(raw)
        try:
            result = parser(path)
        except Exception as exc:
            # Capturing is for a final assertion, never permission to swallow an
            # exception. Every specimen runs even when an earlier one fails.
            failures.append((name, type(exc).__name__, str(exc)))
        else:
            if not isinstance(result, (list, dict)):
                failures.append((name, "bad-result-type", type(result).__name__))
    return failures


def test_decode_image_file_fuzz_stays_closed(tmp_path):
    assert _file_fuzz_failures(tmp_path, qr_decode.decode_image) == []


def test_decode_grid_file_fuzz_stays_closed(tmp_path):
    assert _file_fuzz_failures(tmp_path, lambda p: qr_decode.decode_grid(p, 1, 1)) == []


def test_decode_grid_auto_file_fuzz_stays_closed(tmp_path):
    assert _file_fuzz_failures(tmp_path, qr_decode.decode_grid_auto) == []


def test_decode_report_file_fuzz_stays_closed(tmp_path):
    assert _file_fuzz_failures(tmp_path, qr_decode.decode) == []


def test_find_flag_deterministic_payload_fuzz():
    rng = random.Random(0xF1A6)
    corpus = ["", "\xff" * 128, "CSCTF{", "CSCTF{truncated", "CSCTF|bit_flip}"]
    corpus.extend(rng.randbytes(size).decode("latin1") for size in range(0, 129, 4))
    # None is treated as an empty payload by the API's explicit `p or ""` handling.
    corpus.append(None)
    for value in corpus:
        assert qr_decode.find_flag([value]) == []


def test_find_flag_bad_regex_stays_closed():
    assert qr_decode.find_flag(["CSCTF{vector}"], "[") == []


def test_decode_grid_zero_columns_stays_closed(oracle_single):
    assert qr_decode.decode_grid(oracle_single, 1, 0) == []


def test_decode_report_short_grid_stays_closed(oracle_single):
    assert qr_decode.decode(oracle_single, grid=(1,)) in (None, {}, [])


def test_decode_grid_without_backend_stays_closed(oracle_single, monkeypatch):
    monkeypatch.setattr(qr_decode, "_pyzbar", lambda: None)
    assert qr_decode.decode_grid(oracle_single, 1, 1) == []


@pytest.mark.parametrize("rows,cols", [(0, 1), (-1, 1), (1, -1), (1.5, 1), (1, None)])
def test_decode_grid_invalid_dimensions_stay_closed(oracle_single, rows, cols):
    assert qr_decode.decode_grid(oracle_single, rows, cols) == []
    assert qr_decode.decode(oracle_single, grid=(rows, cols)) == {}


@pytest.mark.parametrize("grid", [(), (1, 2, 3), 1, "2x2"])
def test_decode_report_invalid_grid_shape_stays_closed(oracle_single, grid):
    assert qr_decode.decode(oracle_single, grid=grid) == {}


@pytest.mark.parametrize("argv,expected", [(["--help"], 0), ([], 2),
    (["image.png", "--grid", "0x1"], 2), (["image.png", "--grid", "1"], 2),
    (["image.png", "--grid", "2xthree"], 2)])
def test_cli_returns_for_help_and_invalid_arguments(argv, expected):
    assert qr_decode._main(argv) == expected
