"""Synthetic coverage for carve_stego's nonstandard spatial LSB modes."""
from __future__ import annotations

import sys
import struct
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers/toolkits"))
import carve_stego as C  # noqa: E402


PAYLOAD = b"deep spatial stego payload works\x00"


def _bits(data: bytes) -> list[int]:
    return [(byte >> (7 - bit)) & 1 for byte in data for bit in range(8)]


def _gray_png(width: int, height: int, samples: bytes) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    raw = b"".join(b"\0" + samples[y * width:(y + 1) * width] for y in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)
    return C.PNG_SIG + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def _gray_carrier(order: str, width: int = 32, height: int = 16) -> dict:
    body = bytearray([0x80] * (width * height))
    for pixel, bit in zip(C._pixel_order(width, height, order), _bits(PAYLOAD)):
        body[pixel] = (body[pixel] & 0xFE) | bit
    return {"width": width, "height": height, "mode": "L", "channels": 1, "data": bytes(body)}


def test_snake_and_column_orders_round_trip_and_auto_judge():
    for order in ("snake", "column", "column_snake"):
        px = _gray_carrier(order)
        assert C.lsb_extract(px, "L", 0, order, True).startswith(PAYLOAD)
        if order != "column":  # ordinary lsb_scan already names column-major as historical "yx"
            hits = C.lsb_deep_scan(px)
            assert any(hit["data"].startswith(PAYLOAD[:-1]) and order in hit["method"] for hit in hits)


def test_passphrase_and_integer_seed_permutations_are_exact_and_opt_in():
    width, height = 32, 16
    for kwargs in ({"passphrase": "challenge supplied phrase"}, {"seed": 0xC5C7F}):
        body = bytearray([0xA0] * (width * height))
        order = C.pixel_permutation(width * height, **kwargs)
        for pixel, bit in zip(order, _bits(PAYLOAD)):
            body[pixel] = (body[pixel] & 0xFE) | bit
        px = {"width": width, "height": height, "mode": "L", "channels": 1, "data": bytes(body)}
        assert C.permuted_lsb_extract(px, "L", **kwargs).startswith(PAYLOAD)
        scan_args = {"passphrases": [kwargs["passphrase"]]} if "passphrase" in kwargs else {"seeds": [kwargs["seed"]]}
        hits = C.lsb_deep_scan(px, include_unkeyed=False, **scan_args)
        assert len(hits) == 1
        assert hits[0]["data"] == PAYLOAD[:-1]
        assert "permutation" in hits[0]["method"]
    # A wrong explicit key produces no judged candidate; there is no key-generation API.
    assert C.lsb_deep_scan(px, passphrases=["wrong"], include_unkeyed=False) == []


def test_report_wires_an_explicit_passphrase_without_a_key_sweep():
    width, height, key = 32, 16, "one supplied key"
    body = bytearray([0xA0] * (width * height))
    for pixel, bit in zip(C.pixel_permutation(width * height, passphrase=key), _bits(PAYLOAD)):
        body[pixel] = (body[pixel] & 0xFE) | bit
    report = C.report({"keyed.png": _gray_png(width, height, bytes(body))}, lsb_passphrases=[key])
    hits = [finding for finding in report[0]["findings"] if "permutation" in finding["method"]]
    assert len(hits) == 1 and hits[0]["data"] == PAYLOAD[:-1]


def test_cross_plane_xor_is_auto_judged():
    bits = _bits(PAYLOAD)
    body = bytes((bit << 1) for bit in bits) + bytes(512 - len(bits))
    px = {"width": 32, "height": 16, "mode": "L", "channels": 1, "data": body}
    assert C.cross_plane_xor_extract(px, "L", (0, 1)).startswith(PAYLOAD)
    hits = C.lsb_deep_scan(px)
    assert any("planes 0 xor 1" in hit["method"] and hit["data"].startswith(PAYLOAD[:-1]) for hit in hits)


def test_interchannel_arithmetic_and_adjacent_parity():
    hidden = _bits(PAYLOAD)
    # Individual R/G LSB streams are not the payload; R xor G is.
    rgb = bytearray()
    for index in range(512):
        rb = index & 1
        wanted = hidden[index] if index < len(hidden) else 0
        gb = rb ^ wanted
        rgb += bytes((0x80 | rb, 0x40 | gb, 0x20 | ((index // 3) & 1)))
    px = {"width": 32, "height": 16, "mode": "RGB", "channels": 3, "data": bytes(rgb)}
    assert C.channel_arithmetic_extract(px, "R", "G", "xor").startswith(PAYLOAD)
    hits = C.lsb_deep_scan(px)
    assert any("R xor G" in hit["method"] and hit["data"].startswith(PAYLOAD[:-1]) for hit in hits)

    # Pair sums carry one bit; neither member stream does.
    gray = bytearray()
    for index in range(512):
        wanted = hidden[index] if index < len(hidden) else 0
        first = index & 1
        second = first ^ wanted
        gray += bytes((0x80 | first, 0x40 | second))
    parity_px = {"width": 32, "height": 32, "mode": "L", "channels": 1, "data": bytes(gray)}
    assert C.adjacent_pixel_parity_extract(parity_px, "L").startswith(PAYLOAD)
    parity_hits = C.lsb_deep_scan(parity_px)
    assert any("adjacent parity" in hit["method"] and hit["data"].startswith(PAYLOAD[:-1])
               for hit in parity_hits)


def test_bounds_and_guarded_cli(capsys):
    try:
        C.pixel_permutation(C.MAX_PERMUTED_PIXELS + 1, seed=1)
    except ValueError:
        pass
    else:
        raise AssertionError("permutation allocation cap was not enforced")
    assert C.main(["--lsb-seed", "not-an-integer"]) == 2
    assert "carve_stego.py:" in capsys.readouterr().err

