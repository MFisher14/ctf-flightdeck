from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes  # noqa: E402


def test_payload_build_round_trip_unpacking_and_absolute_offsets() -> None:
    build = PayloadBuild(
        b"AA\x78\x56\x34\x12ZZ",
        {"word": 2, "end": 8},
        {"word": 4},
        architecture="fixture",
        strategy="contract-test",
        base_address=0x400000,
        metadata={"purpose": "inert"},
    )
    payload, placements = build
    assert payload == build.payload
    assert dict(placements) == {"end": 8, "word": 2}
    assert build.slice("word") == bytes.fromhex("78563412")
    assert dict(build.absolute_placements()) == {"end": 0x400008, "word": 0x400002}
    assert build.as_dict()["payload_hex"] == payload.hex()


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"payload": bytearray(b"x"), "placements": {}}, "immutable bytes"),
        ({"payload": b"x", "placements": {"past": 2}}, "outside"),
        ({"payload": b"x", "placements": {"x": 0}, "widths": {"x": 2}}, "overruns"),
        ({"payload": b"x", "placements": {}, "widths": {"x": 1}}, "matching"),
    ],
)
def test_payload_build_rejects_invalid_contracts(kwargs, message) -> None:
    with pytest.raises(BuildError, match=message):
        PayloadBuild(**kwargs)


def test_integer_and_bad_byte_validation() -> None:
    assert ensure_uint(0xFFFFFFFF, 32, name="address") == 0xFFFFFFFF
    with pytest.raises(BuildError, match="fit"):
        ensure_uint(1 << 32, 32, name="address")
    assert reject_bad_bytes(b"ABC", [0, 10]) == (0, 10)
    with pytest.raises(BuildError, match="0x41"):
        reject_bad_bytes(b"ABC", [0x41])
