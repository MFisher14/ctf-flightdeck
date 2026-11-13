"""Independent vector locks and fail-closed checks for emulator-state inspection.

The fixtures below are written directly from the published SNES9x named-block,
VBA-M prefix, and Gens GSX layouts.  No encoder from the implementation under
test is used.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import random

import pytest

import ffgame_emulator_states as engine


def _snes9x_vector() -> tuple[bytes, int]:
    name = b"TOTALWAR.SFC\0"
    name_block = b"NAM:" + f"{len(name):06d}".encode("ascii") + b":" + name

    work_ram = bytearray(0x20000)
    relative = 0x4321
    flag = b"CSCTF{SNES9X_VECTOR}"
    work_ram[relative : relative + len(flag)] = flag
    # FreezeBlock's canonical writer uses six decimal digits at this size.
    ram_header = b"RAM:" + f"{len(work_ram):06d}".encode("ascii") + b":"
    raw = b"#!s9xsnp:0012\n" + name_block + ram_header + bytes(work_ram)
    return raw, len(b"#!s9xsnp:0012\n") + len(name_block) + len(ram_header) + relative


def _vba_vector() -> tuple[bytes, int]:
    identity = b"TOTALWARFARE" + b"TW01"
    trailer = b"\0VBA-M inert bytes\0CSCTF{VBA_VECTOR}\0"
    raw = (11).to_bytes(4, "little") + identity + (1).to_bytes(4, "little") + trailer
    return raw, raw.index(b"CSCTF{")


def _gens_vector(version: int) -> tuple[bytes, int]:
    published_size = {6: 0x22C68, 7: 0x3434E}[version]
    raw = bytearray(published_size)
    raw[:5] = b"GST\x40\xe0"
    raw[0x50] = version
    raw[0x51] = 0  # Gens' source-defined emulator identifier.
    flag_offset = 0x2478 + 0x222
    flag = b"CSCTF{GENS_M68K_VECTOR}"
    raw[flag_offset : flag_offset + len(flag)] = flag
    return bytes(raw), flag_offset


def _section(report: dict, name: str) -> dict:
    return next(row for row in report["sections"] if row["name"] == name)


def _returns_or_declared(call, value) -> None:
    try:
        result = call(value)
    except Exception as exc:  # Deliberately catches leaked implementation errors.
        assert type(exc) is engine.FFGameStateError
    else:
        assert isinstance(result, dict)


def test_snes9x_published_named_block_vector_and_gzip_oracle() -> None:
    raw, flag_offset = _snes9x_vector()
    wrapped = gzip.compress(raw, mtime=0)
    assert gzip.decompress(wrapped) == raw

    report = engine.inspect_state(wrapped)
    assert report["format"] == "snes9x_snapshot"
    assert report["version"] == 12
    assert report["compression"] == "gzip"
    assert report["sha256"] == hashlib.sha256(raw).hexdigest()
    assert [(row["name"], row["byte_size"], row["length_encoding"])
            for row in report["blocks"]] == [
        ("NAM", 13, "decimal_6"),
        ("RAM", 0x20000, "decimal_6"),
    ]
    assert report["blocks"][1]["published_size_matches"] is True
    assert report["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{SNES9X_VECTOR}"}
    ]


def test_vba_m_stable_prefix_vector_with_stdlib_gzip_oracle() -> None:
    raw, flag_offset = _vba_vector()
    wrapped = gzip.compress(raw, mtime=0)
    assert gzip.decompress(wrapped) == raw

    report = engine.parse_vba_gba(wrapped)
    assert report["format"] == "vba_gba_state"
    assert report["version"] == 11
    assert report["rom_identity_hex"] == raw[4:20].hex()
    assert report["rom_title"] == "TOTALWARFARE"
    assert report["game_code"] == "TW01"
    assert report["uses_bios"] is True
    assert report["compression"] == "gzip"
    assert [(row["name"], row["offset"], row["byte_size"])
            for row in report["sections"]] == [
        ("header", 0, 24),
        ("opaque_state_payload", 24, len(raw) - 24),
    ]
    assert report["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{VBA_VECTOR}"}
    ]


@pytest.mark.parametrize(("version", "extension", "extension_size"), [
    (6, "gens_v6_extension", 0x22C68 - 0x2247C),
    (7, "gens_v7_extension", 0x3434E - 0x2247C),
])
def test_gens_published_fixed_layout_vectors(
    version: int, extension: str, extension_size: int
) -> None:
    raw, flag_offset = _gens_vector(version)
    report = engine.inspect_state(raw)

    assert report["format"] == "gens_gsx_state"
    assert report["version"] == version
    assert report["emulator_id"] == 0
    assert report["expected_base_bytes"] == len(raw)
    assert report["sha256"] == hashlib.sha256(raw).hexdigest()
    assert (_section(report, "m68k_ram")["offset"],
            _section(report, "m68k_ram")["byte_size"]) == (0x2478, 0x10000)
    assert (_section(report, extension)["offset"],
            _section(report, extension)["byte_size"]) == (0x2247C, extension_size)
    assert report["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{GENS_M68K_VECTOR}"}
    ]


@pytest.mark.parametrize(("entrypoint", "valid", "flip_at"), [
    (engine.parse_snes9x, _snes9x_vector()[0], 0),
    (engine.parse_vba_gba, _vba_vector()[0], 0),
    (engine.parse_gens, _gens_vector(7)[0], 2),
    (engine.inspect_state, _snes9x_vector()[0], 0),
])
def test_every_public_parser_fails_closed_on_adversarial_bytes(
    monkeypatch: pytest.MonkeyPatch, entrypoint, valid: bytes, flip_at: int
) -> None:
    changed = bytearray(valid)
    changed[flip_at] ^= 0x80
    rng = random.Random(0x52334741)
    samples = [
        b"",
        rng.randbytes(79),
        b"\xff" * 79,
        valid[:-1],
        bytes(changed),
    ]
    for sample in samples:
        _returns_or_declared(entrypoint, sample)

    # Exercise the real limit branch without allocating a 16 MiB object.
    monkeypatch.setattr(engine, "MAX_INPUT", 64)
    _returns_or_declared(entrypoint, b"X" * 65)


def test_released_memoryviews_raise_only_the_declared_error() -> None:
    view = memoryview(b"inert")
    view.release()
    for entrypoint in (
        engine.parse_snes9x,
        engine.parse_vba_gba,
        engine.parse_gens,
        engine.inspect_state,
    ):
        with pytest.raises(engine.FFGameStateError) as caught:
            entrypoint(view)
        assert type(caught.value) is engine.FFGameStateError


def test_state_cli_is_guarded_and_emits_the_vector(tmp_path, capsys, monkeypatch) -> None:
    state, flag_offset = _gens_vector(6)
    artifact = tmp_path / "oracle.gs0"
    artifact.write_bytes(state)

    assert engine.main([str(artifact)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{GENS_M68K_VECTOR}"}
    ]
    assert engine.main([]) == 2
    capsys.readouterr()
    assert engine.main([str(tmp_path / "missing")]) == 2
    capsys.readouterr()

    def non_integer_system_exit(*_args, **_kwargs):
        raise SystemExit("not-an-integer")

    monkeypatch.setattr(engine.argparse.ArgumentParser, "parse_args", non_integer_system_exit)
    assert engine.main([]) == 2
