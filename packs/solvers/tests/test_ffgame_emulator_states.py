"""Independent framing vectors for ``ffgame_emulator_states``.

Fixtures are encoded directly from the upstream layouts rather than by engine
helpers: SNES9x's textual block grammar, VBA-M's gzip + little-endian prefix,
and Gens' published fixed offsets.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import random
import struct

import pytest

import ffgame_emulator_states as states


def _snes_block(tag: bytes, payload: bytes) -> bytes:
    """Independent transcription of ``TAG:%06d:payload``."""
    assert len(tag) == 3 and len(payload) <= 999_999
    return tag + b":" + f"{len(payload):06d}".encode("ascii") + b":" + payload


def _snes_fixture() -> tuple[bytes, int]:
    name = _snes_block(b"NAM", b"Removed\0")
    ram = bytearray(0x20000)
    relative = 0x1234
    ram[relative : relative + len(b"CSCTF{snes_wram}")] = b"CSCTF{snes_wram}"
    framed = b"#!s9xsnp:0012\n" + name + _snes_block(b"RAM", bytes(ram))
    absolute = 14 + len(name) + 11 + relative
    return framed, absolute


def _vba_fixture() -> tuple[bytes, int]:
    identity = b"TOTALWARFARE" + b"CTF1"  # GBA title[12] + game code[4]
    opaque = b"\x00runtime-memory\x00CSCTF{vba_gba_state}\x00"
    plain = struct.pack("<I", 11) + identity + struct.pack("<I", 0) + opaque
    return plain, plain.index(b"CSCTF{")


def _gens_fixture(version: int = 7, suffix: int = 0) -> tuple[bytes, int]:
    size = {6: 0x22C68, 7: 0x3434E}[version]
    data = bytearray(size + suffix)
    data[:5] = b"GST\x40\xe0"
    data[0x50] = version
    data[0x51] = 0
    data[0x474 + 0x40 : 0x474 + 0x40 + len(b"z80-debug-buffer")] = b"z80-debug-buffer"
    flag_offset = 0x2478 + 0x321
    data[flag_offset : flag_offset + len(b"CSCTF{gens_68k_ram}")] = b"CSCTF{gens_68k_ram}"
    return bytes(data), flag_offset


def _only_declared(call, value) -> None:
    try:
        call(value)
    except Exception as exc:  # contract assertion intentionally catches everything
        assert type(exc) is states.FFGameStateError


def test_snes9x_raw_vector_from_published_block_grammar() -> None:
    fixture, flag_offset = _snes_fixture()
    report = states.parse_snes9x(fixture)

    assert report["format"] == "snes9x_snapshot"
    assert report["version"] == 12
    assert report["compression"] == "none"
    assert report["decompressed_size"] == len(fixture)
    assert report["sha256"] == hashlib.sha256(fixture).hexdigest()
    assert report["block_count"] == 2
    assert [(b["name"], b["byte_size"]) for b in report["blocks"]] == [
        ("NAM", 8),
        ("RAM", 0x20000),
    ]
    assert report["blocks"][1]["published_size_matches"] is True
    assert report["flags"] == [{"offset": flag_offset, "value": "CSCTF{snes_wram}"}]
    assert report["blocks"][1]["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{snes_wram}"}
    ]


def test_snes9x_gzip_vector_uses_stdlib_oracle() -> None:
    fixture, _ = _snes_fixture()
    wrapped = gzip.compress(fixture, mtime=0)
    assert gzip.decompress(wrapped) == fixture
    report = states.inspect_state(wrapped)
    assert report["format"] == "snes9x_snapshot"
    assert report["compression"] == "gzip"
    assert report["file_size"] == len(wrapped)


def test_snes9x_binary_u32_length_escape_from_upstream_source() -> None:
    payload = b"\0" * 1_000_000
    # Upstream writes ``TAG:------:`` then overwrites header bytes 6..9.
    header = b"EXT:--" + len(payload).to_bytes(4, "big") + b":"
    fixture = b"#!s9xsnp:0012\n" + header + payload
    report = states.parse_snes9x(fixture)
    assert report["blocks"][0]["name"] == "EXT"
    assert report["blocks"][0]["byte_size"] == 1_000_000
    assert report["blocks"][0]["length_encoding"] == "binary_u32_be"


@pytest.mark.parametrize(
    "fixture",
    [
        b"",
        b"\xff" * 64,
        bytes(random.Random(61850).randrange(256) for _ in range(127)),
        b"#!s9xsnp:",
        b"#!s9xsnp:0012\nRAM:000010:tiny",
        b"#!s9xsnp:0012\nRAM:ABCDEF:payload",
        b"#!s9xsnp:0012\nRAM:000000:",
        gzip.compress(b"#!s9xsnp:0012\nRAM:000010:tiny", mtime=0)[:-3],
    ],
)
def test_snes9x_malformed_inputs_raise_only_declared_error(fixture: bytes) -> None:
    with pytest.raises(states.FFGameStateError):
        states.parse_snes9x(fixture)


def test_snes9x_single_bit_magic_mutation_fails_closed() -> None:
    fixture, _ = _snes_fixture()
    changed = bytes([fixture[0] ^ 1]) + fixture[1:]
    with pytest.raises(states.FFGameStateError):
        states.parse_snes9x(changed)


def test_vba_gba_gzip_prefix_vector() -> None:
    plain, flag_offset = _vba_fixture()
    wrapped = gzip.compress(plain, mtime=0)
    assert gzip.decompress(wrapped) == plain

    report = states.parse_vba_gba(wrapped)
    assert report["format"] == "vba_gba_state"
    assert report["version"] == 11
    assert report["rom_title"] == "TOTALWARFARE"
    assert report["game_code"] == "CTF1"
    assert report["uses_bios"] is False
    assert report["compression"] == "gzip"
    assert report["sections"][0]["offset"] == 0
    assert report["sections"][0]["byte_size"] == 24
    assert report["sections"][1]["offset"] == 24
    assert report["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{vba_gba_state}"}
    ]
    assert report["documented_embedded_region_sizes"]["external_work_ram"] == 0x40000
    assert report["documented_embedded_region_sizes"]["internal_work_ram"] == 0x8000


def test_vba_gba_raw_requires_explicit_kind() -> None:
    plain, _ = _vba_fixture()
    explicit = states.parse_vba_gba(plain)
    dispatched = states.inspect_state(plain, "vba-gba")
    assert explicit["compression"] == "none"
    assert dispatched["format"] == "vba_gba_state"
    assert dispatched["rom_identity_hex"] == plain[4:20].hex()
    with pytest.raises(states.FFGameStateError):
        states.inspect_state(plain)


def test_plausible_vba_prefix_is_not_auto_detected() -> None:
    plausible = struct.pack("<I", 11) + b"RANDOMPREFIX1234" + struct.pack("<I", 0)
    assert len(plausible) == 24
    assert states.parse_vba_gba(plausible)["version"] == 11
    with pytest.raises(states.FFGameStateError):
        states.inspect_state(plausible)

    wrapped = gzip.compress(plausible, mtime=0)
    assert states.inspect_state(wrapped, "vba-gba")["compression"] == "gzip"
    with pytest.raises(states.FFGameStateError):
        states.inspect_state(wrapped)


@pytest.mark.parametrize(
    "fixture",
    [
        b"",
        b"\xff" * 24,
        struct.pack("<I", 12) + b"A" * 16 + struct.pack("<I", 0),
        struct.pack("<I", 11) + b"A" * 16 + struct.pack("<I", 2),
        gzip.compress(b"short", mtime=0)[:-2],
        gzip.compress(b"one", mtime=0) + gzip.compress(b"two", mtime=0),
    ],
)
def test_vba_malformed_inputs_raise_only_declared_error(fixture: bytes) -> None:
    with pytest.raises(states.FFGameStateError):
        states.parse_vba_gba(fixture)


def test_gens_v7_vector_matches_upstream_fixed_offsets() -> None:
    fixture, flag_offset = _gens_fixture()
    report = states.parse_gens(fixture)

    assert report["format"] == "gens_gsx_state"
    assert report["version"] == 7
    assert report["emulator_id"] == 0
    assert report["expected_base_bytes"] == 0x3434E
    assert report["platform"] == "mega_drive"
    sections = {row["name"]: row for row in report["sections"]}
    assert (sections["m68k_registers"]["offset"], sections["m68k_registers"]["byte_size"]) == (
        0x80,
        0x5A,
    )
    assert (sections["vdp_registers"]["offset"], sections["vdp_registers"]["byte_size"]) == (
        0xFA,
        0x18,
    )
    assert (sections["ym2612_registers"]["offset"], sections["ym2612_registers"]["byte_size"]) == (
        0x1E4,
        0x200,
    )
    assert (sections["z80_registers"]["offset"], sections["z80_registers"]["byte_size"]) == (
        0x404,
        0x3C,
    )
    assert (sections["z80_ram"]["offset"], sections["z80_ram"]["byte_size"]) == (
        0x474,
        0x2000,
    )
    assert (sections["m68k_ram"]["offset"], sections["m68k_ram"]["byte_size"]) == (
        0x2478,
        0x10000,
    )
    assert (sections["vram"]["offset"], sections["vram"]["byte_size"]) == (
        0x12478,
        0x10000,
    )
    assert sections["gens_v7_extension"]["offset"] == 0x2247C
    assert sections["gens_v7_extension"]["byte_size"] == 0x11ED2
    assert report["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{gens_68k_ram}"}
    ]
    assert sections["m68k_ram"]["flags"] == [
        {"offset": flag_offset, "value": "CSCTF{gens_68k_ram}"}
    ]


def test_gens_v6_and_32x_suffix_vectors() -> None:
    v6, _ = _gens_fixture(6)
    v6_report = states.inspect_state(v6)
    assert v6_report["version"] == 6
    assert v6_report["expected_base_bytes"] == 0x22C68
    assert v6_report["sections"][-1]["name"] == "gens_v6_extension"
    assert v6_report["sections"][-1]["byte_size"] == 0x7EC

    x32, _ = _gens_fixture(7, 0x849BF)
    x32_report = states.parse_gens(x32)
    assert x32_report["platform"] == "32x_candidate"
    assert x32_report["suffix_bytes"] == 0x849BF
    assert x32_report["sections"][-1]["name"] == "platform_suffix"


@pytest.mark.parametrize(
    "fixture",
    [
        b"",
        b"GST\x40\xe0",
        b"GST\x40\xe0" + b"\0" * 0x4B + b"\x07",
        b"BAD\x40\xe0" + b"\0" * 0x34349,
        (b"GST\x40\xe0" + b"\0" * 0x4B + b"\x05" + b"\0" * (0x3434E - 0x51)),
    ],
)
def test_gens_malformed_inputs_raise_only_declared_error(fixture: bytes) -> None:
    with pytest.raises(states.FFGameStateError):
        states.parse_gens(fixture)


def test_gens_truncated_valid_magic_and_bit_flip_fail_closed() -> None:
    fixture, _ = _gens_fixture()
    with pytest.raises(states.FFGameStateError):
        states.parse_gens(fixture[:-1])
    changed = bytearray(fixture)
    changed[2] ^= 1
    with pytest.raises(states.FFGameStateError):
        states.parse_gens(bytes(changed))


@pytest.mark.parametrize(
    "parser",
    [states.parse_snes9x, states.parse_vba_gba, states.parse_gens, states.inspect_state],
)
def test_public_entrypoints_fail_closed_on_nonbytes_random_and_oversized(parser) -> None:
    samples = [
        None,
        7,
        "not bytes",
        bytes(random.Random(2026).randrange(256) for _ in range(257)),
        b"\xff" * 257,
        b"\0" * (16 * 1024 * 1024 + 1),
    ]
    for sample in samples:
        _only_declared(parser, sample)


def test_auto_dispatch_rejects_gzip_wrapped_gens_instead_of_inventing_support() -> None:
    fixture, _ = _gens_fixture()
    with pytest.raises(states.FFGameStateError):
        states.inspect_state(gzip.compress(fixture, mtime=0))


def test_cli_is_guarded_and_prints_json(tmp_path, capsys) -> None:
    fixture, flag_offset = _gens_fixture()
    path = tmp_path / "state.gs0"
    path.write_bytes(fixture)
    assert states.main([str(path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["flags"][0]["offset"] == flag_offset

    assert states.main(["--definitely-invalid"]) == 2
    assert states.main([str(tmp_path / "missing.gs0")]) == 2


def test_unknown_kind_and_truncated_gzip_use_declared_error() -> None:
    with pytest.raises(states.FFGameStateError):
        states.inspect_state(b"data", "unknown")
    with pytest.raises(states.FFGameStateError):
        states.inspect_state(b"\x1f\x8b\x08\x00")


def test_gzip_expansion_is_bounded() -> None:
    oversized_plaintext = b"A" * (32 * 1024 * 1024 + 1)
    wrapped = gzip.compress(oversized_plaintext, compresslevel=1, mtime=0)
    assert len(wrapped) < 16 * 1024 * 1024
    with pytest.raises(states.FFGameStateError):
        states.parse_snes9x(wrapped)
