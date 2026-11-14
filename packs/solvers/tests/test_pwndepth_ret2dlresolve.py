"""Independent ABI-vector tests for pwndepth_ret2dlresolve."""
from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import struct

import pytest

import pwndepth_ret2dlresolve as engine


def _phdr(ptype: int, flags: int, offset: int, vaddr: int, filesz: int, memsz: int, align: int) -> bytes:
    # System V ELF64 program-header layout, encoded independently of the engine.
    return struct.pack("<IIQQQQQQ", ptype, flags, offset, vaddr, vaddr, filesz, memsz, align)


def _elf(*, now: bool = False, etype: int = 2, cet: int = 0) -> bytes:
    """Hand-encode a stripped dynamic ELF; no engine serializer is used."""

    tags = [
        (3, 0x404100),       # DT_PLTGOT
        (5, 0x404200),       # DT_STRTAB
        (6, 0x404240),       # DT_SYMTAB
        (9, 24),             # DT_RELAENT
        (11, 24),            # DT_SYMENT
        (20, 7),             # DT_PLTREL=DT_RELA
        (23, 0x404300),      # DT_JMPREL
        (2, 0x60),           # DT_PLTRELSZ
        (0x6FFFFFF0, 0x404380),  # DT_VERSYM
    ]
    if now:
        tags.append((0x6FFFFFFB, 1))  # DT_FLAGS_1/DF_1_NOW
    tags.append((0, 0))
    dynamic = b"".join(struct.pack("<qQ", tag, value) for tag, value in tags)
    note = b""
    if cet:
        descriptor = struct.pack("<II", 0xC0000002, 4) + struct.pack("<I", cet) + b"\x00" * 4
        note = struct.pack("<III", 4, len(descriptor), 5) + b"GNU\x00" + descriptor

    phnum = 5 if note else 4
    ident = b"\x7fELF" + bytes((2, 1, 1, 0, 0)) + b"\x00" * 7
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident, etype, 62, 1, 0x400100, 64, 0, 0,
        64, 56, phnum, 0, 0, 0,
    )
    phdrs = [
        _phdr(1, 5, 0, 0x400000, 0x200, 0x200, 0x1000),
        _phdr(1, 6, 0x200, 0x404000, 0x700, 0x1000, 0x1000),
        _phdr(2, 6, 0x200, 0x404000, len(dynamic), len(dynamic), 8),
        _phdr(0x6474E552, 4, 0x200, 0x404000, 0x100, 0x100, 1),
    ]
    if note:
        phdrs.append(_phdr(0x6474E553, 4, 0x180, 0x400180, len(note), len(note), 8))
    data = bytearray(0x900)
    data[:64] = header
    data[64:64 + len(phdrs) * 56] = b"".join(phdrs)
    if note:
        data[0x180:0x180 + len(note)] = note
    data[0x200:0x200 + len(dynamic)] = dynamic
    return bytes(data)


def _forged_blob(*, r_offset: int = 0x404780, versym_symbol_index: int = 32) -> tuple[bytes, dict[str, int]]:
    """Reference Elf64_Rela/Sym construction straight from the AMD64 psABI."""

    blob_address = 0x404480
    rela_address = 0x404480  # (0x404480 - DT_JMPREL 0x404300) / 24 == 16
    sym_address = 0x404240 + versym_symbol_index * 24
    name_address = sym_address + 24
    assert sym_address == 0x404540
    data = bytearray(name_address - blob_address + len(b"write\x00"))
    r_info = (versym_symbol_index << 32) | 7
    data[rela_address - blob_address:rela_address - blob_address + 24] = struct.pack(
        "<QQq", r_offset, r_info, 0
    )
    st_name = name_address - 0x404200
    data[sym_address - blob_address:sym_address - blob_address + 24] = struct.pack(
        "<IBBHQQ", st_name, 0x12, 0, 0, 0, 0
    )
    data[name_address - blob_address:] = b"write\x00"
    return bytes(data), {
        "blob_address": blob_address,
        "rela_address": rela_address,
        "sym_address": sym_address,
        "name_address": name_address,
    }


def test_program_header_dynamic_analysis_accepts_partial_relro_lazy_binding() -> None:
    profile = engine.inspect_elf(_elf(), plt0=0x400100)
    assert profile.feasible
    assert profile.relro and not profile.bind_now
    assert profile.runtime_tag(engine.DT_JMPREL) == 0x404300
    assert profile.runtime_tag(engine.DT_SYMTAB) == 0x404240
    assert profile.writable_ranges[0].contains(0x404780, 8)
    assert any("partial RELRO" in warning for warning in profile.warnings)


def test_inverse_verifier_recomputes_loader_indices_and_versym_address() -> None:
    profile = engine.inspect_elf(_elf(), plt0=0x400100)
    blob, addresses = _forged_blob()
    result = engine.verify_forged_records(
        profile,
        blob=blob,
        requested_symbol=b"write",
        versym_value=0,
        **addresses,
    )
    assert result.relocation_selector == 16
    assert result.symbol_index == 32
    assert result.relocation_target == 0x404780
    assert result.versym_address == 0x404380 + 2 * 32
    assert result.symbol == b"write"


def test_versym_snapshot_is_a_non_circular_value_oracle() -> None:
    profile = engine.inspect_elf(_elf(), plt0=0x400100)
    blob, addresses = _forged_blob()
    versym_address = 0x4043C0
    snapshot = b"\xaa" * 8 + b"\x00\x00" + b"\xbb" * 8
    result = engine.verify_forged_records(
        profile,
        blob=blob,
        versym_memory=snapshot,
        versym_memory_address=versym_address - 8,
        **addresses,
    )
    assert result.versym_value == 0
    bad = snapshot[:8] + b"\x01\x00" + snapshot[10:]
    with pytest.raises(engine.PwnDepthRet2DlError, match="unversioned"):
        engine.verify_forged_records(
            profile, blob=blob, versym_memory=bad,
            versym_memory_address=versym_address - 8, **addresses,
        )


def test_loader_supported_local_notype_and_external_writable_target() -> None:
    profile = engine.inspect_elf(_elf(), plt0=0x400100)
    blob, addresses = _forged_blob(r_offset=0x600100)
    candidate = bytearray(blob)
    candidate[addresses["sym_address"] - addresses["blob_address"] + 4] = 0
    result = engine.verify_forged_records(
        profile,
        blob=bytes(candidate),
        versym_value=0,
        extra_writable_ranges=((0x600000, 0x601000),),
        **addresses,
    )
    assert result.relocation_target == 0x600100


def test_symbol_name_must_begin_inside_staging_blob() -> None:
    profile = engine.inspect_elf(_elf(), plt0=0x400100)
    blob, addresses = _forged_blob()
    candidate = bytearray(blob)
    sym_offset = addresses["sym_address"] - addresses["blob_address"]
    struct.pack_into("<I", candidate, sym_offset, 0)  # selects DT_STRTAB, before blob
    with pytest.raises(engine.PwnDepthRet2DlError, match="outside the staging"):
        engine.verify_forged_records(
            profile,
            blob=bytes(candidate),
            name_address=0x404200,
            versym_value=0,
            **{key: value for key, value in addresses.items() if key != "name_address"},
        )


def test_manually_corrupted_profile_still_raises_declared_error() -> None:
    profile = engine.inspect_elf(_elf(), plt0=0x400100)
    broken = replace(profile, dynamic=None)  # type: ignore[arg-type]
    blob, addresses = _forged_blob()
    with pytest.raises(engine.PwnDepthRet2DlError):
        engine.verify_forged_records(broken, blob=blob, versym_value=0, **addresses)


def test_now_pie_and_cet_are_explicit_fail_closed_blockers() -> None:
    now = engine.inspect_elf(_elf(now=True), plt0=0x400100)
    assert not now.feasible and now.bind_now
    assert any("BIND_NOW" in reason for reason in now.blockers)

    pie = engine.inspect_elf(_elf(etype=3), plt0=0x400100)
    assert not pie.feasible
    assert any("load_bias" in reason for reason in pie.blockers)

    shstk = engine.inspect_elf(_elf(cet=3), plt0=0x400100)
    assert shstk.cet_ibt and shstk.cet_shstk and not shstk.feasible
    assert any("SHSTK" in reason for reason in shstk.blockers)

    with pytest.raises(engine.PwnDepthRet2DlError, match="canonical"):
        engine.inspect_elf(
            _elf(etype=3),
            load_bias=0x0000800000000000,
            plt0=0x0000800000400100,
        )


def test_record_mutations_are_rejected_by_the_declared_error_only() -> None:
    profile = engine.inspect_elf(_elf(), plt0=0x400100)
    blob, addresses = _forged_blob()
    cases: list[tuple[bytes, dict[str, int], str]] = []

    wrong_type = bytearray(blob)
    struct.pack_into("<Q", wrong_type, 8, (32 << 32) | 8)
    cases.append((bytes(wrong_type), addresses, "JUMP_SLOT"))

    unaligned_rela = dict(addresses)
    unaligned_rela["rela_address"] += 1
    cases.append((blob, unaligned_rela, "congruent"))

    bad_target, target_addresses = _forged_blob(r_offset=0x400100)
    cases.append((bad_target, target_addresses, "writable"))

    for candidate, locations, message in cases:
        with pytest.raises(engine.PwnDepthRet2DlError, match=message):
            engine.verify_forged_records(
                profile, blob=candidate, versym_value=0, **locations,
            )
    with pytest.raises(engine.PwnDepthRet2DlError, match="canonical"):
        engine.verify_forged_records(
            profile,
            blob=blob,
            versym_value=0,
            extra_writable_ranges=((0x0000800000000000, 0x0000800000001000),),
            **addresses,
        )


@pytest.mark.parametrize("bad", [b"", b"not-elf", b"\x7fELF" + b"\x00" * 80])
def test_malformed_elf_never_leaks_struct_or_index_errors(bad: bytes) -> None:
    with pytest.raises(engine.PwnDepthRet2DlError):
        engine.inspect_elf(bad, plt0=0x400100)


def test_guarded_cli_and_json_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    elf = tmp_path / "sample"
    elf.write_bytes(_elf())
    assert engine.main(["inspect", str(elf), "--plt0", "0x400100", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["feasible"] is True
    assert report["dynamic"][hex(engine.DT_JMPREL)] == "0x404300"
    assert engine.main(["inspect"]) == 2  # argparse SystemExit is converted to a return code


def test_cli_verify_uses_caller_addresses(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    elf = tmp_path / "sample"
    elf.write_bytes(_elf())
    blob, addresses = _forged_blob()
    config = {
        "plt0": "0x400100",
        "blob_hex": blob.hex(),
        "requested_symbol": "write",
        "versym_value": 0,
        **{name: hex(value) for name, value in addresses.items()},
    }
    config_path = tmp_path / "plan.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    assert engine.main(["verify", str(elf), str(config_path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["verification"]["relocation_selector"] == 16

