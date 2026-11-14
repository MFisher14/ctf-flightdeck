import importlib.util
import io
import json
import random
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ctf import triage

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "solvers" / "toolkits" / "mobile_rf_depth.py"
SPEC = importlib.util.spec_from_file_location("round5_mobile_rf_depth", PATH)
M = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(M)


def macho64(dylib="@rpath/FridaGadget.dylib"):
    name = dylib.encode() + b"\0"
    cmdsize = (24 + len(name) + 7) & ~7
    command = struct.pack("<IIIIII", 0x0C, cmdsize, 24, 0, 0, 0) + name
    command += b"\0" * (cmdsize - len(command))
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0)
    return header + command


def uf2_block(payload=b"FLAG", number=0, total=1, address=0x2000, flags=0x2000):
    out = bytearray(512)
    struct.pack_into("<IIIIIIII", out, 0, M.UF2_MAGIC0, M.UF2_MAGIC1, flags, address,
                     len(payload), number, total, 0xE48BFF56)
    out[32:32 + len(payload)] = payload
    struct.pack_into("<I", out, 508, M.UF2_END)
    return bytes(out)


def pocsag_encode(data21):
    value = data21 << 10
    remainder = value
    for bit in range(30, 9, -1):
        if remainder & (1 << bit):
            remainder ^= M.POCSAG_GENERATOR << (bit - 10)
    word31 = value | (remainder & 0x3FF)
    word = word31 << 1
    return word | (word.bit_count() & 1)


def test_macho_strict_frida_evidence_and_wrong_value_gate(tmp_path):
    parsed = M.parse_macho(macho64())
    assert parsed["cpu"] == "arm64"
    assert parsed["frida_gadget_evidence"] == ["@rpath/FridaGadget.dylib"]
    assert parsed["instrumentation_active_verified"] is False
    broken = bytearray(macho64())
    struct.pack_into("<I", broken, 36, 0xFFFFFFF0)
    with pytest.raises(M.ArtifactError):
        M.parse_macho(bytes(broken))


def test_fat_macho_slices():
    child = macho64("@rpath/UnityFramework")
    off = 0x1000
    data = bytearray(off + len(child))
    struct.pack_into(">II", data, 0, 0xCAFEBABE, 1)
    struct.pack_into(">IIIII", data, 8, 0x0100000C, 0, off, len(child), 12)
    data[off:] = child
    result = M.parse_macho(bytes(data))
    assert result["slices"][0]["macho"]["dylibs"] == ["@rpath/UnityFramework"]


def test_dyld_cache_inventory():
    blob = bytearray(0x300)
    blob[:16] = b"dyld_v1  arm64\0"
    struct.pack_into("<IIII", blob, 16, 0x40, 1, 0x60, 1)
    struct.pack_into("<QQQII", blob, 0x40, 0x180000000, 0x100, 0x200, 7, 5)
    struct.pack_into("<QQQII", blob, 0x60, 0x180000000, 0, 0, 0x180, 0)
    blob[0x180:0x19A] = b"/usr/lib/FridaGadget.dylib\0"
    result = M.parse_dyld_cache(bytes(blob))
    assert result["images"][0]["path"].endswith("FridaGadget.dylib")
    assert not result["instrumentation_active_verified"]


def test_bundle_runtime_pairs_are_evidence_only():
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        zf.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"meta")
        zf.writestr("lib/arm64-v8a/libil2cpp.so", b"elf")
        zf.writestr("lib/arm64-v8a/libapp.so", b"app")
        zf.writestr("assets/flutter_assets/AssetManifest.json", b"{}")
        zf.writestr("assemblies/MyGame.dll", b"MZ")
        zf.writestr("lib/arm64-v8a/libmonodroid.so", b"ELF")
    got = M.inspect_mobile_bundle(out.getvalue())
    assert got["runtime_pairs"] == {"xamarin_or_maui": True, "unity_il2cpp": True, "flutter_aot": True}
    assert got["runtime_executed_verified"] is False


def test_uf2_complete_roundtrip_and_partial_declines_value():
    data = uf2_block(b"ABCD", 0, 2, 0x1000) + uf2_block(b"EF", 1, 2, 0x1004)
    result = M.parse_uf2(data)
    assert result["image"] == b"ABCDEF"
    assert result["reconstruction_verified"] is True
    partial = M.parse_uf2(data[:512])
    assert partial["image"] is None and partial["candidate_only"]
    corrupt = bytearray(data); corrupt[508] ^= 1
    with pytest.raises(M.ArtifactError): M.parse_uf2(bytes(corrupt))


def test_uf2_sparse_writes_do_not_invent_erased_gap_bytes():
    sparse = uf2_block(b"A", 0, 2, 0x1000) + uf2_block(b"B", 1, 2, 0x1010)
    result = M.parse_uf2(sparse)
    assert result["complete"] is True
    assert result["gaps"] == [(0x1001, 0x1010)]
    assert result["image"] is None
    assert result["reconstruction_verified"] is False and result["candidate_only"] is True


def test_pocsag_bch_parity_and_correction_gate():
    valid = pocsag_encode((1 << 20) | 0xABCDE)
    exact = M.correct_pocsag_codeword(valid)
    assert exact["word"] == valid and exact["payload_verified"]
    corrected = M.correct_pocsag_codeword(valid ^ (1 << 4) ^ (1 << 17))
    assert corrected["word"] == valid
    assert corrected["bch_parity_valid"] and not corrected["payload_verified"]
    report = M.decode_pocsag_words([valid])
    assert report["fields"][0]["bits20"] == 0xABCDE
    address = pocsag_encode(0x12345)
    framed = M.decode_pocsag_words([M.POCSAG_SYNC, address, address])
    assert [x["capcode"] & 7 for x in framed["fields"] if x["kind"] == "address"] == [0, 0]


def test_pocsag_uncorrectable_words_still_advance_batch_frame():
    # 0x7 has no valid BCH/parity neighbour within the two-bit correction radius.
    address = pocsag_encode(0x12345)
    report = M.decode_pocsag_words([M.POCSAG_SYNC, 0x7, 0x7, address])
    assert [row["kind"] for row in report["fields"][:3]] == ["sync", "uncorrectable", "uncorrectable"]
    decoded = report["fields"][-1]
    assert decoded["kind"] == "address" and decoded["capcode"] & 7 == 1


def test_fsk_and_glitch_are_candidates_not_claimed_plaintext():
    bits = [1, 0, 1, 1, 0]
    samples = [v for bit in bits for v in ([2.0] * 4 if bit else [-2.0] * 4)]
    sliced = M.slice_fsk_discriminator(samples, 4)
    assert bits in sliced["polarity_candidates"]
    assert not sliced["payload_verified"]
    trace = [0.0] * 20 + [9.0, 10.0] + [0.0] * 20
    gl = M.analyze_glitch_trace(trace, z_threshold=5)
    assert gl["events"][0]["start"] == 20
    assert not gl["fault_or_glitch_cause_verified"]


@pytest.mark.parametrize("which", ["macho", "dyld", "uf2"])
def test_5000_seeded_parser_mutations_never_escape(which):
    rng = random.Random({"macho": 5101, "dyld": 5102, "uf2": 5103}[which])
    seeds = {
        "macho": macho64(),
        "dyld": b"dyld_v1  arm64\0" + b"\0" * 128,
        "uf2": uf2_block(),
    }
    parser = {"macho": M.parse_macho, "dyld": M.parse_dyld_cache, "uf2": M.parse_uf2}[which]
    seed = seeds[which]
    for _ in range(5000):
        data = bytearray(seed[:rng.randrange(len(seed) + 1)])
        for _ in range(rng.randrange(1, 5)):
            if data: data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
        try:
            value = parser(bytes(data))
            assert isinstance(value, dict)
        except (M.ArtifactError, struct.error, UnicodeError, ValueError, OverflowError):
            pass


def test_5000_seeded_boundaries_for_bundle_pocsag_and_signal_helpers():
    rng = random.Random(5199)
    for _ in range(5000):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(40)))
        try:
            M.inspect_mobile_bundle(data)
        except (M.ArtifactError, ValueError, OSError, MemoryError):
            pass
        word = rng.randrange(1 << 32)
        result = M.correct_pocsag_codeword(word, max_errors=0)
        assert result["word"] is None or M._pocsag_valid(result["word"]) or result["word"] == M.POCSAG_SYNC
        samples = [rng.uniform(-2, 2) for _ in range(rng.randrange(1, 20))]
        try:
            sliced = M.slice_fsk_discriminator(samples, rng.randrange(1, 8))
            assert sliced["payload_verified"] is False
        except M.ArtifactError:
            pass
        glitch = M.analyze_glitch_trace(samples)
        assert glitch["fault_or_glitch_cause_verified"] is False


def test_cli_boundary_has_no_traceback(tmp_path):
    path = tmp_path / "bad.bin"; path.write_bytes(b"bad")
    proc = subprocess.run([sys.executable, str(PATH), "macho", str(path)], text=True,
                          capture_output=True, timeout=10)
    assert proc.returncode == 2
    assert "Traceback" not in proc.stderr


def test_misc_triage_routes_saved_rf_and_firmware_depth():
    for description in ("saved POCSAG capture", "UF2 firmware", "LoRa GFSK discriminator",
                        "fault injection glitch trace"):
        suggested = triage.suggest("misc", description)
        assert suggested["engines"][0] == "solvers/toolkits/mobile_rf_depth.py"
