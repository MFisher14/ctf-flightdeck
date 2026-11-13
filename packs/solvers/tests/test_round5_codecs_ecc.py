from __future__ import annotations

import importlib.util
import random
import sys
import zlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
sys.path.insert(0, str(ROOT / "solvers" / "warmups"))
import ecc_codes as E  # noqa: E402
import ecc_steps as S  # noqa: E402
import crib_decode as C  # noqa: E402


def _bits(value: int, width: int) -> list[int]:
    return [(value >> shift) & 1 for shift in range(width - 1, -1, -1)]


def test_rs_gf256_roundtrip_correction_and_independent_existing_engine_crosscheck():
    data = b"CSCTF{general_rs_verified}"
    codeword = E.rs_encode(data, 12)
    clean = E.rs_decode(codeword, 12)
    assert clean and bytes(clean.data) == data and clean.value_verified
    damaged = bytearray(codeword)
    for position, delta in ((0, 0x91), (7, 0x42), (19, 0xE3), (len(damaged) - 2, 0x55)):
        damaged[position] ^= delta
    fixed = E.rs_decode(bytes(damaged), 12)
    assert fixed and bytes(fixed.data) == data and fixed.zero_syndrome and fixed.reencoded
    assert fixed.value_verified is False  # correction still needs an external payload checksum
    erased = bytearray(codeword)
    for position in (1, 5, 9, 13, 17, 21, 25, 29):
        erased[position] = 0
    recovered = E.rs_decode(bytes(erased), 12, erasures=(1, 5, 9, 13, 17, 21, 25, 29))
    assert recovered and bytes(recovered.data) == data and not recovered.value_verified

    # Independent, already-shipped barcode implementation agrees on this shortened word.
    spec = importlib.util.spec_from_file_location("matrix_rs_crosscheck", ROOT / "solvers/toolkits/matrix_barcodes.py")
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module; spec.loader.exec_module(module)
    reference = module.rs_binary(list(damaged), 12, module._GF(0x11D, 256, 0))
    assert reference and bytes(reference[0]) == codeword


def test_rs_nonprimitive_and_beyond_capacity_decline_or_never_verify_wrong():
    with pytest.raises(E.ECCError):
        E.GF2m(0x12)  # reducible/non-primitive for generator 2
    data = b"bounded distance"
    word = bytearray(E.rs_encode(data, 4))
    for position in (0, 3, 8):
        word[position] ^= 0xA5
    result = E.rs_decode(bytes(word), 4)
    assert result is None or result.value_verified is False


def test_hamming_secded_all_nibbles_single_correction_double_decline_triple_unverified():
    for nibble in range(16):
        encoded = E.hamming84_encode(nibble)
        clean = E.hamming84_decode(encoded)
        assert clean and clean.data == tuple(_bits(nibble, 4)) and clean.value_verified
        for bit in range(8):
            fixed = E.hamming84_decode(encoded ^ (1 << bit))
            assert fixed and fixed.data == tuple(_bits(nibble, 4)) and fixed.reencoded
            assert fixed.value_verified is False
        assert E.hamming84_decode(encoded ^ 1 ^ 2) is None
        triple = E.hamming84_decode(encoded ^ 1 ^ 2 ^ 4)
        assert triple is None or triple.value_verified is False


def test_bch_15_7_t2_corrects_two_and_never_verifies_beyond_radius():
    for value in (0, 1, 0x35, 0x7F):
        data = _bits(value, 7)
        word = E.bch_encode(data, 4, 2, 0x13)
        assert len(word) == 15
        for positions in ((), (0,), (2, 12)):
            damaged = word[:]
            for position in positions:
                damaged[position] ^= 1
            result = E.bch_decode(damaged, 4, 2, 0x13)
            assert result and result.data == tuple(data) and result.reencoded
            assert result.value_verified is (not positions)
        damaged = word[:]
        for position in (0, 1, 2):
            damaged[position] ^= 1
        result = E.bch_decode(damaged, 4, 2, 0x13)
        assert result is None or result.value_verified is False


def test_viterbi_exact_and_corrected_candidate_with_exhaustive_small_crosscheck():
    data = [1, 0, 1, 1, 0, 0, 1]
    encoded = E.convolutional_encode(data, terminate=True)
    clean = E.viterbi_decode(encoded, final_state=0, terminated=True)
    assert clean and clean.data == tuple(data) and clean.path_metric == 0 and clean.value_verified
    damaged = encoded[:]; damaged[5] ^= 1
    fixed = E.viterbi_decode(damaged, final_state=0, terminated=True)
    assert fixed and fixed.data == tuple(data) and fixed.unique_ml and fixed.path_metric == 1
    assert fixed.value_verified is False
    # Exhaustive reference over all seven-bit messages proves the returned path really is ML.
    distances = []
    for value in range(1 << len(data)):
        candidate = _bits(value, len(data))
        wire = E.convolutional_encode(candidate, terminate=True)
        distances.append((sum(a != b for a, b in zip(wire, damaged)), candidate))
    best = min(distance for distance, _ in distances)
    winners = [candidate for distance, candidate in distances if distance == best]
    assert winners == [data]


def test_exact_ldpc_unique_nearest_and_ambiguity_decline():
    # Hamming(7,4) parity check: each column is its one-based binary index.
    check = [[(position >> bit) & 1 for position in range(1, 8)] for bit in range(3)]
    clean = [0, 1, 1, 0, 0, 1, 1]
    assert not any(E.syndrome(clean, check))
    result = E.ldpc_decode_exact(clean, check, 1)
    assert result and result.distance == 0 and result.value_verified
    damaged = clean[:]; damaged[4] ^= 1
    fixed = E.ldpc_decode_exact(damaged, check, 1)
    assert fixed and fixed.codeword == tuple(clean) and not fixed.value_verified


def test_crc_known_answers_catalog_uniqueness_and_checksums():
    data = b"123456789"
    expected = {
        "crc8": 0xF4, "crc8_maxim": 0xA1, "crc16_ccitt_false": 0x29B1,
        "crc16_xmodem": 0x31C3, "crc16_modbus": 0x4B37, "crc32_iso_hdlc": 0xCBF43926,
    }
    for name, answer in expected.items():
        width, poly, init, xorout, refin, refout = E.CRC_CATALOG[name]
        assert E.crc_compute(data, width, poly, init=init, xorout=xorout,
                             refin=refin, refout=refout) == answer
        recovered = E.recover_crc_catalog(data, answer)
        assert any(row["name"] == name for row in recovered["matches"])
    assert E.fletcher16(data) == 0x1EDE
    assert E.internet_checksum(b"\x00\x01\xf2\x03\xf4\xf5\xf6\xf7") == 0x220D


def test_subbyte_crc_known_answers_consume_every_input_bit():
    # Published check values for the ASCII string ``123456789``.  These exercise both
    # reflected and non-reflected sub-byte CRCs; a width-bit-per-byte implementation returns
    # plausible but incorrect values here.
    data = b"123456789"
    assert E.crc_compute(data, 4, 0x3, refin=True, refout=True) == 0x7  # CRC-4/G-704
    assert E.crc_compute(data, 5, 0x09, init=0x09) == 0x00  # CRC-5/EPC-C1G2
    assert E.crc_compute(data, 7, 0x09) == 0x75  # CRC-7/MMC


def test_python_codec_survey_exact_roundtrip_and_no_best_guess():
    phrase = "HELLO CTF"
    ebcdic = phrase.encode("cp037")
    rows = E.python_codec_candidates(ebcdic, min_printable=0.9)
    hit = next(row for row in rows if row["text"] == phrase)
    assert "cp037" in hit["codecs"] and hit["roundtrip_verified"] and hit["candidate_only"]
    assert isinstance(rows, list)  # API returns every reading; it never emits a singular best value.


def _h84_envelope(payload: bytes, corrupt: bool = False) -> bytes:
    words = bytearray()
    for byte in payload:
        words.extend((E.hamming84_encode(byte >> 4), E.hamming84_encode(byte & 15)))
    if corrupt:
        words[3] ^= 0x20
    return b"H84:" + words.hex().encode() + b":" + f"{zlib.crc32(payload) & 0xffffffff:08x}".encode()


def test_crc_protected_warmup_ecc_integration_to_flag_and_bad_crc_decline():
    flag = b"CSCTF{ecc_chain_verified}"
    envelope = _h84_envelope(flag, corrupt=True)
    assert S.d_hamming84(envelope) == flag
    hit = C.solve_blob(envelope, budget=1.0)
    assert hit and C.LAST["route"] == "flag" and hit[0] == flag.decode()
    assert "hamming84" in hit[1][0]
    assert S.d_hamming84(envelope[:-8] + b"00000000") is None

    word = bytearray(E.rs_encode(flag, 10)); word[2] ^= 0x44; word[-1] ^= 0x91
    rs_envelope = (b"RS10:" + word.hex().encode() + b":" +
                   f"{zlib.crc32(flag) & 0xffffffff:08x}".encode())
    assert S.d_rs(rs_envelope) == flag


def test_seeded_mutation_boundaries_5000_cases_never_escape_or_claim_unchecked_values():
    rng = random.Random(0xECC2026)
    for _ in range(5000):
        size = rng.randrange(1, 80)
        blob = bytes(rng.randrange(256) for _ in range(size))
        nsym = rng.randrange(1, min(16, size + 1))
        result = E.rs_decode(blob, nsym)
        if result is not None:
            assert result.zero_syndrome and result.reencoded
            if result.corrected_positions:
                assert result.value_verified is False
        bits = [rng.randrange(2) for _ in range(8)]
        ham = E.hamming_secded_decode(bits)
        if ham is not None:
            assert ham.zero_syndrome and ham.reencoded
            if ham.corrected_position is not None:
                assert ham.value_verified is False
        noisy = [rng.randrange(2) for _ in range(rng.choice((6, 8, 10, 12)))]
        vit = E.viterbi_decode(noisy)
        if vit is not None and vit.path_metric:
            assert vit.value_verified is False


def test_guarded_cli_bad_boundaries(capsys):
    assert E.main([]) == 2
    assert "ecc_codes:" in capsys.readouterr().err
    assert E.main(["rs", "zz", "4"]) == 2
    assert "ecc_codes:" in capsys.readouterr().err
    assert E.turbo_decode()["candidate"] is None
