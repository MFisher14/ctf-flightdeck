"""Independent CRC/checksum locks and deterministic API-boundary probes.

Oracles: CRC RevEng catalogue (check string 123456789), crccheck 1.3.1,
Scapy checksum/Fletcher implementations, Python codecs, and RFC 1071 section 3.
https://reveng.sourceforge.io/crc-catalogue/all.htm
https://www.rfc-editor.org/rfc/rfc1071.txt
Previously reported contract failures are now ordinary regression tests.
"""
import codecs
import json
import random

import pytest
from crccheck.crc import Crc8Smbus, Crc16Xmodem, Crc32IsoHdlc
from scapy.utils import checksum, fletcher16_checksum

import crc_force as force
import ecc_codes as ecc
import hash_structures as structures


# Independently transcribed catalogue parameters, never engine.CRC_CATALOG.
# name,width,poly,init,xorout,refin,refout,check
CHECKS = [
    ("CRC-8/SMBUS", 8, 0x07, 0, 0, False, False, 0xF4),
    ("CRC-8/MAXIM-DOW", 8, 0x31, 0, 0, True, True, 0xA1),
    ("CRC-16/ARC", 16, 0x8005, 0, 0, True, True, 0xBB3D),
    ("CRC-16/IBM-3740", 16, 0x1021, 0xFFFF, 0, False, False, 0x29B1),
    ("CRC-16/XMODEM", 16, 0x1021, 0, 0, False, False, 0x31C3),
    ("CRC-16/MODBUS", 16, 0x8005, 0xFFFF, 0, True, True, 0x4B37),
    ("CRC-16/IBM-SDLC", 16, 0x1021, 0xFFFF, 0xFFFF, True, True, 0x906E),
    ("CRC-32/ISO-HDLC", 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True, 0xCBF43926),
    ("CRC-32/ISCSI", 32, 0x1EDC6F41, 0xFFFFFFFF, 0xFFFFFFFF, True, True, 0xE3069283),
    ("CRC-32/BZIP2", 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, False, False, 0xFC891918),
    ("CRC-3/GSM", 3, 0x3, 0, 0x7, False, False, 0x4),
    ("CRC-4/G-704", 4, 0x3, 0, 0, True, True, 0x7),
    ("CRC-7/MMC", 7, 0x09, 0, 0, False, False, 0x75),
]


@pytest.mark.parametrize("name,width,poly,init,xorout,refin,refout,expected", CHECKS)
def test_catalogue_checks(name, width, poly, init, xorout, refin, refout, expected):
    assert ecc.crc_compute(b"123456789", width, poly, init=init, xorout=xorout,
                           refin=refin, refout=refout) == expected
    if not refin and not refout:
        assert structures.crc_msb(b"123456789", width, poly, init=init, xor_out=xorout) == expected


@pytest.mark.parametrize("name,expected,width,poly,init,xorout,refin,refout", [
    ("crc8", 0xF4, 8, 7, 0, 0, False, False),
    ("crc8_maxim", 0xA1, 8, 0x31, 0, 0, True, True),
    ("crc16_ccitt_false", 0x29B1, 16, 0x1021, 0xFFFF, 0, False, False),
    ("crc16_xmodem", 0x31C3, 16, 0x1021, 0, 0, False, False),
    ("crc16_modbus", 0x4B37, 16, 0x8005, 0xFFFF, 0, True, True),
    ("crc32_iso_hdlc", 0xCBF43926, 32, 0x04C11DB7, 0xFFFFFFFF, 0xFFFFFFFF, True, True),
])
def test_recover_catalogue_known_checks(name, expected, width, poly, init, xorout, refin, refout):
    result = ecc.recover_crc_catalog(b"123456789", expected)
    match = {"name": name, "width": width, "polynomial": poly, "init": init,
             "xorout": xorout, "refin": refin, "refout": refout, "verified": True}
    assert result == {"matches": [match], "unique": True, "value": match}


def test_recover_catalogue_ambiguity_unknown_and_no_match():
    # Empty string has zero CRC for multiple catalogue algorithms.
    result = ecc.recover_crc_catalog(b"", 0, ["crc8", "crc16_xmodem"])
    assert result["unique"] is False and result["value"] is None
    assert [m["name"] for m in result["matches"]] == ["crc8", "crc16_xmodem"]
    assert ecc.recover_crc_catalog(b"123456789", 0x100000000)["matches"] == []
    assert ecc.recover_crc_catalog(b"123456789", 0xF4, ["not-a-crc"])["matches"] == []


def test_seeded_valid_checksum_oracles():
    rng = random.Random(0xC5C72026)
    for length in list(range(17)) + [31, 32, 63, 64, 129, 255, 512]:
        data = rng.randbytes(length)
        assert ecc.crc_compute(data, 8, 7) == Crc8Smbus.calc(data)
        assert ecc.crc_compute(data, 16, 0x1021) == Crc16Xmodem.calc(data)
        assert structures.crc_msb(data, 16, 0x1021) == Crc16Xmodem.calc(data)
        assert ecc.crc_compute(data, 32, 0x04C11DB7, init=0xFFFFFFFF,
                               xorout=0xFFFFFFFF, refin=True, refout=True) == Crc32IsoHdlc.calc(data)
        assert ecc.fletcher16(data) == fletcher16_checksum(data)
        assert ecc.internet_checksum(data) == checksum(data)


def test_rfc1071_literal():
    # RFC section3 gives one's-complement sum DDF2; checksum complements it.
    assert ecc.internet_checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220D


def test_force_patch_and_append_independent_crc_library():
    rng = random.Random(0xF04CE)
    for size in (4, 5, 8, 19, 64):
        source = rng.randbytes(size)
        for target in (0, 0xFFFFFFFF, 0xCBF43926, rng.getrandbits(32)):
            for offset in {0, size // 2 if size // 2 + 4 <= size else 0, size - 4}:
                result = force.patch(source, offset, target)
                assert Crc32IsoHdlc.calc(result) == target
                assert result[:offset] == source[:offset]
                assert result[offset + 4:] == source[offset + 4:]
            result = force.append_patch(source, target)
            assert result[:size] == source and len(result) == size + 4
            assert Crc32IsoHdlc.calc(result) == target
    assert Crc32IsoHdlc.calc(force.append_patch(b"", 0)) == 0


def test_crc_patch_exact_reference_bytes():
    # Fixing 32 bits under CRC32 is bijective. The sole patch that reaches this
    # independently computed target is the original message's four-byte suffix.
    expected = b"CSCTF{crc_lock}"
    assert force.patch(expected[:-4] + b"\0" * 4, len(expected) - 4,
                       Crc32IsoHdlc.calc(expected)) == expected
    assert force.append_patch(expected[:-4], Crc32IsoHdlc.calc(expected)) == expected


def test_structures_patch_independent_crc8_exhaustive_solution():
    # Enumerate a single-byte patch with crccheck, not either engine's CRC.
    source = b"ABC"
    target = 0xF4
    winners = [b"A" + bytes([byte]) + b"C" for byte in range(256)
               if Crc8Smbus.calc(b"A" + bytes([byte]) + b"C") == target]
    assert len(winners) == 1
    assert structures.forge_crc_patch(source, target, 1, 1, 8, 7) == winners[0]
    assert structures.forge_crc_patch(source, target, 1, 1, 8, 7,
                                     verify=lambda data, value: Crc8Smbus.calc(data) == value) == winners[0]
    assert structures.forge_crc_patch(source, target, 1, 1, 8, 7,
                                     verify=lambda *_: True) is None
    # Two bytes -> 8 CRC bits cannot uniquely determine the patch.
    assert structures.forge_crc_patch(source, target, 0, 2, 8, 7) is None


def test_codec_candidates_with_independent_stdlib_encoder():
    for encoding, text in [("cp037", "CSCTF{EBCDIC}"), ("utf-8", "CSCTF{caf\u00e9}"),
                           ("utf-16-le", "CSCTF{little_endian}")]:
        raw = codecs.encode(text, encoding, "strict")
        rows = ecc.python_codec_candidates(raw, min_printable=1.0)
        hit = next(row for row in rows if row["text"] == text)
        assert codecs.lookup(encoding).name in hit["codecs"]
        assert hit["roundtrip_verified"] is True and hit["candidate_only"] is True
        for row in rows:
            assert row["printable_ratio"] == 1.0
            for name in row["codecs"]:
                assert codecs.encode(row["text"], name, "strict") == raw


def _clean(call, allowed=(ecc.ECCError,)):
    try:
        call()
    except allowed:
        pass


def test_seeded_malformed_checksum_and_patch_values():
    rng = random.Random(0xBAD)
    for _ in range(75):
        data = rng.randbytes(rng.randrange(24))
        _clean(lambda: ecc.crc_compute(data, rng.choice([-8, 0, 8, 16, 65]),
                                      rng.choice([-1, 0, 7, 0x1021, 1 << 70])))
        _clean(lambda: ecc.recover_crc_catalog(data, rng.choice([-1, 0, 0xF4, 1 << 40])))
        _clean(lambda: force.patch(data, rng.randrange(-4, 30), rng.randrange(-5, 1 << 34)),
               (force.CrcError,))
        _clean(lambda: force.append_patch(data, rng.randrange(-5, 1 << 34)), (force.CrcError,))
        _clean(lambda: structures.forge_crc_patch(data, -1, 0, 1, 8, 7), ())
    for wrong in (None, 1, "not bytes", {}, []):
        _clean(lambda: ecc.crc_compute(wrong, 8, 7))
        _clean(lambda: ecc.python_codec_candidates(wrong))
        _clean(lambda: force.patch(wrong, 0, 0), (force.CrcError,))
        _clean(lambda: force.append_patch(wrong, 0), (force.CrcError,))
        _clean(lambda: structures.forge_crc_patch(wrong, 0, 0, 1, 8, 7), ())
    for wrong in (None, "1", [], 1.5, -1, 1 << 33):
        _clean(lambda: force.patch(b"01234567", wrong, 0), (force.CrcError,))
        _clean(lambda: force.append_patch(b"", wrong), (force.CrcError,))
    _clean(lambda: ecc.python_codec_candidates(b""))


@pytest.mark.parametrize("parameter,bad", [("width", None), ("width", 8.0),
                                         ("polynomial", None), ("init", None), ("xorout", "0")])
def test_bug_crc_parameter_types(parameter, bad):
    kwargs = {"width": 8, "polynomial": 7, parameter: bad}
    _clean(lambda: ecc.crc_compute(b"", **kwargs))


@pytest.mark.parametrize("bad", [None, 1])
def test_bug_catalogue_names_type(bad):
    _clean(lambda: ecc.recover_crc_catalog(b"", 0, bad))


@pytest.mark.parametrize("function,bad", [(ecc.fletcher16, None), (ecc.fletcher16, "a"),
                                         (ecc.internet_checksum, None), (ecc.internet_checksum, "a")])
def test_bug_checksum_input_types(function, bad):
    _clean(lambda: function(bad))


def test_bug_codec_threshold():
    _clean(lambda: ecc.python_codec_candidates(b"a", min_printable=None))


def test_bug_structures_crc_error_contract():
    _clean(lambda: structures.crc_msb(None, 8, 7), ())


def test_codec_seeded_bytes_fuzz():
    rng = random.Random(0xC0DEC)
    for length in range(1, 25):
        _clean(lambda: ecc.python_codec_candidates(rng.randbytes(length)))


def test_ecc_cli_vectors_and_bad_arguments(tmp_path, capsys):
    source = tmp_path / "check.bin"
    source.write_bytes(b"123456789")
    assert ecc.main(["crc", str(source), "0xcbf43926"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["value"]["name"] == "crc32_iso_hdlc"
    source.write_bytes("CSCTF{CODEC}".encode("cp037"))
    assert ecc.main(["codecs", str(source)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert any(row["text"] == "CSCTF{CODEC}" and "cp037" in row["codecs"] for row in report)
    for argv in ([], ["unknown"], ["rs", "GG", "4"], ["hamming", "012"],
                 ["crc", "\x00", "0"], ["crc", str(source), "bad"]):
        assert ecc.main(argv) == 2


def test_bug_ecc_cli_help():
    assert ecc.main(["--help"]) == 0


def test_crc_force_cli_oracle_and_malformed(tmp_path, capsysbinary):
    source = tmp_path / "input"
    source.write_bytes(b"CSCTF{offline_crc}")
    output = tmp_path / "output"
    assert force.main([str(source), "0x12345678", "--out", str(output)]) == 0
    assert Crc32IsoHdlc.calc(output.read_bytes()) == 0x12345678
    for argv in ([], ["--unknown"], [str(source), "bad"], ["\x00", "0"], [str(source), "-1"]):
        assert force.main(argv) in (1, 2)
    assert force.main(["--help"]) == 0


def test_bug_crc_force_output_io_error(tmp_path):
    source = tmp_path / "input"
    source.write_bytes(b"abcd")
    assert force.main([str(source), "0", "--out", str(tmp_path)]) != 0
