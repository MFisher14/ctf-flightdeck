#!/usr/bin/env python3
"""Offline tests of solvers/common/verified_transform.py.

  .venv/bin/python -m pytest tests/test_verified_transform.py   (or `python tests/test_verified_transform.py`)

No network and no token. Every fixture is synthetic and made here in memory. The one check that
exercises the labels-backed convenience sets $CTF_WORKDIR to a throwaway tempdir so the
tracked ledger is never touched. Each check prints one line and asserts.
"""
import gzip
import hashlib
import io
import os
import struct
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COMMON = REPO / "solvers" / "common"

TMP = Path(tempfile.mkdtemp(prefix="test_verified_transform_"))
os.environ["CTF_TESTING"] = "1"
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
sys.dont_write_bytecode = True
sys.path.insert(0, str(COMMON))

import verified_transform as VT  # noqa: E402


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    assert cond, name


# --------------------------------------------------------------------------- fixtures

def crc32(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def make_crc_payload(body):
    """A CRC-32-headed payload: u32le stored CRC, then the body."""
    return struct.pack("<I", crc32(body)) + body


def strip4(p):
    """The transform: drop the 4-byte CRC header."""
    return p[4:]


def make_pseudo_encrypted_zip(name, content, compression=zipfile.ZIP_STORED, corrupt_crc=False):
    """A zip holding one member, then its general-purpose encryption bit (0x0001) set in the local
    file header and the central-directory record (the pseudo-encryption trick). With corrupt_crc,
    the stored CRC-32 in both headers is also mangled so the member no longer validates."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        z.writestr(name, content)
    raw = bytearray(buf.getvalue())

    # local file header at offset 0: flag at +6 (u16le), stored CRC-32 at +14 (u32le)
    assert raw[:4] == b"PK\x03\x04"
    struct.pack_into("<H", raw, 6, struct.unpack_from("<H", raw, 6)[0] | 0x0001)
    if corrupt_crc:
        struct.pack_into("<I", raw, 14, (struct.unpack_from("<I", raw, 14)[0] ^ 0xFFFFFFFF) & 0xFFFFFFFF)

    # central directory record: flag at +8 (u16le), stored CRC-32 at +16 (u32le)
    c = raw.rfind(b"PK\x01\x02")
    assert c > 0
    struct.pack_into("<H", raw, c + 8, struct.unpack_from("<H", raw, c + 8)[0] | 0x0001)
    if corrupt_crc:
        struct.pack_into("<I", raw, c + 16, (struct.unpack_from("<I", raw, c + 16)[0] ^ 0xFFFFFFFF) & 0xFFFFFFFF)
    return bytes(raw)


# --------------------------------------------------------------------------- 1. a CRC-headed payload -> verified

BODY = b"the real decoded content, printable and long enough" * 3
GOOD_CRC = crc32(BODY)

# --------------------------------------------------------------------------- 2. a magic+sizer file -> verified

GZIP_BLOB = gzip.compress(BODY)


# a stored (unencrypted) zip is a CRC-valid structure (testzip() returns None)
def _zip_blob():
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as _z:
        _z.writestr("a.txt", b"hello a")
        _z.writestr("b.txt", b"hello b" * 50)
    return zbuf.getvalue()


ZIP_BLOB = _zip_blob()


# a PNG sizer: a hand-built minimal-but-complete PNG (valid IHDR CRC + IEND)
def _png_chunk(typ, body):
    return struct.pack(">I", len(body)) + typ + body + struct.pack(">I", zlib.crc32(typ + body) & 0xFFFFFFFF)


PNG_BLOB = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)) + \
    _png_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff")) + _png_chunk(b"IEND", b"")

# --------------------------------------------------------------------------- 3. zip pseudo-encrypted member -> read

SECRET = b"the flag is here, pseudo-encrypted but not really"

RANDOM = bytes((i * 131 + 17) & 0xFF for i in range(2048))   # deterministic, non-printable, no structure


def test_1_a_crc_headed_payload_verified():
    check("verify: body under its stored CRC-32 is verified", VT.verify(BODY, crc=GOOD_CRC) is True)
    check("verify: CRC given as a 0x hex string also verifies", VT.verify(BODY, crc=f"0x{GOOD_CRC:08x}") is True)
    check("apply_and_verify: CRC-headed payload yields the body",
          VT.apply_and_verify(make_crc_payload(BODY), strip4, crc=GOOD_CRC) == BODY)


def test_2_a_magic_sizer_file_verified():
    check("verify: a whole gzip stream is a verified structure", VT.verify(GZIP_BLOB, structure=True) is True)
    check("verify: structure + its magic prefix verifies", VT.verify(GZIP_BLOB, magic=b"\x1f\x8b\x08") is True)
    check("verify: structure=exact holds when the blob is exactly the structure",
          VT.verify(GZIP_BLOB, structure="exact") is True)
    check("verify: a CRC-valid zip is a verified structure", VT.verify(ZIP_BLOB, structure=True) is True)
    check("verify: a complete PNG (IHDR..IEND) is a verified structure", VT.verify(PNG_BLOB, structure=True) is True)


def test_3_zip_pseudo_encrypted_member_read():
    PSEUDO = make_pseudo_encrypted_zip("secret.txt", SECRET)

    # a plain unzip cannot read the flagged member
    _plain_read_failed = False
    try:
        with zipfile.ZipFile(io.BytesIO(PSEUDO)) as _z:
            _z.read("secret.txt")
    except (RuntimeError, zipfile.BadZipFile):
        _plain_read_failed = True
    check("zip: plain zipfile refuses the pseudo-encrypted member (fixture is valid)", _plain_read_failed)

    check("zip: read_pseudo_encrypted_member returns the CRC-valid member",
          VT.read_pseudo_encrypted_member(PSEUDO, "secret.txt") == SECRET)
    check("zip: the flag bit really was set (clear_zip_encryption changes the bytes)",
          VT.clear_zip_encryption(PSEUDO) not in (None, PSEUDO))
    check("zip: pseudo_encrypted_members maps the name to its bytes",
          VT.pseudo_encrypted_members(PSEUDO) == {"secret.txt": SECRET})
    check("zip: name=None returns the first validated member",
          VT.read_pseudo_encrypted_member(PSEUDO) == SECRET)

    # the same, deflated
    PSEUDO_DEF = make_pseudo_encrypted_zip("note.bin", SECRET * 40, compression=zipfile.ZIP_DEFLATED)
    check("zip: a deflated pseudo-encrypted member reads too",
          VT.read_pseudo_encrypted_member(PSEUDO_DEF, "note.bin") == SECRET * 40)


# --------------------------------------------------------------------------- 4. corrupt CRC / no validator / random -> not verified / None
def test_4_corrupt_crc_no_validator_random_not_verified():
    check("verify: a wrong CRC-32 is not verified", VT.verify(BODY, crc=GOOD_CRC ^ 0x1) is False)
    check("apply_and_verify: a wrong CRC yields None",
          VT.apply_and_verify(make_crc_payload(BODY), strip4, crc=GOOD_CRC ^ 0x1) is None)

    PSEUDO_BAD = make_pseudo_encrypted_zip("secret.txt", SECRET, corrupt_crc=True)
    check("zip: a corrupt stored CRC-32 is refused (member not returned)",
          VT.read_pseudo_encrypted_member(PSEUDO_BAD, "secret.txt") is None)
    check("zip: pseudo_encrypted_members drops the corrupt-CRC member",
          VT.pseudo_encrypted_members(PSEUDO_BAD) == {})

    check("verify: no validator supplied -> not verified", VT.verify(BODY) is False)
    check("verify: random bytes are not a verified structure", VT.verify(RANDOM, structure=True) is False)
    check("verify: random bytes under a wrong CRC are not verified", VT.verify(RANDOM, crc=0) is False)
    check("apply_and_verify: identity on random bytes with structure proof -> None",
          VT.apply_and_verify(RANDOM, lambda x: x, structure=True) is None)


# --------------------------------------------------------------------------- decide(): plain / unsure / None
def test_decide_plain_unsure_none():
    check("decide: verified body -> 'plain'", VT.decide(BODY, crc=GOOD_CRC) == "plain")
    check("decide: verified gzip structure -> 'plain'", VT.decide(GZIP_BLOB, structure=True) == "plain")
    check("decide: printable but unverified -> 'unsure'",
          VT.decide(b"plainly readable text here", crc=0) == "unsure")
    check("decide: garbage + failing validator -> None", VT.decide(RANDOM, crc=0) is None)
    check("decide: no validator at all -> None", VT.decide(BODY) is None)
    check("decide: printable value but no validator -> None (must opt in)",
          VT.decide(b"plainly readable text here") is None)


# --------------------------------------------------------------------------- length / digest validators
# audit H10: a bare stored length is NOT a proof -- many wrong decodes land on the right length.
def test_length_digest_validators():
    check("verify: a bare matching length is NOT a proof (audit H10)", VT.verify(BODY, length=len(BODY)) is False)
    check("verify: a wrong stored length is not verified", VT.verify(BODY, length=len(BODY) + 1) is False)
    check("verify: a matching length alongside a matching CRC still verifies (strong proof carries it)",
          VT.verify(BODY, crc=GOOD_CRC, length=len(BODY)) is True)
    check("verify: sha256 hex digest matches", VT.verify(BODY, digest=hashlib.sha256(BODY).hexdigest()) is True)
    check("verify: md5 raw-bytes digest matches", VT.verify(BODY, digest=hashlib.md5(BODY).digest()) is True)
    check("verify: (algo, value) digest pair matches",
          VT.verify(BODY, digest=("sha1", hashlib.sha1(BODY).hexdigest())) is True)
    check("verify: a wrong digest is not verified",
          VT.verify(BODY, digest=hashlib.sha256(BODY + b"x").hexdigest()) is False)


# --------------------------------------------------------------------------- never-raises / purity on hostile input
def test_never_raises_purity_on_hostile_input():
    _raised = False
    try:
        for bad in (None, 123, 4.5, object(), {"x": 1}, [1, 2]):
            VT.verify(bad, crc=0)
            VT.decide(bad, crc=0)
            VT.clear_zip_encryption(bad)
            VT.pseudo_encrypted_members(bad)
            VT.read_pseudo_encrypted_member(bad)
        VT.apply_and_verify(b"x", lambda _: (_ for _ in ()).throw(ValueError("boom")), crc=0)
        VT.apply_and_verify(b"x", lambda _: None, crc=0)
    except Exception as exc:  # noqa: BLE001
        _raised = True
        print("   raised:", repr(exc))
    check("purity: no public entry point raises on hostile/None/odd input", not _raised)
    check("apply_and_verify: a raising transform yields None (caught)",
          VT.apply_and_verify(b"x", lambda _: (_ for _ in ()).throw(ValueError("boom")), crc=0) is None)


# --------------------------------------------------------------------------- plain_or_candidate (labels-backed)
# verified -> the value is returned PLAIN (no labels needed)
def test_plain_or_candidate_labels_backed():
    check("plain_or_candidate: verified value is returned plain",
          VT.plain_or_candidate("warmups.payload/verified_transform", BODY.decode("latin-1"),
                                crc=GOOD_CRC) == BODY.decode("latin-1"))
    # garbage -> None
    check("plain_or_candidate: garbage -> None",
          VT.plain_or_candidate("warmups.payload/verified_transform", RANDOM, crc=0) is None)
    # printable but unverified -> an unsure candidate string ('??' wire form), never the plain value
    _unsure = VT.plain_or_candidate("warmups.payload/verified_transform", "readable-but-unproven", crc=0)
    check("plain_or_candidate: printable+unverified -> '??' unsure candidate, not plain",
          isinstance(_unsure, str) and _unsure.startswith("??") and _unsure != "readable-but-unproven")


# --------------------------------------------------------------------------- H9: a loose-sizer structure is not plain-eligible
#
# Five magics have sizers that validate NO content: _pdf_end is rfind(%%EOF); _riff_end/_bmp_end
# trust a SELF-declared length; _pe_end stops at the header and ignores trailing junk; _gif_end
# accepts junk LZW. A blob that merely begins with one of these magics and satisfies its loose sizer
# must NOT self-validate to PLAIN. Only png/jpeg/gzip/7z/elf/zip (genuine content validators) do.
# RIFF/WAVE: declared length = total-8 so _riff_end walks to the exact end; payload is pure garbage.
def test_h9_a_loose_sizer_structure_is_not_plain_eligible():
    _riff_pl = b"\xde\xad\xbe\xef" * 8
    RIFF_FORGED = b"RIFF" + struct.pack("<I", 4 + len(_riff_pl)) + b"WAVE" + _riff_pl
    check("H9 riff: a self-declared-length RIFF is not a verified structure",
          VT.verify(RIFF_FORGED, structure=True) is False)
    check("H9 riff: not verified via its magic prefix either", VT.verify(RIFF_FORGED, magic=b"RIFF") is False)
    check("H9 riff: binary garbage -> decide None (never plain)", VT.decide(RIFF_FORGED, structure=True) is None)

    # PDF: a %PDF- header and a %%EOF marker with arbitrary garbage between (what _pdf_end "accepts").
    PDF_FORGED = b"%PDF-1.4\nARBITRARY GARBAGE NOT A REAL PDF\n%%EOF"
    check("H9 pdf: rfind(%%EOF) is not a verified structure", VT.verify(PDF_FORGED, structure=True) is False)
    check("H9 pdf: printable garbage -> decide 'unsure' (probed candidate), never 'plain'",
          VT.decide(PDF_FORGED, structure=True) == "unsure")

    # BMP: header size == len(blob), reserved 0, valid header size, pixel offset in range.
    _bmp_hdr = 40
    _bmp_size = 14 + _bmp_hdr + 16
    BMP_FORGED = b"BM" + struct.pack("<IIII", _bmp_size, 0, 14 + _bmp_hdr, _bmp_hdr) + b"\x00" * (_bmp_size - 18)
    check("H9 bmp: a self-declared-length BMP is not a verified structure",
          VT.verify(BMP_FORGED, structure=True) is False)

    # PE: MZ + e_lfanew -> PE\0\0, nsec=0 opt=0 so _pe_end stops at the header; trailing junk is ignored.
    _mz = bytearray(b"MZ" + b"\x00" * 0x3a)
    _lfa = 0x40
    _mz += struct.pack("<I", _lfa)
    _mz += b"\x00" * (_lfa - len(_mz))
    _mz += b"PE\x00\x00" + b"\x00" * 2 + struct.pack("<H", 0) + b"\x00" * 12 + struct.pack("<H", 0) + b"\x00" * 2
    PE_FORGED = bytes(_mz) + b"TRAILING-JUNK" * 4
    check("H9 pe: a header-only PE with trailing junk is not a verified structure",
          VT.verify(PE_FORGED, structure=True) is False)

    # A short blob under a loose magic (truncated, sizer would fail) is likewise never plain.
    check("H9: a short RIFF (no complete structure) is not verified", VT.verify(b"RIFF\x08\x00\x00\x00WA", structure=True) is False)

    # Regression: a genuine complete-validator file still verifies and still decides plain.
    check("H9 regress: a genuine gzip still verifies (complete validator)", VT.verify(GZIP_BLOB, structure=True) is True)
    check("H9 regress: a genuine gzip still decides 'plain'", VT.decide(GZIP_BLOB, structure=True) == "plain")
    check("H9 regress: a complete PNG still verifies", VT.verify(PNG_BLOB, structure=True) is True)
    check("H9 regress: a CRC-valid zip still verifies", VT.verify(ZIP_BLOB, structure=True) is True)


# --------------------------------------------------------------------------- H10: length alone is never a proof
def test_h10_length_alone_is_never_a_proof():
    check("H10: length alone on binary -> decide None (never plain)",
          VT.decide(bytes([3, 1, 4, 1, 5, 9, 2, 6]), length=8) is None)
    check("H10: length alone on printable -> 'unsure' candidate, never 'plain'",
          VT.decide(b"plain readable text", length=19) == "unsure")
    check("H10: apply_and_verify with a length-only proof yields None, not the garbage output",
          VT.apply_and_verify(b"IN", lambda p: bytes(20), length=20) is None)
    check("H10 regress: a length alongside a matching CRC still decides 'plain'",
          VT.decide(BODY, crc=GOOD_CRC, length=len(BODY)) == "plain")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
