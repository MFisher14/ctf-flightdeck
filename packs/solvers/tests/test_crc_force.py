"""crc_force: patch 4 bytes so a blob's CRC32 equals a chosen target (verified against zlib)."""
from __future__ import annotations

import random
import zlib

import pytest

import crc_force as cf


def _crc(b):
    return zlib.crc32(b) & 0xFFFFFFFF


def test_patch_hits_target_and_preserves_surroundings():
    data = b"CSCTF{crc_puzzle_here}___padding___"
    target = 0xDEADBEEF
    out = cf.patch(data, 10, target)
    assert _crc(out) == target
    assert len(out) == len(data)
    assert out[:10] == data[:10] and out[14:] == data[14:]   # only the 4-byte window changed


def test_append_patch():
    data = b"hello world"
    out = cf.append_patch(data, 0x12345678)
    assert out[:len(data)] == data
    assert len(out) == len(data) + 4
    assert _crc(out) == 0x12345678


def test_zero_target_reachable():
    out = cf.patch(b"\x01\x02\x03\x04\x05\x06\x07\x08", 2, 0)
    assert _crc(out) == 0


def test_offset_at_start_and_end():
    data = bytes(range(32))
    assert _crc(cf.patch(data, 0, 0xCAFEBABE)) == 0xCAFEBABE
    assert _crc(cf.patch(data, len(data) - 4, 0xCAFEBABE)) == 0xCAFEBABE


@pytest.mark.parametrize("seed", range(8))
def test_random_fuzz(seed):
    rng = random.Random(seed)
    for _ in range(40):
        n = rng.randint(4, 80)
        data = bytes(rng.randrange(256) for _ in range(n))
        off = rng.randint(0, n - 4)
        target = rng.randrange(1 << 32)
        out = cf.patch(data, off, target)
        assert _crc(out) == target
        assert out[:off] == data[:off] and out[off + 4:] == data[off + 4:]


def test_fail_closed():
    with pytest.raises(cf.CrcError):
        cf.patch("not bytes", 0, 0)
    with pytest.raises(cf.CrcError):
        cf.patch(b"abc", 0, 0)                 # too short for a 4-byte window
    with pytest.raises(cf.CrcError):
        cf.patch(b"abcdefgh", 6, 0)            # offset+4 past end
    with pytest.raises(cf.CrcError):
        cf.patch(b"abcdefgh", 0, 1 << 40)      # target not 32-bit
    with pytest.raises(cf.CrcError):
        cf.patch(b"abcdefgh", -1, 0)           # negative offset


def test_cli(capsysbinary, tmp_path):
    src = tmp_path / "blob.bin"
    src.write_bytes(b"the quick brown fox")
    out = tmp_path / "patched.bin"
    # append mode (default), write to file
    assert cf.main([str(src), "0xabad1dea", "--out", str(out)]) == 0
    assert _crc(out.read_bytes()) == 0xABAD1DEA
    # in-place offset mode, result to stdout buffer
    assert cf.main([str(src), "99", "--offset", "4"]) == 0
    piped = capsysbinary.readouterr().out
    assert _crc(piped) == 99
    assert cf.main([str(tmp_path / "missing.bin"), "0x1"]) == 1
    assert cf.main(["--help"]) == 0
