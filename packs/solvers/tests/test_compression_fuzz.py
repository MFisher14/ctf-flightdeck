"""Robustness fuzz over the compression decoders and layered byte-decoders.

These sit directly on UNTRUSTED input (a carved blob, a layer in a decode chain) and wrap real
decompressors (gzip/bz2/lzma/zstd/lz4/brotli/snappy/lzo) whose C backends can raise, hang, or
allocate on malformed or bomb input. This feeds each adversarial bytes — empty, random, a VALID
stream truncated mid-way, and a decompression bomb — and asserts it returns bytes/None and never
lets an uncaught exception or unbounded allocation through. Pairs with test_existing_engine_fuzz.py
and test_new_engine_fuzz.py; adds no engine code."""
from __future__ import annotations

import bz2
import gzip
import lzma
import random
import zlib

import pytest

import compression_codecs as cc
import layered_decode as ld


def _valid_streams():
    payload = b"CSCTF{compression}" * 64
    return {
        "gzip": gzip.compress(payload),
        "zlib": zlib.compress(payload),
        "bz2": bz2.compress(payload),
        "lzma": lzma.compress(payload),
    }


def _mangle(stream, r):
    """Truncations and single-byte corruptions of a valid stream — the nastiest real inputs."""
    out = [stream[: len(stream) // 2], stream[:5], stream[:-1], stream + b"\x00" * 8]
    if stream:
        b = bytearray(stream)
        b[r.randrange(len(b))] ^= 0xFF
        out.append(bytes(b))
    return out


def _bomb():
    # ~10 MB of zeros compresses tiny; decoders must honor their max_output cap, not allocate it all
    big = b"\x00" * (10 << 20)
    return {"gzip": gzip.compress(big), "bz2": bz2.compress(big), "lzma": lzma.compress(big),
            "zlib": zlib.compress(big)}


_DECODERS = [
    "decode_gzip", "decode_zlib", "decode_bzip2", "decode_lzma", "decode_brotli",
    "decode_lz4", "decode_zstd", "decode_snappy_raw", "decode_snappy_framed", "decode_lzo_frame",
]


def _byte_pool(seed):
    r = random.Random(seed)
    pool = [b"", b"\x00" * r.randrange(1, 300), bytes(r.randrange(256) for _ in range(r.randrange(0, 400))),
            b"\xff" * r.randrange(1, 200)]
    for s in _valid_streams().values():
        pool.append(s)
        pool.extend(_mangle(s, r))
    return pool


@pytest.mark.parametrize("fname", _DECODERS)
@pytest.mark.parametrize("seed", range(4))
def test_compression_decoders_fail_closed(fname, seed):
    fn = getattr(cc, fname)
    for data in _byte_pool(seed):
        try:
            out = fn(data)
        except (ValueError, TypeError, KeyError):
            continue                               # declared declines are fine
        except Exception as exc:                   # any backend exception leaking through = bug
            pytest.fail(f"{fname} crashed on {data[:16]!r}...: {type(exc).__name__}: {exc}")
        assert out is None or isinstance(out, (bytes, bytearray))


@pytest.mark.parametrize("fname", ["decode_gzip", "decode_zlib", "decode_bzip2", "decode_lzma"])
def test_compression_bomb_honors_output_cap(fname):
    # a 10 MB expansion against a 1 MB cap must be bounded, not allocated in full (bomb guard)
    fn = getattr(cc, fname)
    key = {"decode_gzip": "gzip", "decode_zlib": "zlib", "decode_bzip2": "bz2", "decode_lzma": "lzma"}[fname]
    bomb = _bomb()[key]
    cap = 1 << 20
    out = fn(bomb, max_output=cap)
    # the decoder either declines (None) or returns no more than a small margin over the cap —
    # the point is it never materializes the full 10 MB expansion
    assert out is None or len(out) <= cap + (1 << 16)


_LAYER_DECODERS = ["d_hex", "d_b64", "d_b64url", "d_b32", "d_b85", "d_a85", "d_b58", "d_b45",
                   "d_binary", "d_octal", "d_decimal"]


@pytest.mark.parametrize("fname", _LAYER_DECODERS)
@pytest.mark.parametrize("seed", range(4))
def test_layered_byte_decoders_fail_closed(fname, seed):
    # layered_decode d_* take BYTES (the pipeline always feeds bytes); assert no uncaught crash
    fn = getattr(ld, fname)
    r = random.Random(seed + 7)
    inputs = [b"", b"A" * r.randrange(1, 200), bytes(r.randrange(256) for _ in range(r.randrange(0, 300))),
              b"0123456789abcdef" * r.randrange(1, 12), b"=" * r.randrange(1, 40),
              bytes(r.choice(b"01 \n") for _ in range(r.randrange(0, 200)))]
    for data in inputs:
        try:
            out = fn(data)
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
        except Exception as exc:
            pytest.fail(f"{fname} crashed on {data[:16]!r}...: {type(exc).__name__}: {exc}")
        assert out is None or isinstance(out, (bytes, bytearray))
