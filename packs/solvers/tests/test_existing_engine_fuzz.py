"""Function-level robustness fuzz over existing decoder/crypto/forensics engines.

The guarded-CLI audit exercises each CLI (which wraps errors); this fuzzes the public FUNCTIONS
directly with correct-type but adversarial VALUES (random/huge/malformed), asserting they fail closed
(no uncaught exception) — the way those functions are used when the autosolve layer chains them. This
is how the timestamp_decode OverflowError was caught. Adds no engine code."""
from __future__ import annotations

import random

import pytest

import codec_decoders
import wire_decode
import carve_stego
import qr_matrix
import blockchain
import pow_solver
import exotic_codecs

_RNG = random.Random(0xC0FFEE)


def _byte_inputs(seed):
    r = random.Random(seed)
    return [
        b"",
        b"\x00" * r.randrange(1, 300),
        bytes(r.randrange(256) for _ in range(r.randrange(0, 400))),
        b"\xff\xfe\xfd\xfc" * r.randrange(1, 60),
        b"A" * r.randrange(1, 500),
        (b"CSCTF{" + bytes(r.randrange(256) for _ in range(r.randrange(0, 40))) + b"}"),
        bytes([r.randrange(256)]) * r.randrange(1, 100),
    ]


def _str_inputs(seed):
    r = random.Random(seed + 1)
    pool = "0123456789abcdefABCDEF .:;|/\\-_{}[]\n\t\x00​￿áé中"
    return [
        "",
        "".join(r.choice(pool) for _ in range(r.randrange(0, 400))),
        "A" * r.randrange(1, 500),
        "0x" + "f" * r.randrange(1, 80),
        "::" * r.randrange(1, 50),
        "\x00\n" * r.randrange(1, 30),
    ]


# byte-input functions (object-typed ones also get fuzzed with bytes here)
_BYTE_FUNCS = [
    ("codec_decoders.decode_character_encodings", lambda d: codec_decoders.decode_character_encodings(d)),
    ("codec_decoders.decode_morse", lambda d: codec_decoders.decode_morse(d)),
    ("wire_decode.decode_protobuf", lambda d: wire_decode.decode_protobuf(d)),
    ("wire_decode.decode_cbor", lambda d: wire_decode.decode_cbor(d)),
    ("wire_decode.decode_grpc_frames", lambda d: wire_decode.decode_grpc_frames(d)),
    ("wire_decode.decode_msgpack", lambda d: wire_decode.decode_msgpack(d)),
    ("wire_decode.decode_bson", lambda d: wire_decode.decode_bson(d)),
    ("carve_stego.sniff", lambda d: carve_stego.sniff(d)),
    ("blockchain.parse_pubkey", lambda d: blockchain.parse_pubkey(d)),
    ("exotic_codecs.decode_semaphore", lambda d: exotic_codecs.decode_semaphore(d)),
    ("exotic_codecs.decode_nato_phonetic", lambda d: exotic_codecs.decode_nato_phonetic(d)),
    ("exotic_codecs.decode_keyboard_shift", lambda d: exotic_codecs.decode_keyboard_shift(d)),
]

# str-input functions
_STR_FUNCS = [
    ("qr_matrix.parse_ascii", lambda s: qr_matrix.parse_ascii(s)),
    ("qr_matrix.parse_ascii_rect", lambda s: qr_matrix.parse_ascii_rect(s)),
    ("qr_matrix.parse_dimensions", lambda s: qr_matrix.parse_dimensions(s)),
    ("qr_matrix.parse_corners", lambda s: qr_matrix.parse_corners(s)),
    ("blockchain.classify_eth_address", lambda s: blockchain.classify_eth_address(s)),
    ("blockchain.classify_btc_address", lambda s: blockchain.classify_btc_address(s)),
    ("pow_solver.parse_prompt", lambda s: pow_solver.parse_prompt(s)),
]


@pytest.mark.parametrize("name,fn", _BYTE_FUNCS)
@pytest.mark.parametrize("seed", range(6))
def test_byte_funcs_fail_closed(name, fn, seed):
    for data in _byte_inputs(seed):
        try:
            fn(data)
        except (ValueError, TypeError, KeyError) as exc:  # declared/benign declines are acceptable
            pass
        except Exception as exc:  # OverflowError, RecursionError, struct.error, UnicodeError, ... = bug
            pytest.fail(f"{name} crashed on {data[:16]!r}...: {type(exc).__name__}: {exc}")


@pytest.mark.parametrize("name,fn", _STR_FUNCS)
@pytest.mark.parametrize("seed", range(6))
def test_str_funcs_fail_closed(name, fn, seed):
    for s in _str_inputs(seed):
        try:
            fn(s)
        except (ValueError, TypeError, KeyError) as exc:
            pass
        except Exception as exc:
            pytest.fail(f"{name} crashed on {s[:16]!r}...: {type(exc).__name__}: {exc}")
