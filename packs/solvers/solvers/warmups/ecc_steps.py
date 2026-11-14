"""Self-validating ECC envelopes for the warmup auto-decoder.

Bare error-correcting codes are deliberately not auto-guessed: a beyond-radius corruption can be
closer to a different valid codeword. These explicit ASCII envelopes carry CRC-32 over the decoded
payload, so correction is promoted into the strict graph only after syndrome, re-encode *and* CRC.

  H84:<hex SECDED bytes>:<8-hex CRC32>
  RS<parity>:<hex GF(256/0x11d codeword>:<8-hex CRC32>
"""
from __future__ import annotations

import importlib.util
import re
import sys
import zlib
from pathlib import Path


MAX_TEXT = 1 << 20
_H84 = re.compile(rb"H84:([0-9A-Fa-f]+):([0-9A-Fa-f]{8})\s*\Z")
_RS = re.compile(rb"RS([1-9][0-9]{0,2}):([0-9A-Fa-f]+):([0-9A-Fa-f]{8})\s*\Z")


def _engine():
    name = "csctf_ecc_codes_for_warmups"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "toolkits" / "ecc_codes.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _crc(payload: bytes, written: bytes) -> bool:
    return f"{zlib.crc32(payload) & 0xffffffff:08x}".encode() == written.lower()


def d_hamming84(blob: bytes):
    if not isinstance(blob, bytes) or len(blob) > MAX_TEXT:
        return None
    match = _H84.fullmatch(blob)
    if not match or len(match.group(1)) % 2:
        return None
    try:
        words = bytes.fromhex(match.group(1).decode("ascii"))
    except ValueError:
        return None
    if not words or len(words) % 2:
        return None
    engine = _engine()
    if engine is None:
        return None
    nibbles = []
    for word in words:
        result = engine.hamming84_decode(word)
        if result is None or not result.zero_syndrome or not result.reencoded:
            return None
        nibbles.append(sum(bit << (3 - index) for index, bit in enumerate(result.data)))
    payload = bytes((nibbles[i] << 4) | nibbles[i + 1] for i in range(0, len(nibbles), 2))
    return payload if _crc(payload, match.group(2)) else None


def d_rs(blob: bytes):
    if not isinstance(blob, bytes) or len(blob) > MAX_TEXT:
        return None
    match = _RS.fullmatch(blob)
    if not match or len(match.group(2)) % 2:
        return None
    nsym = int(match.group(1))
    try:
        word = bytes.fromhex(match.group(2).decode("ascii"))
    except ValueError:
        return None
    engine = _engine()
    result = engine.rs_decode(word, nsym) if engine is not None else None
    if result is None or not result.zero_syndrome or not result.reencoded:
        return None
    payload = bytes(result.data)
    return payload if _crc(payload, match.group(3)) else None


BY_NAME = {"hamming84": d_hamming84, "rs_ecc": d_rs}
NAMES = frozenset(BY_NAME)


def steps(blob: bytes) -> list[tuple[str, bytes]]:
    if not isinstance(blob, bytes):
        return []
    names = ("hamming84",) if blob.startswith(b"H84:") else (("rs_ecc",) if blob.startswith(b"RS") else ())
    out = []
    for name in names:
        try:
            decoded = BY_NAME[name](blob)
        except (ValueError, TypeError, OverflowError, MemoryError, RecursionError):
            decoded = None
        if decoded:
            out.append((name, decoded))
    return out


def step_fn(name: str):
    return BY_NAME.get(name)
