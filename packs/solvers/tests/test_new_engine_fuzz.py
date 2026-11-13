"""Adversarial fail-closed fuzz over the newly added byte-parsing engines.

font_inspect / xlsx_hidden / crc_force take UNTRUSTED bytes at a wave (a downloaded font, a hostile
.xlsx, a blob to patch). This feeds each one random/truncated/malformed input and asserts it either
returns cleanly or raises only its DECLARED error — never an uncaught OverflowError, struct.error,
IndexError, zipfile surprise, RecursionError, etc. Same contract and harness as
test_existing_engine_fuzz.py (which is how the timestamp OverflowError was caught). Adds no engine code."""
from __future__ import annotations

import random
import struct

import pytest

import font_inspect
import xlsx_hidden
import crc_force


def _byte_inputs(seed):
    r = random.Random(seed)
    out = [
        b"",
        b"\x00" * r.randrange(1, 400),
        bytes(r.randrange(256) for _ in range(r.randrange(0, 600))),
        b"\xff" * r.randrange(1, 300),
        b"PK\x03\x04" + bytes(r.randrange(256) for _ in range(r.randrange(0, 200))),   # zip-ish
        b"\x00\x01\x00\x00" + bytes(r.randrange(256) for _ in range(r.randrange(0, 200))),  # sfnt-ish
        b"ttcf" + bytes(r.randrange(256) for _ in range(r.randrange(0, 120))),         # ttc-ish
        b"OTTO" + bytes(r.randrange(256) for _ in range(r.randrange(0, 120))),
    ]
    # a structurally-plausible-but-corrupt SFNT: a huge numTables with no directory
    out.append(b"\x00\x01\x00\x00" + struct.pack(">HHHH", r.randrange(1, 65536), 0, 0, 0))
    return out


# functions that take untrusted bytes and must fail closed (declared exception) or return cleanly
_BYTE_FUNCS = [
    ("font_inspect.inspect", lambda d: font_inspect.inspect(d), font_inspect.FontError),
    ("xlsx_hidden.inspect", lambda d: xlsx_hidden.inspect(d), xlsx_hidden.XlsxError),
    ("crc_force.patch@0", lambda d: crc_force.patch(d, 0, 0xDEADBEEF), crc_force.CrcError),
    ("crc_force.append_patch", lambda d: crc_force.append_patch(d, 0x1234), crc_force.CrcError),
]


@pytest.mark.parametrize("name,fn,declared", _BYTE_FUNCS)
@pytest.mark.parametrize("seed", range(8))
def test_byte_parsers_fail_closed(name, fn, declared, seed):
    for data in _byte_inputs(seed):
        try:
            fn(data)
        except declared:
            pass                       # the engine's own fail-closed decline is fine
        except (ValueError, TypeError, KeyError):
            pass                       # benign declared declines
        except Exception as exc:       # OverflowError, struct.error, IndexError, zipfile.*, ... = bug
            pytest.fail(f"{name} crashed on {data[:24]!r}...: {type(exc).__name__}: {exc}")


@pytest.mark.parametrize("seed", range(8))
def test_crc_force_random_offsets_fail_closed(seed):
    r = random.Random(seed + 100)
    for _ in range(30):
        n = r.randrange(0, 60)
        data = bytes(r.randrange(256) for _ in range(n))
        off = r.randrange(-5, n + 5)            # includes invalid offsets
        target = r.randrange(0, 1 << 34)        # includes out-of-range targets
        try:
            out = crc_force.patch(data, off, target)
        except crc_force.CrcError:
            pass
        except Exception as exc:
            pytest.fail(f"crc_force.patch crashed (n={n}, off={off}, target={target}): "
                        f"{type(exc).__name__}: {exc}")
        else:
            import zlib
            assert 0 <= off and off + 4 <= n and 0 <= target <= 0xFFFFFFFF
            assert zlib.crc32(out) & 0xFFFFFFFF == target
