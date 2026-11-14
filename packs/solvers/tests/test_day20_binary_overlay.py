#!/usr/bin/env python3
"""Pins the review fix of backlog row 366 (commit 3fc2a61) in solvers/binary/generic.py: the trailing packed
overlay's magic OFFSET is answered only when it is pinned.

  .venv/bin/python tests/test_day20_binary_overlay.py

The SHA-256 gate of _overlay_record pins the UNPACKED payload, not where the magic sits: under a key-independent
transform (identity) every header layout of OVERLAY_LAYOUTS whose window fits SHA-matches the same packed bytes,
so before the fix the first layout tried, (44, 5, 6), gave an offset 2 bytes early, PLAIN (a wrong plain answer
that sinks the batch). The record built here is the reviewer's shape: the bare (42, 4, 5) layout
<magic><k1><k2><u32le len><sha256(32)><packed> with the identity transform.

1. With a non-printable byte before the magic only the true offset begins with a printable tag: the offset is
   the true one, and analysis_overlay_offset / analysis_overlay_size answer it plain.
2. With printable bytes before the magic all three candidate offsets read as a printable tag: the offset is
   None, and analysis_overlay_offset / analysis_overlay_size answer None with the reason (never the wrong one).
3. Both ways the payload (a CRC-valid HCFG record) is recovered whole, and _overlay_layers hands it on.
4. A member whose stored digest does not verify gives nothing.

Offline, no token, under a second. Prints one line per check and `ok N passed` at the end; exits 1 on a failure.
"""
import contextlib
import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_day20_binary_overlay_"))
sys.dont_write_bytecode = True
os.environ["CTF_STATE_DIR"] = str(TMP / "state")
os.environ["CTF_WORKDIR"] = str(TMP / "challenges")
os.environ.pop("CTF_PLATFORM_URL", None)
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(REPO / "solvers" / "binary"))
import generic   # noqa: E402
import hcfg      # noqa: E402

CONFIG = {"campaign": "overlay-pin-20", "url": "https://example.invalid/c2", "mutex": "Global\\ov20"}
FAILED = []
PASSED = []


def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"   [{str(detail)[:400]}]"))
    (PASSED if ok else FAILED).append(name)


def hcfg_record(cfg: dict, key: int = 0x5A) -> bytes:
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    return b"HCFG" + struct.pack("<BBHI", 1, key, len(plain), zlib.crc32(plain)) + bytes(b ^ key for b in plain)


def member(before: bytes, payload: bytes, magic: bytes = b"RS20", k1: int = 0x13, k2: int = 0x37,
           digest: bytes = None) -> tuple:
    """(member bytes, true magic offset): a body, `before`, then a (42, 4, 5) identity overlay to EOF."""
    body = b"\x7fELF" + bytes(range(256)) * 2
    at = len(body) + len(before)
    rec = magic + bytes([k1, k2]) + struct.pack("<I", len(payload)) + (digest or hashlib.sha256(payload).digest())
    assert len(rec) == 42
    return body + before + rec + payload, at


def field(data: bytes, name: str):
    with contextlib.redirect_stderr(io.StringIO()):
        return generic.answer_field("d20", name, [("d20--sample", data)], "d20--sample", data, {}, {},
                                    lambda: set())


def crc_configs(blob: bytes) -> list:
    return [c["json"] for c in hcfg.containers(blob, others=True) if c["crc_ok"]]


def main() -> int:
    payload = hcfg_record(CONFIG)

    # 1. a non-printable byte before the magic: the offset is pinned to the true one
    data, true_at = member(b"\x00\x00", payload)
    generic._OVERLAY_CACHE.clear()
    rec = generic._overlay_record(data)
    check("pinned: _overlay_record finds the overlay", rec is not None, rec)
    check("pinned: the offset is the true magic offset (the (42, 4, 5) layout), not a layout-order accident",
          rec is not None and rec[0] == true_at, (rec and rec[0], true_at))
    check("pinned: the payload is recovered byte for byte", rec is not None and rec[1] == payload)
    check("pinned: the payload is the CRC-valid config", rec is not None and crc_configs(rec[1]) == [CONFIG],
          rec and crc_configs(rec[1]))
    off = field(data, "analysis_overlay_offset")
    size = field(data, "analysis_overlay_size")
    check("pinned: analysis_overlay_offset answers the true offset plain", off == (str(true_at), None), off)
    check("pinned: analysis_overlay_size answers the member length minus it", size == (str(len(data) - true_at), None),
          size)
    layers = generic._overlay_layers(data)
    check("pinned: _overlay_layers names the offset and hands on the payload",
          layers == [(f"overlay@0x{true_at:x}", payload)], [(h, len(b)) for h, b in layers])

    # 2. printable bytes before the magic: every candidate reads as a tag, so the offset is not answered
    data2, true_at2 = member(b"AB", payload)
    generic._OVERLAY_CACHE.clear()
    rec2 = generic._overlay_record(data2)
    check("ambiguous: _overlay_record still finds the overlay", rec2 is not None, rec2)
    check("ambiguous: the offset is None (never the wrong layout's offset)", rec2 is not None and rec2[0] is None,
          rec2 and rec2[0])
    check("ambiguous: the payload is still recovered byte for byte", rec2 is not None and rec2[1] == payload)
    check("ambiguous: the payload is the CRC-valid config", rec2 is not None and crc_configs(rec2[1]) == [CONFIG])
    off2 = field(data2, "analysis_overlay_offset")
    size2 = field(data2, "analysis_overlay_size")
    check("ambiguous: analysis_overlay_offset answers None with the not-pinned reason",
          off2[0] is None and "not uniquely pinned" in (off2[1] or ""), off2)
    check("ambiguous: analysis_overlay_size answers None too", size2[0] is None and "not uniquely pinned" in (size2[1] or ""),
          size2)
    check("ambiguous: neither answer is the wrong offset of the first layout tried",
          str(true_at2 - 2) not in (off2[0], size2[0]), (off2, size2))
    layers2 = generic._overlay_layers(data2)
    check("ambiguous: _overlay_layers still hands on the payload, as overlay@?",
          layers2 == [("overlay@?", payload)], [(h, len(b)) for h, b in layers2])

    # 4. a digest that does not verify: nothing at all
    data3, _ = member(b"\x00\x00", payload, digest=b"\x11" * 32)
    generic._OVERLAY_CACHE.clear()
    check("unverified digest: no overlay record", generic._overlay_record(data3) is None)
    off3 = field(data3, "analysis_overlay_offset")
    check("unverified digest: analysis_overlay_offset answers None", off3[0] is None, off3)

    print(f"ok {len(PASSED)} passed" if not FAILED else f"{len(FAILED)} check(s) failed, {len(PASSED)} passed")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
