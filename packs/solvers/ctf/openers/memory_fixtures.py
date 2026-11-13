"""Synthetic Linux memory images for the memory-forensics opener (B-136).

A Linux memory challenge is opened by one fact before any other: which kernel the image holds, and
whether a Volatility symbol table (ISF) for exactly that kernel is at hand. Spooky's Peering Eyes
shipped a LiME image and, beside it, the dwarf2json table of its kernel; the agent matched the two by
hand. These builders write that delivery shape from code, so `python -m ctf arm` checks the opener
(solvers/toolkits/vol_triage.py) does the match with no model:

  base      a LiME image (two physical ranges) whose kernel banner stands in the second range, and
            `symbols.json.xz` beside it: an ISF whose `linux_banner` symbol holds that banner the way
            dwarf2json writes it (base64 of the text, a line end and a NUL).
  variant   another kernel, on arm64, with two plain `.json` tables beside it: one made for another
            kernel and one for this one. The opener has to pick by banner, not by name or by order.
  foreign   control: the base image with a table that has the base's file name and the base's kernel
            RELEASE but another build (a different build number and date). Two builds of one release
            have different tables, so nothing may match.
  blank     control: a LiME image that holds no kernel banner, with the base's table beside it.

Nothing here is real memory: a range is zero bytes with a few strings in it. That is enough for the
no-tool stage (format, banner, table match); the Volatility stage needs a real kernel image and is
tested against a stand-in sandbox in tests/test_b136_vol_triage.py. Every builder is deterministic.
"""
from __future__ import annotations

import base64
import json
import lzma
import struct
from pathlib import Path

BANNER = ("Linux version 6.1.0-armed-amd64 (builder@synthetic) (gcc-12 (Synthetic 12.2.0) 12.2.0, "
          "GNU ld (Synthetic) 2.40) #1 SMP PREEMPT_DYNAMIC Synthetic 6.1.27-1 (2026-01-01)")
# The same release, another build: its table is NOT the base image's table.
FOREIGN_BANNER = BANNER.replace("#1 SMP", "#2 SMP").replace("(2026-01-01)", "(2026-02-02)")
VARIANT_BANNER = ("Linux version 5.15.0-variant-arm64 (build@synthetic) (gcc (Synthetic 11.4.0) 11.4.0, "
                  "GNU ld (Synthetic) 2.38) #7 SMP Thu Jan 1 00:00:00 UTC 2026")
PAGE = 4096


def lime(ranges) -> bytes:
    """A LiME image: for each (physical start, bytes) a 32-byte header (magic, version 1, start, end,
    8 reserved bytes) and the range's bytes."""
    out = bytearray()
    for start, body in ranges:
        out += b"EMiL" + struct.pack("<IQQ", 1, start, start + len(body) - 1) + bytes(8) + body
    return bytes(out)


def page(*strings: tuple[int, bytes]) -> bytes:
    """One zero page with each (offset, bytes) written into it."""
    buf = bytearray(PAGE)
    for at, text in strings:
        buf[at:at + len(text)] = text
    return bytes(buf)


def image(banner: str | None) -> bytes:
    """Two ranges: low memory with a boot string, and the range where the kernel's read-only data
    (the banner, then its line end and NUL) stands. banner=None leaves the banner out."""
    low = page((0x40, b"BOOT_IMAGE=/boot/vmlinuz-synthetic root=/dev/sda1 ro quiet\x00"))
    kernel = page((0x200, banner.encode("ascii") + b"\n\x00")) if banner else page((0x200, b"no kernel text here\x00"))
    return lime([(0x1000, low), (0x100000, kernel + bytes(PAGE))])


def isf(banner: str) -> bytes:
    """A Linux ISF in the shape dwarf2json writes: the `linux_banner` symbol is an array of char whose
    constant data is the base64 of the banner, a line end and a NUL."""
    raw = banner.encode("ascii") + b"\n\x00"
    doc = {
        "metadata": {"format": "6.2.0", "producer": {"name": "synthetic-dwarf2json", "version": "0.0.0"},
                     "linux": {"symbols": [{"kind": "dwarf", "name": "vmlinux-synthetic"}], "types": []}},
        "base_types": {"char": {"size": 1, "signed": True, "kind": "char", "endian": "little"},
                       "pointer": {"size": 8, "signed": False, "kind": "int", "endian": "little"}},
        "user_types": {"list_head": {"size": 16, "kind": "struct", "fields": {
            "next": {"type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "list_head"}}, "offset": 0}}}},
        "enums": {},
        "symbols": {
            "init_task": {"type": {"kind": "struct", "name": "task_struct"}, "address": 18446744071600106560},
            "linux_banner": {"type": {"count": len(raw), "kind": "array", "subtype": {"kind": "base", "name": "char"}},
                             "address": 18446744071594008672, "constant_data": base64.b64encode(raw).decode("ascii")},
        },
    }
    return json.dumps(doc, indent=1).encode("ascii")


def _write(dest: Path, name: str, data: bytes) -> Path:
    dest.mkdir(parents=True, exist_ok=True)
    p = dest / name
    p.write_bytes(data)
    return p


def _xz(data: bytes) -> bytes:
    return lzma.compress(data, format=lzma.FORMAT_XZ, preset=6)


def memory_lime_with_table(dest: Path) -> Path:
    """Base: the LiME image and, beside it, the xz-compressed table of its own kernel."""
    _write(dest, "symbols.json.xz", _xz(isf(BANNER)))
    return _write(dest, "mem.lime", image(BANNER))


def memory_lime_two_tables(dest: Path) -> Path:
    """Variant: another kernel (arm64) with two plain tables beside it; only one was made for it."""
    _write(dest, "a-other-kernel.json", isf(BANNER))
    _write(dest, "kernel-5.15.0.json", isf(VARIANT_BANNER))
    return _write(dest, "capture.lime", image(VARIANT_BANNER))


def memory_lime_foreign_table(dest: Path) -> Path:
    """Control: the base image; the table beside it has the base's name and release, another build."""
    _write(dest, "symbols.json.xz", _xz(isf(FOREIGN_BANNER)))
    return _write(dest, "mem.lime", image(BANNER))


def memory_lime_no_banner(dest: Path) -> Path:
    """Control: a LiME image with no kernel banner in it, and the base's table beside it."""
    _write(dest, "symbols.json.xz", _xz(isf(BANNER)))
    return _write(dest, "mem.lime", image(None))


BUILDERS = {
    "memory_lime_with_table": memory_lime_with_table,
    "memory_lime_two_tables": memory_lime_two_tables,
    "memory_lime_foreign_table": memory_lime_foreign_table,
    "memory_lime_no_banner": memory_lime_no_banner,
}
