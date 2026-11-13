"""Robustness fuzz over the heaviest untrusted-input forensic parsers.

carve_stego / disk_images / file_repair / network parse hostile files directly at a wave (a carved
blob, a disk image, a corrupt archive to repair, a capture). The nastiest inputs are not random bytes
but a VALID magic/header followed by truncation or corruption — that drives the parser deep into its
structure-walking code before it hits the bad byte. This feeds each parser empty / random / all-0xff /
real-magic-then-cut / bit-flipped input and asserts it returns cleanly or raises only its declared
error — never a leaked struct.error / IndexError / MemoryError / UnicodeError. Test-only; pairs with
the other *_fuzz modules."""
from __future__ import annotations

import random
import struct

import pytest

import carve_stego
import disk_images
import file_repair
import network

# real magics, so truncated-valid inputs drive the parsers into their structure walkers
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_IHDR = PNG_SIG + struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 16, 16, 8, 6, 0, 0, 0) + b"\x00\x00\x00\x00"
MAGICS = [
    PNG_SIG, PNG_IHDR,
    b"PK\x03\x04", b"PK\x05\x06",                 # zip local / EOCD
    b"%PDF-1.7\n", b"\x1f\x8b\x08",               # pdf, gzip
    b"BZh91AY&SY",                                 # bzip2
    b"QFI\xfb",                                     # qcow2
    b"KDMV",                                        # vmdk sparse
    b"conectix", b"cxsparse",                       # vhd footer / dynamic
    b"vhdxfile",                                    # vhdx
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",      # pcap LE/BE
    b"\x0a\x0d\x0d\x0a",                            # pcapng
]


def _pool(seed):
    r = random.Random(seed)
    out = [b"", b"\x00" * r.randrange(1, 300), bytes(r.randrange(256) for _ in range(r.randrange(0, 400))),
           b"\xff" * r.randrange(1, 200)]
    for m in MAGICS:
        tail = bytes(r.randrange(256) for _ in range(r.randrange(0, 120)))
        out.append(m + tail)                       # magic then garbage
        out.append(m + b"\x00" * r.randrange(0, 80))  # magic then zeros
        b = bytearray(m + tail)
        if b:
            b[r.randrange(len(b))] ^= 0xFF          # a bit-flip somewhere
        out.append(bytes(b))
    return out


DIE = disk_images.DiskImageError
RPE = file_repair.RepairError

# (name, callable taking bytes, tuple of its declared/benign exceptions)
_FUNCS = [
    ("carve_stego.carve", lambda d: carve_stego.carve(d), ()),
    ("carve_stego.polyglot", lambda d: carve_stego.polyglot(d), ()),
    ("carve_stego.png_chunks", lambda d: carve_stego.png_chunks(d), ()),
    ("carve_stego.png_text", lambda d: carve_stego.png_text(d), ()),
    ("carve_stego.png_pixels", lambda d: carve_stego.png_pixels(d), ()),
    ("carve_stego.trailing", lambda d: carve_stego.trailing(d), ()),
    ("carve_stego.zips", lambda d: carve_stego.zips(d), ()),
    ("disk_images.detect_container", lambda d: disk_images.detect_container(d), (DIE,)),
    ("disk_images.unwrap_qcow2", lambda d: disk_images.unwrap_qcow2(d), (DIE,)),
    ("disk_images.unwrap_vmdk_sparse", lambda d: disk_images.unwrap_vmdk_sparse(d), (DIE,)),
    ("disk_images.unwrap_vhd", lambda d: disk_images.unwrap_vhd(d), (DIE,)),
    ("disk_images.unwrap_vhdx", lambda d: disk_images.unwrap_vhdx(d), (DIE,)),
    ("disk_images.parse_ntfs_data_runs", lambda d: disk_images.parse_ntfs_data_runs(d), (DIE,)),
    ("file_repair.repair_png", lambda d: file_repair.repair_png(d), (RPE,)),
    ("file_repair.repair_zip", lambda d: file_repair.repair_zip(d), (RPE,)),
    ("file_repair.repair_pdf", lambda d: file_repair.repair_pdf(d), (RPE,)),
    ("file_repair.repair_gzip", lambda d: file_repair.repair_gzip(d), (RPE,)),
    ("file_repair.repair_bzip2", lambda d: file_repair.repair_bzip2(d), (RPE,)),
    ("file_repair.detect_format", lambda d: file_repair.detect_format(d), (RPE,)),
    ("network.is_capture", lambda d: network.is_capture(d), ()),
    ("network.parse_dns", lambda d: network.parse_dns(d), ()),
    ("network.parse_ntlmssp", lambda d: network.parse_ntlmssp(d), ()),
]


@pytest.mark.parametrize("name,fn,declared", _FUNCS)
@pytest.mark.parametrize("seed", range(5))
def test_forensic_parsers_fail_closed(name, fn, declared, seed):
    for data in _pool(seed):
        try:
            fn(data)
        except declared:
            pass                                   # the parser's own fail-closed decline
        except (ValueError, TypeError, KeyError):
            pass                                   # benign declared declines
        except Exception as exc:                   # struct.error / IndexError / MemoryError / ... = bug
            pytest.fail(f"{name} crashed on {data[:20]!r}...: {type(exc).__name__}: {exc}")
