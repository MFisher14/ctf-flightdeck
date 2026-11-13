"""Regression tests for the 5 wrong-output bugs the second correctness-audit workflow confirmed.

Each was found by running the engine against an INDEPENDENT oracle (U-Boot image.h enum, the CC1101/TI
PN9 reference sequence, IEEE-1815 DNP3, WebKit epoch arithmetic) and adversarially verified. They lock
the fixes so these parsers emit the correct value rather than a plausible-but-wrong one.
"""
from __future__ import annotations

import datetime as _dt
import struct
import zlib

import ics_protocols
import firmware_containers
import rf_demod_full
import timeline

UTC = _dt.timezone.utc


# --- timeline.parse_timestamp: WebKit microseconds band [1e16, 5e16) dropped the 1601->1970 offset ----
def test_webkit_microseconds_band_keeps_epoch_offset():
    # 13331304000000000 us since 1601 == 2023-06-15T12:00:00Z; the bug returned year 2392 (~+369y).
    got = timeline.parse_timestamp(13331304000000000, field="visit_time")
    assert got == _dt.datetime(2023, 6, 15, 12, 0, 0, tzinfo=UTC), got


def test_webkit_named_and_unnamed_paths_agree():
    # the same value via a webkit/chrome-named field (the [1e15,1e16) / name path) must match the
    # unnamed-but-in-band path — they were inconsistent before the fix.
    v = 13331304000000000
    assert timeline.parse_timestamp(v, field="visit_time") == timeline.parse_timestamp(v, field="chrome_visit_time")


# --- firmware_containers.parse_uimage: _UBOOT_ARCH/_UBOOT_OS enum tables were wrong -------------------
def _uimage(os_id: int, arch_id: int, payload: bytes = b"\x00\x00\x00\x00") -> bytes:
    name = b"test".ljust(32, b"\x00")
    # big-endian >7I4B32s: magic, hdr_crc(0 for now), time, size, load, entry, data_crc, os, arch, type, comp, name
    body = struct.pack(">7I4B32s", 0x27051956, 0, 0, len(payload), 0, 0,
                       zlib.crc32(payload) & 0xFFFFFFFF, os_id, arch_id, 2, 0, name)
    hdr = bytearray(body)
    hdr[4:8] = b"\x00" * 4
    hdr_crc = zlib.crc32(bytes(hdr)) & 0xFFFFFFFF
    out = bytearray(body)
    out[4:8] = struct.pack(">I", hdr_crc)
    return bytes(out) + payload


def test_uimage_arch_enum_matches_uboot():
    for arch_id, arch in ((22, "arm64"), (26, "riscv"), (20, "nds32"), (2, "arm")):
        r = firmware_containers.parse_uimage(_uimage(5, arch_id))
        assert r["arch"] == arch, (arch_id, r["arch"])
        assert r["header_crc_ok"] and r["data_crc_ok"], r


def test_uimage_os_enum_matches_uboot():
    for os_id, os_name in ((16, "qnx"), (17, "u-boot"), (5, "linux"), (14, "vxworks")):
        r = firmware_containers.parse_uimage(_uimage(os_id, 22))
        assert r["os"] == os_name, (os_id, r["os"])


# --- rf_demod_full.pn9: LFSR tap was x^9+x^4+1 instead of the documented x^9+x^5+1 (CC1101/TI) --------
def test_pn9_matches_cc1101_reference():
    # canonical CC1101/TI PN9 whitening of an all-zero buffer
    assert rf_demod_full.pn9(b"\x00" * 16).hex() == "ffe11d9aed853324ea7ad2397097570a"


def test_pn9_is_self_inverse():
    msg = bytes(range(32))
    assert rf_demod_full.pn9(rf_demod_full.pn9(msg)) == msg


# --- ics_protocols DNP3 group 40 var 3: single-float decoded as a signed int -------------------------
def _dnp3_frag(group: int, variation: int, value_bytes: bytes) -> bytes:
    # object header: group, var, qualifier 0x00 (8-bit start/stop), range 0x00 0x00; then flag + value
    return bytes([0x81, 0x81, 0x00, 0x00, group, variation, 0x00, 0x00, 0x00]) + b"\x01" + value_bytes


def _first_point(frag: bytes):
    return ics_protocols.parse_dnp3_application(frag)["application"]["objects"][0]["points"][0]


def test_dnp3_group40_var3_is_float():
    pt = _first_point(_dnp3_frag(40, 3, struct.pack("<f", 3.14)))
    assert abs(pt["value"] - 3.14) < 1e-3, pt


def test_dnp3_group40_var1_still_int():
    # var 1 (32-bit int + flag) is also 4 value bytes — must stay on the int path (no over-correction)
    pt = _first_point(_dnp3_frag(40, 1, struct.pack("<i", 1234)))
    assert pt["value"] == 1234, pt


def test_dnp3_group30_var5_still_float():
    # analog-input float (the pre-existing correct path) must be unaffected
    pt = _first_point(_dnp3_frag(30, 5, struct.pack("<f", 2.5)))
    assert abs(pt["value"] - 2.5) < 1e-3, pt
