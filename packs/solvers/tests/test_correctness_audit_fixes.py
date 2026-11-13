"""Regression tests for the 4 wrong-output bugs the correctness-audit workflow confirmed.

Each was found by running the engine against an INDEPENDENT oracle (reference lib / published
vector / exact integer arithmetic) and adversarially verified. These lock the fixes so the
engines emit the correct value, not a plausible-but-wrong one that would mislead a solve.
"""
from __future__ import annotations

import base64
import datetime as _dt

import asn1_reader
import matrix_barcodes
import timestamp_decode


# --- asn1_reader.classify: armored PGP keys must route to kind='pgp', not 'key' ---------------
# The armor labels 'PGP PUBLIC KEY BLOCK' / 'PGP PRIVATE KEY BLOCK' contain the substrings
# 'PUBLIC KEY' / 'PRIVATE KEY'; the generic-key branch used to swallow them before the PGP branch.
def _armor(label: str) -> bytes:
    # syntactically-valid ASCII armor with real base64 so pem_blocks yields the block; the body
    # need not be semantically meaningful — classify routes on the label, which is the bug's locus.
    body = base64.b64encode(bytes(range(48))).decode()
    return (f"-----BEGIN {label}-----\n\n{body}\n-----END {label}-----\n").encode()


def test_armored_pgp_public_key_routes_to_pgp():
    out = asn1_reader.classify(_armor("PGP PUBLIC KEY BLOCK"))
    assert out is not None and out["kind"] == "pgp", out


def test_armored_pgp_private_key_routes_to_pgp():
    out = asn1_reader.classify(_armor("PGP PRIVATE KEY BLOCK"))
    assert out is not None and out["kind"] == "pgp", out


def test_real_pkcs_public_key_still_routes_to_key():
    # a non-PGP PUBLIC KEY label must still reach the DER key reader (no regression).
    out = asn1_reader.classify(_armor("PUBLIC KEY"))
    assert out is not None and out["kind"] == "key", out


# --- asn1_reader._der_time: UTCTime 2-digit-year pivot at 50 (RFC 5280), not strptime's 69 -----
def test_utctime_pivot_1950s():
    # YY=55 -> 1955 (pivot at 50), the POSIX-69 bug yielded 2055.
    body = b"550101000000Z"
    dt = asn1_reader._der_time(body, 0, len(body))
    assert dt is not None and dt.year == 1955, dt


def test_utctime_pivot_boundary_and_2000s():
    for yy, year in ((50, 1950), (49, 2049), (68, 1968), (69, 1969), (0, 2000)):
        body = f"{yy:02d}0101000000Z".encode()
        dt = asn1_reader._der_time(body, 0, len(body))
        assert dt is not None and dt.year == year, (yy, dt)


def test_generalizedtime_4digit_year_unaffected():
    body = b"20550101000000Z"
    dt = asn1_reader._der_time(body, 0, len(body))
    assert dt is not None and dt.year == 2055, dt


# --- timestamp_decode: sub-microsecond tick formats use exact integer division ------------------
def _utc_of(fmt_prefix: str, value: int) -> str:
    rows = timestamp_decode.decode(value, min_year=1900, max_year=2100)
    hits = [r["utc"] for r in rows if r["format"].startswith(fmt_prefix)]
    assert hits, (fmt_prefix, rows)
    return hits[0]


def test_filetime_microsecond_exact():
    # 132537600001234567 ticks (100ns) since 1601 == 2020-12-30T00:00:00.123456 UTC exactly.
    ft = 132537600001234567
    expected = EPOCH_1601 + _dt.timedelta(microseconds=ft // 10)
    got = _utc_of("windows_filetime", ft)
    assert got == expected.isoformat(), (got, expected.isoformat())
    assert got.endswith("00:00:00.123456+00:00"), got


def test_unix_nanos_microsecond_exact():
    ns = 1609286400123456789  # 2021-01-01-ish, sub-us digits present
    expected = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(microseconds=ns // 1000)
    got = _utc_of("unix_nanos", ns)
    assert got == expected.isoformat(), (got, expected.isoformat())


# --- matrix_barcodes Data Matrix ECI: trailing codewords carry a -1 offset (ISO/IEC 16022) ------
def _encode_eci(eci: int) -> list[int]:
    """ISO/IEC 16022 ECI -> codewords (the independent oracle; NOT the engine's own code)."""
    if eci <= 126:
        return [eci + 1]
    if eci <= 16382:
        v = eci - 127
        return [v // 254 + 128, v % 254 + 1]
    v = eci - 16383
    return [v // 64516 + 192, (v // 254) % 254 + 1, v % 254 + 1]


def _decoded_eci(eci: int) -> int:
    words = [241] + _encode_eci(eci) + [129]  # 241 = ECI latch, 129 = pad/EOM
    segs = [s for s in matrix_barcodes._dm_payload(words)["segments"] if s.get("mode") == "eci"]
    assert segs, words
    return segs[0]["assignment"]


def test_datamatrix_eci_roundtrips_each_regime():
    # one-, two-, and three-codeword ECIs must all decode back to the encoded value.
    for eci in (3, 20, 26, 126, 127, 1000, 16382, 16383, 100000):
        assert _decoded_eci(eci) == eci, eci


def test_datamatrix_eci_two_codeword_offset():
    # ECI 1000 -> codewords [131, 112]; the bug decoded it to 1001 (missing -1 on cw2).
    assert _decoded_eci(1000) == 1000


def test_datamatrix_eci_three_codeword_offset():
    # ECI 16383 -> [192, 1, 1]; the bug decoded it to 16638 (missing -1 on cw2 and cw3).
    assert _decoded_eci(16383) == 16383


EPOCH_1601 = _dt.datetime(1601, 1, 1, tzinfo=_dt.timezone.utc)
