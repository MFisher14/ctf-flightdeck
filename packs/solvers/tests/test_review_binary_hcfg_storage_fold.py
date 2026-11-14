#!/usr/bin/env python3
"""Independent adversarial review of the Day-24 hcfg_storage fold.

Covers solvers/binary/hcfg_storage.py (answer/detect), the field_catalog HCFG_CAMPAIGN_ANY
change, and evidence.folded_storage.  It is also a standalone acceptance test: the
``__main__`` path runs the same parametrized cases pytest collects, so invoking this file
directly cannot silently skip its assertions.

The original review found a cross-day divergence.  The shipped detector now mirrors the
field-catalog day guard; the regression below requires both paths, including the evidence
fallback used by the runtime, to refuse a lone record belonging to another day.
"""
import base64
import gzip
import json
import os
import struct
import sys
import zlib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "solvers", "binary"))
sys.path.insert(0, os.path.join(ROOT, "solvers", "common"))

import hcfg_storage  # noqa: E402
import field_catalog  # noqa: E402


def rec(camp="BR14-000", key=0x5A, version=1, extra=None):
    obj = {"campaign": camp}
    if extra:
        obj.update(extra)
    plain = json.dumps(obj, separators=(",", ":")).encode()
    crc = zlib.crc32(plain) & 0xFFFFFFFF
    enc = bytes(b ^ key for b in plain)
    return b"HCFG" + bytes([version, key]) + struct.pack("<HI", len(plain), crc) + enc


def ans(files, qid="d14_analysis_hcfg_storage"):
    return hcfg_storage.answer({"qid": qid}, files)


# ---------------------------------------------------------------- base64 is the only plain path
def test_base64_day_record_is_plain():
    assert ans({"d14.elf": base64.b64encode(rec("BR14-000"))}) == "base64"


def test_base64_timed_variant_campaign_is_plain():
    # BR14-EFF84CEB: the 8-hex variant suffix HCFG_CAMPAIGN_ANY was added for.
    assert ans({"d14.elf": base64.b64encode(rec("BR14-EFF84CEB"))}) == "base64"


def test_urlsafe_base64_is_plain():
    assert ans({"d14.bin": base64.urlsafe_b64encode(rec("BR14-000"))}) == "base64"


# ---------------------------------------------------------------- unsure layers never go plain
@pytest.mark.parametrize("member", [
    rec("BR14-000"),                                           # raw / verbatim
    base64.b32encode(rec("BR14-000")),                         # base32
    rec("BR14-000").hex().encode(),                            # hex
    zlib.compress(rec("BR14-000")),                            # zlib
    # gzip; mtime pinned: the bytes are the test id, and a header timestamp made xdist workers that
    # collected in different seconds disagree on the ids ("Different tests were collected") (R-01)
    gzip.compress(rec("BR14-000"), mtime=0),
    base64.b64encode(rec("BR14-000")).decode().encode("utf-16-le"),   # utf16 base64
    rec("BR14-000").hex().encode().decode("ascii").encode("utf-16-le"),  # utf16 hex
])
def test_nonbase64_layers_are_unsure_never_plain(member):
    v = ans({"d14.bin": member})
    assert isinstance(v, str) and v.startswith("??"), v


def test_const_array_source_is_unsure():
    arr = ",".join(str(b) for b in rec("BR14-000")).encode()
    v = ans({"d14.c": b"unsigned char cfg[] = {" + arr + b"};"})
    assert v is not None and v.startswith("??") and "raw_const_array" in v


# ---------------------------------------------------------------- malformed / broken -> None
@pytest.mark.parametrize("files,qid", [
    ({}, "d14_analysis_hcfg_storage"),                                           # no members
    ({"d14.bin": rec("BR14-000")[:-5]}, "d14_analysis_hcfg_storage"),            # truncated
    ({"d14.bin": b"XCFG" + rec("BR14-000")[4:]}, "d14_analysis_hcfg_storage"),   # wrong magic
    ({"d14.elf": base64.b64encode(rec())}, "d14_analysis_format"),               # not a storage qid
])
def test_broken_or_irrelevant_is_none(files, qid):
    assert ans(files, qid) is None


def test_bad_crc_is_none():
    bad = bytearray(rec("BR14-000"))
    bad[8] ^= 0xFF  # corrupt the stored CRC-32
    assert ans({"d14.bin": bytes(bad)}) is None
    assert ans({"d14.bin": base64.b64encode(bytes(bad))}) is None


def test_two_disagreeing_configs_is_none():
    a = base64.b64encode(rec("BR14-000"))
    b = rec("BR99-AAA", key=0x11, extra={"z": 1})
    files = {"d14.bin": a + b"\x00" * 8 + b}
    assert ans(files) is None

    import evidence
    qid = "d14_analysis_hcfg_storage"
    got = evidence.folded_storage([{"qid": qid}], {qid: None}, files, {})
    assert got[qid] is None


def test_oversized_rare_layer_guarded_and_none():
    big = bytearray(zlib.compress(rec("BR14-000"))) + b"\x00" * (33 << 20)
    assert ans({"d14.bin": bytes(big)}) is None


# ---------------------------------------------------------------- never overrides an existing answer
def test_answer_only_fills_none_through_fold():
    import evidence
    qs = [{"qid": "d14_analysis_hcfg_storage"}]
    files = {"d14.bin": base64.b64encode(rec("BR14-000"))}
    # an id already answered is left untouched by folded_storage
    got = evidence.folded_storage(qs, {"d14_analysis_hcfg_storage": "raw"}, files, {})
    assert got["d14_analysis_hcfg_storage"] == "raw"
    # a None id is filled
    got = evidence.folded_storage(qs, {"d14_analysis_hcfg_storage": None}, files, {})
    assert got["d14_analysis_hcfg_storage"] == "base64"


def test_setN_prefix_stripped_by_fold():
    import evidence
    qs = [{"qid": "set3.d14_analysis_hcfg_storage"}]
    files = {"d14.bin": base64.b64encode(rec("BR14-000"))}
    got = evidence.folded_storage(qs, {"set3.d14_analysis_hcfg_storage": None}, files, {})
    assert got["set3.d14_analysis_hcfg_storage"] == "base64"


# ---------------------------------------------------------------- HCFG_CAMPAIGN_ANY did not loosen others
def test_campaign_any_used_only_in_r_hcfg_storage():
    src = open(os.path.join(ROOT, "solvers", "binary", "field_catalog.py")).read()
    # one definition + exactly one use
    assert src.count("HCFG_CAMPAIGN_ANY.fullmatch") == 1
    # the strict form is still what every other reader uses
    assert src.count("HCFG_CAMPAIGN.fullmatch") >= 4


# ---------------------------------------------------------------- cross-day records fail closed
def test_wrong_day_base64_is_none_on_detector_catalog_and_runtime_fold():
    """A CRC-valid record of another day is not the asked day's storage fact."""
    member = base64.b64encode(rec("BR99-DEADBEEF"))   # day-99 record, asked as d14
    files = {"d14--variant.bin": member}
    assert ans(files, "d14_analysis_hcfg_storage") is None

    S = field_catalog.Sample("d14--variant.bin", member)
    S.day = 14
    assert field_catalog.r_hcfg_storage(S, {"kind": "exact_text"}, None) is None

    import evidence
    qid = "d14_analysis_hcfg_storage"
    got = evidence.folded_storage([{"qid": qid}], {qid: None}, files, {})
    assert got[qid] is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
