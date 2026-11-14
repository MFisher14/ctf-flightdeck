#!/usr/bin/env python3
"""Mobile: the APK container reader (apk_container.py, wired into codec_search.container_revise).

  .venv/bin/python tests/test_wave124_mobile_container.py

A code an APK hides at the container level, where the flat scans never reach: inside a NON-standard APK
Signing Block ID-value (base64/hex/zlib/gzip), or inside a ZIP local entry the central directory HIDES (a
local file header the CD does not reference) or MISDESCRIBES (a smaller compressed size than the local
header), with the entry DEFLATED/encoded. codec_search already finds a PLAIN code in the archive's own bytes
(`apk-string:archive`) and in every member, so this reader fires ONLY when no other reader found a code, and
only for a code that is not a contiguous plaintext run -- so it never duplicates the existing reading.

Never-wrong: every answer is a one-option pick under a route of its own, unsure until the judge accepts it;
two different hidden codes give None; a code under a standard signature ID or a data-descriptor entry gives
None; a package the usual reading already answers is never changed.

  [S] a non-standard signing-block ID-value, base64 / hex / zlib / gzip: unsure under apk-sigblock:<id>:<how>
      (+ :beside-analysis since the Day 27 so-ambig fix round 2: the document's prose `data` proves no code), the
      same under a Mastery's budget, plain once the route is accepted
  [Z] a hidden local entry (not in the central directory), deflated / base64 / gzip: unsure under
      apk-zip-hidden:<name>:<how> (+ :beside-analysis, as [S])
  [M] a misdescribed entry (local compressed size > the central directory's): read from the local header
  [2] two different hidden codes: None (nothing proves which is asked)
  [X] a code only under a STANDARD signature ID, a data-descriptor entry, a disagreeing size field: None
  [K] the usual reading is never changed: a normal reverse-codec document answers as before, even with a
      hidden container code present (the look-ahead / container readers do not fire when a code was found)
"""
import io
import struct
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mobile_codec_env as T  # noqa: E402  (its environment: a private ledger, no token, no network)

C, labels = T.C, T.labels
apk, doc, solve, options, check, fresh = T.apk, T.doc, T.solve, T.options, T.check, T.fresh
b64 = T.b64
import apk_container  # noqa: E402  (on sys.path via mobile_codec_env)

_SIG_MAGIC = b"APK Sig Block 42"
NONSTD_ID = 0x12AB_CD00          # not one of the Android signature / stamp / padding IDs
V2_ID = 0x7109871A               # a real APK Signature Scheme v2 block ID (standard: skipped)


def code_for(name):
    return T.code_for("wave124:" + name)


def _eocd_at(blob):
    i = blob.rfind(b"PK\x05\x06")
    cd_size, cd_off = struct.unpack_from("<II", blob, i + 12)
    return i, cd_size, cd_off


def _fix_eocd_offset(out, delta):
    ni = out.rfind(b"PK\x05\x06")
    cur = struct.unpack_from("<I", out, ni + 16)[0]
    struct.pack_into("<I", out, ni + 16, cur + delta)


def sign(blob, pairs):
    """Splice an APK Signing Block (the given (id, value) pairs) in just before the central directory."""
    _, _, cd_off = _eocd_at(blob)
    payload = b"".join(struct.pack("<Q", 4 + len(v)) + struct.pack("<I", pid) + v for pid, v in pairs)
    size = len(payload) + 8 + 16
    block = struct.pack("<Q", size) + payload + struct.pack("<Q", size) + _SIG_MAGIC
    out = bytearray(blob[:cd_off] + block + blob[cd_off:])
    _fix_eocd_offset(out, len(block))
    return bytes(out)


def _local_header(name, data, method="deflate", declared_comp=None):
    nb = name.encode()
    if method == "deflate":
        co = zlib.compressobj(9, zlib.DEFLATED, -15)
        comp = co.compress(data) + co.flush()
        m = 8
    else:
        comp, m = data, 0
    csize = len(comp) if declared_comp is None else declared_comp
    head = b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0, m, 0, 0,
                                       zlib.crc32(data) & 0xFFFFFFFF, csize, len(data), len(nb), 0) + nb
    return head + comp


def hide(blob, name, data, method="deflate"):
    """Splice a ZIP local entry the central directory never references (a hidden entry) before the CD."""
    _, _, cd_off = _eocd_at(blob)
    lfh = _local_header(name, data, method)
    out = bytearray(blob[:cd_off] + lfh + blob[cd_off:])
    _fix_eocd_offset(out, len(lfh))
    return bytes(out)


def unknown_doc():
    """A puzzle document whose codec no reader applies and whose data holds no code: the usual reading is None."""
    return doc("backend_only", "the answer is returned by the server for this case")


# Day 27 so-ambig fix round 2 (codec_search._beside_analysis, OPEN RISK 6): a package-look or container code beside a
# document whose payload does not prove it (this prose `data`) goes under `<its key>:beside-analysis`, a key of its own,
# so a name the judge accepts for it never answers another shape plain; it is still the one option, unsure until judged
BESIDE = C.BESIDE_ANALYSIS


def no_plain_code(blob):
    """Guard: the code is genuinely hidden -- no plaintext (ASCII or UTF-16LE) run anywhere in the archive."""
    return not apk_container._raw_codes(blob)


# ---------------------------------------------------------------------------- [S] signing block ID-values

def signing_block():
    for how, enc in (("base64", lambda c: b64(c.encode()).encode()),
                     ("hex", lambda c: c.encode().hex().encode()),
                     ("zlib", lambda c: zlib.compress(c.encode())),
                     ("gzip", lambda c: __import__("gzip").compress(c.encode()))):
        real = code_for("S-" + how)
        blob = sign(apk(unknown_doc()), [(NONSTD_ID, enc(real))])
        check("[S] %s: the hidden code is not plaintext in the archive" % how, no_plain_code(blob), real)
        route = "apk-sigblock:%08x:%s" % (NONSTD_ID, how)
        T.unsure("[S] signing-block id 0x%08x, %s" % (NONSTD_ID, how), blob, real,
                 "mobile.codec/" + route + BESIDE, route, rank=1)


# ---------------------------------------------------------------------------- [Z] hidden ZIP entries

def hidden_entry():
    for how, (name, method) in (("deflate", ("secret.bin", "deflate")),):
        real = code_for("Z-" + how)
        blob = hide(apk(unknown_doc()), name, real.encode(), method)
        check("[Z] deflate: zipfile cannot see the hidden entry",
              name not in C.read_members(blob)[0] and no_plain_code(blob), name)
        route = "apk-zip-hidden:%s" % name
        T.unsure("[Z] a hidden local entry %r, deflated" % name, blob, real,
                 "mobile.codec/" + route + BESIDE, route, rank=1)
    # a stored hidden entry whose bytes are base64 text of the code (deflate would also hide it, this proves the decode layer)
    real = code_for("Z-b64")
    blob = hide(apk(unknown_doc()), "payload.dat", b64(real.encode()).encode(), method="stored")
    check("[Z] base64: no plaintext code in the archive", no_plain_code(blob), real)
    route = "apk-zip-hidden:payload.dat:base64"
    T.unsure("[Z] a hidden stored entry holding base64 of the code", blob, real,
             "mobile.codec/" + route + BESIDE, route, rank=1)


# ---------------------------------------------------------------------------- [M] misdescribed entry (direct read)

def misdescribed():
    """A ZIP whose central directory records a SMALLER compressed size than the local header (a trailing hidden
    payload). Built by hand and read directly, since zipfile would write the two sizes equal."""
    real = code_for("M")
    inner = b64(real.encode()).encode()                 # base64 text, stored, so the local header carries it whole
    name = "data.blob"
    lfh = _local_header(name, inner, method="stored")   # local comp_size == len(inner)
    nb = name.encode()
    lh_off = 0
    cd = (b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", 20, 20, 0, 0, 0, 0,
                                      zlib.crc32(inner) & 0xFFFFFFFF, 4, len(inner), len(nb), 0, 0, 0, 0, 0, lh_off) + nb)
    # ^ the central directory records compressed size 4 (a lie): zipfile would read only 4 bytes, not the code
    cd_off = len(lfh)
    eocd = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, 1, 1, len(cd), cd_off, 0)
    blob = lfh + cd + eocd
    got, _ = apk_container.read(blob)
    check("[M] a misdescribed entry (local size > central-directory size) is read from the local header",
          got is not None and got["code"] == real and got["route"].startswith("apk-zip-mismatch:%s" % name),
          None if got is None else (got["code"], got["route"]))


# ---------------------------------------------------------------------------- [2] two codes / [X] negatives

def two_codes():
    a, b = code_for("2a"), code_for("2b")
    blob = sign(apk(unknown_doc()), [(NONSTD_ID, b64(a.encode()).encode()),
                                     (NONSTD_ID + 1, b64(b.encode()).encode())])
    fresh()
    out, err, last = solve(blob)
    check("[2] two different hidden codes: None", out is None and "different codes" in err,
          "%s | %s" % (out, last.get("route")))


def negatives():
    real = code_for("X")
    # a code under a STANDARD signature ID is never read from the signing block
    blob = sign(apk(unknown_doc()), [(V2_ID, b64(real.encode()).encode())])
    fresh()
    out, _, _ = solve(blob)
    check("[X] a code under a standard signature block id is None", out is None, out)
    # a data-descriptor entry (flag bit 3, no size in the local header) is skipped
    nb = b"desc.bin"
    inner = b64(real.encode()).encode()
    lfh = b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", 20, 0x0008, 0, 0, 0, 0, 0, 0, len(nb), 0) + nb + inner
    _, _, cd_off = _eocd_at(apk(unknown_doc()))
    base = apk(unknown_doc())
    out2 = bytearray(base[:cd_off] + lfh + base[cd_off:])
    _fix_eocd_offset(out2, len(lfh))
    got, _ = apk_container.read(bytes(out2))
    check("[X] a hidden entry that uses a data descriptor (no size in the header) is None", got is None, got)
    # a signing block whose two size fields disagree is not parsed
    blob = bytearray(sign(apk(unknown_doc()), [(NONSTD_ID, b64(real.encode()).encode())]))
    _, _, cd_off = _eocd_at(bytes(blob))
    struct.pack_into("<Q", blob, cd_off - 24, 999999)   # corrupt the trailing size
    got, notes = apk_container.read(bytes(blob))
    check("[X] a signing block whose size fields disagree is not parsed (None)",
          got is None and any("size" in n for n in notes), (got, notes))


# ---------------------------------------------------------------------------- [K] the usual reading is never changed

def never_changed():
    real = code_for("K")
    # a normal reverse-codec document: answered as before, and a hidden container code must NOT change it
    plain_doc = apk(doc("reverse", real[::-1]))
    fresh()
    base_out, _, _ = solve(plain_doc)
    check("[K] a normal reverse document answers its code (control)", base_out == real, base_out)
    hidden = sign(hide(plain_doc, "extra.bin", code_for("K-decoy").encode(), "deflate"),
                  [(NONSTD_ID, b64(code_for("K-decoy2").encode()).encode())])
    fresh()
    out, _, last = solve(hidden)
    check("[K] a hidden container code does NOT change the usual plain reading",
          out == real and not last.get("route", "").startswith("apk-sigblock") and not last.get("route", "").startswith("apk-zip"),
          "%s | %s" % (out, last.get("route")))


PARTS = (signing_block, hidden_entry, misdescribed, two_codes, negatives, never_changed)


@pytest.mark.parametrize("part", PARTS, ids=lambda f: f.__name__)
def test_wave124_mobile_container(part):
    T.run_part(part)


def main():
    return T.run_parts(PARTS)


if __name__ == "__main__":
    sys.exit(main())
