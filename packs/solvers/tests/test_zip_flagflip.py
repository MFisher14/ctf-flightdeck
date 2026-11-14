#!/usr/bin/env python3
"""solvers/common/zip_flagflip.py (Doc1 ticket C4): CRC-gated, lane-agnostic recovery of zip
members with the encryption flag set on plaintext.

  .venv/bin/python tests/test_zip_flagflip.py

Fixtures are built with the stdlib `zipfile`, then rewritten by hand to set general-purpose bit 0
(the encryption flag) in the local and central headers, or to corrupt a body byte, or to mark a
member AES (compress_type 99); a real WinZip-AES member is added with pyzipper when it is present.
The checks exercise the AMBIGUOUS case on purpose, not just the easy single-plain-member case:
  - a STORED member with the encryption bit set but a valid CRC reads PLAIN (crc_ok True), and a
    DEFLATE one does too;
  - a one-byte-corrupted body => None (crc_ok False), with the flag set (encrypted STOP path) and
    with the flag clear (damaged), so the CRC gate is what rejects it, not the flag;
  - a truly AES member (real pyzipper AES and a crafted method-99 member) => no recovery, on the
    STOP path, never guessed;
  - a mixed archive where only some members recover: member_count is the byte-exact
    central-directory entry count (directories included), NEVER the count that recovered.
"""
import io
import struct
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "solvers" / "common"))
import zip_flagflip as zf  # noqa: E402

try:
    import pyzipper  # noqa: E402
except Exception:
    pyzipper = None

FAILS = []


def check(name, ok, detail=""):
    if not ok:
        FAILS.append(name)
    print(("ok   " if ok else "FAIL ") + name + ("" if ok or not detail else f"  [{str(detail)[:600]}]"),
          flush=True)


# --- fixture helpers (independent of the module under test) -------------------------------------

def build_zip(members):
    """members: [(name, bytes, method)] where method is 0 (stored) or 8 (deflate). Returns bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body, method in members:
            zi = zipfile.ZipInfo(name)
            zi.compress_type = method
            z.writestr(zi, body)
    return buf.getvalue()


def _cd_iter(data):
    """Yield (central_header_offset, name, local_header_offset) for each central-directory entry,
    assuming no prefix (zipfile output). Independent of zip_flagflip."""
    eo = data.rfind(b"PK\x05\x06")
    total = struct.unpack_from("<H", data, eo + 10)[0]
    p = struct.unpack_from("<I", data, eo + 16)[0]
    for _ in range(total):
        assert data[p:p + 4] == b"PK\x01\x02"
        name_len = struct.unpack_from("<H", data, p + 28)[0]
        extra_len = struct.unpack_from("<H", data, p + 30)[0]
        comment_len = struct.unpack_from("<H", data, p + 32)[0]
        lho = struct.unpack_from("<I", data, p + 42)[0]
        name = data[p + 46:p + 46 + name_len].decode("utf-8", "replace")
        yield p, name, lho
        p += 46 + name_len + extra_len + comment_len


def set_encryption_bit(data, target):
    """Set GP bit 0 in the local and central headers of member `target`. CRC is untouched, so a
    stored/deflate body stays valid: this is exactly the pseudo-encryption flag flip."""
    b = bytearray(data)
    for cho, name, lho in _cd_iter(data):
        if name == target:
            b[cho + 8] |= 0x01        # central header general-purpose flag
            b[lho + 6] |= 0x01        # local header general-purpose flag
    return bytes(b)


def set_method_99(data, target):
    """Mark member `target` as WinZip AES (compress_type 99) in both headers, and set its
    encryption bit, without any real ciphertext: enough to exercise the AES branch."""
    b = bytearray(data)
    for cho, name, lho in _cd_iter(data):
        if name == target:
            b[cho + 8] |= 0x01
            b[lho + 6] |= 0x01
            struct.pack_into("<H", b, cho + 10, 99)
            struct.pack_into("<H", b, lho + 8, 99)
    return bytes(b)


def corrupt_body(data, target):
    """Flip one byte of member `target`'s stored/compressed body."""
    b = bytearray(data)
    for cho, name, lho in _cd_iter(data):
        if name == target:
            ln = struct.unpack_from("<H", data, lho + 26)[0]
            le = struct.unpack_from("<H", data, lho + 28)[0]
            body = lho + 30 + ln + le
            b[body] ^= 0xFF
    return bytes(b)


# --- tests --------------------------------------------------------------------------------------

def test_flagflip_reads_plain():
    secret = b"TOP SECRET PAYLOAD, flag{not-really-encrypted}"
    data = build_zip([("secret.txt", secret, 0)])
    data = set_encryption_bit(data, "secret.txt")

    # the stdlib refuses it without a password, which is why a plain skip is blind to it
    refused = False
    try:
        zipfile.ZipFile(io.BytesIO(data)).read("secret.txt")
    except RuntimeError:
        refused = True
    check("the stdlib zip module refuses the flagged member (the gap this module closes)", refused)

    rows = zf.recover_members(data)
    row = rows[0]
    check("stored + encryption bit + valid CRC recovers plain (crc_ok True, bytes match)",
          row["crc_ok"] and row["data"] == secret, row)
    check("the recovered member is not on the STOP path", zf.encrypted_members(data) == [],
          zf.encrypted_members(data))
    check("read_member returns the plain bytes by name", zf.read_member(data, "secret.txt") == secret)


def test_deflate_flagflip_reads_plain():
    body = b"ABCDEFGH" * 4096          # compressible, so deflate actually shrinks it
    data = build_zip([("big.bin", body, 8)])
    # confirm the member really is deflate (method 8), not a stored fallback
    is_deflate = any(struct.unpack_from("<H", data, cho + 10)[0] == 8 for cho, n, lho in _cd_iter(data))
    data = set_encryption_bit(data, "big.bin")
    row = zf.recover_members(data)[0]
    check("deflate + encryption bit + valid CRC recovers plain", is_deflate and row["crc_ok"]
          and row["data"] == body, {"is_deflate": is_deflate, "row_reason": row["reason"]})


def test_corrupted_body_is_none():
    body = b"the quick brown fox" * 100
    base = build_zip([("x.bin", body, 0)])

    # flag set + corrupted body => None (CRC gate rejects; treated as genuinely encrypted / STOP)
    flagged = corrupt_body(set_encryption_bit(base, "x.bin"), "x.bin")
    row = zf.recover_members(flagged)[0]
    check("corrupted body with the encryption flag set => None (not recovered)",
          row["data"] is None and not row["crc_ok"], row)
    check("corrupted flagged member is on the STOP path (not guessed)",
          "x.bin" in zf.encrypted_members(flagged), zf.encrypted_members(flagged))
    check("read_member returns None for the corrupted flagged member",
          zf.read_member(flagged, "x.bin") is None)

    # flag clear + corrupted body => None, reported as damaged (not encrypted)
    damaged = corrupt_body(base, "x.bin")
    drow = zf.recover_members(damaged)[0]
    check("corrupted body with the flag clear => None, reported damaged (not STOP)",
          drow["data"] is None and not drow["crc_ok"] and "x.bin" not in zf.encrypted_members(damaged),
          drow)


def test_aes_no_recovery():
    # crafted method-99 member: always available
    base = build_zip([("aes.txt", b"this would be AES ciphertext", 0)])
    crafted = set_method_99(base, "aes.txt")
    row = zf.recover_members(crafted)[0]
    check("a compress_type 99 (AES/WinZip) member is not recovered (data None)",
          row["data"] is None and not row["crc_ok"], row)
    check("the AES member is on the STOP path", "aes.txt" in zf.encrypted_members(crafted))
    check("member_count still counts the AES member", zf.member_count(crafted) == 1,
          zf.member_count(crafted))

    if pyzipper is None:
        check("pyzipper absent: real-AES case SKIPPED (crafted method-99 case covered it)", True,
              "SKIP")
        return
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as z:
        z.setpassword(b"infected")
        z.writestr("real_aes.txt", b"genuinely AES-encrypted secret content")
    real = buf.getvalue()
    rows = zf.recover_members(real)
    r = next((x for x in rows if x["name"] == "real_aes.txt"), None)
    check("a real pyzipper WZ_AES member is not recovered (data None, STOP path)",
          r is not None and r["data"] is None and not r["crc_ok"]
          and "real_aes.txt" in zf.encrypted_members(real), r)


def test_count_is_byte_exact_not_recovered():
    # a mixed archive: a clear member, a flag-flipped plain member, a corrupted member, an AES
    # member, and a directory entry -> five central-directory entries, but only two recover.
    members = [
        ("sub/", b"", 0),                      # directory entry
        ("clear.txt", b"plain readable text", 0),
        ("flip.txt", b"recoverable via the flag flip", 0),
        ("broken.bin", b"will be corrupted" * 50, 0),
        ("locked.txt", b"pretend ciphertext", 0),
    ]
    data = build_zip(members)
    data = set_encryption_bit(data, "flip.txt")
    data = corrupt_body(data, "broken.bin")
    data = set_method_99(data, "locked.txt")

    rows = zf.recover_members(data)
    count = zf.member_count(data)
    recovered = [r for r in rows if r["crc_ok"]]
    names_recovered = {r["name"] for r in recovered}

    check("member_count is the byte-exact central-directory entry count (5, directory included)",
          count == 5, count)
    check("recover_members returns one row per central-directory entry",
          len(rows) == 5, len(rows))
    check("only the clear and flag-flipped members recovered (2), NOT the whole count",
          names_recovered == {"clear.txt", "flip.txt"}, names_recovered)
    check("the recovered count is strictly less than the member count (the never-wrong gap)",
          len(recovered) < count, {"recovered": len(recovered), "count": count})
    check("the directory entry is counted but carries no data",
          any(r["name"] == "sub/" and r["data"] is None for r in rows))
    check("encrypted_members names only the genuinely-encrypted member, not the recovered flip",
          zf.encrypted_members(data) == ["locked.txt"], zf.encrypted_members(data))


def test_not_a_zip():
    check("a non-zip returns no members", zf.recover_members(b"not a zip at all") == [])
    check("member_count of a non-zip is None", zf.member_count(b"not a zip at all") is None)
    check("non-bytes raises TypeError", _raises(lambda: zf.recover_members("str")))


def _raises(fn):
    try:
        fn()
        return False
    except TypeError:
        return True


def main():
    for t in (test_flagflip_reads_plain, test_deflate_flagflip_reads_plain, test_corrupted_body_is_none,
              test_aes_no_recovery, test_count_is_byte_exact_not_recovered, test_not_a_zip):
        try:
            t()
        except Exception as e:
            check(f"{t.__name__} raised {type(e).__name__}: {e}", False)
    print(f"RESULT {'PASS' if not FAILS else 'FAIL'} ({len(FAILS)} failed)")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
