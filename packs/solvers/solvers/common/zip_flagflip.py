#!/usr/bin/env python3
"""General zip pseudo-encryption flag-flip recovery, CRC-gated and lane-agnostic (Doc1 ticket C4).

A "pseudo-encryption" zip has general-purpose bit 0 (the encryption flag) set on a member whose
bytes are in fact stored or deflated in the clear: the zip module refuses to read it without a
password, so a lane that only skips `flag_bits & 1` members is blind to it, and a question that
names such a member wrongly trips the ARCHIVE-PASSWORD STOP / player wait when no password is
needed. This module reads those members back the only safe way: it clears the encryption flag,
inflates (stored or deflate only, bounded by MAX_INFLATE), and accepts the bytes ONLY when the
directory entry's stored CRC-32 matches the decompressed data. The CRC is the proof of a correct
read, so a recovered member is PLAIN-eligible.

It is a library (no self-registration, no CLI, no `signals`/`solve_set`): a lane's `day_patch.py`
override()/patch() or a lane agent imports it and calls `recover_members(data)` or
`read_member(data, name)`. It edits no shipped solver and no existing toolkit, and it never guesses
or brute-forces a password.

NEVER-WRONG rules this module keeps:
  - a member whose stored CRC-32 validates the decompressed bytes is PLAIN-eligible (`crc_ok` True);
  - CRC mismatch, a real encryption with no matching CRC, compress_type 99 (AES/WinZip), or any
    member that needs a password => that member is `crc_ok` False with `data` None and a reason
    that marks it genuinely encrypted (STOP path: leave it to the existing ARCHIVE-PASSWORD STOP,
    never guessed or brute-forced);
  - a short/damaged header, a member larger than MAX_INFLATE, or an unsupported method => `data`
    None;
  - COUNT: `member_count(data)` is the byte-exact central-directory entry count (every directory
    entry included), NEVER the count of members that happened to recover. `recover_members` returns
    one row per central-directory entry, so `len(recover_members(data)) == member_count(data)`.

Public API:
  recover_members(data) -> [ {name, size, crc_ok, data, reason}, ... ]   one row per CD entry
  read_member(data, name) -> bytes | None                                convenience
  member_count(data) -> int                                             byte-exact CD entry count
  encrypted_members(data) -> [name, ...]                                 STOP-path names only

Standard library only; it does not import or edit solvers/common/verified_transform.py (the CRC
check is self-contained with zlib.crc32).
"""
import struct
import zlib

MAX_INFLATE = 64 * 1024 * 1024   # bytes taken out of one member (compressed input or output cap)
MAX_ENTRIES = 200_000            # a sanity cap on how many central-directory entries are walked

_EOCD = b"PK\x05\x06"
_EOCD64 = b"PK\x06\x06"
_EOCD64_LOC = b"PK\x06\x07"
_CEN = b"PK\x01\x02"
_LOC = b"PK\x03\x04"

# reasons (STOP-path reasons are the ones in _STOP_REASONS)
R_READ = "read: not flagged, stored CRC-32 matches"
R_RECOVERED = "recovered: encryption flag set on a member stored in the clear, stored CRC-32 matches"
R_ENCRYPTED = "genuinely encrypted (flag set, no matching CRC): ARCHIVE-PASSWORD STOP, never guessed"
R_AES = "AES/WinZip (compress_type 99): ARCHIVE-PASSWORD STOP, never guessed"
R_CRC = "CRC-32 mismatch (damaged body), not encrypted"
R_METHOD = "unsupported compression method"
R_TOOBIG = "member larger than MAX_INFLATE"
R_HEADER = "short or damaged local header"
R_DIR = "directory entry (no content)"

_STOP_REASONS = frozenset({R_ENCRYPTED, R_AES})


def _find_eocd(data):
    """Offset of the End Of Central Directory record, searching the last chunk from the end."""
    n = len(data)
    if n < 22:
        return -1
    # the EOCD is 22 bytes + up to 65535 bytes of comment
    start = max(0, n - (22 + 65535))
    return data.rfind(_EOCD, start)


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def _central_dir(data):
    """(entries, cd_start, concat) from the EOCD, following ZIP64 when present.

    `entries` is the declared total number of central-directory records. `cd_start` and `concat`
    are byte offsets into `data`: `concat` is the length of any prefix before the archive (a
    self-extracting stub or a carrier the zip was carved from), so a member's recorded local-header
    offset is read at `offset + concat`. Returns (None, None, None) when there is no readable EOCD.
    """
    eo = _find_eocd(data)
    if eo < 0 or eo + 22 > len(data):
        return None, None, None
    try:
        entries = _u16(data, eo + 10)
        cd_size = _u32(data, eo + 12)
        cd_offset = _u32(data, eo + 16)
    except struct.error:
        return None, None, None

    # ZIP64: any of these maxed out means the real values live in the ZIP64 EOCD record.
    if entries == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        loc = data.rfind(_EOCD64_LOC, max(0, eo - 20), eo)
        if loc >= 0 and loc + 16 <= len(data):
            try:
                z64_off = _u64(data, loc + 8)
            except struct.error:
                z64_off = -1
            # the recorded offset is relative to the archive start; try it with and without concat
            for base in (z64_off, z64_off + max(0, eo - cd_size - cd_offset)):
                if 0 <= base and base + 56 <= len(data) and data[base:base + 4] == _EOCD64:
                    try:
                        entries = _u64(data, base + 32)
                        cd_size = _u64(data, base + 40)
                        cd_offset = _u64(data, base + 48)
                    except struct.error:
                        pass
                    break

    if entries is None or entries < 0 or entries > MAX_ENTRIES:
        return None, None, None
    # the prefix length: where the central directory really sits minus where the record says it is
    concat = eo - cd_size - cd_offset
    if concat < 0:
        concat = 0
    cd_start = cd_offset + concat
    if cd_start < 0 or cd_start > len(data):
        return None, None, None
    return entries, cd_start, concat


def _zip64_extra(extra, want_usize, want_csize, want_lho):
    """Pull uncompressed size, compressed size and local-header offset from the ZIP64 extra field,
    for whichever of them the central record maxed out (in that fixed order)."""
    usize = csize = lho = None
    p = 0
    while p + 4 <= len(extra):
        hid, hsz = struct.unpack_from("<HH", extra, p)
        body = extra[p + 4:p + 4 + hsz]
        p += 4 + hsz
        if hid != 0x0001:
            continue
        q = 0
        if want_usize and q + 8 <= len(body):
            usize = struct.unpack_from("<Q", body, q)[0]; q += 8
        if want_csize and q + 8 <= len(body):
            csize = struct.unpack_from("<Q", body, q)[0]; q += 8
        if want_lho and q + 8 <= len(body):
            lho = struct.unpack_from("<Q", body, q)[0]; q += 8
        break
    return usize, csize, lho


def _entries(data):
    """Walk the central directory, yielding one parsed record per entry. Byte-exact: it yields the
    declared number of records, so the directory entry count never depends on what recovers."""
    entries, p, concat = _central_dir(data)
    if entries is None:
        return
    n = len(data)
    for _ in range(entries):
        if p + 46 > n or data[p:p + 4] != _CEN:
            return
        try:
            flag = _u16(data, p + 8)
            method = _u16(data, p + 10)
            crc = _u32(data, p + 16)
            csize = _u32(data, p + 20)
            usize = _u32(data, p + 24)
            name_len = _u16(data, p + 28)
            extra_len = _u16(data, p + 30)
            comment_len = _u16(data, p + 32)
            lho = _u32(data, p + 42)
        except struct.error:
            return
        name = data[p + 46:p + 46 + name_len]
        extra = data[p + 46 + name_len:p + 46 + name_len + extra_len]
        if usize == 0xFFFFFFFF or csize == 0xFFFFFFFF or lho == 0xFFFFFFFF:
            z_u, z_c, z_l = _zip64_extra(extra, usize == 0xFFFFFFFF, csize == 0xFFFFFFFF,
                                         lho == 0xFFFFFFFF)
            if z_u is not None:
                usize = z_u
            if z_c is not None:
                csize = z_c
            if z_l is not None:
                lho = z_l
        yield {"name": name, "flag": flag, "method": method, "crc": crc, "csize": csize,
               "usize": usize, "lho": lho + concat}
        p += 46 + name_len + extra_len + comment_len


def _body(data, ent):
    """Raw member bytes located through the LOCAL header (its own name/extra lengths, not the
    central record's). Returns (bytes, None) or (None, reason) on a short/damaged header."""
    at = ent["lho"]
    if at < 0 or at + 30 > len(data) or data[at:at + 4] != _LOC:
        return None, R_HEADER
    try:
        ln = _u16(data, at + 26)
        le = _u16(data, at + 28)
    except struct.error:
        return None, R_HEADER
    start = at + 30 + ln + le
    body = data[start:start + ent["csize"]]
    if len(body) < ent["csize"]:
        return None, R_HEADER
    return body, None


def _decompress(ent, body):
    """Decompressed bytes for a stored or deflate member, bounded by MAX_INFLATE; None when the
    method is unsupported or the stream is malformed."""
    method = ent["method"]
    if method == 0:
        return body if len(body) <= MAX_INFLATE else None
    if method == 8:
        try:
            d = zlib.decompressobj(-15)
            raw = d.decompress(body, MAX_INFLATE)
            if d.unconsumed_tail:            # hit the cap: the member is larger than MAX_INFLATE
                return None
            raw += d.flush()
        except zlib.error:
            return None
        return raw if len(raw) <= MAX_INFLATE else None
    return None


def _recover_one(data, ent):
    """One result row for one central-directory entry."""
    name = ent["name"].decode("utf-8", "replace")
    usize = ent["usize"]
    row = {"name": name, "size": usize, "crc_ok": False, "data": None, "reason": ""}
    aes = ent["method"] == 99
    encrypted_flag = bool(ent["flag"] & 1) or aes

    if name.endswith("/") and usize == 0 and ent["csize"] == 0:
        row["reason"] = R_DIR
        return row
    if ent["csize"] > MAX_INFLATE or usize > MAX_INFLATE:
        row["reason"] = R_AES if aes else (R_ENCRYPTED if encrypted_flag else R_TOOBIG)
        return row
    if aes:
        # WinZip AES ciphertext never matches the stored CRC of the plaintext; do not even attempt.
        row["reason"] = R_AES
        return row

    body, why = _body(data, ent)
    if body is None:
        row["reason"] = why
        return row
    if ent["method"] not in (0, 8):
        row["reason"] = R_ENCRYPTED if encrypted_flag else R_METHOD
        return row

    raw = _decompress(ent, body)
    if raw is None:
        # a deflate stream that will not inflate from the raw bytes: a genuinely encrypted member
        # (its ciphertext is not a valid stream) if the flag is set, else a damaged body.
        row["reason"] = R_ENCRYPTED if encrypted_flag else R_CRC
        return row

    if len(raw) == usize and (zlib.crc32(raw) & 0xFFFFFFFF) == ent["crc"]:
        row.update(crc_ok=True, data=raw, reason=R_RECOVERED if (ent["flag"] & 1) else R_READ)
        return row

    # bytes read but the CRC did not validate them: encrypted (flag set) or damaged (flag clear).
    row["reason"] = R_ENCRYPTED if encrypted_flag else R_CRC
    return row


def recover_members(data):
    """[ {name, size, crc_ok, data, reason} ] for every central-directory entry of a zip.

    `crc_ok` True with `data` set means the bytes are proven correct (PLAIN-eligible), whether or
    not the encryption flag was set. `crc_ok` False with `data` None is a member left unread: a
    genuinely encrypted / AES member (STOP path; see `encrypted_members`), a damaged body, an
    unsupported method, an oversize member or a short header. The list has one row per directory
    entry, so `len(recover_members(data)) == member_count(data)`.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("recover_members expects bytes")
    data = bytes(data)
    return [_recover_one(data, ent) for ent in _entries(data)]


def read_member(data, name):
    """The decompressed, CRC-validated bytes of one member by name, or None when it is absent or
    could not be read (encrypted, damaged, oversize). Returns the first entry of that name."""
    for row in recover_members(data):
        if row["name"] == name:
            return row["data"]
    return None


def member_count(data):
    """The byte-exact number of central-directory entries (directories included), independent of
    how many members recover. Returns None when there is no readable central directory.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("member_count expects bytes")
    data = bytes(data)
    entries, _, _ = _central_dir(data)
    if entries is None:
        return None
    # the declared total is authoritative; confirm it by walking, and report the walked count when
    # the directory is shorter than it claims (a truncated archive).
    walked = sum(1 for _ in _entries(data))
    return walked if walked < entries else entries


def encrypted_members(data):
    """Names of the members that look genuinely encrypted and belong to the ARCHIVE-PASSWORD STOP
    path (a real encryption with no matching CRC, or WinZip AES). A pseudo-encrypted member whose
    CRC validated is NOT here: it was recovered."""
    return [row["name"] for row in recover_members(data) if row["reason"] in _STOP_REASONS]
