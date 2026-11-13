#!/usr/bin/env python3
"""Harvest candidate passwords from a challenge's own bytes (B-074).

A password-protected delivery (a zip/7z/rar, a hash dropped beside it) almost always ships its own
password somewhere in the handout: appended after a container's logical end (a comment, an overlay),
printed in a readable string inside a file, or written in a sibling note. This module reads those
three places and returns an ordered, de-duplicated list of candidate passwords. It generates nothing
and guesses nothing: every candidate is a string that literally appears in the bytes it was given.

    harvest(path)                       -> [candidate, ...]  (a file and, by default, its siblings)
    harvest(data=b"...")                -> [candidate, ...]  (bytes in hand, no file)
    from_bytes(data)                    -> candidates from appended bytes then from every string
    overlay(data)                       -> the bytes appended after a recognized container's end
    ascii_runs(data) / utf16le_runs(d)  -> printable runs
    siblings(path)                      -> candidates read from small text files beside `path`

Order is deliberate: candidates found in a container's appended bytes come first (the classic place a
CTF hides the archive password), then candidates from the readable strings of the file, then the
siblings. A caller feeds the list to solvers/common/archive_passwords.add_many() (the archive-open
store) or to the hashcrack wordlist. Offline, standard library only; nothing is executed.

A candidate obeys the archive_passwords store's rule: 1..128 characters, no newline, no NUL. Both the
whole stripped run (a passphrase can carry spaces) and its whitespace-split tokens are offered.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path

MIN_LEN = 4                 # a printable run shorter than this is not reported (too much noise)
MAX_PW = 128                # the archive_passwords store's limit; a longer run is not a password
MAX_CANDIDATES = 5000       # a hard cap so a huge handout cannot produce an unbounded list
MAX_SIBLING = 1 << 20       # a sibling text file larger than this is not read for candidates
MAX_SIBLINGS = 64           # at most this many sibling files are read
_PRINTABLE = set(range(0x20, 0x7f)) | {0x09}
# Never mine the harness's own bookkeeping files for passwords (the store, its lock, sweep reports).
_SKIP_SIBLING = re.compile(r"^(_passwords\.json(\.lock)?|\.sweep.*|\.ctf.*|_logs)$")


def _valid(value: str) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_PW and "\n" not in value and "\x00" not in value


# Public names of the two rules other harvesters share (B-076's passphrase_harvest): which sibling files
# are never read, and what a candidate may be.
SKIP_SIBLING = _SKIP_SIBLING
valid = _valid


# ---------------------------------------------------------------- printable runs

def _runs(raw: bytes, min_len: int) -> list[str]:
    out, cur = [], bytearray()
    for b in raw:
        if b in _PRINTABLE and b != 0x09:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def ascii_runs(data: bytes, min_len: int = MIN_LEN) -> list[str]:
    """Printable-ASCII runs of at least `min_len` characters (tabs break a run, as `strings` does)."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    return _runs(bytes(data), max(1, min_len))


def utf16le_runs(data: bytes, min_len: int = MIN_LEN) -> list[str]:
    """Printable UTF-16LE runs (a Windows note or NTFS stream holds the password as wide chars)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 2:
        return []
    data = bytes(data)
    # every ASCII char as a wide char is <ch>\x00; read the even bytes and keep runs whose odd byte is 0
    out, cur = [], bytearray()
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and lo in _PRINTABLE and lo != 0x09:
            cur.append(lo)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


# ---------------------------------------------------------------- the appended-bytes overlay

def overlay(data: bytes) -> bytes:
    """The bytes that follow a recognized container's logical end: a zip's trailing data after its
    End-Of-Central-Directory (and its archive comment), a PNG's bytes after IEND, a JPEG's after the
    FFD9 end marker. b"" when the leading magic is not one of those, or nothing is appended."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 4:
        return b""
    data = bytes(data)
    if data[:2] == b"PK":
        return _zip_overlay(data)
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        end = data.rfind(b"\x00\x00\x00\x00IEND")      # IEND chunk: len(0) + 'IEND' + crc(4)
        if end != -1:
            return data[end + 12:]
        return b""
    if data[:2] == b"\xff\xd8":
        end = data.rfind(b"\xff\xd9")
        if end != -1:
            return data[end + 2:]
        return b""
    return b""


def _zip_overlay(data: bytes) -> bytes:
    sig = data.rfind(b"PK\x05\x06")      # the (last) End-Of-Central-Directory record
    if sig == -1 or sig + 22 > len(data):
        return b""
    (comment_len,) = struct.unpack_from("<H", data, sig + 20)
    end = sig + 22 + comment_len
    # The EOCD comment itself is a place a password is written; offer it, then any trailing bytes.
    tail = data[sig + 22:] if comment_len else data[end:]
    return tail


# ---------------------------------------------------------------- candidates

_WS = re.compile(r"\s+")
_TRIM = ".,;:!?\"'`()[]{}<>"      # a note writes "the password is X." -- offer X too, not only "X."


def _dedup(values) -> list[str]:
    out, seen = [], set()
    for v in values:
        if _valid(v) and v not in seen:
            seen.add(v)
            out.append(v)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def _candidates_from_runs(runs) -> list[str]:
    """Each run as a whole (a passphrase may carry spaces) and each of its whitespace-split tokens."""
    vals = []
    for run in runs:
        run = run.strip()
        if run:
            vals.append(run)
        tokens = [t for t in _WS.split(run) if t]
        toks = tokens if len(tokens) > 1 else []
        for t in toks:
            vals.append(t)
            trimmed = t.strip(_TRIM)        # a token written as `X.` or "X" also yields the bare X
            if trimmed and trimmed != t:
                vals.append(trimmed)
    return vals


def from_bytes(data: bytes, min_len: int = MIN_LEN) -> list[str]:
    """Candidates from one blob: those in its appended overlay first, then every readable string
    (ASCII and UTF-16LE), de-duplicated. The overlay is where a hidden archive password usually is."""
    if not isinstance(data, (bytes, bytearray)):
        return []
    data = bytes(data)
    over = overlay(data)
    front = _candidates_from_runs(ascii_runs(over, min_len) + utf16le_runs(over, min_len)) if over else []
    rest = _candidates_from_runs(ascii_runs(data, min_len) + utf16le_runs(data, min_len))
    return _dedup(front + rest)


def from_file(path, min_len: int = MIN_LEN) -> list[str]:
    try:
        data = Path(path).read_bytes()
    except OSError:
        return []
    return from_bytes(data, min_len)


def siblings(path, min_len: int = MIN_LEN) -> list[str]:
    """Candidates read from the small text files that sit beside `path` (a README, a note, a .txt).
    Binary siblings (a NUL in the first kilobyte) and the harness's own files are skipped."""
    p = Path(path)
    folder = p.parent if p.is_file() or not p.is_dir() else p
    try:
        entries = sorted(e for e in folder.iterdir() if e.is_file() and not e.is_symlink())
    except OSError:
        return []
    out, read = [], 0
    for entry in entries:
        if entry.resolve() == p.resolve() or _SKIP_SIBLING.match(entry.name):
            continue
        if read >= MAX_SIBLINGS:
            break
        try:
            if entry.stat().st_size > MAX_SIBLING:
                continue
            blob = entry.read_bytes()
        except OSError:
            continue
        read += 1
        if b"\x00" in blob[:1024]:        # a binary sibling: not a note; skip it
            continue
        out.extend(_candidates_from_runs(ascii_runs(blob, min_len)))
    return _dedup(out)


def harvest(path=None, *, data: bytes | None = None, include_siblings: bool = True,
            min_len: int = MIN_LEN) -> list[str]:
    """Every candidate password a handout gives up. With `path`: the file's own bytes (overlay first,
    then strings) and, when `include_siblings`, the small text files beside it. With `data`: the bytes
    in hand only. De-duplicated, capped at MAX_CANDIDATES, overlay/own-file candidates before siblings."""
    own = []
    if data is not None:
        own = from_bytes(data, min_len)
    elif path is not None:
        own = from_file(path, min_len)
    sib = siblings(path, min_len) if (include_siblings and path is not None) else []
    return _dedup(own + sib)


def main(argv=None) -> int:
    import argparse
    import sys
    p = argparse.ArgumentParser(description="Harvest candidate passwords from a handout's bytes "
                                            "(appended overlay, readable strings, sibling notes).")
    p.add_argument("file")
    p.add_argument("--no-siblings", action="store_true")
    p.add_argument("--min-len", type=int, default=MIN_LEN)
    a = p.parse_args(list(argv) if argv is not None else None)
    if not Path(a.file).exists():
        print(f"harvest: no such file: {a.file}", file=sys.stderr)
        return 1
    cands = harvest(a.file, include_siblings=not a.no_siblings, min_len=max(1, a.min_len))
    for c in cands:
        print(c)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
