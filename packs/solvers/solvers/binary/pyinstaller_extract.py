#!/usr/bin/env python3
"""Bounded, dependency-free PyInstaller CArchive extractor.

Delivered executables are data: this module never imports, unmarshals, executes, or decompiles an
entry.  It validates the cookie/TOC, inflates zlib members, exposes printable/flag leads, and can
wrap marshalled Python entries in a caller-supplied ``.pyc`` magic.  The returned decompile command
is a literal networkless Docker plan for human review; it is never run by this module.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import struct
import sys
import zlib
from pathlib import Path, PurePosixPath


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
MAX_INPUT = 512 << 20
MAX_ARCHIVE = 256 << 20
MAX_ENTRIES = 100_000
MAX_ENTRY = 128 << 20
FLAG_RE = flagfmt.BYTES


class PyInstallerError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class Cookie:
    offset: int
    size: int
    package_start: int
    package_length: int
    toc_offset: int
    toc_length: int
    python_version: int
    python_library: str | None


@dataclasses.dataclass(frozen=True)
class Entry:
    name: str
    typecode: str
    compressed: bool
    stored_size: int
    original_size: int
    data: bytes

    def report(self) -> dict:
        return {"name": self.name, "typecode": self.typecode, "compressed": self.compressed,
                "stored_size": self.stored_size, "original_size": self.original_size,
                "sha256": hashlib.sha256(self.data).hexdigest(), "leads": printable_leads(self.data)}


def _safe_name(raw: bytes, index: int) -> str:
    name = raw.split(b"\0", 1)[0].decode("utf-8", "replace").replace("\\", "/")
    path = PurePosixPath(name)
    parts = [part for part in path.parts if part not in ("", ".", "..", "/")]
    clean = "/".join(parts)
    if not clean:
        clean = f"entry_{index:05d}"
    if len(clean) > 1024:
        raise PyInstallerError("PyInstaller entry name exceeds cap")
    return clean


def _toc_entries(data: bytes, package_start: int, toc_offset: int, toc_length: int,
                 *, materialize: bool) -> list[Entry]:
    start, end = package_start + toc_offset, package_start + toc_offset + toc_length
    if toc_offset < 0 or toc_length <= 0 or start < package_start or end > len(data):
        raise PyInstallerError("PyInstaller TOC is outside the input")
    rows, cursor = [], start
    while cursor < end:
        if len(rows) >= MAX_ENTRIES or cursor + 18 > end:
            raise PyInstallerError("PyInstaller TOC is truncated or exceeds entry cap")
        entry_size, position, stored, original = struct.unpack_from(">IIII", data, cursor)
        compressed, type_byte = struct.unpack_from("BB", data, cursor + 16)
        if entry_size < 18 or cursor + entry_size > end or compressed not in (0, 1):
            raise PyInstallerError("invalid PyInstaller TOC entry")
        if stored > MAX_ENTRY or original > MAX_ENTRY:
            raise PyInstallerError("PyInstaller member exceeds size cap")
        absolute = package_start + position
        if absolute < package_start or absolute + stored > len(data):
            raise PyInstallerError("PyInstaller member points outside the input")
        name = _safe_name(data[cursor + 18:cursor + entry_size], len(rows))
        typecode = chr(type_byte) if 0x20 <= type_byte < 0x7F else f"0x{type_byte:02x}"
        payload = data[absolute:absolute + stored]
        if materialize and compressed:
            try:
                inflater = zlib.decompressobj()
                decoded = inflater.decompress(payload, original + 1) + inflater.flush()
            except zlib.error as exc:
                raise PyInstallerError(f"zlib failure in member {name!r}") from exc
            if not inflater.eof or len(decoded) != original:
                raise PyInstallerError(f"member {name!r} did not inflate to its declared size")
            payload = decoded
        elif materialize and len(payload) != original:
            raise PyInstallerError(f"stored member {name!r} disagrees with its declared size")
        rows.append(Entry(name, typecode, bool(compressed), stored, original,
                          payload if materialize else b""))
        cursor += entry_size
    if cursor != end or not rows:
        raise PyInstallerError("PyInstaller TOC does not end on an entry boundary")
    return rows


def parse_cookie(data: bytes) -> Cookie:
    if not isinstance(data, bytes) or len(data) < 24 or len(data) > MAX_INPUT:
        raise PyInstallerError("input is outside PyInstaller size bounds")
    search_start = max(0, len(data) - (1 << 20))
    candidates = []
    cursor = len(data)
    while True:
        offset = data.rfind(MAGIC, search_start, cursor)
        if offset < 0:
            break
        cursor = offset
        for cookie_size in (88, 24):
            if offset + cookie_size > len(data):
                continue
            package_length, toc_offset, toc_length, pyver = struct.unpack_from(">IIII", data, offset + 8)
            package_start = offset + cookie_size - package_length
            if package_length > MAX_ARCHIVE or package_start < 0 or package_start + toc_offset + toc_length > offset:
                continue
            library = None
            if cookie_size == 88:
                raw_library = data[offset + 24:offset + 88].split(b"\0", 1)[0]
                if raw_library and not re.fullmatch(rb"[A-Za-z0-9_.+\-]{1,63}", raw_library):
                    continue
                library = raw_library.decode("ascii") if raw_library else None
            try:
                _toc_entries(data, package_start, toc_offset, toc_length, materialize=False)
            except PyInstallerError:
                continue
            candidates.append(Cookie(offset, cookie_size, package_start, package_length,
                                     toc_offset, toc_length, pyver, library))
        if candidates:
            break
    if not candidates:
        raise PyInstallerError("no valid PyInstaller CArchive cookie/TOC found")
    # A v2.1+ cookie is preferred only when its extended library field and TOC both validated.
    return max(candidates, key=lambda row: row.size)


def extract_carchive(data: bytes) -> tuple[Cookie, list[Entry]]:
    cookie = parse_cookie(data)
    return cookie, _toc_entries(data, cookie.package_start, cookie.toc_offset,
                                cookie.toc_length, materialize=True)


def make_pyc(entry: Entry, magic: bytes) -> bytes:
    if entry.typecode not in ("s", "m", "M"):
        raise PyInstallerError("only script/module entries contain marshalled code")
    if not isinstance(magic, bytes) or len(magic) != 4 or magic[2:] != b"\r\n":
        raise PyInstallerError("pyc magic must be exactly four bytes ending CRLF")
    # PEP 552 timestamp-based header with zero metadata.  It is a transport wrapper only; no code
    # object is loaded here.
    return magic + b"\0" * 12 + entry.data


def printable_leads(data: bytes, limit: int = 64) -> list[str]:
    leads = [match.group().decode("utf-8", "replace") for match in FLAG_RE.finditer(data)]
    for match in re.finditer(rb"[ -~]{6,256}", data):
        text = match.group().decode("ascii", "replace")
        if text not in leads:
            leads.append(text)
        if len(leads) >= limit:
            break
    return leads[:limit]


def docker_disassembly_plan(filename: str, image: str = "csctf-sandbox:2") -> tuple[str, ...]:
    clean = PurePosixPath(filename).name
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", clean):
        raise PyInstallerError("unsafe pyc filename for command plan")
    script = ("import dis,marshal,pathlib; p=pathlib.Path('/work/" + clean + "'); "
              "d=p.read_bytes(); dis.dis(marshal.loads(d[16:]))")
    return ("docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--pids-limit", "64", "--memory", "256m",
            "-v", "$PWD:/work:ro", image, "python3", "-I", "-c", script)


def _read(path: str) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise PyInstallerError("input exceeds size cap")
    return data


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # pragma: no cover
        raise ValueError(message)


def main(argv=None) -> int:
    parser = _Parser(prog="pyinstaller_extract.py")
    parser.add_argument("input")
    parser.add_argument("--extract-dir")
    parser.add_argument("--pyc-magic-hex")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        cookie, entries = extract_carchive(_read(args.input))
        report = {"python_version": cookie.python_version, "python_library": cookie.python_library,
                  "cookie_size": cookie.size, "entries": [entry.report() for entry in entries]}
        if args.extract_dir:
            root = Path(args.extract_dir)
            if root.exists():
                raise PyInstallerError("extract directory already exists")
            root.mkdir(parents=True)
            magic = bytes.fromhex(args.pyc_magic_hex) if args.pyc_magic_hex else None
            written = set()
            for entry in entries:
                relative = Path(*PurePosixPath(entry.name).parts)
                output = root / relative
                if entry.typecode in ("s", "m", "M") and magic is not None:
                    output = output.with_suffix(output.suffix + ".pyc")
                    payload = make_pyc(entry, magic)
                else:
                    payload = entry.data
                identity = str(output.relative_to(root)).casefold()
                if identity in written or output.exists():
                    raise PyInstallerError(f"duplicate extraction path {identity!r}")
                written.add(identity)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(payload)
            report["extract_dir"] = str(root)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, OverflowError, UnicodeError, struct.error,
            zlib.error, MemoryError) as exc:
        print(f"pyinstaller_extract: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
