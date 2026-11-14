"""Offline Stuxnet project IOC inventory and classic S7 MC7 metadata reader.

Sources: Symantec W32.Stuxnet Dossier v1.2 pp29-37 (MIT mirror):
https://css.csail.mit.edu/6.566/2018/readings/stuxnet.pdf
https://community.broadcom.com/viewdocument/exploring-stuxnets-plc-infection-p
MC7 layout: Snap7 src/core/s7_types.h TS7CompactBlockInfo and
DotNetSiemensPLCToolBoxLibrary MC7Converter.cs GetAWLBlock/GetBlockHeader.

No disassembly, project decryption, DLL loading or PLC interaction. Filename,
block-number and raw-marker hits are evidence for review, not proof of infection.
Public parsers raise only StuxnetError for malformed/unsupported input; CLI
returns a status. ZIP members are read in memory, never extracted or recursed.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile


class StuxnetError(ValueError):
    """Malformed, unsupported, inaccessible or over-limit artifact."""


MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_ENTRIES = 4096
MAX_PATH = 2048
MAX_DEPTH = 32
MAX_HITS = 64
_BLOCK_TYPES = {8: "OB", 10: "DB", 11: "SDB", 12: "FC", 13: "SFC", 14: "FB", 15: "SFB"}
_LANGUAGES = {1: "AWL", 2: "KOP", 3: "FUP", 4: "SCL", 5: "DB", 6: "GRAPH", 17: "SDB"}
_PROJECT_PATHS = (
    "xutils/listen/xr000000.mdx", "xutils/links/s7p00001.dbf",
    "xutils/listen/s7000001.mdx", "gracs/cc_alg.sav", "gracs/db_log.sav",
    "gracs/cc_tlg7.sav", "gracs/cc_tag.sav",
)
_BLOCK_NAME = re.compile(r"^(OB|DB)[ _-]?0*([0-9]{1,5})(?:\.(?:mc7|bin|blk|db|awl|stl))?$", re.I)
_TEMP_NAME = re.compile(r"^~WR([0-9A-F]{5})\.tmp$", re.I)


def _blob(data, cap=MAX_FILE):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise StuxnetError("artifact must be bytes")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > cap:
            raise StuxnetError("artifact exceeds byte limit")
        return bytes(data)
    except (TypeError, ValueError) as exc:
        raise StuxnetError(str(exc)) from exc


def _name(value):
    if not isinstance(value, str) or not value or len(value) > MAX_PATH or "\0" in value:
        raise StuxnetError("invalid artifact path")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise StuxnetError("path contains invalid Unicode") from exc
    return value.replace("\\", "/")


def _uint(data, start, size):
    return int.from_bytes(data[start:start + size], "big")


def parse_mc7(data) -> dict:
    """Read a complete classic compact block (36-byte header/footer).

    Does not parse code, interface definitions, start-values or checksums. The
    variable region between MC7 and footer is retained as a size. SBB/segment
    lengths are bounded by all body/auxiliary bytes, without assuming a partition:
    field28 is variously documented as interface length or DB actual-value length.
    Timestamp components are raw integers; no timezone or validity is inferred.
    """
    data = _blob(data)
    if len(data) < 72 or data[:2] != b"pp":
        raise StuxnetError("not a complete classic MC7 block")
    load_size = _uint(data, 8, 4)
    mc7_size = _uint(data, 34, 2)
    footer = len(data) - 36
    if load_size != len(data) or 36 + mc7_size > footer:
        raise StuxnetError("MC7 load/code length exceeds block geometry")
    subtype = data[5]
    if subtype not in _BLOCK_TYPES:
        raise StuxnetError("unsupported MC7 block type")
    interface_size, segment_size = _uint(data, 28, 2), _uint(data, 30, 2)
    variable_size = footer - 36 - mc7_size
    if interface_size > footer - 36 or segment_size > footer - 36:
        raise StuxnetError("MC7 SBB/segment length exceeds body/auxiliary region")
    stamps = {}
    for label, offset in (("code", 16), ("interface", 22)):
        milliseconds, days = _uint(data, offset, 4), _uint(data, offset + 4, 2)
        stamps[label] = {"days_since_1984_01_01": days, "milliseconds": milliseconds}
    return {
        "format": "classic-mc7", "block_type": _BLOCK_TYPES[subtype],
        "block_number": _uint(data, 6, 2), "language_code": data[4],
        "language": _LANGUAGES.get(data[4], "unknown"), "flags": data[3],
        "header_unknown": data[2], "security": _uint(data, 12, 4),
        "load_size": load_size, "mc7_offset": 36, "mc7_size": mc7_size,
        "sbb_size": interface_size, "segment_size": segment_size,
        "local_data_size": _uint(data, 32, 2), "variable_size": variable_size,
        "footer_offset": footer, "timestamps": stamps,
        "author": data[footer:footer + 8].rstrip(b"\0 ").decode("latin1"),
        "family": data[footer + 8:footer + 16].rstrip(b"\0 ").decode("latin1"),
        "name": data[footer + 16:footer + 24].rstrip(b"\0 ").decode("latin1"),
        "version": f"{data[footer + 24] >> 4}.{data[footer + 24] & 15}",
        "checksum_stored": _uint(data, footer + 26, 2), "checksum_verified": False,
    }


def _finding(code, strength, detail, **evidence):
    return {"code": code, "strength": strength, "detail": detail, **evidence}


def _marker_offsets(data, marker):
    result, start = [], 0
    while len(result) <= MAX_HITS:
        found = data.find(marker, start)
        if found < 0:
            break
        result.append(found)
        start = found + len(marker)
    return result[:MAX_HITS], len(result) > MAX_HITS


def _mask_comments(data):
    """Linear comment removal; an unclosed block comment consumes the rest."""
    pieces, cursor = [], 0
    opening = re.compile(rb"//|\(\*|/\*")
    while match := opening.search(data, cursor):
        pieces.append(data[cursor:match.start()])
        token = match[0]
        closing = b"\n" if token == b"//" else (b"*)" if token == b"(*" else b"*/")
        end = data.find(closing, match.end())
        pieces.append(b" ")
        if end < 0:
            cursor = len(data)
            break
        cursor = end + len(closing)
    pieces.append(data[cursor:])
    return b"".join(pieces)


def _hook_findings(data, block_hint):
    # Only match the published STL prologue, not isolated FC names/marker text.
    clean = _mask_comments(data).upper()
    sections = []
    has_header = False
    for index, match in enumerate(re.finditer(rb"\bORGANIZATION_BLOCK\s+OB\s*(1|35)\b", clean)):
        has_header = True
        if index >= MAX_HITS:
            break
        tail = clean[match.end():]
        end = tail.find(b"END_ORGANIZATION_BLOCK")
        if end >= 0:
            tail = tail[:end]
        begin = re.search(rb"\bBEGIN\b", tail)
        if begin:
            sections.append((int(match[1]), tail[begin.end():]))
    if not has_header and block_hint and block_hint[0] == "OB":
        sections.append((block_hint[1], clean))
    result = []
    for number, body in sections:
        target = {1: 1865, 35: 1874}.get(number)
        if target is None:
            continue
        # Exporters may terminate statements with semicolons or newlines.
        sep = rb"[\s;]+"
        pattern = (rb"\s*UC\s+FC\s*" + str(target).encode() + sep + rb"POP" + sep
                   + rb"L\s+DW#16#DEADF007" + sep + rb"==D" + sep + rb"BEC" + sep
                   + rb"L\s+DW#16#0" + sep + rb"L\s+DW#16#0(?:[\s;]|$)")
        if re.match(pattern, body):
            result.append(_finding("documented-ob-hook", "structural", "Published STL hook prologue",
                                   block=f"OB{number}", called_fc=target))
    return result


def _inspect(path, size, data):
    lower = path.lower()
    basename = lower.rsplit("/", 1)[-1]
    findings = []
    record = {"path": path, "size": size, "content_scanned": data is not None, "findings": findings}
    if basename == "s7otbxdx.dll":
        findings.append(_finding("step7-original-dll-name", "context", "Normal Step7 DLL name; replacement requires corroboration"))
    elif basename == "s7otbxsx.dll":
        findings.append(_finding("step7-renamed-dll-name", "name", "Name used for original DLL after Stuxnet replacement"))
    for suffix in _PROJECT_PATHS:
        if lower == suffix or lower.endswith("/" + suffix):
            findings.append(_finding("documented-project-path", "name", "Documented project infection artifact path", suffix=suffix))
    if "/apilog/types/" in "/" + lower:
        findings.append(_finding("step7-types-context", "context", "Project data-file area modified by Stuxnet; names alone are not infection evidence"))
    temp = _TEMP_NAME.fullmatch(basename)
    if temp and sum(int(x, 16) for x in temp[1]) % 16 == 0:
        findings.append(_finding("wr-checksummed-name", "name", "Five hexadecimal name digits sum to zero modulo 16"))
        if data is not None and data.startswith(b"LRW~LRW~"):
            findings.append(_finding("wr-name-and-header", "structural", "Documented temporary-file name and first-eight-byte marker"))
    match = _BLOCK_NAME.fullmatch(basename)
    hint = (match[1].upper(), int(match[2])) if match else None
    if data is not None and data.startswith(b"pp"):
        try:
            record["mc7"] = parse_mc7(data)
            hint = (record["mc7"]["block_type"], record["mc7"]["block_number"])
        except StuxnetError as exc:
            record["mc7_error"] = str(exc)
    if hint and hint[0] == "DB" and hint[1] in (888, 889, 890, 891):
        findings.append(_finding("documented-db-number", "context", "Data-block number used by Stuxnet, also available to legitimate programs", block=f"DB{hint[1]}"))
    if hint and hint[0] == "OB" and hint[1] in (1, 35):
        findings.append(_finding("hook-target-ob", "context", "Normal organization block targeted by Stuxnet; inspect its prologue", block=f"OB{hint[1]}"))
    if data is not None:
        for encoding, marker in (("binary-big-endian", b"\xde\xad\xf0\x07"),
                                 ("binary-little-endian", b"\x07\xf0\xad\xde"),
                                 ("ascii", b"DEADF007")):
            offsets, truncated = _marker_offsets(data.upper() if encoding == "ascii" else data, marker)
            if offsets:
                findings.append(_finding("deadf007-marker", "marker", "Documented OB hook constant; raw occurrence does not prove executable hook", encoding=encoding, offsets=offsets, offsets_truncated=truncated))
        if basename.endswith((".awl", ".stl")):
            findings.extend(_hook_findings(data, hint))
    return record


def scan_manifest(entries) -> dict:
    """Inspect [{path, size?, data?}], where data is optional complete bytes.

    Paths in this API are labels only, including Windows absolute paths; they
    are never opened. A name-only manifest cannot establish content evidence.
    """
    if not isinstance(entries, (list, tuple)) or len(entries) > MAX_ENTRIES:
        raise StuxnetError("manifest must be a bounded list")
    prepared, seen, total = [], set(), 0
    for entry in entries:
        if not isinstance(entry, dict) or "path" not in entry:
            raise StuxnetError("manifest entry requires path")
        path = _name(entry["path"])
        key = path.casefold()
        if key in seen:
            raise StuxnetError("duplicate case-insensitive manifest path")
        seen.add(key)
        data = _blob(entry["data"]) if "data" in entry else None
        size = entry.get("size", len(data) if data is not None else None)
        if size is not None and (type(size) is not int or not 0 <= size < 2**63):
            raise StuxnetError("invalid manifest size")
        if data is not None:
            if size != len(data):
                raise StuxnetError("manifest size does not match complete data")
            total += len(data)
            if total > MAX_TOTAL:
                raise StuxnetError("manifest exceeds total byte limit")
        prepared.append((path, size, data))
    records = [_inspect(*entry) for entry in sorted(prepared, key=lambda entry: entry[0].casefold())]
    correlations = []
    for path, _size, _data in prepared:
        if path.lower().rsplit("/", 1)[-1] == "s7otbxsx.dll":
            prefix = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
            if (prefix + "s7otbxdx.dll").casefold() in seen:
                correlations.append(_finding("paired-step7-dll-names", "corroborated-name", "Both DLL names occur in the same directory; binary authenticity is unverified", directory=prefix or "."))
    count = sum(f["strength"] != "context" for row in records for f in row["findings"]) + len(correlations)
    return {"format": "stuxnet-artifact-inventory", "entries": records, "correlations": correlations,
            "scanned_bytes": total, "indicator_count": count,
            "assessment": "review-recommended" if count else "no-indicators-observed",
            "infection_confirmed": False}


def scan_zip(data) -> dict:
    """Scan one ZIP in memory. Reject links, traversal, encryption and bombs."""
    data = _blob(data, MAX_TOTAL)
    entries, total = [], 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ENTRIES:
                raise StuxnetError("ZIP entry limit exceeded")
            seen = set()
            for member in members:
                name = _name(member.filename)
                parts = name.rstrip("/").split("/")
                if name.startswith("/") or ":" in name or any(p in ("", ".", "..") for p in parts):
                    raise StuxnetError("unsafe ZIP member path")
                if len(parts) > MAX_DEPTH or name.casefold() in seen:
                    raise StuxnetError("ZIP depth or duplicate path limit")
                seen.add(name.casefold())
                mode = (member.external_attr >> 16) & 0xffff
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or member.flag_bits & 1:
                    raise StuxnetError("ZIP link/special/encrypted member unsupported")
                if member.is_dir():
                    continue
                total += member.file_size
                if member.file_size > MAX_FILE or total > MAX_TOTAL or member.file_size > max(member.compress_size, 1) * 200:
                    raise StuxnetError("ZIP uncompressed-size or ratio limit exceeded")
                with archive.open(member) as stream:
                    content = stream.read(MAX_FILE + 1)
                if len(content) != member.file_size:
                    raise StuxnetError("ZIP member length mismatch")
                entries.append({"path": name, "size": member.file_size, "data": content})
        return scan_manifest(entries)
    except StuxnetError:
        raise
    except Exception as exc:
        # zipfile/decompressor exception types differ with the compression method.
        raise StuxnetError(f"invalid/unsupported ZIP: {exc}") from exc


def _read_regular(path, cap):
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
            raise StuxnetError("not a regular file or file exceeds byte limit")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(cap + 1)
        if len(data) > cap:
            raise StuxnetError("file grew beyond byte limit")
        return data
    finally:
        if fd is not None:
            os.close(fd)


def scan_path(path) -> dict:
    """Scan a directory, ZIP, or artifact; refuse symlink roots/member entries.

    Intermediate components in the caller-supplied root path resolve normally.
    """
    if not isinstance(path, (str, Path)):
        raise StuxnetError("path must be text or Path")
    try:
        path = Path(path)
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise StuxnetError("symlink input is unsupported")
        if stat.S_ISDIR(info.st_mode):
            entries, pending, visited, total = [], [(path, 0)], 0, 0
            while pending:
                directory, depth = pending.pop()
                with os.scandir(directory) as children:
                    for child in children:
                        visited += 1
                        if visited > MAX_ENTRIES or depth >= MAX_DEPTH:
                            raise StuxnetError("directory entry/depth limit exceeded")
                        child_info = child.stat(follow_symlinks=False)
                        if stat.S_ISDIR(child_info.st_mode):
                            pending.append((Path(child.path), depth + 1))
                        elif stat.S_ISREG(child_info.st_mode):
                            total += child_info.st_size
                            if total > MAX_TOTAL:
                                raise StuxnetError("directory byte limit exceeded")
                            data = _read_regular(child.path, MAX_FILE)
                            entries.append({"path": str(Path(child.path).relative_to(path)), "data": data})
                        else:
                            raise StuxnetError("symlink/special directory member unsupported")
            return scan_manifest(entries)
        data = _read_regular(path, MAX_TOTAL if path.suffix.lower() == ".zip" else MAX_FILE)
        if path.suffix.lower() == ".zip" or data.startswith(b"PK\x03\x04"):
            return scan_zip(data)
        return scan_manifest([{"path": path.name, "data": data}])
    except StuxnetError:
        raise
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise StuxnetError(f"cannot inspect path: {exc}") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", help="directory, ZIP, or individual artifact")
    parser.add_argument("--manifest", action="store_true", help="read JSON [{path, size?}] instead; labels are never opened")
    parser.add_argument("--mc7", action="store_true", help="read one complete raw MC7 block")
    try:
        if argv is not None and (not isinstance(argv, (list, tuple)) or any(not isinstance(x, str) for x in argv)):
            raise StuxnetError("argv must be a list of strings")
        args = parser.parse_args(argv)
        if args.manifest and args.mc7:
            raise StuxnetError("choose manifest or MC7 mode")
        if args.manifest:
            result = scan_manifest(json.loads(_read_regular(args.path, MAX_FILE)))
        elif args.mc7:
            result = parse_mc7(_read_regular(args.path, MAX_FILE))
        else:
            result = scan_path(args.path)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (StuxnetError, OSError, ValueError, TypeError, RecursionError) as exc:
        print(f"ot_stuxnet: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
