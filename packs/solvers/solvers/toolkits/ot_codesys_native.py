#!/usr/bin/env python3
"""Bounded, offline CODESYS V3 artifact inventory; never load or execute a project.

Inspect ZIP-backed projects/archives by signature, plain symbol-configuration XML,
runtime INI configuration, and opaque .app/.application/compile artifacts. Native
serialized objects and machine code remain opaque: printable strings are evidence,
not a reconstructed symbol table. Readable vendor exports delegate to
ics_vendor_exports. No deserialization, decryption, CRC-sidecar verification,
runtime interaction, reference following, or extraction to the filesystem occurs.
All public parsing failures raise CodesysError.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath

from ics_vendor_exports import _BoundedTree, parse_export

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INPUT = 32 * 1024 * 1024
MAX_MEMBER = 8 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
MAX_MEMBERS = 256
MAX_ARCHIVE_DEPTH = 2
MAX_XML = 4 * 1024 * 1024
MAX_SYMBOLS = 5000
MAX_STRINGS = 2000
MAX_STRING_LENGTH = 1024
MAX_EVIDENCE = 8 * 1024 * 1024
MAX_CONFIG_LINES = 10000


class CodesysError(ValueError):
    """Malformed, unsupported structured, or over-limit CODESYS artifact."""


def _bytes(data, maximum=MAX_INPUT):
    if not isinstance(data, bytes) or not data or len(data) > maximum:
        raise CodesysError("data must be nonempty bytes within the input size cap")
    return data


def _local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else "#comment"


def _root(data):
    _bytes(data, MAX_XML)
    parser = ET.XMLParser(target=_BoundedTree())
    parser.feed(data)
    return parser.close()


def _shape(element):
    return {"kind": _local(element.tag), "attributes": dict(element.attrib),
            "text": element.text or "",
            "children": [_shape(child) for child in element if isinstance(child.tag, str)]}


def parse_symbol_xml(data: bytes) -> dict:
    """Read published Symbolconfiguration XML; preserve type/offset attributes.

    XML offsets describe the chosen symbol layout and are NOT memory addresses.
    DTDs and entity declarations are rejected by the shared bounded XML builder.
    """
    try:
        root = _root(data)
        if _local(root.tag) != "Symbolconfiguration":
            raise CodesysError("expected CODESYS Symbolconfiguration XML")
        headers = [child for child in root if _local(child.tag) == "Header"]
        lists = [child for child in root if _local(child.tag) == "NodeList"]
        types = [child for child in root if _local(child.tag) == "TypeList"]
        if len(lists) != 1 or len(types) > 1 or len(headers) > 1:
            raise CodesysError("symbol XML requires one NodeList and unambiguous header/types")
        records = []
        total_path = 0
        stack = [(node, ()) for node in reversed(list(lists[0])) if _local(node.tag) == "Node"]
        while stack:
            node, prefix = stack.pop()
            name = node.get("name")
            if not name:
                raise CodesysError("symbol Node has no name")
            path = prefix + (name,)
            dotted = ".".join(path)
            total_path += len(dotted)
            if len(dotted) > 4096 or total_path > MAX_EVIDENCE:
                raise CodesysError("symbol path size cap exceeded")
            children = [child for child in node if _local(child.tag) == "Node"]
            records.append({"path": dotted, "components": list(path),
                            "attributes": dict(node.attrib), "container": bool(children)})
            if len(records) > MAX_SYMBOLS:
                raise CodesysError("symbol count cap exceeded")
            stack.extend((child, path) for child in reversed(children))
        result = {"format": "codesys-symbolconfiguration", "attributes": dict(root.attrib),
                  "header": _shape(headers[0]) if headers else None,
                  "types": [_shape(child) for child in types[0]] if types else [],
                  "symbols": records,
                  "limitations": ["Symbol layout offsets are preserved, not interpreted as runtime addresses."]}
        if len(json.dumps(result, ensure_ascii=True)) > MAX_EVIDENCE:
            raise CodesysError("symbol evidence size cap exceeded")
        return result
    except CodesysError:
        raise
    except Exception as exc:
        raise CodesysError("malformed symbol configuration XML") from exc


def parse_runtime_config(data: bytes) -> dict:
    """Inventory INI section/key/value evidence, preserving repeats and line numbers.

    Includes, interpolation, variable expansion and mapped paths are never followed.
    An inline semicolon is preserved because it can be part of a runtime value.
    """
    try:
        raw = _bytes(data, MAX_XML)
        text = raw.decode("utf-8-sig")
        if "\x00" in text:
            raise CodesysError("NUL in runtime configuration")
        lines = text.splitlines()
        if len(lines) > MAX_CONFIG_LINES:
            raise CodesysError("configuration line cap exceeded")
        section = ""
        entries = []
        sections = []
        for lineno, line in enumerate(lines, 1):
            value = line.strip()
            if not value or value.startswith((";", "#")):
                continue
            if len(value) > 8192:
                raise CodesysError("configuration line length cap exceeded")
            if value.startswith("["):
                if not value.endswith("]") or not value[1:-1].strip():
                    raise CodesysError("malformed configuration section")
                section = value[1:-1].strip()
                sections.append({"name": section, "line": lineno})
            else:
                key, separator, item = value.partition("=")
                if not separator or not key.strip():
                    raise CodesysError("configuration entry requires key=value")
                entries.append({"section": section, "key": key.strip(),
                                "value": item.strip(), "line": lineno})
        if not sections and not entries:
            raise CodesysError("no configuration records")
        return {"format": "codesys-runtime-ini", "sections": sections, "entries": entries}
    except CodesysError:
        raise
    except Exception as exc:
        raise CodesysError("malformed UTF-8 runtime configuration") from exc


def _charge(budget, evidence):
    budget["evidence"] += len(json.dumps(evidence, ensure_ascii=True))
    if budget["evidence"] > MAX_EVIDENCE:
        raise CodesysError("aggregate evidence size cap exceeded")
    return evidence


def _strings(data, budget):
    found = []
    truncated = False
    patterns = (("ascii", rb"[\x20-\x7e]{4,}"),
                ("utf-16le", rb"(?:[\x20-\x7e]\x00){4,}"),
                ("utf-16be", rb"(?:\x00[\x20-\x7e]){4,}"))
    for encoding, pattern in patterns:
        for match in re.finditer(pattern, data):
            if budget["strings"] >= MAX_STRINGS:
                truncated = True
                break
            width = 1 if encoding == "ascii" else 2
            # Slice before decoding: a huge printable blob must not allocate a huge string.
            value = data[match.start():min(match.end(), match.start() + MAX_STRING_LENGTH * width)].decode(encoding)
            entry = {"offset": match.start(), "encoding": encoding, "value": value,
                     "byte_length": match.end() - match.start(),
                     "truncated": (match.end() - match.start()) > MAX_STRING_LENGTH * width}
            found.append(_charge(budget, entry))
            budget["strings"] += 1
    found.sort(key=lambda item: (item["offset"], item["encoding"]))
    return found, truncated


def _signature(data):
    for magic, label in ((b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"),
                         (b"PK\x07\x08", "zip"), (b"\x7fELF", "elf"),
                         (b"MZ", "dos-or-pe"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole-compound"),
                         (b"\x1f\x8b", "gzip"), (b"7z\xbc\xaf\x27\x1c", "7zip")):
        if data.startswith(magic):
            return label
    return "unrecognized"


def _role(name):
    suffix = PurePosixPath(name.replace("\\", "/")).suffix.lower()
    return {".project": "project", ".projectarchive": "project-archive",
            ".app": "boot-application", ".application": "application-artifact",
            ".crc": "boot-crc-sidecar", ".compileinfo": "compiler-sidecar",
            ".bootinfo": "boot-sidecar", ".p7s": "signature-sidecar",
            ".cfg": "runtime-configuration", ".ini": "runtime-configuration",
            ".library": "library"}.get(suffix, "unspecified")


def _unsafe_name(name):
    portable = name.replace("\\", "/")
    path = PurePosixPath(portable)
    return (not name or "\x00" in name or len(name) > 4096 or path.is_absolute()
            or ".." in path.parts or bool(re.match(r"^[A-Za-z]:", portable)))


def _preflight_zip(data, remaining_members):
    """Bound central-directory work before ZipFile allocates any ZipInfo objects.

    This deliberately supports single-volume, non-ZIP64 ZIPs with a contiguous
    central directory and an exact EOCD/comment ending; extended variants fail
    closed. Count the actual records, since an attacker can understate EOCD count.
    """
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0 or eocd + 22 > len(data):
        raise CodesysError("missing or truncated ZIP end record")
    _, disk, directory_disk, disk_count, total_count, cd_size, cd_offset, comment_size = struct.unpack_from(
        "<4s4H2LH", data, eocd)
    if eocd + 22 + comment_size != len(data):
        raise CodesysError("ZIP end record/comment extent mismatch")
    if disk or directory_disk or disk_count != total_count:
        raise CodesysError("multi-volume ZIPs are unsupported")
    if total_count == 0xffff or cd_size == 0xffffffff or cd_offset == 0xffffffff:
        raise CodesysError("ZIP64 archives are unsupported")
    if total_count > remaining_members:
        raise CodesysError("aggregate archive member count cap exceeded")
    if cd_offset + cd_size != eocd:
        raise CodesysError("ZIP central directory extent mismatch")
    position = cd_offset
    count = 0
    while position < eocd:
        if position + 46 > eocd or data[position:position + 4] != b"PK\x01\x02":
            raise CodesysError("malformed ZIP central directory record")
        compressed, expanded = struct.unpack_from("<LL", data, position + 20)
        name_size, extra_size, note_size, start_disk = struct.unpack_from("<4H", data, position + 28)
        local_offset = struct.unpack_from("<L", data, position + 42)[0]
        if start_disk or compressed == 0xffffffff or expanded == 0xffffffff or local_offset == 0xffffffff:
            raise CodesysError("ZIP64 or multi-volume member unsupported")
        position += 46 + name_size + extra_size + note_size
        count += 1
        if count > remaining_members:
            raise CodesysError("aggregate archive member count cap exceeded")
        if position > eocd:
            raise CodesysError("ZIP central directory record exceeds declared extent")
    if count != total_count:
        raise CodesysError("ZIP central directory member count mismatch")


def _inventory_zip(data, depth, budget):
    if depth >= MAX_ARCHIVE_DEPTH:
        return {"status": "opaque-depth-limit", "members": []}
    _preflight_zip(data, MAX_MEMBERS - budget["members"])
    members = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        budget["members"] += len(infos)
        if budget["members"] > MAX_MEMBERS:
            raise CodesysError("aggregate archive member count cap exceeded")
        seen = set()
        # Validate the entire directory and declared expansion before reading a member.
        for info in infos:
            key = info.filename.replace("\\", "/")
            if key in seen:
                raise CodesysError("duplicate archive member name")
            seen.add(key)
            if info.file_size > MAX_MEMBER:
                raise CodesysError("archive member size cap exceeded")
            budget["expanded"] += info.file_size
            if budget["expanded"] > MAX_EXPANDED:
                raise CodesysError("aggregate archive expansion size cap exceeded")
        for info in infos:
            entry = {"name": info.filename, "size": info.file_size,
                     "compressed_size": info.compress_size, "compression": info.compress_type,
                     "crc32": f"{info.CRC:08x}", "header_offset": info.header_offset,
                     "encrypted": bool(info.flag_bits & 1)}
            mode = info.external_attr >> 16
            if _unsafe_name(info.orig_filename):
                entry["status"] = "opaque-unsafe-name"
            elif stat.S_ISLNK(mode):
                entry["status"] = "opaque-symlink"
            elif info.is_dir():
                entry["status"] = "directory"
            elif info.flag_bits & 1:
                entry["status"] = "opaque-encrypted"
            elif info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                entry["status"] = "opaque-unsupported-compression"
            else:
                with archive.open(info) as handle:
                    payload = handle.read(MAX_MEMBER + 1)
                if len(payload) != info.file_size or len(payload) > MAX_MEMBER:
                    raise CodesysError("archive member length mismatch")
                entry["status"] = "inventoried"
                entry["artifact"] = _analyze(payload, info.filename, depth + 1, budget)
            members.append(entry)
            _charge(budget, {key: value for key, value in entry.items() if key != "artifact"})
        comment_hex = archive.comment.hex()
        _charge(budget, {"comment_hex": comment_hex})
        return {"status": "inventoried", "comment_hex": comment_hex, "members": members}


def _analyze(data, name, depth, budget):
    signature = _signature(data)
    role = _role(name)
    out = {"source": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
           "role_hint": role, "signature": signature, "format": "opaque",
           "strings": [], "string_limit_reached": False, "symbol_candidates": [],
           "findings": [], "limitations": []}
    if not data:
        out["format"] = "empty-member"
        return out
    if signature == "zip":
        out["format"] = "zip-container"
        out["archive"] = _inventory_zip(data, depth, budget)
        out["limitations"].append("ZIP membership does not authenticate CODESYS origin; proprietary objects remain opaque.")
        return out
    out["strings"], out["string_limit_reached"] = _strings(data, budget)
    candidates = set()
    for entry in out["strings"]:
        for match in re.finditer(r"(?<![A-Za-z0-9_])[A-Za-z_]\w*(?:\.[A-Za-z_]\w*){2,}", entry["value"], re.ASCII):
            key = (entry["offset"], match.group())
            if key not in candidates:
                candidates.add(key)
                out["symbol_candidates"].append(_charge(budget, {
                    "value": match.group(), "string_offset": entry["offset"],
                    "encoding": entry["encoding"], "evidence": "printable-string-only"}))
        for match in flagfmt.TEXT.finditer(entry["value"]):
            out["findings"].append(_charge(budget, {"kind": "flag", "value": match.group(),
                                                    "string_offset": entry["offset"]}))
    suffix = PurePosixPath(name).suffix.lower()
    looks_xml = data.lstrip().startswith((b"<", b"\xef\xbb\xbf<", b"\xff\xfe<\x00", b"\xfe\xff\x00<"))
    if looks_xml or suffix in (".xml", ".export"):
        root = _root(data)
        out["xml_root"] = _local(root.tag)
        if _local(root.tag) == "Symbolconfiguration":
            out["detail"] = _charge(budget, parse_symbol_xml(data))
            out["format"] = "codesys-symbolconfiguration"
        elif _local(root.tag) in ("ExportFile", "project", "TcPlcObject", "TcSmProject", "TwinCATProject", "Project", "FEFExchangeFile", "XEFExchangeFile"):
            out["detail"] = _charge(budget, parse_export(data, name=name))
            out["format"] = out["detail"]["format"]
        else:
            out["format"] = "unrecognized-xml"
            out["limitations"].append("XML well-formedness checked; this root has no CODESYS schema decoder.")
    elif role == "runtime-configuration":
        out["detail"] = _charge(budget, parse_runtime_config(data))
        out["format"] = "codesys-runtime-ini"
    else:
        out["limitations"].append("Opaque native/protected content: strings are evidence only, not recovered source or validated symbols.")
    return out


def analyze_bytes(data: bytes, *, name: str = "<bytes>") -> dict:
    """Inventory one artifact and at most two ZIP levels; raise only CodesysError."""
    try:
        _bytes(data)
        if not isinstance(name, str) or len(name) > 4096:
            raise CodesysError("name must be text within the name length cap")
        return _analyze(data, name, 0, {"members": 0, "expanded": 0, "strings": 0, "evidence": 0})
    except CodesysError:
        raise
    except Exception as exc:
        raise CodesysError("malformed CODESYS artifact or container") from exc


def analyze_file(path: str | Path) -> dict:
    """Bounded local-file read; never open paths mentioned inside an artifact."""
    try:
        if not isinstance(path, (str, Path)):
            raise CodesysError("path must be a local path string or Path")
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise CodesysError("artifact must be a regular local file")
        # Nonblocking open plus a descriptor check also covers replacement by a
        # FIFO between stat and open; no special file is ever read.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise CodesysError("artifact must be a regular local file")
            data = handle.read(MAX_INPUT + 1)
        return analyze_bytes(data, name=str(path))
    except CodesysError:
        raise
    except Exception as exc:
        raise CodesysError("cannot read CODESYS artifact") from exc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", help="local .project/.app/.application/archive, symbol XML, or runtime .cfg")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception:
        print("error: malformed command-line arguments", file=sys.stderr)
        return 2
    try:
        print(json.dumps(analyze_file(args.artifact), indent=2, ensure_ascii=True))
        return 0
    except CodesysError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
