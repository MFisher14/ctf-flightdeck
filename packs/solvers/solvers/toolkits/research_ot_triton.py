#!/usr/bin/env python3
"""Offline TRITON/TRISIS (HatMan) artifact and combined-payload inspector.

The combined controller payload layout and artifact SHA-1 values come from
CISA MAR-17-352-01, "HatMan - Safety System Targeted Malware" (Update B).
This module never executes, imports, extracts, or uploads supplied content.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import zipfile
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar


MAX_INPUT = 64 * 1024 * 1024
MAX_NAME = 4096
MAX_ZIP_MEMBERS = 4096
MAX_ZIP_MEMBER_NAME = 4096
MAX_ZIP_MEMBER_UNCOMPRESSED = 64 * 1024 * 1024
MAX_ZIP_UNCOMPRESSED = 256 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 1000.0
MAX_MARKER_CANDIDATES = 4096

FIRST_MARKER = 0x00001234
SECOND_MARKER = 0x0056789A

# CISA MAR-17-352-01 Update B, table of analyzed files.  These are identity
# indicators, not an attribution verdict on their own.
KNOWN_SHA1_BY_NAME: dict[str, str] = {
    "library.zip": "1dd89871c4f8eca7a42642bf4c5ec2aa7688fd5c",
    "TsLow.pyc": "a6357a8792e68b05690a9736bc3051cba4b43227",
    "TsBase.pyc": "d6e997a4b6a54d1aeedb646731f3b0893aee4b82",
    "TsHi.pyc": "66d39af5d61507cf7ea29e4b213f8d7dc9598bed",
    "TS_cnames.pyc": "97e785e92b416638c3a584ffbfce9f8f0434a5fd",
    "crc.pyc": "2262362200aa28b0eead1348cb6fda3b6c83ae01",
    "sh.pyc": "25dd6785b941ffe6085dd5b4dbded37e1077e222",
    "trilog.exe": "dc81f383624955e0c0441734f9f1dabfe03f373c",
    "PresetStatus": "78265509956028b34a9cb44d8df1fcc7d0690be2",
    "dummy": "1c7769053cfd6dd3466b69988744353b3abee013",
    "inject.bin": "f403292f6cb315c84f84f6c51490e2e8cd03c686",
    "imain.bin": "b47ad4840089247b058121e95732beb82e6311d0",
}

ARTIFACT_ROLES: dict[str, str] = {
    "library.zip": "Python runtime library archive",
    "TsLow.pyc": "TriStation low-level protocol module",
    "TsBase.pyc": "TriStation base protocol module",
    "TsHi.pyc": "TriStation high-level protocol module",
    "TS_cnames.pyc": "TriStation command-name module",
    "crc.pyc": "CRC support module",
    "sh.pyc": "shell/support module",
    "trilog.exe": "HatMan workstation executable",
    "PresetStatus": "controller-side artifact",
    "dummy": "controller-side artifact",
    "inject.bin": "controller injection payload",
    "imain.bin": "controller main payload",
}

_NAME_LOOKUP = {name.casefold(): name for name in KNOWN_SHA1_BY_NAME}
_HASH_LOOKUP: dict[str, list[str]] = {}
for _indicator_name, _indicator_hash in KNOWN_SHA1_BY_NAME.items():
    _HASH_LOOKUP.setdefault(_indicator_hash, []).append(_indicator_name)


class TritonArtifactError(ValueError):
    """Artifact is malformed, unsupported, ambiguous, or exceeds a limit."""


_F = TypeVar("_F", bound=Callable[..., Any])


def _guard(function: _F) -> _F:
    """Normalize every ordinary implementation failure to the public error."""
    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except TritonArtifactError:
            raise
        except Exception as exc:
            raise TritonArtifactError("malformed TRITON/HatMan artifact") from exc

    return wrapped  # type: ignore[return-value]


def _blob(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TritonArtifactError("input must be bytes-like")
    try:
        size = len(data)
    except Exception as exc:
        raise TritonArtifactError("input length is unavailable") from exc
    if size == 0:
        raise TritonArtifactError("input is empty")
    if size > MAX_INPUT:
        raise TritonArtifactError("input exceeds size limit")
    return bytes(data)


def _display_name(name: str) -> str:
    if not isinstance(name, str):
        raise TritonArtifactError("artifact name must be text")
    if not name or len(name) > MAX_NAME or "\x00" in name:
        raise TritonArtifactError("artifact name is empty or invalid")
    return name.replace("\\", "/").rsplit("/", 1)[-1]


@_guard
def identify_name(name: str) -> dict[str, str] | None:
    """Return the CISA name indicator, if *name* has a known basename."""
    basename = _display_name(name)
    canonical = _NAME_LOOKUP.get(basename.casefold())
    if canonical is None:
        return None
    return {
        "name": canonical,
        "sha1": KNOWN_SHA1_BY_NAME[canonical],
        "role": ARTIFACT_ROLES[canonical],
        "evidence": "filename-only",
    }


@_guard
def identify_sha1(value: str) -> list[dict[str, str]]:
    """Return CISA artifact identities for a normalized SHA-1 value."""
    if not isinstance(value, str) or not re.fullmatch(r"[0-9A-Fa-f]{40}", value):
        raise TritonArtifactError("SHA-1 must be exactly 40 hexadecimal characters")
    digest = value.lower()
    return [
        {"name": name, "sha1": digest, "role": ARTIFACT_ROLES[name], "evidence": "exact-sha1"}
        for name in _HASH_LOOKUP.get(digest, [])
    ]


def _payload_candidates(data: bytes) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    markers_seen = 0
    byte_order = "little"
    first = FIRST_MARKER.to_bytes(4, byte_order)
    second = SECOND_MARKER.to_bytes(4, byte_order)
    start = 0
    while True:
        marker_offset = data.find(first, start)
        if marker_offset < 0:
            break
        start = marker_offset + 1
        markers_seen += 1
        if markers_seen > MAX_MARKER_CANDIDATES:
            raise TritonArtifactError("combined-payload marker candidate limit exceeded")
        length_offset = marker_offset - 4
        if length_offset <= 0:
            continue
        declared = int.from_bytes(data[length_offset:marker_offset], byte_order)
        if declared <= 8 or declared > MAX_INPUT:
            continue
        imain_length = declared - 8
        imain_offset = marker_offset + 4
        trailer_offset = imain_offset + imain_length
        if trailer_offset + 8 != len(data):
            continue
        if int.from_bytes(data[trailer_offset:trailer_offset + 4], byte_order) != declared:
            continue
        if data[trailer_offset + 4:trailer_offset + 8] != second:
            continue
        inject = data[:length_offset]
        imain = data[imain_offset:trailer_offset]
        if not inject or not imain:
            continue
        candidates.append({
            "format": "hatman-combined-payload",
            "evidence": "validated-combined-payload-structure",
            "byte_order": byte_order,
            "marker_evidence": "CISA MAR Appendix A YARA byte sequence",
            "length_encoding": "little-endian structural interpretation",
            "total_size": len(data),
            "declared_imain_plus_trailer": declared,
            "markers": [f"0x{FIRST_MARKER:08x}", f"0x{SECOND_MARKER:08x}"],
            "inject": {
                "offset": 0,
                "length": len(inject),
                "sha1": hashlib.sha1(inject).hexdigest(),
                "known_hash_matches": identify_sha1(hashlib.sha1(inject).hexdigest()),
            },
            "imain": {
                "offset": imain_offset,
                "length": len(imain),
                "sha1": hashlib.sha1(imain).hexdigest(),
                "known_hash_matches": identify_sha1(hashlib.sha1(imain).hexdigest()),
            },
            "layout": {
                "length_offset": length_offset,
                "first_marker_offset": marker_offset,
                "second_length_offset": trailer_offset,
                "second_marker_offset": trailer_offset + 4,
            },
        })
    return candidates


@_guard
def parse_combined_payload(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Strictly validate and describe one CISA-documented combined payload.

    The whole input must be ``inject || n || 0x1234 || imain || n ||
    0x56789a``.  The MAR Appendix A YARA confirms the marker byte order.  The
    length words are interpreted little-endian to match that observed
    serialization; the prose specifies their values but does not print their
    raw bytes.  A big-endian structural lookalike is deliberately not reported
    as observed HatMan evidence.
    """
    blob = _blob(data)
    candidates = _payload_candidates(blob)
    if not candidates:
        raise TritonArtifactError("input does not match the HatMan combined-payload layout")
    if len(candidates) != 1:
        raise TritonArtifactError("combined-payload layout is ambiguous")
    return candidates[0]


def _unsafe_member_reason(name: str) -> str | None:
    normalized = name.replace("\\", "/")
    components = normalized.split("/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return "absolute path"
    if any(component == ".." for component in components):
        return "parent traversal"
    if "\x00" in name:
        return "NUL in name"
    return None


@_guard
def inspect_zip(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Inventory ZIP central-directory metadata without reading any member."""
    blob = _blob(data)
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob), "r")
        with archive:
            infos = archive.infolist()
            if len(infos) > MAX_ZIP_MEMBERS:
                raise TritonArtifactError("ZIP member count exceeds limit")
            total_uncompressed = 0
            seen: set[str] = set()
            members: list[dict[str, Any]] = []
            recognized: list[dict[str, str]] = []
            findings: list[dict[str, str]] = []
            for info in infos:
                name = info.filename
                if not isinstance(name, str) or not name or len(name) > MAX_ZIP_MEMBER_NAME:
                    raise TritonArtifactError("ZIP contains an invalid member name")
                if info.file_size < 0 or info.compress_size < 0:
                    raise TritonArtifactError("ZIP contains a negative member size")
                if info.file_size > MAX_ZIP_MEMBER_UNCOMPRESSED:
                    raise TritonArtifactError("ZIP member uncompressed size exceeds limit")
                if info.file_size:
                    if info.compress_size == 0:
                        raise TritonArtifactError("ZIP member compression ratio exceeds limit")
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_ZIP_COMPRESSION_RATIO:
                        raise TritonArtifactError("ZIP member compression ratio exceeds limit")
                else:
                    ratio = 0.0
                total_uncompressed += info.file_size
                if total_uncompressed > MAX_ZIP_UNCOMPRESSED:
                    raise TritonArtifactError("ZIP declared uncompressed size exceeds limit")
                folded = name.replace("\\", "/").casefold()
                duplicate = folded in seen
                seen.add(folded)
                unsafe = _unsafe_member_reason(name)
                encrypted = bool(info.flag_bits & 0x1)
                member = {
                    "name": name,
                    "compressed_size": info.compress_size,
                    "uncompressed_size": info.file_size,
                    "crc32": f"{info.CRC & 0xffffffff:08x}",
                    "compression": info.compress_type,
                    "compression_ratio": round(ratio, 3),
                    "encrypted": encrypted,
                    "directory": info.is_dir(),
                }
                members.append(member)
                if duplicate:
                    findings.append({"kind": "duplicate-member", "name": name})
                if unsafe:
                    findings.append({"kind": "unsafe-path", "name": name, "detail": unsafe})
                if encrypted:
                    findings.append({"kind": "encrypted-member", "name": name})
                match = identify_name(name)
                if match is not None:
                    recognized.append(match)
            present = {item["name"] for item in recognized}
            expected_runtime = {
                "TsLow.pyc", "TsBase.pyc", "TsHi.pyc", "TS_cnames.pyc", "crc.pyc", "sh.pyc"
            }
            return {
                "format": "zip-inventory",
                "size": len(blob),
                "sha1": hashlib.sha1(blob).hexdigest(),
                "member_count": len(members),
                "total_uncompressed_size": total_uncompressed,
                "members": members,
                "recognized_hatman_names": recognized,
                "runtime_module_completeness": {
                    "present": sorted(present & expected_runtime),
                    "missing": sorted(expected_runtime - present),
                },
                "findings": findings,
                "limitations": [
                    "Central-directory metadata only; members were not opened, decompressed, or extracted."
                ],
            }
    except TritonArtifactError:
        raise
    except Exception as exc:
        raise TritonArtifactError("malformed ZIP artifact") from exc


@_guard
def analyze_bytes(
    data: bytes | bytearray | memoryview,
    *,
    name: str = "artifact.bin",
    kind: str = "auto",
) -> dict[str, Any]:
    """Analyze one static artifact; never execute or extract its content."""
    blob = _blob(data)
    basename = _display_name(name)
    if kind not in {"auto", "artifact", "payload", "zip"}:
        raise TritonArtifactError("unsupported analysis kind")
    digest = hashlib.sha1(blob).hexdigest()
    identity = {
        "name": basename,
        "size": len(blob),
        "sha1": digest,
        "known_name_match": identify_name(basename),
        "known_hash_matches": identify_sha1(digest),
    }
    zip_magic = blob.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    marker_present = any(marker.to_bytes(4, "little") in blob for marker in (FIRST_MARKER, SECOND_MARKER))
    if kind == "zip" or (kind == "auto" and zip_magic):
        result = inspect_zip(blob)
    elif kind == "payload" or (kind == "auto" and marker_present):
        result = parse_combined_payload(blob)
    else:
        result = {"format": "artifact"}
    return {"identity": identity, **result}


@_guard
def analyze_file(path: str | Path, *, kind: str = "auto") -> dict[str, Any]:
    """Read one bounded local artifact and analyze it statically."""
    if not isinstance(path, (str, Path)):
        raise TritonArtifactError("path must be text or pathlib.Path")
    path_value = Path(path)
    try:
        with path_value.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
    except Exception as exc:
        raise TritonArtifactError("cannot read artifact") from exc
    return analyze_bytes(data, name=path_value.name, kind=kind)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="local artifact to inspect")
    parser.add_argument("--kind", choices=("auto", "artifact", "payload", "zip"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = analyze_file(args.file, kind=args.kind)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except TritonArtifactError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "ARTIFACT_ROLES",
    "KNOWN_SHA1_BY_NAME",
    "TritonArtifactError",
    "analyze_bytes",
    "analyze_file",
    "identify_name",
    "identify_sha1",
    "inspect_zip",
    "main",
    "parse_combined_payload",
]


if __name__ == "__main__":
    raise SystemExit(main())
