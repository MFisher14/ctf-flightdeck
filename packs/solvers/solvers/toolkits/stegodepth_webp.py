#!/usr/bin/env python3
"""Bounded, codec-free WebP structural steganography auditor.

The parser walks the RIFF chunk graph, including the subchunks inside animated
``ANMF`` frames.  It exposes metadata and unknown chunks as byte artifacts,
records their exact offsets, checks VP8X feature declarations and chunk order,
and preserves bytes beyond the declared RIFF extent.  It never invokes an image
decoder and never executes or submits anything.

CLI:
    stegodepth_webp.py FILE [--pretty]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_INPUT_BYTES = 128 << 20
MAX_CHUNKS = 100_000
MAX_ARTIFACTS = 4_096

_TOP_LEVEL = {
    b"VP8X", b"ICCP", b"ANIM", b"ANMF", b"ALPH", b"VP8 ", b"VP8L",
    b"EXIF", b"XMP ",
}
_FRAME_LEVEL = {b"ALPH", b"VP8 ", b"VP8L"}
_METADATA = {b"ICCP", b"EXIF", b"XMP "}
_SINGLETONS = {b"VP8X", b"ICCP", b"ANIM", b"ALPH", b"VP8 ", b"VP8L", b"EXIF", b"XMP "}
_FEATURES = {b"ICCP": 0x20, b"EXIF": 0x08, b"XMP ": 0x04, b"ANIM": 0x02}


class StegodepthWebPError(ValueError):
    """The supplied WebP or an argument is malformed or exceeds a bound."""


@dataclass(frozen=True, slots=True)
class Chunk:
    fourcc: str
    offset: int
    data_offset: int
    size: int
    padded_end: int
    depth: int
    parent_offset: int | None


@dataclass(frozen=True, slots=True)
class Artifact:
    kind: str
    fourcc: str
    offset: int
    path: str
    data: bytes


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    offset: int
    detail: str


@dataclass(frozen=True, slots=True)
class WebPAudit:
    declared_end: int
    physical_size: int
    vp8x_flags: int | None
    chunks: tuple[Chunk, ...]
    artifacts: tuple[Artifact, ...]
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict:
        """A JSON-safe report; artifact bytes are represented by digest and head."""
        return {
            "format": "WebP",
            "declared_end": self.declared_end,
            "physical_size": self.physical_size,
            "vp8x_flags": self.vp8x_flags,
            "chunks": [
                {
                    "fourcc": row.fourcc,
                    "offset": row.offset,
                    "data_offset": row.data_offset,
                    "size": row.size,
                    "padded_end": row.padded_end,
                    "depth": row.depth,
                    "parent_offset": row.parent_offset,
                }
                for row in self.chunks
            ],
            "artifacts": [
                {
                    "kind": row.kind,
                    "fourcc": row.fourcc,
                    "offset": row.offset,
                    "path": row.path,
                    "size": len(row.data),
                    "sha256": hashlib.sha256(row.data).hexdigest(),
                    "head_hex": row.data[:32].hex(),
                }
                for row in self.artifacts
            ],
            "findings": [
                {"code": row.code, "offset": row.offset, "detail": row.detail}
                for row in self.findings
            ],
        }


def _name(raw: bytes) -> str:
    return "".join(chr(value) if 32 <= value <= 126 else f"\\x{value:02x}" for value in raw)


def _bounded_bytes(data) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise StegodepthWebPError("input must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_INPUT_BYTES:
            raise StegodepthWebPError("input exceeds the 128 MiB cap")
        return bytes(data)
    except StegodepthWebPError:
        raise
    except Exception as exc:
        raise StegodepthWebPError("input bytes could not be materialized") from exc


def _walk_chunks(
    raw: bytes,
    start: int,
    end: int,
    *,
    depth: int,
    parent_offset: int | None,
    path: str,
    chunks: list[Chunk],
    artifacts: list[Artifact],
    findings: list[Finding],
) -> list[tuple[bytes, Chunk]]:
    rows: list[tuple[bytes, Chunk]] = []
    position = start
    while position < end:
        if len(chunks) >= MAX_CHUNKS:
            raise StegodepthWebPError("chunk count exceeds cap")
        if end - position < 8:
            raise StegodepthWebPError(f"{path} ends with a partial chunk header")
        kind = raw[position:position + 4]
        size = int.from_bytes(raw[position + 4:position + 8], "little")
        data_offset = position + 8
        body_end = data_offset + size
        padded_end = body_end + (size & 1)
        if body_end < data_offset or padded_end > end:
            raise StegodepthWebPError(f"chunk {_name(kind)} at {position} leaves its container")
        row = Chunk(_name(kind), position, data_offset, size, padded_end, depth, parent_offset)
        chunks.append(row)
        rows.append((kind, row))

        body = raw[data_offset:body_end]
        allowed = _TOP_LEVEL if depth == 0 else _FRAME_LEVEL
        child_path = f"{path}/{_name(kind)}@{position}"
        if kind in _METADATA:
            if len(artifacts) >= MAX_ARTIFACTS:
                raise StegodepthWebPError("artifact count exceeds cap")
            artifacts.append(Artifact("metadata", _name(kind), data_offset, child_path, body))
            if depth:
                findings.append(Finding(
                    "misplaced-metadata", position,
                    f"{_name(kind)} metadata appears inside ANMF frame data",
                ))
        elif kind not in allowed:
            if len(artifacts) >= MAX_ARTIFACTS:
                raise StegodepthWebPError("artifact count exceeds cap")
            artifacts.append(Artifact("unknown-chunk", _name(kind), data_offset, child_path, body))
            findings.append(Finding(
                "unknown-chunk", position,
                f"preserved {_name(kind)} chunk can carry {size} opaque byte(s)",
            ))

        if size & 1 and raw[body_end] != 0:
            if len(artifacts) >= MAX_ARTIFACTS:
                raise StegodepthWebPError("artifact count exceeds cap")
            artifacts.append(Artifact(
                "nonzero-padding", _name(kind), body_end, child_path + "/padding",
                raw[body_end:body_end + 1],
            ))
            findings.append(Finding(
                "nonzero-padding", body_end,
                f"{_name(kind)} has a nonzero RIFF pad byte",
            ))

        if depth == 0 and kind == b"ANMF":
            if size < 16:
                raise StegodepthWebPError(f"ANMF at {position} is shorter than its 16-byte frame header")
            nested = _walk_chunks(
                raw, data_offset + 16, body_end, depth=1, parent_offset=position,
                path=child_path, chunks=chunks, artifacts=artifacts, findings=findings,
            )
            image_chunks = [item for item, _nested_row in nested if item in (b"VP8 ", b"VP8L")]
            if len(image_chunks) != 1:
                findings.append(Finding(
                    "frame-image-count", position,
                    f"ANMF frame contains {len(image_chunks)} image bitstream chunks (expected one)",
                ))
            order = [item for item, _nested_row in nested]
            if b"ALPH" in order and image_chunks and order.index(b"ALPH") > min(
                order.index(item) for item in image_chunks
            ):
                findings.append(Finding(
                    "frame-alpha-order", position,
                    "ANMF ALPH chunk follows its image bitstream",
                ))
        position = padded_end
    return rows


def _add_structure_findings(
    raw: bytes,
    top: list[tuple[bytes, Chunk]],
    all_chunks: list[Chunk],
    findings: list[Finding],
) -> int | None:
    kinds = [kind for kind, _row in top]
    for kind in _SINGLETONS:
        offsets = [row.offset for item, row in top if item == kind]
        if len(offsets) > 1:
            findings.append(Finding(
                "duplicate-chunk", offsets[1],
                f"top-level {_name(kind)} occurs {len(offsets)} times",
            ))

    vp8x_rows = [row for kind, row in top if kind == b"VP8X"]
    flags = None
    if vp8x_rows:
        row = vp8x_rows[0]
        body = raw[row.data_offset:row.data_offset + row.size]
        if len(body) != 10:
            findings.append(Finding(
                "vp8x-size", row.offset, f"VP8X payload is {len(body)} bytes (expected 10)",
            ))
        else:
            flags = body[0]
            if flags & 0xC1 or any(body[1:4]):
                findings.append(Finding(
                    "vp8x-reserved-bits", row.data_offset,
                    "VP8X reserved feature/header bits are nonzero",
                ))
            present = set(kinds)
            for feature, bit in _FEATURES.items():
                declared = bool(flags & bit)
                actual = feature in present or (feature == b"ANIM" and b"ANMF" in present)
                if declared != actual:
                    findings.append(Finding(
                        "vp8x-feature-mismatch", row.offset,
                        f"VP8X {_name(feature)} flag is {declared} but chunk presence is {actual}",
                    ))
            has_alpha_chunk = any(chunk.fourcc == "ALPH" for chunk in all_chunks)
            if has_alpha_chunk and not flags & 0x10:
                findings.append(Finding(
                    "vp8x-feature-mismatch", row.offset,
                    "ALPH chunk is present but the VP8X alpha flag is clear",
                ))
        if kinds and kinds[0] != b"VP8X":
            findings.append(Finding(
                "vp8x-order", row.offset, "VP8X is not the first top-level chunk",
            ))

    anim_offsets = [row.offset for kind, row in top if kind == b"ANIM"]
    frame_offsets = [row.offset for kind, row in top if kind == b"ANMF"]
    if frame_offsets and not anim_offsets:
        findings.append(Finding(
            "animation-control-missing", frame_offsets[0], "ANMF frame exists without ANIM control chunk",
        ))
    if anim_offsets and not frame_offsets:
        findings.append(Finding(
            "animation-frames-missing", anim_offsets[0], "ANIM control exists without ANMF frames",
        ))
    if anim_offsets and frame_offsets and anim_offsets[0] > frame_offsets[0]:
        findings.append(Finding(
            "animation-order", anim_offsets[0], "ANIM control follows an ANMF frame",
        ))

    images = [(kind, row.offset) for kind, row in top if kind in (b"VP8 ", b"VP8L")]
    if not images and not frame_offsets:
        findings.append(Finding(
            "image-data-missing", top[0][1].offset if top else 12,
            "WebP contains neither a still-image bitstream nor an animation frame",
        ))
    if len(images) > 1:
        findings.append(Finding(
            "top-image-count", images[1][1],
            f"top level contains {len(images)} image bitstream chunks",
        ))
    if images and frame_offsets:
        findings.append(Finding(
            "mixed-still-animation", images[0][1],
            "top-level still bitstream and ANMF animation frames coexist",
        ))
    return flags


def audit_webp(data) -> WebPAudit | None:
    """Audit supplied bytes, returning ``None`` for a non-WebP.

    Once the RIFF/WEBP identity is established, malformed structure raises only
    :class:`StegodepthWebPError`.
    """
    try:
        raw = _bounded_bytes(data)
        if len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WEBP":
            return None
        riff_size = int.from_bytes(raw[4:8], "little")
        declared_end = 8 + riff_size
        if riff_size < 4 or declared_end < 12:
            raise StegodepthWebPError("RIFF size is smaller than the WEBP form header")
        if declared_end > len(raw):
            raise StegodepthWebPError("declared RIFF extent is truncated")

        chunks: list[Chunk] = []
        artifacts: list[Artifact] = []
        findings: list[Finding] = []
        if riff_size & 1:
            findings.append(Finding(
                "odd-riff-size", 4, "WebP RIFF size is odd despite padded chunk layout",
            ))
        top = _walk_chunks(
            raw, 12, declared_end, depth=0, parent_offset=None, path="WEBP",
            chunks=chunks, artifacts=artifacts, findings=findings,
        )
        flags = _add_structure_findings(raw, top, chunks, findings)

        if declared_end < len(raw):
            if len(artifacts) >= MAX_ARTIFACTS:
                raise StegodepthWebPError("artifact count exceeds cap")
            tail = raw[declared_end:]
            artifacts.append(Artifact("post-riff-tail", "TAIL", declared_end, "WEBP/tail", tail))
            findings.append(Finding(
                "post-riff-tail", declared_end,
                f"{len(tail)} byte(s) follow the declared RIFF extent",
            ))
        findings.sort(key=lambda row: (row.offset, row.code, row.detail))
        return WebPAudit(
            declared_end, len(raw), flags, tuple(chunks), tuple(artifacts), tuple(findings)
        )
    except StegodepthWebPError:
        raise
    except (TypeError, ValueError, OverflowError, IndexError, MemoryError) as exc:
        raise StegodepthWebPError("WebP structure could not be audited") from exc


def _read(path: str) -> bytes:
    try:
        candidate = Path(path)
        with candidate.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise StegodepthWebPError("input exceeds the 128 MiB cap")
        return raw
    except StegodepthWebPError:
        raise
    except (OSError, ValueError, TypeError, OverflowError) as exc:
        raise StegodepthWebPError(f"cannot read {path!r}") from exc


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise StegodepthWebPError(message)


def main(argv=None) -> int:
    parser = _Parser(description="bounded codec-free WebP structural/stego auditor")
    parser.add_argument("input")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            return exc.code if isinstance(exc.code, int) else 2
        report = audit_webp(_read(args.input))
        if report is None:
            raise StegodepthWebPError("input is not a RIFF/WEBP file")
        print(json.dumps(report.to_dict(), indent=2 if args.pretty else None, sort_keys=True))
        return 0
    except StegodepthWebPError as exc:
        print(f"stegodepth_webp: {exc}", file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError, OverflowError, MemoryError) as exc:
        print(f"stegodepth_webp: output failed ({type(exc).__name__})", file=sys.stderr)
        return 2


__all__ = [
    "StegodepthWebPError", "Chunk", "Artifact", "Finding", "WebPAudit",
    "audit_webp", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
