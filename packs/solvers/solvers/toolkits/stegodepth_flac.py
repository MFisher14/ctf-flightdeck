#!/usr/bin/env python3
"""Bounded, static FLAC metadata-carrier auditor.

This engine does not decode audio frames.  It walks the metadata prefix defined
by RFC 9639, reports the exact first-audio-frame offset, and exposes carrier
bytes that ordinary tag summaries hide:

* non-zero PADDING (invalid: padding is specified as zero bits),
* APPLICATION data after its mandatory four-byte application identifier,
* reserved metadata block bodies,
* complete Vorbis comments, and
* complete PICTURE payloads with their byte provenance.

APPLICATION, reserved, comment, and picture data are legal format features and
are therefore labelled as carrier capacity, not proof of steganography.
Malformed FLAC input raises only :class:`StegodepthFLACError`; a byte string
that is simply not FLAC returns ``None``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


MAX_INPUT = 128 << 20
MAX_ID3 = 16 << 20
MAX_METADATA = 64 << 20
MAX_BLOCKS = 4096
MAX_COMMENTS = 100_000

BLOCK_NAMES = {
    0: "STREAMINFO",
    1: "PADDING",
    2: "APPLICATION",
    3: "SEEKTABLE",
    4: "VORBIS_COMMENT",
    5: "CUESHEET",
    6: "PICTURE",
}


class StegodepthFLACError(ValueError):
    """The supplied FLAC structure or a requested operation is invalid."""


@dataclass(frozen=True, slots=True)
class FLACBlock:
    index: int
    type_id: int
    name: str
    header_offset: int
    data_offset: int
    length: int
    last: bool


@dataclass(frozen=True, slots=True)
class FLACArtifact:
    kind: str
    block_index: int
    offset: int
    data: bytes
    evidence: str
    suspicious: bool
    application_id: bytes | None = None


@dataclass(frozen=True, slots=True)
class VorbisComment:
    block_index: int
    offset: int
    vendor: str
    key: str
    value: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class FLACPicture:
    block_index: int
    data_offset: int
    picture_type: int
    media_type: str
    description: str
    width: int
    height: int
    depth: int
    colors: int
    data: bytes


@dataclass(frozen=True, slots=True)
class StreamInfo:
    minimum_block_size: int
    maximum_block_size: int
    minimum_frame_size: int
    maximum_frame_size: int
    sample_rate: int
    channels: int
    bits_per_sample: int
    total_samples: int
    md5_hex: str


@dataclass(frozen=True, slots=True)
class FLACReport:
    id3_size: int
    signature_offset: int
    audio_offset: int
    blocks: tuple[FLACBlock, ...]
    streaminfo: StreamInfo
    artifacts: tuple[FLACArtifact, ...]
    comments: tuple[VorbisComment, ...]
    pictures: tuple[FLACPicture, ...]


def _error(message: str, cause: BaseException | None = None):
    exc = StegodepthFLACError(message)
    if cause is None:
        raise exc
    raise exc from cause


def _u32be(data: bytes, offset: int, end: int, what: str) -> tuple[int, int]:
    if offset < 0 or offset + 4 > end:
        _error(f"truncated {what}")
    return int.from_bytes(data[offset:offset + 4], "big"), offset + 4


def _u32le(data: bytes, offset: int, end: int, what: str) -> tuple[int, int]:
    if offset < 0 or offset + 4 > end:
        _error(f"truncated {what}")
    return int.from_bytes(data[offset:offset + 4], "little"), offset + 4


def _take(data: bytes, offset: int, length: int, end: int, what: str) -> tuple[bytes, int]:
    if length < 0 or offset < 0 or length > end - offset:
        _error(f"truncated {what}")
    return data[offset:offset + length], offset + length


def _id3_prefix(data: bytes) -> int:
    if not data.startswith(b"ID3"):
        return 0
    if len(data) < 10:
        _error("truncated ID3v2 prefix")
    version, flags = data[3], data[5]
    size_bytes = data[6:10]
    if version not in (2, 3, 4) or any(value & 0x80 for value in size_bytes):
        _error("invalid ID3v2 prefix")
    size = 0
    for value in size_bytes:
        size = (size << 7) | value
    footer = 10 if version == 4 and flags & 0x10 else 0
    total = 10 + size + footer
    if total > MAX_ID3 or total > len(data):
        _error("ID3v2 prefix is truncated or exceeds the size cap")
    return total


def _streaminfo(body: bytes) -> StreamInfo:
    if len(body) != 34:
        _error("STREAMINFO must be exactly 34 bytes")
    try:
        minimum_block, maximum_block = struct.unpack_from(">HH", body, 0)
        minimum_frame = int.from_bytes(body[4:7], "big")
        maximum_frame = int.from_bytes(body[7:10], "big")
        packed = int.from_bytes(body[10:18], "big")
    except (struct.error, ValueError, TypeError, OverflowError) as exc:
        _error("STREAMINFO does not parse", exc)
    if not 16 <= minimum_block <= maximum_block <= 65535:
        _error("STREAMINFO block-size bounds are invalid")
    bits_per_sample = ((packed >> 36) & 0x1F) + 1
    if bits_per_sample < 4:
        _error("STREAMINFO bit depth is outside FLAC's 4-32 bit range")
    return StreamInfo(
        minimum_block,
        maximum_block,
        minimum_frame,
        maximum_frame,
        packed >> 44,
        ((packed >> 41) & 0x7) + 1,
        bits_per_sample,
        packed & ((1 << 36) - 1),
        body[18:34].hex(),
    )


def _parse_comments(
    body: bytes, block: FLACBlock
) -> tuple[VorbisComment, ...]:
    end = len(body)
    vendor_length, at = _u32le(body, 0, end, "Vorbis vendor length")
    vendor_raw, at = _take(body, at, vendor_length, end, "Vorbis vendor")
    count, at = _u32le(body, at, end, "Vorbis comment count")
    if count > MAX_COMMENTS:
        _error("Vorbis comment count exceeds the cap")
    try:
        vendor = vendor_raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _error("Vorbis vendor is not UTF-8", exc)
    out: list[VorbisComment] = []
    for index in range(count):
        length, at = _u32le(body, at, end, f"Vorbis comment {index} length")
        raw_at = at
        raw, at = _take(body, at, length, end, f"Vorbis comment {index}")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            _error(f"Vorbis comment {index} is not UTF-8", exc)
        key, separator, value = text.partition("=")
        if (not separator or not key or any(
            ord(char) < 0x20 or ord(char) > 0x7E or char == "=" for char in key
        )):
            _error(f"Vorbis comment {index} has an invalid field name")
        out.append(VorbisComment(
            block.index,
            block.data_offset + raw_at,
            vendor,
            key,
            value,
            raw,
        ))
    if at != end:
        _error("Vorbis comment block has unowned trailing bytes")
    return tuple(out)


def _parse_picture(body: bytes, block: FLACBlock) -> FLACPicture:
    end = len(body)
    picture_type, at = _u32be(body, 0, end, "picture type")
    mime_length, at = _u32be(body, at, end, "picture media-type length")
    mime_raw, at = _take(body, at, mime_length, end, "picture media type")
    description_length, at = _u32be(body, at, end, "picture description length")
    description_raw, at = _take(body, at, description_length, end, "picture description")
    values = []
    for name in ("width", "height", "depth", "color count", "data length"):
        value, at = _u32be(body, at, end, f"picture {name}")
        values.append(value)
    picture_at = at
    payload, at = _take(body, at, values[4], end, "picture payload")
    if at != end:
        _error("PICTURE block has unowned trailing bytes")
    try:
        media_type = mime_raw.decode("ascii")
        description = description_raw.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        _error("PICTURE strings do not use their required encoding", exc)
    if any(ord(char) < 0x20 or ord(char) > 0x7E for char in media_type):
        _error("PICTURE media type is not printable ASCII")
    return FLACPicture(
        block.index,
        block.data_offset + picture_at,
        picture_type,
        media_type,
        description,
        values[0],
        values[1],
        values[2],
        values[3],
        payload,
    )


def audit_flac(source: bytes | bytearray | memoryview) -> FLACReport | None:
    """Audit a native FLAC stream without decoding audio frames.

    Non-FLAC bytes return ``None``.  Once an optional ID3 prefix or ``fLaC``
    signature identifies the format, structural failure raises only
    :class:`StegodepthFLACError`.
    """
    if not isinstance(source, (bytes, bytearray, memoryview)):
        _error("source must be bytes-like")
    try:
        if isinstance(source, memoryview) and source.nbytes > MAX_INPUT:
            _error("input exceeds the size cap")
        if len(source) > MAX_INPUT:
            _error("input exceeds the size cap")
        data = bytes(source)
    except StegodepthFLACError:
        raise
    except Exception as exc:
        _error("source cannot be materialized safely", exc)
    if not data.startswith((b"fLaC", b"ID3")):
        return None
    id3_size = _id3_prefix(data)
    if data[id3_size:id3_size + 4] != b"fLaC":
        # ID3v2 is also a normal prefix for MP3 and is not sufficient to
        # identify a FLAC stream on its own.
        return None
    signature_offset = id3_size
    at = signature_offset + 4
    metadata_start = at
    blocks: list[FLACBlock] = []
    artifacts: list[FLACArtifact] = []
    comments: list[VorbisComment] = []
    pictures: list[FLACPicture] = []
    streaminfo: StreamInfo | None = None
    saw_vorbis_comment = False
    singleton_picture_types: set[int] = set()
    last = False
    try:
        while not last:
            if len(blocks) >= MAX_BLOCKS:
                _error("metadata block count exceeds the cap")
            if at + 4 > len(data):
                _error("truncated FLAC metadata block header")
            header_offset = at
            first = data[at]
            last = bool(first & 0x80)
            type_id = first & 0x7F
            length = int.from_bytes(data[at + 1:at + 4], "big")
            at += 4
            if type_id == 127:
                _error("metadata block type 127 is forbidden")
            if at + length > len(data):
                _error("truncated FLAC metadata block body")
            if at + length - metadata_start > MAX_METADATA:
                _error("metadata exceeds the aggregate size cap")
            block = FLACBlock(
                len(blocks),
                type_id,
                BLOCK_NAMES.get(type_id, "RESERVED"),
                header_offset,
                at,
                length,
                last,
            )
            body = data[at:at + length]
            blocks.append(block)
            if block.index == 0:
                if type_id != 0:
                    _error("the first FLAC metadata block is not STREAMINFO")
                streaminfo = _streaminfo(body)
            elif type_id == 0:
                _error("FLAC contains more than one STREAMINFO block")
            if type_id == 1 and any(body):
                artifacts.append(FLACArtifact(
                    "nonzero-padding", block.index, block.data_offset, body,
                    "RFC 9639 PADDING is defined as zero bits", True,
                ))
            elif type_id == 2:
                if len(body) < 4:
                    _error("APPLICATION block is shorter than its four-byte identifier")
                if len(body) > 4:
                    artifacts.append(FLACArtifact(
                        "application-data", block.index, block.data_offset + 4, body[4:],
                        "legal application-owned carrier data", False, body[:4],
                    ))
            elif type_id == 4:
                if saw_vorbis_comment:
                    _error("FLAC contains more than one Vorbis comment block")
                saw_vorbis_comment = True
                comments.extend(_parse_comments(body, block))
            elif type_id == 6:
                picture = _parse_picture(body, block)
                if picture.picture_type in (1, 2):
                    if picture.picture_type in singleton_picture_types:
                        _error(
                            f"FLAC contains more than one picture of singleton type "
                            f"{picture.picture_type}"
                        )
                    singleton_picture_types.add(picture.picture_type)
                pictures.append(picture)
                artifacts.append(FLACArtifact(
                    "picture-data", block.index, picture.data_offset, picture.data,
                    f"legal PICTURE payload ({picture.media_type or 'unspecified media type'})",
                    False,
                ))
            elif 7 <= type_id <= 126 and body:
                artifacts.append(FLACArtifact(
                    "reserved-block", block.index, block.data_offset, body,
                    f"legal reserved metadata type {type_id}; inspect as carrier capacity", False,
                ))
            at += length
    except StegodepthFLACError:
        raise
    except Exception as exc:
        _error("FLAC metadata does not parse", exc)
    if streaminfo is None:
        _error("FLAC has no STREAMINFO block")
    return FLACReport(
        id3_size,
        signature_offset,
        at,
        tuple(blocks),
        streaminfo,
        tuple(artifacts),
        tuple(comments),
        tuple(pictures),
    )


def audit_path(path: str | Path) -> FLACReport | None:
    """Read one bounded path and run :func:`audit_flac`."""
    try:
        target = Path(path)
        with target.open("rb") as stream:
            data = stream.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            _error("input exceeds the size cap")
        return audit_flac(data)
    except StegodepthFLACError:
        raise
    except Exception as exc:
        _error(f"cannot read input: {exc}", exc)


def _blob_summary(data: bytes) -> dict:
    return {
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "head_hex": data[:32].hex(),
    }


def _report_dict(report: FLACReport) -> dict:
    return {
        "id3_size": report.id3_size,
        "signature_offset": report.signature_offset,
        "audio_offset": report.audio_offset,
        "streaminfo": {
            "minimum_block_size": report.streaminfo.minimum_block_size,
            "maximum_block_size": report.streaminfo.maximum_block_size,
            "minimum_frame_size": report.streaminfo.minimum_frame_size,
            "maximum_frame_size": report.streaminfo.maximum_frame_size,
            "sample_rate": report.streaminfo.sample_rate,
            "channels": report.streaminfo.channels,
            "bits_per_sample": report.streaminfo.bits_per_sample,
            "total_samples": report.streaminfo.total_samples,
            "md5_hex": report.streaminfo.md5_hex,
        },
        "blocks": [
            {
                "index": block.index,
                "type_id": block.type_id,
                "name": block.name,
                "header_offset": block.header_offset,
                "data_offset": block.data_offset,
                "length": block.length,
                "last": block.last,
            }
            for block in report.blocks
        ],
        "artifacts": [
            {
                "kind": artifact.kind,
                "block_index": artifact.block_index,
                "offset": artifact.offset,
                "evidence": artifact.evidence,
                "suspicious": artifact.suspicious,
                "application_id_hex": (
                    artifact.application_id.hex() if artifact.application_id is not None else None
                ),
                **_blob_summary(artifact.data),
            }
            for artifact in report.artifacts
        ],
        "comments": [
            {
                "block_index": comment.block_index,
                "offset": comment.offset,
                "vendor": comment.vendor,
                "key": comment.key,
                "value": comment.value,
                "raw_hex": comment.raw.hex(),
            }
            for comment in report.comments
        ],
        "pictures": [
            {
                "block_index": picture.block_index,
                "data_offset": picture.data_offset,
                "picture_type": picture.picture_type,
                "media_type": picture.media_type,
                "description": picture.description,
                "width": picture.width,
                "height": picture.height,
                "depth": picture.depth,
                "colors": picture.colors,
                **_blob_summary(picture.data),
            }
            for picture in report.pictures
        ],
    }


def report_dict(report: FLACReport) -> dict:
    """Convert a report to JSON-safe metadata without dumping arbitrary blobs."""
    if not isinstance(report, FLACReport):
        _error("report must be an FLACReport")
    try:
        return _report_dict(report)
    except StegodepthFLACError:
        raise
    except Exception as exc:
        _error(f"cannot serialize FLAC report: {exc}", exc)


def extract_artifacts(report: FLACReport, directory: str | Path) -> tuple[Path, ...]:
    """Write complete binary carrier payloads under deterministic safe names."""
    if not isinstance(report, FLACReport):
        _error("report must be an FLACReport")
    try:
        root = Path(directory)
        root.mkdir(parents=True, exist_ok=True)
        if not root.is_dir():
            _error("extraction destination is not a directory")
        written: list[Path] = []
        for artifact in report.artifacts:
            target = root / f"block-{artifact.block_index:04d}-{artifact.kind}.bin"
            target.write_bytes(artifact.data)
            written.append(target)
        return tuple(written)
    except StegodepthFLACError:
        raise
    except Exception as exc:
        _error(f"cannot extract artifacts: {exc}", exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="stegodepth_flac.py",
        description="Audit FLAC metadata for hidden carrier bytes without decoding audio.",
    )
    parser.add_argument("input", help="native FLAC file")
    parser.add_argument(
        "--extract",
        metavar="DIR",
        help="write complete application, padding, picture, and reserved payloads",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = audit_path(args.input)
        if result is None:
            raise StegodepthFLACError("input is not a native FLAC stream")
        output = report_dict(result)
        if args.extract is not None:
            output["extracted"] = [
                str(path) for path in extract_artifacts(result, args.extract)
            ]
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0
    except StegodepthFLACError as exc:
        print(f"stegodepth_flac: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"stegodepth_flac: {StegodepthFLACError(str(exc))}", file=sys.stderr)
        return 2


__all__ = [
    "StegodepthFLACError",
    "FLACBlock",
    "FLACArtifact",
    "VorbisComment",
    "FLACPicture",
    "StreamInfo",
    "FLACReport",
    "audit_flac",
    "audit_path",
    "report_dict",
    "extract_artifacts",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
