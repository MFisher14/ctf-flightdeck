#!/usr/bin/env python3
"""Bounded, codec-free Matroska/WebM steganography surface inspector.

The parser implements EBML ID and size VINTs, walks selected Matroska master
elements, and preserves exact offsets for attachments, tags, chapters, Void,
BlockAdditional, unknown elements, and bytes after a bounded Segment.  It never
decodes media blocks or invokes a codec.  Attachments and the other reported
surfaces are legal Matroska features unless an artifact is explicitly labelled
``anomaly``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


MAX_INPUT_BYTES = 256 << 20
MAX_ELEMENTS = 100_000
MAX_DEPTH = 12
MAX_ARTIFACT_BYTES = 16 << 20
MAX_TOTAL_ARTIFACT_BYTES = 64 << 20
MAX_TEXT_BYTES = 1 << 20


class StegodepthMatroskaError(ValueError):
    """The only exception intentionally raised by public parsing APIs."""


# IDs needed to distinguish structural containers from opaque codec/block data.
NAMES = {
    0x1A45DFA3: "EBML", 0x4286: "EBMLVersion", 0x42F7: "EBMLReadVersion",
    0x42F2: "EBMLMaxIDLength", 0x42F3: "EBMLMaxSizeLength", 0x4282: "DocType",
    0x4287: "DocTypeVersion", 0x4285: "DocTypeReadVersion",
    0x18538067: "Segment", 0x114D9B74: "SeekHead", 0x4DBB: "Seek",
    0x53AB: "SeekID", 0x53AC: "SeekPosition", 0x1549A966: "Info",
    0x73A4: "SegmentUUID", 0x7384: "SegmentFilename", 0x2AD7B1: "TimestampScale",
    0x4489: "Duration", 0x4461: "DateUTC", 0x7BA9: "Title", 0x4D80: "MuxingApp",
    0x5741: "WritingApp", 0x1654AE6B: "Tracks", 0xAE: "TrackEntry",
    0xD7: "TrackNumber", 0x73C5: "TrackUID", 0x83: "TrackType", 0xB9: "FlagEnabled",
    0x88: "FlagDefault", 0x55AA: "FlagForced", 0x9C: "FlagLacing",
    0x23E383: "DefaultDuration", 0x536E: "TrackName", 0x22B59C: "Language",
    0x22B59D: "LanguageIETF", 0x86: "CodecID", 0x63A2: "CodecPrivate",
    0x258688: "CodecName", 0x56AA: "CodecDelay", 0x56BB: "SeekPreRoll",
    0xE0: "Video", 0xB0: "PixelWidth", 0xBA: "PixelHeight", 0x54B0: "DisplayWidth",
    0x54BA: "DisplayHeight", 0xE1: "Audio", 0xB5: "SamplingFrequency",
    0x78B5: "OutputSamplingFrequency", 0x9F: "Channels", 0x6264: "BitDepth",
    0x1F43B675: "Cluster", 0xE7: "Timestamp", 0xA3: "SimpleBlock",
    0xA0: "BlockGroup", 0xA1: "Block", 0x9B: "BlockDuration", 0xFB: "ReferenceBlock",
    0x75A1: "BlockAdditions", 0xA6: "BlockMore", 0xEE: "BlockAddID",
    0xA5: "BlockAdditional", 0x1941A469: "Attachments", 0x61A7: "AttachedFile",
    0x467E: "FileDescription", 0x466E: "FileName", 0x4660: "FileMediaType",
    0x465C: "FileData", 0x46AE: "FileUID", 0x1043A770: "Chapters",
    0x45B9: "EditionEntry", 0xB6: "ChapterAtom", 0x73C4: "ChapterUID",
    0x91: "ChapterTimeStart", 0x92: "ChapterTimeEnd", 0x80: "ChapterDisplay",
    0x85: "ChapString", 0x437C: "ChapLanguage", 0x437D: "ChapLanguageIETF",
    0x1254C367: "Tags", 0x7373: "Tag", 0x63C0: "Targets", 0x67C8: "SimpleTag",
    0x45A3: "TagName", 0x447A: "TagLanguage", 0x447B: "TagLanguageIETF",
    0x4487: "TagString", 0x4485: "TagBinary", 0x1C53BB6B: "Cues",
    0xBB: "CuePoint", 0xB3: "CueTime", 0xB7: "CueTrackPositions", 0xF7: "CueTrack",
    0xF1: "CueClusterPosition", 0xEC: "Void", 0xBF: "CRC-32",
}

MASTERS = {
    0x1A45DFA3, 0x18538067, 0x114D9B74, 0x4DBB, 0x1549A966, 0x1654AE6B,
    0xAE, 0xE0, 0xE1, 0x1F43B675, 0xA0, 0x75A1, 0xA6, 0x1941A469,
    0x61A7, 0x1043A770, 0x45B9, 0xB6, 0x80, 0x1254C367, 0x7373,
    0x63C0, 0x67C8, 0x1C53BB6B, 0xBB, 0xB7,
}


@dataclass(frozen=True, slots=True)
class Element:
    element_id: int
    name: str
    offset: int
    data_offset: int
    data_size: int
    end: int
    depth: int
    path: tuple[str, ...]
    unknown_size: bool = False


@dataclass(frozen=True, slots=True)
class Artifact:
    kind: str
    name: str | None
    offset: int
    size: int
    data: bytes | None
    status: str
    context: str


@dataclass(frozen=True, slots=True)
class Attachment:
    filename: str | None
    media_type: str | None
    description: str | None
    uid: int | None
    data_offset: int | None
    data: bytes | None


@dataclass(frozen=True, slots=True)
class SimpleTag:
    name: str | None
    string: str | None
    binary: bytes | None
    offset: int


@dataclass(frozen=True, slots=True)
class Chapter:
    display_strings: tuple[str, ...]
    start_ns: int | None
    end_ns: int | None
    offset: int

    @property
    def title(self) -> str | None:
        return self.display_strings[0] if self.display_strings else None


@dataclass(frozen=True, slots=True)
class Track:
    number: int | None
    uid: int | None
    track_type: int | None
    name: str | None
    language: str | None
    codec_id: str | None
    offset: int


@dataclass(frozen=True, slots=True)
class MatroskaReport:
    doc_type: str
    segment_offset: int
    segment_data_offset: int
    segment_end: int
    segment_unknown_size: bool
    elements: tuple[Element, ...]
    attachments: tuple[Attachment, ...]
    tags: tuple[SimpleTag, ...]
    chapters: tuple[Chapter, ...]
    tracks: tuple[Track, ...]
    artifacts: tuple[Artifact, ...]
    issues: tuple[str, ...]
    tail_offset: int | None
    tail_size: int
    tail: bytes | None


@dataclass(slots=True)
class _Node:
    info: Element
    children: list["_Node"]


def _as_bytes(data: object) -> bytes | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_INPUT_BYTES:
            return None
        return bytes(data)
    except Exception:
        return None


def _vint_length(first: int, maximum: int, what: str) -> int:
    if first == 0:
        raise StegodepthMatroskaError(f"zero byte cannot start an EBML {what} VINT")
    marker = 0x80
    length = 1
    while not first & marker:
        marker >>= 1
        length += 1
    if length > maximum:
        raise StegodepthMatroskaError(f"EBML {what} VINT exceeds {maximum} bytes")
    return length


def _read_id(raw: bytes, offset: int, end: int, maximum: int = 4) -> tuple[int, int]:
    if offset >= end:
        raise StegodepthMatroskaError("missing EBML element ID")
    length = _vint_length(raw[offset], maximum, "ID")
    if offset + length > end:
        raise StegodepthMatroskaError("truncated EBML element ID")
    element_id = int.from_bytes(raw[offset:offset + length], "big")
    data_mask = (1 << (7 * length)) - 1
    data_value = element_id & data_mask
    # Matroska legalizes 0x80 (ChapterDisplay), unlike baseline RFC 8794.
    if data_value == 0 and element_id != 0x80:
        raise StegodepthMatroskaError("EBML element ID has reserved all-zero VINT data")
    if data_value == data_mask:
        raise StegodepthMatroskaError("EBML element ID has reserved all-one VINT data")
    if length > 1 and data_value < (1 << (7 * (length - 1))) - 1:
        raise StegodepthMatroskaError("EBML element ID is not shortest-form encoded")
    return element_id, length


def _read_size(raw: bytes, offset: int, end: int) -> tuple[int | None, int]:
    if offset >= end:
        raise StegodepthMatroskaError("missing EBML element size")
    length = _vint_length(raw[offset], 8, "size")
    if offset + length > end:
        raise StegodepthMatroskaError("truncated EBML element size")
    marker = 1 << (8 - length)
    value = raw[offset] & (marker - 1)
    for byte in raw[offset + 1:offset + length]:
        value = (value << 8) | byte
    unknown = value == (1 << (7 * length)) - 1
    return (None if unknown else value), length


def _parse_node(raw: bytes, offset: int, parent_end: int, depth: int,
                path: tuple[str, ...], counter: list[int]) -> _Node:
    if depth > MAX_DEPTH:
        raise StegodepthMatroskaError(f"EBML nesting exceeds depth {MAX_DEPTH}")
    element_id, id_length = _read_id(raw, offset, parent_end)
    size, size_length = _read_size(raw, offset + id_length, parent_end)
    data_offset = offset + id_length + size_length
    name = NAMES.get(element_id, f"unknown-0x{element_id:X}")
    if size is None:
        if element_id != 0x18538067:
            raise StegodepthMatroskaError(f"unknown-sized {name} is not supported safely")
        element_end = parent_end
        data_size = element_end - data_offset
    else:
        element_end = data_offset + size
        data_size = size
        if element_end > parent_end:
            raise StegodepthMatroskaError(f"{name} runs past its parent")
    counter[0] += 1
    if counter[0] > MAX_ELEMENTS:
        raise StegodepthMatroskaError(f"element count exceeds {MAX_ELEMENTS}")
    element_path = path + (name,)
    info = Element(element_id, name, offset, data_offset, data_size, element_end,
                   depth, element_path, size is None)
    children: list[_Node] = []
    if element_id in MASTERS:
        position = data_offset
        while position < element_end:
            child = _parse_node(raw, position, element_end, depth + 1, element_path, counter)
            if child.info.end <= position:
                raise StegodepthMatroskaError("EBML parser made no forward progress")
            children.append(child)
            position = child.info.end
        if position != element_end:
            raise StegodepthMatroskaError(f"{name} child stream does not end exactly")
    return _Node(info, children)


def _flatten(node: _Node) -> list[_Node]:
    output = [node]
    for child in node.children:
        output.extend(_flatten(child))
    return output


def _direct(node: _Node, element_id: int) -> _Node | None:
    matches = [child for child in node.children if child.info.element_id == element_id]
    if len(matches) > 1:
        raise StegodepthMatroskaError(
            f"duplicate {NAMES.get(element_id, hex(element_id))} in {node.info.name}"
        )
    return matches[0] if matches else None


def _text(raw: bytes, node: _Node | None, *, ascii_only: bool = False) -> str | None:
    if node is None:
        return None
    if node.info.data_size > MAX_TEXT_BYTES:
        raise StegodepthMatroskaError(f"text in {node.info.name} exceeds extraction cap")
    body = raw[node.info.data_offset:node.info.end]
    try:
        return body.decode("ascii" if ascii_only else "utf-8")
    except UnicodeDecodeError as exc:
        raise StegodepthMatroskaError(f"invalid text in {node.info.name}") from exc


def _uint(raw: bytes, node: _Node | None) -> int | None:
    if node is None:
        return None
    if node.info.data_size > 8:
        raise StegodepthMatroskaError(f"oversized unsigned integer in {node.info.name}")
    body = raw[node.info.data_offset:node.info.end]
    return int.from_bytes(body, "big")


def _artifact(raw: bytes, node: _Node, kind: str, name: str | None,
              status: str, context: str, totals: list[int]) -> Artifact:
    size = node.info.data_size
    data = None
    if size <= MAX_ARTIFACT_BYTES and totals[0] + size <= MAX_TOTAL_ARTIFACT_BYTES:
        data = raw[node.info.data_offset:node.info.end]
        totals[0] += size
    return Artifact(kind, name, node.info.data_offset, size, data, status, context)


def inspect_matroska(data: object) -> MatroskaReport | None:
    """Inspect one Matroska/WebM byte string without decoding media.

    Non-EBML or non-Matroska/WebM input returns ``None``. Structurally malformed
    matching input raises only :class:`StegodepthMatroskaError`.
    """

    raw = _as_bytes(data)
    if raw is None or not raw.startswith(b"\x1a\x45\xdf\xa3"):
        return None
    try:
        counter = [0]
        header = _parse_node(raw, 0, len(raw), 0, (), counter)
        if header.info.element_id != 0x1A45DFA3 or header.info.unknown_size:
            raise StegodepthMatroskaError("invalid EBML header")
        doc_type = _text(raw, _direct(header, 0x4282), ascii_only=True)
        if doc_type not in ("matroska", "webm"):
            return None
        position = header.info.end
        prefix_nodes: list[_Node] = []
        segment = None
        while position < len(raw):
            element_id, _ = _read_id(raw, position, len(raw))
            node = _parse_node(raw, position, len(raw), 0, (), counter)
            if element_id == 0x18538067:
                segment = node
                break
            if element_id not in (0xEC, 0xBF):
                raise StegodepthMatroskaError("non-Void data appears between EBML header and Segment")
            prefix_nodes.append(node)
            position = node.info.end
        if segment is None:
            raise StegodepthMatroskaError("Matroska file has no Segment")

        nodes = _flatten(header) + prefix_nodes + _flatten(segment)
        elements = tuple(node.info for node in nodes)
        parents = {
            id(child): parent
            for parent in nodes
            for child in parent.children
        }
        totals = [0]
        artifacts: list[Artifact] = []
        issues: list[str] = []

        attachments: list[Attachment] = []
        for node in nodes:
            if node.info.element_id != 0x61A7:
                continue
            filename = _text(raw, _direct(node, 0x466E))
            media = _text(raw, _direct(node, 0x4660), ascii_only=True)
            description = _text(raw, _direct(node, 0x467E))
            uid = _uint(raw, _direct(node, 0x46AE))
            data_node = _direct(node, 0x465C)
            data_bytes = None
            if data_node is not None:
                art = _artifact(raw, data_node, "attachment", filename, "legal-carrier",
                                "AttachedFile/FileData", totals)
                artifacts.append(art)
                data_bytes = art.data
            attachments.append(Attachment(filename, media, description, uid,
                                          data_node.info.data_offset if data_node else None,
                                          data_bytes))

        tags: list[SimpleTag] = []
        for node in nodes:
            if node.info.element_id != 0x67C8:
                continue
            name = _text(raw, _direct(node, 0x45A3))
            string = _text(raw, _direct(node, 0x4487))
            binary_node = _direct(node, 0x4485)
            binary = None
            if binary_node is not None:
                art = _artifact(raw, binary_node, "tag-binary", name, "legal-carrier",
                                "SimpleTag/TagBinary", totals)
                artifacts.append(art)
                binary = art.data
            tags.append(SimpleTag(name, string, binary, node.info.offset))

        chapters: list[Chapter] = []
        for node in nodes:
            if node.info.element_id != 0xB6:
                continue
            displays = [child for child in node.children if child.info.element_id == 0x80]
            titles = [_text(raw, _direct(display, 0x85)) for display in displays]
            titles = [title for title in titles if title is not None]
            chapters.append(Chapter(tuple(titles),
                                    _uint(raw, _direct(node, 0x91)),
                                    _uint(raw, _direct(node, 0x92)), node.info.offset))

        tracks: list[Track] = []
        for node in nodes:
            if node.info.element_id != 0xAE:
                continue
            tracks.append(Track(
                _uint(raw, _direct(node, 0xD7)), _uint(raw, _direct(node, 0x73C5)),
                _uint(raw, _direct(node, 0x83)), _text(raw, _direct(node, 0x536E)),
                _text(raw, _direct(node, 0x22B59C), ascii_only=True),
                _text(raw, _direct(node, 0x86), ascii_only=True), node.info.offset,
            ))

        handled_artifact_ids = {0x465C, 0x4485}
        for node in nodes:
            element_id = node.info.element_id
            if element_id in handled_artifact_ids:
                continue
            if element_id == 0xEC:
                artifacts.append(_artifact(raw, node, "void", None, "legal-carrier",
                                           "/".join(node.info.path), totals))
            elif element_id == 0xA5:
                parent = parents.get(id(node))
                add_id = _uint(raw, _direct(parent, 0xEE)) if parent is not None else None
                artifacts.append(_artifact(raw, node, "block-additional",
                                           str(add_id if add_id is not None else 1),
                                           "legal-carrier", "/".join(node.info.path), totals))
            elif element_id not in NAMES:
                artifacts.append(_artifact(raw, node, "unknown-element", f"0x{element_id:X}",
                                           "legal-extension-surface", "/".join(node.info.path), totals))
                issues.append(f"unknown EBML element 0x{element_id:X} at {node.info.offset}")

        tail_offset = None
        tail_size = 0
        tail: bytes | None = b""
        if not segment.info.unknown_size and segment.info.end < len(raw):
            tail_offset = segment.info.end
            tail_size = len(raw) - tail_offset
            tail_node = _Node(Element(0, "post-Segment", tail_offset, tail_offset, tail_size,
                                     len(raw), 0, ("post-Segment",)), [])
            tail_artifact = _artifact(raw, tail_node, "post-segment-tail", None, "anomaly",
                                      "bytes after bounded Segment", totals)
            artifacts.append(tail_artifact)
            tail = tail_artifact.data
            issues.append(f"{tail_size} byte(s) follow the bounded Segment")
        if any(artifact.data is None and artifact.size for artifact in artifacts):
            issues.append("one or more artifact bodies exceeded extraction caps")

        return MatroskaReport(
            doc_type, segment.info.offset, segment.info.data_offset, segment.info.end,
            segment.info.unknown_size, elements, tuple(attachments), tuple(tags),
            tuple(chapters), tuple(tracks), tuple(artifacts), tuple(issues),
            tail_offset, tail_size, tail,
        )
    except StegodepthMatroskaError:
        raise
    except (IndexError, TypeError, ValueError, OverflowError, MemoryError, RecursionError) as exc:
        raise StegodepthMatroskaError("malformed Matroska/EBML structure") from exc


def _json_report(report: MatroskaReport) -> dict:
    def blob(value: bytes | None, size: int | None = None):
        if value is None:
            return {"size": size, "extracted": False}
        return {"size": len(value), "extracted": True,
                "sha256": hashlib.sha256(value).hexdigest(), "head_hex": value[:32].hex()}

    return {
        "doc_type": report.doc_type,
        "segment": {"offset": report.segment_offset, "data_offset": report.segment_data_offset,
                    "end": report.segment_end, "unknown_size": report.segment_unknown_size},
        "elements": [
            {"id": f"0x{e.element_id:X}", "name": e.name, "offset": e.offset,
             "data_offset": e.data_offset, "size": e.data_size, "end": e.end,
             "depth": e.depth, "path": list(e.path), "unknown_size": e.unknown_size}
            for e in report.elements
        ],
        "attachments": [
            {"filename": a.filename, "media_type": a.media_type, "description": a.description,
             "uid": a.uid, "data_offset": a.data_offset, "data": blob(a.data)}
            for a in report.attachments
        ],
        "tags": [
            {"name": tag.name, "string": tag.string, "binary": blob(tag.binary),
             "offset": tag.offset} for tag in report.tags
        ],
        "chapters": [
            {"display_strings": list(chapter.display_strings), "title": chapter.title,
             "start_ns": chapter.start_ns, "end_ns": chapter.end_ns,
             "offset": chapter.offset}
            for chapter in report.chapters
        ],
        "tracks": [
            {"number": track.number, "uid": track.uid, "track_type": track.track_type,
             "name": track.name, "language": track.language, "codec_id": track.codec_id,
             "offset": track.offset} for track in report.tracks
        ],
        "artifacts": [
            {"kind": artifact.kind, "name": artifact.name, "offset": artifact.offset,
             "status": artifact.status, "context": artifact.context,
             "data": blob(artifact.data, artifact.size)} for artifact in report.artifacts
        ],
        "issues": list(report.issues), "tail_offset": report.tail_offset,
        "tail": blob(report.tail, report.tail_size),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegodepth_matroska.py",
        description="Offline Matroska/WebM attachment/tag/Void stego auditor",
    )
    parser.add_argument("input")
    parser.add_argument("--pretty", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        path = Path(args.input)
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise StegodepthMatroskaError(f"input exceeds {MAX_INPUT_BYTES} bytes")
        report = inspect_matroska(raw)
        if report is None:
            raise StegodepthMatroskaError("input is not a bounded Matroska/WebM file")
        print(json.dumps(_json_report(report), sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except (OSError, StegodepthMatroskaError, MemoryError, TypeError, UnicodeError) as exc:
        print(f"stegodepth_matroska: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "StegodepthMatroskaError", "Element", "Artifact", "Attachment", "SimpleTag",
    "Chapter", "Track", "MatroskaReport", "inspect_matroska", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
