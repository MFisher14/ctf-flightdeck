#!/usr/bin/env python3
"""Bounded structural inspection of JPEG 2000 codestreams and JP2/JPX files.

The parser follows the box and marker syntax published in ITU-T T.800 /
ISO/IEC 15444-1.  It inventories metadata and private data, and decodes only
the fixed fields needed to describe a codestream.  Packet bodies, EBCOT code
blocks, wavelet coefficients, and pixels are never decoded or executed.

``inspect_jp2`` accepts either a raw J2K codestream (SOC, ``FF4F``) or a
JP2-family box file (signature box, ``jP  ``).  Malformed or unsupported input
returns ``None``.  Invalid caller parameters in ``inspect_codestream`` raise
only :class:`StegodepthJP2Error`.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence


MAX_INPUT_BYTES = 128 << 20
MAX_ARTIFACT_BYTES = 16 << 20
MAX_SAVED_ARTIFACT_BYTES = 32 << 20
MAX_ARTIFACTS = 10_000
MAX_BOXES = 100_000
MAX_MARKERS = 100_000
MAX_COMPONENTS = 16_384
MAX_TILE_PARTS = 65_536
MAX_BOX_DEPTH = 8

JP2_SIGNATURE = b"\x00\x00\x00\x0cjP  \x0d\x0a\x87\x0a"


class StegodepthJP2Error(ValueError):
    """The only exception intentionally raised by public JP2 APIs."""


@dataclass(frozen=True, slots=True)
class BoxRecord:
    box_type: str
    offset: int
    size: int
    header_size: int
    depth: int
    path: str
    known: bool


@dataclass(frozen=True, slots=True)
class Artifact:
    kind: str
    offset: int
    size: int
    data: bytes
    path: str
    identifier: str | None = None
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class MarkerRecord:
    name: str
    code: int
    offset: int
    declared_length: int | None
    scope: str


@dataclass(frozen=True, slots=True)
class ComponentRecord:
    precision: int
    signed: bool
    x_subsampling: int
    y_subsampling: int


@dataclass(frozen=True, slots=True)
class CommentRecord:
    offset: int
    registration: int
    text: str | None
    data: bytes
    size: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class TilePartRecord:
    tile_index: int
    part_index: int
    parts_total: int
    offset: int
    declared_size: int
    data_offset: int
    data_size: int


@dataclass(frozen=True, slots=True)
class CodestreamReport:
    offset: int
    logical_end: int
    eoc_offset: int
    width: int
    height: int
    x_origin: int
    y_origin: int
    components: tuple[ComponentRecord, ...]
    progression: str | None
    decomposition_levels: int | None
    transform: str | None
    quantization_style: str | None
    guard_bits: int | None
    markers: tuple[MarkerRecord, ...]
    comments: tuple[CommentRecord, ...]
    tile_parts: tuple[TilePartRecord, ...]
    artifacts: tuple[Artifact, ...]
    tail: bytes
    tail_size: int


@dataclass(frozen=True, slots=True)
class JP2Report:
    container_format: str
    logical_end: int
    boxes: tuple[BoxRecord, ...]
    codestreams: tuple[CodestreamReport, ...]
    artifacts: tuple[Artifact, ...]
    post_container: bytes
    post_container_size: int
    findings: tuple[str, ...]


_MARKER_NAMES = {
    0xFF4F: "SOC",
    0xFF51: "SIZ",
    0xFF52: "COD",
    0xFF53: "COC",
    0xFF55: "TLM",
    0xFF57: "PLM",
    0xFF58: "PLT",
    0xFF5C: "QCD",
    0xFF5D: "QCC",
    0xFF5E: "RGN",
    0xFF5F: "POC",
    0xFF60: "PPM",
    0xFF61: "PPT",
    0xFF63: "CRG",
    0xFF64: "COM",
    0xFF90: "SOT",
    0xFF91: "SOP",
    0xFF92: "EPH",
    0xFF93: "SOD",
    0xFFD9: "EOC",
}

_PROGRESSIONS = {
    0: "LRCP",
    1: "RLCP",
    2: "RPCL",
    3: "PCRL",
    4: "CPRL",
}

_QUANTIZATION = {
    0: "no quantization",
    1: "scalar derived",
    2: "scalar expounded",
}

# Standard Part 1 and commonly encountered JPX box types.  A syntactically
# valid type outside this set is retained as an ``unknown_box`` artifact.
_KNOWN_BOX_TYPES = {
    b"jP  ", b"ftyp", b"jp2h", b"ihdr", b"bpcc", b"colr", b"pclr",
    b"cmap", b"cdef", b"res ", b"resc", b"resd", b"jp2c", b"xml ",
    b"uuid", b"uinf", b"ulst", b"url ", b"asoc", b"lbl ", b"jpch",
    b"jplh", b"cgrp", b"dtbl", b"ftbl", b"flst", b"comp", b"cref",
    b"nlst", b"roid", b"copt", b"jp2i", b"rreq", b"mdat", b"free",
    b"skip",
}

_PURE_SUPERBOXES = {b"jp2h", b"res ", b"uinf", b"asoc"}
_FREE_BOXES = {b"free", b"skip"}
# Part 2 boxes have additional internal grammars. Preserve their complete,
# bounded bodies when this focused inspector does not recurse into them, so a
# private child or free-space carrier never disappears from the report.
_OPAQUE_JPX_BOXES = {
    b"jpch", b"jplh", b"cgrp", b"dtbl", b"ftbl", b"flst", b"comp",
    b"cref", b"nlst", b"roid", b"copt", b"jp2i", b"rreq", b"mdat",
}


def _bounded_bytes(data: object) -> bytes | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_INPUT_BYTES:
            return None
        value = data.tobytes() if isinstance(data, memoryview) else bytes(data)
        return value if len(value) <= MAX_INPUT_BYTES else None
    except Exception:
        # Bytes subclasses and exotic memoryviews can supply hostile protocol
        # methods; public parsing must not expose their exception types.
        return None


def _u16(raw: bytes, offset: int) -> int:
    return struct.unpack_from(">H", raw, offset)[0]


def _u32(raw: bytes, offset: int) -> int:
    return struct.unpack_from(">I", raw, offset)[0]


def _u64(raw: bytes, offset: int) -> int:
    return struct.unpack_from(">Q", raw, offset)[0]


@dataclass(slots=True)
class _ArtifactBudget:
    count: int = 0
    saved_bytes: int = 0


def _artifact_span(raw: bytes, start: int, end: int, kind: str, path: str,
                   budget: _ArtifactBudget,
                   identifier: str | None = None) -> Artifact:
    """Retain a bounded prefix of a span without first copying the whole span."""

    if start < 0 or end < start or end > len(raw):
        raise StegodepthJP2Error("artifact span is outside input")
    if budget.count >= MAX_ARTIFACTS:
        raise StegodepthJP2Error("artifact count exceeds cap")
    remaining = max(0, MAX_SAVED_ARTIFACT_BYTES - budget.saved_bytes)
    retain = min(end - start, MAX_ARTIFACT_BYTES, remaining)
    data = raw[start:start + retain]
    budget.count += 1
    budget.saved_bytes += retain
    return Artifact(
        kind, start, end - start, data, path, identifier, retain < end - start
    )


def _artifact_bytes(data: bytes, offset: int, kind: str, path: str,
                    budget: _ArtifactBudget,
                    identifier: str | None = None) -> Artifact:
    """Bound retention for an already-small marker-segment payload."""

    if budget.count >= MAX_ARTIFACTS:
        raise StegodepthJP2Error("artifact count exceeds cap")
    remaining = max(0, MAX_SAVED_ARTIFACT_BYTES - budget.saved_bytes)
    retain = min(len(data), MAX_ARTIFACT_BYTES, remaining)
    saved = data[:retain]
    budget.count += 1
    budget.saved_bytes += retain
    return Artifact(kind, offset, len(data), saved, path, identifier, retain < len(data))


def _read_marker(raw: bytes, position: int, end: int) -> tuple[int, int, int]:
    """Return ``(code, actual_marker_offset, byte_after_marker)``.

    Consecutive FF fill bytes are legal before a marker.  The last FF is the
    marker prefix and earlier bytes are fill, so ``Psot`` is measured from the
    returned offset rather than from the first fill byte.
    """

    if position >= end or raw[position] != 0xFF:
        raise StegodepthJP2Error("expected JPEG 2000 marker")
    cursor = position
    while cursor < end and raw[cursor] == 0xFF:
        cursor += 1
    if cursor >= end or raw[cursor] == 0x00:
        raise StegodepthJP2Error("truncated or stuffed marker in header")
    marker_offset = cursor - 1
    return 0xFF00 | raw[cursor], marker_offset, cursor + 1


def _parse_siz(body: bytes) -> tuple[int, int, int, int, tuple[ComponentRecord, ...]]:
    if len(body) < 36:
        raise StegodepthJP2Error("short SIZ marker segment")
    (_rsiz, xsiz, ysiz, xosiz, yosiz, xtsiz, ytsiz, xtosiz, ytosiz,
     csiz) = struct.unpack_from(">HIIIIIIIIH", body, 0)
    if csiz < 1 or csiz > MAX_COMPONENTS or len(body) != 36 + 3 * csiz:
        raise StegodepthJP2Error("invalid SIZ component table")
    if xsiz <= xosiz or ysiz <= yosiz or xtsiz == 0 or ytsiz == 0:
        raise StegodepthJP2Error("invalid SIZ geometry")
    if xtosiz > xosiz or ytosiz > yosiz:
        raise StegodepthJP2Error("invalid SIZ tile origin")
    components: list[ComponentRecord] = []
    cursor = 36
    for _ in range(csiz):
        ssiz, xrsiz, yrsiz = body[cursor:cursor + 3]
        if xrsiz == 0 or yrsiz == 0:
            raise StegodepthJP2Error("zero SIZ component subsampling")
        precision = (ssiz & 0x7F) + 1
        if precision > 38:
            raise StegodepthJP2Error("unsupported SIZ component precision")
        components.append(ComponentRecord(precision, bool(ssiz & 0x80), xrsiz, yrsiz))
        cursor += 3
    return xsiz - xosiz, ysiz - yosiz, xosiz, yosiz, tuple(components)


def _parse_cod(body: bytes) -> tuple[str, int, str]:
    if len(body) < 10:
        raise StegodepthJP2Error("short COD marker segment")
    scod = body[0]
    progression_code = body[1]
    layers = _u16(body, 2)
    levels = body[5]
    transform_code = body[9]
    progression = _PROGRESSIONS.get(progression_code)
    if progression is None or layers == 0 or levels > 32:
        raise StegodepthJP2Error("invalid COD coding style")
    expected = 10 + (levels + 1 if scod & 0x01 else 0)
    if len(body) != expected:
        raise StegodepthJP2Error("invalid COD precinct table")
    if transform_code == 0:
        transform = "irreversible 9/7"
    elif transform_code == 1:
        transform = "reversible 5/3"
    else:
        transform = f"unknown transform {transform_code}"
    return progression, levels, transform


def _parse_qcd(body: bytes) -> tuple[str, int]:
    if len(body) < 2:
        raise StegodepthJP2Error("short QCD marker segment")
    style_code = body[0] & 0x1F
    guard_bits = body[0] >> 5
    style = _QUANTIZATION.get(style_code)
    if style is None:
        raise StegodepthJP2Error("reserved QCD quantization style")
    parameters = len(body) - 1
    if ((style_code == 0 and parameters < 1) or
            (style_code == 1 and parameters != 2) or
            (style_code == 2 and (parameters < 2 or parameters & 1))):
        raise StegodepthJP2Error("invalid QCD step-size table")
    return style, guard_bits


def _parse_com(body: bytes, offset: int, budget: _ArtifactBudget) -> tuple[CommentRecord, Artifact]:
    if len(body) < 2:
        raise StegodepthJP2Error("short COM marker segment")
    registration = _u16(body, 0)
    payload = body[2:]
    artifact = _artifact_bytes(
        payload, offset + 6, "comment", "codestream/COM", budget,
        str(registration),
    )
    text = (artifact.data.decode("iso8859_15")
            if registration == 1 and not artifact.truncated else None)
    return (CommentRecord(
        offset, registration, text, artifact.data, len(payload), artifact.truncated
    ), artifact)


def _parse_codestream(raw: bytes, start: int, end: int,
                      budget: _ArtifactBudget | None = None) -> CodestreamReport:
    if start < 0 or end < start or end > len(raw) or end - start < 4:
        raise StegodepthJP2Error("invalid codestream bounds")
    if raw[start:start + 2] != b"\xff\x4f":
        raise StegodepthJP2Error("missing SOC marker")

    artifact_budget = budget if budget is not None else _ArtifactBudget()
    markers: list[MarkerRecord] = [MarkerRecord("SOC", 0xFF4F, start, None, "main_header")]
    artifacts: list[Artifact] = []
    comments: list[CommentRecord] = []
    tile_parts: list[TilePartRecord] = []
    position = start + 2
    scope = "main_header"
    dimensions: tuple[int, int, int, int, tuple[ComponentRecord, ...]] | None = None
    progression = None
    decomposition_levels = None
    transform = None
    quantization_style = None
    guard_bits = None
    saw_cod = saw_qcd = saw_sod = False
    current_tile: tuple[int, int, int, int, int | None] | None = None

    while position < end:
        if len(markers) >= MAX_MARKERS:
            raise StegodepthJP2Error("marker count exceeds cap")
        code, marker_offset, after_marker = _read_marker(raw, position, end)
        name = _MARKER_NAMES.get(code, f"0x{code:04X}")

        if code == 0xFFD9:  # EOC
            if scope != "between_tile_parts" or not saw_sod:
                raise StegodepthJP2Error("EOC before complete tile data")
            markers.append(MarkerRecord(name, code, marker_offset, None, "end"))
            logical_end = after_marker
            tail_size = end - logical_end
            saved_tail = b""
            if tail_size:
                tail_artifact = _artifact_span(
                    raw, logical_end, end, "codestream_tail",
                    "codestream/post_eoc", artifact_budget,
                )
                artifacts.append(tail_artifact)
                saved_tail = tail_artifact.data
            if dimensions is None or not saw_cod or not saw_qcd:
                raise StegodepthJP2Error("incomplete JPEG 2000 main header")
            width, height, x_origin, y_origin, components = dimensions
            return CodestreamReport(
                start, logical_end, marker_offset, width, height, x_origin, y_origin,
                components, progression, decomposition_levels, transform,
                quantization_style, guard_bits, tuple(markers), tuple(comments),
                tuple(tile_parts), tuple(artifacts), saved_tail, tail_size,
            )

        if code in (0xFF4F, 0xFF92, 0xFF93):
            if code != 0xFF93:
                raise StegodepthJP2Error(f"unexpected marker {name} in header")
            if scope != "tile_header" or current_tile is None:
                raise StegodepthJP2Error("SOD outside a tile-part header")
            markers.append(MarkerRecord(name, code, marker_offset, None, scope))
            saw_sod = True
            tile_index, part_index, parts_total, tile_offset, tile_end = current_tile
            data_offset = after_marker
            if tile_end is None:
                # Marker emulation prevention makes FF D9 unambiguous inside
                # packet data; Psot=0 denotes the final tile-part.
                eoc = raw.find(b"\xff\xd9", data_offset, end)
                if eoc < 0:
                    raise StegodepthJP2Error("Psot=0 tile-part has no EOC")
                data_end = eoc
            else:
                if tile_end < data_offset or tile_end > end:
                    raise StegodepthJP2Error("SOT Psot is outside codestream")
                data_end = tile_end
            if len(tile_parts) >= MAX_TILE_PARTS:
                raise StegodepthJP2Error("tile-part count exceeds cap")
            tile_parts.append(TilePartRecord(
                tile_index, part_index, parts_total, tile_offset,
                0 if tile_end is None else tile_end - tile_offset,
                data_offset, data_end - data_offset,
            ))
            position = data_end
            scope = "between_tile_parts"
            current_tile = None
            continue

        if after_marker + 2 > end:
            raise StegodepthJP2Error("truncated marker length")
        declared_length = _u16(raw, after_marker)
        if declared_length < 2:
            raise StegodepthJP2Error("marker length is smaller than its length field")
        segment_end = after_marker + declared_length
        if segment_end > end:
            raise StegodepthJP2Error("marker segment exceeds codestream")
        body_start = after_marker + 2
        body = raw[body_start:segment_end]
        markers.append(MarkerRecord(name, code, marker_offset, declared_length, scope))

        if code == 0xFF90:  # SOT
            if scope not in ("main_header", "between_tile_parts") or len(body) != 8:
                raise StegodepthJP2Error("invalid SOT placement or length")
            tile_index, psot, part_index, parts_total = struct.unpack(">HIBB", body)
            tile_end = None if psot == 0 else marker_offset + psot
            if tile_end is not None and (tile_end < segment_end + 2 or tile_end > end):
                raise StegodepthJP2Error("invalid SOT Psot")
            current_tile = (tile_index, part_index, parts_total, marker_offset, tile_end)
            scope = "tile_header"
        elif code == 0xFF51:  # SIZ
            if scope != "main_header" or dimensions is not None:
                raise StegodepthJP2Error("duplicate or misplaced SIZ")
            dimensions = _parse_siz(body)
        elif code == 0xFF52:  # COD
            cod_progression, cod_levels, cod_transform = _parse_cod(body)
            if scope == "main_header" and not saw_cod:
                progression = cod_progression
                decomposition_levels = cod_levels
                transform = cod_transform
                saw_cod = True
        elif code == 0xFF5C:  # QCD
            q_style, q_guard = _parse_qcd(body)
            if scope == "main_header" and not saw_qcd:
                quantization_style = q_style
                guard_bits = q_guard
                saw_qcd = True
        elif code == 0xFF64:  # COM
            comment, comment_artifact = _parse_com(body, marker_offset, artifact_budget)
            comments.append(comment)
            artifacts.append(comment_artifact)
        elif code not in _MARKER_NAMES:
            artifacts.append(_artifact_bytes(
                body, body_start, "unknown_marker_segment",
                "codestream/unknown_marker", artifact_budget, f"0x{code:04X}",
            ))
        position = segment_end

    raise StegodepthJP2Error("codestream has no EOC")


def inspect_codestream(data: object, *, offset: int = 0,
                       end: int | None = None) -> CodestreamReport | None:
    """Inspect one bounded J2K codestream without decoding compressed data.

    Malformed bytes return ``None``.  Non-integer or out-of-range bounds raise
    only :class:`StegodepthJP2Error`.
    """

    raw = _bounded_bytes(data)
    if raw is None:
        return None
    if type(offset) is not int:
        raise StegodepthJP2Error("offset must be an integer")
    if end is None:
        selected_end = len(raw)
    elif type(end) is not int:
        raise StegodepthJP2Error("end must be an integer or None")
    else:
        selected_end = end
    if offset < 0 or selected_end < offset or selected_end > len(raw):
        raise StegodepthJP2Error("codestream bounds are outside input")
    try:
        return _parse_codestream(raw, offset, selected_end)
    except StegodepthJP2Error:
        return None
    except Exception:
        # Public inspection is deliberately fail closed.  This also ensures a
        # malformed file never exposes struct.error, IndexError, or OverflowError.
        return None


@dataclass(slots=True)
class _BoxState:
    count: int
    boxes: list[BoxRecord]
    artifacts: list[Artifact]
    codestreams: list[CodestreamReport]
    findings: list[str]
    artifact_budget: _ArtifactBudget


def _box_type_name(box_type: bytes) -> str:
    return box_type.decode("latin-1")


def _parse_box_range(raw: bytes, start: int, end: int, *, depth: int,
                     parent: str, state: _BoxState, top_level: bool,
                     allow_tail: bool) -> tuple[int, bool]:
    if depth > MAX_BOX_DEPTH:
        raise StegodepthJP2Error("JP2 box nesting exceeds cap")
    position = start
    index = 0
    while position < end:
        remaining = end - position
        if remaining < 8:
            if allow_tail:
                return position, True
            raise StegodepthJP2Error("truncated JP2 box header")
        lbox = _u32(raw, position)
        box_type = raw[position + 4:position + 8]
        header_size = 8
        if lbox == 1:
            if remaining < 16:
                if allow_tail:
                    return position, True
                raise StegodepthJP2Error("truncated extended JP2 box header")
            box_size = _u64(raw, position + 8)
            header_size = 16
        elif lbox == 0:
            box_size = remaining
        else:
            box_size = lbox
        if box_size < header_size or box_size > remaining:
            if allow_tail and box_type not in _KNOWN_BOX_TYPES:
                return position, True
            raise StegodepthJP2Error("invalid or truncated JP2 box")
        state.count += 1
        if state.count > MAX_BOXES:
            raise StegodepthJP2Error("JP2 box count exceeds cap")
        name = _box_type_name(box_type)
        path = f"{parent}/{name}[{index}]" if parent else f"/{name}[{index}]"
        record = BoxRecord(
            name, position, box_size, header_size, depth, path,
            box_type in _KNOWN_BOX_TYPES,
        )
        state.boxes.append(record)
        body_start = position + header_size
        box_end = position + box_size

        if box_type == b"xml ":
            state.artifacts.append(_artifact_span(
                raw, body_start, box_end, "xml", path, state.artifact_budget
            ))
        elif box_type == b"uuid":
            if box_end - body_start < 16:
                raise StegodepthJP2Error("UUID box is shorter than its identifier")
            state.artifacts.append(_artifact_span(
                raw, body_start + 16, box_end, "uuid", path,
                state.artifact_budget, raw[body_start:body_start + 16].hex(),
            ))
        elif box_type == b"jp2c":
            codestream = _parse_codestream(
                raw, body_start, box_end, state.artifact_budget
            )
            state.codestreams.append(codestream)
            state.artifacts.extend(codestream.artifacts)
            if codestream.tail_size:
                state.findings.append(
                    f"{path} has {codestream.tail_size} byte(s) after EOC"
                )
        elif box_type in _FREE_BOXES:
            state.artifacts.append(_artifact_span(
                raw, body_start, box_end, "free_space", path,
                state.artifact_budget, name,
            ))
        elif box_type in _OPAQUE_JPX_BOXES:
            state.artifacts.append(_artifact_span(
                raw, body_start, box_end, "opaque_jpx_box", path,
                state.artifact_budget, name,
            ))
            state.findings.append(
                f"{path} uses an opaque JPX box grammar; its bounded body was preserved"
            )
        elif box_type not in _KNOWN_BOX_TYPES:
            state.artifacts.append(_artifact_span(
                raw, body_start, box_end, "unknown_box", path,
                state.artifact_budget, name,
            ))

        if box_type in _PURE_SUPERBOXES and box_end > body_start:
            nested_end, nested_tail = _parse_box_range(
                raw, body_start, box_end, depth=depth + 1, parent=path,
                state=state, top_level=False, allow_tail=False,
            )
            if nested_end != box_end or nested_tail:
                raise StegodepthJP2Error("unparsed bytes in JP2 superbox")

        position = box_end
        index += 1
        if lbox == 0:
            break
    return position, False


def _parse_jp2(raw: bytes) -> JP2Report:
    if not raw.startswith(JP2_SIGNATURE):
        raise StegodepthJP2Error("missing JP2 signature box")
    state = _BoxState(0, [], [], [], [], _ArtifactBudget())

    # Parse the mandatory signature and file-type boxes strictly first.  The
    # remaining top-level range may end in non-box bytes, which are the precise
    # post-container artifact requested by this inspector.
    first_end, _ = _parse_box_range(
        raw, 0, 12, depth=0, parent="", state=state,
        top_level=True, allow_tail=False,
    )
    if first_end != 12 or not state.boxes or state.boxes[0].box_type != "jP  ":
        raise StegodepthJP2Error("invalid JP2 signature box")
    if len(raw) < 20 or raw[16:20] != b"ftyp":
        raise StegodepthJP2Error("JP2 signature is not followed by ftyp")
    lbox = _u32(raw, 12)
    if lbox == 1:
        if len(raw) < 28:
            raise StegodepthJP2Error("truncated ftyp box")
        ftyp_size = _u64(raw, 20)
    elif lbox == 0:
        raise StegodepthJP2Error("ftyp cannot consume the whole file")
    else:
        ftyp_size = lbox
    ftyp_header = 16 if lbox == 1 else 8
    ftyp_end = 12 + ftyp_size
    if ftyp_size < ftyp_header + 8 or ftyp_end > len(raw):
        raise StegodepthJP2Error("invalid ftyp box")
    ftyp_body_start = 12 + ftyp_header
    ftyp_body_size = ftyp_end - ftyp_body_start
    if (ftyp_body_size - 8) % 4:
        raise StegodepthJP2Error("invalid ftyp compatibility list")
    family = {b"jp2 ", b"jpx ", b"jpxb"}
    brand = raw[ftyp_body_start:ftyp_body_start + 4]
    compatible = brand in family
    cursor = ftyp_body_start + 8
    while not compatible and cursor < ftyp_end:
        compatible = raw[cursor:cursor + 4] in family
        cursor += 4
    if not compatible:
        raise StegodepthJP2Error("ftyp does not declare JP2/JPX compatibility")
    _parse_box_range(
        raw, 12, ftyp_end, depth=0, parent="", state=state,
        top_level=True, allow_tail=False,
    )
    logical_end, post_container = _parse_box_range(
        raw, ftyp_end, len(raw), depth=0, parent="", state=state,
        top_level=True, allow_tail=True,
    )
    if not state.codestreams:
        raise StegodepthJP2Error("JP2/JPX file contains no contiguous codestream box")
    if not any(box.box_type == "jp2h" and box.depth == 0 for box in state.boxes):
        raise StegodepthJP2Error("JP2/JPX file contains no header superbox")
    if post_container:
        post_artifact = _artifact_span(
            raw, logical_end, len(raw), "post_container", "/post_container",
            state.artifact_budget,
        )
        state.artifacts.append(post_artifact)
        saved_post = post_artifact.data
        state.findings.append(
            f"{len(raw) - logical_end} byte(s) follow the last complete box"
        )
    else:
        saved_post = b""
    container_format = "jpx" if brand in (b"jpx ", b"jpxb") else "jp2"
    return JP2Report(
        container_format, logical_end, tuple(state.boxes), tuple(state.codestreams),
        tuple(state.artifacts), saved_post, len(raw) - logical_end, tuple(state.findings),
    )


def inspect_jp2(data: object) -> JP2Report | None:
    """Inspect a raw J2K codestream or JP2/JPX box file, failing closed."""

    raw = _bounded_bytes(data)
    if raw is None:
        return None
    try:
        if raw.startswith(JP2_SIGNATURE):
            return _parse_jp2(raw)
        if raw.startswith(b"\xff\x4f"):
            codestream = _parse_codestream(raw, 0, len(raw))
            artifacts = list(codestream.artifacts)
            findings = []
            if codestream.tail_size:
                findings.append(f"{codestream.tail_size} byte(s) follow EOC")
            return JP2Report(
                "j2k", codestream.logical_end, (), (codestream,), tuple(artifacts),
                codestream.tail, codestream.tail_size, tuple(findings),
            )
        return None
    except StegodepthJP2Error:
        return None
    except Exception:
        return None


# A short, discoverable alias for interactive use.
inspect = inspect_jp2


def _jsonable(value: object) -> object:
    if isinstance(value, bytes):
        return {"size": len(value), "hex": value.hex()}
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegodepth_jp2.py",
        description="Offline bounded JP2/JPX and raw J2K structural inspector",
    )
    parser.add_argument("input", help="JP2/JPX or raw J2K file")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
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
            raise StegodepthJP2Error(f"input exceeds {MAX_INPUT_BYTES}-byte cap")
        report = inspect_jp2(raw)
        if report is None:
            output = {
                "input": str(path),
                "recognized": False,
                "note": "malformed, unsupported, or incomplete JP2/J2K input",
            }
        else:
            output = {"input": str(path), "recognized": True}
            output.update(_jsonable(asdict(report)))
        print(json.dumps(output, sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except (OSError, StegodepthJP2Error, MemoryError, TypeError, UnicodeError) as exc:
        print(f"stegodepth_jp2: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "StegodepthJP2Error", "BoxRecord", "Artifact", "MarkerRecord",
    "ComponentRecord", "CommentRecord", "TilePartRecord", "CodestreamReport",
    "JP2Report", "inspect_codestream", "inspect_jp2", "inspect", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
