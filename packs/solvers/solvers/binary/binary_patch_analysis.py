"""Bounded structural binary diffing and patch analysis over supplied bytes.

This module performs linear comparisons, section/region correlation, primitive
metadata comparison, and unique fixed-block move detection.  It never opens or
modifies an artifact and deliberately avoids quadratic alignment algorithms.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
from typing import Mapping, Sequence


MAX_BINARY = 64 << 20
MAX_HUNKS = 4096
MAX_REGIONS = 512
MAX_METADATA = 512
MAX_MOVES = 2048
MAX_MOVE_BLOCKS = 262_144
MAX_PREVIEW = 64


class DiffInputError(ValueError):
    pass


@dataclass(frozen=True)
class BinaryRegion:
    name: str
    offset: int
    size: int
    virtual_address: int | None = None
    flags: str = ""


@dataclass(frozen=True)
class PatchHunk:
    before_offset: int
    before_size: int
    after_offset: int
    after_size: int
    before_sha256: str
    after_sha256: str
    before_preview: str
    after_preview: str
    classification: tuple[str, ...]
    confidence: int
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class RegionChange:
    name: str
    status: str
    before: BinaryRegion | None
    after: BinaryRegion | None
    content_changed: bool
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class MetadataChange:
    key: str
    before: str
    after: str


@dataclass(frozen=True)
class MovedBlock:
    before_offset: int
    after_offset: int
    size: int
    sha256: str


@dataclass(frozen=True)
class BinaryDiffReport:
    before_size: int
    after_size: int
    identical: bool
    common_prefix: int
    common_suffix: int
    hunks: tuple[PatchHunk, ...]
    region_changes: tuple[RegionChange, ...]
    metadata_changes: tuple[MetadataChange, ...]
    moved_blocks: tuple[MovedBlock, ...]
    truncated: bool

    def to_dict(self) -> dict:
        return asdict(self)


def _blob(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(f"{label} must be immutable bytes")
    if len(value) > MAX_BINARY:
        raise DiffInputError(f"{label} exceeds the 64 MiB cap")
    return value


def _bounded_int(value: object, field: str, maximum: int = (1 << 64) - 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= maximum:
        raise DiffInputError(f"{field} is out of range")
    return value


_REGION_NAME = re.compile(r"[A-Za-z0-9_.$:/+-]{1,128}\Z")


def _region(value: BinaryRegion | Mapping[str, object]) -> BinaryRegion:
    if isinstance(value, BinaryRegion):
        raw: Mapping[str, object] = asdict(value)
    elif isinstance(value, Mapping):
        raw = value
    else:
        raise TypeError("region must be BinaryRegion or mapping")
    allowed = {"name", "offset", "size", "virtual_address", "flags"}
    if any(key not in allowed for key in raw):
        raise DiffInputError("region contains an unknown field")
    name, flags = raw.get("name"), raw.get("flags", "")
    if not isinstance(name, str) or not _REGION_NAME.fullmatch(name):
        raise DiffInputError("region name is invalid")
    if not isinstance(flags, str) or len(flags) > 64:
        raise DiffInputError("region flags are invalid")
    offset = _bounded_int(raw.get("offset"), "region offset", MAX_BINARY)
    size = _bounded_int(raw.get("size"), "region size", MAX_BINARY)
    virtual = raw.get("virtual_address")
    if virtual is not None:
        virtual = _bounded_int(virtual, "virtual address")
    return BinaryRegion(name, offset, size, virtual, flags)


def normalize_regions(
    values: Sequence[BinaryRegion | Mapping[str, object]], blob_size: int
) -> tuple[BinaryRegion, ...]:
    if not isinstance(blob_size, int) or isinstance(blob_size, bool) or not 0 <= blob_size <= MAX_BINARY:
        raise DiffInputError("blob_size is out of range")
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or len(values) > MAX_REGIONS:
        raise DiffInputError("regions must be a sequence of at most 512 entries")
    rows = sorted((_region(value) for value in values), key=lambda row: (row.offset, row.name))
    names = set()
    end = 0
    for row in rows:
        if row.name in names:
            raise DiffInputError("region names must be unique")
        names.add(row.name)
        if row.offset + row.size > blob_size:
            raise DiffInputError("region exceeds supplied bytes")
        if row.offset < end and row.size:
            raise DiffInputError("regions overlap")
        end = max(end, row.offset + row.size)
    return tuple(rows)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _ascii(value: bytes) -> str | None:
    if not value or len(value) > 256:
        return None
    if sum(0x20 <= byte <= 0x7E for byte in value) / len(value) < 0.8:
        return None
    return "".join(chr(byte) if 0x20 <= byte <= 0x7E else "." for byte in value)


def _classify(before: bytes, after: bytes) -> tuple[tuple[str, ...], int, tuple[str, ...]]:
    classes = []
    evidence = []
    confidence = 60
    if not before:
        classes.append("insertion")
    elif not after:
        classes.append("deletion")
    else:
        classes.append("replacement")
    if after and set(after) <= {0x00}:
        classes.append("zeroed")
        evidence.append("replacement bytes are all zero")
        confidence = max(confidence, 90)
    if after and (set(after) <= {0x90} or after in {b"\x1f\x20\x03\xd5", b"\x13\x00\x00\x00"}):
        classes.append("nop-fill")
        evidence.append("replacement is a common x86/AArch64/RISC-V NOP encoding")
        confidence = max(confidence, 92)
    branch_pairs = {
        (0x74, 0x75): "x86 conditional branch polarity changed",
        (0x75, 0x74): "x86 conditional branch polarity changed",
        (0x74, 0xEB): "x86 conditional branch made unconditional",
        (0x75, 0xEB): "x86 conditional branch made unconditional",
        (0xE8, 0xE9): "x86 call changed to jump",
    }
    if len(before) == len(after) == 1 and (before[0], after[0]) in branch_pairs:
        classes.append("control-flow-edit")
        evidence.append(branch_pairs[(before[0], after[0])])
        confidence = 98
    old_text, new_text = _ascii(before), _ascii(after)
    if old_text is not None or new_text is not None:
        classes.append("string-or-table-edit")
        evidence.append(f"printable content changed: {old_text!r} -> {new_text!r}")
        confidence = max(confidence, 80)
    if len(before) != len(after):
        evidence.append(f"size changed by {len(after) - len(before):+d} bytes")
    return tuple(classes), confidence, tuple(evidence or ("exact byte range differs",))


def _hunk(before_offset: int, before: bytes, after_offset: int, after: bytes) -> PatchHunk:
    classes, confidence, evidence = _classify(before, after)
    return PatchHunk(
        before_offset, len(before), after_offset, len(after), _digest(before), _digest(after),
        before[:MAX_PREVIEW].hex(), after[:MAX_PREVIEW].hex(), classes, confidence, evidence,
    )


def byte_hunks(before: bytes, after: bytes, *, max_hunks: int = MAX_HUNKS) -> tuple[tuple[PatchHunk, ...], bool]:
    before, after = _blob(before, "before"), _blob(after, "after")
    if not isinstance(max_hunks, int) or isinstance(max_hunks, bool) or not 1 <= max_hunks <= MAX_HUNKS:
        raise ValueError("max_hunks must be in 1..4096")
    if before == after:
        return (), False
    if len(before) != len(after):
        prefix = 0
        limit = min(len(before), len(after))
        while prefix < limit and before[prefix] == after[prefix]:
            prefix += 1
        suffix = 0
        while (suffix < limit - prefix and before[len(before) - 1 - suffix] == after[len(after) - 1 - suffix]):
            suffix += 1
        old_end = len(before) - suffix if suffix else len(before)
        new_end = len(after) - suffix if suffix else len(after)
        return (_hunk(prefix, before[prefix:old_end], prefix, after[prefix:new_end]),), False
    rows = []
    index = 0
    truncated = False
    while index < len(before):
        if before[index] == after[index]:
            index += 1
            continue
        start = index
        while index < len(before) and before[index] != after[index]:
            index += 1
        if len(rows) >= max_hunks:
            truncated = True
            break
        rows.append(_hunk(start, before[start:index], start, after[start:index]))
    return tuple(rows), truncated


def _primitive(value: object, field: str) -> str:
    if value is None or isinstance(value, (bool, int, str)):
        rendered = repr(value)
        if len(rendered) <= 4096:
            return rendered
    raise DiffInputError(f"metadata {field!r} is not a bounded primitive")


def diff_metadata(before: Mapping[str, object], after: Mapping[str, object]) -> tuple[MetadataChange, ...]:
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        raise TypeError("metadata must be mappings")
    keys = set(before) | set(after)
    if len(keys) > MAX_METADATA or any(not isinstance(key, str) or len(key) > 128 for key in keys):
        raise DiffInputError("metadata exceeds key caps")
    rows = []
    for key in sorted(keys):
        left = _primitive(before.get(key), key)
        right = _primitive(after.get(key), key)
        if key not in before:
            left = "<missing>"
        if key not in after:
            right = "<missing>"
        if left != right:
            rows.append(MetadataChange(key, left, right))
    return tuple(rows)


def diff_regions(
    before: bytes,
    after: bytes,
    before_regions: Sequence[BinaryRegion | Mapping[str, object]],
    after_regions: Sequence[BinaryRegion | Mapping[str, object]],
) -> tuple[RegionChange, ...]:
    before, after = _blob(before, "before"), _blob(after, "after")
    left = {row.name: row for row in normalize_regions(before_regions, len(before))}
    right = {row.name: row for row in normalize_regions(after_regions, len(after))}
    rows = []
    for name in sorted(set(left) | set(right)):
        old, new = left.get(name), right.get(name)
        if old is None:
            rows.append(RegionChange(name, "added", None, new, True, ("region exists only after patch",)))
            continue
        if new is None:
            rows.append(RegionChange(name, "removed", old, None, True, ("region exists only before patch",)))
            continue
        old_bytes = before[old.offset:old.offset + old.size]
        new_bytes = after[new.offset:new.offset + new.size]
        changed = old_bytes != new_bytes
        facts = []
        if old.offset != new.offset:
            facts.append(f"file offset moved {old.offset:#x}->{new.offset:#x}")
        if old.virtual_address != new.virtual_address:
            facts.append(f"virtual address changed {old.virtual_address!r}->{new.virtual_address!r}")
        if old.size != new.size:
            facts.append(f"size changed {old.size}->{new.size}")
        if old.flags != new.flags:
            facts.append(f"flags changed {old.flags!r}->{new.flags!r}")
        if changed:
            facts.append("region SHA-256 changed")
        status = "modified" if changed else "relocated" if facts else "unchanged"
        rows.append(RegionChange(name, status, old, new, changed, tuple(facts or ("region unchanged",))))
    return tuple(rows)


def _find_unique_moved_blocks(
    before: bytes, after: bytes, *, block_size: int, max_moves: int
) -> tuple[tuple[MovedBlock, ...], bool]:
    before, after = _blob(before, "before"), _blob(after, "after")
    if not isinstance(block_size, int) or isinstance(block_size, bool) or not 16 <= block_size <= 4096:
        raise ValueError("block_size must be in 16..4096")
    if not isinstance(max_moves, int) or isinstance(max_moves, bool) or not 1 <= max_moves <= MAX_MOVES:
        raise ValueError("max_moves must be in 1..2048")
    if max(len(before), len(after)) // block_size > MAX_MOVE_BLOCKS:
        raise DiffInputError("move index exceeds block cap; choose a larger block_size")
    def index(data: bytes) -> dict[bytes, list[int]]:
        rows: dict[bytes, list[int]] = {}
        for offset in range(0, len(data) - block_size + 1, block_size):
            digest = hashlib.sha256(data[offset:offset + block_size]).digest()
            bucket = rows.setdefault(digest, [])
            if len(bucket) < 2:
                bucket.append(offset)
        return rows
    left, right = index(before), index(after)
    moves = []
    for digest in sorted(set(left) & set(right)):
        if len(left[digest]) == len(right[digest]) == 1 and left[digest][0] != right[digest][0]:
            moves.append(MovedBlock(left[digest][0], right[digest][0], block_size, digest.hex()))
    ordered = tuple(sorted(moves, key=lambda row: (row.before_offset, row.after_offset)))
    return ordered[:max_moves], len(ordered) > max_moves


def find_unique_moved_blocks(
    before: bytes, after: bytes, *, block_size: int = 64, max_moves: int = MAX_MOVES
) -> tuple[MovedBlock, ...]:
    """Return capped exact unique-block moves in stable source-offset order."""
    return _find_unique_moved_blocks(
        before, after, block_size=block_size, max_moves=max_moves,
    )[0]


def analyze_binary_patch(
    before: bytes,
    after: bytes,
    *,
    before_regions: Sequence[BinaryRegion | Mapping[str, object]] = (),
    after_regions: Sequence[BinaryRegion | Mapping[str, object]] = (),
    before_metadata: Mapping[str, object] | None = None,
    after_metadata: Mapping[str, object] | None = None,
    move_block_size: int = 64,
) -> BinaryDiffReport:
    before, after = _blob(before, "before"), _blob(after, "after")
    prefix = 0
    limit = min(len(before), len(after))
    while prefix < limit and before[prefix] == after[prefix]:
        prefix += 1
    suffix = 0
    while suffix < limit - prefix and before[-1 - suffix] == after[-1 - suffix]:
        suffix += 1
    hunks, truncated = byte_hunks(before, after)
    # Always pass through the public validators so false-y values of the wrong
    # type are not silently treated as omitted metadata/regions.
    region_changes = diff_regions(before, after, before_regions, after_regions)
    left_metadata = {} if before_metadata is None else before_metadata
    right_metadata = {} if after_metadata is None else after_metadata
    metadata_changes = diff_metadata(left_metadata, right_metadata)
    moves, moves_truncated = _find_unique_moved_blocks(
        before, after, block_size=move_block_size, max_moves=MAX_MOVES,
    )
    return BinaryDiffReport(
        len(before), len(after), before == after, prefix, suffix, hunks,
        region_changes, metadata_changes, moves, truncated or moves_truncated,
    )


__all__ = [
    "DiffInputError", "BinaryRegion", "PatchHunk", "RegionChange", "MetadataChange",
    "MovedBlock", "BinaryDiffReport", "normalize_regions", "byte_hunks", "diff_metadata",
    "diff_regions", "find_unique_moved_blocks", "analyze_binary_patch",
]
