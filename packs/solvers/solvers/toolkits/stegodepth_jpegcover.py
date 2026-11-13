#!/usr/bin/env python3
"""Exact known-cover comparison for baseline sequential JPEG coefficients.

This is an offline diagnostic, not a blind steganography classifier.  It compares
the quantized coefficient arrays of a supplied cover JPEG and suspect JPEG only
after both streams have been completely and strictly decoded.  Geometry,
component/block order, and quantization tables must match.  The resulting report
describes *where and how* the coefficients changed; it deliberately does not label
the changes as J-UNIWARD, UERD, F5, nsF5, or any other embedding algorithm.

Only SOF0/SOF1 single-scan Huffman JPEGs accepted by the repository's strict
pure-Python decoder are supported.  Progressive, arithmetic, lossless, truncated,
polyglot-tailed, and otherwise malformed inputs return ``None``.  A valid pair
whose representations are not comparable raises :class:`StegodepthJPEGCoverError`.

CLI:
    stegodepth_jpegcover.py COVER.jpg SUSPECT.jpg [--pretty]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import numpy as np
except Exception:  # pragma: no cover - dependency failure is reported by compare
    np = None

try:
    import steganalysis as _steganalysis
except Exception:  # pragma: no cover - direct package import fallback
    try:
        from . import steganalysis as _steganalysis
    except Exception:
        _steganalysis = None


MAX_INPUT_BYTES = 128 << 20
MAX_COEFFICIENTS = 16_000_000
MAX_DELTA_BINS = 64


class StegodepthJPEGCoverError(ValueError):
    """The supplied values cannot safely be compared as a known-cover pair."""


@dataclass(frozen=True, slots=True)
class ComponentDiff:
    component: int
    blocks: int
    changed: int
    changed_ac: int
    unit_changes: int
    shrinkage: int
    growth: int


@dataclass(frozen=True, slots=True)
class CoefficientDiffReport:
    width: int
    height: int
    blocks: int
    coefficients: int
    quantization_table_ids: tuple[int, ...]
    changed: int
    changed_blocks: int
    changed_dc: int
    changed_ac: int
    unit_changes: int
    unit_change_fraction: float
    shrinkage: int
    growth: int
    delta_histogram: tuple[tuple[int, int], ...]
    delta_histogram_other: int
    per_component: tuple[ComponentDiff, ...]
    per_frequency: tuple[int, ...]
    all_block_ac_energy_quartiles: tuple[float, float, float]
    changed_block_ac_energy_quartiles: tuple[float, float, float] | None
    changed_to_all_median_energy_ratio: float | None
    interpretation: str = (
        "exact known-cover coefficient deltas only; metrics do not identify an embedding algorithm"
    )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation."""
        return asdict(self)


@dataclass(frozen=True, slots=True)
class _Decoded:
    frame: dict[str, Any]
    coefficients: Any
    tags: tuple[int, ...]
    quantization: tuple[tuple[int, int, tuple[int, ...]], ...]


def _bounded_bytes(value: object, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise StegodepthJPEGCoverError(f"{label} must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
    except Exception as exc:
        raise StegodepthJPEGCoverError(f"cannot measure {label}") from exc
    if size < 1 or size > MAX_INPUT_BYTES:
        raise StegodepthJPEGCoverError(
            f"{label} size must be in 1..{MAX_INPUT_BYTES} bytes"
        )
    try:
        return bytes(value)
    except Exception as exc:
        raise StegodepthJPEGCoverError(f"cannot copy {label}") from exc


def _quantization_tables(raw: bytes) -> tuple[tuple[int, int, tuple[int, ...]], ...]:
    """Return unique DQT definitions as ``(id, precision, values-in-file-order)``."""
    if len(raw) < 4 or raw[:2] != b"\xff\xd8":
        raise StegodepthJPEGCoverError("not a JPEG marker stream")
    position = 2
    tables: dict[int, tuple[int, tuple[int, ...]]] = {}
    while position < len(raw) - 2:
        if raw[position] != 0xFF:
            raise StegodepthJPEGCoverError("non-marker byte before SOS")
        while position < len(raw) and raw[position] == 0xFF:
            position += 1
        if position >= len(raw):
            raise StegodepthJPEGCoverError("truncated JPEG marker")
        marker = raw[position]
        position += 1
        if marker == 0xDA:
            break
        if marker in (0x00, 0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            raise StegodepthJPEGCoverError("unexpected standalone JPEG marker")
        if marker == 0x01:
            continue
        if position + 2 > len(raw):
            raise StegodepthJPEGCoverError("truncated JPEG segment length")
        length = int.from_bytes(raw[position:position + 2], "big")
        if length < 2 or position + length > len(raw):
            raise StegodepthJPEGCoverError("JPEG segment leaves the input")
        body_start = position + 2
        body_end = position + length
        if marker == 0xDB:
            cursor = body_start
            while cursor < body_end:
                descriptor = raw[cursor]
                cursor += 1
                precision, table_id = descriptor >> 4, descriptor & 0x0F
                if precision not in (0, 1) or table_id > 3:
                    raise StegodepthJPEGCoverError("unsupported DQT precision/table id")
                width = 1 if precision == 0 else 2
                needed = 64 * width
                if cursor + needed > body_end:
                    raise StegodepthJPEGCoverError("truncated DQT table")
                values = tuple(
                    int.from_bytes(raw[cursor + index:cursor + index + width], "big")
                    for index in range(0, needed, width)
                )
                if any(value == 0 for value in values):
                    raise StegodepthJPEGCoverError("zero JPEG quantizer")
                definition = (precision, values)
                if table_id in tables and tables[table_id] != definition:
                    raise StegodepthJPEGCoverError("DQT table is redefined")
                tables[table_id] = definition
                cursor += needed
        position += length
    if not tables:
        raise StegodepthJPEGCoverError("JPEG has no quantization table")
    return tuple((table_id, precision, values)
                 for table_id, (precision, values) in sorted(tables.items()))


def _decode(raw: bytes) -> _Decoded | None:
    if _steganalysis is None or np is None:
        raise StegodepthJPEGCoverError("NumPy and steganalysis are required")
    try:
        decoded = _steganalysis._decode_complete_jpeg(raw)
    except Exception:
        decoded = None
    if decoded is None:
        return None
    try:
        frame, coefficients, tags = decoded
        if (not isinstance(coefficients, np.ndarray)
                or coefficients.ndim != 2 or coefficients.shape[1] != 64
                or coefficients.size > MAX_COEFFICIENTS
                or len(tags) != coefficients.shape[0]):
            return None
        quantization = _quantization_tables(raw)
        referenced = {int(component["tq"]) for component in frame["comps"]}
        present = {table_id for table_id, _precision, _values in quantization}
        if not referenced or not referenced <= present:
            return None
        return _Decoded(frame, coefficients, tuple(int(tag) for tag in tags), quantization)
    except StegodepthJPEGCoverError:
        return None
    except (KeyError, TypeError, ValueError, IndexError, OverflowError, MemoryError):
        return None


def _quartiles(values: Any) -> tuple[float, float, float]:
    try:
        result = np.quantile(np.asarray(values, dtype=np.float64), (0.25, 0.5, 0.75))
        return tuple(float(value) for value in result)
    except (TypeError, ValueError, OverflowError, MemoryError) as exc:
        raise StegodepthJPEGCoverError("cannot compute bounded energy quartiles") from exc


def compare(cover: object, suspect: object) -> CoefficientDiffReport | None:
    """Compare two exact baseline JPEG coefficient arrays.

    Malformed or unsupported JPEGs return ``None``.  Valid JPEGs with mismatched
    geometry, scan/component order, coefficient shape, or quantization tables
    raise :class:`StegodepthJPEGCoverError` rather than producing a misleading
    diff.
    """
    cover_raw = _bounded_bytes(cover, "cover")
    suspect_raw = _bounded_bytes(suspect, "suspect")
    try:
        left, right = _decode(cover_raw), _decode(suspect_raw)
        if left is None or right is None:
            return None
        if left.frame != right.frame:
            raise StegodepthJPEGCoverError("JPEG frame geometry/components differ")
        if left.tags != right.tags:
            raise StegodepthJPEGCoverError("JPEG block/component order differs")
        if left.coefficients.shape != right.coefficients.shape:
            raise StegodepthJPEGCoverError("JPEG coefficient shapes differ")
        if left.quantization != right.quantization:
            raise StegodepthJPEGCoverError("JPEG quantization tables differ")

        # The strict baseline decoder emits bounded int32 DCT values.  Their
        # difference is also safely int32; retaining that dtype avoids three
        # unnecessary 128 MiB arrays at the configured coefficient ceiling.
        cover_coefficients = left.coefficients
        suspect_coefficients = right.coefficients
        delta = np.subtract(suspect_coefficients, cover_coefficients, dtype=np.int32)
        changed_mask = delta != 0
        changed = int(np.count_nonzero(changed_mask))
        changed_blocks_mask = np.any(changed_mask, axis=1)
        changed_blocks = int(np.count_nonzero(changed_blocks_mask))
        changed_dc = int(np.count_nonzero(changed_mask[:, 0]))
        changed_ac = changed - changed_dc
        unit_mask = changed_mask & (np.abs(delta) == 1)
        unit_changes = int(np.count_nonzero(unit_mask))
        shrinkage = int(np.count_nonzero(
            changed_mask & (cover_coefficients != 0) & (suspect_coefficients == 0)
        ))
        growth = int(np.count_nonzero(
            changed_mask & (cover_coefficients == 0) & (suspect_coefficients != 0)
        ))

        changed_values = delta[changed_mask]
        histogram: tuple[tuple[int, int], ...] = ()
        histogram_other = 0
        if changed_values.size:
            values, counts = np.unique(changed_values, return_counts=True)
            rows = sorted(
                ((int(value), int(count)) for value, count in zip(values, counts)),
                key=lambda row: (-row[1], row[0]),
            )
            histogram = tuple(rows[:MAX_DELTA_BINS])
            histogram_other = sum(count for _value, count in rows[MAX_DELTA_BINS:])

        component_rows = []
        tags_array = np.asarray(left.tags, dtype=np.int16)
        for component in sorted(set(left.tags)):
            block_mask = tags_array == component
            component_changed = changed_mask[block_mask]
            component_delta = delta[block_mask]
            component_cover = cover_coefficients[block_mask]
            component_suspect = suspect_coefficients[block_mask]
            component_rows.append(ComponentDiff(
                component=int(component),
                blocks=int(np.count_nonzero(block_mask)),
                changed=int(np.count_nonzero(component_changed)),
                changed_ac=int(np.count_nonzero(component_changed[:, 1:])),
                unit_changes=int(np.count_nonzero(
                    component_changed & (np.abs(component_delta) == 1)
                )),
                shrinkage=int(np.count_nonzero(
                    component_changed & (component_cover != 0) & (component_suspect == 0)
                )),
                growth=int(np.count_nonzero(
                    component_changed & (component_cover == 0) & (component_suspect != 0)
                )),
            ))

        per_frequency = tuple(int(value) for value in np.count_nonzero(changed_mask, axis=0))
        cover_energy = np.sum(np.abs(cover_coefficients[:, 1:]), axis=1, dtype=np.int64)
        all_quartiles = _quartiles(cover_energy)
        changed_quartiles = _quartiles(cover_energy[changed_blocks_mask]) if changed_blocks else None
        ratio = None
        if changed_quartiles is not None:
            all_median = all_quartiles[1]
            changed_median = changed_quartiles[1]
            if all_median > 0:
                ratio = float(changed_median / all_median)
                if not math.isfinite(ratio):
                    ratio = None

        return CoefficientDiffReport(
            width=int(left.frame["w"]),
            height=int(left.frame["h"]),
            blocks=int(cover_coefficients.shape[0]),
            coefficients=int(cover_coefficients.size),
            quantization_table_ids=tuple(row[0] for row in left.quantization),
            changed=changed,
            changed_blocks=changed_blocks,
            changed_dc=changed_dc,
            changed_ac=changed_ac,
            unit_changes=unit_changes,
            unit_change_fraction=float(unit_changes / changed) if changed else 0.0,
            shrinkage=shrinkage,
            growth=growth,
            delta_histogram=histogram,
            delta_histogram_other=int(histogram_other),
            per_component=tuple(component_rows),
            per_frequency=per_frequency,
            all_block_ac_energy_quartiles=all_quartiles,
            changed_block_ac_energy_quartiles=changed_quartiles,
            changed_to_all_median_energy_ratio=ratio,
        )
    except StegodepthJPEGCoverError:
        raise
    except (TypeError, ValueError, IndexError, KeyError, OverflowError,
            ArithmeticError, MemoryError) as exc:
        raise StegodepthJPEGCoverError("known-cover comparison failed safely") from exc


def _read(path: str) -> bytes:
    try:
        candidate = Path(path)
        with candidate.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) < 1 or len(raw) > MAX_INPUT_BYTES:
            raise StegodepthJPEGCoverError(
                f"{path}: size must be in 1..{MAX_INPUT_BYTES} bytes"
            )
        return raw
    except StegodepthJPEGCoverError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, MemoryError) as exc:
        raise StegodepthJPEGCoverError(f"cannot read {path}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="stegodepth_jpegcover.py",
        description="Exact known-cover quantized-JPEG coefficient comparison (offline).",
    )
    parser.add_argument("cover")
    parser.add_argument("suspect")
    parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = compare(_read(args.cover), _read(args.suspect))
        if report is None:
            raise StegodepthJPEGCoverError(
                "one or both files are malformed or unsupported baseline JPEGs"
            )
        print(json.dumps(report.to_dict(), sort_keys=True, indent=2 if args.pretty else None))
        return 0
    except StegodepthJPEGCoverError as exc:
        print(f"stegodepth_jpegcover: {exc}", file=sys.stderr)
        return 2
    except (TypeError, ValueError, OverflowError, OSError, MemoryError) as exc:
        print(f"stegodepth_jpegcover: output failure: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "StegodepthJPEGCoverError", "ComponentDiff", "CoefficientDiffReport",
    "compare", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
