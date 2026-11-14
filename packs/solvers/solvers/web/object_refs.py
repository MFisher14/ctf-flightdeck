#!/usr/bin/env python3
"""Bounded, offline direct-object-reference candidate builder.

The caller supplies exact IDs or an explicit small integer range.  This module
converts them to sequential, ``md5(id)``, base64, or UUIDv1 references and
prints ranked values for a human.  It has no HTTP client, socket code, target
URL, retry loop, or submission path.

CLI examples::

    object_refs.py generate md5 --start 40 --stop 44
    object_refs.py generate base64 --id 7 --id invoice-8 --url-safe
    object_refs.py uuid1-inspect 9f16b3c0-...-11f1-....
    object_refs.py uuid1-neighbors --anchor UUID --before 2 --after 2
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import re
import sys
import uuid
from itertools import islice
from typing import Any, Iterable


MAX_CANDIDATES = 256
MAX_ID_CHARS = 4096
MAX_AFFIX_CHARS = 1024
UUID_EPOCH = dt.datetime(1582, 10, 15, tzinfo=dt.timezone.utc)
_HEX_NODE = re.compile(r"^(?:0x)?([0-9A-Fa-f]{1,12})$")


class ObjectRefError(ValueError):
    """Invalid or unbounded object-reference input."""


def _cap(value: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ObjectRefError("max_candidates must be an integer") from exc
    if not 1 <= result <= MAX_CANDIDATES:
        raise ObjectRefError(f"max_candidates must be between 1 and {MAX_CANDIDATES}")
    return result


def _bounded_iterable(values: Iterable[Any], cap: int, label: str) -> list[Any]:
    """Consume at most cap+1 items so library callers cannot pass an unbounded iterable."""
    try:
        iterator = iter(values)
    except TypeError as exc:
        raise ObjectRefError(f"{label} must be iterable") from exc
    result = list(islice(iterator, cap + 1))
    if len(result) > cap:
        raise ObjectRefError(f"{label} exceeds candidate cap")
    return result


def _id_text(value: Any) -> str:
    if isinstance(value, bool):
        raise ObjectRefError("boolean IDs are ambiguous")
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ObjectRefError("byte IDs must be UTF-8") from exc
    elif isinstance(value, (str, int)):
        text = str(value)
    else:
        raise ObjectRefError("IDs must be text, integers, or UTF-8 bytes")
    if not text or len(text.encode("utf-8")) > MAX_ID_CHARS or "\x00" in text:
        raise ObjectRefError("ID is empty, contains NUL, or exceeds the size limit")
    return text


def explicit_integer_range(start: int, stop: int, *, step: int | None = None,
                           max_candidates: int = MAX_CANDIDATES) -> list[int]:
    """Return an inclusive, caller-bounded integer range or reject it."""
    cap = _cap(max_candidates)
    try:
        first, last = int(start), int(stop)
    except (TypeError, ValueError) as exc:
        raise ObjectRefError("range endpoints must be integers") from exc
    if step is None:
        stride = 1 if last >= first else -1
    else:
        try:
            stride = int(step)
        except (TypeError, ValueError) as exc:
            raise ObjectRefError("range step must be an integer") from exc
        if stride == 0 or (last - first) * stride < 0:
            raise ObjectRefError("range step does not move from start toward stop")
    count = abs(last - first) // abs(stride) + 1
    if count > cap:
        raise ObjectRefError(f"explicit range exceeds candidate cap ({count} > {cap})")
    values = []
    current = first
    compare = (lambda item: item <= last) if stride > 0 else (lambda item: item >= last)
    while compare(current):
        values.append(current)
        current += stride
    return values


def _row(rank: int, scheme: str, source_id: str, reference: str, **extra):
    return {
        "rank": rank,
        "scheme": scheme,
        "source_id": source_id,
        "reference": reference,
        "candidate_only": True,
        "offline_only": True,
        "network_requests": 0,
        **extra,
    }


def _parse_uuid1(value: str | uuid.UUID) -> uuid.UUID:
    try:
        parsed = value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ObjectRefError("invalid UUID") from exc
    if parsed.version != 1 or parsed.variant != uuid.RFC_4122:
        raise ObjectRefError("UUID must be RFC 4122 version 1")
    return parsed


def _node(value: int | str) -> int:
    if isinstance(value, bool):
        raise ObjectRefError("node must be a 48-bit integer or hexadecimal value")
    if isinstance(value, str):
        normalized = value.replace(":", "").replace("-", "")
        match = _HEX_NODE.fullmatch(normalized)
        if not match:
            raise ObjectRefError("node must be a 48-bit hexadecimal value")
        result = int(match.group(1), 16)
    else:
        try:
            result = int(value)
        except (TypeError, ValueError) as exc:
            raise ObjectRefError("node must be a 48-bit integer") from exc
    if not 0 <= result < 1 << 48:
        raise ObjectRefError("UUIDv1 node must fit in 48 bits")
    return result


def _clock_seq(value: int | str) -> int:
    try:
        result = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError) as exc:
        raise ObjectRefError("clock sequence must be an integer") from exc
    if not 0 <= result < 1 << 14:
        raise ObjectRefError("UUIDv1 clock sequence must fit in 14 bits")
    return result


def timestamp_to_uuid_ticks(value: int | str | dt.datetime) -> int:
    """Convert UUID ticks, or an ISO-8601/datetime instant, to 100 ns UUID ticks."""
    if isinstance(value, bool):
        raise ObjectRefError("timestamp must be ticks or an ISO-8601 instant")
    if isinstance(value, int):
        ticks = value
    else:
        instant = value
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.isdigit():
                ticks = int(stripped)
                if not 0 <= ticks < 1 << 60:
                    raise ObjectRefError("UUIDv1 timestamp must fit in 60 bits")
                return ticks
            try:
                instant = dt.datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ObjectRefError("timestamp must be UUID ticks or ISO-8601") from exc
        if not isinstance(instant, dt.datetime):
            raise ObjectRefError("timestamp must be UUID ticks or a datetime")
        if instant.tzinfo is None:
            raise ObjectRefError("ISO/datetime timestamp needs an explicit timezone")
        utc = instant.astimezone(dt.timezone.utc)
        delta = utc - UUID_EPOCH
        ticks = ((delta.days * 86_400 + delta.seconds) * 10_000_000
                 + delta.microseconds * 10)
    if not 0 <= ticks < 1 << 60:
        raise ObjectRefError("UUIDv1 timestamp must fit in 60 bits")
    return ticks


def uuid1_from_parts(timestamp_100ns: int | str | dt.datetime, clock_seq: int | str,
                     node: int | str) -> uuid.UUID:
    """Construct a standards-compliant UUIDv1 without reading host state."""
    timestamp = timestamp_to_uuid_ticks(timestamp_100ns)
    sequence = _clock_seq(clock_seq)
    node_int = _node(node)
    fields = (
        timestamp & 0xFFFFFFFF,
        (timestamp >> 32) & 0xFFFF,
        ((timestamp >> 48) & 0x0FFF) | 0x1000,
        ((sequence >> 8) & 0x3F) | 0x80,
        sequence & 0xFF,
        node_int,
    )
    return uuid.UUID(fields=fields)


def inspect_uuid1(value: str | uuid.UUID) -> dict[str, Any]:
    """Expose the timestamp, clock sequence, and node encoded in one UUIDv1."""
    parsed = _parse_uuid1(value)
    seconds, remainder = divmod(parsed.time, 10_000_000)
    microseconds, submicro_ticks = divmod(remainder, 10)
    instant = UUID_EPOCH + dt.timedelta(seconds=seconds, microseconds=microseconds)
    return {
        "uuid": str(parsed),
        "version": 1,
        "variant": "rfc4122",
        "timestamp_100ns": parsed.time,
        "timestamp_utc": instant.isoformat().replace("+00:00", "Z"),
        "submicrosecond_100ns": submicro_ticks,
        "clock_seq": parsed.clock_seq,
        "node": parsed.node,
        "node_hex": f"{parsed.node:012x}",
        "multicast_node_bit": bool(parsed.node & (1 << 40)),
        "offline_only": True,
        "network_requests": 0,
    }


def _neighbor_offsets(before: int, after: int, step: int, cap: int) -> list[int]:
    try:
        left, right, stride = int(before), int(after), int(step)
    except (TypeError, ValueError) as exc:
        raise ObjectRefError("before, after, and step must be integers") from exc
    if left < 0 or right < 0 or stride <= 0:
        raise ObjectRefError("before/after must be nonnegative and step must be positive")
    negative_count = left // stride
    positive_count = right // stride
    if 1 + negative_count + positive_count > cap:
        raise ObjectRefError("UUIDv1 neighborhood exceeds candidate cap")
    ordered = [0]
    for index in range(1, max(negative_count, positive_count) + 1):
        if index <= negative_count:
            ordered.append(-(index * stride))
        if index <= positive_count:
            ordered.append(index * stride)
    return ordered


def uuid1_neighborhood(*, anchor: str | uuid.UUID | None = None,
                       timestamp_100ns: int | str | dt.datetime | None = None,
                       node: int | str | None = None, clock_seq: int | str | None = None,
                       before: int = 0, after: int = 0, step: int = 1,
                       max_candidates: int = MAX_CANDIDATES):
    """Build nearest-first UUIDv1 candidates from explicit clock information.

    An anchor supplies timestamp/node/clock-sequence defaults.  Without an
    anchor all three values are required; no current time, MAC, or randomness
    is ever inferred from the analyst's machine.
    """
    cap = _cap(max_candidates)
    parsed = _parse_uuid1(anchor) if anchor is not None else None
    timestamp = (timestamp_to_uuid_ticks(timestamp_100ns) if timestamp_100ns is not None
                 else parsed.time if parsed is not None else None)
    node_int = _node(node) if node is not None else parsed.node if parsed is not None else None
    sequence = (_clock_seq(clock_seq) if clock_seq is not None
                else parsed.clock_seq if parsed is not None else None)
    if timestamp is None or node_int is None or sequence is None:
        raise ObjectRefError("without an anchor, timestamp, node, and clock_seq are all required")
    offsets = _neighbor_offsets(before, after, step, cap)
    out = []
    for rank, offset in enumerate(offsets, 1):
        shifted = timestamp + offset
        if not 0 <= shifted < 1 << 60:
            raise ObjectRefError("UUIDv1 neighborhood crosses the timestamp limit")
        candidate = uuid1_from_parts(shifted, sequence, node_int)
        out.append(_row(
            rank, "uuidv1", str(anchor) if anchor is not None else str(timestamp), str(candidate),
            offset_100ns=offset, timestamp_100ns=shifted, clock_seq=sequence,
            node_hex=f"{node_int:012x}",
        ))
    return out


def enumerate_references(scheme: str, identifiers: Iterable[Any], *,
                         prefix: str = "", suffix: str = "", url_safe: bool = False,
                         strip_padding: bool = False, uuid_before: int = 0,
                         uuid_after: int = 0, uuid_step: int = 1,
                         max_candidates: int = MAX_CANDIDATES):
    """Convert an explicit finite ID set to ranked offline reference values."""
    cap = _cap(max_candidates)
    values = _bounded_iterable(identifiers, cap, "identifier list")
    if not values:
        raise ObjectRefError("at least one explicit identifier is required")
    normalized = (scheme.lower().replace("_", "").replace("-", "")
                  .replace("(", "").replace(")", ""))
    aliases = {"seq": "sequential", "sequential": "sequential", "md5": "md5",
               "md5id": "md5", "base64": "base64", "b64": "base64",
               "uuid1": "uuidv1", "uuidv1": "uuidv1"}
    kind = aliases.get(normalized)
    if kind is None:
        raise ObjectRefError("scheme must be sequential, md5, base64, or uuidv1")
    prefix, suffix = str(prefix), str(suffix)
    if len(prefix.encode("utf-8")) > MAX_AFFIX_CHARS or len(suffix.encode("utf-8")) > MAX_AFFIX_CHARS:
        raise ObjectRefError("prefix/suffix exceeds limit")

    if kind == "uuidv1":
        # Validate sign/step before doing any sizing arithmetic.  The helper
        # also establishes the exact nearest-first count for one anchor.
        offsets = _neighbor_offsets(uuid_before, uuid_after, uuid_step, cap)
        per_anchor = len(offsets)
        if per_anchor * len(values) > cap:
            raise ObjectRefError("UUIDv1 neighborhoods exceed candidate cap")
        rows = []
        for value in values:
            rows.extend(uuid1_neighborhood(anchor=_id_text(value), before=uuid_before,
                                           after=uuid_after, step=uuid_step,
                                           max_candidates=cap - len(rows)))
        for rank, row in enumerate(rows, 1):
            row["rank"] = rank
        return rows

    out = []
    for rank, identifier in enumerate(values, 1):
        text = _id_text(identifier)
        source = f"{prefix}{text}{suffix}"
        if kind == "sequential":
            reference = text
        elif kind == "md5":
            reference = hashlib.md5(source.encode("utf-8")).hexdigest()  # nosec: specified ID scheme
        else:
            raw = source.encode("utf-8")
            reference = ((base64.urlsafe_b64encode(raw) if url_safe else base64.b64encode(raw))
                         .decode("ascii"))
            if strip_padding:
                reference = reference.rstrip("=")
        out.append(_row(rank, kind, text, reference,
                        transform_input=source if source != text else text,
                        url_safe=bool(url_safe) if kind == "base64" else None,
                        padding_stripped=bool(strip_padding) if kind == "base64" else None))
    return out


def _ids_from_args(args) -> list[Any]:
    values = list(args.id or [])
    has_start = args.start is not None
    has_stop = args.stop is not None
    if has_start != has_stop:
        raise ObjectRefError("--start and --stop must be supplied together")
    if has_start:
        values.extend(explicit_integer_range(args.start, args.stop, step=args.range_step,
                                             max_candidates=args.max_candidates - len(values)))
    if len(values) > args.max_candidates:
        raise ObjectRefError("combined explicit IDs exceed candidate cap")
    return values


def _parser():
    parser = argparse.ArgumentParser(description="bounded offline IDOR/object-reference candidate builder")
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate", help="transform explicit IDs or one explicit integer range")
    generate.add_argument("scheme", choices=("sequential", "md5", "base64", "uuidv1"))
    generate.add_argument("--id", action="append", default=[])
    generate.add_argument("--start", type=int)
    generate.add_argument("--stop", type=int)
    generate.add_argument("--range-step", type=int)
    generate.add_argument("--prefix", default="")
    generate.add_argument("--suffix", default="")
    generate.add_argument("--url-safe", action="store_true")
    generate.add_argument("--strip-padding", action="store_true")
    generate.add_argument("--uuid-before", type=int, default=0, help="100 ns ticks before each UUIDv1 anchor")
    generate.add_argument("--uuid-after", type=int, default=0, help="100 ns ticks after each UUIDv1 anchor")
    generate.add_argument("--uuid-step", type=int, default=1, help="UUIDv1 step in 100 ns ticks")
    generate.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES)

    inspect = sub.add_parser("uuid1-inspect", help="decode one UUIDv1 into time/node/clock fields")
    inspect.add_argument("uuid")

    neighbors = sub.add_parser("uuid1-neighbors", help="build a nearest-first explicit UUIDv1 neighborhood")
    neighbors.add_argument("--anchor")
    neighbors.add_argument("--timestamp", help="UUID 100 ns ticks or timezone-aware ISO-8601")
    neighbors.add_argument("--node", help="48-bit hex node (colons accepted)")
    neighbors.add_argument("--clock-seq")
    neighbors.add_argument("--before", type=int, default=0, help="100 ns ticks before the anchor")
    neighbors.add_argument("--after", type=int, default=0, help="100 ns ticks after the anchor")
    neighbors.add_argument("--step", type=int, default=1, help="step in 100 ns ticks")
    neighbors.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "uuid1-inspect":
            result = inspect_uuid1(args.uuid)
        elif args.command == "uuid1-neighbors":
            result = uuid1_neighborhood(anchor=args.anchor, timestamp_100ns=args.timestamp,
                                        node=args.node, clock_seq=args.clock_seq,
                                        before=args.before, after=args.after, step=args.step,
                                        max_candidates=args.max_candidates)
        else:
            cap = _cap(args.max_candidates)
            args.max_candidates = cap
            identifiers = _ids_from_args(args)
            result = enumerate_references(
                args.scheme, identifiers, prefix=args.prefix, suffix=args.suffix,
                url_safe=args.url_safe, strip_padding=args.strip_padding,
                uuid_before=args.uuid_before, uuid_after=args.uuid_after,
                uuid_step=args.uuid_step, max_candidates=cap,
            )
    except (ObjectRefError, ZeroDivisionError) as exc:
        print(f"object_refs: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
