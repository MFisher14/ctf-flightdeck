"""Shared immutable result contract for the r5b offline payload builders.

The builders in this extension only serialize bytes and describe where caller
supplied values were placed.  They never start a process, open a socket, or
deliver a payload.  ``PayloadBuild`` deliberately supports tuple unpacking so
callers can use the exact ``payload, placements = builder(...)`` convention
while retaining useful, deterministic metadata.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Iterator, Mapping


class BuildError(ValueError):
    """Raised when a requested payload cannot be represented safely."""


def _freeze_int_map(values: Mapping[str, int], *, label: str) -> Mapping[str, int]:
    if not isinstance(values, Mapping):
        raise BuildError(f"{label} must be a mapping")
    frozen: dict[str, int] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not key:
            raise BuildError(f"{label} keys must be non-empty strings")
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BuildError(f"{label}[{key!r}] must be a non-negative integer")
        frozen[key] = value
    return MappingProxyType(dict(sorted(frozen.items())))


def _freeze_text_map(values: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(values, Mapping):
        raise BuildError("metadata must be a mapping")
    frozen: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not key or not isinstance(value, str):
            raise BuildError("metadata must map non-empty strings to strings")
        frozen[key] = value
    return MappingProxyType(dict(sorted(frozen.items())))


@dataclass(frozen=True)
class PayloadBuild:
    """One inert payload plus byte offsets and caller-readable metadata.

    ``placements`` maps semantic labels to byte offsets in ``payload``.  Every
    offset is checked at construction time.  ``widths`` optionally records the
    serialized width at a placement and is checked not to overrun the payload.
    ``base_address`` is descriptive only; no memory is accessed.
    """

    payload: bytes
    placements: Mapping[str, int]
    widths: Mapping[str, int] = field(default_factory=dict)
    architecture: str = "generic"
    strategy: str = "raw"
    base_address: int = 0
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes):
            raise BuildError("payload must be immutable bytes")
        if not isinstance(self.architecture, str) or not self.architecture:
            raise BuildError("architecture must be a non-empty string")
        if not isinstance(self.strategy, str) or not self.strategy:
            raise BuildError("strategy must be a non-empty string")
        if isinstance(self.base_address, bool) or not isinstance(self.base_address, int):
            raise BuildError("base_address must be an integer")
        if self.base_address < 0:
            raise BuildError("base_address must be non-negative")

        placements = _freeze_int_map(self.placements, label="placements")
        widths = _freeze_int_map(self.widths, label="widths")
        metadata = _freeze_text_map(self.metadata)
        for name, offset in placements.items():
            if offset > len(self.payload):
                raise BuildError(f"placement {name!r} is outside the payload")
        for name, width in widths.items():
            if name not in placements:
                raise BuildError(f"width {name!r} has no matching placement")
            if width < 1:
                raise BuildError(f"width {name!r} must be positive")
            if placements[name] + width > len(self.payload):
                raise BuildError(f"placement {name!r} overruns the payload")
        object.__setattr__(self, "placements", placements)
        object.__setattr__(self, "widths", widths)
        object.__setattr__(self, "metadata", metadata)

    def __iter__(self) -> Iterator[object]:
        """Allow ``payload, placements = build`` without discarding metadata."""

        yield self.payload
        yield self.placements

    def absolute_placements(self) -> Mapping[str, int]:
        """Return a deterministic label-to-address view for staged payloads."""

        return MappingProxyType({
            key: self.base_address + offset for key, offset in self.placements.items()
        })

    def slice(self, label: str) -> bytes:
        """Return the serialized field named by ``label`` when its width is known."""

        if not isinstance(label, str) or label not in self.placements or label not in self.widths:
            raise BuildError("slice requires a known placement with a recorded width")
        start = self.placements[label]
        return self.payload[start:start + self.widths[label]]

    def as_dict(self) -> dict[str, object]:
        """JSON-friendly representation with stable key order at the leaves."""

        return {
            "payload_hex": self.payload.hex(),
            "length": len(self.payload),
            "placements": dict(self.placements),
            "widths": dict(self.widths),
            "architecture": self.architecture,
            "strategy": self.strategy,
            "base_address": self.base_address,
            "metadata": dict(self.metadata),
        }


def ensure_uint(value: int, bits: int, *, name: str) -> int:
    """Validate an unsigned caller-supplied address/immediate."""

    if isinstance(bits, bool) or not isinstance(bits, int) or not 1 <= bits <= 64:
        raise BuildError("bits must be an integer in 1..64")
    if isinstance(value, bool) or not isinstance(value, int):
        raise BuildError(f"{name} must be an integer")
    if not 0 <= value < (1 << bits):
        raise BuildError(f"{name} does not fit in {bits} bits")
    return value


def reject_bad_bytes(payload: bytes, bad_bytes: object = ()) -> tuple[int, ...]:
    """Validate a bounded iterable of forbidden octets and reject collisions."""

    if not isinstance(payload, (bytes, bytearray)):
        raise BuildError("payload must be bytes")
    try:
        octets: set[int] = set()
        for index, value in enumerate(bad_bytes):
            if index >= 256:
                raise BuildError("bad_bytes must contain at most 256 octets")
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
                raise BuildError("bad_bytes values must be integer octets")
            octets.add(value)
        values = tuple(sorted(octets))
    except BuildError:
        raise
    except (TypeError, ValueError, OverflowError) as exc:
        raise BuildError("bad_bytes must be an iterable of octets") from exc
    hit = sorted(set(payload).intersection(values))
    if hit:
        rendered = ", ".join(f"0x{value:02x}" for value in hit)
        raise BuildError(f"payload contains forbidden bytes: {rendered}")
    return values
