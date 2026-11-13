"""Dictionary-driven decoding of presence/recurrence-indicator bit messages (helper of schema_bundle, B-159).

VMF K-series bodies (MIL-STD-6017) are bit strings whose layout is a per-message table of fields,
each optionally preceded by a presence indicator (FPI for a field, GPI for a group) and a recurrence
indicator (FRI / GRI). The standard is not publicly distributed, so no message table is shipped here.
This module is the interpreter: an operator who holds the standard transcribes one message into a
JSON dictionary in the schema bundle, and `decode` reads a body against it.

Dictionary (every key is checked; an unknown key is a BitDictionaryError):

    {"message": "K99.9", "title": "...", "edition": "...",
     "fields": [
        {"name": "Originator", "bits": 24},
        {"name": "Speed", "bits": 11, "presence": true, "codes": {"2047": "no statement"}},
        {"name": "Remark", "type": "text7", "max_chars": 20, "presence": true},
        {"name": "Waypoint", "presence": true, "repeat": 4, "fields": [
            {"name": "Latitude", "bits": 25}, {"name": "Longitude", "bits": 26}]}]}

    bits       a fixed-width unsigned field (1..64)
    type       "uint" (default) or "text7": 7-bit characters ended by 0x7F or by max_chars
    presence   true: one indicator bit comes first, 0 = the field or group is absent
    repeat     N > 1: each occurrence is preceded by a recurrence bit, 1 = another follows; at most N
    fields     makes the entry a group
    codes      {"value": "meaning"} labels for a uint field

Bit order is the one the carried VMF header reader uses (sec_tdl_link22): octets in order, the least
significant bit of each octet first, a field's first bit its least significant. `bit_order: "msb0"`
in the dictionary selects most-significant-bit-first for formats that pack that way.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

MAX_DICT_BYTES = 1 << 20
MAX_INPUT = 1 << 20
MAX_FIELDS = 20_000
MAX_DEPTH = 16

__all__ = ["BitDictionaryError", "BitDecodeError", "load_dictionary", "check_dictionary", "decode"]

_TOP = {"message", "title", "edition", "bit_order", "fields", "note"}
_ENTRY = {"name", "bits", "type", "presence", "repeat", "fields", "codes", "max_chars", "note"}


class BitDictionaryError(ValueError):
    """The message dictionary is missing a key, has an unknown one, or states something impossible."""


class BitDecodeError(ValueError):
    """The body is truncated or leaves bits behind."""


def _check_entries(entries: Any, where: str, depth: int, count: list[int]) -> None:
    if not isinstance(entries, list) or not entries:
        raise BitDictionaryError(f"{where}: fields must be a non-empty list")
    if depth > MAX_DEPTH:
        raise BitDictionaryError(f"{where}: groups nest deeper than {MAX_DEPTH}")
    for index, entry in enumerate(entries):
        here = f"{where}[{index}]"
        if not isinstance(entry, dict):
            raise BitDictionaryError(f"{here}: an entry must be an object")
        unknown = sorted(set(entry) - _ENTRY)
        if unknown:
            raise BitDictionaryError(f"{here}: unknown key(s) {', '.join(unknown)}")
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise BitDictionaryError(f"{here}: name must be a non-empty string")
        here = f"{where}[{index}] {name!r}"
        count[0] += 1
        if count[0] > MAX_FIELDS:
            raise BitDictionaryError(f"the dictionary lists more than {MAX_FIELDS} entries")
        if "presence" in entry and type(entry["presence"]) is not bool:
            raise BitDictionaryError(f"{here}: presence must be true or false")
        repeat = entry.get("repeat", 1)
        if type(repeat) is not int or not 1 <= repeat <= 4096:
            raise BitDictionaryError(f"{here}: repeat must be an integer 1..4096")
        if "fields" in entry:
            extra = sorted(set(entry) & {"bits", "type", "codes", "max_chars"})
            if extra:
                raise BitDictionaryError(f"{here}: a group cannot also set {', '.join(extra)}")
            _check_entries(entry["fields"], f"{here}.fields", depth + 1, count)
            continue
        kind = entry.get("type", "uint")
        if kind == "uint":
            bits = entry.get("bits")
            if type(bits) is not int or not 1 <= bits <= 64:
                raise BitDictionaryError(f"{here}: bits must be an integer 1..64")
            if "max_chars" in entry:
                raise BitDictionaryError(f"{here}: max_chars belongs to a text7 field")
            codes = entry.get("codes", {})
            if not isinstance(codes, dict) or not all(
                    isinstance(k, str) and k.isdigit() and isinstance(v, str) for k, v in codes.items()):
                raise BitDictionaryError(f"{here}: codes must map decimal strings to strings")
        elif kind == "text7":
            limit = entry.get("max_chars")
            if type(limit) is not int or not 1 <= limit <= 4096:
                raise BitDictionaryError(f"{here}: a text7 field needs max_chars 1..4096")
            if "bits" in entry or "codes" in entry:
                raise BitDictionaryError(f"{here}: a text7 field takes max_chars, not bits or codes")
        else:
            raise BitDictionaryError(f"{here}: type must be 'uint' or 'text7', not {kind!r}")


def check_dictionary(spec: Any, src: str = "dictionary") -> dict:
    """`spec` when it is a well-formed message dictionary, else BitDictionaryError naming the entry."""
    if not isinstance(spec, dict):
        raise BitDictionaryError(f"{src}: the dictionary must be a JSON object")
    unknown = sorted(set(spec) - _TOP)
    if unknown:
        raise BitDictionaryError(f"{src}: unknown key(s) {', '.join(unknown)}")
    if not isinstance(spec.get("message"), str) or not spec["message"]:
        raise BitDictionaryError(f"{src}: message must be a non-empty string")
    if spec.get("bit_order", "lsb0") not in ("lsb0", "msb0"):
        raise BitDictionaryError(f"{src}: bit_order must be 'lsb0' or 'msb0'")
    _check_entries(spec.get("fields"), f"{src}: fields", 0, [0])
    return spec


def load_dictionary(path: Path | str) -> dict:
    path = Path(path)
    if not path.is_file():
        raise BitDictionaryError(f"message dictionary {path} is missing")
    if path.stat().st_size > MAX_DICT_BYTES:
        raise BitDictionaryError(f"message dictionary {path} is larger than {MAX_DICT_BYTES} bytes")
    try:
        spec = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BitDictionaryError(f"message dictionary {path} is not JSON: {exc}") from None
    return check_dictionary(spec, str(path))


class _Reader:
    def __init__(self, data: bytes, bit_length: int | None, order: str):
        self.data, self.msb = data, order == "msb0"
        self.limit = len(data) * 8 if bit_length is None else bit_length
        self.at = 0

    def take(self, width: int, what: str) -> int:
        if self.at + width > self.limit:
            raise BitDecodeError(f"body ends inside {what} (bit {self.at} of {self.limit})")
        value = 0
        for index in range(width):
            octet, bit = self.data[self.at // 8], self.at % 8
            if self.msb:
                value = (value << 1) | ((octet >> (7 - bit)) & 1)
            else:
                value |= ((octet >> bit) & 1) << index
            self.at += 1
        return value


def _leaf(entry: dict, reader: _Reader, path: str, out: list[dict]) -> Any:
    start = reader.at
    if entry.get("type", "uint") == "text7":
        chars = []
        for _ in range(entry["max_chars"]):
            code = reader.take(7, path)
            if code == 0x7F:
                break
            chars.append(chr(code))
        value: Any = "".join(chars)
        row = {"path": path, "bit_offset": start, "width_bits": reader.at - start, "value": value}
    else:
        value = reader.take(entry["bits"], path)
        row = {"path": path, "bit_offset": start, "width_bits": entry["bits"], "value": value}
        label = entry.get("codes", {}).get(str(value))
        if label is not None:
            row["meaning"] = label
    out.append(row)
    return value


def _entries(entries: list, reader: _Reader, prefix: str, out: list[dict]) -> dict:
    values: dict[str, Any] = {}
    for entry in entries:
        name = entry["name"]
        path = f"{prefix}/{name}" if prefix else name
        group = "fields" in entry
        if entry.get("presence"):
            start = reader.at
            present = reader.take(1, f"{path} presence indicator")
            out.append({"path": path, "indicator": "GPI" if group else "FPI", "bit_offset": start, "value": present})
            if not present:
                continue
        limit = entry.get("repeat", 1)
        items = []
        while True:
            more = 0
            if limit > 1:
                start = reader.at
                more = reader.take(1, f"{path} recurrence indicator")
                out.append({"path": path, "indicator": "GRI" if group else "FRI", "bit_offset": start, "value": more})
            here = f"{path}[{len(items)}]" if limit > 1 else path
            items.append(_entries(entry["fields"], reader, here, out) if group else _leaf(entry, reader, here, out))
            if not more:
                break
            if len(items) >= limit:
                raise BitDecodeError(f"{path} recurs more than the dictionary's {limit} occurrences")
        values[name] = items if limit > 1 else items[0]
    return values


def decode(data: bytes, spec: dict, *, bit_length: int | None = None, allow_trailing: bool = False) -> dict:
    """Read `data` against the checked dictionary `spec`.

    Returns {"message", "values": nested {name: value | [..] | {..}}, "fields": [rows in wire order:
    path, bit_offset, width_bits, value, meaning? | indicator rows], "bits_consumed", "padding_bits"}.
    Bits left over that are not zero fill to the octet are a BitDecodeError unless allow_trailing."""
    check_dictionary(spec)
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise BitDecodeError("input must be bytes")
    data = bytes(data)
    if not data or len(data) > MAX_INPUT:
        raise BitDecodeError(f"input must hold 1..{MAX_INPUT} bytes")
    if bit_length is not None and (type(bit_length) is not int or not 0 < bit_length <= len(data) * 8):
        raise BitDecodeError("bit_length is outside the input")
    reader = _Reader(data, bit_length, spec.get("bit_order", "lsb0"))
    rows: list[dict] = []
    values = _entries(spec["fields"], reader, "", rows)
    consumed, left = reader.at, reader.limit - reader.at
    if not allow_trailing and (left >= 8 or (left and reader.take(left, "padding"))):
        raise BitDecodeError(f"{left} bit(s) follow the last field and are not zero fill to the octet")
    return {"message": spec["message"], "edition": spec.get("edition"), "values": values, "fields": rows,
            "bits_consumed": consumed, "padding_bits": left}
