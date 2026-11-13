#!/usr/bin/env python3
"""Passive parsers for public Link 22, VMF, and JREAP-C structures.

This module deliberately stops at the public boundary.  It classifies normalized
72-bit Link 22 Tactical Message Words, decodes the public
MIL-STD-2045-47001D/E VMF application-header prefix, and inventories the legacy
public MIL-STD-3011 JREAP application header.  Current MIL-STD-6022,
MIL-STD-6017F, and MIL-STD-3011E message bodies are distribution controlled;
opaque fields below are not a claim of current-standard conformance.

``msb0`` and ``lsb0`` describe the supplied *normalized container*: logical bit
zero is respectively the most- or least-significant bit of its first octet.
Link 22 RF/network-packet framing, encryption, EDAC, and byte serialization are
outside this parser.  "SLCP" has no verified public Link 22 layout and is not
guessed here.

Public layout references:
* NILE PMO, Link 22 Familiarization, IDLS 2009 (F/FJ decision tree and ONCS)
* MIL-STD-2045-47001D with Change 1 and MIL-STD-2045-47001E
* A. Jede, Kommunikationsprotokolle fuer taktische Datenlinks, figs. 9.4/9.9
  (a public description derived from the distribution-controlled 3011:2002)
"""
from __future__ import annotations

import argparse
import functools
import json
import math
from pathlib import Path
import statistics
import sys


MAX_INPUT = 1024 * 1024
MAX_LINK22_WORDS = 8
MAX_OBSERVATIONS = 100_000
MAX_JREAP_BLOCKS = 4096


class SecTdlLink22Error(ValueError):
    """Malformed, unsupported, ambiguous, or over-limit supplied artifact."""


def _closed(function):
    """Translate implementation/stdlib failures at every public entry point."""
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecTdlLink22Error:
            raise
        except Exception as exc:
            raise SecTdlLink22Error(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from None
    return wrapper


def _bytes(value, label="input", maximum=MAX_INPUT):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecTdlLink22Error(f"{label} must be bytes-like")
    size = value.nbytes if isinstance(value, memoryview) else len(value)
    if size > maximum:
        raise SecTdlLink22Error(f"{label} exceeds {maximum}-byte limit")
    return bytes(value)


def _container_bits(raw, packing):
    if packing == "msb0":
        return "".join(f"{octet:08b}" for octet in raw)
    if packing == "lsb0":
        return "".join(f"{octet:08b}"[::-1] for octet in raw)
    raise SecTdlLink22Error("packing must be msb0 or lsb0")


def _j_common_header(logical_bits):
    """Classify the public 70-bit J-series common header in logical-bit order."""
    if len(logical_bits) != 70 or set(logical_bits) - {"0", "1"}:
        raise SecTdlLink22Error("invalid normalized J-series information word")
    value = sum((bit == "1") << index for index, bit in enumerate(logical_bits))
    form = value & 3
    names = {0: "initial", 1: "continuation", 2: "extension", 3: "reserved"}
    result = {
        "value_hex": f"{value:018x}",
        "word_format": form,
        "word_kind": names[form],
    }
    if form == 0:
        label = (value >> 2) & 31
        sublabel = (value >> 7) & 7
        result.update({
            "label": label,
            "sublabel": sublabel,
            "message": f"J{label}.{sublabel}",
            "message_length_indicator": (value >> 10) & 7,
        })
    elif form == 1:
        result["continuation_label"] = (value >> 2) & 31
    return result


@_closed
def parse_link22_words(data, packing="msb0"):
    """Classify one to eight normalized 72-bit Link 22 tactical words.

    Only the public Series Indicator / Packed Message Indicator decision tree
    is decoded.  Unique-F contents and packed J-series contents remain opaque.
    """
    raw = _bytes(data, maximum=MAX_LINK22_WORDS * 9)
    if len(raw) % 9:
        raise SecTdlLink22Error("truncated 72-bit Link 22 word")
    count = len(raw) // 9
    if not 1 <= count <= MAX_LINK22_WORDS:
        raise SecTdlLink22Error("a Link 22 message must contain 1..8 words")
    if packing not in ("msb0", "lsb0"):
        raise SecTdlLink22Error("packing must be msb0 or lsb0")

    words = []
    for index in range(count):
        container = raw[index * 9:(index + 1) * 9]
        bits = _container_bits(container, packing)
        series = int(bits[0])
        item = {
            "index": index,
            "raw_hex": container.hex(),
            "series_indicator": series,
        }
        if series == 0:
            item.update(
                kind="unique_f_series",
                packed_message_indicator=None,
                opaque_payload_bits=bits[1:],
                opaque_payload_bit_count=71,
            )
        else:
            packed = int(bits[1])
            item.update(
                packed_message_indicator=packed,
                kind="packed_j_series" if packed == 0 else "reserved",
                opaque_payload_bits=bits[2:],
                opaque_payload_bit_count=70,
            )
            if packed == 0:
                item["j_series_common_header"] = _j_common_header(bits[2:])
        words.append(item)
    return {
        "profile": "public-link22-tmw-classifier",
        "packing": packing,
        "word_count": count,
        "words": words,
        "current_message_body_standard_controlled": True,
        "limitations": [
            "normalized 72-bit words only; no RF, network packet, EDAC, or crypto",
            "F/FJ body fields are opaque",
            "SLCP layout not verified in public material",
        ],
    }


@_closed
def analyze_network_cycle(observations):
    """Infer recurrence from supplied normalized ``timestamp``/``unit`` rows.

    The result is an observation, not an ONCS decoder: public material describes
    ONCS inputs but does not publish a current network-management wire layout.
    """
    if type(observations) not in (list, tuple):
        raise SecTdlLink22Error("observations must be a list or tuple")
    if not 2 <= len(observations) <= MAX_OBSERVATIONS:
        raise SecTdlLink22Error(f"expected 2..{MAX_OBSERVATIONS} observations")
    grouped = {}
    normalized = []
    for index, row in enumerate(observations):
        if not isinstance(row, dict):
            raise SecTdlLink22Error(f"observation {index} must be an object")
        if "timestamp" not in row or "unit" not in row:
            raise SecTdlLink22Error(f"observation {index} lacks timestamp/unit")
        timestamp = row["timestamp"]
        unit = row["unit"]
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise SecTdlLink22Error(f"observation {index} timestamp is not numeric")
        timestamp = float(timestamp)
        if not math.isfinite(timestamp) or timestamp < 0:
            raise SecTdlLink22Error(f"observation {index} timestamp is invalid")
        if not isinstance(unit, str) or not unit or len(unit) > 128:
            raise SecTdlLink22Error(f"observation {index} unit is invalid")
        grouped.setdefault(unit, []).append(timestamp)
        normalized.append((timestamp, unit))

    origin = min(timestamp for timestamp, _unit in normalized)
    unit_results = []
    medians = []
    for unit in sorted(grouped):
        times = sorted(grouped[unit])
        if any(right <= left for left, right in zip(times, times[1:])):
            raise SecTdlLink22Error(f"unit {unit!r} has duplicate timestamps")
        intervals = [right - left for left, right in zip(times, times[1:])]
        if any(not math.isfinite(delta) or delta <= 0 for delta in intervals):
            raise SecTdlLink22Error(f"unit {unit!r} recurrence interval is invalid")
        result = {
            "unit": unit,
            "normalized_timestamps": [value - origin for value in times],
            "intervals_seconds": intervals,
        }
        if intervals:
            median = float(statistics.median(intervals))
            result["median_recurrence_seconds"] = median
            medians.append(median)
        unit_results.append(result)
    if not medians:
        raise SecTdlLink22Error("no unit has two observations")
    estimate = float(statistics.median(medians))
    deltas = [delta for result in unit_results for delta in result["intervals_seconds"]]
    if not math.isfinite(estimate):
        raise SecTdlLink22Error("inferred recurrence is not finite")
    jitter = max(abs(delta - estimate) for delta in deltas)
    if not math.isfinite(jitter):
        raise SecTdlLink22Error("inferred recurrence jitter is not finite")
    return {
        "profile": "observed-link22-cycle",
        "observation_count": len(observations),
        "time_origin": origin,
        "inferred_cycle_seconds": estimate,
        "maximum_absolute_jitter_seconds": jitter,
        "units": unit_results,
        "wire_layout_decoded": False,
    }


class _LsbReader:
    def __init__(self, raw, bit_length=None):
        self.raw = raw
        if bit_length is None:
            bit_length = len(raw) * 8
        if type(bit_length) is not int or not 0 <= bit_length <= len(raw) * 8:
            raise SecTdlLink22Error("invalid bit length")
        self.limit = bit_length
        self.at = 0

    @property
    def remaining(self):
        return self.limit - self.at

    def take(self, width, name):
        if type(width) is not int or width < 0 or self.at + width > self.limit:
            raise SecTdlLink22Error(f"truncated {name}")
        offset = self.at
        value = 0
        for shift in range(width):
            value |= ((self.raw[self.at // 8] >> (self.at % 8)) & 1) << shift
            self.at += 1
        return value, offset

    def skip(self, width, name):
        self.take(width, name)


_HEADER_VERSIONS = {
    3: "MIL-STD-2045-47001D",
    4: "MIL-STD-2045-47001D Change 1",
    5: "MIL-STD-2045-47001E",
}
_UDMF = {
    0: "Link 16",
    1: "binary file",
    2: "Variable Message Format (VMF)",
    3: "NITFS",
    4: "redistributed ALPDU",
    5: "USMTF",
    6: "disused",
    7: "XML-MTF",
    8: "Variable Message Format Markup Language (VML)",
}
_VMF_STANDARD = {
    0: "VMF TIDP-TE R2", 1: "VMF TIDP-TE R3", 2: "VMF TIDP-TE R4",
    3: "VMF TIDP-TE R5", 4: "VMF TIDP-FTE R6", 5: "MIL-STD-6017",
    6: "MIL-STD-6017A", 7: "MIL-STD-6017B", 8: "MIL-STD-6017C",
    9: "MIL-STD-6017D", 10: "MIL-STD-6017E",
    11: "reserved", 12: "reserved", 13: "reserved", 14: "reserved",
    15: "use User Data Message Version",
}
_FAD = {
    0: "network control", 1: "general information", 2: "fire support",
    3: "air operations", 4: "intelligence", 5: "land operations",
    6: "maritime operations", 7: "combat service support",
    8: "special operations", 9: "joint task force operations",
    10: "air defense/airspace control",
}


def _field(reader, fields, name, width, dfi, dui, items=None):
    value, offset = reader.take(width, name)
    item = {
        "name": name, "dfi": dfi, "dui": dui, "bit_offset": offset,
        "width_bits": width, "value": value,
    }
    if items is not None:
        item["data_item"] = items.get(value, "undefined")
    fields.append(item)
    return value


def _indicator(reader, fields, name, dfi, dui):
    return _field(reader, fields, name, 1, dfi, dui)


def _unit_name(reader, fields, label):
    offset = reader.at
    chars = []
    for _index in range(64):
        value, _offset = reader.take(7, label)
        if value == 127:
            break
        chars.append(chr(value))
    decoded = "".join(chars)
    fields.append({
        "name": label,
        "dfi": 6010,
        "dui": 13,
        "bit_offset": offset,
        "width_bits": reader.at - offset,
        "value": decoded,
    })
    return decoded


def _address(reader, fields, label):
    result = {}
    if _indicator(reader, fields, f"{label} URN FPI", 4014, 2):
        result["urn"] = _field(
            reader, fields, f"{label} URN", 24, 4004, 12
        )
    if _indicator(reader, fields, f"{label} Unit Name FPI", 4014, 2):
        result["unit_name"] = _unit_name(reader, fields, f"{label} Unit Name")
    return result


def _address_group(reader, fields, label, maximum):
    if not _indicator(reader, fields, f"{label} GPI", 4014, 1):
        return []
    values = []
    for index in range(maximum):
        more = _indicator(reader, fields, f"{label} GRI", 4045, 1)
        values.append(_address(reader, fields, f"{label} {index + 1}"))
        if not more:
            return values
    if more:
        raise SecTdlLink22Error(f"{label} exceeds {maximum} occurrences")
    return values


def _skip_future_group(reader, fields, number):
    present = _indicator(
        reader, fields, f"Future Use Group {number} GPI", 4014, 1
    )
    if present:
        size = _field(
            reader, fields, f"Future Use Group {number} size", 12, 6005, 4
        )
        reader.skip(size, f"Future Use Group {number} contents")


@_closed
def parse_vmf_header_prefix(data, bit_length=None):
    """Decode the public D/D-Change-1/E application-header prefix.

    Bit fields are joined LSB first as specified by 2045-47001.  Parsing stops
    immediately after the optional VMF FAD/message/subtype identification;
    message-handling remainder and MIL-STD-6017 body stay opaque.
    """
    raw = _bytes(data)
    if not raw:
        raise SecTdlLink22Error("empty VMF application header")
    reader = _LsbReader(raw, bit_length)
    fields = []
    version = _field(reader, fields, "HEADER VERSION", 4, 6001, 6,
                     _HEADER_VERSIONS)
    if not 3 <= version <= 14:
        raise SecTdlLink22Error("only public D-or-later compatible header layout is supported")
    compression = None
    if _indicator(reader, fields, "DATA COMPRESSION TYPE FPI", 4014, 2):
        compression = _field(
            reader, fields, "DATA COMPRESSION TYPE", 2, 6001, 10
        )

    originators = []
    if _indicator(reader, fields, "Originator Address GPI", 4014, 1):
        originators.append(_address(reader, fields, "Originator"))
    recipients = _address_group(reader, fields, "Recipient Address", 16)
    information = _address_group(
        reader, fields, "Information Address", 16 - len(recipients)
    )
    header_size = None
    if _indicator(reader, fields, "HEADER SIZE FPI", 4014, 2):
        header_size = _field(reader, fields, "HEADER SIZE", 16, 6005, 3)
    for number in range(1, 6):
        _skip_future_group(reader, fields, number)

    more_groups = _indicator(
        reader, fields, "User Data Message Handling GRI", 4045, 1
    )
    udmf = _field(reader, fields, "USER DATA MESSAGE FORMAT", 4, 6001, 12, _UDMF)
    standard_version = None
    if _indicator(
        reader, fields, "USER DATA MESSAGE STANDARD VERSION FPI", 4014, 2
    ):
        standard_version = _field(
            reader, fields, "USER DATA MESSAGE STANDARD VERSION", 4,
            6001, 11, _VMF_STANDARD if udmf in (2, 8) else None,
        )
    vmf_identification = None
    if _indicator(reader, fields, "VMF Message Identification GPI", 4014, 1):
        fad = _field(reader, fields, "FUNCTIONAL AREA DESIGNATOR", 4,
                     4081, 1, _FAD)
        number = _field(reader, fields, "MESSAGE NUMBER", 7, 4085, 19)
        subtype = None
        if _indicator(reader, fields, "VMF MESSAGE SUBTYPE FPI", 4014, 2):
            subtype = _field(reader, fields, "VMF MESSAGE SUBTYPE", 7,
                             6001, 13)
        vmf_identification = {
            "fad": fad, "functional_area": _FAD.get(fad, "undefined"),
            "message_number": number,
            "message": f"K{fad}.{number}",
            "message_subtype": subtype,
        }
    return {
        "profile": "MIL-STD-2045-47001D/E-public-prefix",
        "header_version": version,
        "header_version_name": _HEADER_VERSIONS.get(version, "undefined future version"),
        "compression_type": compression,
        "originators": originators,
        "recipients": recipients,
        "information_addressees": information,
        "header_size": header_size,
        "more_message_handling_groups": bool(more_groups),
        "user_data_message_format": udmf,
        "user_data_message_format_name": _UDMF.get(udmf, "undefined"),
        "message_standard_version": standard_version,
        "vmf_identification": vmf_identification,
        "dfi_dui_fields": fields,
        "prefix_bits_consumed": reader.at,
        "remaining_bits_opaque": reader.remaining,
        "mil_std_6017_body_decoded": False,
        "current_mil_std_6017f_controlled": True,
    }


_JREAP_TYPES = {
    0: "management", 1: "J-series", 2: "coded free text",
    3: "uncoded free text", 4: "VMF", 5: "Link 22",
    6: "CMF/IBS",
}


def _parse_jreap_exact(raw):
    if len(raw) < 10:
        raise SecTdlLink22Error("truncated 10-byte JREAP application header")
    header_type = raw[0] >> 4
    message_type = raw[0] & 0x0F
    ttr = raw[1] >> 7
    spare = (raw[1] >> 4) & 0x07
    version = raw[1] & 0x0F
    block_length = int.from_bytes(raw[2:4], "big")
    if header_type != 3:
        raise SecTdlLink22Error("not a JREAP application-layer (header type 3) block")
    if spare:
        raise SecTdlLink22Error("nonzero JREAP application-header spare bits")
    if block_length < 10:
        raise SecTdlLink22Error("invalid JREAP application block length")
    if block_length != len(raw):
        raise SecTdlLink22Error("JREAP application block length mismatch")
    sender = int.from_bytes(raw[4:6], "big")
    time_word = int.from_bytes(raw[6:10], "big")
    accuracy = time_word >> 28
    payload = raw[10:]
    result = {
        "profile": "legacy-public-MIL-STD-3011-application-block",
        "header_type": header_type,
        "message_type": message_type,
        "message_type_name": _JREAP_TYPES.get(message_type, "reserved/extension"),
        "transmission_time_reference": bool(ttr),
        "application_protocol_version": version,
        "application_block_length": block_length,
        "sender_id": sender,
        "time_accuracy_code": accuracy,
        "time_accuracy_milliseconds": None if accuracy == 0 else 1 << (accuracy - 1),
        "data_valid_time_seconds": time_word & 0x0FFFFFFF,
        "payload_hex": payload.hex(),
        "current_mil_std_3011e_controlled": True,
    }
    if message_type == 1 and version == 1:
        messages = []
        offset = 0
        while offset < len(payload):
            if len(payload) - offset < 8:
                raise SecTdlLink22Error("truncated legacy J-series envelope")
            source = int.from_bytes(payload[offset:offset + 2], "big")
            sequence = int.from_bytes(payload[offset + 2:offset + 4], "big")
            flags_age = int.from_bytes(payload[offset + 4:offset + 6], "big")
            reserved_octet = payload[offset + 6]
            word_count = payload[offset + 7]
            if flags_age & 0x2000 or reserved_octet:
                raise SecTdlLink22Error("nonzero legacy J-series spare bits")
            if not 1 <= word_count <= 255:
                raise SecTdlLink22Error("legacy J-series envelope has no words")
            record_end = offset + 8 + 9 * word_count
            if record_end > len(payload):
                raise SecTdlLink22Error("legacy J-series word count/length mismatch")
            message = {
                "payload_offset": offset,
                "source_track_number": source,
                "message_sequence_number": sequence,
                "r_flag": bool(flags_age & 0x8000),
                "a_flag": bool(flags_age & 0x4000),
                "data_age": flags_age & 0x1FFF,
                "word_count": word_count,
                "words_hex": [
                    payload[word_at:word_at + 9].hex()
                    for word_at in range(offset + 8, record_end, 9)
                ],
            }
            messages.append(message)
            offset = record_end
        if not messages:
            raise SecTdlLink22Error("legacy J-series application block has no messages")
        result["j_series_message_count"] = len(messages)
        result["j_series_messages"] = messages
        # Preserve a concise singular view for the overwhelmingly common case.
        if len(messages) == 1:
            result["j_series"] = {
                key: value for key, value in messages[0].items()
                if key != "payload_offset"
            }
    return result


@_closed
def parse_jreap_c_block(data):
    """Parse one exact legacy-public JREAP-C application block."""
    return _parse_jreap_exact(_bytes(data, maximum=65535))


@_closed
def parse_jreap_c_stream(data):
    """Split a supplied TCP byte stream using the public 16-bit block length."""
    raw = _bytes(data)
    if not raw:
        raise SecTdlLink22Error("empty JREAP-C stream")
    blocks = []
    offset = 0
    while offset < len(raw):
        if len(blocks) >= MAX_JREAP_BLOCKS:
            raise SecTdlLink22Error("too many JREAP blocks")
        if len(raw) - offset < 10:
            raise SecTdlLink22Error("truncated JREAP block at end of stream")
        length = int.from_bytes(raw[offset + 2:offset + 4], "big")
        if length < 10 or offset + length > len(raw):
            raise SecTdlLink22Error("invalid/truncated JREAP stream block length")
        block = _parse_jreap_exact(raw[offset:offset + length])
        block["stream_offset"] = offset
        blocks.append(block)
        offset += length
    return {"profile": "JREAP-C-TCP-stream", "block_count": len(blocks), "blocks": blocks}


def _read(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise SecTdlLink22Error("input exceeds 1 MiB limit")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description="Passive public Link 22/VMF/JREAP-C decoder")
    sub = parser.add_subparsers(dest="mode", required=True)
    link = sub.add_parser("link22", help="classify normalized 72-bit tactical words")
    link.add_argument("file", type=Path)
    link.add_argument("--packing", choices=("msb0", "lsb0"), default="msb0")
    cycle = sub.add_parser("cycle", help="analyze supplied JSON timestamp/unit rows")
    cycle.add_argument("file", type=Path)
    vmf = sub.add_parser("vmf", help="decode a public VMF application-header prefix")
    vmf.add_argument("file", type=Path)
    vmf.add_argument("--bits", type=int)
    jreap = sub.add_parser("jreap", help="decode supplied JREAP-C application bytes")
    jreap.add_argument("file", type=Path)
    jreap.add_argument("--stream", action="store_true", help="split a TCP stream")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        raw = _read(args.file)
        if args.mode == "link22":
            result = parse_link22_words(raw, args.packing)
        elif args.mode == "cycle":
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise SecTdlLink22Error(f"invalid cycle JSON: {exc}") from None
            if isinstance(value, dict) and "observations" in value:
                value = value["observations"]
            result = analyze_network_cycle(value)
        elif args.mode == "vmf":
            result = parse_vmf_header_prefix(raw, args.bits)
        else:
            result = parse_jreap_c_stream(raw) if args.stream else parse_jreap_c_block(raw)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, SecTdlLink22Error, ValueError) as exc:
        print(f"sec_tdl_link22: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
