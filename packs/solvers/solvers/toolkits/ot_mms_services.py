#!/usr/bin/env python3
"""Bounded offline ISO 9506 MMS, X.227 ACSE and X.226 presentation decoder.

Input is one complete definite-length BER PDU (or TPKT/COTP DT containing it).
The semantic coverage is named variables/lists/types, status/identify, information
reports, journal and file services, association setup, and normal presentation.
All standard service choices 0..77 have schema decoders; companion-specific
extensions retain raw evidence. No requests are sent and file paths are never opened.

BER lengths and primitive trees reuse network_ics_depth. Its one-octet-tag
restriction requires a small identifier adapter for journal/file service tags.
All public parsing entrypoints raise MMSParseError on invalid/unsupported input.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps
import json
import math
from pathlib import Path
import re
import struct

import network_ics_depth as _ber


class MMSParseError(ValueError):
    """Malformed, unsupported, ambiguous, or over-budget offline MMS input."""


MAX_INPUT = min(4 << 20, _ber.MAX_INPUT)
MAX_NODES = min(8192, _ber.MAX_BER)
MAX_DEPTH = 32
MMS_SYNTAX = "1.0.9506.2.1"
ACSE_SYNTAX = "2.2.1.0.1"
BER_SYNTAX = "2.1.1"

_SERVICE_NAMES = (
    "status get_name_list identify rename read write get_variable_access_attributes "
    "define_named_variable define_scattered_access get_scattered_access_attributes "
    "delete_variable_access define_named_variable_list get_named_variable_list_attributes "
    "delete_named_variable_list define_named_type get_named_type_attributes delete_named_type "
    "input output take_control relinquish_control define_semaphore delete_semaphore "
    "report_semaphore_status report_pool_semaphore_status report_semaphore_entry_status "
    "initiate_download_sequence download_segment terminate_download_sequence "
    "initiate_upload_sequence upload_segment terminate_upload_sequence request_domain_download "
    "request_domain_upload load_domain_content store_domain_content delete_domain "
    "get_domain_attributes create_program_invocation delete_program_invocation start stop "
    "resume reset kill get_program_invocation_attributes obtain_file define_event_condition "
    "delete_event_condition get_event_condition_attributes report_event_condition_status "
    "alter_event_condition_monitoring trigger_event define_event_action delete_event_action "
    "get_event_action_attributes report_event_action_status define_event_enrollment "
    "delete_event_enrollment alter_event_enrollment report_event_enrollment_status "
    "get_event_enrollment_attributes acknowledge_event_notification get_alarm_summary "
    "get_alarm_enrollment_summary read_journal write_journal initialize_journal "
    "report_journal_status create_journal delete_journal get_capability_list file_open "
    "file_read file_close file_rename file_delete file_directory"
).split()
_DATA_NAMES = {1: "array", 2: "structure", 3: "boolean", 4: "bit_string", 5: "integer",
               6: "unsigned", 7: "floating_point", 8: "real", 9: "octet_string",
               10: "visible_string", 11: "generalized_time", 12: "binary_time", 13: "bcd",
               14: "boolean_array", 15: "object_identifier", 16: "mms_string", 17: "utc_time"}
_ACCESS_ERRORS = ("object_invalidated hardware_fault temporarily_unavailable object_access_denied "
                  "object_undefined invalid_address type_unsupported type_inconsistent "
                  "object_attribute_inconsistent object_access_unsupported object_non_existent "
                  "object_value_invalid").split()


def _guard(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except MMSParseError:
            raise
        except Exception as exc:
            raise MMSParseError(f"invalid {fn.__name__} input: {type(exc).__name__}") from exc
    return wrapped


def _blob(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise MMSParseError("input must be a byte buffer")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if not 0 < size <= MAX_INPUT:
        raise MMSParseError("empty or oversized PDU")
    return bytes(data)


def _node(data, offset, end, depth, budget):
    """High-tag identifier adapter; shared parser owns definite BER lengths."""
    if depth > MAX_DEPTH or budget[0] <= 0 or offset >= end:
        raise MMSParseError("BER nesting/node/header limit")
    budget[0] -= 1
    first, at = data[offset], offset + 1
    number = first & 31
    if number == 31:
        number = 0
        for index in range(4):
            if at >= end or (index == 0 and data[at] & 127 == 0):
                raise MMSParseError("invalid high-tag BER identifier")
            octet = data[at]
            at += 1
            number = (number << 7) | (octet & 127)
            if not octet & 128:
                break
        else:
            raise MMSParseError("BER tag exceeds four octets")
        if number < 31:
            raise MMSParseError("nonminimal high-tag BER identifier")
    # _tlv reads the octet immediately before the length as its single-byte tag.
    # For a high tag this is the final identifier octet; its returned tag is ignored.
    row = _ber._tlv(data, at - 1, end)
    if row is None or first == 0:
        raise MMSParseError("invalid definite BER length/value")
    _, start, stop, next_offset = row
    node = {"tag": first, "number": number, "class": first >> 6,
            "constructed": bool(first & 32), "raw": data[start:stop],
            "encoded": data[offset:stop]}
    if first & 32:
        children = []
        while start < stop:
            child, start = _node(data, start, stop, depth + 1, budget)
            children.append(child)
        node["children"] = children
    else:
        if first in (2, 10) and stop - start > 16:
            raise MMSParseError("oversized ASN.1 integer")
        # Shared primitive BER decoding (semantic decoders use raw bytes so an
        # ASCII-looking signed INTEGER never becomes a guessed string).
        leaf = _ber._ber_tree(data, at - 1, end, depth, [1])
        if leaf is not None and "value" in leaf:
            node["ber_value"] = leaf["value"]
    return node, next_offset


def _tree(data):
    node, end = _node(data, 0, len(data), 0, [MAX_NODES])
    if end != len(data):
        raise MMSParseError("trailing bytes after BER PDU")
    return node


def _is(node, number, cls=2, constructed=None):
    return (node["class"] == cls and node["number"] == number and
            (constructed is None or node["constructed"] == constructed))


def _expect(node, number, cls=2, constructed=None):
    if not _is(node, number, cls, constructed):
        raise MMSParseError(f"expected ASN.1 class {cls} tag {number}")
    return node


def _children(node):
    if not node["constructed"]:
        raise MMSParseError("expected constructed BER value")
    return node["children"]


def _one(node):
    children = _children(node)
    if len(children) != 1:
        raise MMSParseError("explicit wrapper must contain one value")
    return children[0]


def _fields(node, required=(), allowed=None):
    out = {}
    for child in _children(node):
        n = child["number"]
        if child["class"] != 2 or n in out or (allowed is not None and n not in allowed):
            raise MMSParseError("duplicate, unexpected or non-context field")
        out[n] = child
    if any(n not in out for n in required):
        raise MMSParseError("missing mandatory field")
    return out


def _primitive(node):
    if node["constructed"]:
        raise MMSParseError("expected primitive value")
    return node["raw"]


def _int(node, signed=True, bits=32):
    raw = _primitive(node)
    if not raw or len(raw) > bits // 8 + 1:
        raise MMSParseError("invalid INTEGER length")
    value = int.from_bytes(raw, "big", signed=True)
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    if not lo <= value <= hi:
        raise MMSParseError("INTEGER out of range")
    return value


def _bool(node):
    raw = _primitive(node)
    if len(raw) != 1:
        raise MMSParseError("BOOLEAN must have one octet")
    return raw != b"\0"


def _null(node):
    if _primitive(node):
        raise MMSParseError("NULL must be empty")
    return None


def _text(node, utf8=False):
    raw = _primitive(node)
    if len(raw) > 65536:
        raise MMSParseError("text exceeds semantic size limit")
    text = raw.decode("utf-8" if utf8 else "ascii")
    if not utf8 and any(ord(c) < 32 or ord(c) > 126 for c in text):
        raise MMSParseError("invalid VisibleString/GraphicString")
    return text


def _oid(node):
    raw = _primitive(node)
    if not raw or len(raw) > 256:
        raise MMSParseError("invalid OBJECT IDENTIFIER")
    values, value, count = [], 0, 0
    for octet in raw:
        if count == 0 and octet == 128:
            raise MMSParseError("nonminimal OID subidentifier")
        value = (value << 7) | (octet & 127)
        count += 1
        if count > 16:
            raise MMSParseError("OID subidentifier too large")
        if not octet & 128:
            values.append(value)
            value, count = 0, 0
    if count or not values:
        raise MMSParseError("truncated OBJECT IDENTIFIER")
    head = values.pop(0)
    first = min(head // 40, 2)
    return ".".join(map(str, [first, head - first * 40] + values))


def _bits(node):
    raw = _primitive(node)
    if not raw or raw[0] > 7 or (len(raw) == 1 and raw[0]) or (raw[0] and raw[-1] & ((1 << raw[0]) - 1)):
        raise MMSParseError("invalid BIT STRING padding")
    return {"hex": raw[1:].hex(), "unused_bits": raw[0], "bit_length": (len(raw) - 1) * 8 - raw[0]}


def _time(node):
    raw = _primitive(node)
    if len(raw) not in (4, 6):
        raise MMSParseError("TimeOfDay must contain four or six octets")
    ms = int.from_bytes(raw[:4], "big")
    if ms >= 86400000:
        raise MMSParseError("TimeOfDay milliseconds exceed one day")
    out = {"milliseconds": ms}
    if len(raw) == 6:
        days = int.from_bytes(raw[4:], "big")
        out.update(days_since_1984=days, iso=(datetime(1984, 1, 1, tzinfo=timezone.utc) +
                                           timedelta(days=days, milliseconds=ms)).isoformat())
    return out


def _object(node):
    if _is(node, 0, constructed=False) or _is(node, 2, constructed=False):
        return {"scope": "vmd" if node["number"] == 0 else "aa", "identifier": _text(node)}
    _expect(node, 1, constructed=True)
    parts = _children(node)
    if len(parts) != 2:
        raise MMSParseError("domain ObjectName needs domain and item")
    return {"scope": "domain", "domain_id": _text(_expect(parts[0], 26, 0, False)),
            "item_id": _text(_expect(parts[1], 26, 0, False))}


def _address(node):
    if _is(node, 0, constructed=False):
        return {"kind": "numeric", "value": _int(node, False)}
    if _is(node, 1, constructed=False):
        return {"kind": "symbolic", "value": _text(node)}
    _expect(node, 2, constructed=False)
    return {"kind": "unconstrained", "value": _primitive(node).hex()}


def _alternate(node):
    out = []
    for child in _children(node):
        n = child["number"]
        if child["class"] != 2:
            raise MMSParseError("invalid AlternateAccess choice")
        if n == 5:
            parts = _children(child)
            if len(parts) != 2:
                raise MMSParseError("named alternate access needs two fields")
            out.append({"name": _text(_expect(parts[0], 0)), "selection": _selection(parts[1])})
        else:
            out.append(_selection(child))
    return out


def _selection(node, nested=False):
    if node["class"] != 2:
        raise MMSParseError("AlternateAccess selection must be context-specific")
    n = node["number"]
    if not nested and n == 0:
        parts = _children(node)
        if len(parts) != 2:
            raise MMSParseError("selectAlternateAccess requires selection and tail")
        _expect(parts[1], 16, 0, True)
        return {"selection": _selection(parts[0], True), "alternate_access": _alternate(parts[1])}
    shift = 0 if nested else 1
    if n == shift:
        return {"component": _text(node)}
    if n == shift + 1:
        return {"index": _int(node, False)}
    if n == shift + 2:
        f = _fields(node, (0, 1), (0, 1))
        return {"low_index": _int(f[0], False), "number_of_elements": _int(f[1], False)}
    if n == shift + 3:
        _null(node)
        return {"all_elements": True}
    raise MMSParseError("unknown AlternateAccess selection")


def _variable_spec(spec):
    if _is(spec, 0):
        return {"name": _object(_one(spec))}
    if _is(spec, 1):
        return {"address": _address(_one(spec))}
    if _is(spec, 2):
        p = _children(spec)
        if len(p) != 2:
            raise MMSParseError("invalid variableDescription")
        return {"address": _address(p[0]), "type_specification": _type(p[1])}
    if _is(spec, 3):
        return {"scattered_access": _scattered(spec)}
    if _is(spec, 4):
        _null(spec)
        return {"invalidated": True}
    raise MMSParseError("unknown VariableSpecification")


def _variables(node):
    out = []
    for entry in _children(node):
        parts = _children(_expect(entry, 16, 0, True))
        if not 1 <= len(parts) <= 2:
            raise MMSParseError("invalid variable-list entry")
        row = _variable_spec(parts[0])
        if len(parts) == 2:
            row["alternate_access"] = _alternate(_expect(parts[1], 5, constructed=True))
        out.append(row)
    return out


def _access(node):
    if _is(node, 0, constructed=True):
        return {"kind": "list_of_variable", "variables": _variables(node)}
    _expect(node, 1, constructed=True)
    return {"kind": "variable_list_name", "name": _object(_one(node))}


def _type(node):
    if node["class"] != 2:
        raise MMSParseError("type specification must be a context choice")
    n = node["number"]
    if n == 0:
        return {"type": "type_name", "name": _object(_one(node))}
    if n == 1:
        f = _fields(node, (1, 2), (0, 1, 2))
        return {"type": "array", "packed": _bool(f[0]) if 0 in f else False,
                "number_of_elements": _int(f[1], False), "element_type": _type(_one(f[2]))}
    if n == 2:
        f = _fields(node, (1,), (0, 1))
        components = []
        for component in _children(f[1]):
            c = _fields(_expect(component, 16, 0, True), (1,), (0, 1))
            item = {"type_specification": _type(_one(c[1]))}
            if 0 in c:
                item["name"] = _text(c[0])
            components.append(item)
        return {"type": "structure", "packed": _bool(f[0]) if 0 in f else False, "components": components}
    if n not in _DATA_NAMES:
        raise MMSParseError("unsupported TypeSpecification")
    out = {"type": _DATA_NAMES[n]}
    if n in (3, 11, 15, 17):
        _null(node)
    elif n == 12:
        out["date_included"] = _bool(node)
    elif n in (5, 6, 13):
        out["width"] = _int(node, False, 8)
    elif n in (4, 9, 10):
        out["size"] = _int(node)
    elif n == 16:
        # libiec61850 uses IMPLICIT Integer32; the 2003/61850 ASN.1 published
        # by ABB/EPFL uses an EXPLICIT Integer32. Both encountered variants
        # have the same semantics, with the wrapper validated when present.
        value = _expect(_one(node), 2, 0, False) if node["constructed"] else node
        out["size"] = _int(value)
    elif n == 7:
        parts = _children(node)
        if len(parts) != 2:
            raise MMSParseError("floating-point type requires format and exponent widths")
        out.update(format_width=_int(_expect(parts[0], 2, 0, False), False, 8),
                   exponent_width=_int(_expect(parts[1], 2, 0, False), False, 8))
    else:
        raise MMSParseError("unsupported TypeSpecification")
    return out


def _real(node):
    """X.690 8.5 REAL, bounded to binary64 finite output plus named specials."""
    raw = _primitive(node)
    if not raw:
        return 0.0
    if len(raw) > 256:
        raise MMSParseError("REAL exceeds numeric size budget")
    first = raw[0]
    if first in (0x40, 0x41, 0x42, 0x43):
        if len(raw) != 1:
            raise MMSParseError("special REAL must have one octet")
        return {0x40: "inf", 0x41: "-inf", 0x42: "nan", 0x43: -0.0}[first]
    if first & 128:
        base = (first >> 4) & 3
        if base == 3:
            raise MMSParseError("reserved binary REAL base")
        count, start = (first & 3) + 1, 1
        if count == 4:
            if len(raw) < 2:
                raise MMSParseError("missing REAL exponent size")
            count, start = raw[1], 2
        if not 1 <= count <= 4 or start + count >= len(raw):
            raise MMSParseError("invalid REAL exponent or missing mantissa")
        encoded_exponent = raw[start:start + count]
        if start == 2 and count > 1 and ((encoded_exponent[0] == 0 and encoded_exponent[1] < 128) or
                                       (encoded_exponent[0] == 255 and encoded_exponent[1] >= 128)):
            raise MMSParseError("nonminimal long REAL exponent")
        exponent = int.from_bytes(encoded_exponent, "big", signed=True)
        mantissa_bytes = raw[start + count:]
        if len(mantissa_bytes) > 64:
            raise MMSParseError("REAL mantissa exceeds numeric size budget")
        mantissa = int.from_bytes(mantissa_bytes, "big")
        if not mantissa:
            raise MMSParseError("binary REAL zero must use empty content")
        exponent = exponent * (1, 3, 4)[base] + ((first >> 2) & 3)
        if not -16384 <= exponent <= 16384:
            raise MMSParseError("REAL exponent exceeds numeric size budget")
        value = math.ldexp(float(-mantissa if first & 64 else mantissa), exponent)
    elif first in (1, 2, 3):
        text = raw[1:].decode("ascii")
        patterns = {
            1: r" *[+-]?[0-9]+ *",
            2: r" *[+-]?(?:[0-9]+[.,][0-9]*|[.,][0-9]+) *",
            3: r" *[+-]?(?:[0-9]+(?:[.,][0-9]*)?|[.,][0-9]+)[Ee][+-]?[0-9]+ *",
        }
        if re.fullmatch(patterns[first], text) is None:
            raise MMSParseError("invalid decimal REAL representation")
        decimal = Decimal(text.strip().replace(",", "."))
        if not decimal:
            raise MMSParseError("decimal REAL zero must use empty content")
        value = float(decimal)
    else:
        raise MMSParseError("reserved REAL representation")
    if not math.isfinite(value) or value == 0:
        raise MMSParseError("finite REAL outside binary64 output range")
    return value


def _data(node):
    if node["class"] != 2 or node["number"] not in _DATA_NAMES:
        raise MMSParseError("invalid MMS Data choice")
    n, raw = node["number"], node["raw"]
    out = {"type": _DATA_NAMES[n]}
    if n in (1, 2):
        value = [_data(c) for c in _children(node)]
    elif n == 3:
        value = _bool(node)
    elif n in (4, 14):
        value = _bits(node)
    elif n in (5, 6, 13):
        value = _int(node, n not in (6, 13), 64)
    elif n == 7:
        _primitive(node)
        if len(raw) == 5 and raw[0] == 8:
            value = struct.unpack(">f", raw[1:])[0]
        elif len(raw) == 9 and raw[0] == 11:
            value = struct.unpack(">d", raw[1:])[0]
        else:
            raise MMSParseError("unsupported MMS floating-point format")
        if not math.isfinite(value):
            value = str(value)
    elif n == 8:
        value = _real(node)
    elif n == 9:
        value = _primitive(node).hex()
    elif n in (10, 11, 16):
        value = _text(node, n == 16)
    elif n == 12:
        value = _time(node)
    elif n == 15:
        value = _oid(node)
    elif n == 17:
        _primitive(node)
        if len(raw) != 8:
            raise MMSParseError("UtcTime must have eight octets")
        seconds, fraction = int.from_bytes(raw[:4], "big"), int.from_bytes(raw[4:7], "big")
        value = {"seconds": seconds, "fraction": fraction, "fraction_denominator": 1 << 24,
                 "quality": raw[7], "leap_seconds_known": bool(raw[7] & 128),
                 "clock_failure": bool(raw[7] & 64), "clock_not_synchronized": bool(raw[7] & 32),
                 "time_accuracy": raw[7] & 31}
    out["value"] = value
    return out


def _results(node, write=False):
    out = []
    for child in _children(node):
        if _is(child, 0, constructed=False):
            value = _int(child, False, 8)
            out.append({"success": False, "error": value,
                        "error_name": _ACCESS_ERRORS[value] if value < len(_ACCESS_ERRORS) else "reserved"})
        elif write:
            _null(_expect(child, 1, constructed=False))
            out.append({"success": True})
        else:
            out.append({"success": True, "data": _data(child)})
    return out


def _filename(node):
    return [_text(_expect(c, 25, 0, False)) for c in _children(node)]


def _file_attributes(node):
    f = _fields(node, (0,), (0, 1))
    out = {"size_of_file": _int(f[0], False)}
    if 1 in f:
        out["last_modified"] = _text(f[1])
    return out


def _application(node):
    f = _fields(node, allowed=(0, 1, 2, 3))
    out = {}
    for n, child in f.items():
        value = _one(child)
        if n in (1, 3):
            parsed = _int(_expect(value, 2, 0, False))
        elif _is(value, 6, 0, False):
            parsed = _oid(value)
        elif _is(value, 2, 0, False):
            parsed = _int(value)
        else:
            parsed = {"raw_hex": value["encoded"].hex()}
        out[("ap_title", "ap_invocation_id", "ae_qualifier", "ae_invocation_id")[n]] = parsed
    return out


def _entry_content(node):
    f = _fields(node, (0,), (0, 1, 2, 3))
    if (2 in f) == (3 in f):
        raise MMSParseError("EntryContent needs exactly one entryForm")
    out = {"occurrence_time": _time(f[0])}
    if 1 in f:
        out["additional_detail_hex"] = f[1]["raw"].hex()
    if 3 in f:
        out["annotation"] = _text(f[3])
    else:
        d = _fields(f[2], allowed=(0, 1))
        if 0 in d:
            event = _fields(d[0], (0, 1), (0, 1))
            out["event"] = {"name": _object(_one(event[0])), "current_state": _int(event[1], False, 8)}
        if 1 in d:
            variables = []
            for row in _children(d[1]):
                v = _fields(_expect(row, 16, 0, True), (0, 1), (0, 1))
                variables.append({"tag": _text(v[0]), "data": _data(_one(v[1]))})
            out["variables"] = variables
    return out


def _journal(service, response, node):
    if response:
        if service in (66, 69, 70):
            _null(node)
            return {}
        if service == 67:
            return {"entries_deleted": _int(node, False)}
        if service == 68:
            f = _fields(node, (0, 1), (0, 1))
            return {"current_entries": _int(f[0], False), "mms_deletable": _bool(f[1])}
        f = _fields(node, (0,), (0, 1))
        entries = []
        for entry in _children(f[0]):
            j = _fields(_expect(entry, 16, 0, True), (0, 1, 2), (0, 1, 2))
            entries.append({"entry_identifier": _primitive(j[0]).hex(),
                            "originating_application": _application(_expect(_one(j[1]), 16, 0, True)),
                            "content": _entry_content(j[2])})
        return {"entries": entries, "more_follows": _bool(f[1]) if 1 in f else False}
    if service == 68:
        return {"journal_name": _object(_one(node))}
    allowed = {65: (0, 1, 2, 4, 5), 66: (0, 1), 67: (0, 1), 69: (0,), 70: (0,)}[service]
    f = _fields(node, (0, 1) if service == 66 else (0,), allowed)
    out = {"journal_name": _object(_one(f[0]))}
    if service == 66:
        out["entries"] = [_entry_content(_expect(c, 16, 0, True)) for c in _children(f[1])]
    elif service == 67 and 1 in f:
        limit = _fields(f[1], (0,), (0, 1))
        out["limit"] = {"time": _time(limit[0])}
        if 1 in limit:
            out["limit"]["entry"] = _primitive(limit[1]).hex()
    elif service == 65:
        for number, key in ((1, "range_start"), (2, "range_stop")):
            if number in f:
                choice = _one(f[number])
                if _is(choice, 0, constructed=False):
                    out[key] = {"time": _time(choice)}
                else:
                    _expect(choice, 1, constructed=False)
                    out[key] = ({"entry": _primitive(choice).hex()} if number == 1 else
                                {"number_of_entries": _int(choice)})
        if 4 in f:
            out["list_of_variables"] = [_text(_expect(c, 26, 0, False)) for c in _children(f[4])]
        if 5 in f:
            start = _fields(f[5], (0, 1), (0, 1))
            out["entry_to_start_after"] = {"time": _time(start[0]), "entry": _primitive(start[1]).hex()}
    return out


def _file(service, response, node):
    if response:
        if service in (46, 74, 75, 76):
            _null(node)
            return {}
        f = _fields(node, (0,), (0, 1))
        if service == 72:
            if 1 not in f:
                raise MMSParseError("fileOpen response lacks attributes")
            return {"frsm_id": _int(f[0]), "file_attributes": _file_attributes(f[1])}
        if service == 73:
            return {"file_data": _primitive(f[0]), "more_follows": _bool(f[1]) if 1 in f else True}
        sequence = _expect(_one(f[0]), 16, 0, True)
        entries = []
        for entry in _children(sequence):
            e = _fields(_expect(entry, 16, 0, True), (0, 1), (0, 1))
            entries.append({"file_name": _filename(e[0]), "file_attributes": _file_attributes(e[1])})
        return {"directory_entries": entries, "more_follows": _bool(f[1]) if 1 in f else False}
    if service in (73, 74):
        return {"frsm_id": _int(node)}
    if service == 76:
        return {"file_name": _filename(node)}
    required = {46: (1, 2), 72: (0, 1), 75: (0, 1), 77: ()}[service]
    f = _fields(node, required, (0, 1, 2) if service == 46 else (0, 1))
    if service == 72:
        return {"file_name": _filename(f[0]), "initial_position": _int(f[1], False)}
    if service == 75:
        return {"current_file_name": _filename(f[0]), "new_file_name": _filename(f[1])}
    if service == 46:
        out = {"source_file": _filename(f[1]), "destination_file": _filename(f[2])}
        if 0 in f:
            out["source_file_server"] = _application(f[0])
        return out
    return {key: _filename(f[n]) for n, key in ((0, "file_specification"), (1, "continue_after")) if n in f}


def _sequence(node, schema):
    """Decode a context-tagged SEQUENCE against named fields and defaults.

    A 3-tuple is required; a fourth value is a DEFAULT, with None meaning OPTIONAL.
    This is a schema walker, not a second BER parser: every node is already bound
    by the shared BER adapter's byte/node/depth limits.
    """
    f = _fields(node, [s[0] for s in schema if len(s) == 3], [s[0] for s in schema])
    out = {}
    for definition in schema:
        tag, name, decoder = definition[:3]
        if tag in f:
            out[name] = decoder(f[tag])
        elif len(definition) == 4 and definition[3] is not None:
            out[name] = definition[3]
    return out


def _seq_decoder(*schema):
    return lambda n: _sequence(n, schema)


def _explicit(decoder):
    return lambda n: decoder(_one(n))


def _list_decoder(decoder, sequence=False):
    return lambda n: [decoder(_expect(c, 16, 0, True) if sequence else c) for c in _children(n)]


def _u32(node):
    return _int(node, False)


def _u16(node):
    return _int(node, False, 16)


def _u8(node):
    return _int(node, False, 8)


def _strings(node):
    return [_text(_expect(c, 26, 0, False)) for c in _children(node)]


def _objx(node):
    return _object(_one(node))


def _appx(node):
    return _application(_expect(_one(node), 16, 0, True))


def _scattered(node):
    return _list_decoder(_seq_decoder(
        (0, "component_name", _text, None),
        (1, "variable_specification", _explicit(_variable_spec)),
        (2, "alternate_access", _alternate, None)), True)(node)


def _event_time(node):
    choice = _one(node)
    if _is(choice, 0, constructed=False):
        return {"time_of_day": _time(choice)}
    _expect(choice, 1, constructed=False)
    return {"sequence_identifier": _u32(choice)}


def _optional_object(node):
    choice = _one(node)
    if _is(choice, 0, constructed=True):
        return {"name": _objx(choice)}
    # MMS 2003 uses a direct ObjectName at some sites where older schemas used
    # an explicit eventCondition/undefined CHOICE. The encodings are distinct.
    if (_is(choice, 0, constructed=False) or _is(choice, 1, constructed=True)
            or _is(choice, 2, constructed=False)):
        return {"name": _object(choice)}
    _null(_expect(choice, 1, constructed=False))
    return {"undefined": True}


def _optional_variable(node):
    choice = _one(node)
    if _is(choice, 0, constructed=True):
        return {"variable_specification": _variable_spec(_one(choice))}
    _null(_expect(choice, 1, constructed=False))
    return {"undefined": True}


def _optional_state(node):
    choice = _one(node)
    if _is(choice, 0, constructed=False):
        return {"state": _u8(choice)}
    _null(_expect(choice, 1, constructed=False))
    return {"undefined": True}


def _load_data_response(node):
    parts = _children(node)
    if not 1 <= len(parts) <= 2:
        raise MMSParseError("segment response needs loadData and optional moreFollows")
    value = parts[0]
    if _is(value, 0, constructed=False):
        data = {"kind": "non_coded", "data": _primitive(value)}
    elif _is(value, 8, 0, True):
        data = {"kind": "coded", "external": _external(value, decode_embedded=False)}
    else:
        raise MMSParseError("invalid loadData choice")
    return {"load_data": data,
            "more_follows": _bool(_expect(parts[1], 1, constructed=False)) if len(parts) == 2 else True}


def _execution_argument(node):
    if _is(node, 1, constructed=False):
        return {"kind": "simple_string", "value": _text(node)}
    _expect(node, 8, 0, True)
    return {"kind": "encoded_string", "external": _external(node, decode_embedded=False)}


def _program_start(node):
    parts = _children(node)
    if not 1 <= len(parts) <= 2:
        raise MMSParseError("program start/resume needs name and optional argument")
    out = {"program_invocation_name": _text(_expect(parts[0], 0, constructed=False))}
    if len(parts) == 2:
        out["execution_argument"] = _execution_argument(parts[1])
    return out


def _program_attributes(node):
    # The ASN.1 has constructed [1] listOfDomainNames and a later primitive
    # [1] simple executionArgument. Validate their positions and construction.
    parts = _children(node)
    if not 6 <= len(parts) <= 7:
        raise MMSParseError("invalid program attributes fields")
    out = {}
    for child, (tag, name, decoder) in zip(parts[:6], (
            (0, "state", _u8), (1, "list_of_domain_names", _strings),
            (2, "mms_deletable", _bool), (3, "reusable", _bool),
            (4, "monitor", _bool), (5, "start_argument", _text))):
        out[name] = decoder(_expect(child, tag))
    if len(parts) == 7:
        out["execution_argument"] = _execution_argument(parts[6])
    return out


def _delete_event(node, action=False, enrollment=False):
    choice = _one(node)
    if _is(choice, 0, constructed=True):
        return {"scope": "specific", "names": [_object(c) for c in _children(choice)]}
    if enrollment:
        if _is(choice, 1, constructed=True) or _is(choice, 2, constructed=True):
            return {"scope": "event_condition" if choice["number"] == 1 else "event_action",
                    "name": _objx(choice)}
    else:
        if _is(choice, 1, constructed=False):
            _null(choice)
            return {"scope": "aa"}
        if _is(choice, 3 if action else 2, constructed=False):
            return {"scope": "domain", "domain_name": _text(choice)}
        if _is(choice, 4 if action else 3, constructed=False):
            _null(choice)
            return {"scope": "vmd"}
    raise MMSParseError("invalid delete-event scope choice")


def _modifier(node):
    if _is(node, 0, constructed=True):
        value = _sequence(node, (
            (0, "event_enrollment_name", _objx), (1, "event_condition_name", _objx),
            (2, "causing_transitions", _bits), (3, "acceptable_delay", _u32, None)))
        return {"kind": "attach_to_event_condition", **value}
    _expect(node, 1, constructed=True)
    value = _sequence(node, (
        (0, "semaphore_name", _objx), (1, "named_token", _text, None),
        (2, "priority", _u8, 64), (3, "acceptable_delay", _u32, None),
        (4, "control_time_out", _u32, None), (5, "abort_on_time_out", _bool, None),
        (6, "relinquish_if_connection_lost", _bool, True)))
    return {"kind": "attach_to_semaphore", **value}


def _nested_service(node, response=False):
    choice = _one(node)
    number = choice["number"]
    if choice["class"] != 2 or number >= len(_SERVICE_NAMES):
        raise MMSParseError("unknown nested MMS service")
    return {"service": {"number": number, "name": _SERVICE_NAMES[number]},
            "details": _service(number, response, choice)}


def _event_action_result(node):
    parts = _children(node)
    if len(parts) != 2:
        raise MMSParseError("actionResult needs event-action name and result")
    out = {"event_action_name": _object(parts[0])}
    if _is(parts[1], 0, constructed=True):
        out["success"] = _nested_service(parts[1], True)
    else:
        _expect(parts[1], 1, constructed=True)
        out["failure"] = _service_error(parts[1])
    return out


def _event_notification(node):
    return _sequence(node, (
        (0, "event_enrollment_name", _objx), (1, "event_condition_name", _optional_object),
        (2, "severity", _u8), (3, "current_state", _u8, None),
        (4, "transition_time", _event_time), (6, "notification_lost", _bool, False),
        (7, "alarm_acknowledgment_rule", _u8, None),
        (8, "action_result", _event_action_result, None)))


def _other_service(number, response, node):
    """Remaining standard ISO 9506 services, using explicit schema descriptors."""
    if response and number in (3, 8, 18, 20, 21, 22, 26, 28, 31, 32, 33, 34, 35, 36,
                               38, 39, 40, 41, 42, 43, 44, 47, 51, 52, 53, 57, 62):
        _null(node)
        return {}
    if number == 3:
        return _sequence(node, ((0, "object_class", lambda n: _u8(_expect(_one(n), 0))),
                                (1, "current_name", _objx), (2, "new_identifier", _text)))
    if number == 8:
        return _sequence(node, ((0, "scattered_access_name", _objx),
                                (1, "scattered_access_description", _scattered)))
    if number == 9:
        if not response:
            return {"scattered_access_name": _objx(node)}
        return _sequence(node, ((0, "mms_deletable", _bool),
                                (1, "scattered_access_description", _scattered)))
    if number == 17:
        if response:
            return {"input": _text(node)}
        return _sequence(node, ((0, "operator_station_name", _text), (1, "echo", _bool, True),
                                (2, "list_of_prompt_data", _strings, None), (3, "input_time_out", _u32, None)))
    if number == 18:
        return _sequence(node, ((0, "operator_station_name", _text), (1, "list_of_output_data", _strings)))
    if number == 19 and response:
        choice = _one(node)
        if _is(choice, 0, constructed=False):
            _null(choice)
            return {"no_result": True}
        return {"named_token": _text(_expect(choice, 1, constructed=False))}
    if number in (19, 20, 21) and not response:
        if number == 21:
            return _sequence(node, ((0, "semaphore_name", _objx), (1, "number_of_tokens", _u16)))
        schema = [(0, "semaphore_name", _objx), (1, "named_token", _text, None)]
        if number == 19:
            schema.extend(((2, "priority", _u8, 64), (3, "acceptable_delay", _u32, None),
                           (4, "control_time_out", _u32, None), (5, "abort_on_time_out", _bool, None),
                           (6, "relinquish_if_connection_lost", _bool, True),
                           (7, "application_to_preempt", _application, None)))
        return _sequence(node, schema)
    if number in (22, 23) and not response:
        return {"semaphore_name": _objx(node)}
    if number == 23:
        return _sequence(node, ((0, "mms_deletable", _bool), (1, "class", _u8),
                                (2, "number_of_tokens", _u16), (3, "number_of_owned_tokens", _u16),
                                (4, "number_of_hung_tokens", _u16)))
    if number in (24, 25):
        if not response:
            tail = ((1, "name_to_start_after", _text, None),) if number == 24 else (
                (1, "state", _u8), (2, "entry_id_to_start_after", _primitive, None))
            return _sequence(node, ((0, "semaphore_name", _objx),) + tail)
        if number == 24:
            def token(n):
                if n["class"] != 2 or n["number"] > 2:
                    raise MMSParseError("invalid named token state")
                return {"state": ("free", "owned", "hung")[n["number"]], "name": _text(n)}
            return _sequence(node, ((0, "list_of_named_tokens", _list_decoder(token)),
                                    (1, "more_follows", _bool, True)))
        entry = _seq_decoder((0, "entry_id", _primitive), (1, "entry_class", _u8),
                             (2, "application_reference", _appx), (3, "named_token", _text, None),
                             (4, "priority", _u8, 64), (5, "remaining_time_out", _u32, None),
                             (6, "abort_on_time_out", _bool, None),
                             (7, "relinquish_if_connection_lost", _bool, True))
        return _sequence(node, ((0, "list_of_semaphore_entry", _list_decoder(entry, True)),
                                (1, "more_follows", _bool, True)))
    if number == 26:
        return _sequence(node, ((0, "domain_name", _text), (1, "list_of_capabilities", _strings),
                                (2, "sharable", _bool)))
    if number in (27, 30) and response:
        return _load_data_response(node)
    if number in (27, 29, 36, 37) and not response:
        return {"domain_name": _text(node)}
    if number == 28:
        return _sequence(node, ((0, "domain_name", _text), (1, "discard", _service_error, None)))
    if number == 29:
        return _sequence(node, ((0, "ulsm_id", _int), (1, "list_of_capabilities", _strings)))
    if number in (30, 31):
        return {"ulsm_id": _int(node)}
    if number in (32, 34):
        schema = [(0, "domain_name", _text), (1, "list_of_capabilities", _strings, None),
                  (2, "sharable", _bool), (4, "file_name", _filename)]
        if number == 34:
            schema.append((5, "third_party", _application, None))
        return _sequence(node, schema)
    if number in (33, 35):
        schema = [(0, "domain_name", _text), (1, "file_name", _filename)]
        if number == 35:
            schema.append((2, "third_party", _application, None))
        return _sequence(node, schema)
    if number == 37:
        return _sequence(node, ((0, "list_of_capabilities", _strings), (1, "state", _u8),
                                (2, "mms_deletable", _bool), (3, "sharable", _bool),
                                (4, "list_of_program_invocations", _strings),
                                (5, "upload_in_progress", lambda n: _int(n, True, 8))))
    if number == 38:
        return _sequence(node, ((0, "program_invocation_name", _text), (1, "list_of_domain_name", _strings),
                                (2, "reusable", _bool, True), (3, "monitor_type", _bool, None)))
    if number in (39, 45) and not response:
        return {"program_invocation_name": _text(node)}
    if number in (40, 42):
        return _program_start(node)
    if number in (41, 43, 44):
        return _sequence(node, ((0, "program_invocation_name", _text),))
    if number == 45:
        return _program_attributes(node)
    if number in (47, 49):
        if number == 49 and not response:
            return {"event_condition_name": _objx(node)}
        schema = [(0, "mms_deletable", _bool, False)] if response else [(0, "event_condition_name", _objx)]
        schema.extend(((1, "class", _u8), (2, "priority", _u8, 64), (3, "severity", _u8, 64),
                       (4, "alarm_summary_reports", _bool, False if response else None),
                       (6, "monitored_variable", _optional_variable if response else _explicit(_variable_spec), None),
                       (7, "evaluation_interval", _u32, None)))
        return _sequence(node, schema)
    if number in (48, 54, 58):
        if response:
            return {"candidates_not_deleted": _u32(node)}
        return _delete_event(node, number == 54, number == 58)
    if number == 50:
        if not response:
            return {"event_condition_name": _objx(node)}
        return _sequence(node, ((0, "current_state", _u8), (1, "number_of_event_enrollments", _u32),
                                (2, "enabled", _bool, None),
                                (3, "time_of_last_transition_to_active", _event_time, None),
                                (4, "time_of_last_transition_to_idle", _event_time, None)))
    if number == 51:
        return _sequence(node, ((0, "event_condition_name", _objx), (1, "enabled", _bool, None),
                                (2, "priority", _u8, None), (3, "alarm_summary_reports", _bool, None),
                                (4, "evaluation_interval", _u32, None)))
    if number == 52:
        return _sequence(node, ((0, "event_condition_name", _objx), (1, "priority", _u8, None)))
    if number in (53, 55):
        if number == 55 and not response:
            return {"event_action_name": _objx(node)}
        schema = [(0, "mms_deletable", _bool, False),
                  (1, "list_of_modifier", _list_decoder(_modifier))] if response else [
                      (0, "event_action_name", _objx),
                      (1, "list_of_modifier", _list_decoder(_modifier), None)]
        # ISO 9506 confirmed-Service-Request is omitted by the old Wireshark
        # schema but retained by the complete ASN.1; decode when present.
        schema.append((2, "confirmed_service_request", _nested_service, None))
        return _sequence(node, schema)
    if number == 56:
        return {"number_of_event_enrollments": _u32(node)} if response else {"event_action_name": _objx(node)}
    if number == 57:
        return _sequence(node, ((0, "event_enrollment_name", _objx), (1, "event_condition_name", _objx),
                                (2, "event_condition_transition", _bits), (3, "alarm_acknowledgment_rule", _u8),
                                (4, "event_action_name", _objx, None), (5, "client_application", _appx, None)))
    if number == 59:
        if response:
            return _sequence(node, ((0, "current_state", _optional_state), (1, "transition_time", _event_time)))
        return _sequence(node, ((0, "event_enrollment_name", _objx),
                                (1, "event_condition_transitions", _bits, None),
                                (2, "alarm_acknowledgment_rule", _u8, None)))
    if number == 60:
        if not response:
            return {"event_enrollment_name": _objx(node)}
        return _sequence(node, ((0, "event_condition_transitions", _bits), (1, "notification_lost", _bool, False),
                                (2, "duration", _u8), (3, "alarm_acknowledgment_rule", _u8, None),
                                (4, "current_state", _u8)))
    if number == 61:
        if not response:
            return _sequence(node, ((0, "scope_of_request", _u8, 1),
                                    (1, "event_enrollment_names", _list_decoder(_object), None),
                                    (2, "client_application", _appx, None),
                                    (3, "event_condition_name", _objx, None),
                                    (4, "event_action_name", _objx, None), (5, "continue_after", _objx, None)))
        entry = _seq_decoder((0, "event_enrollment_name", _objx), (1, "event_condition_name", _optional_object),
                             (2, "event_action_name", _optional_object, None), (3, "client_application", _appx, None),
                             (4, "mms_deletable", _bool, False), (5, "enrollment_class", _u8),
                             (6, "duration", _u8, 0), (7, "invoke_id", _u32),
                             (8, "remaining_acceptable_delay", _u32, None))
        return _sequence(node, ((0, "list_of_event_enrollment", _list_decoder(entry, True)),
                                (1, "more_follows", _bool, False)))
    if number == 62:
        return _sequence(node, ((0, "event_enrollment_name", _objx), (2, "acknowledged_state", _u8),
                                (3, "time_of_acknowledged_transition", _event_time)))
    if number in (63, 64):
        if not response:
            severity = _seq_decoder((0, "most_severe", _u8), (1, "least_severe", _u8))
            return _sequence(node, ((0, "enrollments_only", _bool, True), (1, "active_alarms_only", _bool, True),
                                    (2, "acknowledgment_filter", _u8, 0), (3, "severity_filter", severity, None),
                                    (5, "continue_after", _objx, None)))
        if number == 63:
            entry = _seq_decoder((0, "event_condition_name", _objx), (1, "severity", _u8),
                                 (2, "current_state", _u8), (3, "unacknowledged_state", _u8),
                                 (5, "time_of_last_transition_to_active", _event_time, None),
                                 (6, "time_of_last_transition_to_idle", _event_time, None))
        else:
            entry = _seq_decoder((0, "event_enrollment_name", _objx), (2, "client_application", _appx, None),
                                 (3, "severity", _u8), (4, "current_state", _u8),
                                 (6, "notification_lost", _bool, False), (7, "alarm_acknowledgment_rule", _u8, None),
                                 (8, "enrollment_state", _u8, None),
                                 (9, "time_of_last_transition_to_active", _event_time, None),
                                 (10, "time_active_acknowledged", _event_time, None),
                                 (11, "time_of_last_transition_to_idle", _event_time, None),
                                 (12, "time_idle_acknowledged", _event_time, None))
        name = "list_of_alarm_summary" if number == 63 else "list_of_alarm_enrollment_summary"
        return _sequence(node, ((0, name, _list_decoder(entry, True)), (1, "more_follows", _bool, False)))
    raise MMSParseError("unsupported standard MMS service")


def _service(number, response, node, unconfirmed=False):
    if unconfirmed:
        if number == 0:
            children = _children(node)
            if len(children) != 2:
                raise MMSParseError("informationReport requires specification and results")
            return {"variable_access": _access(children[0]),
                    "access_results": _results(_expect(children[1], 0, constructed=True))}
        if number == 1:
            number, response = 0, True
        else:
            return _event_notification(node)
    if number in range(65, 71):
        return _journal(number, response, node)
    if number in (46, 72, 73, 74, 75, 76, 77):
        return _file(number, response, node)
    if number == 0:
        if not response:
            return {"extended_derivation": _bool(node)}
        f = _fields(node, (0, 1), (0, 1, 2))
        out = {"logical_status": _int(f[0], False, 8), "physical_status": _int(f[1], False, 8)}
        if 2 in f:
            out["local_detail"] = _bits(f[2])
        return out
    if number == 1:
        if response:
            f = _fields(node, (0,), (0, 1))
            return {"identifiers": [_text(_expect(c, 26, 0, False)) for c in _children(f[0])],
                    "more_follows": _bool(f[1]) if 1 in f else True}
        f = _fields(node, (0, 1), (0, 1, 2))
        scope = _one(f[1])
        if _is(scope, 1, constructed=False):
            obj_scope = {"scope": "domain", "domain_id": _text(scope)}
        elif _is(scope, 0, constructed=False) or _is(scope, 2, constructed=False):
            _null(scope)
            obj_scope = {"scope": "vmd" if scope["number"] == 0 else "aa"}
        else:
            raise MMSParseError("invalid ObjectScope")
        out = {"object_class": _int(_expect(_one(f[0]), 0, constructed=False), False, 8), "object_scope": obj_scope}
        if 2 in f:
            out["continue_after"] = _text(f[2])
        return out
    if number == 2:
        if not response:
            _null(node)
            return {}
        f = _fields(node, (0, 1, 2), (0, 1, 2, 3))
        out = {"vendor": _text(f[0]), "model": _text(f[1]), "revision": _text(f[2])}
        if 3 in f:
            out["abstract_syntaxes"] = [_oid(_expect(c, 6, 0, False)) for c in _children(f[3])]
        return out
    if number == 4:
        f = _fields(node, (1,), (0, 1))
        if not response:
            return {"specification_with_result": _bool(f[0]) if 0 in f else False,
                    "variable_access": _access(_one(f[1]))}
        out = {"access_results": _results(f[1])}
        if 0 in f:
            out["variable_access"] = _access(_one(f[0]))
        return out
    if number == 5:
        if response:
            return {"access_results": _results(node, True)}
        children = _children(node)
        if len(children) != 2:
            raise MMSParseError("write needs variable access and listOfData")
        return {"variable_access": _access(children[0]),
                "data": [_data(c) for c in _children(_expect(children[1], 0, constructed=True))]}
    if number == 6:
        if not response:
            choice = _one(node)
            if _is(choice, 0, constructed=True):
                return {"name": _object(_one(choice))}
            _expect(choice, 1, constructed=True)
            return {"address": _address(_one(choice))}
        f = _fields(node, (0, 2), (0, 1, 2))
        out = {"mms_deletable": _bool(f[0]), "type_specification": _type(_one(f[2]))}
        if 1 in f:
            out["address"] = _address(_one(f[1]))
        return out
    if number == 7:
        if response:
            _null(node)
            return {}
        f = _fields(node, (0, 1), (0, 1, 2))
        out = {"name": _object(_one(f[0])), "address": _address(_one(f[1]))}
        if 2 in f:
            out["type_specification"] = _type(_one(f[2]))
        return out
    if number in (10, 13, 16):
        f = _fields(node, (0, 1) if response else (), (0, 1) if response else (0, 1, 2))
        if response:
            return {"number_matched": _int(f[0], False), "number_deleted": _int(f[1], False)}
        out = {"scope_of_delete": _int(f[0], False, 8) if 0 in f else 0}
        if 1 in f:
            out["names"] = [_object(c) for c in _children(f[1])]
        if 2 in f:
            out["domain_name"] = _text(f[2])
        return out
    if number in (11, 14):
        if response:
            _null(node)
            return {}
        parts = _children(node)
        if len(parts) != 2:
            raise MMSParseError("definition requires name and specification")
        if number == 11:
            return {"name": _object(parts[0]), "variables": _variables(_expect(parts[1], 0, constructed=True))}
        return {"name": _object(parts[0]), "type_specification": _type(parts[1])}
    if number in (12, 15):
        if not response:
            return {"name": _object(_one(node))}
        if number == 12:
            f = _fields(node, (0, 1), (0, 1))
            return {"mms_deletable": _bool(f[0]), "variables": _variables(f[1])}
        parts = _children(node)
        if len(parts) != 2:
            raise MMSParseError("named type response needs deletable and type")
        return {"mms_deletable": _bool(_expect(parts[0], 0)), "type_specification": _type(parts[1])}
    if number == 71:
        if not response:
            parts = _children(node)
            if len(parts) > 1:
                raise MMSParseError("GetCapabilityList has at most one continuation")
            return {"continue_after": _text(_expect(parts[0], 26, 0, False))} if parts else {}
        f = _fields(node, (0,), (0, 1))
        if response:
            return {"capabilities": [_text(_expect(c, 26, 0, False)) for c in _children(f[0])],
                    "more_follows": _bool(f[1]) if 1 in f else True}
    return _other_service(number, response, node)


def _service_error(node):
    f = _fields(node, (0,), (0, 1, 2, 3))
    choice = _one(f[0])
    if choice["class"] != 2 or choice["number"] > 12:
        raise MMSParseError("invalid ServiceError class")
    out = {"error_class": choice["number"], "code": _int(choice)}
    if 1 in f:
        out["additional_code"] = _int(f[1])
    if 2 in f:
        out["additional_description"] = _text(f[2])
    if 3 in f:
        out["service_specific_hex"] = f[3]["raw"].hex()
        choice = _one(f[3])
        names = ("obtain_file", "start", "stop", "resume", "reset", "delete_variable_access",
                 "delete_named_variable_list", "delete_named_type", "define_event_enrollment",
                 "file_rename", "additional_service", "change_access_control")
        number = choice["number"]
        if choice["class"] != 2 or number >= len(names):
            raise MMSParseError("unknown service-specific error choice")
        value = (_objx(choice) if number == 8 else {"encoded_hex": choice["encoded"].hex()}
                 if number == 10 else _u32(choice))
        out["service_specific_information"] = {"service": names[number], "value": value}
    return out


def _mms(node):
    n = node["number"]
    if node["class"] != 2 or not 0 <= n <= 13:
        raise MMSParseError("not an MMS PDU")
    pdus = ("confirmed_request", "confirmed_response", "confirmed_error", "unconfirmed", "reject",
            "cancel_request", "cancel_response", "cancel_error", "initiate_request", "initiate_response",
            "initiate_error", "conclude_request", "conclude_response", "conclude_error")
    out = {"protocol": "mms", "pdu": pdus[n], "invoke_id": None}
    if n in (0, 1, 3):
        parts = list(_children(node))
        if n != 3:
            if not parts:
                raise MMSParseError("missing invoke ID")
            out["invoke_id"] = _int(_expect(parts.pop(0), 2, 0, False), False)
        if n == 0 and parts and _is(parts[0], 16, 0, True):
            modifiers = parts.pop(0)
            out["modifiers_hex"] = modifiers["raw"].hex()
            out["modifiers"] = [_modifier(c) for c in _children(modifiers)]
        if not parts or parts[0]["class"] != 2:
            raise MMSParseError("missing MMS service choice")
        service = parts.pop(0)
        number = service["number"]
        if parts:
            if len(parts) != 1 or not _is(parts[0], 79):
                raise MMSParseError("unexpected field after MMS service")
            out["companion_detail_hex"] = parts[0]["raw"].hex()
        if n == 3:
            names = ("information_report", "unsolicited_status", "event_notification")
        else:
            names = _SERVICE_NAMES
        if number >= len(names):
            raise MMSParseError("unknown MMS service number")
        out["service"] = {"number": number, "name": names[number]}
        out["details"] = _service(number, n == 1, service, n == 3)
    elif n in (8, 9):
        f = _fields(node, (1, 2, 4), (0, 1, 2, 3, 4))
        d = _fields(f[4], (0, 1, 2), (0, 1, 2))
        out["details"] = {"max_outstanding_calling": _int(f[1], True, 16),
                          "max_outstanding_called": _int(f[2], True, 16),
                          "version": _int(d[0], True, 16), "parameter_cbb": _bits(d[1]),
                          "services_supported": _bits(d[2])}
        if 0 in f:
            out["details"]["local_detail"] = _int(f[0])
        if 3 in f:
            out["details"]["nesting_level"] = _int(f[3], True, 8)
    elif n in (2, 7):
        f = _fields(node, (0, 2) if n == 2 else (0, 1), (0, 1, 2) if n == 2 else (0, 1))
        out["invoke_id"] = _int(f[0], False)
        out["details"] = _service_error(f[2 if n == 2 else 1])
        if n == 2 and 1 in f:
            out["details"]["modifier_position"] = _int(f[1], False)
    elif n in (10, 13):
        out["details"] = _service_error(node)
    elif n in (5, 6):
        out["invoke_id"] = _int(node, False)
        out["details"] = {}
    elif n in (11, 12):
        _null(node)
        out["details"] = {}
    elif n == 4:
        f = _fields(node, allowed=range(12))
        reason = [c for k, c in f.items() if k != 0]
        if len(reason) != 1:
            raise MMSParseError("reject requires exactly one reason")
        if 0 in f:
            out["invoke_id"] = _int(f[0], False)
        out["details"] = {"reason_class": reason[0]["number"], "reason": _int(reason[0])}
    return out


def _embedded(node, syntax=None):
    if syntax == MMS_SYNTAX:
        return {"mms": _mms(node)}
    if syntax == ACSE_SYNTAX:
        return {"acse": _acse(node)}
    if syntax is not None:
        return {"raw_hex": node["encoded"].hex(), "schema": "unknown_abstract_syntax"}
    if node["class"] == 2 and node["number"] <= 13:
        return {"mms": _mms(node)}
    if node["class"] == 1 and node["number"] <= 4:
        return {"acse": _acse(node)}
    return {"raw_hex": node["encoded"].hex(), "schema": "opaque"}


def _external(node, decode_embedded=True):
    parts = list(_children(_expect(node, 8, 0, True)))
    out = {}
    if parts and _is(parts[0], 6, 0, False):
        out["direct_reference"] = _oid(parts.pop(0))
    if parts and _is(parts[0], 2, 0, False):
        out["indirect_reference"] = _int(parts.pop(0))
    if parts and _is(parts[0], 7, 0, False):
        out["descriptor"] = _text(parts.pop(0))
    if len(parts) != 1:
        raise MMSParseError("EXTERNAL needs one encoding choice")
    choice = parts[0]
    if _is(choice, 0, constructed=True):
        out["encoding"] = "single_asn1_type"
        # EXTERNAL direct-reference identifies a transfer syntax (commonly BER),
        # not the MMS abstract syntax; the enclosed PDU is structurally decoded.
        reference = out.get("direct_reference")
        embedded = _one(choice)
        if not decode_embedded:
            out["encoded_hex"] = embedded["encoded"].hex()
        elif reference in (None, BER_SYNTAX):
            out.update(_embedded(embedded))
        elif reference in (MMS_SYNTAX, ACSE_SYNTAX):
            out.update(_embedded(embedded, reference))
        else:
            out.update(raw_hex=embedded["encoded"].hex(), schema="unknown_external_reference")
    elif _is(choice, 1, constructed=False):
        out.update(encoding="octet_aligned", raw_hex=_primitive(choice).hex())
    elif _is(choice, 2, constructed=False):
        out.update(encoding="arbitrary", value=_bits(choice))
    else:
        raise MMSParseError("invalid EXTERNAL encoding")
    return out


def _acse(node):
    n = node["number"]
    if node["class"] != 1 or n > 4 or not node["constructed"]:
        raise MMSParseError("not a supported ACSE APDU")
    names = ("aarq", "aare", "rlrq", "rlre", "abrt")
    f = _fields(node, (1,) if n == 0 else (1, 2, 3) if n == 1 else (0,) if n == 4 else ())
    out = {"protocol": "acse", "pdu": names[n], "user_information": []}
    handled = {30}
    if n in (0, 1):
        handled.update((0, 1, 29))
        out["application_context"] = _oid(_expect(_one(f[1]), 6, 0, False))
        if 0 in f:
            out["protocol_version"] = _bits(f[0])
        mapping = ({2: "called_ap_title", 3: "called_ae_qualifier", 4: "called_ap_invocation_id",
                    5: "called_ae_invocation_id", 6: "calling_ap_title", 7: "calling_ae_qualifier",
                    8: "calling_ap_invocation_id", 9: "calling_ae_invocation_id"} if n == 0 else
                   {4: "responding_ap_title", 5: "responding_ae_qualifier", 6: "responding_ap_invocation_id",
                    7: "responding_ae_invocation_id"})
        for tag, name in mapping.items():
            if tag in f:
                value = _one(f[tag])
                out[name] = (_oid(value) if _is(value, 6, 0, False) else
                             _int(value) if _is(value, 2, 0, False) else
                             {"raw_hex": value["encoded"].hex()})
        handled.update(mapping)
        req, mechanism, auth = (10, 11, 12) if n == 0 else (8, 9, 10)
        handled.update((req, mechanism, auth))
        if req in f:
            out["acse_requirements"] = _bits(f[req])
        if mechanism in f:
            out["mechanism_name"] = _oid(f[mechanism])
        if auth in f:
            value = _one(f[auth])
            if _is(value, 0, constructed=False):
                out["authentication"] = {"kind": "charstring", "value": _text(value)}
            elif _is(value, 1, constructed=False):
                out["authentication"] = {"kind": "bitstring", "value": _bits(value)}
            else:
                out["authentication"] = {"kind": "other", "raw_hex": value["encoded"].hex()}
        if n == 1:
            handled.update((2, 3))
            out["result"] = _int(_expect(_one(f[2]), 2, 0, False), False, 8)
            if out["result"] > 2:
                raise MMSParseError("invalid association result")
            diagnostic = _one(f[3])
            if diagnostic["class"] != 2 or diagnostic["number"] not in (1, 2):
                raise MMSParseError("invalid ACSE diagnostic source")
            out["diagnostic"] = {"source": "acse_service_user" if diagnostic["number"] == 1 else "acse_service_provider",
                                 "value": _int(_expect(_one(diagnostic), 2, 0, False))}
    else:
        handled.update((0, 1) if n == 4 else (0,))
        if 0 in f:
            out["abort_source" if n == 4 else "reason"] = _int(f[0])
        if n == 4 and 1 in f:
            out["diagnostic"] = _int(f[1])
    if 30 in f:
        out["user_information"] = [_external(c) for c in _children(f[30])]
    if 29 in f and n in (0, 1):
        out["implementation_information"] = _text(f[29])
    unparsed = [{"tag": k, "constructed": v["constructed"], "encoded_hex": v["encoded"].hex()}
                for k, v in f.items() if k not in handled]
    if unparsed:
        out["extension_fields"] = unparsed
    return out


def _contexts_arg(contexts):
    if contexts is None:
        return {}
    if not isinstance(contexts, dict) or len(contexts) > 256:
        raise MMSParseError("contexts must map numeric IDs to abstract-syntax OIDs")
    for key, value in contexts.items():
        if type(key) is not int or not 1 <= key <= 32767 or not isinstance(value, str) or len(value) > 256:
            raise MMSParseError("invalid presentation context mapping")
    return dict(contexts)


def _pdvs(node, contexts, transfers=None, require_context=False):
    if _is(node, 0, 1, False):
        return [{"encoding": "simply_encoded", "raw_hex": node["raw"].hex()}]
    _expect(node, 1, 1, True)
    out = []
    for pdv in _children(node):
        parts = list(_children(_expect(pdv, 16, 0, True)))
        row = {}
        if parts and _is(parts[0], 6, 0, False):
            row["transfer_syntax"] = _oid(parts.pop(0))
        if len(parts) != 2:
            raise MMSParseError("PDV-list requires context ID and data")
        cid = _int(_expect(parts[0], 2, 0, False), False, 16)
        if not 1 <= cid <= 32767:
            raise MMSParseError("invalid presentation context identifier")
        row["context_id"] = cid
        if require_context and cid not in contexts:
            raise MMSParseError("PDV refers to an undefined presentation context")
        if cid in contexts:
            row["abstract_syntax"] = contexts[cid]
        value = parts[1]
        if _is(value, 0, constructed=True):
            row["encoding"] = "single_asn1_type"
            embedded = _one(value)
            allowed = transfers.get(cid) if transfers else None
            selected = row.get("transfer_syntax")
            if selected is not None and allowed and selected not in allowed:
                raise MMSParseError("PDV transfer syntax was not proposed for this context")
            if selected is None:
                selected = (BER_SYNTAX if not allowed or BER_SYNTAX in allowed else allowed[0])
            if selected == BER_SYNTAX:
                row.update(_embedded(embedded, contexts.get(cid)))
            else:
                row.update(raw_hex=embedded["encoded"].hex(), schema="unsupported_transfer_syntax")
        elif _is(value, 1, constructed=False):
            row.update(encoding="octet_aligned", raw_hex=_primitive(value).hex())
        elif _is(value, 2, constructed=False):
            row.update(encoding="arbitrary", value=_bits(value))
        else:
            raise MMSParseError("invalid presentation data-values choice")
        out.append(row)
    if not out:
        raise MMSParseError("fully-encoded-data must contain a PDV-list")
    return out


def _presentation(node, contexts):
    out = {"protocol": "presentation", "pdu": "data", "contexts": [], "pdvs": []}
    if node["class"] == 1:
        out["pdvs"] = _pdvs(node, contexts)
        return out
    _expect(node, 17, 0, True)
    f = _fields(node, (0, 2), (0, 1, 2))
    mode = _fields(f[0], (0,), (0,))
    if _int(mode[0]) != 1 or 1 in f:
        raise MMSParseError("only normal-mode presentation is supported")
    normal, userdata = {}, None
    for child in _children(f[2]):
        if child["class"] == 1:
            if userdata is not None:
                raise MMSParseError("duplicate presentation user-data")
            userdata = child
        elif child["class"] == 2 and child["number"] not in normal:
            normal[child["number"]] = child
        else:
            raise MMSParseError("invalid normal-mode presentation field")
    if 4 in normal and 5 in normal:
        raise MMSParseError("mixed CP/CPA presentation contexts")
    # CP/CPA share a SET tag. Context results or responding selector distinguish
    # CPA; without discriminating fields their direction is inherently ambiguous.
    out["pdu"] = "cpa" if 5 in normal or 3 in normal else "cp" if 4 in normal or 1 in normal or 2 in normal else "cp_or_cpa"
    for tag, name in ((1, "calling_selector"), (2, "called_selector"), (3, "responding_selector")):
        if tag in normal:
            out[name] = _primitive(normal[tag]).hex()
    transfers = {}
    if 4 in normal:
        for definition in _children(normal[4]):
            parts = _children(_expect(definition, 16, 0, True))
            if len(parts) != 3:
                raise MMSParseError("invalid context definition")
            cid = _int(_expect(parts[0], 2, 0, False), False, 16)
            if not 1 <= cid <= 32767 or cid % 2 != 1 or any(c["id"] == cid for c in out["contexts"]):
                raise MMSParseError("duplicate or invalid presentation context")
            syntax = _oid(_expect(parts[1], 6, 0, False))
            syntax_list = [_oid(_expect(c, 6, 0, False)) for c in _children(_expect(parts[2], 16, 0, True))]
            if not syntax_list:
                raise MMSParseError("empty transfer syntax list")
            out["contexts"].append({"id": cid, "abstract_syntax": syntax, "transfer_syntaxes": syntax_list})
            contexts[cid] = syntax
            transfers[cid] = syntax_list
    if 5 in normal:
        out["context_results"] = []
        for result in _children(normal[5]):
            r = _fields(_expect(result, 16, 0, True), (0,), (0, 1, 2))
            row = {"result": _int(r[0], False, 8)}
            if row["result"] > 2 or (row["result"] == 0 and 1 not in r):
                raise MMSParseError("invalid context result or missing accepted transfer syntax")
            if 1 in r:
                row["transfer_syntax"] = _oid(r[1])
            if 2 in r:
                row["provider_reason"] = _int(r[2], False, 8)
            out["context_results"].append(row)
    if userdata is not None:
        out["pdvs"] = _pdvs(userdata, contexts, transfers, 4 in normal)
    if 0 in normal:
        out["protocol_version"] = _bits(normal[0])
    if 6 in normal:
        default = _fields(normal[6], (0, 1), (0, 1))
        out["default_context"] = {"abstract_syntax": _oid(default[0]), "transfer_syntax": _oid(default[1])}
    for tag, name in ((8, "presentation_requirements"), (9, "session_requirements")):
        if tag in normal:
            out[name] = _bits(normal[tag])
    extension = [{"tag": k, "constructed": v["constructed"], "encoded_hex": v["encoded"].hex()}
                 for k, v in normal.items() if k not in (0, 1, 2, 3, 4, 5, 6, 8, 9)]
    if extension:
        out["extension_fields"] = extension
    return out


def _unwrap(data):
    wrappers = []
    if data.startswith(b"\x03\x00"):
        if len(data) < 7 or int.from_bytes(data[2:4], "big") != len(data):
            raise MMSParseError("invalid complete TPKT length")
        if data[4:7] != b"\x02\xf0\x80":
            raise MMSParseError("only complete unfragmented COTP DT is supported")
        data = data[7:]
        wrappers = ["tpkt", "cotp_dt"]
    if data.startswith(b"\x01\x00\x01\x00"):
        data = data[4:]
        wrappers.append("session_data_transfer")
    if not data:
        raise MMSParseError("wrapper contains no PDU")
    return data, wrappers


@_guard
def parse_mms(data):
    """Decode one bare MMS PDU; raise MMSParseError on malformed input."""
    return _mms(_tree(_blob(data)))


@_guard
def parse_acse(data):
    """Decode ACSE AARQ/AARE/release/abort and EXTERNAL user-information."""
    return _acse(_tree(_blob(data)))


@_guard
def parse_presentation(data, contexts=None):
    """Decode normal CP/CPA or fully-encoded user-data; contexts maps ID to OID."""
    return _presentation(_tree(_blob(data)), _contexts_arg(contexts))


@_guard
def analyze(data, layer="auto"):
    """Decode bare BER or complete TPKT/COTP DT/session-data wrappers offline."""
    if layer not in ("auto", "mms", "acse", "presentation"):
        raise MMSParseError("layer must be auto, mms, acse or presentation")
    data, wrappers = _unwrap(_blob(data))
    node = _tree(data)
    if layer == "mms" or (layer == "auto" and node["class"] == 2):
        out = _mms(node)
    elif layer == "presentation" or (layer == "auto" and _is(node, 17, 0, True)):
        out = _presentation(node, {})
    elif layer == "acse":
        out = _acse(node)
    elif layer == "auto" and node["class"] == 1:
        # Application 1 is both AARE and fully-encoded-data. Its first child is
        # context-specific for AARE and universal SEQUENCE for presentation.
        parts = node.get("children", [])
        if node["number"] == 1 and parts and _is(parts[0], 16, 0, True):
            out = _presentation(node, {})
        elif node["number"] == 0 and not node["constructed"]:
            out = _presentation(node, {})
        else:
            out = _acse(node)
    else:
        raise MMSParseError("unrecognized protocol layer")
    if wrappers:
        out["wrappers"] = wrappers
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", nargs="?", help="binary PDU file (read only)")
    parser.add_argument("--hex", dest="hex_data", help="hexadecimal PDU instead of file")
    parser.add_argument("--layer", choices=("auto", "mms", "acse", "presentation"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception:
        return 2
    try:
        if (args.file is None) == (args.hex_data is None):
            raise MMSParseError("supply exactly one file or --hex")
        if args.hex_data is not None:
            if len(args.hex_data) > MAX_INPUT * 3:
                raise MMSParseError("oversized hex input")
            data = bytes.fromhex(args.hex_data)
        else:
            with Path(args.file).open("rb") as handle:
                data = handle.read(MAX_INPUT + 1)
        print(json.dumps(analyze(data, args.layer), indent=2, ensure_ascii=True,
                         default=lambda value: {"hex": value.hex()} if isinstance(value, bytes) else str(value)))
        return 0
    except Exception as exc:
        print(f"MMS parse error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
