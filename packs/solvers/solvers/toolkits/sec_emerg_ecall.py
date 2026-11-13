#!/usr/bin/env python3
"""Passive EU/EAEU eCall evidence decoder.

The module decodes supplied EN 15722 ASN.1 UPER Minimum Set of Data (MSD)
messages (withdrawn v1, receiver-compatible v2, and current v3), the
ERA-GLONASS GOST 33464 optional-data profiles, and RFC 8147 NG-eCall SIP/MIME
messages.  A 140-octet value may be a *recovered* EN 16062/3GPP in-band modem
payload; this module does not demodulate audio or validate the modem CRC/FEC.

All analysis is bounded and offline.  URIs are reported, never dereferenced;
no traffic is generated.  Results establish structure, not authenticity.

CLI examples::

  sec_emerg_ecall.py msd recovered.bin
  sec_emerg_ecall.py msd payload.hex --hex --profile era-glonass
  sec_emerg_ecall.py era era-extra.bin --version 2
  sec_emerg_ecall.py sip invite.sip
"""

from __future__ import annotations

import argparse
import datetime as _dt
from email import policy as _email_policy
from email.parser import BytesParser
from functools import wraps
import json
import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET


MAX_MSD = 140
MAX_SIP = 4 * 1024 * 1024
MAX_PARTS = 32
MAX_PART = 1024 * 1024
MAX_XML = 256 * 1024
MAX_XML_NODES = 4096
MAX_HEADER_LINE = 8192
MAX_HEADER_BLOCK = 256 * 1024
MAX_HEADERS = 256
CONTROL_NS = "urn:ietf:params:xml:ns:EmergencyCallData:control"
MSD_MEDIA = "application/emergencycalldata.ecall.msd"
CONTROL_MEDIA = "application/emergencycalldata.control+xml"
MSD_PURPOSE = "emergencycalldata.ecall.msd"
CONTROL_PURPOSE = "emergencycalldata.control"


class ECallError(ValueError):
    """Malformed, unsupported, ambiguous, or excessive eCall evidence."""


def _public(function):
    """Expose one declared exception type at every public parser boundary."""

    @wraps(function)
    def checked(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ECallError:
            raise
        except Exception as exc:
            raise ECallError(
                f"{function.__name__}: invalid input ({type(exc).__name__})"
            ) from None

    return checked


def _bytes(value, name, maximum, *, allow_empty=False):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise ECallError(f"{name} must be bytes")
    data = bytes(value)
    if (not allow_empty and not data) or len(data) > maximum:
        low = 0 if allow_empty else 1
        raise ECallError(f"{name} size must be {low}..{maximum} bytes")
    return data


class _Bits:
    """Small, schema-specific MSB-first UPER reader."""

    __slots__ = ("data", "position", "limit")

    def __init__(self, data):
        self.data = bytes(data)
        self.position = 0
        self.limit = len(self.data) * 8

    def read(self, width):
        if type(width) is not int or width < 0 or self.position + width > self.limit:
            raise ECallError("truncated UPER value")
        result = 0
        for _ in range(width):
            result = (result << 1) | (
                (self.data[self.position >> 3] >> (7 - (self.position & 7))) & 1
            )
            self.position += 1
        return result

    def octets(self, count):
        if type(count) is not int or count < 0 or count > MAX_MSD:
            raise ECallError("invalid UPER octet count")
        return bytes(self.read(8) for _ in range(count))

    def length(self, maximum=MAX_MSD):
        first = self.read(8)
        if not first & 0x80:
            length = first
        elif first & 0xC0 == 0x80:
            length = ((first & 0x3F) << 8) | self.read(8)
            if length < 128:
                raise ECallError("non-canonical UPER length determinant")
        else:
            raise ECallError("fragmented or reserved UPER length is unsupported")
        if length > maximum:
            raise ECallError("UPER length exceeds profile limit")
        return length

    def finish(self):
        remaining = self.limit - self.position
        if remaining > 7:
            raise ECallError("trailing data after UPER object")
        if remaining and self.read(remaining):
            raise ECallError("non-zero UPER padding bits")


_VIN_ALPHABET = "0123456789ABCDEFGHJKLMNPRSTUVWXYZ"
_PROPULSION = (
    "gasoline",
    "diesel",
    "compressed_natural_gas",
    "liquid_propane_gas",
    "electric",
    "hydrogen",
    "other",
)
_VEHICLE_V2 = (
    "passenger_vehicle_m1",
    "bus_or_coach_m2",
    "bus_or_coach_m3",
    "light_commercial_n1",
    "heavy_duty_n2",
    "heavy_duty_n3",
    "motorcycle_l1e",
    "motorcycle_l2e",
    "motorcycle_l3e",
    "motorcycle_l4e",
    "motorcycle_l5e",
    "motorcycle_l6e",
    "motorcycle_l7e",
)
_VEHICLE_V3 = _VEHICLE_V2 + (
    "trailer_o",
    "agricultural_trailer_r",
    "agricultural_towed_equipment_s",
    "tractor_t",
    "off_road_vehicle_g",
    "special_purpose_sa",
    "special_purpose_sb",
    "special_purpose_sc",
    "special_purpose_sd",
    "other",
)


def _extension_clear(reader, name):
    if reader.read(1):
        raise ECallError(f"unsupported {name} extension addition")


def _relative_oid(reader):
    length = reader.length(32)
    if length < 1:
        raise ECallError("empty relative OID")
    encoded = reader.octets(length)
    arcs, current, continuing = [], 0, False
    for octet in encoded:
        if not continuing and octet == 0x80:
            raise ECallError("non-canonical relative OID arc")
        if current > 0x0FFFFFFF:
            raise ECallError("relative OID arc is excessive")
        current = (current << 7) | (octet & 0x7F)
        if not octet & 0x80:
            arcs.append(current)
            current = 0
            continuing = False
        else:
            continuing = True
    if encoded[-1] & 0x80 or not arcs:
        raise ECallError("truncated relative OID")
    return ".".join(str(arc) for arc in arcs)


def _vin(reader):
    values = []
    for _ in range(17):
        index = reader.read(6)
        if index >= len(_VIN_ALPHABET):
            raise ECallError("VIN uses an unused permitted-alphabet index")
        values.append(_VIN_ALPHABET[index])
    text = "".join(values)
    return {
        "value": text,
        "wmi": text[:3],
        "vds": text[3:9],
        "model_year": text[9],
        "vis_seq_plant": text[10:],
        "alphabet_valid": True,
    }


def _propulsion(reader, version):
    _extension_clear(reader, "propulsion")
    count = 6 if version == 1 else 7
    present = [bool(reader.read(1)) for _ in range(count)]
    # DEFAULT FALSE fields have a presence bit and, when present, a value bit.
    values = [bool(reader.read(1)) if flag else False for flag in present]
    names = _PROPULSION[:count]
    return {
        "flags": dict(zip(names, values)),
        "present_on_wire": dict(zip(names, present)),
        "active": [name for name, value in zip(names, values) if value],
    }


def _location(raw_latitude, raw_longitude):
    issues = []
    unavailable = (
        raw_latitude == 0 and raw_longitude == 0
    ) or raw_latitude == 0x7FFFFFFF or raw_longitude == 0x7FFFFFFF
    if unavailable:
        status = "unavailable"
        latitude = longitude = None
    else:
        latitude = raw_latitude / 3_600_000.0
        longitude = raw_longitude / 3_600_000.0
        if not -90.0 <= latitude <= 90.0:
            issues.append("latitude_out_of_physical_range")
        if not -180.0 <= longitude <= 180.0:
            issues.append("longitude_out_of_physical_range")
        status = "valid" if not issues else "semantically_invalid"
    return {
        "latitude_milliarcseconds": raw_latitude,
        "longitude_milliarcseconds": raw_longitude,
        "latitude_degrees": latitude,
        "longitude_degrees": longitude,
        "status": status,
        "issues": issues,
    }


def _timestamp(value):
    if value == 0:
        return {"unix_seconds": 0, "utc": None, "status": "unavailable"}
    try:
        rendered = _dt.datetime.fromtimestamp(value, tz=_dt.timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise ECallError("timestamp cannot be represented") from exc
    return {"unix_seconds": value, "utc": rendered, "status": "present"}


def _direction(value):
    if value == 255:
        return {"raw": value, "degrees": None, "status": "unavailable"}
    if value > 179:
        return {"raw": value, "degrees": None, "status": "reserved_invalid"}
    return {"raw": value, "degrees": value * 2, "status": "valid"}


def _delta(reader):
    return {
        "latitude_units": reader.read(10) - 512,
        "longitude_units": reader.read(10) - 512,
        "unit_milliarcseconds": 100,
    }


def _computed_recent(current, first, second):
    if current["status"] != "valid":
        return {"n1": None, "n2": None}
    lat = current["latitude_degrees"]
    lon = current["longitude_degrees"]

    def add(origin_lat, origin_lon, delta):
        if delta is None:
            return None
        return {
            "latitude_degrees": origin_lat + delta["latitude_units"] / 36_000.0,
            "longitude_degrees": origin_lon + delta["longitude_units"] / 36_000.0,
        }

    n1 = add(lat, lon, first)
    # EN 15722 defines N2 relative to N1, not relative to the current point.
    n2 = add(n1["latitude_degrees"], n1["longitude_degrees"], second) if n1 and second else None
    return {"n1": n1, "n2": n2}


def _decode_inner(inner, version, *, allow_zero_tail=False):
    reader = _Bits(inner)
    _extension_clear(reader, "MSDMessage")
    additional_present = bool(reader.read(1))
    _extension_clear(reader, "MSDStructure")
    if version == 3:
        occupants_present = bool(reader.read(1))
        n1_present = n2_present = True
    else:
        n1_present = bool(reader.read(1))
        n2_present = bool(reader.read(1))
        occupants_present = bool(reader.read(1))

    message_identifier = reader.read(8)
    control = {
        "automatic_activation": bool(reader.read(1)),
        "test_call": bool(reader.read(1)),
        "position_can_be_trusted": bool(reader.read(1)),
    }
    if reader.read(1):
        raise ECallError("unsupported extended vehicle category")
    categories = _VEHICLE_V3 if version == 3 else _VEHICLE_V2
    vehicle_index = reader.read(5 if version == 3 else 4)
    if vehicle_index >= len(categories):
        raise ECallError("unused vehicle-category value")
    control["vehicle_type_index"] = vehicle_index
    control["vehicle_type"] = categories[vehicle_index]
    control["position_confidence"] = (
        "at_least_95_percent_within_150m"
        if control["position_can_be_trusted"]
        else "less_than_95_percent_within_150m"
    )

    vin = _vin(reader)
    propulsion = _propulsion(reader, version)
    timestamp = _timestamp(reader.read(32))
    location = _location(reader.read(32) - (1 << 31), reader.read(32) - (1 << 31))
    direction = _direction(reader.read(8))
    recent_n1 = _delta(reader) if n1_present else None
    recent_n2 = _delta(reader) if n2_present else None
    occupants = reader.read(8) if occupants_present else None

    additional = None
    if additional_present:
        oid = _relative_oid(reader)
        data = reader.octets(reader.length(MAX_MSD))
        additional = {"relative_oid": oid, "data_hex": data.hex(), "length": len(data)}
        if oid in ("1.4.1", "1.4.2"):
            era_version = 1 if oid == "1.4.1" else 2
            # A recognized profile is not allowed to degrade to opaque on error.
            additional["era_glonass"] = _decode_era(data, era_version)
        else:
            additional["recognized_profile"] = None
    consumed_bits = reader.position
    if allow_zero_tail:
        # A recovered EN 16062 modem block is fixed at 140 octets.  Its MSD
        # ends at the schema-determined bit position and the rest of the block
        # is zero fill.  Do not rstrip octets: zero is legal inside both the
        # MSD and an AdditionalData value, so only the decoder can locate the
        # boundary without destroying evidence.
        remaining = reader.limit - reader.position
        if remaining and reader.read(remaining):
            raise ECallError("non-zero data after recovered v1 MSD")
    else:
        reader.finish()

    issues = list(location["issues"])
    if direction["status"] == "reserved_invalid":
        issues.append("vehicle_direction_reserved")
    if message_identifier == 0:
        issues.append("message_identifier_zero_profile_specific")
    occupant_status = "absent" if occupants is None else "unavailable" if occupants == 255 else "present"
    return {
        "message_identifier": message_identifier,
        "control": control,
        "vin": vin,
        "propulsion": propulsion,
        "timestamp": timestamp,
        "vehicle_location": location,
        "vehicle_direction": direction,
        "recent_vehicle_location_n1": recent_n1,
        "recent_vehicle_location_n2": recent_n2,
        "recent_positions": _computed_recent(location, recent_n1, recent_n2),
        "occupants": {"value": occupants, "status": occupant_status},
        "occupant_field_name": "numberOfOccupants" if version == 3 else "numberOfPassengers",
        "optional_additional_data": additional,
        "issues": issues,
        "semantic_valid": not issues,
    }, consumed_bits


def _decode_msd(data, profile):
    raw = _bytes(data, "MSD", MAX_MSD)
    if profile not in ("auto", "en15722", "era-glonass", "gost"):
        raise ECallError("profile must be auto, en15722, era-glonass, or gost")
    version = raw[0]
    if version not in (1, 2, 3):
        raise ECallError("unsupported MSD version")
    modem_recovered = len(raw) == MAX_MSD
    suffix = b""
    if version == 1:
        inner = raw[1:]
        decoded, consumed_bits = _decode_inner(
            inner, version, allow_zero_tail=modem_recovered
        )
        contained_octets = (consumed_bits + 7) // 8
        trailing = len(inner) - contained_octets
        suffix = inner[contained_octets:]
    else:
        outer = _Bits(raw[1:])
        length = outer.length(MAX_MSD - 2)
        inner = outer.octets(length)
        consumed_octets = 1 + (outer.position // 8)
        suffix = raw[consumed_octets:]
        if suffix and not modem_recovered:
            raise ECallError("trailing data after contained MSD")
        trailing = len(suffix)
        decoded, consumed_bits = _decode_inner(inner, version)
        contained_octets = len(inner)
    declared_profile = "era-glonass" if profile in ("era-glonass", "gost") else "en15722"
    if profile == "auto" and decoded["optional_additional_data"]:
        if decoded["optional_additional_data"]["relative_oid"] in ("1.4.1", "1.4.2"):
            declared_profile = "era-glonass"
    return {
        "protocol": "eCall MSD",
        "encoding": "ASN.1 UPER",
        "version": version,
        "profile": declared_profile,
        "version_status": (
            "withdrawn_legacy" if version == 1 else "receiver_compatibility" if version == 2 else "current_en15722_2020"
        ),
        "transport": {
            "kind": "recovered_in_band_modem_payload" if modem_recovered else "raw_uper",
            "input_octets": len(raw),
            "contained_msd_octets": contained_octets,
            "trailing_transport_octets": trailing,
            "trailing_transport_hex": suffix.hex(),
            "trailing_zero_padding_octets": trailing if not any(suffix) else 0,
            "modem_crc_fec_verified": False,
        },
        "decoded": decoded,
        "limitations": [
            "Structural decoding does not authenticate vehicle, location, or caller.",
            "Recovered 140-byte payload analysis does not validate EN 16062 audio, CRC, HARQ, or FEC.",
        ],
    }


@_public
def decode_msd(data, profile="auto"):
    """Decode one complete EN 15722/GOST UPER MSD; raise only ECallError."""

    return _decode_msd(data, profile)


_DIAGNOSTIC_NAMES = (
    "mic_connection_failure",
    "mic_failure",
    "right_speaker_failure",
    "left_speaker_failure",
    "speakers_failure",
    "ignition_line_failure",
    "uim_failure",
    "status_indicator_failure",
    "battery_failure",
    "battery_voltage_low",
    "crash_sensor_failure",
    "firmware_image_corruption",
    "communication_module_interface_failure",
    "gnss_receiver_failure",
    "raim_problem",
    "gnss_antenna_failure",
    "communication_module_failure",
    "events_memory_overflow",
    "crash_profile_memory_overflow",
    "other_critical_failures",
    "other_noncritical_failures",
)
_CRASH_NAMES = (
    "front",
    "left",
    "right",
    "rear",
    "rollover",
    "side",
    "front_or_side",
    "other",
)


def _optional_booleans(reader, names):
    present = [bool(reader.read(1)) for _ in names]
    values = [bool(reader.read(1)) if flag else None for flag in present]
    return {
        "values": {name: value for name, value in zip(names, values) if value is not None},
        "present": [name for name, flag in zip(names, present) if flag],
        "asserted": [name for name, value in zip(names, values) if value is True],
    }


def _decode_era(data, version):
    raw = _bytes(data, "ERA optional data", MAX_MSD, allow_empty=False)
    if type(version) is not int or version not in (1, 2):
        raise ECallError("ERA data version must be 1 or 2")
    reader = _Bits(raw)
    _extension_clear(reader, "ERAAdditionalData")
    severity_present = bool(reader.read(1))
    diagnostic_present = bool(reader.read(1))
    crash_present = bool(reader.read(1))
    coordinate_present = bool(reader.read(1)) if version == 2 else False
    severity = reader.read(11) if severity_present else None
    diagnostic = _optional_booleans(reader, _DIAGNOSTIC_NAMES) if diagnostic_present else None
    crash = _optional_booleans(reader, _CRASH_NAMES) if crash_present else None
    coordinate = "wgs84"
    if version == 2 and coordinate_present:
        # GOST's two-root ENUMERATED is not extensible (the published ASN.1
        # misspells the symbolic names, but their numeric semantics are clear).
        coordinate = ("wgs84", "pz90")[reader.read(1)]
    reader.finish()
    severity_status = None
    if severity is not None:
        severity_status = "sentinel_or_low" if severity == 0 else "sentinel_or_high" if severity == 2047 else "present"
    return {
        "profile": "ERA-GLONASS optional additional data",
        "version": version,
        "crash_severity_asi15_x100": severity,
        "crash_severity_status": severity_status,
        "diagnostic_result": diagnostic,
        "crash_info": crash,
        "coordinate_system": coordinate if version == 2 else None,
        "coordinate_system_on_wire": coordinate_present if version == 2 else None,
    }


@_public
def decode_era_additional(data, version):
    """Decode the data octets selected by ERA relative OID 1.4.1 or 1.4.2."""

    return _decode_era(data, version)


def _split_header_values(value):
    values, start, angle, quote, escaped = [], 0, 0, False, False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quote and char == "\\":
            escaped = True
        elif char == '"':
            quote = not quote
        elif not quote and char == "<":
            angle += 1
        elif not quote and char == ">":
            angle -= 1
            if angle < 0:
                raise ECallError("unbalanced angle bracket in SIP header")
        elif not quote and angle == 0 and char == ",":
            values.append(value[start:index].strip())
            start = index + 1
    if quote or angle or escaped:
        raise ECallError("unterminated quoted or angle SIP header value")
    values.append(value[start:].strip())
    if any(not item for item in values):
        raise ECallError("empty SIP header list item")
    return values


def _params(value):
    pieces, current, quote, escaped = [], [], False, False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
        elif quote and char == "\\":
            escaped = True
        elif char == '"':
            quote = not quote
            current.append(char)
        elif char == ";" and not quote:
            pieces.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if quote or escaped:
        raise ECallError("unterminated MIME/SIP parameter")
    pieces.append("".join(current).strip())
    head, output = pieces[0], {}
    for piece in pieces[1:]:
        if not piece or "=" not in piece:
            raise ECallError("malformed MIME/SIP parameter")
        name, item = piece.split("=", 1)
        name, item = name.strip().lower(), item.strip()
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
            raise ECallError("invalid parameter name")
        if item.startswith('"'):
            if len(item) < 2 or not item.endswith('"'):
                raise ECallError("malformed quoted parameter")
            item = re.sub(r"\\(.)", r"\1", item[1:-1])
        elif not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~:/?@-]+", item):
            raise ECallError("invalid parameter value")
        if name in output:
            raise ECallError("duplicate parameter")
        output[name] = item
    return head, output


def _parse_link(value):
    match = re.match(r"^<([^<>\s]+)>(.*)$", value)
    if not match:
        raise ECallError("SIP linked-data value must start with one angle-bracket URI")
    uri, tail = match.groups()
    head, parameters = _params("x" + tail)
    if head != "x":
        raise ECallError("malformed SIP linked-data parameters")
    return {"uri": uri, "parameters": parameters}


def _sip_headers(raw):
    marker, separator = raw.find(b"\r\n\r\n"), 4
    if marker < 0:
        marker, separator = raw.find(b"\n\n"), 2
    if marker < 0:
        raise ECallError("SIP header terminator is missing")
    if marker > MAX_HEADER_BLOCK:
        raise ECallError("SIP header block exceeds limit")
    block, body = raw[:marker], raw[marker + separator :]
    try:
        text = block.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ECallError("SIP headers are not valid UTF-8/ASCII") from exc
    lines = text.replace("\r\n", "\n").split("\n")
    if len(lines) - 1 > MAX_HEADERS:
        raise ECallError("SIP header count exceeds limit")
    if not lines or not lines[0] or len(lines[0]) > MAX_HEADER_LINE:
        raise ECallError("invalid SIP start line")
    if any(ord(char) < 32 or ord(char) == 127 for char in lines[0]):
        raise ECallError("control character in SIP start line")
    unfolded = []
    for line in lines[1:]:
        if len(line) > MAX_HEADER_LINE:
            raise ECallError("SIP header line exceeds limit")
        if line[:1] in (" ", "\t"):
            if not unfolded:
                raise ECallError("orphan SIP header continuation")
            unfolded[-1] += " " + line.strip()
        else:
            unfolded.append(line)
    compact = {"f": "from", "t": "to", "m": "contact", "i": "call-id", "v": "via", "c": "content-type", "l": "content-length"}
    headers = {}
    for line in unfolded:
        if not line or ":" not in line:
            raise ECallError("malformed SIP header line")
        name, value = line.split(":", 1)
        name = compact.get(name.strip().lower(), name.strip().lower())
        if not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
            raise ECallError("invalid SIP header name")
        value = value.strip()
        if any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
            raise ECallError("control character in SIP header value")
        headers.setdefault(name, []).append(value)
    request = re.fullmatch(r"([A-Z]+) ([^ \t]+) SIP/2\.0", lines[0])
    response = re.fullmatch(r"SIP/2\.0 ([0-9]{3})(?: (.*))?", lines[0])
    if request:
        start = {"kind": "request", "method": request.group(1),
                 "request_uri": request.group(2), "status": None}
    elif response:
        start = {"kind": "response", "method": None, "request_uri": None,
                 "status": int(response.group(1))}
    else:
        raise ECallError("invalid SIP request/status line")
    lengths = headers.get("content-length", [])
    if len(lengths) > 1:
        raise ECallError("duplicate SIP Content-Length")
    if lengths:
        if not re.fullmatch(r"[0-9]{1,10}", lengths[0]):
            raise ECallError("invalid SIP Content-Length")
        if int(lengths[0]) != len(body):
            raise ECallError("SIP Content-Length does not match body")
    elif body:
        raise ECallError("SIP body requires Content-Length")
    return start, headers, body, lines[0]


def _content_id(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"\s*<([^<>\s]{1,512})>\s*", value)
    if not match:
        raise ECallError("malformed MIME Content-ID")
    return match.group(1)


def _cid_uri(value):
    """Return an RFC 2392 cid URL's percent-decoded, case-exact identifier."""

    if not isinstance(value, str) or not value[:4].lower() == "cid:":
        return None
    encoded = value[4:]
    output = bytearray()
    index = 0
    while index < len(encoded):
        char = encoded[index]
        if char == "%":
            if index + 2 >= len(encoded) or not re.fullmatch(
                r"[0-9A-Fa-f]{2}", encoded[index + 1 : index + 3]
            ):
                raise ECallError("malformed percent escape in CID URL")
            output.append(int(encoded[index + 1 : index + 3], 16))
            index += 3
            continue
        try:
            output.extend(char.encode("ascii"))
        except UnicodeEncodeError as exc:
            raise ECallError("CID URL must use ASCII or percent escapes") from exc
        index += 1
    try:
        identifier = output.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ECallError("CID URL decodes to a non-ASCII identifier") from exc
    if not identifier or len(identifier) > 512 or re.search(r"[<>\s]", identifier):
        raise ECallError("invalid CID URL identifier")
    return identifier


def _mime_parts(content_type, body):
    media, parameters = _params(content_type)
    media = media.lower()
    if not re.fullmatch(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+", media):
        raise ECallError("invalid SIP Content-Type")
    if not media.startswith("multipart/"):
        if len(body) > MAX_PART:
            raise ECallError("MIME body exceeds part limit")
        return [{"media_type": media, "content_id": None, "content_disposition": None,
                 "transfer_encoding": None, "body": body}], media
    boundary = parameters.get("boundary")
    if not boundary or len(boundary.encode("utf-8")) > 70 or "\r" in boundary or "\n" in boundary:
        raise ECallError("multipart boundary is missing or invalid")
    synthetic = b"Content-Type: " + content_type.encode("ascii") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    message = BytesParser(policy=_email_policy.default).parsebytes(synthetic)
    if message.defects or not message.is_multipart():
        raise ECallError("defective MIME multipart framing")
    if message.preamble and message.preamble.strip():
        raise ECallError("non-whitespace MIME preamble")
    if message.epilogue and message.epilogue.strip():
        raise ECallError("non-whitespace MIME epilogue")
    email_parts = list(message.iter_parts())
    if not 1 <= len(email_parts) <= MAX_PARTS:
        raise ECallError("MIME part count exceeds limit")
    output, identifiers = [], set()
    for part in email_parts:
        if part.defects or part.is_multipart():
            raise ECallError("defective or nested MIME part")
        for singleton in (
            "Content-Type",
            "Content-ID",
            "Content-Disposition",
            "Content-Transfer-Encoding",
        ):
            if len(part.get_all(singleton, [])) > 1:
                raise ECallError(f"duplicate MIME {singleton}")
        transfer = (part.get("Content-Transfer-Encoding") or "7bit").lower()
        if transfer not in ("binary", "7bit", "8bit"):
            raise ECallError("unsupported MIME transfer encoding")
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes) or len(payload) > MAX_PART:
            raise ECallError("invalid or oversized MIME part")
        identifier = _content_id(part.get("Content-ID"))
        if identifier is not None:
            key = identifier
            if key in identifiers:
                raise ECallError("duplicate MIME Content-ID")
            identifiers.add(key)
        output.append({
            "media_type": part.get_content_type().lower(),
            "content_id": identifier,
            "content_disposition": part.get("Content-Disposition"),
            "transfer_encoding": transfer,
            "body": payload,
        })
    return output, media


def _control_xml(data):
    raw = _bytes(data, "control XML", MAX_XML)
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I):
        raise ECallError("DOCTYPE and entity declarations are forbidden")
    root = ET.fromstring(raw)
    if root.tag != "{" + CONTROL_NS + "}EmergencyCallData.Control":
        raise ECallError("unexpected NG-eCall control XML root/namespace")
    count, extension_count = 0, 0
    stack = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        count += 1
        if count > MAX_XML_NODES or depth > 32:
            raise ECallError("control XML exceeds node/depth limit")
        if node.tag == "{http://www.w3.org/2001/XInclude}include":
            raise ECallError("XInclude is forbidden")
        namespace, _local = (
            node.tag[1:].split("}", 1)
            if isinstance(node.tag, str) and node.tag.startswith("{")
            else ("", str(node.tag))
        )
        if namespace not in (CONTROL_NS, ""):
            extension_count += 1
        stack.extend((child, depth + 1) for child in reversed(list(node)))

    def local_name(node):
        prefix = "{" + CONTROL_NS + "}"
        if not isinstance(node.tag, str) or not node.tag.startswith(prefix):
            return None
        return node.tag[len(prefix) :]

    def required(node, name):
        value = node.attrib.get(name)
        if value is None or not value.strip() or len(value) > 1024:
            raise ECallError(f"control {local_name(node)} requires {name}")
        return value

    def boolean_attribute(node, name, *, required_value=False):
        value = required(node, name) if required_value else node.attrib.get(name)
        if value is not None and value not in ("true", "false", "1", "0"):
            raise ECallError(f"control {local_name(node)} has invalid {name} boolean")
        return value

    root_events = list(root)
    if len(root_events) != 1 or local_name(root_events[0]) not in (
        "ack",
        "capabilities",
        "request",
    ):
        raise ECallError("control XML requires exactly one ack, capabilities, or request event")
    event = root_events[0]
    event_name = local_name(event)
    output = [{"element": event_name, "attributes": dict(event.attrib)}]

    def validate_request(node, *, in_capabilities):
        action = required(node, "action")
        if action == "send-data":
            required(node, "supported-values" if in_capabilities else "datatype")
        for child in node:
            child_name = local_name(child)
            if child_name not in (None, "text"):
                raise ECallError("unexpected control request child")

    if event_name == "request":
        validate_request(event, in_capabilities=False)
    elif event_name == "capabilities":
        requests = [child for child in event if local_name(child) == "request"]
        if not requests:
            raise ECallError("control capabilities requires at least one request")
        if any(local_name(child) not in (None, "request") for child in event):
            raise ECallError("unexpected control capabilities child")
        for request in requests:
            validate_request(request, in_capabilities=True)
            output.append({"element": "request", "attributes": dict(request.attrib)})
    else:
        required(event, "ref")
        boolean_attribute(event, "received")
        for child in event:
            child_name = local_name(child)
            if child_name is None:
                continue
            if child_name != "actionResult":
                raise ECallError("unexpected control ack child")
            required(child, "action")
            success = boolean_attribute(child, "success", required_value=True)
            if success in ("false", "0"):
                required(child, "reason")
            output.append({"element": "actionResult", "attributes": dict(child.attrib)})
    return {
        "root": "EmergencyCallData.Control",
        "event": event_name,
        "events": output,
        "extension_nodes": extension_count,
    }


def _parse_ng_ecall_sip(data):
    raw = _bytes(data, "SIP message", MAX_SIP)
    start, headers, body, start_line = _sip_headers(raw)
    content_types = headers.get("content-type", [])
    if len(content_types) > 1:
        raise ECallError("duplicate SIP Content-Type")
    parts, top_media = ([], None)
    if body:
        if not content_types:
            raise ECallError("SIP body has no Content-Type")
        parts, top_media = _mime_parts(content_types[0], body)
    elif content_types:
        top_media = _params(content_types[0])[0].lower()

    call_info = []
    for value in headers.get("call-info", []):
        call_info.extend(_parse_link(item) for item in _split_header_values(value))
    geolocation = []
    for value in headers.get("geolocation", []):
        geolocation.extend(_parse_link(item) for item in _split_header_values(value))
    cid_index = {part["content_id"]: part for part in parts if part["content_id"] is not None}
    issues, links = [], []
    for item in call_info:
        purpose = item["parameters"].get("purpose")
        entry = {"uri": item["uri"], "purpose": purpose, "resolved_content_id": None}
        cid = _cid_uri(item["uri"])
        if cid is not None:
            if cid not in cid_index:
                issues.append("call_info_cid_unresolved")
            else:
                entry["resolved_content_id"] = cid_index[cid]["content_id"]
        else:
            entry["external_reference_not_fetched"] = True
        links.append(entry)

    decoded_parts = []
    msd_parts = []
    control_parts = []
    for part in parts:
        item = {k: v for k, v in part.items() if k != "body"}
        item["length"] = len(part["body"])
        if part["media_type"] == MSD_MEDIA:
            item["kind"] = "ecall_msd"
            item["decoded"] = _decode_msd(part["body"], "auto")
            msd_parts.append(item)
            if part.get("transfer_encoding") != "binary":
                issues.append("msd_part_transfer_encoding_not_binary")
        elif part["media_type"] == CONTROL_MEDIA:
            item["kind"] = "ecall_control"
            item["decoded"] = _control_xml(part["body"])
            control_parts.append(item)
        else:
            item["kind"] = "other"
        decoded_parts.append(item)

    ecall_parts = msd_parts + control_parts
    if ecall_parts and not (top_media or "").startswith("multipart/"):
        issues.append("ecall_data_not_multipart")
    if len(msd_parts) > 1:
        issues.append("multiple_msd_parts")
    if len(control_parts) > 1 and start["method"] != "INFO":
        issues.append("multiple_control_parts")
    expected = ((msd_parts, MSD_PURPOSE, "msd"), (control_parts, CONTROL_PURPOSE, "control"))
    for selected_parts, expected_purpose, label in expected:
        for part in selected_parts:
            cid = part.get("content_id") or ""
            if not cid:
                issues.append(f"{label}_part_missing_content_id")
            references = [
                link
                for link in links
                if (link.get("purpose") or "").lower() == expected_purpose
                and _cid_uri(link.get("uri")) == cid
            ] if cid else []
            if len(references) != 1:
                issues.append(f"{label}_part_call_info_reference_count_not_one")
            disposition = part.get("content_disposition") or ""
            disposition_name = _params(disposition)[0].lower() if disposition else None
            if disposition_name != "by-reference":
                issues.append(f"{label}_part_not_by_reference")
    for expected_purpose, selected_parts, label in (
        (MSD_PURPOSE, msd_parts, "msd"),
        (CONTROL_PURPOSE, control_parts, "control"),
    ):
        purpose_links = [
            link for link in links if (link.get("purpose") or "").lower() == expected_purpose
        ]
        if purpose_links and not selected_parts:
            issues.append(f"{label}_call_info_without_part")
        for link in purpose_links:
            if _cid_uri(link.get("uri")) is None:
                issues.append(f"{label}_call_info_not_cid")

    if start["method"] == "INFO":
        packages = [
            item.strip().lower()
            for value in headers.get("info-package", [])
            for item in value.split(",")
            if item.strip()
        ]
        if ecall_parts and packages != ["emergencycalldata.ecall.msd"]:
            issues.append("ecall_info_package_missing_or_invalid")
        if packages == ["emergencycalldata.ecall.msd"] and not ecall_parts:
            issues.append("ecall_info_package_without_ecall_part")
        dispositions = headers.get("content-disposition", [])
        if ecall_parts:
            if len(dispositions) != 1:
                issues.append("ecall_info_content_disposition_missing_or_duplicate")
            else:
                disposition_name = _params(dispositions[0])[0].lower()
                if disposition_name != "info-package":
                    issues.append("ecall_info_content_disposition_invalid")

    service_urn = start["request_uri"] if (start["request_uri"] or "").lower().startswith("urn:service:") else None
    activation_from_urn = None
    test_from_urn = None
    if service_urn:
        lower = service_urn.lower()
        if lower == "urn:service:sos.ecall.automatic":
            activation_from_urn = "automatic"
            test_from_urn = False
        elif lower == "urn:service:sos.ecall.manual":
            activation_from_urn = "manual"
            test_from_urn = False
        elif lower == "urn:service:test.sos.ecall":
            test_from_urn = True
    for part in msd_parts:
        automatic = part["decoded"]["decoded"]["control"]["automatic_activation"]
        test_call = part["decoded"]["decoded"]["control"]["test_call"]
        activation_from_msd = "automatic" if automatic else "manual"
        part["activation_from_msd"] = activation_from_msd
        part["test_call_from_msd"] = test_call
        if activation_from_urn and activation_from_urn != activation_from_msd:
            issues.append("service_urn_msd_activation_mismatch")
        if test_from_urn is not None and test_from_urn != test_call:
            issues.append("service_urn_msd_test_mismatch")

    package_values = []
    for name in ("recv-info", "info-package"):
        for value in headers.get(name, []):
            package_values.extend(item.strip() for item in value.split(",") if item.strip())
    return {
        "protocol": "NG eCall over IMS",
        "standard_binding": "RFC 8147 / EN 17184",
        "start_line": start_line,
        **start,
        "service_urn": service_urn,
        "activation_from_service_urn": activation_from_urn,
        "test_call_from_service_urn": test_from_urn,
        "call_id": headers.get("call-id", [None])[0],
        "cseq": headers.get("cseq", [None])[0],
        "top_content_type": top_media,
        "call_info": links,
        "geolocation": [{"uri": item["uri"], "parameters": item["parameters"], "external_reference_not_fetched": _cid_uri(item["uri"]) is None} for item in geolocation],
        "info_packages": package_values,
        "parts": decoded_parts,
        "issues": list(dict.fromkeys(issues)),
        "structurally_valid": not issues,
        "limitations": [
            "External Call-Info and Geolocation references were not fetched.",
            "SIP/MSD structure does not authenticate a vehicle, caller, or location.",
        ],
    }


@_public
def parse_ng_ecall_sip(data):
    """Parse one supplied RFC 8147 SIP message; raise only ECallError."""

    return _parse_ng_ecall_sip(data)


@_public
def analyze(data, kind="auto", profile="auto"):
    """Analyze supplied bytes as ``msd``, ``sip``, or safely auto-detect."""

    raw = _bytes(data, "eCall artifact", MAX_SIP)
    if kind not in ("auto", "msd", "sip"):
        raise ECallError("kind must be auto, msd, or sip")
    selected = kind
    if selected == "auto":
        prefix = raw[:32].lstrip()
        selected = "sip" if re.match(rb"(?:[A-Z]+\s+\S+\s+SIP/2\.0|SIP/2\.0\s+[0-9]{3})", prefix) else "msd"
    return _parse_ng_ecall_sip(raw) if selected == "sip" else _decode_msd(raw, profile)


def _read(path, maximum, as_hex=False):
    with Path(path).open("rb") as stream:
        raw = stream.read((maximum * 3 if as_hex else maximum) + 1)
    if len(raw) > (maximum * 3 if as_hex else maximum):
        raise ECallError("input file exceeds size cap")
    if as_hex:
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ECallError("hex input is not ASCII") from exc
        compact = re.sub(r"[ \t\r\n]", "", text)
        if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", compact):
            raise ECallError("invalid hexadecimal input")
        raw = bytes.fromhex(compact)
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    msd = commands.add_parser("msd", help="decode EN 15722 / GOST UPER MSD")
    msd.add_argument("file")
    msd.add_argument("--hex", action="store_true")
    msd.add_argument("--profile", choices=("auto", "en15722", "era-glonass", "gost"), default="auto")
    era = commands.add_parser("era", help="decode ERA optional-data payload")
    era.add_argument("file")
    era.add_argument("--hex", action="store_true")
    era.add_argument("--version", type=int, choices=(1, 2), required=True)
    sip = commands.add_parser("sip", help="parse one saved RFC 8147 SIP message")
    sip.add_argument("file")
    auto = commands.add_parser("auto", help="auto-detect raw MSD versus SIP")
    auto.add_argument("file")
    auto.add_argument("--profile", choices=("auto", "en15722", "era-glonass", "gost"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f"sec_emerg_ecall: invalid CLI arguments ({type(exc).__name__})", file=sys.stderr)
        return 2
    try:
        if args.command == "msd":
            report = decode_msd(_read(args.file, MAX_MSD, args.hex), args.profile)
        elif args.command == "era":
            report = decode_era_additional(_read(args.file, MAX_MSD, args.hex), args.version)
        elif args.command == "sip":
            report = parse_ng_ecall_sip(_read(args.file, MAX_SIP))
        else:
            report = analyze(_read(args.file, MAX_SIP), profile=args.profile)
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
        return 0
    except ECallError as exc:
        print(f"sec_emerg_ecall: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"sec_emerg_ecall: file error ({type(exc).__name__})", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"sec_emerg_ecall: invalid input ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
