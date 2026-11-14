"""Passive Mode S/Comm-B, 1090ES ADS-B v2, ARINC 429 and SWIM reader.

This module accepts only supplied bytes or words.  It does not acquire radio
samples, craft frames, open sockets, or contact SWIM services.  Basic ADS-B
identity/position fields are delegated to :mod:`sdr_protocols`; this module
adds the deeper surveillance and avionics-bus formats missing there.

References include ICAO's Mode S DAPs guidance, FAA AC 20-151C/20-165B,
ARINC 429-compatible public equipment manuals, and FAA SWIM specifications.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

from sdr_protocols import SDRDecodeError, modes_crc, parse_adsb_frame


class AirSurvModesError(ValueError):
    """Malformed or unsupported passive air-surveillance evidence."""


MAX_SWIM_BYTES = 2 * 1024 * 1024
MAX_SWIM_NODES = 10_000
MAX_JSON_DEPTH = 64

_BDS_NAMES = {
    "1,0": "data_link_capability",
    "4,0": "selected_vertical_intention",
    "5,0": "track_and_turn",
    "6,0": "heading_and_speed",
}
_BDS_ALIASES = {key.replace(",", ""): key for key in _BDS_NAMES}
_BDS_ALIASES.update({key: key for key in _BDS_NAMES})

_ARINC_LABELS = {
    0o102: "selected_altitude",
    0o203: "pressure_altitude",
    0o204: "baro_corrected_altitude_1",
    0o205: "mach_number",
    0o206: "computed_airspeed",
    0o210: "true_airspeed",
    0o211: "total_air_temperature",
    0o212: "altitude_rate",
    0o213: "static_air_temperature",
    0o310: "present_position_latitude",
    0o311: "present_position_longitude",
    0o312: "ground_speed",
    0o313: "true_track_angle",
    0o314: "true_heading",
    0o320: "magnetic_heading",
    0o324: "pitch_angle",
    0o325: "roll_angle",
    0o353: "indicated_airspeed",
    0o377: "equipment_identifier",
}
_SSM_BNR = {
    0: "failure_warning",
    1: "no_computed_data",
    2: "functional_test",
    3: "normal_operation",
}
_SSM_BCD = {
    0: "plus_north_east_right_to_above",
    1: "no_computed_data",
    2: "functional_test",
    3: "minus_south_west_left_from_below",
}
_ALTITUDE_SOURCES = {
    0: "unknown",
    1: "aircraft_altitude",
    2: "mcp_fcu",
    3: "fms",
}
_EMERGENCY_STATES = {
    0: "no_emergency",
    1: "general_emergency",
    2: "lifeguard_medical",
    3: "minimum_fuel",
    4: "no_communications",
    5: "unlawful_interference",
    6: "downed_aircraft",
    7: "reserved",
}


def _as_payload(data: object) -> tuple[bytes, int]:
    if type(data) is not bytes or len(data) != 7:
        raise AirSurvModesError("BDS/ADS-B payload must be exactly 7 bytes")
    return data, int.from_bytes(data, "big")


def _field(value: int, start: int, end: int, width: int = 56) -> int:
    """Extract inclusive, one-based MSB-first bit positions."""
    if not (1 <= start <= end <= width):
        raise AirSurvModesError("internal bit-field definition is invalid")
    return (value >> (width - end)) & ((1 << (end - start + 1)) - 1)


def _signed(raw: int, bits: int, sign: int) -> int:
    return raw - (1 << bits) if sign else raw


def _require_gated(value: int, status: int, start: int, end: int, name: str) -> None:
    if not _field(value, status, status) and _field(value, start, end):
        raise AirSurvModesError(f"{name} has data while its status bit is clear")


def _normalise_bds(register: object) -> str:
    if type(register) is not str:
        raise AirSurvModesError("BDS register must be a string")
    key = register.strip().lower().replace("bds", "").replace(" ", "")
    result = _BDS_ALIASES.get(key)
    if result is None:
        raise AirSurvModesError("supported BDS registers are 1,0, 4,0, 5,0 and 6,0")
    return result


def decode_bds_register(payload: object, register: object) -> dict:
    """Decode one explicitly identified 56-bit Comm-B MB payload.

    BDS 4,0/5,0/6,0 selectors occur in the interrogation, not the downlink;
    callers must therefore supply the known register rather than relying on a
    potentially ambiguous content heuristic.  BDS 1,0 additionally verifies
    its in-payload ``0x10`` identifier.
    """
    raw, value = _as_payload(payload)
    bds = _normalise_bds(register)
    try:
        if bds == "1,0":
            decoded = _decode_bds10(value)
        elif bds == "4,0":
            decoded = _decode_bds40(value)
        elif bds == "5,0":
            decoded = _decode_bds50(value)
        else:
            decoded = _decode_bds60(value)
    except AirSurvModesError:
        raise
    except (ArithmeticError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AirSurvModesError("malformed BDS payload") from exc
    return {
        "protocol": "mode-s-comm-b",
        "bds": bds,
        "name": _BDS_NAMES[bds],
        "payload_hex": raw.hex().upper(),
        **decoded,
    }


def _decode_bds10(value: int) -> dict:
    if _field(value, 1, 8) != 0x10:
        raise AirSurvModesError("BDS 1,0 identifier byte is not 0x10")
    if _field(value, 10, 14):
        raise AirSurvModesError("BDS 1,0 reserved bits are nonzero")
    return {
        "config": bool(_field(value, 9, 9)),
        "overlay_command_capability": bool(_field(value, 15, 15)),
        "acas_operational": bool(_field(value, 16, 16)),
        "mode_s_subnetwork_version": _field(value, 17, 23),
        "transponder_level5": bool(_field(value, 24, 24)),
        "mode_s_specific_services": bool(_field(value, 25, 25)),
        "uplink_elm_throughput": _field(value, 26, 28),
        "downlink_elm_throughput": _field(value, 29, 32),
        "aircraft_identification_capability": bool(_field(value, 33, 33)),
        "squitter_capability": bool(_field(value, 34, 34)),
        "surveillance_identifier_code": bool(_field(value, 35, 35)),
        "common_usage_gicb_capability": bool(_field(value, 36, 36)),
        "acas_hybrid_surveillance": bool(_field(value, 37, 37)),
        "acas_resolution_advisory": bool(_field(value, 38, 38)),
        "acas_rtca_version": _field(value, 39, 40),
        "dte_status": _field(value, 41, 56),
    }


def _decode_bds40(value: int) -> dict:
    for args in (
        (1, 2, 13, "MCP/FCU altitude"),
        (14, 15, 26, "FMS altitude"),
        (27, 28, 39, "barometric setting"),
        (48, 49, 51, "MCP mode"),
        (54, 55, 56, "altitude source"),
    ):
        _require_gated(value, *args)
    if _field(value, 40, 47) or _field(value, 52, 53):
        raise AirSurvModesError("BDS 4,0 reserved bits are nonzero")
    result: dict = {}
    if _field(value, 1, 1):
        result["selected_altitude_mcp_ft"] = _field(value, 2, 13) * 16
    if _field(value, 14, 14):
        result["selected_altitude_fms_ft"] = _field(value, 15, 26) * 16
    if _field(value, 27, 27):
        result["barometric_pressure_mbar"] = 800.0 + _field(value, 28, 39) * 0.1
    if _field(value, 48, 48):
        result.update({
            "vnav_mode": bool(_field(value, 49, 49)),
            "altitude_hold_mode": bool(_field(value, 50, 50)),
            "approach_mode": bool(_field(value, 51, 51)),
        })
    if _field(value, 54, 54):
        result["target_altitude_source"] = _ALTITUDE_SOURCES[_field(value, 55, 56)]
    return result


def _decode_bds50(value: int) -> dict:
    for args in (
        (1, 2, 11, "roll"),
        (12, 13, 23, "true track"),
        (24, 25, 34, "ground speed"),
        (35, 36, 45, "track rate"),
        (46, 47, 56, "true airspeed"),
    ):
        _require_gated(value, *args)
    result: dict = {}
    if _field(value, 1, 1):
        result["roll_deg"] = _signed(_field(value, 3, 11), 9,
                                      _field(value, 2, 2)) * 45.0 / 256.0
    if _field(value, 12, 12):
        degrees = _signed(_field(value, 14, 23), 10,
                          _field(value, 13, 13)) * 90.0 / 512.0
        result["true_track_deg"] = degrees % 360.0
    if _field(value, 24, 24):
        result["ground_speed_kt"] = _field(value, 25, 34) * 2
    if _field(value, 35, 35):
        result["track_angle_rate_deg_s"] = _signed(
            _field(value, 37, 45), 9, _field(value, 36, 36)) * 8.0 / 256.0
    if _field(value, 46, 46):
        result["true_airspeed_kt"] = _field(value, 47, 56) * 2
    return result


def _decode_bds60(value: int) -> dict:
    for args in (
        (1, 2, 12, "magnetic heading"),
        (13, 14, 23, "indicated airspeed"),
        (24, 25, 34, "Mach"),
        (35, 36, 45, "barometric vertical rate"),
        (46, 47, 56, "inertial vertical rate"),
    ):
        _require_gated(value, *args)
    result: dict = {}
    if _field(value, 1, 1):
        degrees = _signed(_field(value, 3, 12), 10,
                          _field(value, 2, 2)) * 90.0 / 512.0
        result["magnetic_heading_deg"] = degrees % 360.0
    if _field(value, 13, 13):
        result["indicated_airspeed_kt"] = _field(value, 14, 23)
    if _field(value, 24, 24):
        result["mach"] = _field(value, 25, 34) * 2.048 / 512.0
    if _field(value, 35, 35):
        result["barometric_vertical_rate_ft_min"] = _signed(
            _field(value, 37, 45), 9, _field(value, 36, 36)) * 32
    if _field(value, 46, 46):
        result["inertial_vertical_rate_ft_min"] = _signed(
            _field(value, 48, 56), 9, _field(value, 47, 47)) * 32
    return result


def _identity_code(raw: int) -> str:
    def bit(position: int) -> int:
        return (raw >> (12 - position)) & 1

    a = (bit(5) << 2) | (bit(3) << 1) | bit(1)
    b = (bit(11) << 2) | (bit(9) << 1) | bit(7)
    c = (bit(4) << 2) | (bit(2) << 1) | bit(0)
    d = (bit(12) << 2) | (bit(10) << 1) | bit(8)
    return f"{a}{b}{c}{d}"


def decode_adsb_me(payload: object) -> dict:
    """Decode the deeper 1090ES ME fields (TC19, TC28, TC29 and TC31)."""
    raw, value = _as_payload(payload)
    type_code = _field(value, 1, 5)
    result: dict = {"type_code": type_code, "payload_hex": raw.hex().upper()}
    try:
        if type_code == 19:
            result.update(_decode_tc19(value))
        elif type_code == 28:
            result.update(_decode_tc28(value))
        elif type_code == 29:
            result.update(_decode_tc29(value))
        elif type_code == 31:
            result.update(_decode_tc31(value))
        else:
            result["name"] = "covered_by_basic_adsb_decoder"
    except AirSurvModesError:
        raise
    except (ArithmeticError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AirSurvModesError("malformed ADS-B ME payload") from exc
    return result


def _decode_tc19(value: int) -> dict:
    subtype = _field(value, 6, 8)
    result: dict = {
        "name": "airborne_velocity",
        "subtype": subtype,
        "intent_change": bool(_field(value, 9, 9)),
        "ifr_capability": bool(_field(value, 10, 10)),
        "nac_v": _field(value, 11, 13),
    }
    scale = 4 if subtype in (2, 4) else 1
    if subtype in (1, 2):
        ew_raw, ns_raw = _field(value, 15, 24), _field(value, 26, 35)
        if ew_raw and ns_raw:
            ew = (ew_raw - 1) * scale * (-1 if _field(value, 14, 14) else 1)
            ns = (ns_raw - 1) * scale * (-1 if _field(value, 25, 25) else 1)
            result["east_west_velocity_kt"] = ew
            result["north_south_velocity_kt"] = ns
            result["ground_speed_kt"] = math.isqrt(ew * ew + ns * ns)
            result["track_deg"] = math.degrees(math.atan2(ew, ns)) % 360.0
        else:
            result["ground_speed_kt"] = None
            result["track_deg"] = None
    elif subtype in (3, 4):
        result["heading_deg"] = (_field(value, 15, 24) * 360.0 / 1024.0
                                 if _field(value, 14, 14) else None)
        speed = _field(value, 26, 35)
        result["airspeed_type"] = "TAS" if _field(value, 25, 25) else "IAS"
        result["airspeed_kt"] = (speed - 1) * scale if speed else None
    else:
        result["reserved_subtype"] = True

    vertical = _field(value, 38, 46)
    result["vertical_rate_source"] = "barometric" if _field(value, 36, 36) else "gnss"
    result["vertical_rate_ft_min"] = (None if vertical == 0 else
        (vertical - 1) * 64 * (-1 if _field(value, 37, 37) else 1))
    difference = _field(value, 50, 56)
    result["gnss_minus_baro_ft"] = (None if difference in (0, 127) else
        (difference - 1) * 25 * (-1 if _field(value, 49, 49) else 1))
    return result


def _decode_tc28(value: int) -> dict:
    subtype = _field(value, 6, 8)
    result: dict = {"name": "aircraft_status", "subtype": subtype}
    if subtype == 1:
        state = _field(value, 9, 11)
        result.update({
            "emergency_state": state,
            "emergency_state_name": _EMERGENCY_STATES[state],
            "squawk": _identity_code(_field(value, 12, 24)),
            "reserved_nonzero": bool(_field(value, 25, 56)),
        })
    elif subtype == 2:
        result.update({
            "active_resolution_advisories": _field(value, 9, 22),
            "ra_complement": _field(value, 23, 26),
            "ra_terminated": bool(_field(value, 27, 27)),
            "multiple_threat": bool(_field(value, 28, 28)),
            "threat_type_indicator": _field(value, 29, 30),
            "threat_identity_raw": _field(value, 31, 56),
            "acas_ra_payload_hex": f"{_field(value, 9, 56):012X}",
        })
    else:
        result["reserved_subtype"] = True
    return result


def _decode_tc29(value: int) -> dict:
    subtype = _field(value, 6, 7)
    result: dict = {
        "name": "target_state_and_status",
        "subtype": subtype,
        "sil_supplement": _field(value, 8, 8),
    }
    if subtype != 1:
        result["reserved_or_pre_v2_layout"] = True
        return result
    altitude = _field(value, 10, 20)
    result["selected_altitude_ft"] = (altitude - 1) * 32 if altitude else None
    result["selected_altitude_source"] = "fms" if _field(value, 9, 9) else "mcp_fcu"
    pressure = _field(value, 21, 29)
    result["barometric_pressure_mbar"] = 800.0 + (pressure - 1) * 0.8 if pressure else None
    result["selected_heading_deg"] = (_field(value, 31, 39) * 360.0 / 512.0
                                      if _field(value, 30, 30) else None)
    result.update({
        "nac_p": _field(value, 40, 43),
        "nic_baro": _field(value, 44, 44),
        "sil": _field(value, 45, 46),
    })
    if _field(value, 47, 47):
        result.update({
            "autopilot": bool(_field(value, 48, 48)),
            "vnav_mode": bool(_field(value, 49, 49)),
            "altitude_hold_mode": bool(_field(value, 50, 50)),
            "approach_mode": bool(_field(value, 52, 52)),
            "lnav_mode": bool(_field(value, 54, 54)),
        })
    else:
        result.update({key: None for key in (
            "autopilot", "vnav_mode", "altitude_hold_mode", "approach_mode", "lnav_mode")})
    result["tcas_operational"] = bool(_field(value, 53, 53))
    result["imf_or_adsr"] = bool(_field(value, 51, 51))
    result["reserved_nonzero"] = bool(_field(value, 55, 56))
    return result


def _decode_tc31(value: int) -> dict:
    subtype = _field(value, 6, 8)
    version = _field(value, 41, 43)
    if subtype not in (0, 1) or version > 2:
        return {
            "name": "aircraft_operational_status",
            "subtype": subtype,
            "adsb_version": version,
            "reserved_layout": True,
        }
    result: dict = {
        "name": "aircraft_operational_status",
        "subtype": subtype,
        "capability_class": _field(value, 9, 24),
        "operational_mode": _field(value, 25, 40),
        "adsb_version": version,
        "nic_supplement_a": _field(value, 44, 44),
        "nac_p": _field(value, 45, 48),
        "gva_or_reserved": _field(value, 49, 50),
        "sil": _field(value, 51, 52),
        "heading_reference": "magnetic" if _field(value, 54, 54) else "true",
        "reserved_bit_56": _field(value, 56, 56),
    }
    if subtype == 0 and version >= 1:
        result["nic_baro"] = _field(value, 53, 53)
    if version == 2:
        result["sil_supplement"] = _field(value, 55, 55)
        result.update({
            "operational_format": _field(value, 25, 26),
            "resolution_advisory_active": bool(_field(value, 27, 27)),
            "ident_active": bool(_field(value, 28, 28)),
            "single_antenna": bool(_field(value, 30, 30)),
            "system_design_assurance": _field(value, 31, 32),
        })
        if subtype == 0:
            result.update({
                "tcas_operational": bool(_field(value, 11, 11)),
                "es1090_in": bool(_field(value, 12, 12)),
                "air_referenced_velocity_report": bool(_field(value, 15, 15)),
                "target_state_report": bool(_field(value, 16, 16)),
                "trajectory_change_capability": _field(value, 17, 18),
                "uat_in": bool(_field(value, 19, 19)),
                "capability_reserved_nonzero": bool(
                    _field(value, 9, 10) or _field(value, 13, 14)
                    or _field(value, 20, 24)
                ),
                "operational_reserved_nonzero": bool(
                    _field(value, 29, 29) or _field(value, 33, 40)
                ),
            })
        else:
            result.update({
                "position_offset_applied": bool(_field(value, 11, 11)),
                "es1090_in": bool(_field(value, 12, 12)),
                "b2_low": bool(_field(value, 15, 15)),
                "uat_in": bool(_field(value, 16, 16)),
                "nac_v": _field(value, 17, 19),
                "nic_supplement_c": _field(value, 20, 20),
                "length_width_code": _field(value, 21, 24),
                "gps_antenna_offset": _field(value, 33, 40),
                "capability_reserved_nonzero": bool(
                    _field(value, 9, 10) or _field(value, 13, 14)
                ),
                "operational_reserved_nonzero": bool(_field(value, 29, 29)),
            })
    return result


def decode_modes_frame(frame: object, bds: object = None) -> dict:
    """Decode a supplied 112-bit DF17/18 or DF20/21 Mode S frame."""
    if type(frame) is not bytes or len(frame) != 14:
        raise AirSurvModesError("Mode S frame must be exactly 14 bytes")
    value = int.from_bytes(frame, "big")
    df = _field(value, 1, 5, 112)
    if df not in (17, 18, 20, 21):
        raise AirSurvModesError("supported long Mode S DFs are 17, 18, 20 and 21")
    try:
        remainder = modes_crc(frame)
        if df in (17, 18):
            result = parse_adsb_frame(frame)
            if df == 18:
                result["control_field"] = result.pop("capability")
            result["raw_hex"] = frame.hex().upper()
            result["me"] = decode_adsb_me(frame[4:11])
            return result

        result = {
            "protocol": "mode-s-comm-b",
            "df": df,
            "raw_hex": frame.hex().upper(),
            "flight_status": _field(value, 6, 8, 112),
            "downlink_request": _field(value, 9, 13, 112),
            "utility_message": _field(value, 14, 19, 112),
            "parity_hex": frame[11:14].hex().upper(),
            "parity_overlay_remainder": f"{remainder:06X}",
            "icao_candidate_if_address_parity": f"{remainder:06X}",
            "icao_verified": False,
            "icao_recovery_note": "candidate only; data-parity replies need interrogation context",
            "mb_hex": frame[4:11].hex().upper(),
        }
        header_value = _field(value, 20, 32, 112)
        if df == 20:
            result["altitude_code_raw"] = header_value
        else:
            result["identity_code_raw"] = header_value
            result["squawk"] = _identity_code(header_value)
        if bds is None:
            if frame[4] == 0x10:
                bds = "1,0"
            else:
                result["bds"] = None
                result["bds_note"] = "register selector is in the interrogation; pass bds explicitly"
                return result
        result["mb"] = decode_bds_register(frame[4:11], bds)
        result["bds"] = result["mb"]["bds"]
        return result
    except AirSurvModesError:
        raise
    except SDRDecodeError as exc:
        raise AirSurvModesError(str(exc)) from exc
    except (ArithmeticError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise AirSurvModesError("malformed Mode S frame") from exc


def _reverse8(value: int) -> int:
    return int(f"{value:08b}"[::-1], 2)


def decode_arinc429(word: object, *, byteorder: object = "little",
                    label_packing: object = "wire", strict_parity: object = True) -> dict:
    """Decode one captured ARINC 429 word with explicit host packing.

    ``word`` may be a 32-bit integer or four bytes.  For bytes, ``byteorder``
    states how the capture container stores that integer.  ``label_packing``
    is ``wire`` when the low byte contains the bit-reversed transmitted label,
    or ``normalized`` when an analyzer has already restored published label
    order.  The function never guesses either convention.
    """
    if type(byteorder) is not str or byteorder not in ("little", "big"):
        raise AirSurvModesError("byteorder must be little or big")
    if type(label_packing) is not str or label_packing not in ("wire", "normalized"):
        raise AirSurvModesError("label_packing must be wire or normalized")
    if type(strict_parity) is not bool:
        raise AirSurvModesError("strict_parity must be a boolean")
    if type(word) is int:
        if not 0 <= word <= 0xFFFFFFFF:
            raise AirSurvModesError("ARINC word must be an unsigned 32-bit integer")
        value = word
    elif type(word) is bytes:
        if len(word) != 4:
            raise AirSurvModesError("ARINC word must be exactly four bytes")
        value = int.from_bytes(word, byteorder)
    else:
        raise AirSurvModesError("ARINC word must be an integer or four bytes")
    raw_label = value & 0xFF
    label = _reverse8(raw_label) if label_packing == "wire" else raw_label
    ssm = (value >> 29) & 0x3
    parity_ok = value.bit_count() % 2 == 1
    if strict_parity and not parity_ok:
        raise AirSurvModesError("ARINC 429 odd parity check failed")
    return {
        "protocol": "arinc-429",
        "word_hex": f"{value:08X}",
        "byteorder": byteorder,
        "label_packing": label_packing,
        "label_raw_hex": f"{raw_label:02X}",
        "label": label,
        "label_octal": f"{label:03o}",
        "label_description": _ARINC_LABELS.get(label),
        "sdi": (value >> 8) & 0x3,
        "data_raw": (value >> 10) & 0x7FFFF,
        "ssm": ssm,
        "ssm_bnr": _SSM_BNR[ssm],
        "ssm_bcd": _SSM_BCD[ssm],
        "parity_bit": (value >> 31) & 1,
        "parity": "odd",
        "parity_ok": parity_ok,
    }


def _json_metrics(root: object) -> tuple[int, int]:
    count = 0
    max_depth = 0
    pending: list[tuple[object, int]] = [(root, 1)]
    while pending:
        node, depth = pending.pop()
        count += 1
        max_depth = max(max_depth, depth)
        if count > MAX_SWIM_NODES or depth > MAX_JSON_DEPTH:
            raise AirSurvModesError("SWIM JSON exceeds structural limits")
        if type(node) is dict:
            pending.extend((item, depth + 1) for item in node.values())
        elif type(node) is list:
            pending.extend((item, depth + 1) for item in node)
    return count, max_depth


def _model_names(text: str) -> list[str]:
    upper = text.upper()
    result = [name for name in ("FIXM", "AIXM", "IWXXM") if name in upper]
    if "IWXXM" not in upper and "WXXM" in upper:
        result.append("WXXM")
    return result


def parse_swim_artifact(data: object) -> dict:
    """Inspect a bounded saved FAA/EUROCONTROL SWIM JSON or XML artifact."""
    if type(data) is not bytes or not data or len(data) > MAX_SWIM_BYTES:
        raise AirSurvModesError("SWIM artifact must be 1..2097152 supplied bytes")
    try:
        text = data.decode("utf-8-sig")
        stripped = text.lstrip()
        metadata_names = (
            "SWIMDataPublishedTS",
            "SWIMProducerInstanceID",
            "SWIMProducerInstanceMsgSeqNum",
            "JMSTimestamp",
        )
        if stripped.startswith(("{", "[")):
            parsed = json.loads(text)
            nodes, depth = _json_metrics(parsed)
            serialized = json.dumps(parsed, separators=(",", ":"), ensure_ascii=True)
            return {
                "protocol": "swim-saved-artifact",
                "format": "json",
                "models": _model_names(serialized),
                "metadata_present": [name for name in metadata_names if name in serialized],
                "node_count": nodes,
                "max_depth": depth,
                "top_level": sorted(str(key) for key in parsed)[:256]
                if type(parsed) is dict else None,
            }
        if not stripped.startswith("<"):
            raise AirSurvModesError("SWIM artifact is neither JSON nor XML")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.IGNORECASE):
            raise AirSurvModesError("DTD/entity declarations are not accepted")
        root = ET.fromstring(text)
        elements = list(root.iter())
        if len(elements) > MAX_SWIM_NODES:
            raise AirSurvModesError("SWIM XML exceeds element limit")

        def local(tag: object) -> str:
            if type(tag) is not str:
                return ""
            return tag.rsplit("}", 1)[-1]

        root_tag = local(root.tag)
        tags = sorted({local(element.tag) for element in elements if local(element.tag)})
        namespaces = sorted({element.tag[1:].split("}", 1)[0]
                             for element in elements
                             if type(element.tag) is str and element.tag.startswith("{")})
        searchable = " ".join(namespaces + tags)
        return {
            "protocol": "swim-saved-artifact",
            "format": "xml",
            "root": root_tag,
            "namespaces": namespaces[:256],
            "models": _model_names(searchable),
            "metadata_present": [name for name in metadata_names
                                 if any(local(element.tag) == name for element in elements)],
            "element_count": len(elements),
            "local_names": tags[:256],
        }
    except AirSurvModesError:
        raise
    except (ET.ParseError, UnicodeError, json.JSONDecodeError, RecursionError,
            MemoryError, OverflowError, TypeError, ValueError) as exc:
        raise AirSurvModesError("malformed SWIM artifact") from exc


def _hex_bytes(text: object, length: int, name: str) -> bytes:
    if type(text) is not str or re.fullmatch(rf"[0-9A-Fa-f]{{{length * 2}}}", text) is None:
        raise AirSurvModesError(f"{name} must be exactly {length * 2} hexadecimal digits")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise AirSurvModesError(f"invalid {name}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="kind", required=True)
    modes = sub.add_parser("modes", help="decode a 28-hex-digit Mode S frame")
    modes.add_argument("frame")
    modes.add_argument("--bds", choices=tuple(_BDS_NAMES))
    bds = sub.add_parser("bds", help="decode a 14-hex-digit Comm-B MB payload")
    bds.add_argument("register", choices=tuple(_BDS_NAMES))
    bds.add_argument("payload")
    arinc = sub.add_parser("arinc", help="decode a 32-bit ARINC 429 analyzer word")
    arinc.add_argument("word", help="eight hexadecimal digits")
    arinc.add_argument("--label-packing", choices=("wire", "normalized"), default="wire")
    swim = sub.add_parser("swim", help="inspect a saved SWIM JSON/XML artifact")
    swim.add_argument("file")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.kind == "modes":
            result = decode_modes_frame(_hex_bytes(args.frame, 14, "frame"), args.bds)
        elif args.kind == "bds":
            result = decode_bds_register(_hex_bytes(args.payload, 7, "payload"), args.register)
        elif args.kind == "arinc":
            raw = _hex_bytes(args.word, 4, "word")
            result = decode_arinc429(raw, byteorder="big", label_packing=args.label_packing)
        else:
            with Path(args.file).open("rb") as stream:
                raw = stream.read(MAX_SWIM_BYTES + 1)
            result = parse_swim_artifact(raw)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (AirSurvModesError, OSError) as exc:
        print(f"sec_airsurv_modes: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
