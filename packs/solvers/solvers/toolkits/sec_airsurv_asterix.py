#!/usr/bin/env python3
"""Bounded passive EUROCONTROL ASTERIX block and record decoder.

The parser consumes caller-supplied ASTERIX bytes only.  It implements Part 1
CAT/LEN blocking and FSPEC rules, then uses explicit UAP profiles for CAT004,
CAT010, CAT021, CAT023, CAT034, CAT048, CAT062, and CAT240.  Fixed, FX-chain,
repetitive, and explicit-length items are bounded.  A present compound item is
rejected unless its complete sub-UAP is known; record boundaries are never
guessed.

Primary references are EUROCONTROL ASTERIX Part 1 edition 3.1 and the category
editions named in ``CATEGORY_PROFILES`` below.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Callable


class AirSurvAsterixError(ValueError):
    """Malformed, unsupported, or unbounded supplied ASTERIX evidence."""


MAX_STREAM = 16 * 1024 * 1024
MAX_BLOCKS = 4096
MAX_RECORDS = 100_000
MAX_FSPEC_OCTETS = 8
MAX_FX_OCTETS = 32
MAX_EXPLICIT_OCTETS = 255
MAX_REPETITIONS = 255


Decoder = Callable[[bytes], dict[str, object]]


@dataclass(frozen=True)
class ItemSpec:
    item: str
    name: str
    kind: str
    size: int = 0
    unit: int = 0
    max_rep: int = MAX_REPETITIONS
    decoder: Decoder | None = None


@dataclass(frozen=True)
class CategoryProfile:
    category: int
    edition: str
    name: str
    items: dict[int, ItemSpec]


def _fixed(item: str, name: str, size: int, decoder: Decoder | None = None) -> ItemSpec:
    return ItemSpec(item, name, "fixed", size=size, decoder=decoder)


def _fx(item: str, name: str, decoder: Decoder | None = None) -> ItemSpec:
    return ItemSpec(item, name, "fx", decoder=decoder)


def _rep(item: str, name: str, unit: int, decoder: Decoder | None = None,
         max_rep: int = MAX_REPETITIONS) -> ItemSpec:
    return ItemSpec(item, name, "repetitive", unit=unit, decoder=decoder,
                    max_rep=max_rep)


def _explicit(item: str, name: str) -> ItemSpec:
    return ItemSpec(item, name, "explicit")


def _compound(item: str, name: str) -> ItemSpec:
    return ItemSpec(item, name, "compound")


def _signed(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=True)


def _dsi(raw: bytes) -> dict[str, object]:
    return {"sac": raw[0], "sic": raw[1]}


def _time_128(raw: bytes) -> dict[str, object]:
    ticks = int.from_bytes(raw, "big")
    return {"time_ticks_128": ticks, "time_seconds": ticks / 128.0}


def _latlon24(raw: bytes) -> dict[str, object]:
    scale = 180.0 / (1 << 23)
    return {"latitude_deg": _signed(raw[:3]) * scale,
            "longitude_deg": _signed(raw[3:]) * scale}


def _latlon32_30(raw: bytes) -> dict[str, object]:
    scale = 180.0 / (1 << 30)
    return {"latitude_deg": _signed(raw[:4]) * scale,
            "longitude_deg": _signed(raw[4:]) * scale}


def _latlon32_31(raw: bytes) -> dict[str, object]:
    scale = 180.0 / (1 << 31)
    return {"latitude_deg": _signed(raw[:4]) * scale,
            "longitude_deg": _signed(raw[4:]) * scale}


def _latlon32_25(raw: bytes) -> dict[str, object]:
    scale = 180.0 / (1 << 25)
    return {"latitude_deg": _signed(raw[:4]) * scale,
            "longitude_deg": _signed(raw[4:]) * scale}


def _address(raw: bytes) -> dict[str, object]:
    return {"aircraft_address": raw.hex().upper()}


_SIXBIT = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####_###############0123456789######"


def _sixbit_text(raw: bytes) -> str:
    value = int.from_bytes(raw, "big")
    width = len(raw) * 8
    chars = []
    for shift in range(width - 6, -1, -6):
        code = (value >> shift) & 0x3F
        chars.append(_SIXBIT[code] if code < len(_SIXBIT) else "#")
    return "".join(chars).replace("_", " ").replace("#", "").rstrip()


def _target_id6(raw: bytes) -> dict[str, object]:
    return {"target_identification": _sixbit_text(raw)}


def _target_id7(raw: bytes) -> dict[str, object]:
    return {"source_type": (raw[0] >> 6) & 0x03,
            "target_identification": _sixbit_text(raw[1:])}


def _polar_nm(raw: bytes) -> dict[str, object]:
    return {"range_nm": int.from_bytes(raw[:2], "big") / 256.0,
            "azimuth_deg": int.from_bytes(raw[2:], "big") * 360.0 / 65536.0}


def _polar_metres(raw: bytes) -> dict[str, object]:
    return {"range_m": int.from_bytes(raw[:2], "big"),
            "azimuth_deg": int.from_bytes(raw[2:], "big") * 360.0 / 65536.0}


def _cart_nm(raw: bytes) -> dict[str, object]:
    return {"x_nm": _signed(raw[:2]) / 128.0,
            "y_nm": _signed(raw[2:]) / 128.0}


def _cart_metres(raw: bytes) -> dict[str, object]:
    return {"x_m": _signed(raw[:2]), "y_m": _signed(raw[2:])}


def _cart_half_metres(raw: bytes) -> dict[str, object]:
    return {"x_m": _signed(raw[:3]) * 0.5,
            "y_m": _signed(raw[3:]) * 0.5}


def _mode3a(raw: bytes) -> dict[str, object]:
    value = int.from_bytes(raw, "big")
    code = value & 0x0FFF
    return {"validated": not bool(value & 0x8000),
            "garbled": bool(value & 0x4000),
            "not_extracted": bool(value & 0x2000),
            "mode_3a": f"{code:04o}"}


def _flight_level(raw: bytes) -> dict[str, object]:
    value = int.from_bytes(raw, "big")
    level = value & 0x3FFF
    if level & 0x2000:
        level -= 0x4000
    return {"validated": not bool(value & 0x8000),
            "garbled": bool(value & 0x4000),
            "flight_level": level * 0.25,
            "altitude_ft": level * 25.0}


def _track_number(raw: bytes) -> dict[str, object]:
    return {"track_number": int.from_bytes(raw, "big") & 0x0FFF}


def _cat048_velocity(raw: bytes) -> dict[str, object]:
    speed = int.from_bytes(raw[:2], "big") / 16384.0
    return {"ground_speed_nm_s": speed, "ground_speed_knots": speed * 3600.0,
            "track_angle_deg": int.from_bytes(raw[2:], "big") * 360.0 / 65536.0}


_CAT004_TYPES = {
    1: "alive", 2: "route_adherence_longitudinal_deviation",
    3: "route_adherence_heading_deviation", 4: "minimum_safe_altitude_warning",
    5: "area_proximity_warning", 6: "clearance_level_adherence_monitor",
    7: "short_term_conflict_alert", 8: "approach_path_monitor",
    9: "rimcas_arrival_landing_monitor", 10: "rimcas_wrong_runway_alert",
    11: "rimcas_opposite_traffic_alert", 12: "rimcas_departure_monitor",
    13: "rimcas_runway_taxiway_crossing_monitor",
    14: "rimcas_taxiway_separation_monitor",
    15: "rimcas_unauthorised_taxiway_movement_monitor",
    16: "rimcas_stop_bar_overrun_alert", 17: "end_of_conflict",
    18: "acas_resolution_advisory", 19: "near_term_conflict_alert",
    20: "downlinked_barometric_pressure_setting_monitor",
    21: "speed_adherence_monitor", 22: "outside_controlled_airspace_tool",
}
_CAT010_TYPES = {1: "target_report", 2: "start_update_cycle", 3: "periodic_status",
                 4: "event_status"}
_CAT023_TYPES = {1: "ground_station_status", 2: "service_status",
                 3: "service_statistics"}
_CAT034_TYPES = {1: "north_marker", 2: "sector_crossing", 3: "geographical_filtering",
                 4: "jamming_strobe", 5: "solar_storm", 6: "ssr_jamming",
                 7: "mode_s_jamming"}
_CAT240_TYPES = {1: "radar_video_summary", 2: "radar_video"}


def _message_type(table: dict[int, str]) -> Decoder:
    def decode(raw: bytes) -> dict[str, object]:
        value = raw[0]
        return {"message_type": value, "message_type_name": table.get(value, "unknown")}
    return decode


def _sector_angle(raw: bytes) -> dict[str, object]:
    return {"sector_angle_deg": raw[0] * 360.0 / 256.0}


def _cat034_sector(raw: bytes) -> dict[str, object]:
    return {
        "range_start_nm": int.from_bytes(raw[0:2], "big") / 256.0,
        "range_end_nm": int.from_bytes(raw[2:4], "big") / 256.0,
        "azimuth_start_deg": int.from_bytes(raw[4:6], "big") * 360.0 / 65536.0,
        "azimuth_end_deg": int.from_bytes(raw[6:8], "big") * 360.0 / 65536.0,
    }


def _cat034_position(raw: bytes) -> dict[str, object]:
    scale = 180.0 / (1 << 23)
    return {"height_m": _signed(raw[:2]),
            "latitude_deg": _signed(raw[2:5]) * scale,
            "longitude_deg": _signed(raw[5:8]) * scale}


def _cat034_collimation(raw: bytes) -> dict[str, object]:
    return {"range_error_nm": _signed(raw[:1]) / 128.0,
            "azimuth_error_deg": _signed(raw[1:]) * 360.0 / (1 << 14)}


_CAT023_SERVICES = {
    1: "ADS-B VDL4", 2: "ADS-B 1090ES", 3: "ADS-B UAT",
    4: "TIS-B VDL4", 5: "TIS-B 1090ES", 6: "TIS-B UAT",
    7: "FIS-B VDL4", 8: "GRAS VDL4", 9: "MLT",
}


def _cat023_service(raw: bytes) -> dict[str, object]:
    return {"service_id": raw[0] >> 4, "service_type": raw[0] & 0x0F,
            "service_type_name": _CAT023_SERVICES.get(raw[0] & 0x0F, "unknown")}


def _cat023_status(raw: bytes) -> dict[str, object]:
    first = raw[0]
    return {"nogo": bool(first & 0x80), "odp": bool(first & 0x40),
            "oxt": bool(first & 0x20), "msc": bool(first & 0x10),
            "tsv": bool(first & 0x08), "spo": bool(first & 0x04),
            "rn": bool(first & 0x02), "status_extents": list(raw)}


def _cat023_service_status(raw: bytes) -> dict[str, object]:
    code = (raw[0] >> 1) & 0x07
    names = {0: "unknown", 1: "failed", 2: "disabled", 3: "degraded",
             4: "normal", 5: "initialisation"}
    return {"service_status": code, "service_status_name": names.get(code, "reserved"),
            "status_extents": list(raw)}


def _cat240_ascii(raw: bytes) -> dict[str, object]:
    payload = raw[1:]
    return {"summary": payload.decode("ascii", "replace")}


def _cat240_header(unit: str) -> Decoder:
    def decode(raw: bytes) -> dict[str, object]:
        return {"start_azimuth_deg": int.from_bytes(raw[0:2], "big") * 360.0 / 65536.0,
                "end_azimuth_deg": int.from_bytes(raw[2:4], "big") * 360.0 / 65536.0,
                "start_range_cells": int.from_bytes(raw[4:8], "big"),
                f"cell_duration_{unit}": int.from_bytes(raw[8:12], "big")}
    return decode


def _cat240_resolution(raw: bytes) -> dict[str, object]:
    value = int.from_bytes(raw, "big")
    code = value & 0xFF
    return {"compressed": bool(value & 0x8000), "resolution_code": code,
            "bits_per_cell": {1: 1, 2: 2, 3: 4, 4: 8, 5: 16, 6: 32}.get(code)}


def _cat240_count(raw: bytes) -> dict[str, object]:
    return {"valid_octets": int.from_bytes(raw[:2], "big"),
            "video_cells": int.from_bytes(raw[2:], "big")}


def _cat240_index(raw: bytes) -> dict[str, object]:
    return {"message_index": int.from_bytes(raw, "big")}


def _uap(*rows: tuple[int, ItemSpec]) -> dict[int, ItemSpec]:
    return dict(rows)


CATEGORY_PROFILES: dict[int, CategoryProfile] = {
    4: CategoryProfile(4, "1.13", "Safety Net Messages", _uap(
        (1, _fixed("I004/010", "Data Source Identifier", 2, _dsi)),
        (2, _fixed("I004/000", "Message Type", 1, _message_type(_CAT004_TYPES))),
        (3, _rep("I004/015", "SDPS Identifier", 2)),
        (4, _fixed("I004/020", "Time of Message", 3, _time_128)),
        (5, _fixed("I004/040", "Alert Identifier", 2,
                   lambda b: {"alert_identifier": int.from_bytes(b, "big")})),
        (6, _fixed("I004/045", "Alert Status", 1)),
        (7, _compound("I004/060", "Safety Net Function and Status")),
        (8, _fixed("I004/030", "Track Number 1", 2, _track_number)),
        (9, _compound("I004/170", "Aircraft Data 1")),
        (10, _compound("I004/120", "Conflict Characteristics")),
        (11, _compound("I004/070", "Conflict Timing and Separation")),
        (12, _fixed("I004/076", "Vertical Deviation", 2)),
        (13, _fixed("I004/074", "Longitudinal Deviation", 2)),
        (14, _fixed("I004/075", "Transversal Deviation", 3)),
        (15, _compound("I004/100", "Area Definition")),
        (16, _fixed("I004/035", "Track Number 2", 2, _track_number)),
        (17, _compound("I004/171", "Aircraft Data 2")),
        (18, _compound("I004/110", "Sector Control Identification")),
        (20, _explicit("RE", "Reserved Expansion Field")),
        (21, _explicit("SP", "Special Purpose Field")),
    )),
    10: CategoryProfile(10, "1.1", "Monoradar Surface Movement Data", _uap(
        (1, _fixed("I010/010", "Data Source Identifier", 2, _dsi)),
        (2, _fixed("I010/000", "Message Type", 1, _message_type(_CAT010_TYPES))),
        (3, _fx("I010/020", "Target Report Descriptor")),
        (4, _fixed("I010/140", "Time of Day", 3, _time_128)),
        (5, _fixed("I010/041", "Position in WGS-84", 8, _latlon32_31)),
        (6, _fixed("I010/040", "Measured Position in Polar Coordinates", 4, _polar_metres)),
        (7, _fixed("I010/042", "Position in Cartesian Coordinates", 4, _cart_metres)),
        (8, _fixed("I010/200", "Calculated Track Velocity in Polar Coordinates", 4)),
        (9, _fixed("I010/202", "Calculated Track Velocity in Cartesian Coordinates", 4)),
        (10, _fixed("I010/161", "Track Number", 2, _track_number)),
        (11, _fx("I010/170", "Track Status")),
        (12, _fixed("I010/060", "Mode-3/A Code", 2, _mode3a)),
        (13, _fixed("I010/220", "Target Address", 3, _address)),
        (14, _fixed("I010/245", "Target Identification", 7, _target_id7)),
        (15, _rep("I010/250", "Mode S MB Data", 8)),
        (16, _fixed("I010/300", "Vehicle Fleet Identification", 1)),
        (17, _fixed("I010/090", "Flight Level", 2, _flight_level)),
        (18, _fixed("I010/091", "Measured Height", 2)),
        (19, _fx("I010/270", "Target Size and Orientation")),
        (20, _fixed("I010/550", "System Status", 1)),
        (21, _fixed("I010/310", "Pre-programmed Message", 1)),
        (22, _fixed("I010/500", "Standard Deviation of Position", 4)),
        (23, _rep("I010/280", "Presence", 2)),
        (24, _fixed("I010/131", "Amplitude of Primary Plot", 1)),
        (25, _fixed("I010/210", "Calculated Acceleration", 2)),
        (27, _explicit("SP", "Special Purpose Field")),
        (28, _explicit("RE", "Reserved Expansion Field")),
    )),
    21: CategoryProfile(21, "2.7", "ADS-B Target Reports", _uap(
        (1, _fixed("I021/010", "Data Source Identification", 2, _dsi)),
        (2, _fx("I021/040", "Target Report Descriptor")),
        (3, _fixed("I021/161", "Track Number", 2, _track_number)),
        (4, _fixed("I021/015", "Service Identification", 1)),
        (5, _fixed("I021/071", "Time of Applicability for Position", 3, _time_128)),
        (6, _fixed("I021/130", "Position in WGS-84", 6, _latlon24)),
        (7, _fixed("I021/131", "High-Resolution Position in WGS-84", 8, _latlon32_30)),
        (8, _fixed("I021/072", "Time of Applicability for Velocity", 3, _time_128)),
        (9, _fixed("I021/150", "Air Speed", 2)),
        (10, _fixed("I021/151", "True Airspeed", 2)),
        (11, _fixed("I021/080", "Target Address", 3, _address)),
        (12, _fixed("I021/073", "Time of Message Reception for Position", 3, _time_128)),
        (13, _fixed("I021/074", "High-Precision Reception Time for Position", 4)),
        (14, _fixed("I021/075", "Time of Message Reception for Velocity", 3, _time_128)),
        (15, _fixed("I021/076", "High-Precision Reception Time for Velocity", 4)),
        (16, _fixed("I021/140", "Geometric Height", 2)),
        (17, _fx("I021/090", "Quality Indicators")),
        (18, _fixed("I021/210", "MOPS Version", 1)),
        (19, _fixed("I021/070", "Mode 3/A Code", 2, _mode3a)),
        (20, _fixed("I021/230", "Roll Angle", 2)),
        (21, _fixed("I021/145", "Flight Level", 2, _flight_level)),
        (22, _fixed("I021/152", "Magnetic Heading", 2)),
        (23, _fixed("I021/200", "Target Status", 1)),
        (24, _fixed("I021/155", "Barometric Vertical Rate", 2)),
        (25, _fixed("I021/157", "Geometric Vertical Rate", 2)),
        (26, _fixed("I021/160", "Airborne Ground Vector", 4)),
        (27, _fixed("I021/165", "Track Angle Rate", 2)),
        (28, _fixed("I021/077", "Report Transmission Time", 3, _time_128)),
        (29, _fixed("I021/170", "Target Identification", 6, _target_id6)),
        (30, _fixed("I021/020", "Emitter Category", 1)),
        (31, _compound("I021/220", "Met Information")),
        (32, _fixed("I021/146", "Selected Altitude", 2)),
        (33, _fixed("I021/148", "Final State Selected Altitude", 2)),
        (34, _compound("I021/110", "Trajectory Intent")),
        (35, _fixed("I021/016", "Service Management", 1)),
        (36, _fixed("I021/008", "Aircraft Operational Status", 1)),
        (37, _fx("I021/271", "Surface Capabilities and Characteristics")),
        (38, _fixed("I021/132", "Message Amplitude", 1)),
        (39, _rep("I021/250", "Mode S MB Data", 8)),
        (40, _fixed("I021/260", "ACAS Resolution Advisory Report", 7)),
        (41, _fixed("I021/400", "Receiver ID", 1)),
        (42, _compound("I021/295", "Data Ages")),
        (48, _explicit("RE", "Reserved Expansion Field")),
        (49, _explicit("SP", "Special Purpose Field")),
    )),
    23: CategoryProfile(23, "1.3", "CNS/ATM Ground Station Service Messages", _uap(
        (1, _fixed("I023/010", "Data Source Identifier", 2, _dsi)),
        (2, _fixed("I023/000", "Report Type", 1, _message_type(_CAT023_TYPES))),
        (3, _fixed("I023/015", "Service Type and Identification", 1, _cat023_service)),
        (4, _fixed("I023/070", "Time of Day", 3, _time_128)),
        (5, _fx("I023/100", "Ground Station Status", _cat023_status)),
        (6, _compound("I023/101", "Ground Station Status Extension")),
        (7, _fixed("I023/200", "Operational Range", 1,
                   lambda b: {"operational_range_nm": b[0]})),
        (8, _fx("I023/110", "Service Status", _cat023_service_status)),
        (9, _rep("I023/120", "Service Statistics", 6)),
        (13, _explicit("RE", "Reserved Expansion Field")),
        (14, _explicit("SP", "Special Purpose Field")),
    )),
    34: CategoryProfile(34, "1.29", "Monoradar Service Messages", _uap(
        (1, _fixed("I034/010", "Data Source Identifier", 2, _dsi)),
        (2, _fixed("I034/000", "Message Type", 1, _message_type(_CAT034_TYPES))),
        (3, _fixed("I034/030", "Time of Day", 3, _time_128)),
        (4, _fixed("I034/020", "Sector Number", 1, _sector_angle)),
        (5, _fixed("I034/041", "Antenna Rotation Period", 2,
                   lambda b: {"rotation_period_s": int.from_bytes(b, "big") / 128.0})),
        (6, _compound("I034/050", "System Configuration and Status")),
        (7, _compound("I034/060", "System Processing Mode")),
        (8, _rep("I034/070", "Message Count Values", 2)),
        (9, _fixed("I034/100", "Generic Polar Window", 8, _cat034_sector)),
        (10, _fixed("I034/110", "Data Filter", 1)),
        (11, _fixed("I034/120", "3D Position of Data Source", 8, _cat034_position)),
        (12, _fixed("I034/090", "Collimation Error", 2, _cat034_collimation)),
        (13, _explicit("RE", "Reserved Expansion Field")),
        (14, _explicit("SP", "Special Purpose Field")),
    )),
    48: CategoryProfile(48, "1.32", "Monoradar Target Reports", _uap(
        (1, _fixed("I048/010", "Data Source Identifier", 2, _dsi)),
        (2, _fixed("I048/140", "Time of Day", 3, _time_128)),
        (3, _fx("I048/020", "Target Report Descriptor")),
        (4, _fixed("I048/040", "Measured Position in Slant Polar Coordinates", 4, _polar_nm)),
        (5, _fixed("I048/070", "Mode-3/A Code", 2, _mode3a)),
        (6, _fixed("I048/090", "Flight Level", 2, _flight_level)),
        (7, _compound("I048/130", "Radar Plot Characteristics")),
        (8, _fixed("I048/220", "Aircraft Address", 3, _address)),
        (9, _fixed("I048/240", "Aircraft Identification", 6, _target_id6)),
        (10, _rep("I048/250", "Mode S MB Data", 8)),
        (11, _fixed("I048/161", "Track Number", 2, _track_number)),
        (12, _fixed("I048/042", "Calculated Position in Cartesian Coordinates", 4, _cart_nm)),
        (13, _fixed("I048/200", "Calculated Track Velocity in Polar Representation", 4,
                    _cat048_velocity)),
        (14, _fx("I048/170", "Track Status")),
        (15, _fixed("I048/210", "Track Quality", 4)),
        (16, _fx("I048/030", "Warning and Error Conditions")),
        (17, _fixed("I048/080", "Mode-3/A Confidence", 2)),
        (18, _fixed("I048/100", "Mode-C Code and Confidence", 4)),
        (19, _fixed("I048/110", "Height Measured by 3D Radar", 2)),
        (20, _compound("I048/120", "Radial Doppler Speed")),
        (21, _fixed("I048/230", "Communications/ACAS Capability and Flight Status", 2)),
        (22, _fixed("I048/260", "ACAS Resolution Advisory Report", 7)),
        (23, _fixed("I048/055", "Mode-1 Code", 1)),
        (24, _fixed("I048/050", "Mode-2 Code", 2)),
        (25, _fixed("I048/065", "Mode-1 Confidence", 1)),
        (26, _fixed("I048/060", "Mode-2 Confidence", 2)),
        (27, _explicit("SP", "Special Purpose Field")),
        (28, _explicit("RE", "Reserved Expansion Field")),
    )),
    62: CategoryProfile(62, "1.21", "System Track Data", _uap(
        (1, _fixed("I062/010", "Data Source Identifier", 2, _dsi)),
        (3, _fixed("I062/015", "Service Identification", 1)),
        (4, _fixed("I062/070", "Time of Track Information", 3, _time_128)),
        (5, _fixed("I062/105", "Calculated Position in WGS-84", 8, _latlon32_25)),
        (6, _fixed("I062/100", "Calculated Track Position in Cartesian Coordinates", 6,
                   _cart_half_metres)),
        (7, _fixed("I062/185", "Calculated Track Velocity in Cartesian Coordinates", 4)),
        (8, _fixed("I062/210", "Calculated Acceleration", 2)),
        (9, _fixed("I062/060", "Track Mode 3/A Code", 2, _mode3a)),
        (10, _fixed("I062/245", "Target Identification", 7, _target_id7)),
        (11, _compound("I062/380", "Aircraft Derived Data")),
        (12, _fixed("I062/040", "Track Number", 2, _track_number)),
        (13, _fx("I062/080", "Track Status")),
        (14, _compound("I062/290", "System Track Update Ages")),
        (15, _fixed("I062/200", "Mode of Movement", 1)),
        (16, _compound("I062/295", "Track Data Ages")),
        (17, _fixed("I062/136", "Measured Flight Level", 2, _flight_level)),
        (18, _fixed("I062/130", "Calculated Track Geometric Altitude", 2)),
        (19, _fixed("I062/135", "Calculated Track Barometric Altitude", 2)),
        (20, _fixed("I062/220", "Calculated Rate of Climb/Descent", 2)),
        (21, _compound("I062/390", "Flight Plan Related Data")),
        (22, _fx("I062/270", "Target Size and Orientation")),
        (23, _fixed("I062/300", "Vehicle Fleet Identification", 1)),
        (24, _compound("I062/110", "Mode 5 Data Reports and Extended Mode 1 Code")),
        (25, _fixed("I062/120", "Track Mode 2 Code", 2)),
        (26, _compound("I062/510", "Composed Track Number")),
        (27, _compound("I062/500", "Estimated Accuracies")),
        (28, _compound("I062/340", "Measured Information")),
        (34, _explicit("RE", "Reserved Expansion Field")),
        (35, _explicit("SP", "Special Purpose Field")),
    )),
    240: CategoryProfile(240, "1.3", "Radar Video Transmission", _uap(
        (1, _fixed("I240/010", "Data Source Identifier", 2, _dsi)),
        (2, _fixed("I240/000", "Message Type", 1, _message_type(_CAT240_TYPES))),
        (3, _fixed("I240/020", "Video Record Header Message Index", 4, _cat240_index)),
        (4, _rep("I240/030", "Video Summary", 1, _cat240_ascii)),
        (5, _fixed("I240/040", "Video Header Nanoseconds", 12, _cat240_header("ns"))),
        (6, _fixed("I240/041", "Video Header Femtoseconds", 12, _cat240_header("fs"))),
        (7, _fixed("I240/048", "Cell Resolution and Compression", 2, _cat240_resolution)),
        (8, _fixed("I240/049", "Video Octets and Cells", 5, _cat240_count)),
        (9, _rep("I240/050", "Low Data Volume", 4)),
        (10, _rep("I240/051", "Medium Data Volume", 64)),
        (11, _rep("I240/052", "High Data Volume", 256)),
        (12, _fixed("I240/140", "Time of Day", 3, _time_128)),
        (13, _explicit("RE", "Reserved Expansion Field")),
        (14, _explicit("SP", "Special Purpose Field")),
    )),
}


def _bounded_bytes(value: object, name: str, maximum: int = MAX_STREAM) -> bytes:
    if not isinstance(value, bytes) or not value or len(value) > maximum:
        raise AirSurvAsterixError(f"{name} must be 1..{maximum} immutable bytes")
    return value


def _category(value: object) -> CategoryProfile:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AirSurvAsterixError("category must be an integer")
    profile = CATEGORY_PROFILES.get(value)
    if profile is None:
        raise AirSurvAsterixError(f"unsupported ASTERIX category {value}")
    return profile


def _offset(value: object, length: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < length:
        raise AirSurvAsterixError("offset is outside the supplied bytes")
    return value


def _parse_fspec(data: bytes, offset: int) -> tuple[list[int], int, bytes]:
    start = offset
    frns: list[int] = []
    for extent in range(MAX_FSPEC_OCTETS):
        if offset >= len(data):
            raise AirSurvAsterixError("truncated FSPEC")
        octet = data[offset]
        offset += 1
        for index in range(7):
            if octet & (0x80 >> index):
                frns.append(extent * 7 + index + 1)
        if not octet & 1:
            return frns, offset, data[start:offset]
    raise AirSurvAsterixError("FSPEC exceeds the extent cap or never terminates")


def parse_fspec(data: bytes, offset: int = 0) -> dict[str, object]:
    """Decode one bounded FSPEC without interpreting category-specific items."""
    try:
        raw = _bounded_bytes(data, "FSPEC input", 65535)
        at = _offset(offset, len(raw))
        frns, end, encoded = _parse_fspec(raw, at)
        return {"frns": frns, "raw_hex": encoded.hex(), "length": end - at,
                "next_offset": end}
    except AirSurvAsterixError:
        raise
    except Exception as exc:
        raise AirSurvAsterixError(f"malformed FSPEC: {exc}") from exc


def _take(data: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    end = offset + size
    if size < 0 or end > len(data):
        raise AirSurvAsterixError(f"truncated {label}")
    return data[offset:end], end


def _item_bytes(data: bytes, offset: int, spec: ItemSpec) -> tuple[bytes, int, int | None]:
    if spec.kind == "fixed":
        raw, end = _take(data, offset, spec.size, spec.item)
        return raw, end, None
    if spec.kind == "fx":
        start = offset
        for _ in range(MAX_FX_OCTETS):
            octet, offset = _take(data, offset, 1, spec.item)
            if not octet[0] & 1:
                return data[start:offset], offset, None
        raise AirSurvAsterixError(f"{spec.item} FX chain exceeds the extent cap")
    if spec.kind == "repetitive":
        count_raw, at = _take(data, offset, 1, spec.item)
        count = count_raw[0]
        if count > spec.max_rep:
            raise AirSurvAsterixError(f"{spec.item} repetition count exceeds its profile cap")
        payload, end = _take(data, at, count * spec.unit, spec.item)
        return count_raw + payload, end, count
    if spec.kind == "explicit":
        length_raw, at = _take(data, offset, 1, spec.item)
        length = length_raw[0]
        if not 1 <= length <= MAX_EXPLICIT_OCTETS:
            raise AirSurvAsterixError(f"invalid explicit length for {spec.item}")
        rest, end = _take(data, at, length - 1, spec.item)
        return length_raw + rest, end, None
    if spec.kind == "compound":
        raise AirSurvAsterixError(
            f"{spec.item} is a compound item whose sub-UAP is intentionally unsupported"
        )
    raise AirSurvAsterixError(f"unsupported item kind for {spec.item}")


def _decode_record(profile: CategoryProfile, data: bytes, offset: int) -> tuple[dict[str, object], int]:
    start = offset
    frns, offset, fspec = _parse_fspec(data, offset)
    if not frns:
        raise AirSurvAsterixError("empty ASTERIX record FSPEC")
    items: list[dict[str, object]] = []
    for frn in frns:
        spec = profile.items.get(frn)
        if spec is None:
            raise AirSurvAsterixError(
                f"CAT{profile.category:03d} FRN {frn} is spare or unsupported; refusing to guess length"
            )
        raw, offset, repetitions = _item_bytes(data, offset, spec)
        row: dict[str, object] = {
            "frn": frn, "item": spec.item, "name": spec.name,
            "kind": spec.kind, "length": len(raw), "raw_hex": raw.hex(),
        }
        if repetitions is not None:
            row["repetitions"] = repetitions
            row["entries_hex"] = [
                raw[1 + index * spec.unit:1 + (index + 1) * spec.unit].hex()
                for index in range(repetitions)
            ]
        if spec.kind == "explicit":
            row["payload_hex"] = raw[1:].hex()
        if spec.decoder is not None:
            row.update(spec.decoder(raw))
        items.append(row)
    return {
        "category": profile.category, "edition": profile.edition,
        "fspec_hex": fspec.hex(), "frns": frns, "items": items,
        "offset": start, "length": offset - start, "next_offset": offset,
    }, offset


def decode_record(category: int, data: bytes, offset: int = 0) -> dict[str, object]:
    """Decode one record at ``offset`` using the selected current category UAP."""
    try:
        profile = _category(category)
        raw = _bounded_bytes(data, "record input", 65535)
        at = _offset(offset, len(raw))
        record, _ = _decode_record(profile, raw, at)
        return record
    except AirSurvAsterixError:
        raise
    except Exception as exc:
        raise AirSurvAsterixError(f"malformed ASTERIX record: {exc}") from exc


def _decode_block(raw: bytes) -> dict[str, object]:
    if len(raw) < 4:
        raise AirSurvAsterixError("ASTERIX block is truncated")
    declared = int.from_bytes(raw[1:3], "big")
    if declared != len(raw) or declared < 4:
        raise AirSurvAsterixError("ASTERIX LEN does not match the supplied block")
    profile = _category(raw[0])
    records: list[dict[str, object]] = []
    at = 3
    while at < len(raw):
        if len(records) >= MAX_RECORDS:
            raise AirSurvAsterixError("record count exceeds the cap")
        record, end = _decode_record(profile, raw, at)
        if end <= at:
            raise AirSurvAsterixError("record parser made no progress")
        records.append(record)
        at = end
    if not records:
        raise AirSurvAsterixError("ASTERIX block contains no records")
    return {"category": profile.category, "edition": profile.edition,
            "category_name": profile.name, "length": declared,
            "record_count": len(records), "records": records}


def decode_block(data: bytes) -> dict[str, object]:
    """Decode exactly one complete ASTERIX CAT/LEN data block."""
    try:
        return _decode_block(_bounded_bytes(data, "ASTERIX block", 65535))
    except AirSurvAsterixError:
        raise
    except Exception as exc:
        raise AirSurvAsterixError(f"malformed ASTERIX block: {exc}") from exc


def decode_stream(data: bytes) -> list[dict[str, object]]:
    """Decode concatenated ASTERIX data blocks without resynchronisation guesses."""
    try:
        raw = _bounded_bytes(data, "ASTERIX stream")
        blocks: list[dict[str, object]] = []
        at = 0
        while at < len(raw):
            if len(blocks) >= MAX_BLOCKS:
                raise AirSurvAsterixError("block count exceeds the cap")
            if at + 3 > len(raw):
                raise AirSurvAsterixError("truncated ASTERIX block header")
            length = int.from_bytes(raw[at + 1:at + 3], "big")
            if length < 4 or at + length > len(raw):
                raise AirSurvAsterixError("invalid or truncated ASTERIX block length")
            blocks.append(_decode_block(raw[at:at + length]))
            at += length
        return blocks
    except AirSurvAsterixError:
        raise
    except Exception as exc:
        raise AirSurvAsterixError(f"malformed ASTERIX stream: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decode a saved EUROCONTROL ASTERIX byte stream")
    parser.add_argument("input", help="raw concatenated ASTERIX data blocks")
    parser.add_argument("--json", action="store_true", help="pretty-print JSON")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        path = Path(args.input)
        with path.open("rb") as stream:
            raw = stream.read(MAX_STREAM + 1)
        result = decode_stream(raw)
        print(json.dumps(result, sort_keys=True, indent=2 if args.json else None))
        return 0
    except (AirSurvAsterixError, OSError, TypeError, ValueError, OverflowError,
            MemoryError, RecursionError) as exc:
        print(f"sec_airsurv_asterix: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "AirSurvAsterixError", "CATEGORY_PROFILES", "CategoryProfile", "ItemSpec",
    "decode_block", "decode_record", "decode_stream", "main", "parse_fspec",
]
