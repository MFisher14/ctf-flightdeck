#!/usr/bin/env python3
"""Passive ETSI TETRA air-burst and decoded-signalling inspector.

The module accepts only supplied, MSB-first packed bits.  It splits phase-
modulation bursts and parses caller-supplied post-FEC MAC/LLC/MLE/CMCE PDUs;
it does not demodulate IQ, recover keys, decrypt traffic, craft frames, open a
radio, or transmit.  TEDS/QAM and 3GPP MCX are reported as explicit handoffs.

Layouts follow ETSI TS 100 392-2 V3.10.1.  Security context follows ETSI
TS 100 392-7 and TS 104 053-1; the risk annotations reference TETRA:BURST and
ETSI TR 104 291.
"""
from __future__ import annotations

import argparse
import functools
import json
import sys
from pathlib import Path
from typing import Any


MAX_BITS = 16_384
MAX_FILE = (MAX_BITS + 7) // 8


class SecLmrTetraError(ValueError):
    """Malformed, unsupported, ambiguous, or over-limit TETRA artifact."""


def _closed(function):
    """Expose one stable exception type at every public parser boundary."""

    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecLmrTetraError:
            raise
        except Exception as exc:
            raise SecLmrTetraError(
                f"{function.__name__} failed: {type(exc).__name__}"
            ) from None

    return wrapped


def _packed_bits(data: object, bit_length: object, *, maximum: int = MAX_BITS) -> str:
    if type(data) is not bytes:
        raise SecLmrTetraError("input must be immutable packed bytes")
    if type(bit_length) is not int or not 1 <= bit_length <= maximum:
        raise SecLmrTetraError(f"bit length must be 1..{maximum}")
    if len(data) != (bit_length + 7) // 8:
        raise SecLmrTetraError("non-canonical packed-byte container")
    bits = "".join(f"{byte:08b}" for byte in data)
    if any(bit != "0" for bit in bits[bit_length:]):
        raise SecLmrTetraError("non-zero padding bits after declared bit length")
    return bits[:bit_length]


class _Bits:
    def __init__(self, bits: str):
        if type(bits) is not str or any(bit not in "01" for bit in bits):
            raise SecLmrTetraError("invalid internal bit stream")
        self.bits = bits
        self.at = 0

    @property
    def remaining(self) -> int:
        return len(self.bits) - self.at

    def take(self, width: int, name: str) -> int:
        if type(width) is not int or width < 0 or width > self.remaining:
            raise SecLmrTetraError(f"truncated {name}")
        value = int(self.bits[self.at:self.at + width], 2) if width else 0
        self.at += width
        return value

    def text(self, width: int, name: str) -> str:
        if type(width) is not int or width < 0 or width > self.remaining:
            raise SecLmrTetraError(f"truncated {name}")
        value = self.bits[self.at:self.at + width]
        self.at += width
        return value


def _field(bits: str, offset: int, length: int) -> dict[str, Any]:
    value = bits[offset:offset + length]
    if len(value) != length:
        raise SecLmrTetraError("internal burst field overruns input")
    digits = (length + 3) // 4
    return {
        "offset": offset,
        "length": length,
        "offset_bits": offset,
        "length_bits": length,
        "bits": value,
        "hex": f"{int(value, 2):0{digits}x}" if value else "",
    }


# ETSI TS 100 392-2 tables 9.3 through 9.12.  Each tuple is
# (field-name, width, semantic-kind); the ordering itself defines offsets.
_LAYOUTS: dict[tuple[str, str], tuple[tuple[str, int, str], ...]] = {
    ("cb", "pi/4"): (
        ("tail_prefix", 4, "tail"), ("control_1", 84, "control"),
        ("extended_training", 30, "extended_training"),
        ("control_2", 84, "control"), ("tail_suffix", 4, "tail"),
    ),
    ("cb", "pi/8"): (
        ("tail_prefix", 6, "tail_pi8"), ("control_1", 126, "control"),
        ("extended_training", 45, "extended_training_pi8"),
        ("control_2", 126, "control"), ("tail_suffix", 6, "tail_pi8"),
    ),
    ("nub", "pi/4"): (
        ("tail_prefix", 4, "tail"), ("block_1", 216, "block"),
        ("normal_training", 22, "normal_training"),
        ("block_2", 216, "block"), ("tail_suffix", 4, "tail"),
    ),
    ("nub", "pi/8"): (
        ("tail_prefix", 6, "tail_pi8"), ("block_1", 324, "block"),
        ("normal_training", 33, "normal_training_pi8"),
        ("block_2", 324, "block"), ("tail_suffix", 6, "tail_pi8"),
    ),
    ("ndb-cont", "pi/4"): (
        ("training_3_prefix", 12, "q_prefix_cont"), ("phase_a", 2, "phase"),
        ("block_1", 216, "block"), ("broadcast_1", 14, "broadcast"),
        ("normal_training", 22, "normal_training"),
        ("broadcast_2", 16, "broadcast"), ("block_2", 216, "block"),
        ("phase_b", 2, "phase"), ("training_3_suffix", 10, "q_suffix_cont"),
    ),
    ("ndb-cont", "pi/8"): (
        ("training_3_prefix", 12, "q_prefix_cont"), ("phase_a", 3, "phase"),
        ("block_1", 324, "block"), ("broadcast_1", 14, "broadcast"),
        ("normal_training", 33, "normal_training_pi8"),
        ("broadcast_2", 16, "broadcast"), ("block_2", 324, "block"),
        ("phase_b", 3, "phase"), ("training_3_suffix", 10, "q_suffix_cont"),
    ),
    ("sb-cont", "pi/4"): (
        ("training_3_prefix", 12, "q_prefix_cont"), ("phase_a", 2, "phase"),
        ("frequency_correction", 80, "frequency_correction"),
        ("sync_block_1", 120, "block"),
        ("sync_training", 38, "sync_training"),
        ("broadcast", 30, "broadcast"), ("block_2", 216, "block"),
        ("phase_b", 2, "phase"), ("training_3_suffix", 10, "q_suffix_cont"),
    ),
    ("ndb-disc", "pi/4"): (
        ("training_3_prefix", 2, "q_prefix_disc"), ("phase_a", 2, "phase"),
        ("block_1", 216, "block"), ("broadcast_1", 14, "broadcast"),
        ("normal_training", 22, "normal_training"),
        ("broadcast_2", 16, "broadcast"), ("block_2", 216, "block"),
        ("phase_b", 2, "phase"), ("training_3_suffix", 2, "q_suffix_disc"),
    ),
    ("ndb-disc", "pi/8"): (
        ("training_3_prefix", 2, "q_prefix_disc"), ("phase_a", 3, "phase"),
        ("block_1", 324, "block"), ("broadcast_1", 14, "broadcast"),
        ("normal_training", 33, "normal_training_pi8"),
        ("broadcast_2", 16, "broadcast"), ("block_2", 324, "block"),
        ("phase_b", 3, "phase"), ("training_3_suffix", 2, "q_suffix_disc"),
    ),
    ("sb-disc", "pi/4"): (
        ("training_3_prefix", 2, "q_prefix_disc"), ("phase_a", 2, "phase"),
        ("frequency_correction", 80, "frequency_correction"),
        ("sync_block_1", 120, "block"),
        ("sync_training", 38, "sync_training"),
        ("broadcast", 30, "broadcast"), ("block_2", 216, "block"),
        ("phase_b", 2, "phase"), ("training_3_suffix", 2, "q_suffix_disc"),
    ),
}

_NORMAL_1 = "1101000011101001110100"
_NORMAL_2 = "0111101001000011011110"
_NORMAL_3 = "1011011100000110101101"
_SYNC = "11000001100111001110100111000001100111"
_EXTENDED = "100111010000111010011101000011"
_TAIL = "1100"
_FREQUENCY = "11111111" + "0" * 64 + "11111111"

_BURST_NAMES = {
    "cb": "control uplink burst",
    "nub": "normal uplink burst",
    "ndb-cont": "normal continuous downlink burst",
    "sb-cont": "synchronization continuous downlink burst",
    "ndb-disc": "normal discontinuous downlink burst",
    "sb-disc": "synchronization discontinuous downlink burst",
}


def _layout_length(layout: tuple[tuple[str, int, str], ...]) -> int:
    return sum(width for _, width, _ in layout)


def _split_layout(bits: str, layout: tuple[tuple[str, int, str], ...]):
    fields: dict[str, dict[str, Any]] = {}
    kinds: dict[str, str] = {}
    offset = 0
    for name, width, kind in layout:
        fields[name] = _field(bits, offset, width)
        kinds[name] = kind
        offset += width
    if offset != len(bits):
        raise SecLmrTetraError("burst length does not match its ETSI layout")
    return fields, kinds


def _known_sequence(kind: str) -> tuple[str, tuple[str, ...]] | None:
    if kind == "tail":
        return "pi/4 tail", (_TAIL,)
    if kind == "extended_training":
        return "extended training", (_EXTENDED,)
    if kind == "normal_training":
        return "normal training 1/2", (_NORMAL_1, _NORMAL_2)
    if kind == "sync_training":
        return "synchronization training", (_SYNC,)
    if kind == "frequency_correction":
        return "frequency correction", (_FREQUENCY,)
    if kind == "q_prefix_cont":
        return "training 3 q11..q22", (_NORMAL_3[10:],)
    if kind == "q_suffix_cont":
        return "training 3 q1..q10", (_NORMAL_3[:10],)
    if kind == "q_prefix_disc":
        return "training 3 q21..q22", (_NORMAL_3[20:],)
    if kind == "q_suffix_disc":
        return "training 3 q1..q2", (_NORMAL_3[:2],)
    return None


def _sequence_checks(fields, kinds):
    checks = []
    for name, item in fields.items():
        expected = _known_sequence(kinds[name])
        if expected is None:
            continue
        label, values = expected
        observed = item["bits"]
        match = observed in values
        row: dict[str, Any] = {
            "field": name, "sequence": label, "valid": match,
            "observed": observed,
        }
        if kinds[name] == "normal_training" and match:
            row["variant"] = "normal-1" if observed == _NORMAL_1 else "normal-2"
        checks.append(row)
    return checks


def _candidate_report(bits: str, key: tuple[str, str]):
    layout = _LAYOUTS[key]
    fields, kinds = _split_layout(bits, layout)
    checks = _sequence_checks(fields, kinds)
    return fields, checks


@_closed
def parse_air_burst(
    data: bytes,
    bit_length: int | None = None,
    burst_type: str = "auto",
    modulation: str = "auto",
) -> dict[str, Any]:
    """Split one already-demodulated phase burst using exact ETSI offsets.

    Auto classification uses length and, for the ambiguous 510/492-bit normal
    versus synchronization cases, the published training/frequency sequences.
    Sequence mismatches in an explicitly selected layout are reported rather
    than hidden; no FEC, descrambling, or decryption is claimed.
    """

    if type(data) is not bytes:
        raise SecLmrTetraError("input must be immutable packed bytes")
    if bit_length is None:
        candidates = sorted({
            _layout_length(layout) for layout in _LAYOUTS.values()
            if (_layout_length(layout) + 7) // 8 == len(data)
        })
        if len(candidates) != 1:
            raise SecLmrTetraError("--bits is required for this byte length")
        bit_length = candidates[0]
    bits = _packed_bits(data, bit_length, maximum=739)
    if type(burst_type) is not str or burst_type not in {"auto", *_BURST_NAMES}:
        raise SecLmrTetraError("unknown burst type")
    if type(modulation) is not str or modulation not in {"auto", "pi/4", "pi/8"}:
        raise SecLmrTetraError("modulation must be auto, pi/4, or pi/8")

    candidates = []
    for key, layout in _LAYOUTS.items():
        if _layout_length(layout) != len(bits):
            continue
        if burst_type != "auto" and key[0] != burst_type:
            continue
        if modulation != "auto" and key[1] != modulation:
            continue
        candidates.append(key)
    if not candidates:
        raise SecLmrTetraError("bit length/type/modulation do not name an ETSI burst")

    selected = None
    rendered: dict[tuple[str, str], tuple[dict, list]] = {}
    if len(candidates) == 1:
        selected = candidates[0]
    else:
        valid = []
        for key in candidates:
            rendered[key] = _candidate_report(bits, key)
            checks = rendered[key][1]
            if checks and all(row["valid"] for row in checks):
                valid.append(key)
        if len(valid) != 1:
            raise SecLmrTetraError(
                "training sequences do not uniquely classify the burst; select a type"
            )
        selected = valid[0]

    fields, checks = rendered.get(selected, _candidate_report(bits, selected))
    training: dict[str, Any] = {}
    for row in checks:
        if row["sequence"] == "synchronization training":
            training["sync"] = row["valid"]
        elif row["sequence"] == "frequency correction":
            training["frequency_correction"] = row["valid"]
        elif row["sequence"] == "normal training 1/2":
            training["normal"] = row.get("variant") if row["valid"] else None
        elif row["sequence"] == "extended training":
            training["extended"] = row["valid"]
    # Keep the standard's long field name as a convenient alias.
    if "sync_training" in fields:
        fields["synchronization_training"] = fields["sync_training"]
    return {
        "protocol": "ETSI TETRA phase-modulation air burst",
        "trust_boundary": "raw already-demodulated burst; blocks remain scrambled/FEC-coded",
        "burst_type": selected[0],
        "burst_name": _BURST_NAMES[selected[0]],
        "modulation": selected[1],
        "bit_length": len(bits),
        "sequence_checks": checks,
        "training": training,
        "training_valid": all(row["valid"] for row in checks) if checks else None,
        "fields": fields,
    }


_ADDRESS_WIDTHS = {0: 0, 1: 24, 2: 10, 3: 24, 4: 24, 5: 34, 6: 30, 7: 34}
_ADDRESS_NAMES = {
    0: "null", 1: "SSI", 2: "event-label", 3: "USSI", 4: "SMI",
    5: "SSI+event-label", 6: "SSI+usage-marker", 7: "SMI+event-label",
}
_ENCRYPTION_MODES = {
    0: "clear", 1: "static-cipher-key", 2: "derived-cipher-key", 3: "common-cipher-key",
}


def _length_meaning(value: int, modulation: str) -> dict[str, Any]:
    if value in (0, 0x3B, 0x3C):
        raise SecLmrTetraError("reserved MAC length indication")
    if value == 0x3D:
        if modulation != "qam":
            raise SecLmrTetraError("QAM-only MAC length indication on phase modulation")
        return {"kind": "qam-special"}
    if value == 0x3E:
        return {"kind": "second-half-slot-stolen"}
    if value == 0x3F:
        return {"kind": "fragment-start"}
    return {"kind": "length", "coded_block_units": value}


def _parse_address(reader: _Bits, address_type: int) -> dict[str, Any]:
    width = _ADDRESS_WIDTHS[address_type]
    value = reader.take(width, "MAC address") if width else 0
    out: dict[str, Any] = {"type": address_type, "name": _ADDRESS_NAMES[address_type]}
    if address_type in (1, 3, 4):
        out[_ADDRESS_NAMES[address_type].lower()] = value
    elif address_type == 2:
        out["event_label"] = value
    elif address_type in (5, 7):
        out["ssi" if address_type == 5 else "smi"] = value >> 10
        out["event_label"] = value & 0x3FF
    elif address_type == 6:
        out["ssi"] = value >> 6
        out["usage_marker"] = value & 0x3F
    return out


def _parse_channel_allocation(reader: _Bits) -> dict[str, Any]:
    out = {
        "allocation_type": reader.take(2, "channel allocation type"),
        "timeslot": reader.take(4, "channel allocation timeslot"),
        "uplink_downlink_assignment": reader.take(2, "uplink/downlink assignment"),
        "clch_permission": bool(reader.take(1, "CLCH permission")),
        "cell_change_flag": bool(reader.take(1, "cell change flag")),
        "carrier_number": reader.take(12, "carrier number"),
    }
    extended = bool(reader.take(1, "extended carrier present"))
    out["extended_carrier_present"] = extended
    if extended:
        out["extended_carrier"] = {
            "frequency_band": reader.take(4, "extended frequency band"),
            "frequency_offset": reader.take(2, "extended frequency offset"),
            "duplex_spacing": reader.take(3, "extended duplex spacing"),
            "reverse_operation": bool(reader.take(1, "extended reverse operation")),
        }
    pattern = reader.take(2, "monitoring pattern")
    out["monitoring_pattern"] = pattern
    if pattern == 0:
        out["frame_18_monitoring_pattern"] = reader.take(2, "frame-18 monitoring pattern")
    if out["uplink_downlink_assignment"] == 0:
        augmented = {
            "uplink_downlink_assignment": reader.take(2, "augmented assignment"),
            "bandwidth": reader.take(3, "augmented bandwidth"),
            "modulation": reader.take(3, "augmented modulation"),
            "maximum_uplink_qam": reader.take(3, "maximum uplink QAM"),
            "reserved_1": reader.take(3, "augmented reserved bits"),
            "conforming_channel_status": reader.take(3, "conforming channel status"),
            "base_station_imbalance": reader.take(4, "base-station imbalance"),
            "base_station_tx_relative": reader.take(5, "base-station relative TX"),
            "napping_status": reader.take(2, "napping status"),
        }
        if augmented["napping_status"] == 1:
            augmented["napping_information"] = reader.take(11, "napping information")
        augmented["reserved_2"] = reader.take(4, "augmented reserved bits")
        if reader.take(1, "conditional element A present"):
            augmented["conditional_element_a"] = reader.take(16, "conditional element A")
        if reader.take(1, "conditional element B present"):
            augmented["conditional_element_b"] = reader.take(16, "conditional element B")
        augmented["reserved_tail"] = reader.take(1, "augmented reserved tail")
        out["augmented"] = augmented
    return out


def _parse_mac_resource(reader: _Bits, modulation: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "fill_bit": reader.take(1, "fill bit"),
        "grant_position": reader.take(1, "grant position"),
        "encryption_mode": reader.take(2, "encryption mode"),
        "random_access_flag": bool(reader.take(1, "random access flag")),
    }
    out["encryption_mode_name"] = _ENCRYPTION_MODES[out["encryption_mode"]]
    length = reader.take(6, "length indication")
    out["length_indication"] = length
    out["length_meaning"] = _length_meaning(length, modulation)
    address_type = reader.take(3, "address type")
    out["address"] = _parse_address(reader, address_type)
    if address_type == 0:
        out["header_ends_at_null_address"] = True
        out["tm_sdu_bits"] = reader.text(reader.remaining, "TM-SDU")
        return out
    if modulation in ("pi/8", "qam"):
        out["immediate_napping"] = bool(reader.take(1, "immediate napping"))
    power = bool(reader.take(1, "power control present"))
    out["power_control_present"] = power
    if power:
        out["power_control"] = reader.take(4, "power control")
    grant = bool(reader.take(1, "slot granting present"))
    out["slot_granting_present"] = grant
    if grant:
        if modulation == "qam":
            raise SecLmrTetraError("variable QAM multiple-slot granting is not decoded")
        out["slot_granting"] = {
            "number_of_slots_code": reader.take(4, "number-of-slots code"),
            "delay": reader.take(4, "slot-granting delay"),
        }
    allocation = bool(reader.take(1, "channel allocation present"))
    out["channel_allocation_present"] = allocation
    if allocation and out["encryption_mode"] == 0:
        out["channel_allocation"] = _parse_channel_allocation(reader)
    elif allocation:
        out["channel_allocation"] = None
        out["encrypted_remainder_opaque"] = True
    out["tm_sdu_bits"] = reader.text(reader.remaining, "TM-SDU")
    return out


def _parse_sysinfo(reader: _Bits, modulation: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "main_carrier": reader.take(12, "main carrier"),
        "frequency_band": reader.take(4, "frequency band"),
        "frequency_offset": reader.take(2, "frequency offset"),
        "duplex_spacing": reader.take(3, "duplex spacing"),
        "reverse_operation": bool(reader.take(1, "reverse operation")),
        "common_secondary_control_channels": reader.take(2, "common SCCH count"),
        "maximum_mobile_tx_power": reader.take(3, "maximum mobile TX power"),
        "minimum_access_rx_level": reader.take(4, "minimum access RX level"),
        "access_parameter": reader.take(4, "access parameter"),
        "radio_downlink_timeout": reader.take(4, "radio downlink timeout"),
    }
    cck = bool(reader.take(1, "CCK/hyperframe selector"))
    out["cck_identifier_valid"] = cck
    number = reader.take(16, "CCK identifier or hyperframe")
    out["cck_identifier" if cck else "hyperframe_number"] = number
    option = reader.take(2, "optional-field selector")
    option_names = {0: "even-multiframe", 1: "odd-multiframe", 2: "access-code", 3: "extended-services"}
    out["optional_field"] = {"type": option, "name": option_names[option], "value": reader.take(20, "optional field")}
    if modulation == "pi/8":
        reserved = reader.text(28, "pi/8 SYSINFO reserved field")
        out["pi8_reserved_bits"] = reserved
        out["pi8_reserved_zero"] = "1" not in reserved
    elif modulation == "qam":
        raise SecLmrTetraError("SYSINFO-Q uses a different TEDS grammar")
    out["mle_system_information"] = {
        "location_area": reader.take(14, "MLE location area"),
        "subscriber_class": reader.take(16, "MLE subscriber class"),
        "base_station_service_details": reader.take(12, "MLE service details"),
    }
    out["trailing_bits"] = reader.text(reader.remaining, "SYSINFO trailing bits")
    return out


@_closed
def parse_mac_pdu(
    data: bytes,
    bit_length: int,
    direction: str = "downlink",
    modulation: str = "pi/4",
) -> dict[str, Any]:
    """Parse a caller-supplied, post-channel-decoding TETRA MAC PDU."""

    if type(direction) is not str or direction not in ("downlink", "uplink"):
        raise SecLmrTetraError("direction must be downlink or uplink")
    if type(modulation) is not str or modulation not in ("pi/4", "pi/8", "qam"):
        raise SecLmrTetraError("modulation must be pi/4, pi/8, or qam")
    bits = _packed_bits(data, bit_length)
    reader = _Bits(bits)
    pdu_type = reader.take(2, "MAC PDU type")
    names = {
        "downlink": ("MAC-RESOURCE", "MAC-FRAG/MAC-END", "BROADCAST", "SUPPLEMENTARY"),
        "uplink": ("MAC-DATA", "MAC-FRAG/MAC-END", "reserved-broadcast", "MAC-U-SIGNAL"),
    }
    out: dict[str, Any] = {
        "protocol": "ETSI TETRA MAC",
        "trust_boundary": "caller-supplied post-FEC/descrambling PDU",
        "direction": direction,
        "modulation": modulation,
        "pdu_type": pdu_type,
        "pdu_name": names[direction][pdu_type],
        "bit_length": len(bits),
    }
    if direction == "downlink" and pdu_type == 0:
        out["resource"] = _parse_mac_resource(reader, modulation)
        resource = out["resource"]
        out["encryption_mode"] = resource["encryption_mode"]
        detailed_address = resource["address"]
        address_value = next((detailed_address[key] for key in
                              ("ssi", "ussi", "smi", "event_label")
                              if key in detailed_address), None)
        out["address"] = {
            "type": detailed_address["name"],
            "value": address_value,
        }
        if "event_label" in detailed_address and detailed_address["name"] not in ("event-label",):
            out["address"]["event_label"] = detailed_address["event_label"]
        if "usage_marker" in detailed_address:
            out["address"]["usage_marker"] = detailed_address["usage_marker"]
        if "power_control" in resource:
            out["power_control"] = resource["power_control"]
        if "slot_granting" in resource:
            grant = resource["slot_granting"]
            out["slot_grant"] = (grant["number_of_slots_code"] << 4) | grant["delay"]
    elif direction == "downlink" and pdu_type == 2:
        subtype = reader.take(2, "broadcast subtype")
        subtype_names = {0: "SYSINFO", 1: "ACCESS-DEFINE", 2: "SYSINFO-DA", 3: "reserved"}
        out["broadcast_subtype"] = subtype
        out["broadcast_name"] = subtype_names[subtype]
        if subtype == 0:
            out["system_information"] = _parse_sysinfo(reader, modulation)
            system = out["system_information"]
            out["main_carrier"] = system["main_carrier"]
            mle = system["mle_system_information"]
            out["mle"] = {
                "location_area": mle["location_area"],
                "subscriber_class": mle["subscriber_class"],
                "service_details": mle["base_station_service_details"],
            }
        else:
            out["payload_bits"] = reader.text(reader.remaining, "broadcast payload")
    else:
        out["payload_bits"] = reader.text(reader.remaining, "MAC payload")
    return out


_LLC_NAMES = {
    0: "BL-ADATA", 1: "BL-DATA", 2: "BL-UDATA", 3: "BL-ACK",
    4: "BL-ADATA-FCS", 5: "BL-DATA-FCS", 6: "BL-UDATA-FCS", 7: "BL-ACK-FCS",
    8: "AL-SETUP", 9: "AL-DATA/FINAL", 10: "AL-UDATA/UFINAL",
    11: "AL-ACK/RNR", 12: "AL-RECONNECT", 13: "AL-SUPPLEMENTARY",
    14: "AL-L2SIG", 15: "AL-DISC",
}


def _llc_fcs(bits: str) -> int:
    crc = 0xFFFFFFFF
    if len(bits) < 32:
        crc = (crc << (32 - len(bits))) & 0xFFFFFFFF
    for char in bits:
        feedback = int(char) ^ ((crc >> 31) & 1)
        crc = (crc << 1) & 0xFFFFFFFF
        if feedback:
            crc ^= 0x04C11DB7
    return (~crc) & 0xFFFFFFFF


@_closed
def parse_llc_pdu(data: bytes, bit_length: int) -> dict[str, Any]:
    """Parse one post-MAC TETRA LLC PDU and validate basic-link FCS."""

    bits = _packed_bits(data, bit_length)
    reader = _Bits(bits)
    pdu_type = reader.take(4, "LLC PDU type")
    out: dict[str, Any] = {
        "protocol": "ETSI TETRA LLC",
        "trust_boundary": "caller-supplied decoded LLC PDU",
        "pdu_type": pdu_type,
        "pdu_name": _LLC_NAMES[pdu_type],
        "bit_length": len(bits),
    }
    if pdu_type <= 7:
        basic = pdu_type & 3
        if basic == 0:
            out["receive_sequence"] = reader.take(1, "receive sequence")
            out["send_sequence"] = reader.take(1, "send sequence")
        elif basic == 1:
            out["send_sequence"] = reader.take(1, "send sequence")
        elif basic == 3:
            out["receive_sequence"] = reader.take(1, "receive sequence")
        has_fcs = pdu_type >= 4
        if has_fcs and reader.remaining < 32:
            raise SecLmrTetraError("truncated LLC FCS")
        payload_width = reader.remaining - (32 if has_fcs else 0)
        payload = reader.text(payload_width, "TL-SDU")
        out["tl_sdu_bits"] = payload
        out["payload_bits"] = payload
        if "receive_sequence" in out:
            out["nr"] = out["receive_sequence"]
        if "send_sequence" in out:
            out["ns"] = out["send_sequence"]
        out["fcs_present"] = has_fcs
        if has_fcs:
            received = reader.take(32, "LLC FCS")
            computed = _llc_fcs(payload)
            out.update(fcs=f"{received:08x}", computed_fcs=f"{computed:08x}",
                       fcs_valid=received == computed)
    elif pdu_type == 9:
        final = bool(reader.take(1, "AL final flag"))
        out["decoded_name"] = "AL-FINAL" if final else "AL-DATA"
        out["ar_or_reserved"] = reader.take(1, "AL AR/reserved flag")
        out["send_sequence"] = reader.take(3, "AL send sequence")
        out["segment_sequence"] = reader.take(8, "AL segment sequence")
        out["tl_sdu_bits"] = reader.text(reader.remaining, "AL payload")
        if final:
            out["fcs_note"] = "final FCS requires reassembled AL SDU"
    elif pdu_type == 10:
        final = bool(reader.take(1, "AL unnumbered-final flag"))
        out["decoded_name"] = "AL-UFINAL" if final else "AL-UDATA"
        out["send_sequence"] = reader.take(8, "AL send sequence")
        out["segment_sequence"] = reader.take(8, "AL segment sequence")
        out["tl_sdu_bits"] = reader.text(reader.remaining, "AL payload")
        if final:
            out["fcs_note"] = "final FCS requires reassembled AL SDU"
    else:
        out["payload_bits"] = reader.text(reader.remaining, "LLC payload")
    return out


_DISCRIMINATORS = {
    0: "reserved", 1: "MM", 2: "CMCE", 3: "reserved", 4: "SNDCP",
    5: "MLE", 6: "management", 7: "test-reserved",
}
_MLE_DOWNLINK = {
    0: "D-NEW-CELL", 1: "D-PREPARE-FAIL", 2: "D-NETWORK-BROADCAST",
    3: "D-NETWORK-BROADCAST-EXT", 4: "D-RESTORE-ACK",
    5: "D-RESTORE-FAIL", 6: "D-CHANNEL-RESPONSE", 7: "D-EXTENDED",
}
_MLE_UPLINK = {
    0: "U-PREPARE", 1: "U-PREPARE-DA", 2: "U-IRREGULAR-CHANNEL-ADVICE",
    3: "U-CHANNEL-CLASS-ADVICE", 4: "U-RESTORE", 5: "reserved",
    6: "U-CHANNEL-REQUEST", 7: "U-EXTENDED",
}
_CMCE_DOWNLINK = {
    0: "D-ALERT", 1: "D-CALL-PROCEEDING", 2: "D-CONNECT", 3: "D-CONNECT-ACK",
    4: "D-DISCONNECT", 5: "D-INFO", 6: "D-RELEASE", 7: "D-SETUP",
    8: "D-STATUS", 9: "D-TX-CEASED", 10: "D-TX-CONTINUE", 11: "D-TX-GRANTED",
    12: "D-TX-WAIT", 13: "D-TX-INTERRUPT", 14: "D-CALL-RESTORE",
    15: "D-SDS-DATA", 16: "D-FACILITY", 31: "unsupported",
}
_CMCE_UPLINK = {
    0: "U-ALERT", 2: "U-CONNECT", 4: "U-DISCONNECT", 5: "U-INFO",
    6: "U-RELEASE", 7: "U-SETUP", 8: "U-STATUS", 9: "U-TX-CEASED",
    10: "U-TX-DEMAND", 14: "U-CALL-RESTORE", 15: "U-SDS-DATA",
    16: "U-FACILITY", 31: "unsupported",
}


@_closed
def parse_mle_pdu(data: bytes, bit_length: int, direction: str = "downlink") -> dict[str, Any]:
    """Dispatch a decoded TL-SDU to MLE or CMCE with bounded header parsing."""

    if type(direction) is not str or direction not in ("downlink", "uplink"):
        raise SecLmrTetraError("direction must be downlink or uplink")
    bits = _packed_bits(data, bit_length)
    reader = _Bits(bits)
    discriminator = reader.take(3, "MLE protocol discriminator")
    out: dict[str, Any] = {
        "protocol": "ETSI TETRA MLE service data unit",
        "trust_boundary": "caller-supplied post-LLC clear TL-SDU",
        "direction": direction,
        "protocol_discriminator": discriminator,
        "protocol_name": _DISCRIMINATORS[discriminator],
        "bit_length": len(bits),
    }
    if discriminator == 5:
        pdu_type = reader.take(3, "MLE PDU type")
        names = _MLE_DOWNLINK if direction == "downlink" else _MLE_UPLINK
        out["mle"] = {"pdu_type": pdu_type, "pdu_name": names[pdu_type]}
        if pdu_type == 7:
            out["mle"]["extension"] = reader.take(4, "MLE extension")
        out["mle"]["payload_bits"] = reader.text(reader.remaining, "MLE payload")
    elif discriminator == 2:
        pdu_type = reader.take(5, "CMCE PDU type")
        names = _CMCE_DOWNLINK if direction == "downlink" else _CMCE_UPLINK
        out["cmce"] = {
            "pdu_type": pdu_type,
            "pdu_name": names.get(pdu_type, "reserved"),
        }
        if direction == "downlink" and pdu_type == 7:
            out["cmce"]["setup"] = {
                "call_identifier": reader.take(14, "call identifier"),
                "call_timeout": reader.take(4, "call timeout"),
                "hook_method": reader.take(1, "hook method"),
                "simplex_duplex": reader.take(1, "simplex/duplex"),
                "basic_service": reader.take(8, "basic service"),
                "transmission_grant": reader.take(2, "transmission grant"),
                "transmission_request_permission": bool(reader.take(1, "TX request permission")),
                "call_priority": reader.take(4, "call priority"),
            }
            setup = out["cmce"]["setup"]
            out["cmce"].update(setup)
            out["cmce"]["priority"] = setup["call_priority"]
        remainder = reader.text(reader.remaining, "CMCE suffix")
        out["cmce"]["optional_or_payload_bits"] = remainder
        out["cmce"]["remainder_bits"] = remainder
    else:
        out["payload_bits"] = reader.text(reader.remaining, "TL-SDU payload")
    return out


_TEA = {
    "TEA1": {
        "ksg_number": 0, "effective_key_bits": 32,
        "deployment": "general/worldwide export-oriented",
        "risk": "intentional 80-to-32-bit reduction; CVE-2022-24402",
    },
    "TEA2": {
        "ksg_number": 1, "effective_key_bits": 80,
        "deployment": "European public-safety/security restricted use",
        "risk": "unreduced key; AIE still lacks ciphertext authentication",
    },
    "TEA3": {
        "ksg_number": 2, "effective_key_bits": 80,
        "deployment": "public-safety/security outside Europe",
        "risk": "unreduced key; AIE still lacks ciphertext authentication",
    },
    "TEA4": {
        "ksg_number": 3, "effective_key_bits": 56,
        "deployment": "general/worldwide export-oriented",
        "risk": "80-to-56-bit effective reduction confirmed by ETSI TR 104 291",
    },
}


@_closed
def tea_context(algorithm: str | int) -> dict[str, Any]:
    """Return non-secret TEA1–4 keystream parameters and defensive context."""

    if type(algorithm) is int and not isinstance(algorithm, bool):
        if algorithm not in range(4):
            raise SecLmrTetraError("TEA KSG number must be 0..3")
        name = f"TEA{algorithm + 1}"
    elif type(algorithm) is str:
        name = algorithm.upper()
        if name not in _TEA:
            raise SecLmrTetraError("algorithm must be TEA1, TEA2, TEA3, or TEA4")
    else:
        raise SecLmrTetraError("algorithm must be a TEA name or KSG number")
    item = _TEA[name]
    return {
        "protocol": "TETRA air-interface encryption context",
        "algorithm": name,
        "ksg_number": item["ksg_number"],
        "nominal_cipher_key_bits": 80,
        "cipher_key_bits": 80,
        "effective_key_bits": item["effective_key_bits"],
        "initialization_vector_bits": 29,
        "iv_bits": 29,
        "iv_components_lsb_indexed": {
            "timeslot": {"bits": [0, 1], "encoding": "0..3 represent slots 1..4"},
            "frame": {"bits": [2, 6], "range": "1..18"},
            "multiframe": {"bits": [7, 12], "range": "1..60"},
            "hyperframe_low_15": {"bits": [13, 27]},
            "direction": {"bit": 28, "zero": "downlink", "one": "uplink"},
        },
        "operation": "per-burst synchronous keystream XOR",
        "deployment": item["deployment"],
        "risk": item["risk"],
        "common_tetraburst_context": [
            "CVE-2022-24401 unauthenticated network-time/keystream oracle",
            "CVE-2022-24404 unauthenticated AIE ciphertext malleability",
        ],
        "limitations": [
            "MAC encryption-mode does not identify the selected TEA algorithm",
            "keys are not present in an air burst",
            "this engine performs no key search, keystream generation, or decryption",
        ],
    }


@_closed
def evolution_context() -> dict[str, Any]:
    """Describe the TEDS and MCX-over-5G boundaries without mis-decoding them."""

    return {
        "protocol": "TETRA evolution context",
        "phase_modulation": {
            "uplink_bursts": [
                "CB control", "LB linearization (no useful bits)", "NUB normal"
            ],
            "downlink_bursts": [
                "NDB normal", "SB synchronization",
                "LDB linearization replacement (no useful bits)",
            ],
            "parser_scope": (
                "CB/NUB plus continuous and discontinuous NDB/SB; "
                "linearization bursts have no protocol payload to split"
            ),
        },
        "teds": {
            "name": "TETRA Enhanced Data Service (TEDS)",
            "standard_context": "TETRA Release 2 / ETSI TS 100 392-2 and TR 102 300-7",
            "channel_bandwidth_khz": [25, 50, 100, 150],
            "modulations": ["pi/8-D8PSK", "4-QAM", "16-QAM", "64-QAM"],
            "timing": "retains four-slot TETRA TDMA",
            "parser_boundary": "raw multi-subcarrier QAM symbols are not phase-burst decoded here",
        },
        "mcx_over_5g": {
            "name": "MCX over 5G",
            "services": ["MCPTT", "MCData", "MCVideo"],
            "architecture": "3GPP TS 23.280 (common), TS 23.289 (5GS)",
            "interworking": "3GPP TS 23.283 / ETSI TS 100 392-19-1 IWF",
            "media_floor_control": "3GPP TS 24.380 RTCP application profile",
            "parser_boundary": "MCX is an IMS/IP service stack, not a TETRA air-burst type",
        },
    }


def _read_file(path: str) -> bytes:
    candidate = Path(path)
    if not candidate.is_file() or candidate.stat().st_size > MAX_FILE:
        raise SecLmrTetraError(f"input is absent or exceeds {MAX_FILE}-byte cap")
    return candidate.read_bytes()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive offline ETSI TETRA inspector")
    sub = parser.add_subparsers(dest="command", required=True)

    burst = sub.add_parser("burst", help="split one packed phase-modulation air burst")
    burst.add_argument("file")
    burst.add_argument("--bits", type=int)
    burst.add_argument("--type", dest="burst_type", choices=("auto", *_BURST_NAMES), default="auto")
    burst.add_argument("--modulation", choices=("auto", "pi/4", "pi/8"), default="auto")

    mac = sub.add_parser("mac", help="parse one post-FEC MAC PDU")
    mac.add_argument("file")
    mac.add_argument("--bits", type=int, required=True)
    mac.add_argument("--direction", choices=("downlink", "uplink"), default="downlink")
    mac.add_argument("--modulation", choices=("pi/4", "pi/8", "qam"), default="pi/4")

    llc = sub.add_parser("llc", help="parse one decoded LLC PDU")
    llc.add_argument("file")
    llc.add_argument("--bits", type=int, required=True)

    mle = sub.add_parser("mle", help="parse one MLE/CMCE TL-SDU")
    mle.add_argument("file")
    mle.add_argument("--bits", type=int, required=True)
    mle.add_argument("--direction", choices=("downlink", "uplink"), default="downlink")

    tea = sub.add_parser("tea", help="report TEA1-4 defensive keystream context")
    tea.add_argument("algorithm", choices=tuple(_TEA))
    sub.add_parser("evolution", help="report TEDS and MCX-over-5G handoff context")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.command == "burst":
            result = parse_air_burst(
                _read_file(args.file), args.bits, args.burst_type, args.modulation
            )
        elif args.command == "mac":
            result = parse_mac_pdu(
                _read_file(args.file), args.bits, args.direction, args.modulation
            )
        elif args.command == "llc":
            result = parse_llc_pdu(_read_file(args.file), args.bits)
        elif args.command == "mle":
            result = parse_mle_pdu(_read_file(args.file), args.bits, args.direction)
        elif args.command == "tea":
            result = tea_context(args.algorithm)
        else:
            result = evolution_context()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, SecLmrTetraError) as exc:
        print(f"sec_lmr_tetra: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_BITS", "SecLmrTetraError", "evolution_context", "main",
    "parse_air_burst", "parse_llc_pdu", "parse_mac_pdu", "parse_mle_pdu",
    "tea_context",
]
