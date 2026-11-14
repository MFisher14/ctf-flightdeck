#!/usr/bin/env python3
"""Offline decoders for already-demodulated GNSS navigation messages.

The reader covers GPS LNAV/CNAV and post-FEC CNAV-2, Galileo I/NAV,
GLONASS legacy L1OF strings, and BeiDou D1/D2 plus post-FEC B-CNAV2.
It accepts supplied bits only: it does not acquire a signal, control a radio,
solve a position, or transmit anything.

References: IS-GPS-200N/705J/800J, Galileo OS SIS ICD, GLONASS ICD 5.1,
and the BeiDou B1I/B3I/B1C/B2a SIS ICD family.
"""

from __future__ import annotations

import argparse
from functools import wraps
import json
from pathlib import Path
import sys
from typing import Any, Callable, Iterable


MAX_INPUT = 8192


class SecGNSSNavError(ValueError):
    """Malformed, excessive, contradictory, or integrity-invalid GNSS input."""


def _declared(function: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except SecGNSSNavError:
            raise
        except Exception as exc:
            raise SecGNSSNavError(f"invalid {function.__name__} input") from exc
    return guarded


def _buffer(value: object, name: str = "input") -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecGNSSNavError(f"{name} must be a byte buffer")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        raw = bytes(value)
    except (BufferError, TypeError, ValueError) as exc:
        raise SecGNSSNavError(f"invalid {name} byte buffer") from exc
    if size != len(raw) or len(raw) > MAX_INPUT:
        raise SecGNSSNavError(f"invalid or excessive {name}")
    return raw


def _packing(value: object) -> str:
    if type(value) is not str or value not in ("bits", "msb0"):
        raise SecGNSSNavError("packing must be bits or msb0")
    return value


def _exact_bits(data: object, expected: int, *, packing: object = "msb0",
                bit_length: object = None) -> list[int]:
    mode = _packing(packing)
    if bit_length is not None and (type(bit_length) is not int or bit_length != expected):
        raise SecGNSSNavError(f"bit_length must be exactly {expected}")
    if mode == "bits":
        if isinstance(data, str):
            if len(data) > MAX_INPUT * 8:
                raise SecGNSSNavError("excessive ASCII bit input")
            text = data
        else:
            raw = _buffer(data, "ASCII bit input")
            try:
                text = raw.decode("ascii")
            except UnicodeError as exc:
                raise SecGNSSNavError("bit input is not ASCII") from exc
        compact = "".join(text.split())
        if len(compact) != expected or any(ch not in "01" for ch in compact):
            raise SecGNSSNavError(f"expected exactly {expected} binary digits")
        return [ord(ch) - 48 for ch in compact]
    raw = _buffer(data, "packed bit input")
    needed = (expected + 7) // 8
    if len(raw) != needed:
        raise SecGNSSNavError(f"packed input must be exactly {needed} bytes")
    padding = needed * 8 - expected
    if padding and raw[-1] & ((1 << padding) - 1):
        raise SecGNSSNavError("nonzero unused low padding bits")
    return [((octet >> shift) & 1) for octet in raw
            for shift in range(7, -1, -1)][:expected]


def _variable_bits(data: object, *, packing: object = "msb0",
                   bit_length: object = None) -> list[int]:
    mode = _packing(packing)
    if mode == "bits":
        if isinstance(data, str):
            if len(data) > MAX_INPUT * 8:
                raise SecGNSSNavError("excessive ASCII bit input")
            text = data
        else:
            try:
                text = _buffer(data, "ASCII bit input").decode("ascii")
            except UnicodeError as exc:
                raise SecGNSSNavError("bit input is not ASCII") from exc
        compact = "".join(text.split())
        if not compact or len(compact) > MAX_INPUT * 8 or any(ch not in "01" for ch in compact):
            raise SecGNSSNavError("invalid or excessive binary digits")
        if bit_length is not None and (type(bit_length) is not int or bit_length != len(compact)):
            raise SecGNSSNavError("bit_length disagrees with ASCII bits")
        return [ord(ch) - 48 for ch in compact]
    raw = _buffer(data, "packed bit input")
    if not raw:
        raise SecGNSSNavError("empty packed bit input")
    length = len(raw) * 8 if bit_length is None else bit_length
    if type(length) is not int or not 1 <= length <= len(raw) * 8:
        raise SecGNSSNavError("invalid bit_length")
    if len(raw) != (length + 7) // 8:
        raise SecGNSSNavError("bit_length has redundant packed bytes")
    padding = len(raw) * 8 - length
    if padding and raw[-1] & ((1 << padding) - 1):
        raise SecGNSSNavError("nonzero unused low padding bits")
    return [((octet >> shift) & 1) for octet in raw
            for shift in range(7, -1, -1)][:length]


def _uint(bits: Iterable[int]) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _twos(value: int, width: int) -> int:
    return value - (1 << width) if value & (1 << (width - 1)) else value


def _sign_magnitude(value: int, width: int) -> int:
    magnitude = value & ((1 << (width - 1)) - 1)
    return -magnitude if value & (1 << (width - 1)) else magnitude


def _crc24q_value(bits: Iterable[int]) -> int:
    register = 0
    for bit in bits:
        feedback = ((register >> 23) & 1) ^ bit
        register = (register << 1) & 0xFFFFFF
        if feedback:
            register ^= 0x864CFB
    return register


@_declared
def crc24q(data: object, *, packing: object = "msb0",
           bit_length: object = None) -> int:
    """Return CRC-24Q over an arbitrary supplied bit sequence."""
    return _crc24q_value(_variable_bits(data, packing=packing, bit_length=bit_length))


def _lnav_parity(data: list[int], previous_d29: int,
                 previous_d30: int) -> list[int]:
    sets = (
        (1, 2, 3, 5, 6, 10, 11, 12, 13, 14, 17, 18, 20, 23),
        (2, 3, 4, 6, 7, 11, 12, 13, 14, 15, 18, 19, 21, 24),
        (1, 3, 4, 5, 7, 8, 12, 13, 14, 15, 16, 19, 20, 22),
        (2, 4, 5, 6, 8, 9, 13, 14, 15, 16, 17, 20, 21, 23),
        (1, 3, 5, 6, 7, 9, 10, 14, 15, 16, 17, 18, 21, 22, 24),
        (3, 5, 6, 8, 9, 10, 11, 13, 15, 19, 22, 23, 24),
    )
    seeds = (previous_d29, previous_d30, previous_d29,
             previous_d30, previous_d30, previous_d29)
    return [seeds[index] ^ sum(data[position - 1] for position in positions) % 2
            for index, positions in enumerate(sets)]


def _word_field(word: list[int], low: int, high: int) -> int:
    return _uint(word[low - 1:high])


def _decode_lnav_fields(words: list[list[int]], subframe_id: int) -> dict[str, Any]:
    w = lambda number, low, high: _word_field(words[number - 1], low, high)
    if subframe_id == 1:
        iodc = (w(3, 23, 24) << 8) | w(8, 1, 8)
        return {
            "kind": "clock_and_health", "week_number_mod_1024": w(3, 1, 10),
            "code_on_l2": w(3, 11, 12), "ura_index": w(3, 13, 16),
            "sv_health": w(3, 17, 22), "iodc": iodc,
            "tgd_seconds": _twos(w(7, 17, 24), 8) * 2.0 ** -31,
            "toc_seconds": w(8, 9, 24) * 16,
            "af2_seconds_per_second2": _twos(w(9, 1, 8), 8) * 2.0 ** -55,
            "af1_seconds_per_second": _twos(w(9, 9, 24), 16) * 2.0 ** -43,
            "af0_seconds": _twos(w(10, 1, 22), 22) * 2.0 ** -31,
        }
    if subframe_id == 2:
        m0 = (w(4, 17, 24) << 24) | w(5, 1, 24)
        eccentricity = (w(6, 17, 24) << 24) | w(7, 1, 24)
        sqrt_a = (w(8, 17, 24) << 24) | w(9, 1, 24)
        return {
            "kind": "ephemeris_part_1", "iode": w(3, 1, 8),
            "crs_m": _twos(w(3, 9, 24), 16) * 2.0 ** -5,
            "delta_n_semicircles_per_second": _twos(w(4, 1, 16), 16) * 2.0 ** -43,
            "m0_semicircles": _twos(m0, 32) * 2.0 ** -31,
            "cuc_radians": _twos(w(6, 1, 16), 16) * 2.0 ** -29,
            "eccentricity": eccentricity * 2.0 ** -33,
            "cus_radians": _twos(w(8, 1, 16), 16) * 2.0 ** -29,
            "sqrt_a_sqrt_m": sqrt_a * 2.0 ** -19,
            "toe_seconds": w(10, 1, 16) * 16,
            "fit_interval_flag": w(10, 17, 17), "aodo_raw": w(10, 18, 22),
        }
    if subframe_id == 3:
        omega0 = (w(3, 17, 24) << 24) | w(4, 1, 24)
        i0 = (w(5, 17, 24) << 24) | w(6, 1, 24)
        omega = (w(7, 17, 24) << 24) | w(8, 1, 24)
        return {
            "kind": "ephemeris_part_2",
            "cic_radians": _twos(w(3, 1, 16), 16) * 2.0 ** -29,
            "omega0_semicircles": _twos(omega0, 32) * 2.0 ** -31,
            "cis_radians": _twos(w(5, 1, 16), 16) * 2.0 ** -29,
            "i0_semicircles": _twos(i0, 32) * 2.0 ** -31,
            "crc_m": _twos(w(7, 1, 16), 16) * 2.0 ** -5,
            "omega_semicircles": _twos(omega, 32) * 2.0 ** -31,
            "omega_dot_semicircles_per_second": _twos(w(9, 1, 24), 24) * 2.0 ** -43,
            "iode": w(10, 1, 8),
            "idot_semicircles_per_second": _twos(w(10, 9, 22), 14) * 2.0 ** -43,
        }
    data_id, page_id = w(3, 1, 2), w(3, 3, 8)
    common: dict[str, Any] = {
        "kind": "almanac_or_system_page", "data_id": data_id,
        "page_id": page_id,
        "page_payload_bits": "".join(str(bit) for word in words[2:] for bit in word),
    }
    if 1 <= page_id <= 32:
        common.update({
            "kind": "almanac", "sv_id": page_id,
            "eccentricity": w(3, 9, 24) * 2.0 ** -21,
            "toa_seconds": w(4, 1, 8) * 4096,
            "delta_i_semicircles": _twos(w(4, 9, 24), 16) * 2.0 ** -19,
            "omega_dot_semicircles_per_second":
                _twos(w(5, 1, 16), 16) * 2.0 ** -38,
            "sv_health": w(5, 17, 24),
            "sqrt_a_sqrt_m": w(6, 1, 24) * 2.0 ** -11,
            "omega0_semicircles": _twos(w(7, 1, 24), 24) * 2.0 ** -23,
            "omega_semicircles": _twos(w(8, 1, 24), 24) * 2.0 ** -23,
            "m0_semicircles": _twos(w(9, 1, 24), 24) * 2.0 ** -23,
            "af0_seconds": _twos(w(10, 1, 11), 11) * 2.0 ** -20,
            "af1_seconds_per_second": _twos(w(10, 12, 22), 11) * 2.0 ** -38,
        })
    elif page_id == 56:
        a0 = (w(7, 1, 24) << 8) | w(8, 1, 8)
        common.update({
            "kind": "ionosphere_utc",
            "alpha": [
                _twos(w(3, 9, 16), 8) * 2.0 ** -30,
                _twos(w(3, 17, 24), 8) * 2.0 ** -27,
                _twos(w(4, 1, 8), 8) * 2.0 ** -24,
                _twos(w(4, 9, 16), 8) * 2.0 ** -24,
            ],
            "beta": [
                _twos(w(4, 17, 24), 8) * 2.0 ** 11,
                _twos(w(5, 1, 8), 8) * 2.0 ** 14,
                _twos(w(5, 9, 16), 8) * 2.0 ** 16,
                _twos(w(5, 17, 24), 8) * 2.0 ** 16,
            ],
            "utc_a1_seconds_per_second": _twos(w(6, 1, 24), 24) * 2.0 ** -50,
            "utc_a0_seconds": _twos(a0, 32) * 2.0 ** -30,
            "tot_seconds": w(8, 9, 16) * 4096, "wnt": w(8, 17, 24),
            "delta_tls": _twos(w(9, 1, 8), 8), "wn_lsf": w(9, 9, 16),
            "day_number": w(9, 17, 24),
            "delta_tlsf": _twos(w(10, 1, 8), 8),
        })
    return common


@_declared
def decode_gps_lnav(data: object, *, packing: object = "msb0",
                    bit_length: object = None,
                    previous_d29_star: object = 0,
                    previous_d30_star: object = 0) -> dict[str, Any]:
    """Validate/dewhiten one ten-word GPS LNAV subframe and decode key fields."""
    if type(previous_d29_star) is not int or previous_d29_star not in (0, 1):
        raise SecGNSSNavError("previous_d29_star must be 0 or 1")
    if type(previous_d30_star) is not int or previous_d30_star not in (0, 1):
        raise SecGNSSNavError("previous_d30_star must be 0 or 1")
    bits = _exact_bits(data, 300, packing=packing, bit_length=bit_length)
    previous_d29, previous_d30 = previous_d29_star, previous_d30_star
    words: list[list[int]] = []
    parity_words: list[dict[str, Any]] = []
    for index in range(10):
        transmitted = bits[index * 30:(index + 1) * 30]
        recovered = [bit ^ previous_d30 for bit in transmitted[:24]]
        expected = _lnav_parity(recovered, previous_d29, previous_d30)
        received = transmitted[24:30]
        parity_words.append({
            "word": index + 1, "valid": expected == received,
            "received": _uint(received), "computed": _uint(expected),
        })
        words.append(recovered)
        previous_d29, previous_d30 = transmitted[28], transmitted[29]
    invalid = [row["word"] for row in parity_words if not row["valid"]]
    if invalid:
        raise SecGNSSNavError(f"GPS LNAV parity mismatch in word {invalid[0]}")
    preamble = _uint(words[0][:8])
    if preamble != 0x8B:
        raise SecGNSSNavError("GPS LNAV TLM preamble is not 0x8b")
    if previous_d29 or previous_d30:
        raise SecGNSSNavError("GPS LNAV word 10 does not force D29*/D30* to zero")
    how = words[1]
    subframe_id = _uint(how[19:22])
    if subframe_id not in range(1, 6):
        raise SecGNSSNavError("invalid GPS LNAV subframe ID")
    tow_count = _uint(how[:17])
    return {
        "system": "GPS", "family": "LNAV", "bit_length": 300,
        "integrity": {"algorithm": "IS-GPS-200 parity", "valid": True,
                      "words": parity_words},
        "tlm": {"preamble": preamble, "message": _uint(words[0][8:22]),
                "integrity_status": words[0][22], "reserved": words[0][23]},
        "how": {"tow_count": tow_count, "tow_seconds": tow_count * 6,
                "alert": bool(how[17]), "anti_spoof": bool(how[18]),
                "subframe_id": subframe_id, "reserved": _uint(how[22:24])},
        "navigation": _decode_lnav_fields(words, subframe_id),
        "data_words_hex": [f"{_uint(word):06x}" for word in words],
        "final_d29_star": previous_d29, "final_d30_star": previous_d30,
    }


_CNAV_TYPES = {
    10: "ephemeris_1", 11: "ephemeris_2", 30: "clock_iono_group_delay",
    31: "reduced_almanac", 32: "earth_orientation", 33: "utc",
    35: "gps_gnss_time_offset", 37: "midi_almanac",
}


def _cnav_clock(bits: list[int]) -> dict[str, Any]:
    """Clock block shared by CNAV message types 30, 31, and 33."""
    return {
        "top_seconds": _uint(bits[38:49]) * 300,
        "ura_ned0_index": _twos(_uint(bits[49:54]), 5),
        "ura_ned1_index": _uint(bits[54:57]),
        "ura_ned2_index": _uint(bits[57:60]),
        "toc_seconds": _uint(bits[60:71]) * 300,
        "af0_seconds": _twos(_uint(bits[71:97]), 26) * 2.0 ** -35,
        "af1_seconds_per_second": _twos(_uint(bits[97:117]), 20) * 2.0 ** -48,
        "af2_seconds_per_second2": _twos(_uint(bits[117:127]), 10) * 2.0 ** -60,
    }


def _cnav_reduced_almanac(packet: list[int]) -> dict[str, Any]:
    return {
        "prn": _uint(packet[:6]),
        "delta_a_m": _twos(_uint(packet[6:14]), 8) * 2.0 ** 9,
        "omega0_semicircles": _twos(_uint(packet[14:21]), 7) * 2.0 ** -6,
        "phi0_semicircles": _twos(_uint(packet[21:28]), 7) * 2.0 ** -6,
        "l1_health": packet[28], "l2_health": packet[29], "l5_health": packet[30],
    }


@_declared
def decode_gps_cnav(data: object, *, packing: object = "msb0",
                    bit_length: object = None) -> dict[str, Any]:
    """Decode one post-FEC 300-bit GPS CNAV message and verify CRC-24Q."""
    bits = _exact_bits(data, 300, packing=packing, bit_length=bit_length)
    received = _uint(bits[276:300])
    computed = _crc24q_value(bits[:276])
    if received != computed:
        raise SecGNSSNavError("GPS CNAV CRC-24Q mismatch")
    preamble = _uint(bits[:8])
    if preamble != 0x8B:
        raise SecGNSSNavError("GPS CNAV preamble is not 0x8b")
    prn = _uint(bits[8:14])
    if prn == 0:
        raise SecGNSSNavError("GPS CNAV PRN zero is reserved")
    message_type = _uint(bits[14:20])
    typed: dict[str, Any] = {
        "kind": _CNAV_TYPES.get(message_type, "reserved_or_unimplemented"),
        "payload_bits": "".join(str(bit) for bit in bits[38:276]),
    }
    # The common WN/TOP prefix is normative for ephemeris message type 10.
    if message_type == 10:
        typed.update({
            "week_number": _uint(bits[38:51]),
            "signal_health": _uint(bits[51:54]),
            "top_seconds": _uint(bits[54:65]) * 300,
            "ura_ed_index": _twos(_uint(bits[65:70]), 5),
            "toe_seconds": _uint(bits[70:81]) * 300,
            "delta_a_m": _twos(_uint(bits[81:107]), 26) * 2.0 ** -9,
            "a_dot_m_per_second": _twos(_uint(bits[107:132]), 25) * 2.0 ** -21,
            "delta_n0_semicircles_per_second":
                _twos(_uint(bits[132:149]), 17) * 2.0 ** -44,
            "delta_n0_dot_semicircles_per_second2":
                _twos(_uint(bits[149:172]), 23) * 2.0 ** -57,
            "m0_semicircles": _twos(_uint(bits[172:205]), 33) * 2.0 ** -32,
            "eccentricity": _uint(bits[205:238]) * 2.0 ** -34,
            "omega_semicircles": _twos(_uint(bits[238:271]), 33) * 2.0 ** -32,
            "integrity_status": bool(bits[271]), "l2c_phasing": bool(bits[272]),
            "reserved": _uint(bits[273:276]),
        })
    elif message_type == 11:
        typed.update({
            "toe_seconds": _uint(bits[38:49]) * 300,
            "omega0_semicircles": _twos(_uint(bits[49:82]), 33) * 2.0 ** -32,
            "i0_semicircles": _twos(_uint(bits[82:115]), 33) * 2.0 ** -32,
            "delta_omega_dot_semicircles_per_second":
                _twos(_uint(bits[115:132]), 17) * 2.0 ** -44,
            "idot_semicircles_per_second":
                _twos(_uint(bits[132:147]), 15) * 2.0 ** -44,
            "cis_radians": _twos(_uint(bits[147:163]), 16) * 2.0 ** -30,
            "cic_radians": _twos(_uint(bits[163:179]), 16) * 2.0 ** -30,
            "crs_m": _twos(_uint(bits[179:203]), 24) * 2.0 ** -8,
            "crc_m": _twos(_uint(bits[203:227]), 24) * 2.0 ** -8,
            "cus_radians": _twos(_uint(bits[227:248]), 21) * 2.0 ** -30,
            "cuc_radians": _twos(_uint(bits[248:269]), 21) * 2.0 ** -30,
            "reserved": _uint(bits[269:276]),
        })
    elif message_type == 30:
        typed.update(_cnav_clock(bits))
        typed.update({
            "tgd_seconds": _twos(_uint(bits[127:140]), 13) * 2.0 ** -35,
            "isc_l1ca_seconds": _twos(_uint(bits[140:153]), 13) * 2.0 ** -35,
            "isc_l2c_seconds": _twos(_uint(bits[153:166]), 13) * 2.0 ** -35,
            "isc_l5i5_seconds": _twos(_uint(bits[166:179]), 13) * 2.0 ** -35,
            "isc_l5q5_seconds": _twos(_uint(bits[179:192]), 13) * 2.0 ** -35,
            "alpha": [
                _twos(_uint(bits[192:200]), 8) * 2.0 ** -30,
                _twos(_uint(bits[200:208]), 8) * 2.0 ** -27,
                _twos(_uint(bits[208:216]), 8) * 2.0 ** -24,
                _twos(_uint(bits[216:224]), 8) * 2.0 ** -24,
            ],
            "beta": [
                _twos(_uint(bits[224:232]), 8) * 2.0 ** 11,
                _twos(_uint(bits[232:240]), 8) * 2.0 ** 14,
                _twos(_uint(bits[240:248]), 8) * 2.0 ** 16,
                _twos(_uint(bits[248:256]), 8) * 2.0 ** 16,
            ],
            "wnop_mod_256": _uint(bits[256:264]),
            "reserved": _uint(bits[264:276]),
        })
    elif message_type == 31:
        typed.update(_cnav_clock(bits))
        typed.update({
            "almanac_week": _uint(bits[127:140]),
            "toa_seconds": _uint(bits[140:148]) * 4096,
            "reduced_almanac": [
                _cnav_reduced_almanac(bits[start:start + 31])
                for start in (148, 179, 210, 241)
            ],
            "reserved": _uint(bits[272:276]),
        })
    elif message_type == 33:
        typed.update(_cnav_clock(bits))
        typed.update({
            "utc_a0_seconds": _twos(_uint(bits[127:143]), 16) * 2.0 ** -35,
            "utc_a1_seconds_per_second": _twos(_uint(bits[143:156]), 13) * 2.0 ** -51,
            "utc_a2_seconds_per_second2": _twos(_uint(bits[156:163]), 7) * 2.0 ** -68,
            "delta_tls": _twos(_uint(bits[163:171]), 8),
            "tot_seconds": _uint(bits[171:187]) * 16,
            "wnot": _uint(bits[187:200]), "wn_lsf": _uint(bits[200:213]),
            "day_number": _uint(bits[213:217]),
            "delta_tlsf": _twos(_uint(bits[217:225]), 8),
            "reserved_bits": "".join(str(bit) for bit in bits[225:276]),
        })
    return {
        "system": "GPS", "family": "CNAV", "bit_length": 300,
        "preamble": preamble, "prn": prn,
        "message_type": message_type, "tow_count": _uint(bits[20:37]),
        "tow_seconds": _uint(bits[20:37]) * 6, "alert": bool(bits[37]),
        "navigation": typed,
        "integrity": {"algorithm": "CRC-24Q", "valid": True,
                      "received": f"{received:06x}", "computed": f"{computed:06x}"},
    }


@_declared
def decode_gps_cnav2(data: object, *, packing: object = "msb0",
                     bit_length: object = None) -> dict[str, Any]:
    """Decode a post-BCH/LDPC 883-bit GPS L1C CNAV-2 frame."""
    bits = _exact_bits(data, 883, packing=packing, bit_length=bit_length)
    sf2_data, sf2_crc = bits[9:585], _uint(bits[585:609])
    sf3_data, sf3_crc = bits[609:859], _uint(bits[859:883])
    sf2_calc, sf3_calc = _crc24q_value(sf2_data), _crc24q_value(sf3_data)
    if sf2_crc != sf2_calc or sf3_crc != sf3_calc:
        raise SecGNSSNavError("GPS CNAV-2 subframe CRC-24Q mismatch")
    return {
        "system": "GPS", "family": "CNAV-2", "bit_length": 883,
        "fec_scope": "input is already BCH/LDPC decoded",
        "time_of_interval": _uint(bits[:9]),
        "week_number": _uint(sf2_data[:13]),
        "interval_time_of_week": _uint(sf2_data[13:21]),
        "sf2_data_hex": f"{_uint(sf2_data):0144x}",
        "sf3_prn": _uint(sf3_data[:8]),
        "sf3_page_number": _uint(sf3_data[8:14]),
        "sf3_page_id": _uint(sf3_data[8:14]),
        "sf3_data_bits": "".join(str(bit) for bit in sf3_data),
        "integrity": {
            "algorithm": "separate CRC-24Q",
            "sf2": {"valid": True, "crc": f"{sf2_crc:06x}"},
            "sf3": {"valid": True, "crc": f"{sf3_crc:06x}"},
        },
    }


def _galileo_word(bits: list[int]) -> dict[str, Any]:
    word_type = _uint(bits[:6])
    result: dict[str, Any] = {"word_type": word_type}
    if word_type == 1:
        result.update({
            "kind": "ephemeris_1", "iod_nav": _uint(bits[6:16]),
            "toe_seconds": _uint(bits[16:30]) * 60,
            "m0_semicircles": _twos(_uint(bits[30:62]), 32) * 2.0 ** -31,
            "eccentricity": _uint(bits[62:94]) * 2.0 ** -33,
            "sqrt_a_sqrt_m": _uint(bits[94:126]) * 2.0 ** -19,
        })
    elif word_type == 2:
        result.update({
            "kind": "ephemeris_2", "iod_nav": _uint(bits[6:16]),
            "omega0_semicircles": _twos(_uint(bits[16:48]), 32) * 2.0 ** -31,
            "i0_semicircles": _twos(_uint(bits[48:80]), 32) * 2.0 ** -31,
            "omega_semicircles": _twos(_uint(bits[80:112]), 32) * 2.0 ** -31,
            "idot_semicircles_per_second": _twos(_uint(bits[112:126]), 14) * 2.0 ** -43,
        })
    elif word_type == 3:
        result.update({
            "kind": "ephemeris_3", "iod_nav": _uint(bits[6:16]),
            "omega_dot_semicircles_per_second": _twos(_uint(bits[16:40]), 24) * 2.0 ** -43,
            "delta_n_semicircles_per_second": _twos(_uint(bits[40:56]), 16) * 2.0 ** -43,
            "cuc_radians": _twos(_uint(bits[56:72]), 16) * 2.0 ** -29,
            "cus_radians": _twos(_uint(bits[72:88]), 16) * 2.0 ** -29,
            "crc_m": _twos(_uint(bits[88:104]), 16) * 2.0 ** -5,
            "crs_m": _twos(_uint(bits[104:120]), 16) * 2.0 ** -5,
            "sisa_index": _uint(bits[120:128]),
        })
    elif word_type == 4:
        result.update({
            "kind": "ephemeris_clock", "iod_nav": _uint(bits[6:16]),
            "svid": _uint(bits[16:22]),
            "cic_radians": _twos(_uint(bits[22:38]), 16) * 2.0 ** -29,
            "cis_radians": _twos(_uint(bits[38:54]), 16) * 2.0 ** -29,
            "toc_seconds": _uint(bits[54:68]) * 60,
            "af0_seconds": _twos(_uint(bits[68:99]), 31) * 2.0 ** -34,
            "af1_seconds_per_second": _twos(_uint(bits[99:120]), 21) * 2.0 ** -46,
            "af2_seconds_per_second2": _twos(_uint(bits[120:126]), 6) * 2.0 ** -59,
        })
    elif word_type == 5:
        result.update({
            "kind": "iono_health_time",
            "iono_ai0_sfu": _uint(bits[6:17]) * 2.0 ** -2,
            "iono_ai1_sfu_per_degree": _twos(_uint(bits[17:28]), 11) * 2.0 ** -8,
            "iono_ai2_sfu_per_degree2": _twos(_uint(bits[28:42]), 14) * 2.0 ** -15,
            "iono_disturbance_flags": _uint(bits[42:47]),
            "bgd_e1e5a_seconds": _twos(_uint(bits[47:57]), 10) * 2.0 ** -32,
            "bgd_e1e5b_seconds": _twos(_uint(bits[57:67]), 10) * 2.0 ** -32,
            "e5b_health": _uint(bits[67:69]), "e1b_health": _uint(bits[69:71]),
            "e5b_data_validity": bits[71], "e1b_data_validity": bits[72],
            "week_number": _uint(bits[73:85]), "tow_seconds": _uint(bits[85:105]),
        })
    elif word_type == 6:
        result.update({
            "kind": "utc_conversion", "a0_seconds": _twos(_uint(bits[6:38]), 32) * 2.0 ** -30,
            "a1_seconds_per_second": _twos(_uint(bits[38:62]), 24) * 2.0 ** -50,
            "delta_tls": _twos(_uint(bits[62:70]), 8), "tot_hours": _uint(bits[70:78]),
            "wn0t": _uint(bits[78:86]), "wn_lsf": _uint(bits[86:94]),
            "day_number": _uint(bits[94:97]), "delta_tlsf": _twos(_uint(bits[97:105]), 8),
            "tow_seconds": _uint(bits[105:125]),
        })
    elif word_type == 7:
        result.update({
            "kind": "almanac_1", "iod_a": _uint(bits[6:10]),
            "week_number_mod_4": _uint(bits[10:12]),
            "t0a_seconds": _uint(bits[12:22]) * 600,
            "satellite_1": {
                "svid": _uint(bits[22:28]),
                "delta_sqrt_a_sqrt_m": _twos(_uint(bits[28:41]), 13) * 2.0 ** -9,
                "eccentricity": _uint(bits[41:52]) * 2.0 ** -16,
                "omega_semicircles": _twos(_uint(bits[52:68]), 16) * 2.0 ** -15,
                "delta_i_semicircles": _twos(_uint(bits[68:79]), 11) * 2.0 ** -14,
                "omega0_semicircles": _twos(_uint(bits[79:95]), 16) * 2.0 ** -15,
                "omega_dot_semicircles_per_second":
                    _twos(_uint(bits[95:106]), 11) * 2.0 ** -33,
                "m0_semicircles": _twos(_uint(bits[106:122]), 16) * 2.0 ** -15,
            },
            "reserved": _uint(bits[122:128]),
        })
    elif word_type == 8:
        result.update({
            "kind": "almanac_2", "iod_a": _uint(bits[6:10]),
            "satellite_1_continuation": {
                "af0_seconds": _twos(_uint(bits[10:26]), 16) * 2.0 ** -19,
                "af1_seconds_per_second": _twos(_uint(bits[26:39]), 13) * 2.0 ** -38,
                "e5b_health": _uint(bits[39:41]), "e1b_health": _uint(bits[41:43]),
            },
            "satellite_2": {
                "svid": _uint(bits[43:49]),
                "delta_sqrt_a_sqrt_m": _twos(_uint(bits[49:62]), 13) * 2.0 ** -9,
                "eccentricity": _uint(bits[62:73]) * 2.0 ** -16,
                "omega_semicircles": _twos(_uint(bits[73:89]), 16) * 2.0 ** -15,
                "delta_i_semicircles": _twos(_uint(bits[89:100]), 11) * 2.0 ** -14,
                "omega0_semicircles": _twos(_uint(bits[100:116]), 16) * 2.0 ** -15,
                "omega_dot_semicircles_per_second":
                    _twos(_uint(bits[116:127]), 11) * 2.0 ** -33,
            },
            "spare": bits[127],
        })
    elif word_type == 9:
        result.update({
            "kind": "almanac_3", "iod_a": _uint(bits[6:10]),
            "week_number_mod_4": _uint(bits[10:12]),
            "t0a_seconds": _uint(bits[12:22]) * 600,
            "satellite_2_continuation": {
                "m0_semicircles": _twos(_uint(bits[22:38]), 16) * 2.0 ** -15,
                "af0_seconds": _twos(_uint(bits[38:54]), 16) * 2.0 ** -19,
                "af1_seconds_per_second": _twos(_uint(bits[54:67]), 13) * 2.0 ** -38,
                "e5b_health": _uint(bits[67:69]), "e1b_health": _uint(bits[69:71]),
            },
            "satellite_3": {
                "svid": _uint(bits[71:77]),
                "delta_sqrt_a_sqrt_m": _twos(_uint(bits[77:90]), 13) * 2.0 ** -9,
                "eccentricity": _uint(bits[90:101]) * 2.0 ** -16,
                "omega_semicircles": _twos(_uint(bits[101:117]), 16) * 2.0 ** -15,
                "delta_i_semicircles": _twos(_uint(bits[117:128]), 11) * 2.0 ** -14,
            },
        })
    elif word_type == 10:
        result.update({
            "kind": "almanac_4", "iod_a": _uint(bits[6:10]),
            "satellite_3_continuation": {
                "omega0_semicircles": _twos(_uint(bits[10:26]), 16) * 2.0 ** -15,
                "omega_dot_semicircles_per_second":
                    _twos(_uint(bits[26:37]), 11) * 2.0 ** -33,
                "m0_semicircles": _twos(_uint(bits[37:53]), 16) * 2.0 ** -15,
                "af0_seconds": _twos(_uint(bits[53:69]), 16) * 2.0 ** -19,
                "af1_seconds_per_second": _twos(_uint(bits[69:82]), 13) * 2.0 ** -38,
                "e5b_health": _uint(bits[82:84]), "e1b_health": _uint(bits[84:86]),
            },
            "gst_gps_offset": {
                "a0_seconds": _twos(_uint(bits[86:102]), 16) * 2.0 ** -35,
                "a1_seconds_per_second": _twos(_uint(bits[102:114]), 12) * 2.0 ** -51,
                "t0g_seconds": _uint(bits[114:122]) * 3600,
                "wn0g": _uint(bits[122:128]),
            },
        })
    else:
        kind = ("reduced_ephemeris" if word_type == 16 else
                "fec2" if 17 <= word_type <= 20 else
                "integrity_support" if word_type == 22 else "reserved_or_unknown")
        result.update({"kind": kind,
                       "payload_bits": "".join(str(bit) for bit in bits[6:])})
    result["raw_word_hex"] = f"{_uint(bits):032x}"
    return result


@_declared
def decode_galileo_word(data: object, *, packing: object = "msb0",
                        bit_length: object = None) -> dict[str, Any]:
    """Decode one already reassembled 128-bit Galileo I/NAV word."""
    bits = _exact_bits(data, 128, packing=packing, bit_length=bit_length)
    return {"system": "Galileo", "family": "I/NAV-word", "bit_length": 128,
            "navigation": _galileo_word(bits),
            "integrity": {"checked": False,
                          "reason": "a standalone word omits the paired-page CRC context"}}


@_declared
def decode_galileo_inav(data: object, *, packing: object = "msb0",
                        bit_length: object = None) -> dict[str, Any]:
    """Validate a nominal even+odd Galileo I/NAV page pair and decode its word."""
    bits = _exact_bits(data, 240, packing=packing, bit_length=bit_length)
    if bits[0:2] != [0, 0] or bits[120:122] != [1, 0]:
        raise SecGNSSNavError("Galileo nominal pages require even/odd and page-type 0")
    if any(bits[114:120]) or any(bits[234:240]):
        raise SecGNSSNavError("Galileo nominal-page tail bits must be zero")
    crc_input = bits[0:114] + bits[120:202]
    received, computed = _uint(bits[202:226]), _crc24q_value(crc_input)
    if received != computed:
        raise SecGNSSNavError("Galileo I/NAV CRC-24Q mismatch")
    word = bits[2:114] + bits[122:138]
    return {
        "system": "Galileo", "family": "I/NAV", "bit_length": 240,
        "navigation": _galileo_word(word),
        "osnma_bits": "".join(str(bit) for bit in bits[138:178]),
        "sar_bits": "".join(str(bit) for bit in bits[178:200]),
        "spare": _uint(bits[200:202]), "ssp": _uint(bits[226:234]),
        "tails": [_uint(bits[114:120]), _uint(bits[234:240])],
        "integrity": {"algorithm": "CRC-24Q over 196 non-contiguous bits",
                      "valid": True, "received": f"{received:06x}"},
    }


_GLO_HAMMING = (
    (9, 10, 12, 13, 15, 17, 19, 20, 22, 24, 26, 28, 30, 32, 34, 35, 37, 39, 41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 66, 68, 70, 72, 74, 76, 78, 80, 82, 84),
    (9, 11, 12, 14, 15, 18, 19, 21, 22, 25, 26, 29, 30, 33, 34, 36, 37, 40, 41, 44, 45, 48, 49, 52, 53, 56, 57, 60, 61, 64, 65, 67, 68, 71, 72, 75, 76, 79, 80, 83, 84),
    tuple(range(10, 13)) + tuple(range(16, 20)) + tuple(range(23, 27)) + tuple(range(31, 35)) + tuple(range(38, 42)) + tuple(range(46, 50)) + tuple(range(54, 58)) + tuple(range(62, 66)) + tuple(range(69, 73)) + tuple(range(77, 81)) + (85,),
    tuple(range(13, 20)) + tuple(range(27, 35)) + tuple(range(42, 50)) + tuple(range(58, 66)) + tuple(range(73, 81)),
    tuple(range(20, 35)) + tuple(range(50, 66)) + tuple(range(81, 86)),
    tuple(range(35, 66)), tuple(range(66, 86)),
)


def _glonass_value(icd: dict[int, int], low: int, high: int) -> int:
    return _uint(icd[index] for index in range(high, low - 1, -1))


@_declared
def decode_glonass_string(data: object, *, packing: object = "msb0",
                          bit_length: object = None) -> dict[str, Any]:
    """Validate and decode one legacy GLONASS 85-bit navigation string."""
    bits = _exact_bits(data, 85, packing=packing, bit_length=bit_length)
    icd = {index: bits[85 - index] for index in range(1, 86)}
    if icd[85]:
        raise SecGNSSNavError("GLONASS idle bit 85 must be zero")
    checks = [(icd[number] ^ sum(icd[pos] for pos in positions) % 2)
              for number, positions in enumerate(_GLO_HAMMING, 1)]
    checks.append(sum(icd[index] for index in range(1, 86)) % 2)
    if any(checks):
        raise SecGNSSNavError("GLONASS Hamming integrity mismatch")
    number = _glonass_value(icd, 81, 84)
    result: dict[str, Any] = {
        "system": "GLONASS", "family": "L1OF/L2OF", "bit_length": 85,
        "string_number": number,
        "integrity": {"algorithm": "ICD Hamming", "valid": True,
                      "syndrome": checks},
    }
    axis = {1: "x", 2: "y", 3: "z"}.get(number)
    if axis:
        position = _sign_magnitude(_glonass_value(icd, 9, 35), 27) * 2.0 ** -11
        velocity = _sign_magnitude(_glonass_value(icd, 41, 64), 24) * 2.0 ** -20
        acceleration = _sign_magnitude(_glonass_value(icd, 36, 40), 5) * 2.0 ** -30
        nav: dict[str, Any] = {
            "kind": f"{axis}_ephemeris", "position_km": position,
            "velocity_km_s": velocity, "acceleration_km_s2": acceleration,
        }
        if number == 1:
            nav.update({
                "tk_hours": _glonass_value(icd, 72, 76),
                "tk_minutes": _glonass_value(icd, 66, 71),
                "tk_half_minute": _glonass_value(icd, 65, 65),
                "p1": _glonass_value(icd, 77, 78),
            })
        elif number == 2:
            nav.update({"tb_minutes": _glonass_value(icd, 70, 76) * 15,
                        "p2": icd[77], "bn": _glonass_value(icd, 78, 80)})
        else:
            nav.update({
                "gamma_n": _sign_magnitude(_glonass_value(icd, 69, 79), 11) * 2.0 ** -40,
                "p3": icd[80], "p": _glonass_value(icd, 66, 67), "ln": icd[65],
            })
        result["navigation"] = nav
    elif number == 4:
        result["navigation"] = {
            "kind": "clock_age_slot", "tau_n_seconds":
                _sign_magnitude(_glonass_value(icd, 59, 80), 22) * 2.0 ** -30,
            "delta_tau_n_seconds":
                _sign_magnitude(_glonass_value(icd, 54, 58), 5) * 2.0 ** -30,
            "age_days": _glonass_value(icd, 49, 53), "p4": icd[34],
            "accuracy_index": _glonass_value(icd, 30, 33),
            "day_number": _glonass_value(icd, 16, 26),
            "slot_number": _glonass_value(icd, 11, 15),
            "satellite_type": _glonass_value(icd, 9, 10),
        }
    elif number == 5:
        result["navigation"] = {
            "kind": "system_time",
            "calendar_day": _glonass_value(icd, 70, 80),
            "tau_c_seconds":
                _sign_magnitude(_glonass_value(icd, 38, 69), 32) * 2.0 ** -31,
            "four_year_interval": _glonass_value(icd, 32, 36),
            "tau_gps_seconds":
                _sign_magnitude(_glonass_value(icd, 10, 31), 22) * 2.0 ** -30,
            "health": icd[9], "unnamed_bit_37": icd[37],
        }
    elif number in (6, 8, 10, 12, 14):
        result["navigation"] = {
            "kind": "almanac_even", "almanac_pair": (number - 4) // 2,
            "operability": icd[80], "satellite_type": _glonass_value(icd, 78, 79),
            "slot_number": _glonass_value(icd, 73, 77),
            "tau_seconds":
                _sign_magnitude(_glonass_value(icd, 63, 72), 10) * 2.0 ** -18,
            "lambda_semicircles":
                _sign_magnitude(_glonass_value(icd, 42, 62), 21) * 2.0 ** -20,
            "delta_i_semicircles":
                _sign_magnitude(_glonass_value(icd, 24, 41), 18) * 2.0 ** -20,
            "eccentricity": _glonass_value(icd, 9, 23) * 2.0 ** -20,
        }
    elif number in (7, 9, 11, 13, 15):
        result["navigation"] = {
            "kind": "almanac_odd", "almanac_pair": (number - 5) // 2,
            "omega_semicircles":
                _sign_magnitude(_glonass_value(icd, 65, 80), 16) * 2.0 ** -15,
            "t_lambda_seconds": _glonass_value(icd, 44, 64) * 2.0 ** -5,
            "delta_t_seconds":
                _sign_magnitude(_glonass_value(icd, 22, 43), 22) * 2.0 ** -9,
            "delta_t_dot_seconds":
                _sign_magnitude(_glonass_value(icd, 15, 21), 7) * 2.0 ** -14,
            "frequency_channel_raw": _glonass_value(icd, 10, 14),
            "health": icd[9],
        }
    else:
        result["navigation"] = {
            "kind": "time_or_almanac", "information_bits":
                "".join(str(icd[index]) for index in range(84, 8, -1)),
        }
    return result


def _bch_remainder(codeword: int) -> int:
    register = codeword
    for bit in range(14, 3, -1):
        if register & (1 << bit):
            register ^= 0x13 << (bit - 4)
    return register & 0xF


@_declared
def beidou_bch15_valid(codeword: object) -> bool:
    """Validate a systematic BeiDou BCH(15,11,1) codeword."""
    if type(codeword) is not int or not 0 <= codeword < (1 << 15):
        raise SecGNSSNavError("BCH codeword must be an unsigned 15-bit integer")
    return _bch_remainder(codeword) == 0


def _beidou_logical(bits: list[int]) -> tuple[dict[int, int], list[dict[str, Any]]]:
    logical: dict[int, int] = {index + 1: bit for index, bit in enumerate(bits[:15])}
    code1 = _uint(bits[15:30])
    checks = [{"word": 1, "codewords": [f"{code1:04x}"],
               "valid": _bch_remainder(code1) == 0}]
    message = code1 >> 4
    for index in range(11):
        logical[16 + index] = (message >> (10 - index)) & 1
    for word_index in range(1, 10):
        raw = bits[word_index * 30:(word_index + 1) * 30]
        first = _uint(raw[0::2])
        second = _uint(raw[1::2])
        checks.append({"word": word_index + 1,
                       "codewords": [f"{first:04x}", f"{second:04x}"],
                       "valid": _bch_remainder(first) == 0 and _bch_remainder(second) == 0})
        messages = (first >> 4, second >> 4)
        base = word_index * 30 + 1
        for part, value in enumerate(messages):
            for offset in range(11):
                logical[base + part * 11 + offset] = (value >> (10 - offset)) & 1
    return logical, checks


def _logical_value(logical: dict[int, int], positions: Iterable[int]) -> int:
    return _uint(logical[position] for position in positions)


@_declared
def decode_beidou_nav(data: object, *, family: object = "d1",
                      packing: object = "msb0", bit_length: object = None) -> dict[str, Any]:
    """Validate one BeiDou D1 or D2 300-bit subframe and decode its header."""
    if type(family) is not str or family.lower() not in ("d1", "d2"):
        raise SecGNSSNavError("BeiDou family must be d1 or d2")
    kind = family.lower()
    bits = _exact_bits(data, 300, packing=packing, bit_length=bit_length)
    logical, checks = _beidou_logical(bits)
    if not all(row["valid"] for row in checks):
        bad = next(row["word"] for row in checks if not row["valid"])
        raise SecGNSSNavError(f"BeiDou BCH mismatch in word {bad}")
    preamble = _logical_value(logical, range(1, 12))
    if preamble != 0b11100010010:
        raise SecGNSSNavError("BeiDou preamble mismatch")
    fraid = _logical_value(logical, range(16, 19))
    sow = (_logical_value(logical, range(19, 27)) << 12) | _logical_value(logical, range(31, 43))
    roles = {1: "clock_health_time", 2: "ephemeris_1", 3: "ephemeris_2",
             4: "almanac_or_page", 5: "almanac_time_or_page"}
    return {
        "system": "BeiDou", "family": kind.upper(), "bit_length": 300,
        "preamble": preamble, "frame_id": fraid,
        "seconds_of_week": sow, "navigation_kind": roles.get(fraid, "reserved"),
        "logical_data_bits": "".join(str(logical[index]) for index in sorted(logical)),
        "integrity": {"algorithm": "BCH(15,11,1), g(x)=x^4+x+1",
                      "valid": True, "words": checks},
    }


@_declared
def decode_beidou_d1(data: object, *, packing: object = "msb0",
                     bit_length: object = None) -> dict[str, Any]:
    return decode_beidou_nav(data, family="d1", packing=packing, bit_length=bit_length)


@_declared
def decode_beidou_d2(data: object, *, packing: object = "msb0",
                     bit_length: object = None) -> dict[str, Any]:
    return decode_beidou_nav(data, family="d2", packing=packing, bit_length=bit_length)


@_declared
def decode_beidou_bcnav2(data: object, *, packing: object = "msb0",
                         bit_length: object = None) -> dict[str, Any]:
    """Decode one post-FEC 288-bit BeiDou B-CNAV2 message."""
    bits = _exact_bits(data, 288, packing=packing, bit_length=bit_length)
    received, computed = _uint(bits[264:288]), _crc24q_value(bits[:264])
    if received != computed:
        raise SecGNSSNavError("BeiDou B-CNAV2 CRC-24Q mismatch")
    prn = _uint(bits[:6])
    if prn == 0:
        raise SecGNSSNavError("BeiDou B-CNAV2 PRN zero is reserved")
    return {
        "system": "BeiDou", "family": "B-CNAV2", "bit_length": 288,
        "fec_scope": "input is already channel decoded", "prn": prn,
        "message_type": _uint(bits[6:12]), "seconds_of_week": _uint(bits[12:30]),
        "data_bits": "".join(str(bit) for bit in bits[30:264]),
        "integrity": {"algorithm": "CRC-24Q", "valid": True,
                      "received": f"{received:06x}"},
    }


_FAMILIES = {
    "gps-lnav": decode_gps_lnav, "gps-cnav": decode_gps_cnav,
    "gps-cnav2": decode_gps_cnav2, "galileo-inav": decode_galileo_inav,
    "galileo-word": decode_galileo_word, "glonass-l1of": decode_glonass_string,
    "beidou-d1": decode_beidou_d1, "beidou-d2": decode_beidou_d2,
    "beidou-bcnav2": decode_beidou_bcnav2,
}


@_declared
def decode_navigation(data: object, family: object, *, packing: object = "msb0",
                      bit_length: object = None,
                      previous_d29_star: object = 0,
                      previous_d30_star: object = 0) -> dict[str, Any]:
    """Dispatch to one explicitly selected navigation-message grammar."""
    if type(family) is not str or family not in _FAMILIES:
        raise SecGNSSNavError("unsupported GNSS navigation family")
    if family == "gps-lnav":
        return decode_gps_lnav(data, packing=packing, bit_length=bit_length,
                               previous_d29_star=previous_d29_star,
                               previous_d30_star=previous_d30_star)
    if previous_d29_star != 0 or previous_d30_star != 0:
        raise SecGNSSNavError("LNAV previous-word state supplied for another family")
    return _FAMILIES[family](data, packing=packing, bit_length=bit_length)


def _read(path: object) -> bytes:
    if type(path) is not str:
        raise SecGNSSNavError("input path must be text")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise SecGNSSNavError("input exceeds size limit")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline GNSS navigation-message decoder")
    parser.add_argument("family", choices=tuple(_FAMILIES))
    parser.add_argument("input")
    parser.add_argument("--packing", choices=("bits", "msb0"), default="msb0")
    parser.add_argument("--bit-length", type=int)
    parser.add_argument("--previous-d29-star", type=int, choices=(0, 1), default=0)
    parser.add_argument("--previous-d30-star", type=int, choices=(0, 1), default=0)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError, OverflowError) as exc:
        print(f"sec_gnss_nav: {exc}", file=sys.stderr)
        return 2
    try:
        report = decode_navigation(
            _read(args.input), args.family, packing=args.packing,
            bit_length=args.bit_length, previous_d29_star=args.previous_d29_star,
            previous_d30_star=args.previous_d30_star)
        print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (SecGNSSNavError, OSError, UnicodeError, ValueError,
            TypeError, OverflowError) as exc:
        print(f"sec_gnss_nav: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_INPUT", "SecGNSSNavError", "beidou_bch15_valid", "crc24q",
    "decode_beidou_bcnav2", "decode_beidou_d1", "decode_beidou_d2",
    "decode_beidou_nav", "decode_galileo_inav", "decode_galileo_word",
    "decode_glonass_string", "decode_gps_cnav", "decode_gps_cnav2",
    "decode_gps_lnav", "decode_navigation", "main",
]
