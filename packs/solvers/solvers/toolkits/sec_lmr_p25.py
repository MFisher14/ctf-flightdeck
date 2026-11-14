#!/usr/bin/env python3
"""Passive APCO Project 25 Phase 1/Phase 2 structure decoder.

The module consumes caller-supplied, already-demodulated packed bits or
caller-supplied post-FEC metadata words.  It never opens an SDR or socket,
searches for a key, decodes audio, constructs a radio frame, or transmits.

Wire layouts follow the public NTIA P25 CAI descriptions.  The Phase 1 NID
matrix and Phase 2 distributed-DUID codewords are the published OP25 values.
"""
from __future__ import annotations

import argparse
import functools
import json
from pathlib import Path
import sys


MAX_FILE_BYTES = 8192
MAX_PHASE1_BITS = MAX_FILE_BYTES * 8
PHASE1_SYNC = 0x5575F5FF77FF
PHASE2_SYNC = 0x575D57F7FF


class SecLmrP25Error(ValueError):
    """Malformed, ambiguous, unsupported, or over-limit P25 artifact."""


def _closed(function):
    """Expose only the engine's declared error at public parser boundaries."""

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecLmrP25Error:
            raise
        except Exception as exc:
            raise SecLmrP25Error(
                f"{function.__name__} failed: {type(exc).__name__}"
            ) from None

    return wrapper


def _packed_bits(data: object, bit_length: object, *, maximum: int) -> str:
    if type(data) is not bytes:
        raise SecLmrP25Error("input must be immutable bytes")
    if len(data) > MAX_FILE_BYTES:
        raise SecLmrP25Error("input exceeds the file-size limit")
    if bit_length is None:
        bit_length = len(data) * 8
    if type(bit_length) is not int or not 1 <= bit_length <= maximum:
        raise SecLmrP25Error("invalid bit length")
    if len(data) != (bit_length + 7) // 8:
        raise SecLmrP25Error("non-canonical packed-byte container")
    bits = "".join(f"{value:08b}" for value in data)
    if any(bit != "0" for bit in bits[bit_length:]):
        raise SecLmrP25Error("nonzero packed-byte padding")
    return bits[:bit_length]


def _exact_bytes(value: object, length: int, name: str) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise SecLmrP25Error(f"{name} must be exactly {length} bytes")
    return value


def _bits_hex(bits: str) -> str:
    if not bits:
        return ""
    return f"{int(bits, 2):0{(len(bits) + 3) // 4}x}"


def _region(bits: str, name: str, start: int, end: int) -> dict:
    if not (0 <= start <= end <= len(bits)):
        raise SecLmrP25Error(f"truncated {name} region")
    value = bits[start:end]
    return {
        "name": name,
        "start_bit": start,
        "end_bit": end,
        "bit_length": end - start,
        "hex": _bits_hex(value),
    }


# OP25 p25craft.py: systematic (64,16,23) BCH generator matrix.  Standards
# also describe this as BCH(63,16,23) followed by one parity bit.
_BCH_MATRIX = (
    0x8000CD930BDD3B2A, 0x4000AB5A8E33A6BE,
    0x2000983E4CC4E874, 0x10004C1F2662743A,
    0x0800EB9C98EC0136, 0x0400B85D47AB3BB0,
    0x02005C2EA3D59DD8, 0x01002E1751EACEEC,
    0x0080170BA8F56776, 0x0040C616DFA78890,
    0x0020630B6FD3C448, 0x00103185B7E9E224,
    0x000818C2DBF4F112, 0x0004C1F2662743A2,
    0x0002AD6A38CE9AFB, 0x00019B2617BA7657,
)


def _bch_codeword(information: int) -> int:
    if not 0 <= information <= 0xFFFF:
        raise SecLmrP25Error("invalid NID information word")
    result = 0
    for index, row in enumerate(_BCH_MATRIX):
        if information & (0x8000 >> index):
            result ^= row
    return result


_DUID_NAMES = {
    0x0: "HDU",
    0x3: "TDU",
    0x5: "LDU1",
    0x7: "TSDU",
    0xA: "LDU2",
    0xC: "PDU",
    0xF: "TDULC",
}
_PHASE1_LENGTHS = {
    0x0: 792,
    0x3: 144,
    0x5: 1728,
    0x7: 720,
    0xA: 1728,
    0xC: None,
    0xF: 432,
}


def _decode_nid(codeword: int) -> tuple[int, int, int, int]:
    """Return NAC, DUID, distance, and corrected codeword.

    The common exact path is constant time.  On an error, the decoder checks
    only the 28,672 current CAI NAC/DUID codewords and accepts the conservative
    OP25 threshold of at most four changed bits.
    """

    information = codeword >> 48
    duid = information & 0xF
    if duid in _DUID_NAMES:
        expected = _bch_codeword(information)
        distance = (expected ^ codeword).bit_count()
        if distance <= 4:
            return information >> 4, duid, distance, expected

    best_distance = 65
    best: tuple[int, int, int] | None = None
    ambiguous = False
    duid_rows = {candidate: _bch_codeword(candidate) for candidate in _DUID_NAMES}
    for nac in range(1 << 12):
        base = _bch_codeword(nac << 4)
        for candidate, tail in duid_rows.items():
            encoded = base ^ tail
            distance = (encoded ^ codeword).bit_count()
            if distance < best_distance:
                best_distance = distance
                best = (nac, candidate, encoded)
                ambiguous = False
            elif distance == best_distance:
                ambiguous = True
    if best is None or best_distance > 4:
        raise SecLmrP25Error("NID BCH validation failed")
    if ambiguous:
        raise SecLmrP25Error("NID BCH correction is ambiguous")
    return best[0], best[1], best_distance, best[2]


_STATUS_MEANINGS = {
    0: "unknown_or_direct",
    1: "inbound_busy",
    2: "unknown_subscriber_use",
    3: "inbound_idle",
}


def _strip_status(bits: str) -> tuple[str, list[dict]]:
    logical: list[str] = []
    statuses: list[dict] = []
    for offset in range(0, len(bits), 72):
        block = bits[offset:offset + 72]
        logical.extend(block[:70])
        if len(block) > 70:
            if len(block) != 72:
                raise SecLmrP25Error("truncated status dibit")
            value = int(block[70:72], 2)
            statuses.append({
                "physical_bit_offset": offset + 70,
                "dibit": block[70:72],
                "value": value,
                "meaning": _STATUS_MEANINGS[value],
            })
    return "".join(logical), statuses


def _phase1_regions(logical: str, duid: int) -> list[dict]:
    regions = [
        _region(logical, "frame_sync", 0, 48),
        _region(logical, "nid", 48, 112),
    ]
    if duid == 0x0:
        regions.extend((
            _region(logical, "encoded_header", 112, 760),
            _region(logical, "null", 760, 770),
        ))
    elif duid == 0x3:
        regions.append(_region(logical, "null", 112, 140))
    elif duid in (0x5, 0xA):
        auxiliary = "link_control" if duid == 0x5 else "encryption_sync"
        layout = (
            ("voice_1", 112, 256), ("voice_2", 256, 400),
            (f"{auxiliary}_fragment_1", 400, 440),
            ("voice_3", 440, 584), (f"{auxiliary}_fragment_2", 584, 624),
            ("voice_4", 624, 768), (f"{auxiliary}_fragment_3", 768, 808),
            ("voice_5", 808, 952), (f"{auxiliary}_fragment_4", 952, 992),
            ("voice_6", 992, 1136), (f"{auxiliary}_fragment_5", 1136, 1176),
            ("voice_7", 1176, 1320), (f"{auxiliary}_fragment_6", 1320, 1360),
            ("voice_8", 1360, 1504), ("low_speed_data", 1504, 1536),
            ("voice_9", 1536, 1680),
        )
        regions.extend(_region(logical, *item) for item in layout)
    elif duid == 0x7:
        regions.extend(
            _region(logical, f"tsbk_channel_block_{index + 1}",
                    112 + index * 196, 112 + (index + 1) * 196)
            for index in range(3)
        )
    elif duid == 0xF:
        regions.extend((
            _region(logical, "encoded_link_control", 112, 400),
            _region(logical, "null", 400, 420),
        ))
    else:
        regions.append(_region(logical, "packet_data", 112, len(logical)))
    return regions


@_closed
def parse_phase1_frame(data: object, bit_length: object = None) -> dict:
    """Validate and split one packed Phase-1 CAI frame.

    Offsets in ``regions`` refer to the status-stripped structural bit stream;
    status entries retain their physical-frame offsets.
    """

    bits = _packed_bits(data, bit_length, maximum=MAX_PHASE1_BITS)
    if len(bits) < 114:
        raise SecLmrP25Error("Phase 1 frame is too short for FS/NID/status")
    if int(bits[:48], 2) != PHASE1_SYNC:
        raise SecLmrP25Error("Phase 1 frame-sync mismatch")
    nid_bits = bits[48:70] + bits[72:114]
    if len(nid_bits) != 64:
        raise SecLmrP25Error("truncated Phase 1 NID")
    raw_nid = int(nid_bits, 2)
    nac, duid, distance, corrected = _decode_nid(raw_nid)
    expected_length = _PHASE1_LENGTHS[duid]
    if expected_length is not None and len(bits) != expected_length:
        raise SecLmrP25Error(
            f"{_DUID_NAMES[duid]} must contain {expected_length} transmitted bits"
        )
    if expected_length is None and len(bits) < 144:
        raise SecLmrP25Error("packet data unit is implausibly short")
    logical, statuses = _strip_status(bits)
    regions = _phase1_regions(logical, duid)
    return {
        "protocol": "APCO-P25-Phase-1",
        "modulation_context": "C4FM, 4800 symbols/s, 9600 channel bits/s",
        "transmitted_bit_length": len(bits),
        "structural_bit_length": len(logical),
        "coordinate_system": "regions use status-stripped structural bits",
        "sync_hex": f"{PHASE1_SYNC:012x}",
        "nac": nac,
        "nac_hex": f"{nac:03x}",
        "duid": duid,
        "data_unit": _DUID_NAMES[duid],
        "expected_transmitted_bits": expected_length,
        "nid_received_hex": f"{raw_nid:016x}",
        "nid_corrected_hex": f"{corrected:016x}",
        "nid_corrected_bits": distance,
        "nid_valid": True,
        "status_symbols": statuses,
        "regions": regions,
        "limitations": [
            "only the NID BCH is decoded; other channel coding remains encoded",
            "IMBE channel codewords are isolated but not converted to audio",
        ],
    }


_ALGORITHMS = {
    0x80: {
        "name": "clear",
        "standard_context": "unencrypted",
        "key_bits": 0,
        "effective_key_bits": 0,
        "recommended": False,
    },
    0x81: {
        "name": "DES-OFB",
        "standard_context": "legacy P25 block encryption",
        "key_bits": 64,
        "effective_key_bits": 56,
        "recommended": False,
    },
    0x84: {
        "name": "AES-256-OFB",
        "standard_context": "P25 AES profile",
        "key_bits": 256,
        "effective_key_bits": 256,
        "recommended": True,
    },
    0xAA: {
        "name": "ADP/RC4",
        "standard_context": "vendor algorithm identifier exposed by OP25",
        "key_bits": None,
        "effective_key_bits": None,
        "recommended": False,
    },
}


@_closed
def encryption_context(algid: object) -> dict:
    """Describe an observed ALGID without accepting or searching for a key."""

    if type(algid) is not int or not 0 <= algid <= 0xFF:
        raise SecLmrP25Error("ALGID must be an octet")
    details = _ALGORITHMS.get(algid)
    if details is None:
        details = {
            "name": "unknown_or_vendor",
            "standard_context": "not identified by this passive analyzer",
            "key_bits": None,
            "effective_key_bits": None,
            "recommended": None,
        }
    return {
        "algid": algid,
        "algid_hex": f"0x{algid:02x}",
        **details,
        "passive_only": True,
        "note": "MI is synchronization material and KID selects a key; neither is key material",
    }


@_closed
def parse_hdu_fields(data: object) -> dict:
    """Parse one caller-supplied, already-corrected 120-bit HDU header."""

    raw = _exact_bytes(data, 15, "corrected HDU header")
    algid = raw[10]
    return {
        "protocol": "APCO-P25-HDU-corrected-fields",
        "trust_boundary": "caller_supplied_post_fec_word",
        "message_indicator_hex": raw[:9].hex(),
        "manufacturer_id": raw[9],
        "manufacturer_id_hex": f"0x{raw[9]:02x}",
        "algorithm": encryption_context(algid),
        "key_id": int.from_bytes(raw[11:13], "big"),
        "key_id_hex": raw[11:13].hex(),
        "talkgroup_id": int.from_bytes(raw[13:15], "big"),
        "talkgroup_id_hex": raw[13:15].hex(),
    }


def _service_options(value: int) -> dict:
    return {
        "raw": value,
        "emergency": bool(value & 0x80),
        "protected": bool(value & 0x40),
        "duplex": bool(value & 0x20),
        "mode": bool(value & 0x10),
        "reserved_bit": bool(value & 0x08),
        "priority": value & 0x07,
    }


@_closed
def parse_link_control(data: object) -> dict:
    """Parse one caller-supplied, already-corrected 72-bit LCW."""

    raw = _exact_bytes(data, 9, "corrected link-control word")
    protected = bool(raw[0] & 0x80)
    standard_format_flag = bool(raw[0] & 0x40)
    lco = raw[0] & 0x3F
    result = {
        "protocol": "APCO-P25-link-control",
        "trust_boundary": "caller_supplied_post_fec_word",
        "protected": protected,
        "standard_format_flag": standard_format_flag,
        "lco": lco,
        "manufacturer_id": raw[1],
        "raw_hex": raw.hex(),
    }
    if protected:
        result["content_opaque"] = True
        result["note"] = "P bit set; content is not interpreted as clear fields"
        return result
    if lco == 0:
        result.update({
            "name": "group_voice_channel_user",
            "service_options": _service_options(raw[2]),
            "talkgroup_id": int.from_bytes(raw[4:6], "big"),
            "source_id": int.from_bytes(raw[6:9], "big"),
        })
    elif lco == 3:
        result.update({
            "name": "unit_to_unit_voice_channel_user",
            "service_options": _service_options(raw[2]),
            "target_id": int.from_bytes(raw[3:6], "big"),
            "source_id": int.from_bytes(raw[6:9], "big"),
        })
    else:
        result.update({
            "name": "unimplemented_or_manufacturer_specific",
            "opcode_specific_hex": raw[2:].hex(),
        })
    return result


@_closed
def parse_encryption_sync(data: object) -> dict:
    """Parse one caller-supplied, already-corrected 96-bit LDU2 ES word."""

    raw = _exact_bytes(data, 12, "corrected encryption-sync word")
    return {
        "protocol": "APCO-P25-encryption-sync",
        "trust_boundary": "caller_supplied_post_fec_word",
        "message_indicator_hex": raw[:9].hex(),
        "algorithm": encryption_context(raw[9]),
        "key_id": int.from_bytes(raw[10:12], "big"),
        "key_id_hex": raw[10:12].hex(),
    }


_P2_CODEWORDS = (
    0x00, 0x17, 0x2E, 0x39, 0x4B, 0x5C, 0x65, 0x72,
    0x8D, 0x9A, 0xA3, 0xB4, 0xC6, 0xD1, 0xE8, 0xFF,
)
_P2_TYPES = {
    0x0: ("4V", None, "voice"),
    0x3: ("SACCH", True, "control"),
    0x4: ("LCCH", True, "control"),
    0x6: ("2V", None, "voice"),
    0x9: ("FACCH", True, "control"),
    0xC: ("SACCH", False, "control"),
    0xD: ("LCCH_or_TDMA_control", False, "control"),
    0xF: ("FACCH", False, "control"),
}
_P2_DUID_PHYSICAL_DIBITS = (20, 57, 142, 179)


def _decode_phase2_duid(received: int) -> tuple[int, int, int]:
    distances = [(received ^ value).bit_count() for value in _P2_CODEWORDS]
    best = min(distances)
    winners = [index for index, distance in enumerate(distances) if distance == best]
    if best > 1 or len(winners) != 1:
        raise SecLmrP25Error("Phase 2 distributed DUID is uncorrectable")
    return winners[0], best, _P2_CODEWORDS[winners[0]]


@_closed
def parse_phase2_burst(data: object) -> dict:
    """Classify one 360-bit/180-dibit P25 Phase-2 physical burst."""

    bits = _packed_bits(data, 360, maximum=360)
    dibits = [int(bits[offset:offset + 2], 2) for offset in range(0, 360, 2)]
    received = 0
    for position in _P2_DUID_PHYSICAL_DIBITS:
        received = (received << 2) | dibits[position]
    duid, distance, corrected = _decode_phase2_duid(received)
    if duid not in _P2_TYPES:
        raise SecLmrP25Error("Phase 2 DUID is reserved or unsupported")
    name, scrambled, category = _P2_TYPES[duid]
    result = {
        "protocol": "APCO-P25-Phase-2",
        "transmitted_bits": 360,
        "transmitted_dibits": 180,
        "duration_ms": 30,
        "sync_or_isch_hex": f"{int(bits[:40], 2):010x}",
        "phase2_sync_match": int(bits[:40], 2) == PHASE2_SYNC,
        "duid": duid,
        "duid_name": name,
        "category": category,
        "acch_scrambled": scrambled,
        "duid_received_hex": f"{received:02x}",
        "duid_corrected_hex": f"{corrected:02x}",
        "duid_corrected_bits": distance,
        "duid_physical_dibit_offsets": list(_P2_DUID_PHYSICAL_DIBITS),
        "coordinate_note": (
            "physical offsets include the initial ISCH; subtract 10 for OP25's shifted payload view"
        ),
        "limitations": [
            "system-dependent scrambling is not removed",
            "AMBE+2 channel codewords are isolated but not converted to audio",
        ],
    }
    if category == "voice":
        physical = ((21, 57), (58, 94))
        if duid == 0:
            physical += ((106, 142), (143, 179))
        regions = []
        for index, (start, end) in enumerate(physical, 1):
            value = bits[start * 2:end * 2]
            regions.append({
                "name": f"ambe_plus_2_{index}",
                "physical_start_dibit": start,
                "physical_end_dibit": end,
                "payload_view_start_dibit": start - 10,
                "payload_view_end_dibit": end - 10,
                "coded_bits": len(value),
                "hex": _bits_hex(value),
            })
        result["voice_regions"] = regions
    return result


@_closed
def technology_context() -> dict:
    """Return static Phase-1/Phase-2 and vocoder interpretation boundaries."""

    return {
        "phase1": {
            "channel_khz": 12.5,
            "modulation": "C4FM",
            "symbols_per_second": 4800,
            "channel_bits_per_second": 9600,
            "dibit_deviation_khz": {
                "01": 1.8, "00": 0.6, "10": -0.6, "11": -1.8,
            },
            "voice": "IMBE: 88 parameter bits encoded/interleaved to 144 channel bits per 20 ms",
        },
        "phase2": {
            "channel_khz": 12.5,
            "access": "two-slot TDMA",
            "outbound_modulation": "H-DQPSK",
            "inbound_modulation": "H-CPM",
            "symbols_per_second": 6000,
            "aggregate_channel_bits_per_second": 12000,
            "voice": "half-rate AMBE+2: 72 coded bits, 49 parameters after channel decode",
            "scrambling_context": "44-bit WACN(20) || SYSID(12) || NAC(12) initializer required",
            "standards": ["TIA-102.BBAB physical layer", "TIA-102.BBAC MAC"],
        },
        "passive_only": True,
        "handoff": "raw IQ demodulation and vocoder synthesis belong to separate tools",
    }


def _read(path: str) -> bytes:
    candidate = Path(path)
    if not candidate.is_file() or candidate.stat().st_size > MAX_FILE_BYTES:
        raise SecLmrP25Error("input is absent or exceeds 8192 bytes")
    return candidate.read_bytes()


def _integer(text: str) -> int:
    try:
        return int(text, 0)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("expected an integer (decimal or 0x-prefixed)") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive APCO P25 structure decoder")
    sub = parser.add_subparsers(dest="kind", required=True)
    p1 = sub.add_parser("phase1", help="parse one packed Phase-1 air frame")
    p1.add_argument("file")
    p1.add_argument("--bits", type=int)
    p2 = sub.add_parser("phase2", help="parse one packed 360-bit Phase-2 burst")
    p2.add_argument("file")
    hdu = sub.add_parser("hdu", help="parse a corrected 15-byte HDU header")
    hdu.add_argument("file")
    lc = sub.add_parser("lc", help="parse a corrected 9-byte link-control word")
    lc.add_argument("file")
    ess = sub.add_parser("ess", help="parse a corrected 12-byte encryption-sync word")
    ess.add_argument("file")
    context = sub.add_parser("context", help="show Phase/encryption context")
    context.add_argument("--algid", type=_integer)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.kind == "phase1":
            result = parse_phase1_frame(_read(args.file), args.bits)
        elif args.kind == "phase2":
            result = parse_phase2_burst(_read(args.file))
        elif args.kind == "hdu":
            result = parse_hdu_fields(_read(args.file))
        elif args.kind == "lc":
            result = parse_link_control(_read(args.file))
        elif args.kind == "ess":
            result = parse_encryption_sync(_read(args.file))
        else:
            result = {"technology": technology_context()}
            if args.algid is not None:
                result["encryption"] = encryption_context(args.algid)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, SecLmrP25Error) as exc:
        print(f"sec_lmr_p25: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"sec_lmr_p25: internal input error ({type(exc).__name__})", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_FILE_BYTES",
    "PHASE1_SYNC",
    "PHASE2_SYNC",
    "SecLmrP25Error",
    "encryption_context",
    "main",
    "parse_encryption_sync",
    "parse_hdu_fields",
    "parse_link_control",
    "parse_phase1_frame",
    "parse_phase2_burst",
    "technology_context",
]
