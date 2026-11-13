"""Bounded, offline IEC 60870-5-101 FT1.2 serial trace decoder.

The link configuration is supplied by the caller: it is not negotiated on the
wire. Known ASDU layouts are normalized to the existing IEC-104 ASDU decoder;
unknown layouts remain raw evidence. No serial port or network is opened.

References: Beckhoff ``IEC 60870-5-101 telegram structure`` (11700014987),
ABB REC 523 manual 1MRS 750956-MUM, sections 1.2.2--1.2.4, and lib60870's
link_layer.c. These describe the additive checksum, control bits, and examples.
"""

from __future__ import annotations

import argparse
from functools import wraps
import json
from pathlib import Path
import sys

import ics_scada as _shared


MAX_INPUT = 4 * 1024 * 1024
MAX_FRAMES = 16384


class IEC101Error(ValueError):
    """Malformed, unsupported-configuration, or excessive IEC-101 input."""


def _fail_closed(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except IEC101Error:
            raise
        except Exception as exc:
            # Keep errors in the reused decoder inside this module's contract.
            raise IEC101Error(
                f"invalid input to {function.__name__}: {type(exc).__name__}"
            ) from None
    return guarded


def _blob(data, limit):
    if type(data) not in (bytes, bytearray, memoryview):
        raise IEC101Error("input must be bytes, bytearray, or memoryview")
    size = data.nbytes if type(data) is memoryview else len(data)
    if size > limit:
        raise IEC101Error(f"input exceeds {limit} bytes")
    return bytes(data)


def _integer(value, choices, name):
    if type(value) is not int or value not in choices:
        raise IEC101Error(f"invalid {name}")


def _mode(mode):
    if type(mode) is not str or mode not in ("balanced", "unbalanced"):
        raise IEC101Error("mode must be balanced or unbalanced")


def _widths(cot_size, common_address_size, ioa_size):
    _integer(cot_size, (1, 2), "COT size")
    _integer(common_address_size, (1, 2), "common address size")
    _integer(ioa_size, (1, 2, 3), "IOA size")


def _configuration(address_size, mode, cot_size, common_address_size, ioa_size):
    _mode(mode)
    _integer(address_size, (0, 1, 2), "link address size")
    if address_size == 0 and mode != "balanced":
        raise IEC101Error("address size zero requires balanced mode")
    _widths(cot_size, common_address_size, ioa_size)


@_fail_closed
def decode_control(control, *, mode="unbalanced"):
    """Decode the link control octet; retain reserved bits as evidence.

    DIR identifies the physical direction in balanced mode, independently of
    PRM. In unbalanced mode bit 7 is reserved and bit 5 of a secondary response
    is ACD; in balanced mode that secondary bit is reserved instead.
    """
    _integer(control, range(256), "control octet")
    _mode(mode)
    primary = bool(control & 0x40)
    function = control & 15
    if primary:
        names = {0: "reset_remote_link", 1: "reset_user_process",
                 3: "user_data_confirmed", 4: "user_data_unconfirmed",
                 9: "request_link_status"}
        if mode == "balanced":
            names[2] = "test_link"
        else:
            names.update({8: "request_access_demand", 10: "request_class_1",
                          11: "request_class_2"})
    else:
        names = {0: "ack", 1: "nack_link_busy", 11: "link_status",
                 14: "link_service_not_functioning", 15: "link_service_not_implemented"}
        if mode == "unbalanced":
            names.update({8: "user_data", 9: "requested_data_unavailable"})
    reserved = control & 0x80 if mode == "unbalanced" else 0
    if mode == "balanced" and not primary:
        reserved |= control & 0x20
    return {
        "raw": control, "mode": mode, "primary": primary,
        "role": "primary" if primary else "secondary",
        "function_code": function, "function": names.get(function, "reserved"),
        "dir": bool(control & 0x80) if mode == "balanced" else None,
        "fcb": bool(control & 0x20) if primary else None,
        "fcv": bool(control & 0x10) if primary else None,
        "acd": bool(control & 0x20) if not primary and mode == "unbalanced" else None,
        "dfc": bool(control & 0x10) if not primary else None,
        "reserved_bits": reserved,
    }


@_fail_closed
def decode_asdu(data, *, cot_size=2, common_address_size=2, ioa_size=3):
    """Decode a serial ASDU using ics_scada's existing value/type decoders.

    Known layouts must consume the entire ASDU. Unknown type layouts retain
    their original information bytes; their object boundaries are not guessed.
    COT includes its optional originator octet in ``cot_size``.
    """
    data = _blob(data, 254)
    _widths(cot_size, common_address_size, ioa_size)
    header_size = 2 + cot_size + common_address_size
    if len(data) < header_size:
        raise IEC101Error("truncated ASDU header")
    type_id, vsq = data[:2]
    count, sequential = vsq & 0x7f, bool(vsq & 0x80)
    originator = data[3] if cot_size == 2 else 0
    ca_start = 2 + cot_size
    common_address = int.from_bytes(data[ca_start:header_size], "little")
    normalized = bytearray((type_id, vsq, data[2], originator))
    normalized.extend(common_address.to_bytes(2, "little"))
    layout = _shared.IEC104_ELEM.get(type_id)
    information = data[header_size:]
    if layout is None:
        normalized.extend(information)
    else:
        size = layout[0]
        expected = ((ioa_size if count else 0) + count * size
                    if sequential else count * (ioa_size + size))
        if len(information) != expected:
            raise IEC101Error("ASDU object count/size does not match its payload")
        offset = 0
        for index in range(count):
            if not sequential or index == 0:
                ioa = int.from_bytes(information[offset:offset + ioa_size], "little")
                if sequential and ioa + count - 1 >= 1 << (8 * ioa_size):
                    raise IEC101Error("sequential IOA exceeds configured address width")
                normalized.extend(ioa.to_bytes(3, "little"))
                offset += ioa_size
            normalized.extend(information[offset:offset + size])
            offset += size
    result = _shared._iec104_parse_asdu(bytes(normalized))
    result.update({"raw_hex": data.hex(), "layout_decoded": layout is not None,
                   "cot_size": cot_size, "common_address_size": common_address_size,
                   "ioa_size": ioa_size})
    if cot_size == 1:
        result["originator_address"] = None
    if layout is None:
        result["information_raw_hex"] = information.hex()
    return result


def _one(data, offset, address_size, mode, cot_size, common_address_size, ioa_size):
    start = data[offset]
    if start in (0xe5, 0xa2):
        return {"protocol": "IEC-101", "format": "single", "offset": offset,
                "length": 1, "raw_hex": data[offset:offset + 1].hex(),
                "acknowledgement": "positive" if start == 0xe5 else "negative"}, offset + 1
    if start == 0x10:
        length = address_size + 4
        body_start = offset + 1
        body_length = address_size + 1
        kind = "fixed"
    elif start == 0x68:
        if len(data) - offset < 4:
            raise IEC101Error(f"truncated variable header at offset {offset}")
        body_length = data[offset + 1]
        if data[offset + 2] != body_length or data[offset + 3] != 0x68:
            raise IEC101Error(f"invalid repeated length/start at offset {offset}")
        if body_length <= address_size + 1:
            raise IEC101Error("variable frame must contain an ASDU")
        length = body_length + 6
        body_start = offset + 4
        kind = "variable"
    else:
        raise IEC101Error(f"invalid FT1.2 start byte at offset {offset}")
    end = offset + length
    if end > len(data):
        raise IEC101Error(f"truncated {kind} frame at offset {offset}")
    if data[end - 1] != 0x16:
        raise IEC101Error(f"invalid stop byte at offset {offset}")
    body = data[body_start:body_start + body_length]
    checksum = sum(body) & 0xff
    if checksum != data[end - 2]:
        raise IEC101Error(f"checksum mismatch at offset {offset}")
    control = decode_control(body[0], mode=mode)
    address = int.from_bytes(body[1:1 + address_size], "little") if address_size else None
    result = {"protocol": "IEC-101", "format": kind, "offset": offset,
              "length": length, "raw_hex": data[offset:end].hex(),
              "control": control, "link_address": address, "address_size": address_size,
              "broadcast": (mode == "unbalanced" and address == (1 << (8 * address_size)) - 1),
              "checksum": checksum, "checksum_valid": True}
    if kind == "variable":
        result["asdu"] = decode_asdu(body[1 + address_size:], cot_size=cot_size,
                                     common_address_size=common_address_size, ioa_size=ioa_size)
    return result, end


@_fail_closed
def parse_frame(data, *, address_size=1, mode="unbalanced", cot_size=2,
                common_address_size=2, ioa_size=3):
    """Parse exactly one frame; reject trailing bytes and invalid checksums."""
    data = _blob(data, 261)
    _configuration(address_size, mode, cot_size, common_address_size, ioa_size)
    if not data:
        raise IEC101Error("empty frame")
    result, end = _one(data, 0, address_size, mode, cot_size, common_address_size, ioa_size)
    if end != len(data):
        raise IEC101Error("trailing bytes after frame")
    return result


@_fail_closed
def parse_stream(data, *, address_size=1, mode="unbalanced", cot_size=2,
                 common_address_size=2, ioa_size=3, max_frames=MAX_FRAMES):
    """Parse a complete concatenated trace, with no silent resynchronization.

    An empty stream yields an empty list. Any malformed or trailing partial
    frame rejects the entire stream. The input and output counts are bounded.
    """
    data = _blob(data, MAX_INPUT)
    _configuration(address_size, mode, cot_size, common_address_size, ioa_size)
    _integer(max_frames, range(1, MAX_FRAMES + 1), "frame limit")
    offset, frames = 0, []
    while offset < len(data):
        if len(frames) >= max_frames:
            raise IEC101Error("frame count limit exceeded")
        frame, offset = _one(data, offset, address_size, mode, cot_size, common_address_size, ioa_size)
        frames.append(frame)
    return frames


def main(argv=None):
    """CLI: decode a raw serial capture or an ASCII whitespace-separated hex file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--hex", action="store_true", help="input file contains ASCII hexadecimal")
    parser.add_argument("--address-size", type=int, choices=(0, 1, 2), default=1)
    parser.add_argument("--mode", choices=("balanced", "unbalanced"), default="unbalanced")
    parser.add_argument("--cot-size", type=int, choices=(1, 2), default=2)
    parser.add_argument("--common-address-size", type=int, choices=(1, 2), default=2)
    parser.add_argument("--ioa-size", type=int, choices=(1, 2, 3), default=3)
    try:
        if argv is not None and (type(argv) not in (list, tuple)
                                 or any(type(arg) is not str for arg in argv)):
            raise IEC101Error("CLI arguments must be strings")
        args = parser.parse_args(argv)
        limit = 3 * MAX_INPUT if args.hex else MAX_INPUT
        with args.file.open("rb") as handle:
            raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise IEC101Error("input file exceeds size limit")
        if args.hex:
            raw = bytes.fromhex(raw.decode("ascii"))
        result = parse_stream(raw, address_size=args.address_size, mode=args.mode,
                              cot_size=args.cot_size, common_address_size=args.common_address_size,
                              ioa_size=args.ioa_size)
        print(json.dumps(result, indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f"IEC-101 error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
