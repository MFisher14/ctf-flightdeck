#!/usr/bin/env python3
"""Offline IEEE C37.118.2 (2005/2011 layouts) synchrophasor decoder.

Parse exact raw protocol frames, or a concatenation already extracted from a
TCP/UDP capture. CFG-2 supplies the layout for data frames; CFG-1 is decoded as
capability metadata and deliberately does not replace the active layout. No
network I/O, frame generation, untrusted execution, or submission is performed.
CFG-3 and later version-3 layouts are rejected rather than guessed.

API: parse_frame(frame, configuration=cfg2_bytes), parse_stream(stream).
CLI: ./.venv/bin/python solvers/toolkits/power_c37118.py stream.bin
     ./.venv/bin/python solvers/toolkits/power_c37118.py data.bin --config cfg2.bin
     ./.venv/bin/python solvers/toolkits/power_c37118.py frame.hex --hex

All public byte parsers raise PowerC37118Error on malformed/unsupported input.
Reference: PNNL-28499, pp. 22-27; iicsys/pypmu tests/validate_frames.py.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import struct
import sys


MAX_INPUT = 32 * 1024 * 1024
MAX_FRAMES = 100_000
MAX_PMUS = 1024
MAX_CHANNELS = 4096
FRAME_TYPES = {0: "data", 1: "header", 2: "cfg1", 3: "cfg2", 4: "command"}
COMMANDS = {1: "stop_data", 2: "start_data", 3: "send_header", 4: "send_cfg1",
            5: "send_cfg2", 6: "send_cfg3", 8: "extended"}


class PowerC37118Error(ValueError):
    """Invalid, truncated, unsupported, or excessive synchrophasor input."""


def _bytes(data, limit=MAX_INPUT):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise PowerC37118Error("input must be bytes, bytearray, or memoryview")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > limit:
            raise PowerC37118Error("input exceeds size limit")
        return bytes(data)
    except (ValueError, TypeError, BufferError) as exc:
        raise PowerC37118Error("invalid byte buffer") from exc


def crc16(data):
    """CRC-16/IBM-3740 (CCITT-FALSE): poly 0x1021, init 0xffff, no xor/reflection."""
    raw = _bytes(data)
    crc = 0xFFFF
    for byte in raw:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xFFFF
    return crc


class _Reader:
    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    def take(self, size):
        if size > len(self.raw) - self.offset:
            raise PowerC37118Error("truncated frame field")
        start = self.offset
        self.offset += size
        return self.raw[start:self.offset]

    def integer(self, size=2, signed=False):
        return int.from_bytes(self.take(size), "big", signed=signed)

    def floating(self):
        value = struct.unpack(">f", self.take(4))[0]
        if not math.isfinite(value):
            raise PowerC37118Error("non-finite measurement")
        return value

    def text(self, size):
        try:
            return self.take(size).decode("ascii").rstrip(" \x00")
        except UnicodeDecodeError as exc:
            raise PowerC37118Error("non-ASCII station/channel/header text") from exc

    def done(self):
        if self.offset != len(self.raw):
            raise PowerC37118Error("undeclared trailing frame bytes")


def _envelope(raw):
    if not 16 <= len(raw) <= 65535:
        raise PowerC37118Error("frame length must be 16..65535")
    if raw[0] != 0xAA or raw[1] & 0x80:
        raise PowerC37118Error("invalid synchronization word")
    kind, version = raw[1] >> 4, raw[1] & 15
    if kind not in FRAME_TYPES or version not in (1, 2):
        raise PowerC37118Error("unsupported frame type or protocol version")
    if int.from_bytes(raw[2:4], "big") != len(raw):
        raise PowerC37118Error("declared frame length mismatch")
    expected = int.from_bytes(raw[-2:], "big")
    if crc16(raw[:-2]) != expected:
        raise PowerC37118Error("frame CRC mismatch")
    stream_id = int.from_bytes(raw[4:6], "big")
    if not 1 <= stream_id <= 65534:
        raise PowerC37118Error("reserved stream identifier")
    fraction = int.from_bytes(raw[10:14], "big")
    quality = fraction >> 24
    return {"protocol": "ieee-c37.118", "frame_type": FRAME_TYPES[kind],
            "version": version, "frame_size": len(raw), "idcode": stream_id,
            "soc": int.from_bytes(raw[6:10], "big"), "fracsec_raw": fraction,
            "fraction": fraction & 0xFFFFFF, "time_quality_raw": quality,
            "time_quality_code": quality & 15, "leap_pending": bool(quality & 0x10),
            "leap_occurred": bool(quality & 0x20), "leap_delete": bool(quality & 0x40),
            "crc": expected, "crc_valid": True}


def _configuration(raw, record):
    rd = _Reader(raw[14:-2])
    time_base_raw = rd.integer(4)
    time_base = time_base_raw & 0xFFFFFF
    count = rd.integer()
    if not time_base or not 1 <= count <= MAX_PMUS:
        raise PowerC37118Error("invalid time base or excessive/zero PMU count")
    pmus = []
    for _ in range(count):
        station = rd.text(16)
        ident, fmt = rd.integer(), rd.integer()
        if not 1 <= ident <= 65534 or fmt & 0xFFF0:
            raise PowerC37118Error("invalid PMU identifier or reserved FORMAT bits")
        phasors, analogs, digitals = rd.integer(), rd.integer(), rd.integer()
        total = phasors + analogs + 16 * digitals
        if total > MAX_CHANNELS:
            raise PowerC37118Error("excessive channel count")
        names = [rd.text(16) for _ in range(total)]
        ph_units, an_units, dig_units = [], [], []
        for _ in range(phasors):
            unit = rd.integer(4)
            if unit >> 24 not in (0, 1):
                raise PowerC37118Error("unsupported phasor unit type")
            ph_units.append({"raw": unit, "kind": "voltage" if unit >> 24 == 0 else "current",
                             "scale_factor": unit & 0xFFFFFF,
                             "units_per_count": (unit & 0xFFFFFF) * 1e-5})
        for _ in range(analogs):
            raw_unit = rd.take(4)
            an_units.append({"raw": int.from_bytes(raw_unit, "big"), "type": raw_unit[0],
                             "user_scale": int.from_bytes(raw_unit[1:], "big", signed=True)})
        for _ in range(digitals):
            dig_units.append({"normal_mask": rd.integer(), "valid_mask": rd.integer()})
        fnom, cfg_count = rd.integer(), rd.integer()
        if fnom & 0xFFFE:
            raise PowerC37118Error("unsupported FNOM flags")
        pmus.append({"station": station, "idcode": ident, "format": fmt,
                     "phasor_polar": bool(fmt & 1), "phasor_float": bool(fmt & 2),
                     "analog_float": bool(fmt & 4), "frequency_float": bool(fmt & 8),
                     "phasor_names": names[:phasors],
                     "analog_names": names[phasors:phasors + analogs],
                     "digital_names": [names[phasors + analogs + i * 16:
                                             phasors + analogs + (i + 1) * 16]
                                       for i in range(digitals)],
                     "phasor_units": ph_units, "analog_units": an_units,
                     "digital_units": dig_units, "nominal_frequency_hz": 50 if fnom & 1 else 60,
                     "configuration_count": cfg_count})
    rate = rd.integer(signed=True)
    if rate == 0:
        raise PowerC37118Error("zero data rate")
    rd.done()
    record.update(time_base_raw=time_base_raw, time_base=time_base, pmus=pmus,
                  data_rate=rate, frames_per_second=rate if rate > 0 else -1 / rate)
    return record


def _measurements(raw, record, config):
    if config is None or config["frame_type"] != "cfg2":
        raise PowerC37118Error("data frame requires a CFG-2 configuration")
    if record["idcode"] != config["idcode"] or record["version"] != config["version"]:
        raise PowerC37118Error("data/configuration stream ID or version mismatch")
    rd = _Reader(raw[14:-2])
    measurements = []
    for pmu in config["pmus"]:
        status = rd.integer()
        values = []
        for name, unit in zip(pmu["phasor_names"], pmu["phasor_units"]):
            polar, floating = pmu["phasor_polar"], pmu["phasor_float"]
            a = rd.floating() if floating else rd.integer(signed=not polar)
            b = rd.floating() if floating else rd.integer(signed=True)
            first = a if floating else a * unit["units_per_count"]
            second = b if floating else b * (1e-4 if polar else unit["units_per_count"])
            value = {"name": name, "unit": unit["kind"], "raw": [a, b]}
            value.update({"magnitude": first, "angle_radians": second} if polar else
                         {"real": first, "imaginary": second})
            values.append(value)
        floating = pmu["frequency_float"]
        freq = rd.floating() if floating else rd.integer(signed=True)
        dfreq = rd.floating() if floating else rd.integer(signed=True)
        analogs = [{"name": name,
                    "value": rd.floating() if pmu["analog_float"] else rd.integer(signed=True),
                    "unit_metadata": unit}
                   for name, unit in zip(pmu["analog_names"], pmu["analog_units"])]
        digitals = []
        for names, unit in zip(pmu["digital_names"], pmu["digital_units"]):
            value = rd.integer()
            digitals.append({"raw": value,
                             "abnormal_mask": (value ^ unit["normal_mask"]) & unit["valid_mask"],
                             "bits": [{"name": name, "value": bool(value & (1 << bit)),
                                       "valid": bool(unit["valid_mask"] & (1 << bit))}
                                      for bit, name in enumerate(names)]})
        measurements.append({"station": pmu["station"], "idcode": pmu["idcode"],
                             "status_raw": status, "data_error_code": status >> 14,
                             "synchronization_error": bool(status & 0x2000),
                             "sorting_by_arrival": bool(status & 0x1000),
                             "trigger_detected": bool(status & 0x0800),
                             "configuration_change": bool(status & 0x0400),
                             "phasors": values, "frequency_raw": freq, "dfrequency_raw": dfreq,
                             "frequency_hz": freq if floating else pmu["nominal_frequency_hz"] + freq * .001,
                             "rocof_hz_per_second": dfreq if floating else dfreq * .01,
                             "analogs": analogs, "digitals": digitals})
    rd.done()
    # Preserve every timestamp bit, including anomalous fractions, for forensic use.
    record.update(measurements=measurements, time_base=config["time_base"],
                  fractional_seconds=record["fraction"] / config["time_base"],
                  fraction_in_range=record["fraction"] < config["time_base"])
    return record


def _parse(raw, config=None):
    record = _envelope(raw)
    kind = record["frame_type"]
    if kind in ("cfg1", "cfg2"):
        return _configuration(raw, record)
    if kind == "data":
        return _measurements(raw, record, config)
    rd = _Reader(raw[14:-2])
    if kind == "header":
        record["text"] = rd.text(len(raw) - 16)
    else:
        command = rd.integer()
        if command not in COMMANDS:
            raise PowerC37118Error("unsupported or reserved command")
        record.update(command=command, command_name=COMMANDS[command])
        if command == 8:
            record["extended_data_hex"] = rd.take(len(rd.raw) - rd.offset).hex()
    rd.done()
    return record


def _config(data):
    if data is None:
        return None
    result = _parse(_bytes(data, 65535))
    if result["frame_type"] != "cfg2":
        raise PowerC37118Error("configuration argument must contain one CFG-2 frame")
    return result


def parse_frame(data, *, configuration=None):
    """Decode one exact frame; data frames require raw CFG-2 bytes as configuration."""
    return _parse(_bytes(data, 65535), _config(configuration))


def parse_stream(data, *, configuration=None):
    """Decode an exact concatenation, tracking CFG-2 by stream ID. No resync guessing."""
    raw = _bytes(data)
    if not raw:
        raise PowerC37118Error("empty frame stream")
    initial = _config(configuration)
    configs = {} if initial is None else {initial["idcode"]: initial}
    records, offset = [], 0
    while offset < len(raw):
        if len(records) >= MAX_FRAMES or len(raw) - offset < 16:
            raise PowerC37118Error("excessive frame count or truncated stream")
        length = int.from_bytes(raw[offset + 2:offset + 4], "big")
        if length < 16 or length > len(raw) - offset:
            raise PowerC37118Error("invalid stream frame length")
        ident = int.from_bytes(raw[offset + 4:offset + 6], "big")
        record = _parse(raw[offset:offset + length], configs.get(ident))
        if record["frame_type"] == "cfg2":
            configs[ident] = record
        records.append({"offset": offset, **record})
        offset += length
    return records


def _read_file(path, is_hex=False):
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise PowerC37118Error("file exceeds size limit")
        return bytes.fromhex(raw.decode("ascii")) if is_hex else raw
    except (OSError, ValueError, TypeError) as exc:
        raise PowerC37118Error(f"cannot read input: {exc}") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="raw concatenated C37.118 frame file")
    parser.add_argument("--hex", action="store_true", help="input file is whitespace-separated hexadecimal")
    parser.add_argument("--config", help="raw CFG-2 frame for a data-only input")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        config = _read_file(args.config) if args.config else None
        records = parse_stream(_read_file(args.file, args.hex), configuration=config)
        print(json.dumps(records, indent=2, allow_nan=False))
        return 0
    except PowerC37118Error as exc:
        print(f"power_c37118: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
