#!/usr/bin/env python3
"""Offline logic-analyzer, debug-bus, and fault-injection trace analysis.

All functions consume saved arrays/CSV/JSON.  They cannot open serial devices, GPIO, JTAG,
SWD, oscilloscopes, or other interfaces.  Bounded parsers cover UART, SPI, I2C, the JTAG TAP,
SWD transfers, glitch campaign summaries, trace alignment/t-tests, and first-round AES CPA.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import statistics
from pathlib import Path
from typing import Iterable, Sequence


MAX_TEXT = 32 << 20
MAX_SAMPLES = 2_000_000
MAX_FRAMES = 200_000
MAX_TRACE_CELLS = 8_000_000
MAX_CPA_WORK = 50_000_000


class CaptureError(ValueError):
    pass


def _logic(value: object) -> int:
    text = str(value).strip().lower()
    if text in {"0", "0.0", "false", "low", "l"}:
        return 0
    if text in {"1", "1.0", "true", "high", "h"}:
        return 1
    try:
        number = float(text)
    except ValueError as exc:
        raise CaptureError(f"invalid logic value {value!r}") from exc
    if not math.isfinite(number):
        raise CaptureError("non-finite logic value")
    return int(number >= 0.5)


def parse_logic_csv(text: str) -> dict:
    """Parse saved Saleae/sigrok/generic CSV into time + named digital channels."""
    if not isinstance(text, str):
        raise CaptureError("logic CSV exceeds cap")
    try:
        over_cap = len(text.encode("utf-8")) > MAX_TEXT
    except UnicodeError as exc:
        raise CaptureError("logic CSV is not encodable text") from exc
    if over_cap:
        raise CaptureError("logic CSV exceeds cap")
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames or len(reader.fieldnames) > 256:
        raise CaptureError("logic CSV needs a bounded header")
    names = [str(name).strip() for name in reader.fieldnames]
    time_name = next((name for name in names if name.lower() in {
        "time", "time [s]", "timestamp", "seconds", "t"}), names[0])
    channels = {name: [] for name in names if name != time_name}
    times = []
    for row_index, row in enumerate(reader):
        if row_index >= MAX_SAMPLES:
            raise CaptureError("logic sample cap exceeded")
        try:
            timestamp = float(str(row.get(time_name, "")).strip())
        except ValueError as exc:
            raise CaptureError(f"bad timestamp at row {row_index + 2}") from exc
        if not math.isfinite(timestamp) or (times and timestamp < times[-1]):
            raise CaptureError("timestamps must be finite and nondecreasing")
        times.append(timestamp)
        for name in channels:
            channels[name].append(_logic(row.get(name, "")))
    return {"time": times, "channels": channels, "sample_count": len(times)}


def estimate_uart_baud(levels: Sequence[int], sample_rate: float) -> float | None:
    """Estimate baud from the shortest stable run in an oversampled saved trace."""
    if len(levels) > MAX_SAMPLES or sample_rate <= 0 or not math.isfinite(sample_rate):
        raise CaptureError("invalid UART trace")
    runs, start = [], 0
    for index in range(1, len(levels) + 1):
        if index == len(levels) or _logic(levels[index]) != _logic(levels[start]):
            if index - start >= 2:
                runs.append(index - start)
            start = index
    if not runs:
        return None
    # Lower quartile is more robust than the absolute minimum against one-sample glitches.
    runs.sort()
    samples_per_bit = statistics.median(runs[:max(1, len(runs) // 4)])
    return sample_rate / samples_per_bit if samples_per_bit else None


def decode_uart(levels: Sequence[int], sample_rate: float, baud: float, *, data_bits: int = 8,
                parity: str = "none", stop_bits: int = 1, inverted: bool = False) -> list[dict]:
    try:
        sample_count = len(levels)
    except TypeError as exc:
        raise CaptureError("invalid UART trace") from exc
    if sample_count > MAX_SAMPLES or not 5 <= data_bits <= 9 or stop_bits not in (1, 2):
        raise CaptureError("invalid UART layout")
    if not isinstance(parity, str):
        raise CaptureError("invalid UART parity")
    parity = parity.lower()
    if parity not in {"none", "even", "odd", "mark", "space"}:
        raise CaptureError("invalid UART parity")
    if sample_rate <= 0 or baud <= 0 or not math.isfinite(sample_rate + baud):
        raise CaptureError("invalid UART timing")
    sps = sample_rate / baud
    if sps < 2:
        raise CaptureError("UART trace must be at least 2x oversampled")
    logical = [(_logic(v) ^ int(inverted)) for v in levels]
    rows, index = [], 1
    frame_bits = 1 + data_bits + (parity != "none") + stop_bits

    def sample(at: float) -> int | None:
        pos = int(round(at))
        return logical[pos] if 0 <= pos < len(logical) else None

    while index < len(logical) and len(rows) < MAX_FRAMES:
        if logical[index - 1] == 1 and logical[index] == 0:
            start = index
            data = [sample(start + (1.5 + bit) * sps) for bit in range(data_bits)]
            if any(bit is None for bit in data):
                break
            value = sum(int(bit) << bit_index for bit_index, bit in enumerate(data))
            cursor = 1 + data_bits
            parity_ok = None
            parity_bit = None
            if parity != "none":
                parity_bit = sample(start + (cursor + 0.5) * sps)
                cursor += 1
                if parity_bit is None:
                    break
                ones = sum(int(bit) for bit in data)
                expected = {"even": ones & 1, "odd": 1 ^ (ones & 1),
                            "mark": 1, "space": 0}[parity]
                parity_ok = parity_bit == expected
            stops = [sample(start + (cursor + stop + 0.5) * sps) for stop in range(stop_bits)]
            framing_ok = all(bit == 1 for bit in stops)
            rows.append({"sample": start, "value": value, "data": bytes([value & 0xFF]),
                         "parity_bit": parity_bit, "parity_ok": parity_ok,
                         "framing_ok": framing_ok})
            index = max(index + 1, int(start + frame_bits * sps))
        else:
            index += 1
    return rows


def _same_lengths(*channels: Sequence[int]) -> int:
    lengths = {len(channel) for channel in channels if channel is not None}
    if len(lengths) != 1:
        raise CaptureError("logic channels have unequal lengths")
    size = lengths.pop() if lengths else 0
    if size > MAX_SAMPLES:
        raise CaptureError("logic sample cap exceeded")
    return size


def decode_spi(clk: Sequence[int], *, mosi: Sequence[int] | None = None,
               miso: Sequence[int] | None = None, cs: Sequence[int] | None = None,
               mode: int = 0, bit_order: str = "msb", cs_active: int = 0) -> list[dict]:
    """Decode SPI modes 0..3 into chip-select-bounded transactions."""
    if mode not in range(4) or bit_order not in {"msb", "lsb"} or cs_active not in (0, 1):
        raise CaptureError("invalid SPI options")
    n = _same_lengths(clk, *(channel for channel in (mosi, miso, cs) if channel is not None))
    if n < 2:
        return []
    cpol, cpha = mode >> 1, mode & 1
    wanted_rising = (cpol == 0 and cpha == 0) or (cpol == 1 and cpha == 1)
    transactions, current = [], None

    def finish() -> None:
        nonlocal current
        if current is None:
            return
        for key in ("mosi_bits", "miso_bits"):
            bits = current.pop(key)
            current[key.replace("_bits", "")] = _pack_bits(bits, bit_order)
            current[key] = "".join(str(v) for v in bits)
        current["complete"] = (len(current["mosi_bits"]) % 8 == 0 and
                               len(current["miso_bits"]) % 8 == 0)
        transactions.append(current)
        current = None

    for index in range(1, n):
        active = cs is None or _logic(cs[index]) == cs_active
        if not active:
            finish()
            continue
        previous, now = _logic(clk[index - 1]), _logic(clk[index])
        rising = previous == 0 and now == 1
        falling = previous == 1 and now == 0
        sample_edge = rising if wanted_rising else falling
        if sample_edge:
            if current is None:
                current = {"start_sample": index, "mosi_bits": [], "miso_bits": []}
            if mosi is not None:
                current["mosi_bits"].append(_logic(mosi[index]))
            if miso is not None:
                current["miso_bits"].append(_logic(miso[index]))
            current["end_sample"] = index
    finish()
    return transactions[:MAX_FRAMES]


def _pack_bits(bits: Sequence[int], order: str) -> bytes:
    out = bytearray()
    for pos in range(0, len(bits) - 7, 8):
        chunk = bits[pos:pos + 8]
        if order == "msb":
            out.append(sum(_logic(bit) << (7 - idx) for idx, bit in enumerate(chunk)))
        else:
            out.append(sum(_logic(bit) << idx for idx, bit in enumerate(chunk)))
    return bytes(out)


def decode_i2c(scl: Sequence[int], sda: Sequence[int]) -> list[dict]:
    """Decode START/repeated-START/STOP, 7/10-bit address, ACK, and data bytes."""
    n = _same_lengths(scl, sda)
    transactions, current, bits = [], None, []

    def flush_byte() -> None:
        nonlocal bits, current
        if current is None or len(bits) != 9:
            return
        byte = sum(bits[i] << (7 - i) for i in range(8))
        current["octets"].append(byte)
        current["acks"].append(bits[8] == 0)
        bits = []

    def finish(stopped: bool) -> None:
        nonlocal current, bits
        if current is None:
            return
        if bits:
            current["partial_bits"] = "".join(map(str, bits))
        octets = current.pop("octets")
        if octets:
            first = octets[0]
            if first & 0xF8 == 0xF0 and len(octets) >= 2:
                high = (first & 0x06) << 7
                current["address_bits"] = 10
                if first & 1:
                    # Combined 10-bit READ: the read header repeats only the high
                    # address bits; the low address byte was sent in the preceding
                    # write phase (so octets[1:] is data, not the low address byte).
                    prior = transactions[-1] if (current["repeated_start"] and transactions) else None
                    low = prior["address"] & 0xFF if (prior and prior.get("address_bits") == 10) else 0
                    current["address"] = high | low
                    current["rw"] = "r"
                    current["data"] = bytes(octets[1:])
                else:
                    current["address"] = high | octets[1]
                    current["rw"] = "w"
                    current["data"] = bytes(octets[2:])
            else:
                current["address"] = first >> 1
                current["rw"] = "r" if first & 1 else "w"
                current["address_bits"] = 7
                current["data"] = bytes(octets[1:])
        current["stopped"] = stopped
        transactions.append(current)
        current, bits = None, []

    for index in range(1, n):
        clock = _logic(scl[index])
        data_before, data_now = _logic(sda[index - 1]), _logic(sda[index])
        if clock and data_before == 1 and data_now == 0:
            repeated = current is not None
            finish(False)
            current = {"start_sample": index, "repeated_start": repeated,
                       "octets": [], "acks": []}
            bits = []
            continue
        if clock and data_before == 0 and data_now == 1:
            finish(True)
            continue
        if current is not None and _logic(scl[index - 1]) == 0 and clock == 1:
            bits.append(data_now)
            if len(bits) == 9:
                flush_byte()
    finish(False)
    return transactions[:MAX_FRAMES]


_TAP = {
    "test-logic-reset": ("run-test-idle", "test-logic-reset"),
    "run-test-idle": ("run-test-idle", "select-dr-scan"),
    "select-dr-scan": ("capture-dr", "select-ir-scan"),
    "capture-dr": ("shift-dr", "exit1-dr"),
    "shift-dr": ("shift-dr", "exit1-dr"),
    "exit1-dr": ("pause-dr", "update-dr"),
    "pause-dr": ("pause-dr", "exit2-dr"),
    "exit2-dr": ("shift-dr", "update-dr"),
    "update-dr": ("run-test-idle", "select-dr-scan"),
    "select-ir-scan": ("capture-ir", "test-logic-reset"),
    "capture-ir": ("shift-ir", "exit1-ir"),
    "shift-ir": ("shift-ir", "exit1-ir"),
    "exit1-ir": ("pause-ir", "update-ir"),
    "pause-ir": ("pause-ir", "exit2-ir"),
    "exit2-ir": ("shift-ir", "update-ir"),
    "update-ir": ("run-test-idle", "select-dr-scan"),
}


def decode_jtag(tck: Sequence[int], tms: Sequence[int], tdi: Sequence[int],
                tdo: Sequence[int] | None = None, *, initial_state: str = "test-logic-reset") -> dict:
    """Run the IEEE 1149.1 TAP state machine over saved digital samples."""
    if initial_state not in _TAP:
        raise CaptureError("unknown JTAG TAP state")
    n = _same_lengths(tck, tms, tdi, *(channel for channel in (tdo,) if channel is not None))
    state, scans, transitions, active = initial_state, [], [], None
    for index in range(1, n):
        if _logic(tck[index - 1]) == 0 and _logic(tck[index]) == 1:
            if state in {"shift-ir", "shift-dr"}:
                kind = state[-2:].upper()
                if active is None or active["kind"] != kind:
                    active = {"kind": kind, "start_sample": index, "tdi_bits": [], "tdo_bits": []}
                active["tdi_bits"].append(_logic(tdi[index]))
                if tdo is not None:
                    active["tdo_bits"].append(_logic(tdo[index]))
                active["end_sample"] = index
            next_state = _TAP[state][_logic(tms[index])]
            transitions.append((index, state, next_state))
            if active is not None and state.startswith("shift-") and not next_state.startswith("shift-"):
                for key in ("tdi_bits", "tdo_bits"):
                    values = active[key]
                    active[key.replace("_bits", "_value")] = sum(bit << pos for pos, bit in enumerate(values))
                    active[key] = "".join(map(str, values))
                scans.append(active)
                scans[-1]["complete"] = True
                active = None
            state = next_state
    if active is not None:
        for key in ("tdi_bits", "tdo_bits"):
            values = active[key]
            active[key.replace("_bits", "_value")] = sum(bit << pos for pos, bit in enumerate(values))
            active[key] = "".join(map(str, values))
        active["complete"] = False
        scans.append(active)
    return {"initial_state": initial_state, "final_state": state, "scans": scans,
            "transitions": transitions[:MAX_FRAMES]}


_SWD_ACK = {1: "OK", 2: "WAIT", 4: "FAULT"}


def decode_swd_bits(bits: str, *, turnaround: int = 1) -> list[dict]:
    """Decode saved SWDIO bits in temporal order (LSB-first fields)."""
    if (not isinstance(bits, str) or not isinstance(turnaround, int) or isinstance(turnaround, bool)
            or len(bits) > MAX_SAMPLES or set(bits) - {"0", "1"} or not 1 <= turnaround <= 4):
        raise CaptureError("invalid SWD bit stream")
    rows, pos = [], 0
    while pos + 8 + turnaround + 3 <= len(bits) and len(rows) < MAX_FRAMES:
        header = [int(v) for v in bits[pos:pos + 8]]
        if not (header[0] == 1 and header[6] == 0 and header[7] == 1 and
                header[5] == (header[1] ^ header[2] ^ header[3] ^ header[4])):
            pos += 1
            continue
        apndp, rnw, a2, a3 = header[1:5]
        ack_pos = pos + 8 + turnaround
        ack = sum(int(bits[ack_pos + index]) << index for index in range(3))
        row = {"bit_offset": pos, "port": "AP" if apndp else "DP",
               "operation": "read" if rnw else "write", "address": (a3 << 3) | (a2 << 2),
               "ack": _SWD_ACK.get(ack, f"invalid-{ack}"), "request_parity_ok": True}
        cursor = ack_pos + 3
        if ack == 1:
            if not rnw:
                cursor += turnaround
            if cursor + 33 <= len(bits):
                data_bits = [int(v) for v in bits[cursor:cursor + 32]]
                parity = int(bits[cursor + 32])
                row["data"] = sum(bit << index for index, bit in enumerate(data_bits))
                row["data_parity_ok"] = parity == (sum(data_bits) & 1)
                cursor += 33
            else:
                row["truncated"] = True
                cursor = len(bits)
        rows.append(row)
        pos = max(pos + 8, cursor)
    return rows


def compare_faulty_outputs(reference: bytes, faulty: Iterable[bytes]) -> list[dict]:
    if not isinstance(reference, bytes) or len(reference) > MAX_TEXT:
        raise CaptureError("invalid reference output")
    rows = []
    for index, candidate in enumerate(faulty):
        if index >= MAX_FRAMES or not isinstance(candidate, bytes) or len(candidate) != len(reference):
            raise CaptureError("fault outputs must be bounded equal-length bytes")
        changed = [pos for pos, (left, right) in enumerate(zip(reference, candidate)) if left != right]
        rows.append({"index": index, "changed_indices": changed,
                     "xor": bytes(left ^ right for left, right in zip(reference, candidate)),
                     "hamming_distance": sum((left ^ right).bit_count()
                                             for left, right in zip(reference, candidate))})
    return rows


def analyze_glitch_trials(trials: Iterable[dict]) -> dict:
    """Summarize a finite saved voltage/clock glitch campaign without controlling hardware."""
    rows = []
    for index, trial in enumerate(trials):
        if index >= MAX_FRAMES or not isinstance(trial, dict):
            raise CaptureError("glitch trial cap/type exceeded")
        delay, width = float(trial.get("delay", 0)), float(trial.get("width", 0))
        if not math.isfinite(delay + width):
            raise CaptureError("non-finite glitch parameter")
        outcome = str(trial.get("outcome", "unknown"))[:128]
        rows.append({"index": index, "delay": delay, "width": width, "outcome": outcome})
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    by_outcome = {}
    for outcome in sorted(counts):
        selected = [row for row in rows if row["outcome"] == outcome]
        by_outcome[outcome] = {"count": len(selected),
                               "delay_range": [min(r["delay"] for r in selected),
                                               max(r["delay"] for r in selected)],
                               "width_range": [min(r["width"] for r in selected),
                                               max(r["width"] for r in selected)]}
    # Exact cells expose repeatability instead of smoothing sparse observations into guesses.
    cells: dict[tuple[float, float], dict[str, int]] = {}
    for row in rows:
        key = (row["delay"], row["width"])
        bucket = cells.setdefault(key, {})
        bucket[row["outcome"]] = bucket.get(row["outcome"], 0) + 1
    grid = [{"delay": key[0], "width": key[1], "outcomes": cells[key],
             "trials": sum(cells[key].values())} for key in sorted(cells)]
    return {"trial_count": len(rows), "outcome_counts": counts,
            "outcomes": by_outcome, "parameter_cells": grid}


def align_traces(traces: Sequence[Sequence[float]], *, max_shift: int = 64,
                 reference_index: int = 0) -> dict:
    if not traces or not 0 <= reference_index < len(traces) or not 0 <= max_shift <= 4096:
        raise CaptureError("invalid trace alignment request")
    width = len(traces[reference_index])
    if width == 0 or len(traces) * width > MAX_TRACE_CELLS or any(len(row) != width for row in traces):
        raise CaptureError("trace matrix is ragged or exceeds cap")
    reference = [float(v) for v in traces[reference_index]]
    if any(not math.isfinite(value) for row in traces for value in map(float, row)):
        raise CaptureError("trace matrix contains a non-finite sample")
    shifts, aligned = [], []
    for row in traces:
        values = [float(v) for v in row]
        best = (float("-inf"), 0)
        for shift in range(-max_shift, max_shift + 1):
            left = max(0, shift)
            right = min(width, width + shift)
            if right - left < 2:
                continue
            score = sum(reference[pos] * values[pos - shift] for pos in range(left, right))
            if score > best[0]:
                best = (score, shift)
        shift = best[1]
        shifts.append(shift)
        aligned.append([values[pos - shift] if 0 <= pos - shift < width else 0.0
                        for pos in range(width)])
    return {"shifts": shifts, "traces": aligned}


def welch_t_trace(group_a: Sequence[Sequence[float]],
                  group_b: Sequence[Sequence[float]]) -> list[float]:
    if len(group_a) < 2 or len(group_b) < 2:
        raise CaptureError("Welch t-test needs at least two traces per group")
    width = len(group_a[0])
    all_rows = list(group_a) + list(group_b)
    if width == 0 or len(all_rows) * width > MAX_TRACE_CELLS or any(len(row) != width for row in all_rows):
        raise CaptureError("trace matrix is ragged or exceeds cap")
    if any(not math.isfinite(float(value)) for row in all_rows for value in row):
        raise CaptureError("trace matrix contains a non-finite sample")
    result = []
    for column in range(width):
        left = [float(row[column]) for row in group_a]
        right = [float(row[column]) for row in group_b]
        numerator = statistics.fmean(left) - statistics.fmean(right)
        denominator = math.sqrt(statistics.variance(left) / len(left) +
                                statistics.variance(right) / len(right))
        result.append(numerator / denominator if denominator else (math.copysign(math.inf, numerator)
                                                                    if numerator else 0.0))
    return result


_AES_SBOX = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)


def _correlation(left: Sequence[float], right: Sequence[float]) -> float:
    lm, rm = statistics.fmean(left), statistics.fmean(right)
    numerator = sum((a - lm) * (b - rm) for a, b in zip(left, right))
    ld = sum((a - lm) ** 2 for a in left)
    rd = sum((b - rm) ** 2 for b in right)
    return numerator / math.sqrt(ld * rd) if ld and rd else 0.0


def cpa_aes_first_round(traces: Sequence[Sequence[float]], plaintexts: Sequence[bytes], *,
                        byte_index: int = 0, top: int = 8) -> list[dict]:
    """Rank AES first-round key-byte hypotheses using S-box Hamming-weight leakage."""
    if len(traces) != len(plaintexts) or len(traces) < 3 or not 0 <= byte_index < 16:
        raise CaptureError("CPA needs matching traces and 16-byte plaintexts")
    width = len(traces[0])
    if width == 0 or len(traces) * width > MAX_TRACE_CELLS or any(
            len(row) != width for row in traces) or any(len(p) < 16 for p in plaintexts):
        raise CaptureError("CPA matrix/plaintext shape invalid")
    if len(traces) * width * 256 > MAX_CPA_WORK:
        raise CaptureError("CPA work cap exceeded")
    if any(not math.isfinite(float(value)) for row in traces for value in row):
        raise CaptureError("CPA trace contains a non-finite sample")
    columns = [[float(row[column]) for row in traces] for column in range(width)]
    ranked = []
    for key in range(256):
        leakage = [_AES_SBOX[plain[byte_index] ^ key].bit_count() for plain in plaintexts]
        correlations = [_correlation(leakage, column) for column in columns]
        point = max(range(width), key=lambda index: abs(correlations[index]))
        ranked.append({"key": key, "correlation": correlations[point], "sample": point})
    ranked.sort(key=lambda row: (-abs(row["correlation"]), row["key"]))
    return ranked[:max(1, min(top, 256))]


def _jsonable(value):
    if isinstance(value, bytes):
        return value.hex()
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline saved logic/fault capture analyzer")
    parser.add_argument("kind", choices=("csv", "glitch", "swd"))
    parser.add_argument("input")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        raw = Path(args.input).read_bytes()
        if len(raw) > MAX_TEXT:
            raise CaptureError("input exceeds cap")
        if args.kind == "csv":
            result = parse_logic_csv(raw.decode("utf-8"))
        elif args.kind == "glitch":
            result = analyze_glitch_trials(json.loads(raw.decode("utf-8")))
        else:
            result = decode_swd_bits("".join(raw.decode("ascii").split()))
        print(json.dumps(result, indent=2, default=_jsonable, sort_keys=True))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, CaptureError, TypeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
