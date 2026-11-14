#!/usr/bin/env python3
"""Offline hardware/firmware depth helpers for captured buses and flash images.

Inputs are delivery files or already-captured logic traces.  The module never opens a serial port,
CAN interface, JTAG probe, or target connection.  It provides:

* SPI NOR command decoding and bounded read/program image reconstruction;
* I2C EEPROM address/data reconstruction and UART bootloader-log classification;
* a conservative DBC parser plus exact CAN signal decoding;
* JTAG IDCODE/SWD DPIDR interpretation and ranked boundary-scan workflow notes;
* offset-aware carving into the existing CRC/structure-gated SquashFS, JFFS2, UBI/UBIFS and
  U-Boot-environment readers.

Every candidate records its byte/capture provenance for human review.  Nothing is mounted,
executed, flashed, or transmitted.
"""
from __future__ import annotations

import argparse
import csv
import importlib.util
import itertools
import json
import re
import struct
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
MAX_INPUT = 128 << 20
MAX_JSON = 8 << 20
MAX_TRANSACTIONS = 100000
MAX_IMAGE_SPAN = 16 << 20
MAX_DBC_MESSAGES = 4096
MAX_DBC_SIGNALS = 65536
MAX_CARVES = 64


def _module(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


rf = _module("csctf_rf_depth_base", HERE / "rf.py")
firmware = _module("csctf_firmware_depth_base", HERE / "firmware_walk.py")


def _bytes(value, field: str) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        compact = re.sub(r"[\s:_-]", "", value)
        if len(compact) % 2 or len(compact) > MAX_IMAGE_SPAN * 2:
            raise ValueError(f"{field} is not bounded even-length hex")
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError(f"{field} is not hex") from exc
    if isinstance(value, list) and len(value) <= MAX_IMAGE_SPAN and all(
            isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in value):
        return bytes(value)
    raise ValueError(f"{field} must be bytes, hex, or a byte list")


def _sparse_image(memory: dict[int, int]) -> dict:
    if not memory:
        return {"base": None, "end": None, "image": b"", "known": 0, "holes": 0}
    lo, hi = min(memory), max(memory) + 1
    if lo < 0 or hi - lo > MAX_IMAGE_SPAN:
        raise ValueError("reconstructed image span exceeds 16 MiB cap")
    image = bytearray(b"\xff" * (hi - lo))
    for address, value in memory.items():
        image[address - lo] = value
    return {"base": lo, "end": hi, "image": bytes(image), "known": len(memory),
            "holes": (hi - lo) - len(memory)}


def decode_spi_flash(transactions, *, address_bytes: int = 3) -> dict:
    """Decode common JEDEC SPI NOR commands from CS-framed MOSI/MISO byte streams."""
    try:
        rows = list(itertools.islice(iter(transactions), MAX_TRANSACTIONS + 1))
    except (TypeError, MemoryError) as exc:
        raise ValueError("transactions must be a bounded sequence") from exc
    if len(rows) > MAX_TRANSACTIONS or address_bytes not in (3, 4):
        raise ValueError("SPI transaction/address cap exceeded")
    operations, memory, jedec = [], {}, []
    names = {0x03: "read", 0x0B: "fast-read", 0x02: "page-program", 0x20: "sector-erase",
             0xD8: "block-erase", 0x9F: "read-jedec-id", 0x05: "read-status-1",
             0x35: "read-status-2", 0x06: "write-enable", 0x04: "write-disable",
             0xB7: "enter-4byte-address", 0xE9: "exit-4byte-address"}
    active_address_bytes = address_bytes
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        mosi, miso = _bytes(row.get("mosi", b""), "mosi"), _bytes(row.get("miso", b""), "miso")
        if not mosi:
            continue
        command = mosi[0]
        entry = {"index": index, "command": command, "name": names.get(command, "unknown"),
                 "complete": bool(row.get("complete", True))}
        if command == 0xB7:
            active_address_bytes = 4
        elif command == 0xE9:
            active_address_bytes = 3
        elif command == 0x9F:
            ident = miso[1:4] if len(miso) >= 4 else miso[:3]
            entry["jedec_id"] = ident
            if ident:
                jedec.append(ident)
        elif command in (0x03, 0x0B, 0x02, 0x20, 0xD8):
            header = 1 + active_address_bytes + (1 if command == 0x0B else 0)
            if len(mosi) < header:
                entry["truncated"] = True
                operations.append(entry)
                continue
            address = int.from_bytes(mosi[1:1 + active_address_bytes], "big")
            entry["address"] = address
            if command in (0x03, 0x0B):
                # Full-duplex flash output begins after command/address/(dummy) clock bytes.
                data = miso[header:]
                entry["data"] = data
                for offset, value in enumerate(data):
                    memory[address + offset] = value
            elif command == 0x02:
                data = mosi[header:]
                entry["data"] = data
                for offset, value in enumerate(data):
                    memory[address + offset] = value
        operations.append(entry)
    image = _sparse_image(memory)
    return {"operations": operations, "jedec_ids": list(dict.fromkeys(jedec)), **image}


def reconstruct_i2c_eeprom(transactions, *, address_width: int = 2,
                           device_min: int = 0x50, device_max: int = 0x57) -> dict:
    """Reconstruct bytes from conventional 24xx EEPROM write/read transactions."""
    try:
        rows = list(itertools.islice(iter(transactions), MAX_TRANSACTIONS + 1))
    except (TypeError, MemoryError) as exc:
        raise ValueError("transactions must be a bounded sequence") from exc
    if len(rows) > MAX_TRANSACTIONS or address_width not in (1, 2, 3):
        raise ValueError("I2C transaction/address cap exceeded")
    pointers, memory, operations = {}, {}, []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        address = row.get("address")
        if not isinstance(address, int) or not device_min <= address <= device_max:
            continue
        data = _bytes(row.get("data", b""), "I2C data")
        direction = row.get("rw")
        if direction == "w" and len(data) >= address_width:
            pointer = int.from_bytes(data[:address_width], "big")
            pointers[address] = pointer
            payload = data[address_width:]
            for offset, value in enumerate(payload):
                memory[pointer + offset] = value
            pointers[address] += len(payload)
            operations.append({"index": index, "device": address, "operation": "write" if payload else "set-pointer",
                               "address": pointer, "data": payload})
        elif direction == "r" and address in pointers:
            pointer = pointers[address]
            for offset, value in enumerate(data):
                memory[pointer + offset] = value
            pointers[address] += len(data)
            operations.append({"index": index, "device": address, "operation": "read",
                               "address": pointer, "data": data})
    return {"operations": operations, **_sparse_image(memory)}


def classify_uart_bootloader(data: bytes | str) -> dict:
    if isinstance(data, bytes):
        text = data[:MAX_INPUT].decode("utf-8", "replace")
    elif isinstance(data, str) and len(data) <= MAX_INPUT:
        text = data
    else:
        raise ValueError("UART input exceeds cap")
    families = {
        "u-boot": (r"U-Boot\s+[\w.-]+", r"Hit any key to stop autoboot", r"=>\s*$", r"bootcmd="),
        "cfe": (r"CFE version", r"CFE>", r"Board IP address"),
        "redboot": (r"RedBoot", r"RedBoot>"),
        "barebox": (r"barebox", r"barebox@[^:]+:"),
        "linux-console": (r"Linux version\s+\S+", r"Kernel command line:", r"login:\s*$"),
        "esp-rom": (r"ets Jun\s+\d+", r"rst:0x[0-9a-f]+", r"boot:0x[0-9a-f]+"),
    }
    hits = []
    for family, patterns in families.items():
        evidence = []
        for pattern in patterns:
            match = re.search(pattern, text, re.I | re.M)
            if match:
                evidence.append(match.group(0)[:160])
        if evidence:
            hits.append({"family": family, "score": min(100, 55 + 15 * len(evidence)), "evidence": evidence})
    variables = {}
    for key, value in re.findall(r"(?m)^([A-Za-z_][A-Za-z0-9_.-]{0,63})=([^\r\n\x00]{0,4096})$", text):
        if len(variables) >= 1024:
            break
        variables[key] = value
    return {"candidates": sorted(hits, key=lambda item: (-item["score"], item["family"])),
            "variables": variables,
            "bootargs": next((value for key, value in variables.items() if key.lower() == "bootargs"), None)}


_BO = re.compile(r"^BO_\s+(\d+)\s+([A-Za-z_][\w.]*)\s*:\s*(\d+)\s+(\S+)")
_SG = re.compile(
    r'^SG_\s+([A-Za-z_][\w.]*)\s*(?:(M)|m(\d+))?\s*:\s*(\d+)\|(\d+)@([01])([+-])\s*'
    r'\(([-+0-9.eE]+),([-+0-9.eE]+)\)\s*\[([-+0-9.eE]+)\|([-+0-9.eE]+)\]\s*"([^"]*)"'
)


def parse_dbc(text: str) -> dict:
    """Parse the bounded BO_/SG_ subset needed for exact physical-value decoding."""
    if not isinstance(text, str) or len(text) > (16 << 20):
        raise ValueError("DBC text exceeds 16 MiB cap")
    messages, current, signals = {}, None, 0
    for raw in text.splitlines():
        line = raw.strip()
        match = _BO.match(line)
        if match:
            if len(messages) >= MAX_DBC_MESSAGES:
                raise ValueError("DBC message cap exceeded")
            ident = int(match.group(1))
            if ident & 0x80000000:        # DBC extended (29-bit) frame marker bit
                ident &= 0x1FFFFFFF
            current = {"id": ident, "name": match.group(2), "length": int(match.group(3)),
                       "transmitter": match.group(4), "signals": []}
            messages[ident] = current
            continue
        match = _SG.match(line)
        if not match or current is None:
            continue
        signals += 1
        if signals > MAX_DBC_SIGNALS:
            raise ValueError("DBC signal cap exceeded")
        start, length = int(match.group(4)), int(match.group(5))
        if not 1 <= length <= 64 or start < 0 or start > 511:
            continue
        current["signals"].append({
            "name": match.group(1), "multiplexor": bool(match.group(2)),
            "multiplex_value": int(match.group(3)) if match.group(3) is not None else None,
            "start": start, "length": length, "little_endian": match.group(6) == "1",
            "signed": match.group(7) == "-", "factor": float(match.group(8)),
            "offset": float(match.group(9)), "minimum": float(match.group(10)),
            "maximum": float(match.group(11)), "unit": match.group(12),
        })
    return {"messages": messages, "message_count": len(messages), "signal_count": signals}


def _dbc_raw(data: bytes, signal: dict) -> int | None:
    start, length = signal["start"], signal["length"]
    if signal["little_endian"]:
        if start + length > len(data) * 8:
            return None
        value = (int.from_bytes(data, "little") >> start) & ((1 << length) - 1)
    else:
        positions, bit = [], start
        for _ in range(length):
            if bit < 0 or bit >= len(data) * 8:
                return None
            positions.append(bit)
            bit = bit + 15 if bit % 8 == 0 else bit - 1
        value = 0
        for position in positions:
            value = (value << 1) | ((data[position // 8] >> (position % 8)) & 1)
    if signal["signed"] and value & (1 << (length - 1)):
        value -= 1 << length
    return value


def decode_dbc_frame(database: dict, identifier: int, data: bytes) -> dict | None:
    messages = database.get("messages") if isinstance(database, dict) else None
    message = messages.get(identifier) if isinstance(messages, dict) else None
    if not isinstance(message, dict):
        return None
    data = _bytes(data, "CAN payload")
    if len(data) < message.get("length", 0):
        return None
    _SIG_KEYS = ("name", "start", "length", "little_endian", "signed",
                 "factor", "offset", "unit", "minimum", "maximum")
    for signal in message.get("signals", []):
        if not isinstance(signal, dict) or not all(key in signal for key in _SIG_KEYS):
            raise ValueError("malformed DBC signal definition")
    raw_values = {signal["name"]: _dbc_raw(data, signal) for signal in message.get("signals", [])}
    mux = next((raw_values.get(signal["name"]) for signal in message.get("signals", [])
                if signal.get("multiplexor")), None)
    decoded = []
    for signal in message.get("signals", []):
        raw = raw_values.get(signal["name"])
        if raw is None or (signal.get("multiplex_value") is not None and mux != signal["multiplex_value"]):
            continue
        physical = raw * signal["factor"] + signal["offset"]
        decoded.append({"name": signal["name"], "raw": raw, "value": physical,
                        "unit": signal["unit"], "within_declared_range":
                            signal["minimum"] <= physical <= signal["maximum"]})
    return {"id": identifier, "message": message.get("name"), "data": data, "signals": decoded}


def decode_can_log_with_dbc(can_text: str, dbc_text: str) -> list[dict]:
    capture = rf.can_parse(can_text) or rf.can_asc_parse(can_text)
    if not capture:
        raise ValueError("CAN log is not recognized or has fewer than three proven frames")
    database = parse_dbc(dbc_text)
    out = []
    for frame in capture["frames"][:MAX_TRANSACTIONS]:
        decoded = decode_dbc_frame(database, frame["id"], frame["data"])
        if decoded is not None:
            decoded.update({"timestamp": frame.get("ts"), "interface": frame.get("iface")})
            out.append(decoded)
    return out


def boundary_scan_notes(interface: str, identifier: int | None = None) -> dict:
    """Interpret an observed ID and rank manual next steps; no probe is opened."""
    interface = str(interface).lower()
    if interface not in ("jtag", "swd"):
        raise ValueError("interface must be jtag or swd")
    parsed = None
    if identifier is not None:
        if not isinstance(identifier, int) or identifier < 0 or identifier > 0xFFFFFFFF:
            raise ValueError("identifier must be a 32-bit integer")
        if interface == "jtag":
            parsed = {"raw": identifier, "version": (identifier >> 28) & 0xF,
                      "part": (identifier >> 12) & 0xFFFF, "manufacturer": (identifier >> 1) & 0x7FF,
                      "idcode_lsb_valid": bool(identifier & 1)}
        else:
            parsed = {"raw": identifier, "revision": (identifier >> 28) & 0xF,
                      "part": (identifier >> 20) & 0xFF, "designer": (identifier >> 1) & 0x7FF,
                      "dpidr_lsb_valid": bool(identifier & 1)}
    steps = ([
        {"score": 100, "note": "Record IR length and IDCODE with BYPASS/IDCODE only; do not drive unknown EXTEST pins."},
        {"score": 90, "note": "Derive a BSDL pin map, then use SAMPLE/PRELOAD to observe boundary cells passively."},
        {"score": 75, "note": "If the challenge authorizes boundary testing, toggle one mapped non-power cell at a time."},
    ] if interface == "jtag" else [
        {"score": 100, "note": "Read DPIDR/AP ID registers first and preserve the observed power-up state."},
        {"score": 90, "note": "Enumerate ROM-table entries from the captured/offline memory map before any halt/write."},
        {"score": 75, "note": "Use read-only memory access until the assigned challenge explicitly requires a debug action."},
    ])
    return {"interface": interface, "identifier": parsed, "candidates": steps}


def carve_firmware(blob: bytes) -> list[dict]:
    """Find embedded filesystem/env starts and feed slices to the existing fail-closed parsers."""
    if not isinstance(blob, bytes) or len(blob) > MAX_INPUT:
        raise ValueError("firmware input exceeds 128 MiB cap")
    magics = ((b"hsqs", "squashfs", firmware._squashfs),
              (struct.pack("<H", firmware.JFFS2_MAGIC), "jffs2", firmware._jffs2),
              (b"UBI#", "ubi", firmware._ubi),
              (struct.pack("<I", firmware._UBIFS_NODE_MAGIC), "ubifs", firmware._ubi))
    candidates = []
    seen = set()
    for magic, kind, parser in magics:
        start = 0
        while len(candidates) < MAX_CARVES:
            offset = blob.find(magic, start)
            if offset < 0:
                break
            start = offset + max(1, len(magic))
            if (kind, offset) in seen:
                continue
            seen.add((kind, offset))
            try:
                parsed = parser(blob[offset:])
            except Exception:
                parsed = None
            if parsed is not None:
                candidates.append({"kind": parsed.get("kind", kind), "offset": offset,
                                   "verified": True, "report": parsed})
    # U-Boot environments have no magic.  Test common aligned partition sizes and retain only CRC-valid ones.
    sizes = (0x1000, 0x2000, 0x4000, 0x10000, 0x20000)
    for size in sizes:
        for offset in range(0, max(0, len(blob) - size + 1), 0x1000):
            if len(candidates) >= MAX_CARVES:
                break
            # Environments have no magic, but their first key starts immediately after the
            # CRC/(optional flag).  Gate the more expensive region copy/CRC on that small prefix.
            prefix = blob[offset + 4:min(len(blob), offset + 4101)]
            first = prefix.split(b"\x00", 1)[0]
            if b"=" not in first and not (len(prefix) > 1 and b"=" in prefix[1:].split(b"\x00", 1)[0]):
                continue
            region = blob[offset:offset + size]
            try:
                env = firmware._uboot_env(region)
            except Exception:
                env = None
            if env and env.get("crc_valid"):
                candidates.append({"kind": "uboot_env", "offset": offset, "length": size,
                                   "verified": True, "report": env})
    return sorted(candidates, key=lambda item: (item["offset"], item["kind"]))[:MAX_CARVES]


def decode_logic_trace(text: str) -> dict:
    try:
        info = rf.logic_info(text)
        if not info:
            raise ValueError("logic CSV is not recognized")
        capture = rf.logic_csv(text)
    except csv.Error as exc:
        raise ValueError("logic CSV is malformed") from exc
    cols = capture["columns"]
    clk = rf._column(cols, "clk", "sck", "sclk", "clock")
    if clk:
        transactions = rf.spi_transactions(clk, rf._column(cols, "mosi", "sdo", "copi"),
                                           rf._column(cols, "miso", "sdi", "cipo"),
                                           rf._column(cols, "cs", "ss", "ncs", "csn", "enable"))
        if transactions:
            info["spi_transactions"] = transactions
            info["spi_flash"] = decode_spi_flash(transactions)
    if info.get("i2c"):
        info["i2c_eeprom"] = reconstruct_i2c_eeprom(info["i2c"])
    if info.get("uart"):
        info["uart_bootloader"] = classify_uart_bootloader(info["uart"]["bytes"])
    return info


def _read(path: str, cap: int = MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        value = handle.read(cap + 1)
    if len(value) > cap:
        raise ValueError("input exceeds size cap")
    return value


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="hardware_depth.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    spi = sub.add_parser("spi-flash")
    spi.add_argument("input", help="JSON {transactions:[{mosi,miso}]} or logic CSV")
    spi.add_argument("--address-bytes", type=int, default=3)
    dbc = sub.add_parser("dbc")
    dbc.add_argument("dbc")
    dbc.add_argument("can_log")
    carve = sub.add_parser("carve")
    carve.add_argument("input")
    notes = sub.add_parser("debug-notes")
    notes.add_argument("interface", choices=("jtag", "swd"))
    notes.add_argument("identifier", nargs="?")
    uart = sub.add_parser("uart")
    uart.add_argument("input")
    # Output is structured JSON in every mode.  Keep the house-style switch accepted both before
    # and after the subcommand for CLI consistency.
    parser.add_argument("--json", action="store_true")
    for command in (spi, dbc, carve, notes, uart):
        command.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.operation == "spi-flash":
            raw = _read(args.input, MAX_JSON)
            if raw.lstrip().startswith((b"{", b"[")):
                value = json.loads(raw.decode("utf-8"))
                rows = value.get("transactions") if isinstance(value, dict) else value
                result = decode_spi_flash(rows, address_bytes=args.address_bytes)
            else:
                result = decode_logic_trace(raw.decode("utf-8"))["spi_flash"]
        elif args.operation == "dbc":
            result = {"frames": decode_can_log_with_dbc(_read(args.can_log, MAX_JSON).decode("utf-8"),
                                                          _read(args.dbc, MAX_JSON).decode("utf-8"))}
        elif args.operation == "carve":
            result = {"candidates": carve_firmware(_read(args.input))}
        elif args.operation == "debug-notes":
            ident = int(args.identifier, 0) if args.identifier is not None else None
            result = boundary_scan_notes(args.interface, ident)
        else:
            result = classify_uart_bootloader(_read(args.input))
        # Bytes remain local and are rendered as hex in structured output.
        def render(value):
            if isinstance(value, bytes):
                return value.hex()
            raise TypeError
        print(json.dumps(result, sort_keys=True, default=render))
        return 0
    except (KeyError, OSError, TypeError, ValueError, OverflowError, UnicodeError,
            json.JSONDecodeError, struct.error, RecursionError, MemoryError) as exc:
        print(f"hardware_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
