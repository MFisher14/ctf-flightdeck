"""Synthetic handouts for B-078 (DICOM/SNMP timeline forensics). Everything is built here from the
DICOM PS3.7/PS3.8 and SNMP (RFC 3416, BER) layouts; no challenge file is read or committed.

The shape follows csctf 9159: a capture with DICOM P-DATA-TF traffic (routine C-ECHO-RQ to the
configured SCP, C-STORE-RQ to an outside host with an oversized data set) and SNMP traps; a device
XML; a records CSV; an SNMP trap log with routine series, repeated [ANOMALY] decoys and a one-off
boot report written out of order; and a blob XOR-ed with the device serial."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import struct
from pathlib import Path

SERIAL = "SYNTH-SCAN-7731"
SEED = "5150"
SCP = "10.9.40.10"
DEVICE = "10.9.30.45"
OUTSIDE = "203.0.113.77"
MAX_PAYLOAD = 4096
T0 = dt.datetime(2026, 3, 1, 0, 0, 0, tzinfo=dt.timezone.utc)
RECIPE = ('sha256("<dicom_serial>:<snmp_iso_timestamp>:<leak_count>:<anomaly_count>:<manifest_seed>")[:8], '
          "lowercase hex")
STORE_SOP = "1.2.840.10008.5.1.4.1.1.7"
ECHO_SOP = "1.2.840.10008.1.1"


# ------------------------------------------------------------------ DICOM upper layer, by hand
def _el(elem: int, value: bytes) -> bytes:
    if len(value) % 2:
        value += b"\x00"
    return struct.pack("<HHI", 0x0000, elem, len(value)) + value


def command_set(field: int, message_id: int, sop: str, has_dataset: bool) -> bytes:
    """A DIMSE command set: group 0000, Implicit VR Little Endian (PS3.7 section 9.3)."""
    body = (_el(0x0002, sop.encode()) + _el(0x0100, struct.pack("<H", field))
            + _el(0x0110, struct.pack("<H", message_id))
            + _el(0x0800, struct.pack("<H", 0x0000 if has_dataset else 0x0101)))
    return _el(0x0000, struct.pack("<I", len(body))) + body


def pdv(ctx: int, command: bool, last: bool, fragment: bytes) -> bytes:
    mch = (1 if command else 0) | (2 if last else 0)
    return struct.pack(">IBB", len(fragment) + 2, ctx, mch) + fragment


def pdata(*items: bytes) -> bytes:
    body = b"".join(items)
    return struct.pack(">BBI", 4, 0, len(body)) + body


def associate_rq(called: str = "STORESCP", calling: str = "MODALITY") -> bytes:
    """A minimal A-ASSOCIATE-RQ (68-byte fixed part, no variable items)."""
    body = struct.pack(">HH", 1, 0) + called.ljust(16).encode() + calling.ljust(16).encode() + b"\x00" * 32
    return struct.pack(">BBI", 1, 0, len(body)) + body


def store_message(message_id: int, dataset: bytes, ctx: int = 1) -> bytes:
    """One P-DATA-TF PDU holding a C-STORE-RQ command and its data set."""
    return pdata(pdv(ctx, True, True, command_set(0x0001, message_id, STORE_SOP, True)),
                 pdv(ctx, False, True, dataset))


def echo_message(message_id: int, ctx: int = 1) -> bytes:
    return pdata(pdv(ctx, True, True, command_set(0x0030, message_id, ECHO_SOP, False)))


# ------------------------------------------------------------------ SNMP (BER)
def ber(tag: int, value: bytes) -> bytes:
    if len(value) < 128:
        return bytes([tag, len(value)]) + value
    n = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(n)]) + n + value


def ber_int(v: int) -> bytes:
    return ber(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def ber_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return ber(0x06, out)


def snmp_trap(community: str, oid: str, request_id: int = 1) -> bytes:
    varbind = ber(0x30, ber_oid(oid) + ber(0x04, b"x"))
    pdu = ber(0xA7, ber_int(request_id) + ber_int(0) + ber_int(0) + ber(0x30, varbind))
    return ber(0x30, ber_int(1) + ber(0x04, community.encode()) + pdu)


# ------------------------------------------------------------------ capture
def _ip(addr: str) -> bytes:
    return bytes(int(x) for x in addr.split("."))


def frame(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0, _ip(src), _ip(dst)) + l4
    return bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip


def tcp(src, dst, sport, dport, seq, payload, flags=0x18):
    return frame(src, dst, 6, struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload)


def udp(src, dst, sport, dport, payload):
    return frame(src, dst, 17, struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload)


def pcap(frames: list[tuple[dt.datetime, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for when, f in frames:
        secs = int(when.timestamp())
        out += struct.pack("<IIII", secs, 0, len(f), len(f)) + f
    return out


def capture(echo: int = 6, internal_store: int = 2, outside_store: int = 5, traps: int = 3,
            constant_seq: bool = True) -> bytes:
    """Routine C-ECHO-RQ and small C-STORE-RQ to the SCP, then oversized C-STORE-RQ to the outside
    host, then SNMP traps. With `constant_seq` every DICOM segment carries the same sequence number
    (a generated capture's shape: a reassembly that drops repeats would lose messages)."""
    frames, when, seq = [], T0 + dt.timedelta(seconds=30), 1000
    for i in range(echo):
        frames.append((when, tcp(DEVICE, SCP, 40001, 104, seq, echo_message(1))))
        when += dt.timedelta(seconds=10)
        seq += 0 if constant_seq else len(echo_message(1))
    for i in range(internal_store):
        msg = store_message(100 + i, b"\x10" * 256)
        frames.append((when, tcp(DEVICE, SCP, 40002, 104, seq, msg)))
        when += dt.timedelta(seconds=10)
        seq += 0 if constant_seq else len(msg)
    first_outside = None
    for i in range(outside_store):
        msg = store_message(2 + i, b"\xde\xad" * (MAX_PAYLOAD // 2 + 13))
        frames.append((when, tcp(DEVICE, OUTSIDE, 40003, 104, seq, msg)))
        first_outside = first_outside or when
        when += dt.timedelta(seconds=15)
        seq += 0 if constant_seq else len(msg)
    for i in range(traps):
        frames.append((when, udp(OUTSIDE, "10.9.30.1", 50000 + i, 161,
                                 snmp_trap("ward_mgmt_community", "1.3.6.1.2.1.2.2.1.1", i + 1))))
        when += dt.timedelta(seconds=60)
    return pcap(frames)


# ------------------------------------------------------------------ the rest of the handout
def device_xml(serial: str = SERIAL) -> str:
    return (f"<?xml version='1.0'?>\n<dicom_device>\n  <identity>\n    <serial_number>{serial}</serial_number>\n"
            f"    <model>SynthScan</model>\n  </identity>\n  <network>\n    <scp_host>{SCP}</scp_host>\n"
            f"    <backup_server>{OUTSIDE}</backup_server>\n    <max_dicom_payload>{MAX_PAYLOAD}</max_dicom_payload>\n"
            f"  </network>\n  <calibration><DeviceManifestSeed>{SEED}</DeviceManifestSeed></calibration>\n"
            f"</dicom_device>\n")


def records_csv(leaked: int = 7, kept: int = 3) -> str:
    rows = ["patient_id,ward,status"]
    rows += [f"P{i:04d},C,Leaked" for i in range(leaked)]
    rows += [f"P{9000 + i:04d},E,Intact" for i in range(kept)]
    return "\n".join(rows) + "\n"


def iso(when: dt.datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def trap_log(anomaly_days: int = 4, marker: str = "[ANOMALY: Unusual polling frequency]") -> str:
    """Routine linkDown every 6 h from three internal devices over `anomaly_days` days, one
    anomaly line per day at 03:15 from the outside host, and the device's boot report (one second
    after the log opens) written last, out of time order."""
    lines = []
    for slot in range(anomaly_days * 4):
        when = T0 + dt.timedelta(hours=6 * slot)
        for host, name in (("10.9.30.1", "Core Router"), ("10.9.30.2", "Switch A"), ("10.9.40.1", "Records")):
            lines.append((when, f"{iso(when)} SNMPTRAP v2c from {host}: OID=.1.3.6.1.2.1.1.3.0 Trap: linkDown "
                                f"Device: {name}"))
    for day in range(anomaly_days):
        when = T0 + dt.timedelta(days=day, hours=3, minutes=15)
        lines.append((when, f"{iso(when)} SNMPTRAP v2c from {OUTSIDE}: OID=.1.3.6.1.2.1.2.2.1.1 Trap: SNMP GetBulk "
                            f"{marker}".rstrip()))
    lines.sort(key=lambda x: x[0])
    boot = T0 + dt.timedelta(seconds=1)
    out = [text for _, text in lines]
    out.append(f"{iso(boot)} SNMPTRAP v2c from {DEVICE}: OID=.1.3.6.1.4.1.99999.0.1 Trap: deviceBootReport "
               f"DeviceManifestSeed={SEED} Serial={SERIAL}")
    return "\n".join(out) + "\n"


def exfil_plain() -> bytes:
    return f"{OUTSIDE}\x00".encode() + struct.pack(">H", 8443) + b"ward_exfil_dump" + b"\x00" * 9


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def brief(recipe: str = RECIPE) -> str:
    return ("A compromised imaging device leaked records. Flag format: CSCTF{8_lowercase_hex}.\n"
            f"The flag is {recipe}.\n"
            "- `dicom_serial` = the device serial string from the device XML.\n"
            "- `snmp_iso_timestamp` = the exact ISO 8601 timestamp of the anomalous event in snmp_trap.log.\n"
            "- `leak_count` = number of leaked patient records.\n"
            "- `anomaly_count` = number of anomalous C-STORE operations in the pcap.\n"
            "- `manifest_seed` = the calibration seed that agrees between the XML and the log.\n")


def handout(root: Path, *, description: str | None = None, log: str | None = None, files: dict | None = None,
            cap: bytes | None = None) -> Path:
    """An intake-shaped challenge folder: challenge.json plus files/."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "files").mkdir(exist_ok=True)
    (root / "challenge.json").write_text(json.dumps({"name": "Synthetic Ward", "description":
                                                     brief() if description is None else description}))
    contents = {
        "hospital_network.pcap": capture() if cap is None else cap,
        "dicom_device.xml": device_xml().encode(),
        "patient_records.csv": records_csv().encode(),
        "snmp_trap.log": (trap_log() if log is None else log).encode(),
        "exfil_stream.bin": xor(exfil_plain(), SERIAL.encode()),
    }
    contents.update(files or {})
    for name, data in contents.items():
        if data is None:
            continue
        (root / "files" / name).write_bytes(data if isinstance(data, bytes) else data.encode())
    return root


def expected_digest(timestamp: str, leak: int = 7, anomaly: int = 5) -> str:
    """The recipe computed here, independently of the engine."""
    pre = f"{SERIAL}:{timestamp}:{leak}:{anomaly}:{SEED}"
    return hashlib.sha256(pre.encode()).hexdigest()[:8]
