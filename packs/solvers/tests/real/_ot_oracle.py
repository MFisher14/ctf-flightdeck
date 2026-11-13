"""Protocol-detection oracle for the OT real-capture corpus (B-204).

Given a capture file that the manifest labels with an OT protocol, run the repo's own OT parsers
and report which protocols they recognise in it. This is the shared engine behind
`tests/real/test_real_ot.py`: it runs against the real corpus (needs_realdata `ot/<proto>`) and
against the synthetic fixtures that test builds in memory, so the same dispatch is proven on both.

No byte of a capture is executed; only the parsers read it. The capture is untrusted data. Every
parser here is a repo module (`ics_capture`, `ics_protocols` via it, `ics_fieldbus`,
`ics_app_depth`, `network_ics_depth`, `ot_mms_services`). scapy is used only to read a pcap's frames
and to split transport payloads; a missing scapy is reported loudly, never silently skipped — the
caller marks the test needs_tool("py:scapy").
"""
from __future__ import annotations

import sys
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
_TOOLKITS = str(REPO / "solvers" / "toolkits")
if _TOOLKITS not in sys.path:
    sys.path.insert(0, _TOOLKITS)

import ics_capture  # noqa: E402
import ics_fieldbus  # noqa: E402
import ics_app_depth  # noqa: E402
import network_ics_depth  # noqa: E402
import ot_mms_services  # noqa: E402

# The canonical protocol token used by the manifest `expect` field and the corpus folder name
# (challenges `ot/<proto>/`). Parsers spell some of these differently; NORMALIZE maps their spelling
# onto the canonical token so a capture is judged on the protocol, not the parser's label.
CANONICAL = ("modbus", "dnp3", "s7comm", "iec104", "enip", "bacnet",
             "goose", "opcua", "ethercat", "mms", "profinet", "cip")
NORMALIZE = {
    "bacnet-ip": "bacnet",
    "ethernet-ip": "enip",
    "iec61850-goose": "goose",
}

# The engines a manifest row may name. Each takes a capture path and returns a Detection.
ENGINE_NAMES = ("ics_capture", "ics_fieldbus", "goose", "opcua", "ethercat", "mms")

GOOSE_ETHERTYPE = 0x88B8
ETHERCAT_ETHERTYPE = 0x88A4


class OracleError(Exception):
    """A dependency the oracle needs is absent (scapy); named, never swallowed."""


def _norm(token):
    return NORMALIZE.get(token, token)


class Detection:
    """What one engine recognised in one capture: the set of canonical protocol tokens it decoded,
    how many application messages/frames it decoded, and any engine-level error."""

    def __init__(self, engine: str, tokens, count: int, error=None):
        self.engine = engine
        self.tokens = {_norm(t) for t in tokens if t}
        self.count = int(count)
        self.error = error

    def recognised(self, proto: str) -> bool:
        return _norm(proto) in self.tokens

    def __repr__(self):
        return (f"Detection(engine={self.engine!r}, tokens={sorted(self.tokens)}, "
                f"count={self.count}, error={self.error!r})")


def _require_scapy():
    try:
        import scapy.all as sc  # noqa
    except ImportError as exc:  # no silent fallback: name what is missing
        raise OracleError("scapy is required to read a pcap for OT payload extraction "
                          "(pip install scapy); mark the test needs_tool('py:scapy')") from exc
    sc.conf.verb = 0
    return sc


def _read_packets(path):
    """Every frame of a pcap/pcapng, as raw Ethernet bytes. Reads the file, runs nothing."""
    sc = _require_scapy()
    try:
        pkts = sc.rdpcap(str(path))
    except Exception as exc:  # noqa: BLE001 - a corrupt capture is data, reported not crashed on
        raise OracleError(f"could not read pcap {path}: {type(exc).__name__}: {exc}") from exc
    return [bytes(p) for p in pkts]


def _ethertype_payloads(frames, ethertype):
    """Payloads of every Ethernet frame carrying `ethertype`, after one optional 802.1Q tag."""
    out = []
    for raw in frames:
        if len(raw) < 14:
            continue
        etype = struct.unpack_from(">H", raw, 12)[0]
        off = 14
        if etype == 0x8100 and len(raw) >= 18:  # one VLAN tag
            etype = struct.unpack_from(">H", raw, 16)[0]
            off = 18
        if etype == ethertype:
            out.append(raw[off:])
    return out


def _ip_transport_payloads(path, *, want, port):
    """(payload bytes) of every captured TCP or UDP packet on `port`, via the repo's own
    dependency-free pcap reader (ics_capture.extract_transports). `want` is 'tcp' or 'udp'."""
    data = Path(path).read_bytes()
    packets, _ = ics_capture.extract_transports(data)
    out = []
    for pkt in packets:
        if pkt.get("transport") != want:
            continue
        if port not in (pkt.get("source_port"), pkt.get("destination_port")):
            continue
        payload = pkt.get("payload")
        if payload:
            out.append(bytes(payload))
    return out


# --------------------------------------------------------------------------- engines

def engine_ics_capture(path) -> Detection:
    """ics_capture.analyze_capture (and, through it, ics_protocols.dissect): TCP ICS protocols
    (modbus, dnp3, s7comm, iec104, enip, bacnet-over-tcp)."""
    data = Path(path).read_bytes()
    report = ics_capture.analyze_capture(data)
    tokens = set(report.get("protocol_counts", {}))
    tokens |= {m.get("protocol") for m in report.get("messages", [])}
    return Detection("ics_capture", tokens, len(report.get("messages", [])))


def engine_ics_fieldbus(path) -> Detection:
    """ics_fieldbus.reports_from_pcap: BACnet/IP, Profinet and EtherNet/IP via scapy framing."""
    _require_scapy()
    reports = ics_fieldbus.reports_from_pcap(str(path))
    tokens, count = set(), 0
    for rep in reports:
        if not isinstance(rep, dict) or rep.get("error"):
            continue
        proto = rep.get("protocol")
        if proto:
            tokens.add(proto)
            count += 1
    return Detection("ics_fieldbus", tokens, count)


def engine_goose(path) -> Detection:
    """network_ics_depth.parse_goose on every IEC-61850 GOOSE layer-2 frame (ethertype 0x88B8)."""
    frames = _read_packets(path)
    tokens, count = set(), 0
    for payload in _ethertype_payloads(frames, GOOSE_ETHERTYPE):
        parsed = network_ics_depth.parse_goose(payload)
        if parsed:
            tokens.add(parsed.get("protocol", "goose"))
            count += 1
    return Detection("goose", tokens, count)


def engine_ethercat(path) -> Detection:
    """ics_app_depth.parse_ethercat_frame on every EtherCAT layer-2 frame (ethertype 0x88A4)."""
    frames = _read_packets(path)
    tokens, count = set(), 0
    for payload in _ethertype_payloads(frames, ETHERCAT_ETHERTYPE):
        try:
            parsed = ics_app_depth.parse_ethercat_frame(payload, ethernet=False)
        except Exception:  # noqa: BLE001 - foreign/short frame is data, not a crash
            continue
        if parsed and parsed.get("protocol") == "ethercat":
            tokens.add("ethercat")
            count += 1
    return Detection("ethercat", tokens, count)


def engine_opcua(path) -> Detection:
    """ics_app_depth.analyze_opcua_stream on every OPC UA binary payload (TCP 4840)."""
    tokens, count = set(), 0
    for payload in _ip_transport_payloads(path, want="tcp", port=4840):
        try:
            report = ics_app_depth.analyze_opcua_stream(payload)
        except Exception:  # noqa: BLE001 - a non-OPC-UA TCP payload on the port is data
            continue
        chunks = report.get("chunks") or []
        if chunks:
            tokens.add("opcua")
            count += len(chunks)
    return Detection("opcua", tokens, count)


def engine_mms(path) -> Detection:
    """ot_mms_services.analyze on every MMS-over-OSI payload (TCP 102), auto-unwrapping TPKT/COTP."""
    tokens, count = set(), 0
    for payload in _ip_transport_payloads(path, want="tcp", port=102):
        try:
            report = ot_mms_services.analyze(payload, layer="auto")
        except Exception:  # noqa: BLE001 - COTP CR/CC and other non-MMS frames on 102 are data
            continue
        if isinstance(report, dict) and report.get("protocol") == "mms":
            tokens.add("mms")
            count += 1
    return Detection("mms", tokens, count)


ENGINES = {
    "ics_capture": engine_ics_capture,
    "ics_fieldbus": engine_ics_fieldbus,
    "goose": engine_goose,
    "ethercat": engine_ethercat,
    "opcua": engine_opcua,
    "mms": engine_mms,
}


def detect(engine: str, path) -> Detection:
    """Run `engine` on the capture at `path`. Raises KeyError for an unknown engine (loud, never a
    silent no-op) and OracleError when scapy is absent."""
    if engine not in ENGINES:
        raise KeyError(f"unknown OT oracle engine {engine!r}; known: {sorted(ENGINES)}")
    return ENGINES[engine](path)
