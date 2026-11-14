"""Small synthetic deliveries for a lane tools/lanes.py does not know, built in memory: a pcap and an
.eml, each with its questions and its key. Used by tests/test_toolkit_registry.py and by rehearsal
R15 (tests/scenarios/r15_new_lane.py). RFC 5737 addresses and .example names only; nothing here is
read from disk or from the network."""
import hashlib
import json
import struct
from pathlib import Path

T0 = 1_790_000_000          # 2026-09-21T14:13:20Z
DOMAIN = "updates.cdn-sync.example"
SUBJECT = "Invoice 4471 overdue"


def _ip4(src: str, dst: str, payload: bytes, proto: int = 17) -> bytes:
    a = bytes(int(x) for x in src.split("."))
    b = bytes(int(x) for x in dst.split("."))
    head = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0, a, b)
    total = sum(struct.unpack(">10H", head))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return head[:10] + struct.pack(">H", ~total & 0xFFFF) + head[12:] + payload


def _udp(sport: int, dport: int, data: bytes) -> bytes:
    return struct.pack(">HHHH", sport, dport, 8 + len(data), 0) + data


def _eth(payload: bytes) -> bytes:
    return bytes.fromhex("020000000002") + bytes.fromhex("020000000001") + b"\x08\x00" + payload


def _name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def pcap_bytes(domain: str = DOMAIN) -> bytes:
    """A classic pcap (Ethernet): one DNS query for `domain`, its answer, and two NTP-sized UDP packets."""
    query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + _name(domain) + struct.pack(">HH", 1, 1)
    answer = (struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + _name(domain) + struct.pack(">HH", 1, 1)
              + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([203, 0, 113, 50]))
    frames = [_eth(_ip4("192.0.2.10", "192.0.2.53", _udp(53001, 53, query))),
              _eth(_ip4("192.0.2.53", "192.0.2.10", _udp(53, 53001, answer))),
              _eth(_ip4("192.0.2.10", "198.51.100.7", _udp(40123, 123, b"\x1b" + b"\x00" * 47))),
              _eth(_ip4("198.51.100.7", "192.0.2.10", _udp(123, 40123, b"\x1c" + b"\x00" * 47)))]
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, f in enumerate(frames):
        out += struct.pack("<IIII", T0 + i, 1000 * i, len(f), len(f)) + f
    return out


def eml_bytes(subject: str = SUBJECT) -> bytes:
    """A plain single-part mail with three Received hops and one PDF-named attachment."""
    att = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    import base64
    b64 = base64.b64encode(att).decode()
    lines = [
        "Received: from mx.victim.example (mx.victim.example [192.0.2.25]) by mail.victim.example with ESMTP id A1; Mon, 21 Sep 2026 14:13:22 +0000",
        "Received: from relay.transit.example (relay.transit.example [198.51.100.44]) by mx.victim.example with ESMTP id B2; Mon, 21 Sep 2026 14:13:21 +0000",
        "Received: from sender.billing-portal.example (sender.billing-portal.example [203.0.113.9]) by relay.transit.example with ESMTP id C3; Mon, 21 Sep 2026 14:13:20 +0000",
        "From: Accounts <accounts@billing-portal.example>",
        "To: pat@victim.example",
        f"Subject: {subject}",
        "Date: Mon, 21 Sep 2026 14:13:20 +0000",
        "Message-ID: <4471.1790000000@billing-portal.example>",
        "MIME-Version: 1.0",
        'Content-Type: multipart/mixed; boundary="BOUND"',
        "",
        "--BOUND",
        "Content-Type: text/plain; charset=us-ascii",
        "",
        "Please see the attached invoice.",
        "",
        "--BOUND",
        'Content-Type: application/pdf; name="invoice-4471.pdf"',
        "Content-Transfer-Encoding: base64",
        'Content-Disposition: attachment; filename="invoice-4471.pdf"',
        "",
        b64,
        "--BOUND--",
        "",
    ]
    return "\r\n".join(lines).encode()


def _q(qid, text, artifact, kind="exact_text", syntax="exact artifact-derived value only"):
    return {"id": qid, "question": text, "artifact": artifact, "answer_format": {"kind": kind, "syntax": syntax},
            "normalization": "trim"}


def pcap_case() -> dict:
    data = pcap_bytes()
    questions = [
        _q("capture-packet-count", "How many packets are in capture.pcap?", "capture.pcap", "integer", "a whole number"),
        _q("capture-dns-query", "Which domain was queried in the capture?", "capture.pcap"),
    ]
    return {"filename": "capture.pcap", "data": data, "questions": questions, "name": "Wire Tap",
            "key": {"capture-packet-count": "4", "capture-dns-query": DOMAIN}, "toolkit": "network"}


def eml_case() -> dict:
    data = eml_bytes()
    questions = [
        _q("mail-received-count", "How many Received headers does the email have?", "message.eml", "integer", "a whole number"),
        _q("mail-subject", "What is the subject of the email?", "message.eml"),
    ]
    return {"filename": "message.eml", "data": data, "questions": questions, "name": "Past Due",
            "key": {"mail-received-count": "3", "mail-subject": SUBJECT}, "toolkit": "email"}


def attempt_of(case: dict, attempt_id: str = "tk-0001") -> dict:
    """The attempt.json of a solved single solve, as the Game Master's status returns one."""
    data = case["data"]
    return {"result": "CORRECT", "name": case["name"], "prompt": "A new kind of evidence.", "questions": case["questions"],
            "attempt_id": attempt_id, "mode": "single_solve", "started_at": "2026-10-05T13:00:00.000Z", "deadline": None,
            "answer_ids": [q["id"] for q in case["questions"]],
            "artifacts": [{"download": "/?op=download&capability=tk", "filename": case["filename"],
                           "sha256": hashlib.sha256(data).hexdigest(), "size": len(data), "kind": "file"}]}


def write_attempt(folder: Path, case: dict, attempt_id: str = "tk-0001") -> Path:
    """Save the case as an attempt folder (attempt.json, artifact/<file>), as tools/verify.py --start does."""
    folder = Path(folder)
    (folder / "artifact").mkdir(parents=True, exist_ok=True)
    (folder / "artifact" / case["filename"]).write_bytes(case["data"])
    (folder / "attempt.json").write_text(json.dumps(attempt_of(case, attempt_id), indent=1))
    return folder
