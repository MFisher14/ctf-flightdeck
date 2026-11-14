"""Synthetic fixtures for the B-090 series-chaining tests (tests/test_series.py, tests/test_cli_series.py).

Sibling workspaces in the `ctf pull` / `ctf intake` layout, a self-signed certificate generated here
and a made-up ICO. No challenge file is used.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ctf import event

# Synthetic wording in the shape of a split lab (a first task with the briefing, follow-ups that
# only say they continue it). Not any event's text.
BRIEF_1 = ("A lab briefing. The service presents a self-signed certificate.\n<br>**Task 1 - Read the "
           "Certificate**\n<br>Read the serial.\n<br>Flag format: `CSCTF{<answer>}`")
BRIEF_FP = ("<br>\n*Continuation of the same lab. See the first task for the full briefing.*\n<br>"
            "**Task 2 - Fingerprint the Certificate**\n<br>\nGet the certificate's SHA-256 fingerprint.\n"
            "<br>\n**Answer**: the SHA-256 fingerprint, uppercase hexadecimal with colons (e.g. `AA:BB:...`)."
            "\n<br>\nFlag format: `CSCTF{<answer>}`")
BRIEF_MD5 = ("<br>\n*Continuation of the same lab. See the first task for the full briefing.*\n<br>"
             "**Task 2 - Hash the Favicon Again**\n<br>\nGet the favicon's MD5 hash.\n<br>\n"
             "**Answer**: the MD5 hash, hexadecimal.\n<br>\nFlag format: `CSCTF{<answer>}`")

ICON = b"\x00\x00\x01\x00\x01\x00\x10\x10" + bytes(range(256)) * 3


def make_cert(serial: int, cn: str = "lab.example.onion"):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(serial).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def colon_upper(digest: bytes) -> str:
    return ":".join(f"{b:02X}" for b in digest)


def workspace(root: Path, cid: int, name: str, description: str, files: dict | None = None) -> Path:
    from ctf import workspace as ws
    d = root / ws.dir_name(cid, name)
    d.mkdir(parents=True)
    (d / "challenge.json").write_text(json.dumps({"id": cid, "name": name, "category": "OSINT",
                                                  "description": description}), encoding="utf-8")
    for rel, data in (files or {}).items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return d


def profile(prefixes=("CSCTF",)):
    return event.parse({
        "slug": "series-test", "name": "series test",
        "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 1, 2)},
        "platform": {"kind": "ctfd", "base_url": "https://board.series.test"},
        "flag": {"prefixes": list(prefixes), "body": "[^}\\n]{1,256}", "case": "exact"},
        "rules": {"submit_mode": "manual", "flag_sharing": "forbidden", "ai_on_platform": "allowed",
                  "live_service_scope": ["localhost"]},
    }, src="<test>")
