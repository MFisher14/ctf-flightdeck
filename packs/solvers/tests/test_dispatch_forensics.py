from __future__ import annotations

import base64
import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))
import dispatch_forensics as D  # noqa: E402


def _values(report):
    return {row["value"]: row for row in report["candidates"]}


def _has_engine(row, name):
    return row.get("engine") == name or any(step == f"engine={name}" for step in row.get("derivation", []))


def _png(payload: bytes = b"") -> bytes:
    def chunk(kind, body):
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
    raw = b"\x00\x00\x00\x00"  # filter byte plus one RGB pixel
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"") + payload)


def _wav_lsb(payload: bytes) -> bytes:
    bits = [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]
    samples = bytes(128 | bit for bit in bits)
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    return (b"RIFF" + struct.pack("<I", 4 + 8 + len(fmt) + 8 + len(samples)) + b"WAVE"
            + b"fmt " + struct.pack("<I", len(fmt)) + fmt
            + b"data" + struct.pack("<I", len(samples)) + samples)


def _pcap(payload: bytes) -> bytes:
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp = struct.pack(">HHIIHHHH", 4444, 80, 1000, 1, (5 << 12) | 0x18, 8192, 0, 0) + payload
    ip = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                               b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02"))
    frame = eth + ip + tcp
    return (struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)


def _vhd(payload: bytes) -> bytes:
    footer = bytearray(512)
    footer[:8] = b"conectix"
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">Q", footer, 40, len(payload))
    struct.pack_into(">Q", footer, 48, len(payload))
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, 0)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return payload + footer


def _uf2(payload: bytes) -> bytes:
    block = bytearray(512)
    struct.pack_into("<IIIIIIII", block, 0, 0x0A324655, 0x9E5D5157, 0, 0x2000,
                     len(payload), 0, 1, 0)
    block[32:32 + len(payload)] = payload
    struct.pack_into("<I", block, 508, 0x0AB16F30)
    return bytes(block)


def test_archive_member_chain_and_explicit_key_policy():
    flag = b"CSCTF{r5a_archive_member}"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested/flag.txt", flag)
    report = D.dispatch("archive password is stated-only-key", {"evidence.zip": buf.getvalue()})
    row = _values(report)[flag.decode()]
    assert row["verified"]
    assert _has_engine(row, "archive_passwords.read_all")
    assert report["network_requests"] == 0 and report["submitted"] is False


def test_archive_key_leak_file_chains_into_aes_member():
    pyzipper = pytest.importorskip("pyzipper")
    flag = b"CSCTF{r5a_delivered_archive_key}"
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(b"delivered-key")
        zf.writestr("flag.txt", flag)
    report = D.dispatch("open the supplied encrypted archive", {
        "locked.zip": buf.getvalue(), "password.txt": b"delivered-key\n",
    })
    row = _values(report)[flag.decode()]
    assert _has_engine(row, "archive_passwords.read_all")
    assert row["verified"] is True


def test_png_trailing_stego_is_derived_by_container_engine():
    flag = b"CSCTF{r5a_png_trailing}"
    report = D.dispatch("image stego trailing data", {"cover.png": _png(flag)})
    row = _values(report)[flag.decode()]
    assert row["verified"]
    assert _has_engine(row, "carve_stego.scan")


def test_wav_sample_lsb_chain():
    flag = b"CSCTF{r5a_wav_lsb}"
    report = D.dispatch("audio sample LSB steganography", {"tones.wav": _wav_lsb(flag)})
    row = _values(report)[flag.decode()]
    assert _has_engine(row, "carve_stego.scan")


def test_real_qr_image_decodes_to_exact_payload():
    qrcode = pytest.importorskip("qrcode")
    flag = "CSCTF{r5a_qr_decode}"
    image = qrcode.make(flag)
    out = io.BytesIO(); image.save(out, format="PNG")
    report = D.dispatch("decode the QR barcode", {"code.png": out.getvalue()}, budget_seconds=10)
    row = _values(report)[flag]
    assert _has_engine(row, "carve_stego.decode_codes")
    assert row["verified"]


def test_pcap_tcp_payload_and_reassembly_chain():
    flag = b"CSCTF{r5a_pcap_stream}"
    capture = _pcap(b"HTTP/1.1 200 OK\r\nContent-Length: 23\r\n\r\n" + flag)
    report = D.dispatch("reconstruct the TCP stream from this PCAP", {"traffic.pcap": capture})
    row = _values(report)[flag.decode()]
    assert row["engine"].startswith("network.Capture") or any(
        step.startswith("engine=network.Capture") for step in row["derivation"])
    assert any(x["archetype"] == "pcap_reconstruction" for x in report["routes"])


def test_maldoc_static_script_chain_never_executes():
    flag = "CSCTF{r5a_maldoc_script}"
    data = f'<html><script>var evidence="{flag}";</script></html>'.encode()
    report = D.dispatch("analyze this malicious HTA document", {"invoice.hta": data})
    row = _values(report)[flag]
    assert _has_engine(row, "maldoc.parse/derived") or _has_engine(row, "maldoc.handoff")
    assert report["executed_artifacts"] is False


def test_document_metadata_chain_uses_offline_lead_parser():
    flag = "CSCTF{r5a_pdf_metadata}"
    pdf = (f"%PDF-1.4\n1 0 obj <</Author ({flag})>> endobj\n"
           "trailer <</Info 1 0 R>>\n%%EOF").encode()
    report = D.dispatch("recover the document metadata", {"brief.pdf": pdf})
    row = _values(report)[flag]
    assert _has_engine(row, "osint.gather_leads")
    assert report["network_requests"] == 0


def test_description_flag_cannot_be_promoted_as_verified_metadata():
    report = D.dispatch("metadata example CSCTF{description_only}", {
        "brief.pdf": b"%PDF-1.4\n%%EOF",
    })
    assert "CSCTF{description_only}" not in _values(report)


def test_email_base64_attachment_chain():
    flag = b"CSCTF{r5a_email_attachment}"
    raw = (b"From: a@example.test\r\nTo: b@example.test\r\nSubject: fixture\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
           b"--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=flag.txt\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + base64.b64encode(flag) + b"\r\n--x--\r\n")
    report = D.dispatch("phishing email attachment", {"mail.eml": raw})
    row = _values(report)[flag.decode()]
    assert _has_engine(row, "email.load attachments")


def test_fixed_vhd_unwrap_chain():
    flag = b"CSCTF{r5a_vhd_unwrap}"
    report = D.dispatch("recover the disk image", {"disk.vhd": _vhd(flag.ljust(512, b"\0"))})
    row = _values(report)[flag.decode()]
    assert _has_engine(row, "disk_images.unwrap")
    assert row["verified"]


def test_complete_contiguous_uf2_chain():
    flag = b"CSCTF{r5a_uf2_image}"
    report = D.dispatch("UF2 firmware flash image", {"board.uf2": _uf2(flag)})
    row = _values(report)[flag.decode()]
    assert _has_engine(row, "mobile_rf_depth.parse_uf2")
    assert row["verified"]


def test_wrong_value_guards_and_malformed_inputs(tmp_path):
    ambiguous = b"CSCTF{one} and CSCTF{two}"
    report = D.dispatch("unknown", {"two.bin": ambiguous, "bad.pcap": b"\xd4\xc3\xb2\xa1bad"})
    assert set(_values(report)) == {"CSCTF{one}", "CSCTF{two}"}
    assert all(row["submission_ready"] is False for row in report["candidates"])
    assert report["human_review_required"] is True
    assert report["offline"] and report["network_requests"] == 0

    missing = tmp_path / "missing.bin"
    declined = D.dispatch("anything", [missing])
    assert not declined["candidates"] and declined["warnings"]


def test_stego_finding_without_explicit_validation_is_not_verified(monkeypatch):
    flag = "CSCTF{r5a_unvalidated_stego}"

    class FakeCarve:
        @staticmethod
        def scan(*_args, **_kwargs):
            return [{"channel": "heuristic", "method": "fixture", "text": flag}]

        @staticmethod
        def decode_codes(*_args, **_kwargs):
            return []

        @staticmethod
        def sniff(_data):
            return "png"

    monkeypatch.setitem(D._MODULES, f"{D.HERE}:carve_stego", FakeCarve)
    report = D.dispatch("image stego", {"cover.png": _png()})
    row = _values(report)[flag]
    assert row["verified"] is False
    assert row["submission_ready"] is False


def test_cli_boundary_is_guarded(tmp_path):
    bad = tmp_path / "bad.pcap"; bad.write_bytes(b"\xd4\xc3\xb2\xa1bad")
    import subprocess
    proc = subprocess.run([sys.executable, str(ROOT / "solvers" / "toolkits" / "dispatch_forensics.py"),
                           "--json", "--description", "pcap", str(bad)],
                          capture_output=True, text=True, timeout=20)
    assert proc.returncode == 0
    assert "Traceback" not in proc.stderr
    report = __import__("json").loads(proc.stdout)
    assert report["network_requests"] == 0
