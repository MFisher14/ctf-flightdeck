"""Round-5a end-to-end orchestration fixtures.

Each recovery case starts at :func:`autosolve.autosolve`, exercises classifier and dispatcher
selection, reaches a pre-existing engine through one of the new dispatchers, and recovers an exact
flag-format value.  The plan-only cases separately prove that archetypes which require a live,
target-specific interaction remain inert while still preserving a byte-proven review candidate.
"""
from __future__ import annotations

import base64
import io
import json
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pyzipper
import qrcode
from Crypto.Cipher import AES


ROOT = Path(__file__).resolve().parents[1]
TOOLKITS = ROOT / "solvers" / "toolkits"
if str(TOOLKITS) not in sys.path:
    sys.path.insert(0, str(TOOLKITS))

import autosolve as autosolver  # noqa: E402
import dispatch_exploit as exploit_dispatcher  # noqa: E402
import ssti_helper  # noqa: E402


@dataclass(frozen=True)
class RecoveryCase:
    lane: str
    group: str
    classifier: str
    flag: str
    marker: str
    description: str
    category: str
    files: Callable[[], dict[str, bytes | str]]


@dataclass(frozen=True)
class PlanCase:
    lane: str
    observation: str
    marker: str
    description: str
    category: str
    files: Callable[[], dict[str, bytes | str]]


def _png(payload: bytes = b"") -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        checksum = zlib.crc32(kind + body) & 0xFFFFFFFF
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", checksum)

    raw = b"\x00\x00\x00\x00"  # filter byte plus one RGB pixel
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"") + payload)


def _wav_lsb(payload: bytes) -> bytes:
    bits = [(byte >> shift) & 1 for byte in payload for shift in range(7, -1, -1)]
    samples = bytes(128 | bit for bit in bits)
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 8000, 1, 8)
    return (b"RIFF" + struct.pack("<I", 4 + 8 + len(fmt) + 8 + len(samples)) + b"WAVE"
            + b"fmt " + struct.pack("<I", len(fmt)) + fmt
            + b"data" + struct.pack("<I", len(samples)) + samples)


def _pcap(payload: bytes) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    tcp = struct.pack(">HHIIHHHH", 4444, 80, 1000, 1, (5 << 12) | 0x18, 8192, 0, 0) + payload
    ipv4 = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                       b"\x0a\x00\x00\x01", b"\x0a\x00\x00\x02")
    frame = ethernet + ipv4 + tcp
    return (struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)


def _vhd(payload: bytes) -> bytes:
    body = payload.ljust(512, b"\0")
    footer = bytearray(512)
    footer[:8] = b"conectix"
    struct.pack_into(">Q", footer, 16, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">Q", footer, 40, len(body))
    struct.pack_into(">Q", footer, 48, len(body))
    struct.pack_into(">I", footer, 60, 2)
    struct.pack_into(">I", footer, 64, 0)
    struct.pack_into(">I", footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return body + footer


def _uf2(payload: bytes) -> bytes:
    block = bytearray(512)
    struct.pack_into("<IIIIIIII", block, 0, 0x0A324655, 0x9E5D5157, 0, 0x2000,
                     len(payload), 0, 1, 0)
    block[32:32 + len(payload)] = payload
    struct.pack_into("<I", block, 508, 0x0AB16F30)
    return bytes(block)


def _jwt(payload: dict[str, str]) -> str:
    def enc(value: dict[str, str]) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return enc({"alg": "none", "typ": "JWT"}) + "." + enc(payload) + "."


def _qr(flag: str) -> dict[str, bytes]:
    image = qrcode.make(flag)
    handle = io.BytesIO()
    image.save(handle, format="PNG")
    return {"code.png": handle.getvalue()}


def _encrypted_zip(flag: str) -> dict[str, bytes]:
    handle = io.BytesIO()
    with pyzipper.AESZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(b"r5a-delivered-key")
        archive.writestr("nested/flag.txt", flag.encode())
    return {"locked.zip": handle.getvalue(), "password.txt": b"r5a-delivered-key\n"}


def _aes_cbc(flag: str) -> dict[str, bytes]:
    key, iv = b"YELLOW SUBMARINE", bytes(16)
    plaintext = flag.encode()
    padding = 16 - len(plaintext) % 16
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(
        plaintext + bytes([padding]) * padding)
    return {"params.txt": (
        f"key = {key.hex()}\niv = {iv.hex()}\nciphertext = {ciphertext.hex()}\n"
    ).encode()}


def _keystream_reuse(flag: str) -> dict[str, bytes]:
    plaintext = flag.encode()
    known = b"known message for two time pad fixture"[:len(plaintext)].ljust(len(plaintext), b".")
    stream = bytes((index * 17 + 3) & 0xFF for index in range(len(plaintext)))
    first = bytes(left ^ right for left, right in zip(known, stream))
    second = bytes(left ^ right for left, right in zip(plaintext, stream))
    return {"first.bin": first, "second.bin": second, "known.txt": known}


def _rsa(flag: str) -> dict[str, bytes]:
    # The short CTF value is smaller than n; supplied factors make decryption deterministic.
    p, q, exponent = 1_000_000_007, 1_000_000_009, 65_537
    modulus = p * q
    ciphertext = pow(int.from_bytes(flag.encode(), "big"), exponent, modulus)
    return {"rsa.txt": (
        f"n={modulus}\ne={exponent}\np={p}\nq={q}\nc={ciphertext}\n"
    ).encode()}


def _email(flag: str) -> dict[str, bytes]:
    encoded = base64.b64encode(flag.encode())
    raw = (b"From: a@example.test\r\nTo: b@example.test\r\nSubject: r5a\r\n"
           b"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
           b"--x\r\nContent-Type: text/plain\r\n\r\nbody\r\n--x\r\n"
           b"Content-Type: application/octet-stream\r\n"
           b"Content-Disposition: attachment; filename=flag.txt\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\n" + encoded + b"\r\n--x--\r\n")
    return {"message.eml": raw}


def _wasm(flag: str) -> dict[str, bytes]:
    value = flag.encode()
    body = bytes([len(value)]) + value
    return {"module.wasm": b"\0asm\x01\0\0\0" + b"\x00" + bytes([len(body)]) + body}


def _evm(flag: str) -> dict[str, bytes]:
    value = flag.encode()
    code = bytes([0x5F + len(value)]) + value + b"\x32\x14\x57\x00"
    return {"runtime.hex": code.hex().encode()}


RECOVERY_CASES = (
    RecoveryCase("encoding/base64-chain", "crypto", "encoding-chain", "CSCTF{r5a_i_b64}",
                 "crib_decode.solve_blob", "peel this base64 encoding chain", "crypto",
                 lambda: {"layers.txt": base64.b64encode(base64.b64encode(b"CSCTF{r5a_i_b64}"))}),
    RecoveryCase("xor/single-byte", "crypto", "xor-keystream", "CSCTF{r5a_i_xor}",
                 "modern_crypto.solve_xor", "single-byte XOR keystream; recover the flag", "crypto",
                 lambda: {"cipher.bin": bytes(value ^ 0x42 for value in b"CSCTF{r5a_i_xor}")}),
    RecoveryCase("classical/rot13", "crypto", "classical-cipher", "CSCTF{r5a_i_rot}",
                 "classical.solve_classical", "classical Caesar ROT13 cipher", "crypto",
                 lambda: {"cipher.txt": b"PFPGS{e5n_v_ebg}"}),
    RecoveryCase("rsa/given-factors", "crypto", "rsa-ecc", "CTF{x}",
                 "modern_crypto.solve_rsa", "RSA weakness: supplied factors decrypt the ciphertext", "crypto",
                 lambda: _rsa("CTF{x}")),
    RecoveryCase("symmetric/aes-cbc-stated-key", "crypto", "encoding-chain",
                 "CSCTF{r5a_i_aes}", "modern_crypto.solve_sym",
                 "decode the AES CBC ciphertext with the stated key", "crypto",
                 lambda: _aes_cbc("CSCTF{r5a_i_aes}")),
    RecoveryCase("stream/two-time-pad-reuse", "crypto", "xor-keystream",
                 "CSCTF{r5a_i_reuse}", "modern_crypto.solve_reuse",
                 "two-time pad XOR keystream reuse with a known plaintext", "crypto",
                 lambda: _keystream_reuse("CSCTF{r5a_i_reuse}")),
    RecoveryCase("archive/encrypted-key-leak", "forensics", "archive-key-leak",
                 "CSCTF{r5a_i_zip}", "archive_passwords.read_all",
                 "open the encrypted ZIP using only the delivered password file", "forensics",
                 lambda: _encrypted_zip("CSCTF{r5a_i_zip}")),
    RecoveryCase("image/png-trailing", "forensics", "image-stego", "CSCTF{r5a_i_png}",
                 "carve_stego.scan", "image stego with trailing PNG data", "stego",
                 lambda: {"cover.png": _png(b"CSCTF{r5a_i_png}")}),
    RecoveryCase("audio/wav-sample-lsb", "forensics", "audio-stego", "CSCTF{r5a_i_wav}",
                 "carve_stego.scan", "audio WAV sample LSB steganography", "stego",
                 lambda: {"tones.wav": _wav_lsb(b"CSCTF{r5a_i_wav}")}),
    RecoveryCase("barcode/qr-pixels", "forensics", "qr-barcode", "CSCTF{r5a_i_qr}",
                 "carve_stego.decode_codes", "decode this QR barcode image", "misc",
                 lambda: _qr("CSCTF{r5a_i_qr}")),
    RecoveryCase("network/pcap-tcp-reassembly", "forensics", "pcap-network",
                 "CSCTF{r5a_i_pcap}", "network.Capture",
                 "reconstruct the TCP stream from this PCAP network capture", "forensics",
                 lambda: {"traffic.pcap": _pcap(b"HTTP/1.1 200 OK\r\n\r\nCSCTF{r5a_i_pcap}")}),
    RecoveryCase("email/mime-attachment", "forensics", "email-metadata",
                 "CSCTF{r5a_i_mail}", "email.load attachments",
                 "recover the phishing email MIME attachment", "forensics",
                 lambda: _email("CSCTF{r5a_i_mail}")),
    RecoveryCase("maldoc/hta-derived-script", "forensics", "maldoc", "CSCTF{r5a_i_hta}",
                 "maldoc.parse/derived", "analyze this malicious HTA maldoc", "forensics",
                 lambda: {"invoice.hta": b'<html><script>var x="CSCTF{r5a_i_hta}";</script></html>'}),
    RecoveryCase("metadata/pdf-author", "forensics", "email-metadata", "CSCTF{r5a_i_meta}",
                 "osint.gather_leads", "recover the PDF document metadata", "osint",
                 lambda: {"brief.pdf": (b"%PDF-1.4\n1 0 obj <</Author (CSCTF{r5a_i_meta})>> "
                                          b"endobj\ntrailer <</Info 1 0 R>>\n%%EOF")}),
    RecoveryCase("disk/fixed-vhd-reconstruction", "forensics", "disk-forensics",
                 "CSCTF{r5a_i_vhd}", "disk_images.unwrap", "recover the fixed VHD disk image", "forensics",
                 lambda: {"disk.vhd": _vhd(b"CSCTF{r5a_i_vhd}")}),
    RecoveryCase("firmware/uf2-reconstruction", "forensics", "firmware-mobile",
                 "CSCTF{r5a_i_uf2}", "mobile_rf_depth.parse_uf2", "reconstruct the UF2 firmware image", "misc",
                 lambda: {"board.uf2": _uf2(b"CSCTF{r5a_i_uf2}")}),
    RecoveryCase("web/jwt-claim", "exploit", "web-trust", "CSCTF{r5a_i_jwt}",
                 "auth_trust.inspect_jwt", "inspect JWT client-side role trust", "web",
                 lambda: {"token.txt": _jwt({"role": "admin", "flag": "CSCTF{r5a_i_jwt}"})}),
    RecoveryCase("web/xxe-saved-differential", "exploit", "web-trust",
                 "CSCTF{r5a_i_xxe}", "web_xxe_ssrf.flag_from_exploit",
                 "XXE saved file-read response differential", "web",
                 lambda: {"baseline.txt": b"ordinary page",
                          "xxe-exploit-response.txt": b"root:x:0:0\nCSCTF{r5a_i_xxe}"}),
    RecoveryCase("reverse/wasm-custom-section", "exploit", "reverse-engineering",
                 "CSCTF{r5a_i_wasm}", "reverse_formats.analyze_languages",
                 "reverse this WASM binary", "reverse", lambda: _wasm("CSCTF{r5a_i_wasm}")),
    RecoveryCase("blockchain/evm-push-immediate", "exploit", "blockchain",
                 "CSCTF{r5a_i_evm}", "EVM PUSH immediate decode",
                 "analyze this Solidity EVM smart contract", "blockchain",
                 lambda: _evm("CSCTF{r5a_i_evm}")),
)


def _xorshift_files() -> dict[str, bytes]:
    state = 123_456_789
    outputs = []
    for _ in range(6):
        outputs.append(state)
        state ^= (state << 13) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
        state ^= state >> 17
        state &= 0xFFFFFFFF
        state ^= (state << 5) & 0xFFFFFFFF
        state &= 0xFFFFFFFF
    return {"outputs.json": json.dumps(outputs).encode(),
            "expected-review.txt": b"CSCTF{r5a_i_prng_review}"}


def _ssti_files() -> dict[str, str]:
    probe = ssti_helper.fingerprint_probes()[0]
    response = next(iter(probe["expected"].values()))
    return {"response.txt": response, "review.txt": "CSCTF{r5a_i_ssti_review}"}


PLAN_CASES = (
    PlanCase("prng/xorshift-replay", "prng-prediction", "xorshift_predict",
             "predict the xorshift PRNG next output", "crypto", _xorshift_files),
    PlanCase("oracle/cbc-padding", "cbc-padding-oracle", "crypto_oracles.cbc_padding_oracle_decrypt",
             "CBC PKCS#7 padding-oracle challenge", "crypto",
             lambda: {"saved-proof.txt": b"CSCTF{r5a_i_oracle_review}"}),
    PlanCase("pwn/format-string-recon", "format-string-recon", "pwn_exploit.fmtstr_probe",
             "format string GOT overwrite reconnaissance", "pwn",
             lambda: {"saved-proof.txt": b"CSCTF{r5a_i_fmt_review}"}),
    PlanCase("pwn/rop-recon", "rop-recon", "pwn_exploit",
             "buffer overflow ROP ret2libc reconnaissance", "pwn",
             lambda: {"saved-proof.txt": b"CSCTF{r5a_i_rop_review}"}),
    PlanCase("web/graphql-offline", "graphql-offline", "graphql_analyzer.analyze_document",
             "GraphQL authorization review", "web",
             lambda: {"query.graphql": 'query Q { lookup(marker: "CSCTF{r5a_i_gql_review}") { id } }'}),
    PlanCase("web/ssti-saved-response", "ssti-saved-response", "ssti_helper.analyze_response",
             "saved SSTI template injection response", "web", _ssti_files),
    PlanCase("web/deserialization-review", "deserialization-review", "deser_gadgets.synthesize",
             "Python YAML deserialization review", "web",
             lambda: {"app.py": (b"# CSCTF{r5a_i_deser_review}\nimport yaml\n"
                                   b"yaml.load(data, Loader=yaml.UnsafeLoader)\n")}),
    PlanCase("programming/saved-transcript", "saved-transcript", "transcript_automation.analyze_transcript",
             "saved quiz transcript interactive protocol", "programming",
             lambda: {"transcript.json": json.dumps({
                 "events": [{"direction": "recv", "data": "What is 12 + 30?"}]
             }), "review.txt": "CSCTF{r5a_i_transcript_review}"}),
)


def _row_for(report: dict, value: str) -> dict:
    return next(row for row in report["candidates"] if row["value"] == value)


def _semantic_text(report: dict) -> str:
    return json.dumps({
        "attempts": report["attempts"],
        "candidates": report["candidates"],
        "observations": report["observations"],
    }, sort_keys=True)


def _assert_public_contract(report: dict) -> None:
    assert report["schema"] == "csctf-r5a-autosolve-v1"
    assert report["dispatcher"] == "autosolve"
    assert report["offline"] is True
    assert report["network_requests"] == 0
    assert report["submitted"] is False
    assert all(row["submission_ready"] is False for row in report["candidates"])
    assert all(row["requires_human_review"] is True for row in report["candidates"])
    json.dumps(report, allow_nan=False)


import pytest  # noqa: E402  (kept after helper-only dependencies for readable collection errors)


@pytest.mark.parametrize("case", RECOVERY_CASES, ids=lambda case: case.lane)
def test_twenty_parser_backed_triage_engine_decode_flag_chains(case: RecoveryCase):
    report = autosolver.autosolve(case.description, case.files(), category=case.category)
    _assert_public_contract(report)

    assert case.classifier in {row["archetype"] for row in report["archetypes"]}
    assert case.group in {row["dispatcher"] for row in report["dispatcher_selection"]}
    dispatched = next(row for row in report["dispatcher_reports"] if row["group"] == case.group)
    assert dispatched["candidate_count"] >= 1

    row = _row_for(report, case.flag)
    assert row["derivation"]
    assert case.marker in _semantic_text(report)
    # A parser-backed path must contribute a second derivation when the raw-byte backstop also saw
    # the value; encoded/container-only values naturally have a single specialized derivation.
    assert row.get("derivation_paths", 1) >= 1


@pytest.mark.parametrize("case", PLAN_CASES, ids=lambda case: case.lane)
def test_inert_plan_archetypes_keep_engine_evidence_and_review_candidate(case: PlanCase):
    report = autosolver.autosolve(case.description, case.files(), category=case.category)
    _assert_public_contract(report)

    text = _semantic_text(report)
    assert case.observation in text
    assert case.marker in text
    assert report["candidates"]  # saved byte evidence, never an invented target response
    assert all(row["submission_ready"] is False for row in report["candidates"])


def test_integration_inventory_is_unique_and_meets_requested_scale():
    recovery_lanes = [case.lane for case in RECOVERY_CASES]
    plan_lanes = [case.lane for case in PLAN_CASES]
    assert len(recovery_lanes) == 20
    assert len(set(recovery_lanes)) == 20
    assert len(set(recovery_lanes + plan_lanes)) == 28
    assert {case.group for case in RECOVERY_CASES} == {"crypto", "forensics", "exploit"}


def test_plan_fixture_direct_dispatch_remains_inert():
    """The top-level sanitizer drops plan detail, so also pin the source dispatcher's safety bit."""
    report = exploit_dispatcher.dispatch(
        "format string ROP and saved GraphQL transcript",
        {"query.graphql": "query Q { viewer { id } }"}, category="pwn",
    )
    assert report["executed_artifacts"] is False
    assert report["network_requests"] == 0 and report["submitted"] is False
    assert all(plan["executed"] is False and plan["network_requests"] == 0
               for plan in report["plans"])
