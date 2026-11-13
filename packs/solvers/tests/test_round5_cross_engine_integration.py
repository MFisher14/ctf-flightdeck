"""Round-5 cross-engine integrations over synthetic, offline-only fixtures.

Each test starts at :mod:`ctf.triage`, exercises the routed engine, and reaches a
synthetic flag-shaped value.  Candidate-only engines are never silently promoted:
the pwn and OSINT cases end in an explicit, non-submittable human-review record.
All other cases require an independent authentication, checksum, round-trip, or
container-structure check before ``_only_verified_flag`` accepts the value.
"""
from __future__ import annotations

import json
import math
import struct
import sys
import urllib.parse
import uuid
import zlib
from pathlib import Path

import zstandard
import zxingcpp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt, paths
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import flagfmt, paths

ROOT = Path(__file__).resolve().parents[1]
for relative in ("solvers/common", "solvers/toolkits", "solvers/warmups", "solvers/web"):
    sys.path.insert(0, str(ROOT / relative))

from ctf import triage  # noqa: E402

import artifact_depth  # noqa: E402
import audio_stego  # noqa: E402
import crib_decode  # noqa: E402
import disk_images  # noqa: E402
import ecc_codes  # noqa: E402
import ecc_steps  # noqa: E402
import evm_security  # noqa: E402
import language_scripts  # noqa: E402
import llm_security  # noqa: E402
import matrix_barcodes  # noqa: E402
import mobile_rf_depth  # noqa: E402
import network_ics_depth  # noqa: E402
import osint_online  # noqa: E402
import pwn_advanced  # noqa: E402
import reverse_formats  # noqa: E402
import signal_stego  # noqa: E402
import token_depth  # noqa: E402
import transform_stego  # noqa: E402
import web_attack_depth  # noqa: E402


FLAG_BYTES = flagfmt.BYTES       # the event's flag format (the suite runs as csctf)


def _route(category: str, description: str, engine: str, *, first: bool = True) -> dict:
    report = triage.suggest(category, description)
    assert engine in report["engines"]
    if first:
        assert report["engines"][0] == engine
    return report


def _only_verified_flag(value: bytes | str, *, verified: bool) -> str:
    """Extract one value only after an independent integrity assertion passed."""
    assert verified is True
    raw = value.encode() if isinstance(value, str) else bytes(value)
    hits = list(dict.fromkeys(FLAG_BYTES.findall(raw)))
    assert len(hits) == 1
    return hits[0].decode("ascii")


def _review_only_flag(value: bytes | str, *, reason: str) -> dict:
    """Expose a candidate without ever labelling it submission-ready."""
    raw = value.encode() if isinstance(value, str) else bytes(value)
    hits = list(dict.fromkeys(FLAG_BYTES.findall(raw)))
    assert len(hits) == 1 and reason
    return {"value": hits[0].decode("ascii"), "requires_human_review": True,
            "submission_ready": False, "reason": reason}


def _leb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _zx_matrix(content: str, fmt, **options) -> list[list[bool]]:
    symbol = zxingcpp.create_barcode(content, fmt, **options)
    image = zxingcpp.write_barcode_to_image(symbol, scale=1, add_quiet_zones=False)
    height, width = image.shape
    pixels = memoryview(image).cast("B")
    return [[pixels[y * width + x] < 128 for x in range(width)] for y in range(height)]


def _h84_envelope(payload: bytes) -> bytes:
    words = bytearray()
    for byte in payload:
        words.extend((ecc_codes.hamming84_encode(byte >> 4),
                      ecc_codes.hamming84_encode(byte & 15)))
    words[3] ^= 0x20  # exercise correction; the outer CRC is the promotion gate
    return (b"H84:" + words.hex().encode() + b":"
            + f"{zlib.crc32(payload) & 0xffffffff:08x}".encode())


def _other_info(algorithm: str, bits: int) -> bytes:
    field = lambda value: len(value).to_bytes(4, "big") + value
    return field(algorithm.encode()) + field(b"") + field(b"") + bits.to_bytes(4, "big")


def _qcow_zstd(payload: bytes) -> tuple[bytes, bytes, bytes]:
    raw = payload.ljust(512, b"\0")
    packed = zstandard.ZstdCompressor().compress(raw)
    image = bytearray(4 * 512)
    struct.pack_into(">4sI", image, 0, disk_images.QCOW_MAGIC, 3)
    struct.pack_into(">QIIQIIQ", image, 8, 0, 0, 9, 512, 0, 1, 512)
    struct.pack_into(">Q", image, 72, 1 << 3)  # incompatible: extended L2
    struct.pack_into(">I", image, 100, 112)
    image[104] = 1  # zstd compression type
    struct.pack_into(">Q", image, 512, 1024)
    struct.pack_into(">Q", image, 1024, (1 << 62) | 1536)
    image[1536:1536 + len(packed)] = packed
    return bytes(image), raw, packed


def _wav_bfsk(payload: bytes, *, rate: int = 8000, baud: int = 100,
              mark: int = 1400, space: int = 900) -> bytes:
    bits = list(transform_stego._bits(transform_stego.pack_frame(payload)))
    width, samples = rate // baud, []
    for bit in bits:
        frequency = mark if bit else space
        samples.extend(round(12000 * math.sin(2 * math.pi * frequency * i / rate))
                       for i in range(width))
    return audio_stego.build_wav(rate, 16, [samples])


def _pnio_write(payload: bytes) -> bytes:
    ar_uuid = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
    body = ((0x1234).to_bytes(2, "big") + ar_uuid.bytes_le
            + (0x01020304).to_bytes(4, "big") + (0x0506).to_bytes(2, "big")
            + (0x0708).to_bytes(2, "big") + b"\x00\x00" + (0x0A0B).to_bytes(2, "big")
            + len(payload).to_bytes(4, "big") + payload)
    block = b"\x00\x09" + (2 + len(body)).to_bytes(2, "big") + b"\x01\x00" + body
    block += b"\0" * (-len(block) % 4)
    stub = b"\x78\x56\x34\x12" + block
    header = bytearray(80)
    header[0:2] = b"\x04\x00"
    header[4:7] = b"\x10\x00\x00"
    header[24:40] = uuid.UUID("dea00001-6c97-11d1-8271-00a02442df7d").bytes_le
    header[40:56] = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes_le
    header[68:70] = (3).to_bytes(2, "little")
    header[70:72] = (0x1111).to_bytes(2, "little")
    header[72:74] = (0x2222).to_bytes(2, "little")
    header[74:76] = len(stub).to_bytes(2, "little")
    return bytes(header) + stub


def _uf2(payload: bytes) -> bytes:
    block = bytearray(512)
    struct.pack_into("<IIIIIIII", block, 0, mobile_rf_depth.UF2_MAGIC0,
                     mobile_rf_depth.UF2_MAGIC1, 0x2000, 0x2000, len(payload), 0, 1,
                     0xE48BFF56)
    block[32:32 + len(payload)] = payload
    struct.pack_into("<I", block, 508, mobile_rf_depth.UF2_END)
    return bytes(block)


def test_chain_barcode_dmre_rs_to_flag():
    flag = "CSCTF{r5_dmre}"
    _route("stego", "perspective DMRE barcode", "solvers/toolkits/qr_matrix.py")
    matrix = _zx_matrix(flag, zxingcpp.DataMatrix, version=31)
    rows = matrix_barcodes.decode_datamatrix(matrix)
    row = next(item for item in rows if item["text"] == flag)
    assert row["finder_score"] >= 85 and row["corrected_symbols"] == 0
    # A second implementation independently accepts the same matrix content.
    reference = zxingcpp.read_barcode(
        zxingcpp.write_barcode_to_image(
            zxingcpp.create_barcode(flag, zxingcpp.DataMatrix, version=31),
            scale=3, add_quiet_zones=True),
        formats=zxingcpp.DataMatrix, is_pure=True)
    assert _only_verified_flag(row["bytes"], verified=reference.bytes == flag.encode()) == flag


def test_chain_crypto_ecdh_es_authenticated_jwe_to_flag():
    flag = b"CSCTF{r5_ecdh_chain}"
    _route("web", "JWE ECDH-ES epk X25519 compact token", "solvers/web/token_depth.py")
    recipient = x25519.X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    ephemeral = x25519.X25519PrivateKey.from_private_bytes(bytes(range(33, 65)))
    public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw,
                                                 serialization.PublicFormat.Raw)
    header = {"alg": "ECDH-ES", "enc": "A256GCM", "epk": {
        "kty": "OKP", "crv": "X25519", "x": token_depth.b64u_encode(public)}}
    shared = ephemeral.exchange(recipient.public_key())
    cek = ConcatKDFHash(algorithm=hashes.SHA256(), length=32,
                        otherinfo=_other_info("A256GCM", 256)).derive(shared)
    protected = token_depth.b64u_encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode())
    iv = bytes.fromhex("00112233445566778899aabb")
    sealed = AESGCM(cek).encrypt(iv, flag, protected.encode())
    compact = ".".join((protected, "", token_depth.b64u_encode(iv),
                        token_depth.b64u_encode(sealed[:-16]),
                        token_depth.b64u_encode(sealed[-16:])))
    decoded = token_depth.decrypt_jwe(compact, recipient)
    assert _only_verified_flag(decoded["plaintext"], verified=decoded["verified"]) == flag.decode()


def test_chain_qcow2_zstd_disk_recovery_to_flag():
    flag = b"CSCTF{r5_qcow_chain}"
    _route("forensics", "qcow2 zstd extended L2 disk", "solvers/toolkits/disk_images.py")
    image, raw, packed = _qcow_zstd(flag)
    decoded = disk_images.unwrap_qcow2(image)
    independent = zstandard.ZstdDecompressor().decompress(packed) == raw
    assert _only_verified_flag(decoded, verified=independent and decoded == raw) == flag.decode()


def test_chain_systemd_journal_zstd_field_to_flag():
    flag = b"CSCTF{r5_journal_chain}"
    _route("forensics", "systemd journal zstd DATA field", "solvers/toolkits/artifact_depth.py")
    field = b"MESSAGE=" + flag
    packed = zstandard.ZstdCompressor().compress(field)
    obj = bytearray(72 + len(packed))
    struct.pack_into("<Q", obj, 64, len(field))
    obj[72:] = packed
    decoded = artifact_depth._journal_field_payload(bytes(obj), 4)
    check = zstandard.ZstdDecompressor().decompress(packed) == field
    assert _only_verified_flag(decoded, verified=check and decoded.startswith(b"MESSAGE=")) == flag.decode()


def test_chain_pwn_modprobe_serialization_stays_review_only():
    flag = "CSCTF{r5_pwn_plan}"
    _route("pwn", "kernel pwn modprobe_path", "solvers/toolkits/pwn_advanced.py")
    plan = pwn_advanced.kernel_plan(
        "modprobe_path", arch="amd64", modprobe_path=0xFFFFFFFF8245A2A0,
        helper_path="/tmp/" + flag)
    assert plan.arithmetic_verified and not plan.exploitability_verified
    assert plan.payload == bytes.fromhex(plan.computed["write_bytes_hex"])
    candidate = _review_only_flag(plan.payload, reason="inert serialized helper path; exploitability unverified")
    assert candidate == {"value": flag, "requires_human_review": True,
                         "submission_ready": False,
                         "reason": "inert serialized helper path; exploitability unverified"}


def test_chain_reverse_verified_wasm_custom_name_to_flag():
    flag = b"CSCTF{r5_wasm_chain}"
    _route("reverse", "WebAssembly WASM export and custom section",
           "solvers/toolkits/reverse_formats.py")
    body = _leb(len(flag)) + flag
    module = b"\0asm\x01\0\0\0" + b"\0" + _leb(len(body)) + body
    report = reverse_formats.parse_wasm(module)
    assert report["custom_sections"] == [flag.decode()]
    section = report["sections"][0]
    exact = module[section["offset"] + len(_leb(len(flag))):
                   section["offset"] + section["size"]] == flag
    assert _only_verified_flag(report["custom_sections"][0],
                               verified=report["verified_structure"] and exact) == flag.decode()


def test_chain_web_reversible_waf_encoding_to_flag():
    flag = "CSCTF{r5_web_chain}"
    _route("web", "WAF bypass encoding catalog", "solvers/web/web_attack_depth.py")
    rows = {row["name"]: row for row in web_attack_depth.waf_encoding_candidates(flag)}
    encoded = rows["url_percent"]
    decoded = urllib.parse.unquote(encoded["value"])
    assert encoded["candidate_only"]
    assert _only_verified_flag(decoded, verified=(decoded == flag and
                                                   encoded["verified_syntax"])) == flag


def test_chain_mocked_osint_search_stays_human_pin():
    flag = "CSCTF{r5_osint_lead}"
    _route("osint", "Wayback public record search", "solvers/toolkits/osint_online.py")
    calls = []

    def transport(url, headers, timeout, max_bytes):  # noqa: ANN001
        calls.append((url, dict(headers), timeout, max_bytes))
        body = (f'<a class="result__a" href="https://public.example/record">'
                f'Archived record {flag}</a>').encode()
        return osint_online.HTTPResult(200, {"Content-Type": "text/html"}, body, url)

    client = osint_online.PublicOSINTClient(
        transport=transport, clock=lambda: 10.0, sleep=lambda _delay: None,
        min_interval=1.0, request_cap=1)
    evidence = client.search("one exact public archive record")
    assert len(calls) == 1 and client.request_count == 1
    assert calls[0][1]["User-Agent"] == osint_online.GENERIC_USER_AGENT
    candidate = _review_only_flag(evidence[0].value["title"], reason=evidence[0].note)
    assert candidate["value"] == flag and candidate["requires_human_review"]
    assert candidate["submission_ready"] is False and "unverified" in candidate["reason"]


def test_chain_llm_unicode_tag_decode_to_inert_flag():
    flag = "CSCTF{r5_llm_tags}"
    _route("ml", "system prompt indirect unicode tag jailbreak", "solvers/toolkits/llm_security.py")
    cover = "ordinary text " + llm_security.encode_unicode_tags(flag)
    view = next(row for row in llm_security.decoded_views(cover)
                if row["transform"] == "unicode_tags")
    assert "never an instruction" in view["note"]
    assert _only_verified_flag(view["text"], verified=view["verified_decode"]) == flag


def test_chain_hamming_ecc_warmup_crc_to_flag():
    flag = b"CSCTF{r5_hamming_chain}"
    _route("misc", "Hamming code error-correcting warmup", "solvers/toolkits/ecc_codes.py")
    envelope = _h84_envelope(flag)
    decoded = ecc_steps.d_hamming84(envelope)
    warmup = crib_decode.solve_blob(envelope, budget=1.0)
    crc = int(envelope.rsplit(b":", 1)[1], 16)
    assert warmup and warmup[0] == flag.decode() and crib_decode.LAST["route"] == "flag"
    assert _only_verified_flag(decoded, verified=(zlib.crc32(decoded) & 0xFFFFFFFF) == crc) == flag.decode()


def test_chain_ebcdic_language_roundtrip_to_flag():
    flag = "CSCTF{r5_ebcdic_chain}"
    _route("misc", "EBCDIC homoglyph mixed script", "solvers/toolkits/language_scripts.py")
    raw = flag.encode("cp037")
    row = next(item for item in language_scripts.encoding_candidates(raw)
               if item["text"] == flag and "cp037" in item["codecs"])
    assert row["candidate_only"]
    check = row["verified_roundtrip"] and row["text"].encode("cp037") == raw
    assert _only_verified_flag(row["text"], verified=check) == flag


def test_chain_evm_push_literal_with_exact_disassembly_to_flag():
    flag = b"CSCTF{r5_evm_push}"
    _route("crypto", "Solidity audit EVM vulnerability", "solvers/toolkits/evm_security.py")
    code = bytes([0x5F + len(flag)]) + flag + b"\x00"
    security = evm_security.analyze_bytecode(code)
    facts = evm_security.chain.bytecode_report(code)
    instructions = evm_security.chain.disassemble(code)
    assert security["vulnerability_verdict"] is None
    assert facts and facts["strings"] == [flag.decode()]
    exact = instructions[0][3] == flag and instructions[1][2] == "STOP"
    assert _only_verified_flag(facts["strings"][0], verified=exact) == flag.decode()


def test_chain_matrix_stego_crc_frame_to_flag():
    flag = b"CSCTF{r5_matrix_stego}"
    _route("stego", "matrix encoding adaptive stego", "solvers/toolkits/transform_stego.py")
    encoded = transform_stego.matrix_embed([128] * 4000, flag, k=3)
    decoded = transform_stego.matrix_extract(encoded, k=3)
    independent = transform_stego.verify_frame(transform_stego.pack_frame(flag)) == flag
    assert _only_verified_flag(decoded, verified=independent and decoded == flag) == flag.decode()


def test_chain_bfsk_signal_crc_frame_to_flag():
    flag = b"CSCTF{r5_bfsk_chain}"
    _route("stego", "BFSK modulation saved PCM", "solvers/toolkits/signal_stego.py")
    wav = _wav_bfsk(flag)
    decoded = signal_stego.decode_bfsk(wav, baud=100, mark_hz=1400, space_hz=900)
    independent = transform_stego.verify_frame(transform_stego.pack_frame(flag)) == flag
    assert _only_verified_flag(decoded, verified=independent and decoded == flag) == flag.decode()


def test_chain_pnio_ndr_record_to_flag():
    flag = b"CSCTF{r5_pnio_chain}"
    _route("ics", "PNIO-RPC IODWrite Profinet RPC", "solvers/toolkits/network_ics_depth.py")
    wire = _pnio_write(flag)
    report = network_ics_depth.parse_pnio_rpc(wire)
    assert report and report["operation"] == "Write" and report["ndr_prefix"]["aligned"]
    block = report["blocks"][0]
    exact = (block["record_data_length"] == len(flag) and wire.count(flag) == 1
             and block["api"] == 0x01020304 and block["index"] == 0x0A0B)
    assert _only_verified_flag(block["record_data"], verified=exact) == flag.decode()


def test_chain_mobile_rf_uf2_reconstruction_to_flag():
    flag = b"CSCTF{r5_uf2_chain}"
    _route("mobile", "UF2 firmware image for mobile hardware RF",
           "solvers/toolkits/mobile_rf_depth.py", first=False)
    wire = _uf2(flag)
    report = mobile_rf_depth.parse_uf2(wire)
    block = report["blocks"][0]
    exact = (block["payload_size"] == len(flag) and block["target_address"] == 0x2000
             and wire[32:32 + len(flag)] == flag)
    assert _only_verified_flag(report["image"],
                               verified=report["reconstruction_verified"] and exact) == flag.decode()


# The coverage record of the test_chain_* tests above (lane, test, integrity gate). A committed test
# fixture anchored to this file, never paths.workdir(): a CTF_WORKDIR another module leaked must not
# redirect it.
MATRIX = Path(__file__).resolve().parent / "fixtures" / "coverage_round5" / "verification_matrix.json"


def _load_matrix() -> dict:
    return json.loads(MATRIX.read_text(encoding="utf-8"))


def _chain_tests() -> set[str]:
    return {name for name, obj in globals().items()
            if name.startswith("test_chain_") and callable(obj)}


def test_verification_matrix_has_every_integration_lane():
    document = _load_matrix()
    integration = document["cross_engine_integrations"]
    assert document["schema_version"] == 1 and len(integration) >= 15
    assert all(row["test"].startswith("test_chain_") and row["synthetic_only"]
               for row in integration)
    assert {row["lane"] for row in integration} >= {
        "barcode", "crypto", "disk", "artifact", "pwn", "reverse", "web", "osint",
        "llm", "ecc", "language", "evm", "stego", "signal", "network_ics", "mobile_rf",
    }


def test_verification_matrix_matches_this_modules_chain_tests():
    """The matrix is this module's coverage record: one row per test_chain_* function, no row for a
    test that no longer exists, one lane per row."""
    rows = _load_matrix()["cross_engine_integrations"]
    names = [row["test"] for row in rows]
    assert len(names) == len(set(names)), "a chain test is listed twice"
    chain = _chain_tests()
    assert len(chain) >= 16
    assert set(names) == chain, {"unlisted": sorted(chain - set(names)),
                                 "stale": sorted(set(names) - chain)}
    lanes = [row["lane"] for row in rows]
    assert len(lanes) == len(set(lanes)) and all(row["gate"] for row in rows)
    # The review-only chains (pwn, OSINT) are recorded as never submission-ready.
    assert {row["lane"] for row in rows if row.get("submission_ready") is False} == {"pwn", "osint"}


def test_verification_matrix_ignores_a_leaked_workdir(monkeypatch, tmp_path):
    """A CTF_WORKDIR left behind by another module (one holding its own, different matrix) does not
    redirect the matrix: it is read from the repo fixture."""
    decoy = tmp_path / "coverage-round5"
    decoy.mkdir()
    (decoy / "verification_matrix.json").write_text(
        json.dumps({"schema_version": 1, "cross_engine_integrations": []}), encoding="utf-8")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    assert paths.workdir() == tmp_path.resolve()
    assert MATRIX.is_relative_to(paths.repo_root() / "tests" / "fixtures")
    assert len(_load_matrix()["cross_engine_integrations"]) >= 16
    test_verification_matrix_has_every_integration_lane()
