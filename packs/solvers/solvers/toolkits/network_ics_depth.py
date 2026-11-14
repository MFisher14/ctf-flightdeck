#!/usr/bin/env python3
"""Offline network/ICS depth: verified TLS/QUIC epochs, auth artifacts, and OT protocols.

The engine consumes local bytes only.  It never opens a socket, scans a host, sends a packet, or
tries a credential.  Its reusable APIs cover:

* extended NSS key logs, TLS 1.3 traffic-secret updates, and AEAD-verified record decryption;
* QUIC v1/v2 long/short-header protection, Retry authentication, frame grammar, and decryption;
* a unified Kerberos/NTLM/SMB artifact report over an already captured pcap;
* IEC-61850 GOOSE/MMS, OPC-UA Binary, and Profinet RT/DCP byte grammars;
* ranked classification of the covert-channel readers already shipped in ``covert_channels.py``.

Every decrypted record/packet is authenticated before its plaintext is returned.  All parsing and
allocation is bounded; malformed/truncated input declines with a guarded CLI error or an empty
candidate, never a raw traceback.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import re
import struct
import sys
import uuid
from pathlib import Path


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
MAX_INPUT = 128 << 20
MAX_KEYLOG = 16 << 20
MAX_RECORDS = 200000
MAX_RECORD = (1 << 14) + 2048
MAX_QUIC_PACKET = 65535
MAX_HANDSHAKE = 16 << 20
MAX_BER = 100000
MAX_MESSAGES = 100000
MAX_STRINGS = 10000
MAX_OUTPUT = 64 << 20


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


tls = _load("csctf_tls_keylog_depth", COMMON / "tls_keylog.py")
network = _load("csctf_network_depth", HERE / "network.py")
pcap_creds = _load("csctf_pcap_creds_depth", HERE / "pcap_creds.py")
net_auth = _load("csctf_net_auth_depth", HERE / "net_auth.py")
covert = _load("csctf_covert_depth", HERE / "covert_channels.py")

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover - repository venv carries cryptography
    HAVE_CRYPTO = False


# ---- TLS / QUIC key epochs -------------------------------------------------------------------------

_EXT_KEYLOG = re.compile(
    r"(?m)^([A-Z][A-Z0-9_]{2,80})[ \t]+([0-9A-Fa-f]{64})[ \t]+([0-9A-Fa-f]{32,128})[ \t]*$"
)
_LABEL = re.compile(
    r"^(CLIENT|SERVER)_(EARLY_|HANDSHAKE_)?TRAFFIC_SECRET(?:_(\d+))?$|^CLIENT_RANDOM$|"
    r"^(EXPORTER_SECRET|EARLY_EXPORTER_SECRET)$"
)


def parse_extended_keylog(data: bytes) -> dict:
    """Parse current/future traffic-secret labels while preserving label-local conflicts."""
    if not isinstance(data, bytes) or len(data) > MAX_KEYLOG:
        raise ValueError("key log exceeds 16 MiB cap")
    text = data.decode("ascii", "ignore")
    sessions, conflicts, conflicted = {}, [], set()
    for match in _EXT_KEYLOG.finditer(text):
        label, random_hex, secret_hex = match.groups()
        if not _LABEL.fullmatch(label):
            continue
        client_random, secret = bytes.fromhex(random_hex), bytes.fromhex(secret_hex)
        expected_lengths = (48,) if label == "CLIENT_RANDOM" else (32, 48)
        if len(secret) not in expected_lengths:
            continue
        slot = sessions.setdefault(client_random.hex(), {})
        if label in slot and slot[label] != secret.hex():
            key = (client_random.hex(), label)
            if key not in conflicted:
                conflicts.append({"client_random": key[0], "label": label})
                conflicted.add(key)
            slot.pop(label, None)
        elif (client_random.hex(), label) not in conflicted:
            slot[label] = secret.hex()
    return {"sessions": sessions, "conflicts": conflicts}


def keylog_secret(data: bytes, client_random: bytes | str, label: str) -> bytes | None:
    """Return one non-conflicting key-log secret, or ``None`` when it is absent/ambiguous."""
    if isinstance(client_random, bytes):
        random_hex = client_random.hex()
    elif isinstance(client_random, str) and re.fullmatch(r"[0-9a-fA-F]{64}", client_random):
        random_hex = client_random.lower()
    else:
        raise ValueError("client_random must be 32 bytes or 64 hexadecimal characters")
    if not isinstance(label, str) or not _LABEL.fullmatch(label):
        raise ValueError("unsupported key-log label")
    value = parse_extended_keylog(data)["sessions"].get(random_hex, {}).get(label)
    return bytes.fromhex(value) if value is not None else None


_SUITES = {
    0x1301: ("aesgcm", 16, "sha256"),
    0x1302: ("aesgcm", 32, "sha384"),
    0x1303: ("chacha", 32, "sha256"),
}


def tls13_update_secret(secret: bytes, hash_name: str = "sha256") -> bytes:
    if hash_name not in ("sha256", "sha384") or len(secret) != (32 if hash_name == "sha256" else 48):
        raise ValueError("traffic secret/hash length mismatch")
    return tls._hkdf_expand_label(secret, b"traffic upd", b"", len(secret), hash_name)


def quic_update_secret(secret: bytes, hash_name: str = "sha256", version: int = 1) -> bytes:
    """Derive the next RFC 9001/RFC 9369 1-RTT key-phase secret."""
    if hash_name not in ("sha256", "sha384") or len(secret) != (32 if hash_name == "sha256" else 48):
        raise ValueError("traffic secret/hash length mismatch")
    if version not in (1, 0x6B3343CF):
        raise ValueError("unsupported QUIC version")
    label = b"quicv2 ku" if version == 0x6B3343CF else b"quic ku"
    return tls._hkdf_expand_label(secret, label, b"", len(secret), hash_name)


def tls13_epochs(secret: bytes, suite: int, count: int) -> list[bytes]:
    if suite not in _SUITES or not isinstance(count, int) or not 1 <= count <= 64:
        raise ValueError("unsupported suite/epoch count")
    _kind, _key_len, hash_name = _SUITES[suite]
    expected = 32 if hash_name == "sha256" else 48
    if not isinstance(secret, bytes) or len(secret) != expected:
        raise ValueError("traffic secret has the wrong hash length")
    out = [secret]
    for _ in range(count - 1):
        out.append(tls13_update_secret(out[-1], hash_name))
    return out


def _traffic_keys(secret: bytes, suite: int, *, quic: bool = False, quic_version: int = 1):
    kind, key_len, hash_name = _SUITES[suite]
    iv_len = 12
    if quic and quic_version not in (1, 0x6B3343CF):
        raise ValueError("unsupported QUIC version")
    prefix = b"quicv2 " if quic and quic_version == 0x6B3343CF else b"quic " if quic else b""
    key_label = prefix + b"key"
    iv_label = prefix + b"iv"
    key = tls._hkdf_expand_label(secret, key_label, b"", key_len, hash_name)
    iv = tls._hkdf_expand_label(secret, iv_label, b"", iv_len, hash_name)
    return kind, hash_name, key, iv


def _nonce(iv: bytes, sequence: int) -> bytes:
    if not isinstance(sequence, int) or sequence < 0 or sequence >= 1 << (8 * len(iv)):
        raise ValueError("record/packet number exceeds nonce width")
    encoded = sequence.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, encoded))


def _aead_decrypt(kind: str, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if kind == "aesgcm":
        return tls._aes_gcm_decrypt(key, nonce, ciphertext, aad)
    return tls._chacha_poly_decrypt(key, nonce, ciphertext, aad)


def _tls13_inner(plaintext: bytes):
    index = len(plaintext) - 1
    while index >= 0 and plaintext[index] == 0:
        index -= 1
    if index < 0 or plaintext[index] not in (20, 21, 22, 23, 24):
        return None
    return plaintext[:index], plaintext[index], len(plaintext) - index - 1


def _consume_handshakes(pending: bytes, content: bytes):
    if len(pending) + len(content) > MAX_HANDSHAKE:
        raise ValueError("fragmented TLS handshake exceeds 16 MiB cap")
    handshakes, offset, key_update = pending + content, 0, False
    while offset + 4 <= len(handshakes):
        kind = handshakes[offset]
        length = int.from_bytes(handshakes[offset + 1:offset + 4], "big")
        offset += 4
        if length > len(handshakes) - offset:
            offset -= 4
            break
        body = handshakes[offset:offset + length]
        if kind == 24:
            if length != 1 or body[0] not in (0, 1) or key_update:
                raise ValueError("invalid/duplicate TLS KeyUpdate message")
            key_update = True
        offset += length
    return handshakes[offset:], key_update


def _record_blobs(data) -> list[bytes]:
    if isinstance(data, (list, tuple)):
        if len(data) > MAX_RECORDS:
            raise ValueError("TLS record count exceeds cap")
        rows, total = [], 0
        for row in data:
            if not isinstance(row, (bytes, bytearray, memoryview)):
                raise ValueError("TLS record list contains a non-bytes value")
            blob = bytes(row)
            total += len(blob)
            if len(blob) > MAX_RECORD + 5 or total > MAX_INPUT:
                raise ValueError("TLS record list exceeds size cap")
            rows.append(blob)
    elif isinstance(data, bytes):
        if len(data) > MAX_INPUT:
            raise ValueError("TLS record stream exceeds size cap")
        rows, offset = [], 0
        while offset < len(data):
            if len(rows) >= MAX_RECORDS or offset + 5 > len(data):
                raise ValueError("TLS record stream is truncated/capped")
            length = int.from_bytes(data[offset + 3:offset + 5], "big")
            if length > MAX_RECORD or offset + 5 + length > len(data):
                raise ValueError("TLS record length is invalid")
            rows.append(data[offset:offset + 5 + length])
            offset += 5 + length
    else:
        raise ValueError("TLS records must be bytes or a record list")
    if len(rows) > MAX_RECORDS:
        raise ValueError("TLS record count exceeds cap")
    for row in rows:
        if len(row) < 5 or row[0] != 23 or row[1:3] != b"\x03\x03" or len(row) != 5 + int.from_bytes(row[3:5], "big"):
            raise ValueError("expected complete TLS 1.3 application-data records")
    return rows


def decrypt_tls13_records(records, secret: bytes, suite: int, *, search_updates: int = 0) -> dict:
    """AEAD-verify TLS 1.3 records, following encrypted KeyUpdate messages.

    ``search_updates`` (0..8) additionally handles a capture that begins after a KeyUpdate: on an
    invalid tag, successive derived epochs are tried with sequence zero.  A candidate is accepted
    only when its AEAD tag verifies and its TLSInnerPlaintext content type is valid.
    """
    if suite not in _SUITES or not isinstance(search_updates, int) or not 0 <= search_updates <= 8:
        raise ValueError("unsupported TLS suite/update search")
    rows = _record_blobs(records)
    current, epoch, sequence, output = secret, 0, 0, []
    _kind, _key_len, hash_name = _SUITES[suite]
    expected = 32 if hash_name == "sha256" else 48
    if not isinstance(current, bytes) or len(current) != expected:
        raise ValueError("traffic secret has the wrong length")
    total_plain, handshake_pending = 0, b""
    for record_index, record in enumerate(rows):
        attempts = []
        candidate_secret = current
        for jump in range(search_updates + 1):
            candidate_sequence = sequence if jump == 0 else 0
            kind, _hash, key, iv = _traffic_keys(candidate_secret, suite)
            try:
                plain = _aead_decrypt(kind, key, _nonce(iv, candidate_sequence), record[5:], record[:5])
            except Exception:
                plain = None
            inner = _tls13_inner(plain) if plain is not None else None
            if inner is not None:
                attempts.append((candidate_secret, epoch + jump, candidate_sequence, inner))
            candidate_secret = tls13_update_secret(candidate_secret, hash_name)
        if len(attempts) != 1:  # none: bad tag; >1 is cryptographically implausible but ambiguous -> refuse
            return {"verified": False, "complete": False, "records": output,
                    "error_at": record_index, "error": "no unique authenticated epoch"}
        current, epoch, sequence, inner = attempts[0]
        content, content_type, padding = inner
        total_plain += len(content)
        if total_plain > MAX_OUTPUT:
            raise ValueError("decrypted plaintext exceeds 64 MiB cap")
        output.append({"index": record_index, "epoch": epoch, "sequence": sequence,
                       "content_type": content_type, "padding": padding, "content": content})
        sequence += 1
        if content_type == 22:
            handshake_pending, key_update = _consume_handshakes(handshake_pending, content)
            if key_update:
                current = tls13_update_secret(current, hash_name)
                epoch += 1
                sequence = 0
    return {"verified": True, "complete": True, "suite": suite, "records": output,
            "final_epoch": epoch, "next_sequence": sequence,
            "pending_handshake_bytes": len(handshake_pending)}


def decrypt_tls13_keylog(records, keylog: bytes, client_random: bytes | str, label: str,
                         suite: int, *, search_updates: int = 0) -> dict:
    """Select a direction/epoch secret from a key log and decrypt TLS 1.3 records."""
    secret = keylog_secret(keylog, client_random, label)
    if secret is None:
        raise ValueError("key-log secret is absent or conflicting")
    return decrypt_tls13_records(records, secret, suite, search_updates=search_updates)


def _hp_mask(kind: str, hp_key: bytes, sample: bytes) -> bytes:
    if len(sample) < 16:
        raise ValueError("QUIC header-protection sample is truncated")
    if kind == "aesgcm":
        if HAVE_CRYPTO:
            enc = Cipher(algorithms.AES(hp_key), modes.ECB()).encryptor()
            return (enc.update(sample[:16]) + enc.finalize())[:5]
        return tls._PyAES(hp_key).encrypt_block(sample[:16])[:5]
    if not HAVE_CRYPTO:
        raise ValueError("ChaCha QUIC header protection needs cryptography")
    cipher = Cipher(algorithms.ChaCha20(hp_key, sample[:4] + sample[4:16]), mode=None).encryptor()
    return cipher.update(b"\x00" * 5)


def _decode_packet_number(truncated: int, bits: int, largest: int) -> int:
    expected = largest + 1
    window, half = 1 << bits, 1 << (bits - 1)
    candidate = (expected & ~(window - 1)) | truncated
    if candidate <= expected - half and candidate + window < 1 << 62:
        candidate += window
    elif candidate > expected + half and candidate >= window:
        candidate -= window
    return candidate


def _decrypt_quic_short_one(packet: bytes, secret: bytes, suite: int, dcid_length: int,
                            largest_packet_number: int, version: int = 1):
    pn_offset = 1 + dcid_length
    sample_offset = pn_offset + 4
    if len(packet) < sample_offset + 16 or packet[0] & 0x80 or not packet[0] & 0x40:
        return None
    kind, hash_name, key, iv = _traffic_keys(secret, suite, quic=True, quic_version=version)
    hp_len = 16 if kind == "aesgcm" and len(key) == 16 else 32
    hp_label = b"quicv2 hp" if version == 0x6B3343CF else b"quic hp"
    hp = tls._hkdf_expand_label(secret, hp_label, b"", hp_len, hash_name)
    try:
        mask = _hp_mask(kind, hp, packet[sample_offset:sample_offset + 16])
    except Exception:
        return None
    first = packet[0] ^ (mask[0] & 0x1F)
    if first & 0x18:  # reserved bits must be zero after successful header unprotection
        return None
    pn_length = (first & 0x03) + 1
    if pn_offset + pn_length > len(packet):
        return None
    pn_bytes = bytes(packet[pn_offset + index] ^ mask[index + 1] for index in range(pn_length))
    packet_number = _decode_packet_number(int.from_bytes(pn_bytes, "big"), pn_length * 8,
                                          largest_packet_number)
    header = bytes([first]) + packet[1:pn_offset] + pn_bytes
    try:
        plaintext = _aead_decrypt(kind, key, _nonce(iv, packet_number),
                                  packet[pn_offset + pn_length:], header)
    except Exception:
        return None
    return {"verified": True, "packet_number": packet_number, "pn_length": pn_length,
            "key_phase": (first >> 2) & 1, "spin": (first >> 5) & 1,
            "header": header, "plaintext": plaintext}


def decrypt_quic_short(packet: bytes, secret: bytes, suite: int, dcid_length: int, *,
                       largest_packet_number: int = -1, search_updates: int = 0,
                       version: int = 1) -> dict | None:
    """Remove QUIC v1/v2 short-header protection and authenticate one 1-RTT packet.

    ``search_updates`` tries up to eight RFC 9001 ``quic ku`` generations for a capture that begins
    after a key-phase transition.  Exactly one AEAD-valid generation must exist.
    """
    if suite not in _SUITES or version not in (1, 0x6B3343CF) or not isinstance(packet, bytes) or len(packet) > MAX_QUIC_PACKET:
        return None
    if not isinstance(dcid_length, int) or not 0 <= dcid_length <= 20:
        return None
    if not isinstance(search_updates, int) or not 0 <= search_updates <= 8:
        return None
    hash_name = _SUITES[suite][2]
    expected = 48 if hash_name == "sha384" else 32
    if not isinstance(secret, bytes) or len(secret) != expected:
        return None
    candidates, current = [], secret
    for epoch in range(search_updates + 1):
        result = _decrypt_quic_short_one(packet, current, suite, dcid_length,
                                         largest_packet_number, version)
        if result is not None:
            result["epoch"] = epoch
            result["version"] = version
            try:
                result["frames"] = parse_quic_frames(result["plaintext"])
            except ValueError:
                result["frames"] = None
            candidates.append(result)
        current = quic_update_secret(current, hash_name, version)
    return candidates[0] if len(candidates) == 1 else None


def decrypt_quic_short_keylog(packet: bytes, keylog: bytes, client_random: bytes | str, label: str,
                              suite: int, dcid_length: int, *, largest_packet_number: int = -1,
                              search_updates: int = 0, version: int = 1) -> dict | None:
    """Select one NSS secret and authenticate a QUIC v1/v2 1-RTT packet."""
    secret = keylog_secret(keylog, client_random, label)
    if secret is None:
        return None
    return decrypt_quic_short(packet, secret, suite, dcid_length,
                              largest_packet_number=largest_packet_number,
                              search_updates=search_updates, version=version)


def _quic_varint(data: bytes, offset: int):
    if offset >= len(data):
        return None
    length = 1 << (data[offset] >> 6)
    if offset + length > len(data):
        return None
    value = data[offset] & 0x3F
    for byte in data[offset + 1:offset + length]:
        value = (value << 8) | byte
    return value, offset + length


def parse_quic_frames(plaintext: bytes, *, max_frames: int = 100000) -> list[dict]:
    """Parse the RFC 9000/RFC 9221 frame grammar from authenticated plaintext.

    Unknown extension frames are declined because their length cannot be safely
    inferred without an extension-specific grammar.  This function is useful
    independently on plaintext carved by another QUIC implementation.
    """
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_OUTPUT:
        raise ValueError("QUIC plaintext exceeds cap")
    if not isinstance(max_frames, int) or not 1 <= max_frames <= 100000:
        raise ValueError("invalid QUIC frame cap")
    rows, offset = [], 0

    def varint():
        nonlocal offset
        got = _quic_varint(plaintext, offset)
        if got is None:
            raise ValueError("truncated QUIC frame varint")
        value, offset = got
        return value

    def blob(length):
        nonlocal offset
        if length > MAX_OUTPUT or offset + length > len(plaintext):
            raise ValueError("QUIC frame value overruns plaintext")
        value, offset = plaintext[offset:offset + length], offset + length
        return value

    while offset < len(plaintext):
        if len(rows) >= max_frames:
            raise ValueError("QUIC frame cap exceeded")
        frame_type = varint()
        row: dict = {"type": frame_type}
        if frame_type == 0:
            count = 1
            while offset < len(plaintext) and plaintext[offset] == 0:
                offset += 1; count += 1
            row.update(name="padding", count=count)
        elif frame_type == 1:
            row["name"] = "ping"
        elif frame_type in (2, 3):
            largest, delay, range_count, first_range = varint(), varint(), varint(), varint()
            if range_count > max_frames:
                raise ValueError("QUIC ACK range cap exceeded")
            ranges = []
            high = largest
            if first_range > high:
                raise ValueError("invalid QUIC ACK first range")
            ranges.append({"smallest": high - first_range, "largest": high})
            low = high - first_range
            for _ in range(range_count):
                gap, ack_range = varint(), varint()
                if gap + 2 > low:
                    raise ValueError("invalid QUIC ACK gap")
                high = low - gap - 2
                if ack_range > high:
                    raise ValueError("invalid QUIC ACK range")
                low = high - ack_range
                ranges.append({"smallest": low, "largest": high})
            row.update(name="ack_ecn" if frame_type == 3 else "ack", largest_acknowledged=largest,
                       acknowledgement_delay=delay, ranges=ranges)
            if frame_type == 3:
                row["ecn_counts"] = {"ect0": varint(), "ect1": varint(), "ce": varint()}
        elif frame_type == 4:
            row.update(name="reset_stream", stream_id=varint(), application_error_code=varint(),
                       final_size=varint())
        elif frame_type == 5:
            row.update(name="stop_sending", stream_id=varint(), application_error_code=varint())
        elif frame_type == 6:
            crypto_offset, length = varint(), varint()
            row.update(name="crypto", offset=crypto_offset, data=blob(length))
        elif frame_type == 7:
            row.update(name="new_token", token=blob(varint()))
        elif 0x08 <= frame_type <= 0x0F:
            stream_id = varint()
            stream_offset = varint() if frame_type & 4 else 0
            length = varint() if frame_type & 2 else len(plaintext) - offset
            row.update(name="stream", stream_id=stream_id, offset=stream_offset,
                       fin=bool(frame_type & 1), data=blob(length))
        elif frame_type == 0x10:
            row.update(name="max_data", maximum=varint())
        elif frame_type == 0x11:
            row.update(name="max_stream_data", stream_id=varint(), maximum=varint())
        elif frame_type in (0x12, 0x13):
            row.update(name="max_streams", direction="unidirectional" if frame_type & 1 else "bidirectional",
                       maximum=varint())
        elif frame_type == 0x14:
            row.update(name="data_blocked", limit=varint())
        elif frame_type == 0x15:
            row.update(name="stream_data_blocked", stream_id=varint(), limit=varint())
        elif frame_type in (0x16, 0x17):
            row.update(name="streams_blocked", direction="unidirectional" if frame_type & 1 else "bidirectional",
                       limit=varint())
        elif frame_type == 0x18:
            sequence, retire_prior, cid_len = varint(), varint(), varint()
            if not 1 <= cid_len <= 20:
                raise ValueError("invalid QUIC connection-id length")
            row.update(name="new_connection_id", sequence=sequence, retire_prior_to=retire_prior,
                       connection_id=blob(cid_len), stateless_reset_token=blob(16))
        elif frame_type == 0x19:
            row.update(name="retire_connection_id", sequence=varint())
        elif frame_type in (0x1A, 0x1B):
            row.update(name="path_challenge" if frame_type == 0x1A else "path_response", data=blob(8))
        elif frame_type in (0x1C, 0x1D):
            error_code = varint()
            triggering = varint() if frame_type == 0x1C else None
            reason = blob(varint())
            row.update(name="connection_close_transport" if frame_type == 0x1C else "connection_close_application",
                       error_code=error_code, frame_type=triggering,
                       reason=reason.decode("utf-8", "replace"))
        elif frame_type == 0x1E:
            row["name"] = "handshake_done"
        elif frame_type == 0x1F:  # RFC 9368
            row["name"] = "immediate_ack"
        elif frame_type in (0x30, 0x31):
            length = varint() if frame_type & 1 else len(plaintext) - offset
            row.update(name="datagram", data=blob(length))
        elif frame_type == 0xAF:  # RFC 9368 ACK_FREQUENCY
            sequence, tolerance, maximum_delay, reorder = varint(), varint(), varint(), varint()
            if tolerance == 0:
                raise ValueError("ACK_FREQUENCY packet tolerance must be nonzero")
            row.update(name="ack_frequency", sequence_number=sequence,
                       packet_tolerance=tolerance, maximum_ack_delay=maximum_delay,
                       reordering_threshold=reorder)
        else:
            raise ValueError(f"unsupported QUIC frame type 0x{frame_type:x}")
        rows.append(row)
    return rows


_QUIC_INITIAL_SALTS = {
    1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}
_QUIC_RETRY = {
    1: (bytes.fromhex("be0c690b9f66575a1d766b54e368c84e"),
        bytes.fromhex("461599d35d632bf2239825bb"), 3),
    0x6B3343CF: (bytes.fromhex("8fb4b01b56ac48e260fbcbcead7ccc92"),
                 bytes.fromhex("d86969bc2d7c6d9990efb04a"), 0),
}


def quic_initial_secrets(dcid: bytes, version: int = 1) -> dict[str, bytes]:
    """Derive RFC 9001/RFC 9369 client/server Initial secrets from a DCID."""
    if version not in _QUIC_INITIAL_SALTS or not isinstance(dcid, bytes) or not 1 <= len(dcid) <= 20:
        raise ValueError("unsupported QUIC version/DCID")
    initial = hmac.new(_QUIC_INITIAL_SALTS[version], dcid, hashlib.sha256).digest()
    return {"client": tls._hkdf_expand_label(initial, b"client in", b"", 32, "sha256"),
            "server": tls._hkdf_expand_label(initial, b"server in", b"", 32, "sha256")}


def verify_quic_retry(packet: bytes, original_dcid: bytes) -> dict | None:
    """Authenticate a complete QUIC v1/v2 Retry packet with its original DCID."""
    if not HAVE_CRYPTO or not isinstance(packet, bytes) or not 23 <= len(packet) <= MAX_QUIC_PACKET:
        return None
    if not isinstance(original_dcid, bytes) or not 0 <= len(original_dcid) <= 20:
        return None
    version = int.from_bytes(packet[1:5], "big")
    params = _QUIC_RETRY.get(version)
    if params is None or (packet[0] & 0xC0) != 0xC0 or ((packet[0] >> 4) & 3) != params[2]:
        return None
    at = 5
    dcid_length = packet[at]; at += 1
    if dcid_length > 20 or at + dcid_length + 1 > len(packet) - 16:
        return None
    dcid, at = packet[at:at + dcid_length], at + dcid_length
    scid_length = packet[at]; at += 1
    if scid_length > 20 or at + scid_length > len(packet) - 16:
        return None
    scid, at = packet[at:at + scid_length], at + scid_length
    token, tag = packet[at:-16], packet[-16:]
    pseudo = bytes([len(original_dcid)]) + original_dcid + packet[:-16]
    key, nonce, _type = params
    try:
        AESGCM(key).decrypt(nonce, tag, pseudo)
    except Exception:
        return None
    return {"verified": True, "version": version, "dcid": dcid, "scid": scid,
            "token": token, "integrity_tag": tag}


def decrypt_quic_long(packet: bytes, secret: bytes, suite: int, *,
                      largest_packet_number: int = -1) -> dict | None:
    """Authenticate a QUIC v1/v2 Initial/0-RTT/Handshake long-header packet.

    The caller supplies the corresponding direction/epoch secret (normally selected from an NSS
    key log for 0-RTT or Handshake).  Retry and Version Negotiation packets are intentionally
    rejected because they do not carry AEAD-protected packet payloads.
    """
    if suite not in _SUITES or not isinstance(packet, bytes) or not 7 <= len(packet) <= MAX_QUIC_PACKET:
        return None
    hash_name = _SUITES[suite][2]
    expected = 48 if hash_name == "sha384" else 32
    if not isinstance(secret, bytes) or len(secret) != expected:
        return None
    protected_first = packet[0]
    version = int.from_bytes(packet[1:5], "big")
    if not protected_first & 0x80 or not protected_first & 0x40 or version not in (1, 0x6B3343CF):
        return None
    wire_type = (protected_first >> 4) & 0x03
    type_maps = {1: ("initial", "zero_rtt", "handshake", "retry"),
                 0x6B3343CF: ("retry", "initial", "zero_rtt", "handshake")}
    packet_type = type_maps[version][wire_type]
    if packet_type == "retry":
        return None
    at = 5
    dcid_length = packet[at]
    at += 1
    if dcid_length > 20 or at + dcid_length + 1 > len(packet):
        return None
    dcid = packet[at:at + dcid_length]
    at += dcid_length
    scid_length = packet[at]
    at += 1
    if scid_length > 20 or at + scid_length > len(packet):
        return None
    scid = packet[at:at + scid_length]
    at += scid_length
    token = b""
    if packet_type == "initial":
        token_field = _quic_varint(packet, at)
        if token_field is None:
            return None
        token_length, at = token_field
        if token_length > MAX_QUIC_PACKET or at + token_length > len(packet):
            return None
        token = packet[at:at + token_length]
        at += token_length
    length_field = _quic_varint(packet, at)
    if length_field is None:
        return None
    protected_length, pn_offset = length_field
    packet_end = pn_offset + protected_length
    sample_offset = pn_offset + 4
    if protected_length < 17 or packet_end > len(packet) or sample_offset + 16 > packet_end:
        return None
    kind, _hash, key, iv = _traffic_keys(secret, suite, quic=True, quic_version=version)
    hp_len = 16 if kind == "aesgcm" and len(key) == 16 else 32
    hp_label = b"quicv2 hp" if version == 0x6B3343CF else b"quic hp"
    hp = tls._hkdf_expand_label(secret, hp_label, b"", hp_len, hash_name)
    try:
        mask = _hp_mask(kind, hp, packet[sample_offset:sample_offset + 16])
    except Exception:
        return None
    first = protected_first ^ (mask[0] & 0x0F)
    if first & 0x0C:
        return None
    pn_length = (first & 0x03) + 1
    if pn_offset + pn_length > packet_end:
        return None
    pn_bytes = bytes(packet[pn_offset + index] ^ mask[index + 1] for index in range(pn_length))
    packet_number = _decode_packet_number(int.from_bytes(pn_bytes, "big"), pn_length * 8,
                                          largest_packet_number)
    header = bytes([first]) + packet[1:pn_offset] + pn_bytes
    try:
        plaintext = _aead_decrypt(kind, key, _nonce(iv, packet_number),
                                  packet[pn_offset + pn_length:packet_end], header)
    except Exception:
        return None
    try:
        frames = parse_quic_frames(plaintext)
    except ValueError:
        frames = None
    return {"verified": True, "version": version,
            "packet_type": packet_type,
            "packet_number": packet_number, "pn_length": pn_length,
            "dcid": dcid, "scid": scid, "token": token,
            "header": header, "plaintext": plaintext, "frames": frames,
            "packet_length": packet_end}


# ---- unified auth artifacts ------------------------------------------------------------------------

def extract_auth_artifacts(capture: bytes) -> dict:
    if not isinstance(capture, bytes) or len(capture) > MAX_INPUT or not pcap_creds.is_capture(capture):
        raise ValueError("input is not a bounded pcap/pcapng")
    cap = network.read(capture, "capture", limit=2_000_000)
    hashes = pcap_creds.extract(capture)
    kerberos = net_auth.kerberos_messages(cap)
    smb_facts = net_auth.smb2_facts(cap)
    transfers = net_auth.smb_transfers(cap)
    safe_transfers, transfer_bytes = [], 0
    for item in (transfers or [])[:10000]:
        row = dict(item)
        blob = row.get("data")
        if isinstance(blob, bytes):
            if transfer_bytes + len(blob) <= MAX_OUTPUT:
                transfer_bytes += len(blob)
            else:
                row.pop("data", None)
                row["data_omitted"] = "aggregate carved-data cap reached"
        safe_transfers.append(row)
    return {
        "credential_material": [{**item, "renderings": [value for _name, value in pcap_creds.renderings(item)]}
                                for item in hashes[:10000]],
        "kerberos": kerberos[:10000],
        "smb": smb_facts,
        "smb_transfers": safe_transfers,
        "capture_complete": not cap.truncated and cap.damaged is None,
    }


# ---- bounded BER helpers ---------------------------------------------------------------------------

def _tlv(data: bytes, offset: int, end: int):
    if offset < 0 or offset + 2 > end:
        return None
    tag, at = data[offset], offset + 1
    first, at = data[at], at + 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or at + count > end:
            return None
        length = int.from_bytes(data[at:at + count], "big")
        at += count
    else:
        length = first
    if length > MAX_INPUT or at + length > end:
        return None
    return tag, at, at + length, at + length


def _children(data: bytes, start: int, end: int):
    rows, at = [], start
    while at < end and len(rows) < MAX_BER:
        row = _tlv(data, at, end)
        if row is None:
            break
        rows.append(row)
        at = row[3]
    return rows if at == end else []


def _ascii(data: bytes) -> str | None:
    if data and all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data):
        return data.decode("utf-8", "replace")
    return None


def _strings(data: bytes) -> list[str]:
    return list(dict.fromkeys(match.group().decode("ascii", "replace")
                              for match in re.finditer(rb"[\x20-\x7e]{4,512}", data)))[:MAX_STRINGS]


# ---- IEC-61850 GOOSE / MMS -------------------------------------------------------------------------

_GOOSE_FIELDS = {0: "gocb_ref", 1: "time_allowed_to_live", 2: "dataset", 3: "go_id",
                 4: "timestamp", 5: "state_number", 6: "sequence_number", 7: "simulation",
                 8: "conf_revision", 9: "needs_commissioning", 10: "entry_count", 11: "all_data"}
_GOOSE_DATA = {0x83: "boolean", 0x84: "bit_string", 0x85: "integer", 0x86: "unsigned",
               0x87: "float", 0x89: "octet_string", 0x8A: "visible_string",
               0x8C: "binary_time", 0x91: "utc_time", 0xA1: "array", 0xA2: "structure"}


def _goose_value(tag: int, raw: bytes):
    if tag in (0x80, 0x82, 0x83):
        return _ascii(raw) or raw.hex()
    if tag in (0x81, 0x85, 0x86, 0x88, 0x8A):
        return int.from_bytes(raw, "big") if raw else 0
    if tag in (0x87, 0x89):
        return bool(raw and raw[-1])
    if tag == 0x84 and len(raw) == 8:
        seconds = int.from_bytes(raw[:4], "big")
        fraction = int.from_bytes(raw[4:7], "big") / float(1 << 24)
        return {"unix_seconds": seconds, "fraction": fraction, "quality": raw[7]}
    return _ascii(raw) or raw.hex()


def _goose_data_value(tag: int, raw: bytes):
    """Decode an MMS Data choice carried by GOOSE ``allData``.

    The context tags overlap the outer GOOSE field numbers (notably 0x8a), so this intentionally
    stays separate from :func:`_goose_value`.
    """
    if tag == 0x83:
        return bool(raw and raw[-1])
    if tag in (0x85, 0x86):
        return int.from_bytes(raw, "big", signed=tag == 0x85) if raw else 0
    if tag == 0x87 and len(raw) in (5, 9):
        # IEC-61850 floating point carries an exponent-width octet before IEEE-754 bytes.
        try:
            return struct.unpack(">f" if len(raw) == 5 else ">d", raw[1:])[0]
        except struct.error:
            pass
    if tag == 0x8A:
        return raw.decode("utf-8", "replace")
    if tag in (0x89, 0x84, 0x8C, 0x91):
        return raw.hex()
    return _ascii(raw) or raw.hex()


def _goose_data_item(payload: bytes, tag: int, start: int, end: int, depth: int = 0):
    item = {"type": _GOOSE_DATA.get(tag, f"tag_0x{tag:02x}"), "tag": tag,
            "raw_length": end - start}
    if tag in (0xA1, 0xA2) and depth < 16:
        nested = _children(payload, start, end)
        if nested:
            item["children"] = [_goose_data_item(payload, child_tag, child_start, child_end, depth + 1)
                                for child_tag, child_start, child_end, _ in nested[:10000]]
            return item
    raw = payload[start:end]
    item["raw"] = raw
    item["value"] = _goose_data_value(tag, raw)
    return item


def parse_goose(payload: bytes) -> dict | None:
    """Parse an IEC-61850 GOOSE Ethernet payload beginning with APPID."""
    if not isinstance(payload, bytes) or len(payload) < 10 or len(payload) > MAX_INPUT:
        return None
    appid, declared, reserved1, reserved2 = struct.unpack_from(">HHHH", payload, 0)
    if declared < 10 or declared > len(payload):
        return None
    outer = _tlv(payload, 8, declared)
    if outer is None or outer[0] != 0x61 or outer[3] != declared:
        return None
    fields, all_data = {}, []
    for tag, start, end, _next in _children(payload, outer[1], outer[2]):
        number = tag & 0x1F
        name = _GOOSE_FIELDS.get(number, f"field_{number}")
        raw = payload[start:end]
        if number == 11:
            for data_tag, ds, de, _ in _children(payload, start, end):
                all_data.append(_goose_data_item(payload, data_tag, ds, de))
        else:
            fields[name] = _goose_value(tag, raw)
    return {"protocol": "iec61850-goose", "appid": appid, "declared_length": declared,
            "reserved": [reserved1, reserved2], "fields": fields, "all_data": all_data,
            "strings": _strings(payload[:declared])}


_MMS_PDUS = {0xA0: "confirmed_request", 0xA1: "confirmed_response", 0xA2: "confirmed_error",
             0xA3: "unconfirmed", 0xA4: "reject", 0xA8: "initiate_request",
             0xA9: "initiate_response", 0xAA: "initiate_error", 0xAB: "conclude_request",
             0xAC: "conclude_response", 0xAD: "conclude_error"}
_MMS_SERVICES = {
    0: "status", 1: "get_name_list", 2: "identify", 3: "rename", 4: "read", 5: "write",
    6: "get_variable_access_attributes", 7: "define_named_variable", 8: "define_scattered_access",
    9: "get_scattered_access_attributes", 10: "delete_variable_access",
    11: "define_named_variable_list", 12: "get_named_variable_list_attributes",
    13: "delete_named_variable_list", 14: "define_named_type", 15: "get_named_type_attributes",
    16: "delete_named_type", 17: "input", 18: "output", 19: "take_control",
    20: "relinquish_control", 21: "define_semaphore", 22: "delete_semaphore",
    23: "report_semaphore_status", 24: "report_pool_semaphore_status",
    25: "report_semaphore_entry_status", 26: "initiate_download_sequence",
    27: "download_segment", 28: "terminate_download_sequence",
    29: "initiate_upload_sequence", 30: "upload_segment",
}
_MMS_UNCONFIRMED_SERVICES = {0: "information_report", 1: "unsolicited_status",
                             2: "event_notification"}
_MMS_DATA_TYPES = {1: "array", 2: "structure", 3: "boolean", 4: "bit_string",
                   5: "integer", 6: "unsigned", 7: "floating_point", 9: "octet_string",
                   10: "visible_string", 11: "generalized_time", 12: "binary_time",
                   13: "bcd", 14: "boolean_array", 15: "object_identifier",
                   16: "mms_string", 17: "utc_time"}


def _ber_oid(raw: bytes) -> str | None:
    if not raw:
        return None
    values = [raw[0] // 40, raw[0] % 40]
    current = 0
    for byte in raw[1:]:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(current); current = 0
        if current.bit_length() > 128:
            return None
    return None if raw[-1] & 0x80 else ".".join(map(str, values))


def _ber_tree(data: bytes, offset: int, end: int, depth: int = 0,
              budget: list[int] | None = None) -> dict | None:
    """Bounded definite-length BER tree used for full MMS service evidence."""
    if budget is None:
        budget = [MAX_BER]
    if depth > 32 or budget[0] <= 0:
        return None
    row = _tlv(data, offset, end)
    if row is None:
        return None
    budget[0] -= 1
    tag, start, stop, next_offset = row
    node: dict = {"tag": tag, "class": ("universal", "application", "context", "private")[tag >> 6],
                  "number": tag & 0x1F, "constructed": bool(tag & 0x20),
                  "length": stop - start, "next_offset": next_offset}
    raw = data[start:stop]
    if node["constructed"]:
        children, at = [], start
        while at < stop and len(children) < MAX_BER:
            child = _ber_tree(data, at, stop, depth + 1, budget)
            if child is None or child["next_offset"] <= at:
                return None
            at = child.pop("next_offset")
            children.append(child)
        if at != stop:
            return None
        node["children"] = children
    elif tag == 0x01 and len(raw) == 1:
        node["value"] = bool(raw[0])
    elif tag in (0x02, 0x0A):
        node["value"] = int.from_bytes(raw, "big", signed=tag == 0x02) if raw else 0
    elif tag == 0x05 and not raw:
        node["value"] = None
    elif tag == 0x06:
        node["value"] = _ber_oid(raw) or raw.hex()
    elif tag in (0x0C, 0x12, 0x13, 0x16, 0x1A):
        node["value"] = raw.decode("utf-8", "replace")
    elif tag & 0xC0 == 0x80 and _ascii(raw) is not None:
        node["value"] = _ascii(raw)
    elif tag & 0xC0 == 0x80 and len(raw) <= 8:
        node["value"] = int.from_bytes(raw, "big", signed=False) if raw else 0
    else:
        node["raw"] = raw
    # Preserve context-specific wire bytes even when a display heuristic above
    # produced a value.  MMS Data choices reuse these tags and typed decoding
    # must not depend on whether an integer happens to consist of ASCII bytes.
    if tag & 0xC0 == 0x80 and not node["constructed"]:
        node["raw"] = raw
    return node


def _mms_tree_values(node: dict, output: list[dict], path: tuple[int, ...] = ()):
    current = path + (node.get("tag", -1),)
    if "value" in node and node.get("class") == "context":
        row = {"path": list(current), "tag": node["tag"], "value": node["value"],
               # A context tag has different meanings in different MMS service
               # schemas.  Never present this heuristic as a submit-ready fact.
               "schema_verified": False, "candidate_only": True}
        number, raw = node.get("number"), node.get("raw")
        if number in _MMS_DATA_TYPES:
            row["data_type_candidate"] = _MMS_DATA_TYPES[number]
            if isinstance(raw, bytes):
                if number == 3 and len(raw) == 1:
                    row["typed_value"] = bool(raw[0])
                elif number == 5 and raw:
                    row["typed_value"] = int.from_bytes(raw, "big", signed=True)
                elif number in (6, 13) and raw:
                    row["typed_value"] = int.from_bytes(raw, "big", signed=False)
                elif number in (10, 11, 16):
                    try:
                        row["typed_value"] = raw.decode("utf-8", "strict")
                    except UnicodeDecodeError:
                        row["typed_value_valid"] = False
                elif number == 15:
                    oid = _ber_oid(raw)
                    if oid is not None:
                        row["typed_value"] = oid
                elif number in (4, 7, 9, 12, 14, 17):
                    row["typed_value_hex"] = raw.hex()
        output.append(row)
    for child in node.get("children", []):
        _mms_tree_values(child, output, current)


def _strip_tpkt(payload: bytes):
    if len(payload) >= 7 and payload[:2] == b"\x03\x00":
        length = int.from_bytes(payload[2:4], "big")
        if length > len(payload) or length < 7:
            return None
        cotp_length = payload[4]
        offset = 5 + cotp_length
        if offset > length:
            return None
        return payload[offset:length]
    return payload


def parse_mms(payload: bytes) -> dict | None:
    if not isinstance(payload, bytes) or len(payload) < 2 or len(payload) > MAX_INPUT:
        return None
    body = _strip_tpkt(payload)
    if body is None:
        return None
    # ISO presentation/session wrappers may precede the MMS PDU.  Accept only a TLV that reaches
    # the end of the supplied body, keeping the search narrow and deterministic.
    top = None
    for offset in range(min(128, len(body))):
        row = _tlv(body, offset, len(body))
        if row and row[0] in _MMS_PDUS and row[3] == len(body):
            top = (offset, row)
            break
    if top is None:
        return None
    offset, row = top
    children = _children(body, row[1], row[2])
    invoke, service = None, None
    for tag, start, end, _ in children:
        raw = body[start:end]
        if tag == 0x02 and invoke is None:
            invoke = int.from_bytes(raw, "big", signed=False)
        elif tag & 0xC0 == 0x80 and service is None:
            number = tag & 0x1F
            names = _MMS_UNCONFIRMED_SERVICES if row[0] == 0xA3 else _MMS_SERVICES
            service = {"number": number, "name": names.get(number, f"service_{number}"),
                       "raw": raw}
    tree = _ber_tree(body, offset, len(body))
    if tree is None:
        return None
    tree.pop("next_offset", None)
    values: list[dict] = []
    _mms_tree_values(tree, values)
    strings = _strings(body[offset:])
    return {"protocol": "iec61850-mms", "pdu": _MMS_PDUS[row[0]], "pdu_tag": row[0],
            "invoke_id": invoke, "service": service, "wrapper_bytes": offset,
            "tree": tree, "data_values": values, "variable_identifiers": strings,
            "strings": strings}


# ---- OPC-UA Binary ---------------------------------------------------------------------------------

_UA_SERVICES = {422: "FindServersRequest", 425: "FindServersResponse", 428: "GetEndpointsRequest",
                431: "GetEndpointsResponse", 459: "CreateSessionRequest", 462: "CreateSessionResponse",
                465: "ActivateSessionRequest", 468: "ActivateSessionResponse", 471: "CloseSessionRequest",
                527: "BrowseRequest", 530: "BrowseResponse", 631: "ReadRequest", 634: "ReadResponse",
                673: "WriteRequest", 676: "WriteResponse", 712: "CallRequest", 715: "CallResponse",
                787: "CreateSubscriptionRequest", 790: "CreateSubscriptionResponse",
                826: "PublishRequest", 829: "PublishResponse"}


def _ua_blob(data: bytes, offset: int, *, text=False):
    if offset + 4 > len(data):
        return None
    length = int.from_bytes(data[offset:offset + 4], "little", signed=True)
    offset += 4
    if length == -1:
        return None, offset
    if length < 0 or length > MAX_INPUT or offset + length > len(data):
        return None
    raw = data[offset:offset + length]
    return (raw.decode("utf-8", "replace") if text else raw), offset + length


def _ua_nodeid(data: bytes, offset: int):
    if offset >= len(data):
        return None
    encoding, offset = data[offset], offset + 1
    kind = encoding & 0x0F
    namespace, identifier = 0, None
    if kind == 0 and offset + 1 <= len(data):
        identifier, offset = data[offset], offset + 1
    elif kind == 1 and offset + 3 <= len(data):
        namespace, identifier = data[offset], int.from_bytes(data[offset + 1:offset + 3], "little")
        offset += 3
    elif kind == 2 and offset + 6 <= len(data):
        namespace = int.from_bytes(data[offset:offset + 2], "little")
        identifier = int.from_bytes(data[offset + 2:offset + 6], "little")
        offset += 6
    elif kind == 3:
        if offset + 2 > len(data):
            return None
        namespace = int.from_bytes(data[offset:offset + 2], "little"); offset += 2
        got = _ua_blob(data, offset, text=True)
        if got is None:
            return None
        identifier, offset = got
    elif kind == 4 and offset + 18 <= len(data):
        namespace = int.from_bytes(data[offset:offset + 2], "little")
        identifier = data[offset + 2:offset + 18].hex(); offset += 18
    elif kind == 5:
        if offset + 2 > len(data):
            return None
        namespace = int.from_bytes(data[offset:offset + 2], "little"); offset += 2
        got = _ua_blob(data, offset)
        if got is None:
            return None
        value, offset = got
        identifier = None if value is None else value.hex()
    else:
        return None
    return {"encoding": kind, "namespace": namespace, "identifier": identifier,
            "service": _UA_SERVICES.get(identifier) if namespace == 0 and isinstance(identifier, int) else None}, offset


def parse_opcua(payload: bytes) -> list[dict]:
    """Parse complete OPC-UA TCP chunks from one reassembled byte stream."""
    if not isinstance(payload, bytes) or len(payload) > MAX_INPUT:
        return []
    output, offset = [], 0
    while offset + 8 <= len(payload) and len(output) < MAX_MESSAGES:
        kind_raw, chunk = payload[offset:offset + 3], chr(payload[offset + 3])
        if not all(65 <= byte <= 90 for byte in kind_raw) or chunk not in "FCA":
            return []
        size = int.from_bytes(payload[offset + 4:offset + 8], "little")
        if size < 8 or size > MAX_INPUT or offset + size > len(payload):
            return []
        message = payload[offset:offset + size]
        kind = kind_raw.decode("ascii")
        row = {"protocol": "opcua", "message_type": kind, "chunk_type": chunk, "size": size}
        if kind == "HEL" and size >= 28:
            values = struct.unpack_from("<IIIII", message, 8)
            endpoint = _ua_blob(message, 28, text=True)
            row.update(protocol_version=values[0], receive_buffer=values[1], send_buffer=values[2],
                       max_message_size=values[3], max_chunk_count=values[4],
                       endpoint_url=endpoint[0] if endpoint else None)
        elif kind == "ACK" and size >= 28:
            values = struct.unpack_from("<IIIII", message, 8)
            row.update(protocol_version=values[0], receive_buffer=values[1], send_buffer=values[2],
                       max_message_size=values[3], max_chunk_count=values[4])
        elif kind == "ERR" and size >= 12:
            reason = _ua_blob(message, 12, text=True)
            row.update(status_code=int.from_bytes(message[8:12], "little"),
                       reason=reason[0] if reason else None)
        elif kind in ("MSG", "CLO") and size >= 24:
            row.update(secure_channel_id=int.from_bytes(message[8:12], "little"),
                       security_token_id=int.from_bytes(message[12:16], "little"),
                       sequence_number=int.from_bytes(message[16:20], "little"),
                       request_id=int.from_bytes(message[20:24], "little"))
            node = _ua_nodeid(message, 24)
            row["service_nodeid"] = node[0] if node else None
        elif kind == "OPN" and size >= 12:
            row["secure_channel_id"] = int.from_bytes(message[8:12], "little")
            at = 12
            policy = _ua_blob(message, at, text=True)
            if policy is not None:
                row["security_policy_uri"], at = policy
                cert = _ua_blob(message, at)
                if cert is not None:
                    row["sender_certificate_length"] = len(cert[0] or b""); at = cert[1]
                    thumb = _ua_blob(message, at)
                    if thumb is not None:
                        row["receiver_thumbprint"] = None if thumb[0] is None else thumb[0].hex(); at = thumb[1]
                        if at + 8 <= len(message):
                            row["sequence_number"] = int.from_bytes(message[at:at + 4], "little")
                            row["request_id"] = int.from_bytes(message[at + 4:at + 8], "little")
                            node = _ua_nodeid(message, at + 8)
                            row["service_nodeid"] = node[0] if node else None
        row["strings"] = _strings(message)
        output.append(row)
        offset += size
    return output if offset == len(payload) else []


def decrypt_opcua_symmetric_chunk(chunk: bytes, encryption_key: bytes, iv: bytes,
                                  signing_key: bytes, *, hash_name: str = "sha256",
                                  signature_size: int | None = None) -> dict | None:
    """Decrypt and authenticate one OPC-UA MSG/CLO symmetric secure-channel chunk.

    Keys are explicit artifacts recovered from a challenge or derived by the
    caller for the selected SecurityPolicy.  The unencrypted 16-byte message +
    symmetric-security header is covered by the HMAC along with the decrypted
    sequence header and service body.  No plaintext is returned on a bad HMAC,
    padding byte, size, or NodeId.
    """
    if not HAVE_CRYPTO or not isinstance(chunk, bytes) or not 32 <= len(chunk) <= MAX_INPUT:
        return None
    if chunk[:3] not in (b"MSG", b"CLO") or chunk[3:4] not in (b"F", b"C"):
        return None
    declared = int.from_bytes(chunk[4:8], "little")
    if declared != len(chunk) or len(chunk[16:]) % 16:
        return None
    if not isinstance(encryption_key, bytes) or len(encryption_key) not in (16, 24, 32):
        return None
    if not isinstance(iv, bytes) or len(iv) != 16 or not isinstance(signing_key, bytes) or not signing_key:
        return None
    digests = {"sha1": hashlib.sha1, "sha256": hashlib.sha256,
               "sha384": hashlib.sha384, "sha512": hashlib.sha512}
    digest = digests.get(hash_name)
    if digest is None:
        return None
    signature_size = digest().digest_size if signature_size is None else signature_size
    if not isinstance(signature_size, int) or not 8 <= signature_size <= digest().digest_size:
        return None
    try:
        decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(chunk[16:]) + decryptor.finalize()
    except Exception:
        return None
    if not padded:
        return None
    # OPC UA signs MessageHeader | SecurityHeader | SequenceHeader | Body | Padding,
    # appends the signature, then encrypts SequenceHeader..Signature.  Padding is
    # therefore immediately *before* the signature, not at the ciphertext tail.
    if len(padded) < signature_size + 9:
        return None
    signed, signature = padded[:-signature_size], padded[-signature_size:]
    padding_size = signed[-1]
    padding_length = padding_size + 1
    if padding_length > len(signed) - 8 or signed[-padding_length:] != bytes([padding_size]) * padding_length:
        return None
    content = signed[:-padding_length]
    expected = hmac.new(signing_key, chunk[:16] + signed, digest).digest()[:signature_size]
    if not hmac.compare_digest(signature, expected):
        return None
    sequence_number, request_id = struct.unpack_from("<II", content)
    service = _ua_nodeid(content, 8)
    if service is None:
        return None
    return {"verified": True, "protocol": "opcua", "message_type": chunk[:3].decode(),
            "chunk_type": chr(chunk[3]), "secure_channel_id": int.from_bytes(chunk[8:12], "little"),
            "security_token_id": int.from_bytes(chunk[12:16], "little"),
            "sequence_number": sequence_number, "request_id": request_id,
            "service_nodeid": service[0], "service_body": content[service[1]:],
            "signature_size": signature_size, "padding_size": padding_size}


_UA_POLICY_PREFIX = "http://opcfoundation.org/UA/SecurityPolicy#"
_UA_ASYMMETRIC_POLICIES = {
    _UA_POLICY_PREFIX + "Basic128Rsa15": ("pkcs1v15", "sha1", "pkcs1v15"),
    _UA_POLICY_PREFIX + "Basic256": ("oaep-sha1", "sha1", "pkcs1v15"),
    _UA_POLICY_PREFIX + "Basic256Sha256": ("oaep-sha1", "sha256", "pkcs1v15"),
    _UA_POLICY_PREFIX + "Aes128_Sha256_RsaOaep": ("oaep-sha1", "sha256", "pkcs1v15"),
    _UA_POLICY_PREFIX + "Aes256_Sha256_RsaPss": ("oaep-sha256", "sha256", "pss"),
}


def _ua_rsa_private(value: bytes):
    if not isinstance(value, bytes) or not value or len(value) > 1 << 20:
        return None
    try:
        key = serialization.load_pem_private_key(value, password=None)
    except Exception:
        try:
            key = serialization.load_der_private_key(value, password=None)
        except Exception:
            return None
    return key if isinstance(key, rsa.RSAPrivateKey) and 1024 <= key.key_size <= 2048 else None


def _ua_rsa_public(value: bytes):
    if not isinstance(value, bytes) or not value or len(value) > 1 << 20:
        return None
    try:
        key = serialization.load_pem_public_key(value)
    except Exception:
        try:
            key = serialization.load_der_public_key(value)
        except Exception:
            try:
                key = x509.load_der_x509_certificate(value).public_key()
            except Exception:
                try:
                    key = x509.load_pem_x509_certificate(value).public_key()
                except Exception:
                    return None
    return key if isinstance(key, rsa.RSAPublicKey) and 1024 <= key.key_size <= 4096 else None


def _ua_opn_header(chunk: bytes):
    if not isinstance(chunk, bytes) or not 32 <= len(chunk) <= MAX_INPUT:
        return None
    if chunk[:3] != b"OPN" or chunk[3:4] not in (b"F", b"C"):
        return None
    if int.from_bytes(chunk[4:8], "little") != len(chunk):
        return None
    at = 12
    policy = _ua_blob(chunk, at, text=True)
    if policy is None or policy[0] not in _UA_ASYMMETRIC_POLICIES:
        return None
    policy_uri, at = policy
    certificate = _ua_blob(chunk, at)
    if certificate is None:
        return None
    sender_certificate, at = certificate
    thumbprint = _ua_blob(chunk, at)
    if thumbprint is None:
        return None
    receiver_thumbprint, at = thumbprint
    if at >= len(chunk):
        return None
    return {"policy_uri": policy_uri, "sender_certificate": sender_certificate,
            "receiver_thumbprint": receiver_thumbprint, "encrypted_offset": at}


def decrypt_opcua_asymmetric_opn(chunk: bytes, receiver_private_key: bytes, *,
                                 sender_public_key: bytes | None = None,
                                 receiver_certificate: bytes | None = None) -> dict | None:
    """RSA-decrypt and signature-verify one encrypted OPC-UA ``OPN`` chunk.

    The receiver private key and trusted sender public key/certificate are explicit
    challenge artifacts; an in-band certificate is never its own trust anchor.  Only allow-listed OPC UA
    SecurityPolicies are accepted.  Plaintext is returned only after every RSA
    block decrypts, OPC UA padding validates, the sender signature verifies, and
    the sequence/service headers parse.  RSA keys above 2048 bits are declined
    until the two-byte ExtraPaddingSize grammar is implemented.
    """
    if not HAVE_CRYPTO:
        return None
    header = _ua_opn_header(chunk)
    private = _ua_rsa_private(receiver_private_key) if isinstance(receiver_private_key, bytes) else None
    if header is None or private is None or not isinstance(sender_public_key, bytes):
        return None
    enc_name, hash_name, sig_name = _UA_ASYMMETRIC_POLICIES[header["policy_uri"]]
    digest = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256()}[hash_name]
    if enc_name == "pkcs1v15":
        encryption_padding = asym_padding.PKCS1v15()
    else:
        oaep_digest = hashes.SHA1() if enc_name == "oaep-sha1" else hashes.SHA256()
        encryption_padding = asym_padding.OAEP(mgf=asym_padding.MGF1(oaep_digest),
                                               algorithm=oaep_digest, label=None)
    ciphertext = chunk[header["encrypted_offset"]:]
    block_size = (private.key_size + 7) // 8
    if not ciphertext or len(ciphertext) % block_size:
        return None
    clear = bytearray()
    try:
        for at in range(0, len(ciphertext), block_size):
            clear.extend(private.decrypt(ciphertext[at:at + block_size], encryption_padding))
    except Exception:
        return None

    certificate = header["sender_certificate"]
    cert_public = _ua_rsa_public(certificate) if certificate else None
    explicit_public = _ua_rsa_public(sender_public_key)
    if explicit_public is None or (certificate and cert_public is None):
        return None
    if cert_public is not None and explicit_public is not None:
        if cert_public.public_numbers() != explicit_public.public_numbers():
            return None
    public = explicit_public
    if not isinstance(header["receiver_thumbprint"], bytes) or len(header["receiver_thumbprint"]) != 20:
        return None
    signature_size = (public.key_size + 7) // 8
    if len(clear) < signature_size + 9:
        return None
    signed, signature = bytes(clear[:-signature_size]), bytes(clear[-signature_size:])
    padding_size = signed[-1]
    padding_length = padding_size + 1
    if padding_length > len(signed) - 8 or signed[-padding_length:] != bytes([padding_size]) * padding_length:
        return None
    content = signed[:-padding_length]
    signed_wire = chunk[:header["encrypted_offset"]] + signed
    signature_padding = (asym_padding.PKCS1v15() if sig_name == "pkcs1v15" else
                         asym_padding.PSS(mgf=asym_padding.MGF1(digest), salt_length=digest.digest_size))
    try:
        public.verify(signature, signed_wire, signature_padding, digest)
    except (InvalidSignature, ValueError, TypeError):
        return None

    receiver_thumbprint_checked = False
    if receiver_certificate is not None:
        try:
            receiver_cert = x509.load_der_x509_certificate(receiver_certificate)
        except (ValueError, TypeError):
            return None
        if not isinstance(receiver_cert.public_key(), rsa.RSAPublicKey):
            return None
        if receiver_cert.public_key().public_numbers() != private.public_key().public_numbers():
            return None
        expected_thumbprint = hashlib.sha1(receiver_certificate).digest()
        if header["receiver_thumbprint"] != expected_thumbprint:
            return None
        receiver_thumbprint_checked = True
    sequence_number, request_id = struct.unpack_from("<II", content)
    service = _ua_nodeid(content, 8)
    if service is None:
        return None
    return {"verified": True, "signature_verified": True,
            "receiver_thumbprint_checked": receiver_thumbprint_checked,
            "protocol": "opcua", "message_type": "OPN", "chunk_type": chr(chunk[3]),
            "secure_channel_id": int.from_bytes(chunk[8:12], "little"),
            "security_policy_uri": header["policy_uri"], "sequence_number": sequence_number,
            "request_id": request_id, "service_nodeid": service[0],
            "service_body": content[service[1]:], "signature_size": signature_size,
            "padding_size": padding_size, "rsa_encryption": enc_name,
            "rsa_signature": f"{sig_name}-{hash_name}"}


# ---- Profinet RT / DCP -----------------------------------------------------------------------------

_DCP_SERVICE = {3: "Get", 4: "Set", 5: "Identify", 6: "Hello"}
_DCP_TYPE = {0: "request", 1: "response-success", 5: "response-unsupported"}
_DCP_OPTION = {(1, 1): "ip-mac", (1, 2): "ip-parameter", (1, 3): "full-ip-suite",
               (2, 1): "manufacturer", (2, 2): "name-of-station", (2, 3): "device-id",
               (2, 4): "device-role", (2, 5): "device-options", (2, 6): "alias-name",
               (2, 7): "device-instance", (5, 1): "start-transaction", (5, 2): "end-transaction",
               (5, 3): "signal", (5, 4): "response"}


def _ipv4(raw: bytes) -> str:
    return ".".join(str(byte) for byte in raw)


def parse_profinet(payload: bytes) -> dict | None:
    """Parse a Profinet frame payload beginning at FrameID (EtherType removed)."""
    if not isinstance(payload, bytes) or len(payload) < 2 or len(payload) > MAX_INPUT:
        return None
    frame_id = int.from_bytes(payload[:2], "big")
    result = {"protocol": "profinet", "frame_id": frame_id}
    if frame_id in (0xFEFC, 0xFEFD, 0xFEFE, 0xFEFF):
        if len(payload) < 12:
            return None
        service_id, service_type = payload[2], payload[3]
        xid = int.from_bytes(payload[4:8], "big")
        response_delay = int.from_bytes(payload[8:10], "big")
        data_length = int.from_bytes(payload[10:12], "big")
        if 12 + data_length > len(payload):
            return None
        blocks, at, end = [], 12, 12 + data_length
        while at + 4 <= end and len(blocks) < 4096:
            option, suboption = payload[at], payload[at + 1]
            length = int.from_bytes(payload[at + 2:at + 4], "big")
            at += 4
            if length > end - at:
                return None
            raw = payload[at:at + length]
            at += length + (length & 1)
            block = {"option": option, "suboption": suboption,
                     "name": _DCP_OPTION.get((option, suboption), "unknown"), "raw": raw}
            content = raw[2:] if len(raw) >= 2 else b""  # first two bytes are block-info for responses/set
            block["block_info"] = int.from_bytes(raw[:2], "big") if len(raw) >= 2 else None
            if (option, suboption) == (1, 2) and len(content) >= 12:
                block.update(ip=_ipv4(content[:4]), subnet=_ipv4(content[4:8]), gateway=_ipv4(content[8:12]))
            elif (option, suboption) == (2, 2):
                block["station_name"] = _ascii(content) or _ascii(raw)
            elif (option, suboption) == (2, 1):
                block["manufacturer"] = _ascii(content) or _ascii(raw)
            elif (option, suboption) == (2, 3) and len(content) >= 4:
                block.update(vendor_id=int.from_bytes(content[:2], "big"),
                             device_id=int.from_bytes(content[2:4], "big"))
            blocks.append(block)
        if at != end and not (at == end + 1 and data_length & 1):
            return None
        result["dcp"] = {"service_id": service_id, "service": _DCP_SERVICE.get(service_id, "unknown"),
                         "service_type": service_type, "type": _DCP_TYPE.get(service_type, "unknown"),
                         "xid": xid, "response_delay": response_delay,
                         "data_length": data_length, "blocks": blocks}
    else:
        if len(payload) < 6:
            return None
        result["rt"] = {"cyclic_data": payload[2:-4],
                        "cycle_counter": int.from_bytes(payload[-4:-2], "big"),
                        "data_status": payload[-2], "transfer_status": payload[-1]}
    result["strings"] = _strings(payload)
    return result


# ---- Profinet IO CM over connectionless DCE/RPC -----------------------------------------------

_RPC_PTYPE = {0: "request", 1: "ping", 2: "response", 3: "fault", 4: "working",
              5: "nocall", 6: "reject", 7: "ack", 8: "cl_cancel", 9: "fack",
              10: "cancel_ack"}
_PNIO_OPNUM = {0: "Connect", 1: "Release", 2: "Read", 3: "Write", 4: "Control",
               5: "ReadImplicit"}
_PNIO_INTERFACES = {
    "dea00000-6c97-11d1-8271-00a02442df7d": "PNIO",
    "dea00001-6c97-11d1-8271-00a02442df7d": "PNIO-Device",
    "dea00002-6c97-11d1-8271-00a02442df7d": "PNIO-Controller",
    "dea00003-6c97-11d1-8271-00a02442df7d": "PNIO-Supervisor",
}
_PNIO_BLOCK = {
    0x0101: "ARBlockReq", 0x0102: "IOCRBlockReq", 0x0103: "AlarmCRBlockReq",
    0x0104: "ExpectedSubmoduleBlockReq", 0x0105: "PrmServerBlockReq",
    0x0106: "MCRBlockReq", 0x0107: "IRInfoBlockReq", 0x0108: "SRInfoBlockReq",
    0x0110: "ARVendorBlockReq", 0x8101: "ARBlockRes", 0x8102: "IOCRBlockRes",
    0x8103: "AlarmCRBlockRes", 0x8008: "IODReadResHeader", 0x0008: "IODReadReqHeader",
    0x8009: "IODWriteResHeader", 0x0009: "IODWriteReqHeader",
    0x0112: "ControlBlockConnect", 0x8112: "ControlBlockConnectRes",
}


def _uuid_le(raw: bytes) -> str:
    try:
        return str(uuid.UUID(bytes_le=raw))
    except (ValueError, AttributeError):
        return raw.hex()


def _pnio_blocks(stub: bytes) -> tuple[int, list[dict]] | None:
    """Find a bounded exact chain of PNIO blocks after an NDR operation header."""
    best = None
    for start in range(min(256, len(stub))):
        rows, offset = [], start
        while offset + 6 <= len(stub) and len(rows) < MAX_MESSAGES:
            block_type, block_length = struct.unpack_from(">HH", stub, offset)
            total = 4 + block_length
            if block_length < 2 or total > MAX_INPUT or offset + total > len(stub):
                break
            high, low = stub[offset + 4], stub[offset + 5]
            if high > 2 or (not rows and block_type not in _PNIO_BLOCK):
                break
            body = stub[offset + 6:offset + total]
            row = {"type": block_type, "name": _PNIO_BLOCK.get(block_type, f"Block_0x{block_type:04x}"),
                   "length": block_length, "version_high": high, "version_low": low,
                   "body": body}
            if block_type in (0x0101, 0x8101) and len(body) >= 18:
                row["ar_type"] = int.from_bytes(body[:2], "big")
                row["ar_uuid"] = _uuid_le(body[2:18])
                if block_type == 0x0101 and len(body) >= 50:
                    row.update(session_key=int.from_bytes(body[18:20], "big"),
                               initiator_mac=":".join(f"{byte:02x}" for byte in body[20:26]),
                               initiator_object_uuid=_uuid_le(body[26:42]),
                               ar_properties=int.from_bytes(body[42:46], "big"),
                               activity_timeout_factor=int.from_bytes(body[46:48], "big"),
                               initiator_udp_rt_port=int.from_bytes(body[48:50], "big"))
                    if len(body) >= 52:
                        station_length = int.from_bytes(body[50:52], "big")
                        if station_length <= 240 and 52 + station_length <= len(body):
                            row["initiator_station_name"] = body[52:52 + station_length].decode("utf-8", "replace")
            elif block_type in (0x0102, 0x8102) and len(body) >= 16:
                row.update(iocr_type=int.from_bytes(body[:2], "big"),
                           iocr_reference=int.from_bytes(body[2:4], "big"),
                           ethernet_type=int.from_bytes(body[4:6], "big"),
                           iocr_properties=int.from_bytes(body[6:10], "big"),
                           data_length=int.from_bytes(body[10:12], "big"),
                           frame_id=int.from_bytes(body[12:14], "big"),
                           send_clock_factor=int.from_bytes(body[14:16], "big"))
            elif block_type in (0x0008, 0x8008, 0x0009, 0x8009) and len(body) >= 34:
                # IOD Read/Write request/response headers place a 16-byte ARUUID
                # between SequenceNumber and API.  The old focused parser skipped
                # it and consequently emitted wrong API/slot/index values.
                row.update(sequence_number=int.from_bytes(body[:2], "big"),
                           ar_uuid=_uuid_le(body[2:18]),
                           api=int.from_bytes(body[18:22], "big"),
                           slot=int.from_bytes(body[22:24], "big"),
                           subslot=int.from_bytes(body[24:26], "big"),
                           index=int.from_bytes(body[28:30], "big"),
                           record_data_length=int.from_bytes(body[30:34], "big"))
                declared_data = row["record_data_length"]
                if declared_data <= len(body) - 34:
                    row["record_data"] = body[34:34 + declared_data]
            row["strings"] = _strings(body)
            rows.append(row)
            offset += total
            # NDR aligns constructed values to four bytes.  Only consume zero
            # alignment so payload bytes cannot be silently discarded.
            while offset < len(stub) and (offset - start) % 4 and stub[offset] == 0:
                offset += 1
        if rows:
            consumed = offset - start
            candidate = (consumed, -start, start, rows)
            if best is None or candidate[:2] > best[:2]:
                best = candidate
    return (best[2], best[3]) if best else None


def parse_pnio_rpc(payload: bytes) -> dict | None:
    """Parse one Profinet PNIO-CM connectionless DCE/RPC PDU and its blocks."""
    if not isinstance(payload, bytes) or not 80 <= len(payload) <= MAX_INPUT or payload[0] != 4:
        return None
    ptype = payload[1]
    if ptype not in _RPC_PTYPE:
        return None
    drep = payload[4:7]
    little = bool(drep[0] & 0x10)
    order = "little" if little else "big"
    u16 = lambda at: int.from_bytes(payload[at:at + 2], order)
    u32 = lambda at: int.from_bytes(payload[at:at + 4], order)
    stub_length = u16(74)
    if stub_length > MAX_INPUT or 80 + stub_length > len(payload):
        return None
    stub = payload[80:80 + stub_length]
    blocks = _pnio_blocks(stub)
    interface_uuid = _uuid_le(payload[24:40])
    result = {"protocol": "profinet-pnio-rpc", "rpc_version": payload[0],
              "packet_type": _RPC_PTYPE[ptype], "flags": int.from_bytes(payload[2:4], "big"),
              "data_representation": drep.hex(), "serial": (payload[7] << 8) | payload[79],
              "object_uuid": _uuid_le(payload[8:24]), "interface_uuid": interface_uuid,
              "interface_name": _PNIO_INTERFACES.get(interface_uuid),
              "activity_uuid": _uuid_le(payload[40:56]), "server_boot": u32(56),
              "interface_version": u32(60), "sequence": u32(64), "opnum": u16(68),
              "operation": _PNIO_OPNUM.get(u16(68), f"opnum_{u16(68)}"),
              "fragment_number": u16(76), "authentication_protocol": payload[78],
              "interface_hint": u16(70), "activity_hint": u16(72),
              "stub_length": stub_length, "stub": stub, "strings": _strings(stub)}
    if blocks is not None:
        result["block_offset"], result["blocks"] = blocks
        prefix = stub[:result["block_offset"]]
        result["ndr_prefix"] = {"length": len(prefix),
                                "aligned": len(prefix) % 4 == 0,
                                "u32": [int.from_bytes(prefix[i:i + 4], order)
                                        for i in range(0, len(prefix) - 3, 4)]}
    else:
        result["block_offset"], result["blocks"] = None, []
    return result


# ---- capture orchestration + covert classifier -----------------------------------------------------

def _ethernet_payload(frame: bytes):
    if len(frame) < 14:
        return None
    at, ethertype = 14, int.from_bytes(frame[12:14], "big")
    while ethertype in (0x8100, 0x88A8, 0x9100) and at + 4 <= len(frame):
        ethertype = int.from_bytes(frame[at + 2:at + 4], "big")
        at += 4
    return ethertype, frame[at:]


def analyze_ics_capture(capture: bytes) -> dict:
    if not isinstance(capture, bytes) or len(capture) > MAX_INPUT or not pcap_creds.is_capture(capture):
        raise ValueError("input is not a bounded capture")
    goose, profinet, mms, opcua = [], [], [], []
    for linktype, frame in pcap_creds.read_packets(capture):
        if linktype != 1:
            continue
        decoded = _ethernet_payload(frame)
        if decoded is None:
            continue
        ethertype, payload = decoded
        if ethertype == 0x88B8:
            row = parse_goose(payload)
            if row: goose.append(row)
        elif ethertype == 0x8892:
            row = parse_profinet(payload)
            if row: profinet.append(row)
        if len(goose) + len(profinet) >= MAX_MESSAGES:
            break
    cap = network.read(capture, "capture", limit=2_000_000)
    for connection in cap.conns():
        ports = {connection.cport, connection.sport}
        for stream in (connection.c, connection.s):
            if stream is None or not stream.data:
                continue
            if 102 in ports:
                data, at = stream.data, 0
                while at + 4 <= len(data) and len(mms) < MAX_MESSAGES:
                    if data[at:at + 2] != b"\x03\x00":
                        break
                    length = int.from_bytes(data[at + 2:at + 4], "big")
                    if length < 7 or at + length > len(data): break
                    row = parse_mms(data[at:at + length])
                    if row: mms.append(row)
                    at += length
            if 4840 in ports:
                opcua.extend(parse_opcua(stream.data)[:MAX_MESSAGES - len(opcua)])
    return {"goose": goose, "mms": mms, "opcua": opcua, "profinet": profinet}


def classify_covert_channel(source) -> dict:
    if isinstance(source, bytes) and len(source) > MAX_INPUT:
        raise ValueError("capture exceeds size cap")
    if isinstance(source, (list, tuple)) and len(source) > 400000:
        raise ValueError("packet list exceeds count cap")
    scanned = covert.scan(source)
    candidates = []
    for channel, value in scanned.items():
        if channel.startswith("_"):
            continue
        rows = value if isinstance(value, list) else [value]
        for row in rows:
            ranked = list(row.get("ranked") or [])
            best = ranked[0] if ranked else ""
            has_flag = bool(flagfmt.TEXT.search(str(best)))
            raw_only = not ranked or (len(ranked) == 1 and ranked[0] == row.get("blob_hex"))
            score = 100 if has_flag else 78 if ranked and not raw_only else 25
            count = row.get("count") or row.get("gaps") or row.get("names") or row.get("answers") or 0
            if isinstance(count, int) and count >= 8:
                score = min(100, score + 8)
            candidates.append({"channel": channel, "arrangement": row.get("arrangement"),
                               "score": score, "candidate": best, "ranked": ranked[:12],
                               "evidence_count": count, "blob_hex": row.get("blob_hex")})
    candidates.sort(key=lambda item: (-item["score"], item["channel"], str(item["arrangement"])))
    return {"classification": candidates[0]["channel"] if candidates and candidates[0]["score"] >= 50 else None,
            "candidates": candidates[:100], "errors": scanned.get("_errors", {})}


# ---- guarded CLI -----------------------------------------------------------------------------------

def _read(path: str, limit: int = MAX_INPUT) -> bytes:
    with Path(path).open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input exceeds size cap")
    return data


def _json_default(value):
    if isinstance(value, bytes):
        return {"hex": value.hex(), "text": value.decode("utf-8", "replace")}
    raise TypeError


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="network_ics_depth.py")
    sub = parser.add_subparsers(dest="operation", required=True)
    for name in ("keylog", "auth", "ics", "covert", "goose", "mms", "opcua", "profinet",
                 "pnio-rpc", "quic-frames"):
        command = sub.add_parser(name)
        command.add_argument("input")
        command.add_argument("--json", action="store_true")
    tls_cmd = sub.add_parser("tls13")
    tls_cmd.add_argument("records")
    tls_cmd.add_argument("secret")
    tls_cmd.add_argument("--suite", type=lambda value: int(value, 0), default=0x1301)
    tls_cmd.add_argument("--search-updates", type=int, default=0)
    tls_cmd.add_argument("--json", action="store_true")
    quic = sub.add_parser("quic")
    quic.add_argument("packet")
    quic.add_argument("secret")
    quic.add_argument("--suite", type=lambda value: int(value, 0), default=0x1301)
    quic.add_argument("--dcid-length", type=int, required=True)
    quic.add_argument("--largest-pn", type=int, default=-1)
    quic.add_argument("--search-updates", type=int, default=0)
    quic.add_argument("--version", type=lambda value: int(value, 0), default=1)
    quic.add_argument("--json", action="store_true")
    quic_long = sub.add_parser("quic-long")
    quic_long.add_argument("packet")
    quic_long.add_argument("secret")
    quic_long.add_argument("--suite", type=lambda value: int(value, 0), default=0x1301)
    quic_long.add_argument("--largest-pn", type=int, default=-1)
    quic_long.add_argument("--json", action="store_true")
    retry = sub.add_parser("quic-retry")
    retry.add_argument("packet")
    retry.add_argument("original_dcid", help="original destination connection ID in hex")
    retry.add_argument("--json", action="store_true")
    ua_secure = sub.add_parser("opcua-secure")
    ua_secure.add_argument("chunk")
    ua_secure.add_argument("encryption_key")
    ua_secure.add_argument("iv")
    ua_secure.add_argument("signing_key")
    ua_secure.add_argument("--hash", choices=("sha1", "sha256", "sha384", "sha512"), default="sha256")
    ua_secure.add_argument("--signature-size", type=int)
    ua_secure.add_argument("--json", action="store_true")
    ua_opn = sub.add_parser("opcua-opn")
    ua_opn.add_argument("chunk")
    ua_opn.add_argument("receiver_private_key")
    ua_opn.add_argument("--sender-public-key", required=True,
                        help="trusted sender public key or certificate (PEM/DER)")
    ua_opn.add_argument("--receiver-certificate")
    ua_opn.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.operation == "keylog":
            result = parse_extended_keylog(_read(args.input, MAX_KEYLOG))
            if not result["sessions"]:
                raise ValueError("input contains no valid key-log entries")
        elif args.operation == "auth":
            result = extract_auth_artifacts(_read(args.input))
        elif args.operation == "ics":
            result = analyze_ics_capture(_read(args.input))
        elif args.operation == "covert":
            raw = _read(args.input)
            if not pcap_creds.is_capture(raw):
                raise ValueError("covert input is not a pcap/pcapng capture")
            result = classify_covert_channel(raw)
        elif args.operation == "goose":
            result = parse_goose(_read(args.input))
        elif args.operation == "mms":
            result = parse_mms(_read(args.input))
        elif args.operation == "opcua":
            messages = parse_opcua(_read(args.input))
            result = {"messages": messages} if messages else None
        elif args.operation == "profinet":
            result = parse_profinet(_read(args.input))
        elif args.operation == "pnio-rpc":
            result = parse_pnio_rpc(_read(args.input))
        elif args.operation == "quic-frames":
            result = {"frames": parse_quic_frames(_read(args.input, MAX_OUTPUT))}
        elif args.operation == "tls13":
            secret = bytes.fromhex(args.secret)
            result = decrypt_tls13_records(_read(args.records), secret, args.suite,
                                           search_updates=args.search_updates)
        elif args.operation == "quic":
            secret = bytes.fromhex(args.secret)
            result = decrypt_quic_short(_read(args.packet, MAX_QUIC_PACKET), secret, args.suite,
                                        args.dcid_length, largest_packet_number=args.largest_pn,
                                        search_updates=args.search_updates, version=args.version)
        elif args.operation == "quic-long":
            secret = bytes.fromhex(args.secret)
            result = decrypt_quic_long(_read(args.packet, MAX_QUIC_PACKET), secret, args.suite,
                                       largest_packet_number=args.largest_pn)
        elif args.operation == "quic-retry":
            result = verify_quic_retry(_read(args.packet, MAX_QUIC_PACKET),
                                       bytes.fromhex(args.original_dcid))
        elif args.operation == "opcua-secure":
            result = decrypt_opcua_symmetric_chunk(
                _read(args.chunk), bytes.fromhex(args.encryption_key), bytes.fromhex(args.iv),
                bytes.fromhex(args.signing_key), hash_name=args.hash,
                signature_size=args.signature_size,
            )
        else:
            result = decrypt_opcua_asymmetric_opn(
                _read(args.chunk), _read(args.receiver_private_key, 1 << 20),
                sender_public_key=(_read(args.sender_public_key, 1 << 20)
                                   if args.sender_public_key else None),
                receiver_certificate=(_read(args.receiver_certificate, 1 << 20)
                                      if args.receiver_certificate else None),
            )
        if result is None:
            raise ValueError("input did not validate as the selected protocol")
        print(json.dumps(result, sort_keys=True, default=_json_default))
        return 0
    except Exception as exc:  # malformed captures must never escape the guarded CLI as a traceback
        print(f"network_ics_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
