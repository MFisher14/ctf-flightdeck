"""Independent vector and fail-closed tests for sec_gridsec_goose.

The GOOSE frame is the complete libiec61850 issue-603 example.  SV and routed
session records are assembled here directly from their published wire layouts.
IEC 62351-6 CRC/MAC construction is deliberately independent of the engine:
this file has its own bitwise CRC and uses ``cryptography`` while the engine
uses its own code and PyCryptodome for GMAC.
"""
from __future__ import annotations

import argparse
import random
import struct

import pytest
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import sec_gridsec_goose as grid


# Published complete frame from mz-automation/libiec61850 issue #603.
GOOSE = bytes.fromhex(
    "010ccd01000100112233445588b8"
    "3000006100000000"
    "615780144945444c44302f4c4c4e3024474f246763623031"
    "810207d0"
    "82134945444c44302f4c4c4e302444532464733031"
    "83056763623031"
    "84086a5b8f500000000a"
    "8501018601008701008801078901008a0101ab03830101"
)

# Hand-built IEC 61850-9-2 ASDU following the published BER field layout.
SV = bytes.fromhex(
    "010ccd04000100112233445588ba"
    "4000002f00000000"
    "6025800101a220301e80054d5530303182021234830400000001"
    "8501028708000003e800000000"
)

IV16 = bytes(range(16))
HMAC_KEY = bytes(range(32))
AES_KEY = bytes(range(16))


def crc16_iso_hdlc_reference(data: bytes) -> int:
    """Straight bit-loop CRC-16/ISO-HDLC reference, independent of the engine."""
    value = 0xFFFF
    for octet in data:
        value ^= octet
        for _ in range(8):
            value = (value >> 1) ^ 0x8408 if value & 1 else value >> 1
    return value ^ 0xFFFF


def tlv(tag: int, value: bytes) -> bytes:
    assert len(value) < 128
    return bytes((tag, len(value))) + value


def auth_value(*, iv: bytes | None = IV16) -> bytes:
    content = b"".join(
        (
            tlv(0x80, b"\x01"),       # extension version
            tlv(0x81, b"\x01"),       # timeOfCurrentKey
            tlv(0x82, b"\x00"),       # timeToNextKey
            tlv(0x83, iv) if iv is not None else b"",
            tlv(0x84, b"\x07"),       # keyID
        )
    )
    return tlv(0xA4, content)


def crypto_hmac_sha256(key: bytes, data: bytes, length: int) -> bytes:
    oracle = crypto_hmac.HMAC(key, hashes.SHA256())
    oracle.update(data)
    return oracle.finalize()[:length]


def secured_frame(
    frame: bytes,
    *,
    algorithm: str,
    key: bytes,
    iv: bytes | None = IV16,
    tag_length: int = 16,
) -> tuple[bytes, bytes, bytes, int]:
    """Manually append IEC 62351-6 A0/A4/85 and return frame/domain/tag/CRC."""
    assert frame[12:14] in (b"\x88\xb8", b"\x88\xba")
    ethertype = frame[12:14]
    app = bytearray(frame[14:])
    declared = int.from_bytes(app[2:4], "big")
    assert declared == len(app)

    a4 = auth_value(iv=iv)
    extension_length = 2 + len(a4) + 2 + tag_length
    assert extension_length < 128
    extension_prefix = bytes((0xA0, extension_length - 2)) + a4

    app[4:6] = extension_length.to_bytes(2, "big")
    crc = crc16_iso_hdlc_reference(ethertype + app[:6])
    app[6:8] = crc.to_bytes(2, "big")
    domain = ethertype + bytes(app[:declared]) + extension_prefix
    if algorithm == "hmac-sha256":
        tag = crypto_hmac_sha256(key, domain, tag_length)
    else:
        assert algorithm == "aes-gmac" and iv is not None and tag_length == 16
        # Empty plaintext makes AESGCM's returned bytes the GMAC tag over AAD.
        tag = AESGCM(key).encrypt(iv, b"", domain)
    extension = extension_prefix + tlv(0x85, tag)
    assert len(extension) == extension_length
    return frame[:14] + bytes(app) + extension, domain, tag, crc


def routed_record(frame: bytes, tag: int) -> bytes:
    app = frame[14:]
    appid = app[:2]
    apdu = app[8:]
    return bytes((tag, 0)) + appid + len(apdu).to_bytes(2, "big") + apdu


def legacy_rsession(*, signed: bool = True) -> tuple[bytes, bytes]:
    payload = routed_record(GOOSE, 0x81)
    signature = 1 if signed else 0
    # Version-1 common header: SPDU len, number, version, key times,
    # encryption/signature selectors, and key ID.
    header = bytearray(
        b"\x01\x40\xa1\x18\x80\x16"
        + b"\x00\x00\x00\x00"  # SPDU length, filled below
        + (9).to_bytes(4, "big")
        + b"\x00\x01"
        + (1).to_bytes(4, "big")
        + b"\xff\xff"
        + bytes((0, signature))
        + (7).to_bytes(4, "big")
    )
    raw = header + len(payload).to_bytes(4, "big") + payload
    trailer_length = 12 if signed else 0
    raw[6:10] = (len(raw) + trailer_length - 10).to_bytes(4, "big")
    domain = bytes(raw[2:])
    if signed:
        tag = crypto_hmac_sha256(HMAC_KEY, domain, 10)
        raw += b"\x85\x0a" + tag
    return bytes(raw), domain


def libiec_legacy_rsession() -> tuple[bytes, bytes]:
    """Reproduce libiec61850 v1's explicit, non-normative wire choices."""
    app = GOOSE[14:]
    apdu = app[8:]
    payload = b"\x81\x00" + app[:2] + (len(apdu) + 2).to_bytes(2, "big") + apdu
    header = bytearray(
        b"\x01\x40\xa1\x18\x80\x12"
        + b"\x00\x00\x00\x00"
        + (9).to_bytes(4, "big")
        + b"\x00\x01"
        + (1).to_bytes(4, "big")
        + b"\xff\xff"
        + b"\x00\x02"  # HMAC-SHA256-128
        + (7).to_bytes(4, "big")
    )
    raw = header + len(payload).to_bytes(4, "big") + payload
    # libiec61850 r_session.c uses 20 + payloadLength and does not count MAC.
    raw[6:10] = (20 + len(payload)).to_bytes(4, "big")
    domain = bytes(raw)  # its HMAC call starts at buffer offset zero
    raw += b"\x85\x10" + crypto_hmac_sha256(HMAC_KEY, domain, 16)
    return bytes(raw), domain


def current_rsession() -> bytes:
    payload = routed_record(SV, 0x82)
    # Version 2 removes on-wire algorithm selectors and adds ivLen/IV.
    iv = b"\xaa\xbb\xcc\xdd"
    session_header_length = 23 + len(iv)
    header = bytearray(
        b"\x01\x40\xa2"
        + bytes((session_header_length, 0x80, 0x0A))
        + b"\x00\x00\x00\x00"  # SPDU length, filled below
        + (10).to_bytes(4, "big")
        + b"\x00\x02"
        + (2).to_bytes(4, "big")
        + b"\x00\x05"
        + (8).to_bytes(4, "big")
        + bytes((len(iv),))
        + iv
    )
    raw = header + len(payload).to_bytes(4, "big") + payload
    raw[6:10] = (len(raw) - 10).to_bytes(4, "big")
    return bytes(raw)


def classic_pcap(*frames: bytes) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = b"".join(
        struct.pack("<IIII", 1 + index, 250000, len(frame), len(frame)) + frame
        for index, frame in enumerate(frames)
    )
    return header + records


def internet_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(int.from_bytes(data[offset : offset + 2], "big")
                for offset in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ethernet_ipv4_udp(payload: bytes, *, destination_port: int = 102) -> bytes:
    """Build a minimal capture fixture directly from Ethernet/IP/UDP layouts."""
    source_ip, destination_ip = b"\xc0\x00\x02\x01", b"\xef\xc0\x00\x01"
    udp = struct.pack("!HHHH", 41000, destination_port, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x6185, 0, 64, 17, 0,
        source_ip, destination_ip,
    )
    checksum = internet_checksum(ip)
    ip = ip[:10] + checksum.to_bytes(2, "big") + ip[12:]
    return bytes.fromhex("010ccd0100010011223344550800") + ip + udp


def clean_or_declared(call) -> None:
    try:
        result = call()
        assert isinstance(result, (dict, list))
    except grid.GridGooseError:
        pass


def test_published_goose_and_hand_built_sv_vectors() -> None:
    goose = grid.parse_l2(GOOSE)
    assert goose["appid"] == 0x3000
    assert goose["base_length"] == 97
    assert goose["security"]["present"] is False
    fields = goose["base"]["fields"]
    assert fields == {
        "gocb_ref": "IEDLD0/LLN0$GO$gcb01",
        "time_allowed_to_live": 2000,
        "dataset": "IEDLD0/LLN0$DS$ds01",
        "go_id": "gcb01",
        "timestamp": {"unix_seconds": 1784385360, "fraction": 0.0, "quality": 10},
        "state_number": 1,
        "sequence_number": 0,
        "simulation": False,
        "conf_revision": 7,
        "needs_commissioning": False,
        "entry_count": 1,
    }
    assert goose["base"]["all_data"] == [
        {"type": "boolean", "tag": 0x83, "raw_length": 1, "raw": "01", "value": True}
    ]

    sv = grid.parse_l2(SV)
    asdu = sv["base"]["asdus"][0]
    assert (sv["appid"], sv["base_length"], sv["base"]["asdu_count"]) == (0x4000, 47, 1)
    assert asdu == {
        "sv_id": "MU001",
        "data_hex": "000003e800000000",
        "sample_count": 0x1234,
        "conf_revision": 1,
        "sample_sync": 2,
    }


def test_bare_layer2_forms_and_vlan() -> None:
    app = GOOSE[14:]
    assert grid.parse_l2(GOOSE[12:])["base"]["fields"]["state_number"] == 1
    assert grid.parse_l2(app, ethertype=0x88B8)["appid"] == 0x3000
    vlan = GOOSE[:12] + b"\x81\x00\xa0\x2a" + GOOSE[12:]
    parsed = grid.parse_l2(vlan)
    assert parsed["ethernet"]["vlans"] == [
        {"tpid": 0x8100, "id": 42, "priority": 5, "dei": False}
    ]


def test_iec62351_hmac_vector_and_domain_lock() -> None:
    frame, domain, tag, crc = secured_frame(
        GOOSE, algorithm="hmac-sha256", key=HMAC_KEY
    )
    assert crc == 0x0470
    assert tag.hex() == "d1b3f9658800f0872cf44e4da77cdc01"
    parsed = grid.parse_l2(frame, key=HMAC_KEY, auth_algorithm="hmac-sha256")
    security = parsed["security"]
    assert security["crc_valid"] is True
    assert bytes.fromhex(security["mac_domain_hex"]) == domain
    assert security["authentication"] == {
        "status": "verified",
        "algorithm": "hmac-sha256",
        "tag_length": 16,
        "verified": True,
    }
    assert security["extension"]["authentication_value"] == {
        "version": 1,
        "time_of_current_key": 1,
        "time_to_next_key": 0,
        "key_id": 7,
        "initialization_vector": IV16.hex(),
    }
    assert grid.parse_l2(frame)["security"]["authentication"]["status"] == "not_checked"
    assert grid.parse_l2(
        frame, key=b"X" * 32, auth_algorithm="hmac-sha256"
    )["security"]["authentication"]["status"] == "invalid"

    changed = bytearray(frame)
    where = changed.index(b"gcb01")
    changed[where + 4] = ord("2")
    assert grid.parse_l2(
        bytes(changed), key=HMAC_KEY, auth_algorithm="hmac-sha256"
    )["security"]["authentication"]["status"] == "invalid"


def test_iec62351_gmac_goose_and_sv_vectors() -> None:
    goose, goose_domain, goose_tag, goose_crc = secured_frame(
        GOOSE, algorithm="aes-gmac", key=AES_KEY
    )
    assert goose_crc == 0x0470
    assert goose_tag.hex() == "7eea2b51ea76b492c1a21984ccee48e1"
    result = grid.parse_l2(goose, key=AES_KEY, auth_algorithm="aes-gmac")
    assert result["security"]["authentication"]["verified"] is True
    assert bytes.fromhex(result["security"]["mac_domain_hex"]) == goose_domain

    sv, sv_domain, sv_tag, sv_crc = secured_frame(SV, algorithm="aes-gmac", key=AES_KEY)
    assert sv_crc == 0xE0A7
    assert sv_tag.hex() == "4b6338fcdf2ff1cfb5ea0be0c95224f5"
    result = grid.parse_l2(sv, key=AES_KEY, auth_algorithm="aes-gmac")
    assert result["security"]["authentication"]["verified"] is True
    assert bytes.fromhex(result["security"]["mac_domain_hex"]) == sv_domain

    tampered = bytearray(goose)
    tampered[-1] ^= 1
    assert grid.parse_l2(
        bytes(tampered), key=AES_KEY, auth_algorithm="aes-gmac"
    )["security"]["authentication"]["status"] == "invalid"


def test_security_extension_rejects_crc_and_ber_failures() -> None:
    secured, _, _, _ = secured_frame(GOOSE, algorithm="hmac-sha256", key=HMAC_KEY)
    bad_crc = bytearray(secured)
    bad_crc[20] ^= 1
    with pytest.raises(grid.GridGooseError):
        grid.parse_l2(bytes(bad_crc))

    reserved = bytearray(secured)
    reserved[18] |= 0x10
    with pytest.raises(grid.GridGooseError):
        grid.parse_l2(bytes(reserved))

    indefinite = bytearray(secured)
    indefinite[14 + 97 + 1] = 0x80
    with pytest.raises(grid.GridGooseError):
        grid.parse_l2(bytes(indefinite))

    no_mac_ext = tlv(0xA0, auth_value())
    app = bytearray(GOOSE[14:])
    app[4:6] = len(no_mac_ext).to_bytes(2, "big")
    app[6:8] = crc16_iso_hdlc_reference(GOOSE[12:14] + app[:6]).to_bytes(2, "big")
    with pytest.raises(grid.GridGooseError):
        grid.parse_l2(GOOSE[:14] + bytes(app) + no_mac_ext)

    gmac_no_iv, _, _, _ = secured_frame(
        GOOSE, algorithm="hmac-sha256", key=HMAC_KEY, iv=None
    )
    with pytest.raises(grid.GridGooseError):
        grid.parse_l2(gmac_no_iv, key=AES_KEY, auth_algorithm="aes-gmac")


def test_legacy_and_current_routed_session_vectors() -> None:
    legacy, domain = legacy_rsession(signed=True)
    assert legacy[:6].hex() == "0140a1188016"
    assert int.from_bytes(legacy[6:10], "big") == len(legacy) - 10 == 129
    assert legacy[-10:].hex() == "fad1159a6d962bd28570"
    parsed = grid.parse_rsession(legacy, legacy=True, key=HMAC_KEY)
    assert parsed["protocol"] == "r-goose"
    assert parsed["wire_profile"] == "iec-tr-61850-90-5-v1"
    assert parsed["version"] == 1
    assert parsed["spdu_number"] == 9
    assert parsed["common_length_indicator"] == 0x16
    assert parsed["spdu_length_consistent"] is True
    assert parsed["authentication"]["verified"] is True
    assert parsed["authentication"]["mac_domain_profile"] == "iec-tr-61850-90-5"
    assert bytes.fromhex(parsed["authentication"]["mac_domain_hex"]) == domain
    assert parsed["payloads"][0]["base"]["fields"]["gocb_ref"] == "IEDLD0/LLN0$GO$gcb01"

    current = current_rsession()
    parsed = grid.parse_rsession(current)
    assert parsed["protocol"] == "r-sv"
    assert parsed["wire_profile"] == "iec-61850-annex-j-v2"
    assert parsed["version"] == 2
    assert parsed["common_length_indicator"] == 0x0A
    assert parsed["iv_hex"] == "aabbccdd"
    assert parsed["authentication"]["status"] == "not_checked"
    assert parsed["payloads"][0]["base"]["asdus"][0]["sample_count"] == 0x1234

    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(legacy)
    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(current, legacy=True)
    mismatch = bytearray(current)
    mismatch[current.index(b"\x82\x00\x40\x00")] = 0x81
    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(bytes(mismatch))

    for valid, kwargs in ((legacy, {"legacy": True}), (current, {})):
        bad_indicator = bytearray(valid)
        bad_indicator[5] = 9
        with pytest.raises(grid.GridGooseError):
            grid.parse_rsession(bytes(bad_indicator), **kwargs)


def test_explicit_libiec61850_v1_compatibility_vector() -> None:
    raw, domain = libiec_legacy_rsession()
    assert raw[:6].hex() == "0140a1188012"
    assert int.from_bytes(raw[6:10], "big") == 115
    assert len(raw) - 10 == 135
    assert raw[32:38].hex() == "81003000005b"
    assert raw[-16:].hex() == "cea37f79afbeb5b106089db634fa032f"

    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(raw, legacy=True, key=HMAC_KEY)
    parsed = grid.parse_rsession(
        raw, legacy=True, key=HMAC_KEY, libiec_compat=True
    )
    assert parsed["wire_profile"] == "libiec61850-v1"
    assert parsed["common_length_indicator"] == 0x12
    assert parsed["spdu_length_consistent"] is False
    assert parsed["authentication"]["verified"] is True
    assert parsed["authentication"]["mac_domain_profile"] == "libiec61850"
    assert bytes.fromhex(parsed["authentication"]["mac_domain_hex"]) == domain
    assert parsed["payloads"][0]["apdu_length"] == 91
    assert parsed["payloads"][0]["apdu_length_effective"] == 89
    assert parsed["payloads"][0]["apdu_length_profile"] == (
        "libiec61850-last-record-plus-two"
    )


def test_capture_composes_existing_bounded_reader() -> None:
    frame, _, _, _ = secured_frame(GOOSE, algorithm="hmac-sha256", key=HMAC_KEY)
    capture = classic_pcap(frame)
    parsed = grid.analyze_capture(
        capture, key=HMAC_KEY, auth_algorithm="hmac-sha256"
    )
    assert parsed["packets_seen"] == 1
    assert parsed["matching_packets"] == 1
    assert parsed["records"][0]["analysis"]["security"]["authentication"]["verified"] is True
    assert grid.analyze(capture, kind="auto")["protocol"] == "iec61850-capture"


def test_capture_extracts_current_routed_session_from_udp_102() -> None:
    routed = ethernet_ipv4_udp(current_rsession())
    unrelated = ethernet_ipv4_udp(b"not a routed session", destination_port=9999)
    malformed = ethernet_ipv4_udp(b"\x01\x40")
    parsed = grid.analyze_capture(classic_pcap(malformed, routed, unrelated))
    assert parsed["packets_seen"] == 3
    assert parsed["matching_packets"] == 1
    assert parsed["findings"][0]["kind"] == "routed-session-parse-error"
    analysis = parsed["records"][0]["analysis"]
    assert analysis["protocol"] == "r-sv"
    assert analysis["version"] == 2
    assert analysis["payloads"][0]["base"]["asdus"][0]["sv_id"] == "MU001"

    opaque = grid.analyze_capture(classic_pcap(routed), encrypted=True)
    assert opaque["records"][0]["analysis"]["payload_status"] == "opaque_encrypted"
    assert "payloads" not in opaque["records"][0]["analysis"]


def test_capture_legacy_options_key_forwarding_and_replay_finding() -> None:
    legacy, _ = legacy_rsession()
    legacy_packet = ethernet_ipv4_udp(legacy)
    current_packet = ethernet_ipv4_udp(current_rsession())
    capture = classic_pcap(legacy_packet, current_packet)

    default = grid.analyze_capture(capture, key=HMAC_KEY)
    assert default["matching_packets"] == 1
    assert default["findings"][0]["kind"] == "routed-session-parse-error"

    parsed = grid.analyze(capture, kind="pcap", legacy=True, key=HMAC_KEY)
    assert parsed["matching_packets"] == 2
    legacy_result = next(row["analysis"] for row in parsed["records"]
                         if row["analysis"]["version"] == 1)
    assert legacy_result["authentication"]["verified"] is True
    assert parsed["records"][0]["transport"]["destination_port"] == 102

    duplicate = grid.analyze_capture(classic_pcap(current_packet, current_packet))
    assert any(row["kind"] == "routed-spdu-duplicate"
               for row in duplicate["findings"])

    libiec, _ = libiec_legacy_rsession()
    compatible = grid.analyze_capture(
        classic_pcap(ethernet_ipv4_udp(libiec)), legacy=True,
        libiec_compat=True, key=HMAC_KEY,
    )
    assert compatible["records"][0]["analysis"]["authentication"]["verified"] is True


def test_every_valid_vector_truncation_is_fail_closed() -> None:
    secure, _, _, _ = secured_frame(GOOSE, algorithm="hmac-sha256", key=HMAC_KEY)
    legacy, _ = legacy_rsession(signed=True)
    libiec, _ = libiec_legacy_rsession()
    capture = classic_pcap(secure)
    cases = (
        (secure, lambda value: grid.parse_l2(value, key=HMAC_KEY, auth_algorithm="hmac-sha256")),
        (legacy, lambda value: grid.parse_rsession(value, legacy=True, key=HMAC_KEY)),
        (libiec, lambda value: grid.parse_rsession(
            value, legacy=True, key=HMAC_KEY, libiec_compat=True
        )),
        (current_rsession(), grid.parse_rsession),
    )
    for valid, parser in cases:
        for end in range(len(valid)):
            with pytest.raises(grid.GridGooseError):
                parser(valid[:end])
    for end in range(len(capture)):
        clean_or_declared(lambda end=end: grid.analyze_capture(capture[:end]))
        clean_or_declared(lambda end=end: grid.analyze(capture[:end]))
    current = current_rsession()
    for end in range(len(current)):
        clean_or_declared(lambda end=end: grid.analyze(current[:end]))


def test_seeded_random_bitflip_and_type_fuzz_never_leaks() -> None:
    rng = random.Random(0x618506)
    secure, _, _, _ = secured_frame(GOOSE, algorithm="hmac-sha256", key=HMAC_KEY)
    legacy, _ = legacy_rsession(signed=True)
    libiec, _ = libiec_legacy_rsession()
    parsers = (
        lambda value: grid.parse_l2(value),
        lambda value: grid.parse_rsession(value, legacy=True),
        grid.analyze_capture,
        lambda value: grid.analyze(value),
    )
    for _ in range(250):
        raw = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 300)))
        for parser in parsers:
            clean_or_declared(lambda parser=parser, raw=raw: parser(raw))
    for valid, parser in (
        (secure, lambda value: grid.parse_l2(value, key=HMAC_KEY, auth_algorithm="hmac-sha256")),
        (legacy, lambda value: grid.parse_rsession(value, legacy=True, key=HMAC_KEY)),
        (libiec, lambda value: grid.parse_rsession(
            value, legacy=True, key=HMAC_KEY, libiec_compat=True
        )),
    ):
        for index in range(len(valid)):
            changed = bytearray(valid)
            changed[index] ^= 1 << (index % 8)
            clean_or_declared(lambda changed=changed, parser=parser: parser(bytes(changed)))

    capture = classic_pcap(secure)
    for index in range(len(capture)):
        changed = bytearray(capture)
        changed[index] ^= 1 << (index % 8)
        clean_or_declared(lambda changed=changed: grid.analyze_capture(bytes(changed)))
        clean_or_declared(lambda changed=changed: grid.analyze(bytes(changed)))

    for bad in (None, "bytes", 3, object(), [1, 2]):
        for parser in (grid.parse_l2, grid.parse_rsession, grid.analyze_capture, grid.analyze):
            with pytest.raises(grid.GridGooseError):
                parser(bad)  # type: ignore[arg-type]
    two_dimensional = memoryview(bytearray(16)).cast("B", shape=(4, 4))
    for parser in (grid.parse_l2, grid.parse_rsession, grid.analyze_capture, grid.analyze):
        with pytest.raises(grid.GridGooseError):
            parser(two_dimensional)

    oversized_frame = b"A" * (grid.MAX_FRAME + 1)
    with pytest.raises(grid.GridGooseError):
        grid.parse_l2(oversized_frame, ethertype=0x88B8)
    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(oversized_frame)
    oversized_capture = b"A" * (grid.MAX_CAPTURE + 1)
    with pytest.raises(grid.GridGooseError):
        grid.analyze_capture(oversized_capture)
    with pytest.raises(grid.GridGooseError):
        grid.analyze(oversized_capture)

    with pytest.raises(grid.GridGooseError):
        grid.parse_l2(GOOSE, decode_9_2le=1)  # type: ignore[arg-type]
    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(current_rsession(), legacy=1)  # type: ignore[arg-type]
    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(current_rsession(), libiec_compat=True)
    with pytest.raises(grid.GridGooseError):
        grid.parse_rsession(legacy, legacy=True, libiec_compat=1)  # type: ignore[arg-type]
    with pytest.raises(grid.GridGooseError):
        grid.analyze_capture(classic_pcap(secure), libiec_compat=True)
    with pytest.raises(grid.GridGooseError):
        grid.analyze_capture(classic_pcap(secure), encrypted=1)  # type: ignore[arg-type]


def test_cli_guard_and_offline_file_path(tmp_path, monkeypatch, capsys) -> None:
    sample = tmp_path / "goose.bin"
    sample.write_bytes(GOOSE)
    assert grid.main([str(sample), "--kind", "l2"]) == 0
    assert '"appid": 12288' in capsys.readouterr().out
    assert grid.main(["--help"]) == 0
    assert grid.main([]) == 2
    assert grid.main([str(tmp_path / "absent")]) == 2

    libiec_file = tmp_path / "libiec-rgoose.bin"
    libiec_file.write_bytes(libiec_legacy_rsession()[0])
    assert grid.main([
        str(libiec_file), "--kind", "rsession", "--legacy-rsession",
        "--libiec-rsession", "--key-hex", HMAC_KEY.hex(),
    ]) == 0
    assert '"wire_profile": "libiec61850-v1"' in capsys.readouterr().out

    def non_integer_exit(self, argv):
        raise SystemExit("not-an-integer")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", non_integer_exit)
    assert grid.main([]) == 2

