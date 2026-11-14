"""Independent IEEE-1815 SA and IEC-60870-6/TASE.2 regression vectors.

Layouts are handwritten from IEEE 1815 Annex A.45 / the DNP-UG validation
bulletin.  Crypto expectations come from RFC 2202, RFC 4231, NIST SP 800-38D,
and RFC 3394.  The engine has no encoder and is never used to construct an
expected value.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import struct

import pytest
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import sec_gridsec_dnp3sa as dnp


def _obj(variation: int, body: bytes) -> bytes:
    """Hand-encode the qualifier required by Annex A.45."""
    if variation in (3, 4):
        return bytes((120, variation, 0x07, 1)) + body
    return bytes((120, variation, 0x5B, 1)) + len(body).to_bytes(2, "little") + body


def _request(function: int, *objects: bytes, sequence: int = 0) -> bytes:
    return bytes((0xC0 | sequence, function)) + b"".join(objects)


def _response(function: int, *objects: bytes, iin: int = 0, sequence: int = 0) -> bytes:
    return bytes((0xC0 | sequence, function)) + iin.to_bytes(2, "little") + b"".join(objects)


def _bodies() -> dict[int, bytes]:
    challenge = b"CHAL"
    username, public, certification = b"alice", b"PUB", b"CERT"
    return {
        1: struct.pack("<IHBB", 0x01020304, 0x0506, 3, 1) + challenge,
        2: struct.pack("<IH", 0x01020304, 0x0506) + b"M" * 8,
        3: struct.pack("<IH", 0x01020305, 0x0506),
        4: struct.pack("<H", 0x0506),
        5: struct.pack("<IHBBBH", 9, 7, 1, 1, 3, len(challenge)) + challenge + b"A" * 8,
        6: struct.pack("<IH", 9, 7) + b"W" * 24,
        7: struct.pack("<IHHB", 9, 7, 0x1234, 5) + (1700000000000).to_bytes(6, "little") + b"bad mac",
        8: bytes((68, 1)) + b"certificate",
        9: b"H" * 8,
        10: (
            struct.pack(
                "<BBIHHHHH",
                68,
                1,
                0x11223344,
                2,
                60,
                len(username),
                len(public),
                len(certification),
            )
            + username
            + public
            + certification
        ),
        11: struct.pack("<BHH", 3, len(b"Common\0"), 20) + b"Common\0" + b"M" * 20,
        12: struct.pack("<IHH", 11, 7, 20) + b"O" * 20,
        13: struct.pack("<IHH", 11, 7, 8) + b"ENCRYPT!",
        14: b"S" * 32,
        15: b"C" * 16,
    }


def _crypto_hmac(key: bytes, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
    oracle = crypto_hmac.HMAC(key, algorithm)
    oracle.update(data)
    return oracle.finalize()


def _rfc3394_wrap(kek: bytes, plaintext: bytes) -> bytes:
    """Tiny independent RFC 3394 reference using only AES-ECB as primitive."""
    assert len(plaintext) >= 16 and len(plaintext) % 8 == 0
    cipher = AES.new(kek, AES.MODE_ECB)
    blocks = [plaintext[i : i + 8] for i in range(0, len(plaintext), 8)]
    a = b"\xa6" * 8
    n = len(blocks)
    for j in range(6):
        for i in range(n):
            b = cipher.encrypt(a + blocks[i])
            t = n * j + i + 1
            a = (int.from_bytes(b[:8], "big") ^ t).to_bytes(8, "big")
            blocks[i] = b[8:]
    return a + b"".join(blocks)


def _tlv(tag: int, value: bytes) -> bytes:
    assert len(value) < 128
    return bytes((tag, len(value))) + value


def _ctx(number: int, value: bytes, constructed: bool = True) -> bytes:
    return _tlv((0xA0 if constructed else 0x80) | number, value)


def _integer(value: int) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return _tlv(0x02, value.to_bytes(size, "big", signed=True))


def _domain_name(domain: str, item: str) -> bytes:
    return _ctx(1, _tlv(0x1A, domain.encode()) + _tlv(0x1A, item.encode()))


def _variable_list(domain: str, item: str) -> bytes:
    named = _tlv(0x30, _ctx(0, _domain_name(domain, item)))
    return _ctx(0, named)


def _mms_request(service: int, body: bytes) -> bytes:
    return _ctx(0, _integer(1) + _ctx(service, body))


def test_authoritative_group120_variations_1_through_15():
    bodies = _bodies()
    for variation in range(1, 16):
        parsed = dnp.parse_sa_object(variation, bodies[variation])
        assert parsed["group"] == 120
        assert parsed["variation"] == variation
        assert parsed["variation_name"] == dnp.VARIATION_NAMES[variation]
        assert parsed["raw_hex"] == bodies[variation].hex()

    challenge = dnp.parse_sa_object(1, bodies[1])
    assert challenge == {
        **challenge,
        "sequence": 0x01020304,
        "user": 0x0506,
        "mac_algorithm": 3,
        "mac_algorithm_name": "hmac-sha256-8",
        "reason": 1,
        "reason_name": "critical-function",
        "challenge_hex": b"CHAL".hex(),
    }
    status = dnp.parse_sa_object(5, bodies[5])
    assert status["challenge_length"] == 4
    assert status["challenge_hex"] == b"CHAL".hex()
    assert status["mac_hex"] == (b"A" * 8).hex()
    error = dnp.parse_sa_object(7, bodies[7])
    assert error["association_id"] == 0x1234
    assert error["error_name"] == "mac-algorithm-not-supported"
    assert error["error_text"] == "bad mac"
    for code, expected_name in (
        (7, "authorization-failed"),
        (8, "update-key-change-method-not-permitted"),
    ):
        error_body = struct.pack("<IHHB", 9, 7, 0x1234, code) + (0).to_bytes(6, "little")
        assert dnp.parse_sa_object(7, error_body)["error_name"] == expected_name
    change = dnp.parse_sa_object(10, bodies[10])
    assert (change["operation_name"], change["username"]) == ("add", "alice")
    assert change["public_key_hex"] == b"PUB".hex()


def test_free_format_and_fixed_qualifiers_and_application_iin():
    bodies = _bodies()
    stream = _obj(1, bodies[1])
    parsed = dnp.parse_sa_object_stream(stream)[0]
    assert parsed["qualifier"] == 0x5B
    assert parsed["object_size"] == len(bodies[1])

    fixed = dnp.parse_sa_object_stream(_obj(4, bodies[4]))[0]
    assert fixed["qualifier"] == 0x07 and fixed["user"] == 0x0506
    malformed_free_v4 = bytes((120, 4, 0x5B, 1, 2, 0)) + bodies[4]
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_sa_object_stream(malformed_free_v4)

    response = dnp.parse_dnp3_sa_fragment(_response(0x83, stream, iin=0x1234))
    assert response["application"]["iin"] == 0x1234
    assert response["objects"][0]["sequence"] == 0x01020304
    request = dnp.parse_dnp3_sa_fragment(_request(0x20, _obj(2, bodies[2])))
    assert request["application"]["response"] is False
    # An Authentication Response without its two IIN octets must fail closed.
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_dnp3_sa_fragment(b"\xc0\x83" + stream)


@pytest.mark.parametrize("control,function", [(0xE0, 0x81), (0xF0, 0x82)])
def test_request_secure_confirmation_after_bounded_ordinary_response(control, function):
    # g30v1, qualifier 0x07, count 1: flags followed by signed 32-bit value.
    ordinary = bytes.fromhex("1e010701812a000000")
    challenge = _obj(1, _bodies()[1])
    fragment = bytes((control, function, 0, 0)) + ordinary + challenge
    parsed = dnp.parse_dnp3_sa_fragment(fragment)
    assert parsed["request_secure_confirmation"] is True
    assert parsed["ordinary_objects_hex"] == ordinary.hex()
    assert [row["group"] for row in parsed["ordinary_response_objects"]] == [30]
    assert parsed["ordinary_response_objects"][0]["points"][0]["value"] == 42
    assert [row["variation"] for row in parsed["objects"]] == [1]

    # Annex A.45.1 requires the Challenge to be last and the response CON bit set.
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_dnp3_sa_fragment(bytes((control & ~0x20, function, 0, 0)) + ordinary + challenge)
    mismatched_uns = control ^ 0x10
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_dnp3_sa_fragment(bytes((mismatched_uns, function, 0, 0)) + ordinary + challenge)
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_dnp3_sa_fragment(bytes((control, function, 0, 0)) + b"JUNK" + challenge)


@pytest.mark.parametrize(
    "method,master_length,outstation_length",
    [
        (3, 20, 20),
        (4, 32, 32),
        (5, 32, 32),
        (67, 0, 20),
        (68, 0, 32),
        (69, 0, 32),
        (70, 0, 32),
        (71, 0, 32),
    ],
)
def test_update_key_challenge_lengths_follow_method_table(
    method, master_length, outstation_length
):
    username = b"alice"
    request_body = (
        struct.pack("<BHH", method, len(username), master_length)
        + username
        + b"M" * master_length
    )
    request = dnp.parse_sa_object(11, request_body)
    assert request["challenge_length"] == master_length
    assert request["challenge_length_validation"]["status"] == "validated"
    assert request["challenge_length_validation"]["expected"] == master_length

    reply_body = struct.pack("<IHH", 9, 7, outstation_length) + b"O" * outstation_length
    contextual = dnp.parse_sa_object(12, reply_body)
    assert contextual["challenge_length_validation"]["status"] == (
        "requires-key-change-method-context"
    )
    validated = dnp.parse_sa_object(12, reply_body, key_change_method=method)
    assert validated["challenge_length_validation"]["status"] == "validated"
    assert validated["challenge_length_validation"]["expected"] == outstation_length


def test_update_key_challenge_length_mismatches_fail_closed():
    username = b"alice"
    short_request = struct.pack("<BHH", 3, len(username), 4) + username + b"M" * 4
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_sa_object(11, short_request)
    asymmetric_with_master_challenge = (
        struct.pack("<BHH", 68, len(username), 32) + username + b"M" * 32
    )
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_sa_object(11, asymmetric_with_master_challenge)
    obsolete = struct.pack("<BHH", 1, len(username), 0) + username
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_sa_object(11, obsolete)

    too_short_reply = struct.pack("<IHH", 9, 7, 4) + b"OUTS"
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_sa_object(12, too_short_reply)
    sha1_reply = struct.pack("<IHH", 9, 7, 20) + b"O" * 20
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_sa_object(12, sha1_reply, key_change_method=4)


def test_function_and_pair_order_validation():
    bodies = _bodies()
    paired = dnp.parse_dnp3_sa_fragment(_request(0x20, _obj(13, bodies[13]), _obj(14, bodies[14])))
    assert [o["variation"] for o in paired["objects"]] == [13, 14]
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_dnp3_sa_fragment(_request(0x20, _obj(14, bodies[14]), _obj(13, bodies[13])))
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_dnp3_sa_fragment(_request(0x20, _obj(5, bodies[5])))


@pytest.mark.parametrize(
    "algorithm,key,data,full_tag",
    [
        (1, b"\x0b" * 20, b"Hi There", bytes.fromhex("b617318655057264e28bc0b6fb378c8ef146be00")),
        (2, b"\x0b" * 20, b"Hi There", bytes.fromhex("b617318655057264e28bc0b6fb378c8ef146be00")),
        (5, b"\x0b" * 20, b"Hi There", bytes.fromhex("b617318655057264e28bc0b6fb378c8ef146be00")),
        (
            3,
            b"\x0b" * 20,
            b"Hi There",
            bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ),
        (
            4,
            b"\x0b" * 20,
            b"Hi There",
            bytes.fromhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        ),
    ],
)
def test_rfc2202_and_rfc4231_hmac_vectors(algorithm, key, data, full_tag):
    length = dnp.MAC_ALGORITHMS[algorithm]["length"]
    result = dnp.verify_mac(key, algorithm, data, full_tag[:length])
    assert result["verified"] is True
    assert result["provided_mac_length"] == length
    assert dnp.verify_mac(key, algorithm, data + b"!", full_tag[:length])["verified"] is False


def test_nist_gmac_vector_and_cross_library_oracle():
    key, iv, aad = bytes(16), bytes(12), b""
    published = bytes.fromhex("58e2fccefa7e3061367f1d57a4e7455a")
    assert AESGCM(key).encrypt(iv, b"", aad) == published
    result = dnp.verify_mac(key, 6, aad, published[:12], iv=iv)
    assert result["verified"] is True
    assert dnp.verify_mac(key, 6, b"changed", published[:12], iv=iv)["verified"] is False


def test_normal_challenge_reply_exact_full_fragment_domain():
    key = bytes(range(32))
    challenged = b"\xc0\x03"  # complete ordinary SELECT application fragment
    challenge_body = struct.pack("<IHBB", 77, 9, 3, 1) + b"RAND"
    challenge = _response(0x83, _obj(1, challenge_body))
    tag = _crypto_hmac(key, challenge + challenged, hashes.SHA256())[:8]
    reply = _request(0x20, _obj(2, struct.pack("<IH", 77, 9) + tag))
    report = dnp.verify_normal_reply(key, challenge, reply, challenged_fragment=challenged)
    assert report["verification"]["verified"] is True
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.verify_normal_reply(key, challenge, reply)


def test_aggressive_mode_exact_header_prefix_domain():
    key = bytes(range(32))
    challenge_body = struct.pack("<IHBB", 100, 4, 3, 1) + b"RAND"
    challenge = _response(0x83, _obj(1, challenge_body))
    first = _obj(3, struct.pack("<IH", 101, 4))
    ordinary = bytes.fromhex("0c01070103")  # opaque ordinary CROB-header evidence
    mac_header = bytes((120, 9, 0x5B, 1, 8, 0))
    prefix = b"\xc0\x03" + first + ordinary + mac_header
    tag = _crypto_hmac(key, challenge + prefix, hashes.SHA256())[:8]
    fragment = prefix + tag
    report = dnp.verify_aggressive_mode(key, challenge, fragment)
    assert report["verification"]["verified"] is True
    assert report["fragment"]["ordinary_objects_hex"] == ordinary.hex()


def test_rfc3394_reference_and_bound_session_key_unwrap():
    # RFC 3394 section 4.1, 128-bit KEK and 128-bit key data.
    kek = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    clear = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected = bytes.fromhex("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5")
    assert _rfc3394_wrap(kek, clear) == expected

    status = struct.pack("<IHBBBH", 5, 7, 1, 1, 0, 0)
    control, monitoring = bytes(range(16)), bytes(range(16, 32))
    plaintext = (16).to_bytes(2, "little") + control + monitoring + status + b"\0" * 3
    assert len(plaintext) % 8 == 0
    wrapped = _rfc3394_wrap(kek, plaintext)
    change = struct.pack("<IH", 5, 7) + wrapped
    report = dnp.unwrap_session_key_change(kek, status, change)
    assert report["status_binding_verified"] is True
    assert report["control_direction_key_hex"] == control.hex()
    assert report["monitoring_direction_key_hex"] == monitoring.hex()


def test_iccp_corrected_mms_fixture_and_tase_reserved_write():
    # Correct ISO 9506 Confirmed Read of domain ICC, item MW.
    fixture = bytes.fromhex("a018020101a413a111a00f300da00ba1091a034943431a024d57")
    parsed = dnp.analyze_iccp(fixture, layer="mms")
    assert parsed["classification"]["strength"] == "possible-mms-only"
    assert parsed["classification"]["domains"] == ["ICC"]
    assert parsed["classification"]["mms_services"] == ["read"]

    read = _mms_request(4, _ctx(1, _variable_list("ICC", "TASE.2_Version")))
    reserved = dnp.analyze_iccp(read, layer="mms")
    assert reserved["classification"]["strength"] == "strong"
    assert "TASE.2_Version" in reserved["classification"]["reserved_names"]

    write_body = _variable_list("ICC", "Transfer_Set_Name") + _ctx(0, _tlv(0x83, b"\xff"))
    write = dnp.analyze_iccp(_mms_request(5, write_body), layer="mms")
    assert "Transfer_Set_Name" in write["classification"]["reserved_names"]
    assert any(row["id"] == "iccp-mms-write" for row in write["findings"])


def test_sav6_is_metadata_gated_and_never_guessed_as_group120():
    raw = b"opaque future DNP3 security layer"
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.analyze_dnp3_security_layer(raw)
    report = dnp.analyze_dnp3_security_layer(raw, identified_by_capture_metadata=True)
    assert report["parsed"] is False
    assert report["sha256"] == hashlib.sha256(raw).hexdigest()
    assert "Group-120" not in report["protocol"]


def test_declared_exception_contract_truncation_fuzz_and_oversize():
    valid_object = _obj(1, _bodies()[1])
    valid_fragment = _response(0x83, valid_object)
    for end in range(len(valid_object)):
        with pytest.raises(dnp.GridDNP3SAError):
            dnp.parse_sa_object_stream(valid_object[:end])
    for end in range(len(valid_fragment)):
        with pytest.raises(dnp.GridDNP3SAError):
            dnp.parse_dnp3_sa_fragment(valid_fragment[:end])

    entrypoints = [
        lambda blob: dnp.parse_sa_object(1, blob),
        dnp.parse_sa_object_stream,
        dnp.parse_dnp3_sa_fragment,
        lambda blob: dnp.verify_mac(b"k", 3, b"data", blob),
        lambda blob: dnp.verify_normal_reply(b"k", blob, blob, challenged_fragment=b"\xc0\x03"),
        lambda blob: dnp.verify_aggressive_mode(b"k", blob, blob),
        lambda blob: dnp.unwrap_session_key_change(b"k" * 16, blob, blob),
        lambda blob: dnp.analyze_iccp(blob),
        lambda blob: dnp.analyze_dnp3_security_layer(blob, identified_by_capture_metadata=True),
    ]
    rng = random.Random(0x1815)
    samples = [b""] + [
        bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 80)))
        for _ in range(80)
    ]
    samples += [valid_fragment[:i] + bytes((valid_fragment[i] ^ bit,)) + valid_fragment[i + 1 :]
                for i in range(len(valid_fragment)) for bit in (1, 0x80)]
    for function in entrypoints:
        for blob in samples:
            try:
                function(blob)
            except dnp.GridDNP3SAError:
                pass
            except Exception as exc:  # pragma: no cover - contract assertion
                pytest.fail(f"stdlib exception leaked from {function}: {type(exc).__name__}: {exc}")
        with pytest.raises(dnp.GridDNP3SAError):
            function(b"X" * (dnp.MAX_INPUT + 1))


def test_wrong_types_and_multidimensional_memoryview_fail_closed():
    multidimensional = memoryview(bytearray(4)).cast("B", shape=(2, 2))
    bodies = _bodies()
    challenge = _response(0x83, _obj(1, bodies[1]))
    reply = _request(0x20, _obj(2, bodies[2]))
    first = _obj(3, bodies[3])
    mac_header = bytes((120, 9, 0x5B, 1, 8, 0))
    aggressive = b"\xc0\x03" + first + mac_header + bodies[9]
    consumers = [
        lambda value: dnp.parse_sa_object(1, value),
        dnp.parse_sa_object_stream,
        dnp.parse_dnp3_sa_fragment,
        lambda value: dnp.verify_mac(value, 3, b"data", b"0" * 8),
        lambda value: dnp.verify_normal_reply(
            value, challenge, reply, challenged_fragment=b"\xc0\x03"
        ),
        lambda value: dnp.verify_aggressive_mode(value, challenge, aggressive),
        lambda value: dnp.unwrap_session_key_change(value, bodies[5], bodies[6]),
        dnp.analyze_iccp,
        lambda value: dnp.analyze_dnp3_security_layer(
            value, identified_by_capture_metadata=True
        ),
    ]
    for bad in (None, "bytes", 1, object(), multidimensional):
        for consume in consumers:
            with pytest.raises(dnp.GridDNP3SAError):
                consume(bad)  # type: ignore[arg-type]
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.parse_sa_object(True, b"x")
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.verify_mac(b"k", object(), b"data", b"0" * 8)  # type: ignore[arg-type]
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.analyze_iccp(b"x", layer=object())  # type: ignore[arg-type]
    with pytest.raises(dnp.GridDNP3SAError):
        dnp.analyze_dnp3_security_layer(b"x", identified_by_capture_metadata=1)  # type: ignore[arg-type]


def test_cli_guard_and_errors(monkeypatch, tmp_path):
    assert dnp.main(["--help"]) == 0
    assert dnp.main(["sa", str(tmp_path / "missing")]) == 2
    artifact = tmp_path / "objects.bin"
    artifact.write_bytes(_obj(4, _bodies()[4]))
    assert dnp.main(["objects", str(artifact)]) == 0

    def non_integer_exit(self, argv):
        raise SystemExit("bad")

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", non_integer_exit)
    assert dnp.main([]) == 2
