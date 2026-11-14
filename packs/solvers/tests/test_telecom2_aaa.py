"""Independent RFC 2865 wire vectors, Scapy oracle, and manual TLV fixtures."""
import hashlib
import json
import random
import struct

import pytest
from scapy.contrib.diameter import AVP, DiamReq
from pyrad.packet import AuthPacket

import telecom2_aaa as aaa

# Verbatim packet vectors from RFC 2865 section 7.1, secret xyzzy5461.
# https://www.rfc-editor.org/rfc/rfc2865.txt
RFC_REQUEST = bytes.fromhex("""
01 00 00 38 0f 40 3f 94 73 97 80 57 bd 83 d5 cb
98 f4 22 7a 01 06 6e 65 6d 6f 02 12 0d be 70 8d
93 d4 13 ce 31 96 e4 3f 78 2a 0a ee 04 06 c0 a8
01 10 05 06 00 00 00 03
""")
RFC_RESPONSE = bytes.fromhex("""
02 00 00 26 86 fe 22 0e 76 24 ba 2a 10 05 f6 bf
9b 55 e0 b2 06 06 00 00 00 01 0f 06 00 00 00 00
0e 06 c0 a8 01 03
""")


def rattr(code, value):
    """Manual RFC 2865 type/length/value encoder, no engine calls."""
    return bytes((code, len(value) + 2)) + value


def radius(attributes, code=1, auth=bytes(range(16))):
    return struct.pack("!BBH", code, 7, len(attributes) + 20) + auth + attributes


def avp(code, value, vendor=0, flags=64):
    """Manual RFC 6733 AVP layout; values supplied independently by each test."""
    if vendor:
        flags |= 128
    header = struct.pack("!I", code) + bytes((flags,))
    header += (len(value) + (12 if vendor else 8)).to_bytes(3, "big")
    if vendor:
        header += struct.pack("!I", vendor)
    raw = header + value
    return raw + bytes(-len(raw) % 4)


def diameter(attributes):
    return b"\x01" + (len(attributes) + 20).to_bytes(3, "big") + b"\x80\x00\x01\x3c" + struct.pack("!III", 16777251, 7, 9) + attributes


def test_rfc_published_request_and_pap():
    result = aaa.parse_radius(RFC_REQUEST, secret=b"xyzzy5461")
    assert result["code_name"] == "Access-Request"
    assert result["identifier"] == 0
    assert [a["value"] for a in result["attributes"]] == ["nemo", "0dbe708d93d413ce3196e43f782a0aee", "192.168.1.16", 3]
    assert result["attributes"][1]["plaintext_text"] == "arctangent"
    assert result["message_authenticator_valid"] is None
    assert result["message_authenticator_present"] is False


def test_rfc_published_response_authenticator():
    assert aaa.verify_radius_response(RFC_RESPONSE, RFC_REQUEST, b"xyzzy5461") is True
    assert aaa.verify_radius_response(RFC_RESPONSE, RFC_REQUEST, b"wrong") is False
    changed = RFC_RESPONSE[:1] + b"\x01" + RFC_RESPONSE[2:]
    assert aaa.verify_radius_response(changed, RFC_REQUEST, b"xyzzy5461") is False
    assert aaa.parse_radius(RFC_RESPONSE)["attributes"][-1]["value"] == "192.168.1.3"


@pytest.mark.parametrize("length", [1, 16, 17, 31, 32, 47, 128])
def test_pap_multiple_blocks_against_pyrad(length):
    clear = (b"CSCTF{radius_known_secret}" * 6)[:length]
    auth, secret = bytes(range(16)), b"test oracle key"
    packet = AuthPacket(code=1, id=7, authenticator=auth, secret=secret)
    encoded = packet.PwCrypt(clear.decode("ascii"))
    assert aaa.decrypt_user_password(encoded, secret, auth) == clear


def test_order_duplicates_vendor_namespace_and_unknown_opaque():
    attrs = rattr(1, b"a") + rattr(1, b"b")
    attrs += rattr(26, struct.pack("!I", 9) + rattr(1, b"shell:priv-lvl=15"))
    attrs += rattr(26, struct.pack("!I", 311) + rattr(1, bytes.fromhex("aabb")))
    # Unknown vendors may have a completely different subattribute encoding.
    attrs += rattr(26, struct.pack("!I", 9999) + b"\x00\x01\xff")
    result = aaa.parse_radius(radius(attrs))["attributes"]
    assert [r["value"] for r in result[:2]] == ["a", "b"]
    assert result[2]["attributes"][0]["value"] == "shell:priv-lvl=15"
    assert result[2]["attributes"][0]["offset"] == 32
    assert result[3]["attributes"][0]["name"] == "MS-CHAP-Response"
    assert result[3]["attributes"][0]["value"] == "aabb"
    assert "attributes" not in result[4]


def test_eap_reassembly_and_hmac_independent_rfc2104_construction():
    # EAP Response/Identity, identifier 3, payload identity 'bob'.
    attrs = rattr(79, b"\x02\x03\x00") + rattr(79, b"\x08\x01bob") + rattr(80, bytes(16))
    unsigned = radius(attrs)
    secret = b"known"
    # HMAC construction from pads rather than engine or hmac.new.
    key = secret + bytes(64 - len(secret))
    inner = hashlib.md5(bytes(x ^ 0x36 for x in key) + unsigned).digest()
    digest = hashlib.md5(bytes(x ^ 0x5c for x in key) + inner).digest()
    signed = unsigned[:-16] + digest
    result = aaa.parse_radius(signed, secret=secret)
    assert result["eap"]["raw_hex"] == "0203000801626f62"
    assert result["message_authenticator_valid"] is True
    assert aaa.parse_radius(signed, secret=b"wrong")["message_authenticator_valid"] is False


def test_scapy_diameter_group_and_addresses():
    group = AVP([1400, 10415], val=[AVP([1402, 10415], val=b"123456789012345")])
    wire = bytes(DiamReq(316, drAppId=16777251, drHbHId=7, drEtEId=9,
                         avpList=[AVP(264, val=b"host.example"), group, AVP(257, val="2001:db8::1")]))
    result = aaa.parse_diameter(wire)
    assert result["command_code"] == 316
    assert result["application_id"] == 16777251
    assert result["avps"][1]["children"][0]["value"] == "123456789012345"
    assert result["avps"][2]["value"] == "2001:db8::1"
    assert result["avps"][1]["children"][0]["padding_hex"] == "00"


def test_diameter_exact_vendor_namespace_unknown_groups():
    # This unknown vendor's code 264 must not inherit IETF Origin-Host text.
    wire = avp(264, b"\xff\x00", 9999)
    # Nor should an unknown octet AVP be recursively parsed just because it fits.
    wire += avp(987654, avp(264, b"not-a-child"))
    records = aaa.walk_diameter_avps(wire)
    assert records[0]["name"] == "AVP-9999-264"
    assert records[0]["value"] == "ff00"
    assert all("children" not in r for r in records)


def test_diameter_padding_offsets_and_scalar_types():
    attrs = avp(263, b"abc") + avp(421, (2**48 + 7).to_bytes(8, "big"))
    attrs += avp(55, bytes.fromhex("ffffffff")) + avp(450, (-1).to_bytes(4, "big", signed=True))
    result = aaa.parse_diameter(diameter(attrs))["avps"]
    assert [r["offset"] for r in result] == [20, 32, 48, 60]
    assert result[0]["length"] == 11 and result[0]["padding_hex"] == "00"
    assert result[1]["value"] == 2**48 + 7
    assert result[2]["value"] == {"ntp_seconds": 2**32 - 1}
    assert result[3]["value"] == -1
    # RFC 6733 receivers ignore padding, so retain nonzero capture padding.
    changed = avp(263, b"abc")[:-1] + b"\xff"
    assert aaa.walk_diameter_avps(changed)[0]["padding_hex"] == "ff"


def test_subscriber_typed_avps_and_nested_apn():
    apn = avp(1430, avp(1423, b"\x00\x00\x00\x01", 10415) + avp(493, b"ims.example"), 10415)
    records = aaa.walk_diameter_avps(avp(1400, avp(701, b"\x21\x43\xf5", 10415) + apn, 10415))
    children = records[0]["children"]
    assert children[0]["value"] == "12345"
    assert children[1]["children"][1]["value"] == "ims.example"
    for wire, expected in [(b"\x13\x00\x62", {"mcc": "310", "mnc": "260"}),
                           (b"\x32\xf4\x51", {"mcc": "234", "mnc": "15"})]:
        assert aaa.walk_diameter_avps(avp(1407, wire, 10415))[0]["value"] == expected


def test_all_rfc_truncations_and_trailing_data_rejected():
    for end in range(len(RFC_REQUEST)):
        with pytest.raises(aaa.AAAError):
            aaa.parse_radius(RFC_REQUEST[:end])
    wire = diameter(avp(263, b"hello"))
    for end in range(len(wire)):
        with pytest.raises(aaa.AAAError):
            aaa.parse_diameter(wire[:end])
    for fn, raw in [(aaa.parse_radius, RFC_REQUEST), (aaa.parse_diameter, wire)]:
        with pytest.raises(aaa.AAAError):
            fn(raw + b"\x00")


@pytest.mark.parametrize("attrs", [
    b"\x01", b"\x01\x01", b"\x00\x02", b"\x01\xffx",
    rattr(4, b"abc"), rattr(5, b"12345"), rattr(1, b"\xff"),
    rattr(2, b"x"), rattr(3, b"x"), rattr(80, bytes(15)),
    rattr(80, bytes(16)) * 2, rattr(2, bytes(16)) * 2,
    rattr(26, b"\x00\x00\x00\x09"),
    rattr(26, b"\x01\x00\x00\x09x"),
    rattr(26, b"\x00\x00\x00\x09\x01\xff"),
    rattr(79, b"\x02\x03\x00\xffx"),
    rattr(79, b""), rattr(79, b"\x02\x03\x00\x04"),
    rattr(79, b"\x03\x03\x00\x05x"),
])
def test_bad_radius_attributes(attrs):
    with pytest.raises(aaa.AAAError):
        aaa.parse_radius(radius(attrs))


@pytest.mark.parametrize("wire", [
    b"\x00", b"\x00" * 7,
    b"\x00" * 8,  # zero AVP length
    struct.pack("!I", 264) + b"\x80\x00\x00\x08",  # vendor header too short
    struct.pack("!I", 264) + b"\x80\x00\x00\x0c" + bytes(4),
    avp(264, b"\xff"), avp(268, bytes(3)), avp(257, b"\x00\x03abcd"),
    avp(701, b"\x1f", 10415), avp(701, b"\xf1\x23", 10415),
    avp(1407, b"\xaa\xbb\xcc", 10415),
    avp(284, b"\x00"),
    avp(264, b"abc")[:-1],
])
def test_bad_diameter_avps(wire):
    with pytest.raises(aaa.AAAError):
        aaa.walk_diameter_avps(wire)


def test_nesting_and_item_limits():
    group = avp(263, b"leaf")
    for _ in range(aaa.MAX_DEPTH + 1):
        group = avp(284, group)
    with pytest.raises(aaa.AAAError, match="depth"):
        aaa.walk_diameter_avps(group)
    with pytest.raises(aaa.AAAError, match="excessive"):
        aaa.walk_diameter_avps(avp(987654, b"") * (aaa.MAX_ITEMS + 1))


@pytest.mark.parametrize("bad", [None, 1, "bytes", [], {}, -1])
def test_public_type_contract(bad):
    for fn in (aaa.parse_radius, aaa.parse_diameter, aaa.walk_diameter_avps):
        with pytest.raises(aaa.AAAError):
            fn(bad)
    with pytest.raises(aaa.AAAError):
        aaa.decrypt_user_password(bad, b"x", bytes(16))
    with pytest.raises(aaa.AAAError):
        aaa.decrypt_user_password(bytes(16), bad, bytes(16))
    with pytest.raises(aaa.AAAError):
        aaa.verify_radius_response(bad, RFC_REQUEST, b"x")


def test_deterministic_malformed_contract():
    rng = random.Random(2865)
    for _ in range(300):
        raw = rng.randbytes(rng.randrange(0, 300))
        for fn in (aaa.parse_radius, aaa.parse_diameter, aaa.walk_diameter_avps):
            try:
                json.dumps(fn(raw))
            except aaa.AAAError:
                pass


def test_memoryview_size_limits_and_released_view():
    # len(view) is only 1025, but the backing bytes exceed RADIUS's 4096 cap.
    from array import array
    large = memoryview(array("I", [0] * 1025))
    with pytest.raises(aaa.AAAError, match="size"):
        aaa.parse_radius(large)
    assert aaa.parse_radius(memoryview(RFC_REQUEST))["identifier"] == 0
    closed = memoryview(b"abc")
    closed.release()
    for fn in (aaa.parse_radius, aaa.parse_diameter, aaa.walk_diameter_avps):
        with pytest.raises(aaa.AAAError):
            fn(closed)


def test_cli(tmp_path, capsys):
    file = tmp_path / "packet.hex"
    file.write_text(RFC_REQUEST.hex())
    secret = tmp_path / "secret"
    secret.write_bytes(b"xyzzy5461")
    assert aaa.main(["radius", str(file), "--hex", "--secret-file", str(secret)]) == 0
    assert json.loads(capsys.readouterr().out)["attributes"][1]["plaintext_text"] == "arctangent"
    assert aaa.main(["--help"]) == 0
    assert aaa.main([]) == 2
    assert aaa.main(["radius", str(file) + "missing"]) == 2
    file.write_text("not hex")
    assert aaa.main(["radius", str(file), "--hex"]) == 2
