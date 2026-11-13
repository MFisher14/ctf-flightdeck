"""Known-answer tests for the KNX Secure decrypt-with-key helper (B-161).

Independent oracles, none produced by the module under test:

* ``tests/fixtures/knx_secure/xknx_SecureTest.knxkeys``: an ETS-made keyring
  (password ``test``) shipped as xknx test data; its ETS signature, its keys, and
  the Data Secure telegrams xknx's tests decode with them (expected APDUs stated
  there: GroupValueResponse (116, 41, 41), GroupValueWrite (255, 0, 5));
* the KNX IP Secure specification examples (secure-wrapper routing frame,
  backbone key 00..0f; device-authentication / user-password KDF examples;
  SESSION_RESPONSE CBC-MAC);
* RFC 7748 section 6.1 X25519 vector;
* an authentication-only frame and a session response built here with a
  separate AES implementation (pycryptodome) from the specified block layout.
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest
from Crypto.Cipher import AES

import sec_bas_knx_secure as K


FIXTURE = Path(__file__).parent / "fixtures" / "knx_secure" / "xknx_SecureTest.knxkeys"
GROUP_KEY_0_4_0 = "dfdf23a59fbb40404091d1c162087e8b"

# xknx test_data_secure_group_receive: L_Data.ind 4.0.9 -> 0/4/0, seq 155806854986
RESPONSE_FRAME = bytes.fromhex("29003ce0400904001103f110002446cfef4ac085e7092ab062b44d")
# xknx test_data_secure_group_send_extended: 5.0.1 -> 0/4/0, GroupValueWrite (255, 0, 5)
EXTENDED_FRAME = bytes.fromhex("2900" "3ce0500104001103f11000254ae1cb67cd98e577b519be47bb")
# KNX IP Secure spec example: routing SECURE_WRAPPER with backbone key 00..0f
WRAPPER = bytes.fromhex(
    "061009500037" "0000" "c0c1c2c3c4c5" "00fa12345678" "affe"
    "b7ee7e8a1c2f7bbabec775fd6e10d0bc4b" "7212a03aaae49da85689774c1d2b4da4"
)
WRAPPER_INNER = "0610053000112900bcd011590ade010081"
BACKBONE_EXAMPLE = bytes(range(16))


@pytest.fixture(scope="module")
def keyring() -> dict:
    return K.load_keyring(FIXTURE.read_bytes(), "test")


def test_fixture_is_the_documented_keyring():
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == (
        "cd82c69e7a3fe13259a37fdd96219337fe44f52ab08eb79e1daef4c439f5c34d"
    )


# ------------------------------------------------------------------ KDFs (spec examples)

def test_password_kdfs_match_spec_examples():
    assert K.derive_device_authentication_code("trustme").hex() == "e158e4012047bd6cc41aafbc5c04c1fc"
    assert K.derive_user_password_key("secret").hex() == "03fcedb66660251ec81a1a716901696a"


# ------------------------------------------------------------------ keyring

def test_keyring_decrypts_with_verified_signature(keyring):
    assert keyring["signature_verified"] is True
    assert keyring["project"] == "SecureTest"
    assert keyring["group_keys"]["0/4/0"] == GROUP_KEY_0_4_0
    assert set(keyring["group_keys"]) == {"0/4/0", "0/4/3", "0/4/4", "0/4/5"}
    assert keyring["backbone"]["key"] == "15ece0a72bc8606220a88a9f6df4487c"
    assert keyring["backbone"]["multicast_address"] == "224.0.23.13"
    tunnel = next(row for row in keyring["interfaces"] if row["individual_address"] == "5.0.1")
    assert tunnel["password"] == "weinzierl_tunnel_1"
    assert tunnel["user_id"] == "2"
    assert tunnel["user_password_key"] == K.derive_user_password_key("weinzierl_tunnel_1").hex()
    assert tunnel["groups"]["0/4/0"] == ["4.0.1", "4.0.9"]
    assert keyring["devices"]["4.0.9"]["sequence_number"] == "155806854915"
    assert len(bytes.fromhex(keyring["devices"]["4.0.9"]["tool_key"])) == 16


def test_keyring_wrong_password_fails_on_signature():
    with pytest.raises(K.KNXSecureError, match="Signature does not match"):
        K.load_keyring(FIXTURE.read_bytes(), "wrong")


def test_keyring_edit_breaks_signature():
    data = FIXTURE.read_bytes().replace(b'Latency="1000"', b'Latency="1001"')
    assert data != FIXTURE.read_bytes()
    with pytest.raises(K.KNXSecureError, match="Signature does not match"):
        K.load_keyring(data, "test")


def test_keyring_wrong_password_without_signature_check_still_fails_on_passwords():
    with pytest.raises(K.KNXSecureError, match="wrong keyring password"):
        K.load_keyring(FIXTURE.read_bytes(), "wrong", verify_signature=False)


def test_keyring_rejects_non_keyring_and_doctype():
    with pytest.raises(K.KNXSecureError, match="not an ETS keyring"):
        K.load_keyring(b"<Other xmlns='urn:x'/>", "test")
    with pytest.raises(K.KNXSecureError, match="DOCTYPE is forbidden"):
        K.load_keyring(b'<!DOCTYPE x [<!ENTITY a "b">]><Keyring xmlns="http://knx.org/xml/keyring/1"/>', "t")
    # the real keyring with only a DOCTYPE added: everything else (Created, Signature) is valid,
    # so nothing but the DOCTYPE check can reject it
    data = FIXTURE.read_bytes()
    declaration_end = data.index(b"?>") + 2
    with_doctype = data[:declaration_end] + b"\n<!DOCTYPE Keyring>" + data[declaration_end:]
    with pytest.raises(K.KNXSecureError, match="DOCTYPE is forbidden"):
        K.load_keyring(with_doctype, "test")


def _keyring_crypto() -> tuple[bytes, bytes]:
    """Password hash and IV of the fixture, computed here from the ETS recipe."""
    pw_hash = hashlib.pbkdf2_hmac("sha256", b"test", b"1.keyring.ets.knx.org", 65536, 16)
    iv = hashlib.sha256(b"2023-01-30T19:17:06").digest()[:16]
    return pw_hash, iv


def _with_tunnel_password(plain: bytes) -> bytes:
    pw_hash, iv = _keyring_crypto()
    value = base64.b64encode(AES.new(pw_hash, AES.MODE_CBC, iv=iv).encrypt(plain))
    data = FIXTURE.read_bytes()
    old = b'Password="sQZMSoHR/gBjj1guSY2gh4Sziv8cAiwar9F1amBRfE4="'
    assert data.count(old) == 1
    return data.replace(old, b'Password="' + value + b'"')


def test_keyring_password_padding_is_checked_byte_by_byte():
    def tunnel(keyring):
        return next(row for row in keyring["interfaces"] if row["individual_address"] == "5.0.1")

    # 8 random bytes | "crafted-pw" (10) | 14 bytes of padding value 14: decrypts (control)
    good = b"\x5a" * 8 + b"crafted-pw" + bytes((14,)) * 14
    assert tunnel(K.load_keyring(_with_tunnel_password(good), "test",
                                 verify_signature=False))["password"] == "crafted-pw"
    # same length byte, one padding byte wrong: the length byte alone must not pass it
    bad = bytearray(good)
    bad[-5] = 0x0D
    with pytest.raises(K.KNXSecureError, match="5.0.1/Password has invalid padding"):
        K.load_keyring(_with_tunnel_password(bytes(bad)), "test", verify_signature=False)


def test_keyring_signature_must_be_sixteen_bytes():
    data = FIXTURE.read_bytes()
    full = base64.b64decode("4SLrRPMpwFql5ytGzPjeBw==")
    assert len(full) == 16
    # a 1-byte Signature equal to the true first byte would pass a prefix comparison
    short = data.replace(b'Signature="4SLrRPMpwFql5ytGzPjeBw=="',
                         b'Signature="' + base64.b64encode(full[:1]) + b'"')
    assert short != data
    with pytest.raises(K.KNXSecureError, match="Signature is 1 bytes, expected 16"):
        K.load_keyring(short, "test")


# ------------------------------------------------------------------ Data Secure

def test_data_secure_response_known_answer(keyring):
    result = K.decrypt_data_secure(RESPONSE_FRAME, keyring["group_keys"])
    assert result["mac_verified"] is True
    assert result["mode"] == "authenticated-decrypted"
    assert result["key_id"] == "0/4/0"
    assert result["sequence_number"] == 155806854986
    assert result["source"] == "4.0.9"
    assert result["plain_apdu_hex"] == "0040742929"
    assert result["decoded"]["apci"]["service"] == "GroupValueResponse"
    assert result["decoded"]["apci"]["extended_data_hex"] == "742929"
    # rebuilt plain frame: same header, NPDU length 4, TPDU 00 40 74 29 29
    assert result["plain_cemi_hex"] == "29003ce0400904000400" + "40742929"


def test_data_secure_extended_write_known_answer():
    result = K.decrypt_data_secure(EXTENDED_FRAME, GROUP_KEY_0_4_0, dpt="232.600")
    assert result["plain_apdu_hex"] == "0080ff0005"
    assert result["decoded"]["apci"]["service"] == "GroupValueWrite"
    assert (result["decoded"]["dpt"]["red"], result["decoded"]["dpt"]["green"],
            result["decoded"]["dpt"]["blue"]) == (255, 0, 5)


def test_data_secure_inside_tunnelling_request(keyring):
    cemi = RESPONSE_FRAME
    frame = bytes.fromhex("06100420") + (10 + len(cemi)).to_bytes(2, "big") + bytes.fromhex("04011700") + cemi
    result = K.decrypt_data_secure(frame, keyring["group_keys"])
    assert result["plain_apdu_hex"] == "0040742929"
    assert result["knxnetip_prefix_hex"] == "0610042000" + f"{10 + len(cemi):02x}" + "04011700"


def test_data_secure_wrong_key_and_tampering_fail():
    wrong = bytes(16)
    with pytest.raises(K.KNXSecureError, match="MAC verification failed"):
        K.decrypt_data_secure(RESPONSE_FRAME, wrong)
    tampered = RESPONSE_FRAME[:-1] + bytes((RESPONSE_FRAME[-1] ^ 1,))
    with pytest.raises(K.KNXSecureError, match="MAC verification failed"):
        K.decrypt_data_secure(tampered, GROUP_KEY_0_4_0)
    payload_flip = bytearray(RESPONSE_FRAME)
    payload_flip[20] ^= 0x10
    with pytest.raises(K.KNXSecureError, match="MAC verification failed"):
        K.decrypt_data_secure(bytes(payload_flip), GROUP_KEY_0_4_0)
    # the destination is bound into B0/CTR: same bytes to another group fail
    moved = bytearray(RESPONSE_FRAME)
    moved[7] = 0x01
    with pytest.raises(K.KNXSecureError, match="MAC verification failed"):
        K.decrypt_data_secure(bytes(moved), GROUP_KEY_0_4_0)


def test_data_secure_missing_key_and_plain_frame_named():
    with pytest.raises(K.KNXSecureError, match="no key for group address 0/4/0"):
        K.decrypt_data_secure(RESPONSE_FRAME, {"1/2/3": GROUP_KEY_0_4_0})
    plain = bytes.fromhex("29003ce040090400040040742929")
    with pytest.raises(K.KNXSecureError, match="not a Data Secure APDU"):
        K.decrypt_data_secure(plain, GROUP_KEY_0_4_0)


def _independent_cbc_mac(key: bytes, block_0: bytes, ad: bytes, payload: bytes) -> bytes:
    stream = block_0 + len(ad).to_bytes(2, "big") + ad + payload
    stream += bytes(-len(stream) % 16)
    state = bytes(16)
    ecb = AES.new(key, AES.MODE_ECB)
    for offset in range(0, len(stream), 16):
        state = ecb.encrypt(bytes(a ^ b for a, b in zip(state, stream[offset:offset + 16])))
    return state


def test_data_secure_authentication_only_frame():
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    seq = (123456789).to_bytes(6, "big")
    src, dst = bytes.fromhex("1101"), bytes.fromhex("0a03")  # 1.1.1 -> 1/2/3
    apdu = bytes.fromhex("0080") + b"\x0c\x1a"  # GroupValueWrite, DPT 9 payload
    scf = b"\x00"  # authentication only, S-A_Data
    block_0 = seq + src + dst + bytes((0, 0x80, 0x03, 0xF1, 0, 0))
    mac = _independent_cbc_mac(key, block_0, scf + apdu, b"")[:4]
    tpdu = b"\x03\xf1" + scf + seq + apdu + mac
    frame = bytes.fromhex("2900bce0") + src + dst + bytes((len(tpdu) - 1,)) + tpdu
    result = K.decrypt_data_secure(frame, key, dpt="9")
    assert result["mode"] == "authenticated"
    assert result["plain_apdu_hex"] == apdu.hex()
    # DPT 9 0x0C1A: sign 0, exponent 1, mantissa 1050 -> 0.01 * 1050 * 2 = 21.0
    assert result["decoded"]["dpt"]["value"] == pytest.approx(21.0)
    bad = frame[:-1] + bytes((frame[-1] ^ 0xFF,))
    with pytest.raises(K.KNXSecureError, match="authentication-only"):
        K.decrypt_data_secure(bad, key)


# ------------------------------------------------------------------ IP Secure

def test_cbc_mac_spec_examples():
    block_0 = bytes.fromhex("c0c1c2c3c4c500fa12345678affe0011")
    assert K.cbc_mac(BACKBONE_EXAMPLE, bytes.fromhex("061009500037" "0000"),
                     bytes.fromhex(WRAPPER_INNER), block_0).hex() == "bd0a294b952554b23539204c2271d26b"
    aad = bytes.fromhex(
        "0610095200380001b752be246459260f6b0c4801fbd5a67599f83b4057b3ef1e79e469ac17234e15")
    assert K.cbc_mac(K.derive_device_authentication_code("trustme"), aad).hex() == (
        "da3dc6af79896aa6ee7573d69950c283")


def test_secure_wrapper_known_answer():
    result = K.decrypt_secure_wrapper(WRAPPER, BACKBONE_EXAMPLE)
    assert result["mac_verified"] is True
    assert result["inner_hex"] == WRAPPER_INNER
    assert result["mode"] == "secure-routing-multicast"
    assert result["serial_number_hex"] == "00fa12345678"
    assert result["message_tag"] == 0xAFFE
    assert result["inner"]["service"] == "ROUTING_INDICATION"
    assert result["inner"]["cemi"]["apci"]["service"] == "GroupValueWrite"


def test_secure_wrapper_wrong_key_and_tamper_fail():
    with pytest.raises(K.KNXSecureError, match="MAC verification failed"):
        K.decrypt_secure_wrapper(WRAPPER, bytes(16))
    tampered = bytearray(WRAPPER)
    tampered[30] ^= 1
    with pytest.raises(K.KNXSecureError, match="MAC verification failed"):
        K.decrypt_secure_wrapper(bytes(tampered), BACKBONE_EXAMPLE)
    header_changed = bytearray(WRAPPER)
    header_changed[7] = 1  # session id is authenticated data
    with pytest.raises(K.KNXSecureError):
        K.decrypt_secure_wrapper(bytes(header_changed), BACKBONE_EXAMPLE)
    with pytest.raises(K.KNXSecureError, match="not SECURE_WRAPPER"):
        K.decrypt_secure_wrapper(bytes.fromhex(WRAPPER_INNER), BACKBONE_EXAMPLE)


def test_session_key_from_x25519_rfc7748():
    alice = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    bob_public = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert K.session_key_from_x25519(alice, bob_public) == hashlib.sha256(shared).digest()[:16]


def _ctr_first_block(key: bytes, counter_0: bytes, data: bytes) -> bytes:
    stream = AES.new(key, AES.MODE_ECB).encrypt(counter_0)
    return bytes(a ^ b for a, b in zip(data, stream))


def test_session_response_and_authenticate_macs():
    client_public = bytes(range(32))
    server_public = bytes(range(100, 132))
    xor = bytes(a ^ b for a, b in zip(client_public, server_public))
    code = K.derive_device_authentication_code("trustme")
    header = bytes.fromhex("061009520038") + b"\x00\x07"
    mac = _ctr_first_block(code, bytes(14) + b"\xff\x00",
                           _independent_cbc_mac(code, bytes(16), header + xor, b""))
    frame = header + server_public + mac
    good = K.verify_session_response(frame, client_public, code)
    assert good == {"session_id": 7, "server_public_hex": server_public.hex(), "mac_valid": True}
    assert K.verify_session_response(frame, client_public, K.derive_device_authentication_code("x"))[
        "mac_valid"] is False

    user_key = K.derive_user_password_key("secret")
    auth_header = bytes.fromhex("061009530018") + b"\x00\x02"
    auth_mac = _ctr_first_block(user_key, bytes(14) + b"\xff\x00",
                                _independent_cbc_mac(user_key, bytes(16), auth_header + xor, b""))
    inner = auth_header + auth_mac
    assert K.verify_session_authenticate(inner, client_public, server_public, user_key) == {
        "user_id": 2, "mac_valid": True}
    assert K.verify_session_authenticate(inner, client_public, server_public,
                                         K.derive_user_password_key("nope"))["mac_valid"] is False


def test_secure_session_wrapper_roundtrip_with_derived_session_key():
    """A tunnelling wrapper encrypted here (pycryptodome CTR/ECB) under an X25519 session key."""
    private = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    peer = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    key = K.session_key_from_x25519(private, peer)
    inner = bytes.fromhex("061004200015" "04011700" "2900bce011010a03010081")
    nonce = (5).to_bytes(6, "big") + bytes.fromhex("00fa12345678") + b"\x00\x00"
    total = 6 + 16 + len(inner) + 16
    header = bytes.fromhex("06100950") + total.to_bytes(2, "big")
    session = b"\x00\x09"
    cbc = _independent_cbc_mac(key, nonce + len(inner).to_bytes(2, "big"), header + session, inner)
    ctr = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=nonce + b"\xff\x00")
    enc_mac = ctr.encrypt(cbc)
    ciphertext = ctr.encrypt(inner)
    frame = header + session + nonce + ciphertext + enc_mac
    result = K.decrypt_secure_wrapper(frame, key)
    assert result["mode"] == "secure-session-unicast"
    assert result["session_id"] == 9
    assert result["inner_hex"] == inner.hex()
    assert result["inner"]["service"] == "TUNNELLING_REQUEST"


# ------------------------------------------------------------------ CLI

def test_cli_keyring_data_secure_and_wrapper(tmp_path, capsys):
    password = tmp_path / "pw.txt"
    password.write_text("test\n")
    assert K.main(["keyring", str(FIXTURE), "--password-file", str(password)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["group_keys"]["0/4/0"] == GROUP_KEY_0_4_0

    frames = tmp_path / "frames.hex"
    frames.write_text(f"# two telegrams\n{RESPONSE_FRAME.hex()}\n{EXTENDED_FRAME.hex()}\n")
    assert K.main(["data-secure", str(frames), "--hex", "--keyring", str(FIXTURE),
                   "--password-file", str(password)]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [row["plain_apdu_hex"] for row in rows] == ["0040742929", "0080ff0005"]

    wrapper = tmp_path / "wrapper.bin"
    wrapper.write_bytes(WRAPPER)
    assert K.main(["wrapper", str(wrapper), "--key", BACKBONE_EXAMPLE.hex()]) == 0
    assert json.loads(capsys.readouterr().out)["inner_hex"] == WRAPPER_INNER

    assert K.main(["wrapper", str(wrapper), "--key", "00" * 16]) == 2
    assert "MAC verification failed" in capsys.readouterr().err
    assert K.main(["data-secure", str(frames), "--hex"]) == 2
    assert "needs --key or --keyring" in capsys.readouterr().err


# ------------------------------------------------------------------ key selection

def _independent_data_secure_frame(key: bytes, src: bytes, dst: bytes, ctrl2: int, seq: int,
                                   apdu: bytes, *, scf: int) -> bytes:
    """Auth+conf S-A_Data frame built from the KNX CCM layout with pycryptodome (not the module)."""
    seq_raw = seq.to_bytes(6, "big")
    block_0 = seq_raw + src + dst + bytes((0, ctrl2 & 0x8F, 0x03, 0xF1, 0, len(apdu)))
    mac = _independent_cbc_mac(key, block_0, bytes((scf,)), apdu)
    counter_0 = seq_raw + src + dst + bytes(4) + b"\x01\x00"
    # the 4-byte MAC takes the first keystream bytes and the APDU the ones after it
    stream = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=counter_0).encrypt(mac[:4] + apdu)
    enc_mac, enc_apdu = stream[:4], stream[4:]
    tpdu = b"\x03\xf1" + bytes((scf,)) + seq_raw + enc_apdu + enc_mac
    return bytes((0x29, 0x00, 0xB0, ctrl2)) + src + dst + bytes((len(tpdu) - 1,)) + tpdu


def test_data_secure_tool_key_found_by_destination_or_source():
    tool_key = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
    device, tool = bytes.fromhex("1105"), bytes.fromhex("11fa")  # 1.1.5 and 1.1.250
    apdu = bytes.fromhex("0300")  # DeviceDescriptor_Read (APCI 0x300)
    request = _independent_data_secure_frame(tool_key, tool, device, 0x60, 77, apdu, scf=0x90)
    response = _independent_data_secure_frame(tool_key, device, tool, 0x60, 78, apdu, scf=0x90)
    for frame, seq in ((request, 77), (response, 78)):
        result = K.decrypt_data_secure(frame, {"1.1.5": tool_key})
        assert result["key_id"] == "1.1.5"
        assert result["sequence_number"] == seq
        assert result["plain_apdu_hex"] == apdu.hex()
        assert result["mode"] == "authenticated-decrypted"
    with pytest.raises(K.KNXSecureError, match="no tool key for individual address 1.1.5 or 1.1.250"):
        K.decrypt_data_secure(request, {"1.1.6": tool_key, "0/4/0": GROUP_KEY_0_4_0})
    with pytest.raises(K.KNXSecureError, match="MAC verification failed"):
        K.decrypt_data_secure(request, {"1.1.5": bytes(16)})


def test_group_key_lookup_by_raw_address():
    # 0/4/0 is raw 0x0400 = 1024: an integer or decimal-text key works as well as a/b/c
    for keys in ({1024: GROUP_KEY_0_4_0}, {"1024": GROUP_KEY_0_4_0}):
        assert K.decrypt_data_secure(RESPONSE_FRAME, keys)["plain_apdu_hex"] == "0040742929"
    with pytest.raises(K.KNXSecureError, match="no key for group address 0/4/0"):
        K.decrypt_data_secure(RESPONSE_FRAME, {1025: GROUP_KEY_0_4_0})


def test_keyring_keys_merges_group_and_tool_keys(keyring):
    keys = K.keyring_keys(keyring)
    assert keys["0/4/0"] == GROUP_KEY_0_4_0
    tool_keys = {ia: row["tool_key"] for ia, row in keyring["devices"].items() if row.get("tool_key")}
    assert tool_keys and all(keys[ia] == key for ia, key in tool_keys.items())
    assert set(keys) == set(keyring["group_keys"]) | set(tool_keys)


def test_keyring_signature_required_and_size_cap():
    data = FIXTURE.read_bytes()
    start = data.index(b' Signature="')
    end = data.index(b'"', start + len(b' Signature="')) + 1
    unsigned = data[:start] + data[end:]
    with pytest.raises(K.KNXSecureError, match="no Signature"):
        K.load_keyring(unsigned, "test")
    assert K.load_keyring(unsigned, "test", verify_signature=False)["group_keys"]["0/4/0"] == GROUP_KEY_0_4_0
    with pytest.raises(K.KNXSecureError, match="cap"):
        K.load_keyring(b" " * (K.MAX_KEYRING + 1), "test")


def test_wrong_key_length_named():
    with pytest.raises(K.KNXSecureError, match="16 bytes"):
        K.decrypt_secure_wrapper(WRAPPER, bytes(15))
    with pytest.raises(K.KNXSecureError, match="32 bytes"):
        K.session_key_from_x25519("00" * 31, "00" * 32)


def test_cli_x25519_session_key_and_keyring_errors(tmp_path, capsys):
    private = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    peer = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    wrapper = tmp_path / "wrapper.bin"
    wrapper.write_bytes(WRAPPER)
    assert K.main(["wrapper", str(wrapper), "--private-key", private]) == 2
    assert "go together" in capsys.readouterr().err
    # the X25519-derived key is not the backbone key of this frame: the MAC check names it
    assert K.main(["wrapper", str(wrapper), "--private-key", private, "--peer-public", peer]) == 2
    assert "MAC verification failed" in capsys.readouterr().err
    assert K.main(["data-secure", str(wrapper), "--keyring", str(FIXTURE)]) == 2
    assert "--keyring needs --password-file" in capsys.readouterr().err
    password = tmp_path / "pw.txt"
    password.write_text("test\n")
    # with no --key the keyring's backbone key is used: the spec example (key 00..0f) fails, a
    # routing wrapper sealed here under the keyring's backbone key opens
    assert K.main(["wrapper", str(wrapper), "--keyring", str(FIXTURE), "--password-file", str(password)]) == 2
    assert "wrong backbone/session key" in capsys.readouterr().err
    backbone = bytes.fromhex("15ece0a72bc8606220a88a9f6df4487c")
    inner = bytes.fromhex(WRAPPER_INNER)
    nonce = (9).to_bytes(6, "big") + bytes.fromhex("00fa12345678") + b"\xaf\xfe"
    header = bytes.fromhex("06100950") + (6 + 16 + len(inner) + 16).to_bytes(2, "big")
    cbc = _independent_cbc_mac(backbone, nonce + len(inner).to_bytes(2, "big"), header + b"\x00\x00", inner)
    ctr = AES.new(backbone, AES.MODE_CTR, nonce=b"", initial_value=nonce + b"\xff\x00")
    enc_mac = ctr.encrypt(cbc)
    sealed = tmp_path / "sealed.bin"
    sealed.write_bytes(header + b"\x00\x00" + nonce + ctr.encrypt(inner) + enc_mac)
    assert K.main(["wrapper", str(sealed), "--keyring", str(FIXTURE), "--password-file", str(password)]) == 0
    assert json.loads(capsys.readouterr().out)["inner_hex"] == WRAPPER_INNER


def _seal_wrapper(key: bytes, inner: bytes, sequence: int = 9) -> bytes:
    """Routing SECURE_WRAPPER (session 0) sealed with pycryptodome from the KNX IP Secure layout."""
    nonce = sequence.to_bytes(6, "big") + bytes.fromhex("00fa12345678") + b"\xaf\xfe"
    header = bytes.fromhex("06100950") + (6 + 16 + len(inner) + 16).to_bytes(2, "big")
    cbc = _independent_cbc_mac(key, nonce + len(inner).to_bytes(2, "big"), header + b"\x00\x00", inner)
    ctr = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=nonce + b"\xff\x00")
    enc_mac = ctr.encrypt(cbc)
    return header + b"\x00\x00" + nonce + ctr.encrypt(inner) + enc_mac


def test_cli_wrapper_opens_data_secure_inside_with_keyring(tmp_path, capsys):
    password = tmp_path / "pw.txt"
    password.write_text("test\n")
    backbone = bytes.fromhex("15ece0a72bc8606220a88a9f6df4487c")  # the fixture's backbone key
    # ROUTING_INDICATION carrying the xknx Data Secure telegram, inside a backbone-key wrapper
    routing = bytes.fromhex("06100530") + (6 + len(RESPONSE_FRAME)).to_bytes(2, "big") + RESPONSE_FRAME
    sealed = tmp_path / "sealed.bin"
    sealed.write_bytes(_seal_wrapper(backbone, routing))
    base = ["wrapper", str(sealed), "--keyring", str(FIXTURE), "--password-file", str(password)]

    assert K.main(base) == 0
    plain_row = json.loads(capsys.readouterr().out)
    assert plain_row["inner_hex"] == routing.hex()
    assert "data_secure" not in plain_row  # only with --data-secure-keyring

    assert K.main(base + ["--data-secure-keyring"]) == 0
    row = json.loads(capsys.readouterr().out)
    assert row["inner_hex"] == routing.hex()
    assert row["data_secure"]["mac_verified"] is True
    assert row["data_secure"]["key_id"] == "0/4/0"
    assert row["data_secure"]["plain_apdu_hex"] == "0040742929"
    assert row["data_secure"]["knxnetip_prefix_hex"] == routing[:6].hex()

    # with --key instead of --keyring there are no group keys to open the inner APDU with
    assert K.main(["wrapper", str(sealed), "--key", backbone.hex(), "--data-secure-keyring"]) == 2
    assert "--data-secure-keyring needs --keyring" in capsys.readouterr().err


# ------------------------------------------------------------------ KNX IoT OSCORE (RFC 8613 App. C)

MASTER_SECRET = "0102030405060708090a0b0c0d0e0f10"
MASTER_SALT = "9e7ca92223786340"
ID_CONTEXT = "37cbf3210017a2d3"
# C.4 / C.7 / C.8: client Sender ID empty, server Sender ID 01, Master Salt present
C4_REQUEST = "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e"
C4_UNPROTECTED = "44015d1f00003974396c6f63616c686f737483747631"
C5_REQUEST = "440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0"
C5_UNPROTECTED = "440171c30000b932396c6f63616c686f737483747631"
C6_REQUEST = ("44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3"
              "ff72cd7273fd331ac45cffbe55c3")
C6_UNPROTECTED = "44012f8eef9bbf7a396c6f63616c686f737483747631"
C7_RESPONSE = "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106"
C8_RESPONSE = "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e"
RESPONSE_UNPROTECTED = "64455d1f00003974ff48656c6c6f20576f726c6421"


@pytest.mark.parametrize("salt, sender, recipient, context, sender_key, recipient_key, common_iv", [
    # C.1.1 client and C.1.2 server
    (MASTER_SALT, "", "01", None, "f0910ed7295e6ad4b54fc793154302ff",
     "ffb14e093c94c9cac9471648b4f98710", "4622d4dd6d944168eefb54987c"),
    (MASTER_SALT, "01", "", None, "ffb14e093c94c9cac9471648b4f98710",
     "f0910ed7295e6ad4b54fc793154302ff", "4622d4dd6d944168eefb54987c"),
    # C.2.1 client, no Master Salt
    ("", "00", "01", None, "321b26943253c7ffb6003b0b64d74041",
     "e57b5635815177cd679ab4bcec9d7dda", "be35ae297d2dace910c52e99f9"),
    # C.3.1 client, with ID Context
    (MASTER_SALT, "", "01", ID_CONTEXT, "af2a1300a5e95788b356336eeecd2b92",
     "e39a0c7c77b43f03b4b39ab9a268699f", "2ca58fb85ff1b81c0b7181b85e"),
])
def test_oscore_key_derivation_rfc8613_vectors(salt, sender, recipient, context, sender_key,
                                               recipient_key, common_iv):
    keys = K.derive_oscore_context(MASTER_SECRET, sender_id=sender, recipient_id=recipient,
                                   master_salt=salt, id_context=context)
    assert (keys["sender_key"].hex(), keys["recipient_key"].hex(), keys["common_iv"].hex()) == (
        sender_key, recipient_key, common_iv)


def test_oscore_nonce_and_aad_rfc8613_vectors():
    common_iv = bytes.fromhex("4622d4dd6d944168eefb54987c")
    assert K.oscore_nonce(common_iv, b"", b"").hex() == "4622d4dd6d944168eefb54987c"  # C.1.1 PIV 0
    assert K.oscore_nonce(common_iv, b"\x01", b"").hex() == "4722d4dd6d944169eefb54987c"
    assert K.oscore_nonce(common_iv, b"", b"\x14").hex() == "4622d4dd6d944168eefb549868"  # C.4
    # RFC 8613 5.4 example (request_kid 00, request_piv 25) and C.4
    assert K.oscore_aad(b"\x00", b"\x25").hex() == "8368456e63727970743040498501810a4100412540"
    assert K.oscore_aad(b"", b"\x14").hex() == "8368456e63727970743040488501810a40411440"


@pytest.mark.parametrize("message, kwargs, unprotected, nonce", [
    (C4_REQUEST, {"master_salt": MASTER_SALT}, C4_UNPROTECTED, "4622d4dd6d944168eefb549868"),
    (C5_REQUEST, {}, C5_UNPROTECTED, "bf35ae297d2dace910c52e99ed"),
    (C6_REQUEST, {"master_salt": MASTER_SALT}, C6_UNPROTECTED, "2ca58fb85ff1b81c0b7181b84a"),
])
def test_oscore_request_known_answer(message, kwargs, unprotected, nonce):
    result = K.decrypt_oscore(bytes.fromhex(message), MASTER_SECRET, **kwargs)
    assert result["tag_verified"] is True
    assert result["direction"] == "request"
    assert result["plaintext_hex"] == "01b3747631"  # GET, Uri-Path "tv1"
    assert result["nonce_hex"] == nonce
    assert result["unprotected_hex"] == unprotected
    assert result["inner_code_text"] == "0.01"
    assert result["decoded"]["uri_path"] == "/tv1"
    assert [row["value"] for row in result["decoded"]["options"] if row["number"] == 3] == ["localhost"]
    assert "oscore" not in result["decoded"]


def test_oscore_request_kid_context_is_taken_from_the_option():
    result = K.decrypt_oscore(bytes.fromhex(C6_REQUEST), MASTER_SECRET, master_salt=MASTER_SALT)
    assert result["id_context_hex"] == ID_CONTEXT
    assert K.decrypt_oscore(bytes.fromhex(C6_REQUEST), MASTER_SECRET, master_salt=MASTER_SALT,
                            id_context=ID_CONTEXT)["unprotected_hex"] == C6_UNPROTECTED
    with pytest.raises(K.KNXSecureError, match="differs from the kid context"):
        K.decrypt_oscore(bytes.fromhex(C6_REQUEST), MASTER_SECRET, master_salt=MASTER_SALT,
                         id_context="00")


@pytest.mark.parametrize("message, nonce, piv", [
    (C7_RESPONSE, "4622d4dd6d944168eefb549868", "14"),  # no Partial IV: the request's nonce
    (C8_RESPONSE, "4722d4dd6d944169eefb54987c", "00"),  # own Partial IV 0 under Sender ID 01
])
def test_oscore_response_known_answer(message, nonce, piv):
    result = K.decrypt_oscore(bytes.fromhex(message), MASTER_SECRET, master_salt=MASTER_SALT,
                              responder_id="01", request_kid="", request_piv="14")
    assert result["direction"] == "response"
    assert result["plaintext_hex"] == "45ff48656c6c6f20576f726c6421"
    assert result["nonce_hex"] == nonce
    assert result["partial_iv_hex"] == piv
    assert result["aad_hex"] == "8368456e63727970743040488501810a40411440"
    assert result["unprotected_hex"] == RESPONSE_UNPROTECTED
    assert result["inner_code_text"] == "2.05"
    assert bytes.fromhex(result["decoded"]["payload_hex"]) == b"Hello World!"


def test_oscore_inner_class_e_option_replaces_outer_copy():
    """A response sealed here (pycryptodome AES-CCM) with Max-Age both outside (0) and inside (60).

    RFC 8613 4.1: the inner (Class E) value is the real one; the outer copy is for proxies.
    Key, nonce and AAD are the C.7 values from the RFC (server Sender Key, request nonce).
    """
    key = bytes.fromhex("ffb14e093c94c9cac9471648b4f98710")
    nonce = bytes.fromhex("4622d4dd6d944168eefb549868")
    aad = bytes.fromhex("8368456e63727970743040488501810a40411440")
    inner = bytes.fromhex("45" "d1013c") + b"\xff" + b"cached"  # 2.05, Max-Age 60, payload
    ccm = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
    ccm.update(aad)
    sealed, tag = ccm.encrypt_and_digest(inner)
    # outer: OSCORE (9) empty, then Max-Age (14) empty = 0
    message = bytes.fromhex("64445d1f00003974" "90" "50") + b"\xff" + sealed + tag
    result = K.decrypt_oscore(message, MASTER_SECRET, master_salt=MASTER_SALT,
                              responder_id="01", request_kid="", request_piv="14")
    assert result["unprotected_hex"] == "64455d1f00003974" "d1013c" "ff" + b"cached".hex()
    max_age = [row["value"] for row in result["decoded"]["options"] if row["number"] == 14]
    assert max_age == [60]


def test_oscore_outer_option_numbered_above_inner_is_merged_in_order():
    """Outer Class U Max-Age (14) above inner Class E Content-Format (12): the merge must sort.

    Sealed here with pycryptodome AES-CCM under the RFC 8613 C.7 key, nonce and AAD. Written
    in arrival order (outer first) the options would need a negative CoAP delta.
    """
    key = bytes.fromhex("ffb14e093c94c9cac9471648b4f98710")
    nonce = bytes.fromhex("4622d4dd6d944168eefb549868")
    aad = bytes.fromhex("8368456e63727970743040488501810a40411440")
    inner = bytes.fromhex("45" "c0") + b"\xff" + b"hi"  # 2.05, Content-Format 0 (text/plain)
    ccm = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=8)
    ccm.update(aad)
    sealed, tag = ccm.encrypt_and_digest(inner)
    # outer: OSCORE (9) empty, then Max-Age (14) = 30
    message = bytes.fromhex("64445d1f00003974" "90" "511e") + b"\xff" + sealed + tag
    result = K.decrypt_oscore(message, MASTER_SECRET, master_salt=MASTER_SALT,
                              responder_id="01", request_kid="", request_piv="14")
    # Content-Format (delta 12, empty) then Max-Age (delta 2, 0x1e), then the inner payload
    assert result["unprotected_hex"] == "64455d1f00003974" "c0" "211e" "ff" + b"hi".hex()
    numbers = [(row["number"], row["value"]) for row in result["decoded"]["options"]]
    assert numbers == [(12, 0), (14, 30)]


def test_coap_option_bytes_rejects_out_of_order_options():
    assert K._coap_option_bytes([(12, b""), (14, b"\x1e")]).hex() == "c0211e"
    with pytest.raises(K.KNXSecureError, match="out of order: option 12 after 14"):
        K._coap_option_bytes([(14, b"\x1e"), (12, b"")])


def test_oscore_missing_partial_iv_named():
    # C.4 request with the OSCORE option cut to 0x08: kid flag, empty kid, no Partial IV
    no_piv = bytes.fromhex("44025d1f00003974396c6f63616c686f7374" "6108" "ff") + bytes(12)
    with pytest.raises(K.KNXSecureError, match="OSCORE request has no Partial IV"):
        K.decrypt_oscore(no_piv, MASTER_SECRET, master_salt=MASTER_SALT)
    with pytest.raises(K.KNXSecureError, match="request Partial IV is empty"):
        K.decrypt_oscore(bytes.fromhex(C7_RESPONSE), MASTER_SECRET, master_salt=MASTER_SALT,
                         responder_id="01", request_kid="", request_piv="")


def test_oscore_wrong_key_material_and_tamper_fail():
    request = bytes.fromhex(C4_REQUEST)
    with pytest.raises(K.KNXSecureError, match="AEAD tag verification failed"):
        K.decrypt_oscore(request, MASTER_SECRET)  # Master Salt missing
    with pytest.raises(K.KNXSecureError, match="AEAD tag verification failed"):
        K.decrypt_oscore(request, "00" * 16, master_salt=MASTER_SALT)
    flipped = bytearray(request)
    flipped[-3] ^= 1
    with pytest.raises(K.KNXSecureError, match="AEAD tag verification failed"):
        K.decrypt_oscore(bytes(flipped), MASTER_SECRET, master_salt=MASTER_SALT)
    response = bytes.fromhex(C7_RESPONSE)
    for kwargs in ({"responder_id": "02", "request_kid": "", "request_piv": "14"},
                   {"responder_id": "01", "request_kid": "", "request_piv": "15"},
                   {"responder_id": "01", "request_kid": "00", "request_piv": "14"}):
        with pytest.raises(K.KNXSecureError, match="AEAD tag verification failed"):
            K.decrypt_oscore(response, MASTER_SECRET, master_salt=MASTER_SALT, **kwargs)


def test_oscore_missing_inputs_named():
    response = bytes.fromhex(C7_RESPONSE)
    with pytest.raises(K.KNXSecureError, match="needs responder_id, request_kid and request_piv"):
        K.decrypt_oscore(response, MASTER_SECRET, master_salt=MASTER_SALT, responder_id="01")
    with pytest.raises(K.KNXSecureError, match="responses only"):
        K.decrypt_oscore(bytes.fromhex(C4_REQUEST), MASTER_SECRET, master_salt=MASTER_SALT,
                         responder_id="01")
    with pytest.raises(K.KNXSecureError, match="no OSCORE option"):
        K.decrypt_oscore(bytes.fromhex(C4_UNPROTECTED), MASTER_SECRET)
    # OSCORE option 0x01 0x14 is a Partial IV without the kid flag: a request needs a kid
    no_kid = bytes.fromhex("44025d1f00003974396c6f63616c686f7374620114ff612f1092f1776f1c1668b3825e")
    with pytest.raises(K.KNXSecureError, match="has no kid"):
        K.decrypt_oscore(no_kid, MASTER_SECRET, master_salt=MASTER_SALT)
    with pytest.raises(K.KNXSecureError, match="Master Secret is empty"):
        K.decrypt_oscore(bytes.fromhex(C4_REQUEST), "", master_salt=MASTER_SALT)


def test_cli_oscore_pairs_response_with_request_by_token(tmp_path, capsys):
    frames = tmp_path / "coap.hex"
    frames.write_text(f"# C.4 request then C.7 response, token 00003974\n{C4_REQUEST}\n{C7_RESPONSE}\n")
    base = ["oscore", str(frames), "--hex", "--master-secret", MASTER_SECRET, "--master-salt", MASTER_SALT]
    assert K.main(base + ["--responder-id", "01"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [row["unprotected_hex"] for row in rows] == [C4_UNPROTECTED, RESPONSE_UNPROTECTED]
    assert K.main(base) == 2
    assert "needs --responder-id" in capsys.readouterr().err

    lone = tmp_path / "lone.bin"
    lone.write_bytes(bytes.fromhex(C8_RESPONSE))
    lone_base = ["oscore", str(lone), "--master-secret", MASTER_SECRET, "--master-salt", MASTER_SALT,
                 "--responder-id", "01"]
    assert K.main(lone_base) == 2
    assert "no request with token 00003974" in capsys.readouterr().err
    assert K.main(lone_base + ["--request-kid", "", "--request-piv", "14"]) == 0
    assert json.loads(capsys.readouterr().out)["unprotected_hex"] == RESPONSE_UNPROTECTED
