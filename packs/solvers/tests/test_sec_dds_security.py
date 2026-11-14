"""Independent vectors and fail-closed checks for sec_dds_security.

Wire bytes are hand fixtures from the OMG DDS-Security 1.2 layouts.  XML and
multipart fixtures follow the published governance/permissions examples and are
constructed here rather than by code in the engine.
"""
from __future__ import annotations

import ast
import base64
import json
import random
from pathlib import Path

import pytest

import sec_dds_security as engine


PREFIX = bytes.fromhex(
    "31 01 14 00 "
    "00 00 00 04 11 22 33 44 01 02 03 04 05 06 07 08 09 0a 0b 0c"
)
BODY = bytes.fromhex(
    "30 01 14 00 "
    "00 00 00 10 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
)
POSTFIX = bytes.fromhex(
    "32 01 28 00 "
    "a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af "
    "00 00 00 01 55 66 77 88 "
    "b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf"
)
SECURE_STREAM = PREFIX + BODY + POSTFIX
RTPS_HEADER = b"RTPS" + bytes((2, 5, 1, 0x0F)) + bytes(range(1, 13))
SECURE_PACKET = RTPS_HEADER + SECURE_STREAM


GOVERNANCE = b"""<?xml version="1.0" encoding="UTF-8"?>
<dds xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <domain_access_rules><domain_rule>
    <domains><id>0</id></domains>
    <allow_unauthenticated_participants>true</allow_unauthenticated_participants>
    <enable_join_access_control>false</enable_join_access_control>
    <enable_key_revision>false</enable_key_revision>
    <discovery_protection_kind>SIGN</discovery_protection_kind>
    <liveliness_protection_kind>ENCRYPT</liveliness_protection_kind>
    <rtps_protection_kind>ENCRYPT_WITH_ORIGIN_AUTHENTICATION</rtps_protection_kind>
    <rtps_psk_protection_kind>NONE</rtps_psk_protection_kind>
    <topic_access_rules>
      <topic_rule>
        <topic_expression>*</topic_expression>
        <enable_discovery_protection>true</enable_discovery_protection>
        <enable_liveliness_protection>true</enable_liveliness_protection>
        <enable_read_access_control>false</enable_read_access_control>
        <enable_write_access_control>false</enable_write_access_control>
        <metadata_protection_kind>SIGN</metadata_protection_kind>
        <data_protection_kind>NONE</data_protection_kind>
      </topic_rule>
      <topic_rule>
        <topic_expression>Command*</topic_expression>
        <enable_discovery_protection>true</enable_discovery_protection>
        <enable_liveliness_protection>true</enable_liveliness_protection>
        <enable_read_access_control>true</enable_read_access_control>
        <enable_write_access_control>true</enable_write_access_control>
        <metadata_protection_kind>ENCRYPT</metadata_protection_kind>
        <data_protection_kind>ENCRYPT</data_protection_kind>
      </topic_rule>
    </topic_access_rules>
  </domain_rule></domain_access_rules>
</dds>"""


PERMISSIONS = b"""<?xml version="1.0" encoding="UTF-8"?>
<dds><permissions><grant name="plant-operator">
  <subject_name>CN=Operator,O=CSCTF</subject_name>
  <validity><not_before>2025-01-01T00:00:00Z</not_before>
            <not_after>2026-01-01T00:00:00Z</not_after></validity>
  <allow_rule>
    <domains><id_range><min>0</min><max>4294967295</max></id_range></domains>
    <publish><topics><topic>*</topic></topics></publish>
  </allow_rule>
  <deny_rule>
    <domains><id>0</id></domains>
    <publish><topics><topic>SafetyCommands</topic></topics></publish>
  </deny_rule>
  <default>ALLOW</default>
</grant></permissions></dds>"""


def _smime(xml: bytes) -> bytes:
    # Contains the DER encoding of id-signedData (1.2.840.113549.1.7.2).
    signature = bytes.fromhex("300b06092a864886f70d010702")
    encoded = base64.b64encode(signature)
    return (b'MIME-Version: 1.0\r\n'
            b'Content-Type: multipart/signed; '
            b'protocol="application/x-pkcs7-signature"; micalg="sha-256"; '
            b'boundary="dds-security-boundary"\r\n\r\n'
            b'This is an S/MIME signed message\r\n'
            b'--dds-security-boundary\r\n'
            b'Content-Type: text/plain; charset="utf-8"\r\n'
            b'Content-Transfer-Encoding: 8bit\r\n\r\n' + xml + b'\r\n'
            b'--dds-security-boundary\r\n'
            b'Content-Type: application/x-pkcs7-signature; name="smime.p7s"\r\n'
            b'Content-Transfer-Encoding: base64\r\n'
            b'Content-Disposition: attachment; filename="smime.p7s"\r\n\r\n' +
            encoded + b'\r\n--dds-security-boundary--\r\n')


def test_mixed_endian_crypto_envelope_vector():
    report = engine.parse_secure_rtps(SECURE_STREAM, framing="submessages")
    assert [row["name"] for row in report["submessages"]] == [
        "SEC_PREFIX", "SEC_BODY", "SEC_POSTFIX"]
    header = report["submessages"][0]["crypto_header"]
    assert header["algorithm"] == "AES256_GCM"
    assert header["key_revision"] == 0
    assert header["transformation_key_id_hex"] == "11223344"
    assert header["session_id"] == 0x01020304
    assert header["initialization_vector_hex"] == "0102030405060708090a0b0c"
    # Outer lengths are little-endian; inner content length is big-endian.
    assert report["submessages"][1]["declared_length"] == 20
    assert report["submessages"][1]["crypto_content"]["content_length"] == 16
    footer = report["submessages"][2]["crypto_footer"]
    assert footer["common_mac_hex"] == "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    assert footer["receiver_specific_mac_count"] == 1
    assert footer["receiver_specific_macs"][0]["receiver_mac_key_id"] == 0x55667788
    assert report["secure_sequences"][0]["mode"] == "encrypt"
    assert not [item for item in report["findings"] if item["severity"] == "high"]
    assert report["mac_verification"] == "not-performed"


def test_complete_rtps_packet_and_srtps_flags():
    srtps = bytearray(SECURE_STREAM)
    srtps[0] = 0x33
    srtps[1] = 0x07  # E | AAD | PSK
    srtps[len(PREFIX) + len(BODY)] = 0x34
    report = engine.parse_secure_rtps(RTPS_HEADER + srtps)
    assert report["framing"] == "rtps"
    assert report["rtps_header"]["protocol_version"] == "2.5"
    first = report["submessages"][0]
    assert first["additional_authenticated_data"] is True
    assert first["pre_shared_key"] is True
    assert report["secure_sequences"][0]["scope"] == "rtps-message"


def test_big_endian_outer_header_still_has_big_endian_crypto_fields():
    stream = bytes((0x31, 0x00, 0x00, 0x14)) + PREFIX[4:]
    stream += bytes((0x30, 0x00, 0x00, 0x14)) + BODY[4:]
    stream += bytes((0x32, 0x00, 0x00, 0x28)) + POSTFIX[4:]
    report = engine.parse_secure_rtps(stream, framing="submessages")
    assert report["submessages"][0]["endianness"] == "big"
    assert report["submessages"][0]["crypto_header"]["algorithm_id"] == 4
    assert report["submessages"][2]["crypto_footer"]["receiver_specific_mac_count"] == 1


def test_envelope_relationship_anomalies_are_evidence_not_crashes():
    missing_body = PREFIX + POSTFIX
    findings = engine.parse_secure_rtps(missing_body)["findings"]
    assert any(item["kind"] == "missing-secure-body" for item in findings)
    orphan = engine.parse_secure_rtps(BODY, framing="submessages")["findings"]
    assert any(item["kind"] == "orphan-secure-body" for item in orphan)


def test_raw_governance_policy_lint():
    report = engine.parse_security_document(GOVERNANCE)
    assert report["document_kind"] == "governance"
    assert report["container"]["signature_present"] is False
    rule = report["policy"]["domain_rules"][0]
    assert rule["rtps_protection_kind"] == "ENCRYPT_WITH_ORIGIN_AUTHENTICATION"
    kinds = {finding["kind"] for finding in report["findings"]}
    assert {"unsigned-policy-document", "unauthenticated-participants",
            "join-access-control-disabled", "topic-rule-shadowing",
            "unprotected-topic-scope"} <= kinds
    assert report["network_requests"] == 0


def test_permissions_order_default_partition_and_validity():
    report = engine.parse_security_document(PERMISSIONS, as_of="2027-01-01T00:00:00Z")
    assert report["document_kind"] == "permissions"
    grant = report["policy"]["grants"][0]
    assert grant["effective_default"] == "ALLOW"
    criterion = grant["rules"][0]["publish"][0]
    assert criterion["partition_semantics"] == "default-empty-only"
    kinds = {finding["kind"] for finding in report["findings"]}
    assert {"default-allow", "wildcard-allow", "permission-rule-shadowing",
            "grant-expired"} <= kinds


def test_documented_smime_shape_reports_presence_not_validity():
    report = engine.parse_security_document(_smime(GOVERNANCE))
    container = report["container"]
    assert container["container"] == "smime-multipart-signed"
    assert container["signature_present"] is True
    assert container["cms_signed_data_oid_present"] is True
    assert container["signature_verification"] == "not-performed"
    assert container["signer_certificate_included"] == "not-inspected"
    assert any(item["kind"] == "legacy-pkcs7-mime-alias" for item in report["findings"])


@pytest.mark.parametrize("raw", [
    b'<!DOCTYPE dds [<!ENTITY x SYSTEM "file:///etc/passwd">]><dds>&x;</dds>',
    ('<?xml version="1.0" encoding="UTF-16"?>'
     '<!DOCTYPE dds [<!ENTITY x "boom">]><dds>&x;</dds>').encode("utf-16"),
    b"<dds><permissions></dds>",
    b"<not-dds/>",
])
def test_xml_fails_closed_without_entity_or_schema_resolution(raw):
    with pytest.raises(engine.SecDDSSecurityError):
        engine.parse_security_document(raw)


@pytest.mark.parametrize("raw", [
    PREFIX[:-1],
    bytes.fromhex("30 01 08 00 00 00 10 00 01 02 03 04"),
    bytes.fromhex("32 01 14 00") + bytes(16) + (4097).to_bytes(4, "big"),
    bytes.fromhex("31 01 13 00") + bytes(19),
])
def test_malformed_secure_fields_raise_only_declared_error(raw):
    with pytest.raises(engine.SecDDSSecurityError):
        engine.parse_secure_rtps(raw)


@pytest.mark.parametrize("parser,value", [
    (engine.parse_secure_rtps, None),
    (engine.parse_secure_rtps, "RTPS"),
    (engine.parse_security_document, None),
    (engine.parse_security_document, object()),
])
def test_wrong_input_types_use_declared_exception(parser, value):
    with pytest.raises(engine.SecDDSSecurityError):
        parser(value)


def test_seeded_fail_closed_fuzz():
    rng = random.Random(0xDD55EC)
    wire_cases = [b"", b"\x00", bytes(1024)]
    wire_cases += [SECURE_PACKET[:index] for index in range(len(SECURE_PACKET) + 1)]
    for _ in range(128):
        raw = bytearray(SECURE_PACKET)
        index = rng.randrange(len(raw))
        raw[index] ^= 1 << rng.randrange(8)
        wire_cases.append(bytes(raw))
    wire_cases += [rng.randbytes(rng.randrange(0, 257)) for _ in range(128)]
    for raw in wire_cases:
        try:
            assert isinstance(engine.parse_secure_rtps(raw), dict)
        except engine.SecDDSSecurityError:
            pass

    document_cases = [b"", b"<", b"\xff" * 100]
    document_cases += [GOVERNANCE[:index] for index in range(0, len(GOVERNANCE), 17)]
    for _ in range(64):
        raw = bytearray(GOVERNANCE)
        raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
        document_cases.append(bytes(raw))
    for raw in document_cases:
        try:
            assert isinstance(engine.parse_security_document(raw), dict)
        except engine.SecDDSSecurityError:
            pass


def test_oversize_caps_are_checked_before_parsing(monkeypatch):
    monkeypatch.setattr(engine, "MAX_INPUT", 64)
    with pytest.raises(engine.SecDDSSecurityError, match="size limit"):
        engine.parse_secure_rtps(bytes(65))
    with pytest.raises(engine.SecDDSSecurityError, match="size limit"):
        engine.parse_security_document(bytes(65))


def test_cli_guard_json_and_clean_errors(tmp_path, capsys):
    assert engine.main([]) == 2
    assert engine.main(["--help"]) == 0
    capsys.readouterr()
    path = tmp_path / "secure.rtps"
    path.write_bytes(SECURE_PACKET)
    assert engine.main([str(path), "--mode", "wire"]) == 0
    assert json.loads(capsys.readouterr().out)["secure_submessage_count"] == 3
    path.write_bytes(b"broken")
    assert engine.main([str(path), "--mode", "wire"]) == 2
    assert "sec_dds_security:" in capsys.readouterr().err


def test_module_is_offline_and_does_not_offer_a_traffic_builder():
    path = Path(engine.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {alias.name.split(".", 1)[0] for node in ast.walk(tree)
               if isinstance(node, ast.Import) for alias in node.names}
    imports |= {node.module.split(".", 1)[0] for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module}
    assert not ({"socket", "requests", "httpx", "urllib"} & imports)
    public = set(engine.__all__)
    assert not any(word in name for name in public for word in ("send", "build", "craft", "encrypt"))
