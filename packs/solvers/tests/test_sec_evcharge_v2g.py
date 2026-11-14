"""Independent vectors for the passive ISO 15118/OCPP analyzer.

V2GTP/EXI literals are published by EVerest libcbv2g and the
OpenChargingCloud ISO15118ConformanceTests interop traces.  OCPP literals are
the examples published in OCA OCPP-J 1.6 / OCPP 2.0.1 Part 4 and the OCA ISO
15118-over-OCPP-1.6 application note.  The SDP response fixture below is built
directly from the documented network-byte-order layout with stdlib struct; it
does not call an engine encoder.
"""

from __future__ import annotations

import ipaddress
import struct

import pytest

import sec_evcharge_v2g as v2g


# OpenChargingCloud ISO15118ConformanceTests interop trace, including V2GTP.
PUBLISHED_ISO20_SAP_REQUEST = bytes.fromhex(
    "01fe800100000025"
    "8000f3ab9371d34b9b79d39ba321d34b9b79d189a98989c1d1699181d22218010000040040"
)
PUBLISHED_ISO20_SAP_RESPONSE = bytes.fromhex("01fe80010000000480400040")

# OCA specification examples.
OCPP16_BOOT = (
    '[2,"19223201","BootNotification",'
    '{"chargePointVendor":"VendorX","chargePointModel":"SingleSocketCharger"}]'
)
OCPP201_BOOT = (
    '[2,"19223201","BootNotification",'
    '{"reason":"PowerUp","chargingStation":'
    '{"model":"SingleSocketCharger","vendorName":"VendorX"}}]'
)
OCPP_BOOT_RESULT = (
    '[3,"19223201",'
    '{"currentTime":"2013-02-01T20:53:32.486Z","interval":300,"status":"Accepted"}]'
)
OCPP_CALL_ERROR = (
    '[4,"162376037","NotSupported","SetDisplayMessageRequest not supported",{}]'
)
OCPP16_ISO15118_BRIDGE = (
    '[2,"123456","DataTransfer",'
    '{"messageId":"SignCertificate",'
    '"data":"{\\"csr\\":\\"<certificate signing request>\\",'
    '\\"certificateType\\":\\"V2GCertificate\\"}",'
    '"vendorId":"org.openchargealliance.iso15118pnc"}]'
)


def _wired_sdp_response(address: str, port: int, security: int, transport: int) -> bytes:
    """Independent reference serialization of ISO 15118 wired SDP response."""

    payload = (
        ipaddress.IPv6Address(address).packed
        + struct.pack(">HBB", port, security, transport)
    )
    return struct.pack(">BBHI", 0x01, 0xFE, 0x9001, len(payload)) + payload


def test_published_iso20_sap_v2gtp_frames_and_exi_header() -> None:
    request = v2g.parse_v2gtp(PUBLISHED_ISO20_SAP_REQUEST, protocol="iso20")
    assert request["payload_type"] == "0x8001"
    assert request["payload_length"] == 37
    assert request["family"] == "iso20_supported_app_protocol"
    assert request["exi_header"]["cookie"] is False
    assert request["exi_header"]["distinguishing_bits"] == "10"
    assert request["exi_header"]["exi_version"] == "1.0"
    assert request["exi_header"]["semantic_decode"] is False

    response = v2g.parse_v2gtp(PUBLISHED_ISO20_SAP_RESPONSE, protocol="iso20")
    assert response["payload_length"] == 4
    assert response["payload_hex"] == "80400040"
    assert response["exi_header"]["body_bytes_if_byte_aligned"] == 3


def test_published_wired_sdp_request_and_independent_response_layout() -> None:
    # Published complete request: no transport security, TCP.
    request = v2g.parse_v2gtp(bytes.fromhex("01fe9000000000021000"))
    assert request["sdp"] == {
        "kind": "request",
        "security": "no_transport_security",
        "security_code": 0x10,
        "transport": "tcp",
        "transport_code": 0,
        "limitations": [
            "The security selector is preference metadata, not evidence that TLS occurred."
        ],
    }
    udp_request = v2g.parse_v2gtp(bytes.fromhex("01fe9000000000020010"))
    assert udp_request["sdp"]["transport"] == "udp"

    encoded = _wired_sdp_response("2001:db8::1518", 60903, 0x00, 0x00)
    response = v2g.parse_v2gtp(encoded)
    assert response["payload_length"] == 20
    assert response["sdp"]["kind"] == "response"
    assert response["sdp"]["ipv6"] == "2001:db8::1518"
    assert response["sdp"]["port"] == 60903
    assert response["sdp"]["security"] == "tls"
    assert response["sdp"]["transport"] == "tcp"

    payload_only = encoded[8:]
    assert v2g.parse_wired_sdp(payload_only, response=True)["port"] == 60903

    with pytest.raises(v2g.SecEvchargeV2GError, match="49152"):
        v2g.parse_v2gtp(_wired_sdp_response("2001:db8::1518", 15118, 0x00, 0x00))


def test_v2gtp_exact_length_context_and_wireless_boundaries() -> None:
    with pytest.raises(v2g.SecEvchargeV2GError, match="exactly consume"):
        v2g.parse_v2gtp(PUBLISHED_ISO20_SAP_RESPONSE + b"\x00")
    with pytest.raises(v2g.SecEvchargeV2GError, match="exactly consume"):
        v2g.parse_v2gtp(PUBLISHED_ISO20_SAP_RESPONSE[:-1])
    with pytest.raises(v2g.SecEvchargeV2GError, match="ISO 15118-20"):
        v2g.parse_v2gtp(bytes.fromhex("01fe80020000000180"), protocol="iso2")
    with pytest.raises(v2g.SecEvchargeV2GError, match="reserved or unsupported"):
        v2g.parse_v2gtp(bytes.fromhex("01fe700000000000"))

    # The wireless payload is retained but never decoded with the wired layout.
    wireless = v2g.parse_v2gtp(bytes.fromhex("01fe9002000000021000"))
    assert wireless["family"] == "wireless_sdp"
    assert wireless["semantic_decode"] is False
    assert "sdp" not in wireless


def test_exi_header_is_header_only_and_options_remain_opaque() -> None:
    plain = v2g.inspect_exi_header(bytes.fromhex("80400040"))
    assert plain["body_byte_offset"] == 1
    assert plain["opaque_hex"] == "400040"
    assert plain["semantic_decode"] is False

    cookie = v2g.inspect_exi_header(b"$EXI" + bytes.fromhex("a000"))
    assert cookie["cookie"] is True
    assert cookie["options_present"] is True
    assert cookie["body_byte_offset"] is None
    assert cookie["semantic_decode"] is False

    with pytest.raises(v2g.SecEvchargeV2GError, match="distinguishing"):
        v2g.inspect_exi_header(b"\x00")


def test_iso15118_catalog_and_caller_decoded_sequence_checks() -> None:
    catalog = v2g.iso15118_catalog("iso20", amendment_1=True)
    assert catalog["services"]["5"] == "AC_BPT"
    assert catalog["services"]["7"] == "DC_ACDP_BPT"
    assert catalog["control_modes"] == ["scheduled", "dynamic"]
    assert catalog["amendment_1_features"] == [
        "AC_DER", "MCS", "improved_security_concept"
    ]
    assert "AC_ChargeLoop" in catalog["message_families"]["ac"]
    assert "DC_ChargeParameterDiscovery" in catalog["message_families"]["dc"]
    assert "WPT_FinePositioningSetup" in catalog["message_families"]["wpt"]
    assert "WPT_AlignmentCheck" in catalog["message_families"]["wpt"]
    assert "ACDP_VehiclePositioning" in catalog["message_families"]["acdp"]
    assert "ACDP_Disconnect" in catalog["message_families"]["acdp"]

    records = [
        {"message": "SessionSetupReq", "direction": "evcc_to_secc"},
        {"message": "SessionSetupRes", "direction": "secc_to_evcc"},
        {"message": "SessionStopReq", "direction": "evcc_to_secc"},
        {"message": "SessionStopRes", "direction": "secc_to_evcc"},
    ]
    report = v2g.analyze_iso15118_transcript(records, generation="iso20")
    assert report["pairing_valid"] is True
    assert report["issues"] == []
    assert report["semantic_decode"] == "caller_supplied"

    specialized = v2g.analyze_iso15118_transcript(
        [
            {"message": "WPT_FinePositioningSetupReq", "direction": "evcc_to_secc"},
            {"message": "WPT_FinePositioningSetupRes", "direction": "secc_to_evcc"},
            {"message": "ACDP_VehiclePositioningReq", "direction": "evcc_to_secc"},
            {"message": "ACDP_VehiclePositioningRes", "direction": "secc_to_evcc"},
        ],
        generation="iso20",
    )
    assert specialized["pairing_valid"] is True
    assert not any(
        issue["code"] == "generation_message_mismatch"
        for issue in specialized["issues"]
    )

    bad = v2g.analyze_iso15118_transcript(
        [
            {"message": "SessionSetupReq", "direction": "evcc_to_secc"},
            {"message": "AuthorizationRes", "direction": "secc_to_evcc"},
        ],
        generation="iso2",
    )
    assert bad["pairing_valid"] is False
    assert any(issue["code"] == "response_pair_mismatch" for issue in bad["issues"])


def test_pnc_role_topology_and_ceremony_are_metadata_not_trust() -> None:
    evidence = {
        "certificates": [
            {"role": "v2g_root", "is_ca": True},
            {"role": "cpo_sub_ca", "is_ca": True, "issuer_role": "v2g_root"},
            {
                "role": "secc_leaf", "is_ca": False,
                "issuer_role": "cpo_sub_ca", "identifier_type": "EVSEID",
            },
            {"role": "mo_root", "is_ca": True},
            {"role": "mo_sub_ca", "is_ca": True, "issuer_role": "mo_root"},
            {
                "role": "contract_leaf", "is_ca": False,
                "issuer_role": "mo_sub_ca", "identifier_type": "eMAID",
            },
        ],
        "ceremony": [
            "TLS_SECC_AUTH", "CertificateInstallationReq",
            "CertificateInstallationRes", "PaymentDetailsReq",
            "PaymentDetailsRes", "AuthorizationReq", "AuthorizationRes",
        ],
        "trust_anchors": ["caller supplied"],
        "validation_time": "2026-11-05T00:00:00Z",
        "revocation_evidence": [],
    }
    report = v2g.analyze_pnc_evidence(evidence, generation="iso2")
    assert report["generation"] == "iso2"
    assert report["topology_consistent"] is True
    assert report["trust_verdict"] == "not_performed"
    # The caller supplied each input class, but the engine still performs no trust verdict.
    assert report["trust_inputs_present"] is True
    assert any("not a trust verdict" in line for line in report["limitations"])


def test_iso20_pnc_ceremony_multiple_contracts_and_root_edges() -> None:
    evidence = {
        "certificates": [
            {"role": "mo_root", "is_ca": True},
            {"role": "mo_sub_ca", "is_ca": True, "issuer_role": "mo_root"},
            {"role": "contract_leaf", "is_ca": False, "issuer_role": "mo_sub_ca"},
            {"role": "contract_leaf", "is_ca": False, "issuer_role": "mo_sub_ca"},
        ],
        "ceremony": [
            "TLS_SECC_AUTH", "AuthorizationSetupReq", "AuthorizationSetupRes",
            "CertificateInstallationReq", "CertificateInstallationRes",
            "AuthorizationReq", "AuthorizationRes",
        ],
    }
    report = v2g.analyze_pnc_evidence(evidence, generation="iso20")
    assert report["generation"] == "iso20"
    assert report["topology_consistent"] is True
    assert report["issues"] == []

    bad_root = {
        **evidence,
        "certificates": [
            {"role": "v2g_root", "is_ca": True, "issuer_role": "contract_leaf"}
        ],
    }
    bad = v2g.analyze_pnc_evidence(bad_root, generation="iso20")
    assert bad["topology_consistent"] is False
    assert bad["issues"][0]["code"] == "unexpected_role_edge"

    with pytest.raises(v2g.SecEvchargeV2GError, match="iso20"):
        v2g.analyze_pnc_evidence(
            {"certificates": [], "ceremony": ["PaymentDetailsReq"]},
            generation="iso20",
        )


def test_published_ocpp_message_examples() -> None:
    one_six = v2g.parse_ocpp_message(OCPP16_BOOT, version="1.6J")
    assert one_six["kind"] == "CALL"
    assert one_six["action"] == "BootNotification"
    assert one_six["payload"]["chargePointVendor"] == "VendorX"
    assert one_six["payload_check"] == {
        "profile": "published_boot_notification_required_shape",
        "required_fields_checked": True,
        "full_schema_validation": False,
    }

    two = v2g.parse_ocpp_message("  " + OCPP201_BOOT + "\n", version="2.0.1")
    assert two["payload"]["reason"] == "PowerUp"
    assert two["payload"]["chargingStation"]["vendorName"] == "VendorX"
    assert two["payload_check"]["profile"] == "published_boot_notification_required_shape"
    assert two["payload_check"]["required_fields_checked"] is True
    assert two["payload_check"]["full_schema_validation"] is False

    result = v2g.parse_ocpp_message(
        OCPP_BOOT_RESULT, version="2.0.1", response_action="BootNotification"
    )
    assert result["kind"] == "CALLRESULT"
    assert result["payload_check"] == {
        "profile": "published_boot_notification_response_required_shape",
        "required_fields_checked": True,
        "full_schema_validation": False,
    }

    error = v2g.parse_ocpp_message(OCPP_CALL_ERROR, version="2.0.1")
    assert error["kind"] == "CALLERROR"
    assert error["error_code"] == "NotSupported"
    assert error["details"] == {}


def test_published_ocpp16_iso15118_bridge_and_correlated_transcript() -> None:
    bridge = v2g.parse_ocpp_message(OCPP16_ISO15118_BRIDGE, version="1.6")
    assert bridge["action"] == "DataTransfer"
    assert bridge["payload_check"]["iso15118_pnc_bridge"] is True
    assert bridge["payload_check"]["bridge_message_id"] == "SignCertificate"

    transcript = v2g.analyze_ocpp_transcript(
        [
            {"direction": "station_to_csms", "message": OCPP201_BOOT},
            {"direction": "csms_to_station", "message": OCPP_BOOT_RESULT},
        ],
        version="2.0.1",
        handshake={
            "subprotocol": "ocpp2.0.1", "security_profile": 3,
            "tls": True, "mutual_tls": True,
        },
    )
    assert transcript["correlation_valid"] is True
    assert transcript["issues"] == []
    assert transcript["messages"][1]["response_action"] == "BootNotification"
    assert transcript["messages"][1]["payload_check"]["required_fields_checked"] is True
    assert transcript["messages"][1]["payload_check"]["full_schema_validation"] is False
    assert transcript["handshake"]["consistent"] is True


def test_ocpp_security_profile_two_requires_supplied_basic_auth_evidence() -> None:
    handshake = v2g.analyze_ocpp_handshake(
        {
            "subprotocol": "ocpp1.6",
            "security_profile": 2,
            "tls": True,
            "basic_auth": False,
        },
        version="1.6J",
    )
    assert handshake["consistent"] is False
    assert [issue["code"] for issue in handshake["issues"]] == [
        "profile_auth_mismatch"
    ]


def test_boot_result_rejects_impossible_rfc3339_calendar_date() -> None:
    impossible = (
        '[3,"19223201",'
        '{"currentTime":"2013-02-30T20:53:32Z","interval":300,"status":"Accepted"}]'
    )
    with pytest.raises(v2g.SecEvchargeV2GError, match="real RFC 3339 calendar"):
        v2g.parse_ocpp_message(
            impossible, version="2.0.1", response_action="BootNotification"
        )


def test_opposite_senders_may_cross_with_the_same_unique_id() -> None:
    reset = '[2,"19223201","Reset",{"type":"Immediate"}]'
    reset_result = '[3,"19223201",{"status":"Accepted"}]'
    report = v2g.analyze_ocpp_transcript(
        [
            {"direction": "station_to_csms", "message": OCPP201_BOOT},
            {"direction": "csms_to_station", "message": reset},
            {"direction": "csms_to_station", "message": OCPP_BOOT_RESULT},
            {"direction": "station_to_csms", "message": reset_result},
        ],
        version="2.0.1",
    )
    assert report["issues"] == []
    assert report["correlation_valid"] is True
    assert report["messages"][2]["response_action"] == "BootNotification"
    assert report["messages"][2]["request_index"] == 0
    assert report["messages"][3]["response_action"] == "Reset"
    assert report["messages"][3]["request_index"] == 1


def test_same_sender_unique_id_reuse_after_completion_is_reported() -> None:
    heartbeat = '[2,"19223201","Heartbeat",{}]'
    heartbeat_result = '[3,"19223201",{"currentTime":"2026-11-05T12:00:00Z"}]'
    report = v2g.analyze_ocpp_transcript(
        [
            {"direction": "station_to_csms", "message": OCPP201_BOOT},
            {"direction": "csms_to_station", "message": OCPP_BOOT_RESULT},
            {"direction": "station_to_csms", "message": heartbeat},
            {"direction": "csms_to_station", "message": heartbeat_result},
        ],
        version="2.0.1",
    )
    assert [issue["code"] for issue in report["issues"]] == ["reused_unique_id"]
    assert report["messages"][3]["response_action"] == "Heartbeat"
    assert report["correlation_valid"] is False


def test_both_ocpp_versions_reject_two_outstanding_calls_from_one_sender() -> None:
    records = [
        {"direction": "station_to_csms", "message": '[2,"call-a","Heartbeat",{}]'},
        {"direction": "station_to_csms", "message": '[2,"call-b","Heartbeat",{}]'},
    ]
    for version in ("1.6J", "2.0.1"):
        report = v2g.analyze_ocpp_transcript(records, version=version)
        assert any(
            issue["code"] == "multiple_outstanding_calls"
            and issue["severity"] == "error"
            for issue in report["issues"]
        )
        assert report["correlation_valid"] is False


@pytest.mark.parametrize(
    ("message", "version"),
    [
        ('[2,"x","Heartbeat",{"a":1,"a":2}]', "1.6J"),
        ('[2,"x","Heartbeat",{"n":NaN}]', "1.6J"),
        ('[true,"x","Heartbeat",{}]', "1.6J"),
        ('[5,"x","GenericError","bad",{}]', "2.0.1"),
        ('[2,"x","TransactionEvent",{}]', "1.6J"),
        ('[2,"x","NotARealAction",{}]', "2.0.1"),
        ('[2,"x","Heartbeat",{}] trailing', "1.6J"),
    ],
)
def test_ocpp_strict_json_version_and_21_boundaries(message: str, version: str) -> None:
    with pytest.raises(v2g.SecEvchargeV2GError):
        v2g.parse_ocpp_message(message, version=version)


def test_ocpp_response_action_is_only_valid_for_callresult() -> None:
    with pytest.raises(v2g.SecEvchargeV2GError, match="CALLRESULT"):
        v2g.parse_ocpp_message(OCPP16_BOOT, version="1.6J", response_action="BootNotification")


def test_get15118_certificate_requires_canonical_base64_pad_bits() -> None:
    canonical = '[2,"cert-1","Get15118EVCertificate",{' \
        '"iso15118SchemaVersion":"urn:iso:std:iso:15118:-20:CommonMessages",' \
        '"action":"Install","exiRequest":"Zg=="}]'
    parsed = v2g.parse_ocpp_message(canonical, version="2.0.1")
    assert parsed["payload_check"]["exi_bytes"] == 1

    noncanonical = canonical.replace('"Zg=="', '"Zh=="')
    with pytest.raises(v2g.SecEvchargeV2GError, match="canonical Base64"):
        v2g.parse_ocpp_message(noncanonical, version="2.0.1")


@pytest.mark.parametrize(
    "call",
    [
        lambda: v2g.parse_v2gtp(None),
        lambda: v2g.parse_wired_sdp(b""),
        lambda: v2g.inspect_exi_header(object()),
        lambda: v2g.iso15118_catalog("unknown"),
        lambda: v2g.analyze_iso15118_transcript([], generation="iso2"),
        lambda: v2g.analyze_pnc_evidence([]),
        lambda: v2g.parse_ocpp_message([], version="1.6J"),
        lambda: v2g.analyze_ocpp_transcript([], version="2.0.1"),
        lambda: v2g.analyze_ocpp_handshake([], version="1.6J"),
    ],
)
def test_public_malformed_inputs_raise_only_declared_error(call) -> None:
    with pytest.raises(v2g.SecEvchargeV2GError):
        call()


def test_guarded_cli_codes_and_noninteger_systemexit(monkeypatch, tmp_path, capsys) -> None:
    frame = tmp_path / "sdp.bin"
    frame.write_bytes(bytes.fromhex("01fe9000000000021000"))
    assert v2g.main(["v2gtp", str(frame)]) == 0
    assert '"kind": "request"' in capsys.readouterr().out
    assert v2g.main([]) == 2
    capsys.readouterr()
    assert v2g.main(["--help"]) == 0
    capsys.readouterr()

    deep_json = tmp_path / "deep.json"
    deep_json.write_text("[" * 2_000 + "0" + "]" * 2_000, encoding="utf-8")
    assert v2g.main(["pnc", str(deep_json), "--generation", "iso2"]) == 2
    assert "sec_evcharge_v2g:" in capsys.readouterr().err

    pnc_json = tmp_path / "pnc.json"
    pnc_json.write_text('{"certificates":[],"ceremony":[]}', encoding="utf-8")
    assert v2g.main(["pnc", str(pnc_json), "--generation", "iso20"]) == 0
    assert '"generation": "iso20"' in capsys.readouterr().out

    def noninteger_exit(*_args, **_kwargs):
        raise SystemExit("bad argparse exit")

    monkeypatch.setattr(v2g.argparse.ArgumentParser, "parse_args", noninteger_exit)
    assert v2g.main(["anything"]) == 2
