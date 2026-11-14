"""Independent vector and fail-closed tests for :mod:`sec_bas_bacnet`.

The APDUs are published by ASHRAE in ``BACnet Samples Encoding`` and are
wrapped here by hand using Annex J's BVLC layout.  The BACnet/SC byte strings
are Figures YY-5 and YY-6 of ANSI/ASHRAE 135-2016 Addendum bj.  RFC 6455
frames are built by the small reference routine below, never by the engine.

Sources:
https://bacnet.org/wp-content/uploads/sites/4/2022/08/Encoding.pdf
https://bacnet.org/wp-content/uploads/sites/4/2022/08/Add-1995-135a.pdf
https://bacnet.org/wp-content/uploads/sites/4/2022/08/Add-135-2016bj.pdf
"""
from __future__ import annotations

import random
from typing import Any, Callable

import pytest

import sec_bas_bacnet as bacnet


# Published APDUs with independently hand-applied Annex-J BVLC+NPDU headers.
WHO_IS = bytes.fromhex("810b000801001008")
I_AM = bytes.fromhex("810b001401001000c4020000012201e091002102")
READ_PROPERTY = bytes.fromhex("810a001101040203000c0c000000011955")

# Exact Addendum-bj Figures YY-5 and YY-6, including their historical 0x01
# Secure-Path marker.  Addendum cf made 0x41 the current canonical marker.
SC_YY5 = bytes.fromhex(
    "0107b5ec927bf71a96a2"
    "bf0007022bbac5ecc099"
    "3f0003030939"
    "01"
    "01040000010c0c000000051955"
)
SC_YY6 = bytes.fromhex(
    "0009b5ec927bf71a96a2"
    "01"
    "0101bf00070111"
    "556e6dc3b6676c696368657220436f646521"
)


def _websocket_binary(payload: bytes, *, client: bool, mask: bytes = b"\x11\x22\x33\x44") -> bytes:
    """Minimal independent RFC 6455 FIN+binary reference encoder."""

    assert len(mask) == 4
    length = len(payload)
    if length < 126:
        length_field = bytes((length | (0x80 if client else 0),))
    elif length <= 0xFFFF:
        length_field = bytes((126 | (0x80 if client else 0),)) + length.to_bytes(2, "big")
    else:
        length_field = bytes((127 | (0x80 if client else 0),)) + length.to_bytes(8, "big")
    if not client:
        return b"\x82" + length_field + payload
    masked = bytes(value ^ mask[index & 3] for index, value in enumerate(payload))
    return b"\x82" + length_field + mask + masked


def _clean_or_declared(call: Callable[[], Any]) -> None:
    """A malformed case may decode, but may raise only the declared error."""

    try:
        result = call()
    except bacnet.SecBasBACnetError:
        return
    assert isinstance(result, dict)


def test_ashrae_who_is_and_i_am_vectors_through_existing_classic_layer() -> None:
    who = bacnet.parse_bacnet_ip(WHO_IS)
    assert who["bvlc_function"] == 0x0B
    assert who["bvlc_function_name"] == "Original-Broadcast-NPDU"
    assert who["npdu"]["version"] == 1
    assert who["apdu"]["pdu_type"] == 1
    assert who["apdu"]["service"] == 8
    assert who["apdu"]["service_name"] == "who-Is"

    iam = bacnet.parse_bacnet_ip(I_AM)
    assert iam["apdu"]["service_name"] == "i-Am"
    tags = iam["apdu"]["tags"]
    assert tags[0]["type"] == "object-identifier"
    assert (tags[0]["object_type"], tags[0]["instance"]) == (8, 1)
    assert tags[1]["value"] == 480
    assert tags[2]["value"] == 0
    assert tags[3]["value"] == 2


def test_ashrae_read_property_vector_and_auto_dispatch() -> None:
    report = bacnet.analyze(READ_PROPERTY)
    assert report["bvlc_function"] == 0x0A
    assert report["npdu"]["expecting_reply"] is True
    apdu = report["apdu"]
    assert apdu["pdu_type"] == 0
    assert apdu["invoke_id"] == 0
    assert apdu["service"] == 12
    assert apdu["service_name"] == "readProperty"
    assert apdu["object_identifier"] == {"object_type": 0, "instance": 1}
    assert apdu["property_id"] == 85
    assert apdu["property_name"] == "present-value"


def test_addendum_bj_yy5_sc_header_options_and_encapsulated_npdu() -> None:
    report = bacnet.parse_sc_bvll(SC_YY5)
    assert report["protocol"] == "bacnet-sc"
    assert report["function"] == 1
    assert report["function_name"] == "Encapsulated-NPDU"
    assert report["control"] == 0x07
    assert report["message_id"] == 0xB5EC
    assert report["originating_vmac_present"] is False
    assert report["destination_vmac"]["raw"] == "927bf71a96a2"

    destination = report["destination_options"]
    assert [item["type"] for item in destination] == [31, 31]
    assert [item["vendor_id"] for item in destination] == [0x022B, 0x0309]
    assert destination[0]["vendor_data_hex"] == "bac5ecc099"
    assert destination[1]["vendor_data_hex"] == "39"
    assert destination[0]["proprietary_option_type"] == 0xBA
    assert destination[0]["proprietary_data_hex"] == "c5ecc099"
    assert destination[1]["proprietary_option_type"] == 0x39
    assert destination[1]["proprietary_data_hex"] == ""

    secure_path = report["data_options"][0]
    assert secure_path["marker"] == 0x01
    assert secure_path["type_name"] == "Secure-Path"
    assert secure_path["every_segment"] is False
    assert "historical Secure-Path" in secure_path["violations"][0]

    npdu = report["npdu"]
    assert npdu["npdu"]["version"] == 1
    assert npdu["npdu"]["expecting_reply"] is True
    assert npdu["apdu"]["service_name"] == "readProperty"
    assert npdu["apdu"]["object_identifier"] == {"object_type": 0, "instance": 5}
    assert npdu["apdu"]["property_id"] == 85


def test_addendum_bj_yy6_result_nak_is_preserved_not_rewritten() -> None:
    report = bacnet.parse_sc_bvll(SC_YY6)
    assert report["function_name"] == "BVLC-Result"
    assert report["message_id"] == 0xB5EC
    assert report["originating_vmac"]["raw"] == "927bf71a96a2"
    assert report["data_options"][0]["marker"] == 0x01
    assert report["result_for_function"] == 1
    assert report["result_for_function_name"] == "Encapsulated-NPDU"
    assert report["result_code"] == 1
    assert report["result"] == "NAK"
    assert report["error_header_marker"] == 0xBF
    assert report["error_class"] == 7
    assert report["error_code"] == 0x0111
    assert report["error_details_hex"] == "556e6dc3b6676c696368657220436f646521"
    assert report["error_details"] == "Unmöglicher Code!"
    assert "BVLC-Result carries historical data-options flag" in report["violations"]


def test_current_cf_secure_path_and_cp_option_layouts() -> None:
    # Encapsulated Who-Is NPDU + current data-option Secure-Path marker.
    current = bacnet.parse_sc_bvll(bytes.fromhex("010100014101001008"))
    option = current["data_options"][0]
    assert option["type_name"] == "Secure-Path"
    assert option["every_segment"] is True
    assert "violations" not in option
    assert current["npdu"]["apdu"]["service_name"] == "who-Is"

    # Connect request: Hello destination option, then the public 26-byte
    # VMAC/UUID/maximum-BVLC/maximum-NPDU payload.
    connect_payload = (
        bytes.fromhex("010203040506") + bytes(range(16)) + bytes.fromhex("100005c4")
    )
    hello = bacnet.parse_sc_bvll(bytes.fromhex("0602123422000101") + connect_payload)
    hello_option = hello["destination_options"][0]
    assert hello_option["type_name"] == "Hello"
    assert hello_option["identity_relay_supported"] is True
    assert "violations" not in hello
    assert hello["connection_vmac"]["text"] == "01:02:03:04:05:06"
    assert hello["device_uuid"] == "00010203-0405-0607-0809-0a0b0c0d0e0f"
    assert hello["maximum_bvlc_length"] == 0x1000
    assert hello["maximum_npdu_length"] == 0x05C4

    # Encapsulated NPDU data-option chain: Identity then opaque Token.
    auth = bacnet.parse_sc_bvll(
        bytes.fromhex("01010002a30003000005250003aabbcc01001008")
    )
    assert auth["data_options"][0]["device_instance"] == 5
    assert auth["data_options"][1]["access_token_hex"] == "aabbcc"


def test_addendum_bj_advertisement_and_address_resolution_ack_layouts() -> None:
    advertisement = bacnet.parse_sc_bvll(bytes.fromhex("040000010101100005c4"))
    assert advertisement["hub_connection_status_name"] == "primary-hub"
    assert advertisement["accept_direct_connections"] is True
    assert advertisement["maximum_bvlc_length"] == 0x1000
    assert advertisement["maximum_npdu_length"] == 0x05C4

    resolution = bacnet.parse_sc_bvll(
        b"\x03\x00\x00\x02wss://node.example/a wss://node.example/b"
    )
    assert resolution["websocket_uris"] == [
        "wss://node.example/a", "wss://node.example/b",
    ]


@pytest.mark.parametrize("client", [False, True])
def test_rfc6455_binary_reference_frames(client: bool) -> None:
    wire = _websocket_binary(SC_YY5, client=client)
    report = bacnet.parse_sc_websocket(wire, from_client=client)
    assert report["protocol"] == "bacnet-sc-websocket"
    assert report["direction"] == (
        "client-to-server" if client else "server-to-client"
    )
    assert len(report["messages"]) == 1
    assert report["messages"][0]["message_id"] == 0xB5EC
    assert report["messages"][0]["npdu"]["apdu"]["service_name"] == "readProperty"
    assert report["tls"].startswith("not inspected")

    inferred = bacnet.analyze(wire, format="websocket")
    assert inferred["messages"][0]["function_name"] == "Encapsulated-NPDU"


def test_main_guard_and_valid_cli(tmp_path: Any, capsys: Any) -> None:
    assert bacnet.main(["--help"]) == 0
    capsys.readouterr()
    artifact = tmp_path / "whois.bin"
    artifact.write_bytes(WHO_IS)
    assert bacnet.main([str(artifact), "--format", "bacnet-ip"]) == 0
    output = capsys.readouterr().out
    assert '"service_name": "who-Is"' in output
    assert bacnet.main([]) == 2


def test_public_apis_fail_closed_on_wrong_types_and_invalid_arguments() -> None:
    wrong: list[Any] = [None, 1, 1.5, "810b", object(), [0x81]]
    for value in wrong:
        _clean_or_declared(lambda value=value: bacnet.parse_bacnet_ip(value))
        _clean_or_declared(lambda value=value: bacnet.parse_sc_bvll(value))
        _clean_or_declared(
            lambda value=value: bacnet.parse_sc_websocket(value, from_client=False)
        )
        _clean_or_declared(lambda value=value: bacnet.analyze(value))
    _clean_or_declared(lambda: bacnet.analyze(WHO_IS, format="invalid"))
    _clean_or_declared(lambda: bacnet.parse_sc_websocket(b"\x82\x00", from_client=1))


def test_sc_function_specific_lengths_and_options_fail_closed() -> None:
    # ACK results have no NAK detail tail; Advertisement and Connect have fixed
    # public payload lengths; proprietary options include vendor + option IDs.
    malformed = (
        bytes.fromhex("000000010100ff"),
        bytes.fromhex("0400000101"),
        bytes.fromhex("06000001") + bytes(25),
        bytes.fromhex("010200013f00020001") + bytes.fromhex("01001008"),
    )
    for raw in malformed:
        with pytest.raises(bacnet.SecBasBACnetError):
            bacnet.parse_sc_bvll(raw)

    # Destination options are valid without a destination VMAC for Connect;
    # a forbidden VMAC bit is surfaced as a protocol violation, not hidden.
    payload = bytes.fromhex("010203040506") + bytes(16) + bytes.fromhex("100005c4")
    bad_flags = bacnet.parse_sc_bvll(
        bytes.fromhex("0606123401020304050622000101") + payload
    )
    assert any("unexpected control flags" in item for item in bad_flags["violations"])


def test_truncation_bitflips_and_random_bytes_never_leak_stdlib_errors() -> None:
    samples = (
        (bacnet.parse_bacnet_ip, WHO_IS),
        (bacnet.parse_bacnet_ip, READ_PROPERTY),
        (bacnet.parse_sc_bvll, SC_YY5),
        (bacnet.parse_sc_bvll, SC_YY6),
        (bacnet.analyze, READ_PROPERTY),
        (lambda raw: bacnet.parse_sc_websocket(raw, from_client=False),
         _websocket_binary(SC_YY5, client=False)),
    )
    for function, valid in samples:
        for end in range(len(valid)):
            _clean_or_declared(lambda function=function, end=end, valid=valid: function(valid[:end]))
        for index in range(len(valid)):
            changed = bytearray(valid)
            changed[index] ^= 1 << (index & 7)
            _clean_or_declared(
                lambda function=function, changed=bytes(changed): function(changed)
            )

    rng = random.Random(0xBAC135)
    for _ in range(500):
        raw = rng.randbytes(rng.randrange(0, 257))
        _clean_or_declared(lambda raw=raw: bacnet.parse_bacnet_ip(raw))
        _clean_or_declared(lambda raw=raw: bacnet.parse_sc_bvll(raw))
        _clean_or_declared(
            lambda raw=raw: bacnet.parse_sc_websocket(raw, from_client=False)
        )
        _clean_or_declared(lambda raw=raw: bacnet.analyze(raw))


def test_oversized_inputs_raise_only_declared_error() -> None:
    oversized = b"\x00" * (bacnet.MAX_INPUT + 1)
    for call in (
        lambda: bacnet.parse_bacnet_ip(oversized),
        lambda: bacnet.parse_sc_bvll(oversized),
        lambda: bacnet.parse_sc_websocket(oversized, from_client=False),
        lambda: bacnet.analyze(oversized),
    ):
        with pytest.raises(bacnet.SecBasBACnetError):
            call()
