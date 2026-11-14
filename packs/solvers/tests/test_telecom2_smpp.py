"""Independent wire construction from SMPP 3.4 Issue 1.2 §§3--5.

The fixture writer uses no implementation encoders, field tables or constants.
Literal known messages test alphabet tables independently of the parser.
"""
import random
import struct

import pytest

from telecom2_smpp import SMPPError, decode_message, main, parse_pdu, parse_stream


def frame(command, body=b"", status=0, sequence=17):
    return struct.pack("!IIII", 16 + len(body), command, status, sequence) + body


def tlv(tag, value):
    return struct.pack("!HH", tag, len(value)) + value


def short_message(message=b"hello", coding=1, esm=0, optional=b"", command=4):
    # service, source TON/NPI/address, destination TON/NPI/address;
    # esm, protocol, priority, schedule, validity, registered, replace,
    # coding, default id, length and message, followed by optional TLVs.
    body = (b"\0\x01\x01+44123\0\x01\x01+44567\0" + bytes([esm, 0, 0])
            + b"\0\0\x01\0" + bytes([coding, 0, len(message)]) + message + optional)
    return frame(command, body)


def test_literal_enquire_link_and_stream_boundaries():
    # SMPP common header: command_length=16, enquire_link=0x15, seq=7.
    request = bytes.fromhex("00000010000000150000000000000007")
    response = bytes.fromhex("00000010800000150000000000000007")
    values = parse_stream(request + response)
    assert [(x["command"], x["offset"], x["sequence_number"]) for x in values] == [
        ("enquire_link", 0, 7), ("enquire_link_resp", 16, 7)]


def test_bind_credentials_and_interface():
    value = parse_pdu(frame(9, b"esme\0secret\0SMSC\0\x34\x01\x01\0"))
    assert value["command"] == "bind_transceiver"
    assert value["fields"]["password"] == "secret"
    assert value["fields"]["interface_version"] == 0x34


def test_submit_ucs2_and_addresses():
    # Handwritten UCS2 big-endian code units, not encoded by implementation.
    value = parse_pdu(short_message(bytes.fromhex("00430053004300540046007b03a9007d"), coding=8))
    assert value["message"]["text"] == "CSCTF{Ω}"
    assert value["fields"]["source_addr"] == "+44123"
    assert value["fields"]["destination_addr"] == "+44567"


def test_data_sm_payload_and_unknown_tlvs():
    body = (b"\0\x01\x01a\0\x01\x01b\0\x00\x00\x01"
            + tlv(0x424, b"CSCTF{payload}") + tlv(0x7777, b"\x00\xff"))
    value = parse_pdu(frame(0x103, body))
    assert value["message"]["text"] == "CSCTF{payload}"
    assert value["tlvs"][1]["raw_hex"] == "00ff"


def test_data_sm_allows_64_character_addresses_per_spec_table_4_20():
    # data_sm differs from submit_sm: C-octet addresses allow 65 bytes.
    address = b"x" * 64
    body = (b"\0\x01\x01" + address + b"\0\x01\x01" + address
            + b"\0\x00\x00\x01" + tlv(0x424, b"hello"))
    value = parse_pdu(frame(0x103, body))
    assert value["fields"]["source_addr"] == "x" * 64
    assert value["message"]["text"] == "hello"


def test_independent_smpplib_encoder_oracle():
    # Only library serialization is used; no Client connection or socket calls.
    commands = pytest.importorskip("smpplib.command")
    gsm = pytest.importorskip("smpplib.gsm")
    text = "CSCTF{£àΩ€}"
    parts, coding, esm = gsm.make_parts(text)
    pdu = commands.SubmitSM(
        "submit_sm", sequence=1, source_addr_ton=1, source_addr_npi=1, source_addr="44123",
        dest_addr_ton=1, dest_addr_npi=1, destination_addr="44567",
        short_message=parts[0], data_coding=coding, esm_class=esm,
    )
    value = parse_pdu(pdu.generate(), default_alphabet="gsm")
    assert value["fields"]["source_addr"] == "44123"
    assert value["message"]["text"] == text


def test_receipt_and_message_id():
    value = parse_pdu(short_message(b"id:123 stat:DELIVRD", esm=4, command=5,
                                   optional=tlv(0x1E, b"123\0") + tlv(0x427, b"\x02")))
    assert value["message"]["delivery_receipt"] is True
    assert value["tlvs"][0]["value"] == "123"
    assert parse_pdu(frame(0x80000004, b"123\0"))["fields"]["message_id"] == "123"
    assert parse_pdu(frame(0x80000004, status=8))["fields"] == {}


def test_sar_metadata_and_repeated_unknowns_preserved():
    optional = (tlv(0x20C, b"\x12\x34") + tlv(0x20E, b"\x03") + tlv(0x20F, b"\x02")
                + tlv(0x7000, b"a") + tlv(0x7000, b"b"))
    value = parse_pdu(short_message(optional=optional))
    assert value["message"]["concatenation"] == {
        "method": "sar", "reference": 0x1234, "total": 3, "sequence": 2}
    assert len(value["tlvs"]) == 5


@pytest.mark.parametrize("udh,expected", [
    (b"\x05\x00\x03\xab\x03\x02", {"method": "udh8", "reference": 171, "total": 3, "sequence": 2}),
    (b"\x06\x08\x04\x12\x34\x02\x01", {"method": "udh16", "reference": 4660, "total": 2, "sequence": 1}),
])
def test_udh_metadata_stripped_before_decode(udh, expected):
    value = parse_pdu(short_message(udh + b"hello", esm=0x40))
    assert value["message"]["text"] == "hello"
    assert value["message"]["concatenation"] == expected


def test_smsc_default_is_never_guessed():
    assert parse_pdu(short_message(b"ABC", coding=0))["message"]["text"] is None
    assert decode_message(b"ABC", 0, "ascii") == "ABC"
    assert decode_message(b"\x00\x01\x24\x40\x5b\x7f\x1b\x28\x1b\x29\x1b\x65", 0, "gsm") == "@£¤¡Äà{}€"
    assert decode_message(b"\xe9", 3) == "é"
    assert decode_message(b"\xff", 2) is None


@pytest.mark.parametrize("data,coding,alphabet", [
    (b"\xff", 1, "raw"), (b"\x00", 8, "raw"), (b"\xd8\x00\xdc\x00", 8, "raw"),
    (b"\x1b", 0, "gsm"), (b"\x1b\x01", 0, "gsm"), (b"\x80", 0, "gsm"),
    (b"", 256, "raw"), (b"", 0, []), (b"", [], "raw"),
])
def test_bad_text_contract(data, coding, alphabet):
    with pytest.raises(SMPPError):
        decode_message(data, coding, alphabet)


@pytest.mark.parametrize("optional", [
    b"\x00", tlv(0x20C, b"\x01"), tlv(0x20E, b"\x02"),
    tlv(0x424, b"duplicate short"), tlv(0x1E, b"no null"),
    tlv(0x20C, b"\x00\x01") + tlv(0x20E, b"\x00") + tlv(0x20F, b"\x01"),
    tlv(0x20C, b"\x00\x01") * 2,
])
def test_bad_tlv_contract(optional):
    with pytest.raises(SMPPError):
        parse_pdu(short_message(optional=optional))


@pytest.mark.parametrize("payload", [b"", b"\x10\x00", b"\x03\x00\x03\x01", b"\x05\x00\x03\x01\x00\x01"])
def test_bad_udh_contract(payload):
    with pytest.raises(SMPPError):
        parse_pdu(short_message(payload, esm=0x40))


def test_truncation_and_length_mismatch_all_boundaries():
    valid = short_message(b"CSCTF{strict}", optional=tlv(0x20A, b"\x12\x34"))
    for boundary in range(len(valid)):
        with pytest.raises(SMPPError):
            parse_pdu(valid[:boundary])
        with pytest.raises(SMPPError):
            parse_stream(valid[:boundary])
    with pytest.raises(SMPPError):
        parse_pdu(valid + b"x")
    with pytest.raises(SMPPError):
        parse_stream(valid + b"x")


def test_error_contract_arbitrary_bytes_types_and_bounds():
    rng = random.Random(20261105)
    for _ in range(400):
        data = rng.randbytes(rng.randrange(200))
        with pytest.raises(SMPPError):
            parse_pdu(data)
    for value in (None, 1, "abcdef", [], {}):
        with pytest.raises(SMPPError):
            parse_pdu(value)
    with pytest.raises(SMPPError):
        parse_pdu(b"a" * (1024 * 1024 + 1))
    with pytest.raises(SMPPError):
        parse_stream(frame(0x15) * 4097)


def test_unknown_command_is_explicitly_opaque():
    value = parse_pdu(frame(0x12345, b"opaque"))
    assert value["unsupported_body_hex"] == "6f7061717565"


def test_cli(tmp_path, capsys):
    source = tmp_path / "message.hex"
    source.write_text(short_message().hex())
    assert main([str(source), "--hex"]) == 0
    assert '"text": "hello"' in capsys.readouterr().out
    assert main(["--help"]) == 0
    assert main([]) == 2
    assert main([str(tmp_path / "missing")]) == 2
    source.write_text("zz")
    assert main([str(source), "--hex"]) == 2
