"""MAP oracle: pycrate's independently compiled 3GPP ASN.1 schemas.

No production encoder exists. Tests serialize schema values with pycrate and
assert semantic values plus literal TBCD examples from the wire definition.
"""
from copy import deepcopy
import random

import pytest

from telecom2_map import MAPError, decode_isdn, decode_tbcd, main, parse_map


IMSI = bytes.fromhex("00100121436587f9")
ADDRESS = bytes.fromhex("91442143f5")


def encode(module, schema, value):
    MAP = pytest.importorskip("pycrate_asn1dir.MAP")
    obj = deepcopy(getattr(getattr(MAP, module), schema))
    obj.set_val(value)
    return obj.to_ber()


def test_literal_sri_sm_and_tbcd():
    value = parse_map(bytes.fromhex("3011800591442143f58101ff820591446587f9"), 45)
    assert value["name"] == "sendRoutingInfoForSM"
    assert value["fields"]["msisdn"]["digits"] == "4412345"
    assert value["fields"]["serviceCentreAddress"]["digits"] == "4456789"
    assert value["fields"]["sm-RP-PRI"] is True
    assert decode_tbcd(bytes.fromhex("ba dc fe")) == "*#abc"
    assert decode_isdn(b"\x91")["digits"] == ""


def test_sri_sm_arg_oracle_with_extension():
    data = encode("MAP_SM_DataTypes", "RoutingInfoForSM_Arg", {
        "msisdn": ADDRESS, "sm-RP-PRI": False, "serviceCentreAddress": ADDRESS,
        "gprsSupportIndicator": 0,
    })
    value = parse_map(data, 45)
    assert value["fields"]["msisdn"]["digits"] == "4412345"
    assert value["fields"]["sm-RP-PRI"] is False
    assert value["raw_extensions"] == [{"tag_hex": "87", "raw_hex": ""}]


def test_sri_sm_result_oracle():
    data = encode("MAP_SM_DataTypes", "RoutingInfoForSM_Res", {
        "imsi": IMSI, "locationInfoWithLMSI": {
            "networkNode-Number": ADDRESS, "lmsi": b"ABCD", "gprsNodeIndicator": 0,
        },
    })
    fields = parse_map(data, 45, result=True)["fields"]
    assert fields["imsi"] == "000110123456789"
    assert fields["locationInfoWithLMSI"]["networkNode-Number"]["ton"] == 1
    assert fields["locationInfoWithLMSI"]["lmsi_hex"] == "41424344"


def test_psi_oracle():
    data = encode("MAP_MS_DataTypes", "ProvideSubscriberInfoArg", {
        "imsi": IMSI, "lmsi": b"ABCD", "requestedInfo": {
            "locationInformation": 0, "subscriberState": 0, "currentLocation": 0,
            "requestedDomain": "ps-Domain", "imei": 0,
        },
    })
    value = parse_map(data, 70)
    assert value["name"] == "provideSubscriberInfo"
    assert value["fields"]["requestedInfo"] == {
        "locationInformation": True, "subscriberState": True, "currentLocation": True,
        "requestedDomain": "ps-Domain", "imei": True,
    }


@pytest.mark.parametrize("kind,value,expected", [
    ("imsi", IMSI, "000110123456789"), ("msisdn", ADDRESS, {"ton": 1, "npi": 1, "digits": "4412345", "raw_hex": "91442143f5"}),
])
def test_ati_explicit_choice_oracle(kind, value, expected):
    data = encode("MAP_MS_DataTypes", "AnyTimeInterrogationArg", {
        "subscriberIdentity": (kind, value), "requestedInfo": {"locationInformation": 0},
        "gsmSCF-Address": ADDRESS,
    })
    assert parse_map(data, 71)["fields"]["subscriberIdentity"] == {kind: expected}


@pytest.mark.parametrize("opcode,schema,da,oa", [
    (44, "MT_ForwardSM_Arg", ("imsi", IMSI), ("serviceCentreAddressOA", ADDRESS)),
    (46, "MO_ForwardSM_Arg", ("serviceCentreAddressDA", ADDRESS), ("msisdn", ADDRESS)),
    (44, "MT_ForwardSM_Arg", ("lmsi", b"ABCD"), ("noSM-RP-OA", 0)),
])
def test_forward_sm_choice_oracle(opcode, schema, da, oa):
    data = encode("MAP_SM_DataTypes", schema, {"sm-RP-DA": da, "sm-RP-OA": oa, "sm-RP-UI": b"\x01\x02tpdu"})
    fields = parse_map(data, opcode)["fields"]
    assert fields["sm-RP-UI_hex"] == "010274706475"
    assert fields["sm-RP-DA"]["kind"] == ("serviceCentreAddress" if da[0].startswith("service") else da[0])


@pytest.mark.parametrize("opcode", [59, 60, 61])
def test_ussd_ucs2_oracle(opcode):
    data = encode("MAP_SS_DataTypes", "USSD_Arg", {
        "ussd-DataCodingScheme": b"\x48", "ussd-String": bytes.fromhex("00430053004300540046007b03a9007d"),
        "alertingPattern": b"\x01", "msisdn": ADDRESS,
    })
    fields = parse_map(data, opcode)["fields"]
    assert fields["text"] == "CSCTF{Ω}"
    assert fields["msisdn"]["digits"] == "4412345"


def test_ussd_result_preserves_packed_gsm_without_guessing():
    data = encode("MAP_SS_DataTypes", "USSD_Res", {"ussd-DataCodingScheme": b"\x0f", "ussd-String": b"\xe8\x32\x9b\xfd\x06"})
    fields = parse_map(data, 59, result=True)["fields"]
    assert fields["text"] is None
    assert fields["ussd-String_hex"] == "e8329bfd06"


@pytest.mark.parametrize("data", [b"", b"\xff", b"\xf1\x23", b"\x1f", b"\x1f\x23"])
def test_bad_tbcd(data):
    with pytest.raises(MAPError):
        decode_tbcd(data)


@pytest.mark.parametrize("data", [b"", b"\x11\x21", b"\x91" + b"\x21" * 9])
def test_bad_address(data):
    with pytest.raises(MAPError):
        decode_isdn(data)


def test_schema_mismatch_and_unsupported_operations():
    valid = bytes.fromhex("3011800591442143f58101ff820591446587f9")
    for operation in (None, [], 0, 72, "45", True):
        with pytest.raises(MAPError):
            parse_map(valid, operation)
    with pytest.raises(MAPError):
        parse_map(valid, 70)
    with pytest.raises(MAPError):
        parse_map(valid, 70, result=True)
    with pytest.raises(MAPError):
        parse_map(valid, 45, result=1)


def test_invalid_requested_info_and_ucs2_are_rejected():
    # PSI IMSI plus requestedInfo containing invalid NULL/duplicate fields.
    for request in (bytes.fromhex("800100"), bytes.fromhex("80008000")):
        content = b"\x80\x08" + IMSI + bytes([0xA2, len(request)]) + request
        with pytest.raises(MAPError):
            parse_map(bytes([0x30, len(content)]) + content, 70)
    for payload in (b"\x00", b"\xd8\x00\xdc\x00"):
        body = b"\x04\x01\x48" + bytes([4, len(payload)]) + payload
        with pytest.raises(MAPError):
            parse_map(bytes([0x30, len(body)]) + body, 59)


def test_ber_long_length_and_high_tag_extension_preservation():
    body = bytes.fromhex("800591442143f58101ff820591446587f9") + bytes.fromhex("9f20026162")
    value = parse_map(b"\x30\x81" + bytes([len(body)]) + body, 45)
    assert value["raw_extensions"] == [{"tag_hex": "9f20", "raw_hex": "6162"}]


@pytest.mark.parametrize("data", [
    b"\x30\x80\x00\x00", b"\x30\x01\x80", b"\x30\x02\x00\x00",
    b"\x30\x03\x80\x02\x00", b"\x30\x03\x9f\x00\x00", b"\x30\x02\x80\xff",
])
def test_bad_ber(data):
    with pytest.raises(MAPError):
        parse_map(data, 45)


def test_truncation_all_boundaries_and_mutation_contract():
    valid = bytes.fromhex("3011800591442143f58101ff820591446587f9")
    for i in range(len(valid)):
        with pytest.raises(MAPError):
            parse_map(valid[:i], 45)
    with pytest.raises(MAPError):
        parse_map(valid + b"\x05\x00", 45)
    rng = random.Random(71337)
    for _ in range(500):
        value = bytearray(valid)
        value[rng.randrange(len(value))] = rng.randrange(256)
        try:
            parse_map(value, 45)
        except MAPError:
            pass


def test_budget_contract():
    def tlv(value):
        size = len(value)
        length = bytes([size]) if size < 128 else b"\x82" + size.to_bytes(2, "big")
        return b"\x30" + length + value
    nested = b"\x05\x00"
    for _ in range(19):
        nested = tlv(nested)
    with pytest.raises(MAPError):
        parse_map(nested, 45)
    with pytest.raises(MAPError):
        parse_map(tlv(b"\x05\x00" * 2049), 45)
    for value in (None, [], "data", b"x" * (1024 * 1024 + 1)):
        with pytest.raises(MAPError):
            parse_map(value, 45)


def test_cli(tmp_path, capsys):
    source = tmp_path / "sri.hex"
    source.write_text("3011800591442143f58101ff820591446587f9")
    assert main([str(source), "--hex", "--operation", "45"]) == 0
    assert '"digits": "4412345"' in capsys.readouterr().out
    assert main(["--help"]) == 0
    assert main([]) == 2
    assert main([str(source), "--operation", "999"]) == 2
    assert main([str(tmp_path / "missing"), "--operation", "45"]) == 2
