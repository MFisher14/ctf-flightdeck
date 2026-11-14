"""Independent HL7 checks: published HL7apy ADT and library schema/parser.

ADT_SOURCE: https://hl7apy.readthedocs.io/en/latest/tutorial/#parsing
Encoding/ED rules: https://www.hl7.eu/HL7v2x/v24/std24/ch02.htm
MLLP: https://www.hl7.eu/refactored/transport01mllp.html
Fixtures contain synthetic tutorial identities, never real patient data.
"""
import base64
import json
import random

import pytest
from hl7apy.parser import parse_message

import health2_hl7 as H


ADT = (
    "MSH|^~\\&|GHH_ADT||||20080115153000||ADT^A01^ADT_A01|0123456789|P|2.5||||AL\r"
    "EVN||20080115153000||AAA|AAA|20080114003000\r"
    "PID|1||566-554-3423^^^GHH^MR||EVERYMAN^ADAM^A|||M|||2222 HOME STREET^^ANN ARBOR^MI^^USA||555-555-2004~444-333-222|||M\r"
    "NK1|1|NUCLEAR^NELDA^W|SPO|2222 HOME STREET^^ANN ARBOR^MI^^USA\r"
    "PV1|1|I|GHH PATIENT WARD|U||||^SENDER^SAM^^MD|^PUMP^PATRICK^P|CAR||||2|A0|||||||||||||||||||||||||||||2008\r"
    "IN1|1|HCID-GL^GLOBAL|HCID-23432|HC PAYOR, INC.|5555 INSURERS CIRCLE^^ANN ARBOR^MI^99999^USA||||||||||||||||||||||||||||||||||||||||||||444-33-3333"
)


def header(kind="ORU^R01^ORU_R01", version="2.5"):
    return f"MSH|^~\\&|LAB|HOSP|EHR|HOSP|202611050900||{kind}|ID1|P|{version}\r"


def segment(message, name):
    return next(s for s in message["segments"] if s["id"] == name)


def field(message, name, number):
    return segment(message, name)["fields"][number - 1]


def test_published_adt_and_hl7apy_oracle():
    message = H.parse_hl7(ADT)["messages"][0]
    oracle = parse_message(ADT, find_groups=False)
    assert message["message_type"] == oracle.msh.msh_9.to_er7()
    assert message["control_id"] == oracle.msh.msh_10.value
    for parsed, reference in zip(message["segments"], oracle.children):
        assert parsed["id"] == reference.name
        for f in parsed["fields"]:
            matches = [c for c in reference.children if c.name == f'{parsed["id"]}_{f["number"]}']
            expected = "~".join(c.to_er7() for c in matches)
            assert f["raw"] == expected
    assert field(message, "PID", 5)["repetitions"][0][0][0] == oracle.pid.pid_5.xpn_1.fn_1.to_er7()
    assert field(message, "PID", 13)["repetitions"] == [[["555-555-2004"]], [["444-333-222"]]]
    assert field(message, "PID", 5)["definition"]["name"] == "PATIENT_NAME"
    assert field(message, "MSH", 1)["raw"] == "|"
    assert field(message, "MSH", 2)["repetitions"] == [[["^~\\&"]]]


@pytest.mark.parametrize("name,number,expected", [
    ("AL1", 3, "ALLERGEN_CODE_MNEMONIC_DESCRIPTION"),
    ("DG1", 3, "DIAGNOSIS_CODE_DG1"),
    ("ORC", 1, "ORDER_CONTROL"),
    ("OBR", 4, "UNIVERSAL_SERVICE_IDENTIFIER"),
    ("OBX", 5, "OBSERVATION_VALUE"),
    ("TXA", 2, "DOCUMENT_TYPE"),
    ("RXR", 1, "ROUTE"),
    ("IN1", 4, "INSURANCE_COMPANY_NAME"),
])
def test_dictionary_beyond_old_basics(name, number, expected):
    assert H.field_definition(name, number)["name"] == expected
    assert H.field_definition("Z99", number) is None
    assert H.field_definition(name, number, "2.9") is None


def test_orm_mdm_unknown_segment_order_and_nulls():
    for kind in ["ORM^O01^ORM_O01", "MDM^T02^MDM_T02"]:
        message = H.parse_hl7(header(kind) + 'ORC|NW|123\rTXA|1|OP\rZQ9||""|A&B^C~D^E&F|\r')["messages"][0]
        assert [s["id"] for s in message["segments"]] == ["MSH", "ORC", "TXA", "ZQ9"]
        values = segment(message, "ZQ9")["fields"]
        assert values[0]["raw"] == "" and not values[0]["is_null"]
        assert values[1]["is_null"]
        assert values[2]["repetitions"] == [[["A", "B"], ["C"]], [["D"], ["E", "F"]]]
        assert values[3]["raw"] == ""


def test_custom_delimiters_and_escape_before_structure():
    source = "MSH!@$%&!LAB!HOSP!EHR!HOSP!20261105!!ORU@R01!X!P!2.5\rNTE!1!!a%F%b%S%c%R%d%T%e%E%f%X4142%"
    m = H.parse_hl7(source)["messages"][0]
    assert field(m, "NTE", 3)["repetitions"] == [[["a!b@c$d&e%fAB"]]]
    assert field(m, "NTE", 3)["raw"].startswith("a%F%b")


def test_escaped_flags_and_local_escapes_preserved():
    source = header() + r'NTE|1||\X43534354467b6865787d\^a\Zvendor|opaque^stuff\b^\H\bold\N\\.br\line'
    message = H.parse_hl7(source)["messages"][0]
    assert message["flags"] == ["CSCTF{hex}"]
    components = field(message, "NTE", 3)["repetitions"][0]
    assert components[1] == [r"a\Zvendor|opaque^stuff\b"]
    assert components[2] == ["\\H\\bold\\N\\\nline"]


@pytest.mark.parametrize("encoding,payload,expected", [
    ("Base64", "Zm9vYmFy", b"foobar"),  # RFC 4648 vector
    ("Hex", "00ff4142", b"\x00\xffAB"),
    ("A", r"alpha\F\beta", b"alpha|beta"),
])
def test_ed_extraction(encoding, payload, expected):
    message = H.parse_hl7(header("MDM^T02^MDM_T02") + f"TXA|1|OP\rOBX|1|ED|DOC||APP^AP^PDF^{encoding}^{payload}||||||F\r")["messages"][0]
    attachment = message["attachments"][0]
    assert base64.b64decode(attachment["data_base64"]) == expected
    assert attachment["size"] == len(expected)
    assert attachment["subtype"] == "PDF"


def test_ed_repeat_extraction_and_component_1_substructure():
    payload = base64.b64encode(b"CSCTF{attachment}").decode()
    m = H.parse_hl7(header() + f"OBX|1|ED|DOC||APP&OID&ISO^AP^PDF^Base64^{payload}~APP^AP^PDF^Hex^4142")["messages"][0]
    assert len(m["attachments"]) == 2
    assert m["attachments"][0]["source_application"] == "APP&OID&ISO"
    assert m["flags"] == ["CSCTF{attachment}"]


def test_multiple_mllp_frames_and_batch_counts():
    message = header() + "OBX|1|TX|NOTE||sample\r"
    result = H.parse_hl7("\x0b" + message + "\x1c\r\x0b" + ADT + "\x1c\r")
    assert result["framed"] and len(result["messages"]) == 2
    batch = "FHS|^~\\&|SRC\rBHS|^~\\&|SRC\r" + message + ADT + "\rBTS|2\rBHS|^~\\&|SRC\r" + message + "BTS|1\rFTS|2\r"
    result = H.parse_hl7(batch)
    assert len(result["messages"]) == 3
    assert [e["id"] for e in result["envelopes"]] == ["FHS", "BHS", "BTS", "BHS", "BTS", "FTS"]


@pytest.mark.parametrize("tail", [
    "NTE|1||\\", "NTE|1||\\X0\\", "NTE|1||\\XGG\\", "NTE|1||\\Q\\",
    "OBX|1|ED|D||A^AP^PDF^Base64^!!!!", "OBX|1|ED|D||A^AP^PDF^Hex^0",
    "OBX|1|ED|D||A^AP^PDF^bogus^AAA", "OBX|1|ED|D||A^AP^PDF^A^a&b",
    "NOTASEGMENT|x", "NTE|1||a\x00b", "NTE|1\r\rNTE|2",
])
def test_bad_payload_closed(tail):
    with pytest.raises(H.HL7Error):
        H.parse_hl7(header() + tail)


@pytest.mark.parametrize("source", [
    "", "MSH", "MSH|^^\\&|APP", "MSH|^~\\&|APP", "PID|1",
    "\x0b" + ADT, "\x0b" + ADT + "\x1c", "\x0b" + ADT + "\x1c\rx",
    "BHS|^~\\&|A\r" + ADT, "BTS|1\r" + ADT,
    "BHS|^~\\&|A\r" + ADT + "\rBTS|2",
    "FHS|^~\\&|A\rBHS|^~\\&|A\r" + ADT + "\rBTS|1\rFTS|2",
    "FHS|^~\\&|A\r" + ADT + "\rFTS|1",
])
def test_bad_envelope_closed(source):
    with pytest.raises(H.HL7Error):
        H.parse_hl7(source)


def test_nondefault_charset_and_unknown_version():
    source = (header(version="2.9") + "NTE|1||caf\u00e9").encode("latin-1")
    m = H.parse_hl7(source, encoding="latin-1")["messages"][0]
    assert not m["dictionary_available"]
    assert field(m, "NTE", 3)["repetitions"] == [[["caf\u00e9"]]]
    with pytest.raises(H.HL7Error):
        H.parse_hl7(source)


def test_bounded_and_arbitrary_malformed_inputs(monkeypatch):
    rng = random.Random(917)
    for _ in range(200):
        data = rng.randbytes(rng.randrange(100))
        try:
            H.parse_hl7(data)
        except H.HL7Error:
            pass
    for data in [None, 42, {}, [], object()]:
        with pytest.raises(H.HL7Error):
            H.parse_hl7(data)
    monkeypatch.setattr(H, "MAX_BYTES", 10)
    with pytest.raises(H.HL7Error):
        H.parse_hl7(ADT)
    monkeypatch.setattr(H, "MAX_BYTES", 100000)
    monkeypatch.setattr(H, "MAX_PARTS", 10)
    with pytest.raises(H.HL7Error):
        H.parse_hl7(ADT)


def test_cli_extract_help_and_errors(tmp_path, capsys):
    path = tmp_path / "message.hl7"
    path.write_text(header() + "OBX|1|ED|DOC||APP^AP^PDF^Base64^Zm9vYmFy")
    output = tmp_path / "out"
    assert H.main([str(path), "--extract", str(output)]) == 0
    assert (output / "message-0000-ed-0000.bin").read_bytes() == b"foobar"
    assert json.loads(capsys.readouterr().out)["kind"] == "hl7-v2"
    assert H.main([str(path), "--extract", str(output)]) == 2  # no overwrite
    assert H.main(["--help"]) == 0
    assert H.main(["--unknown"]) == 2
    assert H.main([str(tmp_path / "missing")]) == 2
