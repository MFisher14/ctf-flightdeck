"""Independent GS1 IFTMIN specimen and pydifact tokenizer oracle."""
import random

import pytest
from pydifact.segmentcollection import RawSegmentCollection

import transport_edifact as edi

# GS1 EANCOM 2002 S3 IFTMIN example, with its two typographic closing quotes
# normalized to ASCII apostrophes; no field/content changes.
# https://edi.gs1si.org/eancom/ean02s3/part2/iftmin/examples.htm
GS1 = """UNH+ME000001+IFTMIN:D:01B:UN:EAN004'
BGM+610+569952+9'
DTM+137:20020301:102'
DTM+2:200203081100:203'
CNT+11:1'
RFF+CU:TI1284'
TDT+20++30+31'
DTM+133:20020305 1100:203'
LOC+9+5412345678908::9'
NAD+CZ+5412345123453::9'
NAD+CA+5411234512309::9'
NAD+CN+5411234444402::9'
NAD+DP+5412345145660::9'
GID+1+1:09::9+14:PK'
HAN+EAT::9'
TMP+2+000:CEL'
RNG+5+CEL:-5:5'
MOA+44:45000:EUR'
PIA+5+5410738377117:SRV'
MEA+AAE+X7E+KGM:250'
PCI+33E'
GIN+BJ+354123450000000014'
UNT+23+ME000001'"""


def test_published_gs1_transport_instruction():
    out = edi.analyze(GS1)
    message = out["messages"][0]
    assert message["type"] == "IFTMIN"
    assert len(message["segments"]) == 23
    summary = message["summary"]
    assert summary["documents"][0]["number"] == "569952"
    assert summary["parties"][2] == {"qualifier": "CN", "id": "5411234444402", "name": [],
                                     "city": "", "postcode": "", "country": ""}
    assert summary["goods"][0]["packages"] == [["1", "09", "", "9"], ["14", "PK"]]
    assert summary["transport"][0]["mode"] == "30"
    assert summary["measurements"][0] == {"purpose": "AAE", "dimension": "X7E", "unit": "KGM", "value": "250"}


@pytest.mark.parametrize("text", [GS1, "FTX+AAI+++a?+b?:c??d?'e::last'", "UNA;*,! ~FTX*AAI***a!*b!;c!!d!~e;;last~"])
def test_pydifact_independent_tokenizer_oracle(text):
    expected = [{"tag": s.tag, "elements": [v if isinstance(v, list) else [v] for v in s.elements]}
                for s in RawSegmentCollection.from_str(text).segments if s.tag != "UNA"]
    assert edi.parse_segments(text) == expected


def test_escaped_flag_and_envelope():
    text = "UNA:+.? 'UNB+UNOC:3+SENDER+RECIPIENT+261105:1200+REF'" + "UNH+M1+IFTMIN:D:96A:UN'FTX+AAI+++CSCTF{safe?+escaped?:text}'UNT+3+M1'UNZ+1+REF'"
    out = edi.analyze(text)
    assert out["flags"] == ["CSCTF{safe+escaped:text}"]
    assert out["interchange"]["sender"] == "SENDER"


@pytest.mark.parametrize("syntax", [":3", "UNOD:3", "BOGUS:3"])
def test_reject_missing_or_unsupported_character_set(syntax):
    with pytest.raises(edi.TransportEdifactError):
        edi.analyze("UNB+" + syntax + "+S+R+261105:1200+REF'" + GS1 + "UNZ+1+REF'")


@pytest.mark.parametrize("text", ["", "UNA", "FTX+abc", "FTX+abc?", "FTX+bad?x'", "FTX+bad\nline'", "abc+a'",
    "UNA:+.?*'FTX+a'", "UNG+x'", "FTX+AAI'", "UNT+1+X'", "UNH+X+IFTMIN:D:96A:UN'",
    "UNH+X+IFTMIN:D:96A:UN'UNT+3+X'", "UNH+X+IFTMIN:D:96A:UN'UNT+2+Y'",
    "UNB+UNOC:4+A+B+DATE+R'" + GS1 + "UNZ+1+R'",
    "UNB+UNOC:3+A+B+DATE+R'" + GS1 + "UNZ+2+R'",
    "UNB+UNOC:3+A+B+DATE+R'" + GS1 + "UNZ+1+Q'",
    "UNB+UNOC:3+A+B+DATE+R'" + GS1,
    GS1 + GS1, GS1 + "UNZ+1+R'", GS1 + "BGM+610'", "\ud800"])
def test_rejects_malformed(text):
    with pytest.raises(edi.TransportEdifactError):
        edi.analyze(text)


@pytest.mark.parametrize("value", [None, 2, {}, [], bytearray(b"UNH"), True])
def test_invalid_input_types(value):
    for function in (edi.analyze, edi.parse_segments):
        with pytest.raises(edi.TransportEdifactError):
            function(value)


def test_bounded_inputs(monkeypatch):
    monkeypatch.setattr(edi, "MAX_INPUT", 10)
    with pytest.raises(edi.TransportEdifactError):
        edi.parse_segments(GS1)
    monkeypatch.setattr(edi, "MAX_INPUT", 1000)
    monkeypatch.setattr(edi, "MAX_COMPONENTS", 4)
    with pytest.raises(edi.TransportEdifactError):
        edi.parse_segments("FTX+a:b:c:d:e'")


def test_random_bytes_never_leak_stdlib_exception():
    rng = random.Random(931)
    for _ in range(300):
        data = rng.randbytes(rng.randrange(200))
        try:
            edi.analyze(data)
        except edi.TransportEdifactError:
            pass


def test_cli(tmp_path, capsys):
    assert edi.main(["--help"]) == 0
    assert edi.main([]) == 2
    path = tmp_path / "shipment.edi"
    path.write_text(GS1)
    assert edi.main([str(path)]) == 0
    assert '"IFTMIN"' in capsys.readouterr().out
    path.write_text("broken")
    assert edi.main([str(path)]) == 2
    assert edi.main([str(path / "missing")]) == 2
