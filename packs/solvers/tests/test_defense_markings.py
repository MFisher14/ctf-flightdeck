"""Published DoDM/NSA examples plus independent namespaced XML fixtures."""
import random

import pytest

from defense_markings import MarkingsError, main, parse_ism, parse_marking, parse_text


@pytest.mark.parametrize("banner,code,sci,controls", [
    # DoDM5200.01 Vol2 Fig33 and NSA/CSS PM1-52 Table1 (public illustration text).
    ("TOP SECRET//HCS//NOFORN", "TS", ["HCS"], ["NOFORN"]),
    ("SECRET//SI/TK//RELIDO", "S", ["SI", "TK"], ["RELIDO"]),
    ("TOP SECRET//SI-GAMMA//ORCON//NOFORN", "TS", ["SI-GAMMA"], ["ORCON", "NOFORN"]),
    ("(TS//SI-G//OC//NF)", "TS", ["SI-G"], ["ORCON", "NOFORN"]),
    ("UNCLASSIFIED//FOR OFFICIAL USE ONLY", "U", [], ["FOUO"]),
])
def test_published_markings(banner, code, sci, controls):
    result = parse_marking(banner)
    assert result["classification"] == code
    assert result["sci_controls"] == sci
    assert result["dissemination_controls"] == controls


def test_published_release_and_portion_shorthand():
    assert parse_marking("CONFIDENTIAL//REL TO USA, FVEY")["releasable_to"] == ["USA", "FVEY"]
    shorthand = parse_marking("(TS//SI/TK//REL)")
    assert shorthand["releasable_to"] == []
    assert "enclosing banner" in shorthand["warnings"][0]


def test_unknown_and_conflicting_controls_never_lost():
    result = parse_marking("SECRET//CUSTOM-ALPHA//NOFORN/REL TO USA, GBR")
    assert result["unknown_controls"] == ["CUSTOM-ALPHA"]
    assert len(result["warnings"]) == 2
    assert parse_marking("U//SI")["warnings"]


def test_line_extraction():
    result = parse_text("SECRET//SI//NOFORN\nTitle\n(S//SI//NF) CSCTF{label}\n(U) Public\n(Example) prose\n")
    assert [r["line"] for r in result["records"]] == [1, 3, 4]
    assert result["records"][1]["text"] == "CSCTF{label}"
    assert result["unmarked_nonempty_lines"] == 2
    assert result["policy_evaluated"] is False


def test_dodaf_published_ism_example():
    # DoDAF Volume III, p3-6: exact example title + security attributes.
    xml = '''<ddms:Resource xmlns:ddms="http://ddms.dod.mil"
      xmlns:ICISM="urn:us:gov:ic:ism:v2">
      <ddms:title ICISM:classification="U" ICISM:ownerProducer="USA">T-AKE C4ISP Final.doc</ddms:title>
    </ddms:Resource>'''
    result = parse_ism(xml)
    assert len(result["records"]) == 1
    record = result["records"][0]
    assert record["text"] == "T-AKE C4ISP Final.doc"
    assert record["classification"] == "U"
    assert record["lists"]["ownerProducer"] == ["USA"]
    assert result["unmarked_elements"] == 1


def test_namespace_uri_and_explicit_markings():
    xml = '''<r xmlns:x="urn:us:gov:ic:ism" x:classification="TS" x:ownerProducer="USA">
      <p x:classification="U" x:ownerProducer="USA">public</p>
      <p>unmarked</p><p x:classification="OTHER" x:SCIcontrols="SI TK"
         x:releasableTo="USA GBR">unknown</p>
      <p xmlns:evil="urn:evil" evil:classification="U">spoof</p>
    </r>'''
    result = parse_ism(xml)
    assert [r["classification"] for r in result["records"]] == ["TS", "U", "OTHER"]
    assert result["records"][2]["level"] is None
    assert result["records"][2]["lists"]["SCIcontrols"] == ["SI", "TK"]
    assert result["attributes_inherited"] is False
    assert result["unmarked_elements"] == 2
    assert len(result["warnings"]) == 3


@pytest.mark.parametrize("xml", [
    '<r xmlns:ism="urn:evil" ism:classification="U"/>',
    '<r classification="U"/>', '<r>', '<r/ trailing>',
    '<!DOCTYPE r [<!ENTITY e "boom">]><r>&e;</r>',
    '<!DOCTYPE r SYSTEM "file:///etc/passwd"><r/>',
    '<r xmlns:a="urn:us:gov:ic:ism" xmlns:b="urn:us:gov:ic:ism:v2" a:classification="U" b:classification="S"/>',
    '<r>' * 33 + '</r>' * 33,
    '<r>' + '<p/>' * 4096 + '</r>',
])
def test_rejects_xml_malformed_unsafe_ambiguous_and_limits(xml):
    with pytest.raises(MarkingsError):
        parse_ism(xml)


@pytest.mark.parametrize("value", [None, 5, [], {}, True, b"\xff", "\ud800", "U\x00", "x" * (2**20 + 1)])
@pytest.mark.parametrize("parser", [parse_marking, parse_text, parse_ism])
def test_public_input_contract(value, parser):
    with pytest.raises(MarkingsError):
        parser(value)


@pytest.mark.parametrize("value", ["", "PUBLIC", "COSMIC TOP SECRET", "(S", "S)", "S///NF", "S//",
                                   "S//REL TO USA, ??", "S//NOFORN\nU", "S//nonsense", "S//(NF)"])
def test_bad_marking_syntax(value):
    with pytest.raises(MarkingsError):
        parse_marking(value)


def test_deterministic_garbage_contract():
    rng = random.Random(5200)
    for n in range(256):
        raw = rng.randbytes(n)
        for parser in (parse_marking, parse_text, parse_ism):
            try:
                parser(raw)
            except MarkingsError:
                pass


def test_cli(tmp_path):
    source = tmp_path / "marking.txt"
    source.write_text("(S//NF) CSCTF{test}\n")
    assert main([str(source)]) == 0
    assert main(["--help"]) == 0
    assert main([]) == 2
    assert main([str(tmp_path / "missing")]) == 2
    assert main(["bad\x00path"]) == 2


@pytest.mark.parametrize("encoding", ["UTF-16", "UTF-32", "ISO-8859-1", "unknown"])
@pytest.mark.parametrize("as_bytes", [False, True])
def test_incompatible_xml_encoding_declaration(encoding, as_bytes):
    source = (f'<?xml version="1.0" encoding="{encoding}"?>'
              '<r xmlns:i="urn:us:gov:ic:ism" i:classification="U" i:ownerProducer="USA"/>')
    with pytest.raises(MarkingsError, match="encoding declaration"):
        parse_ism(source.encode("utf-8") if as_bytes else source)


@pytest.mark.parametrize("encoding", ["UTF-8", "utf8", "US-ASCII", "ascii"])
def test_compatible_xml_encoding_declaration(encoding):
    source = (f"<?xml version='1.0' encoding='{encoding}'?>"
              '<r xmlns:i="urn:us:gov:ic:ism" i:classification="U" i:ownerProducer="USA"/>')
    assert parse_ism(source.encode())["records"][0]["classification"] == "U"


def test_ascii_declaration_rejects_non_ascii_literal():
    source = ('<?xml version="1.0" encoding="ASCII"?>'
              '<r xmlns:i="urn:us:gov:ic:ism" i:classification="U">caf\u00e9</r>')
    with pytest.raises(MarkingsError, match="non-ASCII"):
        parse_ism(source.encode("utf-8"))
