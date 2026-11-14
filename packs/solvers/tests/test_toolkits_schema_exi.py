"""Schema-informed EXI decoding from an XSD (solvers/toolkits/_schema_exi.py, B-159).

Every expected stream is written out bit by bit from the EXI 1.0 rules (event-code widths and order
are literal strings below, with the grammar state they come from in the comment), so a decoder that
gets a width or an order wrong fails here. Two vectors are public known answers for the ISO 15118
application handshake; the schema they are decoded against is written in
tests/_schema_bundle_fixtures.py (the structure of the handshake, not an ISO file).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "solvers" / "toolkits"))
import _schema_exi as exi  # noqa: E402

from _schema_bundle_fixtures import (  # noqa: E402
    HANDSHAKE, HANDSHAKE_REQ, HANDSHAKE_RES, HEADER, KITCHEN, ROOT_MSG, XS, kitchen_stream, octets, pack, text, uint,
    xsd)


def schema(tmp_path: Path, body: str, name: str = "s.xsd", tns: str = "urn:t") -> exi.Schema:
    (tmp_path / name).write_text(xsd(body, tns))
    return exi.load_schema([tmp_path / name])


def fields(out: dict) -> dict:
    return dict(exi.flatten(out["document"]))


# ---- the public handshake vectors ----------------------------------------------------------------

def handshake_schema(tmp_path: Path) -> exi.Schema:
    (tmp_path / "hs.xsd").write_text(xsd(HANDSHAKE, "urn:t:hs", "unqualified"))
    return exi.load_schema([tmp_path / "hs.xsd"])


def test_known_handshake_request_decodes_to_its_fields(tmp_path):
    out = exi.decode(bytes.fromhex(HANDSHAKE_REQ), handshake_schema(tmp_path))
    assert out["root"] == {"name": "supportedAppProtocolReq", "namespace": "urn:t:hs",
                           "event_code": 0, "event_code_bits": 2}
    assert exi.flatten(out["document"]) == [
        ("supportedAppProtocolReq/AppProtocol/ProtocolNamespace", "urn:din:70121:2012:MsgDef"),
        ("supportedAppProtocolReq/AppProtocol/VersionNumberMajor", 2),
        ("supportedAppProtocolReq/AppProtocol/VersionNumberMinor", 0),
        ("supportedAppProtocolReq/AppProtocol/SchemaID", 1),
        ("supportedAppProtocolReq/AppProtocol/Priority", 1)]
    assert out["padding_bits"] == 6 and out["bits_consumed"] == 34 * 8 - 6


def test_known_handshake_response_decodes_enumeration_and_optional_element(tmp_path):
    out = exi.decode(bytes.fromhex(HANDSHAKE_RES), handshake_schema(tmp_path))
    assert out["root"]["event_code"] == 1
    assert fields(out) == {"supportedAppProtocolRes/ResponseCode": "OK_SuccessfulNegotiation",
                           "supportedAppProtocolRes/SchemaID": 1}


def test_bounded_occurrences_are_unrolled_so_the_last_one_has_no_repeat_code(tmp_path):
    """maxOccurs=2: after the first Item the state holds SE(Item), EE (2 bits with the deviation
    code); after the second only EE (1 bit). A loop instead of two copies would read 2 bits there."""
    s = schema(tmp_path, """
      <xs:element name="L"><xs:complexType><xs:sequence>
        <xs:element name="Item" type="xs:boolean" maxOccurs="2"/></xs:sequence></xs:complexType></xs:element>""")
    item = "0" "1" "0"                       # CH, true, EE (each state: one production + deviation)
    two = pack(HEADER, "0",                  # root: L of {L, SE(*)}: 1 bit
               "0", item,                    # L state 0: SE(Item)
               "00", item,                   # after 1 Item: SE(Item)=0, EE=1
               "0")                          # after 2 Items: EE only
    out = exi.decode(two, s)
    assert [k["value"] for k in out["document"]["children"]] == [True, True]
    one = pack(HEADER, "0", "0", item, "01")
    assert [k["value"] for k in exi.decode(one, s)["document"]["children"]] == [True]
    with pytest.raises(exi.ExiDecodeError):  # a third Item is not in the grammar: its bits are left over
        exi.decode(pack(HEADER, "0", "0", item, "00", item, "00", item, "1111 1111"), s)


# ---- one schema exercising attributes, substitution groups, extension, choice, simple content ----

def test_attributes_substitution_group_extension_and_string_table(tmp_path):
    out = exi.decode(kitchen_stream(), schema(tmp_path, KITCHEN))
    assert out["root"] == {"name": "Msg", "namespace": "urn:t", "event_code": 2, "event_code_bits": 3}
    assert exi.flatten(out["document"]) == [
        ("Msg/@Id", "m1"), ("Msg/@seq", 300),
        ("Msg/Id", {"hex": "cafe"}), ("Msg/Note", "hi"),
        ("Msg/Alpha/Level", -2), ("Msg/Alpha/Delta", -5),
        ("Msg/Item/@unit", "fast"), ("Msg/Item", "hi"), ("Msg/Item", "hi")]
    assert out["padding_bits"] < 8


def test_optional_attribute_and_element_skipped_and_choice_branch(tmp_path):
    stream = pack(
        HEADER, ROOT_MSG,
        "01", uint(7),                       # AT(seq)=1: the optional Id attribute is skipped
        "0", "0", octets(b"\x01"), "0",      # Id
        "011",                               # Note skipped: SE(Zeta)=3 of Note, Alpha, Head, Zeta
        "01", "0", "10", "0",                # ZetaType: SE(On)=0, SE(Mode)=1; CH; enum off = 2; EE
        "0",                                 # EE of Zeta
        "01")                                # no Item: EE=1
    out = exi.decode(stream, schema(tmp_path, KITCHEN))
    assert exi.flatten(out["document"]) == [("Msg/@seq", 7), ("Msg/Id", {"hex": "01"}), ("Msg/Zeta/Mode", "off")]
    other = pack(HEADER, ROOT_MSG, "01", uint(7), "0", "0", octets(b"\x01"), "0",
                 "011", "00", "0", "1", "0", "0", "01")      # the other branch: On = true
    assert fields(exi.decode(other, schema(tmp_path, KITCHEN)))["Msg/Zeta/On"] is True


def test_abstract_substitution_head_keeps_its_event_code(tmp_path):
    """The head is in the sorted member list (Alpha, Head, Zeta): Head is code 1 after Note is skipped
    off the 3-bit state, and its empty type is one EE."""
    stream = pack(HEADER, ROOT_MSG, "01", uint(1), "0", "0", octets(b""), "0",
                  "010",                     # SE(Head)=2 of Note, Alpha, Head, Zeta
                  "0",                       # HeadType: EE
                  "01")
    out = exi.decode(stream, schema(tmp_path, KITCHEN))
    assert [k["name"] for k in out["document"]["children"]] == ["Id", "Head"]


def test_local_string_table_hits_use_the_per_element_partition(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="L"><xs:complexType><xs:sequence>
        <xs:element name="Tag" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element name="Other" type="xs:string" minOccurs="0"/>
      </xs:sequence></xs:complexType></xs:element>""")
    tag = "00" "0"                           # SE(Tag)=0 of Tag, Other, EE -> 2 bits; CH
    stream = pack(HEADER, "0",
                  tag, text("ab"), "0",      # miss: Tag partition [ab]
                  tag, uint(0), "0",         # local hit, partition of 1: no index bits
                  tag, text("cd"), "0",      # miss: [ab, cd]
                  tag, uint(0), "1", "0",    # local hit, index 1 of 2
                  tag, text(""), "0",        # the empty string is never added
                  "01", "0", uint(1), "0", "0",   # SE(Other)=1; CH; global hit index 0 of 2 (1 bit); EE
                  "0")                       # after Other: EE
    out = exi.decode(stream, s)
    assert [k["value"] for k in out["document"]["children"]] == ["ab", "ab", "cd", "cd", "", "ab"]


def test_an_empty_string_value_leaves_both_string_tables_unchanged(tmp_path):
    """After an empty value the local partition and the global table still hold two strings, so a hit
    takes a 1-bit index; were "" added, the index would take 2 bits and every later bit would shift."""
    s = schema(tmp_path, """
      <xs:element name="L"><xs:complexType><xs:sequence>
        <xs:element name="Tag" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
        <xs:element name="Other" type="xs:string" minOccurs="0"/>
      </xs:sequence></xs:complexType></xs:element>""")
    tag = "00" "0"                           # SE(Tag)=0 of Tag, Other, EE -> 2 bits; CH
    bits = "".join([HEADER, "0",
                    tag, text("ab"), "0",    # miss: Tag partition [ab], global [ab]
                    tag, text("cd"), "0",    # miss: [ab, cd] in both
                    tag, text(""), "0",      # empty: added to neither
                    tag, uint(0), "1", "0",  # local hit, index 1 of 2 -> 1 bit -> cd
                    "01", "0", uint(1), "1", "0",   # SE(Other)=1; CH; global hit index 1 of 2 (1 bit) -> cd; EE
                    "0"])                    # after Other: EE
    out = exi.decode(pack(bits), s)
    assert [k["value"] for k in out["document"]["children"]] == ["ab", "cd", "", "cd", "cd"]
    assert out["bits_consumed"] == len(bits)


def test_datatypes(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="D"><xs:complexType><xs:sequence>
        <xs:element name="u" type="xs:unsignedInt"/>
        <xs:element name="i" type="xs:int"/>
        <xs:element name="dec" type="xs:decimal"/>
        <xs:element name="f" type="xs:double"/>
        <xs:element name="inf" type="xs:float"/>
        <xs:element name="list" type="t:bytes"/>
        <xs:element name="b64" type="xs:base64Binary"/>
        <xs:element name="pos" type="xs:positiveInteger"/>
        <xs:element name="b" type="xs:byte"/>
      </xs:sequence></xs:complexType></xs:element>
      <xs:simpleType name="bytes"><xs:list itemType="xs:unsignedByte"/></xs:simpleType>""")

    def leaf(value: str) -> str:
        return "0" "0" + value + "0"         # SE; CH; value; EE

    stream = pack(HEADER, "0",
                  leaf(uint(70000)),                       # three octets
                  leaf("0" + uint(123456)),                # xs:int: sign, magnitude
                  leaf("1" + uint(1) + uint(50)),          # -1.05: fraction digits reversed
                  leaf("0" + uint(15) + "1" + uint(0)),    # mantissa 15, exponent -1
                  leaf("0" + uint(1) + "1" + uint(16383)),  # exponent -(2**14): INF
                  leaf(uint(2) + "00000111" + "11111111"),  # two list items, 8 bits each
                  leaf(octets(b"hey")),
                  leaf(uint(9)),                           # positiveInteger has no upper bound: Unsigned Integer
                  leaf("00000000"),                        # xs:byte: 8 bits over -128..127
                  "0")
    got = fields(exi.decode(stream, s))
    assert got["D/u"] == 70000 and got["D/i"] == 123456 and got["D/dec"] == "-1.05"
    assert got["D/f"] == pytest.approx(1.5) and got["D/inf"] == "INF"
    assert got["D/list"] == [7, 255] and got["D/b64"] == {"hex": b"hey".hex()}
    assert got["D/pos"] == 9 and got["D/b"] == -128


def test_cookie_is_accepted(tmp_path):
    out = exi.decode(b"$EXI" + bytes.fromhex(HANDSHAKE_RES), handshake_schema(tmp_path))
    assert out["header"]["cookie"] is True and out["root"]["name"] == "supportedAppProtocolRes"


def test_mixed_content_text_and_wildcard_width(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="W"><xs:complexType mixed="true"><xs:sequence>
        <xs:element name="a" type="xs:boolean" minOccurs="0"/>
        <xs:any namespace="##other" minOccurs="0"/>
      </xs:sequence></xs:complexType></xs:element>""")
    # state 0: SE(a)=0, SE(*)=1, EE=2, CH=3 -> 4 productions + deviation = 3 bits
    out = exi.decode(pack(HEADER, "0", "011", text("note"), "010"), s)
    assert out["document"]["text"] == ["note"] and "children" not in out["document"]
    with pytest.raises(exi.ExiUnsupported, match="wildcard element"):
        exi.decode(pack(HEADER, "0", "001", "0000 0000"), s)


# ---- the rest of the XSD constructs -------------------------------------------------------------

def test_group_attribute_group_global_attribute_and_include_without_namespace(tmp_path):
    """SE order is schema order (g1 before g2) even when g2 comes from an earlier copy of the group
    than g1 does: after the first g1 the state holds g2 of copy 1 and g1 of copy 2."""
    (tmp_path / "inc.xsd").write_text(f"""<xs:schema {XS} elementFormDefault="qualified">
      <xs:group name="G"><xs:sequence>
        <xs:element name="g1" type="Flag"/><xs:element name="g2" type="Flag" minOccurs="0"/>
      </xs:sequence></xs:group>
      <xs:simpleType name="Flag"><xs:restriction base="xs:boolean"/></xs:simpleType>
    </xs:schema>""")
    s = schema(tmp_path, """
      <xs:include schemaLocation="inc.xsd"/>
      <xs:attribute name="gk" type="xs:boolean"/>
      <xs:attributeGroup name="AG">
        <xs:attribute name="k" type="t:Flag" use="required"/><xs:attribute ref="t:gk"/>
      </xs:attributeGroup>
      <xs:element name="R"><xs:complexType>
        <xs:sequence><xs:group ref="t:G" maxOccurs="2"/></xs:sequence>
        <xs:attributeGroup ref="t:AG"/>
      </xs:complexType></xs:element>""")
    flag = lambda bit: "0" + bit + "0"       # noqa: E731  CH, the boolean, EE
    stream = pack(HEADER, "0",
                  "00", "1",                 # AT(gk)=0, AT(k)=1 by local name; gk = true
                  "0", "0",                  # AT(k); false
                  "0", flag("1"),            # SE(g1): the only production
                  "00", flag("0"),           # g1=0, g2=1, EE=2 -> g1 again (copy 2)
                  "00", flag("1"),           # g2=0, EE=1
                  "0")                       # EE
    out = exi.decode(stream, s)
    assert exi.flatten(out["document"]) == [("R/@gk", True), ("R/@k", False),
                                            ("R/g1", True), ("R/g1", False), ("R/g2", True)]
    assert {k["namespace"] for k in out["document"]["children"]} == {"urn:t"}
    late = pack(HEADER, "0", "01", "1",      # AT(k)=1: gk skipped
                "0", flag("1"),              # g1
                "01", flag("1"),             # g1=0, g2=1, EE=2 -> g2 of copy 1
                "00", flag("0"),             # copy 2: g1=0, EE=1
                "00", flag("1"),             # g2=0, EE=1
                "0")
    assert exi.flatten(exi.decode(late, s)["document"])[1:] == [
        ("R/g1", True), ("R/g2", True), ("R/g1", False), ("R/g2", True)]


def test_all_group_union_and_attribute_wildcard(tmp_path):
    (tmp_path / "u.xsd").write_text(f"""<xs:schema {XS} xmlns:t="urn:t" targetNamespace="urn:t">
      <xs:element name="A" type="t:AllT"/>
      <xs:complexType name="AllT">
        <xs:all><xs:element name="p" type="xs:boolean"/><xs:element name="q" type="t:U" minOccurs="0"/></xs:all>
        <xs:anyAttribute/>
      </xs:complexType>
      <xs:simpleType name="U"><xs:union memberTypes="xs:boolean xs:int"/></xs:simpleType>
    </xs:schema>""")
    s = exi.load_schema([tmp_path / "u.xsd"])
    stream = pack(HEADER, "0",
                  "010", "0", text("7"), "0",    # AT(*)=0, SE(p)=1, SE(q)=2, EE=3 -> q; a union is a String
                  "00", "0", "1", "0",           # no attribute state left: p=0, q=1, EE=2 -> p
                  "10")                          # EE
    out = exi.decode(stream, s)
    assert exi.flatten(out["document"]) == [("A/q", "7"), ("A/p", True)]
    assert [k["namespace"] for k in out["document"]["children"]] == ["", ""]   # unqualified local elements
    with pytest.raises(exi.ExiUnsupported, match="wildcard attribute"):
        exi.decode(pack(HEADER, "0", "000", "0000 0000"), s)


def test_complex_restriction_replaces_content_and_drops_a_prohibited_attribute(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="B" type="t:Narrow"/>
      <xs:complexType name="Wide">
        <xs:sequence><xs:element name="a" type="xs:boolean" minOccurs="0"/><xs:element name="b" type="xs:boolean"/></xs:sequence>
        <xs:attribute name="m" type="xs:boolean"/><xs:attribute name="n" type="xs:boolean"/>
      </xs:complexType>
      <xs:complexType name="Narrow"><xs:complexContent><xs:restriction base="t:Wide">
        <xs:sequence><xs:element name="b" type="xs:boolean"/></xs:sequence>
        <xs:attribute name="m" use="prohibited"/>
      </xs:restriction></xs:complexContent></xs:complexType>""")
    # Narrow state 0: AT(n)=0, SE(b)=1 -> 2 bits (as an extension it would be m, n, a, b: 3 bits)
    out = exi.decode(pack(HEADER, "0", "01", "0", "1", "0", "0"), s)
    assert exi.flatten(out["document"]) == [("B/b", True)]
    out = exi.decode(pack(HEADER, "0", "00", "1", "0", "0", "0", "0", "0"), s)   # n=true; SE(b) alone; false
    assert exi.flatten(out["document"]) == [("B/@n", True), ("B/b", False)]


def test_simple_content_restriction_narrows_the_value_and_keeps_the_attribute(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="S" type="t:Small"/>
      <xs:complexType name="Qty"><xs:simpleContent><xs:extension base="xs:unsignedShort">
        <xs:attribute name="unit" type="xs:boolean"/></xs:extension></xs:simpleContent></xs:complexType>
      <xs:complexType name="Small"><xs:simpleContent><xs:restriction base="t:Qty">
        <xs:maxInclusive value="15"/></xs:restriction></xs:simpleContent></xs:complexType>""")
    out = exi.decode(pack(HEADER, "0", "00", "1", "0", "1001", "0"), s)   # AT(unit); CH; 9 in 4 bits; EE
    assert exi.flatten(out["document"]) == [("S/@unit", True), ("S", 9)]


def test_namespace_wildcards_each_take_an_event_code(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="N"><xs:complexType><xs:sequence>
        <xs:element name="a" type="xs:boolean" minOccurs="0"/>
        <xs:any namespace="urn:zzz ##targetNamespace" minOccurs="0"/>
      </xs:sequence></xs:complexType></xs:element>""")
    # SE(a)=0, SE(urn:t:*)=1, SE(urn:zzz:*)=2, EE=3 -> 3 bits
    assert "children" not in exi.decode(pack(HEADER, "0", "011"), s)["document"]
    for code in ("001", "010"):
        with pytest.raises(exi.ExiUnsupported, match="wildcard element"):
            exi.decode(pack(HEADER, "0", code, "0000 0000"), s)


def test_untyped_element_inline_type_and_substitution_member_without_a_type(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="Any"/>
      <xs:element name="H" type="xs:boolean"/>
      <xs:element name="I"><xs:simpleType><xs:restriction base="xs:unsignedByte">
        <xs:maxInclusive value="3"/></xs:restriction></xs:simpleType></xs:element>
      <xs:element name="M" substitutionGroup="t:H"/>""")
    # roots by name: Any 0, H 1, I 2, M 3 -> 3 bits
    assert exi.decode(pack(HEADER, "011", "0", "1", "0"), s)["document"] == {
        "name": "M", "namespace": "urn:t", "value": True}             # M takes its head's type
    assert exi.decode(pack(HEADER, "010", "0", "11", "0"), s)["document"]["value"] == 3   # 0..3: 2 bits
    # xs:anyType: AT(*)=0, SE(*)=1, EE=2, CH=3 -> 3 bits
    assert exi.decode(pack(HEADER, "000", "011", text("x"), "010"), s)["document"]["text"] == ["x"]


def test_recursive_types_load_lazily_and_depth_and_node_limits_hold(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="N" type="t:Nest"/>
      <xs:complexType name="Nest"><xs:sequence><xs:element ref="t:N" minOccurs="0"/></xs:sequence></xs:complexType>""")
    out = exi.decode(pack(HEADER, "0", "00", "00", "01", "0", "0"), s)     # N > N > N; SE(N)=0, EE=1; then EE alone
    assert out["document"]["children"][0]["children"][0] == {"name": "N", "namespace": "urn:t"}
    with pytest.raises(exi.ExiDecodeError, match="nest deeper"):
        exi.decode(pack(HEADER, "0", "00" * 80), s)
    with pytest.raises(exi.ExiDecodeError, match="more nodes"):
        exi.decode(pack(HEADER, "0", "00", "00", "01", "0", "0"), s, max_nodes=2)


def test_a_content_model_too_large_to_unroll_is_refused(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="Big"><xs:complexType><xs:sequence>
        <xs:element name="e" type="xs:boolean" maxOccurs="1000000"/></xs:sequence></xs:complexType></xs:element>""")
    with pytest.raises(exi.ExiSchemaError, match="more than"):
        exi.decode(pack(HEADER, "0", "0000 0000"), s)


# ---- named failures ------------------------------------------------------------------------------

def test_header_options_and_bad_magic_are_named(tmp_path):
    s = handshake_schema(tmp_path)
    with pytest.raises(exi.ExiUnsupported, match="options document"):
        exi.decode(pack("10" "1" "0" "0000", "0000 0000"), s)
    with pytest.raises(exi.ExiDecodeError, match="distinguishing bits"):
        exi.decode(b"\x00\x00\x00", s)
    with pytest.raises(exi.ExiUnsupported, match="SE\\(\\*\\)"):
        exi.decode(pack(HEADER, "10"), s)                 # root code 2 of {Req, Res, SE(*)}
    with pytest.raises(exi.ExiDecodeError, match="not in the document grammar"):
        exi.decode(pack(HEADER, "11"), s)


def test_deviation_truncation_and_trailing_bits_are_named(tmp_path):
    s = schema(tmp_path, KITCHEN)
    with pytest.raises(exi.ExiUnsupported, match="deviation"):
        exi.decode(pack(HEADER, ROOT_MSG, "10", "0000 0000"), s)      # code 2 = the strict=false escape
    good = kitchen_stream()
    with pytest.raises(exi.ExiDecodeError, match="runs past the stream"):
        exi.decode(good[:9], s)                                       # cut inside the hexBinary Id
    with pytest.raises(exi.ExiDecodeError, match="stream ends"):
        exi.decode(good[:6], s)                                       # cut inside the seq attribute
    assert 0 < exi.decode(good, s)["padding_bits"] < 8                # so the last bit below is padding
    with pytest.raises(exi.ExiDecodeError, match="follow the document"):
        exi.decode(good + b"\x00", s)
    with pytest.raises(exi.ExiDecodeError, match="follow the document"):
        exi.decode(good[:-1] + bytes([good[-1] | 1]), s)              # a set padding bit
    assert exi.decode(good + b"\x00", s, allow_trailing=True)["padding_bits"] >= 8


def test_unsupported_value_types_fail_by_name_not_as_strings(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="When" type="xs:dateTime"/>
      <xs:element name="Code" type="t:code"/>
      <xs:simpleType name="code"><xs:restriction base="xs:string"><xs:pattern value="[A-F]{4}"/></xs:restriction></xs:simpleType>""")
    with pytest.raises(exi.ExiUnsupported, match="Date-Time"):
        exi.decode(pack(HEADER, "01", "0", "0000 0000"), s)           # Code 0, When 1
    with pytest.raises(exi.ExiUnsupported, match="restricted character set"):
        exi.decode(pack(HEADER, "00", "0", "0000 0000"), s)


def test_imports_are_followed_on_disk_and_a_missing_one_is_named(tmp_path):
    folder = tmp_path / "fam"
    folder.mkdir()
    (folder / "main.xsd").write_text(f"""<xs:schema {XS} xmlns:t="urn:t" xmlns:o="urn:other"
        targetNamespace="urn:t" elementFormDefault="qualified">
      <xs:import namespace="urn:other" schemaLocation="http://example.invalid/schemas/other.xsd"/>
      <xs:element name="Top"><xs:complexType><xs:sequence><xs:element ref="o:Leaf"/></xs:sequence></xs:complexType></xs:element>
    </xs:schema>""")
    with pytest.raises(exi.ExiSchemaMissing) as err:
        exi.load_schema([folder / "main.xsd"])
    assert err.value.path == (folder / "other.xsd").resolve() and "main.xsd" in str(err.value)
    # the W3C signature schema's shape: a DOCTYPE with an external id and an internal subset, and the
    # XSD namespace as the default one. Nothing is fetched; unprefixed type names resolve to XSD.
    (folder / "other.xsd").write_text("""<?xml version="1.0"?>
      <!DOCTYPE schema PUBLIC "-//W3C//DTD XMLSchema 200102//EN" "http://www.w3.org/2001/XMLSchema.dtd" [
        <!ATTLIST schema xmlns:o CDATA #FIXED "urn:other">
        <!ENTITY onode 'urn:other'>
        <!ENTITY % p ''>
        <!ENTITY % s ''>
      ]>
      <schema xmlns="http://www.w3.org/2001/XMLSchema" xmlns:o="urn:other" targetNamespace="urn:other"
              elementFormDefault="qualified">
        <element name="Leaf" type="o:LeafType"/>
        <simpleType name="LeafType"><restriction base="unsignedByte"/></simpleType>
      </schema>""")
    s = exi.load_schema([folder / "main.xsd"])
    assert [d.qname for d in s.global_elements] == [("urn:other", "Leaf"), ("urn:t", "Top")]
    out = exi.decode(pack(HEADER, "01", "0", "0", "00101010", "0", "0"), s)   # Top; SE(Leaf); CH; 42; EE; EE
    assert exi.flatten(out["document"]) == [("Top/Leaf", 42)]


def test_an_import_may_not_leave_the_schema_folder(tmp_path):
    folder = tmp_path / "fam"
    folder.mkdir()
    (tmp_path / "outside.xsd").write_text(f'<xs:schema {XS} targetNamespace="urn:x"/>')
    (folder / "main.xsd").write_text(f"""<xs:schema {XS} targetNamespace="urn:t">
      <xs:import namespace="urn:x" schemaLocation="../outside.xsd"/></xs:schema>""")
    with pytest.raises(exi.ExiSchemaError, match="leaves the schema folder"):
        exi.load_schema([folder / "main.xsd"])


def test_schema_errors_are_named(tmp_path):
    (tmp_path / "bad.xsd").write_text("<not-a-schema/>")
    with pytest.raises(exi.ExiSchemaError, match="not xs:schema"):
        exi.load_schema([tmp_path / "bad.xsd"])
    with pytest.raises(exi.ExiSchemaMissing):
        exi.load_schema([tmp_path / "absent.xsd"])
    s = schema(tmp_path, '<xs:element name="E" type="t:Nope"/>')
    with pytest.raises(exi.ExiSchemaError, match="'Nope'"):
        exi.decode(pack(HEADER, "0", "0000 0000"), s)


def test_more_schema_errors_are_named(tmp_path):
    with pytest.raises(exi.ExiSchemaError, match="element 'E' .* is defined twice"):
        schema(tmp_path, '<xs:element name="E" type="xs:boolean"/><xs:element name="E" type="xs:int"/>')
    (tmp_path / "base.xsd").write_text(xsd(""))
    with pytest.raises(exi.ExiSchemaError, match="xs:redefine"):
        schema(tmp_path, '<xs:redefine schemaLocation="base.xsd"/>')
    (tmp_path / "p.xsd").write_text(
        f'<xs:schema {XS} xmlns:t="urn:a" targetNamespace="urn:a"><xs:element xmlns:t="urn:b" name="E"/></xs:schema>')
    with pytest.raises(exi.ExiSchemaError, match="prefix 't' is bound to two namespaces"):
        exi.load_schema([tmp_path / "p.xsd"])
    (tmp_path / "i.xsd").write_text(f"""<xs:schema {XS} xmlns:o="urn:o" targetNamespace="urn:t">
      <xs:import namespace="urn:o"/>
      <xs:element name="E"><xs:complexType><xs:sequence><xs:element ref="o:Leaf"/></xs:sequence></xs:complexType></xs:element>
    </xs:schema>""")
    s = exi.load_schema([tmp_path / "i.xsd"])
    with pytest.raises(exi.ExiSchemaError, match="'Leaf' .*imported without a schemaLocation"):
        exi.decode(pack(HEADER, "0", "0000 0000"), s)
    with pytest.raises(exi.ExiSchemaError, match="prefix 'zz' in 'zz:T' is not declared"):
        exi.decode(pack(HEADER, "0", "0000 0000"), schema(tmp_path, '<xs:element name="E" type="zz:T"/>'))
    with pytest.raises(exi.ExiSchemaError, match="no schema file given"):
        exi.load_schema([])


def test_header_version_and_input_checks(tmp_path):
    s = handshake_schema(tmp_path)
    with pytest.raises(exi.ExiUnsupported, match="preview version"):
        exi.decode(pack("10" "0" "1" "0000", "0000 0000"), s)
    with pytest.raises(exi.ExiUnsupported, match="version field 1"):
        exi.decode(pack("10" "0" "0" "0001", "0000 0000"), s)
    for bad in ("80400040", b"", None):
        with pytest.raises(exi.ExiDecodeError, match="input must"):
            exi.decode(bad, s)
    assert exi.decode(bytearray.fromhex(HANDSHAKE_RES), s)["root"]["name"] == "supportedAppProtocolRes"


def test_malformed_values_are_decode_errors(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="V"><xs:complexType><xs:choice>
        <xs:element name="s" type="xs:string"/>
        <xs:element name="m" type="t:mode"/>
        <xs:element name="h" type="xs:hexBinary"/>
        <xs:element name="l" type="t:flags"/>
        <xs:element name="u" type="xs:unsignedInt"/>
        <xs:element name="f" type="xs:float"/>
      </xs:choice></xs:complexType></xs:element>
      <xs:simpleType name="mode"><xs:restriction base="xs:string">
        <xs:enumeration value="a"/><xs:enumeration value="b"/><xs:enumeration value="c"/></xs:restriction></xs:simpleType>
      <xs:simpleType name="flags"><xs:list><xs:simpleType><xs:restriction base="xs:boolean"/></xs:simpleType></xs:list></xs:simpleType>""")

    def value(code: str, bits: str) -> bytes:        # root V; choice code of 6 (3 bits); CH; the value
        return pack(HEADER, "0", code, "0", bits, "0000 0000")

    cases = [("000", uint(0), "local string-table hit on an empty partition"),
             ("000", uint(1), "global string-table hit on an empty table"),
             ("000", uint(3) + uint(0x110000), "is not a character"),
             ("000", uint(500) + "01100001", "string length 498 runs past the stream"),
             ("001", "11", "enumeration index 3 of 3"),
             ("010", uint(200), "binary length 200 runs past the stream"),
             ("011", uint(5000), "list length 5000 runs past the stream"),
             ("100", "11111111" * 41, "runs past 40 octets")]
    for code, bits, message in cases:
        with pytest.raises(exi.ExiDecodeError, match=message):
            exi.decode(value(code, bits), s)
    ok = exi.decode(pack(HEADER, "0", "011", "0", uint(3), "101", "0", "0"), s)       # a list of three booleans
    assert fields(ok) == {"V/l": [True, False, True]}
    big = exi.decode(pack(HEADER, "0", "101", "0", "0" + uint(15), "0" + uint(500), "0", "0"), s)
    assert fields(big) == {"V/f": "15E500"}                                            # too large for a float
    nan = exi.decode(pack(HEADER, "0", "101", "0", "0" + uint(7), "1" + uint(16383), "0", "0"), s)
    assert fields(nan) == {"V/f": "NaN"}


def test_inline_attribute_type_and_restriction_over_an_inline_base(tmp_path):
    s = schema(tmp_path, """
      <xs:element name="E"><xs:complexType>
        <xs:attribute name="lvl"><xs:simpleType><xs:restriction>
          <xs:simpleType><xs:restriction base="xs:unsignedByte"><xs:maxInclusive value="100"/></xs:restriction></xs:simpleType>
          <xs:minExclusive value="96"/><xs:maxExclusive value="100"/>
        </xs:restriction></xs:simpleType></xs:attribute>
        <xs:attribute name="raw"/>
      </xs:complexType></xs:element>""")
    # 97..99: 3 values, 2 bits. state 0: AT(lvl)=0, AT(raw)=1, EE=2; after lvl: AT(raw)=0, EE=1
    out = exi.decode(pack(HEADER, "0", "00", "10", "00", text("x"), "0"), s)
    assert out["document"]["attributes"] == {"lvl": 99, "raw": "x"}               # no type: anySimpleType, a String


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
