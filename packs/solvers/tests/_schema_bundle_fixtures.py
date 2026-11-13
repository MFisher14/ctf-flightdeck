"""Shared fixtures of the schema-bundle tests (B-159): bit-string builders for hand-written EXI
streams and two synthetic XSDs. Nothing here is a real standard's schema file: HANDSHAKE has the
structure of the ISO 15118 application handshake (so the two public known-answer vectors decode
against it), KITCHEN is invented to exercise attributes, substitution groups, extension, choice
and simple content.
"""
from __future__ import annotations

XS = 'xmlns:xs="http://www.w3.org/2001/XMLSchema"'
HEADER = "10" "0" "0" "0000"      # distinguishing bits, no options, final version 1


def xsd(body: str, tns: str = "urn:t", form: str = "qualified") -> str:
    return (f'<xs:schema {XS} xmlns:t="{tns}" targetNamespace="{tns}" elementFormDefault="{form}">'
            f'{body}</xs:schema>')


def pack(*parts: str) -> bytes:
    bits = "".join(parts).replace(" ", "")
    bits += "0" * (-len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


def uint(n: int) -> str:
    """EXI Unsigned Integer: 7-bit groups, least significant first, top bit = more follows."""
    out = ""
    while True:
        group, n = n & 0x7F, n >> 7
        out += f"{group | (0x80 if n else 0):08b}"
        if not n:
            return out


def text(s: str) -> str:
    """A string-table miss: length + 2, then each code point."""
    return uint(len(s) + 2) + "".join(uint(ord(c)) for c in s)


def octets(raw: bytes) -> str:
    return uint(len(raw)) + "".join(f"{b:08b}" for b in raw)



HANDSHAKE = """
  <xs:element name="supportedAppProtocolReq"><xs:complexType><xs:sequence>
    <xs:element name="AppProtocol" type="t:AppProtocolType" maxOccurs="20"/>
  </xs:sequence></xs:complexType></xs:element>
  <xs:element name="supportedAppProtocolRes"><xs:complexType><xs:sequence>
    <xs:element name="ResponseCode" type="t:responseCodeType"/>
    <xs:element name="SchemaID" type="t:idType" minOccurs="0"/>
  </xs:sequence></xs:complexType></xs:element>
  <xs:complexType name="AppProtocolType"><xs:sequence>
    <xs:element name="ProtocolNamespace" type="t:protocolNamespaceType"/>
    <xs:element name="VersionNumberMajor" type="xs:unsignedInt"/>
    <xs:element name="VersionNumberMinor" type="xs:unsignedInt"/>
    <xs:element name="SchemaID" type="t:idType"/>
    <xs:element name="Priority" type="t:priorityType"/>
  </xs:sequence></xs:complexType>
  <xs:simpleType name="idType"><xs:restriction base="xs:unsignedByte"/></xs:simpleType>
  <xs:simpleType name="protocolNamespaceType"><xs:restriction base="xs:anyURI">
    <xs:maxLength value="100"/></xs:restriction></xs:simpleType>
  <xs:simpleType name="priorityType"><xs:restriction base="xs:unsignedByte">
    <xs:minInclusive value="1"/><xs:maxInclusive value="20"/></xs:restriction></xs:simpleType>
  <xs:simpleType name="responseCodeType"><xs:restriction base="xs:string">
    <xs:enumeration value="OK_SuccessfulNegotiation"/>
    <xs:enumeration value="OK_SuccessfulNegotiationWithMinorDeviation"/>
    <xs:enumeration value="Failed_NoNegotiation"/></xs:restriction></xs:simpleType>
"""
HANDSHAKE_REQ = "8000dbab9371d3234b71d1b981899189d191818991d26b9b3a232b30020000040040"
HANDSHAKE_RES = "80400040"



KITCHEN = """
  <xs:element name="Msg" type="t:MsgType"/>
  <xs:element name="Head" type="t:HeadType" abstract="true"/>
  <xs:element name="Zeta" type="t:ZetaType" substitutionGroup="t:Head"/>
  <xs:element name="Alpha" type="t:AlphaType" substitutionGroup="t:Head"/>
  <xs:complexType name="MsgType">
    <xs:sequence>
      <xs:element name="Id" type="xs:hexBinary"/>
      <xs:element name="Note" type="xs:string" minOccurs="0"/>
      <xs:element ref="t:Head"/>
      <xs:element name="Item" type="t:ItemType" minOccurs="0" maxOccurs="2"/>
    </xs:sequence>
    <xs:attribute name="seq" type="xs:unsignedShort" use="required"/>
    <xs:attribute name="Id" type="xs:ID"/>
  </xs:complexType>
  <xs:complexType name="HeadType"><xs:sequence/></xs:complexType>
  <xs:complexType name="AlphaType"><xs:complexContent><xs:extension base="t:HeadType"><xs:sequence>
    <xs:element name="Level" type="t:levelType"/><xs:element name="Delta" type="xs:short"/>
  </xs:sequence></xs:extension></xs:complexContent></xs:complexType>
  <xs:complexType name="ZetaType"><xs:complexContent><xs:extension base="t:HeadType"><xs:choice>
    <xs:element name="On" type="xs:boolean"/><xs:element name="Mode" type="t:modeType"/>
  </xs:choice></xs:extension></xs:complexContent></xs:complexType>
  <xs:complexType name="ItemType"><xs:simpleContent><xs:extension base="xs:string">
    <xs:attribute name="unit" type="t:modeType"/></xs:extension></xs:simpleContent></xs:complexType>
  <xs:simpleType name="levelType"><xs:restriction base="xs:byte">
    <xs:minInclusive value="-3"/><xs:maxInclusive value="3"/></xs:restriction></xs:simpleType>
  <xs:simpleType name="modeType"><xs:restriction base="xs:string">
    <xs:enumeration value="slow"/><xs:enumeration value="fast"/><xs:enumeration value="off"/>
  </xs:restriction></xs:simpleType>
"""
ROOT_MSG = "010"       # global elements by local name: Alpha 0, Head 1, Msg 2, Zeta 3, SE(*) 4 -> 3 bits


def kitchen_stream() -> bytes:
    return pack(
        HEADER, ROOT_MSG,
        "00", text("m1"),                    # MsgType state 0: AT(Id)=0, AT(seq)=1 (by name) -> 2 bits
        "0", uint(300),                      # then AT(seq) alone; unsignedShort is an Unsigned Integer
        "0", "0", octets(b"\xca\xfe"), "0",  # SE(Id); CH; hexBinary; EE
        "000", "0", text("hi"), "0",         # SE(Note)=0 of Note, Alpha, Head, Zeta -> 3 bits; CH; "hi"; EE
        "00",                                # SE(Alpha)=0 of Alpha, Head, Zeta -> 2 bits
        "0", "0", "001", "0",                # AlphaType: SE(Level); CH; -2 as 3 bits over -3..3; EE
        "0", "0", "1", uint(4), "0",         # SE(Delta); CH; xs:short -5 = sign 1, magnitude 4; EE
        "0",                                 # EE of Alpha
        "00",                                # SE(Item)=0, EE=1 -> 2 bits
        "00", "01",                          # ItemType state 0: AT(unit)=0, CH=1; enum fast = 1 of 3 -> 2 bits
        "0", uint(1), "1", "0",              # CH; "hi" is in the global table at index 1 of 2 -> hit, 1 bit; EE
        "00",                                # second Item
        "01", uint(1), "1", "0",             # CH=1 (no attribute); global hit again (a global hit adds nothing); EE
        "0")                                 # after two Items: EE
