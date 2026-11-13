"""Independent, hand-authored records from published device-description grammars.

No fixture uses this engine to encode itself. The schemas/layouts are documented
by PI, ODVA, CiA, and IEC 61850. Published excerpt provenance is next to fixtures.
"""
import json
import io

import pytest

import ics_vendor_devices as d


# Structure from Siemens PROFINET Driver GSDML Getting Started (ISO15745Profile)
# and PI GSDML specification. All example content is original for these tests.
GSDML = b'''<?xml version="1.0"?>
<ISO15745Profile xmlns="http://www.profibus.com/GSDML/2003/11/DeviceProfile">
 <ProfileHeader><ProfileTechnology>GSDML</ProfileTechnology></ProfileHeader>
 <ProfileBody><DeviceIdentity VendorID="0x002A" DeviceID="0x0008">
  <VendorName Value="Pump Vendor"/></DeviceIdentity>
  <ApplicationProcess><ModuleList><ModuleItem ID="Pump1" ModuleIdentNumber="0x101">
   <ModuleInfo><Name TextId="T_Name"/></ModuleInfo>
   <VirtualSubmoduleList><VirtualSubmoduleItem ID="IO1">
    <IOData><Input><DataItem DataType="Unsigned16" TextId="T_Pressure"/></Input></IOData>
    <RecordDataList><ParameterRecordDataItem Index="1" Length="4">
     <Ref DataType="Unsigned32" DefaultValue="100" ByteOffset="0"/>
    </ParameterRecordDataItem></RecordDataList>
   </VirtualSubmoduleItem></VirtualSubmoduleList>
  </ModuleItem></ModuleList>
  <ExternalTextList><PrimaryLanguage><Text TextId="T_Name" Value="CSCTF{Gsd_Name}"/>
   <Text TextId="T_Pressure" Value="Discharge pressure"/></PrimaryLanguage>
   <Language xml:lang="de"><Text TextId="T_Name" Value="Pumpe"/></Language>
  </ExternalTextList></ApplicationProcess>
  <!-- credential review: password=lab-only -->
 </ProfileBody>
</ISO15745Profile>'''


# Structure checked against mz-automation/libiec61850 official example:
# tools/model_generator/simpleIO_direct_control_goose.scd.
# Values and all text here are original; the source is an independent encoder.
SCL = '''<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
<Header id="SubstationA" version="1"/>
<Communication><SubNetwork name="StationBus" type="8-MMS">
 <ConnectedAP iedName="RelayA" apName="P1"><Address><P type="IP">192.0.2.4</P></Address>
 <GSE ldInst="LD0" cbName="Trip"><Address><P type="MAC-Address">01-0C-CD-01-00-01</P>
 <P type="APPID">1001</P></Address></GSE></ConnectedAP>
</SubNetwork></Communication>
<IED name="RelayA" manufacturer="Relay Vendor"><AccessPoint name="P1"><Server>
 <LDevice inst="LD0"><LN0 lnClass="LLN0" inst="" lnType="LLN0Type">
  <DataSet name="TripSet"><FCDA ldInst="LD0" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/></DataSet>
  <GSEControl name="Trip" datSet="TripSet" appID="trip" confRev="1"/>
 </LN0><LN lnClass="PTRC" inst="1" lnType="PTRCType">
 <DOI name="NamPlt"><DAI name="d"><Val>CSCTF{Relay_Config}</Val></DAI></DOI>
 </LN></LDevice></Server></AccessPoint></IED></SCL>'''


def test_gsdml_known_fields_and_localized_texts():
    result = d.parse(GSDML)
    assert result["format"] == "gsdml"
    assert result["metadata"] == {"VendorID": "0x002A", "DeviceID": "0x0008"}
    assert result["modules"][0]["attributes"]["ModuleIdentNumber"] == "0x101"
    assert result["modules"][0]["text_refs"] == ["T_Name", "T_Pressure"]
    assert [r["attributes"]["Value"] for r in result["texts"]] == ["CSCTF{Gsd_Name}", "Discharge pressure", "Pumpe"]
    assert result["parameters"][2]["attributes"]["DefaultValue"] == "100"
    assert result["flags"] == ["CSCTF{Gsd_Name}"]
    assert result["comments"][0]["text"].strip() == "credential review: password=lab-only"


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_scl_context_and_values(encoding):
    result = d.parse(SCL.encode(encoding))
    assert result["format"] == "scl"
    assert result["metadata"]["id"] == "SubstationA"
    assert result["addresses"][0]["value"] == "192.0.2.4"
    assert result["addresses"][2]["control"] == "Trip"
    assert result["addresses"][2]["ld"] == "LD0"
    assert result["datasets"][0]["members"] == [{"ldInst": "LD0", "lnClass": "PTRC", "lnInst": "1", "doName": "Tr", "daName": "general", "fc": "ST"}]
    assert result["logical_nodes"][1]["ln"] == "PTRC1"
    assert result["controls"][0]["ied"] == "RelayA"
    assert result["values"][0]["path"].endswith("/DOI[NamPlt]/DAI[d]/Val")
    assert result["flags"] == ["CSCTF{Relay_Config}"]


def test_gsd_repeated_modules_continuation_and_semicolon():
    # Siemens gsd_e.pdf keyword grammar, independent literal fixture.
    result = d.parse('''; engineering note CSCTF{Gsd_Comment}
#Profibus_DP
GSD_Revision=1
Vendor_Name="Example; Vendor"
Ident_Number=0x00A2
Module="Pump" \\
 0x10,0x20
EndModule
Module="Valve" 0x30
EndModule
Unit_Diag_Bit(00)="Overpressure"
''')
    assert result["format"] == "gsd"
    assert result["records"][1]["value"] == '"Example; Vendor"'
    assert [r["value"] for r in result["records"] if r["key"] == "Module"] == ['"Pump" 0x10,0x20', '"Valve" 0x30']
    assert result["flags"] == ["CSCTF{Gsd_Comment}"]


def test_canopen_published_vendor_record():
    # Values copied from CopleyControlsOfficial/CANopen-Message-Log-Examples
    # CANopen.eds: authoritative real manufacturer object dictionary records.
    result = d.parse('''[FileInfo]
FileName=COPLEYAMP.EDS
[DeviceInfo]
VendorNumber=0x000000AB
[1000]
ParameterName=Device Type
ObjectType=7
DataType=7
AccessType=RO
DefaultValue=393618
[1200sub1]
ParameterName=SDO COB-ID Client->Server
ObjectType=7
DataType=7
AccessType=RO
DefaultValue=$NODEID+1536
''')
    assert result["format"] == "canopen-eds"
    assert result["objects"][0]["index"] == 0x1000
    assert result["objects"][0]["fields"]["DefaultValue"] == "393618"
    assert result["objects"][1]["index"] == 0x1200
    assert result["objects"][1]["subindex"] == 1
    assert result["objects"][1]["fields"]["DefaultValue"] == "$NODEID+1536"


def test_dcf_literal_values_and_secret_candidates():
    result = d.parse('''[FileInfo]
FileName=unit.dcf
[DeviceComissioning]
NodeID=7
[2000subA]
ParameterName=password
DataType=9
ParameterValue=CSCTF{Dcf_Secret}
''')
    assert result["format"] == "canopen-dcf"
    assert result["objects"][0]["subindex"] == 10
    assert result["flags"] == ["CSCTF{Dcf_Secret}"]
    assert result["secret_candidates"]


def test_cip_eds_real_syntax_distinct_from_ini():
    # Grammar and IO record from Edwards Vacuum DeviceNet Interface, doc 213645
    # Rev C p15. Synthetic label tests quote/comment/semicolon handling.
    result = d.parse('''$ comment CSCTF{Cip_Comment}
[File]
DescText = "XC-8800/8700";
Revision = 2.8;
[Device]
VendCode = 844; ProdCode = 1;
ProdName = "XC-8800; $literal";
[IO_Info]
Input1 = 84,
0, $ reserved
0x0001,
"InputPoll",
0,
"",
"";
''')
    assert result["format"] == "cip-eds"
    assert result["metadata"]["Device"]["VendCode"] == "844"
    assert result["metadata"]["Device"]["ProdName"] == '"XC-8800; $literal"'
    assert result["records"][-1]["value"].replace("\n", "").replace(" ", "") == '84,0,0x0001,"InputPoll",0,"",""'
    assert result["flags"] == ["CSCTF{Cip_Comment}"]


@pytest.mark.parametrize("value", [None, 2, [], {}, b"", "", b"\x00\x01", "garbage",
                                      "<SCL>", "<Unknown/>", "[DeviceInfo]\nfoo", 
                                      "[FileInfo]\na=1\na=2", "[FileInfo]\na=1\n[FileInfo]\nb=2",
                                      "[File]\na=1;\n[Device]\nb=2", "#Profibus_DP\nx=\"unterminated",
                                      "#Profibus_DP\nx=1\\", "#Profibus_DP\n@@@"]) 
def test_fail_closed(value):
    with pytest.raises(d.ParseError):
        d.parse(value)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_dtd_entities_rejected_all_encodings(encoding):
    for text in ('<!DOCTYPE SCL [<!ENTITY x "hidden">]><SCL>&x;</SCL>',
                 '<!DOCTYPE SCL SYSTEM "file:///tmp/never-read"><SCL/>'):
        with pytest.raises(d.ParseError, match="DTD"):
            d.parse(text.encode(encoding))


def test_limits(monkeypatch):
    monkeypatch.setattr(d, "MAX_INPUT", 64)
    with pytest.raises(d.ParseError):
        d.parse(b"a" * 65)
    monkeypatch.setattr(d, "MAX_INPUT", 10000)
    monkeypatch.setattr(d, "MAX_DEPTH", 3)
    with pytest.raises(d.ParseError):
        d.parse("<SCL><a><b><c/></b></a></SCL>")
    monkeypatch.setattr(d, "MAX_NODES", 2)
    with pytest.raises(d.ParseError):
        d.parse("<SCL><!--a--><!--b--></SCL>")
    monkeypatch.setattr(d, "MAX_RECORDS", 1)
    with pytest.raises(d.ParseError):
        d.parse("#Profibus_DP\na=1\nb=2")


def test_no_schema_fetch_and_unknown_fields_preserved():
    result = d.parse('''<SCL xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:noNamespaceSchemaLocation="https://invalid.test/never-fetch.xsd">
    <VendorExtension password="lab-value">CSCTF{Extension}</VendorExtension></SCL>''')
    assert result["flags"] == ["CSCTF{Extension}"]
    assert result["secret_candidates"][0]["attributes"]["password"] == "lab-value"


def test_kind_mismatch_and_unhashable():
    for kind in ("gsdml", "unsupported", [], {}):
        with pytest.raises(d.ParseError):
            d.parse(SCL, kind=kind)


def test_file_and_cli(tmp_path, capsys):
    path = tmp_path / "station.cid"
    path.write_text(SCL)
    assert d.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["format"] == "scl"
    assert d.main([]) == 2
    assert d.main(["--help"]) == 0
    assert d.main([str(tmp_path / "missing")]) == 2
    with pytest.raises(d.ParseError):
        d.parse_file(None)
    with pytest.raises(d.ParseError):
        d.parse_file(tmp_path)


def test_canopen_library_oracle():
    from canopen.objectdictionary.eds import import_eds

    text = '''[FileInfo]
FileName=oracle.eds
[DeviceInfo]
VendorNumber=0xAB
[1200]
ParameterName=SDO parameters
ObjectType=9
SubNumber=1
[1200sub1]
ParameterName=Client COB ID
ObjectType=7
DataType=7
AccessType=ro
DefaultValue=$NODEID+1536
[2000]
ParameterName=Status message
ObjectType=7
DataType=9
AccessType=ro
DefaultValue=CSCTF{Oracle} ; inline comment
'''
    reference = import_eds(io.StringIO(text), node_id=7)
    parsed = d.parse(text)
    objects = {(r["index"], r["subindex"]): r["fields"] for r in parsed["objects"]}
    assert objects[0x1200, 1]["ParameterName"] == reference[0x1200][1].name
    assert int(objects[0x1200, 1]["DataType"]) == reference[0x1200][1].data_type
    assert objects[0x1200, 1]["DefaultValue"] == "$NODEID+1536"
    assert reference[0x1200][1].default == 1543
    assert objects[0x2000, None]["DefaultValue"] == reference[0x2000].default == "CSCTF{Oracle}"
    assert parsed["flags"] == ["CSCTF{Oracle}"]


def test_xml_outside_root_comments_and_sibling_provenance():
    result = d.parse('<!--CSCTF{Before}--><SCL><IED name="same"/><IED name="same"/></SCL><!--CSCTF{After}-->')
    assert result["flags"] == ["CSCTF{After}", "CSCTF{Before}"]
    assert [r["path"] for r in result["devices"]] == ["/SCL/IED[same][1]", "/SCL/IED[same][2]"]


def test_xml_path_and_output_budgets(monkeypatch):
    with pytest.raises(d.ParseError, match="identifier"):
        d.parse('<SCL><IED name="' + 'x' * (d.MAX_NAME + 1) + '"/></SCL>')
    with pytest.raises(d.ParseError, match="name"):
        d.parse('<SCL><' + 'x' * (d.MAX_NAME + 1) + '/></SCL>')
    monkeypatch.setattr(d, "MAX_PATH", 10)
    with pytest.raises(d.ParseError, match="path"):
        d.parse('<SCL><IED name="abcd"/></SCL>')
    monkeypatch.setattr(d, "MAX_PATH", 10000)
    monkeypatch.setattr(d, "MAX_OUTPUT_CHARS", 30)
    with pytest.raises(d.ParseError, match="output"):
        d.parse('<SCL><IED name="abcd"><Foo/><Bar/></IED></SCL>')
