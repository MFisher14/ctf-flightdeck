"""Independent, hand-authored vendor/schema fixtures (not engine-generated).

Shapes: Beckhoff/ADS PLC-TestProject/Untitled1/POUs/MAIN.TcPOU;
PLCopen TC6 XML v2.01 variable/initialValue/body schema;
Schneider XEF FEFExchangeFile/identProgram/STSource and dataBlock;
actual CODESYS export TextLines example published by its owner at
https://www.sps-forum.de/threads/codesys-daten-im-export-alt-txt.89638/
Expected strings, scopes, values and references are handwritten below.
"""
import json
import random

import pytest

import ics_vendor_exports as engine


TWINCAT = b'''<?xml version="1.0" encoding="utf-8"?>
<TcPlcObject Version="1.1.0.1"><POU Name="MAIN" Id="{123}">
<Declaration><![CDATA[PROGRAM MAIN
VAR
 password : STRING := 'motor-key';
END_VAR]]></Declaration>
<Implementation><ST><![CDATA[IF enable THEN speed := 1500; END_IF;]]></ST></Implementation>
<Method Name="Stop"><Declaration>METHOD Stop</Declaration>
<Implementation><ST><![CDATA[speed := 0; // CSCTF{method_flag}]]></ST></Implementation></Method>
</POU><!-- CSCTF{comment_flag} --></TcPlcObject>'''

PLCOPEN = b'''<project xmlns="http://www.plcopen.org/xml/tc6_0201"
 xmlns:xhtml="http://www.w3.org/1999/xhtml">
<fileHeader companyName="Substation" productName="CODESYS"/>
<contentHeader name="Feeder"/>
<types><dataTypes/><pous><pou name="MAIN" pouType="program">
<interface><localVars><variable name="Key" address="%MW10">
<type><string length="80"/></type><initialValue><simpleValue value="CSCTF{tag_init}"/></initialValue>
<documentation><xhtml:p>Trip key &amp; reset</xhtml:p></documentation>
</variable><variable name="Table"><type><array><dimension lower="0" upper="1"/><baseType><INT/></baseType></array></type>
<initialValue><arrayValue><value><simpleValue value="12"/></value><value><simpleValue value="34"/></value></arrayValue></initialValue>
</variable></localVars></interface><body><ST><xhtml:p>output := Key;</xhtml:p></ST></body>
</pou><pou name="Backup" pouType="program"><interface><localVars><variable name="Key"><type><derived name="SecretType"/></type><initialValue><simpleValue value="fallback"/></initialValue></variable></localVars></interface><body><LD><contact localId="0"><variable>enable</variable></contact></LD></body></pou>
</pous></types><instances><configurations><configuration name="PLC"><globalVars><variable name="counter"><type><DINT/></type></variable></globalVars></configuration></configurations></instances>
</project>'''

SCHNEIDER = b'''<FEFExchangeFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="FEFExchangeFile.xsd">
<fileHeader company="Schneider Automation" product="Unity Pro"/>
<contentHeader name="PumpStation"/>
<dataBlock><variables name="TripKey" typeName="STRING" topologicalAddress="%MW100">
<comment>CSCTF{xef_comment}</comment><initialValue value="hardcoded-key"/>
</variables></dataBlock>
<program><identProgram name="PumpControl" type="section" task="MAST"/>
<STSource><![CDATA[IF Trip THEN Pump := FALSE; END_IF;]]></STSource></program>
</FEFExchangeFile>'''

CODESYS = b'''<ExportFile><StructuredView Guid="view"><Single>
<Single Name="Interface"><Single Name="TextDocument"><Array Name="TextLines">
<Single><Single Name="Id">40</Single><Single Name="Text" Type="string">PROGRAM Main</Single></Single>
<Single><Single Name="Id">2</Single><Single Name="Text" Type="string">VAR</Single></Single>
<Single><Single Name="Id">9</Single><Single Name="Text" Type="string">END_VAR</Single></Single>
</Array></Single></Single>
<Single Name="Implementation"><Single Name="TextDocument"><Array Name="TextLines">
<Single><Single Name="Text" Type="string">// CSCTF{codesys_xml}</Single></Single>
<Single><Single Name="Text" Type="string">Pump := TRUE;</Single></Single>
</Array></Single></Single>
</Single></StructuredView></ExportFile>'''


def test_twincat_methods_scope_and_literal_evidence():
    result = engine.parse_export(TWINCAT)
    assert result['format'] == 'twincat-xml'
    assert [(e['scope'], e['text']) for e in result['logic']] == [
        ('POU:MAIN', 'IF enable THEN speed := 1500; END_IF;'),
        ('POU:MAIN/Method:Stop', 'speed := 0; // CSCTF{method_flag}')]
    assert result['declarations'][0]['text'].startswith('PROGRAM MAIN\nVAR')
    assert {e['value'] for e in result['findings'] if e['kind'] == 'flag'} == {'CSCTF{method_flag}', 'CSCTF{comment_flag}'}
    assert any(e['kind'] == 'literal-secret' and e['value'] == 'motor-key' for e in result['findings'])
    assert result['comments'][0]['text'] == ' CSCTF{comment_flag} '


def test_twincat_project_refs_are_not_followed(tmp_path):
    raw = b'''<Project xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>
<Compile Include="POUs\\MAIN.TcPOU"/><ProjectReference Include="../../outside.plcproj"/>
</ItemGroup></Project>'''
    source = tmp_path / 'plant.plcproj'
    source.write_bytes(raw)
    result = engine.analyze_file(source)
    assert [e['target'] for e in result['references']] == ['POUs\\MAIN.TcPOU', '../../outside.plcproj']
    assert result['logic'] == []


def test_twincat_tsproj_real_project_file_attribute():
    result = engine.parse_export(b'<TcSmProject><Project><Plc><Project Name="Line" PrjFilePath="Line\\Line.plcproj"/></Plc></Project></TcSmProject>')
    assert result['references'][0]['target'] == 'Line\\Line.plcproj'


def test_plcopen_scoped_interface_tags_and_initializers():
    result = engine.parse_export(PLCOPEN)
    assert result['metadata']['contentHeader']['name'] == 'Feeder'
    variables = result['variables']
    assert [(v['name'], v['scope']) for v in variables] == [('Key', 'pou:MAIN'), ('Table', 'pou:MAIN'), ('Key', 'pou:Backup'), ('counter', 'configuration:PLC')]
    assert variables[0]['address'] == '%MW10'
    assert variables[0]['type'] == 'string'
    assert variables[0]['initial_value']['children'][0]['attributes']['value'] == 'CSCTF{tag_init}'
    assert variables[1]['type_tree']['children'][0]['children'][0]['attributes'] == {'lower': '0', 'upper': '1'}
    assert variables[1]['initial_value']['children'][0]['children'][1]['children'][0]['attributes']['value'] == '34'
    assert variables[2]['type'] == 'SecretType'
    assert result['comments'][0]['text'] == 'Trip key & reset'
    assert result['logic'][0]['text'] == 'output := Key;'
    assert result['logic'][1]['tree']['children'][0]['attributes']['localId'] == '0'


def test_plcopen_metadata_only_is_useful_without_logic():
    result = engine.parse_export(b'<project xmlns="http://www.plcopen.org/xml/tc6_0200"><fileHeader companyName="Example"/><types/></project>')
    assert result['format'] == 'plcopen-xml'
    assert result['logic'] == []


def test_schneider_xef_source_and_data_block():
    result = engine.parse_export(SCHNEIDER)
    assert result['format'] == 'schneider-xef'
    assert result['variables'][0]['name'] == 'TripKey'
    assert result['variables'][0]['address'] == '%MW100'
    assert result['variables'][0]['tree']['children'][1]['attributes']['value'] == 'hardcoded-key'
    assert result['logic'][0]['scope'] == 'program:PumpControl'
    assert result['logic'][0]['language'] == 'ST'
    assert result['logic'][0]['text'] == 'IF Trip THEN Pump := FALSE; END_IF;'
    assert any(e['value'] == 'CSCTF{xef_comment}' for e in result['findings'])


def test_codesys_text_lines_in_document_order_not_id_order():
    result = engine.parse_export(CODESYS)
    assert result['format'] == 'codesys-export-xml'
    assert result['declarations'][0]['text'] == 'PROGRAM Main\nVAR\nEND_VAR'
    assert result['logic'][0]['text'] == '// CSCTF{codesys_xml}\nPump := TRUE;'
    assert 'not deserialized' in result['limitations'][1]


@pytest.mark.parametrize('codec', ['utf-8', 'utf-16', 'utf-16-be', 'utf-16-le'])
def test_dtd_entities_rejected_in_all_encodings(codec):
    declared = 'utf-8' if codec == 'utf-8' else 'utf-16'
    xml = f'''<?xml version="1.0" encoding="{declared}"?><!DOCTYPE TcPlcObject [<!ENTITY leak SYSTEM "file:///etc/passwd">]><TcPlcObject>&leak;</TcPlcObject>'''
    with pytest.raises(engine.ExportError, match='DTD'):
        engine.parse_export(xml.encode(codec))


def test_valid_utf16_and_numeric_entities():
    xml = '<?xml version="1.0" encoding="utf-16"?><TcPlcObject><Description>CSCTF&#123;decoded&#125;</Description></TcPlcObject>'
    result = engine.parse_export(xml.encode('utf-16'))
    assert result['findings'][0]['value'] == 'CSCTF{decoded}'


@pytest.mark.parametrize('value', [b'', b'<', b'<TcPlcObject>', b'<x/>', b'\x00\xff', None, 42, ['x'], {'x': 1}, '<TcPlcObject>\ud800</TcPlcObject>'])
def test_malformed_input_declared_error_only(value):
    with pytest.raises(engine.ExportError):
        engine.parse_export(value)


def test_limits(monkeypatch):
    monkeypatch.setattr(engine, 'MAX_INPUT', 10)
    with pytest.raises(engine.ExportError):
        engine.parse_export(TWINCAT)
    monkeypatch.setattr(engine, 'MAX_INPUT', 10000)
    monkeypatch.setattr(engine, 'MAX_DEPTH', 3)
    with pytest.raises(engine.ExportError):
        engine.parse_export(b'<TcPlcObject><a><b><c/></b></a></TcPlcObject>')
    monkeypatch.setattr(engine, 'MAX_NODES', 2)
    with pytest.raises(engine.ExportError):
        engine.parse_export(b'<TcPlcObject><!--1--><!--2--></TcPlcObject>')
    monkeypatch.setattr(engine, 'MAX_ATTRIBUTES', 1)
    with pytest.raises(engine.ExportError):
        engine.parse_export(b'<TcPlcObject a="1" b="2"/>')


def test_bounded_deterministic_byte_mutations_do_not_leak_exceptions():
    rng = random.Random(2606)
    for _ in range(150):
        raw = bytearray(TWINCAT)
        for _ in range(rng.randrange(1, 5)):
            raw[rng.randrange(len(raw))] = rng.randrange(256)
        try:
            engine.parse_export(bytes(raw))
        except engine.ExportError:
            pass


def test_file_errors_and_guarded_cli(tmp_path, capsys):
    with pytest.raises(engine.ExportError):
        engine.analyze_file(tmp_path / 'missing')
    with pytest.raises(engine.ExportError):
        engine.analyze_file(None)
    assert engine.main([]) == 2
    assert engine.main(['--help']) == 0
    assert engine.main([str(tmp_path / 'missing')]) == 2
    source = tmp_path / 'sample.TcPOU'
    source.write_bytes(TWINCAT)
    capsys.readouterr()
    assert engine.main([str(source)]) == 0
    assert json.loads(capsys.readouterr().out)['format'] == 'twincat-xml'


def test_named_secret_field_and_entity_decoding():
    raw = b'''<FEFExchangeFile><dataBlock><variables name="AdminPassword" typeName="STRING"><initialValue value="a&amp;b"/></variables></dataBlock></FEFExchangeFile>'''
    result = engine.parse_export(raw)
    assert any(f['kind'] == 'secret-field' and f['key'] == 'AdminPassword' and f['value'] == 'a&b' for f in result['findings'])


def test_output_path_and_name_limits(monkeypatch):
    monkeypatch.setattr(engine, 'MAX_EVIDENCE', 20)
    with pytest.raises(engine.ExportError, match='output cap'):
        engine.parse_export(TWINCAT)
    monkeypatch.setattr(engine, 'MAX_EVIDENCE', 100000)
    monkeypatch.setattr(engine, 'MAX_PATH_TOTAL', 20)
    with pytest.raises(engine.ExportError, match='path evidence'):
        engine.parse_export(TWINCAT)
    long_tag = 'a' * 513
    with pytest.raises(engine.ExportError, match='name length'):
        engine.parse_export(f'<TcPlcObject><{long_tag}/></TcPlcObject>')


def test_wrong_filename_type_and_processing_instruction_static():
    with pytest.raises(engine.ExportError):
        engine.parse_export(TWINCAT, name=33)
    result = engine.parse_export(b'<?xml-stylesheet href="file:///not/read"?><TcPlcObject/>')
    assert result['format'] == 'twincat-xml'
    assert result['references'] == []


def test_document_comments_are_evidence_and_not_source():
    raw = b'''<!-- CSCTF{before} --><TcPlcObject><POU Name="MAIN">
<Declaration>PROGRAM <!-- CSCTF{inline} -->MAIN</Declaration>
<Implementation><ST>a<!-- explanation -->b</ST></Implementation>
</POU></TcPlcObject><!-- CSCTF{after} -->'''
    result = engine.parse_export(raw)
    assert result['declarations'][0]['text'] == 'PROGRAM MAIN'
    assert result['logic'][0]['text'] == 'ab'
    assert {f['value'] for f in result['findings'] if f['kind'] == 'flag'} == {'CSCTF{before}', 'CSCTF{inline}', 'CSCTF{after}'}
    assert len(result['comments']) == 4


def test_nested_brace_is_not_a_valid_flag(monkeypatch):
    # The flag body is the event's: Pink's (like the contract default) forbids braces; CSCTF's admits `{`.
    monkeypatch.setenv("CTF_EVENT", "pink")
    result = engine.parse_export(b'<TcPlcObject><Description>PINK{outer{nested}}</Description></TcPlcObject>')
    assert result['findings'] == []
