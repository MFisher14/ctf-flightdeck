"""Independent hand-built L5X fixtures shaped by Rockwell 1756-RM014.

No production encoder is used. Expected source, bytes and scoped values are
literal test data; ElementTree is only an independent serialized-XML check.
"""
import json
import random
import xml.etree.ElementTree as ET

import pytest

import ics_vendor_l5x as engine


def document(body):
    return '<RSLogix5000Content SchemaRevision="1.0"><Controller Name="Plant">' + body + '</Controller></RSLogix5000Content>'


def test_scopes_comments_logic_alias_and_edit_states():
    report = engine.parse_l5x(document('''
      <!-- CSCTF{xml_comment} -->
      <Tags><Tag Name="Run" TagType="Alias" AliasFor="Local:1:I.Data.0">
        <Description><![CDATA[Door & motor interlock]]></Description>
      </Tag></Tags>
      <Programs><Program Name="Conveyor"><Tags><Tag Name="Run" DataType="BOOL">
        <Data Format="Decorated"><DataValue DataType="BOOL" Value="1"/></Data>
      </Tag></Tags><Routines>
        <Routine Name="Main" Type="RLL"><RLLContent><Rung Number="0" Type="N">
          <Comment><![CDATA[CSCTF{rung_comment}]]></Comment>
          <Text><![CDATA[XIC(Run)OTE(Motor);]]></Text>
        </Rung></RLLContent></Routine>
        <Routine Name="Control" Type="ST">
          <STContent OnlineEditType="Original"><Line Number="0"><![CDATA[Speed := 30;]]></Line></STContent>
          <STContent OnlineEditType="PendingEdits"><Line Number="0"><![CDATA[Speed := 40;]]></Line></STContent>
        </Routine>
      </Routines></Program></Programs>
      <AddOnInstructionDefinitions><AddOnInstructionDefinition Name="ValveAOI">
        <LocalTags><LocalTag Name="Run" DataType="BOOL"/></LocalTags>
      </AddOnInstructionDefinition></AddOnInstructionDefinitions>
    '''))
    assert [t['scope'] for t in report['tags']] == ['Controller:Plant', 'Controller:Plant/Program:Conveyor', 'Controller:Plant/AddOnInstructionDefinition:ValveAOI']
    assert report['tags'][0]['attributes']['AliasFor'] == 'Local:1:I.Data.0'
    assert [i['text'] for i in report['logic']] == ['XIC(Run)OTE(Motor);', 'Speed := 30;', 'Speed := 40;']
    assert report['logic'][2]['attributes']['OnlineEditType'] == 'PendingEdits'
    assert report['flags'] == ['CSCTF{rung_comment}', 'CSCTF{xml_comment}']
    assert any(c['text'] == 'Door & motor interlock' for c in report['comments'])


@pytest.mark.parametrize(('encoded', 'expected'), [
    ("'CSCTF$7Bbytes$7D'", 'CSCTF{bytes}'),
    ("'a$$b$'c$\"d'", 'a$b\'c"d'),
    ("'$00$FF$L$N$P$R$T'", '\x00\xff\n\r\n\f\r\t'),
    ("'$41F'", 'AF'),
    ("''", ''),
])
def test_documented_literal_escapes(encoded, expected):
    assert engine.decode_logix_string(encoded) == expected


def test_string_length_and_all_representations_preserved():
    report = engine.parse_l5x(document('''<Tags><Tag Name="OperatorPassword" DataType="STRING">
       <Data>03 00 00 00 61 62 63 00</Data>
       <Data Format="L5K"><![CDATA[[3,'def$00']]]></Data>
       <Data Format="String" Length="3"><![CDATA['ghi$00$00']]></Data>
       <Data Format="Decorated"><Structure DataType="STRING">
         <DataValueMember Name="LEN" DataType="DINT" Value="3"/>
         <DataValueMember Name="DATA" DataType="STRING"><![CDATA['jkl$00']]></DataValueMember>
       </Structure></Data>
       <ForceData>DE AD BE EF</ForceData>
    </Tag></Tags>'''))
    tag = report['tags'][0]
    assert [v['value'] for v in tag['decoded_strings']] == ['abc', 'def', 'ghi', 'jkl']
    assert len(tag['data']) == 5
    assert '/Data[1]/Raw' in tag['decoded_strings'][0]['path']
    assert ET.fromstring(tag['data'][3]['xml']).attrib['Format'] == 'Decorated'
    assert any(c['field'] == 'named-tag' for c in report['secret_candidates'])


def test_decorated_array_indexes_and_signed_sint():
    report = engine.parse_l5x(document('''<Tag Name="Data" DataType="STRING">
      <Data Format="Decorated"><Structure DataType="STRING">
       <DataValueMember Name="LEN" Value="3"/>
       <ArrayMember Name="DATA" DataType="SINT" Dimensions="4">
        <Element Index="[2]" Value="-1"/><Element Index="[0]" Value="16#41"/>
        <Element Index="[3]" Value="0"/><Element Index="[1]" Value="2#01000010"/>
       </ArrayMember>
      </Structure></Data></Tag>'''))
    assert report['tags'][0]['decoded_strings'][0]['value'] == 'AB\xff'


def test_flag_from_encoded_string_only():
    report = engine.parse_l5x(document('''<Tag Name="Message" DataType="STRING">
    <Data Format="String" Length="14"><![CDATA['CSCTF$7Bencoded$7D$00']]></Data></Tag>'''))
    assert report['flags'] == ['CSCTF{encoded}']


def test_namespaces_utf16_protection_and_fbd():
    xml = '''<?xml version="1.0" encoding="UTF-16"?>
    <RSLogix5000Content xmlns="urn:test"><Controller Name="Plant">
    <Routine Name="Locked"><EncryptedContent>opaque</EncryptedContent></Routine>
    <Routine Name="Loop"><FBDContent><Sheet Number="1"><IRef Operand="Temperature"/></Sheet></FBDContent></Routine>
    </Controller></RSLogix5000Content>'''
    report = engine.parse_l5x(xml.encode('utf-16'))
    assert report['protected'][0]['kind'] == 'EncryptedContent'
    assert report['logic'][0]['language'] == 'FBD'
    assert 'Temperature' in report['logic'][0]['xml']


def test_comments_outside_document_root():
    xml = '<!--CSCTF{before}--><RSLogix5000Content/><!--CSCTF{after}-->'
    report = engine.parse_l5x(xml.encode('utf-16'))
    assert report['flags'] == ['CSCTF{after}', 'CSCTF{before}']
    assert len(report['comments']) == 2


@pytest.mark.parametrize('value', [None, 42, {}, [], b'', '<wrong/>', '<RSLogix5000Content>', '\ud800'])
def test_invalid_inputs_use_declared_exception(value):
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(value)


@pytest.mark.parametrize('encoding', ['utf-8', 'utf-16', 'utf-16-be', 'utf-16-le'])
def test_dtd_and_entities_rejected_in_all_encodings(encoding):
    xml = '''<!DOCTYPE RSLogix5000Content [<!ENTITY secret SYSTEM "file:///no-such-file">]>
    <RSLogix5000Content>&secret;</RSLogix5000Content>'''
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(xml.encode(encoding))


@pytest.mark.parametrize('literal', ["'abc$'", "'abc$Z'", "'abc'xyz'", "notquoted", "'\u2603'"])
def test_invalid_literals(literal):
    with pytest.raises(engine.ParseError):
        engine.decode_logix_string(literal)


@pytest.mark.parametrize('data', [
    '<Data Format="String" Length="-1">\'abc\'</Data>',
    '<Data Format="String" Length="4">\'abc\'</Data>',
    '<Data Format="String" Length="NaN">\'abc\'</Data>',
    '<Data>01 00</Data>',
    '<Data>GG</Data>',
    '<Data Format="L5K">[2]</Data>',
    '''<Data Format="Decorated"><Structure DataType="STRING"><DataValueMember Name="LEN" Value="1"/>
    <ArrayMember Name="DATA"><Element Index="[1]" Value="65"/></ArrayMember></Structure></Data>''',
    '''<Data Format="Decorated"><Structure DataType="STRING"><DataValueMember Name="LEN" Value="1"/>
    <ArrayMember Name="DATA"><Element Index="[0]" Value="65"/><Element Index="[0]" Value="66"/></ArrayMember></Structure></Data>''',
])
def test_malformed_string_data(data):
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(document('<Tag Name="X" DataType="STRING">' + data + '</Tag>'))


def test_resource_limits(monkeypatch):
    with pytest.raises(engine.ParseError):
        engine.parse_l5x('<RSLogix5000Content>' + '<x>' * 70 + '</x>' * 70 + '</RSLogix5000Content>')
    monkeypatch.setattr(engine, 'MAX_NODES', 3)
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(document('<x/><x/>'))
    monkeypatch.setattr(engine, 'MAX_INPUT', 10)
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(document(''))


def test_len_data_named_non_string_udt_is_not_decoded():
    report = engine.parse_l5x(document('''<Tag Name="Packet" DataType="Packet">
    <Data Format="Decorated"><Structure DataType="Packet"><DataValueMember Name="LEN" DataType="DINT" Value="3"/>
    <DataValueMember Name="DATA" DataType="DINT" Value="42"/></Structure></Data></Tag>'''))
    assert report['tags'][0]['decoded_strings'] == []
    assert '42' in report['tags'][0]['data'][0]['xml']


def test_string_array_l5k_preserved_decorated_members_decoded():
    report = engine.parse_l5x(document('''<Tag Name="Words" DataType="STRING" Dimensions="2">
    <Data Format="L5K"><![CDATA[[[1,'A'],[1,'B']]]]></Data>
    <Data Format="Decorated"><Array DataType="STRING" Dimensions="2">
    <Element Index="[0]"><Structure DataType="STRING"><DataValueMember Name="LEN" Value="1"/>
    <DataValueMember Name="DATA" DataType="STRING">'A'</DataValueMember></Structure></Element>
    <Element Index="[1]"><Structure DataType="STRING"><DataValueMember Name="LEN" Value="1"/>
    <DataValueMember Name="DATA" DataType="STRING">'B'</DataValueMember></Structure></Element>
    </Array></Data></Tag>'''))
    assert [v['value'] for v in report['tags'][0]['decoded_strings']] == ['A', 'B']
    assert "[[1,'A'],[1,'B']]" in report['tags'][0]['data'][0]['xml']


def test_output_and_name_limits(monkeypatch):
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(document('<' + 'x' * 600 + '/>'))
    monkeypatch.setattr(engine, 'MAX_EVIDENCE', 32)
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(document('<Tag Name="Message"/>'))


def test_zero_length_empty_cdata_real_export_shape():
    xml = document('''<Tag Name="Empty" DataType="STRING"><Data Format="Decorated">
    <Structure DataType="STRING"><DataValueMember Name="LEN" DataType="DINT" Value="0"/>
    <DataValueMember Name="DATA" DataType="STRING" Radix="ASCII"><![CDATA[]]></DataValueMember>
    </Structure></Data></Tag>''')
    assert engine.parse_l5x(xml)['tags'][0]['decoded_strings'][0]['value'] == ''
    with pytest.raises(engine.ParseError):
        engine.parse_l5x(xml.replace('Value="0"', 'Value="1"'))


def test_random_malformed_bytes_declared_error_only():
    rng = random.Random(2026)
    for _ in range(80):
        blob = rng.randbytes(rng.randrange(100))
        with pytest.raises(engine.ParseError):
            engine.parse_l5x(blob)


def test_cli_and_file_contract(tmp_path, capsys):
    file = tmp_path / 'safe.l5x'
    file.write_text(document('<Tag Name="Run"/>'))
    assert engine.main([str(file)]) == 0
    assert json.loads(capsys.readouterr().out)['tags'][0]['name'] == 'Run'
    assert engine.main(['--help']) == 0
    assert engine.main([]) == 2
    assert engine.main([str(tmp_path / 'missing.l5x')]) == 2
    with pytest.raises(engine.ParseError):
        engine.analyze_file(tmp_path)
