"""Independent IEC 61850 SCL integrity and capture-correlation fixtures.

The SCL documents and BER bytes here are written by hand from IEC 61850-6,
IEC 61850-8-1 GOOSE and IEC 61850-9-2 SV field layouts. No engine encoder or
output establishes an expected value. XML-equivalence tests preserve named
declarations while the dataset-order tests deliberately alter wire semantics.
"""
from __future__ import annotations

import argparse
import json
import random
import struct
import xml.etree.ElementTree as ET

import pytest

import ot_scl_integrity as scl


SCL = '''<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" version="2007" revision="B">
  <Header id="fixture"/>
  <Communication><SubNetwork name="station" type="8-MMS">
    <ConnectedAP iedName="I1" apName="AP1">
      <GSE ldInst="LD0" cbName="g1"><Address>
        <P type="MAC-Address">01-0C-CD-01-00-01</P>
        <P type="APPID">1001</P><P type="VLAN-ID">001</P>
        <P type="VLAN-PRIORITY">4</P>
      </Address></GSE>
      <SMV ldInst="LD0" cbName="sv1"><Address>
        <P type="MAC-Address">01-0C-CD-04-00-01</P>
        <P type="APPID">4001</P><P type="VLAN-ID">001</P>
        <P type="VLAN-PRIORITY">4</P>
      </Address></SMV>
    </ConnectedAP>
  </SubNetwork></Communication>
  <IED name="I1"><AccessPoint name="AP1"><Server><LDevice inst="LD0">
    <LN0 lnClass="LLN0" inst="" lnType="LT0">
      <DataSet name="ds">
        <FCDA ldInst="LD0" prefix="" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
      </DataSet>
      <GSEControl name="g1" type="GOOSE" datSet="ds" confRev="1" appID="go1"/>
      <SampledValueControl name="sv1" datSet="ds" confRev="1" smvID="sv1" smpMod="SmpPerPeriod" smpRate="80" nofASDU="1" multicast="true"/>
    </LN0>
    <LN prefix="" lnClass="GGIO" inst="1" lnType="LTG"/>
  </LDevice></Server></AccessPoint></IED>
  <DataTypeTemplates>
    <LNodeType id="LT0" lnClass="LLN0"/>
    <LNodeType id="LTG" lnClass="GGIO"><DO name="Ind1" type="DOT"/></LNodeType>
    <DOType id="DOT" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST"/>
      <DA name="q" bType="Quality" fc="ST"/>
    </DOType>
  </DataTypeTemplates>
</SCL>
'''


def _codes(report):
    return {finding['code'] for finding in report['findings']}


def _tlv(tag, body):
    """Tiny independent BER writer: a tag and definite length only."""
    if len(body) < 128:
        length = bytes([len(body)])
    else:
        raw = len(body).to_bytes((len(body).bit_length() + 7) // 8, 'big')
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def _ethernet(body, tag, appid, *, destination, ethertype, vlan=1):
    pdu = _tlv(tag, body)
    payload = struct.pack('>4H', appid, len(pdu) + 8, 0, 0) + pdu
    macs = bytes.fromhex(destination.replace(':', '')) + bytes.fromhex('001122334455')
    if vlan is None:
        return macs + struct.pack('>H', ethertype) + payload
    return macs + struct.pack('>3H', 0x8100, (4 << 13) | vlan, ethertype) + payload


def goose_frame(*, dataset='I1LD0/LLN0$ds', confrev=1, appid=0x1001,
                destination='01:0c:cd:01:00:01', reference='I1LD0/LLN0$GO$g1',
                values=None, vlan=1):
    if values is None:
        values = [_tlv(0x83, b'\xff')]
    body = b''.join([
        _tlv(0x80, reference.encode('ascii')),  # gocbRef
        _tlv(0x81, b'\x03\xe8'),              # timeAllowedtoLive = 1000
        _tlv(0x82, dataset.encode('ascii')),
        _tlv(0x83, b'go1'),
        _tlv(0x84, bytes.fromhex('0000000100000000')),
        _tlv(0x85, b'\x01'), _tlv(0x86, b'\x00'),
        _tlv(0x87, b'\x00'), _tlv(0x88, bytes([confrev])),
        _tlv(0x89, b'\x00'), _tlv(0x8a, bytes([len(values)])),
        _tlv(0xab, b''.join(values)),
    ])
    return _ethernet(body, 0x61, appid, destination=destination, ethertype=0x88b8, vlan=vlan)


def sv_frame(*, dataset='I1LD0/LLN0$ds', confrev=1, sv_id='sv1',
             sample_rate=80, sample_mode=0, count=1):
    fields = [
        _tlv(0x80, sv_id.encode('ascii')),
        _tlv(0x81, dataset.encode('ascii')),
        _tlv(0x82, b'\x00\x07'),
        _tlv(0x83, struct.pack('>I', confrev)),
        _tlv(0x85, b'\x02'),
    ]
    if sample_rate is not None:
        fields.append(_tlv(0x86, struct.pack('>H', sample_rate)))
    fields.append(_tlv(0x87, b'\xff'))
    if sample_mode is not None:
        fields.append(_tlv(0x88, bytes([sample_mode])))
    asdu = b''.join(fields)
    return _ethernet(_tlv(0x80, bytes([count])) + _tlv(0xa2, _tlv(0x30, asdu) * count),
                     0x60, 0x4001, destination='01:0c:cd:04:00:01', ethertype=0x88ba)


def _reordered_xml():
    # ElementTree independently changes namespace prefixes and attribute order;
    # reversing named declaration collections does not alter their meanings.
    root = ET.fromstring(SCL)
    for element in root.iter():
        element.attrib = dict(reversed(list(element.attrib.items())))
        if element.tag.rsplit('}', 1)[-1] in ('DataTypeTemplates', 'LDevice', 'LN0', 'Address'):
            element[:] = reversed(list(element))
    return ET.tostring(root)


def pcap(frames):
    """Classic little-endian pcap; timestamps are known literal fixture values."""
    result = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for index, frame in enumerate(frames):
        result += struct.pack('<IIII', index + 1, 500000, len(frame), len(frame)) + frame
    return result


def pcapng(frames):
    """Independent SHB/IDB/EPB encoder using the published pcapng block layout."""
    def block(kind, body):
        body += b'\0' * (-len(body) % 4)
        size = len(body) + 12
        return struct.pack('<II', kind, size) + body + struct.pack('<I', size)
    result = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    result += block(1, struct.pack('<HHI', 1, 0, 65535))
    for index, frame in enumerate(frames):
        body = struct.pack('<IIIII', 0, 0, (index + 1) * 1000000 + 500000, len(frame), len(frame))
        result += block(6, body + frame)
    return result


def test_scl_semantic_equivalence_and_expected_model():
    report = scl.analyze_scl(SCL)
    assert report['findings'] == []
    model = report['canonical']
    assert set(('logical_nodes', 'datasets', 'controls', 'endpoints', 'templates')) <= model.keys()
    assert len(model['logical_nodes']) == 2
    assert len(model['datasets']) == 1
    assert len(model['controls']) == 2
    assert len(model['endpoints']) == 2
    assert len(model['templates']) == 3
    assert scl.canonicalize_scl(SCL) == model
    assert scl.canonicalize_scl(_reordered_xml()) == model
    equivalent = scl.diff_scl(SCL, _reordered_xml())
    assert equivalent['equal'] is True
    assert equivalent['changes'] == []
    assert equivalent['before_sha256'] == equivalent['after_sha256'] == report['sha256']


def test_type_member_order_and_buffered_control_reference():
    root = ET.fromstring(SCL)
    type_node = root.find('.//{*}DOType')
    type_node[:] = reversed(list(type_node))
    difference = scl.diff_scl(SCL, ET.tostring(root))
    assert difference['equal'] is False
    assert [change['section'] for change in difference['changes']] == ['templates']
    report_source = SCL.replace('</LN0>', '<ReportControl name="br1" datSet="ds" buffered="true" confRev="1"/></LN0>')
    controls = scl.canonicalize_scl(report_source)['controls']
    report = next(control for control in controls if control['kind'] == 'ReportControl')
    assert report['reference'] == 'I1LD0/LLN0$BR$br1'


def test_duplicate_addresses_are_reported_across_stream_kinds():
    injected = SCL.replace('4001', '1001').replace('01-0C-CD-04-00-01', '01-0C-CD-01-00-01')
    assert {'duplicate-appid', 'duplicate-mac'} <= _codes(scl.analyze_scl(injected))


def test_declared_ldname_overrides_ied_plus_ld_domain():
    changed = SCL.replace('<LDevice inst="LD0">', '<LDevice inst="LD0" ldName="CUSTOM_DOMAIN">')
    model = scl.canonicalize_scl(changed)
    assert model['datasets'][0]['reference'] == 'CUSTOM_DOMAIN/LLN0$ds'
    report = scl.correlate_frames(changed, [goose_frame(
        dataset='CUSTOM_DOMAIN/LLN0$ds', reference='CUSTOM_DOMAIN/LLN0$GO$g1')])
    assert report['frames'][0]['findings'] == []


@pytest.mark.parametrize('old,new', [
    (' type="GOOSE"', ''),
    ('confRev="1"', 'confRev="01"'),
    (' smpMod="SmpPerPeriod"', ''),
    ('smpRate="80"', 'smpRate="080"'),
    ('nofASDU="1"', 'nofASDU="01"'),
])
def test_control_defaults_and_numeric_spellings_are_semantically_equal(old, new):
    equivalent = SCL.replace(old, new)
    diff = scl.diff_scl(SCL, equivalent)
    assert diff['equal'] is True
    assert diff['changes'] == []
    assert diff['before_sha256'] == diff['after_sha256']


def test_fcd_and_nested_structure_reference_resolution():
    assert scl.analyze_scl(SCL.replace(' daName="stVal"', ''))['findings'] == []
    structured = SCL.replace('daName="stVal"', 'daName="detail.state"')
    structured = structured.replace('<DA name="stVal" bType="BOOLEAN" fc="ST"/>',
        '<DA name="detail" bType="Struct" type="DAT" fc="ST"/>')
    structured = structured.replace('</DataTypeTemplates>',
        '<DAType id="DAT"><BDA name="state" bType="BOOLEAN"/></DAType></DataTypeTemplates>')
    assert scl.analyze_scl(structured)['findings'] == []
    assert 'unresolved-data-attribute' in _codes(scl.analyze_scl(
        structured.replace('detail.state', 'detail.missing')))


def test_compound_data_object_fcd_resolves_descendant_functional_constraint():
    compound = SCL.replace('doName="Ind1" daName="stVal" fc="ST"', 'doName="PhV" fc="MX"')
    compound = compound.replace('<DO name="Ind1" type="DOT"/>', '<DO name="PhV" type="WYE"/>')
    compound = compound.replace('</DataTypeTemplates>', '''
      <DOType id="WYE" cdc="WYE"><SDO name="phsA" type="CMV"/></DOType>
      <DOType id="CMV" cdc="CMV"><DA name="mag" bType="FLOAT32" fc="MX"/></DOType>
      </DataTypeTemplates>''')
    assert scl.analyze_scl(compound)['findings'] == []


def test_external_reference_source_control_and_empty_connected_ap_are_validated():
    extref = '''<Inputs><ExtRef iedName="I1" ldInst="LD0" prefix="" lnClass="GGIO"
      lnInst="1" doName="Ind1" daName="stVal" serviceType="GOOSE" srcLDInst="LD0"
      srcLNClass="LLN0" srcCBName="g1" intAddr="trip"/></Inputs>'''
    referenced = SCL.replace('</LN0>', extref + '</LN0>')
    assert scl.analyze_scl(referenced)['findings'] == []
    assert 'unresolved-control' in _codes(scl.analyze_scl(
        referenced.replace('srcCBName="g1"', 'srcCBName="missing"')))
    dangling = SCL.replace('</SubNetwork>', '<ConnectedAP iedName="missing" apName="AP1"/></SubNetwork>')
    assert 'unresolved-access-point' in _codes(scl.analyze_scl(dangling))


@pytest.mark.parametrize('old,new,code', [
    ('datSet="ds"', 'datSet="missing"', 'unresolved-dataset'),
    ('lnClass="GGIO" lnInst="1"', 'lnClass="GGIO" lnInst="9"', 'unresolved-logical-node'),
    ('doName="Ind1"', 'doName="Missing"', 'unresolved-data-object'),
    ('daName="stVal"', 'daName="Missing"', 'unresolved-data-attribute'),
    ('lnType="LTG"', 'lnType="Missing"', 'unresolved-type'),
    ('cbName="g1"', 'cbName="Missing"', 'unresolved-control'),
])
def test_cross_reference_validation(old, new, code):
    assert code in _codes(scl.analyze_scl(SCL.replace(old, new)))


def test_duplicate_appid_and_mac_injected_in_second_goose_publisher():
    address = '''<GSE ldInst="LD0" cbName="g2"><Address>
      <P type="MAC-Address">01-0c-cd-01-00-01</P><P type="APPID">1001</P>
      <P type="VLAN-ID">001</P><P type="VLAN-PRIORITY">4</P>
      </Address></GSE>'''
    changed = SCL.replace('</ConnectedAP>', address + '</ConnectedAP>')
    changed = changed.replace('</LN0>', '<GSEControl name="g2" type="GOOSE" datSet="ds" confRev="1" appID="go2"/></LN0>')
    codes = _codes(scl.analyze_scl(changed))
    assert {'duplicate-appid', 'duplicate-mac'} <= codes
    diff = scl.diff_scl(SCL, changed)
    assert diff['equal'] is False
    assert diff['before_sha256'] != diff['after_sha256']
    assert {'controls', 'endpoints'} <= {change['section'] for change in diff['changes']}


def test_tampered_dataset_is_precisely_a_dataset_change():
    changed = SCL.replace('daName="stVal"', 'daName="q"')
    diff = scl.diff_scl(SCL, changed)
    assert diff['equal'] is False
    assert diff['before_findings'] == diff['after_findings'] == []
    assert {change['section'] for change in diff['changes']} == {'datasets'}
    assert len(diff['changes']) == 1


def test_dataset_member_order_is_semantic():
    first = '<FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>'
    second = '<FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="q" fc="ST"/>'
    old_start = SCL.index('      <DataSet')
    old_end = SCL.index('</DataSet>') + len('</DataSet>')
    before = SCL[:old_start] + '<DataSet name="ds">' + first + second + '</DataSet>' + SCL[old_end:]
    after = SCL[:old_start] + '<DataSet name="ds">' + second + first + '</DataSet>' + SCL[old_end:]
    diff = scl.diff_scl(before, after)
    assert diff['equal'] is False
    assert {change['section'] for change in diff['changes']} == {'datasets'}


def test_goose_capture_matches_named_scl_publisher():
    report = scl.correlate_frames(SCL, [goose_frame()])
    assert report['findings'] == []
    assert len(report['frames']) == 1
    frame = report['frames'][0]
    assert frame['index'] == 0
    assert frame['protocol'] == 'iec61850-goose'
    assert frame['findings'] == []
    assert len(frame['matches']) == 1
    assert len(frame['mapped_fields']) == 1
    field = frame['mapped_fields'][0]
    assert field['asdu'] == field['index'] == 0
    assert field['member'] == {'ldInst': 'LD0', 'prefix': '', 'lnClass': 'GGIO',
        'lnInst': '1', 'doName': 'Ind1', 'daName': 'stVal', 'fc': 'ST'}
    assert field['value'] == {'type': 'boolean', 'tag': 0x83, 'raw_length': 1,
                              'raw': 'ff', 'value': True}
    assert json.loads(field['dataset']) == ['I1', 'AP1', 'LD0', 'LLN0', 'ds']


def test_sv_capture_matches_named_scl_publisher():
    report = scl.correlate_frames(SCL, [sv_frame()])
    frame = report['frames'][0]
    assert frame['protocol'] == 'iec61850-sv'
    assert frame['findings'] == []
    assert len(frame['matches']) == 1
    field = frame['mapped_fields'][0]
    assert field['asdu'] == 0
    assert field['data_hex'] == 'ff'
    assert field['encoding'] == 'opaque-seqData'
    assert [member['daName'] for member in field['members']] == ['stVal']


def test_capture_tampering_produces_findings():
    for frame, name, expected, actual in (
        (goose_frame(dataset='I1LD0/LLN0$other'), 'dataset', 'I1LD0/LLN0$ds', 'I1LD0/LLN0$other'),
        (goose_frame(confrev=2), 'conf_revision', 1, 2),
        (goose_frame(values=[_tlv(0x83, b'\x00'), _tlv(0x83, b'\xff')]), 'entry_count', 1, 2),
        (goose_frame(vlan=2), 'vlan_id', 1, 2),
        (goose_frame(appid=0x1002), 'appid', 0x1001, 0x1002),
        (goose_frame(destination='01:0c:cd:01:00:02'), 'destination', '01:0c:cd:01:00:01', '01:0c:cd:01:00:02'),
        (sv_frame(confrev=2), 'conf_revision', 1, 2)):
        report = scl.correlate_frames(SCL, [frame])
        assert {'code': 'capture-field-mismatch', 'asdu': 0, 'field': name,
                'expected': expected, 'actual': actual} in report['frames'][0]['findings']


@pytest.mark.parametrize('options,field,expected,actual', [
    ({'sample_rate': 160}, 'sample_rate', 80, 160),
    ({'sample_mode': 1}, 'sample_mode', 0, 1),
    ({'count': 2}, 'asdu_count', 1, 2),
])
def test_sv_sampling_fields_match_scl_controls(options, field, expected, actual):
    report = scl.correlate_frames(SCL, [sv_frame(**options)])
    findings = report['frames'][0]['findings']
    assert {'code': 'capture-field-mismatch', 'asdu': 0, 'field': field,
            'expected': expected, 'actual': actual} in findings
    if options.get('count') == 2:
        assert {'code': 'capture-field-mismatch', 'asdu': 1, 'field': field,
                'expected': expected, 'actual': actual} in findings


def test_absent_optional_sv_sampling_fields_do_not_invent_mismatches():
    configuration = SCL.replace('smpRate="80"', 'smpRate="160"').replace(
        'smpMod="SmpPerPeriod"', 'smpMod="SmpPerSec"')
    report = scl.correlate_frames(configuration, [sv_frame(sample_rate=None, sample_mode=None)])
    assert report['frames'][0]['findings'] == []


@pytest.mark.parametrize('encoder', [pcap, pcapng])
def test_capture_container_mapping_and_timestamps(encoder):
    report = scl.correlate_capture(SCL, encoder([goose_frame(), sv_frame()]))
    assert report['findings'] == []
    assert report['ignored_packets'] == 0
    assert [frame['protocol'] for frame in report['frames']] == ['iec61850-goose', 'iec61850-sv']
    assert [frame['index'] for frame in report['frames']] == [0, 1]
    assert [frame['timestamp'] for frame in report['frames']] == [1.5, 2.5]
    assert all(frame['findings'] == [] for frame in report['frames'])


def test_capture_ignores_unrelated_ethernet_and_bounds_truncated_records():
    unrelated = bytes.fromhex('ffffffffffff0011223344550806') + b'\0' * 28
    report = scl.correlate_capture(SCL, pcap([unrelated, goose_frame()]))
    assert report['ignored_packets'] == 1
    assert len(report['frames']) == 1
    assert report['frames'][0]['index'] == 1
    for raw in (pcap([goose_frame()]), pcapng([goose_frame()])):
        for length in range(len(raw)):
            try:
                result = scl.correlate_capture(SCL, raw[:length])
                assert result['frames'] == []
            except scl.SclError:
                pass


@pytest.mark.parametrize('data', [b'', b'\xff' * 64, b'<SCL',
    b'<?xml version="1.0"?><SCL><IED>',
    b'<?xml version="1.0" encoding="unknown-test"?><SCL/>',
    '<SCL>\ud800</SCL>', None, {}, 1,
    b'<!DOCTYPE SCL [<!ENTITY x "expanded">]><SCL>&x;</SCL>',
    b'<!DOCTYPE SCL SYSTEM "file:///etc/passwd"><SCL/>'])
def test_malformed_xml_raises_only_declared_error(data):
    for parser in (scl.canonicalize_scl, scl.analyze_scl):
        with pytest.raises(scl.SclError):
            parser(data)


def test_parser_mutation_fuzz_fail_closed():
    rng = random.Random(0x61850)
    raw = SCL.encode()
    mutations = [rng.randbytes(size) for size in (1, 4, 16, 64, 256)]
    mutations.extend(raw[:length] for length in range(0, len(raw), 73))
    for _ in range(40):
        damaged = bytearray(raw)
        offset = rng.randrange(len(damaged))
        damaged[offset] ^= 1 << rng.randrange(8)
        mutations.append(bytes(damaged))
    for data in mutations:
        try:
            assert isinstance(scl.analyze_scl(data), dict)
        except scl.SclError:
            pass


def test_xml_depth_cap_and_diff_error_contract():
    too_deep = '<SCL>' + '<Private>' * 100 + '</Private>' * 100 + '</SCL>'
    with pytest.raises(scl.SclError):
        scl.analyze_scl(too_deep)
    for before, after in ((b'<SCL', SCL), (SCL, b'<SCL')):
        with pytest.raises(scl.SclError):
            scl.diff_scl(before, after)


def test_utf16_input_and_namespace_isolation():
    assert scl.canonicalize_scl(SCL.replace('encoding="UTF-8"', 'encoding="UTF-16"').encode('utf-16')) == scl.canonicalize_scl(SCL)
    for raw in (SCL.replace('http://www.iec.ch/61850/2003/SCL', 'urn:unrelated'),
                SCL.replace('<GSEControl ', '<GSEControl xmlns="urn:unrelated" '),
                SCL.replace('<DataSet name=', '<DataSet xmlns="" name='),
                '<!DOCTYPE SCL [<!ENTITY bad SYSTEM "file:///etc/passwd">]><SCL>&bad;</SCL>'.encode('utf-16')):
        with pytest.raises(scl.SclError):
            scl.analyze_scl(raw)


@pytest.mark.parametrize('frames', [None, 123, b'not a frame list', [None], [b'']])
def test_frame_argument_contract(frames):
    with pytest.raises(scl.SclError):
        scl.correlate_frames(SCL, frames)


def test_frame_mutation_fuzz_fail_closed():
    rng = random.Random(0x88b8)
    for raw in (goose_frame(), sv_frame()):
        mutations = [raw[:length] for length in range(len(raw))]
        mutations += [b'', b'\xff' * 80, rng.randbytes(80)]
        for _ in range(20):
            damaged = bytearray(raw)
            damaged[rng.randrange(len(damaged))] ^= 1 << rng.randrange(8)
            mutations.append(bytes(damaged))
        for data in mutations:
            try:
                assert isinstance(scl.correlate_frames(SCL, [data]), dict)
            except scl.SclError:
                pass


@pytest.mark.parametrize('arguments', [[], ['--not-an-option']])
def test_cli_argument_errors_are_guarded(arguments, capsys):
    assert scl.main(arguments) == 2


def test_cli_help_is_guarded(capsys):
    assert scl.main(['--help']) == 0


def test_cli_noninteger_systemexit_is_guarded(monkeypatch):
    def exit_string(*args, **kwargs):
        raise SystemExit('no integer status')
    monkeypatch.setattr(argparse.ArgumentParser, 'parse_args', exit_string)
    assert scl.main([]) == 2


def test_cli_local_analysis_diff_and_capture(tmp_path, capsys):
    source = tmp_path / 'before.scd'
    source.write_text(SCL)
    other = tmp_path / 'after.scd'
    other.write_text(SCL.replace('daName="stVal"', 'daName="q"'))
    capture = tmp_path / 'traffic.pcap'
    capture.write_bytes(pcap([goose_frame()]))
    frame = tmp_path / 'goose.bin'
    frame.write_bytes(goose_frame())
    assert scl.main(['analyze', str(source)]) == 0
    assert json.loads(capsys.readouterr().out)['findings'] == []
    assert scl.main(['canonical', str(source)]) == 0
    assert len(json.loads(capsys.readouterr().out)['datasets']) == 1
    assert scl.main(['diff', str(source), str(other)]) == 0
    assert json.loads(capsys.readouterr().out)['equal'] is False
    for path, options in ((capture, []), (frame, ['--frame'])):
        assert scl.main(['correlate', str(source), str(path), *options]) == 0
        assert json.loads(capsys.readouterr().out)['frames'][0]['findings'] == []
    assert scl.main(['analyze', str(source) + '.missing']) == 2
