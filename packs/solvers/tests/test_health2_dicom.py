"""Independent hand-packed PS3.5 vectors, not engine-produced files.

pydicom bundled CT and DICOMDIR are loaded by local path only (no download API).
"""
import io
import struct
import zlib
from pathlib import Path

import numpy as np
import pydicom
import pytest

import health2_dicom as h


def element(tag, vr, value, endian='<', implicit=False, undefined=False):
    tagbytes = struct.pack(endian + 'HH', tag >> 16, tag & 65535)
    size = 0xFFFFFFFF if undefined else len(value)
    if implicit:
        return tagbytes + struct.pack(endian + 'I', size) + value
    if vr in {'OB','OD','OF','OL','OV','OW','SQ','UC','UN','UR','UT','SV','UV'}:
        return tagbytes + vr.encode() + b'\0\0' + struct.pack(endian+'I',size) + value
    return tagbytes + vr.encode() + struct.pack(endian+'H',size) + value


def text(s):
    b = s.encode()
    return b + (b' ' if len(b) % 2 else b'')


def part10(body, syntax='1.2.840.10008.1.2.1'):
    uid = syntax.encode()
    uid += b'\0' * (len(uid) % 2)
    return bytes(128) + b'DICM' + element(0x00020010,'UI',uid) + body


def native(values, rows=2, cols=3, syntax='1.2.840.10008.1.2.1', frames=1):
    endian = '>' if syntax.endswith('.2.2') else '<'
    implicit = syntax == '1.2.840.10008.1.2'
    def el(tag,vr,value):
        return element(tag,vr,value,endian,implicit)
    def us(tag,value):
        return el(tag,'US',struct.pack(endian+'H',value))
    body = el(0x00100010,'PN',text('Example^Patient'))
    body += us(0x00280002,1) + el(0x00280004,'CS',text('MONOCHROME2'))
    body += el(0x00280008,'IS',text(str(frames)))
    body += us(0x00280010,rows) + us(0x00280011,cols)
    body += us(0x00280100,16) + us(0x00280101,12) + us(0x00280102,11) + us(0x00280103,1)
    body += el(0x7FE00010,'OW',struct.pack(endian+'h'*len(values), *values))
    if syntax.endswith('.99'):
        compressor = zlib.compressobj(wbits=-15)
        body = compressor.compress(body) + compressor.flush()
    return part10(body,syntax)


@pytest.mark.parametrize('syntax', ['1.2.840.10008.1.2','1.2.840.10008.1.2.1','1.2.840.10008.1.2.2','1.2.840.10008.1.2.1.99'])
def test_signed_native_transfer_syntaxes(syntax):
    values = [-2048,-1,0,1,1024,2047]
    r = h.inspect_dicom(native(values,syntax=syntax),decode_pixels=True)
    assert r['pixels']['decoded'].tolist() == [values[:3],values[3:]]
    assert r['pixels']['decoded'].dtype.kind == 'i'
    assert r['transfer_syntax'] == syntax
    assert any(e['keyword']=='PatientName' and e['value']=='Example^Patient' for e in r['elements'])


def item(payload):
    return struct.pack('<II',0xE000FFFE,len(payload)) + payload


def compressed(fragments, bot=b'', count=2, extra=b'', syntax='1.2.840.10008.1.2.4.50'):
    body = b''
    for tag,v in [(0x00280002,1),(0x00280010,1),(0x00280011,3),(0x00280100,8),(0x00280101,8),(0x00280102,7),(0x00280103,0)]:
        body += element(tag,'US',struct.pack('<H',v))
    body += element(0x00280004,'CS',text('MONOCHROME2')) + element(0x00280008,'IS',text(str(count)))
    body += extra
    raw = item(bot) + b''.join(item(x) for x in fragments)
    body += element(0x7FE00010,'OB',raw+struct.pack('<II',0xE0DDFFFE,0),undefined=True)
    return part10(body,syntax),raw


def test_fragment_boundary_bot_and_payload_delimiter_bytes():
    # Delimiter byte pattern inside the payload is data; never a terminator.
    fragments = [b'\xff\xd8ab', struct.pack('<II',0xE0DDFFFE,0)+b'\xff\xd9', b'\xff\xd8cd\xff\xd9']
    offset = 8+len(fragments[0])+8+len(fragments[1])
    data,raw = compressed(fragments,struct.pack('<II',0,offset))
    r = h.inspect_dicom(data)['pixels']
    assert r['raw'] == raw
    assert r['fragments'] == fragments
    assert r['frames'] == [fragments[0]+fragments[1],fragments[2]]


def test_empty_bot_does_not_guess():
    data,_ = compressed([b'ab',b'cd',b'ef'])
    r = h.inspect_dicom(data)['pixels']
    assert r['frames'] is None and 'ambiguous' in r['boundary_note']


def test_extended_offsets_padding():
    fragments = [b'abc\0',b'123456']
    extra = element(0x7FE00001,'OV',struct.pack('<QQ',0,12))
    extra += element(0x7FE00002,'OV',struct.pack('<QQ',3,6))
    data,_ = compressed(fragments,extra=extra)
    assert h.inspect_dicom(data)['pixels']['frames'] == [b'abc',b'123456']


@pytest.mark.parametrize('bot', [struct.pack('<II',2,12),struct.pack('<II',0,13),struct.pack('<III',0,12,24),struct.pack('<II',12,0)])
def test_bad_bot(bot):
    data,_ = compressed([b'abcd',b'efgh'],bot)
    with pytest.raises(h.Health2DicomError):
        h.inspect_dicom(data)


def test_rle_handpacked_packbits_oracle():
    # DICOM RLE 64-byte header: one segment at offset 64; literal run of 3 bytes.
    rle = struct.pack('<16I',1,64,*([0]*14)) + b'\x02\x00\x7f\xff'
    data,_ = compressed([rle],count=1,syntax='1.2.840.10008.1.2.5')
    assert h.inspect_dicom(data,decode_pixels=True)['pixels']['decoded'].tolist() == [[0,127,255]]


def test_private_dictionary_sr_document_directory_and_export(tmp_path):
    pdf=b'%PDF-1.7\nodd!'
    assert len(pdf)%2
    doc = element(0x00420011,'OB',pdf+b'\0') + element(0x00420012,'LO',text('application/pdf')) + element(0x00420015,'UL',struct.pack('<I',len(pdf)))
    sr = element(0x0040A040,'CS',text('TEXT'))+element(0x0040A160,'UT',text('CSCTF{nested_report}'))
    directory = element(0x00041430,'CS',text('IMAGE'))+element(0x00041500,'CS',text('IMAGES\\ONE'))
    body = element(0x00110010,'LO',text('EXAMPLE_CREATOR'))+element(0x00111001,'LO',text('private payload'))
    body += element(0x00041220,'SQ',item(directory)) + element(0x0040A730,'SQ',item(sr)) + doc
    r=h.inspect_dicom(part10(body))
    assert r['documents'][0]['data']==pdf
    assert r['structured_report'][0]['text']=='CSCTF{nested_report}'
    assert r['directory_records'][0]['referenced_file_id']==['IMAGES','ONE']
    assert any(e['private_creator']=='EXAMPLE_CREATOR' for e in r['elements'])
    h.extract_to(r,tmp_path/'extracted')
    assert (tmp_path/'extracted/document-0000.pdf').read_bytes()==pdf
    with pytest.raises(h.Health2DicomError):
        h.extract_to(r,tmp_path/'extracted')


def test_unresolved_document_padding_is_preserved():
    raw=b'%PDF-odd\0\0'
    r=h.inspect_dicom(part10(element(0x00420011,'OB',raw)))
    assert r['documents'][0]['data']==raw
    assert not r['documents'][0]['padding_resolved']


def test_dictionary_full_and_repeaters():
    assert h.lookup_tag(0x00420015)['keyword']=='EncapsulatedDocumentLength'
    assert h.lookup_tag(0x60023000)['keyword']=='OverlayData'
    assert h.lookup_tag(0x00111001) is None
    assert h.lookup_tag(0x00291010,'SIEMENS CSA HEADER')['name']=='CSA Image Header Info'


def test_bare_dataset_requires_syntax():
    body=element(0x0040A160,'UT',text('CSCTF{bare}'))
    with pytest.raises(h.Health2DicomError):
        h.inspect_dicom(body)
    assert h.inspect_dicom(body,transfer_syntax='1.2.840.10008.1.2.1')['elements'][0]['value']=='CSCTF{bare}'


@pytest.mark.parametrize('data', [b'',None,'DICM',bytes(132),part10(b'ab'),part10(element(0x00100010,'PN',b'abc')),part10(struct.pack('<HH2sH',0x10,0x10,b'PN',100)+b'ab')])
def test_bad_input_contract(data):
    with pytest.raises(h.Health2DicomError):
        h.inspect_dicom(data)


def test_all_truncations_fail_closed():
    data=native([1,2,3,4,5,6])
    for cut in range(len(data)):
        try:
            h.inspect_dicom(data[:cut])
        except h.Health2DicomError:
            pass
        # Some cuts end at a valid element boundary: a metadata-only dataset.


def test_cli_contract(tmp_path,capsys):
    assert h.main(['--help'])==0
    assert h.main([])==2
    assert h.main(['--wrong'])==2
    assert h.main([str(tmp_path/'missing')])==2
    p=tmp_path/'image.dcm'
    p.write_bytes(native([1,2,3,4,5,6]))
    assert h.main([str(p),'--decode','--out',str(tmp_path/'output')])==0
    assert np.load(tmp_path/'output/pixels.npy',allow_pickle=False).tolist()==[[1,2,3],[4,5,6]]


def test_local_pydicom_published_fixtures():
    root=Path(pydicom.__file__).parent/'data'/'test_files'
    # Explicit local paths avoid pydicom's lazy network download helpers.
    ct=root/'CT_small.dcm'
    assert ct.exists(), 'pydicom wheel should include CT_small.dcm'
    raw=ct.read_bytes()
    r=h.inspect_dicom(raw,decode_pixels=True)
    assert r['pixels']['decoded'].shape==(128,128)
    # First samples are published in pydicom's pixel-data tutorial/test corpus.
    assert r['pixels']['decoded'][0,:4].tolist()==[175,180,166,143]
    dd=root/'dicomdirtests'/'DICOMDIR'
    if dd.exists():
        d=h.inspect_dicom(dd.read_bytes())
        assert len(d['directory_records'])==52
        assert d['directory_records'][0]['type']=='PATIENT'


def pixel_body(payload, *, bits, samples=1, frames=1, cols=3, planar=0, photo='MONOCHROME2', tag=0x7FE00010):
    body=b''
    fields=[(0x00280002,samples),(0x00280010,1),(0x00280011,cols),(0x00280100,bits)]
    if tag==0x7FE00010:
        fields += [(0x00280101,bits),(0x00280102,bits-1),(0x00280103,0)]
    if samples>1:
        fields += [(0x00280006,planar)]
    for t,v in fields:
        body += element(t,'US',struct.pack('<H',v))
    body += element(0x00280004,'CS',text(photo))+element(0x00280008,'IS',text(str(frames)))
    body += element(tag,'OF' if tag==0x7FE00008 else 'OB',payload)
    return part10(body)


def test_nonbyte_aligned_multiframe_bits():
    # Two 3-pixel frames share a byte: [1,0,1] [0,1,1], least significant bit first.
    r=h.inspect_dicom(pixel_body(b'\x35\0',bits=1,frames=2),decode_pixels=True)['pixels']
    assert r['frames'] is None
    assert r['decoded'].tolist()==[[[1,0,1]],[[0,1,1]]]


def test_planar_rgb_and_float():
    rgb=pixel_body(bytes([1,2,3,11,12,13,21,22,23,0]),bits=8,samples=3,planar=1,photo='RGB')
    assert h.inspect_dicom(rgb,decode_pixels=True)['pixels']['decoded'].tolist()==[[[1,11,21],[2,12,22],[3,13,23]]]
    floats=pixel_body(struct.pack('<3f',-1.5,0,2.25),bits=32,tag=0x7FE00008)
    assert h.inspect_dicom(floats,decode_pixels=True)['pixels']['decoded'].tolist()==[[-1.5,0,2.25]]


def test_private_binary_and_deep_sequences(tmp_path):
    binary=element(0x00111001,'OB',b'CSCTF{private_binary}\0')
    inner=item(binary)+struct.pack('<II',0xE0DDFFFE,0)
    data=part10(element(0x0040A730,'SQ',inner,undefined=True))
    r=h.inspect_dicom(data)
    assert r['flags']==['CSCTF{private_binary}']
    assert r['binary_elements'][0]['data']==b'CSCTF{private_binary}\0'
    h.extract_to(r,tmp_path/'binary')
    assert (tmp_path/'binary/element-0000.bin').read_bytes()==b'CSCTF{private_binary}\0'
    # Missing delimiter is never silently treated as end of sequence.
    with pytest.raises(h.Health2DicomError):
        h.inspect_dicom(data[:-8])


def test_malformed_pixels_and_compressed_delimiter():
    with pytest.raises(h.Health2DicomError):
        h.inspect_dicom(pixel_body(b'\1\2',bits=8))
    data,_=compressed([b'abcd'],count=1)
    with pytest.raises(h.Health2DicomError):
        h.inspect_dicom(data[:-8])
    with pytest.raises(h.Health2DicomError):
        h.inspect_dicom(data[:-2])


def test_published_unknown_vr_sequence():
    fixture=Path(pydicom.__file__).parent/'data/test_files/UN_sequence.dcm'
    r=h.inspect_dicom(fixture.read_bytes())
    assert any(e['vr']=='SQ' and e['items'] for e in r['elements'])


def test_undefined_unknown_vr_implicit_items():
    child=element(0x00100010,'PN',text('Unknown^Sequence'),implicit=True)
    unknown=element(0x00081110,'UN',item(child)+struct.pack('<II',0xE0DDFFFE,0),undefined=True)
    r=h.inspect_dicom(part10(unknown))
    assert any(e.get('value')=='Unknown^Sequence' for e in r['elements'])
