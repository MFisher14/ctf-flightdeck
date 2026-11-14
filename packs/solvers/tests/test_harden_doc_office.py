"""Independent Office vectors and deterministic malformed-input contract locks.

Fixtures come from python-docx/xlwt, crosschecked by zipfile/ElementTree,
xlrd/olefile, or hand-written MS-CFB / MS-OVBA wire encoders. No target encoder
or parser supplies expected fixture bytes or values.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import random
import struct
import uuid
import warnings
import zipfile
from xml.etree import ElementTree as ET

import docx
import olefile
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    from oletools.olevba import decompress_stream
from oletools.oleobj import OleNativeStream
import pytest
import xlrd
import xlwt

import document_forensics as documents
import maldoc

FLAG = b"CSCTF{Office_Vector}"
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
FREE, EOC, FAT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD


def make_docx():
    document = docx.Document()
    document.core_properties.title = FLAG.decode()
    document.core_properties.author = "Offline Author"
    document.core_properties.subject = "Independent metadata"
    document.core_properties.created = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    document.core_properties.modified = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    document.add_paragraph("Visible " + FLAG.decode())
    stream = io.BytesIO()
    document.save(stream)
    # Normalize ZIP timestamps while preserving independently serialized parts.
    result = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(stream.getvalue())) as source, zipfile.ZipFile(result, 'w') as target:
        for part in source.infolist():
            info = zipfile.ZipInfo(part.filename, (2020, 1, 2, 3, 4, 6))
            info.compress_type = zipfile.ZIP_DEFLATED
            target.writestr(info, source.read(part))
    return result.getvalue()


def make_xls():
    book = xlwt.Workbook()
    visible = book.add_sheet("Public")
    visible.write(0, 0, FLAG.decode())
    hidden = book.add_sheet("Hidden")
    hidden.visibility = 1
    hidden.write(1, 2, 42)
    stream = io.BytesIO()
    book.save(stream)
    return stream.getvalue()


def make_cfb(streams):
    """Small MS-CFB v3 container, regular streams only; independently read by olefile.

    MS-CFB 2.2/2.6: 512-byte sectors, directory entries of 128 bytes, and FAT
    chains terminated by ENDOFCHAIN. Deliberately pads data to >=4096 so no mini
    stream is needed. At most three streams fit beside root in one directory.
    """
    assert 1 <= len(streams) <= 3
    names = sorted(streams, key=lambda n: (len(n), n.upper()))
    bodies = {name: streams[name].ljust(max(4096, (len(streams[name]) + 511) // 512 * 512), b'\0') for name in names}
    starts = {}
    sector = 2
    for name in names:
        starts[name] = sector
        sector += len(bodies[name]) // 512
    assert sector <= 128
    header = bytearray(512)
    header[:8] = OLE_MAGIC
    struct.pack_into('<HHHHH', header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into('<IIIIIIIII', header, 40, 0, 1, 1, 0, 4096, EOC, 0, EOC, 0)
    struct.pack_into('<109I', header, 76, 0, *([FREE] * 108))
    fat = [FREE] * 128
    fat[0], fat[1] = FAT, EOC
    for name in names:
        for sec in range(starts[name], starts[name] + len(bodies[name]) // 512):
            fat[sec] = sec + 1
        fat[sec] = EOC

    def entry(name, kind, start=EOC, size=0, left=FREE, right=FREE, child=FREE, color=1):
        raw = bytearray(128)
        encoded = (name + '\0').encode('utf-16-le')
        assert len(encoded) <= 64
        raw[:len(encoded)] = encoded
        struct.pack_into('<HBBIII', raw, 64, len(encoded), kind, color, left, right, child)
        struct.pack_into('<IQ', raw, 116, start, size)
        return bytes(raw)

    middle = len(names) // 2
    directory = entry('Root Entry', 5, child=middle + 1)
    for index, name in enumerate(names):
        left = 1 if index == middle and middle else FREE
        right = 3 if index == middle and len(names) == 3 else FREE
        directory += entry(name, 2, starts[name], len(bodies[name]), left, right,
                           color=1 if index == middle else 0)
    return bytes(header) + struct.pack('<128I', *fat) + directory.ljust(512, b'\0') + b''.join(bodies[n] for n in names)


def make_ole_native(payload=FLAG):
    body = (struct.pack('<H', 2) + b'proof.bin\0C:\\proof.bin\0' + b'\0' * 8
            + b'C:\\tmp\\proof.bin\0' + struct.pack('<I', len(payload)) + payload)
    return struct.pack('<I', len(body)) + body


def make_rtf(payload=FLAG):
    # MS-OLEDS OLE1 embedded object with length-prefixed class/topic/item strings.
    ole1 = struct.pack('<II', 0x501, 2)
    for item in (b'Package\0', b'\0', b'\0'):
        ole1 += struct.pack('<I', len(item)) + item
    native = make_ole_native(payload)[4:]
    ole1 += struct.pack('<I', len(native)) + native
    return b'{\\rtf1{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata ' + ole1.hex().encode() + b'}}}'


@pytest.fixture(scope='module')
def docx_bytes():
    return make_docx()


@pytest.fixture(scope='module')
def xls_bytes():
    return make_xls()


def test_ooxml_python_docx_vector(docx_bytes):
    source = docx.Document(io.BytesIO(docx_bytes))
    broad = maldoc.ooxml(docx_bytes)
    strict = documents.decode_ooxml(docx_bytes)
    assert broad['core']['title'] == source.core_properties.title == FLAG.decode()
    assert broad['core']['author'] == source.core_properties.author
    assert broad['main'] == 'word'
    assert not broad['vba'] and not broad['macro_enabled']
    assert strict is not None and strict.family == 'word' and strict.main_part == 'word/document.xml'
    with zipfile.ZipFile(io.BytesIO(docx_bytes)) as archive:
        assert set(broad['members']) == set(strict.members) == set(archive.namelist())
        root = ET.fromstring(archive.read('_rels/.rels'))
        expected = {(n.attrib['Id'], n.attrib['Type'].rsplit('/', 1)[-1], n.attrib['Target']) for n in root}
    assert {(r.rel_id, r.rel_type, r.target) for r in strict.relationships if r.source_part == ''} == expected
    assert strict.macros == () and strict.embedded == ()
    assert maldoc.kind_of(docx_bytes) == 'ooxml'


def test_xls_cfb_olefile_and_xlrd_vector(xls_bytes):
    expected = xlrd.open_workbook(file_contents=xls_bytes)
    with olefile.OleFileIO(io.BytesIO(xls_bytes)) as oracle:
        stream_names = ['/'.join(p) for p in oracle.listdir()]
        stream_bytes = {name: oracle.openstream(name).read() for name in stream_names}
    compound = maldoc.cfb(xls_bytes)
    assert compound.paths() == stream_names
    assert compound.intact()
    assert compound.directory_entries() == len(stream_names)
    for name, body in stream_bytes.items():
        assert compound.has(name)
        assert compound.stream(name) == body
    workbook = maldoc.biff_workbook(stream_bytes['Workbook'])
    assert [s['name'] for s in workbook['sheets']] == expected.sheet_names()
    assert [s['state'] for s in workbook['sheets']] == ['visible', 'hidden']
    assert expected.sheet_by_index(0).cell_value(0, 0) == FLAG.decode()
    strict = documents.decode_ole(xls_bytes)
    assert strict is not None
    assert {(s.path, s.size, s.sha256) for s in strict.streams} == {
        (n, len(b), hashlib.sha256(b).hexdigest()) for n, b in stream_bytes.items()}
    assert maldoc.ole_properties(xls_bytes) == {}
    assert maldoc.vba_modules(xls_bytes) == []
    assert maldoc.vba_project(compound) == {}


def test_independent_cfb_builder_olefile_vector():
    supplied = {'Payload': FLAG, 'Second': b'Independent', 'Third': bytes(range(256))}
    blob = make_cfb(supplied)
    with olefile.OleFileIO(io.BytesIO(blob)) as oracle:
        expected = {'/'.join(p): oracle.openstream(p).read() for p in oracle.listdir()}
    assert expected == {n: body.ljust(4096, b'\0') for n, body in supplied.items()}
    parsed = maldoc.CFB(blob)
    assert {n: parsed.stream(n) for n in parsed.paths()} == expected
    strict = documents.decode_ole(blob)
    assert strict is not None
    assert {s.path: s.size for s in strict.streams} == {n: len(b) for n, b in expected.items()}


def test_ole_native_and_rtf_handmade_vector():
    oracle = OleNativeStream(make_ole_native())
    native = maldoc.ole10native(make_ole_native())
    assert native == {'filename': oracle.filename, 'source_path': oracle.src_path,
                      'temp_path': oracle.temp_path, 'data': oracle.data}
    assert native == {'filename': 'proof.bin', 'source_path': 'C:\\proof.bin',
                      'temp_path': 'C:\\tmp\\proof.bin', 'data': FLAG}
    assert maldoc.ole10native(make_ole_native()[4:], package=True) == native
    rtf = make_rtf()
    objects = maldoc.rtf_objects(rtf)
    assert len(objects) == 1 and objects[0]['payload'] == FLAG
    assert objects[0]['class_name'] == 'Package' and objects[0]['filename'] == 'proof.bin'
    strict = documents.decode_rtf(rtf)
    assert strict is not None and strict.object_count == 1
    assert strict.classes == ('Package',)
    assert strict.embedded[0].data == FLAG
    assert strict.embedded[0].sha256 == hashlib.sha256(FLAG).hexdigest()


def test_vba_published_no_compression_vector():
    # MS-OVBA 3.2.1: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/515cce92-0cbb-4588-b273-1d93ec583ba6
    encoded = b'\x01\x19\xb0\x00abcdefgh\x00ijklmnop\x00qrstuv.'
    expected = b'abcdefghijklmnopqrstuv.'
    assert decompress_stream(bytearray(encoded)) == expected
    assert maldoc.vba_decompress(encoded) == expected


def test_vba_uncompressed_chunk_oletools_oracle():
    payload = (FLAG + bytes(range(256)) * 16)[:4096].ljust(4096, b'\0')
    encoded = b'\x01\xff\x3f' + payload
    assert maldoc.vba_decompress(encoded) == bytes(decompress_stream(bytearray(encoded))) == payload


def test_macro_static_string_and_heuristic_vectors():
    # VBA Chr integer semantics and the supplied ASCII bytes independently establish output.
    expr = ' & '.join(f'Chr({b})' for b in FLAG)
    source = f'Sub AutoOpen()\nDim s\ns = {expr}\nEnd Sub\n'
    result = maldoc.deobfuscate(source)
    assert FLAG.decode() in result['decoded']
    strict = documents.decode_macro_source(source, name='Module1')
    assert strict is not None and strict.source == source
    assert strict.autoexec == ('AutoOpen',) and FLAG.decode() in strict.decoded
    assert maldoc.mraptor(source) == {'autoexec': ['AutoOpen'], 'write': False,
                                     'execute': False, 'flags': 'A', 'suspicious': False}
    xlm = '=CONCATENATE("CSCTF{", "Office_Vector}")'
    assert FLAG.decode() in documents.decode_macro_source(xlm, language='xlm').decoded


def test_xlm_formula_against_xlwt_encoder():
    for text in ('1+2', 'CHAR(65)', 'CONCATENATE("CSCTF{","Office_Vector}")'):
        # xlwt's rpn begins with uint16 formula size; its parser is independent.
        encoded = xlwt.Formula(text).rpn()[2:]
        assert maldoc.xlm_formula(encoded) == '=' + text.replace(', ', ',')


def test_activemime_and_ppt_zlib_vectors(xls_bytes):
    import zlib
    compressed = zlib.compress(xls_bytes)
    wrapper = b'ActiveMime'.ljust(0x32, b'\0') + compressed
    assert maldoc.activemime(wrapper) == zlib.decompress(compressed) == xls_bytes
    record = struct.pack('<HHI', 0x10, 0x1011, len(compressed) + 4) + struct.pack('<I', len(xls_bytes)) + compressed
    assert maldoc.ppt_storages(record) == [xls_bytes]


def test_scalar_helpers_and_parse_wrappers(docx_bytes):
    expected_date = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    intervals = int((expected_date - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000
    assert maldoc.filetime(intervals) == expected_date
    identity = uuid.UUID('12345678-1234-5678-9abc-def012345678')
    assert maldoc.guid(identity.bytes_le).lower().strip('{}') == str(identity)
    parsed = maldoc.parse(docx_bytes, name='vector.docx')
    assert parsed['sha256'] == hashlib.sha256(docx_bytes).hexdigest()
    assert parsed['fields']['title'] == FLAG.decode()
    assert maldoc.flatten(parsed)[0] == parsed
    assert isinstance(maldoc.handoff(parsed), list)
    assert isinstance(maldoc.derived(parsed), bytes)
    assert maldoc.jsonable(parsed)['name'] == 'vector.docx'
    assert isinstance(maldoc.report(parsed), list)
    assert maldoc.documents({'vector.docx': docx_bytes})[0]['sha256'] == parsed['sha256']


def malformed_corpus():
    rng = random.Random(0xD0C)
    values = [b'', b'\xff', b'\xff' * 32, b'\xff' * 513,
              b'%PDF-', b'PK', b'PK\x03\x04', OLE_MAGIC,
              OLE_MAGIC + b'\0' * 31, OLE_MAGIC + b'\xff' * 504]
    values += [rng.randbytes(n) for n in (1, 2, 3, 7, 17, 31, 64, 127, 511, 1024)]
    return values


CLEAN_PARSERS = [documents.decode_ooxml, documents.decode_ole, documents.decode_rtf,
                 maldoc.kind_of, maldoc.parse, maldoc.ole10native, maldoc.xlm_formula,
                 maldoc.biff_workbook, maldoc.activemime, maldoc.rtf_objects,
                 maldoc.ppt_storages, maldoc.onenote_files]


@pytest.mark.parametrize('parser', CLEAN_PARSERS, ids=lambda f: f.__module__ + '.' + f.__name__)
def test_binary_parser_deterministic_fuzz(parser):
    for raw in malformed_corpus():
        parser(raw)  # No declared exceptions: any exception is a contract failure.


def _mutation_cases():
    cases = []
    rng = random.Random(0xF11F)
    for label, source in (("docx", make_docx()), ("xls", make_xls()), ("rtf", make_rtf())):
        mutations = []
        for cut in sorted({0, 1, 2, 4, 8, 31, 511, len(source) // 2, len(source) - 1}):
            mutations.append((f"cut-{cut}", source[:cut]))
        for _ in range(8):
            damaged = bytearray(source)
            index = rng.randrange(len(damaged))
            bit = 1 << rng.randrange(8)
            damaged[index] ^= bit
            mutations.append((f"flip-{index}-{bit}", bytes(damaged)))
        for parser in (documents.decode_ooxml, documents.decode_ole, documents.decode_rtf, maldoc.parse):
            for name, raw in mutations:
                cases.append(pytest.param(parser, raw, id=f"{parser.__name__}-{label}-{name}"))
    return cases


@pytest.mark.parametrize('parser,raw', _mutation_cases())
def test_truncations_and_bitflips(parser, raw):
    parser(raw)


@pytest.mark.parametrize('parser', [maldoc.CFB, maldoc.cfb, maldoc.vba_decompress])
def test_declared_valueerror_contract(parser):
    for raw in malformed_corpus():
        try:
            parser(raw)
        except Exception as exc:
            assert type(exc) is ValueError


def test_macro_text_fuzz():
    for raw in malformed_corpus():
        text = raw.decode('latin-1')
        documents.decode_macro_source(text)
        maldoc.deobfuscate(text)
        maldoc.mraptor(text)
        maldoc.scripts(text)
        maldoc.dde_formulas(text)


@pytest.mark.parametrize('raw', [b'', b'PK\x03\x04', b'\xff'*40, random.Random(42).randbytes(37)],
                         ids=['empty', 'truncated-PK', 'all-ff', 'random'])
def test_ooxml_bad_container_contract(raw):
    assert maldoc.ooxml(raw) in (None, {})


def test_vba_modules_truncated_ole_contract():
    assert maldoc.vba_modules(OLE_MAGIC) == []


def test_ole_properties_truncated_ole_contract():
    assert maldoc.ole_properties(OLE_MAGIC) == {}


def test_unmatched_vba_wrappers_fuzz():
    for raw in malformed_corpus():
        if not raw.startswith(OLE_MAGIC):
            assert maldoc.vba_modules(raw) == []


def test_scripts_dde_and_vba_stomped_vectors():
    source = '<job><script language="VBScript"><![CDATA[MsgBox "CSCTF{Office_Vector}"]]></script></job>'
    assert maldoc.scripts(source) == [{'language': 'vbscript', 'ext': '.vbs', 'src': None,
                                      'text': 'MsgBox "CSCTF{Office_Vector}"'}]
    assert maldoc.dde_formulas('=cmd|\'/c echo CSCTF{Office_Vector}\'!A0')
    assert maldoc.vba_stomped_modules({}) == []


def test_onenote_object_literal_vector():
    # MS-ONE FileDataStoreObject header/footer GUIDs, independent wire fixture.
    header = uuid.UUID('bde316e7-2665-4511-a4c4-8d4d0b7a9eac').bytes_le
    footer = uuid.UUID('71fba722-0f79-4a0b-bb13-899256426b24').bytes_le
    blob = b'PREFIX' + header + struct.pack('<Q', len(FLAG)) + b'\0' * 12 + FLAG + footer
    assert maldoc.onenote_files(blob) == [(6, FLAG)]


def make_lnk():
    # MS-SHLLINK: HeaderSize=0x4c, CLSID, IsUnicode+HasArguments, then StringData.
    header = bytearray(76)
    struct.pack_into('<I', header, 0, 76)
    header[4:20] = uuid.UUID('00021401-0000-0000-c000-000000000046').bytes_le
    struct.pack_into('<I', header, 20, 0xA0)
    struct.pack_into('<I', header, 60, 1)
    text = '--label CSCTF{Office_Vector}'
    return bytes(header) + struct.pack('<H', len(text)) + text.encode('utf-16-le') + b'\0' * 4


def test_lnk_literal_header_vector():
    output = maldoc.lnk(make_lnk())
    assert output['flags'] == 0xA0
    assert output['arguments'] == '--label CSCTF{Office_Vector}'
    assert output['show_command'] == 1
    assert output['overlay'] == b''


@pytest.mark.parametrize('raw', [b'', b'\xff'*512, random.Random(88).randbytes(70)])
def test_lnk_documented_valueerror_contract(raw):
    with pytest.raises(ValueError) as error:
        maldoc.lnk(raw)
    assert type(error.value) is ValueError


def test_lnk_truncated_stringdata_contract():
    # Valid fixed-size header says HasArguments, but the following count is absent.
    try:
        maldoc.lnk(make_lnk()[:76])
    except ValueError as exc:
        assert type(exc) is ValueError


@pytest.mark.parametrize('flags,tail', [
    (0x01, b''),
    (0x02, b''),
    (0x02, struct.pack('<I', 4)),
    (0x02, struct.pack('<I', 28)),
    (0xA0, b'\x01'),
    (0xA0, b'\x01\x00'),
], ids=['missing-IDList-count', 'missing-LinkInfo-size', 'short-LinkInfo-size',
        'missing-LinkInfo-body', 'partial-StringData-count', 'missing-StringData-body'])
def test_lnk_truncated_sections_raise_declared_error(flags, tail):
    # The independent MS-SHLLINK header builder supplies no variable-size data.
    header = bytearray(make_lnk()[:76])
    struct.pack_into('<I', header, 20, flags)
    with pytest.raises(ValueError) as error:
        maldoc.lnk(bytes(header) + tail)
    assert type(error.value) is ValueError


def test_guid_empty_contract():
    with pytest.raises(ValueError):
        uuid.UUID(bytes_le=b'')
    assert maldoc.guid(b'') is None


@pytest.mark.parametrize('length', [8, 15])
def test_guid_truncated_value(length):
    raw = bytes(length)
    with pytest.raises(ValueError):
        uuid.UUID(bytes_le=raw)
    assert maldoc.guid(raw) is None


@pytest.mark.parametrize('parser', [maldoc.CFB, maldoc.cfb, maldoc.vba_modules, maldoc.ole_properties])
def test_ole_zero_header_contract(parser):
    try:
        parser(OLE_MAGIC + bytes(504))
    except ValueError as exc:
        # CFB's deliberate legacy error is allowed; wrappers promise empty output.
        if parser not in (maldoc.CFB, maldoc.cfb):
            raise
        assert type(exc) is ValueError


def test_vba_truncated_raw_chunk_rejected():
    # MS-OVBA 2.4.1.3.3 requires exactly 4096 raw bytes for CompressedChunkFlag=0.
    # https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/86ff30e6-9442-4232-ba00-e616c64fd9ac
    # The oletools oracle is deliberately not used for this invalid case: it is
    # also permissive and returns b'A'. The normative length is the oracle.
    try:
        decoded = maldoc.vba_decompress(b'\x01\xff\x3fA')
    except ValueError as exc:
        assert type(exc) is ValueError
    else:
        assert decoded in (None, b'')


@pytest.mark.parametrize('raw', [
    b'\x01\xff',
    b'\x01\x00\x80\x00',
    b'\x01\x01\xb0\x00',
    b'\x01\x01\xb0\x01\x00',
    b'\x01\x00\x30A',
], ids=['partial-header', 'invalid-signature', 'truncated-compressed-body',
        'partial-copy-token', 'short-raw-chunk'])
def test_vba_malformed_chunk_structure_raises_declared_error(raw):
    # MS-OVBA: header bits 12..14 are 0b011, low 12 bits are size minus 3;
    # compressed copy tokens occupy two bytes and raw chunks occupy 4096.
    with pytest.raises(ValueError) as error:
        maldoc.vba_decompress(raw)
    assert type(error.value) is ValueError
