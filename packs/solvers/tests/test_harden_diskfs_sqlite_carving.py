"""Independent SQLite/stream vectors and deterministic malformed-byte contracts.

Oracles: sqlite3 itself and SQLite's file-format specification; stdlib stream,
ZIP and WAV writers; hand-built known offsets. No engine encoder is used.
https://www.sqlite.org/fileformat2.html
https://github.com/google/snappy/blob/main/format_description.txt
https://github.com/google/leveldb/blob/main/doc/log_format.md
"""
import bz2
import gzip
import hashlib
import io
import lzma
import random
import sqlite3
import struct
import wave
import zipfile
import zlib
from pathlib import Path

import pytest

import carving as C
import sqlite_artifacts as S


def clean_call(function, *args, allowed=(), **kwargs):
    """Exact declared errors only: UnicodeError is not silently ValueError."""
    try:
        return function(*args, **kwargs)
    except Exception as exc:
        assert type(exc) in allowed, f'{function.__name__} leaked {type(exc).__name__}: {exc}'
        return None


def sqlite_image(tmp_path, *, page_size=512, encoding='UTF-8', negative=False, large=False):
    path=tmp_path/f'db-{page_size}-{encoding}-{negative}-{large}.sqlite'
    con=sqlite3.connect(path)
    con.execute(f'PRAGMA page_size={page_size}')
    con.execute(f"PRAGMA encoding='{encoding}'")
    con.execute('CREATE TABLE items(n, t, b, r)')
    rows=[(7,-129,'CSCTF{sqlite_oracle}',b'\0\xff\x10',1.5),
          (11,8388608,'café λ',b'',-2.25),
          (12,None,'',None,0.0)]
    if negative:
        rows=[(-1,-7,'negative',b'x',2.0)]
    if large:
        rows.append((19,2**48+3,'z'*2400,b'A'*800,3.75))
    con.executemany('INSERT INTO items(rowid,n,t,b,r) VALUES (?,?,?,?,?)',rows)
    con.commit()
    expected=con.execute('SELECT rowid,n,t,b,r FROM items ORDER BY rowid').fetchall()
    root=con.execute("SELECT rootpage FROM sqlite_master WHERE name='items'").fetchone()[0]
    con.close()
    return path.read_bytes(),root,expected


def independent_varint(buf, offset):
    # SQLite spec: first eight bytes carry seven bits, ninth carries eight.
    value=0
    for i in range(9):
        byte=buf[offset+i]
        value=(value << (8 if i==8 else 7)) | (byte if i==8 else byte & 127)
        if i==8 or byte <128:
            return value,offset+i+1
    raise AssertionError('unreachable')


@pytest.mark.parametrize('encoded,value',[
    ('00',0),('7f',127),('8100',128),('817f',255),('c000',8192),
    ('818000',16384),('ffffffffffffffff7f',2**64-129),
    ('ffffffffffffffffff',2**64-1)])
def test_sqlite_published_varints(encoded,value):
    raw=bytes.fromhex(encoded)
    assert independent_varint(raw,0)==(value,len(raw))
    assert S.varint(raw,0)==(value,len(raw))
    assert S.varint(b'xx'+raw,2)==(value,len(raw)+2)


@pytest.mark.parametrize('encoded,expected',[
    ('0200',[None]),('0208',[0]),('0209',[1]),('0201ff',[-1]),
    ('0202ff7f',[-129]),('0203800000',[-8388608]),
    ('020480000000',[-2147483648]),('0205800000000000',[-2**47]),
    ('02068000000000000000',[-2**63]),('02073ff8000000000000',[1.5]),
    ('02106162',[b'ab']),('02116162',['ab']),
    ('0500011009ff6162',[None,-1,b'ab',1])])
def test_sqlite_published_serial_types(encoded,expected):
    raw=bytes.fromhex(encoded)
    assert S.read_record(raw,0,len(raw),strict=True)==(expected,len(raw))


@pytest.mark.parametrize('page_size,encoding',[(512,'UTF-8'),(4096,'UTF-16le'),(65536,'UTF-16be')])
def test_sqlite_pages_records_database_against_sqlite3(tmp_path,page_size,encoding):
    raw,root,expected=sqlite_image(tmp_path,page_size=page_size,encoding=encoding,large=True)
    pages=S.Pages(raw)
    assert pages.page_size==page_size
    assert pages.count==len(raw)//page_size
    assert pages.page(root)==raw[(root-1)*page_size:root*page_size]
    leaves=pages.table_pages(root)
    actual=[]
    for page in leaves:
        actual.extend((rowid,*values) for rowid,values in pages.leaf_cells(pages.page(page),page))
    assert sorted(actual)==expected
    assert pages.freelist_pages()==[]
    assert len(pages.images())==pages.count
    database=S.Database(raw,carve=False)
    assert database.error is None
    assert [tuple(row[k] for k in ('_rowid','n','t','b','r')) for row in database.tables['items']]==expected
    # Independently locate each inline cell's payload and compare direct record parsing.
    for page in leaves:
        pg=pages.page(page)
        header=100 if page==1 else 0
        ncell=int.from_bytes(pg[header+3:header+5],'big')
        for j in range(ncell):
            off=int.from_bytes(pg[header+8+2*j:header+10+2*j],'big')
            size,pos=independent_varint(pg,off)
            rowid,pos=independent_varint(pg,pos)
            if size <=page_size-35:
                oracle=next(r[1:] for r in expected if r[0]==rowid)
                assert S.read_record(pg,pos,pos+size,pages.enc)==(list(oracle),pos+size)


def test_sqlite_negative_rowid_matches_sqlite3(tmp_path):
    raw,root,expected=sqlite_image(tmp_path,negative=True)
    assert [(r,*v) for r,v in S.Pages(raw).leaf_cells(S.Pages(raw).page(root),root)]==expected


def test_sqlite_record_rejects_end_beyond_buffer():
    with pytest.raises(ValueError):
        S.read_record(bytes.fromhex('0201'),0,3)


def test_sqlite_varint_truncated_contract():
    clean_call(S.varint,b'\x80',0,allowed=(ValueError,))


def test_sqlite_interior_cell_count_contract(tmp_path):
    raw,root,_=sqlite_image(tmp_path)
    image=bytearray(raw)
    base=(root-1)*512
    image[base:base+512]=bytes(512)
    image[base]=5
    struct.pack_into('>H',image,base+3,65535)
    clean_call(S.Pages(bytes(image)).table_pages,root,allowed=(ValueError,))


def test_sqlite_free_region_offsets(tmp_path):
    raw,_,_=sqlite_image(tmp_path)
    pg=bytearray(512)
    pg[0]=13
    struct.pack_into('>HHH',pg,1,400,2,400)
    struct.pack_into('>HH',pg,400,450,16)
    struct.pack_into('>HH',pg,450,0,24)
    assert S.Pages(raw).free_regions(pg,2)==[(12,400,False),(400,416,True),(450,474,True)]


def wal_image(tmp_path):
    path=tmp_path/'wal-source.db'
    con=sqlite3.connect(path)
    con.execute('PRAGMA page_size=512')
    con.execute('CREATE TABLE t(value)')
    con.execute("INSERT INTO t VALUES ('before')")
    con.commit()
    con.execute('PRAGMA journal_mode=WAL')
    con.execute("UPDATE t SET value='after!'")
    con.commit()
    raw,wal=path.read_bytes(),Path(str(path)+'-wal').read_bytes()
    root=con.execute("SELECT rootpage FROM sqlite_master WHERE name='t'").fetchone()[0]
    con.close()
    return raw,wal,root


def test_sqlite_wal_committed_view(tmp_path):
    raw,wal,root=wal_image(tmp_path)
    pages=S.Pages(raw,wal)
    assert pages.leaf_cells(pages.page(root),root)==[(1,['after!'])]
    assert pages.leaf_cells(pages.page(root,{}),root)==[(1,['before'])]
    assert S.Database(raw,wal,carve=False).tables['t'][0]['value']=='after!'


def test_sqlite_wal_checksum_matches_sqlite3(tmp_path):
    raw,wal,root=wal_image(tmp_path)
    corrupt=bytearray(wal)
    corrupt[32+24+50]^=1  # page padding, preserving the row but invalidating the frame checksum
    path=tmp_path/'wal-oracle.db'
    path.write_bytes(raw)
    Path(str(path)+'-wal').write_bytes(corrupt)
    with sqlite3.connect(path) as oracle:
        expected=oracle.execute('SELECT rowid,value FROM t').fetchall()
    pages=S.Pages(raw,bytes(corrupt))
    assert [(r,*v) for r,v in pages.leaf_cells(pages.page(root),root)]==expected


def _streams():
    payload=b'CSCTF{independent_stream_oracle}\0'*4
    archive=io.BytesIO()
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED) as z:
        info=zipfile.ZipInfo('known.txt',(2020,1,2,3,4,6))
        z.writestr(info,payload)
    audio=io.BytesIO()
    with wave.open(audio,'wb') as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000)
        w.writeframes(struct.pack('<4h',-32768,-1,0,32767))
    return [('gzip',gzip.compress(payload,mtime=0)),('zlib',zlib.compress(payload)),
            ('bzip2',bz2.compress(payload)),('xz',lzma.compress(payload)),
            ('zip',archive.getvalue()),('wav',audio.getvalue())]


STREAMS=_streams()


@pytest.mark.parametrize('kind,blob',STREAMS)
def test_carve_offsets_against_independent_library_streams(kind,blob):
    prefix=b'offset-is-thirteen'[:13]
    r=C.carve_all(prefix+blob+b'trailing',kinds=(kind,))
    assert len(r)==1
    assert (r[0].kind,r[0].offset,r[0].end,r[0].data)==(kind,13,13+len(blob),blob)


def test_carve_sqlite_real_database(tmp_path):
    raw,_,_=sqlite_image(tmp_path,page_size=4096)
    item,=C.carve_all(b'prefix'+raw+b'tail',kinds=('sqlite',))
    assert (item.offset,item.end,item.data)==(6,6+len(raw),raw)


def test_carve_polyglot_and_slack_cluster_math():
    gzip_blob=STREAMS[0][1]
    zip_blob=STREAMS[4][1]
    poly=C.detect_polyglot(gzip_blob+zip_blob)
    assert poly.formats==('gzip','zip')
    assert [(x.offset,x.end) for x in poly.carvings]==[(0,len(gzip_blob)),(len(gzip_blob),len(gzip_blob)+len(zip_blob))]
    image=bytes(100)+gzip_blob+bytes(30)
    extent=C.FileExtent(20,80,len(image)-20,'known')
    r,=C.carve_file_slack(image,[extent])
    assert (r.slack_offset,r.slack_end)==(100,len(image))
    assert any((x.offset,x.end)==(100,100+len(gzip_blob)) for x in r.carvings)
    image=bytes(64)+gzip_blob+bytes(256-64-len(gzip_blob))
    r,=C.carve_unallocated(image,[True,False,False,True],block_size=64)
    assert (r.start,r.end,r.block_start,r.block_end)==(64,192,1,3)
    assert any(x.data==gzip_blob and x.offset==64 for x in r.carvings)


@pytest.mark.parametrize('kind,blob',STREAMS)
def test_carve_every_stream_truncation_is_clean(kind,blob):
    for end in range(len(blob)):
        assert C.carve_all(blob[:end],kinds=(kind,))==()
        clean_call(C.detect_polyglot,blob[:end])


def malformed_bytes():
    rng=random.Random(0xD15CF5)
    corpus=[b'',b'\xff',b'\xff'*9,b'\xff'*48,b'\xff'*100,bytes(512)]
    corpus.extend(rng.randbytes(n) for n in (1,2,3,7,15,32,64,100,257,512))
    magics=[b'SQLite format 3\0',b'Cr24',b'\x57\xfb\x80\x8b\x24\x75\x47\xdb',
            b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff',b'GIF89a',b'PK\x03\x04',
            b'%PDF-1.7',b'\x1f\x8b\x08',b'BZh9',b'\xfd7zXZ\0',b'RIFF',
            b'BM',b'\x7fELF',b'MZ',b'7z\xbc\xaf\x27\x1c']
    for magic in magics:
        corpus.extend(magic[:n] for n in range(1,len(magic)+1))
        corpus.extend((magic+bytes(16),magic+b'\xff'*16))
    return list(dict.fromkeys(corpus))


@pytest.mark.parametrize('data',malformed_bytes(),ids=lambda b:f'{len(b)}-{b[:8].hex()}')
def test_carving_public_functions_fail_closed(data):
    clean_call(C.carve_all,data)
    clean_call(C.detect_polyglot,data)
    clean_call(C.carve_file_slack,data,[C.FileExtent(0,0,len(data))])
    clean_call(C.carve_unallocated,data,[False]*len(data),block_size=1)


@pytest.mark.parametrize('kind,blob',STREAMS)
def test_carving_bitflips_clean(kind,blob):
    for off in sorted({0,1,3,len(blob)//2,len(blob)-1}):
        changed=bytearray(blob); changed[off]^=0x80
        clean_call(C.carve_all,changed)
        clean_call(C.detect_polyglot,changed)


@pytest.mark.parametrize('data',malformed_bytes(),ids=lambda b:f'{len(b)}-{b[:8].hex()}')
def test_sqlite_binary_readers_fail_closed(data):
    clean_call(S.read_record,data,0,len(data),allowed=(ValueError,))
    clean_call(S.Pages,data,allowed=(ValueError,))
    clean_call(S.leveldb_log,data)
    clean_call(S.leveldb_table,data,allowed=(ValueError,))
    clean_call(S.leveldb_records,data)
    clean_call(S.crx,data,allowed=(ValueError,))
    clean_call(S.firefox_logins,data)


@pytest.mark.parametrize('data',[b'',b'\xff'*100,b'SQLite format 3\0',bytes(512)])
def test_sqlite_database_public_wrapper_fail_closed(data):
    db=clean_call(S.Database,data,carve=False)
    assert db is not None
    assert db.tables=={}


@pytest.mark.parametrize('raw,expected',[(b'\x05\x10hello',b'hello'),(b'\x08\x04ab\x16\x02\0',b'abababab'),(b'\0',b'')])
def test_snappy_published_literal_copy(raw,expected):
    assert S.snappy_decompress(raw)==expected


@pytest.mark.parametrize('raw',[b'',b'\x80',b'\x80'*9])
def test_snappy_truncated_contract(raw):
    clean_call(S.snappy_decompress,raw,allowed=(ValueError,))


def test_crx3_truncated_proto_contract():
    raw=b'Cr24'+struct.pack('<II',3,4)+b'\x80'*4
    clean_call(S.crx,raw,allowed=(ValueError,))


def test_crx2_independent_header():
    key=b'public-key-known-bytes'
    signature=b'signature'
    archive=STREAMS[4][1]
    raw=b'Cr24'+struct.pack('<III',2,len(key),len(signature))+key+signature+archive
    expected=''.join(chr(97+int(c,16)) for c in hashlib.sha256(key).digest()[:16].hex())
    assert S.id_from_bytes(bytes(range(16)))=='aaabacadaeafagahaiajakalamanaoap'
    assert S.id_from_public_key(key)==expected
    assert S.crx(raw)=={'version':2,'zip':archive,'ids':[('crx2_public_key',expected)]}


def test_leveldb_log_handwritten_write_batch():
    # Full physical record, sequence=20, two operations: put k=v and delete x.
    batch=struct.pack('<QI',20,2)+b'\x01\x01k\x01v\x00\x01x'
    # CRC is not used by the existing parser; the independent encoder still supplies it.
    crc=0xffffffff
    for byte in b'\x01'+batch:
        crc^=byte
        for _ in range(8):
            crc=(crc>>1)^(0x82f63b78 if crc&1 else 0)
    crc^=0xffffffff
    masked=(((crc>>15)|(crc<<17))+0xa282ead8)&0xffffffff
    raw=struct.pack('<IHB',masked,len(batch),1)+batch
    expected=[{'seq':20,'state':'live','key':b'k','value':b'v'},
              {'seq':21,'state':'deleted','key':b'x','value':None}]
    assert S.leveldb_log(raw)==expected
    assert S.is_leveldb('000123.log',raw)
    assert S.leveldb_records(raw,'000123.log')[0]=={
        'seq':20,'state':'live','key':'k','value':'v','origin':None,'file':'000123.log'}


def test_leveldb_table_known_offsets():
    def uvarint(n):
        out=bytearray()
        while n>=128:
            out.append((n&127)|128); n>>=7
        out.append(n)
        return bytes(out)
    def block(entries):
        # No shared prefixes, a single restart at byte zero.
        raw=b''.join(b'\0'+uvarint(len(k))+uvarint(len(v))+k+v for k,v in entries)
        return raw+struct.pack('<II',0,1)
    def physical(block):
        crc=0xffffffff
        for byte in block+b'\0':
            crc^=byte
            for _ in range(8):
                crc=(crc>>1)^(0x82f63b78 if crc&1 else 0)
        crc^=0xffffffff
        masked=(((crc>>15)|(crc<<17))+0xa282ead8)&0xffffffff
        return block+b'\0'+struct.pack('<I',masked)
    key=b'key'+struct.pack('<Q',(123<<8)|1)
    data=block([(key,b'CSCTF{leveldb_record}')])
    meta=block([])
    prefix=physical(data)+physical(meta)
    index=block([(key,uvarint(0)+uvarint(len(data)))])
    footer=uvarint(len(physical(data)))+uvarint(len(meta))+uvarint(len(prefix))+uvarint(len(index))
    footer=footer.ljust(40,b'\0')+struct.pack('<Q',0xdb4775248b80fb57)
    raw=prefix+physical(index)+footer
    assert S.leveldb_table(raw)==[{'seq':123,'state':'live','key':b'key','value':b'CSCTF{leveldb_record}'}]
    assert S.is_leveldb('anything',raw)
    assert S.leveldb_records(raw)[0]['value']=='CSCTF{leveldb_record}'


def test_sqlite_real_magic_truncations_and_bitflips(tmp_path):
    raw,root,_=sqlite_image(tmp_path)
    variants=[raw[:n] for n in (16,17,20,31,56,99,100,101,511,512,len(raw)-1)]
    for off in (0,15,16,17,20,21,32,56,99,100,(root-1)*512+3,len(raw)-1):
        modified=bytearray(raw); modified[off]^=0x80
        variants.append(bytes(modified))
    for data in variants:
        pages=clean_call(S.Pages,data,allowed=(ValueError,))
        if pages:
            clean_call(pages.leaf_cells,pages.page(root),root)
        clean_call(S.read_record,data,0,len(data),allowed=(ValueError,))
        clean_call(S.Database,data,carve=False)
        clean_call(C.carve_all,data,kinds=('sqlite',))


def test_snappy_literal_overrun_rejected():
    # Uncompressed length 3, literal tag declares FOUR bytes, only abc follow.
    with pytest.raises(ValueError):
        S.snappy_decompress(b'\x03\x0cabc')


def test_sqlite_wal_opposite_checksum_byte_order(tmp_path):
    raw,wal,root=wal_image(tmp_path)
    modified=bytearray(wal)
    magic=int.from_bytes(modified[:4],'big')^1
    modified[:4]=magic.to_bytes(4,'big')
    order='little' if magic==0x377f0682 else 'big'
    # Rewrite checksum fields using the documented recurrence, then use native
    # SQLite (not this helper or the engine) as the semantic acceptance oracle.
    def sum_bytes(data, prior=(0,0)):
        a,b=prior
        for pos in range(0,len(data),8):
            a=(a+int.from_bytes(data[pos:pos+4],order)+b)%2**32
            b=(b+int.from_bytes(data[pos+4:pos+8],order)+a)%2**32
        return a,b
    checksum=sum_bytes(modified[:24])
    struct.pack_into('>II',modified,24,*checksum)
    ps=int.from_bytes(modified[8:12],'big')
    for pos in range(32,len(modified),24+ps):
        checksum=sum_bytes(modified[pos:pos+8]+modified[pos+24:pos+24+ps],checksum)
        struct.pack_into('>II',modified,pos+16,*checksum)
    path=tmp_path/'opposite-wal-oracle.db'
    path.write_bytes(raw)
    Path(str(path)+'-wal').write_bytes(modified)
    with sqlite3.connect(path) as oracle:
        expected=oracle.execute('SELECT rowid,value FROM t').fetchall()
    assert expected==[(1,'after!')]
    pages=S.Pages(raw,bytes(modified))
    assert [(r,*v) for r,v in pages.leaf_cells(pages.page(root),root)]==expected


def test_sqlite_wal_header_checksum_rejects_bad_header(tmp_path):
    raw,wal,root=wal_image(tmp_path)
    modified=bytearray(wal);modified[24]^=1
    pages=S.Pages(raw,bytes(modified))
    assert pages.frames==[]
    assert pages.leaf_cells(pages.page(root),root)==[(1,['before'])]


@pytest.mark.parametrize('data',[b'\x05\xf0',b'\x04\x04ab\x01',b'\x06\x04ab\x02\x02',
                                 b'\x06\x04ab\x03\x02\0',b'\x03\x04ab\x16\x02\0'])
def test_snappy_truncated_operand_or_output_overrun(data):
    with pytest.raises(ValueError) as caught:
        S.snappy_decompress(data)
    assert type(caught.value) is ValueError


@pytest.mark.parametrize('offset',[-1,2**100])
def test_sqlite_varint_record_out_of_range_offsets(offset):
    for call,args in ((S.varint,(b'\x01',offset)),(S.read_record,(b'\x02\x08',offset,offset+2))):
        with pytest.raises(ValueError) as caught:
            call(*args)
        assert type(caught.value) is ValueError
