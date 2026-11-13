"""Independent filesystem vectors and bounded deterministic fail-closed corpus.

Oracles (never the engine's encoders or existing test fixture helpers):
* Microsoft NTFS MULTI_SECTOR_HEADER/MFT and FAT specification v1.03.
* Linux ext4 inodes/ifork/journal docs and Btrfs on-disk format/accessors.h.
* Apple File System Reference, structures and Fletcher checksum equations.
* libyal VSS format documentation; RFC 3720 CRC32C check value.
All fixtures are hand-packed at published byte offsets with literal expectations.
"""
import datetime
import inspect
import random
import struct
import uuid
from dataclasses import replace

import pytest
import filesystem_depth as F

IDENT = '00112233-4455-6677-8899-aabbccddeeff'
ID_BYTES = uuid.UUID(IDENT).bytes
PAYLOAD = b'CSCTF{known_disk_bytes}'


def ntfs_boot():
    b=bytearray(512)
    b[:11]=b'\xeb\x52\x90NTFS    '
    struct.pack_into('<H',b,11,512)
    b[13]=8
    struct.pack_into('<QQQ',b,40,80000,7,13)
    b[64]=246  # signed -10: 2**10 bytes, not ten clusters
    b[68]=2    # positive: two 4096-byte clusters
    struct.pack_into('<Q',b,72,0x1122334455667788)
    b[510:]=b'\x55\xaa'
    return bytes(b)


def resident(kind, value, ident):
    size=(24+len(value)+7)//8*8
    a=bytearray(size)
    struct.pack_into('<II',a,0,kind,size)
    struct.pack_into('<H',a,14,ident)
    struct.pack_into('<IH',a,16,len(value),24)
    a[24:24+len(value)]=value
    return bytes(a)


def mft_record():
    name='evidence.txt'.encode('utf-16-le')
    fn=bytearray(66+len(name))
    struct.pack_into('<Q',fn,0,5)
    fn[64:66]=bytes([len(name)//2,1]);fn[66:]=name
    attrs=resident(0x30,bytes(fn),2)+resident(0x80,PAYLOAD,3)
    b=bytearray(1024);b[:4]=b'FILE'
    struct.pack_into('<HH',b,4,48,3)
    struct.pack_into('<HHHHIIQ',b,16,9,1,56,1,56+len(attrs)+4,1024,0)
    struct.pack_into('<I',b,44,57)
    b[48:54]=b'\xcd\xab\x12\x34\x56\x78'
    b[56:56+len(attrs)]=attrs
    b[56+len(attrs):60+len(attrs)]=b'\xff'*4
    b[510:512]=b[1022:1024]=b'\xcd\xab'
    return bytes(b)


def usn_record(major=2):
    name='trace.bin'.encode('utf-16-le');start=60 if major==2 else 76
    b=bytearray((start+len(name)+7)//8*8)
    struct.pack_into('<IHH',b,0,len(b),major,0)
    if major==2:
        struct.pack_into('<QQQQIIIIHH',b,8,57,5,100,116444736000000000,0x100,0,42,0x20,len(name),start)
    else:
        b[8:24]=bytes(range(16));b[24:40]=bytes(range(16,32))
        struct.pack_into('<QQIIIIHH',b,40,100,116444736000000000,0x100,0,42,0x20,len(name),start)
    b[start:start+len(name)]=name
    return bytes(b)


def fat_boot():
    # A 1.44-MiB FAT12 floppy: reserved 1 + FATs 2*9 + root 14 = sector 33.
    b=bytearray(512);b[:3]=b'\xeb\x3c\x90'
    struct.pack_into('<HBHBHHBHHHII',b,11,512,1,1,2,224,2880,0xF0,9,18,2,0,0)
    b[510:]=b'\x55\xaa'
    return bytes(b)


def directory(short=b'EVIDENCEBIN', cluster=2, size=len(PAYLOAD), terminator=True):
    b=bytearray(32);b[:11]=short;b[11]=0x20
    struct.pack_into('<H',b,20,cluster>>16)
    struct.pack_into('<HI',b,26,cluster&65535,size)
    return bytes(b)+(bytes(32) if terminator else b'')


def fat12_table():
    b=bytearray(9*512)
    # FAT12 pairs: 0=FF0,1=FFF; 2=3,3=FFF. Three bytes per pair.
    b[:6]=bytes.fromhex('f0ffff03f0ff')
    return bytes(b)


def ext_sb():
    b=bytearray(1024)
    for offset,value in [(0,32),(4,128),(24,0),(32,128),(40,32),(76,1),(92,4),(96,0x40),(224,8)]:
        struct.pack_into('<I',b,offset,value)
    struct.pack_into('<H',b,56,0xEF53);struct.pack_into('<H',b,88,256)
    b[104:120]=ID_BYTES;b[120:124]=b'LAB\0'
    return bytes(b)


def ext_inode(extents=False):
    b=bytearray(256)
    struct.pack_into('<HHI',b,0,0o100640,0x1234,1024+len(PAYLOAD))
    struct.pack_into('<HH',b,24,0x5678,1)
    struct.pack_into('<I',b,100,77)
    struct.pack_into('<HH',b,120,1,2)
    if extents:
        struct.pack_into('<I',b,32,0x80000)
        struct.pack_into('<HHHHI',b,40,0xF30A,1,4,0,0)
        struct.pack_into('<IHHI',b,52,0,2,0,9)
    else:
        struct.pack_into('<II',b,40,9,10)
    return bytes(b)


def jbd(kind=1):
    b=bytearray(1024);struct.pack_into('>III',b,0,0xC03B3998,kind,17)
    if kind==1:
        struct.pack_into('>II',b,12,42,0);b[20:36]=ID_BYTES
        struct.pack_into('>II',b,36,99,0xA)
    elif kind==5:
        struct.pack_into('>III',b,12,24,42,99)
    return bytes(b)


def fletcher_reference(data):
    # Closed-form weighted sums, independent of the engine's recurrence.
    words=struct.unpack('<'+'I'*(len(data)//4),data);m=2**32-1
    s=sum(words)%m;t=sum((len(words)-i)*w for i,w in enumerate(words))%m
    lo=(-(s+t))%m;hi=(-s-lo)%m
    return lo+(hi<<32)


def crc_reference(data):
    # Reflected polynomial long division, independent of lookup-table implementation.
    crc=0xffffffff
    for octet in data:
        crc ^= octet
        for _ in range(8):
            crc=(crc>>1)^(0x82f63b78 if crc&1 else 0)
    return crc^0xffffffff


def apfs_block(kind=1):
    b=bytearray(4096);struct.pack_into('<QQII',b,8,7,11,kind,0)
    if kind==1:
        b[32:36]=b'NXSB';struct.pack_into('<I',b,36,4096)
        struct.pack_into('<Q',b,40,256);b[72:88]=ID_BYTES
        struct.pack_into('<QQ',b,88,12,13)
    else:
        struct.pack_into('<II',b,32,1,1)
        struct.pack_into('<IIIIQQQ',b,40,3,0,4096,0,88,19,23)
    struct.pack_into('<Q',b,0,fletcher_reference(b[8:]))
    return bytes(b)


def apfs_snapshot():
    name=b'snapshot-one\0'
    return struct.pack('<QQQQQIIH',3,4,1_000_000_000,2_000_000_000,2,3,0,len(name))+name


def btrfs_superblock():
    b=bytearray(4096);b[32:48]=ID_BYTES
    struct.pack_into('<Q',b,48,0);b[64:72]=b'_BHRfS_M'
    struct.pack_into('<QQQ',b,72,11,4096,8192)
    struct.pack_into('<QQ',b,112,1048576,16384);struct.pack_into('<Q',b,136,1)
    struct.pack_into('<II',b,144,4096,4096)
    struct.pack_into('<I',b,0,crc_reference(b[32:]))
    return bytes(b)


def btrfs_root_value():
    b=bytearray(283)
    struct.pack_into('<7Q',b,160,11,256,40960,0,8192,9,1)
    struct.pack_into('<I',b,216,1);struct.pack_into('<Q',b,239,11)
    b[247:263]=ID_BYTES
    return bytes(b)


def btrfs_tree(leaf=False):
    b=bytearray(4096);b[32:48]=ID_BYTES;b[64:80]=bytes(range(16))
    struct.pack_into('<Q',b,48,4096);struct.pack_into('<QQI',b,80,11,1,1)
    b[100]=0 if leaf else 1
    struct.pack_into('<QBQ',b,101,256,132,7)
    if leaf:
        payload=btrfs_root_value();physical=4096-len(payload)
        # btrfs_item.offset is relative to END of 101-byte btrfs_header.
        struct.pack_into('<II',b,118,physical-101,len(payload));b[physical:]=payload
    else:
        struct.pack_into('<QQ',b,118,8192,11)
    struct.pack_into('<I',b,0,crc_reference(b[32:]))
    return bytes(b)


def vss_header():
    b=bytearray(512);b[:16]=bytes.fromhex('3808876bc176e448b7ae04046e6cc752')
    struct.pack_into('<II',b,16,1,1)
    struct.pack_into('<QQ',b,24,0x1e00,0x1e00)
    struct.pack_into('<QQ',b,48,16384,1048576)
    b[64:80]=uuid.UUID(IDENT).bytes_le;b[80:96]=uuid.UUID(IDENT).bytes_le
    return bytes(0x1e00)+bytes(b)


def test_ntfs_geometry_fixup_record_and_recovery():
    boot=F.parse_ntfs_boot(ntfs_boot())
    assert (boot.cluster_size,boot.record_size,boot.index_record_size,boot.mft_lcn*boot.cluster_size)==(4096,1024,8192,28672)
    raw=mft_record();fixed=F.apply_ntfs_fixup(raw,512)
    assert fixed[510:512]==b'\x12\x34' and fixed[1022:]==b'\x56\x78'
    record=F.parse_ntfs_record(raw)
    assert (record.record_number,record.sequence,record.names,record.in_use)==(57,9,('evidence.txt',),True)
    stream=record.attributes[1]
    assert stream.value==PAYLOAD
    assert F.recover_ntfs_attribute(b'',stream,512)==PAYLOAD


def test_ntfs_signed_sparse_runlist_and_initialized_boundary():
    # 3 at LCN 300; sparse 2; 1 at LCN 296 (relative -4, sparse doesn't reset base).
    raw=bytes.fromhex('21032c0101021101fc00')
    assert [(r.vcn,r.length,r.lcn) for r in F.decode_ntfs_runlist(raw)]==[(0,3,300),(3,2,None),(5,1,296)]
    assert [(r.vcn,r.lcn) for r in F.decode_ntfs_runlist(bytes.fromhex('1101fe00'),start_vcn=7,start_lcn=9)]==[(7,7)]
    attr=F.NtfsAttribute(0x80,2,'',False,0x8000,None,(F.DataRun(0,1,2),F.DataRun(1,1,None),F.DataRun(2,1,4)),1200,1024,1100)
    image=bytearray(5*512);image[1024:1536]=b'A'*512;image[2048:2560]=b'B'*512
    assert F.recover_ntfs_attribute(image,attr,512)==b'A'*512+bytes(512)+b'B'*76+bytes(100)


@pytest.mark.parametrize('major',[2,3])
def test_usn_reference_vectors(major):
    (r,)=F.parse_usn_records(usn_record(major))
    assert (r.name,r.reason,r.usn,r.security_id)==('trace.bin',0x100,100,42)
    assert r.timestamp==datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
    assert r.file_reference==(57 if major==2 else bytes(range(16)).hex())


def test_fat_geometry_directory_chains_and_recovery():
    boot=F.parse_fat_boot(fat_boot())
    assert (boot.fat_type,boot.first_data_sector,boot.cluster_count,boot.cluster_size)==('FAT12',33,2847,512)
    (entry,)=F.parse_fat_directory(directory(size=512+len(PAYLOAD)))
    assert (entry.name,entry.first_cluster,entry.size)==('EVIDENCE.BIN',2,512+len(PAYLOAD))
    table=fat12_table();assert F.follow_fat_chain(table,2,'FAT12')==(2,3)
    assert F.follow_fat_chain(struct.pack('<5H',0xfff8,0xffff,4,0,0xffff),2,'FAT16')==(2,4)
    assert F.follow_fat_chain(struct.pack('<5I',0xfffffff8,0xffffffff,0xa0000004,0,0xffffffff),2,'FAT32')==(2,4)
    image=bytearray(2880*512);image[33*512:34*512]=b'A'*512;image[34*512:34*512+len(PAYLOAD)]=PAYLOAD
    assert F.recover_fat_file(image,boot,table,entry)==b'A'*512+PAYLOAD


def test_fat_05_filename_escape():
    entries=F.parse_fat_directory(directory(short=b'\x05VIDENCEBIN'))
    assert tuple(x.short_name for x in entries)==('σVIDENCE.BIN',)


def test_fat_full_directory_has_no_required_zero_terminator():
    raw=b''.join(directory(short=f'FILE{i:04d}TXT'.encode(),terminator=False) for i in range(16))
    entries=F.parse_fat_directory(raw)
    assert tuple(x.name for x in entries)==tuple(f'FILE{i:04d}.TXT' for i in range(16))


@pytest.mark.parametrize('extents',[False,True])
def test_ext_inode_and_recover_file(extents):
    sb=F.parse_ext_superblock(ext_sb())
    assert (sb.block_size,sb.inode_size,sb.blocks_count,sb.uuid,sb.volume_name)==(1024,256,128,IDENT,'LAB')
    inode=F.parse_ext_inode(ext_inode(extents),sb)
    assert (inode.uid,inode.gid,inode.size,inode.generation)==(0x11234,0x25678,1024+len(PAYLOAD),77)
    image=bytearray(128*1024);image[9*1024:10*1024]=b'A'*1024;image[10*1024:10*1024+len(PAYLOAD)]=PAYLOAD
    assert F.recover_ext_file(image,sb,inode)==b'A'*1024+PAYLOAD


def test_ext_extent_length_32768_boundary():
    sb=replace(F.parse_ext_superblock(ext_sb()),blocks_count=100000)
    raw=bytearray(ext_inode(True));struct.pack_into('<H',raw,56,0x8000)
    inode=F.parse_ext_inode(raw,sb)
    assert inode is not None and inode.extents==(F.ExtExtent(0,9,32768,False),)


@pytest.mark.parametrize('kind,name,blocks,count',[(1,'descriptor',(42,99),0),(2,'commit',(),0),(5,'revoke',(42,99),2)])
def test_jbd_big_endian_vectors(kind,name,blocks,count):
    r=F.parse_jbd2_block(jbd(kind))
    assert (r.block_type,r.sequence,r.referenced_blocks,r.revoke_count)==(name,17,blocks,count)


def test_checksums_published_and_independent_vectors():
    assert F.crc32c(b'123456789')==0xE3069283
    assert F.crc32c(bytes(range(256)))==crc_reference(bytes(range(256)))
    assert F.apfs_fletcher64(struct.pack('<I',1))==0x00000001fffffffd
    assert F.apfs_fletcher64(struct.pack('<4I',1,2,3,4))==fletcher_reference(struct.pack('<4I',1,2,3,4))


def test_apfs_nx_checkpoint_and_snapshot_vectors():
    nx=F.parse_apfs_superblock(apfs_block())
    assert (nx.object_id,nx.transaction_id,nx.block_size,nx.block_count,nx.uuid)==(7,11,4096,256,IDENT)
    m=F.parse_apfs_checkpoint_map(apfs_block(12))
    assert m.last and m.mappings==(F.ApfsCheckpointMapping(3,0,4096,88,19,23),)
    snap=F.parse_apfs_snapshot_metadata(apfs_snapshot())
    assert (snap.name,snap.create_time_ns,snap.change_time_ns,snap.superblock_object_id)==('snapshot-one',10**9,2*10**9,4)


def test_btrfs_superblock_internal_and_root_value_vectors():
    sb=F.parse_btrfs_superblock(btrfs_superblock())
    assert (sb.fsid,sb.generation,sb.root,sb.chunk_root,sb.total_bytes)==(IDENT,11,4096,8192,1048576)
    tree=F.parse_btrfs_tree_block(btrfs_tree(),physical_bytenr=4096,expected_fsid=IDENT)
    assert tree.node_pointers==(F.BtrfsNodePointer(F.BtrfsKey(256,132,7),8192,11),)
    item=F.BtrfsLeafItem(F.BtrfsKey(256,132,7),3813,btrfs_root_value())
    root=F.parse_btrfs_root_item(item)
    assert (root.generation,root.root_directory_id,root.bytenr,root.readonly,root.root_uuid)==(11,256,40960,True,IDENT)
    tree=F.BtrfsTreeBlock(IDENT,4096,11,1,0,(item,),())
    assert F.parse_btrfs_snapshot_roots(tree)==(root,)


def test_btrfs_leaf_item_relative_offset():
    tree=F.parse_btrfs_tree_block(btrfs_tree(leaf=True))
    assert tree is not None and tree.leaf_items[0].data==btrfs_root_value()


def test_vss_published_field_offsets():
    v=F.parse_vss_header(vss_header())
    assert v is not None and (v.version,v.catalog_offset,v.maximum_size,v.volume_id)==(1,16384,1048576,IDENT)


def test_declarative_snapshot_plan():
    for kind in ('ntfs-vss','apfs','btrfs'):
        plan=F.build_snapshot_plan(kind,IDENT)
        assert plan.kind==kind and plan.identifier==IDENT
        assert len(plan.steps)==4 and plan.steps[0].stage=='validate'


# Complete inventory of defined public parse_* APIs, including structured inputs.
SB=F.ExtSuperblock(1024,128,32,128,32,256,4,0x40,0,IDENT,'LAB',8,32)

def _root_parse(data):
    return F.parse_btrfs_root_item(F.BtrfsLeafItem(F.BtrfsKey(256,132,7),3813,data))


def _roots_parse(data):
    item=F.BtrfsLeafItem(F.BtrfsKey(256,132,7),3813,data)
    return F.parse_btrfs_snapshot_roots(F.BtrfsTreeBlock(IDENT,4096,11,1,0,(item,),()))


PARSE_CASES=[
    ('parse_ntfs_boot',F.parse_ntfs_boot,ntfs_boot()),
    ('parse_ntfs_record',F.parse_ntfs_record,mft_record()),
    ('parse_usn_records',F.parse_usn_records,usn_record()),
    ('parse_fat_boot',F.parse_fat_boot,fat_boot()),
    ('parse_fat_directory',F.parse_fat_directory,directory()),
    ('parse_ext_superblock',F.parse_ext_superblock,ext_sb()),
    ('parse_ext_inode',lambda b:F.parse_ext_inode(b,SB),ext_inode()),
    ('parse_jbd2_block',F.parse_jbd2_block,jbd()),
    ('parse_apfs_superblock',F.parse_apfs_superblock,apfs_block()),
    ('parse_apfs_checkpoint_map',F.parse_apfs_checkpoint_map,apfs_block(12)),
    ('parse_apfs_snapshot_metadata',F.parse_apfs_snapshot_metadata,apfs_snapshot()),
    ('parse_btrfs_superblock',F.parse_btrfs_superblock,btrfs_superblock()),
    ('parse_btrfs_tree_block',F.parse_btrfs_tree_block,btrfs_tree()),
    ('parse_btrfs_root_item',_root_parse,btrfs_root_value()),
    ('parse_btrfs_snapshot_roots',_roots_parse,btrfs_root_value()),
    ('parse_vss_header',F.parse_vss_header,vss_header()),
]


def test_parse_inventory_has_no_missing_public_entrypoint():
    names={name for name,fn in inspect.getmembers(F,inspect.isfunction)
           if fn.__module__==F.__name__ and name.startswith(('parse_','detect_','unwrap_'))}
    assert names=={name for name,_,_ in PARSE_CASES}


def corpus(valid):
    rng=random.Random(0xD15CF5)
    yield 'empty',b''
    for length in (1,2,3,4,7,8,15,16,31,32,47,48,63,64,127,128,255,256,511,512,1023,1024,4096):
        yield f'zero-{length}',bytes(length)
        yield f'ff-{length}',b'\xff'*length
        yield f'random-{length}',rng.randbytes(length)
    # Real signatures and parsed fields survive these prefixes.
    for cut in sorted({1,3,4,7,8,15,31,47,63,len(valid)//2,len(valid)-1}):
        yield f'prefix-{cut}',valid[:cut]
    for offset in sorted({0,1,3,4,7,8,15,16,31,32,47,len(valid)//2,len(valid)-1}):
        if offset<len(valid):
            changed=bytearray(valid);changed[offset]^=1 << (offset%8)
            yield f'bitflip-{offset}',bytes(changed)


@pytest.mark.parametrize('name,call,valid',PARSE_CASES,ids=[c[0] for c in PARSE_CASES])
def test_every_parser_fail_closed_byte_corpus(name,call,valid):
    # This module declares no exception type; its contract is None/empty on errors.
    # A still-valid single-bit mutation may legitimately produce a parsed value.
    for label,data in corpus(valid):
        try:
            call(data)
        except Exception as exc:
            pytest.fail(f'{name} leaked {type(exc).__name__} on {label}: {exc}')


@pytest.mark.parametrize('value',[None,False,7,'not bytes',[],{}])
def test_every_parser_fail_closed_wrong_types(value):
    for name,_,_ in PARSE_CASES:
        call=getattr(F,name)
        if name=='parse_ext_inode':
            assert call(value,SB) is None
        elif name in ('parse_usn_records','parse_fat_directory','parse_btrfs_snapshot_roots'):
            assert call(value)==()
        else:
            assert call(value) is None


@pytest.mark.parametrize('length',[0,1,2,3,4,7,8,9,16,31,64,255,512,1024])
def test_other_public_binary_helpers_fail_closed(length):
    rng=random.Random(1000+length)
    resident_attr=F.NtfsAttribute(0x80,1,'',True,0,PAYLOAD,(),len(PAYLOAD),len(PAYLOAD),len(PAYLOAD))
    entry=F.FatDirEntry('EVIDENCE.BIN','EVIDENCE.BIN',False,0x20,2,len(PAYLOAD))
    boot=F.FatBoot('FAT12',512,1,1,2,9,224,None,2880,33,2847)
    inode=F.ExtInode(0o100640,1,1,len(PAYLOAD),1,0,0,1,False,(),(9,)+(0,)*11,(),None)
    for data in (bytes(length),b'\xff'*length,rng.randbytes(length)):
        F.apply_ntfs_fixup(data,512)
        F.decode_ntfs_runlist(data)
        F.follow_fat_chain(data,2,'FAT12')
        F.apfs_fletcher64(data)
        F.crc32c(data)
        F.recover_ntfs_attribute(data,resident_attr,512)
        F.recover_fat_file(data,boot,fat12_table(),entry)
        F.recover_ext_file(data,SB,inode)


def test_public_auxiliary_argument_rejection():
    for bad in (None,True,-1,2**100,'1',[],{}):
        assert F.apply_ntfs_fixup(mft_record(),bad) is None
        assert F.decode_ntfs_runlist(b'\x11\x01\x01\0',start_vcn=bad)==()
        assert F.follow_fat_chain(fat12_table(),bad,'FAT12')==()
        assert F.recover_ntfs_attribute(b'',bad,512) is None
        assert F.parse_ext_inode(ext_inode(),bad) is None
        assert F.recover_ext_file(b'',bad,None) is None
        assert F.recover_fat_file(b'',bad,b'',None) is None
        assert F.build_snapshot_plan(bad,'snapshot') is None


def test_fat_long_name_and_deleted_short_entry():
    # Microsoft VFAT order/checksum and 5+6+2 UTF-16 fields in one LFN slot.
    short=b'LONGNA~1TXT'
    checksum=0
    for octet in short:
        checksum=((checksum>>1)|(checksum<<7))+octet
        checksum &= 255
    units=list('Long name.txt'.encode('utf-16-le'))
    assert len(units)==26  # exact 13-unit name, no terminator in this LFN slot
    lfn=bytearray(32);lfn[0]=0x41;lfn[11]=0x0f;lfn[13]=checksum
    lfn[1:11]=bytes(units[:10]);lfn[14:26]=bytes(units[10:22]);lfn[28:32]=bytes(units[22:])
    result=F.parse_fat_directory(bytes(lfn)+directory(short=short))
    assert [(x.name,x.short_name,x.first_cluster) for x in result]==[('Long name.txt','LONGNA~1.TXT',2)]
    deleted=F.parse_fat_directory(directory(short=b'\xe5VIDENCEBIN'))
    assert deleted[0].deleted and deleted[0].name=='?VIDENCE.BIN'


def test_ext_unwritten_extent_and_fast_symlink():
    data=bytearray(ext_inode(True))
    # 0x8001 encodes one unwritten block, unlike initialized 0x8000 boundary.
    struct.pack_into('<H',data,56,0x8001)
    struct.pack_into('<I',data,4,25)
    node=F.parse_ext_inode(data,SB)
    assert node.extents==(F.ExtExtent(0,9,1,True),)
    assert F.recover_ext_file(b'',SB,node)==bytes(25)
    link=bytearray(256);target=b'../evidence.bin'
    struct.pack_into('<HHI',link,0,0o120777,17,len(target))
    struct.pack_into('<H',link,26,1);link[40:40+len(target)]=target
    assert F.parse_ext_inode(link,SB).inline_data==target
