"""Independent filesystem vectors; never use fs_walk.build_* as an oracle.

Sources:
https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header
https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification
https://github.com/torvalds/linux/blob/master/fs/squashfs/squashfs_fs.h
https://github.com/torvalds/linux/blob/master/fs/jffs2/write.c

Only test-owned structures are constructed; no mount, subprocess or filesystem execution.
"""
import random
import struct
import zlib

import pytest

import fs_walk as fs


def _resident(tag, data, name=''):
    label=name.encode('utf-16-le')
    start=(24+len(label)+7)//8*8
    length=(start+len(data)+7)//8*8
    out=bytearray(length)
    struct.pack_into('<IIBBHHH',out,0,tag,length,0,len(label)//2,24 if label else 0,0,1)
    struct.pack_into('<IH',out,16,len(data),start)
    out[24:24+len(label)]=label
    out[start:start+len(data)]=data
    return bytes(out)


def _mft_record(*, live=True, name='vector.txt', content=b'CSCTF{mft}', ads=True):
    """Hand-coded NTFS 3.1 resident FILE record, 1024 B, USA at 48, attrs at 56."""
    rawname=name.encode('utf-16-le')
    filename=bytearray(66+len(rawname))
    struct.pack_into('<Q',filename,0,(7<<48)|5)  # parent record 5, sequence 7
    filename[64:66]=bytes([len(rawname)//2,1])
    filename[66:]=rawname
    attrs=_resident(0x30,filename)+_resident(0x80,content)
    if ads:
        attrs+=_resident(0x80,b'ADS proof','hidden')
    record=bytearray(1024)
    record[:4]=b'FILE'
    struct.pack_into('<HH',record,4,48,3)
    struct.pack_into('<HHHHII',record,16,7,1,56,int(live),56+len(attrs)+4,1024)
    record[56:56+len(attrs)]=attrs
    struct.pack_into('<I',record,56+len(attrs),0xffffffff)
    # Two independent original trailer values demonstrate USA replacement.
    record[510:512]=b'\x12\x34'
    record[1022:1024]=b'\x56\x78'
    record[48:54]=b'\xcd\xab\x12\x34\x56\x78'
    record[510:512]=record[1022:1024]=b'\xcd\xab'
    return bytes(record)


def _ntfs_volume(*, sector=512, spc=4, mft_cluster=3, size_field=-10):
    # MFT byte offset = LCN * sectors/cluster * bytes/sector = 6144 by default.
    record=_mft_record()
    out=bytearray(mft_cluster*spc*sector+len(record))
    out[3:11]=b'NTFS    '
    struct.pack_into('<H',out,11,sector)
    out[13]=spc
    struct.pack_into('<Q',out,48,mft_cluster)
    struct.pack_into('<b',out,64,size_field)
    out[510:512]=b'\x55\xaa'
    out[mft_cluster*spc*sector:]=record
    return bytes(out)


def _rotate_add(data, skip=()):
    result=0
    for pos,value in enumerate(data):
        if pos not in skip:
            result=((result>>1)+(32768 if result&1 else 0)+value)&65535
    return result


def _exfat_volume(*, name='report.bin', payload=b'abcdefgh', valid_length=None,
                  sector_shift=9, cluster_shift=1, heap_sectors=8, root_cluster=3, file_cluster=5):
    """Microsoft exFAT sections 3, 6 and 7; independent entry-set checksum."""
    sector=1<<sector_shift
    cluster=sector<<cluster_shift
    names=name.encode('utf-16-le')
    names_upper=name.upper().encode('utf-16-le')  # ASCII test names use exFAT identity/ASCII uppercase mapping.
    entries=(len(names)+29)//30
    directory=bytearray(64+32*entries)
    directory[0:2]=bytes([0x85,1+entries])
    struct.pack_into('<H',directory,4,0x20)
    directory[32:36]=bytes([0xc0,3,0,len(names)//2])
    struct.pack_into('<H',directory,36,_rotate_add(names_upper))
    struct.pack_into('<Q',directory,40,len(payload) if valid_length is None else valid_length)
    struct.pack_into('<I',directory,52,file_cluster)
    struct.pack_into('<Q',directory,56,len(payload))
    for index in range(entries):
        off=64+index*32
        directory[off]=0xc1
        chunk=names[index*30:(index+1)*30]
        directory[off+2:off+2+len(chunk)]=chunk
    struct.pack_into('<H',directory,2,_rotate_add(directory,(2,3)))
    root_offset=heap_sectors*sector+(root_cluster-2)*cluster
    file_offset=heap_sectors*sector+(file_cluster-2)*cluster
    out=bytearray(file_offset+cluster)
    out[3:11]=b'EXFAT   '
    struct.pack_into('<III',out,88,heap_sectors,16,root_cluster)
    out[108:111]=bytes([sector_shift,cluster_shift,1])
    out[510:512]=b'\x55\xaa'
    out[root_offset:root_offset+len(directory)]=directory
    out[file_offset:file_offset+len(payload)]=payload
    return bytes(out)


def _squashfs(*, sparse=False, bad_zlib=False):
    """Linux squashfs_fs.h basic inode/dir structures; one regular file."""
    content=b'abc'
    size=4096 if sparse else len(content)
    filebytes=b'' if sparse else content
    inode_table=96+len(filebytes)
    listing=struct.pack('<IIIHhHH',0,0,2,32,0,2,3)+b'test'
    root=struct.pack('<HHHHII',1,0o755,0,0,0,1)+struct.pack('<IIHHI',0,2,len(listing)+3,0,1)
    regular=struct.pack('<HHHHII',2,0o644,0,0,0,2)+struct.pack('<IIII',96,0xffffffff,0,size)
    regular+=struct.pack('<I',0 if sparse else 0x1000000|len(content))
    inode_payload=root+regular
    iblock=struct.pack('<H',len(inode_payload)|0x8000)+inode_payload
    if bad_zlib:
        iblock=struct.pack('<H',len(inode_payload))+b'!'*len(inode_payload)
    dblock=struct.pack('<H',len(listing)|0x8000)+listing
    directory_table=inode_table+len(iblock)
    used=directory_table+len(dblock)
    sb=bytearray(96)
    struct.pack_into('<4sIIIIHHHHHH',sb,0,b'hsqs',2,0,4096,0,1,12,0,1,4,0)
    struct.pack_into('<8Q',sb,32,0,used,used,0xffffffffffffffff,inode_table,directory_table,used,0xffffffffffffffff)
    return bytes(sb)+filebytes+iblock+dblock


def _raw_crc(data):
    """Bitwise reflected CRC, initial register 0, no final xor (Linux crc32_le)."""
    crc=0
    for value in data:
        crc ^= value
        for _ in range(8):
            crc=(crc>>1)^(0xedb88320 if crc&1 else 0)
    return crc


def _dirent(name=b'vector', inode=2):
    node=bytearray(40+len(name))
    struct.pack_into('<HHI',node,0,0x1985,0xe001,len(node))
    struct.pack_into('<I',node,8,_raw_crc(node[:8]))
    struct.pack_into('<IIIIBB',node,12,1,1,inode,0,len(name),8)
    struct.pack_into('<II',node,32,_raw_crc(node[:32]),_raw_crc(name))
    node[40:]=name
    return bytes(node)+bytes(-len(node)%4)


def _jffs_inode(content=b'CSCTF{jffs}', inode=2):
    node=bytearray(68+len(content))
    struct.pack_into('<HHI',node,0,0x1985,0xe002,len(node))
    struct.pack_into('<I',node,8,_raw_crc(node[:8]))
    struct.pack_into('<IIIHHIIIIIIIBBH',node,12,inode,1,0o100644,0,0,len(content),0,0,0,0,len(content),len(content),0,0,0)
    # Linux jffs2/write.c: node_crc=crc32(0,ri,sizeof(*ri)-8), i.e. 60 bytes.
    struct.pack_into('<II',node,60,_raw_crc(content),_raw_crc(node[:60]))
    node[68:]=content
    return bytes(node)+bytes(-len(node)%4)


def test_ntfs_resident_ads_deleted_and_fixups():
    complete,entries=fs.ntfs(_mft_record())
    assert complete is True
    assert [(e['path'],e['size'],e['content']) for e in entries]==[
        ('\\vector.txt',10,b'CSCTF{mft}'),('\\vector.txt:hidden',9,b'ADS proof')]
    assert all(e['complete'] and e['crc_ok'] for e in entries)
    complete,deleted=fs.ntfs(_mft_record(live=False))
    assert complete is True
    assert all(e['deleted'] and not e['complete'] for e in deleted)
    damaged=bytearray(_mft_record()); damaged[510]^=1
    complete,entries=fs.ntfs(bytes(damaged))
    assert complete is False and not entries[0]['crc_ok']


@pytest.mark.parametrize('sector,spc,cluster,size_field',[(512,4,3,-10),(1024,2,4,-10),(512,2,5,1)])
def test_ntfs_volume_cluster_and_record_size(sector,spc,cluster,size_field):
    complete,entries=fs.ntfs(_ntfs_volume(sector=sector,spc=spc,mft_cluster=cluster,size_field=size_field))
    assert complete is True and entries[0]['content']==b'CSCTF{mft}'
    assert entries[0]['path']=='\\vector.txt'


@pytest.mark.parametrize('sector_shift,cluster_shift,root_cluster,file_cluster',[(9,0,2,3),(9,2,3,5),(10,1,4,7)])
def test_exfat_checksum_filename_and_cluster_math(sector_shift,cluster_shift,root_cluster,file_cluster):
    image=_exfat_volume(sector_shift=sector_shift,cluster_shift=cluster_shift,root_cluster=root_cluster,file_cluster=file_cluster)
    assert fs.is_exfat(image) is True
    complete,entries=fs.exfat(image)
    assert complete is True and len(entries)==1
    assert (entries[0]['name'],entries[0]['path'],entries[0]['size'],entries[0]['content'])==('report.bin','/report.bin',8,b'abcdefgh')
    assert entries[0]['crc_ok'] is True


def test_squashfs_linux_structures_and_file_content():
    image=_squashfs()
    assert fs.is_squashfs(image) is True
    complete,entries=fs.squashfs(image)
    assert complete is True
    assert [(e['path'],e['size'],e['content']) for e in entries]==[('/test',3,b'abc')]


def test_jffs2_dirent_linux_crc():
    assert _raw_crc(b'123456789')==0x2dfd2d88
    image=_dirent()
    assert fs.is_jffs2(image) is True
    complete,entries=fs.jffs2(image)
    assert complete is True
    assert [(e['path'],e['size'],e['content']) for e in entries]==[('/vector',None,None)]
    corrupted=bytearray(image); corrupted[40]^=1
    assert fs.jffs2(bytes(corrupted))==(False,[])


def test_dispatch_listing_signal_and_no_flag_submission():
    image=_mft_record()
    name,complete,entries=fs.walk(image)
    assert (name,complete,entries[0]['content'])==('ntfs',True,b'CSCTF{mft}')
    rows=fs.listing({'one.mft':image,'noise.bin':b'random'})
    assert len(rows)==1 and rows[0][:3]==('one.mft','ntfs',True)
    assert fs.signals([],{'one.mft':image})==0.5
    assert fs.signals([],{'noise':b'random'})==0.0
    assert fs.solve_set([{'qid':'q','question':'What is the flag?'}],{'one.mft':image})=={'q':None}


def test_bug_jffs2_inode_crc_range():
    complete,entries=fs.jffs2(_dirent()+_jffs_inode())
    assert (complete,entries[0]['size'],entries[0]['content'])==(True,11,b'CSCTF{jffs}')


def test_bug_squashfs_sparse_block():
    assert fs.squashfs(_squashfs(sparse=True))[1][0]['content']==bytes(4096)


def test_bug_squashfs_bad_zlib_is_fail_closed():
    try:
        fs.squashfs(_squashfs(bad_zlib=True))
    except (fs._Unsupported,fs._Truncated):
        pass


def test_bug_ntfs_missing_sector_tail_is_not_complete():
    assert fs.ntfs(_mft_record()[:-2])[0] is False


def test_bug_exfat_uninitialized_tail():
    assert fs.exfat(_exfat_volume(valid_length=3))[1][0]['content']==b'abc'+bytes(5)


def test_bug_exfat_utf16_name_length():
    assert fs.exfat(_exfat_volume(name='\U0001f63aA'))[1][0]['name']=='\U0001f63aA'


READERS=(fs.is_squashfs,fs.squashfs,fs.ntfs,fs.is_exfat,fs.exfat,fs.is_jffs2,fs.jffs2,fs.walk)


def _fuzz_cases():
    rng=random.Random(0xD15CF5)
    result=[('empty',b'')]
    for size in (1,2,3,4,7,11,31,47,95,127,255,511,512,1024):
        result.extend([(f'random-{size}',rng.randbytes(size)),(f'ff-{size}',b'\xff'*size)])
    for label,magic in [('squash',b'hsqs'),('jffs',b'\x85\x19\x01\xe0'),('ntfs',b'FILE')]:
        for size in (0,1,2,3,4,7,11,31,47,95,127):
            result.append((f'{label}-truncated-{size}',(magic+bytes(128))[:size]))
    for label,image in [('ntfs',_mft_record()),('exfat',_exfat_volume()),('squash',_squashfs()),('jffs',_dirent()+_jffs_inode())]:
        for size in (1,3,7,31,47,95,len(image)//2,len(image)-1):
            result.append((f'{label}-fixture-cut-{size}',image[:size]))
        for pos in (0,1,3,12,len(image)//2,len(image)-1):
            changed=bytearray(image); changed[pos]^=0x40
            result.append((f'{label}-flip-{pos}',bytes(changed)))
    return result


@pytest.mark.parametrize('label,data',_fuzz_cases(),ids=lambda x:x if isinstance(x,str) else '')
@pytest.mark.parametrize('reader',READERS,ids=lambda f:f.__name__)
def test_fuzz_public_readers_no_stdlib_exception(reader,label,data):
    try:
        reader(data)
    except (fs._Unsupported,fs._Truncated):
        pass


@pytest.mark.parametrize('label,data',_fuzz_cases(),ids=lambda x:x if isinstance(x,str) else '')
def test_fuzz_public_collection_entrypoints(label,data):
    files={'fuzz':data}
    assert isinstance(fs.listing(files),list)
    assert isinstance(fs.signals([],files),float)
    assert fs.solve_set([{'qid':'q','question':'What is the flag?'}],files)=={'q':None}


def test_exfat_surrogate_pair_spanning_name_entries():
    name='a'*14+'\U0001f63a'+'b'
    complete,entries=fs.exfat(_exfat_volume(name=name))
    assert complete and entries[0]['name']==name


@pytest.mark.parametrize('valid_length',[0,8])
def test_exfat_initialized_boundaries(valid_length):
    complete,entries=fs.exfat(_exfat_volume(valid_length=valid_length))
    assert complete and entries[0]['content']==b'abcdefgh'[:valid_length]+bytes(8-valid_length)


def test_exfat_valid_length_larger_than_data_declines():
    complete,entries=fs.exfat(_exfat_volume(valid_length=9))
    assert not complete and entries[0]['content'] is None and not entries[0]['complete']


def test_squashfs_short_final_sparse_block():
    image=bytearray(_squashfs(sparse=True))
    # Data-less image: inode metadata at 96 + 2-byte size, directory inode 32,
    # regular inode header 16, then file size at byte 12 of its body.
    struct.pack_into('<I',image,96+2+32+16+12,3)
    complete,entries=fs.squashfs(bytes(image))
    assert complete and entries[0]['content']==bytes(3)
