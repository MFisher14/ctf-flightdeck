"""Independent disk-container vector locks and bounded deterministic contract fuzz.

Oracles: QEMU QCOW2 format, VMware VMDK 1.1, Microsoft VHD/VHDX,
libyal EWF format, Linux ext4 docs and hand-calculated NTFS run mappings.
No test invokes a shell utility, mounts an image, or calls an engine encoder.
"""
import hashlib
import random
import struct
import uuid
import zlib

import pytest

import disk_images as D


# Test-owned fixture writers: offsets below are literal format fields, not engine constants.
def _qcow(payload=b'Q' * 512, *, backing=False, zero=False, compressed=False):
    image = bytearray(2048)
    image[:4] = b'QFI\xfb'
    struct.pack_into('>I', image, 4, 3 if zero else 2)
    struct.pack_into('>I', image, 20, 9)
    struct.pack_into('>Q', image, 24, 512)
    struct.pack_into('>I', image, 36, 1)
    struct.pack_into('>Q', image, 40, 512)
    if zero:
        struct.pack_into('>I', image, 100, 104)
    if backing:
        struct.pack_into('>QI', image, 8, 120, 4)
        image[120:124] = b'base'
    struct.pack_into('>Q', image, 512, 1024)
    if payload is not None:
        entry = 1 if zero else 1536
        if compressed:
            comp = zlib.compressobj(wbits=-15)
            packed = comp.compress(payload) + comp.flush()
            # Byte-granular compressed offset is deliberately odd (flag bit 0).
            entry = (1 << 62) | 1537
            image[1537:1537 + len(packed)] = packed
        else:
            image[1536:2048] = payload
        struct.pack_into('>Q', image, 1024, entry)
    return bytes(image)


def _vmdk(payload=b'V' * 512, *, compressed=False):
    image = bytearray(2048)
    image[:4] = b'KDMV'
    struct.pack_into('<IIQQ', image, 4, 1, 0x10000 if compressed else 0, 1, 1)
    struct.pack_into('<I', image, 44, 128)
    struct.pack_into('<Q', image, 56, 1)
    struct.pack_into('<I', image, 512, 2)
    struct.pack_into('<I', image, 1024, 3)
    if compressed:
        packed = zlib.compress(payload)
        struct.pack_into('<H', image, 77, 1)
        struct.pack_into('<QI', image, 1536, 0, len(packed))
        image[1548:1548 + len(packed)] = packed
    else:
        image[1536:2048] = payload
    return bytes(image)


def _vhd_footer(size, kind=2, offset=0xFFFFFFFFFFFFFFFF):
    footer = bytearray(512)
    footer[:8] = b'conectix'
    struct.pack_into('>IIQ', footer, 8, 2, 0x00010000, offset)
    struct.pack_into('>QQ', footer, 40, size, size)
    struct.pack_into('>I', footer, 60, kind)
    struct.pack_into('>I', footer, 64, (~sum(footer)) & 0xFFFFFFFF)
    return bytes(footer)


def _vhd_dynamic():
    image = bytearray(4096)
    image[:512] = _vhd_footer(1024, 3, 512)
    header = bytearray(1024)
    header[:8] = b'cxsparse'
    struct.pack_into('>QQIII', header, 8, 0xFFFFFFFFFFFFFFFF, 1536, 0x00010000, 1, 1024)
    struct.pack_into('>I', header, 36, (~sum(header)) & 0xFFFFFFFF)
    image[512:1536] = header
    struct.pack_into('>I', image, 1536, 4)  # sector 4 bitmap, sectors 5 and 6 data
    image[2048] = 0x80  # only the first of two guest sectors exists
    image[2560:3072] = b'A' * 512
    image[3072:3584] = b'S' * 512  # stale bytes MUST be masked by bitmap
    image[3584:] = _vhd_footer(1024, 3, 512)
    return bytes(image)


def _crc32c(buf):
    crc = 0xFFFFFFFF
    for byte in buf:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _vhdx():
    # 1 MiB metadata, 1 MiB BAT, 1 MiB payload after the reserved first MiB.
    mb = 1 << 20
    image = bytearray(4 * mb)
    image[:8] = b'vhdxfile'
    header = bytearray(4096)
    header[:4] = b'head'
    struct.pack_into('<Q', header, 8, 1)
    struct.pack_into('<H', header, 66, 1)
    struct.pack_into('<I', header, 4, _crc32c(header))
    image[65536:69632] = header
    region = bytearray(65536)
    region[:4] = b'regi'
    struct.pack_into('<I', region, 8, 2)
    for i, (guid, pos) in enumerate([
            ('8b7ca206-4790-4b9a-b8fe-575f050f886e', mb),
            ('2dc27766-f623-4200-9d64-115e9bfd4a08', 2 * mb)]):
        at = 16 + i * 32
        region[at:at + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into('<QII', region, at + 16, pos, mb, 1)
    struct.pack_into('<I', region, 4, _crc32c(region))
    image[196608:262144] = region
    metadata = bytearray(mb)
    metadata[:8] = b'metadata'
    struct.pack_into('<H', metadata, 10, 3)
    items = [
        ('caa16737-fa36-4d43-b3b6-33f0aa44e76b', struct.pack('<II', mb, 0)),
        ('2fa54224-cd1b-4876-b211-5dbed83bf4b8', struct.pack('<Q', 512)),
        ('8141bf1d-a96f-4709-ba47-f233a8faab5f', struct.pack('<I', 512)),
    ]
    cursor = 65536
    for i, (guid, data) in enumerate(items):
        at = 32 + i * 32
        metadata[at:at + 16] = uuid.UUID(guid).bytes_le
        struct.pack_into('<IIII', metadata, at + 16, cursor, len(data), 6, 0)
        metadata[cursor:cursor + len(data)] = data
        cursor += len(data)
    image[mb:2 * mb] = metadata
    struct.pack_into('<Q', image, 2 * mb, 3 * mb | 6)
    image[3 * mb:3 * mb + 512] = b'X' * 512
    return bytes(image)


def _ewf(payload=b'E' * 512):
    image = bytearray(b'EVF\t\r\n\xff\0' + b'\1' + struct.pack('<HH', 1, 0))
    def section(kind, body):
        pos = len(image)
        head = bytearray(76)
        head[:len(kind)] = kind.encode()
        size = 76 + len(body)
        struct.pack_into('<QQ', head, 16, pos + size, size)
        struct.pack_into('<I', head, 72, zlib.adler32(head[:72]))
        image.extend(head + body)
        return pos
    geometry = bytearray(24)
    struct.pack_into('<IIIQ', geometry, 4, 1, 1, 512, 1)
    section('volume', geometry)
    sector_offset = section('sectors', payload + struct.pack('<I', zlib.adler32(payload)))
    table = bytearray(32)
    struct.pack_into('<I', table, 0, 1)
    struct.pack_into('<Q', table, 8, sector_offset)
    struct.pack_into('<I', table, 20, zlib.adler32(table[:20]))
    struct.pack_into('<I', table, 24, 76)
    struct.pack_into('<I', table, 28, zlib.adler32(table[24:28]))
    section('table', table)
    section('done', b'')
    return bytes(image)


@pytest.fixture(scope='module')
def containers():
    return {
        'qcow2': (_qcow(), b'Q' * 512, D.unwrap_qcow2),
        'vmdk-sparse': (_vmdk(), b'V' * 512, D.unwrap_vmdk_sparse),
        'vhd': (b'F' * 512 + _vhd_footer(512), b'F' * 512, D.unwrap_vhd),
        'vhdx': (_vhdx(), b'X' * 512, D.unwrap_vhdx),
        'ewf': (_ewf(), b'E' * 512, D.unwrap_ewf),
    }


@pytest.mark.parametrize('kind', ['qcow2', 'vmdk-sparse', 'vhd', 'vhdx', 'ewf'])
def test_independent_container_vectors(kind, containers):
    image, expected, direct = containers[kind]
    assert D.detect_container(image) == kind
    assert direct(image) == expected
    wrapped = D.unwrap(image)
    assert wrapped.raw == expected
    assert wrapped.report()['raw_size'] == 512
    assert wrapped.report()['raw_sha256'] == hashlib.sha256(expected).hexdigest()


def test_qcow_compressed_odd_offset_and_backing_chain():
    payload = (b'CSCTF{compressed_cluster}' * 30)[:512]
    assert D.unwrap_qcow2(_qcow(payload, compressed=True)) == payload
    inherited = b'B' * 512
    child = _qcow(None, backing=True)
    assert D.unwrap_qcow2(child, backing=inherited) == inherited
    assert D.unwrap_qcow2_chain(child, [inherited]) == inherited
    assert D.unwrap_qcow2_chain(child, [_qcow(inherited)]) == inherited
    assert D.unwrap_qcow2(_qcow(b'Z' * 512, backing=True, zero=True), backing=inherited) == bytes(512)


def test_vmdk_compression_descriptor_and_sector_offset():
    assert D.unwrap_vmdk_sparse(_vmdk(b'C' * 512, compressed=True)) == b'C' * 512
    descriptor = b'# Disk DescriptorFile\nversion=1\nRW 1 FLAT "flat" 1\nRW 1 ZERO\nRW 1 SPARSE "sparse"\n'
    extents = {'flat': b'decoy' + bytes(507) + b'P' * 512, 'sparse': _vmdk()}
    expected = b'P' * 512 + bytes(512) + b'V' * 512
    assert D.detect_container(descriptor) == 'vmdk-descriptor'
    assert D.unwrap_vmdk_descriptor(descriptor, extents) == expected
    assert D.unwrap(descriptor, vmdk_extents=extents).raw == expected


def test_vhd_dynamic_sector_bitmap():
    assert D.unwrap_vhd(_vhd_dynamic()) == b'A' * 512 + bytes(512)


def test_ewf_segment_entrypoint_and_crc_oracle():
    assert _crc32c(b'123456789') == 0xE3069283
    assert D.unwrap_ewf_segments([_ewf()]) == b'E' * 512
    corrupt = bytearray(_ewf())
    corrupt[200] ^= 1
    with pytest.raises(D.DiskImageError):
        D.unwrap_ewf_segments([bytes(corrupt)])


def test_known_detector_signatures_and_unsupported_declines():
    assert D.detect_container(b'\x7fELF') == 'not-disk-elf'
    assert D.detect_container(b'') == 'raw-or-unknown'
    for magic in (b'EVF2\r\n\x81\0', b'LEF2\r\n\x81\0'):
        assert D.detect_container(magic) == 'ewf2'
        assert D.unwrap(magic).raw is None


def test_ntfs_runlist_signed_sparse_and_cluster_math():
    # 3 clusters at LCN5; 2 sparse; 1 at LCN3 (delta -2, relative to LCN5).
    encoded = bytes.fromhex('11 03 05 01 02 11 01 fe 00')
    expected = [
        {'vcn': 0, 'lcn': 5, 'clusters': 3, 'sparse': False},
        {'vcn': 3, 'lcn': None, 'clusters': 2, 'sparse': True},
        {'vcn': 5, 'lcn': 3, 'clusters': 1, 'sparse': False},
    ]
    assert D.parse_ntfs_data_runs(encoded) == expected
    volume = b''.join(bytes([i]) * 512 for i in range(8))
    logical = volume[2560:4096] + bytes(1024) + volume[1536:2048]
    result = D.extract_ntfs_runs(volume, expected, 512, 3000, 3072)
    assert result == {'data': logical[:3000], 'slack': logical[3000:], 'allocated': 3072}


def _ntfs_record(name='stream'):
    record = bytearray(1024)
    record[:4] = b'FILE'
    struct.pack_into('<HH', record, 4, 48, 3)
    record[48:54] = b'\x12\x34\0\0\0\0'
    record[510:512] = record[1022:1024] = b'\x12\x34'
    struct.pack_into('<H', record, 20, 56)
    namebytes = name.encode('utf-16le')
    data = b'CSCTF{resident_stream}'
    size = (24 + len(namebytes) + len(data) + 7) & ~7
    struct.pack_into('<II', record, 56, 0x80, size)
    struct.pack_into('<BBH', record, 64, 0, len(namebytes) // 2, 24)
    struct.pack_into('<IH', record, 72, len(data), 24 + len(namebytes))
    record[80:80 + len(namebytes)] = namebytes
    record[80 + len(namebytes):80 + len(namebytes) + len(data)] = data
    struct.pack_into('<I', record, 56 + size, 0xFFFFFFFF)
    struct.pack_into('<I', record, 24, 56 + size + 16)
    return bytes(record), data


def test_resident_ntfs_stream_update_sequence_and_utf16():
    record, expected = _ntfs_record('Σtream')
    result = D.ntfs_data_streams(record)
    assert len(result) == 1
    assert result[0]['name'] == 'Σtream'
    assert result[0]['data'] == expected
    assert result[0]['size'] == len(expected)


def _ext_inode():
    inode = bytearray(128)
    struct.pack_into('<H', inode, 0, 0x81A4)
    struct.pack_into('<I', inode, 4, 1025)
    struct.pack_into('<H', inode, 26, 1)
    struct.pack_into('<I', inode, 32, 0x80000)
    struct.pack_into('<HHHHI', inode, 40, 0xF30A, 2, 4, 0, 0)
    struct.pack_into('<IHHI', inode, 52, 0, 1, 0, 2)
    struct.pack_into('<IHHI', inode, 64, 1, 0x8001, 0, 3)
    return bytes(inode)


def test_ext_extent_coordinates_unwritten_and_slack():
    inode = _ext_inode()
    image = bytes(2048) + b'A' * 1024 + b'S' * 1024
    assert D.ext_extent_tree(inode) == [
        {'logical': 0, 'physical': 2, 'blocks': 1, 'unwritten': False},
        {'logical': 1, 'physical': 3, 'blocks': 1, 'unwritten': True},
    ]
    result = D.recover_ext_inode(inode, image, block_size=1024)
    assert result['data'] == b'A' * 1024 + b'\0'
    assert result['slack'] == bytes(1023)
    assert not result['deleted']


def test_ext_direct_single_indirect_block_math():
    inode = bytearray(128)
    for i in range(12):
        struct.pack_into('<I', inode, 40 + i * 4, i + 2)
    struct.pack_into('<I', inode, 88, 1)
    filesystem = bytearray(2048)
    struct.pack_into('<II', filesystem, 1024, 80, 81)
    assert D.ext_legacy_blocks(bytes(inode), bytes(filesystem), block_size=1024, wanted_blocks=14) == list(range(2, 14)) + [80, 81]


_CALLS = {
    'detect_container': D.detect_container,
    'unwrap': D.unwrap,
    'unwrap_qcow2': D.unwrap_qcow2,
    'unwrap_qcow2_chain': lambda b: D.unwrap_qcow2_chain(b, []),
    'unwrap_vmdk_sparse': D.unwrap_vmdk_sparse,
    'unwrap_vmdk_descriptor': lambda b: D.unwrap_vmdk_descriptor(b, {}),
    'unwrap_vhd': D.unwrap_vhd,
    'unwrap_vhdx': D.unwrap_vhdx,
    'unwrap_ewf': D.unwrap_ewf,
    'unwrap_ewf_segments': lambda b: D.unwrap_ewf_segments([b]),
    'parse_ntfs_data_runs': D.parse_ntfs_data_runs,
    'extract_ntfs_runs': lambda b: D.extract_ntfs_runs(b, [{'clusters':1,'lcn':0}],512,512,512),
    'ntfs_data_streams': D.ntfs_data_streams,
    'ext_extent_tree': D.ext_extent_tree,
    'ext_legacy_blocks': lambda b: D.ext_legacy_blocks(b, b'', wanted_blocks=4),
    'recover_ext_inode': lambda b: D.recover_ext_inode(b, b''),
}


def _no_leaked_exception(function, data):
    try:
        function(data)
    except D.DiskImageError:
        pass


_FUZZ_DATA = [b'', bytes(8), bytes(127), b'\xff' * 16, b'\xff' * 511,
              random.Random(404).randbytes(31), random.Random(405).randbytes(128)]
_FUZZ_CASES = []
for _name in sorted(_CALLS):
    for _index, _data in enumerate(_FUZZ_DATA):
        _marks = []
        _FUZZ_CASES.append(pytest.param(_name, _data, marks=_marks, id=f'{_name}-{_index}'))


@pytest.mark.parametrize('name,data', _FUZZ_CASES)
def test_deterministic_unstructured_fuzz(name, data):
    _no_leaked_exception(_CALLS[name], data)


_TRUNCATION_CASES = []
for _kind in ['qcow2', 'vmdk-sparse', 'vhd', 'vhdx', 'ewf']:
    for _cut in [0,1,4,7,8,9,10,11,12,13,16,31,63,64,71,72,77,103,104,127,511,512,1023,1024,-1]:
        _marks = []
        _TRUNCATION_CASES.append(pytest.param(_kind,_cut,marks=_marks,id=f'{_kind}-{_cut}'))


@pytest.mark.parametrize('kind,cut',_TRUNCATION_CASES)
def test_real_magic_truncations(kind,cut,containers):
    image, _, direct = containers[kind]
    _no_leaked_exception(direct,image[:cut])
    _no_leaked_exception(D.unwrap,image[:cut])


@pytest.mark.parametrize('kind',['qcow2','vmdk-sparse','vhd','vhdx','ewf'])
def test_bounded_bitflips(kind,containers):
    image, _, direct = containers[kind]
    # Keep geometry fixed; mutate signatures, table checksums and real payload bytes.
    for offset in [0, 1, len(image)-1, len(image)-8]:
        mutation = bytearray(image)
        mutation[offset] ^= 0x80
        _no_leaked_exception(direct, bytes(mutation))
        _no_leaked_exception(D.unwrap, bytes(mutation))


def test_bug_descriptor_invalid_utf8_exception_contract():
    _no_leaked_exception(lambda b: D.unwrap_vmdk_descriptor(b, {}), b'\xff')


def test_bug_dispatch_descriptor_invalid_utf8_exception_contract():
    _no_leaked_exception(D.unwrap, b'# Disk DescriptorFile\n\xff')


@pytest.mark.parametrize('size', [8,9,10])
@pytest.mark.parametrize('name', ['unwrap_ewf','unwrap_ewf_segments','unwrap'])
def test_bug_ewf_truncated_signature_exception_contract(name, size):
    _no_leaked_exception(_CALLS[name], (b'EVF\t\r\n\xff\0' + b'\1\1')[:size])


def test_bug_ntfs_invalid_utf16_exception_contract():
    record, _ = _ntfs_record('x')
    bad = bytearray(record)
    bad[80:82] = b'\x00\xd8'
    _no_leaked_exception(D.ntfs_data_streams, bytes(bad))


def test_bug_ext_extent_maximum_initialized_length():
    inode = bytearray(_ext_inode())
    struct.pack_into('<H', inode, 42, 1)
    struct.pack_into('<H', inode, 56, 0x8000)
    assert D.ext_extent_tree(bytes(inode)) == [
        {'logical':0, 'physical':2, 'blocks':32768, 'unwritten':False}]


def _apfs_seal(block):
    # Independent weighted-sum form of Fletcher64, over words after the checksum.
    words = struct.unpack('<' + 'I' * ((len(block)-8)//4), block[8:])
    mod = 0xFFFFFFFF
    low = sum(words) % mod
    high = sum((len(words)-i) * word for i, word in enumerate(words)) % mod
    first = (-low-high) % mod
    second = (-low-first) % mod
    struct.pack_into('<II', block, 0, first, second)
    return block


def _apfs_volume():
    volume = bytearray(5 * 4096)
    sb = bytearray(4096)
    sb[32:36] = b'NXSB'
    struct.pack_into('<IQ', sb, 36, 4096, 5)
    sb[72:88] = uuid.UUID('12345678-1234-1234-1234-123456789abc').bytes
    volume[:4096] = _apfs_seal(sb)
    def leaf(offset, subtype, key, value, fixed=False):
        node = bytearray(4096)
        struct.pack_into('<QQII', node, 8, 99, 3, 3, subtype)
        struct.pack_into('<HHI', node, 32, 6 if fixed else 2, 0, 1)
        stride = 4 if fixed else 8
        struct.pack_into('<HH', node, 40, 0, stride)
        if fixed:
            struct.pack_into('<HH', node, 56, 0, len(value))
        else:
            struct.pack_into('<HHHH', node, 56, 0, len(key), len(value), len(value))
        node[56+stride:56+stride+len(key)] = key
        node[-len(value):] = value
        volume[offset:offset+4096] = _apfs_seal(node)
    leaf(4096, 11, struct.pack('<QQ', 42, 3), struct.pack('<IIQ', 0, 512, 4), True)
    inode_value = bytearray(92)
    struct.pack_into('<QQ', inode_value, 0, 2, 42)
    struct.pack_into('<IIH', inode_value, 72, 501, 20, 0x81A4)
    struct.pack_into('<Q', inode_value, 84, 512)
    leaf(8192, 14, struct.pack('<Q', (3 << 60) | 17), inode_value)
    leaf(12288, 14, struct.pack('<QQ', (8 << 60) | 42, 0), struct.pack('<QQQ', 512, 4, 0))
    volume[16384:16896] = b'P' * 512
    return bytes(volume)


def test_apfs_public_recovery_vectors():
    volume = _apfs_volume()
    info = D.apfs_container_info(volume)
    assert info == {'block_size':4096,'block_count':5,'uuid':'12345678-1234-1234-1234-123456789abc',
                    'features':0,'readonly_compatible_features':0,'incompatible_features':0}
    mapping = {'oid':42,'xid':3,'flags':0,'size':512,'physical_block':4,'node_offset':4096}
    assert D.apfs_omap_records(volume) == [mapping]
    assert D.apfs_resolve_omap(volume,42,xid=3) == mapping
    with pytest.raises(D.DiskImageError):
        D.apfs_resolve_omap(volume,42,xid=2)
    catalog = D.apfs_catalog_records(volume)
    assert len(catalog)==1 and catalog[0]['object_id']==17 and catalog[0]['private_id']==42
    assert catalog[0]['uncompressed_size']==512 and catalog[0]['owner']==501
    extents = D.apfs_file_extent_records(volume[12288:16384])
    assert extents == [{'object_id':42,'logical':0,'length':512,'flags':0,
                        'physical_block':4,'crypto_id':0,'node_oid':99,'item':0}]
    assert D.recover_apfs_file(volume,42,512)['data'] == b'P'*512
    assert D.recover_apfs_catalog_file(volume,17)['data'] == b'P'*512


def _btrfs_volume():
    image = bytearray(128 * 1024)
    fsid = uuid.UUID('11111111-2222-3333-4444-555555555555').bytes
    sb = bytearray(4096)
    sb[32:48] = fsid
    sb[64:72] = b'_BHRfS_M'
    struct.pack_into('<Q',sb,72,9)
    struct.pack_into('<Q',sb,112,len(image))
    struct.pack_into('<III',sb,144,4096,4096,4096)
    struct.pack_into('<I',sb,0,_crc32c(sb[32:]))
    image[65536:69632] = sb
    def leaf(offset, kind, objectid, keyoffset, payload):
        node = bytearray(4096)
        node[32:48] = fsid
        struct.pack_into('<Q',node,48,offset)
        struct.pack_into('<QQI',node,80,9,5 if kind==108 else 3,1)
        # Item payloads compact backward from the end of a Btrfs leaf.
        absolute = len(node)-len(payload)
        struct.pack_into('<QBQII',node,101,objectid,kind,keyoffset,absolute-101,len(payload))
        node[absolute:] = payload
        struct.pack_into('<I',node,0,_crc32c(node[32:]))
        image[offset:offset+4096] = node
    # Inline file extent: generation, ram_bytes, compression/encryption/other, type=0.
    payload = struct.pack('<QQBBHB',9,5,0,0,0,0)+b'BTRFS'
    leaf(0,108,21,0,payload)
    chunk = bytearray(80)
    struct.pack_into('<Q',chunk,0,8192)
    struct.pack_into('<H',chunk,44,1)
    struct.pack_into('<QQ',chunk,48,1,98304)
    leaf(4096,228,256,1048576,chunk)
    return bytes(image),fsid


def test_btrfs_superblock_vector():
    volume,fsid = _btrfs_volume()
    assert D.btrfs_superblock_info(volume) == {'fsid':fsid,'total_bytes':131072,
        'sector_size':4096,'node_size':4096,'leaf_size':4096,'generation':9}


def test_bug_btrfs_chunk_item_offset():
    volume,_ = _btrfs_volume()
    assert D.btrfs_chunk_map(volume)==[(1048576,8192,98304)]


def test_bug_btrfs_extent_item_offset():
    volume,_ = _btrfs_volume()
    records=D.btrfs_extent_records(volume)
    assert len(records)==1 and records[0]['object_id']==21 and records[0]['inline']==b'BTRFS'


def test_bug_btrfs_file_recovery_relative_item_offset():
    volume,_ = _btrfs_volume()
    assert D.recover_btrfs_file(volume,21,5)['data']==b'BTRFS'


_EXTRA_CALLS = {
    'apfs_container_info':D.apfs_container_info,
    'apfs_omap_records':D.apfs_omap_records,
    'apfs_resolve_omap':lambda b:D.apfs_resolve_omap(b,42),
    'apfs_catalog_records':D.apfs_catalog_records,
    'apfs_file_extent_records':D.apfs_file_extent_records,
    'recover_apfs_file':lambda b:D.recover_apfs_file(b,42,512),
    'recover_apfs_catalog_file':lambda b:D.recover_apfs_catalog_file(b,17),
    'btrfs_superblock_info':D.btrfs_superblock_info,
    'btrfs_extent_records':D.btrfs_extent_records,
    'btrfs_chunk_map':D.btrfs_chunk_map,
    'recover_btrfs_file':lambda b:D.recover_btrfs_file(b,21,5),
}


@pytest.mark.parametrize('name',sorted(_EXTRA_CALLS))
@pytest.mark.parametrize('data',_FUZZ_DATA)
def test_additional_public_recovery_fuzz(name,data):
    _no_leaked_exception(_EXTRA_CALLS[name],data)


def test_bug_extract_ntfs_runs_missing_clusters():
    try:
        D.extract_ntfs_runs(bytes(512), [{}], 512, 1)
    except D.DiskImageError:
        pass


def test_cli_ntfs_run_vector(capsys):
    import json
    assert D.main(['ntfs-runs','11030500','--json'])==0
    assert json.loads(capsys.readouterr().out)=={
        'runs':[{'vcn':0,'lcn':5,'clusters':3,'sparse':False}]}
