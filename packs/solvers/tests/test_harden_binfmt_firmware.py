"""Independent firmware vectors and deterministic fail-closed probes; TESTS ONLY.

Pinned authoritative enum oracle:
https://github.com/u-boot/u-boot/blob/v2025.01/include/image.h
https://github.com/u-boot/u-boot/blob/v2025.01/boot/image.c

Independent readers: dissect.squashfs/jffs, ubi_reader, intelhex, bincopy, fdt.
CramFS layout oracle: Linux v6.12 include/uapi/linux/cramfs_fs.h, parsed by
Dissect cstruct (not the engine's struct format). CRC uses a bit-at-a-time
reference, never the engine's CRC helpers. No fixture is executed or mounted.
"""
import io
import json
import random

import bincopy
from dissect.cstruct import cstruct
from dissect.jffs.c_jffs2 import jffs2_def
from dissect.squashfs.c_squashfs import squashfs_def
import fdt
from intelhex import IntelHex
import pytest
from ubireader.ubi.headers import ec_hdr, vid_hdr

import firmware_containers as fw


# Full real IDs in U-Boot v2025.01, excluding the *_COUNT sentinels.
OS_NAMES = (
    'invalid', 'openbsd', 'netbsd', 'freebsd', '4_4bsd', 'linux', 'svr4',
    'esix', 'solaris', 'irix', 'sco', 'dell', 'ncr', 'lynxos', 'vxworks',
    'psos', 'qnx', 'u-boot', 'rtems', 'artos', 'unity', 'integrity', 'ose',
    'plan9', 'openrtos', 'arm-trusted-firmware', 'tee', 'opensbi', 'efi', 'elf',
)
ARCH_NAMES = (
    'invalid', 'alpha', 'arm', 'x86', 'ia64', 'mips', 'mips64', 'ppc', 's390',
    'sh', 'sparc', 'sparc64', 'm68k', 'nios', 'microblaze', 'nios2', 'blackfin',
    'avr32', 'st200', 'sandbox', 'nds32', 'openrisc', 'arm64', 'arc', 'x86_64',
    'xtensa', 'riscv',
)


def crc_ref(data, initial=0xFFFFFFFF, final_xor=0xFFFFFFFF):
    crc = initial
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return (crc ^ final_xor) & 0xFFFFFFFF


def put(blob, start, value, width=4, endian='little'):
    blob[start:start + width] = value.to_bytes(width, endian)


def uimage(os_id=5, arch_id=22):
    payload = b'CSCTF{firmware_vector}'
    b = bytearray(64)
    for at, value in [(0, 0x27051956), (8, 0x12345678), (12, len(payload)),
                      (16, 0x80008000), (20, 0x80008004), (24, crc_ref(payload))]:
        put(b, at, value, endian='big')
    b[28:32] = bytes([os_id, arch_id, 2, 0])
    b[32:43] = b'ctf-fixture'
    put(b, 4, crc_ref(b), endian='big')
    return bytes(b) + payload


def squash(endian='little'):
    # A superblock-only artifact, not a mountable filesystem. Each field below
    # is independently checked by Dissect's own on-disk structure reader.
    b = bytearray(256)
    for at, value in [(0, 0x73717368), (4, 7), (8, 123456), (12, 4096), (16, 2)]:
        put(b, at, value, endian=endian)
    for at, value in [(20, 4), (22, 12), (24, 0x100), (26, 3), (28, 4), (30, 0)]:
        put(b, at, value, 2, endian)
    for at, value in [(32, 0x1234), (40, 256), (48, 112), (56, 120),
                      (64, 128), (72, 160), (80, 200), (88, 240)]:
        put(b, at, value, 8, endian)
    return bytes(b)


def jffs(endian='little'):
    # One real dirent node, whose node/name CRCs are independently calculated.
    name = b'CSCTF{dirent}'
    b = bytearray(40 + len(name))
    put(b, 0, 0x1985, 2, endian); put(b, 2, 0xE001, 2, endian)
    put(b, 4, len(b), endian=endian)
    put(b, 8, crc_ref(b[:8], 0, 0), endian=endian)
    for at, value in [(12, 1), (16, 7), (20, 42), (24, 12345)]:
        put(b, at, value, endian=endian)
    b[28:30] = bytes([len(name), 8])
    put(b, 32, crc_ref(b[:32], 0, 0), endian=endian)
    put(b, 36, crc_ref(name, 0, 0), endian=endian)
    b[40:] = name
    return bytes(b) + b'\xff' * (-len(b) % 4)


def ubi_peb(number=0):
    b = bytearray(256)
    b[:5] = b'UBI#\x01'
    put(b, 8, 17 + number, 8, 'big')
    for at, value in [(16, 64), (20, 128), (24, 0xAABBCCDD)]:
        put(b, at, value, endian='big')
    put(b, 60, crc_ref(b[:60], 0xFFFFFFFF, 0), endian='big')
    b[64:72] = b'UBI!\x01\x02\x00\x00'
    for at, value in [(72, 9), (76, number), (84, 8), (88, 2), (92, 0), (96, crc_ref(b'PAYLOAD!', 0xFFFFFFFF, 0))]:
        put(b, at, value, endian='big')
    put(b, 104, 500 + number, 8, 'big')
    put(b, 124, crc_ref(b[64:124], 0xFFFFFFFF, 0), endian='big')
    b[128:136] = b'PAYLOAD!'
    return bytes(b)


def cram(endian='little'):
    b = bytearray(96)
    for at, value in [(0, 0x28CD3D45), (4, len(b)), (8, 1), (12, 0),
                      (36, 5), (40, 2), (44, 3)]:
        put(b, at, value, endian=endian)
    b[16:32] = b'Compressed ROMFS'
    b[48:59] = b'ctf-fixture'
    put(b, 32, crc_ref(b), endian=endian)
    return bytes(b)


def fit():
    # The separate fdt implementation compiles a literal DTS fixture.
    source = '''/dts-v1/;
/ {
 images {
  kernel {
   description = "CSCTF{fit_vector}";
   type = "kernel";
   arch = "arm64";
   os = "linux";
   compression = "none";
   load = <0x8000>;
   entry = <0x8004>;
   data = [41 42 43 44];
  };
 };
 configurations {
  default = "conf-1";
  conf-1 {
   kernel = "kernel";
  };
 };
};
'''
    return fdt.parse_dts(source).to_dtb(version=17, last_comp_version=16, boot_cpuid_phys=3)


def ihex():
    reference = IntelHex()
    reference.puts(0x10010, b'CSCTF{intel_hex}')
    reference.puts(0x10040, b'END')
    reference.start_addr = {'EIP': 0x10010}
    out = io.StringIO()
    reference.write_hex_file(out)
    return out.getvalue()


def srec():
    reference = bincopy.BinFile()
    reference.header = 'CSCTF{srec_header}'
    reference.add_binary(b'CSCTF{srec_vector}', address=0x123400)
    reference.execution_start_address = 0x123400
    return reference.as_srec(address_length_bits=24)


@pytest.mark.parametrize('endian', ['little', 'big'])
def test_squashfs_vector_vs_dissect(endian):
    data = squash(endian)
    reader = cstruct(endian='<' if endian == 'little' else '>').load(squashfs_def)
    ref = reader.squashfs_super_block(data)
    report = fw.parse_squashfs(data)
    for out, field in [('inode_count','inodes'), ('mkfs_time','mkfs_time'), ('block_size','block_size'),
                       ('block_log','block_log'), ('fragment_count','fragments'), ('compression_id','compression'),
                       ('flags','flags'), ('id_count','no_ids'), ('root_inode_ref','root_inode'), ('bytes_used','bytes_used')]:
        assert report[out] == getattr(ref, field)
    assert report['endian'] == endian and report['compression'] == 'xz'
    assert report['table_offsets'] == dict(id=112, xattr=120, inode=128, directory=160, fragment=200, export=240)


@pytest.mark.parametrize('endian', ['little', 'big'])
def test_jffs2_vector_vs_dissect(endian):
    data = jffs(endian)
    reader = cstruct(endian='<' if endian == 'little' else '>').load(jffs2_def)
    ref = reader.jffs2_raw_dirent(data)
    report = fw.parse_jffs2(data)
    node = report['nodes'][0]
    assert (node['parent_inode'], node['version'], node['inode'], node['mctime']) == (ref.pino, ref.version, ref.ino, ref.mctime)
    assert node['name'] == 'CSCTF{dirent}'
    assert node['header_crc_ok'] and node['node_crc_ok'] and node['name_crc_ok']
    assert report['endian'] == endian and report['node_count'] == 1


def test_ubi_ec_vid_and_container_vs_ubireader():
    data = ubi_peb(0)
    expected_ec, expected_vid = ec_hdr(data[:64]), vid_hdr(data[64:128])
    ec, vid = fw.parse_ubi_ec_header(data), fw.parse_ubi_vid_header(data, 64)
    for out, field in [('version','version'), ('erase_count','ec'), ('vid_header_offset','vid_hdr_offset'),
                       ('data_offset','data_offset'), ('image_sequence','image_seq'), ('header_crc','hdr_crc')]:
        assert ec[out] == getattr(expected_ec, field)
    for out, field in [('version','version'), ('volume_type','vol_type'), ('volume_id','vol_id'),
                       ('logical_eraseblock','lnum'), ('data_size','data_size'), ('used_eraseblocks','used_ebs'),
                       ('data_padding','data_pad'), ('data_crc','data_crc'), ('sequence','sqnum'), ('header_crc','hdr_crc')]:
        assert vid[out] == getattr(expected_vid, field)
    assert ec['header_crc_ok'] == (not expected_ec.errors)
    assert vid['header_crc_ok'] == (not expected_vid.errors)
    report = fw.parse_ubi(data + ubi_peb(1))
    assert report['eraseblock_size'] == 256 and report['peb_count'] == 2
    assert report['headers'][1]['vid']['logical_eraseblock'] == 1


@pytest.mark.parametrize('endian', ['little', 'big'])
def test_cramfs_vector_vs_linux_cstruct(endian):
    # Linux v6.12 include/uapi/linux/cramfs_fs.h struct cramfs_super/fsid.
    reader = cstruct(endian='<' if endian == 'little' else '>').load('''
struct fsid { uint32 crc; uint32 edition; uint32 blocks; uint32 files; };
struct super { uint32 magic; uint32 size; uint32 flags; uint32 future;
char signature[16]; fsid fsid; char name[16]; char root[12]; };
''')
    data = cram(endian)
    ref, report = reader.super(data), fw.parse_cramfs(data)
    assert (report['size'], report['flags'], report['edition'], report['block_count'], report['file_count']) == (
        ref.size, ref.flags, ref.fsid.edition, ref.fsid.blocks, ref.fsid.files)
    assert report['name'] == ref.name.rstrip(b'\0').decode() == 'ctf-fixture'
    assert report['checksum'] == ref.fsid.crc and report['checksum_ok']


def test_uimage_vector_vs_published_header_and_crc():
    # Independent cstruct reader of legacy_img_hdr from U-Boot v2025.01.
    reader = cstruct(endian='>').load('''
struct legacy { uint32 magic; uint32 hcrc; uint32 time; uint32 size;
uint32 load; uint32 ep; uint32 dcrc; uint8 os; uint8 arch; uint8 type; uint8 comp; char name[32]; };
''')
    data = uimage()
    ref, result = reader.legacy(data), fw.parse_uimage(data)
    assert result['timestamp'] == ref.time == 0x12345678
    assert result['load_address'] == ref.load == 0x80008000
    assert result['entry_address'] == ref.ep == 0x80008004
    assert result['payload_size'] == ref.size == len(data) - 64
    assert result['header_crc'] == ref.hcrc
    assert result['data_crc'] == ref.dcrc
    assert result['header_crc_ok'] and result['data_crc_ok']
    assert result['payload'] == b'CSCTF{firmware_vector}'


@pytest.mark.parametrize('value,name', [pytest.param(value, name, id=f'IH_OS_{value}_{name}')
    for value, name in enumerate(OS_NAMES)])
def test_uimage_all_os_ids(value, name):
    assert fw.parse_uimage(uimage(os_id=value))['os'] == name


@pytest.mark.parametrize('value,name', [pytest.param(value, name, id=f'IH_ARCH_{value}_{name}')
    for value, name in enumerate(ARCH_NAMES)])
def test_uimage_all_arch_ids(value, name):
    assert fw.parse_uimage(uimage(arch_id=value))['arch'] == name


def test_fit_vector_vs_fdt():
    data = fit()
    reference = fdt.parse_dtb(data)
    result = fw.parse_fit(data)
    node = reference.get_node('/images/kernel')
    expected = {p.name: p for p in node.props}
    image = result['images'][0]
    for key in ['description','type','arch','os','compression']:
        assert image[key] == expected[key].data[0]
    assert image['load'] == expected['load'].data[0] == 0x8000
    assert image['entry'] == expected['entry'].data[0] == 0x8004
    # fdt's decoder represents this four-byte property as one big-endian word.
    assert expected['data'].data == [0x41424344]
    assert image['embedded_data_size'] == 4 * len(expected['data'].data) == 4
    assert result['configurations'] == ['conf-1'] and result['boot_cpuid'] == 3


def test_intel_hex_vector_vs_intelhex():
    text = ihex()
    ref = IntelHex(io.StringIO(text))
    report = fw.parse_intel_hex(text)
    assert report['entry_address'] == ref.start_addr['EIP']
    assert [(s['address'], s['data']) for s in report['segments']] == [
        (start, ref.tobinarray(start=start, end=end-1).tobytes()) for start, end in ref.segments()]
    assert report['byte_count'] == len(ref.addresses())


def test_srec_vector_vs_bincopy():
    text = srec()
    ref = bincopy.BinFile(); ref.add_srec(text)
    report = fw.parse_srec(text)
    assert report['entry_address'] == ref.execution_start_address == 0x123400
    assert report['headers'] == [ref.header]
    assert report['segments'] == [{'address': s.address, 'data': bytes(s.data)} for s in ref.segments]
    assert report['count_matches']


def test_carver_and_main_vectors(tmp_path, capsys):
    data = b'PAD' + uimage() + b'TAIL' + fit()
    result = fw.carve_firmware(data)
    # Boundaries are from independent fixture lengths, not another engine call.
    assert [(r['kind'], r['offset']) for r in result] == [('uimage',3), ('fit',3 + len(uimage()) + 4)]
    assert result[0]['report']['os'] == 'linux'
    assert result[1]['report']['images'][0]['description'] == 'CSCTF{fit_vector}'
    path = tmp_path / 'firmware.bin'; path.write_bytes(data)
    assert fw.main([str(path)]) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered[0]['report']['payload'] == b'CSCTF{firmware_vector}'.hex()


BINARY_CASES = [
    ('squash', fw.parse_squashfs, squash), ('jffs2', fw.parse_jffs2, jffs),
    ('ubi-ec', fw.parse_ubi_ec_header, ubi_peb),
    ('ubi-vid', lambda b: fw.parse_ubi_vid_header(b,0), lambda: ubi_peb()[64:128]),
    ('ubi', fw.parse_ubi, lambda: ubi_peb() + ubi_peb(1)),
    ('cramfs', fw.parse_cramfs, cram), ('uimage',fw.parse_uimage,uimage), ('fit',fw.parse_fit,fit),
    ('carve',fw.carve_firmware,uimage),
]


def corpus(valid):
    rng = random.Random(0xF17E)
    yield b''
    for n in [1,2,3,4,7,8,12,16,31,32,39,40,63,64,95,96,128]:
        yield b'\xff' * n
        yield rng.randbytes(n)
        yield valid[:n]
    # Real magic plus every missing prefix length, and bounded bit mutations.
    for n in range(min(len(valid), 140)):
        yield valid[:n]
    for _ in range(40):
        b = bytearray(valid)
        at = rng.randrange(len(b)); b[at] ^= 1 << rng.randrange(8)
        yield bytes(b)


@pytest.mark.parametrize('name,entry,builder', BINARY_CASES, ids=[x[0] for x in BINARY_CASES])
def test_binary_fail_closed_deterministic(name,entry,builder):
    for data in corpus(builder()):
        try:
            value = entry(data)
        except fw.FirmwareError:
            continue
        # Mutations can remain valid (e.g. metadata or checksum evidence changed).
        assert value is None or isinstance(value,(dict,list)), (name, data.hex(), value)


@pytest.mark.parametrize('entry,builder', [(fw.parse_intel_hex,ihex),(fw.parse_srec,srec)], ids=['intel-hex','srec'])
def test_text_fail_closed_deterministic(entry,builder):
    for data in corpus(builder().encode()):
        try:
            value = entry(data.decode('latin1'))
        except fw.FirmwareError:
            continue
        assert value is None or isinstance(value,dict)


@pytest.mark.parametrize('entry', [fw.parse_intel_hex,fw.parse_srec])
def test_text_surrogate_declared_error(entry):
    with pytest.raises(fw.FirmwareError):
        entry('\ud800')


def test_srec_non_ascii_digit_declared_error():
    with pytest.raises(fw.FirmwareError):
        fw.parse_srec('S²00')


def test_ubi_vid_invalid_type_declared_error():
    with pytest.raises(fw.FirmwareError):
        fw.parse_ubi_vid_header(None,0)


@pytest.mark.parametrize('entry', [fw.parse_ubi_ec_header,fw.parse_ubi_vid_header])
def test_ubi_bad_offset_declared_error(entry):
    with pytest.raises(fw.FirmwareError):
        entry(ubi_peb(),0.5)


@pytest.mark.parametrize('argv', [[], ['--help'], ['--not-a-real-option']])
def test_cli_argparse_exit_guard(argv):
    assert isinstance(fw.main(argv),int)


def test_fit_missing_end_token_rejected():
    # Remove terminal FDT_END and correct container offsets; bytes are fully in
    # bounds, but the DTSpec chapter 5 structure grammar still requires END.
    data = bytearray(fit())
    struct_at = int.from_bytes(data[8:12], 'big')
    strings_at = int.from_bytes(data[12:16], 'big')
    struct_size = int.from_bytes(data[36:40], 'big')
    last = struct_at + struct_size - 4
    assert data[last:last+4] == b'\0\0\0\x09'
    del data[last:last+4]
    put(data, 4, len(data), endian='big')
    put(data, 12, strings_at - 4, endian='big')
    put(data, 36, struct_size - 4, endian='big')
    with pytest.raises(Exception):  # Independent parser cannot read this tree.
        fdt.parse_dtb(bytes(data))
    with pytest.raises(fw.FirmwareError):
        fw.parse_fit(bytes(data))


@pytest.mark.parametrize('name,entry,builder', [c for c in BINARY_CASES if c[0] != 'ubi-vid'], ids=[c[0] for c in BINARY_CASES if c[0] != 'ubi-vid'])
def test_binary_wrong_input_types(name,entry,builder):
    for value in [None, 7, '', '\ud800', [], {}, bytearray(b'bad')]:
        with pytest.raises(fw.FirmwareError):
            entry(value)


def test_cli_io_error_returns_code(tmp_path):
    assert fw.main([str(tmp_path / 'missing.bin')]) == 2
    text_file = tmp_path / 'invalid.hex'
    text_file.write_bytes(b'\xff')
    assert fw.main([str(text_file), '--format', 'ihex']) == 2


def test_fit_premature_end_with_unclosed_nodes():
    data = bytearray(fit())
    struct_at = int.from_bytes(data[8:12], 'big')
    struct_size = int.from_bytes(data[36:40], 'big')
    # Replace the root's END_NODE immediately before END by a NOP: seeing END
    # alone must not declare an otherwise still-open tree complete.
    at = struct_at + struct_size - 8
    assert data[at:at + 4] == b'\0\0\0\x02'
    put(data, at, fw.FDT_NOP, endian='big')
    with pytest.raises(fw.FirmwareError):
        fw.parse_fit(bytes(data))


@pytest.mark.parametrize('offset', [None, '', float('inf'), -1, 1 << 64])
@pytest.mark.parametrize('entry', [fw.parse_ubi_ec_header, fw.parse_ubi_vid_header])
def test_ubi_invalid_offset_variants(entry, offset):
    with pytest.raises(fw.FirmwareError):
        entry(ubi_peb(), offset)
