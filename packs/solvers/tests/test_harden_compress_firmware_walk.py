"""CRC, JFFS2 zlib, FDT and U-Boot independent firmware fixtures.

Layouts: Linux include/uapi/linux/jffs2.h, U-Boot include/env_internal.h,
Devicetree specification chapter 5. No mounts, execution or network.
"""
import random
import struct
import zlib

import pytest

import firmware_walk as firmware


def raw_crc(data, initial=0):
    # Independent bit-at-a-time reflected IEEE recurrence (no engine CRC used).
    value = initial
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0xedb88320 if value & 1 else 0)
    return value


def jffs2(payload=b'CSCTF{jffs2_oracle}\n', endian='<'):
    name = b'config.txt'
    directory = bytearray(40)
    struct.pack_into(endian+'HHI', directory, 0, 0x1985, 0xe001, 40+len(name))
    struct.pack_into(endian+'I', directory, 8, raw_crc(directory[:8]))
    struct.pack_into(endian+'IIII', directory, 12, 1, 1, 2, 0)
    directory[28:30] = bytes([len(name), 8])
    struct.pack_into(endian+'II', directory, 32, raw_crc(directory[:32]), raw_crc(name))
    directory += name
    directory += bytes((-len(directory)) % 4)
    compressed = zlib.compress(payload)
    inode = bytearray(68)
    struct.pack_into(endian+'HHI', inode, 0, 0x1985, 0xe002, 68+len(compressed))
    struct.pack_into(endian+'I', inode, 8, raw_crc(inode[:8]))
    struct.pack_into(endian+'III', inode, 12, 2, 1, 0o100644)
    struct.pack_into(endian+'I', inode, 28, len(payload))
    struct.pack_into(endian+'III', inode, 44, 0, len(compressed), len(payload))
    inode[56] = 6
    struct.pack_into(endian+'I', inode, 60, raw_crc(compressed))
    struct.pack_into(endian+'I', inode, 64, raw_crc(inode[:64]))
    return bytes(directory + inode + compressed)


def dtb(total_override=None):
    value = b'fixture,board\0'
    structure = (struct.pack('>I', 1) + bytes(4)
                 + struct.pack('>III', 3, len(value), 0) + value + bytes((-len(value)) % 4)
                 + struct.pack('>II', 2, 9))
    strings = b'compatible\0'
    total = 56+len(structure)+len(strings)
    header = struct.pack('>10I', 0xd00dfeed, total if total_override is None else total_override,
                         56, 56+len(structure), 40, 17, 16, 0, len(strings), len(structure))
    return header + bytes(16) + structure + strings


def env():
    body = b'bootcmd=run boot\0serial=CSCTF{env}\0\0' + bytes(16)
    return struct.pack('<I', zlib.crc32(body)) + body


def test_crc_independent_recurrence_and_fixed_check_values():
    assert firmware.crc32_std(b'123456789') == 0xcbf43926
    assert firmware.jffs2_crc(b'123456789') == 0x2dfd2d88
    assert firmware.ubifs_crc(b'123456789') == 0x340bc6d9
    rng = random.Random(123)
    for data in [b'', bytes(range(256))] + [rng.randbytes(n) for n in range(40)]:
        assert firmware.crc32_std(data) == raw_crc(data, 0xffffffff) ^ 0xffffffff
        assert firmware.jffs2_crc(data) == raw_crc(data)
        assert firmware.ubifs_crc(data) == raw_crc(data, 0xffffffff)


@pytest.mark.parametrize('endian', ['<', '>'])
def test_jffs2_zlib_file_from_documented_nodes(endian):
    payload = b'CSCTF{jffs2_oracle}\n'
    out = firmware.walk({'root.jffs2': jffs2(payload, endian)})['images'][0]
    assert out['kind'] == 'jffs2'
    assert out['endian'] == ('little' if endian == '<' else 'big')
    assert out['entries'] == [{'path': '/config.txt', 'name': 'config.txt', 'type': 'file',
                               'size': len(payload), 'content': payload, 'reason': None}]


def test_jffs2_crc_rejection_and_small_content_cap(monkeypatch):
    data = jffs2(b'A'*4096)
    monkeypatch.setattr(firmware, 'MAX_FILE', 32)
    entry = firmware.walk({'image': data})['images'][0]['entries'][0]
    assert entry['content'] is None and 'MAX_FILE' in entry['reason']
    changed = bytearray(data)
    changed[-1] ^= 1
    entry = firmware.walk({'image': changed})['images'][0]['entries'][0]
    assert entry['content'] is None and entry['size'] is None


def test_dtb_property_and_uboot_crc_gate():
    out = firmware.walk({'tree.dtb': dtb(), 'uboot.env': env()})
    tree, environment = out['images']
    assert tree['kind'] == 'dtb' and tree['complete'] is True
    assert tree['nodes'] == ['/']
    assert tree['properties']['/']['compatible']['text'] == 'fixture,board'
    assert environment['vars'] == {'bootcmd': 'run boot', 'serial': 'CSCTF{env}'}
    assert environment['crc_valid'] is True
    broken = bytearray(env()); broken[0] ^= 1
    out = firmware.walk({'uboot.env': broken})['images'][0]
    assert out['crc_valid'] is False and out['vars'] == {}


def test_dtb_total_extent_is_enforced():
    out = firmware.walk({'bad.dtb': dtb(total_override=40)})['images']
    assert not any(image.get('complete') for image in out)


def test_fuzz_public_walk_returns_cleanly():
    rng = random.Random(0x46574b)
    samples = [b'', b'\0'*4096, b'\xff'*4096]
    samples += [rng.randbytes(n) for n in (1, 8, 32, 128, 4096)]
    for seed in (jffs2(), dtb(), env()):
        samples += [seed[:n] for n in range(len(seed))]
        for _ in range(32):
            changed = bytearray(seed)
            changed[rng.randrange(len(seed))] ^= 1 << rng.randrange(8)
            samples.append(bytes(changed))
    for raw in samples:
        assert isinstance(firmware.walk({'artifact': raw}), dict)


@pytest.mark.parametrize('entry', [firmware.is_squashfs, firmware.is_jffs2, firmware.is_ubi,
                                 firmware.is_ubifs, firmware.is_dtb])
def test_format_predicates_malformed_bytes(entry):
    for raw in (b'', b'\xff'*4096, b'\0'*4096, b'hsqs', b'\x85\x19'):
        assert isinstance(entry(raw), bool)


def test_walk_bad_files_container_declines():
    firmware.walk([b'bad'])
