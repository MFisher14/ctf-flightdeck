"""Offline PE mapper vectors against pefile/Capstone; no emulator is instantiated.

Layout oracle: Microsoft PE/COFF specification. Hash oracles: FNV published
check value, standard CRC32 check, and independent arithmetic recurrences.
"""
import hashlib
import os
import random
import socket
import struct
import subprocess
import zlib

from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import pefile
import pytest

import pe_emu as pe


CODE = bytes.fromhex('83f80585c9740190c3')  # cmp eax,5; test ecx,ecx; je; nop; ret


@pytest.fixture(autouse=True)
def no_artifact_execution(monkeypatch):
    calls = []
    def blocked(*args, **kwargs):
        calls.append('backend/process/network')
        raise AssertionError('offline test attempted artifact execution')
    monkeypatch.setattr(pe, '_default_backend', blocked)
    for obj, names in [(os, ['system', 'popen']), (subprocess, ['Popen', 'run', 'call']),
                       (socket, ['create_connection'])]:
        for name in names:
            monkeypatch.setattr(obj, name, blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    yield
    assert calls == []


def fixture_pe(is_64=True):
    """Hand-authored PE with named+ordinal imports and one absolute relocation."""
    data = bytearray(0x800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 0xf0 if is_64 else 0xe0
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if is_64 else 0x14c, 2, 0, 0, 0,
                     optional_size, 0x22 if is_64 else 0x102)
    opt = 0x98
    struct.pack_into('<H', data, opt, 0x20b if is_64 else 0x10b)
    struct.pack_into('<III', data, opt+4, 0x200, 0x400, 0)
    struct.pack_into('<II', data, opt+16, 0x1000, 0x1000)
    base = 0x140000000 if is_64 else 0x400000
    if is_64:
        struct.pack_into('<Q', data, opt+24, base)
        struct.pack_into('<QQQQII', data, opt+72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        struct.pack_into('<II', data, opt+24, 0x2000, base)
        struct.pack_into('<IIIIII', data, opt+72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    struct.pack_into('<II', data, opt+32, 0x1000, 0x200)
    struct.pack_into('<HHHHHH', data, opt+40, 6, 0, 0, 0, 6, 0)
    struct.pack_into('<II', data, opt+56, 0x3000, 0x200)
    struct.pack_into('<H', data, opt+68, 3)
    directory = opt+(112 if is_64 else 96)
    struct.pack_into('<II', data, directory+8, 0x2000, 40)
    struct.pack_into('<II', data, directory+5*8, 0x2100, 12)
    for index, (name, vsize, rva, size, raw, flags) in enumerate([
        (b'.text', 0x200, 0x1000, 0x200, 0x200, 0x60000020),
        (b'.rdata', 0x600, 0x2000, 0x400, 0x400, 0xc0000040),
    ]):
        at = opt+optional_size+index*40
        data[at:at+8] = name.ljust(8, b'\0')
        struct.pack_into('<IIIIIIHHI', data, at+8, vsize, rva, size, raw, 0, 0, 0, 0, flags)
    data[0x200:0x200+len(CODE)] = CODE
    struct.pack_into('<IIIII', data, 0x400, 0x2040, 0, 0, 0x2080, 0x2060)
    width_code = 'Q' if is_64 else 'I'
    for at in [0x440, 0x460]:
        struct.pack_into('<'+width_code*3, data, at, 0x20a0, (1 << (63 if is_64 else 31)) | 7, 0)
    data[0x480:0x480+13] = b'KERNEL32.dll\0'
    struct.pack_into('<H', data, 0x4a0, 3)
    data[0x4a2:0x4a2+12] = b'ExitProcess\0'
    struct.pack_into('<IIHH', data, 0x500, 0x2000, 12, ((10 if is_64 else 3) << 12) | 0x200, 0)
    struct.pack_into('<'+width_code, data, 0x600, base+0x1234)
    return bytes(data)


def closed(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except (pe.PEError, pe.EmulationDenied):
        return None


@pytest.mark.parametrize('is_64', [False, True])
def test_mapping_headers_sections_imports_and_zero_fill_match_pefile(is_64):
    data = fixture_pe(is_64)
    oracle = pefile.PE(data=data)
    mapped = pe.map_pe(data)
    assert mapped.machine == oracle.FILE_HEADER.Machine
    assert mapped.is_64 is is_64
    assert mapped.preferred_base == mapped.load_base == oracle.OPTIONAL_HEADER.ImageBase
    assert mapped.entry_rva == oracle.OPTIONAL_HEADER.AddressOfEntryPoint == 0x1000
    assert mapped.entry == oracle.OPTIONAL_HEADER.ImageBase+0x1000
    assert mapped.file_sha256 == hashlib.sha256(data).hexdigest()
    assert mapped.image == oracle.get_memory_mapped_image().ljust(oracle.OPTIONAL_HEADER.SizeOfImage, b'\0')
    assert mapped.rva_bytes(0x2400, 0x200) == b'\0'*0x200
    assert [(row.name, row.virtual_address, row.raw_offset, row.raw_size) for row in mapped.sections] == [
        (row.Name.rstrip(b'\0').decode(), row.VirtualAddress, row.PointerToRawData, row.SizeOfRawData)
        for row in oracle.sections]
    oracle_imports = [(group.dll.decode().lower(), item.name.decode() if item.name else None,
                       item.ordinal, item.address-oracle.OPTIONAL_HEADER.ImageBase)
                      for group in oracle.DIRECTORY_ENTRY_IMPORT for item in group.imports]
    assert [(item.dll, item.name, item.ordinal, item.iat_rva) for item in mapped.imports] == oracle_imports
    assert [item.display for item in mapped.imports] == ['kernel32.dll!ExitProcess', 'kernel32.dll!#7']
    assert mapped.directory(1).rva == 0x2000


@pytest.mark.parametrize('is_64', [False, True])
@pytest.mark.parametrize('delta', [-0x20000, 0x30000])
def test_highlow_dir64_relocations_match_pefile(is_64, delta):
    data = fixture_pe(is_64)
    oracle = pefile.PE(data=data)
    original_base = oracle.OPTIONAL_HEADER.ImageBase
    new_base = original_base+delta
    oracle.relocate_image(new_base)
    width = 8 if is_64 else 4
    expected = int.from_bytes(oracle.get_data(0x2200, width), 'little')
    assert expected == new_base+0x1234
    mapped = pe.map_pe(data, load_base=new_base)
    assert int.from_bytes(mapped.rva_bytes(0x2200, width), 'little') == expected
    assert [(row.rva, row.kind, row.original, row.relocated) for row in mapped.relocations] == [
        (0x2200, 10 if is_64 else 3, original_base+0x1234, expected)]


@pytest.mark.parametrize('is_64', [False, True])
def test_compare_sites_and_small_caps_match_capstone(is_64):
    mapped = pe.map_pe(fixture_pe(is_64))
    decoder = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    reference = [i for i in decoder.disasm(CODE, mapped.entry) if i.mnemonic in {'cmp', 'test'}]
    found = pe.find_compare_sites(mapped)
    assert [(row.address, row.mnemonic, row.operands, row.size, row.encoding) for row in found] == [
        (i.address, i.mnemonic, i.op_str, i.size, bytes(i.bytes)) for i in reference]
    assert [row.rva for row in found] == [0x1000, 0x1003]
    assert pe.find_compare_sites(mapped) == found
    with pytest.raises(pe.EmulationDenied):
        pe.find_compare_sites(mapped, max_sites=1)
    with pytest.raises(pe.EmulationDenied):
        pe.find_compare_sites(mapped, max_bytes=16)


def reference_ror13(name):
    value = 0
    for byte in name.encode('ascii'):
        binary = format(value, '032b')
        value = (int(binary[-13:]+binary[:-13], 2)+byte) % (1 << 32)
    return value


@pytest.mark.parametrize('name', ['', 'hello', 'LoadLibraryA', 'ExitProcess', '123456789'])
def test_api_hash_independent_arithmetic_and_published_checks(name):
    raw = name.encode('ascii')
    djb = 5381
    for byte in raw:
        djb = (djb*33+byte) % (1 << 32)
    assert pe.hash_ror13(name) == reference_ror13(name)
    assert pe.hash_djb2(name) == djb
    assert pe.hash_crc32(name) == zlib.crc32(raw)
    assert pe.hash_ror13(name, uppercase=True) == reference_ror13(name.upper())
    assert pe.hash_crc32(name, uppercase=True) == zlib.crc32(raw.upper())
    assert pe.hash_fnv1a('hello') == 0x4f9f2cab
    assert pe.hash_fnv1a('') == 0x811c9dc5
    assert pe.hash_ror13('LoadLibraryA') == 0xec0e4e8e
    assert pe.hash_crc32('123456789') == 0xcbf43926


def test_api_hash_catalog_preserves_ambiguity_and_deduplicates():
    symbols = [('ONE.dll', 'hello'), ('TWO.dll', 'hello'), ('ONE.dll', 'hello')]
    index = pe.build_api_hash_index(symbols, {'fnv1a': pe.hash_fnv1a})
    assert set(index) == {0x4f9f2cab}
    assert [row.display for row in index[0x4f9f2cab]] == ['one.dll!hello', 'two.dll!hello']
    assert pe.resolve_api_hash(0x4f9f2cab, symbols, {'fnv1a': pe.hash_fnv1a}) == index[0x4f9f2cab]
    assert pe.resolve_api_hash(0, symbols, {'fnv1a': pe.hash_fnv1a}) == ()


def test_mapper_seeded_empty_truncated_mutated_and_small_caps():
    rng = random.Random(909)
    valid = fixture_pe()
    corpus = [b'', None, {}, 'MZ', b'MZ', b'\xff'*512, b'\0'*1024]
    corpus += [rng.randbytes(n) for n in [1, 32, 64, 256, 4096]]
    corpus += [valid[:n] for n in [2, 64, 128, 152, 240, 511, 1023, 2047]]
    for offset in [0, 60, 128, 134, 152, 184, 188, 208, 392, 1024, 1288]:
        mutated = bytearray(valid); mutated[offset] ^= 0x80; corpus.append(bytes(mutated))
    for data in corpus:
        closed(pe.map_pe, data)
    with pytest.raises(pe.PEError):
        pe.map_pe(valid, max_file=32)
    with pytest.raises(pe.PEError):
        pe.map_pe(valid, max_image=4096)
    for base in [1, -1, 1 << 64, float('inf'), 'bad']:
        with pytest.raises(pe.PEError):
            pe.map_pe(valid, load_base=base)


@pytest.mark.parametrize('fn', [pe.hash_ror13, pe.hash_djb2, pe.hash_fnv1a, pe.hash_crc32])
def test_hashers_fail_closed_on_malformed_names(fn):
    for value in [None, {}, b'name', '\u2603', '\ud800']:
        with pytest.raises(pe.PEError):
            fn(value)


def test_rva_bounds_and_denied_execution_gate_before_backend():
    mapped = pe.map_pe(fixture_pe())
    for rva, size in [(-1, 1), (0x3000, 1), (0, -1), (0, 1 << 64)]:
        with pytest.raises(pe.PEError):
            mapped.rva_bytes(rva, size)
    for options in [{'instruction_cap': 0}, {'memory_cap': 0}, {'wall_seconds': 0}, {'snapshot_cap': 0}]:
        with pytest.raises(pe.EmulationDenied):
            pe.SafeUnicorn(mapped, **options)
    # B-241: a PE32 image runs in the 32-bit sandbox, so its gate before the backend is the same budget
    # check, and an image whose optional-header class and machine disagree is refused outright.
    mapped32 = pe.map_pe(fixture_pe(False))
    with pytest.raises(pe.EmulationDenied):
        pe.SafeUnicorn(mapped32, instruction_cap=0)
    import dataclasses
    with pytest.raises(pe.EmulationDenied):
        pe.SafeUnicorn(dataclasses.replace(mapped32, is_64=True))
    with pytest.raises(pe.EmulationDenied):
        pe.SafeUnicorn(dataclasses.replace(mapped, machine=0x1C0))


@pytest.mark.parametrize('options', [{'max_file': None}, {'max_image': None}])
def test_mapper_invalid_cap_type_fail_closed(options):
    closed(pe.map_pe, fixture_pe(), **options)


def test_api_catalog_cap_declared_error(monkeypatch):
    monkeypatch.setattr(pe, 'MAX_IMPORTS', 1)
    closed(pe.build_api_hash_index, ['ExitProcess', 'LoadLibraryA'])


def test_api_catalog_malformed_tuple_fail_closed():
    closed(pe.build_api_hash_index, [('one-field',)])


def test_api_hash_resolution_malformed_integer_fail_closed():
    closed(pe.resolve_api_hash, 'not-an-integer', ['ExitProcess'])


def test_comparison_parser_malformed_input_fail_closed():
    closed(pe.find_compare_sites, None)


def test_rva_noninteger_fail_closed():
    mapped = pe.map_pe(fixture_pe())
    closed(mapped.rva_bytes, 1.5, 1)


def test_execution_gate_invalid_budget_type_fail_closed():
    closed(pe.SafeUnicorn, pe.map_pe(fixture_pe()), instruction_cap=None)
