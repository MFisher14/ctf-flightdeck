"""Static PE vector-locks using pefile/capstone and independent hash algorithms.

Fixtures are manually packed Microsoft PE/COFF structures, never compiled or
executed. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
FNV vectors: https://www.ietf.org/archive/id/draft-eastlake-fnv-25.html
DJB2 algorithm: http://www.cse.yorku.ca/~oz/hash.html
"""
import dataclasses
import hashlib
import random
import struct
import zlib

import capstone
import pefile
import pytest

import binfmt
import pe_emu as E
import pe_resources as R


def tiny_pe(bits=64):
    """Two platform classes, four sections, name/ordinal imports and one fixup."""
    image_base = 0x140000000 if bits == 64 else 0x400000
    raw = bytearray(0xC00)
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 0x3C, 0x80)
    raw[0x80:0x84] = b'PE\0\0'
    opt_size = 240 if bits == 64 else 224
    struct.pack_into('<HHIIIHH', raw, 0x84, 0x8664 if bits == 64 else 0x14c,
                     4, 0x12345678, 0, 0, opt_size, 0x22 if bits == 64 else 0x102)
    opt = 0x98
    struct.pack_into('<HBB', raw, opt, 0x20b if bits == 64 else 0x10b, 14, 0)
    struct.pack_into('<III', raw, opt + 4, 0x200, 0x600, 0)
    struct.pack_into('<II', raw, opt + 16, 0x1000, 0x1000)
    if bits == 64:
        struct.pack_into('<Q', raw, opt + 24, image_base)
    else:
        struct.pack_into('<II', raw, opt + 24, 0x2000, image_base)
    struct.pack_into('<II', raw, opt + 32, 0x1000, 0x200)
    struct.pack_into('<HHHHHH', raw, opt + 40, 6, 0, 1, 0, 6, 0)
    struct.pack_into('<IIIHH', raw, opt + 56, 0x5000, 0x400, 0, 3, 0x140)
    directory_offset = opt + (112 if bits == 64 else 96)
    struct.pack_into('<I', raw, directory_offset - 4, 16)
    for index, address, size in [(1, 0x2000, 40), (2, 0x3000, 0x180), (5, 0x4000, 12)]:
        struct.pack_into('<II', raw, directory_offset + index * 8, address, size)
    sections = [(b'.text', 0x1000, 0x400, 0x60000020), (b'.idata', 0x2000, 0x600, 0xc0000040),
                (b'.rsrc', 0x3000, 0x800, 0x40000040), (b'.reloc', 0x4000, 0xa00, 0x42000040)]
    for index, (name, address, offset, flags) in enumerate(sections):
        at = opt + opt_size + index * 40
        struct.pack_into('<8sIIIIIIHHI', raw, at, name, 0x200, address, 0x200, offset, 0, 0, 0, 0, flags)
    # CMP eax,42; TEST ecx,ecx; CMPSB; RET. All other code bytes are NOP.
    raw[0x400:0x600] = b'\x90' * 0x200
    raw[0x400:0x408] = bytes.fromhex('83f82a85c9a6c390')
    width = 'Q' if bits == 64 else 'I'
    struct.pack_into('<' + width, raw, 0x480, image_base + 0x1123)
    struct.pack_into('<IIIII', raw, 0x600, 0x2040, 0, 0, 0x2080, 0x2060)
    for offset in (0x640, 0x660):
        struct.pack_into('<' + width * 3, raw, offset, 0x20a0, (1 << (bits - 1)) | 7, 0)
    raw[0x680:0x68d] = b'KERNEL32.dll\0'
    struct.pack_into('<H', raw, 0x6a0, 19)
    raw[0x6a2:0x6ae] = b'ExitProcess\0'
    # Resource root(type10) -> named resource -> lang1033 -> data entry.
    for offset, named, ids in [(0x800, 0, 1), (0x818, 1, 0), (0x830, 0, 1)]:
        struct.pack_into('<IIHHHH', raw, offset, 0, 0, 0, 0, named, ids)
    struct.pack_into('<II', raw, 0x810, 10, 0x80000018)
    struct.pack_into('<II', raw, 0x828, 0x800000a0, 0x80000030)
    struct.pack_into('<II', raw, 0x840, 1033, 0x48)
    payload = b'CSCTF{pe_resource_vector}'
    struct.pack_into('<IIII', raw, 0x848, 0x3100, len(payload), 65001, 0)
    name = 'Evidence'.encode('utf-16-le')
    struct.pack_into('<H', raw, 0x8a0, len(name) // 2)
    raw[0x8a2:0x8a2 + len(name)] = name
    raw[0x900:0x900 + len(payload)] = payload
    # One DIR64/HIGHLOW relocation, plus ABSOLUTE padding.
    struct.pack_into('<IIHH', raw, 0xa00, 0x1000, 12, ((10 if bits == 64 else 3) << 12) | 0x80, 0)
    return bytes(raw)


@pytest.mark.parametrize('bits', [32, 64])
def test_map_pe_header_sections_imports_against_pefile(bits):
    data = tiny_pe(bits)
    oracle = pefile.PE(data=data)
    result = E.map_pe(data)
    assert result.machine == oracle.FILE_HEADER.Machine
    assert result.preferred_base == oracle.OPTIONAL_HEADER.ImageBase
    assert result.entry == oracle.OPTIONAL_HEADER.ImageBase + oracle.OPTIONAL_HEADER.AddressOfEntryPoint
    assert result.size_of_headers == oracle.OPTIONAL_HEADER.SizeOfHeaders
    assert len(result.image) == oracle.OPTIONAL_HEADER.SizeOfImage
    assert result.file_sha256 == hashlib.sha256(data).hexdigest()
    assert result.image_sha256 == hashlib.sha256(result.image).hexdigest()
    for got, want in zip(result.sections, oracle.sections):
        assert (got.name, got.virtual_address, got.virtual_size, got.raw_offset, got.raw_size, got.characteristics) == (
            want.Name.rstrip(b'\0').decode(), want.VirtualAddress, want.Misc_VirtualSize,
            want.PointerToRawData, want.SizeOfRawData, want.Characteristics)
        assert got.executable == bool(want.Characteristics & 0x20000000)
        assert got.writable == bool(want.Characteristics & 0x80000000)
        assert result.rva_bytes(got.virtual_address, got.raw_size) == want.get_data()
    for index, directory in enumerate(oracle.OPTIONAL_HEADER.DATA_DIRECTORY):
        assert dataclasses.astuple(result.directory(index)) == (directory.VirtualAddress, directory.Size)
    assert dataclasses.astuple(result.directory(99)) == (0, 0)
    imports = [(row.dll.decode().lower(), symbol.name.decode() if symbol.name else None,
                symbol.ordinal, symbol.address - oracle.OPTIONAL_HEADER.ImageBase)
               for row in oracle.DIRECTORY_ENTRY_IMPORT for symbol in row.imports]
    assert [(s.dll, s.name, s.ordinal, s.iat_rva) for s in result.imports] == imports
    assert [s.display for s in result.imports] == ['kernel32.dll!ExitProcess', 'kernel32.dll!#7']


@pytest.mark.parametrize('bits', [32, 64])
def test_relocations_against_pefile(bits):
    data = tiny_pe(bits)
    oracle = pefile.PE(data=data)
    target = oracle.OPTIONAL_HEADER.ImageBase + 0x20000
    result = E.map_pe(data, load_base=target)
    oracle.relocate_image(target)
    reference = oracle.get_memory_mapped_image()
    count = bits // 8
    assert result.rva_bytes(0x1080, count) == reference[0x1080:0x1080 + count]
    assert [(r.rva, r.kind) for r in result.relocations] == [
        (r.rva, r.type) for block in oracle.DIRECTORY_ENTRY_BASERELOC for r in block.entries if r.type]
    assert result.relocations[0].relocated == target + 0x1123


@pytest.mark.parametrize('bits', [32, 64])
@pytest.mark.parametrize('explicit_metadata', [False, True])
def test_resource_tree_against_pefile(bits, explicit_metadata):
    data = tiny_pe(bits)
    oracle = pefile.PE(data=data)
    result = R.walk(data, binfmt.pe(data)) if explicit_metadata else R.walk(data)
    assert result['types'] == [{'type': 'RT_RCDATA', 'type_id': oracle.DIRECTORY_ENTRY_RESOURCE.entries[0].id}]
    names = oracle.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries
    leaf = names[0].directory.entries[0]
    actual = result['leaves'][0]
    assert actual['name'] == str(names[0].name) == 'Evidence'
    assert actual['lang'] == leaf.id == 1033
    assert actual['rva'] == leaf.data.struct.OffsetToData
    assert actual['offset'] == oracle.get_offset_from_rva(leaf.data.struct.OffsetToData)
    assert actual['size'] == leaf.data.struct.Size
    assert actual['hcfg'] is False
    assert data[actual['offset']:actual['offset'] + actual['size']] == b'CSCTF{pe_resource_vector}'


@pytest.mark.parametrize('bits', [32, 64])
def test_compare_sites_against_capstone(bits):
    mapped = E.map_pe(tiny_pe(bits))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
    reference = []
    for s in mapped.sections:
        if s.executable:
            code = mapped.rva_bytes(s.virtual_address, s.mapped_size)
            for ins in decoder.disasm(code, mapped.load_base + s.virtual_address):
                if ins.mnemonic in ('cmp', 'test', 'cmpsb', 'cmpsw', 'cmpsd', 'cmpsq'):
                    reference.append((ins.address, ins.mnemonic, ins.op_str, bytes(ins.bytes)))
    assert [(s.address, s.mnemonic, s.operands, s.encoding) for s in E.find_compare_sites(mapped)] == reference
    assert [s.mnemonic for s in E.find_compare_sites(mapped)][:3] == ['cmp', 'test', 'cmpsb']
    assert E.find_compare_sites(mapped, max_sites=0) == ()
    with pytest.raises(E.EmulationDenied):
        E.find_compare_sites(mapped, max_bytes=1)


def _ror13_reference(name):
    # Independent bit-string rotation, rather than the engine's integer shifts.
    value = 0
    for byte in name.encode('ascii'):
        binary = format(value, '032b')
        value = (int(binary[-13:] + binary[:-13], 2) + byte) % (1 << 32)
    return value


def _independent_hashes(name):
    raw = name.encode('ascii')
    djb = (5381 * pow(33, len(raw), 1 << 32) + sum(x * pow(33, len(raw) - i - 1, 1 << 32)
                                                       for i, x in enumerate(raw))) % (1 << 32)
    # FNV-1a published vectors for two inputs; arithmetic reference for APIs.
    fnv = 2166136261
    for c in raw:
        fnv = ((fnv ^ c) * 16777619) % 4294967296
    return {'ror13': _ror13_reference(name), 'djb2': djb, 'fnv1a': fnv, 'crc32': zlib.crc32(raw)}


@pytest.mark.parametrize('name', ['', 'hello', 'LoadLibraryA', 'ExitProcess', 'GetProcAddress'])
def test_hash_entrypoints_and_catalog_against_independent_algorithms(name):
    refs = _independent_hashes(name)
    upper_refs = _independent_hashes(name.upper())
    for label, value in refs.items():
        assert getattr(E, 'hash_' + label)(name) == value
        assert getattr(E, 'hash_' + label)(name, uppercase=True) == upper_refs[label]
    if name == 'hello':
        assert E.hash_fnv1a(name) == 0x4f9f2cab
    if not name:
        assert E.hash_fnv1a(name) == 0x811c9dc5
        assert E.build_api_hash_index(['']) == {}
        return
    # Only lower-case algorithms to make exact collision membership explicit.
    algorithms = {key: E.HASHERS[key] for key in refs}
    index = E.build_api_hash_index([('KERNEL32.DLL', name)], algorithms)
    for algorithm, value in refs.items():
        matches = [r for r in index[value] if r.algorithm == algorithm]
        assert [(r.dll, r.name, r.value) for r in matches] == [('kernel32.dll', name, value)]
        resolved = E.resolve_api_hash(value, [('KERNEL32.DLL', name)], algorithms)
        assert matches[0] in resolved
        assert matches[0].display == 'kernel32.dll!' + name


def malformed_cases():
    rng = random.Random(0x5045)
    cases = [('empty', b''), ('ff-2048', b'\xff' * 2048)]
    cases += [(f'random-{n}', rng.randbytes(n)) for n in [1, 16, 64, 128, 512, 2048]]
    source = tiny_pe()
    cases += [(f'truncated-{n}', source[:n]) for n in [2, 63, 0x80, 0x84, 0x98, 0x120, 0x188, 0x400, 0x601, 0xbff]]
    # Every section/directory and representative raw bytes are covered.
    for at in [0, 1, 0x3c, 0x84, 0x86, 0x94, 0x98, 0xc0, 0xd0, 0xf4, 0x110, 0x188, 0x19c,
               0x220, 0x400, 0x600, 0x610, 0x640, 0x680, 0x6a2, 0x800, 0x810, 0x828, 0x840, 0x848, 0xa00]:
        raw = bytearray(source)
        raw[at] ^= 0xff
        cases.append((f'flipped-{at:x}', bytes(raw)))
    return cases


CASES = malformed_cases()


@pytest.mark.parametrize('name,data', CASES, ids=[n for n, _ in CASES])
def test_map_and_compare_fail_closed_fuzz(name, data):
    try:
        result = E.map_pe(data)
    except E.PEError:
        return
    assert isinstance(result, E.MappedPE)
    try:
        sites = E.find_compare_sites(result)
    except E.EmulationDenied:
        return
    assert isinstance(sites, tuple)


@pytest.mark.parametrize('name,data', CASES, ids=[n for n, _ in CASES])
def test_resources_fail_closed_fuzz(name, data):
    result = R.walk(data)
    assert result is None or isinstance(result, dict)


@pytest.mark.parametrize('value', [b'', b'\xff' * 128, None, 1])
def test_safe_unicorn_rejects_unmapped_objects_without_execution(value):
    with pytest.raises(E.EmulationDenied):
        E.SafeUnicorn(value)


def test_mapped_rva_bounds_fail_closed():
    mapped = E.map_pe(tiny_pe())
    for rva, size in [(-1, 1), (0x5000, 1), (0, -1), (0x1000, 1 << 40)]:
        with pytest.raises(E.PEError):
            mapped.rva_bytes(rva, size)


def test_resources_reject_out_of_file_leaf():
    data = bytearray(tiny_pe())
    struct.pack_into('<I', data, 0x84c, 0x100000)
    # Resource payload begins at file 0x900: 0xC00-byte file has only 0x300
    # bytes left, whereas this IMAGE_RESOURCE_DATA_ENTRY declares 1 MiB.
    assert R.walk(bytes(data)) is None


def test_resources_reject_leaf_crossing_raw_section():
    data = bytearray(tiny_pe())
    # The next section is present on disk, but is not resource payload storage.
    struct.pack_into('<I', data, 0x84c, 0x101)
    assert R.walk(bytes(data)) is None


@pytest.mark.parametrize('base', [float('inf'), float('nan'), 'not-an-address'], ids=['infinity', 'nan', 'text'])
def test_map_pe_invalid_load_base_error_contract(base):
    with pytest.raises(E.PEError):
        E.map_pe(tiny_pe(), load_base=base)


@pytest.mark.parametrize('hasher', [E.hash_ror13, E.hash_djb2, E.hash_fnv1a, E.hash_crc32], ids=lambda f: f.__name__)
def test_hash_nonascii_error_contract(hasher):
    with pytest.raises(E.PEError):
        hasher('\u00e9')


@pytest.mark.parametrize('hasher', [E.hash_ror13, E.hash_djb2, E.hash_fnv1a, E.hash_crc32], ids=lambda f: f.__name__)
def test_hash_invalid_name_type_error_contract(hasher):
    for name in (None, 7, b'ExitProcess'):
        with pytest.raises(E.PEError):
            hasher(name)


@pytest.mark.parametrize('code', [b'', b'\xff' * 128, b'\x0f', b'\x48\x83', random.Random(73).randbytes(128)])
def test_compare_disassembler_malformed_code_clean(code):
    mapped = E.map_pe(tiny_pe())
    # Preserve the parser contract (MappedPE input) but replace its executable
    # region with deterministic empty/truncated/ff/random instruction bytes.
    image = mapped.image[:0x1000] + code
    section = dataclasses.replace(mapped.sections[0], virtual_size=len(code), raw_size=len(code))
    varied = dataclasses.replace(mapped, image=image, sections=(section,))
    try:
        result = E.find_compare_sites(varied)
    except E.EmulationDenied:
        return
    assert isinstance(result, tuple)


@pytest.mark.parametrize('name,reference64', [
    ('Hello World', 13827776004929097857),
    ('Hello World!', 13594750393630990530),
    ('Hello world', 13827776004967047329),
    ('Hello world!', 13594750394883323106),
])
def test_djb2_published_reference_implementation_vectors(name, reference64):
    # TheAlgorithms/C's test_djb2() fixed constants, projected to this API's
    # explicit uint32 width (same polynomial modulo 2**32).
    # https://github.com/TheAlgorithms/C/blob/master/hash/hash_djb2.c
    assert E.hash_djb2(name) == reference64 & 0xffffffff


def test_published_ror13_api_hash_and_catalog_vector():
    # Actual encoded LoadLibraryA lookup constant in Metasploit win32_bind,
    # documented with disassembly on pp. 7/14 of this published review:
    # https://www.exploit-db.com/docs/english/38647-win32_bind-shellcode-review.pdf
    expected = 0xec0e4e8e
    assert E.hash_ror13('LoadLibraryA') == expected
    index = E.build_api_hash_index([('kernel32.dll', 'LoadLibraryA')])
    assert ('ror13', 'kernel32.dll', 'LoadLibraryA', expected) in [dataclasses.astuple(row) for row in index[expected]]
    rows = E.resolve_api_hash(expected, [('kernel32.dll', 'LoadLibraryA')])
    assert ('ror13', 'kernel32.dll', 'LoadLibraryA', expected) in [dataclasses.astuple(row) for row in rows]
