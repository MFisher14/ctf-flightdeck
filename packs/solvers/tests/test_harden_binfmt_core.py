"""Independent binary-format vectors and deterministic malformed-input probes.

ELF/PE/Mach-O oracles: pyelftools, pefile, lief. WASM encoding: wasmtime.
Additional field-layout vectors are transcribed from Microsoft PE/COFF,
AOSP DEX header_item, JVMS 4.1, and Neko v2-3-0 vm/module.c (not binfmt).
None of the generated binary images are executed.
"""
import io
import random
import struct

import lief
import pefile
import pytest
import wasmtime
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_E_MACHINE, ENUM_E_TYPE
from jawa.cf import ClassFile
from dissect.cstruct import cstruct
import binfmt as B


def tiny_elf(bits=64, endian='<'):
    """Standalone ELF fixture: null/.text/.strtab/.symtab/.shstrtab sections."""
    wide = bits == 64
    ehsize, shsize, symsize = (64, 64, 24) if wide else (52, 40, 16)
    names = b'\0.text\0.strtab\0.symtab\0.shstrtab\0'
    strings = b'\0entry\0CSCTF{symbol}\0'
    text_at, str_at, sym_at, names_at, sht_at = 0x100, 0x110, 0x150, 0x200, 0x280
    data = bytearray(sht_at + 5 * shsize)
    data[:16] = b'\x7fELF' + bytes([2 if wide else 1, 1 if endian == '<' else 2, 1]) + bytes(9)
    struct.pack_into(endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), data, 16,
                     1, 62 if wide else 3, 1, 0, 0, sht_at, 0, ehsize, 0, 0, shsize, 5, 4)
    data[text_at:text_at + 2] = b'\x90\xc3'
    data[str_at:str_at + len(strings)] = strings
    data[names_at:names_at + len(names)] = names
    syms = [(0, 0, 0, 0, 0, 0), (1, 0x12, 0, 1, 0, 2), (7, 0x11, 0, 1, 1, 1)]
    for i, (name, info, other, shndx, value, size) in enumerate(syms):
        if wide:
            struct.pack_into(endian + 'IBBHQQ', data, sym_at + i * symsize, name, info, other, shndx, value, size)
        else:
            struct.pack_into(endian + 'IIIBBH', data, sym_at + i * symsize, name, value, size, info, other, shndx)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (1, 1, 6, 0, text_at, 2, 0, 0, 1, 0),
                (7, 3, 0, 0, str_at, len(strings), 0, 0, 1, 0),
                (15, 2, 0, 0, sym_at, 3 * symsize, 2, 1, 8 if wide else 4, symsize),
                (23, 3, 0, 0, names_at, len(names), 0, 0, 1, 0)]
    for i, section in enumerate(sections):
        struct.pack_into(endian + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII'), data, sht_at + i * shsize, *section)
    return bytes(data)


def tiny_pe(plus=False):
    """PE with .text/.idata, a real import descriptor and COFF symbols."""
    data = bytearray(0x900)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optsize = 240 if plus else 224
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664 if plus else 0x14c, 2, 0x12345678, 0x800, 3, optsize, 0x102)
    opt = 0x98
    struct.pack_into('<HBB', data, opt, 0x20b if plus else 0x10b, 14, 1)
    struct.pack_into('<I', data, opt + 16, 0x1000)
    struct.pack_into('<Q' if plus else '<I', data, opt + (24 if plus else 28), 0x140000000 if plus else 0x400000)
    struct.pack_into('<II', data, opt + 32, 0x1000, 0x200)
    struct.pack_into('<HHHHHH', data, opt + 40, 6, 1, 1, 2, 6, 1)
    struct.pack_into('<IIIHH', data, opt + 56, 0x3000, 0x200, 0, 3, 0x140)
    dirs = opt + (112 if plus else 96)
    struct.pack_into('<I', data, dirs - 4, 16)
    struct.pack_into('<II', data, dirs + 8, 0x2000, 40)
    for i, (name, va, raw, flags) in enumerate([(b'.text', 0x1000, 0x200, 0x60000020), (b'.idata', 0x2000, 0x400, 0xc0000040)]):
        at = opt + optsize + 40 * i
        struct.pack_into('<8sIIIIIIHHI', data, at, name, 0x200, va, 0x200, raw, 0, 0, 0, 0, flags)
    data[0x200:0x202] = b'\x90\xc3'
    struct.pack_into('<IIIII', data, 0x400, 0x2050, 0, 0, 0x2080, 0x2060)
    fmt = '<Q' if plus else '<I'
    struct.pack_into(fmt, data, 0x450, 0x2090)
    struct.pack_into(fmt, data, 0x460, 0x2090)
    data[0x480:0x48d] = b'KERNEL32.dll\0'
    data[0x490:0x49e] = b'\0\0ExitProcess\0'
    # Three COFF records: .text with one auxiliary record, then long symbol.
    struct.pack_into('<8sIhHBB', data, 0x800, b'.text\0\0\0', 0, 1, 0, 3, 1)
    struct.pack_into('<II', data, 0x824, 0, 4)
    struct.pack_into('<IhHBB', data, 0x82c, 1, 1, 0x20, 2, 0)
    table = b'CSCTF{coff_symbol}\0'
    struct.pack_into('<I', data, 0x836, 4 + len(table))
    data[0x83a:0x83a + len(table)] = table
    return bytes(data)


def tiny_macho():
    # Apple loader.h: mach_header_64 + LC_SEGMENT_64/section_64 + LC_UUID + LC_MAIN.
    segment = struct.pack('<II16sQQQQiiII', 0x19, 152, b'__TEXT', 0x100000000, 0x1000, 0, 0x200, 7, 5, 1, 0)
    section = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', 0x100000180, 2, 0x180, 0, 0, 0, 0x80000400, 0, 0, 0)
    uuid = struct.pack('<II', 0x1b, 24) + bytes(range(16))
    main = struct.pack('<IIQQ', 0x80000028, 24, 0x180, 0)
    commands = segment + section + uuid + main
    header = struct.pack('<IiiIIIII', 0xfeedfacf, 0x1000007, 3, 2, 3, len(commands), 0x200085, 0)
    return (header + commands).ljust(0x180, b'\0') + b'\x90\xc3'


@pytest.mark.parametrize('bits,endian', [(32, '<'), (32, '>'), (64, '<'), (64, '>')])
def test_elf_header_sections_and_all_symbol_entrypoints(bits, endian):
    data = tiny_elf(bits, endian)
    oracle = ELFFile(io.BytesIO(data))
    got = B.elf(data)
    assert got['bits'] == oracle.elfclass
    assert got['e_type'] == ENUM_E_TYPE[oracle.header['e_type']]
    assert got['e_machine'] == ENUM_E_MACHINE[oracle.header['e_machine']]
    for key in ['e_entry', 'e_phoff', 'e_shoff', 'e_flags', 'e_ehsize', 'e_shentsize', 'e_shnum', 'e_shstrndx']:
        assert got[key] == oracle.header[key]
    assert [s['name'] for s in got['sections']] == [s.name for s in oracle.iter_sections()]
    for actual, expected in zip(got['sections'], oracle.iter_sections()):
        for key, ref in [('offset', 'sh_offset'), ('size', 'sh_size'), ('flags', 'sh_flags'), ('addr', 'sh_addr'), ('link', 'sh_link')]:
            assert actual[key] == expected[ref]
    symbols = list(oracle.get_section_by_name('.symtab').iter_symbols())
    assert B.elf_symbol_names(data, got) == [s.name for s in symbols]
    kinds = {'STT_NOTYPE': 0, 'STT_OBJECT': 1, 'STT_FUNC': 2}
    assert B.elf_symtab_entries(data, got) == [(s.name, kinds[s['st_info']['type']], 0 if s['st_shndx'] == 'SHN_UNDEF' else s['st_shndx']) for s in symbols]
    assert B.elf_symbol_counts(data, got) == (len(symbols), sum(bool(s['st_name']) for s in symbols))


@pytest.mark.parametrize('plus', [False, True])
def test_pe_header_sections_imports_and_rva(plus):
    data = tiny_pe(plus)
    oracle = pefile.PE(data=data)
    got = B.pe(data)
    assert got['machine'] == oracle.FILE_HEADER.Machine
    assert got['timestamp'] == oracle.FILE_HEADER.TimeDateStamp
    for key, ref in [('magic', 'Magic'), ('entry_rva', 'AddressOfEntryPoint'), ('image_base', 'ImageBase'), ('subsystem', 'Subsystem'), ('size_of_image', 'SizeOfImage')]:
        assert got[key] == getattr(oracle.OPTIONAL_HEADER, ref)
    for actual, expected in zip(got['sections'], oracle.sections):
        assert actual['name'] == expected.Name.rstrip(b'\0').decode()
        assert actual['raw'] == expected.PointerToRawData
        assert actual['va'] == expected.VirtualAddress
        assert actual['rsize'] == expected.SizeOfRawData
    assert B.pe_imports(data, got) == [i.dll.decode() for i in oracle.DIRECTORY_ENTRY_IMPORT]
    for rva in [0x1000, 0x1001, 0x2000, 0x2080]:
        assert B.pe_offset(got['sections'], rva) == oracle.get_offset_from_rva(rva)
    # LIEF independently interprets names/classes; source fixture supplies only
    # primary-record indices because LIEF strips auxiliary records from this view.
    coff_image = lief.PE.parse(list(data))
    coff = list(coff_image.symbols)
    assert B.pe_coff_symbols(data) == [(idx, s.name, s.section_idx, int(s.storage_class)) for idx, s in zip((0, 2), coff)]


def test_macho_against_lief():
    data = tiny_macho()
    image = lief.MachO.parse(list(data))
    oracle = image.at(0)
    got = B.macho(data)
    assert got['bits'] == 64
    assert got['cputype'] == int(oracle.header.cpu_type)
    assert got['filetype'] == int(oracle.header.file_type)
    assert got['ncmds'] == oracle.header.nb_cmds
    assert got['sizeofcmds'] == oracle.header.sizeof_cmds
    assert got['flags'] == int(oracle.header.flags)
    assert got['segments'] == [s.name for s in oracle.segments]
    assert got['sections'] == [(s.segment_name, s.name) for s in oracle.sections]
    assert got['uuid'] == bytes(oracle.uuid.uuid).hex()
    assert got['entryoff'] == oracle.main_command.entrypoint


def test_fat_macho_against_lief():
    thin = tiny_macho()
    fat = struct.pack('>IIiiIII', 0xcafebabe, 1, 0x1000007, 3, 0x100, len(thin), 8).ljust(0x100, b'\0') + thin
    image = lief.MachO.parse(list(fat))
    oracle = image.at(0)
    assert B.macho_fat(fat) == [(int(oracle.header.cpu_type), oracle.header.cpu_subtype, oracle.fat_offset, len(thin))]
    assert B.macho(fat, at=0x100)['sections'] == [(s.segment_name, s.name) for s in oracle.sections]


def tiny_wasm():
    return bytes(wasmtime.wat2wasm('''(module
        (import "env" "log" (func $log (param i32)))
        (memory (export "memory") 1 2)
        (func (export "entry") (result i32) i32.const 7)
        (data (i32.const 0) "CSCTF{wasm}"))'''))


def test_wasm_and_data_segments_against_wasmtime_encoder():
    data = tiny_wasm()
    got = B.wasm(data)
    # WAT is the independent logical source; its bytes are from wasmtime's encoder.
    assert got['version'] == 1
    assert got['imports'] == [('env', 'log', 'func')]
    assert got['exports'] == [('memory', 'memory'), ('entry', 'func')]
    assert got['memory_min'] == 1
    assert got['data_segments'] == 1
    segments = B.wasm_data_segments(data, got)
    assert [data[off:off + size] for off, size in segments] == [b'CSCTF{wasm}']


@pytest.mark.parametrize('data,signed,value', [(b'\x03', False, 3), (b'\x83\x00', False, 3), (b'\xe5\x8e\x26', False, 624485), (b'\x9b\xf1\x59', True, -624485), (b'\x7f', True, -1), (b'\xff\x00', True, 127)])
def test_leb128_published_values(data, signed, value):
    # DWARF v5 section 7.6 / WebAssembly binary values: signed/unsigned LEB128.
    assert B.leb128(data, 0, signed=signed) == (value, len(data))


def test_component_against_wasmtime_component_encoder():
    data = bytes(wasmtime.wat2wasm('(component (core module))'))
    got = B.wasm_component(data)
    assert got['version'] == 13 and got['layer'] == 1
    assert got['core_modules'] == 1
    assert len(got['sections']) == 1
    sid, offset, size = got['sections'][0]
    assert sid == 1 and data[offset:offset + size] == b'\0asm\x01\0\0\0'


def tiny_dex(endian='<'):
    # AOSP header_item. Header-only metadata fixture, not executable Dalvik code.
    data = bytearray(0x70)
    data[:8] = b'dex\n035\0'
    struct.pack_into(endian + 'I', data, 8, 0x12345678)
    data[12:32] = bytes(range(20))
    struct.pack_into(endian + 'III', data, 32, 0x1234, 0x70, 0x12345678)
    struct.pack_into(endian + '12I', data, 56, 1, 0x70, 2, 0x74, 3, 0x80, 4, 0xa4, 5, 0xc4, 6, 0xec)
    return bytes(data)


def test_dex_aosp_header_layout():
    data = tiny_dex()
    got = B.dex(data)
    dex_image = lief.DEX.parse(list(data))
    ref = dex_image.header
    assert got['version'] == '035'
    for key in ('checksum', 'file_size', 'header_size', 'endian_tag'):
        assert got[key] == getattr(ref, key)
    assert got['signature'] == bytes(ref.signature).hex()
    for key, refkey in [('strings', 'strings'), ('types', 'types'), ('protos', 'prototypes'), ('fields', 'fields'), ('methods', 'methods'), ('classes', 'classes')]:
        assert got[key] == getattr(ref, refkey)[1]


def tiny_java():
    # JVMS 4.1/4.4: public abstract class Example extends java/lang/Object,
    # one abstract method test()V. No executable code.
    pool = b'\x01\x00\x07Example\x07\x00\x01' + b'\x01\x00\x10java/lang/Object\x07\x00\x03' + b'\x01\x00\x04test\x01\x00\x03()V'
    return bytes.fromhex('cafebabe000000340007') + pool + struct.pack('>HHHHHHHHHHH', 0x421, 2, 4, 0, 0, 1, 0x401, 5, 6, 0, 0)


def test_java_jvms_table_layout():
    data = tiny_java()
    oracle = ClassFile(io.BytesIO(data))
    assert B.java_class_table(data) == (oracle.access_flags.value, oracle.this.name.value, [m.name.value for m in oracle.methods])


def tiny_neko():
    # Neko v2-3-0 vm/module.c: one string global (tag3/u16 length), no
    # field names and one zero-argument opcode slot (AccNull=0 -> packed0).
    value = b'CSCTF{neko}'
    return b'NEKO' + struct.pack('<III', 1, 0, 1) + b'\x03' + struct.pack('<H', len(value)) + value + b'\0'


def test_neko_loader_layout():
    data = tiny_neko()
    # Independent Dissect schema of the published loader's header + one
    # string-global case. This is a fixture oracle, not a general Neko parser.
    reader = cstruct(endian='<').load('''struct fixture {
        char magic[4]; uint32 nglobals; uint32 nfields; uint32 codesize;
        uint8 global_type; uint16 length; char payload[length]; uint8 opcode;
    };''')
    reference = reader.fixture(data)
    assert reference.magic == b'NEKO' and reference.global_type == 3
    assert B.neko_header(data) == (reference.nglobals, reference.nfields, reference.codesize)
    got = B.neko(data)
    assert got['tables'] is True
    assert got['strings'] == [(19, reference.length)]
    assert [data[at:at + size] for at, size in got['strings']] == [reference.payload]
    assert got['names'] == []
    assert got['code_start'] == len(data) - 1 and got['code_bytes'] == 1


FIXTURES = {'elf': tiny_elf, 'pe': tiny_pe, 'macho': tiny_macho, 'wasm': tiny_wasm,
            'dex': tiny_dex, 'java_class_table': tiny_java, 'neko': tiny_neko,
            'neko_header': tiny_neko,
            'macho_fat': lambda: bytes.fromhex('cafebabe00000001') + struct.pack('>iiIII', 0x1000007, 3, 0x100, 2, 8),
            'wasm_component': lambda: bytes(wasmtime.wat2wasm('(component (core module))')),
            'pe_coff_symbols': tiny_pe}


def mutations(seed):
    rng = random.Random(0xB1F04)
    yield b''
    for size in (1, 4, 7, 15, 31, 63, 127, 255):
        yield bytes([255]) * size
        yield rng.randbytes(size)
    for end in sorted(set(range(min(len(seed), 96))) | {len(seed) // 2, len(seed) - 1}):
        yield seed[:end]
    for _ in range(32):
        data = bytearray(seed)
        at = rng.randrange(len(data))
        data[at] ^= 1 << rng.randrange(8)
        yield bytes(data)


@pytest.mark.parametrize('name', sorted(FIXTURES))
def test_public_byte_readers_fail_closed(name):
    # binfmt declares no exception type for these readers: no exception allowed.
    # A header reader may return its documented partial metadata on a cut body.
    for data in mutations(FIXTURES[name]()):
        result = getattr(B, name)(data)
        assert result is None or isinstance(result, (dict, list, tuple))


@pytest.mark.parametrize('name', ['elf_symbol_names', 'elf_symtab_entries', 'elf_symbol_counts'])
def test_elf_helpers_fail_closed(name):
    seed = tiny_elf()
    info = B.elf(seed)
    for data in mutations(seed):
        result = getattr(B, name)(data, info)
        assert result is None or isinstance(result, (list, tuple))
    assert getattr(B, name)(b'', None) is None


def test_pe_imports_and_offsets_fail_closed():
    seed = tiny_pe()
    info = B.pe(seed)
    for data in mutations(seed):
        result = B.pe_imports(data, info)
        assert result is None or isinstance(result, list)
    assert B.pe_imports(b'', None) is None
    assert B.pe_offset([], 0) is None
    for rva in (-1, 0, 1, 0x400000, 2**64, 2**100):
        assert B.pe_offset(info['sections'], rva) is None


def test_wasm_data_segments_fail_closed():
    seed = tiny_wasm()
    info = B.wasm(seed)
    for data in mutations(seed):
        result = B.wasm_data_segments(data, info)
        assert result is None or isinstance(result, list)
    assert B.wasm_data_segments(b'', None) is None


def test_leb128_fail_closed():
    for data in mutations(b'\xe5\x8e\x26'):
        for signed in [False, True]:
            try:
                result = B.leb128(data, 0, signed)
            except ValueError as exc:
                # ValueError is the explicitly documented leb128 error, but its
                # subclasses (e.g. UnicodeError) are not silently whitelisted.
                assert type(exc) is ValueError
            else:
                assert isinstance(result[0], int) and 0 < result[1] <= len(data)


@pytest.mark.parametrize('bits,endian', [(32, '<'), (32, '>'), (64, '<'), (64, '>')])
def test_bug_elf_extended_section_numbering(bits, endian):
    data = bytearray(tiny_elf(bits, endian))
    struct.pack_into(endian + 'HH', data, 60 if bits == 64 else 48, 0, 0xffff)
    struct.pack_into(endian + ('Q' if bits == 64 else 'I'), data, 0x280 + (32 if bits == 64 else 20), 5)
    struct.pack_into(endian + 'I', data, 0x280 + (40 if bits == 64 else 24), 4)
    expected = [s.name for s in ELFFile(io.BytesIO(data)).iter_sections()]
    sections = B.elf(bytes(data))['sections']
    actual = None if sections is None else [s['name'] for s in sections]
    assert actual == expected


def test_bug_java_truncated_class_attributes():
    data = tiny_java()[:-2]
    with pytest.raises(struct.error):
        ClassFile(io.BytesIO(data))
    assert B.java_class_table(data) is None


@pytest.mark.parametrize('offset', [-2, -1, 0.5, None])
def test_bug_leb128_negative_offset(offset):
    with pytest.raises(ValueError) as exc:
        B.leb128(b'\x80', offset)
    assert type(exc.value) is ValueError


def test_elf_extended_program_count_preserves_raw_header():
    data = bytearray(tiny_elf())
    struct.pack_into('<Q', data, 32, 64)  # e_phoff
    struct.pack_into('<HH', data, 54, 56, 0xffff)  # e_phentsize, PN_XNUM
    struct.pack_into('<I', data, 0x280 + 44, 1)  # section-zero sh_info
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0x100, 0x401000, 0x401000, 2, 2, 1)
    oracle = ELFFile(io.BytesIO(data))
    got = B.elf(bytes(data))
    assert got['e_phnum'] == 0xffff
    assert len(got['segments']) == oracle.num_segments() == 1
    ref = oracle.get_segment(0)
    for key, expected in [('offset', 'p_offset'), ('vaddr', 'p_vaddr'), ('filesz', 'p_filesz'), ('memsz', 'p_memsz')]:
        assert got['segments'][0][key] == ref[expected]


def test_elf_extended_count_rejects_cut_section_zero():
    data = bytearray(tiny_elf())
    struct.pack_into('<H', data, 60, 0)
    assert B.elf(bytes(data[:0x290]))['sections'] is None


def test_java_complete_and_truncated_attribute_payload():
    # JVMS allows unknown attributes. Index 5 is the Utf8 name "test".
    data = tiny_java()[:-2] + struct.pack('>HHI', 1, 5, 3) + b'abc'
    oracle = ClassFile(io.BytesIO(data))
    assert B.java_class_table(data) == (oracle.access_flags.value, oracle.this.name.value, [m.name.value for m in oracle.methods])
    assert B.java_class_table(data[:-1]) is None
    assert B.java_class_table(data + b'garbage') is None
