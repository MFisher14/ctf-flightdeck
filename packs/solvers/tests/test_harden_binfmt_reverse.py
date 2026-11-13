"""Independent locks for reverse_formats. All bytes are synthetic and never run.

Oracles: wasmtime WAT encoder/static module metadata; dnfile's CLR metadata
reader; Capstone BPF disassembler; Python AST/stdlib hashing for source-only
plans; hand-derived declarative VM semantics (not an engine encoder).
References: webassembly.github.io/spec/core/binary/modules.html,
docs.kernel.org/bpf/standardization/instruction-set.html, ECMA-335 II.24.2.
"""
import ast
import hashlib
import json
import random
import struct

import capstone
import dnfile
import pytest
import wasmtime

import reverse_formats as R


def wasm_fixture():
    return bytes(wasmtime.wat2wasm('''(module
      (import "host" "read" (func $read (param i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "plus") (param i32) (result i32)
        local.get 0 i32.const 7 i32.add))'''))


def clr_fixture():
    # ECMA-335 metadata root + two disjoint streams, with a legal empty tables
    # header. Stream offsets are 64 and 88, calculated from the record widths.
    root = b'BSJB' + struct.pack('<HHII', 1, 1, 0, 12)
    root += b'v4.0.30319\0\0' + struct.pack('<HH', 0, 2)
    root += struct.pack('<II4s', 64, 24, b'#~\0\0')
    root += struct.pack('<II12s', 88, 8, b'#Strings\0\0\0\0')
    return root + struct.pack('<IBBBBQQ', 0, 2, 0, 0, 1, 0, 0) + b'\0hello\0\0'


class FlatMetadataImage:
    """Only byte access adapter for dnfile; no metadata parsing in this oracle."""
    def __init__(self, data):
        self.data = data

    def get_data(self, rva, size):
        return self.data[rva:rva + size]

    def get_offset_from_rva(self, rva):
        return rva

    def get_string_at_rva(self, rva):
        return self.data[rva:].split(b'\0', 1)[0]

    def add_warning(self, message):
        raise AssertionError(message)


def ebpf_fixture():
    # r1=0x1122334455667788; r2=-7; r2+=3; if r2==-4 skip helper; exit.
    return b''.join([
        struct.pack('<BBhi', 0x18, 1, 0, 0x55667788),
        struct.pack('<BBhi', 0, 0, 0, 0x11223344),
        struct.pack('<BBhi', 0xb7, 2, 0, -7),
        struct.pack('<BBhi', 0x07, 2, 0, 3),
        struct.pack('<BBhi', 0x15, 2, 1, -4),
        struct.pack('<BBhi', 0x85, 0, 0, 1),
        struct.pack('<BBhi', 0x95, 0, 0, 0),
    ])


def test_wasm_import_export_against_wasmtime():
    blob = wasm_fixture()
    engine = wasmtime.Engine()
    module = wasmtime.Module(engine, blob)  # static compilation only; no instance/call
    result = R.parse_wasm(blob)
    assert [(v['module'], v['name']) for v in result['imports']] == [(v.module, v.name) for v in module.imports]
    assert [v['name'] for v in result['exports']] == [v.name for v in module.exports]
    assert [(v['name'], v['kind'], v['index']) for v in result['exports']] == [('memory', 2, 0), ('plus', 0, 1)]
    assert result['version'] == 1
    assert len(result['code_bodies']) == 1
    assert blob[result['code_bodies'][0]['offset']:][:6] == bytes.fromhex('200041076a0b')


def test_clr_streams_against_dnfile():
    blob = clr_fixture()
    oracle = dnfile.ClrMetaData(FlatMetadataImage(blob), 0, len(blob))
    result = R.parse_dotnet_metadata(blob)
    assert result['major'] == oracle.struct.MajorVersion
    assert result['minor'] == oracle.struct.MinorVersion
    assert result['runtime_version'] == oracle.struct.Version.rstrip(b'\0').decode()
    expected = [(s.struct.Name.decode(), s.struct.Offset, s.struct.Size) for s in oracle.streams_list]
    assert [(s['name'], s['offset'], s['size']) for s in result['streams']] == expected
    assert result['root_offset'] == 0


def test_ebpf_operands_and_boundaries_against_capstone():
    blob = ebpf_fixture()
    dis = capstone.Cs(capstone.CS_ARCH_BPF, capstone.CS_MODE_BPF_EXTENDED | capstone.CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    instructions = list(dis.disasm(blob, 0))
    result = R.parse_ebpf(blob)
    assert len(instructions) == 6
    assert [i.address // 8 for i in instructions] == [i['index'] for i in result['instructions']]
    assert instructions[0].operands[1].imm == result['instructions'][0]['immediate64'] == 0x1122334455667788
    assert instructions[1].operands[1].imm & 0xffffffff == result['instructions'][1]['immediate'] & 0xffffffff
    assert result['jump_targets'] == [{'from': 4, 'to': 6}]
    assert result['helper_calls'] == [{'index': 5, 'id': 1, 'name': 'map_lookup_elem'}]
    assert result['exit_indices'] == [6]
    assert instructions[-1].mnemonic == 'exit'


def test_language_dispatch_matches_independent_wasm_and_clr_formats():
    for data, container, lang, key in [(wasm_fixture(), 'wasm', 'WebAssembly', 'wasm'),
                                       (clr_fixture(), None, '.NET metadata', 'dotnet_metadata_candidate')]:
        result = R.analyze_languages(data)
        assert result['container'] == container
        assert result['languages'][0]['language'] == lang
        assert result['structured'][key]['verified_structure'] is True
    assert R.packer_evidence(wasm_fixture()) == []
    assert R.packer_evidence(b'ordinary text UPX! UPX0 UPX1') == []


def test_declarative_vm_independent_byte_layout():
    # Manually decode: offset0 push 0x1234; offset3 jump signed(-5) ->0;
    # offset5 halt. Neither the fixture nor expected IR uses an engine encoder.
    spec = {'bytecode_hex': '01341202fb03', 'branch_mode': 'relative', 'opcode_table': {
        '1': {'name': 'push16', 'semantic': 'push', 'immediate_bytes': 2, 'push': 1},
        '2': {'name': 'back', 'semantic': 'jump', 'immediate_bytes': 1, 'signed': True},
        '3': {'name': 'stop', 'semantic': 'halt'}}}
    result = R.lift_vm(spec)
    assert [(v['offset'], v['name'], v['immediate'], v['size']) for v in result['ir']] == [
        (0, 'push16', 0x1234, 3), (3, 'back', -5, 2), (5, 'stop', None, 1)]
    assert result['branch_targets'] == [{'from': 3, 'to': 0}]
    assert result['complete'] is True


def test_symbolic_plan_parsed_as_inert_ast():
    spec = {'binary': '/chal/never-run', 'length': 3, 'find': [0x401234], 'avoid': [0x401567],
            'prefix': 'A', 'suffix': 'Z', 'alphabet': [66]}
    result = R.symbolic_review_plan(spec)
    tree = ast.parse(result['harness'])
    constants = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body
                 if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
                 and node.targets[0].id in {'BINARY', 'LENGTH', 'FIND', 'AVOID', 'ALPHABET'}}
    assert constants == {'BINARY': '/chal/never-run', 'LENGTH': 3, 'FIND': [0x401234], 'AVOID': [0x401567], 'ALPHABET': [66]}
    assert result['sha256'] == hashlib.sha256(result['harness'].encode()).hexdigest()
    assert result['candidate_only'] is True


def fuzz_bytes():
    rng = random.Random(0xB1F047)
    seeds = [wasm_fixture(), clr_fixture(), ebpf_fixture(), b'MZ', b'\x7fELF', b'\xcf\xfa\xed\xfe']
    yield b''
    for size in [1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 256]:
        yield bytes([255]) * size
        yield rng.randbytes(size)
    for seed in seeds:
        for length in range(min(len(seed), 80)):
            yield seed[:length]
        for _ in range(12):
            mutated = bytearray(seed)
            if mutated:
                mutated[rng.randrange(len(mutated))] ^= 1 << rng.randrange(8)
            yield bytes(mutated)


@pytest.mark.parametrize('entrypoint', [R.parse_wasm, R.parse_dotnet_metadata, R.parse_ebpf,
                                        R.analyze_languages, R.packer_evidence])
def test_byte_parsers_fail_closed(entrypoint):
    # These legacy APIs explicitly use ValueError, with no custom error class.
    for data in fuzz_bytes():
        try:
            result = entrypoint(data)
        except Exception as exc:
            assert type(exc) is ValueError, (entrypoint.__name__, data.hex(), type(exc).__name__)
        else:
            assert isinstance(result, (dict, list)) or result is None


@pytest.mark.parametrize('entrypoint', [R.lift_vm, R.symbolic_review_plan])
def test_declarative_parsers_malformed_types(entrypoint):
    for spec in [None, b'', b'\xff', 0, 1.5, [], '', {}, {'bytecode_hex': 'FF'}, {'length': 0},
                 {'length': 4, 'find': ['not-address']}]:
        try:
            entrypoint(spec)
        except Exception as exc:
            assert type(exc) is ValueError, type(exc).__name__


def test_cli_wasm_vector(tmp_path, capsys):
    path = tmp_path / 'fixture.wasm'
    path.write_bytes(wasm_fixture())
    assert R.main(['wasm', str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert [x['name'] for x in result['exports']] == ['memory', 'plus']
    assert R.main([]) == 2


def test_bug_wasm_padded_leb128_allowed_by_reference():
    blob = b'\0asm\x01\0\0\0\x00\x81\x00\x00'
    wasmtime.Module.validate(wasmtime.Engine(), blob)
    assert R.parse_wasm(blob)['custom_sections'] == ['']


def test_bug_wasm_empty_custom_section_rejected_by_reference():
    blob = b'\0asm\x01\0\0\0\x00\x00'
    with pytest.raises(wasmtime.WasmtimeError):
        wasmtime.Module.validate(wasmtime.Engine(), blob)
    with pytest.raises(ValueError):
        R.parse_wasm(blob)


def test_bug_vm_list_semantic_exception_contract():
    with pytest.raises(ValueError):
        R.lift_vm({'bytecode_hex': '00', 'opcode_table': {'0': {'semantic': []}}})


def test_bug_symbolic_plan_unicode_exception_contract():
    try:
        R.symbolic_review_plan({'length': 1, 'find': [1], 'prefix': '\ud800'})
    except Exception as exc:
        assert type(exc) is ValueError


def test_bug_cli_help_exception_contract():
    assert R.main(['--help']) == 0


def test_packer_evidence_real_elf_container_oracle():
    from io import BytesIO
    from elftools.elf.elffile import ELFFile
    # ELF64 little-endian ET_EXEC/EM_X86_64 with no section/program tables.
    # Overlay carries explicitly planted UPX signatures; this locks evidence
    # reporting only, never asserts the file is an actual runnable/packed ELF.
    header = b'\x7fELF\x02\x01\x01' + bytes(9)
    header += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x401000, 0, 0, 0, 64, 0, 0, 0, 0, 0)
    image = header + b'UPX!\0UPX0\0UPX1\0'
    oracle = ELFFile(BytesIO(image))
    assert oracle.elfclass == 64 and oracle.header['e_machine'] == 'EM_X86_64'
    result = R.packer_evidence(image)
    assert [r['kind'] for r in result] == ['UPX']
    assert result[0]['verified'] is False
    assert set(result[0]['evidence']) == {'UPX! signature', 'paired UPX0/UPX1 section markers'}
    assert R.analyze_languages(image)['container'] == 'elf'
