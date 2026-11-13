"""Independent artifact layouts and saved-signal vectors, never execution.

Oracles: microsoft/uf2 specification; Apple's mach-o/loader.h and
dyld_cache_format.h; POCSAG sync/idle words; median/MAD arithmetic.
"""
import io
import json
import random
import struct
import zipfile

import numpy as np
import pytest

import mobile_rf_depth as mobile


def uf2(payload=b'ABCD', number=0, total=1, address=0x1000, flags=0x2000):
    header = struct.pack('<8I', 0x0a324655, 0x9e5d5157, flags, address,
                         len(payload), number, total, 0xe48bff56)
    return header + payload + bytes(476-len(payload)) + struct.pack('<I', 0x0ab16f30)


def macho(endian='<', bits=64):
    uuid = struct.pack(endian+'II', 0x1b, 24) + bytes(range(16))
    name = b'@rpath/FridaGadget.dylib\0'
    name += bytes((-len(name)) % 4)
    dylib = struct.pack(endian+'6I', 0xc, 24+len(name), 24, 0, 0x10000, 0x10000) + name
    commands = uuid + dylib
    fields = [0xfeedfacf if bits == 64 else 0xfeedface,
              0x100000c if bits == 64 else 12, 0, 2, 2, len(commands), 0x200000]
    if bits == 64:
        fields.append(0)
    return struct.pack(endian+'I'*len(fields), *fields) + commands


def dyld():
    # Header32, mapping32, image32, then NUL-terminated image path.
    return (b'dyld_v1   arm64\0' + struct.pack('<4I', 32, 1, 64, 1)
            + struct.pack('<QQQII', 0x180000000, 32, 0, 5, 5)
            + struct.pack('<QQQII', 0x180001000, 123, 42, 96, 0)
            + b'/usr/lib/libSystem.B.dylib\0')


def bundle():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in ('assets/bin/Data/Managed/Metadata/global-metadata.dat',
                     'lib/arm64-v8a/libil2cpp.so', 'lib/arm64-v8a/libapp.so',
                     'lib/arm64-v8a/libflutter.so', 'assets/flutter_assets/hello.txt',
                     'assemblies/Example.dll', 'lib/arm64-v8a/libmonodroid.so'):
            archive.writestr(path, b'fixture')
    return stream.getvalue()


def test_uf2_reference_dense_reassembly_and_sparse_gap():
    # Blocks intentionally arrive out of order; image address order is independent.
    result = mobile.parse_uf2(uf2(b'EFGH', 1, 2, 0x1004) + uf2(b'ABCD', 0, 2))
    assert result['image'] == b'ABCDEFGH'
    assert result['base_address'] == 0x1000 and result['end_address'] == 0x1008
    assert result['complete'] and result['reconstruction_verified']
    assert result['blocks'][0]['family_id'] == 0xe48bff56
    sparse = mobile.parse_uf2(uf2(b'ABCD', 0, 2) + uf2(b'EFGH', 1, 2, 0x1008))
    assert sparse['gaps'] == [(0x1004, 0x1008)]
    assert sparse['image'] is None and not sparse['reconstruction_verified']
    incomplete = mobile.parse_uf2(uf2(total=2))
    assert not incomplete['complete'] and incomplete['image'] is None


@pytest.mark.parametrize('endian', ['<', '>'])
@pytest.mark.parametrize('bits', [32, 64])
def test_macho_published_fields(endian, bits):
    out = mobile.parse_macho(macho(endian, bits))
    assert out['format'] == f'macho{bits}'
    assert out['cpu'] == ('arm64' if bits == 64 else 'arm')
    assert out['byte_order'] == ('little' if endian == '<' else 'big')
    assert out['flags'] == 0x200000
    assert out['uuids'] == ['000102030405060708090a0b0c0d0e0f']
    assert out['dylibs'] == ['@rpath/FridaGadget.dylib']
    assert out['frida_gadget_evidence'] == ['@rpath/FridaGadget.dylib']
    assert out['instrumentation_active_verified'] is False


def test_fat_macho_slice_and_dyld_classic_tables():
    thin = macho()
    fat = struct.pack('>7I', 0xcafebabe, 1, 0x100000c, 0, 32, len(thin), 2) + bytes(4) + thin
    out = mobile.parse_macho(fat)
    assert out['format'] == 'fat'
    assert out['slices'][0]['offset'] == 32
    assert out['slices'][0]['macho']['cpu'] == 'arm64'
    out = mobile.parse_dyld_cache(dyld())
    assert out['mappings'] == [{'address': 0x180000000, 'size': 32, 'file_offset': 0,
                                'max_protection': 5, 'initial_protection': 5}]
    assert out['images'] == [{'address': 0x180001000, 'mod_time': 123, 'inode': 42,
                              'path': '/usr/lib/libSystem.B.dylib'}]


def test_bundle_real_zip_metadata_only(monkeypatch):
    raw = bundle()
    def forbidden(*args, **kwargs):
        pytest.fail('Inventory must not extract or execute ZIP members')
    monkeypatch.setattr(zipfile.ZipFile, 'read', forbidden)
    monkeypatch.setattr(zipfile.ZipFile, 'extract', forbidden)
    monkeypatch.setattr(zipfile.ZipFile, 'extractall', forbidden)
    out = mobile.inspect_mobile_bundle(raw)
    assert out['member_count'] == 7
    assert out['runtime_pairs'] == {'xamarin_or_maui': True, 'unity_il2cpp': True, 'flutter_aot': True}
    assert out['unity_native'] == ['lib/arm64-v8a/libil2cpp.so']
    assert out['flutter_assets'] == ['assets/flutter_assets/hello.txt']
    assert out['runtime_executed_verified'] is False


def test_pocsag_published_sync_idle_and_frame_positions():
    assert mobile.correct_pocsag_codeword(0x7cd215d8)['protocol_marker'] == 'sync'
    idle = mobile.correct_pocsag_codeword(0x7a89c197)
    assert idle['word'] == 0x7a89c197 and idle['payload_verified']
    corrected = mobile.correct_pocsag_codeword(0x7a89c197 ^ (1 << 7))
    assert corrected['word'] == 0x7a89c197 and corrected['corrected_bits'] == [7]
    assert corrected['payload_verified'] is False
    # All-zero address is a valid zero-remainder, even-parity codeword.
    out = mobile.decode_pocsag_words([0x7cd215d8, 0x7a89c197, 0x7a89c197, 0])
    assert out['fields'][-1]['capcode'] == 1
    assert out['fields'][-1]['function'] == 0


def test_synthetic_fsk_and_glitch_median_mad():
    bits = [1, 0, 0, 1, 0, 1, 1, 0]
    signal = np.repeat(np.array(bits)*2-1, 8).tolist()
    out = mobile.slice_fsk_discriminator(signal, 8)
    assert out['phase'] == 0
    assert out['polarity_candidates'] == [bits, [1-x for x in bits]]
    assert out['separation_score'] == 1.0
    trace = [-1, 0, 1]*33 + [20, 25] + [-1, 0, 1]*33
    out = mobile.analyze_glitch_trace(trace)
    assert (out['median'], out['mad']) == (0, 1)
    assert len(out['events']) == 1
    event = out['events'][0]
    assert (event['start'], event['end'], event['peak_index'], event['peak_value']) == (99, 101, 100, 25)
    assert event['robust_z'] == pytest.approx(25/1.4826)


@pytest.mark.parametrize('entry', [mobile.parse_uf2, mobile.parse_macho, mobile.parse_dyld_cache, mobile.inspect_mobile_bundle])
def test_deterministic_binary_fuzz(entry):
    rng = random.Random(0x4d4f4249)
    samples = [b'', b'\xff'*1024, b'\0'*1024]
    samples += [rng.randbytes(n) for n in (1, 4, 16, 32, 512, 2048)]
    for raw in (uf2(), macho(), dyld(), bundle()):
        samples += [raw[:n] for n in (0, 1, 4, 15, 31, len(raw)-1)]
        for _ in range(12):
            changed = bytearray(raw)
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            samples.append(bytes(changed))
    for raw in samples:
        try:
            entry(raw)
        except mobile.ArtifactError:
            pass


def test_explicit_small_caps(monkeypatch):
    monkeypatch.setattr(mobile, 'MAX_INPUT', 16)
    for entry, raw in [(mobile.parse_uf2, uf2()), (mobile.parse_macho, macho()),
                       (mobile.parse_dyld_cache, dyld()), (mobile.inspect_mobile_bundle, bundle())]:
        with pytest.raises(mobile.ArtifactError):
            entry(raw)
    monkeypatch.setattr(mobile, 'MAX_SAMPLES', 3)
    for entry, args in [(mobile.slice_fsk_discriminator, ([1]*4, 1)),
                        (mobile.analyze_glitch_trace, ([0]*4,))]:
        with pytest.raises(mobile.ArtifactError):
            entry(*args)
    monkeypatch.setattr(mobile, 'MAX_CODEWORDS', 1)
    with pytest.raises(mobile.ArtifactError):
        mobile.decode_pocsag_words([0, 0])


@pytest.mark.parametrize(('entry', 'args'), [
    (mobile.parse_macho, (None,)), (mobile.parse_dyld_cache, (None,)),
    (mobile.inspect_mobile_bundle, (None,)), (mobile.decode_pocsag_words, (None,)),
    (mobile.slice_fsk_discriminator, (['bad'], 1)),
    (mobile.slice_fsk_discriminator, ([1, 2, 3], 1.5)),
    (mobile.analyze_glitch_trace, (['bad'],))])
def test_malformed_public_inputs_only_declared_error(entry, args):
    try:
        entry(*args)
    except mobile.ArtifactError:
        pass


def test_cli_only_saved_fixture(tmp_path, capsys):
    path = tmp_path/'saved.uf2'
    path.write_bytes(uf2())
    assert mobile.main(['uf2', str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['image']['hex'] == '41424344'
    assert mobile.main(['--help']) == 0
    assert mobile.main([]) == 2
