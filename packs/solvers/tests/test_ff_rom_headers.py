"""Independent cartridge fixtures from published layouts, not engine encoders.

NES: https://www.nesdev.org/wiki/NES_2.0 and /wiki/INES
GB: https://gbdev.io/pandocs/The_Cartridge_Header.html
MD: https://www.plutiedev.com/rom-header
"""
import argparse
import json
import random
import struct

import pytest

import ff_rom_headers as rom


# Published logo copied independently from Pan Docs, not the parser's constant.
LOGO = bytes.fromhex('CE ED 66 66 CC 0D 00 0B 03 73 00 83 00 0C 00 0D '
                     '00 08 11 1F 88 89 00 0E DC CC 6E E6 DD DD D9 99 '
                     'BB BB 67 63 6E 0E EC CC DD DC 99 9F BB B9 33 3E')


def gb_fixture():
    data = bytearray(32768)
    data[0x104:0x134] = LOGO
    data[0x134:0x138] = b'TEST'
    # 25 header bytes sum to 320: (-320 - 25) mod 256 = A7.
    # Logo sum 5446 + TEST sum 320 + checksum 167 = 5933 = 172D.
    data[0x14d:0x150] = bytes.fromhex('a7 17 2d')
    return bytes(data)


def genesis_fixture():
    data = bytearray(0x206)
    data[0x100:0x110] = b'SEGA MEGA DRIVE '
    data[0x110:0x120] = b'(C)TEST 2026.NOV'
    data[0x120:0x150] = b'TEST DOMESTIC'.ljust(48, b' ')
    data[0x150:0x180] = b'TEST OVERSEAS'.ljust(48, b' ')
    data[0x180:0x18e] = b'GM 12345678-00'
    data[0x190:0x1a0] = b'J6'.ljust(16, b' ')
    data[0x1a0:0x1b0] = struct.pack('>IIII', 0, 0x205, 0xff0000, 0xffffff)
    data[0x1b0:0x1bc] = bytes.fromhex('52 41 f8 20 00 20 00 01 00 20 ff ff')
    data[0x1c8:0x1f0] = b'CSCTF{header_only}'.ljust(40, b' ')
    data[0x1f0:0x200] = b'JUE'.ljust(16, b' ')
    data[0x200:] = bytes.fromhex('12 34 ab cd 00 01')
    # 1234 + ABCD + 0001 = BE02; header words are excluded.
    data[0x18e:0x190] = bytes.fromhex('be 02')
    return bytes(data)


def nes_fixture():
    # Legacy mapper A5, trainer, battery, vertical mirroring, PRG16K+CHR8K.
    return (bytes.fromhex('4e45531a 01 01 57 a0 01 00 00 00 00 00 00 00')
            + b'T' * 512 + b'P' * 16384 + b'C' * 8192)


def test_ines_layout_mapper_trainer_and_exact_sizes():
    data = nes_fixture()
    parsed = rom.parse_nes(data)
    assert parsed['format'] == 'ines'
    assert parsed['mapper'] == 0xa5
    assert parsed['submapper'] is None
    assert parsed['trainer'] is True
    assert parsed['battery'] is True
    assert parsed['mirroring_bit'] == 1
    assert parsed['prg_rom_bytes'] == 16384
    assert parsed['chr_rom_bytes'] == 8192
    assert parsed['size']['matches'] is True
    assert parsed['suffix']['bytes'] == 0
    assert parsed['ram']['prg_ram_bytes'] == 8192
    assert parsed['regions'] == [
        {'name': 'trainer', 'offset': 16, 'declared_bytes': 512, 'available_bytes': 512, 'missing_bytes': 0},
        {'name': 'prg_rom', 'offset': 528, 'declared_bytes': 16384, 'available_bytes': 16384, 'missing_bytes': 0},
        {'name': 'chr_rom', 'offset': 16912, 'declared_bytes': 8192, 'available_bytes': 8192, 'missing_bytes': 0},
    ]


def test_nes2_extended_mapper_linear_sizes_and_ram_shifts():
    header = bytes.fromhex('4e45531a 02 03 14 28 a3 21 76 98 00 00 00 00')
    parsed = rom.parse_nes(header)
    assert (parsed['format'], parsed['mapper'], parsed['submapper']) == ('nes2', 0x321, 10)
    assert parsed['prg_rom_bytes'] == 0x102 * 16384
    assert parsed['chr_rom_bytes'] == 0x203 * 8192
    assert parsed['ram'] == {'prg_ram_bytes': 4096, 'prg_nvram_bytes': 8192,
                             'chr_ram_bytes': 16384, 'chr_nvram_bytes': 32768}
    assert parsed['size']['missing_bytes'] == 512 + 0x102 * 16384 + 0x203 * 8192
    assert all(item['available_bytes'] == 0 for item in parsed['regions'])


@pytest.mark.parametrize(('lsb', 'expected'), [(0, 1), (1, 3), (2, 5), (3, 7), (0x35, 24576), (0xff, 7 * 2**63)])
def test_nes2_exponent_sizes_are_bytes_without_bank_multiplier(lsb, expected):
    header = bytearray.fromhex('4e45531a 00 00 00 08 00 ff 00 00 00 00 00 00')
    header[4] = header[5] = lsb
    parsed = rom.parse_nes(header)
    assert parsed['prg_rom_bytes'] == expected
    assert parsed['chr_rom_bytes'] == expected
    assert parsed['size']['missing_bytes'] == 2 * expected
    assert parsed['regions'][1]['offset'] == 16 + expected


def test_nes_region_truncation_and_suffix():
    parsed = rom.parse_nes(nes_fixture()[:-100])
    assert parsed['size']['missing_bytes'] == 100
    assert parsed['regions'][2]['available_bytes'] == 8092
    parsed = rom.parse_nes(nes_fixture() + b'CSCTF{suffix}')
    assert parsed['suffix']['bytes'] == 13
    assert parsed['suffix']['preview_hex'] == b'CSCTF{suffix}'.hex()
    assert parsed['size']['excess_bytes'] == 13


def test_nes2_misc_rom_suffix_is_classified():
    header = bytearray.fromhex('4e45531a 00 00 00 08 00 0f 00 00 00 00 02 00')
    # Exponent PRG size1, CHR size0; two misc ROMs together hold five bytes.
    parsed = rom.parse_nes(header + b'Pabcde')
    assert parsed['misc_rom_count'] == 2
    assert parsed['suffix']['kind'] == 'miscellaneous_rom'
    assert parsed['suffix']['offset'] == 17
    assert parsed['suffix']['bytes'] == 5
    assert parsed['size']['matches'] is None
    assert parsed['size']['minimum_bytes'] == 17
    assert parsed['size']['excess_bytes'] is None
    assert not any('Bytes follow' in message for message in parsed['findings'])


def test_ines_playchoice_and_reserved_junk_are_not_silently_ignored():
    header = bytes.fromhex('4e45531a 01 00 00 02 00 00 00 00 00 00 00 00')
    parsed = rom.parse_nes(header + bytes(16384 + 8192 + 32))
    assert parsed['regions'][-1]['name'] == 'playchoice_inst_rom'
    assert parsed['regions'][-1]['available_bytes'] == 8192
    assert parsed['suffix']['bytes'] == 32
    data = bytearray(nes_fixture())
    data[12:16] = b'ude!'
    assert any('copier junk' in message for message in rom.parse_nes(data)['findings'])


def test_gb_fixed_published_layout_checksum_arithmetic():
    data = gb_fixture()
    assert rom.gb_header_checksum(data) == 0xa7
    assert rom.gb_global_checksum(data) == 0x172d
    out = rom.parse_gb(data)
    assert out['title'] == 'TEST'
    assert out['logo_matches'] is True
    assert out['cartridge_type'] == 'ROM ONLY'
    assert out['ram_bytes'] == 0
    assert out['size']['declared_bytes'] == 32768
    assert out['size']['matches'] is True
    assert out['checksums']['header'] == {'stored': 0xa7, 'calculated': 0xa7, 'matches': True}
    assert out['checksums']['global']['matches'] is True
    assert out['checksums']['global']['declared_rom_matches'] is True
    assert out['findings'] == []


def test_gb_global_checksum_excludes_stored_checksum_but_includes_header_checksum():
    data = bytearray(gb_fixture())
    data[0x14e:0x150] = b'\xff\xff'
    assert rom.gb_global_checksum(data) == 0x172d
    data[0x14d] += 1
    assert rom.gb_global_checksum(data) == 0x172e
    assert rom.gb_header_checksum(data) == 0xa7


@pytest.mark.parametrize(('code', 'size'), [(0, 32768), (1, 65536), (5, 1048576), (8, 8388608),
                                           (0x52, 1179648), (0x53, 1310720), (0x54, 1572864), (0xff, None)])
def test_gb_rom_size_codes(code, size):
    data = bytearray(gb_fixture())
    data[0x148] = code
    out = rom.parse_gb(data)
    assert out['size']['declared_bytes'] == size
    if code in (0x52, 0x53, 0x54):
        assert any('unverified' in message for message in out['findings'])


@pytest.mark.parametrize(('code', 'size'), [(0, 0), (1, None), (2, 8192), (3, 32768), (4, 131072), (5, 65536), (255, None)])
def test_gb_ram_codes_keep_unused_code_unknown(code, size):
    data = bytearray(gb_fixture())
    data[0x149] = code
    assert rom.parse_gb(data)['ram_bytes'] == size


def test_gbc_overlapping_title_and_mbc2_nibble_ram():
    data = bytearray(gb_fixture())
    data[0x134:0x144] = b'ABCDEFGHIJKABCD\x80'
    data[0x147] = 6
    out = rom.parse_gb(data)
    assert out['format'] == 'gbc'
    assert out['title'] == 'ABCDEFGHIJKABCD'
    assert out['title_11_candidate'] == 'ABCDEFGHIJK'
    assert out['manufacturer_candidate'] == 'ABCD'
    assert out['cartridge_type'] == 'MBC2+BATTERY'
    assert out['ram_bytes'] == 0
    assert out['mbc2_internal_ram_nibbles'] == 512


def test_gb_appended_and_truncated_images_preserve_checksum_scope():
    out = rom.parse_gb(gb_fixture() + b'\x01')
    assert out['size']['excess_bytes'] == 1
    assert out['checksums']['global']['calculated'] == 0x172e
    assert out['checksums']['global']['matches'] is False
    assert out['checksums']['global']['declared_rom_matches'] is True
    out = rom.parse_gb(gb_fixture()[:-9])
    assert out['size']['missing_bytes'] == 9
    assert out['checksums']['global']['declared_rom_matches'] is None
    # Removing zero padding leaves an additive checksum unchanged, but size catches it.
    assert out['checksums']['global']['matches'] is True


def test_genesis_fixed_checksum_and_published_fields():
    data = genesis_fixture()
    assert rom.sega_checksum(data) == 0xbe02
    out = rom.parse_genesis(data)
    assert out['system'] == 'SEGA MEGA DRIVE'
    assert out['domestic_title'] == 'TEST DOMESTIC'
    assert out['overseas_title'] == 'TEST OVERSEAS'
    assert out['serial'] == 'GM 12345678-00'
    assert out['devices'] == 'J6'
    assert out['rom_start'] == 0
    assert out['rom_end_inclusive'] == 0x205
    assert out['ram_start'] == 0xff0000
    assert out['ram_end_inclusive'] == 0xffffff
    assert out['region'] == 'JUE'
    assert out['memo'] == 'CSCTF{header_only}'
    assert out['size']['declared_bytes'] == 0x206
    assert out['size']['matches'] is True
    assert out['checksum']['matches'] is True
    assert out['checksum']['declared_rom_calculated'] == 0xbe02
    assert out['findings'] == []


def test_genesis_checksum_modulo_and_header_exclusion():
    data = bytearray(genesis_fixture())
    data[:0x100] = b'\xff' * 0x100
    data[0x18e:0x190] = b'\0\0'
    data[0x200:] = bytes.fromhex('ffff ffff 0002')
    assert rom.sega_checksum(data) == 0


def test_genesis_appended_and_odd_tail():
    out = rom.parse_genesis(genesis_fixture() + b'\x00\x01')
    assert out['size']['excess_bytes'] == 2
    assert out['checksum']['calculated'] == 0xbe03
    assert out['checksum']['matches'] is False
    assert out['checksum']['declared_rom_matches'] is True
    out = rom.parse_genesis(genesis_fixture() + b'\xff')
    assert out['checksum']['calculated'] is None
    assert out['checksum']['matches'] is None
    assert out['checksum']['declared_rom_matches'] is True
    assert any('Odd image size' in message for message in out['findings'])
    with pytest.raises(rom.RomError):
        rom.sega_checksum(genesis_fixture() + b'\xff')


def test_genesis_invalid_and_mapped_ranges_are_findings():
    data = bytearray(genesis_fixture())
    data[0x1a0:0x1a8] = struct.pack('>II', 0x400, 0x205)
    out = rom.parse_genesis(data)
    assert out['size']['declared_bytes'] is None
    assert out['checksum']['declared_rom_calculated'] is None
    data[0x1a0:0x1a8] = struct.pack('>II', 0, 0x3fffff)
    out = rom.parse_genesis(data)
    assert out['size']['missing_bytes'] == 0x400000 - 0x206
    assert any('mapper' in message for message in out['findings'])


def test_genesis_shift_jis_and_damaged_multibyte_title():
    data = bytearray(genesis_fixture())
    data[0x120:0x150] = 'テスト'.encode('shift_jis').ljust(48, b' ')
    assert rom.parse_genesis(data)['domestic_title'] == 'テスト'
    data[0x120:0x150] = b'\x81\0'.ljust(48, b' ')
    assert rom.parse_genesis(data)['domestic_title'] == '\ufffd'
    data[0x1f3:0x200] = b'RESERVED DATA'
    assert rom.parse_genesis(data)['region'] == 'JUE'


@pytest.mark.parametrize(('fixture', 'format_name'), [(nes_fixture, 'ines'), (gb_fixture, 'gb'), (genesis_fixture, 'genesis')])
def test_dispatch_and_bytes_like_input(fixture, format_name):
    for value in (fixture(), bytearray(fixture()), memoryview(fixture())):
        assert rom.inspect_rom(value)['format'] == format_name


def test_bad_dispatch_kind_and_damaged_gb_logo():
    for kind in (None, [], 7, 'unknown'):
        with pytest.raises(rom.RomError):
            rom.inspect_rom(gb_fixture(), kind)
    data = bytearray(gb_fixture())
    data[0x104] = 0
    with pytest.raises(rom.RomError):
        rom.inspect_rom(data)
    assert rom.inspect_rom(data, 'gb')['logo_matches'] is False


def corpus():
    rng = random.Random(0xf00d2606)
    items = [b'', b'\xff' * 4096]
    items += [rng.randbytes(size) for size in (1, 3, 4, 15, 16, 31, 335, 336, 511, 512, 513, 1024)]
    for data in (nes_fixture(), gb_fixture(), genesis_fixture()):
        items += [data[:n] for n in (0, 1, 4, 15, 16, 128, 255, 256, 335, 336, 511, 512, len(data) - 1)]
        for _ in range(24):
            changed = bytearray(data)
            index = rng.randrange(min(len(changed), 512))
            changed[index] ^= 1 << rng.randrange(8)
            items.append(bytes(changed))
    return items


@pytest.mark.parametrize('entrypoint', [rom.parse_nes, rom.parse_gb, rom.parse_genesis,
                                      rom.inspect_rom, rom.gb_header_checksum, rom.gb_global_checksum,
                                      rom.sega_checksum])
def test_deterministic_malformed_corpus_only_declared_errors(entrypoint):
    for data in corpus():
        try:
            result = entrypoint(data)
        except rom.RomError:
            continue
        assert isinstance(result, (dict, int))


@pytest.mark.parametrize('entrypoint', [rom.parse_nes, rom.parse_gb, rom.parse_genesis,
                                      rom.inspect_rom, rom.gb_header_checksum, rom.gb_global_checksum,
                                      rom.sega_checksum])
def test_wrong_types_released_views_and_size_bound(entrypoint, monkeypatch):
    released = memoryview(b'abc')
    released.release()
    for value in (None, 'NES\x1a', 14, [], {}, released):
        with pytest.raises(rom.RomError):
            entrypoint(value)
    monkeypatch.setattr(rom, 'MAX_IMAGE_BYTES', 8)
    with pytest.raises(rom.RomError):
        entrypoint(b'\0' * 9)


def test_cli_guard_success_error_and_limits(tmp_path, capsys, monkeypatch):
    path = tmp_path / 'test.gb'
    path.write_bytes(gb_fixture())
    assert rom.main([str(path)]) == 0
    assert json.loads(capsys.readouterr().out)['checksums']['global']['calculated'] == 0x172d
    assert rom.main(['--help']) == 0
    assert rom.main([]) == 2
    assert rom.main(['--not-an-option']) == 2
    assert rom.main([str(tmp_path / 'missing')]) == 2
    monkeypatch.setattr(rom, 'MAX_IMAGE_BYTES', 8)
    assert rom.main([str(path)]) == 2
    def non_integer_exit(*args, **kwargs):
        raise SystemExit('error')
    monkeypatch.setattr(argparse.ArgumentParser, 'parse_args', non_integer_exit)
    assert rom.main([]) == 2
