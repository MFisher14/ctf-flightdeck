"""Bounded, static iNES/NES 2.0, Game Boy and raw Mega Drive inspection.

Public parsers accept bytes-like objects and return JSON-compatible reports.
Invalid input raises RomError; inconsistent sizes/checksums are report findings.
No CPU instructions or cartridge contents are executed. Sources: NESdev iNES /
NES 2.0, Pan Docs The Cartridge Header, plutiedev.com/rom-header.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


MAX_IMAGE_BYTES = 64 * 1024 * 1024
NINTENDO_LOGO = bytes.fromhex(
    'ceed6666cc0d000b03730083000c000d0008111f8889000edccc6ee6dddd'
    'd999bbbb67636e0eecccdddc999fbbb9333e'
)


class RomError(ValueError):
    """Malformed, unsupported or over-limit cartridge input."""


def _data(value: bytes) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise RomError('expected a bytes-like cartridge image')
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > MAX_IMAGE_BYTES:
            raise RomError('image exceeds the 64 MiB limit')
        return bytes(value)
    except (ValueError, TypeError, BufferError) as exc:
        raise RomError(str(exc)) from exc


def _text(raw: bytes, encoding: str = 'ascii') -> str:
    return raw.split(b'\0', 1)[0].decode(encoding, errors='replace').rstrip(' ')


def _size(declared: int | None, actual: int) -> dict:
    return {'declared_bytes': declared, 'actual_bytes': actual,
            'matches': None if declared is None else declared == actual,
            'missing_bytes': None if declared is None else max(0, declared - actual),
            'excess_bytes': None if declared is None else max(0, actual - declared)}


def _region(name: str, offset: int, count: int, data: bytes) -> dict:
    available = min(count, max(0, len(data) - offset))
    return {'name': name, 'offset': offset, 'declared_bytes': count,
            'available_bytes': available, 'missing_bytes': count - available}


def _nes_size(lsb: int, msb: int, unit: int) -> int:
    if msb == 15:
        return (1 << (lsb >> 2)) * (2 * (lsb & 3) + 1)
    return ((msb << 8) | lsb) * unit


def parse_nes(value: bytes) -> dict:
    """Inspect a 16-byte-header iNES/NES2 image without allocating declared sizes."""
    data = _data(value)
    if len(data) < 16 or data[:4] != b'NES\x1a':
        raise RomError('missing or truncated iNES header')
    version = data[7] & 12
    if version not in (0, 8):
        raise RomError('unsupported NES header version bits')
    nes2 = version == 8
    mapper = (data[6] >> 4) | (data[7] & 0xf0)
    mapper |= ((data[8] & 15) << 8) if nes2 else 0
    prg = _nes_size(data[4], data[9] & 15 if nes2 else 0, 16384)
    chr_size = _nes_size(data[5], data[9] >> 4 if nes2 else 0, 8192)
    trainer = bool(data[6] & 4)
    regions = []
    offset = 16
    if trainer:
        regions.append(_region('trainer', offset, 512, data))
        offset += 512
    for name, count in (('prg_rom', prg), ('chr_rom', chr_size)):
        regions.append(_region(name, offset, count, data))
        offset += count
    core_end = offset
    misc_count = (data[14] & 3) if nes2 else 0
    findings = []
    if not nes2 and any(data[12:16]):
        findings.append('Nonzero legacy reserved bytes: mapper high bits may be copier junk.')
    if not nes2 and data[7] & 2:
        # iNES defines an 8 KiB PlayChoice instruction ROM; the 32-byte PROM
        # suffix is optional and cannot be distinguished from arbitrary data.
        regions.append(_region('playchoice_inst_rom', offset, 8192, data))
        offset += 8192
        findings.append('PlayChoice PROM, if present, is included in the suffix.')
    suffix = max(0, len(data) - offset)
    if len(data) < offset:
        findings.append('Image is truncated relative to declared ROM regions.')
    if misc_count:
        findings.append('NES 2.0 declares miscellaneous ROMs; suffix sizes are not specified.')
        if not suffix:
            findings.append('Miscellaneous ROM count is nonzero but no suffix bytes are present.')
    elif suffix:
        findings.append('Bytes follow the declared ROM regions.')
    if prg == 0:
        findings.append('Header declares no PRG ROM.')
    ram = {}
    if nes2:
        for key, shift in (('prg_ram', data[10] & 15), ('prg_nvram', data[10] >> 4),
                           ('chr_ram', data[11] & 15), ('chr_nvram', data[11] >> 4)):
            ram[key + '_bytes'] = (64 << shift) if shift else 0
    else:
        ram = {'prg_ram_bytes': (data[8] or 1) * 8192,
               'chr_ram_bytes': 8192 if chr_size == 0 else 0,
               'basis': 'legacy iNES convention; mapper hardware may differ'}
    size = _size(offset, len(data))
    if misc_count:
        size.update(declared_bytes=None, minimum_bytes=offset, matches=None,
                    missing_bytes=max(0, offset - len(data)), excess_bytes=None)
    return {'format': 'nes2' if nes2 else 'ines', 'file_size': len(data),
            'mapper': mapper, 'submapper': data[8] >> 4 if nes2 else None,
            'console_type': data[7] & 3, 'trainer': trainer,
            'battery': bool(data[6] & 2), 'mirroring_bit': data[6] & 1,
            'four_screen_or_alternative': bool(data[6] & 8),
            'prg_rom_bytes': prg, 'chr_rom_bytes': chr_size, 'ram': ram,
            'regions': regions, 'core_end_offset': core_end,
            'size': size, 'misc_rom_count': misc_count,
            'suffix': {'offset': offset, 'bytes': suffix,
                       'kind': 'miscellaneous_rom' if misc_count else 'unclassified',
                       'preview_hex': data[offset:offset + 64].hex()},
            'findings': findings}


GB_TYPES = {
    0: 'ROM ONLY', 1: 'MBC1', 2: 'MBC1+RAM', 3: 'MBC1+RAM+BATTERY',
    5: 'MBC2', 6: 'MBC2+BATTERY', 8: 'ROM+RAM', 9: 'ROM+RAM+BATTERY',
    0x0b: 'MMM01', 0x0c: 'MMM01+RAM', 0x0d: 'MMM01+RAM+BATTERY',
    0x0f: 'MBC3+TIMER+BATTERY', 0x10: 'MBC3+TIMER+RAM+BATTERY',
    0x11: 'MBC3', 0x12: 'MBC3+RAM', 0x13: 'MBC3+RAM+BATTERY',
    0x19: 'MBC5', 0x1a: 'MBC5+RAM', 0x1b: 'MBC5+RAM+BATTERY',
    0x1c: 'MBC5+RUMBLE', 0x1d: 'MBC5+RUMBLE+RAM', 0x1e: 'MBC5+RUMBLE+RAM+BATTERY',
    0x20: 'MBC6', 0x22: 'MBC7+SENSOR+RUMBLE+RAM+BATTERY', 0xfc: 'POCKET CAMERA',
    0xfd: 'BANDAI TAMA5', 0xfe: 'HuC3', 0xff: 'HuC1+RAM+BATTERY',
}
GB_ROM_SIZES = {code: 32768 << code for code in range(9)}
GB_ROM_SIZES.update({0x52: 72 * 16384, 0x53: 80 * 16384, 0x54: 96 * 16384})
GB_RAM_SIZES = {0: 0, 2: 8192, 3: 32768, 4: 131072, 5: 65536}


def gb_header_checksum(value: bytes) -> int:
    """Pan Docs subtract-and-decrement checksum of bytes 0x134..0x14c."""
    data = _data(value)
    if len(data) < 0x150:
        raise RomError('truncated Game Boy header')
    return (-sum(data[0x134:0x14d]) - 25) & 0xff


def gb_global_checksum(value: bytes) -> int:
    """Sum of every supplied ROM byte except the checksum at 0x14e..0x14f."""
    data = _data(value)
    if len(data) < 0x150:
        raise RomError('truncated Game Boy header')
    return (sum(data) - data[0x14e] - data[0x14f]) & 0xffff


def parse_gb(value: bytes) -> dict:
    """Inspect a GB/CGB image; explicit selection also accepts a damaged logo."""
    data = _data(value)
    if len(data) < 0x150:
        raise RomError('truncated Game Boy header')
    cgb = bool(data[0x143] & 0x80)
    rom_size = GB_ROM_SIZES.get(data[0x148])
    ram_size = GB_RAM_SIZES.get(data[0x149])
    stored_header = data[0x14d]
    stored_global = int.from_bytes(data[0x14e:0x150], 'big')
    header_sum = gb_header_checksum(data)
    global_sum = gb_global_checksum(data)
    declared_sum = (gb_global_checksum(data[:rom_size])
                    if rom_size is not None and len(data) >= rom_size else None)
    findings = []
    if data[0x104:0x134] != NINTENDO_LOGO:
        findings.append('Nintendo logo differs from the standard 48-byte logo.')
    if rom_size is None:
        findings.append('Unknown ROM size code; declared size cannot be established.')
    elif rom_size != len(data):
        findings.append('Declared ROM size differs from file size.')
    if data[0x148] in (0x52, 0x53, 0x54):
        findings.append('ROM size code is historical/unverified; no known cartridges in Pan Docs.')
    if ram_size is None:
        findings.append('Unused or unknown RAM size code; no RAM size inferred.')
    if data[0x147] not in GB_TYPES:
        findings.append('Unknown cartridge type.')
    if stored_header != header_sum:
        findings.append('Header checksum mismatch.')
    if stored_global != global_sum:
        findings.append('Global checksum mismatch over the supplied image.')
    return {'format': 'gbc' if cgb else 'gb', 'file_size': len(data),
            'title': _text(data[0x134:0x143 if cgb else 0x144]),
            'title_11_candidate': _text(data[0x134:0x13f]),
            'manufacturer_candidate': _text(data[0x13f:0x143]),
            'title_raw_hex': data[0x134:0x144].hex(),
            'title_note': 'Later headers reuse the final four title bytes for a manufacturer; interpretation is ambiguous.',
            'cgb_flag': data[0x143], 'sgb_flag': data[0x146],
            'cartridge_type_code': data[0x147],
            'cartridge_type': GB_TYPES.get(data[0x147], 'UNKNOWN'),
            'rom_size_code': data[0x148], 'ram_size_code': data[0x149],
            'ram_bytes': ram_size, 'mbc2_internal_ram_nibbles': 512 if data[0x147] in (5, 6) else 0,
            'licensee_old': data[0x14b], 'licensee_new': _text(data[0x144:0x146]),
            'destination_code': data[0x14a], 'version': data[0x14c],
            'logo_matches': data[0x104:0x134] == NINTENDO_LOGO,
            'size': _size(rom_size, len(data)),
            'checksums': {'header': {'stored': stored_header, 'calculated': header_sum,
                                     'matches': stored_header == header_sum},
                          'global': {'stored': stored_global, 'calculated': global_sum,
                                     'matches': stored_global == global_sum,
                                     'basis': 'all supplied bytes except 0x14e and 0x14f',
                                     'declared_rom_calculated': declared_sum,
                                     'declared_rom_matches': None if declared_sum is None else stored_global == declared_sum}},
            'findings': findings}


def sega_checksum(value: bytes) -> int:
    """Sum big-endian words from 0x200 to EOF; an incomplete word is invalid."""
    data = _data(value)
    if len(data) < 0x200 or len(data) & 1:
        raise RomError('Sega checksum requires a full header and whole 16-bit words')
    # Separate byte sums avoid a large array of Python integer words.
    return ((sum(data[0x200::2]) << 8) + sum(data[0x201::2])) & 0xffff


def parse_genesis(value: bytes) -> dict:
    """Inspect a raw big-endian Mega Drive ROM, not an interleaved SMD dump."""
    data = _data(value)
    if len(data) < 0x200:
        raise RomError('truncated Mega Drive header')
    if data[0x100:0x104] != b'SEGA':
        raise RomError('missing SEGA system identifier in a raw ROM header')
    start = int.from_bytes(data[0x1a0:0x1a4], 'big')
    end = int.from_bytes(data[0x1a4:0x1a8], 'big')
    declared = end - start + 1 if end >= start else None
    stored = int.from_bytes(data[0x18e:0x190], 'big')
    calculated = sega_checksum(data) if len(data) % 2 == 0 else None
    declared_sum = None
    if start == 0 and declared is not None and 0x200 <= declared <= len(data) and declared % 2 == 0:
        declared_sum = sega_checksum(data[:declared])
    findings = []
    if declared is None:
        findings.append('ROM end address precedes start address.')
    elif declared != len(data):
        findings.append('Declared ROM address span differs from file size; a mapper may explain this.')
    if declared is not None and declared < 0x200:
        findings.append('Declared ROM span is shorter than the header.')
    if start != 0:
        findings.append('Nonzero ROM start address; no physical file extent inferred.')
    if calculated is None:
        findings.append('Odd image size: final byte is not a whole checksum word.')
    elif calculated != stored:
        findings.append('Sega checksum mismatch over the supplied image.')
    return {'format': 'genesis', 'file_size': len(data),
            'system': _text(data[0x100:0x110]), 'copyright': _text(data[0x110:0x120]),
            'domestic_title': _text(data[0x120:0x150], 'shift_jis'),
            'overseas_title': _text(data[0x150:0x180], 'shift_jis'),
            'domestic_title_raw_hex': data[0x120:0x150].hex(),
            'overseas_title_raw_hex': data[0x150:0x180].hex(),
            'serial': _text(data[0x180:0x18e]), 'devices': _text(data[0x190:0x1a0]),
            'rom_start': start, 'rom_end_inclusive': end,
            'ram_start': int.from_bytes(data[0x1a8:0x1ac], 'big'),
            'ram_end_inclusive': int.from_bytes(data[0x1ac:0x1b0], 'big'),
            'extra_memory_hex': data[0x1b0:0x1bc].hex(),
            'modem': _text(data[0x1bc:0x1c8]), 'memo': _text(data[0x1c8:0x1f0]),
            'region': _text(data[0x1f0:0x1f3]),
            'region_reserved_hex': data[0x1f3:0x200].hex(), 'size': _size(declared, len(data)),
            'checksum': {'stored': stored, 'calculated': calculated,
                         'matches': None if calculated is None else calculated == stored,
                         'declared_rom_calculated': declared_sum,
                         'declared_rom_matches': None if declared_sum is None else declared_sum == stored},
            'findings': findings}


def inspect_rom(value: bytes, kind: str = 'auto') -> dict:
    """Dispatch by signature or explicit kind: auto, nes, gb, genesis."""
    data = _data(value)
    if not isinstance(kind, str) or kind not in ('auto', 'nes', 'gb', 'genesis'):
        raise RomError('unknown cartridge kind')
    if kind == 'auto':
        if data.startswith(b'NES\x1a'):
            kind = 'nes'
        elif data[0x104:0x134] == NINTENDO_LOGO:
            kind = 'gb'
        elif data[0x100:0x104] == b'SEGA':
            kind = 'genesis'
        else:
            raise RomError('unrecognized cartridge; use --kind for a damaged Game Boy logo')
    return {'nes': parse_nes, 'gb': parse_gb, 'genesis': parse_genesis}[kind](data)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--kind', choices=('auto', 'nes', 'gb', 'genesis'), default='auto')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.file.open('rb') as handle:
            data = handle.read(MAX_IMAGE_BYTES + 1)
        print(json.dumps(inspect_rom(data, args.kind), indent=2, ensure_ascii=True))
        return 0
    except (RomError, OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
