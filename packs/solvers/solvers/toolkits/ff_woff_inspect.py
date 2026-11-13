#!/usr/bin/env python3
"""Bounded, offline WOFF/WOFF2 and SFNT/TTC structural hidden-data inspection.

Complements font_inspect's name decoder. No rendering, TrueType bytecode execution,
XML parsing or image decoding occurs. WOFF2 transforms are inventoried, not reversed;
checksums are checked only when the container actually stores an expected checksum.
All malformed-input failures from inspect_font raise FFWOFFError.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
import zlib
from dataclasses import dataclass


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

class FFWOFFError(Exception):
    """Malformed, unsupported, or resource-limit-exceeding font input."""


@dataclass(frozen=True)
class Limits:
    max_input: int = 32 * 1024 * 1024
    max_decoded: int = 64 * 1024 * 1024
    max_tables: int = 4096
    max_fonts: int = 128
    max_records: int = 65536
    max_ratio: int = 2000


_TAGS = ('cmap head hhea hmtx maxp name OS/2 post'.split() + ['cvt ', 'fpgm', 'glyf', 'loca',
         'prep', 'CFF ', 'VORG', 'EBDT', 'EBLC', 'gasp', 'hdmx', 'kern', 'LTSH', 'PCLT', 'VDMX',
         'vhea', 'vmtx', 'BASE', 'GDEF', 'GPOS', 'GSUB', 'EBSC', 'JSTF', 'MATH', 'CBDT', 'CBLC',
         'COLR', 'CPAL', 'SVG ', 'sbix', 'acnt', 'avar', 'bdat', 'bloc', 'bsln', 'cvar', 'fdsc',
         'feat', 'fmtx', 'fvar', 'gvar', 'hsty', 'just', 'lcar', 'mort', 'morx', 'opbd', 'prop',
         'trak', 'Zapf', 'Silf', 'Glat', 'Gloc', 'Feat', 'Sill'])
_KNOWN = set(_TAGS) | set('CFF2 DSIG HVAR VVAR MVAR STAT VORG meta ltag MERG'.split())
_SFNT = {b'\0\1\0\0', b'OTTO', b'true', b'typ1'}
_FLAGS = flagfmt.BYTES


def _need(condition, message):
    if not condition:
        raise FFWOFFError(message)


def _slice(data, offset, size, label):
    _need(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, label + ' outside input')
    return data[offset:offset + size]


def _unpack(fmt, data, offset=0):
    _slice(data, offset, struct.calcsize(fmt), 'structure')
    return struct.unpack_from(fmt, data, offset)


def _flags(data):
    found = set()
    for match in _FLAGS.finditer(data):
        found.add(match.group().decode('ascii', 'backslashreplace'))
        if len(found) >= 1024:
            break
    return sorted(found)


def _facts(data):
    return {'length': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'flags': _flags(data)}


def _checksum(data, tag):
    if tag == 'head':
        _need(len(data) >= 12, 'short head checksum field')
        data = data[:8] + b'\0' * 4 + data[12:]
    padded = data + b'\0' * (-len(data) % 4)
    return sum(x[0] for x in struct.iter_unpack('>I', padded)) & 0xffffffff


class _Budget:
    def __init__(self, limits):
        self.limits = limits
        self.decoded = 0
        self.records = 0

    def count(self, n):
        self.records += n
        _need(self.records <= self.limits.max_records, 'record budget exceeded')

    def reserve(self, n, compressed=None):
        _need(n >= 0 and self.decoded + n <= self.limits.max_decoded, 'decoded byte budget exceeded')
        if compressed is not None:
            _need(n <= max(1, compressed) * self.limits.max_ratio, 'compression ratio limit exceeded')
        self.decoded += n


def _inflate(data, size, budget, *, gzip=False):
    budget.reserve(size, len(data))
    dec = zlib.decompressobj(31 if gzip else 15)
    out = dec.decompress(data, size + 1)
    _need(len(out) == size and dec.eof and not dec.unused_data and not dec.unconsumed_tail,
          'invalid compressed data or decoded length')
    return out


def _brotli(data, size, budget):
    budget.reserve(size, len(data))
    try:
        import brotli
    except ImportError as exc:
        raise FFWOFFError('WOFF2 requires brotli >= 1.2 with bounded output support') from exc
    dec = brotli.Decompressor()
    _need(hasattr(dec, 'can_accept_more_data'), 'bounded brotli >= 1.2 required')
    pieces, total, pos = [], 0, 0
    while not dec.is_finished():
        if dec.can_accept_more_data() and pos < len(data):
            chunk = data[pos:pos + 4096]
            pos += len(chunk)
        else:
            chunk = b''
        # The native decoder may round its output buffer up to an internal block;
        # the retained result is capped immediately, without whole-stream decoding.
        part = dec.process(chunk, output_buffer_limit=min(65536, size - total + 1))
        _need(part or chunk or dec.is_finished(), 'truncated Brotli stream')
        total += len(part)
        _need(total <= size, 'Brotli output exceeds declared length')
        pieces.append(part)
    _need(pos == len(data) and total == size, 'Brotli trailing data or decoded length mismatch')
    return b''.join(pieces)


def _base128(data, pos):
    value = 0
    for i in range(5):
        b = _slice(data, pos, 1, 'UIntBase128')[0]
        pos += 1
        _need(not (i == 0 and b == 0x80), 'noncanonical UIntBase128')
        value = value * 128 + (b & 127)
        _need(value <= 0xffffffff, 'UIntBase128 overflow')
        if not b & 128:
            return value, pos
    raise FFWOFFError('unterminated UIntBase128')


def _u255(data, pos):
    b = _slice(data, pos, 1, '255UInt16')[0]
    pos += 1
    if b == 253:
        return _unpack('>H', data, pos)[0], pos + 2
    if b in (254, 255):
        return _slice(data, pos, 1, '255UInt16')[0] + (506 if b == 254 else 253), pos + 1
    return b, pos


def _layout(data, regions, budget):
    regions = sorted((o, o + n, label) for o, n, label in regions if n)
    active, overlaps, gaps = [], [], []
    end = 0
    for start, stop, label in regions:
        active = [r for r in active if r[1] > start]
        for a, b, oldlabel in active:
            budget.count(1)
            overlaps.append({'first': oldlabel, 'second': label, 'offset': start,
                             'length': min(stop, b) - start,
                             'shared_exact_range': a == start and b == stop})
        active.append((start, stop, label))
        if start > end:
            raw = data[end:start]
            gaps.append({'offset': end, 'zero_padding': not any(raw), **_facts(raw)})
        end = max(end, stop)
    if end < len(data):
        raw = data[end:]
        gaps.append({'offset': end, 'trailing': True, 'zero_padding': not any(raw), **_facts(raw)})
    return {'overlaps': overlaps, 'gaps': gaps}


def _svg(data, budget):
    version, base, reserved = _unpack('>HII', data)
    _need(version == 0 and base >= 10 and reserved == 0, 'invalid SVG table header')
    count = _unpack('>H', data, base)[0]
    budget.count(count)
    _need(count > 0, 'empty SVG document list')
    _slice(data, base + 2, 12 * count, 'SVG records')
    result, previous, cache = [], -1, {}
    for i in range(count):
        first, last, off, size = _unpack('>HHII', data, base + 2 + 12 * i)
        _need(first <= last and first > previous and off >= 2 + 12 * count and size > 0,
              'invalid SVG glyph range or document offset')
        previous = last
        raw = _slice(data, base + off, size, 'SVG document')
        if (off, size) not in cache:
            compressed = raw.startswith(b'\x1f\x8b\x08')
            if compressed:
                _need(len(raw) >= 18, 'short gzip SVG')
                size_out = int.from_bytes(raw[-4:], 'little')
                raw = _inflate(raw, size_out, budget, gzip=True)
            else:
                budget.reserve(len(raw))
            raw.decode('utf-8')
            cache[(off, size)] = {'gzip': compressed, **_facts(raw),
                'script_markup': bool(re.search(rb'<\s*script\b', raw, re.I)),
                'external_reference_markup': bool(re.search(rb'(?:href\s*=\s*[\x22\x27](?:https?:|//|file:)|<!ENTITY|<!DOCTYPE)', raw, re.I))}
        result.append({'first_glyph': first, 'last_glyph': last, 'offset': base + off,
                       'stored_length': size, **cache[(off, size)]})
    return result


def _bitmap(tables, budget):
    result = []
    if 'sbix' in tables:
        data = tables['sbix']
        version, flags, count = _unpack('>HHI', data)
        _need(version == 1, 'unsupported sbix version')
        budget.count(count)
        _need('maxp' in tables, 'sbix needs maxp glyph count')
        glyphs = _unpack('>H', tables['maxp'], 4)[0]
        offsets = [_unpack('>I', data, 8 + 4 * i)[0] for i in range(count)]
        _need(offsets == sorted(set(offsets)), 'overlapping sbix strike offsets')
        offsets.append(len(data))
        for i in range(count):
            start, end = offsets[i:i + 2]
            _need(start >= 8 + 4 * count and start <= end, 'invalid sbix strike offset')
            strike = _slice(data, start, end - start, 'sbix strike')
            ppem, ppi = _unpack('>HH', strike)
            budget.count(glyphs)
            goff = [_unpack('>I', strike, 4 + 4 * g)[0] for g in range(glyphs + 1)]
            _need(goff == sorted(goff) and goff[0] >= 4 + 4 * (glyphs + 1) and goff[-1] <= len(strike),
                  'invalid sbix glyph offsets')
            for g in range(glyphs):
                off, stop = goff[g:g + 2]
                if off == stop:
                    continue
                blob = _slice(strike, off, stop - off, 'sbix glyph')
                x, y, tag = _unpack('>hh4s', blob)
                record = {'table': 'sbix', 'strike': i, 'glyph': g, 'ppem': ppem, 'ppi': ppi,
                          'format': tag.decode('latin1'), 'origin': [x, y], **_facts(blob[8:])}
                if tag == b'dupe':
                    _need(len(blob) == 10, 'invalid sbix dupe glyph')
                    record['duplicate_glyph'] = _unpack('>H', blob, 8)[0]
                    _need(record['duplicate_glyph'] < glyphs, 'sbix dupe outside glyph range')
                if tag == b'png ' and blob[8:16] == b'\x89PNG\r\n\x1a\n':
                    _need(len(blob) >= 32 and blob[20:24] == b'IHDR', 'truncated PNG glyph header')
                    record['width'], record['height'] = _unpack('>II', blob, 24)
                result.append(record)
    for tag in ('CBLC', 'EBLC', 'bloc'):
        if tag not in tables:
            continue
        data = tables[tag]
        major, minor, count = _unpack('>HHI', data)
        _need(major in (2, 3) and minor == 0, 'unsupported bitmap locator version')
        budget.count(count)
        _slice(data, 8, count * 48, 'bitmap strike records')
        for i in range(count):
            p = 8 + 48 * i
            off, size, nsub = _unpack('>III', data, p)
            first, last, x, y, depth, flags = _unpack('>HHBBBb', data, p + 40)
            _need(first <= last, 'invalid bitmap glyph range')
            _slice(data, off, size, 'bitmap index subtables')
            _need(nsub * 8 <= size, 'invalid bitmap index count')
            budget.count(nsub)
            sub = []
            for j in range(nsub):
                a, b, rel = _unpack('>HHI', data, off + 8 * j)
                _need(first <= a <= b <= last and nsub * 8 <= rel <= size - 8,
                      'invalid bitmap subtable range')
                index_fmt, image_fmt, image_off = _unpack('>HHI', data, off + rel)
                sub.append({'first_glyph': a, 'last_glyph': b, 'index_format': index_fmt,
                            'image_format': image_fmt, 'image_data_offset': image_off})
            result.append({'table': tag, 'strike': i, 'first_glyph': first, 'last_glyph': last,
                           'ppem_x': x, 'ppem_y': y, 'bit_depth': depth, 'subtables': sub})
    return result


def _inventory(tables, budget):
    return {'svg_documents': _svg(tables['SVG '], budget) if 'SVG ' in tables else [],
            'bitmap_glyphs': _bitmap(tables, budget)}


def _table(tag, raw, expected=None):
    result = {'tag': tag, 'private_candidate': tag not in _KNOWN, **_facts(raw)}
    actual = _checksum(raw, tag)
    result['checksum'] = {'actual': actual, 'expected': expected,
                          'valid': actual == expected if expected is not None else None}
    return result


def _sfnt(data, budget):
    regions = []
    table_cache = {}
    if data[:4] == b'ttcf':
        version, count = _unpack('>II', data, 4)
        _need(version in (0x10000, 0x20000) and 0 < count <= budget.limits.max_fonts, 'invalid TTC header')
        offsets = [_unpack('>I', data, 12 + 4 * i)[0] for i in range(count)]
        headlen = 12 + count * 4 + (12 if version == 0x20000 else 0)
        _slice(data, 0, headlen, 'TTC header')
        regions.append((0, headlen, 'TTC header'))
        if version == 0x20000:
            tag, size, off = _unpack('>III', data, 12 + count * 4)
            if tag or size or off:
                _need(tag == 0x44534947 and size > 0, 'invalid TTC DSIG header')
                _slice(data, off, size, 'TTC signature')
                regions.append((off, size, 'TTC DSIG'))
        kind = 'TTC'
    else:
        offsets, kind = [0], 'SFNT'
    fonts = []
    for f, base in enumerate(offsets):
        flavor, count = _unpack('>4sH', data, base)
        _need(flavor in _SFNT and 0 < count <= budget.limits.max_tables, 'invalid SFNT directory')
        _slice(data, base, 12 + count * 16, 'SFNT directory')
        regions.append((base, 12 + count * 16, f'font[{f}] directory'))
        budget.count(count)
        records, payloads = [], {}
        for i in range(count):
            tag_b, checksum, off, size = _unpack('>4sIII', data, base + 12 + 16 * i)
            tag = tag_b.decode('latin1')
            _need(tag not in payloads, 'duplicate SFNT table tag')
            key = (tag, off, size)
            if key not in table_cache:
                budget.reserve(size)
                raw = _slice(data, off, size, 'SFNT table')
                table_cache[key] = (raw, _table(tag, raw))
            raw, cached_facts = table_cache[key]
            payloads[tag] = raw
            facts = dict(cached_facts)
            actual = facts['checksum']['actual']
            facts['checksum'] = {'actual': actual, 'expected': checksum, 'valid': actual == checksum}
            records.append({'offset': off, 'stored_length': size, 'aligned': off % 4 == 0,
                            **facts})
            regions.append((off, size, f'font[{f}] {tag}'))
        fonts.append({'index': f, 'offset': base, 'flavor_hex': flavor.hex(), 'tables': records,
                      **_inventory(payloads, budget)})
    return {'format': kind, 'fonts': fonts, **_layout(data, regions, budget)}


def _optional(data, header_end, meta, priv, regions, budget, version):
    mo, ml, original = meta
    po, pl = priv
    result = {'metadata': None, 'private': None}
    _need((mo == ml == original == 0) or (mo >= header_end and ml > 0 and original > 0),
          'inconsistent metadata bounds')
    _need((po == pl == 0) or (po >= header_end and pl > 0), 'inconsistent private bounds')
    if mo:
        raw = _slice(data, mo, ml, 'metadata')
        plain = _brotli(raw, original, budget) if version == 2 else _inflate(raw, original, budget)
        result['metadata'] = {'offset': mo, 'stored_length': ml, 'aligned': mo % 4 == 0, **_facts(plain)}
        regions.append((mo, ml, 'metadata'))
    if po:
        raw = _slice(data, po, pl, 'private block')
        result['private'] = {'offset': po, 'aligned': po % 4 == 0, **_facts(raw)}
        regions.append((po, pl, 'private block'))
    return result


def _woff(data, budget):
    fields = _unpack('>4s4sIHHIHHIIIII', data)
    _, flavor, size, count, reserved, sfnt_size, major, minor, mo, ml, original, po, pl = fields
    _need(size == len(data) and flavor in _SFNT and 0 < count <= budget.limits.max_tables, 'invalid WOFF header')
    _need(reserved == 0, 'nonzero WOFF reserved field')
    end = 44 + 20 * count
    _slice(data, 0, end, 'WOFF directory')
    budget.count(count)
    regions, tables, payloads = [(0, end, 'WOFF header/directory')], [], {}
    calculated = 12 + 16 * count
    for i in range(count):
        tag_b, off, stored, original_size, check = _unpack('>4sIIII', data, 44 + 20 * i)
        tag = tag_b.decode('latin1')
        _need(tag not in payloads and off >= end and 0 <= stored <= original_size, 'invalid WOFF table record')
        raw = _slice(data, off, stored, 'WOFF table')
        if stored < original_size:
            raw = _inflate(raw, original_size, budget)
        else:
            budget.reserve(original_size)
        payloads[tag] = raw
        tables.append({'offset': off, 'stored_length': stored, 'compressed': stored < original_size,
                       'aligned': off % 4 == 0, **_table(tag, raw, check)})
        regions.append((off, stored, f'WOFF {tag}'))
        calculated += (original_size + 3) & ~3
    _need(calculated == sfnt_size, 'WOFF totalSfntSize mismatch')
    optional = _optional(data, end, (mo, ml, original), (po, pl), regions, budget, 1)
    return {'format': 'WOFF', 'version': [major, minor], 'total_sfnt_size': sfnt_size,
            'fonts': [{'index': 0, 'flavor_hex': flavor.hex(), 'tables': tables, **_inventory(payloads, budget)}],
            **optional, **_layout(data, regions, budget)}


def _woff2(data, budget):
    fields = _unpack('>4s4sIHHIIHHIIIII', data)
    _, flavor, size, count, reserved, sfnt_size, compressed_size, major, minor, mo, ml, original, po, pl = fields
    _need(size == len(data) and (flavor in _SFNT or flavor == b'ttcf') and
          0 < count <= budget.limits.max_tables, 'invalid WOFF2 header')
    budget.count(count)
    pos, stored_total, entries = 48, 0, []
    for i in range(count):
        flags = _slice(data, pos, 1, 'WOFF2 table flags')[0]
        pos += 1
        tagnum, transform = flags & 63, flags >> 6
        if tagnum == 63:
            tag = _slice(data, pos, 4, 'WOFF2 custom tag').decode('latin1')
            pos += 4
        else:
            tag = _TAGS[tagnum]
        length, pos = _base128(data, pos)
        if tag in ('glyf', 'loca'):
            _need(transform in (0, 3), 'unsupported WOFF2 glyf/loca transform')
            transformed = transform == 0
        else:
            _need(transform == 0 or (tag == 'hmtx' and transform == 1), 'unsupported WOFF2 transform')
            transformed = transform != 0
        stored, pos = _base128(data, pos) if transformed else (length, pos)
        _need(tag != 'loca' or not transformed or stored == 0, 'transformed loca must have zero length')
        entries.append({'tag': tag, 'original_length': length, 'stream_offset': stored_total,
                        'stored_length': stored, 'transform_version': transform, 'transformed': transformed,
                        'private_candidate': tag not in _KNOWN})
        stored_total += stored
    for i, entry in enumerate(entries) if flavor == b'ttcf' else []:
        if entry['transformed'] and entry['tag'] == 'glyf':
            _need(i + 1 < len(entries) and entries[i + 1]['tag'] == 'loca' and
                  entries[i + 1]['transformed'], 'transformed glyf must precede paired loca')
        if entry['transformed'] and entry['tag'] == 'loca':
            _need(i > 0 and entries[i - 1]['tag'] == 'glyf' and
                  entries[i - 1]['transformed'], 'transformed loca must follow paired glyf')
    if flavor == b'ttcf':
        version = _unpack('>I', data, pos)[0]
        pos += 4
        count_fonts, pos = _u255(data, pos)
        _need(version in (0x10000, 0x20000) and 0 < count_fonts <= budget.limits.max_fonts, 'invalid WOFF2 collection')
        mapping = []
        for _ in range(count_fonts):
            n, pos = _u255(data, pos)
            sfnt = _slice(data, pos, 4, 'WOFF2 collection flavor')
            pos += 4
            _need(sfnt in _SFNT and 0 < n <= budget.limits.max_tables, 'invalid WOFF2 collection font')
            budget.count(n)
            indices = []
            for _ in range(n):
                index, pos = _u255(data, pos)
                _need(index < len(entries), 'WOFF2 table index out of range')
                indices.append(index)
            mapping.append((sfnt, indices))
    else:
        mapping = [(flavor, list(range(count)))]
    raw = _slice(data, pos, compressed_size, 'WOFF2 compressed stream')
    decoded = _brotli(raw, stored_total, budget)
    regions = [(0, pos, 'WOFF2 header/directory'), (pos, compressed_size, 'WOFF2 compressed stream')]
    payloads = []
    for e in entries:
        raw = decoded[e['stream_offset']:e['stream_offset'] + e['stored_length']]
        e.update(_facts(raw))
        # The digest and length describe the stored bytes, not reconstructed glyphs.
        e['checksum'] = {'expected': None, 'actual': None if e['transformed'] else _checksum(raw, e['tag']), 'valid': None}
        payloads.append(raw)
    fonts = []
    for i, (sfnt, indices) in enumerate(mapping):
        tags = [entries[j]['tag'] for j in indices]
        _need(len(tags) == len(set(tags)), 'duplicate WOFF2 font table tag')
        selected = {entries[j]['tag']: payloads[j] for j in indices if not entries[j]['transformed']}
        transformed = {entries[j]['tag']: entries[j] for j in indices if entries[j]['tag'] in ('glyf', 'loca')}
        if transformed:
            _need(set(transformed) == {'glyf', 'loca'} and transformed['glyf']['transformed'] == transformed['loca']['transformed'],
                  'unpaired WOFF2 glyf/loca transform')
            glyf_index = next(j for j in indices if entries[j]['tag'] == 'glyf')
            loca_index = next(j for j in indices if entries[j]['tag'] == 'loca')
            _need(loca_index > glyf_index, 'WOFF2 loca must follow glyf')
            if flavor == b'ttcf':
                _need(loca_index == glyf_index + 1, 'mismatched WOFF2 collection glyf/loca pair')
        fonts.append({'index': i, 'flavor_hex': sfnt.hex(), 'table_indices': indices,
                      'tables': [entries[j] for j in indices], **_inventory(selected, budget)})
    optional = _optional(data, pos + compressed_size, (mo, ml, original), (po, pl), regions, budget, 2)
    return {'format': 'WOFF2', 'version': [major, minor], 'reserved_nonzero': bool(reserved),
            'total_sfnt_size_reference': sfnt_size, 'compressed_stream_offset': pos,
            'compressed_stream_length': compressed_size, 'decoded_stream_length': len(decoded),
            'transform_reconstruction': False, 'fonts': fonts, **optional, **_layout(data, regions, budget)}


def inspect_font(data, *, limits=None):
    """Return structural facts; raise only FFWOFFError for rejected input.

    Unknown table tags are private *candidates*, not claims of malicious content.
    Overlaps, checksum mismatches and nonzero gaps are facts rather than refusal.
    CBLC/EBLC inventory describes glyph ranges, not decoded bitmap image pixels.
    """
    try:
        if limits is None:
            limits = Limits()
        _need(isinstance(limits, Limits), 'limits must be Limits')
        _need(all(type(value) is int and value > 0 for value in vars(limits).values()), 'invalid limits')
        _need(limits.max_input <= Limits.max_input and limits.max_decoded <= Limits.max_decoded,
              'byte limits exceed hard ceiling')
        _need(limits.max_tables <= Limits.max_tables and limits.max_fonts <= Limits.max_fonts and
              limits.max_records <= Limits.max_records, 'record limits exceed hard ceiling')
        _need(isinstance(data, (bytes, bytearray, memoryview)), 'font data must be bytes')
        _need((data.nbytes if isinstance(data, memoryview) else len(data)) <= limits.max_input,
              'input byte limit exceeded')
        data = bytes(data)
        budget = _Budget(limits)
        if data[:4] == b'wOFF':
            report = _woff(data, budget)
        elif data[:4] == b'wOF2':
            report = _woff2(data, budget)
        elif data[:4] in _SFNT or data[:4] == b'ttcf':
            report = _sfnt(data, budget)
        else:
            raise FFWOFFError('not a supported font container')
        return {**_facts(data), **report, 'processed_bytes': budget.decoded}
    except FFWOFFError:
        raise
    except Exception as exc:
        raise FFWOFFError('malformed font: ' + type(exc).__name__) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file')
    parser.add_argument('--max-input', type=int, default=Limits.max_input)
    parser.add_argument('--max-decoded', type=int, default=Limits.max_decoded)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        limits = Limits(max_input=args.max_input, max_decoded=args.max_decoded)
        _need(limits.max_input > 0 and limits.max_decoded > 0, 'limits must be positive')
        _need(limits.max_input <= Limits.max_input and limits.max_decoded <= Limits.max_decoded,
              'byte limits exceed hard ceiling')
        with open(args.file, 'rb') as handle:
            data = handle.read(limits.max_input + 1)
        print(json.dumps(inspect_font(data, limits=limits), indent=2))
        return 0
    except (OSError, FFWOFFError) as exc:
        print('ff_woff_inspect: ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
