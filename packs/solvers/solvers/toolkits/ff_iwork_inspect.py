#!/usr/bin/env python3
"""Bounded, offline iWork ZIP/IWA structural inspection.

IWA uses Snappy type-0 chunks WITHOUT the standard stream identifier or CRC.
The documented ArchiveInfo/MessageInfo length fields delimit opaque protobuf
payloads; payload reports expose field numbers/wire types, never guessed names,
strings, or submessages. Nothing is extracted, rendered, or executed.

References: obriensp/iWorkFileFormat/Docs/index.md; google/snappy framing_format.txt
and format_description.txt; protobuf.dev/programming-guides/encoding/.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, fields
from functools import wraps
import hashlib
import io
import json
from pathlib import Path
import plistlib
import stat
import struct
import sys
import zipfile
from xml.parsers import expat


class IWorkError(ValueError):
    """Invalid, unsupported, or over-budget input; the only parser exception."""


@dataclass(frozen=True)
class Limits:
    max_input: int = 64 * 1024 * 1024
    max_expanded: int = 128 * 1024 * 1024
    max_stream: int = 16 * 1024 * 1024
    max_member: int = 16 * 1024 * 1024
    max_members: int = 5000
    max_chunks: int = 4096
    max_records: int = 10000
    max_fields: int = 100000
    max_depth: int = 32
    max_ratio: int = 200
    max_plist: int = 1024 * 1024


_DEFAULT = Limits()
_MAGIC = b'\xff\x06\x00\x00sNaPpY'
_WIRE_NAMES = {0: 'varint', 1: 'fixed64', 2: 'length_delimited',
               3: 'start_group', 4: 'end_group', 5: 'fixed32'}


def _closed(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except IWorkError:
            raise
        except Exception as exc:
            raise IWorkError(f'{fn.__name__}: invalid input ({type(exc).__name__})') from exc
    return call


def _limits(value):
    if value is None:
        return _DEFAULT
    if not isinstance(value, Limits):
        raise IWorkError('limits must be Limits')
    for item in fields(Limits):
        n = getattr(value, item.name)
        if type(n) is not int or not 1 <= n <= getattr(_DEFAULT, item.name):
            raise IWorkError(f'{item.name} must be a positive integer no larger than the default')
    return value


def _blob(value, cap):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise IWorkError('input must be bytes-like')
    if (value.nbytes if isinstance(value, memoryview) else len(value)) > cap:
        raise IWorkError('input size limit')
    return bytes(value)


class _Budget:
    def __init__(self, limits):
        self.limits = limits
        self.expanded = self.members = self.chunks = self.records = self.fields = 0

    def take(self, name, count=1):
        value = getattr(self, name) + count
        if value > getattr(self.limits, 'max_' + name):
            raise IWorkError(f'{name} limit')
        setattr(self, name, value)


def _varint(data, pos, end, bits=64):
    value = 0
    for shift in range(0, bits, 7):
        if pos >= end:
            raise IWorkError('truncated varint')
        b = data[pos]
        pos += 1
        value |= (b & 127) << shift
        if value >= 1 << bits:
            raise IWorkError('varint overflow')
        if not b & 128:
            return value, pos
    raise IWorkError('overlong varint')


def _scan_fields(data, budget):
    """Nonrecursive wire scanner; length-delimited values stay opaque."""
    rows, groups, pos, end = [], [], 0, len(data)
    while pos < end:
        budget.take('fields')
        start = pos
        key, pos = _varint(data, pos, end, 32)
        number, wire = key >> 3, key & 7
        if number == 0 or number > 0x1fffffff or wire not in _WIRE_NAMES:
            raise IWorkError('invalid protobuf tag')
        depth, value_start, scalar = len(groups), pos, None
        if wire == 0:
            scalar, pos = _varint(data, pos, end)
        elif wire in (1, 5):
            pos += 8 if wire == 1 else 4
        elif wire == 2:
            size, pos = _varint(data, pos, end, 32)
            value_start = pos
            pos += size
        elif wire == 3:
            if len(groups) >= budget.limits.max_depth:
                raise IWorkError('protobuf group depth limit')
            groups.append(number)
        else:
            if not groups or groups.pop() != number:
                raise IWorkError('mismatched protobuf end-group')
            depth = len(groups)
        if pos > end:
            raise IWorkError('protobuf value extends past end')
        rows.append({'field_number': number, 'wire_type': wire, 'wire_name': _WIRE_NAMES[wire],
                     'offset': start, 'encoded_length': pos - start, 'depth': depth,
                     'value_offset': value_start, 'value_length': pos - value_start,
                     '_varint': scalar})
    if groups:
        raise IWorkError('unterminated protobuf group')
    return rows


def _facts(rows):
    return [{key: value for key, value in row.items() if not key.startswith('_')} for row in rows]


@_closed
def protobuf_fields(data, *, limits=None):
    """Return exact wire facts only; no scalar values or inferred payload types."""
    lim = _limits(limits)
    return _facts(_scan_fields(_blob(data, lim.max_stream), _Budget(lim)))


def _crc_table():
    rows = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82f63b78 if value & 1 else 0)
        rows.append(value)
    return tuple(rows)


_CRC_TABLE = _crc_table()


def _masked_crc32c(data):
    value = 0xffffffff
    for b in data:
        value = _CRC_TABLE[(value ^ b) & 255] ^ (value >> 8)
    value ^= 0xffffffff
    return (((value >> 15) | (value << 17)) + 0xa282ead8) & 0xffffffff


def _decode_snappy(data, framing, budget):
    if framing not in ('iwa', 'snappy', 'auto'):
        raise IWorkError('unknown Snappy framing')
    if framing == 'auto':
        framing = 'snappy' if data.startswith(_MAGIC) else 'iwa'
    if not data or (framing == 'snappy' and not data.startswith(_MAGIC)):
        raise IWorkError('missing Snappy stream identifier or empty IWA')
    out, rows, pos = bytearray(), [], 0
    while pos < len(data):
        budget.take('chunks')
        start = pos
        if len(data) - pos < 4:
            raise IWorkError('truncated Snappy chunk header')
        kind, size = data[pos], int.from_bytes(data[pos + 1:pos + 4], 'little')
        pos += 4
        if size > len(data) - pos:
            raise IWorkError('Snappy chunk extends past end')
        chunk = data[pos:pos + size]
        pos += size
        row = {'offset': start, 'type': kind, 'compressed_length': size,
               'output_offset': len(out), 'output_length': 0, 'checksum': 'absent'}
        if framing == 'snappy' and kind == 255:
            if chunk != b'sNaPpY':
                raise IWorkError('invalid Snappy stream identifier')
            row['kind'] = 'stream_identifier'
        elif framing == 'snappy' and 128 <= kind <= 254:
            row['kind'] = 'skippable'
        else:
            if framing == 'iwa' and kind != 0:
                raise IWorkError('unsupported IWA chunk type')
            if framing == 'snappy' and kind not in (0, 1):
                raise IWorkError('unskippable Snappy chunk type')
            expected_crc = None
            if framing == 'snappy':
                if len(chunk) < 4:
                    raise IWorkError('missing Snappy checksum')
                expected_crc = int.from_bytes(chunk[:4], 'little')
                chunk = chunk[4:]
            if kind == 0:
                expected, _ = _varint(chunk, 0, len(chunk), 32)
            else:
                expected = len(chunk)
            if expected > 65536 or expected > budget.limits.max_stream - len(out):
                raise IWorkError('Snappy decoded size limit')
            budget.take('expanded', expected)
            if kind == 0:
                # Reuse the maintained raw codec; its size prefix is checked
                # before it can allocate its output. IWA framing is handled here.
                import snappy
                plain = snappy.decompress(chunk)
                if len(plain) != expected:
                    raise IWorkError('Snappy decoded size mismatch')
            else:
                plain = chunk
            if expected_crc is not None:
                if _masked_crc32c(plain) != expected_crc:
                    raise IWorkError('Snappy CRC32C mismatch')
                row['checksum'] = 'valid'
            row.update(kind='compressed' if kind == 0 else 'uncompressed', output_length=len(plain))
            out.extend(plain)
        rows.append(row)
    return bytes(out), {'framing': framing, 'chunks': rows, 'uncompressed_size': len(out),
                        'sha256': hashlib.sha256(out).hexdigest()}


@_closed
def decode_snappy_stream(data, *, framing='auto', limits=None):
    """Return (decoded bytes, framing report); IWA and standard Snappy differ."""
    lim = _limits(limits)
    return _decode_snappy(_blob(data, lim.max_input), framing, _Budget(lim))


def _iwa(data, framing, budget):
    plain, report = _decode_snappy(data, framing, budget)
    records, pos = [], 0
    while pos < len(plain):
        budget.take('records')
        start = pos
        size, pos = _varint(plain, pos, len(plain), 32)
        if size > len(plain) - pos:
            raise IWorkError('IWA ArchiveInfo extends past end')
        header_offset = pos
        header = plain[pos:pos + size]
        rows = _scan_fields(header, budget)
        pos += size
        payloads = []
        for row in rows:
            if row['depth'] != 0 or row['field_number'] != 2:
                continue
            if row['wire_type'] != 2:
                raise IWorkError('IWA MessageInfo has wrong wire type')
            a = row['value_offset']
            info = _scan_fields(header[a:a + row['value_length']], budget)
            lengths = [r for r in info if r['depth'] == 0 and r['field_number'] == 3]
            if len(lengths) != 1 or lengths[0]['wire_type'] != 0:
                raise IWorkError('IWA MessageInfo needs one varint length')
            length = lengths[0]['_varint']
            if length > 0xffffffff or length > len(plain) - pos:
                raise IWorkError('IWA payload extends past end')
            payload = plain[pos:pos + length]
            payloads.append({'offset': pos, 'length': length,
                             'sha256': hashlib.sha256(payload).hexdigest(),
                             'message_info_fields': _facts(info),
                             'fields': _facts(_scan_fields(payload, budget))})
            pos += length
        records.append({'offset': start, 'archive_info_offset': header_offset,
                        'archive_info_length': size, 'archive_info_fields': _facts(rows),
                        'payloads': payloads})
    report.update(format='iwa', records=records,
                  payload_semantics='unknown; length-delimited fields are opaque')
    return report


@_closed
def inspect_iwa(data, *, framing='auto', limits=None):
    """Inspect framed IWA objects using only the documented envelope lengths."""
    lim = _limits(limits)
    return _iwa(_blob(data, lim.max_input), framing, _Budget(lim))


def _zip_preflight(data, limit):
    """Bound directory entry count before ZipFile constructs ZipInfo objects."""
    pos = data.rfind(b'PK\x05\x06', max(0, len(data) - 65557))
    if pos < 0 or len(data) - pos < 22:
        raise IWorkError('ZIP end record missing')
    disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from('<4H2IH', data, pos + 4)
    if pos + 22 + comment != len(data) or disk or cd_disk or disk_count != count:
        raise IWorkError('unsupported ZIP layout')
    if count == 65535 or size == 0xffffffff or offset == 0xffffffff:
        raise IWorkError('ZIP64 bundles are unsupported')
    if count > limit or offset + size != pos:
        raise IWorkError('ZIP directory count or bounds')
    cursor, seen = offset, 0
    while cursor < pos:
        if seen >= limit or cursor + 46 > pos or data[cursor:cursor + 4] != b'PK\x01\x02':
            raise IWorkError('invalid ZIP directory')
        name, extra, note = struct.unpack_from('<3H', data, cursor + 28)
        cursor += 46 + name + extra + note
        seen += 1
    if cursor != pos or seen != count:
        raise IWorkError('ZIP directory size or count mismatch')


def _safe_path(info):
    name = info.filename
    if info.orig_filename != name or not name or '\\' in name or ':' in name or name.startswith('/'):
        raise IWorkError('unsafe ZIP path')
    parts = name.rstrip('/').split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise IWorkError('unsafe ZIP path')
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise IWorkError('ZIP symlink refused')
    return name


def _preflight_plist(data, lim):
    if not data.startswith(b'bplist00'):
        parser = expat.ParserCreate()
        depth = count = 0
        def start(name, attrs):
            nonlocal depth, count
            depth += 1
            count += 1
            if depth > lim.max_depth + 1 or count > lim.max_fields:
                raise IWorkError('plist XML structure limit')
        def end(name):
            nonlocal depth
            depth -= 1
        def entity(*args):
            raise IWorkError('plist entity declaration refused')
        parser.StartElementHandler = start
        parser.EndElementHandler = end
        parser.EntityDeclHandler = entity
        parser.ExternalEntityRefHandler = entity
        parser.Parse(data, True)
        return
    if len(data) < 40:
        raise IWorkError('truncated binary plist trailer')
    width, ref_width, count, top, table = struct.unpack_from('>6xBBQQQ', data, len(data) - 32)
    if (width not in (1, 2, 4, 8) or ref_width not in (1, 2, 4, 8)
            or not 0 < count <= lim.max_fields or top >= count or table < 8
            or table + count * width > len(data) - 32):
        raise IWorkError('binary plist trailer bounds')
    offsets = [int.from_bytes(data[table + i * width:table + (i + 1) * width], 'big')
               for i in range(count)]
    edges, references = {}, 0
    for index, pos in enumerate(offsets):
        if not 8 <= pos < table:
            raise IWorkError('binary plist object offset')
        token = data[pos]
        kind, size = token >> 4, token & 15
        pos += 1
        if kind in (4, 5, 6, 10, 13) and size == 15:
            if pos >= table or data[pos] >> 4 != 1:
                raise IWorkError('binary plist length marker')
            n = 1 << (data[pos] & 15)
            pos += 1
            if n > 8 or pos + n > table:
                raise IWorkError('binary plist length bounds')
            size = int.from_bytes(data[pos:pos + n], 'big')
            pos += n
        if kind in (10, 13):
            slots = size * (2 if kind == 13 else 1)
            references += slots
            if references > lim.max_fields or pos + slots * ref_width > table:
                raise IWorkError('binary plist reference limit')
            refs = [int.from_bytes(data[pos + i * ref_width:pos + (i + 1) * ref_width], 'big')
                    for i in range(slots)]
            if any(ref >= count for ref in refs):
                raise IWorkError('binary plist reference bounds')
            edges[index] = refs
        elif kind in (4, 5, 6):
            if pos + size * (2 if kind == 6 else 1) > table:
                raise IWorkError('binary plist scalar bounds')
        elif kind in (1, 2):
            if pos + (1 << size) > table:
                raise IWorkError('binary plist number bounds')
        elif kind == 8 and pos + size + 1 > table:
            raise IWorkError('binary plist UID bounds')
    active, checked, stack, visits = set(), set(), [(top, 0, False)], 0
    while stack:
        index, depth, leaving = stack.pop()
        if leaving:
            active.remove(index)
            checked.add(index)
            continue
        visits += 1
        if depth > lim.max_depth or visits > lim.max_fields or index in active:
            raise IWorkError('binary plist cycle or depth limit')
        if index in checked:
            continue
        active.add(index)
        stack.append((index, depth, True))
        stack.extend((ref, depth + 1, False) for ref in edges.get(index, ()))


def _plist(data, lim):
    if len(data) > lim.max_plist:
        raise IWorkError('plist size limit')
    if b'<!ENTITY' in data.upper():
        raise IWorkError('plist entity declaration refused')
    _preflight_plist(data, lim)
    value = plistlib.loads(data)
    pending, count, seen = [(value, 0)], 0, set()
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > lim.max_fields or depth > lim.max_depth:
            raise IWorkError('plist structure limit')
        if isinstance(node, (dict, list, tuple)):
            if id(node) in seen:
                continue
            seen.add(id(node))
            children = node.values() if isinstance(node, dict) else node
            if len(children) > lim.max_fields - count - len(pending):
                raise IWorkError('plist structure limit')
            pending.extend((v, depth + 1) for v in children)
    return {'encoding': 'binary' if data.startswith(b'bplist00') else 'xml',
            'root_type': type(value).__name__, 'nodes': count,
            'top_level_keys': sorted(value) if isinstance(value, dict) else []}


def _bundle(data, budget, prefix='', depth=0):
    lim = budget.limits
    _zip_preflight(data, lim.max_members - budget.members)
    rows, seen, marker = [], set(), False
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        # Reject every member before opening any body; share limits across Index.zip.
        for info in infos:
            budget.take('members')
            name = _safe_path(info)
            if name.casefold() in seen:
                raise IWorkError('duplicate ZIP member')
            seen.add(name.casefold())
            if info.flag_bits & 1 or info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise IWorkError('encrypted or unsupported ZIP compression')
            if (info.file_size > lim.max_member or info.file_size > lim.max_ratio * max(1, info.compress_size)
                    or info.file_size < 0):
                raise IWorkError('ZIP member size or ratio limit')
        for info in infos:
            name = info.filename
            if info.is_dir():
                continue
            budget.take('expanded', info.file_size)
            with archive.open(info) as source:
                body = source.read(info.file_size + 1)
                if len(body) != info.file_size or source.read(1):
                    raise IWorkError('ZIP size mismatch')
            low, base = name.casefold(), name.rsplit('/', 1)[-1].casefold()
            kind = ('iwa' if low.endswith('.iwa') else 'index_zip' if base == 'index.zip'
                    else 'plist' if low.endswith('.plist') else 'preview' if base.startswith('preview')
                    else 'asset' if 'data' in low.split('/')[:-1]
                    else 'metadata' if 'metadata' in low.split('/')[:-1] else 'other')
            row = {'path': prefix + name, 'kind': kind, 'size': len(body),
                   'compressed_size': info.compress_size, 'sha256': hashlib.sha256(body).hexdigest()}
            if kind == 'iwa':
                marker = True
                row['iwa'] = _iwa(body, 'iwa', budget)
            elif kind == 'index_zip':
                if depth:
                    raise IWorkError('nested Index.zip depth limit')
                nested, nested_marker = _bundle(body, budget, prefix + name + '!/', depth + 1)
                row['members'] = nested
                marker |= nested_marker
            elif kind == 'plist':
                row['plist'] = _plist(body, lim)
                marker |= 'metadata' in low.split('/')[:-1]
            rows.append(row)
    return rows, marker


@_closed
def inspect_bundle(data, *, limits=None):
    """Inventory an iWork ZIP, optionally including one nested Index.zip."""
    lim = _limits(limits)
    raw = _blob(data, lim.max_input)
    budget = _Budget(lim)
    rows, marker = _bundle(raw, budget)
    if not marker:
        raise IWorkError('no iWork IWA or Metadata plist member found')
    return {'format': 'iwork_zip', 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'members': rows, 'member_count': budget.members, 'expanded_bytes': budget.expanded,
            'chunks': budget.chunks, 'records': budget.records, 'protobuf_field_count': budget.fields}


@_closed
def inspect(data, *, format='auto', limits=None):
    """Dispatch an explicitly selected format, or ZIP/standard-Snappy/IWA by magic."""
    lim = _limits(limits)
    raw = _blob(data, lim.max_input)
    if format == 'auto':
        format = 'bundle' if raw.startswith(b'PK\x03\x04') else 'snappy' if raw.startswith(_MAGIC) else 'iwa'
    if format == 'bundle':
        return inspect_bundle(raw, limits=lim)
    if format == 'iwa':
        return inspect_iwa(raw, framing='iwa', limits=lim)
    if format == 'snappy':
        return decode_snappy_stream(raw, framing='snappy', limits=lim)[1]
    if format == 'protobuf':
        return {'format': 'protobuf', 'size': len(raw), 'fields': protobuf_fields(raw, limits=lim)}
    raise IWorkError('unknown input format')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='local ZIP/iWork bundle, IWA, Snappy stream or protobuf file')
    parser.add_argument('--format', choices=('auto', 'bundle', 'iwa', 'snappy', 'protobuf'), default='auto')
    try:
        args = parser.parse_args(argv)
        with Path(args.file).open('rb') as source:
            data = source.read(_DEFAULT.max_input + 1)
        print(json.dumps(inspect(data, format=args.format), indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f'ff_iwork_inspect: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
