#!/usr/bin/env python3
"""Strict offline DICOM extraction. Requires pydicom>=3; pixel decode also needs NumPy.

inspect_dicom() returns JSON-like metadata plus original binary payloads. No file
references are followed. Compression codecs are optional: original fragments and
codestreams can be extracted without one. Ambiguous frame boundaries stay unknown.
CLI: health2_dicom.py FILE [--out NEW_DIRECTORY] [--decode] [--syntax UID]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
from pathlib import Path
import struct
import sys
import warnings
import zlib
from functools import wraps

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_BYTES = 64 * 1024 * 1024
MAX_SAMPLES = 16 * 1024 * 1024
MAX_ELEMENTS = 100000
LONG_VR = {'OB', 'OD', 'OF', 'OL', 'OV', 'OW', 'SQ', 'UC', 'UN', 'UR', 'UT', 'SV', 'UV'}
VRS = LONG_VR | {'AE', 'AS', 'AT', 'CS', 'DA', 'DS', 'DT', 'FD', 'FL', 'IS', 'LO', 'LT', 'PN', 'SH', 'SL', 'SS', 'ST', 'TM', 'UI', 'UL', 'US'}
PIXELS = {0x7FE00010, 0x7FE00008, 0x7FE00009}


class Health2DicomError(ValueError):
    """Malformed, unsupported, oversized DICOM or unavailable dependency/codec."""


def _guard(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Health2DicomError:
            raise
        except Exception as exc:
            raise Health2DicomError(f'{fn.__name__}: {exc}') from None
    return wrapped


def _deps():
    import pydicom
    from pydicom.datadict import get_entry, get_private_entry
    return pydicom, get_entry, get_private_entry


@_guard
def lookup_tag(tag, private_creator=None):
    """Full installed pydicom public/repeater/private dictionary; unknown -> None."""
    pd, get_entry, get_private = _deps()
    tag = pd.tag.Tag(tag)
    try:
        entry = get_private(tag, private_creator) if private_creator else get_entry(tag)
    except KeyError:
        return None
    return dict(zip(('vr', 'vm', 'name', 'retired', 'keyword'), entry))


def _bytes(data):
    if not isinstance(data, (bytes, bytearray)) or not 8 <= len(data) <= MAX_BYTES:
        raise Health2DicomError('expected 8..64 MiB of bytes')
    return bytes(data)


def _header(data, pos, end, explicit, endian):
    if pos + 8 > end:
        raise Health2DicomError('truncated element header')
    g, e = struct.unpack_from(endian + 'HH', data, pos)
    tag = (g << 16) | e
    if g == 0xFFFE:
        return tag, '', struct.unpack_from(endian + 'I', data, pos + 4)[0], pos + 8
    if explicit:
        vr = data[pos + 4:pos + 6].decode('ascii')
        if vr not in VRS:
            raise Health2DicomError('invalid VR')
        if vr in LONG_VR:
            if pos + 12 > end or data[pos + 6:pos + 8] != b'\0\0':
                raise Health2DicomError('truncated long VR or nonzero reserved bytes')
            length, start = struct.unpack_from(endian + 'I', data, pos + 8)[0], pos + 12
        else:
            length, start = struct.unpack_from(endian + 'H', data, pos + 6)[0], pos + 8
    else:
        entry = lookup_tag(tag)
        vr = entry['vr'] if entry else 'UN'
        length, start = struct.unpack_from(endian + 'I', data, pos + 4)[0], pos + 8
    return tag, vr, length, start


def _validate(data, explicit, endian):
    """Bounds-first structural pass; pydicom normally tolerates truncated values."""
    count = 0

    def walk(pos, end, depth=0, terminator=None, local_explicit=explicit, local_endian=endian):
        nonlocal count
        if depth > 32:
            raise Health2DicomError('sequence nesting limit')
        seen = set()
        while pos < end:
            count += 1
            if count > MAX_ELEMENTS:
                raise Health2DicomError('element count limit')
            tag, vr, size, start = _header(data, pos, end, local_explicit, local_endian)
            if tag >> 16 == 0xFFFE:
                if tag == terminator and size == 0:
                    return start
                raise Health2DicomError('unexpected item/delimiter')
            if tag in seen:
                raise Health2DicomError('duplicate element tag')
            seen.add(tag)
            undefined = size == 0xFFFFFFFF
            if not undefined and (size % 2 or start + size > end):
                raise Health2DicomError('odd or truncated element value')
            if vr == 'SQ' or (undefined and vr == 'UN' and tag not in PIXELS):
                # PS3.5 6.2.2: undefined-length UN encapsulates implicit-VR LE items.
                seq_explicit, seq_endian = (False, '<') if vr == 'UN' else (local_explicit, local_endian)
                seq_end = end if undefined else start + size
                pos = start
                closed = False
                while pos < seq_end:
                    count += 1
                    if count > MAX_ELEMENTS:
                        raise Health2DicomError('item count limit')
                    itag, _, ilen, ipos = _header(data, pos, seq_end, False, seq_endian)
                    if itag == 0xFFFEE0DD and ilen == 0 and undefined:
                        pos, closed = ipos, True
                        break
                    if itag != 0xFFFEE000:
                        raise Health2DicomError('expected sequence item')
                    if ilen == 0xFFFFFFFF:
                        pos = walk(ipos, seq_end, depth + 1, 0xFFFEE00D, seq_explicit, seq_endian)
                    else:
                        if ilen % 2 or ipos + ilen > seq_end:
                            raise Health2DicomError('truncated sequence item')
                        pos = walk(ipos, ipos + ilen, depth + 1, None, seq_explicit, seq_endian)
                if undefined and not closed:
                    raise Health2DicomError('missing sequence delimiter')
            elif undefined and tag == 0x7FE00010:
                pos = start
                while True:
                    count += 1
                    if count > MAX_ELEMENTS:
                        raise Health2DicomError('fragment count limit')
                    itag, _, ilen, ipos = _header(data, pos, end, False, local_endian)
                    if itag == 0xFFFEE0DD and ilen == 0:
                        pos = ipos
                        break
                    if itag != 0xFFFEE000 or ilen == 0xFFFFFFFF or ilen % 2 or ipos + ilen > end:
                        raise Health2DicomError('invalid encapsulated item')
                    pos = ipos + ilen
            elif undefined:
                raise Health2DicomError('unsupported undefined-length value')
            else:
                pos = start + size
        if terminator:
            raise Health2DicomError('missing item delimiter')
        return pos
    walk(0, len(data))


def _read(data, syntax):
    pd, _, _ = _deps()
    part10 = len(data) >= 132 and data[128:132] == b'DICM'
    meta = pd.dataset.FileMetaDataset()
    if part10:
        pos = 132
        seen = set()
        while pos + 4 <= len(data) and data[pos:pos + 2] == b'\x02\0':
            tag, vr, size, start = _header(data, pos, len(data), True, '<')
            if size == 0xFFFFFFFF or size % 2 or start + size > len(data) or tag in seen:
                raise Health2DicomError('invalid file meta')
            seen.add(tag)
            pos = start + size
        _validate(data[132:pos], True, '<')
        meta = pd.filereader.read_dataset(io.BytesIO(data[132:pos]), False, True)
        if 'TransferSyntaxUID' not in meta:
            raise Health2DicomError('missing TransferSyntaxUID')
        actual = str(meta.TransferSyntaxUID)
        if syntax and syntax != actual:
            raise Health2DicomError('syntax override conflicts with file meta')
        syntax = actual
        body = data[pos:]
    else:
        if not syntax:
            raise Health2DicomError('bare dataset requires explicit --syntax UID')
        body = data
    uid = pd.uid.UID(syntax)
    if not uid.is_transfer_syntax:
        raise Health2DicomError('unknown transfer syntax')
    if uid.is_deflated:
        dec = zlib.decompressobj(-15)
        body = dec.decompress(body, MAX_BYTES + 1)
        if len(body) > MAX_BYTES or dec.unconsumed_tail or not dec.eof or dec.unused_data not in (b'', b'\0'):
            raise Health2DicomError('invalid/oversized deflated dataset')
    if not body:
        raise Health2DicomError('empty dataset')
    _validate(body, not uid.is_implicit_VR, '<' if uid.is_little_endian else '>')
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        ds = pd.filereader.read_dataset(io.BytesIO(body), uid.is_implicit_VR, uid.is_little_endian)
    ds.file_meta = meta
    ds.file_meta.TransferSyntaxUID = uid
    return ds, part10


def _encapsulated(raw, nframes, ext_offsets=None, ext_lengths=None):
    pos, items, offsets = 0, [], []
    origin = None
    while pos < len(raw):
        if pos + 8 > len(raw):
            raise Health2DicomError('truncated fragment header')
        tag, size = struct.unpack_from('<II', raw, pos)
        if tag != 0xE000FFFE or size % 2 or pos + 8 + size > len(raw):
            raise Health2DicomError('invalid fragment')
        if items:
            if origin is None:
                origin = pos
            offsets.append(pos - origin)
        items.append(raw[pos + 8:pos + 8 + size])
        pos += 8 + size
    if len(items) < 2 or len(items[0]) % 4 or any(not x for x in items[1:]):
        raise Health2DicomError('missing BOT/fragments or invalid BOT')
    bot = list(struct.unpack('<' + 'I' * (len(items[0]) // 4), items[0]))
    fragments = items[1:]
    frames = None
    note = None
    if (ext_offsets is None) != (ext_lengths is None):
        raise Health2DicomError('both extended offsets and lengths required')
    if ext_offsets is not None:
        if bot or len(ext_offsets) != nframes * 8 or len(ext_lengths) != nframes * 8:
            raise Health2DicomError('invalid extended offset table')
        eo = list(struct.unpack('<' + 'Q' * nframes, ext_offsets))
        el = list(struct.unpack('<' + 'Q' * nframes, ext_lengths))
        if eo != offsets or len(fragments) != nframes:
            raise Health2DicomError('extended offsets must identify one fragment per frame')
        frames = []
        for frag, length in zip(fragments, el):
            if length not in (len(frag), len(frag) - 1) or (length % 2 and frag[-1:] != b'\0'):
                raise Health2DicomError('extended frame length mismatch')
            frames.append(frag[:length])
    elif bot:
        index_by_offset = {offset: i for i, offset in enumerate(offsets)}
        if len(bot) != nframes or bot[0] != 0 or bot != sorted(set(bot)) or any(x not in index_by_offset for x in bot):
            raise Health2DicomError('BOT does not identify ordered frame starts')
        indexes = [index_by_offset[x] for x in bot] + [len(fragments)]
        frames = [b''.join(fragments[a:b]) for a, b in zip(indexes, indexes[1:])]
    elif nframes == 1:
        frames = [b''.join(fragments)]
    elif nframes == len(fragments):
        frames = fragments[:]
    else:
        note = 'Empty offset table and ambiguous multi-fragment frames; only fragments extracted'
    return {'fragments': fragments, 'frames': frames, 'basic_offsets': bot, 'boundary_note': note}


def _pixels(ds, decode):
    keys = [tag for tag in PIXELS if tag in ds]
    if not keys:
        return None
    if len(keys) != 1:
        raise Health2DicomError('multiple pixel data representations')
    tag = keys[0]
    raw = ds[tag].value
    rows, cols, samples = int(ds.Rows), int(ds.Columns), int(ds.SamplesPerPixel)
    frames, bits = int(ds.get('NumberOfFrames', 1)), int(ds.BitsAllocated)
    if min(rows, cols, samples, frames) < 1 or frames > MAX_ELEMENTS or rows * cols * samples * frames > MAX_SAMPLES:
        raise Health2DicomError('pixel dimensions invalid or exceed sample limit')
    if bits not in (1, 8, 16, 32, 64):
        raise Health2DicomError('unsupported BitsAllocated')
    if tag == 0x7FE00010:
        stored, high, representation = int(ds.BitsStored), int(ds.HighBit), int(ds.PixelRepresentation)
        if not 1 <= stored <= bits or high != stored - 1 or representation not in (0, 1):
            raise Health2DicomError('invalid stored bits, high bit or pixel representation')
        if bits == 1 and representation:
            raise Health2DicomError('bit-packed pixels must be unsigned')
    elif bits != (32 if tag == 0x7FE00008 else 64):
        raise Health2DicomError('float pixel width mismatch')
    if samples > 1 and int(ds.PlanarConfiguration) not in (0, 1):
        raise Health2DicomError('invalid planar configuration')
    uid = ds.file_meta.TransferSyntaxUID
    out = {'tag': f'{tag:08X}', 'rows': rows, 'columns': cols, 'samples_per_pixel': samples,
           'number_of_frames': frames, 'bits_allocated': bits, 'raw': raw,
           'compressed': uid.is_compressed, 'photometric': str(ds.get('PhotometricInterpretation', ''))}
    if uid.is_compressed:
        if tag != 0x7FE00010 or not ds[tag].is_undefined_length:
            raise Health2DicomError('compressed PixelData must be encapsulated')
        out.update(_encapsulated(raw, frames, ds.get('ExtendedOffsetTable'), ds.get('ExtendedOffsetTableLengths')))
    else:
        if ds[tag].is_undefined_length:
            raise Health2DicomError('native PixelData cannot be encapsulated')
        frame_bits = rows * cols * samples * bits
        if out['photometric'] == 'YBR_FULL_422':
            if samples != 3 or cols % 2:
                raise Health2DicomError('invalid YBR_FULL_422 layout')
            frame_bits = rows * cols * 2 * bits
        required = (frame_bits * frames + 7) // 8
        if len(raw) != required + required % 2:
            raise Health2DicomError('native pixel byte length mismatch')
        out['frames'] = [raw[i * (frame_bits // 8):(i + 1) * (frame_bits // 8)] for i in range(frames)] if frame_bits % 8 == 0 else None
        out['boundary_note'] = None if frame_bits % 8 == 0 else 'Bit-packed frame boundaries; use --decode for samples'
    if decode:
        # raw=True disables optional YBR->RGB display conversion; no LUT/windowing applied.
        from pydicom.pixels import pixel_array
        arr = pixel_array(ds, raw=True)
        if arr.size != rows * cols * samples * frames:
            raise Health2DicomError('decoded sample count mismatch')
        out['decoded'] = arr
    return out


def _value(value):
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, bytes):
        return {'length': len(value), 'sha256': hashlib.sha256(value).hexdigest(), 'hex_preview': value[:64].hex()}
    if isinstance(value, (list, tuple)) or type(value).__name__ == 'MultiValue':
        return [_value(x) for x in value]
    return str(value)


@_guard
def inspect_dicom(data, *, decode_pixels=False, transfer_syntax=None):
    """Extract metadata, DICOMDIR, SR, embedded documents and pixel bytes/samples."""
    data = _bytes(data)
    ds, part10 = _read(data, transfer_syntax)
    report = {'part10': part10, 'transfer_syntax': str(ds.file_meta.TransferSyntaxUID),
              'transfer_syntax_name': ds.file_meta.TransferSyntaxUID.name,
              'preamble_nonzero': part10 and any(data[:128]), 'elements': [],
              'directory_records': [], 'structured_report': [], 'documents': [],
              'binary_elements': [], 'flags': []}

    def flag_scan(value):
        if isinstance(value, bytes):
            value = value.decode('latin-1')
        report['flags'].extend(flagfmt.TEXT.findall(str(value)))

    flag_scan(data)

    def walk(node, prefix='', depth=0):
        if depth > 32:
            raise Health2DicomError('metadata nesting limit')
        if 'EncapsulatedDocument' in node:
            payload = node.EncapsulatedDocument
            size = node.get('EncapsulatedDocumentLength')
            if size is not None:
                size = int(size)
                if size < 0 or len(payload) != size + size % 2 or (size % 2 and payload[-1:] != b'\0'):
                    raise Health2DicomError('document length/padding mismatch')
                payload = payload[:size]
            report['documents'].append({'path': prefix, 'mime': str(node.get('MIMETypeOfEncapsulatedDocument', '')),
                                        'data': payload, 'padding_resolved': size is not None})
        if 'DirectoryRecordType' in node:
            ids = node.get('ReferencedFileID', [])
            if isinstance(ids, str):
                ids = [ids]
            report['directory_records'].append({'path': prefix, 'type': str(node.DirectoryRecordType),
                                                'referenced_file_id': [str(x) for x in ids],
                                                'next_offset': int(node.get('OffsetOfTheNextDirectoryRecord', 0)),
                                                'child_offset': int(node.get('OffsetOfReferencedLowerLevelDirectoryEntity', 0))})
        if 'ValueType' in node:
            report['structured_report'].append({'path': prefix, 'value_type': str(node.ValueType),
                'text': str(node.get('TextValue', '')), 'relationship': str(node.get('RelationshipType', ''))})
        for element in node:
            path = f'{prefix}/{int(element.tag):08X}'
            info = {'path': path, 'tag': f'{int(element.tag):08X}', 'keyword': element.keyword,
                    'name': element.name, 'vr': element.VR, 'private': element.tag.is_private,
                    'private_creator': getattr(element, 'private_creator', None)}
            if element.VR == 'SQ':
                info['items'] = len(element.value)
                report['elements'].append(info)
                for i, child in enumerate(element.value):
                    walk(child, f'{path}[{i}]', depth + 1)
            else:
                info['value'] = _value(element.value)
                report['elements'].append(info)
                flag_scan(element.value)
                if isinstance(element.value, bytes) and int(element.tag) not in PIXELS | {0x00420011}:
                    report['binary_elements'].append({'path': path, 'data': element.value})
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        walk(ds)
        report['pixels'] = _pixels(ds, decode_pixels)
    report['flags'] = list(dict.fromkeys(report['flags']))
    return report


def _json_value(obj):
    if isinstance(obj, bytes):
        return _value(obj)
    if hasattr(obj, 'shape') and hasattr(obj, 'dtype'):
        return {'shape': list(obj.shape), 'dtype': str(obj.dtype)}
    raise Health2DicomError('unsupported JSON value')


@_guard
def extract_to(report, directory):
    """Write only generated filenames; directory must not exist. Never follow DICOM paths."""
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=False)
    for i, element in enumerate(report['binary_elements']):
        (path / f'element-{i:04d}.bin').write_bytes(element['data'])
    for i, document in enumerate(report['documents']):
        ext = '.pdf' if document['mime'] == 'application/pdf' else '.bin'
        (path / f'document-{i:04d}{ext}').write_bytes(document['data'])
    pixels = report['pixels']
    if pixels:
        (path / 'pixels.raw').write_bytes(pixels['raw'])
        for key in ('fragments', 'frames'):
            for i, payload in enumerate(pixels.get(key) or []):
                (path / f'{key}-{i:04d}.bin').write_bytes(payload)
        if 'decoded' in pixels:
            import numpy as np
            np.save(path / 'pixels.npy', pixels['decoded'], allow_pickle=False)
    (path / 'report.json').write_text(json.dumps(report, default=_json_value, indent=2), encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file')
    parser.add_argument('--out', help='new output directory (must not exist)')
    parser.add_argument('--decode', action='store_true', help='decode pixels with installed codecs')
    parser.add_argument('--syntax', help='required UID for a bare dataset')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(args.file, 'rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        report = inspect_dicom(data, decode_pixels=args.decode, transfer_syntax=args.syntax)
        if args.out:
            extract_to(report, args.out)
        print(json.dumps(report, default=_json_value, indent=2))
        return 0
    except (Health2DicomError, OSError) as exc:
        print(f'health2_dicom: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
