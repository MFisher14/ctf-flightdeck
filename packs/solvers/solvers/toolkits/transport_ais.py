"""Strict offline AIS types 1–27 adapter, extending transport.py's basic fields.

Uses pyais only to decode in-memory payloads. No capture, socket or stream APIs.
Input: checksum-bearing !AIVDM/!AIVDO (or other two-letter talker) lines.
Unknown application-specific and type-17 DGNSS data remains bytes/hex; no
internal RTCM2 validation is attempted. Strictness covers the outer message,
not every application schema. Tag blocks and extended 168-bit type27 are
unsupported. Apart from lat/lon sentinels normalized to None, pyais numeric
reserved/unavailable field values are retained for forensic inspection.
Standard byte-padded text and type24A variants are accepted.
References: https://gpsd.io/AIVDM.html ; https://github.com/M0r13n/pyais
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


class TransportAISError(ValueError):
    """Malformed, unsupported, ambiguous or incomplete AIS input."""


_MAX_INPUT = 16 * 1024 * 1024
_FIXED = {1: {168}, 2: {168}, 3: {168}, 4: {168}, 5: {424},
          7: {72, 104, 136, 168}, 9: {168}, 10: {72}, 11: {168},
          13: {72, 104, 136, 168}, 15: {88, 110, 112, 160}, 16: {96, 144},
          18: {168}, 19: {312}, 20: {72, 104, 136, 160}, 22: {168},
          23: {160}, 27: {96}}
_VARIABLE = {6: (88, 1008), 8: (56, 1008), 12: (72, 1008),
             14: (40, 1008), 17: (80, 816), 21: (272, 360),
             25: (40, 168), 26: (60, 1064)}


def _sentence(line):
    if not isinstance(line, str) or len(line) > 1024:
        raise TransportAISError('sentence must be text of at most 1024 characters')
    line = line.strip()
    match = re.fullmatch(r'!([A-Z]{2}VD[MO]),([1-9]),([1-9]),([0-9]?),([AB12]?),([0-W`-w]+),([0-5])\*([0-9A-Fa-f]{2})', line)
    if not match:
        raise TransportAISError('invalid AIS sentence envelope (tag blocks are unsupported)')
    body = line[1:line.index('*')]
    checksum = 0
    for ch in body:
        checksum ^= ord(ch)
    if checksum != int(match[8], 16):
        raise TransportAISError('AIS checksum mismatch')
    tag, total, number, seq, channel, payload, fill, _ = match.groups()
    total, number, fill = int(total), int(number), int(fill)
    if number > total or (number != total and fill):
        raise TransportAISError('fragment index or fill bits invalid')
    bits = ''.join(format(ord(c) - 48 if ord(c) <= 87 else ord(c) - 56, '06b') for c in payload)
    if fill:
        if '1' in bits[-fill:]:
            raise TransportAISError('nonzero AIS fill bits')
        bits = bits[:-fill]
    return {'raw': line, 'tag': tag, 'total': total, 'number': number,
            'seq': seq, 'channel': channel, 'bits': bits}


def _validate_bits(bits):
    if len(bits) < 38:
        raise TransportAISError('AIS header truncated')
    kind = int(bits[:6], 2)
    length = len(bits)
    if kind in _FIXED:
        valid = length in _FIXED[kind]
        if kind == 15 and length == 112:
            valid = valid and bits[-2:] == '00'
    elif kind == 24:
        if length < 40:
            raise TransportAISError('type 24 header truncated')
        part = int(bits[38:40], 2)
        valid = (part == 0 and (length == 160 or (length == 168 and bits[-8:] == '00000000'))) or (part == 1 and length == 168)
    elif kind in _VARIABLE:
        low, high = _VARIABLE[kind]
        valid = low <= length <= high
        if kind in (8, 17, 21):
            valid = valid and length % 8 == 0
        if kind == 21 and valid:
            spare = (length - 272) % 6
            valid = not spare or bits[-spare:] == '0' * spare
        if kind in (12, 14):
            # Text may be followed by zero spare bits to the next byte.
            plain = (length - low) % 6 == 0
            padded = length % 8 == 0 and any(
                length - low >= n and (length - low - n) % 6 == 0
                and bits[-n:] == '0' * n for n in range(1, 8))
            valid = valid and (plain or padded)
        if kind in (25, 26) and valid:
            # Address flag adds destination MMSI; structured flag adds application ID.
            minimum = (40 if kind == 25 else 60) + 30 * int(bits[38]) + 16 * int(bits[39])
            valid = length >= minimum
    else:
        raise TransportAISError(f'unsupported AIS type {kind}')
    if not valid:
        raise TransportAISError(f'invalid type {kind} bit length {length}')
    return kind


def _json_value(value):
    if isinstance(value, bytes):
        return {'hex': value.hex(), 'bytes': len(value)}
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _decode(group):
    bits = ''.join(s['bits'] for s in group)
    kind = _validate_bits(bits)
    try:
        from pyais import decode
        decoded = decode(*(s['raw'] for s in group)).asdict()
    except Exception as exc:
        # External parser exceptions must not cross this public contract.
        raise TransportAISError(f'AIS decoder failed: {type(exc).__name__}') from exc
    for key, limit in (('lat', 90), ('lon', 180)):
        if key in decoded and decoded[key] is not None:
            value = decoded[key]
            if value == limit + 1:  # Defined positive 91/181 unavailable sentinel.
                decoded[key] = None
            elif not -limit <= value <= limit:
                raise TransportAISError(f'invalid AIS {key} coordinate')
    out = {'message_type': kind, 'bit_length': len(bits), 'payload_bits': bits,
           'channel': group[0]['channel'], 'fragments': len(group),
           'decoded': _json_value(decoded)}
    if kind in (6, 8):
        start = 88 if kind == 6 else 56
        out['application_bits'] = bits[start:]
        out['application_bit_length'] = len(bits) - start
    return out


def parse_ais(text: str) -> list[dict]:
    """Decode complete checksum-valid AIS lines, failing the entire input on error.

    Multipart ordering is strict per (talker, channel, sequence ID). New fragment
    1 cannot silently replace an unfinished message, including blank-ID streams.
    Unrelated log prefixes/tag blocks are deliberately rejected, never stripped.
    """
    if not isinstance(text, str) or len(text) > _MAX_INPUT:
        raise TransportAISError('input must be text of at most 16 MiB')
    pending, output = {}, []
    for line in text.splitlines():
        if not line.strip():
            continue
        record = _sentence(line)
        key = record['tag'], record['channel'], record['seq']
        if record['total'] == 1:
            output.append(_decode([record]))
            continue
        if record['number'] == 1:
            if key in pending:
                raise TransportAISError('ambiguous multipart collision')
            pending[key] = [record]
        else:
            group = pending.get(key)
            if not group or record['number'] != len(group) + 1 or record['total'] != group[0]['total']:
                raise TransportAISError('missing, duplicate or inconsistent fragment')
            group.append(record)
        if record['number'] == record['total']:
            output.append(_decode(pending.pop(key)))
    if pending:
        raise TransportAISError('incomplete AIS multipart message')
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='saved AIS NMEA text file')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.file).open('rb') as handle:
            data = handle.read(_MAX_INPUT + 1)
        if len(data) > _MAX_INPUT:
            raise TransportAISError('input exceeds 16 MiB')
        result = parse_ais(data.decode('ascii'))
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, UnicodeError) as exc:
        print(f'transport_ais: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
