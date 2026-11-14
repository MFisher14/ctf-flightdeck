#!/usr/bin/env python3
"""Offline SCTP framing, checksum and DATA-message recovery (RFC 9260).

Input is an SCTP packet starting at the common header, without IP headers.
Reassembly requires packets from ONE direction of ONE association; IP addresses
are not available here, so the caller must separate flows before using it.
I-DATA/interleaving is intentionally unsupported by the reassembler.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import sys

MAX_BYTES = 8 * 1024 * 1024
MAX_ITEMS = 16384


class SCTPError(ValueError):
    """Invalid, incomplete, unsupported or over-budget SCTP input."""


def _bytes(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SCTPError("expected bytes")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_BYTES:
            raise SCTPError("input exceeds 8 MiB")
        return bytes(data)
    except (ValueError, TypeError) as exc:
        raise SCTPError("invalid or oversized byte buffer") from exc


def _crc_table():
    table = []
    for i in range(256):
        n = i
        for _ in range(8):
            n = (n >> 1) ^ (0x82F63B78 if n & 1 else 0)
        table.append(n)
    return tuple(table)


_CRC = _crc_table()


def crc32c(data):
    """Standard reflected CRC-32C (Castagnoli), returned as an integer."""
    value = 0xffffffff
    for octet in _bytes(data):
        value = _CRC[(value ^ octet) & 255] ^ (value >> 8)
    return value ^ 0xffffffff


def _u(data, start, size):
    if start < 0 or start + size > len(data):
        raise SCTPError("truncated integer")
    return int.from_bytes(data[start:start + size], 'big')


_CHUNKS = {0: 'DATA', 1: 'INIT', 2: 'INIT_ACK', 3: 'SACK', 4: 'HEARTBEAT',
           5: 'HEARTBEAT_ACK', 6: 'ABORT', 7: 'SHUTDOWN', 8: 'SHUTDOWN_ACK',
           9: 'ERROR', 10: 'COOKIE_ECHO', 11: 'COOKIE_ACK', 12: 'ECNE',
           13: 'CWR', 14: 'SHUTDOWN_COMPLETE', 64: 'I_DATA', 192: 'FORWARD_TSN'}
_PPIDS = {0: 'unspecified', 3: 'M3UA', 18: 'S1AP', 46: 'Diameter',
          47: 'Diameter_DTLS', 50: 'WebRTC_DCEP', 51: 'WebRTC_String',
          52: 'WebRTC_Binary_Partial', 53: 'WebRTC_Binary', 54: 'WebRTC_String_Partial',
          60: 'NGAP', 61: 'XnAP', 62: 'F1AP', 64: 'E1AP', 66: 'NGAP_DTLS'}


def _parameters(data, causes=False):
    result, offset = [], 0
    while offset < len(data):
        if len(result) >= MAX_ITEMS:
            raise SCTPError('too many parameters')
        kind, length = _u(data, offset, 2), _u(data, offset + 2, 2)
        if length < 4 or offset + length > len(data):
            raise SCTPError('invalid parameter length')
        body = data[offset + 4:offset + length]
        item = {'type': kind, 'length': length, 'value_hex': body.hex()}
        if not causes and kind in (5, 6):
            expected = 4 if kind == 5 else 16
            if len(body) != expected:
                raise SCTPError('invalid address parameter size')
            item['address'] = str(ipaddress.ip_address(body))
        if not causes and kind == 12:
            if len(body) % 2:
                raise SCTPError('invalid supported address types')
            item['address_types'] = [_u(body, i, 2) for i in range(0, len(body), 2)]
        result.append(item)
        end = offset + length
        # Last parameter padding may be excluded from the enclosing chunk length.
        offset = end if end == len(data) else offset + ((length + 3) & ~3)
        if offset > len(data):
            raise SCTPError('truncated parameter padding')
    return result


def parse_packet(data, *, require_checksum=False):
    """Parse all chunks or raise SCTPError; bad CRC is reported unless required.

    Unknown chunk bodies remain raw. Checksums are little-endian on the wire;
    all other integer fields are network byte order. Receiver-ignored padding
    bytes need not be zero, but must exist at packet level.
    """
    data = _bytes(data)
    if len(data) < 16:
        raise SCTPError('SCTP needs a common header and at least one chunk')
    source, destination = _u(data, 0, 2), _u(data, 2, 2)
    if not source or not destination:
        raise SCTPError('zero SCTP port')
    received = int.from_bytes(data[8:12], 'little')
    calculated = crc32c(data[:8] + b'\0' * 4 + data[12:])
    if require_checksum and received != calculated:
        raise SCTPError('CRC32c mismatch')
    result = {'source_port': source, 'destination_port': destination,
              'verification_tag': _u(data, 4, 4), 'checksum': received,
              'calculated_checksum': calculated, 'checksum_valid': received == calculated,
              'chunks': []}
    offset = 12
    while offset < len(data):
        if len(result['chunks']) >= MAX_ITEMS:
            raise SCTPError('too many chunks')
        kind, flags, length = _u(data, offset, 1), _u(data, offset + 1, 1), _u(data, offset + 2, 2)
        end, padded = offset + length, offset + ((length + 3) & ~3)
        if length < 4 or end > len(data) or padded > len(data):
            raise SCTPError('invalid chunk length or missing padding')
        body = data[offset + 4:end]
        chunk = {'type': kind, 'name': _CHUNKS.get(kind, 'UNKNOWN'), 'flags': flags,
                 'length': length, 'offset': offset, 'value_hex': body.hex()}
        if kind == 0:
            if len(body) < 13:
                raise SCTPError('DATA must contain its header and nonempty user data')
            ppid = _u(body, 8, 4)
            chunk.update(tsn=_u(body, 0, 4), stream_id=_u(body, 4, 2),
                         stream_sequence=_u(body, 6, 2), ppid=ppid,
                         protocol_hint=_PPIDS.get(ppid), unordered=bool(flags & 4),
                         begin=bool(flags & 2), end=bool(flags & 1),
                         payload_hex=body[12:].hex())
        elif kind in (1, 2):
            if len(body) < 16:
                raise SCTPError('truncated INIT')
            chunk.update(initiate_tag=_u(body, 0, 4), a_rwnd=_u(body, 4, 4),
                         outbound_streams=_u(body, 8, 2), inbound_streams=_u(body, 10, 2),
                         initial_tsn=_u(body, 12, 4), parameters=_parameters(body[16:]))
            if not chunk['initiate_tag'] or not chunk['outbound_streams'] or not chunk['inbound_streams']:
                raise SCTPError('zero INIT tag or stream count')
        elif kind == 3:
            if len(body) < 12:
                raise SCTPError('truncated SACK')
            gap_count, dup_count = _u(body, 8, 2), _u(body, 10, 2)
            if len(body) != 12 + 4 * (gap_count + dup_count):
                raise SCTPError('SACK count/length mismatch')
            gaps, previous = [], 0
            for i in range(gap_count):
                start, stop = _u(body, 12 + 4 * i, 2), _u(body, 14 + 4 * i, 2)
                if start <= previous or stop < start:
                    raise SCTPError('invalid SACK gap block')
                gaps.append([start, stop])
                previous = stop
            chunk.update(cumulative_tsn=_u(body, 0, 4), a_rwnd=_u(body, 4, 4),
                         gaps=gaps, duplicate_tsns=[_u(body, 12 + 4 * gap_count + 4 * i, 4)
                                                   for i in range(dup_count)])
        elif kind in (4, 5, 6, 9):
            chunk['causes' if kind in (6, 9) else 'parameters'] = _parameters(body, kind in (6, 9))
            if kind in (4, 5) and (len(chunk['parameters']) != 1 or chunk['parameters'][0]['type'] != 1):
                raise SCTPError('heartbeat requires one Heartbeat Info parameter')
        elif kind in (7, 12, 13):
            if len(body) != 4:
                raise SCTPError('invalid TSN chunk size')
            chunk['tsn'] = _u(body, 0, 4)
        elif kind in (8, 11, 14) and body:
            raise SCTPError('unexpected body for empty chunk')
        result['chunks'].append(chunk)
        offset = padded
    for chunk in result['chunks']:
        if chunk['type'] in (1, 2, 14) and len(result['chunks']) != 1:
            raise SCTPError('INIT, INIT ACK and SHUTDOWN COMPLETE cannot be bundled')
        if chunk['type'] == 1 and result['verification_tag'] != 0:
            raise SCTPError('INIT must use common verification tag zero')
    return result


def reassemble(packets, *, require_checksum=False):
    """Recover complete DATA messages from raw packets in one directional flow.

    Exact retransmissions are deduplicated. Incomplete fragments, conflicting
    retransmissions, mixed associations and I-DATA/FORWARD-TSN raise SCTPError.
    Packets may be reordered and TSNs may wrap once. No missing bytes are filled.
    """
    if not isinstance(packets, (list, tuple)) or not packets or len(packets) > MAX_ITEMS:
        raise SCTPError('expected a nonempty bounded packet list')
    chunks, association, total = {}, None, 0
    for raw in packets:
        raw = _bytes(raw)
        total += len(raw)
        if total > MAX_BYTES:
            raise SCTPError('reassembly input exceeds 8 MiB')
        packet = parse_packet(raw, require_checksum=require_checksum)
        key = tuple(packet[k] for k in ('source_port', 'destination_port', 'verification_tag'))
        if association is None:
            association = key
        elif association != key:
            raise SCTPError('mixed associations or directions')
        for chunk in packet['chunks']:
            if chunk['type'] in (64, 192, 194):
                raise SCTPError('interleaving/partial reliability requires a different reassembler')
            if chunk['type'] != 0:
                continue
            tsn = chunk['tsn']
            if tsn in chunks:
                old = chunks[tsn]
                if old['value_hex'] != chunk['value_hex'] or (old['flags'] & 7) != (chunk['flags'] & 7):
                    raise SCTPError('conflicting retransmission')
            else:
                chunks[tsn] = chunk
            if len(chunks) > MAX_ITEMS:
                raise SCTPError('too many DATA chunks')
    if not chunks:
        return []
    ordered = sorted(chunks)
    # Break the TSN ring at its largest unused interval, handling 0xffffffff -> 0.
    gaps = [((ordered[(i + 1) % len(ordered)] - n) & 0xffffffff, i)
            for i, n in enumerate(ordered)]
    _, split = max(gaps)
    ordered = ordered[split + 1:] + ordered[:split + 1]
    if len(ordered) > 1 and ((ordered[-1] - ordered[0]) & 0xffffffff) >= 0x80000000:
        raise SCTPError('ambiguous TSN span')
    result, current, pieces, last = [], None, [], None
    for tsn in ordered:
        chunk = chunks[tsn]
        if chunk['begin']:
            if current is not None:
                raise SCTPError('new message before previous fragment ended')
            current, pieces = chunk, []
        elif current is None:
            raise SCTPError('orphaned fragment')
        if pieces:
            if tsn != ((last + 1) & 0xffffffff):
                raise SCTPError('missing fragment TSN')
            for field in ('stream_id', 'ppid', 'unordered'):
                if chunk[field] != current[field]:
                    raise SCTPError('fragment metadata mismatch')
            if not current['unordered'] and chunk['stream_sequence'] != current['stream_sequence']:
                raise SCTPError('fragment stream sequence mismatch')
        pieces.append(bytes.fromhex(chunk['payload_hex']))
        last = tsn
        if chunk['end']:
            payload = b''.join(pieces)
            result.append({'stream_id': current['stream_id'], 'stream_sequence': current['stream_sequence'],
                           'unordered': current['unordered'], 'ppid': current['ppid'],
                           'protocol_hint': current['protocol_hint'], 'first_tsn': current['tsn'],
                           'last_tsn': tsn, 'payload_hex': payload.hex()})
            current, pieces = None, []
    if current is not None:
        raise SCTPError('incomplete final message')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='+', help='raw SCTP packet files (no IP headers)')
    parser.add_argument('--require-checksum', action='store_true')
    parser.add_argument('--reassemble', action='store_true', help='one directional association only')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        packets = []
        total = 0
        if len(args.files) > MAX_ITEMS:
            raise SCTPError('too many files')
        for name in args.files:
            with Path(name).open('rb') as handle:
                raw = handle.read(MAX_BYTES + 1)
            total += len(raw)
            if total > MAX_BYTES:
                raise SCTPError('input exceeds 8 MiB')
            packets.append(raw)
        result = (reassemble(packets, require_checksum=args.require_checksum) if args.reassemble else
                  [parse_packet(raw, require_checksum=args.require_checksum) for raw in packets])
        print(json.dumps(result, indent=2))
        return 0
    except (SCTPError, OSError, ValueError) as exc:
        print(f'telecom2_sctp: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
