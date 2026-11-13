#!/usr/bin/env python3
"""Offline NGAP aligned-PER reader using pycrate's TS 38.413 ASN.1 schema.

One raw NGAP PDU (SCTP PPID 60), not a pcap or an SCTP packet. Returns decoded
IEs and extracts schema-labelled NAS-PDU values for telecom2_nas. Framing and
ASN.1 constraints are checked; this is not a complete procedure/state validator.
Requires optional pip package pycrate. No network, subprocesses, or evaluation.

CLI: ./.venv/bin/python solvers/toolkits/telecom2_ngap.py ngap.bin [--hex]
"""
import argparse
import json
import sys
from pathlib import Path
from threading import RLock

MAX_BYTES = 256 * 1024
MAX_NODES = 20000
_LOCK = RLock()


class NGAPError(ValueError):
    """Bad/oversized NGAP input or unavailable schema dependency."""


def parse_ngap(data):
    """Decode exactly one APER message, raising only NGAPError on failure.

    Pycrate's APER codec and ASN.1 object hold mutable state. Calls through this
    module are serialized, and the codec offset stack is restored after failure.
    Do not concurrently manipulate the same pycrate objects outside this module.
    """
    try:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise NGAPError('input must be bytes')
        if not 1 <= (data.nbytes if isinstance(data, memoryview) else len(data)) <= MAX_BYTES:
            raise NGAPError('NGAP input size must be 1..262144 bytes')
        data = bytes(data)
        try:
            from pycrate_asn1dir import NGAP
            from pycrate_asn1rt.codecs import ASN1CodecPER
            from pycrate_core.charpy import Charpy
        except ImportError as exc:
            raise NGAPError('NGAP needs the optional pycrate package') from exc
        from telecom2_nas import parse_nas, NASError
        with _LOCK:
            saved_offsets, saved_aligned = list(ASN1CodecPER._off), ASN1CodecPER.ALIGNED
            pdu = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            try:
                buf = Charpy(data)
                pdu.from_aper(buf)
                if buf.len_bit():
                    raise NGAPError('trailing data after NGAP PDU')
                decoded = pdu.get_val()
                budget, nas = [MAX_NODES], []

                def convert(value, depth=0):
                    budget[0] -= 1
                    if budget[0] < 0 or depth > 64:
                        raise NGAPError('NGAP decoded-object limit exceeded')
                    if isinstance(value, bytes):
                        return {'hex': value.hex()}
                    if isinstance(value, tuple):
                        if len(value) == 2 and value[0] == 'NAS-PDU' and isinstance(value[1], bytes):
                            entry = {'raw_hex': value[1].hex()}
                            try:
                                entry['decoded'] = parse_nas(value[1])
                            except NASError as exc:
                                entry['error'] = str(exc)
                            nas.append(entry)
                        return [convert(v, depth + 1) for v in value]
                    if isinstance(value, list):
                        return [convert(v, depth + 1) for v in value]
                    if isinstance(value, dict):
                        return {str(k): convert(v, depth + 1) for k, v in value.items()}
                    if value is None or isinstance(value, (str, int, bool)):
                        return value
                    raise NGAPError('unexpected ASN.1 value type')

                rendered = convert(decoded)
                if not isinstance(decoded, tuple) or len(decoded) != 2 or not isinstance(decoded[1], dict):
                    raise NGAPError('unsupported NGAP top-level choice')
                body = decoded[1]
                open_type = body.get('value')
                if not isinstance(open_type, tuple) or len(open_type) != 2:
                    raise NGAPError('unsupported NGAP procedure open type')
                return {'protocol': 'NGAP', 'encoding': 'aligned PER',
                        'pdu_type': decoded[0], 'procedure_code': body.get('procedureCode'),
                        'criticality': body.get('criticality'), 'message_name': open_type[0],
                        'decoded': rendered, 'nas_pdus': nas,
                        'validation_scope': 'ASN.1 structure and exact framing; no procedure/state validation'}
            finally:
                ASN1CodecPER._off[:] = saved_offsets
                ASN1CodecPER.ALIGNED = saved_aligned
    except NGAPError:
        raise
    except Exception as exc:
        raise NGAPError('NGAP decoding failed: ' + type(exc).__name__) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='one raw NGAP PDU')
    parser.add_argument('--hex', action='store_true', help='file contains hexadecimal text')
    try:
        args = parser.parse_args(argv)
        with Path(args.file).open('rb') as handle:
            data = handle.read(2 * MAX_BYTES + 1 if args.hex else MAX_BYTES + 1)
        if args.hex:
            if len(data) > 2 * MAX_BYTES:
                raise NGAPError('hex file exceeds input limit')
            data = bytes.fromhex(data.decode('ascii'))
        print(json.dumps(parse_ngap(data), indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (NGAPError, OSError, UnicodeError, ValueError) as exc:
        print('telecom2_ngap: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
