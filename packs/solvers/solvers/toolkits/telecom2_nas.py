#!/usr/bin/env python3
"""Bounded offline 5GS NAS reader (TS 24.501), with no runtime dependencies.

Input is exactly one raw NAS PDU, not a pcap. Selected mandatory fields and
optional IEs are decoded; unknown message bodies / IE tails are explicitly
opaque. This is a structural reader, not a complete NAS procedure validator.
No keys are inferred, no MAC is verified, and ciphered content is never parsed.

CLI: ./.venv/bin/python solvers/toolkits/telecom2_nas.py pdu.bin [--hex]
"""
import argparse
import json
import sys
from pathlib import Path

MAX_BYTES = 1 << 20
MAX_IES = 1024


class NASError(ValueError):
    """Malformed, unsupported framing, or oversized NAS input."""


MM_NAMES = {
    0x41: 'Registration request', 0x42: 'Registration accept',
    0x43: 'Registration complete', 0x44: 'Registration reject',
    0x45: 'MO Deregistration request', 0x46: 'MO Deregistration accept',
    0x47: 'MT Deregistration request', 0x48: 'MT Deregistration accept',
    0x4c: 'Service request', 0x4d: 'Service reject', 0x4e: 'Service accept',
    0x4f: 'Control plane service request', 0x50: 'Network slice authentication command',
    0x51: 'Network slice authentication complete', 0x52: 'Network slice authentication result',
    0x54: 'Configuration update command', 0x55: 'Configuration update complete',
    0x56: 'Authentication request', 0x57: 'Authentication response',
    0x58: 'Authentication reject', 0x59: 'Authentication failure',
    0x5a: 'Authentication result', 0x5b: 'Identity request', 0x5c: 'Identity response',
    0x5d: 'Security mode command', 0x5e: 'Security mode complete',
    0x5f: 'Security mode reject', 0x64: '5GMM status', 0x65: 'Notification',
    0x66: 'Notification response', 0x67: 'UL NAS transport', 0x68: 'DL NAS transport',
}
SM_NAMES = {
    0xc1: 'PDU session establishment request', 0xc2: 'PDU session establishment accept',
    0xc3: 'PDU session establishment reject', 0xc5: 'PDU session authentication command',
    0xc6: 'PDU session authentication complete', 0xc7: 'PDU session authentication result',
    0xc9: 'PDU session modification request', 0xca: 'PDU session modification reject',
    0xcb: 'PDU session modification command', 0xcc: 'PDU session modification complete',
    0xcd: 'PDU session modification command reject', 0xd1: 'PDU session release request',
    0xd2: 'PDU session release reject', 0xd3: 'PDU session release command',
    0xd4: 'PDU session release complete', 0xd6: '5GSM status',
}
IDENTITY_NAMES = {0: 'No identity', 1: 'SUCI', 2: '5G-GUTI', 3: 'IMEI',
                  4: '5G-S-TMSI', 5: 'IMEISV', 6: 'MAC address', 7: 'EUI-64'}


def _bytes(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise NASError('input must be bytes')
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_BYTES:
            raise NASError('input exceeds 1 MiB')
        return bytes(data)
    except (ValueError, TypeError, BufferError) as exc:
        raise NASError('invalid or oversized byte buffer') from exc


class _Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or n > len(self.data) - self.pos:
            raise NASError('truncated NAS field')
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def uint(self, n=1):
        return int.from_bytes(self.take(n), 'big')

    def lv(self, width=1, minimum=0):
        size = self.uint(width)
        if size < minimum:
            raise NASError('NAS field shorter than required')
        return self.take(size)

    def remaining(self):
        return self.data[self.pos:]


def _digits(nibbles, allow_filler=False):
    result = []
    ended = False
    for n in nibbles:
        if n == 15 and allow_filler:
            ended = True
        elif n > 9 or ended:
            raise NASError('invalid decimal/filler nibble')
        else:
            result.append(str(n))
    return ''.join(result)


def _bcd(data, *, fixed_padding=False):
    nibbles = [n for b in data for n in (b & 15, b >> 4)]
    if fixed_padding:
        # A routing indicator occupies exactly four nibbles, so a short
        # indicator can have several trailing F nibbles. Identities cannot.
        return _digits(nibbles, True)
    if nibbles and nibbles[-1] == 15:
        nibbles.pop()
    return _digits(nibbles)


def decode_plmn(data):
    """Decode a three-octet MCC/MNC, preserving leading zeros and MNC width."""
    b = _bytes(data)
    if len(b) != 3:
        raise NASError('PLMN must be three bytes')
    mcc = _digits([b[0] & 15, b[0] >> 4, b[1] & 15])
    mnc = _digits([b[2] & 15, b[2] >> 4] + ([] if b[1] >> 4 == 15 else [b[1] >> 4]))
    return {'mcc': mcc, 'mnc': mnc}


def decode_identity(data):
    """Decode a 5GS mobile-identity value, excluding its length prefix."""
    b = _bytes(data)
    if not b:
        raise NASError('empty mobile identity')
    kind = b[0] & 7
    out = {'type': kind, 'type_name': IDENTITY_NAMES[kind], 'raw_hex': b.hex()}
    if kind == 1:
        out['supi_format'] = (b[0] >> 4) & 7
        if b[0] & 0x88:
            raise NASError('nonzero SUCI spare bits')
        if out['supi_format'] != 0:
            out['opaque_hex'] = b[1:].hex()
            return out
        if len(b) < 9 or b[6] & 0xf0:
            raise NASError('truncated or malformed IMSI-format SUCI')
        out.update(decode_plmn(b[1:4]))
        out.update(routing_indicator=_bcd(b[4:6], fixed_padding=True), protection_scheme=b[6] & 15,
                   home_network_key_id=b[7], scheme_output_hex=b[8:].hex())
        if not out['routing_indicator']:
            raise NASError('empty SUCI routing indicator')
        if out['protection_scheme'] == 0:
            out['msin'] = _bcd(b[8:])
            if not out['msin'] or len(out['mcc'] + out['mnc'] + out['msin']) > 15:
                raise NASError('invalid SUCI IMSI length')
            out['imsi'] = out['mcc'] + out['mnc'] + out['msin']
    elif kind in (2, 4):
        if b[0] != 0xf0 | kind or len(b) != (11 if kind == 2 else 7):
            raise NASError('invalid temporary mobile identity')
        pos = 1
        if kind == 2:
            out.update(decode_plmn(b[1:4]))
            out['amf_region_id'] = b[4]
            pos = 5
        amf = int.from_bytes(b[pos:pos + 2], 'big')
        out.update(amf_set_id=amf >> 6, amf_pointer=amf & 63,
                   tmsi=int.from_bytes(b[pos + 2:], 'big'))
    elif kind in (3, 5):
        if len(b) != (8 if kind == 3 else 9):
            raise NASError('invalid IMEI/IMEISV byte length')
        out['digits'] = _digits([b[0] >> 4]) + _bcd(b[1:])
        if len(out['digits']) != (15 if kind == 3 else 16) or (len(out['digits']) % 2) != ((b[0] >> 3) & 1):
            raise NASError('invalid IMEI/IMEISV length or parity')
    elif kind == 0:
        if b != b'\x00':
            raise NASError('invalid no-identity value')
    else:
        # Address identity variants retained without guessing flag semantics.
        if len(b) != (7 if kind == 6 else 9):
            raise NASError('invalid address identity size')
        out['address_hex'] = b[1:].hex()
    return out


def decode_dnn(data):
    """Decode an APN/DNN label string without resolving it."""
    b = _bytes(data)
    if not 1 <= len(b) <= 100:
        raise NASError('invalid DNN length')
    r, labels = _Reader(b), []
    while r.remaining():
        size = r.uint()
        if not 1 <= size <= 63:
            raise NASError('invalid DNN label length')
        label = r.take(size)
        if any(c < 33 or c > 126 or c == 46 for c in label):
            raise NASError('invalid DNN label')
        labels.append(label.decode('ascii'))
    return '.'.join(labels)


def _snssai(b):
    if len(b) not in (1, 2, 4, 5, 8):
        raise NASError('invalid S-NSSAI length')
    out = {'sst': b[0]}
    if len(b) >= 4:
        out['sd'] = b[1:4].hex()
    if len(b) in (2, 5, 8):
        out['mapped_sst'] = b[1 if len(b) == 2 else 4]
    if len(b) == 8:
        out['mapped_sd'] = b[5:].hex()
    return out


# Entries: name, wire framing (fixed byte count or 'lv'/'lve'), permitted size.
_AUTH = {0x21: ('RAND', 16, 16), 0x20: ('AUTN', 'lv', 16), 0x78: ('EAP', 'lve', None)}
_UL = {0x12: ('PDU session ID', 1, 1), 0x59: ('Old PDU session ID', 1, 1),
       0x22: ('S-NSSAI', 'lv', None), 0x25: ('DNN', 'lv', None),
       0x24: ('Additional information', 'lv', None), 0x80: ('Request type', 0, None),
       0xa0: ('MA PDU session information', 0, None), 0xf0: ('Release assistance indication', 0, None)}
_DL = {0x12: _UL[0x12], 0x24: _UL[0x24], 0x58: ('5GMM cause', 1, 1),
       0x37: ('Backoff timer', 'lv', 1), 0x3a: ('Lower bound timer', 'lv', 1)}
_REG = {0x10: ('5GMM capability', 'lv', None), 0x2e: ('UE security capability', 'lv', None),
        0x2f: ('Requested NSSAI', 'lv', None), 0x52: ('Last visited registered TAI', 6, 6),
        0x77: ('Additional GUTI', 'lve', 11), 0x71: ('NAS message container', 'lve', None),
        0x70: ('EPS NAS container', 'lve', None), 0x2b: ('UE status', 'lv', None),
        0xc0: ('Noncurrent native NAS KSI', 0, None), 0xb0: ('MICO indication', 0, None),
        0x90: ('Network slicing indication', 0, None)}
_SM_EST = {0x90: ('PDU session type', 0, None), 0xa0: ('SSC mode', 0, None),
           0xb0: ('Always-on PDU session', 0, None), 0x28: ('5GSM capability', 'lv', None),
           0x55: ('Maximum packet filters', 2, 2), 0x7b: ('Extended protocol configuration', 'lve', None)}


def _options(r, schema):
    out = []
    while r.remaining():
        if len(out) >= MAX_IES:
            raise NASError('too many NAS IEs')
        tag = r.data[r.pos]
        key = tag if tag < 0x80 else tag & 0xf0
        if key not in schema:
            break  # No global NAS TLV grammar: never guess unknown IE lengths.
        r.uint()
        name, framing, size = schema[key]
        value = r.lv(1 if framing == 'lv' else 2) if isinstance(framing, str) else r.take(framing)
        if size is not None and len(value) != size:
            raise NASError('invalid ' + name + ' size')
        item = {'iei': key, 'name': name, 'raw_hex': value.hex()}
        if framing == 0:
            item['value'] = tag & 15
        elif name == 'DNN':
            item['value'] = decode_dnn(value)
        elif name == 'S-NSSAI':
            item['value'] = _snssai(value)
        elif name == 'Additional GUTI':
            item['value'] = decode_identity(value)
        out.append(item)
    return out


def _parse(data, depth=0):
    if depth > 3:
        raise NASError('nested NAS limit exceeded')
    r = _Reader(data)
    epd = r.uint()
    if epd not in (0x7e, 0x2e):
        raise NASError('not a 5GS NAS extended protocol discriminator')
    out = {'protocol': '5GMM' if epd == 0x7e else '5GSM', 'epd': epd,
           'integrity_verified': False, 'ciphered': False}
    if epd == 0x7e:
        security = r.uint()
        if security & 0xf0 or security > 4:
            raise NASError('unsupported or malformed NAS security header')
        out['security_header_type'] = security
        if security:
            out.update(mac_hex=r.take(4).hex(), sequence_number=r.uint(),
                       ciphered=security in (2, 4))
            body = r.remaining()
            if not body:
                raise NASError('missing protected NAS payload')
            out['payload_hex'] = body.hex()
            if out['ciphered']:
                out['decode_status'] = 'ciphertext: not decrypted'
            else:
                if len(body) < 3 or body[:2] != b'\x7e\x00':
                    raise NASError('integrity-only envelope must contain plain 5GMM')
                out['inner'] = _parse(body, depth + 1)
                out['decode_status'] = 'integrity-only content: MAC not verified'
            return out
    else:
        out.update(pdu_session_id=r.uint(), procedure_transaction_id=r.uint())
    msg = r.uint()
    out.update(message_type=msg, message_name=(MM_NAMES if epd == 0x7e else SM_NAMES).get(msg, 'Unknown'),
               fields={}, ies=[], decode_status='opaque message body')
    fields, schema, exact = out['fields'], {}, False
    if epd == 0x2e:
        if msg == 0xc1:
            fields['integrity_maximum_data_rate_hex'] = r.take(2).hex()
            schema = _SM_EST
        elif msg in (0xc3, 0xca, 0xcd, 0xd2, 0xd3, 0xd6):
            fields['5gsm_cause'] = r.uint()
            exact = msg == 0xd6
        else:
            out['opaque_body_hex'] = r.remaining().hex()
            return out
    elif msg in (0x41, 0x45):
        combined = r.uint()
        fields['nas_key_set_id'] = combined >> 4
        if msg == 0x41:
            fields['registration_type'] = combined & 7
            fields['follow_on_request'] = bool(combined & 8)
        else:
            fields['deregistration_type_raw'] = combined & 15
            fields['deregistration_access_type'] = combined & 3
            fields['switch_off'] = bool(combined & 8)
            # Preserve this bit without asserting a network request: this
            # branch handles UE-originated de-registration only.
            fields['reregistration_required_bit'] = bool(combined & 4)
        fields['mobile_identity'] = decode_identity(r.lv(2, 1))
        schema = _REG if msg == 0x41 else {}
    elif msg == 0x5c:
        fields['mobile_identity'] = decode_identity(r.lv(2, 1))
        exact = True
    elif msg == 0x5b:
        identity = r.uint()
        if identity > 7:
            raise NASError('nonzero identity-request spare bits')
        fields['identity_type'] = IDENTITY_NAMES[identity]
        exact = True
    elif msg == 0x56:
        ksi = r.uint()
        if ksi > 15:
            raise NASError('nonzero authentication spare bits')
        fields.update(nas_key_set_id=ksi, abba_hex=r.lv(1, 2).hex())
        schema = _AUTH
    elif msg == 0x57:
        schema = {0x2d: ('RES*', 'lv', 16), 0x78: _AUTH[0x78]}
    elif msg == 0x59:
        fields['5gmm_cause'] = r.uint()
        schema = {0x30: ('AUTS', 'lv', 14)}
    elif msg == 0x5d:
        alg, ksi = r.uint(), r.uint()
        if ksi > 15:
            raise NASError('nonzero security-mode spare bits')
        fields.update(ciphering_algorithm=alg >> 4, integrity_algorithm=alg & 15,
                      nas_key_set_id=ksi, ue_security_capability_hex=r.lv(1, 2).hex())
    elif msg in (0x67, 0x68):
        kind = r.uint()
        if kind > 15:
            raise NASError('nonzero NAS-transport spare bits')
        payload = r.lv(2, 1)
        fields.update(payload_container_type=kind, payload_hex=payload.hex())
        if kind == 1:
            if payload[0] != 0x2e:
                raise NASError('N1 SM container must hold 5GSM')
            fields['inner'] = _parse(payload, depth + 1)
        schema = _UL if msg == 0x67 else _DL
    elif msg in (0x44, 0x4d, 0x5f, 0x64):
        fields['5gmm_cause'] = r.uint()
        exact = msg in (0x5f, 0x64)
    elif msg in (0x46, 0x48, 0x55):
        exact = True
    else:
        out['opaque_body_hex'] = r.remaining().hex()
        return out
    out['ies'] = _options(r, schema)
    if exact and r.remaining():
        raise NASError('unexpected trailing NAS bytes')
    out['decode_status'] = 'selected fields decoded' if not r.remaining() else 'selected fields decoded; unsupported IE tail'
    out['unparsed_tail_hex'] = r.remaining().hex()
    return out


def parse_nas(data):
    """Return a JSON-safe record; invalid inputs raise only :class:`NASError`."""
    return _parse(_bytes(data))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='raw NAS PDU file')
    parser.add_argument('--hex', action='store_true', help='file contains hexadecimal text')
    try:
        args = parser.parse_args(argv)
        with Path(args.file).open('rb') as handle:
            data = handle.read(2 * MAX_BYTES + 1 if args.hex else MAX_BYTES + 1)
        if args.hex:
            if len(data) > 2 * MAX_BYTES:
                raise NASError('hex file exceeds input limit')
            data = bytes.fromhex(data.decode('ascii'))
        print(json.dumps(parse_nas(data), indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (NASError, OSError, UnicodeError, ValueError) as exc:
        print('telecom2_nas: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
