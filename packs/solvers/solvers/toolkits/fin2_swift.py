#!/usr/bin/env python3
"""Offline FIN MT103/202[/COV]/940/950 parser and statement reconciler.

Preserves ordered fields, nested headers/trailers, parties and exact decimal
amounts. MT→MX output is a source-linked analysis projection, NOT a conformant
CBPR+ converter. No MAC/CHK verification or complete SWIFT network validation.
Dates retain YYMMDD: the century cannot be recovered from the wire alone.
Input is a FIN message/batch or bare body with --type. No network or execution.
"""
import argparse
from datetime import date
from decimal import Decimal, localcontext
import json
from pathlib import Path
import re
import sys

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_BYTES = 8 * 1024 * 1024
MAX_MESSAGES = 10000
MAX_FIELDS = 10000
SUPPORTED = {'103', '202', '940', '950'}
_BLOCK_RE = re.compile(r'\{([1-5]):')
_SUBFIELD_RE = re.compile(r'\{([A-Z0-9]{3}):([^{}]*)\}')


class SwiftError(ValueError):
    """Malformed, ambiguous, unsupported or oversized FIN input."""


def _text(data):
    if isinstance(data, bytes):
        try:
            data = data.decode('ascii')
        except UnicodeError as exc:
            raise SwiftError('FIN input must be ASCII') from exc
    if not isinstance(data, str) or not data or len(data) > MAX_BYTES:
        raise SwiftError('expected nonempty bounded bytes or text')
    if any(ord(c) > 126 or (ord(c) < 32 and c not in '\r\n') for c in data):
        raise SwiftError('invalid FIN control or non-ASCII character')
    data = data.replace('\r\n', '\n')
    if '\r' in data:
        raise SwiftError('bare carriage return')
    return data


def _date(value):
    if not re.fullmatch(r'[0-9]{6}', value):
        raise SwiftError('expected YYMMDD date')
    try:
        date(2000 + int(value[:2]), int(value[2:4]), int(value[4:6]))
    except ValueError as exc:
        raise SwiftError('invalid calendar date') from exc
    return value


def _amount(value):
    if len(value) > 15 or not re.fullmatch(r'[0-9]+,[0-9]*', value):
        raise SwiftError('expected at most 15 characters of FIN decimal amount')
    return str(Decimal(value.replace(',', '.')))


def _money(value, dated=False):
    match = re.fullmatch(r'([0-9]{6})?([A-Z]{3})([0-9]+,[0-9]*)', value)
    if not match or bool(match[1]) != dated:
        raise SwiftError('invalid dated amount' if dated else 'invalid currency amount')
    result = {'currency': match[2], 'amount': _amount(match[3])}
    if dated:
        result['value_date'] = _date(match[1])
    return result


def _balance(value):
    if not value or value[0] not in 'CD':
        raise SwiftError('invalid balance sign')
    result = _money(value[1:], True)
    result['credit_debit'] = value[0]
    amount = Decimal(result['amount'])
    result['signed_amount'] = str(amount.copy_negate() if value[0] == 'D' else amount)
    return result


def _entry(value):
    lines = value.split('\n')
    match = re.fullmatch(r'([0-9]{6})([0-9]{4})?(RD|RC|C|D)([A-Z])?([0-9]+,[0-9]*)([NSF][A-Z0-9]{3})([^\n]{1,16}?)(?://([^\n]{1,16}))?', lines[0])
    if not match or len(lines) > 2 or (len(lines) == 2 and len(lines[1]) > 34):
        raise SwiftError('invalid statement line 61')
    result = {'value_date': _date(match[1]), 'entry_date': match[2],
              'credit_debit': match[3], 'funds_code': match[4],
              'amount': _amount(match[5]), 'transaction_type': match[6],
              'account_owner_reference': match[7], 'bank_reference': match[8],
              'supplementary': lines[1] if len(lines) == 2 else '', 'information': []}
    if match[2]:
        # Month/day can refer to adjacent year; use leap-year sentinel to validate.
        try:
            date(2000, int(match[2][:2]), int(match[2][2:]))
        except ValueError as exc:
            raise SwiftError('invalid entry month/day') from exc
    amount = Decimal(result['amount'])
    result['signed_amount'] = str(amount.copy_negate() if match[3] in ('D', 'RC') else amount)
    return result


def _party(tag, value):
    lines = value.split('\n')
    result = {'option': tag[2:] or None, 'raw': value, 'account': None,
              'bic': None, 'name_address': []}
    if lines[0].startswith('/'):
        result['account'] = lines.pop(0)[1:]
    if tag.endswith('A'):
        if len(lines) != 1 or not re.fullmatch(r'[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?', lines[0]):
            raise SwiftError('invalid option A BIC party')
        result['bic'] = lines[0]
    else:
        result['name_address'] = lines
    return result


def _blocks(text, start):
    result, pos = {}, start
    last = 0
    while pos < len(text):
        if text[pos] == '\n':
            pos += 1
            continue
        if text.startswith('{1:', pos) and result:
            break
        if text[pos:pos + 1] == '$':
            break
        match = _BLOCK_RE.match(text, pos)
        if not match:
            raise SwiftError('unexpected bytes outside FIN block')
        key = match[1]
        if int(key) <= last:
            raise SwiftError('duplicate or out-of-order FIN block')
        last = int(key)
        content = pos + 3
        if key == '4':
            end = text.find('\n-}', content)
            if end < 0:
                raise SwiftError('unterminated FIN text block')
            result[key] = text[content:end]
            pos = end + 3
        else:
            depth, end = 1, content
            while end < len(text) and depth:
                depth += (text[end] == '{') - (text[end] == '}')
                if depth > 4:
                    raise SwiftError('excessive FIN nesting')
                end += 1
            if depth:
                raise SwiftError('unterminated FIN block')
            result[key] = text[content:end - 1]
            pos = end
    if not all(k in result for k in ('1', '2', '4')):
        raise SwiftError('FIN requires blocks 1, 2 and 4')
    return result, pos


def _subfields(value):
    result, pos = [], 0
    while pos < len(value):
        match = _SUBFIELD_RE.match(value, pos)
        if not match:
            raise SwiftError('invalid header/trailer subfield')
        result.append({'tag': match[1], 'value': match[2]})
        if len(result) > MAX_FIELDS:
            raise SwiftError('too many header/trailer subfields')
        pos = match.end()
    return result


def _header(blocks):
    b1, b2 = blocks['1'], blocks['2']
    lt = r'[A-Z]{6}[A-Z0-9]{6}'
    if not re.fullmatch(r'F01' + lt + r'[0-9]{10}', b1):
        raise SwiftError('invalid basic FIN header (F01 required)')
    result = {'session': b1[15:19], 'sequence': b1[19:25]}
    if re.fullmatch(r'I[0-9]{3}' + lt + r'[SNU](?:[123](?:[0-9]{3})?)?', b2):
        result.update(direction='input', message_type=b2[1:4], sender_lt=b1[3:15], receiver_lt=b2[4:16], priority=b2[16])
    elif re.fullmatch(r'O[0-9]{3}[0-9]{10}' + lt + r'[0-9]{20}[SNU]', b2):
        result.update(direction='output', message_type=b2[1:4], sender_lt=b2[14:26], receiver_lt=b1[3:15], priority=b2[46], mir=b2[8:36], input_time=b2[4:8], input_date=_date(b2[8:14]), output_date=_date(b2[36:42]), output_time=b2[42:46])
        for clock in (result['input_time'], result['output_time']):
            if int(clock[:2]) > 23 or int(clock[2:]) > 59:
                raise SwiftError('invalid header time')
    else:
        raise SwiftError('invalid FIN application header')
    result['sender_bic'] = result['sender_lt'][:8] + result['sender_lt'][9:]
    result['receiver_bic'] = result['receiver_lt'][:8] + result['receiver_lt'][9:]
    return result


def _fields(body):
    if body.startswith('\n'):
        body = body[1:]
    fields, chunks = [], []
    for line in body.split('\n'):
        match = re.match(r'^:([0-9]{2}[A-Z]?):(.*)$', line)
        if match:
            if fields:
                fields[-1]['value'] = '\n'.join(chunks)
            fields.append({'tag': match[1], 'value': ''})
            chunks = [match[2]]
            if len(fields) > MAX_FIELDS:
                raise SwiftError('too many fields')
        else:
            if not fields or line.startswith(':'):
                raise SwiftError('invalid field delimiter')
            chunks.append(line)
    if fields:
        fields[-1]['value'] = '\n'.join(chunks)
    if not fields or any(not f['value'] for f in fields):
        raise SwiftError('empty message or field')
    return fields


def _one(fields, tags, required=True):
    found = [f for f in fields if f['tag'] in tags]
    if len(found) > 1 or (required and not found):
        raise SwiftError('missing or duplicate field ' + '/'.join(tags))
    return found[0]['value'] if found else None


def _profile(fields, mt, cov):
    # Retain unsupported optional tags for investigation; don't claim full UHB compliance.
    _one(fields, ['20'])
    if not 1 <= len(fields[0]['value']) <= 16 or fields[0]['tag'] != '20':
        raise SwiftError('reference 20 must be first and at most 16 characters')
    if mt in ('940', '950'):
        return
    a = fields
    b = []
    if cov:
        index = next((i for i, f in enumerate(fields) if f['tag'] in ('50A', '50F', '50K')), None)
        if index is None:
            raise SwiftError('COV missing underlying customer sequence')
        a, b = fields[:index], fields[index:]
        _one(b, ['50A', '50F', '50K'])
        _one(b, ['59', '59A', '59F'])
    for sequence in (a, b):
        seen = set()
        for f in sequence:
            base = f['tag'][:2]
            key = base if base in ('50', '51', '52', '53', '54', '55', '56', '57', '58', '59') else f['tag']
            if key in seen and f['tag'] not in ('13C', '23E', '71F'):
                raise SwiftError('duplicate field family ' + base)
            seen.add(key)
    _one(a, ['32A'])
    if mt == '103':
        if _one(a, ['23B']) not in ('CRED', 'CRTS', 'SPAY', 'SPRI', 'SSTD'):
            raise SwiftError('invalid bank operation code')
        _one(a, ['50A', '50F', '50K'])
        _one(a, ['59', '59A', '59F'])
        if _one(a, ['71A']) not in ('OUR', 'BEN', 'SHA'):
            raise SwiftError('invalid charge bearer')
    else:
        _one(a, ['21'])
        _one(a, ['58A', '58D'])
    for f in a:
        f['sequence'] = 'A'
    for f in b:
        f['sequence'] = 'B'


def _statement(fields, mt):
    _one(fields, ['25'])
    _one(fields, ['21'], False)
    _one(fields, ['64'], False)
    numbering = _one(fields, ['28C'])
    if not re.fullmatch(r'[0-9]{1,5}(?:/[0-9]{1,5})?', numbering):
        raise SwiftError('invalid statement numbering')
    opening = _balance(_one(fields, ['60F', '60M']))
    closing = _balance(_one(fields, ['62F', '62M']))
    if opening['currency'] != closing['currency']:
        raise SwiftError('mixed balance currencies cannot reconcile')
    phase, entries, statement_info, available = 'header', [], [], []
    for f in fields:
        tag, value = f['tag'], f['value']
        if tag in ('20', '21', '25', '28C') and phase != 'header':
            raise SwiftError('statement header field after opening balance')
        if tag in ('60F', '60M'):
            if phase != 'header':
                raise SwiftError('opening balance out of order')
            phase = 'entries'
        elif tag == '61':
            if phase != 'entries':
                raise SwiftError('statement entry outside balances')
            entry = _entry(value)
            entry['currency'] = opening['currency']
            entries.append(entry)
            f['decoded'] = entry
        elif tag == '86':
            if mt == '950':
                raise SwiftError('field 86 is not part of MT950')
            if phase == 'entries' and entries:
                entries[-1]['information'].append(value)
            elif phase == 'closed':
                statement_info.append(value)
            else:
                raise SwiftError('unattached statement information')
        elif tag in ('62F', '62M'):
            if phase != 'entries':
                raise SwiftError('closing balance out of order')
            phase = 'closed'
        elif tag in ('64', '65'):
            if phase != 'closed':
                raise SwiftError('available balance before closing')
            available.append({'tag': tag, **_balance(value)})
    with localcontext() as ctx:
        ctx.prec = 64
        total = sum((Decimal(e['signed_amount']) for e in entries), Decimal(0))
        expected = Decimal(opening['signed_amount']) + total
        difference = Decimal(closing['signed_amount']) - expected
    return {'account': _one(fields, ['25']), 'statement_number': numbering,
            'opening': opening, 'closing': closing, 'entries': entries,
            'available_balances': available, 'information': statement_info,
            'entry_net': str(total), 'expected_closing': str(expected),
            'difference': str(difference), 'reconciled': difference == 0}


def _project(result):
    mt = result['message_type']
    mapping = {'target': {'103': 'pacs.008', '202': 'pacs.009', '940': 'camt.053', '950': 'camt.053'}[mt],
               'conformant_translation': False, 'note': 'Analysis projection only; original fields retained. No CBPR+ validation, address enrichment or missing-data synthesis.', 'fields': [], 'header_fields': []}
    if mt in ('103', '202'):
        if result['header']:
            mapping['header_fields'].extend([
                {'source': 'FIN sending LT', 'path_hint': 'InstgAgt/FinInstnId/BICFI', 'value': result['header']['sender_bic']},
                {'source': 'FIN receiving LT', 'path_hint': 'InstdAgt/FinInstnId/BICFI', 'value': result['header']['receiver_bic']},
            ])
        mapping['header_fields'].extend({'source': 'block 3 tag 121', 'path_hint': 'PmtId/UETR', 'value': f['value']}
                                        for f in result['user_header'] if f['tag'] == '121')
    common = {'20': 'PmtId/InstrId', '32A': 'IntrBkSttlmAmt + IntrBkSttlmDt', '33B': 'InstdAmt',
              '50': 'Dbtr + DbtrAcct', '52': 'DbtrAgt', '56': 'IntrmyAgt1',
              '57': 'CdtrAgt', '59': 'Cdtr + CdtrAcct', '70': 'RmtInf/Ustrd',
              '71A': 'ChrgBr', '71F': 'ChrgsInf', '71G': 'ChrgsInf', '72': 'InstrForNxtAgt'}
    if mt == '202':
        common.update({'21': 'Related reference (context required)', '52': 'Dbtr', '58': 'Cdtr'})
    if mt in ('940', '950'):
        common = {'20': 'Stmt/Id', '25': 'Stmt/Acct', '28C': 'Stmt/ElctrncSeqNb + pagination',
                  '60': 'Stmt/Bal (opening)', '61': 'Stmt/Ntry', '62': 'Stmt/Bal (closing)',
                  '64': 'Stmt/Bal (available)', '65': 'Stmt/Bal (forward)', '86': 'Additional information (context required)'}
    for index, f in enumerate(result['fields']):
        path = common.get(f['tag'], common.get(f['tag'][:2]))
        if path:
            value = f.get('decoded', f['value'])
            if f['tag'] == '71A':
                value = {'OUR': 'DEBT', 'BEN': 'CRED', 'SHA': 'SHAR'}[f['value']]
            if result['variant'] == 'COV' and f.get('sequence') == 'B':
                if f['tag'][:2] == '52':
                    path = 'DbtrAgt'
                path = 'UndrlygCstmrCdtTrf/' + path
            mapping['fields'].append({'source_index': index, 'source_tag': f['tag'], 'path_hint': path, 'value': value})
    return mapping


def _analyze(fields, mt, header=None, user_header=None, trailer=None):
    if mt not in SUPPORTED:
        raise SwiftError('supported types: 103, 202, 940, 950')
    user_header = user_header or []
    variants = [f['value'] for f in user_header if f['tag'] == '119']
    if len(variants) > 1:
        raise SwiftError('duplicate validation flag 119')
    cov = mt == '202' and variants == ['COV']
    _profile(fields, mt, cov)
    result = {'message_type': mt, 'variant': 'COV' if cov else None,
              'header': header, 'user_header': user_header, 'trailer': trailer or [],
              'fields': fields, 'authentication_verified': False,
              'validation_scope': 'FIN syntax and core field semantics only; not complete SWIFT network validation'}
    for f in fields:
        tag, value = f['tag'], f['value']
        if tag == '32A':
            f['decoded'] = _money(value, True)
        elif tag in ('32B', '33B', '71F', '71G'):
            f['decoded'] = _money(value)
        elif tag[:2] in ('50', '51', '52', '53', '54', '55', '56', '57', '58', '59'):
            f['decoded'] = _party(tag, value)
    if mt in ('940', '950'):
        result['statement'] = _statement(fields, mt)
    result['mx_projection'] = _project(result)
    result['flags'] = list(dict.fromkeys(flagfmt.TEXT.findall('\n'.join(f['value'] for f in fields))))
    return result


def parse_messages(data, message_type=None):
    """Parse FIN batches (optional $ separators); bare bodies need explicit type.

    Raises only SwiftError for malformed/unsupported input. Accounting mismatch
    is reported as reconciled=False, since it is evidence rather than bad syntax.
    """
    try:
        text = _text(data).strip('\n')
        if message_type is not None and message_type not in SUPPORTED:
            raise SwiftError('invalid explicit message type')
        if text.startswith(':'):
            if message_type is None:
                raise SwiftError('bare body requires explicit message_type')
            return [_analyze(_fields(text), message_type)]
        result, pos = [], 0
        while pos < len(text):
            blocks, pos = _blocks(text, pos)
            header = _header(blocks)
            if message_type is not None and header['message_type'] != message_type:
                raise SwiftError('explicit type conflicts with header')
            result.append(_analyze(_fields(blocks['4']), header['message_type'], header,
                                   _subfields(blocks.get('3', '')), _subfields(blocks.get('5', ''))))
            if len(result) > MAX_MESSAGES:
                raise SwiftError('too many messages')
            if pos < len(text) and text[pos] == '$':
                pos += 1
                if pos == len(text):
                    raise SwiftError('trailing batch separator')
            while pos < len(text) and text[pos] == '\n':
                pos += 1
        if not result:
            raise SwiftError('empty batch')
        return result
    except SwiftError:
        raise
    except (ValueError, TypeError, AttributeError, IndexError, KeyError, ArithmeticError, RecursionError) as exc:
        raise SwiftError('invalid FIN input') from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', type=Path)
    parser.add_argument('--type', choices=sorted(SUPPORTED), dest='message_type')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError):
        return 2
    try:
        with args.file.open('rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        print(json.dumps(parse_messages(data, args.message_type), indent=2))
        return 0
    except (ValueError, TypeError, OSError) as exc:
        print(f'fin2_swift: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
