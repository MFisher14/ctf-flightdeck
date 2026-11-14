#!/usr/bin/env python3
"""Offline ISO20022 XSD validation and payment/statement consistency analysis.

Bundled schemas: pain.001.001.03/.09, pacs.008.001.08, camt.053.001.08.
Use --xsd for a self-contained schema of another version of these families.
--sepa checks a deliberately limited SCT subset, never full EPC compliance.
No schema downloads, entity expansion, signatures, or payment execution.
Public analyze() raises only ISO20022Error for invalid input. Schema/business
violations return valid=False with evidence; malformed XML raises the error.
"""
import argparse
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
MAX_NODES = 100000
PREFIX = 'urn:iso:std:iso:20022:tech:xsd:'
BUNDLED = {'pain.001.001.03', 'pain.001.001.09', 'pacs.008.001.08', 'camt.053.001.08'}
ROOTS = {'pain.001': 'CstmrCdtTrfInitn', 'pacs.008': 'FIToFICstmrCdtTrf', 'camt.053': 'BkToCstmrStmt'}


class ISO20022Error(ValueError):
    """Invalid, unsupported or unsafe XML/schema input."""


def _bytes(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, bytes) or not value or len(value) > MAX_BYTES:
        raise ISO20022Error('expected nonempty XML bytes/text, at most 8 MiB')
    return value


def _xml(value):
    try:
        from lxml import etree
    except ImportError as exc:
        raise ISO20022Error('lxml is required for real XSD validation') from exc

    class DenyResolver(etree.Resolver):
        def resolve(self, url, pubid, context):
            raise ISO20022Error('external XML resource blocked')

    parser = etree.XMLParser(resolve_entities=False, load_dtd=False,
                             no_network=True, huge_tree=False, recover=False)
    parser.resolvers.add(DenyResolver())
    root = etree.fromstring(_bytes(value), parser)
    if root.getroottree().docinfo.doctype:
        raise ISO20022Error('DOCTYPE is forbidden')
    for i, node in enumerate(root.iter()):
        if i >= MAX_NODES:
            raise ISO20022Error('XML node limit exceeded')
        if isinstance(node, etree._Entity):
            raise ISO20022Error('entities are forbidden')
        if isinstance(node.tag, str) and node.tag.startswith('{http://www.w3.org/2001/XInclude}'):
            raise ISO20022Error('XInclude is forbidden')
    return root


def _number(text):
    # XML Schema decimal collapses whitespace and permits a leading sign,
    # .5 and 1.; validation has already applied each element's own facets.
    if not isinstance(text, str):
        raise ISO20022Error('unsupported/invalid monetary decimal')
    text = text.strip()
    if len(text) > 80 or not re.fullmatch(r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)', text):
        raise ISO20022Error('unsupported/invalid monetary decimal')
    return Decimal(text)


def _iban(value):
    if not re.fullmatch(r'[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}', value or ''):
        return False
    rem = 0
    for char in value[4:] + value[:4]:
        for digit in (char if char.isdigit() else str(ord(char) - 55)):
            rem = (rem * 10 + int(digit)) % 97
    return rem == 1


def _analyze(data, schema, sepa):
    from lxml import etree
    root = _xml(data)
    q = etree.QName(root)
    if q.localname != 'Document' or not (q.namespace or '').startswith(PREFIX):
        raise ISO20022Error('expected namespace-qualified ISO20022 Document root')
    version = q.namespace[len(PREFIX):]
    if not re.fullmatch(r'(pain\.001|pacs\.008|camt\.053)\.001\.[0-9]{2}', version):
        raise ISO20022Error('unsupported ISO20022 message family')
    family = version[:8]
    if sepa and family not in ('pain.001', 'pacs.008'):
        raise ISO20022Error('SEPA SCT checks apply only to pain.001/pacs.008')
    if schema is None:
        if version not in BUNDLED:
            raise ISO20022Error('no bundled schema for this version; supply self-contained XSD')
        schema = (Path(__file__).with_name('fin2_schemas') / (version + '.xsd')).read_bytes()
    sr = _xml(schema)
    if sr.tag != '{http://www.w3.org/2001/XMLSchema}schema' or sr.get('targetNamespace') != q.namespace:
        raise ISO20022Error('schema targetNamespace does not match document')
    for node in sr.iter():
        if node.tag in {'{http://www.w3.org/2001/XMLSchema}' + t for t in ('include', 'import', 'redefine', 'override')}:
            raise ISO20022Error('only self-contained XSDs are accepted; dependencies are blocked')
    validator = etree.XMLSchema(sr)
    schema_valid = validator.validate(root)
    result = {'type': 'iso20022', 'message': version, 'schema_valid': schema_valid,
              'schema_errors': [str(e)[:1000] for e in list(validator.error_log)[:30]],
              'valid': False, 'issues': [], 'transactions': [], 'statements': [],
              'sepa_subset': bool(sepa),
              'limitations': ['XSD and consistency checks do not authenticate a payment or verify a signature.',
                              'SEPA mode checks a subset, not full EPC or bank-specific compliance.']}
    if not schema_valid:
        return result
    ns = {'m': q.namespace}

    def all_(parent, path):
        return parent.findall('/'.join('m:' + p if p not in ('.', '..', '') else p for p in path.split('/')), ns)

    def one(parent, path):
        nodes = all_(parent, path)
        return nodes[0] if nodes else None

    def txt(parent, path):
        n = one(parent, path)
        return n.text if n is not None and n.text else None

    def issue(code, path, expected=None, actual=None):
        result['issues'].append({'code': code, 'path': path, 'expected': expected, 'actual': actual})

    def check_count(parent, path, count, label):
        value = txt(parent, path)
        if value is not None and int(value) != count:
            issue('count_mismatch', label + '/' + path, count, int(value))

    def check_sum(parent, path, amounts, label):
        value = txt(parent, path)
        if value is not None and _number(value) != sum(amounts, Decimal(0)):
            issue('sum_mismatch', label + '/' + path, str(sum(amounts, Decimal(0))), value)

    def account(parent, path):
        return txt(parent, path + '/Id/IBAN') or txt(parent, path + '/Id/Othr/Id')

    body = one(root, ROOTS[family])
    if body is None:
        raise ISO20022Error('schema did not enforce the expected message root')
    result['message_id'] = txt(body, 'GrpHdr/MsgId')
    ids = set()
    for node in all_(body, './/IBAN'):
        if not _iban(node.text):
            issue('iban_mod97', root.getroottree().getpath(node), 'valid mod97 IBAN', node.text)
    if family in ('pain.001', 'pacs.008'):
        groups = all_(body, 'PmtInf') if family == 'pain.001' else [body]
        totals = []
        for group_index, group in enumerate(groups):
            txs = all_(group, 'CdtTrfTxInf')
            amounts = []
            for tx in txs:
                amount_path = 'Amt/InstdAmt' if family == 'pain.001' else 'IntrBkSttlmAmt'
                amount_node = one(tx, amount_path)
                if amount_node is None:
                    # Equivalent-currency instructions require exchange context; don't fabricate a sum.
                    raise ISO20022Error('equivalent-currency amounts are unsupported for consistency checks')
                amount = _number(amount_node.text)
                amounts.append(amount)
                currency = amount_node.get('Ccy')
                end_id = txt(tx, 'PmtId/EndToEndId')
                if end_id and end_id != 'NOTPROVIDED':
                    if end_id in ids:
                        issue('duplicate_end_to_end_id', 'PmtId/EndToEndId', 'unique within document', end_id)
                    ids.add(end_id)
                tx_record = {'end_to_end_id': end_id, 'instruction_id': txt(tx, 'PmtId/InstrId'),
                             'transaction_id': txt(tx, 'PmtId/TxId'), 'amount': str(amount), 'currency': currency,
                             'debtor': txt(group if family == 'pain.001' else tx, 'Dbtr/Nm'),
                             'debtor_account': account(group if family == 'pain.001' else tx, 'DbtrAcct'),
                             'creditor': txt(tx, 'Cdtr/Nm'), 'creditor_account': account(tx, 'CdtrAcct'),
                             'remittance': [n.text or '' for n in all_(tx, 'RmtInf/Ustrd')]}
                result['transactions'].append(tx_record)
                if sepa:
                    if currency != 'EUR':
                        issue('sepa_currency', amount_path, 'EUR', currency)
                    if amount <= 0 or amount != amount.quantize(Decimal('.01')):
                        issue('sepa_amount', amount_path, 'positive with at most two nonzero decimal places', str(amount))
                    for party, owner in [('DbtrAcct', group if family == 'pain.001' else tx), ('CdtrAcct', tx)]:
                        if not txt(owner, party + '/Id/IBAN'):
                            issue('sepa_iban_required', party, 'IBAN', None)
                    charge = txt(tx, 'ChrgBr') or txt(group, 'ChrgBr')
                    if charge != 'SLEV':
                        issue('sepa_charge_bearer', 'ChrgBr', 'SLEV', charge)
                    services = all_(tx, 'PmtTpInf/SvcLvl/Cd') or all_(group, 'PmtTpInf/SvcLvl/Cd')
                    if 'SEPA' not in [n.text for n in services]:
                        issue('sepa_service_level', 'PmtTpInf/SvcLvl/Cd', 'SEPA', [n.text for n in services])
                    if family == 'pain.001' and txt(group, 'PmtMtd') != 'TRF':
                        issue('sepa_method', 'PmtMtd', 'TRF', txt(group, 'PmtMtd'))
            totals.extend(amounts)
            if family == 'pain.001':
                check_count(group, 'NbOfTxs', len(txs), f'PmtInf[{group_index}]')
                check_sum(group, 'CtrlSum', amounts, f'PmtInf[{group_index}]')
        check_count(body, 'GrpHdr/NbOfTxs', len(totals), 'Document')
        check_sum(body, 'GrpHdr/CtrlSum', totals, 'Document')
        if family == 'pacs.008':
            node = one(body, 'GrpHdr/TtlIntrBkSttlmAmt')
            if node is not None:
                currencies = {t['currency'] for t in result['transactions']}
                if currencies != {node.get('Ccy')}:
                    issue('settlement_currency_mismatch', 'GrpHdr/TtlIntrBkSttlmAmt', node.get('Ccy'), sorted(currencies))
                check_sum(body, 'GrpHdr/TtlIntrBkSttlmAmt', totals, 'Document')
    else:
        for stmt in all_(body, 'Stmt'):
            balances, entries = [], []
            for bal in all_(stmt, 'Bal'):
                node = one(bal, 'Amt')
                amount = _number(node.text)
                sign = txt(bal, 'CdtDbtInd')
                if sign == 'DBIT':
                    amount = -amount
                balances.append({'code': txt(bal, 'Tp/CdOrPrtry/Cd'), 'amount': str(amount), 'currency': node.get('Ccy')})
            for entry in all_(stmt, 'Ntry'):
                node = one(entry, 'Amt')
                amount = _number(node.text)
                if txt(entry, 'CdtDbtInd') == 'DBIT':
                    amount = -amount
                # RvslInd describes the entry; CdtDbtInd already encodes its accounting sign.
                entries.append({'reference': txt(entry, 'NtryRef'), 'amount': str(amount), 'currency': node.get('Ccy'),
                                'status': txt(entry, 'Sts/Cd') or txt(entry, 'Sts'),
                                'reversal': txt(entry, 'RvslInd'),
                                'text': [n.text or '' for n in all_(entry, './/Ustrd')],
                                'end_to_end_ids': [n.text or '' for n in all_(entry, './/EndToEndId')]})
            record = {'id': txt(stmt, 'Id'), 'account': account(stmt, 'Acct'), 'balances': balances,
                      'entries': entries, 'reconciled': None, 'reconciliation_note': None}
            opening = [b for b in balances if b['code'] == 'OPBD']
            closing = [b for b in balances if b['code'] == 'CLBD']
            booked = [e for e in entries if e['status'] == 'BOOK']
            page = txt(stmt, 'StmtPgntn/PgNb')
            last = txt(stmt, 'StmtPgntn/LastPgInd')
            incomplete = (page is not None and int(page) != 1) or last in ('false', '0')
            unknown_status = any(e['status'] not in ('BOOK', 'PDNG', 'INFO') for e in entries)
            if incomplete or unknown_status:
                record['reconciliation_note'] = 'not checked: partial pagination or unknown booking status'
            elif len(opening) == len(closing) == 1:
                ccy = opening[0]['currency']
                if {e['currency'] for e in booked} <= {ccy} and closing[0]['currency'] == ccy:
                    expected = Decimal(opening[0]['amount']) + sum((Decimal(e['amount']) for e in booked), Decimal(0))
                    record['reconciled'] = expected == Decimal(closing[0]['amount'])
                    if not record['reconciled']:
                        issue('balance_mismatch', 'Stmt/' + str(record['id']), str(expected), closing[0]['amount'])
                else:
                    issue('balance_currency_mismatch', 'Stmt/' + str(record['id']))
            else:
                record['reconciliation_note'] = 'not checked: exactly one OPBD and CLBD required'
            result['statements'].append(record)
    text_values = list(root.itertext())
    result['flags'] = list(dict.fromkeys(flagfmt.TEXT.findall('\n'.join(text_values))))
    result['valid'] = not result['issues']
    return result


def analyze(data, *, schema=None, sepa=False):
    """Return schema/consistency evidence; raise ISO20022Error on unsafe/unsupported input.

    schema is XSD bytes/text, not a path or URL. Other versions must provide it.
    """
    try:
        if not isinstance(sepa, bool):
            raise ISO20022Error('sepa must be a boolean')
        with localcontext() as ctx:
            ctx.prec = 64
            return _analyze(data, schema, sepa)
    except ISO20022Error:
        raise
    except Exception as exc:
        raise ISO20022Error(f'ISO20022 analysis failed: {type(exc).__name__}: {str(exc)[:300]}') from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file')
    parser.add_argument('--xsd', help='local self-contained XSD; all external dependencies blocked')
    parser.add_argument('--sepa', action='store_true', help='limited SCT semantic checks')
    try:
        args = parser.parse_args(argv)
        with Path(args.file).open('rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        schema = None
        if args.xsd:
            with Path(args.xsd).open('rb') as stream:
                schema = stream.read(MAX_BYTES + 1)
        result = analyze(data, schema=schema, sepa=args.sepa)
        print(json.dumps(result, indent=2))
        return 0 if result['valid'] else 1
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (ISO20022Error, OSError, ValueError, TypeError) as exc:
        print(f'fin2_iso20022: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
