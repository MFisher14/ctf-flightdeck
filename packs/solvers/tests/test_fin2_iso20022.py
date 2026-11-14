"""Independent literal XML fixtures checked against published bank/ISO XSDs.

No engine encoder exists. Amount/count expectations are hand-derived; XSDs are
third-party unmodified normative grammar, not schemas generated from our parser.
"""
from pathlib import Path
import random
import pytest
from lxml import etree
import fin2_iso20022 as F


def doc(body, version):
    return (f'<Document xmlns="{F.PREFIX}{version}">{body}</Document>').encode()


def pain(version='pain.001.001.09', count=1, total='12.34'):
    date = '<Dt>2026-11-05</Dt>' if version.endswith('.09') else '2026-11-05'
    bic = 'BICFI' if version.endswith('.09') else 'BIC'
    return doc(f'''<CstmrCdtTrfInitn><GrpHdr><MsgId>msg1</MsgId><CreDtTm>2026-11-05T12:00:00</CreDtTm>
<NbOfTxs>{count}</NbOfTxs><CtrlSum>{total}</CtrlSum><InitgPty><Nm>Alice</Nm></InitgPty></GrpHdr>
<PmtInf><PmtInfId>p1</PmtInfId><PmtMtd>TRF</PmtMtd><NbOfTxs>1</NbOfTxs><CtrlSum>12.34</CtrlSum>
<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl></PmtTpInf><ReqdExctnDt>{date}</ReqdExctnDt>
<Dbtr><Nm>Alice</Nm></Dbtr><DbtrAcct><Id><IBAN>DE89370400440532013000</IBAN></Id></DbtrAcct>
<DbtrAgt><FinInstnId><{bic}>DEUTDEFF</{bic}></FinInstnId></DbtrAgt><ChrgBr>SLEV</ChrgBr>
<CdtTrfTxInf><PmtId><EndToEndId>e1</EndToEndId></PmtId><Amt><InstdAmt Ccy="EUR">12.34</InstdAmt></Amt>
<Cdtr><Nm>Bob</Nm></Cdtr><CdtrAcct><Id><IBAN>GB82WEST12345698765432</IBAN></Id></CdtrAcct>
<RmtInf><Ustrd>CSCTF{{xml_fixture}}</Ustrd></RmtInf></CdtTrfTxInf></PmtInf></CstmrCdtTrfInitn>''', version)


def pacs():
    return doc('''<FIToFICstmrCdtTrf><GrpHdr><MsgId>m2</MsgId><CreDtTm>2026-11-05T12:00:00</CreDtTm>
<NbOfTxs>1</NbOfTxs><TtlIntrBkSttlmAmt Ccy="EUR">12.34</TtlIntrBkSttlmAmt><IntrBkSttlmDt>2026-11-05</IntrBkSttlmDt>
<SttlmInf><SttlmMtd>CLRG</SttlmMtd></SttlmInf></GrpHdr><CdtTrfTxInf><PmtId><EndToEndId>e2</EndToEndId></PmtId>
<PmtTpInf><SvcLvl><Cd>SEPA</Cd></SvcLvl></PmtTpInf><IntrBkSttlmAmt Ccy="EUR">12.34</IntrBkSttlmAmt><ChrgBr>SLEV</ChrgBr>
<Dbtr><Nm>Alice</Nm></Dbtr><DbtrAcct><Id><IBAN>DE89370400440532013000</IBAN></Id></DbtrAcct>
<DbtrAgt><FinInstnId><BICFI>DEUTDEFF</BICFI></FinInstnId></DbtrAgt><CdtrAgt><FinInstnId><BICFI>WESTGB2L</BICFI></FinInstnId></CdtrAgt>
<Cdtr><Nm>Bob</Nm></Cdtr><CdtrAcct><Id><IBAN>GB82WEST12345698765432</IBAN></Id></CdtrAcct></CdtTrfTxInf></FIToFICstmrCdtTrf>''', 'pacs.008.001.08')


def camt(closing='87.66', reversal='false'):
    # BOOKed debit: 100 - 12.34 = 87.66. Reversal flag does not invert CdtDbtInd.
    return doc(f'''<BkToCstmrStmt><GrpHdr><MsgId>m3</MsgId><CreDtTm>2026-11-05T12:00:00</CreDtTm></GrpHdr>
<Stmt><Id>s1</Id><CreDtTm>2026-11-05T12:00:00</CreDtTm><Acct><Id><IBAN>DE89370400440532013000</IBAN></Id></Acct>
<Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy="EUR">100.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-11-04</Dt></Dt></Bal>
<Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy="EUR">{closing}</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-11-05</Dt></Dt></Bal>
<Ntry><NtryRef>n1</NtryRef><Amt Ccy="EUR">12.34</Amt><CdtDbtInd>DBIT</CdtDbtInd><RvslInd>{reversal}</RvslInd>
<Sts><Cd>BOOK</Cd></Sts><BkTxCd><Prtry><Cd>TEST</Cd></Prtry></BkTxCd></Ntry></Stmt></BkToCstmrStmt>''', 'camt.053.001.08')


@pytest.mark.parametrize('message', [pain(), pain('pain.001.001.03'), pacs(), camt()])
def test_published_schemas_and_independent_literals(message):
    root = etree.fromstring(message)
    version = etree.QName(root).namespace.split(':')[-1]
    schema_path = Path(F.__file__).with_name('fin2_schemas') / (version + '.xsd')
    # Authoritative third-party grammar independently verifies our literal inputs.
    schema = etree.XMLSchema(etree.parse(str(schema_path)))
    assert schema.validate(root), str(schema.error_log)
    result = F.analyze(message)
    assert result['schema_valid'] and result['valid'], result


def test_literal_extraction():
    r = F.analyze(pain(), sepa=True)
    assert r['valid'] and r['flags'] == ['CSCTF{xml_fixture}']
    t = r['transactions'][0]
    assert (t['amount'], t['currency'], t['creditor'], t['debtor']) == ('12.34', 'EUR', 'Bob', 'Alice')
    assert t['creditor_account'] == 'GB82WEST12345698765432'
    assert F.analyze(pacs(), sepa=True)['valid']


@pytest.mark.parametrize('message,code', [
    (pain(count=2), 'count_mismatch'),
    (pain(total='12.35'), 'sum_mismatch'),
    (pain().replace(b'DE893704', b'DE883704'), 'iban_mod97'),
    (camt('87.65'), 'balance_mismatch'),
    (pacs().replace(b'<TtlIntrBkSttlmAmt Ccy="EUR">12.34', b'<TtlIntrBkSttlmAmt Ccy="EUR">12.35'), 'sum_mismatch'),
])
def test_semantic_tamper(message, code):
    r = F.analyze(message)
    assert r['schema_valid'] and not r['valid']
    assert code in {i['code'] for i in r['issues']}


def test_statement_signed_and_reversal():
    for reverse in ['true', 'false']:
        s = F.analyze(camt(reversal=reverse))['statements'][0]
        assert s['entries'][0]['amount'] == '-12.34'
        assert s['reconciled'] is True


@pytest.mark.parametrize('mutation', [
    lambda x: x.replace(b'<NbOfTxs>1</NbOfTxs>', b'<NbOfTxs>NaN</NbOfTxs>'),
    lambda x: x.replace(b'<MsgId>msg1</MsgId>', b''),
    lambda x: x.replace(b'<MsgId>msg1</MsgId>', b'<MsgId>msg1</MsgId><MsgId>hidden</MsgId>'),
    lambda x: x.replace(b'Ccy="EUR"', b'Ccy="eu"'),
    lambda x: x.replace(b'<Cdtr><Nm>', b'<Cdtr xmlns="urn:evil"><Nm>'),
])
def test_real_schema_rejects_structure(mutation):
    r = F.analyze(mutation(pain()))
    assert not r['schema_valid'] and not r['valid'] and r['schema_errors']


@pytest.mark.parametrize('mutation,code', [
    (lambda x: x.replace(b'Ccy="EUR"', b'Ccy="USD"'), 'sepa_currency'),
    (lambda x: x.replace(b'SLEV', b'SHAR'), 'sepa_charge_bearer'),
    (lambda x: x.replace(b'>SEPA<', b'>OTHR<'), 'sepa_service_level'),
])
def test_sepa_subset(mutation, code):
    r = F.analyze(mutation(pain()), sepa=True)
    assert r['schema_valid'] and not r['valid'], r
    assert code in {i['code'] for i in r['issues']}


@pytest.mark.parametrize('data', [None, 5, b'', b'<Document>', b'<Document/>', b'\xff',
    '<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
    '<!DOCTYPE a SYSTEM "https://invalid.example/a.dtd"><a/>',
    b'<a xmlns:x="http://www.w3.org/2001/XInclude"><x:include href="file:///etc/passwd"/></a>'])
def test_fail_closed(data):
    with pytest.raises(F.ISO20022Error):
        F.analyze(data)


def test_utf16_doctype_blocked():
    data = '<!DOCTYPE a [<!ENTITY x "ABC">]><a>&x;</a>'.encode('utf-16')
    with pytest.raises(F.ISO20022Error):
        F.analyze(data)


def test_external_schema_import_blocked():
    schema = f'''<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" targetNamespace="{F.PREFIX}pain.001.001.09">
<xs:import namespace="evil" schemaLocation="file:///etc/passwd"/></xs:schema>'''
    with pytest.raises(F.ISO20022Error, match='dependencies'):
        F.analyze(pain(), schema=schema)


def test_wrong_schema_and_unknown_version():
    with pytest.raises(F.ISO20022Error):
        F.analyze(pain(), schema=b'<bad/>')
    with pytest.raises(F.ISO20022Error, match='no bundled schema'):
        F.analyze(pain().replace(b'pain.001.001.09', b'pain.001.001.99'))


def test_truncations_and_noise():
    data = pain()
    for end in range(0, len(data), 31):
        with pytest.raises(F.ISO20022Error):
            F.analyze(data[:end])
    rng = random.Random(173)
    for _ in range(30):
        with pytest.raises(F.ISO20022Error):
            F.analyze(rng.randbytes(50))


def test_cli(tmp_path, capsys):
    assert F.main(['--help']) == 0
    assert F.main([]) == 2
    assert F.main([str(tmp_path / 'missing')]) == 2
    path = tmp_path / 'sample.xml'
    path.write_bytes(pain())
    assert F.main([str(path), '--sepa']) == 0
    path.write_bytes(pain(count=2))
    assert F.main([str(path)]) == 1


@pytest.mark.parametrize('amount', ['+12.34', ' 12.34 ', '12.340000'])
def test_xsd_decimal_lexical_forms(amount):
    r = F.analyze(pain().replace(b'>12.34<', ('>' + amount + '<').encode()))
    assert r['schema_valid'] and r['valid'], r


def test_leading_and_trailing_decimal_points():
    for text in ['.50', '1.']:
        message = pain().replace(b'>12.34<', ('>' + text + '<').encode())
        assert F.analyze(message)['valid']


@pytest.mark.parametrize('page,last', [('1', 'false'), ('2', 'true')])
def test_camt_partial_pagination_not_false_mismatch(page, last):
    message = camt('999.00').replace(b'<Id>s1</Id>', f'<Id>s1</Id><StmtPgntn><PgNb>{page}</PgNb><LastPgInd>{last}</LastPgInd></StmtPgntn>'.encode())
    result = F.analyze(message)
    assert result['valid'], result
    assert result['statements'][0]['reconciled'] is None
    assert 'partial' in result['statements'][0]['reconciliation_note']


def test_camt_unknown_status_not_false_mismatch():
    message = camt('999.00').replace(b'<Sts><Cd>BOOK</Cd></Sts>', b'<Sts><Prtry>QUEUED</Prtry></Sts>')
    result = F.analyze(message)
    assert result['valid'], result
    assert result['statements'][0]['reconciled'] is None


def test_explicit_published_schema_and_invalid_cli_types():
    schema = Path(F.__file__).with_name('fin2_schemas').joinpath('pain.001.001.09.xsd').read_bytes()
    assert F.analyze(pain(), schema=schema)['valid']
    assert F.main([None]) == 2
    with pytest.raises(F.ISO20022Error):
        F.analyze(pain(), sepa='yes')


def test_amount_checks_ignore_callers_decimal_precision():
    from decimal import localcontext
    with localcontext() as context:
        context.prec = 2
        assert F.analyze(pain(), sepa=True)['valid']
        assert F.analyze(camt())['statements'][0]['reconciled'] is True
