"""Independent MT wire fixtures and mt-940 oracle; no engine encoder exists."""
from decimal import Decimal
import random
import pytest
import fin2_swift as swift


def envelope(body, mt='103', header='', output=False):
    # Handwritten FIN framing per Prowide's public field offsets.
    block2 = (f'O{mt}1200260101BANKBEBBAXXX22221234562601011201N'
              if output else f'I{mt}BANKDEFFXXXXN')
    return '{1:F01BANKBEBBAXXX2222123456}{2:' + block2 + '}' + header + '{4:\n' + body + '\n-}{5:{CHK:123456789ABC}}'


# SWIFT PMPG exceptions/investigations published mandatory-field example.
# https://www.swift.com/sites/default/files/documents/swift_pmpg_guidelines_exceptionsandinvestigations.pdf
PAYMENT = ':20:2233NA\n:23B:CRED\n:32A:120828HKD12786,78\n:50K:/122267890\nBIOCOM\n123 Windsor St\nToronto, ON M8Y 1A4\nCanada\n:59:/324788294\nLee Import\n78 Sing Wood Rd\nHappy Valley\nHong Kong\n:71A:SHA'

# Synthetic ledger, computed by hand: 100 - 20 + 5 + 7 - 2 = 90.
LEDGER = ':20:STATEMENT1\n:25:12345\n:28C:1/1\n:60F:C260101EUR100,00\n:61:2601010101D20,00NTRFREF1//BANK1\n:86:Invoice one\n:61:260101C5,00NTRFREF2\n:61:260101RD7,00NTRFREF3\n:61:260101RC2,00NTRFREF4\n:62F:C260101EUR90,00\n:86:Statement footer'


def test_published_payment_and_mx_projection():
    parsed = swift.parse_messages(envelope(PAYMENT))[0]
    fields = {f['tag']: f for f in parsed['fields']}
    assert fields['32A']['decoded'] == {'currency': 'HKD', 'amount': '12786.78', 'value_date': '120828'}
    assert fields['50K']['decoded']['account'] == '122267890'
    assert fields['59']['decoded']['name_address'][0] == 'Lee Import'
    assert parsed['header']['sender_bic'] == 'BANKBEBBXXX'
    assert parsed['header']['receiver_bic'] == 'BANKDEFFXXX'
    assert parsed['mx_projection']['target'] == 'pacs.008'
    assert parsed['mx_projection']['conformant_translation'] is False
    assert next(f['value'] for f in parsed['mx_projection']['fields'] if f['source_tag'] == '71A') == 'SHAR'
    assert parsed['authentication_verified'] is False


def test_output_header_and_nested_optional_blocks():
    msg = envelope(PAYMENT, header='{3:{108:REFERENCE}{121:00112233-4455-4677-8899-aabbccddeeff}}', output=True)
    parsed = swift.parse_messages(msg)[0]
    assert parsed['header']['direction'] == 'output'
    assert parsed['header']['sender_lt'] == 'BANKBEBBAXXX'
    assert parsed['header']['mir'] == '260101BANKBEBBAXXX2222123456'
    assert parsed['header']['output_time'] == '1201'
    assert len(parsed['user_header']) == 2
    assert parsed['trailer'] == [{'tag': 'CHK', 'value': '123456789ABC'}]


def test_payment_repeated_charges_and_flag_braces():
    body = PAYMENT + '\n:71F:HKD1,00\n:71F:HKD2,00\n:71G:HKD3,00\n:72:CSCTF{payment_artifact}'
    parsed = swift.parse_messages(envelope(body))[0]
    assert [f['decoded']['amount'] for f in parsed['fields'] if f['tag'] == '71F'] == ['1.00', '2.00']
    assert parsed['flags'] == ['CSCTF{payment_artifact}']


def test_mt202_published_sample_values():
    # SWIFT Category 6, MT600 example's related MT202 (2022 guide p72).
    body = ':20:3456378\n:21:CRESZZ3605DEUTFF\n:32A:070124USD721000,\n:58A:CRESCHZZ80A'
    parsed = swift.parse_messages(envelope(body, '202'))[0]
    assert parsed['fields'][2]['decoded']['amount'] == '721000'
    assert parsed['fields'][3]['decoded']['bic'] == 'CRESCHZZ80A'
    assert parsed['mx_projection']['target'] == 'pacs.009'


def test_mt202_cov_retains_two_52a_sequences():
    body = ':20:COVER1\n:21:PAYREF\n:32A:260101EUR100,00\n:52A:AAAADEFF\n:58A:BBBBDEFF\n:50K:/111\nDEBTOR\n:52A:CCCCDEFF\n:59:/222\nCREDITOR\n:70:INVOICE'
    parsed = swift.parse_messages(envelope(body, '202', '{3:{119:COV}}'))[0]
    assert parsed['variant'] == 'COV'
    parties = [f for f in parsed['fields'] if f['tag'] == '52A']
    assert [p['sequence'] for p in parties] == ['A', 'B']
    assert parties[1]['decoded']['bic'] == 'CCCCDEFF'
    assert any(p['path_hint'] == 'UndrlygCstmrCdtTrf/DbtrAgt' for p in parsed['mx_projection']['fields'])


def test_mt940_ledger_reversals_and_footer():
    parsed = swift.parse_messages(LEDGER, '940')[0]
    ledger = parsed['statement']
    assert ledger['reconciled']
    assert ledger['entry_net'] == '-10.00'
    assert [x['signed_amount'] for x in ledger['entries']] == ['-20.00', '5.00', '7.00', '-2.00']
    assert ledger['entries'][0]['bank_reference'] == 'BANK1'
    assert ledger['entries'][0]['information'] == ['Invoice one']
    assert ledger['entries'][-1]['information'] == []
    assert ledger['information'] == ['Statement footer']


def test_mt940_against_independent_library():
    mt940 = pytest.importorskip('mt940')
    reference = mt940.models.Transactions(options=mt940.Options(reversal_sign=True))
    reference.parse(LEDGER)
    actual = swift.parse_messages(LEDGER, '940')[0]['statement']
    assert [Decimal(x['signed_amount']) for x in actual['entries']] == [x.data['amount'].amount for x in reference]
    assert [x['account_owner_reference'] for x in actual['entries']] == [x.data['customer_reference'] for x in reference]
    assert Decimal(actual['opening']['signed_amount']) == reference.data['final_opening_balance'].amount.amount
    assert Decimal(actual['closing']['signed_amount']) == reference.data['final_closing_balance'].amount.amount


def test_mt950_gs_published_values_reveal_mismatch():
    # Goldman Sachs developer Swift Reporting MT950 documented sample values;
    # its one shown entry does not reconcile the shown opening/closing balance.
    body = ':20:TRN0000123456789\n:25:0123456789\n:28C:1/1\n:60F:C220308USD2080000000,00\n:61:2203080308D279999800,00NTRFEPHI000015544410//I20081200003033\n:62M:C220308USD900000100,00\n:64:C220308USD900000100,00'
    ledger = swift.parse_messages(envelope(body, '950'))[0]['statement']
    assert not ledger['reconciled']
    assert ledger['expected_closing'] == '1800000200.00'
    assert ledger['difference'] == '-900000100.00'
    assert ledger['available_balances'][0]['amount'] == '900000100.00'


def test_batches_and_crlf():
    messages = swift.parse_messages((envelope(PAYMENT) + '$\n' + envelope(LEDGER, '940')).replace('\n', '\r\n').encode())
    assert [m['message_type'] for m in messages] == ['103', '940']


@pytest.mark.parametrize('bad', [None, 5, [], {}, b'\xff', '', 'garbage', ':20:foo', '{1:bad}',
    envelope(PAYMENT) + 'junk', envelope(PAYMENT) + '$', envelope(PAYMENT).replace('\n-}', '}'),
    envelope(PAYMENT.replace('120828', '120232')), envelope(PAYMENT.replace('12786,78', '12786.78')),
    envelope(PAYMENT + '\n:59A:ABCDDEFF'), envelope(PAYMENT.replace(':71A:SHA', ':71A:BAD')),
    envelope(PAYMENT).replace('{2:', '{1:foo}{2:'), envelope(PAYMENT).replace('I103', 'I999'),
    envelope(PAYMENT).replace('I103', 'O103')])
def test_bad_inputs_raise_only_declared_error(bad):
    with pytest.raises(swift.SwiftError):
        swift.parse_messages(bad)


@pytest.mark.parametrize('bad', [LEDGER.replace('C260101EUR90,00', 'C260101USD90,00'),
    LEDGER.replace('260101RC2,00', '260101XX2,00'), LEDGER + '\n:61:260101C1,00NTRFREF',
    LEDGER.replace(':60F:', ':60F:bad\n:60M:'), LEDGER.replace('2601010101D', '2601010230D')])
def test_invalid_statement_fails_closed(bad):
    with pytest.raises(swift.SwiftError):
        swift.parse_messages(bad, '940')


def test_explicit_type_conflict_and_950_no_86():
    with pytest.raises(swift.SwiftError):
        swift.parse_messages(envelope(PAYMENT), '202')
    with pytest.raises(swift.SwiftError):
        swift.parse_messages(LEDGER, '950')
    with pytest.raises(swift.SwiftError):
        swift.parse_messages(LEDGER, [])


def test_bounded_malformed_random_bytes():
    rng = random.Random(2606)
    for _ in range(300):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(120)))
        try:
            swift.parse_messages(data)
        except swift.SwiftError:
            pass


def test_guarded_cli(tmp_path, capsys):
    assert swift.main(['--help']) == 0
    assert swift.main(['--bad']) == 2
    assert swift.main([str(tmp_path / 'missing')]) == 2
    sample = tmp_path / 'sample.mt'
    sample.write_text(envelope(PAYMENT))
    assert swift.main([str(sample)]) == 0
    assert 'pacs.008' in capsys.readouterr().out
    sample.write_bytes(b'\xff')
    assert swift.main([str(sample)]) == 2


def test_decimal_context_cannot_round_the_ledger():
    from decimal import localcontext
    with localcontext() as ctx:
        ctx.prec = 2
        result = swift.parse_messages(LEDGER, '940')[0]['statement']
    assert result['opening']['signed_amount'] == '100.00'
    assert result['entry_net'] == '-10.00'
    assert result['reconciled']


def test_additional_core_checks():
    with pytest.raises(swift.SwiftError):
        swift.parse_messages(PAYMENT.replace(':23B:CRED', ':23B:WHAT'), '103')
    with pytest.raises(swift.SwiftError):
        swift.parse_messages(LEDGER.replace(':25:12345\n', '') + '\n:25:12345', '940')
    assert swift.main(['\0']) == 2


def test_large_continuation_is_preserved_once():
    # One long unknown extension stresses continuation handling, not network
    # field-width validation. This remains beneath the global input bound.
    continuation = '\n'.join(['static analysis continuation'] * 20000)
    result = swift.parse_messages(envelope(PAYMENT + '\n:99:' + continuation))[0]
    assert result['fields'][-1]['value'] == continuation
    with pytest.raises(swift.SwiftError):
        swift.parse_messages('A' * (swift.MAX_BYTES + 1))


def test_header_subfield_bound_and_many_subfields(monkeypatch):
    header = '{3:{108:first}{111:second}{121:third}}'
    assert len(swift.parse_messages(envelope(PAYMENT, header=header))[0]['user_header']) == 3
    monkeypatch.setattr(swift, 'MAX_FIELDS', 16)
    with pytest.raises(swift.SwiftError, match='header/trailer subfields'):
        swift.parse_messages(envelope(PAYMENT, header='{3:' + '{108:x}' * 17 + '}'))
