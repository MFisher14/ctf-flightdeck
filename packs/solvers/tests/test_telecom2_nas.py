"""Independent encodings: pycrate for NAS, hand-built X.691/38.413 APER for NGAP.

The engines under test never encode data. NAS uses the real pycrate encoder as
oracle. The NGAP oracle is handwritten below, NOT pycrate's encoder (which is
also the NGAP engine's decoder dependency).
"""
import random
import pytest
import telecom2_nas as nas
import telecom2_ngap as ngap
from pycrate_mobile.TS24501_FGMM import (
    FGMMRegistrationRequest, FGMMIdentityResponse, FGMMIdentityRequest,
    FGMMULNASTransport, FGMMAuthenticationRequest, FGMMAuthenticationResponse,
    FGMMSecurityModeCommand, FGMMSecProtNASMessage, FGMMMODeregistrationRequest,
)
from pycrate_mobile.TS24501_FGSM import FGSMPDUSessionEstabRequest
from pycrate_mobile.TS24501_IE import FGSIDGUTI, FGSIDDigit, FGSRegType, DeregistrationType


def guti():
    x = FGSIDGUTI()
    x.set_val({'PLMN': '00101', 'AMFRegionID': 7, 'AMFSetID': 513,
               'AMFPtr': 37, '5GTMSI': 0x12345678})
    return x.to_bytes()


def registration():
    x = FGMMRegistrationRequest()
    x['5GSRegType'].set_val({'V': 1})
    x['5GSID'].set_val({'V': guti()})
    return x.to_bytes()


def test_registration_real_encoder():
    r = nas.parse_nas(registration())
    assert r['message_name'] == 'Registration request'
    assert r['fields']['registration_type'] == 1
    ident = r['fields']['mobile_identity']
    assert ident['mcc'] == '001' and ident['mnc'] == '01'
    assert ident['amf_set_id'] == 513 and ident['amf_pointer'] == 37
    assert ident['amf_region_id'] == 7 and ident['tmsi'] == 0x12345678
    assert not r['unparsed_tail_hex']


def test_identity_real_encoders():
    msg = FGMMIdentityResponse()
    ident = FGSIDDigit()
    ident.set_val('490154203237518')
    msg['5GSID'].set_val({'V': ident.to_bytes()})
    assert nas.parse_nas(msg.to_bytes())['fields']['mobile_identity']['digits'] == '490154203237518'
    msg = FGMMIdentityRequest()
    assert nas.parse_nas(msg.to_bytes())['fields']['identity_type'] == 'SUCI'


def test_suci_handwritten_24501_91134():
    # IMSI SUPI format, MCC 310, MNC 260, routing 1234, null scheme,
    # key id zero, MSIN 123456789. TBCD's low nibble is the earlier digit.
    wire = bytes.fromhex('01 13 00 62 21 43 00 00 21 43 65 87 f9')
    ident = nas.decode_identity(wire)
    assert ident['imsi'] == '310260123456789'
    assert ident['routing_indicator'] == '1234'
    assert ident['protection_scheme'] == 0
    protected = wire[:6] + b'\x01\x04' + b'ciphertext'
    ident = nas.decode_identity(protected)
    assert 'imsi' not in ident and ident['home_network_key_id'] == 4


def test_transport_session_and_dnn_real_encoder():
    sm = FGSMPDUSessionEstabRequest()
    sm[0]['PDUSessID'].set_val(5)
    sm[0]['PTI'].set_val(8)
    sm['PDUSessType'].set_trans(False)
    sm['PDUSessType'].set_val({'V': 3})
    msg = FGMMULNASTransport()
    msg['PayloadContainer'].set_val({'V': sm.to_bytes()})
    msg['DNN'].set_trans(False)
    msg['DNN'].set_val({'V': b'\x08internet\x03ims'})
    msg['SNSSAI'].set_trans(False)
    msg['SNSSAI'].set_val({'V': bytes.fromhex('01 112233')})
    r = nas.parse_nas(msg.to_bytes())
    assert r['fields']['inner']['pdu_session_id'] == 5
    assert r['fields']['inner']['procedure_transaction_id'] == 8
    assert r['fields']['inner']['ies'][0]['value'] == 3
    assert r['ies'][0]['value'] == {'sst': 1, 'sd': '112233'}
    assert r['ies'][1]['value'] == 'internet.ims'


def test_authentication_real_encoders():
    msg = FGMMAuthenticationRequest()
    for name, value in [('RAND', bytes(range(16))), ('AUTN', b'A' * 16)]:
        msg[name].set_trans(False)
        msg[name].set_val({'V': value})
    r = nas.parse_nas(msg.to_bytes())
    assert r['fields']['abba_hex'] == '0000'
    assert [ie['name'] for ie in r['ies']] == ['RAND', 'AUTN']
    assert r['ies'][0]['raw_hex'] == bytes(range(16)).hex()
    msg = FGMMAuthenticationResponse()
    msg['RES'].set_trans(False)
    msg['RES'].set_val({'V': b'R' * 16})
    assert nas.parse_nas(msg.to_bytes())['ies'][0]['raw_hex'] == (b'R' * 16).hex()


def test_security_mode_real_encoder():
    msg = FGMMSecurityModeCommand()
    r = nas.parse_nas(msg.to_bytes())
    assert r['fields']['ciphering_algorithm'] == 1
    assert r['fields']['integrity_algorithm'] == 1


@pytest.mark.parametrize('security', [1, 2, 3, 4])
def test_protected_semantics_real_encoder(security):
    # Pycrate builds the actual MAC/SQN envelope; no MAC is claimed verified.
    msg = FGMMSecProtNASMessage()
    msg[0]['SecHdr'].set_val(security)
    msg['MAC'].set_val(b'ABCD')
    msg['Seqn'].set_val(12)
    msg['NASMessage'].set_val(registration())
    r = nas.parse_nas(msg.to_bytes())
    assert r['integrity_verified'] is False and r['sequence_number'] == 12
    assert r['mac_hex'] == b'ABCD'.hex()
    assert r['ciphered'] == (security in (2, 4))
    assert ('inner' in r) == (security in (1, 3))


def test_opaque_messages_and_unknown_ies_are_not_guessed():
    r = nas.parse_nas(bytes.fromhex('7e00ff1234'))
    assert r['opaque_body_hex'] == '1234'
    assert r['message_name'] == 'Unknown'
    r = nas.parse_nas(registration() + b'\x01\xff')
    assert r['unparsed_tail_hex'] == '01ff'
    assert 'unsupported' in r['decode_status']


@pytest.mark.parametrize('wire', [b'', b'\x7e', b'\x7e\x00', b'\x2e',
    b'\x7e\x05', b'\x7e\x10\x41', bytes.fromhex('7e005c0008f2'),
    bytes.fromhex('7e005bff'), bytes.fromhex('7e005b0100'),
    bytes.fromhex('7e00560701ff'), bytes.fromhex('7e006701000101'),
    bytes.fromhex('7e00572d0401020304'), bytes.fromhex('2e0101c100')])
def test_bad_nas(wire):
    with pytest.raises(nas.NASError):
        nas.parse_nas(wire)


def test_all_required_registration_truncations():
    for n in range(len(registration())):
        with pytest.raises(nas.NASError):
            nas.parse_nas(registration()[:n])


@pytest.mark.parametrize('value', [None, 7, '7e005b01', [], {'a': 1}])
def test_nas_public_type_contract(value):
    for fn in [nas.parse_nas, nas.decode_identity, nas.decode_dnn, nas.decode_plmn]:
        with pytest.raises(nas.NASError):
            fn(value)


def test_released_memoryview_contract():
    value = memoryview(b'x')
    value.release()
    with pytest.raises(nas.NASError):
        nas.parse_nas(value)


def test_random_nas_only_declared_exception():
    rng = random.Random(260501)
    for _ in range(1000):
        data = rng.randbytes(rng.randrange(100))
        try:
            nas.parse_nas(data)
        except nas.NASError:
            pass


# X.691 aligned PER encoders for a deliberately tiny, independent subset.
# NGAP choice index 0 = initiatingMessage. procedureCode is constrained 0..255.
# Criticality uses two bits + alignment; ignore=1 -> 0x40, reject=0 -> 0x00.
# Open types use an octet length determinant. A ProtocolIE-Container uses a
# 16-bit item count; each id is a constrained 16-bit integer.
def short_open(value):
    assert len(value) < 128
    return bytes([len(value)]) + value


def ie(ident, value):
    return ident.to_bytes(2, 'big') + b'\x00' + short_open(value)


def downlink(nas_pdu):
    # AMF and RAN IDs are large constrained integers. For values <=255, their
    # constrained octet-length count is zero, aligned then one value octet.
    ies = [ie(10, b'\x00\x01'), ie(85, b'\x00\x02'), ie(38, short_open(nas_pdu))]
    inner = b'\x00' + len(ies).to_bytes(2, 'big') + b''.join(ies)
    return b'\x00\x04\x40' + short_open(inner)


def test_ngap_handwritten_downlink_aper():
    r = ngap.parse_ngap(downlink(bytes.fromhex('7e005b01')))
    assert r['procedure_code'] == 4
    assert r['pdu_type'] == 'initiatingMessage'
    assert r['message_name'] == 'DownlinkNASTransport'
    assert r['nas_pdus'][0]['decoded']['fields']['identity_type'] == 'SUCI'
    assert r['encoding'] == 'aligned PER'


def test_ngap_valid_outer_bad_inner_preserves_evidence():
    r = ngap.parse_ngap(downlink(b'\xff'))
    assert r['nas_pdus'] == [{'raw_hex': 'ff', 'error': 'not a 5GS NAS extended protocol discriminator'}]


def test_ngap_empty_error_indication():
    # ErrorIndication has optional IEs; empty container is permitted by ASN.1.
    r = ngap.parse_ngap(bytes.fromhex('00094003000000'))
    assert r['message_name'] == 'ErrorIndication' and not r['nas_pdus']


def test_ngap_truncation_trailing_and_state_recovery():
    wire = downlink(bytes.fromhex('7e005b01'))
    for n in range(len(wire)):
        with pytest.raises(ngap.NGAPError):
            ngap.parse_ngap(wire[:n])
        assert ngap.parse_ngap(wire)['procedure_code'] == 4
    with pytest.raises(ngap.NGAPError):
        ngap.parse_ngap(wire + b'\x00')


def test_ngap_type_and_size_contract():
    for value in (None, 7, 'abcd', b'A' * (ngap.MAX_BYTES + 1)):
        with pytest.raises(ngap.NGAPError):
            ngap.parse_ngap(value)


def test_clis_and_parser_systemexit(tmp_path, capsys, monkeypatch):
    p = tmp_path / 'nas.hex'
    p.write_text('7e005b01')
    assert nas.main([str(p), '--hex']) == 0
    assert nas.main(['--help']) == 0
    assert nas.main([]) == 2
    assert nas.main([str(p) + '-missing']) == 2
    p.write_text('xyz')
    assert nas.main([str(p), '--hex']) == 2
    p.write_bytes(downlink(bytes.fromhex('7e005b01')))
    assert ngap.main([str(p)]) == 0
    assert ngap.main(['--help']) == 0
    assert ngap.main([]) == 2
    def exit_string(*args, **kwargs):
        raise SystemExit('failure')
    monkeypatch.setattr(nas.argparse.ArgumentParser, 'parse_args', exit_string)
    assert nas.main([]) == 2
    assert ngap.main([]) == 2


def test_registration_follow_on_bit_real_encoder():
    message = FGMMRegistrationRequest()
    reg_type = FGSRegType()
    reg_type.set_val({'FOR': 1, 'Value': 1})
    message['5GSRegType'].set_val({'V': int.from_bytes(reg_type.to_bytes(), 'big') >> 4})
    message['5GSID'].set_val({'V': guti()})
    fields = nas.parse_nas(message.to_bytes())['fields']
    assert fields['registration_type'] == 1
    assert fields['follow_on_request'] is True
    assert nas.parse_nas(registration())['fields']['follow_on_request'] is False


def test_deregistration_has_its_own_bit_fields():
    message = FGMMMODeregistrationRequest()
    de_type = DeregistrationType()
    de_type.set_val({'SwitchOff': 1, 'ReregistrationRequired': 0, 'AccessType': 2})
    # These three bit fields occupy the low nibble of the encoded octet.
    message['DeregistrationType'].set_val({'V': int.from_bytes(de_type.to_bytes(), 'big') >> 4})
    message['5GSID'].set_val({'V': guti()})
    fields = nas.parse_nas(message.to_bytes())['fields']
    assert fields['deregistration_type_raw'] == 10
    assert fields['deregistration_access_type'] == 2
    assert fields['switch_off'] is True
    assert fields['reregistration_required_bit'] is False
    assert 'follow_on_request' not in fields and 'registration_type' not in fields


@pytest.mark.parametrize('extension', [b'\xff', b'\xff\xff'])
def test_identity_extra_filler_bytes_rejected(extension):
    ident = FGSIDDigit()
    ident.set_val('490154203237518')
    valid = ident.to_bytes()
    assert len(valid) == 8
    assert nas.decode_identity(valid)['digits'] == '490154203237518'
    with pytest.raises(nas.NASError):
        nas.decode_identity(valid + extension)
    suci = bytes.fromhex('011300622143000021436587f9')
    assert nas.decode_identity(suci)['imsi'] == '310260123456789'
    with pytest.raises(nas.NASError):
        nas.decode_identity(suci + extension)


def test_identity_filler_position_and_routing_padding():
    prefix = bytes.fromhex('01130062f1ff0000')  # routing indicator 1 + three F nibbles
    assert nas.decode_identity(prefix + bytes.fromhex('2143'))['routing_indicator'] == '1'
    assert nas.decode_identity(prefix + bytes.fromhex('21f3'))['msin'] == '123'
    for output in [bytes.fromhex('21ff'), bytes.fromhex('2f'), bytes.fromhex('f321')]:
        with pytest.raises(nas.NASError):
            nas.decode_identity(prefix + output)


def test_imeisv_exact_byte_length_real_encoder():
    ident = FGSIDDigit()
    ident.set_val({'Type': 5, 'Digits': '4901542032375186'})
    valid = ident.to_bytes()
    assert len(valid) == 9
    assert nas.decode_identity(valid)['digits'] == '4901542032375186'
    for wire in [valid[:-1], valid + b'\xff']:
        with pytest.raises(nas.NASError):
            nas.decode_identity(wire)
